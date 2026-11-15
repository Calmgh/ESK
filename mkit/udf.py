# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""UDF（Universal Disk Format）1.02 – 2.01 读取

对应 LovelyCarve 的「文件系统」中的 UDF。UDF 与 ISO 9660 同处一张介质：
DVD / 蓝光 / UDF 封包的 U 盘 / Windows 格式化出的硬盘镜像都是这个格式。

已实现：
    · 卷识别序列 VRS（扇区 16 起，BEA01 / NSR02 / NSR03 / TEA01）
    · 扇区大小自动识别：2048（光盘）与 512（硬盘镜像），并兼容 1024 / 4096
    · 锚点 AVDP（扇区 256 与卷尾 N-1、N-256 三处互备）与主卷描述符序列 VDS
    · PVD（卷名 / 卷集名）、PD（分区起始与长度）、LVD（逻辑块大小 / FSD 位置）、
      USD、TD、VDP（描述符序列指针跟随）
    · descriptorTag 校验：tagChecksum 严格校验，descCRC（CRC-16/CCITT）软校验
    · File Set Descriptor（根目录 ICB）与 File Entry(261) / Extended File Entry(266)
    · 分配描述符三种：short_ad / long_ad / extended_ad，以及 embedded（inline）
    · 分配描述符类型：0=已记录、1/2=空洞（补零）、3=下一段 AD 续接
    · 目录内容 FID 解析（4 字节对齐、删除位、父目录位），8 位与 16 位名字解码
    · 文件读取、目录遍历、按路径查找、通配符查找、符号链接（fileType=12）解析
    · 时间戳（UTC / 本地时区 / 协商时间三种类型）

不实现：
    · 元数据分区（Metadata Partition）、虚拟分区 / VAT 重映射、Sparable 分区
      —— 遇到 "*UDF Metadata Partition" / "*UDF Virtual Partition" 映射会显式报错
    · 多分区交叉读取：仅按分区映射表把 partitionReferenceNum 映射到 PD，不做跨分区重组
    · 扩展属性（EA）内容解析：只跳过 lengthExtendedAttr，不解释 FID 之外的 EA 项
    · 删除文件残留雕刻、Bitmap / 空间表、LVID 一致性校验（仅取其中标识）
    · 写回、修复、UDF 2.50+（NSR04）、以及 ISO/UDF 混合桥中的 ISO 侧（见 mkit.iso）
"""

import datetime
import fnmatch
import struct

__all__ = [
    "Udf", "Fe", "Fid", "IcbAddr", "probe",
    "VRS_SECTOR", "ANCHOR_SECTOR", "DESC_SIZE", "SECTOR_SIZES",
]

# ---------------- 常量 ----------------
VRS_SECTOR = 16                 # 卷识别序列起始扇区（2048 字节逻辑扇区）
VRS_OFFSET = VRS_SECTOR * 2048  # = 32768，规范固定的起始字节
ANCHOR_SECTOR = 256             # AVDP 所在扇区
DESC_SIZE = 2048                # 卷描述符 / 文件条目的最大长度基准
SECTOR_SIZES = (2048, 512, 1024, 4096)

TAG_PVD = 1
TAG_AVDP = 2
TAG_VDP = 3
TAG_IUVD = 4
TAG_PD = 5
TAG_LVD = 6
TAG_USD = 7
TAG_TD = 8
TAG_LVID = 9
TAG_FSD = 256
TAG_FID = 257
TAG_AED = 258
TAG_IE = 259
TAG_TE = 260
TAG_FE = 261
TAG_EAHD = 262
TAG_USE = 263
TAG_SBD = 264
TAG_PIE = 265
TAG_EFE = 266

VSD_IDS = frozenset(("BEA01", "NSR02", "NSR03", "TEA01", "BOOT2",
                     "CD001", "CDW02"))

FT_DIR = 4
FT_FILE = 5
FT_SYMLINK = 12
FT_STREAMDIR = 13

AD_SHORT = 0
AD_LONG = 1
AD_EXT = 2
AD_INLINE = 3

EXT_RECORDED = 0
EXT_NOT_RECORDED_ALLOC = 1
EXT_NOT_RECORDED = 2
EXT_NEXT = 3

FID_HIDDEN = 0x01
FID_DIRECTORY = 0x02
FID_DELETED = 0x04
FID_PARENT = 0x08
FID_METADATA = 0x10

UDF_DOMAIN = b"*OSTA UDF Compliant"
IDENT_METADATA = b"*UDF Metadata Partition"
IDENT_VIRTUAL = b"*UDF Virtual Partition"
IDENT_SPARABLE = b"*UDF Sparable Partition"


# ---------------- 基础工具 ----------------
def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _crc16(data):
    """CRC-16/CCITT（poly 0x1021，初值 0，不反转），UDF 的 descCRC"""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def _tag_sum(buf, off=0):
    """tagChecksum：tag 16 字节内除 tagChecksum 自身外求和 mod 256"""
    return (sum(buf[off:off + 4]) + sum(buf[off + 5:off + 16])) & 0xFF


def _crc_ok(buf, off=0):
    """返回 True/False；descCRC 为 0 或长度越界时返回 None（不校验）"""
    if len(buf) < off + 16:
        return None
    crc = _u16(buf, off + 8)
    ln = _u16(buf, off + 10)
    if not crc or not ln or off + 16 + ln > len(buf):
        return None
    return _crc16(buf[off + 16:off + 16 + ln]) == crc


def _valid_tag(buf, off=0, strict=True):
    """校验 descriptorTag，返回 dict；strict=False 时忽略 tagChecksum"""
    if len(buf) < off + 16:
        return None
    tid, ver = struct.unpack_from("<HH", buf, off)
    if tid == 0:
        return None
    if strict and _tag_sum(buf, off) != buf[off + 4]:
        return None
    return {
        "id": tid,
        "version": ver,
        "location": _u32(buf, off + 12),
        "checksum": buf[off + 4],
        "crc_ok": _crc_ok(buf, off),
        "strict": strict,
    }


def _decode_chars(cid, payload):
    """按压缩 ID 解码名字：8 / 16 为 16 位大端，其余按 8 位"""
    if not payload:
        return ""
    if cid in (8, 16):
        if len(payload) & 1:
            payload = payload[:-1]
        try:
            s = payload.decode("utf-16-be")
        except UnicodeDecodeError:
            s = payload.decode("utf-16-be", "replace")
        if s[:1] == "\ufeff":
            s = s[1:]
        return s.rstrip("\x00")
    for enc in ("utf-8", "latin-1"):
        try:
            return payload.decode(enc).rstrip("\x00")
        except UnicodeDecodeError:
            continue
    return payload.decode("latin-1", "replace").rstrip("\x00")


def _decode_osta(raw):
    """OSTA Compressed Unicode：首字节是压缩 ID，其后是字符数据"""
    if not raw:
        return ""
    return _decode_chars(raw[0], raw[1:])


def _decode_dstring(buf, off):
    """dstring{compID u8, length u8, data[]}"""
    if len(buf) < off + 2:
        return ""
    cid = buf[off]
    ln = buf[off + 1]
    return _decode_chars(cid, buf[off + 2:off + 2 + min(ln, 255)])


def _ts(buf, off):
    """timestamp（12B）→ datetime；年份为 0 或越界返回 None"""
    if len(buf) < off + 12:
        return None
    tz_type = _u16(buf, off)
    year = _u16(buf, off + 2)
    if not year:
        return None
    month, day, hour, minute, second = buf[off + 4:off + 9]
    cs, hus, us = buf[off + 9], buf[off + 10], buf[off + 11]
    micro = us + hus * 100 + cs * 10000
    try:
        dt = datetime.datetime(year, month or 1, day or 1, hour or 0,
                               minute or 0, second or 0, min(micro, 999999))
    except ValueError:
        return None
    tz = tz_type & 0x0FFF
    if (tz_type >> 12) & 0x0F == 1:            # 1=本地时间，其余按 UTC/协商
        if tz & 0x0800:
            tz -= 0x1000
        try:
            return dt.replace(tzinfo=datetime.timezone(
                datetime.timedelta(minutes=tz)))
        except ValueError:
            return dt
    return dt


def _rev_str(rev):
    """UDFRevision 0x0102 → '1.02'"""
    if not rev:
        return ""
    return "%d.%02d" % (rev >> 8, rev & 0xFF)


def _regid_ident(buf, off):
    """entity id 的 ident[23]"""
    return buf[off + 1:off + 24].rstrip(b"\x00")


# ---------------- 数据结构 ----------------
class IcbAddr(object):
    """lb_addr（逻辑块号 + 分区引用号），附带 long_ad 里的 extentLength"""

    __slots__ = ("length", "lbn", "part")

    def __init__(self, length=0, lbn=0, part=0):
        self.length = length
        self.lbn = lbn
        self.part = part

    @classmethod
    def from_long_ad(cls, buf, off=0):
        """long_ad{extentLength u32, lb_addr{logicalBlockNum u32, partRef u16}, impUse[6]}"""
        if len(buf) < off + 16:
            return cls()
        return cls(_u32(buf, off), _u32(buf, off + 4), _u16(buf, off + 8))

    def key(self):
        return (self.part, self.lbn)

    def __repr__(self):
        return "<IcbAddr blk=%d part=%d len=%d>" % (self.lbn, self.part,
                                                    self.length)


class Fid(object):
    """File Identifier Descriptor：目录里的一条名字"""

    __slots__ = ("name", "icb", "version", "chars", "fs", "_fe", "offset")

    def __init__(self, name, icb, version=1, chars=0, fs=None, offset=None):
        self.name = name
        self.icb = icb
        self.version = version
        self.chars = chars
        self.fs = fs
        self._fe = None
        self.offset = offset

    is_dir = property(lambda self: bool(self.chars & FID_DIRECTORY))
    is_deleted = property(lambda self: bool(self.chars & FID_DELETED))
    is_parent = property(lambda self: bool(self.chars & FID_PARENT))
    is_metadata = property(lambda self: bool(self.chars & FID_METADATA))
    is_hidden = property(lambda self: bool(self.chars & FID_HIDDEN))

    def fe(self):
        """取得该条目指向的 File Entry（惰性，带缓存）"""
        if self._fe is None:
            self._fe = self.fs._read_fe(self.icb)
        return self._fe

    size = property(lambda self: self.fe().info_len)

    def __repr__(self):
        tag = "DIR " if self.is_dir else "FILE"
        if self.is_deleted:
            tag = "DEL " + tag
        return "<Fid %r %s %dB>" % (self.name, tag, self.fe().info_len)


class Fe(object):
    """File Entry(261) / Extended File Entry(266)"""

    __slots__ = ("tag_id", "lbn", "part", "file_type", "flags", "ad_kind",
                 "parent_lbn", "parent_part", "uid", "gid", "permissions",
                 "link_count", "info_len", "object_size", "logical_blocks",
                 "atime", "mtime", "ctime", "crtime", "ads", "embedded",
                 "length_ads", "length_ea")

    def __init__(self):
        self.tag_id = 0
        self.lbn = 0
        self.part = 0
        self.file_type = 0
        self.flags = 0
        self.ad_kind = AD_SHORT
        self.parent_lbn = 0
        self.parent_part = 0
        self.uid = 0
        self.gid = 0
        self.permissions = 0
        self.link_count = 0
        self.info_len = 0
        self.object_size = 0
        self.logical_blocks = 0
        self.atime = None
        self.mtime = None
        self.ctime = None
        self.crtime = None
        self.ads = []
        self.embedded = b""
        self.length_ads = 0
        self.length_ea = 0

    is_dir = property(lambda self: self.file_type == FT_DIR)
    is_file = property(lambda self: self.file_type == FT_FILE)
    is_symlink = property(lambda self: self.file_type == FT_SYMLINK)

    @classmethod
    def parse(cls, fs, buf, lbn, part):
        tag = _valid_tag(buf)
        if tag is None:
            tag = _valid_tag(buf, strict=False)
        if tag is None:
            raise ValueError("文件条目 tag 校验失败 @lbn=%d" % lbn)
        tid = tag["id"]
        if tid not in (TAG_FE, TAG_EFE):
            raise ValueError("不是文件条目（tagId=%d）@lbn=%d" % (tid, lbn))
        return cls._parse_fe(fs, buf, lbn, part) if tid == TAG_FE else \
            cls._parse_efe(fs, buf, lbn, part)

    @classmethod
    def _parse_fe(cls, fs, buf, lbn, part):
        if len(buf) < 176:
            raise ValueError("File Entry 长度不足 @lbn=%d" % lbn)
        fe = cls()
        fe.tag_id = TAG_FE
        fe.lbn, fe.part = lbn, part
        fe._icb(buf, 16)
        fe.uid = _u32(buf, 36)
        fe.gid = _u32(buf, 40)
        fe.permissions = _u32(buf, 44)
        fe.link_count = _u16(buf, 48)
        fe.info_len = _u64(buf, 56)
        fe.logical_blocks = _u64(buf, 64)
        fe.object_size = fe.info_len
        fe.atime = _ts(buf, 72)
        fe.mtime = _ts(buf, 84)
        fe.ctime = _ts(buf, 96)          # FE 无创建时间，ctime 取 attrTime
        fe.length_ea = _u32(buf, 168)
        fe.length_ads = _u32(buf, 172)
        fe._ads(fs, buf, 176)
        return fe

    @classmethod
    def _parse_efe(cls, fs, buf, lbn, part):
        if len(buf) < 216:
            raise ValueError("Extended File Entry 长度不足 @lbn=%d" % lbn)
        fe = cls()
        fe.tag_id = TAG_EFE
        fe.lbn, fe.part = lbn, part
        fe._icb(buf, 16)
        fe.uid = _u32(buf, 36)
        fe.gid = _u32(buf, 40)
        fe.permissions = _u32(buf, 44)
        fe.link_count = _u16(buf, 48)
        fe.info_len = _u64(buf, 56)
        fe.object_size = _u64(buf, 64)
        fe.logical_blocks = _u64(buf, 72)
        fe.atime = _ts(buf, 80)
        fe.mtime = _ts(buf, 92)
        fe.crtime = _ts(buf, 104)
        fe.ctime = _ts(buf, 116)
        fe.length_ea = _u32(buf, 208)
        fe.length_ads = _u32(buf, 212)
        fe._ads(fs, buf, 216)
        return fe

    def _icb(self, buf, off):
        """icbTag 20B：fileType@11，parentICBLocation@12，flags@18"""
        self.file_type = buf[off + 11]
        self.parent_lbn = _u32(buf, off + 12)
        self.parent_part = _u16(buf, off + 16)
        self.flags = _u16(buf, off + 18)
        self.ad_kind = self.flags & 0x07

    def _ads(self, fs, buf, off):
        if self.ad_kind == AD_INLINE:
            self.embedded = buf[off:off + self.info_len]
            return
        end = off + self.length_ads
        self.ads = fs._parse_ads(buf[off:min(end, len(buf))], self.ad_kind,
                                 self.part)

    def __repr__(self):
        kind = {FT_DIR: "DIR", FT_FILE: "FILE", FT_SYMLINK: "LINK"}.get(
            self.file_type, "TYPE%d" % self.file_type)
        return "<Fe %s %dB lbn=%d>" % (kind, self.info_len, self.lbn)


# ---------------- 主体 ----------------
class Udf(object):
    """UDF 1.02 – 2.01 只读视图

    只依赖 sub.read(offset, size) 与 sub.size，
    因此可直接吃 mkit.image.SubImage（分区切片）。
    """

    def __init__(self, sub):
        self.sub = sub
        self.size = getattr(sub, "size", 0) or 0
        self.sector_size = 2048
        self.block_size = 2048
        self.anchor_sector = 0
        self.vrs_ids = []
        self.warnings = []
        self.bad_tags = 0

        self.udf_version = ""
        self.revision = 0
        self.volume_id = ""
        self.volume_set_id = ""
        self.file_set_id = ""

        self.pvd = None
        self.lvd = None
        self.usd = None
        self.fsd = None
        self.part_maps = []
        self.pds_by_num = {}
        self.partition_start = 0
        self.partition_length = 0
        self.root_icb = None
        self.vds_tags = []

        self._fe_cache = {}

        self._scan_vrs()
        self._load_volume()
        self._load_fsd()

    # ---------------- 卷识别序列 ----------------
    def _scan_vrs(self):
        """VRS：每个描述符 2048B，structType u8 + identifier[5] + version u8"""
        bases = []
        for base in (VRS_OFFSET, 16 * 2048, 16 * 512, 16 * 1024, 16 * 4096):
            if base not in bases:
                bases.append(base)
        for base in bases:
            head = self.sub.read(base, 8)
            if len(head) >= 6 and head[1:6] == b"BEA01":
                self._read_vrs_at(base)
                return
        # 没有 BEA01：再试只以 NSR 打头的镜像
        for base in bases:
            head = self.sub.read(base, 8)
            if len(head) >= 6 and head[1:6] in (b"NSR02", b"NSR03"):
                self._read_vrs_at(base)
                return

    def _read_vrs_at(self, base):
        ids = []
        for i in range(16):
            d = self.sub.read(base + i * DESC_SIZE, DESC_SIZE)
            if len(d) < 8:
                break
            try:
                ident = d[1:6].decode("ascii")
            except UnicodeDecodeError:
                break
            if ident not in VSD_IDS:
                break
            ids.append(ident)
            if ident == "TEA01":
                break
        self.vrs_ids = ids

    def vrs(self):
        """识别序列里看到的 identifier 列表，如 ['BEA01','NSR02','TEA01']"""
        return list(self.vrs_ids)

    # ---------------- 锚点与 VDS ----------------
    def _anchor_candidates(self):
        """AVDP 候选：扇区 256 与卷尾 N-1、N-256，按扇区大小逐个试"""
        out = []
        seen = set()
        for ss in SECTOR_SIZES:
            secs = [ANCHOR_SECTOR]
            if self.size >= ss * 300:
                n = self.size // ss
                secs += [n - 1, n - 256]
            for sec in secs:
                if sec < 0 or (ss, sec) in seen:
                    continue
                seen.add((ss, sec))
                buf = self.sub.read(sec * ss, 512)
                tag = _valid_tag(buf)
                if tag and tag["id"] == TAG_AVDP:
                    out.append((ss, sec, buf))
        return out

    def _load_volume(self):
        last = None
        for ss, sec, buf in self._anchor_candidates():
            self.sector_size = ss
            self.block_size = ss
            main = (_u32(buf, 16), _u32(buf, 20))
            reserve = (_u32(buf, 24), _u32(buf, 28))
            for length, location in (main, reserve):
                if length < 16 or not location:
                    continue
                try:
                    if self._parse_vds(length, location):
                        self.anchor_sector = sec
                        return
                except ValueError as exc:
                    last = exc
        if last is None:
            raise ValueError("未找到 UDF 锚点（AVDP）或主卷描述符序列")
        raise ValueError("锚点存在但卷描述符序列不可用：%s" % last)

    def _parse_vds(self, length, location):
        """顺着 main VDS extent 读描述符，找到 PVD / PD / LVD / USD / TD"""
        base = location * self.sector_size
        data = self.sub.read(base, length)
        if len(data) < 16:
            return False
        pvd = lvd = usd = None
        pds = []
        maps = []
        tags = []
        i = 0
        hops = 0
        while i + 16 <= len(data):
            tag = _valid_tag(data, i)
            tid = tag["id"] if tag else None
            if tag is None:
                break
            tags.append(tid)
            span = DESC_SIZE
            if tid == TAG_PVD:
                if pvd is None:
                    pvd = data[i:i + DESC_SIZE]
                    pvd = pvd if len(pvd) == DESC_SIZE else pvd
            elif tid == TAG_PD:
                pd = self._parse_pd(data, i)
                if pd is not None:
                    pds.append(pd)
            elif tid == TAG_LVD:
                if lvd is None:
                    lvd = data[i:i + DESC_SIZE]
                span = 440 + _u32(data, i + 264)
                span = max(DESC_SIZE, ((span + DESC_SIZE - 1) // DESC_SIZE)
                           * DESC_SIZE)
                maps = self._parse_maps(data, i)
            elif tid == TAG_USD:
                usd = data[i:i + DESC_SIZE]
                span = 24 + 8 * _u32(data, i + 20)
                span = max(DESC_SIZE, ((span + DESC_SIZE - 1) // DESC_SIZE)
                           * DESC_SIZE)
            elif tid == TAG_VDP:
                hops += 1
                if hops > 4:
                    break
                nlen = _u32(data, i + 20)
                nloc = _u32(data, i + 24)
                if nlen < 16 or not nloc:
                    break
                if nloc * self.sector_size == base:
                    break
                base = nloc * self.sector_size
                data = self.sub.read(base, nlen)
                i = 0
                continue
            elif tid == TAG_TD:
                break
            i += span

        if pvd is None or lvd is None:
            return False

        self.pvd = pvd
        self.lvd = lvd
        self.usd = usd
        self.vds_tags = tags
        self.pds_by_num = dict((p["number"], p) for p in pds)
        self.part_maps = maps

        self.volume_id = _decode_dstring(pvd, 24)
        self.volume_set_id = _decode_dstring(pvd, 72)
        self.block_size = _u32(lvd, 212) or self.sector_size
        ident = _regid_ident(lvd, 216)
        rev = _u16(lvd, 240)
        self.revision = rev
        self.udf_version = _rev_str(rev)

        if pds:
            first = pds[0]
            self.partition_start = first["start"]
            self.partition_length = first["length"]

        nsr = [x for x in self.vrs_ids if x in ("NSR02", "NSR03")]
        if not self.udf_version:
            if "NSR03" in nsr:
                self.udf_version = "2.00"
            elif "NSR02" in nsr:
                self.udf_version = "1.02"
        if ident and ident != UDF_DOMAIN:
            self.warnings.append("LVD 域标识非 *OSTA UDF Compliant: %r" % ident)
        return True

    @staticmethod
    def _parse_pd(data, i):
        """Partition Descriptor：编号@22，起始@188，长度@192"""
        if len(data) < i + 196:
            return None
        return {
            "number": _u16(data, i + 22),
            "start": _u32(data, i + 188),
            "length": _u32(data, i + 192),
            "flags": _u16(data, i + 20),
            "access": _u32(data, i + 184),
            "contents": _regid_ident(data, i + 24),
        }

    @staticmethod
    def _parse_maps(data, i):
        """LVD 的分区映射表：type1{volSeq,partNum} / type2{regid,...,partNum@38}"""
        if len(data) < i + 272:
            return []
        ln = _u32(data, i + 264)
        num = _u32(data, i + 268)
        out = []
        p = i + 440
        end = min(p + ln, len(data))
        for _ in range(min(num, 64)):
            if p + 2 > end:
                break
            mtype = data[p]
            mlen = data[p + 1] or 6
            if mtype == 1:
                out.append((1, _u16(data, p + 4), b""))
            elif mtype == 2:
                ident = _regid_ident(data, p + 4)
                out.append((2, _u16(data, p + 38), ident))
            else:
                out.append((mtype, None, b""))
            p += mlen
        return out

    # ---------------- File Set ----------------
    def _load_fsd(self):
        if self.lvd is None:
            raise ValueError("缺少逻辑卷描述符（LVD）")
        icb = IcbAddr.from_long_ad(self.lvd, 248)
        buf = self.sub.read(self._blk_off(icb.lbn, icb.part), DESC_SIZE)
        tag = _valid_tag(buf)
        if tag is None or tag["id"] != TAG_FSD:
            raise ValueError("未找到 File Set Descriptor")
        self.fsd = buf
        self.root_icb = IcbAddr.from_long_ad(buf, 400)
        self.file_set_id = _decode_dstring(buf, 304)
        if not self.volume_id:
            self.volume_id = _decode_dstring(buf, 112)
        if not self.root_icb.length:
            self.root_icb.length = DESC_SIZE

    # ---------------- 地址换算 ----------------
    def _part_base(self, part=0):
        """partitionReferenceNum → 该分区在镜像中的字节起始"""
        if not self.pds_by_num:
            return 0
        pn = None
        if 0 <= part < len(self.part_maps):
            mtype, num, ident = self.part_maps[part]
            if mtype == 1:
                pn = num
            elif mtype == 2:
                if ident in (IDENT_METADATA, IDENT_VIRTUAL):
                    raise ValueError("不支持的分区映射: %r" % ident)
                if ident == IDENT_SPARABLE:
                    self.warnings.append("Sparable 分区按物理分区直读")
                pn = num
            else:
                raise ValueError("未知分区映射类型 %d" % mtype)
        if pn is None:
            pn = sorted(self.pds_by_num)[0]
        pd = self.pds_by_num.get(pn)
        if pd is None:
            raise ValueError("分区 %r 未在 Partition Descriptor 中定义" % (pn,))
        return pd["start"] * self.block_size

    def _blk_off(self, lbn, part=0):
        """逻辑块号 → 镜像字节偏移（分区起始 × 逻辑块大小 + lbn × 逻辑块大小）"""
        return self._part_base(part) + lbn * self.block_size

    # ---------------- 分配描述符 ----------------
    @staticmethod
    def _parse_ads(buf, kind, part=0):
        """解析分配描述符数组 → [(类型, 长度, 块号, 分区引用)]"""
        out = []
        n = len(buf)
        if kind == AD_SHORT:
            step = 8
            for o in range(0, n - step + 1, step):
                ext = _u32(buf, o)
                out.append((ext >> 30, ext & 0x3FFFFFFF, _u32(buf, o + 4), part))
        elif kind == AD_LONG:
            step = 16
            for o in range(0, n - step + 1, step):
                ext = _u32(buf, o)
                out.append((ext >> 30, ext & 0x3FFFFFFF, _u32(buf, o + 4),
                            _u16(buf, o + 8)))
        elif kind == AD_EXT:
            step = 20
            for o in range(0, n - step + 1, step):
                ext = _u32(buf, o)
                info = _u32(buf, o + 8)
                ln = info or (ext & 0x3FFFFFFF)
                out.append((ext >> 30, ln, _u32(buf, o + 12), _u16(buf, o + 16)))
        return out

    def _extent_bytes(self, ads, kind, part, want):
        """按 extent 读数据；类型 1/2 补零，类型 3 续接下一段 AD"""
        out = bytearray()
        pending = list(ads)
        guard = 0
        while pending and len(out) < want and guard < 8192:
            guard += 1
            typ, ln, pos, pref = pending.pop(0)
            if typ == EXT_NEXT:
                cont = self.sub.read(self._blk_off(pos, pref), ln)
                if not cont:
                    continue
                pending[0:0] = self._parse_ads(cont, kind, pref)
                continue
            if not ln:
                continue
            take = min(ln, want - len(out))
            if typ == EXT_RECORDED:
                chunk = self.sub.read(self._blk_off(pos, pref), take)
                out += chunk
                if len(chunk) < take:
                    break
            else:
                out += b"\x00" * take
        return bytes(out)

    # ---------------- 文件条目 ----------------
    def _read_fe(self, icb, _depth=0):
        if _depth > 8:
            raise ValueError("ICB 间接链过深")
        key = icb.key()
        if key in self._fe_cache:
            return self._fe_cache[key]
        off = self._blk_off(icb.lbn, icb.part)
        buf = self.sub.read(off, DESC_SIZE)
        tag = _valid_tag(buf)
        if tag is None:
            tag = _valid_tag(buf, strict=False)
            if tag is not None:
                self.bad_tags += 1
                self.warnings.append("ICB tagChecksum 不符 @lbn=%d" % icb.lbn)
        if tag is None:
            raise ValueError("ICB tag 无效 @lbn=%d part=%d" % (icb.lbn, icb.part))
        if tag["id"] == TAG_IE:
            inner = IcbAddr.from_long_ad(buf, 36)
            fe = self._read_fe(inner, _depth + 1)
        else:
            fe = Fe.parse(self, buf, icb.lbn, icb.part)
            if fe.ad_kind == AD_INLINE:
                need = 176 + fe.info_len + (fe.length_ads or 0)
                if need > len(buf):
                    buf2 = self.sub.read(off, need)
                    if len(buf2) >= need:
                        fe = Fe.parse(self, buf2, icb.lbn, icb.part)
        self._fe_cache[key] = fe
        return fe

    def _as_fe(self, icb=None):
        if icb is None:
            return self.root()
        if isinstance(icb, Fe):
            return icb
        if isinstance(icb, Fid):
            return icb.fe()
        if isinstance(icb, IcbAddr):
            return self._read_fe(icb)
        raise TypeError("需要 Fid / Fe / IcbAddr / None，收到 %r" % type(icb))

    def _fe_data(self, fe):
        if fe.ad_kind == AD_INLINE:
            return bytes(fe.embedded[:fe.info_len])
        return self._extent_bytes(fe.ads, fe.ad_kind, fe.part, fe.info_len)

    def root(self):
        """根目录 File Entry"""
        if self.root_icb is None:
            raise ValueError("尚未定位根目录 ICB")
        return self._read_fe(self.root_icb)

    def stat(self, icb):
        """条目元数据"""
        fe = self._as_fe(icb)
        return {
            "name": getattr(icb, "name", None),
            "file_type": fe.file_type,
            "is_dir": fe.is_dir,
            "size": fe.info_len,
            "ad_kind": fe.ad_kind,
            "lbn": fe.lbn,
            "partition": fe.part,
            "uid": fe.uid,
            "gid": fe.gid,
            "permissions": fe.permissions,
            "link_count": fe.link_count,
            "mtime": fe.mtime,
            "atime": fe.atime,
            "ctime": fe.ctime,
            "crtime": fe.crtime,
        }

    # ---------------- 目录 ----------------
    def listdir(self, icb=None, include_deleted=True, include_parent=False):
        """列目录：icb 可以是 Fid / Fe / IcbAddr，None 表示根目录

        默认剔除父目录项（FID 里名字长度为 0 的那条）与已删除项；
        取证需要残留时传 include_deleted=True（默认就是 True）。
        """
        fe = self._as_fe(icb)
        if not fe.is_dir:
            raise ValueError("不是目录: fileType=%d lbn=%d" % (fe.file_type,
                                                              fe.lbn))
        data = self._fe_data(fe)
        return self._parse_fids(data, include_deleted, include_parent)

    def _parse_fids(self, data, include_deleted=True, include_parent=False):
        """FID 串：tag(16) + ver(2) + chars(1) + nameLen(1) + icb(16) +
        impUseLen(2) + impUse + name，整体 4 字节对齐"""
        out = []
        i = 0
        n = len(data)
        blk = self.block_size or DESC_SIZE
        while i + 38 <= n:
            tag = _valid_tag(data, i)
            if tag is None or tag["id"] != TAG_FID:
                nxt = ((i // blk) + 1) * blk
                if nxt <= i:
                    break
                i = nxt
                if i + 38 > n:
                    break
                continue
            version = _u16(data, i + 16)
            chars = data[i + 18]
            name_len = data[i + 19]
            icb = IcbAddr.from_long_ad(data, i + 20)
            use_len = _u16(data, i + 36)
            p = i + 38 + use_len
            if p + name_len > n:
                break
            raw = data[p:p + name_len]
            total = 38 + use_len + name_len
            total = (total + 3) & ~3
            name = _decode_osta(raw) if raw else ""
            keep = include_deleted or not (chars & FID_DELETED)
            if not include_parent and (chars & FID_PARENT or not name):
                keep = False
            if keep:
                out.append(Fid(name=name, icb=icb, version=version,
                               chars=chars, fs=self, offset=i))
            i += max(total, 4)
        return out

    def walk(self, icb=None, _depth=0, _prefix="", _seen=None):
        """递归遍历，产出 (路径, Fid)"""
        seen = set() if _seen is None else _seen
        fe = self.root() if icb is None else self._as_fe(icb)
        key = (fe.part, fe.lbn)
        if key in seen or _depth > 32:
            return
        seen.add(key)
        for e in self.listdir(fe):
            if e.is_parent or not e.name:
                continue
            path = _prefix + e.name
            yield path, e
            if e.is_dir:
                try:
                    for sub_path, sub_e in self.walk(e.icb, _depth + 1,
                                                     path + "/", seen):
                        yield sub_path, sub_e
                except ValueError as exc:
                    self.warnings.append("遍历 %r 失败: %s" % (path, exc))

    def lookup_path(self, path):
        """按路径查找，返回 Fid（空路径返回根 Fe）；未找到返回 None"""
        comps = [p for p in str(path).replace("\\", "/").split("/")
                 if p not in ("", ".")]
        cur = self.root()
        stack = []
        last = None
        for comp in comps:
            if comp == "..":
                if stack:
                    cur = stack.pop()
                last = None
                continue
            if not cur.is_dir:
                return None
            ents = self.listdir(cur)
            hit = None
            for e in ents:
                if e.name == comp:
                    hit = e
                    break
            if hit is None:
                low = comp.lower()
                for e in ents:
                    if e.name.lower() == low:
                        hit = e
                        break
            if hit is None:
                return None
            last = hit
            stack.append(cur)
            cur = self._as_fe(hit)
        return last if comps else cur

    def read_file(self, icb):
        """读普通文件内容；目录返回 None"""
        fe = self._as_fe(icb)
        if fe.is_dir:
            return None
        return self._fe_data(fe)

    def readlink(self, icb):
        """符号链接目标（fileType=12 的路径组件串）"""
        fe = self._as_fe(icb)
        if not fe.is_symlink:
            return None
        data = self._fe_data(fe)
        out = []
        i = 0
        n = len(data)
        while i + 4 <= n:
            ctype = data[i]
            ln = data[i + 1]
            if ctype in (1, 2, 3) and ln == 0:
                out.append({1: "", 2: ".", 3: ".."}.get(ctype, ""))
                i += 4
                continue
            name = data[i + 4:i + 4 + ln]
            i += 4 + ln
            out.append(_decode_osta(name) if name else "")
        text = "/".join(x for x in out if x != "")
        if out and out[0] == "":
            text = "/" + text
        return text

    def find(self, pattern):
        """按子串或通配符（* ? []）匹配路径"""
        pat = pattern.lower()
        wild = any(c in pattern for c in "*?[")
        out = []
        for path, e in self.walk():
            if wild:
                if fnmatch.fnmatch(path.lower(), pat) or \
                        fnmatch.fnmatch(e.name.lower(), pat):
                    out.append((path, e))
            elif pat in path.lower():
                out.append((path, e))
        return out

    # ---------------- 概要 ----------------
    def info(self):
        root = self.root_icb
        return {
            "format": "udf",
            "udf_version": self.udf_version,
            "volume_id": self.volume_id,
            "volume_set_id": self.volume_set_id,
            "file_set_id": self.file_set_id,
            "sector_size": self.sector_size,
            "logical_block_size": self.block_size,
            "partition_start": self.partition_start,
            "partition_length": self.partition_length,
            "num_partitions": len(self.pds_by_num),
            "partition_maps": [m[0] for m in self.part_maps],
            "anchor_sector": self.anchor_sector,
            "vrs": list(self.vrs_ids),
            "vds_tags": list(self.vds_tags),
            "file_set_root": None if root is None else {
                "lbn": root.lbn, "partition": root.part, "length": root.length},
            "bad_tags": self.bad_tags,
            "warnings": list(self.warnings),
        }

    def __repr__(self):
        return "<Udf %s vol=%r sec=%d blk=%d>" % (
            self.udf_version or "?", self.volume_id, self.sector_size,
            self.block_size)


def probe(sub):
    """快速判定是否为 UDF：VRS 里有 NSR02/NSR03，或扇区 256 处有合法 AVDP"""
    try:
        for base in (VRS_OFFSET, 16 * 512, 16 * 1024, 16 * 4096):
            head = sub.read(base, DESC_SIZE)
            if len(head) >= 6 and head[1:6] == b"BEA01":
                for i in range(1, 4):
                    d = sub.read(base + i * DESC_SIZE, 8)
                    if len(d) >= 6 and d[1:6] in (b"NSR02", b"NSR03"):
                        return True
        total = getattr(sub, "size", 0) or 0
        for ss in SECTOR_SIZES:
            secs = [ANCHOR_SECTOR]
            if total >= ss * 300:
                secs += [total // ss - 1, total // ss - 256]
            for sec in secs:
                buf = sub.read(sec * ss, 512)
                tag = _valid_tag(buf)
                if tag and tag["id"] == TAG_AVDP:
                    return True
    except Exception:
        return False
    return False


# ---------------- 合成镜像自检 ----------------
def _mk_tag(tag_id, location, body, version=2):
    """构造合法描述符：tagChecksum + descCRC 都按规范算"""
    desc = bytearray(16) + bytearray(body)
    struct.pack_into("<HH", desc, 0, tag_id, version)
    desc[4] = 0
    desc[5] = 0
    struct.pack_into("<H", desc, 6, 0)
    struct.pack_into("<H", desc, 8, 0)
    struct.pack_into("<H", desc, 10, 0)
    struct.pack_into("<I", desc, 12, location)
    if body:
        struct.pack_into("<H", desc, 8, _crc16(desc[16:]))
        struct.pack_into("<H", desc, 10, len(body))
    desc[4] = _tag_sum(desc)
    return bytes(desc)


def _mk_ts(y=2024, mo=3, d=4, h=5, mi=6, s=7):
    b = bytearray(12)
    struct.pack_into("<H", b, 0, 0x1000)        # 类型 1：本地时间，时区 0
    struct.pack_into("<H", b, 2, y)
    b[4], b[5], b[6], b[7], b[8] = mo, d, h, mi, s
    return bytes(b)


def _mk_charspec():
    b = bytearray(64)
    b[0] = 0
    b[1:24] = b"OSTA Compressed Unicode"
    return bytes(b)


def _mk_dstring(text, size, cid=254):
    b = bytearray(size)
    raw = text.encode("utf-16-be") if cid in (8, 16) else text.encode("utf-8")
    raw = raw[:min(len(raw), size - 2, 255)]
    b[0] = cid
    b[1] = len(raw)
    b[2:2 + len(raw)] = raw
    return bytes(b)


def _mk_regid(ident, suffix=b""):
    b = bytearray(32)
    b[1:1 + len(ident)] = ident
    b[24:24 + len(suffix)] = suffix
    return bytes(b)


def _mk_icb(lbn, part=0, length=2048):
    """long_ad：extentLength@0, logicalBlockNum@4, partitionRef@8, impUse@10"""
    b = bytearray(16)
    struct.pack_into("<I", b, 0, length)
    struct.pack_into("<I", b, 4, lbn)
    struct.pack_into("<H", b, 8, part)
    return bytes(b)


def _mk_pvd(volume_id):
    b = bytearray(496)
    struct.pack_into("<I", b, 0, 1)
    struct.pack_into("<I", b, 4, 0)
    b[8:40] = _mk_dstring(volume_id, 32)
    struct.pack_into("<H", b, 40, 1)
    struct.pack_into("<H", b, 42, 1)
    struct.pack_into("<H", b, 44, 2)
    struct.pack_into("<H", b, 46, 2)
    struct.pack_into("<I", b, 48, 1)
    struct.pack_into("<I", b, 52, 1)
    b[56:184] = _mk_dstring("ESK-UDF-SET", 128)
    b[184:248] = _mk_charspec()
    b[248:312] = _mk_charspec()
    b[328:360] = _mk_regid(b"*ESK UDF Writer")
    b[360:372] = _mk_ts()
    b[372:404] = _mk_regid(b"*ESK")
    return bytes(b)


def _mk_pd(start, length, number=0):
    b = bytearray(496)
    struct.pack_into("<I", b, 0, 2)
    struct.pack_into("<H", b, 4, 1)              # 已分配
    struct.pack_into("<H", b, 6, number)
    b[8:40] = _mk_regid(b"+NSR02")
    struct.pack_into("<I", b, 168, 1)            # 只读
    struct.pack_into("<I", b, 172, start)
    struct.pack_into("<I", b, 176, length)
    b[180:212] = _mk_regid(b"*ESK")
    return bytes(b)


def _mk_lvd(block_size, fsd_lbn, revision=0x0102):
    b = bytearray(496)
    struct.pack_into("<I", b, 0, 3)
    b[4:68] = _mk_charspec()
    b[68:196] = _mk_dstring("ESK-LV", 128)
    struct.pack_into("<I", b, 196, block_size)
    suffix = struct.pack("<H", revision) + b"\x00" * 6
    b[200:232] = _mk_regid(UDF_DOMAIN, suffix)
    b[232:248] = _mk_icb(fsd_lbn, 0, 2048)       # logicalVolumeContentsUse
    struct.pack_into("<I", b, 248, 6)            # mapTableLength
    struct.pack_into("<I", b, 252, 1)            # numPartitionMaps
    b[256:288] = _mk_regid(b"*ESK")
    struct.pack_into("<II", b, 416, 0, 0)        # integritySeqExt
    b[424] = 1                                   # Type 1 分区映射
    b[425] = 6
    struct.pack_into("<HH", b, 426, 1, 0)        # volSeqNum, partitionNum
    return bytes(b)


def _mk_fsd(root_lbn, part=0):
    b = bytearray(496)
    b[0:12] = _mk_ts()
    struct.pack_into("<H", b, 12, 2)
    struct.pack_into("<H", b, 14, 2)
    struct.pack_into("<I", b, 16, 1)
    struct.pack_into("<I", b, 20, 1)
    struct.pack_into("<I", b, 24, 0)
    struct.pack_into("<I", b, 28, 0)
    b[32:96] = _mk_charspec()
    b[96:224] = _mk_dstring("ESK-LV", 128)
    b[224:288] = _mk_charspec()
    b[288:320] = _mk_dstring("ESK-FILESET", 32)
    b[384:400] = _mk_icb(root_lbn, part, 2048)
    b[400:432] = _mk_regid(UDF_DOMAIN, struct.pack("<H", 0x0102) + b"\x00" * 6)
    return bytes(b)


def _mk_anchor(length, location):
    b = bytearray(496)
    struct.pack_into("<II", b, 0, length, location)
    struct.pack_into("<II", b, 8, length, location)
    return bytes(b)


def _mk_ad_short(length, lbn):
    b = bytearray(8)
    struct.pack_into("<II", b, 0, length & 0x3FFFFFFF, lbn)
    return bytes(b)


def _mk_fe(lbn, file_type, flags, info_len, ads=b"", embedded=b"",
           parent=0, link_count=1):
    """File Entry(261)：icbTag 20B + 定长域 + 分配描述符 + inline 数据"""
    b = bytearray(160)
    struct.pack_into("<I", b, 0, 0)
    struct.pack_into("<H", b, 4, 4)              # strategyType = 4
    struct.pack_into("<H", b, 6, 0)
    struct.pack_into("<H", b, 8, 1)
    b[10] = 0
    b[11] = file_type
    struct.pack_into("<I", b, 12, parent)        # parentICBLocation.lbn
    struct.pack_into("<H", b, 16, 0)
    struct.pack_into("<H", b, 18, flags)
    struct.pack_into("<I", b, 20, 0)             # uid
    struct.pack_into("<I", b, 24, 0)             # gid
    struct.pack_into("<I", b, 28, 0o755)         # permissions
    struct.pack_into("<H", b, 32, link_count)
    struct.pack_into("<I", b, 36, 0)             # recordLength
    struct.pack_into("<Q", b, 40, info_len)
    struct.pack_into("<Q", b, 48, (info_len + 2047) // 2048)
    b[56:68] = _mk_ts()
    b[68:80] = _mk_ts()
    b[80:92] = _mk_ts()
    struct.pack_into("<I", b, 92, 1)             # checkpoint
    struct.pack_into("<Q", b, 144, lbn * 16 + 1)  # uniqueID
    struct.pack_into("<I", b, 152, 0)            # lengthExtendedAttr
    struct.pack_into("<I", b, 156, len(ads))     # lengthAllocDescs
    return _mk_tag(TAG_FE, lbn, bytes(b) + ads + embedded)


def _mk_fid(name_raw, target_lbn, chars, dir_lbn, size=0):
    body = bytearray(22)
    struct.pack_into("<H", body, 0, 1)           # fileVersionNumber
    body[2] = chars
    body[3] = len(name_raw)
    body[4:20] = _mk_icb(target_lbn, 0, size)
    struct.pack_into("<H", body, 20, 0)          # lengthOfImplementationUse
    desc = _mk_tag(TAG_FID, dir_lbn, bytes(body) + name_raw)
    if len(desc) % 4:
        desc += b"\x00" * (4 - len(desc) % 4)
    return desc


def build_image(sector=2048, block=None, volume_id="ESK_UDF_VOL"):
    """最小合成 UDF 1.02 镜像：VRS + AVDP + VDS + FSD + 根目录 + 文件"""
    bs = block or sector
    total = 320 * DESC_SIZE
    img = bytearray(total)
    vrs_base = VRS_SECTOR * sector
    vds_base = 200 * DESC_SIZE
    part_base = 65536
    part_start = part_base // bs
    part_len = (total - part_base) // bs

    def chunk(n):
        """分区内第 n 个 2048 字节块的逻辑块号"""
        return n * DESC_SIZE // bs

    def put(off, data):
        img[off:off + len(data)] = data

    # 1) VRS：扇区 16 起 BEA01 / NSR02 / TEA01
    for i, ident in enumerate((b"BEA01", b"NSR02", b"TEA01")):
        d = bytearray(DESC_SIZE)
        d[1:6] = ident
        d[6] = 1
        put(vrs_base + i * DESC_SIZE, d)

    hello = b"UDF SELFTEST: hello from ESK\n"
    cjk = b"UDF-CJK-PAYLOAD"
    inner = b"INNER-BINARY-OK"

    root_lbn = chunk(1)
    hello_lbn = chunk(2)
    hello_data = chunk(3)
    cjk_lbn = chunk(4)
    cjk_data = chunk(5)
    sub_lbn = chunk(6)
    inner_lbn = chunk(7)
    inner_d1 = chunk(8)
    inner_d2 = chunk(9)

    # 2) FSD 指向根目录 FE
    put(part_base + 0 * DESC_SIZE, _mk_tag(TAG_FSD, chunk(0), _mk_fsd(root_lbn)))

    # 3) 根目录 FE：embedded 数据里放 4 条 FID
    root_dir = b"".join((
        _mk_fid(b"", root_lbn, FID_PARENT, root_lbn, 2048),
        _mk_fid(b"\xfeHELLO.TXT", hello_lbn, 0, root_lbn, 2048),
        _mk_fid(b"\x10" + "中文.TXT".encode("utf-16-be"), cjk_lbn, 0,
                root_lbn, 2048),
        _mk_fid(b"\xfeSUB", sub_lbn, FID_DIRECTORY, root_lbn, 2048),
    ))
    put(part_base + 1 * DESC_SIZE,
        _mk_fe(root_lbn, FT_DIR, AD_INLINE, len(root_dir), embedded=root_dir))

    # 4) 文件 FE：short_ad 指向数据 extent
    put(part_base + 2 * DESC_SIZE,
        _mk_fe(hello_lbn, FT_FILE, AD_SHORT, len(hello),
               ads=_mk_ad_short(len(hello), hello_data)))
    put(part_base + hello_data * bs, hello)

    # 5) 16 位名字的那个文件
    put(part_base + 4 * DESC_SIZE,
        _mk_fe(cjk_lbn, FT_FILE, AD_SHORT, len(cjk),
               ads=_mk_ad_short(len(cjk), cjk_data)))
    put(part_base + cjk_data * bs, cjk)

    # 6) 子目录（同样 inline），里面一个双 extent 文件
    sub_dir = _mk_fid(b"\xfeINNER.BIN", inner_lbn, 0, sub_lbn, 2048)
    put(part_base + 6 * DESC_SIZE,
        _mk_fe(sub_lbn, FT_DIR, AD_INLINE, len(sub_dir), embedded=sub_dir))
    ads = _mk_ad_short(8, inner_d1) + _mk_ad_short(len(inner) - 8, inner_d2)
    put(part_base + 7 * DESC_SIZE,
        _mk_fe(inner_lbn, FT_FILE, AD_SHORT, len(inner), ads=ads))
    put(part_base + inner_d1 * bs, inner[:8])
    put(part_base + inner_d2 * bs, inner[8:])

    # 7) 主卷描述符序列：PVD / PD / LVD / TD
    put(vds_base + 0 * DESC_SIZE,
        _mk_tag(TAG_PVD, vds_base // sector, _mk_pvd(volume_id)))
    put(vds_base + 1 * DESC_SIZE,
        _mk_tag(TAG_PD, (vds_base + DESC_SIZE) // sector,
                _mk_pd(part_start, part_len)))
    put(vds_base + 2 * DESC_SIZE,
        _mk_tag(TAG_LVD, (vds_base + 2 * DESC_SIZE) // sector,
                _mk_lvd(bs, chunk(0))))
    put(vds_base + 3 * DESC_SIZE,
        _mk_tag(TAG_TD, (vds_base + 3 * DESC_SIZE) // sector, bytes(496)))

    # 8) 锚点：扇区 256 与卷尾 N-1 各一份
    put(ANCHOR_SECTOR * sector,
        _mk_tag(TAG_AVDP, ANCHOR_SECTOR, _mk_anchor(4 * DESC_SIZE,
                                                    vds_base // sector)))
    n_sec = total // sector
    put((n_sec - 1) * sector,
        _mk_tag(TAG_AVDP, n_sec - 1, _mk_anchor(4 * DESC_SIZE,
                                               vds_base // sector)))
    return bytes(img)


if __name__ == "__main__":
    class MemSub(object):
        def __init__(self, d):
            self.d = d
            self.size = len(d)

        def read(self, offset, size):
            if offset >= self.size or size <= 0:
                return b""
            return self.d[offset:offset + size]

    HELLO = b"UDF SELFTEST: hello from ESK\n"
    CJK = b"UDF-CJK-PAYLOAD"
    INNER = b"INNER-BINARY-OK"

    for sec in (2048, 512):
        raw = build_image(sec)
        assert probe(MemSub(raw)), "probe 失败 sector=%d" % sec
        udf = Udf(MemSub(raw))
        inf = udf.info()
        assert inf["udf_version"] == "1.02", inf["udf_version"]
        assert inf["volume_id"] == "ESK_UDF_VOL", inf["volume_id"]
        assert inf["sector_size"] == sec, inf["sector_size"]
        assert inf["logical_block_size"] == sec, inf["logical_block_size"]
        assert inf["partition_start"] == 65536 // sec, inf["partition_start"]
        assert udf.vrs() == ["BEA01", "NSR02", "TEA01"], udf.vrs()

        root = udf.root()
        assert root.is_dir, root
        names = sorted(e.name for e in udf.listdir())
        assert names == ["HELLO.TXT", "SUB", "中文.TXT"], names

        assert udf.read_file(udf.lookup_path("/HELLO.TXT")) == HELLO
        assert udf.read_file(udf.lookup_path("/中文.TXT")) == CJK
        assert udf.read_file(udf.lookup_path("/SUB/INNER.BIN")) == INNER
        assert udf.read_file(udf.lookup_path("sub/inner.bin")) == INNER

        paths = sorted(p for p, _ in udf.walk())
        assert paths == ["HELLO.TXT", "SUB", "SUB/INNER.BIN", "中文.TXT"], paths
        hits = [p for p, _ in udf.find("*.txt")]
        assert sorted(hits) == ["HELLO.TXT", "中文.TXT"], hits
        assert [p for p, _ in udf.find("inner")] == ["SUB/INNER.BIN"]
        assert udf.stat(udf.lookup_path("/HELLO.TXT"))["size"] == len(HELLO)

        print("UDF 自检通过 sector=%d: %s vol=%r blk=%d part@%d vrs=%s"
              % (sec, inf["udf_version"], inf["volume_id"],
                 inf["logical_block_size"], inf["partition_start"],
                 "/".join(inf["vrs"])))
        print("  根目录 %d 项: %s" % (len(names), ", ".join(names)))
        print("  HELLO.TXT=%r 中文.TXT=%r SUB/INNER.BIN=%r"
              % (udf.read_file(udf.lookup_path("/HELLO.TXT"))[:12],
                 udf.read_file(udf.lookup_path("/中文.TXT")),
                 udf.read_file(udf.lookup_path("/SUB/INNER.BIN"))))

    # 主锚点被清零时，应能退回卷尾 N-1 锚点
    broken = bytearray(build_image(2048))
    broken[ANCHOR_SECTOR * 2048:ANCHOR_SECTOR * 2048 + 512] = b"\x00" * 512
    udf2 = Udf(MemSub(bytes(broken)))
    assert udf2.info()["volume_id"] == "ESK_UDF_VOL"
    assert udf2.read_file(udf2.lookup_path("/HELLO.TXT")) == HELLO
    print("UDF 自检通过: 主锚点损坏后由尾部锚点恢复 (anchor=%d)"
          % udf2.info()["anchor_sector"])
    print("UDF 模块自检全部通过")
