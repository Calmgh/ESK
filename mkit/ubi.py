# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""UBI 卷层与 UBIFS 文件系统

只依赖可读对象的 `read(offset, size)` 与 `size`，可喂任意设备对象。

============================================================================
已实现
============================================================================
1. UBI（unsorted block images）卷层
   · EC 头（64 B，大端）：magic 0x55424923、version、ec、vid_hdr_offset、
     data_offset、image_seq、hdr_crc（CRC32）
   · VID 头（64 B，大端）：magic 0x55424921、version、vol_type（1=动态
     2=静态）、copy_flag、compat、vol_id、lnum、data_size、used_ebs、
     data_pad、data_crc、sqnum、hdr_crc
   · 逐 PEB 扫描：读 EC 头 → 校验 → 到 vid_hdr_offset 读 VID 头 → 校验
   · 同一 `(vol_id, lnum)` 可能有多份拷贝，取 `sqnum` 最大的一份
   · 按卷拼出逻辑内容：`volumes()` / `read_volume(vol_id)` /
     `read_logical(vol_id, lnum)`
   · 坏 PEB（EC 头 CRC 不过、VID 头 CRC 不过、全 0xFF 空白块）跳过并计数

2. UBIFS
   · 超级块节点（type 6）解析：key_hash、key_fmt、min_io_size、leb_size、
     leb_cnt、max_leb_cnt、log_lebs / lpt_lebs / orph_lebs / jhead_cnt、
     fanout、fmt_version、default_compr、rp_uid / rp_gid / rp_size、
     time_gran、uuid、ro_compat_version
   · **顺序 LEB 扫描**取节点（不是索引遍历）：逐 LEB 按 8 字节对齐找
     `UBIFS_NODE_MAGIC`(0x06101831)，校验 `len` 与 CRC32，按 `node_type` 分类
   · 节点类型：INO(0) / DATA(1) / DENT(2) / XENT(3) / TRUN(4) / PAD(5) /
     SB(6) / MASTER(7) / IDX(8) / CS(9) / ORPH(10) / AUTH(11)
   · 去重：同一 inode 取 `creat_sqnum` 最大者；同一 `(inum, block)` 取
     `sqnum` 最大者；同一 `(parent, name)` 取 `sqnum` 最大者
   · `listdir()` / `walk()` / `read_file()` / `lookup_path()` / `find()`
   · 压缩：`UBIFS_COMPR_NONE`(0) 直取、`UBIFS_COMPR_ZLIB`(2) 用 zlib、
     `UBIFS_COMPR_LZO`(1) 用本文件的 LZO1X 解码器、
     `UBIFS_COMPR_ZSTD`(3) 抛 NotImplementedError

============================================================================
不实现（明确边界，不猜）
============================================================================
· **写入与磨损均衡**：只读
· **UBIFS 索引（IDX 节点）遍历**：本模块用顺序 LEB 扫描取节点。这能恢复
  文件与目录，但**没有**走 TNC 索引树，因此：无法区分「垃圾回收后残留的
  旧节点」与「当前有效节点」，只能按 `sqnum` 取最大者；已删除但仍残留
  数据块的 inode 会被列出来（`orphan_guess=True` 标注）
· **LZO 解码器未用真实 LZO 压缩样本验证**：按 LZO1X 算法规范实现，
  自检只覆盖 NONE 与 ZLIB 两条路径；docstring 与返回值里如实标注
  `lzo_verified=False`
· **UBIFS 认证节点（AUTH）与 HMAC**：只识别类型，不验证签名
· **fastmap / 日志重放（journal replay）**：不做。未回放的卷可能缺少
  最近的元数据更新
· **xattr 与扩展属性内容**：`ino_node` 里的 xattr 计数与长度只报数值，
  不解析条目
· **UBI 的 fastmap 卷、layout volume 的卷表内容**：只报卷号与类型，
  不从 layout volume 反解卷名（名称取自 UBIFS 超级块 / inode）

============================================================================
节点字段偏移（以 ref/ubifs-media.h 为准，key[] 为 UBIFS_MAX_KEY_LEN=16）
============================================================================
    ubifs_ch (24 B)      magic u32@0, crc u32@4, sqnum u64@8, len u32@16,
                         node_type u8@20, group_type u8@21, pad[2]@22
    sb_node              key_hash@26, key_fmt@27, flags@28, min_io_size@32,
                         leb_size@36, leb_cnt@40, max_leb_cnt@44,
                         max_bud_bytes u64@48, log_lebs@56, lpt_lebs@60,
                         orph_lebs@64, jhead_cnt@68, fanout@72, lsave_cnt@76,
                         fmt_version@80, default_compr u16@84, rp_uid@88,
                         rp_gid@92, rp_size u64@96, time_gran@104,
                         uuid[16]@108, ro_compat_version@124
    ino_node             key[16]@24, creat_sqnum u64@40, size u64@48,
                         atime_sec@56, ctime_sec@64, mtime_sec@72,
                         atime_nsec@80, ctime_nsec@84, mtime_nsec@88,
                         nlink@92, uid@96, gid@100, mode@104, flags@108,
                         data_len@112, xattr_cnt@116, xattr_size@120,
                         xattr_names@128, compr_type u16@132, data[]@136
    dent_node            key[16]@24, inum u64@40, pad@48, type@49,
                         nlen u16@50, cookie@52, name[]@56
    data_node            key[16]@24, size u32@40, compr_type u16@44,
                         compr_size u16@46, data[]@48
"""

import struct
import zlib

__all__ = [
    "Ubi", "Ubifs", "UbiNode", "UbifsEnt",
    "probe_ubi", "probe_ubifs", "open_fs",
    "lzo1x_decompress",
    "UBI_EC_HDR_MAGIC", "UBI_VID_HDR_MAGIC", "UBIFS_NODE_MAGIC",
    "UBI_EC_HDR_SIZE", "UBI_VID_HDR_SIZE", "UBIFS_CH_SIZE",
]

UBI_EC_HDR_MAGIC = 0x55424923
UBI_VID_HDR_MAGIC = 0x55424921
UBIFS_NODE_MAGIC = 0x06101831

UBI_EC_HDR_SIZE = 64
UBI_VID_HDR_SIZE = 64
UBIFS_CH_SIZE = 24
UBIFS_MAX_KEY_LEN = 16
UBIFS_BLOCK_SIZE = 4096

UBI_VID_DYNAMIC = 1
UBI_VID_STATIC = 2

UBI_VID_TYPE_NAME = {UBI_VID_DYNAMIC: "dynamic", UBI_VID_STATIC: "static"}

# UBIFS 节点类型
UBIFS_INO_NODE = 0
UBIFS_DATA_NODE = 1
UBIFS_DENT_NODE = 2
UBIFS_XENT_NODE = 3
UBIFS_TRUN_NODE = 4
UBIFS_PAD_NODE = 5
UBIFS_SB_NODE = 6
UBIFS_MASTER_NODE = 7
UBIFS_IDX_NODE = 8
UBIFS_CS_NODE = 9
UBIFS_ORPH_NODE = 10
UBIFS_AUTH_NODE = 11

UBIFS_NODE_TYPE_NAME = {
    UBIFS_INO_NODE: "ino", UBIFS_DATA_NODE: "data", UBIFS_DENT_NODE: "dent",
    UBIFS_XENT_NODE: "xent", UBIFS_TRUN_NODE: "trun", UBIFS_PAD_NODE: "pad",
    UBIFS_SB_NODE: "sb", UBIFS_MASTER_NODE: "master", UBIFS_IDX_NODE: "idx",
    UBIFS_CS_NODE: "cs", UBIFS_ORPH_NODE: "orph", UBIFS_AUTH_NODE: "auth",
}

# UBIFS 压缩类型
UBIFS_COMPR_NONE = 0
UBIFS_COMPR_LZO = 1
UBIFS_COMPR_ZLIB = 2
UBIFS_COMPR_ZSTD = 3

UBIFS_COMPR_NAME = {
    UBIFS_COMPR_NONE: "none", UBIFS_COMPR_LZO: "lzo",
    UBIFS_COMPR_ZLIB: "zlib", UBIFS_COMPR_ZSTD: "zstd",
}

# UBIFS 目录项类型（dtype）
UBIFS_DT = {0: "unknown", 1: "fifo", 2: "chr", 4: "dir", 6: "blk",
            8: "reg", 10: "lnk", 12: "sock"}


def _be16(b, o):
    return struct.unpack_from(">H", b, o)[0]


def _be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def _be64(b, o):
    return struct.unpack_from(">Q", b, o)[0]


def _le16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _le32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _le64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _cstr(raw):
    if not raw:
        return ""
    return raw.split(b"\x00")[0].decode("utf-8", "replace")


# ------------------------------------------------------------
# LZO1X 解压
# ------------------------------------------------------------
def lzo1x_decompress(src, out_len=None):
    """LZO1X 解压

    按 LZO1X 格式规范实现（lzo1x_decompress_safe 的常见分支）：
    首字节若 > 17 表示字面量运行（len = b - 17，0 表示 255+next），
    否则进入匹配分支。匹配里 (b & 3) 决定距离/长度的编码方式，
    M2 最大距离 0x800、M3 最大距离 0x4000。

    注意：本函数按算法规范写成，但**没有用真实 LZO 压缩样本验证**过；
    UBIFS 的包帧格式（[总长 u16][压缩长 u16][数据]）由调用方剥离后再传进来。
    自检只覆盖 NONE 与 ZLIB。
    """
    src = memoryview(bytes(src))
    n = len(src)
    out = bytearray()
    ip = 0
    if n == 0:
        return bytes(out)

    # 字面量运行
    b = src[ip]
    ip += 1
    if b > 17:
        t = b - 17
        if t < 4:
            if ip >= n:
                raise ValueError("LZO：字面量长度被截断")
            t = (t << 8) | src[ip]
            ip += 1
        t += 3
        if ip + t > n:
            raise ValueError("LZO：字面量越界")
        out += src[ip:ip + t]
        ip += t
    else:
        t = b
        if t < 4:
            if ip >= n:
                raise ValueError("LZO：初始匹配长度被截断")
            t = (t << 8) | src[ip]
            ip += 1
        t += 3
        if ip >= n:
            raise ValueError("LZO：缺少初始匹配距离")
        dist = 1 + (src[ip] >> 2) + (src[ip + 1] << 6)
        ip += 2
        if dist > len(out):
            raise ValueError("LZO：初始匹配距离越界")
        for _ in range(t):
            out.append(out[-dist])

    while ip < n:
        t = src[ip]
        ip += 1
        if t < 16:
            # 短匹配
            if ip >= n:
                raise ValueError("LZO：短匹配被截断")
            if t == 0:
                while ip < n and src[ip] == 0:
                    t += 255
                    ip += 1
                if ip >= n:
                    raise ValueError("LZO：短匹配长度序列被截断")
                t += 15 + src[ip]
                ip += 1
            t += 3
            dist = 1 + 0x800 + (src[ip - 1] >> 2)
            # 这一支在 LZO1X 里对应 M4，实际距离由后续字节给出
            if ip >= n:
                raise ValueError("LZO：短匹配距离被截断")
            dist = 1 + (src[ip] >> 2) + (src[ip + 1] << 6) + 0x800
            ip += 1
            if dist > len(out):
                raise ValueError("LZO：短匹配距离越界")
            for _ in range(t):
                out.append(out[-dist])
            continue

        if t >= 64:
            # M2：距离 1..0x800，长度 (t>>5)+1
            ln = (t >> 5) + 1
            if ip >= n:
                raise ValueError("LZO：M2 被截断")
            dist = 1 + ((t >> 2) & 0x7) + (src[ip] << 3)
            ip += 1
            if dist > len(out):
                raise ValueError("LZO：M2 距离越界")
            for _ in range(ln):
                out.append(out[-dist])
            # 尾部字面量
            if ip < n:
                lb = t & 3
                if lb:
                    if ip + lb > n:
                        break
                    out += src[ip:ip + lb]
                    ip += lb
            continue

        if t >= 32:
            # M3：距离 1..0x4000，长度 (t&31)+2
            ln = (t & 0x1F) + 2
            if ip + 1 >= n:
                raise ValueError("LZO：M3 被截断")
            dist = 1 + ((t & 0x1F) << 8) + src[ip]
            ip += 1
            if dist > len(out):
                raise ValueError("LZO：M3 距离越界")
            for _ in range(ln):
                out.append(out[-dist])
            continue

        # t in 16..31 -> M1：距离 1..0x400，长度 (t&7)+2，另有 2 字节扩展
        ln = (t & 0x7) + 2
        if ip >= n:
            raise ValueError("LZO：M1 被截断")
        dist = 1 + ((t >> 3) & 0x3) * 256 + src[ip]
        ip += 1
        if dist > len(out):
            raise ValueError("LZO：M1 距离越界")
        for _ in range(ln):
            out.append(out[-dist])

    return bytes(out)


# ------------------------------------------------------------
# UBI
# ------------------------------------------------------------
class Ubi(object):
    """UBI 卷层

    peb_size: 物理擦除块大小。None 时按常见 NAND 页大小猜（0x20000）
    """

    def __init__(self, sub, peb_size=None, vid_hdr_offset=None,
                 data_offset=None):
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.peb_size = int(peb_size or 0) or self._guess_peb_size()
        self._vid_off = vid_hdr_offset
        self._data_off = data_offset
        self.ec_hdrs = []
        self.vid_hdrs = []
        self.notes = []
        self.bad_pebs = 0
        self.blank_pebs = 0
        self._lebs = {}                 # (vol_id, lnum) -> (sqnum, bytes)
        self._vol_types = {}
        self._scan()

    # ---- 探测 ----
    def _guess_peb_size(self):
        """在开头 4 MiB 里找第二个 EC 头出现的位置，其间距即 PEB 大小"""
        head = self.sub.read(0, 0x30)
        if len(head) < 4 or _be32(head, 0) != UBI_EC_HDR_MAGIC:
            return 0x20000
        window = self.sub.read(0, min(self.size, 4 * 1024 * 1024))
        step = 512
        for off in range(step, len(window) - 4, step):
            if _be32(window, off) == UBI_EC_HDR_MAGIC:
                return off
        return 0x20000

    def _scan(self):
        if not self.peb_size or not self.size:
            return
        npeb = self.size // self.peb_size
        for i in range(npeb):
            base = i * self.peb_size
            ec = self.sub.read(base, UBI_EC_HDR_SIZE)
            if len(ec) < UBI_EC_HDR_SIZE:
                break
            if ec[:4] == b"\xff\xff\xff\xff":
                self.blank_pebs += 1
                continue
            if _be32(ec, 0) != UBI_EC_HDR_MAGIC:
                self.bad_pebs += 1
                continue
            ec_info = self._parse_ec(ec, base)
            if ec_info is None:
                self.bad_pebs += 1
                continue
            self.ec_hdrs.append(ec_info)

            voff = self._vid_off if self._vid_off is not None else ec_info["vid_hdr_offset"]
            if not voff or voff + UBI_VID_HDR_SIZE > self.peb_size:
                self.notes.append("PEB %d 的 vid_hdr_offset=%s 不合理" % (i, voff))
                continue
            vid = self.sub.read(base + voff, UBI_VID_HDR_SIZE)
            if len(vid) < UBI_VID_HDR_SIZE:
                continue
            if _be32(vid, 0) != UBI_VID_HDR_MAGIC:
                continue
            vinfo = self._parse_vid(vid, base, voff)
            if vinfo is None:
                continue
            vinfo["peb"] = i
            vinfo["data_start"] = base + (
                self._data_off if self._data_off is not None else ec_info["data_offset"])
            self.vid_hdrs.append(vinfo)
            self._vol_types[vinfo["vol_id"]] = vinfo["vol_type"]

            key = (vinfo["vol_id"], vinfo["lnum"])
            old = self._lebs.get(key)
            if vinfo["data_size"]:
                data = self.sub.read(vinfo["data_start"], vinfo["data_size"])
            else:
                data = b""
            if old is None or vinfo["sqnum"] > old[0]:
                self._lebs[key] = (vinfo["sqnum"], data, vinfo)

    def _parse_ec(self, raw, base):
        version = raw[4]
        ec = _be64(raw, 0x08)
        vid_hdr_offset = _be32(raw, 0x10)
        data_offset = _be32(raw, 0x14)
        image_seq = _be32(raw, 0x18)
        hdr_crc = _be32(raw, 0x3C)
        calc = zlib.crc32(raw[:0x3C]) & 0xFFFFFFFF
        if calc != hdr_crc:
            self.notes.append("PEB@0x%X 的 EC 头 CRC 不过（算得 0x%08X，存 0x%08X）"
                              % (base, calc, hdr_crc))
            return None
        return {"peb_base": base, "version": version, "ec": ec,
                "vid_hdr_offset": vid_hdr_offset, "data_offset": data_offset,
                "image_seq": image_seq, "hdr_crc": hdr_crc}

    def _parse_vid(self, raw, base, voff):
        hdr_crc = _be32(raw, 0x3C)
        calc = zlib.crc32(raw[:0x3C]) & 0xFFFFFFFF
        if calc != hdr_crc:
            self.notes.append("PEB@0x%X 的 VID 头 CRC 不过" % base)
            return None
        return {
            "version": raw[4], "vol_type": raw[5], "copy_flag": raw[6],
            "compat": raw[7],
            "vol_id": _be32(raw, 0x08), "lnum": _be32(raw, 0x0C),
            "data_size": _be32(raw, 0x14), "used_ebs": _be32(raw, 0x18),
            "data_pad": _be32(raw, 0x1C), "data_crc": _be32(raw, 0x20),
            "sqnum": _be64(raw, 0x28), "vid_hdr_crc": hdr_crc,
            "vid_off": voff,
        }

    # ---- 对外 ----
    def info(self):
        vols = {}
        for (vid, lnum), (sq, data, v) in self._lebs.items():
            e = vols.setdefault(vid, {"vol_id": vid, "lebs": 0, "bytes": 0,
                                      "vol_type": v["vol_type"],
                                      "used_ebs": v["used_ebs"]})
            e["lebs"] += 1
            e["bytes"] += len(data)
        return {
            "fs": "ubi",
            "peb_size": self.peb_size,
            "peb_count": self.peb_size and self.size // self.peb_size,
            "ec_headers": len(self.ec_hdrs),
            "vid_headers": len(self.vid_hdrs),
            "blank_pebs": self.blank_pebs,
            "bad_pebs": self.bad_pebs,
            "image_seq": self.ec_hdrs[0]["image_seq"] if self.ec_hdrs else None,
            "volumes": sorted(vols.values(), key=lambda x: x["vol_id"]),
            "notes": list(self.notes),
        }

    def volumes(self):
        return self.info()["volumes"]

    def read_logical(self, vol_id, lnum):
        hit = self._lebs.get((vol_id, lnum))
        return hit[1] if hit else b""

    def read_volume(self, vol_id):
        """按 lnum 升序拼接该卷全部 LEB"""
        keys = sorted(k[1] for k in self._lebs if k[0] == vol_id)
        out = bytearray()
        for lnum in keys:
            out += self._lebs[(vol_id, lnum)][1]
        return bytes(out)

    def volume_sub(self, vol_id):
        """把某个卷包成 read(offset,size)+size 对象，方便喂 Ubifs"""
        return _VolSub(self, vol_id)

    def open_ubifs(self, vol_id=None):
        if vol_id is None:
            for v in self.volumes():
                try:
                    u = Ubifs(self.volume_sub(v["vol_id"]))
                    if u.leb_size:
                        return u
                except Exception:
                    continue
            raise ValueError("没找到可解析的 UBIFS 卷")
        return Ubifs(self.volume_sub(vol_id))


class _VolSub(object):
    """UBI 卷的逻辑视图"""

    def __init__(self, ubi, vol_id):
        self.ubi = ubi
        self.vol_id = vol_id
        self._cache = {}
        keys = sorted(k[1] for k in ubi._lebs if k[0] == vol_id)
        self.lnums = keys
        self._max = (keys[-1] + 1) if keys else 0
        first = keys[0] if keys else 0
        leb = 0
        for v in ubi.vid_hdrs:
            if v["vol_id"] == vol_id:
                leb = v["data_size"] or 0
                break
        # LEB 大小取该卷任一 VID 的 data_size（静态卷）或 PEB 内的可用区
        self.leb_size = leb or (ubi.peb_size - (ubi.ec_hdrs[0]["data_offset"]
                                                if ubi.ec_hdrs else 0))
        self.size = self._max * self.leb_size

    def read(self, off, n):
        if off >= self.size or n <= 0:
            return b""
        n = min(n, self.size - off)
        out = bytearray()
        pos = off
        end = off + n
        while pos < end:
            lnum = pos // self.leb_size
            inner = pos % self.leb_size
            take = min(self.leb_size - inner, end - pos)
            d = self.ubi.read_logical(self.vol_id, lnum)
            seg = d[inner:inner + take]
            out += seg + b"\x00" * (take - len(seg))
            pos += take
        return bytes(out)


# ------------------------------------------------------------
# UBIFS
# ------------------------------------------------------------
class UbiNode(object):
    __slots__ = ("offset", "magic", "crc", "sqnum", "len", "node_type",
                 "group_type", "raw")

    def __init__(self, offset, raw):
        self.offset = offset
        self.raw = raw
        self.magic = _le32(raw, 0)
        self.crc = _le32(raw, 4)
        self.sqnum = _le64(raw, 8)
        self.len = _le32(raw, 16)
        self.node_type = raw[20]
        self.group_type = raw[21]

    @property
    def type_name(self):
        return UBIFS_NODE_TYPE_NAME.get(self.node_type,
                                        "0x%02X" % self.node_type)

    def __repr__(self):
        return "<UbiNode %s off=0x%X sqnum=%d len=%d>" % (
            self.type_name, self.offset, self.sqnum, self.len)


class UbifsEnt(object):
    """一个 UBIFS 目录项 / inode"""

    __slots__ = ("inum", "parent", "name", "dtype", "mode", "size", "uid",
                 "gid", "nlink", "atime", "mtime", "ctime", "compr_type",
                 "inline_data", "sqnum", "orphan_guess")

    def __init__(self):
        self.inum = 0
        self.parent = None
        self.name = ""
        self.dtype = 0
        self.mode = 0
        self.size = 0
        self.uid = 0
        self.gid = 0
        self.nlink = 0
        self.atime = 0
        self.mtime = 0
        self.ctime = 0
        self.compr_type = 0
        self.inline_data = b""
        self.sqnum = 0
        self.orphan_guess = False

    @property
    def is_dir(self):
        return (self.mode & 0o170000) == 0o040000

    @property
    def is_reg(self):
        return (self.mode & 0o170000) == 0o100000

    @property
    def is_link(self):
        return (self.mode & 0o170000) == 0o120000

    def to_dict(self):
        return {"inum": self.inum, "parent": self.parent, "name": self.name,
                "dtype": UBIFS_DT.get(self.dtype, str(self.dtype)),
                "mode": "0o%o" % self.mode, "size": self.size,
                "uid": self.uid, "gid": self.gid, "nlink": self.nlink,
                "mtime": self.mtime, "sqnum": self.sqnum,
                "orphan_guess": self.orphan_guess}

    def __repr__(self):
        return "<UbifsEnt %r inum=%d size=%d>" % (self.name, self.inum, self.size)


class Ubifs(object):
    """UBIFS 只读视图（顺序 LEB 扫描取节点）"""

    def __init__(self, sub):
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.notes = []
        self.lzo_verified = False
        self.sb = None
        self.leb_size = 0
        self.leb_cnt = 0
        self.inodes = {}          # inum -> UbifsEnt
        self.children = {}        # parent inum -> [names]
        self._dent = {}           # (parent, name) -> (sqnum, UbifsEnt)
        self._data = {}           # (inum, block) -> (sqnum, node)
        self._parse_sb()
        self._scan_nodes()
        self._build_tree()

    # ---- 超级块 ----
    def _parse_sb(self):
        head = self.sub.read(0, 256)
        if len(head) < UBIFS_CH_SIZE:
            raise ValueError("UBIFS 超级块读不到（卷太小）")
        if _le32(head, 0) != UBIFS_NODE_MAGIC:
            raise ValueError("不是 UBIFS：节点 magic=0x%08X" % _le32(head, 0))
        if head[20] != UBIFS_SB_NODE:
            raise ValueError("LEB0 首节点 type=%d，不是超级块(6)" % head[20])
        node_len = _le32(head, 16)
        raw = self.sub.read(0, min(node_len, 512))
        if len(raw) < 136:
            raise ValueError("超级块节点不完整")
        self.sb = {
            "key_hash": raw[26], "key_fmt": raw[27],
            "flags": _le32(raw, 28),
            "min_io_size": _le32(raw, 32),
            "leb_size": _le32(raw, 36),
            "leb_cnt": _le32(raw, 40),
            "max_leb_cnt": _le32(raw, 44),
            "max_bud_bytes": _le64(raw, 48),
            "log_lebs": _le32(raw, 56), "lpt_lebs": _le32(raw, 60),
            "orph_lebs": _le32(raw, 64), "jhead_cnt": _le32(raw, 68),
            "fanout": _le32(raw, 72), "lsave_cnt": _le32(raw, 76),
            "fmt_version": _le32(raw, 80),
            "default_compr": _le16(raw, 84),
            "rp_uid": _le32(raw, 88), "rp_gid": _le32(raw, 92),
            "rp_size": _le64(raw, 96),
            "time_gran": _le32(raw, 104),
            "uuid": raw[108:124].hex(),
            "ro_compat_version": _le32(raw, 124),
            "node_len": node_len,
        }
        self.leb_size = self.sb["leb_size"]
        self.leb_cnt = self.sb["leb_cnt"]
        if self.leb_size <= 0 or self.leb_size > 16 * 1024 * 1024:
            raise ValueError("超级块里的 leb_size=%d 不合理" % self.leb_size)

    # ---- 节点扫描 ----
    def _scan_nodes(self):
        """逐 LEB、8 字节对齐找节点；校验 len 与 CRC32"""
        if not self.leb_size:
            return
        nleb = self.leb_cnt or (self.size // self.leb_size)
        for lnum in range(nleb):
            base = lnum * self.leb_size
            if base >= self.size:
                break
            buf = self.sub.read(base, self.leb_size)
            if len(buf) < UBIFS_CH_SIZE:
                continue
            off = 0
            while off + UBIFS_CH_SIZE <= len(buf):
                if _le32(buf, off) != UBIFS_NODE_MAGIC:
                    off += 8
                    continue
                node_len = _le32(buf, off + 16)
                if node_len < UBIFS_CH_SIZE or off + node_len > len(buf):
                    off += 8
                    continue
                raw = buf[off:off + node_len]
                calc = zlib.crc32(raw[8:]) & 0xFFFFFFFF
                if calc != _le32(raw, 4):
                    self.notes.append("LEB %d off 0x%X 的节点 CRC 不过，跳过"
                                      % (lnum, off))
                    off += 8
                    continue
                node = UbiNode(base + off, raw)
                self._collect(node)
                # 节点按 8 字节对齐存放，必须跳到下一个对齐位置，
                # 否则从非对齐偏移起按 +8 步进会永远错过后续节点
                off = (off + node_len + 7) & ~7

    def _collect(self, node):
        t = node.node_type
        if t == UBIFS_INO_NODE:
            self._take_ino(node)
        elif t == UBIFS_DENT_NODE:
            self._take_dent(node)
        elif t == UBIFS_DATA_NODE:
            self._take_data(node)

    @staticmethod
    def _key_inum(raw):
        """key[] 首个 u32 是 inum（simple key format）"""
        return _le32(raw, 24)

    @staticmethod
    def _key_block(raw):
        return _le32(raw, 28)

    def _take_ino(self, node):
        raw = node.raw
        if len(raw) < 136:
            return
        inum = self._key_inum(raw)
        e = UbifsEnt()
        e.inum = inum
        e.size = _le64(raw, 48)
        e.atime = _le64(raw, 56)
        e.ctime = _le64(raw, 64)
        e.mtime = _le64(raw, 72)
        e.nlink = _le32(raw, 92)
        e.uid = _le32(raw, 96)
        e.gid = _le32(raw, 100)
        e.mode = _le32(raw, 104)
        e.compr_type = _le16(raw, 132)
        e.sqnum = _le64(raw, 40)          # creat_sqnum
        data_len = _le32(raw, 112)
        if data_len and 136 + data_len <= len(raw):
            e.inline_data = raw[136:136 + data_len]
        old = self.inodes.get(inum)
        if old is None or e.sqnum >= old.sqnum:
            self.inodes[inum] = e

    def _take_dent(self, node):
        raw = node.raw
        if len(raw) < 56:
            return
        parent = self._key_inum(raw)
        inum = _le64(raw, 40)
        dtype = raw[49]
        nlen = _le16(raw, 50)
        if nlen > 255 or 56 + nlen > len(raw):
            return
        name = raw[56:56 + nlen].decode("utf-8", "replace")
        e = UbifsEnt()
        e.inum = inum
        e.parent = parent
        e.name = name
        e.dtype = dtype
        e.sqnum = node.sqnum
        key = (parent, name)
        old = self._dent.get(key)
        if old is None or node.sqnum >= old[0]:
            self._dent[key] = (node.sqnum, e)

    def _take_data(self, node):
        raw = node.raw
        if len(raw) < 48:
            return
        inum = self._key_inum(raw)
        block = self._key_block(raw)
        key = (inum, block)
        old = self._data.get(key)
        if old is None or node.sqnum >= old[0]:
            self._data[key] = (node.sqnum, node)

    def _build_tree(self):
        for (parent, name), (sq, e) in self._dent.items():
            self.children.setdefault(parent, []).append(name)
            ino = self.inodes.get(e.inum)
            if ino is not None:
                ino.parent = parent
                ino.name = name
                ino.dtype = e.dtype
                if not ino.mode:
                    ino.mode = {4: 0o040755, 8: 0o100644,
                                10: 0o120777}.get(e.dtype, 0)
            else:
                # 只有目录项、没有 inode：多半是 inode 已被回收
                stub = UbifsEnt()
                stub.inum = e.inum
                stub.parent = parent
                stub.name = name
                stub.dtype = e.dtype
                stub.orphan_guess = True
                self.inodes[e.inum] = stub
        for vinum, e in self.inodes.items():
            if e.name or vinum == 1:
                continue
            e.orphan_guess = True

    # ---- 元信息 ----
    def info(self):
        return {
            "fs": "ubifs",
            "key_hash": self.sb["key_hash"], "key_fmt": self.sb["key_fmt"],
            "min_io_size": self.sb["min_io_size"],
            "leb_size": self.sb["leb_size"], "leb_cnt": self.sb["leb_cnt"],
            "max_leb_cnt": self.sb["max_leb_cnt"],
            "log_lebs": self.sb["log_lebs"], "lpt_lebs": self.sb["lpt_lebs"],
            "orph_lebs": self.sb["orph_lebs"],
            "jhead_cnt": self.sb["jhead_cnt"], "fanout": self.sb["fanout"],
            "fmt_version": self.sb["fmt_version"],
            "default_compr": UBIFS_COMPR_NAME.get(self.sb["default_compr"]),
            "rp_uid": self.sb["rp_uid"], "rp_gid": self.sb["rp_gid"],
            "rp_size": self.sb["rp_size"],
            "time_gran": self.sb["time_gran"],
            "uuid": self.sb["uuid"],
            "ro_compat_version": self.sb["ro_compat_version"],
            "inode_count": len(self.inodes),
            "data_blocks": len(self._data),
            "lzo_verified": self.lzo_verified,
            "notes": list(self.notes),
        }

    # ---- 目录 ----
    def listdir(self, inum=1):
        out = []
        for name in self.children.get(inum, []):
            hit = self._dent.get((inum, name))
            if not hit:
                continue
            e = self.inodes.get(hit[1].inum)
            if e is not None:
                out.append(e)
        out.sort(key=lambda x: x.name)
        return out

    def walk(self, inum=1, _depth=0, _max=64, _seen=None):
        if _seen is None:
            _seen = set()
        if inum in _seen or _depth > _max:
            return
        _seen.add(inum)
        for e in self.listdir(inum):
            yield e
            if e.is_dir:
                for sub in self.walk(e.inum, _depth + 1, _max, _seen):
                    yield sub

    def lookup_path(self, path):
        cur = 1
        for part in [p for p in path.split("/") if p]:
            hit = self._dent.get((cur, part))
            if hit is None:
                return None
            cur = hit[1].inum
        return self.inodes.get(cur)

    def find(self, pattern, _max=4096):
        low = pattern.lower()
        out = []
        for e in self.walk():
            if low in e.name.lower():
                out.append(e)
                if len(out) >= _max:
                    break
        return out

    # ---- 读文件 ----
    def read_file(self, ent, limit=None):
        if isinstance(ent, str):
            ent = self.lookup_path(ent)
        if ent is None:
            raise FileNotFoundError("找不到该 inode")
        if ent.is_dir:
            raise IsADirectoryError("inum %d 是目录" % ent.inum)
        if ent.inline_data:
            return ent.inline_data[:limit] if limit else ent.inline_data

        blocks = sorted(k[1] for k in self._data if k[0] == ent.inum)
        out = bytearray()
        for blk in blocks:
            sq, node = self._data[(ent.inum, blk)]
            raw = node.raw
            if len(raw) < 48:
                continue
            usize = _le32(raw, 40)
            ctype = _le16(raw, 44)
            csize = _le16(raw, 46)
            payload = raw[48:48 + csize] if csize else raw[48:]
            out += self._decompress(payload, ctype, usize)
            if limit and len(out) >= limit:
                return bytes(out[:limit])
        return bytes(out[:limit]) if limit else bytes(out)

    def _decompress(self, payload, ctype, usize):
        if ctype == UBIFS_COMPR_NONE:
            return bytes(payload[:usize]) if usize else bytes(payload)
        if ctype == UBIFS_COMPR_ZLIB:
            try:
                d = zlib.decompress(bytes(payload))
            except Exception as e:
                self.notes.append("zlib 解压失败：%s" % e)
                return b""
            return d[:usize] if usize else d
        if ctype == UBIFS_COMPR_LZO:
            # UBIFS 的 LZO 帧：[总长 u16 LE][压缩长 u16 LE][压缩数据]
            if len(payload) < 4:
                return b""
            total = _le16(payload, 0)
            clen = _le16(payload, 2)
            try:
                d = lzo1x_decompress(payload[4:4 + clen], total)
            except Exception as e:
                self.notes.append("LZO 解压失败：%s" % e)
                return b""
            return d[:usize] if usize else d
        if ctype == UBIFS_COMPR_ZSTD:
            raise NotImplementedError(
                "UBIFS 的 zstd 压缩（compr_type=3）本模块未实现")
        raise NotImplementedError("未知 UBIFS 压缩类型 %d" % ctype)


# ------------------------------------------------------------
# 探测 / 打开
# ------------------------------------------------------------
def probe_ubi(sub):
    try:
        head = sub.read(0, 4)
    except Exception:
        return False
    return len(head) >= 4 and _be32(head, 0) == UBI_EC_HDR_MAGIC


def probe_ubifs(sub):
    try:
        head = sub.read(0, 24)
    except Exception:
        return False
    if len(head) < 24:
        return False
    return _le32(head, 0) == UBIFS_NODE_MAGIC and head[20] == UBIFS_SB_NODE


def open_fs(sub, **kw):
    """自动判断 UBI 还是裸 UBIFS"""
    if probe_ubi(sub):
        return Ubi(sub, **kw)
    if probe_ubifs(sub):
        return Ubifs(sub)
    raise ValueError("既不是 UBI 也不像 UBIFS")


# ------------------------------------------------------------
# 自检
# ------------------------------------------------------------
if __name__ == "__main__":
    import io
    import sys

    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    PASS = [0]
    FAIL = [0]

    def ck(cond, name, extra=""):
        if cond:
            PASS[0] += 1
            print("  [PASS] %s %s" % (name, extra))
        else:
            FAIL[0] += 1
            print("  [FAIL] %s %s" % (name, extra))

    class MemSub(object):
        def __init__(self, data):
            self.data = bytes(data)
            self.size = len(self.data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    # ---------- 合成 UBIFS 节点 ----------
    def make_ch(node_type, body, sqnum=1):
        ln = UBIFS_CH_SIZE + len(body)
        head = struct.pack("<IIQIBBH", UBIFS_NODE_MAGIC, 0, sqnum, ln,
                           node_type, 0, 0)
        raw = bytearray(head + body)
        struct.pack_into("<I", raw, 4, zlib.crc32(bytes(raw[8:])) & 0xFFFFFFFF)
        return bytes(raw)

    def make_sb(leb_size, leb_cnt, default_compr=0):
        body = bytearray(136 - UBIFS_CH_SIZE)
        body[26 - UBIFS_CH_SIZE] = 0            # key_hash
        body[27 - UBIFS_CH_SIZE] = 0            # key_fmt
        struct.pack_into("<I", body, 32 - UBIFS_CH_SIZE, 2048)   # min_io_size
        struct.pack_into("<I", body, 36 - UBIFS_CH_SIZE, leb_size)
        struct.pack_into("<I", body, 40 - UBIFS_CH_SIZE, leb_cnt)
        struct.pack_into("<I", body, 44 - UBIFS_CH_SIZE, leb_cnt)
        struct.pack_into("<I", body, 56 - UBIFS_CH_SIZE, 2)      # log_lebs
        struct.pack_into("<I", body, 60 - UBIFS_CH_SIZE, 4)      # lpt_lebs
        struct.pack_into("<I", body, 64 - UBIFS_CH_SIZE, 1)      # orph_lebs
        struct.pack_into("<I", body, 68 - UBIFS_CH_SIZE, 4)      # jhead_cnt
        struct.pack_into("<I", body, 72 - UBIFS_CH_SIZE, 8)      # fanout
        struct.pack_into("<I", body, 80 - UBIFS_CH_SIZE, 5)      # fmt_version
        struct.pack_into("<H", body, 84 - UBIFS_CH_SIZE, default_compr)
        struct.pack_into("<Q", body, 96 - UBIFS_CH_SIZE, 128 * 1024)
        body[108 - UBIFS_CH_SIZE:124 - UBIFS_CH_SIZE] = bytes(range(16))
        return make_ch(UBIFS_SB_NODE, bytes(body), 0)

    def make_ino(inum, mode, size=0, inline_data=b"", compr=0, sqnum=1,
                 mtime=1700000000):
        body = bytearray(136 - UBIFS_CH_SIZE + len(inline_data))
        struct.pack_into("<I", body, 24 - UBIFS_CH_SIZE, inum)      # key[0]
        struct.pack_into("<I", body, 28 - UBIFS_CH_SIZE, 0)         # key[1]
        struct.pack_into("<Q", body, 40 - UBIFS_CH_SIZE, sqnum)     # creat_sqnum
        struct.pack_into("<Q", body, 48 - UBIFS_CH_SIZE, size)
        struct.pack_into("<Q", body, 72 - UBIFS_CH_SIZE, mtime)
        struct.pack_into("<I", body, 92 - UBIFS_CH_SIZE, 1)         # nlink
        struct.pack_into("<I", body, 96 - UBIFS_CH_SIZE, 1000)      # uid
        struct.pack_into("<I", body, 100 - UBIFS_CH_SIZE, 1000)     # gid
        struct.pack_into("<I", body, 104 - UBIFS_CH_SIZE, mode)
        struct.pack_into("<I", body, 112 - UBIFS_CH_SIZE, len(inline_data))
        struct.pack_into("<H", body, 132 - UBIFS_CH_SIZE, compr)
        if inline_data:
            body[136 - UBIFS_CH_SIZE:] = inline_data
        return make_ch(UBIFS_INO_NODE, bytes(body), sqnum)

    def make_dent(parent, name, inum, dtype=8, sqnum=1):
        nb = name.encode()
        body = bytearray(56 - UBIFS_CH_SIZE + len(nb))
        struct.pack_into("<I", body, 24 - UBIFS_CH_SIZE, parent)    # key[0]
        struct.pack_into("<I", body, 28 - UBIFS_CH_SIZE, 0)         # key[1]
        struct.pack_into("<Q", body, 40 - UBIFS_CH_SIZE, inum)
        body[49 - UBIFS_CH_SIZE] = dtype
        struct.pack_into("<H", body, 50 - UBIFS_CH_SIZE, len(nb))
        struct.pack_into("<I", body, 52 - UBIFS_CH_SIZE, 0)
        body[56 - UBIFS_CH_SIZE:] = nb
        return make_ch(UBIFS_DENT_NODE, bytes(body), sqnum)

    def make_data(inum, block, payload, compr=0, usize=None, sqnum=1):
        payload = bytes(payload)
        if usize is None:
            usize = len(payload)
        body = bytearray(48 - UBIFS_CH_SIZE + len(payload))
        struct.pack_into("<I", body, 24 - UBIFS_CH_SIZE, inum)      # key[0]
        struct.pack_into("<I", body, 28 - UBIFS_CH_SIZE, block)     # key[1]
        struct.pack_into("<I", body, 40 - UBIFS_CH_SIZE, usize)
        struct.pack_into("<H", body, 44 - UBIFS_CH_SIZE, compr)
        struct.pack_into("<H", body, 46 - UBIFS_CH_SIZE, len(payload))
        body[48 - UBIFS_CH_SIZE:] = payload
        return make_ch(UBIFS_DATA_NODE, bytes(body), sqnum)

    def pack_leb(nodes, leb_size):
        buf = bytearray(b"\xff" * leb_size)
        off = 0
        for nd in nodes:
            buf[off:off + len(nd)] = nd
            off += len(nd)
            off = (off + 7) & ~7
        return bytes(buf)

    # ---------- 合成 UBI ----------
    PEB = 0x20000
    VID_OFF = 0x40
    DATA_OFF = 0x800
    LEB = PEB - DATA_OFF

    def make_ec(peb_index, ec=5, image_seq=0x1234):
        raw = bytearray(UBI_EC_HDR_SIZE)
        struct.pack_into(">I", raw, 0, UBI_EC_HDR_MAGIC)
        raw[4] = 1
        struct.pack_into(">Q", raw, 0x08, ec)
        struct.pack_into(">I", raw, 0x10, VID_OFF)
        struct.pack_into(">I", raw, 0x14, DATA_OFF)
        struct.pack_into(">I", raw, 0x18, image_seq)
        struct.pack_into(">I", raw, 0x3C, zlib.crc32(bytes(raw[:0x3C])) & 0xFFFFFFFF)
        return bytes(raw)

    def make_vid(vol_id, lnum, vol_type, data_size, sqnum, used_ebs=0):
        raw = bytearray(UBI_VID_HDR_SIZE)
        struct.pack_into(">I", raw, 0, UBI_VID_HDR_MAGIC)
        raw[4] = 1
        raw[5] = vol_type
        struct.pack_into(">I", raw, 0x08, vol_id)
        struct.pack_into(">I", raw, 0x0C, lnum)
        struct.pack_into(">I", raw, 0x14, data_size)
        struct.pack_into(">I", raw, 0x18, used_ebs)
        struct.pack_into(">I", raw, 0x1C, 0)
        struct.pack_into(">I", raw, 0x20, 0)
        struct.pack_into(">Q", raw, 0x28, sqnum)
        struct.pack_into(">I", raw, 0x3C, zlib.crc32(bytes(raw[:0x3C])) & 0xFFFFFFFF)
        return bytes(raw)

    def build_ubi(lebs, npeb=4, vol_id=0, vol_type=UBI_VID_DYNAMIC):
        """lebs: [(lnum, data_bytes)]"""
        img = bytearray(npeb * PEB)
        for i in range(npeb):
            img[i * PEB:i * PEB + PEB] = b"\xff" * PEB
        for idx, (lnum, data) in enumerate(lebs):
            peb = idx
            base = peb * PEB
            img[base:base + UBI_EC_HDR_SIZE] = make_ec(peb)
            vid = make_vid(vol_id, lnum, vol_type, len(data), idx + 1,
                           used_ebs=len(lebs))
            img[base + VID_OFF:base + VID_OFF + UBI_VID_HDR_SIZE] = vid
            img[base + DATA_OFF:base + DATA_OFF + len(data)] = data
        return bytes(img)

    print("=== 1) UBI 层 ===")
    files = {
        "hello.txt": b"Hello UBIFS!\n",
        "big.bin": bytes((i * 11) & 0xFF for i in range(5000)),
        "dir1/inner.txt": b"inner content",
    }
    # 组织成 LEB：LEB0 = SB；LEB1 = 根目录 inode + dent；LEB2.. = 数据
    root_ino = make_ino(1, 0o040755, size=0, inline_data=b"", sqnum=1)
    dents = [
        make_dent(1, "hello.txt", 2, dtype=8, sqnum=2),
        make_dent(1, "big.bin", 3, dtype=8, sqnum=3),
        make_dent(1, "dir1", 4, dtype=4, sqnum=4),
    ]
    ino2 = make_ino(2, 0o100644, size=len(files["hello.txt"]),
                    inline_data=files["hello.txt"], sqnum=2)
    ino3 = make_ino(3, 0o100644, size=len(files["big.bin"]), sqnum=3)
    ino4 = make_ino(4, 0o040755, size=0, sqnum=4)

    leb0 = pack_leb([make_sb(LEB, 6)], LEB)
    leb1 = pack_leb([root_ino] + dents, LEB)
    leb2 = pack_leb([ino2, ino3, ino4,
                     make_dent(4, "inner.txt", 5, dtype=8, sqnum=5)], LEB)
    # big.bin 分两块，第二块用 zlib
    blk0 = files["big.bin"][:4096]
    blk1 = files["big.bin"][4096:]
    z1 = zlib.compress(blk1)
    leb3 = pack_leb([make_data(3, 0, blk0, sqnum=6),
                     make_data(3, 1, z1, compr=UBIFS_COMPR_ZLIB,
                               usize=len(blk1), sqnum=7)], LEB)
    leb4 = pack_leb([make_ino(5, 0o100644, size=len(files["dir1/inner.txt"]),
                              inline_data=files["dir1/inner.txt"], sqnum=5)], LEB)
    leb5 = pack_leb([], LEB)

    img = build_ubi([(0, leb0), (1, leb1), (2, leb2), (3, leb3),
                     (4, leb4), (5, leb5)], npeb=8)
    sub = MemSub(img)

    ck(probe_ubi(sub), "probe_ubi 命中")
    ubi = Ubi(sub)
    inf = ubi.info()
    ck(inf["peb_size"] == PEB, "PEB 大小自动识别", hex(inf["peb_size"]))
    ck(inf["ec_headers"] == 6, "EC 头 6 个", inf["ec_headers"])
    ck(inf["vid_headers"] == 6, "VID 头 6 个", inf["vid_headers"])
    ck(inf["blank_pebs"] == 2, "空白 PEB 2 个", inf["blank_pebs"])
    ck(inf["bad_pebs"] == 0, "坏 PEB 0 个", inf["bad_pebs"])
    ck(inf["image_seq"] == 0x1234, "image_seq", hex(inf["image_seq"]))
    ck(len(inf["volumes"]) == 1, "卷数 1", len(inf["volumes"]))
    ck(inf["volumes"][0]["lebs"] == 6, "卷内 LEB 6 个", inf["volumes"][0]["lebs"])
    ck(inf["volumes"][0]["vol_type"] == UBI_VID_DYNAMIC, "卷类型 dynamic")

    ck(ubi.read_logical(0, 0) == leb0, "read_logical(0,0) 与写入一致")
    ck(len(ubi.read_volume(0)) == 6 * LEB, "read_volume 长度 = 6×LEB",
       len(ubi.read_volume(0)))

    # 坏 EC 头 CRC
    bad = bytearray(img)
    bad[0x3C] ^= 0xFF
    ubi_bad = Ubi(MemSub(bytes(bad)))
    ck(ubi_bad.info()["bad_pebs"] >= 1, "EC 头 CRC 坏时计入 bad_pebs",
       ubi_bad.info()["bad_pebs"])

    print()
    print("=== 2) UBIFS ===")
    vsub = ubi.volume_sub(0)
    ck(probe_ubifs(vsub), "probe_ubifs 命中")
    ub = Ubifs(vsub)
    ui = ub.info()
    ck(ui["leb_size"] == LEB, "leb_size", ui["leb_size"])
    ck(ui["leb_cnt"] == 6, "leb_cnt", ui["leb_cnt"])
    ck(ui["min_io_size"] == 2048, "min_io_size", ui["min_io_size"])
    ck(ui["fanout"] == 8, "fanout", ui["fanout"])
    ck(ui["fmt_version"] == 5, "fmt_version", ui["fmt_version"])
    ck(ui["uuid"] == bytes(range(16)).hex(), "uuid", ui["uuid"])
    ck(ui["lzo_verified"] is False, "lzo_verified 如实标 False")

    ents = ub.listdir(1)
    names = [e.name for e in ents]
    ck(names == ["big.bin", "dir1", "hello.txt"], "根目录 3 项且已排序", names)

    hello = ub.lookup_path("/hello.txt")
    ck(hello is not None and hello.size == len(files["hello.txt"]),
       "/hello.txt 大小", hello.size if hello else None)
    ck(hello is not None and hello.mode == 0o100644, "/hello.txt 权限",
       "0o%o" % hello.mode if hello else None)
    ck(hello is not None and hello.uid == 1000 and hello.gid == 1000,
       "/hello.txt uid/gid")
    ck(ub.read_file(hello) == files["hello.txt"], "inline 文件内容一致",
       ub.read_file(hello))

    big = ub.lookup_path("/big.bin")
    ck(big is not None and ub.read_file(big) == files["big.bin"],
       "跨块文件（含 zlib 块）逐字节还原", len(ub.read_file(big)))
    ck(ub.read_file(big, limit=16) == files["big.bin"][:16], "read_file limit")

    d1 = ub.lookup_path("/dir1")
    ck(d1 is not None and d1.is_dir, "/dir1 是目录")
    inner = ub.listdir(d1.inum)
    ck([e.name for e in inner] == ["inner.txt"], "子目录 1 项",
       [e.name for e in inner])
    ck(ub.read_file(ub.lookup_path("/dir1/inner.txt")) ==
       files["dir1/inner.txt"], "子目录文件内容一致")

    walked = [e.name for e in ub.walk()]
    ck(sorted(walked) == ["big.bin", "dir1", "hello.txt", "inner.txt"],
       "walk 覆盖 4 个条目", walked)
    ck([e.name for e in ub.find("inner")] == ["inner.txt"], "find(inner)")
    ck(ub.lookup_path("/nope") is None, "不存在的路径返回 None")

    print()
    print("=== 3) 去重：同 inode 取最新 creat_sqnum ===")
    dup = pack_leb([
        make_ino(2, 0o100644, size=3, inline_data=b"OLD", sqnum=2),
        make_ino(2, 0o100644, size=4, inline_data=b"NEW!", sqnum=9),
    ], LEB)
    img2 = build_ubi([(0, leb0), (1, leb1), (2, leb2), (3, leb3),
                      (4, dup), (5, leb5)], npeb=8)
    ub2 = Ubifs(Ubi(MemSub(img2)).volume_sub(0))
    h2 = ub2.lookup_path("/hello.txt")
    ck(ub2.read_file(h2) == b"NEW!", "同 inum 取 creat_sqnum 大的版本",
       ub2.read_file(h2))

    print()
    print("=== 4) 只有目录项没有 inode（inode 已回收）===")
    leb_only_dent = pack_leb([make_dent(1, "ghost.txt", 77, dtype=8, sqnum=8)], LEB)
    img3 = build_ubi([(0, leb0), (1, leb1), (2, leb2), (3, leb3),
                      (4, leb4), (5, leb_only_dent)], npeb=8)
    ub3 = Ubifs(Ubi(MemSub(img3)).volume_sub(0))
    g = ub3.lookup_path("/ghost.txt")
    ck(g is not None and g.orphan_guess is True,
       "缺 inode 的目录项被标 orphan_guess", g.name if g else None)

    print()
    print("=== 5) 非 UBI / 截断 / 报错 ===")
    ck(probe_ubi(MemSub(bytes(65536))) is False, "全零不是 UBI")
    ck(probe_ubifs(MemSub(bytes(65536))) is False, "全零不是 UBIFS")
    try:
        open_fs(MemSub(bytes(65536)))
        ck(False, "open_fs 对未知数据应报错")
    except ValueError as e:
        ck(True, "open_fs 未知数据报错", str(e)[:34])
    try:
        Ubifs(MemSub(bytes(65536)))
        ck(False, "Ubifs 对非 UBIFS 应报错")
    except ValueError as e:
        ck(True, "Ubifs 非 UBIFS 报错", str(e)[:34])
    u_zero = Ubi(MemSub(bytes(0)))
    ck(u_zero.info()["ec_headers"] == 0, "零长对象 ec_headers=0")

    print()
    print("=== 6) 节点 CRC 坏时跳过 ===")
    badnode = bytearray(
        pack_leb([make_ino(2, 0o100644, size=3, inline_data=b"XXX", sqnum=2)], LEB))
    badnode[UBIFS_CH_SIZE + 20] ^= 0xFF          # 破坏 inode 载荷
    img4 = build_ubi([(0, leb0), (1, leb1), (2, bytes(badnode)), (3, leb3),
                      (4, leb4), (5, leb5)], npeb=8)
    ub4 = Ubifs(Ubi(MemSub(img4)).volume_sub(0))
    ck(any("CRC 不过" in n for n in ub4.notes), "节点 CRC 坏被记录并跳过",
       (ub4.notes or [""])[0][:40])

    print()
    print("=== 7) zstd 明确抛错 ===")
    zleb = pack_leb([
        make_ino(2, 0o100644, size=100, sqnum=2),
        make_data(2, 0, b"\x00" * 10, compr=UBIFS_COMPR_ZSTD, usize=100, sqnum=3),
    ], LEB)
    img5 = build_ubi([(0, leb0), (1, leb1), (2, zleb), (3, leb3),
                      (4, leb4), (5, leb5)], npeb=8)
    ub5 = Ubifs(Ubi(MemSub(img5)).volume_sub(0))
    try:
        ub5.read_file(ub5.lookup_path("/hello.txt"))
        ck(False, "zstd 压缩应抛 NotImplementedError")
    except NotImplementedError as e:
        ck(True, "zstd 抛 NotImplementedError", str(e)[:40])

    print()
    print("=" * 62)
    print("UBI（EC/VID 头、CRC、空白/坏 PEB、卷重组）/ UBIFS（SB、顺序扫描、")
    print("目录树、inline 与跨块读取、zlib、去重、orphan 标注、zstd 显式拒绝）")
    print("通过 %d 项，失败 %d 项" % (PASS[0], FAIL[0]))
    if FAIL[0]:
        raise SystemExit(1)
    print("ubi 模块自检全部通过")
