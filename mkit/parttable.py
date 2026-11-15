# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""非 x86 分区表解析：APM / BSD disklabel / Amiga RDB

mkit.volume 处理 x86 世界的 MBR/GPT；本模块补齐 Apple 与 Unix/Amiga 生态的
三张分区表，每个分区统一为 dict，字段固定七个，顺序与含义对齐：

    {"index", "offset", "size", "type", "type_id", "name", "scheme"}

`offset`/`size` 一律是字节值（volume 的 `start` 是字节，`sectors`/`size` 是扇区数，
本模块不重复给扇区数），因此可以原地套进镜像切片层：

    for p in parttable.parse_any(dev)[1]:
        fs = SubImage(dev, p["offset"], p["size"])
        fsname = volume.guess_filesystem(dev, p["offset"], p["size"])

`scheme` 取值 "apm" / "bsd" / "amiga"，`type_id` 对 APM 为 None、对 BSD 是
`p_fstype`、对 Amiga 是 dostype（0x444F5303 等），取不到时为 None。

已实现：
    · APM（Apple Partition Map）：块 0 的 DDM（sbSig=0x4552）→ 从块 1 起
      每块一个 `pmSig=0x504D` 表项，偏移一律按 sbBlkSize 换算（不假定 512）
    · BSD disklabel：在子视图偏移 512 与 0 两处探测；`d_magic`/`d_magic2`/
      `d_npartitions`/`d_secsize` 四项联合打分，自动判别小端(0x82564557)与
      大端(0x57455682)两种存放方式；解析 16 字节分区项
    · Amiga RDB：RDSK → `partitionList` 起始的 PART 链（带环检测与步数上限），
      按 lowCyl/highCyl × heads × sectors × blockSize 换算字节
    · Amiga 块校验：u32 大端全块求和应为 0（`amiga_checksum_ok` /
      `amiga_verify` 单独提供，不塞进分区 dict，保持字段与 volume 一致）
    · detect() / parse_any() 自动识别，describe() 表格化输出

不实现：
    · 任何写操作（改表、重建、修复分区、去重叠）
    · Amiga 的 fileSysHeaderList(FSHD) / badBlockList(BADB) / LSEG 引导链
    · Amiga 的 fsd 参数细节（DosEnvec 只取 lowCyl/highCyl/dostype 三项）
    · BSD 的 `d_checksum` 复算、Sun VTOC8 / x86 变体（magic 在 0x1FE 的 PC 标签）
    · APM 的 Apple_Driver* 驱动描述符内容解析、HFS 卷头交叉验证
    · 几何自洽校验：不验证 cylinders×heads×sectors×blockSize 与实际镜像长度一致，
      截断镜像按声明几何照算
    · GPT/MBR（见 mkit.volume）

关于 Amiga 偏移的两套布局：
    权威 `struct RigidDiskBlock` 将 rdb_Cylinders/Sectors/Heads 放在 0x40/0x44/0x48，
    厂商标识在 0xA0/0xA8/0xB8；不少资料把它简写成 0x28/0x2C/0x30 与 0x64/0x6C/0x7C。
    PART 同理：真实 `pb_Environment[]` 从 0x80 起，DE_SIZEBLOCK=0x84、
    DE_LOWCYL=0xA4、DE_HIGHCYL=0xA8；简写资料写作 0x8C/0x94/0x98。
    本模块先按简写偏移读，取不到可信值（high < low、两项全 0）再退回权威偏移，
    两套布局的镜像都能解析，且不会把真实镜像的 env 字段误当柱面号。

只依赖 `read(offset, size)` 与 `size`，可直接喂 mkit.image.SubImage。
"""

import struct

__all__ = [
    "parse_apm", "parse_bsd", "parse_amiga",
    "detect", "parse_any", "describe",
    "amiga_checksum_ok", "amiga_verify",
    "APM_DDM_SIG", "APM_PART_SIG", "BSD_DISKMAGIC", "BSD_DISKMAGIC_BE",
    "BSD_FSTYPES", "AMIGA_DOSTYPES",
]

# ---------------------------------------------------------------- APM
APM_DDM_SIG = 0x4552            # 'ER'
APM_PART_SIG = 0x504D           # 'PM'
APM_DEFAULT_BLK = 512
APM_MAX_PARTS = 256
APM_ENTRY_LEN = 0x88            # 到 pmProcessor 末尾

# ---------------------------------------------------------------- BSD
BSD_DISKMAGIC = 0x82564557      # 小端存放的 DISKMAGIC
BSD_DISKMAGIC_BE = 0x57455682   # 大端存放的同一 magic（磁盘字节相同：57 45 56 82）
BSD_MAGIC_BYTES = b"\x57\x45\x56\x82"
BSD_LABEL_OFFSETS = (512, 0)    # 分区第 2 个扇区优先，其次块 0
BSD_OFF_SECSIZE = 0x28
BSD_OFF_SECPERUNIT = 0x3C
BSD_OFF_MAGIC2 = 0x84
BSD_OFF_NPARTS = 0x8A
BSD_OFF_PARTS = 0x94
BSD_PART_LEN = 16
BSD_MAXPARTITIONS = 22

BSD_FSTYPES = {
    0: "unused", 1: "swap", 2: "version6", 3: "version7", 4: "SysV", 5: "SysV4",
    6: "HPFS", 7: "4.2BSD(FFS)", 8: "MSDOS", 9: "BSD LFS", 10: "NFS",
    11: "ISO9660", 12: "boot(ext)", 13: "boot", 14: "vinum", 15: "HAMMER",
    16: "HAMMER2", 17: "UFS2", 18: "NVMe", 19: "CDFS", 20: "MSDOSFS", 21: "ext2fs",
    22: "NTFS", 23: "ZFS2", 27: "ZFS", 28: "NANDfs",
}

# ---------------------------------------------------------------- Amiga
AMIGA_RDSK = b"RDSK"
AMIGA_PART = b"PART"
AMIGA_BLK = 512
AMIGA_MAX_CHAIN = 64
AMIGA_GEOM_OFFS = (0x40, 0x28)          # 权威在前，简写兜底
AMIGA_VENDOR_OFFS = ((0xA0, 0xA8, 0xB8), (0x64, 0x6C, 0x7C))
AMIGA_PART_NEXT = 0x10
AMIGA_PART_DRIVE = 0x24
AMIGA_PART_ENV = 0x80
AMIGA_PART_CYL_OFFS = ((0x94, 0x98), None)   # None = 走 pb_Environment
AMIGA_DE_SIZEBLOCK = 1
AMIGA_DE_NUMHEADS = 3
AMIGA_DE_SECSPERBLK = 4
AMIGA_DE_BLKSPERTRACK = 5
AMIGA_DE_LOWCYL = 9
AMIGA_DE_HIGHCYL = 10
AMIGA_DE_FILESYS = 14

AMIGA_DOSTYPES = {
    0x444F5300: "DOS\\0(OFS)", 0x444F5301: "DOS\\1(FFS)",
    0x444F5302: "DOS\\2(OFS Intl)", 0x444F5303: "DOS\\3(FFS Intl)",
    0x444F5304: "DOS\\4(OFS DC)", 0x444F5305: "DOS\\5(FFS DC)",
    0x50465300: "PFS\\0", 0x50465301: "PFS\\1", 0x50465302: "PFS\\2",
    0x50465303: "PFS\\3", 0x53465300: "SFS\\0", 0x53465302: "SFS\\2",
    0x4C4E5800: "LNX(Linux)", 0x4D414300: "MAC\\0", 0x46415400: "FAT",
}


# ---------------------------------------------------------------- 工具
def _ascii(raw):
    """定长 ASCII 字段：截到首个 NUL，去尾部空白，非 ASCII 用替换符。"""
    return bytes(raw).split(b"\x00", 1)[0].decode("ascii", "replace").strip()


def _entry(index, offset, size, ptype, type_id, name, scheme):
    """统一的分区 dict：七个键固定，多一个都不加，调用方按 key 取值。"""
    return {
        "index": index,
        "offset": offset,
        "size": size,
        "type": ptype,
        "type_id": type_id,
        "name": name,
        "scheme": scheme,
    }


def _blk_ok(blk):
    """块大小合理性（128..65536 且为 2 的幂）。"""
    return 128 <= blk <= 65536 and (blk & (blk - 1)) == 0


# ---------------------------------------------------------------- APM
def parse_apm(sub):
    """解析 Apple Partition Map。

    DDM 在块 0（`sbSig=0x4552`），分区表项从块 1 起每块一项，
    直到 `pmSig != 0x504D` 或已取得 `pmMapBlkCnt` 项。
    偏移 = pmPyPartStart * sbBlkSize，大小 = pmPartBlkCnt * sbBlkSize。
    """
    parts = []
    ddm = sub.read(0, 0x200)
    if len(ddm) < 0x12:
        return parts
    if struct.unpack_from(">H", ddm, 0)[0] != APM_DDM_SIG:
        return parts

    blk = struct.unpack_from(">H", ddm, 0x02)[0]
    if not _blk_ok(blk):
        blk = APM_DEFAULT_BLK
    declared = struct.unpack_from(">I", ddm, 0x04)[0]     # sbBlkCount，仅作参考

    total = None
    for i in range(APM_MAX_PARTS):
        blkno = i + 1
        if blkno * blk >= sub.size:
            break
        ent = sub.read(blkno * blk, max(APM_ENTRY_LEN, blk))
        if len(ent) < APM_ENTRY_LEN:
            break
        if struct.unpack_from(">H", ent, 0)[0] != APM_PART_SIG:
            break
        map_cnt = struct.unpack_from(">I", ent, 0x04)[0]
        if total is None:
            total = map_cnt
        start, count = struct.unpack_from(">II", ent, 0x08)
        name = _ascii(ent[0x10:0x30])
        ptype = _ascii(ent[0x30:0x50]) or name or "unknown"
        parts.append(_entry(len(parts), start * blk, count * blk,
                            ptype, None, name, "apm"))
        if total and len(parts) >= total:
            break
        if declared and start >= declared and count == 0:
            break
    return parts


# ---------------------------------------------------------------- BSD
def _bsd_probe(sub, base):
    """在 base 处验 BSD disklabel，返回 (score, fmt, magic, nparts) 或 None。

    `57 45 56 82` 这四字节按小端读是 0x82564557、按大端读是 0x57455682，
    单看 d_magic 无法定端序，所以用 d_magic2 一致、d_npartitions 合理、
    d_secsize 是 2 的幂、d_secperunit 非零四项打分。
    """
    head = sub.read(base, BSD_OFF_PARTS)
    if len(head) < BSD_OFF_PARTS:
        return None
    if head[:4] != BSD_MAGIC_BYTES:
        return None
    best = None
    for fmt, magic in (("<", BSD_DISKMAGIC), (">", BSD_DISKMAGIC_BE)):
        if struct.unpack_from(fmt + "I", head, 0)[0] != magic:
            continue
        score = 0
        if struct.unpack_from(fmt + "I", head, BSD_OFF_MAGIC2)[0] == magic:
            score += 2
        nparts = struct.unpack_from(fmt + "H", head, BSD_OFF_NPARTS)[0]
        if 1 <= nparts <= BSD_MAXPARTITIONS:
            score += 3
        secsize = struct.unpack_from(fmt + "I", head, BSD_OFF_SECSIZE)[0]
        if _blk_ok(secsize):
            score += 2
        if struct.unpack_from(fmt + "I", head, BSD_OFF_SECPERUNIT)[0]:
            score += 1
        if best is None or score > best[0]:
            best = (score, fmt, magic, nparts)
    return best


def parse_bsd(sub, part_offset=0):
    """解析 BSD disklabel。

    探测顺序：子视图偏移 512（分区第 2 个扇区）→ 偏移 0。
    `part_offset` 是子视图在父镜像中的起始偏移，非 0 时结果换算回父镜像坐标
    （默认 0，即返回相对 `sub` 的偏移）。
    只收录 p_size != 0 的项；BSD 既有的 a/b/c 约定不剔除，字母即 name。
    """
    parts = []
    found = None
    for base in BSD_LABEL_OFFSETS:
        probe = _bsd_probe(sub, base)
        if probe is not None and probe[0] >= 3:
            found = (base,) + probe
            break
    if found is None:
        return parts

    base, _score, fmt, _magic, nparts = found
    head = sub.read(base, BSD_OFF_PARTS)
    secsize = struct.unpack_from(fmt + "I", head, BSD_OFF_SECSIZE)[0]
    if not _blk_ok(secsize):
        secsize = 512
    nparts = min(nparts, BSD_MAXPARTITIONS)
    if nparts <= 0:
        return parts

    raw = sub.read(base + BSD_OFF_PARTS, nparts * BSD_PART_LEN)
    for i in range(nparts):
        ent = raw[i * BSD_PART_LEN:(i + 1) * BSD_PART_LEN]
        if len(ent) < BSD_PART_LEN:
            break
        p_size, p_offset, _p_fsize, p_fstype, _frag, _cpg = \
            struct.unpack_from(fmt + "IIIBBH", ent, 0)
        if p_size == 0:
            continue
        letter = chr(0x61 + i) if i < 16 else "p%d" % i
        parts.append(_entry(len(parts), part_offset + p_offset * secsize,
                            p_size * secsize,
                            BSD_FSTYPES.get(p_fstype, "fstype-%d" % p_fstype),
                            p_fstype, letter, "bsd"))
    return parts


# ---------------------------------------------------------------- Amiga
def _sum32(buf):
    """整块 u32 大端求和（Amiga 的 chkSum 取该和的相反数）。"""
    end = len(buf) - (len(buf) % 4)
    total = 0
    for off in range(0, end, 4):
        total = (total + struct.unpack_from(">I", buf, off)[0]) & 0xFFFFFFFF
    return total


def amiga_checksum_ok(buf):
    """RDB / PART 块校验：全块 u32 大端求和为 0 即通过。"""
    if len(buf) < 4:
        return False
    return _sum32(buf) == 0


def _amiga_seal(buf):
    """把一个 Amiga 块（bytearray）的 chkSum 补齐，使全块求和为 0。自检用。"""
    struct.pack_into(">I", buf, 0x08, 0)
    struct.pack_into(">I", buf, 0x08, (0x100000000 - _sum32(buf)) & 0xFFFFFFFF)
    return buf


def _env_word(pb, idx):
    """pb_Environment[idx]：高 16 位是标志/打包位，值取低 16 位；未打包则原值。"""
    off = AMIGA_PART_ENV + idx * 4
    if len(pb) < off + 4:
        return 0
    word = struct.unpack_from(">I", pb, off)[0]
    return word if (word >> 16) == 0 else (word & 0xFFFF)


def _env_u32(pb, idx):
    """取完整 32 位（dostype 这类不许截断的字段）。"""
    off = AMIGA_PART_ENV + idx * 4
    if len(pb) < off + 4:
        return 0
    return struct.unpack_from(">I", pb, off)[0]


def _amiga_geometry(rdb):
    """返回 (cylinders, sectors, heads, 实际命中的偏移)。"""
    for off in AMIGA_GEOM_OFFS:
        if len(rdb) < off + 12:
            continue
        cyl, sec, hd = struct.unpack_from(">III", rdb, off)
        if 0 < cyl <= 0x100000 and 0 < sec <= 0x10000 and 0 < hd <= 0x10000:
            return cyl, sec, hd, off
    return 0, 0, 0, AMIGA_GEOM_OFFS[0]


def _amiga_cyl_range(pb):
    """返回 (lowCyl, highCyl)；简写偏移不可信时退回 pb_Environment。"""
    cands = []
    for pair in AMIGA_PART_CYL_OFFS:
        if pair is None:
            cands.append((_env_word(pb, AMIGA_DE_LOWCYL),
                          _env_word(pb, AMIGA_DE_HIGHCYL)))
        elif len(pb) >= pair[1] + 4:
            cands.append((struct.unpack_from(">I", pb, pair[0])[0],
                          struct.unpack_from(">I", pb, pair[1])[0]))
    for low, high in cands:
        if (low or high) and high >= low and high < 0x1000000:
            return low, high
    return 0, 0


def _amiga_drive_name(pb):
    """pb_DriveName：首字节为长度（含 4 字节长度本身），名字从 +4 起。"""
    raw = pb[AMIGA_PART_DRIVE:AMIGA_PART_DRIVE + 32]
    if not raw:
        return ""
    n = raw[0]
    if 4 <= n <= 32:
        name = _ascii(raw[4:n])
        if name:
            return name
    return _ascii(raw[4:])


def _amiga_vendor(rdb):
    """厂商标识三元组 (vendor, product, revision)。"""
    for offs in AMIGA_VENDOR_OFFS:
        if len(rdb) < offs[2] + 4:
            continue
        vendor = _ascii(rdb[offs[0]:offs[0] + 8])
        product = _ascii(rdb[offs[1]:offs[1] + 16])
        if vendor or product:
            return vendor, product, _ascii(rdb[offs[2]:offs[2] + 4])
    return "", "", ""


def parse_amiga(sub):
    """解析 Amiga RDB。

    块 0 为 `RDSK`，其 `partitionList`（0x1C）指向第一个 `PART` 块；
    沿 `next`（0x10）走链，`next == 0` 结束。
    偏移 = lowCyl × heads × sectors × blockSize，
    大小 = (highCyl − lowCyl + 1) × heads × sectors × blockSize。
    """
    parts = []
    rdb = sub.read(0, AMIGA_BLK)
    if len(rdb) < 0x20 or rdb[:4] != AMIGA_RDSK:
        return parts

    blk = struct.unpack_from(">I", rdb, 0x10)[0]
    if not _blk_ok(blk):
        blk = AMIGA_BLK
    cyl, sec, hd, _off = _amiga_geometry(rdb)
    if not (cyl and sec and hd):
        return parts
    cyl_bytes = sec * hd * blk

    cur = struct.unpack_from(">I", rdb, 0x1C)[0]
    seen = set()
    while cur and cur not in seen and len(parts) < AMIGA_MAX_CHAIN:
        if cur * blk >= sub.size:
            break
        seen.add(cur)
        pb = sub.read(cur * blk, blk)
        if len(pb) < 0xA8 or pb[:4] != AMIGA_PART:
            break
        nxt = struct.unpack_from(">I", pb, AMIGA_PART_NEXT)[0]
        low, high = _amiga_cyl_range(pb)
        dostype = _env_u32(pb, AMIGA_DE_FILESYS)
        if high >= low and (low or high):
            offset = low * cyl_bytes
            size = (high - low + 1) * cyl_bytes
        else:
            offset = 0
            size = 0
        parts.append(_entry(len(parts), offset, size,
                            AMIGA_DOSTYPES.get(dostype, "PART") if dostype else "PART",
                            dostype or None, _amiga_drive_name(pb), "amiga"))
        cur = nxt
    return parts


def amiga_verify(sub):
    """RDB / PART 链的校验和与几何概况（写操作前的可信度核对用）。"""
    out = {"rdsk": False, "part": [], "blocks": 0, "geometry": None, "vendor": None}
    rdb = sub.read(0, AMIGA_BLK)
    if len(rdb) < AMIGA_BLK or rdb[:4] != AMIGA_RDSK:
        return out
    blk = struct.unpack_from(">I", rdb, 0x10)[0]
    if not _blk_ok(blk):
        blk = AMIGA_BLK
    out["rdsk"] = amiga_checksum_ok(rdb)
    cyl, sec, hd, off = _amiga_geometry(rdb)
    out["geometry"] = {"cylinders": cyl, "sectors": sec, "heads": hd,
                       "block_size": blk, "geom_offset": off}
    out["vendor"] = _amiga_vendor(rdb)
    cur = struct.unpack_from(">I", rdb, 0x1C)[0]
    seen = set()
    while cur and cur not in seen and len(out["part"]) < AMIGA_MAX_CHAIN:
        if cur * blk >= sub.size:
            break
        seen.add(cur)
        pb = sub.read(cur * blk, blk)
        if len(pb) < 0xA8 or pb[:4] != AMIGA_PART:
            break
        out["part"].append(amiga_checksum_ok(pb))
        out["blocks"] += 1
        cur = struct.unpack_from(">I", pb, AMIGA_PART_NEXT)[0]
    return out


# ---------------------------------------------------------------- 自动识别
def detect(sub):
    """返回 "apm" / "bsd" / "amiga" / "unknown"。"""
    head = sub.read(0, 0x200)
    if len(head) >= 0x12 and struct.unpack_from(">H", head, 0)[0] == APM_DDM_SIG:
        blk = struct.unpack_from(">H", head, 0x02)[0]
        if not _blk_ok(blk):
            blk = APM_DEFAULT_BLK
        sig = sub.read(blk, 2)
        if len(sig) == 2 and struct.unpack(">H", sig)[0] == APM_PART_SIG:
            return "apm"
    if head[:4] == AMIGA_RDSK:
        return "amiga"
    for base in BSD_LABEL_OFFSETS:
        probe = _bsd_probe(sub, base)
        if probe is not None and probe[0] >= 3:
            return "bsd"
    return "unknown"


def parse_any(sub):
    """自动识别并解析，返回 (scheme, parts)。"""
    scheme = detect(sub)
    if scheme == "apm":
        return scheme, parse_apm(sub)
    if scheme == "bsd":
        return scheme, parse_bsd(sub)
    if scheme == "amiga":
        return scheme, parse_amiga(sub)
    return "unknown", []


def describe(layout):
    """把分区列表排成对齐表格（字符串），空列表给出占位说明。"""
    if not layout:
        return "(无分区项)"
    rows = [("#", "scheme", "offset", "size", "type", "type_id", "name")]
    for p in layout:
        tid = p.get("type_id")
        if tid is None:
            tid_s = "-"
        elif isinstance(tid, int):
            tid_s = "0x%x" % tid
        else:
            tid_s = str(tid)
        rows.append((str(p.get("index", 0)), str(p.get("scheme", "")),
                     "0x%x" % int(p.get("offset", 0)), str(p.get("size", 0)),
                     str(p.get("type", "")), tid_s, str(p.get("name", ""))))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = []
    for n, row in enumerate(rows):
        cells = [row[i].ljust(widths[i]) for i in range(len(row))]
        line = "  ".join(cells).rstrip()
        lines.append(line)
        if n == 0:
            lines.append("-" * len(line))
    lines.append("共 %d 项，覆盖 %d 字节" % (len(layout), sum(int(p.get("size", 0)) for p in layout)))
    return "\n".join(lines)


# ---------------------------------------------------------------- 自检
if __name__ == "__main__":
    class _Mem(object):
        """最小只读视图，接口与 mkit.image.SubImage 一致（read / size）。"""

        def __init__(self, data):
            self.d = bytes(data)
            self.size = len(self.d)

        def read(self, offset, size):
            if offset < 0 or size <= 0 or offset >= self.size:
                return b""
            return self.d[offset:offset + size]

    def _mk_apm(blk, entries, nblk):
        img = bytearray(blk * nblk)
        struct.pack_into(">H", img, 0x00, APM_DDM_SIG)
        struct.pack_into(">H", img, 0x02, blk)
        struct.pack_into(">I", img, 0x04, nblk)
        struct.pack_into(">H", img, 0x08, 1)
        struct.pack_into(">H", img, 0x0A, 1)
        struct.pack_into(">I", img, 0x0C, 0)
        struct.pack_into(">H", img, 0x10, 0)
        for i, (start, count, name, ptype) in enumerate(entries):
            o = (i + 1) * blk
            struct.pack_into(">H", img, o + 0x00, APM_PART_SIG)
            struct.pack_into(">H", img, o + 0x02, 1)
            struct.pack_into(">I", img, o + 0x04, len(entries))
            struct.pack_into(">I", img, o + 0x08, start)
            struct.pack_into(">I", img, o + 0x0C, count)
            img[o + 0x10:o + 0x30] = name.encode("ascii").ljust(32, b"\x00")
            img[o + 0x30:o + 0x50] = ptype.encode("ascii").ljust(32, b"\x00")
            struct.pack_into(">I", img, o + 0x50, 0)
            struct.pack_into(">I", img, o + 0x54, count)
            struct.pack_into(">I", img, o + 0x58, 0x07 if i == 0 else 0x33)
            struct.pack_into(">I", img, o + 0x5C, 0)
            struct.pack_into(">I", img, o + 0x60, 0)
            img[o + 0x78:o + 0x88] = b"PowerPC".ljust(16, b"\x00")
        return bytes(img)

    def _mk_bsd(be, base, secsize, parts_spec, nparts):
        fmt = ">" if be else "<"
        magic = BSD_DISKMAGIC_BE if be else BSD_DISKMAGIC
        img = bytearray(base + BSD_OFF_PARTS + nparts * BSD_PART_LEN + 0x400)
        o = base
        struct.pack_into(fmt + "I", img, o + 0x00, magic)
        struct.pack_into(fmt + "H", img, o + 0x04, 0)
        struct.pack_into(fmt + "H", img, o + 0x06, 0)
        img[o + 0x08:o + 0x18] = b"auto".ljust(16, b"\x00")
        img[o + 0x18:o + 0x28] = b"esk".ljust(16, b"\x00")
        struct.pack_into(fmt + "I", img, o + 0x28, secsize)
        struct.pack_into(fmt + "I", img, o + 0x2C, secsize)
        struct.pack_into(fmt + "I", img, o + 0x30, 2)
        struct.pack_into(fmt + "I", img, o + 0x34, 8)
        struct.pack_into(fmt + "I", img, o + 0x38, secsize * 2)
        struct.pack_into(fmt + "I", img, o + 0x3C, secsize * 16)
        struct.pack_into(fmt + "H", img, o + 0x40, 0)
        struct.pack_into(fmt + "H", img, o + 0x42, 0)
        struct.pack_into(fmt + "I", img, o + 0x44, 0)
        struct.pack_into(fmt + "H", img, o + 0x48, 3600)
        struct.pack_into(fmt + "H", img, o + 0x4A, 1)
        struct.pack_into(fmt + "H", img, o + 0x4C, 0)
        struct.pack_into(fmt + "H", img, o + 0x4E, 0)
        struct.pack_into(fmt + "I", img, o + 0x50, 0)
        struct.pack_into(fmt + "I", img, o + 0x54, 0)
        struct.pack_into(fmt + "I", img, o + 0x58, 0)
        struct.pack_into(fmt + "I", img, o + 0x84, magic)
        struct.pack_into(fmt + "H", img, o + 0x88, 0)
        struct.pack_into(fmt + "H", img, o + 0x8A, nparts)
        struct.pack_into(fmt + "I", img, o + 0x8C, 8192)
        struct.pack_into(fmt + "I", img, o + 0x90, 2048)
        for i, (psize, poff, fstype) in enumerate(parts_spec):
            e = o + BSD_OFF_PARTS + i * BSD_PART_LEN
            struct.pack_into(fmt + "I", img, e + 0x00, psize)
            struct.pack_into(fmt + "I", img, e + 0x04, poff)
            struct.pack_into(fmt + "I", img, e + 0x08, 1024)
            img[e + 0x0C] = fstype
            img[e + 0x0D] = 8
            struct.pack_into(fmt + "H", img, e + 0x0E, 16)
        return bytes(img)

    def _mk_amiga(layout, cyls, heads, sectors, chain, dostype):
        blk = AMIGA_BLK
        img = bytearray(cyls * heads * sectors * blk)
        rdb = bytearray(blk)
        rdb[0:4] = AMIGA_RDSK
        struct.pack_into(">I", rdb, 0x04, 64)
        struct.pack_into(">I", rdb, 0x0C, 7)
        struct.pack_into(">I", rdb, 0x10, blk)
        struct.pack_into(">I", rdb, 0x14, 0x17)
        struct.pack_into(">I", rdb, 0x18, 0)
        struct.pack_into(">I", rdb, 0x1C, chain[0][0])
        struct.pack_into(">I", rdb, 0x20, 0)
        struct.pack_into(">I", rdb, 0x24, 0)
        geom_off = AMIGA_GEOM_OFFS[0] if layout == "canonical" else AMIGA_GEOM_OFFS[1]
        struct.pack_into(">III", rdb, geom_off, cyls, sectors, heads)
        voff = AMIGA_VENDOR_OFFS[0] if layout == "canonical" else AMIGA_VENDOR_OFFS[1]
        rdb[voff[0]:voff[0] + 8] = b"ESK     "
        rdb[voff[1]:voff[1] + 16] = b"SynthDisk".ljust(16, b"\x00")
        rdb[voff[2]:voff[2] + 4] = b"1.0 "
        _amiga_seal(rdb)
        img[0:blk] = rdb
        for blkno, nxt, low, high, drive in chain:
            pb = bytearray(blk)
            pb[0:4] = AMIGA_PART
            struct.pack_into(">I", pb, 0x04, 128)
            struct.pack_into(">I", pb, 0x0C, 7)
            struct.pack_into(">I", pb, 0x10, nxt)
            struct.pack_into(">I", pb, 0x14, 0x02)
            struct.pack_into(">I", pb, 0x24, ((len(drive) + 4) << 24) | 1)
            pb[0x28:0x28 + len(drive)] = drive.encode("ascii")
            if layout == "canonical":
                struct.pack_into(">I", pb, AMIGA_PART_ENV + AMIGA_DE_SIZEBLOCK * 4, 2)
                struct.pack_into(">I", pb, AMIGA_PART_ENV + AMIGA_DE_NUMHEADS * 4, heads)
                struct.pack_into(">I", pb, AMIGA_PART_ENV + AMIGA_DE_SECSPERBLK * 4, 1)
                struct.pack_into(">I", pb, AMIGA_PART_ENV + AMIGA_DE_BLKSPERTRACK * 4, sectors)
                struct.pack_into(">I", pb, AMIGA_PART_ENV + AMIGA_DE_LOWCYL * 4, low)
                struct.pack_into(">I", pb, AMIGA_PART_ENV + AMIGA_DE_HIGHCYL * 4, high)
                struct.pack_into(">I", pb, AMIGA_PART_ENV + AMIGA_DE_FILESYS * 4, dostype)
            else:
                struct.pack_into(">I", pb, 0x8C, 2)
                struct.pack_into(">I", pb, 0x94, low)
                struct.pack_into(">I", pb, 0x98, high)
            _amiga_seal(pb)
            img[blkno * blk:(blkno + 1) * blk] = pb
        return bytes(img)

    print("=" * 62)
    print("mkit.parttable 自检")
    print("=" * 62)

    # ---- APM
    apm_entries = [(1, 2, "Apple", "Apple_partition_map"),
                   (3, 40, "MacHD", "Apple_HFS")]
    apm = _Mem(_mk_apm(512, apm_entries, 64))
    p = parse_apm(apm)
    assert len(p) == 2, "APM 项数应为 2，实际 %d" % len(p)
    assert p[0]["type"] == "Apple_partition_map", p[0]["type"]
    assert p[1]["type"] == "Apple_HFS", p[1]["type"]
    assert p[0]["offset"] == 512 and p[0]["size"] == 1024, p[0]
    assert p[1]["offset"] == 3 * 512 and p[1]["size"] == 40 * 512, p[1]
    assert all(x["scheme"] == "apm" for x in p), "scheme 应为 apm"
    assert all(x["index"] == i for i, x in enumerate(p)), "index 应连续"
    apm2 = _Mem(_mk_apm(1024, apm_entries, 40))
    p2 = parse_apm(apm2)
    assert p2[1]["offset"] == 3 * 1024, "块大小 1024 时偏移应随 sbBlkSize 缩放"
    assert p2[1]["size"] == 40 * 1024, "块大小 1024 时大小应随 sbBlkSize 缩放"
    assert detect(apm) == "apm", detect(apm)
    print("APM    : 项=%d  blkSize=%d/%d  偏移=%d,%d  detect=%s"
          % (len(p), 512, 1024, p[1]["offset"], p2[1]["offset"], detect(apm)))

    # ---- BSD
    bsd_parts = [(2048, 0, 7), (1024, 2048, 8), (2048, 3072, 7)]
    bsd = _Mem(_mk_bsd(False, 512, 512, bsd_parts, 8))
    q = parse_bsd(bsd)
    assert len(q) == 3, "BSD 项数应为 3，实际 %d" % len(q)
    assert q[0]["type_id"] == 7 and q[0]["type"] == "4.2BSD(FFS)", q[0]
    assert q[1]["type_id"] == 8 and q[1]["type"] == "MSDOS", q[1]
    assert q[0]["offset"] == 0 and q[0]["size"] == 2048 * 512, q[0]
    assert q[1]["offset"] == 2048 * 512 and q[1]["size"] == 1024 * 512, q[1]
    assert q[2]["offset"] == 3072 * 512 and q[2]["size"] == 2048 * 512, q[2]
    assert [x["name"] for x in q] == ["a", "b", "c"], [x["name"] for x in q]
    assert all(x["scheme"] == "bsd" for x in q), "scheme 应为 bsd"
    q_be = parse_bsd(_Mem(_mk_bsd(True, 512, 4096, bsd_parts, 8)))
    assert len(q_be) == 3, "大端标签应解析出 3 项"
    assert q_be[1]["offset"] == 2048 * 4096, "大端 d_secsize 换算错"
    q0 = parse_bsd(_Mem(_mk_bsd(False, 0, 512, bsd_parts, 8)))
    assert len(q0) == 3, "标签在块 0 时应解析出 3 项"
    assert q0[1]["offset"] == 2048 * 512, "块 0 标签偏移错"
    q_off = parse_bsd(bsd, part_offset=0x100000)
    assert q_off[1]["offset"] == 0x100000 + 2048 * 512, "part_offset 未叠加"
    assert detect(bsd) == "bsd", detect(bsd)
    print("BSD    : 项=%d  端序=LE/BE 均可  secsize=512/4096  detect=%s"
          % (len(q), detect(bsd)))
    print("         %s" % " | ".join("%s@0x%x+0x%x(%s)"
                                    % (x["name"], x["offset"], x["size"], x["type"])
                                    for x in q))

    # ---- Amiga
    chain = [(1, 2, 1, 3, "DH0"), (2, 0, 4, 7, "DH1")]
    dostype = 0x444F5303
    rz = 2 * 16 * 512
    for layout in ("canonical", "compact"):
        am = _Mem(_mk_amiga(layout, 8, 2, 16, chain, dostype))
        r = parse_amiga(am)
        assert len(r) == 2, "%s: PART 链应走出 2 项，实际 %d" % (layout, len(r))
        assert r[0]["offset"] == 1 * rz and r[0]["size"] == 3 * rz, (layout, r[0])
        assert r[1]["offset"] == 4 * rz and r[1]["size"] == 4 * rz, (layout, r[1])
        assert [x["name"] for x in r] == ["DH0", "DH1"], [x["name"] for x in r]
        if layout == "canonical":
            # 简写布局没有 dostype 位，只有权威布局能取到
            assert r[0]["type_id"] == dostype and r[0]["type"].startswith("DOS"), r[0]
        else:
            assert r[0]["type_id"] is None and r[0]["type"] == "PART", r[0]
        assert all(x["scheme"] == "amiga" for x in r), "scheme 应为 amiga"
        ver = amiga_verify(am)
        assert ver["rdsk"] is True, "%s: RDB 校验和未通过" % layout
        assert ver["part"] == [True, True], "%s: PART 校验和未通过 %r" % (layout, ver["part"])
        assert ver["blocks"] == 2, "%s: 链表长度错 %d" % (layout, ver["blocks"])
        assert ver["geometry"]["cylinders"] == 8 and ver["geometry"]["heads"] == 2, ver["geometry"]
        assert detect(am) == "amiga", detect(am)
    # 破坏一个字节，校验和必须失败
    am_bad = bytearray(_mk_amiga("canonical", 8, 2, 16, chain, dostype))
    am_bad[0x1C] ^= 0xFF
    assert amiga_checksum_ok(bytes(am_bad[0:512])) is False, "篡改后校验和应失败"
    print("Amiga  : 项=%d  两种布局一致  链表 DH0->DH1(next=0)  chkSum RDB=%s PART=%r"
          % (len(parse_amiga(_Mem(_mk_amiga("canonical", 8, 2, 16, chain, dostype)))),
             amiga_verify(_Mem(_mk_amiga("canonical", 8, 2, 16, chain, dostype)))["rdsk"],
             amiga_verify(_Mem(_mk_amiga("canonical", 8, 2, 16, chain, dostype)))["part"]))

    # ---- parse_any / describe
    amiga = _Mem(_mk_amiga("canonical", 8, 2, 16, chain, dostype))
    for name, dev, want in (("apm", apm, "apm"), ("bsd", bsd, "bsd"),
                            ("amiga", amiga, "amiga")):
        scheme, lay = parse_any(dev)
        assert scheme == want, "parse_any 识别 %s 得 %s" % (want, scheme)
        assert lay and all(x["scheme"] == want for x in lay), "%s 分区项异常" % want
    assert detect(_Mem(b"\x00" * 4096)) == "unknown", "空镜像应为 unknown"
    assert parse_any(_Mem(b"\x00" * 4096)) == ("unknown", []), "unknown 应返回空表"
    txt = describe(parse_any(apm)[1])
    assert isinstance(txt, str) and "apm" in txt and "Apple_HFS" in txt, txt
    assert describe([]) == "(无分区项)", describe([])
    print("-" * 62)
    print("describe() 输出示例：")
    print(describe(parse_any(amiga)[1]))
    print("-" * 62)
    print("自检通过：APM / BSD / Amiga 三张表 + detect + parse_any + describe")
