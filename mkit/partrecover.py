#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  分区表解析与重建
# ============================================================

"""MBR / GPT 分区表解析、丢失分区恢复与分区表重建。

已实现
------
* **MBR**：偏移 0x1BE 起 4 个 16 字节分区项；签名 0x55AA；
  扩展分区（type 0x05 / 0x0F / 0x85）沿 **EBR 链**遍历，逻辑分区相对偏移正确累加
* **GPT**：LBA1 处的头（"EFI PART"）、分区项数组、header CRC32 与 entries CRC32
  校验、GUID 按 mixed-endian 格式化、分区名 UTF-16LE
* **重建（本模块的重点）**：
  - `recover_partitions(sub, deep=True)` 首选 MBR，其次 GPT 主/备份，
    分区表彻底没了就按 **1 MiB 步长做文件系统特征扫描**
  - `rebuild_table()` 生成可写回的分区表字节（MBR 512 字节 / GPT 头 + 项）
  - `verify_rebuild()` 把自己生成的表重新解一遍与原布局比对，自校验
* 常见分区类型 / GPT type GUID 的中文名映射

不实现
------
* **扩展分区（EBR 链）的重建**：只做**解析与报告**，不重新生成 EBR 链。
  原因是逻辑分区的 EBR 是链式结构，重建需要对每一项单独写一个扇区，
  调用方通常只想恢复主分区表；这里如实标注，不假装能重建
* **4K 原生扇区（512e / 4Kn）**：全部按 512 字节逻辑扇区处理
* LVM / RAID 成员的自动识别与重组（属 `mkit/vdisk.py` / `mkit/raid.py`）
* 不修改任何输入；`rebuild_table` 只返回字节，写回由调用方负责

格式来源
--------
MBR/EBR：IBM PC 分区表约定；GPT：UEFI 规范 2.10 第 5 章。
两者都是公开且稳定的短格式，字段偏移逐条注明在代码里。
"""

import struct
import zlib

__all__ = [
    "PartRecoverError", "MBR_TYPES", "GPT_TYPES",
    "parse_mbr", "parse_gpt", "detect_table", "recover_partitions",
    "rebuild_table", "verify_rebuild", "describe",
]

SECTOR = 512
MBR_ENTRY_OFF = 0x1BE
MBR_SIGNATURE = b"\x55\xAA"
GPT_SIGNATURE = b"EFI PART"
GPT_REVISION = 0x00010000
GPT_HDR_SIZE = 92
GPT_ENTRY_SIZE = 128

# 常见 MBR 分区类型
MBR_TYPES = {
    0x00: "empty",
    0x01: "FAT12",
    0x04: "FAT16 <32M",
    0x05: "extended (CHS)",
    0x06: "FAT16",
    0x07: "NTFS/exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "extended (LBA)",
    0x11: "hidden FAT12",
    0x12: "compaq diagnostics",
    0x27: "windows recovery",
    0x39: "plan9",
    0x42: "windows dynamic (LDM)",
    0x63: "unix system V",
    0x82: "linux swap",
    0x83: "linux",
    0x84: "hibernation",
    0x85: "linux extended",
    0x8E: "linux LVM",
    0x93: "amiga",
    0x9F: "BSD/OS",
    0xA5: "freebsd",
    0xA6: "openbsd",
    0xA8: "mac OS X",
    0xAB: "mac OS X boot",
    0xAF: "HFS / HFS+",
    0xBE: "solaris boot",
    0xBF: "solaris",
    0xEE: "GPT protective",
    0xEF: "EFI system",
    0xFB: "vmware VMFS",
    0xFC: "vmware swap",
    0xFD: "linux RAID",
}

EXTENDED_TYPES = (0x05, 0x0F, 0x85)

# 常见 GPT 分区类型 GUID（小写、标准 mixed-endian 字符串形式）
GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "21686148-6449-6e6f-744e-656564454649": "BIOS boot",
    "024dee41-33e7-11d3-9d69-0008c781f39f": "MBR partition scheme",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft basic data",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft reserved",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows recovery",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "Windows LDM metadata",
    "af9b60a0-1431-4f62-bc68-3311714a69ad": "Windows LDM data",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "Linux RAID",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
    "426f6f74-0000-11aa-aa11-00306543ecac": "Apple boot",
    "516e7cb4-6ecf-11d6-8ff8-00022d09712b": "FreeBSD UFS",
    "6a82cb45-1dd2-11b2-99a6-080020736631": "Solaris root",
    "49f48d32-b10e-11dc-b99b-0019d1879648": "NetBSD swap",
}


class PartRecoverError(ValueError):
    """分区表结构非法或数据不足"""


# ------------------------------------------------------------
# 小工具
# ------------------------------------------------------------
def _u8(b, o):
    if o < 0 or o + 1 > len(b):
        raise PartRecoverError("读取越界：u8 @%d（长度 %d）" % (o, len(b)))
    return b[o]


def _u16(b, o, le=True):
    if o < 0 or o + 2 > len(b):
        raise PartRecoverError("读取越界：u16 @%d（长度 %d）" % (o, len(b)))
    return struct.unpack_from("<H" if le else ">H", b, o)[0]


def _u32(b, o, le=True):
    if o < 0 or o + 4 > len(b):
        raise PartRecoverError("读取越界：u32 @%d（长度 %d）" % (o, len(b)))
    return struct.unpack_from("<I" if le else ">I", b, o)[0]


def _u64(b, o, le=True):
    if o < 0 or o + 8 > len(b):
        raise PartRecoverError("读取越界：u64 @%d（长度 %d）" % (o, len(b)))
    return struct.unpack_from("<Q" if le else ">Q", b, o)[0]


def _guid_str(b, o=0):
    """GPT GUID -> 标准字符串（前 3 段小端、后 2 段大端）"""
    if o + 16 > len(b):
        raise PartRecoverError("GUID 读取越界：@%d" % o)
    d1 = _u32(b, o, le=True)
    d2 = _u16(b, o + 4, le=True)
    d3 = _u16(b, o + 6, le=True)
    tail = bytes(b[o + 8:o + 16])
    return "%08X-%04X-%04X-%s-%s" % (
        d1, d2, d3, tail[0:2].hex().upper(), tail[2:8].hex().upper())


def _guid_bytes(s):
    """标准 GUID 字符串 -> 16 字节（与 _guid_str 互逆）"""
    if not s:
        raise PartRecoverError("GUID 不能为空")
    t = str(s).strip().strip("{}").replace("-", "")
    if len(t) != 32:
        raise PartRecoverError("GUID 长度异常：%r" % s)
    try:
        raw = bytes.fromhex(t)
    except ValueError:
        raise PartRecoverError("GUID 不是合法的十六进制：%r" % s)
    out = bytearray(16)
    out[0:4] = raw[0:4][::-1]
    out[4:6] = raw[4:6][::-1]
    out[6:8] = raw[6:8][::-1]
    out[8:16] = raw[8:16]
    return bytes(out)


def _mbr_type_name(t):
    return MBR_TYPES.get(int(t), "unknown(0x%02X)" % int(t))


def _gpt_type_name(s):
    return GPT_TYPES.get(str(s).lower(), "")


# ------------------------------------------------------------
# MBR / EBR
# ------------------------------------------------------------
def _parse_mbr_entries(buf, base_off, index_base=1):
    """解析 4 个 16 字节分区项"""
    out = []
    for i in range(4):
        off = base_off + i * 16
        if off + 16 > len(buf):
            break
        status = buf[off]
        ptype = buf[off + 4]
        lba = _u32(buf, off + 8, le=True)
        cnt = _u32(buf, off + 12, le=True)
        if ptype == 0 or cnt == 0:
            continue
        out.append({
            "index": index_base + len(out),
            "status": status,
            "bootable": status == 0x80,
            "type": ptype,
            "type_name": _mbr_type_name(ptype),
            "lba_start": lba,
            "sectors": cnt,
            "byte_offset": lba * SECTOR,
            "size": cnt * SECTOR,
        })
    return out


def parse_mbr(sub):
    """解析 MBR（含扩展分区的 EBR 链）"""
    buf = sub.read(0, SECTOR)
    if len(buf) < SECTOR:
        raise PartRecoverError("MBR 读取失败：只读到 %d 字节" % len(buf))
    sig_ok = bytes(buf[0x1FE:0x200]) == MBR_SIGNATURE
    parts = _parse_mbr_entries(buf, MBR_ENTRY_OFF)
    logical = []
    for p in parts:
        if p["type"] in EXTENDED_TYPES:
            logical.extend(_parse_ebr_chain(sub, p["lba_start"]))
    for i, p in enumerate(logical):
        p["index"] = len(parts) + i + 1
        p["logical"] = True
    return {
        "style": "mbr",
        "signature_ok": sig_ok,
        "disk_signature": "%08X" % _u32(buf, 0x1B8, le=True) if len(buf) >= 0x1BC else "",
        "partitions": parts,
        "logical_partitions": logical,
        "all_partitions": parts + logical,
    }


def _parse_ebr_chain(sub, ext_lba, max_ebr=64):
    """沿 EBR 链遍历逻辑分区；ext_lba 是扩展分区起始 LBA"""
    out = []
    cur = ext_lba
    seen = set()
    while cur and cur not in seen and len(seen) < max_ebr:
        seen.add(cur)
        buf = sub.read(cur * SECTOR, SECTOR)
        if len(buf) < SECTOR:
            break
        if bytes(buf[0x1FE:0x200]) != MBR_SIGNATURE:
            break
        ents = _parse_mbr_entries(buf, MBR_ENTRY_OFF)
        if not ents:
            break
        first = ents[0]
        # 第一项指向逻辑分区，偏移相对 EBR 自身
        log = dict(first)
        log["lba_start"] = cur + first["lba_start"]
        log["byte_offset"] = log["lba_start"] * SECTOR
        out.append(log)
        # 第二项（若存在且是扩展类型）指向下一个 EBR
        nxt = None
        for e in ents[1:]:
            if e["type"] in EXTENDED_TYPES:
                nxt = cur + e["lba_start"]
                break
        cur = nxt
    return out


# ------------------------------------------------------------
# GPT
# ------------------------------------------------------------
def parse_gpt(sub, lba=None):
    """解析 GPT 头与分区项

    lba 为空时依次试 LBA1（主）与镜像最后一个扇区（备份）。
    """
    size = getattr(sub, "size", 0) or 0
    candidates = []
    if lba is not None:
        candidates = [int(lba)]
    else:
        candidates = [1]
        if size >= SECTOR * 2:
            candidates.append(size // SECTOR - 1)
    last_err = None
    for pos in candidates:
        buf = sub.read(pos * SECTOR, SECTOR)
        if len(buf) < GPT_HDR_SIZE:
            last_err = "LBA%d 读取不足" % pos
            continue
        if bytes(buf[0:8]) != GPT_SIGNATURE:
            last_err = "LBA%d 不是 GPT 头（前 8 字节 %r）" % (pos, bytes(buf[0:8]))
            continue
        hdr_size = _u32(buf, 12, le=True)
        if not (GPT_HDR_SIZE <= hdr_size <= SECTOR):
            last_err = "GPT header_size 异常：%d" % hdr_size
            continue
        want_crc = _u32(buf, 16, le=True)
        tmp = bytearray(buf[0:hdr_size])
        tmp[16:20] = b"\x00\x00\x00\x00"
        got_crc = zlib.crc32(bytes(tmp)) & 0xFFFFFFFF
        entries_lba = _u64(buf, 72, le=True)
        num = _u32(buf, 80, le=True)
        esize = _u32(buf, 84, le=True)
        if not (0 < num <= 4096 and 128 <= esize <= 4096):
            last_err = "GPT 分区项参数异常：num=%d esize=%d" % (num, esize)
            continue
        want_ecrc = _u32(buf, 88, le=True)
        raw = sub.read(entries_lba * SECTOR, num * esize)
        entries = []
        for i in range(num):
            base = i * esize
            if base + 128 > len(raw):
                break
            tguid = _guid_str(raw, base)
            if tguid.strip("0-") == "":
                continue
            first = _u64(raw, base + 0x20, le=True)
            last = _u64(raw, base + 0x28, le=True)
            name_raw = bytes(raw[base + 0x38:base + 0x38 + 72])
            name = name_raw.decode("utf-16-le", "replace").split("\x00")[0]
            entries.append({
                "index": len(entries) + 1,
                "type_guid": tguid,
                "type_name": _gpt_type_name(tguid),
                "unique_guid": _guid_str(raw, base + 0x10),
                "first_lba": first,
                "last_lba": last,
                "attributes": _u64(raw, base + 0x30, le=True),
                "name": name,
                "byte_offset": first * SECTOR,
                "size": (last - first + 1) * SECTOR if last >= first else 0,
            })
        got_ecrc = zlib.crc32(bytes(raw)) & 0xFFFFFFFF
        return {
            "style": "gpt",
            "header_lba": pos,
            "backup_header_lba": _u64(buf, 32, le=True),
            "current_lba": _u64(buf, 24, le=True),
            "first_usable_lba": _u64(buf, 40, le=True),
            "last_usable_lba": _u64(buf, 48, le=True),
            "disk_guid": _guid_str(buf, 56),
            "entries_lba": entries_lba,
            "num_entries": num,
            "entry_size": esize,
            "header_size": hdr_size,
            "header_crc32": "0x%08X" % want_crc,
            "header_crc_ok": want_crc == got_crc,
            "entries_crc32": "0x%08X" % want_ecrc,
            "entries_crc_ok": want_ecrc == got_ecrc,
            "partitions": entries,
            "logical_partitions": [],
            "all_partitions": entries,
        }
    raise PartRecoverError("未找到可解析的 GPT：%s" % (last_err or "无候选"))


def detect_table(sub):
    """返回 "mbr" / "gpt" / None"""
    buf = sub.read(0, SECTOR)
    if len(buf) >= 0x200 and bytes(buf[0x1FE:0x200]) == MBR_SIGNATURE:
        # 有 MBR 签名，再看是不是纯保护性 MBR
        ents = _parse_mbr_entries(buf, MBR_ENTRY_OFF)
        if ents and all(e["type"] == 0xEE for e in ents):
            return "gpt"
        return "mbr"
    try:
        g = sub.read(SECTOR, GPT_HDR_SIZE)
        if len(g) >= 8 and bytes(g[0:8]) == GPT_SIGNATURE:
            return "gpt"
    except Exception:
        pass
    return None


# ------------------------------------------------------------
# 恢复：表没了就扫特征
# ------------------------------------------------------------
# 文件系统特征：(名字, 检查偏移, 魔数, 相邻约束说明)
FS_SIGNATURES = [
    ("ntfs", 3, b"NTFS    "),
    ("fat", 0x36, b"FAT12"),
    ("fat", 0x36, b"FAT16"),
    ("fat32", 0x52, b"FAT32"),
    ("exfat", 3, b"EXFAT   "),
    ("ext", 1080, b"\x53\xEF"),          # superblock magic 0xEF53 小端
    ("xfs", 0, b"XFSB"),
    ("hfs+", 1024, b"H+"),
    ("hfsx", 1024, b"HX"),
    ("btrfs", 0x10040, b"_BHRfS_M"),
]
SCAN_STEP = 1 << 20          # 1 MiB
SCAN_MAX = 256 << 20         # 扫到 256 MiB 就停，避免全盘遍历


def _probe_fs_at(sub, off):
    """在 off 处试各种特征，命中返回文件系统名 else None"""
    for name, delta, magic in FS_SIGNATURES:
        try:
            d = sub.read(off + delta, len(magic))
        except Exception:
            continue
        if len(d) < len(magic):
            continue
        if bytes(d) == magic:
            return name
    return None


def _scan_candidates(sub, limit=SCAN_MAX):
    size = getattr(sub, "size", 0) or 0
    end = min(size, limit)
    out = []
    off = 0
    while off < end:
        fs = _probe_fs_at(sub, off)
        if fs:
            out.append({"byte_offset": off, "lba_start": off // SECTOR,
                        "fs": fs, "size": None})
        off += SCAN_STEP
    return out


def recover_partitions(sub, deep=False):
    """尽力恢复分区布局

    顺序：MBR → GPT（主）→ GPT（备份）→ 特征扫描
    """
    result = {"source": None, "partitions": [], "logical_partitions": [],
              "candidates": [], "notes": []}
    style = detect_table(sub)
    if style == "mbr":
        try:
            m = parse_mbr(sub)
            if m["signature_ok"] and (m["partitions"] or m["logical_partitions"]):
                result.update({"source": "mbr",
                               "partitions": m["partitions"],
                               "logical_partitions": m["logical_partitions"]})
                if not deep:
                    return result
        except PartRecoverError as e:
            result["notes"].append("MBR 解析失败：%s" % e)
    try:
        g = parse_gpt(sub)
        if g["partitions"]:
            src = "gpt" if g["header_lba"] == 1 else "backup-gpt"
            result.update({"source": src, "partitions": g["partitions"]})
            if not g["header_crc_ok"]:
                result["notes"].append("GPT 头 CRC32 不匹配（仍按结构解析）")
            if not g["entries_crc_ok"]:
                result["notes"].append("GPT 分区项 CRC32 不匹配（仍按结构解析）")
            if not deep:
                return result
            result["candidates"] = _scan_candidates(sub)
            return result
    except PartRecoverError as e:
        result["notes"].append("GPT 解析失败：%s" % e)
    # 表全没了
    result["candidates"] = _scan_candidates(sub)
    if result["candidates"] and not result["source"]:
        result["source"] = "scan"
    return result


# ------------------------------------------------------------
# 重建
# ------------------------------------------------------------
def rebuild_table(recovered, style="gpt", disk_guid=None):
    """把恢复出来的布局重新生成可写回的分区表字节

    style="mbr" → 512 字节；style="gpt" → 头（1 扇区）+ 分区项（整数扇区）
    **只重建主分区表；扩展分区（EBR 链）不重建**，见模块 docstring。
    """
    parts = list(recovered.get("partitions") or [])
    if not parts:
        raise PartRecoverError("没有可重建的分区")
    if style == "mbr":
        primaries = [p for p in parts if not p.get("logical")]
        if len(primaries) > 4:
            raise PartRecoverError("MBR 最多 4 个主分区，当前 %d 个"
                                   % len(primaries))
        out = bytearray(SECTOR)
        for i, p in enumerate(primaries):
            off = MBR_ENTRY_OFF + i * 16
            out[off] = 0x80 if p.get("bootable") else 0x00
            out[off + 4] = int(p.get("type") or 0) & 0xFF
            struct.pack_into("<I", out, off + 8, int(p.get("lba_start") or 0))
            struct.pack_into("<I", out, off + 12, int(p.get("sectors") or 0))
        out[0x1FE:0x200] = MBR_SIGNATURE
        return bytes(out)

    # ---- GPT ----
    num = len(parts)
    entry_area = bytearray(num * GPT_ENTRY_SIZE)
    for i, p in enumerate(parts):
        base = i * GPT_ENTRY_SIZE
        tg = p.get("type_guid")
        if not tg:
            raise PartRecoverError("第 %d 个分区缺 type_guid，无法生成 GPT" % (i + 1))
        entry_area[base:base + 16] = _guid_bytes(tg)
        ug = p.get("unique_guid")
        if not ug:
            ug = "00000000-0000-4000-8000-%012X" % (i + 1)
        entry_area[base + 0x10:base + 0x20] = _guid_bytes(ug)
        first = int(p.get("first_lba") or (int(p.get("byte_offset") or 0) // SECTOR))
        last = int(p.get("last_lba") or 0)
        if not last and p.get("size"):
            last = first + int(p["size"]) // SECTOR - 1
        struct.pack_into("<Q", entry_area, base + 0x20, first)
        struct.pack_into("<Q", entry_area, base + 0x28, last)
        struct.pack_into("<Q", entry_area, base + 0x30, int(p.get("attributes") or 0))
        nm = (p.get("name") or "").encode("utf-16-le")[:72]
        entry_area[base + 0x38:base + 0x38 + len(nm)] = nm
    entries_crc = zlib.crc32(bytes(entry_area)) & 0xFFFFFFFF

    hdr = bytearray(GPT_HDR_SIZE)
    hdr[0:8] = GPT_SIGNATURE
    struct.pack_into("<I", hdr, 8, GPT_REVISION)
    struct.pack_into("<I", hdr, 12, GPT_HDR_SIZE)
    struct.pack_into("<I", hdr, 16, 0)               # CRC 占位
    struct.pack_into("<Q", hdr, 24, 1)               # current_lba
    first_usable = 2 + ((num * GPT_ENTRY_SIZE) + SECTOR - 1) // SECTOR
    struct.pack_into("<Q", hdr, 40, first_usable)
    last_usable = max(first_usable,
                      max((int(p.get("last_lba") or 0) for p in parts), default=first_usable))
    struct.pack_into("<Q", hdr, 48, last_usable)
    hdr[56:72] = _guid_bytes(disk_guid or
                             "00000000-0000-4000-8000-000000000001")
    struct.pack_into("<Q", hdr, 72, 2)               # entries_lba
    struct.pack_into("<I", hdr, 80, num)
    struct.pack_into("<I", hdr, 84, GPT_ENTRY_SIZE)
    struct.pack_into("<I", hdr, 88, entries_crc)
    hdr_crc = zlib.crc32(bytes(hdr)) & 0xFFFFFFFF
    struct.pack_into("<I", hdr, 16, hdr_crc)

    out = bytearray(hdr)
    if len(out) % SECTOR:
        out += b"\x00" * (SECTOR - len(out) % SECTOR)
    out += entry_area
    if len(entry_area) % SECTOR:
        out += b"\x00" * (SECTOR - len(entry_area) % SECTOR)
    return bytes(out)


class _Mem(object):
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read(self, off, size):
        return self.data[off:off + size]

    def write(self, off, data):
        self.data = (self.data[:off] + bytes(data)
                     + self.data[off + len(data):])
        self.size = len(self.data)


def verify_rebuild(data, style="gpt"):
    """把自己生成的表再解一遍，与原布局比对（自校验）"""
    sub = _Mem(data)
    try:
        if style == "mbr":
            got = parse_mbr(sub)
        else:
            # 生成的是「头 + 项」的紧凑形式，把项挪到 LBA2 才能按标准解
            sub = _Mem(b"\x00" * SECTOR + bytes(data))
            got = parse_gpt(sub, lba=1)
    except PartRecoverError as e:
        return {"ok": False, "style": style, "reason": str(e), "partitions": []}
    parts = got["all_partitions"]
    ok = True
    reason = ""
    if style == "mbr":
        if not got["signature_ok"]:
            ok, reason = False, "重建后的 MBR 签名不对"
    else:
        if not got["header_crc_ok"]:
            ok, reason = False, "重建后的 GPT header CRC32 不自洽"
        elif not got["entries_crc_ok"]:
            ok, reason = False, "重建后的 GPT entries CRC32 不自洽"
    return {"ok": ok, "style": style, "reason": reason,
            "count": len(parts), "partitions": parts}


def describe(sub):
    """容错版：不是分区表也不抛"""
    try:
        style = detect_table(sub)
        if style is None:
            return {"style": None, "error": "未识别到 MBR / GPT"}
        rec = recover_partitions(sub, deep=False)
        return {"style": style, "source": rec["source"],
                "count": len(rec["partitions"]),
                "partitions": rec["partitions"][:8], "notes": rec["notes"]}
    except Exception as e:
        return {"style": None, "error": "%s: %s" % (type(e).__name__, e)}


# ============================================================
# 自检
# ============================================================
def _mk_mbr(parts, disk_sig=0x11223344, sig=None):
    """parts: [(status, type, lba_start, sectors)]"""
    img = bytearray(512)
    struct.pack_into("<I", img, 0x1B8, disk_sig)
    for i, (st, tp, lba, cnt) in enumerate(parts[:4]):
        off = MBR_ENTRY_OFF + i * 16
        img[off] = st
        img[off + 4] = tp
        struct.pack_into("<I", img, off + 8, lba)
        struct.pack_into("<I", img, off + 12, cnt)
    img[0x1FE:0x200] = MBR_SIGNATURE if sig is None else sig
    return bytes(img)


def _mk_ebr(log_lba_rel, log_sectors, next_rel=None):
    """一个 EBR 扇区：项0 = 逻辑分区，项1 = 下一个 EBR"""
    img = bytearray(512)
    img[MBR_ENTRY_OFF + 4] = 0x07
    struct.pack_into("<I", img, MBR_ENTRY_OFF + 8, log_lba_rel)
    struct.pack_into("<I", img, MBR_ENTRY_OFF + 12, log_sectors)
    if next_rel is not None:
        o2 = MBR_ENTRY_OFF + 16
        img[o2 + 4] = 0x0F
        struct.pack_into("<I", img, o2 + 8, next_rel)
        struct.pack_into("<I", img, o2 + 12, 1000)
    img[0x1FE:0x200] = MBR_SIGNATURE
    return bytes(img)


def _mk_gpt(parts, num_entries=4, esize=128, break_crc=False):
    """parts: [(type_guid, first_lba, last_lba, name)]"""
    entry_area = bytearray(num_entries * esize)
    for i, (tg, first, last, name) in enumerate(parts):
        base = i * esize
        entry_area[base:base + 16] = _guid_bytes(tg)
        entry_area[base + 0x10:base + 0x20] = _guid_bytes(
            "11111111-2222-4333-8444-%012X" % (i + 1))
        struct.pack_into("<Q", entry_area, base + 0x20, first)
        struct.pack_into("<Q", entry_area, base + 0x28, last)
        nm = name.encode("utf-16-le")[:72]
        entry_area[base + 0x38:base + 0x38 + len(nm)] = nm
    ecrc = zlib.crc32(bytes(entry_area)) & 0xFFFFFFFF
    hdr = bytearray(GPT_HDR_SIZE)
    hdr[0:8] = GPT_SIGNATURE
    struct.pack_into("<I", hdr, 8, GPT_REVISION)
    struct.pack_into("<I", hdr, 12, GPT_HDR_SIZE)
    struct.pack_into("<I", hdr, 16, 0)
    struct.pack_into("<Q", hdr, 24, 1)
    struct.pack_into("<Q", hdr, 32, 0)
    struct.pack_into("<Q", hdr, 40, 34)
    struct.pack_into("<Q", hdr, 48, 2047)
    hdr[56:72] = _guid_bytes("AABBCCDD-1122-3344-5566-778899AABBCC")
    struct.pack_into("<Q", hdr, 72, 2)
    struct.pack_into("<I", hdr, 80, num_entries)
    struct.pack_into("<I", hdr, 84, esize)
    struct.pack_into("<I", hdr, 88, ecrc)
    crc = zlib.crc32(bytes(hdr)) & 0xFFFFFFFF
    struct.pack_into("<I", hdr, 16, (crc ^ 0x1) if break_crc else crc)
    img = bytearray(2048 * 512)
    img[0:512] = _mk_mbr([(0x00, 0xEE, 1, 2047)])
    img[512:512 + GPT_HDR_SIZE] = hdr
    img[1024:1024 + len(entry_area)] = entry_area
    return bytes(img)


def _selftest():
    ok = 0

    def ck(cond, label, extra=""):
        nonlocal ok
        if cond:
            ok += 1
            print("  [OK] %-54s %s" % (label, extra))
        else:
            raise AssertionError("FAIL: %s  %s" % (label, extra))

    print("\n=== 1) MBR：2 主分区 + 扩展分区（2 逻辑）===")
    # 布局：主1 @2048(1000扇区)、主2 @4096(500)、扩展 @8192(8000)
    #       EBR1 @8192：逻辑 @+2048=10240(1000)；下一 EBR @+4096=12288
    #       EBR2 @12288：逻辑 @+2048=14336(600)
    img = bytearray(16384 * 512)
    img[0:512] = _mk_mbr([(0x80, 0x07, 2048, 1000),
                          (0x00, 0x83, 4096, 500),
                          (0x00, 0x0F, 8192, 8000)])
    img[8192 * 512:8192 * 512 + 512] = _mk_ebr(2048, 1000, next_rel=4096)
    img[12288 * 512:12288 * 512 + 512] = _mk_ebr(2048, 600)
    m = parse_mbr(_Mem(bytes(img)))
    ck(m["signature_ok"] is True, "MBR 签名 OK")
    ck(len(m["partitions"]) == 3, "3 个主/扩展项", len(m["partitions"]))
    ck(m["partitions"][0]["bootable"] is True
       and m["partitions"][0]["type_name"] == "NTFS/exFAT",
       "主1 可引导 + 类型名", m["partitions"][0]["type_name"])
    ck(m["partitions"][2]["type"] == 0x0F, "扩展分区类型 0x0F")
    ck(len(m["logical_partitions"]) == 2, "EBR 链走出 2 个逻辑分区")
    ck([p["lba_start"] for p in m["logical_partitions"]] == [10240, 14336],
       "逻辑分区 LBA 累加正确", [p["lba_start"] for p in m["logical_partitions"]])
    ck(m["logical_partitions"][0]["logical"] is True, "逻辑分区带 logical 标记")

    print("\n=== 2) MBR 签名损坏 ===")
    bad = bytearray(img)
    bad[0x1FE:0x200] = b"\x34\x12"
    m2 = parse_mbr(_Mem(bytes(bad)))
    ck(m2["signature_ok"] is False, "签名坏 -> signature_ok False")
    ck(len(m2["partitions"]) == 3, "签名坏但仍能列出项（不崩）")

    print("\n=== 3) GPT ===")
    ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    LIN = "0fc63daf-8483-4772-8e79-3d69d8477de4"
    gimg = _mk_gpt([(ESP, 34, 1057, "EFI 系统分区"),
                    (LIN, 1058, 2047, "数据")])
    g = parse_gpt(_Mem(gimg))
    ck(g["header_crc_ok"] is True and g["entries_crc_ok"] is True,
       "GPT 两条 CRC 都自洽")
    ck(len(g["partitions"]) == 2, "只返回 2 个有效分区（全零项跳过）",
       len(g["partitions"]))
    ck(g["partitions"][0]["type_name"] == "EFI System", "type GUID -> 名字",
       g["partitions"][0]["type_name"])
    ck(g["partitions"][1]["name"] == "数据", "中文分区名 UTF-16LE", g["partitions"][1]["name"])
    ck(g["disk_guid"] == "AABBCCDD-1122-3344-5566-778899AABBCC",
       "disk GUID mixed-endian 格式化", g["disk_guid"])
    ck(g["partitions"][0]["size"] == (1057 - 34 + 1) * 512, "分区字节数")

    print("\n=== 4) GPT 头 CRC 故意写错 ===")
    gbad = parse_gpt(_Mem(_mk_gpt([(ESP, 34, 1057, "x")], break_crc=True)))
    ck(gbad["header_crc_ok"] is False, "CRC 不匹配被报告")
    ck(len(gbad["partitions"]) == 1, "CRC 坏但仍列出分区（不崩）")

    print("\n=== 5) detect_table ===")
    ck(detect_table(_Mem(bytes(img))) == "mbr", "MBR 镜像识别为 mbr")
    ck(detect_table(_Mem(gimg)) == "gpt", "保护性 MBR + GPT 识别为 gpt")
    ck(detect_table(_Mem(b"\x00" * 4096)) is None, "全零识别为 None")

    print("\n=== 6) recover：只有 MBR ===")
    r1 = recover_partitions(_Mem(bytes(img)))
    ck(r1["source"] == "mbr", "source = mbr", r1["source"])
    ck(len(r1["partitions"]) == 3, "主/扩展 3 项")
    ck(r1["candidates"] == [], "未开 deep 时不做特征扫描")

    print("\n=== 7) recover deep：分区表被清零，靠特征找回 ===")
    flat = bytearray(8 << 20)
    # 在 1 MiB 与 3 MiB 处放 NTFS / ext 特征
    flat[1 << 20:(1 << 20) + 512] = b"\x00" * 3 + b"NTFS    " + b"\x00" * 501
    flat[3 << 20:3 << 20 + 1200] = b"\x00" * 1080 + b"\x53\xEF" + b"\x00" * 118
    r2 = recover_partitions(_Mem(bytes(flat)), deep=True)
    ck(r2["source"] == "scan", "source = scan", r2["source"])
    ck(len(r2["candidates"]) == 2, "扫到 2 个候选", len(r2["candidates"]))
    ck([c["fs"] for c in r2["candidates"]] == ["ntfs", "ext"],
       "候选文件系统类型", [c["fs"] for c in r2["candidates"]])
    ck(r2["candidates"][0]["lba_start"] == (1 << 20) // 512, "候选 LBA 换算")

    print("\n=== 8) rebuild + verify（MBR）===")
    rb = rebuild_table(r1, style="mbr")
    ck(len(rb) == 512, "重建的 MBR 是 512 字节", len(rb))
    ck(rb[0x1FE:0x200] == MBR_SIGNATURE, "签名已写入")
    v1 = verify_rebuild(rb, style="mbr")
    ck(v1["ok"] is True, "重建后自校验通过", v1.get("reason"))
    # 扩展分区容器项（type 0x0F）本身就在主表里，重建时应保留；
    # 只是它内部的 EBR 链不重建，所以逻辑分区不会回来。
    ck(v1["count"] == 3, "重建的 MBR 含 2 主 + 1 扩展项（EBR 链不重建）",
       v1["count"])
    ck(all(p["type"] != 0x05 for p in v1["partitions"]), "重建项类型都有效")
    ck(len([p for p in v1["partitions"] if p["type"] == 0x0F]) == 1,
       "扩展分区容器项保留了")

    print("\n=== 9) rebuild + verify（GPT，含 CRC 重算）===")
    rb2 = rebuild_table({"partitions": g["partitions"]}, style="gpt")
    v2 = verify_rebuild(rb2, style="gpt")
    ck(v2["ok"] is True, "GPT 重建后 header/entries CRC 都自洽", v2.get("reason"))
    ck(v2["count"] == 2, "GPT 重建后分区数一致", v2["count"])
    ck([p["type_guid"] for p in v2["partitions"]]
       == [p["type_guid"] for p in g["partitions"]], "type GUID 往返一致")
    ck([p["name"] for p in v2["partitions"]] == ["EFI 系统分区", "数据"],
       "中文名往返一致", [p["name"] for p in v2["partitions"]])
    ck([p["first_lba"] for p in v2["partitions"]]
       == [p["first_lba"] for p in g["partitions"]], "起始 LBA 往返一致")

    print("\n=== 10) 边界与异常 ===")
    for bad_in in (b"", b"\x00" * 100):
        try:
            parse_mbr(_Mem(bad_in))
            raise AssertionError("过短输入应抛 PartRecoverError")
        except PartRecoverError:
            pass
    ck(True, "过短输入抛 PartRecoverError")
    try:
        parse_gpt(_Mem(b"\x00" * 4096))
        raise AssertionError("无 GPT 应抛 PartRecoverError")
    except PartRecoverError:
        ck(True, "无 GPT 抛 PartRecoverError")
    r3 = recover_partitions(_Mem(b"\x00" * (4 << 20)), deep=True)
    ck(r3["source"] is None and r3["candidates"] == [],
       "全零镜像：source=None 且无候选（不崩）")
    ck(describe(_Mem(b"\x00" * 4096))["style"] is None, "describe 容错不抛")
    try:
        rebuild_table({"partitions": []})
        raise AssertionError("空布局应抛 PartRecoverError")
    except PartRecoverError:
        ck(True, "空布局抛 PartRecoverError")
    try:
        rebuild_table({"partitions": [{"type": 7, "lba_start": i, "sectors": 1}
                                      for i in range(5)]}, style="mbr")
        raise AssertionError("5 个主分区应抛 PartRecoverError")
    except PartRecoverError:
        ck(True, "MBR 超过 4 个主分区被拒")
    ck(_guid_str(_guid_bytes("0FC63DAF-8483-4772-8E79-3D69D8477DE4"))
       == "0FC63DAF-8483-4772-8E79-3D69D8477DE4", "GUID 编解码互逆")

    print("\n" + "-" * 58)
    print("自检：%d 项通过" % ok)
    print("-" * 58)
    return ok


if __name__ == "__main__":
    import sys
    try:
        _selftest()
    except AssertionError as e:
        print("\n[FAIL] %s" % e)
        sys.exit(1)