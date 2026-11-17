"""mkit.vhdx — VHD / VHDX 虚拟磁盘只读解析（零第三方依赖）。

覆盖两种微软虚拟硬盘容器：

* **VHD**（旧格式，页脚驱动）：末尾 512 字节大端页脚 ``conectix``；动态/差分盘在
  文件开头再放一份页脚副本、紧跟 1024 字节 ``cxsparse`` 动态头，随后是 BAT
  （大端 u32 扇区号表）。每个已分配块 = 512 字节扇区位图 + ``block_size`` 字节数据。
* **VHDX**（新格式，小端）：64KB 文件标识区 + 双头（64KB/128KB，CRC-32C）
  + 双区域表（192KB/256KB） + 元数据区域（File Parameters / Virtual Disk Size /
  Virtual Disk ID / Logical+Physical Sector Size / Parent Locator） + BAT
  （u64 小端，state 3bit + FileOffsetMB 17bit + LengthMB 25bit） + 每 chunk 一个
  扇区位图块。

设计约束
--------
* 只用标准库：``struct`` / ``uuid`` / ``os`` / ``io`` / ``tempfile``。
* ``sub`` 支持三种形态：``bytes``/``bytearray``/``memoryview``、文件路径 ``str``/
  ``os.PathLike``、带 ``read``/``seek`` 的文件对象；统一由 :class:`_Source` 包成
  ``read_at(off, n)`` + ``size``。
* CRC-32C：优先借用 ``mkit/filevault2.py`` 的实现，但**必须**先过标准校验值
  ``crc32c(b"123456789") == 0xE3069283`` 才采用；否则回退本模块自带的表驱动实现
  （filevault2 里那个是 PV 头「弱」变体，初值/收尾不同，不能直接用于 VHDX）。

明确**不做**的事
----------------
* 差分 / 父盘链**只解析、不合并**：``parent()`` 只报告 ``parent_unique_id`` /
  ``parent_timestamp`` / ``parent_unicode_name`` / 父盘定位器，不打开父盘、
  不合成 overlay 视图。父盘缺失区域的读结果是零，而不是父盘内容。
* 不做 VHDX **log 重放**（journal 恢复）：只解析 log GUID / length / offset 与
  版本字段并写进 ``info()``，不应用日志、不做一致性修复。
* 只读：不写回、不修复、不重建 BAT，不做快照/增量合并。

位图位序约定
------------
VHD 与 VHDX 的扇区位图都是 **MSB-first**：第 0 号扇区对应首字节的 bit 7
（与 qemu ``vpc.c`` 的 ``1 << (7 - (sector & 7))``、以及 VHD/VHDX 家族位图惯例一致）。
任务书里「位图 bit0 表示该块第一扇区」是简化说法；实现把它收敛到单点
:func:`_bitmap_get`，把模块常量 :data:`BITMAP_MSB_FIRST` 置 False 即可整盘切成
LSB-first 解读。
"""

from __future__ import annotations

import io
import os
import struct
import sys
import uuid

__all__ = [
    "VhdError",
    "Vhd",
    "Vhdx",
    "probe",
    "open_disk",
    "describe",
    "crc32c",
    "BITMAP_MSB_FIRST",
]

SECTOR = 512
BITMAP_MSB_FIRST = True

# ---------------------------------------------------------------- CRC-32C ----

_CRC32C_POLY_REFLECTED = 0x82F63B78
_CRC32C_TABLE = []


def _crc32c_build_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _CRC32C_POLY_REFLECTED
            else:
                crc >>= 1
        table.append(crc)
    return tuple(table)


def _crc32c_local(data):
    """标准 CRC-32C（Castagnoli），初值/收尾均为 0xFFFFFFFF。"""
    global _CRC32C_TABLE
    if not _CRC32C_TABLE:
        _CRC32C_TABLE = _crc32c_build_table()
    table = _CRC32C_TABLE
    crc = 0xFFFFFFFF
    for byte in bytes(data):
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _load_crc32c():
    """优先复用 mkit.filevault2 的实现，校验不通过则回退本地表驱动版本。"""
    import importlib

    candidates = (".filevault2", "mkit.filevault2", "filevault2")
    for mod_name in candidates:
        try:
            if mod_name.startswith("."):
                mod = importlib.import_module(mod_name, package=__package__)
            else:
                mod = importlib.import_module(mod_name)
        except Exception:
            continue
        fn = getattr(mod, "crc32c", None)
        if fn is None:
            continue
        try:
            if fn(b"123456789") == 0xE3069283:
                return "filevault2.crc32c", fn
        except Exception:
            continue
    return "builtin._crc32c_local", _crc32c_local


CRC32C_IMPL, crc32c = _load_crc32c()


# ------------------------------------------------------------------ helpers ---

def _u(buf, off, n, endian="little"):
    chunk = bytes(buf[off:off + n])
    if len(chunk) < n:
        chunk = chunk + b"\x00" * (n - len(chunk))
    return int.from_bytes(chunk, endian)


def _le16(buf, off):
    return _u(buf, off, 2, "little")


def _le32(buf, off):
    return _u(buf, off, 4, "little")


def _le64(buf, off):
    return _u(buf, off, 8, "little")


def _be16(buf, off):
    return _u(buf, off, 2, "big")


def _be32(buf, off):
    return _u(buf, off, 4, "big")


def _be64(buf, off):
    return _u(buf, off, 8, "big")


def _pad(data, n):
    data = bytes(data)
    if len(data) >= n:
        return data
    return data + b"\x00" * (n - len(data))


def _guid_be(raw):
    """VHD 页脚/差分头的 GUID 以网络（大端）字节序存盘。"""
    raw = _pad(raw, 16)
    try:
        return str(uuid.UUID(bytes=raw)).upper()
    except Exception:
        return raw.hex().upper()


def _guid_le(raw):
    """VHDX 的 GUID 前三个字段小端存盘（mixed-endian）。"""
    raw = _pad(raw, 16)
    try:
        return str(uuid.UUID(bytes_le=raw)).upper()
    except Exception:
        return raw.hex().upper()


def _bitmap_get(buf, index):
    """位图取位。默认 MSB-first：第 0 位 = 首字节 bit7。"""
    if index < 0:
        return False
    byte = index >> 3
    if byte >= len(buf):
        return False
    if BITMAP_MSB_FIRST:
        mask = 0x80 >> (index & 7)
    else:
        mask = 1 << (index & 7)
    return bool(buf[byte] & mask)


def _utf16_be(raw):
    """VHD Parent Unicode Name：512 字节 UTF-16BE，遇双零终止。"""
    raw = bytes(raw)
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            raw = raw[:i]
            break
    if len(raw) % 2:
        raw = raw[:-1]
    try:
        return raw.decode("utf-16-be", "replace")
    except Exception:
        return ""


# ------------------------------------------------------------------ _Source ---

class _Source(object):
    """把 bytes / 路径 / 文件对象统一成 ``read_at(off, n)`` + ``size``。"""

    __slots__ = ("_buf", "_fh", "size", "kind")

    def __init__(self, sub):
        self._buf = None
        self._fh = None
        self.size = 0
        self.kind = "unknown"
        if sub is None:
            raise VhdError("sub 为空（None）")
        if isinstance(sub, memoryview):
            self._buf = sub.tobytes()
            self.kind = "buffer"
        elif isinstance(sub, (bytes, bytearray)):
            self._buf = bytes(sub)
            self.kind = "buffer"
        elif isinstance(sub, (str, os.PathLike)):
            path = os.fspath(sub)
            try:
                fh = open(path, "rb")
            except OSError as exc:
                raise VhdError("无法打开路径 %r: %s" % (path, exc)) from exc
            self._fh = fh
            self.kind = "path"
            try:
                self.size = os.fstat(fh.fileno()).st_size
            except OSError:
                fh.seek(0, os.SEEK_END)
                self.size = fh.tell()
                fh.seek(0)
        elif hasattr(sub, "read"):
            if not hasattr(sub, "seek"):
                try:
                    data = sub.read()
                except Exception as exc:
                    raise VhdError("无法读取流: %s" % (exc,)) from exc
                self._buf = bytes(data or b"")
                self.kind = "stream"
            else:
                self._fh = sub
                self.kind = "fileobj"
                try:
                    pos = sub.tell()
                except Exception:
                    pos = None
                try:
                    sub.seek(0, os.SEEK_END)
                    self.size = int(sub.tell())
                    sub.seek(0 if pos is None else pos)
                except Exception:
                    try:
                        sub.seek(0)
                    except Exception:
                        pass
                    try:
                        data = sub.read()
                    except Exception as exc:
                        raise VhdError("无法读取流: %s" % (exc,)) from exc
                    self._buf = bytes(data or b"")
                    self._fh = None
                    self.kind = "stream"
        else:
            raise VhdError("不支持的 sub 类型: %s" % (type(sub).__name__,))
        if self._buf is not None:
            self.size = len(self._buf)

    # -- 核心读 -----------------------------------------------------------
    def read_at(self, off, n):
        if n <= 0:
            return b""
        if off < 0:
            raise VhdError("负偏移: %d" % (off,))
        if off >= self.size:
            return b""
        n = min(n, self.size - off)
        if self._buf is not None:
            return self._buf[off:off + n]
        fh = self._fh
        try:
            fh.seek(off)
            data = fh.read(n)
        except Exception as exc:
            raise VhdError("读取失败 off=%d n=%d: %s" % (off, n, exc)) from exc
        return bytes(data or b"")

    def close(self):
        if self.kind == "path" and self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def __repr__(self):
        return "<_Source %s size=%d>" % (self.kind, self.size)


class VhdError(ValueError):
    """VHD/VHDX 解析错误。"""


# ---------------------------------------------------------------------- VHD ---

VHD_COOKIE = b"conectix"
VHD_CXSPARSE = b"cxsparse"
VHD_FOOTER_SIZE = 512
VHD_HEADER_SIZE = 1024
VHD_DISK_TYPES = {2: "fixed", 3: "dynamic", 4: "differencing"}
VHD_PLATFORM_CODES = ("W2ru", "W2ku", "Wi2r", "Wi2k", "Mac ", "MacX")
VHD_FIXED_BLOCK_SIZE = 0x20000  # 约定值：固定盘等效块 128KB


def vhd_checksum(buf, field_off=64, field_len=4):
    """VHD 页脚/cxsparse 校验和：(~sum) & 0xFFFFFFFF，校验字段按 0 计。"""
    data = bytes(buf)
    total = sum(data) - sum(data[field_off:field_off + field_len])
    return (~total) & 0xFFFFFFFF


def _parse_vhd_footer(raw):
    raw = _pad(raw[:VHD_FOOTER_SIZE], VHD_FOOTER_SIZE)
    geom = raw[56:60]
    d = {
        "cookie": raw[0:8],
        "features": _be32(raw, 8),
        "file_format_version": _be32(raw, 12),
        "data_offset": _be64(raw, 16),
        "timestamp": _be32(raw, 24),
        "creator_application": raw[28:32].decode("ascii", "replace"),
        "creator_version": _be32(raw, 32),
        "creator_host_os": raw[36:40].decode("ascii", "replace"),
        "original_size": _be64(raw, 40),
        "current_size": _be64(raw, 48),
        "disk_geometry": _be32(raw, 56),
        "geometry": {
            "cylinders": _be16(geom, 0),
            "heads": geom[2] if len(geom) > 2 else 0,
            "sectors_per_track": geom[3] if len(geom) > 3 else 0,
        },
        "disk_type": _be32(raw, 60),
        "checksum": _be32(raw, 64),
        "unique_id": _guid_be(raw[68:84]),
        "saved_state_byte": raw[84],
        "saved_state": bool(raw[84] & 1),
        "raw": raw,
    }
    d["checksum_calc"] = vhd_checksum(raw, 64, 4)
    d["checksum_ok"] = d["checksum_calc"] == d["checksum"]
    d["disk_type_name"] = VHD_DISK_TYPES.get(d["disk_type"], "unknown")
    return d


def _parse_vhd_header(raw):
    raw = _pad(raw[:VHD_HEADER_SIZE], VHD_HEADER_SIZE)
    d = {
        "cookie": raw[0:8],
        "data_offset": _be64(raw, 8),
        "table_offset": _be64(raw, 16),
        "header_version": _be32(raw, 24),
        "max_table_entries": _be32(raw, 28),
        "block_size": _be32(raw, 32),
        "checksum": _be32(raw, 36),
        "parent_unique_id": _guid_be(raw[40:56]),
        "parent_timestamp": _be32(raw, 56),
        "raw": raw,
    }
    d["parent_unicode_name"] = _utf16_be(raw[64:576])
    d["checksum_calc"] = vhd_checksum(raw, 36, 4)
    d["checksum_ok"] = d["checksum_calc"] == d["checksum"]
    locs = []
    off = 576
    end = min(len(raw), 1024)
    while off + 12 <= end:
        code = raw[off:off + 4]
        if code == b"\x00\x00\x00\x00":
            break
        data_space = _be32(raw, off + 4)
        data_len = _be32(raw, off + 8)
        if data_len == 0 or off + 12 + data_len > end:
            break
        locs.append({
            "platform": code.decode("ascii", "replace"),
            "data_length": data_len,
            "data": raw[off + 12:off + 12 + data_len],
        })
        step = 12 + (data_space if data_space >= data_len else data_len)
        off += step
    d["parent_locators"] = locs
    return d


class Vhd(object):
    """旧式 VHD 容器（页脚驱动）的只读视图。

    差分盘只暴露父盘元数据，**不做父盘链合并**。
    """

    def __init__(self, sub):
        self.src = _Source(sub)
        self.footer_offsets = []
        self.footer = None
        self.header = None
        self.bat = []
        self._bitmap_cache = {}
        self._locate_footer()
        self.disk_type = self.footer["disk_type"]
        self.current_size = int(self.footer["current_size"])
        if self.current_size < 0:
            raise VhdError("页脚 current_size 非法: %r" % (self.current_size,))
        if self.disk_type == 2:
            self.block_size = VHD_FIXED_BLOCK_SIZE
            self.max_table_entries = 0
            self.table_offset = 0
        elif self.disk_type in (3, 4):
            self._load_dynamic()
        else:
            raise VhdError("未知 disk_type=%d" % (self.disk_type,))

    # -- 定位页脚 ---------------------------------------------------------
    def _locate_footer(self):
        size = self.src.size
        if size < VHD_FOOTER_SIZE:
            raise VhdError("文件太小（%d 字节），放不下 VHD 页脚" % (size,))
        cands = []
        for off in (size - 512, 0, size - 1024, size - 1536, 512):
            if off < 0 or off + 512 > size:
                continue
            if off not in cands:
                cands.append(off)
        parsed = []
        for off in cands:
            raw = self.src.read_at(off, 512)
            if len(raw) < 512 or raw[0:8] != VHD_COOKIE:
                continue
            self.footer_offsets.append(off)
            parsed.append((off, _parse_vhd_footer(raw)))
        if not parsed:
            raise VhdError("找不到 VHD 页脚（cookie=conectix）")
        good = [p for p in parsed if p[1]["checksum_ok"]]
        off, footer = good[0] if good else parsed[0]
        self.footer_offset = off
        self.footer = footer

    # -- 动态/差分头 + BAT ------------------------------------------------
    def _load_dynamic(self):
        data_off = int(self.footer["data_offset"])
        if data_off == 0xFFFFFFFFFFFFFFFF or data_off <= 0:
            data_off = 512
        raw = self.src.read_at(data_off, VHD_HEADER_SIZE)
        if len(raw) < VHD_HEADER_SIZE or raw[0:8] != VHD_CXSPARSE:
            raise VhdError("缺少 cxsparse 动态头（偏移 %d）" % (data_off,))
        self.header_offset = data_off
        self.header = _parse_vhd_header(raw)
        self.max_table_entries = int(self.header["max_table_entries"])
        self.block_size = int(self.header["block_size"])
        self.table_offset = int(self.header["table_offset"])
        if self.block_size <= 0 or self.block_size % SECTOR:
            raise VhdError("cxsparse block_size 非法: %d" % (self.block_size,))
        if self.max_table_entries <= 0 or self.max_table_entries > (1 << 24):
            raise VhdError("cxsparse max_table_entries 非法: %d"
                           % (self.max_table_entries,))
        bat_raw = self.src.read_at(self.table_offset, self.max_table_entries * 4)
        usable = min(self.max_table_entries, len(bat_raw) // 4)
        self.bat = [_be32(bat_raw, i * 4) for i in range(usable)]
        self.bat_count_read = usable

    # -- 读 ---------------------------------------------------------------
    def _block_bitmap(self, blk):
        cached = self._bitmap_cache.get(blk)
        if cached is not None:
            return cached
        entry = self.bat[blk]
        sec = entry
        if sec == 0xFFFFFFFF:
            return None
        off = sec * SECTOR
        bmp = self.src.read_at(off, SECTOR)
        bmp = _pad(bmp, SECTOR)
        if len(self._bitmap_cache) > 256:
            self._bitmap_cache.clear()
        self._bitmap_cache[blk] = bmp
        return bmp

    def _sector(self, blk, sec_in_block):
        """返回 block 内第 sec_in_block 号扇区的 512 字节。"""
        zeros = b"\x00" * SECTOR
        if blk < 0 or blk >= len(self.bat):
            return zeros
        entry = self.bat[blk]
        if entry == 0xFFFFFFFF:
            return zeros
        bmp = self._block_bitmap(blk)
        if bmp is None:
            return zeros
        if not _bitmap_get(bmp, sec_in_block):
            return zeros
        off = entry * SECTOR + SECTOR + sec_in_block * SECTOR
        return _pad(self.src.read_at(off, SECTOR), SECTOR)

    def read(self, offset, size):
        if not isinstance(offset, int) or not isinstance(size, int):
            raise VhdError("read(offset, size) 需要整数")
        if offset < 0 or size < 0:
            raise VhdError("read 参数为负")
        if size == 0:
            return b""
        end = min(offset + size, self.current_size)
        if end <= offset:
            return b""
        if self.disk_type == 2:
            return _pad(self.src.read_at(offset, end - offset), end - offset)
        out = bytearray(end - offset)
        bs = self.block_size
        ss = SECTOR
        pos = offset
        while pos < end:
            blk = pos // bs
            in_blk = pos - blk * bs
            sec = in_blk // ss
            in_sec = in_blk - sec * ss
            take = min(ss - in_sec, end - pos)
            data = self._sector(blk, sec)
            out[pos - offset:pos - offset + take] = data[in_sec:in_sec + take]
            pos += take
        return bytes(out)

    # -- 元数据视图 -------------------------------------------------------
    def allocated_ranges(self):
        if self.disk_type == 2:
            return [(0, self.current_size)] if self.current_size else []
        out = []
        for i, entry in enumerate(self.bat):
            if entry == 0xFFFFFFFF:
                continue
            out.append((entry * SECTOR, SECTOR + self.block_size))
        return out

    def allocated_blocks(self):
        if self.disk_type == 2:
            return (self.current_size + self.block_size - 1) // self.block_size
        return sum(1 for e in self.bat if e != 0xFFFFFFFF)

    def parent(self):
        """差分盘的父盘元数据；固定/动态盘返回 None（只解析，不合并）。"""
        if self.disk_type != 4 or self.header is None:
            return None
        h = self.header
        locators = [{
            "platform": loc["platform"],
            "data_length": loc["data_length"],
        } for loc in h["parent_locators"]]
        return {
            "parent_unique_id": h["parent_unique_id"],
            "parent_timestamp": h["parent_timestamp"],
            "parent_unicode_name": h["parent_unicode_name"],
            "parent_locators": locators,
            "parent_name_encoding": "utf-16-be",
            "merged": False,
            "note": "只解析父盘元数据；不打开、不合并父盘链",
        }

    def info(self):
        f = self.footer
        d = {
            "format": "vhd",
            "disk_type": self.disk_type,
            "disk_type_name": f["disk_type_name"],
            "current_size": self.current_size,
            "original_size": int(f["original_size"]),
            "block_size": self.block_size,
            "max_table_entries": self.max_table_entries,
            "allocated_blocks": self.allocated_blocks(),
            "checksum_ok": bool(f["checksum_ok"]),
            "footer_checksum": f["checksum"],
            "footer_checksum_calc": f["checksum_calc"],
            "unique_id": f["unique_id"],
            "saved_state": bool(f["saved_state"]),
            "features": f["features"],
            "file_format_version": f["file_format_version"],
            "creator_application": f["creator_application"],
            "creator_version": f["creator_version"],
            "creator_host_os": f["creator_host_os"],
            "timestamp": f["timestamp"],
            "disk_geometry": f["geometry"],
            "footer_offset": self.footer_offset,
            "footer_offsets": list(self.footer_offsets),
            "table_offset": self.table_offset,
            "parent": self.parent(),
            "bitmap_msb_first": BITMAP_MSB_FIRST,
            "source_kind": self.src.kind,
            "file_size": self.src.size,
        }
        if self.header is not None:
            d["header_checksum_ok"] = bool(self.header["checksum_ok"])
            d["header_version"] = self.header["header_version"]
            d["header_offset"] = self.header_offset
        return d

    def close(self):
        self.src.close()


# --------------------------------------------------------------------- VHDX ---

VHDX_SIGNATURE = b"vhdxfile"
VHDX_HEADER_SIG = b"head"
VHDX_REGION_SIG = b"regi"
VHDX_METADATA_SIG = b"metadata"

VHDX_HEADER_A = 0x10000
VHDX_HEADER_B = 0x20000
VHDX_REGION_A = 0x30000
VHDX_REGION_B = 0x40000
VHDX_HEADER_SIZE = 4096
VHDX_REGION_SIZE = 0x10000

GUID_BAT = "2DC27766-F623-4200-9D64-115E9BFD4A08"
GUID_METADATA = "8B7CA206-4790-4B9A-B8FE-575F050F886E"
GUID_FILE_PARAMS = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B"
GUID_VIRTUAL_DISK_SIZE = "2FA54224-CD1B-4876-B211-5DBED83BF4B8"
GUID_VIRTUAL_DISK_ID = "BECA12AB-B2E6-4523-93EF-C309E000C746"
GUID_LOGICAL_SECTOR = "8141BF1D-AD47-4709-9BA6-09F233270000"
GUID_PHYSICAL_SECTOR = "CDA348C7-445D-4471-9CC9-E9885251C556"
GUID_PARENT_LOCATOR = "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C"

VHDX_REGION_NAMES = {
    GUID_BAT: "BAT",
    GUID_METADATA: "Metadata",
}
VHDX_ITEM_NAMES = {
    GUID_FILE_PARAMS: "File Parameters",
    GUID_VIRTUAL_DISK_SIZE: "Virtual Disk Size",
    GUID_VIRTUAL_DISK_ID: "Virtual Disk ID",
    GUID_LOGICAL_SECTOR: "Logical Sector Size",
    GUID_PHYSICAL_SECTOR: "Physical Sector Size",
    GUID_PARENT_LOCATOR: "Parent Locator",
}

VHDX_STATE_NAMES = {
    0: "NOT_PRESENT",
    1: "UNDEFINED",
    2: "ZERO",
    3: "UNMAPPED",
    6: "FULLY_PRESENT",
    7: "PARTIALLY_PRESENT",
}
VHDX_READABLE_STATES = (6, 7)


def _crc32c_field_check(buf, field_off, total_len):
    """校验 CRC-32C：把校验字段置 0 后覆盖整个结构。"""
    data = bytes(buf)
    if len(data) < total_len:
        return None, False
    tmp = bytearray(data[:total_len])
    tmp[field_off:field_off + 4] = b"\x00\x00\x00\x00"
    return crc32c(bytes(tmp)), True


def _parse_vhdx_header(raw, label):
    raw = _pad(raw, VHDX_HEADER_SIZE)
    d = {
        "label": label,
        "signature": raw[0:4],
        "checksum": _le32(raw, 4),
        "sequence_number": _le64(raw, 8),
        "file_write_guid": _guid_le(raw[16:32]),
        "data_write_guid": _guid_le(raw[32:48]),
        "log_guid": _guid_le(raw[48:64]),
        "log_version": _le16(raw, 64),
        "version": _le16(raw, 66),
        "log_length": _le32(raw, 68),
        "log_offset": _le64(raw, 72),
        "raw": raw,
    }
    calc, ok = _crc32c_field_check(raw, 4, VHDX_HEADER_SIZE)
    d["crc_calc"] = calc
    d["crc_ok"] = bool(ok and calc == d["checksum"] and d["signature"] == VHDX_HEADER_SIG)
    return d


def _parse_vhdx_region_table(raw, label):
    raw = _pad(raw, VHDX_REGION_SIZE)
    d = {
        "label": label,
        "signature": raw[0:4],
        "checksum": _le32(raw, 4),
        "entry_count": _le32(raw, 8),
        "reserved": _le32(raw, 12),
        "entries": [],
    }
    calc, ok = _crc32c_field_check(raw, 4, VHDX_REGION_SIZE)
    d["crc_calc"] = calc
    d["crc_ok"] = bool(ok and calc == d["checksum"]
                       and d["signature"] == VHDX_REGION_SIG)
    count = d["entry_count"]
    if count > 0x800:
        count = 0x800
    for i in range(count):
        off = 16 + i * 32
        if off + 32 > VHDX_REGION_SIZE:
            break
        guid = _guid_le(raw[off:off + 16])
        d["entries"].append({
            "guid": guid,
            "name": VHDX_REGION_NAMES.get(guid, ""),
            "file_offset": _le64(raw, off + 16),
            "length": _le32(raw, off + 24),
            "required": bool(_le32(raw, off + 28) & 1),
            "required_raw": _le32(raw, off + 28),
        })
    return d


def _parse_vhdx_metadata(raw):
    raw = _pad(raw, 16)
    d = {
        "signature": raw[0:8],
        "entry_count": _le16(raw, 10),
        "items": [],
    }
    for i in range(d["entry_count"]):
        off = 12 + i * 32
        if off + 32 > len(raw):
            break
        guid = _guid_le(raw[off:off + 16])
        flags = _le32(raw, off + 24)
        d["items"].append({
            "item_id": guid,
            "name": VHDX_ITEM_NAMES.get(guid, ""),
            "offset": _le32(raw, off + 16),
            "length": _le32(raw, off + 20),
            "flags": flags,
            "is_user": bool(flags & 1),
            "is_virtual_disk": bool(flags & 2),
            "is_required": bool(flags & 4),
            "reserved": _le32(raw, off + 28),
        })
    return d


class Vhdx(object):
    """VHDX 容器的只读视图：头 → 区域表 → 元数据 → BAT → 扇区位图。

    父盘链只解析不合并；不做 VHDX log 重放。
    """

    def __init__(self, sub):
        self.src = _Source(sub)
        self._bitmap_cache = {}
        self._bat_cache = {}
        if self.src.size < VHDX_HEADER_B + VHDX_HEADER_SIZE:
            raise VhdError("文件太小（%d 字节），放不下 VHDX 头/区域表" % (self.src.size,))
        sig = self.src.read_at(0, 8)
        if sig != VHDX_SIGNATURE:
            raise VhdError("VHDX 文件标识不符: %r" % (sig,))
        creator_raw = _pad(self.src.read_at(8, 512), 512)
        self.creator = creator_raw.decode("utf-16-le", "replace").split("\x00")[0]
        self._load_headers()
        self._load_regions()
        self._load_metadata()
        self._load_bat()

    # -- 双头 -------------------------------------------------------------
    def _load_headers(self):
        a = _parse_vhdx_header(self.src.read_at(VHDX_HEADER_A, VHDX_HEADER_SIZE), "A")
        b = _parse_vhdx_header(self.src.read_at(VHDX_HEADER_B, VHDX_HEADER_SIZE), "B")
        self.headers = {"A": a, "B": b}
        self.header_crc_detail = {"A": a["crc_ok"], "B": b["crc_ok"]}
        good = [h for h in (a, b) if h["crc_ok"]]
        pool = good if good else [a, b]
        chosen = max(pool, key=lambda h: h["sequence_number"])
        self.active_header = chosen["label"]
        self.header = chosen
        self.header_crc_ok = bool(chosen["crc_ok"])

    # -- 双区域表 ---------------------------------------------------------
    def _load_regions(self):
        a = _parse_vhdx_region_table(self.src.read_at(VHDX_REGION_A, VHDX_REGION_SIZE), "A")
        b = _parse_vhdx_region_table(self.src.read_at(VHDX_REGION_B, VHDX_REGION_SIZE), "B")
        self.region_tables = {"A": a, "B": b}
        self.region_crc_detail = {"A": a["crc_ok"], "B": b["crc_ok"]}
        good = [t for t in (a, b) if t["crc_ok"] and t["entries"]]
        pool = good if good else [t for t in (a, b) if t["entries"]]
        if not pool:
            raise VhdError("两份区域表都不可用")
        table = pool[0]
        self.active_region_table = table["label"]
        self.regions = {}
        for entry in table["entries"]:
            key = entry["name"] or entry["guid"]
            self.regions[key] = entry
        self.region_crc_ok = bool(table["crc_ok"])
        self.region_entries = table["entries"]

    def _require_region(self, name):
        entry = self.regions.get(name)
        if entry is None:
            for e in self.region_entries:
                if e["guid"] == name:
                    return e
            raise VhdError("区域表缺少 %s 区域" % (name,))
        if entry["length"] <= 0:
            raise VhdError("区域 %s 长度为 0" % (name,))
        return entry

    # -- 元数据 -----------------------------------------------------------
    def _load_metadata(self):
        region = self._require_region("Metadata")
        base = int(region["file_offset"])
        raw = self.src.read_at(base, min(int(region["length"]), 0x10000))
        if len(raw) < 32 or raw[0:8] != VHDX_METADATA_SIG:
            raise VhdError("元数据区签名不符: %r" % (raw[0:8],))
        self.metadata_region_offset = base
        self.metadata = _parse_vhdx_metadata(raw)
        self.metadata_items = self.metadata["items"]
        self._items = {it["item_id"]: it for it in self.metadata_items}

        def item_bytes(guid, default=b""):
            it = self._items.get(guid)
            if it is None:
                return default
            start = base + it["offset"]
            data = self.src.read_at(start, it["length"])
            return _pad(data, it["length"]) if it["length"] else data

        fp = item_bytes(GUID_FILE_PARAMS)
        if len(fp) >= 8:
            self.block_size = _le32(fp, 0)
            fp_flags = _le32(fp, 4)
        else:
            raise VhdError("缺少 File Parameters 元数据项")
        self.leave_blocks_allocated = bool(fp_flags & 1)
        self.has_parent = bool(fp_flags & 2)
        self.file_parameters_flags = fp_flags

        vs = item_bytes(GUID_VIRTUAL_DISK_SIZE)
        if len(vs) < 8:
            raise VhdError("缺少 Virtual Disk Size 元数据项")
        self.virtual_disk_size = _le64(vs, 0)

        vid = item_bytes(GUID_VIRTUAL_DISK_ID)
        self.virtual_disk_id = _guid_le(vid[:16]) if len(vid) >= 16 else ""

        ls = item_bytes(GUID_LOGICAL_SECTOR)
        self.logical_sector_size = _le32(ls, 0) if len(ls) >= 4 else 512
        ps = item_bytes(GUID_PHYSICAL_SECTOR)
        self.physical_sector_size = _le32(ps, 0) if len(ps) >= 4 else self.logical_sector_size

        pl = item_bytes(GUID_PARENT_LOCATOR, b"")
        self.parent_locator_len = len(pl)
        self.parent_locator_raw = pl

        if self.block_size <= 0 or self.block_size % (1 << 20):
            # VHDX 要求 payload block size 为 1MB 的整数倍；这里只做软提示
            if self.block_size <= 0:
                raise VhdError("block_size 非法: %d" % (self.block_size,))
        if self.logical_sector_size <= 0:
            self.logical_sector_size = 512
        self.chunk_ratio = self.block_size // self.logical_sector_size
        if self.chunk_ratio < 1:
            raise VhdError("chunk_ratio 非法（block_size=%d, lss=%d）"
                           % (self.block_size, self.logical_sector_size))

    # -- BAT --------------------------------------------------------------
    def _load_bat(self):
        region = self._require_region("BAT")
        self.bat_region_offset = int(region["file_offset"])
        self.bat_region_length = int(region["length"])
        self.block_count = (self.virtual_disk_size + self.block_size - 1) // self.block_size
        self.chunk_count = (self.block_count + self.chunk_ratio - 1) // self.chunk_ratio
        self.bat_entry_count = self.chunk_count * (1 + self.chunk_ratio)
        need = self.bat_entry_count * 8
        warn = None
        if need > self.bat_region_length:
            warn = ("BAT 区域 %d 字节不足以容纳 %d 项（需 %d 字节）"
                    % (self.bat_region_length, self.bat_entry_count, need))
            need = self.bat_region_length
        self.bat_region_warning = warn
        raw = self.src.read_at(self.bat_region_offset, need)
        usable = len(raw) // 8
        self.raw_bat = raw
        self.bat_count_read = usable

    def _bat_raw(self, index):
        if index < 0:
            return 0
        if index >= self.bat_count_read:
            return 0
        return _le64(self.raw_bat, index * 8)

    @staticmethod
    def _decode_bat(raw):
        return {
            "raw": raw,
            "state": raw & 0x7,
            "state_name": VHDX_STATE_NAMES.get(raw & 0x7, "UNKNOWN(%d)" % (raw & 0x7,)),
            "file_offset_mb": (raw >> 3) & 0x1FFFF,
            "length_mb": (raw >> 20) & 0x1FFFFFF,
            "file_offset": ((raw >> 3) & 0x1FFFF) * 1024 * 1024,
            "length": ((raw >> 20) & 0x1FFFFFF) * 1024 * 1024,
        }

    def bat_entry(self, block):
        """逻辑块号 → BAT 条目（跳过每个 chunk 前的扇区位图块）。"""
        if not isinstance(block, int) or block < 0:
            raise VhdError("块号非法: %r" % (block,))
        chunk = block // self.chunk_ratio
        index_in_chunk = block % self.chunk_ratio
        index = chunk * (1 + self.chunk_ratio) + 1 + index_in_chunk
        out = self._decode_bat(self._bat_raw(index))
        out.update({
            "block": block,
            "bat_index": index,
            "chunk": chunk,
            "index_in_chunk": index_in_chunk,
            "bitmap_bat_index": chunk * (1 + self.chunk_ratio),
        })
        if out["length"] == 0 and out["state"] in VHDX_READABLE_STATES:
            out["length"] = self.block_size
        return out

    # -- 扇区位图 ---------------------------------------------------------
    def _chunk_bitmap(self, chunk):
        cached = self._bitmap_cache.get(chunk)
        if cached is not None:
            return cached
        index = chunk * (1 + self.chunk_ratio)
        entry = self._decode_bat(self._bat_raw(index))
        if entry["state"] not in VHDX_READABLE_STATES or entry["file_offset"] == 0:
            return None
        bmp_len = max(self.logical_sector_size,
                      ((self.chunk_ratio + 7) // 8 + self.logical_sector_size - 1)
                      // self.logical_sector_size * self.logical_sector_size)
        bmp = _pad(self.src.read_at(entry["file_offset"], bmp_len), bmp_len)
        if len(self._bitmap_cache) > 128:
            self._bitmap_cache.clear()
        self._bitmap_cache[chunk] = bmp
        return bmp

    def _logical_sector(self, sector):
        zeros = b"\x00" * self.logical_sector_size
        block = sector // self.chunk_ratio
        sec_in_block = sector % self.chunk_ratio
        if block >= self.block_count:
            return zeros
        entry = self.bat_entry(block)
        if entry["state"] not in VHDX_READABLE_STATES:
            return zeros
        bmp = self._chunk_bitmap(entry["chunk"])
        if bmp is not None and not _bitmap_get(bmp, sec_in_block):
            return zeros
        off = entry["file_offset"] + sec_in_block * self.logical_sector_size
        return _pad(self.src.read_at(off, self.logical_sector_size),
                    self.logical_sector_size)

    # -- 读 ---------------------------------------------------------------
    def read(self, offset, size):
        if not isinstance(offset, int) or not isinstance(size, int):
            raise VhdError("read(offset, size) 需要整数")
        if offset < 0 or size < 0:
            raise VhdError("read 参数为负")
        if size == 0:
            return b""
        end = min(offset + size, self.virtual_disk_size)
        if end <= offset:
            return b""
        lss = self.logical_sector_size
        out = bytearray(end - offset)
        pos = offset
        while pos < end:
            sector = pos // lss
            in_sector = pos - sector * lss
            take = min(lss - in_sector, end - pos)
            data = self._logical_sector(sector)
            out[pos - offset:pos - offset + take] = data[in_sector:in_sector + take]
            pos += take
        return bytes(out)

    # -- 元数据视图 -------------------------------------------------------
    def allocated_ranges(self):
        out = []
        if self.block_count <= 0:
            return out
        for chunk in range(self.chunk_count):
            base = chunk * (1 + self.chunk_ratio)
            bmp = self._decode_bat(self._bat_raw(base))
            if bmp["state"] in VHDX_READABLE_STATES and bmp["file_offset"]:
                out.append((bmp["file_offset"],
                            max(self.logical_sector_size,
                                (self.chunk_ratio + 7) // 8)))
            for i in range(self.chunk_ratio):
                block = chunk * self.chunk_ratio + i
                if block >= self.block_count:
                    break
                entry = self.bat_entry(block)
                if entry["state"] in VHDX_READABLE_STATES:
                    out.append((entry["file_offset"], entry["length"] or self.block_size))
        out.sort()
        return out

    def allocated_blocks(self):
        total = 0
        for block in range(self.block_count):
            if self.bat_entry(block)["state"] in VHDX_READABLE_STATES:
                total += 1
        return total

    def parent(self):
        if not self.has_parent and not self.parent_locator_len:
            return None
        locators = []
        raw = self.parent_locator_raw
        off = 0
        while off + 20 <= len(raw):
            loc_type = _guid_le(raw[off:off + 16])
            if loc_type == "00000000-0000-0000-0000-000000000000":
                break
            reserved = _le16(raw, off + 16)
            count = _le16(raw, off + 18)
            locators.append({
                "locator_type": loc_type,
                "reserved": reserved,
                "entry_count": count,
            })
            break
        return {
            "has_parent": bool(self.has_parent),
            "parent_locator_len": self.parent_locator_len,
            "locators": locators,
            "merged": False,
            "note": "只解析父盘定位器；不打开、不合并父盘链",
        }

    def info(self):
        d = {
            "format": "vhdx",
            "version": self.header["version"],
            "sequence_number": self.header["sequence_number"],
            "active_header": self.active_header,
            "header_crc_ok": bool(self.header_crc_ok),
            "header_crc_detail": dict(self.header_crc_detail),
            "region_crc_ok": bool(self.region_crc_ok),
            "region_crc_detail": dict(self.region_crc_detail),
            "active_region_table": self.active_region_table,
            "block_size": self.block_size,
            "logical_sector_size": self.logical_sector_size,
            "physical_sector_size": self.physical_sector_size,
            "chunk_ratio": self.chunk_ratio,
            "virtual_disk_size": self.virtual_disk_size,
            "virtual_disk_id": self.virtual_disk_id,
            "disk_id_guid": self.virtual_disk_id,
            "has_parent": bool(self.has_parent),
            "leave_blocks_allocated": bool(self.leave_blocks_allocated),
            "parent_locator_len": self.parent_locator_len,
            "block_count": self.block_count,
            "chunk_count": self.chunk_count,
            "bat_entry_count": self.bat_entry_count,
            "allocated_blocks": self.allocated_blocks(),
            "regions": {k: dict(v) for k, v in self.regions.items()},
            "metadata_items": [dict(it) for it in self.metadata_items],
            "file_write_guid": self.header["file_write_guid"],
            "data_write_guid": self.header["data_write_guid"],
            "log_guid": self.header["log_guid"],
            "log_version": self.header["log_version"],
            "log_length": self.header["log_length"],
            "log_offset": self.header["log_offset"],
            "creator": self.creator,
            "parent": self.parent(),
            "bitmap_msb_first": BITMAP_MSB_FIRST,
            "source_kind": self.src.kind,
            "file_size": self.src.size,
            "bat_region_warning": self.bat_region_warning,
        }
        return d

    def close(self):
        self.src.close()


# ------------------------------------------------------------- 判形 / 入口 ---

def probe(sub):
    """判形：返回 "vhd" / "vhdx" / None。任何异常都收敛成 None。"""
    src = None
    try:
        src = _Source(sub)
        size = src.size
        if size >= 8:
            head8 = src.read_at(0, 8)
            if head8 == VHDX_SIGNATURE:
                return "vhdx"
            if head8 == VHD_COOKIE:
                return "vhd"
        if size >= 8 + 8:
            if src.read_at(512, 8) == VHD_CXSPARSE:
                return "vhd"
        if size >= 512:
            if src.read_at(size - 512, 8) == VHD_COOKIE:
                return "vhd"
        return None
    except Exception:
        return None
    finally:
        if src is not None:
            src.close()


def open_disk(sub):
    """自动判别并返回 :class:`Vhd` 或 :class:`Vhdx`。"""
    fmt = probe(sub)
    if fmt == "vhdx":
        return Vhdx(sub)
    if fmt == "vhd":
        return Vhd(sub)
    raise VhdError("无法识别虚拟磁盘格式（既不是 VHD 也不是 VHDX）")


def describe(sub):
    """容错总入口：永不抛异常，失败时返回带 error 字段的 dict。"""
    out = {"format": None, "ok": False, "probe": None}
    try:
        out["probe"] = probe(sub)
        if out["probe"] is None:
            out["error"] = "无法识别的虚拟磁盘格式"
            return out
        disk = open_disk(sub)
        try:
            info = disk.info()
        finally:
            disk.close()
        if isinstance(info, dict):
            out.update(info)
        out["ok"] = True
        return out
    except Exception as exc:  # 容错入口不抛
        out["ok"] = False
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
        return out


# ============================================================== 自检镜像 ====

def _mk_vhd_geometry(total_bytes):
    sectors = max(1, total_bytes // SECTOR)
    heads, spt = 16, 63
    cyl = sectors // (heads * spt)
    cyl = max(1, min(0xFFFF, cyl))
    return struct.pack(">HBB", cyl, heads, spt)


def _mk_vhd_footer(disk_type, current_size, data_offset, block_size=0,
                   max_table_entries=0, unique_id=None, timestamp=0):
    uid = unique_id if unique_id is not None else bytes(range(1, 17))
    f = bytearray(512)
    f[0:8] = VHD_COOKIE
    struct.pack_into(">I", f, 8, 0x00000002)
    struct.pack_into(">I", f, 12, 0x00010000)
    struct.pack_into(">Q", f, 16, data_offset)
    struct.pack_into(">I", f, 24, timestamp or 0x5A5A5A5A)
    f[28:32] = b"mkvd"
    struct.pack_into(">I", f, 32, 0x00050003)
    f[36:40] = b"Wi2k"
    struct.pack_into(">Q", f, 40, current_size)
    struct.pack_into(">Q", f, 48, current_size)
    f[56:60] = _mk_vhd_geometry(current_size)
    struct.pack_into(">I", f, 60, disk_type)
    struct.pack_into(">I", f, 64, 0)
    f[68:84] = uid
    f[84] = 0
    struct.pack_into(">I", f, 64, vhd_checksum(f, 64, 4))
    return bytes(f)


def _mk_vhd_cxsparse(table_offset, max_entries, block_size, parent_uid=None,
                     parent_ts=0, parent_name=""):
    h = bytearray(VHD_HEADER_SIZE)
    h[0:8] = VHD_CXSPARSE
    struct.pack_into(">Q", h, 8, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">Q", h, 16, table_offset)
    struct.pack_into(">I", h, 24, 0x00010000)
    struct.pack_into(">I", h, 28, max_entries)
    struct.pack_into(">I", h, 32, block_size)
    struct.pack_into(">I", h, 36, 0)
    h[40:56] = parent_uid if parent_uid is not None else b"\x00" * 16
    struct.pack_into(">I", h, 56, parent_ts)
    name = parent_name.encode("utf-16-be")[:510]
    h[64:64 + len(name)] = name
    struct.pack_into(">I", h, 36, vhd_checksum(h, 36, 4))
    return bytes(h)


def _mk_vhd_bitmap(sector_count, present):
    """按 MSB-first 约定造 512 字节扇区位图。present 为扇区号集合。"""
    bmp = bytearray(SECTOR)
    for sec in present:
        idx = sec >> 3
        if idx >= SECTOR:
            continue
        if BITMAP_MSB_FIRST:
            bmp[idx] |= 0x80 >> (sec & 7)
        else:
            bmp[idx] |= 1 << (sec & 7)
    return bytes(bmp)


def _build_vhd_dynamic(disk_type=3, block_size=4096, specs=None,
                       parent_uid=None, parent_name="", parent_ts=0,
                       unique_id=None, max_entries=None):
    """specs[i] = None（未分配）或 (bitmap_bytes, data_bytes)。"""
    specs = specs if specs is not None else []
    nblocks = len(specs)
    table_offset = 1536
    max_entries = max_entries if max_entries is not None else nblocks
    bat_len = max_entries * 4
    bat_padded = ((bat_len + SECTOR - 1) // SECTOR) * SECTOR
    block_bytes = SECTOR + block_size
    cur = table_offset + bat_padded
    bat = [0xFFFFFFFF] * max_entries
    placed = []
    for i, spec in enumerate(specs):
        if spec is None:
            continue
        bat[i] = cur // SECTOR
        placed.append((cur, spec))
        cur += block_bytes
    current_size = nblocks * block_size
    footer = _mk_vhd_footer(disk_type, current_size, SECTOR, block_size,
                            max_entries, unique_id)
    hdr = _mk_vhd_cxsparse(table_offset, max_entries, block_size,
                           parent_uid, parent_ts, parent_name)
    img = bytearray(cur + SECTOR)
    img[0:SECTOR] = footer
    img[SECTOR:1536] = hdr
    for i, entry in enumerate(bat):
        struct.pack_into(">I", img, table_offset + i * 4, entry)
    for off, (bmp, data) in placed:
        img[off:off + SECTOR] = _pad(bmp, SECTOR)
        img[off + SECTOR:off + SECTOR + block_size] = _pad(data, block_size)
    img[cur:cur + SECTOR] = footer
    return bytes(img)


def _mk_vhdx_header(seq, file_write_guid, data_write_guid, log_guid,
                    log_length=0x100000, log_offset=0x80000, version=1):
    h = bytearray(VHDX_HEADER_SIZE)
    h[0:4] = VHDX_HEADER_SIG
    struct.pack_into("<Q", h, 8, seq)
    h[16:32] = file_write_guid
    h[32:48] = data_write_guid
    h[48:64] = log_guid
    struct.pack_into("<H", h, 64, 0)
    struct.pack_into("<H", h, 66, version)
    struct.pack_into("<I", h, 68, log_length)
    struct.pack_into("<Q", h, 72, log_offset)
    tmp = bytearray(h)
    tmp[4:8] = b"\x00\x00\x00\x00"
    struct.pack_into("<I", h, 4, crc32c(bytes(tmp)))
    return bytes(h)


def _mk_vhdx_region_table(entries):
    rt = bytearray(VHDX_REGION_SIZE)
    rt[0:4] = VHDX_REGION_SIG
    struct.pack_into("<I", rt, 8, len(entries))
    struct.pack_into("<I", rt, 12, 0)
    off = 16
    for guid_bytes, file_offset, length, required in entries:
        rt[off:off + 16] = guid_bytes
        struct.pack_into("<Q", rt, off + 16, file_offset)
        struct.pack_into("<I", rt, off + 24, length)
        struct.pack_into("<I", rt, off + 28, 1 if required else 0)
        off += 32
    tmp = bytearray(rt)
    tmp[4:8] = b"\x00\x00\x00\x00"
    struct.pack_into("<I", rt, 4, crc32c(bytes(tmp)))
    return bytes(rt)


def _guid_bytes_le(text):
    return uuid.UUID(text).bytes_le


def _mk_vhdx_metadata(block_size, disk_size, vdisk_id_bytes, lss, pss,
                      has_parent, parent_locator_payload=b""):
    items = []

    def add(guid, off, data, flags):
        items.append((guid, off, data, flags))

    fp_flags = (2 if has_parent else 0)
    add(GUID_FILE_PARAMS, 0x1000, struct.pack("<II", block_size, fp_flags), 0x6)
    add(GUID_VIRTUAL_DISK_SIZE, 0x1100, struct.pack("<Q", disk_size), 0x6)
    add(GUID_VIRTUAL_DISK_ID, 0x1200, vdisk_id_bytes, 0x2)
    add(GUID_LOGICAL_SECTOR, 0x1300, struct.pack("<I", lss), 0x6)
    add(GUID_PHYSICAL_SECTOR, 0x1400, struct.pack("<I", pss), 0x6)
    if has_parent:
        add(GUID_PARENT_LOCATOR, 0x1500, parent_locator_payload, 0x3)

    meta = bytearray(VHDX_REGION_SIZE)
    meta[0:8] = VHDX_METADATA_SIG
    struct.pack_into("<H", meta, 8, 0)
    struct.pack_into("<H", meta, 10, len(items))
    off = 12
    for guid, item_off, data, flags in items:
        meta[off:off + 16] = _guid_bytes_le(guid)
        struct.pack_into("<I", meta, off + 16, item_off)
        struct.pack_into("<I", meta, off + 20, len(data))
        struct.pack_into("<I", meta, off + 24, flags)
        struct.pack_into("<I", meta, off + 28, 0)
        meta[item_off:item_off + len(data)] = data
        off += 32
    return bytes(meta)


def _build_vhdx(block_size=4096, lss=512, nchunks=2, disk_size=None,
                bat_map=None, blobs=None, seq=(1, 2), corrupt_header=None,
                has_parent=False, parent_locator_payload=b"",
                unique_vdisk_id=None):
    """bat_map: {bat_index: (state, off_mb, len_mb)}；blobs: {byte_off: bytes}。"""
    bat_map = bat_map or {}
    blobs = dict(blobs or {})
    chunk_ratio = block_size // lss
    bat_count = nchunks * (1 + chunk_ratio)
    if disk_size is None:
        disk_size = nchunks * chunk_ratio * block_size

    meta_off = 0x50000
    bat_off = 0x60000
    assert bat_count * 8 <= 0x10000
    assert lss <= block_size

    fwg = b"\x11" * 16
    dwg = b"\x22" * 16
    lg = b"\x33" * 16
    hdr_a = _mk_vhdx_header(seq[0], fwg, dwg, lg)
    hdr_b = _mk_vhdx_header(seq[1], fwg, dwg, lg)
    if corrupt_header == "A":
        tmp = bytearray(hdr_a)
        tmp[0x200] ^= 0xFF
        hdr_a = bytes(tmp)
    elif corrupt_header == "B":
        tmp = bytearray(hdr_b)
        tmp[0x200] ^= 0xFF
        hdr_b = bytes(tmp)

    region_entries = [
        (_guid_bytes_le(GUID_BAT), bat_off, 0x10000, True),
        (_guid_bytes_le(GUID_METADATA), meta_off, 0x10000, True),
    ]
    rt_a = _mk_vhdx_region_table(region_entries)
    rt_b = _mk_vhdx_region_table(region_entries)
    meta = _mk_vhdx_metadata(block_size, disk_size,
                             unique_vdisk_id or b"\xaa" * 16, lss,
                             max(lss, 4096), has_parent, parent_locator_payload)

    bat = bytearray(bat_count * 8)
    for index, (state, off_mb, len_mb) in bat_map.items():
        struct.pack_into("<Q", bat, index * 8,
                         (state & 0x7) | ((off_mb & 0x1FFFF) << 3)
                         | ((len_mb & 0x1FFFFFF) << 20))

    total = max([0x70000] + [off + len(data) for off, data in blobs.items()])
    img = bytearray(total)
    img[0:8] = VHDX_SIGNATURE
    img[8:8 + 512] = _pad("mkvd-vhdx".encode("utf-16-le"), 512)
    img[VHDX_HEADER_A:VHDX_HEADER_A + VHDX_HEADER_SIZE] = hdr_a
    img[VHDX_HEADER_B:VHDX_HEADER_B + VHDX_HEADER_SIZE] = hdr_b
    img[VHDX_REGION_A:VHDX_REGION_A + VHDX_REGION_SIZE] = rt_a
    img[VHDX_REGION_B:VHDX_REGION_B + VHDX_REGION_SIZE] = rt_b
    img[meta_off:meta_off + VHDX_REGION_SIZE] = meta
    img[bat_off:bat_off + len(bat)] = bat
    for off, data in blobs.items():
        img[off:off + len(data)] = data
    return bytes(img)


# ================================================================== 自检 ====

def _selfcheck():
    import tempfile

    results = []

    def chk(label, fn):
        try:
            fn()
        except Exception as exc:
            results.append((False, label, exc))
            print("FAIL  %s\n      %s: %s" % (label, type(exc).__name__, exc))
        else:
            results.append((True, label, None))
            print("PASS  %s" % (label,))

    # ---- 1. CRC-32C 标准校验值 -----------------------------------------
    def c1():
        assert crc32c(b"123456789") == 0xE3069283, hex(crc32c(b"123456789"))
        assert crc32c(b"") == 0x00000000, hex(crc32c(b""))
        assert crc32c(b"a") == _crc32c_local(b"a")
        print("      crc32c impl = %s" % (CRC32C_IMPL,))
    chk("01 CRC-32C 标准校验值 123456789 -> 0xE3069283", c1)

    # ---- 2. VHD 页脚 checksum 自证 -------------------------------------
    def c2():
        img = _build_vhd_dynamic(3, 4096, [( _mk_vhd_bitmap(8, [0, 1, 2, 3, 4, 5, 6, 7]), b"\x5a" * 4096), None, None])
        disk = Vhd(img)
        assert disk.footer["checksum"] == disk.footer["checksum_calc"], "页脚 checksum 自证失败"
        assert disk.info()["checksum_ok"] is True
        assert disk.header["checksum_ok"] is True, "cxsparse checksum 自证失败"
        # 动态/差分盘有两份页脚（偏移 0 与文件末尾）：两份都改坏才算破
        bad = bytearray(img)
        assert len(disk.footer_offsets) == 2, disk.footer_offsets
        for off in disk.footer_offsets:
            bad[off + 200] ^= 0x01  # 改 timestamp 区一个字节
        disk_bad = Vhd(bytes(bad))
        assert disk_bad.info()["checksum_ok"] is False, "两份页脚改字节后 checksum_ok 仍为 True"
        # 只改末尾那份 → 应回退到偏移 0 的副本，校验仍有效
        bad2 = bytearray(img)
        bad2[len(img) - 512 + 200] ^= 0x01
        assert Vhd(bytes(bad2)).info()["checksum_ok"] is True, "双份页脚副本回退失败"
        # 固定盘只有一份页脚，改一个字节即 checksum_ok=False
        fx = b"\x00" * 4096 + _mk_vhd_footer(2, 4096, 0xFFFFFFFFFFFFFFFF)
        assert Vhd(fx).info()["checksum_ok"] is True
        fbad = bytearray(fx)
        fbad[len(fx) - 512 + 200] ^= 0x01
        assert Vhd(bytes(fbad)).info()["checksum_ok"] is False, "固定盘改字节后 checksum_ok 仍为 True"
        # 直接验证算法对 512 字节的语义
        raw = bytearray(512)
        raw[0:8] = VHD_COOKIE
        struct.pack_into(">I", raw, 64, vhd_checksum(raw, 64, 4))
        assert _parse_vhd_footer(bytes(raw))["checksum_ok"], "全零页脚要求 checksum 自洽"
    chk("02 VHD 页脚 checksum 算法自证 + 改字节后 checksum_ok=False", c2)

    # ---- 3. VHD 固定盘 --------------------------------------------------
    payload = bytes((i * 7 + 3) & 0xFF for i in range(65536))

    def c3():
        img = payload + _mk_vhd_footer(2, len(payload), 0xFFFFFFFFFFFFFFFF,
                                      unique_id=bytes(range(16, 32)))
        assert probe(img) == "vhd", "probe 未识别固定盘"
        disk = open_disk(img)
        assert isinstance(disk, Vhd)
        info = disk.info()
        assert info["disk_type"] == 2 and info["disk_type_name"] == "fixed"
        assert info["current_size"] == 65536, info["current_size"]
        assert disk.read(0, 16) == payload[:16]
        assert disk.read(100, 200) == payload[100:300]
        assert disk.read(65536 - 10, 100) == payload[-10:], "越界应截断"
        assert disk.read(65536, 10) == b""
        assert disk.allocated_ranges() == [(0, 65536)]
    chk("03 VHD 固定盘（disk_type=2）：probe/info/read 直通", c3)

    # ---- 4/5. VHD 动态盘 + 差分盘 --------------------------------------
    blk0_data = bytes(((0x40 + i) & 0xFF) for i in range(4096))
    blk2_data = bytes(((0xA0 + i) & 0xFF) for i in range(4096))
    dyn_specs = [
        (_mk_vhd_bitmap(8, range(8)), blk0_data),   # 全置位
        None,                                        # 未分配
        (_mk_vhd_bitmap(8, [0, 1, 2]), blk2_data),   # 只置部分扇区
    ]

    def c4():
        img = _build_vhd_dynamic(3, 4096, dyn_specs)
        disk = Vhd(img)
        info = disk.info()
        assert info["disk_type"] == 3 and info["current_size"] == 4096 * 3
        assert info["block_size"] == 4096
        assert info["max_table_entries"] == 3
        assert info["allocated_blocks"] == 2, info["allocated_blocks"]
        assert disk.read(0, 4096) == blk0_data, "块0 数据不符"
        assert disk.read(4096, 4096) == b"\x00" * 4096, "未分配块应补零"
        got = disk.read(8192, 4096)
        assert got[:3 * 512] == blk2_data[:3 * 512], "块2 已置位扇区数据不符"
        assert got[3 * 512:] == b"\x00" * (4096 - 3 * 512), "块2 未置位扇区应补零"
        # 跨块读
        cross = disk.read(4096 - 512, 1024)
        assert cross[:512] == blk0_data[-512:]
        assert cross[512:] == b"\x00" * 512
        ranges = disk.allocated_ranges()
        assert len(ranges) == 2, ranges
        assert ranges[0][0] % 512 == 0 and ranges[0][1] == 512 + 4096
        assert disk.parent() is None, "动态盘不应报父盘"
    chk("04 VHD 动态盘（3 块/未分配/部分位图）：read 补零 + allocated_ranges", c4)

    def c5():
        pname = "父盘-中文名 测试.vhd"
        puid = bytes(range(0x80, 0x90))
        img = _build_vhd_dynamic(4, 4096, dyn_specs[:1] + [None, None],
                                 parent_uid=puid, parent_name=pname, parent_ts=0x11223344)
        disk = Vhd(img)
        info = disk.info()
        assert info["disk_type"] == 4 and info["disk_type_name"] == "differencing"
        par = disk.parent()
        assert par is not None, "差分盘 parent() 为空"
        assert par["parent_unicode_name"] == pname, repr(par["parent_unicode_name"])
        assert par["parent_unique_id"] == _guid_be(puid), par["parent_unique_id"]
        assert par["parent_timestamp"] == 0x11223344
        assert par["merged"] is False
        assert info["parent"]["parent_unicode_name"] == pname
        assert disk.read(0, 4096) == dyn_specs[0][1]
    chk("05 VHD 差分盘（disk_type=4）：parent_unique_id + 中文 parent 名", c5)

    # ---- 6. VHDX 双头 + CRC 回退 ---------------------------------------
    def _vhdx_simple(**kw):
        bw, bh = 4096, 512
        cr = bw // bh
        blobs = {0x100000: _mk_vhd_bitmap(cr, range(cr)),
                 0x200000: bytes(range(256)) * 16}
        bat = {0: (6, 1, 1), 1: (6, 2, 1)}
        bat[2] = (2, 0, 0)                     # 逻辑块 1 → ZERO
        for i in range(3, 1 + cr):             # 逻辑块 2..7 → NOT_PRESENT
            bat[i] = (0, 0, 0)
        for c in range(1, kw.pop("nchunks", 2)):
            base = c * (1 + cr)
            for i in range(1 + cr):
                bat[base + i] = (0, 0, 0)
        kw.setdefault("block_size", bw)
        kw.setdefault("lss", bh)
        return _build_vhdx(bat_map=bat, blobs=blobs, **kw)

    def c6():
        img = _vhdx_simple()
        disk = Vhdx(img)
        assert disk.headers["A"]["crc_ok"] and disk.headers["B"]["crc_ok"]
        assert disk.active_header == "B", disk.active_header
        assert disk.info()["sequence_number"] == 2
        assert disk.info()["header_crc_ok"] is True
        # 改坏 B 的一个字节 → B 失效，回退 A
        bad = bytearray(img)
        bad[VHDX_HEADER_B + 0x300] ^= 0xFF
        d2 = Vhdx(bytes(bad))
        assert d2.header_crc_detail["B"] is False, "被改坏的头 CRC 应为 False"
        assert d2.header_crc_detail["A"] is True
        assert d2.active_header == "A", d2.active_header
        assert d2.info()["header_crc_ok"] is True
        # 改坏 A、B 都坏 → 仍能构造，但 crc_ok 为 False
        bad2 = bytearray(bytes(bad))
        bad2[VHDX_HEADER_A + 0x300] ^= 0xFF
        d3 = Vhdx(bytes(bad2))
        assert d3.info()["header_crc_ok"] is False
    chk("06 VHDX 双头：取 sequence 大的 + CRC 失败回退", c6)

    # ---- 7. 区域表 ------------------------------------------------------
    def c7():
        img = _vhdx_simple()
        disk = Vhdx(img)
        assert disk.region_tables["A"]["crc_ok"] and disk.region_tables["B"]["crc_ok"]
        assert disk.info()["region_crc_ok"] is True
        regs = disk.info()["regions"]
        assert "BAT" in regs and "Metadata" in regs, sorted(regs)
        assert regs["BAT"]["guid"] == GUID_BAT
        assert regs["Metadata"]["guid"] == GUID_METADATA
        assert regs["BAT"]["file_offset"] == 0x60000
        assert regs["Metadata"]["file_offset"] == 0x50000
        bad = bytearray(img)
        bad[VHDX_REGION_A + 0x100] ^= 0xFF
        d2 = Vhdx(bytes(bad))
        assert d2.region_crc_detail["A"] is False
        assert d2.region_crc_detail["B"] is True
        assert d2.info()["region_crc_ok"] is True
    chk("07 VHDX 区域表 CRC 自证 + 认出 BAT/Metadata", c7)

    # ---- 8. 元数据 ------------------------------------------------------
    def c8():
        for has_parent in (False, True):
            img = _vhdx_simple(has_parent=has_parent,
                               parent_locator_payload=b"\x00" * 24 if has_parent else b"")
            disk = Vhdx(img)
            info = disk.info()
            assert info["block_size"] == 4096, info["block_size"]
            assert info["virtual_disk_size"] == 2 * 8 * 4096, info["virtual_disk_size"]
            assert info["logical_sector_size"] == 512
            assert info["physical_sector_size"] == 4096
            assert info["virtual_disk_id"] == _guid_le(b"\xaa" * 16)
            assert info["disk_id_guid"] == info["virtual_disk_id"]
            assert info["has_parent"] is has_parent, info["has_parent"]
            if has_parent:
                assert info["parent_locator_len"] == 24
                assert info["parent"] is not None
                assert info["parent"]["merged"] is False
            else:
                assert info["parent"] is None
            names = [it["name"] for it in info["metadata_items"]]
            for need in ("File Parameters", "Virtual Disk Size", "Virtual Disk ID",
                         "Logical Sector Size", "Physical Sector Size"):
                assert need in names, names
            assert info["chunk_ratio"] == 8
            assert info["block_count"] == 16
            assert info["chunk_count"] == 2
    chk("08 VHDX 元数据：block_size/size/GUID/扇区/has_parent", c8)

    # ---- 9/10. VHDX BAT + 扇区位图 -------------------------------------
    def _vhdx_disk(**kw):
        return _vhdx_simple(**kw)

    def c9():
        img = _vhdx_disk()
        disk = Vhdx(img)
        e0 = disk.bat_entry(0)
        assert e0["state"] == 6 and e0["state_name"] == "FULLY_PRESENT", e0
        assert e0["file_offset"] == 2 * 1024 * 1024, e0["file_offset"]
        assert e0["bat_index"] == 1, e0["bat_index"]  # 跳过 chunk0 位图块
        assert disk.bat_entry(1)["state_name"] == "ZERO", disk.bat_entry(1)
        assert disk.bat_entry(2)["state_name"] == "NOT_PRESENT", disk.bat_entry(2)
        assert disk.bat_entry(8)["state_name"] == "NOT_PRESENT", disk.bat_entry(8)
        # 读：块0 内容（位图全置位）+ 块1 ZERO + 块2 NOT_PRESENT
        payload = bytes(range(256)) * 16
        assert disk.read(0, 4096) == payload, "FULLY_PRESENT 块内容不符"
        assert disk.read(4096, 4096) == b"\x00" * 4096, "ZERO 块应为零"
        assert disk.read(8192, 4096) == b"\x00" * 4096, "NOT_PRESENT 块应为零"
        assert disk.read(0, 65536) == payload + b"\x00" * (65536 - 4096)
        # 越界截断
        assert disk.read(65536 - 8, 100) == b"\x00" * 8
        assert disk.read(65536, 8) == b""
        ranges = disk.allocated_ranges()
        assert (2 * 1024 * 1024, 1024 * 1024) in ranges, ranges[:4]
    chk("09 VHDX BAT：FULLY_PRESENT/ZERO/NOT_PRESENT 逐字节读取", c9)

    def c10():
        bw, bh = 4096, 512
        cr = bw // bh
        blobs = {0x100000: _mk_vhd_bitmap(cr, [0, 1, 3]),
                 0x200000: bytes((0x30 + i) & 0xFF for i in range(4096))}
        bat = {0: (6, 1, 1), 1: (6, 2, 1)}
        for i in range(2, 1 + cr):
            bat[i] = (2, 0, 0)
        for i in range(1 + cr):
            bat[1 + cr + i] = (0, 0, 0)
        img = _build_vhdx(bat_map=bat, blobs=blobs, block_size=bw, lss=bh)
        disk = Vhdx(img)
        got = disk.read(0, bw)
        src = blobs[0x200000]
        assert got[0:512] == src[0:512], "扇区0 应存在"
        assert got[512:1024] == src[512:1024], "扇区1 应存在"
        assert got[1024:1536] == b"\x00" * 512, "扇区2 未置位应为零"
        assert got[1536:2048] == src[1536:2048], "扇区3 应存在"
        assert got[2048:] == b"\x00" * (bw - 2048), "扇区4..7 未置位应为零"
        # 读单扇区视图
        assert disk.read(1024, 512) == b"\x00" * 512
        assert disk.read(512, 512) == src[512:1024]
    chk("10 VHDX 扇区位图：未置位扇区补零，其余正确", c10)

    # ---- 11. 畸形输入 ---------------------------------------------------
    def c11():
        assert probe(b"") is None
        assert probe(b"\x00" * 4096) is None
        assert probe(b"notadisk" * 100) is None
        assert probe(b"") is None
        for bad in (b"", b"\x00" * 4096, b"conectix", b"vhdxfile" + b"\x00" * 100):
            try:
                open_disk(bad)
            except VhdError:
                pass
            else:
                raise AssertionError("open_disk 未对畸形输入抛 VhdError: %r" % (bad[:8],))
        assert probe(None) is None
        assert probe(12345) is None
        # 截断的真页脚：probe 认出 vhd，构造应抛 VhdError（cxsparse 缺失）
        crop = _build_vhd_dynamic(3, 4096, [( _mk_vhd_bitmap(8, range(8)), b"x" * 4096), None, None])[:600]
        assert probe(crop) in ("vhd", None)
        try:
            Vhd(crop)
        except VhdError:
            pass
        # 空窗口
        assert Vhd(_build_vhd_dynamic(3, 4096, [(_mk_vhd_bitmap(8, range(8)), b"x" * 4096), None, None])).read(0, 0) == b""
        # 负参数
        disk = Vhd(_build_vhd_dynamic(3, 4096, [None, None, None]))
        for args in ((-1, 4), (0, -4)):
            try:
                disk.read(*args)
            except VhdError:
                pass
            else:
                raise AssertionError("负参数未抛 VhdError")
        # VHDX 头区被砍
        img = _vhdx_simple()
        try:
            Vhdx(img[:0x15000])
        except VhdError:
            pass
        else:
            raise AssertionError("截断 VHDX 未抛 VhdError")
        # 元数据签名错
        bad = bytearray(img)
        bad[0x50000:0x50008] = b"XXXXXXXX"
        try:
            Vhdx(bytes(bad))
        except VhdError:
            pass
        else:
            raise AssertionError("元数据签名错未抛 VhdError")
    chk("11 截断/空/全零/非两种格式 → VhdError 或 probe=None", c11)

    # ---- 12. describe 容错 + 三种 sub 形态 ------------------------------
    def c12():
        vhd_img = _build_vhd_dynamic(3, 4096, dyn_specs)
        vhdx_img = _vhdx_simple()

        class Tiny(object):
            def __init__(self):
                self.pos = 0
                self.data = b"garbage"

            def seek(self, off, whence=0):
                self.pos = off if whence == 0 else len(self.data)
                return self.pos

            def tell(self):
                return self.pos

            def read(self, n=-1):
                out = self.data[self.pos:] if n is None or n < 0 else self.data[self.pos:self.pos + n]
                self.pos += len(out)
                return out

        assert describe(None)["ok"] is False
        assert describe(b"")["ok"] is False
        assert describe(b"\x00" * 2048)["ok"] is False
        assert describe(b"conectix" + b"\x00" * 1000)["ok"] is False
        assert describe(Tiny())["ok"] is False
        assert describe(vhd_img[:300])["ok"] is False
        assert "error" in describe(vhd_img[:300])

        tmpdir = tempfile.mkdtemp(prefix="mkit_vhdx_")
        results_ok = 0
        for name, data, cls in (("a.vhd", vhd_img, Vhd), ("b.vhdx", vhdx_img, Vhdx)):
            # (1) bytes
            d = describe(data)
            assert d["ok"] is True, d.get("error")
            assert isinstance(open_disk(data), cls)
            # (2) path
            path = os.path.join(tmpdir, name)
            with open(path, "wb") as fh:
                fh.write(data)
            d = describe(path)
            assert d["ok"] is True, d.get("error")
            assert isinstance(open_disk(path), cls)
            # (3) file object
            with open(path, "rb") as fh:
                d = describe(fh)
                assert d["ok"] is True, d.get("error")
            fh = io.BytesIO(data)
            assert isinstance(open_disk(fh), cls)
            # memoryview
            assert isinstance(open_disk(memoryview(data)), cls)
            results_ok += 3
        assert results_ok == 6

        # 读一致性：三种形态读到同样字节
        path = os.path.join(tmpdir, "c.vhdx")
        with open(path, "wb") as fh:
            fh.write(vhdx_img)
        with open(path, "rb") as fh:
            r_file = Vhdx(fh).read(0, 4096)
        assert r_file == Vhdx(vhdx_img).read(0, 4096) == Vhdx(path).read(0, 4096)
        # 关闭清理
        disk = Vhd(path.replace("c.vhdx", "a.vhd"))
        disk.close()
    chk("12 describe 容错不抛 + bytes/路径/文件对象三种 sub", c12)

    # ---- 13. open_disk 判别 --------------------------------------------
    def c13():
        assert type(open_disk(payload + _mk_vhd_footer(2, len(payload), 0xFFFFFFFFFFFFFFFF))) is Vhd
        assert type(open_disk(_vhdx_simple())) is Vhdx
        assert type(open_disk(_build_vhd_dynamic(3, 4096, dyn_specs))) is Vhd
        assert probe(_vhdx_simple()) == "vhdx"
        assert probe(_build_vhd_dynamic(3, 4096, dyn_specs)) == "vhd"
    chk("13 open_disk 自动判别 Vhd / Vhdx", c13)

    # ---- 14. 中文 parent 名字往返 --------------------------------------
    def c14():
        names = ["父盘-中文名 测试.vhd", "中文", "中文父磁盘（差分）.vhd",
                 "mix 混合 名字 テスト"]
        for name in names:
            img = _build_vhd_dynamic(4, 4096, [None, None, None],
                                     parent_uid=bytes(range(16)),
                                     parent_name=name)
            par = Vhd(img).parent()
            assert par["parent_unicode_name"] == name, (name, par["parent_unicode_name"])
            raw = name.encode("utf-16-be")
            assert _utf16_be(_pad(raw, 512)) == name
        # 超长名字截断不炸
        long_name = "中" * 400
        img = _build_vhd_dynamic(4, 4096, [None, None, None], parent_name=long_name)
        got = Vhd(img).parent()["parent_unicode_name"]
        assert got == long_name[:255], len(got)
    chk("14 中文 parent 名（UTF-16BE 存盘）往返无损", c14)

    passed = sum(1 for ok, _, _ in results if ok)
    total = len(results)
    print("\n%d/%d PASS" % (passed, total))
    try:
        with open(os.path.abspath(__file__), "r", encoding="utf-8") as fh:
            lines = sum(1 for _ in fh)
        print("lines: %d   crc32c: %s   bitmap: %s"
              % (lines, CRC32C_IMPL, "MSB-first" if BITMAP_MSB_FIRST else "LSB-first"))
    except OSError:
        pass
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(_selfcheck())