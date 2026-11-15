# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""regf.py —— 自研 Windows 注册表 hive(REGF) 解析器，零外部依赖。

只用标准库 ``struct`` 与 ``datetime``，不依赖 winreg / Registry / dissect 等任何第三方组件，
可在 Linux/macOS 上离线解析 Windows 取证镜像里取出的 hive 文件。

覆盖的结构
----------
* 基块(base block, 4096 字节)：签名 ``regf``、主/次序号、last written(FILETIME)、
  主/次版本、文件类型、文件格式、根单元偏移(0x24)、hive bins 数据大小(0x28)、
  簇因子、hive 文件名(0x30, UTF-16LE)、校验和(0x1FC，前 508 字节按 DWORD 异或)。
* hbin：``hbin`` 签名、自身在 bins 内的偏移、大小；单元(cell)以 int32 长度前缀表示，
  负值 = 已分配(在用)，正值 = 空闲。
* nk(key node)：flags(含 KEY_COMP_NAME 0x20)、last written、parent、
  子键数/子键列表偏移、值个数/值列表偏移、安全键偏移、类名偏移、各类最大长度、键名。
* vk(value node)：名字长、数据大小(0x80000000 位 = 内联)、数据偏移、类型、flags(VALUE_COMP_NAME 0x01)。
* 大值(big data)：数据单元为 ``db`` 结构，由多段(segment)拼成，总长 <= 16344 时不用 db。
* 子键列表：``lf``/``lh``(带 hash 的快速叶)、``li``(叶)、``ri``(索引根，递归子索引)。
* 安全键 sk：读得到但不做 ACL 展开，遇到损坏仅记录不抛异常。

公开 API
--------
    Hive(data: bytes, name: str = "")
        .root() -> Key
        .open(path) -> Key | None
        .keys() -> list[str]
        .values() -> dict
        .close()
        .info() -> dict            # 基块信息 / 校验和结论 / hbin 列表（诊断用）
    Key
        .name .path .timestamp .flags .offset .depth
        .subkeys() .subkey_names() .values() .value(name) .value_names()
        .class_name() .security_offset() .is_root

注册表值类型解码：REG_SZ(1) REG_EXPAND_SZ(2) REG_BINARY(3) REG_DWORD(4)
REG_DWORD_BIG_ENDIAN(5) REG_LINK(6) REG_MULTI_SZ(7) REG_QWORD(11)。
字符串按 UTF-16LE 解码并去掉尾部 NUL；MULTI_SZ 返回 ``list[str]``。

命令行自检::

    python regf.py <hive 文件> [键路径]
"""

from __future__ import annotations

import datetime as _dt
import struct
import sys

__all__ = ["Hive", "Key", "RegfError", "VALUE_TYPES", "filetime_to_datetime"]

# ---------------------------------------------------------------- 常量

BASEBLOCK_SIZE = 0x1000          # 基块固定 4096 字节，hive bins 从 0x1000 开始
FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
BIG_DATA_THRESHOLD = 16344       # 超过此长度且非内联 -> 'db' 分段结构
MAX_KEY_DEPTH = 512              # 键层级硬上限，配合祖先集合防环
MAX_INDEX_DEPTH = 32             # ri 索引根递归上限
CELL_NONE = 0xFFFFFFFF           # 空引用

KEY_COMP_NAME = 0x0020           # nk.flags: 键名为 latin1(ASCII) 而非 UTF-16LE
KEY_HIVE_ENTRY = 0x0004
KEY_ROOT = 0x000C
VALUE_COMP_NAME = 0x0001         # vk.flags: 值名为 latin1(ASCII)

VALUE_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


class RegfError(Exception):
    """hive 结构非法（签名错、偏移越界、单元长度异常等）。"""


# ---------------------------------------------------------------- 小工具

def filetime_to_datetime(ft: int) -> _dt.datetime | None:
    """FILETIME(1601-01-01 起的 100ns 计数) -> 带 UTC 时区的 datetime。"""
    if not ft:
        return None
    try:
        return FILETIME_EPOCH + _dt.timedelta(microseconds=int(ft) // 10)
    except (OverflowError, ValueError):
        return None


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _i32(d: bytes, o: int) -> int:
    return struct.unpack_from("<i", d, o)[0]


def _u64(d: bytes, o: int) -> int:
    return struct.unpack_from("<Q", d, o)[0]


def _latin1(raw: bytes) -> str:
    return raw.decode("latin-1")


def _utf16(raw: bytes, errors: str = "replace") -> str:
    if len(raw) & 1:                      # 奇数长度：截掉最后孤立字节，避免解码报错
        raw = raw[:-1]
    return raw.decode("utf-16-le", errors)


def _cell_checksum(bb: bytes) -> int:
    """基块校验和：前 508(0x1FC) 字节按 DWORD 小端逐个异或。"""
    v = 0
    for (w,) in struct.iter_unpack("<I", bb[:0x1FC]):
        v ^= w
    return v & 0xFFFFFFFF


# ---------------------------------------------------------------- 值解码

def decode_value(dtype: int, raw: bytes):
    """按注册表值类型把原始字节解码成 Python 对象。"""
    if dtype in (1, 2, 6):                                   # REG_SZ / EXPAND_SZ / LINK
        return _utf16(raw).rstrip("\x00")
    if dtype == 3 or dtype == 0:                             # REG_BINARY / REG_NONE
        return raw
    if dtype == 4:                                           # REG_DWORD
        return _u32(raw, 0) if len(raw) >= 4 else raw
    if dtype == 5:                                           # REG_DWORD_BIG_ENDIAN
        return struct.unpack_from(">I", raw, 0)[0] if len(raw) >= 4 else raw
    if dtype == 7:                                           # REG_MULTI_SZ
        parts = _utf16(raw).split("\x00")
        while parts and parts[-1] == "":
            parts.pop()
        return parts
    if dtype == 11:                                          # REG_QWORD
        return _u64(raw, 0) if len(raw) >= 8 else raw
    return raw


# ---------------------------------------------------------------- Hive

class Hive:
    """一个 regf hive（内存中的完整字节）。"""

    def __init__(self, data: bytes, name: str = ""):
        if isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, bytearray):
            data = bytes(data)
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data 必须是 bytes/memoryview/bytearray")
        if len(data) < 0x1000:
            raise RegfError("文件小于 4096 字节，不可能是合法 hive")

        self.data = data if isinstance(data, bytes) else bytes(data)
        self.name = name or ""
        self.size = len(self.data)
        self.closed = False

        self._base = BASEBLOCK_SIZE      # bins 数据起点（regf 基块之后）
        self._bins: list[tuple[int, int]] = []
        self._nk_cache: dict[int, dict] = {}
        self._vk_cache: dict[int, dict] = {}
        self._root: Key | None = None

        self._parse_baseblock()

    # -------------------------------------------------- 基块

    def _parse_baseblock(self) -> None:
        d = self.data
        sig = d[:4]
        if sig == b"regf":
            bb = d[:BASEBLOCK_SIZE]
            self.signature = "regf"
            self.seq1 = _u32(bb, 0x04)
            self.seq2 = _u32(bb, 0x08)
            self.last_written_raw = _u64(bb, 0x0C)
            self.last_written = filetime_to_datetime(self.last_written_raw)
            self.major = _u32(bb, 0x14)
            self.minor = _u32(bb, 0x18)
            self.file_type = _u32(bb, 0x1C)          # 0=primary, 1=log, 2=external
            self.file_format = _u32(bb, 0x20)        # 1=direct memory load
            self.root_offset = _u32(bb, 0x24)
            self.hbins_size = _u32(bb, 0x28)
            self.cluster = _u32(bb, 0x2C)
            self.hive_filename = _utf16(bb[0x30:0x70]).rstrip("\x00")
            self.checksum_stored = _u32(bb, 0x1FC)
            self.checksum_calc = _cell_checksum(bb)
            self.checksum_ok = self.checksum_stored == self.checksum_calc
            self.recovered = bool(self.seq1 != self.seq2)   # dirty / 需回放日志
            self._base = BASEBLOCK_SIZE
        elif sig == b"hbin":
            # 裸 bin 数据（例如事务日志 .LOG1/.LOG2 被误当 hive 传入）：
            # 没有基块，bins 从 0 开始，根 nk 只能靠扫描确定。
            self.signature = "hbin"
            self.seq1 = self.seq2 = 0
            self.last_written_raw = 0
            self.last_written = None
            self.major = self.minor = 0
            self.file_type = 2
            self.file_format = 1
            self.hbins_size = self.size
            self.cluster = 1
            self.hive_filename = self.name
            self.checksum_stored = self.checksum_calc = 0
            self.checksum_ok = True
            self.recovered = False
            self._base = 0
            self.root_offset = self._scan_first_nk()
        else:
            raise RegfError("签名不是 'regf'/'hbin'，实际 %r" % (sig,))

        self._scan_bins()

    def _scan_first_nk(self) -> int:
        """裸 bins：顺序扫 hbin → cell，找到第一个 'nk' 并返回其相对偏移。"""
        pos = 0
        guard = 0
        d = self.data
        while pos + 0x20 <= len(d) and guard < 100000:
            if d[pos:pos + 4] != b"hbin":
                break
            bsize = _u32(d, pos + 8)
            if bsize < 0x20 or pos + bsize > len(d):
                break
            cpos = pos + 0x20
            while cpos + 4 <= pos + bsize:
                csz = _i32(d, cpos)
                total = -csz if csz < 0 else csz
                if total < 4 or cpos + total > pos + bsize:
                    break
                if -csz > 0 and d[cpos + 4:cpos + 6] == b"nk":
                    return cpos - self._base
                cpos += total
                guard += 1
            pos += bsize
        raise RegfError("裸 bins 中找不到 nk 单元")

    def _scan_bins(self) -> None:
        """登记 hbin 头（用于统计与诊断；正常查询直接按偏移寻址，不依赖它）。"""
        pos = self._base
        d = self.data
        total = 0
        while pos + 0x20 <= len(d):
            if d[pos:pos + 4] != b"hbin":
                break
            bsize = _u32(d, pos + 8)
            if bsize < 0x20 or bsize > 0x20000000:
                break
            end = pos + bsize
            if end > len(d):
                self._bins.append((pos - self._base, len(d) - pos))
                total += len(d) - pos
                break
            self._bins.append((pos - self._base, bsize))
            total += bsize
            pos = end
        self.hbins_scanned = total

    # -------------------------------------------------- 底层单元访问

    def _cell(self, off: int) -> tuple[int, int]:
        """返回 (单元总长, 载荷起点绝对偏移)。off 相对 bins 数据起点。"""
        base = self._base + off
        d = self.data
        if off < 0 or base + 4 > len(d):
            raise RegfError("单元偏移越界: 0x%08x" % (off & 0xFFFFFFFF))
        raw = _i32(d, base)
        if raw == 0:
            raise RegfError("单元长度非法(0): 0x%08x" % (off & 0xFFFFFFFF))
        total = -raw if raw < 0 else raw
        if total < 4:
            raise RegfError("单元长度过小(%d): 0x%08x" % (total, off & 0xFFFFFFFF))
        if base + total > len(d):                    # 截断，按可用长度收窄
            total = len(d) - base
            if total <= 4:
                raise RegfError("单元被截断: 0x%08x" % (off & 0xFFFFFFFF))
        return total, base + 4

    def _read(self, off: int, size: int) -> bytes:
        d = self.data
        p = self._base + off
        if p < 0 or p >= len(d) or size <= 0:
            return b""
        return d[p:min(p + size, len(d))]

    # -------------------------------------------------- nk

    def _nk(self, off: int) -> dict:
        cached = self._nk_cache.get(off)
        if cached is not None:
            return cached
        total, p = self._cell(off)
        d = self.data
        if d[p:p + 2] != b"nk":
            raise RegfError("偏移 0x%08x 处不是 nk 单元" % (off & 0xFFFFFFFF))
        avail = p + total - 4            # 载荷可用长度
        if p + 0x4C > avail:
            raise RegfError("nk 单元太短: 0x%08x" % (off & 0xFFFFFFFF))
        flags = _u16(d, p + 0x02)
        info = {
            "offset": off,
            "total_size": total,
            "flags": flags,
            "last_written_raw": _u64(d, p + 0x04),
            "last_written": filetime_to_datetime(_u64(d, p + 0x04)),
            "access_bits": _u32(d, p + 0x0C),
            "parent": _u32(d, p + 0x10),
            "subkey_count": _u32(d, p + 0x14),
            "volatile_subkey_count": _u32(d, p + 0x18),
            "subkey_list": _u32(d, p + 0x1C),
            "volatile_subkey_list": _u32(d, p + 0x20),
            "value_count": _u32(d, p + 0x24),
            "value_list": _u32(d, p + 0x28),
            "security": _u32(d, p + 0x2C),
            "class_name": _u32(d, p + 0x30),
            "max_subkey_name": _u32(d, p + 0x34),
            "max_subkey_class": _u32(d, p + 0x38),
            "max_value_name": _u32(d, p + 0x3C),
            "max_value_data": _u32(d, p + 0x40),
            "work_var": _u32(d, p + 0x44),
            "name_len": _u16(d, p + 0x48),
            "class_len": _u16(d, p + 0x4A),
            "comp_name": bool(flags & KEY_COMP_NAME),
        }
        nlen = info["name_len"]
        room = max(0, (p + total) - (p + 0x4C))
        if nlen > room:
            nlen = room
        raw = d[p + 0x4C:p + 0x4C + nlen]
        info["name"] = _latin1(raw) if info["comp_name"] else _utf16(raw)
        self._nk_cache[off] = info
        return info

    # -------------------------------------------------- vk

    def _vk(self, off: int) -> dict:
        cached = self._vk_cache.get(off)
        if cached is not None:
            return cached
        total, p = self._cell(off)
        d = self.data
        if d[p:p + 2] != b"vk":
            raise RegfError("偏移 0x%08x 处不是 vk 单元" % (off & 0xFFFFFFFF))
        nlen = _u16(d, p + 0x02)
        dsize = _u32(d, p + 0x04)
        doff = _u32(d, p + 0x08)
        dtype = _u32(d, p + 0x0C)
        vflags = _u16(d, p + 0x10)
        inline = bool(dsize & 0x80000000)
        real = dsize & 0x7FFFFFFF
        room = max(0, (p + total) - (p + 0x14))
        if nlen > room:
            nlen = room
        raw_name = d[p + 0x14:p + 0x14 + nlen]
        name = _latin1(raw_name) if (vflags & VALUE_COMP_NAME) else _utf16(raw_name)
        info = {
            "offset": off,
            "total_size": total,
            "name": name,
            "name_len": nlen,
            "data_size_field": dsize,
            "data_size": real,
            "data_offset": doff,
            "type": dtype,
            "flags": vflags,
            "inline": inline,
        }
        self._vk_cache[off] = info
        return info

    def _value_bytes(self, vk: dict) -> bytes:
        """取出 vk 的数据字节，含内联与 'db' 大值拼接。"""
        real = vk["data_size"]
        if vk["inline"]:
            return struct.pack("<I", vk["data_offset"])[:min(real, 4)]
        if real == 0 or vk["data_offset"] in (0, CELL_NONE):
            return b""
        off = vk["data_offset"]
        d = self.data

        # 先看数据单元是不是 'db'（大值分段）
        try:
            total, p = self._cell(off)
        except RegfError:
            return b""
        if d[p:p + 2] == b"db":
            return self._read_big_data(p, total, real)
        # 普通单元：载荷去掉 4 字节长度前缀
        n = min(real, total - 4)
        return d[p:p + n] if n > 0 else b""

    def _read_big_data(self, p: int, total: int, real: int) -> bytes:
        """'db' 单元：段数 + 段列表偏移 -> 拼所有段，最后按实际长度截断。"""
        d = self.data
        if total < 8:
            return b""
        nseg = _u16(d, p + 2)
        list_off = _u32(d, p + 4)
        if nseg == 0 or nseg > 0x4000 or list_off in (0, CELL_NONE):
            return b""
        try:
            ltotal, lp = self._cell(list_off)
        except RegfError:
            return b""
        capacity = (ltotal - 4) // 4
        nseg = min(nseg, capacity)
        chunks = []
        got = 0
        for i in range(nseg):
            seg_off = _u32(d, lp + 4 * i)
            if seg_off in (0, CELL_NONE):
                break
            try:
                stotal, sp = self._cell(seg_off)
            except RegfError:
                break
            n = stotal - 4
            if n <= 0:
                break
            n = min(n, real - got)
            if n <= 0:
                break
            chunks.append(d[sp:sp + n])
            got += n
            if got >= real:
                break
        return b"".join(chunks)

    # -------------------------------------------------- 子键列表

    def _subkey_offsets(self, nk: dict) -> list[int]:
        """展开 lf/lh/li/ri 得到子键 nk 偏移列表（保持原始顺序）。"""
        cnt = nk["subkey_count"]
        loff = nk["subkey_list"]
        if cnt == 0 or loff in (0, CELL_NONE):
            return []
        out: list[int] = []
        try:
            self._walk_index(loff, 0, out, limit=cnt)
        except RegfError:
            return out
        return out

    def _walk_index(self, off: int, depth: int, out: list[int], limit: int) -> None:
        if depth > MAX_INDEX_DEPTH or len(out) >= limit or off in (0, CELL_NONE):
            return
        total, p = self._cell(off)
        d = self.data
        tag = d[p:p + 2]
        n = _u16(d, p + 2)
        room = (total - 4 - 4)
        if tag in (b"lf", b"lh"):
            if n * 8 > room:
                n = max(0, room // 8)
            for i in range(n):
                if len(out) >= limit:
                    return
                out.append(_u32(d, p + 4 + 8 * i))
        elif tag == b"li":
            if n * 4 > room:
                n = max(0, room // 4)
            for i in range(n):
                if len(out) >= limit:
                    return
                out.append(_u32(d, p + 4 + 4 * i))
        elif tag == b"ri":
            if n * 4 > room:
                n = max(0, room // 4)
            for i in range(n):
                if len(out) >= limit:
                    return
                self._walk_index(_u32(d, p + 4 + 4 * i), depth + 1, out, limit)
        # 其它 tag（含损坏）静默跳过

    def _value_offsets(self, nk: dict) -> list[int]:
        cnt = nk["value_count"]
        loff = nk["value_list"]
        if cnt == 0 or loff in (0, CELL_NONE):
            return []
        try:
            total, p = self._cell(loff)
        except RegfError:
            return []
        capacity = (total - 4) // 4
        cnt = min(cnt, capacity)
        d = self.data
        return [_u32(d, p + 4 * i) for i in range(cnt)]

    # -------------------------------------------------- 公开 API

    def root(self) -> "Key":
        if self._root is None:
            self._root = Key(self, self.root_offset, None, ())
        return self._root

    def open(self, path: str) -> "Key | None":
        """按反斜杠路径打开键，大小写不敏感；任何错误/找不到都返回 None。"""
        if self.closed or path is None:
            return None
        try:
            root = self.root()
            if isinstance(path, bytes):
                path = path.decode("latin-1")
            if not isinstance(path, str):
                return None
            parts = [x for x in path.replace("/", "\\").split("\\") if x]
            if not parts:
                return root
            got = self._resolve(root, parts)
            if got is not None:
                return got
            # 兼容写法：首段写成 hive 名（'Virtual\\SAM\\Domains' 之类），
            # 直接解析失败时退回「剥掉首段再解析」。真实 SAM hive 根下恰好
            # 也有一个名为 'SAM' 的子键，所以必须先按原样解析，再考虑剥前缀。
            if len(parts) > 1 and root.name and parts[0].lower() == root.name.lower():
                return self._resolve(root, parts[1:])
            return None
        except (RegfError, struct.error, ValueError, UnicodeError, MemoryError, KeyError):
            return None
        except Exception:                     # 解析器对外永不抛异常
            return None

    @staticmethod
    def _resolve(root: "Key", parts: list[str]) -> "Key | None":
        """从 root 起逐段向下查找，任一段失配返回 None。"""
        cur = root
        for seg in parts:
            if cur._depth >= MAX_KEY_DEPTH:
                return None
            low = seg.lower()
            nxt = None
            for child in cur.subkeys():
                if child.name.lower() == low:
                    nxt = child
                    break
            if nxt is None:
                return None
            cur = nxt
        return cur

    def keys(self) -> list[str]:
        try:
            return self.root().subkey_names()
        except Exception:
            return []

    def values(self) -> dict:
        try:
            return self.root().values()
        except Exception:
            return {}

    def close(self) -> None:
        self.closed = True
        self._nk_cache.clear()
        self._vk_cache.clear()
        self.data = b""
        self._root = None

    def __enter__(self) -> "Hive":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return "<Hive %r size=%d bins=%d%s>" % (
            self.name or self.hive_filename, self.size, len(self._bins),
            " dirty" if self.recovered else "")

    # -------------------------------------------------- 诊断

    def validate(self) -> dict:
        """遍历所有 hbin 的单元链，检查是否严丝合缝铺满每个 bin。

        返回统计：bin 数、单元数、分配/空闲数、各 tag 计数、是否完美铺满。
        单元长度前缀解释正确时，所有单元的绝对长度之和必然等于 bin 大小。
        """
        d = self.data
        bins = cells = alloc = free = 0
        tags: dict[str, int] = {}
        gaps: list[tuple[int, int]] = []
        for rel, bsize in self._bins:
            bins += 1
            pos = rel + 0x20
            end = rel + bsize
            used = 0x20
            guard = 0
            while pos + 4 <= end:
                guard += 1
                if guard > 1000000:
                    break
                fo = self._base + pos
                if fo + 4 > len(d):
                    break
                raw = _i32(d, fo)
                total = -raw if raw < 0 else raw
                if total < 4 or pos + total > end:
                    gaps.append((pos, total))
                    break
                cells += 1
                if raw < 0:
                    alloc += 1
                    if total >= 6:
                        key = d[fo + 4:fo + 6].decode("latin-1")
                        if key.isprintable():
                            tags[key] = tags.get(key, 0) + 1
                else:
                    free += 1
                used += total
                pos += total
            if used != bsize:
                gaps.append((rel + used, bsize - used))
        out = {
            "bins": bins,
            "cells": cells,
            "allocated": alloc,
            "free": free,
            "tags": dict(sorted(tags.items(), key=lambda kv: -kv[1])),
            "tiling_ok": not gaps,
            "gaps": gaps[:8],
        }
        return out

    def info(self) -> dict:
        """基块与校验信息汇总（校验和不匹配只报告，不阻断解析）。"""
        return {
            "name": self.name,
            "size": self.size,
            "signature": self.signature,
            "seq1": self.seq1,
            "seq2": self.seq2,
            "dirty": self.recovered,
            "last_written": self.last_written,
            "version": "%d.%d" % (self.major, self.minor),
            "file_type": self.file_type,
            "file_format": self.file_format,
            "root_offset": self.root_offset,
            "hbins_size": self.hbins_size,
            "hbins_scanned": getattr(self, "hbins_scanned", 0),
            "hbin_count": len(self._bins),
            "cluster": self.cluster,
            "hive_filename": self.hive_filename,
            "checksum_stored": self.checksum_stored,
            "checksum_calc": self.checksum_calc,
            "checksum_ok": self.checksum_ok,
        }


# ---------------------------------------------------------------- Key

class Key:
    """注册表键（惰性解析：属性首次访问时才读 nk 单元）。"""

    __slots__ = ("_hive", "_off", "_parent", "_chain", "_depth", "_nk", "_refused")

    def __init__(self, hive: Hive, off: int, parent: "Key | None", chain: tuple):
        self._hive = hive
        self._off = off
        self._parent = parent
        self._chain = chain            # 祖先 nk 偏移元组，用于防环
        self._depth = 0 if parent is None else parent._depth + 1
        self._nk = None
        self._refused = False

    # -------------------------------------------------- 基础

    @property
    def offset(self) -> int:
        return self._off

    @property
    def depth(self) -> int:
        return self._depth

    def _node(self) -> dict:
        if self._nk is None:
            try:
                self._nk = self._hive._nk(self._off)
            except Exception:
                self._nk = {
                    "offset": self._off, "name": "", "flags": 0, "parent": 0,
                    "subkey_count": 0, "subkey_list": 0, "value_count": 0,
                    "value_list": 0, "security": 0, "class_name": 0,
                    "class_len": 0, "last_written": None, "comp_name": False,
                    "name_len": 0, "total_size": 0, "access_bits": 0,
                    "volatile_subkey_count": 0, "volatile_subkey_list": 0,
                    "max_subkey_name": 0, "max_subkey_class": 0,
                    "max_value_name": 0, "max_value_data": 0, "work_var": 0,
                    "last_written_raw": 0,
                }
                self._refused = True
        return self._nk

    @property
    def name(self) -> str:
        nm = self._node()["name"]
        if not nm and self._parent is None:
            return self._hive.name or self._hive.hive_filename or "ROOT"
        return nm

    @property
    def flags(self) -> int:
        return self._node()["flags"]

    @property
    def is_root(self) -> bool:
        return self._parent is None

    @property
    def timestamp(self) -> "_dt.datetime | None":
        """nk 的 last written（UTC）。"""
        return self._node()["last_written"]

    @property
    def path(self) -> str:
        if self._parent is None:
            return self.name
        return self._parent.path + "\\" + self.name

    def class_name(self) -> str | None:
        nk = self._node()
        clen = nk["class_len"]
        off = nk["class_name"]
        if not clen or off in (0, CELL_NONE):
            return None
        try:
            total, p = self._hive._cell(off)
        except RegfError:
            return None
        n = min(clen, total - 4)
        if n <= 0:
            return None
        return _utf16(self._hive.data[p:p + n])

    def security_offset(self) -> int | None:
        sk = self._node()["security"]
        return None if sk in (0, CELL_NONE) else sk

    # -------------------------------------------------- 子键

    def subkeys(self) -> list["Key"]:
        if self._depth >= MAX_KEY_DEPTH:
            return []
        try:
            offs = self._hive._subkey_offsets(self._node())
        except Exception:
            return []
        chain = self._chain + (self._off,)
        out: list[Key] = []
        seen: set[int] = set()
        for off in offs:
            if off in seen or off in chain:      # 重复项/成环直接丢弃
                continue
            seen.add(off)
            try:
                self._hive._nk(off)              # 校验目标确实是 nk
            except Exception:
                continue
            out.append(Key(self._hive, off, self, chain))
        return out

    def subkey_names(self) -> list[str]:
        return [k.name for k in self.subkeys()]

    def subkey(self, name: str) -> "Key | None":
        if not isinstance(name, str):
            return None
        low = name.lower()
        for k in self.subkeys():
            if k.name.lower() == low:
                return k
        return None

    # -------------------------------------------------- 值

    def value_names(self) -> list[str]:
        try:
            offs = self._hive._value_offsets(self._node())
        except Exception:
            return []
        names = []
        for off in offs:
            try:
                names.append(self._hive._vk(off)["name"])
            except Exception:
                names.append("")
        return names

    def value(self, name: str) -> "tuple[int, object] | None":
        """取单个值 -> (类型, 解码后的值)；不存在返回 None。"""
        if not isinstance(name, str):
            return None
        low = name.lower()
        try:
            offs = self._hive._value_offsets(self._node())
        except Exception:
            return None
        for off in offs:
            try:
                vk = self._hive._vk(off)
            except Exception:
                continue
            if vk["name"].lower() == low or (name == "" and vk["name"] == ""):
                return self._decode(vk)
        return None

    def _decode(self, vk: dict) -> tuple[int, object]:
        try:
            raw = self._hive._value_bytes(vk)
        except Exception:
            raw = b""
        return vk["type"], decode_value(vk["type"], raw)

    def values(self) -> dict:
        """全部值：{名字: (类型, 解码后的值)}，按值列表顺序，重名后者覆盖。"""
        out: dict = {}
        try:
            offs = self._hive._value_offsets(self._node())
        except Exception:
            return out
        for off in offs:
            try:
                vk = self._hive._vk(off)
            except Exception:
                continue
            out[vk["name"]] = self._decode(vk)
        return out

    def value_raw(self, name: str) -> bytes | None:
        """调试用：取原始字节（不做类型解码）。"""
        if not isinstance(name, str):
            return None
        low = name.lower()
        for off in self._hive._value_offsets(self._node()):
            vk = self._hive._vk(off)
            if vk["name"].lower() == low:
                return self._hive._value_bytes(vk)
        return None

    # -------------------------------------------------- 杂项

    def __eq__(self, other) -> bool:
        return isinstance(other, Key) and other._hive is self._hive and other._off == self._off

    def __hash__(self) -> int:
        return hash((id(self._hive), self._off))

    def __repr__(self) -> str:
        return "<Key %r off=0x%x subs=%d vals=%d>" % (
            self.path, self._off, self._node()["subkey_count"], self._node()["value_count"])


# ---------------------------------------------------------------- CLI

def _dump_key(k: Key, depth: int = 0, max_depth: int = 2) -> None:
    pad = "  " * depth
    ts = k.timestamp.isoformat() if k.timestamp else "-"
    print("%s[%s]  subs=%d vals=%d  %s" % (pad, k.name, len(k.subkeys()), len(k.values()), ts))
    for nm, (tp, val) in k.values().items():
        shown = repr(val)
        if len(shown) > 120:
            shown = shown[:117] + "..."
        print("%s  %-28s %-20s %s" % (pad, nm or "(默认)", VALUE_TYPES.get(tp, tp), shown))
    if depth < max_depth:
        for c in k.subkeys():
            _dump_key(c, depth + 1, max_depth)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("用法: python regf.py <hive 文件> [键路径] [--depth N]")
        return 2
    path = argv[1]
    keypath = None
    max_depth = 2
    args = argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--depth" and i + 1 < len(args):
            max_depth = int(args[i + 1])
            i += 2
            continue
        if keypath is None:
            keypath = args[i]
        i += 1

    import os
    t0 = _dt.datetime.now()
    with open(path, "rb") as f:
        data = f.read()
    h = Hive(data, os.path.basename(path))
    nk = None
    if keypath:
        nk = h.open(keypath)
        if nk is None:
            print("未找到键: %s" % keypath)
            return 1
    else:
        nk = h.root()
    for k, v in h.info().items():
        print("%-16s %s" % (k, v))
    print("-" * 60)
    _dump_key(nk, 0, max_depth)
    print("-" * 60)
    print("耗时 %.3fs" % (_dt.datetime.now() - t0).total_seconds())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
