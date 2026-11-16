# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ReFS（Resilient File System）只读解析

格式依据 libfsrefs（Joachim Metz）《Resilient File System (ReFS)》asciidoc 0.0.5，
逐节核对过的结构在注释里标「文档」。

已实现：
    第 1 层 · 卷头与超级块
        · 卷头 volume header @0（512 B）：JMP、"ReFS" 签名、"FSRS" 识别结构、
          扇区数、扇区大小、每簇扇区数、主/次格式版本、卷序列号、容器大小
        · 卷头副本（卷尾 512 B，文档「a copy of the volume header」）
        · 超级块 SUPB：默认采样点 0x10000，另外对头部 8 MiB / 尾部 8 MiB 做
          簇对齐扫描，把所有有效 SUPB 都收进 superblocks()
        · SUPB 内部：卷 GUID、检查点引用表、自身块引用、元数据块头 v1(48B)/v3(80B)
        · 主超级块坏了按偏移顺序回退到备份（后面的 SUPB 副本）

    第 2 层 · 检查点与对象表
        · 检查点 CHKP：超级块副本、检查点头（主/次版本）、检查点尾（偏移数组）、
          13 个 Ministore 树引用（对象 / 介质分配器 / 容器分配器 / 模式 / 父子 /
          对象副本 / 引用计数 / 容器 / 容器副本 / 模式副本 / 容器索引 / 完整性 / 小分配器）
        · Ministore B+ 树（MSB+）：节点头、层号、类型标志、记录数组；
          分支节点递归下降（带环检测），记录 key/value 按 v1(24B)/v3(48B) 块引用解出
        · 对象表：key = 16 B 文件系统标识（高 64 位 + 低 64 位对象 ID）→ 块引用
        · 卷信息对象 0x500 → 卷名记录 0x510（UTF-16LE）

    第 3 层 · 目录与文件
        · 目录对象树：记录类型 0x10 base / 0x20 name / 0x30 entry
        · 目录项类型 0 metadata / 1 file / 2 dir
        · 目录值 72 B：目录对象 ID + 四个 FILETIME + 文件属性位
        · 文件值的 128 B 内嵌头：四个 FILETIME、属性位、文件系统标识、
          数据大小、已分配大小
        · 常驻（resident）$DATA 属性直接读出内容
        · listdir / walk / find / read_file

不实现（调用即抛，不返回空数据）：
    · 写操作、CRC-32C / CRC64-ECMA-182 校验（只读字段，不验证）
    · 非驻留 $DATA 的簇映射 —— libfsrefs 没有给出 file extent 布局，
      遇到非驻留属性抛 NotImplementedError，绝不返回空 bytes
    · 备用数据流 0xb0 $NAMED_DATA、重解析点 0xc0、EA 0xd0/0xe0
    · 容器记录 160 B 值里的语义字段（8 个字段文档仍标 unknown，只做定位不解释）
    · 1.x 版卷（容器大小为 0 的老格式）的分配器树内容

推断（文档未明写，靠结构自洽性验证，代码里标「推断」）：
    · 元数据块地址语义：block_number × cluster_size
    · Ministore 记录偏移数组的基准（节点头 vs 块起点）—— 两个基准都试，
      取全部记录都自洽的那个，优先节点头（文档原文是相对节点头）
    · 检查点尾的位置：self_ref_offset - self_ref_size / self_ref_offset + size /
      检查点头之后，三处都试，失败再窗口扫描（文档没写尾与自身引用的先后）
    · 文件值里 128 B 内嵌头紧贴在节点头之前（文档只说「内嵌 Ministore 节点含
      头数据与属性记录」，未给顺序）
"""

import struct
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch

__all__ = [
    "Refs", "RefsError", "RefsEntry", "RefsRecord",
    "probe", "open_fs",
    "REFS_SIGNATURE", "REFS_FSRS",
    "MAGIC_SUPERBLOCK", "MAGIC_CHECKPOINT", "MAGIC_MINISTORE",
    "VOLUME_HEADER_OFFSET", "VOLUME_HEADER_SIZE", "SUPERBLOCK_OFFSET",
    "TREE_OBJECTS", "TREE_SCHEMA", "TREE_CONTAINERS",
    "OBJECT_VOLUME_INFO", "OBJECT_ROOT_DIRECTORY",
]

# ---------------------------------------------------------------- 常量 · 卷头
VOLUME_HEADER_OFFSET = 0
VOLUME_HEADER_SIZE = 512

REFS_SIGNATURE = b"ReFS"        # 文档：偏移 3，8 字节 "ReFS\x00\x00\x00\x00"
REFS_FSRS = b"FSRS"             # 文档：偏移 16，文件系统识别结构标识

SUPERBLOCK_OFFSET = 0x10000     # 64 KiB，公开分析常用的 SUPB 采样点
SCAN_LIMIT = 8 << 20            # 头部/尾部各扫 8 MiB

MAGIC_SUPERBLOCK = b"SUPB"      # 文档：level 0
MAGIC_CHECKPOINT = b"CHKP"      # 文档：level 1
MAGIC_MINISTORE = b"MSB+"       # 文档：level 2+

BLOCK_HEADER_V1 = 48            # 文档：format version 1 元数据块头
BLOCK_HEADER_V3 = 80            # 文档：format version 3 元数据块头

# ---------------------------------------------------------------- 常量 · 树索引
# 文档「Ministore tree block references」
TREE_OBJECTS = 0
TREE_MEDIUM_ALLOC = 1
TREE_CONTAINER_ALLOC = 2
TREE_SCHEMA = 3
TREE_PARENT_CHILD = 4
TREE_OBJECTS_COPY = 5
TREE_BLOCK_REFCOUNT = 6
TREE_CONTAINERS = 7             # 文档：Seen in format version 3
TREE_CONTAINERS_COPY = 8
TREE_SCHEMA_COPY = 9
TREE_CONTAINER_INDEX = 10
TREE_INTEGRITY = 11
TREE_SMALL_ALLOC = 12

TREE_NAMES = {
    0: "objects", 1: "medium_allocator", 2: "container_allocator", 3: "schema",
    4: "parent_child", 5: "objects_copy", 6: "block_refcount", 7: "containers",
    8: "containers_copy", 9: "schema_copy", 10: "container_index",
    11: "integrity", 12: "small_allocator",
}

# ---------------------------------------------------------------- 常量 · 对象 ID
# 文档「Object identifiers」
OBJECT_UPCAKE = 0x00000007
OBJECT_UPCAKE_COPY = 0x00000008
OBJECT_LOGFILE_INFO = 0x00000009
OBJECT_LOGFILE_INFO_COPY = 0x0000000A
OBJECT_TRASH_STREAM = 0x0000000D
OBJECT_VOLUME_INFO = 0x00000500
OBJECT_VOLUME_INFO_COPY = 0x00000501
OBJECT_FS_INFO = 0x00000520
OBJECT_UNKNOWN_530 = 0x00000530
OBJECT_UNKNOWN_540 = 0x00000540
OBJECT_UNKNOWN_541 = 0x00000541
OBJECT_ROOT_DIRECTORY = 0x00000600
OBJECT_DIRECTORY_FIRST = 0x00000701

REC_VOLUME_NAME = 0x00000510     # 文档：卷信息记录里的卷名记录

OBJECT_NAMES = {
    0x00000007: "upcase", 0x00000008: "upcase_copy",
    0x00000009: "logfile_info", 0x0000000A: "logfile_info_copy",
    0x0000000D: "trash_stream",
    0x00000500: "volume_info", 0x00000501: "volume_info_copy",
    0x00000520: "fs_info", 0x00000530: "unknown_530",
    0x00000540: "unknown_540", 0x00000541: "unknown_541",
    0x00000600: "root_directory",
}

# ---------------------------------------------------------------- 常量 · 节点
NODE_FLAG_BRANCH = 0x01         # 文档：Node type flags
NODE_FLAG_ROOT = 0x02
NODE_FLAG_STREAM = 0x04

# 文档：Node record flags
RECORD_FLAG_NO_KEY = 0x0002
RECORD_FLAG_FREE = 0x0004
RECORD_FLAG_EMBEDDED_NODE = 0x0008
RECORD_FLAG_STREAM = 0x0040

# ---------------------------------------------------------------- 常量 · 目录
REC_BASE = 0x0010               # 文档：Record types
REC_NAME = 0x0020
REC_ENTRY = 0x0030

ENTRY_METADATA = 0              # 文档：Directory entry types
ENTRY_FILE = 1
ENTRY_DIR = 2

ENTRY_TYPE_NAME = {0: "metadata", 1: "file", 2: "dir"}

# 文档：Attribute record 类型
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILENAME = 0x30
ATTR_DIR_LINK = 0x38
ATTR_OBJECT_ID = 0x40
ATTR_OBSOLETE = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFO = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_NAMED_DATA = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_EA_INFORMATION = 0xD0
ATTR_EA = 0xE0

ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION", 0x30: "$FILENAME", 0x38: "$DIR_LINK",
    0x40: "$OBJECT_ID", 0x50: "$OBSOLETE", 0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFO", 0x80: "$DATA", 0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION", 0xB0: "$NAMED_DATA", 0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION", 0xE0: "$EA",
}

FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_ARCHIVE = 0x00000020

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class RefsError(ValueError):
    """ReFS 结构不合法 / 输入被截断"""


# ---------------------------------------------------------------- 小工具
def _u8(b, o):
    return b[o] if 0 <= o < len(b) else 0


def _u16(b, o):
    if o < 0 or o + 2 > len(b):
        return 0
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    if o < 0 or o + 4 > len(b):
        return 0
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    if o < 0 or o + 8 > len(b):
        return 0
    return struct.unpack_from("<Q", b, o)[0]


def _guid(raw):
    """16 B 小端混合序 GUID -> 字符串"""
    if len(raw) < 16:
        return None
    if raw == b"\x00" * 16:
        return None
    d1 = struct.unpack_from("<I", raw, 0)[0]
    d2 = struct.unpack_from("<H", raw, 4)[0]
    d3 = struct.unpack_from("<H", raw, 6)[0]
    return "%08x-%04x-%04x-%s-%s" % (
        d1, d2, d3, raw[8:10].hex(), raw[10:16].hex())


def _filetime(value):
    """FILETIME（1601 起的 100 ns）-> ISO8601 字符串"""
    if not value:
        return None
    try:
        return (_EPOCH + timedelta(microseconds=value // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _utf16(buf, off, size=None):
    """UTF-16LE（无 BOM，无结尾 NUL）-> str；容忍孤立代理项"""
    if off < 0 or off >= len(buf):
        return ""
    raw = buf[off:] if size is None else buf[off:off + size]
    if len(raw) % 2:
        raw = raw[:-1]
    if not raw:
        return ""
    text = raw.decode("utf-16-le", "replace")
    return text.split("\x00")[0]


def _split_path(path):
    if path is None:
        return []
    s = str(path).replace("\\", "/")
    return [p for p in s.split("/") if p and p != "."]


class RefsRecord(object):
    """Ministore 节点里的一条记录"""

    __slots__ = ("key", "value", "flags", "offset")

    def __init__(self, key, value, flags=0, offset=0):
        self.key = key
        self.value = value
        self.flags = flags
        self.offset = offset

    @property
    def key_type(self):
        return _u16(self.key, 0)

    @property
    def object_id(self):
        if len(self.key) >= 16:
            return _u64(self.key, 8)
        if len(self.key) == 8:
            return _u64(self.key, 0)
        return None

    @property
    def has_embedded_node(self):
        return bool(self.flags & RECORD_FLAG_EMBEDDED_NODE)

    def __repr__(self):
        return "<RefsRecord key=%dB value=%dB flags=0x%04X>" % (
            len(self.key), len(self.value), self.flags)


class RefsEntry(object):
    """目录里的一个条目"""

    __slots__ = ("name", "entry_type", "object_id", "file_id", "size",
                 "allocated", "created", "modified", "entry_modified",
                 "accessed", "attributes", "raw")

    def __init__(self, name="", entry_type=ENTRY_FILE, object_id=None,
                 file_id=None, size=None, allocated=None, created=None,
                 modified=None, entry_modified=None, accessed=None,
                 attributes=0, raw=b""):
        self.name = name
        self.entry_type = entry_type
        self.object_id = object_id
        self.file_id = file_id
        self.size = size
        self.allocated = allocated
        self.created = created
        self.modified = modified
        self.entry_modified = entry_modified
        self.accessed = accessed
        self.attributes = attributes
        self.raw = raw

    @property
    def type_name(self):
        return ENTRY_TYPE_NAME.get(self.entry_type, "unknown")

    @property
    def is_dir(self):
        return self.entry_type == ENTRY_DIR

    @property
    def is_file(self):
        return self.entry_type == ENTRY_FILE

    def __repr__(self):
        return "<RefsEntry %s %r %s>" % (
            self.type_name, self.name,
            "" if self.size is None else "%dB" % self.size)


class Refs(object):
    """ReFS 只读"""

    def __init__(self, sub):
        self.sub = sub
        self.size = getattr(sub, "size", None)
        if self.size is None:
            data = getattr(sub, "data", None)
            self.size = len(data) if data is not None else None
        self._sbs = None
        self._sb = None
        self._ck = None
        self._objects = None
        self._label = None
        self._nodes = {}
        self.volume_header = b""
        self._read_volume_header()
        self.superblocks()

    # ---------------- 底层读取 ----------------
    def _read(self, off, size):
        if off < 0 or size <= 0:
            return b""
        try:
            return self.sub.read(off, size) or b""
        except Exception:
            return b""

    # ---------------- 第 1 层：卷头 ----------------
    def _read_volume_header(self):
        hdr = self._read(VOLUME_HEADER_OFFSET, VOLUME_HEADER_SIZE)
        if len(hdr) < VOLUME_HEADER_SIZE:
            raise RefsError("镜像太短：卷头需要 %d B，只读到 %d B"
                            % (VOLUME_HEADER_SIZE, len(hdr)))
        # 文档：偏移 3 的 8 字节签名 "ReFS\x00\x00\x00\x00"
        if hdr[3:7] != REFS_SIGNATURE:
            raise RefsError("不是 ReFS：偏移 3 处签名 %r" % hdr[3:11])
        self.volume_header = hdr
        self.fsrs = hdr[16:20] == REFS_FSRS
        self.number_of_sectors = _u64(hdr, 24)
        self.sector_size = _u32(hdr, 32)
        self.sectors_per_cluster = _u32(hdr, 36)
        self.major_version = _u8(hdr, 40)
        self.minor_version = _u8(hdr, 41)
        self.format_flags = _u16(hdr, 42)
        self.volume_serial = _u64(hdr, 56)
        self.container_size = _u64(hdr, 64)
        if not (512 <= self.sector_size <= 0x10000):
            raise RefsError("扇区大小不合理：%d" % self.sector_size)
        if not (1 <= self.sectors_per_cluster <= 0x10000):
            raise RefsError("每簇扇区数不合理：%d" % self.sectors_per_cluster)
        self.cluster_size = self.sector_size * self.sectors_per_cluster
        if not (512 <= self.cluster_size <= (1 << 25)):
            raise RefsError("簇大小不合理：%d" % self.cluster_size)

    @property
    def fs_version(self):
        return "%d.%d" % (self.major_version, self.minor_version)

    def volume_header_backup(self):
        """卷尾的卷头副本（文档：A copy of volume header at the end of the volume）"""
        if not self.size or self.size < VOLUME_HEADER_SIZE * 2:
            return None
        off = self.size - VOLUME_HEADER_SIZE
        buf = self._read(off, VOLUME_HEADER_SIZE)
        if len(buf) < VOLUME_HEADER_SIZE or buf[3:7] != REFS_SIGNATURE:
            return None
        return {"offset": off, "guid_like": buf[3:11], "raw": buf}

    # ---------------- 第 1 层：超级块 ----------------
    def _scan_offsets(self, magic, start, end, chunk=1 << 20):
        """按簇对齐在 [start, end) 里找 magic 的偏移"""
        out = []
        if end <= start:
            return out
        pos = start
        step = max(chunk, self.cluster_size * 2)
        while pos < end:
            n = min(step, end - pos)
            if n < 32:
                break
            buf = self._read(pos, n)
            if not buf:
                break
            i = buf.find(magic)
            while i >= 0:
                off = pos + i
                if off % self.cluster_size == 0:
                    out.append(off)
                i = buf.find(magic, i + 1)
            if len(buf) < n:
                break
            pos += max(n - 16, 1)
        return out

    def _parse_superblock(self, offset):
        buf = self._read(offset, 512)
        if len(buf) < 128:
            raise RefsError("超级块 @0x%X 读不到 128 B（只有 %d B）"
                            % (offset, len(buf)))
        # 文档：format version 3 的元数据块头在 0 处有签名；
        # version 1 的块头 48 B，0 处是块号
        if buf[0:4] == MAGIC_SUPERBLOCK:
            hdr_len, hdr_ver = BLOCK_HEADER_V3, 3
        else:
            hdr_len, hdr_ver = BLOCK_HEADER_V1, 1
            # 推断：v1 块头 0 处是块号，块号必须与所在偏移自洽，否则判定不是 SUPB
            if _u64(buf, 0) != offset // self.cluster_size:
                raise RefsError("超级块 @0x%X 无签名且块号不符（%d），判为无效"
                                % (offset, _u64(buf, 0)))
        base = hdr_len
        if len(buf) < base + 48:
            raise RefsError("超级块 @0x%X 结构被截断" % offset)
        # 文档：Superblock 48 B —— 卷标识 16 B / 0x00 8 B / 序列号 8 B /
        # 检查点引用偏移 4 B / 检查点条目数 4 B / 自身引用偏移 4 B / 大小 4 B
        out = {
            "offset": offset,
            "block_number": offset // self.cluster_size,
            "header_version": hdr_ver,
            "header_size": hdr_len,
            "volume_guid_raw": buf[base:base + 16],
            "volume_guid": _guid(buf[base:base + 16]),
            "sequence": _u64(buf, base + 24),
            "checkpoint_refs_offset": _u32(buf, base + 32),
            "checkpoint_count": _u32(buf, base + 36),
            "self_ref_offset": _u32(buf, base + 40),
            "self_ref_size": _u32(buf, base + 44),
            "header_block_numbers": [],
        }
        if hdr_ver == 3:
            # 文档：format version 3 块头 32..63 为四个块号
            out["header_block_numbers"] = [_u64(buf, 32 + 8 * i) for i in range(4)]
        else:
            out["header_block_numbers"] = [_u64(buf, 0)]

        blocks = []
        n = out["checkpoint_count"]
        if 0 < n <= 32 and out["checkpoint_refs_offset"]:
            raw = self._read(offset + out["checkpoint_refs_offset"], 8 * n)
            blocks = [_u64(raw, 8 * i) for i in range(len(raw) // 8)]
            blocks = [b for b in blocks if b]
        out["checkpoint_blocks"] = blocks

        if out["volume_guid"] is None:
            raise RefsError("超级块 @0x%X 卷 GUID 全零，判为无效" % offset)
        return out

    def superblocks(self):
        """所有有效 SUPB（偏移升序），第 0 个当主块"""
        if self._sbs is not None:
            return self._sbs
        found_offsets = []
        head_end = SUPERBLOCK_OFFSET + SCAN_LIMIT
        end = head_end if self.size is None else min(head_end, max(self.size, 0x100))
        found_offsets += self._scan_offsets(MAGIC_SUPERBLOCK, 0, end)
        if self.size:
            tail = max(0, self.size - SCAN_LIMIT)
            if tail > end:
                found_offsets += self._scan_offsets(MAGIC_SUPERBLOCK, tail, self.size)
        out = []
        errors = []
        candidates = list(found_offsets)
        # 推断：format version 1 的超级块没有签名，扫描找不到，只能试固定采样点
        for off in (SUPERBLOCK_OFFSET, self.cluster_size * 4):
            if off not in candidates:
                candidates.append(off)
        for off in sorted(set(candidates)):
            try:
                out.append(self._parse_superblock(off))
            except RefsError as exc:
                errors.append(str(exc))
        if not out:
            raise RefsError("找不到有效的 ReFS 超级块（SUPB）%s"
                            % ("；" + "；".join(errors[:3]) if errors else ""))
        out.sort(key=lambda d: d["offset"])
        self._sbs = out
        if self._sb is None:
            self._sb = out[0]
        return self._sbs

    @property
    def sb(self):
        if self._sb is None:
            self.superblocks()
        return self._sb

    # ---------------- 第 2 层：检查点 ----------------
    def _trailer_offsets(self, buf, off, hdr_ver):
        """检查点尾里的偏移数组（文档：Number of offsets + Array of offsets）"""
        if off <= 0 or off + 52 > len(buf):
            return []
        if hdr_ver == 3:
            n = _u32(buf, off + 48)
            arr = off + 52
        else:
            n = _u32(buf, off + 24)
            arr = off + 28
        if not (1 <= n <= 32):
            return []
        if arr + 4 * n > len(buf):
            return []
        out = [_u32(buf, arr + 4 * i) for i in range(n)]
        for o in out:
            if not (0 < o <= len(buf) - 8):
                return []
        return out

    def _find_trailer(self, buf, hdr_ver):
        """推断：检查点尾位置未知时在块内窗口扫描"""
        best = (0, [])
        best_score = 0
        limit = min(len(buf) - 52, 4096)
        for off in range(64, max(64, limit)):
            offs = self._trailer_offsets(buf, off, hdr_ver)
            if not offs:
                continue
            score = sum(1 for o in offs if self._ref_options(buf, o, hdr_ver))
            if score > best_score:
                best, best_score = (off, offs), score
            if offs and score == len(offs) and len(offs) >= 5:
                return off, offs
        return best

    def checkpoint(self, refresh=False):
        if self._ck is not None and not refresh:
            return self._ck
        blocks = self.sb.get("checkpoint_blocks") or []
        errors = []
        for bn in blocks:
            try:
                buf = self._read_block(bn)
            except RefsError as exc:
                errors.append(str(exc))
                continue
            if buf[0:4] == MAGIC_CHECKPOINT:
                hdr_len, hdr_ver = BLOCK_HEADER_V3, 3
            else:
                hdr_len, hdr_ver = BLOCK_HEADER_V1, 1
            base = hdr_len
            if len(buf) < base + 64:
                errors.append("检查点块 %d 太短" % bn)
                continue
            # 文档：Checkpoint header 16 B（0x00 4 B / 主版本 2 B / 次版本 2 B /
            # 自身引用偏移 4 B / 大小 4 B）
            chk = base + 48
            major = _u16(buf, chk + 4)
            minor = _u16(buf, chk + 6)
            self_off = _u32(buf, chk + 8)
            self_size = _u32(buf, chk + 12)
            if not (0 < major <= 15 and 0 <= minor <= 99):
                errors.append("检查点块 %d 版本字段异常 %d.%d" % (bn, major, minor))
                continue
            # 推断：文档顺序是 检查点头 → 尾 → 自身引用，所以先试紧接检查点头；
            # 尾与自身引用的先后文档没写死，另两种位置也试
            cands = []
            for cand in (chk + 16, self_off - self_size, self_off + self_size):
                if cand > 0 and cand not in cands:
                    cands.append(cand)
            ref_offsets = []
            trailer_off = 0
            for cand in cands:
                ref_offsets = self._trailer_offsets(buf, cand, hdr_ver)
                if ref_offsets:
                    trailer_off = cand
                    break
            if not ref_offsets:
                trailer_off, ref_offsets = self._find_trailer(buf, hdr_ver)
            trees = []
            for i, o in enumerate(ref_offsets):
                opts = self._ref_options(buf, o, hdr_ver)
                if opts:
                    trees.append({
                        "index": i,
                        "name": TREE_NAMES.get(i, "unknown_%d" % i),
                        "block": opts[0],
                        "blocks": opts,
                    })
            out = {
                "block_number": bn,
                "offset": bn * self.cluster_size,
                "header_version": hdr_ver,
                "major": major,
                "minor": minor,
                "volume_guid": _guid(buf[base:base + 16]),
                "self_ref_offset": self_off,
                "self_ref_size": self_size,
                "trailer_offset": trailer_off,
                "tree_ref_count": len(ref_offsets),
                "trees": trees,
            }
            self._ck = out
            return out
        raise RefsError("没有可用的检查点块（%s）"
                        % ("；".join(errors[:3]) if errors else "超级块未给出检查点块号"))

    def tree_block(self, index):
        ck = self.checkpoint()
        for t in ck.get("trees") or []:
            if t["index"] == index and t["block"]:
                return t["block"]
        return None

    # ---------------- 第 2 层：块与节点 ----------------
    def _read_block(self, block_number):
        if block_number is None or block_number < 0:
            raise RefsError("非法块号：%r" % (block_number,))
        off = block_number * self.cluster_size
        if self.size is not None and off >= self.size:
            raise RefsError("块 %d @0x%X 超出镜像（%d B）"
                            % (block_number, off, self.size))
        buf = self._read(off, self.cluster_size)
        if not buf:
            raise RefsError("块 %d @0x%X 读不到数据" % (block_number, off))
        return buf

    def _block_header(self, buf):
        if len(buf) >= 4 and buf[0:4] in (MAGIC_SUPERBLOCK, MAGIC_CHECKPOINT,
                                          MAGIC_MINISTORE):
            return BLOCK_HEADER_V3, 3
        return BLOCK_HEADER_V1, 1

    def _ref_options(self, buf, off, header_version=None):
        """一条元数据块引用 -> 可能的块号列表（v3 有四个镜像候选）"""
        if header_version is None:
            header_version = (self._sb or {}).get("header_version", 3)
        if header_version == 3:
            nums = [_u64(buf, off + 8 * i) for i in range(4)]
        else:
            nums = [_u64(buf, off)]
        return [n for n in nums if n]

    def _record_at(self, buf, off):
        """文档：Node record —— 大小 4 / key 偏移 2 / key 大小 2 /
        标志 2 / value 偏移 2 / value 大小 2，偏移相对记录起点"""
        if off < 0 or off + 16 > len(buf):
            return None
        size = _u32(buf, off)
        k_off = _u16(buf, off + 4)
        k_size = _u16(buf, off + 6)
        flags = _u16(buf, off + 8)
        v_off = _u16(buf, off + 10)
        v_size = _u16(buf, off + 12)
        if not (16 <= size <= len(buf) - off):
            return None
        if k_off + k_size > size or v_off + v_size > size:
            return None
        key = buf[off + k_off:off + k_off + k_size]
        value = buf[off + v_off:off + v_off + v_size]
        return RefsRecord(key, value, flags, off)

    def _parse_node_at(self, buf, off, header_version=3):
        """在 buf 的 off 处解析 Ministore 节点头 + 记录数组；不自洽返回 None"""
        if off < 0 or off + 32 > len(buf):
            return None
        level = buf[off + 12]
        flags = buf[off + 13]
        count = _u32(buf, off + 20)
        rec_start = _u32(buf, off + 16)
        if level > 32 or not (1 <= count <= 8192):
            return None
        if not (16 <= rec_start <= len(buf)):
            return None
        fallback = None
        for base in (off, 0):
            arr = base + rec_start
            if arr + 4 * count > len(buf):
                continue
            records = []
            ok = True
            for i in range(count):
                raw = _u32(buf, arr + 4 * i)
                # 文档：format version 3 里记录偏移的高 16 位填 0xffff
                if header_version == 3 and (raw >> 16) == 0xFFFF:
                    raw &= 0xFFFF
                rec = self._record_at(buf, base + raw)
                if rec is None:
                    ok = False
                    break
                records.append(rec)
            if not ok:
                continue
            node = {
                "offset": off,
                "level": level,
                "flags": flags,
                "count": count,
                "is_branch": bool(flags & NODE_FLAG_BRANCH),
                "is_root": bool(flags & NODE_FLAG_ROOT),
                "is_stream": bool(flags & NODE_FLAG_STREAM),
                "records": records,
            }
            if base == off:      # 文档语义：偏移相对节点头
                return node
            if fallback is None:
                fallback = node
        return fallback

    def _parse_node(self, buf, block_number=0):
        hdr_len, hdr_ver = self._block_header(buf)
        node = None
        cands = []
        rel = _u32(buf, hdr_len)
        if 4 <= rel <= len(buf) - hdr_len - 32:
            cands.append(hdr_len + rel)
        cands += [hdr_len, hdr_len + 40]
        for off in cands:
            node = self._parse_node_at(buf, off, hdr_ver)
            if node is not None:
                break
        if node is None:
            raise RefsError("块 %d 不是 Ministore 节点（定位不到节点头）" % block_number)
        node["block"] = block_number
        node["header_version"] = hdr_ver
        node["header_size"] = hdr_len
        return node

    def node(self, block_number):
        """读一个 MSB+ 块并解析成节点"""
        if block_number in self._nodes:
            return self._nodes[block_number]
        node = self._parse_node(self._read_block(block_number), block_number)
        self._nodes[block_number] = node
        return node

    def iter_tree(self, block_number, _seen=None):
        """遍历一棵 Ministore B+ 树，产出叶记录"""
        if block_number is None:
            raise RefsError("树根块号为 None")
        seen = set() if _seen is None else set(_seen)
        if block_number in seen:
            raise RefsError("B+ 树出现环：块 %d" % block_number)
        seen.add(block_number)
        node = self.node(block_number)
        if node["is_branch"]:
            for rec in node["records"]:
                for child in self._ref_options(
                        rec.value, 0, node.get("header_version")):
                    for item in self.iter_tree(child, seen):
                        yield item
        else:
            for rec in node["records"]:
                yield rec

    # ---------------- 第 2 层：对象表 ----------------
    def _object_ref_value(self, value):
        """对象记录值 -> 块号（v3 值里块引用在 32 处，v1 在 0 处）"""
        if len(value) >= 80 and _u32(value, 12) == 48:
            opts = self._ref_options(value, 32, 3)
        elif len(value) >= 24:
            opts = self._ref_options(value, 0, 1)
        else:
            opts = []
        return opts[0] if opts else None

    def objects(self):
        """对象表：object_id -> 元数据块号"""
        if self._objects is not None:
            return self._objects
        root = self.tree_block(TREE_OBJECTS)
        if root is None:
            raise RefsError("检查点里没有对象树引用")
        out = {}
        for rec in self.iter_tree(root):
            oid = rec.object_id
            if oid is None:
                continue
            blk = self._object_ref_value(rec.value)
            if blk is not None:
                out[oid] = blk
        self._objects = out
        return out

    def object_name(self, object_id):
        if object_id in OBJECT_NAMES:
            return OBJECT_NAMES[object_id]
        if object_id >= OBJECT_DIRECTORY_FIRST:
            return "directory_0x%X" % object_id
        return "object_0x%X" % object_id

    def volume_label(self):
        """卷名：卷信息对象 0x500 里的 0x510 记录，UTF-16LE"""
        if self._label is not None:
            return self._label
        objs = self.objects()
        blk = objs.get(OBJECT_VOLUME_INFO) or objs.get(OBJECT_VOLUME_INFO_COPY)
        if not blk:
            return None
        for rec in self.iter_tree(blk):
            oid = rec.object_id
            if oid == REC_VOLUME_NAME:
                self._label = _utf16(rec.value, 0) or None
                return self._label
        return None

    # ---------------- 信息 ----------------
    def _tree_addr(self, index):
        blk = self.tree_block(index)
        return None if blk is None else blk * self.cluster_size

    def info(self):
        label = None
        label_err = None
        try:
            label = self.volume_label()
        except (RefsError, NotImplementedError) as exc:
            label_err = "%s: %s" % (type(exc).__name__, exc)
        trees = {}
        tree_err = None
        object_addr = None
        container_addr = None
        schema_addr = None
        try:
            for idx in sorted(TREE_NAMES):
                blk = self.tree_block(idx)
                if blk is not None:
                    trees[TREE_NAMES[idx]] = blk
            object_addr = self._tree_addr(TREE_OBJECTS)
            container_addr = self._tree_addr(TREE_CONTAINERS)
            if container_addr is None:
                container_addr = self._tree_addr(TREE_CONTAINER_ALLOC)
            schema_addr = self._tree_addr(TREE_SCHEMA)
        except (RefsError, NotImplementedError) as exc:
            tree_err = "%s: %s" % (type(exc).__name__, exc)
        out = {
            "format": "refs",
            "fs_version": self.fs_version,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "sector_size": self.sector_size,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "number_of_sectors": self.number_of_sectors,
            "volume_serial": "0x%016X" % self.volume_serial,
            "container_size": self.container_size,
            "volume_header_fsrs": self.fsrs,
            "volume_label": label,
            "volume_guid": self.sb["volume_guid"],
            "object_table_addr": object_addr,
            "container_table_addr": container_addr,
            "schema_table_addr": schema_addr,
            "superblock_offset": self.sb["offset"],
            "superblock_block": self.sb["block_number"],
            "superblock_header_version": self.sb["header_version"],
            "superblock_count": len(self._sbs or []),
            "trees": trees,
        }
        if label_err:
            out["volume_label_error"] = label_err
        if tree_err:
            out["trees_error"] = tree_err
        return out

    # ---------------- 第 3 层：目录 / 文件 ----------------
    def _dir_block(self, object_id):
        blk = self.objects().get(object_id)
        if not blk:
            raise RefsError("目录对象 0x%X 不在对象表中" % object_id)
        return blk

    def _entry_from_value(self, name, entry_type, value):
        ent = RefsEntry(name=name, entry_type=entry_type, raw=value)
        if entry_type == ENTRY_DIR:
            # 文档：目录值 72 B
            if len(value) >= 72:
                ent.object_id = _u64(value, 0)
                ent.created = _filetime(_u64(value, 16))
                ent.modified = _filetime(_u64(value, 24))
                ent.entry_modified = _filetime(_u64(value, 32))
                ent.accessed = _filetime(_u64(value, 40))
                ent.attributes = _u32(value, 64)
        elif entry_type == ENTRY_FILE:
            # 文档：文件值是内嵌 Ministore 节点，头数据 128 B
            node = self._embedded_node(value)
            base = node["header_base"] if node else 0
            if len(value) >= base + 80:
                ent.created = _filetime(_u64(value, base + 0))
                ent.modified = _filetime(_u64(value, base + 8))
                ent.entry_modified = _filetime(_u64(value, base + 16))
                ent.accessed = _filetime(_u64(value, base + 24))
                ent.attributes = _u32(value, base + 32)
                ent.file_id = _u64(value, base + 40)
                ent.size = _u64(value, base + 64)
                ent.allocated = _u64(value, base + 72)
        return ent

    def _embedded_node(self, value):
        """推断：文件值里 128 B 头数据紧贴节点头之前；逐偏移试解析"""
        limit = min(len(value) - 32, 1024)
        if limit <= 0:
            return None
        for off in range(0, limit + 1):
            if value[off + 12] != 0:      # 只认叶子（层号 0）
                continue
            node = self._parse_node_at(value, off, 3)
            if node is not None:
                node["header_base"] = off - 128 if off >= 128 else 0
                node["value_base"] = 0
                return node
        return None

    def _parse_dir(self, object_id):
        names = {}
        entries = []
        for rec in self.iter_tree(self._dir_block(object_id)):
            key = rec.key
            if len(key) < 2:
                continue
            rtype = _u16(key, 0)
            if rtype == REC_NAME:
                if len(key) < 24:
                    continue
                nm = _utf16(rec.value, 10) if len(rec.value) > 10 else ""
                if nm:
                    names[nm] = _u64(key, 8)
            elif rtype == REC_ENTRY:
                nm = _utf16(key, 4)
                entries.append(self._entry_from_value(nm, _u16(key, 2), rec.value))
        if entries:
            for ent in entries:
                if ent.file_id is None and ent.name in names:
                    ent.file_id = names[ent.name]
        else:
            # 只有 name 记录没有 entry 记录时，退化到「名字 + 标识」
            for nm, fid in names.items():
                entries.append(RefsEntry(name=nm, entry_type=ENTRY_FILE, file_id=fid))
        entries.sort(key=lambda e: e.name.lower())
        return entries

    def listdir(self, path="/"):
        """列目录；path 可以是路径字符串或目录对象 ID"""
        if isinstance(path, int):
            return self._parse_dir(path)
        parts = _split_path(path)
        oid = OBJECT_ROOT_DIRECTORY
        if parts:
            ent = self._lookup(path)
            if ent is None or ent.entry_type != ENTRY_DIR or ent.object_id is None:
                raise RefsError("不是目录: %s" % path)
            oid = ent.object_id
        return self._parse_dir(oid)

    def _lookup(self, path):
        """解析路径最后一项，返回 RefsEntry；根返回 None"""
        parts = _split_path(path)
        if not parts:
            return None
        cur = OBJECT_ROOT_DIRECTORY
        ent = None
        for i, part in enumerate(parts):
            found = None
            for cand in self._parse_dir(cur):
                if cand.name.lower() == part.lower():
                    found = cand
                    break
            if found is None:
                raise RefsError("路径不存在: %s（缺 %r）" % (path, part))
            ent = found
            if i < len(parts) - 1:
                if found.entry_type != ENTRY_DIR or found.object_id is None:
                    raise RefsError("路径中间项不是目录: %s" % found.name)
                cur = found.object_id
        return ent

    def _walk(self, object_id, prefix, seen):
        if object_id in seen:
            return
        seen = seen | {object_id}
        for ent in self._parse_dir(object_id):
            path = prefix + "/" + ent.name
            yield path, ent
            if ent.entry_type == ENTRY_DIR and ent.object_id is not None:
                for item in self._walk(ent.object_id, path, seen):
                    yield item

    def walk(self, top="/"):
        """递归遍历，产出 (路径, RefsEntry)"""
        if isinstance(top, int):
            oid = top
            prefix = "/0x%X" % top
        else:
            parts = _split_path(top)
            if parts:
                ent = self._lookup(top)
                if ent is None or ent.entry_type != ENTRY_DIR or ent.object_id is None:
                    raise RefsError("不是目录: %s" % top)
                oid = ent.object_id
                prefix = "/" + "/".join(parts)
            else:
                oid = OBJECT_ROOT_DIRECTORY
                prefix = ""
        for item in self._walk(oid, prefix, frozenset()):
            yield item

    def find(self, pattern):
        """按 glob 匹配路径或文件名"""
        pat = pattern.lower()
        out = []
        for path, ent in self.walk("/"):
            if fnmatch(path.lower(), pat) or fnmatch(ent.name.lower(), pat):
                out.append((path, ent))
        return out

    def read_file(self, path):
        """读文件内容；只有常驻 $DATA 能读，非驻留抛 NotImplementedError"""
        ent = self._lookup(path)
        if ent is None:
            raise RefsError("路径不存在: %s" % path)
        if ent.entry_type != ENTRY_FILE:
            raise RefsError("不是文件: %s" % path)
        value = ent.raw or b""
        node = self._embedded_node(value)
        if node is None:
            raise NotImplementedError(
                "文件 %s 的记录值里找不到内嵌 Ministore 节点（值 %d B），"
                "无法定位 $DATA 属性" % (path, len(value)))
        attr = None
        for rec in node["records"]:
            if len(rec.key) >= 12 and _u32(rec.key, 8) == ATTR_DATA:
                attr = rec
                break
        if attr is None:
            raise RefsError("文件 %s 没有 $DATA 属性" % path)
        raw = attr.value
        if len(raw) < 12:
            raise RefsError("文件 %s 的 $DATA 属性值太短（%d B）" % (path, len(raw)))
        resident = _u32(raw, 0)
        d_off = _u32(raw, 4)
        d_size = _u32(raw, 8)
        if resident == 0 and 12 <= d_off <= len(raw) and d_off + d_size <= len(raw):
            return raw[d_off:d_off + d_size]
        raise NotImplementedError(
            "文件 %s 的 $DATA 非驻留（resident=0x%X）：簇映射未实现，"
            "libfsrefs 未给出 file extent 布局" % (path, resident))

    def stat(self, path):
        return self._lookup(path)


def probe(sub):
    """是否是 ReFS 卷（只看卷头签名，不抛异常）"""
    try:
        head = sub.read(VOLUME_HEADER_OFFSET, VOLUME_HEADER_SIZE) or b""
    except Exception:
        return False
    if len(head) < 24:
        return False
    return head[3:7] == REFS_SIGNATURE


def open_fs(sub):
    return Refs(sub)


if __name__ == "__main__":
    class Buf(object):
        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    CLUSTER = 0x10000
    SECTOR = 512
    TOTAL_BLOCKS = 16
    TOTAL = CLUSTER * TOTAL_BLOCKS

    VOL_ID = bytes(range(0x10, 0x20))
    FT_CREATE = 132000000000000000
    FT_MOD = 132000000000000000 + 10000000 * 30
    FT_ACC = FT_MOD + 10000000 * 5

    TEXT = "ReFS 自检 a.txt\n".encode("utf-8")
    SUB = b"subdir b.bin\n"

    def ref48(block):
        out = bytearray(48)
        struct.pack_into("<Q", out, 0, block)
        return bytes(out)

    def ref24(block):
        """v1 元数据块引用 24 B（块号 8 + 校验描述符 16）"""
        out = bytearray(24)
        struct.pack_into("<Q", out, 0, block)
        return bytes(out)

    def build_node(records, level=0, flags=NODE_FLAG_ROOT, header_data=b"",
                   sig=MAGIC_MINISTORE, v1=False):
        """一块 Ministore 树节点
        v3：块头 80 B + 节点头偏移 4 B + 树头 36 B + 头数据 + 节点头
        v1：块头 48 B（0 处是块号，无签名）+ 同上
        """
        body = bytearray()
        offs = []
        for key, val in records:
            rec_len = 16 + len(key) + len(val)
            rec_len += (-rec_len) % 8
            rec = bytearray(rec_len)
            struct.pack_into("<IHHHHH", rec, 0, rec_len, 16, len(key), 0,
                             16 + len(key), len(val))
            rec[16:16 + len(key)] = key
            rec[16 + len(key):16 + len(key) + len(val)] = val
            offs.append(len(body))
            body += rec
        out = bytearray(CLUSTER)
        hdr_len = BLOCK_HEADER_V1 if v1 else BLOCK_HEADER_V3
        if v1:
            struct.pack_into("<Q", out, 0, 3)     # 块号（调用方按需覆盖）
        else:
            out[0:4] = sig
            struct.pack_into("<I", out, 4, 2)
            struct.pack_into("<I", out, 12, 0x5A5A)
        nhdr_field = hdr_len
        nhdr_off = 40 + len(header_data)
        struct.pack_into("<I", out, nhdr_field, nhdr_off)
        struct.pack_into("<H", out, nhdr_field + 4, 40)
        struct.pack_into("<I", out, nhdr_field + 4 + 20, len(offs))
        if header_data:
            out[nhdr_field + 40:nhdr_field + 40 + len(header_data)] = header_data
        node_off = nhdr_field + nhdr_off
        data_start = 32
        data_end = 32 + len(body)
        idx_start = data_end + (-data_end) % 8
        struct.pack_into("<II", out, node_off, data_start, data_end)
        out[node_off + 12] = level
        out[node_off + 13] = flags
        struct.pack_into("<I", out, node_off + 16, idx_start)
        struct.pack_into("<I", out, node_off + 20, len(offs))
        struct.pack_into("<I", out, node_off + 24, 16 + 4 * len(offs))
        out[node_off + data_start:node_off + data_end] = body
        for i, rel_off in enumerate(offs):
            struct.pack_into("<I", out, node_off + idx_start + 4 * i,
                             data_start + rel_off)
        return bytes(out)

    def build_embedded(records):
        """无块头的内嵌 Ministore 节点头（偏移相对节点头）"""
        body = bytearray()
        offs = []
        for key, val in records:
            rec_len = 16 + len(key) + len(val)
            rec_len += (-rec_len) % 8
            rec = bytearray(rec_len)
            struct.pack_into("<IHHHHH", rec, 0, rec_len, 16, len(key), 0,
                             16 + len(key), len(val))
            rec[16:16 + len(key)] = key
            rec[16 + len(key):16 + len(key) + len(val)] = val
            offs.append(len(body))
            body += rec
        node = bytearray(32 + len(body) + 4 * len(offs))
        data_start = 32
        data_end = 32 + len(body)
        struct.pack_into("<II", node, 0, data_start, data_end)
        node[12] = 0
        node[13] = NODE_FLAG_ROOT
        struct.pack_into("<I", node, 16, data_end)
        struct.pack_into("<I", node, 20, len(offs))
        struct.pack_into("<I", node, 24, 16 + 4 * len(offs))
        node[data_start:data_end] = body
        for i, rel_off in enumerate(offs):
            struct.pack_into("<I", node, data_end + 4 * i, data_start + rel_off)
        return bytes(node)

    def obj_key(object_id):
        return struct.pack("<QQ", 0, object_id)

    def obj_value(block):
        out = bytearray(80)
        struct.pack_into("<I", out, 12, 48)
        struct.pack_into("<I", out, 16, 80)
        out[32:80] = ref48(block)
        return bytes(out)

    def obj_value_v1(block):
        """v1 对象记录值 48 B：块引用 24 B 在 0 处"""
        out = bytearray(48)
        out[0:24] = ref24(block)
        return bytes(out)

    def dir_name_rec(name, fid):
        key = bytearray(24)
        struct.pack_into("<H", key, 0, REC_NAME)
        struct.pack_into("<H", key, 2, 0x8000)
        struct.pack_into("<Q", key, 8, fid)
        val = bytearray(12)
        struct.pack_into("<H", val, 8, 0x0C)
        val += name.encode("utf-16-le")
        return bytes(key), bytes(val)

    def dir_entry_rec(name, entry_type, value):
        key = bytearray(4)
        struct.pack_into("<H", key, 0, REC_ENTRY)
        struct.pack_into("<H", key, 2, entry_type)
        key += name.encode("utf-16-le")
        return bytes(key), value

    def dir_value(oid):
        val = bytearray(72)
        struct.pack_into("<Q", val, 0, oid)
        struct.pack_into("<Q", val, 16, FT_CREATE)
        struct.pack_into("<Q", val, 24, FT_MOD)
        struct.pack_into("<Q", val, 32, FT_MOD)
        struct.pack_into("<Q", val, 40, FT_ACC)
        struct.pack_into("<I", val, 64, FILE_ATTRIBUTE_DIRECTORY)
        return bytes(val)

    def file_value(name, data, resident=True, fid=0):
        hdr = bytearray(128)
        struct.pack_into("<Q", hdr, 0, FT_CREATE)
        struct.pack_into("<Q", hdr, 8, FT_MOD)
        struct.pack_into("<Q", hdr, 16, FT_MOD)
        struct.pack_into("<Q", hdr, 24, FT_ACC)
        struct.pack_into("<I", hdr, 32, FILE_ATTRIBUTE_ARCHIVE)
        struct.pack_into("<Q", hdr, 40, fid)
        struct.pack_into("<Q", hdr, 64, len(data))
        struct.pack_into("<Q", hdr, 72, (len(data) + 4095) // 4096 * 4096)
        attr_key = struct.pack("<QI", 0x160, ATTR_DATA) + b"\x00\x00"
        attr = bytearray(44)
        if resident:
            struct.pack_into("<III", attr, 0, 0x00, 44, len(data))
            attr += data
        else:
            struct.pack_into("<III", attr, 0, 0x01, 0, 0)
            attr += struct.pack("<QQ", 9, 1)
        return bytes(hdr) + build_embedded([(attr_key, bytes(attr))])

    def put(block, data):
        img[block * CLUSTER:block * CLUSTER + len(data)] = data

    img = bytearray(TOTAL)

    # ---- 卷头 @0（文档：Volume header 512 B）----
    img[0:3] = b"\xEB\x52\x90"
    img[3:11] = b"ReFS\x00\x00\x00\x00"
    img[16:20] = REFS_FSRS
    struct.pack_into("<H", img, 20, 0x200)
    struct.pack_into("<Q", img, 24, TOTAL // SECTOR)
    struct.pack_into("<I", img, 32, SECTOR)
    struct.pack_into("<I", img, 36, CLUSTER // SECTOR)
    img[40] = 3
    img[41] = 4
    struct.pack_into("<Q", img, 56, 0x1122334455667788)
    struct.pack_into("<Q", img, 64, 0x800000)
    # 卷头副本（卷尾）
    img[TOTAL - VOLUME_HEADER_SIZE:TOTAL - VOLUME_HEADER_SIZE + 72] = img[0:72]

    # ---- 超级块 SUPB @0x10000（块 1）----
    sb_off = SUPERBLOCK_OFFSET
    img[sb_off:sb_off + 4] = MAGIC_SUPERBLOCK
    struct.pack_into("<I", img, sb_off + 4, 2)
    struct.pack_into("<I", img, sb_off + 12, 0xA1B2C3D4)
    struct.pack_into("<Q", img, sb_off + 32, 1)          # 首块号
    base = sb_off + BLOCK_HEADER_V3
    img[base:base + 16] = VOL_ID                        # 卷标识
    struct.pack_into("<Q", img, base + 24, 42)          # 序列号
    struct.pack_into("<I", img, base + 32, 128)         # 检查点引用数据偏移
    struct.pack_into("<I", img, base + 36, 2)           # 检查点条目数
    struct.pack_into("<I", img, base + 40, 144)         # 自身引用偏移
    struct.pack_into("<I", img, base + 44, 48)          # 自身引用大小
    struct.pack_into("<Q", img, sb_off + 128, 2)        # 检查点块号 2
    struct.pack_into("<Q", img, sb_off + 136, 0)

    # ---- 检查点 CHKP（块 2）----
    TRAILER_OFF = 144
    N_TREES = 13
    SELF_OFF = TRAILER_OFF + (52 + 4 * N_TREES)
    TREE_REFS_OFF = SELF_OFF + 48
    chk_img = bytearray(CLUSTER)
    chk_img[0:4] = MAGIC_CHECKPOINT
    struct.pack_into("<I", chk_img, 4, 2)
    struct.pack_into("<Q", chk_img, 32, 2)
    cbase = BLOCK_HEADER_V3
    chk_img[cbase:cbase + 16] = VOL_ID
    struct.pack_into("<I", chk_img, cbase + 32, TRAILER_OFF)
    struct.pack_into("<I", chk_img, cbase + 36, 2)
    struct.pack_into("<I", chk_img, cbase + 40, SELF_OFF)
    struct.pack_into("<I", chk_img, cbase + 44, 48)
    chk = cbase + 48
    struct.pack_into("<H", chk_img, chk + 4, 3)          # 主版本
    struct.pack_into("<H", chk_img, chk + 6, 4)          # 次版本
    struct.pack_into("<I", chk_img, chk + 8, SELF_OFF)
    struct.pack_into("<I", chk_img, chk + 12, 48)
    struct.pack_into("<Q", chk_img, TRAILER_OFF, 7)
    struct.pack_into("<Q", chk_img, TRAILER_OFF + 8, 11)
    struct.pack_into("<Q", chk_img, TRAILER_OFF + 40, 0x100)
    struct.pack_into("<I", chk_img, TRAILER_OFF + 44, 32)
    struct.pack_into("<I", chk_img, TRAILER_OFF + 48, N_TREES)
    for i in range(N_TREES):
        struct.pack_into("<I", chk_img, TRAILER_OFF + 52 + 4 * i,
                         TREE_REFS_OFF + 48 * i)
    chk_img[SELF_OFF:SELF_OFF + 8] = struct.pack("<Q", 2)
    chk_img[TREE_REFS_OFF:TREE_REFS_OFF + 48] = ref48(3)   # 索引 0 = 对象树
    put(2, bytes(chk_img))

    # ---- 对象表：两层 B+ 树（根在块 3，叶子在块 7 / 8）----
    leaf_a = build_node([
        (obj_key(OBJECT_VOLUME_INFO), obj_value(5)),
        (obj_key(OBJECT_FS_INFO), obj_value(9)),
    ])
    leaf_b = build_node([
        (obj_key(OBJECT_ROOT_DIRECTORY), obj_value(4)),
        (obj_key(OBJECT_DIRECTORY_FIRST), obj_value(6)),
    ])
    branch = build_node([
        (obj_key(OBJECT_FS_INFO), ref48(7)),
        (obj_key(OBJECT_DIRECTORY_FIRST), ref48(8)),
    ], level=1, flags=NODE_FLAG_BRANCH | NODE_FLAG_ROOT)
    put(3, branch)
    put(7, leaf_a)
    put(8, leaf_b)

    # ---- 卷信息树（块 5）：卷名记录 0x510 ----
    LABEL = "取证卷 Test"
    put(5, build_node([(struct.pack("<Q", REC_VOLUME_NAME),
                        LABEL.encode("utf-16-le"))]))

    # ---- 根目录树（块 4）----
    root_recs = [
        (struct.pack("<H", REC_BASE) + b"\x00\x00", b""),
        dir_name_rec("a.txt", 0x5000000000001001),
        dir_name_rec("c.bin", 0x5000000000001002),
        dir_name_rec("子目录", 0x5000000000001003),
        dir_entry_rec("a.txt", ENTRY_FILE,
                      file_value("a.txt", TEXT, True, 0x5000000000001001)),
        dir_entry_rec("c.bin", ENTRY_FILE,
                      file_value("c.bin", b"", False, 0x5000000000001002)),
        dir_entry_rec("子目录", ENTRY_DIR, dir_value(OBJECT_DIRECTORY_FIRST)),
    ]
    put(4, build_node(root_recs))

    # ---- 子目录树（块 6）----
    sub_recs = [
        (struct.pack("<H", REC_BASE) + b"\x00\x00", b""),
        dir_name_rec("b.bin", 0x5000000000002001),
        dir_entry_rec("b.bin", ENTRY_FILE,
                      file_value("b.bin", SUB, True, 0x5000000000002001)),
    ]
    put(6, build_node(sub_recs))
    img = bytes(img)

    # ================= 断言 =================
    print("== 1. probe ==")
    assert probe(Buf(img)) is True
    assert probe(Buf(b"\x00" * 4096)) is False
    assert probe(Buf(img[:100])) is True     # 签名只看前 24 B，截断交给 Refs()
    assert probe(Buf(img[:20])) is False
    print("   ReFS 命中 / 非 ReFS 不命中 / 不足 24 B 不命中（截断由 Refs 判）")

    print("== 2. 卷头与超级块 ==")
    fs = open_fs(Buf(img))
    inf = fs.info()
    print("   fs_version=%s sector=%d cluster=%d guid=%s"
          % (inf["fs_version"], inf["sector_size"], inf["cluster_size"],
             inf["volume_guid"]))
    print("   卷名=%r  对象表@0x%X  超级块@0x%X  SUPB 数=%d"
          % (inf["volume_label"], inf["object_table_addr"],
             inf["superblock_offset"], inf["superblock_count"]))
    assert inf["fs_version"] == "3.4"
    assert inf["sector_size"] == SECTOR
    assert inf["cluster_size"] == CLUSTER
    assert inf["volume_guid"] == "13121110-1514-1716-1819-1a1b1c1d1e1f"
    assert inf["volume_label"] == LABEL
    assert inf["object_table_addr"] == 3 * CLUSTER
    assert inf["schema_table_addr"] is None
    assert inf["superblock_offset"] == SUPERBLOCK_OFFSET
    assert inf["superblock_header_version"] == 3
    assert inf["superblock_count"] == 1
    sbs = fs.superblocks()
    assert len(sbs) == 1 and sbs[0]["offset"] == SUPERBLOCK_OFFSET
    assert sbs[0]["checkpoint_blocks"] == [2]
    assert fs.volume_header_backup() is not None
    assert fs.volume_header_backup()["offset"] == TOTAL - VOLUME_HEADER_SIZE

    print("== 3. 截断输入 ==")
    for cut, why in ((0, "空"), (100, "卷头不完整"), (SUPERBLOCK_OFFSET + 40, "SUPB 半截")):
        try:
            Refs(Buf(img[:cut]))
        except RefsError as exc:
            print("   %-10s -> RefsError: %s" % (why, exc))
        else:
            raise AssertionError("截断 %d B 未抛异常" % cut)

    print("== 4. 备份超级块回退 ==")
    bad = bytearray(img)
    bad[SUPERBLOCK_OFFSET:SUPERBLOCK_OFFSET + 4] = b"XXXX"      # 主块签名损坏
    bad[12 * CLUSTER:13 * CLUSTER] = img[1 * CLUSTER:2 * CLUSTER]  # 块 12 放副本
    fs2 = Refs(Buf(bytes(bad)))
    inf2 = fs2.info()
    print("   主块坏 -> 采用 @0x%X，卷名=%r，对象表@0x%X"
          % (inf2["superblock_offset"], inf2["volume_label"],
             inf2["object_table_addr"]))
    assert inf2["superblock_offset"] == 12 * CLUSTER
    assert inf2["volume_label"] == LABEL
    assert inf2["superblock_count"] == 1
    assert len(fs2.listdir("/")) == 3

    print("== 5. B+ 树遍历（两层）与目录/文件 ==")
    ck = fs.checkpoint()
    print("   检查点：块 %d 版本 %d.%d，树引用 %d 个：%s"
          % (ck["block_number"], ck["major"], ck["minor"],
             len(ck["trees"]), [(t["index"], t["name"], t["block"])
                                for t in ck["trees"]]))
    assert ck["trees"][0]["index"] == TREE_OBJECTS and ck["trees"][0]["block"] == 3
    root_node = fs.node(3)
    leaf_node = fs.node(7)
    print("   根节点 level=%d branch=%s 记录=%d；叶节点 level=%d 记录=%d"
          % (root_node["level"], root_node["is_branch"], root_node["count"],
             leaf_node["level"], leaf_node["count"]))
    assert root_node["level"] == 1 and root_node["is_branch"]
    assert leaf_node["level"] == 0
    objs = fs.objects()
    print("   对象表 %d 项：%s"
          % (len(objs), {("0x%X" % k): v for k, v in sorted(objs.items())}))
    assert len(objs) == 4
    assert objs[OBJECT_VOLUME_INFO] == 5
    assert objs[OBJECT_ROOT_DIRECTORY] == 4
    assert objs[OBJECT_DIRECTORY_FIRST] == 6

    ents = fs.listdir("/")
    print("   根目录 %d 项：%s"
          % (len(ents), [(e.name, e.type_name, e.size) for e in ents]))
    assert [e.name for e in ents] == ["a.txt", "c.bin", "子目录"]
    a = ents[0]
    assert a.is_file and a.size == len(TEXT) and a.modified is not None
    assert a.allocated == (len(TEXT) + 4095) // 4096 * 4096
    assert ents[2].is_dir and ents[2].object_id == OBJECT_DIRECTORY_FIRST
    assert fs.read_file("/a.txt") == TEXT
    assert fs.read_file("/子目录/b.bin") == SUB

    paths = [p for p, e in fs.walk("/")]
    print("   walk：%s" % paths)
    assert paths == ["/a.txt", "/c.bin", "/子目录", "/子目录/b.bin"]
    found = fs.find("*.txt")
    print("   find('*.txt')：%s" % [p for p, e in found])
    assert [p for p, e in found] == ["/a.txt"]
    assert fs.find("b.bin")[0][0] == "/子目录/b.bin"

    try:
        fs.read_file("/c.bin")
    except NotImplementedError as exc:
        print("   非驻留 $DATA -> NotImplementedError: %s" % exc)
    else:
        raise AssertionError("非驻留 $DATA 应抛 NotImplementedError")

    try:
        fs.listdir("/nope")
    except RefsError as exc:
        print("   不存在路径 -> RefsError: %s" % exc)
    else:
        raise AssertionError("不存在路径应抛 RefsError")

    print("== 6. format version 1 元数据块头（无签名） ==")
    V1_TOTAL = CLUSTER * 8
    img1 = bytearray(V1_TOTAL)
    img1[0:3] = b"\xEB\x52\x90"
    img1[3:11] = b"ReFS\x00\x00\x00\x00"
    img1[16:20] = REFS_FSRS
    struct.pack_into("<H", img1, 20, 0x200)
    struct.pack_into("<Q", img1, 24, V1_TOTAL // SECTOR)
    struct.pack_into("<I", img1, 32, SECTOR)
    struct.pack_into("<I", img1, 36, CLUSTER // SECTOR)
    img1[40] = 3
    img1[41] = 4
    struct.pack_into("<Q", img1, 56, 0x1122334455667788)
    img1[V1_TOTAL - VOLUME_HEADER_SIZE:V1_TOTAL - VOLUME_HEADER_SIZE + 72] = img1[0:72]

    # SUPB v1：块头 48 B（0 处是块号，无签名）
    s1 = SUPERBLOCK_OFFSET
    struct.pack_into("<Q", img1, s1, 1)
    b1 = s1 + BLOCK_HEADER_V1
    img1[b1:b1 + 16] = VOL_ID
    struct.pack_into("<Q", img1, b1 + 24, 7)
    struct.pack_into("<I", img1, b1 + 32, 96)          # 检查点引用数据偏移
    struct.pack_into("<I", img1, b1 + 36, 2)
    struct.pack_into("<I", img1, b1 + 40, 120)         # 自身引用偏移
    struct.pack_into("<I", img1, b1 + 44, 24)
    struct.pack_into("<Q", img1, s1 + 96, 2)           # 检查点块号

    # CHKP v1：块头 48 + 超级块 48 + 检查点头 16 + 尾 + 自身引用 24 + 树引用 24×n
    c1 = 2 * CLUSTER
    struct.pack_into("<Q", img1, c1, 2)
    b2 = c1 + BLOCK_HEADER_V1
    img1[b2:b2 + 16] = VOL_ID
    chk1 = b2 + 48
    trailer1 = chk1 + 16
    SELF1 = trailer1 + 28 + 4 * N_TREES
    TREE1 = SELF1 + 24
    struct.pack_into("<H", img1, chk1 + 4, 1)
    struct.pack_into("<H", img1, chk1 + 6, 2)
    struct.pack_into("<I", img1, chk1 + 8, SELF1 - c1)
    struct.pack_into("<I", img1, chk1 + 12, 24)
    struct.pack_into("<Q", img1, trailer1, 9)
    struct.pack_into("<I", img1, trailer1 + 24, N_TREES)
    for i in range(N_TREES):
        struct.pack_into("<I", img1, trailer1 + 28 + 4 * i, (TREE1 - c1) + 24 * i)
    struct.pack_into("<Q", img1, SELF1, 2)
    img1[TREE1:TREE1 + 24] = ref24(3)

    # 对象树（v1 单叶）、卷信息树、根目录树
    obj1 = build_node([
        (obj_key(OBJECT_VOLUME_INFO), obj_value_v1(5)),
        (obj_key(OBJECT_ROOT_DIRECTORY), obj_value_v1(4)),
    ], v1=True)
    vol1 = build_node([(struct.pack("<Q", REC_VOLUME_NAME),
                        LABEL.encode("utf-16-le"))], v1=True)
    root1 = build_node([
        (struct.pack("<H", REC_BASE) + b"\x00\x00", b""),
        dir_name_rec("a.txt", 0x5000000000001001),
        dir_entry_rec("a.txt", ENTRY_FILE,
                      file_value("a.txt", TEXT, True, 0x5000000000001001)),
    ], v1=True)
    img1[3 * CLUSTER:4 * CLUSTER] = obj1
    img1[4 * CLUSTER:5 * CLUSTER] = root1
    img1[5 * CLUSTER:6 * CLUSTER] = vol1
    img1 = bytes(img1)

    fs1 = open_fs(Buf(img1))
    i1 = fs1.info()
    print("   块头版本=%d 检查点=%d.%d 树引用=%s 卷名=%r 对象表@0x%X"
          % (i1["superblock_header_version"], fs1.checkpoint()["major"],
             fs1.checkpoint()["minor"],
             [(t["index"], t["block"]) for t in fs1.checkpoint()["trees"]],
             i1["volume_label"], i1["object_table_addr"]))
    assert i1["superblock_header_version"] == 1
    assert i1["superblock_offset"] == SUPERBLOCK_OFFSET
    assert i1["object_table_addr"] == 3 * CLUSTER
    assert i1["volume_label"] == LABEL
    assert fs1.checkpoint()["header_version"] == 1
    assert fs1.listdir("/")[0].name == "a.txt"
    assert fs1.read_file("/a.txt") == TEXT
    print("   v1 头 + 24 B 块引用 + v1 尾部偏移数组：解析一致")

    print("自检通过")
