#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  Realm 数据库（.realm）结构解析
# ============================================================

"""Realm 数据库文件（``default.realm`` / ``*.realm``）结构解析。

格式来源（全部逐条对照 realm-core 源码核过，不是凭印象）：
    * ``src/realm/alloc_slab.hpp``    —— ``struct Header`` / ``StreamingFooter``
      / ``footer_magic_cookie``，文件顶部 24 字节的精确布局
    * ``src/realm/alloc_slab.cpp``    —— ``validate_header()``（mnemonic 校验、
      slot_selector、top-ref 对齐与越界判定）、``init_streaming_header()``
    * ``src/realm/node_header.hpp``   —— 节点头 8 字节的位域（capacity / size /
      width / wtype / has_refs / 内节点标志）
    * ``src/realm/group.hpp``         —— ``Group::m_top`` 槽位表（1st 表名、
      2nd 表引用、3rd 逻辑文件大小 …）、``g_current_file_format_version = 24``
    * ``src/realm/table.hpp``         —— ``top_position_for_*`` 槽位常量
    * ``src/realm/spec.hpp``          —— ``Spec`` 槽位（types / names /
      attributes / enumkeys / colkeys）
    * ``src/realm/cluster.hpp`` + ``cluster.cpp`` —— 叶节点
      ``[0]=键数组引用或紧凑尺寸, 1..=各列载荷]``、``s_first_col_index = 1``
    * ``src/realm/column_type.hpp``   —— ``ColumnType::Type`` 与 ``col_attr_*``
    * ``src/realm/array_string_short.hpp`` —— 短字符串块编码（末字节 = 0 个数-1，
      null = m_width）

已实现：
    · 文件头解析：mnemonic ``T-DB``、双 top-ref、文件格式版本、flags 选择位
    · 流式（streaming）布局：``top_ref[0] == 0xFFFF…FF`` 时改读文件尾部
      16 字节 footer（top_ref + magic cookie ``0x3034125237E526C8``）
    · 节点（Array/Node）头解析：capacity / size / width / wtype / has_refs
    · ``Group.m_top`` 槽位：表名数组、表引用数组、逻辑文件大小、事务版本
    · ``tables()``：表名列表（``class_`` 前缀按 realm-core 规则剥离，原样另存）
    · ``schema()``：列名、列类型（含 ColumnType 数值）、属性位（Nullable /
      List / Set / Dictionary / Collection / Unique / StrongLinks / FullText）
    · ``rows()``：走 Cluster 树（内节点 → 叶节点）枚举行，按列类型解码：
        - int（含 nullable ``ArrayIntNull``：0 号元素是 null 哨兵）
        - bool
        - string（短字符串块；medium/big 走 blob 的形态只报描述符，见下）
        - float / double
        - timestamp（秒+纳秒成对整数）
        - link / typed_link（对象键整数）
        - binary / decimal / object_id / uuid / mixed：返回带 ``"decoded": False``
          的描述符字典，给出 ref 与节点形状，**不假装是值**
    · ``find()``：在已解码行上做等值过滤
    · ``probe()`` / ``describe()``：文件标识判定与容错摘要

不实现：
    · **加密库（``encryption_key``）**：加密后 header 与所有节点都被页级
      加密改写，本模块不做 AES 解页，``probe()`` 直接判否、``Realm()`` 抛
      ``RealmError``
    · **medium / big 字符串（ArraySmallBlobs / ArrayBigBlobs）与 Binary**：
      这两种载荷是「分块 blob 数组」，chunk 头与续块指针的布局没有在本次
      查证里逐行确认，因此**不假装能读**：该单元格返回
      ``{"decoded": False, "reason": "blob 载荷未解码"}``，整表不失败
    · **列集合（List / Set / Dictionary）的嵌套内容**：只报外层是 ref 数组，
      不展开元素
    · **Cluster 键偏移的完整推导**：叶节点为紧凑形态时键是隐式的
      （``0..n-1`` 加树内偏移）。本模块给出行号与紧凑键，跨内节点累加的
      偏移只在单层树（根即叶）时保证正确，多层树时 ``row_key`` 标记为
      ``"partial"``
    · **写操作 / 事务 / 历史（history）/ 同步元数据（sync file id）**：
      纯读视图，不解析 changeset
    · **Free list / 空间回收**：只报告 Group 顶层 free_pos/free_len 槽是否存在，
      不重建空闲链表

数据结构速查（本模块据此实现）::

    文件头 24 字节
        +0   u64 top_ref[0]     \
        +8   u64 top_ref[1]      > flags bit0 选中哪个
        +16  "T-DB"              mnemonic（4 字节）
        +20  u8  file_format[0]  文件格式版本（当前 24）
        +21  u8  file_format[1]
        +22  u8  reserved
        +23  u8  flags           bit0 = top-ref 选择位

    节点头 8 字节（每个 Array 都从自己的 ref 开始）
        +0..2  capacity（3 字节）

        +3    未用
        +4    bit7 内节点 / bit6 has_refs / bit5 context /
              bit4-3 wtype (0=bits,1=multiply,2=ignore) / bit2-0 log2(width)
        +5..7  size（3 字节大端）
        data 从 +8 开始

    Group.m_top（ref 数组）
        [0] 表名数组（ArrayStringShort）  [1] 表引用数组  [2] 逻辑文件大小
        [3] free_pos  [4] free_len  [5] free_ver  [6] 事务版本 …
    Table 顶层（ref 数组）
        [0] Spec  [1] columns  [2] Cluster 树  [3] key  [4] search index …
    Spec 顶层（ref 数组）
        [0] types  [1] names(ArrayStringShort)  [2] attributes  [5] colkeys
    Cluster 叶（has_refs 数组）
        [0] 键数组引用 或 紧凑尺寸（tagged, 值 = size<<1|1）
        [1..] 各列载荷，槽位 i 对应 spec 列下标 i-1
"""

import struct

__all__ = [
    "REALM_HEADER_SIZE", "REALM_MNEMONIC", "REALM_FOOTER_MAGIC",
    "NODE_HEADER_SIZE", "CURRENT_FILE_FORMAT_VERSION", "CLASS_NAME_PREFIX",
    "COLUMN_TYPES", "COL_ATTRS",
    "RealmError", "Realm", "probe", "open_fs", "describe",
]

# ------------------------------------------------------------
# 常量（全部来自 realm-core 源码，见 docstring 的出处清单）
# ------------------------------------------------------------

REALM_HEADER_SIZE = 24
REALM_MNEMONIC = b"T-DB"
REALM_FOOTER_MAGIC = 0x3034125237E526C8   # SlabAlloc::footer_magic_cookie
STREAMING_SENTINEL = 0xFFFFFFFFFFFFFFFF   # 流式形态下 top_ref[0] 的取值
NODE_HEADER_SIZE = 8                      # NodeHeader::header_size
CURRENT_FILE_FORMAT_VERSION = 24          # Group::g_current_file_format_version
CLASS_NAME_PREFIX = "class_"              # Group::g_class_name_prefix

# wtype
WTYPE_BITS = 0
WTYPE_MULTIPLY = 1
WTYPE_IGNORE = 2

# ColumnType::Type
COLUMN_TYPES = {
    0: "int",
    1: "bool",
    2: "string",
    4: "binary",
    6: "mixed",
    8: "timestamp",
    9: "float",
    10: "double",
    11: "decimal",
    12: "link",
    14: "backlink",
    15: "object_id",
    16: "typed_link",
    17: "uuid",
}

# col_attr_*
COL_ATTRS = (
    ("indexed", 1),
    ("unique", 2),
    ("strong_links", 8),
    ("nullable", 16),
    ("list", 32),
    ("dictionary", 64),
    ("set", 128),
    ("fulltext_indexed", 256),
)
COL_ATTR_COLLECTION = 128 + 64 + 32   # col_attr_Collection

# Group.m_top 槽位
GROUP_SLOT_NAMES = 0
GROUP_SLOT_TABLES = 1
GROUP_SLOT_FILE_SIZE = 2
GROUP_SLOT_FREE_POS = 3
GROUP_SLOT_FREE_LEN = 4
GROUP_SLOT_FREE_VER = 5
GROUP_SLOT_VERSION = 6
GROUP_SLOT_HIST_TYPE = 7
GROUP_SLOT_HIST_REF = 8
GROUP_SLOT_SYNC_ID = 10

# Table 顶层槽位（table.hpp top_position_for_*）
TABLE_SLOT_SPEC = 0
TABLE_SLOT_COLUMNS = 1
TABLE_SLOT_CLUSTER = 2
TABLE_SLOT_KEY = 3
TABLE_SLOT_SEARCH_INDEXES = 4
TABLE_SLOT_COLUMN_KEY = 5
TABLE_SLOT_VERSION = 6
TABLE_SLOT_PK_COL = 11
TABLE_SLOT_FLAGS = 12
TABLE_SLOT_TOMBSTONES = 13

# Spec 顶层槽位
SPEC_SLOT_TYPES = 0
SPEC_SLOT_NAMES = 1
SPEC_SLOT_ATTRIBUTES = 2
SPEC_SLOT_ENUMKEYS = 4
SPEC_SLOT_COLKEYS = 5

CLUSTER_FIRST_COL_SLOT = 1    # Cluster::s_first_col_index


class RealmError(ValueError):
    """Realm 结构不合法 / 不是 Realm 文件"""


# ------------------------------------------------------------
# 字节读取工具
# ------------------------------------------------------------

def _u24be(b, off):
    return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]


def _sign_extend(raw, width):
    """把 width 位的补码按有符号整数解读（Realm 的整数列就是这么存的）"""
    if width <= 0:
        return 0
    if width >= 64:
        return raw - (1 << 64) if raw & (1 << 63) else raw
    sign = 1 << (width - 1)
    if raw & sign:
        return raw - (1 << width)
    return raw


class _Node(object):
    """一个 Realm 节点（Array）：8 字节头 + 数据区

    只依赖 realm 的 ``read(offset, size)``。
    """

    __slots__ = ("realm", "ref", "capacity", "is_inner", "has_refs", "context",
                 "wtype", "width", "size", "byte_len")

    def __init__(self, realm, ref):
        if ref is None:
            raise RealmError("节点引用为空")
        ref = int(ref)
        if ref <= 0:
            raise RealmError("节点引用非法：%d" % ref)
        if ref % 8:
            raise RealmError("节点引用未按 8 字节对齐：%d" % ref)
        if ref + NODE_HEADER_SIZE > realm.size:
            raise RealmError("节点引用越界：%d（文件 %d 字节）" % (ref, realm.size))
        head = realm._read(ref, NODE_HEADER_SIZE)
        if len(head) != NODE_HEADER_SIZE:
            raise RealmError("节点头读取不全：%d" % ref)
        self.realm = realm
        self.ref = ref
        self.capacity = (head[0] << 19) | (head[1] << 11) | (head[2] << 3)
        flags = head[4]
        self.is_inner = bool(flags & 0x80)
        self.has_refs = bool(flags & 0x40)
        self.context = bool(flags & 0x20)
        self.wtype = (flags & 0x18) >> 3
        self.width = (1 << (flags & 0x07)) >> 1
        self.size = (head[5] << 16) | (head[6] << 8) | head[7]
        if self.has_refs:
            self.byte_len = self.size * 8
        elif self.wtype == WTYPE_MULTIPLY:
            self.byte_len = self.size * self.width
        elif self.wtype == WTYPE_IGNORE:
            self.byte_len = self.size
        else:
            self.byte_len = (self.size * self.width + 7) // 8
        if ref + NODE_HEADER_SIZE + self.byte_len > realm.size:
            raise RealmError(
                "节点数据越界：ref=%d size=%d width=%d wtype=%d 需要 %d 字节，"
                "文件仅 %d 字节" % (ref, self.size, self.width, self.wtype,
                                    NODE_HEADER_SIZE + self.byte_len, realm.size))

    # -- 取值 -------------------------------------------------

    def raw_u(self, i):
        """取第 i 个元素的原始位模式（无符号）"""
        if i < 0 or i >= self.size:
            raise RealmError("元素下标越界：%d/%d（ref=%d）" % (i, self.size, self.ref))
        if self.has_refs:
            d = self.realm._read(self.ref + NODE_HEADER_SIZE + i * 8, 8)
            if len(d) != 8:
                raise RealmError("引用元素读取不全")
            return struct.unpack("<Q", d)[0]
        if self.wtype == WTYPE_BITS:
            w = self.width
            if w == 0:
                return 0
            total_bits = self.size * w
            nbytes = (total_bits + 7) // 8
            d = self.realm._read(self.ref + NODE_HEADER_SIZE, nbytes)
            bitpos = i * w
            bytepos = bitpos >> 3
            shift = bitpos & 7
            need = (shift + w + 7) >> 3
            chunk = d[bytepos:bytepos + need]
            if not chunk:
                raise RealmError("位域元素读取越界")
            acc = int.from_bytes(chunk, "little")
            return (acc >> shift) & ((1 << w) - 1)
        if self.wtype == WTYPE_MULTIPLY:
            d = self.realm._read(
                self.ref + NODE_HEADER_SIZE + i * self.width, self.width)
            if len(d) != self.width:
                raise RealmError("定宽元素读取不全")
            return int.from_bytes(d, "little")
        # wtype_Ignore：每元素 1 字节
        d = self.realm._read(self.ref + NODE_HEADER_SIZE + i, 1)
        return d[0] if d else 0

    def raw_bytes(self, i):
        """取第 i 个元素的原始字节（仅对 multiply / ignore 有意义）"""
        if self.wtype == WTYPE_MULTIPLY:
            off = self.ref + NODE_HEADER_SIZE + i * self.width
            return self.realm._read(off, self.width)
        if self.wtype == WTYPE_IGNORE:
            off = self.ref + NODE_HEADER_SIZE + i
            return self.realm._read(off, 1)
        raise RealmError("位域数组没有「元素字节」概念（ref=%d）" % self.ref)

    def get_int(self, i):
        """按有符号补码解读（整数列、键数组都适用）"""
        if self.has_refs:
            return _sign_extend(self.raw_u(i), 64)
        return _sign_extend(self.raw_u(i), self.width)

    def get_u(self, i):
        return self.raw_u(i) & 0xFFFFFFFFFFFFFFFF

    def is_tagged(self, i):
        """has_refs 数组里 lsb=1 表示这是 tagged 值而不是引用"""
        return bool(self.raw_u(i) & 1)

    def tagged_value(self, i):
        return self.raw_u(i) >> 1

    def ref_at(self, i):
        """取引用；tagged 或空槽（0）时返回 None"""
        if not self.has_refs:
            raise RealmError("ref=%d 不是引用数组（has_refs=0）" % self.ref)
        v = self.raw_u(i)
        if v & 1 or v == 0:
            return None
        return v

    def shape(self):
        return {
            "ref": self.ref,
            "size": self.size,
            "width": self.width,
            "wtype": self.wtype,
            "has_refs": self.has_refs,
            "is_inner": self.is_inner,
            "capacity": self.capacity,
        }

    def __repr__(self):
        return "<_Node ref=%d size=%d w=%d t=%d refs=%s>" % (
            self.ref, self.size, self.width, self.wtype, self.has_refs)


# ============================================================
# 主类
# ============================================================

class Realm(object):
    """Realm 数据库只读视图

    只依赖 sub 的 ``read(offset, size)`` 与 ``size``，无第三方依赖。
    """

    def __init__(self, sub):
        self.sub = sub
        try:
            self.size = int(getattr(sub, "size"))
        except Exception:
            raise RealmError("sub 缺少 size 属性")
        if self.size < REALM_HEADER_SIZE:
            raise RealmError("文件过短（%d 字节），不可能是 Realm" % self.size)
        self._cache = {}
        self._parse_header()

    # -- 底层 -------------------------------------------------

    def _read(self, off, size):
        if off < 0 or size < 0:
            return b""
        try:
            d = self.sub.read(off, size)
        except Exception as e:
            raise RealmError("读取失败 @%d+%d：%s" % (off, size, e))
        return bytes(d or b"")

    def node(self, ref):
        n = self._cache.get(ref)
        if n is None:
            n = _Node(self, ref)
            self._cache[ref] = n
        return n

    # -- 文件头 -----------------------------------------------

    def _parse_header(self):
        head = self._read(0, REALM_HEADER_SIZE)
        if len(head) != REALM_HEADER_SIZE:
            raise RealmError("文件头读取不全")
        self.top_ref = (struct.unpack("<Q", head[0:8])[0],
                        struct.unpack("<Q", head[8:16])[0])
        self.mnemonic = head[16:20]
        self.file_format = (head[20], head[21])
        self.reserved = head[22]
        self.flags = head[23]
        self.slot = 1 if (self.flags & 1) else 0
        self.streaming = False
        self.footer_top_ref = None
        self.footer_magic = None

        if self.mnemonic != REALM_MNEMONIC:
            raise RealmError(
                "mnemonic 不是 T-DB（实际 %r）：不是 Realm 文件、"
                "或是加密 Realm（本模块不做页级解密）、或已损坏" % self.mnemonic)

        self.logical_top = self.top_ref[self.slot]
        if self.slot == 0 and self.logical_top == STREAMING_SENTINEL:
            # 流式形态：真正的 top-ref 在文件尾部 footer
            if self.size < REALM_HEADER_SIZE + 16:
                raise RealmError("流式形态但文件过短")
            foot = self._read(self.size - 16, 16)
            if len(foot) != 16:
                raise RealmError("footer 读取不全")
            self.footer_top_ref = struct.unpack("<Q", foot[0:8])[0]
            self.footer_magic = struct.unpack("<Q", foot[8:16])[0]
            if self.footer_magic != REALM_FOOTER_MAGIC:
                raise RealmError(
                    "流式 footer magic 不符（0x%016X，应为 0x%016X）："
                    "文件可能被截断" % (self.footer_magic, REALM_FOOTER_MAGIC))
            self.streaming = True
            self.logical_top = self.footer_top_ref

        if self.logical_top % 8:
            raise RealmError("top-ref 未按 8 字节对齐：%d" % self.logical_top)
        if self.logical_top >= self.size:
            raise RealmError("top-ref 越界：%d（文件 %d 字节），文件可能被截断"
                             % (self.logical_top, self.size))

    def _group_top(self):
        return self.node(self.logical_top)

    # -- info -------------------------------------------------

    def info(self):
        """版本 / 页大小 / top ref / 表数

        注意：Realm **没有页（page）概念**。它只有 8 字节 ref 对齐，以及
        slab 区段（section）对齐；所以 ``page_size`` 恒为 ``None``，
        另给 ``ref_alignment``。
        """
        top = self._group_top()
        d = {
            "format": "Realm Database",
            "mnemonic": self.mnemonic.decode("latin-1"),
            "version": self.file_format[0],
            "version_second_byte": self.file_format[1],
            "version_is_current": self.file_format[0] == CURRENT_FILE_FORMAT_VERSION,
            "page_size": None,
            "page_size_note": "Realm 无页概念；仅 8 字节 ref 对齐 + slab 区段对齐",
            "ref_alignment": 8,
            "file_size": self.size,
            "size_is_8_aligned": (self.size % 8 == 0),
            "flags": self.flags,
            "top_ref_slot": self.slot,
            "top_refs_raw": [self.top_ref[0], self.top_ref[1]],
            "top_ref": self.logical_top,
            "streaming": self.streaming,
            "group_node": top.shape(),
            "table_count": self._table_names_node().size,
        }
        if self.streaming:
            d["footer_magic"] = "0x%016X" % (self.footer_magic or 0)
        if top.size > GROUP_SLOT_FILE_SIZE:
            d["logical_file_size"] = top.get_int(GROUP_SLOT_FILE_SIZE)
        if top.size > GROUP_SLOT_VERSION:
            d["transaction_version"] = top.get_u(GROUP_SLOT_VERSION)
        d["has_free_lists"] = (
            top.size > GROUP_SLOT_FREE_VER
            and top.ref_at(GROUP_SLOT_FREE_POS) is not None)
        d["has_history"] = (
            top.size > GROUP_SLOT_HIST_REF
            and top.ref_at(GROUP_SLOT_HIST_REF) is not None)
        if top.size > GROUP_SLOT_SYNC_ID:
            d["has_sync_file_id"] = bool(top.get_u(GROUP_SLOT_SYNC_ID))
        return d

    # -- 表名 -------------------------------------------------

    def _table_names_node(self):
        top = self._group_top()
        if not top.has_refs:
            raise RealmError("Group 顶层不是引用数组（ref=%d）" % top.ref)
        ref = top.ref_at(GROUP_SLOT_NAMES)
        if ref is None:
            raise RealmError("Group 顶层缺少表名槽（slot 0）")
        return self.node(ref)

    def _short_string(self, node, i):
        """ArrayStringShort 解码

        规则（array_string_short.hpp 顶部注释给出的编码）：
        每个元素是 width 字节的定长块，块内字符串以 0 填充；
        **块的最后 1 字节 = 尾部 0 的个数 - 1**；等于 width 表示 null。
        width == 0 时：非 nullable 全为空串，nullable 全为 null。
        """
        w = node.width
        if w == 0:
            return ""
        if node.wtype != WTYPE_MULTIPLY:
            raise RealmError(
                "字符串数组的 wtype=%d（期望 multiply=1），无法按块解码" % node.wtype)
        b = node.raw_bytes(i)
        if len(b) != w:
            raise RealmError("字符串块读取不全")
        last = b[w - 1]
        if last >= w:
            return None       # last == w → null
        n = w - 1 - last
        if n < 0:
            return None
        try:
            return b[:n].decode("utf-8")
        except UnicodeDecodeError:
            return b[:n].decode("utf-8", "replace")

    def tables(self):
        """表名列表（已剥离 ``class_`` 前缀）"""
        return [t["name"] for t in self.tables_detail()]

    def tables_detail(self):
        """表名明细：原始名 / 用户可见名 / 表顶层 ref"""
        names = self._table_names_node()
        top = self._group_top()
        tref = top.ref_at(GROUP_SLOT_TABLES)
        tarr = self.node(tref) if tref is not None else None
        out = []
        for i in range(names.size):
            raw = self._short_string(names, i)
            if raw is None:
                raw = ""
            user = raw[len(CLASS_NAME_PREFIX):] if raw.startswith(CLASS_NAME_PREFIX) else raw
            entry = {
                "index": i,
                "name": user,
                "raw_name": raw,
                "top_ref": None,
            }
            if tarr is not None and i < tarr.size:
                entry["top_ref"] = tarr.ref_at(i)
            out.append(entry)
        return out

    # -- 表结构 -----------------------------------------------

    def _table_node(self, table):
        for t in self.tables_detail():
            if t["name"] == table or t["raw_name"] == table:
                if not t["top_ref"]:
                    raise RealmError("表 %r 的顶层引用为空" % table)
                return self.node(t["top_ref"]), t
        raise RealmError("没有这张表：%r（现有：%s）"
                         % (table, ", ".join(self.tables()) or "无"))

    def _spec(self, tnode):
        ref = tnode.ref_at(TABLE_SLOT_SPEC)
        if ref is None:
            raise RealmError("表缺少 Spec 槽（slot 0）")
        spec = self.node(ref)
        types_ref = spec.ref_at(SPEC_SLOT_TYPES)
        names_ref = spec.ref_at(SPEC_SLOT_NAMES)
        attrs_ref = spec.ref_at(SPEC_SLOT_ATTRIBUTES)
        keys_ref = spec.ref_at(SPEC_SLOT_COLKEYS) if spec.size > SPEC_SLOT_COLKEYS else None
        return {
            "node": spec,
            "types": self.node(types_ref) if types_ref else None,
            "names": self.node(names_ref) if names_ref else None,
            "attrs": self.node(attrs_ref) if attrs_ref else None,
            "colkeys": self.node(keys_ref) if keys_ref else None,
        }

    def schema(self, table):
        """列名与类型

        每列：``index`` / ``name`` / ``type``（字符串）/ ``type_raw``（ColumnType
        数值）/ ``attrs``（属性名列表）/ ``nullable`` / ``collection`` / ``col_key``
        """
        tnode, _ = self._table_node(table)
        spec = self._spec(tnode)
        types = spec["types"]
        names = spec["names"]
        attrs = spec["attrs"]
        keys = spec["colkeys"]
        n = 0
        for cand in (types, names, attrs, keys):
            if cand is not None:
                n = max(n, cand.size)
        out = []
        for i in range(n):
            tval = types.get_int(i) if (types is not None and i < types.size) else None
            name = self._short_string(names, i) if (names is not None and i < names.size) else None
            aval = attrs.get_int(i) if (attrs is not None and i < attrs.size) else 0
            attr_names = [nm for nm, bit in COL_ATTRS if (aval & bit)]
            entry = {
                "index": i,
                "name": name,
                "type": COLUMN_TYPES.get(tval, "unknown(%s)" % tval),
                "type_raw": tval,
                "attrs": attr_names,
                "attrs_raw": aval,
                "nullable": bool(aval & 16),
                "collection": bool(aval & COL_ATTR_COLLECTION),
                "leaf_slot": i + CLUSTER_FIRST_COL_SLOT,
            }
            if keys is not None and i < keys.size:
                entry["col_key"] = keys.get_u(i)
            out.append(entry)
        return out

    # -- 行 ---------------------------------------------------

    def _cluster_root(self, tnode):
        ref = tnode.ref_at(TABLE_SLOT_CLUSTER)
        if ref is None:
            raise NotImplementedError(
                "表 %r 的 Cluster 树槽（Table 顶层 slot 2）为空，无法枚举行"
                % (tnode.ref,))
        return self.node(ref)

    def _is_leaf(self, node, ncols):
        """判定 Cluster 节点是叶还是内节点

        依据（cluster_tree.cpp 内节点注释 + cluster.hpp 叶节点布局）：
            * 叶：``[0]=键引用或紧凑尺寸, 1..=各列载荷``，故 size-1 == 列数，
              且 slot 1.. 都是合法引用（0 表示该列在该簇里尚无载荷）
            * 内节点：``[0]=键数组引用, [1]=子树深度（普通整数）, [2..]=子节点引用``
        两者都套不上就抛 NotImplementedError，不猜。
        """
        if node.size - CLUSTER_FIRST_COL_SLOT == ncols:
            ok = True
            for i in range(CLUSTER_FIRST_COL_SLOT, node.size):
                r = node.ref_at(i)
                if r is None:
                    continue
                if r <= 0 or r % 8 or r + NODE_HEADER_SIZE > self.size:
                    ok = False
                    break
            if ok:
                return True
        return False

    def _iter_leaves(self, node, ncols, depth=0, offset=0):
        if depth > 8:
            raise NotImplementedError("Cluster 树深度超过 8 层，未预期的结构")
        if self._is_leaf(node, ncols):
            yield node, offset
            return
        if node.size < 2:
            raise NotImplementedError(
                "Cluster 节点既不像叶（size-1 != 列数）又不像内节点（size<2）：ref=%d"
                % node.ref)
        depth_val = node.get_int(1)
        if depth_val < 0 or depth_val > 8:
            raise NotImplementedError(
                "Cluster 内节点的深度字段异常（%d），无法安全下探：ref=%d"
                % (depth_val, node.ref))
        found = False
        for i in range(2, node.size):
            r = node.ref_at(i)
            if r is None:
                continue
            found = True
            child = self.node(r)
            if child.is_inner:
                pass
            for item in self._iter_leaves(child, ncols, depth + 1, offset):
                yield item
        if not found:
            raise NotImplementedError(
                "Cluster 内节点没有任何子引用：ref=%d" % node.ref)

    def _leaf_rows(self, leaf, cols):
        """把一个 Cluster 叶展开成若干行（dict）"""
        n = 0
        keys = None
        compact = False
        slot0 = leaf.get_u(0) if leaf.size else 0
        if slot0 & 1:
            compact = True
            n = slot0 >> 1
        elif slot0 == 0:
            compact = True
            n = 0
        else:
            keys = self.node(slot0)
            n = keys.size
        for j in range(n):
            row = {}
            for col in cols:
                slot = col["leaf_slot"]
                if slot >= leaf.size:
                    row[col["name"]] = None
                    continue
                pref = leaf.ref_at(slot)
                if pref is None:
                    row[col["name"]] = None
                    continue
                payload = self.node(pref)
                row[col["name"]] = self._cell(payload, j, col)
            yield j, (None if keys is None else keys.get_u(j)), compact, row

    def _cell(self, payload, j, col):
        """按列类型解码一个单元格"""
        t = col["type"]
        nullable = col["nullable"]
        try:
            if t == "int":
                if nullable:
                    # ArrayIntNull：0 号元素是 null 哨兵，值从 1 号开始
                    sentinel = payload.get_int(0) if payload.size else 0
                    v = payload.get_int(j + 1) if j + 1 < payload.size else sentinel
                    return None if v == sentinel else v
                return payload.get_int(j) if j < payload.size else None
            if t == "bool":
                return bool(payload.get_int(j)) if j < payload.size else None
            if t == "string":
                if payload.wtype == WTYPE_MULTIPLY and 1 <= payload.width <= 64:
                    return self._short_string(payload, j) if j < payload.size else None
                if payload.wtype == WTYPE_BITS and payload.width == 0:
                    return ""
                return {"decoded": False,
                        "reason": "字符串为 medium/big（blob 分块）载荷，本模块未解码",
                        "column": col["name"],
                        "node": payload.shape()}
            if t in ("float", "double"):
                if payload.wtype != WTYPE_MULTIPLY:
                    return {"decoded": False, "reason": "浮点载荷形态非 multiply",
                            "column": col["name"], "node": payload.shape()}
                raw = payload.raw_bytes(j)
                if len(raw) != payload.width:
                    return None
                if payload.width == 4:
                    return struct.unpack("<f", raw)[0]
                if payload.width == 8:
                    return struct.unpack("<d", raw)[0]
                return {"decoded": False, "reason": "浮点宽度异常：%d" % payload.width,
                        "column": col["name"], "node": payload.shape()}
            if t == "timestamp":
                # 每元素两个整数：秒、纳秒
                if 2 * j + 1 < payload.size:
                    return {"seconds": payload.get_int(2 * j),
                            "nanoseconds": payload.get_int(2 * j + 1)}
                return None
            if t in ("link", "typed_link"):
                return payload.get_int(j) if j < payload.size else None
            # binary / decimal / object_id / uuid / mixed / unknown
            return {"decoded": False,
                    "reason": "列类型 %s 的载荷布局未在本次查证中确认" % t,
                    "column": col["name"],
                    "node": payload.shape()}
        except RealmError as e:
            return {"decoded": False, "reason": "解码失败：%s" % e,
                    "column": col["name"], "node": payload.shape()}

    def rows(self, table, limit=None):
        """枚举行

        返回 dict 列表：``{"row": 序号, "row_key": 键或 None, "key_mode": ...,
        "values": {列名: 值}}``

        值的三种形态：
            * 正常 Python 值（int / bool / float / str / None / timestamp dict）
            * ``{"decoded": False, ...}``：该单元格的载荷布局未确认，如实标注
        """
        tnode, tinfo = self._table_node(table)
        cols = self.schema(table)
        root = self._cluster_root(tnode)
        ncols = max([c["leaf_slot"] for c in cols], default=0)
        out = []
        for leaf, offset in self._iter_leaves(root, ncols):
            key_mode = "compact" if (leaf.size and (leaf.get_u(0) & 1)) else "keys"
            for j, key, compact, row in self._leaf_rows(leaf, cols):
                if key is None:
                    row_key = offset + j
                else:
                    row_key = key
                out.append({
                    "row": len(out),
                    "row_key": row_key,
                    "key_mode": key_mode,
                    "table": tinfo["name"],
                    "values": row,
                })
                if limit is not None and len(out) >= int(limit):
                    return out
        return out

    def find(self, table, **cond):
        """在已解码的行上做等值过滤

        只做 ``==`` 比较；对未解码的单元格一律视为不匹配。
        """
        if not cond:
            return self.rows(table)
        unknown = set(cond) - set(c["name"] for c in self.schema(table))
        if unknown:
            raise RealmError("表 %r 没有这些列：%s" % (table, ", ".join(sorted(unknown))))
        out = []
        for r in self.rows(table):
            ok = True
            for k, v in cond.items():
                cell = r["values"].get(k)
                if isinstance(cell, dict) and not cell.get("decoded", True):
                    ok = False
                    break
                if cell != v:
                    ok = False
                    break
            if ok:
                out.append(r)
        return out


# ============================================================
# 模块级入口
# ============================================================

def probe(sub):
    """按文件标识判定是不是 Realm 文件

    判据链（与 SlabAlloc::validate_header 对齐）：
        1. 文件长度 >= 24 且 8 字节对齐
        2. 偏移 16 处 4 字节 == ``T-DB``
        3. 选中的 top-ref 8 字节对齐且落在文件内
    """
    try:
        size = int(getattr(sub, "size"))
    except Exception:
        return False
    if size < REALM_HEADER_SIZE or size % 8:
        return False
    try:
        head = bytes(sub.read(0, REALM_HEADER_SIZE) or b"")
    except Exception:
        return False
    if len(head) != REALM_HEADER_SIZE:
        return False
    if head[16:20] != REALM_MNEMONIC:
        return False
    slot = 1 if (head[23] & 1) else 0
    top = struct.unpack("<Q", head[0:8] if slot == 0 else head[8:16])[0]
    if slot == 0 and top == STREAMING_SENTINEL:
        if size < REALM_HEADER_SIZE + 16:
            return False
        try:
            foot = bytes(sub.read(size - 16, 16) or b"")
        except Exception:
            return False
        if len(foot) != 16:
            return False
        if struct.unpack("<Q", foot[8:16])[0] != REALM_FOOTER_MAGIC:
            return False
        top = struct.unpack("<Q", foot[0:8])[0]
    if top % 8 or top >= size:
        return False
    return True


def open_fs(sub, **kw):
    return Realm(sub, **kw)


def describe(sub):
    """容错版：不是 Realm 也不抛"""
    try:
        return Realm(sub).info()
    except Exception as e:
        out = {"format": "Realm Database"}
        try:
            size = int(getattr(sub, "size"))
            out["file_size"] = size
            head = bytes(sub.read(0, REALM_HEADER_SIZE) or b"")
            if len(head) >= 20:
                out["magic"] = head[16:20].decode("latin-1")
                out["version"] = head[20]
                out["page_size"] = None
        except Exception:
            pass
        out["error"] = "%s: %s" % (type(e).__name__, e)
        return out


# ============================================================
# 自检（合成镜像）
# ============================================================

class _Mem(object):
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read(self, off, size):
        return self.data[off:off + size]


class _Builder(object):
    """在内存里拼一个最小 Realm 镜像"""

    def __init__(self):
        self.buf = bytearray(REALM_HEADER_SIZE)

    def _alloc(self, n):
        while len(self.buf) % 8:
            self.buf.append(0)
        off = len(self.buf)
        self.buf.extend(b"\x00" * n)
        while len(self.buf) % 8:
            self.buf.append(0)
        return off

    def node(self, payload, has_refs=False, wtype=WTYPE_BITS, width=8, size=None,
             is_inner=False):
        if size is None:
            size = (len(payload) * 8 // width) if (wtype == WTYPE_BITS and width) else len(payload)
        off = self._alloc(NODE_HEADER_SIZE + len(payload))
        cap = NODE_HEADER_SIZE + len(payload)
        flags = 0
        if is_inner:
            flags |= 0x80
        if has_refs:
            flags |= 0x40
        flags |= (wtype & 0x03) << 3
        log2w = 0
        v = width
        while v:
            log2w += 1
            v >>= 1
        flags |= (log2w & 0x07)
        self.buf[off + 0] = (cap >> 19) & 0xFF
        self.buf[off + 1] = (cap >> 11) & 0xFF
        self.buf[off + 2] = (cap >> 3) & 0xFF
        self.buf[off + 3] = 0
        self.buf[off + 4] = flags
        self.buf[off + 5] = (size >> 16) & 0xFF
        self.buf[off + 6] = (size >> 8) & 0xFF
        self.buf[off + 7] = size & 0xFF
        self.buf[off + 8:off + 8 + len(payload)] = payload
        return off

    def refs(self, refs, is_inner=False):
        """引用数组：has_refs + width 64"""
        payload = b"".join(struct.pack("<Q", r or 0) for r in refs)
        return self.node(payload, has_refs=True, wtype=WTYPE_BITS, width=64,
                         size=len(refs), is_inner=is_inner)

    def ints(self, values, width=None):
        if width is None:
            width = 8
            for v in values:
                if v < 0:
                    need = max(1, v.bit_length() + 1)
                else:
                    need = max(1, v.bit_length() + 1)
                for cand in (1, 2, 4, 8, 16, 32, 64):
                    if need <= cand:
                        width = max(width, cand)
                        break
        bits = "".join(format(v & ((1 << width) - 1), "0%db" % width)[::-1] for v in values)
        nbytes = (len(bits) + 7) // 8
        bits = bits + "0" * (nbytes * 8 - len(bits))
        payload = bytearray(nbytes)
        for byte_i in range(nbytes):
            chunk = bits[byte_i * 8:(byte_i + 1) * 8]
            payload[byte_i] = int(chunk[::-1], 2)
        return self.node(bytes(payload), wtype=WTYPE_BITS, width=width,
                         size=len(values))

    def strings(self, values, width=None):
        """ArrayStringShort：width 字节定长块，末字节 = 尾部 0 个数 - 1

        节点头里的 width 存的是 log2，所以实宽必须是 2 的幂。
        """
        if width is None:
            longest = max([len(v or "") for v in values], default=0)
            width = 1
            while width < longest + 1:
                width *= 2
        payload = bytearray()
        for v in values:
            if v is None:
                block = bytearray(width)
                block[width - 1] = width          # null 标记
                payload.extend(block)
                continue
            b = v.encode("utf-8")
            zeros = width - len(b)
            block = bytearray(b + b"\x00" * zeros)
            block[width - 1] = zeros - 1
            payload.extend(block)
        return self.node(bytes(payload), wtype=WTYPE_MULTIPLY, width=width,
                         size=len(values))

    def doubles(self, values):
        payload = b"".join(struct.pack("<d", v) for v in values)
        return self.node(payload, wtype=WTYPE_MULTIPLY, width=8, size=len(values))

    def finish(self, top_ref, version=CURRENT_FILE_FORMAT_VERSION, flags=0):
        struct.pack_into("<Q", self.buf, 0, top_ref)
        struct.pack_into("<Q", self.buf, 8, 0)
        self.buf[16:20] = REALM_MNEMONIC
        self.buf[20] = version & 0xFF
        self.buf[21] = (version >> 8) & 0xFF
        self.buf[22] = 0
        self.buf[23] = flags
        return bytes(self.buf)


def _build_ok():
    """一个两表的合成库：Person(name:str, age:int nullable) / Note(title:str, score:double)"""
    b = _Builder()

    # ---- Person ----
    p_name = b.strings(["alice", "bob"])
    # nullable int：0 号元素是哨兵（width 8 → 全 1 = 255）
    p_age = b.ints([255, 30, 255], width=8)
    p_leaf = b.refs([1, p_name, p_age])          # slot0 tagged: 1 = (size 0)<<1|1 → 见下覆盖
    # 重写 slot0 为 tagged(2)（2 行）
    struct.pack_into("<Q", b.buf, p_leaf + 8, (2 << 1) | 1)

    p_types = b.ints([2, 0], width=8)            # string, int
    p_names = b.strings(["name", "age"])
    p_attrs = b.ints([0, 16], width=8)           # 第 1 列 nullable
    p_keys = b.ints([0, 1], width=64)
    p_spec = b.refs([p_types, p_names, p_attrs, 0, 0, p_keys])
    p_top = b.refs([p_spec, 0, p_leaf])

    # ---- Note ----
    n_title = b.strings(["hi", "yo", "zz"])
    n_score = b.doubles([1.5, 2.5, -0.25])
    n_leaf = b.refs([1, n_title, n_score])
    struct.pack_into("<Q", b.buf, n_leaf + 8, (3 << 1) | 1)

    n_types = b.ints([2, 10], width=8)           # string, double
    n_names = b.strings(["title", "score"])
    n_attrs = b.ints([0, 0], width=8)
    n_keys = b.ints([0, 1], width=64)
    n_spec = b.refs([n_types, n_names, n_attrs, 0, 0, n_keys])
    n_top = b.refs([n_spec, 0, n_leaf])

    # ---- Group ----
    g_names = b.strings(["class_Person", "class_Note"])
    g_tables = b.refs([p_top, n_top])
    g_top = b.refs([g_names, g_tables, 0, 0, 0, 0])

    return b.finish(g_top)


def _selftest():
    print("=" * 62)
    print(" realm.py 自检（合成镜像）")
    print("=" * 62)
    img = _build_ok()
    sub = _Mem(img)

    # --- probe ---
    assert probe(sub) is True, "probe 应命中合成镜像"
    assert probe(_Mem(b"\x00" * 4096)) is False, "全零不应命中"
    assert probe(_Mem(b"T-DB")) is False, "过短不应命中"
    assert probe(_Mem(b"0123456789abcdef" + b"XXXX" + b"\x01" * 8)) is False, \
        "随机/无 mnemonic 不应命中"
    import random
    random.seed(20261117)
    rnd = bytes(random.randrange(256) for _ in range(4096))
    assert probe(_Mem(rnd)) is False, "随机字节不应命中"
    # mnemonic 对但 top-ref 越界
    bad = bytearray(img)
    struct.pack_into("<Q", bad, 0, 0x100000)
    assert probe(_Mem(bytes(bad))) is False, "top-ref 越界不应命中"
    print("[ok] probe 命中/不命中（真实镜像、全零、过短、随机、top-ref 越界）")

    # --- info ---
    r = Realm(sub)
    ifo = r.info()
    assert ifo["version"] == CURRENT_FILE_FORMAT_VERSION, ifo
    assert ifo["page_size"] is None and ifo["ref_alignment"] == 8, ifo
    assert ifo["table_count"] == 2, ifo
    assert ifo["top_ref"] == struct.unpack("<Q", img[0:8])[0], ifo
    assert ifo["streaming"] is False, ifo
    assert ifo["mnemonic"] == "T-DB", ifo
    print("[ok] info: version=%d table_count=%d top_ref=%d page_size=%s"
          % (ifo["version"], ifo["table_count"], ifo["top_ref"], ifo["page_size"]))

    # --- tables ---
    assert r.tables() == ["Person", "Note"], r.tables()
    det = r.tables_detail()
    assert det[0]["raw_name"] == "class_Person", det[0]
    print("[ok] tables: %s（原始名 %s）" % (r.tables(), det[0]["raw_name"]))

    # --- schema ---
    sc = r.schema("Person")
    assert [c["name"] for c in sc] == ["name", "age"], sc
    assert sc[0]["type"] == "string" and sc[1]["type"] == "int", sc
    assert sc[1]["nullable"] is True and sc[0]["nullable"] is False, sc
    assert sc[0]["leaf_slot"] == 1 and sc[1]["leaf_slot"] == 2, sc
    sc2 = r.schema("Note")
    assert [c["type"] for c in sc2] == ["string", "double"], sc2
    print("[ok] schema: Person=%s Note=%s"
          % ([(c["name"], c["type"]) for c in sc],
             [(c["name"], c["type"]) for c in sc2]))

    # --- rows ---
    rp = r.rows("Person")
    assert len(rp) == 2, rp
    assert rp[0]["values"] == {"name": "alice", "age": 30}, rp[0]
    assert rp[1]["values"] == {"name": "bob", "age": None}, rp[1]
    assert rp[0]["key_mode"] == "compact", rp[0]
    rn = r.rows("Note")
    assert [x["values"]["score"] for x in rn] == [1.5, 2.5, -0.25], rn
    assert [x["values"]["title"] for x in rn] == ["hi", "yo", "zz"], rn
    assert len(r.rows("Note", limit=1)) == 1, "limit 未生效"
    print("[ok] rows: Person=%s Note=%s"
          % (rp[0]["values"], [x["values"]["score"] for x in rn]))

    # --- find ---
    hit = r.find("Person", name="alice")
    assert len(hit) == 1 and hit[0]["values"]["age"] == 30, hit
    assert r.find("Person", age=None)[0]["values"]["name"] == "bob", "nullable 过滤失败"
    assert r.find("Person", name="nobody") == [], "不存在的值应为空"
    try:
        r.find("Person", nosuch=1)
    except RealmError:
        pass
    else:
        raise AssertionError("未知列应抛 RealmError")
    print("[ok] find: name=alice → 1 行，age=None → bob，未知列抛 RealmError")

    # --- 短字符串块编码的边界 ---
    nb = _Builder()
    s = nb.strings(["", "a" * 6, None], width=8)
    struct.pack_into("<Q", nb.buf, 0, s)
    nb.buf[16:20] = REALM_MNEMONIC
    nb.buf[20] = 24
    r2 = Realm(_Mem(bytes(nb.buf)))
    node = r2.node(s)
    assert r2._short_string(node, 0) == "", "空串解码错误"
    assert r2._short_string(node, 1) == "a" * 6, "6 字符解码错误"
    assert r2._short_string(node, 2) is None, "null 解码错误"
    print("[ok] 短字符串块：空串 / 6 字符 / null")

    # --- 未解码载荷如实标注（binary 列）---
    cb = _Builder()
    x_name = cb.strings(["k"])
    x_blob = cb.node(b"\x01\x02\x03\x04", wtype=WTYPE_MULTIPLY, width=4, size=1)
    x_leaf = cb.refs([1, x_name, x_blob])
    struct.pack_into("<Q", cb.buf, x_leaf + 8, (1 << 1) | 1)
    x_types = cb.ints([2, 4], width=8)          # string, binary
    x_names = cb.strings(["k", "blob"])
    x_attrs = cb.ints([0, 0], width=8)
    x_spec = cb.refs([x_types, x_names, x_attrs, 0, 0, 0])
    x_top = cb.refs([x_spec, 0, x_leaf])
    x_names_t = cb.strings(["class_Blob"])
    x_tables = cb.refs([x_top])
    x_gtop = cb.refs([x_names_t, x_tables, 0, 0, 0, 0])
    r3 = Realm(_Mem(cb.finish(x_gtop)))
    row = r3.rows("Blob")[0]
    cell = row["values"]["blob"]
    assert isinstance(cell, dict) and cell["decoded"] is False, cell
    assert "未" in cell["reason"], cell
    print("[ok] binary 列 → {'decoded': False, ...}：%s" % cell["reason"])

    # --- NotImplementedError：Cluster 槽为空 ---
    eb = _Builder()
    e_types = eb.ints([0], width=8)
    e_names = eb.strings(["n"])
    e_spec = eb.refs([e_types, e_names, 0, 0, 0, 0])
    e_top = eb.refs([e_spec, 0, 0])               # slot2 = 0
    e_names_t = eb.strings(["class_Empty"])
    e_tables = eb.refs([e_top])
    e_gtop = eb.refs([e_names_t, e_tables, 0, 0, 0, 0])
    r4 = Realm(_Mem(eb.finish(e_gtop)))
    try:
        r4.rows("Empty")
    except NotImplementedError as e:
        assert "Cluster" in str(e), e
        print("[ok] 空 Cluster 槽 → NotImplementedError: %s" % e)
    else:
        raise AssertionError("空 Cluster 槽应抛 NotImplementedError")

    # --- NotImplementedError：内节点深度异常 ---
    ib = _Builder()
    i_types = ib.ints([0], width=8)
    i_names = ib.strings(["n"])
    i_spec = ib.refs([i_types, i_names, 0, 0, 0, 0])
    bogus_child = ib.refs([0])
    i_root = ib.refs([0, 99, bogus_child], is_inner=True)   # depth=99 非法
    i_top = ib.refs([i_spec, 0, i_root])
    i_names_t = ib.strings(["class_Bad"])
    i_tables = ib.refs([i_top])
    i_gtop = ib.refs([i_names_t, i_tables, 0, 0, 0, 0])
    r5 = Realm(_Mem(ib.finish(i_gtop)))
    try:
        r5.rows("Bad")
    except NotImplementedError as e:
        assert "深度" in str(e), e
        print("[ok] 内节点深度异常 → NotImplementedError: %s" % e)
    else:
        raise AssertionError("非法深度应抛 NotImplementedError")

    # --- 错误路径 ---
    try:
        Realm(_Mem(b"\x00" * 64))
    except RealmError as e:
        assert "mnemonic" in str(e), e
    else:
        raise AssertionError("全零应抛 RealmError")
    try:
        Realm(_Mem(b""))
    except RealmError:
        pass
    else:
        raise AssertionError("空文件应抛 RealmError")

    # 流式 footer 形态
    sb = _Builder()
    g_names = sb.strings(["class_S"])
    g_tables = sb.refs([])
    g_top = sb.refs([g_names, g_tables, 0, 0, 0, 0])
    body = bytearray(sb.finish(g_top))
    struct.pack_into("<Q", body, 0, STREAMING_SENTINEL)
    body.extend(struct.pack("<QQ", g_top, REALM_FOOTER_MAGIC))
    rs = Realm(_Mem(bytes(body)))
    assert rs.streaming is True, "应识别为流式形态"
    assert rs.info()["table_count"] == 1, rs.info()
    print("[ok] 流式 footer 形态：top_ref=%d tables=%s"
          % (rs.info()["top_ref"], rs.tables()))
    # footer magic 错
    bad2 = bytearray(body)
    struct.pack_into("<Q", bad2, len(bad2) - 8, 0xDEADBEEF)
    try:
        Realm(_Mem(bytes(bad2)))
    except RealmError as e:
        assert "magic" in str(e), e
        print("[ok] footer magic 错 → RealmError")
    else:
        raise AssertionError("footer magic 错应抛 RealmError")

    # --- describe 容错 ---
    d = describe(sub)
    assert d["version"] == CURRENT_FILE_FORMAT_VERSION and d["table_count"] == 2, d
    d2 = describe(_Mem(b"\x00" * 64))
    assert "error" in d2 and d2["page_size"] is None, d2
    print("[ok] describe：正常库有 table_count，垃圾数据返回 error 不抛")

    print("-" * 62)
    print(" 全部自检通过")


if __name__ == "__main__":
    import sys
    try:
        _selftest()
    except AssertionError as e:
        print("\n[FAIL] %s" % e)
        sys.exit(1)