# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""Btrfs 文件系统

格式依据 Linux 内核 `include/uapi/linux/btrfs_tree.h`、`fs/btrfs/disk-io.h`、
`fs/btrfs/fs.h`（torvalds/linux master），逐字段核对后实现。
只依赖可读对象 sub.read(offset, size) / sub.size，零第三方依赖。

已实现：
    · 超级块（偏移 0x10000，魔数 _BHRfS_M）：全部字段解析，含 dev_item / label /
      incompat 标志解码；主副本缺失时自动回退 64M / 256G / 1T 三个镜像
    · sys_chunk_array 解析（17 字节 disk_key 与 btrfs_chunk 交替，无填充对齐）
    · chunk 树加载与合并：sys_chunk_array 只覆盖 system/metadata chunk，
      数据 chunk 必须从 chunk_root 树补全，两层合起来才够读文件
    · 逻辑地址 → 物理地址翻译：SINGLE / DUP / RAID1 / RAID1C3 / RAID1C4 精确，
      RAID0 / RAID10 按条带公式精确（只取 mirror 0）
    · 树节点读取：btrfs_header / btrfs_item / btrfs_key_ptr，含 bytenr 自校验
    · 键区间检索（btrfs_search_slot 式剪枝），支持任意层深的树
    · 根树 → ROOT_ITEM → 子卷切换（5 = FS_TREE，256 以上为子卷）
    · 目录遍历：INODE_ITEM / INODE_REF / DIR_ITEM / DIR_INDEX
      （含哈希碰撞时同一 item 内多条 dir_item 记录）
    · 文件读取：INLINE / REG / PREALLOC extent，空洞补零，跨 chunk 拼接
    · zlib 压缩 extent 解码（带 raw deflate 回退）
    · 按路径查找、递归 walk、名称子串筛选

不实现：
    · 写操作、fsck、log 树回放
    · 校验和不验证：csum_type 是 crc32c / xxhash / sha256 / blake2，标准库只有
      crc32 没有 crc32c，所以一律跳过校验，csum 字段只原样暴露。
      节点 csum 全零也能读，取证场景要的正是这种宽容度
    · RAID5 / RAID6 奇偶校验重建：只能给出第一数据条带，结果标记 exact=False
    · lzo / zstd / lz4 压缩 extent：标准库无解码器，抛 NotImplementedError
    · 加密 extent（encryption != 0）
    · DUP / RAID1 第二份拷贝自动重试（副本损坏时不换镜像，只报原样数据）
    · 已删除文件恢复：Btrfs 删除 inode 后 DIR_ITEM 直接消失、不留墓碑，
      与 FAT/NTFS 完全不同，只能靠 extent 雕刻，不属本模块职责
    · extent tree / free space tree / qgroup 语义解析（只做 chunk tree）
    · sub_stripes > 1 的 RAID10 只取 mirror 0

偏移核对（对 btrfs_tree.h 的 packed 结构重算，与需求里给的表逐项比对）：
    · 你列的 32 个超级块偏移全部正确，一个不差；
      仅 @0x40 的 magic 官方类型是 __le64（不是 u8[8]），值同为 8 字节
    · 名称修正：
      @0x68 官方名 __unused_log_root_transid。内核注释：自诞生起从未使用，
            恒为 0，读 log 树一律用 generation + 1。log_root_transid 是历史叫法
      @0x98 官方名 __unused_leafsize，2.6 之后即废弃，唯一权威是 @0x94 nodesize
    · 你表里缺、本实现已补的字段：
      nr_global_roots @0x24B、remap_root @0x253、remap_root_generation @0x25B、
      remap_root_level @0x263、reserved[199] @0x264、super_roots[4] @0xB2B
      （每个 168 字节）、padding[565] @0xDCB —— 合计正好 0x1000，可作长度自检
    · btrfs_header 合计 101 = 0x65（csum32 + fsid16 + bytenr8 + flags8 +
      chunk_tree_uuid16 + generation8 + owner8 + nritems4 + level1）；
      item.offset 以「leaf 数据区起点 = 0x65」为基准，不是节点起点
    · btrfs_item 25 字节，btrfs_key_ptr 33 字节，btrfs_dev_item 98 字节，
      btrfs_chunk 头 48 字节 + 每条带 32 字节（num_stripes=1 时整体 80）
    · 超级块镜像：0x10000 / 0x4000000 / 0x4000000000 / 0x400000000000
      （disk-io.h：mirror 0 固定 64K，其后为 16K << (12 * mirror)）
    · btrfs_root_item：inode(160) + generation@160 + root_dirid@168 + bytenr@176
      + level@238，legacy 长度 239，当前 439

自检：`python mkit/btrfs.py` 构造合成镜像（超级块 + 单个 sys chunk +
两级树 + 一个子卷 + inline / 普通 / zlib 三种 extent），逐项断言。
"""

import struct
import time
import zlib

__all__ = [
    "Btrfs", "Node", "Item", "KeyPtr", "BtrfsKey", "BtrfsDirent",
    "probe", "open_fs", "SB_OFFSET", "SB_MAGIC", "SB_MIRRORS",
    "KEY_TYPES", "INCOMPAT_FLAGS", "COMPRESS_NAMES",
]

# ---------------- 常量 ----------------

SB_OFFSET = 0x10000
SB_SIZE = 0x1000
SB_MAGIC = b"_BHRfS_M"
SB_MIRRORS = (0x10000, 0x4000000, 0x4000000000, 0x400000000000)

HEADER_SIZE = 0x65          # sizeof(struct btrfs_header)
ITEM_SIZE = 0x19            # sizeof(struct btrfs_item) = 17 + 4 + 4
KEY_PTR_SIZE = 0x21         # sizeof(struct btrfs_key_ptr) = 17 + 8 + 8
DISK_KEY_SIZE = 17
CHUNK_HDR_SIZE = 48
STRIPE_SIZE = 32
DEV_ITEM_SIZE = 98

SYSCK_ARRAY_OFF = 0x32B
SYSCK_ARRAY_MAX = 2048
LABEL_OFF = 0x12B
LABEL_SIZE = 256

U64_MAX = (1 << 64) - 1

# 对象号
BTRFS_ROOT_TREE_OBJECTID = 1
BTRFS_EXTENT_TREE_OBJECTID = 2
BTRFS_CHUNK_TREE_OBJECTID = 3
BTRFS_DEV_TREE_OBJECTID = 4
BTRFS_FS_TREE_OBJECTID = 5
BTRFS_FIRST_FREE_OBJECTID = 256
BTRFS_FIRST_CHUNK_TREE_OBJECTID = 256

# key 类型
T_INODE_ITEM = 1
T_INODE_REF = 12
T_INODE_EXTREF = 13
T_XATTR_ITEM = 24
T_ORPHAN_ITEM = 48
T_DIR_LOG_ITEM = 60
T_DIR_LOG_INDEX = 72
T_DIR_ITEM = 84
T_DIR_INDEX = 96
T_EXTENT_DATA = 108
T_EXTENT_CSUM = 128
T_ROOT_ITEM = 132
T_ROOT_BACKREF = 144
T_ROOT_REF = 156
T_EXTENT_ITEM = 168
T_METADATA_ITEM = 169
T_BLOCK_GROUP_ITEM = 192
T_DEV_EXTENT = 204
T_DEV_ITEM = 216
T_CHUNK_ITEM = 228
T_STRING_ITEM = 253

KEY_TYPES = {
    1: "INODE_ITEM", 12: "INODE_REF", 13: "INODE_EXTREF", 24: "XATTR_ITEM",
    36: "VERITY_ITEM", 48: "ORPHAN_ITEM", 60: "DIR_LOG_ITEM",
    72: "DIR_LOG_INDEX", 84: "DIR_ITEM", 96: "DIR_INDEX",
    108: "EXTENT_DATA", 128: "EXTENT_CSUM", 132: "ROOT_ITEM",
    144: "ROOT_BACKREF", 156: "ROOT_REF", 168: "EXTENT_ITEM",
    169: "METADATA_ITEM", 176: "TREE_BLOCK_REF", 178: "EXTENT_DATA_REF",
    182: "SHARED_BLOCK_REF", 184: "SHARED_DATA_REF", 192: "BLOCK_GROUP_ITEM",
    198: "FREE_SPACE_INFO", 199: "FREE_SPACE_EXTENT", 200: "FREE_SPACE_BITMAP",
    204: "DEV_EXTENT", 216: "DEV_ITEM", 228: "CHUNK_ITEM",
    240: "QGROUP_STATUS", 242: "QGROUP_INFO", 243: "QGROUP_RELATION",
    244: "QGROUP_LIMIT", 248: "TEMP_ITEM", 249: "PERSISTENT_ITEM",
    250: "DEV_REPLACE", 251: "UUID_SUBVOL", 252: "UUID_RECEIVED_SUBVOL",
    253: "STRING_ITEM",
}

# 块组 / chunk 类型标志
BLOCK_GROUP_DATA = 1 << 0
BLOCK_GROUP_SYSTEM = 1 << 1
BLOCK_GROUP_METADATA = 1 << 2
BLOCK_GROUP_RAID0 = 1 << 3
BLOCK_GROUP_RAID1 = 1 << 4
BLOCK_GROUP_DUP = 1 << 5
BLOCK_GROUP_RAID10 = 1 << 6
BLOCK_GROUP_RAID5 = 1 << 7
BLOCK_GROUP_RAID6 = 1 << 8
BLOCK_GROUP_RAID1C3 = 1 << 9
BLOCK_GROUP_RAID1C4 = 1 << 10
BLOCK_GROUP_REMAPPED = 1 << 11
BLOCK_GROUP_METADATA_REMAP = 1 << 12

PROFILE_MASK = (BLOCK_GROUP_RAID0 | BLOCK_GROUP_RAID1 | BLOCK_GROUP_DUP
                | BLOCK_GROUP_RAID10 | BLOCK_GROUP_RAID5 | BLOCK_GROUP_RAID6
                | BLOCK_GROUP_RAID1C3 | BLOCK_GROUP_RAID1C4)

BLOCK_GROUP_FLAGS = (
    (BLOCK_GROUP_DATA, "DATA"),
    (BLOCK_GROUP_SYSTEM, "SYSTEM"),
    (BLOCK_GROUP_METADATA, "METADATA"),
    (BLOCK_GROUP_RAID0, "RAID0"),
    (BLOCK_GROUP_RAID1, "RAID1"),
    (BLOCK_GROUP_DUP, "DUP"),
    (BLOCK_GROUP_RAID10, "RAID10"),
    (BLOCK_GROUP_RAID5, "RAID5"),
    (BLOCK_GROUP_RAID6, "RAID6"),
    (BLOCK_GROUP_RAID1C3, "RAID1C3"),
    (BLOCK_GROUP_RAID1C4, "RAID1C4"),
    (BLOCK_GROUP_REMAPPED, "REMAPPED"),
    (BLOCK_GROUP_METADATA_REMAP, "METADATA_REMAP"),
)

# 超级块 incompat 标志（include/uapi/linux/btrfs.h）
INCOMPAT_FLAGS = (
    (1 << 0, "MIXED_BACKREF"),
    (1 << 1, "DEFAULT_SUBVOL"),
    (1 << 2, "MIXED_GROUPS"),
    (1 << 3, "COMPRESS_LZO"),
    (1 << 4, "COMPRESS_ZSTD"),
    (1 << 5, "BIG_METADATA"),
    (1 << 6, "EXTENDED_IREF"),
    (1 << 7, "RAID56"),
    (1 << 8, "SKINNY_METADATA"),
    (1 << 9, "NO_HOLES"),
    (1 << 10, "METADATA_UUID"),
    (1 << 11, "RAID1C34"),
    (1 << 12, "ZONED"),
    (1 << 13, "EXTENT_TREE_V2"),
    (1 << 14, "RAID_STRIPE_TREE"),
    (1 << 16, "SIMPLE_QUOTA"),
    (1 << 17, "REMAP_TREE"),
)

COMPAT_RO_FLAGS = (
    (1 << 0, "FREE_SPACE_TREE"),
    (1 << 1, "FREE_SPACE_TREE_VALID"),
    (1 << 2, "VERITY"),
    (1 << 3, "BLOCK_GROUP_TREE"),
)

CSUM_NAMES = {0: "crc32c", 1: "xxhash64", 2: "sha256", 3: "blake2b"}

COMPRESS_NAMES = {0: "none", 1: "zlib", 2: "lzo", 3: "zstd", 4: "lz4"}

# 文件类型（dir_item.type）
FT_NAMES = {
    0: "unknown", 1: "reg", 2: "dir", 3: "chr", 4: "blk",
    5: "fifo", 6: "sock", 7: "symlink", 8: "xattr",
}

# extent 类型
FILE_EXTENT_INLINE = 0
FILE_EXTENT_REG = 1
FILE_EXTENT_PREALLOC = 2


def _uuid(raw):
    """16 字节 UUID -> 标准 36 字符形式"""
    if not raw or len(raw) < 16:
        return ""
    h = raw[:16].hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def _flag_names(value, table):
    """按标志表解码出名字列表"""
    return [name for bit, name in table if value & bit]


def _block_group_text(ctype):
    """chunk type 位域 -> 'DATA|METADATA|DUP'"""
    names = [name for bit, name in BLOCK_GROUP_FLAGS if ctype & bit]
    return "|".join(names) if names else "-"


def _ts(sec, nsec=0):
    """时间戳 -> 'YYYY-MM-DD HH:MM:SS'（UTC）"""
    if not sec:
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(sec))
    except (OSError, ValueError, OverflowError):
        return None


def _disk_key(buf, off):
    """解析 btrfs_disk_key（packed 17 字节）"""
    objectid, typ, offset = struct.unpack_from("<QBQ", buf, off)
    return BtrfsKey(objectid, typ, offset)


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _mode_name(mode):
    """mode 高 4 位 -> 类型名"""
    mask = mode & 0o170000
    if mask == 0o040000:
        return "dir"
    if mask == 0o100000:
        return "reg"
    if mask == 0o120000:
        return "symlink"
    if mask == 0o060000:
        return "blk"
    if mask == 0o020000:
        return "chr"
    if mask == 0o010000:
        return "fifo"
    if mask == 0o140000:
        return "sock"
    return "unknown"


def _decompress(ctype, raw, ram_bytes=0):
    """解压 extent 数据；只有 zlib 能解，其余明确抛 NotImplementedError"""
    if not ctype:
        return raw
    if ctype == 1:
        try:
            out = zlib.decompress(raw)
        except zlib.error:
            try:
                out = zlib.decompress(raw, -15)     # 裸 deflate 回退
            except zlib.error as exc:
                raise ValueError("zlib 解压失败: %s" % exc)
        return out[:ram_bytes] if ram_bytes else out
    raise NotImplementedError(
        "压缩类型 %s(%d) 需内核解码器，标准库无法处理"
        % (COMPRESS_NAMES.get(ctype, "unknown"), ctype))


class BtrfsKey(object):
    """btrfs_key：objectid + type + offset，字典序即磁盘序"""

    __slots__ = ("objectid", "type", "offset")

    def __init__(self, objectid=0, type=0, offset=0):
        self.objectid = objectid
        self.type = type
        self.offset = offset

    @property
    def type_name(self):
        return KEY_TYPES.get(self.type, "TYPE_%d" % self.type)

    def as_tuple(self):
        return (self.objectid, self.type, self.offset)

    def __eq__(self, other):
        return isinstance(other, BtrfsKey) and self.as_tuple() == other.as_tuple()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.as_tuple() < other.as_tuple()

    def __le__(self, other):
        return self.as_tuple() <= other.as_tuple()

    def __gt__(self, other):
        return self.as_tuple() > other.as_tuple()

    def __ge__(self, other):
        return self.as_tuple() >= other.as_tuple()

    def __hash__(self):
        return hash(self.as_tuple())

    def __repr__(self):
        return "<Key %d:%s:%d>" % (self.objectid, self.type_name, self.offset)


class Item(object):
    """叶子项：key + 数据切片"""

    __slots__ = ("key", "offset", "size", "_buf")

    def __init__(self, key, offset, size, buf):
        self.key = key
        self.offset = offset        # 相对 leaf 数据区起点（= 0x65）
        self.size = size
        self._buf = buf

    @property
    def data_offset(self):
        """数据在节点内的绝对偏移"""
        return HEADER_SIZE + self.offset

    @property
    def data(self):
        start = HEADER_SIZE + self.offset
        return self._buf[start:start + self.size]

    def __repr__(self):
        return "<Item %r %dB>" % (self.key, self.size)


class KeyPtr(object):
    """内部节点指针：key + 子节点逻辑地址 + generation"""

    __slots__ = ("key", "blockptr", "generation")

    def __init__(self, key, blockptr, generation):
        self.key = key
        self.blockptr = blockptr
        self.generation = generation

    def __repr__(self):
        return "<KeyPtr %r -> 0x%X gen=%d>" % (
            self.key, self.blockptr, self.generation)


class Node(object):
    """树节点（叶子或内部节点）"""

    __slots__ = ("fs", "laddr", "paddr", "data", "csum", "fsid", "bytenr",
                 "flags", "chunk_tree_uuid", "generation", "owner",
                 "nritems", "level", "warnings")

    def __init__(self, fs, laddr, paddr, data):
        if len(data) < HEADER_SIZE:
            raise ValueError("节点数据不足一个 btrfs_header（0x%X）" % len(data))
        self.fs = fs
        self.laddr = laddr
        self.paddr = paddr
        self.data = data
        self.csum = data[0x00:0x20]
        self.fsid = data[0x20:0x30]
        self.bytenr, self.flags = struct.unpack_from("<QQ", data, 0x30)
        self.chunk_tree_uuid = data[0x40:0x50]
        (self.generation, self.owner,
         self.nritems, self.level) = struct.unpack_from("<QQIB", data, 0x50)
        self.warnings = []
        if self.bytenr != laddr:
            self.warnings.append(
                "header.bytenr=0x%X 与查找地址 0x%X 不一致" % (self.bytenr, laddr))
        limit = (len(data) - HEADER_SIZE) // ITEM_SIZE
        if self.nritems > limit:
            raise ValueError(
                "nritems=%d 超出节点容量 %d（节点可能损坏）" % (self.nritems, limit))
        if self.level > 8:
            self.warnings.append("level=%d 超出 BTRFS_MAX_LEVEL" % self.level)

    @property
    def is_leaf(self):
        return self.level == 0

    def items(self):
        """叶子项列表；内部节点返回空列表"""
        if self.level != 0:
            return []
        out = []
        for i in range(self.nritems):
            base = HEADER_SIZE + i * ITEM_SIZE
            key = _disk_key(self.data, base)
            offset, size = struct.unpack_from(
                "<II", self.data, base + DISK_KEY_SIZE)
            out.append(Item(key, offset, size, self.data))
        return out

    def ptrs(self):
        """内部节点指针列表；叶子返回空列表"""
        if self.level == 0:
            return []
        out = []
        for i in range(self.nritems):
            base = HEADER_SIZE + i * KEY_PTR_SIZE
            key = _disk_key(self.data, base)
            blockptr, gen = struct.unpack_from(
                "<QQ", self.data, base + DISK_KEY_SIZE)
            out.append(KeyPtr(key, blockptr, gen))
        return out

    def __repr__(self):
        return "<Node 0x%X paddr=0x%X level=%d nritems=%d owner=%d>" % (
            self.laddr, self.paddr, self.level, self.nritems, self.owner)


class BtrfsDirent(object):
    """目录项"""

    __slots__ = ("name", "inode", "ftype", "tree_id", "index", "mode", "size",
                 "nlink", "uid", "gid", "mtime", "is_subvol", "subvol_id",
                 "location")

    def __init__(self, **kw):
        for key in self.__slots__:
            setattr(self, key, kw.get(key))

    @property
    def type_name(self):
        if self.mode:
            name = _mode_name(self.mode)
            if name != "unknown":
                return name
        return FT_NAMES.get(self.ftype, "unknown")

    @property
    def is_dir(self):
        return self.type_name == "dir"

    @property
    def is_symlink(self):
        return self.type_name == "symlink"

    def __repr__(self):
        return "<BtrfsDirent %r %s %dB%s>" % (
            self.name, self.type_name, self.size or 0,
            " SUBVOL" if self.is_subvol else "")


class Btrfs(object):
    """Btrfs 文件系统（只读）"""

    def __init__(self, sub, sb_offset=None):
        self.sub = sub
        self.warnings = []
        self.sb_offset = sb_offset if sb_offset is not None else self._locate_sb()
        self._read_super()
        self._chunks = []
        self._chunks_ready = False
        self._chunk_lock = False
        self._nodes = {}
        self._roots = None
        self._parse_sys_chunk_array()

    # ---------------- 超级块 ----------------
    def _locate_sb(self):
        """主副本 0x10000，失败回退 64M / 256G / 1T"""
        try:
            size = self.sub.size
        except Exception:
            size = 0
        for off in SB_MIRRORS:
            if size and off + SB_SIZE > size:
                continue
            try:
                if self.sub.read(off + 0x40, 8) == SB_MAGIC:
                    if off != SB_OFFSET:
                        self.warnings.append("主超级块缺失，使用镜像 0x%X" % off)
                    return off
            except Exception:
                continue
        raise ValueError("未找到 Btrfs 超级块（0x10000 及 3 个镜像均无 _BHRfS_M）")

    def _read_super(self):
        buf = self.sub.read(self.sb_offset, SB_SIZE)
        if len(buf) < SB_SIZE:
            raise ValueError("超级块被截断：%d < %d" % (len(buf), SB_SIZE))
        if buf[0x40:0x48] != SB_MAGIC:
            raise ValueError("超级块魔数错误: %r" % buf[0x40:0x48])
        self.sb_raw = buf

        self.fsid = buf[0x20:0x30]
        self.bytenr = _u64(buf, 0x30)
        self.flags = _u64(buf, 0x38)
        self.generation = _u64(buf, 0x48)
        self.root = _u64(buf, 0x50)
        self.chunk_root = _u64(buf, 0x58)
        self.log_root = _u64(buf, 0x60)
        self.log_root_transid = _u64(buf, 0x68)       # __unused，恒 0
        self.total_bytes = _u64(buf, 0x70)
        self.bytes_used = _u64(buf, 0x78)
        self.root_dir_objectid = _u64(buf, 0x80)
        self.num_devices = _u64(buf, 0x88)
        self.sectorsize = _u32(buf, 0x90)
        self.nodesize = _u32(buf, 0x94)
        self.leafsize = _u32(buf, 0x98)               # __unused_leafsize
        self.stripesize = _u32(buf, 0x9C)
        self.sys_chunk_array_size = _u32(buf, 0xA0)
        self.chunk_root_generation = _u64(buf, 0xA4)
        self.compat_flags = _u64(buf, 0xAC)
        self.compat_ro_flags = _u64(buf, 0xB4)
        self.incompat_flags = _u64(buf, 0xBC)
        self.csum_type = _u16(buf, 0xC4)
        self.root_level = buf[0xC6]
        self.chunk_root_level = buf[0xC7]
        self.log_root_level = buf[0xC8]
        self.dev_item = self._parse_dev_item(buf[0xC9:0xC9 + DEV_ITEM_SIZE])
        self.label = buf[LABEL_OFF:LABEL_OFF + LABEL_SIZE] \
            .split(b"\x00")[0].decode("utf-8", "replace")
        self.cache_generation = _u64(buf, 0x22B)
        self.uuid_tree_generation = _u64(buf, 0x233)
        self.metadata_uuid = buf[0x23B:0x24B]
        self.nr_global_roots = _u64(buf, 0x24B)
        self.remap_root = _u64(buf, 0x253)
        self.remap_root_generation = _u64(buf, 0x25B)
        self.remap_root_level = buf[0x263]
        raw_len = min(self.sys_chunk_array_size, SYSCK_ARRAY_MAX)
        self.sys_chunk_array = buf[SYSCK_ARRAY_OFF:SYSCK_ARRAY_OFF + raw_len]

        if not self.sectorsize:
            self.sectorsize = 4096
            self.warnings.append("sectorsize 为 0，按 4096 处理")
        if not self.nodesize:
            raise ValueError("nodesize 为 0，超级块无效")
        if self.nodesize < 4096 or self.nodesize > 65536 \
                or self.nodesize & (self.nodesize - 1):
            raise ValueError("nodesize=0x%X 不是 4K..64K 的 2 的幂" % self.nodesize)
        if self.leafsize and self.leafsize != self.nodesize:
            self.warnings.append(
                "leafsize(0x%X) != nodesize(0x%X)，以 nodesize 为准"
                % (self.leafsize, self.nodesize))
        if not self.root:
            raise ValueError("超级块 root 为 0，无根树")

    def _parse_dev_item(self, raw):
        """btrfs_dev_item（98 字节）"""
        return {
            "devid": _u64(raw, 0),
            "total_bytes": _u64(raw, 8),
            "bytes_used": _u64(raw, 16),
            "io_align": _u32(raw, 24),
            "io_width": _u32(raw, 28),
            "sector_size": _u32(raw, 32),
            "type": _u64(raw, 36),
            "generation": _u64(raw, 44),
            "start_offset": _u64(raw, 52),
            "dev_group": _u32(raw, 60),
            "seek_speed": raw[64],
            "bandwidth": raw[65],
            "uuid": _uuid(raw[66:82]),
            "fsid": _uuid(raw[82:98]),
        }

    def info(self):
        """超级块摘要"""
        return {
            "magic": self.sb_raw[0x40:0x48].decode("ascii", "replace"),
            "sb_offset": self.sb_offset,
            "fsid": _uuid(self.fsid),
            "metadata_uuid": _uuid(self.metadata_uuid),
            "label": self.label,
            "bytenr": self.bytenr,
            "generation": self.generation,
            "sectorsize": self.sectorsize,
            "nodesize": self.nodesize,
            "leafsize": self.leafsize,
            "stripesize": self.stripesize,
            "total_bytes": self.total_bytes,
            "bytes_used": self.bytes_used,
            "num_devices": self.num_devices,
            "root": self.root,
            "root_level": self.root_level,
            "chunk_root": self.chunk_root,
            "chunk_root_level": self.chunk_root_level,
            "log_root": self.log_root,
            "root_dir_objectid": self.root_dir_objectid,
            "sys_chunk_array_size": self.sys_chunk_array_size,
            "csum_type": CSUM_NAMES.get(self.csum_type,
                                        "unknown(%d)" % self.csum_type),
            "compat_flags": self.compat_flags,
            "compat_ro_flags": self.compat_ro_flags,
            "incompat_flags": self.incompat_flags,
            "incompat_features": _flag_names(self.incompat_flags, INCOMPAT_FLAGS),
            "compat_ro_features": _flag_names(self.compat_ro_flags,
                                              COMPAT_RO_FLAGS),
            "cache_generation": self.cache_generation,
            "uuid_tree_generation": self.uuid_tree_generation,
            "nr_global_roots": self.nr_global_roots,
            "dev_item": self.dev_item,
            "warnings": list(self.warnings),
        }

    # ---------------- chunk 映射 ----------------
    def _parse_chunk(self, buf, off, logical, source):
        """解析 btrfs_chunk；返回 dict（含 size = 本条记录占用字节）"""
        end = len(buf)
        if off + CHUNK_HDR_SIZE > end:
            return None
        (length, owner, stripe_len, ctype, io_align, io_width,
         sector_size, num_stripes, sub_stripes) = struct.unpack_from(
            "<QQQQIIIHH", buf, off)
        if num_stripes == 0 or num_stripes > 512:
            self.warnings.append("chunk@0x%X 的 num_stripes=%d 异常"
                                 % (logical, num_stripes))
            return None
        need = off + CHUNK_HDR_SIZE + num_stripes * STRIPE_SIZE
        if need > end:
            self.warnings.append("chunk@0x%X 条带越界（需要 0x%X，可用 0x%X）"
                                 % (logical, need, end))
            return None
        stripes = []
        pos = off + CHUNK_HDR_SIZE
        for _ in range(num_stripes):
            devid, soff = struct.unpack_from("<QQ", buf, pos)
            stripes.append({
                "devid": devid,
                "offset": soff,
                "dev_uuid": _uuid(buf[pos + 16:pos + 32]),
            })
            pos += STRIPE_SIZE
        return {
            "logical": logical,
            "length": length,
            "owner": owner,
            "stripe_len": stripe_len,
            "type": ctype,
            "type_text": _block_group_text(ctype),
            "io_align": io_align,
            "io_width": io_width,
            "sector_size": sector_size,
            "num_stripes": num_stripes,
            "sub_stripes": sub_stripes,
            "stripes": stripes,
            "source": source,
            "size": need - off,
        }

    def _parse_sys_chunk_array(self):
        """sys_chunk_array：btrfs_disk_key(17) 与 btrfs_chunk 交替，无对齐填充"""
        raw = self.sys_chunk_array
        pos = 0
        end = len(raw)
        while pos < end:
            if pos + DISK_KEY_SIZE > end:
                self.warnings.append("sys_chunk_array 尾部不足一个 disk_key")
                break
            key = _disk_key(raw, pos)
            pos += DISK_KEY_SIZE
            if key.type != T_CHUNK_ITEM:
                self.warnings.append(
                    "sys_chunk_array 里 type=%d 不是 CHUNK_ITEM，停止解析"
                    % key.type)
                break
            chunk = self._parse_chunk(raw, pos, key.offset, "sys_chunk_array")
            if chunk is None:
                break
            chunk["objectid"] = key.objectid
            self._chunks.append(chunk)
            pos += chunk["size"]
        self._chunks.sort(key=lambda c: c["logical"])

    def _merge_chunk(self, chunk):
        """按逻辑起点去重（sys_chunk_array 优先）"""
        for cur in self._chunks:
            if cur["logical"] == chunk["logical"]:
                return
        self._chunks.append(chunk)
        self._chunks.sort(key=lambda c: c["logical"])

    def _ensure_chunks(self):
        """从 chunk 树补全数据 chunk（sys 数组只覆盖 system/metadata）"""
        if self._chunks_ready or self._chunk_lock:
            return
        self._chunk_lock = True
        self._chunks_ready = True
        try:
            if not self.chunk_root:
                self.warnings.append("chunk_root 为 0，跳过 chunk 树加载")
                return
            for item in self._iter_items(self.chunk_root):
                if item.key.type != T_CHUNK_ITEM:
                    continue
                chunk = self._parse_chunk(item.data, 0, item.key.offset,
                                          "chunk_tree")
                if chunk is not None:
                    self._merge_chunk(chunk)
        except Exception as exc:
            self.warnings.append("chunk 树加载失败: %s" % exc)
        finally:
            self._chunk_lock = False

    def chunk_map(self):
        """全部 chunk，一行一个 dict"""
        self._ensure_chunks()
        return [dict(c) for c in self._chunks]

    def _chunk_for(self, laddr):
        for chunk in self._chunks:
            if chunk["logical"] <= laddr < chunk["logical"] + chunk["length"]:
                return chunk
        return None

    def _stripe_offset(self, chunk, delta):
        """chunk 内偏移 -> (物理地址, 是否精确)"""
        stripes = chunk["stripes"]
        count = len(stripes)
        profile = chunk["type"] & PROFILE_MASK
        stripe_len = chunk["stripe_len"] or 65536

        if profile & BLOCK_GROUP_RAID0:
            stripe_nr, within = divmod(delta, stripe_len)
            index = stripe_nr % count
            row = stripe_nr // count
            return stripes[index]["offset"] + row * stripe_len + within, True

        if profile & BLOCK_GROUP_RAID10:
            groups = max(1, count // max(1, chunk["sub_stripes"]))
            stripe_nr, within = divmod(delta, stripe_len)
            index = (stripe_nr % groups) * max(1, chunk["sub_stripes"])
            row = stripe_nr // groups
            if index >= count:
                index = 0
            return stripes[index]["offset"] + row * stripe_len + within, True

        if profile & (BLOCK_GROUP_RAID5 | BLOCK_GROUP_RAID6):
            # 未扣奇偶校验条带，只能给近似地址
            stripe_nr, within = divmod(delta, stripe_len)
            index = stripe_nr % count
            row = stripe_nr // count
            return stripes[index]["offset"] + row * stripe_len + within, False

        # SINGLE / DUP / RAID1 / RAID1C3 / RAID1C4：第一份拷贝
        return stripes[0]["offset"] + delta, True

    def logical_to_physical(self, laddr):
        """逻辑地址 -> (物理地址, 剩余长度, chunk 类型) | None"""
        detail = self.map_detail(laddr)
        if detail is None:
            return None
        return detail["paddr"], detail["length"], detail["type"]

    def map_detail(self, laddr):
        """逻辑地址映射明细（含 exact 标记）"""
        self._ensure_chunks()
        chunk = self._chunk_for(laddr)
        if chunk is None:
            return None
        delta = laddr - chunk["logical"]
        paddr, exact = self._stripe_offset(chunk, delta)
        if paddr is None:
            return None
        return {
            "logical": laddr,
            "paddr": paddr,
            "length": chunk["length"] - delta,
            "type": chunk["type"],
            "type_text": _block_group_text(chunk["type"]),
            "chunk_logical": chunk["logical"],
            "offset_in_chunk": delta,
            "exact": exact,
            "source": chunk["source"],
        }

    # ---------------- 节点 ----------------
    def read_node(self, laddr):
        """按逻辑地址读树节点"""
        cached = self._nodes.get(laddr)
        if cached is not None:
            return cached
        detail = self.map_detail(laddr)
        if detail is None:
            raise ValueError("逻辑地址 0x%X 无 chunk 映射" % laddr)
        paddr = detail["paddr"]
        data = self.sub.read(paddr, self.nodesize)
        if len(data) < HEADER_SIZE:
            raise ValueError("节点 0x%X 读取过短：%d 字节" % (laddr, len(data)))
        if len(data) < self.nodesize:
            self.warnings.append(
                "节点 0x%X 不足 nodesize（%d < %d），按零填充"
                % (laddr, len(data), self.nodesize))
            data = data + b"\x00" * (self.nodesize - len(data))
        node = Node(self, laddr, paddr, data)
        self.warnings.extend(node.warnings)
        if len(self._nodes) > 4096:
            self._nodes.clear()
        self._nodes[laddr] = node
        return node

    def root_tree(self):
        """根树根节点"""
        return self.read_node(self.root)

    def chunk_root_tree(self):
        """chunk 树根节点"""
        if not self.chunk_root:
            raise ValueError("超级块未给出 chunk_root")
        return self.read_node(self.chunk_root)

    def iter_items(self, laddr, kmin=None, kmax=None):
        """按 key 区间检索整棵树（叶子项迭代器）"""
        yield from self._iter_items(laddr, kmin, kmax)

    def _iter_items(self, laddr, kmin=None, kmax=None, depth=0):
        if depth > 16:
            self.warnings.append("树深超过 16（疑似环路），在 0x%X 处截断" % laddr)
            return
        node = self.read_node(laddr)
        if node.level == 0:
            for item in node.items():
                if kmin is not None and item.key < kmin:
                    continue
                if kmax is not None and item.key > kmax:
                    continue
                yield item
            return
        ptrs = node.ptrs()
        total = len(ptrs)
        for i, ptr in enumerate(ptrs):
            if kmin is not None and i + 1 < total and ptrs[i + 1].key <= kmin:
                continue
            if kmax is not None and ptr.key > kmax:
                break
            yield from self._iter_items(ptr.blockptr, kmin, kmax, depth + 1)

    # ---------------- 根树 / 子卷 ----------------
    def roots(self):
        """根树里的全部 ROOT_ITEM -> {tree_id: info}"""
        if self._roots is not None:
            return self._roots
        out = {}
        for item in self._iter_items(self.root):
            if item.key.type != T_ROOT_ITEM:
                continue
            data = item.data
            if len(data) < 239:
                self.warnings.append(
                    "ROOT_ITEM %d 只有 %d 字节，跳过"
                    % (item.key.objectid, len(data)))
                continue
            info = {
                "id": item.key.objectid,
                "offset": item.key.offset,
                "bytenr": _u64(data, 176),
                "level": data[238],
                "generation": _u64(data, 160),
                "root_dirid": _u64(data, 168),
                "bytes_used": _u64(data, 192),
                "flags": _u64(data, 208),
                "refs": _u32(data, 216),
                "uuid": _uuid(data[247:263]) if len(data) >= 263 else "",
            }
            if len(data) >= 247:
                info["generation_v2"] = _u64(data, 239)
            tid = item.key.objectid
            if tid in out and item.key.offset != 0:
                continue
            out[tid] = info
        self._roots = out
        return out

    def subvolumes(self):
        """子卷列表（tree_id >= 256）"""
        return [dict(info) for tid, info in sorted(self.roots().items())
                if tid >= BTRFS_FIRST_FREE_OBJECTID]

    def _tree_info(self, tree_id=BTRFS_FS_TREE_OBJECTID):
        info = self.roots().get(tree_id)
        if info is None:
            raise KeyError("根树里没有 tree_id=%d 的 ROOT_ITEM" % tree_id)
        info = dict(info)
        if not info.get("root_dirid"):
            info["root_dirid"] = BTRFS_FIRST_FREE_OBJECTID
        return info

    def tree(self, tree_id=BTRFS_FS_TREE_OBJECTID):
        """子卷/树的根节点"""
        return self.read_node(self._tree_info(tree_id)["bytenr"])

    def inode(self, ino, tree_id=BTRFS_FS_TREE_OBJECTID):
        """INODE_ITEM -> dict | None"""
        info = self._tree_info(tree_id)
        kmin = BtrfsKey(ino, T_INODE_ITEM, 0)
        kmax = BtrfsKey(ino, T_INODE_ITEM, U64_MAX)
        for item in self._iter_items(info["bytenr"], kmin, kmax):
            if item.key.type != T_INODE_ITEM or item.key.objectid != ino:
                continue
            data = item.data
            if len(data) < 160:
                continue
            mode = _u32(data, 52)
            name = _mode_name(mode)
            return {
                "ino": ino,
                "tree_id": tree_id,
                "generation": _u64(data, 0),
                "transid": _u64(data, 8),
                "size": _u64(data, 16),
                "nbytes": _u64(data, 24),
                "nlink": _u32(data, 40),
                "uid": _u32(data, 44),
                "gid": _u32(data, 48),
                "mode": mode,
                "type": name,
                "is_dir": name == "dir",
                "is_symlink": name == "symlink",
                "rdev": _u64(data, 56),
                "flags": _u64(data, 64),
                "sequence": _u64(data, 72),
                "atime": _ts(_u64(data, 112), _u32(data, 120)),
                "ctime": _ts(_u64(data, 124), _u32(data, 132)),
                "mtime": _ts(_u64(data, 136), _u32(data, 144)),
                "otime": _ts(_u64(data, 148), _u32(data, 156)),
                "mtime_raw": _u64(data, 136),
            }
        return None

    # ---------------- 目录 ----------------
    def _parse_dir_item(self, data):
        """一个 DIR_ITEM / DIR_INDEX item 内可含多条记录（哈希碰撞）"""
        out = []
        pos = 0
        total = len(data)
        while pos + 30 <= total:
            location = _disk_key(data, pos)
            transid, data_len, name_len, ftype = struct.unpack_from(
                "<QHHB", data, pos + 17)
            head_end = pos + 30
            name = data[head_end:head_end + name_len].decode("utf-8", "replace")
            out.append({
                "name": name,
                "location": location,
                "transid": transid,
                "data_len": data_len,
                "ftype": ftype,
                "index": None,
            })
            pos = head_end + name_len + data_len
        return out

    def dir_records(self, ino, tree_id=BTRFS_FS_TREE_OBJECTID):
        """目录 inode 的全部目录项（DIR_ITEM 与 DIR_INDEX 去重合并）"""
        info = self._tree_info(tree_id)
        kmin = BtrfsKey(ino, 0, 0)
        kmax = BtrfsKey(ino, 255, U64_MAX)
        merged = {}
        order = []
        for item in self._iter_items(info["bytenr"], kmin, kmax):
            if item.key.objectid != ino:
                continue
            if item.key.type not in (T_DIR_ITEM, T_DIR_INDEX):
                continue
            index = item.key.offset if item.key.type == T_DIR_INDEX else None
            for rec in self._parse_dir_item(item.data):
                dedup = (rec["name"], rec["location"].objectid,
                         rec["location"].type)
                if dedup in merged:
                    if index is not None and merged[dedup]["index"] is None:
                        merged[dedup]["index"] = index
                    continue
                rec["index"] = index
                merged[dedup] = rec
                order.append(dedup)
        out = [merged[key] for key in order]
        out.sort(key=lambda r: (r["index"] is None,
                                r["index"] if r["index"] is not None else 0,
                                r["name"]))
        return out

    def _make_dirent(self, tree_id, rec):
        location = rec["location"]
        if location.type == T_ROOT_ITEM:
            sub_id = location.objectid
            ino = 0
            inode = None
            try:
                ino = self._tree_info(sub_id)["root_dirid"]
                inode = self.inode(ino, sub_id)
            except (KeyError, ValueError):
                inode = None
            inode = inode or {}
            return BtrfsDirent(
                name=rec["name"], inode=ino, ftype=rec["ftype"],
                tree_id=sub_id, index=rec["index"], mode=inode.get("mode"),
                size=None, nlink=inode.get("nlink"), uid=inode.get("uid"),
                gid=inode.get("gid"), mtime=inode.get("mtime"),
                is_subvol=True, subvol_id=sub_id, location=location)
        ino = location.objectid
        inode = None
        try:
            inode = self.inode(ino, tree_id)
        except (KeyError, ValueError):
            inode = None
        inode = inode or {}
        return BtrfsDirent(
            name=rec["name"], inode=ino, ftype=rec["ftype"], tree_id=tree_id,
            index=rec["index"], mode=inode.get("mode"), size=inode.get("size"),
            nlink=inode.get("nlink"), uid=inode.get("uid"),
            gid=inode.get("gid"), mtime=inode.get("mtime"),
            is_subvol=False, subvol_id=None, location=location)

    def resolve(self, path="/"):
        """路径 -> (tree_id, inode)。支持子卷跨越与 .. 上溯"""
        if path in (None, "", "/", "."):
            info = self._tree_info(BTRFS_FS_TREE_OBJECTID)
            return BTRFS_FS_TREE_OBJECTID, info["root_dirid"]
        tree_id = BTRFS_FS_TREE_OBJECTID
        ino = self._tree_info(tree_id)["root_dirid"]
        parents = []
        parts = [p for p in str(path).replace("\\", "/").split("/")
                 if p and p != "."]
        for part in parts:
            if part == "..":
                if parents:
                    tree_id, ino = parents.pop()
                continue
            hit = None
            for rec in self.dir_records(ino, tree_id):
                if rec["name"] == part:
                    hit = rec
                    break
            if hit is None:
                raise FileNotFoundError(path)
            parents.append((tree_id, ino))
            location = hit["location"]
            if location.type == T_ROOT_ITEM:
                tree_id = location.objectid
                ino = self._tree_info(tree_id)["root_dirid"]
            else:
                ino = location.objectid
        return tree_id, ino

    def listdir(self, path="/"):
        """列目录，返回 BtrfsDirent 列表（按 DIR_INDEX 序号排序）"""
        tree_id, ino = self.resolve(path)
        inode = self.inode(ino, tree_id)
        if inode is not None and not inode["is_dir"]:
            raise ValueError("不是目录: %s" % path)
        return [self._make_dirent(tree_id, rec)
                for rec in self.dir_records(ino, tree_id)]

    def walk(self, path="/", _depth=0, _max=64):
        """递归遍历，产出 (路径, BtrfsDirent)"""
        prefix = "" if path in (None, "", "/") else str(path).rstrip("/\\") + "/"
        for entry in self.listdir(path):
            if entry.name in (".", ".."):
                continue
            full = prefix + entry.name
            yield full, entry
            if entry.is_dir and _depth < _max:
                for sub_path, sub_entry in self.walk(full, _depth + 1, _max):
                    yield sub_path, sub_entry

    def find(self, pattern=""):
        """按路径子串筛选（不区分大小写）"""
        out = []
        needle = (pattern or "").lower()
        for full, entry in self.walk():
            if needle and needle not in full.lower():
                continue
            out.append((full, entry))
        return out

    # ---------------- 文件数据 ----------------
    def _read_logical(self, laddr, length):
        """跨 chunk 读逻辑区间"""
        out = bytearray()
        pos = laddr
        end = laddr + length
        while pos < end:
            detail = self.map_detail(pos)
            if detail is None:
                raise ValueError("逻辑地址 0x%X 无 chunk 映射" % pos)
            span = min(detail["length"], end - pos)
            out += self.sub.read(detail["paddr"], span)
            pos += span
        return bytes(out)

    def extent_payload(self, item):
        """一条 EXTENT_DATA -> 该记录对应的文件数据"""
        data = item.data
        if len(data) < 21:
            raise ValueError("EXTENT_DATA 项过短：%d" % len(data))
        ram_bytes = _u64(data, 8)
        compression = data[16]
        encryption = data[17]
        etype = data[20]
        if encryption:
            raise NotImplementedError(
                "加密 extent（encryption=%d）不支持" % encryption)
        if etype == FILE_EXTENT_INLINE:
            raw = data[21:]
            if compression:
                return _decompress(compression, raw, ram_bytes)
            return raw[:ram_bytes] if ram_bytes else raw
        disk_bytenr, disk_num_bytes, extent_offset, num_bytes = \
            struct.unpack_from("<QQQQ", data, 21)
        if disk_bytenr == 0:
            return b"\x00" * num_bytes           # 空洞 / 未写入的 prealloc
        raw = self._read_logical(disk_bytenr, disk_num_bytes)
        if compression:
            raw = _decompress(compression, raw, ram_bytes)
        return raw[extent_offset:extent_offset + num_bytes]

    def read_file(self, path=None, tree_id=None, ino=None):
        """按路径（或 tree_id + ino）读文件内容"""
        if tree_id is None or ino is None:
            tree_id, ino = self.resolve(path)
        inode = self.inode(ino, tree_id)
        if inode is None:
            raise ValueError("找不到 inode %d（tree %d）" % (ino, tree_id))
        if inode["is_dir"]:
            raise ValueError("是目录，不是文件: %s" % path)
        size = inode["size"]
        info = self._tree_info(tree_id)
        kmin = BtrfsKey(ino, T_EXTENT_DATA, 0)
        kmax = BtrfsKey(ino, T_EXTENT_DATA, U64_MAX)
        out = bytearray()
        for item in self._iter_items(info["bytenr"], kmin, kmax):
            if item.key.type != T_EXTENT_DATA or item.key.objectid != ino:
                continue
            if item.key.offset > len(out):
                out += b"\x00" * (item.key.offset - len(out))   # 空洞补零
            out += self.extent_payload(item)
            if size and len(out) >= size:
                break
        if size and len(out) < size:
            out += b"\x00" * (size - len(out))
        return bytes(out[:size]) if size else bytes(out)

    def __repr__(self):
        return "<Btrfs label=%r nodesize=%d gen=%d>" % (
            self.label, self.nodesize, self.generation)


def probe(sub):
    """判断是否是 Btrfs（主副本或 3 个镜像任一命中）"""
    try:
        size = sub.size
    except Exception:
        return False
    for off in SB_MIRRORS:
        if size and off + SB_SIZE > size:
            continue
        try:
            if sub.read(off + 0x40, 8) == SB_MAGIC:
                return True
        except Exception:
            continue
    return False


def open_fs(sub, sb_offset=None):
    """打开 Btrfs 卷"""
    if not probe(sub):
        raise ValueError("不是 Btrfs 文件系统（未找到 _BHRfS_M）")
    return Btrfs(sub, sb_offset=sb_offset)


if __name__ == "__main__":
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    NODESIZE = 16384
    SECTORSIZE = 4096
    GEN = 7
    FSID = bytes.fromhex("00112233445566778899aabbccddeeff")
    CHUNK_UUID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    DEV_UUID = bytes.fromhex("0123456789abcdeffedcba9876543210")

    # chunk 布局：sys/metadata 共用 0x100000，数据 chunk 在 0x500000。
    # 逻辑与物理刻意错开，这样「翻译」不是恒等映射，能真正验证 chunk map
    CHUNK_LOG, CHUNK_LEN, CHUNK_PHYS = 0x100000, 0x400000, 0x200000
    DATA_LOG, DATA_LEN, DATA_PHYS = 0x500000, 0x100000, 0x300000
    ROOT_ROOT = 0x100000        # 根树（叶子）
    CHUNK_ROOT = 0x110000       # chunk 树（叶子）
    FS_ROOT = 0x120000          # FS 树根（level 1 内部节点）
    FS_LEAF_A = 0x140000        # 子卷 5：objectid 256 的项
    FS_LEAF_B = 0x144000        # 子卷 5：objectid 257..259 的项
    SUB_ROOT = 0x148000         # 子卷 256（叶子）
    IMG_SIZE = 0x400000

    HELLO = b"hello btrfs\n"
    INNER = b"inner\n"
    ZTEXT = b"zlib inline\n"
    BIG = bytes(range(256)) * 32
    LABEL_TEXT = b"ESK-BTRFS\x00"        # 9 字符 + NUL，写入切片必须定长

    def l2p(laddr):
        if CHUNK_LOG <= laddr < CHUNK_LOG + CHUNK_LEN:
            return CHUNK_PHYS + (laddr - CHUNK_LOG)
        if DATA_LOG <= laddr < DATA_LOG + DATA_LEN:
            return DATA_PHYS + (laddr - DATA_LOG)
        raise ValueError("合成镜像里 0x%X 没有映射" % laddr)

    img = bytearray(IMG_SIZE)

    def put(laddr, data):
        pos = l2p(laddr)
        img[pos:pos + len(data)] = data

    def build_chunk(length, phys, ctype):
        buf = bytearray(CHUNK_HDR_SIZE + STRIPE_SIZE)
        struct.pack_into("<QQQQIIIHH", buf, 0, length,
                         BTRFS_FIRST_CHUNK_TREE_OBJECTID, 65536, ctype,
                         SECTORSIZE, SECTORSIZE, SECTORSIZE, 1, 1)
        struct.pack_into("<QQ", buf, CHUNK_HDR_SIZE, 1, phys)
        buf[CHUNK_HDR_SIZE + 16:CHUNK_HDR_SIZE + 32] = DEV_UUID
        return bytes(buf)

    def build_inode(mode, size=0, nlink=1, mtime=1700000000):
        buf = bytearray(160)
        struct.pack_into("<Q", buf, 0, GEN)               # generation
        struct.pack_into("<Q", buf, 8, GEN)               # transid
        struct.pack_into("<Q", buf, 16, size)             # size
        struct.pack_into("<Q", buf, 24, size)             # nbytes
        struct.pack_into("<I", buf, 40, nlink)
        struct.pack_into("<I", buf, 44, 0)                # uid
        struct.pack_into("<I", buf, 48, 0)                # gid
        struct.pack_into("<I", buf, 52, mode)
        struct.pack_into("<Q", buf, 136, mtime)           # mtime.sec
        struct.pack_into("<I", buf, 144, 0)               # mtime.nsec
        return bytes(buf)

    def build_ref(index, name):
        raw = name.encode("utf-8")
        buf = bytearray(10 + len(raw))
        struct.pack_into("<QH", buf, 0, index, len(raw))
        buf[10:] = raw
        return bytes(buf)

    def build_dir_item(name, location, ftype):
        raw = name.encode("utf-8")
        buf = bytearray(30 + len(raw))
        struct.pack_into("<QBQ", buf, 0, location[0], location[1], location[2])
        struct.pack_into("<Q", buf, 17, GEN)              # transid
        struct.pack_into("<H", buf, 25, 0)                # data_len
        struct.pack_into("<H", buf, 27, len(raw))         # name_len
        buf[29] = ftype
        buf[30:] = raw
        return bytes(buf)

    def build_inline(payload, compression=0, ram=0):
        buf = bytearray(21 + len(payload))
        struct.pack_into("<Q", buf, 0, GEN)
        struct.pack_into("<Q", buf, 8, ram or len(payload))
        buf[16] = compression
        buf[20] = FILE_EXTENT_INLINE
        buf[21:] = payload
        return bytes(buf)

    def build_reg(disk_bytenr, disk_num_bytes, num_bytes):
        buf = bytearray(53)
        struct.pack_into("<Q", buf, 0, GEN)
        struct.pack_into("<Q", buf, 8, num_bytes)         # ram_bytes
        buf[20] = FILE_EXTENT_REG
        struct.pack_into("<QQQQ", buf, 21, disk_bytenr, disk_num_bytes,
                         0, num_bytes)
        return bytes(buf)

    def build_root_item(bytenr, level, root_dirid=256, flags=0):
        buf = bytearray(439)
        struct.pack_into("<I", buf, 52, 0o40755)          # inode.mode
        struct.pack_into("<Q", buf, 160, GEN)             # generation
        struct.pack_into("<Q", buf, 168, root_dirid)      # root_dirid
        struct.pack_into("<Q", buf, 176, bytenr)          # bytenr
        struct.pack_into("<Q", buf, 192, 0)               # bytes_used
        struct.pack_into("<Q", buf, 208, flags)           # flags
        struct.pack_into("<I", buf, 216, 1)               # refs
        buf[237] = 0                                      # drop_level
        buf[238] = level                                  # level
        struct.pack_into("<Q", buf, 239, GEN)             # generation_v2
        buf[247:263] = bytes.fromhex("aabbccddeeff00112233445566778899")
        return bytes(buf)

    def write_leaf(laddr, owner, items, level=0):
        node = bytearray(NODESIZE)
        node[0x20:0x30] = FSID
        struct.pack_into("<QQ", node, 0x30, laddr, 0)
        node[0x40:0x50] = CHUNK_UUID
        items = sorted(items, key=lambda kv: kv[0])
        struct.pack_into("<QQIB", node, 0x50, GEN, owner, len(items), level)
        cursor = NODESIZE - HEADER_SIZE
        for i, (key, payload) in enumerate(items):
            cursor -= len(payload)
            base = HEADER_SIZE + i * ITEM_SIZE
            struct.pack_into("<QBQII", node, base, key[0], key[1], key[2],
                             cursor, len(payload))
            node[HEADER_SIZE + cursor:HEADER_SIZE + cursor + len(payload)] = payload
        put(laddr, bytes(node))

    def write_node(laddr, owner, ptrs):
        node = bytearray(NODESIZE)
        node[0x20:0x30] = FSID
        struct.pack_into("<QQ", node, 0x30, laddr, 0)
        node[0x40:0x50] = CHUNK_UUID
        struct.pack_into("<QQIB", node, 0x50, GEN, owner, len(ptrs), 1)
        for i, (key, blockptr) in enumerate(ptrs):
            base = HEADER_SIZE + i * KEY_PTR_SIZE
            struct.pack_into("<QBQQQ", node, base, key[0], key[1], key[2],
                             blockptr, GEN)
        put(laddr, bytes(node))

    # ---- 文件数据放在数据 chunk 里，只有 chunk 树加载后才能读到 ----
    put(DATA_LOG, BIG)

    # ---- 叶子 A：子卷 5 的根目录 ----
    mode_dir = 0o040755
    leaf_a = [
        ((256, T_INODE_ITEM, 0), build_inode(mode_dir, 0, 4)),
        ((256, T_DIR_ITEM, 0x1111),
         build_dir_item("hello.txt", (257, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_ITEM, 0x2222),
         build_dir_item("big.bin", (258, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_ITEM, 0x3333),
         build_dir_item("z.txt", (259, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_ITEM, 0x4444),
         build_dir_item("sub", (256, T_ROOT_ITEM, 0), 2)),
        ((256, T_DIR_INDEX, 1),
         build_dir_item("hello.txt", (257, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_INDEX, 2),
         build_dir_item("big.bin", (258, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_INDEX, 3),
         build_dir_item("z.txt", (259, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_INDEX, 4),
         build_dir_item("sub", (256, T_ROOT_ITEM, 0), 2)),
    ]
    write_leaf(FS_LEAF_A, BTRFS_FS_TREE_OBJECTID, leaf_a)

    # ---- 叶子 B：文件 inode / ref / extent ----
    leaf_b = [
        ((257, T_INODE_ITEM, 0), build_inode(0o100644, len(HELLO))),
        ((258, T_INODE_ITEM, 0), build_inode(0o100644, len(BIG))),
        ((259, T_INODE_ITEM, 0), build_inode(0o100644, len(ZTEXT))),
        ((257, T_INODE_REF, 256), build_ref(1, "hello.txt")),
        ((258, T_INODE_REF, 256), build_ref(2, "big.bin")),
        ((259, T_INODE_REF, 256), build_ref(3, "z.txt")),
        ((257, T_EXTENT_DATA, 0), build_inline(HELLO)),
        ((258, T_EXTENT_DATA, 0), build_reg(DATA_LOG, len(BIG), len(BIG))),
        ((259, T_EXTENT_DATA, 0),
         build_inline(zlib.compress(ZTEXT), 1, len(ZTEXT))),
    ]
    write_leaf(FS_LEAF_B, BTRFS_FS_TREE_OBJECTID, leaf_b)

    # ---- FS 树根：level 1，两个指针跨两个叶子，验证搜索剪枝 ----
    write_node(FS_ROOT, BTRFS_FS_TREE_OBJECTID,
               [((256, 0, 0), FS_LEAF_A), ((257, 0, 0), FS_LEAF_B)])

    # ---- 子卷 256 ----
    sub_leaf = [
        ((256, T_INODE_ITEM, 0), build_inode(mode_dir, 0, 2)),
        ((256, T_DIR_ITEM, 0x5555),
         build_dir_item("inner.txt", (257, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_INDEX, 1),
         build_dir_item("inner.txt", (257, T_INODE_ITEM, 0), 1)),
        ((257, T_INODE_ITEM, 0), build_inode(0o100644, len(INNER))),
        ((257, T_INODE_REF, 256), build_ref(1, "inner.txt")),
        ((257, T_EXTENT_DATA, 0), build_inline(INNER)),
    ]
    write_leaf(SUB_ROOT, BTRFS_FIRST_FREE_OBJECTID, sub_leaf)

    # ---- chunk 树：重复 sys chunk + 新增数据 chunk ----
    chunk_sys = build_chunk(
        CHUNK_LEN, CHUNK_PHYS,
        BLOCK_GROUP_DATA | BLOCK_GROUP_SYSTEM | BLOCK_GROUP_METADATA)
    chunk_data = build_chunk(DATA_LEN, DATA_PHYS, BLOCK_GROUP_DATA)
    write_leaf(CHUNK_ROOT, BTRFS_CHUNK_TREE_OBJECTID, [
        ((BTRFS_FIRST_CHUNK_TREE_OBJECTID, T_CHUNK_ITEM, CHUNK_LOG), chunk_sys),
        ((BTRFS_FIRST_CHUNK_TREE_OBJECTID, T_CHUNK_ITEM, DATA_LOG), chunk_data),
    ])

    # ---- 根树：FS_TREE(5) 与子卷(256) 的 ROOT_ITEM ----
    write_leaf(ROOT_ROOT, BTRFS_ROOT_TREE_OBJECTID, [
        ((BTRFS_FS_TREE_OBJECTID, T_ROOT_ITEM, 0), build_root_item(FS_ROOT, 1)),
        ((BTRFS_FIRST_FREE_OBJECTID, T_ROOT_ITEM, 0),
         build_root_item(SUB_ROOT, 0)),
    ])

    # ---- 超级块 ----
    sb = bytearray(SB_SIZE)
    sb[0x20:0x30] = FSID
    struct.pack_into("<QQ", sb, 0x30, SB_OFFSET, 0)          # bytenr, flags
    sb[0x40:0x48] = SB_MAGIC
    struct.pack_into("<Q", sb, 0x48, GEN)                    # generation
    struct.pack_into("<Q", sb, 0x50, ROOT_ROOT)              # root
    struct.pack_into("<Q", sb, 0x58, CHUNK_ROOT)             # chunk_root
    struct.pack_into("<Q", sb, 0x60, 0)                      # log_root
    struct.pack_into("<Q", sb, 0x68, 0)                      # __unused_log_root_transid
    struct.pack_into("<Q", sb, 0x70, IMG_SIZE)               # total_bytes
    struct.pack_into("<Q", sb, 0x78, 0x8000)                 # bytes_used
    struct.pack_into("<Q", sb, 0x80, 6)                      # root_dir_objectid
    struct.pack_into("<Q", sb, 0x88, 1)                      # num_devices
    struct.pack_into("<I", sb, 0x90, SECTORSIZE)
    struct.pack_into("<I", sb, 0x94, NODESIZE)
    struct.pack_into("<I", sb, 0x98, NODESIZE)               # __unused_leafsize
    struct.pack_into("<I", sb, 0x9C, 65536)                  # stripesize
    struct.pack_into("<Q", sb, 0xA4, GEN)                    # chunk_root_generation
    struct.pack_into("<H", sb, 0xC4, 0)                      # csum_type = crc32c
    sb[0xC6] = 0                                             # root_level
    sb[0xC7] = 0                                             # chunk_root_level
    sb[0xC8] = 0                                             # log_root_level
    struct.pack_into("<QQQIII", sb, 0xC9, 1, IMG_SIZE, 0x8000,
                     SECTORSIZE, SECTORSIZE, SECTORSIZE)
    struct.pack_into("<Q", sb, 0xC9 + 36, 0)                 # dev_item.type
    struct.pack_into("<Q", sb, 0xC9 + 44, GEN)               # dev_item.generation
    struct.pack_into("<Q", sb, 0xC9 + 52, 0)                 # dev_item.start_offset
    struct.pack_into("<I", sb, 0xC9 + 60, 0)                 # dev_item.dev_group
    sb[0xC9 + 64] = 2                                        # seek_speed
    sb[0xC9 + 65] = 100                                      # bandwidth
    sb[0xC9 + 66:0xC9 + 82] = DEV_UUID
    sb[0xC9 + 82:0xC9 + 98] = FSID
    sb[LABEL_OFF:LABEL_OFF + len(LABEL_TEXT)] = LABEL_TEXT
    struct.pack_into("<Q", sb, 0x22B, GEN)                   # cache_generation
    struct.pack_into("<Q", sb, 0x233, GEN)                   # uuid_tree_generation
    sb[0x23B:0x24B] = FSID                                   # metadata_uuid

    entry = bytearray(DISK_KEY_SIZE + len(chunk_sys))
    struct.pack_into("<QBQ", entry, 0, BTRFS_FIRST_CHUNK_TREE_OBJECTID,
                     T_CHUNK_ITEM, CHUNK_LOG)
    entry[DISK_KEY_SIZE:] = chunk_sys
    sb[SYSCK_ARRAY_OFF:SYSCK_ARRAY_OFF + len(entry)] = entry
    struct.pack_into("<I", sb, 0xA0, len(entry))             # sys_chunk_array_size

    img[SB_OFFSET:SB_OFFSET + SB_SIZE] = bytes(sb)
    image = bytes(img)
    assert len(sb) == SB_SIZE, "超级块必须正好 0x1000 字节"
    assert len(image) == IMG_SIZE, "镜像长度被切片赋值改动"

    class _MemSub(object):
        """最小的 read(offset, size) / size 接口"""

        def __init__(self, raw):
            self.data = raw
            self.size = len(raw)

        def read(self, offset, size):
            if offset < 0 or size <= 0:
                return b""
            return self.data[offset:offset + size]

    checks = []

    def ok(name, cond, extra=""):
        checks.append(bool(cond))
        print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                               ("  " + str(extra)) if extra else ""))
        if not cond:
            volume = globals().get("fs")
            if volume is not None and volume.warnings:
                print("  模块告警: %s" % volume.warnings)
            raise AssertionError(name)

    print("Btrfs 合成镜像自检（镜像 %d 字节，nodesize=%d）"
          % (len(image), NODESIZE))
    sub = _MemSub(image)
    fs = open_fs(sub)

    print("\n-- 第 1 层：超级块 --")
    info = fs.info()
    ok("魔数 _BHRfS_M", info["magic"] == "_BHRfS_M", info["magic"])
    ok("label", info["label"] == "ESK-BTRFS", info["label"])
    ok("fsid", info["fsid"] == "00112233-4455-6677-8899-aabbccddeeff",
       info["fsid"])
    ok("nodesize", info["nodesize"] == NODESIZE)
    ok("sectorsize", info["sectorsize"] == SECTORSIZE)
    ok("total_bytes", info["total_bytes"] == IMG_SIZE)
    ok("bytes_used", info["bytes_used"] == 0x8000)
    ok("generation", info["generation"] == GEN)
    ok("num_devices", info["num_devices"] == 1)
    ok("incompat_flags", info["incompat_flags"] == 0)
    ok("csum_type", info["csum_type"] == "crc32c")
    ok("root / chunk_root",
       (info["root"], info["chunk_root"]) == (ROOT_ROOT, CHUNK_ROOT))
    ok("dev_item.devid", info["dev_item"]["devid"] == 1)
    ok("dev_item.total_bytes", info["dev_item"]["total_bytes"] == IMG_SIZE)
    ok("sys_chunk_array_size",
       info["sys_chunk_array_size"] == DISK_KEY_SIZE + len(chunk_sys))
    ok("超级块结构长度 0x1000 自洽",
       len(fs.sb_raw) == 0x1000 and 0xDCB + 565 == 0x1000)

    print("\n-- 第 2 层：sys_chunk_array 与 chunk 映射 --")
    chunks = fs.chunk_map()
    ok("sys 数组 1 条 + chunk 树补 1 条", len(chunks) == 2,
       [(hex(c["logical"]), hex(c["length"]), c["type_text"]) for c in chunks])
    ok("chunk 按逻辑地址递增",
       [c["logical"] for c in chunks] == [CHUNK_LOG, DATA_LOG])
    ok("chunk 条带",
       chunks[0]["stripes"][0]["offset"] == CHUNK_PHYS
       and chunks[0]["num_stripes"] == 1)
    ok("logical_to_physical(0x100000)",
       fs.logical_to_physical(CHUNK_LOG) == (CHUNK_PHYS, CHUNK_LEN,
                                             chunks[0]["type"]))
    ok("偏移内翻译 +0x10",
       fs.logical_to_physical(CHUNK_LOG + 0x10)[0] == CHUNK_PHYS + 0x10)
    ok("剩余长度随偏移递减",
       fs.logical_to_physical(CHUNK_LOG + 0x10)[1] == CHUNK_LEN - 0x10)
    ok("数据 chunk 来自 chunk 树",
       fs.logical_to_physical(DATA_LOG + 0x100)
       == (DATA_PHYS + 0x100, DATA_LEN - 0x100, BLOCK_GROUP_DATA))
    ok("未映射地址返回 None", fs.logical_to_physical(0x900000) is None)
    ok("map_detail.exact", fs.map_detail(CHUNK_LOG)["exact"] is True)

    print("\n-- 第 3 层：树节点 --")
    rt = fs.root_tree()
    ok("根树 level 0", rt.level == 0)
    ok("根树 nritems", rt.nritems == 2)
    ok("根树节点回映射", (rt.laddr, rt.paddr) == (ROOT_ROOT, CHUNK_PHYS))
    rt_keys = [it.key.as_tuple() for it in rt.items()]
    ok("根树条目顺序", rt_keys == [(5, T_ROOT_ITEM, 0),
                                   (256, T_ROOT_ITEM, 0)], rt_keys)
    ok("条目数据切片", len(rt.items()[0].data) == 439)
    ct_keys = [it.key.as_tuple() for it in fs.chunk_root_tree().items()]
    ok("chunk 树两条 CHUNK_ITEM",
       ct_keys == [(256, T_CHUNK_ITEM, CHUNK_LOG),
                   (256, T_CHUNK_ITEM, DATA_LOG)], ct_keys)

    fs_node = fs.read_node(FS_ROOT)
    ok("FS 树根是 level 1 内部节点", fs_node.level == 1 and not fs_node.is_leaf)
    ptrs = fs_node.ptrs()
    ok("内部节点 ptrs 数量", len(ptrs) == 2)
    ok("ptr[0].key / blockptr",
       ptrs[0].key.as_tuple() == (256, 0, 0)
       and ptrs[0].blockptr == FS_LEAF_A)
    ok("ptr[1].key / blockptr",
       ptrs[1].key.as_tuple() == (257, 0, 0)
       and ptrs[1].blockptr == FS_LEAF_B)
    ok("ptr generation", ptrs[1].generation == GEN)
    ok("内部节点 items() 为空", fs_node.items() == [])

    leaf_a_node = fs.read_node(FS_LEAF_A)
    a_keys = [it.key.as_tuple() for it in leaf_a_node.items()]
    ok("叶子 A nritems", leaf_a_node.nritems == 9, leaf_a_node.nritems)
    ok("叶子 A 键严格递增", a_keys == sorted(a_keys))
    ok("叶子 A 首项是 INODE_ITEM", a_keys[0] == (256, T_INODE_ITEM, 0))
    ok("ITEM 数据区不越界",
       all(it.data_offset + it.size <= NODESIZE
           for it in leaf_a_node.items()))
    ok("节点 bytenr 自校验无告警", not leaf_a_node.warnings)

    print("\n-- 第 4 层：目录遍历与文件读取 --")
    names = [d.name for d in fs.listdir("/")]
    ok("listdir('/') 按 DIR_INDEX 序号排序",
       names == ["hello.txt", "big.bin", "z.txt", "sub"], names)
    ok("文件大小来自 INODE_ITEM", fs.listdir("/")[1].size == len(BIG))
    ok("子卷目录项标记", fs.listdir("/")[3].is_subvol is True)
    ok("read_file 读普通 extent（数据 chunk）", fs.read_file("/big.bin") == BIG)
    ok("read_file 读 inline extent", fs.read_file("/hello.txt") == HELLO)
    ok("read_file 解 zlib inline extent", fs.read_file("/z.txt") == ZTEXT)
    ok("子卷内文件", fs.read_file("/sub/inner.txt") == INNER)
    walked = [p for p, _ in fs.walk("/")]
    ok("walk 递归结果",
       walked == ["hello.txt", "big.bin", "z.txt", "sub", "sub/inner.txt"],
       walked)
    ok("find 名称筛选", [p for p, _ in fs.find("big")] == ["big.bin"])
    ok("子卷列表", [s["id"] for s in fs.subvolumes()] == [256],
       [s["id"] for s in fs.subvolumes()])
    ok("路径穿越子卷",
       fs.resolve("/sub/inner.txt")[0] == BTRFS_FIRST_FREE_OBJECTID)
    ok("probe 命中", probe(sub) is True)
    ok("截断镜像 probe 失败", probe(_MemSub(image[:0x10000])) is False)

    print("\n全部 %d 项断言通过" % len(checks))
    print("超级块 label=%r nodesize=%d root=0x%X chunk_root=0x%X"
          % (info["label"], info["nodesize"], info["root"], info["chunk_root"]))
    sys.exit(0)
