# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""Btrfs 文件系统（只读，含校验和与多设备 RAID）

格式依据 Linux 内核源码逐项核对后实现，全部纯标准库：
    include/uapi/linux/btrfs_tree.h   on-disk 结构、key 类型、incompat 位
    include/uapi/linux/btrfs.h        特性标志位、csum 类型
    fs/btrfs/disk-io.c                csum_tree_block（校验和覆盖范围）
    fs/btrfs/volumes.c                btrfs_map_block（RAID0/1/10/5/6 条带公式）
    fs/btrfs/lzo.c                    LZO extent 封帧
    lib/lzo/lzo1x_decompress_safe.c   LZO1X 解码器（逐分支移植）
    lib/lzo/lzodefs.h                 M2_MAX_OFFSET / MIN_ZERO_RUN_LENGTH 等常数

只依赖可读对象 sub.read(offset, size) / sub.size，零第三方依赖。

已实现：
    · 超级块（0x10000，魔数 _BHRfS_M）全字段解析，主副本缺失回退 64M/256G/1T
    · sys_chunk_array 解析（17 字节 disk_key 与 btrfs_chunk 交替，无对齐填充）
    · chunk 树加载与合并：sys 数组只覆盖 system/metadata，数据 chunk 靠 chunk 树补齐
    · **校验和**：crc32c（表驱动，非 zlib 的 crc32）/ xxhash64 / sha256 / blake2b-256
      —— 元数据校验和覆盖 node[0x20:]；数据校验和来自 csum 树（objectid = -10）
    · **校验和验证**：read_node() 默认校验，不符记告警并尝试其它副本；
      verify_extent() / verify_node() 显式校验，strict 模式直接抛异常
    · **多设备**：devices={devid: sub}，按 chunk 条带把逻辑地址分发到各设备
    · **副本策略**：SINGLE/DUP/RAID1/RAID1C3/RAID1C4 逐个副本重试（镜像 0..n-1），
      校验和不过或短读才换下一个副本，取证上等价于手工换镜像
    · **RAID0 / RAID10 / RAID5 / RAID6 条带映射**：按 volumes.c 的 map_blocks_* 公式
    · **RAID5/6 数据重建**：整行 XOR 恢复缺失条带（P），RAID6 的 Q 用 Reed-Solomon
      仅支持"丢失单个数据条带"的情形，多盘缺失明确拒绝
    · 树节点读取：btrfs_header / btrfs_item / btrfs_key_ptr，按 key 区间剪枝检索
    · 根树 → ROOT_ITEM → 子卷切换（5 = FS_TREE，≥256 为子卷）
    · 目录遍历：INODE_ITEM / INODE_REF / DIR_ITEM / DIR_INDEX（含哈希碰撞多条记录）
    · 文件读取：INLINE / REG / PREALLOC extent，空洞补零，跨 chunk 拼接
    · **压缩**：zlib / LZO1X（btrfs 封帧，纯 Python 移植解码器）/ LZ4 块 /
      zstd（ctypes 调本机 libzstd，找不到库时明确报错）
    · 按路径查找、递归 walk、名称子串筛选、子卷枚举

不实现：
    · 写操作、fsck、log 树回放、scrub
    · **RAID6 的 Q 校验恢复**：只有 P 参与 XOR 重建；Q（RS）需要 GF(2^8) 矩阵运算，
      本模块只做到"单条带丢失 + P 可用"的程度，多盘缺失或 P 缺失直接抛异常
    · **RAID5/6 条带内的部分对齐读取**：只按整条带（stripe_len 对齐）重建
    · zstd 若本机无 libzstd：抛 NotImplementedError，不做纯 Python FSE/Huffman 解码
    · 加密 extent（encryption != 0）
    · 已删除文件恢复：Btrfs 删除 inode 后 DIR_ITEM 直接消失、不留墓碑，
      与 FAT/NTFS 完全不同，只能靠 extent 雕刻，不属本模块职责
    · extent tree / free space tree / qgroup 语义解析（只读 chunk 树与 csum 树）
    · 跨设备 dev-replace / seed 设备 / 条带树（raid-stripe-tree）新布局

偏移核对（对 btrfs_tree.h 的 packed 结构重算，与需求里给的表逐项比对）：
    · 你列的 32 个超级块偏移全部正确；
      仅 @0x40 的 magic 官方类型是 __le64（不是 u8[8]），值同为 8 字节
    · 名称修正：
      @0x68 官方名 __unused_log_root_transid，内核注释「自诞生起从未使用、恒为 0，
            读 log 树用 generation + 1」，log_root_transid 只是历史叫法
      @0x98 官方名 __unused_leafsize，2.6 后即废弃，唯一权威是 @0x94 nodesize
    · 你表里缺、本实现已补：nr_global_roots@0x24B、remap_root@0x253、
      remap_root_generation@0x25B、remap_root_level@0x263、reserved[199]@0x264、
      super_roots[4]@0xB2B（每个 168B）、padding[565]@0xDCB —— 合计正好 0x1000
    · btrfs_header 合计 101 = 0x65；item.offset 以「leaf 数据区起点 0x65」为基准
    · btrfs_item 25、btrfs_key_ptr 33、btrfs_dev_item 98、
      btrfs_chunk 头 48 + 每条带 32（num_stripes=1 时 80）
    · btrfs_root_item：inode(160)+generation@160+root_dirid@168+bytenr@176
      +refs@216+drop_level@237+level@238+generation_v2@239，legacy 239 / 当前 439

自检：`python mkit/btrfs.py` 构造合成镜像（超级块 + DUP 双副本 chunk +
两级树 + 子卷 + inline/普通/zlib intent），并验证校验和、副本切换、
RAID 条带公式、LZO/LZ4 解码与已知测试向量。
"""

import bisect
import ctypes
import ctypes.util
import struct
import time
import zlib

__all__ = [
    "Btrfs", "Node", "Item", "KeyPtr", "BtrfsKey", "BtrfsDirent",
    "probe", "open_fs",
    "crc32c", "xxhash64", "csum_data", "csum_size",
    "lzo1x_decompress", "lz4_block_decompress", "zstd_available",
    "SB_OFFSET", "SB_MAGIC", "SB_MIRRORS", "KEY_TYPES", "INCOMPAT_FLAGS",
    "COMPRESS_NAMES", "CSUM_NAMES",
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
ROOT_ITEM_LEGACY = 239

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
BTRFS_CSUM_TREE_OBJECTID = 7
BTRFS_UUID_TREE_OBJECTID = 9
BTRFS_FREE_SPACE_TREE_OBJECTID = 10
BTRFS_FIRST_FREE_OBJECTID = 256
BTRFS_FIRST_CHUNK_TREE_OBJECTID = 256
BTRFS_EXTENT_CSUM_OBJECTID = U64_MAX - 9      # -10ULL

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
RAID56_MASK = BLOCK_GROUP_RAID5 | BLOCK_GROUP_RAID6
MIRROR_MASK = (BLOCK_GROUP_DUP | BLOCK_GROUP_RAID1
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
CSUM_SIZES = {0: 4, 1: 8, 2: 32, 3: 32}

COMPRESS_NAMES = {0: "none", 1: "zlib", 2: "lzo", 3: "zstd", 4: "lz4"}

FT_NAMES = {
    0: "unknown", 1: "reg", 2: "dir", 3: "chr", 4: "blk",
    5: "fifo", 6: "sock", 7: "symlink", 8: "xattr",
}

FILE_EXTENT_INLINE = 0
FILE_EXTENT_REG = 1
FILE_EXTENT_PREALLOC = 2

# LZO1X 常数（lib/lzo/lzodefs.h）
M2_MAX_OFFSET = 0x0800
MIN_ZERO_RUN_LENGTH = 4
MAX_255_COUNT = (U64_MAX // 255) - 2


# ---------------- 校验和 ----------------

def _make_crc32c_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
        table.append(crc)
    return tuple(table)


_CRC32C_TABLE = _make_crc32c_table()


def crc32c(data, crc=0):
    """CRC-32C（Castagnoli，多项式 0x1EDC6F41 反射形式 0x82F63B78）

    标准 init=0xFFFFFFFF / xorout=0xFFFFFFFF，故 crc32c(b"123456789") == 0xE3069283。
    btrfs 的元数据与数据校验和都用它；注意它和 zlib.crc32（IEEE）不是一个东西。
    """
    crc ^= 0xFFFFFFFF
    table = _CRC32C_TABLE
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFFFFFF


_P1 = 0x9E3779B185EBCA87
_P2 = 0xC2B2AE3D27D4EB4F
_P3 = 0x165667B19E3779F9
_P4 = 0x85EBCA77C2B2AE63
_P5 = 0x27D4EB2F165667C5
_M64 = (1 << 64) - 1


def _rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & _M64


def _xxh_round(acc, lane):
    acc = (acc + lane * _P2) & _M64
    acc = _rotl64(acc, 31)
    return (acc * _P1) & _M64


def _xxh_merge(acc, val):
    val = _xxh_round(0, val)
    acc ^= val
    return (acc * _P1 + _P4) & _M64


def xxhash64(data, seed=0):
    """XXH64（xxHash 规范），btrfs csum_type=1 使用"""
    n = len(data)
    pos = 0
    if n >= 32:
        v1 = (seed + _P1 + _P2) & _M64
        v2 = (seed + _P2) & _M64
        v3 = seed & _M64
        v4 = (seed - _P1) & _M64
        limit = n - 32
        while pos <= limit:
            v1 = _xxh_round(v1, struct.unpack_from("<Q", data, pos)[0])
            v2 = _xxh_round(v2, struct.unpack_from("<Q", data, pos + 8)[0])
            v3 = _xxh_round(v3, struct.unpack_from("<Q", data, pos + 16)[0])
            v4 = _xxh_round(v4, struct.unpack_from("<Q", data, pos + 24)[0])
            pos += 32
        h = (_rotl64(v1, 1) + _rotl64(v2, 7)
             + _rotl64(v3, 12) + _rotl64(v4, 18)) & _M64
        h = _xxh_merge(h, v1)
        h = _xxh_merge(h, v2)
        h = _xxh_merge(h, v3)
        h = _xxh_merge(h, v4)
    else:
        h = (seed + _P5) & _M64
    h = (h + n) & _M64
    while pos + 8 <= n:
        k = _xxh_round(0, struct.unpack_from("<Q", data, pos)[0])
        h ^= k
        h = (_rotl64(h, 27) * _P1 + _P4) & _M64
        pos += 8
    if pos + 4 <= n:
        h ^= (struct.unpack_from("<I", data, pos)[0] * _P1) & _M64
        h = (_rotl64(h, 23) * _P2 + _P3) & _M64
        pos += 4
    while pos < n:
        h ^= (data[pos] * _P5) & _M64
        h = (_rotl64(h, 11) * _P1) & _M64
        pos += 1
    h ^= h >> 33
    h = (h * _P2) & _M64
    h ^= h >> 29
    h = (h * _P3) & _M64
    h ^= h >> 32
    return h


def csum_size(csum_type):
    """每种校验和占用的字节数"""
    return CSUM_SIZES.get(csum_type, 0)


def csum_data(data, csum_type=0):
    """按 btrfs csum_type 计算校验和，返回定长 bytes（与磁盘上的 csum 字段等长）"""
    if csum_type == 0:
        return struct.pack("<I", crc32c(data))
    if csum_type == 1:
        return struct.pack("<Q", xxhash64(data))
    if csum_type == 2:
        import hashlib
        return hashlib.sha256(data).digest()
    if csum_type == 3:
        import hashlib
        return hashlib.blake2b(data, digest_size=32).digest()
    raise NotImplementedError("未知 csum_type=%d" % csum_type)


# ---------------- 压缩 ----------------

def lzo1x_decompress(src, dst_len=0):
    """LZO1X 解压，按 lib/lzo/lzo1x_decompress_safe.c 逐分支移植

    dst_len > 0 时作为输出上限（对应内核的 out_len 缓冲上界）。
    """
    n = len(src)
    if n < 3:
        raise ValueError("lzo1x: 输入不足 3 字节")
    limit = dst_len if dst_len > 0 else (1 << 26)
    out = bytearray()
    ip = 0
    state = 0
    bitstream_version = 0

    def need_ip(k):
        if ip + k > n:
            raise ValueError("lzo1x: input overrun")

    def need_op(k):
        if len(out) + k > limit:
            raise ValueError("lzo1x: output overrun")

    def copy_literals(count):
        nonlocal ip
        need_ip(count)
        need_op(count)
        out.extend(src[ip:ip + count])
        ip += count

    def long_length(t, base):
        """处理 255 连续计数扩展，返回新的 t"""
        nonlocal ip
        ip_last = ip
        while ip < n and src[ip] == 0:
            ip += 1
            need_ip(1)
        offset = ip - ip_last
        if offset > MAX_255_COUNT:
            raise ValueError("lzo1x: 长度溢出")
        offset = (offset << 8) - offset
        need_ip(1)
        t += offset + base + src[ip]
        ip += 1
        return t

    if n >= 5 and src[0] == 17:
        bitstream_version = src[1]
        ip = 2
    else:
        bitstream_version = 0

    if src[ip] > 17:
        t = src[ip] - 17
        ip += 1
        if t < 4:
            state = t
            need_ip(t + 3)
            copy_literals(t)
        else:
            need_op(t)
            need_ip(t + 3)
            # 与内核一致：允许 t 字节字面量，随后进入主循环
            out.extend(src[ip:ip + t])
            ip += t
            state = 4

    next_count = 0
    while True:
        need_ip(1)
        t = src[ip]
        ip += 1
        m_pos = 0
        if t < 16:
            if state == 0:
                if t == 0:
                    t = long_length(t, 15)
                t += 3
                need_op(t)
                need_ip(t)
                copy_literals(t)
                state = 4
                continue
            if state != 4:
                next_count = t & 3
                need_ip(1)
                m_pos = len(out) - 1 - (t >> 2) - (src[ip] << 2)
                ip += 1
                if m_pos < 0:
                    raise ValueError("lzo1x: lookbehind overrun")
                need_op(2)
                out.append(out[m_pos])
                out.append(out[m_pos + 1])
                need_ip(next_count)
                copy_literals(next_count)
                state = next_count
                continue
            next_count = t & 3
            need_ip(1)
            m_pos = len(out) - (1 + M2_MAX_OFFSET) - (t >> 2) - (src[ip] << 2)
            ip += 1
            t = 3
        elif t >= 64:
            next_count = t & 3
            need_ip(1)
            m_pos = len(out) - 1 - ((t >> 2) & 7) - (src[ip] << 3)
            ip += 1
            t = (t >> 5) + 1
        elif t >= 32:
            t = (t & 31) + 2
            if t == 2:
                t = long_length(t, 31)
            need_ip(2)
            m_pos = len(out) - 1
            next_count = src[ip] | (src[ip + 1] << 8)
            ip += 2
            m_pos -= next_count >> 2
            next_count &= 3
        else:
            need_ip(2)
            next_count = src[ip] | (src[ip + 1] << 8)
            if (next_count & 0xFFFC) == 0xFFFC and (t & 0xF8) == 0x18 \
                    and bitstream_version:
                need_ip(3)
                t &= 7
                t |= src[ip + 2] << 3
                t += MIN_ZERO_RUN_LENGTH
                need_op(t)
                out.extend(b"\x00" * t)
                next_count &= 3
                ip += 3
                need_ip(next_count)
                copy_literals(next_count)
                state = next_count
                continue
            m_pos = len(out) - ((t & 8) << 11)
            t = (t & 7) + 2
            if t == 2:
                t = long_length(t, 7)
                need_ip(2)
                next_count = src[ip] | (src[ip + 1] << 8)
            ip += 2
            m_pos -= next_count >> 2
            next_count &= 3
            if m_pos == len(out):
                return bytes(out)          # eof
            m_pos -= 0x4000
        if m_pos < 0:
            raise ValueError("lzo1x: lookbehind overrun %d" % m_pos)
        need_op(t)
        if m_pos + t <= len(out):
            out.extend(out[m_pos:m_pos + t])
        else:
            for i in range(t):
                out.append(out[m_pos + i])
        need_ip(next_count)
        copy_literals(next_count)
        state = next_count


def lzo_decompress(raw, ram_bytes=0):
    """btrfs LZO extent：每段 [u32 LE 段总长][u32 LE 压缩长][lzo 数据]"""
    out = bytearray()
    pos = 0
    total = len(raw)
    while pos + 8 <= total:
        seg_total, seg_len = struct.unpack_from("<II", raw, pos)
        if seg_total < 8 or pos + seg_total > total:
            raise ValueError("lzo extent 段头异常：seg_total=%d pos=%d" % (seg_total, pos))
        if seg_len > seg_total - 8:
            raise ValueError("lzo extent 段长异常：seg_len=%d total=%d"
                             % (seg_len, seg_total))
        chunk = raw[pos + 8:pos + 8 + seg_len]
        out += lzo1x_decompress(chunk, seg_len * 16 + 64)
        pos += seg_total
        if ram_bytes and len(out) >= ram_bytes:
            break
    if ram_bytes:
        if len(out) < ram_bytes:
            raise ValueError("lzo extent 输出不足：%d < %d" % (len(out), ram_bytes))
        return bytes(out[:ram_bytes])
    return bytes(out)


def lz4_block_decompress(src, dst_len):
    """LZ4 块解压（标准 LZ4 block 格式），dst_len 为期望输出长度"""
    out = bytearray()
    ip = 0
    n = len(src)
    while ip < n:
        token = src[ip]
        ip += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                if ip >= n:
                    raise ValueError("lz4: 字面量长度越界")
                b = src[ip]
                ip += 1
                lit_len += b
                if b != 255:
                    break
        if lit_len:
            if ip + lit_len > n:
                raise ValueError("lz4: 字面量越界")
            out += src[ip:ip + lit_len]
            ip += lit_len
        if ip >= n:
            break
        if ip + 2 > n:
            raise ValueError("lz4: 缺少匹配偏移")
        offset = src[ip] | (src[ip + 1] << 8)
        ip += 2
        if offset == 0 or offset > len(out):
            raise ValueError("lz4: 匹配偏移非法 %d" % offset)
        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if ip >= n:
                    raise ValueError("lz4: 匹配长度越界")
                b = src[ip]
                ip += 1
                match_len += b
                if b != 255:
                    break
        match_len += 4
        start = len(out) - offset
        if start + match_len <= len(out):
            out += out[start:start + match_len]
        else:
            for i in range(match_len):
                out.append(out[start + i])
    if dst_len and len(out) != dst_len:
        raise ValueError("lz4: 输出长度 %d != %d" % (len(out), dst_len))
    return bytes(out)


_ZSTD_LIB = None
_ZSTD_TRIED = False


def _zstd_lib():
    """尝试加载本机 libzstd（找不到返回 None，绝不静默降级）"""
    global _ZSTD_LIB, _ZSTD_TRIED
    if _ZSTD_TRIED:
        return _ZSTD_LIB
    _ZSTD_TRIED = True
    for name in ("libzstd.dll", "zstd.dll", "libzstd.so.1", "libzstd.so",
                 "libzstd.dylib"):
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        try:
            lib.ZSTD_decompress.restype = ctypes.c_size_t
            lib.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                            ctypes.c_void_p, ctypes.c_size_t]
            lib.ZSTD_isError.restype = ctypes.c_uint
            lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
            lib.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
            lib.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        except AttributeError:
            continue
        _ZSTD_LIB = lib
        break
    return _ZSTD_LIB


def zstd_available():
    """本机是否可解 zstd"""
    return _zstd_lib() is not None


def zstd_decompress(raw, dst_len=0):
    """zstd 解压：走本机 libzstd；没有库就明确报错，不做静默降级"""
    lib = _zstd_lib()
    if lib is None:
        raise NotImplementedError(
            "zstd 需要本机 libzstd（未找到 libzstd.dll/.so）；"
            "标准库不做 FSE/Huffman 解码")
    size = dst_len
    if not size:
        size = int(lib.ZSTD_getFrameContentSize(raw, len(raw)))
        if size >= (1 << 63):
            raise ValueError("zstd: 帧未声明内容大小，需显式给 dst_len")
    buf = ctypes.create_string_buffer(size)
    got = lib.ZSTD_decompress(buf, size, raw, len(raw))
    if lib.ZSTD_isError(got):
        raise ValueError("zstd 解压失败（错误码 %d）" % got)
    return buf.raw[:got]


def decompress(ctype, raw, ram_bytes=0):
    """按 btrfs compression 字段解压"""
    if not ctype:
        return raw
    if ctype == 1:
        try:
            out = zlib.decompress(raw)
        except zlib.error:
            try:
                out = zlib.decompress(raw, -15)
            except zlib.error as exc:
                raise ValueError("zlib 解压失败: %s" % exc)
        return out[:ram_bytes] if ram_bytes else out
    if ctype == 2:
        return lzo_decompress(raw, ram_bytes)
    if ctype == 3:
        return zstd_decompress(raw, ram_bytes)
    if ctype == 4:
        return lz4_block_decompress(raw, ram_bytes)
    raise NotImplementedError(
        "未知压缩类型 %d（btrfs 只定义 0..4）" % ctype)


# ---------------- 小工具 ----------------

def _uuid(raw):
    """16 字节 UUID -> 标准 36 字符形式"""
    if not raw or len(raw) < 16:
        return ""
    h = raw[:16].hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def _flag_names(value, table):
    return [name for bit, name in table if value & bit]


def _block_group_text(ctype):
    names = [name for bit, name in BLOCK_GROUP_FLAGS if ctype & bit]
    return "|".join(names) if names else "-"


def _ts(sec, nsec=0):
    if not sec:
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(sec))
    except (OSError, ValueError, OverflowError):
        return None


def _disk_key(buf, off):
    objectid, typ, offset = struct.unpack_from("<QBQ", buf, off)
    return BtrfsKey(objectid, typ, offset)


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _mode_name(mode):
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


# ---------------- 结构体 ----------------

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
        return HEADER_SIZE + self.offset

    @property
    def data(self):
        start = HEADER_SIZE + self.offset
        return self._buf[start:start + self.size]

    def __repr__(self):
        return "<Item %r %dB>" % (self.key, self.size)


class KeyPtr(object):
    """内部节点指针"""

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

    __slots__ = ("fs", "laddr", "paddr", "devid", "data", "csum", "fsid",
                 "bytenr", "flags", "chunk_tree_uuid", "generation", "owner",
                 "nritems", "level", "warnings", "csum_ok", "mirror")

    def __init__(self, fs, laddr, data, paddr=0, devid=0, mirror=1):
        if len(data) < HEADER_SIZE:
            raise ValueError("节点数据不足一个 btrfs_header（0x%X）" % len(data))
        self.fs = fs
        self.laddr = laddr
        self.paddr = paddr
        self.devid = devid
        self.mirror = mirror
        self.data = data
        self.csum = data[0x00:0x20]
        self.fsid = data[0x20:0x30]
        self.bytenr, self.flags = struct.unpack_from("<QQ", data, 0x30)
        self.chunk_tree_uuid = data[0x40:0x50]
        (self.generation, self.owner,
         self.nritems, self.level) = struct.unpack_from("<QQIB", data, 0x50)
        self.warnings = []
        self.csum_ok = None
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
        return ("<Node 0x%X dev=%d paddr=0x%X level=%d nritems=%d owner=%d "
                "csum=%s>" % (self.laddr, self.devid, self.paddr, self.level,
                              self.nritems, self.owner,
                              {True: "ok", False: "BAD", None: "-"}[self.csum_ok]))


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
    """Btrfs 文件系统（只读）

    devices 用于多设备卷：{devid: 可读对象}。只给主设备时，其它 devid 的条带
    会记录告警并跳过（单盘镜像的常见情形）。
    """

    def __init__(self, sub, sb_offset=None, devices=None, verify=True):
        self.sub = sub
        self.devices = {1: sub}
        if devices:
            self.devices.update(devices)
        self.verify = verify
        self.warnings = []
        self.sb_offset = sb_offset if sb_offset is not None else self._locate_sb()
        self._read_super()
        self._chunks = []
        self._chunks_ready = False
        self._chunk_lock = False
        self._nodes = {}
        self._roots = None
        self._csums = {}
        self._parse_sys_chunk_array()

    # ---------------- 超级块 ----------------
    def _locate_sb(self):
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
        if self.csum_type not in CSUM_SIZES:
            self.warnings.append("未知 csum_type=%d，跳过校验" % self.csum_type)
            self.verify = False
        if not self.root:
            raise ValueError("超级块 root 为 0，无根树")

    def _parse_dev_item(self, raw):
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
            "csum_size": csum_size(self.csum_type),
            "compat_flags": self.compat_flags,
            "compat_ro_flags": self.compat_ro_flags,
            "incompat_flags": self.incompat_flags,
            "incompat_features": _flag_names(self.incompat_flags, INCOMPAT_FLAGS),
            "compat_ro_features": _flag_names(self.compat_ro_flags,
                                              COMPAT_RO_FLAGS),
            "cache_generation": self.cache_generation,
            "uuid_tree_generation": self.uuid_tree_generation,
            "nr_global_roots": self.nr_global_roots,
            "devices": sorted(self.devices),
            "dev_item": self.dev_item,
            "warnings": list(self.warnings),
        }

    # ---------------- chunk ----------------
    def _parse_chunk(self, buf, off, logical, source):
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
            self.warnings.append("chunk@0x%X 条带越界（需 0x%X，有 0x%X）"
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
                    "sys_chunk_array 里 type=%d 不是 CHUNK_ITEM，停止解析" % key.type)
                break
            chunk = self._parse_chunk(raw, pos, key.offset, "sys_chunk_array")
            if chunk is None:
                break
            chunk["objectid"] = key.objectid
            self._chunks.append(chunk)
            pos += chunk["size"]
        self._chunks.sort(key=lambda c: c["logical"])

    def _merge_chunk(self, chunk):
        for cur in self._chunks:
            if cur["logical"] == chunk["logical"]:
                return
        self._chunks.append(chunk)
        self._chunks.sort(key=lambda c: c["logical"])

    def _ensure_chunks(self):
        """从 chunk 树补全数据 chunk；chunk 树本身只用 sys 数组地址读"""
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
        self._ensure_chunks()
        return [dict(c) for c in self._chunks]

    def _chunk_for(self, laddr):
        for chunk in self._chunks:
            if chunk["logical"] <= laddr < chunk["logical"] + chunk["length"]:
                return chunk
        return None

    # ---------------- 条带映射 ----------------
    def _data_stripes(self, chunk):
        """RAID56 的数据条带数（RAID5 少 1、RAID6 少 2）"""
        if chunk["type"] & BLOCK_GROUP_RAID6:
            return max(1, chunk["num_stripes"] - 2)
        if chunk["type"] & BLOCK_GROUP_RAID5:
            return max(1, chunk["num_stripes"] - 1)
        return chunk["num_stripes"]

    def _stripes_for(self, chunk, delta, mirror=1):
        """chunk 内偏移 -> [(devid, paddr, 该条带可读长度, stripe_index, 是否奇偶)]

        公式对照 fs/btrfs/volumes.c 的 map_blocks_raid0 / raid1 / dup /
        raid10 / raid56_read：注意 RAID56 的 parity 会按行轮转。
        """
        stripes = chunk["stripes"]
        count = len(stripes)
        profile = chunk["type"] & PROFILE_MASK
        stripe_len = chunk["stripe_len"] or 65536

        if profile & BLOCK_GROUP_RAID0:
            stripe_nr, within = divmod(delta, stripe_len)
            index = stripe_nr % count
            row = stripe_nr // count
            base = stripes[index]["offset"] + row * stripe_len + within
            return [(stripes[index]["devid"], base,
                     min(stripe_len - within, chunk["length"] - delta),
                     index, False)]

        if profile & BLOCK_GROUP_RAID10:
            sub = max(1, chunk["sub_stripes"])
            factor = max(1, count // sub)
            stripe_nr, within = divmod(delta, stripe_len)
            group = stripe_nr % factor
            row = stripe_nr // factor
            out = []
            for i in range(sub):
                index = group * sub + i
                if index >= count:
                    continue
                base = stripes[index]["offset"] + row * stripe_len + within
                out.append((stripes[index]["devid"], base,
                            min(stripe_len - within, chunk["length"] - delta),
                            index, False))
            return out

        if profile & RAID56_MASK:
            data_stripes = self._data_stripes(chunk)
            stripe_nr, within = divmod(delta, stripe_len)
            data_index = stripe_nr % data_stripes
            row = stripe_nr // data_stripes
            index = (row + data_index) % count
            base = stripes[index]["offset"] + row * stripe_len + within
            return [(stripes[index]["devid"], base,
                     min(stripe_len - within, chunk["length"] - delta),
                     index, False)]

        # SINGLE / DUP / RAID1 / RAID1C3 / RAID1C4：同一位移的 n 份拷贝
        out = []
        for index in range(count):
            out.append((stripes[index]["devid"], stripes[index]["offset"] + delta,
                        chunk["length"] - delta, index, False))
        if mirror and 1 <= mirror <= len(out):
            out = [out[mirror - 1]]
        return out

    def logical_to_physical(self, laddr, mirror=1):
        """逻辑地址 -> (物理地址, 剩余长度, chunk 类型) | None"""
        detail = self.map_detail(laddr, mirror=mirror)
        if detail is None:
            return None
        return detail["paddr"], detail["length"], detail["type"]

    def map_detail(self, laddr, mirror=1):
        self._ensure_chunks()
        chunk = self._chunk_for(laddr)
        if chunk is None:
            return None
        delta = laddr - chunk["logical"]
        stripes = self._stripes_for(chunk, delta, mirror=mirror)
        if not stripes:
            return None
        devid, paddr, avail, index, parity = stripes[0]
        return {
            "logical": laddr,
            "devid": devid,
            "paddr": paddr,
            "length": avail,
            "type": chunk["type"],
            "type_text": _block_group_text(chunk["type"]),
            "chunk_logical": chunk["logical"],
            "offset_in_chunk": delta,
            "stripe_index": index,
            "mirror": mirror,
            "parity": parity,
            "exact": not parity,
            "source": chunk["source"],
        }

    # ---------------- 底层读 ----------------
    def _read_dev(self, devid, paddr, size):
        dev = self.devices.get(devid)
        if dev is None:
            raise IOError("缺少设备 devid=%d（已在 devices 里补上即可）" % devid)
        data = dev.read(paddr, size)
        if len(data) < size:
            raise IOError("devid=%d 偏移 0x%X 短读：%d < %d"
                          % (devid, paddr, len(data), size))
        return data

    def _read_logical(self, laddr, length, verify=None, strict=False):
        """跨 chunk、跨设备读逻辑区间；DUP/RAID1 自动换副本，RAID56 单盘重建"""
        want_verify = self.verify if verify is None else verify
        self._ensure_chunks()
        out = bytearray()
        pos = laddr
        end = laddr + length
        while pos < end:
            chunk = self._chunk_for(pos)
            if chunk is None:
                raise ValueError("逻辑地址 0x%X 无 chunk 映射" % pos)
            delta = pos - chunk["logical"]
            copies = self._stripes_for(chunk, delta, mirror=0)
            span = min(end - pos, chunk["length"] - delta)
            if not copies:
                raise ValueError("chunk@0x%X 没有可用条带" % chunk["logical"])
            span = min(span, copies[0][2])
            got = None
            errors = []
            for devid, paddr, avail, index, parity in copies:
                try:
                    raw = self._read_dev(devid, paddr, span)
                except IOError as exc:
                    errors.append(str(exc))
                    continue
                if want_verify:
                    if not self._verify_data(pos, raw, chunk, strict=strict):
                        errors.append("devid=%d 0x%X 校验和不符" % (devid, paddr))
                        continue
                got = raw
                break
            if got is None:
                if chunk["type"] & RAID56_MASK:
                    got = self._rebuild_raid56(chunk, delta, span)
                if got is None:
                    raise IOError("逻辑区间 0x%X+0x%X 全部副本不可读：%s"
                                  % (pos, span, "; ".join(errors) or "无副本"))
            out += got
            pos += span
        return bytes(out)

    def _rebuild_raid56(self, chunk, delta, span):
        """RAID5/6：整行 XOR 重建缺失的数据条带

        只解 P（XOR），不碰 Q（Reed-Solomon）。RAID6 里必须跳过 Q 条带，
        否则异或进来的是 RS 校验值，结果必错。
        """
        stripe_len = chunk["stripe_len"] or 65536
        count = chunk["num_stripes"]
        data_stripes = self._data_stripes(chunk)
        is_raid6 = bool(chunk["type"] & BLOCK_GROUP_RAID6)
        stripe_nr, within = divmod(delta, stripe_len)
        if within != 0 or span != stripe_len:
            self.warnings.append(
                "RAID56 重建只支持整条带对齐：offset_in_stripe=%d span=%d"
                % (within, span))
            return None
        row = stripe_nr // data_stripes
        data_index = stripe_nr % data_stripes
        missing = (row + data_index) % count
        # RAID5 只有 P；RAID6 才有 P/Q 两条校验条带
        q_index = (row + data_stripes + 1) % count if is_raid6 else -1
        if is_raid6 and missing == q_index:
            self.warnings.append("RAID56：缺失的是 Q 条带，需 RS 解码，未实现")
            return None
        acc = bytearray(stripe_len)
        used = 0
        for index in range(count):
            if index == missing or (is_raid6 and index == q_index):
                continue
            devid = chunk["stripes"][index]["devid"]
            paddr = chunk["stripes"][index]["offset"] + row * stripe_len
            try:
                raw = self._read_dev(devid, paddr, stripe_len)
            except IOError:
                self.warnings.append("RAID56 重建失败：条带 %d 不可读" % index)
                return None
            for i in range(stripe_len):
                acc[i] ^= raw[i]
            used += 1
        if used < data_stripes:
            self.warnings.append("RAID56 重建不完整：只有 %d/%d 个条带可用"
                                 % (used, data_stripes))
            return None
        self.warnings.append(
            "RAID5/6 用 P 条带 XOR 重建了逻辑 0x%X 的条带 %d"
            % (chunk["logical"] + delta, missing))
        return bytes(acc)

    # ---------------- 校验和 ----------------
    def _csum_tree_root(self):
        """csum 树根逻辑地址（根树里 tree_id=7 的 ROOT_ITEM），没有则 None"""
        info = self.roots().get(BTRFS_CSUM_TREE_OBJECTID)
        return info["bytenr"] if info else None

    def _load_csums(self):
        """把 csum 树读进内存：{逻辑起始: (覆盖长度, 校验和串)}"""
        if self._csums:
            return self._csums
        try:
            root = self._csum_tree_root()
        except Exception:
            root = None
        if not root:
            return self._csums
        size = csum_size(self.csum_type)
        try:
            for item in self._iter_items(root):
                if item.key.type != T_EXTENT_CSUM:
                    continue
                data = item.data
                if size:
                    span = (len(data) // size) * self.sectorsize
                else:
                    span = 0
                if span:
                    self._csums[item.key.offset] = (span, data)
        except Exception as exc:
            self.warnings.append("csum 树读取失败: %s" % exc)
        self._csum_starts = sorted(self._csums)
        return self._csums

    def stored_csum(self, laddr, size=None):
        """查 csum 树，取某逻辑地址处的校验和（找不到返回 None）"""
        csize = csum_size(self.csum_type)
        if not csize:
            return None
        size = size or self.sectorsize
        self._load_csums()
        starts = getattr(self, "_csum_starts", [])
        index = bisect.bisect_right(starts, laddr) - 1
        while index >= 0:
            start = starts[index]
            span, blob = self._csums[start]
            if laddr + size <= start + span:
                off = laddr - start
                pos = (off // self.sectorsize) * csize
                return blob[pos:pos + csize]
            index -= 1
        return None

    def verify_extent(self, laddr, length=None, strict=False):
        """按 csum 树校验一段数据；返回 (是否通过, 说明)"""
        csize = csum_size(self.csum_type)
        if not csize:
            return True, "csum_type=%d 不支持校验" % self.csum_type
        length = length or self.sectorsize
        data = self._read_logical(laddr, length, verify=False)
        bad = []
        for off in range(0, length, self.sectorsize):
            block = data[off:off + self.sectorsize]
            stored = self.stored_csum(laddr + off, len(block))
            if stored is None:
                bad.append("0x%X 无 csum 记录" % (laddr + off))
                continue
            if csum_data(block, self.csum_type) != stored:
                bad.append("0x%X 校验和不符" % (laddr + off))
        if bad:
            message = "; ".join(bad)
            if strict:
                raise ValueError(message)
            self.warnings.append(message)
            return False, message
        return True, "ok"

    def _verify_data(self, laddr, raw, chunk, strict=False):
        """数据校验和核对：逐扇区比较；无 csum 记录按"未知"放行（不误判）"""
        csize = csum_size(self.csum_type)
        if not csize:
            return True
        if not self._load_csums():
            return True
        step = self.sectorsize
        for off in range(0, len(raw), step):
            block = raw[off:off + step]
            if len(block) < step:
                # 尾部不足一个扇区：btrfs 的 csum 只对完整扇区计算，跳过
                if strict:
                    self.warnings.append("0x%X 尾部残块（%d 字节）无法校验"
                                         % (laddr + off, len(block)))
                    return False
                continue
            stored = self.stored_csum(laddr + off, step)
            if stored is None:
                if strict:
                    self.warnings.append("0x%X 缺 csum 记录" % (laddr + off))
                    return False
                continue
            if csum_data(block, self.csum_type) != stored:
                self.warnings.append(
                    "逻辑 0x%X 校验和不符（%s）"
                    % (laddr + off, _block_group_text(chunk["type"])))
                return False
        return True

    def verify_node(self, laddr, strict=True):
        """校验一个树节点的元数据校验和：覆盖 node[0x20:]"""
        node = self.read_node(laddr, verify=False)
        if not self.verify:
            return True, "校验已关闭"
        csize = csum_size(self.csum_type)
        expect = node.csum[:csize]
        got = csum_data(node.data[0x20:], self.csum_type)
        ok = (got == expect)
        node.csum_ok = ok
        if not ok:
            message = ("节点 0x%X 校验和不符：存 %s 算 %s"
                       % (laddr, expect.hex(), got.hex()))
            if strict:
                raise ValueError(message)
            self.warnings.append(message)
            return False, message
        return True, "ok"

    # ---------------- 节点 ----------------
    def read_node(self, laddr, verify=None, strict=False):
        """按逻辑地址读树节点；校验和不过自动换下一个副本"""
        cached = self._nodes.get(laddr)
        if cached is not None:
            return cached
        chunk = None
        self._ensure_chunks()
        chunk = self._chunk_for(laddr)
        if chunk is None:
            raise ValueError("逻辑地址 0x%X 无 chunk 映射" % laddr)
        delta = laddr - chunk["logical"]
        copies = self._stripes_for(chunk, delta, mirror=0)
        want_verify = self.verify if verify is None else verify
        errors = []
        last_bad = None
        for devid, paddr, avail, index, parity in copies:
            if parity:
                errors.append("条带 %d 是奇偶校验条带" % index)
                continue
            take = min(self.nodesize, avail)
            try:
                data = self._read_dev(devid, paddr, take)
            except IOError as exc:
                errors.append(str(exc))
                continue
            if len(data) < self.nodesize:
                data = data + b"\x00" * (self.nodesize - len(data))
            node = Node(self, laddr, data, paddr=paddr, devid=devid,
                        mirror=index + 1)
            if want_verify:
                got = csum_data(node.data[0x20:], self.csum_type)
                node.csum_ok = (got == node.csum[:csum_size(self.csum_type)])
                if not node.csum_ok:
                    errors.append("devid=%d 0x%X 节点校验和不符"
                                  % (devid, paddr))
                    last_bad = node
                    continue
            if index > 0:
                self.warnings.append(
                    "节点 0x%X 镜像 1 不可用，改用镜像 %d（devid=%d paddr=0x%X）"
                    % (laddr, index + 1, devid, paddr))
            self.warnings.extend(node.warnings)
            if len(self._nodes) > 4096:
                self._nodes.clear()
            self._nodes[laddr] = node
            return node
        if last_bad is not None:
            # 全部副本校验和都不对：把最后一份交出去，让调用方看到数据本身
            self.warnings.append(
                "节点 0x%X 所有副本校验和都不符，返回最后一份（已标记 csum_ok=False）"
                % laddr)
            self.warnings.extend(last_bad.warnings)
            self._nodes[laddr] = last_bad
            return last_bad
        raise ValueError("节点 0x%X 读取失败：%s" % (laddr, "; ".join(errors)))

    def root_tree(self):
        return self.read_node(self.root)

    def chunk_root_tree(self):
        if not self.chunk_root:
            raise ValueError("超级块未给出 chunk_root")
        return self.read_node(self.chunk_root)

    def iter_items(self, laddr, kmin=None, kmax=None):
        yield from self._iter_items(laddr, kmin, kmax)

    def _iter_items(self, laddr, kmin=None, kmax=None, depth=0):
        if depth > 16:
            self.warnings.append("树深超过 16（疑似环路），在 0x%X 截断" % laddr)
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
        if self._roots is not None:
            return self._roots
        out = {}
        for item in self._iter_items(self.root):
            if item.key.type != T_ROOT_ITEM:
                continue
            data = item.data
            if len(data) < ROOT_ITEM_LEGACY:
                self.warnings.append("ROOT_ITEM %d 只有 %d 字节，跳过"
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
        return self.read_node(self._tree_info(tree_id)["bytenr"])

    def inode(self, ino, tree_id=BTRFS_FS_TREE_OBJECTID):
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
        tree_id, ino = self.resolve(path)
        inode = self.inode(ino, tree_id)
        if inode is not None and not inode["is_dir"]:
            raise ValueError("不是目录: %s" % path)
        return [self._make_dirent(tree_id, rec)
                for rec in self.dir_records(ino, tree_id)]

    def walk(self, path="/", _depth=0, _max=64):
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
        out = []
        needle = (pattern or "").lower()
        for full, entry in self.walk():
            if needle and needle not in full.lower():
                continue
            out.append((full, entry))
        return out

    # ---------------- 文件数据 ----------------
    def extent_payload(self, item):
        data = item.data
        if len(data) < 21:
            raise ValueError("EXTENT_DATA 项过短：%d" % len(data))
        ram_bytes = _u64(data, 8)
        compression = data[16]
        encryption = data[17]
        etype = data[20]
        if encryption:
            raise NotImplementedError("加密 extent（encryption=%d）不支持" % encryption)
        if etype == FILE_EXTENT_INLINE:
            raw = data[21:]
            if compression:
                return decompress(compression, raw, ram_bytes)
            return raw[:ram_bytes] if ram_bytes else raw
        disk_bytenr, disk_num_bytes, extent_offset, num_bytes = \
            struct.unpack_from("<QQQQ", data, 21)
        if disk_bytenr == 0:
            return b"\x00" * num_bytes
        raw = self._read_logical(disk_bytenr, disk_num_bytes)
        if compression:
            raw = decompress(compression, raw, ram_bytes)
        return raw[extent_offset:extent_offset + num_bytes]

    def read_file(self, path=None, tree_id=None, ino=None):
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
                out += b"\x00" * (item.key.offset - len(out))
            out += self.extent_payload(item)
            if size and len(out) >= size:
                break
        if size and len(out) < size:
            out += b"\x00" * (size - len(out))
        return bytes(out[:size]) if size else bytes(out)

    def __repr__(self):
        return "<Btrfs label=%r nodesize=%d gen=%d devices=%s>" % (
            self.label, self.nodesize, self.generation, sorted(self.devices))


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


def open_fs(sub, sb_offset=None, devices=None, verify=True):
    """打开 Btrfs 卷"""
    if not probe(sub):
        raise ValueError("不是 Btrfs 文件系统（未找到 _BHRfS_M）")
    return Btrfs(sub, sb_offset=sb_offset, devices=devices, verify=verify)


if __name__ == "__main__":
    import hashlib
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    checks = []

    def ok(name, cond, extra=""):
        checks.append(bool(cond))
        print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                               ("  " + str(extra)) if extra else ""))
        if not cond:
            volume = globals().get("fs")
            if volume is not None and volume.warnings:
                print("  模块告警: %s" % volume.warnings[:6])
            raise AssertionError(name)

    print("Btrfs 模块自检")

    # ---------- 1. 校验和：已知测试向量 ----------
    print("\n-- 校验和（已知测试向量）--")
    ok("crc32c('123456789') == 0xE3069283",
       crc32c(b"123456789") == 0xE3069283,
       hex(crc32c(b"123456789")))
    ok("crc32c(b'') == 0", crc32c(b"") == 0)
    ok("crc32c 与 zlib.crc32（IEEE）不同",
       crc32c(b"123456789") != zlib.crc32(b"123456789"))
    ok("xxhash64(b'') == 0xEF46DB3751D8E999",
       xxhash64(b"") == 0xEF46DB3751D8E999, hex(xxhash64(b"")))
    ok("xxhash64(b'a') == 0xD24EC4F1A98C6E5B",
       xxhash64(b"a") == 0xD24EC4F1A98C6E5B, hex(xxhash64(b"a")))
    ok("xxhash64(b'abc') == 0x44BC2CF5AD770999",
       xxhash64(b"abc") == 0x44BC2CF5AD770999, hex(xxhash64(b"abc")))
    ok("xxhash64 单字节尾部走 tail 分支",
       xxhash64(b"x" * 31) != xxhash64(b"x" * 32))
    ok("sha256 走 hashlib",
       csum_data(b"abc", 2) == hashlib.sha256(b"abc").digest())
    ok("blake2b-256 走 hashlib",
       csum_data(b"abc", 3) == hashlib.blake2b(b"abc", digest_size=32).digest())
    ok("csum_size 表", [csum_size(i) for i in range(4)] == [4, 8, 32, 32])

    # ---------- 2. 压缩解码 ----------
    print("\n-- 压缩解码 --")
    payload = b"abc" * 100
    ok("zlib 往返", decompress(1, zlib.compress(payload), len(payload)) == payload)
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    ok("zlib 裸 deflate 回退",
       decompress(1, co.compress(b"xyzxyz") + co.flush(), 6) == b"xyzxyz")

    # LZO1X 只含字面量段的合法流：首字节 17+n 表示 n 字节字面量，
    # 结尾必须是 EOF 标记 11 00 00（内核 copy_literal_run 会预读 t+3 字节）
    lit = b"LZO-literal-run!"
    eof = b"\x11\x00\x00"
    stream = bytes([17 + len(lit)]) + lit + eof
    ok("LZO1X 纯字面量段", lzo1x_decompress(stream, 64) == lit,
       lzo1x_decompress(stream, 64))
    # M3 编码（token>=64）：t=0x6C → 距离 1+(0x6C>>2&7)=4、长度 (0x6C>>5)+1=4
    match_stream = bytes([17 + 4]) + b"ABCD" + bytes([0x6C, 0x00]) + eof
    ok("LZO1X M3 匹配（距离 4、长度 4）",
       lzo1x_decompress(match_stream, 64) == b"ABCDABCD",
       lzo1x_decompress(match_stream, 64))
    # btrfs LZO 封帧：[段总长][压缩长][数据]
    framed = struct.pack("<II", 8 + len(stream), len(stream)) + stream
    ok("btrfs LZO 封帧", lzo_decompress(framed, len(lit)) == lit)

    lz4_raw = bytes([0x40]) + b"ABCD" + bytes([0x04, 0x00])
    ok("LZ4 块：字面量 + 匹配",
       lz4_block_decompress(lz4_raw, 8) == b"ABCDABCD",
       lz4_block_decompress(lz4_raw, 8))
    ok("LZ4 块：纯字面量",
       lz4_block_decompress(bytes([0x40]) + b"WXYZ", 4) == b"WXYZ")
    try:
        lz4_block_decompress(bytes([0x40]) + b"WXYZ", 99)
        ok("LZ4 长度不符要报错", False)
    except ValueError:
        ok("LZ4 长度不符要报错", True)
    print("  [INFO] zstd_available() = %s" % zstd_available())

    # ---------- 3. 合成镜像 ----------
    NODESIZE = 16384
    SECTORSIZE = 4096
    GEN = 7
    FSID = bytes.fromhex("00112233445566778899aabbccddeeff")
    CHUNK_UUID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    DEV_UUID = bytes.fromhex("0123456789abcdeffedcba9876543210")

    CHUNK_LOG, CHUNK_LEN, CHUNK_PHYS = 0x100000, 0x400000, 0x400000
    DATA_LOG, DATA_LEN, DATA_PHYS = 0x500000, 0x100000, 0x100000
    ROOT_ROOT = 0x100000
    CHUNK_ROOT = 0x110000
    CSUM_ROOT = 0x118000
    FS_ROOT = 0x120000
    FS_LEAF_A = 0x140000
    FS_LEAF_B = 0x144000
    SUB_ROOT = 0x148000
    MIRROR_OFF = 0x400000          # DUP 第二份拷贝的物理位移
    IMG_SIZE = 0xC00000

    HELLO = b"hello btrfs\n"
    INNER = b"inner\n"
    ZTEXT = b"zlib inline\n"
    BIG = bytes(range(256)) * 32
    LABEL_TEXT = b"ESK-BTRFS\x00"

    def l2p(laddr):
        if CHUNK_LOG <= laddr < CHUNK_LOG + CHUNK_LEN:
            return CHUNK_PHYS + (laddr - CHUNK_LOG)
        if DATA_LOG <= laddr < DATA_LOG + DATA_LEN:
            return DATA_PHYS + (laddr - DATA_LOG)
        raise ValueError("合成镜像里 0x%X 没有映射" % laddr)

    img = bytearray(IMG_SIZE)

    def put(laddr, data):
        """元数据 chunk 是 DUP，所以落在 CHUNK 区间的内容双写；数据 chunk 单写"""
        pos = l2p(laddr)
        img[pos:pos + len(data)] = data
        if CHUNK_LOG <= laddr < CHUNK_LOG + CHUNK_LEN:
            img[pos + MIRROR_OFF:pos + MIRROR_OFF + len(data)] = data

    def seal(node):
        """按 csum_type=0（crc32c）把 node[0x20:] 的校验和写进 node[0:4]"""
        node[0:4] = struct.pack("<I", crc32c(bytes(node[0x20:])))
        return node

    def build_chunk(length, phys, ctype, num_stripes=1, sub=1):
        buf = bytearray(CHUNK_HDR_SIZE + STRIPE_SIZE * num_stripes)
        struct.pack_into("<QQQQIIIHH", buf, 0, length,
                         BTRFS_FIRST_CHUNK_TREE_OBJECTID, 65536, ctype,
                         SECTORSIZE, SECTORSIZE, SECTORSIZE, num_stripes, sub)
        for i in range(num_stripes):
            struct.pack_into("<QQ", buf, CHUNK_HDR_SIZE + i * STRIPE_SIZE,
                             1, phys + i * MIRROR_OFF)
        return bytes(buf)

    def build_inode(mode, size=0, nlink=1, mtime=1700000000):
        buf = bytearray(160)
        struct.pack_into("<Q", buf, 0, GEN)
        struct.pack_into("<Q", buf, 8, GEN)
        struct.pack_into("<Q", buf, 16, size)
        struct.pack_into("<Q", buf, 24, size)
        struct.pack_into("<I", buf, 40, nlink)
        struct.pack_into("<I", buf, 52, mode)
        struct.pack_into("<Q", buf, 136, mtime)
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
        struct.pack_into("<Q", buf, 17, GEN)
        struct.pack_into("<H", buf, 27, len(raw))
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
        struct.pack_into("<Q", buf, 8, num_bytes)
        buf[20] = FILE_EXTENT_REG
        struct.pack_into("<QQQQ", buf, 21, disk_bytenr, disk_num_bytes, 0, num_bytes)
        return bytes(buf)

    def build_root_item(bytenr, level, root_dirid=256, flags=0):
        buf = bytearray(439)
        struct.pack_into("<I", buf, 52, 0o40755)
        struct.pack_into("<Q", buf, 160, GEN)
        struct.pack_into("<Q", buf, 168, root_dirid)
        struct.pack_into("<Q", buf, 176, bytenr)
        struct.pack_into("<Q", buf, 208, flags)
        struct.pack_into("<I", buf, 216, 1)
        buf[238] = level
        struct.pack_into("<Q", buf, 239, GEN)
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
        put(laddr, bytes(seal(node)))

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
        put(laddr, bytes(seal(node)))

    # 数据 + 数据校验和（每 sectorsize 一条，extent 覆盖 2 个扇区）
    put(DATA_LOG, BIG)
    data_csums = b"".join(csum_data(BIG[i:i + SECTORSIZE], 0)
                          for i in range(0, len(BIG), SECTORSIZE))

    mode_dir = 0o040755
    leaf_a = [
        ((256, T_INODE_ITEM, 0), build_inode(mode_dir, 0, 4)),
        ((256, T_DIR_ITEM, 0x1111), build_dir_item("hello.txt", (257, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_ITEM, 0x2222), build_dir_item("big.bin", (258, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_ITEM, 0x3333), build_dir_item("z.txt", (259, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_ITEM, 0x4444), build_dir_item("sub", (256, T_ROOT_ITEM, 0), 2)),
        ((256, T_DIR_INDEX, 1), build_dir_item("hello.txt", (257, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_INDEX, 2), build_dir_item("big.bin", (258, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_INDEX, 3), build_dir_item("z.txt", (259, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_INDEX, 4), build_dir_item("sub", (256, T_ROOT_ITEM, 0), 2)),
    ]
    write_leaf(FS_LEAF_A, BTRFS_FS_TREE_OBJECTID, leaf_a)

    write_leaf(FS_LEAF_B, BTRFS_FS_TREE_OBJECTID, [
        ((257, T_INODE_ITEM, 0), build_inode(0o100644, len(HELLO))),
        ((258, T_INODE_ITEM, 0), build_inode(0o100644, len(BIG))),
        ((259, T_INODE_ITEM, 0), build_inode(0o100644, len(ZTEXT))),
        ((257, T_INODE_REF, 256), build_ref(1, "hello.txt")),
        ((258, T_INODE_REF, 256), build_ref(2, "big.bin")),
        ((259, T_INODE_REF, 256), build_ref(3, "z.txt")),
        ((257, T_EXTENT_DATA, 0), build_inline(HELLO)),
        ((258, T_EXTENT_DATA, 0), build_reg(DATA_LOG, len(BIG), len(BIG))),
        ((259, T_EXTENT_DATA, 0), build_inline(zlib.compress(ZTEXT), 1, len(ZTEXT))),
    ])

    write_node(FS_ROOT, BTRFS_FS_TREE_OBJECTID,
               [((256, 0, 0), FS_LEAF_A), ((257, 0, 0), FS_LEAF_B)])

    write_leaf(SUB_ROOT, BTRFS_FIRST_FREE_OBJECTID, [
        ((256, T_INODE_ITEM, 0), build_inode(mode_dir, 0, 2)),
        ((256, T_DIR_ITEM, 0x5555), build_dir_item("inner.txt", (257, T_INODE_ITEM, 0), 1)),
        ((256, T_DIR_INDEX, 1), build_dir_item("inner.txt", (257, T_INODE_ITEM, 0), 1)),
        ((257, T_INODE_ITEM, 0), build_inode(0o100644, len(INNER))),
        ((257, T_INODE_REF, 256), build_ref(1, "inner.txt")),
        ((257, T_EXTENT_DATA, 0), build_inline(INNER)),
    ])

    # csum 树：一条 EXTENT_CSUM 覆盖 2 个扇区
    write_leaf(CSUM_ROOT, BTRFS_CSUM_TREE_OBJECTID, [
        ((BTRFS_EXTENT_CSUM_OBJECTID, T_EXTENT_CSUM, DATA_LOG), data_csums),
    ])

    # chunk 树：DUP（2 条带，第二份在 +0x400000），数据 chunk 单条带
    chunk_sys = build_chunk(
        CHUNK_LEN, CHUNK_PHYS,
        BLOCK_GROUP_DATA | BLOCK_GROUP_SYSTEM | BLOCK_GROUP_METADATA
        | BLOCK_GROUP_DUP, num_stripes=2)
    chunk_data = build_chunk(DATA_LEN, DATA_PHYS, BLOCK_GROUP_DATA)
    write_leaf(CHUNK_ROOT, BTRFS_CHUNK_TREE_OBJECTID, [
        ((BTRFS_FIRST_CHUNK_TREE_OBJECTID, T_CHUNK_ITEM, CHUNK_LOG), chunk_sys),
        ((BTRFS_FIRST_CHUNK_TREE_OBJECTID, T_CHUNK_ITEM, DATA_LOG), chunk_data),
    ])

    write_leaf(ROOT_ROOT, BTRFS_ROOT_TREE_OBJECTID, [
        ((BTRFS_FS_TREE_OBJECTID, T_ROOT_ITEM, 0), build_root_item(FS_ROOT, 1)),
        ((BTRFS_FIRST_FREE_OBJECTID, T_ROOT_ITEM, 0), build_root_item(SUB_ROOT, 0)),
        ((BTRFS_CSUM_TREE_OBJECTID, T_ROOT_ITEM, 0), build_root_item(CSUM_ROOT, 0)),
    ])

    sb = bytearray(SB_SIZE)
    sb[0x20:0x30] = FSID
    struct.pack_into("<QQ", sb, 0x30, SB_OFFSET, 0)
    sb[0x40:0x48] = SB_MAGIC
    struct.pack_into("<Q", sb, 0x48, GEN)
    struct.pack_into("<Q", sb, 0x50, ROOT_ROOT)
    struct.pack_into("<Q", sb, 0x58, CHUNK_ROOT)
    struct.pack_into("<Q", sb, 0x60, 0)
    struct.pack_into("<Q", sb, 0x68, 0)
    struct.pack_into("<Q", sb, 0x70, IMG_SIZE)
    struct.pack_into("<Q", sb, 0x78, 0x8000)
    struct.pack_into("<Q", sb, 0x80, 6)
    struct.pack_into("<Q", sb, 0x88, 1)
    struct.pack_into("<I", sb, 0x90, SECTORSIZE)
    struct.pack_into("<I", sb, 0x94, NODESIZE)
    struct.pack_into("<I", sb, 0x98, NODESIZE)
    struct.pack_into("<I", sb, 0x9C, 65536)
    struct.pack_into("<Q", sb, 0xA4, GEN)
    struct.pack_into("<H", sb, 0xC4, 0)
    sb[0xC6] = 0
    sb[0xC7] = 0
    sb[0xC8] = 0
    struct.pack_into("<QQQIII", sb, 0xC9, 1, IMG_SIZE, 0x8000,
                     SECTORSIZE, SECTORSIZE, SECTORSIZE)
    struct.pack_into("<Q", sb, 0xC9 + 44, GEN)
    sb[0xC9 + 66:0xC9 + 82] = DEV_UUID
    sb[0xC9 + 82:0xC9 + 98] = FSID
    sb[LABEL_OFF:LABEL_OFF + len(LABEL_TEXT)] = LABEL_TEXT
    struct.pack_into("<Q", sb, 0x22B, GEN)
    struct.pack_into("<Q", sb, 0x233, GEN)
    sb[0x23B:0x24B] = FSID

    entry = bytearray(DISK_KEY_SIZE + len(chunk_sys))
    struct.pack_into("<QBQ", entry, 0, BTRFS_FIRST_CHUNK_TREE_OBJECTID,
                     T_CHUNK_ITEM, CHUNK_LOG)
    entry[DISK_KEY_SIZE:] = chunk_sys
    sb[SYSCK_ARRAY_OFF:SYSCK_ARRAY_OFF + len(entry)] = entry
    struct.pack_into("<I", sb, 0xA0, len(entry))
    img[SB_OFFSET:SB_OFFSET + SB_SIZE] = bytes(sb)
    image = bytes(img)
    assert len(sb) == SB_SIZE, "超级块必须正好 0x1000 字节"
    assert len(image) == IMG_SIZE

    class _MemSub(object):
        def __init__(self, raw, broken=None):
            self.data = raw
            self.size = len(raw)
            self.broken = broken or ()

        def read(self, offset, size):
            if offset < 0 or size <= 0:
                return b""
            for lo, hi in self.broken:
                if lo <= offset < hi:
                    return b"\x00" * size
            return self.data[offset:offset + size]

    print("\n-- 第 1 层：超级块 --")
    sub = _MemSub(image)
    fs = open_fs(sub)
    info = fs.info()
    ok("魔数", info["magic"] == "_BHRfS_M")
    ok("label", info["label"] == "ESK-BTRFS", info["label"])
    ok("nodesize/sectorsize",
       (info["nodesize"], info["sectorsize"]) == (NODESIZE, SECTORSIZE))
    ok("csum_type/csum_size", (info["csum_type"], info["csum_size"]) == ("crc32c", 4))
    ok("total_bytes", info["total_bytes"] == IMG_SIZE)
    ok("num_devices", info["num_devices"] == 1)
    ok("fsid", info["fsid"] == "00112233-4455-6677-8899-aabbccddeeff")

    print("\n-- 第 2 层：chunk 映射（DUP 双副本）--")
    chunks = fs.chunk_map()
    ok("2 条 chunk", len(chunks) == 2, len(chunks))
    ok("DUP 类型与条带数",
       chunks[0]["type_text"].endswith("DUP") and chunks[0]["num_stripes"] == 2,
       chunks[0]["type_text"])
    ok("logical_to_physical(镜像 1)",
       fs.logical_to_physical(CHUNK_LOG) == (CHUNK_PHYS, CHUNK_LEN, chunks[0]["type"]))
    ok("logical_to_physical(镜像 2)",
       fs.logical_to_physical(CHUNK_LOG, mirror=2)[0] == CHUNK_PHYS + MIRROR_OFF)
    ok("数据 chunk 来自 chunk 树",
       fs.logical_to_physical(DATA_LOG)[0] == DATA_PHYS)
    ok("未映射地址 None", fs.logical_to_physical(0x900000) is None)

    print("\n-- 第 3 层：节点与校验和 --")
    rt = fs.root_tree()
    ok("根树 nritems", rt.nritems == 3)
    ok("根树校验和 ok", rt.csum_ok is True)
    ok("根树 keys",
       [it.key.as_tuple() for it in rt.items()]
       == [(5, T_ROOT_ITEM, 0), (7, T_ROOT_ITEM, 0), (256, T_ROOT_ITEM, 0)])
    ok("verify_node 通过", fs.verify_node(ROOT_ROOT) == (True, "ok"))

    fs_node = fs.read_node(FS_ROOT)
    ptrs = fs_node.ptrs()
    ok("FS 树 level 1 / 2 个指针", fs_node.level == 1 and len(ptrs) == 2)
    ok("ptr blockptr", (ptrs[0].blockptr, ptrs[1].blockptr) == (FS_LEAF_A, FS_LEAF_B))
    ok("叶子 A nritems", fs.read_node(FS_LEAF_A).nritems == 9)
    a_keys = [it.key.as_tuple() for it in fs.read_node(FS_LEAF_A).items()]
    ok("叶子 A 键递增", a_keys == sorted(a_keys))
    ok("ITEM 不越界",
       all(it.data_offset + it.size <= NODESIZE
           for it in fs.read_node(FS_LEAF_A).items()))

    print("\n-- 校验和验证与副本切换 --")
    ok("verify_extent 通过", fs.verify_extent(DATA_LOG, len(BIG))[0] is True)
    bad = bytearray(image)
    bad[DATA_PHYS] ^= 0xFF
    fs_bad = open_fs(_MemSub(bytes(bad)))
    ok("数据被改 -> 校验失败",
       fs_bad.verify_extent(DATA_LOG, len(BIG))[0] is False)
    try:
        fs_bad.verify_extent(DATA_LOG, len(BIG), strict=True)
        ok("strict 模式抛异常", False)
    except ValueError:
        ok("strict 模式抛异常", True)

    # 第一份拷贝整块写坏，应自动换到 DUP 第二份
    fs_dup = open_fs(_MemSub(image, broken=[(CHUNK_PHYS, CHUNK_PHYS + 0x80000)]))
    leaf_dup = fs_dup.read_node(FS_LEAF_A)
    ok("镜像 1 损坏 -> 自动用镜像 2",
       leaf_dup.csum_ok is True and leaf_dup.mirror == 2,
       "mirror=%s csum=%s" % (leaf_dup.mirror, leaf_dup.csum_ok))
    ok("镜像 1 损坏仍能读文件", fs_dup.read_file("/hello.txt") == HELLO)
    ok("副本切换留痕", any("改用镜像 2" in w for w in fs_dup.warnings),
       fs_dup.warnings[:2])

    print("\n-- 第 4 层：目录与文件 --")
    names = [d.name for d in fs.listdir("/")]
    ok("listdir 顺序", names == ["hello.txt", "big.bin", "z.txt", "sub"], names)
    ok("文件大小", fs.listdir("/")[1].size == len(BIG))
    ok("子卷项", fs.listdir("/")[3].is_subvol is True)
    ok("读普通 extent", fs.read_file("/big.bin") == BIG)
    ok("读 inline", fs.read_file("/hello.txt") == HELLO)
    ok("读 zlib inline", fs.read_file("/z.txt") == ZTEXT)
    ok("子卷文件", fs.read_file("/sub/inner.txt") == INNER)
    ok("walk", [p for p, _ in fs.walk("/")]
       == ["hello.txt", "big.bin", "z.txt", "sub", "sub/inner.txt"])
    ok("find", [p for p, _ in fs.find("big")] == ["big.bin"])
    ok("subvolumes", [s["id"] for s in fs.subvolumes()] == [256])

    print("\n-- RAID 条带公式（对照 volumes.c map_blocks_*）--")

    def stripe(i, base, count):
        return {"devid": i + 1, "offset": base + i * 0x100000, "dev_uuid": ""}

    raid0 = {"logical": 0, "length": 3 * 65536, "stripe_len": 65536,
             "type": BLOCK_GROUP_DATA | BLOCK_GROUP_RAID0,
             "num_stripes": 3, "sub_stripes": 1,
             "stripes": [stripe(i, 0x1000, 3) for i in range(3)]}
    got = fs._stripes_for(raid0, 2 * 65536 + 7, mirror=0)[0]
    ok("RAID0: index = stripe_nr % n, row = stripe_nr // n",
       got[0] == 3 and got[1] == 0x1000 + 2 * 0x100000 + 7, got)

    raid10 = {"logical": 0, "length": 4 * 65536, "stripe_len": 65536,
              "type": BLOCK_GROUP_DATA | BLOCK_GROUP_RAID10,
              "num_stripes": 4, "sub_stripes": 2,
              "stripes": [stripe(i, 0x2000, 4) for i in range(4)]}
    pair = fs._stripes_for(raid10, 65536 + 9, mirror=0)
    ok("RAID10: 一组 sub_stripes 个副本",
       len(pair) == 2 and pair[0][0] == 3 and pair[1][0] == 4, pair[0][:2])

    raid5 = {"logical": 0, "length": 4 * 65536, "stripe_len": 65536,
             "type": BLOCK_GROUP_DATA | BLOCK_GROUP_RAID5,
             "num_stripes": 4, "sub_stripes": 1,
             "stripes": [stripe(i, 0x3000, 4) for i in range(4)]}
    ok("RAID5 数据条带 = n-1", fs._data_stripes(raid5) == 3)
    ok("RAID6 数据条带 = n-2",
       fs._data_stripes(dict(raid5, type=BLOCK_GROUP_DATA | BLOCK_GROUP_RAID6)) == 2)
    first = fs._stripes_for(raid5, 0, mirror=0)[0]
    row1 = fs._stripes_for(raid5, 3 * 65536, mirror=0)[0]
    ok("RAID56 parity 逐行轮转 (row0→idx0, row1→idx1)",
       first[3] == 0 and row1[3] == 1, (first[3], row1[3]))

    print("\n全部 %d 项断言通过" % len(checks))
    sys.exit(0)

