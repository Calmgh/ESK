# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  OCFS2 只读解析
# ============================================================
"""OCFS2（Oracle Cluster File System 2）只读解析 — 纯标准库（struct / uuid）。

分层与实现情况（与 CAPS 一致）：
  L1 超级块     已实现。超级块本身是 ocfs2_dinode，签名 OCFSV2，
                i_flags 带 OCFS2_SUPER_BLOCK_FL；字段偏移逐条对齐
                fs/ocfs2/ocfs2_fs.h（mainline，拉取于 2026-11）
  L2 链列表     已实现。id2.i_chain（cl_count / cl_next_free_rec / cl_recs[]）
                与 group_desc 链（GROUP01，bg_next_group 串联），只报组数
                与组头字段，不逐位解析位图
  L3 inode      已实现。i_mode/i_uid/i_gid/i_size/i_links_count/时间戳
                （u64 秒 + u32 纳秒）；inline data；extent_list 递归，
                l_tree_depth>0 时下钻 EXBLK01 扩展块
  L4 目录       线性目录已实现（inline 目录 + extent 目录 + DIRTRL1 尾块）；
                索引目录（DXDIR01 / DXLEAF1）抛 NotImplementedError

未做（原因）：位图逐位分配审计（只需计数，成本/收益不划算）、slot map、
journal 重放（需 cluster 栈语义，只读解析意义有限）、xattr、refcount tree、
符号链接目标读取、任何写操作。

偏移核对说明：
  * 全部偏移取自 ocfs2_fs.h 的 /*00*/ /*10*/ ... 行标，结构体均为小端 __le。
  * dinode：id1@0xB8，id2@0xC0（union 分支 i_super / i_chain / i_list /
    i_data 同起点，按 i_flags 与 i_dyn_features 选择）。
  * 超级块字段偏移相对 id2，故 s_label 绝对偏移 = 0xC0+0x50 = 0x110，
    s_uuid = 0xC0+0x90 = 0x150。
  * 块号换算：i_blkno / e_blkno / bg_blkno 在头文件注释里都写 "in blocks"，
    故字节偏移 = blkno << blocksize_bits；OCFS2 元数据按簇对齐，此时
    blkno * blocksize == 集群号 * clustersize（两式等价）。非簇对齐的
    blkno 只有一种解释成立，见 _blk_off 的 docstring。
  * 仅两处为推断并已标注：备份超级块位于 (1<<30)+i 簇（内核
    OCFS2_BACKUP_SB_START 注释），以及 dir_entry.file_type 沿用 ext2
    dirent 取值（ocfs2_fs.h 未给 FT_* 枚举）。
"""
import datetime
import fnmatch
import struct
import uuid

# ---------------------------------------------------------------- 签名
# 规范给的是 8 字节 "OCFSV2  "；mainline 头文件给的是 6 字节宏
# OCFS2_SUPER_BLOCK_SIGNATURE "OCFSV2"，实盘尾部可能补空格或 NUL。
# 因此 8 字节精确比对两种都接受，另用 6 字节 magic 做 probe。
SIG_SB = b"OCFSV2  "
SIG_SB_NUL = b"OCFSV2\x00\x00"
SIG_SB_MAGIC = b"OCFSV2"
# 下面这些在 OCFS2 里都是 char sig[8]，磁盘上第 8 字节是 NUL。
# 常量必须补齐到 8 字节：否则 (a) 读端拿 8 字节切片去比 7 字节常量永远不等，
# (b) 构建端 `b[0:8] = SIG_xxx` 只写 7 字节，bytearray 的切片赋值会把缓冲区
#     缩短 1 字节，导致之后所有字段偏移整体错位。
SIG_DINODE = b"INODE01\x00"
SIG_EB = b"EXBLK01\x00"           # mainline: OCFS2_EXTENT_BLOCK_SIGNATURE
SIG_EB_ALT = b"OCFSV2EB"          # 规范给的别名
SIG_GD = b"GROUP01\x00"           # mainline: OCFS2_GROUP_DESC_SIGNATURE
SIG_GD_ALT = b"OCFSV2G "          # 规范给的别名
SIG_DIR_TRAILER = b"DIRTRL1\x00"
SIG_DX_ROOT = b"DXDIR01\x00"
SIG_DX_LEAF = b"DXLEAF1\x00"

SIGS_SB = (SIG_SB, SIG_SB_NUL)
SIGS_EB = (SIG_EB, SIG_EB_ALT)
SIGS_GD = (SIG_GD, SIG_GD_ALT)

# ---------------------------------------------------------------- i_flags
OCFS2_VALID_FL = 0x00000001
OCFS2_ORPHANED_FL = 0x00000004
OCFS2_SYSTEM_FL = 0x00000010
OCFS2_SUPER_BLOCK_FL = 0x00000020
OCFS2_LOCAL_ALLOC_FL = 0x00000040
OCFS2_BITMAP_FL = 0x00000080
OCFS2_JOURNAL_FL = 0x00000100
OCFS2_HEARTBEAT_FL = 0x00000200
OCFS2_CHAIN_FL = 0x00000400
OCFS2_DEALLOC_FL = 0x00000800
OCFS2_QUOTA_FL = 0x00001000

# i_flags 里的兼容属性位（FS_INDEX_FL 与 ext2 同值）
OCFS2_INDEX_FL = 0x00001000

# i_dyn_features
OCFS2_INLINE_DATA_FL = 0x0001
OCFS2_HAS_XATTR_FL = 0x0002
OCFS2_INLINE_XATTR_FL = 0x0004
OCFS2_INDEXED_DIR_FL = 0x0008
OCFS2_HAS_REFCOUNT_FL = 0x0010

# extent rec 的 e_flags
OCFS2_EXT_UNWRITTEN = 0x01
OCFS2_EXT_REFCOUNTED = 0x02

# 特性位
FEAT_INCOMPAT = {
    0x0001: "LOCAL_ALLOC",
    0x0002: "HEARTBEAT_DEV",
    0x0004: "RESIZE_INPROG",
    0x0008: "LOCAL_MOUNT",
    0x0010: "SPARSE_ALLOC",
    0x0020: "TUNEFS_INPROG",
    0x0040: "INLINE_DATA",
    0x0080: "USERSPACE_STACK",
    0x0100: "EXTENDED_SLOT_MAP",
    0x0200: "XATTR",
    0x0400: "INDEXED_DIRS",
    0x0800: "META_ECC",
    0x1000: "REFCOUNT_TREE",
    0x2000: "DISCONTIG_BG",
    0x4000: "CLUSTERINFO",
    0x8000: "APPEND_DIO",
}
FEAT_COMPAT = {
    0x0001: "BACKUP_SB",
    0x0002: "JBD2_SB",
}
FEAT_RO_COMPAT = {
    0x0001: "UNWRITTEN",
    0x0002: "USRQUOTA",
    0x0004: "GRPQUOTA",
}
FEATURE_INCOMPAT_INDEXED_DIRS = 0x0400
FEATURE_INCOMPAT_INLINE_DATA = 0x0040

# ---------------------------------------------------------------- 偏移
# ocfs2_dinode（ocfs2_fs.h L663-736），全小端
DI_SIGNATURE = 0x00
DI_GENERATION = 0x08
DI_SUBALLOC_SLOT = 0x0C
DI_SUBALLOC_BIT = 0x0E
DI_LINKS_COUNT_HI = 0x10
DI_XATTR_INLINE_SIZE = 0x12
DI_CLUSTERS = 0x14
DI_UID = 0x18
DI_GID = 0x1C
DI_SIZE = 0x20
DI_MODE = 0x28
DI_LINKS_COUNT = 0x2A
DI_FLAGS = 0x2C
DI_ATIME = 0x30
DI_CTIME = 0x38
DI_MTIME = 0x40
DI_DTIME = 0x48
DI_BLKNO = 0x50
DI_LAST_EB_BLK = 0x58
DI_FS_GENERATION = 0x60
DI_ATIME_NSEC = 0x64
DI_CTIME_NSEC = 0x68
DI_MTIME_NSEC = 0x6C
DI_ATTR = 0x70
DI_ORPHANED_SLOT = 0x74
DI_DYN_FEATURES = 0x76
DI_XATTR_LOC = 0x78
DI_CHECK = 0x80
DI_DX_ROOT = 0x88
DI_REFCOUNT_LOC = 0x90
DI_SUBALLOC_LOC = 0x98
DI_ID1 = 0xB8
DI_ID2 = 0xC0

# ocfs2_super_block，偏移相对 id2（绝对 = 0xC0 + 下值）
SB_MAJOR = 0x00
SB_MINOR = 0x02
SB_MNT_COUNT = 0x04
SB_MAX_MNT_COUNT = 0x06
SB_STATE = 0x08
SB_ERRORS = 0x0A
SB_CHECKINTERVAL = 0x0C
SB_LASTCHECK = 0x10
SB_CREATOR_OS = 0x18
SB_FEATURE_COMPAT = 0x1C
SB_FEATURE_INCOMPAT = 0x20
SB_FEATURE_RO_COMPAT = 0x24
SB_ROOT_BLKNO = 0x28
SB_SYSTEM_DIR_BLKNO = 0x30
SB_BLOCKSIZE_BITS = 0x38
SB_CLUSTERSIZE_BITS = 0x3C
SB_MAX_SLOTS = 0x40
SB_TUNEFS_FLAG = 0x42
SB_UUID_HASH = 0x44
SB_FIRST_CLUSTER_GROUP = 0x48
SB_LABEL = 0x50
SB_LABEL_LEN = 64
SB_UUID = 0x90
SB_UUID_LEN = 16
SB_CLUSTER_INFO = 0xA0
SB_XATTR_INLINE_SIZE = 0xB8

# ocfs2_extent_list，偏移相对 id2.i_list 或 extent_block.h_list
EL_TREE_DEPTH = 0x00
EL_COUNT = 0x02
EL_NEXT_FREE_REC = 0x04
EL_RESERVED1 = 0x06
EL_RESERVED2 = 0x08
EL_RECS = 0x10
EXTENT_REC_SIZE = 0x10

# ocfs2_extent_block（ocfs2_fs.h L506-525）
EB_SIGNATURE = 0x00
EB_CHECK = 0x08
EB_SUBALLOC_SLOT = 0x10
EB_SUBALLOC_BIT = 0x12
EB_FS_GENERATION = 0x14
EB_BLKNO = 0x18
EB_SUBALLOC_LOC = 0x20
EB_NEXT_LEAF = 0x28
EB_LIST = 0x30

# ocfs2_chain_list，偏移相对 id2.i_chain
CL_CPG = 0x00
CL_BPC = 0x02
CL_COUNT = 0x04
CL_NEXT_FREE_REC = 0x06
CL_RESERVED1 = 0x08
CL_RECS = 0x10
CHAIN_REC_SIZE = 0x10

# ocfs2_group_desc（ocfs2_fs.h L880-922）
BG_SIGNATURE = 0x00
BG_SIZE = 0x08
BG_BITS = 0x0A
BG_FREE_BITS = 0x0C
BG_CHAIN = 0x0E
BG_GENERATION = 0x10
BG_CONTIG_FREE = 0x14
BG_RESERVED1 = 0x16
BG_NEXT_GROUP = 0x18
BG_PARENT_DINODE = 0x20
BG_BLKNO = 0x28
BG_CHECK = 0x30
BG_RESERVED2 = 0x38
BG_BITMAP = 0x40
BG_LIST = 0x140

# ocfs2_dir_entry（packed）+ ocfs2_dir_block_trailer
DE_INODE = 0x00
DE_REC_LEN = 0x08
DE_NAME_LEN = 0x0A
DE_FILE_TYPE = 0x0B
DE_NAME = 0x0C
DE_MIN_SIZE = 0x0C
DIR_TRAILER_SIZE = 0x40
DIR_TRAILER_SIG = 0x10

# ocfs2_inline_data（相对 id2）
ID_COUNT = 0x00
ID_DATA = 0x08

OCFS2_MAX_SLOTS = 255
OCFS2_BACKUP_SB_START = 1 << 30
OCFS2_MAX_BACKUP_SUPERBLOCKS = 6

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000

# ocfs2_dir_entry.file_type：ocfs2_fs.h 未给枚举，与 ext2 dirent 同布局，
# 故沿用 ext2 的 EXT2_FT_* 取值（推断，见模块 docstring）。
FT_NAMES = {
    0: "unknown", 1: "reg", 2: "dir", 3: "chr", 4: "blk",
    5: "fifo", 6: "sock", 7: "symlink",
}

CAPS = {
    "superblock": True,        # 主份 + 备份扫描
    "chain_list": True,        # 头字段 + group_desc 计数；位图未逐位解析
    "bitmap_bits": False,
    "inode": True,
    "inline_data": True,
    "extent_inline": True,     # l_tree_depth == 0
    "extent_tree": True,       # l_tree_depth > 0，递归 EXBLK01
    "dir_linear": True,        # inline 目录 / extent 目录 / DIRTRL1 尾块
    "dir_indexed": False,      # DXDIR01/DXLEAF1 未实现，抛 NotImplementedError
    "symlink_target": False,
    "xattr": False,
    "refcount": False,
    "journal": False,
}


class Ocfs2Error(ValueError):
    """结构损坏、偏移越界或输入被截断。"""


# ---------------------------------------------------------------- 取值助手
def _u8(buf, off):
    if off + 1 > len(buf):
        raise Ocfs2Error("读取越界：需要 u8@%#x，缓冲仅 %d 字节" % (off, len(buf)))
    return buf[off]


def _u16(buf, off):
    if off + 2 > len(buf):
        raise Ocfs2Error("读取越界：需要 u16@%#x，缓冲仅 %d 字节" % (off, len(buf)))
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    if off + 4 > len(buf):
        raise Ocfs2Error("读取越界：需要 u32@%#x，缓冲仅 %d 字节" % (off, len(buf)))
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    if off + 8 > len(buf):
        raise Ocfs2Error("读取越界：需要 u64@%#x，缓冲仅 %d 字节" % (off, len(buf)))
    return struct.unpack_from("<Q", buf, off)[0]


def _cstr(raw):
    """NUL 结尾的定长字段转字符串。"""
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    return raw.decode("utf-8", "replace")


def _ts(sec, nsec):
    """OCFS2 时间戳：u64 秒 + u32 纳秒（分字段存放）。"""
    if not sec:
        return None
    try:
        base = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        return base + datetime.timedelta(seconds=int(sec),
                                         microseconds=int(nsec) // 1000)
    except (OverflowError, ValueError, OSError):
        return None


def _feat_names(value, table):
    return [name for bit, name in sorted(table.items()) if value & bit]


def _mode_str(mode):
    return "%s%04o" % ("d" if (mode & S_IFMT) == S_IFDIR else "-", mode & 0o7777)


# ---------------------------------------------------------------- 主类
class Ocfs2:
    """OCFS2 只读解析。sub 需提供 .read(offset, size) 与 .size。"""

    MAX_TREE_DEPTH = 8
    MAX_GROUP_WALK = 1 << 16

    def __init__(self, sub):
        self.sub = sub
        size = getattr(sub, "size", None)
        if size is None:
            raise Ocfs2Error("sub 缺少 size 属性")
        self.size = int(size)
        if self.size < 0x200:
            raise Ocfs2Error("输入过短（%d 字节），不足以容纳超级块" % self.size)
        self.sb_offset, body = self._locate_sb()
        self._adopt_sb(self._parse_sb(body, self.sb_offset, "primary"))

    # ------------------------------------------------------------ 超级块
    def _sb_candidates(self):
        """超级块候选偏移。

        ocfs2_fs.h L27-30：OCFS2_SUPER_BLOCK_BLKNO = 2，单位是“块不是扇区”，
        故字节偏移 = 2 * blocksize，随块大小变化；同时接受规范给出的块 0。
        """
        offs = [0]
        for bits in (9, 10, 11, 12):
            offs.append(2 << bits)
        return offs

    def _locate_sb(self):
        for off in self._sb_candidates():
            if off + 0x200 > self.size:
                continue
            head = self.sub.read(off, 8) or b""
            if not head.startswith(SIG_SB_MAGIC):
                continue
            body = self.sub.read(off, 0x200) or b""
            if len(body) < 0x200:
                continue
            if self._sb_sane(body):
                return off, body
        raise Ocfs2Error("未找到 OCFS2 超级块（签名 OCFSV2）")

    @staticmethod
    def _sb_sane(body):
        flags = _u32(body, DI_FLAGS)
        bs_bits = _u32(body, DI_ID2 + SB_BLOCKSIZE_BITS)
        cs_bits = _u32(body, DI_ID2 + SB_CLUSTERSIZE_BITS)
        slots = _u16(body, DI_ID2 + SB_MAX_SLOTS)
        root = _u64(body, DI_ID2 + SB_ROOT_BLKNO)
        if not (flags & OCFS2_SUPER_BLOCK_FL):
            return False
        if not (flags & OCFS2_VALID_FL):
            return False
        if not (9 <= bs_bits <= 12):
            return False
        if not (12 <= cs_bits <= 20):
            return False
        if cs_bits < bs_bits:
            return False
        if not (1 <= slots <= OCFS2_MAX_SLOTS):
            return False
        return root != 0

    def _parse_sb(self, body, offset, kind):
        b = DI_ID2
        fid = uuid.UUID(bytes=bytes(body[b + SB_UUID:b + SB_UUID + SB_UUID_LEN]))
        info = {
            "kind": kind,
            "offset": offset,
            "signature": bytes(body[DI_SIGNATURE:DI_SIGNATURE + 8]),
            "major": _u16(body, b + SB_MAJOR),
            "minor": _u16(body, b + SB_MINOR),
            "mnt_count": _u16(body, b + SB_MNT_COUNT),
            "max_mnt_count": _u16(body, b + SB_MAX_MNT_COUNT),
            "state": _u16(body, b + SB_STATE),
            "errors": _u16(body, b + SB_ERRORS),
            "checkinterval": _u32(body, b + SB_CHECKINTERVAL),
            "lastcheck": _ts(_u64(body, b + SB_LASTCHECK), 0),
            "creator_os": _u32(body, b + SB_CREATOR_OS),
            "feature_compat": _u32(body, b + SB_FEATURE_COMPAT),
            "feature_incompat": _u32(body, b + SB_FEATURE_INCOMPAT),
            "feature_ro_compat": _u32(body, b + SB_FEATURE_RO_COMPAT),
            "root_blkno": _u64(body, b + SB_ROOT_BLKNO),
            "system_dir_blkno": _u64(body, b + SB_SYSTEM_DIR_BLKNO),
            "blocksize_bits": _u32(body, b + SB_BLOCKSIZE_BITS),
            "clustersize_bits": _u32(body, b + SB_CLUSTERSIZE_BITS),
            "max_slots": _u16(body, b + SB_MAX_SLOTS),
            "tunefs_flag": _u16(body, b + SB_TUNEFS_FLAG),
            "uuid_hash": _u32(body, b + SB_UUID_HASH),
            "first_cluster_group": _u64(body, b + SB_FIRST_CLUSTER_GROUP),
            "label": _cstr(bytes(body[b + SB_LABEL:b + SB_LABEL + SB_LABEL_LEN])),
            "uuid_raw": bytes(body[b + SB_UUID:b + SB_UUID + SB_UUID_LEN]),
            "uuid": str(fid),
            "xattr_inline_size": _u16(body, b + SB_XATTR_INLINE_SIZE),
            "dinode_flags": _u32(body, DI_FLAGS),
            "fs_generation": _u32(body, DI_FS_GENERATION),
            "i_blkno": _u64(body, DI_BLKNO),
        }
        info["block_size"] = 1 << info["blocksize_bits"]
        info["cluster_size"] = 1 << info["clustersize_bits"]
        info["blocks_per_cluster"] = max(1, info["cluster_size"] // info["block_size"])
        info["features"] = {
            "compat": _feat_names(info["feature_compat"], FEAT_COMPAT),
            "incompat": _feat_names(info["feature_incompat"], FEAT_INCOMPAT),
            "ro_compat": _feat_names(info["feature_ro_compat"], FEAT_RO_COMPAT),
        }
        return info

    def _adopt_sb(self, info):
        self.sb = info
        self.label = info["label"]
        self.uuid_raw = info["uuid_raw"]
        self.uuid = info["uuid"]
        self.major = info["major"]
        self.minor = info["minor"]
        self.block_size = info["block_size"]
        self.cluster_size = info["cluster_size"]
        self.blocks_per_cluster = info["blocks_per_cluster"]
        self.max_slots = info["max_slots"]
        self.root_blkno = info["root_blkno"]
        self.system_dir_blkno = info["system_dir_blkno"]
        self.feature_compat = info["feature_compat"]
        self.feature_incompat = info["feature_incompat"]
        self.feature_ro_compat = info["feature_ro_compat"]
        self.fs_generation = info["fs_generation"]
        self.indexed_dirs = bool(self.feature_incompat & FEATURE_INCOMPAT_INDEXED_DIRS)

    def info(self):
        d = dict(self.sb)
        d["sb_offset"] = self.sb_offset
        d["label"] = self.label
        d["uuid"] = self.uuid
        d["block_size"] = self.block_size
        d["cluster_size"] = self.cluster_size
        d["blocks_per_cluster"] = self.blocks_per_cluster
        d["max_slots"] = self.max_slots
        d["root_blkno"] = self.root_blkno
        d["system_dir_blkno"] = self.system_dir_blkno
        d["caps"] = dict(CAPS)
        return d

    def superblocks(self):
        """主份 + 备份超级块（备份位置为推断：第 (1<<30)+i 簇）。"""
        out = [dict(self.sb)]
        for i in range(OCFS2_MAX_BACKUP_SUPERBLOCKS):
            off = (OCFS2_BACKUP_SB_START + i) * self.cluster_size
            if off + 0x200 > self.size:
                break
            head = self.sub.read(off, 8) or b""
            if not head.startswith(SIG_SB_MAGIC):
                continue
            body = self.sub.read(off, 0x200) or b""
            if len(body) < 0x200 or not self._sb_sane(body):
                continue
            try:
                out.append(self._parse_sb(body, off, "backup"))
            except (Ocfs2Error, ValueError):
                continue
        return out

    # ------------------------------------------------------------ 底层读
    def _read(self, off, n):
        if n < 0 or off < 0:
            raise Ocfs2Error("非法读取：off=%r n=%r" % (off, n))
        if n == 0:
            return b""
        data = self.sub.read(off, n)
        data = b"" if data is None else data
        if len(data) != n:
            raise Ocfs2Error(
                "输入被截断：偏移 %#x 需要 %d 字节，仅得到 %d（镜像 %d 字节）"
                % (off, n, len(data), self.size))
        return data

    def _blk_off(self, blkno):
        """块号 → 字节偏移。

        i_blkno / e_blkno / bg_blkno 在 ocfs2_fs.h 中均标注 "in blocks"，
        故用 blkno << blocksize_bits。OCFS2 元数据按簇分配并对齐，
        因此本式与“集群号 × 集群大小”在合法镜像上恒等；
        非簇对齐的 blkno 只有本式成立（另一式会放大约 blocks_per_cluster 倍）。
        """
        if blkno < 0:
            raise Ocfs2Error("非法块号 %r" % (blkno,))
        return blkno * self.block_size

    def _cluster_off(self, cluster):
        """集群号 → 字节偏移（仅供按簇编号定位时使用）。"""
        return cluster * self.cluster_size

    def _read_meta(self, blkno):
        """读一个元数据块（inode / extent block / group desc 均占一簇）。"""
        off = self._blk_off(blkno)
        if off >= self.size:
            raise Ocfs2Error("块号 %#x 超出镜像（偏移 %#x >= %d）"
                             % (blkno, off, self.size))
        n = min(self.cluster_size, self.size - off)
        if n < 0x200:
            raise Ocfs2Error("块号 %#x 处剩余 %d 字节，不足以容纳元数据"
                             % (blkno, n))
        data = self.sub.read(off, n)
        return b"" if data is None else data

    def _read_dinode(self, blkno):
        buf = self._read_meta(blkno)
        sig = bytes(buf[0:8])
        if sig not in SIGS_SB and sig != SIG_DINODE:
            raise Ocfs2Error("块号 %#x 不是 dinode（签名 %r）" % (blkno, sig))
        return buf

    # ------------------------------------------------------------ inode
    def inode(self, blkno):
        buf = self._read_dinode(blkno)
        flags = _u32(buf, DI_FLAGS)
        dyn = _u16(buf, DI_DYN_FEATURES)
        mode = _u16(buf, DI_MODE)
        size = _u64(buf, DI_SIZE)
        raw_uid = _u32(buf, DI_UID)
        raw_gid = _u32(buf, DI_GID)
        atime = _u64(buf, DI_ATIME)
        ctime = _u64(buf, DI_CTIME)
        mtime = _u64(buf, DI_MTIME)
        d = {
            "blkno": blkno,
            "signature": bytes(buf[0:8]),
            "generation": _u32(buf, DI_GENERATION),
            "fs_generation": _u32(buf, DI_FS_GENERATION),
            "suballoc_slot": _u16(buf, DI_SUBALLOC_SLOT),
            "suballoc_bit": _u16(buf, DI_SUBALLOC_BIT),
            "clusters": _u32(buf, DI_CLUSTERS),
            # mainline 是 __le32 i_uid/i_gid；旧 16 位布局共用同一槽位，
            # 故同时给出 16 位视图（uid16@0x18 / gid16@0x1C）。
            "uid": raw_uid,
            "gid": raw_gid,
            "uid_lo16": raw_uid & 0xFFFF,
            "uid_hi16": (raw_uid >> 16) & 0xFFFF,
            "gid_lo16": raw_gid & 0xFFFF,
            "gid_hi16": (raw_gid >> 16) & 0xFFFF,
            "size": size,
            "mode": mode,
            "mode_str": _mode_str(mode),
            "is_dir": (mode & S_IFMT) == S_IFDIR,
            "is_reg": (mode & S_IFMT) == S_IFREG,
            "links": ((_u16(buf, DI_LINKS_COUNT_HI) << 16)
                      | _u16(buf, DI_LINKS_COUNT)),
            "flags": flags,
            "flag_names": self._flag_names(flags),
            "dyn_features": dyn,
            "inline_data": bool(dyn & OCFS2_INLINE_DATA_FL),
            "indexed_dir": bool(dyn & OCFS2_INDEXED_DIR_FL),
            "has_xattr": bool(dyn & OCFS2_HAS_XATTR_FL),
            "has_refcount": bool(dyn & OCFS2_HAS_REFCOUNT_FL),
            "atime": _ts(atime, _u32(buf, DI_ATIME_NSEC)),
            "ctime": _ts(ctime, _u32(buf, DI_CTIME_NSEC)),
            "mtime": _ts(mtime, _u32(buf, DI_MTIME_NSEC)),
            "dtime": _ts(_u64(buf, DI_DTIME), 0),
            "atime_raw": atime,
            "ctime_raw": ctime,
            "mtime_raw": mtime,
            "last_eb_blk": _u64(buf, DI_LAST_EB_BLK),
            "dx_root": _u64(buf, DI_DX_ROOT),
            "xattr_loc": _u64(buf, DI_XATTR_LOC),
            "refcount_loc": _u64(buf, DI_REFCOUNT_LOC),
            "suballoc_loc": _u64(buf, DI_SUBALLOC_LOC),
            "is_super": bool(flags & OCFS2_SUPER_BLOCK_FL),
            "is_chain": bool(flags & OCFS2_CHAIN_FL),
        }
        if d["indexed_dir"] or (flags & OCFS2_INDEX_FL):
            # 索引目录的目录项在 DX 树里，未实现；这里只标注，读取时再抛
            d["extents"] = []
        elif d["is_chain"]:
            d["extents"] = []
        else:
            d["extents"] = self._extent_recs(buf, DI_ID2)
        d["extent_count"] = len(d["extents"])
        d["tree_depth"] = _u16(buf, DI_ID2 + EL_TREE_DEPTH)
        return d

    @staticmethod
    def _flag_names(flags):
        table = [
            (OCFS2_VALID_FL, "VALID"), (OCFS2_ORPHANED_FL, "ORPHANED"),
            (OCFS2_SYSTEM_FL, "SYSTEM"), (OCFS2_SUPER_BLOCK_FL, "SUPER_BLOCK"),
            (OCFS2_LOCAL_ALLOC_FL, "LOCAL_ALLOC"), (OCFS2_BITMAP_FL, "BITMAP"),
            (OCFS2_JOURNAL_FL, "JOURNAL"), (OCFS2_HEARTBEAT_FL, "HEARTBEAT"),
            (OCFS2_CHAIN_FL, "CHAIN"), (OCFS2_DEALLOC_FL, "DEALLOC"),
            (OCFS2_QUOTA_FL, "QUOTA"),
        ]
        return [name for bit, name in table if flags & bit]

    # ------------------------------------------------------------ extent
    def _extent_recs(self, buf, base):
        """展开 extent_list，返回叶子记录列表（按 cpos 排序）。

        ocfs2_fs.h L426-439：e_int_clusters 与 (e_leaf_clusters u16 +
        e_reserved1 u8 + e_flags u8) 是同 4 字节 union，故不论深度都先读
        u32；叶子取低 16 位为簇数、第 4 字节为 flags。
        """
        if base + EL_RECS > len(buf):
            return []
        tree_depth = _u16(buf, base + EL_TREE_DEPTH)
        count = _u16(buf, base + EL_COUNT)
        used = _u16(buf, base + EL_NEXT_FREE_REC)
        used = min(used, count)
        if used <= 0:
            return []
        if tree_depth > self.MAX_TREE_DEPTH:
            raise Ocfs2Error("extent 树深 %d 超限" % tree_depth)
        out = []
        for i in range(used):
            p = base + EL_RECS + i * EXTENT_REC_SIZE
            if p + EXTENT_REC_SIZE > len(buf):
                raise Ocfs2Error("extent 记录 %d 越界" % i)
            cpos = _u32(buf, p)
            raw = _u32(buf, p + 4)
            blkno = _u64(buf, p + 8)
            if tree_depth == 0:
                out.append({
                    "cpos": cpos,
                    "clusters": raw & 0xFFFF,
                    "flags": (raw >> 24) & 0xFF,
                    "unwritten": bool(((raw >> 24) & 0xFF) & OCFS2_EXT_UNWRITTEN),
                    "blkno": blkno,
                    "interior": False,
                })
            else:
                out.append({
                    "cpos": cpos,
                    "clusters": raw,          # e_int_clusters：子树覆盖簇数
                    "flags": 0,
                    "unwritten": False,
                    "blkno": blkno,
                    "interior": True,
                })
                out.extend(self._tree_children(blkno, tree_depth))
        out.sort(key=lambda r: (r["cpos"], r["blkno"]))
        return out

    def _tree_children(self, blkno, depth, seen=None):
        seen = seen if seen is not None else set()
        if blkno in seen:
            raise Ocfs2Error("extent 树成环（块 %#x）" % blkno)
        seen.add(blkno)
        buf = self._read_meta(blkno)
        sig = bytes(buf[0:8])
        if sig not in SIGS_EB:
            raise Ocfs2Error("块 %#x 不是 extent block（签名 %r）" % (blkno, sig))
        child_depth = _u16(buf, EB_LIST + EL_TREE_DEPTH)
        if child_depth != depth - 1:
            raise Ocfs2Error("extent block %#x 深度不一致：%d != %d"
                             % (blkno, child_depth, depth - 1))
        recs = []
        count = _u16(buf, EB_LIST + EL_COUNT)
        used = min(_u16(buf, EB_LIST + EL_NEXT_FREE_REC), count)
        for i in range(used):
            p = EB_LIST + EL_RECS + i * EXTENT_REC_SIZE
            if p + EXTENT_REC_SIZE > len(buf):
                raise Ocfs2Error("extent block %#x 记录越界" % blkno)
            cpos = _u32(buf, p)
            raw = _u32(buf, p + 4)
            child = _u64(buf, p + 8)
            if child_depth == 0:
                recs.append({
                    "cpos": cpos, "clusters": raw & 0xFFFF,
                    "flags": (raw >> 24) & 0xFF,
                    "unwritten": bool(((raw >> 24) & 0xFF) & OCFS2_EXT_UNWRITTEN),
                    "blkno": child, "interior": False,
                })
            else:
                recs.append({
                    "cpos": cpos, "clusters": raw, "flags": 0,
                    "unwritten": False, "blkno": child, "interior": True,
                })
                recs.extend(self._tree_children(child, child_depth, seen))
        return recs

    # ------------------------------------------------------------ 文件读取
    def _inline_data(self, buf, size):
        count = _u16(buf, DI_ID2 + ID_COUNT)
        start = DI_ID2 + ID_DATA
        n = min(count, size, max(0, len(buf) - start))
        return bytes(buf[start:start + n])

    def _extent_data(self, recs, size):
        out = bytearray(size)
        for r in recs:
            if r.get("interior"):
                continue
            loff = r["cpos"] * self.cluster_size
            if loff >= size:
                continue
            n = min(r["clusters"] * self.cluster_size, size - loff)
            if n <= 0:
                continue
            if r.get("unwritten"):
                continue                      # 未写入区保持 0
            phys = self._blk_off(r["blkno"])
            out[loff:loff + n] = self._read(phys, n)
        return bytes(out)

    def _dinode_data(self, dino, buf, size):
        if dino["inline_data"]:
            return self._inline_data(buf, size)
        return self._extent_data(dino["extents"], size)

    def read_file(self, ref, size=None):
        """读文件内容。ref 可以是 dinode 块号、inode() 结果或目录项 dict。"""
        if isinstance(ref, dict):
            blkno = ref["blkno"]
        else:
            blkno = int(ref)
        dino = self.inode(blkno)
        buf = self._read_meta(blkno)
        total = dino["size"]
        if size is None:
            size = total
        else:
            size = min(int(size), total)
        if size <= 0:
            return b""
        data = self._dinode_data(dino, buf, size)
        return data[:size]

    # ------------------------------------------------------------ 目录
    def _dir_blocks(self, data):
        """按块切分目录数据，返回 (块起点, 有效上限)。

        每个目录块的尾部可能有 ocfs2_dir_block_trailer（64 字节，签名在
        偏移 0x10 处，即块尾 -0x30），命中则把有效上限收窄。
        """
        bs = self.block_size
        for base in range(0, len(data), bs):
            end = min(base + bs, len(data))
            limit = end
            tsig = end - DIR_TRAILER_SIZE + DIR_TRAILER_SIG
            if (end - base >= DIR_TRAILER_SIZE
                    and bytes(data[tsig:tsig + 8]) == SIG_DIR_TRAILER):
                limit = end - DIR_TRAILER_SIZE
            yield base, limit

    def _parse_dirents(self, data, limit_total=None):
        entries = []
        total = len(data) if limit_total is None else min(len(data), limit_total)
        data = data[:total]
        for base, limit in self._dir_blocks(data):
            pos = base
            while pos + DE_MIN_SIZE <= limit:
                ino = _u64(data, pos)
                rec_len = _u16(data, pos + DE_REC_LEN)
                name_len = data[pos + DE_NAME_LEN]
                ftype = data[pos + DE_FILE_TYPE]
                if rec_len < DE_MIN_SIZE or pos + rec_len > limit:
                    break
                if ino and name_len and DE_NAME + name_len <= rec_len:
                    name = bytes(data[pos + DE_NAME:pos + DE_NAME + name_len])
                    entries.append({
                        "name": name.decode("utf-8", "replace"),
                        "name_raw": name,
                        "inode": ino,
                        "file_type": ftype,
                        "type": FT_NAMES.get(ftype, "type%d" % ftype),
                        "rec_len": rec_len,
                    })
                pos += rec_len
        return entries

    def listdir(self, blkno=None):
        """列目录。未给 blkno 时从根目录开始。"""
        if blkno is None:
            blkno = self.root_blkno
        dino = self.inode(blkno)
        if not dino["is_dir"]:
            raise Ocfs2Error("块 %#x 不是目录（mode=%s）"
                             % (blkno, dino["mode_str"]))
        if dino["indexed_dir"] or (dino["flags"] & OCFS2_INDEX_FL):
            raise NotImplementedError(
                "索引目录（i_dyn_features 带 OCFS2_INDEXED_DIR_FL 或 i_flags 带 "
                "OCFS2_INDEX_FL）未实现：DX 根/叶（%r/%r）与 dx_entry 树未解析，"
                "故块 %#x 的目录项无法枚举" % (SIG_DX_ROOT, SIG_DX_LEAF, blkno))
        buf = self._read_meta(blkno)
        size = dino["size"]
        if size <= 0:
            size = len(buf) - (DI_ID2 + ID_DATA if dino["inline_data"] else 0)
        data = self._dinode_data(dino, buf, max(size, 0))
        return self._parse_dirents(data, size)

    def walk(self, blkno=None):
        """深度优先遍历，产出 {path, blkno, type, size, ...}。"""
        if blkno is None:
            blkno = self.root_blkno
        seen = set()
        stack = [("", blkno, None)]
        while stack:
            prefix, cur, parent = stack.pop()
            key = cur
            if key in seen:
                continue
            seen.add(key)
            try:
                dino = self.inode(cur)
            except Ocfs2Error:
                continue
            path = prefix or "/"
            yield {
                "path": path,
                "blkno": cur,
                "parent": parent,
                "type": "dir" if dino["is_dir"] else (
                    "symlink" if (dino["mode"] & S_IFMT) == S_IFLNK else "reg"),
                "size": dino["size"],
                "mode": dino["mode_str"],
                "uid": dino["uid"],
                "gid": dino["gid"],
                "mtime": dino["mtime"],
            }
            if not dino["is_dir"]:
                continue
            try:
                entries = self.listdir(cur)
            except (NotImplementedError, Ocfs2Error):
                continue
            for ent in entries:
                if ent["name"] in (".", ".."):
                    continue
                child = ent["blkno"] if "blkno" in ent else ent["inode"]
                child_path = (path.rstrip("/") + "/" + ent["name"])
                stack.append((child_path, child, cur))

    def lookup_path(self, path):
        """按路径查目录项，返回目录项 dict（附 blkno）。"""
        parts = [p for p in str(path).replace("\\", "/").split("/") if p]
        cur = self.root_blkno
        ent = None
        for name in parts:
            dino = self.inode(cur)
            if not dino["is_dir"]:
                raise Ocfs2Error("路径 %r 中 %r 不是目录" % (path, name))
            if dino["indexed_dir"] or (dino["flags"] & OCFS2_INDEX_FL):
                raise NotImplementedError("索引目录查找未实现（块 %#x）" % cur)
            found = None
            for e in self.listdir(cur):
                if e["name"] == name:
                    found = e
                    break
            if found is None:
                raise Ocfs2Error("路径不存在：%r（缺 %r）" % (path, name))
            ent = dict(found)
            cur = found["inode"]
        if ent is None:
            return {"blkno": self.root_blkno, "name": "/", "inode": self.root_blkno,
                    "type": "dir", "file_type": 2, "rec_len": 0}
        ent["blkno"] = ent["inode"]
        return ent

    def find(self, pattern):
        """按 fnmatch 通配符在 walk 结果里找路径。"""
        hits = []
        for item in self.walk():
            base = item["path"].rstrip("/").rsplit("/", 1)[-1] or "/"
            if fnmatch.fnmatch(item["path"], pattern) or fnmatch.fnmatch(base, pattern):
                hits.append(item)
        return hits

    # ------------------------------------------------------------ 链列表
    def _find_system_file(self, name):
        for base in (self.system_dir_blkno, self.root_blkno):
            if not base:
                continue
            try:
                for ent in self.listdir(base):
                    if ent["name"] == name:
                        return ent["inode"]
            except (NotImplementedError, Ocfs2Error):
                continue
        return None

    def _group_walk(self, first_blkno, parent_hint=None):
        groups = []
        seen = set()
        cur = first_blkno
        while cur and cur not in seen and len(groups) < self.MAX_GROUP_WALK:
            seen.add(cur)
            buf = self._read_meta(cur)
            sig = bytes(buf[0:8])
            if sig not in SIGS_GD:
                raise Ocfs2Error("块 %#x 不是 group_desc（签名 %r）" % (cur, sig))
            groups.append({
                "blkno": _u64(buf, BG_BLKNO),
                "chain": _u16(buf, BG_CHAIN),
                "size": _u16(buf, BG_SIZE),
                "bits": _u16(buf, BG_BITS),
                "free_bits": _u16(buf, BG_FREE_BITS),
                "contig_free_bits": _u16(buf, BG_CONTIG_FREE),
                "generation": _u32(buf, BG_GENERATION),
                "parent_dinode": _u64(buf, BG_PARENT_DINODE),
                "next_group": _u64(buf, BG_NEXT_GROUP),
                "bitmap_off": BG_BITMAP,
            })
            cur = _u64(buf, BG_NEXT_GROUP)
        return groups

    def chain(self, blkno=None):
        """解析链列表（通常是系统文件 global_bitmap 的 dinode）。

        只给链头字段与每个链的组描述符列表；位图不逐位解析。
        """
        if blkno is None:
            blkno = self._find_system_file("global_bitmap")
            if blkno is None:
                raise Ocfs2Error("未在系统目录/根目录找到 global_bitmap，"
                                 "请显式传链分配器 inode 块号")
        blkno = int(blkno)
        dino = self.inode(blkno)
        if not dino["is_chain"]:
            raise Ocfs2Error("块 %#x 不是链分配器（i_flags 无 OCFS2_CHAIN_FL）" % blkno)
        buf = self._read_meta(blkno)
        base = DI_ID2
        cpg = _u16(buf, base + CL_CPG)
        bpc = _u16(buf, base + CL_BPC)
        count = _u16(buf, base + CL_COUNT)
        next_free = _u16(buf, base + CL_NEXT_FREE_REC)
        used = min(next_free, count)
        chains = []
        for i in range(used):
            p = base + CL_RECS + i * CHAIN_REC_SIZE
            if p + CHAIN_REC_SIZE > len(buf):
                raise Ocfs2Error("链记录 %d 越界" % i)
            c_blkno = _u64(buf, p + 8)
            groups = self._group_walk(c_blkno) if c_blkno else []
            chains.append({
                "index": i,
                "c_free": _u32(buf, p),
                "c_total": _u32(buf, p + 4),
                "c_blkno": c_blkno,
                "groups": groups,
                "group_count": len(groups),
            })
        return {
            "blkno": blkno,
            "cl_cpg": cpg,
            "cl_bpc": bpc,
            "cl_count": count,
            "cl_next_free_rec": next_free,
            "records": used,
            "chains": chains,
            "chain_count": len(chains),
            "group_total": sum(c["group_count"] for c in chains),
            "flags": dino["flags"],
        }


def probe(sub):
    """是否是 OCFS2 卷（只做只读探测，不抛异常）。"""
    try:
        size = int(getattr(sub, "size", 0) or 0)
    except (TypeError, ValueError):
        return False
    if size < 0x200:
        return False
    dummy = Ocfs2.__new__(Ocfs2)
    for off in (0, 512, 1024, 2048, 4096, 8192):
        if off + 0x200 > size:
            continue
        try:
            head = sub.read(off, 8) or b""
            if not head.startswith(SIG_SB_MAGIC):
                continue
            head8 = bytes(head[:8])
            if head8 not in SIGS_SB and head8 != SIG_SB_MAGIC + b"\x00\x00":
                # 允许其它补齐方式，但仍要求前 6 字节 magic
                if not head8.startswith(SIG_SB_MAGIC):
                    continue
            body = sub.read(off, 0x200) or b""
        except Exception:
            continue
        if len(body) < 0x200:
            continue
        try:
            if Ocfs2._sb_sane(body):
                return True
        except Ocfs2Error:
            continue
    return False


def open_fs(sub):
    """打开 OCFS2 卷，返回 Ocfs2 实例。"""
    return Ocfs2(sub)


# ---------------------------------------------------------------- 自检
class _MemSub:
    """自检用的内存 sub，接口与 mkit.image.SubImage 一致。"""

    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)
        self.offset = 0

    def read(self, offset, size):
        if offset < 0 or size <= 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + size]


def _put(buf, off, fmt, value):
    struct.pack_into(fmt, buf, off, value)


def _mk_dinode(mode=0o100644, size=0, blkno=0, flags=OCFS2_VALID_FL,
               dyn=0, uid=1000, gid=1000, links=1, clusters=1,
               atime=1700000000, ctime=1700000100, mtime=1700000200,
               bs=4096):
    b = bytearray(bs)
    b[0:8] = SIG_DINODE
    _put(b, DI_GENERATION, "<I", 0x11223344)
    _put(b, DI_CLUSTERS, "<I", clusters)
    _put(b, DI_UID, "<I", uid)
    _put(b, DI_GID, "<I", gid)
    _put(b, DI_SIZE, "<Q", size)
    _put(b, DI_MODE, "<H", mode)
    _put(b, DI_LINKS_COUNT, "<H", links & 0xFFFF)
    _put(b, DI_LINKS_COUNT_HI, "<H", (links >> 16) & 0xFFFF)
    _put(b, DI_FLAGS, "<I", flags)
    _put(b, DI_ATIME, "<Q", atime)
    _put(b, DI_CTIME, "<Q", ctime)
    _put(b, DI_MTIME, "<Q", mtime)
    _put(b, DI_BLKNO, "<Q", blkno)
    _put(b, DI_ATIME_NSEC, "<I", 123456789)
    _put(b, DI_CTIME_NSEC, "<I", 222000000)
    _put(b, DI_MTIME_NSEC, "<I", 333000000)
    _put(b, DI_FS_GENERATION, "<I", 0xA1B2C3D4)
    _put(b, DI_DYN_FEATURES, "<H", dyn)
    return b


def _mk_sb(label="ESK-OCFS2", root_blkno=1, sys_blkno=6, max_slots=8,
           bs_bits=12, cs_bits=12, incompat=FEATURE_INCOMPAT_INLINE_DATA,
           uuid_bytes=b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"):
    b = _mk_dinode(mode=0o040755, size=1 << cs_bits, blkno=0, clusters=2,
                   flags=OCFS2_VALID_FL | OCFS2_SYSTEM_FL | OCFS2_SUPER_BLOCK_FL,
                   bs=1 << bs_bits)
    # _mk_dinode 写的是普通 inode 签名（SIG_DINODE），超级块必须把它覆盖成
    # "OCFSV2  "（8 字节、两个尾随空格），否则 _locate_sb 永远匹配不上。
    b[0:8] = SIG_SB
    base = DI_ID2
    _put(b, base + SB_MAJOR, "<H", 1)
    _put(b, base + SB_MINOR, "<H", 0)
    _put(b, base + SB_MNT_COUNT, "<H", 3)
    _put(b, base + SB_MAX_MNT_COUNT, "<H", 20)
    _put(b, base + SB_STATE, "<H", 0)
    _put(b, base + SB_ERRORS, "<H", 1)
    _put(b, base + SB_CHECKINTERVAL, "<I", 15552000)
    _put(b, base + SB_LASTCHECK, "<Q", 1700000000)
    _put(b, base + SB_CREATOR_OS, "<I", 0)
    _put(b, base + SB_FEATURE_COMPAT, "<I", 0x0003)
    _put(b, base + SB_FEATURE_INCOMPAT, "<I", incompat)
    _put(b, base + SB_FEATURE_RO_COMPAT, "<I", 0x0001)
    _put(b, base + SB_ROOT_BLKNO, "<Q", root_blkno)
    _put(b, base + SB_SYSTEM_DIR_BLKNO, "<Q", sys_blkno)
    _put(b, base + SB_BLOCKSIZE_BITS, "<I", bs_bits)
    _put(b, base + SB_CLUSTERSIZE_BITS, "<I", cs_bits)
    _put(b, base + SB_MAX_SLOTS, "<H", max_slots)
    _put(b, base + SB_UUID_HASH, "<I", 0xDEADBEEF)
    _put(b, base + SB_FIRST_CLUSTER_GROUP, "<Q", 8)
    lab = label.encode("utf-8")[:SB_LABEL_LEN]
    b[base + SB_LABEL:base + SB_LABEL + len(lab)] = lab
    assert len(uuid_bytes) == 16
    b[base + SB_UUID:base + SB_UUID + 16] = uuid_bytes
    _put(b, base + SB_XATTR_INLINE_SIZE, "<H", 0)
    return b


def _mk_extent_list(buf, base, depth, recs, count=None):
    """recs: [(cpos, clusters_or_int, blkno, flags)]"""
    if count is None:
        count = max(1, (len(buf) - base - EL_RECS) // EXTENT_REC_SIZE)
    _put(buf, base + EL_TREE_DEPTH, "<H", depth)
    _put(buf, base + EL_COUNT, "<H", count)
    _put(buf, base + EL_NEXT_FREE_REC, "<H", len(recs))
    for i, (cpos, clusters, blkno, flags) in enumerate(recs):
        p = base + EL_RECS + i * EXTENT_REC_SIZE
        _put(buf, p, "<I", cpos)
        _put(buf, p + 4, "<I", (clusters & 0xFFFF) | ((flags & 0xFF) << 24)
             if depth == 0 else clusters)
        _put(buf, p + 8, "<Q", blkno)


def _mk_dirents(entries):
    out = bytearray()
    for name, ino, ftype in entries:
        nb = name.encode("utf-8")
        rec_len = (DE_NAME + len(nb) + 3) & ~3
        e = bytearray(rec_len)
        _put(e, DE_INODE, "<Q", ino)
        _put(e, DE_REC_LEN, "<H", rec_len)
        e[DE_NAME_LEN] = len(nb)
        e[DE_FILE_TYPE] = ftype
        e[DE_NAME:DE_NAME + len(nb)] = nb
        out += e
    return bytes(out)


def _mk_gd(blkno, parent, next_group, chain=0, bits=8192, free_bits=4096):
    b = bytearray(4096)
    b[0:8] = SIG_GD
    _put(b, BG_SIZE, "<H", 256)
    _put(b, BG_BITS, "<H", bits)
    _put(b, BG_FREE_BITS, "<H", free_bits)
    _put(b, BG_CHAIN, "<H", chain)
    _put(b, BG_GENERATION, "<I", 0x5A5A5A5A)
    _put(b, BG_NEXT_GROUP, "<Q", next_group)
    _put(b, BG_PARENT_DINODE, "<Q", parent)
    _put(b, BG_BLKNO, "<Q", blkno)
    return b


def _mk_eb(blkno, depth, recs, bs=4096):
    b = bytearray(bs)
    b[0:8] = SIG_EB
    _put(b, EB_BLKNO, "<Q", blkno)
    _put(b, EB_FS_SIGNATURE if False else EB_FS_GENERATION, "<I", 0xA1B2C3D4)
    _mk_extent_list(b, EB_LIST, depth, recs)
    return b


def _build_image():
    BS = 4096
    CS = 4096
    blocks = {}

    # 0 超级块
    blocks[0] = _mk_sb(label="取证测试卷 OCFS2")
    # 1 根目录（inline data）
    root_entries = _mk_dirents([
        (".", 1, 2),
        ("..", 1, 2),
        ("文档.txt", 3, 1),
        ("子目录", 2, 2),
        ("big.bin", 4, 1),
        ("索引目录", 16, 2),
    ])
    b = _mk_dinode(mode=0o040755, size=len(root_entries), blkno=1,
                   dyn=OCFS2_INLINE_DATA_FL, links=3, clusters=1)
    _put(b, DI_ID2 + ID_COUNT, "<H", len(root_entries))
    b[DI_ID2 + ID_DATA:DI_ID2 + ID_DATA + len(root_entries)] = root_entries
    blocks[1] = b

    # 2 子目录（extent 目录，数据在块 12）
    b = _mk_dinode(mode=0o040755, size=CS, blkno=2, links=2, clusters=1)
    _mk_extent_list(b, DI_ID2, 0, [(0, 1, 12, 0)])
    blocks[2] = b
    sub_entries = _mk_dirents([
        (".", 2, 2),
        ("..", 1, 2),
        ("线性目录.txt", 3, 1),
        ("深层目录", 16, 2),
    ])
    data = bytearray(BS)
    data[0:len(sub_entries)] = sub_entries
    # 目录块尾加 DIRTRL1，验证尾块收缩逻辑
    tr = BS - DIR_TRAILER_SIZE
    data[tr + DIR_TRAILER_SIG:tr + DIR_TRAILER_SIG + 8] = SIG_DIR_TRAILER
    _put(data, tr + 0x28, "<Q", 12)          # db_blkno
    blocks[12] = data

    # 3 文件（inline extent，数据在块 13）
    payload = ("OCFS2 内联 extent 测试 / inline extent payload\n" * 20).encode()
    payload = payload[:BS]
    payload = payload + b"\x00" * (BS - len(payload))
    b = _mk_dinode(mode=0o100644, size=BS, blkno=3, clusters=1)
    _mk_extent_list(b, DI_ID2, 0, [(0, 1, 13, 0)])
    blocks[3] = b
    blocks[13] = payload

    # 4 文件（l_tree_depth=1，EB 在 5，数据块 14/15）
    d1 = bytes((i * 7 + 11) & 0xFF for i in range(BS))
    d2 = bytes((i * 13 + 29) & 0xFF for i in range(BS))
    b = _mk_dinode(mode=0o100644, size=2 * CS, blkno=4, clusters=2)
    _mk_extent_list(b, DI_ID2, 1, [(0, 2, 5, 0)])
    blocks[4] = b
    blocks[5] = _mk_eb(5, 0, [(0, 1, 14, 0), (1, 1, 15, 0)])
    blocks[14] = d1
    blocks[15] = d2

    # 6 系统目录（inline），含 global_bitmap -> 7
    sys_entries = _mk_dirents([
        (".", 6, 2), ("..", 1, 2), ("global_bitmap", 7, 1),
    ])
    b = _mk_dinode(mode=0o040755, size=len(sys_entries), blkno=6,
                   flags=OCFS2_VALID_FL | OCFS2_SYSTEM_FL,
                   dyn=OCFS2_INLINE_DATA_FL, links=2)
    _put(b, DI_ID2 + ID_COUNT, "<H", len(sys_entries))
    b[DI_ID2 + ID_DATA:DI_ID2 + ID_DATA + len(sys_entries)] = sys_entries
    blocks[6] = b

    # 7 链分配器（global_bitmap 风格），两条链：8->9，10
    b = _mk_dinode(mode=0o100600, size=0, blkno=7,
                   flags=OCFS2_VALID_FL | OCFS2_SYSTEM_FL | OCFS2_CHAIN_FL,
                   links=1)
    _put(b, DI_ID2 + CL_CPG, "<H", 8192)
    _put(b, DI_ID2 + CL_BPC, "<H", 1)
    _put(b, DI_ID2 + CL_COUNT, "<H", 2)
    _put(b, DI_ID2 + CL_NEXT_FREE_REC, "<H", 2)
    for i, (cfree, ctotal, cblk) in enumerate([(100, 8192, 8), (50, 4096, 10)]):
        p = DI_ID2 + CL_RECS + i * CHAIN_REC_SIZE
        _put(b, p, "<I", cfree)
        _put(b, p + 4, "<I", ctotal)
        _put(b, p + 8, "<Q", cblk)
    blocks[7] = b
    blocks[8] = _mk_gd(8, 7, 9, chain=0, bits=8192, free_bits=100)
    blocks[9] = _mk_gd(9, 7, 0, chain=0, bits=8192, free_bits=0)
    blocks[10] = _mk_gd(10, 7, 0, chain=1, bits=4096, free_bits=50)

    # 16 索引目录（i_flags 带 OCFS2_INDEX_FL + dyn INDEXED_DIR_FL）
    b = _mk_dinode(mode=0o040755, size=CS, blkno=16, clusters=1,
                   flags=OCFS2_VALID_FL | OCFS2_INDEX_FL,
                   dyn=OCFS2_INLINE_DATA_FL | OCFS2_INDEXED_DIR_FL)
    blocks[16] = b

    nblocks = max(blocks) + 3
    img = bytearray(nblocks * BS)
    for blk, data in blocks.items():
        assert len(data) <= BS, (blk, len(data))
        img[blk * BS:blk * BS + min(len(data), BS)] = data[:BS]
    return bytes(img), payload, d1 + d2


def _selftest():
    ok = 0
    bad = 0

    def check(cond, label, extra=""):
        nonlocal ok, bad
        if cond:
            ok += 1
            print("  PASS  %s" % label)
        else:
            bad += 1
            print("  FAIL  %s%s" % (label, ("  [" + extra + "]") if extra else ""))

    img, payload, tree_payload = _build_image()
    sub = _MemSub(img)

    print("[1] probe")
    check(probe(sub) is True, "合法镜像 probe=True")
    rnd = bytes((i * 37 + 101) & 0xFF for i in range(65536))
    check(probe(_MemSub(rnd)) is False, "随机数据 probe=False")
    check(probe(_MemSub(b"\x00" * 65536)) is False, "全零 probe=False")
    check(probe(_MemSub(SIG_SB_MAGIC + b"  ")) is False, "过短输入 probe=False")
    check(probe(_MemSub(b"")) is False, "空输入 probe=False")

    print("[2] 超级块")
    fs = open_fs(sub)
    inf = fs.info()
    check(inf["major"] == 1 and inf["minor"] == 0, "major/minor = 1.0",
          "%r/%r" % (inf["major"], inf["minor"]))
    check(inf["block_size"] == 4096, "块大小 4096", repr(inf["block_size"]))
    check(inf["cluster_size"] == 4096, "集群大小 4096", repr(inf["cluster_size"]))
    check(inf["max_slots"] == 8, "max_slots = 8", repr(inf["max_slots"]))
    check(inf["label"] == "取证测试卷 OCFS2", "label 含中文且解码正确",
          repr(inf["label"]))
    check(inf["uuid"] == "01234567-89ab-cdef-fedc-ba9876543210",
          "uuid 字符串", inf["uuid"])
    check(len(inf["uuid_raw"]) == 16, "uuid 原始 16 字节")
    check(inf["root_blkno"] == 1, "root_blkno = 1", repr(inf["root_blkno"]))
    check(inf["system_dir_blkno"] == 6, "system_dir_blkno = 6")
    check(inf["fs_generation"] == 0xA1B2C3D4, "i_fs_generation")
    check(inf["feature_incompat"] == FEATURE_INCOMPAT_INLINE_DATA
          and inf["features"]["incompat"] == ["INLINE_DATA"],
          "incompat 特性解码", repr(inf["features"]))
    check(len(fs.superblocks()) == 1, "superblocks() 主份 1 条",
          repr(len(fs.superblocks())))

    print("[3] 链列表")
    ch = fs.chain()
    check(ch["cl_count"] == 2, "cl_count = 2", repr(ch["cl_count"]))
    check(ch["cl_next_free_rec"] == 2 and ch["records"] == 2,
          "cl_next_free_rec / 记录数 = 2")
    check(ch["cl_cpg"] == 8192 and ch["cl_bpc"] == 1, "cl_cpg=8192 cl_bpc=1")
    check([c["group_count"] for c in ch["chains"]] == [2, 1],
          "各链组描述符数 [2, 1]", repr([c["group_count"] for c in ch["chains"]]))
    check(ch["group_total"] == 3, "组描述符合计 3")
    g0 = ch["chains"][0]["groups"][0]
    check(g0["blkno"] == 8 and g0["next_group"] == 9
          and g0["parent_dinode"] == 7 and g0["bits"] == 8192,
          "组头字段 bg_blkno/next/parent/bits", repr(g0))

    print("[4] 目录")
    root = fs.listdir()
    names = [e["name"] for e in root]
    check("文档.txt" in names, "根目录列出中文名 文档.txt", repr(names))
    check("子目录" in names and "big.bin" in names, "根目录其余项")
    # rec_len 是整数字段（OCFS2_DIR_REC_LEN 至少 11 字节），不是字节串，
    # 不能取 len()；原来那句还带 `or True`，恒真、等于没测。
    check(all(11 <= e["rec_len"] for e in root), "rec_len 解析",
          repr([e["rec_len"] for e in root]))
    root_inode = fs.inode(fs.root_blkno)
    check(root_inode["is_dir"] and root_inode["inline_data"],
          "根 inode 是 inline 目录")
    sub_entries = fs.listdir(2)
    sub_names = [e["name"] for e in sub_entries]
    check("线性目录.txt" in sub_names, "extent 目录列出 线性目录.txt",
          repr(sub_names))
    check("深层目录" in sub_names, "extent 目录列出 深层目录")
    check(len(sub_names) == 4, "extent 目录共 4 项（含 . ..）", repr(len(sub_names)))
    ent = fs.lookup_path("/子目录/线性目录.txt")
    check(ent["blkno"] == 3 and ent["name"] == "线性目录.txt",
          "lookup_path 命中", repr(ent.get("blkno")))
    walk_paths = [w["path"] for w in fs.walk()]
    check("/big.bin" in walk_paths, "walk 含 /big.bin", repr(walk_paths))
    hits = fs.find("*.bin")
    check(len(hits) == 1 and hits[0]["path"] == "/big.bin", "find('*.bin')")

    print("[5] 文件（内联 extent）")
    got = fs.read_file(3)
    check(got == payload, "read_file(3) 内容一致", "%d vs %d" % (len(got), len(payload)))
    dino = fs.inode(3)
    check(dino["extent_count"] == 1 and dino["tree_depth"] == 0, "1 条叶子 extent")
    check(dino["extents"][0]["blkno"] == 13
          and dino["extents"][0]["clusters"] == 1, "extent 指向块 13 / 1 簇")
    check(dino["uid"] == 1000 and dino["gid"] == 1000, "uid/gid")
    check(dino["links"] == 1 and dino["size"] == 4096, "links / size")
    check(dino["mtime"] is not None
          and dino["mtime"].year == 2023, "mtime 时间戳", str(dino["mtime"]))
    check(fs.read_file(dino, 32) == payload[:32], "read_file size 参数")

    print("[6] extent 树（l_tree_depth=1）")
    big = fs.read_file(4)
    check(big == tree_payload, "树形 extent 读文件正确",
          "%d vs %d" % (len(big), len(tree_payload)))
    big_dino = fs.inode(4)
    check(big_dino["tree_depth"] == 1, "树深 1", repr(big_dino["tree_depth"]))
    leaf_recs = [r for r in big_dino["extents"] if not r["interior"]]
    check([r["blkno"] for r in leaf_recs] == [14, 15],
          "展开后叶子块号 [14, 15]", repr([r["blkno"] for r in leaf_recs]))

    print("[7] 截断")
    try:
        Ocfs2(_MemSub(img[:300]))
    except Ocfs2Error:
        check(True, "300 字节输入抛 Ocfs2Error")
    except Exception as e:                      # noqa: BLE001
        check(False, "300 字节输入抛 Ocfs2Error", type(e).__name__)
    else:
        check(False, "300 字节输入抛 Ocfs2Error", "未抛异常")
    cut = fs.__class__(_MemSub(img[:20 * 1024]))
    try:
        cut.read_file(4)
    except Ocfs2Error:
        check(True, "数据块被截断时 read_file 抛 Ocfs2Error")
    except Exception as e:                      # noqa: BLE001
        check(False, "数据块被截断时 read_file 抛 Ocfs2Error", type(e).__name__)
    else:
        check(False, "数据块被截断时 read_file 抛 Ocfs2Error", "未抛异常")
    try:
        fs.inode(0x9999)
    except Ocfs2Error:
        check(True, "越界块号抛 Ocfs2Error")
    else:
        check(False, "越界块号抛 Ocfs2Error", "未抛异常")

    print("[8] 未实现路径")
    idx = fs.inode(16)
    check(idx["indexed_dir"] is True, "索引目录标志被识别")
    try:
        fs.listdir(16)
    except NotImplementedError as e:
        check("DX" in str(e) or "索引" in str(e), "索引目录抛 NotImplementedError")
    except Exception as e:                      # noqa: BLE001
        check(False, "索引目录抛 NotImplementedError", type(e).__name__)
    else:
        check(False, "索引目录抛 NotImplementedError", "未抛异常")
    try:
        fs.lookup_path("/索引目录/x")
    except NotImplementedError:
        check(True, "索引目录 lookup 抛 NotImplementedError")
    except Exception as e:                      # noqa: BLE001
        check(False, "索引目录 lookup 抛 NotImplementedError", type(e).__name__)
    else:
        check(False, "索引目录 lookup 抛 NotImplementedError", "未抛异常")
    try:
        fs.chain(3)                             # 普通文件 inode
    except Ocfs2Error:
        check(True, "非链 inode 调 chain 抛 Ocfs2Error")
    else:
        check(False, "非链 inode 调 chain 抛 Ocfs2Error", "未抛异常")

    print("-" * 52)
    print("自检：%d 通过，%d 失败" % (ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
