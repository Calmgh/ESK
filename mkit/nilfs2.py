# -*- coding: utf-8 -*-
# ============================================================
#  ESK  路  Calmgh06
#  Electronic Software Kit  |  NILFS2 只读解析
# ============================================================
"""NILFS2（New Implementation of a Log-structured File System）只读解析。

NILFS2 是 NTT 的日志结构文件系统，CE 设备与嵌入式 Linux 常见。
格式依据 Linux 内核源码（均按 2024-2025 主线 master 核对）：

  * ``include/uapi/linux/nilfs2_ondisk.h``   —— 全部磁盘结构
  * ``fs/nilfs2/super.c``                    —— 超级块 CRC 计算方式
  * ``fs/nilfs2/the_nilfs.c``                —— 挂载期超级块校验
  * ``fs/nilfs2/alloc.c`` / ``alloc.h``      —— DAT/ifile 的 palloc 块布局
  * ``fs/nilfs2/btree.c`` / ``btree.h``      —— B-tree 节点 keys/ptrs 偏移
  * ``fs/nilfs2/cpfile.c``                   —— CPFILE 的 cno -> 块内偏移
  * ``fs/nilfs2/ifile.c`` / ``dat.c``        —— 两者均走 palloc 取块

============================================================================
已实现（三层全通）
============================================================================
1. 超级块
   路 主超级块偏移 **1024**；备份在 ``NILFS_SB2_OFFSET_BYTES(devsize)``
      = ``((devsize >> 12) - 1) << 12``（设备末尾 4 KiB 对齐处）
   路 魔数 ``0x3434``（u16 @ 结构内 +0x06）
   路 全部关键字段按头文件偏移解析（见 ``SB_FIELDS``）
   路 校验和：``s_sum == crc32_le(s_crc_seed, sb[0:s_bytes])``，计算时
      ``s_sum`` 字段置 0（super.c:287-294 的写法）；用 ``zlib.crc32``
      反推 Linux 的 ``crc32_le``（见 ``nilfs_crc32``）
   路 块大小 = ``1024 << s_log_block_size``
   路 主块坏 -> 自动回退备份（magic + CRC 双条件择优）

2. 段摘要与检查点
   路 段摘要 magic ``0x1eaffa11``（``NILFS_SEGSUM_MAGIC``；**不是**任务里
      猜的 0xC0FFEE00），结构 64 字节，其后紧跟 ``nfinfo`` 个 finfo（24 字节）
      与全部 binfo（各 16 字节，DAT 段用 binfo_dat，其余用 binfo_v）
   路 段链：``s_last_pseg`` 起、``ss_next`` 串链；再按 ``s_first_data_block
      + i * s_blocks_per_segment`` 逐段补扫首 pseg
   路 超级根块位于 pseg 内段摘要之后的第一个块（``SS_SR`` 标志位），
      内含 DAT / CPFILE / SUFILE 三个内联 inode
   路 检查点：CPFILE 用**直接块寻址**（cpfile.c 的 ``tcno`` 算法，非 palloc），
      cno -> ``(cno + first_entry_offset - 1)``，结构含内联 ``cp_ifile_inode``

3. inode / B-tree / 目录
   路 ``nilfs_inode`` 128 字节，``i_bmap[7]`` 起始于 +56
   路 bmap 两种形态：
      - direct：``dn_flags`` @+0，指针自 +8 起，最多 6 个
      - btree：根节点 ``bn_flags`` 带 ``NILFS_BTREE_NODE_ROOT(0x01)``，
        keys @+8、ptrs @+8+3*8；节点块 keys @+16、ptrs @+16+((bs-16)/16)*8
   路 虚块号 -> 物理块：先查 DAT（palloc 定位条目），失败/成环回退到
      段摘要日志映射（DAT 自身的块必然成环，日志里的 ``binfo_dat.bi_blkoff``
      就是 vblocknr，可破环）
   路 目录项 ``nilfs_dir_entry``：inode u64 / rec_len u16 / name_len u8 /
      file_type u8 / name[]，8 字节对齐
   路 ``listdir`` / ``walk`` / ``read_file`` / ``lookup_path`` / ``find``

============================================================================
未实现 / 明确边界
============================================================================
路 写操作、fsck、GC（快照回收）
路 SUFILE 只解出 inode，不解析段用途表内容
路 ``ss_datasum`` / ``ss_sumsum``：结构里有值、也提供 ``verify_segsum``，
  但默认不做强制校验（内核计算范围含日志块，未被真实镜像回测）
路 稀疏空洞：bmap 查不到即补零并记 note，不区分「空洞」与「坏链」
路 快速符号链接（bmap 内存 target）：按普通块读，若读空则记 note
路 压缩 / 加密：NILFS2 无此特性
路 真机镜像未回测（本机无样本），自检全部基于合成镜像
路 自检只覆盖 4 KiB 块 + 128 B inode（其它块大小/条目尺寸的算式同源，
  但未跑过镜像）
路 与任务描述的两处出入（以头文件为准）：段摘要没有 ``ss_cycle``
  （实际是 ``ss_seq`` / ``ss_create`` / ``ss_next``）；检查点没有
  ``cp_pad`` / ``cp_dat_entry``（实际是 ``cp_checkpoints_count`` /
  ``cp_snapshot_list`` / ``cp_nblk_inc`` / ``cp_inodes_count`` /
  ``cp_blocks_count``）
"""

import datetime
import fnmatch
import struct
import zlib

__all__ = [
    "Nilfs2", "Nilfs2Super", "Nilfs2Inode",
    "Nilfs2Error", "NotNilfs2Error",
    "probe", "open_fs", "nilfs_crc32",
    "SUPER_OFFSET", "SUPER_MAGIC", "SEGSUM_MAGIC",
    "SB_FIELDS", "INODE_SIZE_MIN", "CHECKPOINT_SIZE_MIN",
    "DAT_ENTRY_SIZE_MIN", "BTREE_ROOT_NCHILDREN_MAX",
    "ROOT_INO", "DAT_INO", "CPFILE_INO", "SUFILE_INO", "IFILE_INO",
]

# ---------------------------------------------------------------- 常量

SUPER_OFFSET = 1024              # NILFS_SB_OFFSET_BYTES
SUPER_MAGIC = 0x3434             # NILFS_SUPER_MAGIC（u16）
SEGSUM_MAGIC = 0x1EAFFA11        # NILFS_SEGSUM_MAGIC
SEGSUM_SIZE = 64                 # struct nilfs_segment_summary
FINFO_SIZE = 24                  # struct nilfs_finfo
BINFO_SIZE = 16                  # union nilfs_binfo（v 与 dat 均 16 字节）

SR_HEAD_SIZE = 16                # sr_sum/sr_bytes/sr_flags/sr_nongc_ctime
INODE_SIZE_MIN = 128             # NILFS_MIN_INODE_SIZE
CHECKPOINT_SIZE_MIN = 192        # NILFS_MIN_CHECKPOINT_SIZE = 64 + 128
DAT_ENTRY_SIZE_MIN = 32          # NILFS_MIN_DAT_ENTRY_SIZE
SUFILE_ENTRY_SIZE_MIN = 16       # NILFS_MIN_SEGMENT_USAGE_SIZE
CPFILE_HEADER_SIZE = 32          # struct nilfs_cpfile_header
BMAP_SIZE = 56                   # NILFS_INODE_BMAP_SIZE * 8
BTREE_NODE_HEAD_SIZE = 8         # struct nilfs_btree_node
BTREE_NODE_EXTRA_PAD = 8         # NILFS_BTREE_NODE_EXTRA_PAD_SIZE
BTREE_NODE_ROOT = 0x01           # NILFS_BTREE_NODE_ROOT
BTREE_LEVEL_MAX = 14
DIRENT_HEAD = 12                 # inode u64 + rec_len u16 + name_len u8 + ft u8
DIR_PAD = 8                      # NILFS_DIR_PAD

ROOT_INO = 2
DAT_INO = 3
CPFILE_INO = 4
SUFILE_INO = 5
IFILE_INO = 6
USER_INO = 11

# 段摘要标志
SS_LOGBGN = 0x0001
SS_LOGEND = 0x0002
SS_SR = 0x0004
SS_SYNDT = 0x0008
SS_GC = 0x0010

SS_FLAG_NAMES = (
    (SS_LOGBGN, "logbegin"),
    (SS_LOGEND, "logend"),
    (SS_SR, "super_root"),
    (SS_SYNDT, "synthesis_data"),
    (SS_GC, "gc"),
)

# 检查点标志
CP_SNAPSHOT = 0x0001
CP_INVALID = 0x0002
CP_SKETCH = 0x0004
CP_MINOR = 0x0008

# 文件系统状态
NILFS_VALID_FS = 0x0001
NILFS_ERROR_FS = 0x0002
NILFS_RESIZE_FS = 0x0004

# 目录项 file_type
FT_NAMES = {
    0: "unknown", 1: "file", 2: "dir", 3: "chrdev",
    4: "blkdev", 5: "fifo", 6: "sock", 7: "symlink",
}

# S_IFMT
S_IFMT = 0o170000
S_IFSOCK = 0o140000
S_IFLNK = 0o120000
S_IFREG = 0o100000
S_IFBLK = 0o060000
S_IFDIR = 0o040000
S_IFCHR = 0o020000
S_IFIFO = 0o010000

# 超级块字段：名称 / 结构内偏移 / struct 格式（均按 nilfs2_ondisk.h 注释核对）
SB_FIELDS = (
    ("s_rev_level", 0x00, "I"),
    ("s_minor_rev_level", 0x04, "H"),
    ("s_magic", 0x06, "H"),
    ("s_bytes", 0x08, "H"),
    ("s_flags", 0x0A, "H"),
    ("s_crc_seed", 0x0C, "I"),
    ("s_sum", 0x10, "I"),
    ("s_log_block_size", 0x14, "I"),
    ("s_nsegments", 0x18, "Q"),
    ("s_dev_size", 0x20, "Q"),
    ("s_first_data_block", 0x28, "Q"),
    ("s_blocks_per_segment", 0x30, "I"),
    ("s_r_segments_percentage", 0x34, "I"),
    ("s_last_cno", 0x38, "Q"),
    ("s_last_pseg", 0x40, "Q"),
    ("s_last_seq", 0x48, "Q"),
    ("s_free_blocks_count", 0x50, "Q"),
    ("s_ctime", 0x58, "q"),
    ("s_mtime", 0x60, "q"),
    ("s_wtime", 0x68, "q"),
    ("s_mnt_count", 0x70, "H"),
    ("s_max_mnt_count", 0x72, "H"),
    ("s_state", 0x74, "H"),
    ("s_errors", 0x76, "H"),
    ("s_lastcheck", 0x78, "q"),
    ("s_checkinterval", 0x80, "I"),
    ("s_creator_os", 0x84, "I"),
    ("s_def_resuid", 0x88, "H"),
    ("s_def_resgid", 0x8A, "H"),
    ("s_first_ino", 0x8C, "I"),
    ("s_inode_size", 0x90, "H"),
    ("s_dat_entry_size", 0x92, "H"),
    ("s_checkpoint_size", 0x94, "H"),
    ("s_segment_usage_size", 0x96, "H"),
    ("s_uuid", 0x98, "16s"),
    ("s_volume_name", 0xA8, "80s"),
    ("s_c_interval", 0xF8, "I"),
    ("s_c_block_max", 0xFC, "I"),
    ("s_feature_compat", 0x100, "Q"),
    ("s_feature_compat_ro", 0x108, "Q"),
    ("s_feature_incompat", 0x110, "Q"),
)

# NILFS_SB_BYTES = offsetof(struct nilfs_super_block, s_reserved)
SB_BYTES_DEFAULT = 0x118         # 280
SB_MIN_READ = 0x118

# inode 字段：i_bmap 之后的部分
INODE_BMAP_OFF = 56
INODE_XATTR_OFF = 112
INODE_GENERATION_OFF = 120
INODE_FIELDS = (
    ("i_blocks", 0x00, "Q"),
    ("i_size", 0x08, "Q"),
    ("i_ctime", 0x10, "q"),
    ("i_mtime", 0x18, "q"),
    ("i_ctime_nsec", 0x20, "I"),
    ("i_mtime_nsec", 0x24, "I"),
    ("i_uid", 0x28, "I"),
    ("i_gid", 0x2C, "I"),
    ("i_mode", 0x30, "H"),
    ("i_links_count", 0x32, "H"),
    ("i_flags", 0x34, "I"),
)


# ---------------------------------------------------------------- 异常


class Nilfs2Error(Exception):
    """NILFS2 解析层的通用错误（越界、结构损坏、无法定位元数据）。"""


class NotNilfs2Error(Nilfs2Error):
    """镜像不是 NILFS2（魔数不匹配）。"""


# ---------------------------------------------------------------- 小工具


def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def nilfs_crc32(seed, data):
    """Linux ``crc32_le(seed, data)`` 的等价实现。

    内核的实现是「带初值、无前后取反」的反射 CRC32 表循环::

        crc = (crc >> 8) ^ table[(crc ^ *p) & 0xff]

    而 ``zlib.crc32(buf, v)`` 等价于 ``raw(v ^ ~0, buf) ^ ~0``，因此反解出::

        raw(seed, data) == ~zlib.crc32(data, ~seed)
    """
    inv = 0xFFFFFFFF ^ (seed & 0xFFFFFFFF)
    return zlib.crc32(bytes(data), inv) ^ 0xFFFFFFFF


def _iso(sec, nsec=0):
    """秒 + 纳秒 -> ISO8601（UTC）；非法值返回 None。"""
    if sec is None:
        return None
    try:
        sec = int(sec)
    except (TypeError, ValueError):
        return None
    if sec <= 0:
        return None
    try:
        dt = datetime.datetime.fromtimestamp(sec, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    if nsec:
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + (".%09dZ" % (nsec % 1000000000))
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_name(raw):
    """文件名 / 卷名解码：先 UTF-8，失败退 Latin-1（保留原字节）。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _uuid_str(b):
    if len(b) != 16:
        return None
    h = b.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def _mode_kind(mode):
    t = mode & S_IFMT
    return {
        S_IFREG: "file", S_IFDIR: "dir", S_IFLNK: "symlink",
        S_IFCHR: "chrdev", S_IFBLK: "blkdev", S_IFIFO: "fifo",
        S_IFSOCK: "sock",
    }.get(t, "unknown")


def _mode_str(mode):
    """rwx 字符串（ls 风格，10 字符）。"""
    if not mode and not (mode & S_IFMT):
        return "----------"
    kind = {S_IFDIR: "d", S_IFLNK: "l", S_IFCHR: "c", S_IFBLK: "b",
            S_IFIFO: "p", S_IFSOCK: "s"}.get(mode & S_IFMT, "-")
    out = [kind]
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 0x7
        out.append("r" if bits & 4 else "-")
        out.append("w" if bits & 2 else "-")
        out.append("x" if bits & 1 else "-")
    return "".join(out)


# ---------------------------------------------------------------- 超级块


class Nilfs2Super(object):
    """一个 ``struct nilfs_super_block`` 副本。"""

    __slots__ = tuple(f[0] for f in SB_FIELDS) + (
        "offset", "raw", "crc_ok", "crc_calc", "magic_ok", "size_ok",
    )

    def __init__(self, raw, offset):
        self.raw = bytes(raw)
        self.offset = int(offset)
        self.crc_ok = None
        self.crc_calc = None
        self.magic_ok = False
        self.size_ok = False
        for name, off, fmt in SB_FIELDS:
            try:
                val = struct.unpack_from("<" + fmt, self.raw, off)[0]
            except struct.error:
                val = None
            setattr(self, name, val)
        self.magic_ok = (self.s_magic == SUPER_MAGIC)

    @property
    def blocksize(self):
        if self.s_log_block_size is None:
            return None
        if self.s_log_block_size > 16:
            return None
        return 1024 << self.s_log_block_size

    @property
    def volume_name(self):
        raw = self.s_volume_name or b""
        raw = raw.split(b"\x00", 1)[0]
        return _decode_name(raw) if raw else ""

    @property
    def uuid_bytes(self):
        return self.s_uuid or b""

    @property
    def uuid(self):
        return _uuid_str(self.s_uuid or b"")

    def verify_crc(self):
        """按 super.c 的写法算 CRC：s_sum 置 0，范围取 ``s_bytes``。"""
        nbytes = self.s_bytes or SB_BYTES_DEFAULT
        if nbytes <= 0 or nbytes > len(self.raw) or self.s_crc_seed is None:
            self.crc_ok = None
            return None
        buf = bytearray(self.raw[:nbytes])
        struct.pack_into("<I", buf, 0x10, 0)          # s_sum 置 0
        calc = nilfs_crc32(self.s_crc_seed, buf)
        self.crc_calc = calc
        self.crc_ok = (calc == (self.s_sum or 0))
        return self.crc_ok

    def to_dict(self):
        return {
            "offset": self.offset,
            "magic_ok": self.magic_ok,
            "crc_ok": self.crc_ok,
            "s_sum": self.s_sum,
            "crc_calc": self.crc_calc,
            "s_crc_seed": self.s_crc_seed,
            "rev": "%s.%s" % (self.s_rev_level, self.s_minor_rev_level),
            "bytes": self.s_bytes,
            "blocksize": self.blocksize,
            "nsegments": self.s_nsegments,
            "dev_size": self.s_dev_size,
            "first_data_block": self.s_first_data_block,
            "blocks_per_segment": self.s_blocks_per_segment,
            "last_cno": self.s_last_cno,
            "last_pseg": self.s_last_pseg,
            "last_seq": self.s_last_seq,
            "volume_name": self.volume_name,
            "uuid": self.uuid,
            "wtime": _iso(self.s_wtime),
        }


# ---------------------------------------------------------------- inode


class Nilfs2Inode(object):
    """``struct nilfs_inode``（128 字节最小形态）。"""

    __slots__ = tuple(f[0] for f in INODE_FIELDS) + (
        "ino", "bmap_raw", "i_xattr", "i_generation", "i_pad", "raw",
    )

    def __init__(self, raw, ino=None):
        self.raw = bytes(raw)
        self.ino = ino
        for name, off, fmt in INODE_FIELDS:
            try:
                setattr(self, name, struct.unpack_from("<" + fmt, self.raw, off)[0])
            except struct.error:
                setattr(self, name, None)
        self.bmap_raw = self.raw[INODE_BMAP_OFF:INODE_BMAP_OFF + BMAP_SIZE]
        try:
            self.i_xattr = _u64(self.raw, INODE_XATTR_OFF)
            self.i_generation = _u32(self.raw, INODE_GENERATION_OFF)
        except struct.error:
            self.i_xattr = None
            self.i_generation = None
        self.i_pad = None

    # -- 便捷属性
    @property
    def kind(self):
        return _mode_kind(self.i_mode or 0)

    @property
    def is_dir(self):
        return (self.i_mode or 0) & S_IFMT == S_IFDIR

    @property
    def is_file(self):
        return (self.i_mode or 0) & S_IFMT == S_IFREG

    @property
    def is_symlink(self):
        return (self.i_mode or 0) & S_IFMT == S_IFLNK

    @property
    def mode_str(self):
        return _mode_str(self.i_mode or 0)

    def to_dict(self):
        return {
            "ino": self.ino,
            "mode": "0o%o" % (self.i_mode or 0),
            "mode_str": self.mode_str,
            "type": self.kind,
            "size": self.i_size,
            "blocks": self.i_blocks,
            "links": self.i_links_count,
            "uid": self.i_uid,
            "gid": self.i_gid,
            "flags": self.i_flags,
            "ctime": _iso(self.i_ctime, self.i_ctime_nsec or 0),
            "mtime": _iso(self.i_mtime, self.i_mtime_nsec or 0),
            "generation": self.i_generation,
            "bmap": self.bmap_raw.hex(),
        }


class _DatCycle(Exception):
    """DAT 自引用（DAT 文件自身的块）——回退到段摘要日志映射。"""


# ---------------------------------------------------------------- 主体


class Nilfs2(object):
    """NILFS2 只读解析器。

    只依赖可读对象 ``sub.read(offset, size)`` 与 ``sub.size``（可选
    ``__len__``），零第三方依赖。
    """

    def __init__(self, sub, sb_offset=None, scan_segments=True,
                 max_segments=4096, verify_segsum=False):
        self.sub = sub
        self.notes = []
        self.size = self._probe_size()
        self._sb_cache = {}
        self._blk_cache = {}
        self._inode_cache = {}
        self._segs = None
        self._sr = None
        self._vmap_log = {}
        self._file_vmap = {}
        self._dat_guard = set()
        self._log_scanned = False
        self._dat_inode_obj = None
        self._cpfile_inode_obj = None
        self._sufile_inode_obj = None
        self._ifile_inode_obj = None
        self._ifile_cno = None
        self._max_segments = max(1, int(max_segments))
        self._scan_segments = bool(scan_segments)
        self._verify_segsum = bool(verify_segsum)

        self._sbs = self._load_super_copies(sb_offset)
        chosen = self._choose_super()
        self.sb = chosen
        self.sb_offset = chosen.offset
        self.blocksize = chosen.blocksize
        if not self.blocksize:
            raise Nilfs2Error("超级块 s_log_block_size=%r 非法，无法推算块大小"
                              % (chosen.s_log_block_size,))
        if self.blocksize < 1024 or self.blocksize > 65536:
            raise Nilfs2Error("块大小 %d 超出 NILFS2 允许范围 1024..65536"
                              % self.blocksize)
        self.inode_size = chosen.s_inode_size or INODE_SIZE_MIN
        if self.inode_size < INODE_SIZE_MIN:
            self.notes.append("s_inode_size=%d 小于最小值 %d，按 %d 解析"
                              % (self.inode_size, INODE_SIZE_MIN, INODE_SIZE_MIN))
            self.inode_size = INODE_SIZE_MIN
        self.dat_entry_size = chosen.s_dat_entry_size or DAT_ENTRY_SIZE_MIN
        self.checkpoint_size = chosen.s_checkpoint_size or CHECKPOINT_SIZE_MIN
        self.segment_usage_size = (chosen.s_segment_usage_size
                                   or SUFILE_ENTRY_SIZE_MIN)
        if chosen.crc_ok is False:
            self.notes.append(
                "选中的超级块（偏移 %d）CRC 校验失败：s_sum=0x%08X 实际=0x%08X"
                % (chosen.offset, chosen.s_sum or 0, chosen.crc_calc or 0))
        if chosen.crc_ok is None:
            self.notes.append("超级块 CRC 未计算（s_bytes 异常）")
        if chosen.s_feature_incompat:
            self.notes.append("s_feature_incompat=0x%X 非零，内核会拒绝挂载"
                              % chosen.s_feature_incompat)

    # -- 基础 IO ------------------------------------------------------

    def _probe_size(self):
        size = getattr(self.sub, "size", None)
        if size is None:
            try:
                size = len(self.sub)
            except Exception:
                size = None
        if size is None:
            return None
        try:
            return int(size)
        except (TypeError, ValueError):
            return None

    def _read(self, off, n):
        if off < 0 or n < 0:
            raise Nilfs2Error("非法读取 off=%r size=%r" % (off, n))
        if self.size is not None and off + n > self.size:
            raise Nilfs2Error(
                "镜像截断：请求 0x%X..0x%X 超出镜像大小 0x%X"
                % (off, off + n, self.size))
        data = self.sub.read(off, n)
        if data is None:
            raise Nilfs2Error("底层读取返回 None（off=0x%X size=0x%X）" % (off, n))
        if len(data) != n:
            raise Nilfs2Error(
                "镜像截断：偏移 0x%X 期望 %d 字节，实际 %d 字节"
                % (off, n, len(data)))
        return bytes(data)

    def _read_soft(self, off, n):
        if off < 0 or n < 0:
            return None
        try:
            data = self.sub.read(off, n)
        except Exception:
            return None
        if data is None:
            return None
        return bytes(data)

    def _read_block(self, blk, strict=False):
        """按块号读整块；越界返回 None（strict 时抛）。"""
        if blk is None or blk < 0:
            return None
        off = blk * self.blocksize
        data = self._read_soft(off, self.blocksize)
        if data is None or len(data) != self.blocksize:
            if strict:
                raise Nilfs2Error("块 %d（偏移 0x%X）读取失败/截断" % (blk, off))
            return None
        return data

    # -- 超级块 ------------------------------------------------------

    def _sb2_offset(self, devsize):
        if not devsize:
            return None
        off = ((int(devsize) >> 12) - 1) << 12
        return off if off > SUPER_OFFSET else None

    def _load_super_copies(self, sb_offset=None):
        if self.size is not None and self.size < SUPER_OFFSET + SB_MIN_READ:
            raise Nilfs2Error(
                "镜像过短：%d 字节，不足主超级块所需 %d 字节"
                % (self.size, SUPER_OFFSET + SB_MIN_READ))
        main = self._read_soft(SUPER_OFFSET, SB_BYTES_DEFAULT)
        if main is None or len(main) < SB_MIN_READ:
            raise Nilfs2Error("无法读取主超级块（偏移 %d）" % SUPER_OFFSET)

        devsize = self.size
        if not devsize and len(main) >= 0x28:
            devsize = _u64(main, 0x20)
        offsets = []
        if sb_offset is not None:
            offsets.append(int(sb_offset))
        else:
            offsets.append(SUPER_OFFSET)
        sb2 = self._sb2_offset(devsize)
        if sb2 and sb2 not in offsets:
            offsets.append(sb2)

        out = []
        for off in offsets:
            raw = self._read_soft(off, SB_BYTES_DEFAULT)
            if raw is None or len(raw) < SB_MIN_READ:
                continue
            sb = Nilfs2Super(raw, off)
            if sb.magic_ok:
                sb.verify_crc()
            else:
                sb.crc_ok = None
            out.append(sb)
        if not out:
            raise Nilfs2Error("没有可解析的超级块副本")
        return out

    def _choose_super(self):
        cands = self._sbs
        good = [c for c in cands if c.magic_ok and c.crc_ok]
        if good:
            chosen = good[0]
            for c in good[1:]:
                if (c.s_last_seq or 0) > (chosen.s_last_seq or 0):
                    chosen = c
            return chosen
        magic = [c for c in cands if c.magic_ok]
        if magic:
            self.notes.append("主/备份超级块 CRC 均未通过，退化为按魔数解析"
                              "（偏移 %d）" % magic[0].offset)
            return magic[0]
        raise NotNilfs2Error(
            "魔数 0x%04X 未命中 NILFS2（偏移 %s）"
            % (SUPER_MAGIC, ",".join(str(c.offset) for c in cands)))

    def superblocks(self):
        """全部超级块副本（含未选中的）。"""
        out = []
        for c in self._sbs:
            d = c.to_dict()
            d["selected"] = (c.offset == self.sb_offset)
            out.append(d)
        return out

    # -- 段摘要 ------------------------------------------------------

    def _parse_segsum(self, blk):
        head = self._read_block(blk)
        if head is None or len(head) < SEGSUM_SIZE:
            return None
        magic = _u32(head, 8)
        if magic != SEGSUM_MAGIC:
            return None
        nfinfo = _u32(head, 44)
        nblocks = _u32(head, 40)
        sumbytes = _u32(head, 48)
        if nfinfo > 1 << 20 or nblocks > 1 << 28 or sumbytes < SEGSUM_SIZE:
            return None
        if sumbytes > 64 << 20:
            return None
        buf = self._read_soft(blk * self.blocksize, sumbytes)
        if buf is None or len(buf) < SEGSUM_SIZE:
            return None
        need = SEGSUM_SIZE + nfinfo * FINFO_SIZE + nblocks * BINFO_SIZE
        if len(buf) < need:
            buf2 = self._read_soft(blk * self.blocksize, need)
            if buf2 is None or len(buf2) < need:
                return None
            buf = buf2

        seg = {
            "blk": blk,
            "datasum": _u32(buf, 0),
            "sumsum": _u32(buf, 4),
            "magic": magic,
            "bytes": _u16(buf, 12),
            "flags": _u16(buf, 14),
            "seq": _u64(buf, 16),
            "create": _u64(buf, 24),
            "next": _u64(buf, 32),
            "nblocks": nblocks,
            "nfinfo": nfinfo,
            "sumbytes": sumbytes,
            "cno": _u64(buf, 56),
            "flags_names": [n for bit, n in SS_FLAG_NAMES if _u16(buf, 14) & bit],
            "finfo": [],
        }
        seg["sum_blocks"] = (sumbytes + self.blocksize - 1) // self.blocksize
        seg["have_sr"] = bool(seg["flags"] & SS_SR)
        seg["payload_start"] = blk + seg["sum_blocks"] + (1 if seg["have_sr"] else 0)

        pos = SEGSUM_SIZE
        blocks_left = nblocks
        finfo_raw = []
        for _ in range(nfinfo):
            if pos + FINFO_SIZE > len(buf):
                break
            finfo_raw.append((_u64(buf, pos), _u64(buf, pos + 8),
                              _u32(buf, pos + 16), _u32(buf, pos + 20)))
            pos += FINFO_SIZE
        cur = seg["payload_start"]
        for ino, cno, nb, ndatablk in finfo_raw:
            nb_eff = max(0, min(nb, blocks_left))
            seg["finfo"].append({
                "ino": ino, "cno": cno, "nblocks": nb, "ndatablk": ndatablk,
                "first_blk": cur, "binfo": [],
            })
            cur += nb_eff
            blocks_left -= nb_eff
        # binfo 数组紧跟在所有 finfo 之后
        for fi in seg["finfo"]:
            for i in range(fi["nblocks"]):
                if pos + BINFO_SIZE > len(buf):
                    break
                if fi["ino"] == DAT_INO:
                    # binfo_dat: bi_blkoff(8) bi_level(1) bi_pad[7]
                    vblocknr = _u64(buf, pos)
                    level = buf[pos + 8]
                    blkoff = None
                else:
                    # binfo_v: bi_vblocknr(8) bi_blkoff(8)
                    vblocknr = _u64(buf, pos)
                    blkoff = _u64(buf, pos + 8)
                    level = None
                fi["binfo"].append({
                    "vblocknr": vblocknr, "blkoff": blkoff,
                    "level": level, "blk": fi["first_blk"] + i,
                })
                pos += BINFO_SIZE
        return seg

    def segments(self):
        """段 / 部分段（pseg）列表。

        先沿 ``s_last_pseg`` -> ``ss_next`` 串自最新向旧回溯，再按
        ``first_data_block + i * blocks_per_segment`` 扫描每段首 pseg 补齐。
        """
        if self._segs is not None:
            return self._segs
        segs = {}
        order = []

        def add(seg):
            if seg is None:
                return False
            key = seg["blk"]
            if key in segs:
                return False
            segs[key] = seg
            order.append(key)
            return True

        first = self.sb.s_last_pseg
        seen = set()
        cur = first
        hops = 0
        while cur and hops < self._max_segments:
            if cur in seen:
                self.notes.append("段链在块 %d 处成环，停止回溯" % cur)
                break
            seen.add(cur)
            seg = self._parse_segsum(cur)
            if seg is None:
                if hops == 0:
                    self.notes.append("s_last_pseg=%d 处没有有效段摘要" % cur)
                break
            add(seg)
            nxt = seg["next"]
            if not nxt or nxt == cur:
                break
            if nxt * self.blocksize >= (self.size or (self.sb.s_dev_size or 0)):
                break
            cur = nxt
            hops += 1

        if self._scan_segments:
            fdb = self.sb.s_first_data_block or 0
            bps = self.sb.s_blocks_per_segment or 0
            nseg = min(self.sb.s_nsegments or 0, self._max_segments)
            if bps and nseg:
                for i in range(int(nseg)):
                    seg = self._parse_segsum(fdb + i * bps)
                    if seg is not None:
                        add(seg)

        segs_list = [segs[k] for k in order]
        self._segs = segs_list
        if not segs_list:
            self.notes.append("未解析到任何段摘要")
        return segs_list

    def verify_segsum(self, seg):
        """校验 ``ss_sumsum``（把该字段置 0 后按 ``ss_sumbytes`` 计算）。

        返回 True/False；数据不足时返回 None。
        """
        if seg is None:
            return None
        sumbytes = seg["sumbytes"]
        buf = self._read_soft(seg["blk"] * self.blocksize, sumbytes)
        if buf is None or len(buf) < SEGSUM_SIZE:
            return None
        b = bytearray(buf)
        struct.pack_into("<I", b, 4, 0)
        calc = nilfs_crc32(self.sb.s_crc_seed or 0, b)
        return calc == (seg["sumsum"] or 0)

    # -- 超级根 ------------------------------------------------------

    def _sr_candidates(self):
        segs = [s for s in self.segments() if s.get("have_sr")]
        segs.sort(key=lambda s: (s.get("cno") or 0, s.get("seq") or 0), reverse=True)
        for seg in segs:
            base = seg["blk"] + seg["sum_blocks"]
            for k in range(0, 4):
                yield seg, base + k

    def _looks_like_sr(self, raw, inode_size):
        if raw is None or len(raw) < SR_HEAD_SIZE:
            return False
        sr_bytes = _u16(raw, 4)
        want = SR_HEAD_SIZE + 3 * inode_size
        if sr_bytes != want:
            # 也接受 3 个 inode 的其它对齐写法（sr_bytes 缺失的旧镜像）
            if sr_bytes not in (0, SR_HEAD_SIZE + inode_size):
                return False
        # DAT inode 应该是普通文件
        dat_off = SR_HEAD_SIZE
        if len(raw) < dat_off + INODE_FIELDS[-1][1] + 4:
            return False
        mode = _u16(raw, dat_off + 0x30)
        if mode & S_IFMT != S_IFREG:
            return False
        return True

    def _load_super_root(self):
        if self._sr is not None:
            return self._sr
        inode_size = self.inode_size
        for seg, blk in self._sr_candidates():
            raw = self._read_block(blk)
            if not self._looks_like_sr(raw, inode_size):
                continue
            sr = {
                "blk": blk,
                "seg": seg["blk"],
                "sum": _u32(raw, 0),
                "bytes": _u16(raw, 4),
                "flags": _u16(raw, 6),
                "nongc_ctime": _u64(raw, 8),
                "dat": Nilfs2Inode(raw[SR_HEAD_SIZE:SR_HEAD_SIZE + inode_size], DAT_INO),
                "cpfile": Nilfs2Inode(raw[SR_HEAD_SIZE + inode_size:
                                          SR_HEAD_SIZE + 2 * inode_size], CPFILE_INO),
                "sufile": Nilfs2Inode(raw[SR_HEAD_SIZE + 2 * inode_size:
                                          SR_HEAD_SIZE + 3 * inode_size], SUFILE_INO),
            }
            self._sr = sr
            return sr
        self.notes.append("未找到可用的超级根块（含 DAT/CPFILE/SUFILE inode）")
        return None

    def super_root(self):
        """超级根的信息摘要（块号 + 三个元数据 inode）。"""
        sr = self._load_super_root()
        if sr is None:
            return None
        return {
            "blk": sr["blk"],
            "seg": sr["seg"],
            "sr_bytes": sr["bytes"],
            "nongc_ctime": _iso(sr["nongc_ctime"]),
            "dat": sr["dat"].to_dict(),
            "cpfile": sr["cpfile"].to_dict(),
            "sufile": sr["sufile"].to_dict(),
        }

    # -- palloc 布局 -------------------------------------------------

    def _palloc_geom(self, entry_size):
        """palloc 元数据文件的块布局几何量（alloc.c 的算式）。"""
        bs = self.blocksize
        epb = max(1, bs // entry_size)                 # entries_per_block
        epg = bs * 8                                   # entries_per_group
        gpd = max(1, bs // 4)                          # groups_per_desc_block
        bpg = (epg + epb - 1) // epb + 1               # blocks_per_group（含 bitmap）
        bpd = gpd * bpg + 1                            # blocks_per_desc_block
        return epb, epg, gpd, bpg, bpd

    def _palloc_pos(self, entry_size, nr):
        """条目号 -> (文件内块偏移, 块内字节偏移)。alloc.c 的算式。"""
        epb, epg, gpd, bpg, bpd = self._palloc_geom(entry_size)
        group = nr // epg
        desc_blkoff = (group // gpd) * bpd
        bitmap_blkoff = desc_blkoff + 1 + (group % gpd) * bpg
        idx = nr % epg
        return bitmap_blkoff + 1 + idx // epb, (idx % epb) * entry_size

    def _cpfile_pos(self, cno):
        """cno -> (文件内块偏移, 块内字节偏移)：cpfile.c 的 tcno 算法。"""
        cp_size = self.checkpoint_size
        epb = max(1, self.blocksize // cp_size)
        first_off = (CPFILE_HEADER_SIZE + cp_size - 1) // cp_size
        tcno = cno + first_off - 1
        return tcno // epb, (tcno % epb) * cp_size

    # -- 块地址翻译（DAT + 日志） ------------------------------------

    def _scan_log(self):
        """扫段摘要，建 vblocknr -> 物理块 / (ino, blkoff) -> 物理块 映射。"""
        if self._log_scanned:
            return
        self._log_scanned = True
        best_v = {}
        best_f = {}
        for seg in self.segments():
            seq = seg.get("seq") or 0
            for fi in seg["finfo"]:
                ino = fi["ino"]
                for b in fi["binfo"]:
                    if not b["blk"]:
                        continue
                    vbn = b["vblocknr"]
                    if vbn:
                        prev = best_v.get(vbn)
                        if prev is None or seq >= prev[0]:
                            best_v[vbn] = (seq, b["blk"])
                    if ino != DAT_INO and b["blkoff"] is not None:
                        key = (ino, b["blkoff"])
                        prev = best_f.get(key)
                        if prev is None or seq >= prev[0]:
                            best_f[key] = (seq, b["blk"])
        self._vmap_log = {k: v[1] for k, v in best_v.items()}
        self._file_vmap = {k: v[1] for k, v in best_f.items()}

    def _meta_inode(self, which):
        sr = self._load_super_root()
        if sr is None:
            return None
        return sr[which]

    def _dat_inode(self):
        if self._dat_inode_obj is None:
            self._dat_inode_obj = self._meta_inode("dat")
        return self._dat_inode_obj

    def _cpfile_inode(self):
        if self._cpfile_inode_obj is None:
            self._cpfile_inode_obj = self._meta_inode("cpfile")
        return self._cpfile_inode_obj

    def _sufile_inode(self):
        if self._sufile_inode_obj is None:
            self._sufile_inode_obj = self._meta_inode("sufile")
        return self._sufile_inode_obj

    def _dat_translate(self, vbn):
        """DAT 条目：vblocknr -> 物理块号。失败返回 None。"""
        if vbn in self._dat_guard:
            raise _DatCycle()
        dat = self._dat_inode()
        if dat is None:
            raise _DatCycle()
        self._dat_guard.add(vbn)
        try:
            blkoff, off = self._palloc_pos(self.dat_entry_size, vbn)
            blk = self._meta_block(dat, blkoff)
        finally:
            self._dat_guard.discard(vbn)
        if blk is None or off + 8 > len(blk):
            return None
        blocknr = _u64(blk, off)
        if blocknr == 0:
            return None
        # de_start / de_end 仅供取证参考，不做范围过滤
        return blocknr

    def _translate(self, vbn):
        """虚块号 -> 物理块号：先 DAT，成环或缺失时退回段摘要日志。"""
        if not vbn:
            return None
        if vbn not in self._dat_guard:
            try:
                blk = self._dat_translate(vbn)
            except _DatCycle:
                blk = None
            if blk:
                return blk
        self._scan_log()
        return self._vmap_log.get(vbn)

    def dat_entry(self, vblocknr):
        """直接查 DAT 条目（不经过 DAT 自引用兜底）。"""
        dat = self._dat_inode()
        if dat is None:
            return None
        blkoff, off = self._palloc_pos(self.dat_entry_size, vblocknr)
        blk = self._meta_block(dat, blkoff)
        if blk is None or off + 32 > len(blk):
            return None
        return {
            "vblocknr": vblocknr,
            "de_blocknr": _u64(blk, off),
            "de_start": _u64(blk, off + 8),
            "de_end": _u64(blk, off + 16),
            "de_rsv": _u64(blk, off + 24),
        }

    # -- bmap --------------------------------------------------------

    @staticmethod
    def _bmap_kind(raw):
        """粗判 bmap 形态：btree 根节点带 NILFS_BTREE_NODE_ROOT，direct 全 0。"""
        if len(raw) < BTREE_NODE_HEAD_SIZE:
            return "direct"
        flags = raw[0]
        level = raw[1]
        nch = _u16(raw, 2)
        if flags & BTREE_NODE_ROOT:
            return "btree"
        if flags == 0 and level <= BTREE_LEVEL_MAX and 1 <= nch <= 3:
            first_key = _u64(raw, 8)
            first_ptr = _u64(raw, 8 + 3 * 8)
            if first_key == 0 and first_ptr:
                return "btree"
        return "direct"

    def _bmap_lookup_kind(self, inode, raw, blkoff, kind):
        if kind == "direct":
            if blkoff * 8 + 8 > BMAP_SIZE - 8:
                return None
            return _u64(raw, 8 + blkoff * 8)
        return self._btree_lookup(raw, blkoff, 0)

    def _btree_lookup(self, node, blkoff, depth, root=True):
        if depth > BTREE_LEVEL_MAX or not node or len(node) < 16:
            return None
        level = node[1]
        nch = _u16(node, 2)
        if nch == 0 or level > BTREE_LEVEL_MAX:
            return None
        if root:
            keys_off = BTREE_NODE_HEAD_SIZE
            ncmax = (BMAP_SIZE - BTREE_NODE_HEAD_SIZE) // 16
        else:
            keys_off = BTREE_NODE_HEAD_SIZE + BTREE_NODE_EXTRA_PAD
            ncmax = max(1, (self.blocksize - keys_off) // 16)
        ptrs_off = keys_off + ncmax * 8
        nch = min(nch, ncmax, (len(node) - ptrs_off) // 8)
        if nch <= 0:
            return None
        pick = None
        for i in range(nch):
            key = _u64(node, keys_off + i * 8)
            if key <= blkoff:
                pick = i
        if pick is None:
            return None
        ptr = _u64(node, ptrs_off + pick * 8)
        if not ptr:
            return None
        if level == 0:
            return ptr
        child_blk = self._translate(ptr)
        child = self._read_block(child_blk) if child_blk else None
        if child is None:
            return None
        return self._btree_lookup(child, blkoff, depth + 1, root=False)

    def bmap_lookup(self, inode, blkoff):
        """文件逻辑块 -> 虚块号（vblocknr）；不支持返回 None。"""
        raw = inode.bmap_raw
        kind = self._bmap_kind(raw)
        order = (kind, "direct" if kind == "btree" else "btree")
        for k in order:
            v = self._bmap_lookup_kind(inode, raw, blkoff, k)
            if v:
                return v
        return None

    # -- 元数据块读取 ------------------------------------------------

    def _meta_block(self, inode, blkoff):
        """元数据文件（DAT/CPFILE/SUFILE/IFILE）的第 blkoff 块内容。"""
        if inode is None:
            return None
        key = (inode.ino, blkoff)
        if key in self._blk_cache:
            return self._blk_cache[key]
        self._blk_cache[key] = None            # 占位，防环
        vbn = self.bmap_lookup(inode, blkoff)
        blk = self._translate(vbn) if vbn else None
        if blk is None:
            self._scan_log()
            blk = self._file_vmap.get((inode.ino, blkoff))
        data = self._read_block(blk) if blk else None
        if data is None:
            self.notes.append(
                "元数据块缺失：ino=%s blkoff=%s（bmap vbn=%s）"
                % (inode.ino, blkoff, vbn))
        self._blk_cache[key] = data
        return data

    # -- 检查点 ------------------------------------------------------

    def _read_checkpoint(self, cno):
        cpfile = self._cpfile_inode()
        if cpfile is None:
            return None
        blkoff, off = self._cpfile_pos(cno)
        blk = self._meta_block(cpfile, blkoff)
        if blk is None or off + 64 > len(blk):
            return None
        flags = _u32(blk, off)
        cp = {
            "cno": cno,
            "cp_flags": flags,
            "flags_names": [n for n, bit in (("snapshot", CP_SNAPSHOT),
                                             ("invalid", CP_INVALID),
                                             ("sketch", CP_SKETCH),
                                             ("minor", CP_MINOR))
                            if flags & bit],
            "cp_checkpoints_count": _u32(blk, off + 4),
            "cp_snapshot_next": _u64(blk, off + 8),
            "cp_snapshot_prev": _u64(blk, off + 16),
            "cp_cno": _u64(blk, off + 24),
            "cp_create": _u64(blk, off + 32),
            "cp_nblk_inc": _u64(blk, off + 40),
            "cp_inodes_count": _u64(blk, off + 48),
            "cp_blocks_count": _u64(blk, off + 56),
            "cp_ifile_inode": Nilfs2Inode(
                blk[off + 64:off + 64 + self.inode_size], IFILE_INO),
        }
        cp["cp_create_iso"] = _iso(cp["cp_create"])
        if cp["cp_cno"] != cno:
            self.notes.append("检查点 cno 不匹配：期望 %d，块内为 %d"
                              % (cno, cp["cp_cno"]))
        return cp

    def checkpoints(self, limit=None):
        """已有检查点列表（cno 从 1 起；上限默认 min(last_cno, 512)）。"""
        last = int(self.sb.s_last_cno or 0)
        hi = min(last, 512)
        if limit is not None:
            hi = min(hi, int(limit))
        out = []
        for cno in range(1, hi + 1):
            cp = self._read_checkpoint(cno)
            if cp is None:
                continue
            if CP_INVALID & cp["cp_flags"]:
                continue
            out.append(cp)
        return out

    def _ifile_inode(self):
        """最新检查点里的内联 ifile inode。"""
        if self._ifile_inode_obj is not None:
            return self._ifile_inode_obj
        last = int(self.sb.s_last_cno or 0)
        tried = 0
        for cno in range(last, 0, -1):
            if tried >= 64:
                break
            tried += 1
            cp = self._read_checkpoint(cno)
            if cp is None:
                continue
            if CP_INVALID & cp["cp_flags"]:
                continue
            ino = cp["cp_ifile_inode"]
            if ino.i_mode and ino.i_size:
                self._ifile_inode_obj = ino
                self._ifile_cno = cno
                return ino
        self.notes.append("没有可用检查点，无法从 cp_ifile_inode 取 ifile inode")
        return None

    # -- inode -------------------------------------------------------

    def inode(self, ino):
        """按 inode 号取 inode（元数据 inode 直接来自超级根）。"""
        if ino in self._inode_cache:
            return self._inode_cache[ino]
        if ino in (DAT_INO, CPFILE_INO, SUFILE_INO):
            which = {DAT_INO: "dat", CPFILE_INO: "cpfile", SUFILE_INO: "sufile"}[ino]
            obj = self._meta_inode(which)
            if obj is not None:
                self._inode_cache[ino] = obj
            return obj
        ifile = self._ifile_inode()
        if ifile is None:
            raise NotImplementedError(
                "缺少可用检查点 / cp_ifile_inode，无法定位 ifile，"
                "因而无法读取 inode %d" % ino)
        blkoff, off = self._palloc_pos(self.inode_size, ino)
        blk = self._meta_block(ifile, blkoff)
        if blk is None or off + self.inode_size > len(blk):
            self._scan_log()
            blkno = self._file_vmap.get((IFILE_INO, blkoff))
            blk = self._read_block(blkno) if blkno else None
        if blk is None:
            self.notes.append("ifile 第 %d 块缺失，inode %d 不可读" % (blkoff, ino))
            return None
        obj = Nilfs2Inode(blk[off:off + self.inode_size], ino)
        if not obj.i_mode and not obj.i_size:
            self.notes.append("inode %d 为空（ifile blkoff=%d off=%d）"
                              % (ino, blkoff, off))
            return None
        self._inode_cache[ino] = obj
        return obj

    def inode_count_hint(self):
        """从 ifile 的 i_size 估算 inode 数（非权威）。"""
        ifile = self._ifile_inode()
        if ifile is None:
            return None
        epb = max(1, self.blocksize // self.inode_size)
        return ifile.i_size // self.inode_size

    # -- 文件读取 ----------------------------------------------------

    def _file_block(self, inode, blkoff):
        """文件逻辑块 -> 物理块内容（稀疏空洞返回零块）。"""
        vbn = self.bmap_lookup(inode, blkoff)
        blk = self._translate(vbn) if vbn else None
        if blk is None:
            self._scan_log()
            blk = self._file_vmap.get((inode.ino, blkoff))
        if blk is None:
            if vbn or blkoff < ((inode.i_size or 0) + self.blocksize - 1) // self.blocksize:
                self.notes.append("文件 ino=%s blkoff=%d 无块映射，补零"
                                  % (inode.ino, blkoff))
            return b"\x00" * self.blocksize
        data = self._read_block(blk)
        if data is None:
            self.notes.append("文件 ino=%s blkoff=%d 指向越界块 %d，补零"
                              % (inode.ino, blkoff, blk))
            return b"\x00" * self.blocksize
        return data

    def read_file(self, ino=None, offset=0, size=None, path=None):
        """读文件内容；``path`` 优先于 ``ino``。"""
        if path is not None:
            ino = self.lookup_path(path)
        if ino is None:
            raise Nilfs2Error("read_file 需要 ino 或 path")
        inode = self.inode(ino)
        if inode is None:
            raise Nilfs2Error("inode %s 不存在或不可读" % ino)
        if inode.is_dir:
            raise Nilfs2Error("inode %s 是目录，不能当文件读" % ino)
        total = int(inode.i_size or 0)
        offset = max(0, int(offset))
        if offset >= total:
            return b""
        end = total if size is None else min(total, offset + int(size))
        first = offset // self.blocksize
        last = (end - 1) // self.blocksize
        out = []
        for b in range(first, last + 1):
            out.append(self._file_block(inode, b))
        buf = b"".join(out)
        start = offset - first * self.blocksize
        return buf[start:start + (end - offset)]

    # -- 目录 --------------------------------------------------------

    def _dir_entries(self, inode):
        total = int(inode.i_size or 0)
        if total <= 0:
            return []
        nblk = (total + self.blocksize - 1) // self.blocksize
        out = []
        skipped = 0
        for b in range(nblk):
            blk = self._file_block(inode, b)
            pos = 0
            while pos + DIRENT_HEAD <= len(blk):
                ino = _u64(blk, pos)
                rec_len = _u16(blk, pos + 8)
                name_len = blk[pos + 10]
                ftype = blk[pos + 11]
                if rec_len < DIRENT_HEAD or rec_len % DIR_PAD or pos + rec_len > len(blk):
                    skipped += 1
                    break
                if ino == 0 or name_len == 0:
                    pos += rec_len
                    continue
                if DIRENT_HEAD + name_len > rec_len:
                    skipped += 1
                    pos += rec_len
                    continue
                raw = blk[pos + DIRENT_HEAD:pos + DIRENT_HEAD + name_len]
                out.append({
                    "name": _decode_name(raw),
                    "name_raw": raw,
                    "ino": ino,
                    "file_type": ftype,
                    "file_type_name": FT_NAMES.get(ftype, "ft%d" % ftype),
                })
                pos += rec_len
        if skipped:
            self.notes.append("目录 ino=%s 有 %d 个块出现非法 rec_len，已跳过"
                              % (inode.ino, skipped))
        return out

    def listdir(self, ino=None):
        """列目录；``ino`` 缺省为根目录（ino 2）。"""
        if ino is None:
            ino = ROOT_INO
        inode = self.inode(ino)
        if inode is None:
            raise Nilfs2Error("inode %s 不存在" % ino)
        if not inode.is_dir:
            raise Nilfs2Error("inode %s 不是目录（type=%s）" % (ino, inode.kind))
        return self._dir_entries(inode)

    def _child_ino(self, inode, name):
        for e in self._dir_entries(inode):
            if e["name"] == name:
                return e["ino"]
        return None

    def lookup_path(self, path):
        """路径 -> inode 号；不存在抛 ``FileNotFoundError``。"""
        if isinstance(path, bytes):
            path = _decode_name(path)
        parts = [p for p in str(path).replace("\\", "/").split("/") if p and p != "."]
        ino = ROOT_INO
        cur = self.inode(ino)
        for name in parts:
            if cur is None or not cur.is_dir:
                raise FileNotFoundError("路径 %r 中 %r 不是目录" % (path, name))
            nxt = self._child_ino(cur, name)
            if nxt is None:
                raise FileNotFoundError("路径不存在：%r（缺少 %r）" % (path, name))
            if name == "..":
                continue
            ino = nxt
            cur = self.inode(ino)
        return ino

    def walk(self, max_entries=200000):
        """遍历整棵树，返回 [{path, ino, type, size, mtime}]。"""
        out = []
        seen = set()
        stack = [("", ROOT_INO)]
        guard = 0
        while stack:
            prefix, ino = stack.pop()
            if (prefix, ino) in seen:
                continue
            seen.add((prefix, ino))
            inode = self.inode(ino)
            if inode is None:
                out.append({"path": prefix or "/", "ino": ino,
                            "type": "missing", "size": None, "mtime": None})
                continue
            out.append({
                "path": prefix or "/",
                "ino": ino,
                "type": inode.kind,
                "size": inode.i_size,
                "mtime": _iso(inode.i_mtime, inode.i_mtime_nsec or 0),
                "mode": inode.mode_str,
            })
            guard += 1
            if guard > max_entries:
                self.notes.append("walk 超过 %d 项，提前停止" % max_entries)
                break
            if not inode.is_dir:
                continue
            for e in self._dir_entries(inode):
                if e["name"] in (".", ".."):
                    continue
                child = "%s/%s" % (prefix, e["name"]) if prefix else "/" + e["name"]
                stack.append((child, e["ino"]))
        out.sort(key=lambda d: d["path"])
        return out

    def find(self, pattern):
        """按 glob 匹配路径（同时匹配 basename 与完整路径）。"""
        hits = []
        for item in self.walk():
            base = item["path"].rsplit("/", 1)[-1]
            if fnmatch.fnmatch(base, pattern) or fnmatch.fnmatch(item["path"], pattern):
                hits.append(item)
        return hits

    # -- 汇总 --------------------------------------------------------

    def info(self):
        sb = self.sb
        segs = self.segments()
        return {
            "fs": "nilfs2",
            "rev": "%s.%s" % (sb.s_rev_level, sb.s_minor_rev_level),
            "rev_level": sb.s_rev_level,
            "minor_rev_level": sb.s_minor_rev_level,
            "blocksize": self.blocksize,
            "log_block_size": sb.s_log_block_size,
            "blocks_per_segment": sb.s_blocks_per_segment,
            "segment_size": (sb.s_blocks_per_segment or 0) * self.blocksize,
            "segments": sb.s_nsegments,
            "segments_found": len(segs),
            "first_data_block": sb.s_first_data_block,
            "r_segments_percentage": sb.s_r_segments_percentage,
            "volume_name": self.sb.volume_name,
            "uuid": sb.uuid,
            "last_cno": sb.s_last_cno,
            "last_pseg": sb.s_last_pseg,
            "last_seq": sb.s_last_seq,
            "free_blocks_count": sb.s_free_blocks_count,
            "dev_size": sb.s_dev_size,
            "crc_ok": sb.crc_ok,
            "crc_calc": sb.crc_calc,
            "crc_seed": sb.s_crc_seed,
            "s_sum": sb.s_sum,
            "sb_offset": self.sb_offset,
            "sb_copies": len(self._sbs),
            "state": sb.s_state,
            "state_flags": [n for n, bit in (("valid", NILFS_VALID_FS),
                                             ("error", NILFS_ERROR_FS),
                                             ("resize", NILFS_RESIZE_FS))
                            if (sb.s_state or 0) & bit],
            "mnt_count": sb.s_mnt_count,
            "max_mnt_count": sb.s_max_mnt_count,
            "errors": sb.s_errors,
            "checkinterval": sb.s_checkinterval,
            "creator_os": sb.s_creator_os,
            "first_ino": sb.s_first_ino,
            "inode_size": self.inode_size,
            "dat_entry_size": self.dat_entry_size,
            "checkpoint_size": self.checkpoint_size,
            "segment_usage_size": self.segment_usage_size,
            "c_interval": sb.s_c_interval,
            "c_block_max": sb.s_c_block_max,
            "feature_compat": sb.s_feature_compat,
            "feature_compat_ro": sb.s_feature_compat_ro,
            "feature_incompat": sb.s_feature_incompat,
            "ctime": _iso(sb.s_ctime),
            "mtime": _iso(sb.s_mtime),
            "wtime": _iso(sb.s_wtime),
            "lastcheck": _iso(sb.s_lastcheck),
            "image_size": self.size,
            "notes": list(self.notes),
        }

    def summary(self):
        """一行摘要（取证报告常用）。"""
        i = self.info()
        return ("NILFS2 rev %s, %d B/block, %s segs, vol=%r, uuid=%s, "
                "last_cno=%s, last_pseg=%s, crc_ok=%s"
                % (i["rev"], i["blocksize"], i["segments"], i["volume_name"],
                   i["uuid"], i["last_cno"], i["last_pseg"], i["crc_ok"]))


# ---------------------------------------------------------------- 入口


def probe(sub):
    """判断镜像是否为 NILFS2（魔数 + 备份超级块）。"""
    try:
        head = sub.read(SUPER_OFFSET, 8)
        if head and len(head) == 8 and _u16(head, 6) == SUPER_MAGIC:
            return True
        size = getattr(sub, "size", None)
        if size is None:
            try:
                size = len(sub)
            except Exception:
                size = None
        if size:
            off = ((int(size) >> 12) - 1) << 12
            if off > SUPER_OFFSET:
                head = sub.read(off, 8)
                if head and len(head) == 8 and _u16(head, 6) == SUPER_MAGIC:
                    return True
    except Exception:
        return False
    return False


def open_fs(sub, **kw):
    """打开 NILFS2 镜像，返回 ``Nilfs2`` 实例。"""
    return Nilfs2(sub, **kw)


# ================================================================
#  自检：合成镜像
# ================================================================

class _BytesSub(object):
    """最小可读对象，模拟 ESK 的 SubImage 接口。"""

    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read(self, off, size):
        return self.data[off:off + size]

    def __len__(self):
        return len(self.data)


# 合成镜像的布局常量（块大小 4096）
_T_BS = 4096
_T_BPS = 250
_T_NSEG = 8
_T_FIRST = 2

_T_VBN = {
    "dat": (1, 2, 3),          # vblocknr 0 保留为 NILFS_BMAP_INVALID_PTR
    "cpfile": 4,
    "sufile": 5,
    "ifile": (6, 7, 8),
    "rootdir": 9,
    "txt": 10,
    "subdir": 11,
    "bt_n0": 12,          # B-tree 根节点内联在 inode 的 i_bmap[56] 里，不占块
    "bt_n1": 13,
    "bt_data": tuple(range(14, 22)),
}

_T_TXT = ("NILFS2 只读解析自检 A\n").encode("utf-8") * 4
_T_DEEP = "BTREE-BLK-内容-".encode("utf-8")


def _pad_block(data, bs=_T_BS):
    if len(data) > bs:
        raise ValueError("块内容超长")
    return bytes(data) + b"\x00" * (bs - len(data))


def _mk_inode(mode, size, blocks, ptrs=None, btree=None, uid=0, gid=0,
              links=1, ctime=1700000000, mtime=1700000100):
    raw = bytearray(INODE_SIZE_MIN)
    struct.pack_into("<Q", raw, 0x00, blocks)
    struct.pack_into("<Q", raw, 0x08, size)
    struct.pack_into("<q", raw, 0x10, ctime)
    struct.pack_into("<q", raw, 0x18, mtime)
    struct.pack_into("<I", raw, 0x20, 12345)
    struct.pack_into("<I", raw, 0x24, 67890)
    struct.pack_into("<I", raw, 0x28, uid)
    struct.pack_into("<I", raw, 0x2C, gid)
    struct.pack_into("<H", raw, 0x30, mode)
    struct.pack_into("<H", raw, 0x32, links)
    struct.pack_into("<I", raw, 0x34, 0)
    if ptrs:
        for i, p in enumerate(ptrs):
            # direct bmap 的指针自 sizeof(struct nilfs_direct_node)=8 之后开始
            struct.pack_into("<Q", raw, INODE_BMAP_OFF + 8 + i * 8, p)
    if btree is not None:
        raw[INODE_BMAP_OFF:INODE_BMAP_OFF + BMAP_SIZE] = btree
    return bytes(raw)


def _mk_btree_root(keys, ptrs):
    raw = bytearray(BMAP_SIZE)
    raw[0] = BTREE_NODE_ROOT
    raw[1] = 1                                  # level 1
    struct.pack_into("<H", raw, 2, len(ptrs))
    for i, k in enumerate(keys):
        struct.pack_into("<Q", raw, 8 + i * 8, k)
    for i, p in enumerate(ptrs):
        struct.pack_into("<Q", raw, 8 + 3 * 8 + i * 8, p)
    return bytes(raw)


def _mk_btree_node(keys, ptrs, level=0, bs=_T_BS):
    raw = bytearray(bs)
    raw[0] = 0                                  # 非根节点
    raw[1] = level
    struct.pack_into("<H", raw, 2, len(ptrs))
    keys_off = BTREE_NODE_HEAD_SIZE + BTREE_NODE_EXTRA_PAD
    ncmax = max(1, (bs - keys_off) // 16)
    for i, k in enumerate(keys):
        struct.pack_into("<Q", raw, keys_off + i * 8, k)
    for i, p in enumerate(ptrs):
        struct.pack_into("<Q", raw, keys_off + ncmax * 8 + i * 8, p)
    return bytes(raw)


def _mk_dirblock(entries, bs=_T_BS):
    out = bytearray()
    for idx, (ino, name, ftype) in enumerate(entries):
        nraw = name.encode("utf-8") if isinstance(name, str) else name
        rec = (DIRENT_HEAD + len(nraw) + DIR_PAD - 1) & ~(DIR_PAD - 1)
        if idx == len(entries) - 1:
            rec = bs - len(out)
        item = bytearray(rec)
        struct.pack_into("<Q", item, 0, ino)
        struct.pack_into("<H", item, 8, rec)
        item[10] = len(nraw)
        item[11] = ftype
        item[DIRENT_HEAD:DIRENT_HEAD + len(nraw)] = nraw
        out += item
    return _pad_block(bytes(out), bs)


def _mk_segsum(seq, cno, next_blk, nblocks, finfos, flags=SS_SR | SS_LOGBGN | SS_LOGEND,
               bs=_T_BS, seed=0x9F3A1C2D):
    """finfos: [(ino, nblocks, ndatablk, [(vblocknr, blkoff_or_None), ...])]"""
    nbins = sum(len(f[3]) for f in finfos)
    sumbytes = SEGSUM_SIZE + len(finfos) * FINFO_SIZE + nbins * BINFO_SIZE
    raw = bytearray(sumbytes)
    struct.pack_into("<I", raw, 8, SEGSUM_MAGIC)
    struct.pack_into("<H", raw, 12, SEGSUM_SIZE)
    struct.pack_into("<H", raw, 14, flags)
    struct.pack_into("<Q", raw, 16, seq)
    struct.pack_into("<q", raw, 24, 1700000200)
    struct.pack_into("<Q", raw, 32, next_blk)
    struct.pack_into("<I", raw, 40, nblocks)
    struct.pack_into("<I", raw, 44, len(finfos))
    struct.pack_into("<I", raw, 48, sumbytes)
    struct.pack_into("<Q", raw, 56, cno)
    pos = SEGSUM_SIZE
    for ino, nb, ndatablk, _bins in finfos:
        struct.pack_into("<Q", raw, pos, ino)
        struct.pack_into("<Q", raw, pos + 8, cno)
        struct.pack_into("<I", raw, pos + 16, nb)
        struct.pack_into("<I", raw, pos + 20, ndatablk)
        pos += FINFO_SIZE
    for ino, _nb, _nd, bins in finfos:
        for vbn, blkoff in bins:
            if ino == DAT_INO:
                struct.pack_into("<Q", raw, pos, vbn)
                raw[pos + 8] = 0
            else:
                struct.pack_into("<Q", raw, pos, vbn)
                struct.pack_into("<Q", raw, pos + 8, blkoff or 0)
            pos += BINFO_SIZE
    datasum = nilfs_crc32(seed, bytes(raw))
    struct.pack_into("<I", raw, 0, datasum)
    calc = nilfs_crc32(seed, bytes(raw[0:4]) + b"\x00" * 4 + bytes(raw[8:]))
    struct.pack_into("<I", raw, 4, calc)
    return bytes(raw), sumbytes


def _mk_super(bs, bps, nseg, first_data, devsize, last_cno, last_pseg,
              last_seq, volname, uuid, seed=0x9F3A1C2D, rev=2, minor=0):
    raw = bytearray(SB_BYTES_DEFAULT)
    log_blk = 0
    while (1024 << log_blk) < bs:
        log_blk += 1
    blk = log_blk
    struct.pack_into("<I", raw, 0x00, rev)
    struct.pack_into("<H", raw, 0x04, minor)
    struct.pack_into("<H", raw, 0x06, SUPER_MAGIC)
    struct.pack_into("<H", raw, 0x08, SB_BYTES_DEFAULT)
    struct.pack_into("<H", raw, 0x0A, 0)
    struct.pack_into("<I", raw, 0x0C, seed)
    struct.pack_into("<I", raw, 0x10, 0)
    struct.pack_into("<I", raw, 0x14, blk)
    struct.pack_into("<Q", raw, 0x18, nseg)
    struct.pack_into("<Q", raw, 0x20, devsize)
    struct.pack_into("<Q", raw, 0x28, first_data)
    struct.pack_into("<I", raw, 0x30, bps)
    struct.pack_into("<I", raw, 0x34, 10)
    struct.pack_into("<Q", raw, 0x38, last_cno)
    struct.pack_into("<Q", raw, 0x40, last_pseg)
    struct.pack_into("<Q", raw, 0x48, last_seq)
    struct.pack_into("<Q", raw, 0x50, 1200)
    struct.pack_into("<q", raw, 0x58, 1699000000)
    struct.pack_into("<q", raw, 0x60, 1700000000)
    struct.pack_into("<q", raw, 0x68, 1700000300)
    struct.pack_into("<H", raw, 0x70, 3)
    struct.pack_into("<H", raw, 0x72, 50)
    struct.pack_into("<H", raw, 0x74, NILFS_VALID_FS)
    struct.pack_into("<H", raw, 0x76, 1)
    struct.pack_into("<q", raw, 0x78, 1699000500)
    struct.pack_into("<I", raw, 0x80, 0)
    struct.pack_into("<I", raw, 0x84, 0)
    struct.pack_into("<H", raw, 0x88, 0)
    struct.pack_into("<H", raw, 0x8A, 0)
    struct.pack_into("<I", raw, 0x8C, USER_INO)
    struct.pack_into("<H", raw, 0x90, INODE_SIZE_MIN)
    struct.pack_into("<H", raw, 0x92, DAT_ENTRY_SIZE_MIN)
    struct.pack_into("<H", raw, 0x94, CHECKPOINT_SIZE_MIN)
    struct.pack_into("<H", raw, 0x96, SUFILE_ENTRY_SIZE_MIN)
    raw[0x98:0x98 + 16] = uuid
    vraw = volname.encode("utf-8") if isinstance(volname, str) else volname
    raw[0xA8:0xA8 + len(vraw[:80])] = vraw[:80]
    struct.pack_into("<I", raw, 0xF8, 5)
    struct.pack_into("<I", raw, 0xFC, 2048)
    struct.pack_into("<Q", raw, 0x100, 0)
    struct.pack_into("<Q", raw, 0x108, 0)
    struct.pack_into("<Q", raw, 0x110, 0)
    crc = nilfs_crc32(seed, raw)
    struct.pack_into("<I", raw, 0x10, crc)
    return bytes(raw)


def _build_image(volname="NILFS2测试卷", corrupt_main=False, corrupt_crc=False,
                 extra_pseg=False):
    """构造最小但布局自洽的 NILFS2 镜像。

    结构：主超级块(1024) + 备份(devsize 末 4KiB) + 一个 pseg
          (段摘要 + 超级根 + DAT/CPFILE/SUFILE/IFILE + 根目录 + 数据块)。
    ``extra_pseg=True`` 时在第 2 段首块再放一个只有段摘要的 pseg，
    并用 ``ss_next`` 指回第 1 个 pseg，用于验证段链回溯与最新检查点。
    """
    bs = _T_BS
    bps = _T_BPS
    nseg = _T_NSEG
    first = _T_FIRST
    pseg = first
    sr_blk = pseg + 1
    payload_base = pseg + 2
    devsize = (first + nseg * bps + 1) * bs
    img = bytearray(devsize)

    def put(blk, data):
        img[blk * bs:blk * bs + len(data)] = data

    # --- 内容
    btree_data = [(_T_DEEP + ("%02d" % i).encode("ascii")).ljust(32, b".") * (bs // 32)
                  for i in range(8)]
    root_dir = _mk_dirblock([
        (ROOT_INO, ".", 2), (ROOT_INO, "..", 2),
        (11, "中文.txt", 1), (12, "中文目录", 2),
    ], bs)
    sub_dir = _mk_dirblock([
        (12, ".", 2), (ROOT_INO, "..", 2), (13, "deep.bin", 1),
    ], bs)

    # --- 元数据 inode（vblocknr 见 _T_VBN）
    dat_inode = _mk_inode(S_IFREG | 0o600, 3 * bs, 3, ptrs=list(_T_VBN["dat"]))
    cpfile_inode = _mk_inode(S_IFREG | 0o600, bs, 1, ptrs=[_T_VBN["cpfile"]])
    sufile_inode = _mk_inode(S_IFREG | 0o600, bs, 1, ptrs=[_T_VBN["sufile"]])
    ifile_inode = _mk_inode(S_IFREG | 0o600, 3 * bs, 3, ptrs=list(_T_VBN["ifile"]))

    # --- ifile 条目块：ino 0..31（每块 32 个 inode）
    ifile_entries = bytearray(bs)
    root_inode = _mk_inode(S_IFDIR | 0o755, bs, 1, ptrs=[_T_VBN["rootdir"]],
                           links=2, ctime=1699000100, mtime=1700000000)
    txt_inode = _mk_inode(S_IFREG | 0o644, len(_T_TXT), 1, ptrs=[_T_VBN["txt"]])
    sub_inode = _mk_inode(S_IFDIR | 0o755, bs, 1, ptrs=[_T_VBN["subdir"]],
                          links=2, ctime=1699000200)
    bt_inode = _mk_inode(
        S_IFREG | 0o644, 8 * bs, 11,
        btree=_mk_btree_root([0, 4], [_T_VBN["bt_n0"], _T_VBN["bt_n1"]]))
    for ino, raw in ((ROOT_INO, root_inode), (11, txt_inode),
                     (12, sub_inode), (13, bt_inode)):
        ifile_entries[ino * INODE_SIZE_MIN:(ino + 1) * INODE_SIZE_MIN] = raw

    # --- DAT 条目块：vblocknr -> 物理块号
    dat_entries = bytearray(bs)
    epb_dat = bs // DAT_ENTRY_SIZE_MIN
    for vbn in range(1, 22):
        off = (vbn % epb_dat) * DAT_ENTRY_SIZE_MIN
        struct.pack_into("<Q", dat_entries, off, payload_base + vbn - 1)
        struct.pack_into("<Q", dat_entries, off + 8, 1)
        struct.pack_into("<Q", dat_entries, off + 16, 0xFFFFFFFF)
    dat_desc = bytearray(bs)
    struct.pack_into("<I", dat_desc, 0, 0)
    dat_bitmap = bytearray(bs)
    for vbn in range(1, 22):
        dat_bitmap[vbn // 8] |= 1 << (vbn % 8)

    # --- CPFILE 块 0：header + 检查点（extra_pseg 时写 cno 1 与 2）
    cpfile_blk = bytearray(bs)
    cnos = (1, 2) if extra_pseg else (1,)
    struct.pack_into("<Q", cpfile_blk, 0, len(cnos))     # ch_ncheckpoints
    struct.pack_into("<Q", cpfile_blk, 8, 0)             # ch_nsnapshots
    cp_off = CHECKPOINT_SIZE_MIN                         # first_entry_offset = 1
    for cno in cnos:
        off = cp_off + (cno - 1) * CHECKPOINT_SIZE_MIN
        struct.pack_into("<I", cpfile_blk, off, 0)             # cp_flags
        struct.pack_into("<I", cpfile_blk, off + 4, 1)         # cp_checkpoints_count
        struct.pack_into("<Q", cpfile_blk, off + 24, cno)      # cp_cno
        struct.pack_into("<q", cpfile_blk, off + 32, 1700000300 + cno)   # cp_create
        struct.pack_into("<Q", cpfile_blk, off + 40, 21)       # cp_nblk_inc
        struct.pack_into("<Q", cpfile_blk, off + 48, 8)        # cp_inodes_count
        struct.pack_into("<Q", cpfile_blk, off + 56, 21)       # cp_blocks_count
        cpfile_blk[off + 64:off + 64 + INODE_SIZE_MIN] = ifile_inode

    sufile_blk = bytearray(bs)
    struct.pack_into("<Q", sufile_blk, 0, 7)
    struct.pack_into("<Q", sufile_blk, 8, 1)

    # --- 按顺序铺 payload（顺序必须与 finfo 一致）
    payload = [
        bytes(dat_desc), bytes(dat_bitmap), bytes(dat_entries),
        bytes(cpfile_blk), bytes(sufile_blk),
        b"\x00" * bs,                 # ifile desc
        b"\x00" * bs,                 # ifile bitmap
        bytes(ifile_entries),
        root_dir, _T_TXT.ljust(1, b"\x00"), sub_dir,
        _mk_btree_node([0, 1, 2, 3],
                       [_T_VBN["bt_data"][i] for i in range(4)], 0, bs),
        _mk_btree_node([4, 5, 6, 7],
                       [_T_VBN["bt_data"][i] for i in range(4, 8)], 0, bs),
    ]
    for d in btree_data:
        payload.append(d)
    assert len(payload) == 21, len(payload)

    # --- 段摘要
    finfos = [
        (DAT_INO, 3, 0, [(1, None), (2, None), (3, None)]),
        (CPFILE_INO, 1, 0, [(_T_VBN["cpfile"], 0)]),
        (SUFILE_INO, 1, 0, [(_T_VBN["sufile"], 0)]),
        (IFILE_INO, 3, 0, [(6, 0), (7, 1), (8, 2)]),
        (ROOT_INO, 1, 1, [(9, 0)]),
        (11, 1, 1, [(10, 0)]),
        (12, 1, 1, [(11, 0)]),
        (13, 10, 8, [(12, 0), (13, 0)] +
                    [(14 + i, i) for i in range(8)]),
    ]
    nblocks = 2 + len(payload)                    # 段摘要 + 超级根 + payload
    segsum, sumbytes = _mk_segsum(1, 1, 0, nblocks, finfos, bs=bs)
    assert sumbytes <= bs, sumbytes
    put(pseg, _pad_block(segsum, bs))

    # --- 超级根
    sr = bytearray(bs)
    struct.pack_into("<I", sr, 0, nilfs_crc32(0x9F3A1C2D, bytes(sr[4:16])))
    struct.pack_into("<H", sr, 4, SR_HEAD_SIZE + 3 * INODE_SIZE_MIN)
    struct.pack_into("<H", sr, 6, 0)
    struct.pack_into("<q", sr, 8, 1700000250)
    sr[SR_HEAD_SIZE:SR_HEAD_SIZE + INODE_SIZE_MIN] = dat_inode
    sr[SR_HEAD_SIZE + INODE_SIZE_MIN:SR_HEAD_SIZE + 2 * INODE_SIZE_MIN] = cpfile_inode
    sr[SR_HEAD_SIZE + 2 * INODE_SIZE_MIN:SR_HEAD_SIZE + 3 * INODE_SIZE_MIN] = sufile_inode
    put(sr_blk, bytes(sr))

    # --- payload 落地
    for i, data in enumerate(payload):
        put(payload_base + i, data)

    # --- 可选的第二个 pseg：只有段摘要，ss_next 指回第 1 个 pseg
    last_cno, last_pseg, last_seq = 1, pseg, 1
    if extra_pseg:
        pseg2 = first + bps
        segsum2, _sb2 = _mk_segsum(2, 2, pseg, 1, [],
                                   flags=SS_LOGBGN | SS_LOGEND, bs=bs)
        put(pseg2, _pad_block(segsum2, bs))
        last_cno, last_pseg, last_seq = 2, pseg2, 2

    # --- 超级块（主 + 备份）
    uuid = bytes(range(16))
    sb = _mk_super(bs, bps, nseg, first, devsize, last_cno, last_pseg,
                   last_seq, volname, uuid)
    sb2_off = ((devsize >> 12) - 1) << 12
    img[SUPER_OFFSET:SUPER_OFFSET + len(sb)] = sb
    img[sb2_off:sb2_off + len(sb)] = sb
    if corrupt_main:
        img[SUPER_OFFSET:SUPER_OFFSET + 16] = b"\x00" * 16
    if corrupt_crc:
        # 两副本都改卷名区一个字节，但不更新 s_sum
        for base in (SUPER_OFFSET, sb2_off):
            img[base + 0xA8 + 3] ^= 0xFF
    return bytes(img), {
        "bs": bs, "pseg": pseg, "sr_blk": sr_blk, "payload_base": payload_base,
        "sb2_off": sb2_off, "devsize": devsize, "nblocks": nblocks,
        "txt": _T_TXT, "bt_data": btree_data, "bps": bps,
        "pseg2": (first + bps) if extra_pseg else None,
    }


def _selftest():
    results = []

    def chk(name, cond, extra=""):
        results.append((name, bool(cond), extra))
        if not cond:
            raise AssertionError("%s 失败%s" % (name, (": " + extra) if extra else ""))

    img, meta = _build_image()
    sub = _BytesSub(img)

    # 1) probe 命中 / 不命中
    chk("1a probe 命中", probe(sub) is True)
    chk("1b probe 非 NILFS2 不命中",
        probe(_BytesSub(b"\x00" * 65536)) is False)
    chk("1c probe 短输入不抛异常",
        probe(_BytesSub(b"\x01\x02\x03")) is False)

    fs = Nilfs2(sub)
    info = fs.info()

    # 2) 版本 / 块大小 / 段数 / 卷名 / uuid
    chk("2a rev", info["rev"] == "2.0", info["rev"])
    chk("2b blocksize", info["blocksize"] == 4096, str(info["blocksize"]))
    chk("2c segments", info["segments"] == 8, str(info["segments"]))
    chk("2d 卷名(中文)", info["volume_name"] == "NILFS2测试卷",
        repr(info["volume_name"]))
    chk("2e uuid", info["uuid"] == "00010203-0405-0607-0809-0a0b0c0d0e0f",
        str(info["uuid"]))
    chk("2f 段数解析", info["segments_found"] >= 1, str(info["segments_found"]))
    chk("2g last_cno/last_pseg",
        info["last_cno"] == 1 and info["last_pseg"] == meta["pseg"])
    chk("2h 两个超级块副本", len(fs.superblocks()) == 2)
    chk("2i 选中副本为 1024", fs.sb_offset == SUPER_OFFSET)

    # 3) 主超级块坏 -> 回退备份
    img_bad, meta_bad = _build_image(corrupt_main=True)
    fs_bad = Nilfs2(_BytesSub(img_bad))
    chk("3a 主块坏回退备份偏移", fs_bad.sb_offset == meta_bad["sb2_off"],
        "%s vs %s" % (fs_bad.sb_offset, meta_bad["sb2_off"]))
    chk("3b 回退后仍能读卷名", fs_bad.info()["volume_name"] == "NILFS2测试卷")

    # 4) 校验和
    chk("4a 正常镜像 crc_ok True", info["crc_ok"] is True, repr(info["crc_ok"]))
    img_crc, _ = _build_image(corrupt_crc=True)
    fs_crc = Nilfs2(_BytesSub(img_crc))
    chk("4b 改一字节 crc_ok False", fs_crc.info()["crc_ok"] is False,
        repr(fs_crc.info()["crc_ok"]))
    chk("4c 坏 CRC 有 note",
        any("CRC" in n for n in fs_crc.info()["notes"]))

    # 5) 目录 / 读文件
    names = [e["name"] for e in fs.listdir()]
    chk("5a 根目录项", set(names) == {".", "..", "中文.txt", "中文目录"}, str(names))
    txt = fs.read_file(11)
    chk("5b 读文件(中文内容)", txt == meta["txt"], repr(txt[:24]))
    chk("5c lookup_path 中文路径",
        fs.lookup_path("/中文目录/deep.bin") == 13)
    sub_ino = fs.lookup_path("/中文目录")
    chk("5d 子目录 listdir",
        set(e["name"] for e in fs.listdir(sub_ino)) == {".", "..", "deep.bin"})
    deep = fs.read_file(13)
    expect_deep = b"".join(meta["bt_data"])
    chk("5e btree 文件 8 块内容", deep == expect_deep,
        "%d vs %d 字节" % (len(deep), len(expect_deep)))
    paths = [w["path"] for w in fs.walk()]
    chk("5f walk 含深路径", "/中文目录/deep.bin" in paths, str(paths))
    chk("5g find glob", [h["path"] for h in fs.find("*.txt")] == ["/中文.txt"],
        str([h["path"] for h in fs.find("*.txt")]))
    chk("5h 读取偏移", fs.read_file(11, offset=4, size=8) == meta["txt"][4:12])

    # 5i) 抹掉 DAT 条目块，强制只走段摘要日志映射
    img_nd, meta_nd = _build_image()
    b_nd = bytearray(img_nd)
    dat_blk = meta_nd["payload_base"] + 2          # DAT 的第 3 个 payload 块
    b_nd[dat_blk * 4096:(dat_blk + 1) * 4096] = b"\x00" * 4096
    fs_nd = Nilfs2(_BytesSub(bytes(b_nd)))
    chk("5i 无 DAT 时按日志映射读文件", fs_nd.read_file(11) == meta_nd["txt"])
    chk("5j 无 DAT 时目录仍可列",
        set(e["name"] for e in fs_nd.listdir()) == {".", "..", "中文.txt", "中文目录"})

    # 6) 检查点 / 段摘要 / 超级根
    cps = fs.checkpoints()
    chk("6a 检查点可读", len(cps) == 1 and cps[0]["cp_cno"] == 1, str(len(cps)))
    chk("6b 检查点内联 ifile inode",
        cps[0]["cp_ifile_inode"].is_file and cps[0]["cp_ifile_inode"].i_size == 3 * 4096)
    segs = fs.segments()
    chk("6c 段摘要", len(segs) == 1 and segs[0]["cno"] == 1 and
        segs[0]["nfinfo"] == 8, str(len(segs)))
    chk("6d 段摘要 finfo 数", segs[0]["nblocks"] == meta["nblocks"])
    sr = fs.super_root()
    chk("6e 超级根", sr is not None and sr["blk"] == meta["sr_blk"])
    chk("6f DAT 条目可读",
        fs.dat_entry(1) is not None and
        fs.dat_entry(1)["de_blocknr"] == meta["payload_base"])
    chk("6g btree 根节点判定",
        Nilfs2._bmap_kind(fs.inode(13).bmap_raw) == "btree")

    # 6h) 段链 ss_next 回溯 + 最新检查点
    img_ch, meta_ch = _build_image(extra_pseg=True)
    fs_ch = Nilfs2(_BytesSub(img_ch))
    segs_ch = fs_ch.segments()
    chk("6h 段链两段", len(segs_ch) == 2, str([s["blk"] for s in segs_ch]))
    chk("6i 段链首段为最新 pseg",
        segs_ch and segs_ch[0]["blk"] == meta_ch["pseg2"],
        str([s["blk"] for s in segs_ch]))
    chk("6j ss_next 指回旧 pseg",
        segs_ch and segs_ch[0]["next"] == meta_ch["pseg"])
    chk("6k 检查点按 cno 递增",
        [c["cp_cno"] for c in fs_ch.checkpoints()] == [1, 2],
        str([c["cp_cno"] for c in fs_ch.checkpoints()]))
    chk("6l 最新 cno 下仍可读文件", fs_ch.read_file(11) == meta_ch["txt"])

    # 7) 截断输入抛明确异常
    try:
        Nilfs2(_BytesSub(b"\x00" * 200))
        chk("7a 截断抛异常", False)
    except Nilfs2Error as exc:
        chk("7a 截断抛异常", True)
        chk("7b 异常信息明确", "过短" in str(exc), str(exc))
    try:
        Nilfs2(_BytesSub(b"\x00" * 65536))
        chk("7c 非 NILFS2 抛异常", False)
    except NotNilfs2Error as exc:
        chk("7c 非 NILFS2 抛异常", True)
        chk("7d 异常信息为魔数", "魔数" in str(exc), str(exc))
    try:
        fs.read_file(9999)
        chk("7e 不存在的 inode", False)
    except Nilfs2Error:
        chk("7e 不存在的 inode", True)
    try:
        fs.listdir(11)
        chk("7f 非目录 listdir", False)
    except Nilfs2Error:
        chk("7f 非目录 listdir", True)

    ok = sum(1 for _n, good, _x in results if good)
    print("NILFS2 自检：%d/%d 通过" % (ok, len(results)))
    for name, good, extra in results:
        print("  [%s] %s%s" % ("PASS" if good else "FAIL", name,
                               ("  <- " + extra) if (extra and not good) else ""))
    print("摘要：%s" % fs.summary())
    print("notes：%s" % ("; ".join(info["notes"]) or "无"))
    return results


if __name__ == "__main__":
    _selftest()
