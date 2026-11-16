# ============================================================
#  ESK · Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""EROFS (Enhanced Read-Only File System) 只读解析

格式依据 Linux `fs/erofs/erofs_fs.h`（on-disk 结构，全部小端）。

已实现：
    · 超级块：偏移 1024，magic 0xE0F5E1E2，144 字节（base 128 + extslots）
    · inode：compact 32 B / extended 64 B，由 i_format bit0 判定；
      数据布局 i_format>>1：0=FLAT_PLAIN / 1=COMPRESSED_FULL /
      2=FLAT_INLINE / 3=COMPRESSED_COMPACT / 4=CHUNK_BASED
    · nid → 偏移：(nid & 0xFFFFFFFF) << 5，再加 meta_blkaddr << blkszbits
    · 目录：erofs_dirent 12 B（nid le64@0 / nameoff le16@8 / file_type u8@0xA），
      名字紧跟 dirent 数组连续存放；一个目录可跨多个 dir block
    · 读文件：FLAT_PLAIN（raw_blkaddr 起连续块）、FLAT_INLINE（尾部内联在 inode 之后）
    · LZ4 block 解压（自实现，含 0padding 尾部零填充的宽容停止）
    · COMPRESSED_COMPACT / COMPRESSED_FULL 的 lcluster 索引（每逻辑簇一条 8 B 记录），
      单算法 LZ4、clusterofs=0、无 fragment 的常见情形可以读通
    · lookup_path / walk / find / listdir / read_file

未实现（明确抛 NotImplementedError，不做假支持）：
    · CHUNK_BASED（多设备 chunk 索引）
    · 压缩：fragment（packed inode）、HEAD2（1 MiB 处第二算法头）、
      clusterofs != 0 的 partial lcluster、算法 != LZ4（LZMA/ZLIB/ZSTD）、
      新式 extent 索引（z_erofs_extent）
    · 硬链接父目录回溯（lookup_path 中 ".." 直接忽略）
    · xattr 内容解析（只按 icount 跳过 inline xattr 区域）
    · 写操作

关键格式点（易踩坑，已记录）：
    * 超级块 0x18 是 epoch（u64，compact inode 的时间基准），build_time 在 0x6C（u32）；
      两者都不是同一个字段，别混用
    * i_format 的 bit0 只表示 compact/extended，布局位从 bit1 起，共 3 bit
    * dirent 的名字不跨块：每块最后一个条目的名字用 strnlen 语义（到块尾、去 NUL）
"""

import fnmatch
import struct

__all__ = [
    "Erofs", "ErofsError", "ErofsTruncated", "ErofsInode", "ErofsDirEntry",
    "EROFS_SUPER_MAGIC", "EROFS_SUPER_OFFSET", "lz4_decode_block",
    "probe", "open_fs",
]

# ---------------------------------------------------------------- 常量

EROFS_SUPER_OFFSET = 1024
EROFS_SUPER_MAGIC = 0xE0F5E1E2
EROFS_SB_BASE = 128              # 基础超级块长度
EROFS_SB_EXTSLOT = 16            # 每个扩展槽 16 字节
EROFS_ISLOTBITS = 5              # nid 以 32 字节为槽
EROFS_ISLOTSIZE = 1 << EROFS_ISLOTBITS
EROFS_NAME_LEN = 255
EROFS_DIRENT_SIZE = 12
EROFS_DIRENT_NID_METABOX_BIT = 63
EROFS_DIRENT_NID_MASK = (1 << EROFS_DIRENT_NID_METABOX_BIT) - 1

# feature_compat
EROFS_FEATURE_COMPAT_SB_CHKSUM = 0x00000001
EROFS_FEATURE_COMPAT_MTIME = 0x00000002
EROFS_FEATURE_COMPAT_XATTR_FILTER = 0x00000004
EROFS_FEATURE_COMPAT_SHARED_EA_IN_METABOX = 0x00000008
EROFS_FEATURE_COMPAT_PLAIN_XATTR_PFX = 0x00000010
EROFS_FEATURE_COMPAT_ISHARE_XATTRS = 0x00000020

# feature_incompat
EROFS_FEATURE_INCOMPAT_LZ4_0PADDING = 0x00000001
EROFS_FEATURE_INCOMPAT_COMPR_CFGS = 0x00000002
EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER = 0x00000002
EROFS_FEATURE_INCOMPAT_CHUNKED_FILE = 0x00000004
EROFS_FEATURE_INCOMPAT_DEVICE_TABLE = 0x00000008
EROFS_FEATURE_INCOMPAT_COMPR_HEAD2 = 0x00000008
EROFS_FEATURE_INCOMPAT_ZTAILPACKING = 0x00000010
EROFS_FEATURE_INCOMPAT_FRAGMENTS = 0x00000020
EROFS_FEATURE_INCOMPAT_DEDUPE = 0x00000020
EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES = 0x00000040
EROFS_FEATURE_INCOMPAT_48BIT = 0x00000080
EROFS_FEATURE_INCOMPAT_METABOX = 0x00000100

COMPAT_FEATURE_NAMES = (
    (EROFS_FEATURE_COMPAT_SB_CHKSUM, "SB_CHKSUM"),
    (EROFS_FEATURE_COMPAT_MTIME, "MTIME"),
    (EROFS_FEATURE_COMPAT_XATTR_FILTER, "XATTR_FILTER"),
    (EROFS_FEATURE_COMPAT_SHARED_EA_IN_METABOX, "SHARED_EA_IN_METABOX"),
    (EROFS_FEATURE_COMPAT_PLAIN_XATTR_PFX, "PLAIN_XATTR_PFX"),
    (EROFS_FEATURE_COMPAT_ISHARE_XATTRS, "ISHARE_XATTRS"),
)

INCOMPAT_FEATURE_NAMES = (
    (EROFS_FEATURE_INCOMPAT_LZ4_0PADDING, "LZ4_0PADDING"),
    (EROFS_FEATURE_INCOMPAT_COMPR_CFGS, "COMPR_CFGS"),
    (EROFS_FEATURE_INCOMPAT_CHUNKED_FILE, "CHUNKED_FILE"),
    (EROFS_FEATURE_INCOMPAT_DEVICE_TABLE, "DEVICE_TABLE"),
    (EROFS_FEATURE_INCOMPAT_ZTAILPACKING, "ZTAILPACKING"),
    (EROFS_FEATURE_INCOMPAT_FRAGMENTS, "FRAGMENTS"),
    (EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES, "XATTR_PREFIXES"),
    (EROFS_FEATURE_INCOMPAT_48BIT, "48BIT"),
    (EROFS_FEATURE_INCOMPAT_METABOX, "METABOX"),
)

# 数据布局（i_format >> 1）
FLAT_PLAIN = 0
COMPRESSED_FULL = 1
FLAT_INLINE = 2
COMPRESSED_COMPACT = 3
CHUNK_BASED = 4

LAYOUT_NAMES = {
    FLAT_PLAIN: "flat_plain",
    COMPRESSED_FULL: "compressed_full",
    FLAT_INLINE: "flat_inline",
    COMPRESSED_COMPACT: "compressed_compact",
    CHUNK_BASED: "chunk_based",
}

COMPRESSED_LAYOUTS = (COMPRESSED_FULL, COMPRESSED_COMPACT)

# z_erofs_lcluster_index.di_advise 低 2 位
LCLUSTER_HEAD = 0
LCLUSTER_NONHEAD = 1
LCLUSTER_PLAIN = 2
LCLUSTER_HEAD2 = 3
LCLUSTER_TYPE_MASK = 3

# 压缩算法（h_algorithmtype 半字节）
Z_COMPRESSION_LZ4 = 0
Z_COMPRESSION_LZMA = 1
Z_COMPRESSION_DEFLATE = 2
Z_COMPRESSION_ZSTD = 3

Z_COMPRESSION_NAMES = {
    Z_COMPRESSION_LZ4: "lz4",
    Z_COMPRESSION_LZMA: "lzma",
    Z_COMPRESSION_DEFLATE: "deflate",
    Z_COMPRESSION_ZSTD: "zstd",
}

# 文件类型（dirent.file_type，与内核 FT_* 对齐）
FT_UNKNOWN = 0
FT_REG_FILE = 1
FT_DIR = 2
FT_CHRDEV = 3
FT_BLKDEV = 4
FT_FIFO = 5
FT_SOCK = 6
FT_SYMLINK = 7

FILE_TYPE_NAMES = {
    FT_UNKNOWN: "unknown",
    FT_REG_FILE: "file",
    FT_DIR: "dir",
    FT_CHRDEV: "chrdev",
    FT_BLKDEV: "blkdev",
    FT_FIFO: "fifo",
    FT_SOCK: "socket",
    FT_SYMLINK: "symlink",
}

# 文件类型（i_mode 高位）
S_IFMT = 0o170000
S_IFSOCK = 0o140000
S_IFLNK = 0o120000
S_IFREG = 0o100000
S_IFBLK = 0o060000
S_IFDIR = 0o040000
S_IFCHR = 0o020000
S_IFIFO = 0o010000

MODE_TYPE_NAMES = (
    (S_IFREG, "file"),
    (S_IFDIR, "dir"),
    (S_IFLNK, "symlink"),
    (S_IFCHR, "chrdev"),
    (S_IFBLK, "blkdev"),
    (S_IFIFO, "fifo"),
    (S_IFSOCK, "socket"),
)


class ErofsError(Exception):
    """EROFS 结构非法或不可读。"""


class ErofsTruncated(ErofsError):
    """输入在需要的偏移处提前结束（镜像被截断）。"""


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def _uuid_str(raw):
    h = raw.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


# ---------------------------------------------------------------- LZ4

def lz4_decode_block(src, max_out=None):
    """解一个 LZ4 block（不是 frame，无 magic/帧头）。

    EROFS 的物理簇就是裸 LZ4 block。序列格式：
        token: 高 4 位=字面量长度，低 4 位=匹配长度-4
        长度 15 时紧跟 255 累加的扩展字节
        [字面量][offset le16][扩展]
    最后一个序列只有字面量，没有 offset。

    max_out 给定时输出到达该长度即停（EROFS 需要按逻辑簇截断）。
    遇到 offset==0 或 offset>已输出长度时视为 0padding 尾部零填充，停止并
    返回已解出的数据（EROFS 常见：编码流补零到块尾）。
    """
    n = len(src)
    out = bytearray()
    i = 0
    while i < n:
        token = src[i]
        i += 1
        litlen = token >> 4
        if litlen == 15:
            while True:
                if i >= n:
                    return bytes(out)
                b = src[i]
                i += 1
                litlen += b
                if b != 255:
                    break
        if litlen:
            if i + litlen > n:            # 输入结束在字面量中：截断，返回已有内容
                out += src[i:]
                return bytes(out)
            out += src[i:i + litlen]
            i += litlen
        if max_out is not None and len(out) >= max_out:
            break
        if i + 2 > n:                     # 没有 offset：正常结束
            break
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0 or offset > len(out):
            # 零填充或损坏；0padding 镜像在此之后全是补齐字节
            break
        matchlen = token & 0x0F
        if matchlen == 15:
            while True:
                if i >= n:
                    return bytes(out)
                b = src[i]
                i += 1
                matchlen += b
                if b != 255:
                    break
        matchlen += 4
        if max_out is not None:
            matchlen = min(matchlen, max_out - len(out))
        start = len(out) - offset
        if offset >= matchlen:
            out += out[start:start + matchlen]
        else:
            chunk = bytes(out[start:])
            while len(chunk) < matchlen:
                chunk += chunk
            out += chunk[:matchlen]
        if max_out is not None and len(out) >= max_out:
            break
    return bytes(out)


# ---------------------------------------------------------------- 记录对象

class ErofsDirEntry(object):
    """目录项（erofs_dirent）。"""

    __slots__ = ("nid", "name", "file_type")

    def __init__(self, nid, name, file_type):
        self.nid = nid
        self.name = name
        self.file_type = file_type

    @property
    def type_name(self):
        return FILE_TYPE_NAMES.get(self.file_type, "ft%d" % self.file_type)

    @property
    def is_dir(self):
        return self.file_type == FT_DIR

    @property
    def is_file(self):
        return self.file_type == FT_REG_FILE

    def __repr__(self):
        return "<ErofsDirEntry %r nid=%d %s>" % (self.name, self.nid, self.type_name)


class ErofsInode(object):
    """已解析的 on-disk inode。"""

    __slots__ = (
        "nid", "off", "extended", "format", "layout", "layout_name",
        "xattr_icount", "xattr_isize", "inode_isize", "mode", "size",
        "nlink", "mtime", "mtime_nsec", "uid", "gid", "ino", "raw_blkaddr",
        "rdev", "data_off", "name",
    )

    def __init__(self, **kw):
        for key, value in kw.items():
            setattr(self, key, value)

    @property
    def type_name(self):
        mt = self.mode & S_IFMT
        for bit, name in MODE_TYPE_NAMES:
            if mt == bit:
                return name
        return "mode%o" % mt

    @property
    def is_dir(self):
        return (self.mode & S_IFMT) == S_IFDIR

    @property
    def is_file(self):
        return (self.mode & S_IFMT) == S_IFREG

    @property
    def is_symlink(self):
        return (self.mode & S_IFMT) == S_IFLNK

    @property
    def is_compressed(self):
        return self.layout in COMPRESSED_LAYOUTS

    @property
    def disk_blocks(self):
        """压缩 inode 的 i_u 存的是物理块数；平坦 inode 无此信息。"""
        return self.raw_blkaddr if self.layout in COMPRESSED_LAYOUTS else None

    def __repr__(self):
        return "<ErofsInode nid=%d %s %s size=%d>" % (
            self.nid, self.type_name, self.layout_name, self.size)


# ---------------------------------------------------------------- 主体

class Erofs(object):
    """EROFS 只读视图。sub 需提供 read(offset, size) 与 size。"""

    def __init__(self, sub):
        self.sub = sub
        self._inode_cache = {}
        self._dir_cache = {}
        self._load_super()

    # ------------------------------------------------------------ 超级块

    def _load_super(self):
        raw = self.sub.read(EROFS_SUPER_OFFSET, EROFS_SB_BASE)
        if len(raw) < EROFS_SB_BASE:
            raise ErofsTruncated(
                "超级块被截断：偏移 %d 处只有 %d 字节，需要 %d（镜像大小 %s）"
                % (EROFS_SUPER_OFFSET, len(raw), EROFS_SB_BASE,
                   getattr(self.sub, "size", "?")))
        magic, checksum, feat_compat = struct.unpack_from("<III", raw, 0)
        if magic != EROFS_SUPER_MAGIC:
            raise ErofsError("不是 EROFS：magic=0x%08X，期望 0x%08X"
                             % (magic, EROFS_SUPER_MAGIC))
        self.magic = magic
        self.checksum = checksum
        self.feature_compat = feat_compat
        self.blkszbits = raw[0x0C]
        self.sb_extslots = raw[0x0D]
        self.root_nid_2b = struct.unpack_from("<H", raw, 0x0E)[0]
        self.inos = struct.unpack_from("<Q", raw, 0x10)[0]
        self.epoch = struct.unpack_from("<Q", raw, 0x18)[0]
        self.fixed_nsec = struct.unpack_from("<I", raw, 0x20)[0]
        self.blocks_lo = struct.unpack_from("<I", raw, 0x24)[0]
        self.meta_blkaddr = struct.unpack_from("<I", raw, 0x28)[0]
        self.xattr_blkaddr = struct.unpack_from("<I", raw, 0x2C)[0]
        self.uuid_raw = bytes(raw[0x30:0x40])
        self.volume_name_raw = bytes(raw[0x40:0x50])
        self.feature_incompat = struct.unpack_from("<I", raw, 0x50)[0]
        self.u1 = struct.unpack_from("<H", raw, 0x54)[0]
        self.extra_devices = struct.unpack_from("<H", raw, 0x56)[0]
        self.devt_slotoff = struct.unpack_from("<H", raw, 0x58)[0]
        self.dirblkbits = raw[0x5A]
        self.build_time = struct.unpack_from("<I", raw, 0x6C)[0]

        if not 9 <= self.blkszbits <= 20:
            raise ErofsError("blkszbits=%d 非法（应在 9..20）" % self.blkszbits)
        self.blocksize = 1 << self.blkszbits

        # 0x70 起在 128 字节基础块之外，按可用长度可选解析
        tail = self.sub.read(EROFS_SUPER_OFFSET + 0x70, 16)
        self.root_nid_8b = struct.unpack_from("<Q", tail, 0)[0] if len(tail) >= 8 else 0
        self.metabox_nid = struct.unpack_from("<Q", tail, 8)[0] if len(tail) >= 16 else 0

        if self.feature_incompat & EROFS_FEATURE_INCOMPAT_48BIT:
            self.blocks = self.blocks_lo | (self.root_nid_2b << 32)
            self.root_nid = self.root_nid_8b or self.root_nid_2b
        else:
            self.blocks = self.blocks_lo
            self.root_nid = self.root_nid_2b

        self.meta_off = self.meta_blkaddr * self.blocksize
        self.xattr_off = self.xattr_blkaddr * self.blocksize
        self.dir_blkbits = self.dirblkbits or self.blkszbits
        if self.dir_blkbits < self.blkszbits or self.dir_blkbits > 20:
            self.dir_blkbits = self.blkszbits
        self.dir_block_size = 1 << self.dir_blkbits
        self.sb_size = EROFS_SB_BASE + self.sb_extslots * EROFS_SB_EXTSLOT

    def _compat_names(self):
        return [n for bit, n in COMPAT_FEATURE_NAMES if self.feature_compat & bit]

    def _incompat_names(self):
        return [n for bit, n in INCOMPAT_FEATURE_NAMES if self.feature_incompat & bit]

    @property
    def volume_name(self):
        return self.volume_name_raw.rstrip(b"\x00").decode("utf-8", "replace")

    @property
    def uuid(self):
        return _uuid_str(self.uuid_raw)

    def info(self):
        return {
            "magic": "0x%08X" % self.magic,
            "checksum": "0x%08X" % self.checksum,
            "blkszbits": self.blkszbits,
            "blocksize": self.blocksize,
            "dir_blkbits": self.dir_blkbits,
            "blocks": self.blocks,
            "inos": self.inos,
            "root_nid": self.root_nid,
            "meta_blkaddr": self.meta_blkaddr,
            "meta_offset": self.meta_off,
            "xattr_blkaddr": self.xattr_blkaddr,
            "uuid": self.uuid,
            "volume_name": self.volume_name,
            "epoch": self.epoch,
            "build_time": self.build_time,
            "build_time_abs": (self.epoch + self.build_time) if self.build_time else None,
            "fixed_nsec": self.fixed_nsec,
            "sb_size": self.sb_size,
            "sb_extslots": self.sb_extslots,
            "feature_compat": "0x%08X" % self.feature_compat,
            "feature_incompat": "0x%08X" % self.feature_incompat,
            "compat_features": self._compat_names(),
            "incompat_features": self._incompat_names(),
            "extra_devices": self.extra_devices,
            "lz4_max_distance": self.u1,
            "image_size": getattr(self.sub, "size", None),
        }

    # ------------------------------------------------------------ 读取助手

    def _read_exact(self, offset, size):
        data = self.sub.read(offset, size)
        if len(data) != size:
            raise ErofsTruncated(
                "读取越界：偏移 %d 需要 %d 字节，只得到 %d（镜像 %s）"
                % (offset, size, len(data), getattr(self.sub, "size", "?")))
        return data

    def nid_to_offset(self, nid):
        return self.meta_off + ((int(nid) & 0xFFFFFFFF) << EROFS_ISLOTBITS)

    # ------------------------------------------------------------ inode

    def inode(self, nid):
        nid = int(nid) & 0xFFFFFFFF
        cached = self._inode_cache.get(nid)
        if cached is not None:
            return cached
        off = self.nid_to_offset(nid)
        head = self.sub.read(off, EROFS_ISLOTSIZE)
        if len(head) < EROFS_ISLOTSIZE:
            raise ErofsTruncated(
                "inode nid=%d 越界：偏移 %d 只剩 %d 字节" % (nid, off, len(head)))
        i_format = struct.unpack_from("<H", head, 0)[0]
        extended = bool(i_format & 0x01)
        layout = (i_format >> 1) & 0x07
        if layout not in LAYOUT_NAMES:
            raise ErofsError("nid=%d 数据布局 %d 为保留值" % (nid, layout))

        if extended:
            raw = self._read_exact(off, 64)
            xattr_icount = struct.unpack_from("<H", raw, 2)[0]
            mode = struct.unpack_from("<H", raw, 4)[0]
            size = struct.unpack_from("<Q", raw, 8)[0]
            u = struct.unpack_from("<I", raw, 16)[0]
            ino = struct.unpack_from("<I", raw, 20)[0]
            uid = struct.unpack_from("<I", raw, 24)[0]
            gid = struct.unpack_from("<I", raw, 28)[0]
            mtime = struct.unpack_from("<Q", raw, 32)[0]
            mtime_nsec = struct.unpack_from("<I", raw, 40)[0]
            nlink = struct.unpack_from("<I", raw, 44)[0]
            inode_isize = 64
        else:
            fmt, xattr_icount, mode, nlink, size, mtime, u, ino, uid, gid = \
                struct.unpack_from("<HHHHIIIIHH", head, 0)
            mtime_nsec = 0
            inode_isize = 32

        if xattr_icount:
            xattr_isize = 12 + 4 * (xattr_icount - 1)
            if xattr_isize > self.blocksize:
                raise ErofsError("nid=%d inline xattr 长度 %d 超出块大小"
                                 % (nid, xattr_isize))
        else:
            xattr_isize = 0

        ino_obj = ErofsInode(
            nid=nid, off=off, extended=extended, format=i_format,
            layout=layout, layout_name=LAYOUT_NAMES[layout],
            xattr_icount=xattr_icount, xattr_isize=xattr_isize,
            inode_isize=inode_isize, mode=mode, size=size, nlink=nlink,
            mtime=mtime, mtime_nsec=mtime_nsec, uid=uid, gid=gid, ino=ino,
            raw_blkaddr=u, rdev=u,
            data_off=off + inode_isize + xattr_isize, name=None,
        )
        if ino_obj.size > getattr(self.sub, "size", 0) * 4 + 0x100000 and ino_obj.is_file:
            # 明显不合理的 i_size（防止在损坏镜像上做巨额分配）
            raise ErofsError("nid=%d i_size=%d 与镜像大小不符，疑似损坏"
                             % (nid, ino_obj.size))
        self._inode_cache[nid] = ino_obj
        return ino_obj

    # ------------------------------------------------------------ 目录

    def _parse_dir(self, ino):
        cached = self._dir_cache.get(ino.nid)
        if cached is not None:
            return cached
        entries = []
        total = ino.size
        base = ino.raw_blkaddr * self.blocksize
        dbs = self.dir_block_size
        pos = 0
        while pos < total:
            want = min(dbs, total - pos)
            if want < EROFS_DIRENT_SIZE:
                break
            blk = self._read_exact(base + pos, want)
            first_nameoff = struct.unpack_from("<H", blk, 8)[0]
            count = first_nameoff // EROFS_DIRENT_SIZE
            if count == 0:
                break
            if count > len(blk) // EROFS_DIRENT_SIZE:
                raise ErofsError(
                    "目录 nid=%d 块内 dirent 数 %d 超出块容量" % (ino.nid, count))
            items = []
            for index in range(count):
                nid, nameoff, file_type = struct.unpack_from(
                    "<QHB", blk, index * EROFS_DIRENT_SIZE)
                items.append((nid, nameoff, file_type))
            for index, (nid, nameoff, file_type) in enumerate(items):
                if nameoff < first_nameoff or nameoff > len(blk):
                    raise ErofsError(
                        "目录 nid=%d 第 %d 个 dirent 的 nameoff=%d 非法"
                        % (ino.nid, index, nameoff))
                if index + 1 < count:
                    end = items[index + 1][1]
                    if end < nameoff:
                        raise ErofsError(
                            "目录 nid=%d 第 %d 个 nameoff 递减" % (ino.nid, index))
                else:
                    end = len(blk)
                raw_name = blk[nameoff:end]
                if index + 1 == count:
                    # 每块最后一个条目：名字到块尾，去 NUL 填充（strnlen 语义）
                    raw_name = raw_name.rstrip(b"\x00")
                if not raw_name or len(raw_name) > EROFS_NAME_LEN:
                    raise ErofsError(
                        "目录 nid=%d 第 %d 个条目名字长度 %d 非法"
                        % (ino.nid, index, len(raw_name)))
                entries.append(ErofsDirEntry(
                    nid=nid & EROFS_DIRENT_NID_MASK,
                    name=raw_name.decode("utf-8", "surrogateescape"),
                    file_type=file_type,
                ))
            pos += want
        self._dir_cache[ino.nid] = entries
        return entries

    def listdir(self, nid=None, names_only=False):
        ino = self._as_inode(nid if nid is not None else self.root_nid)
        if not ino.is_dir:
            raise ErofsError("nid=%d 不是目录（%s）" % (ino.nid, ino.type_name))
        entries = self._parse_dir(ino)
        return [e.name for e in entries] if names_only else list(entries)

    def _as_inode(self, obj):
        if isinstance(obj, ErofsInode):
            return obj
        if isinstance(obj, ErofsDirEntry):
            return self.inode(obj.nid)
        if isinstance(obj, int):
            return self.inode(obj)
        if isinstance(obj, str):
            return self.lookup_path(obj)
        raise TypeError("需要 nid / ErofsInode / ErofsDirEntry / 路径，得到 %r" % (obj,))

    # ------------------------------------------------------------ 文件数据

    def _read_blocks(self, ino):
        if ino.size == 0:
            return b""
        return self._read_exact(ino.raw_blkaddr * self.blocksize, ino.size)

    def _read_inline(self, ino):
        """FLAT_INLINE：尾部（i_size % blocksize）内联在 inode 之后，其余在块区。"""
        size = ino.size
        if size == 0:
            return b""
        inline_off = ino.data_off
        room = self.blocksize - (inline_off % self.blocksize)
        if size <= self.blocksize:
            tail = size
        else:
            tail = size % self.blocksize
            if tail == 0:
                tail = 0
            elif tail > room:
                # mkfs 可能把尾部缩小到块尾剩余空间
                tail = room
        head_len = size - tail
        out = bytearray()
        if head_len:
            out += self._read_exact(ino.raw_blkaddr * self.blocksize, head_len)
        if tail:
            out += self._read_exact(inline_off, tail)
        return bytes(out)

    def _read_compressed(self, ino):
        base = ino.data_off
        hdr_off = _align(base, 8)
        raw = self._read_exact(hdr_off, 8)
        _fragmentoff = struct.unpack_from("<I", raw, 0)[0]
        advise = struct.unpack_from("<H", raw, 4)[0]
        algtypes = raw[6]
        clusterbits = raw[7]

        if clusterbits & 0x80:
            raise NotImplementedError(
                "nid=%d：fragment（整文件打包进 packed inode）未实现" % ino.nid)
        lclusterbits = self.blkszbits + (clusterbits & 0x07)
        lclustersize = 1 << lclusterbits
        alg0 = algtypes & 0x0F
        alg1 = (algtypes >> 4) & 0x0F
        if alg0 not in (Z_COMPRESSION_LZ4,) or alg1 not in (0, Z_COMPRESSION_LZ4):
            raise NotImplementedError(
                "nid=%d：压缩算法 %s/%s 未实现（只做 LZ4）" % (
                    ino.nid,
                    Z_COMPRESSION_NAMES.get(alg0, "alg%d" % alg0),
                    Z_COMPRESSION_NAMES.get(alg1, "alg%d" % alg1)))
        if advise & 0x0400:
            raise NotImplementedError("nid=%d：新式 extent 索引（z_erofs_extent）未实现"
                                      % ino.nid)

        if ino.layout == COMPRESSED_COMPACT:
            idx_off = hdr_off + 8
        else:
            idx_off = hdr_off + 16

        ncluster = (ino.size + lclustersize - 1) // lclustersize
        out = bytearray()
        lcn = 0
        while lcn < ncluster:
            rec = self._read_exact(idx_off + lcn * 8, 8)
            di_advise, clusterofs = struct.unpack_from("<HH", rec, 0)
            blkaddr = struct.unpack_from("<I", rec, 4)[0]
            ltype = di_advise & LCLUSTER_TYPE_MASK
            remaining = ino.size - len(out)

            if ltype == LCLUSTER_NONHEAD:
                # 由前一个 HEAD 的物理簇一并产出
                lcn += 1
                continue
            if ltype == LCLUSTER_HEAD2:
                raise NotImplementedError(
                    "nid=%d 逻辑簇 %d：HEAD2（多算法 1 MiB 边界）未实现"
                    % (ino.nid, lcn))
            if ltype == LCLUSTER_PLAIN:
                want = min(lclustersize, remaining)
                out += self._read_exact(blkaddr * self.blocksize, want)
                lcn += 1
                continue
            if clusterofs != 0:
                raise NotImplementedError(
                    "nid=%d 逻辑簇 %d：partial lcluster（clusterofs=%d）未实现"
                    % (ino.nid, lcn, clusterofs))

            span = 1
            while lcn + span < ncluster:
                nxt = self._read_exact(idx_off + (lcn + span) * 8, 8)
                if (struct.unpack_from("<H", nxt, 0)[0] & LCLUSTER_TYPE_MASK) != LCLUSTER_NONHEAD:
                    break
                span += 1
            want = min(lclustersize * span, remaining)
            src = self.sub.read(blkaddr * self.blocksize, self.blocksize * span)
            if not src:
                raise ErofsTruncated(
                    "nid=%d 逻辑簇 %d：物理块 %d 越界" % (ino.nid, lcn, blkaddr))
            data = lz4_decode_block(src, lclustersize * span)
            if len(data) < want:
                if lcn + span < ncluster:
                    raise ErofsError(
                        "nid=%d 逻辑簇 %d：LZ4 只解出 %d 字节，需要 %d"
                        % (ino.nid, lcn, len(data), want))
                out += data
                out += b"\x00" * (want - len(data))   # 末尾簇补齐
            else:
                out += data[:want]
            lcn += span
        return bytes(out)

    def read_file(self, nid_or_entry):
        ino = self._as_inode(nid_or_entry)
        if ino.is_dir:
            raise ErofsError("nid=%d 是目录，请用 listdir()" % ino.nid)
        if ino.layout == FLAT_PLAIN:
            return self._read_blocks(ino)
        if ino.layout == FLAT_INLINE:
            return self._read_inline(ino)
        if ino.layout in COMPRESSED_LAYOUTS:
            return self._read_compressed(ino)
        if ino.layout == CHUNK_BASED:
            raise NotImplementedError(
                "nid=%d：CHUNK_BASED（chunk 索引 / 多设备）未实现" % ino.nid)
        raise ErofsError("nid=%d 未知布局 %d" % (ino.nid, ino.layout))

    def read_symlink(self, nid_or_entry):
        ino = self._as_inode(nid_or_entry)
        return self.read_file(ino).decode("utf-8", "surrogateescape")

    # ------------------------------------------------------------ 路径

    def lookup_path(self, path):
        """按路径查 inode。忽略 ""/"."/".."（无父指针，不做上溯）。"""
        ino = self.inode(self.root_nid)
        text = str(path).replace("\\", "/")
        for part in text.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                continue
            if not ino.is_dir:
                raise ErofsError("%r 的 %r 不是目录" % (path, part))
            found = None
            for entry in self._parse_dir(ino):
                if entry.name == part:
                    found = entry
                    break
            if found is None:
                raise ErofsError("找不到路径：%r（缺少 %r）" % (path, part))
            ino = self.inode(found.nid)
            ino.name = found.name
        return ino

    def walk(self, nid=None, root="/"):
        """深度优先产出 (路径, inode)。"""
        start = self._as_inode(nid if nid is not None else self.root_nid)
        seen = set()
        stack = [(root, start)]
        while stack:
            path, ino = stack.pop()
            yield path, ino
            if not ino.is_dir or ino.nid in seen:
                continue
            seen.add(ino.nid)
            children = self._parse_dir(ino)
            for entry in reversed(children):
                child_path = ("/" + entry.name) if path == "/" else (path + "/" + entry.name)
                child = self.inode(entry.nid)
                child.name = entry.name
                stack.append((child_path, child))

    def find(self, pattern):
        """按 fnmatch 通配匹配路径，返回 [(路径, inode)]。"""
        return [(path, ino) for path, ino in self.walk()
                if fnmatch.fnmatch(path, pattern)]

    def tree(self, nid=None):
        """[(路径, 类型名, 大小)]，便于终端展示。"""
        out = []
        for path, ino in self.walk(nid):
            out.append((path, ino.type_name, ino.size))
        return out


# ---------------------------------------------------------------- 模块级接口

def probe(sub):
    """magic + blkszbits 合法性检查。"""
    try:
        raw = sub.read(EROFS_SUPER_OFFSET, EROFS_SB_BASE)
    except Exception:
        return False
    if len(raw) < 16:
        return False
    magic, = struct.unpack_from("<I", raw, 0)
    if magic != EROFS_SUPER_MAGIC:
        return False
    if len(raw) >= 0x0D:
        bits = raw[0x0C]
        if not 9 <= bits <= 20:
            return False
    return True


def open_fs(sub):
    return Erofs(sub)


# ---------------------------------------------------------------- 自检

def _selftest():
    BS = 4096
    BITS = 12
    UUID = bytes(range(0x10, 0x20))
    ROOT_NID = 36
    HELLO_NID = 40
    CNFILE_NID = 44
    SUB_NID = 48
    BIG_NID = 52
    COMP_NID = 56
    THING_NID = 60
    SFULL_NID = 64
    CHUNK_NID = 72
    LZMA_NID = 76
    SPLIT_NID = 80

    BLK_ROOT = 2
    BLK_HELLO = 3
    BLK_SUB = 4
    BLK_BIG0 = 5
    BLK_BIG1 = 6
    BLK_COMP = 7
    BLK_SPLIT = 8
    TOTAL_BLOCKS = 9

    class Mem(object):
        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, size):
            if size <= 0 or off < 0 or off >= self.size:
                return b""
            return self.data[off:off + size]

    def cmp_inode(mode, size, blkaddr, layout=FLAT_PLAIN, nlink=1, ino=1):
        fmt = layout << 1
        body = struct.pack("<HHHHIIIIHH", fmt, 0, mode, nlink & 0xFFFF,
                           size & 0xFFFFFFFF, 0x5F5E1000, blkaddr, ino, 0, 0)
        return body + b"\x00" * 4

    def ext_inode(mode, size, blkaddr, layout=FLAT_INLINE, nlink=1, ino=2):
        raw = struct.pack("<HHHH", (layout << 1) | 1, 0, mode, nlink & 0xFFFF)
        raw += struct.pack("<Q", size)
        raw += struct.pack("<I", blkaddr)
        raw += struct.pack("<II", ino, 1000)
        raw += struct.pack("<I", 1000)
        raw += struct.pack("<Q", 0x65000000)
        raw += struct.pack("<II", 123456789, nlink)
        raw += b"\x00" * 16
        assert len(raw) == 64, len(raw)
        return raw

    def pack_dir(items):
        """items=[(name_bytes, nid, ftype)] → 每块独立打包的目录数据列表。"""
        blocks = []
        cursor = 0
        while cursor < len(items):
            chosen = []
            used_names = 0
            while cursor < len(items):
                name = items[cursor][0]
                need = EROFS_DIRENT_SIZE * (len(chosen) + 1) + used_names + len(name)
                if need > BS and chosen:
                    break
                if need > BS:
                    raise AssertionError("单个名字放不进块：%r" % (name,))
                chosen.append(items[cursor])
                used_names += len(name)
                cursor += 1
            nameoff = EROFS_DIRENT_SIZE * len(chosen)
            head = bytearray()
            names = bytearray()
            for name, nid, ftype in chosen:
                head += struct.pack("<QHBB", nid, nameoff + len(names), ftype, 0)
                names += name
            block = bytes(head) + bytes(names)
            blocks.append(block + b"\x00" * (BS - len(block)))
        return blocks

    # ---- 内容
    hello_data = b"hello erofs!\n"
    cn_data = "内联数据：中文内容 ✓".encode("utf-8")
    thing_data = b"thing"
    comp_data = bytes((i * 7) & 0xFF for i in range(3000))
    split_data = bytes(((i * 13) + 5) & 0xFF for i in range(5000))

    def lz4_literals(data):
        """只发字面量的合法 LZ4 block（末尾无 offset）。"""
        out = bytearray()
        n = len(data)
        if n < 15:
            out.append(n << 4)
        else:
            out.append(0xF0)
            extra = n - 15
            while extra >= 255:
                out.append(255)
                extra -= 255
            out.append(extra)
        out += data
        return bytes(out)

    comp_encoded = lz4_literals(comp_data)
    assert len(comp_encoded) <= BS, len(comp_encoded)

    # ---- 目录布局
    root_items = [
        (b"big", BIG_NID, FT_DIR),
        (b"c.bin", COMP_NID, FT_REG_FILE),
        (b"chunk.bin", CHUNK_NID, FT_REG_FILE),
        (b"full.bin", SFULL_NID, FT_REG_FILE),
        (b"hello.txt", HELLO_NID, FT_REG_FILE),
        (b"lzma.bin", LZMA_NID, FT_REG_FILE),
        (b"split.bin", SPLIT_NID, FT_REG_FILE),
        (b"sub", SUB_NID, FT_DIR),
        ("中文名.txt".encode("utf-8"), CNFILE_NID, FT_REG_FILE),
    ]
    root_blocks = pack_dir(root_items)
    assert len(root_blocks) == 1

    sub_items = [(b"thing", THING_NID, FT_REG_FILE)]
    sub_blocks = pack_dir(sub_items)

    big_items = [(("entry_%03d_padpadpad" % i).encode(), THING_NID, FT_REG_FILE)
                 for i in range(150)]
    big_items.append(("跨块中文名称.txt".encode("utf-8"), THING_NID, FT_REG_FILE))
    big_blocks = pack_dir(big_items)
    assert len(big_blocks) == 2, len(big_blocks)          # 必须跨 dirent 块

    # ---- 组装镜像
    img = bytearray(BS * TOTAL_BLOCKS)

    def put(off, data):
        img[off:off + len(data)] = data

    sb = bytearray(144)
    struct.pack_into("<I", sb, 0x00, EROFS_SUPER_MAGIC)
    struct.pack_into("<I", sb, 0x04, 0xDEADBEEF)          # checksum
    struct.pack_into("<I", sb, 0x08, 0)                   # feature_compat
    sb[0x0C] = BITS
    sb[0x0D] = 1                                          # sb_extslots
    struct.pack_into("<H", sb, 0x0E, ROOT_NID)
    struct.pack_into("<Q", sb, 0x10, 7)                    # inos
    struct.pack_into("<Q", sb, 0x18, 0x60000000)           # epoch
    struct.pack_into("<I", sb, 0x20, 0)                    # fixed_nsec
    struct.pack_into("<I", sb, 0x24, TOTAL_BLOCKS)         # blocks_lo
    struct.pack_into("<I", sb, 0x28, 1)                    # meta_blkaddr
    struct.pack_into("<I", sb, 0x2C, 0)                    # xattr_blkaddr
    sb[0x30:0x40] = UUID
    sb[0x40:0x50] = b"ESK_EROFS_TEST".ljust(16, b"\x00")
    struct.pack_into("<I", sb, 0x50, 0)                    # feature_incompat
    struct.pack_into("<I", sb, 0x6C, 0)                    # build_time
    put(EROFS_SUPER_OFFSET, bytes(sb))

    meta = 1 * BS
    put(meta + ROOT_NID * 32,
        cmp_inode(S_IFDIR | 0o755, BS * len(root_blocks), BLK_ROOT, layout=FLAT_PLAIN, nlink=2))
    put(meta + HELLO_NID * 32,
        cmp_inode(S_IFREG | 0o644, len(hello_data), BLK_HELLO, layout=FLAT_PLAIN))
    put(meta + SUB_NID * 32,
        cmp_inode(S_IFDIR | 0o755, BS * len(sub_blocks), BLK_SUB, layout=FLAT_PLAIN, nlink=2))
    put(meta + BIG_NID * 32,
        cmp_inode(S_IFDIR | 0o755, BS * len(big_blocks), BLK_BIG0, layout=FLAT_PLAIN, nlink=2))
    put(meta + THING_NID * 32,
        cmp_inode(S_IFREG | 0o644, len(thing_data), 0, layout=FLAT_INLINE))
    put(meta + THING_NID * 32 + 32, thing_data)   # 内联数据紧跟 32B compact inode

    # 中文名.txt：extended inode + FLAT_INLINE，内容紧跟 inode
    cn_off = meta + CNFILE_NID * 32
    put(cn_off, ext_inode(S_IFREG | 0o644, len(cn_data), 0, layout=FLAT_INLINE, nlink=1))
    put(cn_off + 64, cn_data)

    # c.bin：extended + COMPRESSED_COMPACT（map header 8B + 一条 lcluster 索引）
    comp_off = meta + COMP_NID * 32
    put(comp_off, ext_inode(S_IFREG | 0o644, len(comp_data), 1,
                            layout=COMPRESSED_COMPACT, nlink=1, ino=3))
    hdr_off = _align(comp_off + 64, 8)
    hdr = bytearray(8)
    struct.pack_into("<I", hdr, 0, 0)      # h_fragmentoff / h_idata_size
    struct.pack_into("<H", hdr, 4, 0)      # h_advise
    hdr[6] = Z_COMPRESSION_LZ4             # h_algorithmtype
    hdr[7] = 0                             # h_clusterbits（= blkszbits）
    put(hdr_off, bytes(hdr))
    lcluster = struct.pack("<HHI", LCLUSTER_HEAD, 0, BLK_COMP)
    put(hdr_off + 8, lcluster)

    # full.bin：extended + COMPRESSED_FULL（索引在 map header 之后再隔 8 B）
    full_off = meta + SFULL_NID * 32
    put(full_off, ext_inode(S_IFREG | 0o644, len(comp_data), 1,
                            layout=COMPRESSED_FULL, nlink=1, ino=4))
    full_hdr = _align(full_off + 64, 8)
    put(full_hdr, bytes(hdr))
    put(full_hdr + 16, struct.pack("<HHI", LCLUSTER_HEAD, 0, BLK_COMP))

    # chunk.bin：CHUNK_BASED，只验证被明确拒绝
    put(meta + CHUNK_NID * 32,
        ext_inode(S_IFREG | 0o644, 4096, 0, layout=CHUNK_BASED, nlink=1, ino=5))

    # lzma.bin：COMPRESSED_COMPACT 但算法为 LZMA，只验证被明确拒绝
    lzr_off = meta + LZMA_NID * 32
    put(lzr_off, ext_inode(S_IFREG | 0o644, len(comp_data), 1,
                           layout=COMPRESSED_COMPACT, nlink=1, ino=6))
    lzr_hdr = _align(lzr_off + 64, 8)
    hdr_lzma = bytearray(hdr)
    hdr_lzma[6] = Z_COMPRESSION_LZMA
    put(lzr_hdr, bytes(hdr_lzma))
    put(lzr_hdr + 8, struct.pack("<HHI", LCLUSTER_HEAD, 0, BLK_COMP))

    # split.bin：FLAT_INLINE 且 i_size > blocksize（4096 B 在块区 + 904 B 内联）
    split_off = meta + SPLIT_NID * 32
    put(split_off, ext_inode(S_IFREG | 0o644, len(split_data), BLK_SPLIT,
                             layout=FLAT_INLINE, nlink=1, ino=7))
    put(split_off + 64, split_data[BS:])

    for index, blk in enumerate(root_blocks):
        put(BLK_ROOT * BS + index * BS, blk)
    put(BLK_HELLO * BS, hello_data)
    for index, blk in enumerate(sub_blocks):
        put(BLK_SUB * BS + index * BS, blk)
    for index, blk in enumerate(big_blocks):
        put((BLK_BIG0 + index) * BS, blk)
    put(BLK_COMP * BS, comp_encoded)
    put(BLK_SPLIT * BS, split_data[:BS])

    image = bytes(img)
    checks = []

    def ok(cond, label):
        if not cond:
            raise AssertionError("自检失败：" + label)
        checks.append(label)

    # 1. probe
    sub = Mem(image)
    ok(probe(sub) is True, "probe 命中 EROFS")
    ok(probe(Mem(b"\x00" * 8192)) is False, "probe 拒绝全零输入")
    ok(probe(Mem(b"hsqs" + b"\x00" * 8188)) is False, "probe 拒绝 squashfs 魔数")
    ok(probe(Mem(image[:600])) is False, "probe 拒绝过短输入")

    # 2. 超级块字段
    fs = open_fs(sub)
    inf = fs.info()
    ok(inf["blkszbits"] == BITS, "blkszbits=%d" % inf["blkszbits"])
    ok(inf["blocksize"] == BS, "blocksize=%d" % inf["blocksize"])
    ok(inf["blocks"] == TOTAL_BLOCKS, "blocks=%d" % inf["blocks"])
    ok(inf["root_nid"] == ROOT_NID, "root_nid=%d" % inf["root_nid"])
    ok(inf["volume_name"] == "ESK_EROFS_TEST", "volume_name=%r" % inf["volume_name"])
    ok(inf["uuid"] == _uuid_str(UUID), "uuid=%s" % inf["uuid"])
    ok(inf["meta_blkaddr"] == 1 and inf["meta_offset"] == BS, "meta_blkaddr/meta_offset")
    ok(inf["sb_size"] == 144, "sb_size=%d" % inf["sb_size"])
    ok(inf["checksum"] == "0xDEADBEEF", "checksum 保留原值")

    # 3. compact / extended inode
    hello_ino = fs.inode(HELLO_NID)
    ok(hello_ino.extended is False, "hello.txt 走 compact 32B")
    ok(hello_ino.size == len(hello_data), "hello.txt size=%d" % hello_ino.size)
    ok(hello_ino.layout == FLAT_PLAIN, "hello.txt 布局 flat_plain")
    cn_ino = fs.inode(CNFILE_NID)
    ok(cn_ino.extended is True, "中文名.txt 走 extended 64B")
    ok(cn_ino.uid == 1000 and cn_ino.gid == 1000, "extended uid/gid")
    ok(cn_ino.mtime == 0x65000000 and cn_ino.mtime_nsec == 123456789, "extended mtime/nsec")
    ok(cn_ino.is_file, "extended inode 类型为 file")

    # 4. listdir / read_file / lookup_path
    names = fs.listdir(names_only=True)
    expect = [it[0].decode("utf-8") for it in root_items]
    ok(names == expect, "listdir(根) = %r" % names)
    ok(fs.read_file(HELLO_NID) == hello_data, "read_file(flat_plain) 内容一致")
    ok(fs.read_file(fs.lookup_path("/hello.txt")) == hello_data, "lookup_path + read_file")
    ok(fs.read_file("/hello.txt") == hello_data, "read_file 接受路径")
    ok(fs.lookup_path("/sub/thing").nid == THING_NID, "lookup_path 两级")
    ok(fs.read_file("/sub/thing") == thing_data, "子目录文件内容")
    entry_sub = [e for e in fs.listdir() if e.name == "sub"][0]
    ok(entry_sub.is_dir and entry_sub.type_name == "dir", "dirent.file_type=dir")
    try:
        fs.read_file(ROOT_NID)
        raise AssertionError("自检失败：读目录应报错")
    except ErofsError:
        checks.append("read_file(目录) 抛 ErofsError")

    # 5. 中文名 + 跨 dirent 块
    ok("中文名.txt" in names, "根目录中文名")
    big_names = fs.listdir(BIG_NID, names_only=True)
    ok(len(big_names) == 151, "big 目录 151 项（实测 %d）" % len(big_names))
    ok("跨块中文名称.txt" in big_names, "第二个 dirent 块中的中文名")
    ok(fs.read_file("/big/跨块中文名称.txt") == thing_data, "跨块目录项可读")
    ok(len(big_blocks) == 2, "big 目录确实跨 2 个 dirent 块")

    # 6. FLAT_INLINE
    ok(fs.read_file(CNFILE_NID) == cn_data, "FLAT_INLINE 内容一致（extended）")
    ok(fs.read_file(THING_NID) == thing_data, "FLAT_INLINE 内容一致（compact）")

    # 7. LZ4 + 压缩布局
    ok(lz4_decode_block(b"\x62abcdef\x06\x00") == b"abcdefabcdef", "LZ4 offset 匹配解压")
    ok(lz4_decode_block(b"\x10A\x01\x00" + b"\x00" * 8) == b"AAAAA", "LZ4 重叠匹配 + 尾零填充")
    ok(fs.read_file(COMP_NID) == comp_data, "COMPRESSED_COMPACT(LZ4) 内容一致")
    ok(fs.inode(COMP_NID).layout == COMPRESSED_COMPACT, "压缩 inode 布局判定")
    ok(fs.read_file(SFULL_NID) == comp_data, "COMPRESSED_FULL(LZ4) 内容一致")
    ok(fs.inode(SFULL_NID).layout == COMPRESSED_FULL, "COMPRESSED_FULL 布局判定")
    ok(fs.read_file(SPLIT_NID) == split_data, "FLAT_INLINE 跨块 %d B 内容一致" % len(split_data))
    ok(fs.inode(SPLIT_NID).size == len(split_data), "split.bin i_size=%d"
       % fs.inode(SPLIT_NID).size)
    try:
        fs.read_file(CHUNK_NID)
        raise AssertionError("自检失败：CHUNK_BASED 应抛 NotImplementedError")
    except NotImplementedError:
        checks.append("CHUNK_BASED → NotImplementedError")
    try:
        fs.read_file(LZMA_NID)
        raise AssertionError("自检失败：非 LZ4 压缩应抛 NotImplementedError")
    except NotImplementedError:
        checks.append("LZMA 压缩 → NotImplementedError")

    # 8. 遍历 / 查找
    paths = [p for p, _ in fs.walk()]
    ok("/hello.txt" in paths and "/sub/thing" in paths, "walk 覆盖已知路径")
    ok(any(p == "/中文名.txt" for p in paths), "walk 含中文路径")
    found = fs.find("*.txt")
    ok(len(found) >= 3, "find('*.txt') 命中 %d 项" % len(found))

    # 9. 截断
    try:
        Erofs(Mem(image[:1100]))
        raise AssertionError("自检失败：截断镜像应抛异常")
    except ErofsTruncated as exc:
        checks.append("截断超级块 → ErofsTruncated（%s）" % str(exc).split("：")[0])
    try:
        Erofs(Mem(image[:BS + ROOT_NID * 32 + 8])).inode(ROOT_NID)
        raise AssertionError("自检失败：截断 inode 应抛异常")
    except ErofsTruncated:
        checks.append("截断 inode → ErofsTruncated")
    try:
        Erofs(Mem(image[:BLK_HELLO * BS + 4])).read_file(HELLO_NID)
        raise AssertionError("自检失败：截断文件数据应抛异常")
    except ErofsTruncated:
        checks.append("截断文件数据 → ErofsTruncated")

    print("EROFS 自检通过：%d 项" % len(checks))
    for index, label in enumerate(checks, 1):
        print("  %2d. %s" % (index, label))
    return True


if __name__ == "__main__":
    _selftest()
