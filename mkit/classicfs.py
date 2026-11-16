# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  Minix V1/V2/V3 · JFS · ReiserFS 3.5/3.6
# ============================================================
"""经典 Linux 文件系统只读解析：Minix FS（V1/V2/V3）、JFS、ReiserFS 3.5 / 3.6

格式依据 Linux 内核 v6.6 源码（本文件逐字段核对过下列头/源文件）：

    include/uapi/linux/minix_fs.h        minix_super_block / minix3_super_block
                                         / minix_inode / minix2_inode
    fs/minix/inode.c                     superblock 读取位置、版本判定、imap 起点
    fs/jfs/jfs_superblock.h              struct jfs_superblock（字段顺序）
    fs/jfs/jfs_dinode.h                  struct dinode（512 B）
    fs/jfs/jfs_dtree.h                   dtroot_t / dtpage_t / ldtentry / idtentry
    fs/jfs/jfs_imap.h                    struct iag、INOEXT 偏移、INOPBLK 宏
    fs/jfs/jfs_xtree.h                   xtpage_t / xad_t
    fs/jfs/jfs_btree.h                   BT_ROOT / BT_LEAF / BT_INTERNAL
    fs/jfs/jfs_imap.c                    diReadSpecial / diRead 的 inode 定位
    fs/reiserfs/reiserfs.h               block_head / item_head / key / de_head
                                         / stat_data(_v1) / disk_child

已实现：
    Minix
        · V1 / V2 / V3 超级块（含 V1 30 字符变体 0x138F、V2 30 字符变体 0x2478）
        · V3 超级块的扫描定位（1024 / 2048 / 4096 / 8192 …）与 s_blocksize
        · V1 / V2 / V3 inode、直接块 + 一次 / 二次 / 三次间接块寻址
        · 目录项（16 / 32 / 64 B 三种）、listdir / walk / lookup_path / find
    JFS
        · 超级块全字段（小端）、卷名 fpack / label、UUID、ait2 / aim2 / logpxd
        · inode 定位：聚合 inode（AIT 固定页）+ 文件集 inode（imap → iag → inoext）
        · dinode 512 B 全字段（含 di_ixpxd、di_xtroot / di_dtroot）
        · 文件读取：xtree（B+ 树）inode 内联根 + 内部页下钻
        · 目录遍历：dtree 内联根 + 内部页下钻，UTF-16LE 名字重组
    ReiserFS
        · 3.5 / 3.6 / 3.6+journal 超级块（0x10000 与老式 0x2000 两个位置）
        · block_head / item_head / key（3.5 与 3.6 两种 key 编码）/ disk_child
        · S+ 树整树遍历（内部页下钻 + 叶子 item 枚举）
        · 目录项 reiserfs_de_head 解析、stat data（v1 / v2）解析
        · 文件读取：direct item + 未压缩 indirect item
    · 统一入口 probe / open_fs / detect_all

不实现：
    · 任何写操作
    · Minix 位图分配核对（imap / zmap 只记录几何，不校验）
    · JFS 日志回放、DASD limits、EA / ACL、压缩文件（s_compress > 0 时读文件抛
      NotImplementedError）、JFS 目录项的 13 字符 legacy 布局（名字 > 11 字符时可能
      少取 2 个字符，见 _dt_name 注释）
    · JFS 非 4096 字节块上的 dtree 页（dtpage 定长 4096）与 512 B 块的 inode 页混排
    · ReiserFS 压缩尾块（unfm 指针带标志位时抛 NotImplementedError）、journal 回放、
      大文件的 key 有序查找（改为整树扫描，见 _scan_items）

与任务书写法不一致、已按源码修正的地方（docstring 留档）：
    · JFS 超级块是**小端**（struct 全用 __le32 / __le64），不是大端
    · JFS s_size 是 __le64（8 字节），所以 s_bsize 在 0x10、s_pbsize 在 0x18、
      s_agsize 在 0x20、s_flag 在 0x24、s_state 在 0x28、s_compress 在 0x2C、
      s_ait2 在 0x30、s_aim2 在 0x38、s_fpack 在 0x65
    · Minix V2 inode 是 64 字节（i_zone[10] 为 __u32），不是 32 字节；V3 同为 64 字节
    · Minix V1 i_zone[9] 为 __u16（间接块指针 2 字节），V2/V3 为 __u32（4 字节）
    · Minix 目录项：V1/V2 14 字符版 16 B，30 字符版 32 B；V3 60 字符 64 B
    · ReiserFS key 是 16 字节（dir_id 4 + objectid 4 + offset/uniqueness 8），
      item_head 是 24 字节（key 16 + u16 ×4），不是 24 + 8 = 32
    · ReiserFS block_head 是 24 字节（8 字节头 + 16 字节 right_delim_key）
    · ReiserFS 超级块 s_blocksize 在 0x2C、s_umount_state 在 0x32、s_magic 在 0x34、
      s_hash_function_code 在 0x40、s_tree_height 在 0x44、s_bmap_nr 在 0x46、
      s_version 在 0x48
    · ReiserFS 内部节点布局为 [block_head][nr_item 个 key][nr_item+1 个 disk_child]，
      由 reiserfs.h 的 B_N_CHILD 宏确认（不是 key/child 交替）
"""

import struct

__all__ = [
    "Minix", "MinixEntry", "MinixInode", "MINIX_MAGIC",
    "Jfs", "JfsEntry", "JfsInode", "JFS_MAGIC",
    "ReiserFs", "ReiserEntry", "ReiserFsInode", "REISER_MAGIC",
    "probe", "open_fs", "detect_all",
]

# ---------------------------------------------------------------- 通用小工具

MODE_TYPE = [
    (0x8000, "reg"), (0x4000, "dir"), (0xA000, "symlink"),
    (0x2000, "chr"), (0x6000, "blk"), (0x1000, "fifo"), (0xC000, "sock"),
]


def _mode_type(mode):
    t = mode & 0xF000
    for v, name in MODE_TYPE:
        if v == t:
            return name
    return "unknown"


def _u8(b, o):
    return b[o] if 0 <= o < len(b) else 0


def _s8(b, o):
    v = _u8(b, o)
    return v - 256 if v > 127 else v


def _le16(b, o):
    if o < 0 or o + 2 > len(b):
        return 0
    return struct.unpack_from("<H", b, o)[0]


def _le32(b, o):
    if o < 0 or o + 4 > len(b):
        return 0
    return struct.unpack_from("<I", b, o)[0]


def _le64(b, o):
    if o < 0 or o + 8 > len(b):
        return 0
    return struct.unpack_from("<Q", b, o)[0]


def _cstr(b):
    i = b.find(b"\x00")
    return b if i < 0 else b[:i]


def _dec(b):
    """UTF-8 优先，坏字节用替换符（保留原始字节在 entry.raw 里）"""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("utf-8", "replace")


def _as_ino(x):
    if isinstance(x, int):
        return x
    for attr in ("inode", "ino"):
        if hasattr(x, attr):
            return int(getattr(x, attr))
    raise TypeError("需要 inode 号或目录项，收到 %r" % (x,))


# ================================================================ Minix FS

MINIX_SUPER_POS = 1024
# V3 的超级块可能不在 1024（不同 mkfs 版本 / 块大小），依次尝试这些字节偏移
MINIX_SCAN = (1024, 2048, 4096, 8192, 16384, 32768, 65536)

# magic -> (版本, 名字长度, 目录项长度)
MINIX_MAGIC = {
    0x137F: ("v1", 14, 16),
    0x138F: ("v1", 30, 32),
    0x2468: ("v2", 14, 16),
    0x2478: ("v2", 30, 32),
    0x4D5A: ("v3", 60, 64),
}
MINIX3_MAGIC = 0x4D5A

MINIX_INODE_SIZE = {"v1": 32, "v2": 64, "v3": 64}


class MinixEntry(object):
    """目录项；raw 是磁盘上的原始名字字节（未解码、未补 NUL）"""

    __slots__ = ("name", "inode", "raw", "offset")

    def __init__(self, name, inode, raw, offset=0):
        self.name = name
        self.inode = inode
        self.raw = raw
        self.offset = offset

    def __repr__(self):
        return "<MinixEntry %r ino=%d %dB>" % (self.name, self.inode, len(self.raw))


class MinixInode(object):
    __slots__ = ("ino", "offset", "mode", "uid", "gid", "size", "nlink",
                 "atime", "mtime", "ctime", "zones", "version")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def type_name(self):
        return _mode_type(self.mode)

    @property
    def is_dir(self):
        return self.mode & 0xF000 == 0x4000

    @property
    def is_reg(self):
        return self.mode & 0xF000 == 0x8000

    @property
    def is_symlink(self):
        return self.mode & 0xF000 == 0xA000

    @property
    def perm(self):
        return "0o%04o" % (self.mode & 0o7777)

    def __repr__(self):
        return "<MinixInode %d %s %s %dB>" % (
            self.ino, self.version, self.type_name, self.size)


class Minix(object):
    """Minix V1 / V2 / V3

    只依赖 sub.read(offset, size) 与 sub.size。
    """

    def __init__(self, sub, sb_offset=None):
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.sb_offset = None
        self._sb_raw = b""
        if sb_offset is not None:
            raw = self.sub.read(sb_offset, 32)
            self._accept_super(raw, sb_offset)
        else:
            self._find_super()
        if self.sb_offset is None:
            raise ValueError("Minix: 未找到合法超级块（扫描偏移 %s）"
                             % (MINIX_SCAN,))
        self._parse_super()

    # ------------------------------------------------------------ 超级块
    def _accept_super(self, raw, off):
        """判断一段 32 字节是否为 Minix 超级块，是则记下版本与偏移"""
        if len(raw) < 24:
            return False
        if _le16(raw, 0x18) == MINIX3_MAGIC:
            imap = _le16(raw, 0x06)
            zmap = _le16(raw, 0x08)
            ninodes = _le32(raw, 0x00)
            bs = _le16(raw, 0x1C)
            if imap and zmap and ninodes and 1024 <= bs <= 65536 and not bs & (bs - 1):
                self.version = "v3"
                self.magic = MINIX3_MAGIC
                self.sb_offset = off
                self._sb_raw = raw
                return True
        magic = _le16(raw, 0x10)
        if magic in MINIX_MAGIC and magic != MINIX3_MAGIC:
            imap = _le16(raw, 0x04)
            zmap = _le16(raw, 0x06)
            ninodes = _le16(raw, 0x00)
            first = _le16(raw, 0x08)
            if imap and zmap and ninodes and first >= 2:
                self.version = MINIX_MAGIC[magic][0]
                self.magic = magic
                self.sb_offset = off
                self._sb_raw = raw
                return True
        return False

    def _find_super(self):
        for off in MINIX_SCAN:
            raw = self.sub.read(off, 32)
            if self._accept_super(raw, off):
                return True
        return False

    def _parse_super(self):
        raw = self._sb_raw or self.sub.read(self.sb_offset, 32)
        if self.version == "v3":
            self.ninodes = _le32(raw, 0x00)
            self.imap_blocks = _le16(raw, 0x06)
            self.zmap_blocks = _le16(raw, 0x08)
            self.firstdatazone = _le16(raw, 0x0A)
            self.log_zone_size = _le16(raw, 0x0C)
            self.max_size = _le32(raw, 0x10)
            self.nzones = _le32(raw, 0x14)
            self.state = 1                      # V3 无 s_state，内核固定 VALID_FS
            self.disk_version = _u8(raw, 0x1E)
            self.block_size = _le16(raw, 0x1C)
        else:
            self.ninodes = _le16(raw, 0x00)
            self.nzones = _le16(raw, 0x02)
            self.imap_blocks = _le16(raw, 0x04)
            self.zmap_blocks = _le16(raw, 0x06)
            self.firstdatazone = _le16(raw, 0x08)
            self.log_zone_size = _le16(raw, 0x0A)
            self.max_size = _le32(raw, 0x0C)
            self.state = _le16(raw, 0x12)
            z = _le32(raw, 0x14)
            if self.version == "v2" and z:
                self.nzones = z            # V2 的真实区数在 s_zones
            self.disk_version = 0
            self.block_size = 1024         # V1/V2 固定 1 KiB 块

        self.namelen, self.dirsize = MINIX_MAGIC[self.magic][1:]
        self.inode_size = MINIX_INODE_SIZE[self.version]
        self.inode_table_block = 2 + self.imap_blocks + self.zmap_blocks
        self.inode_table_off = self.inode_table_block * self.block_size
        self.inodes_per_block = self.block_size // self.inode_size
        self.root_ino = 1
        self.imap_off = 2 * self.block_size
        self.zmap_off = (2 + self.imap_blocks) * self.block_size

    # ------------------------------------------------------------ inode
    def _zone2blk(self, zone):
        """区号 -> 块号

        log_zone_size == 0（现实镜像几乎都是 0）时区号即块号，与内核
        V1/V2_minix_get_block 的做法一致；否则按老式 Minix 语义换算。
        """
        if zone <= 0:
            return 0
        if not self.log_zone_size:
            return zone
        if zone < self.firstdatazone:
            return zone
        return ((zone - self.firstdatazone) << self.log_zone_size) + self.firstdatazone

    def inode(self, ino):
        ino = int(ino)
        if ino < 1 or (self.ninodes and ino > self.ninodes):
            raise ValueError("Minix: inode 号越界 %d（共 %d）" % (ino, self.ninodes))
        off = self.inode_table_off + (ino - 1) * self.inode_size
        raw = self.sub.read(off, self.inode_size)
        if len(raw) < self.inode_size:
            raise ValueError("Minix: inode %d 读取不完整（偏移 0x%X）" % (ino, off))

        kw = {"ino": ino, "offset": off, "version": self.version}
        if self.version == "v1":
            kw["mode"] = _le16(raw, 0)
            kw["uid"] = _le16(raw, 2)
            kw["size"] = _le32(raw, 4)
            kw["atime"] = kw["mtime"] = kw["ctime"] = _le32(raw, 8)
            kw["gid"] = _u8(raw, 12)
            kw["nlink"] = _u8(raw, 13)
            kw["zones"] = [_le16(raw, 14 + 2 * i) for i in range(9)]
        else:
            kw["mode"] = _le16(raw, 0)
            kw["nlink"] = _le16(raw, 2)
            kw["uid"] = _le16(raw, 4)
            kw["gid"] = _le16(raw, 6)
            kw["size"] = _le32(raw, 8)
            kw["atime"] = _le32(raw, 12)
            kw["mtime"] = _le32(raw, 16)
            kw["ctime"] = _le32(raw, 20)
            kw["zones"] = [_le32(raw, 24 + 4 * i) for i in range(10)]
        return MinixInode(**kw)

    def root(self):
        return self.inode(self.root_ino)

    # ------------------------------------------------------------ 块映射
    def _inode_blocks(self, ip):
        """返回覆盖整个文件的数据块号列表（0 表示空洞）"""
        bs = self.block_size
        need = (ip.size + bs - 1) // bs
        out = []
        z = list(ip.zones or [])
        for i in range(min(7, len(z))):
            if len(out) >= need:
                return out
            out.append(self._zone2blk(z[i]))
        ptr = 2 if self.version == "v1" else 4
        if len(z) > 7 and len(out) < need:
            self._indirect(z[7], 1, out, need, ptr)
        if len(z) > 8 and len(out) < need:
            self._indirect(z[8], 2, out, need, ptr)
        if len(z) > 9 and len(out) < need:
            self._indirect(z[9], 3, out, need, ptr)
        return out

    def _indirect(self, blk, level, out, need, ptr, _depth=0):
        if blk <= 0 or _depth > 4 or len(out) >= need:
            return
        bs = self.block_size
        data = self.sub.read(self._zone2blk(blk) * bs, bs)
        if len(data) < bs:
            return
        count = bs // ptr
        for i in range(count):
            if len(out) >= need:
                return
            v = _le16(data, i * 2) if ptr == 2 else _le32(data, i * 4)
            if level <= 1:
                out.append(self._zone2blk(v))
            elif v:
                self._indirect(v, level - 1, out, need, ptr, _depth + 1)
            else:
                # 指向空二级间接块：整段空洞，按二级块容量补零
                span = count ** (level - 1)
                out.extend([0] * min(span, need - len(out)))

    def _data(self, ip):
        if ip.size <= 0:
            return b""
        bs = self.block_size
        chunks = []
        for b in self._inode_blocks(ip):
            if b <= 0:
                chunks.append(b"\x00" * bs)
            else:
                chunks.append(self.sub.read(b * bs, bs))
        return b"".join(chunks)[:ip.size]

    def read_file(self, ino_or_entry):
        ip = ino_or_entry if isinstance(ino_or_entry, MinixInode) \
            else self.inode(_as_ino(ino_or_entry))
        if ip.is_dir:
            return None
        return self._data(ip)

    def read_path(self, path):
        return self.read_file(self.lookup_path(path))

    # ------------------------------------------------------------ 目录
    def listdir(self, ino=None):
        ip = self.root() if ino is None else (
            ino if isinstance(ino, MinixInode) else self.inode(_as_ino(ino)))
        if not ip.is_dir:
            raise ValueError("Minix: inode %d 不是目录（mode=0o%o）"
                             % (ip.ino, ip.mode))
        data = self._data(ip)
        ds = self.dirsize
        # 目录项 inode 字段：V1/V2 为 u16，V3 为 u32（见 minix3_dir_entry）
        raw_len = 4 if self.version == "v3" else 2
        out = []
        for off in range(0, len(data) - ds + 1, ds):
            ei = _le32(data, off) if raw_len == 4 else _le16(data, off)
            if not ei:
                continue
            nraw = _cstr(data[off + raw_len:off + ds])
            if not nraw:
                continue
            out.append(MinixEntry(_dec(nraw), ei, nraw, off))
        return out

    def walk(self, ino=None, prefix="", _depth=0, _max=32):
        for e in self.listdir(ino):
            if e.name in (".", ".."):
                continue
            path = prefix + e.name
            yield path, e
            try:
                child = self.inode(e.inode)
            except ValueError:
                continue
            if child.is_dir and _depth < _max:
                for sub_path, sub_e in self.walk(child, path + "/",
                                                 _depth + 1, _max):
                    yield sub_path, sub_e

    def lookup_path(self, path):
        ip = self.root()
        for part in [p for p in path.split("/") if p]:
            if part == ".":
                continue
            hit = None
            for e in self.listdir(ip):
                if e.name == part:
                    hit = e
                    break
            if hit is None:
                raise FileNotFoundError(path)
            ip = self.inode(hit.inode)
        return ip

    def find(self, pattern):
        pat = pattern.lower()
        return [(p, e) for p, e in self.walk() if pat in p.lower()]

    # ------------------------------------------------------------ 概要
    def info(self):
        return {
            "fs": "minix",
            "version": self.version,
            "magic": "0x%04X" % self.magic,
            "block_size": self.block_size,
            "inodes": self.ninodes,
            "zones": self.nzones,
            "imap_blocks": self.imap_blocks,
            "zmap_blocks": self.zmap_blocks,
            "inode_table_block": self.inode_table_block,
            "inode_size": self.inode_size,
            "inodes_per_block": self.inodes_per_block,
            "firstdatazone": self.firstdatazone,
            "log_zone_size": self.log_zone_size,
            "max_size": self.max_size,
            "state": self.state,
            "namelen": self.namelen,
            "dirsize": self.dirsize,
            "super_offset": self.sb_offset,
            "disk_version": self.disk_version,
            "root_ino": self.root_ino,
        }


# ==================================================================== JFS

JFS_MAGIC = b"JFS1"
JFS_SUPER_POS = 0x8000
JFS_SUPER_LEN = 0xB8
JFS_AIMAP_OFF = 0x9000
JFS_AITBL_OFF = 0xB000          # AGGR_INODE_TABLE_START = 44 KiB
JFS_SUPER2_OFF = 0xF000
JFS_PAGE = 4096                 # PSIZE
JFS_AGGR_INODES = 32            # AIT 首批固定页覆盖的聚合 inode 数
JFS_INOSPEREXT = 32
JFS_INOSPERIAG = 4096
JFS_IMAP_INO = 16               # FILESYSTEM_I
JFS_ROOT_INO = 2                # ROOT_I
JFS_INOEXT_OFF = 3072           # struct iag.inoext[] 的字节偏移

BT_ROOT = 0x01
BT_LEAF = 0x02
BT_INTERNAL = 0x04
BT_RIGHTMOST = 0x10
BT_LEFTMOST = 0x20

JFS_STATE_NAME = {
    0x00: "clean", 0x01: "mounted", 0x02: "dirty",
    0x04: "logredo-failed", 0x08: "extendfs",
}

JFS_FLAG_BITS = [
    (0x00000001, "unicode"), (0x00000002, "err-remount-ro"),
    (0x00000004, "err-continue"), (0x00000008, "err-panic"),
    (0x00000010, "usrquota"), (0x00000020, "grpquota"),
    (0x00000080, "discard"), (0x00000800, "inlinelog"),
    (0x00020000, "sparse"), (0x00200000, "dir-index"),
    (0x10000000, "linux"), (0x40000000, "os2"), (0x80000000, "aix"),
]


def _pxd(b, off):
    """pxd_t：__le32 len; __le32 addr（长度、地址均以文件系统块计）"""
    return _le32(b, off), _le32(b, off + 4)


def _jfs_time(b, off):
    return _le32(b, off), _le32(b, off + 4)


class JfsEntry(object):
    __slots__ = ("name", "inode", "raw", "slot")

    def __init__(self, name, inode, raw=b"", slot=0):
        self.name = name
        self.inode = inode
        self.raw = raw
        self.slot = slot

    def __repr__(self):
        return "<JfsEntry %r ino=%d>" % (self.name, self.inode)


class JfsInode(object):
    __slots__ = ("ino", "offset", "inostamp", "fileset", "number", "gen",
                 "ixpxd", "size", "nblocks", "nlink", "uid", "gid", "mode",
                 "atime", "ctime", "mtime", "otime", "next_index", "acltype",
                 "root", "raw")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def type_name(self):
        return _mode_type(self.mode)

    @property
    def is_dir(self):
        return bool(self.mode & 0x20000000) or self.mode & 0xF000 == 0x4000

    @property
    def is_reg(self):
        return self.mode & 0xF000 == 0x8000

    @property
    def is_symlink(self):
        return self.mode & 0xF000 == 0xA000

    def __repr__(self):
        return "<JfsInode %d %s %dB>" % (self.ino, self.type_name, self.size)


class Jfs(object):
    """JFS（IBM Journaled File System），超级块在 0x8000，小端"""

    def __init__(self, sub, super_pos=JFS_SUPER_POS):
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.super_pos = super_pos
        raw = self.sub.read(super_pos, JFS_SUPER_LEN)
        if len(raw) < JFS_SUPER_LEN:
            raise ValueError("JFS: 超级块读取不完整（偏移 0x%X 只有 %d 字节）"
                             % (super_pos, len(raw)))
        if raw[:4] != JFS_MAGIC:
            raise ValueError("JFS: 超级块 magic 不符，得到 %r（期望 %r）"
                             % (raw[:4], JFS_MAGIC))
        self._parse_super(raw)
        self._imap_ip = None

    def _parse_super(self, raw):
        self.magic = raw[0:4].decode("ascii", "replace")
        self.version = _le32(raw, 0x04)
        self.aggr_size = _le64(raw, 0x08)
        self.block_size = _le32(raw, 0x10)
        self.l2bsize = _le16(raw, 0x14)
        self.l2bfactor = _le16(raw, 0x16)
        self.pbsize = _le32(raw, 0x18)
        self.l2pbsize = _le16(raw, 0x1C)
        self.agsize = _le32(raw, 0x20)
        self.flag = _le32(raw, 0x24)
        self.state = _le32(raw, 0x28)
        self.compress = _le32(raw, 0x2C)
        self.ait2 = _pxd(raw, 0x30)
        self.aim2 = _pxd(raw, 0x38)
        self.logdev = _le32(raw, 0x40)
        self.logserial = _le32(raw, 0x44)
        self.logpxd = _pxd(raw, 0x48)
        self.fsckpxd = _pxd(raw, 0x50)
        self.sb_time = _jfs_time(raw, 0x58)
        self.fsckloglen = _le32(raw, 0x60)
        self.fscklog = _u8(raw, 0x64)
        self.fpack = _cstr(raw[0x65:0x70]).decode("ascii", "replace")
        self.xsize = _le64(raw, 0x70)
        self.uuid = raw[0x88:0x98]
        self.label = _cstr(raw[0x98:0xA8]).decode("ascii", "replace")
        self.loguuid = raw[0xA8:0xB8]
        if self.block_size not in (512, 1024, 2048, 4096) or \
                (1 << self.l2bsize) != self.block_size:
            raise ValueError(
                "JFS: 块大小不自洽（s_bsize=%d, s_l2bsize=%d）"
                % (self.block_size, self.l2bsize))
        self.root_ino = JFS_ROOT_INO
        self.l2nbperpage = 12 - self.l2bsize

    # ------------------------------------------------------------ inode
    def imap_inode(self):
        """文件集 inode 映射文件（AIT 里的 16 号聚合 inode）"""
        if self._imap_ip is None:
            self._imap_ip = self.ait_inode(JFS_IMAP_INO)
        return self._imap_ip

    def ait_inode(self, ino):
        """聚合 inode（0..31）：位于 AITBL_OFF 起的固定页，不经 inode map

        对应内核 diReadSpecial()：address = AITBL_OFF >> L2PSIZE，再右移
        inum >> 3 个 4 KiB 页，页内偏移 (inum & 7) * 512。
        """
        ino = int(ino)
        if not 0 <= ino < JFS_AGGR_INODES:
            raise ValueError("JFS: 聚合 inode 号应在 0..31，收到 %d" % ino)
        page = (JFS_AITBL_OFF >> 12) + (ino >> 3)
        off = page * JFS_PAGE + (ino & 7) * 512
        raw = self.sub.read(off, 512)
        if len(raw) < 512:
            raise ValueError("JFS: AIT inode %d 读取失败（偏移 0x%X）" % (ino, off))
        return self._parse_dinode(raw, ino, off)

    def inode(self, ino):
        """文件集 inode：imap -> iag 页 -> inoext[extno] -> 页内 512 B 槽

        对应内核 diRead()：iag 页号 = (iagno + 1) << l2nbperpage（页大小 4 KiB），
        inoext 在 struct iag 内偏移 3072，槽地址再加
        ((ino & 31) >> 3) << l2nbperpage 个块。
        """
        ino = int(ino)
        if ino < 0:
            raise ValueError("JFS: 非法 inode 号 %d" % ino)
        iagno = ino >> 12
        imap = self.imap_inode()
        if imap.size and (iagno + 1) * JFS_PAGE >= imap.size:
            raise ValueError("JFS: inode %d 的 iag %d 超出 inode map 范围"
                             % (ino, iagno))
        page = self._read_range(imap, (iagno + 1) * JFS_PAGE, JFS_PAGE)
        extno = (ino & (JFS_INOSPERIAG - 1)) >> 5
        plen, paddr = _pxd(page, JFS_INOEXT_OFF + extno * 8)
        if not paddr or not plen:
            raise ValueError("JFS: inode %d 的 inoext[%d] 为空（iag=%d）"
                             % (ino, extno, iagno))
        blk = paddr + (((ino & (JFS_INOSPEREXT - 1)) >> 3) << self.l2nbperpage)
        off = blk * self.block_size + (ino & 7) * 512
        raw = self.sub.read(off, 512)
        if len(raw) < 512:
            raise ValueError("JFS: inode %d 数据不完整（偏移 0x%X）" % (ino, off))
        return self._parse_dinode(raw, ino, off)

    def _parse_dinode(self, raw, ino, off):
        return JfsInode(
            ino=ino, offset=off, raw=raw,
            inostamp=_le32(raw, 0x00), fileset=_le32(raw, 0x04),
            number=_le32(raw, 0x08), gen=_le32(raw, 0x0C),
            ixpxd=_pxd(raw, 0x10),
            size=_le64(raw, 0x18), nblocks=_le64(raw, 0x20),
            nlink=_le32(raw, 0x28), uid=_le32(raw, 0x2C), gid=_le32(raw, 0x30),
            mode=_le32(raw, 0x34),
            atime=_jfs_time(raw, 0x38), ctime=_jfs_time(raw, 0x40),
            mtime=_jfs_time(raw, 0x48), otime=_jfs_time(raw, 0x50),
            next_index=_le32(raw, 0x78), acltype=_le32(raw, 0x7C),
            root=raw[0xE0:0x200],
        )

    def root(self):
        return self.inode(self.root_ino)

    # ------------------------------------------------------------ xtree
    def _xt_spans(self, page, lo, hi, out, _depth=0):
        """在 xtree 页上收集与 [lo, hi) 块区间重叠的 extent"""
        if len(page) < 32 or _depth > 8:
            return
        flag = _u8(page, 16)
        n = _le16(page, 18)
        n = min(n, (len(page) - 32) // 16)
        for i in range(n):
            e = 32 + i * 16
            xoff = (_u8(page, e + 3) << 32) | _le32(page, e + 4)
            ln, addr = _pxd(page, e + 8)
            if ln == 0 or addr == 0:
                continue
            if xoff + ln <= lo or xoff >= hi:
                continue
            if flag & BT_LEAF:
                out.append((xoff, addr, ln))
            else:
                child = self.sub.read(addr * self.block_size,
                                      ln * self.block_size)
                if child:
                    self._xt_spans(child, lo, hi, out, _depth + 1)

    def _read_range(self, ip, off, length):
        """按字节区间读文件内容（空洞补零）"""
        if length <= 0:
            return b""
        bs = self.block_size
        lo = off // bs
        hi = (off + length + bs - 1) // bs
        spans = []
        self._xt_spans(ip.root or b"", lo, hi, spans)
        buf = bytearray(length)
        for xoff, addr, ln in sorted(spans):
            bstart = xoff * bs
            data = self.sub.read(addr * bs, ln * bs)
            if not data:
                continue
            # 只把与请求窗口重叠的部分拷进输出缓冲
            copy_lo = max(off, bstart)
            copy_hi = min(off + length, bstart + len(data))
            if copy_hi <= copy_lo:
                continue
            buf[copy_lo - off:copy_hi - off] = \
                data[copy_lo - bstart:copy_hi - bstart]
        return bytes(buf)

    def read_file(self, ino_or_entry, length=None):
        ip = ino_or_entry if isinstance(ino_or_entry, JfsInode) \
            else self.inode(_as_ino(ino_or_entry))
        if ip.is_dir:
            return None
        if self.compress:
            raise NotImplementedError(
                "JFS: 卷启用压缩（s_compress=%d），本实现不解析压缩文件" % self.compress)
        if ip.is_symlink and 0 < ip.size <= 256:
            # 快符号链接：目标内联在 dinode 的 di_inlinedata（0xE0 起 256 B）
            return ip.raw[0xE0:0xE0 + ip.size]
        n = ip.size if length is None else min(ip.size, length)
        return self._read_range(ip, 0, n)

    def read_path(self, path):
        return self.read_file(self.lookup_path(path))

    # ------------------------------------------------------------ dtree
    def _dt_name(self, page, ent, namlen):
        """重组目录项名字

        头部 ldtentry 带 11 个 UTF-16 字符（DTLHDRDATALEN），剩余字符挂在
        next 指向的 dtslot 链上（每槽 15 字符）。legacy（无 index 字段）布局
        头部可放 13 字符，本实现按 11 处理；名字 <= 11 字符时两种布局一致。
        """
        chars = []
        for i in range(min(namlen, 11)):
            chars.append(_le16(page, ent + 6 + i * 2))
        nxt = _s8(page, ent + 4)
        guard = 0
        while len(chars) < namlen and nxt >= 0 and guard < 64:
            s = 32 + nxt * 32
            if s + 32 > len(page):
                break
            cnt = _u8(page, s + 1)
            take = min(cnt, namlen - len(chars), 15)
            for i in range(take):
                chars.append(_le16(page, s + 2 + i * 2))
            nxt = _s8(page, s)
            guard += 1
        raw = b"".join(struct.pack("<H", c & 0xFFFF) for c in chars)
        if self.flag & 0x00000001:                 # JFS_UNICODE
            return raw.decode("utf-16-le", "replace"), raw
        return raw.decode("latin-1"), raw

    def _dt_walk(self, page, out, _depth=0):
        if len(page) < 64 or _depth > 8:
            return
        flag = _u8(page, 16)
        nextindex = _u8(page, 17)
        if flag & BT_ROOT:
            stbl_off, maxslot, cap = 24, 9, 8
        else:
            stbl_off = 32 + _u8(page, 21) * 32
            maxslot = _u8(page, 20) or 128
            cap = maxslot
        n = min(nextindex, cap)
        for i in range(n):
            s = _u8(page, stbl_off + i)
            if s <= 0 or s >= maxslot:
                continue
            ent = 32 + s * 32
            if ent + 32 > len(page):
                continue
            if flag & BT_LEAF:
                ino = _le32(page, ent)
                namlen = _u8(page, ent + 5)
                name, raw = self._dt_name(page, ent, namlen)
                out.append(JfsEntry(name, ino, raw, s))
            else:
                plen, paddr = _pxd(page, ent)
                if not paddr or not plen:
                    continue
                child = self.sub.read(paddr * self.block_size,
                                     max(plen * self.block_size, JFS_PAGE))
                self._dt_walk(child, out, _depth + 1)

    def listdir(self, ino=None):
        ip = self.root() if ino is None else (
            ino if isinstance(ino, JfsInode) else self.inode(_as_ino(ino)))
        if not ip.is_dir:
            raise ValueError("JFS: inode %d 不是目录（mode=0x%08X）"
                             % (ip.ino, ip.mode))
        out = []
        self._dt_walk(ip.root or b"", out)
        return out

    def walk(self, ino=None, prefix="", _depth=0, _max=32):
        for e in self.listdir(ino):
            if e.name in (".", ".."):
                continue
            path = prefix + e.name
            yield path, e
            try:
                child = self.inode(e.inode)
            except ValueError:
                continue
            if child.is_dir and _depth < _max:
                for sp, se in self.walk(child, path + "/", _depth + 1, _max):
                    yield sp, se

    def lookup_path(self, path):
        ip = self.root()
        for part in [p for p in path.split("/") if p]:
            if part == ".":
                continue
            hit = None
            for e in self.listdir(ip):
                if e.name == part:
                    hit = e
                    break
            if hit is None:
                raise FileNotFoundError(path)
            ip = self.inode(hit.inode)
        return ip

    def find(self, pattern):
        pat = pattern.lower()
        return [(p, e) for p, e in self.walk() if pat in p.lower()]

    # ------------------------------------------------------------ 概要
    def flags_named(self):
        return [n for bit, n in JFS_FLAG_BITS if self.flag & bit]

    def info(self):
        return {
            "fs": "jfs",
            "magic": self.magic,
            "version": self.version,
            "block_size": self.block_size,
            "l2bsize": self.l2bsize,
            "l2bfactor": self.l2bfactor,
            "pbsize": self.pbsize,
            "aggr_size": self.aggr_size,
            "agsize": self.agsize,
            "flag": "0x%08X" % self.flag,
            "flags": self.flags_named(),
            "state": JFS_STATE_NAME.get(self.state, "0x%X" % self.state),
            "compress": self.compress,
            "ait2": {"len": self.ait2[0], "addr": self.ait2[1]},
            "aim2": {"len": self.aim2[0], "addr": self.aim2[1]},
            "logpxd": {"len": self.logpxd[0], "addr": self.logpxd[1]},
            "logdev": self.logdev,
            "volume_name": self.fpack,
            "label": self.label,
            "uuid": self.uuid.hex(),
            "super_offset": self.super_pos,
            "root_ino": self.root_ino,
            "imap_ino": JFS_IMAP_INO,
        }


# ============================================================= ReiserFS

REISER_MAGIC = b"ReIsEr2Fs"
REISER_POS = 0x10000            # 64 KiB
REISER_OLD_POS = 0x2000         # 3.5 - 3.5.10 的超级块位置
REISER_SUPER_LEN = 0xCC

REISER_MAGICS = (
    (b"ReIsErFs", "3.5", "ReIsErFs"),
    (b"ReIsEr2Fs", "3.6", "ReIsEr2Fs"),
    (b"ReIsEr3Fs", "3.6+jr", "ReIsEr3Fs"),
)

HASH_NAME = {0: "unset", 1: "tea", 2: "yura", 3: "r5"}

KEY_FORMAT_3_5 = 0
KEY_FORMAT_3_6 = 1

TYPE_STAT_DATA = 0
TYPE_INDIRECT = 1
TYPE_DIRECT = 2
TYPE_DIRENTRY = 3
TYPE_ANY = 15

TYPE_NAME = {0: "stat-data", 1: "indirect", 2: "direct", 3: "direntry",
             15: "any"}

V1_UNIQUENESS = {0: TYPE_STAT_DATA, 0xFFFFFFFE: TYPE_INDIRECT,
                 0xFFFFFFFF: TYPE_DIRECT, 500: TYPE_DIRENTRY}

DISK_LEAF_NODE_LEVEL = 1
FREE_LEVEL = 0
BLKH_SIZE = 24
KEY_SIZE = 16
IH_SIZE = 24
DC_SIZE = 8
DEH_SIZE = 16
DEH_VISIBLE = 2
REISER_ROOT_OBJECTID = 2
REISER_ROOT_PARENT_OBJECTID = 1


class ReiserEntry(object):
    __slots__ = ("name", "inode", "state", "entry_offset", "parent")

    def __init__(self, name, inode, state=0, entry_offset=0, parent=0):
        self.name = name
        self.inode = inode
        self.state = state
        self.entry_offset = entry_offset
        self.parent = parent

    @property
    def visible(self):
        return bool(self.state & DEH_VISIBLE)

    def __repr__(self):
        return "<ReiserEntry %r ino=%d%s>" % (
            self.name, self.inode, "" if self.visible else " hidden")


class ReiserFsInode(object):
    __slots__ = ("ino", "mode", "nlink", "uid", "gid", "size", "atime",
                 "mtime", "ctime", "blocks", "sd_version", "attrs")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def type_name(self):
        return _mode_type(self.mode)

    @property
    def is_dir(self):
        return self.mode & 0xF000 == 0x4000

    @property
    def is_reg(self):
        return self.mode & 0xF000 == 0x8000

    @property
    def is_symlink(self):
        return self.mode & 0xF000 == 0xA000

    def __repr__(self):
        return "<ReiserFsInode %d %s %dB>" % (self.ino, self.type_name, self.size)


class ReiserItem(object):
    """叶子节点里的一个条目"""

    __slots__ = ("block", "index", "key", "dir_id", "objid", "offset",
                 "type", "version", "entry_count", "body")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def type_name(self):
        return TYPE_NAME.get(self.type, str(self.type))

    def __repr__(self):
        return "<ReiserItem %s dir=%d obj=%d off=%d %dB>" % (
            self.type_name, self.dir_id, self.objid, self.offset, len(self.body or b""))


class ReiserFs(object):
    """ReiserFS 3.5 / 3.6（S+ 树；只读）"""

    def __init__(self, sub, super_pos=None):
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.super_pos = None
        self.magic = ""
        positions = (super_pos,) if super_pos is not None \
            else (REISER_POS, REISER_OLD_POS)
        for pos in positions:
            raw = self.sub.read(pos, REISER_SUPER_LEN)
            if len(raw) < REISER_SUPER_LEN:
                continue
            hit = self._magic_version(raw[0x34:0x3E])
            if not hit:
                continue
            bs = _le16(raw, 0x2C)
            if bs not in (1024, 2048, 4096, 8192, 16384):
                continue
            self.super_pos = pos
            self._raw = raw
            self._hit = hit
            break
        if self.super_pos is None:
            raise ValueError("ReiserFS: 未找到超级块（已试 0x%X / 0x%X）"
                             % (REISER_POS, REISER_OLD_POS))
        self._parse_super(self._raw)
        self._leaf_cache = None

    @staticmethod
    def _magic_version(buf):
        for magic, ver, label in REISER_MAGICS:
            if buf[:len(magic)] == magic:
                return ver, label
        return None

    def _parse_super(self, raw):
        ver, label = self._hit
        self.version = ver
        self.magic = label
        self.block_count = _le32(raw, 0x00)
        self.free_blocks = _le32(raw, 0x04)
        self.root_block = _le32(raw, 0x08)
        self.journal_1st_block = _le32(raw, 0x0C)
        self.journal_dev = _le32(raw, 0x10)
        self.journal_size = _le32(raw, 0x14)
        self.journal_trans_max = _le32(raw, 0x18)
        self.journal_magic = _le32(raw, 0x1C)
        self.journal_max_batch = _le32(raw, 0x20)
        self.journal_max_commit_age = _le32(raw, 0x24)
        self.journal_max_trans_age = _le32(raw, 0x28)
        self.block_size = _le16(raw, 0x2C)
        self.oid_maxsize = _le16(raw, 0x2E)
        self.oid_cursize = _le16(raw, 0x30)
        self.umount_state = _le16(raw, 0x32)
        self.fs_state = _le16(raw, 0x3E)
        self.hash_code = _le32(raw, 0x40)
        self.tree_height = _le16(raw, 0x44)
        self.bmap_nr = _le16(raw, 0x46)
        self.sb_version = _le16(raw, 0x48)
        self.s_reserved = _le16(raw, 0x4A)
        self.inode_generation = _le32(raw, 0x4C)
        self.s_flags = _le32(raw, 0x50)
        self.uuid = raw[0x54:0x64]
        self.label = _cstr(raw[0x64:0x74]).decode("utf-8", "replace")
        self.mnt_count = _le16(raw, 0x74)
        self.max_mnt_count = _le16(raw, 0x76)
        self.lastcheck = _le32(raw, 0x78)
        self.check_interval = _le32(raw, 0x7C)
        self.root_ino = REISER_ROOT_OBJECTID

    # ------------------------------------------------------------ 节点
    def node(self, blk):
        """返回 (level, nr_item, free_space, reserved, right_delim, data, items, children)"""
        bs = self.block_size
        data = self.sub.read(blk * bs, bs)
        if len(data) < BLKH_SIZE:
            raise ValueError("ReiserFS: 节点块 %d 读取失败" % blk)
        level = _le16(data, 0)
        nr = _le16(data, 2)
        free = _le16(data, 4)
        reserved = _le16(data, 6)
        right = data[8:24]
        items = []
        children = []
        if level == DISK_LEAF_NODE_LEVEL:
            for i in range(min(nr, (bs - BLKH_SIZE) // IH_SIZE)):
                o = BLKH_SIZE + i * IH_SIZE
                if o + IH_SIZE > bs:
                    break
                key = data[o:o + KEY_SIZE]
                ver = _le16(data, o + 22) & 0x7FFF
                ilen = _le16(data, o + 18)
                iloc = _le16(data, o + 20)
                body = data[iloc:iloc + ilen] if iloc + ilen <= bs else data[iloc:]
                items.append(self._mk_item(blk, i, key, ver, body,
                                           _le16(data, o + 16)))
        elif level > DISK_LEAF_NODE_LEVEL:
            dc_off = BLKH_SIZE + min(nr, (bs - BLKH_SIZE) // KEY_SIZE) * KEY_SIZE
            for i in range(nr + 1):
                o = dc_off + i * DC_SIZE
                if o + DC_SIZE > bs:
                    break
                children.append(_le32(data, o))
        return {"block": blk, "level": level, "nr_item": nr,
                "free_space": free, "reserved": reserved,
                "right_delim": right, "items": items, "children": children,
                "data": data}

    def _key_parts(self, key, version):
        dir_id = _le32(key, 0)
        objid = _le32(key, 4)
        if version == KEY_FORMAT_3_5:
            offset = _le32(key, 8)
            itype = V1_UNIQUENESS.get(_le32(key, 12), TYPE_ANY)
        else:
            v = _le64(key, 8)
            itype = (v >> 60) & 0xF
            offset = v & ((1 << 60) - 1)
            if itype > TYPE_ANY:
                itype = TYPE_ANY
        return dir_id, objid, offset, itype

    def _mk_item(self, blk, index, key, ver, body, entry_count):
        d, o, off, t = self._key_parts(key, ver)
        return ReiserItem(block=blk, index=index, key=key, dir_id=d, objid=o,
                          offset=off, type=t, version=ver,
                          entry_count=entry_count, body=body)

    # ------------------------------------------------------------ 树扫描
    def leaves(self):
        """遍历整棵 S+ 树，返回所有叶子节点（结果缓存）"""
        if self._leaf_cache is not None:
            return self._leaf_cache
        out = []
        seen = set()
        stack = [self.root_block]
        max_blocks = self.block_count or 1 << 24
        while stack:
            blk = stack.pop()
            if not blk or blk in seen or blk >= max_blocks or blk <= 0:
                continue
            seen.add(blk)
            if len(seen) > 1 << 22:
                break
            try:
                nd = self.node(blk)
            except ValueError:
                continue
            lvl = nd["level"]
            if lvl == DISK_LEAF_NODE_LEVEL:
                out.append(nd)
            elif lvl > DISK_LEAF_NODE_LEVEL:
                for c in reversed(nd["children"]):
                    stack.append(c)
            # lvl == FREE_LEVEL(0)：已释放节点，跳过
        out.sort(key=lambda nd: nd["block"])
        self._leaf_cache = out
        return out

    def items(self, objid=None, itype=None):
        for nd in self.leaves():
            for it in nd["items"]:
                if objid is not None and it.objid != objid:
                    continue
                if itype is not None and it.type != itype:
                    continue
                yield it

    # ------------------------------------------------------------ inode
    def inode(self, ino):
        ino = int(ino)
        sd = None
        for it in self.items(objid=ino, itype=TYPE_STAT_DATA):
            sd = it
            break
        if sd is None:
            raise ValueError("ReiserFS: 对象 %d 没有 stat data" % ino)
        return self._parse_sd(ino, sd)

    def _parse_sd(self, ino, it):
        b = it.body or b""
        if it.version == KEY_FORMAT_3_5 and len(b) >= 32:
            return ReiserFsInode(
                ino=ino, sd_version=1, attrs=0,
                mode=_le16(b, 0), nlink=_le16(b, 2), uid=_le16(b, 4),
                gid=_le16(b, 6), size=_le32(b, 8), atime=_le32(b, 12),
                mtime=_le32(b, 16), ctime=_le32(b, 20), blocks=_le32(b, 24))
        if len(b) < 44:
            raise ValueError("ReiserFS: 对象 %d 的 stat data 长度异常（%d B）"
                             % (ino, len(b)))
        return ReiserFsInode(
            ino=ino, sd_version=2, attrs=_le16(b, 2),
            mode=_le16(b, 0), nlink=_le32(b, 4), size=_le64(b, 8),
            uid=_le32(b, 16), gid=_le32(b, 20), atime=_le32(b, 24),
            mtime=_le32(b, 28), ctime=_le32(b, 32), blocks=_le32(b, 36))

    def root(self):
        return self.inode(self.root_ino)

    # ------------------------------------------------------------ 文件
    def read_file(self, ino_or_entry):
        ip = ino_or_entry if isinstance(ino_or_entry, ReiserFsInode) \
            else self.inode(_as_ino(ino_or_entry))
        if ip.is_dir:
            return None
        bs = self.block_size
        size = int(ip.size or 0)
        buf = bytearray(size)
        for it in self.items(objid=ip.ino):
            if it.type == TYPE_DIRECT:
                off = int(it.offset)
                body = it.body or b""
                if off < size and body:
                    n = min(len(body), size - off)
                    buf[off:off + n] = body[:n]
            elif it.type == TYPE_INDIRECT:
                off = int(it.offset)
                body = it.body or b""
                for i in range(len(body) // 4):
                    ptr = _le32(body, i * 4)
                    if ptr == 0:
                        continue
                    if ptr >= (self.block_count or 0xFFFFFFFF):
                        raise NotImplementedError(
                            "ReiserFS: 对象 %d 的间接块指针 0x%X 带压缩/尾块标志，"
                            "本实现只支持未压缩间接项" % (ip.ino, ptr))
                    pos = off + i * bs
                    if pos >= size:
                        break
                    blk = self.sub.read(ptr * bs, bs)
                    n = min(bs, size - pos)
                    buf[pos:pos + n] = blk[:n]
        return bytes(buf)

    def read_path(self, path):
        return self.read_file(self.lookup_path(path))

    # ------------------------------------------------------------ 目录
    def _dir_entries(self, item, visible_only=True):
        body = item.body or b""
        n = item.entry_count
        if n <= 0:
            n = len(body) // DEH_SIZE
        n = min(n, len(body) // DEH_SIZE)
        out = []
        for i in range(n):
            o = i * DEH_SIZE
            loc = _le16(body, o + 12)
            state = _le16(body, o + 14)
            if i + 1 < n:
                end = _le16(body, (i + 1) * DEH_SIZE + 12)
                ln = end - loc - 1
            else:
                ln = len(body) - loc
            if ln <= 0 or loc < 0 or loc + ln > len(body):
                # 长度不可信时退回按 NUL 截断
                nm = body[loc:] if 0 <= loc < len(body) else b""
                nm = _cstr(nm)[:255]
            else:
                nm = body[loc:loc + ln]
            if not nm:
                continue
            e = ReiserEntry(_dec(nm), _le32(body, o + 8), state, loc,
                            _le32(body, o + 4))
            if visible_only and not e.visible:
                continue
            out.append(e)
        return out

    def listdir(self, ino=None, visible_only=True):
        ip = self.root() if ino is None else (
            ino if isinstance(ino, ReiserFsInode) else self.inode(_as_ino(ino)))
        if not ip.is_dir:
            raise ValueError("ReiserFS: 对象 %d 不是目录（mode=0o%o）"
                             % (ip.ino, ip.mode))
        out = []
        for it in self.items(objid=ip.ino, itype=TYPE_DIRENTRY):
            out.extend(self._dir_entries(it, visible_only))
        return out

    def walk(self, ino=None, prefix="", _depth=0, _max=32):
        for e in self.listdir(ino):
            if e.name in (".", ".."):
                continue
            path = prefix + e.name
            yield path, e
            try:
                child = self.inode(e.inode)
            except ValueError:
                continue
            if child.is_dir and _depth < _max:
                for sp, se in self.walk(child, path + "/", _depth + 1, _max):
                    yield sp, se

    def lookup_path(self, path):
        ip = self.root()
        for part in [p for p in path.split("/") if p]:
            if part == ".":
                continue
            hit = None
            for e in self.listdir(ip):
                if e.name == part:
                    hit = e
                    break
            if hit is None:
                raise FileNotFoundError(path)
            ip = self.inode(hit.inode)
        return ip

    def find(self, pattern):
        pat = pattern.lower()
        return [(p, e) for p, e in self.walk() if pat in p.lower()]

    # ------------------------------------------------------------ 概要
    def info(self):
        return {
            "fs": "reiserfs",
            "version": self.version,
            "magic": self.magic,
            "block_size": self.block_size,
            "block_count": self.block_count,
            "free_blocks": self.free_blocks,
            "root_block": self.root_block,
            "tree_height": self.tree_height,
            "hash": HASH_NAME.get(self.hash_code, "0x%X" % self.hash_code),
            "hash_code": self.hash_code,
            "bmap_nr": self.bmap_nr,
            "umount_state": self.umount_state,
            "fs_state": self.fs_state,
            "sb_version": self.sb_version,
            "inode_generation": self.inode_generation,
            "flags": "0x%08X" % self.s_flags,
            "journal_block": self.journal_1st_block,
            "journal_size": self.journal_size,
            "journal_dev": self.journal_dev,
            "label": self.label,
            "uuid": self.uuid.hex(),
            "super_offset": self.super_pos,
            "root_ino": self.root_ino,
            "leaf_nodes": len(self.leaves()),
        }


# ============================================================ 统一入口

def _probe_minix(sub):
    for off in MINIX_SCAN:
        raw = sub.read(off, 32)
        if len(raw) < 24:
            continue
        if _le16(raw, 0x18) == MINIX3_MAGIC:
            bs = _le16(raw, 0x1C)
            if _le32(raw, 0) and _le16(raw, 0x06) and _le16(raw, 0x08) \
                    and 1024 <= bs <= 65536 and not bs & (bs - 1):
                return "minix3"
        m = _le16(raw, 0x10)
        if m in MINIX_MAGIC and m != MINIX3_MAGIC:
            if _le16(raw, 0x04) and _le16(raw, 0x06) and _le16(raw, 0x00) \
                    and _le16(raw, 0x08) >= 2:
                return "minix1" if MINIX_MAGIC[m][0] == "v1" else "minix2"
    return None


def _probe_reiser(sub):
    for pos in (REISER_POS, REISER_OLD_POS):
        raw = sub.read(pos, REISER_SUPER_LEN)
        if len(raw) < REISER_SUPER_LEN:
            continue
        hit = ReiserFs._magic_version(raw[0x34:0x3E])
        if hit and _le16(raw, 0x2C) in (1024, 2048, 4096, 8192, 16384):
            # "3.6+jr"（ReIsEr3Fs）对外统一报 3.6，info() 里保留细分
            ver = "3.6" if hit[0].startswith("3.6") else hit[0]
            return "reiserfs" + ver
    return None


def _probe_jfs(sub):
    raw = sub.read(JFS_SUPER_POS, 0x20)
    if len(raw) < 0x20 or raw[:4] != JFS_MAGIC:
        return None
    bs = _le32(raw, 0x10)
    if bs in (512, 1024, 2048, 4096) and (1 << _le16(raw, 0x14)) == bs:
        return "jfs"
    return None


def probe(sub):
    """返回 "minix1" / "minix2" / "minix3" / "jfs" / "reiserfs3.5" /
    "reiserfs3.6" / "unknown"

    判定顺序 jfs -> reiserfs -> minix：前两者 magic 在固定偏移，Minix 需要扫描，
    放在最后避免误判。
    """
    for fn in (_probe_jfs, _probe_reiser, _probe_minix):
        kind = fn(sub)
        if kind:
            return kind
    return "unknown"


def open_fs(sub, **kw):
    kind = probe(sub)
    if kind == "unknown":
        raise ValueError("classicfs: 三种格式都未识别，请确认镜像/偏移")
    if kind.startswith("minix"):
        return Minix(sub, **kw)
    if kind == "jfs":
        return Jfs(sub, **kw)
    return ReiserFs(sub, **kw)


def detect_all(sub):
    """三种都试一遍，返回命中的类型列表（构造失败的也算命中，只记录类型）"""
    hits = []
    for kind, cls in (("minix", Minix), ("jfs", Jfs), ("reiserfs", ReiserFs)):
        try:
            fs = cls(sub)
        except Exception:
            continue
        if kind == "minix":
            hits.append("minix" + fs.version[-1])
        elif kind == "reiserfs":
            hits.append("reiserfs" + fs.version)
        else:
            hits.append("jfs")
    return hits


# ============================================================== 自检

if __name__ == "__main__":
    import sys

    # 控制台可能是 GBK；自检里会打印截断后的非法 UTF-8 名字，需要 replace 兜底
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    class Buf(object):
        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, n):
            if off < 0 or n <= 0 or off >= self.size:
                return b""
            return self.data[off:off + n]

    # ---------------------------------------------------------- Minix
    def build_minix(version, block_size, magic, namelen, dirsize,
                    inode_size, total_blocks):
        """合成最小 Minix：root(1) 目录 + a.txt(2) + 中文目录(3) + 截断名项"""
        img = bytearray(total_blocks * block_size)
        imap_blocks, zmap_blocks = 1, 1
        first_data = 5
        inode_table_block = 2 + imap_blocks + zmap_blocks

        # --- 超级块 @1024 ---
        if version == "v3":
            struct.pack_into("<I", img, 1024 + 0x00, 64)          # s_ninodes
            struct.pack_into("<H", img, 1024 + 0x06, imap_blocks)
            struct.pack_into("<H", img, 1024 + 0x08, zmap_blocks)
            struct.pack_into("<H", img, 1024 + 0x0A, first_data)
            struct.pack_into("<H", img, 1024 + 0x0C, 0)           # log_zone_size
            struct.pack_into("<I", img, 1024 + 0x10, 0x7FFFFFFF)  # s_max_size
            struct.pack_into("<I", img, 1024 + 0x14, total_blocks)  # s_zones
            struct.pack_into("<H", img, 1024 + 0x18, magic)
            struct.pack_into("<H", img, 1024 + 0x1C, block_size)
            img[1024 + 0x1E] = 3                                   # s_disk_version
        else:
            struct.pack_into("<H", img, 1024 + 0x00, 32)          # s_ninodes
            struct.pack_into("<H", img, 1024 + 0x02, total_blocks & 0xFFFF)
            struct.pack_into("<H", img, 1024 + 0x04, imap_blocks)
            struct.pack_into("<H", img, 1024 + 0x06, zmap_blocks)
            struct.pack_into("<H", img, 1024 + 0x08, first_data)
            struct.pack_into("<H", img, 1024 + 0x0A, 0)
            struct.pack_into("<I", img, 1024 + 0x0C, 0x0FFFFFFF)
            struct.pack_into("<H", img, 1024 + 0x10, magic)
            struct.pack_into("<H", img, 1024 + 0x12, 1)           # s_state
            struct.pack_into("<I", img, 1024 + 0x14, total_blocks)

        # --- 位图占位（块 2 = imap，块 3 = zmap）---
        img[2 * block_size + 0] = 0x03        # inode 1,2 已用
        img[3 * block_size + 0] = 0x1F        # 前几个块已用

        def put_inode(ino, mode, size, zones, nlink=1):
            off = inode_table_block * block_size + (ino - 1) * inode_size
            if version == "v1":
                struct.pack_into("<H", img, off + 0, mode)
                struct.pack_into("<H", img, off + 2, 0)          # i_uid
                struct.pack_into("<I", img, off + 4, size)
                struct.pack_into("<I", img, off + 8, 0x60000000)  # i_time
                img[off + 12] = 0                                  # i_gid
                img[off + 13] = nlink & 0xFF                       # i_nlinks
                for i, z in enumerate(zones[:9]):
                    struct.pack_into("<H", img, off + 14 + 2 * i, z)
            else:
                struct.pack_into("<H", img, off + 0, mode)
                struct.pack_into("<H", img, off + 2, nlink)
                struct.pack_into("<H", img, off + 4, 0)          # i_uid
                struct.pack_into("<H", img, off + 6, 0)          # i_gid
                struct.pack_into("<I", img, off + 8, size)
                struct.pack_into("<I", img, off + 12, 0x60000000)
                struct.pack_into("<I", img, off + 16, 0x60000001)
                struct.pack_into("<I", img, off + 20, 0x60000002)
                for i, z in enumerate(zones[:10]):
                    struct.pack_into("<I", img, off + 24 + 4 * i, z)

        def put_dir_block(blk, entries):
            off = blk * block_size
            p = off
            for ei, nm in entries:
                raw = nm.encode("utf-8")[:namelen]
                if version == "v3":
                    struct.pack_into("<I", img, p, ei)
                    img[p + 4:p + 4 + len(raw)] = raw
                else:
                    struct.pack_into("<H", img, p, ei)
                    img[p + 2:p + 2 + len(raw)] = raw
                p += dirsize
            return p - off

        # 目录块：root 在块 5，中文目录在块 7
        CH_DIR = "中文目录"
        TRUNC = "中文名字超长测试"          # 24 B，V1 会截到 14 B
        root_size = put_dir_block(5, [(1, "."), (1, ".."), (2, "a.txt"),
                                      (3, CH_DIR), (2, TRUNC)])
        sub_size = put_dir_block(7, [(3, "."), (1, "..")])

        CONTENT = b"minix payload 01\n"
        img[6 * block_size:6 * block_size + len(CONTENT)] = CONTENT
        put_inode(1, 0o040755, root_size, [5], 2)
        put_inode(2, 0o100644, len(CONTENT), [6], 1)
        put_inode(3, 0o040755, sub_size, [7], 2)
        return bytes(img), CONTENT, CH_DIR, TRUNC

    m1_img, M1_CONTENT, M1_CH, M1_TRUNC = build_minix(
        "v1", 1024, 0x137F, 14, 16, 32, 64)
    fs1 = Minix(Buf(m1_img))
    i1 = fs1.info()
    print("Minix V1: ver=%s bs=%d inodes=%d zones=%d magic=%s namelen=%d itbl=%d"
          % (i1["version"], i1["block_size"], i1["inodes"], i1["zones"],
             i1["magic"], i1["namelen"], i1["inode_table_block"]))
    assert i1["version"] == "v1" and i1["block_size"] == 1024
    assert i1["magic"] == "0x137F" and i1["namelen"] == 14
    assert i1["inode_table_block"] == 4
    ents1 = fs1.listdir()
    names1 = [e.name for e in ents1]
    print("  根目录: %s" % names1)
    assert "." in names1 and ".." in names1 and "a.txt" in names1
    assert M1_CH in names1
    assert fs1.read_file(2) == M1_CONTENT
    assert fs1.read_path("/a.txt") == M1_CONTENT
    # 14 字节截断：raw 必须是原名前 14 字节
    tr = [e for e in ents1 if e.inode == 2 and e.name not in ("a.txt",)][0]
    assert len(tr.raw) == 14, tr.raw
    assert tr.raw == M1_TRUNC.encode("utf-8")[:14]
    print("  截断项 raw=%r（14 B，已按 UTF-8 边界截断，解码含替换符）" % tr.raw)

    m3_img, M3_CONTENT, M3_CH, M3_TRUNC = build_minix(
        "v3", 4096, 0x4D5A, 60, 64, 64, 32)
    fs3 = Minix(Buf(m3_img))
    i3 = fs3.info()
    print("Minix V3: ver=%s bs=%d inodes=%d zones=%d magic=%s namelen=%d"
          % (i3["version"], i3["block_size"], i3["inodes"], i3["zones"],
             i3["magic"], i3["namelen"]))
    assert i3["version"] == "v3" and i3["block_size"] == 4096
    assert i3["magic"] == "0x4D5A" and i3["namelen"] == 60
    assert i3["super_offset"] == 1024
    names3 = [e.name for e in fs3.listdir()]
    print("  根目录: %s" % names3)
    assert M3_CH in names3
    assert M3_TRUNC in names3, names3       # 60 B 名长，24 B 中文名完整保留
    assert fs3.read_file(2) == M3_CONTENT
    assert fs3.lookup_path("/%s" % M3_CH).is_dir
    walked = sorted(dict(fs3.walk()))
    print("  walk: %s" % walked)
    assert walked == sorted(["a.txt", M3_CH, M3_TRUNC])
    child_names = [e.name for e in fs3.listdir(fs3.lookup_path("/" + M3_CH))]
    assert child_names == [".", ".."], child_names
    assert fs3.find("a.txt")

    m2_img, M2_CONTENT, _, _ = build_minix("v2", 1024, 0x2468, 14, 16, 64, 64)
    fs2 = Minix(Buf(m2_img))
    i2 = fs2.info()
    print("Minix V2: ver=%s bs=%d magic=%s inode_size=%d"
          % (i2["version"], i2["block_size"], i2["magic"], i2["inode_size"]))
    assert i2["version"] == "v2" and i2["inode_size"] == 64
    assert fs2.read_file(2) == M2_CONTENT

    # --- 间接块寻址（V1：7 直接 + 1 一级间接）---
    def build_minix_indirect():
        bs = 1024
        img = bytearray(32 * bs)
        struct.pack_into("<H", img, 1024 + 0x00, 32)
        struct.pack_into("<H", img, 1024 + 0x02, 32)
        struct.pack_into("<H", img, 1024 + 0x04, 1)
        struct.pack_into("<H", img, 1024 + 0x06, 1)
        struct.pack_into("<H", img, 1024 + 0x08, 5)
        struct.pack_into("<H", img, 1024 + 0x0A, 0)
        struct.pack_into("<I", img, 1024 + 0x0C, 0x0FFFFFFF)
        struct.pack_into("<H", img, 1024 + 0x10, 0x137F)
        struct.pack_into("<H", img, 1024 + 0x12, 1)
        struct.pack_into("<I", img, 1024 + 0x14, 32)
        content = bytes(range(256)) * 32              # 8192 B = 8 块
        for i in range(7):
            img[(8 + i) * bs:(9 + i) * bs] = content[i * bs:(i + 1) * bs]
        img[16 * bs:17 * bs] = content[7 * bs:8 * bs]
        struct.pack_into("<H", img, 15 * bs, 16)      # 间接块：第 0 项 -> 块 16
        off = 4 * bs                                   # inode 表在块 4
        # inode 1：root 目录（块 5）
        struct.pack_into("<H", img, off + 0, 0o040755)
        struct.pack_into("<I", img, off + 4, 48)
        img[off + 13] = 2
        struct.pack_into("<H", img, off + 14, 5)
        p = 5 * bs
        for ei, nm in ((1, "."), (1, ".."), (2, "big.bin")):
            struct.pack_into("<H", img, p, ei)
            img[p + 2:p + 2 + len(nm)] = nm.encode()
            p += 16
        # inode 2：文件，7 直接 + 1 间接
        off2 = 4 * bs + 32
        struct.pack_into("<H", img, off2 + 0, 0o100644)
        struct.pack_into("<I", img, off2 + 4, len(content))
        img[off2 + 13] = 1
        for i, z in enumerate([8, 9, 10, 11, 12, 13, 14, 15, 0]):
            struct.pack_into("<H", img, off2 + 14 + 2 * i, z)
        return bytes(img), content

    mi_img, MI_CONTENT = build_minix_indirect()
    fsi = Minix(Buf(mi_img))
    assert [e.name for e in fsi.listdir()][-1] == "big.bin"
    got = fsi.read_file(2)
    print("Minix 间接块: inode2 size=%d 读回 %d B，前 8 B=%r"
          % (fsi.inode(2).size, len(got), got[:8]))
    assert len(got) == len(MI_CONTENT)
    assert got == MI_CONTENT, "间接块内容不符"

    # ---------------------------------------------------------- JFS
    def build_jfs():
        BLK = 4096
        NBLK = 64
        img = bytearray(NBLK * BLK)

        def put(off, data):
            img[off:off + len(data)] = data

        def pxd(ln, addr):
            return struct.pack("<II", ln, addr)

        # 超级块
        sb = bytearray(0xB8)
        sb[0:4] = b"JFS1"
        struct.pack_into("<I", sb, 0x04, 2)              # s_version
        struct.pack_into("<Q", sb, 0x08, NBLK)           # s_size
        struct.pack_into("<I", sb, 0x10, BLK)            # s_bsize
        struct.pack_into("<H", sb, 0x14, 12)             # s_l2bsize
        struct.pack_into("<H", sb, 0x16, 3)              # s_l2bfactor
        struct.pack_into("<I", sb, 0x18, 512)            # s_pbsize
        struct.pack_into("<H", sb, 0x1C, 9)              # s_l2pbsize
        struct.pack_into("<I", sb, 0x20, 32)             # s_agsize
        struct.pack_into("<I", sb, 0x24, 0x10000001)     # s_flag = unicode|linux
        struct.pack_into("<I", sb, 0x28, 0)              # s_state = clean
        struct.pack_into("<I", sb, 0x2C, 0)              # s_compress
        sb[0x30:0x38] = pxd(4, 11)                       # s_ait2
        sb[0x38:0x40] = pxd(2, 12)                       # s_aim2
        struct.pack_into("<I", sb, 0x40, 0)              # s_logdev
        sb[0x48:0x50] = pxd(2, 13)                       # s_logpxd
        sb[0x65:0x70] = b"eskjfs\x00\x00\x00\x00\x00"    # s_fpack[11]
        sb[0x88:0x98] = bytes(range(16))                 # s_uuid
        sb[0x98:0xA8] = b"ESKJFS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        put(0x8000, bytes(sb))

        def dinode(ino, mode, size, root_bytes, xt=None, nlink=1):
            d = bytearray(512)
            struct.pack_into("<I", d, 0x00, 0x1234)      # di_inostamp
            struct.pack_into("<I", d, 0x04, 0)           # di_fileset
            struct.pack_into("<I", d, 0x08, ino)         # di_number
            struct.pack_into("<I", d, 0x0C, 1)           # di_gen
            d[0x10:0x18] = pxd(4, 30)                    # di_ixpxd
            struct.pack_into("<Q", d, 0x18, size)
            struct.pack_into("<Q", d, 0x20, 0)
            struct.pack_into("<I", d, 0x28, nlink)       # di_nlink
            struct.pack_into("<I", d, 0x34, mode)        # di_mode
            struct.pack_into("<I", d, 0x38, 0x60000000)  # atime.sec
            struct.pack_into("<I", d, 0x40, 0x60000001)  # ctime.sec
            struct.pack_into("<I", d, 0x48, 0x60000002)  # mtime.sec
            if root_bytes:
                d[0xE0:0xE0 + len(root_bytes)] = root_bytes
            return bytes(d)

        # AIT 页：inode 16（imap）在页 11+2 = 13，槽 0
        imap_root = bytearray(288)
        imap_root[16] = BT_ROOT | BT_LEAF
        struct.pack_into("<H", imap_root, 18, 1)
        imap_root[32 + 3] = 0                            # off1
        struct.pack_into("<I", imap_root, 32 + 4, 0)     # off2
        imap_root[32 + 8:32 + 16] = pxd(2, 20)           # xad: len=2, addr=20
        ait = dinode(16, 0o100600, 2 * 4096, bytes(imap_root))
        put(0xB000 + (16 >> 3) * 4096 + (16 & 7) * 512, ait)

        # iag 页（imap 文件的第 1 页 -> 块 21）
        iag = bytearray(4096)
        struct.pack_into("<Q", iag, 0, 0)                # agstart
        struct.pack_into("<I", iag, 8, 0)                # iagnum
        struct.pack_into("<I", iag, 64, 32)              # nfreeinos
        iag[3072:3080] = pxd(4, 30)                      # inoext[0]
        put(21 * BLK, bytes(iag))

        # 根目录 inode 2：dtroot（内联，288 B）
        dt = bytearray(288)
        dt[0:16] = b"\x00" * 16                          # DASD
        dt[16] = BT_ROOT | BT_LEAF                       # flag
        dt[17] = 3                                       # nextindex
        dt[18] = 6                                       # freecnt
        dt[19] = 0xFF                                    # freelist
        struct.pack_into("<I", dt, 20, 2)                # idotdot
        dt[24:27] = bytes([1, 2, 3])                     # stbl
        names = [(".", 2), ("..", 2), ("a.txt", 4)]
        for i, (nm, ino) in enumerate(names):
            e = 32 + (i + 1) * 32
            struct.pack_into("<I", dt, e, ino)
            dt[e + 4] = 0xFF                             # next = -1
            dt[e + 5] = len(nm)                           # namlen（字符数）
            for j, ch in enumerate(nm):
                struct.pack_into("<H", dt, e + 6 + j * 2, ord(ch))
        put(30 * BLK + 2 * 512, dinode(2, 0o040755, 0, bytes(dt), nlink=2))

        # 文件 inode 4：xtree 根指向块 40
        xt = bytearray(288)
        xt[16] = BT_ROOT | BT_LEAF
        struct.pack_into("<H", xt, 18, 1)
        xt[32 + 3] = 0
        struct.pack_into("<I", xt, 32 + 4, 0)             # xoff = 0
        xt[32 + 8:32 + 16] = pxd(1, 40)                   # len=1, addr=40
        CONTENT = b"jfs payload 01\n"
        put(40 * BLK, CONTENT)
        put(30 * BLK + 4 * 512, dinode(4, 0o100644, len(CONTENT), bytes(xt)))
        return bytes(img), CONTENT

    jfs_img, JFS_CONTENT = build_jfs()
    jf = Jfs(Buf(jfs_img))
    ji = jf.info()
    print("JFS: magic=%s ver=%d bs=%d agsize=%d vol=%r label=%r state=%s flags=%s"
          % (ji["magic"], ji["version"], ji["block_size"], ji["agsize"],
             ji["volume_name"], ji["label"], ji["state"], ji["flags"]))
    assert ji["magic"] == "JFS1" and ji["version"] == 2
    assert ji["block_size"] == 4096 and ji["agsize"] == 32
    assert ji["volume_name"] == "eskjfs" and ji["label"] == "ESKJFS"
    assert ji["state"] == "clean"
    assert "unicode" in ji["flags"] and "linux" in ji["flags"]
    assert ji["ait2"] == {"len": 4, "addr": 11}
    assert ji["uuid"] == bytes(range(16)).hex()

    imap_ip = jf.imap_inode()
    print("  imap inode: ino=%d mode=0o%o size=%d xt=%dB"
          % (imap_ip.ino, imap_ip.mode, imap_ip.size, len(imap_ip.root)))
    assert imap_ip.ino == 16 and imap_ip.is_reg

    root_ip = jf.root()
    print("  根 inode: ino=%d mode=0o%o dir=%s dtroot=%dB"
          % (root_ip.ino, root_ip.mode, root_ip.is_dir, len(root_ip.root)))
    assert root_ip.is_dir
    jents = jf.listdir()
    print("  根目录: %s" % [(e.name, e.inode) for e in jents])
    assert [e.name for e in jents] == [".", "..", "a.txt"]
    f_ip = jf.inode(4)
    assert f_ip.size == len(JFS_CONTENT)
    data = jf.read_file(f_ip)
    print("  a.txt: size=%d 读回 %r" % (f_ip.size, data))
    assert data == JFS_CONTENT, data
    assert jf.read_path("/a.txt") == JFS_CONTENT
    assert jf.lookup_path("/a.txt").ino == 4
    assert jf.find("a.txt")
    assert jf.ait_inode(16).ino == 16

    # 压缩卷：读文件应明确拒绝，而不是返回错数据
    compr = bytearray(jfs_img)
    struct.pack_into("<I", compr, 0x8000 + 0x2C, 1)
    jc = Jfs(Buf(bytes(compr)))
    try:
        jc.read_file(4)
        raise AssertionError("压缩卷读文件应抛 NotImplementedError")
    except NotImplementedError as e:
        print("  JFS 压缩卷 -> NotImplementedError: %s" % e)

    # 截断输入
    try:
        Jfs(Buf(b"\x00" * 0x8000))
        raise AssertionError("JFS 应当拒绝无 magic 的镜像")
    except ValueError as e:
        print("  JFS 截断/无 magic -> ValueError: %s" % e)

    # ------------------------------------------------------ ReiserFS
    def build_reiserfs():
        BLK = 4096
        NBLK = 64
        img = bytearray(NBLK * BLK)

        sb = bytearray(0xCC)
        struct.pack_into("<I", sb, 0x00, NBLK)             # s_block_count
        struct.pack_into("<I", sb, 0x04, NBLK - 8)         # s_free_blocks
        struct.pack_into("<I", sb, 0x08, 20)               # s_root_block
        struct.pack_into("<I", sb, 0x0C, 8)                # journal 1st block
        struct.pack_into("<I", sb, 0x14, 16)               # journal size
        struct.pack_into("<H", sb, 0x2C, BLK)              # s_blocksize
        struct.pack_into("<H", sb, 0x32, 1)                # s_umount_state
        sb[0x34:0x3E] = b"ReIsEr2Fs\x00"
        struct.pack_into("<H", sb, 0x3E, 0)                # s_fs_state
        struct.pack_into("<I", sb, 0x40, 3)                # hash = r5
        struct.pack_into("<H", sb, 0x44, 2)                # tree_height
        struct.pack_into("<H", sb, 0x46, 1)                # bmap_nr
        struct.pack_into("<H", sb, 0x48, 2)                # s_version
        sb[0x54:0x64] = bytes(range(16))
        sb[0x64:0x74] = b"ESKREISER\x00\x00\x00\x00\x00\x00\x00"
        img[0x10000:0x10000 + len(sb)] = bytes(sb)

        def key(dir_id, objid, offset, itype, version=KEY_FORMAT_3_6):
            k = bytearray(16)
            struct.pack_into("<I", k, 0, dir_id)
            struct.pack_into("<I", k, 4, objid)
            if version == KEY_FORMAT_3_5:
                struct.pack_into("<I", k, 8, offset)
                uniq = {0: 0, 1: 0xFFFFFFFE, 2: 0xFFFFFFFF, 3: 500}[itype]
                struct.pack_into("<I", k, 12, uniq)
            else:
                struct.pack_into("<Q", k, 8, (itype << 60) | (offset & ((1 << 60) - 1)))
            return bytes(k)

        def sd_v2(mode, nlink, size):
            b = bytearray(44)
            struct.pack_into("<H", b, 0, mode)
            struct.pack_into("<H", b, 2, 0)                 # attrs
            struct.pack_into("<I", b, 4, nlink)
            struct.pack_into("<Q", b, 8, size)
            struct.pack_into("<I", b, 24, 0x60000000)       # atime
            struct.pack_into("<I", b, 28, 0x60000001)       # mtime
            struct.pack_into("<I", b, 32, 0x60000002)       # ctime
            return bytes(b)

        def dir_item(entries):
            n = len(entries)
            body = bytearray(DEH_SIZE * n)
            pos = DEH_SIZE * n
            for i, (nm, ino) in enumerate(entries):
                raw = nm.encode("utf-8")
                struct.pack_into("<I", body, i * 16 + 0, 0x1000 + i)
                struct.pack_into("<I", body, i * 16 + 4, 1)      # deh_dir_id
                struct.pack_into("<I", body, i * 16 + 8, ino)    # deh_objectid
                struct.pack_into("<H", body, i * 16 + 12, pos)   # deh_location
                struct.pack_into("<H", body, i * 16 + 14, DEH_VISIBLE)
                if i + 1 < n:
                    body += raw + b"\x00"
                    pos += len(raw) + 1
                else:
                    body += raw
            return bytes(body)

        def leaf(blk, items):
            """items: [(key, version, entry_count, body)]，body 从块尾倒着放"""
            node = bytearray(BLK)
            struct.pack_into("<H", node, 0, DISK_LEAF_NODE_LEVEL)
            struct.pack_into("<H", node, 2, len(items))
            body_end = BLK
            for i, (k, ver, ecount, body) in enumerate(items):
                o = BLKH_SIZE + i * IH_SIZE
                node[o:o + 16] = k
                struct.pack_into("<H", node, o + 16, ecount)
                struct.pack_into("<H", node, o + 18, len(body))
                struct.pack_into("<H", node, o + 20, body_end - len(body))
                struct.pack_into("<H", node, o + 22, ver)
                body_end -= len(body)
                node[body_end:body_end + len(body)] = body
            struct.pack_into("<H", node, 4, body_end - BLKH_SIZE - len(items) * IH_SIZE)
            img[blk * BLK:(blk + 1) * BLK] = bytes(node)

        def internal(blk, level, keys, children):
            node = bytearray(BLK)
            struct.pack_into("<H", node, 0, level)
            struct.pack_into("<H", node, 2, len(keys))
            for i, k in enumerate(keys):
                o = BLKH_SIZE + i * KEY_SIZE
                node[o:o + KEY_SIZE] = k
            dc = BLKH_SIZE + len(keys) * KEY_SIZE
            for i, c in enumerate(children):
                struct.pack_into("<I", node, dc + i * DC_SIZE, c)
                struct.pack_into("<H", node, dc + i * DC_SIZE + 4, 4096)
            img[blk * BLK:(blk + 1) * BLK] = bytes(node)

        CONTENT = b"reiserfs payload 01\n"
        leaf(21, [
            (key(1, 2, 0, TYPE_STAT_DATA), KEY_FORMAT_3_6, 0, sd_v2(0o040755, 2, 64)),
            (key(1, 2, 0x1234, TYPE_DIRENTRY), KEY_FORMAT_3_6, 3,
             dir_item([(".", 2), ("..", 2), ("a.txt", 3)])),
            (key(1, 3, 0, TYPE_STAT_DATA), KEY_FORMAT_3_6, 0,
             sd_v2(0o100644, 1, len(CONTENT))),
            (key(1, 3, 0, TYPE_DIRECT), KEY_FORMAT_3_6, 0, CONTENT),
        ])
        leaf(22, [(key(1, 9, 0, TYPE_STAT_DATA), KEY_FORMAT_3_6, 0,
                   sd_v2(0o100600, 1, 0))])
        internal(20, 2, [key(1, 2, 0, TYPE_STAT_DATA)], [21, 22])
        return bytes(img), CONTENT

    r_img, R_CONTENT = build_reiserfs()
    rf = ReiserFs(Buf(r_img))
    ri = rf.info()
    print("ReiserFS: ver=%s magic=%s bs=%d blocks=%d root=%d height=%d hash=%s label=%r"
          % (ri["version"], ri["magic"], ri["block_size"], ri["block_count"],
             ri["root_block"], ri["tree_height"], ri["hash"], ri["label"]))
    assert ri["magic"] == "ReIsEr2Fs" and ri["version"] == "3.6"
    assert ri["block_size"] == 4096 and ri["block_count"] == 64
    assert ri["root_block"] == 20 and ri["tree_height"] == 2
    assert ri["hash"] == "r5" and ri["label"] == "ESKREISER"
    assert ri["leaf_nodes"] == 2
    rroot = rf.root()
    print("  根对象: ino=%d mode=0o%o dir=%s" % (rroot.ino, rroot.mode, rroot.is_dir))
    assert rroot.is_dir and rroot.ino == REISER_ROOT_OBJECTID
    rents = rf.listdir()
    print("  根目录: %s" % [(e.name, e.inode) for e in rents])
    assert [e.name for e in rents] == [".", "..", "a.txt"]
    rdata = rf.read_file(3)
    print("  a.txt: size=%d 读回 %r" % (rf.inode(3).size, rdata))
    assert rdata == R_CONTENT, rdata
    assert rf.read_path("/a.txt") == R_CONTENT
    assert rf.lookup_path("/a.txt").ino == 3
    assert rf.find("a.txt")

    # --- ReiserFS 3.5 key 格式 + indirect item ---
    def build_reiserfs35():
        BLK = 4096
        NBLK = 64
        img2 = bytearray(NBLK * BLK)
        sb = bytearray(0xCC)
        struct.pack_into("<I", sb, 0x00, NBLK)
        struct.pack_into("<I", sb, 0x08, 20)
        struct.pack_into("<H", sb, 0x2C, BLK)
        struct.pack_into("<H", sb, 0x32, 1)
        sb[0x34:0x3E] = b"ReIsErFs\x00\x00"
        struct.pack_into("<I", sb, 0x40, 1)            # hash = tea
        struct.pack_into("<H", sb, 0x44, 2)            # tree_height
        struct.pack_into("<H", sb, 0x46, 1)
        struct.pack_into("<H", sb, 0x48, 0)            # 3.5
        sb[0x64:0x74] = b"ESK35\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        img2[0x10000:0x10000 + len(sb)] = bytes(sb)

        def key35(dir_id, objid, offset, uniq):
            k = bytearray(16)
            struct.pack_into("<I", k, 0, dir_id)
            struct.pack_into("<I", k, 4, objid)
            struct.pack_into("<I", k, 8, offset)
            struct.pack_into("<I", k, 12, uniq)
            return bytes(k)

        def sd1(mode, nlink, size):
            b = bytearray(32)
            struct.pack_into("<H", b, 0, mode)
            struct.pack_into("<H", b, 2, nlink)
            struct.pack_into("<I", b, 8, size)
            return bytes(b)

        def leaf(blk, items):
            node = bytearray(BLK)
            struct.pack_into("<H", node, 0, DISK_LEAF_NODE_LEVEL)
            struct.pack_into("<H", node, 2, len(items))
            end = BLK
            for i, (k, ver, cnt, body) in enumerate(items):
                o = BLKH_SIZE + i * IH_SIZE
                node[o:o + 16] = k
                struct.pack_into("<H", node, o + 16, cnt)
                struct.pack_into("<H", node, o + 18, len(body))
                struct.pack_into("<H", node, o + 20, end - len(body))
                struct.pack_into("<H", node, o + 22, ver)
                end -= len(body)
                node[end:end + len(body)] = body
            img2[blk * BLK:(blk + 1) * BLK] = bytes(node)

        def internal(blk, level, keys, children):
            node = bytearray(BLK)
            struct.pack_into("<H", node, 0, level)
            struct.pack_into("<H", node, 2, len(keys))
            for i, k in enumerate(keys):
                o = BLKH_SIZE + i * KEY_SIZE
                node[o:o + KEY_SIZE] = k
            dc = BLKH_SIZE + len(keys) * KEY_SIZE
            for i, c in enumerate(children):
                struct.pack_into("<I", node, dc + i * DC_SIZE, c)
                struct.pack_into("<H", node, dc + i * DC_SIZE + 4, 4096)
            img2[blk * BLK:(blk + 1) * BLK] = bytes(node)

        def dir_body(entries):
            n = len(entries)
            body = bytearray(DEH_SIZE * n)
            pos = DEH_SIZE * n
            for i, (nm, ino) in enumerate(entries):
                raw = nm.encode("utf-8")
                struct.pack_into("<I", body, i * 16, 0x2000 + i)
                struct.pack_into("<I", body, i * 16 + 4, 1)
                struct.pack_into("<I", body, i * 16 + 8, ino)
                struct.pack_into("<H", body, i * 16 + 12, pos)
                struct.pack_into("<H", body, i * 16 + 14, DEH_VISIBLE)
                if i + 1 < n:
                    body += raw + b"\x00"
                    pos += len(raw) + 1
                else:
                    body += raw
            return bytes(body)

        tail = b"tail-direct\n"
        img2[30 * BLK:31 * BLK] = b"B" * BLK
        ptr = struct.pack("<I", 30)
        leaf(21, [
            (key35(1, 2, 0, 0), KEY_FORMAT_3_5, 0, sd1(0o040755, 2, 64)),
            (key35(1, 2, 0x4321, 500), KEY_FORMAT_3_5, 2,
             dir_body([(".", 2), ("old.txt", 3)])),
            (key35(1, 3, 0, 0), KEY_FORMAT_3_5, 0,
             sd1(0o100644, 1, BLK + len(tail))),
            (key35(1, 3, 0, 0xFFFFFFFE), KEY_FORMAT_3_5, 0, ptr),
            (key35(1, 3, BLK, 0xFFFFFFFF), KEY_FORMAT_3_5, 0, tail),
        ])
        leaf(22, [(key35(1, 9, 0, 0), KEY_FORMAT_3_5, 0, sd1(0o100600, 1, 0))])
        internal(20, 2, [key35(1, 2, 0, 0)], [21, 22])
        return bytes(img2), b"B" * BLK + tail

    r35_img, R35_CONTENT = build_reiserfs35()
    rf35 = ReiserFs(Buf(r35_img))
    i35 = rf35.info()
    print("ReiserFS 3.5: magic=%s bs=%d height=%d hash=%s label=%r sb_version=%d"
          % (i35["magic"], i35["block_size"], i35["tree_height"],
             i35["hash"], i35["label"], i35["sb_version"]))
    assert i35["version"] == "3.5" and i35["magic"] == "ReIsErFs"
    assert i35["sb_version"] == 0 and i35["hash"] == "tea"
    assert [e.name for e in rf35.listdir()] == [".", "old.txt"]
    got35 = rf35.read_file(3)
    print("  old.txt: size=%d 读回 %d B，尾部=%r"
          % (rf35.inode(3).size, len(got35), got35[-14:]))
    assert got35 == R35_CONTENT, "3.5 indirect + direct 内容不符"
    assert probe(Buf(r35_img)) == "reiserfs3.5"

    # ------------------------------------------------------ 互不误判
    print("probe: minix1=%s minix2=%s minix3=%s jfs=%s reiserfs=%s unknown=%s"
          % (probe(Buf(m1_img)), probe(Buf(m2_img)), probe(Buf(m3_img)),
             probe(Buf(jfs_img)), probe(Buf(r_img)),
             probe(Buf(b"\x00" * 4096))))
    assert probe(Buf(m1_img)) == "minix1"
    assert probe(Buf(m2_img)) == "minix2"
    assert probe(Buf(m3_img)) == "minix3"
    assert probe(Buf(jfs_img)) == "jfs"
    assert probe(Buf(r_img)) == "reiserfs3.6"
    assert probe(Buf(b"\x00" * 4096)) == "unknown"
    assert probe(Buf(b"\x55" * 100)) == "unknown"

    print("detect_all(minix1)=%s" % detect_all(Buf(m1_img)))
    print("detect_all(jfs)=%s" % detect_all(Buf(jfs_img)))
    print("detect_all(reiser)=%s" % detect_all(Buf(r_img)))
    assert detect_all(Buf(m3_img)) == ["minix3"]
    assert detect_all(Buf(jfs_img)) == ["jfs"]
    assert detect_all(Buf(r_img)) == ["reiserfs3.6"]

    fs = open_fs(Buf(jfs_img))
    assert isinstance(fs, Jfs)
    fs = open_fs(Buf(m3_img))
    assert isinstance(fs, Minix)
    fs = open_fs(Buf(r_img))
    assert isinstance(fs, ReiserFs)

    # ------------------------------------------------------ 异常路径
    try:
        Minix(Buf(b"\x00" * 8192))
        raise AssertionError("Minix 应当拒绝无超级块的镜像")
    except ValueError as e:
        print("Minix 空镜像 -> ValueError: %s" % e)
    try:
        ReiserFs(Buf(b"\x00" * 0x10000))
        raise AssertionError("ReiserFS 应当拒绝无超级块的镜像")
    except ValueError as e:
        print("ReiserFS 空镜像 -> ValueError: %s" % e)
    try:
        open_fs(Buf(b"\xEE" * 262144))
        raise AssertionError("open_fs 应当拒绝未知格式")
    except ValueError as e:
        print("open_fs 未知格式 -> ValueError: %s" % e)
    # 目录读文件返回 None（三种实现一致）
    assert fs3.read_file(1) is None
    assert jf.read_file(2) is None
    assert rf.read_file(2) is None
    print("三种格式的目录 read_file 均返回 None")

    print("自检通过")
