# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""JFFS2 与 YAFFS1 / YAFFS2 裸 NAND 闪存文件系统

格式依据：
    · Linux `include/uapi/linux/jffs2.h`（节点类型、压缩算法、raw 结构）
    · Linux `fs/jffs2/nodelist.h`（`jffs2_raw_dirent` / `jffs2_raw_inode` 字段顺序）
    · Linux `fs/jffs2/write.c` + `fs/jffs2/readinode.c`（三种 CRC 的**实际覆盖范围**）
    · Aleph One `yaffs2/core/yaffs_guts.h`（`yaffs_obj_hdr` 落盘布局）
    · Aleph One `yaffs2/core/yaffs_packedtags1.h` / `yaffs_packedtags2.h`（tags 位域）
    · Aleph One `yaffs2/core/yaffs_tagsmarshall.c`（tags 在 OOB 中的位置）

已实现：
    JFFS2
        · 全镜像扫描：4 字节对齐、按 totlen 前进、0xFF 空闲区跳过
        · 通用头 hdr_crc 必须先通过才算节点（0x1985 单独出现不算）
        · 节点类型识别：dirent / inode / cleanmarker / padding / summary / xattr / xref
          并兼容「obsolete 节点」（ACCURATE 位 0x2000 被清零）仍列入取证结果
        · node_crc / name_crc 双覆盖范围校验（内核范围 + 变体范围）
        · 压缩：NONE / ZERO / COPY / ZLIB；RTIME / RUBINMIPS / DYNRUBIN / LZO 抛
          NotImplementedError
        · 多版本日志重建：同一 inode 按 (ino, version) 归并，数据按 offset 叠加，
          最终长度取最新版本的 isize（等价于 truncate 语义）
        · dirent 按 (pino, name) 取最大 version；ino==0 视为删除（unlink）
        · 目录树、递归遍历、按路径查找、按名字查找
        · 版本历史：`versions(ino)` 返回 [(version, 节点偏移, 数据长度)]
        · erase size 推断：cleanmarker 间距的 GCD，失败回落到 64 KiB
        · 取证摘要 info()：节点总数/分类型计数/四类 CRC 失败数/erase size

    YAFFS2
        · 几何自动判定（page+spare）：2048+64 / 512+16 / 4096+128 / 4096+224 /
          2048+128 / 1024+32 / 512+8 全试，用 tags 合理性打分
        · tags2 解析：seqNumber / objectId / chunkId / byteCount（小端 4×u32）
        · OOB 里 tags 起点尝试 0 与 2（2 字节坏块标记前置的厂商布局）
        · pageGuard：spare[20:24] 的 u32 0xFFFFFFFF 页尾哨兵，作为几何判定加分项，
          并在 info() 里统计一致性
        · 对象头 `yaffs_obj_hdr` 四种候选布局自动识别（见下「关键格式点」）
        · 对象类型：file / symlink / dir / hardlink / special
        · 数据块按 chunkId 归并、按 seqNumber 取最新，fileSize 截断
        · 目录树、递归遍历、按路径查找、读文件、读软链
        · 删除取证：`deleted()` 列出被覆盖的旧版块、YAFFS1 deleted 位为 1 的块、
          以及 objectId 3/4（unlinked / deleted 命名空间）的对象

    YAFFS1
        · tags1 解析：8 字节位域（chunk_id:20 / serial:2 / n_bytes:10 /
          obj_id:18 / ecc:12 / deleted:1 / unused:1），与 `yaffs_packed_tags1.h` 一致
        · 对象头、数据块、fileSize 截断、deleted 位取证（deleted=1 的块不进活文件）
        · 通过 page_size（512）判定版本（YAFFS1 页小、无 seqNumber）
        · 老版对象头布局（u8 type）由候选打分自动识别，见下面第 6 条
        · `Yaffs(sub, parent_off=...)` 可手工指定父指针偏移，覆盖自动判定

不实现（原因随附）：
    · JFFS2 压缩 RTIME(2) / RUBINMIPS(3) / DYNRUBIN(5) / LZO(7)
        RTIME 是 JFFS2 自带的 8 位滑动窗口行程编码，RUBINMIPS 是 MIPS 汇编版的
        Rubin 解压器，二者都不是标准算法且无 stdlib 实现；LZO 需要 lzo1x 解压器，
        Python stdlib 没有。遇到即抛 NotImplementedError，绝不静默返回空数据。
    · JFFS2 summary 节点的加速索引
        summary 只是挂载加速，跳过它不影响重建结果；这里仅统计其数量。
    · JFFS2 xattr / xref 的语义合并（ACL、security.* 等）
        节点会被识别、计数、可列出，但不参与目录树与文件内容重建。
    · JFFS2 写操作 / GC / 磨损均衡模拟——纯只读取证。
    · YAFFS tags 的 ECC 校验（yaffs_ECCOther / PackedTags1 的 ecc:12 位）
        那是 Aleph One 私有的列/行奇偶方案（非 BCH、非标准 CRC），需要按
        yaffs_ecc.c 逐位复刻；本轮以「tags 字段合理性」替代，不声称校验通过。
    · YAFFS 老版（u8 type）对象头里 parentObjectId 的确切偏移
        老版 `yaffs_ObjectHeader` 有多代变体，parentObjectId 有时在头部、有时在
        variant 联合体里，没有单一权威偏移。本实现用 5 种候选布局打分自动识别；
        若选中的候选不含 parent 字段且未给 `parent_off=`，`listdir()` / `walk()` /
        `lookup_path()` 抛 NotImplementedError 并提示指定偏移，`objects()` /
        `read_file()` / `deleted()` 仍然可用。不猜、不返回空列表。
    · YAFFS inband tags（tags 塞进 data 区尾部，无 spare）——无 OOB 时无法定位。
    · YAFFS checkpoint / summary 对象（objectId 0x10 / 0x20）——只计数不解析。
    · 任何写操作。

关键格式点（与常见资料不一致处，均以源码为准并在此记录）：
    1. `jffs2_raw_dirent` 是 **pino 在前、ino 在后**：
           pino@0x0C  version@0x10  ino@0x14  mctime@0x18
           nsize@0x1C  type@0x1D  unused[2]@0x1E
           node_crc@0x20  name_crc@0x24  name@0x28
       头部 40 字节、名字从 0x28 开始。网上流传的「ino@0x0C / pino@0x14 /
       namelen@0x18 / name@0x24」是错的，与 `nodelist.h` 对不上。
    2. `node_crc` 的覆盖范围**不是**从 0x0C 开始。内核里是
           crc32(0, node, sizeof(*node) - 8)
       即 inode 覆盖 0x00..0x3B（60 字节，含 12 字节通用头，不含 data_crc 与
       node_crc 自身），dirent 覆盖 0x00..0x1F（32 字节）。因为 hdr_crc 先写、
       node_crc 后算，所以 node_crc 事实上把 hdr_crc 也覆盖进去了。
       本实现先按内核范围校验，失败再按「0x0C 起」的变体范围复核，两者都失败才
       计入 crc_fail，避免误杀第三方 mkfs 产物。
    3. `hdr_crc` 覆盖 0x00..0x07（`sizeof(jffs2_unknown_node) - 4`）。
    4. `data_crc` 覆盖压缩后的 csize 字节，即 `totlen - 68`。
    5. 压缩编号：0=NONE 1=ZERO 2=RTIME 3=RUBINMIPS 4=COPY 5=DYNRUBIN 6=ZLIB
       7=LZO。常见资料把 7 写成 RUBINMIPS 是错的，7 是 LZO。
    6. `yaffs_obj_hdr` 的落盘布局在 2011 年前后变过，本实现按候选表自动识别：
           yaffs2        : u32 type@0, parent@4, u16 sum@8, name@10，
                           自然对齐（name 后补 2 字节），mode@268，fileSizeLow@292，
                           fileSizeHigh@496，shadows@504，isShrink@508，共 512 字节
           yaffs2-packed : 同上但 packed，name@10，mode@266，整体前移 2 字节
           legacy-u8-p8  : u8 type@0, u32 parent@4, name@8, mode@264
           legacy-u8     : u8 type@0, name@2, mode@260（无 parent 字段）
           legacy-u8-shd : u8 type@0, isShadowed@2, name@3, mode@260（无 parent）
       识别打分依据：type∈1..5、name 以 NUL 结尾且字节可解码、mode 的 S_IFMT
       与 type 自洽、时间戳落在 1970..2100、parent 落在已知 objectId 范围。
       现代布局自然对齐后正好 512 字节，这与「对象头占用 chunk 的前 512 字节」吻合。
       候选都不含 parent 时可用 `parent_off=` 手工指定偏移。
    7. YAFFS 的 chunkId 是**对象内**的块序号（0=对象头，1..n=数据块），
       不是物理块号；物理位置由扫描偏移决定。
    8. YAFFS1 的 tags1 没有 seqNumber，覆盖顺序只能按物理先后（后写的赢）；
       YAFFS2 才有 seqNumber，同 (objectId, chunkId) 取 seq 最大者。
"""

import struct
import zlib
from math import gcd

__all__ = [
    "Jffs2", "Jffs2Node", "Jffs2Entry", "Yaffs", "YaffsObject",
    "probe", "open_fs",
    "JFFS2_MAGIC_BITMASK", "JFFS2_NODETYPE_DIRENT", "JFFS2_NODETYPE_INODE",
    "JFFS2_NODETYPE_CLEANMARKER", "JFFS2_NODETYPE_PADDING",
    "JFFS2_NODETYPE_SUMMARY", "JFFS2_NODETYPE_XATTR", "JFFS2_NODETYPE_XREF",
    "JFFS2_COMPR_NONE", "JFFS2_COMPR_ZERO", "JFFS2_COMPR_RTIME",
    "JFFS2_COMPR_RUBINMIPS", "JFFS2_COMPR_COPY", "JFFS2_COMPR_DYNRUBIN",
    "JFFS2_COMPR_ZLIB", "JFFS2_COMPR_LZO",
    "COMPR_NAME", "NODETYPE_NAME", "crc32_jffs2",
    "YAFFS_OBJ_TYPE_NAME", "YAFFS_OBJECTID_ROOT", "YAFFS_OBJECTID_LOSTNFOUND",
    "YAFFS_OBJECTID_UNLINKED", "YAFFS_OBJECTID_DELETED",
    "detect_geometry", "parse_tags2", "parse_tags1",
]

# ============================================================
#  通用：窗口缓存读取器 / CRC
# ============================================================

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000


def _a4(n):
    """向上对齐到 4 字节"""
    return (n + 3) & ~3


def _sub_size(sub):
    """取镜像长度；sub 没有 size 时用 read() 二分探测"""
    try:
        n = int(getattr(sub, "size", 0))
    except (TypeError, ValueError):
        n = 0
    if n > 0:
        return n
    lo, hi = 0, 1 << 12
    while hi < (1 << 31) and sub.read(hi - 1, 1):
        lo = hi
        hi <<= 1
    if hi >= (1 << 31):
        return lo
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if sub.read(mid - 1, 1):
            lo = mid
        else:
            hi = mid
    return lo


class _Win(object):
    """带窗口缓存的只读访问器，只依赖 sub.read(offset, size) 与 sub.size"""

    __slots__ = ("sub", "size", "win", "_base", "_buf")

    def __init__(self, sub, win=1 << 18):
        self.sub = sub
        self.size = _sub_size(sub)
        self.win = win
        self._base = 0
        self._buf = b""

    def read(self, off, n):
        if off < 0 or n <= 0 or off >= self.size:
            return b""
        if n >= self.win:
            return self.sub.read(off, n)
        end = off + n
        base, buf = self._base, self._buf
        if off >= base and end <= base + len(buf):
            s = off - base
            return buf[s:s + n]
        base = (off // self.win) * self.win
        buf = self.sub.read(base, self.win)
        self._base, self._buf = base, buf
        s = off - base
        if s >= 0 and s + n <= len(buf):
            return buf[s:s + n]
        return self.sub.read(off, n)


def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        t.append(c)
    return t


_CRC_T = _crc_table()


def _crc32_reflect(data, crc=0):
    """纯 Python 反射 CRC32（poly 0xEDB88320），init=crc，无最终取反 —— 与
    内核 crc32_le 语义一致"""
    c = crc & 0xFFFFFFFF
    t = _CRC_T
    for b in data:
        c = t[(c ^ b) & 0xFF] ^ (c >> 8)
    return c & 0xFFFFFFFF


def crc32_jffs2(data):
    """JFFS2 用的 CRC32 = 内核 crc32(0, data, len)

    等价于 zlib 里 `zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF`
    （空输入返回 0，与内核一致）。
    """
    if not data:
        return 0
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


# ============================================================
#  JFFS2
# ============================================================

JFFS2_OLD_MAGIC_BITMASK = 0x1984
JFFS2_MAGIC_BITMASK = 0x1985
JFFS2_EMPTY_BITMASK = 0xFFFF
JFFS2_SUM_MAGIC = 0x02851885
JFFS2_MAX_NAME_LEN = 254

JFFS2_FEATURE_INCOMPAT = 0xC000
JFFS2_FEATURE_ROCOMPAT = 0x8000
JFFS2_FEATURE_RWCOMPAT_COPY = 0x4000
JFFS2_FEATURE_RWCOMPAT_DELETE = 0x0000
JFFS2_NODE_ACCURATE = 0x2000

JFFS2_NODETYPE_DIRENT = 0xE001
JFFS2_NODETYPE_INODE = 0xE002
JFFS2_NODETYPE_CLEANMARKER = 0x2003
JFFS2_NODETYPE_PADDING = 0x2004
JFFS2_NODETYPE_SUMMARY = 0x2006
JFFS2_NODETYPE_XATTR = 0xE008
JFFS2_NODETYPE_XREF = 0xE009

NODETYPE_NAME = {
    JFFS2_NODETYPE_DIRENT: "dirent",
    JFFS2_NODETYPE_INODE: "inode",
    JFFS2_NODETYPE_CLEANMARKER: "cleanmarker",
    JFFS2_NODETYPE_PADDING: "padding",
    JFFS2_NODETYPE_SUMMARY: "summary",
    JFFS2_NODETYPE_XATTR: "xattr",
    JFFS2_NODETYPE_XREF: "xref",
}

JFFS2_COMPR_NONE = 0x00
JFFS2_COMPR_ZERO = 0x01
JFFS2_COMPR_RTIME = 0x02
JFFS2_COMPR_RUBINMIPS = 0x03
JFFS2_COMPR_COPY = 0x04
JFFS2_COMPR_DYNRUBIN = 0x05
JFFS2_COMPR_ZLIB = 0x06
JFFS2_COMPR_LZO = 0x07

COMPR_NAME = {
    JFFS2_COMPR_NONE: "none",
    JFFS2_COMPR_ZERO: "zero",
    JFFS2_COMPR_RTIME: "rtime",
    JFFS2_COMPR_RUBINMIPS: "rubinmips",
    JFFS2_COMPR_COPY: "copy",
    JFFS2_COMPR_DYNRUBIN: "dynrubin",
    JFFS2_COMPR_ZLIB: "zlib",
    JFFS2_COMPR_LZO: "lzo",
}

JFFS2_HDR_LEN = 12          # jffs2_unknown_node
JFFS2_INODE_HDR_LEN = 68    # jffs2_raw_inode
JFFS2_DIRENT_HDR_LEN = 40   # jffs2_raw_dirent

# node_crc 的内核覆盖长度 = sizeof(struct) - 8
INODE_NODE_CRC_LEN = JFFS2_INODE_HDR_LEN - 8      # 60
DIRENT_NODE_CRC_LEN = JFFS2_DIRENT_HDR_LEN - 8    # 32

# DT_* 类型（dirent->type == (mode & S_IFMT) >> 12）
DT_NAMES = {
    0: "unknown", 1: "fifo", 2: "chr", 4: "dir", 6: "blk", 8: "reg",
    10: "lnk", 12: "sock", 14: "wht",
}

class Jffs2Node(object):
    """一个 JFFS2 原始节点（inode / dirent / cleanmarker / padding / ...）"""

    __slots__ = (
        "offset", "magic", "nodetype", "totlen", "hdr_crc", "kind", "accurate",
        # inode 字段
        "ino", "version", "mode", "uid", "gid", "isize",
        "atime", "mtime", "ctime", "file_offset", "csize", "dsize",
        "compr", "usercompr", "flags", "data_crc", "node_crc", "data_off",
        # dirent 字段
        "pino", "mctime", "nsize", "dtype", "name", "name_crc",
        "crc_hdr", "crc_node", "crc_name", "crc_data",
    )

    def __init__(self):
        for k in self.__slots__:
            setattr(self, k, 0)
        self.kind = "?"
        self.name = b""
        self.crc_hdr = True
        self.crc_node = "unknown"
        self.crc_name = None
        self.crc_data = None

    @property
    def compr_name(self):
        return COMPR_NAME.get(self.compr, "?%d" % self.compr)

    @property
    def is_dir(self):
        return (self.mode & S_IFMT) == S_IFDIR

    @property
    def is_file(self):
        return (self.mode & S_IFMT) == S_IFREG

    @property
    def is_symlink(self):
        return (self.mode & S_IFMT) == S_IFLNK

    def as_dict(self):
        d = {
            "offset": self.offset, "nodetype": "0x%04X" % self.nodetype,
            "kind": self.kind, "totlen": self.totlen, "accurate": self.accurate,
            "crc_node": self.crc_node,
        }
        if self.kind == "inode":
            d.update({
                "ino": self.ino, "version": self.version,
                "mode": "0o%o" % self.mode, "uid": self.uid, "gid": self.gid,
                "isize": self.isize, "file_offset": self.file_offset,
                "csize": self.csize, "dsize": self.dsize,
                "compr": self.compr_name,
            })
        elif self.kind == "dirent":
            d.update({
                "pino": self.pino, "ino": self.ino, "version": self.version,
                "name": self.name.decode("utf-8", "replace"),
                "dtype": DT_NAMES.get(self.dtype, "?%d" % self.dtype),
            })
        return d

    def __repr__(self):
        if self.kind == "inode":
            return "<Jffs2Node inode@0x%X ino=%d v%d off=%d %dB %s>" % (
                self.offset, self.ino, self.version, self.file_offset,
                self.dsize, self.compr_name)
        if self.kind == "dirent":
            return "<Jffs2Node dirent@0x%X pino=%d %r -> %d v%d>" % (
                self.offset, self.pino, self.name.decode("utf-8", "replace"),
                self.ino, self.version)
        return "<Jffs2Node %s@0x%X len=%d>" % (self.kind, self.offset, self.totlen)


class Jffs2Entry(object):
    """目录项（dirent 最新版本 + 对应 inode 最新版本）"""

    __slots__ = ("name", "pino", "ino", "dtype", "version", "node_off",
                 "mode", "uid", "gid", "size", "atime", "mtime", "ctime",
                 "target")

    def __init__(self):
        self.name = ""
        self.pino = 0
        self.ino = 0
        self.dtype = 0
        self.version = 0
        self.node_off = 0
        self.mode = 0
        self.uid = 0
        self.gid = 0
        self.size = 0
        self.atime = 0
        self.mtime = 0
        self.ctime = 0
        self.target = None

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
    def type_name(self):
        mt = self.mode & S_IFMT
        if mt == S_IFDIR:
            return "dir"
        if mt == S_IFREG:
            return "file"
        if mt == S_IFLNK:
            return "link"
        return DT_NAMES.get(self.dtype, "mode0o%o" % mt)

    def as_dict(self):
        return {
            "name": self.name, "ino": self.ino, "pino": self.pino,
            "type": self.type_name, "mode": "0o%o" % self.mode,
            "uid": self.uid, "gid": self.gid, "size": self.size,
            "mtime": self.mtime, "version": self.version,
            "node_offset": self.node_off,
        }

    def __repr__(self):
        return "<Jffs2Entry %s %r ino=%d %dB>" % (
            self.type_name, self.name, self.ino, self.size)


class Jffs2(object):
    """JFFS2 只读重建"""

    def __init__(self, sub, erase_size=None):
        self.rd = _Win(sub)
        self.size = self.rd.size
        self._erase_param = erase_size
        self.nodes_list = []
        self.crc_fail = {"hdr": 0, "node": 0, "name": 0, "data": 0, "totlen": 0}
        self.crc_node_variant = {"kernel": 0, "alt": 0, "fail": 0}
        self.by_ino = {}
        self.dirents = {}
        self._scan()
        self._index()
        self.erase_size, self.erase_src = self._infer_erase_size()

    # ---------------- 扫描 ----------------
    def _scan(self):
        rd = self.rd
        size = self.size
        pos = 0
        magic_b = b"\x19\x85"
        append = self.nodes_list.append
        while pos + JFFS2_HDR_LEN <= size:
            win = rd.read(pos, 1 << 18)
            if len(win) < JFFS2_HDR_LEN:
                break
            j = win.find(magic_b)
            if j < 0:
                # 整窗无魔数：只回退 1 字节，防止跨窗漏掉
                pos += len(win) - 1
                continue
            cand = pos + j
            node = self._try_node(cand)
            if node is None:
                pos = cand + 1
                continue
            append(node)
            step = _a4(node.totlen)
            if step < 4:
                step = 4
            pos = cand + step

    def _try_node(self, off):
        hdr = self.rd.read(off, JFFS2_HDR_LEN)
        if len(hdr) < JFFS2_HDR_LEN:
            return None
        magic, nodetype, totlen, hdr_crc = struct.unpack_from(">HHII", hdr, 0)
        if magic != JFFS2_MAGIC_BITMASK:
            if magic != JFFS2_OLD_MAGIC_BITMASK:
                return None
        if totlen < JFFS2_HDR_LEN or totlen > (self.size - off):
            self.crc_fail["totlen"] += 1
            return None
        if crc32_jffs2(hdr[:8]) != hdr_crc:
            self.crc_fail["hdr"] += 1
            return None

        kind = NODETYPE_NAME.get(nodetype) or NODETYPE_NAME.get(nodetype | JFFS2_NODE_ACCURATE)
        n = Jffs2Node()
        n.offset = off
        n.magic = magic
        n.nodetype = nodetype
        n.totlen = totlen
        n.hdr_crc = hdr_crc
        n.accurate = bool(nodetype & JFFS2_NODE_ACCURATE)
        n.kind = kind or "unknown"

        if kind == "inode":
            raw = self.rd.read(off, JFFS2_INODE_HDR_LEN)
            if len(raw) < JFFS2_INODE_HDR_LEN:
                self.crc_fail["totlen"] += 1
                return None
            self._fill_inode(n, raw)
        elif kind == "dirent":
            raw = self.rd.read(off, JFFS2_DIRENT_HDR_LEN)
            if len(raw) < JFFS2_DIRENT_HDR_LEN:
                self.crc_fail["totlen"] += 1
                return None
            if not self._fill_dirent(n, raw):
                return None
        return n

    def _fill_inode(self, n, raw):
        (n.ino, n.version, n.mode) = struct.unpack_from(">III", raw, 0x0C)
        (n.uid, n.gid) = struct.unpack_from(">HH", raw, 0x18)
        (n.isize, n.atime, n.mtime, n.ctime, n.file_offset,
         n.csize, n.dsize) = struct.unpack_from(">IIIIIII", raw, 0x1C)
        n.compr = raw[0x38]
        n.usercompr = raw[0x39]
        (n.flags,) = struct.unpack_from(">H", raw, 0x3A)
        (n.data_crc,) = struct.unpack_from(">I", raw, 0x3C)
        (n.node_crc,) = struct.unpack_from(">I", raw, 0x40)
        n.data_off = n.offset + JFFS2_INODE_HDR_LEN
        n.crc_node = self._check_node_crc(raw, INODE_NODE_CRC_LEN, n.node_crc,
                                          0x0C, 0x3C)

    def _fill_dirent(self, n, raw):
        (n.pino, n.version, n.ino, n.mctime) = struct.unpack_from(">IIII", raw, 0x0C)
        n.nsize = raw[0x1C]
        n.dtype = raw[0x1D]
        (n.node_crc,) = struct.unpack_from(">I", raw, 0x20)
        (n.name_crc,) = struct.unpack_from(">I", raw, 0x24)
        name_off = n.offset + JFFS2_DIRENT_HDR_LEN
        n.crc_node = self._check_node_crc(raw, DIRENT_NODE_CRC_LEN, n.node_crc,
                                          0x0C, 0x20)
        name = self.rd.read(name_off, n.nsize)
        if len(name) < n.nsize:
            self.crc_fail["totlen"] += 1
            return False
        n.name = name
        if n.nsize:
            if crc32_jffs2(name) == n.name_crc:
                n.crc_name = True
            else:
                n.crc_name = False
                self.crc_fail["name"] += 1
        else:
            n.crc_name = True
        return True

    def _check_node_crc(self, raw, klen, want, alt_lo, alt_hi):
        if crc32_jffs2(raw[:klen]) == want:
            self.crc_node_variant["kernel"] += 1
            return "kernel"
        if crc32_jffs2(raw[alt_lo:alt_hi]) == want:
            self.crc_node_variant["alt"] += 1
            return "alt"
        self.crc_node_variant["fail"] += 1
        self.crc_fail["node"] += 1
        return "fail"

    # ---------------- 索引 ----------------
    def _index(self):
        by_ino = self.by_ino
        dirents = self.dirents
        for n in self.nodes_list:
            if n.kind == "inode":
                by_ino.setdefault(n.ino, []).append(n)
            elif n.kind == "dirent":
                key = (n.pino, n.name)
                dirents.setdefault(key, []).append(n)
        for lst in by_ino.values():
            lst.sort(key=lambda x: x.version)
        for lst in dirents.values():
            lst.sort(key=lambda x: x.version)

    def _infer_erase_size(self):
        if self._erase_param:
            return int(self._erase_param), "param"
        offs = sorted(n.offset for n in self.nodes_list if n.kind == "cleanmarker")
        if len(offs) >= 2:
            g = 0
            for i in range(len(offs) - 1):
                d = offs[i + 1] - offs[i]
                if d > 0:
                    g = gcd(g, d)
            if 0x1000 <= g <= 0x1000000:
                return g, "cleanmarker"
        return 0x10000, "default"

    # ---------------- 查询 ----------------
    def info(self):
        counts = {}
        for n in self.nodes_list:
            counts[n.kind] = counts.get(n.kind, 0) + 1
        versions = sum(len(v) for v in self.by_ino.values())
        return {
            "format": "jffs2",
            "size": self.size,
            "erase_size": self.erase_size,
            "erase_size_source": self.erase_src,
            "total_nodes": len(self.nodes_list),
            "counts": counts,
            "crc_fail": dict(self.crc_fail),
            "node_crc_variant": dict(self.crc_node_variant),
            "inodes": len(self.by_ino),
            "inode_versions": versions,
            "dirent_keys": len(self.dirents),
            "max_version": versions and max(n.version for n in self.nodes_list
                                            if n.kind == "inode") or 0,
        }

    def nodes(self, kind=None):
        """节点摘要列表（可按 kind 过滤）"""
        if kind is None:
            return list(self.nodes_list)
        return [n for n in self.nodes_list if n.kind == kind]

    def versions(self, ino):
        """同一 inode 的历史版本：[(version, 节点偏移, 数据长度)]"""
        out = []
        for n in self.by_ino.get(int(ino), ()):
            out.append((n.version, n.offset, n.dsize))
        out.sort(key=lambda x: x[0])
        return out

    def inode_meta(self, ino):
        """取该 inode 版本号最大的 inode 节点（即最新元数据）"""
        lst = self.by_ino.get(int(ino))
        if not lst:
            return None
        return max(lst, key=lambda x: x.version)

    # ---------------- 解码 ----------------
    def decode(self, node):
        """解压一个 inode 节点的数据段，返回明文字节"""
        compr = node.compr
        if compr == JFFS2_COMPR_ZERO:
            if node.crc_data is None:
                node.crc_data = True
            return b"\x00" * node.dsize
        want = node.csize
        raw = self.rd.read(node.data_off, want) if want else b""
        if len(raw) < want:
            node.crc_data = False
            self.crc_fail["data"] += 1
            return b""
        if node.crc_data is None:
            if crc32_jffs2(raw) == node.data_crc:
                node.crc_data = True
            else:
                node.crc_data = False
                self.crc_fail["data"] += 1
        if compr in (JFFS2_COMPR_NONE, JFFS2_COMPR_COPY):
            return raw
        if compr == JFFS2_COMPR_ZLIB:
            try:
                out = zlib.decompress(raw)
            except zlib.error:
                node.crc_data = False
                return b""
            if node.dsize and len(out) != node.dsize:
                # dsize 不符但仍返回可用数据，交给上层判断
                pass
            return out
        raise NotImplementedError(
            "JFFS2 压缩算法 %s(%d) 未实现（无 stdlib 解码器）：节点 @0x%X ino=%d"
            % (node.compr_name, compr, node.offset, node.ino))

    def verify(self):
        """遍历所有 inode 节点校验 data_crc（会解码，可能抛 NotImplementedError）"""
        bad = 0
        checked = 0
        for n in self.nodes_list:
            if n.kind != "inode":
                continue
            if n.csize == 0 and n.compr != JFFS2_COMPR_ZERO:
                continue
            checked += 1
            try:
                self.decode(n)
            except NotImplementedError:
                continue
            if n.crc_data is False:
                bad += 1
        return {"checked": checked, "bad": bad,
                "fail_counts": dict(self.crc_fail)}

    # ---------------- 目录树 ----------------
    def _entry_from(self, name, dnode):
        e = Jffs2Entry()
        e.name = name
        e.pino = dnode.pino
        e.ino = dnode.ino
        e.dtype = dnode.dtype
        e.version = dnode.version
        e.node_off = dnode.offset
        meta = self.inode_meta(dnode.ino)
        if meta is not None:
            e.mode = meta.mode
            e.uid = meta.uid
            e.gid = meta.gid
            e.size = meta.isize
            e.atime = meta.atime
            e.mtime = meta.mtime
            e.ctime = meta.ctime
        else:
            e.mode = (dnode.dtype << 12) & S_IFMT
        return e

    def listdir(self, ino=1):
        """列目录。ino 可以是 inode 号或 Jffs2Entry"""
        if isinstance(ino, Jffs2Entry):
            ino = ino.ino
        ino = int(ino)
        out = []
        for (pino, name), lst in self.dirents.items():
            if pino != ino:
                continue
            latest = max(lst, key=lambda x: x.version)
            if latest.ino == 0:
                continue                     # ino==0 即 unlink
            out.append(self._entry_from(name.decode("utf-8", "replace"), latest))
        out.sort(key=lambda e: e.name)
        return out

    def unlinked(self, pino=None):
        """被删除的目录项（最新 dirent 的 ino == 0）"""
        out = []
        for (p, name), lst in self.dirents.items():
            if pino is not None and p != int(pino):
                continue
            latest = max(lst, key=lambda x: x.version)
            if latest.ino == 0:
                out.append({"pino": p, "name": name.decode("utf-8", "replace"),
                            "version": latest.version, "offset": latest.offset})
        out.sort(key=lambda d: (d["pino"], d["name"]))
        return out

    def walk(self, ino=1, _prefix="", _depth=0, _max=48, _seen=None):
        """递归遍历，产出 (路径, Jffs2Entry)"""
        if isinstance(ino, Jffs2Entry):
            ino = ino.ino
        ino = int(ino)
        if _seen is None:
            _seen = set()
        if ino in _seen or _depth > _max:
            return
        _seen.add(ino)
        for e in self.listdir(ino):
            path = _prefix + "/" + e.name if _prefix else e.name
            yield path, e
            if e.is_dir:
                for item in self.walk(e.ino, path, _depth + 1, _max, _seen):
                    yield item

    def lookup_path(self, path):
        """按路径查找，返回 Jffs2Entry；找不到抛 FileNotFoundError"""
        if isinstance(path, bytes):
            path = path.decode("utf-8", "replace")
        cur = None
        parts = [p for p in str(path).replace("\\", "/").split("/") if p and p != "."]
        if not parts:
            root = Jffs2Entry()
            root.name = "/"
            root.ino = 1
            root.pino = 1
            meta = self.inode_meta(1)
            if meta is not None:
                root.mode = meta.mode
                root.size = meta.isize
                root.mtime = meta.mtime
            root.mode = root.mode or (S_IFDIR | 0o755)
            return root
        for part in parts:
            pino = 1 if cur is None else cur.ino
            hit = None
            for e in self.listdir(pino):
                if e.name == part:
                    hit = e
                    break
            if hit is None:
                raise FileNotFoundError(str(path))
            cur = hit
        return cur

    def find(self, pattern):
        p = pattern.lower()
        return [(path, e) for path, e in self.walk() if p in path.lower()]

    # ---------------- 文件内容 ----------------
    def read_file(self, ino_or_entry):
        """读文件内容。接受 inode 号 / Jffs2Entry / 路径字符串"""
        if isinstance(ino_or_entry, (str, bytes)):
            return self.read_file(self.lookup_path(ino_or_entry))
        if isinstance(ino_or_entry, Jffs2Entry):
            ino = ino_or_entry.ino
        else:
            ino = int(ino_or_entry)
        meta = self.inode_meta(ino)
        if meta is None:
            raise KeyError("inode %d 在镜像中没有 inode 节点" % ino)
        mt = meta.mode & S_IFMT
        if mt == S_IFDIR:
            return None
        data = self._assemble(ino, meta.isize)
        if mt == S_IFLNK:
            return data
        return data

    def read_link(self, ino_or_entry):
        e = ino_or_entry
        if not isinstance(e, Jffs2Entry):
            e = self.lookup_path(e) if isinstance(e, (str, bytes)) else None
        data = self.read_file(ino_or_entry)
        if data is None:
            return None
        if e is not None and not e.is_symlink:
            return None
        return data.decode("utf-8", "replace")

    def _assemble(self, ino, final_size):
        lst = self.by_ino.get(ino, [])
        buf = bytearray()
        for n in lst:                     # 已按 version 升序，后写覆盖先写
            if n.dsize == 0 and n.compr != JFFS2_COMPR_ZERO:
                continue
            blob = self.decode(n)
            if not blob:
                continue
            end = n.file_offset + len(blob)
            if end > len(buf):
                buf.extend(b"\x00" * (end - len(buf)))
            buf[n.file_offset:end] = blob
        if final_size and len(buf) < final_size:
            buf.extend(b"\x00" * (final_size - len(buf)))
        if final_size and len(buf) > final_size:
            del buf[final_size:]
        return bytes(buf)


# ============================================================
#  YAFFS1 / YAFFS2
# ============================================================

YAFFS_OBJECTID_ROOT = 1
YAFFS_OBJECTID_LOSTNFOUND = 2
YAFFS_OBJECTID_UNLINKED = 3
YAFFS_OBJECTID_DELETED = 4
YAFFS_OBJECTID_SUMMARY = 0x10
YAFFS_OBJECTID_CHECKPOINT_DATA = 0x20

YAFS_TYPE_UNKNOWN = 0
YAFS_TYPE_FILE = 1
YAFS_TYPE_SYMLINK = 2
YAFS_TYPE_DIRECTORY = 3
YAFS_TYPE_HARDLINK = 4
YAFS_TYPE_SPECIAL = 5

YAFFS_OBJ_TYPE_NAME = {
    1: "file", 2: "symlink", 3: "dir", 4: "hardlink", 5: "special",
}

YAFFS_MAX_NAME_LENGTH = 255
YAFFS_MAX_ALIAS_LENGTH = 159

YAFFS_NO_OBJECT = 0xFFFFFFFF

# 常见 NAND 几何：(page, spare)
_YAFFS_GEOMETRIES = [
    (2048, 64), (512, 16), (4096, 128), (4096, 224),
    (2048, 128), (1024, 32), (512, 8),
]

# yaffs_obj_hdr 候选布局（字段偏移，字节）
_YHDR_LAYOUTS = [
    {
        "id": "yaffs2",
        "desc": "u32 type + 自然对齐；name@10，mode@268，共 512 字节",
        "type": 0, "type_w": 4, "sum": 8, "name_off": 10, "parent": 4,
        "mode": 268, "uid": 272, "gid": 276, "atime": 280, "mtime": 284,
        "ctime": 288, "fsize_low": 292, "equiv": 296, "alias": 300,
        "rdev": 460, "shadowed": 488, "is_shrink": 492, "fsize_high": 496,
        "shadows": 504, "shrink": 508, "size": 512,
    },
    {
        "id": "yaffs2-packed",
        "desc": "u32 type + packed；name@10，mode@266",
        "type": 0, "type_w": 4, "sum": 8, "name_off": 10, "parent": 4,
        "mode": 266, "uid": 270, "gid": 274, "atime": 278, "mtime": 282,
        "ctime": 286, "fsize_low": 290, "equiv": 294, "alias": 298,
        "rdev": 458, "shadowed": 486, "is_shrink": 490, "fsize_high": 494,
        "shadows": 502, "shrink": 506, "size": 512,
    },
    {
        "id": "legacy-u8-p8",
        "desc": "u8 type + u32 parent@4；name@8，mode@264",
        "type": 0, "type_w": 1, "sum": 1, "name_off": 8, "parent": 4,
        "mode": 264, "uid": 268, "gid": 272, "atime": 276, "mtime": 280,
        "ctime": 284, "fsize_low": 288, "equiv": 292, "alias": 296,
        "rdev": 456, "shadowed": 484, "is_shrink": 488, "fsize_high": 492,
        "shadows": 500, "shrink": 504, "size": 508,
    },
    {
        "id": "legacy-u8",
        "desc": "u8 type；name@2，mode@260，无 parentObjectId 解析",
        "type": 0, "type_w": 1, "sum": 1, "name_off": 2, "parent": None,
        "mode": 260, "uid": 264, "gid": 268, "atime": 272, "mtime": 276,
        "ctime": 280, "fsize_low": 284, "equiv": 288, "alias": 292,
        "rdev": 452, "shadowed": 480, "is_shrink": 484, "fsize_high": 488,
        "shadows": 496, "shrink": 500, "size": 504,
    },
    {
        "id": "legacy-u8-shadowed",
        "desc": "u8 type + isShadowed；name@3，mode@260",
        "type": 0, "type_w": 1, "sum": 1, "name_off": 3, "parent": None,
        "mode": 260, "uid": 264, "gid": 268, "atime": 272, "mtime": 276,
        "ctime": 280, "fsize_low": 284, "equiv": 288, "alias": 292,
        "rdev": 452, "shadowed": 480, "is_shrink": 484, "fsize_high": 488,
        "shadows": 496, "shrink": 500, "size": 504,
    },
]

# 便于按布局 id 取
YHDR_BY_NAME = dict((d["id"], d) for d in _YHDR_LAYOUTS)


def parse_tags2(spare, off=0):
    """YAFFS2 tags：spare[off:off+16] = 4×u32 小端
    (seqNumber, objectId, chunkId, byteCount)。全 0xFF 视为未用页。"""
    if len(spare) < off + 16:
        return None
    seq, obj, chunk, nbytes = struct.unpack_from("<IIII", spare, off)
    if seq == 0xFFFFFFFF and obj == 0xFFFFFFFF and chunk == 0xFFFFFFFF:
        return None
    return {"seq": seq, "obj": obj, "chunk": chunk, "nbytes": nbytes,
            "off": off}


def parse_tags1(spare, off=0):
    """YAFFS1 tags：spare[off:off+8] 是一个 64 位小端位域
    chunk_id:20 / serial:2 / n_bytes:10 / obj_id:18 / ecc:12 / deleted:1 /
    unused:1（与 yaffs_packedtags1.h 一致）。全 0xFF 视为未用页。"""
    if len(spare) < off + 8:
        return None
    v = struct.unpack_from("<Q", spare, off)[0]
    if v == 0xFFFFFFFFFFFFFFFF:
        return None
    d = {
        "chunk": v & 0xFFFFF,
        "serial": (v >> 20) & 0x3,
        "nbytes": (v >> 22) & 0x3FF,
        "obj": (v >> 32) & 0x3FFFF,
        "ecc": (v >> 50) & 0xFFF,
        "deleted": (v >> 62) & 0x1,
        "unused": (v >> 63) & 0x1,
        "off": off,
    }
    if d["obj"] == 0x3FFFF and d["chunk"] == 0xFFFFF:
        return None
    return d


def _page_guard(spare):
    """取 spare[20:24] 的 u32 页尾哨兵；不足 24 字节返回 None"""
    if len(spare) < 24:
        return None
    return struct.unpack_from("<I", spare, 20)[0]


def _score_geom(sub, page_size, spare_size, version, samples=96):
    """给一个 (page, spare, version) 几何打分：tags 合理性 + pageGuard"""
    stride = page_size + spare_size
    if stride <= 0:
        return 0.0, {}
    try:
        total = int(getattr(sub, "size", 0)) or 0
    except (TypeError, ValueError):
        total = 0
    if total <= 0:
        return 0.0, {}
    pages = total // stride
    if pages <= 0:
        return 0.0, {}
    step = max(1, pages // samples)
    score = 0
    seen = 0
    used = 0
    guard_ff = 0
    guard_seen = 0
    for pi in range(0, pages, step):
        if seen >= samples:
            break
        seen += 1
        base = pi * stride
        spare = sub.read(base + page_size, spare_size)
        if len(spare) < (8 if version == 1 else 16):
            continue
        if version == 2:
            t = parse_tags2(spare, 0)
            if t is None:
                t = parse_tags2(spare, 2)
            if t is None:
                continue
        else:
            t = parse_tags1(spare, 0)
            if t is None:
                t = parse_tags1(spare, 2)
            if t is None:
                continue
        obj = t["obj"]
        chunk = t["chunk"]
        nb = t["nbytes"]
        local = 0
        if 1 <= obj <= 0x0FFFFFFF:
            local += 2
        else:
            continue
        limit_chunk = 0x100000 if version == 2 else 0xFFFFF
        if chunk <= limit_chunk:
            local += 1
        else:
            continue
        if nb == 0 or nb == 0xFFFFFFFF or nb <= page_size:
            local += 1
        else:
            continue
        if version == 2 and t["seq"] not in (0xFFFFFFFF, 0):
            local += 1
        used += 1
        g = _page_guard(spare)
        if g is not None:
            guard_seen += 1
            if g == 0xFFFFFFFF:
                guard_ff += 1
                local += 1
        score += local
    if used == 0:
        return 0.0, {"samples": seen, "used": 0}
    return float(score) / used, {
        "samples": seen, "used": used,
        "guard_seen": guard_seen, "guard_ff": guard_ff,
    }


def detect_geometry(sub, page_size=None, spare_size=None):
    """判定 NAND 几何与 YAFFS 版本，返回 dict(page_size, spare_size, version,
    score, stats, source)"""
    if page_size and spare_size:
        best = None
        best_v = None
        for v in (2, 1):
            sc, st = _score_geom(sub, int(page_size), int(spare_size), v)
            if best is None or sc > best:
                best, best_v, best_st = sc, v, st
        return {"page_size": int(page_size), "spare_size": int(spare_size),
                "version": best_v, "score": best, "stats": best_st,
                "source": "param"}
    cands = []
    for (ps, ss) in _YAFFS_GEOMETRIES:
        for v in (2, 1):
            sc, st = _score_geom(sub, ps, ss, v)
            if st.get("used", 0):
                cands.append((sc, st["used"], ps, ss, v, st))
    if not cands:
        return {"page_size": 0, "spare_size": 0, "version": 0, "score": 0.0,
                "stats": {}, "source": "none"}
    cands.sort(key=lambda x: (x[0], x[1]), reverse=True)
    sc, used, ps, ss, v, st = cands[0]
    return {"page_size": ps, "spare_size": ss, "version": v, "score": sc,
            "stats": st, "source": "detect"}


def _score_hdr_layout(data, lay):
    """给一个对象头布局打分，判断它是否解释得通"""
    sc = 0
    tw = lay["type_w"]
    if tw == 4:
        if len(data) < 4:
            return -1
        otype = struct.unpack_from("<I", data, lay["type"])[0]
    else:
        if len(data) < 1:
            return -1
        otype = data[lay["type"]]
    if otype not in (1, 2, 3, 4, 5):
        return -1
    sc += 2
    no = lay["name_off"]
    if no + 4 > len(data):
        return -1
    raw = data[no:no + YAFFS_MAX_NAME_LENGTH + 1]
    z = raw.find(b"\x00")
    if z < 0:
        return -1
    nm = raw[:z]
    if len(nm) > YAFFS_MAX_NAME_LENGTH:
        return -1
    if b"\xff" in nm:
        return -1
    if nm:
        try:
            nm.decode("utf-8")
        except UnicodeDecodeError:
            return -1
        if any(c < 0x20 and c not in (0x09,) for c in nm):
            return -1
    sc += 3
    mo = lay["mode"]
    if mo + 4 <= len(data):
        mode = struct.unpack_from("<I", data, mo)[0]
        mt = mode & S_IFMT
        expect = {1: S_IFREG, 2: S_IFLNK, 3: S_IFDIR}.get(otype)
        if expect is not None:
            if mt == expect:
                sc += 3
            elif mt == 0:
                sc += 1
            else:
                sc -= 2
    to = lay["mtime"]
    if to + 4 <= len(data):
        t = struct.unpack_from("<I", data, to)[0]
        if 0 < t < 4102444800:      # 1970..2100
            sc += 1
    if lay["parent"] is not None and lay["parent"] + 4 <= len(data):
        par = struct.unpack_from("<I", data, lay["parent"])[0]
        if 1 <= par <= 0x0FFFFFFF:
            sc += 1
    return sc


class YaffsObject(object):
    """一个 YAFFS 对象（对象头 + 归属它的数据块）"""

    __slots__ = ("obj_id", "name", "parent", "type_id", "mode", "uid", "gid",
                 "atime", "mtime", "ctime", "file_size", "equiv_id", "alias",
                 "rdev", "shadowed", "shadows", "is_shrink", "hdr_off", "seq",
                 "chunks", "layout", "deleted_flag")

    def __init__(self):
        self.obj_id = 0
        self.name = ""
        self.parent = 0
        self.type_id = 0
        self.mode = 0
        self.uid = 0
        self.gid = 0
        self.atime = 0
        self.mtime = 0
        self.ctime = 0
        self.file_size = 0
        self.equiv_id = 0
        self.alias = ""
        self.rdev = 0
        self.shadowed = 0
        self.shadows = 0
        self.is_shrink = 0
        self.hdr_off = 0
        self.seq = 0
        self.chunks = {}
        self.layout = ""
        self.deleted_flag = 0

    @property
    def type_name(self):
        return YAFFS_OBJ_TYPE_NAME.get(self.type_id, "?%d" % self.type_id)

    @property
    def is_dir(self):
        return self.type_id == YAFS_TYPE_DIRECTORY

    @property
    def is_file(self):
        return self.type_id == YAFS_TYPE_FILE

    @property
    def is_symlink(self):
        return self.type_id == YAFS_TYPE_SYMLINK

    @property
    def is_hardlink(self):
        return self.type_id == YAFS_TYPE_HARDLINK

    def as_dict(self):
        return {
            "object_id": self.obj_id, "name": self.name, "parent": self.parent,
            "type": self.type_name, "mode": "0o%o" % self.mode,
            "uid": self.uid, "gid": self.gid, "size": self.file_size,
            "mtime": self.mtime, "seq": self.seq, "chunks": len(self.chunks),
            "hdr_offset": self.hdr_off, "layout": self.layout,
        }

    def __repr__(self):
        return "<YaffsObject %s %r id=%d %dB>" % (
            self.type_name, self.name, self.obj_id, self.file_size)


class Yaffs(object):
    """YAFFS1 / YAFFS2 只读重建"""

    def __init__(self, sub, page_size=None, spare_size=None, parent_off=None):
        self.rd = _Win(sub)
        self.size = self.rd.size
        geo = detect_geometry(sub, page_size, spare_size)
        self.geo = geo
        self.page_size = geo["page_size"]
        self.spare_size = geo["spare_size"]
        self.stride = self.page_size + self.spare_size
        self.pages = (self.size // self.stride) if self.stride else 0
        self.version = geo["version"] or 2
        self.objs = {}
        self._shadowed = []
        self._deleted_tags = []
        self._hdr_pages = {}
        self._parent_off = parent_off
        self.tags_seen = 0
        self.tags_bad = 0
        self.guard = {"seen": 0, "ff": 0, "offset": 20}
        self.layout = _YHDR_LAYOUTS[0]
        self.layout_scores = {}
        if self.pages:
            self._scan()
            self._pick_layout()
            self._parse_headers()

    # ---------------- 扫描 ----------------
    def _parse(self, spare):
        if self.version == 1:
            t = parse_tags1(spare, 0)
            if t is None:
                t = parse_tags1(spare, 2)
            return t
        t = parse_tags2(spare, 0)
        if t is None:
            t = parse_tags2(spare, 2)
        return t

    def _scan(self):
        rd = self.rd
        ps, ss, stride = self.page_size, self.spare_size, self.stride
        for pi in range(self.pages):
            base = pi * stride
            spare = rd.read(base + ps, ss)
            if len(spare) < (8 if self.version == 1 else 16):
                break
            g = _page_guard(spare)
            if g is not None:
                self.guard["seen"] += 1
                if g == 0xFFFFFFFF:
                    self.guard["ff"] += 1
            t = self._parse(spare)
            if t is None:
                continue
            obj = t["obj"]
            chunk = t["chunk"]
            if obj == 0 or obj == YAFFS_NO_OBJECT or obj > 0x0FFFFFFF:
                self.tags_bad += 1
                continue
            self.tags_seen += 1
            seq = t.get("seq", 0)          # YAFFS1 没有 seqNumber，退化为物理顺序
            if self.version == 1 and t.get("deleted"):
                self._deleted_tags.append({
                    "object_id": obj, "chunk_id": chunk, "page": pi,
                    "page_offset": base, "reason": "deleted-tag",
                })
                continue                   # 已删除块不再属于活文件
            if chunk == 0:
                self._read_obj_hdr(obj, pi, base, t)
            else:
                key = (obj, chunk)
                prev = self._chunks.get(key)
                if prev is None or seq >= prev["seq"]:
                    if prev is not None:
                        self._shadowed.append({
                            "object_id": obj, "chunk_id": chunk,
                            "page": prev["page"], "page_offset": prev["page_offset"],
                            "seq": prev["seq"], "nbytes": prev["nbytes"],
                            "reason": "shadowed",
                        })
                    self._chunks[key] = {
                        "page": pi, "page_offset": base, "seq": seq,
                        "nbytes": t["nbytes"], "deleted": t.get("deleted", 0),
                    }
                else:
                    self._shadowed.append({
                        "object_id": obj, "chunk_id": chunk, "page": pi,
                        "page_offset": base, "seq": seq,
                        "nbytes": t["nbytes"], "reason": "shadowed",
                    })

    @property
    def _chunks(self):
        # 延迟创建，保证 _scan 里第一次访问前已存在
        d = self.__dict__.get("_chunk_map")
        if d is None:
            d = {}
            self.__dict__["_chunk_map"] = d
        return d

    def _read_obj_hdr(self, obj_id, pi, base, tags):
        """第一遍：只登记对象头页的位置（seq 最大者胜），等布局判定后再解析"""
        seq = tags.get("seq", 0)
        cur = self._hdr_pages.get(obj_id)
        if cur is not None:
            if seq < cur[2]:
                self._shadowed.append({
                    "object_id": obj_id, "chunk_id": 0, "page": pi,
                    "page_offset": base, "seq": seq, "nbytes": 0,
                    "reason": "shadowed-header",
                })
                return
            self._shadowed.append({
                "object_id": obj_id, "chunk_id": 0, "page": cur[0],
                "page_offset": cur[1], "seq": cur[2], "nbytes": 0,
                "reason": "shadowed-header",
            })
        self._hdr_pages[obj_id] = (pi, base, seq)

    def _parse_headers(self):
        """第二遍：用判定好的布局解析所有对象头"""
        no = self.layout
        for obj_id in sorted(self._hdr_pages):
            pi, base, seq = self._hdr_pages[obj_id]
            data = self.rd.read(base, self.page_size)
            if len(data) < 64:
                continue
            obj = YaffsObject()
            obj.obj_id = obj_id
            obj.hdr_off = base
            obj.seq = seq
            obj.layout = no["id"]

            def read_u32(off):
                if off is None or off + 4 > len(data):
                    return 0
                return struct.unpack_from("<I", data, off)[0]

            if no["type_w"] == 4:
                obj.type_id = read_u32(no["type"])
            else:
                obj.type_id = data[no["type"]] if no["type"] < len(data) else 0
            par_off = self._parent_off if self._parent_off is not None else no["parent"]
            obj.parent = read_u32(par_off)
            obj.mode = read_u32(no["mode"])
            obj.uid = read_u32(no["uid"])
            obj.gid = read_u32(no["gid"])
            obj.atime = read_u32(no["atime"])
            obj.mtime = read_u32(no["mtime"])
            obj.ctime = read_u32(no["ctime"])
            obj.equiv_id = read_u32(no["equiv"])
            obj.rdev = read_u32(no["rdev"])
            obj.shadowed = read_u32(no["shadowed"])
            obj.shadows = read_u32(no["shadows"])
            obj.is_shrink = read_u32(no["shrink"])
            low = read_u32(no["fsize_low"])
            high = read_u32(no["fsize_high"])
            obj.file_size = (low | (high << 32)) if high < 0x100000 else low
            nb = data[no["name_off"]:no["name_off"] + YAFFS_MAX_NAME_LENGTH + 1]
            z = nb.find(b"\x00")
            if z < 0:
                z = YAFFS_MAX_NAME_LENGTH
            obj.name = nb[:z].decode("utf-8", "replace")
            ab = data[no["alias"]:no["alias"] + YAFFS_MAX_ALIAS_LENGTH + 1]
            az = ab.find(b"\x00")
            if az < 0:
                az = YAFFS_MAX_ALIAS_LENGTH
            obj.alias = ab[:az].decode("utf-8", "replace")
            self.objs[obj_id] = obj

    def _pick_layout(self):
        """用样本对象头给候选布局打分，选最优"""
        hdrs = sorted(self._hdr_pages.items())[:64]
        datas = []
        for obj_id, (pi, base, seq) in hdrs:
            d = self.rd.read(base, self.page_size)
            if len(d) >= 300:
                datas.append(d)
        if not datas:
            self.layout_scores = {}
            return
        scores = {}
        for lay in _YHDR_LAYOUTS:
            s = 0
            for d in datas:
                v = _score_hdr_layout(d, lay)
                if v < 0:
                    s -= 4
                else:
                    s += v
            scores[lay["id"]] = s
        best = max(_YHDR_LAYOUTS, key=lambda L: scores[L["id"]])
        # 分数相同时保留当前（默认 yaffs2）
        if scores.get(self.layout["id"], -10 ** 9) >= scores[best["id"]]:
            best = self.layout
        self.layout_scores = scores
        self.layout = best

    # ---------------- 查询 ----------------
    def info(self):
        return {
            "format": "yaffs%d" % self.version,
            "version": self.version,
            "page_size": self.page_size,
            "spare_size": self.spare_size,
            "pages": self.pages,
            "geometry_source": self.geo.get("source"),
            "geometry_score": round(self.geo.get("score", 0.0), 3),
            "objects": len(self.objs),
            "object_headers": sum(1 for o in self.objs.values() if o.hdr_off),
            "data_chunks": len(getattr(self, "_chunk_map", {})),
            "shadowed_chunks": len(self._shadowed),
            "deleted_tags": len(self._deleted_tags),
            "tags_seen": self.tags_seen,
            "tags_bad": self.tags_bad,
            "hdr_layout": self.layout["id"],
            "hdr_layout_scores": getattr(self, "layout_scores", {}),
            "parent_off": (self._parent_off if self._parent_off is not None
                           else self.layout["parent"]),
            "page_guard": {
                "offset": self.guard["offset"],
                "checked": self.guard["seen"],
                "all_ff": self.guard["ff"],
                "consistent": self.guard["seen"] > 0 and
                              self.guard["ff"] == self.guard["seen"],
            },
        }

    def objects(self):
        """所有活对象（每个 objectId 取 seq 最大的对象头）"""
        return sorted(self.objs.values(), key=lambda o: o.obj_id)

    def object(self, obj_id):
        return self.objs.get(int(obj_id))

    def _need_parent(self):
        if self.layout["parent"] is None and self._parent_off is None:
            raise NotImplementedError(
                "对象头布局 %s（legacy u8 type）不含可识别的 parentObjectId 偏移，"
                "无法构建目录树；请用 Yaffs(sub, parent_off=<偏移>) 指定父指针偏移，"
                "或改用 objects() / read_file() / deleted() 逐个取证"
                % self.layout["id"])

    def listdir(self, obj_id=YAFFS_OBJECTID_ROOT):
        if isinstance(obj_id, YaffsObject):
            obj_id = obj_id.obj_id
        obj_id = int(obj_id)
        self._need_parent()
        out = []
        for o in self.objs.values():
            if o.parent == obj_id and o.obj_id != obj_id:
                out.append(o)
        out.sort(key=lambda o: o.name)
        return out

    def walk(self, obj=None, _prefix="", _depth=0, _max=48, _seen=None):
        if obj is None:
            oid = YAFFS_OBJECTID_ROOT
        elif isinstance(obj, YaffsObject):
            oid = obj.obj_id
        else:
            oid = int(obj)
        if _seen is None:
            _seen = set()
        if oid in _seen or _depth > _max:
            return
        _seen.add(oid)
        for o in self.listdir(oid):
            path = (_prefix + "/" + o.name) if _prefix else o.name
            yield path, o
            if o.is_dir:
                for item in self.walk(o, path, _depth + 1, _max, _seen):
                    yield item

    def lookup_path(self, path):
        if isinstance(path, bytes):
            path = path.decode("utf-8", "replace")
        parts = [p for p in str(path).replace("\\", "/").split("/")
                 if p and p != "."]
        cur = self.objs.get(YAFFS_OBJECTID_ROOT)
        if not parts:
            return cur
        for part in parts:
            if cur is None:
                raise FileNotFoundError(str(path))
            hit = None
            for o in self.listdir(cur.obj_id):
                if o.name == part:
                    hit = o
                    break
            if hit is None:
                raise FileNotFoundError(str(path))
            cur = hit
        return cur

    def find(self, pattern):
        p = pattern.lower()
        return [(path, o) for path, o in self.walk() if p in path.lower()]

    # ---------------- 数据 ----------------
    def _page_data(self, page_off, nbytes):
        if nbytes in (0, 0xFFFFFFFF) or nbytes > self.page_size:
            nbytes = self.page_size
        return self.rd.read(page_off, nbytes)

    def _obj_chunks(self, obj_id):
        out = {}
        for (oid, cid), info in self._chunk_map.items():
            if oid == obj_id:
                out[cid] = info
        return out

    def read_file(self, obj):
        """读文件内容；obj 可为 YaffsObject / objectId / 路径"""
        if isinstance(obj, (str, bytes)):
            obj = self.lookup_path(obj)
        if not isinstance(obj, YaffsObject):
            obj = self.objs.get(int(obj))
        if obj is None:
            raise KeyError("对象不存在")
        if obj.is_dir:
            return None
        if obj.is_hardlink:
            tgt = self.objs.get(obj.equiv_id)
            return self.read_file(tgt) if tgt is not None else None
        if obj.is_symlink:
            return obj.alias.encode("utf-8")
        chunks = self._obj_chunks(obj.obj_id)
        if not chunks:
            return b""
        last = max(chunks)
        buf = bytearray()
        for cid in range(1, last + 1):
            info = chunks.get(cid)
            if info is None:
                buf.extend(b"\x00" * self.page_size)
                continue
            blob = self._page_data(info["page_offset"], info["nbytes"])
            buf.extend(blob)
        size = obj.file_size
        if size and size <= len(buf):
            del buf[size:]
        return bytes(buf)

    def read_link(self, obj):
        if isinstance(obj, (str, bytes)):
            obj = self.lookup_path(obj)
        if not isinstance(obj, YaffsObject):
            obj = self.objs.get(int(obj))
        if obj is None or not obj.is_symlink:
            return None
        return obj.alias

    def deleted(self):
        """删除取证：被覆盖的旧版本块 / YAFFS1 deleted 位 / unlinked 对象"""
        out = list(self._shadowed)
        out.extend(self._deleted_tags)
        for oid in (YAFFS_OBJECTID_UNLINKED, YAFFS_OBJECTID_DELETED):
            o = self.objs.get(oid)
            if o is not None:
                out.append({
                    "object_id": oid, "chunk_id": 0, "page": o.hdr_off // self.stride
                    if self.stride else 0, "page_offset": o.hdr_off,
                    "seq": o.seq, "nbytes": 0, "reason": "reserved-obj",
                    "name": o.name,
                })
        out.sort(key=lambda d: (d.get("page_offset", 0), d.get("chunk_id", 0)))
        return out

    def versions(self, obj_id, chunk_id=None):
        """某对象/某块的物理副本（含被覆盖的）：[(seq, page_offset)]"""
        res = []
        for info in self._shadowed:
            if info.get("object_id") == obj_id:
                if chunk_id is None or info.get("chunk_id") == chunk_id:
                    res.append((info.get("seq", 0), info.get("page_offset", 0)))
        for (oid, cid), info in self._chunk_map.items():
            if oid == obj_id and (chunk_id is None or cid == chunk_id):
                res.append((info["seq"], info["page_offset"]))
        res.sort(reverse=True)
        return res


# ============================================================
#  统一入口
# ============================================================

def _probe_jffs2(sub, limit=1 << 20):
    """在前 limit 字节里找 0x1985 且 hdr_crc 通过的节点"""
    rd = _Win(sub)
    size = min(rd.size, limit)
    pos = 0
    hits = 0
    while pos + 12 <= size:
        win = rd.read(pos, 1 << 16)
        if len(win) < 12:
            break
        j = win.find(b"\x19\x85")
        if j < 0:
            pos += len(win) - 1
            continue
        cand = pos + j
        hdr = rd.read(cand, 12)
        if len(hdr) == 12:
            magic, nodetype, totlen, hdr_crc = struct.unpack_from(">HHII", hdr, 0)
            if (magic == JFFS2_MAGIC_BITMASK and 12 <= totlen <= rd.size - cand
                    and crc32_jffs2(hdr[:8]) == hdr_crc):
                hits += 1
                if hits >= 2:
                    return True
        pos = cand + 1
    return hits >= 1


def _has_obj_header(sub, page_size, spare_size, version, max_pages=256):
    """更强的 YAFFS 判据：找到一个 chunkId==0 且对象头布局解释得通的页"""
    stride = page_size + spare_size
    try:
        total = int(getattr(sub, "size", 0)) or 0
    except (TypeError, ValueError):
        total = 0
    if stride <= 0 or total <= 0:
        return False
    pages = min(total // stride, max_pages)
    for pi in range(pages):
        base = pi * stride
        spare = sub.read(base + page_size, spare_size)
        if len(spare) < (8 if version == 1 else 16):
            return False
        if version == 2:
            t = parse_tags2(spare, 0) or parse_tags2(spare, 2)
        else:
            t = parse_tags1(spare, 0) or parse_tags1(spare, 2)
        if not t or t["chunk"] != 0:
            continue
        data = sub.read(base, min(page_size, 520))
        if len(data) < 64:
            continue
        for lay in _YHDR_LAYOUTS:
            if _score_hdr_layout(data, lay) >= 8:
                return True
    return False


def probe(sub):
    """判定镜像类型："jffs2" / "yaffs1" / "yaffs2" / "unknown" """
    if _probe_jffs2(sub):
        return "jffs2"
    geo = detect_geometry(sub)
    if not geo["page_size"]:
        return "unknown"
    if geo.get("score", 0.0) < 3.5 or geo["stats"].get("used", 0) < 3:
        return "unknown"
    if not _has_obj_header(sub, geo["page_size"], geo["spare_size"],
                           geo["version"]):
        return "unknown"
    return "yaffs1" if geo["version"] == 1 else "yaffs2"


def open_fs(sub, **kw):
    """按 probe 结果打开对应文件系统对象

    额外关键字：jffs2 -> erase_size；yaffs -> page_size / spare_size
    """
    kind = kw.pop("kind", None) or probe(sub)
    if kind == "jffs2":
        return Jffs2(sub, erase_size=kw.get("erase_size"))
    if kind in ("yaffs1", "yaffs2"):
        return Yaffs(sub, page_size=kw.get("page_size"),
                     spare_size=kw.get("spare_size"),
                     parent_off=kw.get("parent_off"))
    raise ValueError("unknown image: probe() 无法识别该裸闪存镜像")


# ============================================================
#  自检
# ============================================================

if __name__ == "__main__":
    class Buf(object):
        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, n):
            if off >= self.size or n <= 0 or off < 0:
                return b""
            return self.data[off:off + n]

    # ---------- JFFS2 合成 ----------
    def mk_inode(ino, version, mode, data, file_off=0, compr=0,
                 isize=None, uid=0, gid=0, mtime=0x5F000000, name=None):
        if compr == JFFS2_COMPR_ZLIB:
            payload = zlib.compress(data, 9)
        elif compr == JFFS2_COMPR_ZERO:
            payload = b""
        else:
            payload = data
        csize = len(payload)
        dsize = len(data) if compr != JFFS2_COMPR_ZERO else (isize or len(data))
        if isize is None:
            isize = file_off + dsize
        totlen = JFFS2_INODE_HDR_LEN + csize
        buf = bytearray(totlen)
        struct.pack_into(">HHI", buf, 0x00, JFFS2_MAGIC_BITMASK,
                         JFFS2_NODETYPE_INODE, totlen)
        struct.pack_into(">II", buf, 0x0C, ino, version)
        struct.pack_into(">I", buf, 0x14, mode)
        struct.pack_into(">HH", buf, 0x18, uid, gid)
        struct.pack_into(">I", buf, 0x1C, isize)
        struct.pack_into(">III", buf, 0x20, mtime - 10, mtime, mtime)
        struct.pack_into(">III", buf, 0x2C, file_off, csize, dsize)
        buf[0x38] = compr
        buf[0x39] = compr
        struct.pack_into(">H", buf, 0x3A, 0)
        struct.pack_into(">I", buf, 0x3C, crc32_jffs2(payload))
        # hdr_crc 必须先写，node_crc 覆盖 0x00..0x3B 含 hdr_crc
        struct.pack_into(">I", buf, 0x08, crc32_jffs2(bytes(buf[0:8])))
        struct.pack_into(">I", buf, 0x40, crc32_jffs2(bytes(buf[0:60])))
        buf[0x44:0x44 + csize] = payload
        return bytes(buf)

    def mk_dirent(pino, name, ino, version, dtype=8, mctime=0x5F000000):
        nb = name.encode("utf-8")
        totlen = _a4(JFFS2_DIRENT_HDR_LEN + len(nb))
        buf = bytearray(totlen)
        struct.pack_into(">HHI", buf, 0x00, JFFS2_MAGIC_BITMASK,
                         JFFS2_NODETYPE_DIRENT, totlen)
        struct.pack_into(">IIII", buf, 0x0C, pino, version, ino, mctime)
        buf[0x1C] = len(nb)
        buf[0x1D] = dtype
        buf[0x28:0x28 + len(nb)] = nb
        struct.pack_into(">I", buf, 0x24, crc32_jffs2(nb))          # name_crc
        struct.pack_into(">I", buf, 0x08, crc32_jffs2(bytes(buf[0:8])))
        struct.pack_into(">I", buf, 0x20, crc32_jffs2(bytes(buf[0:32])))
        return bytes(buf)

    def mk_cleanmarker():
        buf = bytearray(12)
        struct.pack_into(">HHI", buf, 0, JFFS2_MAGIC_BITMASK,
                         JFFS2_NODETYPE_CLEANMARKER, 12)
        struct.pack_into(">I", buf, 8, crc32_jffs2(bytes(buf[0:8])))
        return bytes(buf)

    V1 = b"version-1-payload"
    V2 = b"version-2-payload-longer!"
    ZLIB_DATA = (b"zlib compressible line\n" * 20)
    ZERO_LEN = 100
    NAME_CN = "中文.txt"
    NAME_Z = "zlib.txt"
    NAME_0 = "零.bin"

    def build_jffs2():
        img = bytearray(b"\xff" * 0x20000)
        pos = [0]

        def put(node):
            p = pos[0]
            img[p:p + len(node)] = node
            pos[0] = p + len(node)
            while pos[0] % 4:
                img[pos[0]] = 0xFF
                pos[0] += 1
            return p

        off_cm = put(mk_cleanmarker())
        off_dir = put(mk_inode(1, 1, S_IFDIR | 0o755, b"", isize=0))
        off_v1 = put(mk_inode(2, 1, S_IFREG | 0o644, V1, file_off=0, isize=len(V1)))
        off_v2 = put(mk_inode(2, 2, S_IFREG | 0o644, V2, file_off=0, isize=len(V2)))
        off_z = put(mk_inode(3, 1, S_IFREG | 0o644, ZLIB_DATA,
                             compr=JFFS2_COMPR_ZLIB))
        off_zero = put(mk_inode(4, 1, S_IFREG | 0o600, b"\x00" * ZERO_LEN,
                                compr=JFFS2_COMPR_ZERO, isize=ZERO_LEN))
        off_d1 = put(mk_dirent(1, NAME_CN, 2, 1, dtype=8))
        off_d2 = put(mk_dirent(1, NAME_Z, 3, 1, dtype=8))
        off_d3 = put(mk_dirent(1, NAME_0, 4, 1, dtype=8))
        img[0x10000:0x1000C] = mk_cleanmarker()
        return (bytes(img), {"cleanmarker": off_cm, "dir": off_dir, "v1": off_v1,
                             "v2": off_v2, "zlib": off_z, "zero": off_zero,
                             "d1": off_d1, "d2": off_d2, "d3": off_d3})

    img, offs = build_jffs2()

    # CRC 实现自检：zlib 快路径必须与纯 Python 表实现一致
    for blob in (b"", b"A", b"0123456789", V2, ZLIB_DATA):
        assert crc32_jffs2(blob) == _crc32_reflect(blob, 0), "CRC 两种实现不一致"

    assert probe(Buf(img)) == "jffs2", "probe 应判为 jffs2"
    fs = Jffs2(Buf(img))
    inf = fs.info()
    print("JFFS2: size=%d erase=%d(%s) nodes=%d inodes=%d versions=%d"
          % (inf["size"], inf["erase_size"], inf["erase_size_source"],
             inf["total_nodes"], inf["inodes"], inf["inode_versions"]))
    print("       节点分类: %s" % inf["counts"])
    print("       CRC: %s  node_crc 覆盖: %s"
          % (inf["crc_fail"], inf["node_crc_variant"]))

    assert inf["erase_size"] == 0x10000, inf["erase_size"]
    assert inf["erase_size_source"] == "cleanmarker", inf["erase_size_source"]
    assert inf["counts"].get("cleanmarker") == 2, inf["counts"]
    assert inf["counts"].get("inode") == 5, inf["counts"]
    assert inf["counts"].get("dirent") == 3, inf["counts"]
    assert inf["total_nodes"] == 10, inf["total_nodes"]
    assert inf["crc_fail"]["hdr"] == 0 and inf["crc_fail"]["node"] == 0
    assert inf["crc_fail"]["name"] == 0, inf["crc_fail"]

    # 节点字段落地正确
    inodes = fs.nodes("inode")
    assert len(inodes) == 5
    for n in inodes:
        assert n.magic == JFFS2_MAGIC_BITMASK
        assert n.nodetype == JFFS2_NODETYPE_INODE
        assert n.crc_hdr is True
        assert n.crc_node == "kernel", (n, n.crc_node)
    dirs = fs.nodes("dirent")
    for n in dirs:
        assert n.nodetype == JFFS2_NODETYPE_DIRENT
        assert n.crc_node == "kernel", (n, n.crc_node)
        assert n.crc_name is True

    # 多版本
    vers = fs.versions(2)
    print("       ino=2 版本: %s" % (vers,))
    assert len(vers) == 2 and vers[0][0] == 1 and vers[1][0] == 2, vers
    assert fs.read_file(2) == V2, "应取 version 2"
    assert fs.inode_meta(2).offset == offs["v2"]

    # ZLIB / ZERO
    z = fs.read_file(3)
    assert z == ZLIB_DATA, "zlib 解压不符 %d vs %d" % (len(z), len(ZLIB_DATA))
    z0 = fs.read_file(4)
    assert z0 == b"\x00" * ZERO_LEN and len(z0) == ZERO_LEN, len(z0)
    print("       ZLIB 节点解压 %d B 正确；ZERO 节点 %d B 全零正确"
          % (len(z), len(z0)))

    # 目录树
    ents = fs.listdir(1)
    names = [e.name for e in ents]
    print("       根目录: %s" % [(e.name, e.type_name, e.size) for e in ents])
    assert len(ents) == 3, names
    assert NAME_CN in names, names
    e_cn = [e for e in ents if e.name == NAME_CN][0]
    assert e_cn.is_file and e_cn.size == len(V2)
    assert e_cn.uid == 0 and e_cn.gid == 0
    assert fs.read_file(e_cn) == V2
    assert fs.lookup_path("/" + NAME_CN).ino == 2
    assert fs.read_file("/" + NAME_Z) == ZLIB_DATA
    walk = [p for p, e in fs.walk()]
    print("       walk: %s" % walk)
    assert NAME_CN in walk and NAME_Z in walk and NAME_0 in walk
    assert fs.find("zlib")[0][0] == NAME_Z
    assert fs.read_file(1) is None, "目录 read_file 应返回 None"

    print("       versions(2)=%s  中文名=%r" % (fs.versions(2), e_cn.name))

    # 损坏一个字节 -> hdr_crc 失败被跳过而不是崩溃
    bad = bytearray(img)
    bad[offs["zlib"] + 2] ^= 0xFF          # 破坏 nodetype 字节 -> hdr_crc 失败
    fs_bad = Jffs2(Buf(bytes(bad)))
    inf_bad = fs_bad.info()
    print("       破坏 1 字节后: nodes=%d hdr_crc 失败=%d"
          % (inf_bad["total_nodes"], inf_bad["crc_fail"]["hdr"]))
    assert inf_bad["total_nodes"] == inf["total_nodes"] - 1, inf_bad["total_nodes"]
    assert inf_bad["crc_fail"]["hdr"] >= 1
    # 其余节点仍可读，进程没崩
    assert fs_bad.read_file("/" + NAME_CN) == V2

    # data_crc 校验
    ver = fs.verify()
    print("       verify: %s" % (ver,))
    assert ver["checked"] >= 4 and ver["bad"] == 0, ver

    # ---------- YAFFS2 合成 ----------
    def yaffs_obj_hdr(otype, parent, name, mode, size, alias="", seq=1):
        lay = YHDR_BY_NAME["yaffs2"]
        buf = bytearray(512)
        struct.pack_into("<I", buf, lay["type"], otype)
        struct.pack_into("<I", buf, lay["parent"], parent)
        struct.pack_into("<H", buf, lay["sum"], 0)
        nb = name.encode("utf-8")[:YAFFS_MAX_NAME_LENGTH]
        buf[lay["name_off"]:lay["name_off"] + len(nb)] = nb
        struct.pack_into("<I", buf, lay["mode"], mode)
        struct.pack_into("<I", buf, lay["uid"], 0)
        struct.pack_into("<I", buf, lay["gid"], 0)
        struct.pack_into("<III", buf, lay["atime"], 0x5F000000, 0x5F000000, 0x5F000000)
        struct.pack_into("<I", buf, lay["fsize_low"], size & 0xFFFFFFFF)
        struct.pack_into("<I", buf, lay["fsize_high"], (size >> 32) & 0xFFFFFFFF)
        if alias:
            ab = alias.encode("utf-8")[:YAFFS_MAX_ALIAS_LENGTH]
            buf[lay["alias"]:lay["alias"] + len(ab)] = ab
        return bytes(buf)

    def yaffs_page(data, seq, obj, chunk, nbytes, page=2048, spare=64):
        d = bytearray(b"\xff" * page)
        d[:min(len(data), page)] = data[:page]
        sp = bytearray(b"\xff" * spare)
        struct.pack_into("<IIII", sp, 0, seq, obj, chunk, nbytes)
        struct.pack_into("<I", sp, 24, 0x00000000)      # tags ECC 占位
        # spare[20:24] 保持 0xFF -> pageGuard 一致
        return bytes(d) + bytes(sp)

    YDATA = b"hello yaffs2 world\n" * 3
    YNAME = "闪存文件.txt"
    pages = []
    pages.append(yaffs_page(yaffs_obj_hdr(3, 1, "", S_IFDIR | 0o755, 0),
                            1, 1, 0, 0xFFFFFFFF))
    pages.append(yaffs_page(yaffs_obj_hdr(1, 1, YNAME, S_IFREG | 0o644,
                                          len(YDATA)), 1, 257, 0, 0xFFFFFFFF))
    pages.append(yaffs_page(YDATA, 1, 257, 1, len(YDATA)))
    pages.append(b"\xff" * (2048 + 64))
    yimg = b"".join(pages)

    assert probe(Buf(yimg)) == "yaffs2", "probe 应判为 yaffs2"
    yfs = Yaffs(Buf(yimg))
    yinf = yfs.info()
    print("YAFFS: page=%d spare=%d pages=%d objects=%d layout=%s guard=%s"
          % (yinf["page_size"], yinf["spare_size"], yinf["pages"],
             yinf["objects"], yinf["hdr_layout"], yinf["page_guard"]))
    print("       tags_seen=%d chunks=%d shadowed=%d geo_score=%s"
          % (yinf["tags_seen"], yinf["data_chunks"],
             yinf["shadowed_chunks"], yinf["geometry_score"]))
    assert yinf["page_size"] == 2048 and yinf["spare_size"] == 64, yinf
    assert yinf["version"] == 2
    assert yinf["hdr_layout"] == "yaffs2", yinf["hdr_layout_scores"]
    assert yinf["page_guard"]["consistent"] is True, yinf["page_guard"]
    assert yinf["tags_seen"] == 3, yinf["tags_seen"]

    kids = yfs.listdir(1)
    print("       根目录: %s" % [(o.name, o.type_name, o.file_size) for o in kids])
    assert len(kids) == 1 and kids[0].name == YNAME, [o.name for o in kids]
    assert yfs.read_file(kids[0]) == YDATA
    assert yfs.read_file("/" + YNAME) == YDATA
    assert yfs.lookup_path("/" + YNAME).obj_id == 257
    assert [p for p, o in yfs.walk()] == [YNAME]
    assert yfs.object(1).is_dir and yfs.object(257).is_file
    assert yfs.deleted() == [], yfs.deleted()

    # 被覆盖的旧块应进入 deleted()
    pages2 = [pages[0], pages[1],
              yaffs_page(b"stale version\n", 1, 257, 1, 14),
              yaffs_page(YDATA, 2, 257, 1, len(YDATA)),
              pages[3]]
    yimg2 = b"".join(pages2)
    yfs2 = Yaffs(Buf(yimg2))
    dl = yfs2.deleted()
    print("       覆盖后 deleted(): %d 条 %s"
          % (len(dl), [(d["object_id"], d["chunk_id"], d["reason"]) for d in dl]))
    assert len(dl) == 1 and dl[0]["reason"] == "shadowed", dl
    assert yfs2.read_file(257) == YDATA, "应按 seq 取最新块"

    # ---------- YAFFS1 合成（512+16，legacy 对象头布局，tags1 位域） ----------
    Y1_LAY = YHDR_BY_NAME["legacy-u8-p8"]

    def yaffs1_obj_hdr(otype, parent, name, mode, size):
        buf = bytearray(512)
        buf[0] = otype
        buf[1] = 0                                    # sumNoLongerUsed
        struct.pack_into("<I", buf, 4, parent)
        nb = name.encode("utf-8")[:YAFFS_MAX_NAME_LENGTH]
        buf[8:8 + len(nb)] = nb
        struct.pack_into("<I", buf, Y1_LAY["mode"], mode)
        struct.pack_into("<III", buf, Y1_LAY["atime"], 0x5F000000, 0x5F000000,
                         0x5F000000)
        struct.pack_into("<I", buf, Y1_LAY["fsize_low"], size & 0xFFFFFFFF)
        struct.pack_into("<I", buf, Y1_LAY["fsize_high"], (size >> 32) & 0xFFFFFFFF)
        return bytes(buf)

    def tags1(obj, chunk, nbytes, serial=0, deleted=0):
        v = (chunk & 0xFFFFF)
        v |= (serial & 0x3) << 20
        v |= (nbytes & 0x3FF) << 22
        v |= (obj & 0x3FFFF) << 32
        v |= (0 & 0xFFF) << 50
        v |= (deleted & 1) << 62
        return struct.pack("<Q", v)

    def y1_page(data, obj, chunk, nbytes, deleted=0, page=512, spare=16):
        d = bytearray(b"\xff" * page)
        d[:min(len(data), page)] = data[:page]
        sp = bytearray(b"\xff" * spare)
        sp[0:8] = tags1(obj, chunk, nbytes, deleted=deleted)
        return bytes(d) + bytes(sp)

    Y1DATA = b"YAFFS1 data block\n"
    Y1NAME = "y1文件.txt"
    y1pages = [
        y1_page(yaffs1_obj_hdr(3, 1, "", S_IFDIR | 0o755, 0), 1, 0, 512),
        y1_page(yaffs1_obj_hdr(1, 1, Y1NAME, S_IFREG | 0o644, len(Y1DATA)),
                33, 0, 512),
        y1_page(Y1DATA, 33, 1, len(Y1DATA)),
        y1_page(b"tombstone\n", 33, 2, 10, deleted=1),
        b"\xff" * (512 + 16),
    ]
    y1img = b"".join(y1pages)

    assert probe(Buf(y1img)) == "yaffs1", "probe 应判为 yaffs1"
    y1fs = Yaffs(Buf(y1img))
    y1inf = y1fs.info()
    print("YAFFS1: page=%d spare=%d objects=%d layout=%s parent_off=%s"
          % (y1inf["page_size"], y1inf["spare_size"], y1inf["objects"],
             y1inf["hdr_layout"], y1inf["parent_off"]))
    print("        tags_seen=%d deleted_tags=%d"
          % (y1inf["tags_seen"], y1inf["deleted_tags"]))
    assert y1inf["version"] == 1, y1inf
    assert y1inf["page_size"] == 512 and y1inf["spare_size"] == 16, y1inf
    assert y1inf["hdr_layout"] == "legacy-u8-p8", y1inf["hdr_layout_scores"]

    y1kids = y1fs.listdir(1)
    print("        根目录: %s" % [(o.name, o.type_name, o.file_size) for o in y1kids])
    assert len(y1kids) == 1 and y1kids[0].name == Y1NAME
    assert y1fs.read_file(y1kids[0]) == Y1DATA
    assert y1fs.read_file("/" + Y1NAME) == Y1DATA
    d1 = y1fs.deleted()
    print("        deleted(): %s" % [(d["object_id"], d["chunk_id"], d["reason"])
                                     for d in d1])
    assert len(d1) == 1 and d1[0]["reason"] == "deleted-tag", d1
    # parent_off 手工覆盖也能工作
    y1fs2 = Yaffs(Buf(y1img), parent_off=4)
    assert [o.name for o in y1fs2.listdir(1)] == [Y1NAME]

    # ---------- JFFS2：未实现压缩 + unlink 取证 ----------
    img3 = bytearray(b"\xff" * 0x1000)
    pos3 = 0
    n3 = mk_inode(9, 1, S_IFREG | 0o644, b"rtime-payload", compr=JFFS2_COMPR_RTIME)
    img3[pos3:pos3 + len(n3)] = n3
    pos3 += _a4(len(n3))
    d_old = mk_dirent(1, "gone.txt", 9, 1)
    img3[pos3:pos3 + len(d_old)] = d_old
    pos3 += _a4(len(d_old))
    d_new = mk_dirent(1, "gone.txt", 0, 2)          # ino==0 -> unlink
    img3[pos3:pos3 + len(d_new)] = d_new
    pos3 += _a4(len(d_new))
    fs3 = Jffs2(Buf(bytes(img3)))
    assert fs3.listdir(1) == [], "unlink 后不应出现在目录里"
    ul = fs3.unlinked()
    print("       unlink 取证: %s" % ul)
    assert len(ul) == 1 and ul[0]["name"] == "gone.txt" and ul[0]["version"] == 2
    try:
        fs3.read_file(9)
    except NotImplementedError as exc:
        print("       RTIME 节点如约抛 NotImplementedError: %s" % str(exc)[:40])
    else:
        raise AssertionError("RTIME 压缩应抛 NotImplementedError")

    # 非 YAFFS / 非 JFFS2
    junk = bytes(bytearray((i * 37 + 11) & 0xFF for i in range(0x4000)))
    assert probe(Buf(junk)) == "unknown", "非闪存数据应为 unknown"
    assert probe(Buf(b"\x00" * 0x4000)) == "unknown"
    try:
        open_fs(Buf(junk))
    except ValueError:
        pass
    else:
        raise AssertionError("open_fs 对未知镜像应抛 ValueError")

    # 统一入口
    assert isinstance(open_fs(Buf(img)), Jffs2)
    assert isinstance(open_fs(Buf(yimg)), Yaffs)

    print("自检通过（JFFS2 + YAFFS2 + YAFFS1 三种镜像全部通过）")
