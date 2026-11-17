# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""XFS 文件系统（v4 / v5）

格式依据 Linux `fs/xfs/libxfs/xfs_format.h`。

已实现：
    · 超级块 `xfs_dsb` 全字段解析（大端），版本用 sb_versionnum & 0x000f 判定
    · v5 的 CRC / meta_uuid / features_* 字段
    · AG 头 `xfs_agf` / `xfs_agi` 的定位与关键字段
    · inode 定位：`agno = ino >> (sb_agblklog + sb_inopblog)`
    · inode 核心 `xfs_dinode`（v2 / v3）
    · 目录遍历：短格式（local）、块格式（extent 直接映射）
    · 文件读取：extent 格式（di_format == XFS_DINODE_FMT_EXTENTS）
    · 按路径查找、递归遍历

不实现：
    · 写操作
    · B-tree 格式的 inode（di_format == XFS_DINODE_FMT_BTREE）
      —— 大目录与大文件会落到这种格式，遇到时抛 NotImplementedError 而不是返回错数据
    · 属性 fork、实时设备、log 回放
    · CRC 校验（v5 只读字段，不验证）
"""

import struct

__all__ = ["Xfs", "XFS_SB_MAGIC", "XFS_DINODE_FMT_EXTENTS"]

try:
    from .xfs_bmap import (read_bmap, decode_bmbt_rec, encode_bmbt_rec,
                           XfsBmapError)
except ImportError:                                  # 直接跑本脚本时
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(
        _os.path.abspath(__file__))))
    from mkit.xfs_bmap import (read_bmap, decode_bmbt_rec,
                               encode_bmbt_rec, XfsBmapError)

XFS_SB_MAGIC = b"XFSB"
XFS_AGF_MAGIC = b"XAGF"
XFS_AGI_MAGIC = b"XAGI"
XFS_DINODE_MAGIC = b"IN"

SUPERBLOCK_LEN = 512

# di_format
XFS_DINODE_FMT_DEV = 0
XFS_DINODE_FMT_LOCAL = 1
XFS_DINODE_FMT_EXTENTS = 2
XFS_DINODE_FMT_BTREE = 3
XFS_DINODE_FMT_UUID = 4
XFS_DINODE_FMT_RMAP = 5

# dir2 目录块/叶子块的 magic：
#   XD2B = v4 块格式（数据项 + 尾部 leaf 数组）
#   XDB3 = v5 块格式
#   XD2D = v4 数据块
#   XDD3 = v5 数据块
DIR2_BLOCK_MAGICS = (b"XD2B", b"XDB3", b"XD2D", b"XDD3")
DIR2_FREE_TAG = 0xFFFF

FORMAT_NAME = {
    0: "dev", 1: "local", 2: "extents", 3: "btree", 4: "uuid", 5: "rmap",
}

# 文件类型
FT_UNKNOWN = 0
FT_REG = 1
FT_DIR = 2
FT_CHR = 3
FT_BLK = 4
FT_FIFO = 5
FT_SOCK = 6
FT_SYMLINK = 7
FT_WHT = 8

FTYPE_NAME = {
    0: "unknown", 1: "reg", 2: "dir", 3: "chr", 4: "blk",
    5: "fifo", 6: "sock", 7: "symlink", 8: "wht",
}

# mode 高 4 位 -> 类型
MODE_TYPE = [
    (0x8000, "reg"), (0x4000, "dir"), (0xA000, "symlink"),
    (0x2000, "chr"), (0x6000, "blk"), (0x1000, "fifo"), (0xC000, "sock"),
]

# extent 标志
XFS_BMBT_REC_FLAG_UNWRITTEN = 1 << 15
XFS_BMBT_EXNTFLAG_STATE_MASK = 0x3
XFS_BMBT_STARTBLOCK_MASK = (1 << 54) - 1
XFS_BMBT_STARTBLOCK_BITLEN = 9


def _mode_type(mode):
    m = mode & 0xF000
    for v, name in MODE_TYPE:
        if v == m:
            return name
    return "unknown"


class XfsEntry(object):
    __slots__ = ("name", "inode", "ftype", "mode", "size", "mtime", "ino_off")

    def __init__(self, name, inode, ftype, mode=0, size=0, mtime=None, ino_off=0):
        self.name = name
        self.inode = inode
        self.ftype = ftype
        self.mode = mode
        self.size = size
        self.mtime = mtime
        self.ino_off = ino_off

    @property
    def type_name(self):
        return FTYPE_NAME.get(self.ftype, _mode_type(self.mode))

    @property
    def is_dir(self):
        return self.ftype == FT_DIR or _mode_type(self.mode) == "dir"

    def __repr__(self):
        return "<XfsEntry %s %r %dB>" % (self.type_name, self.name, self.size)


class XfsInode(object):
    __slots__ = ("ino", "offset", "version", "format", "mode", "nlink",
                 "size", "mtime", "ctime", "atime", "extents", "symlink",
                 "local_data", "nextents", "forkoff")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def is_dir(self):
        return _mode_type(self.mode) == "dir"

    @property
    def is_file(self):
        return _mode_type(self.mode) == "reg"

    @property
    def is_symlink(self):
        return _mode_type(self.mode) == "symlink"

    def __repr__(self):
        return "<XfsInode %d mode=0o%o %s fmt=%s>" % (
            self.ino, self.mode or 0, _mode_type(self.mode),
            FORMAT_NAME.get(self.format, "?"))


class Xfs(object):
    """XFS v4 / v5 只读"""

    def __init__(self, sub):
        self.sub = sub
        self._read_sb()

    # ---------------- 超级块 ----------------
    def _read_sb(self):
        s = self.sub.read(0, SUPERBLOCK_LEN)
        if len(s) < SUPERBLOCK_LEN:
            raise ValueError("镜像太短，读不到 XFS 超级块")
        if s[0:4] != XFS_SB_MAGIC:
            raise ValueError("不是 XFS（magic=%r）" % s[0:4])

        u16 = lambda o: struct.unpack_from(">H", s, o)[0]
        u32 = lambda o: struct.unpack_from(">I", s, o)[0]
        u64 = lambda o: struct.unpack_from(">Q", s, o)[0]

        self.blocksize = u32(4)
        self.dblocks = u64(8)
        self.rblocks = u64(16)
        self.rextents = u64(24)
        self.uuid = s[32:48].hex()
        self.logstart = u64(48)
        self.rootino = u64(56)
        self.rbmino = u64(64)
        self.rsumino = u64(72)
        self.rextsize = u32(80)
        self.agblocks = u32(84)
        self.agcount = u32(88)
        self.rbmblocks = u32(92)
        self.logblocks = u32(96)
        self.versionnum = u16(100)
        self.sectsize = u16(102)
        self.inodesize = u16(104)
        self.inopblock = u16(106)
        self.fname = u32(108)
        self.blocklog = u16(112)
        self.sectsize_bits = u16(114)
        self.inodelog = u16(116)
        self.inopblog = u16(118)
        self.agblklog = u16(120)
        self.rextslog = u16(122)
        self.inprogress = u8(s, 124)
        self.imax_pct = u8(s, 125)
        self.icount = u64(128)
        self.ifree = u64(136)
        self.fdblocks = u64(144)

        self.version = self.versionnum & 0x000F
        self.is_v5 = (self.version == 5)

        # v5 扩展
        self.meta_uuid = s[248:264].hex() if self.is_v5 else None
        self.features_compat = u32(208) if self.is_v5 else 0
        self.features_ro_compat = u32(212) if self.is_v5 else 0
        self.features_incompat = u32(216) if self.is_v5 else 0
        self.features_log_incompat = u32(220) if self.is_v5 else 0
        self.crc = u32(224) if self.is_v5 else 0

    def info(self):
        return {
            "format": "xfs",
            "version": self.version,
            "v5": self.is_v5,
            "blocksize": self.blocksize,
            "dblocks": self.dblocks,
            "agcount": self.agcount,
            "agblocks": self.agblocks,
            "inodesize": self.inodesize,
            "inopblock": self.inopblock,
            "rootino": self.rootino,
            "uuid": self.uuid,
            "meta_uuid": self.meta_uuid,
            "fname": self.fname,
            "inprogress": self.inprogress,
            "icount": self.icount,
            "ifree": self.ifree,
            "features_incompat": "0x%08X" % self.features_incompat,
        }

    # ---------------- AG ----------------
    def _ag_offset(self, agno):
        return agno * self.agblocks * self.blocksize

    def ag_info(self, agno):
        """读某个 AG 的 AGF / AGI 关键字段"""
        base = self._ag_offset(agno)
        sectsz = self.sectsize or 512
        agf = self.sub.read(base + 1 * sectsz, 256)
        agi = self.sub.read(base + 2 * sectsz, 256)
        out = {"agno": agno, "offset": base}
        if len(agf) >= 32 and agf[0:4] == XFS_AGF_MAGIC:
            out.update(
                agf_magic="XAGF",
                agf_seqno=struct.unpack_from(">I", agf, 4)[0],
                agf_length=struct.unpack_from(">I", agf, 8)[0],
                agf_roots=[struct.unpack_from(">I", agf, 12 + 4 * i)[0]
                           for i in range(3)],
                agf_levels=[struct.unpack_from(">I", agf, 24 + 4 * i)[0]
                            for i in range(3)],
                agf_flfirst=struct.unpack_from(">I", agf, 36)[0],
                agf_fllast=struct.unpack_from(">I", agf, 40)[0],
            )
        if len(agi) >= 32 and agi[0:4] == XFS_AGI_MAGIC:
            out.update(
                agi_magic="XAGI",
                agi_seqno=struct.unpack_from(">I", agi, 4)[0],
                agi_length=struct.unpack_from(">I", agi, 8)[0],
                agi_count=struct.unpack_from(">I", agi, 12)[0],
                agi_root=struct.unpack_from(">I", agi, 16)[0],
                agi_level=struct.unpack_from(">I", agi, 20)[0],
                agi_freecount=struct.unpack_from(">I", agi, 24)[0],
            )
        return out

    # ---------------- inode ----------------
    def inode_offset(self, ino):
        """ino -> 镜像内绝对偏移"""
        bits = self.agblklog + self.inopblog
        agno = ino >> bits
        agino = ino & ((1 << bits) - 1)
        agbno = agino >> self.inopblog
        off_in_ag = (agino & ((1 << self.inopblog) - 1)) * self.inodesize
        return self._ag_offset(agno) + agbno * self.blocksize + off_in_ag

    def inode(self, ino):
        off = self.inode_offset(ino)
        raw = self.sub.read(off, self.inodesize)
        if len(raw) < 100:
            raise ValueError("inode 读不到（ino=%d off=%d）" % (ino, off))

        magic = raw[0:2]
        version = raw[4]
        fmt = raw[5]
        mode = struct.unpack_from(">H", raw, 2)[0]
        nlink_v1 = struct.unpack_from(">H", raw, 6)[0]
        # v2/v3: di_onlink@6 是 pad，真正的 nlink 在 di_nlink@16
        nlink = struct.unpack_from(">I", raw, 16)[0] if version >= 2 else nlink_v1
        size = struct.unpack_from(">q", raw, 56)[0]
        nblocks = struct.unpack_from(">Q", raw, 64)[0]
        # v3 的 nextents 是 64 位：低 32 位在 di_nextents@76，
        # 高 32 位在 di_big_nextents@24（与 v2 的 di_pad 共用一个 union）
        nextents = struct.unpack_from(">I", raw, 76)[0]
        if version >= 3:
            nextents |= struct.unpack_from(">I", raw, 24)[0] << 32
        forkoff = raw[82] if version >= 2 else 0
        # 时间戳在 di_atime@32 / di_mtime@40 / di_ctime@48（各 sec u32 + nsec u32）。
        # 早先这里写成 24/32/40，把 v2 的 di_pad / v3 的 di_big_nextents 当成了 atime。
        atime = struct.unpack_from(">I", raw, 32)[0]
        mtime = struct.unpack_from(">I", raw, 40)[0]
        ctime = struct.unpack_from(">I", raw, 48)[0]

        # v3 有 176 字节的加长核
        core = 176 if version >= 3 else 100
        data = raw[core:]

        kw = dict(ino=ino, offset=off, version=version, format=fmt, mode=mode,
                  nlink=nlink, size=size, mtime=mtime, ctime=ctime, atime=atime,
                  nextents=nextents, forkoff=forkoff, extents=[], symlink=None,
                  local_data=None)

        if fmt == XFS_DINODE_FMT_LOCAL:
            n = size if size > 0 else len(data)
            kw["local_data"] = data[:n]

        elif fmt == XFS_DINODE_FMT_EXTENTS:
            exts = []
            for i in range(min(nextents, 64)):
                off_e = i * 16
                if off_e + 16 > len(data):
                    break
                # 位域交给 xfs_bmap.decode_bmbt_rec 统一处理：
                #   lo bit63 = unwritten；startoff 54 位；startblock 52 位；
                #   blockcount 21 位。早先这里按「2 位 state + 53 位 startoff」
                #   解，位宽是错的。
                exts.append(decode_bmbt_rec(data, off_e))
            kw["extents"] = exts

        elif fmt == XFS_DINODE_FMT_BTREE:
            # bmap b-tree：内联根 xfs_bmdr_block → 外部 BMAP/BMA3 块，多级下钻。
            # 具体解析与 fork_len 的两种歧义都交给 xfs_bmap 处理，
            # 这里只把 data fork 与块参数传进去。
            recs = read_bmap(self.sub, data, self.blocksize, self.inodesize,
                             core, forkoff)
            kw["extents"] = [(r["startblock"], r["blockcount"],
                              r["startoff"], r["state"]) for r in recs]

        return XfsInode(**kw)

    def read_file(self, inode):
        if inode.is_dir:
            return None
        if inode.is_symlink and inode.local_data is not None:
            return inode.local_data
        if inode.format == XFS_DINODE_FMT_LOCAL:
            return inode.local_data or b""
        if inode.format in (XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE):
            # b-tree 展开后的记录与 extent 是同一种四元组
            # (startblock, blockcount, startoff, state)，所以这里统一处理。
            # 按 startoff 排序是为了让乱序写入的 extent 也能按文件偏移摆对；
            # b-tree 出来的记录本来就已升序。
            recs = sorted(inode.extents or [], key=lambda r: r[2])
            out = bytearray()
            for startblock, blockcount, startoff, state in recs:
                n = blockcount * self.blocksize
                data = self.sub.read(startblock * self.blocksize, n)
                if state:                          # 1 = unwritten
                    data = b"\x00" * n
                out += data
                if inode.size and len(out) >= inode.size:
                    break
            return bytes(out[:inode.size] if inode.size else out)
        return None

    # ---------------- 目录 ----------------
    def listdir(self, inode=None):
        ino = inode or self.inode(self.rootino)
        if not ino.is_dir:
            raise ValueError("不是目录: %r" % ino)

        out = []
        if ino.format == XFS_DINODE_FMT_LOCAL:
            self._parse_dir_data(ino.local_data or b"", out)
        elif ino.format in (XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE):
            # extent 与 b-tree 展开后都是同一串块映射。b-tree 目录的叶子记录
            # 直接指向目录数据块，所以逐块判类型：dir2 块走 dir2 解析，
            # 其余仍按原短格式解析（短格式实际住在 inode 的 literal area，
            # 走不到这里，保留只是为了不改动既有行为）。
            for startblock, blockcount, startoff, state in \
                    sorted(ino.extents or [], key=lambda r: r[2]):
                for b in range(blockcount):
                    off = (startblock + b) * self.blocksize
                    data = self.sub.read(off, self.blocksize)
                    if not data:
                        continue
                    if bytes(data[0:4]) in DIR2_BLOCK_MAGICS:
                        self._parse_dir2_block(data, out)
                    else:
                        self._parse_dir_data(data, out)
        return out

    def _parse_dir_data(self, data, out):
        """解析 XFS 短格式（local）目录数据

        短格式目录结构：
          u8 count; u8 i8count; u32 parent_ino(8 或 4 字节);
          然后 count 个 xfs_dir2_sf_entry:
            u64 ino(8 或 4 字节); u8 namelen; u8 ftype; name[namelen]; u8 foffset
        """
        if len(data) < 6:
            return
        count = data[0]
        i8count = data[1]
        big = i8count > 0
        iw = 8 if big else 4
        p = 2 + iw                     # 跳过 parent ino

        for _ in range(count):
            if p + iw + 2 > len(data):
                break
            if big:
                ino = struct.unpack_from(">Q", data, p)[0]
            else:
                ino = struct.unpack_from(">I", data, p)[0]
            p += iw
            namelen = data[p]
            ftype = data[p + 1]
            p += 2
            name = data[p:p + namelen]
            p += namelen
            p += 1                     # foffset
            if not name:
                continue
            out.append(XfsEntry(name.decode("utf-8", "replace"), ino, ftype))

    # ---------------- dir2 目录块 ----------------
    # XFS 的块格式目录把目录项放在数据块里，有两种布局：
    #   · 块格式（XD2B / XDB3）：数据项 + 尾部 leaf 数组 + 最后 8 字节 (count, stale)
    #   · 数据块（XD2D / XDD3）：只有数据项，数据区起点之前是块头
    # dir2 数据项是：u64 inumber + u8 namelen + name[namelen] + u8 ftype，
    # 之后按 8 字节对齐。空闲区以 freetag 0xFFFF 开头，紧跟 u16 长度。
    def _parse_dir2_block(self, data, out):
        """解析 dir2 目录块；返回新增的条目数"""
        before = len(out)
        if len(data) < 16:
            return 0
        magic = bytes(data[0:4])
        bsize = len(data)
        if magic in (b"XD2B", b"XDB3"):
            # 块格式：尾部 8 字节是 (count, stale)，紧邻其前是 count 条 leaf 数组
            count, stale = struct.unpack_from(">II", data, bsize - 8)
            if count <= 0 or count * 8 + 8 > bsize:
                return 0
            leaf_start = bsize - 8 - count * 8
            live = count - stale if 0 <= stale <= count else count
            for i in range(live):
                addr = struct.unpack_from(">I", data, leaf_start + i * 8 + 4)[0]
                self._dir2_entry_at(data, addr, out)
            return len(out) - before

        # 数据块：数据区起点随版本不同，用「走完刚好到块尾」自校验挑一个
        best = None
        for start in self._dir2_data_offsets(magic):
            if start >= bsize:
                continue
            ents, used = self._walk_dir2_data(data, start)
            if best is None or used > best[0]:
                best = (used, ents)
            if used >= bsize:
                break
        if best:
            out.extend(best[1])
        return len(out) - before

    @staticmethod
    def _dir2_data_offsets(magic):
        """dir2 数据区可能的起点

        v5（XDD3）的块头是 48 字节 blk_hdr + 12 字节 best_free + 4 字节 pad =64，
        v4（XD2D）是 16 字节。这里把几种可能都当候选，交给
        `_walk_dir2_data` 用「走完刚好到块尾」来判别，不把版本头长度写死。
        """
        if magic == b"XDD3":
            return (64, 56, 48, 16)
        if magic == b"XD2D":
            return (16, 24)
        return (16,)

    def _walk_dir2_data(self, data, start):
        """从 start 起顺序走 dir2 数据项，返回 (条目列表, 走到的偏移)"""
        ents = []
        p = start
        n = len(data)
        guard = 0
        while p + 8 <= n:
            guard += 1
            if guard > 100000:
                break
            if struct.unpack_from(">H", data, p)[0] == DIR2_FREE_TAG:
                ln = struct.unpack_from(">H", data, p + 2)[0]
                if ln < 8 or p + ln > n:
                    break
                p += ln
                continue
            used = self._dir2_entry_at(data, p, ents)
            if not used:
                break
            p += used
        return ents, p

    def _dir2_entry_at(self, data, off, out):
        """解析 off 处的一条 dir2 数据项

        成功返回该条占用的字节数（含尾部对齐），不是有效项返回 None。
        """
        n = len(data)
        if off < 0 or off + 9 > n:
            return None
        if struct.unpack_from(">H", data, off)[0] == DIR2_FREE_TAG:
            return None
        ino = struct.unpack_from(">Q", data, off)[0]
        namelen = data[off + 8]
        if namelen == 0 or off + 9 + namelen + 1 > n:
            return None
        name = bytes(data[off + 9:off + 9 + namelen])
        ftype = data[off + 9 + namelen]
        used = (8 + 1 + namelen + 1 + 7) & ~7
        if off + used > n:
            return None
        out.append(XfsEntry(name.decode("utf-8", "replace"), ino, ftype))
        return used

    def walk(self, inode=None, _depth=0, _max=32):
        prefix = "" if inode is None else inode.name + "/" if hasattr(inode, "name") else ""
        for it in self.listdir(inode):
            yield prefix + it.name, it
            if it.is_dir and _depth < _max:
                try:
                    child = self.inode(it.inode)
                except Exception:
                    continue
                if child.is_dir:
                    for sn, si in self.walk(child, _depth + 1, _max):
                        yield prefix + it.name + "/" + sn, si

    def lookup_path(self, path):
        cur = self.inode(self.rootino)
        for part in [p for p in path.split("/") if p]:
            hit = None
            for it in self.listdir(cur):
                if it.name == part:
                    hit = it
                    break
            if hit is None:
                raise FileNotFoundError(path)
            cur = self.inode(hit.inode)
        return cur

    def read_path(self, path):
        return self.read_file(self.lookup_path(path))

    def find(self, pattern):
        return [(p, e) for p, e in self.walk() if pattern.lower() in p.lower()]


def u8(b, o):
    return b[o]


if __name__ == "__main__":
    class Buf(object):
        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    def build():
        """合成一个最小 XFS：1 个 AG，根目录用 local 格式，含 1 个文件"""
        BLK = 4096
        SECT = 512
        INODE_SIZE = 512
        AG_BLOCKS = 16
        total = AG_BLOCKS * BLK
        img = bytearray(total)

        # ---- 超级块 ----
        def be32(o, v):
            struct.pack_into(">I", img, o, v)

        def be64(o, v):
            struct.pack_into(">Q", img, o, v)

        img[0:4] = XFS_SB_MAGIC
        be32(4, BLK)                       # blocksize
        be64(8, AG_BLOCKS)                 # dblocks
        img[32:48] = bytes(range(16))      # uuid
        be64(56, 8 * 3)                    # rootino = agbno3 的第 0 个 inode
        be32(84, AG_BLOCKS)                # agblocks
        be32(88, 1)                        # agcount
        struct.pack_into(">H", img, 100, 5)    # versionnum -> v5
        struct.pack_into(">H", img, 102, SECT)  # sectsize
        struct.pack_into(">H", img, 104, INODE_SIZE)
        struct.pack_into(">H", img, 106, BLK // INODE_SIZE)   # inopblock = 8
        be32(108, 0)                       # fname
        struct.pack_into(">H", img, 112, 12)   # blocklog
        struct.pack_into(">H", img, 116, 9)    # inodelog
        struct.pack_into(">H", img, 118, 3)    # inopblog = 3 (8 inodes/block)
        struct.pack_into(">H", img, 120, 4)    # agblklog = 4 (16 blocks/ag)
        img[124] = 0                       # inprogress = 0
        img[248:264] = bytes(range(16))    # meta_uuid

        # ---- AGI @ ag 0, sector 2 ----
        agi_off = 2 * SECT
        img[agi_off:agi_off + 4] = XFS_AGI_MAGIC
        struct.pack_into(">I", img, agi_off + 4, 0)
        struct.pack_into(">I", img, agi_off + 8, AG_BLOCKS)
        struct.pack_into(">I", img, agi_off + 12, 2)     # count
        struct.pack_into(">I", img, agi_off + 16, 3)     # root
        struct.pack_into(">I", img, agi_off + 20, 1)     # level

        # ---- AG 元数据占用 0..2 块，数据从块 3 开始 ----
        # inode 128 -> agno=0, agino=128, agbno=128>>3=16 -> 超出 AG 范围
        # 用 ino=8*3=24 -> agbno=3
        ROOT_INO = 8 * 3
        FILE_INO = 8 * 4

        def inode_off(ino):
            agbno = ino >> 3
            idx = ino & 7
            return agbno * BLK + idx * INODE_SIZE

        def mk_inode(ino, mode, fmt, size, data_body, nlink=1):
            off = inode_off(ino)
            hdr = bytearray(INODE_SIZE)
            hdr[0:2] = b"IN"
            struct.pack_into(">H", hdr, 2, mode)
            hdr[4] = 3               # version 3
            hdr[5] = fmt
            struct.pack_into(">I", hdr, 16, nlink)
            struct.pack_into(">q", hdr, 56, size)
            struct.pack_into(">I", hdr, 76, 0)      # nextents
            hdr[82] = 0                              # forkoff
            body = bytes(hdr[0:176]) + data_body
            img[off:off + len(body)] = body

        # ---- 根目录（local 格式）----
        # 短格式目录：count=2, i8count=1(用 8 字节 ino), parent=ROOT_INO
        sf = bytearray()
        sf.append(2)             # count
        sf.append(1)             # i8count>0 -> 8 字节 ino
        sf += struct.pack(">Q", ROOT_INO)          # parent
        for nm, ino, ft in (("a.txt", FILE_INO, FT_REG),):
            sf += struct.pack(">Q", ino)
            sf.append(len(nm))
            sf.append(ft)
            sf += nm.encode()
            sf.append(0)         # foffset
        mk_inode(ROOT_INO, 0o040755, XFS_DINODE_FMT_LOCAL, len(sf), bytes(sf))

        # ---- 文件 inode（extent 格式，1 个 extent 指向块 5）----
        DATA_BLK = 5
        CONTENT = b"Hello XFS v5!\n" * 5
        file_hdr = bytearray(INODE_SIZE)
        file_hdr[0:2] = b"IN"
        struct.pack_into(">H", file_hdr, 2, 0o100644)
        file_hdr[4] = 3
        file_hdr[5] = XFS_DINODE_FMT_EXTENTS
        struct.pack_into(">I", file_hdr, 16, 1)
        struct.pack_into(">q", file_hdr, 56, len(CONTENT))
        struct.pack_into(">Q", file_hdr, 64, 1)          # nblocks
        struct.pack_into(">I", file_hdr, 76, 1)          # nextents
        # extent：startoff=0, startblock=DATA_BLK, blockcount=1, state=0
        startoff = 0
        blockcount = 1
        lo = (0 << 62) | (startoff << 9) | ((DATA_BLK >> 43) & 0x1FF)
        hi = ((DATA_BLK & ((1 << 43) - 1)) << 21) | (blockcount & 0x1FFFFF)
        ext = struct.pack(">QQ", lo, hi)
        body = bytes(file_hdr[0:176]) + ext
        off = inode_off(FILE_INO)
        img[off:off + len(body)] = body

        img[DATA_BLK * BLK:DATA_BLK * BLK + len(CONTENT)] = CONTENT

        # ---- b-tree 格式的 inode（di_format = 3）----
        # 块位规划：6 = b-tree 文件 inode，7 = b-tree 目录 inode，
        #           8 = 文件的内联根指向的外部 BMAP 叶块，9/10 = 文件数据块，
        #           11 = 目录的 BMAP 叶块，12 = dir2 目录数据块
        BT_FILE_INO = 8 * 6
        BT_DIR_INO = 8 * 7
        BMAP_LEAF = 8
        BT_D0, BT_D1 = 9, 10
        DIR_LEAF = 11
        DIR_DATA = 12

        PART0 = bytes(((i * 37) & 0xFF) for i in range(BLK))
        PART1 = bytes(((255 - i * 11) & 0xFF) for i in range(BLK))
        BT_SIZE = BLK + 100
        BT_EXPECT = (PART0 + PART1)[:BT_SIZE]
        img[BT_D0 * BLK:(BT_D0 + 1) * BLK] = PART0
        img[BT_D1 * BLK:(BT_D1 + 1) * BLK] = PART1

        def mk_bmap_leaf(fsb, recs):
            """造一个外部 bmap b-tree 块（BMA3 = CRC 版，头 72 字节，level 0）"""
            blk = bytearray(BLK)
            blk[0:4] = b"BMA3"
            struct.pack_into(">H", blk, 4, 0)             # bb_level
            struct.pack_into(">H", blk, 6, len(recs))      # bb_numrecs
            struct.pack_into(">Q", blk, 24, fsb)           # bb_blkno
            p = 72
            for rec in recs:
                blk[p:p + 16] = encode_bmbt_rec(*rec)
                p += 16
            img[fsb * BLK:(fsb + 1) * BLK] = bytes(blk)

        # 内联根 xfs_bmdr_block：4 字节头 + keys 全在前 + ptrs 在 4+maxrecs*8
        FORK_LEN = INODE_SIZE - 176
        MAXRECS = (FORK_LEN - 4) // 16

        def mk_bmdr(level, keys, ptrs):
            root = bytearray(FORK_LEN)
            struct.pack_into(">HH", root, 0, level, len(ptrs))
            for i, k in enumerate(keys):
                struct.pack_into(">Q", root, 4 + i * 8, k)
            base = 4 + MAXRECS * 8
            for i, pv in enumerate(ptrs):
                struct.pack_into(">Q", root, base + i * 8, pv)
            return bytes(root)

        # 文件：内联根 level=1 指到块 8，块 8 是 level 0 的叶块，两条记录
        mk_bmap_leaf(BMAP_LEAF, [(BT_D0, 1, 0, 0), (BT_D1, 1, 1, 0)])
        mk_inode(BT_FILE_INO, 0o100644, XFS_DINODE_FMT_BTREE, BT_SIZE,
                 mk_bmdr(1, [0], [BMAP_LEAF]), nlink=1)

        # 目录：内联根 -> 块 11 的叶块 -> 块 12 的 dir2 数据块
        mk_bmap_leaf(DIR_LEAF, [(DIR_DATA, 1, 0, 0)])
        db = bytearray(BLK)
        db[0:4] = b"XDD3"                              # v5 dir2 数据块
        struct.pack_into(">Q", db, 8, DIR_DATA)        # blkno
        dp = 64                                        # 数据区起点
        for dino, dname, dft in ((FILE_INO, "b.txt", FT_REG),
                                 (BT_FILE_INO, "big.bin", FT_REG)):
            nb = dname.encode()
            db[dp:dp + 8] = struct.pack(">Q", dino)
            db[dp + 8] = len(nb)
            db[dp + 9:dp + 9 + len(nb)] = nb
            db[dp + 9 + len(nb)] = dft
            dp += (8 + 1 + len(nb) + 1 + 7) & ~7
        struct.pack_into(">HH", db, dp, DIR2_FREE_TAG, BLK - dp)
        struct.pack_into(">II", db, 48, dp, BLK - dp)  # best_free[0]
        img[DIR_DATA * BLK:(DIR_DATA + 1) * BLK] = bytes(db)
        mk_inode(BT_DIR_INO, 0o040755, XFS_DINODE_FMT_BTREE, BLK,
                 mk_bmdr(1, [0], [DIR_LEAF]), nlink=2)

        fx = dict(bt_file=BT_FILE_INO, bt_dir=BT_DIR_INO,
                  bt_d0=BT_D0, bt_d1=BT_D1, bt_size=BT_SIZE,
                  bt_expect=BT_EXPECT, big_ino=BT_FILE_INO, file_ino=FILE_INO,
                  root_ino=ROOT_INO, root_off=inode_off(ROOT_INO))
        return bytes(img), CONTENT, fx

    img, CONTENT, FX = build()
    fs = Xfs(Buf(img))
    inf = fs.info()
    print("XFS: v%d blocksize=%d dblocks=%d agcount=%d inodesize=%d inopblog=%d"
          % (inf["version"], inf["blocksize"], inf["dblocks"], inf["agcount"],
             inf["inodesize"], fs.inopblog))
    assert inf["version"] == 5
    assert inf["blocksize"] == 4096

    ag = fs.ag_info(0)
    print("AG0: %s count=%s root=%s" % (ag.get("agi_magic"), ag.get("agi_count"),
                                        ag.get("agi_root")))
    assert ag.get("agi_magic") == "XAGI"

    root = fs.inode(fs.rootino)
    print("根 inode: mode=0o%o fmt=%s" % (root.mode, FORMAT_NAME[root.format]))
    assert root.is_dir

    ents = fs.listdir(root)
    print("根目录 %d 项: %s" % (len(ents), [(e.name, e.type_name) for e in ents]))
    assert len(ents) == 1 and ents[0].name == "a.txt"

    f = fs.inode(ents[0].inode)
    print("  a.txt: fmt=%s size=%d extents=%s"
          % (FORMAT_NAME[f.format], f.size, f.extents))
    data = fs.read_file(f)
    print("  读回 %d B: %r" % (len(data), data[:20]))
    assert data == CONTENT, "内容不符: %r" % data[:40]

    assert fs.read_path("/a.txt") == CONTENT

    # ---- b-tree 格式的 inode ----
    bfi = fs.inode(FX["bt_file"])
    print("  big.bin: fmt=%s size=%d extents=%s"
          % (FORMAT_NAME[bfi.format], bfi.size, bfi.extents))
    assert bfi.format == XFS_DINODE_FMT_BTREE, \
        "b-tree inode 未被识别: format=%d" % bfi.format
    assert len(bfi.extents) == 2, "应展开出 2 条记录，实得 %d" % len(bfi.extents)
    assert bfi.extents == [(FX["bt_d0"], 1, 0, 0), (FX["bt_d1"], 1, 1, 0)], \
        "b-tree 展开结果不符: %r" % (bfi.extents,)
    bt_data = fs.read_file(bfi)
    assert len(bt_data) == FX["bt_size"], \
        "b-tree 文件长度不符: %d != %d" % (len(bt_data), FX["bt_size"])
    assert bt_data == FX["bt_expect"], "b-tree 文件内容不符"
    print("  b-tree 读回 %d B 且逐字节正确" % len(bt_data))

    bdi = fs.inode(FX["bt_dir"])
    assert bdi.format == XFS_DINODE_FMT_BTREE
    bents = fs.listdir(bdi)
    print("  b-tree 目录 %d 项: %s" % (len(bents), [e.name for e in bents]))
    assert [e.name for e in bents] == ["b.txt", "big.bin"], \
        "b-tree 目录项不符: %r" % ([e.name for e in bents],)
    assert [e.inode for e in bents] == [FX["file_ino"], FX["bt_file"]], \
        "b-tree 目录 inode 号不符"

    # 位域：手算一组期望值对拍（state 是 bit63 单比特，startoff 54 位）
    lo = (1 << 63) | (0x2A << 9) | 0x1
    hi = (0x5 << 21) | 0x7
    rec = decode_bmbt_rec(struct.pack(">QQ", lo, hi), 0)
    assert rec == ((1 << 43) | 5, 7, 0x2A, 1), "bmbt_rec 位域解码不符: %r" % (rec,)
    assert encode_bmbt_rec(*rec) == struct.pack(">QQ", lo, hi), \
        "bmbt_rec 编解码不互逆"

    # 时间戳偏移：di_mtime 在 40，di_atime 在 32
    home = FX["root_off"]
    img2 = bytearray(img)                 # img 是 bytes，拷一份再改
    struct.pack_into(">I", img2, home + 40, 0x22222222)
    struct.pack_into(">I", img2, home + 32, 0x11111111)
    fs2 = Xfs(Buf(bytes(img2)))
    r2 = fs2.inode(FX["root_ino"])
    assert r2.mtime == 0x22222222 and r2.atime == 0x11111111, \
        "时间戳偏移不对: atime=%#x mtime=%#x" % (r2.atime, r2.mtime)

    print("自检通过")
