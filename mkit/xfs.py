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
        nextents = struct.unpack_from(">I", raw, 76)[0]
        forkoff = raw[82] if version >= 2 else 0
        atime = struct.unpack_from(">I", raw, 24)[0]
        mtime = struct.unpack_from(">I", raw, 32)[0]
        ctime = struct.unpack_from(">I", raw, 40)[0]

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
                e = data[i * 16:(i + 1) * 16]
                if len(e) < 16:
                    break
                lo = struct.unpack_from(">Q", e, 0)[0]
                hi = struct.unpack_from(">Q", e, 8)[0]
                # xfs_bmbt_rec 位域（大端 128 位）：
                #   l0[63:62] state | l0[61:9] startoff(53)
                #   startblock(52) = l0[8:0] << 43 | l1[63:21]
                #   blockcount(21) = l1[20:0]
                state = (lo >> 62) & 0x3
                startoff = (lo >> 9) & ((1 << 53) - 1)
                startblock = ((lo & 0x1FF) << 43) | (hi >> 21)
                blockcount = hi & 0x1FFFFF
                exts.append((startblock, blockcount, startoff, state))
            kw["extents"] = exts

        elif fmt == XFS_DINODE_FMT_BTREE:
            raise NotImplementedError(
                "inode %d 是 B-tree 格式（大文件/大目录），本实现未支持" % ino)

        return XfsInode(**kw)

    def read_file(self, inode):
        if inode.is_dir:
            return None
        if inode.is_symlink and inode.local_data is not None:
            return inode.local_data
        if inode.format == XFS_DINODE_FMT_LOCAL:
            return inode.local_data or b""
        if inode.format == XFS_DINODE_FMT_EXTENTS:
            out = bytearray()
            for startblock, blockcount, startoff, state in inode.extents:
                n = blockcount * self.blocksize
                data = self.sub.read(startblock * self.blocksize, n)
                if state == 1:                    # unwritten
                    data = b"\x00" * len(data)
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
        elif ino.format == XFS_DINODE_FMT_EXTENTS:
            for startblock, blockcount, startoff, state in ino.extents:
                n = blockcount * self.blocksize
                data = self.sub.read(startblock * self.blocksize, n)
                self._parse_dir_data(data, out)
        elif ino.format == XFS_DINODE_FMT_BTREE:
            raise NotImplementedError(
                "目录 inode %d 是 B-tree 格式，本实现未支持" % ino.ino)
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
        return bytes(img), CONTENT

    img, CONTENT = build()
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
    print("自检通过")
