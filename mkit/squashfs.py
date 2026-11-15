# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""SquashFS v4 文件系统

格式依据 squashfs-tools 的 `squashfs_fs.h` 与 Linux `fs/squashfs/`。

已实现：
    · 超级块（小端 `hsqs` / 大端 `sqsh` 两种魔数）
    · 元数据块（2 字节头，bit15=未压缩，低 15 位=长度，单块上限 8 KiB）
    · inode 表与 inode 引用 `(block << 16) | offset`
    · 14 种 inode：基础版 DIR/REG/SYMLINK/BLKDEV/CHRDEV/FIFO/SOCKET
      与扩展版 LDIR/LREG/LSYMLINK/LBLKDEV/LCHRDEV/LFIFO/LSOCKET
    · 目录表（dir_header + dir_entry，inode 号差值编码）
    · 文件数据块（含稀疏块、跨块）、片段（fragment）尾块
    · id 表、片段表（经 u64 指针数组定位元数据块）
    · 按路径查找、递归遍历、读文件

压缩算法支持：
    · gzip(1)  —— zlib
    · xz(4)    —— lzma
    · 其余（lzma 2 / lzo 3 / lz4 5 / zstd 6）抛 NotImplementedError，
      并说明所需依赖，不做假支持

不实现：
    · 写操作
    · xattr 内容读取（只记录 xattr_idx）
    · 导出表 / 查找表的加速索引（直接线性遍历目录表）
"""

import struct
import zlib

try:
    import lzma as _lzma
except ImportError:
    _lzma = None

__all__ = ["Squashfs", "SQUASHFS_MAGIC_LE", "SQUASHFS_MAGIC_BE", "COMPRESSORS"]

SQUASHFS_MAGIC_LE = 0x73717368        # 小端读出的 "hsqs"
SQUASHFS_MAGIC_BE = 0x68737173        # 大端读出的 "sqsh"

SUPERBLOCK_LEN = 96
METADATA_MAX = 8192

# 压缩器
COMPRESSORS = {
    1: "gzip",
    2: "lzma",
    3: "lzo",
    4: "xz",
    5: "lz4",
    6: "zstd",
}

# inode 类型
T_DIR = 1
T_REG = 2
T_SYMLINK = 3
T_BLKDEV = 4
T_CHRDEV = 5
T_FIFO = 6
T_SOCKET = 7
T_LDIR = 8
T_LREG = 9
T_LSYMLINK = 10
T_LBLKDEV = 11
T_LCHRDEV = 12
T_LFIFO = 13
T_LSOCKET = 14

INODE_TYPE_NAME = {
    T_DIR: "dir", T_REG: "file", T_SYMLINK: "symlink",
    T_BLKDEV: "blkdev", T_CHRDEV: "chrdev", T_FIFO: "fifo", T_SOCKET: "socket",
    T_LDIR: "dir", T_LREG: "file", T_LSYMLINK: "symlink",
    T_LBLKDEV: "blkdev", T_LCHRDEV: "chrdev", T_LFIFO: "fifo", T_LSOCKET: "socket",
}

NO_FRAGMENT = 0xFFFFFFFF
BLOCK_COMPRESSED = 1 << 24            # 块大小字段的 bit24 = 未压缩标志(0=压缩)
BLOCK_SIZE_MASK = 0xFFFFFF


class SqInode(object):
    __slots__ = ("ino", "type_id", "mode", "uid_idx", "gid_idx", "mtime",
                 "inode_number", "start_block", "file_size", "block_offset",
                 "parent_inode", "nlink", "fragment", "block_sizes",
                 "symlink_target", "rdev", "xattr_idx", "dir_block",
                 "dir_offset")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def type_name(self):
        return INODE_TYPE_NAME.get(self.type_id, "?")

    @property
    def is_dir(self):
        return self.type_id in (T_DIR, T_LDIR)

    @property
    def is_file(self):
        return self.type_id in (T_REG, T_LREG)

    @property
    def is_symlink(self):
        return self.type_id in (T_SYMLINK, T_LSYMLINK)

    def __repr__(self):
        return "<SqInode %d %s mode=0o%o size=%s>" % (
            self.ino, self.type_name, self.mode or 0, self.file_size)


class Squashfs(object):
    """SquashFS v4 只读"""

    def __init__(self, sub):
        self.sub = sub
        self._meta_cache = {}
        self._read_superblock()

    # ---------------- 超级块 ----------------
    def _read_superblock(self):
        s = self.sub.read(0, SUPERBLOCK_LEN)
        if len(s) < SUPERBLOCK_LEN:
            raise ValueError("镜像太短，读不到 SquashFS 超级块")

        le_magic = struct.unpack_from("<I", s, 0)[0]
        if le_magic == SQUASHFS_MAGIC_LE:
            self.endian = "<"
        else:
            be_magic = struct.unpack_from(">I", s, 0)[0]
            if be_magic == SQUASHFS_MAGIC_LE:
                self.endian = ">"
            else:
                raise ValueError("不是 SquashFS（magic=0x%08X）" % le_magic)

        e = self.endian
        u16 = lambda o: struct.unpack_from(e + "H", s, o)[0]
        u32 = lambda o: struct.unpack_from(e + "I", s, o)[0]
        u64 = lambda o: struct.unpack_from(e + "Q", s, o)[0]

        self.inodes = u32(4)
        self.mkfs_time = u32(8)
        self.block_size = u32(12)
        self.fragments = u32(16)
        self.compression = u16(20)
        self.block_log = u16(22)
        self.flags = u16(24)
        self.no_ids = u16(26)
        self.s_major = u16(28)
        self.s_minor = u16(30)
        self.root_inode = u64(32)
        self.bytes_used = u64(40)
        self.id_table_start = u64(48)
        self.xattr_id_table_start = u64(56)
        self.inode_table_start = u64(64)
        self.directory_table_start = u64(72)
        self.fragment_table_start = u64(80)
        self.lookup_table_start = u64(88)

        if self.s_major != 4:
            raise ValueError("只支持 SquashFS v4（本镜像 v%d.%d）"
                             % (self.s_major, self.s_minor))
        self.compressor = COMPRESSORS.get(self.compression, "?")

    def info(self):
        return {
            "format": "squashfs",
            "version": "%d.%d" % (self.s_major, self.s_minor),
            "endian": "little" if self.endian == "<" else "big",
            "block_size": self.block_size,
            "compression": self.compressor,
            "compression_id": self.compression,
            "inodes": self.inodes,
            "fragments": self.fragments,
            "no_ids": self.no_ids,
            "bytes_used": self.bytes_used,
            "root_inode": self.root_inode,
            "mkfs_time": self.mkfs_time,
            "inode_table_start": self.inode_table_start,
            "directory_table_start": self.directory_table_start,
            "fragment_table_start": self.fragment_table_start,
            "id_table_start": self.id_table_start,
        }

    # ---------------- 解压 ----------------
    def _decompress(self, data, expected_max):
        c = self.compression
        if c == 1:                                  # gzip
            try:
                return zlib.decompress(data)
            except zlib.error as ex:
                raise ValueError("gzip 解压失败: %s" % ex)
        if c == 4:                                  # xz
            if _lzma is None:
                raise NotImplementedError("xz 需要 Python 的 lzma 模块")
            try:
                return _lzma.decompress(data, format=_lzma.FORMAT_XZ)
            except Exception:
                # 某些镜像用 raw 流
                return _lzma.decompress(data)
        raise NotImplementedError(
            "压缩算法 %s(id=%d) 需要额外依赖，标准库无法解压。"
            "gzip 与 xz 可直接用。" % (self.compressor, c))

    # ---------------- 元数据块 ----------------
    def _meta_block(self, block_start):
        """读一个元数据块，返回 (解压后数据, 该块在镜像里的总长)"""
        hit = self._meta_cache.get(block_start)
        if hit is not None:
            return hit
        hdr = self.sub.read(block_start, 2)
        if len(hdr) < 2:
            raise ValueError("元数据块头读不到 @%d" % block_start)
        (v,) = struct.unpack_from(self.endian + "H", hdr, 0)
        length = v & 0x7FFF
        uncompressed = bool(v & 0x8000)
        if length == 0:
            out = b""
        else:
            raw = self.sub.read(block_start + 2, length)
            out = raw if uncompressed else self._decompress(raw, METADATA_MAX)
        total = 2 + length
        self._meta_cache[block_start] = (out, total)
        return out, total

    def _meta_stream(self, block_start, offset, length):
        """从 (block_start, offset) 起跨块读 length 字节"""
        out = b""
        cur = block_start
        first = offset
        while len(out) < length:
            data, total = self._meta_block(cur)
            if first:
                if first >= len(data):
                    break
                out += data[first:]
                first = 0
            else:
                out += data
            cur += total
            if total <= 2 and len(out) < length:
                break
        return out[:length]

    # ---------------- inode ----------------
    def inode(self, ino_ref):
        """按 inode 引用读 inode；引用是 (block<<16)|offset"""
        blk = (ino_ref >> 16) & 0xFFFFFFFFFFFF
        off = ino_ref & 0xFFFF
        base = self.inode_table_start + blk

        # 先把公共头读出来（16 字节）
        head = self._meta_stream(base, off, 16)
        if len(head) < 16:
            raise ValueError("inode 头读不到（ref=0x%X）" % ino_ref)
        e = self.endian
        type_id, mode, uid_idx, gid_idx, mtime, inum = struct.unpack_from(
            e + "HHHHII", head, 0)

        kw = dict(ino=ino_ref, type_id=type_id, mode=mode, uid_idx=uid_idx,
                  gid_idx=gid_idx, mtime=mtime, inode_number=inum,
                  block_sizes=[], file_size=0, start_block=0, block_offset=0,
                  parent_inode=0, nlink=1, fragment=NO_FRAGMENT,
                  symlink_target=None, rdev=0, xattr_idx=0xFFFFFFFF,
                  dir_block=blk, dir_offset=off)

        def more(n, at):
            return self._meta_stream(base, off + at, n)

        if type_id == T_DIR:
            b = more(16, 16)
            sb, nlink, fsize, boff, parent = struct.unpack_from(e + "IIHHI", b, 0)
            kw.update(start_block=sb, nlink=nlink, file_size=fsize,
                      block_offset=boff, parent_inode=parent)

        elif type_id == T_REG:
            b = more(16, 16)
            sb, frag, boff, fsize = struct.unpack_from(e + "IIII", b, 0)
            nblk = (fsize + self.block_size - 1) // self.block_size
            if frag != NO_FRAGMENT and fsize % self.block_size:
                nblk -= 1
            nblk = max(0, nblk)
            sizes = []
            if nblk:
                raw = more(nblk * 4, 32)
                sizes = list(struct.unpack_from(e + "%dI" % nblk, raw, 0))
            kw.update(start_block=sb, fragment=frag, block_offset=boff,
                      file_size=fsize, block_sizes=sizes)

        elif type_id == T_SYMLINK:
            b = more(8, 16)
            nlink, slen = struct.unpack_from(e + "II", b, 0)
            tgt = more(slen, 24)
            kw.update(nlink=nlink, symlink_target=tgt, file_size=slen)

        elif type_id in (T_BLKDEV, T_CHRDEV):
            b = more(8, 16)
            nlink, rdev = struct.unpack_from(e + "II", b, 0)
            kw.update(nlink=nlink, rdev=rdev)

        elif type_id in (T_FIFO, T_SOCKET):
            b = more(4, 16)
            (nlink,) = struct.unpack_from(e + "I", b, 0)
            kw.update(nlink=nlink)

        elif type_id == T_LDIR:
            b = more(24, 16)
            nlink, fsize, sb, parent, idx_count, boff, xattr = struct.unpack_from(
                e + "IIIIHHI", b, 0)
            kw.update(nlink=nlink, file_size=fsize, start_block=sb,
                      parent_inode=parent, block_offset=boff, xattr_idx=xattr)

        elif type_id == T_LREG:
            b = more(40, 16)
            sb, fsize, sparse, nlink, frag, boff, xattr = struct.unpack_from(
                e + "QQQIIII", b, 0)
            nblk = (fsize + self.block_size - 1) // self.block_size
            if frag != NO_FRAGMENT and fsize % self.block_size:
                nblk -= 1
            nblk = max(0, nblk)
            sizes = []
            if nblk:
                raw = more(nblk * 4, 56)
                sizes = list(struct.unpack_from(e + "%dI" % nblk, raw, 0))
            kw.update(start_block=sb, file_size=fsize, nlink=nlink,
                      fragment=frag, block_offset=boff, block_sizes=sizes,
                      xattr_idx=xattr)

        elif type_id == T_LSYMLINK:
            b = more(8, 16)
            nlink, slen = struct.unpack_from(e + "II", b, 0)
            tgt = more(slen, 24)
            xb = more(4, 24 + slen)
            (xattr,) = struct.unpack_from(e + "I", xb, 0)
            kw.update(nlink=nlink, symlink_target=tgt, file_size=slen,
                      xattr_idx=xattr)

        elif type_id in (T_LBLKDEV, T_LCHRDEV):
            b = more(12, 16)
            nlink, rdev, xattr = struct.unpack_from(e + "III", b, 0)
            kw.update(nlink=nlink, rdev=rdev, xattr_idx=xattr)

        elif type_id in (T_LFIFO, T_LSOCKET):
            b = more(8, 16)
            nlink, xattr = struct.unpack_from(e + "II", b, 0)
            kw.update(nlink=nlink, xattr_idx=xattr)

        else:
            raise ValueError("未知 inode 类型 %d（ref=0x%X）" % (type_id, ino_ref))

        return SqInode(**kw)

    # ---------------- 目录 ----------------
    def listdir(self, inode=None):
        if inode is None:
            inode = self.inode(self.root_inode)
        if not inode.is_dir:
            raise ValueError("不是目录: %r" % inode)

        e = self.endian
        # 目录数据在 directory_table_start + start_block 的元数据流里，
        # 从 block_offset 起，长度约 file_size
        base = self.directory_table_start + (inode.start_block or 0)
        data = self._meta_stream(base, inode.block_offset or 0,
                                 max(inode.file_size or 0, 3))

        out = []
        pos = 0
        n = len(data)
        while pos + 12 <= n:
            count, start_block, inum = struct.unpack_from(e + "III", data, pos)
            pos += 12
            cnt = count + 1
            if cnt > 256:
                break
            for _ in range(cnt):
                if pos + 8 > n:
                    break
                off, delta, typ, size = struct.unpack_from(e + "HhHH", data, pos)
                pos += 8
                namelen = size + 1
                name = data[pos:pos + namelen]
                pos += namelen
                if not name:
                    continue
                real_ino = (inum + delta) & 0xFFFFFFFF
                if name in (b".", b".."):
                    continue
                ref = ((start_block or 0) << 16) | off
                out.append((name.decode("utf-8", "replace"), typ, ref, real_ino))
        return out

    def walk(self, inode=None, _depth=0, _max=64):
        ino = inode or self.inode(self.root_inode)
        prefix = "" if inode is None else ""
        try:
            ents = self.listdir(ino)
        except Exception:
            return
        for name, typ, ref, real_ino in ents:
            yield prefix + name, typ, ref, real_ino
            if typ in (T_DIR, T_LDIR) and _depth < _max:
                try:
                    child = self.inode(ref)
                except Exception:
                    continue
                for sn, st, sr, si in self.walk(child, _depth + 1, _max):
                    yield prefix + name + "/" + sn, st, sr, si

    def find(self, pattern):
        return [(p, t, r, i) for p, t, r, i in self.walk()
                if pattern.lower() in p.lower()]

    def lookup_path(self, path):
        cur = self.inode(self.root_inode)
        for part in [p for p in path.split("/") if p]:
            hit = None
            for name, typ, ref, real_ino in self.listdir(cur):
                if name == part:
                    hit = ref
                    break
            if hit is None:
                raise FileNotFoundError(path)
            cur = self.inode(hit)
        return cur

    # ---------------- 片段表 ----------------
    def _fragment_entry(self, idx):
        """fragment 表：指针数组每项 u64，指向一个含 512 条 16 字节记录的元数据块"""
        if idx >= self.fragments:
            raise IndexError("片段号越界: %d >= %d" % (idx, self.fragments))
        e = self.endian
        ptr_off = self.fragment_table_start + (idx // 512) * 8
        (blk,) = struct.unpack_from(e + "Q", self.sub.read(ptr_off, 8), 0)
        data, _ = self._meta_block(blk)
        at = (idx % 512) * 16
        sb, size, unused = struct.unpack_from(e + "QII", data, at)
        return sb, size

    # ---------------- 读文件 ----------------
    def read_file(self, inode):
        if inode.is_dir:
            return None
        if inode.is_symlink:
            return inode.symlink_target or b""
        if not inode.is_file:
            return None

        fsize = inode.file_size or 0
        if fsize == 0:
            return b""
        out = bytearray()
        pos = inode.start_block or 0
        remaining = fsize
        for sz in (inode.block_sizes or []):
            if remaining <= 0:
                break
            if sz == 0:                                  # 稀疏块
                take = min(self.block_size, remaining)
                out += b"\x00" * take
                remaining -= take
                continue
            uncompressed = bool(sz & BLOCK_COMPRESSED)
            length = sz & BLOCK_SIZE_MASK
            raw = self.sub.read(pos, length)
            pos += length
            data = raw if uncompressed else self._decompress(raw, self.block_size)
            take = min(len(data), remaining)
            out += data[:take]
            remaining -= take

        # 片段尾块
        if remaining > 0 and inode.fragment != NO_FRAGMENT:
            sb, fsz = self._fragment_entry(inode.fragment)
            raw = self.sub.read(sb, fsz)
            data = raw if (fsz & BLOCK_COMPRESSED) else self._decompress(raw, self.block_size)
            off = inode.block_offset or 0
            out += data[off:off + remaining]
            remaining = 0

        return bytes(out[:fsize])

    def read_path(self, path):
        return self.read_file(self.lookup_path(path))


if __name__ == "__main__":
    class Buf(object):
        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    def meta_block(payload, compress=True):
        """打包一个元数据块：2 字节头 + 可能的压缩数据"""
        if compress:
            comp = zlib.compress(payload)
            if len(comp) < len(payload):
                return struct.pack("<H", len(comp)) + comp, len(comp)
        return struct.pack("<H", len(payload) | 0x8000) + payload, len(payload)

    def build():
        """合成 SquashFS v4：根目录 + 1 个 gzip 压缩的文件 a.txt"""
        BLK = 4096
        CONTENT = b"Hello SquashFS v4!\n" * 10          # 200 字节，单块
        comp = zlib.compress(CONTENT)

        # ---- 先算目录表（它只依赖 inode 偏移，不依赖长度）----
        root_inode_off = 0
        file_inode_off = 32
        root_ino_num = 1
        file_ino_num = 2

        def drec(offset, delta, typ, name):
            nb = name.encode()
            return struct.pack("<HhHH", offset, delta, typ, len(nb) - 1) + nb

        dir_payload = b""
        dir_payload += struct.pack("<III", 0, 0, root_ino_num)
        dir_payload += drec(root_inode_off, 0, T_DIR, ".")
        dir_payload += struct.pack("<III", 0, 0, root_ino_num)
        dir_payload += drec(root_inode_off, 0, T_DIR, "..")
        dir_payload += struct.pack("<III", 0, 0, file_ino_num)
        dir_payload += drec(file_inode_off, 0, T_REG, "a.txt")
        dir_size = len(dir_payload)

        # ---- 布局（数据块紧跟超级块）----
        sb_len = 96
        data_off = sb_len
        comp = zlib.compress(CONTENT)

        # ---- inode（此时 data_off 与 dir_size 都是已知量）----
        root_inode = struct.pack(
            "<HHHHII", T_DIR, 0o040755, 0, 0, 0x5F000000, root_ino_num)
        root_inode += struct.pack("<IIHHI", 0, 3, dir_size, 0, root_ino_num)

        file_inode = struct.pack(
            "<HHHHII", T_REG, 0o100644, 0, 0, 0x5F000000, file_ino_num)
        file_inode += struct.pack("<IIII", data_off, NO_FRAGMENT, 0, len(CONTENT))
        file_inode += struct.pack("<I", len(comp))

        inode_payload = root_inode + file_inode
        inode_meta, _ = meta_block(inode_payload, compress=True)
        dir_meta, _ = meta_block(dir_payload, compress=True)
        id_payload = struct.pack("<I", 0)
        id_meta, _ = meta_block(id_payload, compress=True)

        data_end = data_off + len(comp)
        inode_off = data_end
        inode_end = inode_off + len(inode_meta)
        dir_off = inode_end
        dir_end = dir_off + len(dir_meta)
        id_meta_off = dir_end
        id_meta_end = id_meta_off + len(id_meta)
        id_ptr_off = id_meta_end
        total = id_ptr_off + 8

        img = bytearray(total)
        struct.pack_into("<I", img, 0, SQUASHFS_MAGIC_LE)
        struct.pack_into("<I", img, 4, 2)
        struct.pack_into("<I", img, 8, 0x5F000000)
        struct.pack_into("<I", img, 12, BLK)
        struct.pack_into("<I", img, 16, 0)
        struct.pack_into("<H", img, 20, 1)
        struct.pack_into("<H", img, 22, 12)
        struct.pack_into("<H", img, 24, 0)
        struct.pack_into("<H", img, 26, 1)
        struct.pack_into("<H", img, 28, 4)
        struct.pack_into("<H", img, 30, 0)
        struct.pack_into("<Q", img, 32, 0)
        struct.pack_into("<Q", img, 40, total)
        struct.pack_into("<Q", img, 48, id_ptr_off)
        struct.pack_into("<Q", img, 56, 0xFFFFFFFFFFFFFFFF)
        struct.pack_into("<Q", img, 64, inode_off)
        struct.pack_into("<Q", img, 72, dir_off)
        struct.pack_into("<Q", img, 80, 0xFFFFFFFFFFFFFFFF)
        struct.pack_into("<Q", img, 88, 0xFFFFFFFFFFFFFFFF)

        img[data_off:data_off + len(comp)] = comp
        img[inode_off:inode_off + len(inode_meta)] = inode_meta
        img[dir_off:dir_off + len(dir_meta)] = dir_meta
        img[id_meta_off:id_meta_off + len(id_meta)] = id_meta
        struct.pack_into("<Q", img, id_ptr_off, id_meta_off)

        return bytes(img), CONTENT

    img, CONTENT = build()
    fs = Squashfs(Buf(img))
    inf = fs.info()
    print("SquashFS: v%s %s block=%d comp=%s inodes=%d"
          % (inf["version"], inf["endian"], inf["block_size"],
             inf["compression"], inf["inodes"]))
    assert inf["compression"] == "gzip"

    root = fs.inode(fs.root_inode)
    print("根 inode: type=%s mode=0o%o dir_size=%d"
          % (root.type_name, root.mode, root.file_size))
    assert root.is_dir

    ents = fs.listdir(root)
    print("根目录 %d 项: %s" % (len(ents), [e[0] for e in ents]))
    assert len(ents) == 1 and ents[0][0] == "a.txt", ents

    name, typ, ref, inum = ents[0]
    f = fs.inode(ref)
    print("  a.txt: type=%s size=%d blocks=%s" % (f.type_name, f.file_size, f.block_sizes))
    data = fs.read_file(f)
    print("  读回 %d B: %r..." % (len(data), data[:20]))
    assert data == CONTENT, "内容不符（%d vs %d）" % (len(data), len(CONTENT))

    assert fs.read_path("/a.txt") == CONTENT
    print("自检通过")
