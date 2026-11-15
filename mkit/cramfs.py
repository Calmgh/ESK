# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""CramFS v2 文件系统

格式依据 Linux `include/uapi/linux/cramfs_fs.h`、`fs/cramfs/inode.c`
与 `mkfs.cramfs.c`。

已实现：
    · 超级块解析（magic / size / flags / fsid / name / 根 inode）
    · 位域 inode 解包：mode:16 uid:16 / size:24 gid:8 / namelen:6 offset:26
    · 目录遍历（inode 流，4 字节对齐，namelen 存的是 len>>2）
    · 块指针表读取，块长由「下一指针 − 本指针」得出
    · 未压缩块、zlib 压缩块、空洞（块长 0）、DIRECT_PTR 块
    · 按路径查找、递归遍历、读文件

不实现：
    · 写操作
    · 交叉块指针（flags 的 EXT_BLOCK_POINTERS）
    · SHIFTED_ROOT_OFFSET 变体（非 x86 对齐的镜像）

关键格式点（与常见误解不同，已记录）：
    * 块指针的标志位在**指针自身的高位**，不在 inode offset 的低 2 位：
        CRAMFS_BLK_FLAG_UNCOMPRESSED = 1 << 31
        CRAMFS_BLK_FLAG_DIRECT_PTR   = 1 << 30
        CRAMFS_BLK_DIRECT_PTR_SHIFT  = 2
    * 指针报的是「块结束位置」而不是起始位置，所以
        block_start = 前一指针（索引 0 时为指针表之后）
        block_len   = 本指针 - block_start
    * namelen 存的是 len >> 2，还原要 << 2，且名字带 4 字节对齐的 NUL 填充
"""

import struct
import zlib

__all__ = ["Cramfs", "CRAMFS_MAGIC", "CRAMFS_FLAG_SORTED_DIRS"]

CRAMFS_MAGIC = 0x28CD3D45
CRAMFS_SIGNATURE = b"Compressed ROMFS"

# flags
CRAMFS_FLAG_FSID_VERSION_2 = 0x00000001
CRAMFS_FLAG_SORTED_DIRS = 0x00000002
CRAMFS_FLAG_HOLES = 0x00000100
CRAMFS_FLAG_WRONG_SIGNATURE = 0x00000200
CRAMFS_FLAG_SHIFTED_ROOT_OFFSET = 0x00000400
CRAMFS_FLAG_EXT_BLOCK_POINTERS = 0x00000800

# 块指针标志
CRAMFS_BLK_FLAG_UNCOMPRESSED = 1 << 31
CRAMFS_BLK_FLAG_DIRECT_PTR = 1 << 30
CRAMFS_BLK_FLAGS = CRAMFS_BLK_FLAG_UNCOMPRESSED | CRAMFS_BLK_FLAG_DIRECT_PTR
CRAMFS_BLK_DIRECT_PTR_SHIFT = 2

# 位域宽度
MODEL_WIDTH = 16
UID_WIDTH = 16
SIZE_WIDTH = 24
GID_WIDTH = 8
NAMELEN_WIDTH = 6
OFFSET_WIDTH = 26

MAXPATHLEN = ((1 << 6) - 1) << 2

# 文件类型（mode 高 4 位）
S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000

PAGE_SIZE = 4096


class Inode(object):
    __slots__ = ("mode", "uid", "size", "gid", "namelen", "offset",
                 "name", "inode_off", "is_dir", "is_file", "is_link")

    def __init__(self, mode, uid, size, gid, namelen, offset, name, inode_off):
        self.mode = mode
        self.uid = uid
        self.size = size
        self.gid = gid
        self.namelen = namelen
        self.offset = offset
        self.name = name
        self.inode_off = inode_off
        self.is_dir = (mode & S_IFMT) == S_IFDIR
        self.is_file = (mode & S_IFMT) == S_IFREG
        self.is_link = (mode & S_IFMT) == S_IFLNK

    def __repr__(self):
        kind = "DIR" if self.is_dir else ("LNK" if self.is_link else "FILE")
        return "<Inode %s %r %dB>" % (kind, self.name, self.size)


def unpack_inode(raw):
    """12 字节 inode -> (mode, uid, size, gid, namelen, offset)"""
    if len(raw) < 12:
        raise ValueError("inode 需要 12 字节，只有 %d" % len(raw))
    w0, w1, w2 = struct.unpack_from("<III", raw, 0)
    mode = w0 & 0xFFFF
    uid = (w0 >> 16) & 0xFFFF
    size = w1 & 0xFFFFFF
    gid = (w1 >> 24) & 0xFF
    namelen = w2 & 0x3F
    offset = (w2 >> 6) & 0x03FFFFFF
    return mode, uid, size, gid, namelen, offset


class Cramfs(object):
    """CramFS v2 只读"""

    def __init__(self, sub):
        self.sub = sub
        self._read_super()

    # ---------------- 超级块 ----------------
    def _read_super(self):
        s = self.sub.read(0, 76)
        if len(s) < 76:
            raise ValueError("镜像太短，读不到 CramFS 超级块")
        (magic,) = struct.unpack_from("<I", s, 0)
        if magic != CRAMFS_MAGIC:
            raise ValueError("不是 CramFS（magic=0x%08X）" % magic)

        (self.size,) = struct.unpack_from("<I", s, 4)
        (self.flags,) = struct.unpack_from("<I", s, 8)
        (self.future,) = struct.unpack_from("<I", s, 12)
        self.signature = s[16:32]
        (self.crc,) = struct.unpack_from("<I", s, 32)
        (self.edition,) = struct.unpack_from("<I", s, 36)
        (self.blocks,) = struct.unpack_from("<I", s, 40)
        (self.files,) = struct.unpack_from("<I", s, 44)
        self.label = s[48:64].split(b"\x00")[0].decode("utf-8", "replace")

        mode, uid, size, gid, namelen, offset = unpack_inode(s[64:76])
        self.root = Inode(mode, uid, size, gid, namelen, offset, "/", 64)
        if not self.root.is_dir:
            raise ValueError("根 inode 不是目录（mode=0o%o）" % self.root.mode)
        self.root_off = 64

    def info(self):
        return {
            "format": "cramfs",
            "size": self.size,
            "flags": "0x%08X" % self.flags,
            "sorted_dirs": bool(self.flags & CRAMFS_FLAG_SORTED_DIRS),
            "has_holes": bool(self.flags & CRAMFS_FLAG_HOLES),
            "label": self.label,
            "crc": "0x%08X" % self.crc,
            "edition": self.edition,
            "blocks": self.blocks,
            "files": self.files,
            "root_offset": self.root.offset,
        }

    # ---------------- 目录 ----------------
    def listdir(self, inode=None):
        """列目录。inode=None 表示根"""
        ino = inode or self.root
        if not ino.is_dir:
            raise ValueError("不是目录: %r" % ino.name)
        pos = ino.offset << 2
        if pos <= 0:
            return []
        out = []
        # 目录大小 = 该目录所有 inode 记录 + 名字的总字节数
        end = pos + ino.size
        while pos + 12 <= end and pos + 12 <= self.size:
            raw = self.sub.read(pos, 12)
            if len(raw) < 12:
                break
            mode, uid, sz, gid, nl, off = unpack_inode(raw)
            namebytes = nl << 2
            name = b""
            if namebytes:
                name = self.sub.read(pos + 12, namebytes)
            name = name.split(b"\x00")[0].decode("utf-8", "replace")
            out.append(Inode(mode, uid, sz, gid, nl, off, name, pos))
            step = 12 + namebytes
            # 4 字节对齐
            if step % 4:
                step += 4 - (step % 4)
            pos += step
        return out

    def walk(self, inode=None, _depth=0, _max=32):
        prefix = "" if inode is None else inode.name + "/"
        for it in self.listdir(inode):
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            if it.is_dir and _depth < _max and it.offset:
                for sn, si in self.walk(it, _depth + 1, _max):
                    yield prefix + sn, si

    def find(self, pattern):
        return [(p, e) for p, e in self.walk() if pattern.lower() in p.lower()]

    # ---------------- 数据 ----------------
    def _read_block(self, ptr, block_start):
        """按块指针读一个块，返回解压后的字节"""
        uncompressed = bool(ptr & CRAMFS_BLK_FLAG_UNCOMPRESSED)
        direct = bool(ptr & CRAMFS_BLK_FLAG_DIRECT_PTR)
        val = ptr & ~CRAMFS_BLK_FLAGS & 0xFFFFFFFF

        if direct:
            start = val << CRAMFS_BLK_DIRECT_PTR_SHIFT
            if uncompressed:
                n = PAGE_SIZE
            else:
                hdr = self.sub.read(start, 2)
                if len(hdr) < 2:
                    return b""
                (n,) = struct.unpack("<H", hdr)
                start += 2
        else:
            start = block_start
            n = val - start

        if n <= 0 or n > (1 << 20):
            return b""                       # 空洞或异常长度
        raw = self.sub.read(start, n)
        if uncompressed:
            return raw
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return b""

    def read_file(self, inode):
        if inode.is_dir:
            return None
        if inode.is_link:
            # 符号链接：offset 指向链接目标字符串
            return self.sub.read(inode.offset << 2, inode.size)

        nblocks = (inode.size + PAGE_SIZE - 1) // PAGE_SIZE
        if nblocks == 0:
            return b""
        tab = self.sub.read(inode.offset << 2, nblocks * 4)
        if len(tab) < nblocks * 4:
            return b""
        ptrs = list(struct.unpack("<%dI" % nblocks, tab[:nblocks * 4]))

        data_start = (inode.offset << 2) + nblocks * 4
        out = bytearray()
        prev = data_start
        for i, p in enumerate(ptrs):
            blk = self._read_block(p, prev)
            if not (p & CRAMFS_BLK_FLAG_DIRECT_PTR):
                prev = p & ~CRAMFS_BLK_FLAGS & 0xFFFFFFFF
            out += blk
            if len(out) >= inode.size:
                break
        return bytes(out[:inode.size])

    def read_path(self, path):
        cur = None
        for part in [p for p in path.split("/") if p]:
            hit = None
            for it in self.listdir(cur):
                if it.name == part:
                    hit = it
                    break
            if hit is None:
                raise FileNotFoundError(path)
            cur = hit
        return self.read_file(cur) if cur else None


if __name__ == "__main__":
    import io

    class Buf(object):
        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    def build():
        """合成一个最小 CramFS：根目录 + 两个文件（一个未压缩、一个 zlib）"""
        PAGE = 4096
        img = bytearray()
        # ---------------- 布局 ----------------
        # 0      : super (76 B)
        # 76     : 根目录的 inode 流
        # data   : 文件块
        # 先算各段位置
        FILE1 = b"A" * 100                 # 未压缩
        FILE2 = b"B" * 300                 # zlib 压缩（内容重复度高）
        z2 = zlib.compress(FILE2)

        # 根目录 inode 流：先放 2 个文件的 inode + 名字
        def mk(name, mode, size, offset_div4):
            nb = name.encode()
            nl_padded = (len(nb) + 3) & ~3
            namelen_field = nl_padded >> 2
            w0 = (mode & 0xFFFF) | ((0 & 0xFFFF) << 16)
            w1 = (size & 0xFFFFFF) | ((0 & 0xFF) << 24)
            w2 = (namelen_field & 0x3F) | ((offset_div4 & 0x03FFFFFF) << 6)
            raw = struct.pack("<III", w0, w1, w2) + nb + b"\x00" * (nl_padded - len(nb))
            return raw

        # 目录大小先占位，最后回填
        root_dir_off = 76
        # 估算：2 个 inode 记录
        # 名字 "a.txt"(5)->8 字节对齐=8, namelen=2 ; "b.bin"(5)->8
        NAME1 = "a.txt"
        NAME2 = "b.bin"

        def rec_len(nm):
            nb = (len(nm.encode()) + 3) & ~3
            return 12 + nb

        dir_size = rec_len(NAME1) + rec_len(NAME2)
        data_off = root_dir_off + dir_size
        # 对齐到 4
        if data_off % 4:
            data_off += 4 - (data_off % 4)

        f1_off = data_off
        # 文件 1：1 个块，指针表 1 项 + 数据
        f1_ptr_pos = f1_off
        f1_data = f1_off + 4
        f1_end = f1_data + len(FILE1)
        f1_ptr = f1_end | CRAMFS_BLK_FLAG_UNCOMPRESSED     # 指向块结束之后

        f2_off = f1_end
        if f2_off % 4:
            f2_off += 4 - (f2_off % 4)
        f2_ptr_pos = f2_off
        f2_data = f2_off + 4
        f2_end = f2_data + len(z2)
        f2_ptr = f2_end                                        # 压缩，无 UNCOMPRESSED 标志

        total = f2_end
        img = bytearray(total)

        # ---------------- 超级块 ----------------
        struct.pack_into("<I", img, 0, CRAMFS_MAGIC)
        struct.pack_into("<I", img, 4, total)
        struct.pack_into("<I", img, 8, CRAMFS_FLAG_FSID_VERSION_2 | CRAMFS_FLAG_SORTED_DIRS)
        struct.pack_into("<I", img, 12, 0)
        img[16:32] = CRAMFS_SIGNATURE
        struct.pack_into("<I", img, 32, 0)                     # crc
        struct.pack_into("<I", img, 36, 0)                     # edition
        struct.pack_into("<I", img, 40, 2)                     # blocks
        struct.pack_into("<I", img, 44, 2)                     # files
        img[48:64] = b"TESTCRAM".ljust(16, b"\x00")
        # 根 inode @64
        img[64:76] = mk("", S_IFDIR | 0o755, dir_size, root_dir_off >> 2)[:12]

        # ---------------- 目录 ----------------
        buf = bytearray()
        buf += mk(NAME1, S_IFREG | 0o644, len(FILE1), f1_off >> 2)
        buf += mk(NAME2, S_IFREG | 0o644, len(FILE2), f2_off >> 2)
        assert len(buf) == dir_size, "目录长度 %d != 预期 %d" % (len(buf), dir_size)
        img[root_dir_off:root_dir_off + len(buf)] = buf

        # ---------------- 文件数据 ----------------
        struct.pack_into("<I", img, f1_ptr_pos, f1_ptr)
        img[f1_data:f1_data + len(FILE1)] = FILE1

        struct.pack_into("<I", img, f2_ptr_pos, f2_ptr)
        img[f2_data:f2_data + len(z2)] = z2

        return bytes(img), FILE1, FILE2

    img, FILE1, FILE2 = build()
    fs = Cramfs(Buf(img))
    info = fs.info()
    print("CramFS: size=%d flags=%s label=%r files=%d blocks=%d"
          % (info["size"], info["flags"], info["label"], info["files"], info["blocks"]))

    ents = fs.listdir()
    print("根目录 %d 项: %s" % (len(ents), [e.name for e in ents]))
    assert len(ents) == 2, "根目录应有 2 项，实际 %d" % len(ents)

    a = [e for e in ents if e.name == "a.txt"][0]
    b = [e for e in ents if e.name == "b.bin"][0]
    print("  a.txt size=%d  b.bin size=%d" % (a.size, b.size))
    assert a.size == len(FILE1) and b.size == len(FILE2)

    da = fs.read_file(a)
    db = fs.read_file(b)
    print("  a.txt 读回 %d B（未压缩块）" % len(da))
    print("  b.bin 读回 %d B（zlib 块）" % len(db))
    assert da == FILE1, "未压缩文件内容不符"
    assert db == FILE2, "zlib 文件内容不符（长度 %d vs %d）" % (len(db), len(FILE2))

    got = fs.read_path("/b.bin")
    assert got == FILE2, "read_path 结果不符"

    print("自检通过")
