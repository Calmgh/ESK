# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""Linux ROMFS 文件系统

格式依据 Linux `fs/romfs/super.c` 与 `fs/romfs/internal.h`。

已实现：
    · 超级块（"-rom1fs-" 魔数、总大小、校验和、卷名）
    · inode 头（next / spec_info / size / checksum / name）
    · 文件类型判定（spec_info & 7）
    · 目录遍历（同级链表，靠 next 指针串联）
    · 普通文件读取、符号链接目标读取
    · 硬链接解析（spec_dst 指向目标 inode 偏移）
    · 全卷校验和验证（4 字节大端字求和应为 0）
    · 按路径查找、递归遍历

不实现：
    · 写操作
    · 设备节点的内容读取（只报类型与主次设备号）

格式要点：
    * 所有整数是**大端**
    * 名字 NUL 结尾并按 4 字节对齐，对齐填充的字节**计入 next 偏移**，
      所以解析时必须 `(len(name) + 1 + 3) & ~3` 才是下一段的真实位置
    * 每个文件头前 4 字节是 `next`，链接到同目录的下一个兄弟；
      0 表示同目录结束
    * 目录的第一个子项紧跟在本目录头 + 对齐名字之后
    * 校验和：把整卷按 4 字节大端读成 u32 求和，结果应为 0
"""

import struct

__all__ = ["Romfs", "ROMFS_MAGIC", "romfs_checksum", "ROMFS_TYPE_DIR"]

ROMFS_MAGIC = b"-rom1fs-"
HEADER_LEN = 16
INO_HDR_LEN = 16

# spec_info & 7
ROMFS_TYPE_HARDLINK = 0
ROMFS_TYPE_DIR = 1
ROMFS_TYPE_REG = 2
ROMFS_TYPE_SYMLINK = 3
ROMFS_TYPE_BLKDEV = 4
ROMFS_TYPE_CHRDEV = 5
ROMFS_TYPE_SOCKET = 6
ROMFS_TYPE_FIFO = 7

TYPE_NAME = {
    ROMFS_TYPE_HARDLINK: "hardlink",
    ROMFS_TYPE_DIR: "dir",
    ROMFS_TYPE_REG: "file",
    ROMFS_TYPE_SYMLINK: "symlink",
    ROMFS_TYPE_BLKDEV: "blkdev",
    ROMFS_TYPE_CHRDEV: "chrdev",
    ROMFS_TYPE_SOCKET: "socket",
    ROMFS_TYPE_FIFO: "fifo",
}

ROMFS_EXEC = 0x8


def _pad4(n):
    """名字长度 -> 4 字节对齐后的占用（含结尾 NUL）"""
    return (n + 1 + 3) & ~3


def romfs_checksum(data):
    """整卷校验和：按 4 字节大端求和，正常镜像应为 0"""
    total = 0
    n = len(data) & ~3
    for i in range(0, n, 4):
        total = (total + struct.unpack_from(">I", data, i)[0]) & 0xFFFFFFFF
    return total


class RomEntry(object):
    __slots__ = ("name", "next", "spec_info", "spec_dst", "size", "checksum",
                 "offset", "data_off")

    def __init__(self, name, next_off, spec_info, spec_dst, size, checksum,
                 offset, data_off):
        self.name = name
        self.next = next_off
        self.spec_info = spec_info
        self.spec_dst = spec_dst
        self.size = size
        self.checksum = checksum
        self.offset = offset
        self.data_off = data_off

    @property
    def type_id(self):
        return self.spec_info & 7

    @property
    def type_name(self):
        return TYPE_NAME.get(self.type_id, "?")

    @property
    def is_dir(self):
        return self.type_id == ROMFS_TYPE_DIR

    @property
    def is_file(self):
        return self.type_id == ROMFS_TYPE_REG

    @property
    def is_symlink(self):
        return self.type_id == ROMFS_TYPE_SYMLINK

    @property
    def is_hardlink(self):
        return self.type_id == ROMFS_TYPE_HARDLINK

    @property
    def executable(self):
        return bool(self.spec_info & ROMFS_EXEC)

    def __repr__(self):
        return "<RomEntry %s %r %dB>" % (self.type_name, self.name, self.size)


class Romfs(object):
    """ROMFS 只读"""

    def __init__(self, sub):
        self.sub = sub
        self._read_header()

    def _read_header(self):
        h = self.sub.read(0, HEADER_LEN)
        if len(h) < HEADER_LEN:
            raise ValueError("镜像太短，读不到 ROMFS 头")
        if h[:8] != ROMFS_MAGIC:
            raise ValueError("不是 ROMFS（魔数 %r）" % h[:8])

        (self.size,) = struct.unpack_from(">I", h, 8)
        (self.checksum,) = struct.unpack_from(">I", h, 12)

        # 卷名：NUL 结尾 + 4 字节对齐
        raw = self.sub.read(HEADER_LEN, 256)
        z = raw.find(b"\x00")
        if z < 0:
            z = 0
        self.label = raw[:z].decode("utf-8", "replace")
        self.root_off = HEADER_LEN + _pad4(z) if z else HEADER_LEN + 4

    def info(self):
        return {
            "format": "romfs",
            "size": self.size,
            "checksum": "0x%08X" % self.checksum,
            "label": self.label,
            "root_offset": self.root_off,
        }

    def verify_checksum(self):
        """整卷校验和应为 0；只对前 size 字节算"""
        data = self.sub.read(0, self.size)
        return romfs_checksum(data) == 0

    # ---------------- inode ----------------
    def _read_entry(self, off):
        raw = self.sub.read(off, INO_HDR_LEN)
        if len(raw) < INO_HDR_LEN:
            return None
        nxt, spec_info, size, cks = struct.unpack_from(">IIII", raw, 0)
        name_raw = self.sub.read(off + INO_HDR_LEN, 256)
        z = name_raw.find(b"\x00")
        if z < 0:
            z = 0
        name = name_raw[:z].decode("utf-8", "replace")
        data_off = off + INO_HDR_LEN + _pad4(z) if z else off + INO_HDR_LEN + 4
        return RomEntry(name, nxt, spec_info, size if False else 0, size, cks,
                        off, data_off)

    def entry_at(self, off):
        """读某个偏移上的 inode（含 spec_dst 修正）"""
        e = self._read_entry(off)
        if e is None:
            return None
        # spec_dst 只在非目录、非普通文件时有意义；
        # 对普通文件/目录，第 8 字节起已经当作 size 读了 —— romfs 的 inode 是
        # next / spec_info / size / checksum，spec_dst 与 size 共用第 3 个 u32：
        #   目录/普通文件：该字段是 size（数据长度）
        #   硬链接/设备：  该字段是 spec_dst
        raw = self.sub.read(off + 8, 4)
        if len(raw) == 4:
            (field,) = struct.unpack(">I", raw)
            if e.type_id in (ROMFS_TYPE_HARDLINK, ROMFS_TYPE_BLKDEV,
                             ROMFS_TYPE_CHRDEV):
                e.spec_dst = field
                e.size = 0
            else:
                e.spec_dst = 0
        return e

    # ---------------- 目录 ----------------
    def listdir(self, entry=None):
        """列目录。entry=None 表示根"""
        e = entry if entry is not None else self.entry_at(self.root_off)
        if e is None:
            return []
        if not e.is_dir:
            raise ValueError("不是目录: %r" % e.name)

        out = []
        pos = e.data_off          # 第一个子项紧跟在目录头之后
        seen = set()
        while pos and pos not in seen:
            seen.add(pos)
            child = self.entry_at(pos)
            if child is None or not child.name:
                break
            out.append(child)
            pos = child.next
        return out

    def walk(self, entry=None, _depth=0, _max=32):
        prefix = "" if entry is None else entry.name + "/"
        for it in self.listdir(entry):
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            real = self.resolve(it)
            if real.is_dir and _depth < _max:
                for sn, si in self.walk(real, _depth + 1, _max):
                    yield prefix + sn, si

    def resolve(self, entry):
        """硬链接 -> 目标 inode；其他原样返回"""
        hop = 0
        e = entry
        seen = set()
        while e.is_hardlink and hop < 8 and e.offset not in seen:
            seen.add(e.offset)
            t = self.entry_at(e.spec_dst)
            if t is None:
                break
            e = t
            hop += 1
        return e

    def find(self, pattern):
        return [(p, e) for p, e in self.walk() if pattern.lower() in p.lower()]

    # ---------------- 数据 ----------------
    def read_file(self, entry):
        e = self.resolve(entry)
        if e.is_dir:
            return None
        if e.is_file or e.is_symlink:
            return self.sub.read(e.data_off, e.size)
        return None            # 设备/套接字/fifo 无内容

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
            cur = self.resolve(hit)
        return self.read_file(cur) if cur else None


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
        """合成 ROMFS：根目录含 hello.txt 与 sub/（sub 内有 deep.txt）"""
        WORD = 4

        def pad(n):
            return (n + 1 + 3) & ~3

        def ino(name, spec_info, size_field, data, next_off):
            nb = name.encode()
            body = data
            # 目录/普通文件的 size 字段就是 len(body)；硬链接/设备用 spec_dst
            return (struct.pack(">IIII", next_off, spec_info, size_field,
                                _cks_placeholder())
                    + nb + b"\x00" * (pad(len(nb)) - len(nb)) + body)

        def _cks_placeholder():
            return 0

        # ---- 先排布局 ----
        # 0..16           : 超级块头
        # 16..            : 卷名 "ESKVOL\0" -> pad 1 个? "ESKVOL"=6 -> (6+1+3)&~3 = 8
        LABEL = "ESKVOL"
        root_off = 16 + pad(len(LABEL))

        # 根目录 inode 头 + 名字 "ESK"
        ROOT_NM = "ESK"
        root_data_off = root_off + 16 + pad(len(ROOT_NM))

        # 根下两项：hello.txt, sub
        HELLO = b"Hello ROMFS!\n"
        DEEP = b"deep content\n"

        # 计算每段长度
        def ino_len(nm, body):
            return 16 + pad(len(nm)) + len(body)

        hello_len = ino_len("hello.txt", HELLO)
        sub_len = ino_len("sub", b"")          # 目录的 body 是空的，子项跟在后面
        deep_len = ino_len("deep.txt", DEEP)

        hello_off = root_data_off
        sub_off = hello_off + hello_len
        deep_off = sub_off + sub_len

        total = deep_off + deep_len
        total = (total + 3) & ~3

        img = bytearray(total)

        # ---- 超级块 ----
        img[0:8] = ROMFS_MAGIC
        struct.pack_into(">I", img, 8, total)
        struct.pack_into(">I", img, 12, 0)     # 校验和占位
        img[16:16 + len(LABEL)] = LABEL.encode()
        # 名字剩余字节为 0（已由 bytearray 初始化保证）

        def put_ino(off, nm, spec_info, size_field, body, next_off):
            nb = nm.encode()
            struct.pack_into(">IIII", img, off, next_off, spec_info,
                             size_field, 0)
            p = off + 16
            img[p:p + len(nb)] = nb
            p += pad(len(nb))
            if body:
                img[p:p + len(body)] = body
            return p + len(body)

        # ---- 根目录 ----
        put_ino(root_off, ROOT_NM, ROMFS_TYPE_DIR, 0, b"", 0)
        # 根的第一个子项就是 hello.txt
        put_ino(hello_off, "hello.txt", ROMFS_TYPE_REG, len(HELLO), HELLO,
                sub_off)                       # next -> sub
        # sub 目录：size=0，子项紧跟
        put_ino(sub_off, "sub", ROMFS_TYPE_DIR, 0, b"", 0)
        put_ino(deep_off, "deep.txt", ROMFS_TYPE_REG, len(DEEP), DEEP, 0)

        # ---- 回填校验和 ----
        # 让整卷 u32 和为 0：把负和写进超级块的 checksum 字段
        # 先把该字段清零再求和
        struct.pack_into(">I", img, 12, 0)
        s = romfs_checksum(bytes(img))
        neg = (0x100000000 - s) & 0xFFFFFFFF
        struct.pack_into(">I", img, 12, neg)

        return bytes(img), HELLO, DEEP

    img, HELLO, DEEP = build()
    fs = Romfs(Buf(img))
    info = fs.info()
    print("ROMFS: size=%d label=%r root@%d"
          % (info["size"], info["label"], info["root_offset"]))
    assert info["label"] == "ESKVOL", info["label"]
    assert fs.verify_checksum(), "校验和应为 0"

    ents = fs.listdir()
    print("根目录 %d 项: %s" % (len(ents), [(e.name, e.type_name) for e in ents]))
    assert len(ents) == 2, len(ents)

    hello = [e for e in ents if e.name == "hello.txt"][0]
    sub = [e for e in ents if e.name == "sub"][0]
    assert hello.is_file and sub.is_dir

    d = fs.read_file(hello)
    print("  hello.txt -> %r" % d)
    assert d == HELLO

    kids = fs.listdir(sub)
    print("  sub/ %d 项: %s" % (len(kids), [e.name for e in kids]))
    assert len(kids) == 1 and kids[0].name == "deep.txt"
    assert fs.read_file(kids[0]) == DEEP

    assert fs.read_path("/sub/deep.txt") == DEEP

    walk = [p for p, e in fs.walk()]
    print("  walk:", walk)
    assert "sub/deep.txt" in walk

    print("自检通过")
