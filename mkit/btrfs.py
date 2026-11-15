# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""Btrfs 文件系统

格式依据 Linux `fs/btrfs/ctree.h`、`fs/btrfs/disk-io.c` 与 on-disk format 文档。

已实现：
    · 超级块解析（位于镜像偏移 0x10000，魔数 `_BHRfS_M`），全字段
    · `sys_chunk_array` 解析 → 逻辑地址到物理地址的 chunk 映射
    · chunk 表的 type 标志解码（DATA / SYSTEM / METADATA / RAID0/1/10/5/6/DUP）
    · 树节点读取（`btrfs_header` + 叶子项 `btrfs_item` / 内部项 `btrfs_key_ptr`）
    · 节点大小、层级、条目键（objectid / type / offset）解出
    · 按逻辑地址随机读（穿过 chunk 映射）
    · `info()` / `chunk_map()` / `logical_to_physical()` / `read_node()` / `root_tree()`

不实现（明确标注，不假装支持）：
    · **目录遍历 / 读文件** —— 需要 root tree → FS_TREE → 子卷根 → INODE_ITEM /
      DIR_ITEM 的完整链路，以及对 extent tree 的解析。`listdir()` / `walk()` /
      `read_file()` 一律抛 `NotImplementedError`，返回空列表会造成误判。
    · 压缩数据 extent（zlib 可解，lzo/zstd/lz4 标准库无实现）
    · RAID5/6 校验重建、多设备拼接
    · 写操作、快照、qgroup

坐标说明：
    `read(off, n)` 用的是**物理**偏移（与镜像一致）；
    `read_logical(laddr, n)` 穿过 chunk 映射；
    `read_node(bytenr)` 接受**逻辑**地址（树节点都是逻辑地址）。
"""

import struct

__all__ = ["Btrfs", "probe", "open_fs", "BTRFS_MAGIC", "SUPER_OFFSET",
           "CHUNK_TYPE_NAME"]

BTRFS_MAGIC = b"_BHRfS_M"
SUPER_OFFSET = 0x10000
SUPER_LEN = 0x1000
HEADER_LEN = 0x65          # btrfs_header 到 level 字段为止

# ---- 超级块字段偏移（小端）----
SB = {
    "csum": 0x000, "fsid": 0x020, "bytenr": 0x030, "flags": 0x038,
    "magic": 0x040, "generation": 0x048, "root": 0x050, "chunk_root": 0x058,
    "log_root": 0x060, "log_root_transid": 0x068, "total_bytes": 0x070,
    "bytes_used": 0x078, "root_dir_objectid": 0x080, "num_devices": 0x088,
    "sectorsize": 0x090, "nodesize": 0x094, "leafsize": 0x098,
    "stripesize": 0x09C, "sys_chunk_array_size": 0x0A0,
    "chunk_root_generation": 0x0A4, "compat_flags": 0x0AC,
    "compat_ro_flags": 0x0B4, "incompat_flags": 0x0BC,
    "csum_type": 0x0C4, "root_level": 0x0C6, "chunk_root_level": 0x0C7,
    "log_root_level": 0x0C8, "label": 0x12B, "cache_generation": 0x22B,
    "uuid_tree_generation": 0x233, "metadata_uuid": 0x23B,
    "sys_chunk_array": 0x32B,
}

# ---- chunk type 标志 ----
CHUNK_TYPE_DATA = 1 << 0
CHUNK_TYPE_SYSTEM = 1 << 1
CHUNK_TYPE_METADATA = 1 << 2
CHUNK_TYPE_RAID0 = 1 << 3
CHUNK_TYPE_RAID1 = 1 << 4
CHUNK_TYPE_DUP = 1 << 5
CHUNK_TYPE_RAID10 = 1 << 6
CHUNK_TYPE_RAID5 = 1 << 7
CHUNK_TYPE_RAID6 = 1 << 8

CHUNK_TYPE_NAME = {
    CHUNK_TYPE_DATA: "DATA",
    CHUNK_TYPE_SYSTEM: "SYSTEM",
    CHUNK_TYPE_METADATA: "METADATA",
    CHUNK_TYPE_RAID0: "RAID0",
    CHUNK_TYPE_RAID1: "RAID1",
    CHUNK_TYPE_DUP: "DUP",
    CHUNK_TYPE_RAID10: "RAID10",
    CHUNK_TYPE_RAID5: "RAID5",
    CHUNK_TYPE_RAID6: "RAID6",
}

# ---- 键类型 ----
KEY_TYPE_NAME = {
    1: "INODE_ITEM", 12: "INODE_REF", 13: "INODE_EXTREF",
    24: "INODE_ITEM_?", 84: "DIR_ITEM", 96: "DIR_INDEX",
    108: "DIR_LOG_ITEM", 132: "ROOT_ITEM", 144: "ROOT_BACKREF",
    156: "ROOT_REF", 168: "EXTENT_DATA", 169: "EXTENT_CSUM",
    176: "EXTENT_TREE_BLOCK_REF", 178: "SHARED_BLOCK_REF",
    184: "EXTENT_DATA_REF", 192: "EXTENT_ITEM", 228: "CHUNK_ITEM",
    240: "DEV_ITEM", 248: "DEV_EXTENT", 204: "EXTENT_REF",
}


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def chunk_type_text(flags):
    names = [v for k, v in sorted(CHUNK_TYPE_NAME.items()) if flags & k]
    return "|".join(names) if names else "0x%X" % flags


class Key(object):
    """btrfs_disk_key：objectid u64 / type u8 / offset u64（共 17 字节）"""
    __slots__ = ("objectid", "type", "offset")

    def __init__(self, objectid, type_, offset):
        self.objectid = objectid
        self.type = type_
        self.offset = offset

    @classmethod
    def parse(cls, buf, off=0):
        return cls(u64(buf, off), buf[off + 8],
                   u64(buf, off + 9) if len(buf) >= off + 17 else 0)

    @property
    def type_name(self):
        return KEY_TYPE_NAME.get(self.type, "type%d" % self.type)

    def __repr__(self):
        return "(%d %s %d)" % (self.objectid, self.type_name, self.offset)


class Chunk(object):
    """一个 chunk 映射项"""
    __slots__ = ("logical", "length", "owner", "stripe_len", "type",
                 "io_align", "io_width", "sector_size", "num_stripes",
                 "sub_stripes", "stripes")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def type_text(self):
        return chunk_type_text(self.type)

    def __repr__(self):
        return "<Chunk log=%d len=%d %s stripes=%d>" % (
            self.logical, self.length, self.type_text, self.num_stripes)


class Node(object):
    """一个 btrfs 树节点"""

    __slots__ = ("bytenr", "fsid", "flags", "generation", "owner",
                 "nritems", "level", "raw", "chunk_tree_uuid")

    def __init__(self, raw, bytenr=None):
        if len(raw) < HEADER_LEN:
            raise ValueError("节点太短: %d 字节" % len(raw))
        self.raw = raw
        self.bytenr = u64(raw, 0x30) or bytenr
        self.fsid = raw[0x20:0x30]
        self.chunk_tree_uuid = raw[0x40:0x50]
        self.flags = u64(raw, 0x38)
        self.generation = u64(raw, 0x50)
        self.owner = u64(raw, 0x58)
        self.nritems = u32(raw, 0x60)
        self.level = raw[0x64]

    @property
    def is_leaf(self):
        return self.level == 0

    def items(self):
        """叶子项：btrfs_item { key(17) offset u32 size u32 } = 25 字节"""
        if not self.is_leaf:
            raise ValueError("不是叶子节点（level=%d）" % self.level)
        out = []
        base = HEADER_LEN
        for i in range(self.nritems):
            p = base + i * 25
            if p + 25 > len(self.raw):
                break
            k = Key.parse(self.raw, p)
            off = u32(self.raw, p + 17)
            size = u32(self.raw, p + 21)
            data_off = HEADER_LEN + off
            out.append((k, self.raw[data_off:data_off + size]))
        return out

    def ptrs(self):
        """内部项：btrfs_key_ptr { key(17) blockptr u64 generation u64 } = 33 字节"""
        if self.is_leaf:
            raise ValueError("叶子节点没有子指针")
        out = []
        base = HEADER_LEN
        for i in range(self.nritems):
            p = base + i * 33
            if p + 33 > len(self.raw):
                break
            k = Key.parse(self.raw, p)
            out.append((k, u64(self.raw, p + 17)))
        return out

    def describe(self):
        return {
            "bytenr": self.bytenr,
            "level": self.level,
            "nritems": self.nritems,
            "owner": self.owner,
            "generation": self.generation,
            "is_leaf": self.is_leaf,
            "fsid": self.fsid.hex(),
        }

    def __repr__(self):
        return "<Node bytenr=%d level=%d nritems=%d>" % (
            self.bytenr, self.level, self.nritems)


class Btrfs(object):
    """Btrfs 只读"""

    def __init__(self, sub):
        self.sub = sub
        self._node_cache = {}
        self._read_super()

    # ---------------- 超级块 ----------------
    def _read_super(self):
        raw = self.sub.read(SUPER_OFFSET, SUPER_LEN)
        if len(raw) < 0x1000:
            raise ValueError("镜像太小，读不到 Btrfs 超级块（偏移 0x10000）")
        if raw[SB["magic"]:SB["magic"] + 8] != BTRFS_MAGIC:
            raise ValueError("不是 Btrfs（magic=%r）"
                             % raw[SB["magic"]:SB["magic"] + 8])

        g = lambda name: u64(raw, SB[name])
        g32 = lambda name: u32(raw, SB[name])

        self.fsid = raw[SB["fsid"]:SB["fsid"] + 16]
        self.bytenr = g("bytenr")
        self.flags = g("flags")
        self.generation = g("generation")
        self.root = g("root")
        self.chunk_root = g("chunk_root")
        self.log_root = g("log_root")
        self.total_bytes = g("total_bytes")
        self.bytes_used = g("bytes_used")
        self.root_dir_objectid = g("root_dir_objectid")
        self.num_devices = g("num_devices")
        self.sectorsize = g32("sectorsize")
        self.nodesize = g32("nodesize")
        self.leafsize = g32("leafsize")
        self.stripesize = g32("stripesize")
        self.sys_chunk_array_size = g32("sys_chunk_array_size")
        self.compat_flags = g("compat_flags")
        self.compat_ro_flags = g("compat_ro_flags")
        self.incompat_flags = g("incompat_flags")
        self.csum_type = u16(raw, SB["csum_type"])
        self.root_level = raw[SB["root_level"]]
        self.chunk_root_level = raw[SB["chunk_root_level"]]
        self.label = raw[SB["label"]:SB["label"] + 256].split(b"\x00")[0] \
            .decode("utf-8", "replace")

        self._sys_chunk_raw = raw[SB["sys_chunk_array"]:
                                  SB["sys_chunk_array"] + self.sys_chunk_array_size]
        self.chunks = self._parse_chunks(self._sys_chunk_raw)

    def _parse_chunks(self, buf):
        """交替解析 btrfs_disk_key(17) + btrfs_chunk(48 + 32*n)"""
        out = []
        pos = 0
        n = len(buf)
        while pos + 17 + 48 <= n:
            key = Key.parse(buf, pos)
            p = pos + 17
            length = u64(buf, p + 0x00)
            owner = u64(buf, p + 0x08)
            stripe_len = u64(buf, p + 0x10)
            ctype = u64(buf, p + 0x18)
            io_align = u32(buf, p + 0x20)
            io_width = u32(buf, p + 0x24)
            sector_size = u32(buf, p + 0x28)
            num_stripes = u16(buf, p + 0x2C)
            sub_stripes = u16(buf, p + 0x2E)
            sp = p + 0x30
            stripes = []
            for i in range(num_stripes):
                q = sp + i * 32
                if q + 32 > n:
                    break
                stripes.append({
                    "devid": u64(buf, q),
                    "offset": u64(buf, q + 8),
                    "dev_uuid": buf[q + 16:q + 32].hex(),
                })
            if not stripes:
                break
            out.append(Chunk(logical=key.offset, length=length, owner=owner,
                             stripe_len=stripe_len, type=ctype,
                             io_align=io_align, io_width=io_width,
                             sector_size=sector_size,
                             num_stripes=num_stripes, sub_stripes=sub_stripes,
                             stripes=stripes))
            # 前进：key(17) + chunk 固定 48 + stripes*32，且 8 字节对齐
            step = 17 + 48 + num_stripes * 32
            step = (step + 7) & ~7
            pos += step
        return out

    def info(self):
        return {
            "format": "btrfs",
            "label": self.label,
            "fsid": self.fsid.hex(),
            "bytenr": self.bytenr,
            "generation": self.generation,
            "total_bytes": self.total_bytes,
            "bytes_used": self.bytes_used,
            "sectorsize": self.sectorsize,
            "nodesize": self.nodesize,
            "num_devices": self.num_devices,
            "root": self.root,
            "chunk_root": self.chunk_root,
            "root_level": self.root_level,
            "chunk_root_level": self.chunk_root_level,
            "csum_type": self.csum_type,
            "incompat_flags": "0x%016X" % self.incompat_flags,
            "compat_ro_flags": "0x%016X" % self.compat_ro_flags,
            "chunks_in_sys_array": len(self.chunks),
            "sys_chunk_array_size": self.sys_chunk_array_size,
        }

    def chunk_map(self):
        return [{"logical": c.logical, "length": c.length,
                 "type": c.type_text, "type_flags": "0x%X" % c.type,
                 "owner": c.owner, "stripes": c.stripes}
                for c in self.chunks]

    # ---------------- 地址翻译 ----------------
    def logical_to_physical(self, laddr):
        """逻辑地址 -> (物理地址, 所在 chunk 剩余长度, chunk 类型)"""
        for c in self.chunks:
            if c.logical <= laddr < c.logical + c.length:
                if not c.stripes:
                    return None
                st = c.stripes[0]
                delta = laddr - c.logical
                return (st["offset"] + delta, c.length - delta, c.type_text)
        return None

    def read_logical(self, laddr, n):
        """按逻辑地址读（只处理单条带，多设备/RAID 不支持）"""
        hit = self.logical_to_physical(laddr)
        if hit is None:
            raise ValueError("逻辑地址 %d 不在任何 chunk 里" % laddr)
        paddr, avail, _t = hit
        n = min(n, avail)
        return self.sub.read(paddr, n)

    def read_node(self, bytenr):
        """按逻辑地址读一个树节点"""
        hit = self._node_cache.get(bytenr)
        if hit is not None:
            return hit
        raw = self.read_logical(bytenr, self.nodesize)
        if len(raw) < HEADER_LEN:
            raise ValueError("节点 %d 读不到（%d 字节）" % (bytenr, len(raw)))
        node = Node(raw, bytenr)
        self._node_cache[bytenr] = node
        return node

    def root_tree(self):
        """根树的根节点（逻辑地址 = superblock.root）"""
        return self.read_node(self.root)

    def chunk_tree(self):
        return self.read_node(self.chunk_root)

    # ---------------- 未实现（明确抛错，不返回空）----------------
    def listdir(self, *a, **kw):
        raise NotImplementedError(
            "Btrfs 目录遍历未实现：需要 root tree → FS_TREE → 子卷根 → "
            "INODE_ITEM/DIR_ITEM 的完整链路与 extent tree 解析。"
            "本模块只做到超级块、chunk 映射与树节点读取。")

    def walk(self, *a, **kw):
        raise NotImplementedError("Btrfs 遍历未实现，原因同 listdir()")

    def read_file(self, *a, **kw):
        raise NotImplementedError(
            "Btrfs 读文件未实现：需要 EXTENT_DATA 的 inline/extent 两路解析，"
            "以及压缩 extent 的解压。")

    def find(self, *a, **kw):
        raise NotImplementedError("Btrfs 搜索未实现，原因同 listdir()")


def probe(sub):
    """快速判断是不是 Btrfs"""
    try:
        raw = sub.read(SUPER_OFFSET, 0x50)
    except Exception:
        return False
    return len(raw) >= 0x48 and raw[0x40:0x48] == BTRFS_MAGIC


def open_fs(sub):
    return Btrfs(sub)


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
        """合成最小 Btrfs：超级块 + sys_chunk_array + 一个叶子节点"""
        NODESIZE = 16384
        SECTORSIZE = 4096
        LEAF_PADDR = 0x20000
        # 镜像要能容纳 超级块(0x10000+0x1000) 与叶子节点(0x20000+0x4000)
        total = LEAF_PADDR + NODESIZE + NODESIZE
        img = bytearray(total)

        # ---- 叶子节点放在物理 0x20000，逻辑地址 0x100000 ----
        LEAF_LADDR = 0x100000

        node = bytearray(NODESIZE)
        node[0x20:0x30] = bytes(range(16))            # fsid
        struct.pack_into("<Q", node, 0x30, LEAF_LADDR)  # bytenr
        struct.pack_into("<Q", node, 0x38, 0)          # flags
        node[0x40:0x50] = bytes(range(16))             # chunk_tree_uuid
        struct.pack_into("<Q", node, 0x50, 42)         # generation
        struct.pack_into("<Q", node, 0x58, 5)          # owner = FS_TREE
        struct.pack_into("<I", node, 0x60, 3)          # nritems = 3
        node[0x64] = 0                                 # level = 0 (leaf)

        # 3 个 item：INODE_ITEM / DIR_ITEM / ROOT_ITEM
        items = [
            (1, 1, 0, b"I" * 16),        # oid=1 type=1(INODE_ITEM)
            (256, 84, 100, b"D" * 8),    # oid=256 type=84(DIR_ITEM)
            (5, 132, 0, b"R" * 24),      # oid=5 type=132(ROOT_ITEM)
        ]
        data_off = 0x1000           # 数据区从节点内 0x1000 起
        for i, (oid, typ, off, payload) in enumerate(items):
            p = HEADER_LEN + i * 25
            struct.pack_into("<Q", node, p, oid)
            node[p + 8] = typ
            struct.pack_into("<Q", node, p + 9, off)
            rel = data_off - HEADER_LEN
            struct.pack_into("<I", node, p + 17, rel)
            struct.pack_into("<I", node, p + 21, len(payload))
            node[data_off:data_off + len(payload)] = payload
            data_off += len(payload) + 32
        img[LEAF_PADDR:LEAF_PADDR + NODESIZE] = node

        # ---- 超级块 ----
        sb = bytearray(SUPER_LEN)
        sb[SB["fsid"]:SB["fsid"] + 16] = bytes(range(16))
        struct.pack_into("<Q", sb, SB["bytenr"], 0x10000)
        sb[SB["magic"]:SB["magic"] + 8] = BTRFS_MAGIC
        struct.pack_into("<Q", sb, SB["generation"], 42)
        struct.pack_into("<Q", sb, SB["root"], LEAF_LADDR)
        struct.pack_into("<Q", sb, SB["chunk_root"], LEAF_LADDR)
        struct.pack_into("<Q", sb, SB["total_bytes"], total)
        struct.pack_into("<Q", sb, SB["bytes_used"], NODESIZE)
        struct.pack_into("<Q", sb, SB["root_dir_objectid"], 6)
        struct.pack_into("<Q", sb, SB["num_devices"], 1)
        struct.pack_into("<I", sb, SB["sectorsize"], SECTORSIZE)
        struct.pack_into("<I", sb, SB["nodesize"], NODESIZE)
        struct.pack_into("<I", sb, SB["leafsize"], NODESIZE)
        struct.pack_into("<I", sb, SB["stripesize"], SECTORSIZE)
        struct.pack_into("<Q", sb, SB["incompat_flags"], 0x1 | 0x40)
        sb[SB["root_level"]] = 0
        sb[SB["chunk_root_level"]] = 0
        sb[SB["label"]:SB["label"] + 9] = b"ESK-BTRFS"

        # sys_chunk_array：disk_key(17) + chunk(48 + 1*32)，8 字节对齐
        sca = bytearray(17 + 48 + 32)          # 先按最终长度分配
        struct.pack_into("<Q", sca, 0, 256)          # key.objectid
        sca[8] = 228                                 # key.type = CHUNK_ITEM
        struct.pack_into("<Q", sca, 9, LEAF_LADDR)   # key.offset = 逻辑地址
        p = 17
        struct.pack_into("<Q", sca, p + 0x00, NODESIZE * 2)   # length
        struct.pack_into("<Q", sca, p + 0x08, 2)              # owner = CHUNK_TREE
        struct.pack_into("<Q", sca, p + 0x10, 0x10000)        # stripe_len
        struct.pack_into("<Q", sca, p + 0x18, CHUNK_TYPE_METADATA | CHUNK_TYPE_SYSTEM)
        struct.pack_into("<I", sca, p + 0x20, SECTORSIZE)
        struct.pack_into("<I", sca, p + 0x24, SECTORSIZE)
        struct.pack_into("<I", sca, p + 0x28, SECTORSIZE)
        struct.pack_into("<H", sca, p + 0x2C, 1)              # num_stripes
        struct.pack_into("<H", sca, p + 0x2E, 1)              # sub_stripes
        q = p + 0x30
        struct.pack_into("<Q", sca, q, 1)                     # devid
        struct.pack_into("<Q", sca, q + 8, LEAF_PADDR)        # 物理偏移
        sca[q + 16:q + 32] = bytes(range(16))                 # dev_uuid

        struct.pack_into("<I", sb, SB["sys_chunk_array_size"], len(sca))
        sb[SB["sys_chunk_array"]:SB["sys_chunk_array"] + len(sca)] = sca

        img[SUPER_OFFSET:SUPER_OFFSET + SUPER_LEN] = sb
        return bytes(img), NODESIZE, LEAF_LADDR

    img, NODESIZE, LEAF_LADDR = build()
    fs = Btrfs(Buf(img))
    inf = fs.info()
    print("Btrfs: label=%r nodesize=%d sectorsize=%d chunks=%d gen=%d"
          % (inf["label"], inf["nodesize"], inf["sectorsize"],
             inf["chunks_in_sys_array"], inf["generation"]))
    assert inf["label"] == "ESK-BTRFS", inf["label"]
    assert inf["nodesize"] == NODESIZE
    assert inf["sectorsize"] == 4096
    assert inf["chunks_in_sys_array"] == 1
    assert probe(Buf(img)) is True

    cm = fs.chunk_map()
    print("  chunk: log=%d len=%d type=%s stripes=%d"
          % (cm[0]["logical"], cm[0]["length"], cm[0]["type"],
             len(cm[0]["stripes"])))
    assert "METADATA" in cm[0]["type"] and "SYSTEM" in cm[0]["type"]

    hit = fs.logical_to_physical(LEAF_LADDR)
    print("  logical %d -> %s" % (LEAF_LADDR, hit))
    assert hit is not None and hit[0] == 0x20000, hit

    node = fs.read_node(LEAF_LADDR)
    print("  node: level=%d nritems=%d leaf=%s"
          % (node.level, node.nritems, node.is_leaf))
    assert node.is_leaf and node.nritems == 3
    assert node.generation == 42 and node.owner == 5

    items = node.items()
    print("  items: %s" % [(k.objectid, k.type_name, k.offset) for k, _ in items])
    assert items[0][0].objectid == 1 and items[0][0].type_name == "INODE_ITEM"
    assert items[1][0].type_name == "DIR_ITEM"
    assert items[2][0].type == 132 and items[2][0].type_name == "ROOT_ITEM"
    assert items[0][1] == b"I" * 16

    rt = fs.root_tree()
    print("  root_tree bytenr=%d" % rt.bytenr)
    assert rt.bytenr == LEAF_LADDR

    # 未实现的接口必须抛 NotImplementedError
    for fn in (fs.listdir, fs.walk, fs.read_file, fs.find):
        try:
            fn()
        except NotImplementedError:
            pass
        else:
            raise AssertionError("%s 应抛 NotImplementedError" % fn.__name__)
    print("  未实现接口均正确抛 NotImplementedError")

    print("自检通过")
