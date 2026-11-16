# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""F2FS 文件系统（Flash-Friendly File System）只读解析

格式依据 Linux `include/linux/f2fs_fs.h`、`fs/f2fs/node.c`、`fs/f2fs/dir.c`。

F2FS 是 Android 设备与部分嵌入式设备的主力文件系统，取证上常见于
`/userdata`、`/data` 分区。

============================================================================
已实现
============================================================================
1. 超级块
   · 两份副本：偏移 1024 与 5120（`F2FS_SUPER_OFFSET` + `F2FS_BLKSIZE`）
   · 魔数 0xF2F52010；版本、块大小、段大小、各区域起始块号、根 inode 号、
     卷名（UTF-16LE）、UUID、feature 位
   · `checksum_offset` 指向的 CRC32 校验（计算时该字段置 0）

2. checkpoint
   · `cp_blkaddr` 处两份 checkpoint pack，取 `checkpoint_ver` 更大的一份
   · `user_block_count` / `valid_block_count` / `free_segment_count` /
     `valid_node_count` / `valid_inode_count` / `next_free_nid` / `ckpt_flags`
   · 内嵌的 NAT / SIT 位图（`sit_nat_version_bitmap`，起始 0xC0）
   · checkpoint 自身 CRC32

3. NAT（Node Address Table）
   · `nat_blkaddr` 起线性排布，每项 9 字节
     （`version u8 / ino u32 / block_addr u32`），每块 455 项
   · `nid -> 物理块号`

4. SIT（Segment Info Table）
   · `sit_blkaddr` 起，每项 70 字节
     （`vblocks u16 / valid_map[64] / mtime u32`），每块 58 项
   · 段内有效块位图

5. node / inode
   · node 块 footer（偏移 4072）：`nid / ino / flag / cp_ver / next_blkaddr`
   · inode 关键字段：`i_mode`(0x00) / `i_uid`(0x04) / `i_gid`(0x08) /
     `i_links`(0x0C) / `i_size`(0x10) / `i_atime`(0x20) / `i_ctime`(0x28) /
     `i_mtime`(0x30) / `i_pino`(0x54) / `i_namelen`(0x58) / `i_name`(0x5C) /
     `i_inline`(0x03)
   · `i_addr` 起点 **360**、`i_nid` 起点 **4052**
     （由 `DEF_ADDRS_PER_INODE = 923` 反推校验：360 + 923*4 = 4052，
      4052 + 5*4 = 4072，正好接 footer）

6. 数据读取
   · **inline 数据**：`i_inline & F2FS_INLINE_DATA` 时数据内嵌在 inode 的
     `i_addr` 区
   · **直接块**：`i_addr[]` 逐个跟随
   · **间接**：`i_nid[0]` 一次间接（direct_node.addr[1018]）、
     `i_nid[1]` 二次、`i_nid[2]` 三次（按 `i_nid[4]` 关掉二次/三次前的层数）
   · 稀疏块（地址为 0 或 0xFFFFFFFF）补零

7. 目录
   · dentry 块布局：`bitmap[27]` @0、`reserved[3]` @27、
     `dentry[214]` @30（每项 11 字节：hash u32 / ino u32 / name_len u16 /
     file_type u8）、`filename[214][8]` @2384
   · `listdir()` / `walk()` / `read_file()` / `lookup_path()` / `find()`

8. 取证辅助
   · `info()` 给出卷级信息与各区域地址
   · `nat_entry()` / `sit_entry()` 可直接查表
   · 任何一步读不出来都记进 `self.notes`，不静默返回空

============================================================================
不实现（明确边界）
============================================================================
· 写操作、fsck、gc 日志回放
· **加密（`F2FS_IOC_*` / inline encryption / ICE）**：识别 `feature` 位与
  `encryption_level`，但不做解密——没有密钥材料
· **压缩（`i_compr_blocks` / `i_compress_algorithm`）**：只报字段值，
  不做解压
· **多设备（`devs[]`）**：只用主设备，多设备分段不拼接
· **`i_nid[1..2]` 的二次/三次间接**：已实现，但若节点为空/坏会补零并记 note
· **xattr（`i_xattr_nid`）**：只报 nid，不解析条目
· **配额（`qf_ino[]`）与 orphan 列表**：只报字段
· **checkpoint 的 data summary / journal**：不解析
· 真实 Android userdata 镜像上未回测（本机没有样本），自检全部基于合成镜像
"""

import struct

__all__ = [
    "F2fs", "F2fsInode", "F2fsDirent",
    "probe", "open_fs",
    "SUPER_MAGIC", "SUPER_OFFSET", "BLKSIZE",
    "NAT_ENTRY_SIZE", "NAT_ENTRY_PER_BLOCK",
    "SIT_ENTRY_SIZE", "SIT_ENTRY_PER_BLOCK",
    "INODE_ADDR_OFF", "INODE_NID_OFF", "NODE_FOOTER_OFF",
    "DENTRY_PER_BLOCK",
]

SUPER_MAGIC = 0xF2F52010
SUPER_OFFSET = 1024
BLKSIZE = 4096

# NAT / SIT 表项尺寸与每块项数
NAT_ENTRY_SIZE = 9          # version u8 + ino u32 + block_addr u32
NAT_ENTRY_PER_BLOCK = BLKSIZE // NAT_ENTRY_SIZE          # 455
SIT_ENTRY_SIZE = 70         # vblocks u16 + valid_map[64] + mtime u32
SIT_ENTRY_PER_BLOCK = BLKSIZE // SIT_ENTRY_SIZE          # 58

# inode 内部偏移（由 DEF_ADDRS_PER_INODE=923 反推校验）
INODE_ADDR_OFF = 360
INODE_NID_OFF = 4052
NODE_FOOTER_OFF = 4072
DEF_ADDRS_PER_INODE = 923
DEF_ADDRS_PER_BLOCK = 1018      # (4096 - 24) / 4

# dentry 块布局
DENTRY_PER_BLOCK = 214
DENTRY_BITMAP_LEN = 27
DENTRY_ARR_OFF = 30
DENTRY_SIZE = 11
FILENAME_ARR_OFF = 2384
SLOT_LEN = 8

# i_inline 位
F2FS_INLINE_DATA = 0x02
F2FS_INLINE_DENTRY = 0x04
F2FS_EXTRA_ATTR = 0x08

# file_type
FT_NAME = {0: "unknown", 1: "reg", 2: "dir", 3: "chr", 4: "blk",
           5: "fifo", 6: "sock", 7: "sym"}

# checkpoint 标志
CP_FLAGS = {
    0x0001: "umount", 0x0002: "orphan_present", 0x0004: "compact_sum",
    0x0008: "error", 0x0010: "fsck", 0x0020: "fastboot",
    0x0040: "crc_recovery", 0x0080: "nat_bits", 0x0100: "trimmed",
    0x0200: "nocrc_recovery", 0x0400: "large_nat_bitmap",
    0x1000: "disabled", 0x2000: "disabled_quick", 0x4000: "resizefs",
}


def _le16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _le32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _le64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _crc32(data):
    import zlib
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


def _dtype_from_mode(mode):
    t = mode & 0o170000
    return {0o100000: 2, 0o040000: 1, 0o120000: 7, 0o020000: 3,
            0o060000: 4, 0o010000: 5, 0o140000: 6}.get(t, 0)


class F2fsDirent(object):
    """一个目录项"""

    __slots__ = ("name", "ino", "file_type", "hash")

    def __init__(self, name, ino, file_type, hash_):
        self.name = name
        self.ino = ino
        self.file_type = file_type
        self.hash = hash_

    @property
    def is_dir(self):
        return self.file_type == 2

    def to_dict(self):
        return {"name": self.name, "ino": self.ino,
                "type": FT_NAME.get(self.file_type, str(self.file_type))}

    def __repr__(self):
        return "<F2fsDirent %r ino=%d>" % (self.name, self.ino)


class F2fsInode(object):
    """解析后的 inode"""

    __slots__ = ("nid", "ino", "mode", "uid", "gid", "links", "size",
                 "atime", "ctime", "mtime", "pino", "name", "inline_flags",
                 "addr", "nid_ptrs", "raw_footer", "is_inline_data", "_raw")

    def __init__(self):
        self.nid = 0
        self.ino = 0
        self.mode = 0
        self.uid = 0
        self.gid = 0
        self.links = 0
        self.size = 0
        self.atime = 0
        self.ctime = 0
        self.mtime = 0
        self.pino = 0
        self.name = 0
        self.inline_flags = 0
        self.addr = []
        self.nid_ptrs = []
        self.raw_footer = None
        self.is_inline_data = False

    @property
    def dtype(self):
        return _dtype_from_mode(self.mode)

    @property
    def is_dir(self):
        return self.dtype == 1

    @property
    def is_reg(self):
        return self.dtype == 2

    @property
    def is_link(self):
        return self.dtype == 7

    def to_dict(self):
        return {"nid": self.nid, "ino": self.ino,
                "mode": "0o%o" % self.mode, "uid": self.uid, "gid": self.gid,
                "links": self.links, "size": self.size,
                "type": FT_NAME.get(self.dtype, "?"),
                "mtime": self.mtime, "inline_data": self.is_inline_data}

    def __repr__(self):
        return "<F2fsInode ino=%d %s size=%d>" % (
            self.ino, FT_NAME.get(self.dtype, "?"), self.size)


class F2fs(object):
    """F2FS 只读"""

    def __init__(self, sub):
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.notes = []
        self.sb = None
        self.sb_offset = None
        self.block_size = BLKSIZE
        self.blocks_per_seg = 512
        self.cp = None
        self._nat = {}
        self._sit = {}
        self._node = {}
        self._read_super()
        self._read_checkpoint()

    # ---------------- 超级块 ----------------
    def _read_super(self):
        """两份副本：1024 与 5120；取第一份能通过校验的"""
        cands = [SUPER_OFFSET, SUPER_OFFSET + BLKSIZE]
        if self.size >= 8192:
            cands.append(SUPER_OFFSET + 2 * BLKSIZE)
        first_err = None
        for off in cands:
            raw = self.sub.read(off, 1024)
            if len(raw) < 512:
                continue
            if _le32(raw, 0) != SUPER_MAGIC:
                if first_err is None:
                    first_err = "偏移 %d 处魔数 0x%08X（期望 0x%08X）" % (
                        off, _le32(raw, 0), SUPER_MAGIC)
                continue
            sb = self._parse_super(raw)
            if sb is None:
                continue
            self.sb = sb
            self.sb_offset = off
            self.block_size = 1 << sb["log_blocksize"]
            self.blocks_per_seg = 1 << sb["log_blocks_per_seg"]
            if off != SUPER_OFFSET:
                self.notes.append("主超级块不可用，使用了偏移 %d 的副本" % off)
            return
        raise ValueError("不是 F2FS（%s）" % (first_err or "未找到超级块"))

    def _parse_super(self, raw):
        """字段偏移逐条照 `f2fs_fs.h` 的 struct f2fs_super_block 排：
        magic@0x00 / major@0x04 / minor@0x06 / log_sectorsize@0x08 /
        log_sectors_per_block@0x0C / log_blocksize@0x10 /
        log_blocks_per_seg@0x14 / segs_per_sec@0x18 / secs_per_zone@0x1C /
        checksum_offset@0x20 / block_count(u64)@0x24 / section_count@0x2C /
        segment_count@0x30 … segment_count_main@0x44 /
        segment0_blkaddr@0x48 / cp@0x4C / sit@0x50 / nat@0x54 / ssa@0x58 /
        main@0x5C / root_ino@0x60 / node_ino@0x64 / meta_ino@0x68 /
        uuid[16]@0x6C / volume_name[512]@0x7C / extension_count@0x27C
        """
        log_blocksize = _le32(raw, 0x10)
        if not (9 <= log_blocksize <= 16):
            self.notes.append("超级块 log_blocksize=%d 不合理" % log_blocksize)
            return None
        bs = 1 << log_blocksize
        csum_off = _le32(raw, 0x20)
        crc_ok = None
        if 0 < csum_off <= 1020:
            crc_stored = _le32(raw, csum_off)
            tmp = bytearray(raw)
            struct.pack_into("<I", tmp, csum_off, 0)
            crc_ok = (_crc32(tmp) == crc_stored)
            if not crc_ok:
                self.notes.append("超级块 CRC 不过（算得 0x%08X，存 0x%08X）"
                                  % (_crc32(tmp), crc_stored))
        volname_raw = raw[0x7C:0x7C + 512]
        try:
            volname = volname_raw.decode("utf-16-le").split("\x00")[0]
        except Exception:
            volname = volname_raw.split(b"\x00")[0].decode("latin-1", "replace")

        return {
            "magic": "0x%08X" % _le32(raw, 0),
            "major_ver": _le16(raw, 0x04), "minor_ver": _le16(raw, 0x06),
            "log_sectorsize": _le32(raw, 0x08),
            "log_sectors_per_block": _le32(raw, 0x0C),
            "log_blocksize": log_blocksize,
            "block_size": bs,
            "log_blocks_per_seg": _le32(raw, 0x14),
            "segs_per_sec": _le32(raw, 0x18),
            "secs_per_zone": _le32(raw, 0x1C),
            "checksum_offset": csum_off,
            "crc_ok": crc_ok,
            "block_count": _le64(raw, 0x24),
            "section_count": _le32(raw, 0x2C),
            "segment_count": _le32(raw, 0x30),
            "segment_count_ckpt": _le32(raw, 0x34),
            "segment_count_sit": _le32(raw, 0x38),
            "segment_count_nat": _le32(raw, 0x3C),
            "segment_count_ssa": _le32(raw, 0x40),
            "segment_count_main": _le32(raw, 0x44),
            "segment0_blkaddr": _le32(raw, 0x48),
            "cp_blkaddr": _le32(raw, 0x4C),
            "sit_blkaddr": _le32(raw, 0x50),
            "nat_blkaddr": _le32(raw, 0x54),
            "ssa_blkaddr": _le32(raw, 0x58),
            "main_blkaddr": _le32(raw, 0x5C),
            "root_ino": _le32(raw, 0x60),
            "node_ino": _le32(raw, 0x64),
            "meta_ino": _le32(raw, 0x68),
            "uuid": raw[0x6C:0x7C].hex(),
            "volume_name": volname,
            "extension_count": _le32(raw, 0x27C),
        }

    # ---------------- checkpoint ----------------
    def _read_checkpoint(self):
        sb = self.sb
        bs = self.block_size
        base = sb["cp_blkaddr"] * bs
        # 两份 pack；每份首块是 f2fs_checkpoint
        cands = [base, base + 8 * bs, base + 16 * bs, base + 24 * bs]
        best = None
        for off in cands:
            raw = self.sub.read(off, bs)
            if len(raw) < 0xC0:
                continue
            ver = _le64(raw, 0)
            if ver == 0 or ver == 0xFFFFFFFFFFFFFFFF:
                continue
            cp = self._parse_cp(raw, off)
            if cp is None:
                continue
            if best is None or cp["checkpoint_ver"] > best["checkpoint_ver"]:
                best = cp
        if best is None:
            self.notes.append("两份 checkpoint 都读不出，只能靠超级块")
            return
        self.cp = best
        if best["flags_unknown"]:
            self.notes.append("checkpoint 有未知标志位：%s"
                              % best["flags_unknown"])

    def _parse_cp(self, raw, off):
        csum_off = _le32(raw, 0xA4)
        crc_ok = None
        if 0 < csum_off <= self.block_size - 4:
            stored = _le32(raw, csum_off)
            tmp = bytearray(raw)
            struct.pack_into("<I", tmp, csum_off, 0)
            crc_ok = (_crc32(tmp) == stored)
        flags = _le32(raw, 0x84)
        known = {k: v for k, v in CP_FLAGS.items() if flags & k}
        unknown = flags & ~sum(CP_FLAGS.keys())
        return {
            "offset": off,
            "checkpoint_ver": _le64(raw, 0),
            "user_block_count": _le64(raw, 0x08),
            "valid_block_count": _le64(raw, 0x10),
            "rsvd_segment_count": _le32(raw, 0x18),
            "overprov_segment_count": _le32(raw, 0x1C),
            "free_segment_count": _le32(raw, 0x20),
            "ckpt_flags": "0x%08X" % flags,
            "flags": sorted(known.values()),
            "flags_unknown": ("0x%X" % unknown) if unknown else None,
            "cp_pack_total_block_count": _le32(raw, 0x88),
            "cp_pack_start_sum": _le32(raw, 0x8C),
            "valid_node_count": _le32(raw, 0x90),
            "valid_inode_count": _le32(raw, 0x94),
            "next_free_nid": _le32(raw, 0x98),
            "sit_ver_bitmap_bytesize": _le32(raw, 0x9C),
            "nat_ver_bitmap_bytesize": _le32(raw, 0xA0),
            "checksum_offset": csum_off,
            "crc_ok": crc_ok,
            "elapsed_time": _le64(raw, 0xA8),
        }

    # ---------------- NAT / SIT ----------------
    def nat_entry(self, nid):
        """nid -> (ino, block_addr)；读不到返回 None"""
        if not (0 <= nid < (1 << 32)):
            return None
        blk_idx, slot = divmod(nid, NAT_ENTRY_PER_BLOCK)
        off = (self.sb["nat_blkaddr"] + blk_idx) * self.block_size \
            + slot * NAT_ENTRY_SIZE
        raw = self.sub.read(off, NAT_ENTRY_SIZE)
        if len(raw) < NAT_ENTRY_SIZE:
            self.notes.append("NAT 项 nid=%d 读不到" % nid)
            return None
        return {"nid": nid, "version": raw[0],
                "ino": _le32(raw, 1), "block_addr": _le32(raw, 5)}

    def sit_entry(self, segno):
        """段号 -> (vblocks, 有效位图, mtime)"""
        blk_idx, slot = divmod(segno, SIT_ENTRY_PER_BLOCK)
        off = (self.sb["sit_blkaddr"] + blk_idx) * self.block_size \
            + slot * SIT_ENTRY_SIZE
        raw = self.sub.read(off, SIT_ENTRY_SIZE)
        if len(raw) < SIT_ENTRY_SIZE:
            return None
        return {"segno": segno, "vblocks": _le16(raw, 0),
                "valid_map": raw[2:66].hex(), "mtime": _le32(raw, 66)}

    # ---------------- node / inode ----------------
    def read_node_block(self, blk_addr):
        """读一个 node 块（不校验 footer）"""
        if blk_addr in (0, 0xFFFFFFFF):
            return b""
        raw = self.sub.read(blk_addr * self.block_size, self.block_size)
        if len(raw) < self.block_size:
            self.notes.append("node 块 %d 读不全（%d/%d）"
                              % (blk_addr, len(raw), self.block_size))
        return raw

    def node_footer(self, node_raw):
        if len(node_raw) < NODE_FOOTER_OFF + 20:
            return None
        return {"nid": _le32(node_raw, NODE_FOOTER_OFF),
                "ino": _le32(node_raw, NODE_FOOTER_OFF + 4),
                "flag": _le32(node_raw, NODE_FOOTER_OFF + 8),
                "cp_ver": _le32(node_raw, NODE_FOOTER_OFF + 12),
                "next_blkaddr": _le32(node_raw, NODE_FOOTER_OFF + 16)}

    def inode(self, ino):
        """按 inode 号取 F2fsInode；节点号与 inode 号在 F2FS 里相同"""
        hit = self._node.get(ino)
        if hit is not None:
            return hit
        nat = self.nat_entry(ino)
        if nat is None or not nat["block_addr"]:
            self.notes.append("inode %d 的 NAT 项为空" % ino)
            return None
        raw = self.read_node_block(nat["block_addr"])
        if len(raw) < 4072:
            return None
        e = F2fsInode()
        e.nid = ino
        e.ino = ino
        e.mode = _le16(raw, 0x00)
        e.inline_flags = raw[0x03]
        e.uid = _le32(raw, 0x04)
        e.gid = _le32(raw, 0x08)
        e.links = _le32(raw, 0x0C)
        e.size = _le64(raw, 0x10)
        e.atime = _le64(raw, 0x20)
        e.ctime = _le64(raw, 0x28)
        e.mtime = _le64(raw, 0x30)
        e.pino = _le32(raw, 0x54)
        namelen = _le32(raw, 0x58)
        if 0 < namelen <= 8:
            try:
                e.name = raw[0x5C:0x5C + namelen].decode("utf-8", "replace")
            except Exception:
                e.name = raw[0x5C:0x5C + namelen].decode("latin-1", "replace")
        e.is_inline_data = bool(e.inline_flags & F2FS_INLINE_DATA)
        for i in range(DEF_ADDRS_PER_INODE):
            e.addr.append(_le32(raw, INODE_ADDR_OFF + i * 4))
        for i in range(5):
            e.nid_ptrs.append(_le32(raw, INODE_NID_OFF + i * 4))
        e.raw_footer = self.node_footer(raw)
        if e.raw_footer and e.raw_footer["nid"] not in (0, ino):
            self.notes.append("inode %d 的 footer nid=%d 不一致"
                              % (ino, e.raw_footer["nid"]))
        e._raw = raw
        if len(self._node) > 4096:
            self._node.clear()
        self._node[ino] = e
        return e

    # ---------------- 数据读取 ----------------
    def _read_data_blocks(self, addrs, want, out):
        bs = self.block_size
        for a in addrs:
            if len(out) >= want:
                return
            if a in (0, 0xFFFFFFFF):
                out += b"\x00" * min(bs, want - len(out))
                continue
            d = self.sub.read(a * bs, bs)
            out += d + b"\x00" * max(0, min(bs, want - len(out)) - len(d))

    def _walk_indirect(self, blk_addr, level, want, out):
        """level=1 一次间接（direct_node.addr），2 二次，3 三次"""
        if len(out) >= want or blk_addr in (0, 0xFFFFFFFF):
            return
        raw = self.read_node_block(blk_addr)
        if len(raw) < 24 + 4:
            return
        for i in range(DEF_ADDRS_PER_BLOCK):
            if len(out) >= want:
                return
            p = _le32(raw, i * 4)
            if level == 1:
                self._read_data_blocks([p], want, out)
            else:
                self._walk_indirect(p, level - 1, want, out)

    def _resolve(self, ent):
        """把 ino / 路径 / F2fsInode 统一成 F2fsInode"""
        if isinstance(ent, str):
            ent = self.lookup_path(ent)
        if ent is None:
            raise FileNotFoundError("找不到该 inode")
        if isinstance(ent, int):
            ent = self.inode(ent)
            if ent is None:
                raise FileNotFoundError("inode 读不到")
        return ent

    def read_file(self, ent, limit=None):
        """读文件数据；ent 可以是 ino、F2fsInode 或路径字符串"""
        ent = self._resolve(ent)
        if ent.is_dir:
            raise IsADirectoryError("ino %d 是目录" % ent.ino)
        want = ent.size if limit is None else min(ent.size, limit)
        return self._read_raw(ent, want)

    def _read_raw(self, ent, want):
        """不做目录检查地读 inode 的数据块（目录内容也走这条路）"""
        if want <= 0:
            return b""

        # inline 数据：数据就在 i_addr 区起始处
        if ent.is_inline_data:
            raw = getattr(ent, "_raw", b"")
            if raw:
                off = INODE_ADDR_OFF
                return raw[off:off + want]

        out = bytearray()
        # 先按直接块取，再按需要走间接
        self._read_data_blocks(ent.addr, want, out)
        if len(out) < want and len(ent.nid_ptrs) >= 1:
            self._walk_indirect(ent.nid_ptrs[0], 1, want, out)
        if len(out) < want and len(ent.nid_ptrs) >= 2:
            self._walk_indirect(ent.nid_ptrs[1], 2, want, out)
        if len(out) < want and len(ent.nid_ptrs) >= 3:
            self._walk_indirect(ent.nid_ptrs[2], 3, want, out)
        if len(out) < want:
            self.notes.append("ino %d 声明 %d 字节，只取到 %d"
                              % (ent.ino, want, len(out)))
            out += b"\x00" * (want - len(out))
        return bytes(out[:want])

    # ---------------- 目录 ----------------
    def _parse_dentry_block(self, raw):
        """解析一个 dentry 块 -> [F2fsDirent]"""
        out = []
        if len(raw) < FILENAME_ARR_OFF:
            return out
        # F2FS 的长文件名占用**连续多个 8 字节槽位**，槽位按 dentry 顺序密集排布，
        # 所以名字起点要按「已用槽位游标」走，不能用 dentry 下标直接索引。
        slot = 0
        for i in range(DENTRY_PER_BLOCK):
            p = DENTRY_ARR_OFF + i * DENTRY_SIZE
            if p + DENTRY_SIZE > len(raw):
                break
            ino = _le32(raw, p + 4)
            nlen = _le16(raw, p + 8)
            ftype = raw[p + 10]
            if ino == 0 or nlen == 0:
                continue
            nslots = (nlen + SLOT_LEN - 1) // SLOT_LEN
            f = FILENAME_ARR_OFF + slot * SLOT_LEN
            slot += nslots
            name = raw[f:min(f + nslots * SLOT_LEN, len(raw))][:nlen]
            if not name:
                continue
            try:
                txt = name.decode("utf-8")
            except UnicodeDecodeError:
                txt = name.decode("gbk", "replace")
            out.append(F2fsDirent(txt, ino, ftype, _le32(raw, p)))
        return out

    def listdir(self, ino=None):
        """列目录；ino 为 None 时用超级块里的 root_ino"""
        if ino is None:
            ino = self.sb["root_ino"]
        if isinstance(ino, F2fsInode):
            ino = ino.ino
        e = self.inode(ino)
        if e is None:
            return []
        if not e.is_dir:
            return []
        data = self._read_raw(e, e.size)
        out = []
        for off in range(0, len(data), self.block_size):
            out.extend(self._parse_dentry_block(data[off:off + self.block_size]))
        return out

    def walk(self, ino=None, _depth=0, _max=64, _seen=None):
        if _seen is None:
            _seen = set()
        if ino is None:
            ino = self.sb["root_ino"]
        if ino in _seen or _depth > _max:
            return
        _seen.add(ino)
        for d in self.listdir(ino):
            yield d
            if d.is_dir:
                for sub in self.walk(d.ino, _depth + 1, _max, _seen):
                    yield sub

    def lookup_path(self, path):
        cur = self.sb["root_ino"]
        for part in [p for p in path.split("/") if p]:
            hit = None
            for d in self.listdir(cur):
                if d.name == part:
                    hit = d
                    break
            if hit is None:
                return None
            cur = hit.ino
        return self.inode(cur)

    def find(self, pattern, _max=4096):
        low = pattern.lower()
        out = []
        for d in self.walk():
            if low in d.name.lower():
                out.append(d)
                if len(out) >= _max:
                    break
        return out

    # ---------------- 摘要 ----------------
    def info(self):
        sb = self.sb
        return {
            "fs": "f2fs",
            "super_offset": self.sb_offset,
            "version": "%d.%d" % (sb["major_ver"], sb["minor_ver"]),
            "block_size": self.block_size,
            "blocks_per_seg": self.blocks_per_seg,
            "segment_count": sb["segment_count"],
            "segment_count_ckpt": sb["segment_count_ckpt"],
            "segment_count_sit": sb["segment_count_sit"],
            "segment_count_nat": sb["segment_count_nat"],
            "segment_count_ssa": sb["segment_count_ssa"],
            "segment_count_main": sb["segment_count_main"],
            "segment0_blkaddr": sb["segment0_blkaddr"],
            "cp_blkaddr": sb["cp_blkaddr"],
            "sit_blkaddr": sb["sit_blkaddr"],
            "nat_blkaddr": sb["nat_blkaddr"],
            "ssa_blkaddr": sb["ssa_blkaddr"],
            "main_blkaddr": sb["main_blkaddr"],
            "root_ino": sb["root_ino"],
            "node_ino": sb["node_ino"],
            "meta_ino": sb["meta_ino"],
            "block_count": sb["block_count"],
            "volume_name": sb["volume_name"],
            "uuid": sb["uuid"],
            "sb_crc_ok": sb.get("crc_ok"),
            "checkpoint": self.cp,
            "notes": list(self.notes),
        }


def probe(sub):
    """判断是否是 F2FS：偏移 1024 或 5120 处有魔数 0xF2F52010"""
    for off in (SUPER_OFFSET, SUPER_OFFSET + BLKSIZE):
        try:
            raw = sub.read(off, 4)
        except Exception:
            return False
        if len(raw) >= 4 and _le32(raw, 0) == SUPER_MAGIC:
            return True
    return False


def open_fs(sub):
    if not probe(sub):
        raise ValueError("不是 F2FS 文件系统（未找到魔数 0xF2F52010）")
    return F2fs(sub)


# ------------------------------------------------------------
# 自检
# ------------------------------------------------------------
if __name__ == "__main__":
    import io
    import sys
    import zlib

    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    PASS = [0]
    FAIL = [0]

    def ck(cond, name, extra=""):
        if cond:
            PASS[0] += 1
            print("  [PASS] %s %s" % (name, extra))
        else:
            FAIL[0] += 1
            print("  [FAIL] %s %s" % (name, extra))

    class MemSub(object):
        def __init__(self, data):
            self.data = bytes(data)
            self.size = len(self.data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    def crc32(b):
        return zlib.crc32(bytes(b)) & 0xFFFFFFFF

    BS = 4096
    # 布局（块号）：0=sb0, 1=sb1, 2..3=cp, 20..39=sit, 40..79=nat,
    # 100..=main 区；根 inode=3, 子目录 inode=4, 文件 inode=5
    SEG_BLKS = 512
    NBLK = 4096
    IMG = bytearray(NBLK * BS)

    def put_blk(blk, data):
        IMG[blk * BS:blk * BS + len(data)] = data

    # ---- 超级块 ----
    # 偏移逐条照 `f2fs_fs.h` 的 struct f2fs_super_block 排；
    # 超级块本身位于「块内偏移 0x400」，不是块首，所以不能直接用 put_blk。
    def make_sb():
        sb = bytearray(1024)
        struct.pack_into("<I", sb, 0x00, SUPER_MAGIC)
        struct.pack_into("<H", sb, 0x04, 1)          # major_ver
        struct.pack_into("<H", sb, 0x06, 15)         # minor_ver
        struct.pack_into("<I", sb, 0x08, 9)          # log_sectorsize
        struct.pack_into("<I", sb, 0x0C, 3)          # log_sectors_per_block
        struct.pack_into("<I", sb, 0x10, 12)         # log_blocksize = 4096
        struct.pack_into("<I", sb, 0x14, 9)          # log_blocks_per_seg = 512
        struct.pack_into("<I", sb, 0x18, 1)          # segs_per_sec
        struct.pack_into("<I", sb, 0x1C, 1)          # secs_per_zone
        struct.pack_into("<I", sb, 0x20, 0x100)      # checksum_offset
        struct.pack_into("<Q", sb, 0x24, NBLK)       # block_count
        struct.pack_into("<I", sb, 0x2C, 8)          # section_count
        struct.pack_into("<I", sb, 0x30, 8)          # segment_count
        struct.pack_into("<I", sb, 0x34, 1)          # segment_count_ckpt
        struct.pack_into("<I", sb, 0x38, 1)          # segment_count_sit
        struct.pack_into("<I", sb, 0x3C, 1)          # segment_count_nat
        struct.pack_into("<I", sb, 0x40, 1)          # segment_count_ssa
        struct.pack_into("<I", sb, 0x44, 4)          # segment_count_main
        struct.pack_into("<I", sb, 0x48, 0)          # segment0_blkaddr
        struct.pack_into("<I", sb, 0x4C, 2)          # cp_blkaddr
        struct.pack_into("<I", sb, 0x50, 20)         # sit_blkaddr
        struct.pack_into("<I", sb, 0x54, 40)         # nat_blkaddr
        struct.pack_into("<I", sb, 0x58, 80)         # ssa_blkaddr
        struct.pack_into("<I", sb, 0x5C, 100)        # main_blkaddr
        struct.pack_into("<I", sb, 0x60, 3)          # root_ino
        struct.pack_into("<I", sb, 0x64, 4)          # node_ino
        struct.pack_into("<I", sb, 0x68, 5)          # meta_ino
        sb[0x6C:0x7C] = bytes(range(16))             # uuid
        nm = "F2FSVOL".encode("utf-16-le")
        sb[0x7C:0x7C + len(nm)] = nm                 # volume_name[512]
        struct.pack_into("<I", sb, 0x100, 0)         # CRC 字段先清零
        struct.pack_into("<I", sb, 0x100, crc32(sb))
        return bytes(sb)

    # 超级块在「块内偏移 0x400」；两份副本分别在块 0 与块 1
    _SB = make_sb()
    IMG[SUPER_OFFSET:SUPER_OFFSET + len(_SB)] = _SB
    IMG[BLKSIZE + SUPER_OFFSET:BLKSIZE + SUPER_OFFSET + len(_SB)] = _SB

    # ---- checkpoint（版本 7） ----
    def make_cp(ver=7, csum_off=0x200):
        cp = bytearray(BS)
        struct.pack_into("<Q", cp, 0x00, ver)
        struct.pack_into("<Q", cp, 0x08, 16000)
        struct.pack_into("<Q", cp, 0x10, 120)
        struct.pack_into("<I", cp, 0x18, 2)
        struct.pack_into("<I", cp, 0x1C, 4)
        struct.pack_into("<I", cp, 0x20, 100)
        struct.pack_into("<I", cp, 0x84, 0x0001 | 0x0100)   # umount|trimmed
        struct.pack_into("<I", cp, 0x88, 8)
        struct.pack_into("<I", cp, 0x8C, 2)
        struct.pack_into("<I", cp, 0x90, 3)
        struct.pack_into("<I", cp, 0x94, 3)
        struct.pack_into("<I", cp, 0x98, 400)
        struct.pack_into("<I", cp, 0x9C, 64)
        struct.pack_into("<I", cp, 0xA0, 256)
        struct.pack_into("<I", cp, 0xA4, csum_off)
        struct.pack_into("<Q", cp, 0xA8, 12345)
        struct.pack_into("<I", cp, csum_off, 0)
        struct.pack_into("<I", cp, csum_off, crc32(cp))
        return bytes(cp)

    put_blk(2, make_cp(ver=7))
    put_blk(10, make_cp(ver=5))       # 第二份 pack，版本更低

    # ---- NAT ----
    def nat_off(nid):
        blk_idx, slot = divmod(nid, NAT_ENTRY_PER_BLOCK)
        return (40 + blk_idx) * BS + slot * NAT_ENTRY_SIZE

    def put_nat(nid, ino, blk):
        off = nat_off(nid)
        IMG[off] = 1
        struct.pack_into("<I", IMG, off + 1, ino)
        struct.pack_into("<I", IMG, off + 5, blk)

    # ---- node 块 ----
    def make_inode_node(ino, mode, size=0, addr=(), inline=None, name=b"",
                        pino=3, inline_flags=0):
        if isinstance(name, str):
            name = name.encode()
        name = name[:8]          # i_name 只有 F2FS_NAME_LEN=8 字节（SPOR 用）
        node = bytearray(BS)
        struct.pack_into("<H", node, 0x00, mode)
        node[0x03] = inline_flags
        struct.pack_into("<I", node, 0x04, 1000)
        struct.pack_into("<I", node, 0x08, 1000)
        struct.pack_into("<I", node, 0x0C, 1)
        struct.pack_into("<Q", node, 0x10, size)
        struct.pack_into("<Q", node, 0x20, 1700000000)
        struct.pack_into("<Q", node, 0x28, 1700000100)
        struct.pack_into("<Q", node, 0x30, 1700000200)
        struct.pack_into("<I", node, 0x54, pino)
        struct.pack_into("<I", node, 0x58, len(name))
        if isinstance(name, str):
            name = name.encode()
        name = name[:8]          # i_name 只有 F2FS_NAME_LEN=8 字节（SPOR 用）
        node[0x5C:0x5C + len(name)] = name
        if inline is not None:
            node[INODE_ADDR_OFF:INODE_ADDR_OFF + len(inline)] = inline
        else:
            for i, a in enumerate(addr):
                struct.pack_into("<I", node, INODE_ADDR_OFF + i * 4, a)
        # footer
        struct.pack_into("<I", node, NODE_FOOTER_OFF, ino)
        struct.pack_into("<I", node, NODE_FOOTER_OFF + 4, ino)
        struct.pack_into("<I", node, NODE_FOOTER_OFF + 8, 0)
        struct.pack_into("<I", node, NODE_FOOTER_OFF + 12, 7)
        struct.pack_into("<I", node, NODE_FOOTER_OFF + 16, 0xFFFFFFFF)
        return bytes(node)

    def make_dentry_block(entries):
        """entries: [(name_bytes, ino, ftype)]"""
        blk = bytearray(BS)
        slot = 0
        for i, (nm, ino, ft) in enumerate(entries):
            if i >= DENTRY_PER_BLOCK:
                break
            nslots = (len(nm) + SLOT_LEN - 1) // SLOT_LEN
            p = DENTRY_ARR_OFF + i * DENTRY_SIZE
            struct.pack_into("<I", blk, p, 0x1234 + i)      # hash
            struct.pack_into("<I", blk, p + 4, ino)
            struct.pack_into("<H", blk, p + 8, len(nm))
            blk[p + 10] = ft
            f = FILENAME_ARR_OFF + slot * SLOT_LEN
            blk[f:f + len(nm)] = nm
            slot += nslots
            bi = i // 8
            if bi < DENTRY_BITMAP_LEN:
                blk[bi] |= (1 << (i % 8))
        return bytes(blk)

    # 根目录 inode=3（目录），子目录 inode=6，文件 inode=5
    ROOT, FILE_INO, SUB_INO = 3, 5, 6
    FILE_DATA = b"Hello F2FS!\n" * 40
    SUB_DATA = "子目录内容".encode()

    # 文件 5：inline 数据
    put_nat(FILE_INO, FILE_INO, 300)
    put_blk(300, make_inode_node(FILE_INO, 0o100644, size=len(FILE_DATA),
                                 inline=FILE_DATA, inline_flags=F2FS_INLINE_DATA,
                                 name="hello.txt"))
    # 子目录 6（目录，数据用直接块）
    dir_blk = make_dentry_block([(b"inner.txt", FILE_INO, 1)])
    put_nat(SUB_INO, SUB_INO, 301)
    put_blk(301, make_inode_node(SUB_INO, 0o040755, size=BS, addr=(400,),
                                 name="sub"))
    put_blk(400, dir_blk)
    # 根目录 3：数据块含 hello.txt 与 sub 两个项
    root_blk = make_dentry_block([(b"hello.txt", FILE_INO, 1),
                                  ("中文.txt".encode(), FILE_INO, 1),
                                  (b"sub", SUB_INO, 2)])
    put_nat(ROOT, ROOT, 302)
    put_blk(302, make_inode_node(ROOT, 0o040755, size=BS, addr=(401,),
                                 name="/"))
    put_blk(401, root_blk)

    print("=== 1) 超级块与探测 ===")
    sub = MemSub(IMG)
    ck(probe(sub) is True, "probe 命中 F2FS")
    fs = F2fs(sub)
    inf = fs.info()
    ck(inf["version"] == "1.15", "版本 1.15", inf["version"])
    ck(inf["block_size"] == BS, "块大小 4096", inf["block_size"])
    ck(inf["blocks_per_seg"] == 512, "每段块数 512", inf["blocks_per_seg"])
    ck(inf["segment_count_main"] == 4, "main 段数 4", inf["segment_count_main"])
    ck(inf["root_ino"] == ROOT, "root_ino", inf["root_ino"])
    ck(inf["volume_name"] == "F2FSVOL", "卷名", inf["volume_name"])
    ck(inf["uuid"] == bytes(range(16)).hex(), "uuid", inf["uuid"])
    ck(inf["sb_crc_ok"] is True, "超级块 CRC 通过")
    ck(inf["super_offset"] == SUPER_OFFSET, "用主超级块", inf["super_offset"])

    print()
    print("=== 2) checkpoint ===")
    cp = inf["checkpoint"]
    ck(cp is not None and cp["checkpoint_ver"] == 7, "取到版本 7 的 checkpoint",
       cp["checkpoint_ver"] if cp else None)
    ck(cp["crc_ok"] is True, "checkpoint CRC 通过")
    ck("umount" in cp["flags"] and "trimmed" in cp["flags"], "标志位解码",
       cp["flags"])
    ck(cp["valid_node_count"] == 3, "valid_node_count", cp["valid_node_count"])
    ck(cp["next_free_nid"] == 400, "next_free_nid", cp["next_free_nid"])

    print()
    print("=== 3) NAT / SIT ===")
    ne = fs.nat_entry(FILE_INO)
    ck(ne is not None and ne["block_addr"] == 300, "NAT: ino 5 -> 块 300",
       ne["block_addr"] if ne else None)
    ck(fs.nat_entry(9999)["block_addr"] == 0, "未分配的 NAT 项 block_addr=0")
    se = fs.sit_entry(0)
    ck(se is not None, "SIT 段 0 可读", se is not None)

    print()
    print("=== 4) inode ===")
    e = fs.inode(FILE_INO)
    ck(e is not None, "inode 5 解析成功")
    ck(e.mode == 0o100644, "i_mode", "0o%o" % e.mode)
    ck(e.size == len(FILE_DATA), "i_size", e.size)
    ck(e.uid == 1000 and e.gid == 1000, "uid/gid")
    ck(e.name == "hello.tx", "i_name 只存 8 字节（已截断）", e.name)
    ck(e.mtime == 1700000200, "i_mtime", e.mtime)
    ck(e.is_inline_data is True, "inline 标志")
    ck(e.raw_footer is not None and e.raw_footer["nid"] == FILE_INO,
       "footer nid 一致")
    root = fs.inode(ROOT)
    ck(root is not None and root.is_dir, "根 inode 是目录")
    ck(root.dtype == 1, "dtype=dir", root.dtype)

    print()
    print("=== 5) 读文件（inline）===")
    got = fs.read_file(e)
    ck(got == FILE_DATA, "inline 文件内容一致", "%d B" % len(got))
    ck(fs.read_file(e, limit=10) == FILE_DATA[:10], "read_file limit")

    print()
    print("=== 6) 目录遍历 ===")
    ents = fs.listdir(ROOT)
    names = sorted(d.name for d in ents)
    ck(names == ["hello.txt", "sub", "中文.txt"], "根目录 3 项", names)
    d1 = [d for d in ents if d.name == "hello.txt"][0]
    ck(d1.ino == FILE_INO and d1.file_type == 1, "hello.txt 目录项",
       "ino=%d type=%d" % (d1.ino, d1.file_type))
    d2 = [d for d in ents if d.name == "sub"][0]
    ck(d2.is_dir, "sub 是目录项")
    walked = sorted(d.name for d in fs.walk())
    ck(walked == ["hello.txt", "inner.txt", "sub", "中文.txt"],
       "walk 覆盖 4 项", walked)

    print()
    print("=== 7) lookup_path / find ===")
    h = fs.lookup_path("/hello.txt")
    ck(h is not None and h.ino == FILE_INO, "/hello.txt 可解析",
       h.ino if h else None)
    ck(fs.lookup_path("/sub") is not None, "/sub 可解析")
    ck(fs.lookup_path("/nope") is None, "不存在路径返回 None")
    f = fs.find("hello")
    ck(len(f) == 1 and f[0].name == "hello.txt", "find(hello)")

    print()
    print("=== 8) 中文文件名 ===")
    ck("中文.txt" in walked, "中文目录项名字解码正确", [w for w in walked
                                                if not w.isascii()])

    print()
    print("=== 9) 容错与报错 ===")
    ck(probe(MemSub(bytes(8192))) is False, "全零不是 F2FS")
    ck(probe(MemSub(b"")) is False, "零长不是 F2FS")
    try:
        open_fs(MemSub(bytes(8192)))
        ck(False, "open_fs 非 F2FS 应报错")
    except ValueError as ex:
        ck(True, "open_fs 非 F2FS 报错", str(ex)[:40])
    # 主超级块坏 -> 回退到副本
    bad = bytearray(IMG)
    struct.pack_into("<I", bad, SUPER_OFFSET, 0xDEADBEEF)
    fs2 = F2fs(MemSub(bytes(bad)))
    ck(fs2.sb_offset == SUPER_OFFSET + BLKSIZE, "主 SB 坏时回退到副本",
       fs2.sb_offset)
    ck(any("副本" in n for n in fs2.notes), "回退有 note")
    # 截断
    try:
        F2fs(MemSub(bytes(2048)))
        ck(False, "过短镜像应报错")
    except ValueError:
        ck(True, "过短镜像报错")

    print()
    print("=" * 64)
    print("F2FS：超级块（双副本+CRC）/ checkpoint（取高版本+CRC+标志）/")
    print("NAT / SIT / inode（含 footer 与 inline）/ 目录项 / walk / lookup / find")
    print("通过 %d 项，失败 %d 项" % (PASS[0], FAIL[0]))
    if FAIL[0]:
        raise SystemExit(1)
    print("f2fs 模块自检全部通过")
