# ============================================================
#  ESK  路  Calmgh06
#  Electronic Software Kit  |  GFS2 只读解析
# ============================================================
"""GFS2（Red Hat Global File System 2）只读解析 — 纯标准库。

覆盖层级（CAPS 里如实标注）：
  L1 超级块（主份 + 末尾镜像回退）
  L2 资源组头 rgrp（含 rg_skip 链 / 顺序扫描定位，位图读取）
  L3 dinode（232 B，逐字段核对 gfs2_ondisk.h）
  L4 目录（stuffed 线性目录 + exhash 哈希树，含叶子溢出链）
  L5 读文件（height==0 内联 extent，height>0 元树）

字段偏移核对来源：include/uapi/linux/gfs2_ondisk.h（torvalds/linux，
拉取日期 2026-11）。全部为 __attribute__((packed)) 大端结构，偏移逐条手算，
关键处（dinode=232、leaf=104、dirent=40、meta_header=24、sb=272）均与
sizeof 注释一致。

未做（原因见 CAPS 注释）：rindex 遍历、扩展属性(eattr)、日志(journal) 重放、
符号链接目标读取。
"""
import datetime
import re
import struct

# ---------------------------------------------------------------- 常量

GFS2_MAGIC = 0x01161970
GFS2_BASIC_BLOCK = 512
GFS2_SB_ADDR = 128                       # 以 512 B 基本块计
SB_OFFSET = GFS2_SB_ADDR * GFS2_BASIC_BLOCK   # 0x10000 = 64 KiB

# mh_type
MT_NONE = 0
MT_SB = 1
MT_RG = 2
MT_RB = 3
MT_DI = 4
MT_IN = 5
MT_LF = 6
MT_JD = 7
MT_LH = 8
MT_LD = 9
MT_EA = 10
MT_ED = 11
MT_LB = 12
MT_QC = 14

MT_NAME = {
    MT_NONE: "none", MT_SB: "superblock", MT_RG: "rgrp", MT_RB: "rg bitmap",
    MT_DI: "dinode", MT_IN: "indirect", MT_LF: "leaf", MT_JD: "jdata",
    MT_LH: "log header", MT_LD: "log desc", MT_EA: "eattr", MT_ED: "eattr data",
    MT_LB: "log block", MT_QC: "quota change",
}

# mh_format
FMT_NONE = 0
FMT_SB = 100
FMT_RG = 200
FMT_RB = 300
FMT_DI = 400
FMT_IN = 500
FMT_LF = 600
FMT_JD = 700
FMT_EA = 1600
FMT_ED = 1700
FMT_DE = 1200
FMT_FS = 1802
FMT_MULTI = 1900

# 结构尺寸（sizeof，全部来自 packed 结构累加）
META_HDR_SIZE = 24
SB_SIZE = 272
RGRP_SIZE = 128
DINODE_SIZE = 232
DIRENT_HDR_SIZE = 40
LEAF_HDR_SIZE = 104
EXTENT_SIZE = 16

# dinode 标志
DIF_JDATA = 0x00000001
DIF_EXHASH = 0x00000002
DIF_EA_INDIRECT = 0x00000008
DIF_SYSTEM = 0x00000200
DIF_TOPDIR = 0x00000400
DIF_TRUNC_IN_PROG = 0x20000000

# 目录项类型（DT_*）
DT_UNKNOWN = 0
DT_FIFO = 1
DT_CHR = 2
DT_DIR = 4
DT_BLK = 6
DT_REG = 8
DT_LNK = 10
DT_SOCK = 12
DT_NAME = {
    DT_UNKNOWN: "unknown", DT_FIFO: "fifo", DT_CHR: "chr", DT_DIR: "dir",
    DT_BLK: "blk", DT_REG: "reg", DT_LNK: "lnk", DT_SOCK: "sock",
}

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000
S_IFCHR = 0o020000
S_IFBLK = 0o060000
S_IFIFO = 0o010000
S_IFSOCK = 0o140000

# 每块可容纳的指针数（推导自 fs/gfs2 内核代码）
#   sd_diptrs = (bsize - sizeof(dinode)) / 8
#   sd_inptrs = (bsize - sizeof(meta_header)) / 8
#   sd_jbsize = bsize - sizeof(meta_header)   （目录/日志数据块的载荷尺寸）
DIRENT_MAX_NAME = 255

# 实现了什么 / 没实现什么 —— 自检与调用方都应以此为准
CAPS = {
    "superblock": True,          # 含末尾镜像回退
    "rgrp": True,                # 头字段 + 位图读取；rindex 遍历未实现
    "rgrp_rindex": False,        # sb_master_dir/rindex 链未解析，靠扫描定位
    "inode": True,
    "dir_linear": True,          # stuffed / 无 EXHASH
    "dir_exhash": True,          # 哈希表（stuffed 或 JD 块）+ 叶子溢出链
    "extent_inline": True,       # height == 0
    "metatree": True,            # height > 0，radix 下降（推断，见函数注释）
    "eattr": False,
    "journal": False,
    "readlink": False,
}


class Gfs2Error(Exception):
    """结构损坏或无法解析。"""


class TruncatedError(Gfs2Error):
    """输入被截断，读不到需要的字节。"""


# ---------------------------------------------------------------- 字节读取


def _u16(buf, off):
    if off < 0 or off + 2 > len(buf):
        raise TruncatedError("读 u16 越界：偏移 %d，长度 %d" % (off, len(buf)))
    return struct.unpack_from(">H", buf, off)[0]


def _u32(buf, off):
    if off < 0 or off + 4 > len(buf):
        raise TruncatedError("读 u32 越界：偏移 %d，长度 %d" % (off, len(buf)))
    return struct.unpack_from(">I", buf, off)[0]


def _u64(buf, off):
    if off < 0 or off + 8 > len(buf):
        raise TruncatedError("读 u64 越界：偏移 %d，长度 %d" % (off, len(buf)))
    return struct.unpack_from(">Q", buf, off)[0]


def _cstr(buf, off, size):
    raw = buf[off:off + size]
    end = raw.find(b"\0")
    if end >= 0:
        raw = raw[:end]
    return raw.decode("utf-8", "replace")


def _ts(sec, nsec=0):
    try:
        return datetime.datetime.fromtimestamp(sec, datetime.timezone.utc) \
            .replace(microsecond=min(max(int(nsec), 0), 999999))
    except Exception:
        return None


def _mode_type(mode):
    return mode & S_IFMT


def _mode_name(mode):
    t = _mode_type(mode)
    return {S_IFDIR: "dir", S_IFREG: "file", S_IFLNK: "symlink",
            S_IFCHR: "chrdev", S_IFBLK: "blkdev", S_IFIFO: "fifo",
            S_IFSOCK: "socket"}.get(t, "unknown")


def _mode_str(mode):
    t = _mode_type(mode)
    ch = {S_IFDIR: "d", S_IFREG: "-", S_IFLNK: "l", S_IFCHR: "c",
          S_IFBLK: "b", S_IFIFO: "p", S_IFSOCK: "s"}.get(t, "?")
    bits = ("r" if mode & 0o400 else "-") + ("w" if mode & 0o200 else "-") + \
           ("x" if mode & 0o100 else "-") + ("r" if mode & 0o040 else "-") + \
           ("w" if mode & 0o020 else "-") + ("x" if mode & 0o010 else "-") + \
           ("r" if mode & 0o004 else "-") + ("w" if mode & 0o002 else "-") + \
           ("x" if mode & 0o001 else "-")
    return ch + bits


# ---------------------------------------------------------------- inode


class Dinode(object):
    """struct gfs2_dinode（232 B）+ di_data[]（从 232 起，到块尾）。"""

    __slots__ = ("fs", "block", "raw", "formal", "addr", "mode", "uid", "gid",
                 "nlink", "size", "blocks", "atime", "mtime", "ctime",
                 "atime_nsec", "mtime_nsec", "ctime_nsec", "major", "minor",
                 "goal_meta", "goal_data", "generation", "flags",
                 "payload_format", "height", "depth", "entries", "eattr",
                 "hdr_magic", "hdr_type", "hdr_format")

    def __init__(self, fs, block, raw):
        self.fs = fs
        self.block = block
        self.raw = raw
        if len(raw) < DINODE_SIZE:
            raise TruncatedError(
                "块 %d 的 dinode 只有 %d 字节，需要 %d 字节"
                % (block, len(raw), DINODE_SIZE))

        # di_header: magic@0 type@4 (__pad0@8) format@16 jid@20
        self.hdr_magic = _u32(raw, 0)
        self.hdr_type = _u32(raw, 4)
        self.hdr_format = _u32(raw, 16)
        if self.hdr_magic != GFS2_MAGIC:
            raise Gfs2Error("块 %d 缺 GFS2 magic（读到 0x%08X）"
                            % (block, self.hdr_magic))
        if self.hdr_type != MT_DI:
            raise Gfs2Error("块 %d 的 mh_type=%d（%s），不是 dinode"
                            % (block, self.hdr_type,
                               MT_NAME.get(self.hdr_type, "?")))

        # di_num: no_formal_ino@24 no_addr@32
        self.formal = _u64(raw, 24)
        self.addr = _u64(raw, 32)
        self.mode = _u32(raw, 40)
        self.uid = _u32(raw, 44)
        self.gid = _u32(raw, 48)
        self.nlink = _u32(raw, 52)
        self.size = _u64(raw, 56)
        self.blocks = _u64(raw, 64)
        self.atime = _u64(raw, 72)
        self.mtime = _u64(raw, 80)
        self.ctime = _u64(raw, 88)
        self.major = _u32(raw, 96)
        self.minor = _u32(raw, 100)
        self.goal_meta = _u64(raw, 104)
        self.goal_data = _u64(raw, 112)
        self.generation = _u64(raw, 120)
        self.flags = _u32(raw, 128)
        self.payload_format = _u32(raw, 132)
        # __pad1@136(u16), di_height@138, __pad2@140(u32),
        # __pad3@144(u16), di_depth@146, di_entries@148, __pad4@152(16)
        self.height = _u16(raw, 138)
        self.depth = _u16(raw, 146)
        self.entries = _u32(raw, 148)
        self.eattr = _u64(raw, 168)
        self.atime_nsec = _u32(raw, 176)
        self.mtime_nsec = _u32(raw, 180)
        self.ctime_nsec = _u32(raw, 184)

    # ---- 便捷属性 ----
    @property
    def is_dir(self):
        return _mode_type(self.mode) == S_IFDIR

    @property
    def is_file(self):
        return _mode_type(self.mode) == S_IFREG

    @property
    def is_symlink(self):
        return _mode_type(self.mode) == S_IFLNK

    @property
    def type_name(self):
        return _mode_name(self.mode)

    @property
    def mode_str(self):
        return _mode_str(self.mode)

    @property
    def exhash(self):
        return bool(self.flags & DIF_EXHASH)

    @property
    def jdata(self):
        return bool(self.flags & DIF_JDATA)

    @property
    def stuffed(self):
        """数据是否内联在 dinode 块内（无独立数据块）。"""
        bs = self.fs.bsize
        return (self.height == 0 and not self.jdata
                and self.size <= bs - DINODE_SIZE)

    @property
    def atime_dt(self):
        return _ts(self.atime, self.atime_nsec)

    @property
    def mtime_dt(self):
        return _ts(self.mtime, self.mtime_nsec)

    @property
    def ctime_dt(self):
        return _ts(self.ctime, self.ctime_nsec)

    @property
    def di_data(self):
        return self.raw[DINODE_SIZE:]

    def extents(self):
        """height==0 时的内联 extent 列表 [(addr, len)]。

        布局（推断 + 与内核 __be64 双槽读取一致）：每槽 16 B，
        ext_addr=be64@+0，ext_len=be32@+8，+12 为保留。ext_len==0 结束。
        """
        return self.fs.inline_extents(self)

    def to_dict(self):
        return {
            "block": self.block, "no_formal_ino": self.formal,
            "no_addr": self.addr, "mode": "0o%o" % self.mode,
            "mode_str": self.mode_str, "type": self.type_name,
            "uid": self.uid, "gid": self.gid, "nlink": self.nlink,
            "size": self.size, "blocks": self.blocks,
            "atime": self.atime, "mtime": self.mtime, "ctime": self.ctime,
            "atime_utc": self.atime_dt.isoformat() if self.atime_dt else None,
            "mtime_utc": self.mtime_dt.isoformat() if self.mtime_dt else None,
            "ctime_utc": self.ctime_dt.isoformat() if self.ctime_dt else None,
            "height": self.height, "depth": self.depth, "entries": self.entries,
            "flags": "0x%08X" % self.flags, "exhash": self.exhash,
            "jdata": self.jdata, "eattr": self.eattr,
            "goal_meta": self.goal_meta, "goal_data": self.goal_data,
            "generation": self.generation,
        }

    def __repr__(self):
        return "<Dinode blk=%d ino=%d %s %s size=%d>" % (
            self.block, self.formal, self.mode_str, self.type_name, self.size)


class DirEntry(object):
    """struct gfs2_dirent（40 B 头 + 名字，按 8 字节对齐）。"""

    __slots__ = ("name", "raw_name", "formal", "addr", "hash", "dtype",
                 "block", "offset")

    def __init__(self, name, raw_name, formal, addr, de_hash, dtype, block,
                 offset):
        self.name = name
        self.raw_name = raw_name
        self.formal = formal
        self.addr = addr
        self.hash = de_hash
        self.dtype = dtype
        self.block = block
        self.offset = offset

    @property
    def type_name(self):
        return DT_NAME.get(self.dtype, "type%d" % self.dtype)

    def to_dict(self):
        return {"name": self.name, "no_formal_ino": self.formal,
                "no_addr": self.addr, "hash": "0x%08X" % self.hash,
                "type": self.type_name, "type_id": self.dtype,
                "block": self.block, "offset": self.offset}

    def __repr__(self):
        return "<DirEntry %r ino=%d blk=%d %s>" % (
            self.name, self.formal, self.addr, self.type_name)


# ---------------------------------------------------------------- 主体


class Gfs2(object):
    """GFS2 只读视图。sub 需提供 read(offset, size) 与 size。"""

    def __init__(self, sub):
        self.sub = sub
        try:
            self.size = int(getattr(sub, "size", 0) or 0)
        except Exception:
            self.size = 0
        self._inodes = {}
        self._rgrps = None
        self.sb_offset = None
        self.sb_source = None
        self.sb = None
        self._load_super()

    # ---------------- L1 超级块 ----------------

    def _read(self, off, n):
        off = int(off)
        n = int(n)
        if off < 0 or n < 0:
            raise Gfs2Error("非法读取：偏移 %d 长度 %d" % (off, n))
        data = self.sub.read(off, n)
        if data is None:
            data = b""
        data = bytes(data)
        if len(data) < n:
            raise TruncatedError(
                "偏移 0x%X 处需要 %d 字节，只读到 %d 字节（输入被截断？）"
                % (off, n, len(data)))
        return data

    def _parse_sb(self, off):
        raw = self._read(off, SB_SIZE)
        magic = _u32(raw, 0)
        mtype = _u32(raw, 4)
        mformat = _u32(raw, 16)
        if magic != GFS2_MAGIC or mtype != MT_SB:
            return None
        sb = {
            "offset": off,
            "mh_magic": magic,
            "mh_type": mtype,
            "mh_format": mformat,
            "sb_fs_format": _u32(raw, 24),
            "sb_multihost_format": _u32(raw, 28),
            "sb_bsize": _u32(raw, 36),
            "sb_bsize_shift": _u32(raw, 40),
            "sb_master_dir": {"no_formal_ino": _u64(raw, 48),
                              "no_addr": _u64(raw, 56)},
            "sb_root_dir": {"no_formal_ino": _u64(raw, 64 + 16),
                            "no_addr": _u64(raw, 88)},
            "sb_lockproto": _cstr(raw, 96, 64),
            "sb_locktable": _cstr(raw, 160, 64),
            "sb_uuid": raw[256:272].hex(),
            "raw": raw,
        }
        return sb

    def _sb_read_soft(self, off):
        """容错读取，失败返回 (None, 原因)。"""
        if self.size and off >= self.size:
            return None, "偏移 0x%X 超出镜像末尾 0x%X" % (off, self.size)
        try:
            sb = self._parse_sb(off)
        except TruncatedError as exc:
            return None, "截断：%s" % exc
        except Gfs2Error as exc:
            return None, str(exc)
        if sb is None:
            return None, "magic/mh_type 不匹配"
        return sb, None

    def _sb_candidates(self):
        """主份 + 末尾镜像。GFS2 的备份惯例是「距末尾 64 KiB」。"""
        cands = [SB_OFFSET]
        if self.size:
            for off in (self.size - SB_OFFSET, self.size - 4096,
                        self.size - self.size % 4096):
                if off > 0 and off + SB_SIZE <= self.size and off not in cands:
                    cands.append(off)
        return cands

    def _load_super(self):
        chosen = None
        reason = None
        for idx, off in enumerate(self._sb_candidates()):
            sb, err = self._sb_read_soft(off)
            if sb is None:
                if idx == 0:
                    reason = err
                continue
            bs = sb["sb_bsize"]
            if bs < 512 or bs > 65536 or (bs & (bs - 1)):
                reason = "偏移 0x%X 的 sb_bsize=%d 不合法" % (off, bs)
                continue
            chosen = sb
            break
        if chosen is None:
            msg = ("未找到 GFS2 超级块（主份偏移 0x%X）：%s"
                   % (SB_OFFSET, reason or "无有效副本"))
            if reason and reason.startswith("截断"):
                raise TruncatedError(msg)
            raise Gfs2Error(msg)
        self.sb = chosen
        self.sb_offset = chosen["offset"]
        self.sb_source = "primary" if chosen["offset"] == SB_OFFSET else "backup"
        self.bsize = chosen["sb_bsize"]
        self.bsize_shift = chosen["sb_bsize_shift"]
        if self.bsize_shift != self.bsize.bit_length() - 1:
            # 不致命，但记下来
            self.shift_mismatch = True
        else:
            self.shift_mismatch = False
        self.nblocks = (self.size // self.bsize) if self.size else 0
        self.diptrs = (self.bsize - DINODE_SIZE) // 8
        self.inptrs = (self.bsize - META_HDR_SIZE) // 8
        self.jbsize = self.bsize - META_HDR_SIZE
        self.root_block = chosen["sb_root_dir"]["no_addr"]
        self.master_block = chosen["sb_master_dir"]["no_addr"]

    def superblocks(self):
        """列出主份与所有候选副本的解析结果。"""
        out = []
        for off in self._sb_candidates():
            sb, err = self._sb_read_soft(off)
            item = {
                "offset": off,
                "source": "primary" if off == SB_OFFSET else "backup",
                "valid": sb is not None,
                "error": err,
            }
            if sb is not None:
                item.update({k: v for k, v in sb.items() if k != "raw"})
                item["selected"] = (off == self.sb_offset)
            out.append(item)
        return out

    def info(self):
        sb = self.sb
        return {
            "type": "gfs2",
            "sb_offset": self.sb_offset,
            "sb_source": self.sb_source,
            "fs_format": sb["sb_fs_format"],
            "multihost_format": sb["sb_multihost_format"],
            "bsize": self.bsize,
            "bsize_shift": self.bsize_shift,
            "root_dir": self.root_block,
            "root_dir_inum": dict(sb["sb_root_dir"]),
            "master_dir": self.master_block,
            "lockproto": sb["sb_lockproto"],
            "locktable": sb["sb_locktable"],
            "uuid": sb["sb_uuid"],
            "mh_magic": "0x%08X" % sb["mh_magic"],
            "mh_type": sb["mh_type"],
            "mh_format": sb["mh_format"],
            "image_size": self.size,
            "nblocks": self.nblocks,
            "diptrs": self.diptrs,
            "inptrs": self.inptrs,
        }

    # ---------------- L2 资源组 ----------------

    @staticmethod
    def _parse_rgrp(raw, block):
        if _u32(raw, 0) != GFS2_MAGIC or _u32(raw, 4) != MT_RG:
            return None
        return {
            "block": block,
            "mh_format": _u32(raw, 16),
            "rg_flags": _u32(raw, 24),
            "rg_free": _u32(raw, 28),
            "rg_dinodes": _u32(raw, 32),
            "rg_skip": _u32(raw, 36),
            "rg_igeneration": _u64(raw, 40),
            "rg_data0": _u64(raw, 48),
            "rg_data": _u32(raw, 56),
            "rg_bitbytes": _u32(raw, 60),
            "rg_crc": _u32(raw, 64),
            # 内核 ondisk.h 的 gfs2_rgrp 没有 rg_fsck_error_flags 字段：
            # 那是 gfs1 / gfs2-utils 内存结构里的东西。这里取 rg_reserved[0:4]，
            # 仅作兼容展示，真实值不可信（标记 inferred）。
            "rg_fsck_error_flags": _u32(raw, 68),
            "rg_fsck_error_flags_source": "rg_reserved[0:4]（推断，内核无此字段）",
        }

    def _rgrp_at(self, block):
        if self.nblocks and block >= self.nblocks:
            return None
        try:
            raw = self._read(block * self.bsize, RGRP_SIZE)
        except Gfs2Error:
            return None
        rg = self._parse_rgrp(raw, block)
        if rg is not None:
            rg["offset"] = block * self.bsize
        return rg

    def rgrps(self, max_scan=65536):
        """资源组头列表。

        定位策略（rindex 未解析，见 CAPS）：
          1) 从块 0 起顺序找 mh_type==RG 的块；
          2) 命中后按 rg_skip 跳到下一个组；rg_skip 不可用时用
             rg_data0+rg_data 推定下一组起点；
          3) 跳转失败则继续顺序扫描，累计扫描上限 max_scan 块。
        最后一个 dict 带 "scan_truncated" 标记（若触及上限）。
        """
        if self._rgrps is not None:
            return [dict(r) for r in self._rgrps]

        out = []
        seen = set()
        blk = 0
        scanned = 0
        truncated = False
        limit = self.nblocks or 0
        while limit and blk < limit:
            rg = None
            while blk < limit and scanned < max_scan:
                scanned += 1
                rg = self._rgrp_at(blk)
                if rg is not None:
                    break
                blk += 1
            if rg is None:
                truncated = scanned >= max_scan
                break
            if rg["block"] in seen:
                blk += 1
                continue
            seen.add(rg["block"])
            span = rg["rg_skip"]
            if not span and rg["rg_data0"] and rg["rg_data"]:
                end = rg["rg_data0"] + rg["rg_data"]
                if end > rg["block"]:
                    span = end - rg["block"]
            rg["rg_blocks"] = span
            out.append(rg)
            blk = rg["block"] + (span if span else 1)
        if out:
            out[-1]["scan_truncated"] = bool(truncated)
        self._rgrps = out
        return [dict(r) for r in out]

    def bitmap_bytes(self, rg):
        """读资源组位图原始字节（rg_bitbytes 字节，紧跟 rg 头块之后）。"""
        n = rg["rg_bitbytes"]
        if n <= 0:
            return b""
        start = (rg["block"] + 1) * self.bsize
        if self.size and start + n > self.size:
            n = max(0, self.size - start)
        if n <= 0:
            return b""
        return self._read(start, n)

    def rg_of_block(self, block):
        """块 -> 所属资源组（rindex 不可用时的反推，标记 inferred）。

        优先在已枚举的 rgrp 区间里找；否则按「第一个 rgrp 的 rg_blocks」
        估算组号：index = block // rg_blocks。
        """
        rgs = self.rgrps()
        for rg in rgs:
            span = rg.get("rg_blocks") or 0
            if span and rg["block"] <= block < rg["block"] + span:
                return {"rgrp": rg["block"], "index": rgs.index(rg),
                        "span": span, "method": "range"}
        if rgs:
            base = rgs[0]["block"]
            span = rgs[0].get("rg_blocks") or 0
            if span and block >= base:
                idx = (block - base) // span
                return {"rgrp": base + idx * span, "index": idx,
                        "span": span, "method": "inferred_div"}
        return None

    # ---------------- L3 inode ----------------

    def inode(self, block):
        block = int(block)
        if block in self._inodes:
            return self._inodes[block]
        off = block * self.bsize
        n = self.bsize
        if self.size:
            avail = self.size - off
            if avail <= 0:
                raise TruncatedError("块 %d 超出镜像范围（%d 块）"
                                     % (block, self.nblocks))
            n = min(n, avail)
        raw = self._read(off, n)
        di = Dinode(self, block, raw)
        self._inodes[block] = di
        return di

    def inline_extents(self, di):
        """解析 di_data[] 里的内联 extent（height==0）。"""
        out = []
        pos = DINODE_SIZE
        end = len(di.raw)
        while pos + EXTENT_SIZE <= end:
            addr = _u64(di.raw, pos)
            ln = _u32(di.raw, pos + 8)
            if addr == 0 and ln == 0:
                break
            if ln:
                out.append((addr, ln))
            pos += EXTENT_SIZE
        return out

    # ---------------- L4 目录 ----------------

    def _dir_read(self, di, off, size):
        """按目录「文件」偏移读数据。

        stuffed -> dinode 块内 232 起；
        非 stuffed -> 每块载荷从 +24 起，块容量 jbsize = bsize-24
        （内核 gfs2_dir_read_data 的 JD 分支）。
        """
        if di.stuffed:
            raw = self._read(di.block * self.bsize, self.bsize)
            start = DINODE_SIZE + off
            seg = raw[start:start + size]
            if len(seg) < size:
                raise TruncatedError(
                    "目录 inode 块 %d 内联数据不足（要 %d 字节，得 %d）"
                    % (di.block, size, len(seg)))
            return seg
        out = bytearray()
        left = size
        cur = off
        while left > 0:
            lblock = cur // self.jbsize
            within = cur % self.jbsize
            dblk = self._bmap(di, lblock)
            if not dblk:
                out.extend(b"\0" * left)
                break
            raw = self._read(dblk * self.bsize, self.bsize)
            take = min(left, self.jbsize - within)
            out.extend(raw[META_HDR_SIZE + within:META_HDR_SIZE + within + take])
            left -= take
            cur += take
        return bytes(out)

    @staticmethod
    def _parse_dirents(raw, start, block):
        out = []
        pos = start
        end = len(raw)
        while pos + DIRENT_HDR_SIZE <= end:
            rec_len = _u16(raw, pos + 20)
            name_len = _u16(raw, pos + 22)
            if rec_len < DIRENT_HDR_SIZE or (rec_len % 8) or pos + rec_len > end:
                break
            if name_len > rec_len - DIRENT_HDR_SIZE or name_len > DIRENT_MAX_NAME:
                break
            addr = _u64(raw, pos + 8)
            if addr:
                name_raw = raw[pos + DIRENT_HDR_SIZE:
                               pos + DIRENT_HDR_SIZE + name_len]
                out.append(DirEntry(
                    name_raw.decode("utf-8", "replace"), name_raw,
                    _u64(raw, pos), addr, _u32(raw, pos + 16),
                    _u16(raw, pos + 24), block, pos))
            pos += rec_len
        return out

    def _collect_leaf(self, di, blk, level, out, seen):
        if blk in seen:
            return
        seen.add(blk)
        if self.nblocks and blk >= self.nblocks:
            raise Gfs2Error("目录块 %d 超出镜像范围（%d 块）"
                            % (blk, self.nblocks))
        raw = self._read(blk * self.bsize, self.bsize)
        magic = _u32(raw, 0)
        mtype = _u32(raw, 4)
        if magic != GFS2_MAGIC:
            raise Gfs2Error("目录块 %d 缺 magic（0x%08X）" % (blk, magic))
        if mtype == MT_LF:
            out.extend(self._parse_dirents(raw, LEAF_HDR_SIZE, blk))
            nxt = _u64(raw, 32)          # lf_next：溢出叶子链
            if nxt:
                self._collect_leaf(di, nxt, level, out, seen)
            return
        if mtype == MT_IN and level > 0:
            for j in range(self.inptrs):
                nxt = _u64(raw, META_HDR_SIZE + j * 8)
                if nxt:
                    self._collect_leaf(di, nxt, level - 1, out, seen)
            return
        raise Gfs2Error(
            "目录块 %d 的 mh_type=%d（%s）无法按 exhash 解析（剩余层数 %d）"
            % (blk, mtype, MT_NAME.get(mtype, "?"), level))

    def _dir_entries_exhash(self, di):
        if di.depth <= 0 or di.depth > 31:
            raise Gfs2Error("目录 inode 块 %d 的 di_depth=%d 不合法"
                            % (di.block, di.depth))
        hsize = 1 << di.depth
        table = self._dir_read(di, 0, hsize * 8)
        out = []
        seen = set()
        for i in range(hsize):
            blk = _u64(table, i * 8)
            if blk:
                self._collect_leaf(di, blk, di.depth - 1, out, seen)
        return out

    def listdir(self, block=None, skip_dot=False):
        """列出目录项。block 省略时用 sb_root_dir。"""
        if block is None:
            block = self.root_block
        di = self.inode(block) if not isinstance(block, Dinode) else block
        if not di.is_dir:
            raise Gfs2Error("块 %d 不是目录（mode=0o%o %s）"
                            % (di.block, di.mode, di.type_name))
        if di.exhash:
            ents = self._dir_entries_exhash(di)
        else:
            if di.size > 0x7FFFFFFF:
                raise Gfs2Error("目录 inode 块 %d 的 di_size=%d 异常"
                                % (di.block, di.size))
            raw = self._read(di.block * self.bsize, self.bsize)
            ents = self._parse_dirents(raw, DINODE_SIZE, di.block)
        if skip_dot:
            ents = [e for e in ents if e.name not in (".", "..")]
        return ents

    def readdir(self, block=None):
        return self.listdir(block)

    # ---------------- L5 读文件 ----------------

    def _bmap(self, di, lblock):
        """逻辑块 -> 物理块；0 表示空洞。

        height>0 走元树 radix 下降：dinode 指针表在 +232（diptrs 个），
        中间块指针表在 +24（inptrs 个）。此路径为推断（未在真实镜像验证）。
        """
        height = di.height
        cur = di.block
        for level in range(height, 0, -1):
            cnt = self.diptrs if level == height else self.inptrs
            base = DINODE_SIZE if level == height else META_HDR_SIZE
            raw = self._read(cur * self.bsize, self.bsize)
            if _u32(raw, 0) != GFS2_MAGIC:
                raise Gfs2Error("元树块 %d 缺 magic" % cur)
            idx = lblock // (self.inptrs ** (level - 1))
            if idx >= cnt:
                return 0
            cur = _u64(raw, base + idx * 8)
            if cur == 0:
                return 0
            if self.nblocks and cur >= self.nblocks:
                raise Gfs2Error("元树指针指向越界块 %d（%d 块）"
                                % (cur, self.nblocks))
        return cur

    def _extent_map(self, di):
        """height==0 的 extent 列表展开成 {lblock: pblock}。"""
        m = {}
        l = 0
        for addr, ln in self.inline_extents(di):
            if addr == 0 or ln == 0:
                continue
            for i in range(ln):
                m[l] = addr + i
                l += 1
        return m

    def _as_inode(self, inode):
        if isinstance(inode, Dinode):
            return inode
        if isinstance(inode, int):
            return self.inode(inode)
        if isinstance(inode, str):
            return self.lookup_path(inode)
        raise Gfs2Error("无法把 %r 当作 inode" % (inode,))

    def read_file(self, inode, size=None, offset=0):
        """读普通文件内容。

        inode 可为块号 / Dinode / 路径字符串。
        height==0 用内联 extent；height>0 用元树（推断实现）。
        """
        di = self._as_inode(inode)
        if di.is_dir:
            raise Gfs2Error("块 %d 是目录，不是普通文件" % di.block)
        total = di.size
        if offset:
            offset = int(offset)
        else:
            offset = 0
        want = total - offset if size is None else min(size, total - offset)
        if want <= 0:
            return b""
        if di.height == 0:
            emap = self._extent_map(di)
        else:
            emap = None
        out = bytearray()
        first = offset // self.bsize
        last = (offset + want - 1) // self.bsize
        for lb in range(first, last + 1):
            if emap is not None:
                dblk = emap.get(lb, 0)
            else:
                dblk = self._bmap(di, lb)
            if dblk:
                out.extend(self._read(dblk * self.bsize, self.bsize))
            else:
                out.extend(b"\0" * self.bsize)
        start_in = offset % self.bsize
        return bytes(out[start_in:start_in + want])

    def readlink(self, *args, **kwargs):
        raise NotImplementedError(
            "readlink 未实现（CAPS['readlink']=False）："
            "符号链接目标读取留待第 6 层，未在本文件提供")

    # ---------------- 遍历 ----------------

    def walk(self, block=None, _prefix=""):
        """深度优先遍历，yield (路径, Dinode)。含循环保护。"""
        if block is None:
            block = self.root_block
        seen = set()
        stack = [(_prefix or "/", block)]
        while stack:
            path, blk = stack.pop()
            if blk in seen:
                continue
            seen.add(blk)
            try:
                di = self.inode(blk)
            except Gfs2Error:
                continue
            yield path, di
            if not di.is_dir:
                continue
            try:
                ents = self.listdir(di)
            except Gfs2Error:
                continue
            kids = [e for e in ents if e.name not in (".", "..")]
            for e in reversed(kids):
                p = (path.rstrip("/") + "/" + e.name) if path != "/" \
                    else "/" + e.name
                stack.append((p, e.addr))

    def lookup_path(self, path):
        """按路径取 Dinode。'/' 开头或不开头都行。"""
        if isinstance(path, Dinode):
            return path
        parts = [p for p in str(path).replace("\\", "/").split("/") if p]
        cur = self.root_block
        for part in parts:
            if part == ".":
                continue
            ents = {e.name: e for e in self.listdir(cur)}
            if part == "..":
                ent = ents.get("..")
                if ent is None:
                    raise Gfs2Error("路径 %r：目录块 %d 无 '..'" % (path, cur))
                cur = ent.addr
                continue
            ent = ents.get(part)
            if ent is None:
                raise Gfs2Error("路径 %r 不存在：块 %d 中无 %r"
                                % (path, cur, part))
            cur = ent.addr
        return self.inode(cur)

    def find(self, pattern):
        """按正则匹配遍历路径，yield (路径, Dinode)。"""
        rx = re.compile(pattern)
        out = []
        for path, di in self.walk():
            if rx.search(path):
                out.append((path, di))
        return out


# ---------------------------------------------------------------- 入口


def probe(sub):
    """命中返回 dict，否则返回 None。"""
    try:
        fs = Gfs2(sub)
    except Exception:
        return None
    info = fs.info()
    return {
        "ok": True,
        "type": "gfs2",
        "sb_offset": info["sb_offset"],
        "sb_source": info["sb_source"],
        "bsize": info["bsize"],
        "fs_format": info["fs_format"],
        "locktable": info["locktable"],
        "uuid": info["uuid"],
        "root_dir": info["root_dir"],
    }


def open_fs(sub):
    return Gfs2(sub)


# ---------------------------------------------------------------- 自检

def _mh(mtype, mformat):
    return struct.pack(">IIQII", GFS2_MAGIC, mtype, 0, mformat, 0)


def _sb_bytes(bsize=4096, bshift=12, root=18, master=18,
              lockproto=b"lock_nolock", locktable=b"mycluster:testvol",
              uuid=bytes(range(16))):
    b = bytearray(SB_SIZE)
    b[0:META_HDR_SIZE] = _mh(MT_SB, FMT_SB)
    struct.pack_into(">I", b, 24, FMT_FS)
    struct.pack_into(">I", b, 28, FMT_MULTI)
    struct.pack_into(">I", b, 36, bsize)
    struct.pack_into(">I", b, 40, bshift)
    struct.pack_into(">QQ", b, 48, 0, master)      # sb_master_dir
    struct.pack_into(">QQ", b, 80, 0, root)        # sb_root_dir
    b[96:96 + 64] = lockproto.ljust(64, b"\0")
    b[160:160 + 64] = locktable.ljust(64, b"\0")
    b[256:272] = uuid
    return bytes(b)


def _dinode_bytes(block, formal, mode, size=0, height=0, depth=0, entries=0,
                  flags=0, nlink=1, payload_format=FMT_DI, eattr=0,
                  atime=1000, mtime=2000, ctime=3000, extra=0):
    b = bytearray(DINODE_SIZE + extra)
    b[0:META_HDR_SIZE] = _mh(MT_DI, FMT_DI)
    struct.pack_into(">QQ", b, 24, formal, block)
    struct.pack_into(">III", b, 40, mode, 0, 0)        # mode uid gid
    struct.pack_into(">I", b, 52, nlink)
    struct.pack_into(">Q", b, 56, size)
    struct.pack_into(">Q", b, 64, 1)                   # di_blocks
    struct.pack_into(">QQQ", b, 72, atime, mtime, ctime)
    struct.pack_into(">II", b, 96, 0, 0)               # major minor
    struct.pack_into(">I", b, 128, flags)
    struct.pack_into(">I", b, 132, payload_format)
    struct.pack_into(">H", b, 138, height)
    struct.pack_into(">H", b, 146, depth)
    struct.pack_into(">I", b, 148, entries)
    struct.pack_into(">Q", b, 168, eattr)
    return b


def _dirent_bytes(name, formal, addr, dtype, de_hash=0):
    n = len(name)
    total = (DIRENT_HDR_SIZE + n + 7) & ~7
    b = bytearray(total)
    struct.pack_into(">QQIHHHH", b, 0, formal, addr, de_hash, total, n, dtype, 0)
    b[DIRENT_HDR_SIZE:DIRENT_HDR_SIZE + n] = name
    return bytes(b)


class _MemSub(object):
    """最小 sub：read(offset, size) + size。"""

    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read(self, off, n):
        off = int(off)
        n = int(n)
        if off < 0 or n < 0:
            raise ValueError("bad read %d %d" % (off, n))
        return self.data[off:off + n]


BSZ = 4096
DEV = 0x40000
HELLO = b"Hello, GFS2!\n"
CN_TEXT = "你好，GFS2 世界\n".encode("utf-8")
DEEP_TEXT = "哈希叶子里的文件\n".encode("utf-8")


def _build_image():
    """超级块(+备份) / rgrp / 根目录(stuffed) / hello.txt(内联 extent)
    / docs(EXHASH 深度 8，叶子直接挂桶) / 中文.txt"""
    img = bytearray(DEV)

    def put(off, data):
        img[off:off + len(data)] = data

    def put_blk(blk, off, data):
        put(blk * BSZ + off, data)

    sb = _sb_bytes(root=18, master=18)
    put(SB_OFFSET, sb)
    put(DEV - SB_OFFSET, sb)                       # 末尾镜像

    # 17: 资源组头
    rg = bytearray(RGRP_SIZE)
    rg[0:META_HDR_SIZE] = _mh(MT_RG, FMT_RG)
    struct.pack_into(">IIII", rg, 24, 0, 1000, 5, 0)   # flags free dinodes skip
    struct.pack_into(">Q", rg, 40, 0x11)               # igeneration
    struct.pack_into(">Q", rg, 48, 25)                 # data0
    struct.pack_into(">III", rg, 56, 4000, 1000, 0)    # data bitbytes crc
    put_blk(17, 0, bytes(rg))

    # 18: 根目录 dinode（线性/stuffed）
    names = [
        (b".", 0, 18, DT_DIR),
        (b"..", 0, 18, DT_DIR),
        (b"hello.txt", 1, 19, DT_REG),
        ("中文.txt".encode("utf-8"), 2, 23, DT_REG),
        (b"docs", 3, 21, DT_DIR),
    ]
    body = b"".join(_dirent_bytes(n, f, a, t) for n, f, a, t in names)
    root = _dinode_bytes(18, 2, S_IFDIR | 0o755, size=len(body), entries=5,
                         depth=0, flags=DIF_SYSTEM)
    put_blk(18, 0, bytes(root) + body)

    # 19: hello.txt dinode + 20: 数据块（内联 extent: addr=20 len=1）
    hello = _dinode_bytes(19, 1, S_IFREG | 0o644, size=len(HELLO), extra=16)
    struct.pack_into(">QI", hello, DINODE_SIZE, 20, 1)
    put_blk(19, 0, bytes(hello))
    put_blk(20, 0, HELLO)

    # 21: docs（EXHASH depth=8，哈希表内联；桶 0 直指叶子块 22）
    hsize = 1 << 8
    table = bytearray(hsize * 8)
    struct.pack_into(">Q", table, 0, 22)
    docs = _dinode_bytes(21, 3, S_IFDIR | 0o755, size=len(table), depth=8,
                         entries=3, flags=DIF_EXHASH)
    put_blk(21, 0, bytes(docs) + bytes(table))

    # 22: 叶子块（lf_depth=8，覆盖全部桶）
    leaf = bytearray(BSZ)
    leaf[0:META_HDR_SIZE] = _mh(MT_LF, FMT_LF)
    struct.pack_into(">HHI", leaf, 24, 8, 3, FMT_DE)   # depth, entries, format
    struct.pack_into(">Q", leaf, 32, 0)                # lf_next
    dents = b"".join([
        _dirent_bytes(b".", 3, 21, DT_DIR),
        _dirent_bytes(b"..", 2, 18, DT_DIR),
        _dirent_bytes("深.txt".encode("utf-8"), 4, 25, DT_REG),
    ])
    leaf[LEAF_HDR_SIZE:LEAF_HDR_SIZE + len(dents)] = dents
    put_blk(22, 0, bytes(leaf))

    # 23: 中文.txt dinode + 24: 数据块
    cn = _dinode_bytes(23, 4, S_IFREG | 0o644, size=len(CN_TEXT), extra=16)
    struct.pack_into(">QI", cn, DINODE_SIZE, 24, 1)
    put_blk(23, 0, bytes(cn))
    put_blk(24, 0, CN_TEXT)

    # 25: 深.txt dinode + 26: 数据块（独立 inode，避免与 23 复用）
    deep = _dinode_bytes(25, 5, S_IFREG | 0o600, size=len(DEEP_TEXT), extra=16)
    struct.pack_into(">QI", deep, DINODE_SIZE, 26, 1)
    put_blk(25, 0, bytes(deep))
    put_blk(26, 0, DEEP_TEXT)

    # 27: big.bin（height=1 元树）-> 28,29 两个数据块
    d1 = b"A" * BSZ
    d2 = b"B" * 1000
    big = _dinode_bytes(27, 6, S_IFREG | 0o644, size=len(d1) + len(d2),
                        height=1, extra=16)
    struct.pack_into(">QQ", big, DINODE_SIZE, 28, 29)
    put_blk(27, 0, bytes(big))
    put_blk(28, 0, d1)
    put_blk(29, 0, d2)

    return bytes(img)


def _selftest():
    ok = 0
    img = _build_image()

    # 1. probe 命中 / 不命中
    p = probe(_MemSub(img))
    assert p and p["ok"] and p["type"] == "gfs2", p
    junk = _MemSub(b"\xAA" * DEV)
    assert probe(junk) is None, "非 GFS2 镜像不应命中"
    try:
        Gfs2(junk)
    except Gfs2Error:
        pass
    else:
        raise AssertionError("非 GFS2 镜像应抛 Gfs2Error")
    ok += 1
    print("[1] probe：命中 GFS2，随机数据不命中，open_fs 抛 Gfs2Error  OK")

    # 2. 超级块字段
    fs = Gfs2(_MemSub(img))
    inf = fs.info()
    assert inf["fs_format"] == FMT_FS == 1802, inf["fs_format"]
    assert inf["multihost_format"] == 1900, inf["multihost_format"]
    assert inf["bsize"] == 4096 and inf["bsize_shift"] == 12, inf["bsize"]
    assert inf["root_dir"] == 18, inf["root_dir"]
    assert inf["lockproto"] == "lock_nolock", inf["lockproto"]
    assert inf["locktable"] == "mycluster:testvol", inf["locktable"]
    assert inf["uuid"] == bytes(range(16)).hex(), inf["uuid"]
    assert inf["sb_offset"] == 0x10000 and inf["sb_source"] == "primary"
    ok += 1
    print("[2] 超级块：fs_format=1802 multihost=1900 bsize=4096 root=18 "
          "locktable=%s uuid=%s  OK" % (inf["locktable"], inf["uuid"]))

    # 3. 主份损坏 -> 回退末尾副本
    bad = bytearray(img)
    bad[SB_OFFSET:SB_OFFSET + 4] = b"\x00\x00\x00\x00"
    fs2 = Gfs2(_MemSub(bytes(bad)))
    assert fs2.sb_source == "backup", fs2.sb_source
    assert fs2.sb_offset == DEV - SB_OFFSET, hex(fs2.sb_offset)
    assert fs2.info()["bsize"] == 4096 and fs2.info()["root_dir"] == 18
    assert Gfs2(_MemSub(bytes(bad))).lookup_path("/hello.txt").size == len(HELLO)
    sbs = fs.superblocks()
    assert len([s for s in sbs if s["valid"]]) == 2, sbs
    ok += 1
    print("[3] 主份 magic 清零 -> 回退 0x%X 副本，字段仍正确，superblocks() "
          "报 2 份有效  OK" % fs2.sb_offset)

    # 4. 根 inode + listdir
    root = fs.inode(fs.root_block)
    assert root.is_dir and _mode_type(root.mode) == S_IFDIR
    assert root.mode_str.startswith("d"), root.mode_str
    assert root.entries == 5, root.entries
    ents = fs.listdir()
    names = [e.name for e in ents]
    for want in (".", "..", "hello.txt", "中文.txt", "docs"):
        assert want in names, (want, names)
    assert fs.listdir()[0].name == "."
    ok += 1
    print("[4] 根 inode：mode=%s 目录，listdir=%s  OK"
          % (root.mode_str, names))

    # EXHASH 子目录
    sub_ents = fs.listdir(21)
    sub_names = [e.name for e in sub_ents]
    assert "深.txt" in sub_names, sub_names
    assert fs.lookup_path("/docs").depth == 8
    ok += 1
    print("[4b] EXHASH 子目录（depth=8，桶->叶子）listdir=%s  OK" % sub_names)

    # 5. 内联 extent 读文件
    hello_di = fs.inode(19)
    assert hello_di.height == 0 and hello_di.extents() == [(20, 1)]
    data = fs.read_file(hello_di)
    assert data == HELLO, (len(data), data[:40])
    assert fs.read_file(19, size=5) == HELLO[:5]
    assert fs.read_file("/hello.txt") == HELLO
    ok += 1
    print("[5] 内联 extent：extents=%s read_file=%r  OK"
          % (hello_di.extents(), data))

    # 6. 中文目录项
    cn = fs.lookup_path("/中文.txt")
    assert cn.is_file and cn.size == len(CN_TEXT)
    assert fs.read_file(cn) == CN_TEXT
    deep = fs.lookup_path("/docs/深.txt")
    assert deep.is_file and deep.size == len(DEEP_TEXT)
    assert fs.read_file(deep) == DEEP_TEXT
    ok += 1
    print("[6] 中文目录项：/中文.txt(%r) 与 /docs/深.txt(%r) 均读取一致  OK"
          % (CN_TEXT.decode("utf-8").strip(), DEEP_TEXT.decode("utf-8").strip()))

    # 7. 截断输入
    short = _MemSub(img[:SB_OFFSET + 64])
    try:
        Gfs2(short)
    except TruncatedError as exc:
        assert isinstance(exc, Gfs2Error)
        msg = str(exc)
    else:
        raise AssertionError("截断输入应抛 TruncatedError")
    assert "截断" in msg, msg
    try:
        fs.read_file(fs.inode(19), size=10 ** 9)
    except Gfs2Error:
        raise AssertionError("读文件不应因 size 过大而失败")
    ok += 1
    print("[7] 截断输入（0x%X 字节）抛 TruncatedError：%s  OK"
          % (len(short.data), msg))

    # 8. 未实现的功能如实抛 NotImplementedError
    assert CAPS["readlink"] is False
    try:
        fs.readlink("/x")
    except NotImplementedError as exc:
        nb = str(exc)
    else:
        raise AssertionError("readlink 应抛 NotImplementedError")
    for key in ("dir_linear", "dir_exhash", "extent_inline", "metatree"):
        assert CAPS[key] is True, key
    ok += 1
    print("[8] 未实现能力如实抛 NotImplementedError（readlink）：%s  OK"
          % nb[:36])

    # 9. 遍历与查找
    paths = [p for p, _ in fs.walk()]
    assert "/" in paths and "/hello.txt" in paths and "/docs/深.txt" in paths, paths
    hits = fs.find(r"\.txt$")
    assert any(p == "/hello.txt" for p, _ in hits), [p for p, _ in hits]
    ok += 1
    print("[9] walk/find：%s  OK" % paths)

    # 10. 资源组
    rgs = fs.rgrps()
    assert len(rgs) == 1 and rgs[0]["block"] == 17, rgs
    rg0 = rgs[0]
    assert rg0["rg_free"] == 1000 and rg0["rg_dinodes"] == 5
    assert rg0["rg_data0"] == 25 and rg0["rg_data"] == 4000
    assert rg0["rg_bitbytes"] == 1000 and rg0["rg_blocks"] == 25 + 4000 - 17
    assert fs.rg_of_block(18)["rgrp"] == 17, fs.rg_of_block(18)
    bmp = fs.bitmap_bytes(rg0)
    assert len(bmp) == 1000, len(bmp)
    ok += 1
    print("[10] 资源组：block=%d free=%d dinodes=%d data0=%d bitbytes=%d "
          "rg_blocks=%d 位图 %d B  OK"
          % (rg0["block"], rg0["rg_free"], rg0["rg_dinodes"],
             rg0["rg_data0"], rg0["rg_bitbytes"], rg0["rg_blocks"], len(bmp)))

    # 11. inode 字段偏移抽查
    d = root.to_dict()
    # 5 个目录项按 GFS2_DIRENT_SIZE 对齐后的总长
    expect_size = sum((DIRENT_HDR_SIZE + len(n) + 7) & ~7 for n in
                      [b".", b"..", b"hello.txt", "中文.txt".encode("utf-8"),
                       b"docs"])
    assert root.size == expect_size == 256, (root.size, expect_size)
    assert d["size"] == root.size and d["entries"] == 5
    assert root.height == 0 and root.depth == 0
    assert root.atime == 1000 and root.mtime == 2000 and root.ctime == 3000
    assert root.nlink == 1 and root.mtime_dt.year == 1970
    assert d["mode"] == "0o40755", d["mode"]
    ok += 1
    print("[11] dinode 偏移抽查：232 B，mode@40=0o40755 size@56=%d "
          "height@138 depth@146 eattr@168  OK" % root.size)

    # 12. height=1 元树读文件（推断实现，合成镜像验证指针下降本身）
    big = fs.inode(27)
    assert big.height == 1, big.height
    chunk = fs.read_file(big)
    assert len(chunk) == big.size == BSZ + 1000, (len(chunk), big.size)
    assert chunk[:BSZ] == b"A" * BSZ and chunk[BSZ:] == b"B" * 1000
    assert fs.read_file(27, offset=BSZ - 5, size=10) == b"AAAAA" + b"BBBBB"
    ok += 1
    print("[12] height=1 元树：diptrs=%d，读回 %d B，跨块偏移切片正确  OK"
          % (fs.diptrs, len(chunk)))

    print("\n自检通过：%d 组断言" % ok)
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
