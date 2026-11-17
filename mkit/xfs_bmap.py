#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XFS bmap b-tree（BMAP / BMA3）独立只读解析器。

本模块刻意不依赖 ``mkit/xfs.py``：调用方只需给出 dinode 里 data fork 那段字节
（从 core 起）、blocksize、inode_size、core 长度与 forkoff，就能拿回一份按
``startoff`` 升序排列的 extent 描述列表。只用到 stdlib ``struct``。

布局（已验证）
-------------
``xfs_bmbt_rec`` —— 16 字节，``lo`` u64 大端 + ``hi`` u64 大端::

    state      = (lo >> 63) & 1                      # 1 = unwritten
    startoff   = (lo >> 9) & ((1 << 54) - 1)         # 54 bit
    startblock = ((lo & 0x1FF) << 43) | (hi >> 21)   # 52 bit
    blockcount = hi & 0x1FFFFF                       # 21 bit

内联根 ``xfs_bmdr_block``（dinode data fork 起始处）::

    0              : bb_level   u16 BE
    2              : bb_numrecs u16 BE
    4              : keys       numrecs * 8B（br_startoff, BE）
    4 + maxrecs*8  : ptrs       numrecs * 8B（u64 fsb）
    maxrecs = (fork_len - 4) // 16
    level == 0 时该层直接是 xfs_bmbt_rec，起点 = 4

外部 btree 块（``xfs_btree_block`` long 形式，块首）::

    0 : bb_magic   u32 BE = 0x424D4150("BMAP") 或 0x424D4133("BMA3")
    4 : bb_level   u16 BE
    6 : bb_numrecs u16 BE
    hlen: "BMAP" -> 24, "BMA3" -> 72
    maxrecs = (blocksize - hlen) // 16
    level == 0: recs 起于 hlen，每条 16B
    level >  0: keys 起于 hlen；ptrs 起于 hlen + maxrecs*8，每项 8B fsb
    块字节偏移 = fsb * blocksize

空 fork 行为（明确约定）
------------------------
``fork`` 为 ``b""``、或整段全零（即 bb_level=0 / bb_numrecs=0）时，
:func:`read_bmap` **返回空列表** ``[]``，不抛异常 —— 在 XFS 里等价于"没有
extent"（例如刚创建的空文件）。**只有结构损坏才抛** :class:`XfsBmapError`：
magic 不符、ptr 越界、成环/重复引用、超深、numrecs > maxrecs、
子块 level 与父层期望不符、读不足一个块。

fork_len 的两种解释
-------------------
``forkoff != 0`` 时历史上有两种读法：

* A（真实内核语义）：``di_forkoff << 3`` 是属性 fork 相对 **inode 起始**的
  偏移，因此 data fork 长度 = ``(forkoff << 3) - core``；
* B：``fork_len = forkoff << 3``（直接把 forkoff 当成 fork 长度）。

两者都作为候选、A 优先：逐个尝试完整解析，谁能让 inline root 与沿途所有子块
（magic / level / numrecs）自洽就用谁；都失败则抛错并附上两侧失败原因。

注：keys 数组只用于真实内核的二分定位，本实现按 ``bb_numrecs`` 遍历全部 ptr，
不依赖 key 值，所以 keys 全零的合成镜像同样可解。

自检：``python mkit/xfs_bmap.py``（纯合成镜像，退出码 0 表示全过）。
"""

from __future__ import annotations

import struct
import sys

__all__ = [
    "XfsBmapError",
    "BMAP_MAGIC",
    "BMA3_MAGIC",
    "MAGIC_HLEN",
    "decode_bmbt_rec",
    "encode_bmbt_rec",
    "read_bmap",
]

# ---------------------------------------------------------------- 常量 / 位域

BMAP_MAGIC = 0x424D4150  # "BMAP"，老式无 CRC 块头
BMA3_MAGIC = 0x424D4133  # "BMA3"，带 CRC 块头
MAGIC_HLEN = {BMAP_MAGIC: 24, BMA3_MAGIC: 72}

REC_SIZE = 16          # xfs_bmbt_rec 字节数
ROOT_HDR_SIZE = 4      # xfs_bmdr_block 头（bb_level + bb_numrecs）
KEY_SIZE = 8           # br_startoff
PTR_SIZE = 8           # fsb

STATE_SHIFT = 63
STARTOFF_SHIFT = 9
STARTOFF_MASK = (1 << 54) - 1
STARTBLOCK_SPLIT = 43                  # startblock 高 9 位在 lo、低 43 位在 hi
STARTBLOCK_LO_MASK = 0x1FF
STARTBLOCK_HI_MASK = (1 << STARTBLOCK_SPLIT) - 1
BLOCKCOUNT_MASK = (1 << 21) - 1
STARTBLOCK_MAX = (1 << 52) - 1


class XfsBmapError(ValueError):
    """bmap 结构损坏 / 无法解释时抛出。"""


# ------------------------------------------------------------ 单条 extent 记录


def decode_bmbt_rec(buf, off=0) -> tuple:
    """解一条 16 字节 ``xfs_bmbt_rec``。

    返回 ``(startblock, blockcount, startoff, state)``。
    越界或长度不足抛 :class:`XfsBmapError`。
    """
    if buf is None or len(buf) - off < REC_SIZE or off < 0:
        raise XfsBmapError(
            "bmbt_rec 长度不足: off=%r len=%r (需要 %d 字节)"
            % (off, 0 if buf is None else len(buf), REC_SIZE)
        )
    lo, hi = struct.unpack_from(">QQ", buf, off)
    state = (lo >> STATE_SHIFT) & 1
    startoff = (lo >> STARTOFF_SHIFT) & STARTOFF_MASK
    startblock = ((lo & STARTBLOCK_LO_MASK) << STARTBLOCK_SPLIT) | (hi >> 21)
    blockcount = hi & BLOCKCOUNT_MASK
    return (startblock, blockcount, startoff, state)


def encode_bmbt_rec(startblock, blockcount, startoff, state=0) -> bytes:
    """:func:`decode_bmbt_rec` 的逆运算（供构造测试镜像用）。"""
    if not isinstance(startblock, int) or not 0 <= startblock <= STARTBLOCK_MAX:
        raise XfsBmapError("startblock 越界: %r (0..%d)" % (startblock, STARTBLOCK_MAX))
    if not isinstance(blockcount, int) or not 0 <= blockcount <= BLOCKCOUNT_MASK:
        raise XfsBmapError("blockcount 越界: %r (0..%d)" % (blockcount, BLOCKCOUNT_MASK))
    if not isinstance(startoff, int) or not 0 <= startoff <= STARTOFF_MASK:
        raise XfsBmapError("startoff 越界: %r (0..%d)" % (startoff, STARTOFF_MASK))
    if state not in (0, 1):
        raise XfsBmapError("state 只能 0/1: %r" % (state,))
    lo = ((state & 1) << STATE_SHIFT) | (startoff << STARTOFF_SHIFT) | (
        (startblock >> STARTBLOCK_SPLIT) & STARTBLOCK_LO_MASK
    )
    hi = ((startblock & STARTBLOCK_HI_MASK) << 21) | (blockcount & BLOCKCOUNT_MASK)
    return struct.pack(">QQ", lo, hi)


def _rec_dict(startblock, blockcount, startoff, state):
    return {
        "startblock": startblock,
        "blockcount": blockcount,
        "startoff": startoff,
        "state": state,
    }


# ---------------------------------------------------------------- fork_len 候选


def _fork_len_candidates(inode_size, core, forkoff, have):
    """返回候选 fork 长度列表（A 优先）。候选需 4 <= flen <= len(fork)。"""
    if forkoff:
        raw = [
            ("A:(forkoff<<3)-core", (int(forkoff) << 3) - int(core)),
            ("B:forkoff<<3", int(forkoff) << 3),
        ]
    else:
        raw = [("inode_size-core", int(inode_size) - int(core))]

    out, seen = [], set()
    for label, flen in raw:
        if flen in seen:
            continue
        seen.add(flen)
        if flen < ROOT_HDR_SIZE:
            continue
        if flen > have:  # fork 切片不够长，无法安全解析 root 的 keys/ptrs 区
            continue
        out.append((label, flen))
    return out


# ------------------------------------------------------------------- 块读取


def _read_block(reader, fsb, blocksize):
    """按 fsb 读一个整块；越界/读不足统一抛 XfsBmapError。"""
    if blocksize <= 0:
        raise XfsBmapError("blocksize 必须为正: %r" % (blocksize,))
    if fsb < 0:
        raise XfsBmapError("ptr 越界: 负 fsb %r" % (fsb,))
    off = fsb * blocksize
    size = getattr(reader, "size", None)
    if isinstance(size, int) and not isinstance(size, bool):
        if off + blocksize > size:
            raise XfsBmapError(
                "ptr 越界: fsb=%d -> offset=%d + blocksize=%d > reader.size=%d"
                % (fsb, off, blocksize, size)
            )
    buf = reader.read(off, blocksize)
    if buf is None or len(buf) < blocksize:
        raise XfsBmapError(
            "ptr 越界/读不足: fsb=%d offset=%d 只取到 %d 字节 < blocksize=%d"
            % (fsb, off, 0 if buf is None else len(buf), blocksize)
        )
    return bytes(buf)


# ------------------------------------------------------------ 外部 btree 块


def _walk_block(reader, fsb, expect_level, blocksize, max_depth, visited):
    """递归下钻一个外部 btree 块，返回该子树里的全部 extent dict。"""
    if expect_level < 0:
        raise XfsBmapError("内部错误: expect_level < 0 (fsb=%d)" % (fsb,))
    if expect_level > max_depth:
        raise XfsBmapError(
            "超深: 期望 level %d > max_depth %d (fsb=%d)"
            % (expect_level, max_depth, fsb)
        )
    if fsb in visited:
        raise XfsBmapError("成环/重复引用: fsb %d 已被访问过（bmap 环）" % (fsb,))
    visited.add(fsb)

    buf = _read_block(reader, fsb, blocksize)
    magic = struct.unpack_from(">I", buf, 0)[0]
    hlen = MAGIC_HLEN.get(magic)
    if hlen is None:
        raise XfsBmapError(
            "magic 不符: fsb=%d 处 bb_magic=0x%08X（期望 0x%08X BMAP / 0x%08X BMA3）"
            % (fsb, magic, BMAP_MAGIC, BMA3_MAGIC)
        )
    level, numrecs = struct.unpack_from(">HH", buf, 4)
    if level != expect_level:
        raise XfsBmapError(
            "level 不自洽: fsb=%d bb_level=%d，父层期望 %d"
            % (fsb, level, expect_level)
        )
    if level > max_depth:
        raise XfsBmapError(
            "超深: fsb=%d bb_level=%d > max_depth=%d" % (fsb, level, max_depth)
        )
    maxrecs = (blocksize - hlen) // REC_SIZE
    if numrecs > maxrecs:
        raise XfsBmapError(
            "numrecs 非法: fsb=%d bb_numrecs=%d > maxrecs=%d (hlen=%d)"
            % (fsb, numrecs, maxrecs, hlen)
        )
    if numrecs == 0:
        return []

    out = []
    if level == 0:
        need = hlen + numrecs * REC_SIZE
        if need > len(buf):
            raise XfsBmapError(
                "numrecs*16 超出块尾: fsb=%d need=%d 块长=%d" % (fsb, need, len(buf))
            )
        for i in range(numrecs):
            out.append(_rec_dict(*decode_bmbt_rec(buf, hlen + i * REC_SIZE)))
        return out

    ptr_off = hlen + maxrecs * KEY_SIZE
    need = ptr_off + numrecs * PTR_SIZE
    if need > len(buf):
        raise XfsBmapError(
            "ptr 区超出块尾: fsb=%d need=%d (ptr_off=%d) 块长=%d"
            % (fsb, need, ptr_off, len(buf))
        )
    for i in range(numrecs):
        child = struct.unpack_from(">Q", buf, ptr_off + i * PTR_SIZE)[0]
        out.extend(_walk_block(reader, child, level - 1, blocksize, max_depth, visited))
    return out


# ------------------------------------------------------------- 内联根解析


def _parse_inline_fork(reader, fork, fork_len, blocksize, max_depth):
    if fork_len < ROOT_HDR_SIZE:
        raise XfsBmapError("inline root 太小: fork_len=%d < 4" % (fork_len,))
    level, numrecs = struct.unpack_from(">HH", fork, 0)
    maxrecs = (fork_len - ROOT_HDR_SIZE) // REC_SIZE
    if level > max_depth:
        raise XfsBmapError(
            "超深: inline root bb_level=%d > max_depth=%d" % (level, max_depth)
        )
    if numrecs > maxrecs:
        raise XfsBmapError(
            "numrecs 非法: inline root bb_numrecs=%d > maxrecs=%d (fork_len=%d)"
            % (numrecs, maxrecs, fork_len)
        )
    if numrecs == 0:
        return []

    if level == 0:
        need = ROOT_HDR_SIZE + numrecs * REC_SIZE
        if need > len(fork):
            raise XfsBmapError(
                "inline rec 区越界: need=%d 只有 %d 字节" % (need, len(fork))
            )
        return [
            _rec_dict(*decode_bmbt_rec(fork, ROOT_HDR_SIZE + i * REC_SIZE))
            for i in range(numrecs)
        ]

    ptr_off = ROOT_HDR_SIZE + maxrecs * KEY_SIZE
    need = ptr_off + numrecs * PTR_SIZE
    if need > len(fork):
        raise XfsBmapError(
            "inline ptr 区越界: need=%d (ptr_off=%d, maxrecs=%d) 只有 %d 字节"
            % (need, ptr_off, maxrecs, len(fork))
        )
    visited = set()
    out = []
    for i in range(numrecs):
        child = struct.unpack_from(">Q", fork, ptr_off + i * PTR_SIZE)[0]
        out.extend(
            _walk_block(reader, child, level - 1, blocksize, max_depth, visited)
        )
    return out


# ------------------------------------------------------------------ 对外入口


def read_bmap(reader, fork, blocksize, inode_size, core, forkoff=0, max_depth=8) -> list:
    """解析 bmap 格式 inode 的 data fork。

    :param reader: 提供 ``read(offset, size)``；若有整型 ``size`` 属性则做越界预检
    :param fork:   dinode 里 data fork 那段字节（从 core 起）
    :param blocksize: 文件系统块大小
    :param inode_size: inode 大小
    :param core:   inode 核心大小（version >= 3 为 176，< 3 为 100）
    :param forkoff: di_forkoff（8 字节单位）；0 表示没有属性 fork
    :param max_depth: 允许的最大 btree level
    :returns: ``[{'startblock','blockcount','startoff','state'}, ...]``，按 startoff 升序

    空 fork（``b""`` 或全零）返回 ``[]``，见模块 docstring。
    ``forkoff != 0`` 时 ``(forkoff<<3)-core`` 与 ``forkoff<<3`` 都作为 fork_len
    候选（前者优先），用"整棵子树 magic/level/numrecs 自洽"来挑；都失败抛
    :class:`XfsBmapError`。所有错误一律 :class:`XfsBmapError`。
    """
    if not isinstance(blocksize, int) or blocksize <= 0:
        raise XfsBmapError("blocksize 必须为正整数: %r" % (blocksize,))
    if not isinstance(core, int) or core < 0:
        raise XfsBmapError("core 必须为非负整数: %r" % (core,))
    if not isinstance(max_depth, int) or max_depth < 0:
        raise XfsBmapError("max_depth 必须为非负整数: %r" % (max_depth,))

    fork = b"" if fork is None else bytes(fork)
    inode_size = 0 if inode_size is None else int(inode_size)

    if not fork or not any(fork):
        # 明确约定：空 fork / 全零 fork == 无 extent
        return []

    cands = _fork_len_candidates(inode_size, core, forkoff, len(fork))
    if not cands:
        raise XfsBmapError(
            "无法确定 fork_len: forkoff=%r inode_size=%r core=%r fork=%d 字节，"
            "候选均不可用（(forkoff<<3)-core 与 forkoff<<3 都越界或过小）"
            % (forkoff, inode_size, core, len(fork))
        )

    errors = []
    for label, flen in cands:
        try:
            recs = _parse_inline_fork(reader, fork, flen, blocksize, max_depth)
        except XfsBmapError as exc:
            errors.append("%s fork_len=%d: %s" % (label, flen, exc))
            continue
        except (struct.error, ValueError) as exc:  # pragma: no cover - 防御
            errors.append("%s fork_len=%d: %s: %s" % (label, flen, type(exc).__name__, exc))
            continue
        recs.sort(key=lambda r: (r["startoff"], r["startblock"]))
        return recs

    raise XfsBmapError("bmap 解析失败（所有 fork_len 解释都不自洽）: " + " | ".join(errors))


# ============================================================ 自检（合成镜像）


class _MemImage(object):
    """极简块设备镜像：只暴露 read(offset,size) 与 size。"""

    def __init__(self, size, blocksize=4096):
        self.blocksize = blocksize
        self.size = size
        self._b = bytearray(size)

    def put_block(self, fsb, data):
        off = fsb * self.blocksize
        if off + len(data) > self.size:
            raise AssertionError("测试镜像太小: fsb=%d 需要 %d 字节" % (fsb, off + len(data)))
        self._b[off:off + len(data)] = data

    def read(self, off, size):
        if off >= self.size:
            return b""
        return bytes(self._b[off:off + size])


def _mk_block(magic, level, recs=None, keys=None, ptrs=None, blocksize=4096, numrecs=None):
    """构造一个外部 btree 块（magic/level/numrecs + recs 或 keys/ptrs）。"""
    hlen = MAGIC_HLEN[magic]
    maxrecs = (blocksize - hlen) // REC_SIZE
    buf = bytearray(blocksize)
    struct.pack_into(">I", buf, 0, magic)
    if numrecs is None:
        numrecs = len(recs) if recs is not None else len(ptrs or [])
    struct.pack_into(">HH", buf, 4, level, numrecs)
    if level == 0:
        for i, rec in enumerate(recs or []):
            buf[hlen + i * REC_SIZE:hlen + (i + 1) * REC_SIZE] = rec
    else:
        for i, key in enumerate(keys or []):
            struct.pack_into(">Q", buf, hlen + i * KEY_SIZE, key)
        for i, ptr in enumerate(ptrs or []):
            struct.pack_into(">Q", buf, hlen + maxrecs * KEY_SIZE + i * PTR_SIZE, ptr)
    return bytes(buf)


def _mk_fork(level, numrecs, records=None, ptrs=None, fork_len=336, keys=None):
    """构造 dinode data fork（内联根 xfs_bmdr_block）。"""
    fork = bytearray(fork_len)
    struct.pack_into(">HH", fork, 0, level, numrecs)
    maxrecs = (fork_len - ROOT_HDR_SIZE) // REC_SIZE
    if level == 0:
        for i, rec in enumerate(records or []):
            fork[ROOT_HDR_SIZE + i * REC_SIZE:ROOT_HDR_SIZE + (i + 1) * REC_SIZE] = rec
    else:
        for i, key in enumerate(keys or []):
            struct.pack_into(">Q", fork, ROOT_HDR_SIZE + i * KEY_SIZE, key)
        ptr_off = ROOT_HDR_SIZE + maxrecs * KEY_SIZE
        for i, ptr in enumerate(ptrs or []):
            struct.pack_into(">Q", fork, ptr_off + i * PTR_SIZE, ptr)
    return bytes(fork)


def _rec(sb, bc, so, st=0):
    return encode_bmbt_rec(sb, bc, so, st)


def _triples(recs):
    return [(r["startoff"], r["startblock"], r["blockcount"], r["state"]) for r in recs]


BS = 4096
INODE = 512
CORE = 176
FORK_LEN = INODE - CORE  # 336


def t01_bitfield():
    lo = (1 << 63) | (0x2A << 9) | 0x1
    hi = (0x5 << 21) | 0x7
    raw = struct.pack(">QQ", lo, hi)
    want = ((1 << 43) | 5, 7, 0x2A, 1)
    got = decode_bmbt_rec(raw)
    assert got == want, "hand-computed 期望 %r 实得 %r" % (want, got)
    # off 参数
    got2 = decode_bmbt_rec(b"HEAD" + raw + b"TAIL", 4)
    assert got2 == want, "off=4 期望 %r 实得 %r" % (want, got2)
    # 单独核每个位域的手算值
    sb, bc, so, st = got
    assert sb == (1 << 43) | 5, sb
    assert bc == 7, bc
    assert so == 0x2A, so
    assert st == 1, st


def t02_roundtrip():
    cases = [
        (0, 0, 0, 0),
        ((1 << 43) | 5, 7, 0x2A, 1),
        (STARTBLOCK_MAX, BLOCKCOUNT_MASK, STARTOFF_MASK, 1),  # 极值：startoff=2^54-1
        (12345, 1, STARTOFF_MASK, 0),
        (1, BLOCKCOUNT_MASK, 1, 1),
        (STARTBLOCK_MAX, 0, 0, 0),
    ]
    for sb, bc, so, st in cases:
        raw = encode_bmbt_rec(sb, bc, so, st)
        assert len(raw) == 16, len(raw)
        back = decode_bmbt_rec(raw)
        assert back == (sb, bc, so, st), "往返不符 %r -> %r" % ((sb, bc, so, st), back)
    # encode 也要拒绝越界
    for bad in [(1 << 52, 0, 0), (0, 1 << 21, 0), (0, 0, 1 << 54)]:
        try:
            encode_bmbt_rec(*bad)
        except XfsBmapError:
            pass
        else:
            raise AssertionError("encode 未拒绝越界输入 %r" % (bad,))


def t03_two_level_inline_root():
    img = _MemImage(8 * BS, BS)
    # 叶块乱序放：startoff 100 在前、0 在后，验证排序
    img.put_block(2, _mk_block(BMAP_MAGIC, 0, recs=[
        _rec(900, 4, 100), _rec(500, 2, 0),
    ]))
    fork = _mk_fork(1, 1, ptrs=[2])
    recs = read_bmap(img, fork, BS, INODE, CORE, forkoff=0)
    assert len(recs) == 2, recs
    assert _triples(recs) == [(0, 500, 2, 0), (100, 900, 4, 0)], _triples(recs)


def t04_three_levels_sorted():
    img = _MemImage(16 * BS, BS)
    img.put_block(3, _mk_block(BMAP_MAGIC, 1, keys=[0, 200], ptrs=[4, 5]))
    img.put_block(4, _mk_block(BMAP_MAGIC, 0, recs=[_rec(70, 3, 30), _rec(80, 1, 10)]))
    img.put_block(5, _mk_block(BMAP_MAGIC, 0, recs=[_rec(90, 2, 20), _rec(100, 5, 5)]))
    fork = _mk_fork(2, 1, keys=[0], ptrs=[3])
    recs = read_bmap(img, fork, BS, INODE, CORE)
    got = [r["startoff"] for r in recs]
    assert got == [5, 10, 20, 30], got
    assert _triples(recs) == [
        (5, 100, 5, 0), (10, 80, 1, 0), (20, 90, 2, 0), (30, 70, 3, 0),
    ], _triples(recs)


def t05_both_magics():
    results = {}
    for magic, fsb in ((BMAP_MAGIC, 2), (BMA3_MAGIC, 2)):
        img = _MemImage(8 * BS, BS)
        img.put_block(fsb, _mk_block(magic, 0, recs=[_rec(11, 2, 0), _rec(21, 1, 1)]))
        fork = _mk_fork(1, 1, ptrs=[fsb])
        results[magic] = _triples(read_bmap(img, fork, BS, INODE, CORE))
    assert results[BMAP_MAGIC] == results[BMA3_MAGIC] == [
        (0, 11, 2, 0), (1, 21, 1, 0),
    ], results
    # hlen 差异必须真的被用上：BMA3 的 maxrecs 更小
    assert (BS - MAGIC_HLEN[BMA3_MAGIC]) // 16 == (BS - 72) // 16
    assert MAGIC_HLEN[BMAP_MAGIC] == 24 and MAGIC_HLEN[BMA3_MAGIC] == 72


def t06_bad_magic():
    img = _MemImage(8 * BS, BS)
    bad = bytearray(BS)
    struct.pack_into(">I", bad, 0, 0xDEADBEEF)
    struct.pack_into(">HH", bad, 4, 0, 1)
    img.put_block(2, bytes(bad))
    fork = _mk_fork(1, 1, ptrs=[2])
    try:
        read_bmap(img, fork, BS, INODE, CORE)
    except XfsBmapError as exc:
        assert "magic" in str(exc), str(exc)
    else:
        raise AssertionError("坏 magic 未报错")


def t07_ptr_out_of_image():
    img = _MemImage(8 * BS, BS)  # 镜像只有 8 个块
    fork = _mk_fork(1, 1, ptrs=[9999])
    try:
        read_bmap(img, fork, BS, INODE, CORE)
    except XfsBmapError as exc:
        assert "越界" in str(exc) or "读不足" in str(exc), str(exc)
    else:
        raise AssertionError("ptr 指向镜像外未报错")

    # 无 size 属性的 reader 也必须靠"读不足"兜住
    class _NoSize(object):
        def __init__(self, data):
            self._d = data

        def read(self, off, size):
            return self._d[off:off + size]

    try:
        read_bmap(_NoSize(bytes(img._b)), fork, BS, INODE, CORE)
    except XfsBmapError as exc:
        assert "读不足" in str(exc), str(exc)
    else:
        raise AssertionError("无 size reader 的越界未报错")


def t08_cycle():
    img = _MemImage(16 * BS, BS)
    # 块 3 的 ptr 指回自己 -> 成环
    img.put_block(3, _mk_block(BMAP_MAGIC, 1, keys=[0], ptrs=[3]))
    fork = _mk_fork(2, 1, keys=[0], ptrs=[3])
    try:
        read_bmap(img, fork, BS, INODE, CORE)
    except XfsBmapError as exc:
        assert "成环" in str(exc) or "重复引用" in str(exc), str(exc)
    else:
        raise AssertionError("环未报错")

    # 两个不同父 ptr 指同一子块（非严格环，但同样重复引用）
    img2 = _MemImage(16 * BS, BS)
    img2.put_block(3, _mk_block(BMAP_MAGIC, 1, keys=[0, 100], ptrs=[5, 5]))
    img2.put_block(5, _mk_block(BMAP_MAGIC, 0, recs=[_rec(1, 1, 0)]))
    fork2 = _mk_fork(2, 1, keys=[0], ptrs=[3])
    try:
        read_bmap(img2, fork2, BS, INODE, CORE)
    except XfsBmapError as exc:
        assert "重复引用" in str(exc) or "成环" in str(exc), str(exc)
    else:
        raise AssertionError("重复 ptr 未报错")


def t09_numrecs_over_maxrecs():
    # 块级：BMAP 块 maxrecs = (4096-24)//16 = 254
    img = _MemImage(8 * BS, BS)
    bad = bytearray(BS)
    struct.pack_into(">I", bad, 0, BMAP_MAGIC)
    struct.pack_into(">HH", bad, 4, 0, 255)
    img.put_block(2, bytes(bad))
    fork = _mk_fork(1, 1, ptrs=[2])
    try:
        read_bmap(img, fork, BS, INODE, CORE)
    except XfsBmapError as exc:
        assert "numrecs" in str(exc), str(exc)
    else:
        raise AssertionError("块级 numrecs 越界未报错")

    # 内联根级：fork_len=336 -> maxrecs=20
    fork2 = _mk_fork(0, 21, records=[])
    try:
        read_bmap(img, fork2, BS, INODE, CORE)
    except XfsBmapError as exc:
        assert "numrecs" in str(exc), str(exc)
    else:
        raise AssertionError("内联根 numrecs 越界未报错")


def t10_too_deep():
    img = _MemImage(8 * BS, BS)
    # 默认 max_depth=8，root level=9
    fork = _mk_fork(9, 1, ptrs=[2])
    try:
        read_bmap(img, fork, BS, INODE, CORE)
    except XfsBmapError as exc:
        assert "超深" in str(exc), str(exc)
    else:
        raise AssertionError("超深未报错")

    # 显式 max_depth=1 时 level=2 的根同样被拦
    fork2 = _mk_fork(2, 1, ptrs=[2])
    try:
        read_bmap(img, fork2, BS, INODE, CORE, max_depth=1)
    except XfsBmapError as exc:
        assert "超深" in str(exc), str(exc)
    else:
        raise AssertionError("max_depth=1 下 level=2 未报错")
    # 而 max_depth=3 时同一结构不因深度被拦（会因 magic 报错，说明深度已放行）
    try:
        read_bmap(img, fork2, BS, INODE, CORE, max_depth=3)
    except XfsBmapError as exc:
        assert "超深" not in str(exc), str(exc)


def t11_empty_fork():
    img = _MemImage(8 * BS, BS)
    assert read_bmap(img, b"", BS, INODE, CORE) == [], "空 bytes 应返回 []"
    assert read_bmap(img, b"\x00" * FORK_LEN, BS, INODE, CORE) == [], "全零 fork 应返回 []"
    assert read_bmap(img, None, BS, INODE, CORE) == [], "None 应返回 []"
    # 全零 + forkoff 非 0 也一样
    assert read_bmap(img, b"\x00" * FORK_LEN, BS, INODE, CORE, forkoff=64) == []
    # 但 level=0 且 numrecs=0 之外的空结构（level>0,numrecs>0 但 fork 太短）要报错
    try:
        read_bmap(img, b"\x00\x02\x00\x01", BS, INODE, CORE)
    except XfsBmapError:
        pass
    else:
        raise AssertionError("tiny fork 未报错")


def t12_fork_len_dual_interpretation():
    """forkoff!=0 时两个 fork_len 候选都会被尝试（A 优先，A 失败回退 B）。"""
    # inode_size=512, core=176, forkoff=64:
    #   A = 64*8 - 176 = 336 ; B = 64*8 = 512
    img = _MemImage(8 * BS, BS)
    img.put_block(2, _mk_block(BMAP_MAGIC, 0, recs=[_rec(11, 2, 0), _rec(21, 1, 1)]))

    # 按 B 语义放置内联根：fork_len=512 -> maxrecs=31 -> ptr_off=4+248=252
    fork = bytearray(512)
    struct.pack_into(">HH", fork, 0, 1, 1)
    fork[4:12] = struct.pack(">Q", 0)                     # key
    struct.pack_into(">Q", fork, ROOT_HDR_SIZE + 31 * KEY_SIZE, 2)  # ptr -> fsb 2
    recs = read_bmap(img, bytes(fork), BS, INODE, CORE, forkoff=64)
    assert _triples(recs) == [(0, 11, 2, 0), (1, 21, 1, 0)], _triples(recs)

    # 按 A 语义放置（maxrecs=(336-4)//16=20 -> ptr_off=4+160=164）：A 优先命中
    forkA = bytearray(512)
    struct.pack_into(">HH", forkA, 0, 1, 1)
    struct.pack_into(">Q", forkA, ROOT_HDR_SIZE + 20 * KEY_SIZE, 2)
    recsA = read_bmap(img, bytes(forkA), BS, INODE, CORE, forkoff=64)
    assert _triples(recsA) == [(0, 11, 2, 0), (1, 21, 1, 0)], _triples(recsA)

    # 全零 fork 仍然按约定返回 []
    assert read_bmap(img, b"\x00" * 512, BS, INODE, CORE, forkoff=64) == []
    # 结构确实坏掉（level=1 但 ptr 指向无 magic 的块）时 A、B 都失败 -> 抛错
    broken = bytearray(512)
    struct.pack_into(">HH", broken, 0, 1, 1)
    struct.pack_into(">Q", broken, ROOT_HDR_SIZE + 31 * KEY_SIZE, 7)
    img2 = _MemImage(8 * BS, BS)  # 块 7 全零
    try:
        read_bmap(img2, bytes(broken), BS, INODE, CORE, forkoff=64)
    except XfsBmapError as exc:
        assert "所有 fork_len" in str(exc) or "magic" in str(exc), str(exc)
    else:
        raise AssertionError("坏结构未报错")


def _self_test():
    tests = [
        ("01 decode_bmbt_rec 位域手算对拍", t01_bitfield),
        ("02 encode/decode 互逆（含 startoff=2^54-1 极值、state 0/1）", t02_roundtrip),
        ("03 内联根 level=1 -> 外部叶块 2 条记录且排序", t03_two_level_inline_root),
        ("04 三级 level=2 -> level=1(2 ptr) -> 2 叶块合并排序", t04_three_levels_sorted),
        ("05 BMAP(hlen24) 与 BMA3(hlen72) 两种块头", t05_both_magics),
        ("06 magic 坏 -> XfsBmapError", t06_bad_magic),
        ("07 ptr 指向镜像外 -> XfsBmapError", t07_ptr_out_of_image),
        ("08 成环 -> XfsBmapError 且不死循环", t08_cycle),
        ("09 bb_numrecs > maxrecs -> XfsBmapError", t09_numrecs_over_maxrecs),
        ("10 level > max_depth -> XfsBmapError", t10_too_deep),
        ("11 空 fork -> 明确返回 []", t11_empty_fork),
        ("12 fork_len 双解释候选挑选（A 优先，回退 B）", t12_fork_len_dual_interpretation),
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - 自检要吞全部异常并报告
            failed += 1
            print("FAIL %s: %s: %s" % (name, type(exc).__name__, exc))
        else:
            print("ok   %s" % (name,))
    total = len(tests)
    if failed:
        print("\n%d/%d 项失败" % (failed, total))
        return 1
    print("\n%d/%d 项全部通过" % (total, total))
    return 0


if __name__ == "__main__":
    sys.exit(_self_test())
