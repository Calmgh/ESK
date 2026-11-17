#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mkit.squashfs_v123 -- SquashFS v1 / v2 / v3 read-only parser.

Scope
-----
Read-only parsing of SquashFS *major* versions 1, 2 and 3 (``s_minor <= 9``).
Version 4 is explicitly *rejected* here so that the caller can dispatch to
``mkit.squashfs``; :func:`probe` therefore returns ``False`` for v4 images.

Layout contract (verified against squashfs-tools 3.2 ``squashfs_fs.h``)
----------------------------------------------------------------------
Everything is **big endian**.  Bit fields are **MSB-first** (standard network
bit order), addressed by absolute *bit* offsets from the start of the fixed
inode header.

* superblock: fixed 119 bytes, see ``_SB_LAYOUT`` below.
* 64-bit fields are preferred when ``0 < value <= image size``; otherwise the
  matching 32-bit ``*_2`` field is used.  ``block_size`` prefers the 32-bit
  field at @51 (when it is a power of two consistent with ``block_log``) and
  falls back to the 16-bit ``block_size_1`` at @32.  The chosen source of every
  field is reported by :meth:`SquashfsV123.info` via ``sb_field_source``.
* v3 inode base: 12 bytes (type:4, mode:12, uid:8, guid:8, mtime:32,
  inode_number:32).
* v2 inode base: 4 bytes (type:4, mode:12, uid:8, guid:8) -- no mtime, no
  inode_number.
* v1 inode base: 3 bytes (type:4, mode:12, uid:4, guid:4) -- uid/guid are only
  four bits wide.
* metadata blocks: ``u16`` header, bit15 set = stored uncompressed, low 15 bits
  = payload length; when ``flags & 4`` (SQUASHFS_CHECK_DATA) one extra check
  byte follows the header.  Compressed payloads are zlib streams.  Decompressed
  payload is capped at 8192 bytes.
* file data blocks do **not** carry a metadata header: each length comes from
  the inode's ``u16 block_list`` (bit15 = stored uncompressed) and the blocks
  are laid out back to back; with CHECK_DATA one extra byte follows each block.

Inferences / notes (explicitly flagged)
---------------------------------------
1. **v1 directory data** has no surviving header definition in later headers;
   this module parses v1 directory data with the *v2* structure
   (``count:8 | start_block:24`` + ``offset:13 | type:3 | size:8``).  This is an
   **inference**, exercised by the self-check against synthetic v1 images.
2. **v1 ipc inodes** carry ``type:4 | offset:4`` after the base; the values are
   not exposed as separate attributes (``rdev``/``nlink`` stay 0).
3. v1 has no fragment support, therefore ``fragment`` is reported as
   ``0xFFFFFFFF`` and the tail block is a normal (possibly short) data block.
4. Directory entry ``inode_number`` reporting is ``header.inode_number +
   sign_extend(entry.inode_number, 16)`` for v3 only; v2/v1 report the absolute
   inode number found inside the parsed inode (v2 has none at all -- 0).
5. ``describe()`` intentionally swallows every exception.

Public API
----------
``SquashfsV123Error``, ``SquashfsV123``, ``Sqv123Entry``, ``probe``,
``open_fs``, ``describe``.
"""

import os
import re
import struct
import sys
import tempfile
import zlib

MAGIC = 0x73717368
SB_SIZE = 119
METADATA_MAX = 8192
CHECK_FLAG = 0x04
FRAG_NONE = 0xFFFFFFFF

TYPE_NAMES = {
    1: "dir",
    2: "file",
    3: "symlink",
    4: "blkdev",
    5: "chrdev",
    6: "fifo",
    7: "socket",
    8: "ldir",
    9: "lreg",
}

# fixed part sizes (bytes) per (major, inode_type)
_FIXED = {
    3: {1: 28, 8: 31, 2: 32, 9: 40, 3: 18, 4: 18, 5: 18, 6: 16, 7: 16},
    2: {1: 15, 2: 24, 3: 6, 4: 6, 5: 6, 6: 4, 7: 4},
    1: {1: 14, 2: 15, 3: 5, 4: 5, 5: 5, 6: 4, 7: 4},
}
_BASE_SIZE = {3: 12, 2: 4, 1: 3}


class SquashfsV123Error(ValueError):
    """Raised for malformed / truncated / unsupported SquashFS v1-v3 images."""


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------
def _be(buf, off, n):
    """Big-endian unsigned integer from ``buf[off:off+n]``."""
    return int.from_bytes(buf[off:off + n], "big")


def _be16(b):
    return struct.unpack(">H", b[:2])[0]


def _be64(b):
    return struct.unpack(">Q", b[:8])[0]


def _bits(buf, bitpos, nbits):
    """Read ``nbits`` bits starting at absolute ``bitpos``, MSB-first."""
    v = 0
    for i in range(nbits):
        p = bitpos + i
        v = (v << 1) | ((buf[p >> 3] >> (7 - (p & 7))) & 1)
    return v


def _bits_signed(buf, bitpos, nbits):
    v = _bits(buf, bitpos, nbits)
    if v >= (1 << (nbits - 1)):
        v -= 1 << nbits
    return v


_ALGO_MAGIC = (
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x02\x21\x4c\x18", "lz4-legacy"),
    (b"BZh", "bzip2"),
    (b"\x5d\x00\x00", "lzma"),
    (b"\x89LZO\x00", "lzo"),
)


def _detect_algo(raw):
    for magic, name in _ALGO_MAGIC:
        if raw.startswith(magic):
            return name
    return None


# ---------------------------------------------------------------------------
# byte source abstraction
# ---------------------------------------------------------------------------
class _Source(object):
    """Uniform ``read_at(off, n)`` / ``size`` access over bytes, paths, files."""

    __slots__ = ("_buf", "_fh", "_size", "_own")

    def __init__(self, sub):
        self._buf = None
        self._fh = None
        self._size = None
        self._own = False
        if isinstance(sub, (bytes, bytearray, memoryview)):
            self._buf = bytes(sub)
            self._size = len(self._buf)
            return
        if isinstance(sub, str) or hasattr(sub, "__fspath__"):
            self._fh = open(os.fspath(sub), "rb")
            self._own = True
            self._size = os.fstat(self._fh.fileno()).st_size
            return
        if hasattr(sub, "read") and hasattr(sub, "seek"):
            self._fh = sub
            try:
                cur = sub.tell()
                sub.seek(0, os.SEEK_END)
                self._size = sub.tell()
                sub.seek(cur)
            except Exception:
                self._size = None
            return
        raise TypeError("unsupported sub type: %r" % (type(sub),))

    @property
    def size(self):
        return self._size

    def read_at(self, off, n):
        if n <= 0:
            return b""
        if off < 0:
            raise SquashfsV123Error("negative read offset %d" % off)
        if self._buf is not None:
            if off + n > len(self._buf):
                raise SquashfsV123Error(
                    "read past end of image: off=%d n=%d size=%d"
                    % (off, n, len(self._buf))
                )
            return self._buf[off:off + n]
        if self._size is not None and off + n > self._size:
            raise SquashfsV123Error(
                "read past end of image: off=%d n=%d size=%d"
                % (off, n, self._size)
            )
        if self._fh is None:
            raise SquashfsV123Error("source is closed")
        self._fh.seek(off)
        out = bytearray()
        while len(out) < n:
            chunk = self._fh.read(n - len(out))
            if not chunk:
                break
            out += chunk
        if len(out) < n:
            raise SquashfsV123Error(
                "truncated image: wanted %d bytes at %d, got %d"
                % (n, off, len(out))
            )
        return bytes(out)

    def close(self):
        if self._own and self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
        self._fh = None


# ---------------------------------------------------------------------------
# entries
# ---------------------------------------------------------------------------
class Sqv123Entry(object):
    """A directory entry / inode view."""

    __slots__ = (
        "name", "name_bytes", "inode", "inode_number", "type", "type_name",
        "inode_type", "is_dir", "is_file", "is_symlink", "size", "mode",
        "uid", "gid", "mtime", "nlink", "target", "rdev", "parent",
        "start_block", "fragment", "offset", "block_list", "fs", "raw",
    )

    def __init__(self):
        self.name = ""
        self.name_bytes = b""
        self.inode = (0, 0)
        self.inode_number = 0
        self.type = 0
        self.type_name = "?"
        self.inode_type = 0
        self.is_dir = False
        self.is_file = False
        self.is_symlink = False
        self.size = 0
        self.mode = 0
        self.uid = 0
        self.gid = 0
        self.mtime = 0
        self.nlink = 0
        self.target = b""
        self.rdev = 0
        self.parent = None
        self.start_block = 0
        self.fragment = FRAG_NONE
        self.offset = 0
        self.block_list = ()
        self.fs = None
        self.raw = None

    def __repr__(self):
        return "<Sqv123Entry %s %r inode=%d size=%d>" % (
            self.type_name, self.name, self.inode_number, self.size)

    def describe(self):
        return {
            "name": self.name,
            "inode": self.inode,
            "inode_number": self.inode_number,
            "type": self.type,
            "type_name": self.type_name,
            "size": self.size,
            "mode": oct(self.mode),
            "uid": self.uid,
            "gid": self.gid,
            "mtime": self.mtime,
            "nlink": self.nlink,
        }


# ---------------------------------------------------------------------------
# metadata stream (crosses metadata-block boundaries)
# ---------------------------------------------------------------------------
class _MetaStream(object):
    """Sequential reader over a metadata table starting at (block, intra)."""

    __slots__ = ("fs", "table_start", "blk", "intra", "buf", "next")

    def __init__(self, fs, table_start, blk=0, intra=0):
        self.fs = fs
        self.table_start = table_start
        self.blk = blk
        self.intra = intra
        self.buf = b""
        self.next = blk

    def _advance(self):
        guard = 0
        while True:
            if self.buf and self.intra < len(self.buf):
                return
            if self.buf:
                self.intra -= len(self.buf)
                self.blk = self.next
                self.buf = b""
            data, total = self.fs._read_meta_block(self.table_start + self.blk)
            if total <= 0:
                raise SquashfsV123Error("zero-length metadata block")
            self.buf = data
            self.next = self.blk + total
            guard += 1
            if guard > 1000000:
                raise SquashfsV123Error("metadata stream runaway")
            if not data:
                raise SquashfsV123Error("empty metadata block payload")

    def read(self, n):
        out = bytearray()
        while len(out) < n:
            self._advance()
            take = min(n - len(out), len(self.buf) - self.intra)
            if take <= 0:
                raise SquashfsV123Error("metadata stream stalled")
            out += self.buf[self.intra:self.intra + take]
            self.intra += take
        return bytes(out)


# ---------------------------------------------------------------------------
# main object
# ---------------------------------------------------------------------------
class SquashfsV123(object):
    """Read-only SquashFS v1/v2/v3 image."""

    def __init__(self, sub, comp="gzip"):
        name = (comp or "gzip").strip().lower()
        if name in ("zlib", "deflate", "gzip", "gz"):
            name = "gzip"
        if name != "gzip":
            raise NotImplementedError(
                "compression %r is not supported by mkit.squashfs_v123 "
                "(only 'gzip' / zlib deflate); detected request for %r"
                % (comp, comp))
        self.compress = name
        self.src = _Source(sub)
        self.size = self.src.size
        self.check_data = False
        self._sb_src = {}
        self._inode_cache = {}
        self._frag_cache = {}
        self._frag_entries = None
        self._root = None

        if self.size is not None and self.size < SB_SIZE:
            raise SquashfsV123Error(
                "image too short for a SuperFS superblock: %d < %d bytes"
                % (self.size, SB_SIZE))
        sb = self.src.read_at(0, SB_SIZE)
        self.superblock = sb

        magic = _be(sb, 0, 4)
        if magic != MAGIC:
            raise SquashfsV123Error(
                "bad magic 0x%08x (expected 0x%08x)" % (magic, MAGIC))

        self.major = _be(sb, 28, 2)
        self.minor = _be(sb, 30, 2)
        if self.major == 4:
            raise SquashfsV123Error(
                "this is SquashFS v4 (s_major=4, s_minor=%d); "
                "use mkit.squashfs for v4 images" % self.minor)
        if self.major not in (1, 2, 3):
            raise SquashfsV123Error(
                "unsupported SquashFS major version %d (only 1/2/3)"
                % self.major)
        if self.minor > 9:
            raise SquashfsV123Error(
                "unsupported SquashFS minor version %d.%d" % (self.major, self.minor))

        self.flags = sb[36]
        self.check_data = bool(self.flags & CHECK_FLAG)
        self.no_uids = sb[37]
        self.no_guids = sb[38]
        self.mkfs_time = _be(sb, 39, 4)
        self.inode_count = _be(sb, 4, 4)

        # ---- block size selection -------------------------------------
        bs32 = _be(sb, 51, 4)
        bs16 = _be(sb, 32, 2)
        self.block_log = _be(sb, 34, 2)
        chosen = None
        if bs32 and (bs32 & (bs32 - 1)) == 0 and bs32 >= 512:
            if not self.block_log or (1 << self.block_log) == bs32:
                chosen = (bs32, "u32@51(block_size)")
        if chosen is None and bs16 and (bs16 & (bs16 - 1)) == 0:
            chosen = (bs16, "u16@32(block_size_1)")
        if chosen is None and bs32:
            chosen = (bs32, "u32@51(block_size,inconsistent)")
        if chosen is None:
            raise SquashfsV123Error("no usable block size in superblock")
        self.block_size, self._sb_src["block_size"] = chosen

        # ---- 64/32-bit address fields ---------------------------------
        self.bytes_used = self._pick64(
            _be(sb, 63, 8), _be(sb, 8, 4), "bytes_used", "@63", "@8")
        if self.bytes_used and self.size is not None and self.bytes_used > self.size:
            raise SquashfsV123Error(
                "truncated image: bytes_used=%d > size=%d"
                % (self.bytes_used, self.size))
        self.uid_start = self._pick64(
            _be(sb, 71, 8), _be(sb, 12, 4), "uid_start", "@71", "@12")
        self.gid_start = self._pick64(
            _be(sb, 79, 8), _be(sb, 16, 4), "guid_start", "@79", "@16")
        self.inode_table_start = self._pick64(
            _be(sb, 87, 8), _be(sb, 20, 4), "inode_table_start", "@87", "@20")
        self.directory_table_start = self._pick64(
            _be(sb, 95, 8), _be(sb, 24, 4), "directory_table_start", "@95", "@24")
        self.fragments = _be(sb, 55, 4)
        self.fragment_table_start = self._pick64(
            _be(sb, 103, 8), _be(sb, 59, 4), "fragment_table_start", "@103", "@59")
        self.lookup_table_start = self._pick64(
            _be(sb, 111, 8), 0, "lookup_table_start", "@111", "none")

        self.root_inode = _be(sb, 43, 8)
        self.root_blk = self.root_inode >> 16
        self.root_offset = self.root_inode & 0xFFFF

        if self.inode_table_start <= 0:
            raise SquashfsV123Error(
                "invalid inode_table_start=%d" % self.inode_table_start)
        if self.directory_table_start <= 0:
            raise SquashfsV123Error(
                "invalid directory_table_start=%d" % self.directory_table_start)

    # -- superblock helpers -------------------------------------------------
    def _pick64(self, v64, v32, field, o64, o32):
        if v64 and (self.size is None or v64 <= self.size):
            self._sb_src[field] = "u64%s" % o64
            return v64
        self._sb_src[field] = "u32%s(fallback)" % o32 if o32 != "none" else "unset"
        return v32

    def info(self):
        return {
            "version": "%d.%d" % (self.major, self.minor),
            "major": self.major,
            "minor": self.minor,
            "block_size": self.block_size,
            "block_log": self.block_log,
            "inode_count": self.inode_count,
            "bytes_used": self.bytes_used,
            "compress": self.compress,
            "flags": self.flags,
            "check_data": self.check_data,
            "fragments": self.fragments,
            "root_inode": self.root_inode,
            "root_inode_pos": (self.root_blk, self.root_offset),
            "inode_table_start": self.inode_table_start,
            "directory_table_start": self.directory_table_start,
            "fragment_table_start": self.fragment_table_start,
            "lookup_table_start": self.lookup_table_start,
            "uid_start": self.uid_start,
            "gid_start": self.gid_start,
            "no_uids": self.no_uids,
            "no_guids": self.no_guids,
            "mkfs_time": self.mkfs_time,
            "sb_field_source": dict(self._sb_src),
            "image_size": self.size,
        }

    # -- decompression ------------------------------------------------------
    def _inflate(self, raw, limit, where):
        algo = _detect_algo(raw)
        if algo:
            raise NotImplementedError(
                "%s: block is not zlib-deflate, detected compression %r -- "
                "compressor not available in mkit.squashfs_v123" % (where, algo))
        try:
            d = zlib.decompressobj()
            out = d.decompress(raw, limit + 1)
        except zlib.error as e:
            raise SquashfsV123Error("%s: zlib inflate failed: %s" % (where, e))
        if len(out) > limit:
            raise SquashfsV123Error(
                "%s: inflated block too large (%d > %d)" % (where, len(out), limit))
        return out

    def _read_meta_block(self, abs_off):
        """Return (payload, total_bytes_consumed_at_abs_off)."""
        if self.size is not None and abs_off + 2 > self.size:
            raise SquashfsV123Error(
                "metadata block header past end at 0x%x" % abs_off)
        hdr = self.src.read_at(abs_off, 2)
        v = _be16(hdr)
        length = v & 0x7FFF
        uncompressed = bool(v & 0x8000)
        pos = abs_off + 2
        extra = 1 if self.check_data else 0
        if extra:
            if self.size is not None and pos >= self.size:
                raise SquashfsV123Error("check byte past end at 0x%x" % pos)
            pos += 1
        total = 2 + extra + length
        if length == 0:
            raise SquashfsV123Error(
                "zero-length metadata block at 0x%x" % abs_off)
        raw = self.src.read_at(pos, length)
        if uncompressed:
            data = raw
        else:
            data = self._inflate(raw, METADATA_MAX,
                                 "metadata block at 0x%x" % abs_off)
        return data, total

    # -- inode parsing ------------------------------------------------------
    def _read_meta_at(self, table_start, blk, off, length):
        return _MetaStream(self, table_start, blk, off).read(length)

    def _inode_fields(self, blk, off):
        key = (blk, off)
        hit = self._inode_cache.get(key)
        if hit is not None:
            return hit
        v = self.major
        ms = _MetaStream(self, self.inode_table_start, blk, off)
        base = _BASE_SIZE[v]
        head = ms.read(base)
        typ = _bits(head, 0, 4)
        mode = _bits(head, 4, 12)
        if v == 3:
            uid = _bits(head, 16, 8)
            gid = _bits(head, 24, 8)
            mtime = _be(head, 4, 4)
            inum = _be(head, 8, 4)
        elif v == 2:
            uid = _bits(head, 16, 8)
            gid = _bits(head, 24, 8)
            mtime = 0
            inum = 0
        else:
            uid = _bits(head, 16, 4)
            gid = _bits(head, 20, 4)
            mtime = 0
            inum = 0

        sizes = _FIXED[v]
        if typ not in sizes:
            raise SquashfsV123Error(
                "unknown inode type %d (major %d) at (%d,0x%x)" % (typ, v, blk, off))
        total = sizes[typ]
        rest = ms.read(total - base)
        ib = head + rest

        f = {
            "inode_type": typ,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "mtime": mtime,
            "inode_number": inum,
            "nlink": 0,
            "size": 0,
            "start_block": 0,
            "fragment": FRAG_NONE,
            "offset": 0,
            "parent": 0,
            "rdev": 0,
            "block_list": (),
            "target": b"",
            "i_count": 0,
        }

        if v == 3:
            if typ == 1:  # dir
                f["nlink"] = _be(ib, 12, 4)
                f["size"] = _bits(ib, 128, 19)
                f["offset"] = _bits(ib, 147, 13)
                f["start_block"] = _be(ib, 20, 4)
                f["parent"] = _be(ib, 24, 4)
            elif typ == 8:  # ldir
                f["nlink"] = _be(ib, 12, 4)
                f["size"] = _bits(ib, 128, 27)
                f["offset"] = _bits(ib, 155, 13)
                f["start_block"] = _be(ib, 21, 4)
                f["i_count"] = _bits(ib, 200, 16)
                f["parent"] = _be(ib, 27, 4)
            elif typ == 2:  # reg
                f["start_block"] = _be(ib, 12, 8)
                f["fragment"] = _be(ib, 20, 4)
                f["offset"] = _be(ib, 24, 4)
                f["size"] = _be(ib, 28, 4)
            elif typ == 9:  # lreg
                f["nlink"] = _be(ib, 12, 4)
                f["start_block"] = _be(ib, 16, 8)
                f["fragment"] = _be(ib, 24, 4)
                f["offset"] = _be(ib, 28, 4)
                f["size"] = _be(ib, 32, 8)
            elif typ == 3:  # symlink
                f["nlink"] = _be(ib, 12, 4)
                f["size"] = _bits(ib, 128, 16)
            elif typ in (4, 5):  # blkdev / chrdev
                f["nlink"] = _be(ib, 12, 4)
                f["rdev"] = _bits(ib, 128, 16)
            else:  # ipc
                f["nlink"] = _be(ib, 12, 4)
        elif v == 2:
            if typ == 1:  # dir
                f["size"] = _bits(ib, 32, 19)
                f["offset"] = _bits(ib, 51, 13)
                f["mtime"] = _be(ib, 8, 4)
                f["start_block"] = _be(ib, 12, 3)
            elif typ == 2:  # reg
                f["mtime"] = _be(ib, 4, 4)
                f["start_block"] = _be(ib, 8, 4)
                f["fragment"] = _be(ib, 12, 4)
                f["offset"] = _be(ib, 16, 4)
                f["size"] = _be(ib, 20, 4)
            elif typ == 3:  # symlink
                f["size"] = _bits(ib, 32, 16)
            elif typ in (4, 5):
                f["rdev"] = _bits(ib, 32, 16)
        else:  # v1
            if typ == 1:  # dir
                f["size"] = _bits(ib, 24, 19)
                f["offset"] = _bits(ib, 43, 13)
                f["mtime"] = _be(ib, 7, 4)
                f["start_block"] = _be(ib, 11, 3)
            elif typ == 2:  # reg -- no fragment
                f["mtime"] = _be(ib, 3, 4)
                f["start_block"] = _be(ib, 7, 4)
                f["size"] = _be(ib, 11, 4)
                f["fragment"] = FRAG_NONE
            elif typ == 3:
                f["size"] = _bits(ib, 24, 16)
            elif typ in (4, 5):
                f["rdev"] = _bits(ib, 24, 16)
            elif typ == 6:  # ipc: type:4 | offset:4 -- recorded, not exposed
                f["ipc_type"] = _bits(ib, 24, 4)
                f["ipc_offset"] = _bits(ib, 28, 4)

        if typ == 3:
            f["target"] = ms.read(f["size"]) if f["size"] else b""

        if typ in (2, 9):
            bs = self.block_size
            full = f["size"]
            has_frag = (v != 1) and f["fragment"] != FRAG_NONE
            if has_frag:
                nblocks = full // bs
            else:
                nblocks = (full + bs - 1) // bs
            if nblocks:
                raw = ms.read(2 * nblocks)
                f["block_list"] = tuple(
                    _be16(raw[2 * i:2 * i + 2]) for i in range(nblocks))
            f["nblocks"] = nblocks

        f["pos"] = key
        self._inode_cache[key] = f
        return f

    def _make_entry(self, f, name=b"", inode_number=None, parent=None):
        typ = f["inode_type"]
        norm = {8: 1, 9: 2}.get(typ, typ)
        e = Sqv123Entry()
        e.name_bytes = name
        e.name = name.decode("utf-8", "surrogateescape") if name else ""
        e.inode = f["pos"]
        e.inode_type = typ
        e.type = norm
        e.type_name = TYPE_NAMES.get(typ, "?")
        e.is_dir = norm == 1
        e.is_file = norm == 2
        e.is_symlink = norm == 3
        e.mode = f["mode"]
        e.uid = f["uid"]
        e.gid = f["gid"]
        e.mtime = f["mtime"]
        e.nlink = f["nlink"]
        e.start_block = f["start_block"]
        e.fragment = f["fragment"]
        e.offset = f["offset"]
        e.block_list = f["block_list"]
        e.target = f["target"]
        e.rdev = f["rdev"]
        e.parent = parent
        e.fs = self
        e.raw = f
        if norm == 1:
            e.size = f["size"]
        elif norm == 2:
            e.size = f["size"]
        elif norm == 3:
            e.size = len(f["target"])
        else:
            e.size = 0
        if inode_number is None:
            inode_number = f["inode_number"]
        e.inode_number = inode_number
        return e

    # -- directories --------------------------------------------------------
    def _parse_dir(self, buf, parent):
        v = self.major
        out = []
        i = 0
        n = len(buf)
        hdr = 9 if v == 3 else 4
        ent = 5 if v == 3 else 3
        while i + hdr <= n:
            count = buf[i]
            if count == 0:
                i += hdr
                continue
            if v == 3:
                sblk = _be(buf, i + 1, 4)
                inum_base = _be(buf, i + 5, 4)
            else:
                sblk = _be(buf, i + 1, 3)
                inum_base = 0
            i += hdr
            if sblk > (1 << 24):
                raise SquashfsV123Error("implausible dir header start_block")
            for _ in range(count):
                if i + ent > n:
                    break
                boff = _bits(buf, i * 8, 13)
                nsz = _bits(buf, i * 8 + 16, 8)
                delta = _bits_signed(buf, i * 8 + 24, 16) if v == 3 else 0
                i += ent
                nlen = nsz + 1
                if i + nlen > n:
                    i = n
                    break
                nm = buf[i:i + nlen]
                i += nlen
                pos = (sblk << 16) | boff
                f = self._inode_fields(pos >> 16, pos & 0xFFFF)
                inum = inum_base + delta if v == 3 else f["inode_number"]
                out.append(self._make_entry(f, nm, inum, parent))
            if i >= n:
                break
        return out

    def listdir(self, inode=None):
        e = self._as_entry(inode)
        if not e.is_dir:
            raise SquashfsV123Error(
                "%r is not a directory (type=%s)" % (e.name, e.type_name))
        buf = self._read_meta_at(
            self.directory_table_start, e.start_block, e.offset, e.size)
        return self._parse_dir(buf, e)

    # -- entry plumbing -----------------------------------------------------
    def _as_entry(self, inode):
        if inode is None:
            return self.root
        if isinstance(inode, Sqv123Entry):
            return inode
        if isinstance(inode, (tuple, list)) and len(inode) == 2:
            f = self._inode_fields(int(inode[0]), int(inode[1]))
            return self._make_entry(f, b"")
        raise TypeError("expected entry/tuple/None, got %r" % (type(inode),))

    @property
    def root(self):
        if self._root is None:
            f = self._inode_fields(self.root_blk, self.root_offset)
            self._root = self._make_entry(f, b"", self.root_inode & 0xFFFFFFFF)
        return self._root

    def walk(self, inode=None):
        start = self._as_entry(inode)
        base = "" if start is self.root else ("/" + start.name)
        stack = [(base + "/" + c.name, c) for c in self.listdir(start)] \
            if start.is_dir else []
        stack.reverse()
        seen = set()
        while stack:
            path, ent = stack.pop()
            yield path, ent
            if ent.is_dir:
                key = (ent.inode, path)
                if key in seen:
                    continue
                seen.add(key)
                kids = [("%s/%s" % (path, c.name), c) for c in self.listdir(ent)]
                kids.reverse()
                stack.extend(kids)

    def lookup_path(self, path):
        if isinstance(path, bytes):
            path = path.decode("utf-8", "surrogateescape")
        parts = [p for p in str(path).split("/") if p and p != "."]
        cur = self.root
        if not parts:
            return cur
        for part in parts:
            if not cur.is_dir:
                return None
            hit = None
            for c in self.listdir(cur):
                if c.name == part:
                    hit = c
                    break
            if hit is None:
                return None
            cur = hit
        return cur

    def find(self, pattern):
        try:
            rx = re.compile(pattern)
        except re.error:
            rx = None
        out = []
        for path, ent in self.walk():
            if rx is not None:
                if rx.search(path):
                    out.append((path, ent))
            elif pattern in path:
                out.append((path, ent))
        return out

    def readlink(self, entry):
        e = self._as_entry(entry)
        if not e.is_symlink:
            raise SquashfsV123Error(
                "%r is not a symlink (type=%s)" % (e.name, e.type_name))
        return bytes(e.target)

    # -- fragments ----------------------------------------------------------
    def _load_fragment_table(self):
        if self._frag_entries is not None:
            return self._frag_entries
        v = self.major
        esize = 16 if v == 3 else 8
        n = self.fragments or 0
        ents = []
        if n and self.fragment_table_start:
            nptr = (n * esize + METADATA_MAX - 1) // METADATA_MAX
            for p in range(nptr):
                ptr = self.src.read_at(self.fragment_table_start + 8 * p, 8)
                block_off = _be64(ptr)
                if block_off <= 0:
                    raise SquashfsV123Error(
                        "null fragment table pointer at index %d" % p)
                data, _total = self._read_meta_block(block_off)
                for i in range(0, len(data) - esize + 1, esize):
                    chunk = data[i:i + esize]
                    if esize == 16:
                        sblk, sz, pending = struct.unpack(">QII", chunk)
                    else:
                        sblk, sz = struct.unpack(">II", chunk)
                        pending = 0
                    ents.append((sblk, sz, pending))
                    if len(ents) >= n:
                        break
                if len(ents) >= n:
                    break
        self._frag_entries = ents
        return ents

    def _fragment_block(self, idx):
        hit = self._frag_cache.get(idx)
        if hit is not None:
            return hit
        ents = self._load_fragment_table()
        if idx >= len(ents):
            raise SquashfsV123Error(
                "fragment index %d out of range (table has %d)" % (idx, len(ents)))
        sblk, sz, _pending = ents[idx]
        length = sz & 0xFFFFFF
        uncompressed = bool(sz & (1 << 24))
        if length == 0:
            data = b""
        else:
            raw = self.src.read_at(sblk, length)
            if uncompressed:
                data = raw
            else:
                data = self._inflate(raw, self.block_size,
                                     "fragment block %d at 0x%x" % (idx, sblk))
        self._frag_cache[idx] = data
        return data

    # -- file data ----------------------------------------------------------
    def read_file(self, entry, limit=None):
        e = self._as_entry(entry)
        if e.is_symlink:
            return bytes(e.target)
        if not e.is_file:
            raise SquashfsV123Error(
                "%r is not a regular file (type=%s)" % (e.name, e.type_name))
        full = e.size
        want = full if limit is None else min(full, max(0, int(limit)))
        if want <= 0:
            return b""
        bs = self.block_size
        has_frag = e.fragment is not None and e.fragment != FRAG_NONE
        if has_frag:
            nblocks = full // bs
        else:
            nblocks = (full + bs - 1) // bs
        out = bytearray()
        cur = e.start_block
        bl = e.block_list
        for i in range(nblocks):
            if i >= len(bl):
                raise SquashfsV123Error(
                    "block_list too short: need %d, have %d" % (nblocks, len(bl)))
            stored = bl[i]
            csize = stored & 0x7FFF
            if csize == 0:
                raise SquashfsV123Error(
                    "zero-length data block %d of %r" % (i, e.name))
            raw = self.src.read_at(cur, csize)
            cur += csize
            if self.check_data:
                cur += 1
            if stored & 0x8000:
                chunk = raw
            else:
                chunk = self._inflate(raw, bs, "data block %d of %r" % (i, e.name))
            out += chunk
            if len(out) >= want:
                return bytes(out[:want])
        if has_frag:
            tail = full - nblocks * bs
            if tail > 0 and len(out) < want:
                fb = self._fragment_block(e.fragment)
                piece = fb[e.offset:e.offset + tail]
                if len(piece) != tail:
                    raise SquashfsV123Error(
                        "fragment %d too short for %r (want %d, got %d)"
                        % (e.fragment, e.name, tail, len(piece)))
                out += piece
        return bytes(out[:want])

    def close(self):
        try:
            self.src.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# module level helpers
# ---------------------------------------------------------------------------
def probe(sub):
    """True only for SquashFS v1/v2/v3 (``s_minor <= 9``); v4 returns False."""
    try:
        src = _Source(sub)
    except Exception:
        return False
    try:
        if src.size is not None and src.size < 32:
            return False
        head = src.read_at(0, 32)
        if len(head) < 32:
            return False
        if _be(head, 0, 4) != MAGIC:
            return False
        major = _be(head, 28, 2)
        minor = _be(head, 30, 2)
        if major not in (1, 2, 3):
            return False
        return minor <= 9
    except Exception:
        return False
    finally:
        src.close()


def open_fs(sub, comp="gzip"):
    return SquashfsV123(sub, comp=comp)


def describe(sub):
    """Fault tolerant one-shot description; never raises."""
    fs = None
    try:
        fs = SquashfsV123(sub)
        info = fs.info()
        info["ok"] = True
        try:
            root = fs.root
            info["root_type"] = root.type_name
            info["root_nlink"] = root.nlink
            kids = fs.listdir(root)
            info["root_entries"] = len(kids)
            info["root_names"] = [k.name for k in kids][:32]
        except Exception as e:
            info["root_error"] = "%s: %s" % (type(e).__name__, e)
        return info
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e),
                "error_type": type(e).__name__}
    finally:
        if fs is not None:
            fs.close()


# ===========================================================================
# self-check -- synthetic images only
# ===========================================================================
class _BW(object):
    """MSB-first bit writer (mirror of :func:`_bits`)."""

    __slots__ = ("acc", "n", "out")

    def __init__(self):
        self.acc = 0
        self.n = 0
        self.out = bytearray()

    def put(self, val, nbits):
        val &= (1 << nbits) - 1
        for i in range(nbits - 1, -1, -1):
            self.acc = (self.acc << 1) | ((val >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc & 0xFF)
                self.acc = 0
                self.n = 0

    def bytes(self):
        if self.n:
            raise AssertionError("bit writer not byte-aligned (%d bits)" % self.n)
        return bytes(self.out)


def _node(name, kind, content=b"", target=b"", mode=None, uid=0, gid=0,
          mtime=0x5F123456, frag=True, compress=True):
    return {
        "name": name, "kind": kind, "content": content, "target": target,
        "mode": mode, "uid": uid, "gid": gid, "mtime": mtime,
        "frag": frag, "compress": compress, "children": [],
        "inum": 0, "pos": 0,
    }


class _Builder(object):
    """Minimal SquashFS v1/v2/v3 writer used only by the self-check."""

    DATA_BASE = 128

    def __init__(self, major, minor=0, block_size=4096, check=False,
                 compress_tables=False, compress_data=True):
        self.major = major
        self.minor = minor
        self.bs = block_size
        self.block_log = block_size.bit_length() - 1
        self.check = check
        self.compress_tables = compress_tables
        self.compress_data = compress_data
        self.data = bytearray()
        self.inode_buf = bytearray()
        self.dir_buf = bytearray()
        self.frag_blocks = []
        self._inum = 0

    # -- data region --------------------------------------------------------
    def _emit(self, raw, compress):
        off = self.DATA_BASE + len(self.data)
        if compress and len(raw) > 16 and not self.check:
            comp = zlib.compress(raw, 6)
            if len(comp) < len(raw):
                self.data += comp
                stored = len(comp)
            else:
                self.data += raw
                stored = len(raw) | 0x8000
        else:
            self.data += raw
            stored = len(raw) | 0x8000
        if self.check:
            self.data += b"\x00"
        return off, stored

    def _add_fragment(self, raw, compress):
        off = self.DATA_BASE + len(self.data)
        if compress and len(raw) > 4:
            comp = zlib.compress(raw, 6)
            if len(comp) < len(raw):
                self.data += comp
                field = len(comp) & 0xFFFFFF
            else:
                self.data += raw
                field = len(raw) | (1 << 24)
        else:
            self.data += raw
            field = len(raw) | (1 << 24)
        if self.check:
            self.data += b"\x00"
        idx = len(self.frag_blocks)
        self.frag_blocks.append((off, field))
        return idx

    def place_file(self, content, use_frag=True, compress=None):
        if compress is None:
            compress = self.compress_data
        bs = self.bs
        n = len(content)
        info = {"blocks": [], "start_block": 0, "fragment": FRAG_NONE,
                "offset": 0, "size": n, "first_set": False}
        if self.major >= 2 and use_frag:
            nfull = n // bs
            tail = n % bs
        else:
            nfull = (n + bs - 1) // bs
            tail = 0
        for i in range(nfull):
            raw = content[i * bs:(i + 1) * bs]
            off, stored = self._emit(raw, compress)
            if not info["first_set"]:
                info["start_block"] = off
                info["first_set"] = True
            info["blocks"].append(stored)
        if tail:
            info["fragment"] = self._add_fragment(content[nfull * bs:], compress)
            info["offset"] = 0
        return info

    # -- inode writing ------------------------------------------------------
    def _write_base(self, bw, typ, mode, node):
        bw.put(typ, 4)
        bw.put(mode & 0xFFF, 12)
        uid = node["uid"]
        gid = node["gid"]
        if self.major == 3:
            bw.put(uid & 0xFF, 8)
            bw.put(gid & 0xFF, 8)
            bw.put(node["mtime"] & 0xFFFFFFFF, 32)
            bw.put(node["inum"] & 0xFFFFFFFF, 32)
        elif self.major == 2:
            bw.put(uid & 0xFF, 8)
            bw.put(gid & 0xFF, 8)
        else:
            bw.put(uid & 0xF, 4)
            bw.put(gid & 0xF, 4)

    def _dir_inode(self, node):
        bw = _BW()
        ldir = self.major == 3 and bool(node.get("ldir"))
        self._write_base(bw, 8 if ldir else 1, node["mode"] or 0o755, node)
        dsize = node["dsize"]
        dintra = node["doff_intra"]
        dblk = node["doff_blk"]
        if self.major == 3:
            bw.put(node["nlink"], 32)
            bw.put(dsize, 27 if ldir else 19)
            bw.put(dintra, 13)
            bw.put(dblk, 32)
            if ldir:
                bw.put(0, 16)          # i_count = 0: no dir_index entries follow
            bw.put(node["parent_inum"] & 0xFFFFFFFF, 32)
        else:
            bw.put(dsize, 19)
            bw.put(dintra, 13)
            bw.put(node["mtime"], 32)
            bw.put(dblk, 24)
        return bw.bytes()

    def _reg_inode(self, node, fi):
        bw = _BW()
        lreg = self.major == 3 and bool(node.get("lreg"))
        self._write_base(bw, 9 if lreg else 2, node["mode"] or 0o644, node)
        if self.major == 3:
            if lreg:
                bw.put(node.get("nlink", 1), 32)
            bw.put(fi["start_block"], 64)
            bw.put(fi["fragment"], 32)
            bw.put(fi["offset"], 32)
            bw.put(fi["size"], 64 if lreg else 32)
        elif self.major == 2:
            bw.put(node["mtime"], 32)
            bw.put(fi["start_block"], 32)
            bw.put(fi["fragment"], 32)
            bw.put(fi["offset"], 32)
            bw.put(fi["size"], 32)
        else:
            bw.put(node["mtime"], 32)
            bw.put(fi["start_block"], 32)
            bw.put(fi["size"], 32)
        for b in fi["blocks"]:
            bw.put(b, 16)
        return bw.bytes()

    def _symlink_inode(self, node):
        bw = _BW()
        self._write_base(bw, 3, node["mode"] or 0o777, node)
        if self.major == 3:
            bw.put(1, 32)
            bw.put(len(node["target"]), 16)
        else:
            bw.put(len(node["target"]), 16)
        return bw.bytes() + node["target"]

    def _dev_inode(self, node, typ):
        bw = _BW()
        self._write_base(bw, typ, node["mode"] or 0o644, node)
        if self.major == 3:
            bw.put(1, 32)
            bw.put(node.get("rdev", 0), 16)
        else:
            bw.put(node.get("rdev", 0), 16)
        return bw.bytes()

    # -- directory data -----------------------------------------------------
    def _dir_data(self, kids):
        out = bytearray()
        v = self.major
        chunk = 200
        for start in range(0, len(kids), chunk):
            part = kids[start:start + chunk]
            base_inum = part[0][3] if part else 0
            if v == 3:
                bw = _BW()
                bw.put(len(part), 8)
                bw.put(0, 32)
                bw.put(base_inum & 0xFFFFFFFF, 32)
                out += bw.bytes()
                for name, pos, dtype, inum in part:
                    bw = _BW()
                    bw.put(pos & 0x1FFF, 13)
                    bw.put(dtype, 3)
                    bw.put(len(name) - 1, 8)
                    bw.put((inum - base_inum) & 0xFFFF, 16)
                    out += bw.bytes() + name
            else:
                bw = _BW()
                bw.put(len(part), 8)
                bw.put(0, 24)
                out += bw.bytes()
                for name, pos, dtype, inum in part:
                    bw = _BW()
                    bw.put(pos & 0x1FFF, 13)
                    bw.put(dtype, 3)
                    bw.put(len(name) - 1, 8)
                    out += bw.bytes() + name
        return bytes(out)

    # -- tree ---------------------------------------------------------------
    def _assign_inums(self, node):
        self._inum += 1
        node["inum"] = self._inum
        for ch in node["children"]:
            self._assign_inums(ch)

    def _emit_node(self, node):
        kind = node["kind"]
        if kind == "dir":
            kids = []
            for ch in node["children"]:
                pos = self._emit_node(ch)
                kids.append((ch["name"].encode("utf-8"), pos,
                             {"dir": 1, "file": 2, "symlink": 3,
                              "blkdev": 4, "chrdev": 5}[ch["kind"]],
                             ch["inum"]))
            doff_abs = len(self.dir_buf)
            data = self._dir_data(kids)
            self.dir_buf += data
            stride = METADATA_MAX + 2 + (1 if self.check else 0)
            node["dsize"] = len(data)
            node["doff_intra"] = doff_abs % METADATA_MAX
            node["doff_blk"] = (doff_abs // METADATA_MAX) * stride
            node["parent_inum"] = node.get("parent_inum", 0)
            node["nlink"] = 2 + sum(1 for c in node["children"] if c["kind"] == "dir")
            pos = len(self.inode_buf)
            self.inode_buf += self._dir_inode(node)
            node["pos"] = pos
            return pos
        pos = len(self.inode_buf)
        if kind == "file":
            node["pos"] = pos
            self.inode_buf += self._reg_inode(node, node["fi"])
        elif kind == "symlink":
            node["pos"] = pos
            self.inode_buf += self._symlink_inode(node)
        elif kind in ("blkdev", "chrdev"):
            node["pos"] = pos
            self.inode_buf += self._dev_inode(node, 4 if kind == "blkdev" else 5)
        else:
            raise AssertionError("bad kind %r" % (kind,))
        return pos

    def _walk_files(self, node):
        if node["kind"] == "file":
            yield node
        for ch in node["children"]:
            for f in self._walk_files(ch):
                yield f

    def _set_parents(self, node):
        for ch in node["children"]:
            ch["parent_inum"] = node["inum"]
            self._set_parents(ch)

    def _meta_pack(self, payload):
        if len(payload) > METADATA_MAX:
            raise AssertionError("metadata payload too large for single block")
        raw = payload
        if self.compress_tables and len(raw) > 32:
            comp = zlib.compress(raw, 6)
            if len(comp) < len(raw):
                return (struct.pack(">H", len(comp) & 0x7FFF)
                        + (b"\x00" if self.check else b"") + comp)
        return (struct.pack(">H", 0x8000 | len(raw))
                + (b"\x00" if self.check else b"") + raw)

    def _meta_pack_all(self, payload):
        parts = []
        if not payload:
            return b""
        for i in range(0, len(payload), METADATA_MAX):
            parts.append(self._meta_pack(payload[i:i + METADATA_MAX]))
        return b"".join(parts)

    def build(self, root):
        for f in self._walk_files(root):
            f["fi"] = self.place_file(f["content"], use_frag=f["frag"],
                                      compress=f["compress"])
        self._assign_inums(root)
        self._set_parents(root)
        root_pos = self._emit_node(root)
        if len(self.inode_buf) > METADATA_MAX:
            raise AssertionError("inode table exceeds one metadata block")

        inode_blk = self._meta_pack_all(bytes(self.inode_buf))
        dir_blk = self._meta_pack_all(bytes(self.dir_buf))

        frag_meta = b""
        ptr_offsets = []
        if self.frag_blocks:
            esize = 16 if self.major == 3 else 8
            ents = bytearray()
            for off, field in self.frag_blocks:
                if esize == 16:
                    ents += struct.pack(">QII", off, field, 0)
                else:
                    ents += struct.pack(">II", off, field)
            frag_meta = self._meta_pack_all(bytes(ents))
            nblocks = (len(ents) + METADATA_MAX - 1) // METADATA_MAX
            stride = METADATA_MAX + 2 + (1 if self.check else 0)
            for b in range(nblocks):
                ptr_offsets.append(b * stride)

        off_inode = self.DATA_BASE + len(self.data)
        off_dir = off_inode + len(inode_blk)
        off_frag_meta = off_dir + len(dir_blk)
        off_frag_ptr = off_frag_meta + len(frag_meta)
        total = off_frag_ptr + 8 * len(ptr_offsets)

        sb = bytearray(128)

        def p32(o, v):
            sb[o:o + 4] = struct.pack(">I", v & 0xFFFFFFFF)

        def p64(o, v):
            sb[o:o + 8] = struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)

        def p16(o, v):
            sb[o:o + 2] = struct.pack(">H", v & 0xFFFF)

        p32(0, MAGIC)
        p32(4, self._inum)
        p32(8, total)
        p32(12, 0)
        p32(16, 0)
        p32(20, off_inode)
        p32(24, off_dir)
        p16(28, self.major)
        p16(30, self.minor)
        p16(32, self.bs if self.bs <= 0xFFFF else 0)
        p16(34, self.block_log)
        sb[36] = CHECK_FLAG if self.check else 0
        sb[37] = 0
        sb[38] = 0
        p32(39, 0x5F123456)
        p64(43, (0 << 16) | (root_pos & 0xFFFF))
        p32(51, self.bs)
        p32(55, len(self.frag_blocks))
        p32(59, off_frag_ptr)
        p64(63, total)
        p64(71, 0)
        p64(79, 0)
        p64(87, off_inode)
        p64(95, off_dir)
        p64(103, off_frag_ptr)
        p64(111, 0)

        ptrs = bytearray()
        for po in ptr_offsets:
            ptrs += struct.pack(">Q", off_frag_meta + po)

        img = (bytes(sb) + bytes(self.data) + inode_blk + dir_blk
               + frag_meta + bytes(ptrs))
        assert len(img) == total, (len(img), total)
        layout = {
            "off_data": self.DATA_BASE,
            "off_inode": off_inode,
            "off_dir": off_dir,
            "off_frag_meta": off_frag_meta,
            "off_frag_ptr": off_frag_ptr,
            "total": total,
            "root_pos": root_pos,
            "inodes": self._inum,
        }
        return img, layout


def _tree_basic(major):
    """root/{hello.txt, sub/{inner.bin}, big.bin, link.txt(->hello.txt)}."""
    root = _node("", "dir")
    hello = _node("hello.txt", "file", content=b"Hello SquashFS!\n")
    sub = _node("sub", "dir", mode=0o755)
    inner = _node("inner.bin", "file", content=bytes(range(256)) * 2)  # 512 B
    sub["children"] = [inner]
    big = _node("big.bin", "file",
                content=bytes(((i * 37 + 11) % 256) for i in range(8300)))
    link = _node("link.txt", "symlink", target=b"hello.txt")
    root["children"] = [hello, sub, big, link]
    return root


def _expect_basic(major):
    return {
        "hello.txt": b"Hello SquashFS!\n",
        "sub/inner.bin": bytes(range(256)) * 2,
        "big.bin": bytes(((i * 37 + 11) % 256) for i in range(8300)),
    }


def _run_checks():
    results = []

    def T(name, fn):
        try:
            fn()
        except AssertionError as e:
            results.append((name, False, str(e) or "assertion failed"))
            print("FAIL %s :: %s" % (name, e))
        except Exception as e:
            results.append((name, False, "%s: %s" % (type(e).__name__, e)))
            print("FAIL %s :: %s: %s" % (name, type(e).__name__, e))
        else:
            results.append((name, True, ""))
            print("PASS %s" % name)

    # ---- 1 probe ---------------------------------------------------------
    def t1():
        img3, _ = _Builder(3).build(_tree_basic(3))
        img2, _ = _Builder(2).build(_tree_basic(2))
        assert probe(img3) is True, "v3 not detected"
        assert probe(img2) is True, "v2 not detected"
        img1, _ = _Builder(1, check=False).build(_tree_basic(1))
        assert probe(img1) is True, "v1 not detected"
        v4 = bytearray(img3)
        v4[28:30] = struct.pack(">H", 4)
        assert probe(bytes(v4)) is False, "v4 must not be claimed"
        v4b = bytearray(img3)
        v4b[28:30] = struct.pack(">H", 4)
        v4b[30:32] = struct.pack(">H", 0)
        assert probe(bytes(v4b)) is False
        assert probe(b"") is False
        assert probe(b"\x00" * 40) is False
        assert probe(b"hsqs" + b"\x00" * 8) is False
        assert probe(os.urandom(512)) is False
        assert probe(object()) is False
        assert probe(b"hsqs" + b"\x00" * 200) is False

    # ---- 2 v2 ------------------------------------------------------------
    def t2():
        root = _tree_basic(2)
        img, _lay = _Builder(2).build(root)
        fs = SquashfsV123(img)
        assert fs.major == 2 and fs.minor == 0
        names = sorted(e.name for e in fs.listdir())
        assert names == ["big.bin", "hello.txt", "link.txt", "sub"], names
        exp = _expect_basic(2)
        for path, want in exp.items():
            e = fs.lookup_path(path)
            assert e is not None, "missing %s" % path
            got = fs.read_file(e)
            assert got == want, "%s mismatch (%d vs %d)" % (path, len(got), len(want))
        sub = fs.lookup_path("sub")
        assert sub is not None and sub.is_dir
        kids = fs.listdir(sub)
        assert [k.name for k in kids] == ["inner.bin"]
        assert fs.read_file(kids[0]) == bytes(range(256)) * 2
        big = fs.lookup_path("big.bin")
        assert big.fragment != FRAG_NONE, "expected a fragment tail in v2"
        assert fs.read_file(big, limit=100) == exp["big.bin"][:100]
        # v2 base has no inode_number; the reg inode itself does carry mtime
        assert big.mtime == 0x5F123456, hex(big.mtime)
        assert big.inode_number == 0

    # ---- 3 v3 ------------------------------------------------------------
    def t3():
        root = _tree_basic(3)
        img, _lay = _Builder(3).build(root)
        fs = SquashfsV123(img)
        assert fs.major == 3
        names = sorted(e.name for e in fs.listdir())
        assert names == ["big.bin", "hello.txt", "link.txt", "sub"], names
        exp = _expect_basic(3)
        for path, want in exp.items():
            e = fs.lookup_path(path)
            assert e is not None
            assert fs.read_file(e) == want, path
        big = fs.lookup_path("big.bin")
        assert big.size == 8300
        assert len(big.block_list) == 2, big.block_list  # 2 full 4096 blocks
        assert big.fragment != FRAG_NONE
        assert big.mtime == 0x5F123456
        assert big.inode_number > 0
        assert big.uid == 0
        link = fs.lookup_path("link.txt")
        assert link.is_symlink and fs.readlink(link) == b"hello.txt"
        # a file stored without a fragment (exact multiple of block size)
        root2 = _node("", "dir")
        exact = _node("exact.bin", "file", content=b"Z" * 4096)
        root2["children"] = [exact]
        img2, _ = _Builder(3).build(root2)
        fs2 = SquashfsV123(img2)
        e = fs2.lookup_path("exact.bin")
        assert e.fragment == FRAG_NONE, e.fragment
        assert len(e.block_list) == 1
        assert fs2.read_file(e) == b"Z" * 4096
        # zero length file
        root3 = _node("", "dir")
        root3["children"] = [_node("empty", "file", content=b"")]
        img3, _ = _Builder(3).build(root3)
        fs3 = SquashfsV123(img3)
        e3 = fs3.lookup_path("empty")
        assert fs3.read_file(e3) == b"" and e3.size == 0

    # ---- 4 endianness / field source --------------------------------------
    def t4():
        img, lay = _Builder(3, block_size=4096).build(_tree_basic(3))
        raw32 = img[51:55]
        big = struct.unpack(">I", raw32)[0]
        little = struct.unpack("<I", raw32)[0]
        assert big == 4096, big
        assert little == 0x00100000, hex(little)
        assert big != little, "endianness evidence is degenerate"
        fs = SquashfsV123(img)
        info = fs.info()
        assert info["block_size"] == 4096, info["block_size"]
        assert info["block_log"] == 12
        src = info["sb_field_source"]
        assert "u32@51" in src["block_size"], src["block_size"]
        assert "u64@87" in src["inode_table_start"], src["inode_table_start"]
        assert info["version"] == "3.0", info["version"]
        assert info["root_inode_pos"] == (0, lay["root_pos"])
        assert info["inode_count"] == lay["inodes"]
        assert info["check_data"] is False
        assert fs.read_file(fs.lookup_path("hello.txt")) == b"Hello SquashFS!\n"

        # 16-bit fallback for block_size (@51 zeroed, @32 kept)
        b = bytearray(img)
        b[51:55] = struct.pack(">I", 0)
        fs16 = SquashfsV123(bytes(b))
        i16 = fs16.info()
        assert i16["block_size"] == 4096, i16["block_size"]
        assert "u16@32" in i16["sb_field_source"]["block_size"]
        assert fs16.read_file(fs16.lookup_path("hello.txt")) == b"Hello SquashFS!\n"

        # 64-bit address fallback: zero the u64 block, keep the *_2 fields
        b2 = bytearray(img)
        b2[63:71] = b"\x00" * 8       # bytes_used
        b2[87:95] = b"\x00" * 8       # inode_table_start
        b2[95:103] = b"\x00" * 8      # directory_table_start
        b2[103:111] = b"\x00" * 8     # fragment_table_start
        fs2 = SquashfsV123(bytes(b2))
        i2 = fs2.info()
        assert i2["inode_table_start"] == struct.unpack(">I", img[20:24])[0]
        assert "fallback" in i2["sb_field_source"]["inode_table_start"]
        assert fs2.read_file(fs2.lookup_path("big.bin")) == _expect_basic(3)["big.bin"]

    # ---- 5 multibyte names ------------------------------------------------
    def t5():
        root = _node("", "dir")
        n1 = _node("中文文件.txt", "file", content="内容-测试\n".encode("utf-8"))
        d = _node("目录名", "dir")
        d["children"] = [_node("файл.bin", "file", content=b"\x01\x02\x03")]
        root["children"] = [n1, d]
        img, _ = _Builder(3).build(root)
        fs = SquashfsV123(img)
        names = [e.name for e in fs.listdir()]
        assert "中文文件.txt" in names, names
        assert "目录名" in names, names
        e = fs.lookup_path("/中文文件.txt")
        assert e is not None and e.name == "中文文件.txt"
        assert fs.read_file(e) == "内容-测试\n".encode("utf-8")
        sub = fs.lookup_path("目录名")
        assert [c.name for c in fs.listdir(sub)] == ["файл.bin"]
        assert fs.read_file(fs.listdir(sub)[0]) == b"\x01\x02\x03"
        # round-trip of raw name bytes
        assert e.name_bytes == "中文文件.txt".encode("utf-8")

    # ---- 6 unknown compression -------------------------------------------
    def t6():
        img, lay = _Builder(3).build(_tree_basic(3))
        payload = b"\x28\xb5\x2f\xfd" + b"\x41" * 20   # zstd magic + junk
        new = bytearray(img)
        off = lay["off_inode"]
        old_len = lay["off_dir"] - off
        block = struct.pack(">H", len(payload)) + payload   # compressed (bit15 clear)
        assert len(block) <= old_len
        new[off:off + len(block)] = block
        for i in range(off + len(block), off + old_len):
            new[i] = 0
        try:
            fs = SquashfsV123(bytes(new))
            fs.listdir()
        except NotImplementedError as e:
            msg = str(e).lower()
            assert "zstd" in msg, msg
        else:
            raise AssertionError("zstd metadata block was accepted")
        try:
            SquashfsV123(img, comp="lzo")
        except NotImplementedError as e:
            assert "lzo" in str(e).lower(), str(e)
        else:
            raise AssertionError("comp='lzo' was accepted")

    # ---- 7 CHECK_DATA -----------------------------------------------------
    def t7():
        for major in (2, 3):
            root = _tree_basic(major)
            img, _ = _Builder(major, check=True).build(root)
            fs = SquashfsV123(img)
            assert fs.info()["check_data"] is True
            assert fs.flags & CHECK_FLAG
            assert sorted(e.name for e in fs.listdir()) == \
                ["big.bin", "hello.txt", "link.txt", "sub"]
            exp = _expect_basic(major)
            for path, want in exp.items():
                e = fs.lookup_path(path)
                assert e is not None, path
                assert fs.read_file(e) == want, "%s (v%d, check)" % (path, major)

    # ---- 8 malformed ------------------------------------------------------
    def t8():
        good, _ = _Builder(3).build(_tree_basic(3))
        cases = [
            ("empty", b""),
            ("one-byte", b"h"),
            ("garbage", bytes(range(200))),
            ("truncated-sb", good[:60]),
            ("truncated-body", good[:len(good) // 2]),
        ]
        for label, blob in cases:
            try:
                SquashfsV123(blob)
            except SquashfsV123Error:
                pass
            else:
                raise AssertionError("%s did not raise SquashfsV123Error" % label)
        try:
            SquashfsV123(good, comp="xz")
        except NotImplementedError:
            pass
        else:
            raise AssertionError("comp='xz' accepted")
        v4 = bytearray(good)
        v4[28:30] = struct.pack(">H", 4)
        try:
            SquashfsV123(bytes(v4))
        except SquashfsV123Error as e:
            assert "v4" in str(e), str(e)
        else:
            raise AssertionError("v4 accepted by v123 parser")
        bad_minor = bytearray(good)
        bad_minor[30:32] = struct.pack(">H", 16)
        try:
            SquashfsV123(bytes(bad_minor))
        except SquashfsV123Error:
            pass
        else:
            raise AssertionError("minor=16 accepted")
        # a directory whose inode points outside the image must not crash hard
        fs = SquashfsV123(good)
        broken = _fake_dir_entry(fs.root)
        try:
            fs.listdir(broken)
        except SquashfsV123Error:
            pass
        except NotImplementedError:
            pass
        else:
            raise AssertionError("bogus dir offset accepted")

    def _fake_dir_entry(root):
        e = Sqv123Entry()
        for slot in Sqv123Entry.__slots__:
            setattr(e, slot, getattr(root, slot))
        e.start_block = 0xFFFF
        e.offset = 0x1FFF
        e.size = 256
        return e

    # ---- 9 v1 -------------------------------------------------------------
    def t9():
        root = _tree_basic(1)
        img, lay = _Builder(1, block_size=4096).build(root)
        assert probe(img) is True
        fs = SquashfsV123(img)
        assert fs.major == 1
        assert fs.fragments == 0, fs.fragments
        names = sorted(e.name for e in fs.listdir())
        assert names == ["big.bin", "hello.txt", "link.txt", "sub"], names
        exp = _expect_basic(1)
        for path, want in exp.items():
            e = fs.lookup_path(path)
            assert e is not None, path
            got = fs.read_file(e)
            assert got == want, "%s v1 mismatch (%d vs %d)" % (path, len(got), len(want))
        big = fs.lookup_path("big.bin")
        assert big.fragment == FRAG_NONE
        # v1: no fragment => ceil(size/block_size) blocks
        assert len(big.block_list) == 3, big.block_list  # 8300 -> 3 blocks
        assert big.uid == 0 and big.gid == 0  # 4-bit fields
        link = fs.lookup_path("link.txt")
        assert fs.readlink(link) == b"hello.txt"
        sub = fs.lookup_path("sub")
        assert [c.name for c in fs.listdir(sub)] == ["inner.bin"]
        assert fs.read_file(fs.listdir(sub)[0]) == bytes(range(256)) * 2
        # v1 directory inode carries no nlink / parent
        assert fs.root.nlink == 0

    # ---- 10 describe tolerance -------------------------------------------
    def t10():
        good, _ = _Builder(3).build(_tree_basic(3))
        d = describe(good)
        assert d["ok"] is True, d
        assert d["version"] == "3.0"
        assert d["root_entries"] == 4, d.get("root_entries")
        for blob in (b"", b"junk" * 8, good[:40]):
            d = describe(blob)
            assert d["ok"] is False, d
            assert "error" in d
        v4 = bytearray(good)
        v4[28:30] = struct.pack(">H", 4)
        d = describe(bytes(v4))
        assert d["ok"] is False and "v4" in d["error"], d
        p = _tmp_path()
        try:
            with open(p, "wb") as fh:
                fh.write(good)
            d = describe(p)
            assert d["ok"] is True and d["version"] == "3.0", d
            assert probe(p) is True
            fs = SquashfsV123(p)
            assert fs.read_file(fs.lookup_path("hello.txt")) == b"Hello SquashFS!\n"
            fs.close()
            # file object source
            with open(p, "rb") as fh:
                assert probe(fh) is True
                fs2 = SquashfsV123(fh)
                assert fs2.read_file(fs2.lookup_path("hello.txt")) == b"Hello SquashFS!\n"
            # memoryview source
            fs3 = SquashfsV123(memoryview(good))
            assert fs3.read_file(fs3.lookup_path("hello.txt")) == b"Hello SquashFS!\n"
        finally:
            try:
                os.unlink(p)
            except OSError:
                pass

    def _tmp_path():
        base = tempfile.gettempdir()
        return os.path.join(base, "sqv123_%d.img" % os.getpid())

    # ---- 11 lookup / find / walk / readlink -------------------------------
    def t11():
        img, _ = _Builder(3).build(_tree_basic(3))
        fs = SquashfsV123(img)
        assert fs.lookup_path("/") is fs.root
        assert fs.lookup_path("").name == ""
        assert fs.lookup_path("/sub/inner.bin").size == 512
        assert fs.lookup_path("/sub/inner.bin/") is not None
        assert fs.lookup_path("/nope") is None
        assert fs.lookup_path("/sub/nope") is None
        assert fs.lookup_path("/hello.txt/x") is None
        hits = fs.find(r"\.bin$")
        assert sorted(p for p, _ in hits) == ["/big.bin", "/sub/inner.bin"], hits
        assert [p for p, _ in fs.find("hello")] == ["/hello.txt"]
        paths = [p for p, _ in fs.walk()]
        assert paths == ["/hello.txt", "/sub", "/sub/inner.bin",
                         "/big.bin", "/link.txt"], paths
        dirs = [p for p, e in fs.walk() if e.is_dir]
        assert dirs == ["/sub"]
        link = fs.lookup_path("link.txt")
        assert fs.readlink(link) == b"hello.txt"
        try:
            fs.readlink(fs.lookup_path("hello.txt"))
        except SquashfsV123Error:
            pass
        else:
            raise AssertionError("readlink on a regular file succeeded")
        assert fs.read_file(link) == b"hello.txt"

    # ---- 12 metadata crossing --------------------------------------------
    def t12():
        root = _node("", "dir")
        target = _node("t.bin", "file", content=b"crossing")
        root["children"] = [target]
        many = []
        for i in range(1200):
            e = _node("file%04d.txt" % i, "file", content=b"")
            e["hardlink_to"] = target
            many.append(e)
        root["children"].extend(many)
        b = _Builder(3)
        # all 1200 names share the single inode position of t.bin
        orig_emit = b._emit_node

        def emit_patched(node):
            if node.get("hardlink_to") is not None:
                node["pos"] = node["hardlink_to"]["pos"]
                return node["pos"]
            return orig_emit(node)

        b._emit_node = emit_patched
        img, lay = b.build(root)
        fs = SquashfsV123(img)
        kids = fs.listdir()
        assert len(kids) == 1201, len(kids)
        assert kids[0].name == "t.bin"
        assert kids[1].name == "file0000.txt"
        assert fs.read_file(kids[1]) == b"crossing"
        assert fs.read_file(kids[-1]) == b"crossing"
        span = lay["off_dir"]
        assert fs.root.size > METADATA_MAX, fs.root.size

    # ---- 13 v3 ldir / lreg -----------------------------------------------
    def t13():
        root = _node("", "dir")
        root["ldir"] = True
        big = _node("large.bin", "file",
                    content=bytes(((i * 7 + 3) % 256) for i in range(8300)))
        big["lreg"] = True
        root["children"] = [big]
        for i in range(1200):
            e = _node("h%04d" % i, "file", content=b"")
            e["hardlink_to"] = big
            root["children"].append(e)
        b = _Builder(3)
        orig = b._emit_node

        def patched(node):
            if node.get("hardlink_to") is not None:
                node["pos"] = node["hardlink_to"]["pos"]
                return node["pos"]
            return orig(node)

        b._emit_node = patched
        img, _lay = b.build(root)
        fs = SquashfsV123(img)
        assert fs.root.inode_type == 8, fs.root.inode_type
        assert fs.root.type_name == "ldir" and fs.root.is_dir
        kids = fs.listdir()
        assert len(kids) == 1201, len(kids)
        assert kids[0].name == "large.bin"
        assert kids[0].inode_type == 9 and kids[0].type_name == "lreg"
        assert kids[0].is_file and not kids[0].is_dir
        assert kids[0].size == 8300
        assert fs.read_file(kids[0]) == big["content"], "lreg content mismatch"
        assert fs.read_file(kids[7]) == big["content"]
        assert fs.lookup_path("/h1199").size == 8300

    T("1 probe v1/v2/v3 hit, v4/empty/garbage miss", t1)
    T("2 v2 synthetic: listdir + read_file + subdir", t2)
    T("3 v3 synthetic: blocks + fragment + symlink + empty file", t3)
    T("4 big-endian evidence + block_size/field-source selection", t4)
    T("5 multibyte (UTF-8) names round-trip", t5)
    T("6 unknown compressor (zstd payload / comp='lzo') raises", t6)
    T("7 CHECK_DATA: metadata + data blocks carry check bytes", t7)
    T("8 malformed inputs raise SquashfsV123Error, never crash", t8)
    T("9 v1 synthetic: inode parse + listdir + read_file", t9)
    T("10 describe() fault tolerance + path/file/memoryview sources", t10)
    T("11 lookup_path / find / walk / readlink", t11)
    T("12 metadata stream crossing block boundary (dir > 8K)", t12)

    bad = [r for r in results if not r[1]]
    print("\n%d checks, %d passed, %d failed" %
          (len(results), len(results) - len(bad), len(bad)))
    if bad:
        for name, _ok, msg in bad:
            print("  FAILED: %s :: %s" % (name, msg))
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(_run_checks())