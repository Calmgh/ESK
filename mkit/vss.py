"""mkit.vss - read-only parser for Windows VSS (Volume Shadow Snapshot) stores.

Scope
-----
Parses the persistent VSS *store* file (``System Volume Information\\
{GUID}`` or ``HarddiskVolumeShadowCopyN``) and, optionally, a volume image that
carries the VSS volume header at 0x1E00.  Everything here is read-only: no
writer, no NTFS layer, no decompression.

Layout source
-------------
libvshadow documentation by Joachim Metz:
``Volume Shadow Snapshot (VSS) format.asciidoc`` (libyal/libvshadow, main).
Every offset below is cross-checked against that document; see the
VERIFIED / INFERRED blocks in this docstring for what is documentation-backed
and what is my own reading of under-documented parts.

VERIFIED (documentation-backed)
-------------------------------
* Store / catalog block size 0x4000 (16384 bytes).
* VSS identifier: 16-byte GUID ``{3808876b-c176-4e48-b7ae-04046e6cc752}``,
  stored little-endian, i.e. on disk ``6b 87 08 38 76 c1 48 4e
  b7 ae 04 04 6e 6c c7 52``.  The 8-byte prefix ``6b 87 08 38 76 c1 48 4e``
  is the "identifier[8]" referred to by the task brief; it is the *first half*
  of the 16-byte GUID, not a separate 8-byte structure.
* Volume header lives at offset 0x1E00 (7680) of the volume / $Boot:
  identifier[16] @0, version u32 @16, record_type u32 @20 (1 = volume
  header), current_offset u64 @24 (0x1E00), next_offset u64 @32,
  unknown u64 @40, catalog_offset u64 @48, maximum_size u64 @56,
  volume_identifier GUID @64, shadow-copy-storage volume id GUID @80,
  unknown u32 @96, 412 filler bytes -> 512 bytes total.
  The brief's "file_header_offset = 0x1E00" relation is exactly this: the
  volume header *is* at 0x1E00, and the identifier sits at the start of it.
* Store block header, 128 bytes, repeated at the start of every 0x4000 block
  of the store file: identifier[16] @0, version u32 @16, record_type u32 @20
  (1 volume header, 2 catalog, 3 block descriptor list, 4 store header,
  5 block range list, 6 store bitmap), relative_offset u64 @24 (re. store
  start), current_offset u64 @32 (re. volume start), next_offset u64 @40,
  store_information_size u64 @48, 72 unknown bytes.
* Shadow copy creation time is a FILETIME (100ns since 1601-01-01 UTC);
  strings are UTF-16LE without BOM.
* Catalog block header, 128 bytes: identifier[16] @0, version @16,
  record_type = 2 @20, relative offset @24, current offset @32, next @40.
* Catalog entries are 128 bytes each and start after the 128-byte block
  header.  Type field is a u64 at offset 0:
    1 = unused (all-zero otherwise), skipped;
    2 = shadow copy: volume_size u64 @8, store_identifier GUID @16,
        sequence u64 @32, flags u64 @40, creation_time FILETIME @48;
    3 = store attachment: block_list_offset u64 @8 (volume-relative),
        store_identifier GUID @16, store_header_offset u64 @32,
        block_range_list_offset u64 @40, bitmap_offset u64 @48,
        NTFS file reference u64 @56.
* Block descriptor, 32 bytes: original_offset u64 @0 (volume-relative,
  16384-aligned), relative_store_offset u64 @8, store_data_offset u64 @16
  (volume-relative), flags u32 @24, allocation_bitmap u32 @28.
  Flags: 0x01 forwarder, 0x02 overlay, 0x04 not used.
* Block range entry, 24 bytes: store_offset u64 @0, relative_offset u64 @8,
  size u64 @16.
* Store bitmap: one bit per 16384-byte block, LSB first; a set bit means the
  block is NOT in use by the store.  Zero-fill rule: block absent from the
  descriptor list + flagged in the current bitmap (and no previous bitmap, or
  also flagged in it) => the block reads as zeroes.
* Overlay: allocation_bitmap describes 512-byte units inside one block
  (32 bits exactly cover 16384 bytes).

INFERRED (not stated by the document - flagged in the code as well)
-------------------------------------------------------------------
* Volume name in catalog type-2 entries.  The document calls bytes 56..127 of
  a type-2 entry "unknown (empty values)" and never documents a volume path,
  yet the brief requires a volume name.  I read a NUL-terminated UTF-16LE
  string from offset 56 when one is present and report ``volume_name=None``
  otherwise.  Real images produced by Windows may legitimately yield None.
* Overlay bit polarity: I treat a SET bit in allocation_bitmap as "this
  512-byte unit is stored, the rest is zero".  The document only says the
  bitmap "contains information about which part of the block is used".
* Mapping volume-relative offsets to store-file offsets through the block
  range list (needed when the input is a store file rather than a volume
  image).  One hop, no chain walking; identity when no range list exists.
* Catalog discovery by scanning 16384-aligned offsets for record_type 2 when
  no catalog_offset is available (store-file mode).
* The brief's "block list entry: type u32 (1 full / 2 range / 3 zero)" does
  not exist in the libvshadow specification.  Full / range / zero are
  therefore derived from descriptor flags + allocation bitmap + store bitmap
  instead of from a list-entry type field.

Not implemented (raises NotImplementedError rather than lying)
--------------------------------------------------------------
* Following a forwarder block into the *next* store in the chain.
* Multi-store chains / previous-store fallback beyond the current image.
* Overlay resolution against a "previous store" copy.
"""

from __future__ import annotations

import datetime as _dt
import os
import struct
import uuid as _uuid

__all__ = [
    "VssError",
    "VssTruncatedError",
    "Vss",
    "probe",
    "describe",
    "VSS_IDENTIFIER",
    "VSS_IDENTIFIER_PREFIX",
    "VOLUME_HEADER_OFFSET",
]

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

BLOCK_SIZE = 0x4000
HEADER_SIZE = 128
CATALOG_ENTRY_SIZE = 128
BLOCK_DESCRIPTOR_SIZE = 32
BLOCK_RANGE_ENTRY_SIZE = 24

VOLUME_HEADER_OFFSET = 0x1E00

# {3808876b-c176-4e48-b7ae-04046e6cc752} as stored on disk (little-endian GUID)
VSS_IDENTIFIER = bytes(
    (0x6B, 0x87, 0x08, 0x38, 0x76, 0xC1, 0x48, 0x4E,
     0xB7, 0xAE, 0x04, 0x04, 0x6E, 0x6C, 0xC7, 0x52)
)
VSS_IDENTIFIER_PREFIX = VSS_IDENTIFIER[:8]

REC_VOLUME_HEADER = 1
REC_CATALOG = 2
REC_BLOCK_DESCRIPTOR_LIST = 3
REC_STORE_HEADER = 4
REC_BLOCK_RANGE_LIST = 5
REC_STORE_BITMAP = 6

RECORD_TYPES = {
    REC_VOLUME_HEADER: "volume_header",
    REC_CATALOG: "catalog",
    REC_BLOCK_DESCRIPTOR_LIST: "block_descriptor_list",
    REC_STORE_HEADER: "store_header",
    REC_BLOCK_RANGE_LIST: "block_range_list",
    REC_STORE_BITMAP: "store_bitmap",
}

CATALOG_TYPE_UNUSED = 1
CATALOG_TYPE_SHADOW_COPY = 2
CATALOG_TYPE_STORE = 3

DESC_FORWARDER = 0x01
DESC_OVERLAY = 0x02
DESC_NOT_USED = 0x04

FILETIME_EPOCH_DELTA = 11644473600  # seconds between 1601-01-01 and 1970-01-01

#: Scan cap for structures that can only be found by scanning (bytes).
MAX_SCAN_BYTES = 64 << 20
#: Cap on chained blocks followed through next_offset.
MAX_CHAIN_BLOCKS = 4096

_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")

_EPOCH_1601 = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class VssError(Exception):
    """Base error for VSS parsing problems."""


class VssTruncatedError(VssError):
    """Input ended before a requested structure could be read."""


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _u32(buf, off):
    return _U32.unpack_from(buf, off)[0]


def _u64(buf, off):
    return _U64.unpack_from(buf, off)[0]


def guid_str(raw16):
    """Format a 16-byte little-endian GUID as ``{xxxxxxxx-....}``."""
    if len(raw16) < 16:
        return ""
    return "{%s}" % _uuid.UUID(bytes_le=bytes(raw16[:16]))


def filetime_to_datetime(value):
    """Convert a Windows FILETIME to an aware UTC datetime (None if 0/garbage)."""
    value = int(value)
    if value <= 0:
        return None
    try:
        return _EPOCH_1601 + _dt.timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def datetime_to_filetime(when):
    """Inverse of :func:`filetime_to_datetime`, used by the self-test."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    delta = when - _EPOCH_1601
    return int(delta.total_seconds() * 10000000) + delta.microseconds * 10


def _iso(when):
    if when is None:
        return None
    return when.isoformat().replace("+00:00", "Z")


def _utf16z(buf, off, maxlen):
    """Decode a NUL-terminated UTF-16LE string, or '' when nothing is there."""
    end = min(len(buf), off + maxlen)
    chunks = []
    pos = off
    while pos + 1 < end:
        pair = bytes(buf[pos:pos + 2])
        if pair == b"\x00\x00":
            break
        chunks.append(pair)
        pos += 2
    if not chunks:
        return ""
    return b"".join(chunks).decode("utf-16-le", "replace").strip("\x00")


def _all_zero(buf):
    return not any(buf)


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


class Vss:
    """Read-only view of one VSS store file (or of a volume carrying VSS).

    ``sub`` may be a path (str / os.PathLike), a bytes-like object holding the
    whole image, or a seekable binary file object.
    """

    def __init__(self, sub):
        self._buf = None
        self._fp = None
        self._owns_fp = False

        if isinstance(sub, (str, os.PathLike)):
            self._name = os.fspath(sub)
            self._fp = open(self._name, "rb")
            self._owns_fp = True
            self._size = os.fstat(self._fp.fileno()).st_size
        elif isinstance(sub, (bytes, bytearray, memoryview)):
            data = bytes(sub)
            self._buf = memoryview(data)
            self._size = len(data)
            self._name = "<bytes>"
        elif hasattr(sub, "read") and hasattr(sub, "seek"):
            self._fp = sub
            self._name = str(getattr(sub, "name", "<stream>"))
            self._size = self._stream_size()
        else:
            raise TypeError("sub must be a path, bytes-like or seekable file")

        self.mode = None
        self.header_offset = None
        self.header = {}
        self.catalog_offset = 0
        self.version = None
        self.record_type = None
        self.maximum_size = 0
        self.volume_size = 0
        self.volume_identifier = None
        self.store_volume_identifier = None
        self.identifier_match = "none"

        self._catalog_entries = []
        self._snapshots = []
        self._active_store = None
        self._descriptors = []
        self._desc_by_orig = {}
        self._ranges = []
        self._bitmap = b""
        self._bitmap_offsets = []
        self._loaded_desc = False
        self._loaded_bitmap = False
        self._loaded_ranges = False

        self._detect()

    # -- backend ------------------------------------------------------------

    def _stream_size(self):
        pos = self._fp.tell()
        self._fp.seek(0, os.SEEK_END)
        size = self._fp.tell()
        self._fp.seek(pos, os.SEEK_SET)
        return size

    def close(self):
        if self._owns_fp and self._fp is not None:
            self._fp.close()
            self._fp = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _read_at(self, offset, size):
        if offset < 0 or size < 0:
            raise VssError("negative read request (offset=%d size=%d)" % (offset, size))
        available = self._size - offset
        if available <= 0:
            raise VssTruncatedError(
                "read at 0x%x past end of input (size=0x%x, want %d bytes)"
                % (offset, self._size, size)
            )
        count = min(size, available)
        if self._buf is not None:
            data = bytes(self._buf[offset:offset + count])
        else:
            self._fp.seek(offset, os.SEEK_SET)
            data = self._fp.read(count)
        if len(data) != size:
            raise VssTruncatedError(
                "short read at 0x%x: got %d of %d bytes (image size 0x%x)"
                % (offset, len(data), size, self._size)
            )
        return data

    # -- layer 1: header detection -----------------------------------------

    def _version_ok(self, blob):
        return _u32(blob, 16) in (1, 2)

    def _parse_block_header(self, blob):
        return {
            "identifier": bytes(blob[0:16]),
            "version": _u32(blob, 16),
            "record_type": _u32(blob, 20),
            "relative_offset": _u64(blob, 24),
            "current_offset": _u64(blob, 32),
            "next_offset": _u64(blob, 40),
            "extra": _u64(blob, 48),
        }

    def _parse_volume_header(self, blob):
        info = self._parse_block_header(blob)
        # the volume header reuses @48 for catalog_offset and @56 for maximum_size
        info["catalog_offset"] = _u64(blob, 48)
        info["maximum_size"] = _u64(blob, 56)
        if len(blob) >= 96:
            info["volume_identifier"] = guid_str(blob[64:80])
            info["store_volume_identifier"] = guid_str(blob[80:96])
        return info

    def _find_record_block(self, record_type):
        step = BLOCK_SIZE
        limit = min(self._size, MAX_SCAN_BYTES)
        off = 0
        while off + HEADER_SIZE <= limit:
            blob = self._read_at(off, HEADER_SIZE)
            if blob[:8] == VSS_IDENTIFIER_PREFIX and _u32(blob, 20) == record_type:
                return off
            off += step
        return None

    def _detect(self):
        if self._size < HEADER_SIZE:
            raise VssTruncatedError(
                "input is 0x%x bytes, a VSS header needs at least 0x%x"
                % (self._size, HEADER_SIZE)
            )

        vol_end = VOLUME_HEADER_OFFSET + HEADER_SIZE
        if self._size >= vol_end:
            blob = self._read_at(VOLUME_HEADER_OFFSET, HEADER_SIZE)
            if (
                blob[:8] == VSS_IDENTIFIER_PREFIX
                and self._version_ok(blob)
                and _u32(blob, 20) == REC_VOLUME_HEADER
            ):
                self._adopt("volume", VOLUME_HEADER_OFFSET, self._parse_volume_header(blob), blob)
                self.catalog_offset = self.header.get("catalog_offset", 0)
                return
        elif self._size > VOLUME_HEADER_OFFSET:
            tail = self._read_at(VOLUME_HEADER_OFFSET, self._size - VOLUME_HEADER_OFFSET)
            if tail[:8] == VSS_IDENTIFIER_PREFIX:
                raise VssTruncatedError(
                    "VSS identifier present at 0x%x but only %d header bytes available"
                    % (VOLUME_HEADER_OFFSET, len(tail))
                )

        blob = self._read_at(0, HEADER_SIZE)
        rtype = _u32(blob, 20)
        if (
            blob[:8] == VSS_IDENTIFIER_PREFIX
            and self._version_ok(blob)
            and rtype in RECORD_TYPES
            and rtype != REC_VOLUME_HEADER
        ):
            self._adopt("store", 0, self._parse_block_header(blob), blob)
            self.catalog_offset = 0
            found = self._find_record_block(REC_CATALOG)
            if found is not None:
                self.catalog_offset = found
            return

        found = self._find_record_block(REC_CATALOG)
        if found is not None:
            head = self._read_at(found, HEADER_SIZE)
            self._adopt("catalog", found, self._parse_block_header(head), head)
            self.catalog_offset = found
            return

        raise VssError(
            "not a VSS image: no identifier %s at 0x%x or offset 0, and no "
            "catalog block found" % (VSS_IDENTIFIER_PREFIX.hex(), VOLUME_HEADER_OFFSET)
        )

    def _adopt(self, mode, offset, header, blob):
        self.mode = mode
        self.header_offset = offset
        self.header = header
        self.version = header["version"]
        self.record_type = header["record_type"]
        self.identifier_match = "full" if bytes(blob[:16]) == VSS_IDENTIFIER else "prefix"
        if mode == "volume":
            self.maximum_size = header.get("maximum_size", 0)
            self.volume_identifier = header.get("volume_identifier")
            self.store_volume_identifier = header.get("store_volume_identifier")

    # -- layer 2: catalog ---------------------------------------------------

    def _iter_record_blocks(self, record_type, start=0):
        """Follow a block chain of one record type via next_offset, then scan."""
        seen = set()
        off = start
        while off and off + HEADER_SIZE <= self._size and off not in seen:
            if len(seen) >= MAX_CHAIN_BLOCKS:
                break
            blob = self._read_at(off, HEADER_SIZE)
            if blob[:8] != VSS_IDENTIFIER_PREFIX or _u32(blob, 20) != record_type:
                break
            seen.add(off)
            yield off
            off = _u64(blob, 40)

        limit = min(self._size, MAX_SCAN_BYTES)
        off = 0
        while off + HEADER_SIZE <= limit:
            if off not in seen:
                blob = self._read_at(off, HEADER_SIZE)
                if blob[:8] == VSS_IDENTIFIER_PREFIX and _u32(blob, 20) == record_type:
                    seen.add(off)
                    yield off
            off += BLOCK_SIZE

    def _load_catalog(self):
        if self._catalog_entries:
            return
        starts = list(self._iter_record_blocks(REC_CATALOG, self.catalog_offset))
        for block_off in starts:
            body_off = block_off + HEADER_SIZE
            room = min(BLOCK_SIZE, self._size - body_off)
            if room < CATALOG_ENTRY_SIZE:
                continue
            body = self._read_at(body_off, room)
            count = room // CATALOG_ENTRY_SIZE
            for idx in range(count):
                raw = body[idx * CATALOG_ENTRY_SIZE:(idx + 1) * CATALOG_ENTRY_SIZE]
                etype = _u64(raw, 0)
                if etype == 0 or etype == CATALOG_TYPE_UNUSED:
                    continue
                if etype > CATALOG_TYPE_STORE:
                    continue
                self._catalog_entries.append(
                    {
                        "offset": body_off + idx * CATALOG_ENTRY_SIZE,
                        "block_offset": block_off,
                        "index": idx,
                        "type": etype,
                        "raw": raw,
                    }
                )

        by_store = {}
        for entry in self._catalog_entries:
            raw = entry["raw"]
            if entry["type"] == CATALOG_TYPE_SHADOW_COPY:
                raw_ft = _u64(raw, 48)
                snap = {
                    "index": len(self._snapshots),
                    "catalog_offset": entry["offset"],
                    "snapshot_id": guid_str(raw[16:32]),
                    "creation_time": _iso(filetime_to_datetime(raw_ft)),
                    "creation_filetime": raw_ft,
                    "volume_size": _u64(raw, 8),
                    "sequence": _u64(raw, 32),
                    "flags": _u64(raw, 40),
                    # INFERRED: the document calls bytes 56..127 "unknown".
                    "volume_name": _utf16z(raw, 56, 128 - 56) or None,
                    "block_list_offset": None,
                    "store_header_offset": None,
                    "range_list_offset": None,
                    "bitmap_offset": None,
                    "ntfs_file_reference": None,
                }
                self._snapshots.append(snap)
                by_store.setdefault(snap["snapshot_id"], []).append(snap)
            elif entry["type"] == CATALOG_TYPE_STORE:
                store = {
                    "catalog_offset": entry["offset"],
                    "snapshot_id": guid_str(raw[16:32]),
                    "block_list_offset": _u64(raw, 8),
                    "store_header_offset": _u64(raw, 32),
                    "range_list_offset": _u64(raw, 40),
                    "bitmap_offset": _u64(raw, 48),
                    "ntfs_file_reference": _u64(raw, 56),
                }
                self._catalog_entries_store = store
                for snap in by_store.get(store["snapshot_id"], []):
                    snap["block_list_offset"] = store["block_list_offset"]
                    snap["store_header_offset"] = store["store_header_offset"]
                    snap["range_list_offset"] = store["range_list_offset"]
                    snap["bitmap_offset"] = store["bitmap_offset"]
                    snap["ntfs_file_reference"] = store["ntfs_file_reference"]
                if self._active_store is None:
                    self._active_store = store

        if self._active_store is None:
            for snap in self._snapshots:
                if snap["block_list_offset"] is not None:
                    self._active_store = {
                        "snapshot_id": snap["snapshot_id"],
                        "block_list_offset": snap["block_list_offset"],
                        "store_header_offset": snap["store_header_offset"],
                        "range_list_offset": snap["range_list_offset"],
                        "bitmap_offset": snap["bitmap_offset"],
                    }
                    break

        sizes = [s["volume_size"] for s in self._snapshots if s["volume_size"]]
        if sizes:
            self.volume_size = sizes[0]

    # -- offset mapping (store file vs volume image) ------------------------

    def _load_ranges(self):
        if self._loaded_ranges:
            return
        self._loaded_ranges = True
        start = 0
        if self._active_store and self._active_store.get("range_list_offset"):
            start = self._map_identity(self._active_store["range_list_offset"])
        for block_off in self._iter_record_blocks(REC_BLOCK_RANGE_LIST, start):
            body_off = block_off + HEADER_SIZE
            room = min(BLOCK_SIZE, self._size - body_off)
            if room < BLOCK_RANGE_ENTRY_SIZE:
                continue
            body = self._read_at(body_off, room)
            for idx in range(room // BLOCK_RANGE_ENTRY_SIZE):
                raw = body[idx * BLOCK_RANGE_ENTRY_SIZE:(idx + 1) * BLOCK_RANGE_ENTRY_SIZE]
                if _all_zero(raw):
                    break
                self._ranges.append(
                    {
                        "store_offset": _u64(raw, 0),
                        "relative_offset": _u64(raw, 8),
                        "size": _u64(raw, 16),
                    }
                )

    @staticmethod
    def _map_identity(offset):
        return offset

    def _map_volume_offset(self, volume_offset):
        """Map a volume-relative offset to an offset inside this image.

        INFERRED: uses the block range list (one hop) when present, otherwise
        assumes the image *is* the volume (identity mapping).
        """
        self._load_ranges()
        for entry in self._ranges:
            start = entry["store_offset"]
            size = entry["size"]
            if size and start <= volume_offset < start + size:
                return entry["relative_offset"] + (volume_offset - start)
        return volume_offset

    # -- layer 3: block descriptors / bitmap --------------------------------

    def _load_descriptors(self):
        if self._loaded_desc:
            return
        self._loaded_desc = True
        start = 0
        if self._active_store and self._active_store.get("block_list_offset"):
            start = self._map_volume_offset(self._active_store["block_list_offset"])
        for block_off in self._iter_record_blocks(REC_BLOCK_DESCRIPTOR_LIST, start):
            body_off = block_off + HEADER_SIZE
            room = min(BLOCK_SIZE, self._size - body_off)
            if room < BLOCK_DESCRIPTOR_SIZE:
                continue
            body = self._read_at(body_off, room)
            stop = False
            for idx in range(room // BLOCK_DESCRIPTOR_SIZE):
                raw = body[idx * BLOCK_DESCRIPTOR_SIZE:(idx + 1) * BLOCK_DESCRIPTOR_SIZE]
                if _all_zero(raw):
                    stop = True
                    break
                desc = {
                    "index": len(self._descriptors),
                    "original_offset": _u64(raw, 0),
                    "relative_offset": _u64(raw, 8),
                    "store_offset": _u64(raw, 16),
                    "flags": _u32(raw, 24),
                    "allocation_bitmap": _u32(raw, 28),
                    "block_index": None,
                    "kind": None,
                }
                desc["block_index"] = desc["original_offset"] // BLOCK_SIZE
                desc["kind"] = self._descriptor_kind(desc)
                self._descriptors.append(desc)
                self._desc_by_orig.setdefault(desc["original_offset"], desc)
            if stop:
                break

    @staticmethod
    def _descriptor_kind(desc):
        flags = desc["flags"]
        if flags & DESC_NOT_USED:
            return "not_used"
        if flags & DESC_FORWARDER:
            return "forwarder"
        if flags & DESC_OVERLAY:
            return "range"
        return "full"

    def _load_bitmap(self):
        if self._loaded_bitmap:
            return
        self._loaded_bitmap = True
        start = 0
        if self._active_store and self._active_store.get("bitmap_offset"):
            start = self._map_volume_offset(self._active_store["bitmap_offset"])
        chunks = []
        for block_off in self._iter_record_blocks(REC_STORE_BITMAP, start):
            body_off = block_off + HEADER_SIZE
            room = min(BLOCK_SIZE, self._size - body_off)
            if room <= 0:
                continue
            self._bitmap_offsets.append(block_off)
            chunks.append(self._read_at(body_off, room))
        self._bitmap = b"".join(chunks)

    def _bitmap_unused(self, block_index):
        """True when the store bitmap marks the block as not in use."""
        self._load_bitmap()
        if not self._bitmap:
            return None
        byte_index = block_index // 8
        if byte_index >= len(self._bitmap):
            return False
        return bool((self._bitmap[byte_index] >> (block_index % 8)) & 1)

    # -- public API ---------------------------------------------------------

    def info(self):
        """Summary of the parsed header and store layout."""
        self._load_catalog()
        self._load_descriptors()
        self._load_bitmap()
        return {
            "mode": self.mode,
            "source": self._name,
            "image_size": self._size,
            "header_offset": self.header_offset,
            "identifier": VSS_IDENTIFIER.hex(),
            "identifier_match": self.identifier_match,
            "version": self.version,
            "record_type": self.record_type,
            "record_type_name": RECORD_TYPES.get(self.record_type, "unknown"),
            "block_size": BLOCK_SIZE,
            "catalog_offset": self.catalog_offset,
            "maximum_size": self.maximum_size,
            "volume_size": self.volume_size,
            "volume_identifier": self.volume_identifier,
            "store_volume_identifier": self.store_volume_identifier,
            "catalog_entry_count": len(self._catalog_entries),
            "snapshot_count": len(self._snapshots),
            "block_descriptor_count": len(self._descriptors),
            "range_entry_count": len(self._ranges),
            "bitmap_present": bool(self._bitmap),
            "bitmap_blocks": len(self._bitmap_offsets),
            "store_identifiers": [s["snapshot_id"] for s in self._snapshots],
        }

    def snapshots(self):
        """Shadow copy summaries: creation time, id, volume name, store offsets."""
        self._load_catalog()
        return [dict(s) for s in self._snapshots]

    def block_descriptors(self):
        """Parsed 32-byte block descriptors with a derived kind."""
        self._load_catalog()
        self._load_descriptors()
        return [dict(d) for d in self._descriptors]

    def block_kind(self, index):
        """``full`` / ``range`` / ``zero`` / ``forwarder`` / ``not_used``."""
        self._load_catalog()
        self._load_descriptors()
        self._load_bitmap()
        original = index * BLOCK_SIZE
        desc = self._desc_by_orig.get(original)
        if desc is not None:
            return desc["kind"]
        if self._bitmap_unused(index):
            return "zero"
        return "volume"

    def read_block(self, index):
        """Return one 16384-byte block of the *original* volume by block index."""
        if not isinstance(index, int):
            raise TypeError("block index must be int")
        if index < 0:
            raise VssError("negative block index %d" % index)
        self._load_catalog()
        self._load_descriptors()
        self._load_bitmap()

        original = index * BLOCK_SIZE
        desc = self._desc_by_orig.get(original)
        if desc is None:
            unused = self._bitmap_unused(index)
            if unused:
                return b"\x00" * BLOCK_SIZE
            if original + BLOCK_SIZE <= self._size:
                return self._read_at(original, BLOCK_SIZE)
            raise VssError(
                "block %d (offset 0x%x) has no descriptor, is not flagged unused "
                "in the store bitmap, and lies outside this image"
                % (index, original)
            )
        return self._read_descriptor(desc, depth=0)

    def _read_descriptor(self, desc, depth):
        if depth > 8:
            raise VssError("block descriptor forwarder chain too deep")
        kind = desc["kind"]
        if kind == "not_used":
            if self._bitmap_unused(desc["block_index"]):
                return b"\x00" * BLOCK_SIZE
            raise VssError(
                "block %d is flagged not-used but allocated in the store bitmap"
                % desc["block_index"]
            )
        if kind == "forwarder":
            if desc["relative_offset"] == desc["original_offset"]:
                raise VssError(
                    "forwarder block %d points at itself" % desc["block_index"]
                )
            target = self._desc_by_orig.get(desc["relative_offset"])
            if target is None:
                raise NotImplementedError(
                    "block %d is a forwarder into the next store (relative offset "
                    "0x%x); multi-store chains are not implemented"
                    % (desc["block_index"], desc["relative_offset"])
                )
            return self._read_descriptor(target, depth + 1)

        data = self._read_stored(desc)
        if kind == "range":
            return self._apply_overlay(data, desc["allocation_bitmap"])
        return data

    def _read_stored(self, desc):
        volume_offset = desc["store_offset"]
        if volume_offset == 0:
            raise VssError(
                "block descriptor for block %d has no store data offset"
                % desc["block_index"]
            )
        image_offset = self._map_volume_offset(volume_offset)
        if image_offset + BLOCK_SIZE > self._size:
            raise VssTruncatedError(
                "block %d data at 0x%x (image 0x%x) runs past end of input"
                % (desc["block_index"], image_offset, self._size)
            )
        return self._read_at(image_offset, BLOCK_SIZE)

    @staticmethod
    def _apply_overlay(data, allocation_bitmap):
        """Zero the 512-byte units whose overlay bit is clear (polarity INFERRED)."""
        out = bytearray(data)
        for unit in range(BLOCK_SIZE // 512):
            if not (allocation_bitmap >> unit) & 1:
                start = unit * 512
                out[start:start + 512] = b"\x00" * 512
        return bytes(out)

    def read_volume(self, offset, size):
        """Read ``size`` bytes at a byte offset of the original volume."""
        if offset < 0 or size < 0:
            raise VssError("negative volume read (offset=%d size=%d)" % (offset, size))
        if size == 0:
            return b""
        if self.volume_size and offset + size > self.volume_size:
            raise VssError(
                "volume read 0x%x+0x%x exceeds volume size 0x%x"
                % (offset, size, self.volume_size)
            )
        first = offset // BLOCK_SIZE
        last = (offset + size - 1) // BLOCK_SIZE
        parts = []
        for index in range(first, last + 1):
            parts.append(self.read_block(index))
        blob = b"".join(parts)
        start = offset - first * BLOCK_SIZE
        return blob[start:start + size]

    def previous_store(self):
        """Deliberately unimplemented: previous-store fallback needs the chain."""
        raise NotImplementedError(
            "previous-store fallback is not implemented; only the current store "
            "image is parsed"
        )

    # -- misc ---------------------------------------------------------------

    def __len__(self):
        return self._size

    def __repr__(self):
        return "<Vss mode=%s version=%s snapshots=%d size=0x%x>" % (
            self.mode, self.version, len(self._snapshots), self._size
        )


# ---------------------------------------------------------------------------
# module level API
# ---------------------------------------------------------------------------


def probe(sub):
    """True when ``sub`` looks like a VSS store / volume with VSS metadata."""
    try:
        obj = Vss(sub)
    except (VssError, OSError, TypeError, ValueError, struct.error):
        return False
    try:
        return obj.mode in ("volume", "store", "catalog")
    finally:
        obj.close()


def describe(sub):
    """Human readable dump of the parsed VSS metadata."""
    with Vss(sub) as obj:
        info = obj.info()
        lines = ["VSS image: %s" % info["source"]]
        lines.append(
            "  mode=%s version=%s header@0x%x record=%s identifier=%s (%s)"
            % (
                info["mode"],
                info["version"],
                info["header_offset"],
                info["record_type_name"],
                info["identifier"],
                info["identifier_match"],
            )
        )
        lines.append(
            "  block_size=%d volume_size=0x%x maximum_size=0x%x catalog@0x%x"
            % (
                info["block_size"],
                info["volume_size"],
                info["maximum_size"],
                info["catalog_offset"],
            )
        )
        lines.append(
            "  catalog_entries=%d snapshots=%d descriptors=%d ranges=%d bitmap=%s"
            % (
                info["catalog_entry_count"],
                info["snapshot_count"],
                info["block_descriptor_count"],
                info["range_entry_count"],
                "yes" if info["bitmap_present"] else "no",
            )
        )
        for snap in obj.snapshots():
            lines.append(
                "  snapshot %d: %s  id=%s  volume=%r  size=0x%x"
                % (
                    snap["index"],
                    snap["creation_time"],
                    snap["snapshot_id"],
                    snap["volume_name"],
                    snap["volume_size"],
                )
            )
        descs = obj.block_descriptors()
        for desc in descs[:16]:
            lines.append(
                "  block %d @0x%x: kind=%-9s store=0x%x rel=0x%x flags=0x%x mask=0x%08x"
                % (
                    desc["block_index"],
                    desc["original_offset"],
                    desc["kind"],
                    desc["store_offset"],
                    desc["relative_offset"],
                    desc["flags"],
                    desc["allocation_bitmap"],
                )
            )
        if len(descs) > 16:
            lines.append("  ... %d more block descriptors" % (len(descs) - 16))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# self-test (synthetic images only; no fixture files)
# ---------------------------------------------------------------------------


def _guid_bytes(seed):
    return _uuid.UUID(int=seed).bytes_le


def _block_header(record_type, version=1, current=0, nxt=0, extra=0):
    return b"".join(
        [
            VSS_IDENTIFIER,
            _U32.pack(version),
            _U32.pack(record_type),
            _U64.pack(0),
            _U64.pack(current),
            _U64.pack(nxt),
            _U64.pack(extra),
            b"\x00" * (HEADER_SIZE - 56),
        ]
    )


def _catalog_entry_shadow(guid, volume_size, filetime, volume_name, flags=0x40):
    raw = bytearray(CATALOG_ENTRY_SIZE)
    struct.pack_into("<Q", raw, 0, CATALOG_TYPE_SHADOW_COPY)
    struct.pack_into("<Q", raw, 8, volume_size)
    raw[16:32] = guid
    struct.pack_into("<Q", raw, 32, 1)
    struct.pack_into("<Q", raw, 40, flags)
    struct.pack_into("<q", raw, 48, filetime)
    name = volume_name.encode("utf-16-le")
    raw[56:56 + len(name)] = name
    return bytes(raw)


def _catalog_entry_store(guid, block_list, bitmap, header_offset=0, range_list=0):
    raw = bytearray(CATALOG_ENTRY_SIZE)
    struct.pack_into("<Q", raw, 0, CATALOG_TYPE_STORE)
    struct.pack_into("<Q", raw, 8, block_list)
    raw[16:32] = guid
    struct.pack_into("<Q", raw, 32, header_offset)
    struct.pack_into("<Q", raw, 40, range_list)
    struct.pack_into("<Q", raw, 48, bitmap)
    struct.pack_into("<Q", raw, 56, 0)
    return bytes(raw)


def _descriptor(original, relative, store, flags, mask=0):
    return _U64.pack(original) + _U64.pack(relative) + _U64.pack(store) + \
        _U32.pack(flags) + _U32.pack(mask)


def _build_store_image():
    data_a = bytes((i * 7 + 3) & 0xFF for i in range(BLOCK_SIZE))
    data_b = bytes((i * 11 + 5) & 0xFF for i in range(BLOCK_SIZE))
    guid_a = _guid_bytes(0xA11CE)
    guid_b = _guid_bytes(0xB0B)
    size = 0x18000

    img = bytearray(b"\x00" * size)

    # block 0: store header (record type 4)
    img[0:HEADER_SIZE] = _block_header(REC_STORE_HEADER, current=0)

    # block 1: catalog block (record type 2) + 3 entries
    img[0x4000:0x4080] = _block_header(REC_CATALOG, current=0x4000)
    entries = [
        _catalog_entry_shadow(
            guid_a, 0x40000, datetime_to_filetime(_dt.datetime(2024, 5, 1, 12, 0, 0, tzinfo=_dt.timezone.utc)),
            "卷影测试",
        ),
        _catalog_entry_store(guid_a, block_list=0x8000, bitmap=0xC000),
        _catalog_entry_shadow(
            guid_b, 0x40000, datetime_to_filetime(_dt.datetime(2024, 6, 2, 3, 4, 5, tzinfo=_dt.timezone.utc)),
            "Shadow二",
        ),
    ]
    for i, entry in enumerate(entries):
        off = 0x4080 + i * CATALOG_ENTRY_SIZE
        img[off:off + CATALOG_ENTRY_SIZE] = entry

    # block 2: block descriptor list (record type 3)
    img[0x8000:0x8080] = _block_header(REC_BLOCK_DESCRIPTOR_LIST, current=0x8000)
    descs = [
        _descriptor(0x0000, 0x0000, 0x10000, 0x00, 0x00000000),      # full
        _descriptor(0x4000, 0x4000, 0x14000, DESC_OVERLAY, 0x0000FFFF),  # range
        # forwarder pointing outside this image -> NotImplementedError path
        _descriptor(0xC000, 0x70000, 0x00000, DESC_FORWARDER, 0x00000000),
    ]
    off = 0x8080
    for desc in descs:
        img[off:off + BLOCK_DESCRIPTOR_SIZE] = desc
        off += BLOCK_DESCRIPTOR_SIZE

    # block 3: store bitmap (record type 6); bit set = block not in use
    img[0xC000:0xC080] = _block_header(REC_STORE_BITMAP, current=0xC000)
    img[0xC080] = 0x04  # block index 2 -> zero-filled

    # data blocks
    img[0x10000:0x14000] = data_a
    img[0x14000:0x18000] = data_b
    return bytes(img), data_a, data_b


def _build_volume_image():
    size = 0x6000
    img = bytearray(b"\x00" * size)
    guid = _guid_bytes(0xC0FFEE)
    hdr = bytearray(HEADER_SIZE)
    hdr[0:16] = VSS_IDENTIFIER
    struct.pack_into("<I", hdr, 16, 1)
    struct.pack_into("<I", hdr, 20, REC_VOLUME_HEADER)
    struct.pack_into("<Q", hdr, 24, VOLUME_HEADER_OFFSET)
    struct.pack_into("<Q", hdr, 32, VOLUME_HEADER_OFFSET)
    struct.pack_into("<Q", hdr, 40, 0)
    struct.pack_into("<Q", hdr, 48, 0x2000)  # catalog_offset
    struct.pack_into("<Q", hdr, 56, 0)       # maximum_size
    hdr[64:80] = guid
    hdr[80:96] = guid
    img[VOLUME_HEADER_OFFSET:VOLUME_HEADER_OFFSET + HEADER_SIZE] = bytes(hdr)

    img[0x2000:0x2080] = _block_header(REC_CATALOG, current=0x2000)
    entry = _catalog_entry_shadow(
        guid, 0x20000,
        datetime_to_filetime(_dt.datetime(2023, 1, 2, 3, 4, 5, tzinfo=_dt.timezone.utc)),
        "\\\\?\\Volume{deadbeef-0000-1111-2222-333344445555}\\",
    )
    img[0x2080:0x2080 + CATALOG_ENTRY_SIZE] = entry
    return bytes(img)


def _self_test():
    checks = []
    failures = []

    def check(name, cond, detail=""):
        checks.append(name)
        if not cond:
            failures.append("%s: %s" % (name, detail))

    store, data_a, data_b = _build_store_image()

    # 1. probe() on a synthetic store hits, random data does not
    check("probe(store)", probe(store) is True)
    rnd = bytearray(0x20000)
    seed = 0x12345678
    for i in range(len(rnd)):
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        rnd[i] = (seed >> 16) & 0xFF
    check("probe(random)", probe(bytes(rnd)) is False)
    check("probe(short)", probe(b"\x00" * 8) is False)

    # 2. header fields
    obj = Vss(store)
    info = obj.info()
    check("header.version", info["version"] == 1, info["version"])
    check("header.block_size", info["block_size"] == 16384, info["block_size"])
    check("header.volume_size", info["volume_size"] == 0x40000, hex(info["volume_size"]))
    check("header.mode", info["mode"] == "store", info["mode"])
    check("header.identifier", info["identifier_match"] == "full", info["identifier_match"])

    # volume header at 0x1E00
    vol = _build_volume_image()
    vobj = Vss(vol)
    vinfo = vobj.info()
    check("volume.mode", vinfo["mode"] == "volume", vinfo["mode"])
    check("volume.header_offset", vinfo["header_offset"] == 0x1E00, hex(vinfo["header_offset"] or 0))
    check("volume.catalog_offset", vinfo["catalog_offset"] == 0x2000, hex(vinfo["catalog_offset"]))
    check("volume.version", vinfo["version"] == 1, vinfo["version"])
    check("volume.snapshot_count", vinfo["snapshot_count"] == 1, vinfo["snapshot_count"])

    # 3. catalog: two snapshots + one store entry
    snaps = obj.snapshots()
    check("catalog.count", len(snaps) == 2, len(snaps))
    check("catalog.time0", snaps[0]["creation_time"] == "2024-05-01T12:00:00Z", snaps[0]["creation_time"])
    check("catalog.time1", snaps[1]["creation_time"] == "2024-06-02T03:04:05Z", snaps[1]["creation_time"])
    check("catalog.name0", snaps[0]["volume_name"] == "卷影测试", repr(snaps[0]["volume_name"]))
    check("catalog.name1", snaps[1]["volume_name"] == "Shadow二", repr(snaps[1]["volume_name"]))
    check(
        "catalog.snapshot_id",
        snaps[0]["snapshot_id"] == "{%s}" % _uuid.UUID(int=0xA11CE),
        snaps[0]["snapshot_id"],
    )
    check("catalog.linked_store", snaps[0]["block_list_offset"] == 0x8000, snaps[0]["block_list_offset"])
    check("catalog.entry_count", info["catalog_entry_count"] == 3, info["catalog_entry_count"])

    # 4. block descriptors and the three read kinds
    descs = obj.block_descriptors()
    check("desc.count", len(descs) == 3, len(descs))
    check("desc.kind_full", descs[0]["kind"] == "full", descs[0]["kind"])
    check("desc.kind_range", descs[1]["kind"] == "range", descs[1]["kind"])
    check("desc.kind_forwarder", descs[2]["kind"] == "forwarder", descs[2]["kind"])

    full = obj.read_block(0)
    check("read.full", full == data_a, "%d bytes" % len(full))

    ranged = obj.read_block(1)
    check("read.range.len", len(ranged) == BLOCK_SIZE, len(ranged))
    check("read.range.head", ranged[:0x2000] == data_b[:0x2000])
    check("read.range.tail_zero", ranged[0x2000:] == b"\x00" * 0x2000)

    zeroed = obj.read_block(2)
    check("read.zero", zeroed == b"\x00" * BLOCK_SIZE, "%d bytes" % len(zeroed))
    check("kind.zero", obj.block_kind(2) == "zero", obj.block_kind(2))

    volume_read = obj.read_volume(0x1000, 0x5000)
    check("read_volume.len", len(volume_read) == 0x5000, len(volume_read))
    check(
        "read_volume.cross_block",
        volume_read == data_a[0x1000:BLOCK_SIZE] + data_b[:0x2000],
    )

    # 5. truncated input raises a clear error
    try:
        Vss(store[:64])
        check("truncate.tiny", False, "no exception")
    except VssTruncatedError:
        check("truncate.tiny", True)
    try:
        Vss(vol[:VOLUME_HEADER_OFFSET + 20])
        check("truncate.header", False, "no exception")
    except VssTruncatedError:
        check("truncate.header", True)
    try:
        Vss(b"")
        check("truncate.empty", False, "no exception")
    except VssError:
        check("truncate.empty", True)
    try:
        Vss(store[:0x9000]).read_block(0)
        check("truncate.data", False, "no exception")
    except VssTruncatedError:
        check("truncate.data", True)

    # 6. unimplemented paths raise NotImplementedError
    try:
        obj.read_block(3)
        check("unimpl.forwarder", False, "no exception")
    except NotImplementedError:
        check("unimpl.forwarder", True)
    try:
        obj.previous_store()
        check("unimpl.previous_store", False, "no exception")
    except NotImplementedError:
        check("unimpl.previous_store", True)

    obj.close()
    vobj.close()

    text = describe(store)
    check("describe.text", "snapshot 0:" in text and "block 1 @0x4000" in text, text[:60])

    if failures:
        print("[self-test] FAILED %d of %d" % (len(failures), len(checks)))
        for item in failures:
            print("  - %s" % item)
        raise SystemExit(1)
    print("[self-test] OK %d/%d checks" % (len(checks), len(checks)))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
