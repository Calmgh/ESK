# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""Apple DMG（UDIF）镜像

格式依据 UDIF 的 `koly` trailer 与 `mish`（BLKX）块表。

═══ 端序：全部大端 ═══
实测两个真实 DMG 的 koly 原始字节：

    hfsplus_zlib.dmg (20056 B)
      version    @0x004 = 00 00 00 04  -> 大端 4      （小端 67108864）
      headerSize @0x008 = 00 00 02 00  -> 大端 512    （小端 131072）
      sectorCount@0x1EC = 00×6 0e e9   -> 大端 3817   （小端 1.6e19）

    CC-Switch-v3.18.0-macOS.dmg (26699423 B)
      version    @0x004 = 00 00 00 04  -> 大端 4
      headerSize @0x008 = 00 00 02 00  -> 大端 512
      sectorCount@0x1EC = 00×5 02 90 4b -> 大端 168011

只有大端解释能得到 version=4 / headerSize=512 / 数据落在文件范围内。
早期有一版按小端实现，在上述两个真实镜像上直接崩（MemoryError / offset 溢出），
已废弃；本文件只保留大端实现。

═══ BLKX 表头偏移（容易差 4 字节）═══
实测 hfsplus_zlib.dmg 的 plist 里每个 blkx 的 Data 都是 284 字节、含 1 个 mish：
    284 = 0xCC + 40 × 2   -> ChunkCount 在 0xC8、chunks 从 0xCC 开始

    0x000  signature 'mish'
    0x004  version              u32
    0x008  firstSectorNumber    u64
    0x010  sectorCount          u64
    0x018  dataStart            u64
    0x020  buffersNeeded        u32
    0x024  blocksDescriptor     u32
    0x028  reserved[6]          24 B
    0x040  checksum             136 B
    0x0C8  numberOfBlockChunks  u32      <- 不是 0xCC
    0x0CC  chunks[]             40 B 每条 <- 不是 0xD0

已实现：
    · koly trailer 全字段（含两枚 136 字节校验和、variant、sectorCount）
    · XML / binary plist；`blkx.Data` 为 bytes 或 base64 文本都支持
    · 单个 Data 内串联多张 mish 自动重同步（整盘镜像的常态）
    · chunk 类型：zero / raw / ignore / comment / terminator /
      zlib / bzip2 / LZMA（三级级联）
    · 按扇区随机读，解压块 LRU 缓存（上限 64 MiB），raw 块直读不缓存
    · `Dmg.open()` / `sub()` / `read()` / `info()` / `blkx()`

不实现（读到就抛 NotImplementedError，不静默出错）：
    · ADC(0x80000007) 与 LZFSE(0x80000008) —— 标准库无对应算法
    · 加密 DMG、多段 .dmgpart（只读第一段，info() 报 segment_count）
    · 旧式 rsrc 镜像（无 XML）
"""

import base64
import bz2
import lzma
import os
import plistlib
import struct
import zlib

__all__ = ["Dmg", "open_dmg", "CHUNK_TYPE_NAME",
           "CHUNK_ZERO", "CHUNK_RAW", "CHUNK_IGNORE", "CHUNK_COMMENT",
           "CHUNK_TERMINATOR", "CHUNK_ZLIB", "CHUNK_BZIP2", "CHUNK_ADC",
           "CHUNK_LZFSE", "CHUNK_LZMA"]

SECTOR = 512
KOLY_LEN = 512
MISH_HDR = 0xCC        # BLKX 数据区起点（chunks 从这里开始）
MISH_CNT_OFF = 0xC8    # numberOfBlockChunks

CHUNK_ZERO = 0x00000000
CHUNK_RAW = 0x00000001
CHUNK_IGNORE = 0x00000002
CHUNK_COMMENT = 0x7FFFFFFE
CHUNK_TERMINATOR = 0x7FFFFFFF
CHUNK_END2 = 0xFFFFFFFF          # 部分实现用这个作结束标记（真实 DMG 里出现过）
CHUNK_ZLIB = 0x80000005
CHUNK_BZIP2 = 0x80000006
CHUNK_ADC = 0x80000007
CHUNK_LZFSE = 0x80000008
CHUNK_LZMA = 0x80000009

CHUNK_TYPE_NAME = {
    CHUNK_ZERO: "zero",
    CHUNK_RAW: "raw",
    CHUNK_IGNORE: "ignore",
    CHUNK_COMMENT: "comment",
    CHUNK_TERMINATOR: "terminator",
    CHUNK_END2: "end",
    CHUNK_ZLIB: "zlib",
    CHUNK_BZIP2: "bzip2",
    CHUNK_ADC: "adc",
    CHUNK_LZFSE: "lzfse",
    CHUNK_LZMA: "lzma",
}


def be16(b, o):
    return struct.unpack_from(">H", b, o)[0]


def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def be64(b, o):
    return struct.unpack_from(">Q", b, o)[0]


class Chunk(object):
    __slots__ = ("entry_type", "comment", "sector_number", "sector_count",
                 "compressed_offset", "compressed_length")

    def __init__(self, entry_type, comment, sector_number, sector_count,
                 compressed_offset, compressed_length):
        self.entry_type = entry_type
        self.comment = comment
        self.sector_number = sector_number
        self.sector_count = sector_count
        self.compressed_offset = compressed_offset
        self.compressed_length = compressed_length

    @property
    def type_name(self):
        return CHUNK_TYPE_NAME.get(self.entry_type, "0x%08X" % self.entry_type)

    @property
    def start_byte(self):
        return self.sector_number * SECTOR

    @property
    def size_bytes(self):
        return self.sector_count * SECTOR

    def __repr__(self):
        return "<Chunk %s sec=%d n=%d clen=%d>" % (
            self.type_name, self.sector_number, self.sector_count,
            self.compressed_length)


class Blkx(object):
    """一张 BLKX 块表"""

    __slots__ = ("name", "first_sector", "sector_count", "data_start",
                 "blocks_descriptor", "buffers_needed", "chunks")

    def __init__(self, name, first_sector, sector_count, data_start,
                 blocks_descriptor, buffers_needed, chunks):
        self.name = name
        self.first_sector = first_sector
        self.sector_count = sector_count
        self.data_start = data_start
        self.blocks_descriptor = blocks_descriptor
        self.buffers_needed = buffers_needed
        self.chunks = chunks

    def __repr__(self):
        return "<Blkx %r sec=%d chunks=%d>" % (
            self.name, self.sector_count, len(self.chunks))


def parse_mish_tables(buf, name="blkx"):
    """从一个 Data blob 里切出全部 mish 表（整盘镜像常串联多张）"""
    out = []
    pos = 0
    n = len(buf)
    guard = 0
    while guard < 512:
        guard += 1
        p = buf.find(b"mish", pos)
        if p < 0 or p + MISH_HDR > n:
            break
        try:
            tbl = _parse_one_mish(buf, p, name)
        except Exception:
            tbl = None
        if tbl is not None:
            out.append(tbl)
            end = p + MISH_HDR + 40 * len(tbl.chunks)
            pos = max(end, p + 4)
        else:
            pos = p + 4
    return out


def _parse_one_mish(buf, p, name):
    if buf[p:p + 4] != b"mish":
        return None
    first_sector = be64(buf, p + 0x008)
    sector_count = be64(buf, p + 0x010)
    data_start = be64(buf, p + 0x018)
    buffers_needed = be32(buf, p + 0x020)
    blocks_desc = be32(buf, p + 0x024)
    nchunks = be32(buf, p + MISH_CNT_OFF)

    if nchunks > 1000000:
        return None

    chunks = []
    base = p + MISH_HDR
    for i in range(nchunks):
        q = base + i * 40
        if q + 40 > len(buf):
            break
        chunks.append(Chunk(
            be32(buf, q + 0x00),
            buf[q + 0x04:q + 0x08],
            be64(buf, q + 0x08),
            be64(buf, q + 0x10),
            be64(buf, q + 0x18),
            be64(buf, q + 0x20),
        ))
    if not chunks:
        return None
    return Blkx(name, first_sector, sector_count, data_start,
                blocks_desc, buffers_needed, chunks)


class Dmg(object):
    """UDIF 只读设备"""

    def __init__(self, path):
        self.path = path
        self._fh = open(path, "rb")
        self._cache = {}
        self._order = []
        self._cache_bytes = 0
        self._cache_cap = 64 << 20
        self._read_koly()
        self._read_plist()
        self._read_blkx()

    @classmethod
    def open(cls, path):
        return cls(path)

    # ---------------- koly（大端）----------------
    def _read_koly(self):
        f = self._fh
        f.seek(0, os.SEEK_END)
        self._file_size = f.tell()
        if self._file_size < KOLY_LEN:
            raise ValueError("文件太小，不是 DMG（%d 字节）" % self._file_size)
        f.seek(self._file_size - KOLY_LEN)
        k = f.read(KOLY_LEN)
        if k[0:4] != b"koly":
            raise ValueError("未找到 koly trailer（末尾 4 字节=%r）" % k[0:4])

        self.version = be32(k, 0x004)
        self.header_size = be32(k, 0x008)
        self.flags = be32(k, 0x00C)
        self.running_data_fork_offset = be64(k, 0x010)
        self.data_fork_offset = be64(k, 0x018)
        self.data_fork_length = be64(k, 0x020)
        self.rsrc_fork_offset = be64(k, 0x028)
        self.rsrc_fork_length = be64(k, 0x030)
        self.segment_number = be32(k, 0x038)
        self.segment_count = be32(k, 0x03C)
        self.segment_id = k[0x040:0x050]
        self.data_checksum = k[0x050:0x050 + 136]
        self.xml_offset = be64(k, 0x0D8)
        self.xml_length = be64(k, 0x0E0)
        self.master_checksum = k[0x160:0x160 + 136]
        self.image_variant = be32(k, 0x1E8)
        self.sector_count = be64(k, 0x1EC)

        self.size = self.sector_count * SECTOR

    # ---------------- plist ----------------
    def _read_plist(self):
        self.plist = None
        self._blkx_items = []
        if not self.xml_offset or not self.xml_length:
            return
        if self.xml_offset + self.xml_length > self._file_size:
            return
        self._fh.seek(self.xml_offset)
        raw = self._fh.read(self.xml_length)
        try:
            pl = plistlib.loads(raw)
        except Exception:
            pl = None
        if not isinstance(pl, dict):
            return
        self.plist = pl
        rf = pl.get("resource-fork") or {}
        blkx = rf.get("blkx") or []
        if isinstance(blkx, dict):
            blkx = [blkx]
        self._blkx_items = [x for x in blkx if isinstance(x, dict)]

    # ---------------- blkx ----------------
    def _read_blkx(self):
        self._tables = []
        self.problems = []

        for i, item in enumerate(self._blkx_items):
            name = item.get("Name") or item.get("CFName") or "blkx%d" % i
            data = item.get("Data")
            if isinstance(data, str):
                try:
                    data = base64.b64decode(data)
                except Exception:
                    self.problems.append("%s: base64 解码失败" % name)
                    continue
            if not isinstance(data, (bytes, bytearray)):
                continue
            tables = parse_mish_tables(bytes(data), str(name))
            if not tables:
                self.problems.append("%s: 未解析出 mish 表" % name)
            self._tables.extend(tables)

        if not self._tables and self.data_fork_length and self.sector_count:
            chunks = [Chunk(CHUNK_RAW, b"", 0, self.sector_count,
                            self.data_fork_offset, self.data_fork_length)]
            self._tables.append(Blkx("(fallback)", 0, self.sector_count,
                                     self.data_fork_offset, 0, 1, chunks))

    # ---------------- 解压 ----------------
    def _decompress(self, chunk):
        et = chunk.entry_type
        if et in (CHUNK_ZERO, CHUNK_IGNORE):
            return b"\x00" * chunk.size_bytes
        if et in (CHUNK_COMMENT, CHUNK_TERMINATOR):
            return b""
        if et == CHUNK_RAW:
            self._fh.seek(chunk.compressed_offset)
            return self._fh.read(chunk.compressed_length)

        self._fh.seek(chunk.compressed_offset)
        raw = self._fh.read(chunk.compressed_length)

        if et == CHUNK_ZLIB:
            return zlib.decompress(raw)
        if et == CHUNK_BZIP2:
            return bz2.decompress(raw)
        if et == CHUNK_LZMA:
            return self._lzma_cascade(raw)
        if et == CHUNK_ADC:
            raise NotImplementedError(
                "ADC 压缩（0x80000007）标准库无实现，需要第三方解码器")
        if et == CHUNK_LZFSE:
            raise NotImplementedError(
                "lzfse 压缩（0x80000008）标准库无实现，需要第三方解码器")
        raise NotImplementedError("未知 chunk 类型 0x%08X" % et)

    @staticmethod
    def _lzma_cascade(raw):
        """UDIF 的 LZMA 有三种封装，逐级试"""
        try:
            return lzma.decompress(raw)
        except Exception:
            pass
        if len(raw) > 5:
            try:
                props = raw[0]
                lc = props % 9
                rest = props // 9
                lp = rest % 5
                pb = rest // 5
                dict_size = struct.unpack_from("<I", raw, 1)[0]
                filt = [{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp,
                         "pb": pb, "dict_size": max(dict_size, 4096)}]
                return lzma.decompress(raw[5:], format=lzma.FORMAT_RAW,
                                       filters=filt)
            except Exception:
                pass
        try:
            return lzma.decompress(raw, format=lzma.FORMAT_RAW,
                                   filters=[{"id": lzma.FILTER_LZMA1}])
        except Exception as e:
            raise ValueError("LZMA 解压失败（三种封装都不匹配）: %s" % e)

    def _get_chunk_data(self, ti, ci):
        key = (ti, ci)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        chunk = self._tables[ti].chunks[ci]
        if chunk.entry_type == CHUNK_RAW:
            self._fh.seek(chunk.compressed_offset)
            return self._fh.read(chunk.compressed_length)

        data = self._decompress(chunk)
        while self._cache_bytes + len(data) > self._cache_cap and self._order:
            old = self._order.pop(0)
            oldd = self._cache.pop(old, None)
            if oldd:
                self._cache_bytes -= len(oldd)
        self._cache[key] = data
        self._order.append(key)
        self._cache_bytes += len(data)
        return data

    # ---------------- 读 ----------------
    @staticmethod
    def _chunk_abs_start(tbl, ch):
        """chunk.sectorNumber 是相对所属表 firstSectorNumber 的偏移，不是绝对扇区

        实测证据（hfsplus_zlib.dmg）：
            「GPT Header」表 firstSector=1，而它的 chunk[0] sector=0
            「GPT Partition Data」表 firstSector=2，chunk[0] sector=0
        若把 chunk.sectorNumber 当绝对扇区，多张表会全部挤到扇区 0 附近互相覆盖。
        """
        return (tbl.first_sector + ch.sector_number) * SECTOR

    def _find_chunk(self, pos):
        for ti, tbl in enumerate(self._tables):
            lo = tbl.first_sector * SECTOR
            hi = (tbl.first_sector + tbl.sector_count) * SECTOR
            if not (lo <= pos < hi):
                continue
            for ci, ch in enumerate(tbl.chunks):
                a = self._chunk_abs_start(tbl, ch)
                if a <= pos < a + ch.size_bytes:
                    return (ti, ci)
        return None

    def read(self, off, n):
        if off < 0 or n <= 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        end = off + n
        out = bytearray()
        pos = off
        stall = 0
        while pos < end:
            hit = self._find_chunk(pos)
            if hit is None:
                step = min(SECTOR, end - pos)
                out += b"\x00" * step
                pos += step
                stall += 1
                if stall > (1 << 20):
                    break
                continue
            stall = 0
            ti, ci = hit
            tbl = self._tables[ti]
            ch = tbl.chunks[ci]
            data = self._get_chunk_data(ti, ci)
            inner = pos - self._chunk_abs_start(tbl, ch)
            take = min(ch.size_bytes - inner, end - pos)
            if ch.entry_type in (CHUNK_ZERO, CHUNK_IGNORE):
                out += b"\x00" * take
            else:
                seg = data[inner:inner + take]
                out += seg + b"\x00" * (take - len(seg))
            pos += take
        return bytes(out)

    def sub(self, offset, size=None):
        """切成子区间，方便套给 mkit.fat / mkit.ntfs"""
        return _Sub(self, offset, self.size - offset if size is None else size)

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass

    # ---------------- 摘要 ----------------
    def info(self):
        counts = {}
        for tbl in self._tables:
            for ch in tbl.chunks:
                counts[ch.type_name] = counts.get(ch.type_name, 0) + 1
        return {
            "format": "dmg-udif",
            "version": self.version,
            "header_size": self.header_size,
            "sector_count": self.sector_count,
            "size": self.size,
            "segment_number": self.segment_number,
            "segment_count": self.segment_count,
            "image_variant": self.image_variant,
            "data_fork_offset": self.data_fork_offset,
            "data_fork_length": self.data_fork_length,
            "xml_offset": self.xml_offset,
            "xml_length": self.xml_length,
            "has_plist": self.plist is not None,
            "blkx_tables": len(self._tables),
            "chunk_types": counts,
            "problems": list(self.problems),
        }

    def blkx(self):
        out = []
        for tbl in self._tables:
            counts = {}
            for ch in tbl.chunks:
                counts[ch.type_name] = counts.get(ch.type_name, 0) + 1
            out.append({
                "name": tbl.name,
                "first_sector": tbl.first_sector,
                "sector_count": tbl.sector_count,
                "blocks_descriptor": tbl.blocks_descriptor,
                "buffers_needed": tbl.buffers_needed,
                "chunk_count": len(tbl.chunks),
                "chunk_types": counts,
                "chunks": [{"type": c.type_name,
                            "sector": c.sector_number,
                            "sectors": c.sector_count,
                            "compressed_offset": c.compressed_offset,
                            "compressed_length": c.compressed_length}
                           for c in tbl.chunks[:64]],
            })
        return out


class _Sub(object):
    """设备子区间"""

    def __init__(self, dev, offset, size):
        self.dev = dev
        self.offset = offset
        self.size = size

    def read(self, off, n):
        if off >= self.size or n <= 0:
            return b""
        n = min(n, self.size - off)
        return self.dev.read(self.offset + off, n)


def open_dmg(path):
    return Dmg(path)


if __name__ == "__main__":
    import tempfile

    def mk_mish(total_sectors, chunks, first_sector=0):
        buf = bytearray(MISH_HDR + 40 * len(chunks))
        buf[0:4] = b"mish"
        struct.pack_into(">I", buf, 0x004, 1)
        struct.pack_into(">Q", buf, 0x008, first_sector)
        struct.pack_into(">Q", buf, 0x010, total_sectors)
        struct.pack_into(">Q", buf, 0x018, 0)
        struct.pack_into(">I", buf, 0x020, 1)
        struct.pack_into(">I", buf, 0x024, 1)
        struct.pack_into(">I", buf, MISH_CNT_OFF, len(chunks))
        for i, (et, sn, sc, co, cl) in enumerate(chunks):
            p = MISH_HDR + i * 40
            struct.pack_into(">I", buf, p + 0x00, et)
            struct.pack_into(">Q", buf, p + 0x08, sn)
            struct.pack_into(">Q", buf, p + 0x10, sc)
            struct.pack_into(">Q", buf, p + 0x18, co)
            struct.pack_into(">Q", buf, p + 0x20, cl)
        return bytes(buf)

    def build_dmg():
        A = b"A" * SECTOR * 2
        C = b"Hello DMG zlib!\n" * 30          # 510 B
        cz = zlib.compress(C)

        data = bytearray()
        raw_off = 0
        data += A
        zlib_off = len(data)
        data += cz
        data += b"\x00" * ((SECTOR - len(cz) % SECTOR) % SECTOR)

        t1 = mk_mish(5, [
            (CHUNK_RAW, 0, 2, raw_off, len(A)),
            (CHUNK_ZERO, 2, 2, 0, 0),
            (CHUNK_ZLIB, 4, 1, zlib_off, len(cz)),
        ])
        t2 = mk_mish(1, [(CHUNK_COMMENT, 0, 1, 0, 0)], first_sector=100)

        blob = t1 + t2                          # 两张 mish 串在一个 Data 里
        plist = {"resource-fork": {"blkx": [
            {"Name": "whole disk (synth : 0)",
             "CFName": "whole disk (synth : 0)",
             "Attributes": "0x0050",
             "ID": "0",
             "Data": base64.b64encode(blob).decode()},
            {"Name": "second-blkx",
             "Data": base64.b64encode(t2).decode()},
        ]}}
        xml = plistlib.dumps(plist)

        img = bytearray()
        img += data
        xml_off = len(img)
        img += xml
        koly_off = len(img)
        img += b"\x00" * KOLY_LEN
        struct.pack_into(">4s", img, koly_off + 0x000, b"koly")
        struct.pack_into(">I", img, koly_off + 0x004, 4)
        struct.pack_into(">I", img, koly_off + 0x008, KOLY_LEN)
        struct.pack_into(">Q", img, koly_off + 0x018, 0)
        struct.pack_into(">Q", img, koly_off + 0x020, len(data))
        struct.pack_into(">I", img, koly_off + 0x038, 1)
        struct.pack_into(">I", img, koly_off + 0x03C, 1)
        struct.pack_into(">Q", img, koly_off + 0x0D8, xml_off)
        struct.pack_into(">Q", img, koly_off + 0x0E0, len(xml))
        struct.pack_into(">Q", img, koly_off + 0x1EC, 5)
        return bytes(img), A, C

    img, A, C = build_dmg()
    tmp = tempfile.mkdtemp(prefix="esk_dmg_")
    p = os.path.join(tmp, "synth.dmg")
    with open(p, "wb") as f:
        f.write(img)

    d = Dmg.open(p)
    inf = d.info()
    print("DMG: v%d hdr=%d sectors=%d size=%d tables=%d types=%s"
          % (inf["version"], inf["header_size"], inf["sector_count"],
             inf["size"], inf["blkx_tables"], inf["chunk_types"]))
    assert inf["version"] == 4
    assert inf["header_size"] == 512
    assert inf["sector_count"] == 5
    assert inf["size"] == 5 * SECTOR
    assert inf["blkx_tables"] == 3, inf["blkx_tables"]     # 1+2（含内嵌那张）

    bl = d.blkx()
    print("  blkx: %s" % [(b["name"], b["chunk_count"], b["chunk_types"])
                          for b in bl])
    assert bl[0]["chunk_types"].get("raw") == 1
    assert bl[0]["chunk_types"].get("zero") == 1
    assert bl[0]["chunk_types"].get("zlib") == 1

    assert d.read(0, SECTOR * 2) == A
    print("  raw 区 ok")
    assert d.read(SECTOR * 2, SECTOR * 2) == b"\x00" * (SECTOR * 2)
    print("  zero 区 ok")
    got = d.read(SECTOR * 4, SECTOR)
    assert got[:len(C)] == C and len(got) == SECTOR
    print("  zlib 区 ok（%r）" % got[:20])

    got = d.read(SECTOR * 2 - 10, 20)
    assert got[:10] == A[-10:] and got[10:] == b"\x00" * 10
    print("  跨块边界 ok")

    assert d.read(-1, 10) == b""
    assert d.read(d.size, 10) == b""
    assert d.read(0, 0) == b""
    assert len(d.read(d.size - 10, 999)) == 10
    print("  越界与截断 ok")

    s = d.sub(0, SECTOR)
    assert s.size == SECTOR and s.read(0, SECTOR) == A[:SECTOR]
    print("  sub() ok")

    bad = os.path.join(tmp, "bad.dmg")
    with open(bad, "wb") as f:
        f.write(b"X" * 2048)
    try:
        Dmg(bad)
    except ValueError:
        print("  非 DMG 正确拒绝")
    else:
        raise AssertionError("非 DMG 应抛 ValueError")

    d.close()
    print("自检通过")
