# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""Apple DMG（UDIF，Universal Disk Image Format）只读设备 —— 纯 Python

三层结构，全部小端：
  1. 文件末尾 512 字节 `koly` 尾块：版本、数据区偏移/长度、XML 偏移/长度、
     段号/段数、镜像变体、扇区总数、两枚 136 字节 UDIF 校验和结构。
  2. XML plist（`koly.xmlOffset` / `xmlLength`）：`resource-fork` → `blkx` 数组，
     每项含 `Attributes` / `CFName` / `Data`（plist 里通常是 <data>，
     也有实现写成 base64 文本，两种都吃）。
  3. BLKX 表（`mish`）+ 40 字节块表项：每项描述一段扇区区间的存放方式。

已实现：
  · koly 尾块全字段（含 UDIF 校验和结构）
  · XML plist（`plistlib`，XML / binary 都吃），Data 为 bytes 或 base64 文本
  · 一张 `Data` 里串联多张 `mish`（整盘镜像的常态），逐张解析并自动重同步
  · 块类型：0x00 零填充、0x01 原样、0x02 跳过（读零）、0x7FFFFFFE 注释、
    0x7FFFFFFF 结束标记、0x80000005 zlib、0x80000006 bzip2、0x80000009 LZMA
  · LZMA 三种封装级联：xz/.lzma 容器 → 裸 LZMA1（5 字节属性头）→ 裸 LZMA1 默认属性
  · 设备对象：按扇区映射随机读，解压块带 LRU 缓存（上限 64 MiB）
  · 多张 blkx 表重叠时按扇区先到先得，重叠块丢弃并记入 problems

不实现：
  · 0x80000007 ADC（Apple Data Compression）—— 标准库没有，读到时抛 NotImplementedError
  · 0x80000008 LZFSE —— 同上，标准库没有
  · 加密 DMG（带加密资源叉的 AES-128/256 镜像）
  · 多段镜像（`.002.dmgpart` 等）：只读第一段，info() 报 segment_count 供上层判断
  · 旧式 resource-fork（rsrc）镜像：没有 XML 时直接报错
  · 写回；卷内文件系统解析交给 mkit.hfs / mkit.apfs（ext/apfs_fs.py）

koly 尾块字段（512 字节，小端）：
    0x000 'koly'   0x004 version   0x008 headerSize  0x00C flags
    0x010 runningDataForkOffset(u64)  0x018 dataForkOffset(u64)
    0x020 dataForkLength(u64)         0x028 rsrcForkOffset(u64)
    0x030 rsrcForkLength(u64)         0x038 segmentNumber(u32)
    0x03C segmentCount(u32)           0x040 segmentID[16]
    0x050 dataChecksum[136]           0x0D8 xmlOffset(u64)
    0x0E0 xmlLength(u64)              0x0E8 reserved[120]
    0x160 masterChecksum[136]         0x1E8 imageVariant(u32)
    0x1EC sectorCount(u64)            0x1F4 reserved2[3]

BLKX（'mish'）：
    0x000 'mish'  0x004 version  0x008 firstSectorNumber(u64)
    0x010 sectorCount(u64)  0x018 dataStart(u64)  0x020 decompressedBufferRequested(u64)
    0x028 blocksDescriptor(u32)  0x02C reserved[6]  0x044 checksum[136]
    0x0CC numberOfBlockChunks(u32)  0x0D0 chunks[]
每项 40 字节：entryType(u32) comment(4B) sectorNumber(u64) sectorCount(u64)
              compressedOffset(u64) compressedLength(u64)
"""

import base64
import bz2
import lzma
import plistlib
import struct
import zlib
from bisect import bisect_right

__all__ = [
    "Dmg", "open_dmg",
    "KOLY_SIZE", "SECTOR_SIZE",
    "RUN_ZERO", "RUN_RAW", "RUN_IGNORE", "RUN_COMMENT", "RUN_TERMINATOR",
    "RUN_ZLIB", "RUN_BZIP2", "RUN_ADC", "RUN_LZFSE", "RUN_LZMA",
    "RUN_NAMES", "run_name",
]

KOLY_SIZE = 512
SECTOR_SIZE = 512
KOLY_MAGIC = b"koly"
MISH_MAGIC = b"mish"

# 块类型
RUN_ZERO = 0x00000000
RUN_RAW = 0x00000001
RUN_IGNORE = 0x00000002
RUN_COMMENT = 0x7FFFFFFE
RUN_TERMINATOR = 0x7FFFFFFF
RUN_ZLIB = 0x80000005
RUN_BZIP2 = 0x80000006
RUN_ADC = 0x80000007
RUN_LZFSE = 0x80000008
RUN_LZMA = 0x80000009

RUN_NAMES = {
    RUN_ZERO: "zero",
    RUN_RAW: "raw",
    RUN_IGNORE: "ignore",
    RUN_COMMENT: "comment",
    RUN_TERMINATOR: "terminator",
    RUN_ZLIB: "zlib",
    RUN_BZIP2: "bzip2",
    RUN_ADC: "adc",
    RUN_LZFSE: "lzfse",
    RUN_LZMA: "lzma",
}

# 不产生数据（读零）的类型
_NO_DATA = (RUN_ZERO, RUN_IGNORE, RUN_COMMENT, RUN_TERMINATOR)

CHECKSUM_NAMES = {
    0: "none",
    1: "CRC32",
    2: "MD5",
    3: "SHA1",
    4: "SHA256",
    5: "SHA512",
}

_CACHE_LIMIT = 64 << 20


def run_name(rtype):
    """块类型的可读名字（未知类型给十六进制）"""
    return RUN_NAMES.get(rtype, "0x%08X" % rtype)


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _checksum(b):
    """136 字节的 UDIF 校验和结构：type(u32) bits(u32) data[128]"""
    if len(b) < 136:
        b = bytes(b) + b"\x00" * (136 - len(b))
    ctype = _u32(b, 0)
    bits = _u32(b, 4)
    raw = b[8:8 + min(128, max(0, bits // 8))]
    return {
        "type": ctype,
        "type_name": CHECKSUM_NAMES.get(ctype, "0x%X" % ctype),
        "bits": bits,
        "value": raw.hex(),
    }


class Dmg(object):
    """Apple DMG（UDIF）只读设备

    用法：
        dev = Dmg.open(r"E:\\case\\image.dmg")
        dev.size                # 卷容量（sectorCount * 512）
        dev.read(0, 1 << 20)    # 任意偏移读，自动跨块解压
        dev.info()              # koly 字段 + 块类型统计
        dev.blkx()              # 每张 mish 表的摘要
    """

    def __init__(self, path):
        self.path = None
        self.problems = []
        self._fh = None
        self._own_fh = False
        self._cache = {}
        self._cache_order = []
        self._cache_bytes = 0
        self._runs = []
        self._starts = []
        self._tables = []

        if hasattr(path, "read"):
            self._fh = path
            self.path = getattr(path, "name", None)
        else:
            self.path = str(path)
            self._fh = open(self.path, "rb")
            self._own_fh = True
        try:
            self._fh.seek(0, 2)
            self.file_size = self._fh.tell()
            if self.file_size < KOLY_SIZE + 4:
                raise ValueError("DMG: 文件太短，放不下 koly 尾块")
            self._read_koly()
            self._read_tables()
            self._build_runs()
        except Exception:
            self.close()
            raise

    # ---------- 打开 / 关闭 ----------
    @classmethod
    def open(cls, path):
        return cls(path)

    def close(self):
        if self._fh is not None and self._own_fh:
            try:
                self._fh.close()
            except Exception:
                pass
        if self._own_fh:
            self._fh = None

    def _read(self, off, n):
        if n <= 0:
            return b""
        self._fh.seek(off)
        return self._fh.read(n)

    # ---------- koly ----------
    def _read_koly(self):
        self.koly_offset = self.file_size - KOLY_SIZE
        raw = self._read(self.koly_offset, KOLY_SIZE)
        if len(raw) < KOLY_SIZE:
            raise ValueError("DMG: 读不到 512 字节 koly 尾块")
        if raw[0:4] != KOLY_MAGIC:
            raise ValueError("DMG: 尾块签名不是 koly（%r）" % raw[0:4])
        self.version = _u32(raw, 0x004)
        self.header_size = _u32(raw, 0x008)
        self.flags = _u32(raw, 0x00C)
        self.running_data_fork_offset = _u64(raw, 0x010)
        self.data_fork_offset = _u64(raw, 0x018)
        self.data_fork_length = _u64(raw, 0x020)
        self.rsrc_fork_offset = _u64(raw, 0x028)
        self.rsrc_fork_length = _u64(raw, 0x030)
        self.segment_number = _u32(raw, 0x038)
        self.segment_count = _u32(raw, 0x03C)
        self.segment_id = raw[0x040:0x050].hex()
        self.data_checksum = _checksum(raw[0x050:0x0D8])
        self.xml_offset = _u64(raw, 0x0D8)
        self.xml_length = _u64(raw, 0x0E0)
        self.master_checksum = _checksum(raw[0x160:0x1E8])
        self.variant = _u32(raw, 0x1E8)
        self.sector_count = _u64(raw, 0x1EC)
        self.size = self.sector_count * SECTOR_SIZE
        if self.segment_count > 1:
            self.problems.append("多段镜像，只读了第 %d/%d 段"
                                 % (self.segment_number, self.segment_count))
        if not self.xml_offset or not self.xml_length:
            raise ValueError("DMG: koly 里没有 XML plist（旧式 rsrc 镜像未支持）")

    # ---------- XML / BLKX ----------
    def _read_tables(self):
        blob = self._read(self.xml_offset, self.xml_length)
        if not blob:
            raise ValueError("DMG: XML 区为空")
        end = blob.rfind(b"</plist>")
        if end != -1:
            blob = blob[:end + len(b"</plist>")]
        try:
            plist = plistlib.loads(blob)
        except Exception as exc:
            raise ValueError("DMG: XML plist 解析失败：%s" % exc)
        entries = self._find_blkx(plist)
        if not entries:
            raise ValueError("DMG: plist 里没有 resource-fork/blkx")
        for index, entry in enumerate(entries):
            name = entry.get("CFName") or entry.get("Name") or ""
            attrs = entry.get("Attributes")
            attrs = "" if attrs is None else str(attrs)
            data = entry.get("Data")
            if data is None:
                self.problems.append("blkx[%d] 没有 Data" % index)
                continue
            if isinstance(data, str):
                try:
                    data = base64.b64decode("".join(data.split()), validate=False)
                except Exception as exc:
                    self.problems.append("blkx[%d] Data base64 解码失败：%s" % (index, exc))
                    continue
            elif not isinstance(data, (bytes, bytearray)):
                self.problems.append("blkx[%d] Data 类型异常：%s"
                                     % (index, type(data).__name__))
                continue
            try:
                self._parse_blob(bytes(data), index, str(name), attrs)
            except Exception as exc:
                self.problems.append("blkx[%d]（%s）解析失败：%s" % (index, name, exc))

    @staticmethod
    def _find_blkx(plist):
        """找 blkx 数组：resource-fork → blkx，也兼容顶层直挂"""
        if not isinstance(plist, dict):
            return []
        fork = plist.get("resource-fork")
        if isinstance(fork, dict) and isinstance(fork.get("blkx"), list):
            return fork["blkx"]
        if isinstance(plist.get("blkx"), list):
            return plist["blkx"]
        return []

    def _parse_blob(self, blob, index, name, attrs):
        """一张 Data 里可能串联多张 mish；逐张解析并向前重同步"""
        off = 0
        first = True
        while off + 0xD0 <= len(blob):
            if blob[off:off + 4] != MISH_MAGIC:
                nxt = blob.find(MISH_MAGIC, off)
                if nxt < 0:
                    break
                if first:
                    self.problems.append("blkx[%d] 起始不是 mish，跳到 0x%X" % (index, nxt))
                off = nxt
            table, off = self._parse_mish(blob, off, index, name, attrs)
            table["first_in_entry"] = first
            first = False
            self._tables.append(table)

    def _parse_mish(self, blob, off, index, name, attrs):
        if off + 0xD0 > len(blob):
            raise ValueError("mish 头被截断")
        version = _u32(blob, off + 0x004)
        first_sector = _u64(blob, off + 0x008)
        sectors = _u64(blob, off + 0x010)
        data_start = _u64(blob, off + 0x018)
        buffers = _u64(blob, off + 0x020)
        descriptor = _u32(blob, off + 0x028)
        checksum = _checksum(blob[off + 0x044:off + 0x044 + 136])
        count = _u32(blob, off + 0x0CC)
        if count > (1 << 20):
            raise ValueError("块数异常 %d" % count)
        avail = max(0, (len(blob) - off - 0xD0) // 40)
        if count > avail:
            self.problems.append("blkx[%d] 声明 %d 个块，实际只有 %d 个"
                                 % (index, count, avail))
            count = avail
        runs = []
        for i in range(count):
            p = off + 0xD0 + i * 40
            runs.append({
                "type": _u32(blob, p + 0x00),
                "comment": blob[p + 0x04:p + 0x08].hex(),
                "sector": _u64(blob, p + 0x08),
                "count": _u64(blob, p + 0x10),
                "offset": _u64(blob, p + 0x18),
                "length": _u64(blob, p + 0x20),
            })
        table = {
            "index": len(self._tables),
            "blkx_index": index,
            "name": name,
            "attributes": attrs,
            "version": version,
            "first_sector": first_sector,
            "sector_count": sectors,
            "data_start": data_start,
            "buffers_requested": buffers,
            "descriptor": descriptor,
            "checksum": checksum,
            "runs": runs,
        }
        return table, off + 0xD0 + count * 40

    # ---------- 块映射 ----------
    def _build_runs(self):
        flat = []
        for table in self._tables:
            for run in table["runs"]:
                if run["count"] <= 0:
                    continue
                rtype = run["type"]
                if rtype in (RUN_COMMENT, RUN_TERMINATOR):
                    continue
                item = {
                    "type": rtype,
                    "sector": run["sector"],
                    "count": run["count"],
                    "length": run["length"],
                    "table": table["index"],
                    "name": table["name"],
                }
                if rtype == RUN_RAW:
                    length = run["length"] or run["count"] * SECTOR_SIZE
                    item["offset"] = self._abs(run["offset"], length, table["index"])
                elif rtype in _NO_DATA:
                    item["offset"] = 0
                else:
                    item["offset"] = self._abs(run["offset"], run["length"], table["index"])
                flat.append(item)

        flat.sort(key=lambda r: (r["sector"], r["table"]))
        runs = []
        covered = 0
        dropped = 0
        for run in flat:
            if run["sector"] < covered:
                dropped += 1
                continue
            runs.append(run)
            covered = run["sector"] + run["count"]
        if dropped:
            self.problems.append("%d 个块与更早的 blkx 表重叠，按先到先得丢弃" % dropped)
        self._runs = runs
        self._starts = [r["sector"] for r in runs]

        max_end = 0
        for run in runs:
            max_end = max(max_end, (run["sector"] + run["count"]) * SECTOR_SIZE)
        if not self.size:
            self.size = max_end
        elif max_end > self.size:
            self.problems.append("块表覆盖到 %d 字节，超过 koly 的 %d 字节"
                                 % (max_end, self.size))

    def _abs(self, offset, length, table_index):
        """块偏移换算成文件偏移：UDIF 里它是相对数据区起点的"""
        absolute = self.data_fork_offset + offset
        if length and absolute + length > self.file_size:
            if offset + length <= self.file_size:
                self.problems.append("blkx[%d] 块偏移像是不含数据区基点，按绝对偏移处理"
                                     % table_index)
                return offset
        return absolute

    # ---------- 解压 ----------
    @staticmethod
    def _lzma(data, expect):
        """UDIF 的 LZMA：先试容器（xz/.lzma），再试裸 LZMA1（5 字节属性头）"""
        try:
            return lzma.decompress(data)
        except Exception:
            pass
        if len(data) > 5:
            d = data[0]
            lc = d % 9
            rest = d // 9
            lp = rest % 5
            pb = rest // 5
            dict_size = _u32(data, 1)
            if lc <= 4 and lp <= 4 and pb <= 4 and dict_size >= 4096:
                filt = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size,
                         "lc": lc, "lp": lp, "pb": pb}]
                try:
                    return lzma.decompress(data[5:], format=lzma.FORMAT_RAW, filters=filt)
                except Exception:
                    pass
        filt = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 26,
                 "lc": 3, "lp": 0, "pb": 2}]
        for payload in (data, data[5:]):
            try:
                return lzma.decompress(payload, format=lzma.FORMAT_RAW, filters=filt)
            except Exception:
                continue
        raise ValueError("LZMA 块解不开（%d 字节，期望 %d 字节）" % (len(data), expect))

    @classmethod
    def decompress_run(cls, rtype, data, expect):
        """按块类型解出数据，并裁到 expect 字节"""
        if rtype == RUN_ZLIB:
            try:
                out = zlib.decompress(data)
            except zlib.error:
                out = zlib.decompressobj().decompress(data)
        elif rtype == RUN_BZIP2:
            out = bz2.decompress(data)
        elif rtype == RUN_LZMA:
            out = cls._lzma(data, expect)
        elif rtype == RUN_ADC:
            raise NotImplementedError(
                "DMG: 块类型 0x80000007 是 ADC（Apple Data Compression），标准库无解压器")
        elif rtype == RUN_LZFSE:
            raise NotImplementedError(
                "DMG: 块类型 0x80000008 是 LZFSE，标准库无解压器")
        else:
            raise NotImplementedError("DMG: 未支持的块类型 0x%08X" % rtype)
        if expect and len(out) > expect:
            out = out[:expect]
        return out

    # ---------- 读 ----------
    def _run_bytes(self, index):
        run = self._runs[index]
        if index in self._cache:
            return self._cache[index]
        if run["type"] == RUN_RAW:
            return self._read(run["offset"], run["length"] or run["count"] * SECTOR_SIZE)
        expect = run["count"] * SECTOR_SIZE
        blob = self._read(run["offset"], run["length"])
        if not blob:
            return b""
        data = self.decompress_run(run["type"], blob, expect)
        self._cache[index] = data
        self._cache_order.append(index)
        self._cache_bytes += len(data)
        while self._cache_order and (self._cache_bytes > _CACHE_LIMIT or
                                     len(self._cache_order) > 16):
            old = self._cache_order.pop(0)
            self._cache_bytes -= len(self._cache.pop(old, b""))
        return data

    def _covering(self, sector):
        i = bisect_right(self._starts, sector) - 1
        if i < 0:
            return None
        run = self._runs[i]
        if sector < run["sector"] + run["count"]:
            return i
        return None

    def read(self, off, n):
        if off < 0 or n <= 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        out = bytearray()
        pos = off
        end = off + n
        while pos < end:
            sector = pos // SECTOR_SIZE
            index = self._covering(sector)
            if index is None:
                j = bisect_right(self._starts, sector)
                stop = self._starts[j] * SECTOR_SIZE if j < len(self._starts) else end
                take = min(end, stop) - pos
                if take <= 0:
                    take = end - pos
                out += b"\x00" * take
                pos += take
                continue
            run = self._runs[index]
            start = run["sector"] * SECTOR_SIZE
            stop = start + run["count"] * SECTOR_SIZE
            take = min(end, stop) - pos
            if run["type"] in _NO_DATA:
                out += b"\x00" * take
            else:
                data = self._run_bytes(index)
                within = pos - start
                piece = data[within:within + take]
                if len(piece) < take:
                    piece += b"\x00" * (take - len(piece))
                out += piece
            pos += take
        return bytes(out)

    def sub(self, offset, size=None):
        return _Slice(self, offset, size if size is not None else self.size - offset)

    # ---------- 元信息 ----------
    def _chunk_types(self):
        counts = {}
        for table in self._tables:
            for run in table["runs"]:
                key = run_name(run["type"])
                counts[key] = counts.get(key, 0) + 1
        return counts

    def info(self):
        types = self._chunk_types()
        compressed = any(k in ("zlib", "bzip2", "lzma", "adc", "lzfse") for k in types)
        return {
            "format": "dmg",
            "version": self.version,
            "header_size": self.header_size,
            "flags": self.flags,
            "sector_count": self.sector_count,
            "size": self.size,
            "segment_number": self.segment_number,
            "segment_count": self.segment_count,
            "segment_id": self.segment_id,
            "variant": self.variant,
            "blkx_count": len(self._tables),
            "chunk_types": types,
            "compressed": compressed,
            "data_fork_offset": self.data_fork_offset,
            "data_fork_length": self.data_fork_length,
            "xml_offset": self.xml_offset,
            "xml_length": self.xml_length,
            "data_checksum": self.data_checksum,
            "master_checksum": self.master_checksum,
            "problems": len(self.problems),
        }

    def blkx(self):
        """每张 mish 表的摘要（含块类型统计，不展开全部块）"""
        out = []
        for table in self._tables:
            types = {}
            for run in table["runs"]:
                key = run_name(run["type"])
                types[key] = types.get(key, 0) + 1
            out.append({
                "index": table["index"],
                "blkx_index": table["blkx_index"],
                "name": table["name"],
                "attributes": table["attributes"],
                "version": table["version"],
                "first_sector": table["first_sector"],
                "sector_count": table["sector_count"],
                "data_start": table["data_start"],
                "chunks": len(table["runs"]),
                "types": types,
                "checksum": table["checksum"],
            })
        return out


class _Slice(object):
    """把设备切成子区间，方便套给 mkit.hfs / ntfs 等"""

    def __init__(self, dev, offset, size):
        self.dev = dev
        self.offset = offset
        self.size = size

    def read(self, off, n):
        if off >= self.size:
            return b""
        n = min(n, self.size - off)
        return self.dev.read(self.offset + off, n)


def open_dmg(path):
    """按 koly 尾块识别并打开 DMG，非 DMG 抛 ValueError"""
    return Dmg.open(path)


# ============================================================
# 自检：构造一个 raw + zero 的合成 UDIF
# ============================================================
if __name__ == "__main__":
    import os
    import shutil
    import tempfile

    PAYLOAD = bytes(range(256)) * 4                    # 1024 字节，占 2 个扇区
    TOTAL_SECTORS = 4                                  # 2 扇区 raw + 2 扇区 zero

    def make_mish(first_sector, sector_count, runs, data_start=0):
        blob = bytearray(0xD0 + 40 * len(runs))
        blob[0:4] = MISH_MAGIC
        struct.pack_into("<I", blob, 0x004, 1)
        struct.pack_into("<Q", blob, 0x008, first_sector)
        struct.pack_into("<Q", blob, 0x010, sector_count)
        struct.pack_into("<Q", blob, 0x018, data_start)
        struct.pack_into("<Q", blob, 0x020, 1)
        struct.pack_into("<I", blob, 0x028, 1)
        struct.pack_into("<I", blob, 0x0CC, len(runs))
        for i, (rtype, sector, count, coff, clen) in enumerate(runs):
            p = 0xD0 + 40 * i
            struct.pack_into("<I", blob, p + 0x00, rtype)
            struct.pack_into("<Q", blob, p + 0x08, sector)
            struct.pack_into("<Q", blob, p + 0x10, count)
            struct.pack_into("<Q", blob, p + 0x18, coff)
            struct.pack_into("<Q", blob, p + 0x20, clen)
        return bytes(blob)

    whole = make_mish(0, TOTAL_SECTORS, [
        (RUN_RAW, 0, 2, 0, len(PAYLOAD)),
        (RUN_ZERO, 2, 2, len(PAYLOAD), 0),
    ])
    only_comment = make_mish(0, 0, [
        (RUN_COMMENT, 0, 0, 0, 0),
    ])

    # 一个 blkx 用 <data>（真实 DMG 的写法），另一个用 base64 文本
    plist = {
        "resource-fork": {
            "blkx": [
                {"Attributes": "0x0050", "CFName": "whole disk (synthetic)",
                 "Data": whole},
                {"Attributes": "0x0051", "CFName": "comment only",
                 "Data": base64.b64encode(only_comment).decode("ascii")},
            ]
        }
    }
    xml = plistlib.dumps(plist, fmt=plistlib.FMT_XML)

    def build_image():
        buf = bytearray()
        buf += PAYLOAD                       # 数据区 0..1024
        xml_off = len(buf)
        buf += xml
        koly_off = len(buf)
        k = bytearray(KOLY_SIZE)
        k[0:4] = KOLY_MAGIC
        struct.pack_into("<I", k, 0x004, 4)              # version
        struct.pack_into("<I", k, 0x008, KOLY_SIZE)      # headerSize
        struct.pack_into("<I", k, 0x00C, 1)              # flags
        struct.pack_into("<Q", k, 0x010, 0)              # runningDataForkOffset
        struct.pack_into("<Q", k, 0x018, 0)              # dataForkOffset
        struct.pack_into("<Q", k, 0x020, len(PAYLOAD))   # dataForkLength
        struct.pack_into("<I", k, 0x038, 1)              # segmentNumber
        struct.pack_into("<I", k, 0x03C, 1)              # segmentCount
        k[0x040:0x050] = bytes(range(16))
        struct.pack_into("<I", k, 0x050, 1)              # dataChecksum.type = CRC32
        struct.pack_into("<I", k, 0x054, 32)             # dataChecksum.bits
        struct.pack_into("<Q", k, 0x0D8, xml_off)
        struct.pack_into("<Q", k, 0x0E0, len(xml))
        struct.pack_into("<I", k, 0x1E8, 1)              # imageVariant
        struct.pack_into("<Q", k, 0x1EC, TOTAL_SECTORS)  # sectorCount
        buf += k
        return bytes(buf), koly_off

    tmp = tempfile.mkdtemp(prefix="esk-dmg-")
    try:
        image, koly_off = build_image()
        path = os.path.join(tmp, "synth.dmg")
        with open(path, "wb") as fh:
            fh.write(image)

        dev = Dmg.open(path)
        inf = dev.info()
        print("DMG: v%d sectors=%d size=%d blkx=%d types=%s" % (
            inf["version"], inf["sector_count"], inf["size"],
            inf["blkx_count"], inf["chunk_types"]))
        assert inf["sector_count"] == TOTAL_SECTORS, inf["sector_count"]
        assert inf["size"] == TOTAL_SECTORS * SECTOR_SIZE, inf["size"]
        assert inf["blkx_count"] == 2, inf["blkx_count"]
        assert inf["variant"] == 1 and inf["segment_count"] == 1
        assert inf["data_checksum"]["type_name"] == "CRC32"
        assert inf["chunk_types"].get("raw") == 1 and inf["chunk_types"].get("zero") == 1
        assert inf["chunk_types"].get("comment") == 1, inf["chunk_types"]

        tables = dev.blkx()
        print("blkx:", [(t["name"], t["chunks"], t["types"]) for t in tables])
        assert tables[0]["chunks"] == 2 and tables[0]["sector_count"] == TOTAL_SECTORS
        assert tables[1]["types"] == {"comment": 1}, tables[1]["types"]
        assert tables[1]["blkx_index"] == 1

        assert dev.read(0, len(PAYLOAD)) == PAYLOAD, "raw 区数据不符"
        assert dev.read(1024, 1024) == b"\x00" * 1024, "zero 区应为全零"
        assert dev.read(1024, 512) == b"\x00" * 512, "zero 区单块应为全零"
        assert dev.read(512, 1024) == PAYLOAD[512:] + b"\x00" * 512, "跨界读取不符"
        assert dev.read(0, TOTAL_SECTORS * SECTOR_SIZE) == PAYLOAD + b"\x00" * 1024
        assert dev.read(1536, 4096) == b"\x00" * 512, "尾部读应截断到 size"
        assert dev.read(dev.size, 16) == b"", "越界应返回空"
        assert dev.read(-1, 16) == b"", "负偏移应返回空"
        assert dev.sub(1024, 512).read(0, 512) == b"\x00" * 512, "切片不符"
        print("DMG 自检通过（koly / XML / mish / raw / zero / 跨界读取）")

        # 压缩类型：zlib、bzip2 走真数据；LZMA 三种封装都试；ADC / LZFSE 必须拒
        body = (b"UDIF-ZLIB-" * 200)[:2000]
        assert Dmg.decompress_run(RUN_ZLIB, zlib.compress(body), len(body)) == body
        assert Dmg.decompress_run(RUN_BZIP2, bz2.compress(body), len(body)) == body
        assert Dmg.decompress_run(RUN_LZMA, lzma.compress(body), len(body)) == body
        assert Dmg.decompress_run(
            RUN_LZMA, lzma.compress(body, format=lzma.FORMAT_ALONE), len(body)) == body
        props = bytes([(2 * 5 + 0) * 9 + 3]) + struct.pack("<I", 1 << 20)
        raw_lzma = lzma.compress(body, format=lzma.FORMAT_RAW, filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}])
        assert Dmg.decompress_run(RUN_LZMA, props + raw_lzma, len(body)) == body, "裸 LZMA1 失败"
        for bad in (RUN_ADC, RUN_LZFSE):
            try:
                Dmg.decompress_run(bad, b"\x00" * 32, 512)
            except NotImplementedError:
                pass
            else:
                raise AssertionError("块类型 0x%08X 应该抛 NotImplementedError" % bad)
        print("DMG 压缩自检通过（zlib / bzip2 / lzma 容器与裸流；ADC、LZFSE 明确拒绝）")
        dev.close()

        # 一张 Data 里串联多张 mish（整盘镜像的常态）
        probe = object.__new__(Dmg)
        probe.problems = []
        probe._tables = []
        two = (make_mish(10, 1, [(RUN_ZERO, 10, 1, 0, 0)]) +
               make_mish(20, 1, [(RUN_ZERO, 20, 1, 0, 0)]))
        probe._parse_blob(two, 99, "multi-mish", "")
        assert [t["first_sector"] for t in probe._tables] == [10, 20], \
            [t["first_sector"] for t in probe._tables]
        assert probe.problems == [], probe.problems
        print("多 mish 串联解析通过（%d 张表）" % len(probe._tables))

        # 非 DMG 必须被拒
        import io
        try:
            Dmg(io.BytesIO(b"\x00" * 4096))
        except ValueError:
            pass
        else:
            raise AssertionError("非 DMG 应抛 ValueError")
        print("非 DMG 拒绝通过")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
