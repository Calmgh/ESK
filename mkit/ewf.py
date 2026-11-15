# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""自研 EWF(E01) 解析器 —— 纯 Python + zlib，无 libewf 依赖。

支持：EWF1 单段/多段(.E01..E99)、table/table2 索引、zlib chunk 解压、
      随机读取。索引基准(offset base)通过 chunk 落在 data section 内
      且能成功解压来现场判定，避免硬编码格式假设。
"""
import struct
import zlib

SIG = b"EVF\x09\x0d\x0a\xff\x00"


def _u32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


class Section:
    __slots__ = ("type", "offset", "size", "seg")

    def __init__(self, type_, offset, size, seg):
        self.type = type_
        self.offset = offset
        self.size = size
        self.seg = seg

    def __repr__(self):
        return f"<{self.type} seg={self.seg} off={self.offset} size={self.size}>"


class EWF:
    def __init__(self, paths):
        self.paths = list(paths)
        self._fh = [open(p, "rb") for p in self.paths]
        self.sections = []
        self.media_size = 0
        self.chunk_size = 0
        self.chunk_count = 0
        self.sectors_per_chunk = 0
        self.bytes_per_sector = 512
        self.header_text = ""
        self._index = []          # list[(seg, data_off, compressed)]
        self._cache_i = -1
        self._cache_d = b""
        self._parse()

    # ---------- 结构解析 ----------
    def _parse(self):
        for seg, fh in enumerate(self._fh):
            fh.seek(0)
            head = fh.read(8)
            if head != SIG:
                raise ValueError(f"not EWF: {self.paths[seg]}")
            fh.seek(13)
            pos = 13
            fsize = _filesize(fh)
            guard = 0
            while pos + 76 <= fsize and guard < 100000:
                guard += 1
                fh.seek(pos)
                desc = fh.read(76)
                if len(desc) < 76:
                    break
                stype = desc[:16].split(b"\x00")[0].decode("latin1")
                next_off = _u64(desc, 16)
                ssize = _u64(desc, 24)
                self.sections.append(Section(stype, pos, ssize, seg))
                if stype == "done":
                    break
                if next_off <= pos or next_off > fsize:
                    break
                pos = next_off

        for s in self.sections:
            if s.type in ("volume", "disk"):
                self._parse_volume(s)
            elif s.type in ("header", "header2"):
                self._parse_header(s)

        self._tables = [s for s in self.sections if s.type == "table"]
        self._data = [s for s in self.sections if s.type in ("sectors", "data")]
        if not self.chunk_size:
            raise ValueError("cannot determine chunk size")
        self._build_index()

    def _parse_volume(self, s):
        fh = self._fh[s.seg]
        fh.seek(s.offset + 76)
        buf = fh.read(min(s.size, 1052 - 76))
        if len(buf) < 24:
            return
        self.chunk_count = _u32(buf, 4)
        self.sectors_per_chunk = _u32(buf, 8)
        self.bytes_per_sector = _u32(buf, 12) or 512
        sector_count = _u64(buf, 16)
        self.media_size = sector_count * self.bytes_per_sector
        self.chunk_size = self.sectors_per_chunk * self.bytes_per_sector

    def _parse_header(self, s):
        fh = self._fh[s.seg]
        fh.seek(s.offset + 76)
        raw = fh.read(min(s.size, 1 << 16))
        txt = ""
        for st in (raw[:1], raw):
            if not st:
                continue
            try:
                txt = zlib.decompress(st).decode("latin1")
                break
            except Exception:
                continue
        if not txt:
            txt = raw.decode("latin1", "replace")
        self.header_text = txt
        vals = {}
        for line in txt.replace("\r", "").split("\n"):
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0].strip() and "\t".join(parts) != line[: len(parts[0])]:
                pass
            if len(parts) >= 6:
                vals[parts[0]] = parts[1:]
        if "size" in vals:
            try:
                self.media_size = int(vals["size"][2])
            except Exception:
                pass

    # ---------- chunk 索引 ----------
    def _build_index(self):
        idx = []
        datas = self._data
        for t in self._tables:            # _tables 只含 "table"（跳过 table2 副本）
            prev = [d for d in datas if d.seg == t.seg and d.offset < t.offset]
            fh = self._fh[t.seg]
            best = None
            for delta in (24, 8, 0, 16, 32, 40):      # 条目数组起点相对 section+76 的偏移
                fh.seek(t.offset + 76)
                head = fh.read(8)
                if len(head) < 8:
                    continue
                count = _u32(head, 0)
                if count == 0 or count > 1 << 24:
                    continue
                fh.seek(t.offset + 76 + delta)
                body = fh.read(count * 4)
                if len(body) < 16:
                    continue
                n = len(body) // 4
                entries = struct.unpack_from(f"<{n}I", body, 0)
                for base in ([prev[-1].offset, prev[-1].offset + 76] if prev else []) + \
                            [t.offset, t.offset + 76, t.offset + 84]:
                    score = self._score(t, entries, fh, base)
                    if best is None or score > best[0]:
                        best = (score, entries, base)
            if not best or best[0] <= 0:
                continue
            _, entries, base = best
            for e in entries:
                comp = bool(e & 0x80000000)
                off = (e & 0x7FFFFFFF) + base
                idx.append((t.seg, off, comp))
        if not idx:
            raise ValueError("no chunk index recovered")
        need = (self.media_size + self.chunk_size - 1) // self.chunk_size
        if len(idx) > need:
            idx = idx[:need]
        self._index = idx

    def _score(self, t, entries, fh, base):
        data_ranges = [(d.offset, d.offset + d.size) for d in self._data if d.seg == t.seg]
        score = 0
        for e in entries[:8]:
            off = (e & 0x7FFFFFFF) + base
            if data_ranges and not any(a <= off < b for a, b in data_ranges):
                continue
            fh.seek(off)
            blob = fh.read(self.chunk_size + 64)
            if not blob:
                continue
            if e & 0x80000000:
                try:
                    zlib.decompress(blob)
                    score += 2
                except Exception:
                    pass
            else:
                score += 1
        return score

    def _pick_base(self, t, entries, fh, prev_data=None):
        cands = []
        if prev_data is not None:
            cands += [prev_data.offset, prev_data.offset + 76]
        cands += [t.offset, t.offset + 76, t.offset + 84]
        best, best_score = None, -1
        for base in cands:
            s = self._score(t, entries, fh, base)
            if s > best_score:
                best, best_score = base, s
        return best if best_score > 0 else None

    def _pick_base(self, t, entries, fh, prev_data=None):
        cands = []
        if prev_data is not None:
            cands.append(prev_data.offset)
        cands += [t.offset, t.offset + 76, t.offset + 84, t.offset + 24, t.offset + 80]
        data_ranges = [(d.offset, d.offset + d.size) for d in self._data if d.seg == t.seg]
        best = None
        best_score = -1
        probe = list(entries[:8]) or list(entries)
        for base in cands:
            score = 0
            for e in probe:
                off = (e & 0x7FFFFFFF) + base
                if data_ranges and not any(a <= off < b for a, b in data_ranges):
                    continue
                fh.seek(off)
                blob = fh.read(self.chunk_size + 64)
                if not blob:
                    continue
                if e & 0x80000000:
                    try:
                        zlib.decompress(blob)
                        score += 1
                    except Exception:
                        pass
                else:
                    score += 1
            if score > best_score:
                best_score, best = score, base
        return best if best_score > 0 else None

    # ---------- 数据访问 ----------
    def _chunk(self, i):
        if i == self._cache_i:
            return self._cache_d
        if i >= len(self._index):
            return b""
        seg, off, comp = self._index[i]
        fh = self._fh[seg]
        fh.seek(off)
        blob = fh.read(self.chunk_size + 64)
        if comp:
            try:
                data = zlib.decompress(blob)
            except Exception:
                try:
                    data = zlib.decompressobj().decompress(blob)
                except Exception:
                    data = blob[: self.chunk_size]
        else:
            data = blob[: self.chunk_size]
        self._cache_i, self._cache_d = i, data
        return data

    def read(self, offset, size):
        if offset >= self.media_size or size <= 0:
            return b""
        size = min(size, self.media_size - offset)
        out = bytearray()
        while size > 0:
            ci = offset // self.chunk_size
            cio = offset % self.chunk_size
            cdata = self._chunk(ci)
            if not cdata:
                break
            take = min(size, len(cdata) - cio)
            if take <= 0:
                break
            out += cdata[cio: cio + take]
            offset += take
            size -= take
        return bytes(out)

    def close(self):
        for fh in self._fh:
            try:
                fh.close()
            except Exception:
                pass


def _filesize(fh):
    cur = fh.tell()
    fh.seek(0, 2)
    n = fh.tell()
    fh.seek(cur)
    return n
