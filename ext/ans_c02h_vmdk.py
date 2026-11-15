#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_c02h_vmdk.py —— 手写 VMware 拆分稀疏 VMDK（twoGbMaxExtentSparse）只读解析。

虚拟盘 = 多个 extent 线性拼接；每个 extent 是 sparse：
  512B 头 KDMV -> grainSize/numGTEsPerGT/gdOffset；GD 为 u32 扇区表，GT 为 u32 扇区表。
提供 read(offset,size)，可直接喂给 mkit.ext4.Ext4。
"""
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")

SECTOR = 512


class NtfsFile:
    """NTFS 文件按 data runs 随机读。"""

    def __init__(self, fs, path):
        self.fs = fs
        ent = fs.lookup(path, include_deleted=True)
        if ent is None:
            raise FileNotFoundError(path)
        self.ent = ent
        self.size = ent.size
        self.runs = []
        for a in fs._stream_attrs(ent, 0x80, None):
            if getattr(a, "name", None):
                continue
            self.runs.extend(a.runs)
        self.runs.sort(key=lambda r: r[0])

    def read(self, off, size):
        if size <= 0 or off < 0 or off >= self.size:
            return b""
        size = min(size, self.size - off)
        return self.fs.read_runs(self.runs, off, size)


class SparseExtent:
    """单个 2GB 稀疏 extent。"""

    def __init__(self, f):
        self.f = f
        h = f.read(0, 512)
        if h[:4] != b"KDMV":
            raise ValueError("bad KDMV magic %r" % h[:4])
        self.version = struct.unpack_from("<I", h, 4)[0]
        self.flags = struct.unpack_from("<I", h, 8)[0]
        self.capacity = struct.unpack_from("<Q", h, 12)[0]          # 扇区
        self.grain_size = struct.unpack_from("<Q", h, 20)[0] or 128  # 扇区
        self.num_gte = struct.unpack_from("<I", h, 44)[0] or 512
        self.gd_offset = struct.unpack_from("<Q", h, 56)[0]
        self.overhead = struct.unpack_from("<Q", h, 64)[0]
        self.bytes = self.capacity * SECTOR
        self.ngrains = (self.capacity + self.grain_size - 1) // self.grain_size
        self.ngt = (self.ngrains + self.num_gte - 1) // self.num_gte
        gd = f.read(self.gd_offset * SECTOR, self.ngt * 4)
        self.gd = struct.unpack_from("<%dI" % self.ngt, gd, 0) if self.ngt else ()
        self._gt = {}
        self._cache = {}

    def _gtab(self, gti):
        t = self._gt.get(gti)
        if t is None:
            off = self.gd[gti]
            n = self.num_gte
            if off == 0:
                t = (0,) * n
            else:
                raw = self.f.read(off * SECTOR, n * 4)
                if len(raw) < n * 4:
                    raw = raw + b"\x00" * (n * 4 - len(raw))
                t = struct.unpack_from("<%dI" % n, raw, 0)
            if len(self._gt) > 512:
                self._gt.clear()
            self._gt[gti] = t
        return t

    def read(self, off, size):
        if size <= 0 or off >= self.bytes:
            return b""
        size = min(size, self.bytes - off)
        gsz = self.grain_size * SECTOR
        out = bytearray()
        pos, rem = off, size
        while rem > 0:
            g = pos // gsz
            bo = pos % gsz
            n = min(gsz - bo, rem)
            out += self._grain(g)[bo:bo + n]
            pos += n
            rem -= n
        return bytes(out)

    def _grain(self, g):
        b = self._cache.get(g)
        if b is not None:
            return b
        gti, gi = divmod(g, self.num_gte)
        sec = self._gtab(gti)[gi]
        gsz = self.grain_size * SECTOR
        if sec == 0:
            b = b"\x00" * gsz
        else:
            b = self.f.read(sec * SECTOR, gsz)
            if len(b) < gsz:
                b = b + b"\x00" * (gsz - len(b))
        if len(self._cache) > 64:
            self._cache.clear()
        self._cache[g] = b
        return b


class SplitVmdk:
    def __init__(self, fs, base_path, extents):
        """extents: [(parent_dir, filename, sectors)]"""
        self.parts = []
        self.starts = []
        tot = 0
        for d, fn, sec in extents:
            p = d.rstrip("/") + "/" + fn
            e = SparseExtent(NtfsFile(fs, p))
            print("  extent %s cap=%d sectors bytes=%d grain=%d nGT=%d" %
                  (fn, e.capacity, e.bytes, e.grain_size, e.ngt), flush=True)
            self.starts.append(tot)
            self.parts.append(e)
            tot += e.bytes
        self.size = tot

    def read(self, off, size):
        if size <= 0 or off >= self.size:
            return b""
        size = min(size, self.size - off)
        out = bytearray()
        pos, rem = off, size
        while rem > 0:
            for i in range(len(self.parts) - 1, -1, -1):
                if pos >= self.starts[i]:
                    e = self.parts[i]
                    bo = pos - self.starts[i]
                    n = min(e.bytes - bo, rem)
                    out += e.read(bo, n)
                    pos += n
                    rem -= n
                    break
            else:
                n = min(size, rem)
                out += b"\x00" * n
                pos += n
                rem -= n
        return bytes(out)


DESC_DIR = "/Users/C79594/Documents/Virtual Machines/Tronic_s2"
DESC = DESC_DIR + "/Tronic_s2.vmdk"

EXTENTS = [
    (DESC_DIR, "Tronic_s2-s001.vmdk", 8323072),
    (DESC_DIR, "Tronic_s2-s002.vmdk", 8323072),
    (DESC_DIR, "Tronic_s2-s003.vmdk", 8323072),
    (DESC_DIR, "Tronic_s2-s004.vmdk", 8323072),
    (DESC_DIR, "Tronic_s2-s005.vmdk", 8323072),
    (DESC_DIR, "Tronic_s2-s006.vmdk", 327680),
]


def open_disk(fs):
    return SplitVmdk(fs, DESC, EXTENTS)
