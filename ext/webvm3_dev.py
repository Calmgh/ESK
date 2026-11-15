# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""webvm3_dev.py —— Web VM 单文件 monolithicSparse VMDK 只读设备层（无副作用）"""
import collections
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
import ans_c02vm2 as D      # noqa: E402
import mkit.ntfs as M       # noqa: E402

SECTOR = 512
KDMV = b"KDMV"
VM = "/Users/C79594/Documents/Virtual Machines/Tronic"

_fs = None


def ntfs():
    global _fs
    if _fs is None:
        _fs = D.ntfs()
    return _fs


class Dev1:
    """单文件 monolithicSparse VMDK → 字节精确只读设备

    关键：只用 fs.read_runs 局部读，绝不 fs.read_file 全读（Tronic.vmdk 有 11 GB）
    """

    def __init__(self, path):
        self.fs = ntfs()
        self.path = path
        ent = self.fs.lookup(path)
        if ent is None:
            raise RuntimeError("找不到 %s" % path)
        self.file_size = ent.size
        runs = []
        for a in self.fs._stream_attrs(ent, M.ATTR_DATA, None):
            runs.extend(a.runs)
        runs.sort(key=lambda r: r[0])
        self.runs = runs
        hdr = self.fs.read_runs(runs, 0, 512)
        if hdr[:4] != KDMV:
            raise RuntimeError("KDMV 魔数不符: %r" % hdr[:8])
        (self.version, self.flags, self.capacity, self.grain_size,
         self.desc_off, self.desc_size, self.num_gtes) = struct.unpack_from("<IIQQQQI", hdr, 4)
        self.rgd_off, self.gd_off, self.overhead = struct.unpack_from("<QQQ", hdr, 48)
        self.grain_bytes = self.grain_size * SECTOR
        self.size = self.capacity * SECTOR
        self._gd = None
        self._cache = collections.OrderedDict()
        self._gc = 0

    def _raw(self, off, size):
        if off >= self.file_size:
            return b""
        return self.fs.read_runs(self.runs, off, min(size, self.file_size - off))

    def _load_gd(self):
        if self._gd is not None:
            return self._gd
        n = (self.capacity // self.grain_size) // max(1, self.num_gtes) + 1
        raw = self._raw(self.gd_off * SECTOR, n * 4)
        self._gd = list(struct.unpack_from("<%dI" % (len(raw) // 4), raw, 0))
        return self._gd

    def grain_sector(self, vg):
        gd = self._load_gd()
        gi = vg // self.num_gtes
        if gi >= len(gd):
            return None
        gt_sec = gd[gi]
        if gt_sec == 0:
            return None
        gt = self._raw(gt_sec * SECTOR, self.num_gtes * 4)
        idx = vg % self.num_gtes
        if idx * 4 + 4 > len(gt):
            return None
        g = struct.unpack_from("<I", gt, idx * 4)[0]
        return g * SECTOR if g else None

    def _grain(self, vg, gstart):
        if vg in self._cache:
            self._cache.move_to_end(vg)
            return self._cache[vg]
        data = self._raw(gstart, self.grain_bytes)
        if len(data) < self.grain_bytes:
            data = data + b"\x00" * (self.grain_bytes - len(data))
        self._cache[vg] = data
        self._gc += 1
        if len(self._cache) > 6000:
            self._cache.popitem(last=False)
        return data

    def read(self, off, size):
        if off >= self.size or size <= 0:
            return b""
        size = min(size, self.size - off)
        out = bytearray()
        pos = 0
        gsz = self.grain_bytes
        while pos < size:
            v = off + pos
            vg = v // gsz
            ingrain = v % gsz
            n = min(gsz - ingrain, size - pos)
            gs = self.grain_sector(vg)
            if gs is None:
                out += b"\x00" * n
            else:
                out += self._grain(vg, gs)[ingrain:ingrain + n]
            pos += n
        return bytes(out)


class Sub:
    def __init__(self, dev, off):
        self.dev = dev
        self.off = off
        self.size = max(0, dev.size - off)

    def read(self, o, n):
        return self.dev.read(self.off + o, n)
