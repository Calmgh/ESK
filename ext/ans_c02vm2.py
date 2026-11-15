# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_c02vm2.py —— VMDK→ext4 只读设备层（修正扇区内余数 bug）。
关键修复：ingrain 必须包含 v % 512，不能先 sec = v//512 再算。
"""
import collections
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
from mkit.image import Image, SubImage   # noqa: E402
from mkit.ntfs import NTFS                # noqa: E402
import mkit.ntfs as M                     # noqa: E402

E01 = r"D:\meiya\src\Com-02\Com-02\Com-02.e01"
VM_DIR = "/Users/C79594/Documents/Virtual Machines/Tronic_s2"
SECTOR = 512
KDMV = b"KDMV"

_ntfs = None


def ntfs():
    global _ntfs
    if _ntfs is None:
        img = Image(E01)
        _ntfs = NTFS(SubImage(img, 0x7500000, 975 * 2 ** 30))
    return _ntfs


class Extent:
    """拆分稀疏 VMDK 的单个 extent 文件。"""

    def __init__(self, fs, path):
        self.fs = fs
        self.path = path
        ent = fs.lookup(path)
        if ent is None:
            raise FileNotFoundError(path)
        self.size = ent.size
        runs = []
        for a in fs._stream_attrs(ent, M.ATTR_DATA, None):
            runs.extend(a.runs)
        runs.sort(key=lambda r: r[0])
        self.runs = runs
        self._cache = collections.OrderedDict()

        hdr = self._raw(0, 512)
        if hdr[:4] != KDMV:
            raise ValueError("bad KDMV magic %r in %s" % (hdr[:4], path))
        (self.version, self.flags, self.capacity, self.grain_size,
         self.desc_off, self.desc_size, self.num_gtes) = struct.unpack_from("<IIQQQQI", hdr, 4)
        self.rgd_off, self.gd_off, self.overhead = struct.unpack_from("<QQQ", hdr, 48)
        self.grain_bytes = self.grain_size * SECTOR
        self._gd = None

    def _raw(self, off, size):
        if off >= self.size or size <= 0:
            return b""
        size = min(size, self.size - off)
        return self.fs.read_runs(self.runs, off, size)

    def _load_gd(self):
        n = (self.capacity * SECTOR + self.grain_bytes - 1) // self.grain_bytes
        ngt = (n + self.num_gtes - 1) // self.num_gtes
        raw = self._raw(self.gd_off * SECTOR, ngt * 4)
        self._gd = list(struct.unpack_from("<%dI" % (len(raw) // 4), raw))

    def grain_sector(self, vg):
        """返回该虚拟 grain 在 extent 文件里的字节偏移；None 表示未分配。"""
        if self._gd is None:
            self._load_gd()
        gt_idx = vg // self.num_gtes
        gte_idx = vg % self.num_gtes
        if gt_idx >= len(self._gd):
            return None
        gt_sec = self._gd[gt_idx]
        if gt_sec == 0:
            return None
        gt = self._raw(gt_sec * SECTOR, self.num_gtes * 4)
        if (gte_idx + 1) * 4 > len(gt):
            return None
        g = struct.unpack_from("<I", gt, gte_idx * 4)[0]
        return g * SECTOR if g else None


class VmdkDev:
    def __init__(self, desc_path):
        self.fs = ntfs()
        desc = self.fs.read_file(desc_path).decode("utf-8", "ignore")
        self.desc = desc
        base = desc_path.rsplit("/", 1)[0]
        self.extents = []
        cur = 0
        for line in desc.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line[:2] not in ("RW", "RD", "NO"):
                continue
            parts = line.replace('"', " ").split()
            # RW 8323072 SPARSE "file.vmdk"
            try:
                nsec = int(parts[1])
            except Exception:
                continue
            fn = None
            for p in parts[2:]:
                if p.lower().endswith(".vmdk"):
                    fn = p
                    break
            if fn is None:
                continue
            e = Extent(self.fs, base + "/" + fn)
            self.extents.append((cur, nsec, e))
            cur += nsec
        self.sectors = cur
        self.size = cur * SECTOR

    def read(self, off, size):
        """★ 修复版：按字节精确计算，ingrain 包含 v % 512。"""
        if off >= self.size or size <= 0:
            return b""
        size = min(size, self.size - off)
        out = bytearray(size)
        pos = 0
        while pos < size:
            v = off + pos
            sec = v // SECTOR
            ent = None
            for st, ns, e in self.extents:
                if st <= sec < st + ns:
                    ent = (st, ns, e)
                    break
            if ent is None:
                n = min(SECTOR - (v % SECTOR), size - pos)
                pos += n
                continue
            st, ns, e = ent
            gsz = e.grain_bytes
            vbase = max(v, st * SECTOR)          # extent 内绝对字节起点
            local = vbase - st * SECTOR          # extent 内字节偏移
            vg = local // gsz                    # 虚拟 grain 号
            ingrain = local % gsz                # ★ grain 内字节偏移（含 v%512）
            gstart = e.grain_sector(vg)
            n = min(gsz - ingrain, size - pos)
            if gstart is None:
                pos += n
                continue
            data = self._grain_bytes(e, vg, gstart, gsz)
            out[pos:pos + n] = data[ingrain:ingrain + n]
            pos += n
        return bytes(out)

    def _grain_bytes(self, e, vg, gstart, gsz):
        key = (id(e), vg)
        hit = e._cache.get(key)
        if hit is not None:
            e._cache.move_to_end(key)
            return hit
        raw = e._raw(gstart, gsz)
        if len(raw) < gsz:
            raw = raw + b"\x00" * (gsz - len(raw))
        e._cache[key] = raw
        if len(e._cache) > 4096:
            e._cache.popitem(last=False)
        return raw


PART_OFF = 4096 * SECTOR     # 2097152


class Sub:
    def __init__(self, dev, off):
        self.dev = dev
        self.off = off
        self.size = dev.size - off

    def read(self, o, n):
        return self.dev.read(self.off + o, n)


def open_s2():
    from mkit.ext4 import Ext4
    dev = VmdkDev(VM_DIR + "/Tronic_s2.vmdk")
    fs = Ext4(Sub(dev, PART_OFF))
    return dev, fs


if __name__ == "__main__":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    dev = VmdkDev(VM_DIR + "/Tronic_s2.vmdk")
    print("extents:", len(dev.extents), " sectors:", dev.sectors,
          " size: %.2f GiB" % (dev.size / 2 ** 30))
    for st, ns, e in dev.extents:
        print("  start=%d nsec=%d gs=%d numgtes=%d gd=%d  %s" % (
            st, ns, e.grain_size, e.num_gtes, e.gd_off, e.path.rsplit("/", 1)[-1]))
    # 关键校验：非对齐读
    X = PART_OFF + 1060 * 4096
    a = dev.read(X, 512)
    b = dev.read(X + 256, 256)
    print()
    print("aligned  @0    :", a[:16].hex())
    print("+256 read       :", b[:16].hex(), " (应与 aligned[256:272] 一致)")
    print("aligned[256:272]:", a[256:272].hex())
    print("MATCH:", b[:16] == a[256:272])
