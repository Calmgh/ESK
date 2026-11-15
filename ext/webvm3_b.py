# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""webvm3_b.py —— 直读单文件 monolithicSparse VMDK（不走 read_file 全读）

修正前序 bug：ans_c02vm2.VmdkDev.__init__ 对 Tronic.vmdk(11 GB) 调 fs.read_file()
会把整盘读进内存 → MemoryError / 卡死。这里只用 fs.read_runs 局部读。
"""
import collections
import io
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")

import ans_c02vm2 as D          # noqa: E402
import mkit.ntfs as M           # noqa: E402

SECTOR = 512
KDMV = b"KDMV"
VM = "/Users/C79594/Documents/Virtual Machines/Tronic"

fs = D.ntfs()


class Dev1:
    """单文件 monolithicSparse VMDK → 字节精确只读设备"""

    def __init__(self, path):
        self.path = path
        ent = fs.lookup(path)
        if ent is None:
            raise RuntimeError("找不到 %s" % path)
        self.file_size = ent.size
        runs = []
        for a in fs._stream_attrs(ent, M.ATTR_DATA, None):
            runs.extend(a.runs)
        runs.sort(key=lambda r: r[0])
        self.runs = runs
        hdr = fs.read_runs(runs, 0, 512)
        if hdr[:4] != KDMV:
            raise RuntimeError("KDMV 魔数不符: %r" % hdr[:8])
        (self.version, self.flags, self.capacity, self.grain_size,
         self.desc_off, self.desc_size, self.num_gtes) = struct.unpack_from("<IIQQQQI", hdr, 4)
        self.rgd_off, self.gd_off, self.overhead = struct.unpack_from("<QQQ", hdr, 48)
        self.grain_bytes = self.grain_size * SECTOR
        self.size = self.capacity * SECTOR
        self._gd = None
        self._cache = collections.OrderedDict()

    def _raw(self, off, size):
        if off >= self.file_size:
            return b""
        return fs.read_runs(self.runs, off, min(size, self.file_size - off))

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
        if len(self._cache) > 4096:
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


print("=== 打开 base ===", flush=True)
base = Dev1(VM + "/Tronic.vmdk")
print("  文件 %s B  虚拟容量 %.2f GiB (%d 扇区)" % (
    format(base.file_size, ","), base.size / 2 ** 30, base.capacity))
print("  grain=%d 扇区=%d B  numGTEs=%d  gdOffset=%d  overhead=%d" % (
    base.grain_size, base.grain_bytes, base.num_gtes, base.gd_off, base.overhead))
print("  descriptor: off=%d 扇区 size=%d 扇区" % (base.desc_off, base.desc_size))
desc = base._raw(base.desc_off * SECTOR, base.desc_size * SECTOR).decode("utf-8", "ignore")
print("  ---- 描述符 ----")
for line in desc.splitlines()[:18]:
    print("   ", line)

print("\n=== MBR ===", flush=True)
mbr = base.read(0, 512)
print("  sig=%02x%02x" % (mbr[510], mbr[511]))
for i in range(4):
    e = mbr[446 + i * 16: 446 + (i + 1) * 16]
    if not any(e):
        continue
    lba, cnt = struct.unpack_from("<II", e, 8)
    print("  part%d type=0x%02x start_lba=%-12d sectors=%-12d" % (i, e[4], lba, cnt))

print("\n=== GPT ===", flush=True)
gpt = base.read(512, 128 * 128)


def guid(b):
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return "%08X-%04X-%04X-%s-%s" % (d1, d2, d3, b[8:10].hex().upper(), b[10:16].hex().upper())


parts = []
for i in range(128):
    e = gpt[i * 128:(i + 1) * 128]
    if not any(e):
        continue
    first, last = struct.unpack_from("<QQ", e, 32)
    if first == 0:
        continue
    nm = e[56:128].decode("utf-16-le", "ignore").rstrip("\x00")
    parts.append((i, guid(e[0:16]), first, last, nm))
    print("  part%d type=%s" % (i, parts[-1][1]))
    print("        first_lba=%-12d sectors=%-12d (%d bytes) name=%r" % (
        first, last - first + 1, (last - first + 1) * SECTOR, nm))

LVM = "E6D6D379-F507-44C2-A23C-238F2A3DF928"
lv = [p for p in parts if p[1] == LVM]
if lv:
    i, tg, first, last, nm = lv[0]
    print("\n>>> LVM 分区 part%d  起始字节 %d  (%d 字节)" % (
        i, first * SECTOR, (last - first + 1) * SECTOR))
    open("out/_webvm3_part.txt", "w").write("%d %d\n" % (first * SECTOR, (last - first + 1) * SECTOR))
else:
    print("\n!! 无 LVM 分区")
