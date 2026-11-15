"""selftest_new.py —— 新模块自检（构造合成镜像验证）"""
import io
import os
import struct
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

OK = 0
FAIL = 0


def check(name, cond, detail=""):
    global OK, FAIL
    if cond:
        OK += 1
        print("  OK   %-34s %s" % (name, detail))
    else:
        FAIL += 1
        print("  FAIL %-34s %s" % (name, detail))


# ============================================================
print("=" * 70)
print("1. hashcalc")
print("=" * 70)
from mkit.hashcalc import sm3, bytes_hash, file_hash, _SM3

check("SM3('abc')", sm3(b"abc") ==
      "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
check("SM3('abcd'*16)", sm3(b"abcd" * 16) ==
      "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")
check("SM3('')", sm3(b"") ==
      "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")
h = _SM3()
h.update(b"a")
h.update(b"bc")
check("SM3 增量更新 = 一次性", h.hexdigest() == sm3(b"abc"))
r = bytes_hash(b"abc", ("md5", "sha1", "sha256"))
check("MD5('abc')", r["md5"] == "900150983cd24fb0d6963f7d28e17f72")
check("SHA1('abc')", r["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d")
check("SHA256('abc')", r["sha256"] ==
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

# ============================================================
print("\n" + "=" * 70)
print("2. search")
print("=" * 70)
from mkit.search import scan, Encoding

blob = (b"\x00" * 64 + b"secret_key" + b"\x00" * 32
        + "密码".encode("utf-8") + b"\x00" * 32
        + "密码".encode("utf-16-le") + b"\x00" * 32
        + "密码".encode("gbk") + b"\x00" * 64)
rd = lambda o, n: blob[o:o + n]
check("ascii 命中", len(scan(rd, len(blob), "secret_key", ["ascii"])) == 1)
check("utf8 命中", len(scan(rd, len(blob), "密码", ["utf8"])) == 1)
check("utf16le 命中", len(scan(rd, len(blob), "密码", ["utf16le"])) == 1)
check("gbk 命中", len(scan(rd, len(blob), "密码", ["gbk"])) == 1)
check("正则命中", len(scan(rd, len(blob), r"secret_\w+", ["ascii"], is_regex=True)) == 1)
check("编码别名 utf16", len(scan(rd, len(blob), "密码", ["utf16"])) == 1)
# 分块边界：故意用小 chunk 验证 overlap 逻辑
h_small = scan(rd, len(blob), "密码", ["utf16le"], chunk=16, overlap=8)
check("分块 overlap 不漏", len(h_small) >= 1, "hits=%d" % len(h_small))

# ============================================================
print("\n" + "=" * 70)
print("3. carve")
print("=" * 70)
from mkit.carve import carve, CARVERS


def mk_png():
    raw = b"\x00\xff\x00\x00" * 4
    ihdr = struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0)
    def chunk(t, d):
        return (struct.pack(">I", len(d)) + t + d +
                struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


png = mk_png()
jpg = b"\xff\xd8\xff\xe0" + b"JFIF\x00" + b"A" * 300 + b"\xff\xd9"
# 合成一个最小 SQLite（1 页，page_size=512）
sq = bytearray(512)
sq[0:16] = b"SQLite format 3\x00"
sq[16:18] = struct.pack(">H", 512)
sq[28:32] = struct.pack(">I", 1)
sq = bytes(sq)

blob2 = b"\x00" * 512 + png + b"\x00" * 400 + jpg + b"\x00" * 300 + sq + b"\x00" * 512
got = carve(lambda o, n: blob2[o:o + n], len(blob2))
kinds = {g.kind for g in got}
check("雕刻 PNG", "png" in kinds)
check("雕刻 JPEG", "jpeg" in kinds)
check("雕刻 SQLite", "sqlite" in kinds)
check("签名表 16 种", len(CARVERS) >= 16, "%d 种" % len(CARVERS))

# ============================================================
print("\n" + "=" * 70)
print("4. fat  （构造合成 FAT16 镜像）")
print("=" * 70)


class MemSub:
    def __init__(self, data):
        self.data = data
        self.size = len(data)
    def read(self, off, n):
        return self.data[off:off + n]


def build_fat16():
    """构造一个 32MB 的 FAT16：根目录有 1 个文件 + 1 个已删除文件

    簇数须 >= 4085 才会被判为 FAT16（< 4085 是 FAT12）
    """
    BPS = 512
    SPC = 4                      # cluster = 2048
    RESERVED = 1
    NFATS = 2
    ROOT_ENTRIES = 512
    FAT_SECTORS = 64             # 16384 簇 × 2 字节 / 512 = 64 扇区
    total = 65535                # 32 MB（刚好能放进 tot16 字段）

    fat_off = RESERVED * BPS
    root_off = fat_off + NFATS * FAT_SECTORS * BPS
    root_sectors = (ROOT_ENTRIES * 32 + BPS - 1) // BPS
    data_off = root_off + root_sectors * BPS

    img = bytearray(total * BPS)

    # --- BPB ---
    bs = bytearray(512)
    bs[0:3] = b"\xeb\x3c\x90"
    bs[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", bs, 11, BPS)
    bs[13] = SPC
    struct.pack_into("<H", bs, 14, RESERVED)
    bs[16] = NFATS
    struct.pack_into("<H", bs, 17, ROOT_ENTRIES)
    struct.pack_into("<H", bs, 19, total)         # tot16
    bs[21] = 0xF8
    struct.pack_into("<H", bs, 22, FAT_SECTORS)   # fat16
    struct.pack_into("<H", bs, 24, 32)            # sectors_per_track
    struct.pack_into("<H", bs, 26, 2)             # num_heads
    struct.pack_into("<I", bs, 28, 0)             # hidden
    struct.pack_into("<I", bs, 32, 0)             # tot32 = 0（用 tot16）
    # FAT16 的 EBPB：drive@36, sig@38, vol_id@39, label@43, fstype@54
    bs[36] = 0x80
    bs[38] = 0x29
    struct.pack_into("<I", bs, 39, 0x12345678)
    bs[43:54] = b"TESTVOL    "
    bs[54:62] = b"FAT16   "
    bs[510:512] = b"\x55\xaa"
    img[0:512] = bs

    # --- FAT 表 ---
    clusters = (total - data_off // BPS) // SPC
    fat = bytearray(FAT_SECTORS * BPS)
    struct.pack_into("<H", fat, 0, 0xFFF8)
    struct.pack_into("<H", fat, 2, 0xFFFF)
    # 簇2 = 文件 A 的首簇，簇3 = 文件 A 的第二簇，簇4 = 已删除文件
    struct.pack_into("<H", fat, 4, 3)              # 2 -> 3
    struct.pack_into("<H", fat, 6, 0xFFFF)         # 3 -> EOC
    struct.pack_into("<H", fat, 8, 0xFFFF)         # 4 -> EOC（已删除，链还在）
    for i in range(NFATS):
        img[fat_off + i * FAT_SECTORS * BPS: fat_off + (i + 1) * FAT_SECTORS * BPS] = fat

    # --- 根目录 ---
    def dirent(name8, ext3, attr, cluster, size, first=0):
        e = bytearray(32)
        e[0:8] = name8.ljust(8)[:8].encode()
        e[8:11] = ext3.ljust(3)[:3].encode()
        e[11] = attr
        struct.pack_into("<H", e, 26, cluster)
        struct.pack_into("<I", e, 28, size)
        struct.pack_into("<H", e, 24, 0x5A21)      # date
        struct.pack_into("<H", e, 22, 0x6000)      # time
        if first:
            e[0] = first
        return bytes(e)

    root = bytearray(ROOT_ENTRIES * 32)
    root[0:32] = dirent("TESTVOL", "", 0x08, 0, 0)        # 卷标
    root[32:64] = dirent("HELLO", "TXT", 0x20, 2, 3000)   # 正常文件
    root[64:96] = dirent("DELETED", "BIN", 0x20, 4, 100, first=0xE5)  # 已删除
    img[root_off:root_off + len(root)] = root

    # --- 数据区 ---
    content = (b"Hello from FAT16! " * 200)[:3000]
    c2 = data_off + (2 - 2) * SPC * BPS
    c3 = data_off + (3 - 2) * SPC * BPS
    img[c2:c2 + SPC * BPS] = content[:SPC * BPS]
    img[c3:c3 + (3000 - SPC * BPS)] = content[SPC * BPS:]
    c4 = data_off + (4 - 2) * SPC * BPS
    img[c4:c4 + 100] = b"D" * 100

    return bytes(img), dict(data_off=data_off, cluster_size=SPC * BPS, clusters=clusters)


fatimg, meta = build_fat16()
from mkit.fat import Fat

fs = Fat(MemSub(fatimg))
info = fs.info()
check("识别 FAT16", info["type"] == "FAT16", info["type"])
check("卷标", info["label"] == "TESTVOL", info["label"])
check("簇大小 2048", info["cluster_size"] == 2048, str(info["cluster_size"]))
check("簇总数 > 4000", info["clusters"] > 4000, str(info["clusters"]))

allentries = fs.root_dir()
check("根目录 3 项", len(allentries) == 3, "%d 项" % len(allentries))

hello = [e for e in allentries if e.name.startswith("HELLO")]
check("找到 HELLO.TXT", len(hello) == 1)
if hello:
    data = fs.read_file(hello[0])
    check("读文件 3000 B", len(data) == 3000, "%d B" % len(data))
    check("内容正确", data.startswith(b"Hello from FAT16!"))
    check("跨簇链正确 2->3", fs.chain(hello[0].cluster) == [2, 3])
    check("修改时间已解析", hello[0].mtime is not None, str(hello[0].mtime))

dl = fs.deleted()
check("找到已删除项", len(dl) >= 1, "%d 项" % len(dl))
if dl:
    check("删除项 cluster=4", dl[0][1].cluster == 4, str(dl[0][1].cluster))

unalloc = list(fs.unallocated_ranges())
check("能枚举未分配区间", len(unalloc) > 0, "%d 段" % len(unalloc))

# ============================================================
print("\n" + "=" * 70)
print("5. vdisk  （QCOW2 / VDI）")
print("=" * 70)
import subprocess

_here = os.path.dirname(os.path.abspath(__file__))
for _mod in ("vdisk", "luks"):
    _r = subprocess.run([sys.executable, os.path.join(_here, "mkit", _mod + ".py")],
                        capture_output=True, text=True, encoding="utf-8")
    _tail = ((_r.stdout or "").strip().splitlines() or [""])[-1]
    check("%s 自检" % _mod, _r.returncode == 0, _tail or (_r.stderr or "")[:60])

# ============================================================
print("\n" + "=" * 70)
print("6. 包索引一致性")
print("=" * 70)
import mkit as _mk
_missing = []
for _m in _mk.__all__:
    try:
        __import__("mkit." + _m)
    except Exception as _e:
        _missing.append("%s(%s)" % (_m, str(_e)[:30]))
check("__all__ 全部可导入", not _missing, ", ".join(_missing) or "%d 个模块" % len(_mk.__all__))
check("版本号", _mk.__version__ == "1.3.0", _mk.__version__)
check("水印", _mk.__watermark__ == "ESK by Calmgh06", _mk.__watermark__)

# ============================================================
print("\n" + "=" * 70)
print("7. exfat / iso  （合成镜像）")
print("=" * 70)
import subprocess as _sp

_here2 = os.path.dirname(os.path.abspath(__file__))
for _m in ("iso",):
    _r = _sp.run([sys.executable, os.path.join(_here2, "mkit", _m + ".py")],
                 capture_output=True, text=True, encoding="utf-8")
    _t = ((_r.stdout or "").strip().splitlines() or [""])[-1]
    check("%s 自检" % _m, _r.returncode == 0, _t or (_r.stderr or "")[:60])


def build_exfat():
    """构造一个最小 exFAT：根目录 1 个文件 TEST.TXT（内容 12 字节）"""
    BPS = 512
    SPC = 1
    FAT_OFF = 24                 # 扇区
    FAT_LEN = 1
    HEAP_OFF = 32                # 扇区
    NCLUST = 100
    ROOT_CLUSTER = 4
    FILE_CLUSTER = 5
    total = HEAP_OFF + NCLUST * SPC      # 扇区

    img = bytearray(total * BPS)

    # --- VBR ---
    v = bytearray(512)
    v[0:3] = b"\xeb\x76\x90"
    v[3:11] = b"EXFAT   "
    struct.pack_into("<I", v, 80, FAT_OFF)
    struct.pack_into("<I", v, 84, FAT_LEN)
    struct.pack_into("<I", v, 88, HEAP_OFF)
    struct.pack_into("<I", v, 92, NCLUST)
    struct.pack_into("<I", v, 96, ROOT_CLUSTER)
    struct.pack_into("<I", v, 100, 0xCAFEBABE)
    struct.pack_into("<H", v, 104, 0x0100)      # revision 1.0
    struct.pack_into("<H", v, 106, 0)
    v[108] = 9                                  # bytes_per_sector_shift = 512
    v[109] = 0                                  # sectors_per_cluster_shift = 1
    v[110] = 1                                  # number_of_fats
    v[112] = 10                                 # percent_in_use
    v[510:512] = b"\x55\xaa"
    img[0:512] = v

    # --- FAT（簇 2..N，根目录簇与文件簇标 EOC）---
    fat = bytearray(FAT_LEN * BPS)
    struct.pack_into("<I", fat, ROOT_CLUSTER * 4, 0xFFFFFFFF)
    struct.pack_into("<I", fat, FILE_CLUSTER * 4, 0xFFFFFFFF)
    img[FAT_OFF * BPS:FAT_OFF * BPS + len(fat)] = fat

    heap = HEAP_OFF * BPS

    def coff(c):
        return heap + (c - 2) * (BPS * SPC)

    # --- 根目录簇 ---
    name = "TEST.TXT"
    d = bytearray(BPS)
    # 0x85 file entry
    d[0] = 0x85
    d[1] = 2                               # secondary count
    struct.pack_into("<H", d, 4, 0x20)     # ARCHIVE
    struct.pack_into("<H", d, 16, (45 << 9) | (6 << 5) | 15)   # mdate 2025-06-15
    struct.pack_into("<H", d, 18, (12 << 11) | (30 << 5))      # mtime 12:30
    # 0xC0 stream extension
    d[32] = 0xC0
    d[33] = 0x03                           # 分配 + NoFatChain
    d[35] = len(name)                      # name length
    struct.pack_into("<Q", d, 40, 12)      # valid data length
    struct.pack_into("<I", d, 52, FILE_CLUSTER)
    struct.pack_into("<Q", d, 56, 12)      # data length
    # 0xC1 file name
    d[64] = 0xC1
    d[66:66 + len(name) * 2] = name.encode("utf-16-le")
    img[coff(ROOT_CLUSTER):coff(ROOT_CLUSTER) + BPS] = d

    # --- 文件内容 ---
    img[coff(FILE_CLUSTER):coff(FILE_CLUSTER) + 12] = b"EXFAT-CONTNT"
    return bytes(img)


from mkit.exfat import Exfat

ex = Exfat(MemSub(build_exfat()))
ei = ex.info()
check("exFAT 卷标 / 簇大小", ei["cluster_size"] == 512 and ei["cluster_count"] == 100,
      "cluster=%d count=%d" % (ei["cluster_size"], ei["cluster_count"]))
check("exFAT serial", ei["volume_serial"] == "0xCAFEBABE", ei["volume_serial"])
ents = ex.root_dir()
check("exFAT 根目录 1 项", len(ents) == 1, "%d 项" % len(ents))
if ents:
    e = ents[0]
    check("exFAT 文件名", e.name == "TEST.TXT", e.name)
    check("exFAT 文件大小 12", e.size == 12, str(e.size))
    check("exFAT 非目录", not e.is_dir)
    data = ex.read_file(e)
    check("exFAT 读内容", data == b"EXFAT-CONTNT", repr(data))
    check("exFAT 时间戳", e.mtime is not None, str(e.mtime))

# ============================================================
print("\n" + "=" * 70)
print("结果：OK %d / FAIL %d" % (OK, FAIL))
print("=" * 70)
sys.exit(1 if FAIL else 0)
