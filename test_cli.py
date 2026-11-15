"""test_cli.py —— 端到端测 esk_cli：造一个 FAT16 镜像存盘，再跑 CLI 各命令"""
import io
import os
import struct
import subprocess
import sys
import tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
PY = r"C:\Users\LUCCa\AppData\Local\Programs\Python\Python311\python.exe"
sys.path.insert(0, HERE)


def build_fat16(path):
    BPS, SPC, RESERVED, NFATS = 512, 4, 1, 2
    ROOT_ENTRIES, FAT_SECTORS, total = 512, 64, 65535
    fat_off = RESERVED * BPS
    root_off = fat_off + NFATS * FAT_SECTORS * BPS
    root_sectors = (ROOT_ENTRIES * 32 + BPS - 1) // BPS
    data_off = root_off + root_sectors * BPS
    img = bytearray(total * BPS)

    bs = bytearray(512)
    bs[0:3] = b"\xeb\x3c\x90"
    bs[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", bs, 11, BPS)
    bs[13] = SPC
    struct.pack_into("<H", bs, 14, RESERVED)
    bs[16] = NFATS
    struct.pack_into("<H", bs, 17, ROOT_ENTRIES)
    struct.pack_into("<H", bs, 19, total)
    bs[21] = 0xF8
    struct.pack_into("<H", bs, 22, FAT_SECTORS)
    struct.pack_into("<I", bs, 32, 0)
    bs[38] = 0x29
    struct.pack_into("<I", bs, 39, 0x12345678)
    bs[43:54] = b"CLITEST    "
    bs[54:62] = b"FAT16   "
    bs[510:512] = b"\x55\xaa"
    img[0:512] = bs

    fat = bytearray(FAT_SECTORS * BPS)
    struct.pack_into("<H", fat, 0, 0xFFF8)
    struct.pack_into("<H", fat, 2, 0xFFFF)
    struct.pack_into("<H", fat, 4, 3)
    struct.pack_into("<H", fat, 6, 0xFFFF)
    for i in range(NFATS):
        a = fat_off + i * FAT_SECTORS * BPS
        img[a:a + len(fat)] = fat

    def dirent(n8, e3, attr, clus, size, first=0):
        e = bytearray(32)
        e[0:8] = n8.ljust(8)[:8].encode()
        e[8:11] = e3.ljust(3)[:3].encode()
        e[11] = attr
        struct.pack_into("<H", e, 26, clus)
        struct.pack_into("<I", e, 28, size)
        struct.pack_into("<H", e, 24, 0x5A21)
        struct.pack_into("<H", e, 22, 0x6000)
        if first:
            e[0] = first
        return bytes(e)

    root = bytearray(ROOT_ENTRIES * 32)
    root[0:32] = dirent("CLITEST", "", 0x08, 0, 0)
    root[32:64] = dirent("HELLO", "TXT", 0x20, 2, 3000)
    root[64:96] = dirent("DELETED", "BIN", 0x20, 4, 100, first=0xE5)
    img[root_off:root_off + len(root)] = root

    content = (b"Hello from FAT16! " * 200)[:3000]
    c2 = data_off + 0
    c3 = data_off + 1 * SPC * BPS
    img[c2:c2 + SPC * BPS] = content[:SPC * BPS]
    img[c3:c3 + (3000 - SPC * BPS)] = content[SPC * BPS:]
    with open(path, "wb") as f:
        f.write(bytes(img))
    return len(img)


def run(args, expect_ok=True):
    r = subprocess.run([PY, os.path.join(HERE, "esk_cli.py")] + args,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=300)
    ok = (r.returncode == 0)
    tag = "OK  " if ok else "FAIL"
    if expect_ok and not ok:
        print("  %s %-46s rc=%d %s" % (tag, " ".join(args)[:46], r.returncode,
                                       (r.stderr or "").strip().splitlines()[-1][:60] if r.stderr else ""))
    else:
        print("  %s %-46s rc=%d" % (tag, " ".join(args)[:46], r.returncode))
    return r


tmp = tempfile.mkdtemp(prefix="esk_cli_")
img = os.path.join(tmp, "test_fat16.bin")
size = build_fat16(img)
print("合成 FAT16: %s  %.1f MB" % (os.path.basename(img), size / 2 ** 20))
print()

print("=== CLI 端到端 ===")
r = run(["images", "open", img])
if r.returncode == 0:
    import json
    d = json.loads(r.stdout)
    print("       container=%s partitions=%d fs=%s"
          % (d["container"], d["partition_count"],
             d["partitions"][0]["filesystem"]))

r = run(["--image", img, "fs", "ls", "/"])
if r.returncode == 0:
    import json
    d = json.loads(r.stdout)
    print("       fs=%s 条目=%d  %s"
          % (d["fs"], len(d["entries"]), [e["name"] for e in d["entries"]]))

r = run(["--image", img, "fs", "find", "hello"])
if r.returncode == 0:
    import json
    d = json.loads(r.stdout)
    print("       find=hello 命中=%d  %s"
          % (d["count"], [m["path"] for m in d["matches"]]))

out_file = os.path.join(tmp, "out.txt")
r = run(["--image", img, "fs", "cat", "/HELLO.TXT", "-o", out_file])
if r.returncode == 0 and os.path.exists(out_file):
    with open(out_file, "rb") as f:
        data = f.read()
    print("       cat 写出 %d B，前 20: %r" % (len(data), data[:20]))
    assert data.startswith(b"Hello from FAT16!"), "内容不符"

r = run(["hash", img, "--algos", "md5,sha256,sm3"])
if r.returncode == 0:
    import json
    d = json.loads(r.stdout)
    print("       md5=%s..." % d["hashes"]["md5"][:16])
    print("       sm3=%s..." % d["hashes"]["sm3"][:16])

r = run(["--image", img, "search", "FAT16", "--encodings", "ascii", "--max-hits", "3"])
if r.returncode == 0:
    import json
    d = json.loads(r.stdout)
    print("       search 命中=%d 首个 offset=%s"
          % (d["count"], d["hits"][0]["offset"] if d["hits"] else "-"))

r = run(["--image", img, "luks"])
if r.returncode == 0:
    import json
    d = json.loads(r.stdout)
    print("       luks 卷=%d" % d["count"])

r = run(["schema"])
r = run(["schema", "fs ls"])

# session（JSONL）
print()
print("=== session JSONL ===")
lines = "\n".join([
    '{"cmd":"images","action":"open","image":"%s"}' % img.replace("\\", "\\\\"),
    '{"cmd":"fs","action":"ls","image":"%s","path":"/"}' % img.replace("\\", "\\\\"),
    '{"cmd":"fs","action":"find","image":"%s","pattern":"hello"}' % img.replace("\\", "\\\\"),
])
r = subprocess.run([PY, os.path.join(HERE, "esk_cli.py"), "session"],
                   input=lines, capture_output=True, text=True,
                   encoding="utf-8", errors="replace", timeout=300)
ok = 0
for line in (r.stdout or "").splitlines():
    if line.strip():
        import json
        try:
            d = json.loads(line)
            if d.get("ok"):
                ok += 1
        except Exception:
            pass
print("  session: 输入 3 行，成功 %d 行，rc=%d" % (ok, r.returncode))
if ok != 3 and r.stderr:
    print("  stderr:", r.stderr.strip().splitlines()[-1][:100])

print()
print("临时目录:", tmp)
