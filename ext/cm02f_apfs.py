#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""cm02f_apfs.py —— 基于 ext=(logical_off, len, phys_block) 的 APFS 文件读取器。"""
import io
import pickle
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
from mkit.image import Image, SubImage   # noqa: E402

IDX = pickle.load(open("out/cm02_idx.pkl", "rb"))
EXT, PART, BS = IDX["ext"], IDX["part_off"], IDX["bs"]
TREE = pickle.load(open("out/cm02s_tree.pkl", "rb"))
INODES = TREE["inodes"]

_IMG = None
_SUB = None


def _init():
    global _IMG, _SUB
    if _SUB is None:
        _IMG = Image(r"D:\meiya\src\CM-02\CM-02\CM-02.E01")
        _SUB = SubImage(_IMG, PART, _IMG.size - PART)
    return _SUB


def extents(ino):
    md = INODES.get(ino) or {}
    pid = md.get("private_id", ino)
    return EXT.get(ino) or EXT.get(pid), pid


def read_file(ino, size=None, limit=None):
    """按 ext 拼出文件内容。ext 元组 = (logical_off, length, phys_block)。"""
    e, pid = extents(ino)
    if not e:
        return None, pid
    sub = _init()
    out = bytearray()
    for lo, ln, ph in e:
        # 保证按 logical 升序
        off = ph * BS
        want = ln
        if size is not None:
            want = min(ln, max(0, size - lo))
        if want <= 0:
            continue
        try:
            out += sub.read(off, want)
        except Exception as ex:
            print("  ! read fail lo=%d ln=%d ph=%d : %s" % (lo, ln, ph, ex))
            out += b"\x00" * want
        if limit and len(out) >= limit:
            break
    return bytes(out), pid


if __name__ == "__main__":
    # 自检：Picture_9.png
    tests = [
        ("Picture_9.png", 621559, 8436393),
        ("图片_image.png", 526410, 4566125),
        ("Web Data", 328331, 157696),
        ("女生投资Tcoin赚大钱.png", 600434, 4451372),
    ]
    for name, ino, sz in tests:
        d, pid = read_file(ino, sz)
        head = d[:24].hex() if d else "None"
        print("%-26s ino=%-7d pid=%-7s got=%s  期望=%s"
              % (name, ino, pid, len(d) if d else 0, sz))
        print("   head: %s" % head)
        if d and d[:8] == b"\x89PNG\r\n\x1a\n":
            print("   → PNG ✓")
        if d and d[:16] == b"SQLite format 3\x00":
            print("   → SQLite ✓")
