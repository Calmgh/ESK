#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_c02r_lib.py —— COM-02 只读访问层：EWF + NTFS 分区2 + 大小写不敏感查找。"""
import os
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
from mkit.image import Image, SubImage  # noqa: E402
from mkit.ntfs import NTFS  # noqa: E402

OUT = r"E:\ALL\AAAI\Works\RE\meiya\out"
E01 = r"D:\meiya\src\Com-02\Com-02\Com-02.e01"
PART2_OFF = 0x7500000

_cache = {}


def fs():
    if "fs" not in _cache:
        img = Image(E01)
        _cache["img"] = img
        _cache["fs"] = NTFS(SubImage(img, PART2_OFF, 975 * 2**30))
    return _cache["fs"]


def ls(path):
    """列目录，返回 [(name, is_dir, size, num)]"""
    f = fs()
    out = []
    for p in _variants(path):
        try:
            ents = f.ls(p)
        except Exception:
            continue
        for e in ents:
            out.append((e.name, e.is_dir, e.size, e.num))
        return out
    raise FileNotFoundError(path)


def tree(path, depth=2, _d=0):
    for nm, isdir, sz, num in ls(path):
        print("  " * _d + f"{'D' if isdir else 'f'} {nm} {sz} #{num}")
        if isdir and _d < depth and "~" not in nm:
            try:
                tree(path.rstrip("/") + "/" + nm, depth, _d + 1)
            except Exception as e:
                print("  " * (_d + 1) + f"ERR {e}")


def cat(path, ads=None):
    f = fs()
    for p in _variants(path):
        try:
            return f.read_file(p, ads=ads)
        except Exception:
            continue
    raise FileNotFoundError(path)


def _variants(path):
    yield path
    yield path.replace("/", "\\")
    yield path.replace("\\", "/")


def find(name_sub, roots=("/",), maxdepth=8, limit=60):
    """按名字子串递归查找（大小写不敏感），返回路径列表"""
    f = fs()
    name_sub = name_sub.lower()
    hits = []
    stack = [(r, 0) for r in roots]
    while stack and len(hits) < limit:
        d, depth = stack.pop()
        try:
            ents = f.ls(d)
        except Exception:
            continue
        for e in ents:
            nm = e[0] if isinstance(e, (list, tuple)) else getattr(e, "name", str(e))
            if nm in (".", "..", ""):
                continue
            sub = (d.rstrip("/\\") + "/" + nm) if d not in ("/", "\\") else "/" + nm
            isdir = e[1] if isinstance(e, (list, tuple)) and len(e) > 1 else getattr(e, "is_dir", False)
            if name_sub in nm.lower():
                hits.append(sub)
                if len(hits) >= limit:
                    break
            if isdir and depth < maxdepth:
                stack.append((sub, depth + 1))
    return hits
