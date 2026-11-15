#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""com03_lib.py —— Com-03 公共工具（只读检材）。"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

SRC = r"D:\meiya\src\Com-03\Com-03"
OUT = os.path.join(ROOT, "out")
if not os.path.isdir(OUT):
    os.makedirs(OUT, exist_ok=True)

D0 = os.path.join(SRC, "COM03_NAS_DISK0.E01")
D1 = os.path.join(SRC, "COM03_NAS_DISK1.E01")
D2 = os.path.join(SRC, "COM03_NAS_DISK2.E01")


def text(fs, path, n=8000, enc="utf8"):
    try:
        i = fs.lookup(path)
        if i is None or i.is_dir:
            return None
        d = fs.read_data(i)
        return d[:n].decode(enc, "replace") if d else None
    except Exception:
        return None


def blob(fs, path):
    try:
        i = fs.lookup(path)
        if i is None or i.is_dir:
            return None
        return fs.read_data(i)
    except Exception:
        return None


def grep(fs, path, pat, ctx=0, enc="utf8", maxhits=200):
    """在文件内按正则搜行，返回 [(lineno, line)]。"""
    import re
    t = text(fs, path, 4 * 1024 * 1024, enc)
    if not t:
        return []
    rx = re.compile(pat, re.I)
    out = []
    for i, line in enumerate(t.splitlines(), 1):
        if rx.search(line):
            out.append((i, line[:400]))
            if len(out) >= maxhits:
                break
    return out


def walk_all(fs, root="/", maxnodes=400000):
    """返回 [(path, inode)]，path 用 / 连接。"""
    out = []
    seen_dirs = set()
    stack = [(root, fs.lookup(root))]
    while stack:
        path, d = stack.pop()
        if d is None or d.num in seen_dirs:
            continue
        seen_dirs.add(d.num)
        try:
            ents = fs.listdir(d)
        except Exception:
            continue
        for e in ents:
            if e.name in (".", ".."):
                continue
            p = (path.rstrip("/") + "/" + e.name) if path != "/" else "/" + e.name
            ch = fs.inode(e.inode)
            if ch is None:
                continue
            out.append((p, ch))
            if ch.is_dir:
                stack.append((p, ch))
            if len(out) > maxnodes:
                return out
    return out
