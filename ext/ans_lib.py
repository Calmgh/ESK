# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""ans_* 脚本共用工具：带路径的 NTFS 遍历、镜像工厂、路径解析。只读。"""
import sys, os, io, json, functools

BASE = r'E:\ALL\AAAI\Works\RE\meiya'
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from mkit.image import Image, SubImage
from mkit.ntfs import NTFS
import mkit.volume as volume

SRC = {
    'CL-02': r'D:\meiya\src\CL-02\CL-02\CL-02.bin',
    'LL-01': r'D:\meiya\src\LL-01\LL-01\LL-01.bin',
    'WKH-01': r'D:\meiya\src\WKH-01\WKH-01\WKH-01.bin',
    'CL-01': r'D:\meiya\src\CL-01\CL-01\CL-01.e01',
    'COM-01': r'F:\ALL\meiya\src\Com-01\Com-01\COM-01.e01',
    'COM-01RAM': r'F:\ALL\meiya\src\Com-01\Com-01\COM-01_ram.raw',
}

_cache = {}


def get_fs(key):
    if key in _cache:
        return _cache[key]
    if key == 'CL-01':
        img = Image(SRC['CL-01'])
        fs = NTFS(SubImage(img, 0x7500000, 837 * 2 ** 30))
    else:
        fs = NTFS(Image(SRC[key]))
    _cache[key] = fs
    return fs


def walk_paths(fs, root='/', include_deleted=True):
    """yield (path, entry)。用 ls_entry 递归，构造完整路径。"""
    start = fs._resolve(root, include_deleted=True)
    if start is None:
        return
    stack = [(root.rstrip('/') + '/' + str(start.name), start)]
    visited = set()
    while stack:
        p, ent = stack.pop()
        if ent.num in visited:
            continue
        visited.add(ent.num)
        yield p, ent
        if not ent.is_dir:
            continue
        try:
            kids = fs.ls_entry(ent, include_deleted=include_deleted)
        except Exception:
            continue
        for c in kids:
            if c.num in visited:
                continue
            cp = (p.rstrip('/') + '/' + str(c.name)) if p != '/' else ('/' + str(c.name))
            stack.append((cp, c))


def all_paths(key, root='/', include_deleted=True):
    fs = get_fs(key)
    return list(walk_paths(fs, root, include_deleted))


def find(key, pred, root='/'):
    out = []
    for p, e in walk_paths(get_fs(key), root):
        try:
            if pred(p, e):
                out.append((p, e))
        except Exception:
            pass
    return out


def read(key, path):
    return get_fs(key).read_file(path)


def save(key, path, dest):
    data = read(key, path)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, 'wb') as f:
        f.write(data)
    return len(data)


def mft_index(key):
    """num -> entry，覆盖全部 MFT 记录（含长名多重硬链接）。"""
    ck = 'mft:' + key
    if ck in _cache:
        return _cache[ck]
    fs = get_fs(key)
    idx = {}
    for e in fs.iter_mft():
        try:
            if not e.valid:
                continue
        except Exception:
            pass
        idx[e.num] = e
    _cache[ck] = idx
    return idx


def path_of(key, num, idx=None):
    """按 parent_num 向上重建路径（长名）。"""
    if idx is None:
        idx = mft_index(key)
    parts = []
    seen = set()
    cur = num
    while cur and cur in idx and cur not in seen:
        seen.add(cur)
        e = idx[cur]
        nm = str(e.name)
        if nm in ('.', ''):
            break
        parts.append(nm)
        pn = getattr(e, 'parent_num', None)
        if pn is None or pn == cur:
            break
        cur = pn
    return '/' + '/'.join(reversed(parts))


def mft_find(key, pat, idx=None):
    import re
    rx = re.compile(pat, re.I)
    if idx is None:
        idx = mft_index(key)
    return [(path_of(key, n, idx), e) for n, e in idx.items() if rx.search(str(e.name))]


def dump(obj, name):
    p = os.path.join(BASE, 'out', name)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, default=str)
    return p
