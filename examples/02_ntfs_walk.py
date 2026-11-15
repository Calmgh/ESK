#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""示例 2：NTFS 完整路径重建

用法：
    python 02_ntfs_walk.py <镜像> <分区偏移(hex或dec)> [路径关键字]

为什么需要这个示例：
    mkit 的 fs.walk() / fs.ls_entry() 对每个文件条目**只返回一个名字**
    （通常是 8.3 短名），会遗漏长文件名。
    正确做法：用 fs.iter_mft() 建 MFT 索引，再按 parent_num 重建完整路径。

示例：
    python 02_ntfs_walk.py disk.E01 0x7500000 .xlsx
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from mkit.image import Image, SubImage        # noqa: E402
from mkit.ntfs import NTFS                     # noqa: E402


def build_index(fs):
    """MFT 号 → entry，以及 parent 关系"""
    idx = {}
    for ent in fs.iter_mft():
        if ent is None:
            continue
        idx[ent.num] = ent
    print("  MFT 记录 %s 条" % format(len(idx), ","))
    return idx


def path_of(idx, num, depth=0):
    """从 entry 往上回溯拼路径"""
    parts = []
    seen = set()
    cur = num
    while cur in idx and cur not in seen and depth < 64:
        seen.add(cur)
        e = idx[cur]
        nm = getattr(e, "name", None)
        if nm:
            parts.append(nm)
        p = getattr(e, "parent_num", 0)
        if p == cur or p == 5 or p not in idx:
            break
        cur = p
        depth += 1
    parts.reverse()
    return "\\" + "\\".join(parts)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    img_path = sys.argv[1]
    off = int(sys.argv[2], 0)
    kw = sys.argv[3] if len(sys.argv) > 3 else None

    img = Image(img_path)
    sub = SubImage(img, off, img.size - off)
    fs = NTFS(sub)

    print("=" * 74)
    print("建立 MFT 索引 ...")
    idx = build_index(fs)

    print()
    print("重建路径（%s）..." % ("筛选: " + kw if kw else "全部"))
    hits = 0
    for num, e in idx.items():
        if getattr(e, "is_dir", False):
            continue
        nm = getattr(e, "name", "") or ""
        if kw and kw.lower() not in nm.lower():
            continue
        p = path_of(idx, num)
        sz = getattr(e, "size", 0)
        print("  %-90s %12s B  mft=%d" % (p[:90], format(sz, ","), num))
        hits += 1
        if not kw and hits > 200:
            print("  ...（只显示前 200 条，加关键字筛选）")
            break
    print("  命中 %d 条" % hits)
    img.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
