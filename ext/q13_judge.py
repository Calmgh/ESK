#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""q13_judge.py —— 裁决 Q13：Picture_9.png 到底与哪个 Downloads PNG 同源。
做法：三者都解码为 numpy 数组，按 RGB 三通道逐像素比较，统计
  · 完全相同像素占比
  · 差值恰为 ±1 的占比（LSB 隐写特征）
"""
import io
import sys

import numpy as np
from PIL import Image

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

P9 = r"E:\ALL\AAAI\Works\RE\meiya\out\_cm02files\Picture_9.png"
CAND = {
    "大学生.png": r"E:\ALL\AAAI\Works\RE\meiya\out\_cm02files\大学生.png",
    "Picture_8.png": r"E:\ALL\AAAI\Works\RE\meiya\out\_cm02files\Picture_8.png",
    "图片_image.png": r"E:\ALL\AAAI\Works\RE\meiya\out\_cm02files\图片_image.png",
}

a = Image.open(P9).convert("RGB")
A = np.asarray(a, dtype=np.int16)
print("Picture_9: %dx%d  %s  -> 转 RGB" % (a.width, a.height, Image.open(P9).mode))
print()

for name, path in CAND.items():
    im = Image.open(path)
    b = im.convert("RGB")
    print("=" * 70)
    print("%s  %dx%d  原mode=%s  文件 %d B" % (
        name, im.width, im.height, im.mode, os.path.getsize(path) if (os := __import__("os")) else 0))
    if (b.width, b.height) != (a.width, a.height):
        print("  尺寸不同，跳过")
        continue
    B = np.asarray(b, dtype=np.int16)
    d = A - B
    tot = d.size
    eq = int((d == 0).sum())
    pm1 = int((np.abs(d) == 1).sum())
    big = int((np.abs(d) > 1).sum())
    print("  总通道数 %d" % tot)
    print("  完全相同 %d (%.4f%%)" % (eq, 100.0 * eq / tot))
    print("  差 ±1   %d (%.4f%%)   ← LSB 隐写特征" % (pm1, 100.0 * pm1 / tot))
    print("  |差|>1  %d (%.4f%%)" % (big, 100.0 * big / tot))
    # 逐像素判定：三通道都满足 |d|<=1 的像素占比
    pix_ok = int((np.abs(d) <= 1).all(axis=2).sum())
    print("  三通道差均≤1 的像素: %d / %d (%.4f%%)" % (
        pix_ok, a.width * a.height, 100.0 * pix_ok / (a.width * a.height)))
    print()
