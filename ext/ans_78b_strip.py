#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""ans_78b_strip.py —— PST 块 trailer 剥离重组，修复 4 张大图。

PST ANSI 块大小 512，每块尾部 16 字节 trailer（cb/wSig/dwCRC/bid），
图像 IDAT 流跨块时会被这些 trailer 切断。剥离方式：每 512 字节只取前 496。
"""
import io
import os
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

OST = r"E:\ALL\AAAI\Works\RE\meiya\out\_q78.ost"
OUT = r"E:\ALL\AAAI\Works\RE\meiya\out\q78_png"
d = open(OST, "rb").read()
N = len(d)

BAD = [(0x00196C00, 640, 520, 387996), (0x001F5800, 307, 250, 91339),
       (0x002A0A00, 640, 520, 387996), (0x002FF600, 307, 250, 91339)]

# ---------- 先看块 trailer 特征 ----------
print("=" * 74)
print("块尾 16 字节特征（怀疑 PST BLOCKTRAILER）")
print("=" * 74)
for off in (0x00196C00,):
    for p in range(3):
        page = off + p * 512
        tail = d[page + 496:page + 512]
        print("  page@0x%08X tail: %s" % (page, tail.hex(" ")))
        cb = struct.unpack_from("<H", tail, 0)[0]
        wSig = struct.unpack_from("<H", tail, 2)[0]
        print("      cb=%d wSig=0x%04X" % (cb, wSig))

print()
print("=" * 74)
print("重组方案：每 512 字节取前 496 字节")
print("=" * 74)


def strip_pages(buf):
    out = bytearray()
    for i in range(0, len(buf) - 511, 512):
        out += buf[i:i + 496]
    return bytes(out)


for off, w, h, est in BAD:
    print("\n--- @0x%08X  %dx%d ---" % (off, w, h))
    # 取一段足够长的原始区（按估算长度 ×1.2 + 余量）
    need_raw = int(est * 512 / 496) + 4096
    raw = d[off:off + need_raw]
    cand = strip_pages(raw)

    # 在剥离后的流里找 IEND
    j = cand.find(b"IEND")
    if j < 0:
        print("   剥离后仍未找到 IEND")
        continue
    end = j + 8
    png = cand[:end]
    fn = os.path.join(OUT, "fix_%08X_%dx%d.png" % (off, w, h))
    open(fn, "wb").write(png)
    print("   剥离后长度 %s B → %s" % (format(end, ","), os.path.basename(fn)))
    try:
        from PIL import Image
        im = Image.open(fn)
        im.load()
        print("   ✅ PIL 校验通过: %s %dx%d" % (im.mode, im.width, im.height))
    except Exception as e:
        print("   ❌ PIL 仍失败: %s" % e)
        # 兜底：尝试不同 trailer 大小
        for tr in (0, 8, 12, 20, 24):
            if tr == 16:
                continue
            c2 = bytearray()
            for i in range(0, len(raw) - 511, 512):
                c2 += raw[i:i + 512 - tr]
            c2 = bytes(c2)
            k = c2.find(b"IEND")
            if k < 0:
                continue
            t = os.path.join(OUT, "try_%08X_tr%d.png" % (off, tr))
            open(t, "wb").write(c2[:k + 8])
            try:
                im2 = Image.open(t)
                im2.load()
                print("      ✔ trailer=%d 成功: %s %dx%d → %s" % (
                    tr, im2.mode, im2.width, im2.height, os.path.basename(t)))
                break
            except Exception:
                os.remove(t)
