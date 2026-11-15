#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""ans_78b_zlib.py —— 容错解压大图：IDAT 流被间隙打断，能解多少解多少。

做法：
  1. 从 PNG 魔数后跳过 IHDR，收集后续所有 IDAT 的 data（遇到坏块就停）
  2. 用 zlib.decompressobj 逐段喂，忽略错误，保留已解出的字节
  3. 按 IHDR 的 宽/高/通道数 把解出的字节渲染成图像（不足部分填黑）
  4. 保存为 PNG 供人工查看
"""
import io
import os
import struct
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

OST = r"E:\ALL\AAAI\Works\RE\meiya\out\_q78.ost"
OUT = r"E:\ALL\AAAI\Works\RE\meiya\out\q78_png"
d = open(OST, "rb").read()

BAD = [0x00196C00, 0x001F5800, 0x002A0A00, 0x002FF600]


def parse_ihdr(off):
    ln = struct.unpack_from(">I", d, off + 8)[0]
    if d[off + 12:off + 16] != b"IHDR" or ln != 13:
        return None
    w, h = struct.unpack_from(">II", d, off + 16)
    bd = d[off + 24]
    ct = d[off + 25]
    return w, h, bd, ct


def gather_idat(off, limit=6 * 1024 * 1024):
    """收集 IDAT 数据（跳过块头/CRC），遇坏块即停"""
    p = off + 8
    buf = bytearray()
    chunks = 0
    while p + 8 <= len(d) and p - off < limit:
        ln = struct.unpack_from(">I", d, p)[0]
        typ = d[p + 4:p + 8]
        if ln > 64 * 1024 * 1024:
            break
        if typ == b"IDAT":
            buf += d[p + 8:p + 8 + ln]
            chunks += 1
        elif typ == b"IEND":
            break
        elif typ not in (b"IHDR", b"PLTE", b"tRNS", b"pHYs", b"sRGB", b"gAMA",
                         b"bKGD", b"tIME", b"eXIf", b"iCCP", b"sBIT", b"hIST",
                         b"tEXt", b"iTXt", b"zTXt", b"cHRM", b"sPLT", b"oFFs",
                         b"pCAL", b"sCAL", b"gIFg", b"gIFx", b"gIFt", b"fRAc"):
            break
        p += 12 + ln
    return bytes(buf), chunks


CH = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


for off in BAD:
    print("=" * 74)
    info = parse_ihdr(off)
    if not info:
        print("@0x%08X IHDR 异常" % off)
        continue
    w, h, bd, ct = info
    print("@0x%08X  %dx%d  bd=%d ct=%d  需要解压 %s B" % (
        off, w, h, bd, ct, format(h * (1 + w * CH.get(ct, 4)), ",")))

    idat, nchunk = gather_idat(off)
    print("  收集到 IDAT %d 块，%s B" % (nchunk, format(len(idat), ",")))
    if not idat:
        continue

    # 容错解压
    raw = bytearray()
    do = zlib.decompressobj()
    step = 64 * 1024
    err = None
    for i in range(0, len(idat), step):
        try:
            raw += do.decompress(idat[i:i + step])
        except Exception as e:
            err = e
            break
    try:
        raw += do.flush()
    except Exception:
        pass
    print("  解压出 %s B / 需要 %s B (%.1f%%)%s" % (
        format(len(raw), ","), format(h * (1 + w * CH.get(ct, 4)), ","),
        100.0 * len(raw) / (h * (1 + w * CH.get(ct, 4))),
        ("  中断: %s" % err) if err else ""))

    if len(raw) < 64:
        print("  解出太少，放弃")
        continue

    # 反滤波 + 渲染（逐行）
    bpp = CH.get(ct, 4) * (bd // 8)
    stride = w * bpp
    outrows = bytearray()
    prev = bytearray(stride)
    pos = 0
    rows_ok = 0
    for y in range(h):
        if pos >= len(raw):
            outrows += prev
            continue
        f = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if len(line) < stride:
            line += bytes(stride - len(line))
        if f == 0:
            pass
        elif f == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif f == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif f == 3:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif f == 4:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        outrows += line
        prev = line
        rows_ok += 1

    print("  重建 %d/%d 行" % (rows_ok, h))
    from PIL import Image
    mode = {1: "L", 3: "RGB", 4: "RGBA"}.get(bpp, "RGBA")
    try:
        im = Image.frombytes(mode, (w, h), bytes(outrows))
        fn = os.path.join(OUT, "partial_%08X_%dx%d.png" % (off, w, h))
        im.save(fn)
        print("  ✅ 已存 %s" % os.path.basename(fn))
    except Exception as e:
        print("  ❌ 渲染失败: %s" % e)
