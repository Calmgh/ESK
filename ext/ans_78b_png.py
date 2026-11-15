#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""ans_78b_png.py —— 提取 OST 内嵌的全部 PNG，看尺寸/内容，判断哪张是验证码图。

同时打印每张 PNG 前后 ±160 字节的可打印上下文（找文件名 / property 标记），
并检查两个 6 位数字候选（ASCII 888888、UTF-16LE 483606）的邻近内容。
"""
import io
import os
import re
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

OST = r"E:\ALL\AAAI\Works\RE\meiya\out\_q78.ost"
OUT = r"E:\ALL\AAAI\Works\RE\meiya\out\q78_png"
os.makedirs(OUT, exist_ok=True)

d = open(OST, "rb").read()
N = len(d)
MAGIC = b"\x89PNG\r\n\x1a\n"


def ctx(off, before=160, after=160):
    """取可打印上下文"""
    a = max(0, off - before)
    b = min(N, off + after)
    raw = d[a:b]
    s = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
    return s


def parse_png(off):
    """从 off 起解析 PNG，返回 (end_offset, width, height, bitdepth, colortype, chunks)"""
    p = off + 8
    w = h = bd = ct = 0
    chunks = []
    while p + 8 <= N:
        ln = struct.unpack_from(">I", d, p)[0]
        typ = d[p + 4:p + 8]
        if ln > 64 * 1024 * 1024:
            return None
        chunks.append((typ.decode("latin1", "ignore"), ln))
        if typ == b"IHDR" and ln >= 13:
            w, h = struct.unpack_from(">II", d, p + 8)
            bd = d[p + 16]
            ct = d[p + 17]
        p += 12 + ln
        if typ == b"IEND":
            return p, w, h, bd, ct, chunks
    return None


print("=" * 78)
print("OST 内嵌 PNG 逐个解析")
print("=" * 78)
offs = [m.start() for m in re.finditer(re.escape(MAGIC), d)]
print("PNG 魔数出现 %d 次\n" % len(offs))

found = []
for i, off in enumerate(offs):
    r = parse_png(off)
    if not r:
        print("[%02d] @0x%08X  解析失败（可能被截断）" % (i, off))
        continue
    end, w, h, bd, ct, chunks = r
    size = end - off
    ctn = {0: "Gray", 2: "RGB", 3: "Palette", 4: "GrayA", 6: "RGBA"}.get(ct, "?")
    names = [c[0] for c in chunks]
    print("[%02d] @0x%08X  %4dx%-4d  bd=%d ct=%s(%s)  %7s B  块=%s" % (
        i, off, w, h, bd, ct, ctn, format(size, ","), names[:6]))
    found.append((off, end, size, w, h, ct))
    # 保存
    fn = os.path.join(OUT, "png%02d_%dx%d.bin" % (i, w, h))
    open(fn, "wb").write(d[off:end])
    # 上下文
    c = ctx(off)
    printable = sum(1 for ch in c if ch != ".")
    if printable > 20:
        print("      ctx: %s" % c)

print()
print("=" * 78)
print("6 位数字候选的上下文")
print("=" * 78)

# ASCII 888888
for m in re.finditer(rb"(?<!\d)888888(?!\d)", d):
    off = m.start()
    print("ASCII '888888' @0x%08X" % off)
    print("  %s" % ctx(off, 200, 200))
    print()

# UTF-16LE 483606
needle = "483606".encode("utf-16-le")
for m in re.finditer(re.escape(needle), d):
    off = m.start()
    print("UTF-16LE '483606' @0x%08X" % off)
    # 用 utf-16 解码周围
    a = max(0, off - 200)
    b = min(N, off + 200)
    try:
        s = d[a:b].decode("utf-16-le", "ignore")
    except Exception:
        s = ""
    s = "".join(ch if 32 <= ord(ch) < 127 or ch in "　" else "." for ch in s)
    print("  %s" % s)
    print()

print("已保存 %d 张 PNG 到 %s" % (len(found), OUT))
