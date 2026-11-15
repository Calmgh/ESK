#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""ans_78b_probe.py —— Q78 第一步：正确解析 OST 头 + 探测内容分布

不信前序的 0x1ED，改用「文件真实大小 16,818,176」反查 ibFileEof 真实偏移。
同时统计非零页、搜 PNG 魔数 / base64 PNG / HTML 标记 / 6 位数字。
"""
import io
import re
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

OST = r"E:\ALL\AAAI\Works\RE\meiya\out\_q78.ost"
d = open(OST, "rb").read()
N = len(d)
print("文件 %s  %s B (0x%X)" % (OST, format(N, ","), N))
print()

# ---------- 1. 头字段逐项核对 ----------
print("=" * 72)
print("【1】HEADER 前 0x240 字节")
print("=" * 72)
h = d[:0x240]
print("  dwMagic        @0x00 = %r" % h[0:4])
print("  dwCRCPartial   @0x04 = 0x%08X" % struct.unpack_from("<I", h, 0x04)[0])
print("  wMagicClient   @0x08 = 0x%04X (%r)" % (struct.unpack_from("<H", h, 0x08)[0], h[8:10]))
wVer = struct.unpack_from("<H", h, 0x0A)[0]
wVerClient = struct.unpack_from("<H", h, 0x0C)[0]
print("  wVer           @0x0A = 0x%04X  → %s" % (wVer, "ANSI(0x14)" if wVer == 0x14 else
      ("Unicode(0x23)" if wVer == 0x23 else "未知")))
print("  wVerClient     @0x0C = 0x%04X" % wVerClient)
bidNextP = struct.unpack_from("<Q", h, 0x20)[0]
print("  bidNextP       @0x20 = 0x%016X" % bidNextP)
dwUnique = struct.unpack_from("<I", h, 0x28)[0]
print("  dwUnique       @0x28 = 0x%08X" % dwUnique)

# root BREF @0xB4
root_bid = struct.unpack_from("<Q", h, 0xB4)[0]
root_ib = struct.unpack_from("<Q", h, 0xBC)[0]
print("  root.bid       @0xB4 = 0x%016X (NID=0x%X)" % (root_bid, root_bid & 0xFFFFFFFF))
print("  root.ib        @0xBC = 0x%X (%s)" % (root_ib, format(root_ib, ",")))

print()
print("  --- 用文件真实大小反查 ibFileEof 位置 ---")
for off in range(0, 0x240, 4):
    if off + 8 > len(h):
        break
    v = struct.unpack_from("<Q", h, off)[0]
    if v == N:
        print("    命中 ! ibFileEof @0x%03X = %s  ← 真实偏移" % (off, format(v, ",")))
print("  --- 前序声称 0x1E4 处的值 ---")
print("     @0x1E4 = %s" % format(struct.unpack_from("<Q", h, 0x1E4)[0], ","))
print("     @0x1EC = %s" % format(struct.unpack_from("<Q", h, 0x1EC)[0], ","))
print("     @0x1A4 = %s" % format(struct.unpack_from("<Q", h, 0x1A4)[0], ","))
print("     @0xA8  = %s" % format(struct.unpack_from("<Q", h, 0xA8)[0], ","))
print("     @0xB0  = %s" % format(struct.unpack_from("<Q", h, 0xB0)[0], ","))

print()
print("  --- bCryptMethod 候选（0x1F8~0x210 逐字节）---")
for off in range(0x1F8, 0x212):
    print("     @0x%03X = 0x%02X" % (off, h[off]))

# ---------- 2. 非零页统计 ----------
print()
print("=" * 72)
print("【2】非零页统计（512 B / 页）")
print("=" * 72)
PAGE = 512
npages = (N + PAGE - 1) // PAGE
nz = 0
nz_idx = []
for i in range(npages):
    blk = d[i * PAGE:(i + 1) * PAGE]
    if blk.count(0) != len(blk):
        nz += 1
        if len(nz_idx) < 40:
            nz_idx.append(i)
print("  总页数 %s   非零页 %s (%.1f%%)" % (
    format(npages, ","), format(nz, ","), 100.0 * nz / npages))
print("  前 40 个非零页索引: %s" % nz_idx)
print("  前 40 个非零页偏移: %s" % [hex(i * PAGE) for i in nz_idx])

# ---------- 3. 关键内容搜索 ----------
print()
print("=" * 72)
print("【3】内容搜索（ASCII / UTF-16LE 双编码）")
print("=" * 72)


def cnt(pat):
    return d.count(pat)


PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
KWS = [
    ("<html", b"<html"), ("<HTML", b"<HTML"), ("<body", b"<body"),
    ("<img", b"<img"), ("<div", b"<div"), ("<table", b"<table"),
    ("html", b"html"), ("body", b"body"),
    ("quoracdn", b"quoracdn"), ("qsf.fs", b"qsf.fs"),
    ("poe-no-reply", b"poe-no-reply"), ("poe", b"poe"),
    ("verification", b"verification"), ("Your verification", b"Your verification"),
    ("PNG magic", PNG_MAGIC),
    ("b64 PNG", b"iVBORw0KGgo"),
    ("JFIF", b"\xff\xd8\xff"),
]
for name, pat in KWS:
    a = cnt(pat)
    u = cnt(pat.decode("latin1").encode("utf-16-le")) if all(32 <= c < 127 for c in pat) else 0
    if a or u:
        print("  %-20s ascii=%-5d utf16le=%-5d" % (name, a, u))

# ---------- 4. 6 位数字频率 ----------
print()
print("=" * 72)
print("【4】6 位数字候选（ASCII 与 UTF-16LE），按出现次数排序")
print("=" * 72)
c1 = {}
for m in re.finditer(rb"(?<!\d)\d{6}(?!\d)", d):
    s = m.group().decode()
    c1[s] = c1.get(s, 0) + 1
print("  ASCII 唯一 6 位数字 %d 个" % len(c1))
for s, k in sorted(c1.items(), key=lambda x: -x[1])[:25]:
    print("     %s × %d" % (s, k))

u16 = d.decode("utf-16-le", "ignore")
c2 = {}
for m in re.finditer(r"(?<!\d)\d{6}(?!\d)", u16):
    s = m.group()
    c2[s] = c2.get(s, 0) + 1
print("  UTF-16LE 唯一 6 位数字 %d 个" % len(c2))
for s, k in sorted(c2.items(), key=lambda x: -x[1])[:25]:
    print("     %s × %d" % (s, k))

# ---------- 5. 页类型分布（PST 页 trailer 的 ptype）----------
print()
print("=" * 72)
print("【5】PST 页类型统计（页尾 16 B PAGETRAILER: ptype@+8 为 u16）")
print("=" * 72)
PT = {
    0x80: "ptypeBBT", 0x81: "ptypeNBT", 0x82: "ptypeFMap",
    0x83: "ptypePMap", 0x84: "ptypeAMap", 0x85: "ptypeFPMap",
    0x86: "ptypeDL", 0x87: "ptypeXBlock",
}
from collections import Counter
tc = Counter()
for i in range(npages):
    blk = d[i * PAGE:(i + 1) * PAGE]
    if len(blk) < PAGE:
        continue
    pt = struct.unpack_from("<H", blk, PAGE - 8)[0]
    tc[pt] += 1
for pt, k in sorted(tc.items(), key=lambda x: -x[1])[:15]:
    print("  ptype=0x%04X %-12s × %s" % (pt, PT.get(pt, "?"), format(k, ",")))
