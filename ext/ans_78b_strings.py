#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""ans_78b_strings.py —— 验证 OST 到底有没有正文文本。

提取 ASCII 与 UTF-16LE 两种编码下最长的若干字符串，看是否出现
邮件主题 / 发件人 / 正文关键词。若全是路径与二进制垃圾，则确认「仅元数据」。
"""
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

OST = r"E:\ALL\AAAI\Works\RE\meiya\out\_q78.ost"
d = open(OST, "rb").read()
N = len(d)
print("文件 %s B" % format(N, ","))
print()

# ---------- ASCII 长串 ----------
print("=" * 78)
print("【ASCII】长度 ≥8 的字符串，按长度取前 60")
print("=" * 78)
asc = [(m.start(), m.group().decode("ascii")) for m in re.finditer(rb"[\x20-\x7e]{8,}", d)]
asc.sort(key=lambda x: -len(x[1]))
print("总数 %s 条" % format(len(asc), ","))
for off, s in asc[:60]:
    print("  @0x%08X len=%-4d %s" % (off, len(s), s[:140]))

print()
print("=" * 78)
print("【UTF-16LE】长度 ≥8 的字符串，按长度取前 60")
print("=" * 78)
# 用正则匹配 UTF-16LE 可打印（低字节 0x20-0x7e，高字节 0x00）
pat = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")
u = [(m.start(), m.group().decode("utf-16-le")) for m in pat.finditer(d)]
u.sort(key=lambda x: -len(x[1]))
print("总数 %s 条" % format(len(u), ","))
for off, s in u[:60]:
    print("  @0x%08X len=%-4d %s" % (off, len(s), s[:140]))

# ---------- 关键实体是否存在 ----------
print()
print("=" * 78)
print("【关键实体检查】")
print("=" * 78)
CHECKS = [
    ("@outlook.com", b"@outlook.com"),
    ("@gmail.com", b"@gmail.com"),
    ("@quora.com", b"@quora.com"),
    ("quora", b"quora"),
    ("Poe", b"Poe"),
    ("Message-ID", b"Message-ID"),
    ("Subject:", b"Subject:"),
    ("Received:", b"Received:"),
    ("2026-07-29", b"2026-07-29"),
    ("verification", b"verification"),
    ("code", b"code"),
    ("Dear", b"Dear"),
    ("html", b"html"),
    ("img src", b"img src"),
    ("http", b"http"),
    ("https", b"https"),
]
for name, pat in CHECKS:
    a = d.count(pat)
    uu = 0
    if all(32 <= c < 127 for c in pat):
        uu = d.count(pat.decode().encode("utf-16-le"))
    mark = "  ←" if (a or uu) else ""
    print("  %-16s ascii=%-5d utf16le=%-5d%s" % (name, a, uu, mark))

# ---------- BMP / 其它格式 ----------
print()
print("=" * 78)
print("【其他图像格式】")
print("=" * 78)
for name, magic in (("BMP 'BM'", b"BM"), ("GIF8", b"GIF8"),
                    ("JPEG FFD8FF", b"\xff\xd8\xff"), ("ICO 00000100", b"\x00\x00\x01\x00")):
    c = d.count(magic)
    print("  %-14s %d 次" % (name, c))
