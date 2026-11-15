#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""ans_78b_recover.py —— 恢复 4 张被截断的 PNG。

失败原因可能是 IDAT 长度字段跨了 PST XBlock，或 IEND 在更远处。
策略：从魔数起向后搜 IEND+CRC（4 字节），截到那里；同时打印 IHDR 尺寸。
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

BAD = [0x00196C00, 0x001F5800, 0x002A0A00, 0x002FF600]

print("=" * 74)
print("恢复被截断的 PNG")
print("=" * 74)

for off in BAD:
    print("\n--- @0x%08X ---" % off)
    if d[off:off + 8] != b"\x89PNG\r\n\x1a\n":
        print("   魔数不符，跳过")
        continue
    # IHDR
    ln = struct.unpack_from(">I", d, off + 8)[0]
    typ = d[off + 12:off + 16]
    print("   首块 %r len=%d" % (typ, ln))
    w = h = bd = ct = 0
    if typ == b"IHDR":
        w, h = struct.unpack_from(">II", d, off + 16)
        bd = d[off + 24]
        ct = d[off + 25]
        print("   尺寸 %dx%d  bd=%d ct=%d" % (w, h, bd, ct))

    # 找 IEND
    i = off
    got = None
    while True:
        j = d.find(b"IEND", i + 4)
        if j < 0 or j > off + 8 * 1024 * 1024:
            break
        # IEND 块 = len(4)=0 + "IEND" + crc(4)
        if j >= 4 and struct.unpack_from(">I", d, j - 4)[0] == 0:
            got = j + 8
            break
        i = j
    if not got:
        print("   未找到 IEND（8 MB 内）")
        # 尝试更大范围
        j = d.find(b"IEND", off)
        if j > 0:
            print("   宽松命中 IEND @0x%08X（%d B 处）" % (j, j - off))
        continue

    size = got - off
    print("   IEND 结束 @0x%08X  总长 %s B" % (got, format(size, ",")))
    fn = os.path.join(OUT, "rec_%08X_%dx%d.bin" % (off, w, h))
    open(fn, "wb").write(d[off:got])
    open(fn[:-4] + ".png", "wb").write(d[off:got])
    # 验证能否被 PIL 打开
    try:
        from PIL import Image
        im = Image.open(fn[:-4] + ".png")
        im.load()
        print("   PIL 校验通过: %s %dx%d" % (im.mode, im.width, im.height))
    except Exception as e:
        print("   PIL 校验失败: %s" % e)

print("\n" + "=" * 74)
print("同时检查：是否还有别的图片格式（JPEG / GIF / BMP）")
print("=" * 74)
for name, magic in (("JPEG", b"\xff\xd8\xff"), ("GIF", b"GIF8"), ("BMP", b"BM")):
    cnt = d.count(magic)
    print("  %-5s 出现 %d 次" % (name, cnt))
