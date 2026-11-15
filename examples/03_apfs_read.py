#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""示例 3：APFS 文件级读取

用法：
    python 03_apfs_read.py <CM-02.E01> <分区偏移> [卷OID] [文件路径]

背景：
    mkit.macart.Apfs 只提供 info() / volumes()，volumes() 返回 0 条，
    **不支持文件级读取**。本包 ext/apfs_fs.py + apfs_map.py 提供实现。

关键点：
    1. NXSB 魔数在分区内偏移 0x20（前 32 字节是 obj_phys），不是 0
    2. 卷 OID 是虚拟对象号，必须经容器 omap B-tree 翻译成物理地址，
       不能 oid × block_size 直读
    3. extent 三元组是 (logical_off, length_bytes, phys_block)
       —— 物理块在**第三位**
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "ext"))

from mkit.image import Image, SubImage        # noqa: E402
import apfs_map as M                           # noqa: E402
import apfs_fs as F                            # noqa: E402


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    img_path = sys.argv[1]
    off = int(sys.argv[2], 0)

    img = Image(img_path)
    sub = SubImage(img, off, img.size - off)

    magic = sub.read(0x20, 4)
    print("=" * 74)
    print("NXSB @0x20 : %r  %s" % (magic, "✓ APFS" if magic == b"NXSB" else "✗ 不是 APFS"))
    if magic != b"NXSB":
        return 1

    print("扫描容器 omap（可能需要几十秒）...")
    c = M.Container()
    c.scan(800000, 1400000, verbose=False)
    print("  block_size      =", c.block_size)
    print("  block_count     =", format(c.block_count, ","))
    print("  卷 OID          =", c.vol_oids)

    # 列出各卷
    print()
    print("卷列表：")
    for oid in c.vol_oids:
        try:
            v = F.VolFS(c, oid)
            print("  oid=%-8d  name=%s" % (oid, getattr(v, "name", "?")))
        except Exception as e:
            print("  oid=%-8d  读取失败 %s" % (oid, str(e)[:40]))

    # 若指定卷与路径，则读文件
    if len(sys.argv) >= 5:
        oid = int(sys.argv[3])
        target = sys.argv[4]
        v = F.VolFS(c, oid)
        print()
        print("在 oid=%d 中读取 %s" % (oid, target))
        try:
            ino = v.path(target)
            data = v.read_file(ino)
            print("  大小 %s B" % format(len(data), ","))
            print("  头 16 字节: %s" % data[:16].hex(" "))
        except Exception as e:
            print("  失败:", e)

    img.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
