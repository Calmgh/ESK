#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""示例 4：VMware VMDK → LVM2 → ext4 全链路

用法：
    python 04_vmdk_lvm.py <fs镜像> <VMDK路径>

背景（两个真实踩过的坑）：
    坑 1：不少代码用 fs.read_file(vmdk) 读描述符 —— 对 11 GB 的
          monolithicSparse 盘会直接 MemoryError。
          正确做法：取 runlist，用 read_runs 只读前 512 字节头。
    坑 2：GPT → LVM2 → ext4 是三层，不能直接按分区偏移挂 ext4。

LVM2 PV 标签实际布局（与部分资料不同）：
    0x00  "LABELONE"            (8B)
    0x08  sector_xl             (8B)
    0x10  crc_xl                (4B)
    0x14  offset_xl             (4B) = 0x20
    0x18  "LVM2 001"            (8B)   ← 在 0x18，不是 0x08
    0x20  pv_uuid               (32B)
    pv_header 起点 = 0x200 + offset_xl
      +0x28  pe_start           (8B)
"""
import io
import os
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "ext"))

from mkit.image import Image, SubImage        # noqa: E402
from mkit.ntfs import NTFS                     # noqa: E402
from mkit.ext4 import Ext4                     # noqa: E402
import webvm3_dev as V                         # noqa: E402


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    fsimg, vmdk = sys.argv[1], sys.argv[2]

    img = Image(fsimg)
    # 若第一个参数是分区镜像，按需改这里；此处假设直接是 NTFS 卷
    fs = NTFS(img)

    print("=" * 74)
    print("1) 打开 VMDK（只读 512 字节头）")
    dev = V.Dev1(vmdk)
    print("   容量 %.2f GiB" % (dev.size / 2 ** 30))
    print("   grain = %d 扇区 = %d B" % (dev.grain_size, dev.grain_bytes))

    print()
    print("2) 解析 GPT")
    mbr = dev.read(0, 512)
    print("   MBR 分区类型: 0x%02x %s" % (
        mbr[446 + 4], "(保护性 MBR，含 GPT)" if mbr[446 + 4] == 0xEE else ""))
    gpt = dev.read(1024, 128 * 128)            # 条目在 LBA2 = 偏移 1024
    LVM = "E6D6D379-F507-44C2-A23C-238F2A3DF928"

    for i in range(128):
        e = gpt[i * 128:(i + 1) * 128]
        if e[:16] == b"\x00" * 16:
            continue
        import uuid as _u
        typ = str(_u.UUID(bytes_le=e[:16])).upper()
        first = struct.unpack_from("<Q", e, 32)[0]
        last = struct.unpack_from("<Q", e, 40)[0]
        n = last - first + 1
        print("   [%d] %s  LBA %d..%d  (%d 扇区, %.2f GiB)" % (
            i, "LVM PV" if typ == LVM else typ, first, last, n, n * 512 / 2 ** 30))

        if typ == LVM:
            pstart = first * 512
            print()
            print("3) 解析 LVM2")
            lab = dev.read(pstart + 0x200, 512)
            print("   0x00 = %r" % lab[:8])
            print("   0x18 = %r  (LVM2 001 应在此处)" % lab[0x18:0x20])
            offset_xl = struct.unpack_from("<I", lab, 0x14)[0]
            pv = pstart + 0x200 + offset_xl
            pe_start = struct.unpack_from("<Q", dev.read(pv + 0x28, 8), 0)[0]
            print("   offset_xl = 0x%x   pe_start = 0x%x (%d B = %d 扇区)" % (
                offset_xl, pe_start, pe_start, pe_start // 512))

            print()
            print("4) 尝试在 pe_start 处挂 ext4")
            lv_off = pstart + pe_start
            magic = dev.read(lv_off + 1024 + 0x38, 2)
            print("   ext4 魔数 @%d+1080 : %s  %s" % (
                lv_off, magic.hex(), "✓" if magic == b"\x53\xef" else "✗"))
            if magic == b"\x53\xef":
                fsx = Ext4(V.Sub(dev, lv_off))
                print("   挂载成功  bs=%d blocks=%d inodes=%d" % (
                    fsx.block_size, fsx.blocks_count, fsx.inodes_count))
                print("   根目录：", [e.name for e in fsx.listdir(fsx.lookup("/"))][:20])
            break

    img.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
