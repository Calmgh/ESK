#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""示例 5：mdadm RAID5 缺块 XOR 重建

用法：
    python 05_raid5.py <磁盘1镜像> <磁盘2镜像> <输出镜像> [chunk_kb]

场景：三盘 RAID5 只拿到两盘（缺 role1），用 XOR 重建出完整数据。

参数从超级块读（偏移 4096，magic 0xa92b4efc）：
    level / layout / chunk / data_offset / raid_disks

重建原理：
    RAID5 每个 stripe 上 数据块 XOR 校验块 = 0
    → 缺失块 = 已知块逐字节 XOR
"""
import io
import os
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

SB_MAGIC = 0xA92B4EFC


def read_sb(f):
    f.seek(4096)
    sb = f.read(4096)
    magic = struct.unpack_from("<I", sb, 0)[0]
    if magic != SB_MAGIC:
        return None
    return {
        "magic": magic,
        "major": struct.unpack_from("<I", sb, 4)[0],
        "minor": struct.unpack_from("<I", sb, 8)[0],
        "role": struct.unpack_from("<I", sb, 0x10)[0],
        "chunk": struct.unpack_from("<I", sb, 0x18)[0] >> 9,      # 扇区
        "layout": struct.unpack_from("<I", sb, 0x1C)[0],
        "raid_disks": struct.unpack_from("<I", sb, 0x20)[0],
        "name": sb[0x40:0x40 + 32].rstrip(b"\x00").decode("latin-1"),
        "data_offset": struct.unpack_from("<Q", sb, 0x80)[0] * 512,
        "data_size": struct.unpack_from("<Q", sb, 0x88)[0] * 512,
    }


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    f1 = open(sys.argv[1], "rb")
    f2 = open(sys.argv[2], "rb")
    out = open(sys.argv[3], "wb")
    chunk_kb = int(sys.argv[4]) if len(sys.argv) > 4 else 512

    sbs = [s for s in (read_sb(f1), read_sb(f2)) if s]
    if not sbs:
        print("未找到 mdadm 超级块（magic 0xa92b4efc）")
        return 1
    sb = sbs[0]
    print("=" * 74)
    print("数组名   : %s" % sb["name"])
    print("级别     : %d" % sb["major"])
    print("磁盘数   : %d" % sb["raid_disks"])
    print("role     : %s" % [s["role"] for s in sbs])
    print("chunk    : %d KB" % chunk_kb)
    print("data_off : %s" % format(sb["data_offset"], ","))
    print("data_size: %s" % format(sb["data_size"], ","))

    roles = [s["role"] for s in sbs]
    if 1 not in roles:
        # 缺 role1 → 两盘 XOR 即可（left-symmetric，数据块与校验块逐字节异或）
        print()
        print("缺 role1，按 XOR 重建 ...")
        total = min(sb["data_size"], os.path.getsize(sys.argv[1]), os.path.getsize(sys.argv[2]))
        off = sb["data_offset"]
        blk = 4 << 20
        done = 0
        while done < total:
            n = min(blk, total - done)
            f1.seek(off + done)
            f2.seek(off + done)
            a = f1.read(n)
            b = f2.read(n)
            if len(a) < n:
                a += b"\x00" * (n - len(a))
            if len(b) < n:
                b += b"\x00" * (n - len(b))
            out.write(bytes(x ^ y for x, y in zip(a, b)))
            done += n
            if done % (256 << 20) == 0:
                print("   %d / %d MB" % (done >> 20, total >> 20))
        print("   完成，输出 %s B" % format(os.path.getsize(sys.argv[3]), ","))
    else:
        print("两盘 role 连续，需按 stripe 布局重建，此处略")

    f1.close()
    f2.close()
    out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
