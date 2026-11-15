#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_c02h_ext.py —— Tronic_s2 VMDK 内部 ext4 分区（GPT 分区2 @LBA4096）挂载工具。"""
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
from mkit.image import Image, SubImage
from mkit.ntfs import NTFS
from mkit.ext4 import Ext4
import ans_c02h_vmdk as V

PART2_OFF = 4096 * 512


class Sub:
    def __init__(self, base, off, size):
        self.base = base
        self.off = off
        self.size = size

    def read(self, o, n):
        if n <= 0 or o >= self.size:
            return b""
        n = min(n, self.size - o)
        return self.base.read(self.off + o, n)


def ntfs_main():
    img = Image(r"D:\meiya\src\Com-02\Com-02\Com-02.e01")
    return NTFS(SubImage(img, 0x7500000, 975 * 2 ** 30))


def open_tronic_s2():
    fs = ntfs_main()
    d = V.open_disk(fs)
    sub = Sub(d, PART2_OFF, d.size - PART2_OFF)
    e = Ext4(sub)
    return e, d


if __name__ == "__main__":
    e, d = open_tronic_s2()
    print("ext4 bs=%s blocks=%s" % (getattr(e, "block_size", "?"), getattr(e, "blocks_count", "?")))
    for p in ["/", "/etc", "/var", "/var/lib"]:
        try:
            ino, ent = e.lookup(p)
            print("LOOKUP-OK", p, ino)
        except Exception as ex:
            print("LOOKUP-ERR", p, type(ex).__name__, ex)
