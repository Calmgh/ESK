#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""com03_raidfs.py —— 最终 RAID5 重组模块（chunk=512KiB, left-symmetric, 缺 role1）。

mdadm 1.2 superblock 事实（DISK1 role0 devnum0 / DISK2 role2 devnum2）：
  magic 0xa92b4efc  set=openmediavault:0  level=5 layout=2 raid_disks=3
  chunk_sectors=1024 (512 KiB)  data_offset=18432 sectors (9 MiB)
  数组可用容量 = 2 × (10 GiB − 9 MiB) = 21455962112 B，与 ext4 blocks*4096 完全相等
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from com03_lib import D1, D2      # noqa: E402
from mkit.image import Image      # noqa: E402
from mkit.ext4 import Ext4        # noqa: E402

N = 3
ROLE_DATA_OFF = 18432 * 512       # 每个成员的数据区起点
CHUNK = 512 * 1024                # s_chunk 1024 扇区


def disk_order(stripe, n=N, layout=2):
    pd = (n - 1) - (stripe % n)
    return pd, [(pd + 1 + k) % n for k in range(n - 1)]


class RAID5:
    def __init__(self, members, chunk=CHUNK, layout=2, cache_cap=192):
        self.m = members                  # {role: (Image, data_offset)}
        self.chunk = chunk
        self.layout = layout
        self.sizes = {r: (img.size - doff) for r, (img, doff) in members.items()}
        self.per_disk = min(self.sizes.values())
        self.size = self.per_disk * (N - 1)
        self.cache = {}
        self.cap = cache_cap
        self.xor = 0
        self.missing = 0

    def _rc(self, role, ci):
        k = (role, ci)
        v = self.cache.get(k)
        if v is not None:
            return v
        img, doff = self.m[role]
        base = doff + ci * self.chunk
        if base >= img.size:
            return b"\x00" * self.chunk
        v = img.read(base, self.chunk)
        if len(v) < self.chunk:
            v += b"\x00" * (self.chunk - len(v))
        if len(self.cache) > self.cap:
            self.cache.clear()
        self.cache[k] = v
        return v

    def _chunk(self, ac):
        s, i = divmod(ac, N - 1)
        pd, data = disk_order(s, N, self.layout)
        want = data[i]
        if want in self.m:
            return self._rc(want, s)
        peers = [d for d in data if d != want and d in self.m]
        if pd in self.m and peers:
            self.xor += 1
            a = self._rc(pd, s)
            b = self._rc(peers[0], s)
            return bytes(x ^ y for x, y in zip(a, b))
        self.missing += 1
        return b"\x00" * self.chunk

    def read(self, off, size):
        if off < 0 or size <= 0 or off >= self.size:
            return b""
        size = min(size, self.size - off)
        out = bytearray()
        pos, end = off, off + size
        while pos < end:
            ac = pos // self.chunk
            io = pos - ac * self.chunk
            take = min(self.chunk - io, end - pos)
            out += self._chunk(ac)[io:io + take]
            pos += take
        return bytes(out)


def open_array():
    i1, i2 = Image(D1), Image(D2)
    r = RAID5({0: (i1, ROLE_DATA_OFF), 2: (i2, ROLE_DATA_OFF)})
    return r, Ext4(r), (i1, i2)


if __name__ == "__main__":
    r, fs, imgs = open_array()
    print("array size:", r.size, "fs blocks:", fs.blocks_count, fs.block_size)
    print("expected fs bytes:", fs.blocks_count * fs.block_size)
    for blk in (32768, 98304, 163840):
        off = blk * fs.block_size + 1024
        b = r.read(off, 64)
        print(f"  backup sb blk={blk} magic=0x{struct.unpack_from('<H', b, 0x38)[0]:04x}")
    root = fs.inode(2)
    print("root:", [(e.name, e.inode) for e in fs.listdir(root)])
    print("xor-reconstructed chunks:", r.xor, "unrecoverable:", r.missing)
