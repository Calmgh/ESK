#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""com03_raid2.py —— RAID5 映射校准：pd 公式 × 数据盘顺序 全组合暴力验证。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from com03_lib import D1, D2            # noqa: E402
from mkit.image import Image            # noqa: E402
from mkit.ext4 import Ext4              # noqa: E402

N = 3


def disk_order(pdmode, order, stripe):
    n = N
    if pdmode == "asym":
        pd = stripe % n
    else:
        pd = (n - 1) - (stripe % n)
    if order == "fwd":
        data = [(pd + 1 + k) % n for k in range(n - 1)]
    else:
        data = [(pd - 1 - k) % n for k in range(n - 1)]
    return pd, data


class R5:
    def __init__(self, members, chunk, pdmode, order, chunk_cap=192):
        self.m = members
        self.chunk = chunk
        self.pdmode = pdmode
        self.order = order
        self.cache = {}
        self.cap = chunk_cap
        self.size = min(s for _i, s in members.values()) * (N - 1)
        self.xor = 0
        self.miss = 0

    def _rc(self, role, ci):
        k = (role, ci)
        v = self.cache.get(k)
        if v is not None:
            return v
        img, doff = self.m[role]
        v = img.read(doff + ci * self.chunk, self.chunk)
        if len(v) < self.chunk:
            v += b"\x00" * (self.chunk - len(v))
        if len(self.cache) > self.cap:
            self.cache.clear()
        self.cache[k] = v
        return v

    def _chunk(self, ac):
        s, i = divmod(ac, N - 1)
        pd, data = disk_order(self.pdmode, self.order, s)
        want = data[i]
        if want in self.m:
            return self._rc(want, s)
        peers = [d for d in data if d != want and d in self.m]
        if pd in self.m and peers:
            self.xor += 1
            a = self._rc(pd, s)
            b = self._rc(peers[0], s)
            return bytes(x ^ y for x, y in zip(a, b))
        self.miss += 1
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


def main():
    i1, i2 = Image(D1), Image(D2)
    m = {0: (i1, 18432 * 512), 2: (i2, 18432 * 512)}
    for chunk in (512 * 1024, 256 * 1024, 1024 * 1024, 64 * 1024):
        for pdmode in ("asym", "sym"):
            for order in ("fwd", "bwd"):
                r = R5(m, chunk, pdmode, order)
                tag = f"chunk={chunk//1024}K pd={pdmode} order={order}"
                try:
                    fs = Ext4(r)
                except Exception as e:
                    print(f"  {tag}: Ext4 open ERR {e}")
                    continue
                gdt = r.read((fs.first_data_block + 1) * fs.block_size, 64)
                it0 = struct.unpack_from("<I", gdt, 8)[0]
                ino2 = fs.inode(2)
                names = []
                if ino2 is not None:
                    try:
                        names = [e.name for e in fs.listdir(ino2)]
                    except Exception as e:
                        names = [f"ERR {e}"]
                ok = len([n for n in names if n not in (".", "..")]) > 0
                print(f"  {tag}: inode_table0={it0} ino2={ino2} "
                      f"root={names[:10]}{'  <<< OK' if ok else ''}  xor={r.xor}")
    i1.close()
    i2.close()


if __name__ == "__main__":
    main()
