# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
﻿#!/usr/bin/env python3
"""ans_c02h_webvm.py —— Tronic.vmdk(base) + Tronic-000001.vmdk(snapshot) 链式只读，挂 ext4。"""
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
from mkit.ext4 import Ext4
import ans_c02h_vmdk as V

DIR = "/Users/C79594/Documents/Virtual Machines/Tronic"
BASE = DIR + "/Tronic.vmdk"
DELTA = DIR + "/Tronic-000001.vmdk"


class Ext:
    """单层 sparse extent，可查询是否分配。"""

    def __init__(self, f):
        self.f = f
        h = f.read(0, 512)
        assert h[:4] == b"KDMV"
        self.capacity = struct.unpack_from("<Q", h, 12)[0]
        self.grain_size = struct.unpack_from("<Q", h, 20)[0] or 128
        self.num_gte = struct.unpack_from("<I", h, 44)[0] or 512
        self.gd_offset = struct.unpack_from("<Q", h, 56)[0]
        self.bytes = self.capacity * 512
        self.ngrains = (self.capacity + self.grain_size - 1) // self.grain_size
        self.ngt = (self.ngrains + self.num_gte - 1) // self.num_gte
        raw = f.read(self.gd_offset * 512, self.ngt * 4)
        self.gd = struct.unpack_from("<%dI" % self.ngt, raw, 0)
        self._cache = {}

    def gt(self, gti):
        t = self._cache.get(gti)
        if t is None:
            off = self.gd[gti]
            n = self.num_gte
            if off == 0:
                t = (0,) * n
            else:
                raw = self.f.read(off * 512, n * 4)
                if len(raw) < n * 4:
                    raw += b"\x00" * (n * 4 - len(raw))
                t = struct.unpack_from("<%dI" % n, raw, 0)
            if len(self._cache) > 256:
                self._cache.clear()
            self._cache[gti] = t
        return t

    def grain_sec(self, g):
        gti, gi = divmod(g, self.num_gte)
        return self.gt(gti)[gi]

    def read(self, off, size):
        if size <= 0 or off >= self.bytes:
            return b""
        size = min(size, self.bytes - off)
        gsz = self.grain_size * 512
        out = bytearray()
        pos, rem = off, size
        while rem > 0:
            g = pos // gsz
            bo = pos % gsz
            n = min(gsz - bo, rem)
            sec = self.grain_sec(g)
            if sec == 0:
                out += b"\x00" * n
            else:
                b = self.f.read(sec * 512 + bo, n)
                out += b + b"\x00" * (n - len(b))
            pos += n
            rem -= n
        return bytes(out)


class Chain:
    def __init__(self, layers):
        self.layers = layers
        self.size = layers[0].bytes

    def read(self, off, size):
        if size <= 0 or off >= self.size:
            return b""
        size = min(size, self.size - off)
        gsz = self.layers[0].grain_size * 512
        out = bytearray()
        pos, rem = off, size
        while rem > 0:
            g = pos // gsz
            bo = pos % gsz
            n = min(gsz - bo, rem)
            got = None
            for L in self.layers:
                if L.grain_sec(g) != 0:
                    got = L.read(pos, n)
                    break
            out += got if got is not None else b"\x00" * n
            pos += n
            rem -= n
        return bytes(out)


def open_webvm(fs):
    base = Ext(V.NtfsFile(fs, BASE))
    delta = Ext(V.NtfsFile(fs, DELTA))
    print("base bytes=%d delta bytes=%d grain=%d %d" %
          (base.bytes, delta.bytes, base.grain_size, delta.grain_size), flush=True)
    ch = Chain([delta, base])
    # GPT?
    mbr = ch.read(0, 512)
    parts = []
    if struct.unpack_from("<H", mbr, 510)[0] == 0xAA55:
        first = ch.read(512, 92)
        if first[:8] == b"EFI PART":
            lba = struct.unpack_from("<Q", first, 72)[0]
            cnt = struct.unpack_from("<I", first, 80)[0]
            esz = struct.unpack_from("<I", first, 84)[0]
            raw = ch.read(lba * 512, cnt * esz)
            for i in range(cnt):
                e = raw[i * esz:(i + 1) * esz]
                if not any(e) or e[:16] == b"\x00" * 16:
                    continue
                f0, l0 = struct.unpack_from("<QQ", e, 32)
                parts.append((f0 * 512, (l0 - f0 + 1) * 512, e[:16].hex()))
        else:
            for i in range(4):
                e = mbr[446 + 16 * i:446 + 16 * (i + 1)]
                if e[4] == 0:
                    continue
                l0 = struct.unpack_from("<I", e, 8)[0]
                n0 = struct.unpack_from("<I", e, 12)[0]
                parts.append((l0 * 512, n0 * 512, "mbr:%02x" % e[4]))
    for p in parts:
        print("part off=%d size=%d type=%s" % p, flush=True)
    return ch, parts


if __name__ == "__main__":
    from mkit.image import Image, SubImage
    from mkit.ntfs import NTFS
    img = Image(r"D:\meiya\src\Com-02\Com-02\Com-02.e01")
    fs = NTFS(SubImage(img, 0x7500000, 975 * 2 ** 30))
    ch, parts = open_webvm(fs)
    for off, size, typ in parts:
        sb = ch.read(off + 1024, 1024)
        if int.from_bytes(sb[0x38:0x3a], "little") == 0xEF53:
            e = Ext4(V.Sub(ch, off, size) if False else ans_c02h_ext.Sub(ch, off, size))
            print("ext4 at", off, "bs", e.block_size, "blocks", e.blocks_count)
