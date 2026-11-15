#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_c02h_lvm.py —— 解析 LVM2 PV（单 PV 线性 LV），暴露 LV 的 read。"""
import re
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")


class Sub:
    def __init__(self, base, off, size):
        self.base, self.off, self.size = base, off, size

    def read(self, o, n):
        if n <= 0 or o >= self.size:
            return b""
        n = min(n, self.size - o)
        return self.base.read(self.off + o, n)


def parse_lvm(part, verbose=True):
    lab = part.read(512, 32)
    assert lab[:8] == b"LABELONE", lab[:8]
    pv_uuid = part.read(1024, 32)
    dev_size = struct.unpack_from("<Q", part.read(1056, 8), 0)[0]
    # data areas 从 1064 开始，16 字节一项，offset==0 结束
    p = 1064
    data = []
    while True:
        raw = part.read(p, 16)
        off, size = struct.unpack_from("<QQ", raw, 0)
        p += 16
        if off == 0:
            break
        data.append((off * 512, size))
    mda = []
    while True:
        raw = part.read(p, 16)
        off, size = struct.unpack_from("<QQ", raw, 0)
        p += 16
        if off == 0:
            break
        mda.append((off * 512, size))
    if verbose:
        print("PV uuid=%r dev_size=%d data=%s mda=%s" % (pv_uuid[:32], dev_size, data, mda), flush=True)
    # mda_header: checksum4 magic16 version4 start8 size8
    txt = b""
    for off, size in mda:
        h = part.read(off, 4096)
        magic = h[4:20]
        rel = h[40:40 + 8]
        rl_off, rl_size = struct.unpack_from("<QQ", h, 40)
        if rl_off == 0:
            continue
        txt += part.read(off + rl_off, rl_size)
    if verbose:
        print("metadata %d bytes" % len(txt), flush=True)
    return txt.decode("utf-8", "replace"), data


def lv_extent_map(meta):
    """返回 {lv_name: (start_sector_in_pv, sectors)}（假设单 PV、线性/单条带）。"""
    out = {}
    for m in re.finditer(r"(\w+) \{", meta):
        pass
    for block in re.split(r"\n\s*\n", meta):
        pass
    # 逐 logical_volumes 段解析
    idx = meta.find("logical_volumes")
    seg = meta[idx:]
    for m in re.finditer(r'\n\t\t(\S+) \{(.*?)\n\t\t\}', seg, re.S):
        name, body = m.group(1), m.group(2)
        em = re.search(r"extent_count = (\d+)", body)
        sm = re.search(r"start_extent = (\d+)", body)
        pm = re.search(r'stripes = \[\s*"([^"]+)",\s*(\d+)', body)
        if not (em and pm):
            continue
        out[name] = (int(pm.group(2)), int(em.group(1)), int(sm.group(1)) if sm else 0)
    return out
