#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_cm02_util.py -- 容错读取 APFS 小文件并解析 bplist（只读）"""
import plistlib
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
import ans_cm02_lib as L  # noqa: E402


def xfields(buf, off):
    """xf_blob_t: u16 num_exts, u16 used_data, [num_exts * (u8 type,u8 flags,u16 size)] then data"""
    out = {}
    if off + 4 > len(buf):
        return out
    n = struct.unpack_from("<H", buf, off)[0]
    if not (0 < n <= 64):
        return out
    used = struct.unpack_from("<H", buf, off + 2)[0]
    ents = []
    p = off + 4
    for _ in range(n):
        if p + 4 > len(buf):
            return out
        t, fl, sz = struct.unpack_from("<BBH", buf, p)
        ents.append((t, fl, sz))
        p += 4
    dp = off + 4 + 4 * n
    for t, fl, sz in ents:
        out[t] = buf[dp:dp + sz]
        dp += sz
        dp = (dp + 7) & ~7          # xfield 数据 8 字节对齐
        _ = used
    return out


def file_size(v, ino):
    """inode size：先取 uncompressed_size@0x54，否则取 DSTREAM xfield(type 8) 的 u64 size"""
    r = v.find(ino, 3)
    if not r:
        return 0
    vb = r[0][1]
    sz = struct.unpack_from("<Q", vb, 0x54)[0]
    if sz:
        return sz
    xf = xfields(vb, 0x5C)
    d = xf.get(8)
    if d and len(d) >= 8:
        return struct.unpack_from("<Q", d, 0)[0]
    return 0


def raw_big(v, ino, blocks=None):
    """按第一个 extent 的 paddr 连续读 blocks 个块（小文件实际连续，用于绕过 extent 表不全）"""
    i = v.inode(ino)
    ex = v.extents(i["private_id"] if i else ino)
    if not ex:
        return b""
    paddr = ex[0][2]
    return v.c.sub.read(v.c.bs * paddr, blocks * v.c.bs)


def trim_plist(b):
    """用 bplist trailer 反推真实长度，返回可解析的 bytes 或 None"""
    if not b.startswith(b"bplist00"):
        return None
    for end in range(len(b), 40, -1):
        t = b[end - 32:end]
        off_size, ref_size = t[6], t[7]
        if off_size not in (1, 2, 3, 4, 8) or ref_size not in (1, 2, 3, 4, 8):
            continue
        num, top, tab = struct.unpack(">QQQ", t[8:32])
        if not (0 < num < 100000 and 0 < top < num and 8 < tab < end - 32):
            continue
        try:
            return plistlib.loads(b[:end])
        except Exception:
            continue
    return None


def grab(v, ino, cap=8 << 20):
    """按 dstream size 读文件；extent 只有一条时按块连续读"""
    size = file_size(v, ino)
    ex = v.extents(ino)
    i = v.inode(ino)
    if i and i["private_id"] != ino:
        ex2 = v.extents(i["private_id"])
        if len(ex2) > len(ex):
            ex = ex2
    if not ex:
        return b""
    if size and size <= cap:
        nb = (size + v.c.bs - 1) // v.c.bs
        b = v.c.sub.read(v.c.bs * ex[0][2], nb * v.c.bs)[:size]
        if len(b) == size:
            return b
    buf = b""
    for laddr, ln, paddr in ex:
        if size and laddr >= size:
            break
        n = ln if not size else min(ln, size - laddr)
        buf += v.c.sub.read(v.c.bs * paddr, n)
    return buf


def get_plist(path, vol=371006, blocks=64):
    v = L.fs(vol)
    ino = v.path(path)
    b = grab(v, ino)
    p = trim_plist(b)
    if p is None:
        p = trim_plist(raw_big(v, ino, blocks))
    return p, b


def walk(v, dir_id, prefix="", depth=0, maxdepth=6, out=None):
    out = out if out is not None else []
    try:
        ents = v.listdir(dir_id)
    except Exception:
        return out
    for e in ents:
        p = prefix + "/" + e["name"]
        out.append((p, e["id"], e["dtype"]))
        if e["dtype"] == 4 and depth < maxdepth:
            walk(v, e["id"], p, depth + 1, maxdepth, out)
    return out
