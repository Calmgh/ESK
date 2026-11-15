#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_cm02s_base.py -- 读 out/cm02s_oidmap.pkl 构造 Container（不重扫），给后续脚本用。"""
import pickle
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
import apfs_fs as F  # noqa: E402
import apfs_map as M  # noqa: E402

CACHE = r"E:\ALL\AAAI\Works\RE\meiya\out\cm02s_oidmap.pkl"
_C = None
_FS = {}


def container():
    global _C
    if _C is not None:
        return _C
    c = M.Container()
    with open(CACHE, "rb") as f:
        d = pickle.load(f)
    assert d["bs"] == c.bs, "block size mismatch"
    c.oidmap = d["oidmap"]
    c.volumes = d["volumes"]
    _C = c
    return c


def fs(oid=None):
    c = container()
    if oid is None:
        # 数据卷 = 根目录含 Users 的那个（本镜像实测 oid=371006，卷名 ' - Data'）
        oid = 371006
    if oid not in _FS:
        _FS[oid] = F.VolFS(c, oid)
    return _FS[oid]


def vols():
    c = container()
    return [(oid, v["name"], v["index"], v["root_tree"], v["uuid"])
            for oid, v in sorted(c.volumes.items(), key=lambda kv: kv[1]["index"])]


def ts(ns):
    """APFS 纳秒时间戳 -> UTC+8 'YYYY-MM-DD HH:MM:SS'"""
    import datetime
    if not ns:
        return ""
    return datetime.datetime.utcfromtimestamp(ns / 1e9 + 8 * 3600).strftime("%Y-%m-%d %H:%M:%S")


def ls(v, path):
    return sorted(v.listdir(v.path(path)), key=lambda x: x["name"].lower())


def walk(v, dir_id, prefix="", depth=0, maxdepth=8, out=None):
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


def read_all(v, ino, cap=64 << 20, bs=None):
    """按 extent 读文件全部数据；不信任 inode size（APFS 压缩/稀疏时更稳）"""
    bs = bs or v.c.bs
    i = v.inode(ino)
    pid = i["private_id"] if i else ino
    ex = v.extents(pid)
    if not ex:
        return b""
    buf = bytearray()
    last = 0
    for laddr, ln, paddr in ex:
        if laddr > last:
            buf.extend(b"\x00" * (laddr - last))
        if len(buf) >= cap:
            break
        n = min(ln, cap - len(buf))
        buf.extend(v.c.sub.read(bs * paddr, n))
        last = laddr + ln
    return bytes(buf)


def size_of(v, ino):
    r = v.find(ino, 3)
    if not r:
        return 0
    vb = r[0][1]
    sz = struct.unpack_from("<Q", vb, 0x54)[0]
    if sz:
        return sz
    # DSTREAM xfield(type 8)
    off = 0x5C
    n = struct.unpack_from("<H", vb, off)[0] if off + 4 <= len(vb) else 0
    if 0 < n <= 64:
        ents = []
        p = off + 4
        for _ in range(n):
            t, fl, sz2 = struct.unpack_from("<BBH", vb, p)
            ents.append((t, sz2))
            p += 4
        dp = off + 4 + 4 * n
        for t, sz2 in ents:
            if t == 8 and sz2 >= 8:
                return struct.unpack_from("<Q", vb, dp)[0]
            dp += sz2
            dp = (dp + 7) & ~7
    return 0
