#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_cm02_lib.py -- 复用 APFS 读取，批量取证（只读）"""
import plistlib
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
import apfs_fs as F  # noqa: E402
import apfs_map as M  # noqa: E402

_C = None
_FS = {}

def init():
    global _C
    if _C is None:
        _C = M.Container()
        _C.scan(800000, 1400000, verbose=False)
    return _C

def fs(oid=371006):
    if oid not in _FS:
        init()
        _FS[oid] = F.VolFS(_C, oid)
    return _FS[oid]

def ls(path, vol=371006):
    v = fs(vol)
    print("== ls", path)
    for e in sorted(v.listdir(v.path(path)), key=lambda x: x["name"].lower()):
        print("   %-45r id=%-8d dtype=%d" % (e["name"], e["id"], e["dtype"]))

def read(path, vol=371006):
    v = fs(vol)
    return v.read_file(v.path(path))

def plist(path, vol=371006):
    b = read(path, vol)
    return plistlib.loads(b)

def xattrs(path, vol=371006):
    v = fs(vol)
    return v.xattrs(v.path(path))

def inode(path, vol=371006):
    v = fs(vol)
    return v.inode(v.path(path))

def ts(ns):
    import datetime
    if not ns:
        return ""
    sec = ns / 1e9
    return datetime.datetime.utcfromtimestamp(sec + 8 * 3600).strftime("%Y-%m-%d %H:%M:%S")

if __name__ == "__main__":
    cmd = sys.argv[1]
    a = sys.argv[2]
    if cmd == "ls":
        ls(a)
    elif cmd == "read":
        sys.stdout.write(read(a).decode("utf-8", "replace"))
    elif cmd == "inode":
        print(inode(a))
    elif cmd == "xattr":
        for k, v in xattrs(a).items():
            print(k, v["flags"], v["size"], v["data"][:120])
