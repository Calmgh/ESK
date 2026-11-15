#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_cm02_idx.py -- 一次性全树叶索引，再用索引做目录/文件/xattr 查询（只读）"""
import pickle
import struct
import sys
import time

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
import apfs_fs as F  # noqa: E402
import apfs_map as M  # noqa: E402

T_INODE, T_XATTR, T_FILE_EXTENT, T_DREC = 3, 4, 8, 9
IDX = r"E:\ALL\AAAI\Works\RE\meiya\out\cm02_idx.pkl"


def build(vol_oid=371006, save=True):
    c = M.Container()
    c.scan(800000, 1400000, verbose=False)
    v = F.VolFS(c, vol_oid)
    drec = {}    # parent -> [(name, file_id, date_added, flags)]
    inode = {}   # obj_id -> val bytes
    xattr = {}   # obj_id -> [(name, valbytes)]
    ext = {}     # obj_id -> [(logical, len, paddr)]
    t0 = time.time()
    stack = [v.root_paddr]
    leaves = 0
    while stack:
        paddr = stack.pop()
        n = v.node(paddr)
        if n.level > 0:
            for i in reversed(range(n.nkeys)):
                stack.append(v._child(n, i))
            continue
        leaves += 1
        for i in range(n.nkeys):
            k = v.key_bytes(n, i)
            vb = v.val_bytes(n, i)
            kv = struct.unpack_from("<Q", k, 0)[0]
            oid, typ = kv & 0x0FFFFFFFFFFFFFFF, kv >> 60
            if typ == T_DREC:
                nlh = struct.unpack_from("<I", k, 8)[0]
                nl = nlh & 0x3FF
                nm = k[12:12 + nl].split(b"\x00")[0].decode("utf-8", "replace")
                fid, added, flags = struct.unpack_from("<QQH", vb, 0)
                drec.setdefault(oid, []).append((nm, fid, added, flags))
            elif typ == T_INODE:
                inode[oid] = vb
            elif typ == T_XATTR:
                nl = struct.unpack_from("<H", k, 8)[0]
                nm = k[10:10 + nl].decode("utf-8", "replace")
                xattr.setdefault(oid, []).append((nm, vb))
            elif typ == T_FILE_EXTENT:
                la = struct.unpack_from("<Q", k, 8)[0]
                lnk, pa = struct.unpack_from("<QQ", vb, 0)
                ext.setdefault(oid, []).append((la, lnk & 0x00FFFFFFFFFFFFFF, pa))
    for d in ext.values():
        d.sort()
    print("leaves=%d %.1fs drec_dirs=%d inodes=%d xattr_objs=%d extent_objs=%d" % (
        leaves, time.time() - t0, len(drec), len(inode), len(xattr), len(ext)))
    blob = dict(drec=drec, inode=inode, xattr=xattr, ext=ext,
                root=v.root_paddr, oidmap=c.oidmap, bs=c.bs,
                vols=c.volumes, part_off=M.PART_OFF, path=M.PATH)
    if save:
        with open(IDX, "wb") as f:
            pickle.dump(blob, f)
    return blob


def load():
    with open(IDX, "rb") as f:
        return pickle.load(f)


if __name__ == "__main__":
    b = build()
    print("saved", IDX)
