#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""test_apfs_btree.py —— 用真实 CM-02 检材验证 APFS B-tree 完整遍历

算法依据 apfs-fuse `ApfsLib/BTree.cpp`，逐项在真实数据上验算。

验收项：
  1. NXSB / block_size / 卷 OID 列表
  2. 容器 omap：从 apfs_omap_phys 解析出树根并遍历
  3. 卷超级块：omap_oid@0x80 / root_tree_oid@0x88 / volname@0x2C0
  4. 卷 omap：构建 oid->paddr 表，条目数与 btree_info 一致
  5. 虚树遍历：文件系统树记录数 == btree_info.key_count
  6. lookup 二分查找
"""

import io
import os
import struct
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ESK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ESK)
sys.path.insert(0, os.path.join(ESK, "ext"))

from mkit.image import Image, SubImage          # noqa: E402
import apfs_btree as BT                        # noqa: E402
import apfs_omap as OM                         # noqa: E402

E01 = r"D:\meiya\src\CM-02\CM-02\CM-02.E01"
PART_OFF = 0xC805000

u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
u64 = lambda b, o: struct.unpack_from("<Q", b, o)[0]

OK = FAIL = 0


def check(name, cond, detail=""):
    global OK, FAIL
    if cond:
        OK += 1
        print("  OK   %-42s %s" % (name, detail))
    else:
        FAIL += 1
        print("  FAIL %-42s %s" % (name, detail))
    return cond


t_all = time.time()
print("=" * 76)
print("打开检材 %s" % os.path.basename(E01))
img = Image(E01)
sub = SubImage(img, PART_OFF, img.size - PART_OFF)
bs = 4096
rb = lambda p: sub.read(p * bs, bs)
print("  镜像 %.2f GiB，APFS 分区起点 0x%X" % (img.size / 2 ** 30, PART_OFF))

# ============================================================
print()
print("=" * 76)
print("1. 容器超级块")
nx = sub.read(0, 4096)
check("NXSB 魔数 @0x20", nx[0x20:0x24] == b"NXSB", nx[0x20:0x24].hex())
block_size = u32(nx, 0x24)
block_count = u64(nx, 0x28)
omap_oid = u64(nx, 0xA0)
maxfs = u32(nx, 0xB4)
fs_oids = [v for v in (u64(nx, 0xB8 + 8 * i) for i in range(maxfs)) if v]
check("block_size == 4096", block_size == 4096, str(block_size))
check("卷 OID 6 个", len(fs_oids) == 6, str(fs_oids))
print("  block_count=%s  nx_uuid=%s" % (format(block_count, ","), nx[0x48:0x58].hex()))

# ============================================================
print()
print("=" * 76)
print("2. 容器 omap B-tree")
omap_blk = rb(omap_oid)
check("nx_omap_oid 指向 OBJ_OMAP 对象",
      (u32(omap_blk, 0x18) & 0xFFFF) == BT.OBJ_OMAP,
      "o_type=0x%08X" % u32(omap_blk, 0x18))

root_paddr, why = BT.resolve_tree_root(omap_blk)
check("从 omap 对象解析出树根", root_paddr is not None, str(root_paddr))

tr = BT.TreeReader(rb, bs)
cnode = tr.node(root_paddr)
print("  容器 omap 根: level=%d nkeys=%d flags=0x%04X"
      % (cnode.level, cnode.nkeys, cnode.flags))
if cnode.info:
    print("  btree_info: key_size=%d val_size=%d key_count=%d node_count=%d"
          % (cnode.info["key_size"], cnode.info["val_size"],
             cnode.info["key_count"], cnode.info["node_count"]))
check("容器 omap 是 FIXED_KV", cnode.fixed_kv, "flags=0x%04X" % cnode.flags)
check("容器 omap key/val 各 16 字节",
      bool(cnode.info) and cnode.info["key_size"] == 16 and cnode.info["val_size"] == 16)

cmap = {}
for k, v, p in tr.walk(root_paddr, max_nodes=5000):
    if len(k) < 16 or len(v) < 16:
        continue
    oid, xid = u64(k, 0), u64(k, 8)
    if oid not in cmap or xid > cmap[oid][0]:
        cmap[oid] = (xid, u64(v, 8))
check("容器 omap 条目数 == btree_info.key_count",
      len(cmap) == cnode.info["key_count"],
      "%d vs %d" % (len(cmap), cnode.info["key_count"]))
check("容器 omap 含 oid 371006", 371006 in cmap, str(cmap.get(371006)))

# ============================================================
print()
print("=" * 76)
print("3. 卷超级块（Data 卷）")
vol_paddr = cmap[371006][1]
vol = rb(vol_paddr)
check("卷超级块 magic = APSB", vol[0x20:0x24] == b"APSB")
check("卷 oid == 371006", u64(vol, 0x08) == 371006, str(u64(vol, 0x08)))

vol_name = vol[0x2C0:0x2C0 + 256].split(b"\x00")[0].decode("utf-8", "replace")
vol_omap_oid = u64(vol, 0x80)
vol_root_tree = u64(vol, 0x88)
check("volname @0x2C0", vol_name == "OS X Base System - Data", vol_name)
check("root_tree_oid @0x88 == 371007", vol_root_tree == 371007, str(vol_root_tree))
print("  卷 paddr=%d  omap_oid=%d  root_tree_oid=%d"
      % (vol_paddr, vol_omap_oid, vol_root_tree))

# ============================================================
print()
print("=" * 76)
print("4. 卷 omap -> oid->paddr 表")
t = time.time()
om = OM.Omap.build(rb, bs, vol_omap_oid)
print("  构建耗时 %.2fs" % (time.time() - t))
s = om.summary()
for k in ("entries", "unique_oids", "key_count", "node_count", "physical"):
    print("    %-14s %s" % (k, s.get(k)))

check("卷 omap 是物理树", s.get("physical") is True)
check("卷 omap 条目数 == btree_info.key_count",
      s["entries"] == s["key_count"], "%s vs %s" % (s["entries"], s["key_count"]))
check("卷 omap 能翻译 371007", om.get(371007) is not None, str(om.get(371007)))

fs_root_paddr = om.get(371007)
fs_root = BT.TreeReader(rb, bs).node(fs_root_paddr)
check("FS 树根是 ROOT 且非 LEAF",
      fs_root.is_root and not fs_root.is_leaf,
      "level=%d flags=0x%04X" % (fs_root.level, fs_root.flags))
check("FS 树是虚树（无 BTREE_PHYSICAL）",
      bool(fs_root.info) and not (fs_root.info["flags"] & BT.BTREE_PHYSICAL),
      "btree_flags=0x%X" % (fs_root.info["flags"] if fs_root.info else 0))

# ============================================================
print()
print("=" * 76)
print("5. 文件系统树完整遍历（虚树，需 omap 解析子 oid）")
ftr = BT.TreeReader(rb, bs)
t = time.time()
nrec = 0
types = {}
samples = []
for k, v, p in ftr.walk(fs_root_paddr, resolve=om.resolve, max_nodes=200000):
    nrec += 1
    if len(k) >= 8:
        ot = (u64(k, 0) >> 60) & 0xF
        types[ot] = types.get(ot, 0) + 1
    if len(samples) < 3:
        samples.append((k.hex(), len(v)))
print("  遍历 %s 条，耗时 %.1fs" % (format(nrec, ","), time.time() - t))
print("  类型分布: %s" % sorted(types.items()))
for hx, vl in samples:
    print("    key=%s val_len=%d" % (hx, vl))

TYPE_NAME = {
    3: "inode", 4: "xattr", 5: "sibling_link", 6: "sibling_map",
    8: "file_extent", 9: "drec", 10: "dirstats", 12: "snap_name",
}
print("  可读名: %s" % {TYPE_NAME.get(k, k): v for k, v in sorted(types.items())})

froot_info = ftr.info or {}
check("遍历条数 == btree_info.key_count",
      nrec == froot_info.get("key_count"),
      "%s vs %s" % (format(nrec, ","),
                    format(froot_info.get("key_count") or 0, ",")))
check("含 inode 记录（类型 3）", types.get(3, 0) > 1000, str(types.get(3, 0)))
check("含目录项记录（类型 9）", types.get(9, 0) > 1000, str(types.get(9, 0)))
check("含文件 extent（类型 8）", types.get(8, 0) > 1000, str(types.get(8, 0)))
check("含 xattr（类型 4）", types.get(4, 0) > 0, str(types.get(4, 0)))

# ============================================================
print()
print("=" * 76)
print("6. lookup 二分查找")
target = BT.jkey_make(2, 3)      # 根目录 inode：obj_id=2, type=3
got = ftr.lookup(fs_root_paddr, target, cmp_fn=BT.jkey_cmp, resolve=om.resolve)
check("lookup 能找到根目录 inode", got is not None,
      "key=%s" % (got[0].hex() if got else "None"))
if got:
    k, v = got
    mode = struct.unpack_from("<H", v, 0x50)[0] if len(v) >= 0x52 else 0
    print("  根目录 inode: val_len=%d mode=0o%o" % (len(v), mode))

img.close()
print()
print("=" * 76)
print("结果：OK %d / FAIL %d   总耗时 %.1fs" % (OK, FAIL, time.time() - t_all))
print("=" * 76)
sys.exit(1 if FAIL else 0)
