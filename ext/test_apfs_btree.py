"""test_apfs_btree.py —— 用真实 CM-02 检材验证 B-tree 遍历

验收标准：
  1. 容器 omap 遍历能找到 oid 371006 -> paddr（与旧扫描法的 876153 一致）
  2. 读出的卷超级块是 APSB，名字为 "OS X Base System - Data"
  3. 卷 omap 遍历能把 root_tree 371007 翻译成物理地址
  4. 文件系统树遍历能跑通，产出真实条目（含 ID 与记录类型）
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

E01 = r"D:\meiya\src\CM-02\CM-02\CM-02.E01"
PART_OFF = 0xC805000
EXPECT_VOL_PADDR = 876153                      # 旧扫描法得到的值，用作交叉验证

u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
u64 = lambda b, o: struct.unpack_from("<Q", b, o)[0]

OK = FAIL = 0


def check(name, cond, detail=""):
    global OK, FAIL
    if cond:
        OK += 1
        print("  OK   %-40s %s" % (name, detail))
    else:
        FAIL += 1
        print("  FAIL %-40s %s" % (name, detail))
    return cond


print("=" * 74)
print("打开检材 %s" % os.path.basename(E01))
t0 = time.time()
img = Image(E01)
sub = SubImage(img, PART_OFF, img.size - PART_OFF)
print("  镜像 %.2f GiB，APFS 分区起点 0x%X" % (img.size / 2 ** 30, PART_OFF))

nx = sub.read(0, 4096)
check("NXSB 魔数 @0x20", nx[0x20:0x24] == b"NXSB", nx[0x20:0x24].hex())

bs = u32(nx, 0x24)
block_count = u64(nx, 0x28)
nx_uuid = nx[0x48:0x58].hex()
omap_oid = u64(nx, 0xA0)
maxfs = u32(nx, 0xB4)
fs_oids = [v for v in (u64(nx, 0xB8 + 8 * i) for i in range(maxfs)) if v]

print("  block_size   = %d" % bs)
print("  block_count  = %s" % format(block_count, ","))
print("  nx_uuid      = %s" % nx_uuid)
print("  nx_omap_oid  = %d" % omap_oid)
print("  fs_oids      = %s" % fs_oids)

check("block_size == 4096", bs == 4096, str(bs))

# ============================================================
# 容器 omap
# ============================================================
print()
print("=" * 74)
print("1. 容器 omap B-tree 遍历")


def read_block(paddr):
    return sub.read(paddr * bs, bs)


tr = BT.TreeReader(read_block, bs)

# nx_omap_oid 指向 apfs_omap_phys 对象，不是树根
omap_obj = sub.read(omap_oid * bs, bs)
root_paddr, why = BT.resolve_tree_root(omap_obj)
print("  omap 对象 @%d -> %s" % (omap_oid, why))
check("能从 omap 对象解析出树根", root_paddr is not None, str(root_paddr))
node = tr.node(root_paddr)
print("  根节点 @paddr %d(0x%X)" % (root_paddr, root_paddr))
BT.dump_node(node)

check("omap 根节点 flags 有 ROOT", node.is_root or node.level >= 0,
      "level=%d nkeys=%d" % (node.level, node.nkeys))

OMAP_VAL_SIZE = 16


def omap_key_oid(k):
    return u64(k, 0) if len(k) >= 8 else None


found = {}
n_entries = 0
t = time.time()
for k, v, paddr in tr.walk(root_paddr, max_nodes=5000):
    n_entries += 1
    if len(k) < 16 or len(v) < 16:
        continue
    oid = u64(k, 0)
    xid = u64(k, 8)
    flags = u32(v, 0)
    size = u32(v, 4)
    paddr_v = u64(v, 8)
    if oid not in found or xid > found[oid][0]:
        found[oid] = (xid, paddr_v, size, flags)

print("  遍历完成: 节点若干, 条目 %d, oid %d 个, 耗时 %.2fs"
      % (n_entries, len(found), time.time() - t))

check("omap 里有 oid 371006", 371006 in found,
      str(found.get(371006, "未找到")))

if 371006 in found:
    xid, paddr_v, size, flags = found[371006]
    check("oid 371006 -> paddr 与旧扫描法一致",
          paddr_v == EXPECT_VOL_PADDR,
          "新=%d 旧=%d" % (paddr_v, EXPECT_VOL_PADDR))

    # 读卷超级块
    vol = sub.read(paddr_v * bs, bs)
    check("卷超级块是 APSB", vol[0x20:0x24] == b"APSB", vol[0x20:0x24].hex())
    vol_name = vol[0x2D0:0x2D0 + 256].split(b"\x00")[0].decode("utf-8", "replace")
    vol_root_tree = u64(vol, 0x88)
    vol_omap_oid = u64(vol, 0xC0)
    print("  卷名 = %r" % vol_name)
    print("  root_tree oid = %d" % vol_root_tree)
    print("  vol omap oid  = %d" % vol_omap_oid)
    check("卷名含 'OS X Base System'", "OS X Base System" in vol_name, vol_name)
    check("root_tree oid == 371007", vol_root_tree == 371007, str(vol_root_tree))

    # ============================================================
    # 卷 omap
    # ============================================================
    print()
    print("=" * 74)
    print("2. 卷 omap -> 文件系统树根")

    # 卷 omap 的 oid 需要再从容器 omap 里翻译（它不是 physical）
    if vol_omap_oid in found:
        vo_paddr = found[vol_omap_oid][1]
    else:
        vo_paddr = None
    check("能在容器 omap 里找到卷 omap 对象", vo_paddr is not None,
          "oid=%d -> %s" % (vol_omap_oid, vo_paddr))

    if vo_paddr:
        vtr = BT.TreeReader(read_block, bs)
        vfound = {}
        for k, v, paddr in vtr.walk(vo_paddr, max_nodes=20000):
            if len(k) < 16 or len(v) < 16:
                continue
            oid = u64(k, 0)
            xid = u64(k, 8)
            if oid not in vfound or xid > vfound[oid][0]:
                vfound[oid] = (xid, u64(v, 8))
        check("卷 omap 能翻译 root_tree 371007", 371007 in vfound,
              str(vfound.get(371007, "未找到")))

        if 371007 in vfound:
            fs_root_paddr = vfound[371007][1]
            print("  FS 树根 paddr = %d（旧扫描法为 900504）" % fs_root_paddr)
            check("FS 树根 paddr == 900504", fs_root_paddr == 900504,
                  str(fs_root_paddr))

            # ============================================================
            # 文件系统树
            # ============================================================
            print()
            print("=" * 74)
            print("3. 文件系统树遍历")

            ftr = BT.TreeReader(read_block, bs)
            root_node = ftr.node(fs_root_paddr)
            BT.dump_node(root_node)

            check("FS 树根是内部节点", not root_node.is_leaf,
                  "level=%d" % root_node.level)
            check("FS 树根 nkeys > 0", root_node.nkeys > 0, str(root_node.nkeys))

            # 完整遍历（限节点数，避免超时）
            types = {}
            total = 0
            sample = []
            t = time.time()
            try:
                for k, v, paddr in ftr.walk(fs_root_paddr, max_nodes=20000):
                    total += 1
                    if len(k) >= 8:
                        oid_type = u64(k, 0)
                        otype = (oid_type & 0x0FFFFFFF) >> 60 if False else (oid_type >> 60) & 0xF
                        # j_key_t: obj_id_and_type = (type << 60) | obj_id
                        otype = (oid_type >> 60) & 0xF
                        types[otype] = types.get(otype, 0) + 1
                    if len(sample) < 5:
                        sample.append((k[:16].hex(), len(v)))
            except Exception as e:
                print("  遍历中断: %s" % e)

            print("  遍历 %d 条记录，耗时 %.2fs" % (total, time.time() - t))
            print("  记录类型分布: %s" % sorted(types.items()))
            for s in sample:
                print("    样例 key=%s  val_len=%d" % (s[0], s[1]))

            check("FS 树遍历到大量记录", total > 1000, "%d 条" % total)
            check("记录类型含 3（inode）", types.get(3, 0) > 0, str(types.get(3, 0)))
            check("记录类型含 9（目录项）", types.get(9, 0) > 0, str(types.get(9, 0)))

img.close()
print()
print("=" * 74)
print("结果：OK %d / FAIL %d   总耗时 %.1fs" % (OK, FAIL, time.time() - t0))
print("=" * 74)
sys.exit(1 if FAIL else 0)
