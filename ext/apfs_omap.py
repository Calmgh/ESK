#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""apfs_omap.py -- APFS 对象映射表（omap）高层封装

把 apfs_btree 的底层遍历包成「oid -> paddr」查表，供虚树使用。

关键概念（踩过的坑）
─────────────────────────────────────────────────────────────
* 容器 omap 与卷 omap 都是 **physical** 树（btree_info.flags 含
  BTREE_PHYSICAL=0x10），内部节点值就是 paddr，直接可用。

* **文件系统树是虚树**（flags 里没有 BTREE_PHYSICAL），内部节点值
  是 **oid**，必须先过 omap 翻译成 paddr。直接把 oid 当 paddr 读，
  会读到无关块（表现为 nkeys=0、flags=0x0000 的"空节点"）。

* omap 键是 (oid, xid)，同一个 oid 有多个历史版本，取 **xid 最大**的那个。

* `nx_omap_oid` / `apfs_omap_oid` 指向 apfs_omap_phys 对象，不是树根，
  真根在 om_tree_oid@0x30。若 om_tree_type 含 OBJ_PHYSICAL，该值即 paddr；
  否则还要再翻译一层。

用法：
    om = Omap.from_omap_object(read_block, bs, omap_oid)
    paddr = om.get(root_tree_oid)
    om.build(read_block, bs, omap_paddr)   # 或直接给 omap 对象的 paddr
"""

import struct

import apfs_btree as BT

__all__ = ["Omap", "OMAP_VAL_DELETED", "OMAP_VAL_ENCRYPTED", "OMAP_VAL_NOHEADER"]

OMAP_VAL_DELETED = 0x01
OMAP_VAL_SAVED = 0x02
OMAP_VAL_ENCRYPTED = 0x04
OMAP_VAL_NOHEADER = 0x08
OMAP_VAL_CRYPTO_GENERATION = 0x10


class Omap(object):
    """oid -> paddr 映射（取 xid 最大版本）"""

    def __init__(self):
        self.map = {}          # oid -> (xid, paddr, size, flags)
        self.info = {}
        self.entries = 0
        self.nodes = 0

    # ---------------- 构建 ----------------
    @classmethod
    def build(cls, read_block, block_size, omap_paddr, max_nodes=100000,
              max_xid=None):
        """从 omap 对象的 paddr 构建映射表

        max_xid —— **重要的语义开关**

          参考实现（apfs-fuse `ApfsNodeMapperBTree.cpp:97` 用
          `Lookup(..., exact=false)` 即 FindMode::LE；`go-apfs`
          `GetOMapEntry(r, oid, maxXid)` 遇到 `Key.Xid > maxXid` 就回退）
          都是取「**xid ≤ max_xid 的最大版本**」。

          本函数默认 `max_xid=None` → 取全局最大 xid（宽松模式）。
          这与参考实现**不完全等价**：如果镜像是某个快照点的副本，
          全局最大可能取到「比快照更新」的版本。

          要严格对齐参考实现，传 `max_xid=<卷头 xid 或树 xid>`。

        跳过 `OMAP_VAL_DELETED(0x1)` 的条目（apfs-fuse BTree.cpp:403-406 同样跳过）。
        """
        self = cls()
        blk = read_block(omap_paddr)
        if len(blk) < 0x40:
            raise ValueError("omap 对象读不到（paddr=%d）" % omap_paddr)
        otype = BT.u32(blk, 0x18)
        if (otype & 0xFFFF) != BT.OBJ_OMAP:
            raise ValueError("paddr=%d 不是 omap 对象（o_type=0x%08X）"
                             % (omap_paddr, otype))

        self.info["omap_paddr"] = omap_paddr
        self.info["omap_xid"] = BT.u64(blk, 0x10)
        om_flags = BT.u32(blk, 0x20)
        self.info["om_flags"] = om_flags
        self.info["encrypting"] = bool(om_flags & 0x02)
        tree_type = BT.u32(blk, BT.OMAP_TREE_TYPE_OFF)
        tree_oid = BT.u64(blk, BT.OMAP_TREE_OID_OFF)
        self.info["tree_type"] = tree_type
        self.info["tree_oid"] = tree_oid
        self.info["physical"] = bool(tree_type & BT.OBJ_PHYSICAL)
        self.info["max_xid"] = max_xid

        if not self.info["physical"]:
            raise NotImplementedError(
                "该 omap 的树不是物理树（tree_type=0x%08X），需先翻译一层；"
                "当前未实现" % tree_type)

        self.skipped_deleted = 0
        tr = BT.TreeReader(read_block, block_size)
        for k, v, paddr in tr.walk(tree_oid, max_nodes=max_nodes):
            if len(k) < 16 or len(v) < 16:
                continue
            oid = BT.u64(k, 0)
            xid = BT.u64(k, 8)
            flags = BT.u32(v, 0)
            size = BT.u32(v, 4)
            paddr_v = BT.u64(v, 8)

            if flags & OMAP_VAL_DELETED:
                self.skipped_deleted += 1
                continue
            if max_xid is not None and xid > max_xid:
                continue

            self.entries += 1
            prev = self.map.get(oid)
            if prev is None or xid > prev[0]:
                self.map[oid] = (xid, paddr_v, size, flags)

        self.nodes = len(tr._cache)
        info = tr.info or {}
        self.info["key_count"] = info.get("key_count")
        self.info["node_count"] = info.get("node_count")
        return self

    # ---------------- 查询 ----------------
    def get(self, oid, default=None):
        e = self.map.get(oid)
        return e[1] if e else default

    def get_full(self, oid):
        return self.map.get(oid)

    def __contains__(self, oid):
        return oid in self.map

    def __len__(self):
        return len(self.map)

    def resolve(self, oid):
        """给 apfs_btree.TreeReader.walk 当 resolve 回调用"""
        return self.get(oid)

    def summary(self):
        ks = list(self.map.keys())
        return {
            "entries": self.entries,
            "unique_oids": len(self.map),
            "min_oid": min(ks) if ks else None,
            "max_oid": max(ks) if ks else None,
            **self.info,
        }


if __name__ == "__main__":
    print("apfs_omap：把 omap 树包成 oid -> paddr 查表。")
    print("  Omap.build(read_block, bs, omap_paddr)")
    print("  om.get(oid) / om.resolve(oid) / om.summary()")
