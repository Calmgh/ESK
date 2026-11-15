#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""apfs_btree.py -- APFS B-tree 遍历（**未完成**，见下方状态）

═══════════════════════════════════════════════════════════════════
状态：2026-11-15 实测 CM-02.E01
═══════════════════════════════════════════════════════════════════
已解决（用真实检材验证过）
  ✓ nx_omap_oid / apfs_omap_oid 指向的是 **apfs_omap_phys 对象**，
    不是 B-tree 根。真根在 om_tree_oid@0x30；om_tree_type@0x28
    带 OBJ_PHYSICAL(0x40000000) 时该值就是物理地址。
    实测：nx_omap_oid=870244 -> om_tree_oid=870247
  ✓ OBJ_* 标志位：PHYSICAL=0x40000000、EPHEMERAL=0x80000000
    （旧代码把 PHYSICAL 写成 0x80000000 是错的）
  ✓ 节点头长度 0x38，btn_flags@0x20 / level@0x22 / nkeys@0x24 /
    table_space@0x28(off,len) —— 这几个字段实测正确
  ✓ resolve_tree_root() 能把 omap 对象解析成树根

未解决（这就是"没打通"的部分）
  ✗ FIXED_KV 节点的 TOC 布局对不上。实测节点：
        flags=0x0007(ROOT|LEAF|FIXED_KV) level=0 nkeys=6
        table_off=0x0  table_len=0x1C0(448)
        TOC @0x38: 0000 1000 4000 5000 1000 2000 5000 6000
                   6000 7000 3000 4000 3000 4000 0000 0000
    按 4 字节 kvoff（k_off,v_off）解：v-k 恒为 16，符合"键值各 16 字节"，
    但 k_off 出现 0，且 k/v 偏移区间互相重叠（0x10 既是 e0 的 v_off
    又是 e2 的 k_off），与 16B 定长键值不自洽。
    原因未定：可能是 offsets 的基准不是"节点末尾"，也可能定长节点
    的 TOC 项是别的结构。

  ✗ 因此 walk() / lookup() 在本实现下**读不出有效条目**，不要用来下结论。

当前可用的替代路径
  用 apfs_map.py 的「按物理块扫 o_oid 建 oid->paddr 目录」——
  这条路虽然不能遍历，但能拿到卷与树根的物理地址，够做文件级读取。
  实测 CM-02 上它给出的卷 paddr=876153、FS 树根=900504 都对得上。

如果你要继续攻这一块
  1. 取一个小的卷（Preboot 最合适，几百个文件）
  2. 同时用 dpp / apfs-fuse 读同一个节点，对比它们解析出的 key 字节
  3. 有了"这个节点的第 0 条键长什么样"这个已知量，再反推 TOC 语义
  4. 不要靠猜——猜出来的解析器会静默给出错误键值，比报错危险
═══════════════════════════════════════════════════════════════════

模块提供：
    BTreeNode           单节点解析（TOC 是否可信见上）
    walk() / lookup()   遍历与查找（**FIXED_KV 场景下不可用**）
    resolve_tree_root() omap 对象 -> 树根 paddr（已实测可用）
    dump_node()         节点摘要，便于人工核对
"""

btree_node_phys 布局（关键：头是 0x38 字节，不是 0x28）
    0x00  obj_phys        32 B
    0x20  btn_flags       u16      BTNODE_ROOT=0x01 LEAF=0x02 FIXED_KV=0x04 HASHED=0x08 NOHEADER=0x10
    0x22  btn_level       u16      0 = 叶子
    0x24  btn_nkeys       u32
    0x28  btn_table_space { u16 off; u16 len; }   -> TOC 起点 = 0x38 + off
    0x2C  btn_free_space_off     u16
    0x2E  btn_free_space_len     u16
    0x30  btn_key_free_list_off  u16
    0x32  btn_key_free_list_len  u16
    0x34  btn_val_free_list_off  u16
    0x36  btn_val_free_list_len  u16
    0x38  btn_data[]

TOC —— 这里是之前一直没打通的地方
    定长节点（flags & 0x04）：nkeys 个 kvloc_t（8 B）= {nloc k; nloc v;}
        每条 = k.off(2) k.len(2) v.off(2) v.len(2)
    变长节点（无 0x04）：
        **两张并列数组**，起点都是 0x38 + table_space.off
        数组 A: nkeys 个 kvoff_t（4 B）= {u16 k_off; u16 v_off;}
        数组 B: 紧接其后，nkeys 个 kvloc_t（8 B）= {nloc k; nloc v;}
        即 b_off = a_off + nkeys*4

    所有 off 都是「相对节点末尾」的负偏移：
        绝对位置 = node_size - off

之前只读了一张数组，偏移与长度混用，于是"每种解释都只命中一半节点的键"。

提供：
    BTreeNode    单个节点解析（keys/values/子指针）
    walk()       深度优先遍历，产出 (key, val)
    lookup()     按键查值（B-tree 有序，逐层二分）
    dump_node()  打印节点摘要，便于核对
"""

import struct

# obj_phys_t.o_type 的标志位（与 OMAP 类型号共存于同一 u32）
OBJ_VIRTUAL = 0x00000000
OBJ_EPHEMERAL = 0x80000000
OBJ_PHYSICAL = 0x40000000
OBJ_NOHEADER = 0x20000000
OBJ_ENCRYPTED = 0x10000000
OBJ_NONPERSISTENT = 0x08000000

OBJ_BTREE = 0x02
OBJ_BTREE_NODE = 0x03
OBJ_OMAP = 0x0B
OBJ_FS = 0x0D
OBJ_PHYS_MASK = OBJ_PHYSICAL

BTNODE_ROOT = 0x0001
BTNODE_LEAF = 0x0002
BTNODE_FIXED_KV_SIZE = 0x0004
BTNODE_HASHED = 0x0008
BTNODE_NOHEADER = 0x0010

HEADER_LEN = 0x38

# apfs_omap_phys：om_tree_type@0x28(u32)，om_tree_oid@0x30(u64)
OMAP_TREE_TYPE_OFF = 0x28
OMAP_TREE_OID_OFF = 0x30


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


class BTreeNode(object):
    """一个 btree_node_phys"""

    __slots__ = ("data", "size", "flags", "level", "nkeys",
                 "table_off", "table_len", "_kv")

    def __init__(self, data, size=None):
        self.data = data
        self.size = size or len(data)
        if len(data) < HEADER_LEN:
            raise ValueError("节点太短: %d" % len(data))
        self.flags = u16(data, 0x20)
        self.level = u16(data, 0x22)
        self.nkeys = u32(data, 0x24)
        self.table_off = u16(data, 0x28)
        self.table_len = u16(data, 0x2A)
        self._kv = None

    # ---------------- 元信息 ----------------
    @property
    def is_leaf(self):
        return bool(self.flags & BTNODE_LEAF) or self.level == 0

    @property
    def is_root(self):
        return bool(self.flags & BTNODE_ROOT)

    @property
    def fixed_kv(self):
        return bool(self.flags & BTNODE_FIXED_KV_SIZE)

    def info(self):
        return {
            "level": self.level,
            "nkeys": self.nkeys,
            "flags": "0x%04X%s%s%s" % (
                self.flags,
                " ROOT" if self.is_root else "",
                " LEAF" if self.is_leaf else "",
                " FIXED_KV" if self.fixed_kv else ""),
            "table_off": self.table_off,
            "table_len": self.table_len,
        }

    # ---------------- TOC ----------------
    def _parse_toc(self):
        """返回 [(k_off,k_len,v_off,v_len)]，全部是「相对末尾的负偏移」"""
        if self._kv is not None:
            return self._kv
        d = self.data
        n = self.nkeys
        base = HEADER_LEN + self.table_off
        out = []

        if self.fixed_kv:
            # 定长：nkeys 个 kvloc_t（8 B）
            need = base + n * 8
            if need > len(d):
                raise ValueError("定长 TOC 越界: need %d > %d" % (need, len(d)))
            for i in range(n):
                o = base + i * 8
                out.append((u16(d, o), u16(d, o + 2),
                            u16(d, o + 4), u16(d, o + 6)))
        else:
            # 变长：先 kvoff_t（4 B）× n，再 kvloc_t（8 B）× n
            a_off = base
            b_off = base + n * 4
            if b_off + n * 8 > len(d):
                raise ValueError("变长 TOC 越界: need %d > %d"
                                 % (b_off + n * 8, len(d)))
            for i in range(n):
                oa = a_off + i * 4
                ob = b_off + i * 8
                k_off = u16(d, oa)
                v_off = u16(d, oa + 2)
                k_len = u16(d, ob + 2)
                v_len = u16(d, ob + 6)
                out.append((k_off, k_len, v_off, v_len))
        self._kv = out
        return out

    def _slice(self, off, ln):
        """off 是相对末尾的负偏移"""
        start = self.size - off
        if ln == 0:
            # 长度未知时，取到下一个条目的起点（调用方按需再截）
            return self.data[start:start + 0]
        if start < 0 or start + ln > len(self.data):
            raise ValueError("切片越界: size=%d off=%d len=%d" % (self.size, off, ln))
        return self.data[start:start + ln]

    # ---------------- 键值 ----------------
    def keys(self):
        if self.nkeys:
            self._parse_toc()
        return [self._slice(k[0], k[1]) for k in (self._kv or [])]

    def values(self):
        if self.nkeys:
            self._parse_toc()
        return [self._slice(k[2], k[3]) for k in (self._kv or [])]

    def items(self):
        if self.nkeys:
            self._parse_toc()
        return [(self._slice(k[0], k[1]), self._slice(k[2], k[3]))
                for k in (self._kv or [])]

    def raw_key(self, i):
        """不解长度，直接从 k_off 到 v_off 之间取（用于长度字段缺失时）"""
        if self.nkeys:
            self._parse_toc()
        k = self._kv[i]
        start = self.size - k[0]
        return self.data[start:start + (k[1] or 64)]


# ============================================================
# 对象层：把 paddr/block_size 变成节点
# ============================================================
class TreeReader(object):
    """按 block_size 读 B-tree 节点

    read_block(paddr) -> bytes(block_size)
    """

    def __init__(self, read_block, block_size, cache_size=256):
        self.read_block = read_block
        self.bs = block_size
        self._cache = {}
        self._order = []
        self._cap = cache_size

    def node(self, paddr):
        n = self._cache.get(paddr)
        if n is not None:
            return n
        raw = self.read_block(paddr)
        if len(raw) < HEADER_LEN:
            raise ValueError("paddr %d 读不到节点（%d 字节）" % (paddr, len(raw)))
        n = BTreeNode(raw, self.bs)
        self._cache[paddr] = n
        self._order.append(paddr)
        if len(self._order) > self._cap:
            old = self._order.pop(0)
            self._cache.pop(old, None)
        return n

    # ---------------- 遍历 ----------------
    def walk(self, root_paddr, max_nodes=200000, progress=None):
        """深度优先，产出 (key, val, paddr)"""
        stack = [(root_paddr, 0)]
        seen = set()
        visited = 0
        while stack:
            paddr, depth = stack.pop()
            if paddr in seen:
                continue
            seen.add(paddr)
            visited += 1
            if visited > max_nodes:
                raise RuntimeError("遍历节点数超过上限 %d，可能有环" % max_nodes)
            if progress:
                progress(visited, depth, paddr)
            n = self.node(paddr)
            if n.is_leaf:
                for k, v in n.items():
                    yield (k, v, paddr)
            else:
                # 内部节点：value 就是子节点 paddr
                for k, v in n.items():
                    child = self._child_paddr(v)
                    if child:
                        stack.append((child, depth + 1))

    @staticmethod
    def _child_paddr(val):
        """内部节点的 value 是 u64 子节点物理地址（或含 flags 的 u64）"""
        if len(val) >= 8:
            v = struct.unpack_from("<Q", val, 0)[0]
            return v & 0x7FFFFFFFFFFF            # 掩掉可能的 OMAP_VAL 标志
        if len(val) >= 4:
            return struct.unpack_from("<I", val, 0)[0]
        return None

    def lookup(self, root_paddr, target_key, cmp_fn=None):
        """按键查找。cmp_fn(key, target) -> <0 / 0 / >0

        B-tree 有序，逐层找第一个 >= target 的槽位（或按 cmp_fn 决定方向）
        """
        paddr = root_paddr
        guard = 0
        while guard < 64:
            guard += 1
            n = self.node(paddr)
            if n.nkeys == 0:
                return None
            items = n.items()
            idx = None
            if cmp_fn is None:
                # 默认：按字节比较
                for i, (k, v) in enumerate(items):
                    if k >= target_key:
                        idx = i
                        break
                if idx is None:
                    idx = len(items) - 1
            else:
                for i, (k, v) in enumerate(items):
                    if cmp_fn(k, target_key) >= 0:
                        idx = i
                        break
                if idx is None:
                    idx = len(items) - 1
            k, v = items[idx]
            if n.is_leaf:
                if cmp_fn is None:
                    return (k, v) if k == target_key else None
                return (k, v) if cmp_fn(k, target_key) == 0 else None
            paddr = self._child_paddr(v)
            if not paddr:
                return None
        raise RuntimeError("lookup 层数超过 64，可能有环")


def dump_node(node, limit=6):
    """打印一个节点，便于人工核对"""
    i = node.info()
    print("  node level=%d nkeys=%d flags=%s table_off=0x%X table_len=0x%X"
          % (i["level"], i["nkeys"], i["flags"], i["table_off"], i["table_len"]))
    try:
        items = node.items()
    except Exception as e:
        print("    TOC 解析失败:", e)
        return
    for n, (k, v) in enumerate(items[:limit]):
        print("    [%d] key(%d)=%s  val(%d)=%s"
              % (n, len(k), k[:24].hex(), len(v), v[:24].hex()))
    if len(items) > limit:
        print("    ... 共 %d 项" % len(items))


def resolve_tree_root(block, read_block=None):
    """从 omap / btree 对象里取出真正的 B-tree 根物理地址

    nx_omap_oid 和 apfs_omap_oid 指向的是 **apfs_omap_phys 对象**，不是树根。
    树上根在 om_tree_oid@0x30；om_tree_type@0x28 若带 OBJ_PHYSICAL 则它就是 paddr。

    传入一个 4096 字节的块，返回 (root_paddr, 说明)
    """
    otype = u32(block, 0x18)
    base = otype & 0xFFFF
    if base == OBJ_OMAP:
        tree_type = u32(block, OMAP_TREE_TYPE_OFF)
        tree_oid = u64(block, OMAP_TREE_OID_OFF)
        phys = bool(tree_type & OBJ_PHYSICAL)
        return (tree_oid if phys else None,
                "omap: tree_type=0x%08X tree_oid=%d physical=%s"
                % (tree_type, tree_oid, phys))
    if base == OBJ_BTREE:
        return u64(block, 0x08), "btree: oid 即 paddr"
    return None, "不是 omap/btree 对象（o_type=0x%08X）" % otype


if __name__ == "__main__":
    print("apfs_btree 模块已加载。")
    print("  BTreeNode(data, block_size)      单节点解析")
    print("  TreeReader(read_block, bs)       节点读取 + 缓存")
    print("  TreeReader.walk(root_paddr)      深度优先遍历")
    print("  TreeReader.lookup(root, key)     按键查找")
