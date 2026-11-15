#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""apfs_btree.py -- APFS B-tree 完整遍历

算法依据：apfs-fuse `ApfsLib/BTree.cpp`（BTreeNodeFix::GetEntry /
BTreeNodeVar::GetEntry）与 `ApfsLib/DiskStruct.h` 的结构定义，
并用真实检材 CM-02.E01 逐项验算通过。

关键点（之前踩过的坑都在这）
─────────────────────────────────────────────────────────────
1) TOC 起点 = 节点头之后 0x38，`btn_table_space.off` 恒为 0
   （apfs-fuse 里有 assert(m_btn->btn_table_space.off == 0)）

2) **键向前排，值向后排**，两者基准不同：
       keys_start = 0x38 + btn_table_space.len
       vals_start = (ROOT ? node_size - 40 : node_size)
       key = data[keys_start + k_off : ...]
       val = data[vals_start - v_off : ...]
   所以 k_off 与 v_off 的数值集合"看起来重叠"是正常的，
   它们量的是两个相反方向的坐标，不是同一空间。

3) root 节点末尾嵌一个 40 字节 `btree_info_t`：
       bt_flags u32 / bt_node_size u32 / bt_key_size u32 / bt_val_size u32
       bt_longest_key u32 / bt_longest_val u32 / bt_key_count u64 / bt_node_count u64
   定长节点的键长/值长**不在 TOC 里**，只存在于这个结构。

4) 定长节点（BTNODE_FIXED_KV）TOC 是 kvoff_t(4B)：k_off(2) v_off(2)
   变长节点 TOC 是 kvloc_t(8B)：k_off(2) k_len(2) v_off(2) v_len(2)

5) 内部节点的值固定是 8 字节子节点 oid（定长节点里不是 bt_val_size）

6) BTOFF_INVALID = 0xFFFF 表示该条无值（ghost entry）

7) 常量：OBJ_PHYSICAL = 0x40000000（0x80000000 是 OBJ_EPHEMERAL）
   nx_omap_oid / apfs_omap_oid 指向 apfs_omap_phys 对象，
   真树根在 om_tree_oid@0x30

提供：
    BTreeNode      单节点解析（keys() / values() / items()）
    TreeReader     walk() / lookup() / 缓存
    resolve_tree_root()  omap 对象 -> 树根 paddr
    read_btree_info()    读 root 节点尾部的 btree_info_t
"""

import struct

# ---- obj_phys_t.o_type 的标志位 ----
OBJ_VIRTUAL = 0x00000000
OBJ_EPHEMERAL = 0x80000000
OBJ_PHYSICAL = 0x40000000
OBJ_NOHEADER = 0x20000000
OBJ_ENCRYPTED = 0x10000000
OBJ_NONPERSISTENT = 0x08000000
OBJ_PHYS_MASK = OBJ_PHYSICAL

OBJ_BTREE = 0x02
OBJ_BTREE_NODE = 0x03
OBJ_OMAP = 0x0B
OBJ_FS = 0x0D

# ---- btn_flags ----
BTNODE_ROOT = 0x0001
BTNODE_LEAF = 0x0002
BTNODE_FIXED_KV_SIZE = 0x0004
BTNODE_HASHED = 0x0008
BTNODE_NOHEADER = 0x0010

# ---- btree_info_t.bt_flags ----
BTREE_UINT64_KEYS = 0x00000001
BTREE_SEQUENTIAL_INSERT = 0x00000002
BTREE_ALLOW_GHOSTS = 0x00000004
BTREE_EPHEMERAL = 0x00000008
BTREE_PHYSICAL = 0x00000010
BTREE_NONPERSISTENT = 0x00000020
BTREE_KV_NONALIGNED = 0x00000040
BTREE_HASHED = 0x00000080
BTREE_NOHEADER = 0x00000100

HEADER_LEN = 0x38           # sizeof(btree_node_phys_t)
BTREE_INFO_SIZE = 40        # sizeof(btree_info_t)
BTOFF_INVALID = 0xFFFF

# apfs_omap_phys: om_tree_type@0x28(u32), om_tree_oid@0x30(u64)
OMAP_TREE_TYPE_OFF = 0x28
OMAP_TREE_OID_OFF = 0x30


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def read_btree_info(block):
    """从 root 节点尾部读 btree_info_t（40 字节）"""
    if len(block) < BTREE_INFO_SIZE:
        return None
    t = block[len(block) - BTREE_INFO_SIZE:]
    return {
        "flags": u32(t, 0),
        "node_size": u32(t, 4),
        "key_size": u32(t, 8),
        "val_size": u32(t, 12),
        "longest_key": u32(t, 16),
        "longest_val": u32(t, 20),
        "key_count": u64(t, 24),
        "node_count": u64(t, 32),
    }


# ============================================================
# j_key_t 比较器
# ============================================================
OBJ_ID_MASK = 0x0FFFFFFFFFFFFFFF
OBJ_TYPE_SHIFT = 60

# obj_type 取值（j_key_t 的高 4 位）
J_TYPE_NAMES = {
    1: "snap_metadata",
    2: "extent",
    3: "inode",
    4: "xattr",
    5: "sibling_link",
    6: "sibling_map",
    7: "sibling_map_val",
    8: "file_extent",
    9: "drec",
    10: "dirstats",
    11: "snap_name_old",
    12: "snap_name",
}


def jkey_split(key):
    """拆出 (obj_id, obj_type)"""
    if len(key) < 8:
        return (0, 0)
    q = u64(key, 0)
    return (q & OBJ_ID_MASK, (q >> OBJ_TYPE_SHIFT) & 0xF)


def jkey_cmp(a, b):
    """APFS 文件系统树的键序：obj_id → obj_type → 剩余字节

    实测依据（CM-02 Data 卷遍历前若干条）：
        oid=1 type=9
        oid=2 type=3
        oid=2 type=4
        oid=2 type=9 ...
    即 obj_id 是主序、type 次序。若直接按 obj_id_and_type 的 u64 比较，
    type 在高位会把 type=9 的全部排到最前，与真实顺序相反。
    """
    oa, ta = jkey_split(a)
    ob, tb = jkey_split(b)
    if oa != ob:
        return -1 if oa < ob else 1
    if ta != tb:
        return -1 if ta < tb else 1
    ra, rb_ = a[8:], b[8:]
    if ra != rb_:
        return -1 if ra < rb_ else 1
    return 0


def jkey_make(obj_id, obj_type, tail=b""):
    """构造一个 j_key 字节串，便于传给 lookup"""
    q = ((obj_type & 0xF) << OBJ_TYPE_SHIFT) | (obj_id & OBJ_ID_MASK)
    return struct.pack("<Q", q) + tail


class BTreeNode(object):
    """一个 btree_node_phys

    fixed_kv 节点的键长/值长必须由树的 btree_info 提供，
    因此要把 info 传进来（TreeReader 会自动从 root 取）。
    """

    __slots__ = ("data", "size", "flags", "level", "nkeys",
                 "table_off", "table_len", "keys_start", "vals_start",
                 "info", "_items")

    def __init__(self, data, size=None, info=None):
        self.data = data
        self.size = size or len(data)
        if len(data) < HEADER_LEN:
            raise ValueError("节点太短: %d 字节" % len(data))

        self.flags = u16(data, 0x20)
        self.level = u16(data, 0x22)
        self.nkeys = u32(data, 0x24)
        self.table_off = u16(data, 0x28)
        self.table_len = u16(data, 0x2A)

        # 键向前、值向后（BTree.cpp:86-90）
        self.keys_start = HEADER_LEN + self.table_len
        self.vals_start = (self.size - BTREE_INFO_SIZE) if self.is_root else self.size

        self.info = info or (read_btree_info(data) if self.is_root else None)
        self._items = None

    # ---------------- 元信息 ----------------
    @property
    def is_leaf(self):
        return bool(self.flags & BTNODE_LEAF)

    @property
    def is_root(self):
        return bool(self.flags & BTNODE_ROOT)

    @property
    def fixed_kv(self):
        return bool(self.flags & BTNODE_FIXED_KV_SIZE)

    def info_dict(self):
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
            "keys_start": self.keys_start,
            "vals_start": self.vals_start,
        }

    # ---------------- 取条目 ----------------
    def _fixed_entry(self, i):
        """定长节点：TOC 是 kvoff_t（4 字节），长 0x38 + i*4"""
        o = HEADER_LEN + i * 4
        k_off = u16(self.data, o)
        v_off = u16(self.data, o + 2)

        k_len = (self.info or {}).get("key_size") or 0
        ks = self.keys_start + k_off
        key = self.data[ks:ks + k_len] if k_len else self.data[ks:ks + 64]

        if v_off == BTOFF_INVALID:
            return key, b""
        # 内部节点的值是 8 字节子 oid，不是 bt_val_size
        v_len = ((self.info or {}).get("val_size") or 0) if self.is_leaf else 8
        vs = self.vals_start - v_off
        if vs < 0 or vs >= self.size:
            raise ValueError("值偏移越界: v_off=%d -> vs=%d (size=%d)"
                             % (v_off, vs, self.size))
        val = self.data[vs:vs + v_len] if v_len else self.data[vs:vs + 32]
        return key, val

    def _var_entry(self, i):
        """变长节点：TOC 是 kvloc_t（8 字节），长 0x38 + i*8"""
        o = HEADER_LEN + i * 8
        k_off = u16(self.data, o)
        k_len = u16(self.data, o + 2)
        v_off = u16(self.data, o + 4)
        v_len = u16(self.data, o + 6)

        ks = self.keys_start + k_off
        if ks + k_len > self.size:
            raise ValueError("键越界: keys_start=%d k_off=%d k_len=%d"
                             % (self.keys_start, k_off, k_len))
        key = self.data[ks:ks + k_len]

        if v_off == BTOFF_INVALID:
            return key, b""
        vs = self.vals_start - v_off
        if vs < 0 or vs + v_len > self.size:
            raise ValueError("值越界: vals_start=%d v_off=%d v_len=%d"
                             % (self.vals_start, v_off, v_len))
        return key, self.data[vs:vs + v_len]

    def items(self):
        if self._items is not None:
            return self._items
        out = []
        try:
            if self.fixed_kv:
                for i in range(self.nkeys):
                    out.append(self._fixed_entry(i))
            else:
                for i in range(self.nkeys):
                    out.append(self._var_entry(i))
        except Exception:
            self._items = out
            raise
        self._items = out
        return out

    def keys(self):
        return [k for k, v in self.items()]

    def values(self):
        return [v for k, v in self.items()]

    def children(self):
        """内部节点的子 paddr 列表"""
        if self.is_leaf:
            return []
        out = []
        for k, v in self.items():
            if len(v) >= 8:
                out.append(u64(v, 0) & 0x7FFFFFFFFFFF)
        return out


# ============================================================
class TreeReader(object):
    """按 block_size 读 B-tree 节点并做缓存"""

    def __init__(self, read_block, block_size, cache_size=512):
        self.read_block = read_block
        self.bs = block_size
        self._cache = {}
        self._order = []
        self._cap = cache_size
        self.info = None          # 从 root 取到的 btree_info

    # ---------------- 节点 ----------------
    def node(self, paddr, is_root=None):
        n = self._cache.get(paddr)
        if n is not None:
            return n
        raw = self.read_block(paddr)
        if len(raw) < HEADER_LEN:
            raise ValueError("paddr %d 读不到节点（%d 字节）" % (paddr, len(raw)))
        flags = u16(raw, 0x20)
        if is_root is None:
            is_root = bool(flags & BTNODE_ROOT)
        # 先把 root 的 info 落地，供后续定长节点用
        info = self.info
        if is_root and info is None:
            info = read_btree_info(raw)
            self.info = info
        n = BTreeNode(raw, self.bs, info)
        self._cache[paddr] = n
        self._order.append(paddr)
        if len(self._order) > self._cap:
            old = self._order.pop(0)
            self._cache.pop(old, None)
        return n

    # ---------------- 遍历 ----------------
    def walk(self, root_paddr, resolve=None, max_nodes=200000, progress=None):
        """深度优先，产出 (key, val, paddr)

        resolve —— 虚树必备。虚树的内部节点值是 **oid**，不是 paddr，
                   必须经 omap 翻译。传 resolve(oid) -> paddr 或 None。
                   物理树（btree_info.flags 含 BTREE_PHYSICAL）不需要。
        """
        stack = [root_paddr]
        seen = set()
        visited = 0
        while stack:
            paddr = stack.pop()
            if not paddr or paddr in seen:
                continue
            seen.add(paddr)
            visited += 1
            if visited > max_nodes:
                raise RuntimeError("遍历节点数超过上限 %d（可能有环）" % max_nodes)
            if progress:
                progress(visited, len(seen), paddr)
            n = self.node(paddr)
            if n.is_leaf:
                for k, v in n.items():
                    yield (k, v, paddr)
            else:
                kids = []
                for ch in n.children():
                    if not ch:
                        continue
                    if resolve is not None:
                        ch = resolve(ch)
                        if not ch:
                            continue
                    kids.append(ch)
                # 逆序压栈，保证按 key 升序弹出
                for ch in reversed(kids):
                    stack.append(ch)

    def count_nodes(self, root_paddr, resolve=None):
        """只数节点与层级分布，不取键值"""
        seen = set()
        stack = [root_paddr]
        levels = {}
        while stack:
            p = stack.pop()
            if not p or p in seen:
                continue
            seen.add(p)
            n = self.node(p)
            levels[n.level] = levels.get(n.level, 0) + 1
            if not n.is_leaf:
                for c in n.children():
                    if not c:
                        continue
                    if resolve is not None:
                        c = resolve(c)
                        if not c:
                            continue
                    stack.append(c)
        return len(seen), levels

    # ---------------- 查找 ----------------
    def lookup(self, root_paddr, target_key, cmp_fn=None, resolve=None):
        """按键查找。

        cmp_fn  —— (key, target) -> <0 / 0 / >0；不传则按字节比较
        resolve —— 虚树必备，把子 oid 翻成 paddr（同 walk）

        注意：文件系统树实测定序为 **obj_id 优先、type 次之、再比名字**，
        与 `obj_id_and_type` 的原始 u64 顺序（type 在高位）**不同**。
        查 FS 树请传 jkey_cmp，否则会找错分支。

        返回 (key, val) 或 None。
        """
        paddr = root_paddr
        depth = 0

        def _cmp(x, y):
            if cmp_fn is not None:
                return cmp_fn(x, y)
            return -1 if x < y else (1 if x > y else 0)

        while depth < 64:
            depth += 1
            n = self.node(paddr)
            if n.nkeys == 0:
                return None
            items = n.items()

            if n.is_leaf:
                # 叶子：二分找精确匹配
                lo, hi = 0, len(items) - 1
                while lo <= hi:
                    mid = (lo + hi) // 2
                    c = _cmp(items[mid][0], target_key)
                    if c == 0:
                        return items[mid]
                    if c < 0:
                        lo = mid + 1
                    else:
                        hi = mid - 1
                return None

            # 内部节点：每项 (key, child) 表示 child 里的键都 >= key，
            # 因此要下降到「最后一个 key <= target」的子节点。
            idx = 0
            lo, hi = 0, len(items) - 1
            while lo <= hi:
                mid = (lo + hi) // 2
                if _cmp(items[mid][0], target_key) <= 0:
                    idx = mid
                    lo = mid + 1
                else:
                    hi = mid - 1

            v = items[idx][1]
            if len(v) < 8:
                return None
            child = u64(v, 0) & 0x7FFFFFFFFFFF
            if resolve is not None:
                child = resolve(child)
                if not child:
                    return None
            paddr = child
        raise RuntimeError("lookup 超过 64 层，可能有环")


# ============================================================
def resolve_tree_root(block):
    """从 omap / btree 对象里取出真正的 B-tree 根物理地址

    nx_omap_oid 与 apfs_omap_oid 指向 apfs_omap_phys 对象，不是树根：
        om_tree_type @0x28 (u32)
        om_tree_oid  @0x30 (u64)   <- 真树根
    返回 (root_paddr 或 None, 说明)
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
        return u64(block, 0x08), "btree: 对象本身就是树根"
    return None, "不是 omap/btree 对象（o_type=0x%08X）" % otype


def dump_node(node, limit=8):
    """打印节点摘要，便于人工核对"""
    d = node.info_dict()
    print("  node level=%d nkeys=%d flags=%s table_len=0x%X keys_start=%d vals_start=%d"
          % (d["level"], d["nkeys"], d["flags"], d["table_len"],
             d["keys_start"], d["vals_start"]))
    if node.info:
        print("    btree_info: key_size=%d val_size=%d key_count=%d node_count=%d flags=0x%X"
              % (node.info["key_size"], node.info["val_size"],
                 node.info["key_count"], node.info["node_count"], node.info["flags"]))
    try:
        items = node.items()
    except Exception as e:
        print("    取条目失败:", e)
        return
    for i, (k, v) in enumerate(items[:limit]):
        print("    [%d] key(%2d)=%s  val(%2d)=%s"
              % (i, len(k), k[:24].hex(), len(v), v[:24].hex()))
    if len(items) > limit:
        print("    ... 共 %d 项" % len(items))


if __name__ == "__main__":
    print("apfs_btree：按 apfs-fuse BTree.cpp 的算法实现。")
    print("  resolve_tree_root(block)         omap 对象 -> 树根 paddr")
    print("  TreeReader(read_block, bs)       节点读取 + 缓存")
    print("  TreeReader.walk(root)            深度优先遍历，按 key 升序")
    print("  TreeReader.lookup(root, key)     二分查找")
    print("  read_btree_info(block)           读 root 尾部的 btree_info_t")
