<!-- ESK · Calmgh06 -->
# APFS 技术笔记

> 适用：`ext/apfs_map.py` + `ext/apfs_fs.py`
> 本文记录实现过程中的结构发现与踩坑，可作为阅读代码的注解。

---

## 1. 为什么自建

`mkit.macart.Apfs` 只暴露两个方法：

```python
class Apfs:
    def info(self): ...      # 打印容器基本信息
    def volumes(self): ...   # 返回卷列表 —— 实测返回 0 条
```

对一个正常 APFS 容器，`volumes()` 返回 0 条意味着**无法列出卷**，更无法读文件。

因此 `ext/apfs_map.py` + `ext/apfs_fs.py` 重新实现了一条通路。

---

## 2. 容器定位

### 2.1 魔数在 0x20，不是 0

这是第一个坑。APFS 的每个对象都以 32 字节的 `obj_phys` 头开始：

```
struct obj_phys {
    uint8_t  o_cksum[8];      // Fletcher-64 校验
    uint64_t o_oid;           // 对象 ID
    uint64_t o_xid;           // 事务 ID
    uint32_t o_type;          // 类型 + 标志
    uint32_t o_subtype;
};
```

容器超级块 `NXSB` 的魔数就落在这个头的末尾，即**分区内偏移 0x20**。

```python
sub.read(0x20, 4) == b"NXSB"
```

只读前 8 字节会看不到任何魔数，容易误判为"这不是 APFS"或者"这是 FileVault 加密卷"——我在实践中就在这个误判上浪费了好几轮。

### 2.2 容器超级块字段

| 偏移 | 字段 | 实测样例 |
|---|---|---|
| 0x20 | `nx_magic` = "NXSB" | — |
| 0x24 | `nx_block_size` | 4096 |
| 0x28 | `nx_block_count` | 122,086,923 |
| 0x48 | `nx_xp_desc_blocks` | — |
| 0x68 | `nx_uuid` (16B) | 76910f91ac724b848daafe709c8f9119 |
| 0x88 | `nx_next_oid` | — |
| 0xA0 | `nx_max_file_systems` | 100 |
| 0xC0 | `nx_omap_oid` | 870,244 |

---

## 3. 核心难点：卷 OID 是虚拟对象号

**这是整个实现里最关键的认知。**

拿到卷 OID 列表后，第一反应是：

```python
paddr = oid * block_size      # ✗ 完全错误
```

算出来的地址读到的是别的对象的垃圾数据。

**原因**：`oid` 是虚拟对象号。APFS 用 **omap（object map）** 做 (oid, xid) → (paddr, size) 的映射。omap 本身是一棵 B-tree。

容器有一棵 omap（`nx_omap_oid`），每个卷内部还有自己的一棵（`apfs_superblock.apfs_omap_oid`）。

### 3.1 翻译链

```
NXSB  (分区内 0x20)
  │  nx_omap_oid = 870244
  ▼
容器 omap B-tree
  │  查 (oid=371006, xid=max)
  ▼
paddr = 876153
  │  876153 × 4096 = 3,588,722,688
  ▼
apfs_superblock @ 该地址
  │  apfs_root_tree_oid = 371007
  ▼
卷 omap B-tree
  │  查 (oid=371007)
  ▼
paddr = 900504
  │  900504 × 4096 = 3,688,464,384
  ▼
文件系统树根节点
```

### 3.2 卷名从哪来

卷超级块里的 `apfs_volname` 字段（偏移 0x2C0，704 字节）。

一个典型的 Mac 会有 6 个卷：

```
[371217, 1030, 5583, 5585, 371006, 5603]
```

其中只有 `- Data` 后缀的那个（这里是 `371006` = "OS X Base System - Data"）含用户数据。
其他是 System（只读）、Preboot、Recovery、VM。

**这解释了一个常见误判**：如果只读了 System 卷，会得出"`/private/var/log` 不存在"的结论——那卷本来就没有用户内容。

---

## 4. B-tree 节点

### 4.1 节点头

```python
btn_flags       @ 0x20   u16
btn_level       @ 0x22   u16     # 0 = 叶子
btn_nkeys       @ 0x24   u32
btn_table_space @ 0x28           # TOC 起始
```

节点类型中，**文件系统树的 subtype = 0x0e**。

### 4.2 TOC

`btn_table_space` 之后是 `nloc` 数组，每项：

```c
struct nloc {
    uint16_t key_offset;   // 相对 btree_node_phys 结尾的负偏移
    uint16_t val_offset;   // 同上
};
```

---

## 5. B-tree 遍历

算法依据 apfs-fuse `ApfsLib/BTree.cpp`。

### 5.1 节点头与 TOC 位置

```
btree_node_phys_t（头长 0x38）
  0x00  obj_phys        32 B
  0x20  btn_flags       u16   ROOT=0x01 LEAF=0x02 FIXED_KV=0x04 HASHED=0x08 NOHEADER=0x10
  0x22  btn_level       u16
  0x24  btn_nkeys       u32
  0x28  btn_table_space {u16 off; u16 len;}     <- TOC 起点 = 0x38（off 恒为 0）
  0x2C  btn_free_space
  0x30  btn_key_free_list
  0x34  btn_val_free_list
  0x38  btn_data[]
```

apfs-fuse 里有 `assert(m_btn->btn_table_space.off == 0)`——所以 TOC 就在 `0x38`，
不是 `0x38 + off`。这一点之前一直搞错。

### 5.2 键向前、值向后（最关键的一条）

```cpp
// BTree.cpp:86-90
m_keys_start = sizeof(btree_node_phys_t) + m_btn->btn_table_space.len;   // 0x38 + len
m_vals_start = (m_btn->btn_flags & BTNODE_ROOT)
               ? blocksize - sizeof(btree_info_t)                        // 末尾 40 字节归 btree_info
               : blocksize;
```

```cpp
// BTreeNodeFix::GetEntry
result.key = block + m_keys_start + e[i].k;        // 键：从 keys_start 向**后**长
result.val = block + m_vals_start - e[i].v;        // 值：从 vals_start 向**前**长
```

**所以 `k_off` 与 `v_off` 的数值集合"看起来重叠"是正常的**——它们量的是两个
相反方向的坐标，不是同一坐标空间。这是之前误判成"矛盾"的原因。

### 5.3 两种 TOC 结构

| 节点类型 | TOC 项 | 大小 | 键长/值长从哪来 |
|---|---|---|---|
| `BTNODE_FIXED_KV` | `kvoff_t {u16 k_off; u16 v_off;}` | 4 B | 树根尾部 `btree_info` 的 `bt_key_size`/`bt_val_size` |
| 变长 | `kvloc_t {nloc k; nloc v;}` | 8 B | TOC 项自带 `k.len`/`v.len` |

定长节点的**内部节点**值固定 8 字节（子 oid），不是 `bt_val_size`。

`BTOFF_INVALID = 0xFFFF` → 该条无值（ghost entry）。

### 5.4 `btree_info_t`（仅有 ROOT 节点在末尾带 40 字节）

```c
struct btree_info_fixed_t {   // 16 B
    u32 bt_flags; u32 bt_node_size; u32 bt_key_size; u32 bt_val_size;
};
struct btree_info_t {         // 40 B
    btree_info_fixed_t bt_fixed;
    u32 bt_longest_key; u32 bt_longest_val;
    u64 bt_key_count;   u64 bt_node_count;
};
```

`bt_flags` 关键位：`BTREE_PHYSICAL = 0x10`。

### 5.5 物理树 vs 虚树（第二个大坑）

| | `bt_flags & BTREE_PHYSICAL` | 内部节点值 | 用法 |
|---|---|---|---|
| omap 树 | 有（实测 `0x12`） | **paddr** | 直接读 |
| 文件系统树 | 无（实测 `0x42`） | **oid** | 必须先经 omap 翻译 |

把虚树的 oid 当 paddr 读，会读到无关块，表现为 `nkeys=0 flags=0x0000` 的"空节点"。
实测就是这么卡住过一次。

```python
om  = Omap.build(rb, bs, vol_omap_oid)          # oid -> paddr
root = om.get(vol_root_tree_oid)                 # 371007 -> 900504
for k, v, p in tree.walk(root, resolve=om.resolve):
    ...
```

### 5.6 文件系统树的键序

实测前 16 条（CM-02 Data 卷）：

```
oid=1 type=9 → oid=2 type=3 → oid=2 type=4 → oid=2 type=9 ×12
```

所以是 **obj_id 优先、obj_type 次之、再比名字字节**。

而 `j_key_t.obj_id_and_type` 的原始 u64 是 `(type << 60) | obj_id`——
按 u64 直排会把 type=9 的全排到最前，与真实顺序相反。
`lookup` 必须传 `jkey_cmp`。

### 5.7 B-tree 下降方向

标准语义：内部节点每项 `(key, child)` 表示「child 里的键都 ≥ key」，
所以要下降到**最后一个 `key ≤ target`** 的子节点，不是第一个 `≥`。
写成后者会走错分支、叶子层找不到键。

### 5.8 omap 对象的解析

```
nx_omap_oid / apfs_omap_oid  指向 apfs_omap_phys 对象（o_type=0x4000000B），不是树根
  om_tree_type @0x28  (u32)   实测 0x40000002 = OBJ_PHYSICAL | OBJ_BTREE
  om_tree_oid  @0x30  (u64)   实测 870247 / 873573
```

`OBJ_PHYSICAL = 0x40000000`（`0x80000000` 是 `OBJ_EPHEMERAL`，别搞反）。

### 5.9 卷超级块字段偏移（用真实数据定位）

| 字段 | 偏移 | 实测值 |
|---|---|---|
| `apfs_omap_oid` | **0x80** | 873520 |
| `apfs_root_tree_oid` | **0x88** | 371007 |
| `apfs_extentref_tree_oid` | 0x90 | 900417 |
| `apfs_snap_meta_tree_oid` | 0x98 | 870147 |
| `apfs_volname` | **0x2C0** | "OS X Base System - Data" |

反推 `wrapped_meta_crypto_state_t` 占 `0x060..0x074` 共 **20 字节**
（2+2+4+4+2+2+2 = 18，补齐到 20），所以三个 `*_tree_type` 落在
`0x74 / 0x78 / 0x7C`，`omap_oid` 落在 `0x80`。

### 5.10 实测验证结果（CM-02.E01）

| 检查项 | 结果 |
|---|---|
| 容器 omap 条目数 vs `btree_info.key_count` | **6 = 6** ✓ |
| 卷 omap 条目数 vs `key_count` | **22,060 = 22,060** ✓ |
| 卷 omap 节点数 vs `node_count` | **275 = 275** ✓ |
| 卷 omap 翻译 371007 | → paddr **900504** ✓ |
| FS 树遍历条数 vs `key_count` | **1,032,191 = 1,032,191** ✓ |
| `lookup(oid=2, type=3)` | 命中，`val_len=108` ✓ |

记录类型分布：inode 153,571 / xattr 69,209 / sibling_link 143,987 /
sibling_map 96,414 / file_extent 175,595 / drec 249,406 / dirstats 22 / snap_name 143,987。

遍历出的条数与 `btree_info` 声明值一致。

### 5.11 顺带发现的一个旧 bug

旧扫描法（`apfs_map.py`）记录「卷 371006 → paddr 876153」是**错的**。
实测 876153 属于卷 **371217**（`OS X Base System`，System 卷），
371006（`OS X Base System - Data`）的 paddr 是 **873588**。

两者 xid 也不同：873588 是 xid=118689，876153 是 xid=110771。
扫描法按块序覆盖 `oidmap`，会把不同卷的地址记混。

### 5.12 仍未做的

- `BTNODE_HASHED` / `BTNODE_NOHEADER` 分支未实现（当前检材没出现）
- 加密卷（`OBJ_ENCRYPTED`）未处理
- 快照树（`apfs_snap_meta_tree_oid`）未接
- 遍历 100 万条约需 100 s，未做性能优化（瓶颈是 omap 逐节点翻译）

---

## 6. 绕过方案：按记录类型模式匹配

既然遍历不完整，就不追求遍历——**从每个叶节点里按记录类型直接提取**。

`j_key_t.obj_type` 的取值：

| obj_type | 记录 | 关键字段 |
|---|---|---|
| 3 | `j_inode_val` | `private_id`、`create_time`、`mode`、xfields |
| 8 | `j_file_extent_val` | `logical_off`、`len_and_flags`、`phys_block` |
| 9 | `j_drec_key` / `j_drec_val` | 目录项名 + `file_id` |

### 6.1 extent 三元组的坑

**最容易误读的地方。**

```python
ext = (2945, 8192, 2374)     # 看起来像 (paddr, len, off)
```

实际是：

```python
(logical_off, length_bytes, phys_block)
```

**物理块在第三位。**

验证方法（用已知格式的文件做标定）：

```python
ext = [(0, 4096, 2339011), (4096, 147456, 6961352), (151552, 8192, 2102381)]
```

三重校验：

1. **逻辑连续**：`0 → 4096 → 151552`，且 `4096 + 147456 = 151552` ✓
2. **长度合理**：合计 159,744，与 inode 声明的大小 157,696 基本吻合 ✓
3. **魔数正确**：按 `offset = part_base + phys_block × 4096` 读出，头 16 字节为 `SQLite format 3\x00` ✓

三条都吻合才敢确认语义。

### 6.2 `inode()` 的 size 恒为 0

`j_inode_val` 偏移 `0x54` 看起来像文件大小，但那是 **`uncompressed_size`**——对非压缩文件恒为 0。

真实大小在 inode 的 **xfields** 里，类型 `INO_EXT_TYPE_DSTREAM`。

```python
v.inode(path)["size"]        # 永远是 0
len(v.read_file(ino))        # ← 用这个
```

这个坑曾让我一度以为所有文件都是 0 字节。

---

## 7. 验证清单

如果要确认自己的 APFS 实现是对的，跑这四项：

| 检查 | 期望 |
|---|---|
| `sub.read(0x20, 4)` | `b"NXSB"` |
| 容器 omap 翻译 `oid=371006` | 落在合理范围（几 GB 以内） |
| 读出 `Web Data`（Chrome SQLite） | 头 16 字节 `SQLite format 3\x00`，且能被 `sqlite3` 打开 |
| 读出任意 `.png` | 头 8 字节 `89 50 4E 47 0D 0A 1A 0A`，且能被 PIL 解码 |

前两项过不了 → 容器层问题；后两项过不了 → 文件系统树或 extent 层问题。

---

## 8. 代码入口

```python
import sys
sys.path.insert(0, "ESK")
sys.path.insert(0, "ESK/ext")

from mkit.image import Image, SubImage
import apfs_map as M
import apfs_fs as F

img = Image("mac.E01")
sub = SubImage(img, 0xC805000, img.size - 0xC805000)

# 1. 验证魔数
assert sub.read(0x20, 4) == b"NXSB"

# 2. 扫容器（可能需要几十秒）
c = M.Container()
c.scan(800000, 1400000, verbose=False)
print(c.block_size, c.block_count, c.vol_oids)

# 3. 选卷
v = F.VolFS(c, 371006)
print(v.name)

# 4. 读文件
ino = v.path("/Users/me/Desktop/a.png")
data = v.read_file(ino)

# 5. 读扩展属性
print(v.xattrs(ino))
```

`scan(start, end)` 的两个参数是**扫描 omap B-tree 的物理块范围**，用于定位容器 omap 的根。范围需要根据镜像实际情况给；`800000..1400000` 是常见 Mac 的元数据集中区。

---

<sub>ESK · **Calmgh06**</sub>
