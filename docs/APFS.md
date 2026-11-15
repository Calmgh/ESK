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

## 5. 未解决的部分：TOC 布局

**2026-11-15 更新：又推进了一格，但仍未打通。**

### 5.1 已确认（用 CM-02.E01 实测）

**`nx_omap_oid` 不是树根。** 它指向一个 `apfs_omap_phys` 对象：

```
paddr 870244:  o_type = 0x4000000B  (OBJ_PHYSICAL | OBJ_OMAP)
               0x20  om_flags             = 0x00000001
               0x24  om_snap_count        = 0x00000000
               0x28  om_tree_type         = 0x40000002  (PHYSICAL | BTREE)
               0x2C  om_snapshot_tree_type= 0x40000002
               0x30  om_tree_oid          = 0x000D4767 = 870247   <- 真树根
```

正确顺序：`nx_omap_oid` → 读 omap 对象 → `om_tree_oid@0x30` → 树根。

**`OBJ_PHYSICAL` 是 `0x40000000`，不是 `0x80000000`**（后者是 `OBJ_EPHEMERAL`）。
这两个搞反会导致无法判断 `om_tree_oid` 能否直接当 paddr 用。

节点头这几个字段实测正确：
`btn_flags@0x20` / `btn_level@0x22` / `btn_nkeys@0x24` / `btn_table_space@0x28(off,len)`，头长 `0x38`。

### 5.2 仍未打通：FIXED_KV 节点的 TOC

实测节点（omap 树根，paddr 870247）：

```
flags = 0x0007   (ROOT | LEAF | FIXED_KV)
level = 0        nkeys = 6
table_off = 0x0  table_len = 0x1C0 (448)

TOC @0x38 (32 字节):
  00 00 10 00  40 00 50 00  10 00 20 00  50 00 60 00
  60 00 70 00  30 00 40 00  30 00 40 00  00 00 00 00
```

按 4 字节 `kvoff_t {u16 k_off; u16 v_off;}` 解：

| 项 | k_off | v_off | v-k |
|---|---|---|---|
| e0 | 0x0000 | 0x0010 | 16 |
| e1 | 0x0040 | 0x0050 | 16 |
| e2 | 0x0010 | 0x0020 | 16 |
| e3 | 0x0050 | 0x0060 | 16 |
| e4 | 0x0060 | 0x0070 | 16 |
| e5 | 0x0030 | 0x0040 | 16 |

`v - k` 恒为 16，与"omap_key 16 B + omap_val 16 B"吻合。

**但有两个矛盾**：

1. `k_off = 0`。若按"相对节点末尾"解释，键落在 4096 处——越界。
2. `k_off` 与 `v_off` 取值集合互相重叠：`0x10` 既是 e0 的 `v_off` 又是 e2 的 `k_off`；
   `0x40` 既是 e1 的 `k_off` 又是 e5 的 `v_off`。若键值各占 16 字节，物理上不可能重叠。

所以"offsets 相对节点末尾"这个基准是错的，或者定长节点的 TOC 项根本不是 `kvoff_t`。

**节点尾部 96 字节**（数据区可能在这里）：

```
79 5e 0d 00 00 00 00 00 | ff ff 10 00 00 10 00 00
ec 47 0d 00 00 00 00 00 | 00 00 00 00 00 10 00 00
1b 47 0d 00 00 00 00 00 | 00 00 00 00 00 10 00 00
2c 47 0d 00 00 00 00 00 | 12 00 00 00 00 10 00 00
```

反复出现的 `0x0D5E79 / 0x0D47EC / 0x0D471B / 0x0D472C` 都在 869000–870000（omap 块所在区），
像是**子节点地址**，但当前节点标了 LEAF。这个矛盾也还没解释。

### 5.3 现状

- `ext/apfs_btree.py` 的 `resolve_tree_root()` **可用**（已实测）。
- `walk()` / `lookup()` **不可用**，FIXED_KV 下读不出有效条目，不要用它下结论。
- 文件级读取继续走 `apfs_map.py` 的"扫物理块建 oid→paddr"——它绕开 B-tree，
  但实测在 CM-02 上给出的卷 paddr=876153、FS 树根=900504 都正确。

### 5.4 历史记录

最早尝试过三种 `voff` 理解，每种都只命中一部分节点：

| 假设 | 结果 |
|---|---|
| `val = node_end - voff` | 部分节点正确 |
| `val = node_end - 40 - voff` | 另一部分节点正确 |
| 累积式（逐项累加长度） | 又一部分 |

现在知道了：先要把设备/omap 这一层弄对（见 5.1），再谈 TOC；否则基准本身就是错的。

### 5.5 如果要继续攻

1. 取一个小卷（Preboot 最合适，几百个文件）
2. 用 dpp / apfs-fuse 读**同一个节点**，拿到它们解析出的键字节
3. 有了"这个节点第 0 条键长什么样"这个已知量，再反推 TOC 语义
4. **不要靠猜**——猜出来的解析器会静默给出错误键值，比直接报错危险得多

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
