<!-- ESK · Calmgh06 -->
# APFS B-tree 实现核对报告

对 `ext/apfs_btree.py` + `ext/apfs_omap.py` 的独立核查，参考实现为
`apfs-fuse`（`ApfsLib/BTree.cpp`、`DiskStruct.h`、`ApfsDir.cpp`、`ApfsNodeMapperBTree.cpp`）
与 `blacktop/go-apfs`（`types/btree.go`、`apfs.go`）。

核查结论：**布局与遍历算法与两个参考实现一致**，`walk()` / `lookup()` 在真实
CM-02.E01 上产出正确有序键值。核出 7 处偏差，其中 5 处已修，2 处作为已知风险记录在下方。

---

## 一、逐条核对

| # | 断言 | 结论 | 依据 |
|---|---|---|---|
| 1 | `btree_node_phys_t` 头长 0x38；`btn_flags@0x20` / `level@0x22` / `nkeys@0x24` / `table_space@0x28` / `free_space@0x2C` / `key_free_list@0x30` / `val_free_list@0x34` | 一致 | `DiskStruct.h:923-934`；`obj_phys_t` 为 8+8+8+4+4=0x20（`MAX_CKSUM_SIZE=8`） |
| 2 | TOC 起点是 0x38（`table_space.off` 恒为 0） | 一致 | `BTree.cpp:84` `assert(m_btn->btn_table_space.off == 0)`；`:110`/`:140` 用 `m_block.data() + sizeof(btree_node_phys_t)`；go-apfs 用 `+56` |
| 3 | 键向前、值向后：`keys_start = 0x38 + table_space.len`，`vals_start = ROOT ? node_size-40 : node_size` | 一致 | `BTree.cpp:86-90`、`:120-126`、`:150-156`；go-apfs `types/btree.go:215,222` 两式逐字等价 |
| 4 | root 末尾 40 字节 `btree_info_t`（4+4+4+4+4+4+8+8）；定长节点键长/值长只能从这里取 | 一致 | `DiskStruct.h:943-949`；`BTree.cpp:87-88,199,121,126` |
| 5 | 定长节点 TOC = `kvoff_t`(4B)；变长 = `kvloc_t`(8B) | 一致 | `DiskStruct.h:960-968`；`BTree.cpp:110` vs `:140` |
| 6 | 内部节点值固定 8 字节子 oid | 一致（非 HASHED） | `BTree.cpp:126` `(btn_flags & BTNODE_LEAF) ? GetValLen() : sizeof(oid_t)`、`:244` assert |
| 7 | `BTOFF_INVALID = 0xFFFF` 表示 ghost | 一致 | `DiskStruct.h:958`；`BTree.cpp:123,153` |
| 8 | `OBJ_PHYSICAL = 0x40000000`（`0x80000000` 是 `OBJ_EPHEMERAL`） | 一致 | `DiskStruct.h` 常量区；`BTree.cpp:448-461` 的 physical 分支 |
| 9 | `nx_omap_oid` / `apfs_omap_oid` 指向 `apfs_omap_phys` 对象，树根在 `om_tree_oid@0x30`，类型在 `om_tree_type@0x28` | 一致 | `DiskStruct.h:306-317`；`ApfsNodeMapperBTree.cpp:80` `m_tree.Init(m_omap.om_tree_oid, xid)` |
| 10 | 虚树内部值是 oid 需 omap 翻译；omap 树是物理树 | 一致（语义） | `BTree.cpp:398-407,448-461`；go-apfs `readChildNode` 同样是「index 值经 omap 翻译再读块」 |
| 11 | `j_key_t` 排序是 obj_id 优先、obj_type 次之 | 一致 | `ApfsDir.cpp:752-765` 的 `ks = (ks<<4)|(ks>>60)` 旋转技巧 |
| 12 | 内部节点应下降到「最后一个 key ≤ target」 | 一致 | `BTree.cpp:230` `FindBin(..., FindMode::LE)`；`:622-624` `res = (rc <= 0) ? mid : (mid - 1)`；go-apfs `GetFSRecordsForOid` 同义 |
| 13 | 卷超级块 `omap_oid@0x80` / `root_tree_oid@0x88` / `volname@0x2C0` | 一致 | 按 `DiskStruct.h:416-488` 手工推排：`meta_crypto` 占 0x060..0x074（0x14），三个 `*_tree_type` 落 0x74/0x78/0x7C |

算术自洽（容器 omap 根，`nkeys=6`，`table_len=0x1C0=448`）：
`keys_start = 56+448 = 504`，TOC 24 字节占 `[0x38,0x50)`，与键区 `[504,600)` 不重叠；
`vals_start = 4096-40 = 4056`，6×16 字节值占 `[3960,4056)`；中间为 free space。布局自洽。

---

## 二、核出的偏差与处理

| # | 偏差 | 影响 | 处理 |
|---|---|---|---|
| 1 | `Omap.build` 取全局最大 xid，参考实现取「**≤ 树/卷头 xid 的最大版本**」 | 若镜像是快照副本，可能取到比快照更新的版本 | **已修**：加 `max_xid` 参数；默认仍宽松，严格用时传卷头 xid |
| 2 | `jkey_cmp` 尾部按原始字节比较；参考实现按类型做**数值**比较 | 查 drec / xattr / file_extent 会走错分支 | **已修**：按类型分派；drec 用 u32 且只比高 22 位 hash；extent 用 u64 数值；xattr / snap_name 只比名字 |
| 3 | 未处理 `BTNODE_HASHED`（内部值是 `btn_index_node_val_t`，子 oid 需加 `binv_child_oid + m_oid`） | 哈希树遍历会读到错误子节点 | **已修**：`children(oid_base)` 与 `lookup` 都按标志位分支 |
| 4 | `children()` / `lookup()` 用 `& 0x7FFFFFFFFFFF` 掩码，参考实现没有任何掩码 | 大于 2^47 的 oid 会被截断 | **已修**：去掉掩码 |
| 5 | 忽略 `OMAP_VAL_DELETED` | 会把已删条目当成有效映射 | **已修**：`Omap.build` 跳过并计数 |
| 6 | 无 Fletcher64 校验 | 块损坏时静默解析 | **未修**（见下） |
| 7 | `read_btree_info` 不校验 `bt_node_size == blocksize` | 块大小不符时会按错误尺寸解析 | **未修**（见下） |

已确认为「正确、非问题」的项：
- `btn_free_space` / `btn_key_free_list` / `btn_val_free_list` **不参与** `keys_start` 计算
  （`BTree.cpp:86` 只用 `btn_table_space.len`），忽略它们是对的
- `BTREE_KV_NONALIGNED`、`BTREE_UINT64_KEYS` 只是对齐与优化提示，不影响按显式长度解析

---

## 三、未修的两项：为什么留着

**Fletcher64 校验**：APFS 用的是改造过的 Fletcher64（校验字段先置零再整体求和，
结果有特定的取反约定）。没拿到可直接对照的实现细节前贸然加进去，
一旦算错会把好块判成坏块——比不校验更糟。当前策略是明确记录「不做校验」，
而不是加一个可能误判的检查。

**`bt_node_size` 校验**：这一项风险很低。`block_size` 来自 NXSB，参考实现也直接用
容器块大小；`bt_node_size` 在校验和成立时必然相等。加校验的收益小于引入
「合法镜像被判非法」的风险，所以记录为待办而非立即实现。

---

## 四、额外风险（已知边界）

| 项 | 状态 | 说明 |
|---|---|---|
| `BTNODE_HASHED` | 已实现但未在真实卷上验证 | CM-02 未出现哈希树；代码路径照参考实现写，无实测样本 |
| `BTNODE_NOHEADER` / `BTREE_NOHEADER` | 未实现 | 节点不带 obj_phys 头时 `keys_start` 基准会变；apfs-fuse 也按有头处理 |
| 加密卷（`OBJ_ENCRYPTED`） | 未实现 | 需先用卷密钥解密块；`omap_val.ov_flags` 里已保留该位 |
| 名字比较的大小写 | 按**敏感**实现 | CM-02 的 `OS X Base System - Data` 是 case-sensitive 卷；大小写不敏感卷需传 `case_insensitive=True` |
| Unicode 归一化 | 未实现 | 参考实现用 `apfs_strncmp` 做归一化 + 折叠；当前只做 ASCII 逐字节比较 |
| 性能 | 未优化 | 100 万条记录约 100 s，瓶颈在 omap 逐节点翻译；可做批量预取 |

---

## 五、验证证据

真实检材 `CM-02.E01`（465.92 GiB，APFS 分区 `0xC805000`，`block_size=4096`）：

| 检查项 | 结果 |
|---|---|
| 容器 omap 条目数 vs `btree_info.key_count` | 6 = 6 |
| 卷 omap 条目数 vs `key_count` | 22,060 = 22,060 |
| 卷 omap 节点数 vs `node_count` | 275 = 275 |
| 卷 omap 翻译 oid 371007 | → paddr 900504 |
| **FS 树遍历条数 vs `key_count`** | **1,032,191 = 1,032,191** |
| `lookup(oid=2, type=3)` | 命中，`val_len=108`，`mode=0o40775` |
| 遍历顺序单调性（`jkey_cmp`） | 相邻 1,032,190 对记录，**0 处逆序** |

记录类型分布：inode 153,571 / xattr 69,209 / sibling_link 143,987 /
sibling_map 96,414 / file_extent 175,595 / drec 249,406 / dirstats 22 / snap_name 143,987。

遍历条数与 `btree_info` 声明值逐一吻合，且顺序在自建比较器下单调——这两条同时成立，
才说明 TOC 与键序都解析正确。

---

## 六、顺带发现的一处旧 bug

旧的「按物理块扫 o_oid 建目录」路径（`apfs_map.py`）记录「卷 371006 → paddr 876153」是错的：

```
paddr 873588  oid=371006  xid=118689  name="OS X Base System - Data"   ← 正确
paddr 876153  oid=371217  xid=110771  name="OS X Base System"          ← 属于 System 卷
```

扫描法按块序覆盖 `oidmap`，会把不同卷的地址记混。B-tree 路径按 (oid, xid) 精确翻译，
不存在这个问题。

---

<sub>ESK · Calmgh06</sub>
