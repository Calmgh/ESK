<!-- ESK · Calmgh06 -->
# 贡献指南

这个项目是个人参赛沉淀，不追求完整，但欢迎补洞。

## 最想被补的地方

按优先级：

### 1. APFS B-tree 的 TOC 布局（最重要，已经推进一半）

见 `docs/APFS.md` 第 5 节。**现状：卡在 FIXED_KV 节点。**

**已经确认的**（2026-11-15 用 CM-02.E01 实测，写在 `ext/apfs_btree.py`）：

- `nx_omap_oid` / `apfs_omap_oid` 指向 `apfs_omap_phys` 对象，**不是树根**；
  真根在 `om_tree_oid@0x30`。实测 `870244 → 870247`
- `OBJ_PHYSICAL = 0x40000000`（`0x80000000` 是 `OBJ_EPHEMERAL`）
- 节点头长度 `0x38`，`btn_flags@0x20 / level@0x22 / nkeys@0x24 / table_space@0x28` 都对
- `resolve_tree_root()` 已可用

**卡住的地方**：`flags=0x0007`（含 `FIXED_KV`）的节点，
TOC 按 `kvoff_t {u16 k_off; u16 v_off;}` 解出来 `v-k ≡ 16`（符合 16 B 键值），
但 `k_off=0` 且 k/v 偏移区间互相重叠。**基准不是"节点末尾"，或 TOC 项结构不对。**

**建议路径**（比之前更具体）：

1. 取小卷（Preboot），用 **dpp / apfs-fuse 读同一个节点**，拿到它们解析出的键字节
2. 有了"这个节点第 0 条键长什么样"这个已知量，再反推 TOC 语义
3. **不要靠猜**——猜出来的解析器会静默给出错误键值，比报错危险得多

补完这一块，`apfs_fs.py` 就能做完整遍历（目前只能靠 `apfs_map.py` 的物理扫描绕行）。

### 2. APFS 快照 / FileVault

目前完全不支持。

### 3. RAID5 其他 layout

`com03_raid2.py` 只实现了 left-symmetric。left-asymmetric / right-* 需要按 stripe 逐块算。

### 4. VHDX 日志回放

未实现。回放后可恢复最近的 BAT/数据更新。

### 5. 更多平台的痕迹解析

`mkit/` 里 `linuxart` / `macart` / `iosart` 覆盖面有限，欢迎按真实案例补。

## 提交前

```bash
python examples/00_selftest.py     # 自检
```

新增模块请：
- 加文件头水印块
- 在 README 的模块地图里登记
- 如果是「导入即执行」的脚本，别放进 `mkit/` 或 `ext/` 顶层，另开子目录

## 报告问题

请附：Python 版本、依赖版本、最小复现、以及**脱敏后**的错误输出。

**不要上传任何真实检材**。

---

<sub>ESK · **Calmgh06**</sub>
