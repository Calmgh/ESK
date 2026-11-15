<!-- ESK · Calmgh06 -->
# 贡献指南

这个项目是个人参赛沉淀，不追求完整，但欢迎补洞。

## 最想被补的地方

按优先级：

### 1. APFS B-tree —— **已完成**（2026-11-15）

完整遍历已实现并验证：文件系统树 1,032,191 条记录与 `btree_info.key_count`
逐一吻合，`lookup` 可用。见 `docs/APFS.md` 第 5 节、`ext/apfs_btree.py`、`ext/apfs_omap.py`。

**还开放的子任务**：

- `BTNODE_HASHED` / `BTNODE_NOHEADER` 分支（当前检材未出现，未实现）
- 加密卷（`OBJ_ENCRYPTED`）的 B-tree
- 快照树 `apfs_snap_meta_tree_oid` 的遍历
- 性能：100 万条遍历需约 100 s，瓶颈在 omap 逐节点翻译，可做批量预取

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
