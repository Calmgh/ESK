<!-- ESK · Calmgh06 -->
# 贡献指南

这个项目是个人参赛沉淀，不追求完整，但欢迎补洞。

## 最想被补的地方

按优先级：

### 1. APFS B-tree 的 `voff` 约定（最重要）

见 `docs/APFS.md` 第 5 节。目前 `nloc.val_offset` 的三种解释各只命中一半节点，
怀疑是 `btn_flags` 里某个位在切换布局。

**建议路径**：
1. 取一个小卷（Preboot 最合适，几百个文件）
2. dump 根节点和几层子节点
3. 用已知键值对（例如已知 inode 号）反推 header 与首条 TOC 项的真实相对位置
4. 逐位验证 `btn_flags`

补完这一块，`apfs_fs.py` 就能做完整遍历了。

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
