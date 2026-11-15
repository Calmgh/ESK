<!-- ESK · Calmgh06 -->
# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-11-15

首个公开版本。全部内容沉淀自 2026 年美亚杯参赛过程。

### 核心库 `mkit/`（28 模块 / 25,982 行）

- **镜像层**：`image`（EWF/裸镜像统一加载 + `SubImage` 分区切片）、`ewf`、`ewf_external`
- **分区层**：`volume`（MBR/GPT）
- **文件系统**：`ntfs`（MFT/属性/ADS/`iter_mft`）、`ext4`
- **注册表**：`regf`
- **平台痕迹**：`winart`、`winacct`、`appdata`、`sysconf`、`netart`、`linuxart`、`macart`、`iosart`、`mobile`
- **专项**：`stego`（隐写）、`wallet`（钱包/助记词）、`mail`（邮件）、`heif`（HEIC）、
  `iosbackup_crypto`（iOS 备份解密）、`online`、`chain`（证据链）、`aes`、`revkit`、`zipview`

### 扩展 `ext/`（34 模块）

- **APFS 文件级读取**：`apfs_map`（容器 omap B-tree 翻译）+ `apfs_fs`（卷文件系统树）
  - 补 `mkit.macart` 只到 `info()`/`volumes()` 的空白
- **虚拟磁盘**：`ans_c02vm2`（拆分稀疏 VMDK）、`webvm3_dev`（单文件 VMDK）、
  `ans_c02h_vmdk`、`ans_c02h_webvm`（base+snapshot 链式读）
- **LVM2**：`ans_c02h_lvm`（PV 标签 + `pe_start`）
- **VHDX**：`ans_c02_vhdx`、`ans_c02r_lib`
- **RAID5**：`com03_raid2`（缺块 XOR 重建）、`com03_raidfs`（重建后挂 ext4）
- **图像分析**：`q13_judge`（PNG 像素级同源判定）、`ans_78b_png`（PST 内嵌 PNG 提取）、
  `ans_78b_zlib`（zlib 容错解压 + 逐行反滤波）
- **通用**：`ans_lib`（MFT 索引 / `path_of` / `mft_find` / `read` / `dump`）

### 示例 `examples/`（6 个）

- `00_selftest.py` 环境自检
- `01_mount_ewf.py` 装载镜像、识别分区
- `02_ntfs_walk.py` NTFS 完整路径重建
- `03_apfs_read.py` APFS 容器扫描与文件读取
- `04_vmdk_lvm.py` VMDK → GPT → LVM2 → ext4 全链路
- `05_raid5.py` mdraid RAID5 缺块重建

### 文档 `docs/`

- `APFS.md` — 容器/omap/B-tree 技术笔记（含未解决问题与补完建议）
- `VMDK-LVM2.md` — VMDK / LVM2 / VHDX 结构与踩坑
- `RAID5.md` — mdadm 超级块、XOR 重建、三重验证

### 已知问题

- APFS 完整 B-tree 遍历未完成（TOC `voff` 约定未收敛），现用按记录类型模式匹配绕过
- APFS 快照 / FileVault 不支持
- LVM2 元数据区常读为全零，采用「单 segment、`start_extent=0`」假设
- RAID5 只实现 left-symmetric
- VHDX 未实现日志回放

---

<sub>ESK · **Calmgh06**</sub>
