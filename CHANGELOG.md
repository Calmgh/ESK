<!-- ESK · Calmgh06 -->
# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.3.0] - 2026-11-15

**APFS B-tree 完整遍历打通。** 这是之前唯一标注为「未完成」的核心能力。

### 新增

- **`ext/apfs_btree.py`** —— 真正的 APFS B-tree 遍历（替换原来的猜测式实现）
  - 算法依据 apfs-fuse `ApfsLib/BTree.cpp`，逐项在真实检材上验算
  - 键**向前**排（`keys_start + k_off`）、值**向后**排（`vals_start - v_off`）
  - root 节点末尾 40 字节 `btree_info_t`，定长节点的键长/值长从这里取
  - 定长节点 TOC = `kvoff_t`(4B)，变长 = `kvloc_t`(8B)
  - 内部节点值固定 8 字节子 oid；`BTOFF_INVALID=0xFFFF` 表示 ghost
  - `walk()` / `lookup()` / `count_nodes()` / `dump_node()`
  - `jkey_cmp()` / `jkey_make()`：APFS 文件系统树的键序比较器
  - `resolve_tree_root()`：从 `apfs_omap_phys` 对象取真树根

- **`ext/apfs_omap.py`** —— omap 高层封装 `Omap.build()` → oid→paddr 查表
  - 自动取同 oid 的 **最大 xid** 版本
  - 明确拒绝非物理 omap（不猜）

- **`ext/test_apfs_btree.py`** —— 用真实 CM-02.E01 跑的 24 项验证

### 修复（都是会导致静默错误的 bug）

- **虚树 vs 物理树搞混**：文件系统树的内部节点值是 **oid**，不是 paddr。
  直接当 paddr 读会得到 `nkeys=0 flags=0x0000` 的「空节点」，遍历静默返回 0 条。
  现由 `walk(resolve=...)` / `lookup(resolve=...)` 显式要求传入 omap 翻译器。
- **B-tree 下降方向写反**：内部节点应下降到「最后一个 `key <= target`」的子节点，
  原实现取第一个 `>=`，导致走错分支、叶子层查不到键。
- **`OBJ_PHYSICAL` 常量错**：应为 `0x40000000`，旧代码写成 `0x80000000`（那是 `OBJ_EPHEMERAL`）。
- **`nx_omap_oid` 不是树根**：它指向 `apfs_omap_phys` 对象，真树根在 `om_tree_oid@0x30`。
- **卷超级块字段偏移**：`apfs_omap_oid@0x80`、`apfs_root_tree_oid@0x88`、`apfs_volname@0x2C0`
  （之前用 0xC0 / 0x2D0，读出来的卷名少了 15 个字符）。
- **顺带发现旧扫描法的 bug**：它记录「卷 371006 → paddr 876153」是错的，
  876153 实际属于卷 371217（System 卷）。正确值是 873588。

### 验证（真实检材 CM-02.E01，24 项断言全过）

| 检查项 | 结果 |
|---|---|
| 容器 omap 条目数 vs `btree_info.key_count` | 6 = 6 |
| 卷 omap 条目数 vs `key_count` | 22,060 = 22,060 |
| 卷 omap 节点数 vs `node_count` | 275 = 275 |
| 卷 omap 翻译 oid 371007 | → paddr 900504 |
| **FS 树遍历条数 vs `key_count`** | **1,032,191 = 1,032,191** |
| `lookup(oid=2, type=3)` | 命中，val_len=108 |

记录类型分布：inode 153,571 / xattr 69,209 / sibling_link 143,987 /
sibling_map 96,414 / file_extent 175,595 / drec 249,406 / dirstats 22 / snap_name 143,987。

### 已知问题

- `BTNODE_HASHED` / `BTNODE_NOHEADER` 分支未实现（当前检材未出现）
- 加密卷（`OBJ_ENCRYPTED`）的 B-tree 未处理
- 快照树 `apfs_snap_meta_tree_oid` 未接
- 100 万条遍历约 100 s，瓶颈在 omap 逐节点翻译，未优化

## [1.2.0] - 2026-11-15

继续对标 LovelyCarve 补文件系统与容器。

### 新增

- **mkit/exfat.py** —— exFAT
  - VBR 解析（含 4Kn 扇区、双 FAT 标记）
  - 目录项三种类型：0x85 文件项 / 0xC0 流扩展 / 0xC1 文件名
  - 长文件名、时间戳、删除标记（条目类型 bit7）
  - NoFatChain 连续分配与簇链两种读取路径
  - unallocated_ranges() 供雕刻

- **mkit/iso.py** —— ISO 9660（含 Joliet / Rock Ridge）
  - 卷描述符扫描，优先 Joliet（UCS-2BE 文件名）
  - 目录记录双端字段解析、;1 版本号剥离
  - Rock Ridge 的 NM 替代名（POSIX 长名）
  - 递归遍历、按路径查找

- **docs/FEATURES.md** —— 功能覆盖矩阵
  - 逐项对照 LovelyCarve v1.3.0 的容器/文件系统/加密/分析能力
  - 标注 [*] 已实现并测试 / [~] 已实现未实测 / [ ] 未实现 / [-] 不做
  - 当前：26 项已实现并测试，5 项部分实现，65 项计划
  - 附「ESK 独有能力」与「推进顺序」

### 修复

- exfat.py 目录项类型比较漏了 in-use 位掩码：etype & 0x7F 得到 0x05，
  却拿去和 0x85 比，导致根目录永远解析为 0 项。改为比较 ENTRY_FILE_M = 0x05。

### 已知问题

- UDF 未实现（结构与 ISO9660 完全不同）
- HFS / HFS+ 未实现
- exFAT 只在合成镜像上验过

## [1.1.0] - 2026-11-15

补 6 个模块，主要对着 LovelyCarve 的能力面找自己的空白。

### 新增

- **`mkit/hashcalc.py`** —— 哈希与校验
  - MD5 / SHA-1 / SHA-256 / **SM3**（GB/T 32905-2016，纯 Python 实现）
  - `stream_hash()` 分块流式，任意大小的镜像都不吃内存
  - `verify_ewf_hash()` 读 EWF 头部记录的采集哈希并重新计算比对
  - `tree_hash()` 目录树哈希
  - SM3 通过三条标准测试向量

- **`mkit/search.py`** —— 多编码全局搜索
  - ASCII / UTF-8 / UTF-16LE / UTF-16BE / GBK
  - 关键词与正则，宽编码下按 2 字节步进换算偏移
  - 分块扫描 + overlap，跨块边界不漏命中
  - `to_csv()` 导出 Excel 友好格式

- **`mkit/carve.py`** —— 签名文件雕刻
  - 16 种格式：JPEG PNG GIF BMP PDF ZIP RAR 7z GZIP RTF SQLite OLE2 PE ELF MP4 RIFF
  - 三种定尾策略：**LENGTH**（从头部算长度，最可靠）/ **TAIL**（找结束标记 + 校验）/ **CAP**（截断并标记）
  - SQLite 用 page_size × page_count 精确算长；PE 用节表算真实大小
  - `carve_unallocated()` 接未分配区间迭代器

- **`mkit/fat.py`** —— FAT12/16/32
  - 标准簇数阈值判定类型（先用 fat16 试算，超 65525 才认 FAT32）
  - 簇链跟踪、8.3 短名 + VFAT 长名、已删除条目（首字节 0xE5）
  - `unallocated_ranges()` 供雕刻使用

- **`mkit/vdisk.py`** —— QCOW2 v2/v3 与 VirtualBox VDI
  - QCOW2：L1→L2→数据簇三级映射，稀疏块补零，标志位掩码 `& 0x00FFFFFFFFFFFE00`
  - VDI：block map 解析，`0xFFFFFFFF` 视为未分配
  - `open_disk()` 按魔数自动识别 VMDK / QCOW2 / VDI

- **`mkit/luks.py`** —— LUKS1 / LUKS2 头部解析
  - LUKS1：cipher / mode / hash / payload offset / 8 个密钥槽的激活状态与 PBKDF2 迭代
  - LUKS2：JSON 元数据（偏移 4096）里的 cipher / pbkdf / slots / digests / segments
  - `strength_note()` 按迭代次数给密码强度线索
  - **不解锁**：`af_split/af_merge` 未在真实卷上验证，见「已知问题」

### 修复

- `fat.py` 初版把 `fat_size` 无条件从偏移 36 读（那是 FAT16 的 EBPB `drive_number`），
  导致 FAT16 镜像被误判、`data_off` 算到 TB 级。改为标准算法：先按 fat16 试算簇数，超阈值才读 fat32。
- `fat.py` 的 `volume_id` 偏移写反了（FAT32 应是 67，FAT16 是 39）。
- `luks.py` LUKS2 的 JSON 元数据应从**偏移 4096**（二进制头之后）读，不是 `header_size`。
- `luks.py` LUKS2 的 JSON 数值有 int 和 str 两种写法，加了 `_int()` 归一。

### 已知问题

- LUKS 只做到头部，不解锁。
- FAT32 只在合成镜像上验过逻辑，无真实 FAT32 卷回归。
- exFAT / HFS+ / Btrfs / XFS / SquashFS 未实现。

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
