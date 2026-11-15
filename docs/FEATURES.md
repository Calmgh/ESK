<!-- ESK · Calmgh06 -->
# 功能覆盖矩阵

对照 [LovelyCarve v1.3.0](https://github.com/LovelyTeams/LovelyCarve) 的能力面，逐项标注 ESK 的状态。

> 说明：LovelyCarve 是 Rust + Tauri 的桌面平台，33 种文件系统、19 类容器、加密与插件系统，
> 是多人长期工程的体量。ESK 是纯 Python 的库，目标是**覆盖取证/CTF 里真正会用到的部分**，
> 并把它做成可被脚本和代理直接调用的模块。
> 下表如实标注 `已实现 / 部分 / 未实现`，不掩饰差距。

**图例**：`[*]` 已实现并有测试　`[~]` 已实现未实测　`[ ]` 未实现　`[-]` 不做（见文末）

---

## 一、镜像容器

| 格式 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| RAW / DD / IMG / BIN | ✅ | **[*]** | `image.Image` |
| E01 / Ex01（EWF） | ✅ | **[*]** | `image.Image` + `ewf` + `ewf_external` |
| VMDK（拆分/单文件） | ✅ | **[*]** | `ext/ans_c02vm2.py`、`ext/webvm3_dev.py` |
| VHD / VHDX | ✅ | **[~]** | `ext/ans_c02_vhdx.py`、`ext/ans_c02r_lib.py` |
| QCOW2 | ✅ | **[*]** | `vdisk.Qcow2`（v2/v3） |
| VDI | ✅ | **[*]** | `vdisk.Vdi` |
| ISO 9660 | ✅ | **[*]** | `iso.Iso9660`（PVD/SVD/Joliet/Rock Ridge NM，合成镜像已测） |
| UDF 1.02–2.01 | ✅ | `[ ]` | 计划（UDF 结构独立于 ISO9660，未实现） |
| AD1（FTK 逻辑镜像） | ✅ | `[ ]` | 计划 |
| DMG（Apple） | ✅ | `[ ]` | 计划 |
| Parallels PHDI | ✅ | `[ ]` | 计划 |
| DiskGenius PMFX | ✅ | `[ ]` | 计划 |
| 雷电模拟器 LDBK | ✅ | `[ ]` | 计划 |
| 光盘 BIN / CUE | ✅ | `[ ]` | 计划 |
| 小米 HDR1 | ✅ | `[ ]` | 计划 |
| Buffalo ENC / TRX | ✅ | `[ ]` | 计划 |
| TP-Link SafeLoader | ✅ | `[ ]` | 计划 |
| U-Boot legacy uImage | ✅ | `[ ]` | 计划 |
| Netgear CHK | ✅ | `[ ]` | 计划 |
| Sercomm NAND ZIP | ✅ | `[ ]` | 计划 |
| UBI（含内嵌 SquashFS/UBIFS） | ✅ | `[ ]` | 计划 |

## 二、逻辑检材

| 类型 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| 文件夹 | ✅ | **[*]** | 直接用 `os.walk` |
| ZIP | ✅ | **[*]** | `zipview` |
| TAR / TAR.GZ | ✅ | `[ ]` | 计划（标准库 tarfile 可快速补） |
| 7z | ✅ | `[ ]` | 计划（需 py7zr） |
| Docker / OCI 归档 | ✅ | `[ ]` | 计划（本质是 tar） |
| iOS 本地备份 | ✅ | **[*]** | `iosart` + `iosbackup_crypto` |
| 加密 iOS 备份 | ✅ | **[*]** | `iosbackup_crypto` |
| BCP 交换数据 | ✅ | `[ ]` | 计划 |
| 小米 `.bak` | ✅ | `[ ]` | 计划 |

## 三、分区与卷

| 类型 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| GPT | ✅ | **[*]** | `volume._gpt`（注意 `parse()` 有 bug） |
| MBR / EBR | ✅ | **[*]** | `volume.parse` |
| APM（Apple） | ✅ | `[ ]` | 计划 |
| Amiga RDB | ✅ | `[ ]` | 计划 |
| BSD 标签 | ✅ | `[ ]` | 计划 |
| LVM2 线性卷 | ✅ | **[*]** | `ext/ans_c02h_lvm.py` |
| mdadm RAID 成员（0.90/1.x） | ✅ | **[*]** | `ext/com03_raid2.py` |
| RAID0/1/4/5/6/10 重组 | ✅ | **[~]** | 只完整实现 RAID5 缺单盘 |
| Intel IMSM / VROC | ✅ | `[ ]` | 计划 |
| SNIA DDF（PERC/MegaRAID） | ✅ | `[ ]` | 计划 |

## 四、文件系统

| 文件系统 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| NTFS | ✅ | **[*]** | `ntfs`（含 `iter_mft`、ADS） |
| ext2/3/4 | ✅ | **[*]** | `ext4`（注意没有 `read_file`，用 `read_data`） |
| FAT12/16/32 | ✅ | **[~]** | `fat`（合成 FAT16 已测，真实卷待验） |
| exFAT | ✅ | **[*]** | `exfat`（VBR/簇堆/0x85-0xC0-0xC1 目录项，合成镜像已测） |
| APFS | ✅ | **[*]** | `ext/apfs_fs.py` + `apfs_map.py`（自建 omap 翻译） |
| HFS | ✅ | `[ ]` | 计划 |
| HFS+ / HFSX | ✅ | `[ ]` | 计划（卷头可解，Catalog B-tree 未做） |
| ISO 9660 | ✅ | **[*]** | `iso.Iso9660`（PVD/SVD/Joliet/Rock Ridge NM，合成镜像已测） |
| UDF | ✅ | `[ ]` | 计划 |
| Btrfs | ✅ | `[ ]` | 计划 |
| ZFS | ✅ | `[ ]` | 计划（体量大，优先级低） |
| XFS | ✅ | `[ ]` | 计划 |
| ReFS | ✅ | `[ ]` | 计划 |
| SquashFS v1–v4 | ✅ | `[ ]` | 计划（固件常用） |
| CramFS v2 | ✅ | `[ ]` | 计划 |
| ROMFS | ✅ | `[ ]` | 计划 |
| MINIFS v3 | ✅ | `[ ]` | 计划 |
| F2FS | ✅ | `[ ]` | 计划（Android） |
| EROFS | ✅ | `[ ]` | 计划（Android） |
| QNX4 / QNX6 | ✅ | `[ ]` | 计划（车机/IoT） |
| UBIFS v4/v5 | ✅ | `[ ]` | 计划 |
| JFFS2 | ✅ | `[ ]` | 计划 |
| YAFFS1 / YAFFS2 | ✅ | `[ ]` | 计划 |
| Minix FS V1/V2/V3 | ✅ | `[ ]` | 计划 |
| JFS | ✅ | `[ ]` | 计划 |
| ReiserFS 3.5/3.6 | ✅ | `[ ]` | 计划 |
| Amiga OFS/FFS | ✅ | `[ ]` | 计划 |
| BeFS | ✅ | `[ ]` | 计划 |
| GFS2 | ✅ | `[ ]` | 计划 |
| OCFS2 | ✅ | `[ ]` | 计划 |
| NILFS2 | ✅ | `[ ]` | 计划 |
| bcachefs | ✅ | `[ ]` | 计划 |
| **exFAT（ESK 独有前置）** | ✅ | **[*]** | 见上 |

> **小结**：文件系统 33 种里，ESK 已覆盖 7 种（NTFS / ext / FAT / exFAT / APFS / ISO9660），
> 其余 26 种为计划项。这是最大的差距，也是后续工作的主线。

## 五、加密与快照

| 类型 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| LUKS1 / LUKS2 | ✅ | **[~]** | `luks`（**只解头，不解锁**） |
| BitLocker | ✅ | `[ ]` | 计划 |
| VeraCrypt | ✅ | `[ ]` | 计划 |
| FileVault 2 | ✅ | `[ ]` | 计划 |
| Windows EFS | — | `[ ]` | 计划 |
| NTFS VSS 卷影 | ✅ | `[ ]` | 计划 |
| 钱包/助记词 | — | **[*]** | `wallet`（**ESK 独有**） |
| iOS 备份加密 | ✅ | **[*]** | `iosbackup_crypto` |

## 六、分析功能

| 能力 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| 案件管理 + 哈希链审计 | ✅ | `[ ]` | 计划（`chain` 有 keccak，未接审计） |
| 卷快照 / 文件索引落盘 | ✅ | `[ ]` | 计划 |
| 原类型预览（文本/十六进制/图片/音视频/PDF/Office） | ✅ | `[ ]` | 计划 |
| SQLite 浏览（WAL 回放 / 删除恢复） | ✅ | `[ ]` | 高优先 |
| Realm 浏览 | ✅ | `[ ]` | 低优先 |
| PE / ELF / Mach-O / GGUF 结构视图 | ✅ | `[ ]` | 计划（`revkit` 有部分） |
| 校验 MD5/SHA-1/SHA-256/SM3 | ✅ | **[*]** | `hashcalc` |
| E01 采集哈希核对 | ✅ | **[*]** | `hashcalc.verify_ewf_hash` |
| 全局搜索（多编码/正则/未分配） | ✅ | **[*]** | `search` |
| 时间线（+ USN 日志） | ✅ | `[ ]` | 计划 |
| 文件恢复（删除记录 + 重建分区） | ✅ | **[~]** | `fat.deleted`、`ntfs` 有删除项；重建分区未做 |
| 文件雕刻（14 种） | ✅ | **[*]** | `carve`（**16 种**，多 2 种） |
| 插件系统（LPP v2） | ✅ | `[ ]` | `[-]` 不做，见文末 |
| CLI + JSONL 会话 | ✅ | `[ ]` | 计划（高优先，便于代理编排） |
| Dokany 只读挂载 | ✅ | `[-]` | 不做，见文末 |

## 七、ESK 相对 LovelyCarve 的独有能力

| 能力 | ESK | LovelyCarve |
|---|---|---|
| **APFS 容器 omap B-tree 翻译（自建、无第三方）** | ✅ | 用 vendor 的 dpp |
| **PNG 像素级同源判定（LSB 隐写定量判据）** | ✅ `ext/q13_judge.py` | ❌ |
| **零宽字符隐写检测（8 种码位）** | ✅ `stego` | 部分（`stego` 里有） |
| **钱包助记词 / 密钥材料提取** | ✅ `wallet` | ❌ |
| **PST/OST 内嵌 PNG 提取 + 断裂修复** | ✅ `ext/ans_78b_*.py` | ❌ |
| **SM3 纯 Python 实现（无 OpenSSL 依赖）** | ✅ `hashcalc` | 有 SM3 |
| **JPEG 尾部追加隐写检出** | ✅ `stego` | 部分 |
| **HEIC/HEIF 纯 Python 解码** | ✅ `heif` | 用第三方 |
| **q13 判据：±1 通道差占比量化** | ✅ | ❌ |
| **EWF 头部哈希字段解析** | ✅ | ✅ |

## 八、不做的部分

| 项 | 理由 |
|---|---|
| **GUI（Tauri + Vue）** | ESK 定位是库，界面交给调用方；用 Python 生态（Jupyter / CLI / agent）组织 |
| **LPP v2 插件系统** | 需要宿主进程隔离与 C ABI，超出纯 Python 库的边界；ESK 用「模块 + 函数」替代 |
| **Dokany 只读挂载** | Windows 驱动级依赖，与"零依赖起步"冲突；需要时用 7-Zip / Arsenal Image Mounter |
| **写回 / 取证镜像制作** | ESK 设计上只读 |

---

## 九、推进顺序（按性价比）

1. ~~hashcalc / search / carve / fat / vdisk / luks~~ ✅ v1.1.0
2. ~~exfat / iso~~ ✅ v1.2.0　｜　hfs / UDF 顺延
3. **SQLite 深度浏览**（WAL 回放 + 删除记录恢复）—— 取证最高频
4. **时间线聚合**（$STANDARD_INFORMATION / $FILE_NAME / USN / 各平台）
5. **CLI + JSONL 会话** —— 便于代理编排
6. **exFAT 之外的移动端**：F2FS / EROFS
7. **固件栈**：SquashFS → CramFS → ROMFS → JFFS2 → YAFFS2 → UBI
8. **Linux 服务器**：Btrfs / XFS
9. **加密**：BitLocker → VeraCrypt → FileVault 2
10. **剩余容器**：AD1 / DMG / PHDI / BIN-CUE / LDBK / PMFX

---

<sub>ESK · Calmgh06</sub>
