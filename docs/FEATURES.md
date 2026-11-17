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
| UDF 1.02–2.01 | ✅ | **[*]** | `udf`（VRS / AVDP 双锚点 / PVD·PD·LVD / FSD / FE / FID，short_ad·long_ad·embedded） |
| AD1（FTK 逻辑镜像） | ✅ | **[~]** | `ad1`（段发现/头/块解压/目录树；ADCRYPT 未实现） |
| DMG（Apple） | ✅ | **[*]** | `dmg`（koly/plist/mish/zlib/bzip2/LZMA；ADC·LZFSE 未实现） |
| Parallels PHDI | ✅ | **[*]** | `containers`（BAT 稀疏读，未分配块返回零） |
| DiskGenius PMFX | ✅ | **[~]** | `containers`：**只识别**，无公开规范，不解析字段 |
| 雷电模拟器 LDBK | ✅ | **[~]** | `containers`：**只识别**，无公开规范，不解析字段 |
| 光盘 BIN / CUE | ✅ | **[*]** | `bincue`（8 种扇区模式、多轨多文件、CCD/MDS 头部、SUB Q 通道） |
| 小米 HDR1 | ✅ | **[~]** | `containers`：**只识别**，无公开规范，不解析字段 |
| Buffalo ENC / TRX | ✅ | **[~]** | `containers`（DNI 全字段；ENC 加密体不解密） |
| TP-Link SafeLoader | ✅ | **[*]** | `containers`（512 B 头，0xA5/0x55AA 双重确认，按 ofs 切段） |
| U-Boot legacy uImage | ✅ | **[*]** | `containers`（64 B 头 + hcrc/dcrc + gzip/bzip2/lzma） |
| Netgear CHK | ✅ | **[*]** | `containers`（40 B 头 + board_id + 区域/版本 + CRC） |
| Sercomm NAND ZIP | ✅ | **[*]** | `containers`（512 B 头，偏移 511 校验和） |
| UBI（含内嵌 SquashFS/UBIFS） | ✅ | **[*]** | `ubi`（EC/VID 头 + PEB 扫描 + 卷重组；UBIFS 顺序 LEB 扫描读文件，LZO 未用真实样本验证） |

## 二、逻辑检材

| 类型 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| 文件夹 | ✅ | **[*]** | 直接用 `os.walk` |
| ZIP | ✅ | **[*]** | `zipview` |
| TAR / TAR.GZ | ✅ | **[*]** | `archive`（ustar/GNU/PAX、重复成员与 superseded、gz/bz2/xz） |
| 7z | ✅ | **[*]** | `archive`（纯 Python：LZMA/LZMA2/Copy/BCJ/Delta/Deflate/BZip2；AES 抛错） |
| Docker / OCI 归档 | ✅ | **[*]** | `archive`（manifest/index 双路径、whiteout、逐层变更） |
| iOS 本地备份 | ✅ | **[*]** | `iosart` + `iosbackup_crypto` |
| 加密 iOS 备份 | ✅ | **[*]** | `iosbackup_crypto` |
| BCP 交换数据 | ✅ | **[*]** | `archive`（.fmt 10.0、字符与原生定长、20+ SQL 类型） |
| 小米 `.bak` | ✅ | **[*]** | `archive`（tar/zip/gzip 探明、descriptor.xml；加密抛错） |

## 三、分区与卷

| 类型 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| GPT | ✅ | **[*]** | `volume._gpt`（注意 `parse()` 有 bug） |
| MBR / EBR | ✅ | **[*]** | `volume.parse` |
| APM（Apple） | ✅ | **[*]** | `parttable.parse_apm` |
| Amiga RDB | ✅ | **[*]** | `parttable.parse_amiga`（含校验和验证） |
| BSD 标签 | ✅ | **[*]** | `parttable.parse_bsd`（双端序） |
| LVM2 线性卷 | ✅ | **[*]** | `ext/ans_c02h_lvm.py` |
| mdadm RAID 成员（0.90/1.x） | ✅ | **[*]** | `ext/com03_raid2.py` |
| RAID0/1/4/5/6/10 重组 | ✅ | **[*]** | `raid`（GF(2^8)；RAID5 缺 1 盘；**RAID6 缺 2 盘 P+Q 联立**，10 种组合实测；RAID10 near/offset） |
| Intel IMSM / VROC | ✅ | **[*]** | `raidmeta`（MPB 倒扫 + 校验和；disk_ord_tbl；级别与 chunk） |
| SNIA DDF（PERC/MegaRAID） | ✅ | **[*]** | `raidmeta`（anchor/primary、phys/virt/config 三段、13 种 prl/rlq 映射） |

## 四、文件系统

| 文件系统 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| NTFS | ✅ | **[*]** | `ntfs`（含 `iter_mft`、ADS） |
| ext2/3/4 | ✅ | **[*]** | `ext4`（注意没有 `read_file`，用 `read_data`） |
| FAT12/16/32 | ✅ | **[~]** | `fat`（合成 FAT16 已测，真实卷待验） |
| exFAT | ✅ | **[*]** | `exfat`（VBR/簇堆/0x85-0xC0-0xC1 目录项，合成镜像已测） |
| APFS | ✅ | **[*]** | `ext/apfs_fs.py` + `apfs_map.py`（自建 omap 翻译） |
| HFS | ✅ | **[*]** | `hfs`（MDB 解析 + 经典 HFS Catalog B 树遍历与读写；超过 3 个 extent 的 Catalog 溢出部分不跟进） |
| HFS+ / HFSX | ✅ | **[*]** | `hfs.HfsPlus`（卷头/备份卷头、Catalog B-tree、extents overflow、UTF-16BE 名） |
| ISO 9660 | ✅ | **[*]** | `iso.Iso9660`（PVD/SVD/Joliet/Rock Ridge NM，合成镜像已测） |
| UDF | ✅ | **[*]** | `udf`（同上） |
| Btrfs | ✅ | **[*]** | `btrfs`（超级块 / chunk 树合并 / 目录遍历 / 读文件 / zlib） |
| ZFS | ✅ | **[*]** | `zfs`（uberblock/blkptr/fletcher4/ZAP/目录；**SA 未解，文件精确长度与 mtime 取不到**；无真实镜像验证） |
| XFS | ✅ | **[*]** | `xfs`（超级块/AG/inode/短格式与 dir2 目录/extent 与 **b-tree inode**，经 `xfs_bmap`；**attr fork 与 rmap 未做**） |
| ReFS | ✅ | **[*]** | `refs`（超级块 + 容器表 + 对象表 B+ 树） |
| SquashFS v1–v4 | ✅ | **[*]** | `squashfs`（v4）+ `squashfs_v123`（v1/v2/v3 大端 119 字节超级块、MSB-first 位域、ldir/lreg、fragment、CHECK_DATA，自检 14 项；**v1 目录结构为推断**，验证靠自建 writer↔parser 互证而非真样本；非 gzip/未压缩抛 NotImplementedError） |
| CramFS v2 | ✅ | **[*]** | `cramfs`（位域 inode、块指针表、zlib/未压缩/空洞/DIRECT_PTR） |
| ROMFS | ✅ | **[*]** | `romfs`（inode 链表、校验和、硬链接/符号链接） |
| MINIFS（VxWorks MiniFS，变体 A） | ✅ | **[*]** | `minifs`（`magic[16]+flag` + 88 B 明文目录项、路径内联、LZMA prop 0x5A/0x5D） |
| MINIFS（VxWorks MiniFS，变体 B） | ✅ | **[*]** | `minifs`（32 B 头 + ToN + 20 B 文件表 + 12 B 块表；一块多文件；名表非明文只硬解并记 notes） |
| F2FS | ✅ | **[*]** | `f2fs`（超级块/checkpoint/NAT/SIT/inode/目录；加密只识别） |
| EROFS | ✅ | **[*]** | `erofs`（FLAT_PLAIN/INLINE/COMPRESSED + 自实现 LZ4；CHUNK_BASED 与 LZMA/ZSTD 抛 NotImplementedError） |
| QNX4 / QNX6 | ✅ | **[*]** | `retrofs`（QNX4 64 B inode / QNX6 大端 @0x2000） |
| UBIFS v4/v5 | ✅ | **[*]** | `ubi`（顺序 LEB 扫描读文件；**未做 IDX 索引遍历**，GC 残留旧节点按 sqnum 取舍） |
| JFFS2 | ✅ | **[*]** | `flashfs`（日志式多版本重建 + unlink 取证；RTIME/RUBIN/LZO 未实现） |
| YAFFS1 / YAFFS2 | ✅ | **[*]** | `flashfs`（几何自动判定 + tags 解析；ECC 不校验） |
| Minix FS V1/V2/V3 | ✅ | **[*]** | `classicfs`（三级间接 + 16/32/64 B 目录项） |
| JFS | ✅ | **[*]** | `classicfs`（imap/dtree/xtree；压缩卷抛 NotImplementedError） |
| ReiserFS 3.5/3.6 | ✅ | **[*]** | `classicfs`（S+ 树整树遍历 + 双 key 编码） |
| Amiga OFS/FFS | ✅ | **[*]** | `retrofs`（根块/哈希表/OFS-FFS 两种数据块） |
| BeFS | ✅ | **[*]** | `retrofs`（超级块 @512 + inode + dirent） |
| GFS2 | ✅ | **[*]** | `gfs2`（超级块/资源组/dinode/stuffed 与 EXHASH 目录/元树；rindex 与 readlink 未做） |
| OCFS2 | ✅ | **[*]** | `ocfs2`（超级块/链列表/extent 与 extent 块树/线性目录；索引目录抛 NotImplementedError，位图不逐位解析） |
| NILFS2 | ✅ | **[*]** | `nilfs2`（段摘要/超级根/checkpoint/B-tree；SUFILE 语义与 ss_sumsum 强校验未做，无真实镜像验证） |
| bcachefs | ✅ | **[*]** | `bcachefs`（超级块/字段链/成员/journal；**btree 未实现，不能列目录或读文件**，jset csum 未校验） |
| **exFAT（ESK 独有前置）** | ✅ | **[*]** | 见上 |

> **小结**：文件系统 33 种里，ESK 已覆盖 13 种（NTFS / ext / FAT / exFAT / APFS / ISO9660 / UDF / HFS+ / XFS / SquashFS / CramFS / ROMFS / Btrfs），
> 其余 20 种为计划项。这是最大的差距，也是后续工作的主线。

## 五、加密与快照

| 类型 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| LUKS1 / LUKS2 | ✅ | **[*]** | `luks`（头解析 + 口令解锁：LUKS1 PBKDF2+AFmerge+mk_digest、LUKS2 pbkdf2 keyslot；Argon2 与非 AES 抛 NotImplementedError；无真实镜像验证） |
| BitLocker | ✅ | **[~]** | `bitlocker`（恢复密码 + .BEK 启动密钥解锁、XTS/CBC/diffuser）+ `tpmseal`（TPM 保护者 / PCR 策略结构解析与「能否离线解开」判定；**TPM 解封无解，不做**） |
| VeraCrypt | ✅ | **[*]** | `veracrypt`（AES-XTS + 多 PRF + PIM；whirlpool/stribog/Serpent/Twofish/Argon2id 抛 NotImplementedError，无真实卷验证） |
| FileVault 2 | ✅ | **[*]** | `filevault2`（AES-KW 按 RFC 3394 官方向量验证 + XTS + 密钥链；加密上下文定位为启发式，无真实镜像验证） |
| Windows EFS | ✅ | **[*]** | `efs`（$EFS 属性/凭据/密钥信息解析；**FEK 为 RSA 加密，decrypt_file() 抛 NotImplementedError**） |
| NTFS VSS 卷影 | ✅ | **[*]** | `vss`（catalog + 描述符 + full/overlay/零三种块；多存储链与 previous_store 抛 NotImplementedError） |
| 钱包/助记词 | — | **[*]** | `wallet`（**ESK 独有**） |
| iOS 备份加密 | ✅ | **[*]** | `iosbackup_crypto` |

## 六、分析功能

| 能力 | LovelyCarve | ESK | 模块 / 说明 |
|---|:---:|:---:|---|
| 案件管理 + 哈希链审计 | ✅ | **[*]** | `casebook`（Case + AuditLog 哈希链，篡改/删行/插行/改 prev 均可定位；**无签名或外部锚**，整链重写无法察觉） |
| 卷快照 / 文件索引落盘 | ✅ | **[*]** | `casebook`（sqlite 文件索引 + 卷快照：`snapshot` / `diff_snapshots` / `restore_snapshot` / `verify_snapshot`；快照为自校验 sha256，**无签名**，整体重写无法察觉） |
| 原类型预览（文本/十六进制/图片/音视频/PDF/Office） | ✅ | **[*]** | `preview`（sniff 20+ 类型、text/hex 预览、PNG/JPEG/GIF/BMP/PDF/RIFF/MP4/OOXML 元信息） |
| SQLite 浏览（WAL 回放 / 删除恢复） | ✅ | **[*]** | `sqlite_forensic`（WAL 帧校验与回放、freeblock 扫描、已删表检测） |
| Realm 浏览 | ✅ | **[*]** | `realm`（表/列/行只读浏览；**未能确认的布局抛 NotImplementedError**，不假装成功） |
| PE / ELF / Mach-O / GGUF 结构视图 | ✅ | **[*]** | `preview`（PE / ELF / Mach-O，含证书表、导入表、fat 架构）+ `gguf`（元数据 KV / tensor_info / alignment；**不做反量化**，K-quant 类型不猜字节数） |
| 校验 MD5/SHA-1/SHA-256/SM3 | ✅ | **[*]** | `hashcalc` |
| E01 采集哈希核对 | ✅ | **[*]** | `hashcalc.verify_ewf_hash` |
| 全局搜索（多编码/正则/未分配） | ✅ | **[*]** | `search` |
| 时间线（+ USN 日志） | ✅ | **[*]** | `timeline`（6 种换算 + CSV/JSONL/SQLite 导出；USN/EVTX 需先由别的模块解析） |
| 文件恢复（删除记录 + 重建分区） | ✅ | **[*]** | `fat.deleted` / `ntfs` 删除项 + `partrecover`（MBR/EBR/GPT 解析、特征扫描恢复、分区表重建 + 自校验；**EBR 链只解析不重建**，4K 原生扇区不处理） |
| 文件雕刻（14 种） | ✅ | **[*]** | `carve`（**16 种**，多 2 种） |
| 插件系统（LPP v2） | ✅ | `[ ]` | `[-]` 不做，见文末 |
| CLI + JSONL 会话 | ✅ | **[*]** | `esk_cli.py`（images / fs / hash / search / carve / luks / schema / session） |
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
2. ~~exfat / iso~~ v1.2.0　｜　~~hfs / squashfs / cramfs / romfs / xfs~~ v1.4.0　｜　UDF / btrfs / ad1 / dmg 顺延
3. ~~SQLite 深度浏览~~ v1.4.0　｜　~~BitLocker / Btrfs / 时间线 / AD1 / DMG / 三张分区表 / CLI~~ v1.5.0　｜　UDF 顺延
4. **时间线聚合**（$STANDARD_INFORMATION / $FILE_NAME / USN / 各平台）
5. **CLI + JSONL 会话** —— 便于代理编排
6. **exFAT 之外的移动端**：F2FS / EROFS
7. **固件栈**：SquashFS → CramFS → ROMFS → JFFS2 → YAFFS2 → UBI
8. **Linux 服务器**：Btrfs / XFS
9. **加密**：BitLocker → VeraCrypt → FileVault 2
10. **剩余容器**：AD1 / DMG / PHDI / BIN-CUE / LDBK / PMFX

---

<sub>ESK · Calmgh06</sub>
