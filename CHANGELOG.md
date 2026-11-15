<!-- ESK · Calmgh06 -->
# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.6.1] - 2026-11-15

容器补 UBI / UBIFS。

### 新增

- **`mkit/ubi.py`** —— UBI 卷层与 UBIFS
  - UBI EC 头（64 B，大端，magic `0x55424923`）：version、ec、
    vid_hdr_offset、data_offset、image_seq、hdr_crc（CRC32）
  - UBI VID 头（64 B，magic `0x55424921`）：vol_type（动态/静态）、copy_flag、
    compat、vol_id、lnum、data_size、used_ebs、data_pad、data_crc、sqnum、hdr_crc
  - 逐 PEB 扫描并把空白块（全 0xFF）与坏块（头 CRC 不过）分开计数；
    同一 `(vol_id, lnum)` 取 `sqnum` 最大的一份
  - `volumes()` / `read_volume()` / `read_logical()` / `volume_sub()`；
    卷的逻辑视图是 `read(offset,size)+size` 鸭子类型，可直接喂 `Ubifs`
  - UBIFS 超级块解析：key_hash、key_fmt、min_io_size、leb_size、leb_cnt、
    max_leb_cnt、log_lebs / lpt_lebs / orph_lebs / jhead_cnt、fanout、
    fmt_version、default_compr、rp_uid / rp_gid / rp_size、time_gran、uuid
  - **顺序 LEB 扫描**取节点（INO / DATA / DENT），校验 CRC32，按节点长度
    跳到下一个 8 字节对齐位置
  - 目录树由 DENT 与 INO 关联得到；只有 DENT 没有 INO 时建存根并标
    `orphan_guess=True`
  - 去重：同 inode 取 `creat_sqnum` 最大者，同 `(inum, block)` 与
    `(parent, name)` 取 `sqnum` 最大者
  - `listdir()` / `walk()` / `read_file()` / `lookup_path()` / `find()`
  - 压缩：none 直取、zlib 用标准库、LZO 用自写 LZO1X 解码器（含 UBIFS 的
    `[总长 u16][压缩长 u16][数据]` 帧格式）、zstd 抛 `NotImplementedError`
  - 自检 43 项：EC/VID 头 CRC、空白与坏 PEB 计数、卷重组、超级块字段、
    根目录与子目录列表、inline 与跨块（含 zlib 块）逐字节还原、去重、
    orphan 标注、节点 CRC 坏时跳过、zstd 显式拒绝

### 未实现（docstring 已写明）

- **UBIFS 索引（IDX / TNC）遍历**：本模块用顺序 LEB 扫描。能恢复文件与
  目录，但不能区分垃圾回收残留的旧节点与当前有效节点，只能按 `sqnum`
  取最大者；已删除但仍残留数据块的 inode 会被列出并标 `orphan_guess=True`
- **LZO 解码器未用真实 LZO 压缩样本验证**：按 LZO1X 算法规范实现，
  自检只覆盖 none 与 zlib 两条路径，`info()` 里如实给出 `lzo_verified=False`
- UBIFS 认证节点（AUTH）与 HMAC、fastmap、日志重放、xattr 条目内容、
  UBI 的 fastmap 卷与 layout volume 卷表内容：均不做

### 验证

- `mkit/ubi.py` 自检 43 项全过
- `mkit` 53 个模块全部可导入；`selftest_new.py` 45 项通过


## [1.6.0] - 2026-11-15

第 1 波：归档、光盘、RAID 重组与 RAID 元数据。

### 新增

- **`mkit/archive.py`** —— 归档与逻辑包
  - TAR / TAR.GZ / TAR.BZ2 / TAR.XZ：ustar / GNU / PAX 三种头，全量成员含重复，
    真实 `offset` / `offset_data`，`duplicate` / `duplicate_of` / `superseded` /
    `supersedes` / `live`，`read(name, occurrence=n)` 可读任一历史副本
  - 7z：三处 CRC 校验、`kEncodedHeader` 解压、PackInfo / UnPackInfo /
    SubStreamsInfo / FilesInfo、solid 子流切分、Copy / LZMA / LZMA2 /
    BCJ(x86,PPC,IA64,ARM,ARMT,SPARC) / Delta、单 coder Deflate / BZip2
  - Docker / OCI：`manifest.json` 与 `index.json`+`oci-layout` 双路径、
    gzip 层、`.wh.<name>` 删除、`.wh..wh..opq` opaque、逐层变更留存
  - BCP：`.fmt` 10.0（宿主/文件列序、前缀长度、转义）、字符与原生定长模式、
    20 余种 SQL 类型、无 `.fmt` 时启发式推断并标 `inferred`
  - 小米 `.bak`：tar / 前置头 zip / gzip 探明、`descriptor.xml` 定位、加密抛错
  - 实测两个格式坑：7z 的 `Digests` 段**没有** NumDigests 字段（`kCRC` 后紧跟
    AllAreDefined）；多 pack 流的基准是 `32 + packPos + 前面所有流长度之和`
  - 未实现：GNU sparse 内容重组、zstd tar/层、7z 的 BCJ2 / PPMd / Deflate64 /
    AES-256、BCP 的 `-w` Unicode 全宽、小米加密备份解密

- **`mkit/bincue.py`** —— 光盘镜像
  - CUE 解析：`FILE` / `TRACK` / `INDEX 00/01` / `PREGAP` / `POSTGAP` / `REM` /
    `CATALOG` / CD-TEXT；多 `FILE` 多轨路由
  - 扇区模式 8 种：MODE1/2048、MODE1/2352、MODE2/2048、MODE2/2324、
    MODE2/2336、MODE2/2352、CDI/2336、CDI/2352；Form1/Form2 按子头第 3 字节
    bit5 判定
  - `read_data()` 给逻辑 2048 字节，可直接 `Iso9660(bc)`
  - CCD：INI 全解析、`AMSF−150` 与 `ALBA` 交叉校验、leadout(0xA2)
  - MDS：魔数与版本、会话表在 8 个候选偏移里按结构自校验定位，不命中只留头部
  - SUB：Q 通道含 MSF 与 CRC
  - 一处规格表会算错：MODE2/2336 写「偏移 8 / 长 2336」实际 8+2336=2344 越界，
    实现按 8+2328 拆
  - 未实现：CCD/IMG 与 MDS/MDF 的数据抽取、音频解码、WAVE/MOTOROLA 内嵌偏移

- **`mkit/raid.py`** —— RAID 重组
  - GF(2^8)：多项式 `0x11D`，exp/log 表实现乘、除、求逆、幂
  - RAID0 / RAID1 / RAID4 / RAID5（left、right）/ RAID6 / RAID10（near、offset）
  - RAID5 缺 1 盘用 XOR 重建
  - **RAID6 缺 2 盘用 P、Q 联立求解**：分三种情形（缺 P+数据盘、缺 Q+数据盘、
    缺两个数据盘），实测 5 盘 RAID6 的 **全部 10 种双盘缺失组合**逐字节还原正确
  - RAID1 / RAID10 读失败自动换副本并写告警（取证可追溯）
  - 未实现：写回与重同步、坏块级扇区重试、RAID7 / RAID-TP、RAID5E / 5EE

- **`mkit/raidmeta.py`** —— RAID 控制器元数据
  - Intel IMSM / VROC：尾部倒扫签名 + `mpb_size` 与校验和双重验证；
    MPB 两种拼接解释（签名处向后 / 窗口在签名扇区末尾收尾）都试，取校验和通过者
  - IMSM 全字段：`check_sum` / `mpb_size` / `family_num` / `generation_num` /
    `attributes` / `num_disks` / `num_raid_devs` / `cache_size` / `creation_time`；
    `imsm_disk` 48 B、`imsm_dev` 164+4×(n−1) B、`imsm_map` 与 `disk_ord_tbl`
  - IMSM 级别映射：`raid_level==1` 且成员数≠2 即 RAID10；chunk =
    `blocks_per_strip × 512`
  - SNIA DDF：最后 32 MiB 内扫 `0xDE11DE11`，按 `type` 区分 anchor/primary/
    secondary；头部 512 字节全字段；phys / virt / config 三段解析；
    `vd_config` 的 `prim_elmnt_count` / `chunk_shift` / `prl` / `rlq` /
    `srl` / `blocks` / `array_blocks` / `phys_refnum` / `lba_offset`
  - DDF 级别映射照 mdadm `layout_ddf2md`，13 种 prl/rlq/srl 组合逐一实测：
    RAID0、RAID1（2 盘/3 盘）、RAID1E→10、RAID4、RAID5 三种布局、
    RAID6 三种布局、sec_elmnt_count>1 的 RAID10
  - RAID3 / RAID5E / RAID5EE / CONCAT 判为不支持并给出原因，不假装能重组
  - 产出统一描述供 `mkit.raid.Raid` 直接消费
  - 未实现：写回、DDF 各 section 内部记录 CRC（只验头部，标
    `section_crc_verified=False`）、IMSM 迁移中的第二份 map、BBM 日志内容、
    SED / OPAL 加密状态

### 与常见二手资料的差异（本版以 mdadm 源码为准）

- IMSM `check_sum` 在 **0x20**、`mpb_size` 在 **0x24**、`family_num` 在 0x28；
  磁盘表从 **0xD8** 开始。`attributes` 的 0x80000000 位是「校验和需验证」，
  不是 family_id
- `imsm_disk` 里没有 `start_sector`，也没有 `vol_id[2]`；容量是
  `total_blocks_lo@0x10 | total_blocks_hi@0x20`
- `imsm_dev` 里没有 `password`、没有 `chunk_size` 字段；chunk 由
  `blocks_per_strip × 512` 得到
- `disk_ord_tbl` 是 u32（不是 u8[4]），最高字节是重建标志，低 24 位是盘号
- DDF 的 `vd_config` 没有单独 chunk 字段，是 `chunk_shift`
  （`chunk = 512 << chunk_shift`）

### 验证

- 四个新模块 `__main__` 自检全部通过：`archive` / `bincue` / `raid`
  （43 项，含 RAID6 全 10 种双盘缺失）/ `raidmeta`（74 项，含 13 种 DDF 级别映射）
- `mkit` 52 个模块全部可导入；`selftest_new.py` 45 项通过


## [1.5.1] - 2026-11-15

BitLocker 补上启动密钥（.BEK）。

### 新增

- **`mkit/bitlocker.py`** —— 启动密钥（.BEK / external key）
  - `parse_bek()`：解析 .BEK 文件（常见 156 字节）——48 字节头（版本 1、
    元数据长度、卷 GUID、next nonce、encryption method、创建时间）+
    FVE external key（value_type 0x0009 = GUID(16) + FILETIME(8) + 属性数组），
    从属性里 entry type 0 的条目取出 256 位未加密密钥材料
  - `BitLocker.unlock_with_startup_key()`：与恢复密码同一套 stretch + AES-CCM
    通路，只把 initial_sha256 换成 BEK 密钥材料；按 `SHA256(材料)` 与原始材料
    两种候选依次试解，成不成立由解密后密钥块的结构自校验决定
  - 自检新增第 12 节：合成 StartupKey 保护器 + 配套 .BEK，覆盖 bytes / dict /
    文件路径三种入参、错误 BEK 返回 None、5 类非法输入、无保护器时的报错

### 修复

- **卷内 `value_type 0x0009` 的语义弄错了。** 按 libbde「FVE External Key」
  一节，它是 `GUID(16) + FILETIME(8) + 属性数组` 的 .BEK **GUID 引用**，
  不是密文。原先写成 `protector.ciphertext = child.data`，当 0x0009 排在
  stretch key 之后时会把 stretch key 里正确的 CCM 密文覆盖掉。现改为记录到
  `KeyProtector.external_key_guid`。
- **`parse_bek()` 的兜底分支会把 GUID 当密钥。** BEK 里的密钥材料不足 32 字节时，
  兜底逻辑原先会取 0x0009 条目自身的前 32 字节（那里是 GUID + FILETIME），
  于是一个残缺的 BEK 会被当成解析成功。现改为跳过 `value_type 0x0009`。

### 边界

- 启动密钥路径按公开结构实现，但**没有真实 .BEK 文件与配套加密卷做回归**，
  结果只作参考；文档未写死 initial_sha256 的取法，所以实现里保留两种候选试解
- TPM / TPM+PIN / 用户口令保护器仍需外部密钥材料（TPM 密封数据、
  口令编码规则），只枚举不推导


## [1.5.0] - 2026-11-15

补 7 个模块：BitLocker、Btrfs、时间线、AD1、DMG、三张非 x86 分区表，以及 CLI。

### 新增

- **`mkit/bitlocker.py`** —— BitLocker
  - 元数据三处全扫：卷头 0x03 签名 + 指针、卷尾 `size-0x10000/-0x20000`、0x1000/0x2000/0x10000/0x20000 候选，各用签名+版本+尺寸三重自校验
  - 8 字节 entry 链（含 value_type）；VMK 内部属性（描述串 / stretch key / CCM 密钥）
  - **恢复密码真实解锁**：8×6 位 ÷11 → u16 LE×8 → SHA-256 → 0x100000 轮 stretch → AES-256-CCM-CTR → VMK
  - 自研原语并已对拍：AES-XTS（**NIST CAVP**）、AES-CCM（**RFC 3610 #1**）、CCM-CTR、Elephant diffuser A/B、CBC
  - 卷解密：XTS / CBC / CBC+diffuser，`decrypt_sector` / `read_decrypted`
  - 未实现：TPM / .BEK / 用户口令（需外部密钥材料，只枚举）；CCM 的 MAC 校验（AAD 无公开定义，与 libbde 一致只做 CTR，`tag_verified=False`）

- **`mkit/btrfs.py`** —— Btrfs
  - 超级块（偏移 0x10000，`_BHRfS_M`）全字段 + dev_item + incompat 位域；
    主副本缺失时回退 64M / 256G / 1T 三个镜像位置
  - `sys_chunk_array`（17B key + chunk 交替，无对齐）**并与 chunk 树合并**
    —— 数据 chunk 只存在于 chunk 树里，不合并读不到文件
  - 树节点：`btrfs_header`(0x65) / `btrfs_item`(25) / `btrfs_key_ptr`(33)；
    item 数据偏移以 leaf 数据区起点 0x65 为基准（不是节点起点）
  - **目录遍历与读文件已完成**：root tree → ROOT_ITEM → FS_TREE/子卷 →
    DIR_ITEM/DIR_INDEX 去重 → INODE_ITEM
  - `read_file()` 支持 INLINE / REG / PREALLOC、空洞补零、跨 chunk 拼接
  - **校验和全部实现**：crc32c（表驱动，独立于 zlib.crc32）/ xxhash64 /
    sha256 / blake2b-256；元数据覆盖 `node[0x20:]`（依据 `disk-io.c`
    `csum_tree_block`），数据走 csum 树（objectid = **-10**）逐扇区比对；
    `verify_extent()` / `verify_node()`
  - **多设备与副本重试**：`Btrfs(sub, devices={devid: sub})`；DUP / RAID1
    校验失败或短读会自动换镜像，并写告警留痕（取证上必须可追溯）
  - **RAID0/10/5/6 映射**对照 `volumes.c` 的 `map_blocks_*` 公式；
    RAID56 的 P 逐行轮转；RAID5 单条带丢失用 XOR 重建
  - **压缩**：zlib、LZO（按 `lzo1x_decompress_safe.c` 逐分支移植 + btrfs 封帧）、
    LZ4（标准块解码）；zstd 走 ctypes 加载本机 libzstd，缺库时明确抛
    `NotImplementedError`，**不静默降级**
  - 未实现：加密 extent、已删除文件恢复（Btrfs 删 inode 后 DIR_ITEM 直接消失、
    无墓碑）、extent / free-space / qgroup 语义、RAID6 的 Q 解码（不做 RS）

- **`mkit/timeline.py`** —— 跨平台时间线
  - 6 种时间戳换算：Unix / FILETIME / HFS(1904) / APFS 纳秒 / FAT DOS（含 `tz_assumed` 标注）/ ext4（秒+纳秒）
  - 时区归一：`tz_offset_hours` 把墙钟折算 UTC
  - 适配器：`from_fs`（任意 `walk()`）、`from_regf`（LastWriteTime）、`from_csv`、`from_json`
  - `Timeline`：排序、`(ts,source,path,action)` 去重（可关）、filter / stats / heatmap / gaps
  - 导出：CSV（`utf-8-sig`，Excel 中文不乱码）/ JSONL / SQLite（建表 + 4 索引）

- **`mkit/ad1.py`** —— AccessData AD1 逻辑镜像
  - 段发现（`.ad1…adN`、`.AD1`、`.ad01`，段号缺口即止）
  - 段头 `ADSEGMENTEDFILE`、`ADLOGICALIMAGE` 头、`ADCRYPT` 识别后抛 `NotImplementedError`
  - 条目树（48 字节头，兄弟链 + 子链，带环检测）、元数据链（大小 / 4 个时间戳 / MD5 / SHA-1）
  - 块表 + zlib 解压 + 跨段读取；设备对象 `size` / `read` / `entries` / `entry` / `sub`

- **`mkit/dmg.py`** —— Apple DMG（UDIF）
  - `koly` trailer 全字段；XML / binary plist；`blkx.Data` 为 bytes 或 base64
  - 单个 Data 内串联多张 `mish` 自动重同步
  - chunk 类型：zero / raw / ignore / comment / terminator / end / zlib / bzip2 / LZMA（三级级联）
  - 按扇区随机读 + LRU 缓存（上限 64 MiB），raw 块直读不缓存
  - ADC / LZFSE 抛 `NotImplementedError`

- **`mkit/parttable.py`** —— 非 x86 分区表
  - APM（DDM `sbSig=0x4552` + 逐块 `pmSig=0x504D`，块大小不固定）
  - BSD disklabel（偏移 512/0 双点探测，四项指标判端序，16 字节分区项）
  - Amiga RDB（`RDSK` + `PART` 链，环检测 + 越界保护 + 校验和验证）
  - `detect()` / `parse_any()` / `describe()`

- **`esk_cli.py`** —— 命令行入口
  - `<集合> <动词>` 结构：`images open` / `fs ls|tree|cat|find` / `hash` / `search` / `carve` / `luks` / `schema` / `session`
  - `FsAdapter` 抹平各文件系统接口差异（按路径 / 按 inode / 按 entry 三种）
  - `session` 读 stdin 的 JSONL，逐行执行并回 JSON——便于脚本与代理编排
  - 端到端验证：合成 FAT16 镜像上 `images open` → `fs ls` → `fs find` → `fs cat` → `hash` → `search` → `session` 全通

- **`mkit/udf.py`** —— UDF 1.02–2.01
  - VRS（BEA01 / NSR02 / NSR03 / TEA01）识别，扇区 512 与 2048 都支持
  - AVDP 主锚点（扇区 256）与尾部锚点，主锚点损坏可自动回退
  - PVD / PD / LVD / USD / Terminating 描述符；descriptorTag 校验和验证
  - FSD → 根 ICB → File Entry（tagId 261/266）→ FID 目录项
  - 分配描述符：short_ad / long_ad / embedded(inline) 三种
  - 文件名支持 8-bit 与 16-bit（compressed unicode），4 字节对齐填充
  - 稀疏文件（extent 类型 2/3）、中文文件名
  - `probe()` / `open_fs()` / `info()` / `listdir()` / `walk()` /
    `read_file()` / `lookup_path()` / `find()`

### 修复

DMG 有两处实测出来的真 bug：

- **`koly` / `mish` 是大端，不是小端。** 实测 `hfsplus_zlib.dmg` 与
  `CC-Switch-v3.18.0-macOS.dmg`：`version@0x004 = 00 00 00 04` → 大端 4（小端 67108864）；
  `headerSize@0x008 = 00 00 02 00` → 大端 512（小端 131072）。
  早期一版按小端实现，在上述真实镜像上直接崩（`MemoryError` / offset 溢出），已废弃。
- **BLKX 表头差 4 字节。** 真实 `Data=284 B` 且含 1 个 `mish`，284 = 0xCC + 40×2
  ⇒ `numberOfBlockChunks` 在 **0xC8**、chunks 从 **0xCC** 起（原写 0xCC / 0xD0）。
- **chunk 的 `sectorNumber` 是相对所属表 `firstSectorNumber` 的偏移**，不是绝对扇区。
  实测「GPT Header」表 `firstSector=1` 而 chunk `sector=0`；当绝对扇区用会让多张表挤到扇区 0 互相覆盖。

### 验证

- 19 个模块的 `__main__` 自检通过；`selftest_new.py` 45 项通过；`mkit.__all__` 47 个模块全部可导入
- **DMG 对真实镜像验到端到端**：`Dmg → GPT（分区 0 = Apple HFS+，LBA 40..3783）→ HFS+ 挂载 → 列出 5 项`，读到 `passwords.txt`、`a_directory`
- **BitLocker**：AES-XTS 对拍 NIST CAVP、AES-CCM 对拍 RFC 3610 #1；恢复密码走真实 0x100000 轮 stretch 后 VMK 匹配，错误密码返回 None

### 已知问题

- Btrfs 只有超级块 / chunk 映射 / 树节点，**不能列目录、不能读文件**
- BitLocker 不支持 TPM / BEK / 用户口令；CCM 的 MAC 未校验
- DMG 不支持 ADC / LZFSE 压缩、加密 DMG、`.dmgpart` 多段
- AD1 不支持 ADCRYPT 加密、v1/v2 老格式
- `volume._gpt()` 在 DMG 设备上返回不完整（同一 GPT 手工解析正常，问题在 volume 侧）

## [1.4.0] - 2026-11-15

补 6 个模块：4 个文件系统、1 个 SQLite 取证、1 个 XFS 重写。

### 新增

- **`mkit/squashfs.py`** —— SquashFS v4
  - 96 字节超级块，小端 `hsqs` / 大端 `sqsh` 两种魔数
  - 元数据块（2 字节头，bit15 未压缩，低 15 位长度，单块上限 8 KiB）
  - 14 种 inode（基础版 + 扩展版）：DIR/REG/SYMLINK/BLKDEV/CHRDEV/FIFO/SOCKET
  - 目录表 dir_header + dir_entry（inode 号差值编码）
  - 数据块（含稀疏块）、片段尾块、id 表、片段表（经 u64 指针数组定位）
  - 压缩：gzip（zlib）、xz（lzma）；其余算法抛 `NotImplementedError`

- **`mkit/cramfs.py`** —— CramFS v2
  - 76 字节超级块（64 + 根 inode），位域 inode 解包
  - 目录遍历（inode 流，namelen 存 len>>2，4 字节对齐）
  - 块指针表：指针报「块结束位置」，`block_len = ptr - prev`
  - 未压缩块 / zlib 块 / 空洞 / DIRECT_PTR
  - 注：块指针标志位在指针高位（`1<<31` 未压缩、`1<<30` DIRECT_PTR），
    不在 inode offset 的低 2 位

- **`mkit/romfs.py`** —— Linux ROMFS
  - `-rom1fs-` 头、大端字段、校验和验证
  - inode 链表遍历（`next` 串联同目录兄弟）、`spec_info & 7` 类型判定
  - 普通文件 / 符号链接 / 硬链接解析

- **`mkit/hfs.py`** —— HFS / HFS+ / HFSX
  - 卷头 @1024，主卷头坏时回退卷尾备份
  - 5 个特殊文件 fork、extent 读取、extents overflow B-tree 续链
  - Catalog B-tree：节点描述符、索引下钻、叶子 fLink 链、尾部逆序偏移表
  - 目录项 1/2/3/4，UTF-16BE 名、CNID、POSIX 权限、5 个时间戳（1904 纪元）
  - 经典 HFS：MDB 解析、分配块参数、内嵌 HFS+ wrapper 定位
  - 目录遍历与文件读取抛 `NotImplementedError`（经典 HFS）

- **`mkit/sqlite_forensic.py`** —— SQLite 取证
  - WAL 解析与回放（帧头校验、salt、坏帧跳过并计数）
  - 删除记录恢复（freeblock / freelist 扫描，带置信度与 partial 标记）
  - 已删除表检测（freelist 页里搜 `CREATE TABLE` 残留）
  - 结构浏览、元数据（页大小 / 编码 / journal_mode / freelist_count）

### 重写

- **`mkit/xfs.py`** —— XFS v4 / v5
  - 超级块全字段（大端）、v5 的 CRC / meta_uuid / features_*
  - AG 头 AGF / AGI 定位与关键字段
  - inode 定位 `agno = ino >> (agblklog + inopblog)`
  - 目录：短格式（local）与块格式（extent）
  - 文件：**extent 格式**（`di_format == 2`）
  - B-tree 格式 inode（`di_format == 3`）抛 `NotImplementedError`
  - 原 agent 版本被 PowerShell 编码问题损坏，本次整文件重写

### 验证

`selftest_new.py` 45 项通过；以下模块的 `__main__` 自检通过：
squashfs / cramfs / romfs / hfs / xfs / sqlite_forensic / hashcalc / search /
carve / vdisk / luks / iso / exfat。

APFS B-tree：`ext/test_apfs_btree.py` 25 项通过，FS 树 1,032,191 条记录，
相邻记录在 `jkey_cmp` 下 0 处逆序。

### 已知问题

- squashfs 只支持 gzip / xz，lzma / lzo / lz4 / zstd 需要额外依赖
- xfs 不支持 B-tree 格式 inode，大目录 / 大文件会抛异常
- hfs 经典版只解析 MDB，不能遍历
- sqlite 删除记录恢复：`secure_delete=ON` / 已 VACUUM / 页被整理后不可恢复；
  被删行的主键常因 freeblock 头覆盖而丢失（其余字段可恢复）
- 未实现：btrfs、ad1、dmg

## [1.3.0] - 2026-11-15

APFS B-tree 遍历。

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

- **`ext/test_apfs_btree.py`** —— 真实 CM-02.E01 上的验证脚本

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

### 验证（真实检材 CM-02.E01）

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
