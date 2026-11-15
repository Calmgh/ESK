<!-- ESK · Calmgh06 -->
# ESK

**E**lectronic **S**oftware **K**it　·　纯 Python　·　只读　·　零依赖起步

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Deps](https://img.shields.io/badge/required%20deps-1-lightgrey)]()
[![Author](https://img.shields.io/badge/ESK-Calmgh06-orange)]()

> 版本 1.0.0　｜　Python 3.11+　｜　Windows / Linux / macOS

---

## 为什么有这个东西

打了几次取证。每年赛前最烦的是装美亚的工具——主办方的工具箱动辄几十个G，还一直报毒，要权限，申请授权，环境还经常对不上。

等装完、跑通，时间过去了几个小时。

今年换了个做法：自己搓一套。

先用往年题目让ai来转化成数据集，把框架写出来；
比赛当天再结合本地模型lora的qwen，按真实检材的现场补扩展做题。

全程没有用美亚的任何工具，个人赛全部ak，团队赛做了285/291。

效果还可以，不过也有明显没做出来的地方，都写在下面。

---

## 目录

- [成绩](#成绩)
- [这个包是什么](#这个包是什么)
- [安装](#安装)
- [快速开始](#快速开始)
- [模块地图](#模块地图)
- [能力与边界](#能力与边界)
- [Q/A](#qa)
- [自建扩展说明](#自建扩展说明)
- [示例脚本](#示例脚本)
- [目录结构](#目录结构)
- [已知限制](#已知限制)
- [许可与致谢](#许可与致谢)

---

## 成绩

| | 名次 | 备注 |
|---|---|---|
| **个人赛（上午）** | 二等奖（前 100） | 128 题全部AK，但一定有错题 |
| **团队赛（下午）** | 三等奖 | 285 / 291，剩 6 题没做出来 |

**团队赛那几题为什么没做出来**：主办方限制了在线模型，全程只能用本地 LoRA 微调的 qwen 跑。上下文和推理能力都受限，几个需要跨多份镜像做长链推理的题就卡住了 框架应该是没问题的，师傅们可以用在线的模型试试看。

整体效果我认为可以接受，但谈不上成熟。欢迎批评指正。

---

## 这个包是什么

`mkit` 是一套纯 Python 的电子数据取证基础库，把"读镜像 → 解分区 → 挂文件系统 → 提取结构化数据"这条链路封装成统一接口。

本包分两部分：

| 部分 | 内容 | 规模 |
|---|---|---|
| **`mkit/`** | 核心库：镜像与容器、NTFS/ext4/FAT、APFS、注册表、哈希、搜索、雕刻、隐写、钱包、加密头、各平台痕迹 | **34 个模块 / 约 27,700 行** |
| **`ext/`** | 实战中补写的扩展：APFS 文件级读取、VMDK/LVM2/VHDX、RAID5 重建、像素级比对等 | 34 个模块 |

**适合谁用**：做 CTF 取证题、做真实案件的初检、写自动化提取脚本、需要绕开商业工具限制的场景。

**不适合谁用**：需要图形界面的人、需要写报告模板的人、需要法庭认可链的人（本包只管数据提取，不管流程合规）。

---

## 安装

### 2.1 依赖

```bash
pip install -r requirements.txt
```

**必需**只有一个：

| 包 | 用途 |
|---|---|
| `libewf-python` | 读 `.E01` / `.e01` EWF 镜像 |

其余按需：

| 包 | 启用什么 |
|---|---|
| `pycryptodome` | `wallet`（钱包解密）、`iosbackup_crypto`（iOS 备份解密） |
| `Pillow` | `stego`（隐写检测） |
| `dissect.eventlog` | `winart`（Windows EVTX 解析） |
| `numpy` | `ext/q13_judge`（像素级比对） |
| `capstone` | `revkit`（反汇编） |
| `pyzbar` | `stego` 的二维码识别（另需系统库 `zbar`） |
| `cryptography` | 证书 X.509 解析 |
| `openpyxl` | xlsx 读写 |

### 2.2 关于 libewf-python

这是最容易装失败的一个。三个方案按顺序试：

```bash
# 方案 1：预编译轮子（多数平台可用）
pip install libewf-python

# 方案 2：conda（跨平台最省事）
conda install -c conda-forge libewf-python

# 方案 3：源码编译（需 libewf-dev / libewf-devel）
#   Ubuntu/Debian: apt install libewf-dev
#   macOS:         brew install libewf
#   Windows:       从 https://github.com/libyal/libewf-legacy/releases 取预编译 dll
pip install libewf-python --no-binary :all:
```

装不上也能用——裸镜像（`.dd` / `.raw` / `.img` / `.bin`）不需要 pyewf。只有 `.E01` 才需要。

### 2.3 验证

```bash
python examples/00_selftest.py
```

全 OK 就绪。若「必需」项有 FAIL，先解决依赖。

---

## 快速开始

### 3.1 挂镜像、看分区

```python
import sys
sys.path.insert(0, "path/to/ESK")

from mkit.image import Image, SubImage
import mkit.volume as volume

img = Image("disk.E01")

# ⚠️ 重要：GPT 必须用 _gpt()，不能用 parse()
parts = volume._gpt(img, None) or volume.parse(img)
for p in parts:
    print(hex(p["offset"]), p["size"], p["type"])

# 取某个分区
sub = SubImage(img, 0x7500000, 837 * 2**30)
```

### 3.2 挂 NTFS、重建完整路径

```python
from mkit.ntfs import NTFS

fs = NTFS(sub)

# ⚠️ 不要用 fs.walk() —— 它会漏长文件名，见第 2 条
idx = {e.num: e for e in fs.iter_mft() if e is not None}

def path_of(num):
    parts, cur, seen = [], num, set()
    while cur in idx and cur not in seen:
        seen.add(cur)
        e = idx[cur]
        if e.name:
            parts.append(e.name)
        p = e.parent_num
        if p == cur or p == 5 or p not in idx:
            break
        cur = p
    return "\\" + "\\".join(reversed(parts))

for num, e in idx.items():
    if not e.is_dir:
        print(path_of(num), e.size)
```

### 3.3 按 MFT 号直取文件（最快）

```python
# 已知 MFT 号时，这是最快的路径 —— 比 fs.find() 快几百倍
ent = fs.read_entry(8120)
data = fs.read_entry_data(ent)
open("out.bin", "wb").write(data)
```

### 3.4 挂 ext4

```python
from mkit.ext4 import Ext4

# ⚠️ 循环结束后 p 会停在最后一个分区（常是 swap）→ 必须显式过滤
parts = [x for x in volume.parse(img) if x["type_id"] == 0x83]
fsx = Ext4(SubImage(img, parts[0]["offset"], parts[0]["size"]))

# 读文件
ino = fsx.lookup("/etc/passwd")
data = fsx.read_data(ino)          # ⚠️ 是 read_data，不是 read_file
```

---

## 模块地图

### 4.1 核心库 `mkit/`

| 模块 | 大小 | 用途 |
|---|---|---|
| `image.py` | 2.3 KB | 镜像加载（EWF/原始）+ `SubImage` 分区切片 |
| `ewf.py` / `ewf_external.py` | 10 KB | EWF 解析，外部 libewf 调用 |
| `volume.py` | 4.9 KB | MBR / GPT 分区表 |
| `ntfs.py` | 42 KB | NTFS：MFT、属性、ADS、`iter_mft` |
| `ext4.py` | 16 KB | ext4 |
| `regf.py` | 32 KB | 注册表 hive |
| `macart.py` | 29 KB | macOS 痕迹（APFS 仅 `info()`/`volumes()`） |
| `iosart.py` | 25 KB | iOS 痕迹 |
| `iosbackup_crypto.py` | 32 KB | iOS 备份解密 |
| `linuxart.py` | 87 KB | Linux 痕迹 |
| `winart.py` | 19 KB | Windows 痕迹（含 EVTX） |
| `winacct.py` | 19 KB | Windows 账户 |
| `appdata.py` | 92 KB | 应用数据（Windows） |
| `sysconf.py` | 48 KB | 系统配置 |
| `netart.py` | 20 KB | 网络痕迹 |
| `mobile.py` | 107 KB | 移动端综合 |
| `mail.py` | 50 KB | 邮件 |
| `heif.py` | 43 KB | HEIF/HEIC 解码 |
| `stego.py` | 60 KB | 隐写检测 |
| `wallet.py` | 65 KB | 钱包 / 助记词 |
| `online.py` | 11 KB | 在线服务痕迹 |
| `chain.py` | 64 KB | 证据链完整性 |
| `aes.py` | 8.8 KB | AES |
| `revkit.py` | 84 KB | 逆向套件 |
| `revkit_help.py` | 8.6 KB | 逆向辅助 |
| `zipview.py` | 3.9 KB | 压缩包只读浏览 |
| `hashcalc.py` | 9.3 KB | **哈希校验**：MD5 / SHA-1 / SHA-256 / **SM3**（纯 Python）、EWF 采集哈希核对、目录树哈希 |
| `search.py` | 9.0 KB | **多编码全局搜索**：ASCII / UTF-8 / UTF-16LE·BE / GBK，关键词或正则，可导出 CSV |
| `carve.py` | 12.6 KB | **签名雕刻**：16 种格式，按长度/结束标记/截断三种定尾策略 |
| `fat.py` | 12.1 KB | **FAT12/16/32**：BPB、簇链、LFN 长文件名、**删除项**、未分配簇枚举 |
| `vdisk.py` | 11.6 KB | **QCOW2 v2/v3 + VirtualBox VDI**：块映射、稀疏块补零、自动识别 |
| `luks.py` | 8.9 KB | **LUKS1 / LUKS2 头部解析**：算法、密钥槽、PBKDF2 迭代、LUKS2 JSON 元数据 |

### 4.2 扩展 `ext/`

见第七节。

---

## 能力与边界

**能做到**

- EWF（含分卷、拆分）与裸镜像统一加载
- MBR / GPT 分区表
- NTFS 完整路径重建（含长文件名、已删除条目）、ADS、注册表
- ext4 读写（只读）、mdadm RAID5 缺块重建
- APFS 容器解析 + **文件级读取**（核心库做不到，见第七节）
- VMware VMDK（拆分稀疏 / 单文件）/ Hyper-V VHDX / LVM2
- 隐写检测（JPEG 尾部追加、PNG LSB、零宽字符）
- 钱包助记词、密钥材料提取
- iOS 备份解密、HEIC 解码
- **哈希校验** MD5 / SHA-1 / SHA-256 / SM3，含 EWF 采集哈希核对
- **全局搜索** 覆盖 ASCII / UTF-8 / UTF-16LE·BE / GBK，支持正则与未分配空间
- **文件雕刻** 16 种格式（JPEG/PNG/GIF/BMP/PDF/ZIP/RAR/7z/GZIP/RTF/SQLite/OLE2/PE/ELF/MP4/RIFF）
- **FAT12/16/32** 完整读取，含长文件名与删除项恢复
- **QCOW2 / VDI** 虚拟机磁盘，稀疏块自动补零
- **LUKS1 / LUKS2** 头部识别与密钥槽枚举

**做不到**

- APFS 快照 / 加密卷（FileVault）—— 自建实现未覆盖
- 完整的 APFS B-tree 遍历 —— 见第七节，只到"能按键值对提取记录"
- 回收站/未分配簇的通用恢复 —— 各平台各有专门工具
- 内存镜像 —— 本包不含，请用 Volatility 3
- 写证据 —— 设计上只读
- **LUKS 解锁** —— 只解析头部，不派生密钥；`af_split/af_merge` 未在真卷上验证，不进发行版
- **BitLocker / VeraCrypt / FileVault 2** —— 未实现
- **HFS+ / Btrfs / XFS / SquashFS / YAFFS** —— 未实现
- **AD1 / DMG / QCOW 之外的商业镜像** —— 未实现

---

## Q/A

每一条都是真实踩过、并且导致过错误结论的。

### 1. `volume.parse()` 明明返回了，为什么分区信息是空的？

它检查 `head[450:454] == b"EFI PART"`，而 GPT 签名实际在**偏移 512**。所以所有 GPT 磁盘都只返回保护性 MBR。

```python
parts = volume._gpt(img, None) or volume.parse(img)   # ← 就这样
```

### 2. 目录明明是空的，为什么镜像里其实有几十个文件？

`fs.walk()` / `fs.ls_entry()` 对每个条目**只返回一个名字**，通常是 8.3 短名，长文件名全被漏掉。

必须用 `fs.iter_mft()` + `parent_num` 自己重建路径（见 3.2）。

### 3. `fs.read_file("/Windows/System32/config/SOFTWARE")` 为什么报路径不存在？

注册表 hive 不能按路径读。按 MFT 号取：

```python
for num, name in [(1485, "SYSTEM"), (1483, "SOFTWARE"), (1487, "SAM")]:
    ent = fs.read_entry(num)
    open(name + ".hive", "wb").write(fs.read_entry_data(ent))
```

### 4. 明明是 APFS 盘，为什么读前 8 字节没魔数、被误判成 FileVault？

`NXSB` 在分区内偏移 **0x20**，前 32 字节是 `obj_phys` 结构。

```python
sub.read(0x20, 4) == b"NXSB"      # ← 正确
```

### 5. APFS 卷 OID 拿到了，为什么 `oid × block_size` 读出来是垃圾？

OID 是**虚拟对象号**，必须经容器 omap B-tree 翻译成物理地址。见 `docs/APFS.md`。

### 6. `fsx.read_file(ino)` 为什么报 AttributeError？

`mkit.ext4.Ext4` 没有 `read_file`，只有 **`read_data(ino, size=None, offset=0)`**。

```python
fsx.read_file(ino)      # AttributeError
fsx.read_data(ino)      # ← 正确
```

**更危险的是**：如果代码写成 `read_file` 又被 `except` 吞掉异常，会**静默返回 `None`**——空结果和"确实没数据"看起来一模一样。这是最危险的失败模式。

### 7. 只是读个描述符，脚本为什么挂死 / 爆内存？

`VmdkDev` 之类的代码若用 `fs.read_file(desc_path)` 读描述符，遇到 11 GB 的 VMDK 会直接 `MemoryError`，表现为"脚本挂死、长时间无输出"。

正确做法：取 runlist，只读需要的字节。

```python
runs = []
for a in fs._stream_attrs(ent, ATTR_DATA, None):
    runs.extend(a.runs)
hdr = fs.read_runs(runs, 0, 512)
```

### 8. ext4 挂上了，为什么 inode 的 `mode` 读出来是 0？

VMDK 读取丢了扇区内余数：

```python
ingrain = (ext_sec * SECTOR) % gsz          # ✗ 丢掉了 v % 512
ingrain = (v - ext_start) % gsz             # ✓
```

症状：所有非 512 字节对齐的读取都返回扇区边界数据。

### 9. LVM2 的 `"LVM2 001"` 魔数为什么找不到？

它在偏移 **0x18**，不是 0x08。`offset_xl` 在 0x14，`pv_uuid` 在 0x20。见 `docs/VMDK-LVM2.md`。

### 10. 按 GPT 分区偏移读，为什么数据错位 128 字节？

偏移 512 读到的是 GPT **头**，条目在 **LBA2（偏移 1024）**。

### 11. `format(fs.count_records(), ",")` 为什么抛 TypeError？

它返回的是 **tuple**，不是 int。

### 12. `fs.find()` 跑了半小时还没完？

931 GiB 全扫会跑到超时。已知 MFT 号时用 `fs.read_entry()`；未知时先建一次索引缓存。

### 13. `for p in parts` 挂上 ext4 后目录是空的？

循环结束后 `p` 停在最后一个分区（常是 swap）。按 `type_id` 显式过滤：

```python
for p in parts:            # ✗
    fs = Ext4(...)

p = [x for x in parts if x["type_id"] == 0x83][0]     # ✓
```

### 14. `vol.exe > file` 读出来全是乱码？

Volatility 3 重定向输出是 **UTF-16LE**，Python 必须以 `encoding='utf-16'` 读。

另：新版插件名 `hivelist` → **`registry.hivelist`**。

### 15. 中文在 Windows 控制台显示成乱码？

控制台默认 GBK。务必：

```python
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
```

PowerShell 的 `>` 重定向会产生 UTF-16 文件——用 Python 直接写文件，别用重定向。

---

## 自建扩展说明

核心库在这里有明确的空白，`ext/` 就是补这些空白的。

### 7.1 APFS 文件级读取

**核心库现状**：`mkit.macart.Apfs` 只有 `info()` 和 `volumes()`，而 `volumes()` 返回 0 条。**不能读文件**。

**扩展**：`apfs_map.py`（容器 omap B-tree 翻译）+ `apfs_fs.py`（卷文件系统树）。

```python
import apfs_map as M, apfs_fs as F

c = M.Container()
c.scan(800000, 1400000)          # 扫描容器 omap
print(c.block_size, c.vol_oids)

v = F.VolFS(c, 371006)           # 目标卷 OID
ino = v.path("/Users/foo/Desktop/a.png")
data = v.read_file(ino)
```

关键技术点见 `docs/APFS.md`。

### 7.2 VMDK / LVM2 / VHDX

**核心库现状**：无 vmware / lvm / vhdx 模块。

| 模块 | 用途 |
|---|---|
| `ans_c02vm2.py` | 拆分稀疏盘（`twoGbMaxExtentSparse`），`VmdkDev` + `Sub` |
| `webvm3_dev.py` | 单文件 `monolithicSparse`，`Dev1`（避免 MemoryError） |
| `ans_c02h_lvm.py` | LVM2 PV 标签解析 |
| `ans_c02h_webvm.py` | base + snapshot 链式读 |
| `ans_c02_vhdx.py` | Hyper-V VHDX 动态盘 |

```python
import webvm3_dev as V
dev = V.Dev1("/path/to/disk.vmdk")
print(dev.size, dev.grain_bytes)
data = dev.read(0, 512)
```

见 `docs/VMDK-LVM2.md`。

### 7.3 RAID5 缺块重建

**核心库现状**：无 mdadm 支持。

**扩展**：`com03_raid2.py`（XOR 重建）+ `com03_raidfs.py`（重建后挂 ext4）。

见 `docs/RAID5.md`。

### 7.4 图像分析

| 模块 | 用途 |
|---|---|
| `q13_judge.py` | PNG 像素级同源判定（识别 LSB 隐写关系） |
| `ans_78b_png.py` | 从 PST 中提取内嵌 PNG |
| `ans_78b_zlib.py` | zlib 容错解压 + 逐行反滤波（修复断裂 PNG） |

`q13_judge.py` 的判据：两个 PNG 若绝大多数像素通道差恰为 **±1**，且"三通道差均 ≤1 的像素"占比接近 100%，则二者是 **LSB 隐写**关系（载体 = 源图）。

### 7.5 通用工具

| 模块 | 用途 |
|---|---|
| `ans_lib.py` | MFT 索引 / `path_of` / `mft_find` / `read` / `dump` |
| `ans_c02vm2.py` | 见 7.2 |

---

## 示例脚本

`examples/` 下 6 个可直接跑的脚本（参数化，不含任何案件路径）：

| 脚本 | 演示什么 |
|---|---|
| `00_selftest.py` | 环境自检 |
| `01_mount_ewf.py` | 装载 EWF/原始镜像，识别 MBR/GPT，列出分区 |
| `02_ntfs_walk.py` | NTFS 完整路径重建（绕开第 2 条） |
| `03_apfs_read.py` | APFS 容器扫描、列卷、按路径读文件 |
| `04_vmdk_lvm.py` | VMDK → GPT → LVM2 → ext4 全链路 |
| `05_raid5.py` | mdadm RAID5 缺块 XOR 重建 |

```bash
python examples/01_mount_ewf.py  /path/to/disk.E01
python examples/02_ntfs_walk.py  /path/to/disk.E01  0x7500000  .xlsx
python examples/03_apfs_read.py  /path/to/mac.E01   0xC805000
python examples/04_vmdk_lvm.py   /path/to/ntfs.img  /path/vm/disk.vmdk
python examples/05_raid5.py      disk0.img disk2.img rebuilt.img
```

---

## 目录结构

```
ESK/
├── README.md               本文件
├── requirements.txt
├── VERSION
├── mkit/                   核心库（34 模块 / 约 27,700 行）
├── ext/                    自建扩展（34 模块）
│   └── __init__.py
├── examples/               可运行示例（6 个）
│   ├── 00_selftest.py
│   ├── 01_mount_ewf.py
│   ├── 02_ntfs_walk.py
│   ├── 03_apfs_read.py
│   ├── 04_vmdk_lvm.py
│   └── 05_raid5.py
└── docs/
    ├── APFS.md             APFS 容器/omap/B-tree 技术笔记
    ├── VMDK-LVM2.md        VMDK / LVM2 / VHDX 技术笔记
    └── RAID5.md            mdadm RAID5 重建笔记
```

---

## 已知限制

| 项 | 状态 | 说明 |
|---|---|---|
| APFS 完整 B-tree 遍历 | **未完成** | TOC 的 `voff` 偏移约定未收敛；现用"按记录类型模式匹配"绕过，能读文件但不能完整遍历 |
| APFS 快照 / FileVault | 不支持 | — |
| LVM2 元数据解析 | 部分 | `pe_start` 前 2 MB 常读为全零，采用"单 segment、`start_extent=0`"假设，靠 ext4 魔数验证 |
| RAID5 layout | 只实现 left-symmetric | 其他 layout（left-asymmetric / right-*）未覆盖 |
| VHDX | 基础读取 | 未实现日志回放 |
| 内存镜像 | 不含 | 请用 Volatility 3 |
| LUKS 解锁 | 未实现 | 仅头部解析（算法/槽/PBKDF2 迭代）；`af_merge` 分支合并未在真卷验证，不放进发行版 |
| FAT32 | 已实现未实测 | BPB/簇链/LFN 逻辑覆盖，但只在合成 FAT16 上做过回归；真实 FAT32 卷待验 |
| exFAT | 未实现 | — |
| HFS+ / Btrfs / XFS | 未实现 | — |
| BitLocker / VeraCrypt / FileVault 2 | 未实现 | — |

**用法建议**：把本包当作"文件系统层与磁盘容器层的工具"，内存与高层应用分析另找工具配合。

**关于比赛成绩**：这套东西在 2026 年美亚杯拿到个人赛二等奖、团队赛三等奖，团队赛 285/291。成绩不能反推工具质量——题目有运气成分，检材形态也有偶然性。

---

## 许可与致谢

本包为 **Calmgh06** 个人实战整理的产物，可自由使用与修改。

欢迎师傅们批判指正

**ESK by Calmgh06**

---

<sub>ESK · Calmgh06</sub>
