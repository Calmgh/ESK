<!-- ESK · Calmgh06 -->
# VMDK / LVM2 / VHDX 技术笔记

> 适用：`ext/ans_c02vm2.py`、`ext/webvm3_dev.py`、`ext/ans_c02h_lvm.py`、`ext/ans_c02_vhdx.py`
> 记录虚拟机磁盘解析的结构细节与踩过的坑。

---

## 1. 为什么自建

`mkit` 没有 VMware / LVM / VHDX 模块。而实战中经常遇到：

- 取证镜像里嵌着虚拟机磁盘（`Users/<user>/Documents/Virtual Machines/...`）
- 业务数据不在宿主系统里，而在 VM 内
- WSL 的 `ext4.vhdx` 有 187 GB，里面是 Linux 侧的全部数据

不解析这些，等于只看了一半证据。

---

## 2. VMDK

### 2.1 两种常见布局

| 类型 | `createType` | 特征 |
|---|---|---|
| 单文件稀疏盘 | `monolithicSparse` | 一个 `.vmdk` 文件，含头 + 描述符 + 数据 |
| 两 GB 分卷 | `twoGbMaxExtentSparse` | 描述符 726 B，数据分散在 `-s001.vmdk` ~ `-sNNN.vmdk` |

**关键区分方法**：看文件大小。
- 726 字节 → 纯描述符（分卷盘）
- 几 GB ~ 几十 GB → 单文件稀疏盘（**描述符内嵌在文件头部**）

### 2.2 坑：把整个 VMDK 当描述符读

有的代码这样写：

```python
desc = fs.read_file(desc_path).decode("utf-8", "ignore")     # ✗
```

对 726 字节的分卷描述符没问题。但对一个 **11 GB 的 `monolithicSparse`** 盘，这会：

1. 试图把 11 GB 读进内存 → `MemoryError`
2. 或者先挂住几十秒到几分钟，看起来像"脚本卡死"

**正确做法**：取 runlist，只读头部 512 字节。

```python
runs = []
for a in fs._stream_attrs(ent, M.ATTR_DATA, None):
    runs.extend(a.runs)
runs.sort(key=lambda r: r[0])

hdr = fs.read_runs(runs, 0, 512)
```

`webvm3_dev.Dev1` 就是这么实现的。

### 2.3 KDMV 头字段

```python
(magic, version, flags, capacity, grain_size,
 desc_off, desc_size, num_gtes) = struct.unpack_from("<IIIIQQQQI", hdr, 0)
rgd_off, gd_off, overhead = struct.unpack_from("<QQQ", hdr, 48)
```

| 偏移 | 字段 | 说明 |
|---|---|---|
| 0x00 | `magic` | `"KDMV"` = `0x564D444B` |
| 0x04 | `version` | 通常 1 |
| 0x08 | `flags` | — |
| 0x0C | `capacity` | **虚拟容量（扇区数）** |
| 0x14 | `grainSize` | **扇区数**，通常 128 = 64 KiB |
| 0x1C | `descriptorOffset` | 扇区数 |
| 0x24 | `descriptorSize` | 扇区数 |
| 0x2C | `numGTEsPerGT` | 每张 GT 的条目数，通常 512 |
| 0x30 | `rgdOffset` | 冗余 GD |
| 0x38 | `gdOffset` | **GD 表位置（扇区）** |
| 0x40 | `overHead` | 元数据总大小 |

> 有的资料把 `rgdOffset/gdOffset/overhead` 写成 0x2C/0x34/0x3C，实测是 **0x30 / 0x38 / 0x40**（因为 `numGTEsPerGT` 占了 0x2C 的 4 字节）。**以实际 hexdump 为准。**

### 2.4 GD / GT 映射

```
虚拟 grain 号 vg
    ↓
gd[vg // num_gtes]        → GT 所在扇区号（0 = 未分配）
    ↓
gt[vg %  num_gtes]        → grain 所在扇区号（0 = 空洞）
    ↓
grain 数据 = 该扇区起 grain_bytes 字节
```

### 2.5 坑：字节精确读取

这是我在 ext4 解析上耗最久的一个 bug。

**错误写法**：

```python
sec     = v // SECTOR
ext_sec = sec - ext_start
ingrain = (ext_sec * SECTOR) % grain_bytes      # ✗ 丢掉了 v % 512
```

**症状**：
- ext4 挂载成功，但 inode 2 的 `mode` 读出来是 **0**（应为 `0o40755`）
- 所有非 512 字节对齐的读取都返回扇区边界数据

**定位过程**（这个手法值得记）：

```python
dev.read(X, 512)[0:16]
# b'\x00'*8 + b'\x7d\x13\xfc\x69...'
dev.read(X + 256, 256)
# b'\x00'*8 + b'\x7d\x13\xfc\x69...'    ← 与上面开头完全相同！
dev.read(X + 512, 256)
# b'\x00' * 256                          ← 全零
```

看到"偏移 +256 读出的内容与偏移 +0 读出的开头一模一样"，就基本确定是**余数被丢弃**了。

**正确写法**：

```python
local   = v - ext_start * SECTOR        # extent 内的字节偏移
vg      = local // grain_bytes
ingrain = local %  grain_bytes          # ✓ 保留扇区内余数
n       = min(grain_bytes - ingrain, size - pos)
data    = read_grain(vg)
out[pos:pos+n] = data[ingrain:ingrain+n]
```

修正后 inode 2 的 `mode = 0x41ED = 0o40755` ✓。

---

## 3. LVM2

### 3.1 为什么需要

Linux 的根分区常是 **GPT → LVM2 → ext4** 三层。直接按 GPT 分区偏移挂 ext4 必然失败，因为中间隔了一层 LVM。

### 3.2 PV 标签布局

在物理卷起始处偏移 **0x200**（第 2 扇区）：

| 偏移 | 字段 | 说明 |
|---|---|---|
| 0x00 | `"LABELONE"` | 8 字节标识 |
| 0x08 | `sector_xl` | 8 字节，标签所在扇区号 |
| 0x10 | `crc_xl` | 4 字节 |
| 0x14 | `offset_xl` | 4 字节，**pv_header 的字节偏移** |
| 0x18 | `"LVM2 001"` | 8 字节 ← **注意在 0x18，不是 0x08** |
| 0x20 | `pv_uuid` | 32 字节 ASCII |

**这个偏移我在网上看到过至少两种说法**，最后靠 hexdump 确认：

```
00000200  4c 41 42 45 4c 4f 4e 45 01 00 00 00 00 00 00 00  LABELONE........
00000210  33 a6 bd 27 20 00 00 00 4c 56 4d 32 20 30 30 31  3..' ...LVM2 001
00000220  72 4f 35 4c 41 55 32 48 5a 31 71 6a 70 6d 48 6d  rO5LAU2HZ1qjpmHm
00000230  30 67 5a 6f 79 5a 31 68 4e 45 76 39 6c 44 4b 42  0gZoyZ1hNEv9lDKB
```

读法：
- `0x00..0x07` = `LABELONE`
- `0x08` = `01 00 00 00 00 00 00 00` → `sector_xl = 1`
- `0x10` = `33 a6 bd 27` → `crc_xl`
- `0x14` = `20 00 00 00` → **`offset_xl = 0x20 = 32`**
- `0x18` = `LVM2 001` ✓
- `0x20` = `rO5LAU2HZ1qjpmHm0gZoyZ1hNEv9lDKB` → `pv_uuid`

### 3.3 pv_header

起点 = `0x200 + offset_xl`（本例 = 0x220）。

| 偏移 | 字段 |
|---|---|
| +0x00 | `pv_uuid` (32B) |
| +0x20 | `device_size` (8B) |
| +0x28 | **`pe_start` (8B)** ← 关键 |

`pe_start` 是**物理区（physical extent）的起始字节偏移**，实测 `0x100000` = 1,048,576 字节 = 2048 扇区。

### 3.4 定位 LV

若只有一个 LV 且 `start_extent = 0`：

```
ext4 起始 = 分区起始 + pe_start
```

实测：

```
part2_start = 4,198,400 × 512 = 2,149,580,800
pe_start                      =         1,048,576
ext4 起始                      =     2,150,629,376
```

**验证**：在 `起始 + 1024 + 0x38` 处读 2 字节，应为 `53 EF`（ext4 魔数）。

### 3.5 元数据读不到怎么办

理论上 `pe_start` 之前有 metadata area，含 VG/LV 的**文本定义**（可以直接搜 `ubuntu-vg`、`ubuntu-lv`、`start_extent`）。

但实测该区域常常读出来是**全零**（可能已被清、或在别的位置）。

**兜底方案**：既然 `pe_start` 拿到了，直接假设"单 segment、`start_extent = 0`"，从 `pe_start` 处试挂 ext4，用魔数 `0x53 0xEF` 验证。

```python
for cand in (pe_start, pe_start + 0x100000, pe_start + 8192 * 512):
    if dev.read(part_start + cand + 1024 + 0x38, 2) == b"\x53\xef":
        fs = Ext4(V.Sub(dev, part_start + cand))
        break
```

这个假设在实践中成立，但**要知道它不是绝对的**——多 segment 或多 LV 的情况会失效。

---

## 4. VHDX

### 4.1 结构

| 区域 | GUID |
|---|---|
| BAT（块分配表） | `2DC27766-F623-4200-9D64-115E9BFD4A08` |
| METADATA | `8B7CA206-4790-4B9A-B8FE-575F050F886E` |
| LOG | `E7C4A76F-3F5D-4B7E-9F3B-0A0C3B9C9E1D` |

块大小通常 1 MB。

### 4.2 BAT 状态值

| 值 | 含义 |
|---|---|
| 0 | 未映射（读零） |
| 1 | 未分配 |
| 2 | 零（读零） |
| 3 | 未映射 |
| 4 | 全零 |
| 5 | 未分配 |
| 6 | **部分存在**（只有部分扇区在文件里） |
| 7 | **存在**（完整） |

**注意**：只扫状态 7 会漏掉状态 6 的部分数据。如果要完整，得读 PAYLOAD_BLOCK_STATUS 位图。

### 4.3 WSL 的 ext4.vhdx

WSL2 把 Linux 根文件系统放在 `ext4.vhdx` 里，位置通常是：

```
C:\Users\<user>\AppData\Local\Packages\
  CanonicalGroupLimited.Ubuntu_<hash>\LocalState\ext4.vhdx
```

体积可达 187 GB。里面是完整的 ext4，可以用本包解析后交给 `mkit.ext4.Ext4` 挂载。

---

## 5. 完整链路示例

```python
import sys
sys.path.insert(0, "ESK")
sys.path.insert(0, "ESK/ext")

import webvm3_dev as V
from mkit.ext4 import Ext4
import struct

# 1. 打开 VMDK
dev = V.Dev1("/path/to/disk.vmdk")
print("容量 %.2f GiB" % (dev.size / 2**30))

# 2. 解析 GPT（条目在 LBA2 = 偏移 1024）
gpt = dev.read(1024, 128 * 128)
for i in range(128):
    e = gpt[i*128:(i+1)*128]
    if e[:16] == b"\x00" * 16:
        continue
    first = struct.unpack_from("<Q", e, 32)[0]
    n     = struct.unpack_from("<Q", e, 40)[0] - first + 1
    print(i, hex(first*512), n*512)

# 3. 若是 LVM PV，读 pe_start
lab = dev.read(part_start + 0x200, 512)
offset_xl = struct.unpack_from("<I", lab, 0x14)[0]
pe_start  = struct.unpack_from("<Q", dev.read(part_start + 0x200 + offset_xl + 0x28, 8), 0)[0]

# 4. 挂 ext4
lv_off = part_start + pe_start
assert dev.read(lv_off + 1024 + 0x38, 2) == b"\x53\xef"
fs = Ext4(V.Sub(dev, lv_off))
print(fs.block_size, fs.blocks_count)
print([e.name for e in fs.listdir(fs.lookup("/"))])
```

---

## 6. 踩坑速查

| 坑 | 症状 | 解法 |
|---|---|---|
| 把整个 VMDK 当描述符读 | `MemoryError` / 长时间无输出 | runlist + `read_runs(0, 512)` |
| KDMV 头字段偏移记错 | `num_gtes` 等读出垃圾 | `numGTEsPerGT@0x2C`, `gdOffset@0x38` |
| 读取丢 `v % 512` 余数 | inode `mode` 读出 0 | `ingrain = local % grain_bytes` |
| GPT 条目从 512 读 | 错位 128 字节 | 条目在 **1024** |
| `"LVM2 001"` 找在 0x08 | 读不到 | 在 **0x18** |
| LVM 元数据全零 | 搜不到 `ubuntu-vg` | 用 `pe_start` + 魔数验证兜底 |
| VHDX 只扫状态 7 | 漏数据 | 状态 6 也要读 |

---

<sub>ESK · **Calmgh06**</sub>
