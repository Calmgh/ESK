<!-- mkit_toolkit · dev by Calmgh06 -->
# RAID5 缺块重建笔记

> 适用：`ext/com03_raid2.py`、`ext/com03_raidfs.py`

---

## 1. 场景

一次实战中拿到 3 块硬盘的镜像：

```
DISK0  20 GiB   —— 系统盘（MBR，ext4 + swap）
DISK1  10 GiB   —— RAID5 成员
DISK2  10 GiB   —— RAID5 成员
```

**缺 `role1`**。数组本来是 `raid_disks = 3`，只有两块。

问题：业务数据（NAS 的 `/USERS` 共享目录）全在 RAID5 上。

---

## 2. 超级块

mdadm 的超级块（1.2 版）在成员盘**偏移 4096** 处。

```c
struct mdp_superblock_1 {
    __le32  magic;          // 0xa92b4efc
    __le32  major_version;  // 1
    __le32  feature_map;
    __le32  pad0;
    __le64  set_uuid;
    char    set_name[32];
    __le64  ctime;
    __le32  level;          // 5 = RAID5
    __le32  layout;         // 0=left-asym, 1=right-asym, 2=left-sym, ...
    __le64  size;
    __le32  chunksize;      // 字节
    __le32  raid_disks;
    ...
    __le32  dev_number;     // 本盘在数组中的角色
    ...
    __le64  data_offset;    // 扇区
    __le64  data_size;      // 扇区
};
```

### 实际读到的值

```python
f.seek(4096)
sb = f.read(4096)

magic    = struct.unpack_from("<I", sb, 0x00)[0]   # 0xa92b4efc
level    = struct.unpack_from("<I", sb, 0x10)[0]   # 5
layout   = struct.unpack_from("<I", sb, 0x1C)[0]   # 2 (left-symmetric)
chunk    = struct.unpack_from("<I", sb, 0x18)[0]   # 524288 B = 512 KiB
raid_disks = struct.unpack_from("<I", sb, 0x20)[0] # 3
dev_number = ... # role 0 与 2
data_offset = struct.unpack_from("<Q", sb, 0x80)[0] * 512
data_size   = struct.unpack_from("<Q", sb, 0x88)[0] * 512
```

本次实测：

```
set_name    = openmediavault:0
level       = 5
layout      = 2  (left-symmetric)
chunk       = 512 KiB
raid_disks  = 3
data_offset = 9 MiB
roles       = [0, 2]     ← 缺 1
```

---

## 3. RAID5 的 XOR 原理

RAID5 的每个 stripe（一个 chunk 宽）上：

```
数据块_0 XOR 数据块_1 XOR ... XOR 校验块 = 0
```

所以：

```
缺失块 = 其余所有块逐字节 XOR
```

三盘 RAID5 缺一块 → 两块 XOR 就是缺失的那块。

---

## 4. left-symmetric 布局

`layout = 2` 是 left-symmetric：校验块从最后一块开始，每个 stripe 左移一位。

**但是**：如果只是要重建缺失的那一整块盘，而缺失的盘恰好是 `role1`，那么情况会简化——

对于三盘 left-symmetric，缺失的 `role1` 在每个 stripe 上要么是数据块、要么是校验块，但**无论哪种，用另外两块 XOR 得到的结果都是正确的**（XOR 的可逆性）。

所以：

```python
for 每个字节位置:
    recovered = disk0_byte ^ disk2_byte
```

这个简化**只在"恰好缺一块"时成立**。缺两块就不行。

---

## 5. 实际实现

```python
def rebuild(d1, d2, out, data_offset, data_size):
    blk = 4 << 20                       # 4 MB 分块
    done = 0
    while done < data_size:
        n = min(blk, data_size - done)
        d1.seek(data_offset + done)
        d2.seek(data_offset + done)
        a = d1.read(n)
        b = d2.read(n)
        # 补齐短读
        if len(a) < n: a += b"\x00" * (n - len(a))
        if len(b) < n: b += b"\x00" * (n - len(b))
        out.write(bytes(x ^ y for x, y in zip(a, b)))
        done += n
```

**性能**：`bytes(x ^ y for ...)` 对 20 GB 太慢。生产代码用：

```python
import numpy as np
out.write((np.frombuffer(a, np.uint8) ^ np.frombuffer(b, np.uint8)).tobytes())
```

快 1~2 个数量级。

---

## 6. 验证——这一步不能省

重建完**必须验证**，否则整个后续分析都建立在错误数据上。

本次用的三重校验：

### 6.1 大小校验

```
重建结果    = 21,455,962,112 字节
ext4 声明   = 5,238,272 块 × 4096 字节/块 = 21,455,962,112 字节
                          ↓
                    完全相等 ✓
```

### 6.2 超级块校验

在重建镜像的偏移 1024 + 0x38 处读 ext4 魔数：

```python
assert img.read(1024 + 0x38, 2) == b"\x53\xef"
```

### 6.3 挂载校验

```python
from mkit.ext4 import Ext4
fs = Ext4(img)
print(fs.block_size, fs.blocks_count, fs.inodes_count)
print([e.name for e in fs.listdir(fs.lookup("/"))])
# → ['lost+found', 'USERS']
```

根目录出现预期的 `USERS`，说明数据完整。

### 6.4 unrecoverable 检查

ext4 超级块里有 `s_unrecoverable` 之类标志；`fsck` 也能报。本次 `unrecoverable = 0`。

---

## 7. 踩坑

| 坑 | 说明 |
|---|---|
| `data_offset` 忘了乘 512 | 超级块里是扇区数，不是字节 |
| chunk 大小没读对 | `chunksize` 字段是**字节**，不是扇区 |
| 缺两块还想重建 | RAID5 只能容一块盘失效，缺两块数据不可恢复 |
| 不验证就往下跑 | 重建错了会得到"结构合理但内容错乱"的 ext4，比直接挂不上更坑 |
| 用 Python 逐字节 XOR | 20 GB 会跑到天荒地老，用 numpy |

---

## 8. 代码入口

```python
import sys
sys.path.insert(0, "mkit_toolkit")
sys.path.insert(0, "mkit_toolkit/ext")

# 方式一：用现成脚本
#   python examples/05_raid5.py disk0.img disk2.img rebuilt.img

# 方式二：自己调
import com03_raid2 as R
sb = R.read_sb(open("disk0.img", "rb"))
print(sb)
```

`com03_raidfs.py` 里封装了"读超级块 → XOR 重建 → 挂 ext4 → 遍历"的完整流程。

---

## 9. 如果缺的不是 role1

上面的简化只适用于"缺哪块都能用其余两块 XOR"，因为 XOR 可逆。

但如果缺了**两块**，或者 `raid_disks > 3` 缺一块非校验位置，就需要按 layout 逐 stripe 计算，代码复杂度会显著上升。

`com03_raid2.py` 里保留了一份完整 layout 的实现，可作参考。

---

<sub>mkit_toolkit · **dev by Calmgh06**</sub>
