# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""多种 RAID 级别的重组读取

成员盘只需提供 `read(offset, size)` 与 `size`，因此可以直接喂
`mkit.image.SubImage`、`mkit.vdisk.Qcow2`、`mkit.dmg.Dmg` 等任何设备对象。

============================================================================
已实现
============================================================================
1. RAID0 —— 条带切分，无冗余
2. RAID1 —— 镜像；读失败自动换副本并留痕
3. RAID4 —— 奇偶固定为最后一盘
4. RAID5 —— left-sync / right-sync 两种布局；缺 1 盘用 XOR 重建
5. RAID6 —— P + Q 双校验；缺 1 盘重建；**缺 2 盘用 P、Q 联立求解**
6. RAID10 —— near / far / offset 三种副本排布
7. GF(2^8) —— 多项式 0x11D，exp/log 表实现乘除与求逆
8. 降级读取 —— `degraded()` / `warnings()` 如实反映哪些盘不可读、做过哪些重建

============================================================================
不实现（明确边界）
============================================================================
· 写回与重同步：本模块只读，不产生任何写操作
· 元数据解析：IMSM / DDF 等控制器元数据在别的模块；这里只接受已经算好的
  成员顺序与起始偏移
· 条带大小不一致、成员盘容量不一致时的裁剪策略：按最小成员盘与给定
  chunk 计算逻辑容量，不做跨盘重映射
· 坏块级重试（读某一扇区失败只按整段换盘，不做扇区级重试）
· 三重校验（RAID7 / RAID-TP）与 RAID5E/5EE

============================================================================
几何约定
============================================================================
数据按「条带行」组织：一行覆盖所有成员各一个 chunk。
    stripe_row   = 逻辑偏移 // (chunk * 数据盘数)
    in_row_off   = 逻辑偏移 %  (chunk * 数据盘数)
    data_index   = in_row_off // chunk          （该行内第几个数据块）
    in_chunk     = in_row_off %  chunk
再按各布局把 data_index 映射到物理盘号与盘内偏移。
"""

import struct

__all__ = [
    "Raid", "RaidError",
    "gf_mul", "gf_div", "gf_inv", "gf_pow",
    "raid0", "raid1", "raid4", "raid5", "raid6", "raid10",
    "LAYOUTS", "LEVELS",
]

GF_POLY = 0x11D          # x^8 + x^4 + x^3 + x^2 + 1

LAYOUTS = {
    0: ("stripe",),
    1: ("mirror",),
    4: ("fixed-parity",),
    5: ("left", "right"),
    6: ("left", "right"),
    10: ("near", "far", "offset"),
}
LEVELS = tuple(sorted(LAYOUTS))


class RaidError(Exception):
    """成员数不合、布局不支持、缺盘过多等"""


# ------------------------------------------------------------
# GF(2^8)
# ------------------------------------------------------------
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _gf_init():
    """用生成元 2 建 exp/log 表；多项式 0x11D"""
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= GF_POLY
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]
    _GF_LOG[0] = -1          # 0 没有对数


_gf_init()


def gf_mul(a, b):
    """GF(2^8) 乘法"""
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def gf_div(a, b):
    """GF(2^8) 除法；b 为 0 抛异常"""
    if b == 0:
        raise ZeroDivisionError("GF(2^8) 里除以 0")
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]


def gf_inv(a):
    """GF(2^8) 求逆元"""
    if a == 0:
        raise ZeroDivisionError("GF(2^8) 里 0 没有逆元")
    return _GF_EXP[(255 - _GF_LOG[a]) % 255]


def gf_pow(a, n):
    """GF(2^8) 幂；RAID6 的 Q 需要 2^i"""
    if n == 0:
        return 1
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] * n) % 255]


def _gf_mul_region(buf, factor):
    """把一段字节整体乘 factor（就地返回新 bytes）"""
    if factor == 1:
        return bytes(buf)
    if factor == 0:
        return b"\x00" * len(buf)
    exp = _GF_EXP
    log = _GF_LOG
    lf = log[factor]
    return bytes(exp[log[b] + lf] if b else 0 for b in buf)


def _gf_add_region(a, b):
    """GF(2^8) 加法 = XOR；长度取较长者，短者补零"""
    if len(a) < len(b):
        a, b = b, a
    out = bytearray(a)
    for i, x in enumerate(b):
        out[i] ^= x
    return bytes(out)


# ------------------------------------------------------------
# 布局：把「行内第几个数据块」映射到「物理盘号」
# ------------------------------------------------------------
def _parity_index(level, layout, row, n):
    """该行的校验盘号

    RAID4 固定为最后一盘；RAID5 左同步 = (n-1) - row%n，右同步 = row%n；
    RAID6 的 P 与 Q 占相邻两列，按行轮转（P 在 row%n，Q 在 (row+1)%n）。
    """
    if level == 4:
        return n - 1
    if layout == "left":
        return (n - 1) - (row % n)
    return row % n


def _data_disk_index(level, layout, row, data_index, n):
    """行内第 data_index 个数据块落在哪块盘（跳过校验盘）"""
    if level in (0, 1):
        return data_index

    ndata = n - 1 if level in (4, 5) else n - 2
    if data_index >= ndata:
        raise RaidError("data_index %d 超出该行数据块数 %d" % (data_index, ndata))

    if level == 4:
        # 固定校验在最后一盘，数据按顺序填 0..n-2
        return data_index

    if level == 5:
        p = _parity_index(level, layout, row, n)
        if layout == "left":
            # 数据从 p+1 开始顺时针填充
            return (p + 1 + data_index) % n
        # right: 数据从 0 开始，遇到 p 跳过
        return data_index if data_index < p else data_index + 1

    # RAID6：P 与 Q 占两列
    p = row % n
    q = (row + 1) % n
    if layout == "left":
        start = q
        out = (start + 1 + data_index) % n
    else:
        start = p
        out = data_index if data_index < min(p, q) else data_index + 2
        if min(p, q) <= data_index < max(p, q):
            out = data_index + 1
    if out in (p, q):
        # 兜底：沿着环找第一个非校验位
        for k in range(n):
            cand = (out + k) % n
            if cand not in (p, q):
                return cand
    return out


def _raidsix_columns(row, n, layout):
    """RAID6 该行的 (P 盘号, Q 盘号, [数据盘号按 Q 权重顺序])"""
    p = row % n
    q = (row + 1) % n
    data = [i for i in range(n) if i != p and i != q]
    if layout == "left":
        # 让数据列按 Q 的权重顺序排列：权重 = 2^k，k 为该列在数据序列里的位置
        pass
    return p, q, data


# ------------------------------------------------------------
# 主体
# ------------------------------------------------------------
class Raid(object):
    """RAID 只读视图

    members: 成员盘对象列表（需有 read(offset,size) 与 size）
    level:   0 / 1 / 4 / 5 / 6 / 10
    chunk:   条带单元字节数
    missing: 缺失的成员盘序号集合（这些位置按重建处理）
    """

    def __init__(self, members, level, chunk=65536, layout=None,
                 missing=None, member_offsets=None):
        level = int(level)
        if level not in LAYOUTS:
            raise RaidError("不支持的 RAID 级别：%d（支持 %s）" % (level, list(LEVELS)))

        self.level = level
        self.members = list(members)
        n = len(self.members)
        if n < 2 and level != 1:
            raise RaidError("RAID%d 至少需要 2 块成员盘，收到 %d" % (level, n))
        if level == 4 and n < 3:
            raise RaidError("RAID4 至少需要 3 块成员盘")

        self.n = n
        self.chunk = int(chunk)
        if self.chunk <= 0 or (self.chunk & (self.chunk - 1)):
            # 允许非 2 的幂，但记录告警（md 允许任意 chunk）
            pass

        allowed = LAYOUTS[level]
        if layout is None:
            layout = allowed[0]
        if layout not in allowed:
            raise RaidError("RAID%d 不支持布局 %r（可选 %s）"
                            % (level, layout, list(allowed)))
        self.layout = layout

        self.missing = set(missing or ())
        for m in self.missing:
            if not (0 <= m < n):
                raise RaidError("缺失盘序号 %d 越界（共 %d 块）" % (m, n))

        if member_offsets is None:
            member_offsets = [0] * n
        if len(member_offsets) != n:
            raise RaidError("member_offsets 长度 %d 与成员盘数 %d 不符"
                            % (len(member_offsets), n))
        self.member_offsets = [int(x) or 0 for x in member_offsets]

        self._warnings = []
        self._good = []          # 每块盘当前是否可读
        for i, m in enumerate(self.members):
            self._good.append(i not in self.missing and self._probe_member(i))

        # 逻辑容量
        self.size = self._compute_size()

        # 缺盘数校验
        ndata = self._data_disks_per_row()
        if self.num_missing_good() > self._redundancy():
            raise RaidError(
                "RAID%d 允许最多 %d 块盘不可读，实际 %d 块，无法重建"
                % (level, self._redundancy(), self.num_missing_good()))

    # ---------- 基本查询 ----------
    def num_missing_good(self):
        return sum(1 for g in self._good if not g)

    def _redundancy(self):
        return {0: 0, 1: self.n - 1, 4: 1, 5: 1, 6: 2}.get(self.level, 1)

    def _probe_member(self, i):
        try:
            m = self.members[i]
            return bool(getattr(m, "size", 0)) and m.read(0, 1) != b""
        except Exception:
            return False

    def _data_disks_per_row(self):
        if self.level in (0,):
            return self.n
        if self.level == 1:
            return 1
        if self.level == 4:
            return self.n - 1
        if self.level == 5:
            return self.n - 1
        if self.level == 6:
            return self.n - 2
        if self.level == 10:
            return self.n // 2
        return self.n

    def _member_capacity(self, i):
        m = self.members[i]
        size = int(getattr(m, "size", 0) or 0) - self.member_offsets[i]
        return max(0, size)

    def _compute_size(self):
        caps = [self._member_capacity(i) for i in range(self.n)]
        usable = min(caps) if caps else 0
        if self.level == 0:
            return usable * self.n
        if self.level == 1:
            return usable
        if self.level == 4:
            return usable * (self.n - 1)
        if self.level == 5:
            return usable * (self.n - 1)
        if self.level == 6:
            return usable * (self.n - 2)
        if self.level == 10:
            return usable * (self.n // 2)
        return usable

    def info(self):
        return {
            "level": self.level,
            "layout": self.layout,
            "chunk": self.chunk,
            "members": self.n,
            "member_offsets": list(self.member_offsets),
            "missing": sorted(self.missing),
            "unreadable": [i for i, g in enumerate(self._good) if not g],
            "degraded": self.degraded(),
            "size": self.size,
            "warnings": list(self._warnings),
        }

    def degraded(self):
        return self.num_missing_good() > 0

    def warnings(self):
        return list(self._warnings)

    # ---------- 单盘读 ----------
    def _read_member(self, i, off, size):
        """读第 i 块盘的 [off, off+size)；失败或短读返回 None 并留痕"""
        if not self._good[i]:
            return None
        base = self.member_offsets[i]
        try:
            d = self.members[i].read(base + off, size)
        except Exception as e:
            self._good[i] = False
            self._warnings.append("盘 %d 读 0x%X 处失败（%s），标记为不可读"
                                  % (i, off, e))
            return None
        if d is None or len(d) < size:
            self._good[i] = False
            self._warnings.append("盘 %d 在 0x%X 处短读（%d/%d），标记为不可读"
                                  % (i, off, len(d or b""), size))
            return None
        return d

    def _read_member_padded(self, i, off, size):
        """读到多少算多少，不足补零（用于容量边界）"""
        d = self._read_member(i, off, size)
        if d is None:
            return None
        return d

    # ---------- 行读取 ----------
    def _read_row(self, row, length):
        """读一条带行中每块盘该行的 chunk（长度 length ≤ chunk）"""
        base = row * self.chunk
        out = []
        for i in range(self.n):
            d = self._read_member(i, base, length)
            if d is None:
                d = self._read_member(i, base, length)   # 再试一次
            out.append(d)
        return out

    # ---------- 对外读 ----------
    def read(self, offset, size):
        if offset < 0 or size <= 0 or offset >= self.size:
            return b""
        size = min(size, self.size - offset)
        if self.level == 1:
            return self._read_mirror(offset, size)
        if self.level == 10:
            return self._read_raid10(offset, size)
        return self._read_striped(offset, size)

    def _read_mirror(self, offset, size):
        out = bytearray()
        pos = offset
        end = offset + size
        while pos < end:
            take = min(self.chunk * 64, end - pos)
            got = None
            for i in range(self.n):
                d = self._read_member(i, pos, take)
                if d is not None:
                    got = d
                    break
                self._warnings.append("RAID1：盘 %d 在 0x%X 读不到，换下一块" % (i, pos))
            if got is None:
                self._warnings.append("RAID1：0x%X 起 %d 字节所有副本都读不到，补零"
                                      % (pos, take))
                got = b"\x00" * take
            out += got
            pos += take
        return bytes(out)

    def _read_striped(self, offset, size):
        out = bytearray()
        pos = offset
        end = offset + size
        ndata = self._data_disks_per_row()
        row_bytes = self.chunk * ndata

        while pos < end:
            row = pos // row_bytes
            in_row = pos % row_bytes
            data_index = in_row // self.chunk
            in_chunk = in_row % self.chunk
            take = min(self.chunk - in_chunk, end - pos)

            block = self._get_row_span(row, data_index, in_chunk, take)
            out += block
            pos += take
        return bytes(out)

    def _get_row_span(self, row, data_index, in_chunk, take):
        """取某行第 data_index 个数据块的 [in_chunk, in_chunk+take)"""
        if self.level == 0:
            disk = data_index
            d = self._read_member(disk, row * self.chunk + in_chunk, take)
            if d is None:
                self._warnings.append("RAID0：盘 %d 在行 %d 读不到，补零" % (disk, row))
                return b"\x00" * take
            return d

        if self.level == 4 or self.level == 5:
            disk = _data_disk_index(self.level, self.layout, row, data_index, self.n)
            want = self.chunk
            d = self._read_member(disk, row * self.chunk + in_chunk, take)
            if d is not None:
                return d
            # 该盘不可读 -> 用 P 重建整块
            seg = self._rebuild_raid5_block(row, disk)
            if seg is None:
                return b"\x00" * take
            return seg[in_chunk:in_chunk + take]

        if self.level == 6:
            disk = _data_disk_index(self.level, self.layout, row, data_index, self.n)
            d = self._read_member(disk, row * self.chunk + in_chunk, take)
            if d is not None:
                return d
            seg = self._rebuild_raid6_block(row, disk)
            if seg is None:
                return b"\x00" * take
            return seg[in_chunk:in_chunk + take]

        raise RaidError("级别 %d 没有这样的行读取路径" % self.level)

    def _row_all(self, row, length):
        """读该行所有盘；不可读的位置为 None"""
        base = row * self.chunk
        out = []
        for i in range(self.n):
            out.append(self._read_member(i, base, length))
        return out

    def _rebuild_raid5_block(self, row, bad_disk):
        """XOR 重建 RAID5 缺块"""
        blocks = self._row_all(row, self.chunk)
        acc = None
        for i, b in enumerate(blocks):
            if i == bad_disk or b is None:
                continue
            acc = b if acc is None else _gf_add_region(acc, b)
        if acc is None:
            self._warnings.append("RAID5：行 %d 盘 %d 无可用数据重建" % (row, bad_disk))
            return None
        acc = _pad_to(acc, self.chunk)
        self._warnings.append("RAID5：行 %d 盘 %d 用 XOR 重建" % (row, bad_disk))
        return acc

    def _rebuild_raid6_block(self, row, bad_disk):
        """RAID6 重建：缺 1 块用 P 或 Q，缺 2 块用 P+Q 联立"""
        blocks = self._row_all(row, self.chunk)
        p, q, data_disks = _raidsix_columns(row, self.n, self.layout)
        bad = [i for i, b in enumerate(blocks) if b is None]
        if bad_disk not in bad:
            bad.append(bad_disk)

        if len(bad) == 1:
            # 单块缺失：优先用 P（对数据盘）或 Q（对 P 盘）
            seg = self._rebuild_raid6_single(row, blocks, p, q, data_disks, bad[0])
            if seg is not None:
                self._warnings.append("RAID6：行 %d 盘 %d 单块重建" % (row, bad[0]))
            return seg

        if len(bad) == 2:
            seg_a, seg_b = self._rebuild_raid6_double(row, blocks, p, q, data_disks, bad)
            if seg_a is None:
                return None
            self._warnings.append("RAID6：行 %d 盘 %d,%d 用 P+Q 联立重建"
                                  % (row, bad[0], bad[1]))
            return seg_a if bad[0] == bad_disk else seg_b

        self._warnings.append("RAID6：行 %d 缺 %d 块，超出双校验能力" % (row, len(bad)))
        return None

    def _rebuild_raid6_single(self, row, blocks, p, q, data_disks, bad):
        """缺 1 块"""
        if bad == q:
            # 用 P 恢复 Q：Q = Σ D_i·2^i
            return self._compute_q(blocks, data_disks)
        if bad == p:
            # 用 Q 反推 P：P = XOR(其余) 也可，但 P 本身就是 XOR，直接用数据算
            acc = None
            for d in data_disks:
                b = blocks[d]
                if b is None:
                    continue
                acc = b if acc is None else _gf_add_region(acc, b)
            return _pad_to(acc, self.chunk) if acc is not None else None
        # 缺一个数据盘：用 P 恢复（P = XOR(所有数据)）
        acc = None
        for i, b in enumerate(blocks):
            if i == bad or i == q or b is None:
                continue
            acc = b if acc is None else _gf_add_region(acc, b)
        return _pad_to(acc, self.chunk) if acc is not None else None

    def _compute_q(self, blocks, data_disks):
        """Q = Σ D_i · 2^i"""
        acc = None
        for k, d in enumerate(data_disks):
            b = blocks[d]
            if b is None:
                return None
            term = _gf_mul_region(b, gf_pow(2, k))
            acc = term if acc is None else _gf_add_region(acc, term)
        return _pad_to(acc, self.chunk) if acc is not None else None

    def _rebuild_raid6_double(self, row, blocks, p, q, data_disks, bad):
        """缺 2 块：用 P 与 Q 联立求解

        返回 (bad[0] 的重建块, bad[1] 的重建块)，按盘号升序对应。

        记数据盘按 data_disks 顺序编号，第 t 个数据盘 D_t 在 Q 里的权重是 2^t：
            P = XOR(所有 D_t)
            Q = Σ D_t · 2^t
        分三种情形，各自能解出唯一答案；缺 P 又缺 Q 时无解（返回 None）。
        """
        bad = sorted(bad)
        d0, d1 = bad[0], bad[1]
        k = self.chunk

        # 已知数据盘的 XOR 与加权和
        p_known = None
        q_known = None
        for t, disk in enumerate(data_disks):
            if disk in (d0, d1):
                continue
            blk = blocks[disk]
            if blk is None:
                return (None, None)
            p_known = blk if p_known is None else _gf_add_region(p_known, blk)
            term = _gf_mul_region(blk, gf_pow(2, t))
            q_known = term if q_known is None else _gf_add_region(q_known, term)
        p_known = _pad_to(p_known or b"", k)
        q_known = _pad_to(q_known or b"", k)

        def get(disk):
            b = blocks[disk]
            return None if b is None else _pad_to(b, k)

        # ---- 情形 1：缺 P 与一个数据盘（用 Q 反解该数据盘，再算 P）----
        if d0 == p or d1 == p:
            ddisk = d1 if d0 == p else d0
            if ddisk == q:
                return (None, None)          # 缺 P 又缺 Q，无冗余可用
            t = data_disks.index(ddisk)
            qv = get(q)
            if qv is None:
                return (None, None)
            # Q = D·2^t ⊕ q_known  ->  D = (Q ⊕ q_known) / 2^t
            seg_d = _pad_to(_gf_mul_region(
                _gf_add_region(qv, q_known), gf_inv(gf_pow(2, t))), k)
            seg_p = _pad_to(_gf_add_region(seg_d, p_known), k)
            return (seg_p, seg_d) if d0 == p else (seg_d, seg_p)

        # ---- 情形 2：缺 Q 与一个数据盘（用 P 反解该数据盘，再算 Q）----
        if d0 == q or d1 == q:
            ddisk = d1 if d0 == q else d0
            t = data_disks.index(ddisk)
            pv = get(p)
            if pv is None:
                return (None, None)
            # P = D ⊕ p_known  ->  D = P ⊕ p_known
            seg_d = _pad_to(_gf_add_region(pv, p_known), k)
            seg_q = _pad_to(_gf_add_region(
                _gf_mul_region(seg_d, gf_pow(2, t)), q_known), k)
            return (seg_q, seg_d) if d0 == q else (seg_d, seg_q)

        # ---- 情形 3：缺两个数据盘 D_a 与 D_b（P、Q 都在）----
        a = data_disks.index(d0)
        b = data_disks.index(d1)
        pv = get(p)
        qv = get(q)
        if pv is None or qv is None:
            return (None, None)

        wa = gf_pow(2, a)
        wb = gf_pow(2, b)

        # 由 P：D_a ⊕ D_b = P ⊕ p_known
        base = _pad_to(_gf_add_region(pv, p_known), k)
        # 由 Q：D_a·wa ⊕ D_b·wb = Q ⊕ q_known
        #   代入 D_a = D_b ⊕ base：
        #   D_b·(wa ⊕ wb) = Q ⊕ q_known ⊕ base·wa
        coeff = wa ^ wb                      # GF 加法即 XOR；a≠b 故非零
        rhs = _pad_to(_gf_add_region(
            qv, _gf_add_region(_gf_mul_region(base, wa), q_known)), k)
        seg_b = _pad_to(_gf_mul_region(rhs, gf_inv(coeff)), k)
        seg_a = _pad_to(_gf_add_region(seg_b, base), k)
        return (seg_a, seg_b)

    def _read_raid10(self, offset, size):
        out = bytearray()
        pos = offset
        end = offset + size
        n = self.n
        pairs = n // 2
        pair_bytes = self.chunk * pairs

        while pos < end:
            row = pos // pair_bytes
            in_row = pos % pair_bytes
            pair = in_row // self.chunk
            in_chunk = in_row % self.chunk
            take = min(self.chunk - in_chunk, end - pos)

            seg = None
            if self.layout == "near":
                a, b = pair * 2, pair * 2 + 1
            elif self.layout == "offset":
                a, b = pair, pair + pairs
                b = min(b, n - 1)
            else:                      # far
                a, b = pair, (pair + 1) % n
                if a == b:
                    b = (a + 1) % n
            for disk in (a, b):
                if disk >= n:
                    continue
                d = self._read_member(disk, row * self.chunk + in_chunk, take)
                if d is not None:
                    seg = d
                    break
                self._warnings.append("RAID10：盘 %d 在行 %d 读不到，换副本"
                                      % (disk, row))
            if seg is None:
                self._warnings.append("RAID10：行 %d 组 %d 两副本都读不到，补零"
                                      % (row, pair))
                seg = b"\x00" * take
            out += seg
            pos += take
        return bytes(out)


def _pad_to(data, size):
    if len(data) >= size:
        return data[:size]
    return data + b"\x00" * (size - len(data))


# ------------------------------------------------------------
# 便捷构造
# ------------------------------------------------------------
def raid0(members, chunk=65536, **kw):
    return Raid(members, 0, chunk, "stripe", **kw)


def raid1(members, chunk=65536, **kw):
    return Raid(members, 1, chunk, "mirror", **kw)


def raid4(members, chunk=65536, **kw):
    return Raid(members, 4, chunk, "fixed-parity", **kw)


def raid5(members, chunk=65536, layout="left", **kw):
    return Raid(members, 5, chunk, layout, **kw)


def raid6(members, chunk=65536, layout="left", **kw):
    return Raid(members, 6, chunk, layout, **kw)


def raid10(members, chunk=65536, layout="near", **kw):
    return Raid(members, 10, chunk, layout, **kw)


# ------------------------------------------------------------
# 自检
# ------------------------------------------------------------
if __name__ == "__main__":
    import io
    import sys

    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    PASS = [0]
    FAIL = [0]

    def ck(cond, name, extra=""):
        if cond:
            PASS[0] += 1
            print("  [PASS] %s %s" % (name, extra))
        else:
            FAIL[0] += 1
            print("  [FAIL] %s %s" % (name, extra))

    class MemDisk(object):
        """内存假盘"""

        def __init__(self, data=None, size=None):
            if data is None:
                data = b""
            self.data = bytes(data)
            self.size = size if size is not None else len(self.data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

        def write_at(self, off, payload):
            b = bytearray(self.data)
            need = off + len(payload)
            if len(b) < need:
                b.extend(b"\x00" * (need - len(b)))
            b[off:off + len(payload)] = payload
            self.data = bytes(b)
            # 不要缩小构造时给定的容量，否则各盘容量会被最后一次写入左右
            if len(self.data) > self.size:
                self.size = len(self.data)

    def payload(n):
        return bytes((i * 7 + (i >> 8) * 13) & 0xFF for i in range(n))

    print("=== 1) GF(2^8) 运算 ===")
    ck(gf_mul(2, 0x80) == 0x1D, "gf_mul(2,0x80)==0x1D（0x100 归约到 0x11D）",
       hex(gf_mul(2, 0x80)))
    ck(gf_mul(1, 0xAB) == 0xAB, "乘 1 保持不变")
    ck(gf_mul(0x5A, 0x00) == 0, "乘 0 得 0")
    import random
    random.seed(20261115)
    ok_round = True
    for _ in range(100):
        a = random.randrange(1, 256)
        b = random.randrange(1, 256)
        if gf_div(gf_mul(a, b), b) != a:
            ok_round = False
            break
    ck(ok_round, "随机 100 组 gf_div(gf_mul(a,b),b)==a")
    ok_inv = all(gf_mul(x, gf_inv(x)) == 1 for x in range(1, 256))
    ck(ok_inv, "1..255 全部满足 a·a⁻¹==1")
    ck(gf_pow(2, 0) == 1 and gf_pow(2, 1) == 2, "gf_pow 边界")
    ck(gf_pow(2, 8) == 0x1D, "gf_pow(2,8)==0x1D", hex(gf_pow(2, 8)))

    print()
    print("=== 2) RAID0 ===")
    N = 4 * 1024 * 10                    # 10 KB
    data = payload(N)
    chunk = 4096
    disks = [MemDisk(size=N // 4) for _ in range(4)]
    # 按条带切分写入
    for off in range(0, N, chunk):
        row = off // (chunk * 4)
        di = (off // chunk) % 4
        seg = data[off:off + chunk]
        disks[di].write_at(row * chunk, seg)
    r0 = raid0(disks, chunk)
    ck(r0.read(0, N) == data, "RAID0 4 盘逐字节还原", "(%d B)" % N)
    ck(r0.read(0, 10) == data[:10], "RAID0 头部 10 字节")
    ck(r0.read(N - 10, 10) == data[-10:], "RAID0 尾部 10 字节")
    ck(r0.read(-1, 5) == b"" and r0.read(N, 5) == b"", "RAID0 越界返回空")
    ck(r0.size == N, "RAID0 逻辑容量", r0.size)
    ck(len(r0.read(100, 500)) == 500, "RAID0 任意偏移长度正确")

    print()
    print("=== 3) RAID1 与换副本 ===")
    N1 = 6000
    d1 = payload(N1)
    a = MemDisk(d1)
    b = MemDisk(d1)
    c = MemDisk(d1)
    r1 = raid1([a, b, c], chunk=2048)
    ck(r1.read(0, N1) == d1, "RAID1 三副本读取正确")
    ck(not r1.degraded(), "RAID1 初始未降级")

    class FlakyDisk(MemDisk):
        """前 k 次读抛异常，之后正常"""

        def __init__(self, data, fail_times=1):
            MemDisk.__init__(self, data)
            self.left = fail_times

        def read(self, off, n):
            if self.left > 0:
                self.left -= 1
                raise IOError("模拟坏盘")
            return MemDisk.read(self, off, n)

    fa = FlakyDisk(d1)
    r1b = raid1([fa, MemDisk(d1)], chunk=2048)
    got = r1b.read(0, 1000)
    ck(got == d1[:1000], "RAID1 首盘抛异常时换副本仍读对")
    ck(any("换" in w or "读不到" in w for w in r1b.warnings()), "RAID1 换副本留痕",
       r1b.warnings()[:1])

    print()
    print("=== 4) RAID4 ===")
    N4 = chunk * 3 * 4                    # 4 行 × 3 数据盘
    d4 = payload(N4)
    n = 4                                  # 3 数据 + 1 P
    disks4 = [MemDisk(size=chunk * 8) for _ in range(n)]
    rows = (N4 + chunk * 3 - 1) // (chunk * 3)
    for row in range(rows):
        p_acc = None
        for di in range(3):
            off = row * chunk * 3 + di * chunk
            seg = d4[off:off + chunk]
            if len(seg) < chunk:
                seg = _pad_to(seg, chunk)
            disks4[di].write_at(row * chunk, seg)
            p_acc = seg if p_acc is None else _gf_add_region(p_acc, seg)
        disks4[3].write_at(row * chunk, p_acc)
    r4 = raid4(disks4, chunk)
    ck(r4.read(0, N4) == d4, "RAID4 读取正确", "(%d B)" % N4)
    r4d = raid4(disks4, chunk, missing={1})
    ck(r4d.read(0, N4) == d4, "RAID4 缺 1 数据盘重建正确")

    print()
    print("=== 5) RAID5 left / right ===")
    for layout in ("left", "right"):
        n5 = 4
        disks5 = [MemDisk(size=chunk * 8) for _ in range(n5)]
        N5 = chunk * 3 * 3
        d5 = payload(N5)
        rows5 = (N5 + chunk * 3 - 1) // (chunk * 3)
        for row in range(rows5):
            p = _parity_index(5, layout, row, n5)
            acc = None
            for di in range(3):
                disk = _data_disk_index(5, layout, row, di, n5)
                off = row * chunk * 3 + di * chunk
                seg = _pad_to(d5[off:off + chunk], chunk)
                disks5[disk].write_at(row * chunk, seg)
                acc = seg if acc is None else _gf_add_region(acc, seg)
            disks5[p].write_at(row * chunk, acc)
        r5 = raid5(disks5, chunk, layout)
        ck(r5.read(0, N5) == d5, "RAID5 %s 读取正确" % layout)
        ck(r5.info()["layout"] == layout, "RAID5 %s info.layout" % layout)
        # 缺一块数据盘
        r5d = raid5(disks5, chunk, layout, missing={0})
        ck(r5d.read(0, N5) == d5, "RAID5 %s 缺盘 0 重建正确" % layout)
        ck(r5d.degraded(), "RAID5 %s 缺盘时 degraded()" % layout)

    print()
    print("=== 6) RAID6 单盘与双盘缺失 ===")
    level = 6
    layout = "right"
    n6 = 5                                 # 3 数据 + P + Q
    disks6 = [MemDisk(size=chunk * 8) for _ in range(n6)]
    N6 = chunk * 3 * 3
    d6 = payload(N6)
    rows6 = (N6 + chunk * 3 - 1) // (chunk * 3)
    for row in range(rows6):
        p, q, dd = _raidsix_columns(row, n6, layout)
        acc_p = None
        acc_q = None
        for k, disk in enumerate(dd):
            off = row * chunk * 3 + k * chunk
            seg = _pad_to(d6[off:off + chunk], chunk)
            disks6[disk].write_at(row * chunk, seg)
            acc_p = seg if acc_p is None else _gf_add_region(acc_p, seg)
            term = _gf_mul_region(seg, gf_pow(2, k))
            acc_q = term if acc_q is None else _gf_add_region(acc_q, term)
        disks6[p].write_at(row * chunk, _pad_to(acc_p, chunk))
        disks6[q].write_at(row * chunk, _pad_to(acc_q, chunk))

    r6 = raid6(disks6, chunk, layout)
    ck(r6.read(0, N6) == d6, "RAID6 无缺盘读取正确")
    for miss in ({0}, {1}, {2}, {3}, {4}):
        rr = raid6(disks6, chunk, layout, missing=miss)
        ck(rr.read(0, N6) == d6, "RAID6 缺盘 %s 单块重建正确" % sorted(miss)[0])

    # 双盘缺失：逐个组合
    ok_all = True
    fails = []
    for i in range(n6):
        for j in range(i + 1, n6):
            try:
                rr = raid6(disks6, chunk, layout, missing={i, j})
                if rr.read(0, N6) != d6:
                    ok_all = False
                    fails.append((i, j))
            except RaidError as e:
                ok_all = False
                fails.append((i, j, str(e)[:30]))
    ck(ok_all, "RAID6 缺 2 盘（全部 10 种组合）用 P+Q 联立重建正确",
       "" if ok_all else fails[:3])

    print()
    print("=== 7) RAID10 near / offset ===")
    for layout10 in ("near", "offset"):
        n10 = 4
        disks10 = [MemDisk(size=chunk * 8) for _ in range(n10)]
        N10 = chunk * 2 * 3
        d10 = payload(N10)
        pairs = n10 // 2
        rows10 = (N10 + chunk * pairs - 1) // (chunk * pairs)
        for row in range(rows10):
            for pair in range(pairs):
                off = row * chunk * pairs + pair * chunk
                seg = _pad_to(d10[off:off + chunk], chunk)
                if layout10 == "near":
                    x, y = pair * 2, pair * 2 + 1
                else:
                    x, y = pair, pair + pairs
                    y = min(y, n10 - 1)
                for disk in {x, y}:
                    disks10[disk].write_at(row * chunk, seg)
        rr = raid10(disks10, chunk, layout10)
        ck(rr.read(0, N10) == d10, "RAID10 %s 读取正确" % layout10)
        rrd = raid10(disks10, chunk, layout10, missing={0})
        ck(rrd.read(0, N10) == d10, "RAID10 %s 缺 1 盘仍可读" % layout10)

    print()
    print("=== 8) 边界与报错 ===")
    try:
        Raid([MemDisk(size=100)], 5, 512)
        ck(False, "RAID5 单盘应报错")
    except RaidError as e:
        ck(True, "RAID5 单盘报错", str(e)[:34])
    try:
        Raid([MemDisk(size=100)], 7, 512)
        ck(False, "不支持的级别应报错")
    except RaidError as e:
        ck(True, "不支持的级别报错", str(e)[:34])
    try:
        Raid([MemDisk(size=100) for _ in range(3)], 5, 512, missing={0, 1})
        ck(False, "RAID5 缺 2 盘应报错")
    except RaidError as e:
        ck(True, "RAID5 缺 2 盘报错", str(e)[:34])
    try:
        Raid([MemDisk(size=100) for _ in range(3)], 5, 512, layout="near")
        ck(False, "RAID5 用 near 布局应报错")
    except RaidError as e:
        ck(True, "RAID5 非法布局报错", str(e)[:34])
    try:
        raid5([MemDisk(size=0) for _ in range(3)], 512)
        ck(False, "成员容量为 0 时应拒绝（全部盘不可读）")
    except RaidError as e:
        ck(True, "成员容量为 0 时拒绝", str(e)[:40])

    print()
    print("=" * 60)
    print("GF / RAID0 / RAID1 / RAID4 / RAID5(left,right) / RAID6 / RAID10")
    print("通过 %d 项，失败 %d 项" % (PASS[0], FAIL[0]))
    if FAIL[0]:
        raise SystemExit(1)
    print("raid 模块自检全部通过")
