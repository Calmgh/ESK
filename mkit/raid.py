# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""多级 RAID 重组读取（RAID0 / 1 / 4 / 5 / 6 / 10），纯标准库、只读。

成员盘只需要两个能力：`read(offset, size)` 与 `size`。
重组结果是逻辑卷，可直接喂 `mkit.ntfs` / `mkit.fat` / `mkit.ext4` / `mkit.volume`。

术语（本模块严格区分，混用必错）
    chunk           一个条带单元（stripe unit）的字节数
    row             一行 = 每块成员盘各取一个 chunk 的横向切片
    logical chunk   逻辑卷上的第几个 chunk，编号连续，与物理落点无关
    stripe_number   **条带单元号**，不是整行号：
                    disk = stripe_number % n
                    offset_in_disk = (stripe_number // n) * chunk + in_chunk
                    两者差 n 倍，把整行号当条带单元号会整体错位

两套条带布局都支持
    · 同步型（left / right / asymmetric）：P 在数据条带中的位置随行轮转，
      数据盘逻辑顺序按「跳过 parity 的环形映射」推出
    · 副本型（near / far / offset）：Linux md 的 RAID10 布局族

已实现：
    · RAID0   条带（无冗余）；缺盘时该段置 0 并留痕（degraded 为真）
    · RAID1   镜像；读失败/零字节/短读自动换副本，换盘路径逐次记入 warnings()
    · RAID4   固定奇偶盘（P 恒为最后一盘 n-1），缺 1 盘 XOR 重建
    · RAID5   left / right 同步（P 随行轮转 + 环形数据映射），
              另接受 md 的 asymmetric 变体、固定 P 变体（n-2 / parity-0）与数字别名；
              缺 1 盘 XOR 重建（缺数据盘或校验盘走同一路径）
    · RAID6   P + Q 双校验，GF(2^8)、不可约多项式 0x11D（x^8+x^4+x^3+x^2+1）、
              生成元 2，exp[512] / log[256] 查表，乘法走 log/exp，逆元走 exp[255-log]；
              P/Q 在相邻列上按行轮转（md 式），数据顺序接在 Q 之后环形展开；
              缺 1 盘：数据块用 P、P 用 XOR、Q 用 Σ D_i·2^i 分别重建；
              缺 2 盘：按 P、Q 联立求解（Vandermonde 形式）：
                  X1 = P ⊕ ΣD_avail        = D_a ⊕ D_b
                  X2 = Q ⊕ Σ D_avail·2^i   = D_a·2^a ⊕ D_b·2^b
                  D_a = (X2 ⊕ X1·2^b) / (2^a ⊕ 2^b)   ← GF 里真做除法（逆元）
                  D_b = X1 ⊕ D_a
              另含 (P,Q) 双失、(P,数据)、(Q,数据) 三种组合的专门解法；
              缺 3 块及以上如实置 0 并留痕，绝不假装能修
    · RAID10  near / offset / far 三种副本排布，读失败自动换副本
    · 任意偏移、任意长度的 read()，跨 chunk 自动拼接
    · 每块盘可带自己的数据起始偏移（member_offsets），适配 mdadm 的 data_offset

不实现：
    · 写回与在线修复（只读重组，绝不改成员盘）
    · mdadm 超级块自动解析（0.90 / 1.x）—— 成员顺序、chunk、data_offset 由调用方给；
      1.2 超级块字段与实测值见 docs/RAID5.md，参考实现见 ext/com03_raid2.py
      （本模块复用了它的 left/right 结论，但未改动该文件，也不 import 它）
    · DDF（SNIA）、Intel Matrix / IMSM、LSI MegaRAID 的元数据布局
    · RAID5E / 5EE / 5R / 6E 等带热备的变体、reshape 中间态
    · RAID6 的三盘失效；任意 k+m 的通用 Reed-Solomon
    · 坏道重映射表 / 坏扇区跳过表 / TRIM 未映射区的稀疏语义
    · far 布局只实现 stride = k 个 chunk 的模型（副本沿设备环外推 k 位、
      物理 chunk 同时偏移 k），未与内核 raid10.c 逐字节对拍；
      near / offset 已在自检里逐字节验证

速度：
    XOR 走 int.from_bytes 大整数异或，GF 乘法走 bytes.translate 查表，
    没有逐字节 Python 循环；但缺盘重建每读 1 个逻辑 chunk 要读 k 块盘，
    建议 chunk ≥ 64 KiB。20 GB 级别的重建仍建议先把结果落盘再挂文件系统。
"""

__all__ = [
    "GF_POLY", "gf_mul", "gf_inv", "gf_div", "gf_pow", "gf_pow2", "gf_mul_block",
    "xor_blocks", "p_parity", "q_parity",
    "raid5_parity_index", "raid5_data_order",
    "raid6_parity_indices", "raid6_data_order", "raid10_placement",
    "Raid", "RaidError", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10",
    "LEVELS", "LAYOUTS",
]

GF_POLY = 0x11D          # x^8 + x^4 + x^3 + x^2 + 1
GF_GENERATOR = 2

LEVEL_NAMES = {0: "RAID0", 1: "RAID1", 4: "RAID4", 5: "RAID5", 6: "RAID6", 10: "RAID10"}

# 每级接受的规范布局名（别名另见 _LAYOUT_ALIASES，如 "n-2" → "parity_n"）
LAYOUTS = {
    0: ("flat",),
    1: ("mirror",),
    4: ("fixed",),
    5: ("left", "right", "left-asym", "right-asym", "parity_n", "parity_0"),
    6: ("left", "right", "left-asym", "right-asym", "parity_n", "parity_0"),
    10: ("near", "offset", "far"),
}
LEVELS = tuple(sorted(LAYOUTS))

_LAYOUT_CANON = ("left", "right", "left-asym", "right-asym",
                 "parity_n", "parity_0", "near", "offset", "far", "fixed", "flat", "mirror")

_LAYOUT_ALIASES = {
    "left": "left", "left-sync": "left", "left-synchronous": "left",
    "left-sym": "left", "left-symmetric": "left", "ls": "left", "2": "left",
    "right": "right", "right-sync": "right", "right-synchronous": "right",
    "right-sym": "right", "right-symmetric": "right", "rs": "right", "3": "right",
    "left-asym": "left-asym", "left-asymmetric": "left-asym", "la": "left-asym",
    "0": "left-asym",
    "right-asym": "right-asym", "right-asymmetric": "right-asym", "ra": "right-asym",
    "1": "right-asym",
    "parity-n": "parity_n", "parity_n": "parity_n", "pn": "parity_n",
    "n-2": "parity_n", "5": "parity_n",
    "parity-0": "parity_0", "parity_0": "parity_0", "p0": "parity_0", "4": "parity_0",
    "near": "near", "n": "near", "offset": "offset", "o": "offset",
    "far": "far", "f": "far",
    # raidmeta 按 mdadm 的 layout_ddf2md 产出的名字，必须能直接喂进本模块，
    # 否则「DDF 元数据解析」和「条带几何」两半接不上（会抛 RaidError）。
    #   stripe               -> RAID0 无奇偶校验
    #   fixed-parity         -> RAID4 固定末位校验
    #   rotating-n-restart   -> RAID6 左非对称（与 RAID5 的 left-asymmetric 同序）
    #   rotating-zero-restart-> RAID6 右非对称
    #   rotating-n-continue  -> RAID6 左对称
    "stripe": "flat",
    "fixed-parity": "fixed",
    "rotating-n-restart": "left-asym",
    "rotating-zero-restart": "right-asym",
    "rotating-0-restart": "right-asym",
    "rotating-n-continue": "left",
}


class RaidError(ValueError):
    """成员数不合、布局不支持、缺盘过多等"""


# ------------------------------------------------------------------
# GF(2^8)：多项式 0x11D，生成元 2
# ------------------------------------------------------------------
_GF_EXP = [0] * 512       # 双倍长度，省掉 log 相加后的取模
_GF_LOG = [0] * 256


def _gf_init():
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= GF_POLY
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_gf_init()


def gf_mul(a, b):
    """GF(2^8) 乘法：a·b = exp[log a + log b]"""
    a &= 0xFF
    b &= 0xFF
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def gf_inv(a):
    """GF(2^8) 乘法逆元：a^-1 = exp[255 - log a]"""
    a &= 0xFF
    if a == 0:
        raise ZeroDivisionError("GF(2^8) 中 0 没有乘法逆元")
    return _GF_EXP[255 - _GF_LOG[a]]


def gf_div(a, b):
    """GF(2^8) 除法：a / b = exp[log a - log b]"""
    a &= 0xFF
    b &= 0xFF
    if b == 0:
        raise ZeroDivisionError("GF(2^8) 中不能除以 0")
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]


def gf_pow2(i):
    """2^i（i 自动对 255 取模）"""
    return _GF_EXP[i % 255]


def gf_pow(a, n):
    """a^n（演示用；重建路径不依赖它）"""
    a &= 0xFF
    if n == 0:
        return 1
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] * n) % 255]


_MUL_TBL = {}


def gf_mul_block(coef, block):
    """整块乘以常数系数：bytes.translate + 256 字节查表，不逐字节循环"""
    coef &= 0xFF
    if coef == 0:
        return bytes(len(block))
    if coef == 1:
        return bytes(block)
    tbl = _MUL_TBL.get(coef)
    if tbl is None:
        lg = _GF_LOG[coef]
        arr = bytearray(256)
        for v in range(1, 256):
            arr[v] = _GF_EXP[(_GF_LOG[v] + lg) % 255]
        tbl = bytes(arr)
        _MUL_TBL[coef] = tbl
    return bytes(block).translate(tbl)


def xor_blocks(blocks):
    """整块 XOR：走大整数异或，比 bytes(x ^ y for ...) 快一个量级"""
    if not blocks:
        raise ValueError("xor_blocks 需要至少一个块")
    n = len(blocks[0])
    acc = 0
    for b in blocks:
        acc ^= int.from_bytes(b, "big")
    return acc.to_bytes(n, "big")


def p_parity(blocks):
    """P = XOR(所有数据块)"""
    return xor_blocks(blocks)


def q_parity(blocks):
    """Q = Σ D_i · 2^i（blocks 按行内逻辑槽顺序给出）"""
    if not blocks:
        return b""
    n = len(blocks[0])
    acc = 0
    for i, b in enumerate(blocks):
        acc ^= int.from_bytes(gf_mul_block(gf_pow2(i), b), "big")
    return acc.to_bytes(n, "big")


# ------------------------------------------------------------------
# 条带几何
# ------------------------------------------------------------------
def _canon(layout):
    raw = str(layout).strip().lower().replace(" ", "").replace("_", "-")
    if raw in _LAYOUT_ALIASES:
        return _LAYOUT_ALIASES[raw]
    if raw in _LAYOUT_CANON:
        return raw
    raise RaidError("未知条带布局 %r（left/right/left-asym/right-asym/n-2/parity-0/"
                    "near/far/offset）" % (layout,))


def raid5_parity_index(row, n, layout="left"):
    """RAID5 某行的 P 盘设备号。

    left  : P = (n-1) - (row % n)   —— 与 docs/RAID5.md 里 layout=2 的实测一致
    right : P = row % n
    n-2   : P 固定 n-1（等价 RAID4 语义，md 的 parity_n）
    parity-0 : P 固定 0
    """
    lay = _canon(layout)
    if n < 2:
        raise RaidError("RAID5 至少 2 块盘")
    if lay in ("left", "left-asym"):
        return ((n - 1) - (row % n)) % n        # 取模兜住环形回卷
    if lay in ("right", "right-asym"):
        return row % n
    if lay == "parity_n":
        return n - 1
    if lay == "parity_0":
        return 0
    raise RaidError("RAID5 不支持布局 %r" % (layout,))


def raid5_data_order(row, n, layout="left"):
    """RAID5 某行内数据盘的逻辑顺序（跳过 P 盘的环形映射）。

    同步型（left/right）：从 P 的下一块开始顺时针 —— (P+1)，(P+2)，… 绕回
    非对称型（*-asym）  ：从 0 号盘升序排列，遇到 P 盘跳过
    """
    lay = _canon(layout)
    pd = raid5_parity_index(row, n, layout)
    if lay in ("left", "right"):
        return [(pd + 1 + i) % n for i in range(n - 1)]
    return [d for d in range(n) if d != pd]


def raid6_parity_indices(row, n, layout="left"):
    """RAID6 某行的 (P, Q) 设备号。

    left  : P = (n-2) - (row % n)，Q = P+1（相邻列）
    right : P = row % n，Q = P+1
    n-2   : P = n-2，Q = n-1（固定尾部两盘）
    parity-0 : P = 0，Q = 1（固定头部两盘）
    """
    lay = _canon(layout)
    if n < 3:
        raise RaidError("RAID6 至少 3 块盘")
    if lay in ("left", "left-asym"):
        p = ((n - 2) - (row % n)) % n           # md 式：P 每行左移一格，环形回卷
    elif lay in ("right", "right-asym"):
        p = row % n
    elif lay == "parity_n":
        return n - 2, n - 1
    elif lay == "parity_0":
        return 0, 1
    else:
        raise RaidError("RAID6 不支持布局 %r" % (layout,))
    return p, (p + 1) % n


def raid6_data_order(row, n, layout="left"):
    """RAID6 某行内数据盘的逻辑顺序：从 Q 的下一块开始环形展开"""
    p, q = raid6_parity_indices(row, n, layout)
    return [(q + 1 + i) % n for i in range(n - 2)]


def raid10_placement(row, slot, n, copies, layout):
    """RAID10 某逻辑 chunk 的副本落点 [(设备号, 该设备上的 chunk 序号), ...]

    near  : 副本在相邻盘、同一个 chunk 序号（成对镜像，再按 RAID0 跨对条带）
    offset: 设备相邻，但第 i 份副本整体错位 i 个 chunk（错开一个条带）
    far   : 副本沿设备环外推 k 位（k = n/copies），同时物理 chunk 偏移 k
    """
    lay = _canon(layout)
    if lay == "near":
        return [(slot * copies + i, row) for i in range(copies)]
    if lay == "offset":
        return [(slot * copies + i, row + i) for i in range(copies)]
    if lay == "far":
        k = n // copies
        return [((slot + i * k) % n, row + i * k) for i in range(copies)]
    raise RaidError("RAID10 不支持布局 %r" % (layout,))


def _parse_layout(layout, level):
    """返回 (规范布局名, 副本数提示)；副本数提示只对 RAID10 的 n2/f2/o2 写法有意义"""
    raw = str(layout).strip().lower().replace(" ", "").replace("_", "-")
    if level == 10:
        hint = None
        key = raw
        if raw not in _LAYOUT_ALIASES and len(raw) > 1 and raw[-1].isdigit():
            base = raw[:-1]
            if base in ("near", "n", "far", "f", "offset", "o"):
                key = base
                hint = int(raw[-1])
        name = _LAYOUT_ALIASES.get(key)
        if name not in ("near", "offset", "far"):
            raise RaidError("RAID10 布局只支持 near / offset / far（或 n2 / o2 / f2 写法），"
                            "收到 %r" % (layout,))
        return name, hint
    name = _canon(layout)
    if name in ("near", "offset", "far"):
        raise RaidError("布局 %r 只用于 RAID10" % (layout,))
    if level == 4:
        return "fixed", None
    if level in (5, 6) and name not in LAYOUTS[level]:
        raise RaidError("RAID%d 不支持布局 %r（可选 %s）"
                        % (level, layout, list(LAYOUTS[level])))
    return name, None


# ------------------------------------------------------------------
# 逻辑卷
# ------------------------------------------------------------------
class Raid(object):
    """RAID 逻辑卷（只读重组）。

    成员盘：任意带 `read(offset, size)` 与 `size` 的对象
            （mkit.image.Image / SubImage / 自造假盘都行）
    """

    LEVELS = LEVELS

    def __init__(self, members, level, chunk_bytes=65536, layout="left",
                 missing=None, member_offsets=None, copies=2, chunk=None):
        self.level = int(level)
        if self.level not in LAYOUTS:
            raise RaidError("不支持的 RAID 级别 %r（可选 %s）" % (level, list(LEVELS)))
        if chunk is not None:                 # 兼容旧写法 Raid(..., chunk=4096)
            chunk_bytes = chunk
        self.chunk = int(chunk_bytes)
        if self.chunk <= 0:
            raise RaidError("chunk_bytes 必须是正整数")
        self._zero = bytes(self.chunk)

        # ---- 成员盘 ----
        if isinstance(members, dict):
            top = max(members) if members else -1
            seq = [members.get(i) for i in range(top + 1)]
        else:
            seq = list(members)
        if not seq:
            raise RaidError("members 为空")
        self.members = seq
        self.n = len(seq)

        self.missing = set(int(i) for i in (missing or ()))
        for i, d in enumerate(seq):
            if d is None:
                self.missing.add(i)
        for i in self.missing:
            if i < 0 or i >= self.n:
                raise RaidError("missing 含越界成员号 %d（成员数 %d）" % (i, self.n))
        self._live = set(range(self.n)) - self.missing

        if member_offsets is None:
            self.offsets = [0] * self.n
        elif isinstance(member_offsets, int):
            self.offsets = [member_offsets] * self.n
        else:
            self.offsets = [int(x) for x in member_offsets]
            if len(self.offsets) != self.n:
                raise RaidError("member_offsets 长度 %d 与成员数 %d 不符"
                                % (len(self.offsets), self.n))

        self.stats = dict((k, 0) for k in (
            "direct", "rebuild1", "rebuild2", "mirror_switch",
            "unrecoverable", "short_read", "io_error", "probe_fail"))
        self._warn = []
        self.warn_limit = 64
        self._seen = set()
        self._truncated = 0

        # ---- 布局 / 副本数 ----
        if self.level == 0:
            self.layout = "flat"
            self.copies = 1
        elif self.level == 1:
            self.layout = "mirror"
            self.copies = max(1, self.n)
        else:
            name, hint = _parse_layout(layout, self.level)
            self.layout = name
            if self.level == 10:
                self.copies = int(copies if hint is None else hint)
                if self.copies < 2 or self.copies > self.n:
                    raise RaidError("RAID10 副本数 %d 不合法（2 ≤ copies ≤ 成员数）"
                                    % self.copies)
            else:
                self.copies = 1

        # ---- 每行数据盘数 ----
        if self.level == 0:
            k = self.n
        elif self.level == 1:
            k = 1
        elif self.level in (4, 5):
            k = self.n - 1
        elif self.level == 6:
            k = self.n - 2
        else:
            if self.n % self.copies:
                raise RaidError("RAID10 成员数 %d 不能被副本数 %d 整除"
                                % (self.n, self.copies))
            k = self.n // self.copies
        if k < 1:
            raise RaidError("RAID%d 至少需要 %d 块成员盘"
                            % (self.level, {4: 2, 5: 2, 6: 3}.get(self.level, 1)))
        self.data_disks = k

        # ---- 容量 ----
        caps = []
        for i in sorted(self._live):
            d = self.members[i]
            try:
                sz = int(getattr(d, "size", 0) or 0)
            except Exception:
                sz = 0
            caps.append(sz - self.offsets[i])
        self.per_disk = max(0, min(caps)) if caps else 0
        self.chunks_per_disk = self.per_disk // self.chunk

        cpd = self.chunks_per_disk
        if self.level == 1:
            rows = cpd
            self.size = self.per_disk                     # 镜像：与单盘等长
        elif self.level == 10:
            if self.layout == "near":
                shift = 0
            elif self.layout == "offset":
                shift = self.copies - 1
            else:
                shift = (self.copies - 1) * k
            rows = max(0, cpd - shift)
            self.size = rows * k * self.chunk
        else:
            rows = cpd
            self.size = rows * k * self.chunk
        self.rows = rows

        # ---- 缺盘容错校验 ----
        tol = {0: 0, 1: self.n - 1, 4: 1, 5: 1, 6: 2, 10: self.copies - 1}[self.level]
        bad = self._n_unreadable()
        if bad > tol:
            raise RaidError("RAID%d 最多容忍 %d 块盘不可读，实际 %d 块，无法重组"
                            % (self.level, tol, bad))
        self.tolerance = tol

        self.readable = []
        self._probe()
        self._chunk_reader = {
            0: self._chunk_raid0,
            1: self._chunk_mirror,
            4: self._chunk_raid4,
            5: self._chunk_raid5,
            6: self._chunk_raid6,
            10: self._chunk_raid10,
        }[self.level]

    # ---------------- 留痕 ----------------
    def _note(self, kind, msg, key=None):
        """计数 always +1；message 按 key 去重（避免坏盘刷屏），超限截断"""
        self.stats[kind] = self.stats.get(kind, 0) + 1
        if key is not None:
            if key in self._seen:
                return
            self._seen.add(key)
        if len(self._warn) >= self.warn_limit:
            self._truncated += 1
            return
        self._warn.append(msg)

    def warnings(self):
        """换副本 / 重建 / 不可恢复的留痕（同成员同类故障只留第一条，次数看 info()['stats']）"""
        out = list(self._warn)
        if self._truncated:
            out.append("另有 %d 条告警未列出（warn_limit=%d）" % (self._truncated, self.warn_limit))
        return out

    def degraded(self):
        """有成员缺失/探活失败，或出现过无法恢复的 chunk"""
        return bool(self.missing) or (not all(self.readable)) or self.stats["unrecoverable"] > 0

    def _n_unreadable(self):
        """构造期粗判：声明缺失的 + 探活失败的"""
        cnt = len(self.missing)
        for i in range(self.n):
            if i in self._live:
                try:
                    d = self.members[i]
                    if int(getattr(d, "size", 0) or 0) <= self.offsets[i]:
                        cnt += 1
                except Exception:
                    cnt += 1
        return cnt

    def _probe(self):
        for i in range(self.n):
            if i not in self._live:
                self.readable.append(False)
                continue
            d = self.members[i]
            try:
                sz = int(getattr(d, "size", 0) or 0)
                if sz <= self.offsets[i]:
                    self.readable.append(False)
                    continue
                d.read(self.offsets[i], 1)
                self.readable.append(True)
            except Exception as e:
                self.readable.append(False)
                self._note("probe_fail", "成员 %d 探活失败：%s" % (i, e), key=(i, "probe"))

    # ---------------- 物理块 ----------------
    def _phys(self, dev, chunk_no):
        """读成员 dev 的第 chunk_no 个物理 chunk。

        返回 (状态, 数据块)：'ok' 完整块 / 'short' 短读后补 0 / None 不可用。
        零字节返回按读失败处理 —— 否则镜像会把「坏道读空」当成合法零数据。
        """
        if dev not in self._live:
            return None, None
        disk = self.members[dev]
        try:
            dsize = int(getattr(disk, "size", 0) or 0)
        except Exception:
            dsize = 0
        base = self.offsets[dev] + chunk_no * self.chunk
        if chunk_no < 0 or base >= dsize:
            return "ok", self._zero
        try:
            blk = disk.read(base, self.chunk)
        except Exception as e:
            self._note("io_error", "成员 %d 在 chunk %d（字节 0x%X）读失败：%s"
                       % (dev, chunk_no, base, e), key=(dev, "io"))
            return None, None
        if not blk:
            self._note("io_error", "成员 %d 在 chunk %d（字节 0x%X）返回 0 字节，按读失败处理"
                       % (dev, chunk_no, base), key=(dev, "empty"))
            return None, None
        blk = bytes(blk)
        if len(blk) < self.chunk:
            self._note("short_read", "成员 %d 在 chunk %d 短读 %d/%d 字节，缺的部分按 0 补齐"
                       % (dev, chunk_no, len(blk), self.chunk), key=(dev, "short"))
            return "short", blk + self._zero[:self.chunk - len(blk)]
        return "ok", blk

    # ---------------- 对外读 ----------------
    def read(self, off, size):
        """逻辑卷任意偏移读；跨 chunk 自动拼接，越界自动截断"""
        off = int(off)
        size = int(size)
        if size <= 0 or off < 0 or off >= self.size:
            return b""
        size = min(size, self.size - off)
        out = bytearray()
        pos = off
        end = off + size
        while pos < end:
            lc, inside = divmod(pos, self.chunk)
            take = min(self.chunk - inside, end - pos)
            blk = self._chunk_reader(lc)
            out += blk[inside:inside + take]
            pos += take
        return bytes(out)

    # ---------------- 各级别 ----------------
    def _chunk_raid0(self, lc):
        row, slot = divmod(lc, self.n)
        st, blk = self._phys(slot, row)
        if st is not None:
            self.stats["direct"] += 1
            return blk
        self._note("unrecoverable", "RAID0 成员 %d 在 chunk %d 不可读，该段置 0（无冗余，无法恢复）"
                   % (slot, row), key=("r0-u",))
        return self._zero

    def _chunk_mirror(self, lc):
        spare = None
        spare_dev = None
        failed = []
        for pos, dev in enumerate(sorted(self._live)):
            st, blk = self._phys(dev, lc)
            if st == "ok":
                if pos:
                    self._note("mirror_switch", "RAID1 chunk %d：成员 %s 不可读，改读成员 %d"
                               % (lc, "/".join(str(x) for x in failed) or "0", dev),
                               key=(dev, "mir"))
                else:
                    self.stats["direct"] += 1
                return blk
            if st == "short" and spare is None:
                spare = blk
                spare_dev = dev
            if st is None:
                failed.append(dev)
        if spare is not None:
            self._note("short_read", "RAID1 chunk %d：所有副本都短读，退回成员 %d 的补零块"
                       % (lc, spare_dev), key=(spare_dev, "mir-short"))
            return spare
        self._note("unrecoverable", "RAID1 chunk %d：所有副本都不可读，该段置 0" % lc, key=("r1-u",))
        return self._zero

    def _chunk_raid4(self, lc):
        k = self.data_disks
        row, slot = divmod(lc, k)
        dev = slot                              # RAID4：数据盘固定 0..n-2
        st, blk = self._phys(dev, row)
        if st is not None:
            self.stats["direct"] += 1
            return blk
        blocks = []
        for d in range(self.n):
            if d == dev:
                continue
            st2, b2 = self._phys(d, row)
            if st2 is None:
                self._note("unrecoverable", "RAID4 行 %d 同时缺成员 %d 与 %d，超出单盘容错"
                           % (row, dev, d), key=("r4-u",))
                return self._zero
            blocks.append(b2)
        self._note("rebuild1", "RAID4 行 %d 逻辑槽 %d：成员 %d 不可读，用固定 P 盘 %d 与其余 %d 块 XOR 重建"
                   % (row, slot, dev, self.n - 1, len(blocks)), key=("r4-r1",))
        return xor_blocks(blocks)

    def _chunk_raid5(self, lc):
        k = self.data_disks
        row, slot = divmod(lc, k)
        order = raid5_data_order(row, self.n, self.layout)
        dev = order[slot]
        st, blk = self._phys(dev, row)
        if st is not None:
            self.stats["direct"] += 1
            return blk
        blocks = []
        for d in range(self.n):
            if d == dev:
                continue
            st2, b2 = self._phys(d, row)
            if st2 is None:
                self._note("unrecoverable", "RAID5(%s) 行 %d 同时缺成员 %d 与 %d，超出单盘容错"
                           % (self.layout, row, dev, d), key=("r5-u",))
                return self._zero
            blocks.append(b2)
        self._note("rebuild1", "RAID5(%s) 行 %d 逻辑槽 %d：成员 %d 不可读，XOR P 盘 %d 与其余 %d 块重建"
                   % (self.layout, row, slot, dev,
                      raid5_parity_index(row, self.n, self.layout), len(blocks)),
                   key=("r5-r1",))
        return xor_blocks(blocks)

    def _q_of(self, order, by_dev):
        acc = 0
        for i, dev in enumerate(order):
            blk = by_dev.get(dev)
            if blk is None:
                raise ValueError("Q 计算缺数据块")
            acc ^= int.from_bytes(gf_mul_block(gf_pow2(i), blk), "big")
        return acc.to_bytes(self.chunk, "big")

    def _raid6_solve(self, row, missing):
        """给定行号与缺失设备集合，返回 {设备号: 数据块}；救不了返回 None"""
        order = raid6_data_order(row, self.n, self.layout)
        p_idx, q_idx = raid6_parity_indices(row, self.n, self.layout)
        slot_of = dict((dev, i) for i, dev in enumerate(order))
        need = set(missing)
        by_dev = {}
        for dev in range(self.n):
            if dev in need:
                continue
            st, blk = self._phys(dev, row)
            if st is None:
                need.add(dev)          # 声明之外又坏一块
            else:
                by_dev[dev] = blk
        if not need:
            return {}
        if len(need) > 2:
            return None

        # ---- 缺 1 块 ----
        if len(need) == 1:
            d = next(iter(need))
            if d == p_idx:
                if not all(x in by_dev for x in order):
                    return None
                self._note("rebuild1", "RAID6(%s) 行 %d：P 盘（成员 %d）缺失，由 %d 块数据 XOR 重算"
                           % (self.layout, row, d, len(order)), key=("r6-p",))
                return {d: xor_blocks([by_dev[x] for x in order])}
            if d == q_idx:
                if not all(x in by_dev for x in order):
                    return None
                self._note("rebuild1", "RAID6(%s) 行 %d：Q 盘（成员 %d）缺失，由 Σ D_i·2^i 重算"
                           % (self.layout, row, d), key=("r6-q",))
                return {d: self._q_of(order, by_dev)}
            if p_idx not in by_dev or not all(x in by_dev for x in order if x != d):
                return None
            self._note("rebuild1", "RAID6(%s) 行 %d：数据块（成员 %d，逻辑槽 %d）缺失，"
                       "用 P 盘与其余 %d 块 XOR 重建"
                       % (self.layout, row, d, slot_of[d], len(order) - 1), key=("r6-d",))
            return {d: xor_blocks([by_dev[p_idx]] + [by_dev[x] for x in order if x != d])}

        a, b = sorted(need)

        # ---- 缺 2 块：P、Q 双失 → 直接由数据重算 ----
        if set((a, b)) == set((p_idx, q_idx)):
            if not all(x in by_dev for x in order):
                return None
            self._note("rebuild2", "RAID6(%s) 行 %d：P、Q 同时缺失，由 %d 块数据一次重算 P 与 Q"
                       % (self.layout, row, len(order)), key=("r6-pq",))
            return {p_idx: xor_blocks([by_dev[x] for x in order]),
                    q_idx: self._q_of(order, by_dev)}

        # ---- 缺 2 块：P + 数据 → Q 反解数据，再 XOR 出 P ----
        if p_idx in need:
            d = a if a != p_idx else b
            if q_idx not in by_dev or not all(x in by_dev for x in order if x != d):
                return None
            s = slot_of[d]
            acc = int.from_bytes(by_dev[q_idx], "big")
            for i, dev in enumerate(order):
                if dev == d:
                    continue
                acc ^= int.from_bytes(gf_mul_block(gf_pow2(i), by_dev[dev]), "big")
            da = gf_mul_block(gf_inv(gf_pow2(s)), acc.to_bytes(self.chunk, "big"))
            by_dev[d] = da
            self._note("rebuild2", "RAID6(%s) 行 %d：P 与数据块（成员 %d，逻辑槽 %d）双失，"
                       "先用 Q 除以 2^%d 反解数据，再 XOR 得 P"
                       % (self.layout, row, d, s, s), key=("r6-pd",))
            return {d: da, p_idx: xor_blocks([by_dev[x] for x in order])}

        # ---- 缺 2 块：Q + 数据 → P 反解数据，再算 Q ----
        if q_idx in need:
            d = a if a != q_idx else b
            if p_idx not in by_dev or not all(x in by_dev for x in order if x != d):
                return None
            da = xor_blocks([by_dev[p_idx]] + [by_dev[x] for x in order if x != d])
            by_dev[d] = da
            self._note("rebuild2", "RAID6(%s) 行 %d：Q 与数据块（成员 %d）双失，"
                       "先用 P 反解数据，再重算 Q" % (self.layout, row, d), key=("r6-qd",))
            return {d: da, q_idx: self._q_of(order, by_dev)}

        # ---- 缺 2 块：两块数据 → P、Q 联立（Vandermonde 解法）----
        if p_idx not in by_dev or q_idx not in by_dev:
            return None
        if not all(x in by_dev for x in order if x not in (a, b)):
            return None
        x1 = xor_blocks([by_dev[p_idx]] + [by_dev[x] for x in order if x not in (a, b)])
        acc = int.from_bytes(by_dev[q_idx], "big")
        for i, dev in enumerate(order):
            if dev in (a, b):
                continue
            acc ^= int.from_bytes(gf_mul_block(gf_pow2(i), by_dev[dev]), "big")
        x2 = acc.to_bytes(self.chunk, "big")
        ca = gf_pow2(slot_of[a])
        cb = gf_pow2(slot_of[b])
        den = ca ^ cb
        if den == 0:
            return None
        da = gf_mul_block(gf_inv(den), xor_blocks([x2, gf_mul_block(cb, x1)]))
        db = xor_blocks([x1, da])
        self._note("rebuild2", "RAID6(%s) 行 %d：数据块 a=%d(slot %d) 与 b=%d(slot %d) 双失，"
                   "P+Q 在 GF(2^8)/0x%X 联立求解 "
                   "D_a=(X2⊕X1·2^b)/(2^a⊕2^b)，再回代 P 得 D_b"
                   % (self.layout, row, a, slot_of[a], b, slot_of[b], GF_POLY),
                   key=("r6-dd",))
        return {a: da, b: db}

    def _chunk_raid6(self, lc):
        k = self.data_disks
        row, slot = divmod(lc, k)
        dev = raid6_data_order(row, self.n, self.layout)[slot]
        st, blk = self._phys(dev, row)
        if st is not None:
            self.stats["direct"] += 1
            return blk
        rec = self._raid6_solve(row, set((dev,)))
        if rec and dev in rec:
            return rec[dev]
        self._note("unrecoverable", "RAID6 行 %d：缺块超出纠错能力（≥3 块或读失败），"
                   "逻辑 chunk %d 置 0" % (row, lc), key=("r6-u",))
        return self._zero

    def _chunk_raid10(self, lc):
        k = self.data_disks
        row, slot = divmod(lc, k)
        spare = None
        failed = []
        for pos, (dev, pc) in enumerate(raid10_placement(row, slot, self.n,
                                                         self.copies, self.layout)):
            st, blk = self._phys(dev, pc)
            if st == "ok":
                if pos:
                    self._note("mirror_switch", "RAID10(%s) 逻辑 chunk %d：副本 %d（成员 %s）不可读，"
                               "改读成员 %d" % (self.layout, lc, pos,
                                                "/".join(str(x) for x in failed) or "0", dev),
                               key=(dev, "r10-mir"))
                else:
                    self.stats["direct"] += 1
                return blk
            if st == "short" and spare is None:
                spare = blk
            if st is None:
                failed.append(dev)
        if spare is not None:
            self._note("short_read", "RAID10(%s) 逻辑 chunk %d：所有副本都短读，退回补零块"
                       % (self.layout, lc), key=("r10-short",))
            return spare
        self._note("unrecoverable", "RAID10(%s) 逻辑 chunk %d：所有副本都不可读，置 0"
                   % (self.layout, lc), key=("r10-u",))
        return self._zero

    # ---------------- 元信息 ----------------
    def info(self):
        return {
            "level": self.level,
            "name": LEVEL_NAMES.get(self.level, "RAID?"),
            "layout": self.layout,
            "copies": self.copies if self.level == 10 else None,
            "chunk": self.chunk,
            "chunk_bytes": self.chunk,
            "members": self.n,
            "data_per_row": self.data_disks,
            "rows": self.rows,
            "chunks_per_disk": self.chunks_per_disk,
            "per_disk_bytes": self.per_disk,
            "member_offsets": list(self.offsets),
            "member_sizes": [self._msize(i) for i in range(self.n)],
            "missing": sorted(self.missing),
            "readable": list(self.readable),
            "unreadable": [i for i, r in enumerate(self.readable) if not r],
            "tolerance": self.tolerance,
            "degraded": self.degraded(),
            "size": self.size,
            "warnings": len(self.warnings()),
            "stats": dict(self.stats),
        }

    def _msize(self, i):
        d = self.members[i]
        if d is None:
            return None
        try:
            return int(getattr(d, "size", 0) or 0)
        except Exception:
            return None

    def __repr__(self):
        return "<Raid %s(%s) n=%d chunk=%d size=%d%s>" % (
            LEVEL_NAMES.get(self.level, "?"), self.layout, self.n, self.chunk,
            self.size, " DEGRADED" if self.degraded() else "")


# ------------------------------------------------------------------
# 便捷构造
# ------------------------------------------------------------------
def raid0(members, chunk_bytes=65536, missing=None, member_offsets=None):
    """RAID0：disk = stripe_number % n，offset = (stripe_number // n) * chunk"""
    return Raid(members, 0, chunk_bytes, "left", missing, member_offsets)


def raid1(members, chunk_bytes=65536, missing=None, member_offsets=None):
    """RAID1：任一可读副本即数据"""
    return Raid(members, 1, chunk_bytes, "left", missing, member_offsets)


def raid4(members, chunk_bytes=65536, missing=None, member_offsets=None):
    """RAID4：P 恒为最后一盘"""
    return Raid(members, 4, chunk_bytes, "left", missing, member_offsets)


def raid5(members, chunk_bytes=65536, layout="left", missing=None, member_offsets=None):
    """RAID5：layout = left / right / left-asym / right-asym / n-2"""
    return Raid(members, 5, chunk_bytes, layout, missing, member_offsets)


def raid6(members, chunk_bytes=65536, layout="left", missing=None, member_offsets=None):
    """RAID6：P、Q 相邻列按行轮转；缺 2 盘走 GF(2^8) 联立求解"""
    return Raid(members, 6, chunk_bytes, layout, missing, member_offsets)


def raid10(members, chunk_bytes=65536, layout="near", copies=2,
           missing=None, member_offsets=None):
    """RAID10：layout = near / offset / far"""
    return Raid(members, 10, chunk_bytes, layout, missing, member_offsets, copies)


# ------------------------------------------------------------------
# 自检：内存假盘 + 合成磁盘组，逐字节校验
# ------------------------------------------------------------------
class MemDisk(object):
    """内存型假盘：只暴露 read(offset, size) 与 size"""

    def __init__(self, data=b""):
        self.data = bytes(data)
        self.size = len(self.data)

    def read(self, off, n):
        if n <= 0 or off < 0 or off >= self.size:
            return b""
        return self.data[off:off + n]

    def __repr__(self):
        return "<MemDisk %d B>" % self.size


class BadSectorDisk(MemDisk):
    """从 fail_from 起整段抛 IOError —— 模拟坏道 / 设备掉线"""

    def __init__(self, data, fail_from):
        MemDisk.__init__(self, data)
        self.fail_from = fail_from

    def read(self, off, n):
        if off + n > self.fail_from:
            raise IOError("模拟坏道 @0x%X" % off)
        return MemDisk.read(self, off, n)


class DeadSectorDisk(MemDisk):
    """从 dead_from 起返回 0 字节 —— 模拟「读得到但全是空」的假活盘"""

    def __init__(self, data, dead_from):
        MemDisk.__init__(self, data)
        self.dead_from = dead_from

    def read(self, off, n):
        if off + n > self.dead_from:
            return b""
        return MemDisk.read(self, off, n)


def _ceil_div(a, b):
    return (a + b - 1) // b


def _pad_to(data, need):
    data = bytes(data)
    if len(data) >= need:
        return data[:need]
    return data + bytes(((i * 31 + 7) & 0xFF) for i in range(need - len(data)))


def _first_diff(a, b):
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i
    return min(len(a), len(b))


def _build_raid0(data, chunk, n):
    rows = _ceil_div(len(data), chunk * n)
    data = _pad_to(data, rows * n * chunk)
    disks = [bytearray(rows * chunk) for _ in range(n)]
    for row in range(rows):
        for slot in range(n):
            off = (row * n + slot) * chunk
            disks[slot][row * chunk:(row + 1) * chunk] = data[off:off + chunk]
    return [bytes(d) for d in disks], data


def _build_parity(data, chunk, n, level, layout="left"):
    k = (n - 1) if level in (4, 5) else (n - 2)
    rows = _ceil_div(len(data), chunk * k)
    data = _pad_to(data, rows * k * chunk)
    disks = [bytearray(rows * chunk) for _ in range(n)]
    for row in range(rows):
        if level == 4:
            order = list(range(n - 1))
            p_idx, q_idx = n - 1, None
        elif level == 5:
            order = raid5_data_order(row, n, layout)
            p_idx, q_idx = raid5_parity_index(row, n, layout), None
        else:
            order = raid6_data_order(row, n, layout)
            p_idx, q_idx = raid6_parity_indices(row, n, layout)
        blocks = []
        for slot, dev in enumerate(order):
            off = (row * k + slot) * chunk
            b = data[off:off + chunk]
            disks[dev][row * chunk:(row + 1) * chunk] = b
            blocks.append(b)
        disks[p_idx][row * chunk:(row + 1) * chunk] = xor_blocks(blocks)
        if q_idx is not None:
            disks[q_idx][row * chunk:(row + 1) * chunk] = q_parity(blocks)
    return [bytes(d) for d in disks], data


def _build_raid10(data, chunk, n, copies, layout):
    k = n // copies
    rows = _ceil_div(len(data), chunk * k)
    if layout == "near":
        extra = 0
    elif layout == "offset":
        extra = copies - 1
    else:
        extra = (copies - 1) * k
    data = _pad_to(data, rows * k * chunk)
    disks = [bytearray((rows + extra) * chunk) for _ in range(n)]
    for row in range(rows):
        for slot in range(k):
            off = (row * k + slot) * chunk
            b = data[off:off + chunk]
            for dev, pc in raid10_placement(row, slot, n, copies, layout):
                disks[dev][pc * chunk:(pc + 1) * chunk] = b
    return [bytes(d) for d in disks], data


def _cmp(tag, raid, raw, full):
    """全卷 + 前缀 + 未对齐跨 chunk 读，逐字节比对"""
    got = raid.read(0, len(full))
    assert len(got) == len(full), "%s：长度不符 %d/%d" % (tag, len(got), len(full))
    assert got == full, "%s：内容不符，首个差异在 %d" % (tag, _first_diff(got, full))
    assert raid.read(0, len(raw)) == raw, "%s：前 %d 字节不符" % (tag, len(raw))
    probes = ((1, 999), (raid.chunk - 3, 7), (raid.chunk + 100, 3 * raid.chunk + 17),
              (len(full) - 5, 5), (len(full) // 2 + 3, raid.chunk * 2 + 1))
    for off, ln in probes:
        if off < 0 or off >= len(full):
            continue
        ln = min(ln, len(full) - off)
        seg = raid.read(off, ln)
        assert seg == full[off:off + ln], "%s：偏移 %d 长 %d 不符" % (tag, off, ln)
    assert raid.read(raid.size, 16) == b"", "%s：尾部越界未截断" % tag
    assert raid.read(-1, 16) == b"", "%s：负偏移未拒绝" % tag
    assert raid.read(0, 0) == b"", "%s：size=0 未拒绝" % tag


def _selftest():
    import random

    step = [0]

    def head(title):
        step[0] += 1
        print("[%02d] %s" % (step[0], title))

    CH = 4096
    RAW = bytes(i & 0xFF for i in range(102400))       # 100 KiB = 25 个 4 KiB chunk

    # ---------------- 01 GF(2^8) ----------------
    head("GF(2^8)：0x11D / 生成元 2 / 乘·逆元·除")
    assert GF_POLY == 0x11D
    assert gf_mul(2, 0x80) == 0x1D, hex(gf_mul(2, 0x80))     # 0x100 归约到 0x1D
    assert gf_mul(0, 0x7F) == 0 and gf_mul(0x7F, 0) == 0
    assert gf_mul(1, 0xA5) == 0xA5
    assert gf_inv(1) == 1
    assert gf_pow(2, 8) == 0x1D
    for x in range(1, 256):
        assert _GF_EXP[_GF_LOG[x]] == x, "exp/log 表不自洽 @%d" % x
        assert gf_mul(x, gf_inv(x)) == 1, "逆元错 @%d" % x
    rnd = random.Random(0xE5C)
    for _ in range(100):
        a = rnd.randrange(1, 256)
        b = rnd.randrange(1, 256)
        assert gf_div(gf_mul(a, b), b) == a, "除法错 a=%d b=%d" % (a, b)
    assert gf_div(0, 7) == 0
    blk = bytes(rnd.randrange(256) for _ in range(64))
    q = q_parity([blk, blk])
    for i in range(64):
        assert q[i] == gf_mul(blk[i], 3), "Q 系数错 @%d" % i   # 2^0 ⊕ 2^1 = 3
    print("     gf_mul(2,0x80)=0x%02X  逆元 255 个全过  随机 100 组乘除互逆"
          % gf_mul(2, 0x80))

    # ---------------- 02 RAID0 ----------------
    head("RAID0：4 盘 × chunk 4096，100 KiB 按条带切分")
    d0, pad0 = _build_raid0(RAW, CH, 4)
    r = raid0([MemDisk(x) for x in d0], CH)
    _cmp("RAID0", r, RAW, pad0)
    assert r.size == len(pad0) == 4 * 7 * CH
    assert not r.degraded() and not r.warnings()
    print("     size=%d（4×7×4096）, stats=%s" % (r.size, r.stats))

    # ---------------- 03 RAID1 ----------------
    head("RAID1：3 副本，正常读 + 坏道/假活盘自动换副本并留痕")
    r = raid1([MemDisk(RAW) for _ in range(3)], CH)
    _cmp("RAID1 正常", r, RAW, RAW)
    assert not r.warnings() and not r.degraded()
    bad = BadSectorDisk(RAW, 3 * CH)        # 第 3 个 chunk 起抛异常
    dead = DeadSectorDisk(RAW, 5 * CH)      # 第 5 个 chunk 起返回 0 字节
    r = raid1([bad, dead, MemDisk(RAW)], CH)
    _cmp("RAID1 换盘", r, RAW, RAW)
    w = r.warnings()
    assert len(w) >= 2, w
    assert r.stats["mirror_switch"] >= 2, r.stats
    print("     换副本留痕 %d 条：" % len(w))
    for line in w[:3]:
        print("       · %s" % line)

    # ---------------- 04 RAID4 ----------------
    head("RAID4：4 盘（3 数据 + 1 固定 P）")
    d4, pad4 = _build_parity(RAW, CH, 4, 4)
    r = raid4([MemDisk(x) for x in d4], CH)
    _cmp("RAID4", r, RAW, pad4)
    r = raid4([None if i == 1 else MemDisk(x) for i, x in enumerate(d4)], CH, missing=[1])
    _cmp("RAID4 缺 1 盘", r, RAW, pad4)
    assert r.stats["rebuild1"] > 0 and r.degraded()
    print("     size=%d  缺数据盘 1：rebuild1=%d" % (r.size, r.stats["rebuild1"]))

    # ---------------- 05 RAID5 left ----------------
    head("RAID5 left-sync：4 盘，P=(n-1)-row%n；正常 + 缺 1 盘重建")
    d5l, pad5l = _build_parity(RAW, CH, 4, 5, "left")
    r = raid5([MemDisk(x) for x in d5l], CH, layout="left")
    _cmp("RAID5-left", r, RAW, pad5l)
    assert raid5_parity_index(0, 4, "left") == 3
    assert raid5_parity_index(1, 4, "left") == 2
    r = raid5([None if i == 1 else MemDisk(x) for i, x in enumerate(d5l)], CH,
              layout="left", missing=[1])
    _cmp("RAID5-left 缺盘", r, RAW, pad5l)
    assert r.stats["rebuild1"] > 0
    print("     size=%d  缺成员 1：rebuild1=%d" % (r.size, r.stats["rebuild1"]))

    # ---------------- 06 RAID5 right ----------------
    head("RAID5 right-sync：4 盘，P=row%n；正常 + 缺 1 盘重建")
    d5r, pad5r = _build_parity(RAW, CH, 4, 5, "right")
    r = raid5([MemDisk(x) for x in d5r], CH, layout="right")
    _cmp("RAID5-right", r, RAW, pad5r)
    assert raid5_parity_index(0, 4, "right") == 0
    assert raid5_parity_index(1, 4, "right") == 1
    r = raid5([None if i == 0 else MemDisk(x) for i, x in enumerate(d5r)], CH,
              layout="right", missing=[0])
    _cmp("RAID5-right 缺盘", r, RAW, pad5r)
    assert r.stats["rebuild1"] > 0
    print("     缺成员 0：rebuild1=%d" % r.stats["rebuild1"])

    # ---------------- 07 RAID6 ----------------
    head("RAID6：5 盘（3 数据 + P + Q），正常 / 缺 1 / 缺 2 联立")
    d6, pad6 = _build_parity(RAW, CH, 5, 6, "left")
    r = raid6([MemDisk(x) for x in d6], CH, layout="left")
    _cmp("RAID6 正常", r, RAW, pad6)
    print("     size=%d  正常读 stats=%s" % (r.size, r.stats))

    r = raid6([None if i == 2 else MemDisk(x) for i, x in enumerate(d6)], CH,
              layout="left", missing=[2])
    _cmp("RAID6 缺 1 盘", r, RAW, pad6)
    assert r.stats["rebuild1"] > 0
    print("     缺成员 2（单块）：rebuild1=%d" % r.stats["rebuild1"])

    r = raid6([None if i in (0, 1) else MemDisk(x) for i, x in enumerate(d6)], CH,
              layout="left", missing=[0, 1])
    _cmp("RAID6 缺 2 盘（数据+数据）", r, RAW, pad6)
    assert r.stats["rebuild2"] > 0, r.stats
    print("     缺成员 0,1（每行两块数据 → P+Q 联立）：rebuild2=%d" % r.stats["rebuild2"])

    r = raid6([None if i in (1, 4) else MemDisk(x) for i, x in enumerate(d6)], CH,
              layout="left", missing=[1, 4])
    _cmp("RAID6 缺 2 盘（数据+P/Q 混排）", r, RAW, pad6)
    print("     缺成员 1,4（逐行混合 P/Q 组合）：rebuild2=%d"
          % r.stats["rebuild2"])

    # 全组合：C(5,2)=10 种双盘缺失，逐字节
    combos = [(i, j) for i in range(5) for j in range(i + 1, 5)]
    for i, j in combos:
        rr = raid6([None if k in (i, j) else MemDisk(x) for k, x in enumerate(d6)],
                   CH, layout="left", missing=[i, j])
        _cmp("RAID6 缺 %d,%d" % (i, j), rr, RAW, pad6)
        assert rr.stats["rebuild2"] > 0
    print("     5 盘全部 %d 种双盘缺失组合逐字节通过" % len(combos))

    d6n, pad6n = _build_parity(RAW, CH, 5, 6, "n-2")
    r = raid6([MemDisk(x) for x in d6n], CH, layout="n-2")
    _cmp("RAID6 n-2 布局", r, RAW, pad6n)
    r = raid6([None if i in (0, 1) else MemDisk(x) for i, x in enumerate(d6n)], CH,
              layout="n-2", missing=[0, 1])
    _cmp("RAID6 n-2 缺 2 盘", r, RAW, pad6n)
    d6r, pad6r = _build_parity(RAW, CH, 5, 6, "right")
    r = raid6([MemDisk(x) for x in d6r], CH, layout="right")
    _cmp("RAID6 right 布局", r, RAW, pad6r)
    print("     固定 P=n-2/Q=n-1 与 right 布局也逐字节通过")

    # ---------------- 08 RAID10 near ----------------
    head("RAID10 near：4 盘 2 组镜像（k=2），正常 + 缺 1 盘")
    d10, pad10 = _build_raid10(RAW, CH, 4, 2, "near")
    r = raid10([MemDisk(x) for x in d10], CH, layout="near", copies=2)
    _cmp("RAID10-near", r, RAW, pad10)
    r = raid10([None if i == 2 else MemDisk(x) for i, x in enumerate(d10)], CH,
               layout="near", copies=2, missing=[2])
    _cmp("RAID10-near 缺盘", r, RAW, pad10)
    assert r.stats["mirror_switch"] > 0 and r.degraded()
    print("     size=%d  缺成员 2：mirror_switch=%d" % (r.size, r.stats["mirror_switch"]))

    # ---------------- 09 RAID10 offset ----------------
    head("RAID10 offset：副本错位 1 个 chunk，4 盘")
    do, pado = _build_raid10(RAW, CH, 4, 2, "offset")
    r = raid10([MemDisk(x) for x in do], CH, layout="offset", copies=2)
    _cmp("RAID10-offset", r, RAW, pado)
    r = raid10([None if i == 3 else MemDisk(x) for i, x in enumerate(do)], CH,
               layout="offset", copies=2, missing=[3])
    _cmp("RAID10-offset 缺盘", r, RAW, pado)
    print("     size=%d（每盘 %d chunk，错位吃掉 %d 个）"
          % (r.size, r.chunks_per_disk, r.copies - 1))

    # ---------------- 10 RAID10 far ----------------
    head("RAID10 far：副本沿设备环外推 k、chunk 偏移 k（尽力实现）")
    df, padf = _build_raid10(RAW, CH, 4, 2, "far")
    r = raid10([MemDisk(x) for x in df], CH, layout="far", copies=2)
    _cmp("RAID10-far", r, RAW, padf)
    r = raid10([None if i == 0 else MemDisk(x) for i, x in enumerate(df)], CH,
               layout="far", copies=2, missing=[0])
    _cmp("RAID10-far 缺盘", r, RAW, padf)
    print("     size=%d  缺成员 0：mirror_switch=%d" % (r.size, r.stats["mirror_switch"]))

    # ---------------- 11 member_offsets + 超容错 ----------------
    head("member_offsets（每盘 512 B 头）+ 超容错的降级留痕")
    pre = b"MD\x00" + bytes(509)
    with_head = [pre + x for x in d6]
    r = raid6([MemDisk(x) for x in with_head], CH, layout="left", member_offsets=512)
    _cmp("RAID6 data_offset=512", r, RAW, pad6)
    assert r.per_disk == len(d6[0]) == r.size // 3
    print("     member_offsets=512：size=%d（与无头一致）" % r.size)

    # 缺 2 盘：构造期就该拦下（RAID5 只容 1 块）
    try:
        raid5([None if i in (1, 2) else MemDisk(x) for i, x in enumerate(d5l)], CH,
              layout="left", missing=[1, 2])
        raise AssertionError("缺 2 盘竟然没报错")
    except RaidError as e:
        print("     构造期拦下 RAID5 双盘缺失：%s" % e)

    # 运行期才坏的情况：先按健康阵列打开，读的过程中两块盘同时掉
    r = raid5([MemDisk(x) for x in d5l], CH, layout="left")
    r._live.discard(1)
    r._live.discard(2)
    assert r.read(0, CH) == pad5l[:CH]                  # 逻辑 chunk 0 落在仍活着的 0 号盘
    assert r.read(CH, CH) == bytes(CH)                  # 逻辑 chunk 1 需 1、2 号盘，救不回来
    assert r.stats["unrecoverable"] > 0 and r.degraded() and r.warnings()
    print("     运行期双盘掉线：unrecoverable=%d，degraded=%s，置 0 且留痕"
          % (r.stats["unrecoverable"], r.degraded()))

    # ---------------- DDF 名字接缝 ----------------
    # raidmeta 按 mdadm 的 layout_ddf2md 产出这些名字；它们必须能直接喂进本模块，
    # 否则「DDF 元数据解析」与「条带几何」两半接不上（以前 stripe / fixed-parity /
    # rotating-* 五种会抛 RaidError）。
    ddf_names = [
        ("stripe", 0), ("mirror", 1), ("fixed-parity", 4),
        ("left-asymmetric", 5), ("right-asymmetric", 5), ("left-symmetric", 5),
        ("rotating-n-restart", 6), ("rotating-zero-restart", 6),
        ("rotating-n-continue", 6), ("near", 10), ("offset", 10),
    ]
    for lay, lvl in ddf_names:
        name = _canon(lay)
        assert name in LAYOUTS[lvl], \
            "DDF 布局 %r 归一到 %r 后不属于级别 %d 的可选布局 %r" \
            % (lay, name, lvl, list(LAYOUTS[lvl]))
    step[0] += 1
    print("      raidmeta 的 %d 个 DDF 布局名全部能归一到合法条带布局"
          % len(ddf_names))

    # ---------------- 汇总 ----------------
    print("-" * 60)
    print("自检通过：%d 组（GF 表 + 乘除互逆 + 逆元全域 + 6 个级别 + 9 种布局）" % step[0])
    return True


if __name__ == "__main__":
    print("=" * 60)
    print(" ESK · mkit.raid 自检（内存假盘合成磁盘组，逐字节校验）")
    print("=" * 60)
    _selftest()
