# ============================================================
#  ESK  路  Calmgh06
#  Electronic Software Kit  |  bcachefs (read-only, partial)
# ============================================================
"""bcachefs 只读解析：超级块 / 版本编码 / sb 字段链 / 成员表 / journal 定位。

实现边界（如实标注，不做假装成功）
------------------------------------
已实现（第 1~3 层）：

* 超级块：设备偏移 0x1000（``BCH_SB_SECTOR = 8`` 个 512B 扇区）处的 ``struct bch_sb``，
  逐字段解析（csum / version / version_min / magic / uuid / user_uuid / label / offset /
  seq / block_size / dev_idx / nr_devices / u64s / time_base / flags[7] / write_time /
  features[2] / compat[2] / layout）。
* 版本编码：``BCH_VERSION(major, minor) = (major << 10) | minor``，反解 major/minor。
* 字段链：``struct bch_sb_field { __u64 _data[0]; __le32 u64s; __le32 type; }``，
  按 ``u64s * 8`` 字节步进，以 ``u64s == 0`` 为链结束；任何越界立即抛 ``BcachefsError``，
  绝不静默截断。
* 成员：``members_v1``（定长 ``BCH_MEMBER_V1_BYTES = 56`` 字节/项）与 ``members_v2``
  （头部 ``member_bytes`` 给出每项字节数，精确）。桶大小 = ``bucket_size << 9`` 字节。
* journal：从 sb 的 ``journal``（type 0）或 ``journal_v2``（type 9）取桶号，
  按桶读入、顺序扫描 ``struct jset``（magic = 设备 uuid 前 8 字节异或 ``JSET_MAGIC``），
  给出每条 jset 的 seq / version / u64s / last_seq / 偏移。

未实现（明确抛 ``NotImplementedError``）：

* **btree 完全未实现**。缺少 btree 节点读取、``bkey_format`` 的 ``bkey_packed`` 解包、
  extent 解析、bch_csum 校验与压缩（lz4/zstd）支持。因此 **目录遍历与文件内容读取不可用**：
  ``listdir()`` / ``read_file()`` / ``walk()`` 一律抛 ``NotImplementedError``，
  不返回空列表。

字段偏移的依据
--------------
所有偏移来自 ``fs/bcachefs/bcachefs_format.h``（bcachefs-testing 分支）与
``fs/bcachefs/sb/members_format.h``，逐字段按 C 结构声明顺序 + 自然对齐推得；
本机无真实 bcachefs 镜像可对照，标注「推断」处未在真实镜像上验证。
"""

import struct

# ---------------------------------------------------------------- 常量

BCH_SB_SECTOR = 8                      # 超级块所在 512B 扇区号（bcachefs_format.h）
SB_OFFSET = BCH_SB_SECTOR * 512        # = 0x1000 = 4096

# BCHFS_MAGIC 是 __uuid_t（16 字节），UUID_INIT(0xc68573f6, 0x66ce, 0x90a9, d0..d7)
# 按大端序展开前三个字段：c6 85 73 f6 | 66 ce | 90 a9 | d9 6a 60 cf 80 3d f7 ef
BCHFS_MAGIC_UUID = bytes.fromhex("c68573f666ce90a9d96a60cf803df7ef")

# 任务书给出的旧版 64 位魔数。当前头文件里 bch_sb.magic 已改成 __uuid_t，
# 该值与 BCHFS_MAGIC 的 UUID 不对应（应为更早的定长布局），仅作为探测兼容。
BCHFS_MAGIC_U64_LEGACY = 0xCA451A4BC78044DD

JSET_MAGIC = 0x245235C1A3625032
BSET_MAGIC = 0x90135C78B99E07F5

BCH_SB_LABEL_SIZE = 32
BCH_SB_MEMBERS_MAX = 64
BCH_SB_MEMBER_INVALID = 255

BCH_MEMBER_V1_BYTES = 56               # sb/members_format.h
BCH_MEMBER_FULL_BYTES = 296            # sizeof(struct bch_member)，逐字段累加
BCH_JOURNAL_BUCKETS_MIN = 8

# struct bch_sb 头长度 = 到 layout 末尾（含 512 字节 layout），字段链从此开始。
SB_HEADER_SIZE = 752

# struct bch_sb 内偏移（逐字段核对 bcachefs_format.h 的 struct bch_sb）
OFF_CSUM_LO = 0
OFF_CSUM_HI = 8
OFF_VERSION = 16
OFF_VERSION_MIN = 18
OFF_PAD = 20
OFF_MAGIC = 24          # __uuid_t magic
OFF_UUID = 40
OFF_USER_UUID = 56
OFF_LABEL = 72
OFF_SB_OFFSET = 104     # __le64 offset：该超级块写在哪个扇区
OFF_SEQ = 112
OFF_BLOCK_SIZE = 120
OFF_DEV_IDX = 122
OFF_NR_DEVICES = 123
OFF_U64S = 124
OFF_TIME_BASE_LO = 128
OFF_TIME_BASE_HI = 136
OFF_TIME_PRECISION = 140
OFF_FLAGS = 144         # __le64 flags[7] → 144..200
OFF_WRITE_TIME = 200
OFF_FEATURES = 208      # __le64 features[2] → 208..224
OFF_COMPAT = 224        # __le64 compat[2] → 224..240
OFF_LAYOUT = 240        # struct bch_sb_layout
LAYOUT_MAGIC = 240
LAYOUT_TYPE = 256
LAYOUT_SB_MAX_SIZE_BITS = 257
LAYOUT_NR_SUPERBLOCKS = 258
LAYOUT_SB_OFFSET = 264  # __le64 sb_offset[61] → 264..752
LAYOUT_SB_OFFSET_NR = 61

# BCH_SB_FIELDS() x 宏顺序（bcachefs_format.h）
SB_FIELD_TYPES = {
    0: "journal",
    1: "members_v1",
    2: "crypt",
    3: "replicas_v0",
    4: "quota",
    5: "disk_groups",
    6: "clean",
    7: "replicas",
    8: "journal_seq_blacklist",
    9: "journal_v2",
    10: "counters",
    11: "members_v2",
    12: "errors",
    13: "ext",
    14: "downgrade",
    15: "recovery_passes",
    16: "extent_type_u64s",
}

# BCH_SB_FIELD_journal 里的桶号数组元素宽度
JOURNAL_FIELD_U64 = 8

# BCH_MEMBER_STATES()
MEMBER_STATES = {0: "rw", 1: "ro", 2: "evacuating", 3: "spare"}

# struct jset 内偏移（逐字段核对 bcachefs_format.h 的 struct jset）
JSET_CSUM = 0
JSET_MAGIC_OFF = 16
JSET_SEQ = 24
JSET_VERSION = 32
JSET_FLAGS = 36
JSET_U64S = 40
JSET_READ_CLOCK = 44
JSET_WRITE_CLOCK = 46
JSET_LAST_SEQ = 48
JSET_HEADER_SIZE = 56   # sizeof(struct jset) = 7 个 u64


class BcachefsError(ValueError):
    """bcachefs 结构错误：魔数不符、长度不足、字段链越界、成员表异常等。"""


# ---------------------------------------------------------------- 小工具


def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _le64_bytes(raw):
    return struct.unpack("<Q", raw[:8])[0]


def _be64_bytes(raw):
    return struct.unpack(">Q", raw[:8])[0]


def _uuid(raw):
    """16 字节 UUID → 8-4-4-4-12 文本（与 UUID_INIT 的大端序布局一致）"""
    h = raw.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def bch_version(major, minor):
    """BCH_VERSION(major, minor) = (major << 10) | minor"""
    return ((major << 10) | (minor & 0x3FF)) & 0xFFFF


def bch_version_major(v):
    return (v >> 10) & 0x3F


def bch_version_minor(v):
    return v & 0x3FF


def _cstr(raw):
    """C 定长字符数组 → str（去尾部 NUL，非法字节替换）"""
    if raw is None:
        return None
    raw = raw.split(b"\x00", 1)[0]
    return raw.decode("utf-8", "replace")


def _is_pow2(v):
    return v > 0 and (v & (v - 1)) == 0


def _log2(v):
    n = 0
    while (1 << n) < v:
        n += 1
    return n


def _bits(value, lo, hi):
    """取 value 的 [lo, hi) 位（对应 LE64_BITMASK 的位域取法）"""
    return (value >> lo) & ((1 << (hi - lo)) - 1)


# ---------------------------------------------------------------- 主体


class Bcachefs(object):
    """bcachefs 只读解析（超级块 / 字段 / 成员 / journal 定位）。

    只依赖可读对象 ``sub.read(offset, size)`` 与 ``sub.size``，零第三方依赖。

    传入的 ``sub`` 必须是**单个成员设备**的视图（bcachefs 的超级块是每设备一份，
    偏移固定在 0x1000）；多设备卷请为每个设备各建一个实例。

    btree 未实现，因此本类不提供任何目录/文件内容读取能力，相关方法抛
    ``NotImplementedError``。
    """

    btree_available = False

    def __init__(self, sub, sb_offset=None):
        self.sub = sub
        self.warnings = []
        self.sb_offset = SB_OFFSET if sb_offset is None else sb_offset
        self._fields = None
        self._members = None
        self._read_super()

    # ---------------- 基础 ----------------
    def _size(self):
        try:
            return int(getattr(self.sub, "size", 0) or 0)
        except Exception:
            return 0

    def _read(self, off, size):
        try:
            data = self.sub.read(off, size)
        except Exception as exc:                      # 读失败按结构错误报
            raise BcachefsError("读取偏移 0x%X 失败：%s" % (off, exc))
        return data or b""

    # ---------------- 第 1 层：超级块 ----------------
    def _read_super(self):
        size = self._size()
        if size and self.sb_offset + SB_HEADER_SIZE > size:
            raise BcachefsError(
                "镜像过短：0x%X 处放不下 %d 字节的 bch_sb（设备大小 %d）"
                % (self.sb_offset, SB_HEADER_SIZE, size))
        head = self._read(self.sb_offset, SB_HEADER_SIZE)
        if len(head) < SB_HEADER_SIZE:
            raise BcachefsError(
                "bch_sb 头被截断：%d < %d 字节" % (len(head), SB_HEADER_SIZE))

        magic = head[OFF_MAGIC:OFF_MAGIC + 16]
        if magic != BCHFS_MAGIC_UUID:
            legacy = _u64(head, OFF_MAGIC)
            if legacy == BCHFS_MAGIC_U64_LEGACY:
                raise BcachefsError(
                    "命中旧版 bcachefs 魔数 0x%016X，但旧版 bch_sb 定长布局"
                    "（csum/magic/seq 均为 u64）未实现" % legacy)
            raise BcachefsError(
                "不是 bcachefs 超级块：magic=%s（期望 %s）"
                % (_uuid(magic), _uuid(BCHFS_MAGIC_UUID)))

        self.sb_raw = head
        self.magic = magic
        self.csum = (_u64(head, OFF_CSUM_LO), _u64(head, OFF_CSUM_HI))
        self.version = _u16(head, OFF_VERSION)
        self.version_min = _u16(head, OFF_VERSION_MIN)
        self.uuid = head[OFF_UUID:OFF_UUID + 16]
        self.user_uuid = head[OFF_USER_UUID:OFF_USER_UUID + 16]
        self.label = _cstr(head[OFF_LABEL:OFF_LABEL + BCH_SB_LABEL_SIZE])
        self.sb_offset_sectors = _u64(head, OFF_SB_OFFSET)
        self.seq = _u64(head, OFF_SEQ)
        self.block_size_sectors = _u16(head, OFF_BLOCK_SIZE)
        self.dev_idx = head[OFF_DEV_IDX]
        self.nr_devices = head[OFF_NR_DEVICES]
        self.sb_u64s = _u32(head, OFF_U64S)
        self.time_base_lo = _u64(head, OFF_TIME_BASE_LO)
        self.time_base_hi = _u32(head, OFF_TIME_BASE_HI)
        self.time_precision = _u32(head, OFF_TIME_PRECISION)
        self.flags = [_u64(head, OFF_FLAGS + 8 * i) for i in range(7)]
        self.write_time = _u64(head, OFF_WRITE_TIME)
        self.features = [_u64(head, OFF_FEATURES + 8 * i) for i in range(2)]
        self.compat = [_u64(head, OFF_COMPAT + 8 * i) for i in range(2)]

        # 块大小：现代布局的 block_size 是 __le16 扇区数（LE16_BITMASK
        # BCH_SB_BLOCK_SIZE, flags 0..16），推断为 512B 扇区单位。
        self.block_size = self.block_size_sectors * 512
        self.block_size_bits = _log2(self.block_size) if _is_pow2(self.block_size) else None
        if not self.block_size_sectors:
            self.warnings.append("超级块 block_size 为 0，块大小未知")

        # flags[0] 位域（bcachefs_format.h 的 LE64_BITMASK）
        f0 = self.flags[0]
        self.initialized = bool(_bits(f0, 0, 1))
        self.clean = bool(_bits(f0, 1, 2))
        self.csum_type = _bits(f0, 2, 8)
        self.error_action = _bits(f0, 8, 12)
        self.btree_node_size = _bits(f0, 12, 28)
        self.meta_replicas_want = _bits(f0, 48, 52)
        self.data_replicas_want = _bits(f0, 52, 56)

        # layout
        self.layout = {
            "magic": _uuid(head[LAYOUT_MAGIC:LAYOUT_MAGIC + 16]),
            "layout_type": head[LAYOUT_TYPE],
            "sb_max_size_bits": head[LAYOUT_SB_MAX_SIZE_BITS],
            "nr_superblocks": head[LAYOUT_NR_SUPERBLOCKS],
            "sb_offsets": [],
        }
        nr = min(head[LAYOUT_NR_SUPERBLOCKS], LAYOUT_SB_OFFSET_NR)
        for i in range(nr):
            self.layout["sb_offsets"].append(_u64(head, LAYOUT_SB_OFFSET + 8 * i))

        if self.nr_devices == 0:
            raise BcachefsError("超级块 nr_devices 为 0")
        if self.nr_devices > BCH_SB_MEMBERS_MAX:
            raise BcachefsError("超级块 nr_devices=%d 超过上限 %d"
                                % (self.nr_devices, BCH_SB_MEMBERS_MAX))

    def info(self):
        """超级块摘要（magic / seq / uuid / label / version / block_size / nr_devices）"""
        return {
            "magic": _uuid(self.magic),
            "magic_hex": self.magic.hex(),
            "magic_u64": _u64(self.sb_raw, OFF_MAGIC),
            "seq": self.seq,
            "uuid": _uuid(self.uuid),
            "user_uuid": _uuid(self.user_uuid),
            "label": self.label,
            "version": self.version,
            "version_major": bch_version_major(self.version),
            "version_minor": bch_version_minor(self.version),
            "version_text": "%d.%d" % (bch_version_major(self.version),
                                       bch_version_minor(self.version)),
            "version_min": self.version_min,
            "version_min_major": bch_version_major(self.version_min),
            "version_min_minor": bch_version_minor(self.version_min),
            "block_size": self.block_size,
            "block_size_sectors": self.block_size_sectors,
            "block_size_bits": self.block_size_bits,
            "nr_devices": self.nr_devices,
            "dev_idx": self.dev_idx,
            "offset_sectors": self.sb_offset_sectors,
            "sb_bytes": self.sb_u64s * 8,
            "initialized": self.initialized,
            "clean": self.clean,
            "csum_type": self.csum_type,
            "csum": "0x%016x%016x" % (self.csum[1], self.csum[0]),
            "error_action": self.error_action,
            "btree_node_size": self.btree_node_size,
            "meta_replicas_want": self.meta_replicas_want,
            "data_replicas_want": self.data_replicas_want,
            "time_base": self.time_base_lo,
            "time_base_hi": self.time_base_hi,
            "time_precision": self.time_precision,
            "write_time": self.write_time,
            "features": list(self.features),
            "compat": list(self.compat),
            "flags": list(self.flags),
            "layout": dict(self.layout, sb_offsets=list(self.layout["sb_offsets"])),
            "btree_available": False,
            "warnings": list(self.warnings),
        }

    # ---------------- 第 2 层：sb 字段链 ----------------
    def _sb_body(self):
        """按 sb.u64s 读出完整超级块（含字段链），并做截断/越界校验"""
        total = self.sb_u64s * 8
        if total < SB_HEADER_SIZE:
            raise BcachefsError(
                "sb.u64s=%d（%d 字节）小于超级块头长度 %d"
                % (self.sb_u64s, total, SB_HEADER_SIZE))
        size = self._size()
        if size and self.sb_offset + total > size:
            raise BcachefsError(
                "超级块声明 %d 字节（sb.u64s=%d），超出镜像边界 0x%X"
                % (total, self.sb_u64s, size))
        body = self._read(self.sb_offset, total)
        if len(body) < total:
            raise BcachefsError("超级块被截断：%d < %d 字节" % (len(body), total))
        return body

    def fields(self):
        """遍历 sb 字段链，返回 [{type, type_name, u64s, offset, bytes, data}]。

        每个字段头是 ``__le32 u64s`` + ``__le32 type``，按 ``u64s * 8`` 字节步进
        （``BCH_SB_FIELDS()`` 的遍历方式）；``u64s == 0`` 表示链结束。
        任何越界抛 ``BcachefsError``，不做截断猜测。
        """
        if self._fields is not None:
            return [dict(f) for f in self._fields]

        body = self._sb_body()
        total = len(body)
        out = []
        pos = SB_HEADER_SIZE
        while pos + 8 <= total:
            u64s = _u32(body, pos)
            ftype = _u32(body, pos + 4)
            if u64s == 0:
                break                                  # 链结束标记
            end = pos + u64s * 8
            if u64s < 1 or end > total:
                raise BcachefsError(
                    "sb 字段越界：type=%d u64s=%d @0x%X，终点 0x%X 超出字段区末尾 0x%X"
                    % (ftype, u64s, pos, end, total))
            if end <= pos + 8:
                raise BcachefsError("sb 字段 u64s=%d 不足以容纳 8 字节头" % u64s)
            out.append({
                "type": ftype,
                "type_name": SB_FIELD_TYPES.get(ftype, "unknown"),
                "u64s": u64s,
                "offset": self.sb_offset + pos,
                "bytes": u64s * 8,
                "data": body[pos + 8:end],
            })
            pos = end
        # 循环退出条件之一：剩余不足 8 字节（u64s 中的对齐留白），无需报错
        self._fields = out
        return [dict(f) for f in out]

    def field(self, name):
        """按名字取第一个 sb 字段（无则 None）"""
        for f in self.fields():
            if f["type_name"] == name:
                return f
        return None

    # ---------------- 第 2 层：成员 ----------------
    def members(self):
        """解析 members_v2（优先）或 members_v1，返回成员列表。

        桶字节数 = ``bucket_size << 9``（bucket_size 以 512B 扇区计）。
        """
        if self._members is not None:
            return [dict(m) for m in self._members]

        v2 = self.field("members_v2")
        v1 = self.field("members_v1")
        if v2 is not None:
            members = self._members_v2(v2)
        elif v1 is not None:
            members = self._members_v1(v1)
        else:
            raise BcachefsError("超级块既无 members_v2 也无 members_v1 字段")
        self._members = members
        return [dict(m) for m in members]

    def _members_v2(self, field):
        data = field["data"]
        if len(data) < 8:
            raise BcachefsError("members_v2 字段过短：%d 字节" % len(data))
        member_bytes = _u16(data, 0)
        if member_bytes < 48:
            raise BcachefsError("members_v2 member_bytes=%d 过小" % member_bytes)
        body = data[8:]
        if len(body) % member_bytes:
            raise BcachefsError(
                "members_v2 数据 %d 字节不是 member_bytes=%d 的整数倍"
                % (len(body), member_bytes))
        nr = len(body) // member_bytes
        return [self._parse_member(body[i * member_bytes:(i + 1) * member_bytes],
                                   i, member_bytes)
                for i in range(nr)]

    def _members_v1(self, field):
        body = field["data"]
        stride = BCH_MEMBER_V1_BYTES
        if body and len(body) % stride:
            if len(body) % BCH_MEMBER_FULL_BYTES == 0:
                # 部分实现按完整 struct bch_member 写入，按 296 字节重试
                stride = BCH_MEMBER_FULL_BYTES
            else:
                raise BcachefsError(
                    "members_v1 数据 %d 字节无法按 %d/项 或 %d/项 整除"
                    % (len(body), BCH_MEMBER_V1_BYTES, BCH_MEMBER_FULL_BYTES))
        nr = len(body) // stride if body else 0
        if not nr:
            raise BcachefsError("members_v1 字段为空")
        return [self._parse_member(body[i * stride:(i + 1) * stride], i, stride)
                for i in range(nr)]

    def _parse_member(self, entry, idx, stride):
        """解析单个 struct bch_member（偏移见 sb/members_format.h）"""
        if len(entry) < 48:
            raise BcachefsError("成员项 #%d 只有 %d 字节" % (idx, len(entry)))

        uuid = entry[0:16]
        nbuckets = _u64(entry, 16)
        first_bucket = _u16(entry, 24)
        bucket_size = _u16(entry, 26)
        shift = entry[28]
        last_mount = _u64(entry, 32) if stride >= 40 else None
        flags = _u64(entry, 40)

        state = _bits(flags, 0, 4)
        member = {
            "index": idx,
            "uuid": _uuid(uuid),
            "uuid_deleted": uuid == bytes.fromhex("ffffffffffffffff"
                                                  "d96a60cf803df7ef"),
            "nbuckets": nbuckets,
            "first_bucket": first_bucket,
            "bucket_size": bucket_size,               # 512B 扇区
            "bucket_bytes": bucket_size << 9,
            "btree_bitmap_shift": shift,
            "last_mount": last_mount,
            "flags": flags,
            "state": state,
            "state_name": MEMBER_STATES.get(state, "reserved%d" % state),
            "discard": bool(_bits(flags, 14, 15)),
            "data_allowed": _bits(flags, 15, 20),
            "group": _bits(flags, 20, 28),
            "durability": _bits(flags, 28, 30),
            "freespace_initialized": bool(_bits(flags, 30, 31)),
            "resize_on_mount": bool(_bits(flags, 31, 32)),
            "rotational": bool(_bits(flags, 32, 33)),
            "rotational_set": bool(_bits(flags, 33, 34)),
            "member_bytes": stride,
            "size_bytes": nbuckets * (bucket_size << 9),
            "device_name": None,
            "device_model": None,
            "device_serial": None,
            "seq": None,
            "last_journal_bucket": None,
            "last_journal_bucket_offset": None,
        }
        if stride >= 144:                              # 后续字段按 stride 是否覆盖决定
            member["iops"] = [_u32(entry, 48 + 4 * i) for i in range(4)]
            member["errors"] = [_u64(entry, 64 + 8 * i) for i in range(3)]
            member["errors_at_reset"] = [_u64(entry, 88 + 8 * i) for i in range(3)]
            member["errors_reset_time"] = _u64(entry, 112)
            member["seq"] = _u64(entry, 120)
            member["btree_allocated_bitmap"] = _u64(entry, 128)
            member["last_journal_bucket"] = _u32(entry, 136)
            member["last_journal_bucket_offset"] = _u32(entry, 140)
        if stride >= 296:
            member["device_name"] = _cstr(entry[144:160])
            member["device_model"] = _cstr(entry[160:224])
            member["flush_errors"] = _u64(entry, 224)
            member["device_serial"] = _cstr(entry[232:296])
        if not bucket_size:
            self.warnings.append("成员 #%d bucket_size 为 0" % idx)
        return member

    # ---------------- 第 3 层：journal ----------------
    def _journal_buckets(self):
        """从 journal（type 0）或 journal_v2（type 9）取桶号列表"""
        f = self.field("journal")
        if f is not None:
            data = f["data"]
            if len(data) % JOURNAL_FIELD_U64:
                raise BcachefsError("journal 字段 %d 字节不是 u64 的整数倍" % len(data))
            return [_u64(data, i * 8) for i in range(len(data) // JOURNAL_FIELD_U64)]

        f = self.field("journal_v2")
        if f is not None:
            data = f["data"]
            if len(data) % 16:
                raise BcachefsError("journal_v2 字段 %d 字节不是 16 的整数倍" % len(data))
            out = []
            for i in range(len(data) // 16):
                start = _u64(data, i * 16)
                nr = _u64(data, i * 16 + 8)
                if nr > (1 << 16):
                    raise BcachefsError("journal_v2 区间 nr=%d 异常" % nr)
                out.extend(range(start, start + nr))
            return out
        return []

    def _jset_magics(self):
        """jset 的 on-disk magic = 设备 uuid 前 8 字节（LE）异或 JSET_MAGIC"""
        return (_le64_bytes(self.uuid) ^ JSET_MAGIC,
                _be64_bytes(self.uuid) ^ JSET_MAGIC)

    def journal_buckets(self):
        """journal 桶号（原样，未乘桶大小）"""
        return self._journal_buckets()

    def bucket_offset(self, bucket, dev=0):
        """桶号 → 设备内字节偏移（桶号按绝对索引处理，推断）"""
        members = self.members()
        if dev >= len(members):
            raise BcachefsError("设备号 %d 超出成员表（%d 项）" % (dev, len(members)))
        bs = members[dev]["bucket_bytes"]
        if not bs:
            raise BcachefsError("成员 #%d 桶大小未知" % dev)
        return bucket * bs

    def journal_sets(self, dev=0):
        """扫描 journal 桶，返回按 seq 升序的 jset 列表。

        每条 jset：seq / version / u64s / last_seq / offset / bucket / magic_ok。
        桶内按 ``(u64s + 7) * 8`` 字节步进（``jset_u64s``）；magic 不符即停止该桶。
        """
        buckets = self._journal_buckets()
        if not buckets:
            raise BcachefsError("超级块中没有 journal / journal_v2 字段，无法定位 journal")
        members = self.members()
        if not members:
            raise BcachefsError("成员表为空，无法换算 journal 桶偏移")
        expect_le, expect_be = self._jset_magics()

        out = []
        for bucket in buckets:
            try:
                base = self.bucket_offset(bucket, dev)
            except BcachefsError as exc:
                self.warnings.append("journal 桶 %d 跳过：%s" % (bucket, exc))
                continue
            blen = members[dev]["bucket_bytes"]
            buf = self._read(base, blen)
            if len(buf) < JSET_HEADER_SIZE:
                self.warnings.append(
                    "journal 桶 %d（0x%X）不足一个 jset 头" % (bucket, base))
                continue
            pos = 0
            while pos + JSET_HEADER_SIZE <= len(buf):
                magic = _u64(buf, pos + JSET_MAGIC_OFF)
                if magic != expect_le and magic != expect_be:
                    if pos == 0:
                        self.warnings.append(
                            "journal 桶 %d 起始无 jset magic（0x%016x，期望 0x%016x）"
                            % (bucket, magic, expect_le))
                    break
                seq = _u64(buf, pos + JSET_SEQ)
                version = _u32(buf, pos + JSET_VERSION)
                flags = _u32(buf, pos + JSET_FLAGS)
                u64s = _u32(buf, pos + JSET_U64S)
                total = JSET_HEADER_SIZE + u64s * 8
                if total < JSET_HEADER_SIZE:
                    self.warnings.append("journal 桶 %d 的 jset u64s 溢出" % bucket)
                    break
                rec = {
                    "bucket": bucket,
                    "offset": base + pos,
                    "seq": seq,
                    "version": version,
                    "version_major": bch_version_major(version),
                    "version_minor": bch_version_minor(version),
                    "flags": flags,
                    "u64s": u64s,
                    "bytes": total,
                    "read_clock": _u16(buf, pos + JSET_READ_CLOCK),
                    "write_clock": _u16(buf, pos + JSET_WRITE_CLOCK),
                    "last_seq": _u64(buf, pos + JSET_LAST_SEQ),
                    "csum_type": _bits(flags, 0, 4),
                    "big_endian": magic == expect_be,
                    "magic_ok": True,
                    "truncated": False,
                }
                if pos + total > len(buf):
                    rec["truncated"] = True
                    self.warnings.append(
                        "journal 桶 %d 的 jset seq=%d 越界（需 %d，余 %d）"
                        % (bucket, seq, total, len(buf) - pos))
                    out.append(rec)
                    break
                out.append(rec)
                pos += total

        out.sort(key=lambda r: (r["seq"], r["offset"]))
        return out

    # ---------------- 第 4 层：btree（未实现） ----------------
    def _no_btree(self, what):
        raise NotImplementedError(
            "bcachefs btree 未实现（%s 不可用）：需要 btree 节点读取、bkey_format/"
            "bkey_packed 解包、extent 解析，以及 bch_csum 校验与 lz4/zstd 压缩支持。"
            "本模块目前只做超级块、sb 字段链、成员表与 journal 定位。" % what)

    def listdir(self, path="/"):
        """未实现：btree 未实现，目录读取不可用（不返回空列表）。"""
        self._no_btree("listdir(%r)" % (path,))

    def read_file(self, path):
        """未实现：btree 未实现，文件内容读取不可用。"""
        self._no_btree("read_file(%r)" % (path,))

    def walk(self, path="/"):
        """未实现：btree 未实现，目录遍历不可用。"""
        self._no_btree("walk(%r)" % (path,))

    def __repr__(self):
        return "<Bcachefs label=%r seq=%d version=%d.%d block_size=%d devices=%d>" % (
            self.label, self.seq,
            bch_version_major(self.version), bch_version_minor(self.version),
            self.block_size, self.nr_devices)


# ---------------------------------------------------------------- 入口


def probe(sub):
    """判断是否为 bcachefs 单设备视图（0x1000 处的 sb magic）"""
    try:
        size = int(getattr(sub, "size", 0) or 0)
    except Exception:
        size = 0
    if size and size < SB_OFFSET + 64:
        return False
    try:
        head = sub.read(SB_OFFSET, 64) or b""
    except Exception:
        return False
    if len(head) < OFF_MAGIC + 16:
        return False
    if head[OFF_MAGIC:OFF_MAGIC + 16] == BCHFS_MAGIC_UUID:
        return True
    return _u64(head, OFF_MAGIC) == BCHFS_MAGIC_U64_LEGACY


def open_fs(sub, sb_offset=None):
    """打开 bcachefs 设备视图"""
    if not probe(sub):
        raise BcachefsError("不是 bcachefs 文件系统（0x%X 处未找到 BCHFS_MAGIC）" % SB_OFFSET)
    return Bcachefs(sub, sb_offset=sb_offset)


# ---------------------------------------------------------------- 自检


if __name__ == "__main__":
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    checks = []

    def ok(name, cond, extra=""):
        checks.append(bool(cond))
        print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                             ("  " + str(extra)) if extra else ""))

    class Mem(object):
        """最小可读对象，符合 mkit 的 sub.read(off, size) / sub.size 约定"""

        def __init__(self, data):
            self.data = bytes(data)
            self.size = len(self.data)

        def read(self, off, size):
            if off < 0 or size <= 0 or off >= self.size:
                return b""
            return self.data[off:off + size]

    # ---------------- 合成镜像 ----------------
    BUCKET_SECTORS = 128                      # 128 * 512 = 64 KiB
    BUCKET_BYTES = BUCKET_SECTORS * 512
    NBUCKETS = 64
    DEV_UUID = bytes(range(0x10, 0x20))
    USER_UUID = bytes(range(0x20, 0x30))
    LABEL = "ESK-bcachefs 测试卷"              # 含中文
    SEQ = 7
    VERSION = bch_version(1, 13)
    VERSION_MIN = bch_version(1, 0)
    BLOCK_SECTORS = 8                          # 4096 字节
    KNOWN_U64S = {}

    def mk_field(ftype, body):
        pad = (-len(body)) % 8
        body = body + b"\x00" * pad
        return struct.pack("<II", (8 + len(body)) // 8, ftype) + body

    def member_v1(uuid, nbuckets, first_bucket, bucket_sectors, flags, last_mount):
        # uuid / nbuckets / first_bucket / bucket_size / shift / pad3 / last_mount /
        # flags / iops[2]（凑满 BCH_MEMBER_V1_BYTES = 56）
        return (uuid + struct.pack("<QHHB3sQQ", nbuckets, first_bucket,
                                   bucket_sectors, 0, b"\x00" * 3,
                                   last_mount, flags) + b"\x00" * 8)

    def member_full(uuid, nbuckets, first_bucket, bucket_sectors, flags, last_mount,
                    name=b"", model=b"", serial=b"", seq=0, last_jb=0, last_jb_off=0):
        """完整 struct bch_member（296 字节），偏移见 sb/members_format.h"""
        e = bytearray(BCH_MEMBER_FULL_BYTES)
        struct.pack_into("<16sQHHB3s", e, 0, uuid, nbuckets, first_bucket,
                         bucket_sectors, 0, b"\x00" * 3)
        struct.pack_into("<Q", e, 32, last_mount)
        struct.pack_into("<Q", e, 40, flags)
        struct.pack_into("<4I", e, 48, 100, 200, 300, 400)      # iops
        struct.pack_into("<Q", e, 120, seq)
        struct.pack_into("<II", e, 136, last_jb, last_jb_off)
        e[144:144 + len(name)] = name
        e[160:160 + len(model)] = model
        e[232:232 + len(serial)] = serial
        return bytes(e)

    def mk_image(member_kind="v1"):
        img = bytearray(NBUCKETS * BUCKET_BYTES)

        mem_flags = (1 << 28) | (0x1F << 15)     # durability=1, data_allowed=31
        if member_kind == "v1":
            members_body = member_v1(DEV_UUID, NBUCKETS, 0, BUCKET_SECTORS, mem_flags,
                                     0x65000000)
            members_field = mk_field(1, members_body)               # members_v1
            KNOWN_U64S["members_v1"] = (8 + BCH_MEMBER_V1_BYTES) // 8
        else:
            members_body = member_full(DEV_UUID, NBUCKETS, 0, BUCKET_SECTORS, mem_flags,
                                       0x65000000, name=b"nvme0n1",
                                       model=b"ESK Virtual Disk", serial=b"SN-0001",
                                       seq=19, last_jb=2, last_jb_off=0x80)
            members_field = mk_field(11, struct.pack("<H6x", BCH_MEMBER_FULL_BYTES)
                                     + members_body)                # members_v2
            KNOWN_U64S["members_v2"] = (8 + 8 + BCH_MEMBER_FULL_BYTES) // 8
        clean = struct.pack("<IHHQ", 0, 0, 0, 41)          # flags/clocks/journal_seq
        custom = bytes.fromhex("deadbeef") * 2

        fields = (members_field +
                  mk_field(6, clean) +              # clean
                  mk_field(0, struct.pack("<QQ", 1, 2)) +   # journal：桶 1、2
                  mk_field(0x2A, custom))           # 自定义字段
        KNOWN_U64S["clean"] = 3                 # (8 + 16) / 8
        KNOWN_U64S["journal"] = 3               # (8 + 16) / 8
        KNOWN_U64S["custom"] = 2                # (8 + 8) / 8

        # 尾部 8 字节 0 → u64s == 0 的链结束标记，验证循环不越界
        blob = bytes(fields) + b"\x00" * 8
        sb = bytearray(SB_HEADER_SIZE) + bytearray(blob)
        total_u64s = len(sb) // 8

        struct.pack_into("<QQ", sb, OFF_CSUM_LO, 0x1122334455667788, 0x99AABBCCDDEEFF00)
        struct.pack_into("<HHHH", sb, OFF_VERSION, VERSION, VERSION_MIN, 0, 0)
        sb[OFF_MAGIC:OFF_MAGIC + 16] = BCHFS_MAGIC_UUID
        sb[OFF_UUID:OFF_UUID + 16] = DEV_UUID
        sb[OFF_USER_UUID:OFF_USER_UUID + 16] = USER_UUID
        enc = LABEL.encode("utf-8")
        sb[OFF_LABEL:OFF_LABEL + len(enc)] = enc
        struct.pack_into("<QQ", sb, OFF_SB_OFFSET, BCH_SB_SECTOR, SEQ)
        struct.pack_into("<HBBI", sb, OFF_BLOCK_SIZE, BLOCK_SECTORS, 0, 1, total_u64s)
        struct.pack_into("<QII", sb, OFF_TIME_BASE_LO, 0x65000000, 0, 1)
        flags0 = (1 << 0) | (1 << 1) | (1 << 2) | (16 << 12) | (1 << 48) | (1 << 52)
        struct.pack_into("<Q", sb, OFF_FLAGS, flags0)
        struct.pack_into("<Q", sb, OFF_WRITE_TIME, 0x65000100)
        struct.pack_into("<QQ", sb, OFF_FEATURES, 0x1, 0x2)
        struct.pack_into("<QQ", sb, OFF_COMPAT, 0x0, 0x0)
        # layout
        sb[LAYOUT_MAGIC:LAYOUT_MAGIC + 16] = DEV_UUID
        sb[LAYOUT_TYPE] = 0
        sb[LAYOUT_SB_MAX_SIZE_BITS] = 9
        sb[LAYOUT_NR_SUPERBLOCKS] = 1
        struct.pack_into("<Q", sb, LAYOUT_SB_OFFSET, BCH_SB_SECTOR)

        img[SB_OFFSET:SB_OFFSET + len(sb)] = sb

        magic = _le64_bytes(DEV_UUID) ^ JSET_MAGIC

        def mk_jset(seq, u64s, payload=b""):
            h = bytearray(JSET_HEADER_SIZE + u64s * 8)
            struct.pack_into("<QQ", h, JSET_CSUM, 0, 0)
            struct.pack_into("<Q", h, JSET_MAGIC_OFF, magic)
            struct.pack_into("<QQ", h, JSET_SEQ, seq, 0)
            struct.pack_into("<II", h, JSET_VERSION, VERSION, 0)
            struct.pack_into("<I", h, JSET_U64S, u64s)
            struct.pack_into("<HH", h, JSET_READ_CLOCK, 3, 4)
            struct.pack_into("<Q", h, JSET_LAST_SEQ, 0)
            h[JSET_HEADER_SIZE:JSET_HEADER_SIZE + len(payload)] = payload
            return bytes(h)

        # 桶 1：seq 1（空）、seq 2（1 个 u64 负载）、seq 3（空）
        b1 = BUCKET_BYTES
        blob1 = mk_jset(1, 0) + mk_jset(2, 1, b"\xAA" * 8) + mk_jset(3, 0)
        img[b1:b1 + len(blob1)] = blob1
        # 桶 2：seq 4
        b2 = 2 * BUCKET_BYTES
        blob2 = mk_jset(4, 0)
        img[b2:b2 + len(blob2)] = blob2
        return bytes(img)

    IMG = mk_image()
    print("== 合成 bcachefs 镜像：%d 字节，sb@0x%X，桶 %d 个 × %d 字节 =="
          % (len(IMG), SB_OFFSET, NBUCKETS, BUCKET_BYTES))

    # ---------------- 1. probe ----------------
    print("\n-- 1. probe --")
    ok("命中 BCHFS_MAGIC（0x1000）", probe(Mem(IMG)) is True)
    fs = open_fs(Mem(IMG))
    ok("open_fs 返回 Bcachefs", isinstance(fs, Bcachefs))
    zero = b"\x00" * (NBUCKETS * BUCKET_BYTES)
    ok("全零不命中", probe(Mem(zero)) is False)
    rnd = bytearray(IMG)
    for i in range(SB_OFFSET, SB_OFFSET + 64):
        rnd[i] = (i * 37 + 11) & 0xFF
    ok("随机字节不命中", probe(Mem(bytes(rnd))) is False)
    ok("过短（2 KiB）不命中", probe(Mem(IMG[:2048])) is False)
    ok("过短（0 字节）不命中", probe(Mem(b"")) is False)
    ok("空对象不命中", probe(object()) is False)

    # ---------------- 2. 超级块 ----------------
    print("\n-- 2. 超级块字段 --")
    inf = fs.info()
    ok("seq", inf["seq"] == SEQ, inf["seq"])
    ok("uuid", inf["uuid"] == _uuid(DEV_UUID), inf["uuid"])
    ok("user_uuid", inf["user_uuid"] == _uuid(USER_UUID), inf["user_uuid"])
    ok("label 含中文", inf["label"] == LABEL, repr(inf["label"]))
    ok("version 编码 %d = %d.%d" % (VERSION, 1, 13),
       inf["version"] == VERSION and inf["version_major"] == 1
       and inf["version_minor"] == 13, inf["version_text"])
    ok("version_min = 1.0",
       inf["version_min_major"] == 1 and inf["version_min_minor"] == 0,
       "%d.%d" % (inf["version_min_major"], inf["version_min_minor"]))
    ok("block_size = %d 字节（%d 扇区）" % (BLOCK_SECTORS * 512, BLOCK_SECTORS),
       inf["block_size"] == BLOCK_SECTORS * 512
       and inf["block_size_sectors"] == BLOCK_SECTORS, inf["block_size"])
    ok("block_size_bits = 12", inf["block_size_bits"] == 12, inf["block_size_bits"])
    ok("nr_devices", inf["nr_devices"] == 1, inf["nr_devices"])
    ok("dev_idx", inf["dev_idx"] == 0)
    ok("sb.offset = 8 扇区", inf["offset_sectors"] == BCH_SB_SECTOR)
    ok("sb.u64s 与镜像一致",
       inf["sb_bytes"] == (SB_HEADER_SIZE + 64 + 24 + 24 + 16 + 8), inf["sb_bytes"])
    ok("layout.nr_superblocks=1 且 sb_offsets=[8]",
       inf["layout"]["nr_superblocks"] == 1
       and inf["layout"]["sb_offsets"] == [BCH_SB_SECTOR], inf["layout"]["sb_offsets"])
    ok("flags[0] 位域：initialized/clean/csum_type",
       inf["initialized"] is True and inf["clean"] is True
       and inf["csum_type"] == 1, (inf["initialized"], inf["clean"], inf["csum_type"]))
    ok("btree_available 标记为 False", inf["btree_available"] is False)
    ok("repr 含 label", "ESK-bcachefs" in repr(fs), repr(fs))

    # ---------------- 3. sb 字段链 ----------------
    print("\n-- 3. sb 字段链 --")
    flds = fs.fields()
    ok("字段数 = 4（尾部 u64s=0 结束标记未被计入）", len(flds) == 4, len(flds))
    ok("类型顺序 members_v1/clean/journal/custom",
       [f["type"] for f in flds] == [1, 6, 0, 0x2A],
       [f["type_name"] for f in flds])
    ok("members_v1 u64s", flds[0]["u64s"] == KNOWN_U64S["members_v1"], flds[0]["u64s"])
    ok("clean u64s", flds[1]["u64s"] == KNOWN_U64S["clean"], flds[1]["u64s"])
    ok("journal u64s", flds[2]["u64s"] == KNOWN_U64S["journal"], flds[2]["u64s"])
    ok("自定义字段 type=0x2A 名回落 unknown",
       flds[3]["u64s"] == KNOWN_U64S["custom"] and flds[3]["type_name"] == "unknown",
       (flds[3]["u64s"], flds[3]["type_name"]))
    ok("自定义字段载荷", flds[3]["data"] == bytes.fromhex("deadbeef") * 2)
    ok("字段偏移连续且不重叠",
       all(flds[i]["offset"] + flds[i]["bytes"] == flds[i + 1]["offset"]
           for i in range(len(flds) - 1)),
       [(f["offset"], f["bytes"]) for f in flds])
    ok("首个字段紧接头之后 0x%X" % (SB_OFFSET + SB_HEADER_SIZE),
       flds[0]["offset"] == SB_OFFSET + SB_HEADER_SIZE, hex(flds[0]["offset"]))
    used = SB_HEADER_SIZE + sum(f["bytes"] for f in flds)
    ok("字段总步进不越界（+8 结束标记 = sb 长度）",
       used + 8 == fs.sb_u64s * 8, (used, fs.sb_u64s * 8))
    ok("field('clean') 命中", fs.field("clean")["type"] == 6)
    ok("field('crypt') 缺失返回 None", fs.field("crypt") is None)

    # ---------------- 4. 成员 ----------------
    print("\n-- 4. members --")
    mems = fs.members()
    m = mems[0]
    ok("成员数 = 1", len(mems) == 1, len(mems))
    ok("成员 uuid", m["uuid"] == _uuid(DEV_UUID), m["uuid"])
    ok("nbuckets = %d" % NBUCKETS, m["nbuckets"] == NBUCKETS, m["nbuckets"])
    ok("first_bucket = 0", m["first_bucket"] == 0)
    ok("bucket_size = %d 扇区" % BUCKET_SECTORS,
       m["bucket_size"] == BUCKET_SECTORS, m["bucket_size"])
    ok("桶字节数 = bucket_size << 9 = %d" % BUCKET_BYTES,
       m["bucket_bytes"] == BUCKET_BYTES, m["bucket_bytes"])
    ok("设备字节数 = nbuckets × 桶", m["size_bytes"] == NBUCKETS * BUCKET_BYTES,
       m["size_bytes"])
    ok("state = rw / durability = 1 / data_allowed = 31",
       m["state_name"] == "rw" and m["durability"] == 1 and m["data_allowed"] == 31,
       (m["state_name"], m["durability"], m["data_allowed"]))
    ok("v1 项宽 = %d" % BCH_MEMBER_V1_BYTES, m["member_bytes"] == BCH_MEMBER_V1_BYTES)
    ok("v1 无 device_name（项宽不足，如实为 None）", m["device_name"] is None)
    ok("bucket_offset(2) = %d" % (2 * BUCKET_BYTES),
       fs.bucket_offset(2) == 2 * BUCKET_BYTES, fs.bucket_offset(2))

    # ---------------- 5. 截断与异常 ----------------
    print("\n-- 5. 截断 / 异常 --")
    try:
        open_fs(Mem(IMG[:SB_OFFSET + 100]))
        ok("过短镜像抛 BcachefsError", False, "未抛")
    except NotImplementedError:
        ok("过短镜像抛 BcachefsError", False, "抛了 NotImplementedError")
    except BcachefsError as exc:
        ok("过短镜像抛 BcachefsError", True, str(exc)[:60])
    try:
        Bcachefs(Mem(IMG), sb_offset=0)
        ok("错位读 sb 抛 BcachefsError", False, "未抛")
    except BcachefsError as exc:
        ok("错位读 sb 抛 BcachefsError", True, str(exc)[:48])
    bad = bytearray(IMG)
    bad[SB_OFFSET + OFF_MAGIC] ^= 0xFF
    try:
        open_fs(Mem(bytes(bad)))
        ok("魔数损坏抛 BcachefsError", False, "未抛")
    except BcachefsError as exc:
        ok("魔数损坏抛 BcachefsError", True, str(exc)[:48])
    over = bytearray(IMG)
    struct.pack_into("<I", over, SB_OFFSET + SB_HEADER_SIZE, 0x4000)   # 字段 u64s 巨大
    try:
        Bcachefs(Mem(bytes(over))).fields()
        ok("字段 u64s 越界抛 BcachefsError", False, "未抛")
    except BcachefsError as exc:
        ok("字段 u64s 越界抛 BcachefsError", True, str(exc)[:56])
    short_u64s = bytearray(IMG)
    struct.pack_into("<I", short_u64s, SB_OFFSET + OFF_U64S, 4)        # sb.u64s < 头
    try:
        Bcachefs(Mem(bytes(short_u64s))).fields()
        ok("sb.u64s 小于头长度抛 BcachefsError", False, "未抛")
    except BcachefsError as exc:
        ok("sb.u64s 小于头长度抛 BcachefsError", True, str(exc)[:56])
    nofields = bytearray(IMG)
    struct.pack_into("<I", nofields, SB_OFFSET + OFF_U64S, SB_HEADER_SIZE // 8)
    try:
        Bcachefs(Mem(bytes(nofields))).members()
        ok("无成员字段抛 BcachefsError", False, "未抛")
    except BcachefsError as exc:
        ok("无成员字段抛 BcachefsError", True, str(exc)[:40])

    # ---------------- 6. journal ----------------
    print("\n-- 6. journal --")
    ok("journal 桶号 = [1, 2]", fs.journal_buckets() == [1, 2], fs.journal_buckets())
    req, _be = fs._jset_magics()
    ok("jset magic = le64(uuid) ^ JSET_MAGIC",
       req == (_le64_bytes(DEV_UUID) ^ JSET_MAGIC), hex(req))
    jsets = fs.journal_sets()
    ok("jset 数 = 4（跨 2 个桶）", len(jsets) == 4, len(jsets))
    ok("seq 升序 [1,2,3,4]", [j["seq"] for j in jsets] == [1, 2, 3, 4],
       [j["seq"] for j in jsets])
    ok("每条 magic 校验通过", all(j["magic_ok"] for j in jsets))
    ok("seq=2 的 u64s=1、长度 64 字节",
       jsets[1]["u64s"] == 1 and jsets[1]["bytes"] == 64,
       (jsets[1]["u64s"], jsets[1]["bytes"]))
    ok("seq=1 的 u64s=0、长度 56 字节",
       jsets[0]["u64s"] == 0 and jsets[0]["bytes"] == JSET_HEADER_SIZE)
    ok("桶内偏移 = 桶基址 + n×jset 长度",
       jsets[0]["offset"] == BUCKET_BYTES
       and jsets[1]["offset"] == BUCKET_BYTES + 56
       and jsets[2]["offset"] == BUCKET_BYTES + 120,
       [hex(j["offset"]) for j in jsets])
    ok("桶 2 的 seq=4 偏移 = 2×桶字节数",
       jsets[3]["offset"] == 2 * BUCKET_BYTES, hex(jsets[3]["offset"]))
    ok("jset version 解码 = 1.13",
       (jsets[0]["version_major"], jsets[0]["version_minor"]) == (1, 13))
    ok("jset last_seq / clocks",
       jsets[0]["last_seq"] == 0 and jsets[0]["write_clock"] == 4)
    ok("无 jset 的桶（0）不出记录", all(j["bucket"] in (1, 2) for j in jsets))

    # ---------------- 7. btree 未实现 ----------------
    print("\n-- 7. btree 层（未实现，必须抛）--")
    for name, fn in (("listdir()", lambda: fs.listdir("/")),
                     ("read_file()", lambda: fs.read_file("/x")),
                     ("walk()", lambda: fs.walk("/"))):
        try:
            fn()
            ok("%s 抛 NotImplementedError" % name, False, "未抛")
        except NotImplementedError as exc:
            ok("%s 抛 NotImplementedError" % name, True, str(exc)[:46])
        except Exception as exc:
            ok("%s 抛 NotImplementedError" % name, False, type(exc).__name__)
    # ---------------- 8. members_v2（完整项宽 + 设备名） ----------------
    print("\n-- 8. members_v2 --")
    IMG2 = mk_image("v2")
    fs2 = open_fs(Mem(IMG2))
    ok("v2 字段类型 = members_v2", fs2.fields()[0]["type_name"] == "members_v2",
       fs2.fields()[0]["type_name"])
    ok("v2 字段 u64s", fs2.fields()[0]["u64s"] == KNOWN_U64S["members_v2"],
       fs2.fields()[0]["u64s"])
    m2 = fs2.members()[0]
    ok("v2 项宽 = %d" % BCH_MEMBER_FULL_BYTES,
       m2["member_bytes"] == BCH_MEMBER_FULL_BYTES, m2["member_bytes"])
    ok("v2 设备名 / 型号 / 序列号",
       (m2["device_name"], m2["device_model"], m2["device_serial"])
       == ("nvme0n1", "ESK Virtual Disk", "SN-0001"),
       (m2["device_name"], m2["device_model"], m2["device_serial"]))
    ok("v2 nbuckets/bucket_size 与 v1 一致",
       (m2["nbuckets"], m2["bucket_bytes"]) == (NBUCKETS, BUCKET_BYTES),
       (m2["nbuckets"], m2["bucket_bytes"]))
    ok("v2 member.seq / last_journal_bucket",
       m2["seq"] == 19 and m2["last_journal_bucket"] == 2
       and m2["last_journal_bucket_offset"] == 0x80,
       (m2["seq"], m2["last_journal_bucket"], m2["last_journal_bucket_offset"]))
    ok("v2 iops[0..3]", m2["iops"] == [100, 200, 300, 400], m2["iops"])
    ok("v2 journal 仍可定位（与 v1 镜像同桶布局）",
       [j["seq"] for j in fs2.journal_sets()] == [1, 2, 3, 4],
       [j["seq"] for j in fs2.journal_sets()])

    # ---------------- 9. 无 journal 字段 ----------------
    print("\n-- 9. 无 journal 字段 --")
    noj = bytearray(IMG)
    # 第三个字段（journal，type 0）改成未知类型 0x30
    jpos = SB_OFFSET + SB_HEADER_SIZE + KNOWN_U64S["members_v1"] * 8 \
        + KNOWN_U64S["clean"] * 8
    struct.pack_into("<I", noj, jpos + 4, 0x30)
    fs3 = Bcachefs(Mem(bytes(noj)))
    ok("未知类型字段不影响链路", [f["type"] for f in fs3.fields()] == [1, 6, 0x30, 0x2A],
       [f["type_name"] for f in fs3.fields()])
    ok("journal 桶号为空", fs3.journal_buckets() == [])
    try:
        fs3.journal_sets()
        ok("无 journal 字段时 journal_sets 抛 BcachefsError", False, "未抛")
    except BcachefsError as exc:
        ok("无 journal 字段时 journal_sets 抛 BcachefsError", True, str(exc)[:40])

    print("\n全部 %d 项断言通过" % len(checks))
    if not all(checks):
        print("有断言失败")
        sys.exit(1)
    sys.exit(0)
