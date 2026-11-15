# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""统一时间线聚合 —— 跨模块 / 跨平台事件归并

对应 LovelyCarve 的「时间线」能力：把 NTFS / FAT / exFAT / HFS / XFS / ext4
的目录项时间、注册表键的 LastWriteTime、以及外部 CSV / JSON 里的痕迹，
统一成一条按时间排序的事件流，并能导出成证据报表。

只依赖可读对象 fs.read(offset, size) / fs.size（以及可选 fs.walk()），不依赖第三方库。

已实现：
    · 6 种时间戳换算
        - Unix 秒（1970-01-01 UTC）
        - Windows FILETIME（1601-01-01，100ns）
        - HFS / Mac 纪元（1904-01-01）
        - APFS 纳秒（1970-01-01，ns）
        - FAT / exFAT DOS 日期时间（1980 基准，2 秒精度，无时区 → 标 tz_assumed）
        - ext4（Unix 秒 + 纳秒扩展）
    · 时区偏移归一：给定 tz_offset_hours 时把墙钟时间折算成 UTC
    · Event 事件对象 + Timeline 聚合器
    · 适配器（各自独立可用）
        - from_fs(fs, kinds=None)    任意带 walk() 的文件系统对象
        - from_regf(hive, ...)       注册表 hive 的 nk LastWriteTime
        - from_csv(path, ...)        已有 CSV 导入（列名可配置）
        - from_json(path, ...)       JSON 行 / JSON 数组导入
    · 排序、去重（(ts, source, path, action) 相同视为重复，保留第一条）
    · filter / stats / heatmap / gaps
    · 导出 CSV（utf-8-sig，Excel 打开中文不乱码）/ JSONL / SQLite（建表 + 索引）

不实现：
    · 时间戳缺失的推测（缺失即跳过，不做「推断创建时间」）
    · 时区历史库（夏令时切换请自己给正确的 tz_offset_hours）
    · $UsnJrnl / EVTX / APFS 二进制解析（先由 winart / ext 侧模块解析，再喂给本模块）
    · 流式外部排序（全内存聚合，百万级以内；更大请先按天分片）
"""

import csv
import datetime
import json
import os
import sqlite3
import struct

__all__ = [
    "Event", "Timeline", "EVENT_FIELDS",
    "UNIX_EPOCH", "FILETIME_EPOCH", "HFS_EPOCH", "FAT_EPOCH",
    "FILETIME_UNIX_DELTA", "HFS_UNIX_DELTA",
    "from_unix", "from_filetime", "from_hfs", "from_apfs_ns",
    "from_fat", "from_ext4", "filetime_from_raw", "parse_dos_string",
    "coerce_dt",
    "from_fs", "from_regf", "from_csv", "from_json",
]


# ============================================================
# 纪元常量
# ============================================================
_UTC = datetime.timezone.utc

UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=_UTC)
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=_UTC)
HFS_EPOCH = datetime.datetime(1904, 1, 1, tzinfo=_UTC)
FAT_EPOCH = datetime.datetime(1980, 1, 1, tzinfo=_UTC)

FILETIME_UNIX_DELTA = 11644473600          # 1601-01-01 到 1970-01-01 的秒数
HFS_UNIX_DELTA = 2082844800                # 1904-01-01 到 1970-01-01 的秒数

_FILETIME_TICKS = 10 ** 7                  # FILETIME 每秒 1000 万个 100ns
_NS_PER_SEC = 10 ** 9

# 纯数字字符串视为时间戳
_NUMERIC = "-+0123456789."

# 文本时间戳的常见写法（不含时区的按 UTC 解释）
_TEXT_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%Y/%m/%d",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S %z",
)


def _shift(dt, tz_offset_hours=None):
    """把「墙钟值」按参考时区折算到 UTC。

    dt 是已经按 UTC 语义构造出来的 datetime；tz_offset_hours 表示这个数值
    实际所属时区（东八区传 8）。折算即减去该偏移。None / 0 视为已是 UTC。
    """
    if not tz_offset_hours:
        return dt
    return dt - datetime.timedelta(hours=float(tz_offset_hours))


# ============================================================
# 6 种时间戳换算
# ============================================================
def from_unix(sec, tz_offset_hours=None, micro=0):
    """Unix 秒 -> 带 UTC 时区的 datetime"""
    try:
        dt = UNIX_EPOCH + datetime.timedelta(seconds=int(sec), microseconds=int(micro))
    except (OverflowError, ValueError, TypeError):
        raise ValueError("Unix 时间戳越界: %r" % (sec,))
    return _shift(dt, tz_offset_hours)


def from_filetime(ft, tz_offset_hours=None):
    """Windows FILETIME(1601-01-01 起的 100ns 计数) -> UTC datetime

    unix = ft / 10**7 - 11644473600
    微秒级截断（100ns 的三位无法塞进 datetime，按向下取整丢弃）。
    """
    try:
        ft = int(ft)
    except (TypeError, ValueError):
        raise ValueError("FILETIME 必须是整数: %r" % (ft,))
    whole, frac = divmod(ft, _FILETIME_TICKS)      # 整数运算，避免 float 丢精度
    # whole 已经是「1601 起的秒」，直接加在 1601 纪元上；
    # unix = ft/10**7 - 11644473600 只是同一件事的另一种写法。
    try:
        dt = FILETIME_EPOCH + datetime.timedelta(
            seconds=whole, microseconds=frac // 10)
    except (OverflowError, ValueError):
        raise ValueError("FILETIME 越界: %r" % (ft,))
    return _shift(dt, tz_offset_hours)


def from_hfs(hfs, tz_offset_hours=None):
    """HFS / HFS+ / HFSX 时间（1904-01-01 起的秒）-> UTC datetime

    unix = hfs - 2082844800
    """
    try:
        # hfs 本身就是「1904 起的秒」，直接加在 1904 纪元上；
        # unix = hfs - 2082844800 是等价写法（2082844800 即两纪元之差）。
        dt = HFS_EPOCH + datetime.timedelta(seconds=int(hfs))
    except (OverflowError, ValueError, TypeError):
        raise ValueError("HFS 时间戳越界: %r" % (hfs,))
    return _shift(dt, tz_offset_hours)


def from_apfs_ns(ns, tz_offset_hours=None):
    """APFS 时间（1970-01-01 起的纳秒）-> UTC datetime（微秒精度）"""
    try:
        ns = int(ns)
    except (TypeError, ValueError):
        raise ValueError("APFS 纳秒必须是整数: %r" % (ns,))
    sec, rem = divmod(ns, _NS_PER_SEC)
    try:
        dt = UNIX_EPOCH + datetime.timedelta(seconds=sec, microseconds=rem // 1000)
    except (OverflowError, ValueError):
        raise ValueError("APFS 纳秒越界: %r" % (ns,))
    return _shift(dt, tz_offset_hours)


def from_fat(date_word, time_word=None, tz_offset_hours=None,
             sub10ms=0, with_flag=False):
    """FAT / exFAT 的 DOS 日期时间 -> UTC datetime

    参数：
        date_word —— 16 位日期（year-1980 << 9 | month << 5 | day）
        time_word —— 16 位时间（hour << 11 | min << 5 | sec/2）；为 None 时
                     把 date_word 当成 32 位 dword（高 16 日期、低 16 时间）
        sub10ms   —— exFAT 的 10ms 扩展位（0~199）
        with_flag —— True 时返回 (datetime, tz_assumed)

    FAT 本身不带时区：未给 tz_offset_hours 时按 UTC 解释，并把 tz_assumed
    置 True（导出里保留这一标注，避免把「假定值」当「确证值」）。
    """
    word = int(date_word)
    if time_word is None:
        d, t = (word >> 16) & 0xFFFF, word & 0xFFFF
    else:
        d, t = word & 0xFFFF, int(time_word) & 0xFFFF

    y = 1980 + ((d >> 9) & 0x7F)
    mo = (d >> 5) & 0x0F
    da = d & 0x1F
    hh = (t >> 11) & 0x1F
    mi = (t >> 5) & 0x3F
    ss = (t & 0x1F) * 2

    if not (1 <= mo <= 12 and 1 <= da <= 31):
        raise ValueError("FAT 日期字非法: 0x%04X" % d)
    if hh > 23 or mi > 59 or ss > 59:
        raise ValueError("FAT 时间字非法: 0x%04X" % t)
    if not (0 <= sub10ms <= 199):
        raise ValueError("FAT 10ms 扩展越界: %r" % (sub10ms,))

    try:
        dt = datetime.datetime(y, mo, da, hh, mi, ss, tzinfo=_UTC)
    except ValueError as e:
        raise ValueError("FAT 日期不存在: %04d-%02d-%02d (%s)" % (y, mo, da, e))
    dt = dt + datetime.timedelta(milliseconds=sub10ms * 10)
    out = _shift(dt, tz_offset_hours)
    if with_flag:
        return out, tz_offset_hours is None
    return out


def from_ext4(sec, nsec=0, tz_offset_hours=None):
    """ext4 时间（Unix 秒 + 纳秒扩展）-> UTC datetime（微秒精度）"""
    try:
        nsec = int(nsec or 0)
    except (TypeError, ValueError):
        raise ValueError("ext4 纳秒非法: %r" % (nsec,))
    if not (0 <= nsec < _NS_PER_SEC):
        raise ValueError("ext4 纳秒越界: %r" % (nsec,))
    return from_unix(sec, tz_offset_hours, micro=nsec // 1000)


def filetime_from_raw(raw, offset=0):
    """从原始字节里读 FILETIME（小端 u64）并换算 -> UTC datetime"""
    if len(raw) - offset < 8:
        raise ValueError("字节不足 8，读不出 FILETIME")
    (ft,) = struct.unpack_from("<Q", raw, offset)
    return from_filetime(ft)


def parse_dos_string(text, tz_offset_hours=None):
    """解析 mkit.fat / mkit.exfat 给出的 'YYYY-MM-DD HH:MM:SS' 字符串

    这类字符串没有时区，未给偏移时按 UTC 解释（与 from_fat 一致）。
    """
    if text is None:
        return None
    s = str(text).strip()
    if not s:
        return None
    try:
        dt = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise ValueError("不是 DOS 时间字符串: %r" % (text,))
    return _shift(dt.replace(tzinfo=_UTC), tz_offset_hours)


# ============================================================
# 通用时间归一
# ============================================================
def _from_number(value, epoch, tz_offset_hours):
    kind = (epoch or "unix").lower()
    if kind in ("unix", "unix_s", "posix"):
        return from_unix(value, tz_offset_hours)
    if kind in ("unix_ns", "apfs_ns", "ns"):
        return from_apfs_ns(value, tz_offset_hours)
    if kind == "filetime":
        return from_filetime(value, tz_offset_hours)
    if kind in ("hfs", "mac"):
        return from_hfs(value, tz_offset_hours)
    if kind in ("fat", "exfat", "dos"):
        return from_fat(value, None, tz_offset_hours)
    raise ValueError("未知时间戳格式: %r" % (epoch,))


def coerce_dt(value, epoch="unix", tz_offset_hours=None, time_format=None):
    """把任意时间字段统一成带 UTC 时区的 datetime

    接受：
        · datetime（naive 视为 UTC；带时区的转 UTC）
        · date
        · 字符串：ISO 8601 / 'YYYY-MM-DD HH:MM:SS' / 纯数字时间戳
        · int / float：按 epoch 解释（unix / unix_ns / apfs_ns / filetime / hfs / fat）
        · (sec, nsec) 二元组：按 ext4 解释
    无法解析返回 None（适配器据此跳过该字段，不猜）。
    """
    if value is None:
        return None

    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            return _shift(value.replace(tzinfo=_UTC), tz_offset_hours)
        return value.astimezone(_UTC)

    if isinstance(value, datetime.date):
        dt = datetime.datetime(value.year, value.month, value.day, tzinfo=_UTC)
        return _shift(dt, tz_offset_hours)

    if isinstance(value, (tuple, list)):
        if len(value) == 2 and epoch in ("ext4", "unix", None):
            return from_ext4(value[0], value[1], tz_offset_hours)
        return None

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if time_format:
            try:
                dt = datetime.datetime.strptime(s, time_format)
            except ValueError:
                return None
            if dt.tzinfo is None:
                return _shift(dt.replace(tzinfo=_UTC), tz_offset_hours)
            return dt.astimezone(_UTC)
        # 纯数字字符串当作时间戳
        if s.lstrip("+-").replace(".", "", 1).isdigit():
            try:
                num = float(s) if "." in s else int(s)
            except ValueError:
                return None
            try:
                return _from_number(num, epoch, tz_offset_hours)
            except (ValueError, OverflowError):
                return None
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = None
        try:
            dt = datetime.datetime.fromisoformat(iso)
        except ValueError:
            for fmt in _TEXT_FORMATS:
                try:
                    dt = datetime.datetime.strptime(s, fmt)
                    break
                except ValueError:
                    continue
        if dt is None:
            return None
        if dt.tzinfo is None:
            return _shift(dt.replace(tzinfo=_UTC), tz_offset_hours)
        return dt.astimezone(_UTC)

    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return _from_number(value, epoch, tz_offset_hours)
        except (ValueError, OverflowError):
            return None
    return None


# ============================================================
# Event
# ============================================================
EVENT_FIELDS = ("ts", "ts_raw", "source", "artifact", "path",
                "inode", "action", "detail", "tz_assumed")


class Event(object):
    """一条时间线事件（数据类）

    ts        —— datetime，UTC 且带时区
    ts_raw    —— 原始时间戳（int 或 str），留作复核
    source    —— 来源模块名，如 'ntfs' / 'hfs' / 'regf' / 'evtx'
    artifact  —— 具体痕迹名，如 'STANDARD_INFORMATION' / 'catalog' / 'LastWriteTime'
    path      —— 文件路径或对象路径
    inode     —— inode / MFT 号 / oid，可为 None
    action    —— create / modify / access / change / delete / execute ...
    detail    —— 附加说明
    tz_assumed—— 时间戳原本无时区（FAT/exFAT），此处为 True
    """

    __slots__ = EVENT_FIELDS

    def __init__(self, ts, ts_raw=None, source="", artifact="", path="",
                 inode=None, action="", detail="", tz_assumed=False):
        if isinstance(ts, datetime.datetime):
            self.ts = ts if ts.tzinfo else ts.replace(tzinfo=_UTC)
            self.ts = self.ts.astimezone(_UTC)
        else:
            dt = coerce_dt(ts, "unix")
            if dt is None:
                raise ValueError("Event.ts 不是可用时间: %r" % (ts,))
            self.ts = dt
        self.ts_raw = ts_raw
        self.source = source or ""
        self.artifact = artifact or ""
        self.path = path or ""
        self.inode = inode
        self.action = (action or "").lower()
        self.detail = detail or ""
        self.tz_assumed = bool(tz_assumed)

    # ---------------- 输出形态 ----------------
    def ts_iso(self, sep="T"):
        """ISO 8601（UTC）。有微秒就带上，便于排序与回读"""
        s = self.ts.strftime("%Y-%m-%d" + sep + "%H:%M:%S")
        if self.ts.microsecond:
            s += ".%06d" % self.ts.microsecond
        return s + "+00:00"

    def ts_epoch(self):
        """Unix 秒（向下取整）"""
        return int(self.ts.timestamp())

    def ts_micro(self):
        """Unix 微秒（去重与排序用的整数键）"""
        return int(round(self.ts.timestamp() * 1000000))

    def key(self):
        """去重键：(ts, source, path, action)"""
        return (self.ts_micro(), self.source, self.path, self.action)

    def as_row(self):
        """CSV 行（None 统一成空串）"""
        return {
            "ts": self.ts.strftime("%Y-%m-%d %H:%M:%S") +
                  (".%06d" % self.ts.microsecond if self.ts.microsecond else ""),
            "ts_raw": "" if self.ts_raw is None else str(self.ts_raw),
            "source": self.source,
            "artifact": self.artifact,
            "path": self.path,
            "inode": "" if self.inode is None else str(self.inode),
            "action": self.action,
            "detail": self.detail,
            "tz_assumed": "1" if self.tz_assumed else "0",
        }

    def to_dict(self):
        """JSON 友好 dict"""
        d = self.as_row()
        d["ts"] = self.ts_iso()
        d["inode"] = self.inode
        d["tz_assumed"] = self.tz_assumed
        return d

    @classmethod
    def from_dict(cls, row):
        """从 dict 还原（ts 支持 ISO / 'YYYY-MM-DD HH:MM:SS'）"""
        ts = coerce_dt(row.get("ts"))
        if ts is None:
            raise ValueError("缺少可用 ts 字段: %r" % (row,))
        ino = row.get("inode")
        if isinstance(ino, str):
            ino = int(ino) if ino.strip().lstrip("+-").isdigit() else (ino or None)
        flag = row.get("tz_assumed")
        if isinstance(flag, str):
            flag = flag.strip().lower() in ("1", "true", "yes", "y")
        return cls(ts, row.get("ts_raw"), row.get("source", ""),
                   row.get("artifact", ""), row.get("path", ""), ino,
                   row.get("action", ""), row.get("detail", ""), bool(flag))

    # ---------------- 比较 ----------------
    def __eq__(self, other):
        if not isinstance(other, Event):
            return NotImplemented
        return all(getattr(self, f) == getattr(other, f) for f in EVENT_FIELDS)

    def __hash__(self):
        return hash(self.key())

    def __lt__(self, other):
        return self.key() < other.key()

    def __repr__(self):
        return "<Event %s %s %s %r %s%s>" % (
            self.ts_iso(sep=" "), self.source, self.action, self.path,
            self.artifact, " tz_assumed" if self.tz_assumed else "")


# ============================================================
# 适配器 1：任意文件系统对象
# ============================================================
# 各模块条目字段 -> 动作。FAT / exFAT 的 ctime 其实是「创建时间」，
# 与 POSIX 的 ctime（inode 变更）不是一回事，必须分开映射。
_FAT_FIELDS = (("ctime", "create"), ("atime", "access"), ("mtime", "modify"))
_GENERIC_FIELDS = (("mtime", "modify"), ("ctime", "change"),
                   ("atime", "access"), ("btime", "create"), ("crtime", "create"))
_FS_FIELD_ACTIONS = {
    "fat": _FAT_FIELDS,
    "exfat": _FAT_FIELDS,
    "hfs": (("create", "create"), ("modify", "modify"),
            ("attr_modify", "change"), ("access", "access"), ("backup", "backup")),
    "xfs": (("mtime", "modify"), ("ctime", "change"), ("atime", "access")),
    "ext4": (("crtime", "create"), ("mtime", "modify"), ("atime", "access"),
             ("ctime", "change"), ("dtime", "delete")),
    "squashfs": (("mtime", "modify"),),
    "romfs": (("mtime", "modify"),),
    "cramfs": (("mtime", "modify"),),
}

_FS_ARTIFACT = {
    "fat": "dirent", "exfat": "dirent", "hfs": "catalog",
    "xfs": "inode", "ext4": "inode", "squashfs": "inode",
    "romfs": "inode", "cramfs": "inode", "ntfs": "STANDARD_INFORMATION",
}

# 无时区语义的模块：DOS 时间只能标注为「假定」
_TZ_ASSUMED_KINDS = ("fat", "exfat")

_INODE_ATTRS = ("inode", "ino", "cnid", "num", "offset", "slot_off")


def _fs_kind(entry):
    """按条目所属模块判断文件系统类型"""
    if hasattr(entry, "si_times"):
        return "ntfs"
    mod = (type(entry).__module__ or "").lower()
    tail = mod.split(".")[-1] if mod else ""
    if tail in _FS_FIELD_ACTIONS or tail == "ntfs":
        return tail
    return "generic"


def _split_walk_item(item):
    """walk() 产出 (path, entry) 或仅 entry 两种形态都接受"""
    if isinstance(item, tuple) and len(item) == 2:
        path, entry = item
        return (path if isinstance(path, str) else str(path)), entry
    entry = item
    path = getattr(entry, "path", None) or getattr(entry, "name", None) or ""
    return str(path), entry


def _entry_inode(entry):
    for name in _INODE_ATTRS:
        v = getattr(entry, name, None)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    return None


def _entry_deleted(entry):
    if getattr(entry, "deleted", False):
        return True
    if getattr(entry, "is_deleted", False):
        return True
    # HFS：rec_off 为 None 表示已从 B 树摘除
    if hasattr(entry, "rec_off") and getattr(entry, "rec_off", 0) is None:
        return True
    return False


def _entry_size(entry):
    v = getattr(entry, "size", None)
    if isinstance(v, int):
        return v
    v = getattr(entry, "real_size", None)
    return v if isinstance(v, int) else None


def _safe_dt(value, epoch, tz):
    try:
        return coerce_dt(value, epoch, tz)
    except (ValueError, OverflowError, TypeError):
        return None


def _ntfs_events(entry, path, kinds, tz, assumed, include_deleted):
    """NTFS MFT 记录：$STANDARD_INFORMATION 的 4 个时间 + $FILE_NAME 的 4 个时间"""
    deleted = _entry_deleted(entry)
    if deleted and not include_deleted:
        return
    ino = _entry_inode(entry)
    size = _entry_size(entry)
    tag = "deleted" if deleted else "in-use"
    detail_base = tag + (" dir" if getattr(entry, "is_dir", False) else "")
    if size is not None:
        detail_base += " %dB" % size

    for attr, action in (("si_ctime", "create"), ("si_mtime", "modify"),
                         ("si_atime", "access"), ("si_etime", "change")):
        if kinds and action not in kinds:
            continue
        raw = getattr(entry, attr, None)
        if raw is None:
            continue
        epoch = "filetime" if isinstance(raw, (int, float)) else "unix"
        ts = _safe_dt(raw, epoch, tz)
        if ts is None:
            continue
        yield Event(ts, raw if not isinstance(raw, datetime.datetime) else raw.isoformat(),
                    "ntfs", "STANDARD_INFORMATION", path, ino, action,
                    detail_base, assumed)

    for fn in getattr(entry, "names", ()) or ():
        ns = getattr(fn, "namespace_name", "")
        for attr, action in (("ctime", "create"), ("mtime", "modify"),
                             ("atime", "access"), ("etime", "change")):
            if kinds and action not in kinds:
                continue
            raw = getattr(fn, attr, None)
            if raw is None:
                continue
            ts = _safe_dt(raw, "filetime" if isinstance(raw, (int, float)) else "unix", tz)
            if ts is None:
                continue
            detail = detail_base + (" ns=%s" % ns if ns else "")
            yield Event(ts, raw if not isinstance(raw, datetime.datetime) else raw.isoformat(),
                        "ntfs", "$FILE_NAME", path, ino, action, detail, assumed)


def _stat_events(entry, path, kind, kinds, tz, include_deleted):
    """通用目录项：按字段名映射动作，值可能是 datetime / 字符串 / int"""
    deleted = _entry_deleted(entry)
    if deleted and not include_deleted:
        return
    fields = _FS_FIELD_ACTIONS.get(kind, _GENERIC_FIELDS)
    artifact = _FS_ARTIFACT.get(kind, "stat")
    ino = _entry_inode(entry)
    size = _entry_size(entry)
    detail_base = ("deleted" if deleted else "in-use")
    if size is not None:
        detail_base += " %dB" % size
    assumed = kind in _TZ_ASSUMED_KINDS and tz is None

    for attr, action in fields:
        if kinds and action not in kinds:
            continue
        raw = getattr(entry, attr, None)
        if raw is None:
            continue
        if isinstance(raw, str):
            ts = parse_dos_string(raw, tz) if kind in _TZ_ASSUMED_KINDS else None
            if ts is None:
                ts = _safe_dt(raw, "unix", tz)
        else:
            ts = _safe_dt(raw, "unix", tz)
        if ts is None:
            continue
        raw_copy = raw if not isinstance(raw, datetime.datetime) else raw.isoformat()
        yield Event(ts, raw_copy, kind, artifact, path, ino, action,
                    detail_base, assumed)


def from_fs(fs, kinds=None, tz_offset_hours=None, include_deleted=True,
            max_entries=200000, walk_kw=None):
    """从任意文件系统对象取时间戳，返回 Event 列表

    参数：
        fs               —— 需有 walk()；条目可以是 (path, entry) 二元组或 entry 本身
        kinds            —— 只取这些动作，如 ("create", "modify")；None 取全部
        tz_offset_hours  —— 无时区字段（FAT/exFAT）的参考时区；给了就折算成 UTC
        include_deleted  —— 是否保留已删除条目
        max_entries      —— 遍历条目上限（防呆）

    兼容：
        · mkit.fat    DirEntry  —— mtime/ctime/atime 均为 'YYYY-MM-DD HH:MM:SS'
        · mkit.exfat  Entry     —— 同上
        · mkit.hfs    HfsEntry  —— create/modify/attr_modify/access/backup
        · mkit.xfs    XfsEntry  —— mtime（walk 里常为 None，会自动回查 inode）
        · mkit.ntfs   MftEntry  —— si_times + names[]（$SI / $FN 两套时间）
        · mkit.ext4   Inode     —— datetime；另含 crtime / dtime
        · 其它模块只要条目带 mtime/ctime/atime/btime 就能用
    """
    if not hasattr(fs, "walk"):
        raise TypeError("该对象没有 walk()，无法遍历: %r" % (fs,))

    kinds_set = None
    if kinds:
        kinds_set = set(k.lower() for k in kinds)
    kw = dict(walk_kw or {})

    out = []
    seen = 0
    for item in fs.walk(**kw):
        seen += 1
        if seen > max_entries:
            break
        try:
            path, entry = _split_walk_item(item)
        except Exception:
            continue
        kind = _fs_kind(entry)

        # XFS 的 walk 只带 inode 号，时间要在 inode 里取
        if kind == "xfs" and getattr(entry, "mtime", None) is None:
            ino = getattr(entry, "inode", None)
            resolver = getattr(fs, "inode", None)
            if ino is not None and callable(resolver):
                try:
                    full = resolver(ino)
                except Exception:
                    full = None
                if full is not None:
                    entry = full
                    path = path or getattr(full, "name", "")

        try:
            if kind == "ntfs":
                events = _ntfs_events(entry, path, kinds_set,
                                      tz_offset_hours, False, include_deleted)
            else:
                events = _stat_events(entry, path, kind, kinds_set,
                                      tz_offset_hours, include_deleted)
            out.extend(events)
        except Exception:
            continue
    return out


# ============================================================
# 适配器 2：注册表 hive
# ============================================================
def from_regf(hive, root=None, max_depth=32, action="modify",
              artifact="LastWriteTime", include_root=True, max_keys=500000):
    """从注册表 hive 取 key 的 LastWriteTime，返回 Event 列表

    参数：
        hive        —— mkit.regf.Hive 实例（有 root()）或 Key 实例；也接受 bytes
        root        —— 起始键路径（反斜杠），None 表示 hive 根
        max_depth   —— 递归深度上限
        include_root—— 是否把起始键本身也算进去

    key 的 LastWriteTime 语义是「该键最后一次被改写」，对应 action='modify'。
    """
    if isinstance(hive, (bytes, bytearray, memoryview)):
        from .regf import Hive as _Hive       # 只在真需要时才导入
        hive = _Hive(bytes(hive))

    if hasattr(hive, "root") and callable(getattr(hive, "root")):
        key = hive.open(root) if root else hive.root()
        if key is None:
            raise KeyError("hive 里找不到键: %r" % (root,))
    elif hasattr(hive, "timestamp"):
        key = hive
    else:
        raise TypeError("既不是 Hive 也不是 Key: %r" % (hive,))

    out = []
    stack = [(key, 0)]
    seen = set()
    visited = 0
    while stack:
        cur, depth = stack.pop()
        visited += 1
        if visited > max_keys:
            break
        off = getattr(cur, "offset", None)
        if off is not None:
            if off in seen:
                continue
            seen.add(off)

        if include_root or depth > 0:
            ts = getattr(cur, "timestamp", None)
            if ts is not None:
                try:
                    dt = coerce_dt(ts, "filetime" if isinstance(ts, (int, float)) else "unix")
                except (ValueError, OverflowError, TypeError):
                    dt = None
                if dt is not None:
                    raw = ts.isoformat() if isinstance(ts, datetime.datetime) else ts
                    out.append(Event(dt, raw, "regf", artifact,
                                     getattr(cur, "path", "") or "",
                                     off, action, "", False))
        if depth >= max_depth:
            continue
        try:
            subs = cur.subkeys()
        except Exception:
            subs = []
        for sk in subs:
            stack.append((sk, depth + 1))
    return out


# ============================================================
# 适配器 3 / 4：CSV 与 JSON
# ============================================================
DEFAULT_COLUMNS = {f: f for f in EVENT_FIELDS}


def _merge_columns(columns):
    cols = dict(DEFAULT_COLUMNS)
    if columns:
        cols.update({k: v for k, v in columns.items() if v})
    return cols


def _row_to_event(row, cols, source_default="", epoch="unix",
                  tz_offset_hours=None, time_format=None):
    """dict 行 -> Event；缺 ts 或无法解析时返回 None"""
    def pick(field):
        name = cols.get(field)
        if not name:
            return None
        v = row.get(name)
        if isinstance(v, str) and not v.strip():
            return None
        return v

    ts = coerce_dt(pick("ts"), epoch, tz_offset_hours, time_format)
    if ts is None:
        return None

    ino = pick("inode")
    if isinstance(ino, str):
        ino = int(ino) if ino.strip().lstrip("+-").isdigit() else (ino or None)

    flag = pick("tz_assumed")
    if isinstance(flag, str):
        flag = flag.strip().lower() in ("1", "true", "yes", "y")
    elif flag is None:
        flag = False

    raw = pick("ts_raw")
    return Event(ts, raw if raw is not None else (pick("ts")),
                 pick("source") or source_default,
                 pick("artifact") or "", pick("path") or "", ino,
                 pick("action") or "", pick("detail") or "", bool(flag))


def from_csv(path, columns=None, encoding="utf-8-sig", delimiter=",",
             source=None, epoch="unix", tz_offset_hours=None,
             time_format=None, limit=None):
    """从已有 CSV 导入事件

    columns —— 列名映射，键取 EVENT_FIELDS 里的字段名，值是 CSV 表头。
               例如 {"ts": "时间", "path": "路径", "action": "动作"}
    encoding—— 默认 utf-8-sig（兼容 Excel 带 BOM 与无 BOM 两种写法）
    """
    cols = _merge_columns(columns)
    out = []
    with open(path, "r", encoding=encoding, newline="") as f:
        for row in csv.DictReader(f, delimiter=delimiter):
            ev = _row_to_event(row, cols, source or "", epoch,
                               tz_offset_hours, time_format)
            if ev is not None:
                out.append(ev)
                if limit and len(out) >= limit:
                    break
    return out


def from_json(path, columns=None, encoding="utf-8", source=None, epoch="unix",
              tz_offset_hours=None, time_format=None, limit=None):
    """从 JSON 导入事件

    支持 JSON Lines（一行一个对象）与单个 JSON 数组两种写法。
    columns 用法同 from_csv。
    """
    cols = _merge_columns(columns)
    with open(path, "r", encoding=encoding) as f:
        text = f.read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(stripped)
    else:
        data = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            data.append(json.loads(line))

    out = []
    for row in data:
        if not isinstance(row, dict):
            continue
        ev = _row_to_event(row, cols, source or "", epoch,
                           tz_offset_hours, time_format)
        if ev is not None:
            out.append(ev)
            if limit and len(out) >= limit:
                break
    return out


# ============================================================
# Timeline
# ============================================================
class Timeline(object):
    """事件聚合器：添加 -> 排序去重 -> 筛选 -> 统计 -> 导出"""

    __slots__ = ("_events", "dedup")

    def __init__(self, events=None, dedup=True):
        self._events = []
        self.dedup = bool(dedup)
        if events:
            self.extend(events)

    # ---------------- 添加 ----------------
    def add(self, event):
        """加一条事件，返回它本身"""
        if not isinstance(event, Event):
            raise TypeError("只接受 Event: %r" % (event,))
        self._events.append(event)
        return event

    def extend(self, events):
        """批量添加（接受列表 / 生成器 / 另一个 Timeline），返回新增条数"""
        if isinstance(events, Timeline):
            events = events.events()
        n = 0
        for ev in events:
            if not isinstance(ev, Event):
                raise TypeError("只接受 Event: %r" % (ev,))
            self._events.append(ev)
            n += 1
        return n

    def clear(self):
        self._events = []

    def __len__(self):
        return len(self._events)

    def __iter__(self):
        return iter(self.events())

    def __repr__(self):
        return "<Timeline %d 条%s>" % (len(self._events),
                                       "" if self.dedup else " 未去重")

    # ---------------- 排序 + 去重 ----------------
    def events(self, dedup=None):
        """按时间排序的事件列表（默认去重，保留最先加入的那条）"""
        use = self.dedup if dedup is None else bool(dedup)
        if use:
            seen = set()
            kept = []
            for ev in self._events:
                k = ev.key()
                if k in seen:
                    continue
                seen.add(k)
                kept.append(ev)
        else:
            kept = list(self._events)
        kept.sort(key=lambda e: e.key())
        return kept

    # ---------------- 筛选 ----------------
    def filter(self, start=None, end=None, source=None, path_contains=None,
               action=None):
        """筛选，返回新 Timeline（区间为闭区间）"""
        t0 = coerce_dt(start) if start is not None else None
        t1 = coerce_dt(end) if end is not None else None
        srcs = None
        if source is not None:
            srcs = set([source] if isinstance(source, str) else list(source))
        acts = None
        if action is not None:
            acts = set([action] if isinstance(action, str) else list(action))
            acts = set(a.lower() for a in acts)
        needle = path_contains.lower() if path_contains else None

        out = Timeline(dedup=self.dedup)
        for ev in self.events():
            if t0 is not None and ev.ts < t0:
                continue
            if t1 is not None and ev.ts > t1:
                continue
            if srcs is not None and ev.source not in srcs:
                continue
            if acts is not None and ev.action not in acts:
                continue
            if needle is not None and needle not in ev.path.lower():
                continue
            out.add(ev)
        return out

    # ---------------- 统计 ----------------
    def stats(self):
        """统计：总数 / 时间跨度 / 按 source / 按 action / 按天"""
        evs = self.events()
        by_source = {}
        by_action = {}
        by_day = {}
        by_artifact = {}
        for ev in evs:
            by_source[ev.source] = by_source.get(ev.source, 0) + 1
            by_action[ev.action] = by_action.get(ev.action, 0) + 1
            by_artifact[ev.artifact] = by_artifact.get(ev.artifact, 0) + 1
            day = ev.ts.strftime("%Y-%m-%d")
            by_day[day] = by_day.get(day, 0) + 1

        span = 0.0
        if len(evs) >= 2:
            span = (evs[-1].ts - evs[0].ts).total_seconds()

        return {
            "total": len(evs),
            "start": evs[0].ts_iso() if evs else None,
            "end": evs[-1].ts_iso() if evs else None,
            "start_epoch": evs[0].ts_epoch() if evs else None,
            "end_epoch": evs[-1].ts_epoch() if evs else None,
            "span_seconds": span,
            "span_hours": round(span / 3600.0, 3),
            "span_days": round(span / 86400.0, 3),
            "by_source": dict(sorted(by_source.items())),
            "by_action": dict(sorted(by_action.items())),
            "by_artifact": dict(sorted(by_artifact.items())),
            "by_day": dict(sorted(by_day.items())),
            "tz_assumed": sum(1 for e in evs if e.tz_assumed),
        }

    def heatmap(self, by="day"):
        """活动热力图数据：[(标签, 计数)]，按标签升序

        by —— day / hour / week / month
        """
        mode = (by or "day").lower()
        if mode not in ("day", "hour", "week", "month"):
            raise ValueError("by 只支持 day / hour / week / month: %r" % (by,))
        buckets = {}
        for ev in self.events():
            if mode == "day":
                label = ev.ts.strftime("%Y-%m-%d")
            elif mode == "hour":
                label = ev.ts.strftime("%Y-%m-%dT%H")
            elif mode == "month":
                label = ev.ts.strftime("%Y-%m")
            else:
                iso = ev.ts.isocalendar()
                label = "%04d-W%02d" % (iso[0], iso[1])
            buckets[label] = buckets.get(label, 0) + 1
        return sorted(buckets.items())

    def gaps(self, min_hours=24):
        """活动空档：相邻事件间隔 >= min_hours 小时即记一条

        取证上用于判断「关机期 / 休眠期 / 数据被清理期」。
        返回 [{"start", "end", "hours", "before", "after", ...}]，按时间升序。
        """
        evs = self.events()
        out = []
        limit = float(min_hours) * 3600.0
        for a, b in zip(evs, evs[1:]):
            delta = (b.ts - a.ts).total_seconds()
            if delta < limit:
                continue
            out.append({
                "start": a.ts_iso(),
                "end": b.ts_iso(),
                "hours": round(delta / 3600.0, 3),
                "days": round(delta / 86400.0, 3),
                "before": a.path,
                "after": b.path,
                "before_source": a.source,
                "after_source": b.source,
            })
        return out

    # ---------------- 导出 ----------------
    def to_csv(self, path, encoding="utf-8-sig"):
        """导出 CSV。默认 utf-8-sig，Excel 直接打开中文不乱码"""
        evs = self.events()
        with open(path, "w", encoding=encoding, newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(EVENT_FIELDS))
            w.writeheader()
            for ev in evs:
                w.writerow(ev.as_row())
        return len(evs)

    def to_jsonl(self, path, encoding="utf-8"):
        """导出 JSON Lines（一行一个事件，ts 为 ISO 8601 +00:00）"""
        evs = self.events()
        with open(path, "w", encoding=encoding, newline="\n") as f:
            for ev in evs:
                f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
        return len(evs)

    def to_sqlite(self, path, table="events"):
        """导出 SQLite：建表 + 索引，便于用 SQL 二次查询"""
        evs = self.events()
        if os.path.exists(path):
            os.remove(path)
        con = sqlite3.connect(path)
        try:
            cur = con.cursor()
            cur.execute(
                "CREATE TABLE %s ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ts TEXT NOT NULL,"          # ISO 8601 UTC
                "ts_epoch INTEGER NOT NULL,"  # Unix 秒
                "ts_us INTEGER NOT NULL,"     # Unix 微秒，排序用
                "ts_raw TEXT,"
                "source TEXT NOT NULL,"
                "artifact TEXT,"
                "path TEXT,"
                "inode INTEGER,"
                "action TEXT,"
                "detail TEXT,"
                "tz_assumed INTEGER)" % table)
            cur.executemany(
                "INSERT INTO %s (ts, ts_epoch, ts_us, ts_raw, source, artifact,"
                " path, inode, action, detail, tz_assumed)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)" % table,
                [(ev.ts_iso(), ev.ts_epoch(), ev.ts_micro(),
                  "" if ev.ts_raw is None else str(ev.ts_raw),
                  ev.source, ev.artifact, ev.path, ev.inode, ev.action,
                  ev.detail, 1 if ev.tz_assumed else 0) for ev in evs])
            cur.execute("CREATE INDEX idx_%s_ts ON %s(ts_us)" % (table, table))
            cur.execute("CREATE INDEX idx_%s_source ON %s(source)" % (table, table))
            cur.execute("CREATE INDEX idx_%s_action ON %s(action)" % (table, table))
            cur.execute("CREATE INDEX idx_%s_path ON %s(path)" % (table, table))
            con.commit()
        finally:
            con.close()
        return len(evs)

    # ---------------- 便捷 ----------------
    def sources(self):
        """出现过的 source 列表"""
        return sorted({ev.source for ev in self.events()})

    def span(self):
        """(最早, 最晚) 事件；(空时间线返回 (None, None))"""
        evs = self.events()
        if not evs:
            return (None, None)
        return (evs[0], evs[-1])


# ============================================================
# 自检
# ============================================================
def _selftest():
    """合成数据自检：时间换算 / 适配器 / 聚合 / 导出回读"""
    import tempfile

    ok = []

    # ---------- 1. 6 种时间戳换算 ----------
    assert from_filetime(0) == datetime.datetime(1601, 1, 1, tzinfo=_UTC)
    assert from_filetime(116444736000000000) == datetime.datetime(1970, 1, 1, tzinfo=_UTC)
    assert from_filetime(132223104000000000) == datetime.datetime(2020, 1, 1, tzinfo=_UTC)
    assert from_filetime(116444736010000000) == \
        datetime.datetime(1970, 1, 1, 0, 0, 1, tzinfo=_UTC)
    # FILETIME 的 100ns 精度：微秒向下取整
    assert from_filetime(116444736000001234) == \
        datetime.datetime(1970, 1, 1, 0, 0, 0, 123, tzinfo=_UTC)
    ok.append("FILETIME")

    assert from_unix(0) == datetime.datetime(1970, 1, 1, tzinfo=_UTC)
    assert from_unix(1577836800) == datetime.datetime(2020, 1, 1, tzinfo=_UTC)
    assert from_unix(-86400) == datetime.datetime(1969, 12, 31, tzinfo=_UTC)
    # 时区偏移：墙钟 08:00 +08 -> 00:00 UTC
    assert from_unix(1577836800, tz_offset_hours=8) == \
        datetime.datetime(2019, 12, 31, 16, 0, tzinfo=_UTC)
    ok.append("Unix")

    assert from_hfs(2082844800) == datetime.datetime(1970, 1, 1, tzinfo=_UTC)
    assert from_hfs(3660681600) == datetime.datetime(2020, 1, 1, tzinfo=_UTC)
    assert from_hfs(0) == datetime.datetime(1904, 1, 1, tzinfo=_UTC)
    ok.append("HFS")

    assert from_apfs_ns(1577836800 * 10 ** 9) == \
        datetime.datetime(2020, 1, 1, tzinfo=_UTC)
    assert from_apfs_ns(1577836800123456789) == \
        datetime.datetime(2020, 1, 1, 0, 0, 0, 123456, tzinfo=_UTC)
    ok.append("APFS ns")

    # 2020-01-01 12:34:56 的 DOS 字：date=20513 time=25692
    fat_dt, fat_assumed = from_fat(20513, 25692, with_flag=True)
    assert fat_dt == datetime.datetime(2020, 1, 1, 12, 34, 56, tzinfo=_UTC)
    assert fat_assumed is True
    # 2 秒精度：秒位只能是偶数
    assert from_fat(20513, 25692).second % 2 == 0
    # 32 位打包形态
    assert from_fat((20513 << 16) | 25692) == fat_dt
    # 给了时区就不再是「假定」
    _, assumed_cn = from_fat(20513, 25692, tz_offset_hours=8, with_flag=True)
    assert assumed_cn is False
    assert from_fat(20513, 25692, tz_offset_hours=8) == \
        datetime.datetime(2020, 1, 1, 4, 34, 56, tzinfo=_UTC)
    ok.append("FAT (tz_assumed=True)")

    assert from_ext4(1577836800, 0) == datetime.datetime(2020, 1, 1, tzinfo=_UTC)
    assert from_ext4(1577836800, 999999999) == \
        datetime.datetime(2020, 1, 1, 0, 0, 0, 999999, tzinfo=_UTC)
    assert from_ext4(1577836800, 500000000).microsecond == 500000
    ok.append("ext4 (sec+nsec)")

    # 越界与非法输入必须拒绝，不能静默给出假时间
    for bad in (lambda: from_fat(0, 0), lambda: from_ext4(0, 10 ** 9),
                lambda: from_filetime("x")):
        try:
            bad()
        except ValueError:
            pass
        else:
            raise AssertionError("非法时间戳未被拒绝")
    ok.append("非法输入拒绝")

    # ---------- 2. from_fs ----------
    class _FakeFatEntry(object):
        __module__ = "mkit.fat"
        __slots__ = ("name", "size", "mtime", "ctime", "atime", "deleted", "is_dir")

        def __init__(self, **kw):
            for k in self.__slots__:
                setattr(self, k, kw.get(k))

    class _FakeXfsEntry(object):
        __module__ = "mkit.xfs"
        __slots__ = ("name", "inode", "size", "mtime", "deleted", "is_dir")

        def __init__(self, **kw):
            for k in self.__slots__:
                setattr(self, k, kw.get(k))

    class _FakeFs(object):
        def __init__(self, items):
            self.items = items

        def walk(self):
            for p, e in self.items:
                yield p, e

    fs = _FakeFs([
        ("/DOC/报告.txt", _FakeFatEntry(
            name="报告.txt", size=1024, is_dir=False, deleted=False,
            mtime="2020-01-02 03:04:05", ctime="2020-01-01 00:00:00", atime=None)),
        ("/DOC/old.log", _FakeFatEntry(
            name="old.log", size=64, is_dir=False, deleted=True,
            mtime="2020-01-03 00:00:00", ctime=None, atime=None)),
        ("/xfs/a.bin", _FakeXfsEntry(
            name="a.bin", inode=77, size=8, mtime=1577836800, deleted=False, is_dir=False)),
    ])
    fs_events = from_fs(fs)
    # FAT: ctime->create, mtime->modify；已删除条目默认保留（deleted 标在 detail）
    assert len(fs_events) == 4, [e.action for e in fs_events]
    actions = sorted(e.action for e in fs_events)
    assert actions == ["create", "modify", "modify", "modify"], actions
    fat_c = [e for e in fs_events if e.source == "fat" and e.action == "create"]
    assert len(fat_c) == 1
    assert fat_c[0].ts == datetime.datetime(2020, 1, 1, tzinfo=_UTC)
    assert fat_c[0].tz_assumed is True            # FAT 无时区，必须标注
    assert fat_c[0].inode is None
    assert fat_c[0].artifact == "dirent"
    assert "1024B" in fat_c[0].detail
    assert any("deleted" in e.detail for e in fs_events)
    assert len(from_fs(fs, kinds=("create",))) == 1
    assert len(from_fs(fs, include_deleted=False)) == 3
    # 给了时区偏移，FAT 时间整体前移 8 小时
    shifted = from_fs(fs, kinds=("create",), tz_offset_hours=8)
    assert shifted[0].ts == datetime.datetime(2019, 12, 31, 16, 0, tzinfo=_UTC)
    assert shifted[0].tz_assumed is False
    ok.append("from_fs (FAT/XFS/时区/kinds/已删除)")

    # ---------- 3. from_regf ----------
    class _FakeKey(object):
        __slots__ = ("name", "_parent", "offset", "timestamp", "_subs")

        def __init__(self, name, offset, ts, parent=None):
            self.name = name
            self._parent = parent
            self.offset = offset
            self.timestamp = ts
            self._subs = []

        @property
        def path(self):
            return (self._parent.path + "\\" + self.name) if self._parent else self.name

        def subkeys(self):
            return list(self._subs)

    class _FakeHive(object):
        def __init__(self, root):
            self._root = root

        def root(self):
            return self._root

    hk = _FakeKey("ROOT", 0x20, datetime.datetime(2020, 6, 1, tzinfo=_UTC))
    run = _FakeKey("Run", 0x40, datetime.datetime(2020, 6, 2, 5, tzinfo=_UTC), hk)
    mu = _FakeKey("Mu", 0x60, datetime.datetime(2020, 6, 2, 6, tzinfo=_UTC), hk)
    empty = _FakeKey("NoTime", 0x80, None, hk)
    hk._subs = [run, mu, empty]
    reg_events = from_regf(_FakeHive(hk))
    assert len(reg_events) == 3, len(reg_events)      # NoTime 无时间 -> 跳过
    assert reg_events[0].source == "regf"
    assert reg_events[0].artifact == "LastWriteTime"
    assert reg_events[0].action == "modify"
    assert any(e.path == "ROOT\\Run" for e in reg_events)
    assert len(from_regf(hk, include_root=False)) == 2
    assert from_regf(hk, max_depth=0)[0].path == "ROOT"
    ok.append("from_regf (LastWriteTime/深度/无时间跳过)")

    # ---------- 4. Timeline：排序 / 去重 / filter / stats / heatmap / gaps ----------
    base = 1577836800
    tl = Timeline()
    tl.add(Event(from_unix(base), base, "ntfs", "STANDARD_INFORMATION",
                 "/a.txt", 42, "create", "in-use 10B"))
    tl.add(Event(from_unix(base), base, "ntfs", "STANDARD_INFORMATION",
                 "/a.txt", 42, "create", "in-use 10B"))       # 完全重复
    tl.add(Event(from_unix(base + 3600), base + 3600, "ntfs", "$FILE_NAME",
                 "/b.txt", 43, "modify", "ns=Win32"))
    tl.add(Event(from_unix(base + 3 * 86400), base + 3 * 86400, "regf",
                 "LastWriteTime", "HKLM\\SOFTWARE", None, "modify", ""))
    tl.add(Event(from_unix(base + 3 * 86400 + 60), base + 3 * 86400 + 60, "evtx",
                 "EventRecordID", "Security.evtx", None, "logon", "4624"))

    evs = tl.events()
    assert len(evs) == 4, len(evs)                     # 去重掉 1 条
    assert len(tl.events(dedup=False)) == 5
    assert len(Timeline(tl.events(), dedup=False).events()) == 4  # events() 已去重
    assert [e.action for e in evs] == ["create", "modify", "modify", "logon"]
    assert evs[0].ts <= evs[-1].ts
    assert evs[0].path == "/a.txt"
    assert len(tl) == 5
    assert tl.sources() == ["evtx", "ntfs", "regf"]

    assert len(tl.filter(source="ntfs").events()) == 2
    assert len(tl.filter(source=["regf", "evtx"]).events()) == 2
    assert len(tl.filter(action="create").events()) == 1
    assert len(tl.filter(path_contains="B.TXT").events()) == 1     # 大小写不敏感
    assert len(tl.filter(start=from_unix(base + 7200)).events()) == 2
    assert len(tl.filter(end=from_unix(base + 3600)).events()) == 2
    assert len(tl.filter(start=from_unix(base), end=from_unix(base + 3600)).events()) == 2
    assert len(tl.filter(path_contains="不存在").events()) == 0

    st = tl.stats()
    assert st["total"] == 4
    assert st["by_source"] == {"evtx": 1, "ntfs": 2, "regf": 1}, st["by_source"]
    assert st["by_action"] == {"create": 1, "logon": 1, "modify": 2}, st["by_action"]
    assert st["by_day"] == {"2020-01-01": 2, "2020-01-04": 2}, st["by_day"]
    # 跨度为 3 天 + 60 秒（最后一条比整 3 天晚 1 分钟）
    assert abs(st["span_hours"] - 72.0167) < 0.01, st["span_hours"]
    assert abs(st["span_days"] - 3.0007) < 0.01, st["span_days"]
    assert st["start"].startswith("2020-01-01T00:00:00")
    assert st["end"].startswith("2020-01-04T00:01:00")
    assert st["tz_assumed"] == 0

    hm = tl.heatmap()
    assert hm == [("2020-01-01", 2), ("2020-01-04", 2)], hm
    assert len(tl.heatmap("hour")) == 3
    assert tl.heatmap("month") == [("2020-01", 4)]
    assert tl.heatmap("week")[0][0].startswith("2020-W")
    try:
        tl.heatmap("year")
    except ValueError:
        pass
    else:
        raise AssertionError("heatmap 未拒绝非法 by")

    gp = tl.gaps(min_hours=24)
    assert len(gp) == 1, gp
    assert gp[0]["hours"] == 71.0, gp[0]["hours"]     # 3d - 1h
    assert gp[0]["before"] == "/b.txt"
    assert gp[0]["after"] == "HKLM\\SOFTWARE"
    assert tl.gaps(min_hours=100) == []
    assert Timeline().gaps() == []
    ok.append("Timeline 排序/去重/filter/stats/heatmap/gaps")

    # ---------- 5. 导出落盘 + 回读 ----------
    tmp = tempfile.mkdtemp(prefix="esk_tl_")
    try:
        csv_path = os.path.join(tmp, "timeline.csv")
        jsonl_path = os.path.join(tmp, "timeline.jsonl")
        db_path = os.path.join(tmp, "timeline.db")

        assert tl.to_csv(csv_path) == 4
        # BOM 必须存在（Excel 中文不乱码）
        with open(csv_path, "rb") as f:
            head_bytes = f.read(3)
        assert head_bytes == b"\xef\xbb\xbf", head_bytes
        with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 4
        assert list(rows[0].keys()) == list(EVENT_FIELDS)
        assert rows[0]["ts"] == "2020-01-01 00:00:00"
        assert rows[0]["source"] == "ntfs"
        assert rows[0]["inode"] == "42"

        back = from_csv(csv_path)
        assert len(back) == 4, len(back)
        assert back[0].ts == tl.events()[0].ts
        assert back[0].ts_raw == str(base)
        assert back[0].inode == 42 and isinstance(back[0].inode, int)
        assert back[0].action == "create"
        assert [e.ts for e in back] == [e.ts for e in tl.events()]

        assert tl.to_jsonl(jsonl_path) == 4
        with open(jsonl_path, "r", encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        assert len(lines) == 4
        assert json.loads(lines[0])["source"] == "ntfs"
        back2 = from_json(jsonl_path)
        assert len(back2) == 4
        assert back2[0].ts == back[0].ts
        assert back2[0].path == "/a.txt"

        assert tl.to_sqlite(db_path) == 4
        con = sqlite3.connect(db_path)
        try:
            cur = con.cursor()
            cur.execute("SELECT COUNT(*) FROM events")
            assert cur.fetchone()[0] == 4
            cur.execute("SELECT ts, source, action FROM events ORDER BY ts_us LIMIT 1")
            first = cur.fetchone()
            assert first == ("2020-01-01T00:00:00+00:00", "ntfs", "create"), first
            cur.execute("SELECT COUNT(*) FROM events WHERE action = ?", ("modify",))
            assert cur.fetchone()[0] == 2
            cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
            idx = {r[0] for r in cur.fetchall()}
            for want in ("idx_events_ts", "idx_events_source",
                         "idx_events_action", "idx_events_path"):
                assert want in idx, (want, idx)
        finally:
            con.close()
        ok.append("导出 CSV(utf-8-sig)/JSONL/SQLite + 回读")

        # ---------- 6. 自定义列名（中文表头）导入 ----------
        z_path = os.path.join(tmp, "中文列.csv")
        with open(z_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["时间", "来源", "痕迹", "路径", "动作", "说明"])
            w.writerow(["2020-05-01 08:00:00", "hfs", "catalog",
                        "/用户/桌面/笔记.txt", "create", "中文路径"])
        z = from_csv(z_path, columns={
            "ts": "时间", "source": "来源", "artifact": "痕迹",
            "path": "路径", "action": "动作", "detail": "说明"})
        assert len(z) == 1, z
        assert z[0].ts == datetime.datetime(2020, 5, 1, 8, tzinfo=_UTC)
        assert z[0].source == "hfs"
        assert z[0].path == "/用户/桌面/笔记.txt"
        assert z[0].detail == "中文路径"
        ok.append("from_csv 自定义列名（中文表头 / BOM）")

        # ---------- 7. 全链路：from_fs -> Timeline -> CSV ----------
        chain = Timeline(from_fs(fs, include_deleted=False)
                         + from_regf(_FakeHive(hk))
                         + from_csv(csv_path))
        assert len(chain) == 3 + 3 + 4
        assert len(chain.events()) == 10
        c_path = os.path.join(tmp, "chain.csv")
        assert chain.to_csv(c_path) == 10
        assert len(from_csv(c_path)) == 10
        assert chain.stats()["by_source"]["ntfs"] == 2
        ok.append("全链路 from_fs+from_regf+from_csv -> Timeline -> CSV")
    finally:
        for name in os.listdir(tmp):
            try:
                os.remove(os.path.join(tmp, name))
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass

    print("时间戳换算：")
    print("  FILETIME 116444736000000000 ->", from_filetime(116444736000000000).isoformat())
    print("  Unix     1577836800          ->", from_unix(1577836800).isoformat())
    print("  HFS      3660681600          ->", from_hfs(3660681600).isoformat())
    print("  APFS ns  1577836800123456789 ->", from_apfs_ns(1577836800123456789).isoformat())
    print("  FAT      0x5021/0x645C       ->", from_fat(20513, 25692).isoformat(),
          "(tz_assumed)")
    print("  ext4     1577836800+999999999->", from_ext4(1577836800, 999999999).isoformat())
    print("  UTC+8 墙钟 1577836800        ->",
          from_unix(1577836800, tz_offset_hours=8).isoformat())
    print("自检项：", " / ".join(ok))
    print("Timeline：%d 条（去重后 %d），跨度 %.1f 小时，%d 个空档"
          % (len(tl), len(tl.events()), st["span_hours"], len(gp)))
    print("全部自检通过：%d/%d" % (len(ok), len(ok)))


if __name__ == "__main__":
    _selftest()
