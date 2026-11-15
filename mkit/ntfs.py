# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""NTFS 解析器 —— 纯 Python 标准库实现（struct / datetime），零第三方依赖。

只依赖 SubImage 的两个接口：read(offset, size) -> bytes、size。
不 import 任何第三方库（pytsk3 / dissect / Registry 均不涉及）。

已实现：
  * 引导扇区解析（含备份引导扇区回退、负值簇数约定）
  * MFT 记录解析：'FILE'/'BAAD' 签名、upd_seq/usa fixup、属性链、0xFFFFFFFF 终止
  * 常驻 / 非常驻属性，runlist（负 delta、稀疏 hole 补零），多 extent 合并
  * $STANDARD_INFORMATION(0x10) / $FILE_NAME(0x30) 多命名空间（POSIX/Win32/DOS）
  * 目录枚举：$INDEX_ROOT(0x90) + $INDEX_ALLOCATION(0xA0) + $BITMAP(0xB0)，
    INDX 记录 fixup、索引项 0x10 key、子树 BFS、已删除条目（in_use=0 / 序列号失配）
  * 索引不可用时退化为全 MFT 扫描 parent_ref 反查
  * 大小写不敏感路径解析（优先使用卷内 $UpCase 表），'\\' 与 '/' 均可
  * FILETIME(1601 UTC, 100ns) -> datetime(UTC)
  * 压缩 / 加密只做标记，read_file 遇到时抛清晰异常
"""

import re
import struct
from datetime import datetime, timedelta, timezone
from collections import OrderedDict

__all__ = [
    "NTFS", "MftEntry", "Attr", "FileName", "NTFSError", "NTFSUnsupported",
    "ATTR_TYPE_NAMES", "NAMESPACE_NAMES",
]

FILE_REF_MASK = 0x0000FFFFFFFFFFFF
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_EA_INFORMATION = 0xD0
ATTR_EA = 0xE0
ATTR_LOGGED_UTILITY_STREAM = 0x100

ATTR_TYPE_NAMES = {
    0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID", 0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION", 0x80: "$DATA", 0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION", 0xE0: "$EA", 0x100: "$LOGGED_UTILITY_STREAM",
}

NAMESPACE_NAMES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}

# 属性 flags
ATTR_FLAG_COMPRESSED = 0x0001
ATTR_FLAG_ENCRYPTED = 0x4000
ATTR_FLAG_SPARSE = 0x8000

# 文件记录 flags
RECORD_IN_USE = 0x0001
RECORD_IS_DIR = 0x0002

# 索引项 flags
INDEX_ENTRY_HAS_SUBNODE = 0x0001
INDEX_ENTRY_LAST = 0x0002

_MFT_RECORD_READY = object()


class NTFSError(Exception):
    """NTFS 结构错误。"""


class NTFSUnsupported(NTFSError):
    """结构可识别但本实现不解码（压缩 / 加密）。"""


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def filetime_to_datetime(value):
    """NTFS FILETIME（100ns since 1601-01-01 UTC）-> 带时区 datetime。"""
    if not value:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None


def parse_runlist(data, base_vcn=0):
    """解析 runlist，返回 [[vcn, lcn|None, 簇数], ...]。

    offset 字段为有符号小端（相对上一个 LCN 的增量，可为负）；
    长度字段存在而 offset 字段缺失表示稀疏区间（hole）。
    """
    runs = []
    i = 0
    lcn = 0
    vcn = base_vcn
    n = len(data)
    while i < n:
        header = data[i]
        if header == 0:
            break
        length_size = header & 0x0F
        offset_size = header >> 4
        if length_size == 0 or length_size > 8 or offset_size > 8:
            break
        end = i + 1 + length_size + offset_size
        if end > n:
            break
        length = int.from_bytes(data[i + 1:i + 1 + length_size], "little")
        if length == 0:
            break
        if offset_size:
            delta = int.from_bytes(data[i + 1 + length_size:end], "little", signed=True)
            lcn += delta
            runs.append([vcn, lcn, length])
        else:
            runs.append([vcn, None, length])
        vcn += length
        i = end
    return runs


class FileName:
    """一个 $FILE_NAME(0x30) 属性值。"""

    __slots__ = ("parent_ref", "parent_num", "ctime", "atime", "mtime", "etime",
                 "alloc_size", "real_size", "flags", "reparse", "name", "namespace")

    def __init__(self, parent_ref, ctime, atime, mtime, etime,
                 alloc_size, real_size, flags, reparse, name, namespace):
        self.parent_ref = parent_ref
        self.parent_num = parent_ref & FILE_REF_MASK
        self.ctime = ctime
        self.atime = atime
        self.mtime = mtime
        self.etime = etime
        self.alloc_size = alloc_size
        self.real_size = real_size
        self.flags = flags
        self.reparse = reparse
        self.name = name
        self.namespace = namespace

    @property
    def is_dir(self):
        return bool(self.flags & 0x10000000)

    @property
    def namespace_name(self):
        return NAMESPACE_NAMES.get(self.namespace, str(self.namespace))

    def __repr__(self):
        return "<FileName %r ns=%s parent=%d>" % (self.name, self.namespace_name,
                                                  self.parent_num)


class Attr:
    """一个 MFT 属性（常驻或非常驻）。"""

    __slots__ = ("fs", "type", "non_resident", "name", "flags", "attr_id", "value",
                 "runs", "start_vcn", "last_vcn", "alloc_size", "real_size",
                 "init_size", "comp_unit", "record_offset", "length")

    def __init__(self, fs):
        self.fs = fs
        self.type = 0
        self.non_resident = 0
        self.name = ""
        self.flags = 0
        self.attr_id = 0
        self.value = b""
        self.runs = []
        self.start_vcn = 0
        self.last_vcn = 0
        self.alloc_size = 0
        self.real_size = 0
        self.init_size = 0
        self.comp_unit = 0
        self.record_offset = 0
        self.length = 0

    @property
    def type_name(self):
        return ATTR_TYPE_NAMES.get(self.type, "0x%x" % self.type)

    @property
    def compressed(self):
        return bool(self.flags & ATTR_FLAG_COMPRESSED)

    @property
    def encrypted(self):
        return bool(self.flags & ATTR_FLAG_ENCRYPTED)

    @property
    def sparse(self):
        return bool(self.flags & ATTR_FLAG_SPARSE)

    def read(self, offset=0, size=None):
        if size is None:
            size = (self.real_size if self.non_resident else len(self.value)) - offset
        if not self.non_resident:
            return self.value[offset:offset + size]
        return self.fs.read_runs(self.runs, offset, size)

    def __repr__(self):
        kind = "NR" if self.non_resident else "R"
        return "<Attr %s %s%s size=%d>" % (self.type_name, kind,
                                           ("/" + self.name) if self.name else "",
                                           self.real_size)


class MftEntry:
    """一条 MFT 记录（或由目录索引项还原出的“记录视图”）。"""

    def __init__(self, fs, num):
        self.fs = fs
        self.num = num
        self.sequence = 0
        self.in_use = False
        self.is_dir = False
        self.base_ref = 0
        self.link_count = 0
        self.flags = 0
        self.attrs = {}          # attr_type -> [Attr, ...]
        self.names = []          # [FileName, ...]（按索引顺序）
        self.record = b""
        self.valid = False
        self.si_times = (None, None, None, None)
        self._name_override = None
        self._light_sizes = (0, 0)
        self.from_index = False

    # ---------------- 基本属性 ----------------
    @property
    def is_deleted(self):
        return not self.in_use

    @property
    def parent_ref(self):
        fn = self._preferred_name()
        if fn is not None:
            return fn.parent_ref
        return 0

    @property
    def parent_num(self):
        return self.parent_ref & FILE_REF_MASK

    @property
    def name(self):
        if self._name_override is not None:
            return self._name_override
        fn = self._preferred_name()
        if fn is not None:
            return fn.name
        return ""

    @property
    def name_space(self):
        fn = self._preferred_name()
        return fn.namespace if fn is not None else 2

    @property
    def is_reparse(self):
        return ATTR_REPARSE_POINT in self.attrs

    def _preferred_name(self):
        if not self.names:
            return None
        for want in (1, 0, 3, 2):
            for fn in self.names:
                if fn.namespace == want:
                    return fn
        return self.names[0]

    @property
    def size(self):
        data = self._unnamed_data
        if data is not None:
            return data.real_size
        fn = self._preferred_name()
        if fn is not None:
            return fn.real_size
        return self._light_sizes[0]

    @property
    def alloc_size(self):
        data = self._unnamed_data
        if data is not None:
            return data.alloc_size
        fn = self._preferred_name()
        if fn is not None:
            return fn.alloc_size
        return self._light_sizes[1]

    @property
    def _unnamed_data(self):
        for a in self.attrs.get(ATTR_DATA, ()):
            if not a.name:
                return a
        return None

    # ---------------- 时间戳 ----------------
    @property
    def si_ctime(self):
        return self.si_times[0]

    @property
    def si_atime(self):
        return self.si_times[1]

    @property
    def si_mtime(self):
        return self.si_times[2]

    @property
    def si_etime(self):
        return self.si_times[3]

    @property
    def fn_ctime(self):
        fn = self._preferred_name()
        return fn.ctime if fn is not None else None

    @property
    def fn_atime(self):
        fn = self._preferred_name()
        return fn.atime if fn is not None else None

    @property
    def fn_mtime(self):
        fn = self._preferred_name()
        return fn.mtime if fn is not None else None

    @property
    def fn_etime(self):
        fn = self._preferred_name()
        return fn.etime if fn is not None else None

    # ---------------- 数据 ----------------
    def read_data(self, ads=None):
        """读取未命名数据流或指定 ADS（如 'Zone.Identifier'）。"""
        return self.fs.read_entry_data(self, ads)

    def attr_list(self, attr_type):
        return list(self.attrs.get(attr_type, ()))

    def __repr__(self):
        state = "in-use" if self.in_use else "deleted"
        kind = "dir" if self.is_dir else "file"
        return "<MftEntry #%d %s %s %r size=%d>" % (self.num, state, kind,
                                                    self.name, self.size)


# --------------------------------------------------------------------------
# NTFS 卷
# --------------------------------------------------------------------------
class NTFS:
    def __init__(self, sub, label=""):
        self.sub = sub
        self.label = label
        self._rec_cache = OrderedDict()
        self._rec_cache_max = 60000
        self._upcase = None
        self._upcase_loaded = False
        self._index_cache = {}
        self._ls_cache = {}

        self.boot = self._read_boot()
        self._parse_boot(self.boot)
        self._mft_runs = []
        self.mft_size = 0
        self.record_count = 0
        self.mft_source = ""
        self._load_mft()
        self.volume_label = self._read_volume_label()

    # ---------------- 引导扇区 ----------------
    def _read_boot(self):
        boot = self.sub.read(0, 512)
        if len(boot) == 512 and boot[3:11] == b"NTFS    ":
            return boot
        # 备份引导扇区（卷尾）回退
        if self.sub.size > 1024:
            for off in (self.sub.size - 512,):
                alt = self.sub.read(off, 512)
                if len(alt) == 512 and alt[3:11] == b"NTFS    ":
                    return alt
        if len(boot) < 512:
            raise NTFSError("引导扇区读取不足 512 字节")
        raise NTFSError("不是 NTFS 卷（OEM 标识 = %r）" % (boot[3:11],))

    def _parse_boot(self, boot):
        self.bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0]
        if self.bytes_per_sector not in (256, 512, 1024, 2048, 4096):
            self.bytes_per_sector = 512

        spc = boot[0x0D]
        if spc > 0x80:                      # 负值约定：2^(256-n)
            spc = 1 << (256 - spc)
        if spc == 0:
            spc = 1
        self.sectors_per_cluster = spc
        self.cluster_size = self.bytes_per_sector * spc

        self.total_sectors = struct.unpack_from("<Q", boot, 0x28)[0]
        max_sectors = self.sub.size // self.bytes_per_sector
        if self.total_sectors == 0 or self.total_sectors > max_sectors * 2:
            alt = struct.unpack_from("<I", boot, 0x28)[0]
            self.total_sectors = alt if alt else max_sectors

        self.mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
        self.mftmirr_lcn = struct.unpack_from("<Q", boot, 0x38)[0]
        self.mft_offset = self.mft_lcn * self.cluster_size

        cpr_mft = struct.unpack_from("<b", boot, 0x40)[0]
        self.clusters_per_mft_record = cpr_mft
        if cpr_mft < 0:
            self.mft_record_size = 1 << (-cpr_mft)
        else:
            self.mft_record_size = cpr_mft * self.cluster_size

        cpr_idx = struct.unpack_from("<b", boot, 0x44)[0]
        self.clusters_per_index_buffer = cpr_idx
        if cpr_idx < 0:
            self.index_record_size = 1 << (-cpr_idx)
        elif cpr_idx:
            self.index_record_size = cpr_idx * self.cluster_size
        else:
            self.index_record_size = self.cluster_size

        self.volume_serial = struct.unpack_from("<Q", boot, 0x48)[0]
        self.checksum = struct.unpack_from("<I", boot, 0x50)[0]

        if not 1 <= self.mft_record_size <= 65536:
            raise NTFSError("非法 MFT 记录大小 %d" % self.mft_record_size)

    # ---------------- MFT ----------------
    def _mft_candidates(self):
        """当前引导扇区参数下的 $MFT 候选位置：主位置、$MFTMirr。"""
        cands = [("主 $MFT", self.mft_offset)]
        if self.mftmirr_lcn:
            cands.append(("$MFTMirr", self.mftmirr_lcn * self.cluster_size))
        return cands

    def _try_mft_at(self, offset):
        """在 offset 处读记录 0，成功则装配 $MFT 布局并返回 True。"""
        rec0 = self._parse_record(self.sub.read(offset, self.mft_record_size), 0)
        if not rec0.valid:
            return False, "记录 0 处无 'FILE' 签名（offset=0x%x）" % offset
        data_attrs = [a for a in rec0.attrs.get(ATTR_DATA, ()) if not a.name]
        if not data_attrs:
            return False, "记录 0 缺少未命名 $DATA 属性（offset=0x%x）" % offset
        attr = data_attrs[0]
        if not attr.non_resident or not attr.runs:
            return False, "记录 0 的 $DATA 不是有效非常驻属性（offset=0x%x）" % offset
        self._mft_runs = [list(r) for r in attr.runs]
        self.mft_size = (attr.real_size
                         or sum(r[2] for r in attr.runs) * self.cluster_size)
        self.record_count = self.mft_size // self.mft_record_size
        self.mft_offset = offset
        self._rec_cache[0] = rec0
        return True, ""

    def _load_mft(self):
        """定位 $MFT。失败时回退到 $MFTMirr，再回退到卷尾备份引导扇区。"""
        last_err = ""
        for where, offset in self._mft_candidates():
            ok, err = self._try_mft_at(offset)
            if ok:
                self.mft_source = where
                return
            last_err = "%s: %s" % (where, err)
        # 主引导扇区不可信时，尝试卷尾备份引导扇区
        if self.sub.size > 1024:
            backup = self.sub.read(self.sub.size - 512, 512)
            if (len(backup) == 512 and backup[3:11] == b"NTFS    "
                    and backup != self.boot):
                saved = self._boot_snapshot()
                try:
                    self._parse_boot(backup)
                except NTFSError:
                    self._boot_restore(saved)
                else:
                    for where, offset in self._mft_candidates():
                        ok, err = self._try_mft_at(offset)
                        if ok:
                            self.boot = backup
                            self.mft_source = "备份引导扇区/" + where
                            return
                        last_err = "备份引导扇区/%s: %s" % (where, err)
                    self._boot_restore(saved)
        raise NTFSError("无法定位有效 $MFT（%s）" % last_err)

    _BOOT_FIELDS = (
        "bytes_per_sector", "sectors_per_cluster", "cluster_size", "total_sectors",
        "mft_lcn", "mftmirr_lcn", "mft_offset", "clusters_per_mft_record",
        "mft_record_size", "clusters_per_index_buffer", "index_record_size",
        "volume_serial", "checksum",
    )

    def _boot_snapshot(self):
        return {name: getattr(self, name, None) for name in self._BOOT_FIELDS}

    def _boot_restore(self, saved):
        for name, value in saved.items():
            setattr(self, name, value)

    def read_runs(self, runs, offset, size):
        """按 runlist 读取数据流（offset/size 相对流起始）。稀疏区填 0。"""
        if size <= 0:
            return b""
        cs = self.cluster_size
        out = bytearray()
        end = offset + size
        for vcn, lcn, cnt in runs:
            run_start = vcn * cs
            run_end = run_start + cnt * cs
            if run_end <= offset or run_start >= end:
                continue
            s = max(offset, run_start)
            e = min(end, run_end)
            if len(out) < s - offset:
                out.extend(b"\x00" * (s - offset - len(out)))
            if lcn is None:
                out.extend(b"\x00" * (e - s))
                continue
            pos = lcn * cs + (s - run_start)
            left = e - s
            while left > 0:
                take = min(left, 4 << 20)
                blob = self.sub.read(pos, take)
                if len(blob) < take:
                    blob = blob + b"\x00" * (take - len(blob))
                out.extend(blob)
                pos += take
                left -= take
        if len(out) < size:
            out.extend(b"\x00" * (size - len(out)))
        return bytes(out[:size])

    def _iter_raw_records(self, chunk=256):
        """按 256 条一批读取 MFT 原始数据，减少底层随机读次数。"""
        rsize = self.mft_record_size
        total = self.record_count
        num = 0
        while num < total:
            cnt = min(chunk, total - num)
            blob = self.read_runs(self._mft_runs, num * rsize, cnt * rsize)
            for i in range(cnt):
                yield num + i, blob[i * rsize:(i + 1) * rsize]
            num += cnt

    # ---------------- 记录解析 ----------------
    def _apply_fixup(self, raw):
        if len(raw) < 48:
            return raw
        usa_off, usa_cnt = struct.unpack_from("<HH", raw, 4)
        if usa_cnt < 2 or usa_off + usa_cnt * 2 > len(raw):
            return raw
        usa = raw[usa_off:usa_off + usa_cnt * 2]
        for i in range(1, usa_cnt):
            pos = i * self.bytes_per_sector - 2
            if pos + 2 <= len(raw):
                raw[pos:pos + 2] = usa[2 * i:2 * i + 2]
        return raw

    def _parse_record(self, buf, num):
        ent = MftEntry(self, num)
        ent.from_index = False
        if not buf or len(buf) < 48:
            return ent
        magic = buf[:4]
        if magic == b"BAAD":
            return ent
        if magic != b"FILE":
            return ent
        raw = bytearray(buf)
        raw = self._apply_fixup(raw)
        ent.valid = True
        ent.record = bytes(raw)
        ent.sequence = struct.unpack_from("<H", raw, 16)[0]
        ent.link_count = struct.unpack_from("<H", raw, 18)[0]
        attr_off = struct.unpack_from("<H", raw, 20)[0]
        ent.flags = struct.unpack_from("<H", raw, 22)[0]
        used = struct.unpack_from("<I", raw, 24)[0]
        ent.in_use = bool(ent.flags & RECORD_IN_USE)
        ent.is_dir = bool(ent.flags & RECORD_IS_DIR)
        ent.base_ref = struct.unpack_from("<Q", raw, 32)[0]

        limit = used if 48 <= used <= len(raw) else len(raw)
        pos = attr_off if 48 <= attr_off < limit else 48
        while pos + 4 <= limit:
            atype = struct.unpack_from("<I", raw, pos)[0]
            if atype == 0xFFFFFFFF:
                break
            alen = struct.unpack_from("<I", raw, pos + 4)[0]
            if alen < 16 or pos + alen > len(raw):
                break
            attr = self._parse_attr(raw, pos, alen)
            ent.attrs.setdefault(attr.type, []).append(attr)
            pos += alen

        for attr in ent.attrs.get(ATTR_STANDARD_INFORMATION, ())[:1]:
            v = attr.value
            if len(v) >= 32:
                ent.si_times = tuple(filetime_to_datetime(struct.unpack_from("<Q", v, o)[0])
                                     for o in (0, 8, 16, 24))
        for attr in ent.attrs.get(ATTR_FILE_NAME, ()):
            fn = self._parse_file_name_value(attr.value)
            if fn is not None:
                ent.names.append(fn)
        return ent

    def _parse_attr(self, raw, pos, alen):
        attr = Attr(self)
        attr.record_offset = pos
        attr.length = alen
        (attr.type, attr.length) = struct.unpack_from("<II", raw, pos)
        attr.non_resident = raw[pos + 8]
        name_len = raw[pos + 9]
        name_off = struct.unpack_from("<H", raw, pos + 10)[0]
        attr.flags, attr.attr_id = struct.unpack_from("<HH", raw, pos + 12)
        if name_len and name_off and pos + name_off + name_len * 2 <= len(raw):
            attr.name = raw[pos + name_off:pos + name_off + name_len * 2].decode(
                "utf-16le", "replace")
        if not attr.non_resident:
            vlen = struct.unpack_from("<I", raw, pos + 16)[0]
            voff = struct.unpack_from("<H", raw, pos + 20)[0]
            start = pos + voff
            stop = min(start + vlen, pos + alen, len(raw))
            attr.value = bytes(raw[start:stop]) if start < stop else b""
            attr.real_size = len(attr.value)
            attr.alloc_size = len(attr.value)
            attr.init_size = len(attr.value)
        else:
            attr.start_vcn, attr.last_vcn = struct.unpack_from("<QQ", raw, pos + 16)
            run_off = struct.unpack_from("<H", raw, pos + 32)[0]
            attr.comp_unit = struct.unpack_from("<H", raw, pos + 34)[0]
            (attr.alloc_size, attr.real_size,
             attr.init_size) = struct.unpack_from("<QQQ", raw, pos + 40)
            run_end = min(pos + alen, len(raw))
            run_blob = bytes(raw[pos + run_off:run_end]) if pos + run_off < run_end else b""
            attr.runs = parse_runlist(run_blob, attr.start_vcn)
        return attr

    def _parse_file_name_value(self, v):
        if len(v) < 66:
            return None
        parent_ref = struct.unpack_from("<Q", v, 0)[0]
        times = tuple(filetime_to_datetime(struct.unpack_from("<Q", v, o)[0])
                      for o in (8, 16, 24, 32))
        alloc_size, real_size = struct.unpack_from("<QQ", v, 40)
        flags = struct.unpack_from("<I", v, 56)[0]
        reparse = struct.unpack_from("<I", v, 60)[0]
        name_len = v[64]
        namespace = v[65]
        name_bytes = v[66:66 + name_len * 2]
        name = name_bytes.decode("utf-16le", "replace")
        return FileName(parent_ref, times[0], times[1], times[2], times[3],
                        alloc_size, real_size, flags, reparse, name, namespace)

    def _cache_put(self, num, ent):
        cache = self._rec_cache
        cache[num] = ent
        cache.move_to_end(num)
        while len(cache) > self._rec_cache_max:
            cache.popitem(last=False)

    def read_entry(self, rec_num):
        """按记录号读取 MFT 记录，无效返回 None。"""
        if rec_num is None or rec_num < 0 or rec_num >= self.record_count:
            return None
        cached = self._rec_cache.get(rec_num)
        if cached is not None:
            self._rec_cache.move_to_end(rec_num)
            return cached
        buf = self.read_runs(self._mft_runs, rec_num * self.mft_record_size,
                             self.mft_record_size)
        ent = self._parse_record(buf, rec_num)
        if not ent.valid:
            return None
        self._cache_put(rec_num, ent)
        if ent.attrs.get(ATTR_ATTRIBUTE_LIST):
            try:
                self.expand(ent)
            except Exception:
                pass
        return ent

    def iter_mft(self, include_deleted=True):
        """遍历全部 MFT 记录（含已删除）。"""
        for num, buf in self._iter_raw_records():
            ent = self._parse_record(buf, num)
            if not ent.valid:
                continue
            if not include_deleted and not ent.in_use:
                continue
            self._cache_put(num, ent)
            yield ent

    # ---------------- 卷信息 ----------------
    def _read_volume_label(self):
        ent = self.read_entry(3)
        if ent is None:
            return ""
        for attr in ent.attrs.get(ATTR_VOLUME_NAME, ()):
            try:
                return attr.value.decode("utf-16le", "replace").rstrip("\x00")
            except Exception:
                return ""
        return ""

    # ---------------- 大小写折叠 ----------------
    def _load_upcase(self):
        if self._upcase_loaded:
            return self._upcase
        self._upcase_loaded = True
        try:
            ent = self.read_entry(10)
            if ent is not None:
                blob = self.read_entry_data(ent)
                if len(blob) >= 131072:
                    self._upcase = struct.unpack_from("<65536H", blob, 0)
        except Exception:
            self._upcase = None
        return self._upcase

    def fold(self, text):
        """NTFS 大小写折叠：优先使用卷内 $UpCase 表。"""
        if not text:
            return ""
        table = self._load_upcase()
        if table is None:
            return text.upper()
        out = []
        for ch in text:
            cp = ord(ch)
            out.append(chr(table[cp]) if cp < 65536 else ch)
        return "".join(out)

    # ---------------- 数据流读取 ----------------
    def _stream_attrs(self, ent, attr_type, name=None):
        wanted = name or ""
        attrs = [a for a in ent.attrs.get(attr_type, ()) if (a.name or "") == wanted]
        attrs.sort(key=lambda a: (a.start_vcn if a.non_resident else 0, a.attr_id))
        return attrs

    # ---------------- ATTRIBUTE_LIST 分片合并 ----------------
    def parse_attr_list(self, ent):
        """解析 $ATTRIBUTE_LIST（类型 0x20）常驻值。

        条目结构：type(4) len(2) name_len(1) name_off(1) lowest_vcn(8)
                  file_reference(8) attr_id(2) name(UTF-16)
        """
        out = []
        for a in ent.attrs.get(ATTR_ATTRIBUTE_LIST, ()):
            if a.non_resident:
                continue
            buf = a.value or b""
            pos = 0
            while pos + 26 <= len(buf):
                try:
                    atype = struct.unpack_from("<I", buf, pos)[0]
                    alen = struct.unpack_from("<H", buf, pos + 4)[0]
                    nlen = buf[pos + 6]
                    noff = buf[pos + 7]
                    vcn = struct.unpack_from("<Q", buf, pos + 8)[0]
                    ref = struct.unpack_from("<Q", buf, pos + 16)[0]
                    aid = struct.unpack_from("<H", buf, pos + 24)[0]
                except Exception:
                    break
                nm = ""
                if nlen and noff and pos + noff + nlen * 2 <= len(buf):
                    nm = buf[pos + noff:pos + noff + nlen * 2].decode("utf-16le", "replace")
                out.append(dict(type=atype, name=nm, lowest_vcn=vcn,
                                ref=ref & 0xFFFFFFFFFFFF, attr_id=aid))
                if alen < 26:
                    break
                pos += alen
        return out

    def expand(self, ent, seen=None, depth=0):
        """按 $ATTRIBUTE_LIST 把扩展 MFT 记录里的属性合并到 ent.attrs。"""
        if not ent.attrs.get(ATTR_ATTRIBUTE_LIST) or depth > 3:
            return ent
        if seen is None:
            seen = {ent.num}
        for item in self.parse_attr_list(ent):
            ref = item["ref"]
            if ref == ent.num or ref in seen:
                continue
            seen.add(ref)
            try:
                ext = self.read_entry(ref)
            except Exception:
                continue
            if ext is None or not ext.valid:
                continue
            for a in ext.attrs.get(item["type"], ()):
                if (a.name or "") != (item["name"] or ""):
                    continue
                if item["attr_id"] and a.attr_id != item["attr_id"]:
                    continue
                ent.attrs.setdefault(item["type"], []).append(a)
        return ent

    def read_entry_data(self, ent, ads=None):
        attrs = self._stream_attrs(ent, ATTR_DATA, ads)
        if not attrs:
            if ads:
                raise NTFSError("记录 #%d 没有名为 %r 的数据流" % (ent.num, ads))
            if ent.is_dir:
                return b""
            return b""
        first = attrs[0]
        if not first.non_resident:
            return first.value
        if first.encrypted:
            raise NTFSUnsupported(
                "记录 #%d（%r）数据流被 EFS 加密（$DATA flags=0x%04x），"
                "本实现不解密" % (ent.num, ent.name, first.flags))
        if first.compressed and first.comp_unit:
            raise NTFSUnsupported(
                "记录 #%d（%r）数据流为 NTFS 压缩（compression_unit=%d），"
                "本实现不实现 LZNT1 解压" % (ent.num, ent.name, first.comp_unit))
        runs = []
        for a in attrs:
            runs.extend(a.runs)
        runs.sort(key=lambda r: r[0])
        size = first.real_size
        if size <= 0:
            return b""
        return self.read_runs(runs, 0, size)

    def read_file(self, path, ads=None):
        """按路径读取文件内容；支持已删除文件（自动 include_deleted 查找）。"""
        ent = self.lookup(path, include_deleted=True)
        if ent is None:
            raise NTFSError("路径不存在: %r" % (path,))
        if ent.is_dir:
            raise NTFSError("路径是目录: %r" % (path,))
        return ent.read_data(ads)

    # ---------------- 目录索引 ----------------
    def _index_root_attrs(self, ent):
        return [a for a in ent.attrs.get(ATTR_INDEX_ROOT, ()) if a.name in ("$I30", "")]

    def _index_alloc_attrs(self, ent):
        return [a for a in ent.attrs.get(ATTR_INDEX_ALLOCATION, ()) if a.name in ("$I30", "")]

    def _iter_index_node(self, buf, hdr_off, items, subnodes):
        """解析一个索引节点（$INDEX_ROOT 值或 INDX 记录）中的索引项。"""
        if hdr_off + 16 > len(buf):
            return
        ent_off, total, _alloc = struct.unpack_from("<III", buf, hdr_off)
        pos = hdr_off + ent_off
        end = hdr_off + total
        if end > len(buf):
            end = len(buf)
        if pos < hdr_off + 16 or pos > end:
            return
        guard = 0
        while pos + 16 <= end and guard < 100000:
            guard += 1
            ref, elen, klen, eflags = struct.unpack_from("<QHHI", buf, pos)
            if elen < 16 or pos + elen > len(buf):
                break
            if klen:
                key = bytes(buf[pos + 16:pos + 16 + klen])
                fn = self._parse_file_name_value(key)
                if fn is not None:
                    items.append({
                        "ref": ref,
                        "rec": ref & FILE_REF_MASK,
                        "seq": (ref >> 48) & 0xFFFF,
                        "fn": fn,
                    })
            if eflags & INDEX_ENTRY_HAS_SUBNODE:
                child = struct.unpack_from("<Q", buf, pos + elen - 8)[0]
                subnodes.append(child)
            if eflags & INDEX_ENTRY_LAST:
                break
            pos += elen

    def _read_index_block(self, alloc_attrs, vcn, block_size):
        offset = vcn * block_size
        runs = []
        for a in alloc_attrs:
            runs.extend(a.runs)
        runs.sort(key=lambda r: r[0])
        return self.read_runs(runs, offset, block_size)

    def _parse_indx_block(self, blob, items, subnodes):
        if len(blob) < 32 or blob[:4] != b"INDX":
            return False
        raw = bytearray(blob)
        raw = self._apply_fixup(raw)
        self._iter_index_node(raw, 24, items, subnodes)
        return True

    def _index_items(self, ent, include_deleted=False):
        """目录的全量索引项（BFS 走 $INDEX_ROOT + $INDEX_ALLOCATION，含陈旧/已删除块）。"""
        key = (ent.num, bool(include_deleted))
        cached = self._index_cache.get(key)
        if cached is not None:
            return cached
        roots = self._index_root_attrs(ent)
        if not roots:
            self._index_cache[key] = None
            return None
        root_attr = roots[0]
        if root_attr.non_resident or len(root_attr.value) < 32:
            self._index_cache[key] = None
            return None
        value = root_attr.value
        block_size = struct.unpack_from("<I", value, 8)[0] or self.index_record_size
        if block_size < 256 or block_size > (1 << 20):
            block_size = self.index_record_size

        items = []
        subnodes = []
        self._iter_index_node(value, 16, items, subnodes)

        alloc_attrs = self._index_alloc_attrs(ent)
        if alloc_attrs:
            visited = set()
            queue = list(subnodes)
            blocks = 0
            max_blocks = 100000
            while queue and blocks < max_blocks:
                vcn = queue.pop(0)
                if vcn in visited:
                    continue
                visited.add(vcn)
                blocks += 1
                blob = self._read_index_block(alloc_attrs, vcn, block_size)
                child = []
                if self._parse_indx_block(blob, items, child):
                    queue.extend(child)
            if include_deleted:
                # 补扫未被 B 树引用的块（已删除目录项的残留位置）
                total_blocks = 0
                for a in alloc_attrs:
                    if a.non_resident and a.alloc_size:
                        total_blocks = max(total_blocks,
                                           a.alloc_size // block_size)
                limit = min(total_blocks, 8192)
                for vcn in range(limit):
                    if vcn in visited:
                        continue
                    visited.add(vcn)
                    blob = self._read_index_block(alloc_attrs, vcn, block_size)
                    if len(blob) >= 32 and blob[:4] == b"INDX":
                        child = []
                        self._parse_indx_block(blob, items, child)
        self._index_cache[key] = items
        return items

    def _scan_by_parent(self, ent):
        """索引不可用时的退化方案：全 MFT 扫描 parent_ref 反查。"""
        items = []
        target = ent.num
        for child in self.iter_mft(include_deleted=True):
            if child.parent_num != target:
                continue
            fn = child._preferred_name()
            if fn is None:
                continue
            items.append({
                "ref": (child.sequence << 48) | child.num,
                "rec": child.num,
                "seq": child.sequence,
                "fn": fn,
            })
        return items

    def _materialize(self, item, parent_num):
        """把索引项变成 MftEntry：优先取真实记录，失效则用索引 key 构造视图。"""
        rec_num = item["rec"]
        fn = item["fn"]
        rec = self.read_entry(rec_num)
        if rec is not None and rec.valid and rec.num == rec_num:
            if rec.sequence == item["seq"]:
                ent = _copy_entry(rec)
                ent._name_override = fn.name
                if not rec.in_use:
                    # 记录已释放但仍被索引引用
                    ent.in_use = False
                return ent, not rec.in_use
            light = self._light_entry(rec_num, item["seq"], fn)
            return light, True
        return self._light_entry(rec_num, item["seq"], fn), True

    def _light_entry(self, rec_num, seq, fn):
        ent = MftEntry(self, rec_num)
        ent.from_index = True
        ent.sequence = seq
        ent.in_use = False
        ent.is_dir = fn.is_dir
        ent.names = [fn]
        ent._name_override = fn.name
        ent._light_sizes = (fn.real_size, fn.alloc_size)
        return ent

    def ls_entry(self, ent, include_deleted=False):
        """列出某个目录记录的条目。"""
        if ent is None or not ent.is_dir:
            return []
        items = self._index_items(ent, include_deleted=include_deleted)
        if items is None:
            items = self._scan_by_parent(ent)
        out = []
        seen = set()
        for item in items:
            fn = item["fn"]
            name = fn.name
            if not name or name in (".", ".."):
                continue
            if item["rec"] == ent.num and self.fold(name) == self.fold(ent.name):
                continue
            key = (item["rec"], item["seq"], name)
            if key in seen:
                continue
            seen.add(key)
            entry, deleted = self._materialize(item, ent.num)
            if deleted and not include_deleted:
                continue
            out.append(entry)
        out.sort(key=lambda e: self.fold(e.name))
        return out

    def ls(self, path="/", include_deleted=False):
        """列出目录项（大小写不敏感）。include_deleted=True 时含已删除项。"""
        ent = self._resolve(path, include_deleted=True)
        if ent is None:
            raise NTFSError("路径不存在: %r" % (path,))
        if not ent.is_dir:
            raise NTFSError("不是目录: %r" % (path,))
        return self.ls_entry(ent, include_deleted=include_deleted)

    # ---------------- 路径解析 ----------------
    def _split_path(self, path):
        if path is None:
            return []
        text = path.replace("\\", "/")
        return [p for p in text.split("/") if p and p != "."]

    def _find_child(self, dir_ent, name, include_deleted):
        folded = self.fold(name)
        children = self.ls_entry(dir_ent, include_deleted=include_deleted)
        for child in children:
            if not child.in_use:
                continue
            if self.fold(child.name) == folded:
                return child
        if include_deleted:
            for child in children:
                if self.fold(child.name) == folded:
                    return child
        return None

    def _resolve(self, path, include_deleted=False):
        parts = self._split_path(path)
        ent = self.read_entry(5)
        if ent is None:
            return None
        for i, part in enumerate(parts):
            if not ent.is_dir:
                return None
            child = self._find_child(ent, part, include_deleted)
            if child is None and not include_deleted:
                child = self._find_child(ent, part, True)
            if child is None:
                return None
            ent = child
        return ent

    def lookup(self, path, include_deleted=False):
        """按路径取 MftEntry（大小写不敏感，'/' 与 '\\' 均可）。"""
        return self._resolve(path, include_deleted=include_deleted)

    # ---------------- 遍历 ----------------
    def walk(self, root="/", include_deleted=True):
        """递归遍历（先序），yield 每个 MftEntry。"""
        start = self._resolve(root, include_deleted=True)
        if start is None:
            return
        stack = [start]
        visited = set()
        while stack:
            ent = stack.pop()
            if ent.num in visited:
                continue
            visited.add(ent.num)
            yield ent
            if not ent.is_dir:
                continue
            try:
                children = self.ls_entry(ent, include_deleted=include_deleted)
            except NTFSError:
                continue
            for child in reversed(children):
                if child.num in visited:
                    continue
                stack.append(child)

    def find(self, name_regex, root="/", include_deleted=True, max_depth=64):
        """按文件名正则搜索（在 root 下递归）。"""
        if isinstance(name_regex, str):
            pattern = re.compile(name_regex, re.IGNORECASE)
        else:
            pattern = name_regex
        hits = []
        start = self._resolve(root, include_deleted=True)
        if start is None:
            return hits
        stack = [(start, 0)]
        visited = set()
        while stack:
            ent, depth = stack.pop()
            if ent.num in visited:
                continue
            visited.add(ent.num)
            if ent.name and pattern.search(ent.name):
                hits.append(ent)
            if not ent.is_dir or depth >= max_depth:
                continue
            try:
                children = self.ls_entry(ent, include_deleted=include_deleted)
            except NTFSError:
                continue
            for child in children:
                if child.num not in visited:
                    stack.append((child, depth + 1))
        return hits

    # ---------------- 统计 ----------------
    def count_records(self):
        """返回 (总记录数, 在用, 已删除)。"""
        total = 0
        used = 0
        deleted = 0
        for ent in self.iter_mft(include_deleted=True):
            total += 1
            if ent.in_use:
                used += 1
            else:
                deleted += 1
        return total, used, deleted

    def __repr__(self):
        return "<NTFS %r vol=%r cluster=%d mft@0x%x records=%d>" % (
            self.label, self.volume_label, self.cluster_size, self.mft_offset,
            self.record_count)


def _copy_entry(ent):
    """浅拷贝记录对象，便于同一记录在不同目录项下显示不同名字。"""
    clone = MftEntry.__new__(MftEntry)
    clone.__dict__.update(ent.__dict__)
    clone._name_override = None
    return clone
