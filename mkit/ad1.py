# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""AccessData AD1 逻辑镜像（FTK Imager Custom Content Image）—— 纯 Python + zlib

AD1 是 FTK Imager 的「逻辑」镜像：不是整盘物理镜像，而是取证人员挑选的文件 /
目录树加上每个文件的内容块。镜像分卷保存（.ad1、.ad2 …），每卷开头都有 512
字节保证金（margin），解压后的地址空间是所有卷的载荷首尾相接，地址不含这
512 字节。

已实现：
  · 段发现：xxx.ad1 → xxx.ad2 … xxx.adN（.AD1 / .ad01 同样识别，大小写不敏感）
  · 段头 ADSEGMENTEDFILE：段号(0x18)、段总数(0x1C)、段大小(0x22，单位 64 KiB)
  · ADCRYPT 加密段识别（识别到直接 NotImplementedError，不做解密）
  · 逻辑镜像头 ADLOGICALIMAGE：version(0x10)、chunk_size(0x18)、
    逻辑镜像标志(0x1C)、首条目(0x24)、源名长度(0x2C)、源名偏移(0x34，v4)
  · 条目树：next 兄弟链 + child 首子链，目录(kind=5) / 文件(kind=0) 展开成路径
  · 元数据链：category + key + 文本值（大小 / 三种时间 / MD5 / SHA-1 / 属性）
  · 内容块表：u64 块数 + (块数+1) 个 u64 边界，逐块 zlib 解压
  · 设备对象：全部文件内容按镜像遍历顺序串成线性流，size / read / info / entries

不实现：
  · ADCRYPT 解密（只认签名，口令与密钥一律不碰）
  · 写回、口令恢复、镜像二次封装
  · v1 / v2 老格式（只按 version 3 / 4 解析）
  · 缺段容错（段数不符直接报错，不跨卷补零）
  · 块级 CRC 校验（AD1 块头不带 CRC，官方校验值是整文件 MD5/SHA-1 元数据）

设备语义：AD1 没有「盘」的线性地址空间。本模块把每个有内容的条目按镜像遍历
顺序（先根链，再子目录）依次拼成线性流：dev.size 是这些内容之和，read(off)
跨条目连续读取。想按路径取单个文件用 entries() 里的 dev_offset，或 entry(path)。

参考：P. C. Bjelland《AccessData Format (AD1)》的字段分析。
"""

import os
import re
import struct
import zlib
from bisect import bisect_right
from datetime import date

__all__ = [
    "Ad1", "find_segments",
    "SEGMENT_SIGNATURE", "IMAGE_SIGNATURE", "ENCRYPTED_SIGNATURE",
    "FOLDER", "FILE",
]

# ---- 段头 / 镜像头常量 ----
MARGIN = 512                       # 每段开头的保证金
SEGMENT_SIGNATURE = b"ADSEGMENTEDFILE"
IMAGE_SIGNATURE = b"ADLOGICALIMAGE"
ENCRYPTED_SIGNATURE = b"ADCRYPT"
SEGMENT_UNIT = 1 << 16             # 段大小字段的单位：64 KiB
SEG_OFF_NUMBER = 0x18              # 段号 u32
SEG_OFF_COUNT = 0x1C               # 段总数 u32
SEG_OFF_SIZE = 0x22                # 段大小 u32（单位 64 KiB）

# ---- 逻辑镜像头 ----
HDR_OFF_VERSION = 0x10             # u32
HDR_OFF_CHUNK = 0x18               # u32，zlib 块大小
HDR_OFF_FLAGS = 0x1C               # u32，0x70=逻辑镜像容器，0=自定义内容
HDR_OFF_FIRST = 0x24               # u64，首条目地址
HDR_OFF_NAME_LEN = 0x2C            # u32，源名长度
HDR_OFF_NAME_PTR = 0x34            # u64，源名地址（version >= 4）
HDR_SIZE = 0x5C                    # 读满 92 字节足够覆盖上面的字段

# ---- 条目 / 元数据 ----
ITEM_HEADER = 48                   # next(8) child(8) meta(8) chunks(8) size(8) kind(4) namelen(4)
ITEM_OFF_NEXT = 0x00
ITEM_OFF_CHILD = 0x08
ITEM_OFF_META = 0x10
ITEM_OFF_CHUNKS = 0x18
ITEM_OFF_SIZE = 0x20
ITEM_OFF_KIND = 0x28
ITEM_OFF_NAME_LEN = 0x2C

META_HEADER = 20                   # next(8) category(4) key(4) length(4)
META_OFF_NEXT = 0x00
META_OFF_CAT = 0x08
META_OFF_KEY = 0x0C
META_OFF_LEN = 0x10

FILE = 0
FOLDER = 5

CAT_TEXT = 1
CAT_NUMBER = 3
CAT_FLAG = 4
CAT_TIME = 5

KEY_SIZE = 0x3
KEY_ACCESSED = 0x7
KEY_CREATED = 0x8
KEY_MODIFIED = 0x9
KEY_MD5 = 0x5001
KEY_SHA1 = 0x5002
KEY_RECORD_CHANGED = 0xA002

MAX_ITEMS = 5000000
MAX_ATTRS = 10000
MAX_NAME = 1 << 16
MAX_VALUE = 1 << 20
MAX_CHUNK = 1 << 26

_SEG_RE = re.compile(r"^(?P<stem>.*)\.(?P<ext>ad\d{1,3})$", re.IGNORECASE)


# ============================================================
# 小工具
# ============================================================
def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _text(raw):
    """AD1 的文本字段：UTF-8 到首个 NUL；个别镜像写 UTF-16LE，按零字节密度兜底"""
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    if not raw:
        return ""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        odd = raw[1::2]
        if odd and odd.count(0) >= len(odd) * 0.9:
            s = raw.decode("utf-16-le", "replace")
        else:
            s = raw.decode("utf-8", "replace")
    return s.replace("\x00", "").strip()


def _filetime(text):
    """`YYYYMMDDTHHMMSS[.ffffff]`（UTC）→ FILETIME（1601 起 100ns）"""
    if not text or len(text) < 15 or text[8] != "T":
        return None
    try:
        y, mo, d = int(text[0:4]), int(text[4:6]), int(text[6:8])
        h, mi, s = int(text[9:11]), int(text[11:13]), int(text[13:15])
        ticks = 0
        if "." in text:
            frac = text.split(".", 1)[1]
            if not frac.isdigit() or len(frac) > 7:
                return None
            ticks = int(frac.ljust(7, "0"))
        days = date(y, mo, d).toordinal() - 719163
        return (days * 86400 + h * 3600 + mi * 60 + s + 11644473600) * 10000000 + ticks
    except (ValueError, OverflowError):
        return None


def _iso(text):
    """`YYYYMMDDTHHMMSS[.ffffff]` → `YYYY-MM-DDTHH:MM:SS.ffffffZ`"""
    if not text or len(text) < 15 or text[8] != "T":
        return None
    whole = text[:15]
    if not (whole[:8] + whole[9:]).isdigit():
        return None
    frac = ""
    if "." in text:
        frac = text.split(".", 1)[1][:6]
        if not frac.isdigit():
            return None
    out = "%s-%s-%sT%s:%s:%s" % (whole[0:4], whole[4:6], whole[6:8],
                                 whole[9:11], whole[11:13], whole[13:15])
    return out + ("." + frac if frac else "") + "Z"


def find_segments(path):
    """给定任意一个 AD1 段文件，返回按段号升序的段文件列表

    目录里找同主名、扩展名为 .ad1/.ad2/…/.ad99（含 .AD1、.ad01）的文件，
    段号从 1 开始连续，遇到缺口就停（缺口之后的段不会被猜到）。
    找不到同族文件时退化为只含 path 的单元素列表。
    """
    path = os.path.abspath(os.fspath(path))
    directory = os.path.dirname(path) or "."
    base = os.path.basename(path)
    m = _SEG_RE.match(base)
    stem = m.group("stem") if m else os.path.splitext(base)[0]
    if not os.path.isdir(directory):
        return [path]
    try:
        names = os.listdir(directory)
    except OSError:
        return [path]
    found = {}
    for name in names:
        mm = _SEG_RE.match(name)
        if not mm:
            continue
        if mm.group("stem").lower() != stem.lower():
            continue
        num = int(mm.group("ext")[2:])
        if num <= 0:
            continue
        found.setdefault(num, os.path.join(directory, name))
    if not found:
        return [path]
    out = []
    want = 1
    while want in found:
        out.append(found[want])
        want += 1
    return out or [found[min(found)]]


# ============================================================
# AD1
# ============================================================
class Ad1(object):
    """AccessData AD1 逻辑镜像只读设备

    用法：
        dev = Ad1.open(r"E:\\case\\logical.ad1")
        dev.size                    # 全部文件内容之和
        dev.read(0, 4096)           # 跨文件连续读
        dev.info()                  # 段数 / 压缩 / 逻辑标志 / 版本 …
        dev.entries()               # 目录树 + 文件元数据
    """

    def __init__(self, path, segments=None):
        self.path = None
        self.problems = []
        self.items = []
        self._fh = []
        self._cache = {}
        self._cache_order = []
        self._compressed = None
        self.segment_size = 0
        self.version = 0
        self.chunk_size = 0
        self.logical_flag = 0
        self.first_item = 0
        self.source = ""
        self._borrowed = None

        first_fh = None
        if hasattr(path, "read"):
            first_fh = path
            self._borrowed = path
            name = getattr(path, "name", None)
            if segments is not None:
                paths = [os.fspath(p) for p in segments]
            elif isinstance(name, str) and name:
                paths = find_segments(name)
            else:
                paths = []
        else:
            self.path = os.path.abspath(os.fspath(path))
            paths = [os.fspath(p) for p in segments] if segments else find_segments(self.path)
        if not paths:
            raise ValueError("AD1: 无法确定段文件列表（给的是无文件名的流对象？）")

        try:
            for i, p in enumerate(paths):
                self._fh.append(first_fh if (i == 0 and first_fh is not None) else open(p, "rb"))
            self._scan_segments()
            self._read_image_header()
            self._walk()
            self._build_device()
        except Exception:
            self.close()
            raise

    # ---------- 打开 / 关闭 ----------
    @classmethod
    def open(cls, path, segments=None):
        """打开 AD1；path 可以是 .ad1/.AD1/.ad01 任一段，也可以是带 name 的流对象"""
        return cls(path, segments=segments)

    def close(self):
        for fh in self._fh:
            if fh is None or fh is self._borrowed:
                continue                    # 调用方给的流对象由调用方关
            try:
                fh.close()
            except Exception:
                pass
        self._fh = []

    # ---------- 段头 ----------
    def _scan_segments(self):
        count = len(self._fh)
        for i, fh in enumerate(self._fh):
            fh.seek(0)
            margin = fh.read(MARGIN)
            if len(margin) < 0x30:
                raise ValueError("AD1: 段 %d 太短，不是 AD1 段" % (i + 1))
            if margin.startswith(ENCRYPTED_SIGNATURE):
                raise NotImplementedError("AD1: ADCRYPT 加密镜像，本模块不解密（段 %d）" % (i + 1))
            if not margin.startswith(SEGMENT_SIGNATURE):
                raise ValueError("AD1: 段 %d 缺少 ADSEGMENTEDFILE 签名" % (i + 1))
            number = _u32(margin, SEG_OFF_NUMBER)
            total = _u32(margin, SEG_OFF_COUNT)
            unit = _u32(margin, SEG_OFF_SIZE)
            if number != i + 1:
                raise ValueError("AD1: 第 %d 个文件的段号是 %d，段序错乱" % (i + 1, number))
            if total and total != count:
                if total < count:
                    for fh2 in self._fh[total:]:
                        try:
                            fh2.close()
                        except Exception:
                            pass
                    self._fh = self._fh[:total]
                    count = total
                    self.problems.append("段数按段头截断为 %d" % total)
                else:
                    raise ValueError("AD1: 段头声明 %d 段，实际只有 %d 段" % (total, count))
            if i == 0:
                if not unit:
                    raise ValueError("AD1: 段头里的段大小为 0")
                self.segment_size = unit * SEGMENT_UNIT
        if not self.segment_size:
            raise ValueError("AD1: 无法确定段大小")

    # ---------- 地址空间 ----------
    def _read_at(self, addr, n):
        """按「载荷地址」跨段读取，地址不含每段 512 字节保证金"""
        if n <= 0:
            return b""
        out = bytearray()
        done = 0
        size = self.segment_size
        while done < n:
            at = addr + done
            idx = at // size
            within = at % size
            want = min(size - within, n - done)
            if idx >= len(self._fh):
                raise ValueError("AD1: 地址 0x%X 越出最后一段" % at)
            fh = self._fh[idx]
            fh.seek(MARGIN + within)
            blob = fh.read(want)
            if len(blob) < want:
                raise IOError("AD1: 段 %d 在 0x%X 处提前结束" % (idx + 1, MARGIN + within))
            out += blob
            done += want
        return bytes(out)

    # ---------- 镜像头 ----------
    def _read_image_header(self):
        h = self._read_at(0, HDR_SIZE)
        if not h.startswith(IMAGE_SIGNATURE):
            raise ValueError("AD1: 载荷开头不是 ADLOGICALIMAGE")
        self.version = _u32(h, HDR_OFF_VERSION)
        self.chunk_size = _u32(h, HDR_OFF_CHUNK)
        self.logical_flag = _u32(h, HDR_OFF_FLAGS)
        self.first_item = _u64(h, HDR_OFF_FIRST)
        name_len = _u32(h, HDR_OFF_NAME_LEN)
        if self.version not in (3, 4):
            self.problems.append("未知格式版本 %d，按 v4 布局试解析" % self.version)
        if not self.chunk_size or self.chunk_size > MAX_CHUNK:
            raise ValueError("AD1: 块大小异常 %d" % self.chunk_size)
        if name_len > MAX_NAME:
            raise ValueError("AD1: 源名长度异常 %d" % name_len)
        name_at = _u64(h, HDR_OFF_NAME_PTR) if self.version >= 4 else 0x30
        if name_len:
            try:
                self.source = _text(self._read_at(name_at, name_len))
            except Exception as exc:
                self.problems.append("源名读取失败：%s" % exc)

    # ---------- 条目树 ----------
    def _read_item(self, addr, parent):
        h = self._read_at(addr, ITEM_HEADER)
        nxt = _u64(h, ITEM_OFF_NEXT)
        child = _u64(h, ITEM_OFF_CHILD)
        meta = _u64(h, ITEM_OFF_META)
        chunks = _u64(h, ITEM_OFF_CHUNKS)
        size = _u64(h, ITEM_OFF_SIZE)
        kind = _u32(h, ITEM_OFF_KIND)
        name_len = _u32(h, ITEM_OFF_NAME_LEN)
        if name_len > MAX_NAME:
            raise ValueError("条目名长度异常 %d" % name_len)
        name = _text(self._read_at(addr + ITEM_HEADER, name_len)) if name_len else ""
        path = name if parent is None else "%s/%s" % (self.items[parent]["path"], name)
        attrs = self._read_attrs(meta)
        return {
            "name": name,
            "path": path,
            "parent": parent,
            "kind": kind,
            "size": size,
            "address": addr,
            "chunks": chunks,
            "attrs": attrs,
            "problems": [],
        }, nxt, child

    def _read_attrs(self, addr):
        attrs = []
        seen = set()
        guard = 0
        while addr and guard < MAX_ATTRS and addr not in seen:
            seen.add(addr)
            guard += 1
            try:
                h = self._read_at(addr, META_HEADER)
            except Exception as exc:
                self.problems.append("元数据 0x%X 读取失败：%s" % (addr, exc))
                break
            nxt = _u64(h, META_OFF_NEXT)
            cat = _u32(h, META_OFF_CAT)
            key = _u32(h, META_OFF_KEY)
            length = _u32(h, META_OFF_LEN)
            if length > MAX_VALUE:
                self.problems.append("元数据 0x%X 值长度异常 %d" % (addr, length))
                break
            try:
                value = _text(self._read_at(addr + META_HEADER, length)) if length else ""
            except Exception as exc:
                self.problems.append("元数据 0x%X 值读取失败：%s" % (addr, exc))
                break
            attrs.append((cat, key, value))
            addr = nxt
        return attrs

    def _walk(self):
        seen = set()
        groups = [(self.first_item, None)]
        guard = 0
        while groups:
            addr, parent = groups.pop()
            while addr:
                if addr in seen:
                    self.problems.append("条目 0x%X 被重复访问，疑似环" % addr)
                    break
                seen.add(addr)
                guard += 1
                if guard > MAX_ITEMS:
                    self.problems.append("条目数超过上限 %d" % MAX_ITEMS)
                    return
                try:
                    item, nxt, child = self._read_item(addr, parent)
                except Exception as exc:
                    self.problems.append("条目 0x%X 解析失败：%s" % (addr, exc))
                    break
                index = len(self.items)
                self.items.append(item)
                if child:
                    groups.append((child, index))
                addr = nxt

    # ---------- 内容块 ----------
    def _bounds(self, item):
        table = item["chunks"]
        if not table:
            return []
        head = self._read_at(table, 8)
        count = _u64(head, 0)
        if not count or count > (1 << 24):
            raise ValueError("块表 0x%X 的块数异常：%d" % (table, count))
        raw = self._read_at(table + 8, (count + 1) * 8)
        bounds = list(struct.unpack("<%dQ" % (count + 1), raw))
        for a, b in zip(bounds, bounds[1:]):
            if b < a:
                raise ValueError("块表 0x%X 边界非单调" % table)
        return bounds

    def _decode_chunk(self, blob, expect):
        """先按 zlib 解；失败且长度对得上就当未压缩块"""
        if not blob:
            return b""
        try:
            d = zlib.decompressobj()
            out = d.decompress(blob) + d.flush()
            if out:
                return out
        except zlib.error:
            pass
        if len(blob) <= expect + 8:
            return blob
        raise ValueError("块数据既不能 zlib 解压，长度也不像未压缩块（%d 字节）" % len(blob))

    def _chunk(self, item_index, chunk_index):
        key = (item_index, chunk_index)
        if key in self._cache:
            return self._cache[key]
        item = self.items[item_index]
        if "_bounds" not in item:
            item["_bounds"] = self._bounds(item)
        bounds = item["_bounds"]
        if chunk_index + 1 >= len(bounds):
            return b""
        start, end = bounds[chunk_index], bounds[chunk_index + 1]
        if end <= start:
            data = b""
        else:
            blob = self._read_at(start, end - start)
            data = self._decode_chunk(blob, self.chunk_size)
        self._cache[key] = data
        self._cache_order.append(key)
        while len(self._cache_order) > 16:
            self._cache.pop(self._cache_order.pop(0), None)
        return data

    def _item_read(self, item_index, off, n):
        item = self.items[item_index]
        size = item["size"]
        if off >= size or n <= 0:
            return b""
        n = min(n, size - off)
        out = bytearray()
        pos = off
        end = off + n
        while pos < end:
            ci = pos // self.chunk_size
            within = pos % self.chunk_size
            data = self._chunk(item_index, ci)
            take = min(self.chunk_size - within, end - pos)
            piece = data[within:within + take]
            out += piece
            if len(piece) < take:
                break
            pos += take
        return bytes(out)

    # ---------- 设备对象 ----------
    def _build_device(self):
        self._spans = []
        self._starts = []
        total = 0
        for index, item in enumerate(self.items):
            item["dev_offset"] = None
            if item["kind"] == FOLDER or not item["chunks"] or not item["size"]:
                continue
            item["dev_offset"] = total
            self._spans.append((total, index))
            self._starts.append(total)
            total += item["size"]
        self.size = total

    def read(self, off, n):
        if off < 0 or n <= 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        out = bytearray()
        pos = off
        end = off + n
        while pos < end:
            i = bisect_right(self._starts, pos) - 1
            if i < 0:
                break
            span_off, item_index = self._spans[i]
            size = self.items[item_index]["size"]
            take = min(end - pos, span_off + size - pos)
            out += self._item_read(item_index, pos - span_off, take)
            pos += take
        return bytes(out)

    def sub(self, offset, size=None):
        return _Slice(self, offset, size if size is not None else self.size - offset)

    # ---------- 元信息 ----------
    def _probe_compressed(self):
        """AD1 头里没有压缩标志，用第一个内容块的字节特征现场判定"""
        if self._compressed is not None:
            return self._compressed
        self._compressed = True
        for item in self.items:
            if not item["chunks"] or not item["size"]:
                continue
            try:
                if "_bounds" not in item:
                    item["_bounds"] = self._bounds(item)
                bounds = item["_bounds"]
                if len(bounds) < 2 or bounds[1] <= bounds[0]:
                    continue
                blob = self._read_at(bounds[0], bounds[1] - bounds[0])
                try:
                    zlib.decompress(blob)
                    self._compressed = True
                except zlib.error:
                    # 解不动，但长度与未压缩块相称 → 认为是压缩级别 0 的原样块
                    self._compressed = len(blob) > min(item["size"], self.chunk_size) + 8
            except Exception:
                self._compressed = True
            break
        return self._compressed

    def info(self):
        files = [i for i in self.items if i["kind"] != FOLDER and i["chunks"]]
        return {
            "format": "ad1",
            "version": self.version,
            "segment_count": len(self._fh),
            "segment_size": self.segment_size,
            "chunk_size": self.chunk_size,
            "compressed": self._probe_compressed(),
            "logical": self.logical_flag != 0,
            "logical_flag": self.logical_flag,
            "source": self.source,
            "entry_count": len(self.items),
            "file_count": len(files),
            "total_size": self.size,
            "first_item": self.first_item,
            "problems": len(self.problems),
        }

    def entries(self):
        """目录树条目（镜像遍历顺序）

        每项：path / name / kind / size / md5 / sha1 / 时间（ISO + FILETIME）/
              dev_offset（在设备线性流里的偏移，目录为 None）
        """
        out = []
        for item in self.items:
            attrs = {}
            for cat, key, value in item["attrs"]:
                attrs.setdefault((cat, key), value)

            def pick(cat, key):
                return attrs.get((cat, key))

            kind = item["kind"]
            out.append({
                "path": item["path"],
                "name": item["name"],
                "kind": "folder" if kind == FOLDER else ("file" if kind == FILE else "other(%d)" % kind),
                "size": item["size"],
                "md5": pick(CAT_TEXT, KEY_MD5),
                "sha1": pick(CAT_TEXT, KEY_SHA1),
                "created": _iso(pick(CAT_TIME, KEY_CREATED)),
                "modified": _iso(pick(CAT_TIME, KEY_MODIFIED)),
                "accessed": _iso(pick(CAT_TIME, KEY_ACCESSED)),
                "record_changed": _iso(pick(CAT_TIME, KEY_RECORD_CHANGED)),
                "created_ft": _filetime(pick(CAT_TIME, KEY_CREATED)),
                "modified_ft": _filetime(pick(CAT_TIME, KEY_MODIFIED)),
                "dev_offset": item.get("dev_offset"),
                "attributes": len(item["attrs"]),
                "address": item["address"],
            })
        return out

    def entry(self, path):
        """按路径取单个条目（失败返回 None）"""
        want = path.replace("\\", "/").strip("/").lower()
        for item in self.entries():
            if item["path"].lower() == want:
                return item
        return None


class _Slice(object):
    """把设备切成子区间，方便套给 mkit.ntfs / Fat 等"""

    def __init__(self, dev, offset, size):
        self.dev = dev
        self.offset = offset
        self.size = size

    def read(self, off, n):
        if off >= self.size:
            return b""
        n = min(n, self.size - off)
        return self.dev.read(self.offset + off, n)


# ============================================================
# 自检：构造一个两段的合成 AD1
# ============================================================
if __name__ == "__main__":
    import datetime
    import hashlib
    import shutil
    import tempfile

    CHUNK = 4096
    SEG = 1 << 16

    hello = b"".join(hashlib.sha256(b"hello-%d" % i).digest() for i in range(94))  # 3008B，不可压
    notes = b"NOTES-" * 500                                                        # 3000B，可压
    z_hello = zlib.compress(hello, 9)
    z_notes = zlib.compress(notes, 9)

    def build_payload():
        buf = bytearray(SEG * 2)
        name = b"Custom Content Image(SYNTH-AD1)"
        buf[0:14] = IMAGE_SIGNATURE
        struct.pack_into("<I", buf, HDR_OFF_VERSION, 4)
        struct.pack_into("<I", buf, 0x14, 1)
        struct.pack_into("<I", buf, HDR_OFF_CHUNK, CHUNK)
        struct.pack_into("<I", buf, HDR_OFF_FLAGS, 0x70)      # 逻辑镜像
        struct.pack_into("<Q", buf, HDR_OFF_FIRST, 160)
        struct.pack_into("<I", buf, HDR_OFF_NAME_LEN, len(name))
        buf[0x30:0x34] = b"AD\x00\x00"
        struct.pack_into("<Q", buf, HDR_OFF_NAME_PTR, 96)
        buf[96:96 + len(name)] = name

        def put_item(base, nxt, child, meta, chunks, size, kind, nm):
            struct.pack_into("<Q", buf, base + ITEM_OFF_NEXT, nxt)
            struct.pack_into("<Q", buf, base + ITEM_OFF_CHILD, child)
            struct.pack_into("<Q", buf, base + ITEM_OFF_META, meta)
            struct.pack_into("<Q", buf, base + ITEM_OFF_CHUNKS, chunks)
            struct.pack_into("<Q", buf, base + ITEM_OFF_SIZE, size)
            struct.pack_into("<I", buf, base + ITEM_OFF_KIND, kind)
            struct.pack_into("<I", buf, base + ITEM_OFF_NAME_LEN, len(nm))
            buf[base + ITEM_HEADER:base + ITEM_HEADER + len(nm)] = nm
            return base + ITEM_HEADER + len(nm)

        def put_meta(base, nxt, cat, key, value):
            struct.pack_into("<Q", buf, base + META_OFF_NEXT, nxt)
            struct.pack_into("<I", buf, base + META_OFF_CAT, cat)
            struct.pack_into("<I", buf, base + META_OFF_KEY, key)
            struct.pack_into("<I", buf, base + META_OFF_LEN, len(value))
            buf[base + META_HEADER:base + META_HEADER + len(value)] = value
            return base + META_HEADER + len(value)

        # 目录 docs（160）→ 子项 hello.txt（224）；docs 的兄弟 notes.txt（288）
        put_item(160, 288, 224, 0, 0, 0, FOLDER, b"docs")
        put_item(224, 0, 0, 360, 520, len(hello), FILE, b"hello.txt")
        put_item(288, 0, 0, 0, 560, len(notes), FILE, b"notes.txt")

        put_meta(360, 384, CAT_NUMBER, KEY_SIZE, b"3008")
        put_meta(384, 436, CAT_TEXT, KEY_MD5, hashlib.md5(hello).hexdigest().encode())
        put_meta(436, 0, CAT_TIME, KEY_MODIFIED, b"20240102T030405.123456")

        struct.pack_into("<Q", buf, 520, 1)
        struct.pack_into("<Q", buf, 528, 65000)
        struct.pack_into("<Q", buf, 536, 65000 + len(z_hello))
        struct.pack_into("<Q", buf, 560, 1)
        struct.pack_into("<Q", buf, 568, 600)
        struct.pack_into("<Q", buf, 576, 600 + len(z_notes))
        buf[600:600 + len(z_notes)] = z_notes
        buf[65000:65000 + len(z_hello)] = z_hello      # 故意跨 65536 段界
        return buf

    def margin(num, total, unit=1):
        m = bytearray(MARGIN)
        m[0:15] = SEGMENT_SIGNATURE
        struct.pack_into("<I", m, 0x10, 1)
        struct.pack_into("<I", m, 0x14, 1)
        struct.pack_into("<I", m, SEG_OFF_NUMBER, num)
        struct.pack_into("<I", m, SEG_OFF_COUNT, total)
        struct.pack_into("<I", m, SEG_OFF_SIZE, unit)
        return bytes(m)

    tmp = tempfile.mkdtemp(prefix="esk-ad1-")
    try:
        payload = build_payload()
        p1 = os.path.join(tmp, "synth.ad1")
        p2 = os.path.join(tmp, "synth.ad2")
        with open(p1, "wb") as fh:
            fh.write(margin(1, 2) + bytes(payload[:SEG]))
        with open(p2, "wb") as fh:
            fh.write(margin(2, 2) + bytes(payload[SEG:]))

        segs = find_segments(p1)
        print("段发现：%d 段 -> %s" % (len(segs), [os.path.basename(s) for s in segs]))
        assert len(segs) == 2, "段发现失败"

        dev = Ad1.open(p1)
        inf = dev.info()
        print("AD1: v%d seg=%d chunk=%d logical=%s compressed=%s total=%d entries=%d" % (
            inf["version"], inf["segment_count"], inf["chunk_size"],
            inf["logical"], inf["compressed"], inf["total_size"], inf["entry_count"]))
        assert inf["version"] == 4 and inf["segment_count"] == 2
        assert inf["chunk_size"] == CHUNK and inf["logical"] is True
        assert inf["compressed"] is True, "压缩判定错"
        assert inf["total_size"] == len(hello) + len(notes), "容量不符"
        assert inf["source"] == "Custom Content Image(SYNTH-AD1)", inf["source"]

        ent = dev.entries()
        print("目录树：", [e["path"] for e in ent])
        assert [e["path"] for e in ent] == ["docs", "notes.txt", "docs/hello.txt"], ent
        assert ent[0]["kind"] == "folder" and ent[0]["dev_offset"] is None
        assert ent[1]["size"] == len(notes)
        assert ent[2]["md5"] == hashlib.md5(hello).hexdigest()
        assert ent[2]["modified"] == "2024-01-02T03:04:05.123456Z", ent[2]["modified"]
        expect_ft = int(datetime.datetime(2024, 1, 2, 3, 4, 5,
                                          tzinfo=datetime.timezone.utc).timestamp()
                        + 11644473600) * 10000000 + 1234560
        assert ent[2]["modified_ft"] == expect_ft, (ent[2]["modified_ft"], expect_ft)
        assert ent[2]["dev_offset"] == len(notes), ent[2]["dev_offset"]

        assert dev.read(0, len(notes)) == notes, "notes 读取不符"
        assert dev.read(len(notes), len(hello)) == hello, "hello 跨段读取不符"
        edge = 20
        assert dev.read(len(notes) - edge, edge * 2) == notes[-edge:] + hello[:edge], "跨界读取不符"
        assert dev.read(dev.size, 16) == b"", "越界应返回空"
        assert dev.read(100, 10 ** 9) == (notes + hello)[100:], "超长读取应截断"
        assert dev.sub(len(notes), 32).read(0, 32) == hello[:32], "切片不符"
        dev.close()

        # ADCRYPT 加密镜像：只识别，不解密
        enc = os.path.join(tmp, "crypt.ad1")
        with open(enc, "wb") as fh:
            head = bytearray(margin(1, 1))
            head[0:7] = ENCRYPTED_SIGNATURE
            fh.write(bytes(head) + b"\x00" * 4096)
        try:
            Ad1.open(enc)
        except NotImplementedError as exc:
            assert "ADCRYPT" in str(exc), exc
        else:
            raise AssertionError("ADCRYPT 应抛 NotImplementedError")

        # 传流对象 / 显式给段列表 / 按路径取条目
        fh = open(p1, "rb")
        dev2 = Ad1(fh)
        assert dev2.info()["segment_count"] == 2, "流对象没带出段文件"
        assert dev2.entry("docs/hello.txt")["md5"] == hashlib.md5(hello).hexdigest()
        dev2.close()
        assert not fh.closed, "调用方的流对象不应被 close() 关掉"
        fh.close()

        dev3 = Ad1.open(p1, segments=[p1, p2])
        assert dev3.read(0, 4) == notes[:4], "显式段列表读取不符"
        dev3.close()

        # 大小写 / 零填充变体也要能发现
        alt = os.path.join(tmp, "alt")
        os.makedirs(alt)
        for src, dst in ((p1, "BLK.AD1"), (p2, "BLK.AD2")):
            shutil.copyfile(src, os.path.join(alt, dst))
        assert len(find_segments(os.path.join(alt, "blk.ad1"))) == 2, "大写扩展名未识别"
        print("AD1 自检通过（段发现 / 头 / 块解压 / 目录树 / 跨段读取 / 时间戳）")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
