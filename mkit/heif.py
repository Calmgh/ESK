# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""HEIF/HEIC 元数据解析（自研 ISO-BMFF box 解析，不依赖 PIL）+ BIP39 助记词工具。

对应 2024 美亚杯个人赛：HEIC 拍摄参数（机型/光圈/焦距）、AirDrop 来源、Live Photo、
后置摄像头张数统计；以及助记词题（BIP39 校验）。

设计要点
--------
* 自己解析 ``ftyp / meta / iinf / iloc / iref / iprp(ipco,ipma) / ispe / irot``，
  从 ``pitm`` 主项 + ``ipma`` 属性关联拿真实宽高与旋转，而不是靠第三方库猜。
* EXIF 走 ``iinf`` 里的 ``Exif`` 项 → ``iloc`` 定位 → 兼容三种起始布局：
  1) 4 字节大端 TIFF 偏移前缀 + TIFF（iPhone 常见）
  2) ``"Exif\\0\\0"`` + TIFF
  3) 直接 TIFF（``II*\\0`` / ``MM\\0*``）
* Live Photo / AirDrop 用结构证据 + 字符串证据双通道判定，并给出命中依据。
* BIP39 自带熵→助记词、助记词→种子、校验和验证，词表可自动查找。

仅需标准库；加密备份相关函数在 ``iosbackup_crypto`` 中（AES 由 pycryptodome 提供）。
"""
import hashlib
import os
import re
import struct

__all__ = [
    "HeifFile", "heic_metadata", "heic_dimensions", "heic_thumbnail",
    "export_thumbnail", "is_live_photo", "heic_stats",
    "load_bip39", "mnemonic_valid", "mnemonic_check", "mnemonic_to_seed",
    "entropy_to_mnemonic", "extract_mnemonic_candidates",
    "decrypt_ios_backup_keybag", "decrypt_ios_file",
]

# ---------------------------------------------------------------------------
# ISO-BMFF box 层
# ---------------------------------------------------------------------------

# meta 是 FullBox：4 字节 version/flags 之后才是子 box
_META_SKIP = 4
# iprp 是纯容器
_CONTAINER = {
    b"meta", b"iprp", b"ipco", b"moov", b"trak", b"mdia", b"minf",
    b"stbl", b"dinf", b"edts", b"udta", b"moof", b"mvex", b"tref",
}


class Box:
    """一个 box 的头信息（不复制负载，只记偏移）。"""

    __slots__ = ("type", "offset", "size", "hdr", "end", "data_off", "path")

    def __init__(self, btype, offset, size, hdr, path=()):
        self.type = btype
        self.offset = offset
        self.size = size
        self.hdr = hdr
        self.end = offset + size
        self.data_off = offset + hdr
        self.path = path

    @property
    def name(self):
        return self.type.decode("latin1", "replace")

    def __repr__(self):
        return "<Box %s off=%d size=%d>" % (self.name, self.offset, self.size)


def _iter_boxes(buf, start, end, depth=0, path=(), limit=4096):
    """在 [start, end) 内迭代 box；容器递归展开（深度上限 10）。"""
    off = start
    n = 0
    while off + 8 <= end and n < limit:
        size = struct.unpack_from(">I", buf, off)[0]
        btype = bytes(buf[off + 4:off + 8])
        hdr = 8
        if size == 1:
            if off + 16 > end:
                break
            size = struct.unpack_from(">Q", buf, off + 8)[0]
            hdr = 16
        elif size == 0:
            size = end - off
        if size < hdr or off + size > end:
            break
        box = Box(btype, off, size, hdr, path + (btype,))
        yield box
        n += 1
        if btype in _CONTAINER and depth < 10:
            skip = _META_SKIP if btype == b"meta" else 0
            yield from _iter_boxes(buf, box.data_off + skip, off + size,
                                  depth + 1, box.path, limit)
        off += size


def _children(buf, box, skip=0):
    """取某个容器 box 的直接子 box。"""
    return list(_iter_boxes(buf, box.data_off + skip, box.end, 0, box.path, 512))


# ---------------------------------------------------------------------------
# TIFF / EXIF
# ---------------------------------------------------------------------------

_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

TAGS = {
    # TIFF / IFD0
    0x0100: "ImageWidth", 0x0101: "ImageLength", 0x010E: "ImageDescription",
    0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
    0x011A: "XResolution", 0x011B: "YResolution", 0x0128: "ResolutionUnit",
    0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright",
    0x8769: "ExifIFD", 0x8825: "GPSIFD",
    0x0201: "JPEGInterchangeFormat", 0x0202: "JPEGInterchangeFormatLength",
    # Exif IFD
    0x829A: "ExposureTime", 0x829D: "FNumber", 0x8822: "ExposureProgram",
    0x8827: "ISOSpeedRatings", 0x8830: "SensitivityType",
    0x8831: "StandardOutputSensitivity", 0x8832: "RecommendedExposureIndex",
    0x9000: "ExifVersion", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime", 0x9011: "OffsetTimeOriginal",
    0x9201: "ShutterSpeedValue", 0x9202: "ApertureValue", 0x9203: "BrightnessValue",
    0x9204: "ExposureBiasValue", 0x9205: "MaxApertureValue", 0x9206: "SubjectDistance",
    0x9207: "MeteringMode", 0x9208: "LightSource", 0x9209: "Flash",
    0x920A: "FocalLength", 0x9214: "SubjectArea", 0x927C: "MakerNote",
    0x9286: "UserComment", 0x9290: "SubSecTime", 0x9291: "SubSecTimeOriginal",
    0xA000: "FlashpixVersion", 0xA001: "ColorSpace",
    0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
    0xA405: "FocalLengthIn35mmFilm", 0xA406: "SceneCaptureType",
    0xA430: "CameraOwnerName", 0xA431: "BodySerialNumber",
    0xA432: "LensSpecification", 0xA433: "LensMake", 0xA434: "LensModel",
    0xA435: "LensSerialNumber", 0xA460: "CompositeImage",
    # GPS IFD
    0x0000: "GPSVersionID", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude", 0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude", 0x0007: "GPSTimeStamp", 0x0008: "GPSSatellites",
    0x0009: "GPSStatus", 0x000B: "GPSDOP", 0x000D: "GPSSpeed",
    0x0010: "GPSImgDirectionRef", 0x0011: "GPSImgDirection",
    0x0012: "GPSMapDatum", 0x001D: "GPSDateStamp",
}


class Tiff:
    """最小 TIFF 解析器：IFD 链 + 子 IFD（Exif/GPS/IFD1）。"""

    def __init__(self, buf):
        self.buf = buf
        if buf[:4] == b"II*\x00":
            self.e = "<"
        elif buf[:4] == b"MM\x00*":
            self.e = ">"
        else:
            raise ValueError("不是 TIFF 头: %r" % buf[:4])
        self.ifd0_off = struct.unpack_from(self.e + "I", buf, 4)[0]

    # -- 值解析 --------------------------------------------------------
    def _read_value(self, typ, count, pos):
        unit = _TYPE_SIZE.get(typ, 1)
        total = unit * count
        if total == 0:
            return None
        if total <= 4:
            raw = self.buf[pos:pos + total]
        else:
            if pos + 4 > len(self.buf):
                return None
            off = struct.unpack_from(self.e + "I", self.buf, pos)[0]
            raw = self.buf[off:off + total]
        if raw is None or len(raw) < total:
            return None
        if typ == 2:
            return raw.split(b"\x00")[0].decode("utf-8", "replace").strip()
        if typ in (1, 7):
            return bytes(raw) if count > 1 else raw[0]
        if typ in (3, 8):
            vals = list(struct.unpack(self.e + "%d%s" % (count, "H" if typ == 3 else "h"), raw))
        elif typ in (4, 9):
            vals = list(struct.unpack(self.e + "%d%s" % (count, "I" if typ == 4 else "i"), raw))
        elif typ in (5, 10):
            fmt = "I" if typ == 5 else "i"
            flat = struct.unpack(self.e + "%d%s" % (count * 2, fmt), raw)
            vals = [flat[i * 2] / flat[i * 2 + 1] if flat[i * 2 + 1] else 0.0
                    for i in range(count)]
        elif typ == 11:
            vals = list(struct.unpack(self.e + "%df" % count, raw))
        elif typ == 12:
            vals = list(struct.unpack(self.e + "%dd" % count, raw))
        else:
            return bytes(raw)
        return vals[0] if len(vals) == 1 else vals

    def read_ifd(self, offset, max_entries=400):
        """返回 ({tag_int: value}, next_ifd_offset)。"""
        out = {}
        if not offset or offset + 2 > len(self.buf):
            return out, 0
        count = struct.unpack_from(self.e + "H", self.buf, offset)[0]
        pos = offset + 2
        for _ in range(min(count, max_entries)):
            if pos + 12 > len(self.buf):
                break
            tag, typ, cnt = struct.unpack_from(self.e + "HHI", self.buf, pos)
            try:
                val = self._read_value(typ, cnt, pos + 8)
            except (struct.error, IndexError, ValueError):
                val = None
            if val is not None:
                out[tag] = val
            pos += 12
        nxt = 0
        if pos + 4 <= len(self.buf):
            nxt = struct.unpack_from(self.e + "I", self.buf, pos)[0]
        return out, nxt

    def parse(self):
        """解析出 ifd0 / exif / gps / ifd1 命名标签字典。"""
        ifd0_raw, nxt = self.read_ifd(self.ifd0_off)
        res = {"ifd0": _named(ifd0_raw), "ifd0_raw": ifd0_raw, "exif": {}, "gps": {},
               "ifd1": {}, "ifd1_raw": {}}
        exif_off = ifd0_raw.get(0x8769)
        if isinstance(exif_off, int) and exif_off:
            raw, _ = self.read_ifd(exif_off)
            res["exif_raw"] = raw
            res["exif"] = _named(raw)
        gps_off = ifd0_raw.get(0x8825)
        if isinstance(gps_off, int) and gps_off:
            raw, _ = self.read_ifd(gps_off)
            res["gps_raw"] = raw
            res["gps"] = _named(raw)
        if nxt:
            raw, nxt2 = self.read_ifd(nxt)
            res["ifd1_raw"] = raw
            res["ifd1"] = _named(raw)
            if nxt2:  # IFD2（少见，多页 TIFF）
                raw2, _ = self.read_ifd(nxt2)
                res.setdefault("ifd2_raw", raw2)
                res["ifd2"] = _named(raw2)
        return res


def _named(raw):
    return {TAGS.get(t, "Tag_0x%04X" % t): v for t, v in raw.items()}


def _to_float(v):
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, (list, tuple)) and v and isinstance(v[0], (int, float)):
        return float(v[0])
    return None


def _exposure_str(t):
    if t is None:
        return None
    return ("1/%d" % round(1 / t)) if 0 < t < 1 else ("%g" % t)


def _gps_decimal(gps):
    """GPS IFD → (lat, lon, alt)。"""
    lat = lon = alt = None
    la, lo = gps.get("GPSLatitude"), gps.get("GPSLongitude")
    if isinstance(la, (list, tuple)) and len(la) >= 3:
        lat = la[0] + la[1] / 60.0 + la[2] / 3600.0
        if str(gps.get("GPSLatitudeRef", "N")).strip().upper().startswith("S"):
            lat = -lat
    if isinstance(lo, (list, tuple)) and len(lo) >= 3:
        lon = lo[0] + lo[1] / 60.0 + lo[2] / 3600.0
        if str(gps.get("GPSLongitudeRef", "E")).strip().upper().startswith("W"):
            lon = -lon
    a = _to_float(gps.get("GPSAltitude"))
    if a is not None:
        ref = gps.get("GPSAltitudeRef")
        if isinstance(ref, (bytes, bytearray)) and ref and ref[0] == 1:
            a = -a
        elif isinstance(ref, int) and ref == 1:
            a = -a
        alt = a
    return lat, lon, alt


def _exif_tiff_block(payload):
    """把 Exif 项负载裁成纯 TIFF（兼容 4 字节偏移前缀 / "Exif\\0\\0" / 裸 TIFF）。"""
    if not payload:
        return None, "空负载"
    if payload[:4] in (b"II*\x00", b"MM\x00*"):
        return payload, "tiff-direct"
    i = payload.find(b"Exif\x00\x00", 0, 64)
    if i >= 0 and payload[i + 6:i + 10] in (b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+"):
        return payload[i + 6:], "exif-marker"
    if len(payload) >= 8:
        off = struct.unpack_from(">I", payload, 0)[0]
        if 0 < off <= len(payload) - 8 and payload[off:off + 4] in (b"II*\x00", b"MM\x00*"):
            # ISO/IEC 23008-12: Exif 项 = 4 字节 TIFF 头偏移（相对项起始）
            return payload[off:], "offset-prefix"
        if payload[4:8] in (b"II*\x00", b"MM\x00*"):
            return payload[4:], "offset-zero"
    j = payload.find(b"II*\x00")
    k = payload.find(b"MM\x00*")
    cand = [x for x in (j, k) if x >= 0]
    if cand:
        return payload[min(cand):], "tiff-scan"
    return None, "未见 TIFF 头"


# ---------------------------------------------------------------------------
# HEIF 主类
# ---------------------------------------------------------------------------

ITEM_TYPE_IMAGE = {b"hvc1", b"hev1", b"av01", b"jpeg", b"grid", b"iovl", b"iden"}
ITEM_TYPE_VIDEO = {b"hvc2", b"avc1", b"mp4v"}


class HeifFile:
    """HEIC/HEIF 文件解析器。``HeifFile(path)`` 或 ``HeifFile(data=bytes)``。"""

    def __init__(self, path=None, data=None, max_scan=64 << 20):
        if data is None:
            if path is None:
                raise ValueError("需要 path 或 data")
            with open(path, "rb") as f:
                data = f.read(max_scan)
        self.path = path
        self.data = data
        self.size = len(data)
        self.boxes = list(_iter_boxes(data, 0, self.size))
        self.top = [b for b in self.boxes if not b.path[:-1]]
        self._by_type = {}
        for b in self.boxes:
            self._by_type.setdefault(b.type, []).append(b)
        self._items = None
        self._prop_map = None
        self._str_cache = None

    # -- 基础 ----------------------------------------------------------
    @property
    def brands(self):
        out = []
        for b in self._by_type.get(b"ftyp", [])[:1]:
            major = self.data[b.data_off:b.data_off + 4].decode("latin1", "replace")
            out.append(major)
            p = b.data_off + 8  # major(4) + minor_version(4)
            while p + 4 <= b.end:
                br = self.data[p:p + 4].decode("latin1", "replace").strip("\x00")
                if br:
                    out.append(br)
                p += 4
        seen, res = set(), []
        for x in out:
            if x and x not in seen:
                seen.add(x)
                res.append(x)
        return res

    @property
    def brand(self):
        bs = self.brands
        return bs[0] if bs else None

    @property
    def is_heif(self):
        return self.data[4:8] == b"ftyp" and bool(self._by_type.get(b"meta"))

    def find(self, btype):
        return self._by_type.get(btype, [])

    def _meta_child(self, btype):
        metas = self.find(b"meta")
        if not metas:
            return None
        for b in _children(self.data, metas[0], _META_SKIP):
            if b.type == btype:
                return b
        return None

    # -- 字符串扫描（Live Photo / AirDrop 证据）--------------------------
    def _text(self):
        if self._str_cache is None:
            self._str_cache = self.data.decode("latin1", "replace")
        return self._str_cache

    def _head_text(self, limit=262144):
        return self.data[:limit].decode("latin1", "replace")

    # -- iinf / iloc / iref / iprp -------------------------------------
    @property
    def primary_id(self):
        b = self._meta_child(b"pitm")
        if not b:
            return None
        ver = self.data[b.data_off]
        if ver == 0:
            return struct.unpack_from(">H", self.data, b.data_off + 4)[0]
        return struct.unpack_from(">I", self.data, b.data_off + 4)[0]

    def items(self):
        """解析 iinf(infe) + iloc，返回 {item_id: {...}}。"""
        if self._items is not None:
            return self._items
        items = {}
        iinf = self._meta_child(b"iinf")
        if iinf is not None and iinf.size >= 16:
            d = self.data
            ver = d[iinf.data_off]
            p = iinf.data_off + 4
            if ver == 0:
                p += 2
            else:
                p += 4
            guard = 0
            while p + 8 <= iinf.end and guard < 512:
                sz = struct.unpack_from(">I", d, p)[0]
                typ = d[p + 4:p + 8]
                if typ != b"infe" or sz < 8:
                    break
                iver = d[p + 8]
                if iver == 0 or iver == 1:
                    iid = struct.unpack_from(">H", d, p + 12)[0]
                    q = p + 16
                    itype = b""
                    name = d[q:p + sz].split(b"\x00")[0].decode("utf-8", "replace")
                else:
                    iid = struct.unpack_from(">H", d, p + 12)[0]
                    q = p + 16
                    itype = bytes(d[q:q + 4])
                    name = d[q + 4:p + sz].split(b"\x00")[0].decode("utf-8", "replace")
                items[iid] = {"id": iid, "type": itype, "name": name,
                              "content_type": None, "extents": [], "method": 0}
                p += sz
                guard += 1
        # iloc
        iloc = self._meta_child(b"iloc")
        if iloc is not None and iloc.size >= 12:
            self._parse_iloc(iloc, items)
        # 补 mime 项的内容类型（写在 item_name 之后，infe v2 的扩展类型字段）
        self._items = items
        return items

    def _parse_iloc(self, iloc, items):
        d = self.data
        p = iloc.data_off
        ver = d[p]
        p += 4
        b0 = d[p]
        off_size, len_size = b0 >> 4, b0 & 0x0F
        b1 = d[p + 1]
        base_size, index_size = b1 >> 4, b1 & 0x0F
        p += 2
        if ver < 2:
            count = struct.unpack_from(">H", d, p)[0]
            p += 2
        else:
            count = struct.unpack_from(">I", d, p)[0]
            p += 4
        for _ in range(min(count, 4096)):
            if p + 4 > iloc.end:
                break
            if ver < 2:
                iid = struct.unpack_from(">H", d, p)[0]
                p += 2
            else:
                iid = struct.unpack_from(">I", d, p)[0]
                p += 4
            method = 0
            if ver in (1, 2):
                method = struct.unpack_from(">H", d, p)[0] & 0x0F
                p += 2
            p += 2  # data_reference_index
            base = int.from_bytes(d[p:p + base_size], "big") if base_size else 0
            p += base_size
            if p + 2 > iloc.end:
                break
            ec = struct.unpack_from(">H", d, p)[0]
            p += 2
            extents = []
            for _ in range(min(ec, 1024)):
                if index_size:
                    p += index_size
                off = int.from_bytes(d[p:p + off_size], "big") if off_size else 0
                p += off_size
                ln = int.from_bytes(d[p:p + len_size], "big") if len_size else 0
                p += len_size
                extents.append((base + off, ln))
                if p > iloc.end:
                    break
            ent = items.setdefault(iid, {"id": iid, "type": b"", "name": "",
                                         "content_type": None})
            ent["method"] = method
            ent["extents"] = extents
            if p > iloc.end:
                break

    def item_data(self, item_id):
        """按 iloc 取某项的原始负载（多 extent 拼接；method=1 取自 idat）。"""
        items = self.items()
        ent = items.get(item_id)
        if not ent:
            return b""
        if ent.get("method") == 1:
            idat = self._meta_child(b"idat")
            if idat is None:
                return b""
            out = b""
            for off, ln in ent["extents"]:
                base = idat.data_off + off
                out += self.data[base:base + ln]
            return out
        out = b""
        for off, ln in ent["extents"]:
            if off <= 0 or off >= self.size:
                continue
            out += self.data[off:off + ln if ln else self.size - off]
        return out

    @property
    def references(self):
        """iref → [(ref_type, from_id, [to_ids])]。"""
        if getattr(self, "_refs", None) is not None:
            return self._refs
        res = []
        b = self._meta_child(b"iref")
        if b is not None:
            d = self.data
            ver = d[b.data_off]
            p = b.data_off + 4
            idw = 2 if ver == 0 else 4
            guard = 0
            while p + 8 <= b.end and guard < 512:
                sz = struct.unpack_from(">I", d, p)[0]
                rtype = bytes(d[p + 4:p + 8])
                if sz < 8 + idw + 2:
                    break
                frm = struct.unpack_from(">H", d, p + 8)[0] if idw == 2 else \
                    struct.unpack_from(">I", d, p + 8)[0]
                q = p + 8 + idw
                cnt = struct.unpack_from(">H", d, q)[0]
                q += 2
                tos = []
                for _ in range(min(cnt, 4096)):
                    if q + idw > p + sz:
                        break
                    tos.append(struct.unpack_from(">H", d, q)[0] if idw == 2 else
                               struct.unpack_from(">I", d, q)[0])
                    q += idw
                res.append((rtype, frm, tos))
                p += sz
                guard += 1
        self._refs = res
        return res

    def property_map(self):
        """ipma → {item_id: [ipco 序号]}。"""
        if self._prop_map is not None:
            return self._prop_map
        out = {}
        b = self._meta_child(b"iprp")
        if b is None:
            self._prop_map = out
            return out
        ipma = None
        for c in _children(self.data, b):
            if c.type == b"ipma":
                ipma = c
        if ipma is None:
            self._prop_map = out
            return out
        d = self.data
        ver = d[ipma.data_off]
        flags = d[ipma.data_off + 3]
        p = ipma.data_off + 4
        n = struct.unpack_from(">I", d, p)[0]
        p += 4
        wide = bool(flags & 1)
        for _ in range(min(n, 4096)):
            if p + 3 > ipma.end:
                break
            iid = struct.unpack_from(">H", d, p)[0] if ver < 1 else \
                struct.unpack_from(">I", d, p)[0]
            p += 2 if ver < 1 else 4
            ac = d[p]
            p += 1
            idxs = []
            for _ in range(ac):
                if p + (2 if wide else 1) > ipma.end:
                    break
                if wide:
                    idxs.append(struct.unpack_from(">H", d, p)[0] & 0x7FFF)
                    p += 2
                else:
                    idxs.append(d[p] & 0x7F)
                    p += 1
            out[iid] = idxs
        self._prop_map = out
        return out

    def ipco_properties(self):
        """ipco 属性列表：[{type, offset, size, ...}]。"""
        res = []
        b = self._meta_child(b"iprp")
        if b is None:
            return res
        ipco = None
        for c in _children(self.data, b):
            if c.type == b"ipco":
                ipco = c
        if ipco is None:
            return res
        for c in _children(self.data, ipco):
            ent = {"type": c.type, "offset": c.offset, "size": c.size}
            if c.type == b"ispe" and c.size >= 20:
                ent["width"], ent["height"] = struct.unpack_from(">II", self.data, c.data_off + 4)
            elif c.type == b"irot" and c.size >= 13:
                # FullBox：version/flags(4) + angle(1)
                ent["angle"] = (self.data[c.data_off + 4] & 0x03) * 90
            elif c.type == b"imir" and c.size >= 13:
                # FullBox：version/flags(4) + axis(1)
                ent["axis"] = self.data[c.data_off + 4] & 0x01
            res.append(ent)
        return res

    def item_properties(self, item_id):
        """返回某 item 关联的属性 dict 列表。"""
        props = self.ipco_properties()
        idxs = self.property_map().get(item_id, [])
        out = []
        for i in idxs:
            if 1 <= i <= len(props):
                out.append(props[i - 1])
        return out

    # -- 尺寸 / 旋转 ---------------------------------------------------
    def image_size(self):
        """主图 (宽, 高)，已排除属性里的缩略图 ispe。"""
        props = self.ipco_properties()
        pmap = self.property_map()
        pid = self.primary_id
        cand = []
        if pid is not None:
            for p in self.item_properties(pid):
                if p["type"] == b"ispe":
                    cand.append((p["width"], p["height"]))
        if not cand:
            # 退化：所有 ispe，取面积最大者
            for p in props:
                if p["type"] == b"ispe":
                    cand.append((p["width"], p["height"]))
        if not cand:
            return None, None
        # 主项可能带多个 ispe（含缩略图），取面积最大
        w, h = max(cand, key=lambda t: t[0] * t[1])
        return w, h

    def rotation(self):
        pid = self.primary_id
        if pid is not None:
            for p in self.item_properties(pid):
                if p["type"] == b"irot":
                    return p.get("angle", 0)
        for p in self.ipco_properties():
            if p["type"] == b"irot":
                return p.get("angle", 0)
        return 0

    # -- EXIF / XMP ----------------------------------------------------
    def exif_item_id(self):
        for iid, ent in self.items().items():
            if ent.get("type") == b"Exif":
                return iid
        for iid, ent in self.items().items():
            if ent.get("name", "").lower() == "exif":
                return iid
        return None

    def exif_payload(self):
        """返回 (TIFF bytes, 来源说明, 原始项长度)。"""
        iid = self.exif_item_id()
        raw = self.item_data(iid) if iid is not None else b""
        src = "iloc item %s" % iid
        if not raw:
            for b in self.find(b"Exif"):  # 老式 Exif box（meta 下的独立 box）
                raw = self.data[b.data_off:b.end]
                src = "Exif box@%d" % b.offset
                break
        if not raw:
            return None, "无 Exif 项/box", 0
        tiff, how = _exif_tiff_block(raw)
        return tiff, "%s/%s" % (src, how), len(raw)

    def exif(self):
        tiff, how, ln = self.exif_payload()
        if not tiff:
            return {"present": False, "reason": how}
        try:
            parsed = Tiff(tiff).parse()
        except Exception as e:  # 损坏样本不应炸掉整条链路
            return {"present": False, "reason": "TIFF 解析失败: %s" % e}
        parsed["present"] = True
        parsed["source"] = how
        parsed["payload_len"] = ln
        return parsed

    def xmp(self):
        """取 XMP（mime 项 application/rdf+xml 或直接扫描 xmpmeta）。"""
        for iid, ent in self.items().items():
            if ent.get("type") == b"mime":
                raw = self.item_data(iid)
                if b"<x:xmpmeta" in raw or b"<?xpacket" in raw:
                    return raw.decode("utf-8", "replace")
        d = self.data
        i = d.find(b"<x:xmpmeta")
        if i < 0:
            i = d.find(b"<?xpacket")
        if i < 0:
            return None
        j = d.find(b"</x:xmpmeta>", i)
        if j > 0:
            return d[i:j + 12].decode("utf-8", "replace")
        return d[i:i + 65536].decode("utf-8", "replace")

    # -- 缩略图 --------------------------------------------------------
    def thumbnail(self):
        """返回 {mime, data, source} 或 None（HEVC 位流不可直接转 JPEG）。"""
        ex = self.exif()
        if ex.get("present"):
            ifd1 = ex.get("ifd1_raw") or {}
            off = ifd1.get(0x0201)
            ln = ifd1.get(0x0202)
            raw = ex.get("_tiff")
            if isinstance(off, int) and isinstance(ln, int) and ln > 0:
                tiff, _, _ = self.exif_payload()
                if tiff and off + ln <= len(tiff):
                    blob = tiff[off:off + ln]
                    if blob[:2] == b"\xff\xd8":
                        return {"mime": "image/jpeg", "data": blob,
                                "source": "exif-ifd1"}
        # thmb 引用：from=缩略图项, to=主项
        for rtype, frm, tos in self.references:
            if rtype == b"thmb":
                data = self.item_data(frm)
                if data[:2] == b"\xff\xd8":
                    return {"mime": "image/jpeg", "data": data, "source": "thmb item %d" % frm}
        # mime 项直接给 jpeg
        for iid, ent in self.items().items():
            if ent.get("type") in (b"jpeg", b"mime"):
                data = self.item_data(iid)
                if data[:2] == b"\xff\xd8":
                    return {"mime": "image/jpeg", "data": data,
                            "source": "item %d" % iid}
        return None

    # -- Live Photo / AirDrop ------------------------------------------
    def live_photo_evidence(self):
        ev = []
        items = self.items()
        for iid, ent in items.items():
            if ent.get("type") == b"mebx":
                ev.append("item %d 类型 mebx" % iid)
        for rtype, frm, tos in self.references:
            if rtype == b"cdsc":
                for t in tos:
                    t_ent = items.get(t, {})
                    if t_ent.get("type") == b"mebx" or t_ent.get("type") in ITEM_TYPE_VIDEO:
                        ev.append("cdsc %d→%d(%s)" % (frm, t, t_ent.get("type", b"?").decode("latin1")))
        if b"com.apple.quicktime.live-photo" in self.data:
            ev.append("com.apple.quicktime.live-photo 键")
        if self.find(b"moov") and self.find(b"trak"):
            brands = self.brands
            if "heic" in brands or "mif1" in brands or "msf1" in brands:
                ev.append("ftyp(%s)+moov 视频轨" % ",".join(brands[:4]))
        for key in (b"apple:ContentIdentifier", b"com.apple.quicktime.content.identifier",
                    b"MicroVideo", b"LivePhoto"):
            if key in self.data:
                ev.append("字符串 %s" % key.decode())
        return ev

    def airdrop_evidence(self):
        ev = []
        ex = self.exif()
        if ex.get("present"):
            for tag in ("Software", "Artist", "Copyright", "UserComment", "ImageDescription"):
                val = (ex.get("ifd0") or {}).get(tag) if tag in ("Software", "Artist",
                                                                "Copyright", "ImageDescription") \
                    else (ex.get("exif") or {}).get(tag)
                if isinstance(val, str) and "airdrop" in val.lower():
                    ev.append("EXIF %s=%r" % (tag, val))
        xmp = self.xmp()
        if xmp:
            for m in re.finditer(r"AirDrop[^\"<]{0,60}", xmp, re.I):
                ev.append("XMP: " + m.group(0)[:80])
        # MakerApple 字典 / 系统来源字符串
        for key in (b"AirDrop", b"airdrop", b"com.apple.quarantine"):
            if key in self.data:
                ev.append("原始字符串 %s" % key.decode())
        # `WhereFroms` 可能出现在 XMP/IPTC 里
        if b"kMDItemWhereFroms" in self.data:
            ev.append("kMDItemWhereFroms")
        seen, res = set(), []
        for e in ev:
            if e not in seen:
                seen.add(e)
                res.append(e)
        return res

    # -- 相机位置 ------------------------------------------------------
    def camera_position(self):
        ex = self.exif()
        lens = ""
        if ex.get("present"):
            e = ex.get("exif") or {}
            lens = " ".join(str(e.get(k, "")) for k in ("LensModel", "LensMake"))
        low = lens.lower()
        if "front" in low:
            return "front", "LensModel=%s" % lens.strip()
        if "back" in low:
            return "back", "LensModel=%s" % lens.strip()
        fl = _to_float((ex.get("exif") or {}).get("FocalLength")) if ex.get("present") else None
        if fl:
            # iPhone 前摄 2.2~2.9mm；后摄 3.9~6.8mm（超广角 1.5mm 例外）
            if fl < 3.0:
                return "front", "FocalLength=%gmm" % fl
            if fl >= 3.5:
                return "back", "FocalLength=%gmm" % fl
        return "unknown", lens.strip() or None


# ---------------------------------------------------------------------------
# 对外 API
# ---------------------------------------------------------------------------

def heic_metadata(path):
    """解析一个 HEIC/HEIF，返回拍摄参数/尺寸/方向/Live Photo/AirDrop 等。"""
    try:
        hf = HeifFile(path)
    except OSError as e:
        return {"error": "打开失败: %s" % e}
    if not hf.is_heif:
        return {"error": "不是 HEIF/HEIC（缺 ftyp 或 meta）", "brands": hf.brands}
    out = {
        "file": os.path.basename(str(path)),
        "size": hf.size,
        "brand": hf.brand,
        "brands": hf.brands,
        "is_heic": any(b in ("heic", "heix", "hevc", "hevx", "heim", "heis",
                             "mif1", "mif2", "msf1") for b in hf.brands),
        "box_types": sorted({b.name for b in hf.boxes}),
        "item_types": sorted({e.get("type", b"").decode("latin1")
                              for e in hf.items().values() if e.get("type")}),
        "primary_item": hf.primary_id,
        "item_count": len(hf.items()),
    }
    w, h = hf.image_size()
    out["width"], out["height"] = w, h
    out["rotation"] = hf.rotation()
    if w and h and out["rotation"] in (90, 270):
        out["display_width"], out["display_height"] = h, w
    else:
        out["display_width"], out["display_height"] = w, h

    ex = hf.exif()
    out["exif_present"] = bool(ex.get("present"))
    if ex.get("present"):
        e = ex.get("exif") or {}
        i0 = ex.get("ifd0") or {}
        out["exif_source"] = ex.get("source")
        out["make"] = i0.get("Make")
        out["model"] = i0.get("Model")
        out["software"] = i0.get("Software")
        out["artist"] = i0.get("Artist")
        out["lens_model"] = e.get("LensModel")
        out["lens_make"] = e.get("LensMake")
        out["datetime"] = (e.get("DateTimeOriginal") or i0.get("DateTime")
                           or e.get("DateTimeDigitized"))
        out["datetime_original"] = e.get("DateTimeOriginal")
        out["datetime_digitized"] = e.get("DateTimeDigitized")
        out["offset_time"] = e.get("OffsetTimeOriginal") or e.get("OffsetTime")
        out["fnumber"] = _to_float(e.get("FNumber"))
        out["aperture_value"] = _to_float(e.get("ApertureValue"))
        exp = _to_float(e.get("ExposureTime"))
        out["exposure_time"] = exp
        out["exposure_str"] = _exposure_str(exp)
        iso = e.get("ISOSpeedRatings")
        out["iso"] = iso if not isinstance(iso, list) else (iso[0] if iso else None)
        out["focal_length"] = _to_float(e.get("FocalLength"))
        out["focal_length_35mm"] = e.get("FocalLengthIn35mmFilm")
        out["lens_spec"] = e.get("LensSpecification")
        out["pixel_x"] = e.get("PixelXDimension")
        out["pixel_y"] = e.get("PixelYDimension")
        out["flash"] = e.get("Flash")
        out["metering"] = e.get("MeteringMode")
        out["exposure_program"] = e.get("ExposureProgram")
        out["body_serial"] = e.get("BodySerialNumber")
        out["owner"] = e.get("CameraOwnerName")
        lat, lon, alt = _gps_decimal(ex.get("gps") or {})
        out["gps_lat"], out["gps_lon"], out["gps_alt"] = lat, lon, alt
        if ex.get("gps"):
            out["gps_datestamp"] = (ex.get("gps") or {}).get("GPSDateStamp")
            out["gps_timestamp"] = (ex.get("gps") or {}).get("GPSTimeStamp")
        out["exif_ifd0"] = i0
        out["exif_sub"] = e
        out["gps_tags"] = ex.get("gps") or {}
    else:
        out["exif_reason"] = ex.get("reason")

    xmp = hf.xmp()
    out["xmp_present"] = bool(xmp)
    if xmp:
        m = re.search(r'xmp:CreatorTool="([^"]+)"', xmp)
        if m and not out.get("software"):
            out["software"] = m.group(1)
        m = re.search(r'xmp:CreateDate="([^"]+)"', xmp)
        out["xmp_create_date"] = m.group(1) if m else None
        m = re.search(r'photoshop:DateCreated="([^"]+)"', xmp)
        out["xmp_date_created"] = m.group(1) if m else None

    lev = hf.live_photo_evidence()
    out["live_photo"] = bool(lev)
    out["live_photo_evidence"] = lev
    aev = hf.airdrop_evidence()
    out["airdrop"] = bool(aev)
    out["airdrop_evidence"] = aev
    pos, why = hf.camera_position()
    out["camera_position"] = pos
    out["camera_position_by"] = why
    th = hf.thumbnail()
    out["has_embedded_jpeg_thumb"] = bool(th)
    if th:
        out["thumb_source"] = th["source"]
        out["thumb_bytes"] = len(th["data"])
    return out


def heic_dimensions(path):
    """(宽, 高)；解析失败返回 (None, None)。"""
    try:
        return HeifFile(path).image_size()
    except (OSError, struct.error, ValueError):
        return None, None


def heic_thumbnail(path, out_path=None):
    """导出内嵌缩略图。成功返回写出的文件路径，失败返回 None。"""
    try:
        hf = HeifFile(path)
    except (OSError, ValueError):
        return None
    th = hf.thumbnail()
    if not th:
        return None
    if out_path is None:
        base = os.path.splitext(str(path))[0]
        out_path = base + "_thumb.jpg"
    with open(out_path, "wb") as f:
        f.write(th["data"])
    return out_path


def export_thumbnail(path, out_path=None):
    return heic_thumbnail(path, out_path)


def is_live_photo(path):
    """是否为 Live Photo（结构 + 字符串证据）。"""
    try:
        return bool(HeifFile(path).live_photo_evidence())
    except (OSError, ValueError):
        return False


def heic_stats(directory, pattern=None, recursive=False):
    """目录批量统计：机型分组、前后置、Live Photo、AirDrop。"""
    exts = pattern or (".heic", ".heif", ".hif")
    files = []
    walker = os.walk(directory) if recursive else [(directory, [], os.listdir(directory))]
    for root, _dirs, names in walker:
        for n in names:
            if not n.lower().endswith(exts):
                continue
            full = os.path.join(root, n)
            if not os.path.isfile(full):
                continue
            files.append(full)
    files.sort()
    res = {"files": len(files), "models": {}, "positions": {"back": 0, "front": 0, "unknown": 0},
           "live_photo": 0, "airdrop": 0, "errors": [], "items": []}
    for p in files:
        md = heic_metadata(p)
        if "error" in md:
            res["errors"].append({"file": p, "error": md["error"]})
            continue
        model = md.get("model") or "(未知机型)"
        res["models"][model] = res["models"].get(model, 0) + 1
        res["positions"][md.get("camera_position", "unknown")] = \
            res["positions"].get(md.get("camera_position", "unknown"), 0) + 1
        if md.get("live_photo"):
            res["live_photo"] += 1
        if md.get("airdrop"):
            res["airdrop"] += 1
        res["items"].append({
            "file": os.path.basename(p), "model": md.get("model"),
            "width": md.get("width"), "height": md.get("height"),
            "datetime": md.get("datetime"), "fnumber": md.get("fnumber"),
            "focal_length": md.get("focal_length"),
            "live_photo": md.get("live_photo"), "airdrop": md.get("airdrop"),
            "camera_position": md.get("camera_position"),
        })
    return res


# ---------------------------------------------------------------------------
# BIP39
# ---------------------------------------------------------------------------

BIP39_URL = ("https://raw.githubusercontent.com/bitcoin/bips/master/"
             "bip-0039/english.txt")
_WORDLIST_CACHE = {}


def _wordlist_candidates():
    here = os.path.dirname(os.path.abspath(__file__))
    return [
        os.environ.get("MKIT_BIP39"),
        os.path.join(here, "bip39_english.txt"),
        os.path.join(here, os.pardir, "_corpus", "bip39_english.txt"),
        os.path.join(here, os.pardir, os.pardir, "_corpus", "bip39_english.txt"),
        os.path.join(os.getcwd(), "bip39_english.txt"),
        os.path.join(os.getcwd(), "_corpus", "bip39_english.txt"),
    ]


def load_bip39(path=None):
    """加载 BIP39 英文词表；返回 2048 词列表，找不到返回 None。"""
    cands = [path] if path else _wordlist_candidates()
    for c in cands:
        if not c:
            continue
        try:
            with open(c, "r", encoding="utf8") as f:
                words = [w.strip() for w in f if w.strip()]
        except OSError:
            continue
        if len(words) == 2048:
            _WORDLIST_CACHE["wl"] = words
            return words
    return _WORDLIST_CACHE.get("wl")


def _ensure_wordlist(wordlist):
    return wordlist or _WORDLIST_CACHE.get("wl") or load_bip39()


def entropy_to_mnemonic(entropy, wordlist=None):
    """熵（bytes）→ BIP39 助记词。"""
    wl = _ensure_wordlist(wordlist)
    if wl is None:
        raise ValueError("缺 BIP39 词表（load_bip39 失败）")
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("熵长度必须是 16/20/24/28/32 字节")
    bits = "".join(f"{b:08b}" for b in entropy)
    cs = len(bits) // 32
    h = hashlib.sha256(entropy).digest()
    bits += "".join(f"{b:08b}" for b in h)[:cs]
    return " ".join(wl[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def mnemonic_check(phrase, wordlist=None):
    """返回 (是否合法, 原因)。合法 = 词数正确 + 词在表内 + 校验和正确。"""
    words = str(phrase).split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False, "词数 %d 非法（应为 12/15/18/21/24）" % len(words)
    wl = _ensure_wordlist(wordlist)
    if wl is None:
        return False, "缺 BIP39 词表，无法校验（先 load_bip39）"
    idx = {w: i for i, w in enumerate(wl)}
    bad = [w for w in words if w not in idx]
    if bad:
        return False, "非词表词: %s" % ", ".join(bad[:5])
    bits = "".join(f"{idx[w]:011b}" for w in words)
    cs_len = len(bits) // 33
    ent_bits = bits[:len(bits) - cs_len]
    chk = bits[len(bits) - cs_len:]
    ent = int(ent_bits, 2).to_bytes(len(ent_bits) // 8, "big")
    expect = "".join(f"{b:08b}" for b in hashlib.sha256(ent).digest())[:cs_len]
    if chk != expect:
        return False, "校验和错误（期望 %s，实际 %s）" % (expect, chk)
    return True, "校验和正确（熵 %d bit）" % len(ent_bits)


def mnemonic_valid(phrase, wordlist=None):
    """助记词合法性（bool）。"""
    return mnemonic_check(phrase, wordlist)[0]


def mnemonic_to_seed(phrase, passphrase=""):
    """BIP39 种子（PBKDF2-HMAC-SHA512, 2048 轮, 64 字节）。"""
    m = " ".join(str(phrase).split())
    return hashlib.pbkdf2_hmac("sha512", m.encode("utf8"),
                               ("mnemonic" + passphrase).encode("utf8"), 2048, 64)


def extract_mnemonic_candidates(text, wordlist=None):
    """从任意文本里抓连续 12/15/18/21/24 个 BIP39 词（校验和过滤）。"""
    wl = _ensure_wordlist(wordlist)
    if wl is None:
        return []
    wset = set(wl)
    tokens = re.findall(r"[a-z]{3,8}", str(text).lower())
    out, seen = [], set()
    for n in (24, 21, 18, 15, 12):
        for i in range(max(0, len(tokens) - n + 1)):
            win = tokens[i:i + n]
            if not all(w in wset for w in win):
                continue
            cand = " ".join(win)
            if cand in seen:
                continue
            if mnemonic_valid(cand, wl):
                seen.add(cand)
                out.append(cand)
    return out


# ---------------------------------------------------------------------------
# 兼容层：旧的 keybag 入口转到 iosbackup_crypto
# ---------------------------------------------------------------------------

def decrypt_ios_backup_keybag(manifest_plist_bytes, password):
    """[兼容入口] 解 iOS 加密备份 keybag，返回 dict。"""
    from .iosbackup_crypto import BackupCrypto
    bc = BackupCrypto(manifest_plist_bytes)
    ok = bc.unlock(password)
    return {"ok": ok, "encrypted": bc.encrypted, "keybag": bc.keybag_info()}


def decrypt_ios_file(data, key, iv=None):
    """[兼容入口] AES-256-CBC 解单个文件（默认前 16 字节为 IV）。"""
    from .iosbackup_crypto import aes_cbc_decrypt
    return aes_cbc_decrypt(key, data, iv)


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) > 1:
        if os.path.isdir(sys.argv[1]):
            print(json.dumps(heic_stats(sys.argv[1]), ensure_ascii=False,
                             indent=2, default=str))
        else:
            print(json.dumps(heic_metadata(sys.argv[1]), ensure_ascii=False,
                             indent=2, default=str))
