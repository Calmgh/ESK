# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""自研 Windows 痕迹解析：LNK / Prefetch / USB / 回收站 / 用户辅助。

依赖：标准库 + 本包 mkit.regf（自研注册表）。
evtx 由 mkit.evtx 提供（自研 BinXML 解码），此处只做薄封装。
"""
import datetime
import os
import struct

FT_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime(v):
    if not v:
        return None
    try:
        return FT_EPOCH + datetime.timedelta(microseconds=int(v) / 10)
    except Exception:
        return None


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _ansi(b, o, n):
    return b[o:o + n].split(b"\x00")[0].decode("mbcs", "replace")


def _uni(b, o, n_chars):
    raw = b[o:o + n_chars * 2]
    try:
        return raw.decode("utf-16le").split("\x00")[0]
    except Exception:
        return ""


# ---------------- LNK ----------------
LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


class Lnk:
    def __init__(self, data, name=""):
        self.name = name
        self.data = data
        self.flags = 0
        self.target = None
        self.args = None
        self.workdir = None
        self.icon = None
        self.drive_serial = None
        self.drive_type = None
        self.machine_id = None
        self.droid_volume = None
        self.droid_file = None
        self.droid_net = None
        self.tracker = {}
        self.extra = {}
        self.parse()

    def parse(self):
        b = self.data
        if len(b) < 76 or _u32(b, 0) != 0x4C:
            raise ValueError("not a .lnk")
        self.flags = _u32(b, 0x14)
        has_idlist = bool(self.flags & 0x01)
        has_linkinfo = bool(self.flags & 0x02)
        has_name = bool(self.flags & 0x04)
        has_relpath = bool(self.flags & 0x08)
        has_workdir = bool(self.flags & 0x10)
        has_args = bool(self.flags & 0x20)
        has_icon = bool(self.flags & 0x40)
        off = 76
        if has_idlist:
            n = _u16(b, off)
            off += 2 + n
        if has_linkinfo:
            li_size = _u32(b, off)
            li = b[off:off + li_size]
            self._parse_linkinfo(li)
            off += li_size
        if has_name:
            n = _u16(b, off)
            self.extra["description"] = _uni(b, off + 2, n // 2)
            off += 2 + n
        if has_relpath:
            n = _u16(b, off)
            self.extra["relative_path"] = _uni(b, off + 2, n // 2)
            off += 2 + n
        if has_workdir:
            n = _u16(b, off)
            self.workdir = _uni(b, off + 2, n // 2)
            off += 2 + n
        if has_args:
            n = _u16(b, off)
            self.args = _uni(b, off + 2, n // 2)
            off += 2 + n
        if has_icon:
            n = _u16(b, off)
            self.icon = _uni(b, off + 2, n // 2)
            off += 2 + n
        self._parse_extra(b, off)

    def _parse_linkinfo(self, li):
        if len(li) < 0x24:
            return
        self.linkinfo_size = _u32(li, 0)
        self.linkinfo_flags = _u32(li, 8)
        self.droid_volume = filetime(_u64(li, 0x10))
        self.droid_file = filetime(_u64(li, 0x18))
        self.droid_net = filetime(_u64(li, 0x20))
        p = 0x24
        try:
            cnrl = _u32(li, 0x1C)
            if cnrl:
                if cnrl & 0x1:
                    p += 16
                if cnrl & 0x2:
                    p += 1 + li[p]
                offs = (_u32(li, 0x1C) >> 2)
                names = []
                p = 0x24
                while p < len(li) - 12:
                    if li[p] == 0:
                        break
                    bo = li[p]
                    if bo == 0x14:
                        p += 1 + 4 + 4 + 2 + 2 + 2 + 8 + 2 + 2
                    elif bo in (0x1F, 0x2F, 0x3F):
                        p += 1 + 8 + 8 + 2 + 2 + 2 + li[p + 1 + 8 + 8 + 2 + 2 + 1]
                    elif bo == 0x11:
                        p += 1 + 0
                        break
                    else:
                        break
        except Exception:
            pass
        try:
            if p + 2 <= len(li):
                self.drive_serial = _u32(li, p + 2)
                self.drive_type = _u32(li, p + 6)
            if p + 0x30 <= len(li):
                self.ip = _u32(li, p + 0x12)
                self.drive_type = _u32(li, p + 0x1A)
        except Exception:
            pass
        # Unicode local base path 在 LinkInfo 尾部（含 0x1C 之后），直接用标志位与长度
        try:
            flag_hdr = _u32(li, 0)
            off = 0x24
            # LocalBasePath 以 UTF-16 结尾：取最后一个可打印 run 作为兜底
            txt = li[0x24:].decode("utf-16le", "ignore").split("\x00")[0]
            if txt and len(txt) > 2:
                self.target_unverified = txt
        except Exception:
            pass

    def _parse_extra(self, b, off):
        while off + 8 <= len(b):
            size = _u32(b, off)
            sig = b[off + 4: off + 8]
            block = b[off + 8: off + size]
            if size < 8:
                break
            name = {
                b"\x1a\x00\x00\x00": "TrackerData",
                b"\x1f\x00\x00\x00": "IconEnv",
                b"\x32\x00\x00\x00": "ConsoleProbe",
                b"\x40\x00\x00\x00": "KnownFolder",
                b"\xa0\x00\x00\x00": "EnvironmentVariable",
                b"\xc0\x00\x00\x00": "CommandLine",
                b"\xb1\x00\x00\x00": "IconLocation",
                b"\x1c\x00\x00\x00": "ShimData",
                b"\x03\x00\x00\x00": "SpecialFolder",
                b"\x01\x00\x00\x00": "Darwin",
                b"\x02\x00\x00\x00": "IconEnv2",
            }.get(sig, sig.hex())
            if sig == b"\x1a\x00\x00\x00" and len(block) >= 96:
                cb = _u32(block, 0)
                self.machine_id = block[16:32].split(b"\x00")[0].decode("latin1")
                self.droid_volume = filetime(_u64(block, 32)) or self.droid_volume
                self.droid_file = filetime(_u64(block, 40)) or self.droid_file
                if len(block) >= 88:
                    self.mac_address = block[72:78].hex(":")
            self.extra.setdefault(name, []).append(block)
            off += size

    def to_dict(self):
        return dict(name=self.name, target=self.local_base_path() or getattr(self, "target_unverified", None),
                    args=self.args, workdir=self.workdir, icon=self.icon,
                    drive_serial=f"0x{self.drive_serial:08X}" if self.drive_serial else None,
                    drive_type=self.drive_type, machine_id=self.machine_id,
                    mac=getattr(self, "mac_address", None),
                    ctime=self.droid_file, atime=self.droid_volume, mtime=self.droid_file,
                    extra_list=sorted(self.extra.keys()))

    def local_base_path(self):
        blocks = self.extra.get("EnvironmentVariable") or []
        for blk in blocks:
            if len(blk) > 260:
                return _ansi(blk, 0, 260)
        return None


# ---------------- Prefetch ----------------
class Prefetch:
    def __init__(self, data, name=""):
        self.name = name
        self.raw = data
        self.version = 0
        self.exe = None
        self.hash = None
        self.run_count = 0
        self.last_run = None
        self.run_times = []
        self.volumes = []
        self.files = []
        self.dirs = []
        self.parse()

    def parse(self):
        b = self.raw
        if len(b) < 0x54:
            raise ValueError("too small")
        self.version = _u32(b, 0)
        body = b
        if self.version == 0x11:
            self.exe = _uni(b, 0x10, 60)
            self.hash = _u32(b, 0x7C)
            self.run_count = _u32(b, 0x90)
        elif self.version in (0x17,):
            self.exe = _uni(b, 0x10, 60)
            self.hash = _u32(b, 0x7C)
            self.run_count = _u32(b, 0x98)
            self.last_run = filetime(_u64(b, 0x80))
        elif self.version >= 0x1A:  # 23 (Win7) / 26 / 30 / 31
            self.mam = b[:4] == b"MAM\x04"
            if self.mam:
                b = _mam_decompress(b)
                self.decompressed = b
            sig = b[4:8] if len(b) >= 8 else b""
            if sig == b"SCCA":
                b = _xpress_huffman(b[0x54:])
                self.decompressed = b
            if len(b) < 0x54 or _u32(b, 0) not in (0x11, 0x17, 0x1A, 0x1E, 0x1F, 0x26):
                # 解压失败：保留原始，标记 unsupported，不抛异常
                self.version = _u32(self.raw, 0) if len(self.raw) >= 4 else 0
                self.unsupported = True
                self.exe = None
                self.hash = None
                self.run_count = 0
                return
            self.version = _u32(b, 0)
            self.exe = _uni(b, 0x10, 30)
            self.hash = _u32(b, 0x4C)
            self.run_count = _u32(b, 0xD0) if len(b) > 0xD4 else 0
            if len(b) > 0x88:
                self.last_run = filetime(_u64(b, 0x80))
        self.first_run = None
        if self.version >= 0x1A and len(b) > 0xD8:
            n = _u32(b, 0xD4)
            for i in range(min(n, 8)):
                ft = _u64(b, 0xD8 + i * 8)
                if ft:
                    self.run_times.append(filetime(ft))
        self.file_size = len(self.raw)
        self.volumes = self._volumes(b)
        self._file_strings(b)

    def _mam_decompress(self, data):
        return _xpress_huffman(data)

    def _volumes(self, b):
        out = []
        try:
            if self.version == 0x17:
                off = _u32(b, 0x84)
                count = _u32(b, 0x88)
                p = off + 0x28 * 0
            else:
                off = _u32(b, 0x54) if len(b) > 0x58 else 0
                count = _u32(b, 0x58) if len(b) > 0x5C else 0
                p = off
            for i in range(min(count, 16)):
                rec = b[p + i * 0x60: p + (i + 1) * 0x60]
                if len(rec) < 0x60:
                    break
                dev_off = _u32(rec, 0)
                ctime = filetime(_u64(rec, 0x14))
                serial = _u32(rec, 0x7C & 0xFF) if False else None
                name = None
                if dev_off:
                    raw = b[off + dev_off: off + dev_off + 104]
                    name = _uni(raw, 0, 52).rstrip("\x00")
                out.append(dict(path=name, created=ctime))
        except Exception:
            pass
        return out

    def _file_strings(self, b):
        try:
            txt = b[0x100:].decode("utf-16le", "ignore")
            parts = [p for p in txt.split("\x00") if len(p) > 3 and "\\" in p]
            self.files = parts[:400]
        except Exception:
            pass

    def to_dict(self):
        return dict(name=self.name, version=hex(self.version), exe=self.exe,
                    hash=f"{self.hash:08X}" if self.hash else None,
                    run_count=self.run_count,
                    last_run=str(self.last_run) if self.last_run else None,
                    run_times=[str(t) for t in self.run_times],
                    volumes=self.volumes, file_count=len(self.files))


def _build_lengths(huff, variant):
    """按不同解释生成 512 个符号的码长，供自校验后择优。"""
    lengths = []
    if variant == "hi_lo_same":
        for i in range(256):
            b = huff[i]
            lengths += [i + 1] * (b >> 4)
            lengths += [i + 1] * (b & 0x0F)
    elif variant == "lo_hi_same":
        for i in range(256):
            b = huff[i]
            lengths += [i + 1] * (b & 0x0F)
            lengths += [i + 1] * (b >> 4)
    elif variant == "hi_len_lo_len16":
        for i in range(256):
            b = huff[i]
            lengths += [i + 1] * (b >> 4)
            lengths += [i + 1 + 16] * (b & 0x0F)
    else:
        for i in range(256):
            b = huff[i]
            lengths += [i + 1] * (b >> 4)
            lengths += [i + 17] * (b & 0x0F)
    return lengths


def _decode_with_lengths(data, lengths):
    huff = data[:256]
    if len(data) < 260:
        return b""
    table = {}
    code = 0
    prev_len = 0
    sym_idx = 0
    for ln in lengths:
        if ln <= 0:
            sym_idx += 1
            continue
        if ln > 32:
            return b""
        code <<= (ln - prev_len) if prev_len else ln
        table[(ln, code)] = sym_idx
        code += 1
        prev_len = ln
        sym_idx += 1
    dlen = len(data)
    p = 256
    out = bytearray()
    bitbuf = 0
    bitcnt = 0

    def getbit():
        nonlocal bitbuf, bitcnt, p
        if bitcnt == 0:
            if p >= dlen:
                return -1
            bitbuf = data[p]
            p += 1
            bitcnt = 8
        bitcnt -= 1
        return (bitbuf >> bitcnt) & 1

    cur = 0
    ln = 0
    while len(out) < (1 << 24):
        sym = None
        while ln < 16:
            b = getbit()
            if b < 0:
                return bytes(out)
            cur = (cur << 1) | b
            ln += 1
            if (ln, cur) in table:
                sym = table[(ln, cur)]
                break
        if sym is None:
            return bytes(out)
        cur = 0
        ln = 0
        if sym < 256:
            out.append(sym)
            continue
        s = sym - 256
        extra = s & 0x0F
        base = s >> 4
        v = 0
        for _ in range(extra):
            b = getbit()
            if b < 0:
                return bytes(out)
            v = (v << 1) | b
        match_len = (base << 4) + v + 3
        hi = 0
        for _ in range(extra):
            b = getbit()
            if b < 0:
                return bytes(out)
            hi = (hi << 1) | b
        lo = 0
        for _ in range(8):
            b = getbit()
            if b < 0:
                return bytes(out)
            lo = (lo << 1) | b
        offset = (hi << 8) | lo
        if offset + 1 > len(out):
            return bytes(out)
        start = len(out) - offset - 1
        for i in range(match_len):
            out.append(out[start + i])
        if p >= dlen:
            return bytes(out)
    return bytes(out)


def _plausible_pf(blob):
    """解压结果自校验：版本号 + 可读 exe 名。"""
    if len(blob) < 0x100:
        return False
    ver = struct.unpack_from("<I", blob, 0)[0]
    if ver not in (0x11, 0x17, 0x1A, 0x1E, 0x1F, 0x23, 0x26, 0x1A):
        return False
    raw = blob[0x10:0x10 + 60].decode("utf-16le", "ignore")
    name = raw.split("\x00")[0]
    return len(name) > 2 and all(31 < ord(c) < 127 for c in name)


def _xpress_chunk(chunk, expected):
    """尽力解一个 chunk：择优标准 = 解出长度等于 expected。"""
    if len(chunk) < 260:
        return b""
    huff = chunk[:256]
    best = b""
    for variant in ("hi_lo_same", "lo_hi_same", "hi_len_lo_len16", "hi_len_lo_len17"):
        try:
            blob = _decode_with_lengths(chunk, _build_lengths(huff, variant))
        except Exception:
            continue
        if not blob:
            continue
        if expected and len(blob) == expected:
            return blob
        if expected and len(blob) >= expected and not best:
            best = blob[:expected]
        elif not best:
            best = blob
    if expected and len(best) > expected:
        best = best[:expected]
    return best


def _mam_decompress(data):
    """MAM 容器：'MAM\\x04' + 总长 + 块数 + 块表 + 逐块 XPRESS Huffman。"""
    if data[:4] != b"MAM\x04" or len(data) < 12:
        return data
    total, = struct.unpack_from("<I", data, 4)
    nchunks, = struct.unpack_from("<I", data, 8)
    p = 12
    table = []
    for _ in range(min(nchunks, 1 << 20)):
        if p + 8 > len(data):
            break
        csz, dsz = struct.unpack_from("<II", data, p)
        p += 8
        table.append((csz, dsz))
    out = bytearray()
    for csz, dsz in table:
        chunk = data[p:p + csz]
        p += csz
        out += _xpress_chunk(chunk, dsz)
        if len(out) >= total and total:
            break
    if total and len(out) > total:
        out = out[:total]
    return bytes(out)


def _xpress_huffman(data):
    """兼容入口：MAM 或裸 XPRESS Huffman。"""
    if data[:4] == b"MAM\x04":
        return _mam_decompress(data)
    return _xpress_chunk(data, 0)


# ---------------- USB / 回收站 ----------------
class UsbHistory:
    def __init__(self, hive):
        self.hive = hive
        self.devices = []
        self.mounted = {}
        self.parse()

    def parse(self):
        k = self.hive.open(r"ControlSet001\Enum\USBSTOR") or self.hive.open(r"CurrentControlSet\Enum\USBSTOR")
        if k:
            for dev_cls in k.subkeys():
                for serial in dev_cls.subkeys():
                    info = {}
                    v = serial.values()
                    for nm in ("FriendlyName", "DeviceDesc", "Mfg", "ParentIdPrefix", "Service"):
                        if nm in v:
                            val = v[nm][1]
                            if isinstance(val, bytes):
                                val = val.decode("utf-16le", "ignore").rstrip("\x00")
                            info[nm] = val
                    self.devices.append(dict(device=dev_cls.name, serial=serial.name, **info))
        try:
            md = self.hive.open(r"MountedDevices")
            if md:
                for name, (vt, val) in md.values().items():
                    self.mounted[name] = val.hex() if isinstance(val, bytes) else val
        except Exception:
            pass

    def to_list(self):
        return self.devices


class RecycleBin:
    """解析 $Recycle.Bin 的 $I 文件（Win10 格式）。"""

    def __init__(self, data, name=""):
        self.name = name
        self.size = None
        self.original_path = None
        self.deleted_at = None
        if len(data) >= 28:
            self.header = _u64(data, 0)
            self.size = _u64(data, 8)
            self.deleted_at = filetime(_u64(data, 16))
            try:
                self.original_path = data[28:].decode("utf-16le", "ignore").split("\x00\x00")[0].rstrip("\x00")
            except Exception:
                pass

    def to_dict(self):
        return dict(name=self.name, size=self.size, deleted=str(self.deleted_at) if self.deleted_at else None,
                    path=self.original_path)


# ---------------- EVTX 薄封装 ----------------
def evtx_records(path_or_bytes):
    """优先用自研 mkit.evtx；没有就用 dissect.eventlog 兜底（标注来源）。"""
    try:
        from mkit.evtx import Evtx
        if isinstance(path_or_bytes, (bytes, bytearray)):
            e = Evtx(bytes(path_or_bytes))
        else:
            with open(path_or_bytes, "rb") as f:
                e = Evtx(f.read())
        return [r for r in e.records()], "self"
    except Exception:
        pass
    try:
        from dissect.eventlog.evtx import Evtx as DEvtx
        data = path_or_bytes
        if not isinstance(data, (bytes, bytearray)):
            with open(path_or_bytes, "rb") as f:
                data = f.read()
        import io
        out = []
        for rec in DEvtx(io.BytesIO(data)):
            out.append(dict(record_id=getattr(rec, "record_num", None),
                            event_id=None, data=rec))
        return out, "dissect"
    except Exception as e:
        return [], f"unavailable: {e}"
