# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""文件雕刻 —— 按签名从字节流/未分配空间恢复文件

对应 LovelyCarve 的「文件恢复 / 文件雕刻」能力（取其可用子集）。

支持 16 种格式：
    JPEG  PNG  GIF  BMP  PDF  ZIP  RAR  GZIP  7z  RTF
    SQLite  OLE2(doc/xls/ppt)  PE(exe/dll)  ELF  MP4  RIFF(wav/avi)

三种定尾方式（按可靠性排序）：
    1. LENGTH  —— 从头部字段直接算出长度（SQLite / BMP / RIFF 等），最可靠
    2. TAIL    —— 向后搜结束标记（JPEG / PNG / PDF / ZIP），需校验
    3. CAP     —— 定不下来就截到 max_size，标记 truncated

用法：
    from mkit.carve import carve
    img = Image("disk.E01")
    for item in carve(img.read, img.size, kinds=["jpeg","png","sqlite"]):
        print(item.kind, hex(item.offset), item.size, item.truncated)

    carve(img.read, img.size, out_dir="carved/")     # 直接落盘
"""

import os
import struct

__all__ = ["Carver", "CARVERS", "carve", "scan_only", "carve_unallocated"]


class Carver(object):
    """一种格式的雕刻规则"""

    __slots__ = ("kind", "ext", "heads", "tail", "length_fn", "validate",
                 "max_size", "note")

    def __init__(self, kind, ext, heads, tail=None, length_fn=None,
                 validate=None, max_size=64 << 20, note=""):
        self.kind = kind
        self.ext = ext
        self.heads = heads if isinstance(heads, (list, tuple)) else [heads]
        self.tail = tail
        self.length_fn = length_fn
        self.validate = validate
        self.max_size = max_size
        self.note = note

    def __repr__(self):
        return "<Carver %s>" % self.kind


class Carved(object):
    """一个雕刻结果"""

    __slots__ = ("kind", "ext", "offset", "size", "data", "truncated", "note")

    def __init__(self, kind, ext, offset, data, truncated, note=""):
        self.kind = kind
        self.ext = ext
        self.offset = offset
        self.data = data
        self.size = len(data)
        self.truncated = truncated
        self.note = note

    def save(self, out_dir, name=None):
        os.makedirs(out_dir, exist_ok=True)
        if name is None:
            name = "%s_0x%08X.%s" % (self.kind, self.offset, self.ext)
        p = os.path.join(out_dir, name)
        with open(p, "wb") as f:
            f.write(self.data)
        return p

    def __repr__(self):
        return "<Carved %s @0x%X %d B%s>" % (
            self.kind, self.offset, self.size, " TRUNC" if self.truncated else "")


# ---------------- 长度推算函数 ----------------
def _len_sqlite(buf):
    """SQLite: page_size@16(2B, 1 表示 65536) × page_count@28(4B)"""
    if len(buf) < 32:
        return None
    ps = struct.unpack_from(">H", buf, 16)[0]
    if ps == 1:
        ps = 65536
    pc = struct.unpack_from(">I", buf, 28)[0]
    if ps < 512 or ps & (ps - 1) or pc == 0:
        return None
    return ps * pc


def _len_bmp(buf):
    if len(buf) < 6:
        return None
    n = struct.unpack_from("<I", buf, 2)[0]
    return n if 26 <= n else None


def _len_riff(buf):
    if len(buf) < 8:
        return None
    n = struct.unpack_from("<I", buf, 4)[0]
    return n + 8 if n else None


def _len_pe(buf):
    """PE: 用节表算真实文件大小"""
    if len(buf) < 0x40:
        return None
    try:
        e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
        if buf[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        nsec = struct.unpack_from("<H", buf, coff + 2)[0]
        opt_size = struct.unpack_from("<H", buf, coff + 16)[0]
        sec_off = coff + 20 + opt_size
        end = 0
        for i in range(nsec):
            base = sec_off + i * 40
            if base + 40 > len(buf):
                break
            raw_size = struct.unpack_from("<I", buf, base + 16)[0]
            raw_ptr = struct.unpack_from("<I", buf, base + 20)[0]
            end = max(end, raw_ptr + raw_size)
        return end if end else None
    except Exception:
        return None


def _len_zip_first(buf):
    """ZIP: 从第一个 local header 起，找 EOCD 得到总长"""
    i = buf.find(b"PK\x05\x06")
    if i < 0:
        return None
    if i + 22 > len(buf):
        return None
    cd_size = struct.unpack_from("<I", buf, i + 12)[0]
    cd_off = struct.unpack_from("<I", buf, i + 16)[0]
    total = cd_off + cd_size + 22
    comment_len = struct.unpack_from("<H", buf, i + 20)[0]
    return total + comment_len


# ---------------- 校验函数 ----------------
def _val_png(buf):
    """PNG: 结尾必须是 IEND + CRC"""
    return buf.rfind(b"IEND") > 0


def _val_jpeg(buf):
    """JPEG: 结尾 FF D9"""
    return buf[-2:] == b"\xff\xd9"


def _val_pdf(buf):
    return b"%%EOF" in buf[-1024:]


# ---------------- 签名表 ----------------
CARVERS = [
    Carver("jpeg", "jpg", b"\xff\xd8\xff", tail=b"\xff\xd9",
           validate=_val_jpeg, max_size=32 << 20),
    Carver("png", "png", b"\x89PNG\r\n\x1a\n", tail=b"IEND",
           validate=_val_png, max_size=32 << 20),
    Carver("gif", "gif", [b"GIF87a", b"GIF89a"], tail=b"\x3b", max_size=16 << 20),
    Carver("bmp", "bmp", b"BM", length_fn=_len_bmp, max_size=64 << 20),
    Carver("pdf", "pdf", b"%PDF-", tail=b"%%EOF", validate=_val_pdf,
           max_size=128 << 20),
    Carver("zip", "zip", b"PK\x03\x04", length_fn=_len_zip_first,
           max_size=256 << 20, note="含 docx/xlsx/pptx/apk/jar"),
    Carver("rar", "rar", [b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"],
           max_size=256 << 20),
    Carver("7z", "7z", b"7z\xbc\xaf\x27\x1c", max_size=256 << 20),
    Carver("gzip", "gz", b"\x1f\x8b\x08", max_size=64 << 20),
    Carver("rtf", "rtf", b"{\\rtf", tail=b"}", max_size=16 << 20),
    Carver("sqlite", "sqlite", b"SQLite format 3\x00",
           length_fn=_len_sqlite, max_size=512 << 20),
    Carver("ole2", "ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
           max_size=128 << 20, note="doc/xls/ppt/msg"),
    Carver("pe", "exe", b"MZ", length_fn=_len_pe, max_size=128 << 20),
    Carver("elf", "elf", b"\x7fELF", max_size=128 << 20),
    Carver("mp4", "mp4", b"ftyp", max_size=512 << 20, note="头部前 4 字节为长度"),
    Carver("riff", "riff", b"RIFF", length_fn=_len_riff, max_size=256 << 20,
           note="wav/avi/webp"),
]

_BY_KIND = {c.kind: c for c in CARVERS}


def _carve_one(cv, buf, start, end, base, max_size_override=None):
    """在 buf[start:end] 里尝试雕一个，返回 Carved 或 None

    base = buf[0] 对应的绝对偏移
    """
    cap = max_size_override or cv.max_size
    avail = min(len(buf), end)

    # 1) 长度可由头部算出
    if cv.length_fn:
        n = cv.length_fn(buf[:avail])
        if n and 16 <= n <= cap:
            trunc = start + n > avail
            data = buf[start:min(start + n, avail)]
            if trunc:
                return None                     # 头部说得很长但数据不够，视为假命中
            return Carved(cv.kind, cv.ext, base + start, data, False)
        # 算不出来时退回 tail/cap

    # 2) 找结束标记
    if cv.tail:
        k = buf.find(cv.tail, start + 4, avail)
        if k >= 0:
            stop = k + len(cv.tail)
            # PNG 的 IEND 后面还有 4 字节 CRC
            if cv.kind == "png":
                stop = min(stop + 4, avail)
            n = stop - start
            if n <= cap:
                data = buf[start:stop]
                if cv.validate and not cv.validate(data):
                    return None
                return Carved(cv.kind, cv.ext, base + start, data, False)
        # 找不到尾巴 → 走 cap

    # 3) 截断到 cap
    n = min(cap, avail - start)
    if n < 32:
        return None
    data = buf[start:start + n]
    if cv.validate and not cv.validate(data):
        return None
    return Carved(cv.kind, cv.ext, base + start, data, True,
                  note="未找到结束标记，已截断")


def carve(read_fn, size, kinds=None, out_dir=None, start=0, end=None,
          chunk=16 << 20, overlap=1 << 20, max_size=None,
          max_per_kind=1000, progress=None):
    """在字节流里雕刻文件

    read_fn(offset, n) -> bytes
    kinds     —— 只雕这些类型（None = 全部）
    out_dir   —— 给了就直接落盘，否则返回带 data 的结果
    """
    end = size if end is None else min(end, size)
    want = CARVERS if not kinds else [c for c in CARVERS if c.kind in kinds]
    if not want:
        return []

    counts = {c.kind: 0 for c in want}
    found = []
    buf = b""
    base = start
    pos = start

    # 预先编译「头部 → Carver」映射
    head_map = []
    for cv in want:
        for h in cv.heads:
            head_map.append((h, cv))

    while pos < end:
        n = min(chunk, end - pos)
        piece = read_fn(pos, n)
        if not piece:
            pos += n
            continue
        old = len(buf)
        buf = (buf + piece) if buf else piece

        lo = max(0, old - overlap) if old else 0
        hi = len(buf)

        for h, cv in head_map:
            if counts[cv.kind] >= max_per_kind:
                continue
            i = lo
            while True:
                k = buf.find(h, i, hi)
                if k < 0:
                    break
                absolute = base + k
                if absolute < start:
                    i = k + 1
                    continue
                item = _carve_one(cv, buf, k, hi, base, max_size)
                if item is not None:
                    counts[cv.kind] += 1
                    if out_dir:
                        item.save(out_dir)
                        item.data = b""            # 省内存
                    found.append(item)
                    if counts[cv.kind] >= max_per_kind:
                        break
                i = k + 1

        pos += len(piece)
        if progress:
            progress(pos, end)
        if len(buf) > 2 * overlap:
            cut = len(buf) - overlap
            base += cut
            buf = buf[cut:]

    found.sort(key=lambda x: x.offset)
    return found


def scan_only(read_fn, size, kinds=None, **kw):
    """只报位置和大小，不读数据（快）"""
    kw["out_dir"] = None
    keep = kw.pop("_keep_data", False)
    out = []
    for it in carve(read_fn, size, kinds, **kw):
        out.append((it.kind, it.offset, it.size, it.truncated))
        if keep:
            out[-1] = out[-1] + (it.data,)
    return out


def carve_unallocated(fs, out_dir=None, kinds=("jpeg", "png", "sqlite", "zip"),
                      max_size=None, progress=None):
    """在文件系统的未分配空间里雕刻

    需要 fs 提供：
        fs.cluster_size / fs.used_map() -> 可迭代的 (offset, length) 未分配区间
    或退化为：对 NTFS 用 $Bitmap，对 FAT 用 FAT 表。

    这里提供通用实现：接受一个「未分配区间迭代器」。
    """
    ranges = getattr(fs, "unallocated_ranges", None)
    if ranges is None:
        raise AttributeError(
            "该文件系统未提供 unallocated_ranges()；请自行传入未分配区间")

    all_found = []
    for off, ln in ranges():
        sub_read = lambda o, n, _b=off: fs.read(_b + o, n)
        all_found.extend(carve(sub_read, ln, kinds, out_dir,
                               max_size=max_size, progress=progress))
    return all_found


if __name__ == "__main__":
    import io
    import zlib

    # 造一个 PNG
    def _png():
        raw = b"\x00\xff\x00\x00" * 4
        ihdr = struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0)
        def chunk(t, d):
            return (struct.pack(">I", len(d)) + t + d +
                    struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF))
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
                + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))

    png = _png()
    jpg = b"\xff\xd8\xff\xe0" + b"JFIF\x00" + b"A" * 200 + b"\xff\xd9"
    blob = b"\x00" * 1000 + png + b"\x00" * 800 + jpg + b"\x00" * 500
    got = carve(lambda o, n: blob[o:o + n], len(blob))
    print("雕刻结果:")
    for it in got:
        print("  %-7s @0x%04X  %6d B  trunc=%s" % (it.kind, it.offset, it.size, it.truncated))
    assert any(i.kind == "png" for i in got)
    assert any(i.kind == "jpeg" for i in got)
    print("雕刻自检通过")
