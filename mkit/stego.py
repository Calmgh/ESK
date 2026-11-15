# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""stego.py —— 隐写 / 二维码 / 图片容器取证（纯标准库，自研实现）

    * lsb_scan          : PNG/BMP 像素级 LSB 分析（位平面熵、卡方、字节熵）+ 按 LSB 顺序提取并识别载荷
    * appended_data     : 结构级真末尾定位（JPEG 到 EOI、PNG 到 IEND、GIF 到 0x3B、PDF 到 %%EOF、ZIP 到 EOCD）并 dump
    * embedded_archives : 全文件魔数扫描（ZIP/7z/RAR/PDF/PE/OLE/GZIP/XZ/BZ2/SQLite/ELF/Mach-O/TAR）
    * exif_all          : 自研 JPEG APP1 / TIFF IFD / PNG eXIf 解析，含 GPS 度分秒换算、缩略图、PS 改图判定
    * qr_decode         : 优先 pyzbar（可选），必带自研 qr_matrix_extract（二值化 + 定位图案 + 仿射抽样）
    * png_chunks        : chunk 列表 + CRC 校验 + 异常标注（tEXt 藏文本、多 IEND、IEND 后数据、非标准名）
    * strings_utf16     : UTF-16LE/BE 字符串提取（对齐 + 非对齐两遍扫描）

像素读取为自研 PNG(含 Adam7 隔行)/BMP/PPM 解码；JPEG/GIF 像素仅在装了 Pillow 时借其解码，
EXIF 与容器结构解析完全不依赖 Pillow / pyzbar。
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import zlib

__all__ = [
    "lsb_scan", "appended_data", "embedded_archives", "exif_all",
    "qr_decode", "qr_matrix_extract", "matrix_to_ascii",
    "png_chunks", "strings_utf16", "load_pixels", "gps_decimal", "MAGICS",
]

PNG_SIG = b"\x89PNG\r\n\x1a\n"


# ---------------------------------------------------------------------------
# 像素读取：PNG / BMP / PPM 自研解码
# ---------------------------------------------------------------------------

_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
          (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))

_PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def _paeth(a, b, c):
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _unfilter(data, pos, width, height, bpp, stride):
    """PNG 反滤波，返回 (rows, newpos)。"""
    rows = []
    prev = bytearray(stride)
    for _ in range(height):
        if pos >= len(data):
            raise ValueError("PNG: truncated image data")
        ft = data[pos]
        pos += 1
        line = bytearray(data[pos:pos + stride])
        if len(line) != stride:
            raise ValueError("PNG: truncated scanline")
        pos += stride
        if ft == 0:
            pass
        elif ft == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ft == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                upleft = prev[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + _paeth(left, prev[i], upleft)) & 0xFF
        else:
            raise ValueError("PNG: bad filter type %d" % ft)
        rows.append(bytes(line))
        prev = line
    return rows, pos


def _decode_png(raw):
    if raw[:8] != PNG_SIG:
        raise ValueError("not a PNG")
    pos = 8
    ihdr = None
    idat = []
    plte = None
    while pos + 12 <= len(raw):
        ln = struct.unpack_from(">I", raw, pos)[0]
        typ = raw[pos + 4:pos + 8]
        data = raw[pos + 8:pos + 8 + ln]
        pos += 12 + ln
        if typ == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", data[:13])
        elif typ == b"PLTE":
            plte = data
        elif typ == b"IDAT":
            idat.append(data)
        elif typ == b"IEND":
            break
    if ihdr is None:
        raise ValueError("PNG: no IHDR")
    w, h, bd, ct, comp, filt, inter = ihdr
    if ct not in _PNG_CHANNELS:
        raise ValueError("PNG: bad color type %d" % ct)
    if bd not in (1, 2, 4, 8, 16):
        raise ValueError("PNG: bad bit depth %d" % bd)
    raw_img = zlib.decompress(b"".join(idat))
    ch = _PNG_CHANNELS[ct]
    bits_pp = bd * ch
    bpp = max(1, (bits_pp + 7) // 8)
    rgb = bytearray(w * h * 3)
    maxv = (1 << bd) - 1

    def put(x, y, sx):
        if bd == 16:
            base = x * ch * 2
            vals = [sx[base + k * 2] for k in range(ch)]
        elif bd == 8:
            base = x * ch
            vals = [sx[base + k] for k in range(ch)]
        else:
            per = 8 // bd
            idx_in = x // per
            shift = 8 - bd * ((x % per) + 1)
            if idx_in >= len(sx):
                return
            vals = [(sx[idx_in] >> shift) & maxv]
        if ct == 0:
            g = vals[0] * 255 // maxv if bd < 8 else vals[0]
            r = gg = b = g
        elif ct == 2:
            r, gg, b = vals[0], vals[1], vals[2]
        elif ct == 3:
            pi = vals[0]
            if plte is None or pi * 3 + 2 >= len(plte):
                r = gg = b = 0
            else:
                r, gg, b = plte[pi * 3], plte[pi * 3 + 1], plte[pi * 3 + 2]
        elif ct == 4:
            g = vals[0]
            r = gg = b = g
        else:
            r, gg, b = vals[0], vals[1], vals[2]
        o = (y * w + x) * 3
        rgb[o] = r
        rgb[o + 1] = gg
        rgb[o + 2] = b

    if inter == 0:
        stride = (w * bits_pp + 7) // 8
        rows, _ = _unfilter(raw_img, 0, w, h, bpp, stride)
        for y, row in enumerate(rows):
            for x in range(w):
                put(x, y, row)
    else:
        p2 = 0
        for (xoff, yoff, xstep, ystep) in _ADAM7:
            pw = (w - xoff + xstep - 1) // xstep
            ph = (h - yoff + ystep - 1) // ystep
            if pw <= 0 or ph <= 0:
                continue
            stride = (pw * bits_pp + 7) // 8
            rows, p2 = _unfilter(raw_img, p2, pw, ph, bpp, stride)
            for ry, row in enumerate(rows):
                for rx in range(pw):
                    put(xoff + rx * xstep, yoff + ry * ystep, row)
    return {"format": "PNG", "width": w, "height": h, "bit_depth": bd,
            "color_type": ct, "interlaced": bool(inter), "rgb": rgb}


def _decode_bmp(raw):
    if raw[:2] != b"BM":
        raise ValueError("not a BMP")
    data_off = struct.unpack_from("<I", raw, 10)[0]
    hdr_size = struct.unpack_from("<I", raw, 14)[0]
    w = struct.unpack_from("<i", raw, 18)[0]
    h = struct.unpack_from("<i", raw, 22)[0]
    bpp = struct.unpack_from("<H", raw, 28)[0]
    comp = struct.unpack_from("<I", raw, 30)[0]
    top_down = h < 0
    h = abs(h)
    if w <= 0 or h <= 0:
        raise ValueError("BMP: bad dimensions")
    rgb = bytearray(w * h * 3)

    def offset(x, y):
        yy = y if top_down else (h - 1 - y)
        return (yy * w + x) * 3

    if bpp in (24, 32) and comp in (0, 3, 6):
        stride = ((w * bpp + 31) // 32) * 4
        step = bpp // 8
        for y in range(h):
            base = data_off + y * stride
            for x in range(w):
                p = base + x * step
                if p + 2 >= len(raw):
                    continue
                o = offset(x, y)
                rgb[o] = raw[p + 2]
                rgb[o + 1] = raw[p + 1]
                rgb[o + 2] = raw[p]
    elif bpp == 8 and comp == 0:
        stride = ((w * 8 + 31) // 32) * 4
        pal_off = 14 + hdr_size
        ncol = int((data_off - pal_off) // 4)
        ncol = min(256, ncol) if ncol > 0 else 256
        palette = []
        for i in range(ncol):
            p = pal_off + i * 4
            if p + 2 >= len(raw):
                break
            palette.append((raw[p + 2], raw[p + 1], raw[p]))
        for y in range(h):
            base = data_off + y * stride
            for x in range(w):
                p = base + x
                if p >= len(raw):
                    continue
                idx = raw[p]
                c = palette[idx] if idx < len(palette) else (0, 0, 0)
                o = offset(x, y)
                rgb[o], rgb[o + 1], rgb[o + 2] = c
    elif bpp == 16 and comp in (0, 3):
        stride = ((w * 16 + 31) // 32) * 4
        for y in range(h):
            base = data_off + y * stride
            for x in range(w):
                p = base + x * 2
                if p + 1 >= len(raw):
                    continue
                v = raw[p] | (raw[p + 1] << 8)
                o = offset(x, y)
                rgb[o] = ((v >> 10) & 0x1F) * 255 // 31
                rgb[o + 1] = ((v >> 5) & 0x1F) * 255 // 31
                rgb[o + 2] = (v & 0x1F) * 255 // 31
    else:
        raise ValueError("BMP: unsupported bpp=%d comp=%d" % (bpp, comp))
    return {"format": "BMP", "width": w, "height": h, "bit_depth": bpp,
            "color_type": bpp, "interlaced": False, "rgb": rgb}


def _decode_ppm(raw):
    if raw[:2] not in (b"P5", b"P6"):
        raise ValueError("not a PPM/PGM")
    parts = []
    i = 2
    while len(parts) < 3:
        while i < len(raw) and raw[i:i + 1].isspace():
            i += 1
        if raw[i:i + 1] == b"#":
            while i < len(raw) and raw[i] not in (10, 13):
                i += 1
            continue
        j = i
        while j < len(raw) and not raw[j:j + 1].isspace():
            j += 1
        parts.append(int(raw[i:j]))
        i = j
    i += 1
    w, h, maxv = parts
    ch = 3 if raw[:2] == b"P6" else 1
    rgb = bytearray(w * h * 3)
    for y in range(h):
        for x in range(w):
            p = i + (y * w + x) * ch
            if p + ch - 1 >= len(raw):
                break
            o = (y * w + x) * 3
            if ch == 3:
                rgb[o], rgb[o + 1], rgb[o + 2] = raw[p], raw[p + 1], raw[p + 2]
            else:
                rgb[o] = rgb[o + 1] = rgb[o + 2] = raw[p]
    return {"format": "PPM", "width": w, "height": h, "bit_depth": 8,
            "color_type": ch, "interlaced": False, "rgb": rgb}


def _decode_with_pil(path):
    try:
        from PIL import Image
    except ImportError:
        raise ValueError("该格式的像素解码需要 Pillow（内置解码器仅覆盖 PNG/BMP/PPM）")
    im = Image.open(path)
    fmt = im.format or "?"
    im = im.convert("RGB")
    w, h = im.size
    return {"format": "PIL:" + fmt, "width": w, "height": h, "bit_depth": 8,
            "color_type": 3, "interlaced": False, "rgb": bytearray(im.tobytes())}


def load_pixels(path):
    """图片 -> 8bit RGB 平面。PNG/BMP/PPM 自研解码，其它格式在有 Pillow 时借其解码。"""
    with open(path, "rb") as f:
        head = f.read(32)
    if head[:8] == PNG_SIG:
        with open(path, "rb") as f:
            return _decode_png(f.read())
    if head[:2] == b"BM":
        with open(path, "rb") as f:
            return _decode_bmp(f.read())
    if head[:2] in (b"P5", b"P6"):
        with open(path, "rb") as f:
            return _decode_ppm(f.read())
    return _decode_with_pil(path)


# ---------------------------------------------------------------------------
# LSB 分析
# ---------------------------------------------------------------------------

# 兼容旧接口的魔数表
MAGICS = {
    b"PK\x03\x04": "zip", b"PK\x05\x06": "zip-eocd", b"PK\x01\x02": "zip-central",
    b"7z\xbc\xaf\x27\x1c": "7z", b"Rar!\x1a\x07": "rar",
    b"\x1f\x8b": "gzip", b"BZh": "bzip2", b"\xfd7zXZ": "xz",
    b"%PDF": "pdf", b"\x89PNG": "png", b"\xff\xd8\xff": "jpeg", b"GIF8": "gif",
    b"SQLite format 3": "sqlite", b"MZ": "pe", b"\x7fELF": "elf",
    b"EVF\x09": "e01", b"regf": "registry", b"BM": "bmp",
}

_MAGICS = [
    (b"\x78\x9c", "zlib"), (b"\x78\x01", "zlib"), (b"\x78\xda", "zlib"),
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"), (PNG_SIG, "png"), (b"\xff\xd8\xff", "jpeg"),
    (b"GIF89a", "gif"), (b"GIF87a", "gif"), (b"%PDF", "pdf"), (b"MZ", "pe/exe"),
    (b"BM", "bmp"),
]


def _entropy_bits(ones, total):
    if total == 0:
        return 0.0
    p = ones / total
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def _entropy_bytes(data):
    if not data:
        return 0.0
    n = len(data)
    h = 0.0
    for i in range(256):
        c = data.count(i)          # bytes.count 为 C 实现，比逐字节累加快
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _sniff(blob):
    """兼容旧接口：按魔数返回类型名。"""
    for m, n in MAGICS.items():
        if blob.startswith(m):
            return n
    try:
        blob[:4096].decode("utf8")
        return "text/utf8"
    except UnicodeDecodeError:
        return "unknown"


def _identify_payload(data):
    """识别字节流类型 -> (type, detail)。"""
    if not data:
        return "empty", ""
    if data[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        try:
            out = zlib.decompressobj().decompress(data, 1 << 24)
            return "zlib", "解压得到 %d 字节，头部 %s" % (len(out), out[:24].hex())
        except zlib.error:
            return "binary", "疑似 zlib 头但解压失败"
    for magic, name in _MAGICS:
        if data.startswith(magic):
            return name, "魔数 %s" % magic.hex()
    printable = sum(1 for b in data[:512] if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / max(1, min(len(data), 512))
    if ratio > 0.90:
        return "text", data[:120].decode("ascii", "replace")
    return "binary", "头部 %s" % data[:16].hex()


_LSB_TABLE = bytes(i & 1 for i in range(256))


def _pack_bits(lsb_vals, max_bytes):
    """把 0/1 字节序列按 MSB-first 打包成字节。"""
    n = min(len(lsb_vals) // 8, max_bytes)
    out = bytearray(n)
    mv = memoryview(lsb_vals)
    for i in range(n):
        b = i * 8
        out[i] = ((mv[b] << 7) | (mv[b + 1] << 6) | (mv[b + 2] << 5) | (mv[b + 3] << 4)
                  | (mv[b + 4] << 3) | (mv[b + 5] << 2) | (mv[b + 6] << 1) | mv[b + 7])
    return bytes(out)


def _carrier_noise(rgb, w, h):
    """载体自身的相邻像素平均绝对差（0=纯色，越大越接近噪声）。"""
    if w < 2 or h < 2:
        return 0.0
    step = 1 if w * h <= 400000 else 3
    total = 0
    cnt = 0
    for ci in range(3):
        plane = bytes(rgb[ci::3])
        for y in range(0, h, step):
            seg = plane[y * w:(y + 1) * w]
            if len(seg) < 2:
                continue
            total += sum(abs(a - b) for a, b in zip(seg, seg[1:]))
            cnt += len(seg) - 1
    return total / cnt if cnt else 0.0


def lsb_scan(path, max_bytes=1 << 20, dump=None):
    """PNG/BMP LSB 隐写分析。

    统计逐通道 LSB 比例、8 个位平面的熵、提取流的字节熵与卡方，并按 LSB 顺序
    （行优先 R→G→B）还原字节流，尝试识别为 zlib/zip/文本/明文头。
    """
    px = load_pixels(path)
    w, h = px["width"], px["height"]
    rgb = px["rgb"]
    n = w * h
    out = {
        "path": os.path.abspath(path), "format": px["format"],
        "width": w, "height": h, "pixels": n,
        "bit_depth": px["bit_depth"], "interlaced": px.get("interlaced", False),
        "lsb_ones_ratio": {}, "plane_entropy": {}, "chi_square": {},
        "byte_entropy": {}, "suspicious": False, "verdict": "",
        "payload": None, "candidates": [], "dump_path": None,
    }
    # 每个像素 8 位中取第 0 位：掩码 n 个 0x01
    lsb_mask = int.from_bytes(b"\x01" * n, "little") if n else 0
    for name, ci in (("R", 0), ("G", 1), ("B", 2)):
        plane = bytes(rgb[ci::3])
        # 用大整数掩码一次性取各比特平面，避免 8 倍 Python 循环
        x = int.from_bytes(plane, "little")
        plane_ones = []
        for b in range(8):
            plane_ones.append((x & (lsb_mask << b)).bit_count())
        ones = plane_ones[0]
        out["lsb_ones_ratio"][name] = round(ones / n, 6) if n else 0.0
        out["plane_entropy"][name] = [round(_entropy_bits(plane_ones[b], n), 6) for b in range(8)]
        exp = n / 2.0
        out["chi_square"][name] = round(((ones - exp) ** 2) / exp, 3) if n else 0.0

    limit = min(n, max_bytes * 8 // 3 + 8)
    # 行优先 R→G→B 的 LSB 流：translate 取 LSB（C 速度）后按 8 位打包
    lsb_vals = rgb.translate(_LSB_TABLE)[: limit * 3]
    payload = _pack_bits(lsb_vals, max_bytes)
    out["extracted_len"] = len(payload)
    out["extracted_sha256"] = hashlib.sha256(payload).hexdigest()
    out["extracted_head_hex"] = payload[:64].hex()
    out["byte_entropy"]["extracted"] = round(_entropy_bytes(payload[:262144]), 4)

    ptype, detail = _identify_payload(payload)
    out["payload"] = {"type": ptype, "detail": detail}

    # 容忍载荷前有盐/长度头：在流内继续找魔数
    scan = payload[:min(len(payload), 65536)]
    for magic, name in _MAGICS:
        idx = scan.find(magic)
        if idx >= 0:
            seg = payload[idx:idx + 4096]
            stype, sdetail = _identify_payload(seg)
            out["candidates"].append({"offset": idx, "magic": magic.hex(),
                                      "type": stype, "detail": sdetail,
                                      "head_hex": seg[:32].hex()})
    if ptype == "text":
        out["candidates"].append({"offset": 0, "magic": "", "type": "text",
                                  "detail": detail, "head_hex": payload[:32].hex()})

    ratios = [out["lsb_ones_ratio"][c] for c in "RGB"]
    max_dev = max(abs(r - 0.5) for r in ratios)
    ent = out["byte_entropy"]["extracted"]
    noise = _carrier_noise(rgb, w, h)
    out["carrier_noise"] = round(noise, 3)
    container = ("zlib", "zip", "gzip", "bzip2", "xz", "7z", "rar",
                 "png", "jpeg", "pdf", "pe/exe", "sqlite", "elf")
    if ptype in container:
        out["suspicious"] = True
        out["verdict"] = "高度可疑：LSB 流起始即命中合法容器魔数（%s）" % ptype
    elif noise >= 28:
        out["verdict"] = ("无法判定：载体本身接近随机噪声（相邻像素平均差 %.1f），"
                          "其 LSB 天然接近随机，统计法不可区分" % noise)
    elif ent > 7.5 and max_dev < 0.03 and n > 4096:
        out["suspicious"] = True
        out["verdict"] = ("可疑：平滑载体上 LSB 位面异常随机（字节熵 %.2f，0/1 偏差 %.4f），"
                          "符合 LSB 隐写特征" % (ent, max_dev))
    elif max_dev > 0.25:
        out["verdict"] = "正常：LSB 分布明显偏斜（0/1 偏差 %.4f），未见隐写迹象" % max_dev
    else:
        out["verdict"] = ("未检出：LSB 字节熵 %.2f，未见魔数或异常随机性" % ent)

    if dump:
        target = dump if isinstance(dump, str) else os.path.abspath(path) + ".lsb.bin"
        with open(target, "wb") as f:
            f.write(payload)
        out["dump_path"] = os.path.abspath(target)
    return out


# ---------------------------------------------------------------------------
# 结构末尾定位 / 追加数据
# ---------------------------------------------------------------------------


def _jpeg_end(raw):
    """走 JPEG 段结构找真正的 EOI（不靠 rfind，避免追加数据内含 FF D9）。"""
    if raw[:2] != b"\xff\xd8":
        return None
    pos = 2
    n = len(raw)
    while pos + 1 < n:
        if raw[pos] != 0xFF:
            pos += 1
            continue
        marker = raw[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0xD9:
            return pos + 2
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if pos + 4 > n:
            return None
        ln = struct.unpack_from(">H", raw, pos + 2)[0]
        if marker == 0xDA:
            pos += 2 + ln
            while pos + 1 < n:
                if (raw[pos] == 0xFF and raw[pos + 1] != 0x00
                        and not (0xD0 <= raw[pos + 1] <= 0xD7)):
                    break
                pos += 1
        else:
            pos += 2 + ln
    return None


def _png_end(raw):
    if raw[:8] != PNG_SIG:
        return None
    pos = 8
    while pos + 12 <= len(raw):
        ln = struct.unpack_from(">I", raw, pos)[0]
        typ = raw[pos + 4:pos + 8]
        pos += 12 + ln
        if typ == b"IEND":
            return pos
    return None


def _gif_end(raw):
    if raw[:6] not in (b"GIF87a", b"GIF89a") or len(raw) < 13:
        return None
    flags = raw[10]
    pos = 13
    if flags & 0x80:
        pos += 3 * (2 ** ((flags & 7) + 1))
    n = len(raw)
    while pos < n:
        b = raw[pos]
        if b == 0x3B:
            return pos + 1
        if b == 0x21:
            pos += 2
            while pos < n and raw[pos]:
                pos += 1 + raw[pos]
            pos += 1
        elif b == 0x2C:
            if pos + 10 > n:
                return None
            local = raw[pos + 9]
            pos += 10
            if local & 0x80:
                pos += 3 * (2 ** ((local & 7) + 1))
            pos += 1
            while pos < n and raw[pos]:
                pos += 1 + raw[pos]
            pos += 1
        else:
            return pos
    return None


def _pdf_end(raw):
    idx = raw.rfind(b"%%EOF")
    return idx + 5 if idx >= 0 else None


def _zip_end(raw):
    idx = raw.rfind(b"PK\x05\x06")
    if idx < 0 or idx + 22 > len(raw):
        return None
    comment_len = struct.unpack_from("<H", raw, idx + 20)[0]
    end = idx + 22 + comment_len
    return end if end <= len(raw) else idx + 22


def _detect_format(raw):
    if raw[:8] == PNG_SIG:
        return "png"
    if raw[:2] == b"\xff\xd8":
        return "jpeg"
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if raw[:5] == b"%PDF-":
        return "pdf"
    if raw[:4] == b"PK\x03\x04":
        return "zip"
    if raw[:2] == b"BM":
        return "bmp"
    return "unknown"


def appended_data(path, dump=None):
    """检出结构末尾之后的追加数据，返回 dict（含 sha256/preview/类型猜测），可 dump。"""
    with open(path, "rb") as f:
        raw = f.read()
    fmt = _detect_format(raw)
    end = None
    if fmt == "jpeg":
        end = _jpeg_end(raw)
        if end is None:
            idx = raw.rfind(b"\xff\xd9")
            end = idx + 2 if idx >= 0 else None
    elif fmt == "png":
        end = _png_end(raw)
    elif fmt == "gif":
        end = _gif_end(raw)
    elif fmt == "pdf":
        end = _pdf_end(raw)
    elif fmt == "zip":
        end = _zip_end(raw)

    out = {"path": os.path.abspath(path), "format": fmt, "file_size": len(raw),
           "end_offset": end, "appended_length": 0, "appended_sha256": None,
           "appended_head_hex": "", "ascii_preview": "", "guess": None,
           "dump_path": None, "truncated_structure": False}
    if end is None:
        out["truncated_structure"] = True
        out["note"] = "未能定位结构末尾（文件可能被截断或格式不支持）"
        return out
    extra = raw[end:]
    out["appended_length"] = len(extra)
    if not extra:
        out["note"] = "无追加数据"
        return out
    out["appended_sha256"] = hashlib.sha256(extra).hexdigest()
    out["appended_head_hex"] = extra[:4096].hex()
    out["ascii_preview"] = "".join(chr(b) if 32 <= b < 127 else "." for b in extra[:200])
    gtype, gdetail = _identify_payload(extra)
    out["guess"] = {"type": gtype, "detail": gdetail}
    if dump:
        target = dump if isinstance(dump, str) else os.path.abspath(path) + ".appended.bin"
        with open(target, "wb") as f:
            f.write(extra)
        out["dump_path"] = os.path.abspath(target)
    return out


# ---------------------------------------------------------------------------
# 内部归档 / 嵌入文件扫描
# ---------------------------------------------------------------------------

_EMBED_SIGS = [
    (b"PK\x03\x04", "zip-local"),
    (b"PK\x01\x02", "zip-central"),
    (b"PK\x05\x06", "zip-eocd"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07\x01\x00", "rar5"),
    (b"Rar!\x1a\x07\x00", "rar4"),
    (b"%PDF-", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole(cfb)"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh9", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\x7fELF", "elf"),
    (b"\xce\xfa\xed\xfe", "macho32"),
    (b"\xcf\xfa\xed\xfe", "macho64"),
]


def embedded_archives(path, chunk=1 << 22, max_hits=2000):
    """全文件扫描嵌入归档/文件魔数，返回 [{offset,type,sig_hex,name_preview}]。"""
    hits = []
    seen = set()
    size = os.path.getsize(path)
    max_sig = max(len(s) for s, _ in _EMBED_SIGS)
    with open(path, "rb") as f:
        off = 0
        tail = b""
        while off < size and len(hits) < max_hits:
            f.seek(off)
            buf = f.read(chunk)
            if not buf:
                break
            data = tail + buf
            base = off - len(tail)
            for sig, name in _EMBED_SIGS:
                start = 0
                while True:
                    idx = data.find(sig, start)
                    if idx < 0:
                        break
                    abs_off = base + idx
                    if abs_off not in seen:
                        seen.add(abs_off)
                        hits.append({"offset": abs_off, "type": name,
                                     "sig_hex": sig.hex(), "name_preview": None})
                    start = idx + 1
            # MZ 需 PE 头二次确认，避免 4D5A 误报
            start = 0
            while True:
                idx = data.find(b"MZ", start)
                if idx < 0:
                    break
                abs_off = base + idx
                if abs_off not in seen and abs_off + 0x40 <= size:
                    f.seek(abs_off + 0x3C)
                    pe = f.read(4)
                    if len(pe) == 4:
                        lfanew = struct.unpack("<I", pe)[0]
                        if 0 < lfanew < 0x1000 and abs_off + lfanew + 4 <= size:
                            f.seek(abs_off + lfanew)
                            if f.read(4) == b"PE\x00\x00":
                                seen.add(abs_off)
                                hits.append({"offset": abs_off, "type": "pe(exe/dll)",
                                             "sig_hex": "4d5a", "name_preview": None})
                start = idx + 2
            tail = data[-max_sig:]
            off += chunk

    # tar 的 ustar 在 +257
    with open(path, "rb") as f:
        pos = 0
        while pos + 512 <= size:
            f.seek(pos + 257)
            if f.read(5) == b"ustar":
                if pos not in seen:
                    seen.add(pos)
                    hits.append({"offset": pos, "type": "tar", "sig_hex": "7573746172",
                                 "name_preview": None})
            pos += 512

    for hit in hits:
        if hit["type"] == "zip-local":
            with open(path, "rb") as f:
                f.seek(hit["offset"] + 26)
                hdr = f.read(4)
                if len(hdr) == 4:
                    nlen = struct.unpack("<H", hdr[:2])[0]
                    f.seek(hit["offset"] + 30)
                    nm = f.read(min(nlen, 256))
                    hit["name_preview"] = nm.decode("utf-8", "replace")
        elif hit["type"] in ("rar4", "rar5"):
            with open(path, "rb") as f:
                f.seek(hit["offset"] + 7)
                head = f.read(24)
                if len(head) >= 24:
                    nm = head[3:3 + 16].split(b"\x00")[0].decode("latin-1", "replace")
                    hit["name_preview"] = nm or None
    hits.sort(key=lambda x: (x["offset"], x["type"]))
    return hits


# ---------------------------------------------------------------------------
# EXIF
# ---------------------------------------------------------------------------

_TAG_NAMES = {
    0x0100: "ImageWidth", 0x0101: "ImageLength", 0x010E: "ImageDescription",
    0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation", 0x011A: "XResolution",
    0x011B: "YResolution", 0x0128: "ResolutionUnit", 0x0131: "Software",
    0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright",
    0x8769: "ExifIFD", 0x8825: "GPSIFD",
    0x0201: "JPEGInterchangeFormat", 0x0202: "JPEGInterchangeFormatLength",
    0x829A: "ExposureTime", 0x829D: "FNumber", 0x8827: "ISOSpeedRatings",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized", 0x9010: "OffsetTime",
    0x9201: "ShutterSpeedValue", 0x9202: "ApertureValue", 0x9209: "Flash",
    0x920A: "FocalLength", 0x927C: "MakerNote", 0x9286: "UserComment",
    0xA002: "PixelXDimension", 0xA003: "PixelYDimension", 0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber", 0xA432: "LensSpecification", 0xA433: "LensMake",
    0xA434: "LensModel", 0xA435: "LensSerialNumber",
    0x0000: "GPSVersionID", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude", 0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude", 0x0007: "GPSTimeStamp", 0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection", 0x0012: "GPSMapDatum", 0x001D: "GPSDateStamp",
}

_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


class _Tiff:
    def __init__(self, buf):
        if buf[:4] == b"II*\x00":
            self.e = "<"
        elif buf[:4] == b"MM\x00*":
            self.e = ">"
        else:
            raise ValueError("不是有效的 TIFF/EXIF 头")
        self.buf = buf
        self.off = struct.unpack_from(self.e + "I", buf, 4)[0]

    def _val(self, typ, count, pos):
        size = _TYPE_SIZE.get(typ, 1) * count
        if size <= 4:
            raw = self.buf[pos:pos + 4][:size]
        else:
            off = struct.unpack_from(self.e + "I", self.buf, pos)[0]
            raw = self.buf[off:off + size]
        if len(raw) < size:
            return None
        if typ == 2:
            return raw.split(b"\x00")[0].decode("utf-8", "replace")
        if typ in (1, 7):
            return bytes(raw)
        if typ in (3, 8):
            return list(struct.unpack(self.e + "%dH" % count, raw))
        if typ in (4, 9):
            fmt = "I" if typ == 4 else "i"
            return list(struct.unpack(self.e + "%d%s" % (count, fmt), raw))
        if typ in (5, 10):
            fmt = "I" if typ == 5 else "i"
            vals = struct.unpack(self.e + "%d%s" % (count * 2, fmt), raw)
            return [(vals[i * 2], vals[i * 2 + 1]) for i in range(count)]
        if typ == 11:
            return list(struct.unpack(self.e + "%df" % count, raw))
        if typ == 12:
            return list(struct.unpack(self.e + "%dd" % count, raw))
        return bytes(raw)

    def ifd(self, offset):
        tags = {}
        if offset == 0 or offset + 2 > len(self.buf):
            return tags, 0
        count = struct.unpack_from(self.e + "H", self.buf, offset)[0]
        pos = offset + 2
        for _ in range(min(count, 512)):
            if pos + 12 > len(self.buf):
                break
            tag, typ, cnt = struct.unpack_from(self.e + "HHI", self.buf, pos)
            try:
                val = self._val(typ, cnt, pos + 8)
            except (struct.error, IndexError):
                val = None
            if val is not None:
                tags[_TAG_NAMES.get(tag, "Tag_0x%04X" % tag)] = val
            pos += 12
        nxt = 0
        if pos + 4 <= len(self.buf):
            nxt = struct.unpack_from(self.e + "I", self.buf, pos)[0]
        return tags, nxt


def _dms_list(vals):
    if not vals or len(vals) < 3:
        return None
    out = []
    for pair in vals[:3]:
        if isinstance(pair, tuple):
            num, den = pair
            out.append(num / den if den else 0.0)
        else:
            out.append(float(pair))
    return out


def _dms_to_decimal(dms, ref):
    if not dms:
        return None
    deg = dms[0] + (dms[1] / 60.0 if len(dms) > 1 else 0) + (dms[2] / 3600.0 if len(dms) > 2 else 0)
    if ref in ("S", "W"):
        deg = -deg
    return deg


def _jpeg_marker_name(marker):
    table = {0xE0: "APP0(JFIF)", 0xE1: "APP1(Exif/XMP)", 0xE2: "APP2(ICC)",
             0xED: "APP13(Photoshop/IPTC)", 0xEE: "APP14(Adobe)", 0xFE: "COM(注释)",
             0xDB: "DQT(量化表)", 0xC4: "DHT(霍夫曼表)", 0xDD: "DRI(重启间隔)",
             0xDA: "SOS(扫描开始)", 0xD9: "EOI", 0xCC: "DAC"}
    if marker in table:
        return table[marker]
    if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
        return "SOF%d(帧头)" % (marker - 0xC0)
    if 0xE0 <= marker <= 0xEF:
        return "APP%d" % (marker - 0xE0)
    return "0x%02X" % marker


def _jpeg_app_segments(raw):
    if raw[:2] != b"\xff\xd8":
        return
    pos = 2
    n = len(raw)
    while pos + 4 <= n:
        if raw[pos] != 0xFF:
            pos += 1
            continue
        marker = raw[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0xD9:
            return
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        ln = struct.unpack_from(">H", raw, pos + 2)[0]
        if ln < 2:
            return
        payload = raw[pos + 4:pos + 2 + ln]
        yield marker, payload, pos
        if marker == 0xDA:
            return
        pos += 2 + ln


def _gps_from_tags(gps_tags):
    out = {"present": False, "lat": None, "lon": None, "altitude": None,
           "timestamp": None, "datestamp": None, "raw": {}}
    if not gps_tags:
        return out
    out["present"] = True
    out["raw"] = dict(gps_tags)
    lat_dms = _dms_list(gps_tags.get("GPSLatitude"))
    lon_dms = _dms_list(gps_tags.get("GPSLongitude"))
    if lat_dms:
        out["lat_dms"] = [round(x, 6) for x in lat_dms]
        out["lat"] = _dms_to_decimal(lat_dms, gps_tags.get("GPSLatitudeRef"))
        out["lat_ref"] = gps_tags.get("GPSLatitudeRef")
    if lon_dms:
        out["lon_dms"] = [round(x, 6) for x in lon_dms]
        out["lon"] = _dms_to_decimal(lon_dms, gps_tags.get("GPSLongitudeRef"))
        out["lon_ref"] = gps_tags.get("GPSLongitudeRef")
    alt = gps_tags.get("GPSAltitude")
    if isinstance(alt, list) and alt and isinstance(alt[0], tuple) and alt[0][1]:
        val = alt[0][0] / alt[0][1]
        ref = gps_tags.get("GPSAltitudeRef")
        if isinstance(ref, (bytes, bytearray)) and ref and ref[0] == 1:
            val = -val
        out["altitude"] = val
    ts = gps_tags.get("GPSTimeStamp")
    if isinstance(ts, list) and len(ts) == 3:
        parts = []
        for p in ts:
            if isinstance(p, tuple):
                parts.append(p[0] / p[1] if p[1] else 0)
            else:
                parts.append(float(p))
        out["timestamp"] = "%02d:%02d:%06.3f" % (parts[0], parts[1], parts[2])
    ds = gps_tags.get("GPSDateStamp")
    if isinstance(ds, str):
        out["datestamp"] = ds
    return out


def _fmt_rational(v):
    if isinstance(v, list) and v and isinstance(v[0], tuple):
        num, den = v[0]
        return "%g/%g" % (num, den)
    return v


def exif_all(path):
    """自研 EXIF 解析：相机 / Software / 时间 / GPS(含度分秒) / 缩略图 / 是否被改图。"""
    with open(path, "rb") as f:
        raw = f.read()
    res = {
        "path": os.path.abspath(path), "format": None, "exif_present": False,
        "camera": {"make": None, "model": None, "lens": None, "serial": None},
        "software": None, "datetime": {"ifd0": None, "original": None, "digitized": None},
        "gps": {"present": False, "lat": None, "lon": None, "altitude": None},
        "thumbnail": {"offset": None, "length": None, "bytes_available": None},
        "photoshop_modified": False, "photoshop_evidence": [],
        "ifd0_tags": {}, "exif_tags": {}, "gps_tags": {},
        "app_markers": [], "error": None,
    }
    tiff_buf = None
    fmt = _detect_format(raw)

    if fmt == "jpeg":
        res["format"] = "JPEG"
        for marker, payload, off in _jpeg_app_segments(raw):
            res["app_markers"].append({"marker": "0x%02x" % marker,
                                       "name": _jpeg_marker_name(marker),
                                       "offset": off, "length": len(payload)})
            if marker == 0xE1 and payload[:6] == b"Exif\x00\x00":
                if tiff_buf is None:
                    tiff_buf = payload[6:]
            elif marker == 0xE1 and (b"<x:xmpmeta" in payload[:128]
                                     or b"http://ns.adobe.com" in payload[:512]):
                res["photoshop_evidence"].append("存在 XMP 元数据（APP1），被支持 XMP 的软件重写过")
            elif marker == 0xED and b"Photoshop 3.0" in payload[:64]:
                res["photoshop_evidence"].append("存在 APP13 Photoshop 3.0 / 8BIM 资源块")
            elif marker == 0xEE and payload[:5] == b"Adobe":
                res["photoshop_evidence"].append("存在 APP14 Adobe 标记")
    elif raw[:8] == PNG_SIG:
        res["format"] = "PNG"
        pos = 8
        while pos + 12 <= len(raw):
            ln = struct.unpack_from(">I", raw, pos)[0]
            typ = raw[pos + 4:pos + 8]
            if typ == b"eXIf":
                tiff_buf = raw[pos + 8:pos + 8 + ln]
            pos += 12 + ln
    elif raw[:4] in (b"II*\x00", b"MM\x00*"):
        res["format"] = "TIFF"
        tiff_buf = raw
    else:
        res["format"] = fmt.upper()
        res["error"] = "该容器不含可解析的 EXIF"
        return res

    if not tiff_buf:
        res["error"] = "未找到 EXIF/TIFF 数据"
        return res
    try:
        t = _Tiff(tiff_buf)
        ifd0, next_off = t.ifd(t.off)
    except (ValueError, struct.error) as exc:
        res["error"] = "EXIF 解析失败：%s" % exc
        return res

    res["exif_present"] = True
    res["ifd0_tags"] = ifd0
    cam = res["camera"]
    cam["make"] = ifd0.get("Make")
    cam["model"] = ifd0.get("Model")
    res["software"] = ifd0.get("Software")
    res["datetime"]["ifd0"] = ifd0.get("DateTime")
    res["camera"]["orientation"] = ifd0.get("Orientation")

    def first(v):
        return v[0] if isinstance(v, list) and v else None

    exif_off = first(ifd0.get("ExifIFD"))
    gps_off = first(ifd0.get("GPSIFD"))
    if exif_off:
        etags, _ = t.ifd(exif_off)
        res["exif_tags"] = etags
        res["datetime"]["original"] = etags.get("DateTimeOriginal")
        res["datetime"]["digitized"] = etags.get("DateTimeDigitized")
        cam["lens"] = etags.get("LensModel")
        cam["serial"] = etags.get("BodySerialNumber")
        cam["lens_make"] = etags.get("LensMake")
        cam["lens_serial"] = etags.get("LensSerialNumber")
        if etags.get("ExposureTime"):
            cam["exposure"] = _fmt_rational(etags["ExposureTime"])
        if etags.get("FNumber"):
            cam["fnumber"] = _fmt_rational(etags["FNumber"])
        iso = etags.get("ISOSpeedRatings")
        if iso is not None:
            cam["iso"] = iso[0] if isinstance(iso, list) else iso
        if etags.get("FocalLength"):
            cam["focal_length"] = _fmt_rational(etags["FocalLength"])
        uc = etags.get("UserComment")
        if isinstance(uc, (bytes, bytearray)) and uc:
            res["user_comment"] = uc[8:].decode("utf-8", "replace").strip("\x00 ")
    if gps_off:
        gtags, _ = t.ifd(gps_off)
        res["gps_tags"] = gtags
        res["gps"] = _gps_from_tags(gtags)

    if next_off:
        try:
            ifd1, _ = t.ifd(next_off)
            th_off = first(ifd1.get("JPEGInterchangeFormat"))
            th_len = first(ifd1.get("JPEGInterchangeFormatLength"))
            res["thumbnail"]["offset"] = th_off
            res["thumbnail"]["length"] = th_len
            if th_off is not None and th_len:
                avail = max(0, len(tiff_buf) - th_off)
                res["thumbnail"]["bytes_available"] = min(avail, th_len)
                blob = tiff_buf[th_off:th_off + th_len]
                res["thumbnail"]["format"] = "JPEG" if blob[:2] == b"\xff\xd8" else "未知"
                res["thumbnail"]["sha256"] = hashlib.sha256(blob).hexdigest()
        except (ValueError, struct.error):
            pass

    ev = res["photoshop_evidence"]
    sw = res["software"] or ""
    if re.search(r"Adobe Photoshop|Photoshop|GIMP|Lightroom|ACDSee|Snapseed|Picsart|美图|醒图",
                 sw, re.I):
        ev.append("Software=%r，说明经过图像编辑软件保存" % sw)
    if ifd0.get("Make") and not ifd0.get("Model"):
        ev.append("有 Make 无 Model，元数据可能被部分清除")
    if (res["datetime"]["original"] and res["datetime"]["ifd0"]
            and res["datetime"]["original"] != res["datetime"]["ifd0"]):
        ev.append("DateTimeOriginal 与 DateTime 不一致（原始 %s / 保存 %s）"
                  % (res["datetime"]["original"], res["datetime"]["ifd0"]))
    if res["exif_present"] and not res["gps"].get("present"):
        ev.append("无 GPS IFD（可能被剥离或被编辑/社交软件清洗）")
    res["photoshop_modified"] = bool(ev)
    res["exif_byte_length"] = len(tiff_buf)
    return res


def gps_decimal(exif):
    """兼容辅助：从 exif_all() 结果或裸 IFD 字典取 (lat, lon)。"""
    gps = exif.get("gps") if isinstance(exif, dict) and "gps" in exif else exif
    if not isinstance(gps, dict):
        return None, None
    return gps.get("lat"), gps.get("lon")


# ---------------------------------------------------------------------------
# PNG chunk 审计
# ---------------------------------------------------------------------------

_PNG_STANDARD = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP",
    b"sBIT", b"sRGB", b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"hIST", b"pHYs",
    b"sPLT", b"tIME", b"eXIf", b"acTL", b"fcTL", b"fdAT", b"oFFs", b"pCAL",
    b"sCAL", b"gIFg", b"gIFt", b"gIFx", b"fRAc", b"sTER", b"dSIG",
}


def png_chunks(path):
    """列出 PNG 全部 chunk（类型/长度/CRC）并标注异常。"""
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:8] != PNG_SIG:
        raise ValueError("不是 PNG 文件")
    chunks = []
    anomalies = []
    pos = 8
    idat_seen = False
    iend_count = 0
    after_iend = []
    while pos + 12 <= len(raw):
        ln = struct.unpack_from(">I", raw, pos)[0]
        typ = raw[pos + 4:pos + 8]
        data = raw[pos + 8:pos + 8 + ln]
        crc_stored = (struct.unpack_from(">I", raw, pos + 8 + ln)[0]
                      if pos + 12 + ln <= len(raw) else None)
        crc_calc = zlib.crc32(typ + data) & 0xFFFFFFFF
        nm = typ.decode("latin-1")
        if iend_count and typ != b"IEND":
            after_iend.append({"offset": pos, "type": nm, "length": ln})
        rec = {"offset": pos, "length": ln, "type": nm, "type_hex": typ.hex(),
               "crc_stored": crc_stored, "crc_calculated": crc_calc,
               "crc_ok": crc_stored == crc_calc,
               "critical": not (typ[0] & 0x20),
               "data_head_hex": data[:32].hex()}
        if typ == b"tEXt" and b"\x00" in data:
            k, _, v = data.partition(b"\x00")
            rec["text"] = {"keyword": k.decode("latin-1", "replace"),
                           "value": v.decode("latin-1", "replace")[:2000]}
        elif typ == b"zTXt":
            try:
                k, _, rest = data.partition(b"\x00")
                rec["text"] = {"keyword": k.decode("latin-1", "replace"),
                               "value": zlib.decompress(rest[1:]).decode("utf-8", "replace")[:2000]}
            except (zlib.error, IndexError):
                rec["text"] = {"error": "zTXt 解压失败"}
        elif typ == b"iTXt":
            try:
                parts = data.split(b"\x00", 5)
                if len(parts) >= 6:
                    comp_flag = parts[1]
                    body = parts[5]
                    val = zlib.decompress(body) if comp_flag == b"\x01" else body
                    rec["text"] = {"keyword": parts[0].decode("latin-1", "replace"),
                                   "value": val.decode("utf-8", "replace")[:2000]}
            except (zlib.error, IndexError):
                rec["text"] = {"error": "iTXt 解压失败"}
        elif typ == b"eXIf":
            rec["exif_bytes"] = ln
        if typ == b"IHDR" and ln == 13:
            rec["ihdr"] = dict(zip(("width", "height", "bit_depth", "color_type",
                                    "compression", "filter", "interlace"),
                                   struct.unpack(">IIBBBBB", data)))
        chunks.append(rec)

        if typ == b"IEND":
            iend_count += 1
        if typ == b"IDAT":
            idat_seen = True

        if not re.fullmatch(r"[A-Za-z]{4}", nm):
            anomalies.append({"offset": pos, "kind": "非标准 chunk 名（含非字母字节）", "type": nm})
        elif typ[2] & 0x20:
            anomalies.append({"offset": pos, "kind": "保留位为 1（第 3 字节应为大写）", "type": nm})
        if crc_stored is not None and crc_stored != crc_calc:
            anomalies.append({"offset": pos, "kind": "CRC 不符（数据被改过）", "type": nm,
                              "stored": crc_stored, "calculated": crc_calc})
        if typ not in _PNG_STANDARD:
            anomalies.append({"offset": pos, "kind": "非标准/私有 chunk", "type": nm})
        if typ in (b"tEXt", b"zTXt", b"iTXt") and ln > 512:
            anomalies.append({"offset": pos, "kind": "文本 chunk 过大（%d 字节，疑似藏数据）" % ln,
                              "type": nm})
        if typ == b"IEND" and iend_count > 1:
            anomalies.append({"offset": pos, "kind": "重复 IEND", "type": nm})
        pos += 12 + ln
        if pos > len(raw):
            anomalies.append({"offset": pos, "kind": "chunk 长度越界（截断或长度被改）",
                              "type": nm})
            break
        if typ == b"IEND":
            # PNG 规范：IEND 之后不允许有任何数据
            break
    tail = len(raw) - pos
    if tail > 0:
        anomalies.append({"offset": pos, "kind": "IEND 之后还有 %d 字节数据" % tail, "type": ""})
    if not idat_seen:
        anomalies.append({"offset": None, "kind": "缺少 IDAT", "type": ""})
    if iend_count == 0:
        anomalies.append({"offset": None, "kind": "缺少 IEND", "type": ""})
    return {"path": os.path.abspath(path), "file_size": len(raw),
            "chunk_count": len(chunks), "chunks": chunks,
            "anomalies": anomalies, "data_after_iend": after_iend,
            "trailing_bytes": tail}


# ---------------------------------------------------------------------------
# UTF-16 字符串
# ---------------------------------------------------------------------------


def _is_printable_u16(cp):
    if cp in (9, 10, 13):
        return True
    if 0x20 <= cp <= 0x7E:
        return True
    if 0x4E00 <= cp <= 0x9FFF:
        return True
    if 0x3000 <= cp <= 0x303F:
        return True
    if 0xFF00 <= cp <= 0xFFEF:
        return True
    if 0x00A0 <= cp <= 0x02FF:
        return True
    return False


def _scan_u16(data, little, min_len, shift):
    out = []
    i = shift
    n = len(data) - 1
    run_start = None
    chars = []
    while i < n:
        cp = (data[i] | (data[i + 1] << 8)) if little else ((data[i] << 8) | data[i + 1])
        if _is_printable_u16(cp):
            if run_start is None:
                run_start = i
            chars.append(cp)
            i += 2
        else:
            if run_start is not None and len(chars) >= min_len:
                out.append({"offset": run_start, "encoding": "UTF-16LE" if little else "UTF-16BE",
                            "length_chars": len(chars),
                            "text": "".join(chr(c) for c in chars)})
            run_start = None
            chars = []
            i += 2
    if run_start is not None and len(chars) >= min_len:
        out.append({"offset": run_start, "encoding": "UTF-16LE" if little else "UTF-16BE",
                    "length_chars": len(chars), "text": "".join(chr(c) for c in chars)})
    return out


def strings_utf16(path, min_len=4, max_strings=20000):
    """提取 UTF-16LE/BE 字符串（两遍扫描覆盖奇偶对齐），返回带偏移的记录列表。"""
    with open(path, "rb") as f:
        data = f.read()
    results = []
    for little in (True, False):
        for shift in (0, 1):
            results.extend(_scan_u16(data, little, min_len, shift))
    results.sort(key=lambda r: (r["offset"], r["encoding"]))
    dedup = []
    for r in results:
        if dedup and r["offset"] == dedup[-1]["offset"] and r["encoding"] == dedup[-1]["encoding"]:
            continue
        dedup.append(r)
    return dedup[:max_strings]


# ---------------------------------------------------------------------------
# 二维码
# ---------------------------------------------------------------------------


def qr_decode(path):
    """优先 pyzbar 解码；不可用时标记 need_manual，并附自研矩阵提取结果。"""
    out = {"path": os.path.abspath(path), "engine": None, "results": [],
           "need_manual": False, "matrix": None, "error": None}
    try:
        from pyzbar.pyzbar import decode as _zbar_decode
        from PIL import Image as _Image
    except ImportError:
        out["engine"] = "none"
        out["need_manual"] = True
        out["error"] = "未安装 pyzbar/Pillow，无法自动解码；请用 qr_matrix_extract() 取矩阵后人工/联网解码"
        try:
            out["matrix"] = qr_matrix_extract(path)
        except (ValueError, OSError) as exc:
            out["matrix"] = {"error": str(exc)}
        return out
    try:
        img = _Image.open(path)
        dec = _zbar_decode(img)
        out["engine"] = "pyzbar"
        for d in dec:
            out["results"].append({
                "type": d.type,
                "data": d.data.decode("utf-8", "replace"),
                "data_hex": d.data.hex(),
                "rect": {"x": d.rect.left, "y": d.rect.top,
                         "w": d.rect.width, "h": d.rect.height},
                "polygon": [(p.x, p.y) for p in (d.polygon or [])],
            })
        if not out["results"]:
            out["need_manual"] = True
            out["error"] = "pyzbar 未解出内容（图像可能过模糊/无二维码）"
    except Exception as exc:                            # noqa: BLE001
        out["engine"] = "pyzbar"
        out["need_manual"] = True
        out["error"] = "pyzbar 解码失败：%s" % exc
    try:
        out["matrix"] = qr_matrix_extract(path)
    except (ValueError, OSError) as exc:
        out["matrix"] = {"error": str(exc)}
    return out


def _otsu_threshold(gray):
    """Otsu 全局阈值。返回两类均值的中间值（比直接用 t 更稳，避免双峰图退化到 0/255）。"""
    hist = [0] * 256
    for v in gray:
        hist[v] += 1
    total = len(gray)
    if total == 0:
        return 128
    sum_all = sum(i * hist[i] for i in range(256))
    sum_b = 0.0
    w_b = 0
    best = -1.0
    best_t = 127
    for t in range(256):
        w_b += hist[t]
        if w_b == 0:
            continue
        w_f = total - w_b
        if w_f == 0:
            break
        sum_b += t * hist[t]
        m_b = sum_b / w_b
        m_f = (sum_all - sum_b) / w_f
        var = w_b * w_f * (m_b - m_f) ** 2
        if var > best:
            best = var
            best_t = t
    # 用最优分割处的两类均值中点作为阈值
    hist_b = sum(hist[:best_t + 1])
    if hist_b == 0 or hist_b == total:
        return best_t
    mean_b = sum(i * hist[i] for i in range(best_t + 1)) / hist_b
    mean_f = (sum_all - sum(i * hist[i] for i in range(best_t + 1))) / (total - hist_b)
    thr = int(round((mean_b + mean_f) / 2))
    return max(1, min(254, thr))


def _row_runs(binary, w, y):
    runs = []
    start = 0
    cur = binary[y * w]
    ln = 1
    for x in range(1, w):
        v = binary[y * w + x]
        if v == cur:
            ln += 1
        else:
            runs.append((start, ln, cur))
            start = x
            cur = v
            ln = 1
    runs.append((start, ln, cur))
    return runs


def _ratio_ok(lens):
    total = sum(lens)
    if total < 7:
        return None
    m = total / 7.0
    tol = max(1.0, m * 0.8)
    for ln, target in zip(lens, (1, 1, 3, 1, 1)):
        if abs(ln - target * m) > tol:
            return None
    return m


def _col_runs(binary, w, h, x, y0, y1):
    runs = []
    y0 = max(0, y0)
    y1 = min(h - 1, y1)
    if y0 > y1:
        return runs
    start = y0
    cur = binary[y0 * w + x]
    ln = 1
    for y in range(y0 + 1, y1 + 1):
        v = binary[y * w + x]
        if v == cur:
            ln += 1
        else:
            runs.append((start, ln, cur))
            start = y
            cur = v
            ln = 1
    runs.append((start, ln, cur))
    return runs


def _find_finders(binary, w, h):
    """行扫描找 1:1:3:1:1（黑:白:黑:白:黑），再纵向复核并聚类。"""
    cands = []
    step = 1 if h <= 1200 else 2
    for y in range(0, h, step):
        runs = _row_runs(binary, w, y)
        for i in range(len(runs) - 4):
            if runs[i][2] != 1 or runs[i + 2][2] != 1 or runs[i + 4][2] != 1:
                continue
            if runs[i + 1][2] != 0 or runs[i + 3][2] != 0:
                continue
            lens = [runs[i + k][1] for k in range(5)]
            m = _ratio_ok(lens)
            if m is None:
                continue
            cx = runs[i][0] + sum(lens) / 2.0
            span = int(m * 4) + 2
            vr = _col_runs(binary, w, h, int(cx), y - span, y + span)
            for j in range(len(vr) - 4):
                if vr[j][2] != 1 or vr[j + 2][2] != 1 or vr[j + 4][2] != 1:
                    continue
                if vr[j + 1][2] != 0 or vr[j + 3][2] != 0:
                    continue
                vlens = [vr[j + k][1] for k in range(5)]
                vm = _ratio_ok(vlens)
                if vm is None:
                    continue
                vcy = vr[j][0] + sum(vlens) / 2.0
                if abs(vcy - y) <= max(2, m * 2):
                    cands.append((cx, vcy, (m + vm) / 2.0))
                    break
    clusters = []
    for cx, cy, m in cands:
        for c in clusters:
            if abs(c["x"] - cx) <= max(2.0, m * 1.5) and abs(c["y"] - cy) <= max(2.0, m * 1.5):
                c["pts"].append((cx, cy, m))
                c["x"] = sum(p[0] for p in c["pts"]) / len(c["pts"])
                c["y"] = sum(p[1] for p in c["pts"]) / len(c["pts"])
                c["m"] = sum(p[2] for p in c["pts"]) / len(c["pts"])
                break
        else:
            clusters.append({"x": cx, "y": cy, "m": m, "pts": [(cx, cy, m)]})
    clusters.sort(key=lambda c: len(c["pts"]), reverse=True)
    return clusters


def _dist(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


def _sample_module(binary, w, h, fx, fy, m):
    r = max(1, int(m * 0.25))
    ix, iy = int(round(fx)), int(round(fy))
    dark = 0
    tot = 0
    for dy in range(-r, r + 1):
        for dx in range(-r, r + 1):
            x, y = ix + dx, iy + dy
            if 0 <= x < w and 0 <= y < h:
                tot += 1
                if binary[y * w + x]:
                    dark += 1
    if tot == 0:
        return 0
    return 1 if dark * 2 > tot else 0


def qr_matrix_extract(path):
    """自研二维码模块矩阵提取：二值化 → 定位图案 → 版本估计 → 仿射抽样。

    不做格式信息/RS 纠错解码，只输出模块矩阵、版本号与模块尺寸，供人工判读。
    """
    px = load_pixels(path)
    w, h = px["width"], px["height"]
    rgb = px["rgb"]
    gray = bytes((rgb[i * 3] * 299 + rgb[i * 3 + 1] * 587 + rgb[i * 3 + 2] * 114) // 1000
                 for i in range(w * h))
    thr = _otsu_threshold(gray)
    binary = bytearray(1 if v <= thr else 0 for v in gray)

    attempts = []
    for polarity, buf in (("normal", binary),
                          ("inverted", bytearray(1 - b for b in binary))):
        clusters = _find_finders(buf, w, h)
        strong = [c for c in clusters if len(c["pts"]) >= 3] or clusters
        if len(strong) < 3:
            attempts.append({"polarity": polarity, "error": "定位图案不足 3 个",
                             "found": len(clusters)})
            continue
        strong = strong[:12]
        trio = None
        best_score = None
        for i in range(len(strong)):
            for j in range(i + 1, len(strong)):
                for k in range(j + 1, len(strong)):
                    trio_pts = [strong[i], strong[j], strong[k]]
                    pt = [(t["x"], t["y"]) for t in trio_pts]
                    sides = sorted([_dist(pt[0], pt[1]), _dist(pt[0], pt[2]),
                                    _dist(pt[1], pt[2])])
                    if sides[2] <= 0 or sides[0] <= 0:
                        continue
                    ratio = sides[0] / sides[2]
                    # 直角等腰：两短边相等且 = 斜边/√2
                    score = abs(ratio - 0.7071) + abs(sides[0] - sides[1]) / sides[2]
                    if best_score is None or score < best_score:
                        best_score = score
                        trio = trio_pts
        if trio is None:
            attempts.append({"polarity": polarity, "error": "三定位图案构不成直角"})
            continue
        pt = [(t["x"], t["y"]) for t in trio]
        d01, d02, d12 = _dist(pt[0], pt[1]), _dist(pt[0], pt[2]), _dist(pt[1], pt[2])
        sides = sorted([(d01, (0, 1)), (d02, (0, 2)), (d12, (1, 2))])
        legs = sides[0][1], sides[1][1]
        hyp = sides[2][1]
        tl_idx = ({0, 1, 2} - set(hyp)).pop()
        TL = pt[tl_idx]
        P1, P2 = pt[hyp[0]], pt[hyp[1]]
        cross = (P1[0] - TL[0]) * (P2[1] - TL[1]) - (P1[1] - TL[1]) * (P2[0] - TL[0])
        if cross >= 0:
            TR, BL = P1, P2
        else:
            TR, BL = P2, P1
        m_est = sum(t["m"] for t in trio) / 3.0
        if m_est <= 0:
            continue
        dim_est = (_dist(TL, TR) / m_est + _dist(TL, BL) / m_est) / 2.0 + 7.0
        version = int(round((dim_est - 17) / 4.0))
        version = max(1, min(40, version))
        attempts.append({"polarity": polarity, "TL": TL, "TR": TR, "BL": BL,
                         "module_estimate": m_est,
                         "raw_dimension_estimate": dim_est,
                         "version": version, "size": 17 + 4 * version})

    valid = [a for a in attempts if "error" not in a]
    if not valid:
        detail = "; ".join("%s:%s" % (a["polarity"], a.get("error")) for a in attempts)
        raise ValueError("未能在图像中定位二维码（%s）" % detail)
    best = min(valid, key=lambda a: abs(a["raw_dimension_estimate"] - a["size"]))
    buf = binary if best["polarity"] == "normal" else bytearray(1 - b for b in binary)
    dim = best["size"]
    TL, TR, BL = best["TL"], best["TR"], best["BL"]
    ex = ((TR[0] - TL[0]) / (dim - 7.0), (TR[1] - TL[1]) / (dim - 7.0))
    ey = ((BL[0] - TL[0]) / (dim - 7.0), (BL[1] - TL[1]) / (dim - 7.0))
    m = best["module_estimate"]
    matrix = []
    for r in range(dim):
        row = []
        for c in range(dim):
            fx = TL[0] + ((c + 0.5) - 3.5) * ex[0] + ((r + 0.5) - 3.5) * ey[0]
            fy = TL[1] + ((c + 0.5) - 3.5) * ex[1] + ((r + 0.5) - 3.5) * ey[1]
            row.append(_sample_module(buf, w, h, fx, fy, m))
        matrix.append(row)
    return {
        "path": os.path.abspath(path), "width": w, "height": h,
        "threshold": thr, "polarity": best["polarity"],
        "module_size": round(m, 3), "version": best["version"],
        "size": dim, "matrix": matrix,
        "finder_centers": {"TL": [round(v, 2) for v in TL],
                           "TR": [round(v, 2) for v in TR],
                           "BL": [round(v, 2) for v in BL]},
        "dimension_estimate": round(best["raw_dimension_estimate"], 2),
        "note": "仅提取模块矩阵（未做格式信息/RS 纠错解码）",
    }


def matrix_to_ascii(matrix):
    """把 0/1 矩阵渲染成 █/空格，便于人工判读。"""
    return "\n".join("".join("██" if v else "  " for v in row) for row in matrix)


if __name__ == "__main__":
    import sys
    table = {"lsb": lsb_scan, "append": appended_data, "exif": exif_all,
             "qr": qr_decode, "png": png_chunks, "u16": strings_utf16,
             "embed": embedded_archives}
    if len(sys.argv) > 2 and sys.argv[1] in table:
        print(table[sys.argv[1]](sys.argv[2]))
    else:
        print("usage: python -m mkit.stego [lsb|append|exif|qr|png|u16|embed] <file>")
