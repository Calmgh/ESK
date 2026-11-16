# -*- coding: utf-8 -*-
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  原类型预览 / PE · ELF · Mach-O 结构视图
# ============================================================
"""原类型预览 —— 不知道手里是什么字节时先看它一眼。

三件事：
    1. 类型识别      sniff(head_bytes, name=None) -> {"kind","mime","detail"}
    2. 人眼友好预览  text_preview / hex_preview / media_info
    3. 可执行结构    pe_info / elf_info / macho_info

统一入口：
    from mkit.preview import preview
    r = preview(open("a.exe","rb").read())
    print(r["kind"]); print(r["text"])

设计约定：
    * 只看头部就能定的（图片 / 容器 / 归档）不做深度解析，拿不到就标 None；
    * 结构解析失败不抛栈，返回 {"error": "..."} 让上层渲染成一行提示；
    * 纯 stdlib，无第三方依赖。
"""

from __future__ import annotations

import datetime
import io
import json
import re
import struct
import zipfile
import zlib

__all__ = ["sniff", "text_preview", "hex_preview", "media_info",
           "pe_info", "elf_info", "macho_info", "preview"]


# ============================================================
#  常量
# ============================================================

MIME = {
    "pe": "application/vnd.microsoft.portable-executable",
    "elf": "application/x-elf",
    "macho": "application/x-mach-binary",
    "fatmacho": "application/x-mach-binary",
    "png": "image/png",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "tiff": "image/tiff",
    "webp": "image/webp",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "gzip": "application/gzip",
    "bz2": "application/x-bzip2",
    "xz": "application/x-xz",
    "7z": "application/x-7z-compressed",
    "rar": "application/vnd.rar",
    "tar": "application/x-tar",
    "sqlite": "application/vnd.sqlite3",
    "regf": "application/x-windows-registry",
    "evtx": "application/x-evtx",
    "ole2": "application/x-ole-storage",
    "rtf": "application/rtf",
    "wav": "audio/wav",
    "avi": "video/x-msvideo",
    "mp4": "video/mp4",
    "mkv": "video/x-matroska",
    "webm": "video/webm",
    "ebml": "application/ebml",
    "text": "text/plain",
    "json": "application/json",
    "xml": "application/xml",
    "html": "text/html",
    "unknown": "application/octet-stream",
}

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# 魔数表来源：mkit/carve.py 的 CARVERS（复制一份常量，不 import 其私有函数）
# 前缀签名 —— 命中即定性，顺序即优先级
_MAGIC = [
    (b"\xff\xd8\xff", "jpeg"),
    (PNG_SIG, "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"Rar!\x1a\x07\x01\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (b"\x7fELF", "elf"),
    (b"regf", "regf"),
    (b"ElfFile\x00", "evtx"),
    (b"{\\rtf", "rtf"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bz2"),
]

# Mach-O 四种字节序/位宽变体 + fat
_MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe": ("macho", 32, "<"),
    b"\xcf\xfa\xed\xfe": ("macho", 64, "<"),
    b"\xfe\xed\xfa\xce": ("macho", 32, ">"),
    b"\xfe\xed\xfa\xcf": ("macho", 64, ">"),
    b"\xca\xfe\xba\xbe": ("fatmacho", None, ">"),
    b"\xbe\xba\xfe\xca": ("fatmacho", None, "<"),
}

_ELF_MACHINE = {
    0: "none", 2: "sparc", 3: "x86", 4: "m68k", 8: "mips", 0x14: "ppc",
    0x15: "ppc64", 0x16: "s390", 0x28: "arm", 0x2A: "sh", 0x32: "ia64",
    0x3E: "x86-64", 0xB7: "aarch64", 0xF3: "riscv", 0x102: "loongarch",
}

_ELF_TYPE = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}

_ELF_OSABI = {
    0: "SYSV", 1: "HPUX", 2: "NETBSD", 3: "LINUX", 4: "HURD",
    6: "SOLARIS", 7: "AIX", 8: "IRIX", 9: "FREEBSD", 10: "TRU64",
    11: "MODESTO", 12: "OPENBSD", 13: "OPENVMS", 14: "NSK", 15: "AROS",
    16: "FENIXOS", 17: "CLOUDABI", 64: "ARM_AEABI", 97: "ARM",
}

_ELF_PHDR_TYPE = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
    5: "SHLIB", 6: "PHDR", 7: "TLS", 0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO", 0x6474E550: "GNU_EH_FRAME",
    0x6474E553: "GNU_PROPERTY",
}

_MACHO_CPU = {
    7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
    18: "ppc", 0x01000012: "ppc64", 0x0200000C: "arm64_32",
}

_MACHO_FILETYPE = {
    1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB", 4: "CORE", 5: "PRELOAD",
    6: "DYLIB", 7: "DYLINKER", 8: "BUNDLE", 9: "DYLIB_STUB",
    10: "DSYM", 11: "KEXT_BUNDLE", 12: "FILESET",
}

_PE_MACHINE = {
    0x014C: "i386", 0x8664: "x86-64", 0x01C0: "ARM", 0x01C4: "ARMv7",
    0xAA64: "ARM64", 0x0200: "IA64", 0x01F0: "PowerPC", 0x0EBC: "EBC",
    0x5032: "RISCV32", 0x5064: "RISCV64", 0x6264: "LOONGARCH64",
}

_PE_SUBSYSTEM = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
    5: "OS2_CUI", 7: "POSIX_CUI", 8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}

_PE_CHAR = [
    (0x0001, "RELOCS_STRIPPED"), (0x0002, "EXECUTABLE"),
    (0x0004, "LINE_NUMS_STRIPPED"), (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0010, "AGGRESSIVE_WS_TRIM"), (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0100, "32BIT_MACHINE"), (0x0200, "DEBUG_STRIPPED"),
    (0x0400, "REMOVABLE_RUN_FROM_SWAP"), (0x0800, "NET_RUN_FROM_SWAP"),
    (0x1000, "SYSTEM"), (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"),
]

_PE_DLLCHAR = [
    (0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"), (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"), (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"), (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"), (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]


# ============================================================
#  小工具
# ============================================================

def _u8(b, off):
    return b[off] if 0 <= off < len(b) else None


def _u16(b, off, endian="<"):
    if off < 0 or off + 2 > len(b):
        return None
    return struct.unpack_from(endian + "H", b, off)[0]


def _u32(b, off, endian="<"):
    if off < 0 or off + 4 > len(b):
        return None
    return struct.unpack_from(endian + "I", b, off)[0]


def _u64(b, off, endian="<"):
    if off < 0 or off + 8 > len(b):
        return None
    return struct.unpack_from(endian + "Q", b, off)[0]


def _cstr(b, off, limit=512):
    """读 NUL 结尾字符串，越界返回 None。"""
    if off < 0 or off >= len(b):
        return None
    end = b.find(b"\x00", off)
    if end < 0 or end - off > limit:
        end = min(len(b), off + limit)
    try:
        return b[off:end].decode("utf-8", "replace")
    except Exception:
        return None


def _stamp(v):
    """DWORD 时间戳 → 可读 UTC。"""
    if not v:
        return "0 (未设置)"
    try:
        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=int(v))
        return "%d (%s UTC)" % (v, dt.strftime("%Y-%m-%d %H:%M:%S"))
    except Exception:
        return str(v)


def _ratio_printable(s):
    if not s:
        return 0.0
    ok = 0
    for ch in s:
        if ch in "\r\n\t" or ch.isprintable():
            ok += 1
    return ok / float(len(s))


def _hexs(v, width=8):
    return ("0x%0*X" % (width, v)) if isinstance(v, int) else str(v)


# ============================================================
#  A. 类型识别
# ============================================================

def _decode_probe(b):
    """能当文本读就返回 (text, encoding, lossy)，否则 None。"""
    if b.startswith(b"\xef\xbb\xbf"):
        try:
            return b[3:].decode("utf-8"), "utf-8", False
        except UnicodeDecodeError:
            return b[3:].decode("utf-8", "replace"), "utf-8", True
    if b.startswith(b"\xff\xfe"):
        try:
            return b[2:].decode("utf-16-le"), "utf-16le", False
        except UnicodeDecodeError:
            return b[2:].decode("utf-16-le", "replace"), "utf-16le", True
    if b.startswith(b"\xfe\xff"):
        try:
            return b[2:].decode("utf-16-be"), "utf-16be", False
        except UnicodeDecodeError:
            return b[2:].decode("utf-16-be", "replace"), "utf-16be", True

    for enc in ("utf-8", "gbk"):
        try:
            t = b.decode(enc)
        except UnicodeDecodeError:
            continue
        if _ratio_printable(t) >= 0.95:
            return t, enc, False

    if b"\x00" not in b:
        t = b.decode("latin-1")
        if _ratio_printable(t) >= 0.95:
            return t, "latin-1", False
    return None


def _looks_bmp(b):
    if len(b) < 26 or b[:2] != b"BM":
        return False
    dib = _u32(b, 14)
    if dib not in (12, 16, 40, 52, 56, 64, 108, 124):
        return False
    w = _u32(b, 18)
    h = _u32(b, 22)
    return bool(w) and bool(h)


def _looks_fat_macho(b):
    """0xCAFEBABE 同时是 Java class 魔数，用 nfat_arch 合理性区分。"""
    if len(b) < 8:
        return False
    n = _u32(b, 4, ">")
    if not n or n > 32:
        return False
    need = 8 + n * 20
    if need > len(b):
        return False
    for i in range(min(n, 8)):
        base = 8 + i * 20
        off = _u32(b, base + 8, ">")
        size = _u32(b, base + 12, ">")
        if off is None or size is None:
            return False
        if off == 0 or size == 0:
            return False
    return True


def _classify(b, name=None):
    n = len(b)
    if n == 0:
        return "unknown", MIME["unknown"], "空输入 (0 字节)"

    # ---- 可执行 ----
    if b[:2] == b"MZ":
        e = _u32(b, 0x3C)
        if e and 4 <= e <= n - 4 and b[e:e + 4] == b"PE\x00\x00":
            magic = _u16(b, e + 24)
            machine = _u16(b, e + 4)
            mname = _PE_MACHINE.get(machine, _hexs(machine, 4) if machine is not None else "?")
            kindtxt = {0x10B: "PE32", 0x20B: "PE32+", 0x107: "ROM"}.get(magic, "PE?")
            return "pe", MIME["pe"], "%s / %s" % (kindtxt, mname)
        return "pe", MIME["pe"], "MZ 头，未找到有效 PE 签名"

    if b[:4] == b"\x7fELF":
        cls = _u8(b, 4)
        endian = {1: "<", 2: ">"}.get(_u8(b, 5) or 0, "<")
        etype = _u16(b, 16, endian)
        mach = _u16(b, 18, endian)
        return ("elf", MIME["elf"], "ELF%s %s %s / %s" % (
            {1: "32", 2: "64"}.get(cls, "?"),
            "LE" if endian == "<" else "BE",
            _ELF_TYPE.get(etype, _hexs(etype, 2) if etype is not None else "?"),
            _ELF_MACHINE.get(mach, _hexs(mach, 2) if mach is not None else "?")))

    mg = _MACHO_MAGICS.get(b[:4])
    if mg:
        kind, bits, _endian = mg
        if kind == "fatmacho" and not _looks_fat_macho(b):
            # Java class 或损坏的 fat 头
            pass
        else:
            if kind == "macho":
                cput = _u32(b, 4, _endian)
                return "macho", MIME["macho"], "Mach-O %d-bit %s" % (
                    bits, _MACHO_CPU.get(cput, _hexs(cput, 8) if cput is not None else "?"))
            nfat = _u32(b, 4, _endian)
            return "fatmacho", MIME["fatmacho"], "fat Mach-O, %s 个架构" % nfat

    # ---- 图片 ----
    if b[:8] == PNG_SIG:
        w = _u32(b, 16, ">")
        h = _u32(b, 20, ">")
        return "png", MIME["png"], "PNG %sx%s" % (w, h)
    if b[:3] == b"\xff\xd8\xff":
        return "jpeg", MIME["jpeg"], "JPEG (SOI %s)" % (
            "%02X" % b[3] if n > 3 else "?")
    if b[:6] in (b"GIF87a", b"GIF89a"):
        w = _u16(b, 6)
        h = _u16(b, 8)
        return "gif", MIME["gif"], "GIF %s %sx%s" % (
            b[:6].decode("ascii"), w, h)
    if b[:2] == b"BM" and _looks_bmp(b):
        return "bmp", MIME["bmp"], "BMP %sx%s" % (_u32(b, 18), _u32(b, 22))
    if b[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff", MIME["tiff"], "TIFF (%s)" % (
            "little-endian" if b[:2] == b"II" else "big-endian")
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp", MIME["webp"], "WebP (%s)" % b[12:16].decode("ascii", "replace")

    # ---- 文档 ----
    if b[:5] == b"%PDF-":
        ver = b[5:8].decode("ascii", "replace")
        return "pdf", MIME["pdf"], "PDF %s" % ver
    if b[:5] == b"{\\rtf":
        return "rtf", MIME["rtf"], "RTF"

    # ---- 归档 / 压缩 ----
    for sig, kind in _MAGIC:
        if kind in ("jpeg", "png", "gif", "pdf", "rtf", "tiff", "elf"):
            continue
        if b.startswith(sig):
            detail = {
                "zip": "ZIP (PKZIP/APK/JAR/OOXML)",
                "rar": "RAR %s" % ("v5" if len(sig) == 8 else "v1.5-4.x"),
                "7z": "7-Zip",
                "gzip": "gzip",
                "bz2": "bzip2",
                "xz": "xz",
                "sqlite": "SQLite 3 数据库",
                "ole2": "OLE2 复合文档 (doc/xls/ppt/msg)",
                "regf": "Windows 注册表 hive",
                "evtx": "Windows 事件日志 EVTX",
            }.get(kind, kind)
            return kind, MIME.get(kind, MIME["unknown"]), detail

    if n >= 262 and b[257:262] == b"ustar":
        return "tar", MIME["tar"], "POSIX tar (magic@257)"

    # ---- 媒体容器 ----
    if b[:4] == b"RIFF":
        form = b[8:12].decode("ascii", "replace") if n >= 12 else "?"
        if form == "WAVE":
            return "wav", MIME["wav"], "RIFF/WAVE"
        if form == "AVI ":
            return "avi", MIME["avi"], "RIFF/AVI"
        return "riff", MIME["unknown"], "RIFF/%s" % form
    if n >= 8 and b[4:8] == b"ftyp":
        brand = b[8:12].decode("ascii", "replace") if n >= 12 else "?"
        return "mp4", MIME["mp4"], "ISO BMFF (ftyp %s)" % brand
    if b[:4] == b"\x1aE\xdf\xa3":
        head = b[:256]
        if b"matroska" in head:
            return "mkv", MIME["mkv"], "Matroska (EBML)"
        if b"webm" in head:
            return "webm", MIME["webm"], "WebM (EBML)"
        return "ebml", MIME["ebml"], "EBML (容器未定)"

    # ---- 文本 ----
    probe = _decode_probe(b)
    if probe is not None:
        text, enc, _lossy = probe
        s = text.lstrip("\ufeff \t\r\n")
        low = s[:512].lower()
        if s[:1] in ("{", "["):
            try:
                json.loads(s)
                return "json", MIME["json"], "JSON (编码 %s)" % enc
            except Exception:
                if s[:1] == "{":
                    return "json", MIME["json"], "形似 JSON 对象但解析失败 (编码 %s)" % enc
        if low.startswith("<!doctype html") or low.startswith("<html"):
            return "html", MIME["html"], "HTML (编码 %s)" % enc
        if low.startswith("<?xml"):
            return "xml", MIME["xml"], "XML (编码 %s)" % enc
        if s[:1] == "<" and ">" in s[:200]:
            return "xml", MIME["xml"], "形似标记语言 (编码 %s)" % enc
        return "text", MIME["text"], "文本 (编码 %s, %d 字节)" % (enc, n)

    hint = ("来自文件名 %s；" % name) if name else ""
    return "unknown", MIME["unknown"], "%s无匹配魔数，%d 字节" % (hint, n)


def sniff(head_bytes, name=None):
    """按魔数 + 启发式判断类型。

    返回 {"kind": str, "mime": str, "detail": str, "size": int}
    """
    b = bytes(head_bytes or b"")
    kind, mime, detail = _classify(b, name)
    return {"kind": kind, "mime": mime, "detail": detail, "size": len(b)}


# ============================================================
#  B. 文本预览
# ============================================================

def _decode_text(b, encoding=None):
    """返回 (text, encoding, lossy)。"""
    if encoding:
        enc = encoding.lower()
        try:
            if enc in ("utf-8", "utf8"):
                return b.decode("utf-8"), "utf-8", False
            if enc in ("utf-16le", "utf-16-le"):
                return b.decode("utf-16-le"), "utf-16le", False
            if enc in ("utf-16be", "utf-16-be"):
                return b.decode("utf-16-be"), "utf-16be", False
            return b.decode(encoding), encoding, False
        except (UnicodeDecodeError, LookupError):
            return b.decode(encoding if encoding else "utf-8", "replace"), encoding, True

    probe = _decode_probe(b)
    if probe is not None:
        return probe[0], probe[1], probe[2]
    return b.decode("utf-8", "replace"), "utf-8", True


def _escape_ctrl(line):
    out = []
    for ch in line:
        o = ord(ch)
        if ch == "\t":
            out.append(ch)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def text_preview(data, max_lines=200, max_cols=100, encoding=None):
    """文本预览：自动编码探测 + 控制字符转义 + 行/列截断。"""
    b = bytes(data or b"")
    if not b:
        return "# 空数据 (0 字节)"

    text, enc, lossy = _decode_text(b, encoding)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    if lines and lines[-1] == "" and len(lines) > 1:
        lines.pop()                      # 结尾换行不算一行

    total = len(lines)
    max_lines = int(max_lines) if max_lines and max_lines > 0 else 0
    shown = lines if not max_lines else lines[:max_lines]

    head = "# encoding=%s%s  bytes=%d  lines=%d  shown=%d" % (
        enc, " (errors=replace)" if lossy else "", len(b), total, len(shown))
    body = []
    for ln in shown:
        s = _escape_ctrl(ln)
        if max_cols and len(s) > max_cols:
            s = s[:max_cols] + "…"
        body.append(s)

    out = [head] + body
    if max_lines and total > max_lines:
        out.append("… 已截断：共 %d 行，只显示前 %d 行" % (total, max_lines))
    return "\n".join(out)


# ============================================================
#  C. 十六进制预览
# ============================================================

def hex_preview(data, offset=0, width=16, max_rows=64):
    """标准 offset / hex / ascii 三列。

    行格式： ``00000000  00 01 .. 07  08 .. 0f  |................|``
    半行（组间）多一个空格，ASCII 列定宽对齐。
    """
    b = bytes(data or b"")
    if not b:
        return "[空数据 0 字节]"

    width = int(width or 16)
    if width < 1 or width > 64:
        width = 16
    group = max(1, width // 2)
    field = width * 3 - 1 + (width // group - 1 if width > group else 0)

    rows = int(max_rows) if max_rows and max_rows > 0 else 0
    limit = len(b) if not rows else min(len(b), rows * width)

    lines = []
    for pos in range(0, limit, width):
        chunk = b[pos:pos + width]
        parts = []
        for i in range(width):
            if i and i % group == 0:
                parts.append("")         # 组间分隔
            parts.append("%02x" % chunk[i] if i < len(chunk) else "  ")
        hexpart = " ".join(parts)
        ascii_part = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append("%08x  %s  |%s|" % (
            offset + pos, hexpart.ljust(field), ascii_part.ljust(width)))

    if limit < len(b):
        lines.append("… 已截断：剩余 %d 字节未显示（共 %d 字节）" % (
            len(b) - limit, len(b)))
    return "\n".join(lines)


# ============================================================
#  D. 图片 / 音视频 / PDF / Office 元信息
# ============================================================

_PNG_COLOR = {
    0: "灰度", 2: "真彩 RGB", 3: "索引调色板", 4: "灰度+Alpha",
    6: "真彩 RGBA",
}

_JPEG_SOF = {0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC3: "SOF3",
             0xC5: "SOF5", 0xC6: "SOF6", 0xC7: "SOF7",
             0xC9: "SOF9", 0xCA: "SOF10", 0xCB: "SOF11",
             0xCD: "SOF13", 0xCE: "SOF14", 0xCF: "SOF15"}

_JPEG_SEG = {
    0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT", 0xDD: "DRI",
    0xC4: "DHT", 0xC8: "JPG", 0xCC: "DAC", 0xFE: "COM", 0x01: "TEM",
}
for _i in range(16):
    _JPEG_SEG.setdefault(0xE0 + _i, "APP%d" % _i)
for _m, _nm in _JPEG_SOF.items():
    _JPEG_SEG.setdefault(_m, _nm)


def _png_info(b):
    out = {"kind": "png", "family": "image"}
    if len(b) < 33:
        out["error"] = "头部不足 33 字节，无法读 IHDR"
        return out
    w, h, bd, ct, comp, filt, inter = struct.unpack_from(">IIBBBBB", b, 16)
    out.update(width=w, height=h, bit_depth=bd, color_type=ct,
               color_name=_PNG_COLOR.get(ct, "未知"),
               compression=comp, filter=filt,
               interlace="Adam7" if inter else "none")
    chunks = []
    pos = 8
    while pos + 8 <= len(b) and len(chunks) < 64:
        ln = _u32(b, pos, ">")
        typ = b[pos + 4:pos + 8]
        if ln is None or ln > 0x7FFFFFFF:
            out["error"] = "chunk 长度异常 @0x%X" % pos
            break
        chunks.append((typ.decode("latin-1"), ln))
        if typ == b"IEND":
            break
        pos += 12 + ln
    out["chunks"] = chunks
    if not chunks:
        out["error"] = "chunk 列表为空（数据被截断？）"
    return out


def _jpeg_info(b):
    out = {"kind": "jpeg", "family": "image", "segments": []}
    pos = 2                      # 跳过 SOI
    out["segments"].append(("SOI", 0, 0))
    while pos + 1 < len(b):
        if b[pos] != 0xFF:
            out["error"] = "段边界不同步 @0x%X（可能已进入熵编码数据）" % pos
            break
        m = b[pos + 1]
        if m == 0xFF:            # 填充字节
            pos += 1
            continue
        if m == 0xD9:
            out["segments"].append(("EOI", pos, 0))
            break
        if 0xD0 <= m <= 0xD7 or m == 0x01:
            pos += 2
            continue
        ln = _u16(b, pos + 2, ">")
        if ln is None or ln < 2:
            out["error"] = "段长度非法 @0x%X" % pos
            break
        name = _JPEG_SEG.get(m, "0x%02X" % m)
        out["segments"].append((name, pos, ln))
        if m in _JPEG_SOF:
            if pos + 9 <= len(b):
                out["precision"] = b[pos + 4]
                out["height"] = _u16(b, pos + 5, ">")
                out["width"] = _u16(b, pos + 7, ">")
                out["components"] = b[pos + 9]
                out["sof"] = name
        if m == 0xDA:            # SOS 之后是压缩数据，停止扫描
            break
        pos += 2 + ln

    if "width" not in out:
        out.setdefault("error", "未遇到 SOF 段，拿不到宽高")
    return out


def _gif_skip_sub(b, pos):
    """跳过 GIF 数据子块链，返回下一个块位置。"""
    while pos < len(b):
        n = b[pos]
        pos += 1
        if n == 0:
            return pos
        pos += n
    return pos


def _gif_info(b):
    out = {"kind": "gif", "family": "image"}
    if len(b) < 13:
        out["error"] = "头部不足 13 字节"
        return out
    out["version"] = b[:6].decode("ascii", "replace")
    out["width"] = _u16(b, 6)
    out["height"] = _u16(b, 8)
    flags = b[10]
    out["global_palette"] = bool(flags & 0x80)
    out["background_index"] = b[11]
    pos = 13
    if flags & 0x80:
        pos += 3 * (2 ** ((flags & 0x07) + 1))
    frames = 0
    while pos < len(b):
        tag = b[pos]
        if tag == 0x3B:                      # trailer
            break
        if tag == 0x21:                      # extension
            pos += 2
            pos = _gif_skip_sub(b, pos)
        elif tag == 0x2C:                    # image descriptor
            if pos + 10 > len(b):
                break
            frames += 1
            iflags = b[pos + 9]
            pos += 10
            if iflags & 0x80:
                pos += 3 * (2 ** ((iflags & 0x07) + 1))
            pos += 1                          # LZW min code size
            pos = _gif_skip_sub(b, pos)
        else:
            out["error"] = "块不识别 0x%02X @0x%X" % (tag, pos)
            break
    out["frames"] = frames
    if frames == 0:
        out.setdefault("error", "未找到图像描述符，帧数按 0 计（可能被截断）")
    return out


def _bmp_info(b):
    out = {"kind": "bmp", "family": "image"}
    if len(b) < 26:
        out["error"] = "头部不足 26 字节"
        return out
    out["dib_size"] = _u32(b, 14)
    out["width"] = _u32(b, 18)
    hraw = _u32(b, 22)
    if hraw is not None:
        out["height"] = hraw if hraw < 0x80000000 else hraw - 0x100000000
        out["bottom_up"] = hraw < 0x80000000
    if out["dib_size"] and out["dib_size"] >= 40 and len(b) >= 34:
        out["bit_count"] = _u16(b, 28)
        out["compression"] = _u32(b, 30)
        out["image_size"] = _u32(b, 34) if len(b) >= 38 else None
    elif out["dib_size"] == 12 and len(b) >= 26:
        out["bit_count"] = _u16(b, 24)
        out["compression"] = 0
    if not out.get("width") or not out.get("height"):
        out.setdefault("error", "宽高为 0 或不可读")
    return out


_PDF_COUNT_RE = re.compile(rb"/Count\s+(\d+)")


def _pdf_info(b):
    out = {"kind": "pdf", "family": "pdf"}
    if not b.startswith(b"%PDF-"):
        out["error"] = "缺少 %PDF- 头"
        return out
    out["version"] = b[5:8].decode("ascii", "replace").strip()
    # 头部注释里可能声明二进制标记
    out["binary_marker"] = b"%\xe2\xe3\xcf\xd3" in b[:1024]
    out["encrypted"] = b"/Encrypt" in b
    counts = [int(m.group(1)) for m in _PDF_COUNT_RE.finditer(b)]
    out["page_count_candidates"] = counts
    out["pages"] = max(counts) if counts else None
    out["has_pages_node"] = b"/Type /Pages" in b or b"/Type/Pages" in b
    out["has_page_node"] = b"/Type /Page" in b or b"/Type/Page" in b
    out["linearized"] = b"/Linearized" in b
    out["object_stream"] = b"/ObjStm" in b
    out["xref_stream"] = b"/XRef" in b
    out["trailer_count"] = b.count(b"%%EOF")
    if out["pages"] is None:
        out["note"] = "未找到 /Count（流压缩或数据被截断时拿不到）"
    return out


def _riff_info(b):
    out = {"family": "av"}
    if len(b) < 12:
        out.update(kind="riff", error="RIFF 头不足 12 字节")
        return out
    form = b[8:12].decode("latin-1")
    out["riff_size"] = _u32(b, 4)
    if form == "WAVE":
        out["kind"] = "wav"
        pos = 12
        while pos + 8 <= len(b):
            cid = b[pos:pos + 4]
            sz = _u32(b, pos + 4)
            if sz is None:
                break
            if cid == b"fmt " and pos + 8 + 16 <= len(b):
                fmt, ch, sr = struct.unpack_from("<HHI", b, pos + 8)
                br = _u32(b, pos + 16)
                ba = _u16(b, pos + 20)
                bits = _u16(b, pos + 22)
                out.update(audio_format=fmt, channels=ch, sample_rate=sr,
                           byte_rate=br, block_align=ba, bits_per_sample=bits)
            elif cid == b"data":
                out["data_size"] = sz
                if out.get("byte_rate"):
                    out["duration_sec"] = round(sz / float(out["byte_rate"]), 3)
            pos += 8 + sz + (sz & 1)
        if "channels" not in out:
            out["error"] = "未找到 fmt chunk"
        return out
    if form == "AVI ":
        out["kind"] = "avi"
        out["has_hdrl"] = b"hdrl" in b
        out["has_movi"] = b"movi" in b
        streams = b.count(b"strh")
        out["stream_count"] = streams or None
        return out
    out["kind"] = "riff"
    out["error"] = "未知 RIFF 子类型 %r" % form
    return out


def _mp4_info(b):
    out = {"kind": "mp4", "family": "av"}
    if len(b) < 12 or b[4:8] != b"ftyp":
        out["error"] = "缺少 ftyp box"
        return out
    out["major_brand"] = b[8:12].decode("latin-1").strip()
    out["minor_version"] = _u32(b, 12, ">")
    # ISO BMFF：ftyp = size(4) type(4) major_brand(4) minor_version(4)
    #                         + compatible_brands(4×n)
    # 兼容品牌在 ftyp box **内部**，不是独立的 box，所以不能按 box 去读。
    size_ftyp = _u32(b, 0, ">") or 0
    if size_ftyp < 16 or size_ftyp > len(b):
        size_ftyp = len(b)
    brands = []
    for i in range(16, size_ftyp - 3, 4):
        br = b[i:i + 4].decode("latin-1")
        if br.strip("\x00 ") == "":
            continue
        brands.append(br)
    out["compatible_brands"] = brands
    # ftyp 之后的顶层 box 才按 size/type 链式走
    boxes = []
    pos = size_ftyp
    limit = min(len(b), size_ftyp + 4096)
    while pos + 8 <= limit and len(boxes) < 32:
        sz = _u32(b, pos, ">")
        name = b[pos + 4:pos + 8].decode("latin-1")
        boxes.append((name, sz))
        if not sz or sz < 8:
            break
        pos += sz
    out["boxes"] = boxes
    out["has_moov"] = b"moov" in b or any(n == "moov" for n, _ in boxes)
    out["has_mdat"] = b"mdat" in b or any(n == "mdat" for n, _ in boxes)
    return out


def _ebml_info(b):
    out = {"family": "av"}
    if b[:4] != b"\x1aE\xdf\xa3":
        out.update(kind="ebml", error="缺少 EBML 头")
        return out
    head = b[:256]
    doctype = None
    i = head.find(b"\x42\x82")            # DocType
    if i >= 0 and i + 3 <= len(head):
        size = head[i + 2] & 0x7F
        raw = head[i + 3:i + 3 + size]
        doctype = raw.decode("ascii", "replace")
    out["doctype"] = doctype
    if doctype == "webm":
        out["kind"] = "webm"
    elif doctype == "matroska":
        out["kind"] = "mkv"
    else:
        out["kind"] = "ebml"
    j = head.find(b"\x42\x87")            # DocTypeVersion
    if j >= 0 and j + 2 < len(head):
        out["doctype_version"] = head[j + 2] & 0x7F
    if doctype is None:
        out.setdefault("error", "未找到 DocType 元素")
    return out


_CORE_TITLE = re.compile(r"<dc:title>(.*?)</dc:title>", re.S)
_CORE_CREATOR = re.compile(r"<dc:creator>(.*?)</dc:creator>", re.S)
_CORE_LASTBY = re.compile(r"<cp:lastModifiedBy>(.*?)</cp:lastModifiedBy>", re.S)
_CORE_CREATED = re.compile(r"<dcterms:created[^>]*>(.*?)</dcterms:created>", re.S)
_CORE_MODIFIED = re.compile(r"<dcterms:modified[^>]*>(.*?)</dcterms:modified>", re.S)


def _xml_text(m):
    if not m:
        return None
    s = m.group(1).strip()
    s = re.sub(r"<[^>]+>", "", s)
    return s or None


def _office_info(b):
    out = {"kind": "office", "family": "office"}
    if b[:2] != b"PK":
        out["error"] = "不是 zip（OOXML 才支持）"
        return out
    try:
        zf = zipfile.ZipFile(io.BytesIO(b))
    except Exception as e:
        out["error"] = "zip 解析失败: %s" % e
        return out
    names = zf.namelist()
    out["zip_members"] = len(names)
    out["content_types"] = "[Content_Types].xml" in names
    out["core_props"] = "docProps/core.xml" in names
    if any(n.startswith("word/") for n in names):
        out["document"] = "docx"
    elif any(n.startswith("xl/") for n in names):
        out["document"] = "xlsx"
    elif any(n.startswith("ppt/") for n in names):
        out["document"] = "pptx"
    elif "AndroidManifest.xml" in names:
        out["document"] = "apk"
    else:
        out["document"] = None
    if "[Content_Types].xml" in names:
        try:
            ct = zf.read("[Content_Types].xml").decode("utf-8", "replace")
            out["content_types_declared"] = len(re.findall(r"<Override", ct))
        except Exception as e:
            out["error"] = "读 [Content_Types].xml 失败: %s" % e
    if "docProps/core.xml" in names:
        try:
            core = zf.read("docProps/core.xml").decode("utf-8", "replace")
            out["title"] = _xml_text(_CORE_TITLE.search(core))
            out["author"] = _xml_text(_CORE_CREATOR.search(core))
            out["last_modified_by"] = _xml_text(_CORE_LASTBY.search(core))
            out["created"] = _xml_text(_CORE_CREATED.search(core))
            out["modified"] = _xml_text(_CORE_MODIFIED.search(core))
        except Exception as e:
            out["error"] = "读 docProps/core.xml 失败: %s" % e
    else:
        out["note"] = "无 docProps/core.xml，标题/作者取不到"
    return out


def media_info(data):
    """图片 / 音视频 / PDF / Office 元信息。

    返回 dict，一定有 "kind"/"family"；解析不动就给 "error" 一行原因。
    """
    b = bytes(data or b"")
    if not b:
        return {"kind": None, "family": None, "error": "空数据"}

    try:
        if b[:8] == PNG_SIG:
            return _png_info(b)
        if b[:3] == b"\xff\xd8\xff":
            return _jpeg_info(b)
        if b[:6] in (b"GIF87a", b"GIF89a"):
            return _gif_info(b)
        if b[:2] == b"BM" and _looks_bmp(b):
            return _bmp_info(b)
        if b[:5] == b"%PDF-":
            return _pdf_info(b)
        if b[:4] == b"RIFF":
            return _riff_info(b)
        if len(b) >= 8 and b[4:8] == b"ftyp":
            return _mp4_info(b)
        if b[:4] == b"\x1aE\xdf\xa3":
            return _ebml_info(b)
        if b[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            return _office_info(b)
    except Exception as e:                     # 半截数据不崩
        return {"kind": None, "family": None,
                "error": "解析异常 %s: %s" % (type(e).__name__, e)}

    kind = _classify(b)[0]
    return {"kind": kind, "family": None,
            "note": "%s 不在 media_info 覆盖范围（仅图片/音视频/PDF/OOXML）" % kind}

# ============================================================
#  E. PE 视图
# ============================================================

_SEC_CHAR = [
    (0x00000020, "CODE"), (0x00000040, "IDATA"), (0x00000080, "UDATA"),
    (0x00000200, "INFO"), (0x00000800, "REMOVE"), (0x00001000, "COMDAT"),
    (0x02000000, "DISCARDABLE"), (0x04000000, "NOT_CACHED"),
    (0x08000000, "NOT_PAGED"), (0x10000000, "SHARED"),
    (0x20000000, "EXEC"), (0x40000000, "READ"), (0x80000000, "WRITE"),
]

_PE_DIRS = ["export", "import", "resource", "exception", "security",
            "reloc", "debug", "arch", "globalptr", "tls", "load_config",
            "bound_import", "iat", "delay_import", "com_descriptor",
            "reserved"]


def _pe_flags(value, table):
    return [name for bit, name in table if value & bit]


def _rva_to_off(rva, sections):
    """RVA → 文件偏移；落在未初始化区间或越界返回 None。"""
    for s in sections:
        va = s["virtual_address"]
        span = max(s["virtual_size"], s["raw_size"])
        if span and va <= rva < va + span:
            delta = rva - va
            if delta >= s["raw_size"]:
                return None
            return s["raw_ptr"] + delta
    return None


def _pe_imports(b, sections, start, bits, limit_dlls=256, limit_funcs=2048):
    out = []
    pos = start
    seen = set()
    while pos + 20 <= len(b) and len(out) < limit_dlls:
        if pos in seen:
            out.append({"dll": None, "functions": None, "error": "导入描述符成环 @0x%X" % pos})
            break
        seen.add(pos)
        oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", b, pos)
        if not oft and not name_rva and not ft:
            break
        noff = _rva_to_off(name_rva, sections)
        dll = _cstr(b, noff) if noff is not None else None
        item = {"dll": dll, "functions": []}
        if dll is None:
            item["error"] = "DLL 名 RVA 0x%X 无法映射到文件偏移" % name_rva
        thunk_rva = oft or ft
        toff = _rva_to_off(thunk_rva, sections)
        if toff is None:
            item["functions"] = None
            item["error"] = (item.get("error", "") + "；" if item.get("error") else "") + \
                "thunk 表 RVA 0x%X 越界" % thunk_rva
        else:
            step = 8 if bits == 64 else 4
            flag = (1 << 63) if bits == 64 else (1 << 31)
            mask = flag - 1
            i = 0
            while i < limit_funcs:
                off = toff + i * step
                if off + step > len(b):
                    item["truncated"] = True
                    break
                v = struct.unpack_from("<Q" if bits == 64 else "<I", b, off)[0]
                if v == 0:
                    break
                if v & flag:
                    item["functions"].append({"ordinal": v & 0xFFFF})
                else:
                    foff = _rva_to_off(v & mask, sections)
                    if foff is None or foff + 2 > len(b):
                        item["functions"].append({"name": None,
                                                  "note": "名称 RVA 0x%X 越界" % (v & mask)})
                    else:
                        hint = struct.unpack_from("<H", b, foff)[0]
                        item["functions"].append(
                            {"hint": hint, "name": _cstr(b, foff + 2, 512)})
                i += 1
            if i >= limit_funcs:
                item["truncated"] = True
        out.append(item)
        pos += 20
    return out


def pe_info(data):
    """PE32 / PE32+ 结构视图。失败返回 {"format":"pe","error":...}。"""
    b = bytes(data or b"")
    out = {"format": "pe"}

    if len(b) < 0x40:
        return {"format": "pe", "error": "只有 %d 字节，DOS 头不完整（需 0x40）" % len(b)}
    if b[:2] != b"MZ":
        return {"format": "pe", "error": "缺少 MZ 签名（前两字节 %r）" % b[:2]}

    e_lfanew = _u32(b, 0x3C)
    out["e_lfanew"] = e_lfanew
    out["dos_stub_bytes"] = max(0, (e_lfanew or 0) - 0x40)
    if e_lfanew is None or e_lfanew < 0x40:
        out["error"] = "e_lfanew=0x%X 非法" % (e_lfanew or 0)
        return out
    if e_lfanew + 24 > len(b):
        out["error"] = "e_lfanew=0x%X 超出文件长度 %d" % (e_lfanew, len(b))
        return out
    if b[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        out["error"] = "0x%X 处不是 PE\\0\\0（得到 %r）" % (
            e_lfanew, b[e_lfanew:e_lfanew + 4])
        return out

    coff = e_lfanew + 4
    machine, nsec, ts, _psym, _nsym, opt_size, chars = struct.unpack_from(
        "<HHIIIHH", b, coff)
    out.update(machine=_PE_MACHINE.get(machine, "0x%04X" % machine),
               machine_raw=machine,
               section_count=nsec,
               timestamp=_stamp(ts),
               timestamp_raw=ts,
               optional_header_size=opt_size,
               characteristics=_pe_flags(chars, _PE_CHAR),
               characteristics_raw=chars,
               is_dll=bool(chars & 0x2000))

    opt = coff + 20
    if opt_size == 0 or opt + opt_size > len(b):
        out["error"] = ("可选头被截断：需要 %d 字节，现存 %d"
                        % (opt_size, max(0, len(b) - opt)))
        out["sections"] = []
        return out

    magic = _u16(b, opt)
    bits = 64 if magic == 0x20B else 32
    out["optional_magic"] = "0x%X" % magic if magic is not None else None
    out["pe_type"] = {0x10B: "PE32", 0x20B: "PE32+", 0x107: "ROM"}.get(
        magic, "未知 0x%X" % (magic or 0))

    if magic == 0x20B:
        image_base = _u64(b, opt + 24)
        entry = _u32(b, opt + 16)
        sec_align = _u32(b, opt + 32)
        file_align = _u32(b, opt + 36)
        size_image = _u32(b, opt + 56)
        size_headers = _u32(b, opt + 60)
        subsystem = _u16(b, opt + 68)
        dllchar = _u16(b, opt + 70)
        nrva = _u32(b, opt + 108)
        dir_off = opt + 112
    else:
        image_base = _u32(b, opt + 28)
        entry = _u32(b, opt + 16)
        sec_align = _u32(b, opt + 32)
        file_align = _u32(b, opt + 36)
        size_image = _u32(b, opt + 56)
        size_headers = _u32(b, opt + 60)
        subsystem = _u16(b, opt + 68)
        dllchar = _u16(b, opt + 70)
        nrva = _u32(b, opt + 92)
        dir_off = opt + 96

    out.update(image_base=image_base, entry_point=entry,
               image_base_hex=_hexs(image_base, 16) if image_base is not None else None,
               entry_point_hex=_hexs(entry, 8) if entry is not None else None,
               section_alignment=sec_align, file_alignment=file_align,
               size_of_image=size_image, size_of_headers=size_headers,
               subsystem=_PE_SUBSYSTEM.get(subsystem, "0x%X" % (subsystem or 0)),
               subsystem_raw=subsystem,
               dll_characteristics=_pe_flags(dllchar or 0, _PE_DLLCHAR),
               rva_and_sizes=nrva,
               bits=bits)

    # 数据目录
    dirs = []
    if nrva:
        nrva_eff = min(nrva, 16, max(0, (opt + opt_size - dir_off) // 8))
        for i in range(nrva_eff):
            addr = _u32(b, dir_off + i * 8)
            size = _u32(b, dir_off + i * 8 + 4)
            dirs.append({"name": _PE_DIRS[i] if i < len(_PE_DIRS) else "dir%d" % i,
                         "rva": addr, "size": size})
    out["data_directories"] = [d for d in dirs if d["rva"] or d["size"]]

    # 节表
    sections = []
    sec_off = opt + opt_size
    avail = max(0, (len(b) - sec_off) // 40)
    kept = min(nsec, avail, 96)
    for i in range(kept):
        base = sec_off + i * 40
        raw_name = b[base:base + 8]
        name = raw_name.rstrip(b"\x00").decode("latin-1", "replace")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", b, base + 8)
        sch = _u32(b, base + 36) or 0
        flags = _pe_flags(sch, _SEC_CHAR)
        sections.append({
            "name": name,
            "virtual_address": va,
            "virtual_size": vsize,
            "raw_size": rsize,
            "raw_ptr": rptr,
            "characteristics": "|".join(flags),
            "characteristics_raw": "0x%08X" % sch,
            "executable": bool(sch & 0x20000000),
            "writable": bool(sch & 0x80000000),
            "readable": bool(sch & 0x40000000),
        })
    out["sections"] = sections
    if kept < nsec:
        out["sections_truncated"] = "节表声明 %d 个，实际可读 %d 个" % (nsec, kept)

    # 入口所在节
    if entry:
        for s in sections:
            span = max(s["virtual_size"], s["raw_size"])
            if span and s["virtual_address"] <= entry < s["virtual_address"] + span:
                out["entry_section"] = s["name"]
                break

    # 导入表
    imp = next((d for d in dirs if d["name"] == "import" and d["rva"]), None)
    if imp is None:
        out["imports"] = []
        out["import_note"] = "无导入目录（静态链接或已加壳/抹除）"
    else:
        ioff = _rva_to_off(imp["rva"], sections)
        if ioff is None:
            out["imports"] = None
            out["import_error"] = "导入表 RVA 0x%X 不在任何节的原始数据里" % imp["rva"]
        else:
            try:
                out["imports"] = _pe_imports(b, sections, ioff, bits)
                if not out["imports"]:
                    out["import_error"] = "导入描述符立即全零（表为空）"
            except Exception as e:
                out["imports"] = None
                out["import_error"] = "解析异常 %s: %s" % (type(e).__name__, e)

    # .NET / COM Descriptor
    com = next((d for d in dirs if d["name"] == "com_descriptor"), None)
    out["dotnet"] = bool(com and com["rva"])
    if out["dotnet"]:
        coff_meta = _rva_to_off(com["rva"], sections)
        if coff_meta is not None:
            bsjb = b.find(b"BSJB", coff_meta, min(len(b), coff_meta + 0x200))
            if bsjb >= 0:
                out["dotnet_metadata"] = _cstr(b, bsjb + 16, 64)

    # 签名
    sec = next((d for d in dirs if d["name"] == "security"), None)
    if sec and sec["size"]:
        off = sec["rva"]                    # 该目录的 RVA 就是文件偏移
        cert = {"file_offset": off, "size": sec["size"],
                "in_file": off + sec["size"] <= len(b)}
        if off + 8 <= len(b):
            clen, rev, ctype = struct.unpack_from("<IHH", b, off)
            cert.update(cert_length=clen, revision="0x%04X" % rev,
                        cert_type={1: "X509", 2: "PKCS_SIGNED_DATA",
                                   3: "RESERVED_1", 4: "TS_STACK_SIGNED"}.get(ctype, ctype))
            # PKCS#7 SignedData 是 DER，以 30 82 <len_hi> <len_lo> 开头。
            # 注意要取 2 字节切片去比 2 字节常量：取 4 字节永远不等于 2 字节。
            cert["pkcs7"] = b[off + 8:off + 10] == b"\x30\x82"
        out["signature"] = cert
    else:
        out["signature"] = None

    # Rich 头
    rich = b.find(b"Rich", 0x40, min(len(b), e_lfanew))
    if rich > 0 and rich + 8 <= len(b):
        out["rich_header"] = {"offset": rich,
                              "xor_key": "0x%08X" % _u32(b, rich + 4)}

    # overlay
    if sections:
        end = max((s["raw_ptr"] + s["raw_size"]) for s in sections)
        out["overlay_size"] = max(0, len(b) - end)

    # 提示项
    warn = []
    if out["section_alignment"] and out["section_alignment"] < 0x1000 \
            and out["section_alignment"] != out["file_alignment"]:
        warn.append("SectionAlignment < 0x1000，常见于加壳/畸形样本")
    if out["subsystem"] == "NATIVE":
        warn.append("NATIVE 子系统，可能是驱动")
    if any(s["writable"] and s["executable"] for s in sections):
        warn.append("存在同时可写可执行的节")
    if not out.get("signature"):
        warn.append("无证书表（未签名）")
    out["warnings"] = warn
    return out

# ============================================================
#  F. ELF 视图
# ============================================================

_SH_TYPE = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
            5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
            10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
            16: "PREINIT_ARRAY", 17: "GROUP", 18: "SYMTAB_SHNDX"}


def _elf_flags_str(flags):
    return ("R" if flags & 4 else "-") + ("W" if flags & 2 else "-") + \
           ("X" if flags & 1 else "-")


def elf_info(data):
    """ELF32/ELF64，两种字节序。失败返回 {"format":"elf","error":...}。"""
    b = bytes(data or b"")
    out = {"format": "elf"}

    if len(b) < 16:
        return {"format": "elf", "error": "只有 %d 字节，e_ident 不完整" % len(b)}
    if b[:4] != b"\x7fELF":
        return {"format": "elf", "error": "缺少 \\x7fELF 魔数（得到 %r）" % b[:4]}

    cls = b[4]
    data_enc = b[5]
    if cls not in (1, 2):
        return {"format": "elf", "error": "EI_CLASS=%d 非法（应为 1/2）" % cls}
    if data_enc not in (1, 2):
        return {"format": "elf", "error": "EI_DATA=%d 非法（应为 1/2）" % data_enc}
    endian = "<" if data_enc == 1 else ">"
    bits = 32 if cls == 1 else 64
    need = 52 if bits == 32 else 64
    if len(b) < need:
        return {"format": "elf",
                "error": "ELF%d 头需 %d 字节，只有 %d" % (bits, need, len(b))}

    out.update(bits=bits, endian="little" if endian == "<" else "big",
               osabi=_ELF_OSABI.get(b[7], "0x%02X" % b[7]),
               abi_version=b[8])

    if bits == 32:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, e_flags,
         e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from(endian + "HHIIIIIHHHHHH", b, 16)
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, e_flags,
         e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from(endian + "HHIQQQIHHHHHH", b, 16)

    out.update(type=_ELF_TYPE.get(e_type, "0x%X" % e_type), type_raw=e_type,
               machine=_ELF_MACHINE.get(e_machine, "0x%X" % e_machine),
               machine_raw=e_machine,
               entry=e_entry, entry_hex=_hexs(e_entry, 8),
               phoff=e_phoff, phentsize=e_phentsize, phnum=e_phnum,
               shoff=e_shoff, shentsize=e_shentsize, shnum=e_shnum,
               shstrndx=e_shstrndx, flags=e_flags)

    # ---- program headers ----
    phs = []
    step = e_phentsize or (32 if bits == 32 else 56)
    if e_phnum and e_phoff:
        avail = max(0, (len(b) - e_phoff) // step) if step else 0
        kept = min(e_phnum, avail, 256)
        for i in range(kept):
            base = e_phoff + i * step
            try:
                if bits == 32:
                    p_type, p_off, p_va, _pa, p_fsz, p_msz, p_fl, p_al = \
                        struct.unpack_from(endian + "IIIIIIII", b, base)
                else:
                    p_type, p_fl, p_off, p_va, _pa, p_fsz, p_msz, p_al = \
                        struct.unpack_from(endian + "IIQQQQQQ", b, base)
            except struct.error:
                out["phdr_error"] = "program header #%d 被截断" % i
                break
            phs.append({"index": i,
                        "type": _ELF_PHDR_TYPE.get(p_type, "0x%X" % p_type),
                        "type_raw": p_type,
                        "offset": p_off, "vaddr": p_va,
                        "vaddr_hex": _hexs(p_va, 8),
                        "filesz": p_fsz, "memsz": p_msz,
                        "flags": _elf_flags_str(p_fl), "flags_raw": p_fl,
                        "align": p_al})
            if p_type == 3 and p_fsz and p_off + p_fsz <= len(b):     # PT_INTERP
                out["interpreter"] = b[p_off:p_off + p_fsz].rstrip(b"\x00").decode(
                    "utf-8", "replace")
        if kept < e_phnum:
            out["phdr_truncated"] = "声明 %d 个，可读 %d 个" % (e_phnum, kept)
    out["program_headers"] = phs

    # ---- section headers ----
    secs = []
    sstep = e_shentsize or (40 if bits == 32 else 64)
    shnum = e_shnum
    if shnum == 0 and e_shoff and e_shoff + sstep <= len(b):
        # 扩展节数：section[0].sh_size
        try:
            if bits == 32:
                shnum = struct.unpack_from(endian + "I", b, e_shoff + 20)[0]
            else:
                shnum = struct.unpack_from(endian + "Q", b, e_shoff + 32)[0]
            out["shnum_extended"] = shnum
        except struct.error:
            shnum = 0
    if shnum and e_shoff:
        avail = max(0, (len(b) - e_shoff) // sstep) if sstep else 0
        kept = min(shnum, avail, 512)
        raw = []
        for i in range(kept):
            base = e_shoff + i * sstep
            try:
                if bits == 32:
                    (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                     sh_link, sh_info, sh_addralign, sh_entsize) = \
                        struct.unpack_from(endian + "IIIIIIIIII", b, base)
                else:
                    (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                     sh_link, sh_info, sh_addralign, sh_entsize) = \
                        struct.unpack_from(endian + "IIQQQQIIQQ", b, base)
            except struct.error:
                out["shdr_error"] = "section header #%d 被截断" % i
                break
            raw.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                        sh_size, sh_entsize))
        # .shstrtab
        strtab = None
        if 0 <= e_shstrndx < len(raw):
            st = raw[e_shstrndx]
            if st[4] + st[5] <= len(b):
                strtab = b[st[4]:st[4] + st[5]]
            else:
                out["shstrtab_error"] = ".shstrtab 越界（偏移 0x%X 长度 0x%X）" % (st[4], st[5])
        elif raw:
            out["shstrtab_error"] = "e_shstrndx=%d 超出节数 %d" % (e_shstrndx, len(raw))

        for i, (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                sh_entsize) in enumerate(raw):
            name = None
            if strtab is not None and sh_name < len(strtab):
                end = strtab.find(b"\x00", sh_name)
                name = strtab[sh_name:end if end >= 0 else len(strtab)].decode(
                    "utf-8", "replace")
                if not name:
                    name = None              # NULL 节（index 0）无名字
            secs.append({"index": i, "name": name,
                         "type": _SH_TYPE.get(sh_type, "0x%X" % sh_type),
                         "addr": _hexs(sh_addr, 8),
                         "offset": sh_offset, "size": sh_size,
                         "flags": _elf_flags_str(sh_flags)})
        if kept < shnum:
            out["shdr_truncated"] = "声明 %d 个，可读 %d 个" % (shnum, kept)
    out["sections"] = secs
    out["section_names_available"] = any(s["name"] for s in secs)
    return out

# ============================================================
#  G. Mach-O 视图
# ============================================================

_LC = {
    0x00000001: "LC_SEGMENT", 0x00000002: "LC_SYMTAB", 0x00000003: "LC_SYMSEG",
    0x00000004: "LC_THREAD", 0x00000005: "LC_UNIXTHREAD",
    0x00000006: "LC_LOADFVMLIB", 0x00000007: "LC_IDFVMLIB",
    0x00000008: "LC_IDENT", 0x00000009: "LC_FVMFILE",
    0x0000000A: "LC_PREPAGE", 0x0000000B: "LC_DYSYMTAB",
    0x0000000C: "LC_LOAD_DYLIB", 0x0000000D: "LC_ID_DYLIB",
    0x0000000E: "LC_LOAD_DYLINKER", 0x0000000F: "LC_ID_DYLINKER",
    0x00000010: "LC_PREBOUND_DYLIB", 0x00000011: "LC_ROUTINES",
    0x00000012: "LC_SUB_FRAMEWORK", 0x00000013: "LC_SUB_UMBRELLA",
    0x00000014: "LC_SUB_CLIENT", 0x00000015: "LC_SUB_LIBRARY",
    0x00000016: "LC_TWOLEVEL_HINTS", 0x00000017: "LC_PREBIND_CKSUM",
    0x80000018: "LC_LOAD_WEAK_DYLIB", 0x00000019: "LC_SEGMENT_64",
    0x0000001A: "LC_ROUTINES_64", 0x0000001B: "LC_UUID",
    0x8000001C: "LC_RPATH", 0x0000001D: "LC_CODE_SIGNATURE",
    0x0000001E: "LC_SEGMENT_SPLIT_INFO",
    0x8000001F: "LC_REEXPORT_DYLIB", 0x00000020: "LC_LAZY_LOAD_DYLIB",
    0x00000021: "LC_ENCRYPTION_INFO", 0x00000022: "LC_DYLD_INFO",
    0x80000022: "LC_DYLD_INFO_ONLY", 0x80000023: "LC_LOAD_UPWARD_DYLIB",
    0x00000024: "LC_VERSION_MIN_MACOSX", 0x00000025: "LC_VERSION_MIN_IPHONEOS",
    0x00000026: "LC_FUNCTION_STARTS", 0x00000027: "LC_DYLD_ENVIRONMENT",
    0x80000028: "LC_MAIN", 0x00000029: "LC_DATA_IN_CODE",
    0x0000002A: "LC_SOURCE_VERSION", 0x0000002B: "LC_DYLIB_CODE_SIGN_DRS",
    0x0000002C: "LC_ENCRYPTION_INFO_64",
    0x0000002D: "LC_LINKER_OPTION", 0x0000002E: "LC_LINKER_OPTIMIZATION_HINT",
    0x0000002F: "LC_VERSION_MIN_TVOS", 0x00000030: "LC_VERSION_MIN_WATCHOS",
    0x00000032: "LC_BUILD_VERSION",
}

_DYLIB_CMDS = {"LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB",
               "LC_ID_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB"}


def _macho_header(b, endian, bits):
    """返回 (fields_dict, header_size)。"""
    if bits == 32:
        if len(b) < 28:
            return None, 28
        (cputype, cpusubtype, filetype, ncmds, sizeofcmds,
         flags) = struct.unpack_from(endian + "IIIIII", b, 4)
        return dict(cputype=cputype, cpusubtype=cpusubtype, filetype=filetype,
                    ncmds=ncmds, sizeofcmds=sizeofcmds, flags=flags), 28
    if len(b) < 32:
        return None, 32
    (cputype, cpusubtype, filetype, ncmds, sizeofcmds,
     flags, reserved) = struct.unpack_from(endian + "IIIIIII", b, 4)
    return dict(cputype=cputype, cpusubtype=cpusubtype, filetype=filetype,
                ncmds=ncmds, sizeofcmds=sizeofcmds, flags=flags,
                reserved=reserved), 32


def _fat_info(b, endian):
    out = {"format": "macho", "fat": True}
    if len(b) < 8:
        out["error"] = "fat 头不足 8 字节"
        return out
    nfat = _u32(b, 4, endian)
    out["arch_count"] = nfat
    if not nfat or nfat > 64:
        out["error"] = "nfat_arch=%s 不合理（0xCAFEBABE 也可能是 Java class）" % nfat
        return out
    if 8 + nfat * 20 > len(b):
        out["error"] = "fat 架构表被截断：需 %d 字节" % (8 + nfat * 20)
        return out
    arches = []
    for i in range(nfat):
        base = 8 + i * 20
        cput, csub, off, size, align = struct.unpack_from(endian + "IIIII", b, base)
        arches.append({"index": i,
                       "cputype": _MACHO_CPU.get(cput, "0x%X" % cput),
                       "cputype_raw": cput,
                       "cpusubtype": "0x%X" % csub,
                       "offset": off, "size": size,
                       "in_file": off + size <= len(b),
                       "align": "2^%d" % align})
    out["architectures"] = arches
    return out


def macho_info(data):
    """Mach-O（含 fat）结构视图。失败返回 {"format":"macho","error":...}。"""
    b = bytes(data or b"")
    mag = _MACHO_MAGICS.get(b[:4])
    if not mag:
        return {"format": "macho", "error": "魔数 %r 不是 Mach-O" % b[:4]}
    kind, bits, endian = mag
    if kind == "fatmacho":
        if not _looks_fat_macho(b):
            return {"format": "macho",
                    "error": "0xCAFEBABE 但架构表不合理（可能是 Java class 文件）"}
        return _fat_info(b, endian)

    out = {"format": "macho", "fat": False,
           "bits": bits,
           "endian": "little" if endian == "<" else "big"}
    if len(b) < (28 if bits == 32 else 32):
        out["error"] = "头不完整：需 %d 字节，只有 %d" % (
            28 if bits == 32 else 32, len(b))
        return out

    hdr, hsize = _macho_header(b, endian, bits)
    if hdr is None:
        out["error"] = "头字段读取失败"
        return out

    out.update(cputype=_MACHO_CPU.get(hdr["cputype"], "0x%X" % hdr["cputype"]),
               cputype_raw=hdr["cputype"],
               cpusubtype="0x%X" % hdr["cpusubtype"],
               filetype=_MACHO_FILETYPE.get(hdr["filetype"], "0x%X" % hdr["filetype"]),
               filetype_raw=hdr["filetype"],
               ncmds=hdr["ncmds"], sizeofcmds=hdr["sizeofcmds"],
               flags="0x%08X" % hdr["flags"])

    cmds = []
    segments = []
    dylibs = []
    entry = None
    entry_src = None
    uuid = None
    pos = hsize
    end_cmds = hsize + hdr["sizeofcmds"]
    if end_cmds > len(b):
        out["cmds_truncated"] = "sizeofcmds=0x%X 超出文件（截断）" % hdr["sizeofcmds"]
        end_cmds = len(b)

    for i in range(min(hdr["ncmds"], 4096)):
        if pos + 8 > end_cmds:
            out.setdefault("cmds_truncated",
                           "第 %d 个 load command 越界" % i)
            break
        cmd, csize = struct.unpack_from(endian + "II", b, pos)
        if csize < 8 or pos + csize > len(b):
            out.setdefault("cmds_truncated",
                           "第 %d 个 load command size=0x%X 非法" % (i, csize))
            break
        name = _LC.get(cmd, "0x%08X" % cmd)
        item = {"index": i, "cmd": name, "cmd_raw": "0x%08X" % cmd,
                "size": csize, "offset": pos}

        if name == "LC_SEGMENT":
            if csize >= 56:
                segname = b[pos + 8:pos + 24].rstrip(b"\x00").decode("latin-1", "replace")
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = \
                    struct.unpack_from(endian + "IIIIIIII", b, pos + 24)
                item.update(segname=segname, vmaddr=_hexs(vmaddr, 8),
                            vmaddr_raw=vmaddr, vmsize=vmsize,
                            fileoff=fileoff, filesize=filesize,
                            maxprot="0x%X" % maxprot, initprot="0x%X" % initprot,
                            nsects=nsects)
                segments.append({"name": segname, "vmaddr": _hexs(vmaddr, 8),
                                 "vmaddr_raw": vmaddr, "vmsize": vmsize,
                                 "fileoff": fileoff, "filesize": filesize})
        elif name == "LC_SEGMENT_64":
            if csize >= 72:
                segname = b[pos + 8:pos + 24].rstrip(b"\x00").decode("latin-1", "replace")
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = \
                    struct.unpack_from(endian + "QQQQIIII", b, pos + 24)
                item.update(segname=segname, vmaddr=_hexs(vmaddr, 16),
                            vmaddr_raw=vmaddr, vmsize=vmsize,
                            fileoff=fileoff, filesize=filesize,
                            maxprot="0x%X" % maxprot, initprot="0x%X" % initprot,
                            nsects=nsects)
                segments.append({"name": segname, "vmaddr": _hexs(vmaddr, 16),
                                 "vmaddr_raw": vmaddr, "vmsize": vmsize,
                                 "fileoff": fileoff, "filesize": filesize})
                # 段内节名
                sects = []
                sent = 80 if bits == 64 else 68
                sbase = pos + (72 if bits == 64 else 56)
                for k in range(min(nsects, 64)):
                    so = sbase + k * sent
                    if so + 68 > pos + csize:
                        break
                    sname = b[so:so + 16].rstrip(b"\x00").decode("latin-1", "replace")
                    saddr = _u64(b, so + 32) if bits == 64 else _u32(b, so + 32)
                    ssize = _u64(b, so + 40) if bits == 64 else _u32(b, so + 36)
                    sects.append("%s (0x%X, %s)" % (
                        sname, saddr or 0, ssize))
                if sects:
                    item["sections"] = sects
        elif name in _DYLIB_CMDS:
            if csize >= 24:
                nameoff = _u32(b, pos + 8)
                if nameoff and nameoff < csize:
                    lib = _cstr(b, pos + nameoff, 1024)
                    item.update(lib=lib, ts=_stamp(_u32(b, pos + 12)))
                    if name != "LC_ID_DYLIB":
                        dylibs.append({"cmd": name, "path": lib,
                                       "current_version": "0x%X" % (_u32(b, pos + 16) or 0),
                                       "compat_version": "0x%X" % (_u32(b, pos + 20) or 0)})
        elif name == "LC_MAIN":
            if csize >= 24:
                entryoff, stacksize = struct.unpack_from(endian + "QQ", b, pos + 8)
                entry = entryoff
                entry_src = "LC_MAIN (文件偏移)"
                item.update(entryoff=entryoff, stacksize=stacksize)
        elif name in ("LC_UNIXTHREAD", "LC_THREAD"):
            item["note"] = "线程状态，入口按寄存器推断"
            if bits == 64 and hdr["cputype"] == 0x01000007 and csize >= 16 + 17 * 8:
                rip = _u64(b, pos + 16 + 16 * 8)
                if rip:
                    entry = rip
                    entry_src = "LC_UNIXTHREAD (RIP)"
                    item["rip"] = _hexs(rip, 16)
            elif bits == 32 and hdr["cputype"] == 7 and csize >= 16 + 11 * 4:
                eip = _u32(b, pos + 16 + 10 * 4)
                if eip:
                    entry = eip
                    entry_src = "LC_UNIXTHREAD (EIP)"
                    item["eip"] = _hexs(eip, 8)
        elif name == "LC_UUID":
            if csize >= 24:
                raw = b[pos + 8:pos + 24]
                uuid = "-".join([raw[0:4].hex(), raw[4:6].hex(), raw[6:8].hex(),
                                 raw[8:10].hex(), raw[10:16].hex()])
                item["uuid"] = uuid
        elif name == "LC_CODE_SIGNATURE":
            if csize >= 16:
                item.update(dataoff=_u32(b, pos + 8), datasize=_u32(b, pos + 12))
        elif name == "LC_BUILD_VERSION":
            if csize >= 16:
                plat, minos, sdk = struct.unpack_from(endian + "III", b, pos + 8)
                item.update(platform=plat, minos=_hexs(minos, 8), sdk=_hexs(sdk, 8))

        cmds.append(item)
        pos += csize

    out["load_commands"] = cmds
    out["segments"] = segments
    out["dylibs"] = dylibs
    out["entry"] = _hexs(entry, 16) if entry is not None else None
    out["entry_raw"] = entry
    out["entry_source"] = entry_src
    out["uuid"] = uuid
    out["encrypted"] = any(c["cmd"] in ("LC_ENCRYPTION_INFO", "LC_ENCRYPTION_INFO_64")
                           for c in cmds)
    if not segments:
        out["note"] = "无 LC_SEGMENT/LC_SEGMENT_64（文件被截断或畸形）"
    return out

# ============================================================
#  渲染
# ============================================================

def _dump(obj, indent=0):
    """通用 dict/list 展开，跳过 *_raw 与 None。"""
    pad = "  " * indent
    lines = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.endswith("_raw"):
                continue
            if isinstance(v, dict):
                if not v:
                    continue
                lines.append("%s%s:" % (pad, k))
                lines.extend(_dump(v, indent + 1))
            elif isinstance(v, list):
                if not v:
                    lines.append("%s%s: []" % (pad, k))
                    continue
                lines.append("%s%s:" % (pad, k))
                lines.extend(_dump(v, indent + 1))
            elif v is None:
                continue
            else:
                lines.append("%s%s: %s" % (pad, k, v))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                lines.append("%s[%d]" % (pad, i))
                lines.extend(_dump(v, indent + 1))
            else:
                lines.append("%s- %s" % (pad, v))
    else:
        lines.append(pad + str(obj))
    return lines


def _render_pe(d):
    if "machine" not in d:
        return "PE 无法解析: %s" % d.get("error", "未知原因")
    L = []
    L.append("PE  %s  machine=%s(0x%04X)  sections=%d  timestamp=%s" % (
        d.get("pe_type"), d.get("machine"), d.get("machine_raw", 0),
        d.get("section_count", 0), d.get("timestamp")))
    L.append("image_base=%s  entry=%s%s  align(section=%s, file=%s)" % (
        d.get("image_base_hex"), d.get("entry_point_hex"),
        (" [" + d["entry_section"] + "]") if d.get("entry_section") else "",
        _hexs(d.get("section_alignment") or 0, 4),
        _hexs(d.get("file_alignment") or 0, 4)))
    L.append("subsystem=%s  dll=%s  characteristics=%s" % (
        d.get("subsystem"), d.get("is_dll"),
        "|".join(d.get("characteristics") or []) or "-"))
    if d.get("dll_characteristics"):
        L.append("dll_characteristics=%s" % "|".join(d["dll_characteristics"]))
    L.append("size_of_image=%s  size_of_headers=%s  rva_and_sizes=%s" % (
        _hexs(d.get("size_of_image") or 0, 6),
        _hexs(d.get("size_of_headers") or 0, 6), d.get("rva_and_sizes")))
    dirs = d.get("data_directories") or []
    if dirs:
        L.append("data_directories: " + "  ".join(
            "%s=%s/0x%X" % (x["name"], _hexs(x["rva"], 6), x["size"]) for x in dirs))

    secs = d.get("sections") or []
    if secs:
        L.append("节表:")
        L.append("  #  %-8s %-10s %-8s %-8s %-8s %s" % (
            "name", "VA", "VSZ", "RAW", "PTR", "flags"))
        for i, s in enumerate(secs):
            L.append("  %-2d %-8s 0x%08X 0x%-6X 0x%-6X 0x%-6X %s" % (
                i, s["name"] or "-", s["virtual_address"], s["virtual_size"],
                s["raw_size"], s["raw_ptr"], s["characteristics"] or "-"))
    if d.get("sections_truncated"):
        L.append("  ! " + d["sections_truncated"])

    if d.get("imports") is None:
        L.append("导入表: 解析失败 —— %s" % d.get("import_error", "原因未知"))
    elif not d.get("imports"):
        L.append("导入表: 空（%s）" % d.get("import_note", "无描述符"))
    else:
        L.append("导入表:")
        for it in d["imports"]:
            L.append("  %s" % (it.get("dll") or "<无名字>"))
            if it.get("functions") is None:
                L.append("    ! %s" % it.get("error", "函数列表不可读"))
                continue
            for f in it["functions"][:40]:
                if "ordinal" in f:
                    L.append("    #%d (ordinal)" % f["ordinal"])
                else:
                    L.append("    %s (hint %s)" % (f.get("name"), f.get("hint")))
            if len(it["functions"]) > 40:
                L.append("    … 共 %d 项" % len(it["functions"]))
    if d.get("import_error") and d.get("imports"):
        L.append("  ! " + d["import_error"])

    L.append("签名: %s" % (
        "证书表 @0x%X, %d 字节%s" % (
            d["signature"]["file_offset"], d["signature"]["size"],
            "" if d["signature"].get("in_file", True) else "（超出文件，被截断）")
        if d.get("signature") else "无"))
    L.append(".NET/COM Descriptor: %s" % (
        (".NET" + ("  metadata=%s" % d["dotnet_metadata"]
                   if d.get("dotnet_metadata") else ""))
        if d.get("dotnet") else "否"))
    if d.get("rich_header"):
        L.append("Rich 头: @0x%X key=%s" % (
            d["rich_header"]["offset"], d["rich_header"]["xor_key"]))
    if d.get("overlay_size"):
        L.append("overlay: %d 字节" % d["overlay_size"])
    for w in d.get("warnings") or []:
        L.append("  ! " + w)
    if d.get("error"):
        L.append("  ! " + d["error"])
    return "\n".join(L)


def _render_elf(d):
    if "type" not in d:
        return "ELF 无法解析: %s" % d.get("error", "未知原因")
    L = []
    L.append("ELF%d %s-endian  type=%s  machine=%s(0x%X)  entry=%s" % (
        d.get("bits"), d.get("endian"), d.get("type"), d.get("machine"),
        d.get("machine_raw", 0), d.get("entry_hex")))
    L.append("osabi=%s  abi_ver=%s  flags=0x%X  phnum=%s  shnum=%s  shstrndx=%s" % (
        d.get("osabi"), d.get("abi_version"), d.get("flags") or 0,
        d.get("phnum"), d.get("shnum"), d.get("shstrndx")))
    if d.get("interpreter"):
        L.append("interpreter: %s" % d["interpreter"])

    phs = d.get("program_headers") or []
    if phs:
        L.append("程序头:")
        L.append("  #  %-14s %-10s %-12s %-10s %-10s %s" % (
            "type", "offset", "vaddr", "filesz", "memsz", "flags"))
        for p in phs:
            L.append("  %-2d %-14s 0x%-8X %-12s 0x%-8X 0x%-8X %s" % (
                p["index"], p["type"], p["offset"], p["vaddr_hex"],
                p["filesz"], p["memsz"], p["flags"]))
    else:
        L.append("程序头: 无（phnum=%s）" % d.get("phnum"))
    if d.get("phdr_error"):
        L.append("  ! " + d["phdr_error"])

    secs = d.get("sections") or []
    if secs:
        L.append("节表:")
        L.append("  #  %-18s %-12s %-12s %-9s %-9s %s" % (
            "name", "type", "addr", "offset", "size", "flags"))
        for s in secs:
            L.append("  %-2d %-18s %-12s %-12s 0x%-7X 0x%-7X %s" % (
                s["index"], s["name"] if s["name"] is not None else "<无名>",
                s["type"], s["addr"], s["offset"], s["size"], s["flags"]))
    else:
        L.append("节表: 无（shnum=%s, shoff=0x%X）" % (d.get("shnum"), d.get("shoff") or 0))
    if d.get("shstrtab_error"):
        L.append("  ! 节名不可读: " + d["shstrtab_error"])
    for k in ("shdr_error", "shdr_truncated", "phdr_truncated"):
        if d.get(k):
            L.append("  ! %s" % d[k])
    return "\n".join(L)


def _render_macho(d):
    if d.get("error") and "cputype" not in d:
        return "Mach-O 无法解析: %s" % d["error"]
    L = []
    if d.get("fat"):
        L.append("fat Mach-O  %d 个架构" % (d.get("arch_count") or 0))
        for a in d.get("architectures") or []:
            L.append("  [%d] %-10s subtype=%s offset=0x%-8X size=0x%-8X align=%s%s" % (
                a["index"], a["cputype"], a["cpusubtype"], a["offset"],
                a["size"], a["align"], "" if a["in_file"] else " (超出文件)"))
        return "\n".join(L)

    L.append("Mach-O %d-bit %s-endian  cputype=%s(0x%X)  cpusubtype=%s  filetype=%s" % (
        d.get("bits"), d.get("endian"), d.get("cputype"), d.get("cputype_raw", 0),
        d.get("cpusubtype"), d.get("filetype")))
    L.append("ncmds=%s  sizeofcmds=%s  flags=%s  uuid=%s" % (
        d.get("ncmds"), d.get("sizeofcmds"), d.get("flags"), d.get("uuid")))
    L.append("entry=%s%s" % (d.get("entry") or "未知",
                             ("  (%s)" % d["entry_source"]) if d.get("entry_source") else ""))

    segs = d.get("segments") or []
    if segs:
        L.append("段:")
        L.append("  %-18s %-20s %-12s %-9s %s" % (
            "name", "vmaddr", "vmsize", "fileoff", "filesize"))
        for s in segs:
            L.append("  %-18s %-20s 0x%-10X 0x%-7X 0x%X" % (
                s["name"], s["vmaddr"], s["vmsize"], s["fileoff"], s["filesize"]))
    else:
        L.append("段: 无")

    if d.get("dylibs"):
        L.append("依赖库:")
        for x in d["dylibs"]:
            L.append("  %s" % x["path"])
    else:
        L.append("依赖库: 无（可能是静态或已裁剪）")

    cmds = d.get("load_commands") or []
    if cmds:
        L.append("load commands: " + "  ".join(
            "%s(%d)" % (c["cmd"], c["size"]) for c in cmds[:24]))
        if len(cmds) > 24:
            L.append("  … 共 %d 条" % len(cmds))
    if d.get("cmds_truncated"):
        L.append("  ! " + d["cmds_truncated"])
    return "\n".join(L)


def _render_media(d):
    if d.get("error") and not d.get("width"):
        head = "%s 解析受限: %s" % ((d.get("kind") or "?").upper(), d["error"])
    else:
        head = None

    L = []
    k = d.get("kind")
    if k == "png":
        L.append("PNG %sx%s 位深=%s 色彩=%s(%s) 隔行=%s" % (
            d.get("width"), d.get("height"), d.get("bit_depth"),
            d.get("color_type"), d.get("color_name"), d.get("interlace")))
        L.append("chunks: " + "  ".join(
            "%s(%d)" % (n, ln) for n, ln in (d.get("chunks") or [])[:16]))
    elif k == "jpeg":
        L.append("JPEG %sx%s 精度=%s 分量=%s (%s)" % (
            d.get("width"), d.get("height"), d.get("precision"),
            d.get("components"), d.get("sof")))
        L.append("段: " + "  ".join(
            "%s@0x%X/%s" % (n, off, ln) for n, off, ln in (d.get("segments") or [])[:20]))
    elif k == "gif":
        L.append("GIF %sx%s 帧数=%s 全局调色板=%s 版本=%s" % (
            d.get("width"), d.get("height"), d.get("frames"),
            d.get("global_palette"), d.get("version")))
    elif k == "bmp":
        L.append("BMP %sx%s 位深=%s 压缩=%s DIB=%s" % (
            d.get("width"), d.get("height"), d.get("bit_count"),
            d.get("compression"), d.get("dib_size")))
    elif k == "pdf":
        L.append("PDF %s  页数=%s  加密=%s  linearized=%s  objstm=%s" % (
            d.get("version"), d.get("pages"), d.get("encrypted"),
            d.get("linearized"), d.get("object_stream")))
        if d.get("page_count_candidates"):
            L.append("/Count 候选: %s" % d["page_count_candidates"])
    elif k in ("wav", "avi", "riff"):
        L.append("RIFF/%s  %s Hz  %s 声道  %s bit  时长=%s s" % (
            k.upper(), d.get("sample_rate"), d.get("channels"),
            d.get("bits_per_sample"), d.get("duration_sec")))
        extra = {kk: vv for kk, vv in d.items()
                 if kk not in ("kind", "family", "riff_size") and vv is not None}
        L.extend(_dump(extra, 0))
    elif k == "mp4":
        L.append("MP4 ftyp=%s  brands=%s  moov=%s mdat=%s" % (
            d.get("major_brand"), ",".join(d.get("compatible_brands") or []),
            d.get("has_moov"), d.get("has_mdat")))
    elif k in ("mkv", "webm", "ebml"):
        L.append("EBML/%s  doctype=%s  version=%s" % (
            k, d.get("doctype"), d.get("doctype_version")))
    elif k == "office":
        if d.get("document"):
            L.append("OOXML %s  zip 成员=%s  [Content_Types].xml=%s  core.xml=%s" % (
                d.get("document"), d.get("zip_members"), d.get("content_types"),
                d.get("core_props")))
        else:
            L.append("ZIP 归档（非 OOXML/APK）  zip 成员=%s" % d.get("zip_members"))
        if d.get("title") or d.get("author"):
            L.append("标题=%r 作者=%r" % (d.get("title"), d.get("author")))
    else:
        L.extend(_dump(d, 0))
    if head:
        L.insert(0, head)
    if d.get("error") and len(L) > 0 and not L[0].startswith("%s 解析受限" % (k or "").upper()):
        L.append("  ! %s" % d["error"])
    if d.get("note"):
        L.append("  · %s" % d["note"])
    return "\n".join([x for x in L if x is not None])


# ============================================================
#  统一入口
# ============================================================

IMG_KINDS = ("png", "jpeg", "gif", "bmp", "tiff", "webp")
AV_KINDS = ("wav", "avi", "riff", "mp4", "mkv", "webm", "ebml")
TEXT_KINDS = ("text", "json", "xml", "html")


def preview(data, name=None, max_lines=200):
    """自动 sniff 后选视图。

    返回 {"kind","mime","detail","text","info"}；text 一定非空。
    """
    b = bytes(data or b"")
    meta = sniff(b, name)
    kind = meta["kind"]
    info = None
    body = ""

    if kind == "pe":
        info = pe_info(b)
        body = _render_pe(info)
    elif kind == "elf":
        info = elf_info(b)
        body = _render_elf(info)
    elif kind in ("macho", "fatmacho"):
        info = macho_info(b)
        body = _render_macho(info)
    elif kind in IMG_KINDS or kind == "pdf" or kind in AV_KINDS or kind == "office":
        info = media_info(b)
        body = _render_media(info)
        body += "\n\n" + hex_preview(b, max_rows=8)
    elif kind in TEXT_KINDS:
        body = text_preview(b, max_lines=max_lines)
    elif kind == "zip":
        info = media_info(b)
        body = _render_media(info) + "\n\n" + hex_preview(b, max_rows=8)
    elif kind == "unknown":
        body = "无结构视图，仅十六进制：\n" + hex_preview(b, max_rows=16)
    else:
        body = hex_preview(b, max_rows=16)

    header = "== %s | %s | %s ==" % (kind, meta["mime"], meta["detail"])
    text = header + "\n" + (body or "(无内容)")
    return {"kind": kind, "mime": meta["mime"], "detail": meta["detail"],
            "text": text, "info": info, "size": len(b)}

# ============================================================
#  自检 —— 全部用自己拼的最小二进制
# ============================================================

if __name__ == "__main__":
    import sys

    _n = [0]

    def ok(cond, label):
        _n[0] += 1
        if not cond:
            raise AssertionError("FAIL: " + label)
        return True

    # ---------- 合成样本 ----------
    def mk_png(w, h, depth=8, ctype=2):
        def chunk(t, d):
            return (struct.pack(">I", len(d)) + t + d +
                    struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF))
        ihdr = struct.pack(">IIBBBBB", w, h, depth, ctype, 0, 0, 0)
        return (PNG_SIG + chunk(b"IHDR", ihdr)
                + chunk(b"IDAT", zlib.compress(b"\x00" * 16)) + chunk(b"IEND", b""))

    def mk_jpeg(w, h):
        sof = struct.pack(">BHHB", 8, h, w, 3) + b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"
        return (b"\xff\xd8" + b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof
                + b"\xff\xd9")

    def mk_gif(w, h):
        return (b"GIF89a" + struct.pack("<HH", w, h) + b"\x00\x00\x00"
                + b"\x2c" + struct.pack("<HHHH", 0, 0, w, h) + b"\x00"
                + b"\x02" + b"\x02\x44\x01" + b"\x00" + b"\x3b")

    def mk_bmp(w, h, bits=24):
        dib = struct.pack("<IiiHHIIiiII", 40, w, h, 1, bits, 0, 0, 0, 0, 0, 0)
        return b"BM" + struct.pack("<I", 14 + len(dib)) + b"\x00\x00\x00\x00" + \
            struct.pack("<I", 14 + len(dib)) + dib

    def mk_pdf(ver=b"1.7", pages=5, enc=True):
        body = b"%PDF-" + ver + b"\n1 0 obj\n<</Type /Pages /Count %d>>\nendobj\n" % pages
        if enc:
            body += b"trailer\n<</Encrypt 9 0 R>>\n"
        return body + b"%%EOF\n"

    def mk_pe(bits=32, dotnet=False, cert=False):
        e_lfanew = 0x80
        opt_size = 0xE0 if bits == 32 else 0xF0
        buf = bytearray(0x200 + 0x200)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, e_lfanew)
        buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
        coff = e_lfanew + 4
        struct.pack_into("<HHIIIHH", buf, coff,
                         0x14C if bits == 32 else 0x8664, 1, 0x5F5E1000, 0, 0,
                         opt_size, 0x2102)
        opt = coff + 20
        struct.pack_into("<H", buf, opt, 0x10B if bits == 32 else 0x20B)
        struct.pack_into("<I", buf, opt + 16, 0x1000)          # entry
        struct.pack_into("<I", buf, opt + 32, 0x1000)          # section align
        struct.pack_into("<I", buf, opt + 36, 0x200)           # file align
        struct.pack_into("<I", buf, opt + 56, 0x2000)          # size of image
        struct.pack_into("<I", buf, opt + 60, 0x200)           # size of headers
        struct.pack_into("<H", buf, opt + 68, 3)               # WINDOWS_CUI
        struct.pack_into("<H", buf, opt + 70, 0x8140)
        if bits == 32:
            struct.pack_into("<I", buf, opt + 28, 0x400000)
            struct.pack_into("<I", buf, opt + 92, 16)
            dir_off = opt + 96
        else:
            struct.pack_into("<Q", buf, opt + 24, 0x140000000)
            struct.pack_into("<I", buf, opt + 108, 16)
            dir_off = opt + 112
        struct.pack_into("<II", buf, dir_off + 8, 0x1000, 0x80)   # import dir

        sec = opt + opt_size
        buf[sec:sec + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", buf, sec + 8, 0x1000, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", buf, sec + 36, 0x60000020)        # CODE|EXEC|READ

        if bits == 32:
            thunk, name_o, h1, h2 = 0x240, 0x260, 0x280, 0x290
            step = 4
        else:
            thunk, name_o, h1, h2 = 0x240, 0x270, 0x290, 0x2A0
            step = 8
        base = 0x1000 - 0x200
        t_rva, n_rva = base + thunk, base + name_o
        h1_rva, h2_rva = base + h1, base + h2
        struct.pack_into("<IIIII", buf, 0x200, t_rva, 0, 0, n_rva, t_rva)
        for i, v in enumerate((h1_rva, h2_rva, 0)):
            struct.pack_into("<Q" if step == 8 else "<I", buf, thunk + i * step, v)
        buf[name_o:name_o + 13] = b"KERNEL32.dll\x00"
        buf[h1:h1 + 2] = b"\x00\x00"
        buf[h1 + 2:h1 + 2 + 12] = b"ExitProcess\x00"
        buf[h2:h2 + 2] = b"\x07\x00"
        buf[h2 + 2:h2 + 2 + 6] = b"Sleep\x00"

        if dotnet:            # COM Descriptor 目录非零 → .NET
            struct.pack_into("<II", buf, dir_off + 14 * 8, 0x1000, 0x48)
        if cert:              # 证书表（目录里的 RVA 就是文件偏移）
            # WIN_CERTIFICATE = dwLength(4) + wRevision(2) + wCertificateType(2)
            #                   + 证书数据；dwLength 必须等于整个结构长度，
            #                   所以数据要补到 8 字节，总长 16 才自洽
            cert_off = len(buf)
            buf += (struct.pack("<IHH", 16, 0x0200, 0x0002)
                    + b"\x30\x82\x00\x00" + b"\x00" * 4)
            struct.pack_into("<II", buf, dir_off + 4 * 8, cert_off, 16)
        return bytes(buf)

    def mk_elf64():
        ehsize, phoff, phnum, phentsize = 64, 64, 2, 56
        shoff, shnum, shentsize = phoff + phnum * phentsize, 3, 64
        strtab_off = shoff + shnum * shentsize
        shstr = b"\x00.text\x00.shstrtab\x00"
        b = bytearray(strtab_off + len(shstr))
        b[0:4] = b"\x7fELF"
        b[4], b[5], b[6], b[7] = 2, 1, 1, 3          # 64-bit, LE, v1, LINUX
        struct.pack_into("<HHIQQQIHHHHHH", b, 16, 2, 0x3E, 1, 0x401000,
                         phoff, shoff, 0, ehsize, phentsize, phnum,
                         shentsize, shnum, 2)
        struct.pack_into("<IIQQQQQQ", b, phoff, 1, 5, 0, 0x400000, 0x400000,
                         0x200, 0x200, 0x1000)                       # PT_LOAD
        struct.pack_into("<IIQQQQQQ", b, phoff + 56, 2, 6, 0x300, 0x400300,
                         0x400300, 0x40, 0x40, 8)                    # PT_DYNAMIC
        struct.pack_into("<IIQQQQIIQQ", b, shoff + 64, 1, 1, 6, 0x401000,
                         0x300, 0x10, 0, 0, 16, 0)                   # .text
        struct.pack_into("<IIQQQQIIQQ", b, shoff + 128, 7, 3, 0, 0,
                         strtab_off, len(shstr), 0, 0, 1, 0)         # .shstrtab
        b[strtab_off:strtab_off + len(shstr)] = shstr
        return bytes(b)

    def mk_macho():
        seg, main = 72, 24
        dylib_path = b"/usr/lib/libSystem.B.dylib\x00"
        dylib = (24 + len(dylib_path) + 7) & ~7
        sizeofcmds = seg + main + dylib
        b = bytearray(32 + sizeofcmds)
        b[0:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<IIIIIII", b, 4, 0x01000007, 3, 2, 3, sizeofcmds, 0, 0)
        pos = 32
        struct.pack_into("<II", b, pos, 0x19, seg)                  # LC_SEGMENT_64
        b[pos + 8:pos + 24] = b"__TEXT".ljust(16, b"\x00")
        struct.pack_into("<QQQQIIII", b, pos + 24, 0x100000000, 0x1000, 0, 0x1000,
                         7, 5, 0, 0)
        pos += seg
        struct.pack_into("<IIQQ", b, pos, 0x80000028, main, 0x1000, 0)   # LC_MAIN
        pos += main
        struct.pack_into("<IIIIII", b, pos, 0xC, dylib, 24, 2, 0x10000, 0x10000)
        b[pos + 24:pos + 24 + len(dylib_path)] = dylib_path
        return bytes(b)

    def mk_wav(sr=8000, ch=1, bits=8, nsamp=800):
        fmt = struct.pack("<HHIIHH", 1, ch, sr, sr * ch * bits // 8,
                          ch * bits // 8, bits)
        pcm = b"\x80" * nsamp
        body = (b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt
                + b"data" + struct.pack("<I", len(pcm)) + pcm)
        return b"RIFF" + struct.pack("<I", len(body)) + body

    def mk_mp4():
        # ftyp = 8(size+type) + 4(major) + 4(minor) + 12(三个兼容品牌) = 28
        ftyp = (struct.pack(">I", 28) + b"ftypisom" + struct.pack(">I", 512)
                + b"isomiso2mp41")
        return ftyp + struct.pack(">I", 8) + b"moov"

    def mk_docx(title, author):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml",
                        '<?xml version="1.0"?><Types>'
                        '<Override PartName="/word/document.xml" '
                        'ContentType="application/xml"/></Types>')
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("docProps/core.xml",
                        '<cp:coreProperties><dc:title>%s</dc:title>'
                        '<dc:creator>%s</dc:creator>'
                        '<cp:lastModifiedBy>%s</cp:lastModifiedBy>'
                        '</cp:coreProperties>' % (title, author, author))
        return buf.getvalue()

    def mk_elf32be():
        ehsize, phoff, phnum, phentsize = 52, 52, 1, 32
        b = bytearray(phoff + phentsize + 16)
        b[0:4] = b"\x7fELF"
        b[4], b[5], b[6], b[7] = 1, 2, 1, 0      # 32-bit, big-endian, SYSV
        struct.pack_into(">HHIIIIIHHHHHH", b, 16, 2, 8, 1, 0x1000,
                         phoff, 0, 0, ehsize, phentsize, phnum, 0, 0, 0)
        struct.pack_into(">IIIIIIII", b, phoff, 1, 0, 0x10000, 0x10000,
                         0x100, 0x100, 5, 0x1000)
        return bytes(b)

    # ---------- 1. sniff ----------
    sniffs = [
        (b"\x89PNG\r\n\x1a\n" + b"\x00" * 25, "png"),
        (b"\xff\xd8\xff\xe0" + b"JFIF\x00", "jpeg"),
        (b"GIF89a" + b"\x00" * 10, "gif"),
        (b"BM" + b"\x00" * 12 + struct.pack("<I", 40) + struct.pack("<ii", 4, 6), "bmp"),
        (b"%PDF-1.4\n", "pdf"),
        (b"PK\x03\x04" + b"\x00" * 20, "zip"),
        (b"\x1f\x8b\x08\x00" + b"\x00" * 8, "gzip"),
        (b"BZh9" + b"\x00" * 8, "bz2"),
        (b"\xfd7zXZ\x00" + b"\x00" * 8, "xz"),
        (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 8, "7z"),
        (b"Rar!\x1a\x07\x01\x00" + b"\x00" * 8, "rar"),
        (b"\x00" * 257 + b"ustar\x0000" + b"\x00" * 200, "tar"),
        (b"SQLite format 3\x00" + b"\x00" * 40, "sqlite"),
        (b"regf" + b"\x00" * 40, "regf"),
        (b"ElfFile\x00" + b"\x00" * 40, "evtx"),
        (b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 0x3E), "elf"),
        (mk_pe(32), "pe"),
        (b"II*\x00" + b"\x00" * 40, "tiff"),
        (b"RIFF" + b"\x00" * 4 + b"WEBPVP8 " + b"\x00" * 8, "webp"),
        (b"RIFF" + struct.pack("<I", 64) + b"WAVEfmt " + b"\x00" * 16, "wav"),
        (b"RIFF" + struct.pack("<I", 64) + b"AVI LIST" + b"\x00" * 16, "avi"),
        (b"\x00\x00\x00\x20ftypisom" + b"\x00" * 8, "mp4"),
        (b"\x1aE\xdf\xa3" + b"\x00" * 8 + b"matroska", "mkv"),
        (b"\x1aE\xdf\xa3" + b"\x00" * 8 + b"webm", "webm"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16, "ole2"),
        (b'{"k": [1, 2]}', "json"),
        (b"<?xml version='1.0'?><r/>", "xml"),
        (b"<!DOCTYPE html><html><body>x</body></html>", "html"),
        ("纯中文文本，含标点。".encode("utf-8"), "text"),
        (b"\xff\xfe" + "UTF-16 中文".encode("utf-16-le"), "text"),
        (bytes(range(1, 32)) + b"\xf0\x9f\x92\xa9", "unknown"),
        (b"", "unknown"),
    ]
    for data, want in sniffs:
        got = sniff(data)
        ok(got["kind"] == want, "sniff 期望 %s 得到 %s" % (want, got["kind"]))
        ok(isinstance(got["mime"], str) and got["mime"], "sniff mime 非空")
        ok(isinstance(got["detail"], str) and got["detail"], "sniff detail 非空")
    ok(len(sniffs) >= 20, "sniff 覆盖 >= 20 种")

    # ---------- 2. text_preview ----------
    t = text_preview("中文测试\x00\x01控制\r\n第二行".encode("utf-8"))
    ok("中文测试" in t, "text_preview 保留中文")
    ok("\\x00" in t and "\\x01" in t, "text_preview 转义控制字符")
    ok("encoding=utf-8" in t, "text_preview 标注编码")
    ok("第二行" in t, "text_preview 多行")

    t16 = text_preview(b"\xff\xfe" + "中文 UTF16".encode("utf-16-le"))
    ok("utf-16le" in t16 and "中文 UTF16" in t16, "text_preview UTF-16LE BOM")

    long_text = "\n".join("line %03d" % i for i in range(300))
    tl = text_preview(long_text.encode("utf-8"), max_lines=10)
    ok("已截断" in tl, "text_preview 超长截断提示")
    ok("共 300 行" in tl, "text_preview 注明总行数")
    body_lines = [x for x in tl.split("\n") if x.startswith("line ")]
    ok(len(body_lines) == 10, "text_preview 只显示 max_lines 行")

    wide = "x" * 200
    tw = text_preview(wide.encode("utf-8"), max_cols=20)
    ok("…" in tw, "text_preview 按列截断")

    # ---------- 3. hex_preview 逐字符 ----------
    data32 = b"ABCDEFGHIJKLMNOP" + bytes(range(16))
    expect = (
        "00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|\n"
        "00000010  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  |................|"
    )
    got = hex_preview(data32)
    ok(got == expect, "hex_preview 输出逐字符一致")
    ok(hex_preview(b"", ) == "[空数据 0 字节]", "hex_preview 空输入")
    hh = hex_preview(b"\x00" * 100, offset=0x100, max_rows=2)
    ok("剩余 68 字节" in hh, "hex_preview 截断注明剩余字节")
    ok(hh.split("\n")[0].startswith("00000100"), "hex_preview offset 生效")

    # ---------- 4. 图片 ----------
    png = mk_png(640, 480, 8, 2)
    mi = media_info(png)
    ok(mi["width"] == 640 and mi["height"] == 480, "PNG 宽高")
    ok(mi["bit_depth"] == 8 and mi["color_type"] == 2, "PNG 位深/色彩类型")
    ok(sniff(png)["kind"] == "png", "sniff PNG")

    jpg = mk_jpeg(640, 480)
    mj = media_info(jpg)
    ok(mj["width"] == 640 and mj["height"] == 480, "JPEG 宽高")
    names = [s[0] for s in mj["segments"]]
    ok(names[0] == "SOI" and "SOF0" in names and names[-1] == "EOI", "JPEG 段列表")

    gif = mk_gif(100, 50)
    mg = media_info(gif)
    ok(mg["width"] == 100 and mg["height"] == 50, "GIF 宽高")
    ok(mg["frames"] == 1, "GIF 帧数")

    bmp = mk_bmp(320, 240, 24)
    mb = media_info(bmp)
    ok(mb["width"] == 320 and mb["height"] == 240, "BMP 宽高")
    ok(mb["bit_count"] == 24, "BMP 位深")

    # ---------- 5. PDF ----------
    pdf = mk_pdf(b"1.7", 5, True)
    mp = media_info(pdf)
    ok(mp["version"] == "1.7", "PDF 版本")
    ok(mp["pages"] == 5, "PDF 页数 /Count")
    ok(mp["encrypted"] is True, "PDF 加密标记")
    ok(media_info(mk_pdf(b"1.3", 2, False))["encrypted"] is False, "PDF 未加密标记")

    # ---------- 5b. 音视频 / OOXML ----------
    wav = media_info(mk_wav())
    ok(wav["kind"] == "wav", "WAV 识别")
    ok(wav["sample_rate"] == 8000 and wav["channels"] == 1
       and wav["bits_per_sample"] == 8, "WAV fmt 字段")
    ok(abs((wav.get("duration_sec") or 0) - 0.1) < 0.01, "WAV 时长")

    mp4 = media_info(mk_mp4())
    ok(mp4["kind"] == "mp4" and mp4["major_brand"] == "isom", "MP4 brand")
    ok("isom" in mp4["compatible_brands"], "MP4 兼容 brand 列表")
    ok(mp4["has_moov"] is True, "MP4 moov 探测")

    docx = mk_docx("季度报告", "张三")
    od = media_info(docx)
    ok(od["kind"] == "office" and od["document"] == "docx", "OOXML 文档类型")
    ok(od["content_types"] is True, "OOXML [Content_Types].xml")
    ok(od["title"] == "季度报告" and od["author"] == "张三", "OOXML 标题/作者")
    ok(od["last_modified_by"] == "张三", "OOXML lastModifiedBy")
    ok(sniff(docx)["kind"] == "zip", "sniff OOXML 归为 zip")

    # ---------- 6. PE ----------
    p32 = pe_info(mk_pe(32))
    ok(p32["machine"] == "i386", "PE32 Machine")
    ok(p32["pe_type"] == "PE32", "PE32 Magic")
    ok(p32["image_base"] == 0x400000, "PE32 ImageBase")
    ok(p32["entry_point"] == 0x1000, "PE32 入口")
    ok(p32["section_count"] == 1 and p32["sections"][0]["name"] == ".text",
       "PE32 节表")
    ok(p32["sections"][0]["executable"] and p32["sections"][0]["readable"]
       and not p32["sections"][0]["writable"], "PE32 节权限位")
    ok(p32["subsystem"] == "WINDOWS_CUI", "PE32 Subsystem")
    ok(p32["timestamp"].startswith(str(0x5F5E1000)) and "UTC" in p32["timestamp"],
       "PE32 时间戳转可读")
    ok(p32["imports"] and p32["imports"][0]["dll"] == "KERNEL32.dll", "PE32 导入 DLL")
    fn = [f.get("name") for f in p32["imports"][0]["functions"]]
    ok(fn == ["ExitProcess", "Sleep"], "PE32 导入函数名")
    ok(p32["dotnet"] is False, "PE32 非 .NET")

    p64 = pe_info(mk_pe(64))
    ok(p64["machine"] == "x86-64", "PE32+ Machine")
    ok(p64["pe_type"] == "PE32+", "PE32+ Magic")
    ok(p64["image_base"] == 0x140000000, "PE32+ ImageBase")
    ok(p64["entry_point"] == 0x1000, "PE32+ 入口")
    ok(p64["sections"][0]["name"] == ".text", "PE32+ 节表")
    ok(p64["imports"] and [f.get("name") for f in p64["imports"][0]["functions"]]
       == ["ExitProcess", "Sleep"], "PE32+ 导入（64 位 thunk）")

    pd = pe_info(mk_pe(32, dotnet=True))
    ok(pd["dotnet"] is True, "PE .NET 标志（COM Descriptor 非零）")

    pc = pe_info(mk_pe(32, cert=True))
    ok(pc["signature"] and pc["signature"]["size"] == 16, "PE 证书表大小")
    ok(pc["signature"]["in_file"] is True and pc["signature"]["pkcs7"] is True,
       "PE 证书表定位/PKCS7")
    ok(pc["overlay_size"] == 16, "PE overlay 计算")

    # ---------- 7. ELF ----------
    e64 = elf_info(mk_elf64())
    ok(e64["bits"] == 64 and e64["endian"] == "little", "ELF64 class/endian")
    ok(e64["type"] == "EXEC", "ELF type")
    ok(e64["machine"] == "x86-64", "ELF machine")
    ok(e64["entry"] == 0x401000, "ELF entry")
    ok(e64["phnum"] == 2 and len(e64["program_headers"]) == 2, "ELF phnum")
    ok(e64["program_headers"][0]["type"] == "LOAD"
       and e64["program_headers"][1]["type"] == "DYNAMIC", "ELF 程序头类型")
    ok([s["name"] for s in e64["sections"]] == [None, ".text", ".shstrtab"],
       "ELF 节名（.shstrtab 可读）")

    e32 = elf_info(mk_elf32be())
    ok(e32["bits"] == 32 and e32["endian"] == "big", "ELF32 大端")
    ok(e32["type"] == "EXEC" and e32["machine"] == "mips", "ELF32 type/machine")
    ok(e32["entry"] == 0x1000 and e32["phnum"] == 1, "ELF32 entry/phnum")
    ok(e32["program_headers"][0]["type"] == "LOAD", "ELF32 程序头")

    # ---------- 8. Mach-O ----------
    mo = macho_info(mk_macho())
    ok(mo["bits"] == 64, "Mach-O 64 位")
    ok(mo["cputype"] == "x86_64", "Mach-O cputype")
    ok(mo["filetype"] == "EXECUTE", "Mach-O filetype")
    ok(mo["ncmds"] == 3, "Mach-O ncmds")
    ok(mo["segments"] and mo["segments"][0]["name"] == "__TEXT", "Mach-O 段名")
    ok(mo["segments"][0]["vmaddr_raw"] == 0x100000000, "Mach-O vmaddr")
    ok(mo["entry_raw"] == 0x1000, "Mach-O LC_MAIN 入口")
    ok(mo["dylibs"] and mo["dylibs"][0]["path"] == "/usr/lib/libSystem.B.dylib",
       "Mach-O 依赖库")

    fat = (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
           + struct.pack(">IIIII", 7, 3, 0x1000, 0x2000, 12)
           + struct.pack(">IIIII", 0x01000007, 3, 0x3000, 0x4000, 12)
           + b"\x00" * 0x100)
    fmo = macho_info(fat)
    ok(fmo.get("fat") and fmo["arch_count"] == 2, "fat Mach-O 架构数")
    ok([a["cputype"] for a in fmo["architectures"]] == ["x86", "x86_64"],
       "fat Mach-O 架构列表")
    ok(sniff(fat)["kind"] == "fatmacho", "sniff fat Mach-O")

    # ---------- 9. 截断 / 不足 ----------
    odd = [
        (pe_info, b"MZ"),
        (pe_info, b"MZ" + b"\x00" * 0x3C),
        (pe_info, b"NO"),
        (elf_info, b"\x7fELF"),
        (elf_info, b"\x7fELF\x02\x01"),
        (elf_info, b"not elf"),
        (macho_info, b"\xcf\xfa\xed\xfe"),
        (macho_info, b"\xce\xfa\xed\xfe\x00"),
        (media_info, PNG_SIG),
        (media_info, b"\xff\xd8\xff"),
        (media_info, b"%PDF-"),
        (media_info, b""),
    ]
    for fn, blob in odd:
        r = fn(blob)
        ok(isinstance(r, dict) and ("error" in r or "note" in r),
           "%s 截断输入给出 error/note" % fn.__name__)
        pv = preview(blob)
        ok(isinstance(pv["text"], str) and pv["text"].strip(),
           "%s 截断输入 preview 非空" % fn.__name__)

    # 半截 PE：声明 3 个节但只剩 1 个
    half = bytearray(mk_pe(32))
    struct.pack_into("<H", half, 0x84 + 2, 3)
    hp = pe_info(bytes(half[:-0x100]))
    ok("error" in hp or hp.get("sections_truncated") or len(hp["sections"]) <= 3,
       "PE 节表截断有交代")

    # ---------- 10. preview 各 kind 非空 ----------
    samples = [(d, k) for d, k in sniffs if d]
    for data, want in samples:
        r = preview(data)
        ok(r["kind"] == want, "preview kind=%s" % want)
        ok(isinstance(r["text"], str) and len(r["text"].strip()) > 0,
           "preview text 非空 kind=%s" % want)
        ok(r["text"].startswith("== "), "preview 带类型抬头 kind=%s" % want)

    rp = preview(mk_pe(32), name="a.exe")
    ok("image_base=0x0000000000400000" in rp["text"] or
       "image_base=0x400000" in rp["text"], "preview PE 渲染 ImageBase")
    ok("KERNEL32.dll" in rp["text"], "preview PE 渲染导入")
    ok(rp["info"]["machine"] == "i386", "preview 返回 info")

    re_ = preview(mk_elf64())
    ok("entry=0x00401000" in re_["text"] and ".shstrtab" in re_["text"],
       "preview ELF 渲染")
    rm = preview(mk_macho())
    ok("__TEXT" in rm["text"] and "libSystem" in rm["text"], "preview Mach-O 渲染")
    rg = preview(mk_gif(64, 32))
    ok("GIF 64x32" in rg["text"], "preview GIF 渲染")

    # 输出一份样例（人工眼看）
    print("=" * 60)
    print(preview(mk_pe(64), name="demo.exe")["text"])
    print("=" * 60)
    print(preview(mk_elf64())["text"])
    print("=" * 60)
    print(preview(mk_macho())["text"])
    print("=" * 60)
    print(preview(mk_png(16, 8))["text"][:600])
    print("=" * 60)

    print("自检通过：%d 项断言" % _n[0])
    sys.exit(0)

