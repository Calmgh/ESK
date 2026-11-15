# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""全局搜索 —— 多编码关键词与正则

对应 LovelyCarve 的「全局搜索」能力：
  · 编码：ASCII / UTF-8 / UTF-16LE / UTF-16BE / GBK
  · 关键词或正则
  · 可跨整个镜像，也可只在某个区间（如未分配空间）
  · 命中带上下文字节，可导出 CSV
  · 按文件去重

用法：
    from mkit.search import scan, Encoding
    img = Image("disk.E01")
    for hit in scan(img.read, img.size, "password", encodings=["ascii","utf16le"]):
        print(hit.offset, hit.encoding, hit.context)

注意：
    这里扫的是**原始字节流**。要"只在某个文件的簇范围内扫"，
    请把 read 换成按簇读的闭包，或先导出该文件再扫。
"""

import csv
import re
import struct

__all__ = ["Encoding", "Hit", "scan", "scan_file", "to_csv", "find_all"]

# 编码表：名称 -> (字节编码, 说明)
Encoding = {
    "ascii":   ("ascii",   "ASCII / Latin-1 单字节"),
    "utf8":    ("utf-8",   "UTF-8（中文常见）"),
    "utf16le": ("utf-16-le", "UTF-16 小端（Windows 注册表/内存）"),
    "utf16be": ("utf-16-be", "UTF-16 大端"),
    "gbk":     ("gbk",     "GBK（简体中文）"),
    "utf16":   ("utf-16-le", "同 utf16le（兼容别名）"),
}

DEFAULT_ENCODINGS = ("ascii", "utf8", "utf16le")


class Hit(object):
    """一处命中"""

    __slots__ = ("offset", "length", "encoding", "text", "context", "pattern")

    def __init__(self, offset, length, encoding, text, context, pattern):
        self.offset = offset
        self.length = length
        self.encoding = encoding
        self.text = text
        self.context = context
        self.pattern = pattern

    def __repr__(self):
        return "<Hit @0x%X %s %r>" % (self.offset, self.encoding, self.text[:40])

    def as_row(self):
        return {
            "offset": "0x%X" % self.offset,
            "offset_dec": self.offset,
            "length": self.length,
            "encoding": self.encoding,
            "text": self.text,
            "context": self.context,
        }


def _encode(needle, enc):
    """把关键词按指定编码转成字节；无法表示的编码返回 None"""
    codec = Encoding.get(enc)
    if not codec:
        raise ValueError("未知编码: %s（可用: %s）" % (enc, ", ".join(Encoding)))
    try:
        b = needle.encode(codec[0])
    except (UnicodeEncodeError, LookupError):
        return None
    return b or None


def _context_of(buf, start, end, ctx_bytes):
    """从缓冲区里取上下文（把不可打印字节转成 .）"""
    lo = max(0, start - ctx_bytes)
    hi = min(len(buf), end + ctx_bytes)
    raw = buf[lo:hi]
    s = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
    return s


def scan(read_fn, size, pattern, encodings=DEFAULT_ENCODINGS,
         is_regex=False, chunk=8 << 20, overlap=None,
         context_bytes=32, max_hits=0, dedup=True,
         start=0, end=None, progress=None):
    """在字节流里搜关键词

    read_fn(offset, n) -> bytes   必须支持任意偏移读取
    size                            可读总长度

    is_regex=True 时 pattern 为正则（对每种编码分别编译；
                  UTF-16 类编码会把正则按宽字符处理）

    返回 Hit 列表（按 offset 升序）。
    """
    end = size if end is None else min(end, size)
    if start < 0 or start >= end:
        return []

    if overlap is None:
        overlap = 64 if not is_regex else 4096

    # 每种编码各自的匹配器
    matchers = []          # (enc_name, bytes_pattern or compiled regex, width)
    for enc in encodings:
        codec = Encoding.get(enc)
        if not codec:
            continue
        if is_regex:
            # 正则：对宽字符编码先转成「每字符插入 \x00」的形式太脆弱，
            # 这里的策略是——宽编码把原始文本先解码再匹配，见下方 decode 模式
            matchers.append((enc, pattern, codec[0]))
        else:
            nb = _encode(pattern, enc)
            if nb:
                matchers.append((enc, nb, codec[0]))

    if not matchers:
        return []

    hits = []
    seen = set()
    buf = b""
    base = start              # buf[0] 对应的绝对偏移
    pos = start

    while pos < end:
        n = min(chunk, end - pos)
        piece = read_fn(pos, n)
        if not piece:
            pos += n
            continue
        old_len = len(buf)
        buf = buf + piece if buf else piece
        # buf 起点偏移保持 base 不变，末尾对应 pos + len(piece)

        # 只在「新进入的部分 + overlap」里找，避免重复
        lo = max(0, old_len - overlap) if old_len else 0
        hi = len(buf)

        for enc, matcher, codec in matchers:
            if is_regex:
                # 宽编码：先解码成文本再匹配，命中后换算回字节偏移
                if codec.startswith("utf-16"):
                    try:
                        text = buf[lo:hi].decode(codec, "ignore")
                    except Exception:
                        continue
                    for m in re.finditer(matcher, text):
                        # 文本下标 -> 字节偏移（宽字符固定 2 字节）
                        b_off = base + lo + m.start() * 2
                        if b_off < start:
                            continue
                        key = (b_off, enc)
                        if dedup and key in seen:
                            continue
                        seen.add(key)
                        raw = buf[m.start() * 2: m.end() * 2]
                        hits.append(Hit(b_off, len(raw), enc, m.group(0),
                                        _context_of(buf, lo + m.start() * 2,
                                                    lo + m.end() * 2, context_bytes),
                                        pattern))
                else:
                    try:
                        text = buf[lo:hi].decode(codec, "ignore")
                    except Exception:
                        continue
                    for m in re.finditer(matcher, text):
                        b_off = base + lo + m.start()
                        if b_off < start:
                            continue
                        key = (b_off, enc)
                        if dedup and key in seen:
                            continue
                        seen.add(key)
                        hits.append(Hit(b_off, m.end() - m.start(), enc, m.group(0),
                                        _context_of(buf, lo + m.start(),
                                                    lo + m.end(), context_bytes),
                                        pattern))
            else:
                # 字面量：直接在字节里找
                idx = lo
                while True:
                    k = buf.find(matcher, idx, hi)
                    if k < 0:
                        break
                    b_off = base + k
                    if b_off >= start:
                        key = (b_off, enc)
                        if not dedup or key not in seen:
                            seen.add(key)
                            try:
                                txt = matcher.decode(codec, "replace")
                            except Exception:
                                txt = repr(matcher)
                            hits.append(Hit(b_off, len(matcher), enc, txt,
                                            _context_of(buf, k, k + len(matcher),
                                                        context_bytes),
                                            pattern))
                        if max_hits and len(hits) >= max_hits:
                            return sorted(hits, key=lambda h: h.offset)
                    idx = k + 1

        pos += len(piece)
        if progress:
            progress(pos, end)

        # 滑动窗口：保留尾部 overlap 字节
        if len(buf) > 2 * overlap:
            cut = len(buf) - overlap
            base += cut
            buf = buf[cut:]

    hits.sort(key=lambda h: h.offset)
    if max_hits:
        hits = hits[:max_hits]
    return hits


def scan_file(path, pattern, encodings=DEFAULT_ENCODINGS, is_regex=False, **kw):
    """对一个普通文件搜索"""
    import os

    def rd(off, n):
        with open(path, "rb") as f:
            f.seek(off)
            return f.read(n)

    return scan(rd, os.path.getsize(path), pattern, encodings, is_regex, **kw)


def to_csv(hits, out_path, encoding="utf-8-sig"):
    """导出命中为 CSV（Excel 友好）"""
    fields = ["offset", "offset_dec", "length", "encoding", "text", "context"]
    with open(out_path, "w", encoding=encoding, newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for h in hits:
            w.writerow(h.as_row())
    return len(hits)


def find_all(read_fn, size, needles, **kw):
    """批量搜多个关键词，返回 {关键词: [Hit]}"""
    out = {}
    for nd in needles:
        out[nd] = scan(read_fn, size, nd, **kw)
    return out


if __name__ == "__main__":
    import os
    import tempfile

    # 造一个混合编码的样本，验证各编码都能命中
    blob = (
        b"\x00" * 100
        + b"password=CorrectHorse"                 # ascii
        + b"\x00" * 50
        + "密码".encode("utf-8")                    # utf8
        + b"\x00" * 50
        + "密码".encode("utf-16-le")                # utf16le
        + b"\x00" * 50
        + "密码".encode("gbk")                      # gbk
        + b"\x00" * 100
    )
    hits = scan(lambda o, n: blob[o:o + n], len(blob), "password", ["ascii"])
    print("ascii 命中:", len(hits), hits[0].offset if hits else None)

    h_u8 = scan(lambda o, n: blob[o:o + n], len(blob), "密码", ["utf8"])
    h_u16 = scan(lambda o, n: blob[o:o + n], len(blob), "密码", ["utf16le"])
    h_gbk = scan(lambda o, n: blob[o:o + n], len(blob), "密码", ["gbk"])
    print("utf8 命中:", len(h_u8), " utf16le:", len(h_u16), " gbk:", len(h_gbk))

    h_re = scan(lambda o, n: blob[o:o + n], len(blob), r"pass\w+", ["ascii"], is_regex=True)
    print("正则命中:", len(h_re), h_re[0].text if h_re else None)
