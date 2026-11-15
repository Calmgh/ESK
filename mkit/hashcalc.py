# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""文件哈希与校验 —— MD5 / SHA-1 / SHA-256 / SM3

对应 LovelyCarve 的「校验与导出」能力：
  · 单文件 / 目录树 / 镜像全量哈希
  · EWF(E01) 采集哈希核对
  · 分区与卷的哈希
  · 大文件分块流式计算（不占内存）

SM3 为国密标准（GB/T 32905-2016），纯 Python 实现，不依赖 OpenSSL。
"""

import hashlib
import os
import struct

__all__ = [
    "ALGOS", "file_hash", "stream_hash", "verify_ewf_hash",
    "tree_hash", "bytes_hash", "sm3",
]

ALGOS = ("md5", "sha1", "sha256", "sm3")


# ============================================================
# SM3 —— GB/T 32905-2016
# ============================================================
_IV = (0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
       0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E)


def _rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _gg(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (~x & 0xFFFFFFFF & z)


_T = [0x79CC4519 if j < 16 else 0x7A879D8A for j in range(64)]


class _SM3:
    """SM3 增量哈希"""

    block_size = 64
    digest_size = 32
    name = "sm3"

    def __init__(self, data=b""):
        self._v = list(_IV)
        self._buf = b""
        self._len = 0
        if data:
            self.update(data)

    def update(self, data):
        if isinstance(data, str):
            data = data.encode()
        self._len += len(data)
        buf = self._buf + data
        off = 0
        while off + 64 <= len(buf):
            self._compress(buf[off:off + 64])
            off += 64
        self._buf = buf[off:]
        return self

    def _compress(self, block):
        w = list(struct.unpack(">16I", block))
        for j in range(16, 68):
            w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
                     ^ _rotl(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]

        a, b, c, d, e, f, g, h = self._v
        for j in range(64):
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(_T[j], j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            tt1 = (_ff(j, a, b, c) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (_gg(j, e, f, g) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = _rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = _p0(tt2)
        self._v = [(x ^ y) & 0xFFFFFFFF for x, y in zip(self._v, (a, b, c, d, e, f, g, h))]

    def digest(self):
        """返回 32 字节摘要（不改变内部状态）"""
        clone = _SM3()
        clone._v = list(self._v)
        clone._buf = self._buf
        clone._len = self._len
        bitlen = clone._len * 8
        clone.update(b"\x80")
        while len(clone._buf) % 64 != 56:
            clone.update(b"\x00")
        clone.update(struct.pack(">Q", bitlen))
        return struct.pack(">8I", *clone._v)

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        c = _SM3()
        c._v = list(self._v)
        c._buf = self._buf
        c._len = self._len
        return c


def sm3(data=b""):
    """便捷函数：返回 SM3 十六进制摘要"""
    return _SM3(data).hexdigest()


def _new(algo):
    a = algo.lower().replace("-", "")
    if a == "sm3":
        return _SM3()
    if a in ("md5", "sha1", "sha256"):
        return hashlib.new(a)
    raise ValueError("不支持的算法: %s（可用: %s）" % (algo, ", ".join(ALGOS)))


# ============================================================
# 流式计算
# ============================================================
def stream_hash(read_fn, size, algos=ALGOS, chunk=4 << 20, progress=None):
    """对一个「按偏移读」的可调用对象做流式哈希

    read_fn(offset, n) -> bytes
    """
    hs = {a: _new(a) for a in algos}
    off = 0
    while off < size:
        n = min(chunk, size - off)
        data = read_fn(off, n)
        if not data:
            off += n                     # 坏区：跳过但不假装读到
            continue
        for h in hs.values():
            h.update(data)
        off += len(data)
        if progress:
            progress(off, size)
    return {a: h.hexdigest() for a, h in hs.items()}


def file_hash(path, algos=ALGOS, chunk=4 << 20, progress=None):
    """计算文件的多个哈希（一次读取全部算出）"""
    hs = {a: _new(a) for a in algos}
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            for h in hs.values():
                h.update(data)
            done += len(data)
            if progress:
                progress(done, total)
    return {a: h.hexdigest() for a, h in hs.items()}


def bytes_hash(data, algos=ALGOS):
    hs = {a: _new(a) for a in algos}
    for h in hs.values():
        h.update(data)
    return {a: h.hexdigest() for a, h in hs.items()}


def tree_hash(root, algos=("sha256",), follow_links=False):
    """目录树哈希：{相对路径: {algo: hex}}，只哈希普通文件"""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
        dirnames.sort()
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            if not os.path.isfile(p) or os.path.islink(p) and not follow_links:
                continue
            rel = os.path.relpath(p, root)
            try:
                out[rel] = file_hash(p, algos)
            except OSError as e:
                out[rel] = {"error": str(e)}
    return out


# ============================================================
# EWF 采集哈希核对
# ============================================================
def verify_ewf_hash(image_or_path, algos=("md5", "sha1", "sha256")):
    """核对 EWF 的采集哈希

    返回 dict:
      stored   —— EWF 头部记录的哈希
      computed —— 重新算出来的哈希
      match    —— 逐项比对结果
      note     —— 无法核对时的说明

    支持 mkit.image.Image 实例或路径。
    """
    stored = {}
    note = ""
    img = image_or_path

    # 1) 取 EWF 头部记录的哈希
    try:
        ewf = getattr(img, "ewf", None) or getattr(img, "_ewf", None)
        if ewf is not None:
            for attr, algo in (("md5_hash", "md5"), ("sha1_hash", "sha1")):
                v = getattr(ewf, attr, None)
                if v:
                    stored[algo] = v.hex() if isinstance(v, bytes) else str(v).lower()
    except Exception as e:
        note = "读取 EWF 头部失败: %s" % e

    if not stored:
        note = note or "该镜像未携带采集哈希，或解析器未暴露该字段"

    # 2) 重新计算
    computed = {}
    try:
        computed = stream_hash(img.read, img.size, algos)
    except Exception as e:
        note = (note + " | " if note else "") + "计算失败: %s" % e

    # 3) 比对
    match = {}
    for algo, want in stored.items():
        got = computed.get(algo)
        if got:
            match[algo] = (got.lower() == want.lower())

    return {"stored": stored, "computed": computed,
            "match": match, "note": note}


if __name__ == "__main__":
    # 自检向量（GB/T 32905-2016 与公开测试向量）
    assert sm3(b"abc") == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    assert sm3(b"abcd" * 16) == \
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
    assert sm3(b"") == "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
    print("SM3 自检通过")
    print("md5('abc') =", bytes_hash(b"abc", ("md5",))["md5"])
