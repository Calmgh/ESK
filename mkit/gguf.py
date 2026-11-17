#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  GGUF 模型文件结构解析
# ============================================================

"""GGUF（llama.cpp / ggml 模型文件格式）结构解析。

已实现
------
* 头部：magic ``GGUF``（小端 u32 = 0x46554747）、version、tensor_count、
  metadata_kv_count
* 元数据 KV：key 为 u64 长度 + UTF-8；值按 13 种类型解释
  （UINT8/INT8/UINT16/INT16/UINT32/INT32/FLOAT32/BOOL/STRING/ARRAY/
  UINT64/INT64/FLOAT64）。ARRAY 只展开到阈值（默认 1024），超过就只报
  元素类型与长度，避免把大词表全读进内存
* tensor_info：name、n_dims、dims[]、type、offset（相对数据区起点）
* ``alignment`` 取自 ``general.alignment``，缺省 32；据此算出数据区起点
* ``read_tensor`` 按偏移读原始字节，**不做反量化**
* 常用 kv 的便捷取值（架构、名字、分词器等），取不到返回 None

不实现
------
* **反量化 / 张量数值还原**：本模块是结构视图，只给布局与原始字节，
  不给浮点数值。要把 Q4_0 之类还原成 F32 需要 ggml 的量化表，
  本模块不做
* **GGML_TYPE 的完整 block 大小表**：见下方 ``GGML_TYPES``。只列出能
  在公开文档里逐一核对过的那一批；``Q2_K`` 以上的 K-quant 与 IQ 系列
  **不在表内**，遇到时 ``bytes`` 与 ``block_size`` 返回 ``None`` 并在
  ``notes`` 里说明，不猜数值
* 分片（``split.count`` / 多文件）不合并，只按单文件解析
* 不校验 CRC（GGUF 本身没有校验字段）

格式来源
--------
``ggml`` 仓库 ``docs/gguf.md``（官方规范）。字段顺序与类型枚举以该文档为准。
"""

import struct

__all__ = [
    "GGUF_MAGIC", "DEFAULT_ALIGNMENT", "TYPE_NAMES", "GGML_TYPES",
    "GgufError", "Gguf", "probe", "open_fs", "describe",
]

GGUF_MAGIC = 0x46554747          # 小端读 "GGUF"
DEFAULT_ALIGNMENT = 32

# 元数据类型枚举 -> 名字
TYPE_NAMES = {
    0: "UINT8", 1: "INT8", 2: "UINT16", 3: "INT16",
    4: "UINT32", 5: "INT32", 6: "FLOAT32", 7: "BOOL",
    8: "STRING", 9: "ARRAY", 10: "UINT64", 11: "INT64", 12: "FLOAT64",
}

# 定长标量的 struct 格式
_FIXED = {
    0: "<B", 1: "<b", 2: "<H", 3: "<h",
    4: "<I", 5: "<i", 6: "<f", 7: "<B",
    10: "<Q", 11: "<q", 12: "<d",
}

# GGML_TYPE -> (名字, block 里元素个数, block 字节数)
# 只列公开文档能逐一核对的那一批；K-quant 与 IQ 系列故意不列（见 docstring）。
GGML_TYPES = {
    0: ("F32", 1, 4),
    1: ("F16", 1, 2),
    2: ("Q4_0", 32, 18),
    3: ("Q4_1", 32, 20),
    6: ("Q5_0", 32, 22),
    7: ("Q5_1", 32, 24),
    8: ("Q8_0", 32, 34),
    9: ("Q8_1", 32, 40),
    24: ("I8", 1, 1),
    25: ("I16", 1, 2),
    26: ("I32", 1, 4),
    27: ("I64", 1, 8),
    28: ("F64", 1, 8),
    30: ("BF16", 1, 2),
}


class GgufError(ValueError):
    """GGUF 结构非法或数据不足"""


class _Reader(object):
    def __init__(self, sub):
        self.sub = sub
        self.pos = 0
        self.size = getattr(sub, "size", None)

    def read(self, n):
        if n < 0:
            raise GgufError("读取长度为负：%d" % n)
        d = self.sub.read(self.pos, n)
        d = bytes(d or b"")
        if len(d) < n:
            raise GgufError("数据不足：偏移 %d 处想要 %d 字节，只读到 %d"
                            % (self.pos, n, len(d)))
        self.pos += n
        return d

    def u8(self):
        return self.read(1)[0]

    def u32(self):
        return struct.unpack("<I", self.read(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.read(8))[0]

    def string(self):
        n = self.u64()
        if n > 64 << 20:
            raise GgufError("字符串长度异常：%d 字节" % n)
        return self.read(n).decode("utf-8", "replace")


class Gguf(object):
    """只读的 GGUF 结构视图

    参数
    ----
    sub : 提供 ``read(offset, size)`` 的对象（``mkit`` 统一接口）
    array_limit : int
        ARRAY 类型元数据最多展开多少个元素，超过只报长度。默认 1024。
    """

    def __init__(self, sub, array_limit=1024):
        self.sub = sub
        self.array_limit = int(array_limit)
        self.notes = []
        r = _Reader(sub)
        if r.size is not None and r.size < 24:
            raise GgufError("文件太小，不足以容纳 GGUF 头部（%d 字节）" % r.size)
        magic = r.u32()
        if magic != GGUF_MAGIC:
            raise GgufError("不是 GGUF：magic = 0x%08X，期望 0x%08X"
                            % (magic, GGUF_MAGIC))
        self.magic = magic
        self.version = r.u32()
        if self.version not in (2, 3):
            self.notes.append("版本 %d 不是常见的 2 或 3，字段顺序按规范照读"
                              % self.version)
        self.tensor_count = r.u64()
        self.kv_count = r.u64()
        self._kv = []
        for _ in range(self.kv_count):
            key = r.string()
            t = r.u32()
            self._kv.append((key, t, self._value(r, t)))
        self._tensors = []
        for _ in range(self.tensor_count):
            name = r.string()
            n_dims = r.u32()
            if n_dims > 8:
                raise GgufError("tensor %r 的维数异常：%d" % (name, n_dims))
            dims = [r.u64() for _ in range(n_dims)]
            ttype = r.u32()
            off = r.u64()
            self._tensors.append({
                "name": name, "dims": dims, "type_id": ttype,
                "type": self._ggml_name(ttype), "offset": off,
            })
        self._kv_end = r.pos
        self.alignment = self._alignment()
        self.data_offset = self._align_up(r.pos, self.alignment)
        for t in self._tensors:
            t["bytes"] = self._tensor_bytes(t)
            t["block_size"] = self._block_size(t["type_id"])

    # ---------------- 内部 ----------------

    def _value(self, r, t):
        if t in _FIXED:
            return struct.unpack(_FIXED[t], r.read(struct.calcsize(_FIXED[t])))[0]
        if t == 8:
            return r.string()
        if t == 9:
            et = r.u32()
            cnt = r.u64()
            if cnt > (1 << 40):
                raise GgufError("ARRAY 元素个数异常：%d" % cnt)
            arr = {"elem_type": self._type_name(et),
                   "elem_type_id": et, "count": cnt, "items": None}
            if cnt and et == 9:
                # 嵌套数组按规范允许，但实际文件里几乎不出现；
                # 不递归展开，直接按元素大小跳过会算不准，故明确拒绝。
                raise GgufError("ARRAY 的元素是 ARRAY（嵌套数组），本模块不展开")
            if cnt <= self.array_limit:
                arr["items"] = [self._value(r, et) for _ in range(cnt)]
            else:
                # 不展开，但要按类型把这段跳过，才能继续读后面的 kv
                step = self._elem_size(et)
                r.read(step * cnt)
                self.notes.append("ARRAY %d 项超过阈值 %d，只报长度"
                                  % (cnt, self.array_limit))
            return arr
        raise GgufError("未知的元数据类型编号：%d" % t)

    @staticmethod
    def _elem_size(et):
        """ARRAY 元素的定长大小；变长的给 -1"""
        if et in _FIXED:
            return struct.calcsize(_FIXED[et])
        return -1

    def _alignment(self):
        v = self.get("general.alignment")
        if isinstance(v, int) and v > 0 and (v & (v - 1)) == 0:
            return v
        return DEFAULT_ALIGNMENT

    @staticmethod
    def _align_up(n, a):
        if a <= 1:
            return n
        return (n + a - 1) // a * a

    @staticmethod
    def _type_name(tid):
        return TYPE_NAMES.get(tid, "TYPE_%d" % tid)

    @staticmethod
    def _ggml_name(tid):
        """张量类型是 GGML_TYPE，和元数据值类型是两套编号，别混用"""
        e = GGML_TYPES.get(tid)
        return e[0] if e else "GGML_TYPE_%d" % tid

    @staticmethod
    def _block_size(tid):
        e = GGML_TYPES.get(tid)
        return e[1] if e else None

    def _tensor_bytes(self, t):
        e = GGML_TYPES.get(t["type_id"])
        if e is None:
            self.notes.append(
                "tensor %r 的类型 %d 不在已核对的 block 表里，字节数未算"
                % (t["name"], t["type_id"]))
            return None
        _name, per_block, block_bytes = e
        total = 1
        for d in t["dims"]:
            total *= d
        if per_block <= 0:
            return None
        # 元素总数按 block 向上取整
        blocks = (total + per_block - 1) // per_block
        if blocks * per_block != total:
            self.notes.append(
                "tensor %r 的元素数 %d 不是 block 大小 %d 的整数倍"
                % (t["name"], total, per_block))
        return blocks * block_bytes

    # ---------------- 对外 ----------------

    def get(self, key, default=None):
        for k, _t, v in self._kv:
            if k == key:
                return v
        return default

    def info(self):
        return {
            "format": "GGUF",
            "magic": "0x%08X" % self.magic,
            "version": self.version,
            "tensor_count": self.tensor_count,
            "kv_count": self.kv_count,
            "alignment": self.alignment,
            "kv_end_offset": self._kv_end,
            "data_offset": self.data_offset,
            "architecture": self.architecture(),
            "name": self.get("general.name"),
        }

    def metadata(self):
        """key -> 值 的字典；ARRAY 超过阈值的 items 为 None"""
        return dict((k, v) for k, _t, v in self._kv)

    def metadata_types(self):
        return dict((k, TYPE_NAMES.get(t, "TYPE_%d" % t))
                    for k, t, _v in self._kv)

    def tensors(self):
        return [dict(t) for t in self._tensors]

    def tensor(self, name):
        for t in self._tensors:
            if t["name"] == name:
                return dict(t)
        return None

    def read_tensor(self, name, limit=None):
        """按 offset 读张量的**原始字节**（未反量化）"""
        t = self.tensor(name)
        if t is None:
            raise KeyError("找不到张量 %r" % name)
        if t["bytes"] is None:
            raise NotImplementedError(
                "张量 %r 的类型 %d 不在已核对的 block 表里，无法确定长度；"
                "请显式给 limit" % (name, t["type_id"]))
        n = t["bytes"] if limit is None else min(t["bytes"], int(limit))
        d = self.sub.read(self.data_offset + t["offset"], n)
        d = bytes(d or b"")
        if len(d) < n:
            raise GgufError("张量 %r 数据不足：想要 %d 字节，只读到 %d"
                            % (name, n, len(d)))
        return d

    def architecture(self):
        return self.get("general.architecture")

    def tokenizer_model(self):
        return self.get("tokenizer.ggml.model")

    def __repr__(self):
        return "<Gguf v%d kv=%d tensors=%d align=%d>" % (
            self.version, self.kv_count, self.tensor_count, self.alignment)


def probe(sub):
    """按 magic 判断是不是 GGUF"""
    try:
        d = bytes(sub.read(0, 4) or b"")
    except Exception:
        return False
    return len(d) == 4 and struct.unpack("<I", d)[0] == GGUF_MAGIC


def open_fs(sub, **kw):
    return Gguf(sub, **kw)


def describe(sub):
    """容错版：不是 GGUF 也不抛"""
    try:
        return Gguf(sub).info()
    except Exception as e:
        return {"format": "GGUF", "error": "%s: %s" % (type(e).__name__, e)}


# ============================================================
# 自检（合成镜像）
# ============================================================
class _Mem(object):
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read(self, off, size):
        return self.data[off:off + size]

    def write(self, off, data):
        self.data = (self.data[:off] + bytes(data)
                     + self.data[off + len(data):])
        self.size = len(self.data)


def _str(s):
    b = s.encode("utf-8")
    return struct.pack("<Q", len(b)) + b


def _mk_gguf(version=3, tensors=None, kv=None, alignment=32, pad=64):
    """构造最小 GGUF。kv 是 [(key, type_id, 打包好的值字节)]"""
    tensors = tensors or []
    kv = kv or []
    out = bytearray()
    out += struct.pack("<IIQQ", GGUF_MAGIC, version, len(tensors), len(kv))
    for key, t, vbytes in kv:
        out += _str(key) + struct.pack("<I", t) + vbytes
    for name, dims, ttype, off in tensors:
        out += _str(name) + struct.pack("<I", len(dims))
        for d in dims:
            out += struct.pack("<Q", d)
        out += struct.pack("<IQ", ttype, off)
    # 对齐到 alignment
    while len(out) % alignment:
        out += b"\x00"
    out += b"\x00" * pad
    return bytes(out)


def _selftest():
    ok = 0

    def ck(cond, label, extra=""):
        nonlocal ok
        if cond:
            ok += 1
            print("  [OK] %-52s %s" % (label, extra))
        else:
            raise AssertionError("FAIL: %s  %s" % (label, extra))

    print("\n=== 1) probe ===")
    img = _mk_gguf()
    ck(probe(_Mem(img)) is True, "probe() 命中 GGUF")
    ck(probe(_Mem(b"\x00" * 64)) is False, "全零 probe=False")
    ck(probe(_Mem(b"")) is False, "空输入 probe=False")
    ck(probe(_Mem(b"GGU")) is False, "过短 probe=False")
    ck(probe(_Mem(b"NOPE" + b"\x00" * 60)) is False, "别的 magic probe=False")

    print("\n=== 2) 头部与 info ===")
    kv = [
        ("general.name", 8, _str("测试模型")),
        ("general.architecture", 8, _str("llama")),
        ("general.alignment", 4, struct.pack("<I", 32)),
        ("llama.block_count", 4, struct.pack("<I", 32)),
        ("tokenizer.ggml.model", 8, _str("gpt2")),
    ]
    tensors = [
        ("token_embd.weight", [4, 8], 0, 0),      # F32
        ("blk.0.attn_q.weight", [4], 1, 128),     # F16
    ]
    img2 = _mk_gguf(version=3, tensors=tensors, kv=kv, pad=256)
    g = Gguf(_Mem(img2))
    i = g.info()
    ck(i["format"] == "GGUF" and i["version"] == 3, "version = 3", i["version"])
    ck(i["tensor_count"] == 2 and i["kv_count"] == 5, "计数正确",
       (i["tensor_count"], i["kv_count"]))
    ck(i["alignment"] == 32, "alignment 取自 general.alignment", i["alignment"])
    ck(i["architecture"] == "llama", "architecture", i["architecture"])
    ck(i["name"] == "测试模型", "中文 general.name 无损", i["name"])
    ck(g.tokenizer_model() == "gpt2", "tokenizer.ggml.model",
       g.tokenizer_model())
    ck(i["data_offset"] % 32 == 0, "数据区按 alignment 对齐", i["data_offset"])

    print("\n=== 3) 元数据 KV ===")
    md = g.metadata()
    ck(md["general.architecture"] == "llama", "STRING 取值")
    ck(md["llama.block_count"] == 32, "UINT32 取值", md["llama.block_count"])
    ts = g.metadata_types()
    ck(ts["general.name"] == "STRING" and ts["llama.block_count"] == "UINT32",
       "类型名")
    ck(g.get("不存在的键") is None, "取不到的键返回 None")
    ck(g.get("不存在的键", "d") == "d", "默认值生效")

    print("\n=== 4) ARRAY ===")
    arr_vals = b"".join(struct.pack("<I", v) for v in (3, 1, 4, 1, 5, 9, 2, 6))
    kv3 = [("tokenizer.ggml.tokens", 9,
            struct.pack("<IQ", 4, 8) + arr_vals)]
    g3 = Gguf(_Mem(_mk_gguf(kv=kv3)))
    a = g3.metadata()["tokenizer.ggml.tokens"]
    ck(a["elem_type"] == "UINT32" and a["count"] == 8, "ARRAY 类型与长度",
       (a["elem_type"], a["count"]))
    ck(a["items"] == [3, 1, 4, 1, 5, 9, 2, 6], "ARRAY 元素展开", a["items"])
    g3b = Gguf(_Mem(_mk_gguf(kv=kv3)), array_limit=4)
    a2 = g3b.metadata()["tokenizer.ggml.tokens"]
    ck(a2["items"] is None and a2["count"] == 8,
       "超阈值只报长度不展开", a2["count"])
    ck(any("超过阈值" in n for n in g3b.notes), "超阈值记了 note")

    print("\n=== 5) tensor 视图 ===")
    tl = g.tensors()
    ck(len(tl) == 2, "tensors() 数量", len(tl))
    t0 = g.tensor("token_embd.weight")
    ck(t0["dims"] == [4, 8] and t0["type"] == "F32", "dims 与类型",
       (t0["dims"], t0["type"]))
    ck(t0["bytes"] == 4 * 8 * 4, "F32 字节数 = 元素数 x 4", t0["bytes"])
    ck(t0["block_size"] == 1, "F32 block 大小 = 1")
    t1 = g.tensor("blk.0.attn_q.weight")
    ck(t1["bytes"] == 4 * 2, "F16 字节数 = 元素数 x 2", t1["bytes"])
    ck(g.tensor("不存在") is None, "不存在的 tensor 返回 None")

    print("\n=== 6) read_tensor ===")
    raw = g.read_tensor("token_embd.weight")
    ck(len(raw) == t0["bytes"], "读满整个张量", len(raw))
    ck(raw == b"\x00" * t0["bytes"], "合成文件里是零填充")
    ck(len(g.read_tensor("token_embd.weight", limit=8)) == 8, "limit 生效")
    try:
        g.read_tensor("不存在")
        raise AssertionError("应抛 KeyError")
    except KeyError:
        ck(True, "不存在的张量抛 KeyError")

    print("\n=== 7) 未核对的类型不猜 ===")
    kvk = [("general.name", 8, _str("k"))]
    gk = Gguf(_Mem(_mk_gguf(tensors=[("q4k", [256], 12, 0)], kv=kvk)))
    tk = gk.tensor("q4k")
    ck(tk["bytes"] is None and tk["block_size"] is None,
       "Q4_K 不在表内 -> bytes/block_size 为 None")
    ck(any("不在已核对的 block 表里" in n for n in gk.notes), "记了 note")

    print("\n=== 8) 截断与非法输入 ===")
    # 元数据区内的截断：连 key/type/value 都读不全，构造就该失败
    for cut in (4, 16, 30, 60):
        try:
            Gguf(_Mem(img2[:cut]))
            raise AssertionError("元数据区内截断 %d 字节应抛 GgufError" % cut)
        except GgufError:
            pass
    ck(True, "元数据区内的截断均抛 GgufError")
    # 元数据读完、只少了尾部数据区：头部依然合法，构造不该失败，
    # 只有真正去读张量时才报错——这里要区分清楚，别把合法头当坏文件。
    # 数据区填充了 256 字节而两个张量只要 136 字节，所以必须切得比余量多，
    # 否则读到的仍是完整张量（切 40 字节时 file 依然够读）。
    gcut = Gguf(_Mem(img2[:len(img2) - 200]))
    try:
        gcut.read_tensor("token_embd.weight")
        raise AssertionError("数据区截断时读张量应抛 GgufError")
    except GgufError:
        ck(True, "数据区截断时 read_tensor 抛 GgufError")
    d = describe(_Mem(b"not a gguf file"))
    ck(d.get("error") is not None, "describe() 容错不抛")
    try:
        Gguf(_Mem(b"\x00" * 64))
        raise AssertionError("非 GGUF 应抛 GgufError")
    except GgufError:
        ck(True, "非 GGUF 抛 GgufError")

    print("\n=== 9) 版本 ===")
    g2 = Gguf(_Mem(_mk_gguf(version=2)))
    ck(g2.version == 2, "version = 2 可解析", g2.version)
    g9 = Gguf(_Mem(_mk_gguf(version=9)))
    ck(g9.version == 9 and any("不是常见" in n for n in g9.notes),
       "非常见版本照读并记 note")

    print("\n=== 10) 便捷取值 ===")
    g0 = Gguf(_Mem(_mk_gguf()))
    ck(g0.architecture() is None, "无架构时返回 None")
    ck(g0.tokenizer_model() is None, "无分词器时返回 None")
    ck(g0.tensors() == [], "无张量时返回空列表")
    ck(g0.info()["data_offset"] >= 24, "空文件也给出数据区偏移")

    print("\n" + "-" * 52)
    print("自检：%d 项通过" % ok)
    print("-" * 52)
    return ok


if __name__ == "__main__":
    import sys
    try:
        _selftest()
    except AssertionError as e:
        print("\n[FAIL] %s" % e)
        sys.exit(1)