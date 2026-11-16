# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  ZFS（只读）
# ============================================================
"""ZFS / OpenZFS 磁盘格式只读解析（全部小端）

已实现：
    · vdev label：4 个 label（0 / 256 KiB / size-512 KiB / size-256 KiB），
      每个 label 的 uberblock 环 128 × 1 KiB，`ub_magic` 校验后取 `ub_txg` 最大者
    · blkptr_t（128 B）、dnode_phys_t（512 B）、objset_phys_t（前 512 B 为 meta dnode）
    · 校验：fletcher4（32 位累加，另附 64 位累加变体作为兼容回退）、sha256
      校验不通过写 note 到 `Zfs.notes`，按块返回数据但仍显式记录
    · 解压：none(0) / lzjb(1) / gzip(2,6) / zle(3)；lz4(4)、zstd(5,7) 抛 NotImplementedError
    · 对象读取：`dn_nlevels` 多级 indirection、hole bp、embedded bp
    · ZAP：microzap（`ZBT_MICRO`，条目 64 B @0x40）与 fat-ZAP
      （`ZBT_HEADER` + `ZBT_LEAF`，chunk 24 B，embedded ptrtbl 与 ptrtbl 块两条路径）
    · 目录项值：3×u64 形式与单 u64 形式（低 48 位为对象号，高 4 位为类型）
    · `info()` / `labels()` / `read_block()` / `root_objset()` / `listdir()` /
      `walk()` / `read_file()` / `find()`

不实现（遇到即抛 NotImplementedError 或记 note，不返回假数据）：
    · 写操作、ZIL 回放、快照遍历、加密数据集（`ZBM_CRYPT`）、dedup、gang block
    · lz4 / zstd 解压
    · SA / 旧 znode bonus 布局解析 —— 文件精确长度、mtime、mode 取不到；
      `read_file()` 返回按块对齐的长度（`size=` 可由调用方裁剪）
    · label nvlist（pool 名 / guid）不解析，只做 uberblock 层
    · 多 vdev / raidz 重组：只读 blkptr 中第一个可读 DVA
"""

import fnmatch
import hashlib
import struct
import zlib

__all__ = [
    "Zfs", "probe", "open_fs",
    "SPA_MAGIC", "ZAP_MAGIC",
    "fletcher4", "lzjb_decompress", "lzjb_compress", "zle_decompress", "zle_compress",
    "decompress", "parse_bp", "parse_dnode", "dirent_obj",
    "DMU_OT_NAME",
]

# ------------------------------------------------------------
# 常量
# ------------------------------------------------------------
SPA_MAGIC = 0x00BAB10C
BLKPTR_LEN = 128
DNODE_LEN = 512
UBERBLOCK_LEN = 1024
UBERBLOCK_RING_OFFSET = 128 * 1024
UBERBLOCK_RING_COUNT = 128
VDEV_LABEL_SIZE = 256 * 1024
SPA_MINBLOCKSHIFT = 9

ZAP_MAGIC = 0x2F52AB2AB
ZBT_LEAF = (1 << 63) + 0
ZBT_HEADER = (1 << 63) + 1
ZBT_MICRO = (1 << 63) + 3
ZAP_LEAF_MAGIC = 0x02AB1EAF
ZAP_CHUNK_FREE = 253
ZAP_CHUNK_ENTRY = 252
ZAP_CHUNK_ARRAY = 251
ZAP_LEAF_CHUNKSIZE = 24
ZAP_LEAF_ARRAY_BYTES = 21
ZAP_FLAG_EMBEDDED_PTRTBL = 1 << 3

MASTER_NODE_OBJ = 1

DMU_OT_OBJECT_DIRECTORY = 1
DMU_OT_OBJECT_ARRAY = 2
DMU_OT_PACKED_NVLIST = 3
DMU_OT_DNODE = 10
DMU_OT_OBJSET = 11
DMU_OT_ZNODE = 12
DMU_OT_PLAIN_FILE_CONTENTS = 19
DMU_OT_DIRECTORY_CONTENTS = 20
DMU_OT_SA = 44

DMU_OT_NAME = {
    0: "none", 1: "object_directory", 2: "object_array", 3: "packed_nvlist",
    4: "packed_nvlist_size", 5: "packed_nvlist_old", 6: "spacemap_header",
    7: "spacemap_phys", 8: "unknown", 9: "zil_header", 10: "dnode",
    11: "objset", 12: "znode", 13: "acl", 14: "acl_sa", 15: "dir_acl",
    16: "dsl_dir", 17: "dsl_dataset", 18: "dsl_prop", 19: "plain_file_contents",
    20: "directory_contents", 21: "master_node", 22: "delete_queue",
    23: "link", 24: "prop", 25: "dir", 26: "dnode_child",
    27: "dir_ext_attr", 28: "dir_ext_attr_dir", 29: "map_entry",
    30: "map", 31: "dnode_child_attr", 32: "spill", 33: "unlinked_set",
    34: "unlinked_bpobj", 35: "deadlist", 36: "bpobj", 37: "dsl_scan",
    38: "dsl_scan_dir", 39: "dead_bpobj", 40: "deadlist_clone",
    41: "dsl_scan_phys", 42: "dsl_destroy", 43: "dsl_destroy_dir",
    44: "sa", 45: "sa_master", 46: "sa_attr_reg",
}

ZIO_COMPRESS_NAME = {
    0: "off", 1: "lzjb", 2: "gzip", 3: "zle", 4: "lz4", 5: "zstd",
    6: "gzip", 7: "zstd",
}

ZIO_CHECKSUM_NAME = {
    0: "inherit", 1: "on", 2: "off", 3: "labels", 4: "gang", 5: "zilog",
    6: "fletcher2", 7: "fletcher4", 8: "sha256", 9: "zilog2",
    10: "noparity", 11: "sha512", 12: "skein", 13: "edonr", 14: "blake3",
}

_HOLE_BP_RAW = b"\x00" * BLKPTR_LEN


# ------------------------------------------------------------
# 小工具
# ------------------------------------------------------------
def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def comp_name(c):
    return ZIO_COMPRESS_NAME.get(c, "comp%d" % c)


def cksum_name(c):
    return ZIO_CHECKSUM_NAME.get(c, "cksum%d" % c)


# ------------------------------------------------------------
# 校验和
# ------------------------------------------------------------
def fletcher4(data, wide=False):
    """Fletcher-4。

    wide=False：32 位累加（a+=w; b+=a; c+=b; d+=c，每步 mod 2^32），
                与任务规定一致，也是 zio_cksum_t 的常见落盘结果。
    wide=True ：64 位累加，部分 OpenZFS 编译/架构下的变体，用作兼容回退。
    返回 4 个整数，对应 blk_cksum 的 4 个 u64 字。
    """
    data = bytes(data)
    n = len(data) // 4
    a = b = c = d = 0
    if n:
        words = struct.unpack_from("<%dI" % n, data, 0)
        if wide:
            for w in words:
                a += w
                b += a
                c += b
                d += c
        else:
            m = 0xFFFFFFFF
            for w in words:
                a = (a + w) & m
                b = (b + a) & m
                c = (c + b) & m
                d = (d + c) & m
    return (a, b, c, d)


def _sha256(data):
    return hashlib.sha256(bytes(data)).digest()


# ------------------------------------------------------------
# 解压
# ------------------------------------------------------------
def zle_decompress(src, dlen):
    """ZLE：`0x00` + 2 字节大端长度 = 零游程；否则该字节 = 字面量长度"""
    out = bytearray()
    i = 0
    n = len(src)
    while i < n and len(out) < dlen:
        c = src[i]
        i += 1
        if c == 0:
            if i + 1 >= n:
                break
            run = (src[i] << 8) | src[i + 1]
            i += 2
            out.extend(b"\x00" * run)
        else:
            out.extend(src[i:i + c])
            i += c
    return bytes(out[:dlen])


def zle_compress(data):
    """仅供自检使用的最小 ZLE 编码器（字面量段 + 零游程）"""
    data = bytes(data)
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        if data[i] == 0:
            j = i
            while j < n and data[j] == 0:
                j += 1
            run = j - i
            while run > 0:
                take = min(run, 0xFFFF)
                out.append(0)
                out.extend(struct.pack(">H", take))
                run -= take
            i = j
        else:
            j = i
            while j < n and data[j] != 0 and j - i < 0x7F:
                j += 1
            out.append(j - i)
            out.extend(data[i:j])
            i = j
    return bytes(out)


def lzjb_decompress(src, dlen):
    """LZJB：copymap 每字节控制 8 项；match = 高位 2 位长度 + 14 位偏移"""
    dst = bytearray()
    i = 0
    n = len(src)
    while len(dst) < dlen:
        if i >= n:
            break
        copymap = src[i]
        i += 1
        for bit in range(8):
            if len(dst) >= dlen:
                break
            if copymap & (1 << bit):
                if i + 1 >= n:
                    i = n
                    break
                b0 = src[i]
                b1 = src[i + 1]
                i += 2
                start = len(dst) - ((((b0 & 0x3F) << 8) | b1) + 1)
                ln = (b0 >> 6) + 3
                if start < 0:
                    raise ValueError("lzjb 偏移越过输出起点（%d）" % start)
                for k in range(ln):
                    dst.append(dst[start + k])
            else:
                if i >= n:
                    break
                dst.append(src[i])
                i += 1
    return bytes(dst[:dlen])


def lzjb_compress(data, window=0x3FFF, maxlen=6):
    """LZJB 压缩（自检用往返验证；也用于构造合成块）"""
    src = bytes(data)
    out = bytearray()
    pos = 0
    n = len(src)
    while pos < n:
        cmap_pos = len(out)
        out.append(0)
        cmap = 0
        for bit in range(8):
            if pos >= n:
                break
            blen = 0
            boff = 0
            if pos > 0 and pos + 3 <= n:
                for off in range(1, min(pos, window) + 1):
                    k = 0
                    while (k < maxlen and pos + k < n
                           and src[pos + k] == src[pos + k - off]):
                        k += 1
                    if k > blen:
                        blen = k
                        boff = off
                        if blen == maxlen:
                            break
            if blen >= 3:
                cmap |= 1 << bit
                v = boff - 1
                out.append(((blen - 3) << 6) | ((v >> 8) & 0x3F))
                out.append(v & 0xFF)
                pos += blen
            else:
                out.append(src[pos])
                pos += 1
        out[cmap_pos] = cmap
    return bytes(out)


def decompress(comp, data, lsize):
    """按 blk_prop 的压缩算法解压到 lsize 字节"""
    if lsize == 0:
        return b""
    data = bytes(data)
    if comp == 0:
        return data[:lsize]
    if comp in (2, 6):
        for wbits in (15, -15, 31, 47):
            try:
                return zlib.decompress(data, wbits)
            except zlib.error:
                continue
        raise ValueError("gzip 解压失败（zlib/raw deflate/gzip 三种窗口都试过）")
    if comp == 3:
        return zle_decompress(data, lsize)
    if comp == 1:
        return lzjb_decompress(data, lsize)
    if comp == 4:
        raise NotImplementedError("lz4 压缩块未实现（需 lz4 解压器）")
    if comp in (5, 7):
        raise NotImplementedError("zstd 压缩块未实现（需 zstd 解压器）")
    raise NotImplementedError("压缩算法 %d 未实现" % comp)


# ------------------------------------------------------------
# blkptr_t
# ------------------------------------------------------------
def parse_bp(raw):
    """解析 128 B blkptr_t（小端）"""
    if len(raw) < BLKPTR_LEN:
        raise ValueError("blkptr 长度不足 128 字节（%d）" % len(raw))
    raw = bytes(raw[:BLKPTR_LEN])
    prop = _u64(raw, 0x30)
    embedded = bool((prop >> 39) & 1)
    if embedded:
        lsize = (prop & 0xFFFF) + 1
    else:
        lsize = ((prop & 0xFFFF) + 1) << SPA_MINBLOCKSHIFT
    psize = (((prop >> 16) & 0xFFFF) + 1) << SPA_MINBLOCKSHIFT
    dvas = []
    for i in range(3):
        w0 = _u64(raw, i * 16)
        w1 = _u64(raw, i * 16 + 8)
        if w0 == 0 and w1 == 0:
            continue
        dvas.append({
            "asize": (w0 & 0xFFFFFF) << SPA_MINBLOCKSHIFT,
            "vdev": (w0 >> 32) & 0xFFFFFF,
            "offset": (w1 & 0x7FFFFFFFFFFFFFFF) << SPA_MINBLOCKSHIFT,
        })
    return {
        "raw": raw,
        "prop": prop,
        "lsize": lsize,
        "psize": psize,
        "comp": (prop >> 32) & 0x7F,
        "cksum": (prop >> 40) & 0xFF,
        "type": (prop >> 48) & 0xFF,
        "level": (prop >> 56) & 0x1F,
        "embedded": embedded,
        "dvas": dvas,
        "hole": prop == 0 and not any(raw[0x00:0x30]),
    }


# ------------------------------------------------------------
# dnode_phys_t
# ------------------------------------------------------------
def parse_dnode(raw, obj=None):
    """解析 dnode_phys_t（512 B + dn_extra_slots × 512 B 的 bonus 区）"""
    if len(raw) < DNODE_LEN:
        raise ValueError("dnode 长度不足 512 字节（%d）" % len(raw))
    raw = bytes(raw)
    bonuslen = _u16(raw, 0x0A)
    bonus = b""
    if bonuslen:
        avail = len(raw) - 0x1C0
        bonus = raw[0x1C0:0x1C0 + min(bonuslen, max(avail, 0))]
    return {
        "raw": raw,
        "obj": obj,
        "type": raw[0x00],
        "indblkshift": raw[0x01],
        "nlevels": raw[0x02],
        "nblkptr": raw[0x03],
        "bonustype": raw[0x04],
        "checksum": raw[0x05],
        "compress": raw[0x06],
        "flags": raw[0x07],
        "datablkszsec": _u16(raw, 0x08),
        "blocksize": _u16(raw, 0x08) << SPA_MINBLOCKSHIFT,
        "bonuslen": bonuslen,
        "extra_slots": raw[0x0C],
        "maxblkid": _u64(raw, 0x10),
        "used": _u64(raw, 0x18),
        "bps": [parse_bp(raw[0x40 + i * BLKPTR_LEN:0x40 + (i + 1) * BLKPTR_LEN])
                for i in range(3)],
        "bonus": bonus,
    }


# ------------------------------------------------------------
# 目录项值
# ------------------------------------------------------------
def dirent_obj(value):
    """目录 ZAP 值 → 对象号。

    3×u64 形式（object, gen, cookie）取第 0 字；
    单 u64 形式（现代 ZPL）低 48 位为对象号、高 4 位为类型号。
    两种都按 48 位掩码取对象号。
    """
    if len(value) < 8:
        raise ValueError("目录项值长度 %d，无法解析对象号" % len(value))
    return _u64(value, 0) & 0x0000FFFFFFFFFFFF


# ------------------------------------------------------------
# Zfs
# ------------------------------------------------------------
class Zfs:
    """ZFS 只读卷

    sub 只需 `read(offset, size)` 与 `size`（mkit.image.SubImage 满足）。
    """

    def __init__(self, sub, ashift=None):
        self.sub = sub
        self.ashift = ashift
        self.notes = []
        self.ubers = []
        self.label_info = []
        self.uber = None
        self._meta = None
        self._root = None
        self._dn_cache = {}
        self._scan()

    # -- 基础设施 ------------------------------------------
    def note(self, msg):
        self.notes.append(msg)
        return msg

    def _read(self, off, n):
        if n <= 0:
            return b""
        if off < 0:
            raise ValueError("负偏移 %d" % off)
        size = getattr(self.sub, "size", None)
        if size is not None and off >= size:
            return b""
        return bytes(self.sub.read(off, n))

    # -- label / uberblock ---------------------------------
    def _label_offsets(self):
        size = getattr(self.sub, "size", 0) or 0
        out = [0, VDEV_LABEL_SIZE]
        if size >= 4 * VDEV_LABEL_SIZE:
            out.append(size - 2 * VDEV_LABEL_SIZE)
            out.append(size - VDEV_LABEL_SIZE)
        return out

    def _scan(self):
        for idx, base in enumerate(self._label_offsets()):
            ring = base + UBERBLOCK_RING_OFFSET
            scanned = 0
            for i in range(UBERBLOCK_RING_COUNT):
                raw = self._read(ring + i * UBERBLOCK_LEN, UBERBLOCK_LEN)
                if len(raw) < UBERBLOCK_LEN:
                    break
                scanned += 1
                magic = _u64(raw, 0)
                self.ubers.append({
                    "label": idx,
                    "ring": i,
                    "offset": ring + i * UBERBLOCK_LEN,
                    "magic": magic,
                    "magic_ok": magic == SPA_MAGIC,
                    "version": _u64(raw, 8),
                    "txg": _u64(raw, 0x10),
                    "guid_sum": _u64(raw, 0x18),
                    "timestamp": _u64(raw, 0x20),
                    "rootbp": raw[0x28:0x28 + BLKPTR_LEN],
                })
            mine = [u for u in self.ubers if u["label"] == idx and u["magic_ok"]]
            self.label_info.append({
                "index": idx,
                "offset": base,
                "scanned": scanned,
                "magic_ok": len(mine),
                "max_txg": max((u["txg"] for u in mine), default=None),
            })
        cand = [u for u in self.ubers if u["magic_ok"]]
        if not cand:
            raise ValueError("未找到有效 uberblock（0x%08x），不是 ZFS 或已损坏" % SPA_MAGIC)
        self.uber = max(cand, key=lambda u: (u["txg"], u["version"]))
        self.notes.append(
            "uberblock 选定：label %d ring %d txg %d version %d"
            % (self.uber["label"], self.uber["ring"], self.uber["txg"], self.uber["version"]))

    def labels(self):
        """各 label 摘要"""
        out = []
        for li in self.label_info:
            out.append({
                "index": li["index"],
                "offset": li["offset"],
                "uberblocks_scanned": li["scanned"],
                "uberblocks_valid": li["magic_ok"],
                "max_txg": li["max_txg"],
                "selected": bool(self.uber and self.uber["label"] == li["index"]),
            })
        return out

    # -- 块读取 --------------------------------------------
    def _stored(self, bp):
        if bp["embedded"]:
            return bp["raw"][:min(bp["lsize"], 112)]
        if not bp["dvas"]:
            raise ValueError("blkptr 无 DVA")
        last = None
        for n, dva in enumerate(bp["dvas"]):
            data = self._read(dva["offset"], bp["psize"])
            if len(data) == bp["psize"]:
                if n > 0:
                    self.note("DVA[0] 读取不完整，改用 DVA[%d]" % n)
                return data
            last = (n, dva["offset"], len(data))
        raise ValueError("blkptr 所有 DVA 都读不全（最后尝试 %r）" % (last,))

    def _check_cksum(self, bp, stored):
        if bp["embedded"]:
            self.note("embedded bp 的校验未验证（lsize=%d）" % bp["lsize"])
            return None
        want = bp["raw"][0x60:0x80]
        ck = bp["cksum"]
        where = "vdev%d+0x%x psize=%d" % (
            bp["dvas"][0]["vdev"], bp["dvas"][0]["offset"], bp["psize"]) if bp["dvas"] else "embedded"
        if ck == 7:
            if struct.pack("<4Q", *fletcher4(stored)) == want:
                return True
            if struct.pack("<4Q", *fletcher4(stored, wide=True)) == want:
                self.note("fletcher4 以 64 位累加变体通过（%s）" % where)
                return True
            self.note("fletcher4 校验失败（%s）" % where)
            return False
        if ck == 8:
            ok = _sha256(stored) == want
            if not ok:
                self.note("sha256 校验失败（%s）" % where)
            return ok
        self.note("校验类型 %s 未实现，跳过（%s）" % (cksum_name(ck), where))
        return None

    def verify_block(self, bp):
        """True / False / None（未实现的校验类型）"""
        if not isinstance(bp, dict):
            bp = parse_bp(bp)
        if bp["prop"] == 0:
            return None
        return self._check_cksum(bp, self._stored(bp))

    def read_block(self, bp, verify=True):
        """读一个块：读存储字节 → 校验 → 解压到 lsize。bp 可以是 dict 或 128 B"""
        if not isinstance(bp, dict):
            bp = parse_bp(bp)
        if bp["prop"] == 0:
            return b"\x00" * bp["lsize"] if bp["lsize"] else b""
        stored = self._stored(bp)
        if verify:
            self._check_cksum(bp, stored)
        out = decompress(bp["comp"], stored, bp["lsize"])
        if len(out) < bp["lsize"]:
            self.note("解压结果偏短：%d < lsize %d，尾部补零" % (len(out), bp["lsize"]))
            out = out + b"\x00" * (bp["lsize"] - len(out))
        elif len(out) > bp["lsize"]:
            self.note("解压结果偏长：%d > lsize %d，已截断" % (len(out), bp["lsize"]))
            out = out[:bp["lsize"]]
        return out

    # -- objset / dnode ------------------------------------
    def root_objset(self):
        """ub_rootbp → 块前 512 B 的 meta dnode"""
        if self._meta is None:
            blk = self.read_block(self.uber["rootbp"])
            if len(blk) < DNODE_LEN:
                raise ValueError("objset 块过短（%d）" % len(blk))
            meta = parse_dnode(blk[:DNODE_LEN], obj=0)
            if meta["type"] != DMU_OT_OBJSET:
                self.note("meta dnode 类型为 %d（期望 11=objset），继续尝试"
                          % meta["type"])
            self._meta = meta
        return self._meta

    def dnode(self, obj):
        """对象号 → dnode_phys_t"""
        obj = int(obj)
        if obj in self._dn_cache:
            return self._dn_cache[obj]
        meta = self.root_objset()
        raw = self._read_obj(meta, obj * DNODE_LEN, DNODE_LEN)
        if len(raw) < DNODE_LEN:
            raise ValueError("dnode %d 读取越界（%d 字节）" % (obj, len(raw)))
        dn = parse_dnode(raw, obj=obj)
        extra = dn["extra_slots"]
        if extra:
            raw = self._read_obj(meta, obj * DNODE_LEN, DNODE_LEN * (1 + extra))
            dn = parse_dnode(raw, obj=obj)
        self._dn_cache[obj] = dn
        return dn

    def _leaf_bps(self, dn):
        """展平 indirection，返回 [(逻辑块号, bp)]"""
        nbp = min(dn["nblkptr"], len(dn["bps"]))
        bps = dn["bps"][:nbp]
        if dn["nlevels"] <= 1:
            return [(i, bp) for i, bp in enumerate(bps)]
        shift = dn["indblkshift"]
        if shift <= 0 or shift > 24:
            raise NotImplementedError("dn_indblkshift=%d 无法展开多级 indirection" % shift)
        per = (1 << shift) // BLKPTR_LEN
        out = []

        def walk(bp, depth, base):
            if depth == 0:
                out.append((base, bp))
                return
            span = per ** depth
            if bp["prop"] == 0:
                for k in range(span):
                    out.append((base + k, parse_bp(_HOLE_BP_RAW)))
                return
            blk = self.read_block(bp)
            for k in range(per):
                sub = parse_bp(blk[k * BLKPTR_LEN:(k + 1) * BLKPTR_LEN])
                walk(sub, depth - 1, base + k * (per ** (depth - 1)))

        for i, bp in enumerate(bps):
            walk(bp, dn["nlevels"] - 1, i * (per ** (dn["nlevels"] - 1)))
        return out

    def _read_obj(self, dn, off, length):
        """按字节区间读对象数据（跨块拼接，hole 补零）"""
        if length <= 0:
            return b""
        bs = dn["blocksize"]
        if bs <= 0:
            bs = 1 << 17
            self.note("dnode blocksize 为 0，按 128 KiB 处理")
        bps = self._leaf_bps(dn)
        first = off // bs
        last = (off + length - 1) // bs
        out = bytearray()
        for idx in range(first, last + 1):
            bp = bps[idx][1] if idx < len(bps) else parse_bp(_HOLE_BP_RAW)
            if bp["prop"] == 0:
                chunk = b"\x00" * bs
            else:
                chunk = self.read_block(bp)
                if len(chunk) < bs:
                    chunk = bytes(chunk) + b"\x00" * (bs - len(chunk))
            out.extend(chunk[:bs])
        rel = off - first * bs
        return bytes(out[rel:rel + length])

    def _obj_size(self, dn):
        """块级数据长度（末块按 bp.lsize 收敛；精确 size 需 SA/znode bonus，未实现）"""
        bs = dn["blocksize"] or (1 << 17)
        total = 0
        for idx, bp in self._leaf_bps(dn):
            if bp["prop"] == 0:
                continue
            end = idx * bs + bp["lsize"]
            if end > total:
                total = end
        return total

    # -- ZAP -----------------------------------------------
    def _zap_bs(self, dn):
        bs = dn["blocksize"]
        if bs <= 0 or (bs & (bs - 1)):
            self.note("ZAP blocksize=%d 非法，按 16 KiB 处理" % bs)
            bs = 1 << 14
        return bs

    def zap_entries(self, dn):
        """ZAP 对象 → {名字: 值字节}；不支持的布局抛 NotImplementedError"""
        bs = self._zap_bs(dn)
        hdr = self._read_obj(dn, 0, bs)
        if len(hdr) < 0x68:
            raise ValueError("ZAP 头块过短（%d）" % len(hdr))
        btype = _u64(hdr, 0)
        magic = _u64(hdr, 8)
        if magic != ZAP_MAGIC:
            raise NotImplementedError(
                "对象 %r 不是 ZAP（magic=0x%x, block_type=0x%x, dnode type=%s）"
                % (dn.get("obj"), magic, btype, DMU_OT_NAME.get(dn["type"], dn["type"])))
        if btype == ZBT_MICRO:
            return self._zap_micro(dn, bs)
        if btype == ZBT_HEADER:
            return self._zap_leaf(dn, bs, hdr)
        raise NotImplementedError("ZAP block_type 0x%016x 未支持" % btype)

    def _zap_micro(self, dn, bs):
        blk = self._read_obj(dn, 0, bs)
        out = {}
        off = 0x40
        while off + 64 <= len(blk):
            name = blk[off + 14:off + 64].split(b"\x00")[0]
            if not name:
                break
            out[name.decode("utf-8", "surrogateescape")] = blk[off:off + 8]
            off += 64
        return out

    def _zap_leaf(self, dn, bs, hdr):
        shift = bs.bit_length() - 1
        numhash = 1 << (shift - 5)
        chunk_base = 0x30 + 2 * numhash
        numchunks = (bs - 2 * numhash) // ZAP_LEAF_CHUNKSIZE - 2
        zt_blk = _u64(hdr, 0x10)
        zt_numblks = _u64(hdr, 0x18)
        zt_shift = _u64(hdr, 0x20)
        num_leafs = _u64(hdr, 0x40)
        flags = _u64(hdr, 0x60)
        embedded = bool(flags & ZAP_FLAG_EMBEDDED_PTRTBL) or zt_numblks == 0
        if zt_shift > 20:
            raise NotImplementedError("ZAP ptrtbl shift=%d 异常" % zt_shift)

        def leaf_block(n):
            if embedded:
                at = 0x68 + n * 8
                if at + 8 > bs:
                    raise NotImplementedError("embedded ptrtbl 越界（leaf %d）" % n)
                return _u64(hdr, at)
            b = n >> zt_shift
            ptr = self._read_obj(dn, (zt_blk + b) * bs, bs)
            if len(ptr) < (n & ((1 << zt_shift) - 1)) * 8 + 8:
                raise NotImplementedError("ZAP ptrtbl 块读取失败（leaf %d）" % n)
            return _u64(ptr, (n & ((1 << zt_shift) - 1)) * 8)

        out = {}
        for n in range(num_leafs):
            blkno = leaf_block(n)
            lb = self._read_obj(dn, blkno * bs, bs)
            if len(lb) < chunk_base:
                raise NotImplementedError("ZAP leaf %d 块过短" % n)
            if _u64(lb, 0) != ZBT_LEAF:
                self.note("ZAP leaf %d block_type=0x%x（期望 ZBT_LEAF）"
                          % (n, _u64(lb, 0)))
            if _u32(lb, 0x18) != ZAP_LEAF_MAGIC:
                self.note("ZAP leaf %d magic=0x%x 不符" % (n, _u32(lb, 0x18)))
            out.update(self._leaf_entries(lb, chunk_base, numchunks))
        return out

    @staticmethod
    def _leaf_array(lb, chunk_base, numchunks, chunk, nbytes):
        out = bytearray()
        c = chunk
        guard = 0
        while len(out) < nbytes and c < numchunks and guard < 8192:
            guard += 1
            o = chunk_base + c * ZAP_LEAF_CHUNKSIZE
            if lb[o] != ZAP_CHUNK_ARRAY:
                break
            out.extend(lb[o + 1:o + 1 + ZAP_LEAF_ARRAY_BYTES])
            c = _u16(lb, o + 22)
        return bytes(out[:nbytes])

    @classmethod
    def _leaf_entries(cls, lb, chunk_base, numchunks):
        out = {}
        for i in range(numchunks):
            o = chunk_base + i * ZAP_LEAF_CHUNKSIZE
            if lb[o] != ZAP_CHUNK_ENTRY:
                continue
            intlen = lb[o + 1] or 1
            nchunk = _u16(lb, o + 4)
            nints = _u16(lb, o + 6)
            vchunk = _u16(lb, o + 8)
            vints = _u16(lb, o + 0x0A)
            if not nints:
                continue
            name = cls._leaf_array(lb, chunk_base, numchunks, nchunk, nints)
            name = name.split(b"\x00")[0]
            if not name:
                continue
            value = cls._leaf_array(lb, chunk_base, numchunks, vchunk, vints * intlen)
            out[name.decode("utf-8", "surrogateescape")] = value
        return out

    # -- 目录 ----------------------------------------------
    def root_dir_obj(self):
        if self._root is None:
            mn = self.dnode(MASTER_NODE_OBJ)
            ent = self.zap_entries(mn)
            if "ROOT" not in ent:
                raise NotImplementedError(
                    "master node（对象 1，type=%s）中找不到 ROOT 键；已解析出 %d 项"
                    % (DMU_OT_NAME.get(mn["type"], mn["type"]), len(ent)))
            self._root = dirent_obj(ent["ROOT"])
        return self._root

    def _split_path(self, path):
        p = str(path).replace("\\", "/")
        return [c for c in p.split("/") if c and c != "."]

    def _resolve(self, path):
        obj = self.root_dir_obj()
        for comp in self._split_path(path):
            entries = self.zap_entries(self.dnode(obj))
            if comp not in entries:
                raise FileNotFoundError(path)
            obj = dirent_obj(entries[comp])
        return obj

    def listdir_obj(self, obj):
        dn = self.dnode(obj)
        if dn["type"] != DMU_OT_DIRECTORY_CONTENTS:
            raise NotImplementedError(
                "对象 %d 类型 %s 不是目录（DIRECTORY_CONTENTS）"
                % (obj, DMU_OT_NAME.get(dn["type"], dn["type"])))
        out = []
        for name, value in self.zap_entries(dn).items():
            try:
                child = dirent_obj(value)
            except ValueError as exc:
                self.note("目录 %d 的项 %r 跳过：%s" % (obj, name, exc))
                continue
            kind = "?"
            try:
                cd = self.dnode(child)
                kind = DMU_OT_NAME.get(cd["type"], "type%d" % cd["type"])
            except Exception as exc:                     # noqa: BLE001
                self.note("目录项 %r 的对象 %d 无法解析：%s" % (name, child, exc))
            out.append({
                "name": name,
                "obj": child,
                "kind": kind,
                "value_len": len(value),
            })
        out.sort(key=lambda e: e["name"])
        return out

    def listdir(self, path="/"):
        return self.listdir_obj(self._resolve(path))

    def walk(self, path="/"):
        """广度优先遍历，产出 (路径, 对象号, 类型名)"""
        base = str(path).replace("\\", "/").rstrip("/")
        queue = [(base, self._resolve(path))]
        while queue:
            prefix, obj = queue.pop(0)
            try:
                entries = self.listdir_obj(obj)
            except NotImplementedError as exc:
                self.note("walk 跳过对象 %d：%s" % (obj, exc))
                continue
            for e in entries:
                p = (prefix + "/" + e["name"]) if prefix else "/" + e["name"]
                yield p, e["obj"], e["kind"]
                if e["kind"] == "directory_contents":
                    queue.append((p, e["obj"]))

    def find(self, pattern, path="/"):
        out = []
        for p, _obj, _kind in self.walk(path):
            if fnmatch.fnmatch(p.rsplit("/", 1)[-1], pattern) or fnmatch.fnmatch(p, pattern):
                out.append(p)
        return out

    def read_file(self, path, size=None):
        """读文件内容（块对齐长度；精确 size 需 SA/znode bonus，未实现）"""
        dn = self.dnode(self._resolve(path))
        if dn["type"] != DMU_OT_PLAIN_FILE_CONTENTS:
            raise NotImplementedError(
                "%s 类型为 %s，不是 PLAIN_FILE_CONTENTS"
                % (path, DMU_OT_NAME.get(dn["type"], dn["type"])))
        data = self._read_obj(dn, 0, self._obj_size(dn))
        if size is not None:
            data = data[:size]
        return data

    # -- 汇总 ----------------------------------------------
    def info(self):
        ub = self.uber
        rootbp = parse_bp(ub["rootbp"])
        return {
            "type": "zfs",
            "version": ub["version"],
            "txg": ub["txg"],
            "guid_sum": ub["guid_sum"],
            "timestamp": ub["timestamp"],
            "uberblock_offset": ub["offset"],
            "label": ub["label"],
            "ashift": self.ashift,
            "rootbp": {
                "lsize": rootbp["lsize"],
                "psize": rootbp["psize"],
                "comp": comp_name(rootbp["comp"]),
                "cksum": cksum_name(rootbp["cksum"]),
                "type": rootbp["type"],
                "level": rootbp["level"],
                "dvas": rootbp["dvas"],
            },
            "meta_dnode": {
                "type": DMU_OT_NAME.get(self.root_objset()["type"]),
                "nlevels": self.root_objset()["nlevels"],
                "nblkptr": self.root_objset()["nblkptr"],
                "blocksize": self.root_objset()["blocksize"],
            },
            "labels": self.labels(),
            "notes": list(self.notes),
        }


# ------------------------------------------------------------
# 模块级接口
# ------------------------------------------------------------
def probe(sub):
    """粗判是否 ZFS：扫 4 个 label 的 uberblock 环找 0x00bab10c"""
    size = getattr(sub, "size", 0) or 0
    bases = [0, VDEV_LABEL_SIZE]
    if size >= 4 * VDEV_LABEL_SIZE:
        bases += [size - 2 * VDEV_LABEL_SIZE, size - VDEV_LABEL_SIZE]
    for base in bases:
        ring = base + UBERBLOCK_RING_OFFSET
        head = sub.read(ring, UBERBLOCK_LEN)
        if len(head) >= 24 and _u64(head, 0) == SPA_MAGIC:
            return True
        for i in range(UBERBLOCK_RING_COUNT):
            raw = sub.read(ring + i * UBERBLOCK_LEN, 8)
            if len(raw) >= 8 and _u64(raw, 0) == SPA_MAGIC:
                return True
    return False


def open_fs(sub, ashift=None):
    if not probe(sub):
        raise ValueError("非 ZFS 镜像：未找到 uberblock magic 0x%08x" % SPA_MAGIC)
    return Zfs(sub, ashift=ashift)


# ------------------------------------------------------------
# 自检（全部合成镜像，无外部数据）
# ------------------------------------------------------------
class _Mem:
    """带 .size 的最小只读 sub"""

    def __init__(self, data):
        self._d = bytearray(data)
        self.size = len(self._d)

    def read(self, off, n):
        if off < 0 or n <= 0 or off >= self.size:
            return b""
        return bytes(self._d[off:off + n])


class _Bld:
    """合成镜像：标签区之外从 0x100000 起顺序分配数据块"""

    def __init__(self, size=6 << 20):
        self.buf = bytearray(size)
        self.cursor = 0x100000

    def alloc(self, data, align=512):
        off = (self.cursor + align - 1) & ~(align - 1)
        if off + len(data) > len(self.buf):
            raise RuntimeError("合成镜像空间不足")
        self.buf[off:off + len(data)] = data
        self.cursor = off + len(data)
        return off


def _mk_bp(stored, lsize, comp=0, ck=7, typ=0, level=0, offset=0, vdev=0,
           cksum=None):
    psize = ((len(stored) + 511) // 512) * 512
    assert lsize % 512 == 0, "lsize 必须是 512 的倍数"
    prop = (lsize // 512 - 1) & 0xFFFF
    prop |= ((psize // 512) - 1) << 16
    prop |= (comp & 0x7F) << 32
    prop |= (ck & 0xFF) << 40
    prop |= (typ & 0xFF) << 48
    prop |= (level & 0x1F) << 56
    raw = bytearray(128)
    struct.pack_into("<Q", raw, 0, (psize >> 9) | (vdev << 32))
    struct.pack_into("<Q", raw, 8, offset >> 9)
    struct.pack_into("<Q", raw, 0x30, prop)
    if cksum is None:
        if ck == 7:
            cksum = struct.pack("<4Q", *fletcher4(stored))
        elif ck == 8:
            cksum = _sha256(stored)
        else:
            cksum = b"\x00" * 32
    raw[0x60:0x80] = bytes(cksum)[:32]
    return bytes(raw)


def _put_block(bld, stored, lsize, comp=0, ck=7, typ=0, level=0):
    """把存储字节写入镜像并返回指向它的 blkptr"""
    psize = ((len(stored) + 511) // 512) * 512
    padded = bytes(stored) + b"\x00" * (psize - len(stored))
    off = bld.alloc(padded)
    return _mk_bp(padded, lsize, comp=comp, ck=ck, typ=typ, level=level, offset=off)


def _mk_dnode(typ, bps, blocksize=1 << 14, nlevels=1, indblkshift=14,
              bonustype=0, bonus=b"", ck=7):
    raw = bytearray(512)
    raw[0x00] = typ
    raw[0x01] = indblkshift
    raw[0x02] = nlevels
    raw[0x03] = len(bps)
    raw[0x04] = bonustype
    raw[0x05] = ck
    raw[0x06] = 0
    raw[0x07] = 0
    struct.pack_into("<H", raw, 0x08, blocksize >> 9)
    struct.pack_into("<H", raw, 0x0A, len(bonus))
    raw[0x0C] = 0
    struct.pack_into("<Q", raw, 0x10, 0)
    struct.pack_into("<Q", raw, 0x18, 0)
    for i, bp in enumerate(bps[:3]):
        raw[0x40 + i * BLKPTR_LEN:0x40 + (i + 1) * BLKPTR_LEN] = bp
    if bonus:
        raw[0x1C0:0x1C0 + len(bonus)] = bonus[:64]
    return bytes(raw)


def _mk_microzap(bs, items):
    """items: [(name, u64)] → microzap 块"""
    blk = bytearray(bs)
    struct.pack_into("<Q", blk, 0, ZBT_MICRO)
    struct.pack_into("<Q", blk, 8, ZAP_MAGIC)
    off = 0x40
    for name, value in items:
        nm = name.encode()
        assert len(nm) <= 49
        struct.pack_into("<Q", blk, off, value)
        struct.pack_into("<I", blk, off + 8, 0)
        blk[off + 14:off + 14 + len(nm)] = nm
        off += 64
    return bytes(blk)


def _mk_leaf_zap(bs, items, embedded=True):
    """items: [(name, value_bytes)] → [header, (ptrtbl), leaf] 块列表"""
    shift = bs.bit_length() - 1
    numhash = 1 << (shift - 5)
    chunk_base = 0x30 + 2 * numhash
    numchunks = (bs - 2 * numhash) // ZAP_LEAF_CHUNKSIZE - 2
    leaf = bytearray(bs)
    struct.pack_into("<Q", leaf, 0, ZBT_LEAF)
    struct.pack_into("<I", leaf, 0x18, ZAP_LEAF_MAGIC)
    free = list(range(numchunks))

    def put_array(data):
        nch = (len(data) + ZAP_LEAF_ARRAY_BYTES - 1) // ZAP_LEAF_ARRAY_BYTES
        idxs = [free.pop(0) for _ in range(nch)]
        pos = 0
        for k, ci in enumerate(idxs):
            o = chunk_base + ci * ZAP_LEAF_CHUNKSIZE
            leaf[o] = ZAP_CHUNK_ARRAY
            piece = data[pos:pos + ZAP_LEAF_ARRAY_BYTES]
            pos += ZAP_LEAF_ARRAY_BYTES
            leaf[o + 1:o + 1 + len(piece)] = piece
            nxt = idxs[k + 1] if k + 1 < len(idxs) else 0xFFFF
            struct.pack_into("<H", leaf, o + 22, nxt)
        return idxs[0]

    for name, value in items:
        nm = name.encode() + b"\x00"
        assert len(nm) <= 0xFFFF and len(value) <= 0xFFFF
        nfirst = put_array(nm)
        vfirst = put_array(value)
        intlen = 8 if len(value) % 8 == 0 else 1
        ci = free.pop(0)
        o = chunk_base + ci * ZAP_LEAF_CHUNKSIZE
        leaf[o] = ZAP_CHUNK_ENTRY
        leaf[o + 1] = intlen
        struct.pack_into("<H", leaf, o + 2, 0)
        struct.pack_into("<H", leaf, o + 4, nfirst)
        struct.pack_into("<H", leaf, o + 6, len(nm))
        struct.pack_into("<H", leaf, o + 8, vfirst)
        struct.pack_into("<H", leaf, o + 0x0A, len(value) // intlen)

    hdr = bytearray(bs)
    struct.pack_into("<Q", hdr, 0, ZBT_HEADER)
    struct.pack_into("<Q", hdr, 8, ZAP_MAGIC)
    struct.pack_into("<Q", hdr, 0x40, 1)          # num_leafs
    struct.pack_into("<Q", hdr, 0x48, len(items))  # num_entries
    if embedded:
        struct.pack_into("<Q", hdr, 0x60, ZAP_FLAG_EMBEDDED_PTRTBL)
        struct.pack_into("<Q", hdr, 0x10, 0)      # zt_blk
        struct.pack_into("<Q", hdr, 0x18, 0)      # zt_numblks
        struct.pack_into("<Q", hdr, 0x68, 1)      # leaf 块号 = 1
        return [bytes(hdr), bytes(leaf)]
    struct.pack_into("<Q", hdr, 0x10, 1)          # zt_blk = 1
    struct.pack_into("<Q", hdr, 0x18, 1)          # zt_numblks
    struct.pack_into("<Q", hdr, 0x20, 0)          # zt_shift
    ptr = bytearray(bs)
    struct.pack_into("<Q", ptr, 0, 2)             # leaf 块号 = 2
    return [bytes(hdr), bytes(ptr), bytes(leaf)]


def _mk_uber(txg, rootbp, magic=SPA_MAGIC, version=5000, guid_sum=0x1122334455667788,
             ts=1700000000):
    b = bytearray(UBERBLOCK_LEN)
    struct.pack_into("<Q", b, 0x00, magic)
    struct.pack_into("<Q", b, 0x08, version)
    struct.pack_into("<Q", b, 0x10, txg)
    struct.pack_into("<Q", b, 0x18, guid_sum)
    struct.pack_into("<Q", b, 0x20, ts)
    b[0x28:0x28 + BLKPTR_LEN] = rootbp
    return bytes(b)


def _write_uber(bld, label_off, slot, txg, rootbp, magic=SPA_MAGIC):
    at = label_off + UBERBLOCK_RING_OFFSET + slot * UBERBLOCK_LEN
    bld.buf[at:at + UBERBLOCK_LEN] = _mk_uber(txg, rootbp, magic=magic)


def _build_image():
    bld = _Bld(6 << 20)
    bs = 1 << 14

    # 文件内容
    hello = b"hello zfs\n" + b"x" * (512 - 10)
    gz = zlib.compress(hello, 6)
    zeros = b"\x00" * 512
    zle = zle_compress(zeros)
    bbin = (b"lzjb-roundtrip-" * 100)[:1024]
    lz = lzjb_compress(bbin)

    bp_hello = _put_block(bld, gz, 512, comp=2, ck=7, typ=DMU_OT_PLAIN_FILE_CONTENTS)
    bp_zeros = _put_block(bld, zle, 512, comp=3, ck=7, typ=DMU_OT_PLAIN_FILE_CONTENTS)
    bp_bbin = _put_block(bld, lz, 1024, comp=1, ck=8, typ=DMU_OT_PLAIN_FILE_CONTENTS)
    bp_plain = _put_block(bld, hello, 512, comp=0, ck=7, typ=DMU_OT_PLAIN_FILE_CONTENTS)

    # 多级 indirection：level-1 间接块指向两个 512 B 叶子块
    big = b"A" * 512 + b"B" * 512
    bp_big0 = _put_block(bld, big[:512], 512, typ=DMU_OT_PLAIN_FILE_CONTENTS)
    bp_big1 = _put_block(bld, big[512:], 512, typ=DMU_OT_PLAIN_FILE_CONTENTS)
    ind = bytearray(bs)
    ind[0:BLKPTR_LEN] = bp_big0
    ind[BLKPTR_LEN:2 * BLKPTR_LEN] = bp_big1
    bp_ind = _put_block(bld, bytes(ind), bs, typ=DMU_OT_PLAIN_FILE_CONTENTS, level=1)

    # 子目录：fat-ZAP（非 embedded ptrtbl），值 3×u64
    sub_blocks = _mk_leaf_zap(bs, [("b.bin", struct.pack("<3Q", 5, 1, 0))],
                              embedded=False)
    sub_bps = [_put_block(bld, blk, bs, typ=DMU_OT_DIRECTORY_CONTENTS)
               for blk in sub_blocks]

    # 根目录：fat-ZAP（embedded ptrtbl），值 3×u64
    root_blocks = _mk_leaf_zap(bs, [
        ("hello.txt", struct.pack("<3Q", 3, 7, 0)),
        ("sub", struct.pack("<3Q", 4, 7, 0)),
        ("zeros.bin", struct.pack("<3Q", 6, 7, 0)),
        ("big.dat", struct.pack("<3Q", 7, 7, 0)),
    ], embedded=True)
    root_bps = [_put_block(bld, blk, bs, typ=DMU_OT_DIRECTORY_CONTENTS)
                for blk in root_blocks]

    # master node（对象 1）：microzap ROOT → 2
    mn_blk = _mk_microzap(bs, [("ROOT", 2)])
    mn_bp = _put_block(bld, mn_blk, bs, typ=DMU_OT_OBJECT_DIRECTORY)

    nodes = {
        1: _mk_dnode(DMU_OT_OBJECT_DIRECTORY, [mn_bp], blocksize=bs, bonustype=8),
        2: _mk_dnode(DMU_OT_DIRECTORY_CONTENTS, root_bps, blocksize=bs, bonustype=44),
        3: _mk_dnode(DMU_OT_PLAIN_FILE_CONTENTS, [bp_hello], blocksize=512, bonustype=44),
        4: _mk_dnode(DMU_OT_DIRECTORY_CONTENTS, sub_bps, blocksize=bs, bonustype=44),
        5: _mk_dnode(DMU_OT_PLAIN_FILE_CONTENTS, [bp_bbin], blocksize=1024, bonustype=44),
        6: _mk_dnode(DMU_OT_PLAIN_FILE_CONTENTS, [bp_zeros], blocksize=512, bonustype=44),
        7: _mk_dnode(DMU_OT_PLAIN_FILE_CONTENTS, [bp_ind], blocksize=512, nlevels=2,
                     bonustype=44),
    }
    arr = bytearray(bs)
    for obj, raw in nodes.items():
        arr[obj * DNODE_LEN:(obj + 1) * DNODE_LEN] = raw
    arr_bp = _put_block(bld, bytes(arr), bs, typ=DMU_OT_DNODE)

    meta = _mk_dnode(DMU_OT_OBJSET, [arr_bp], blocksize=bs, ck=7)
    osblk = bytearray(1024)
    osblk[0:512] = meta
    osblk[512:1024] = _mk_dnode(0, [], blocksize=bs)   # os_zil_header 区，占位
    rootbp = _put_block(bld, bytes(osblk), 1024, typ=DMU_OT_OBJSET)

    # 4 个 label：label0 有好的 txg200；label1 的 txg300 magic 坏；label2 好的 txg150
    size = len(bld.buf)
    labels = [0, VDEV_LABEL_SIZE, size - 2 * VDEV_LABEL_SIZE, size - VDEV_LABEL_SIZE]
    _write_uber(bld, labels[0], 0, 50, rootbp)
    _write_uber(bld, labels[0], 5, 200, rootbp)
    _write_uber(bld, labels[0], 40, 100, rootbp, magic=0x00BAB10D)   # 坏 magic
    _write_uber(bld, labels[1], 3, 300, rootbp, magic=0xDEADBEEF)    # 坏 magic，txg 更大
    _write_uber(bld, labels[2], 7, 150, rootbp)
    _write_uber(bld, labels[3], 9, 60, rootbp, magic=0x00BAB10C ^ 0xFF)
    return bytes(bld.buf), {
        "hello": hello, "bp_hello": bp_hello, "bp_plain": bp_plain,
        "bp_zeros": bp_zeros, "bbin": bbin, "lz": lz, "gz": gz, "zle": zle,
        "big": big,
    }


def selftest():
    img, fx = _build_image()
    sub = _Mem(img)
    done = []

    def ok(name):
        done.append(name)
        print("[ok] %s" % name)

    # 8. 非 ZFS
    assert probe(sub) is True
    assert probe(_Mem(b"\x00" * 8192)) is False
    assert probe(_Mem(b"NOTZFS" * 4096)) is False
    ok("probe(): ZFS 镜像 True，非 ZFS 输入 False")

    z = Zfs(sub)
    # 1. uberblock 选择：坏 magic 的 txg300 不能胜
    assert z.uber["txg"] == 200, z.uber["txg"]
    assert z.uber["label"] == 0 and z.uber["ring"] == 5
    labs = z.labels()
    assert len(labs) == 4
    assert [l["uberblocks_valid"] for l in labs] == [2, 0, 1, 0], labs
    assert labs[0]["selected"] is True
    assert labs[1]["max_txg"] is None            # label1 只有坏 magic 的 txg300
    assert z.ubers[0]["magic_ok"] and not any(
        u["magic_ok"] and u["label"] == 1 for u in z.ubers)
    ok("uberblock：4 label × 128 环全扫，坏 magic 的 txg300 被排除，选中 txg200")

    # 2. read_block 内容一致
    assert z.read_block(fx["bp_plain"]) == fx["hello"][:512]
    assert z.read_block(fx["bp_hello"]) == fx["hello"][:512]
    ok("read_block：明文与 gzip 块内容与已知数据一致")

    # 3. fletcher4
    assert fletcher4(fx["hello"]) == fletcher4(fx["hello"])
    assert fletcher4(fx["hello"]) != fletcher4(fx["hello"][:-1] + b"Y")
    assert z.verify_block(fx["bp_plain"]) is True
    bad = bytearray(img)
    off = _u64(fx["bp_plain"], 8) << 9
    bad[off + 3] ^= 0xFF
    zb = Zfs(_Mem(bytes(bad)))
    zb.notes.clear()
    assert zb.verify_block(fx["bp_plain"]) is False
    assert any("fletcher4 校验失败" in n for n in zb.notes), zb.notes
    ok("fletcher4：正确数据通过，改一字节失败并记 note")

    # 4. zle
    assert z.read_block(fx["bp_zeros"]) == b"\x00" * 512
    assert zle_decompress(zle_compress(b"\x00" * 1000 + b"AB" + b"\x00" * 5), 1007) \
        == b"\x00" * 1000 + b"AB" + b"\x00" * 5
    ok("zle：全零块解压长度 512 正确，字面量/零游程混合往返正确")

    # 5. lzjb 往返
    assert lzjb_decompress(fx["lz"], 1024) == fx["bbin"]
    for sample in (b"a", b"abc", b"aaaaaaaaaaaaaaaa", b"0123456789" * 20):
        comp = lzjb_compress(sample)
        assert lzjb_decompress(comp, len(sample)) == sample, sample
    ok("lzjb：自造样例往返正确（len 3..6 / offset 14 位）")

    # 6. gzip
    assert z.read_block(fx["bp_hello"]) == fx["hello"][:512]
    assert decompress(2, zlib.compress(b"gzip-body" * 10), 90) == b"gzip-body" * 10
    ok("gzip：zlib 头与块路径都能解")

    # 7. lz4 / zstd
    for comp in (4, 5, 7):
        bp = _mk_bp(b"\x00" * 512, 512, comp=comp, ck=2)
        try:
            z.read_block(bp)
        except NotImplementedError as exc:
            assert "lz4" in str(exc) or "zstd" in str(exc), exc
        else:
            raise AssertionError("comp=%d 未抛 NotImplementedError" % comp)
    ok("lz4 / zstd：read_block 抛 NotImplementedError")

    # 9. objset → dnode → ZAP → 目录
    meta = z.root_objset()
    assert meta["type"] == DMU_OT_OBJSET
    assert z.root_dir_obj() == 2
    root = z.listdir("/")
    names = [e["name"] for e in root]
    assert names == ["big.dat", "hello.txt", "sub", "zeros.bin"], names
    kinds = {e["name"]: e["kind"] for e in root}
    assert kinds["sub"] == "directory_contents", kinds
    assert kinds["hello.txt"] == "plain_file_contents", kinds
    subdir = z.listdir("/sub")
    assert [e["name"] for e in subdir] == ["b.bin"]
    assert subdir[0]["obj"] == 5
    assert subdir[0]["value_len"] == 24          # 3×u64
    assert [e["value_len"] for e in root][0] == 24
    ok("ZAP/目录：microzap(ROOT) + fat-ZAP leaf（embedded 与 ptrtbl 块两路径）解析成功，3×u64 值取第 1 字")

    # 10. read_file / walk / find
    assert z.read_file("/hello.txt") == fx["hello"][:512]
    assert z.read_file("/sub/b.bin") == fx["bbin"]
    assert z.read_file("/zeros.bin") == b"\x00" * 512
    paths = sorted(p for p, _o, _k in z.walk("/"))
    assert paths == ["/big.dat", "/hello.txt", "/sub", "/sub/b.bin",
                     "/zeros.bin"], paths
    assert z.find("*.txt") == ["/hello.txt"]
    assert z.find("b.bin") == ["/sub/b.bin"]
    ok("read_file / walk / find：内容、遍历、匹配正确")

    # 11. 多级 indirection
    assert z.read_file("/big.dat") == fx["big"]
    dn7 = z.dnode(7)
    assert dn7["nlevels"] == 2 and dn7["nblkptr"] == 1
    ok("多级 indirection：dn_nlevels=2（level-1 间接块）跨叶子块拼装正确")

    # info 汇总 + 接口完整性
    info = z.info()
    assert info["txg"] == 200 and info["label"] == 0
    assert len(info["labels"]) == 4
    fs = open_fs(sub)
    assert fs.info()["version"] == 5000
    ok("info() / open_fs() 接口可用")

    print("")
    print("self-test: %d 项全部通过" % len(done))
    return done


if __name__ == "__main__":
    selftest()
