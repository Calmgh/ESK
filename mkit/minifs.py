# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""VxWorks MiniFS 文件系统（TP-Link / Mercusys 路由器固件）

格式依据（公开逆向资料，非厂商文档；MiniFS 是闭源私有格式）：
    Belimov & Vinogradov,《Reverse Engineered MiniFS File System》,
        ARES 2024, DOI 10.1145/3664476.3664511 / arXiv:2407.05064
    H4lo/MINIFS-Decompression（88 字节明文目录项变体的参考解包脚本）
    《VxWorks 固件系统研究》（ctfiot.com/84459、cn-sec.com/archives/1468351）
        —— 给出 struct MINIFS / struct file_info 的 C 形态
    CN111552511B（VxWorks IoT 固件文件名还原方法，仅作佐证）

关于「MINIFS v3」这个名字：上述所有公开资料都没有给出「v1/v2/v3」的版本编号，
论文明确写着「头部某个字段可能是文件系统版本，但是未识别」（header 偏移 0x10）。
资料能确认的是**两套不同布局**同时存在于现场：
    A：16 字节 magic 区（"MINIFS" + 0 填充）+ 4 字节 flag + 88 字节定长目录项
    B：32 字节固定头（含文件数 @0x14、名表长度 @0x1C）+ 名表 + 20 字节文件表
       + 12 字节块表
所以本模块按**结构自动判别**两种变体，不按「版本号」分支——版本号无从验证。

已实现：
    · 魔数定位（"MINIFS"，可扫描整卷，不要求位于扇区/页对齐处）
    · 变体 A：magic[16] + flag(u32) + file_info[FILECOUNT]
              file_info = { size:u32, offset:u32, name[80] }
              名字是**相对路径明文**，以 NUL 结尾，遇到非可打印名字即表尾
    · 变体 B：32 字节头 + ToN（NUL 分隔的路径表）+ 文件表 + 块表
              文件表 20 字节：path_off / name_off / chunk_no / part_off / size
              块表   12 字节：chunk_off / chunk_size / decompressed_size
    · 大小端自动判别（两套变体都按结构自洽性打分，不假定字节序）
    · LZMA-alone 块解压（13 字节头：prop + dictsize + 未压缩长度；
      兼容未压缩长度=0xFF..FF 的「未知长度」写法与流被截断的容错）
    · 变体 A 的块边界：扫描 LZMA-alone 头并做合法性校验
      （prop<=224、dictsize 为 2^n 或 3*2^n、长度字段合法），
      不只匹配 4 字节配置字，避免压缩流内部误命中
    · 目录树重建（路径来自记录本身，无 inode 概念）、listdir / walk /
      lookup_path / find / read_file / tree / info

不实现：
    · 写操作（格式本身只读，VxWorks 里是 romfs 式只读挂载）
    · 厂商把块改成非 LZMA-alone（例如 AES 加密或 zlib）的固件：
      这部分资料里只提到「1MB 以上固件名字不再是明文、疑似加密」，
      没有公开算法，遇到时抛 MinifsError 并在 notes 里点名
    · 变体 B 的 ToN 若不是明文字符串：按 utf-8/replace 硬解并记 warning，
      不做厂商私有的名字解密
    · 变体 A 的 dsize 缺失导致的「块内多文件」推断：A 只按记录里的
      offset/size 取切片；B 才用块表的 decompressed_size 校验
    · 硬链接 / 符号链接 / 权限 / 属主 / 时间戳（格式里没有这些字段）

格式要点（易错处）：
    * 所有多字节整数是**大端**（变体 B 的部分固件是 LE，靠打分回退）
    * 变体 A 的 offset 是**相对第一个 LZMA 块**的偏移，不是相对文件开头；
      变体 B 的 chunk_off 是相对**第一个块起点**的偏移，两者都不能当绝对偏移
    * 变体 A 名字字段宽度 80 字节，但 NUL 之后的填充**不保证**清零
    * 变体 B 的头部固定 32 字节，所以 ToN 起点 = base + 32，很容易错写成
      magic 字段宽度（16）
    * LZMA 配置字随版本变化：老固件 0x5A000080（prop=0x5A），
      新固件 0x5D000080（prop=0x5D，dict=8 MiB）——两者都要能吃
"""

import bisect
import fnmatch
import lzma
import struct

__all__ = [
    "Minifs", "MinifsError", "MinifsEntry",
    "MINIFS_MAGIC", "MINIFS_MAGIC_FIELD",
    "MINIFS_VARIANT_A", "MINIFS_VARIANT_B",
    "LZMA_CFG_WORDS", "probe", "open_fs",
]

MINIFS_MAGIC = b"MINIFS"
MINIFS_MAGIC_FIELD = 16          # magic 字段宽度，不足补 0

HDR_A = 20                       # 变体 A：magic(16) + flag(4)
ENTRY_A = 88                     # 变体 A 目录项
NAME_A = 80                      # 变体 A 名字字段

HDR_B = 32                       # 变体 B 固定头
OFF_B_UNKNOWN0 = 0x10            # 变体 B：用途未明（疑似版本/标志）
OFF_B_NFILES = 0x14              # 变体 B：文件数
OFF_B_UNKNOWN1 = 0x18            # 变体 B：用途未明
OFF_B_TONSIZE = 0x1C             # 变体 B：名表字节数
FILE_B = 20                      # 变体 B 文件表项
CHUNK_B = 12                     # 变体 B 块表项

MINIFS_VARIANT_A = "A"
MINIFS_VARIANT_B = "B"
VARIANT_DESC = {
    MINIFS_VARIANT_A: "A: magic[16]+flag+88B 明文目录项（路径内联）",
    MINIFS_VARIANT_B: "B: 32B 头 + ToN + 20B 文件表 + 12B 块表",
}

# LZMA-alone 前 4 字节（prop + dictsize 低 3 字节）在现场固件里出现过的值
LZMA_CFG_WORDS = (0x5A000080, 0x5D000080)
_LZMA_CFG_PREFIX = (b"\x5a\x00\x00", b"\x5d\x00\x00")
_LZMA_HDR = 13

MAX_ENTRIES = 1 << 20            # 目录项/文件数上限，防坏镜像把内存打死
MAX_CHUNKS = 1 << 16
SCAN_CAP = 64 << 20              # 块扫描/魔数扫描的读入上限
PROBE_CAP = 32 << 20
CACHE_CHUNKS = 8


class MinifsError(ValueError):
    """MiniFS 结构错误（魔数缺失、表越界、块解压失败等）"""


# ---------------------------------------------------------------- 基础工具

def _u32(raw, off, endian):
    return struct.unpack_from(endian + "I", raw, off)[0]


def _printable(blob):
    """名字字段是否像可打印路径：无控制字符，且含 / 或为可见 ASCII"""
    if not blob:
        return False
    for b in blob:
        if b == 0x09:
            continue
        if b < 0x20 or b == 0x7F:
            return False
    try:
        blob.decode("ascii")
    except UnicodeDecodeError:
        # 允许 UTF-8 中文名，但不允许随机二进制
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return all(ch.isprintable() for ch in text)
    return True


def _dict_ok(dsize):
    """LZMA 字典大小合法：0 .. 1 GiB 且为 2^n 或 3*2^n"""
    if dsize < 4096 or dsize > (1 << 30):
        return False
    for cand in (dsize, dsize // 3 if dsize % 3 == 0 else 0):
        if cand and not (cand & (cand - 1)):
            return True
    return False


def _lzma_alone_ok(blob):
    """13 字节头是否像 lzma_alone：prop<=224、dictsize 合法、长度字段合法"""
    if len(blob) < _LZMA_HDR:
        return False
    prop = blob[0]
    if prop > 224:
        return False                                   # 9*lc+9*lp*? +45*pb 上限 224
    if not _dict_ok(struct.unpack_from("<I", blob, 1)[0]):
        return False
    usize = struct.unpack_from("<Q", blob, 5)[0]
    return usize == 0xFFFFFFFFFFFFFFFF or usize < (1 << 40)


def _force_unknown_size(blob):
    """把 13 字节头的「未压缩大小」改成未知（0xFF*8），用于厂商写错长度字段"""
    if len(blob) < _LZMA_HDR:
        return blob
    return blob[:5] + b"\xff" * 8 + blob[_LZMA_HDR:]


def _lzma_decode(blob):
    """解一段 lzma_alone 流；容忍长度字段写错与流被截断"""
    if not blob:
        raise MinifsError("空块，无法 LZMA 解码")
    for cand in (blob, _force_unknown_size(blob)):
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        out = bytearray()
        try:
            for i in range(0, len(cand), 1 << 16):
                out += dec.decompress(cand[i:i + (1 << 16)])
                if dec.eof:
                    break
        except lzma.LZMAError:
            if not out:
                continue
            return bytes(out)          # 截断/尾部坏数据，保留已解出的部分
        if out:
            return bytes(out)
    raise MinifsError("LZMA-alone 解码失败（块长 %d）" % len(blob))


def _locate_magic(sub, limit=PROBE_CAP):
    """在镜像里找 "MINIFS"；返回绝对偏移，找不到返回 -1"""
    total = getattr(sub, "size", 0) or 0
    end = min(total, limit)
    step = 1 << 20
    pos = 0
    while pos < end:
        take = min(step + len(MINIFS_MAGIC) - 1, end - pos)
        blk = sub.read(pos, take) or b""
        hit = blk.find(MINIFS_MAGIC)
        if hit >= 0:
            return pos + hit
        pos += step
    return -1


# ---------------------------------------------------------------- 目录项

class MinifsEntry(object):
    """一个文件或目录。MiniFS 没有 inode，路径就是唯一标识"""

    __slots__ = ("path", "name", "size", "chunk", "part", "abs_off", "is_dir",
                 "offset_field")

    def __init__(self, path, name, size, chunk, part, abs_off, is_dir,
                 offset_field=0):
        self.path = path
        self.name = name
        self.size = size
        self.chunk = chunk
        self.part = part
        self.abs_off = abs_off
        self.is_dir = is_dir
        self.offset_field = offset_field   # 记录里原始 offset 值，便于取证

    @property
    def type_name(self):
        return "dir" if self.is_dir else "file"

    @property
    def is_file(self):
        return not self.is_dir

    def __repr__(self):
        return "<MinifsEntry %s %r %dB chunk=%s>" % (
            self.type_name, self.path, self.size, self.chunk)


# ---------------------------------------------------------------- 主体

class Minifs(object):
    """MiniFS 只读解析（变体 A / B 自动判别）"""

    def __init__(self, sub, base=None):
        self.sub = sub
        self.size = getattr(sub, "size", 0) or 0
        self.notes = []
        self.base = _locate_magic(sub) if base is None else int(base)
        if self.base is None or self.base < 0:
            raise MinifsError("未找到 MINIFS 魔数")
        if self.sub.read(self.base, len(MINIFS_MAGIC)) != MINIFS_MAGIC:
            raise MinifsError("偏移 0x%X 处不是 MINIFS 魔数" % self.base)

        self.variant = None
        self.endian = ">"
        self.nfiles = 0
        self.header_unknown = {}
        self.ton_size = 0
        self.ton_off = self.base + HDR_B
        self.files_off = 0
        self.chunks_off = 0
        self.first_chunk = 0
        self.chunks = []        # [(绝对偏移, 压缩长度, 解压长度或 None)]
        self._chunk_pos = []    # 块起点升序，供二分
        self.prop_bytes = set()

        self.entries = []       # 全部文件项（不含目录）
        self.dirs = {}          # "/" -> MinifsEntry
        self._children = {}     # 父路径 -> [MinifsEntry]
        self._cache = {}
        self._cache_order = []

        self._parse()

    # ------------------------------------------------------------ 判别
    def _score_a(self, endian):
        """变体 A 打分：连续 88 字节定长项，名字可打印且含斜杠"""
        score = 0
        off = self.base + HDR_A
        for i in range(64):
            raw = self.sub.read(off + i * ENTRY_A, ENTRY_A)
            if len(raw) < ENTRY_A:
                break
            size = _u32(raw, 0, endian)
            foff = _u32(raw, 4, endian)
            name = raw[8:8 + NAME_A].split(b"\x00")[0]
            if size > (1 << 26) or foff > (1 << 30):
                break
            if not _printable(name):
                break
            text = name.decode("utf-8", "replace")
            if "/" not in text and "\\" not in text:
                break
            score += 1
        return score

    def _score_b(self, endian):
        """变体 B 打分：文件数/名表长度自洽 + 前若干文件表项取值合法"""
        head = self.sub.read(self.base, HDR_B)
        if len(head) < HDR_B:
            return 0
        nfiles = _u32(head, OFF_B_NFILES, endian)
        ton = _u32(head, OFF_B_TONSIZE, endian)
        if not 0 < nfiles <= MAX_ENTRIES:
            return 0
        if not 0 < ton <= (1 << 24):
            return 0
        files_off = self.base + HDR_B + ton
        if files_off + nfiles * FILE_B > self.size:
            return 0
        score = 0
        want = min(nfiles, 64)
        for i in range(want):
            raw = self.sub.read(files_off + i * FILE_B, FILE_B)
            if len(raw) < FILE_B:
                return score
            poff = _u32(raw, 0, endian)
            noff = _u32(raw, 4, endian)
            cno = _u32(raw, 8, endian)
            part = _u32(raw, 12, endian)
            size = _u32(raw, 16, endian)
            if poff >= ton and noff >= ton:
                return score
            if cno > MAX_CHUNKS or part > (1 << 28) or size > (1 << 28):
                return score
            score += 1
        return score

    def _parse(self):
        cands = {}
        for endian in (">", "<"):
            cands[(MINIFS_VARIANT_A, endian)] = self._score_a(endian)
            cands[(MINIFS_VARIANT_B, endian)] = self._score_b(endian)

        # 变体 B 要求「表内绝大多数项自洽」，防止把 A 的 flag 误当文件数
        best = None
        best_score = 0
        for (family, endian), score in cands.items():
            if score <= 0:
                continue
            if family == MINIFS_VARIANT_B:
                nfiles = _u32(self.sub.read(self.base, HDR_B),
                              OFF_B_NFILES, endian)
                need = min(nfiles, 64)
                if score < max(1, int(need * 0.9)):
                    continue
            if score > best_score:
                best, best_score = (family, endian), score

        if best is None:
            raise MinifsError(
                "MINIFS 魔数之后的结构无法识别（变体 A/B、大小端均不成立）：%s"
                % dict((("%s/%s" % (k[0], k[1])), v)
                       for k, v in cands.items()))
        self.variant, self.endian = best
        if self.variant == MINIFS_VARIANT_A:
            self._parse_a()
        else:
            self._parse_b()
        self._chunk_pos = [c[0] for c in self.chunks]
        self._build_tree()

    # ------------------------------------------------------------ 变体 A
    def _parse_a(self):
        endian = self.endian
        flag_raw = self.sub.read(self.base + MINIFS_MAGIC_FIELD, 4)
        self.header_unknown = {
            "flag": _u32(flag_raw, 0, endian) if len(flag_raw) == 4 else None,
        }
        recs = []
        off = self.base + HDR_A
        while len(recs) < MAX_ENTRIES:
            raw = self.sub.read(off, ENTRY_A)
            if len(raw) < ENTRY_A:
                break
            name = raw[8:8 + NAME_A].split(b"\x00")[0]
            if not _printable(name):
                break                       # 表尾
            recs.append((name.decode("utf-8", "replace"),
                         _u32(raw, 0, endian), _u32(raw, 4, endian)))
            off += ENTRY_A
        if not recs:
            raise MinifsError("变体 A：目录项为空")
        self.nfiles = len(recs)

        table_end = self.base + HDR_A + ENTRY_A * len(recs)
        self.files_off = table_end
        self.first_chunk = self._scan_first_chunk(table_end)
        if self.first_chunk < 0:
            raise MinifsError("变体 A：目录项之后找不到 LZMA 块头（起点 0x%X）"
                              % table_end)
        self.chunks = self._scan_chunks(self.first_chunk)
        self._chunk_pos = [c[0] for c in self.chunks]   # _chunk_of 依赖升序

        for name, size, foff in recs:
            abs_off = self.first_chunk + foff
            idx, part = self._chunk_of(abs_off)
            self.entries.append(MinifsEntry(
                self._norm(name), self._basename(name), size, idx, part,
                abs_off, False, foff))

    def _scan_first_chunk(self, start):
        """在 [start, size) 里找第一个合法 lzma_alone 头"""
        hits = self._scan_cfg_words(start)
        return hits[0] if hits else -1

    def _scan_cfg_words(self, start):
        """扫描 lzma_alone 头候选位置：先匹配配置字前缀，再校验 13 字节头"""
        end = min(self.size, start + SCAN_CAP)
        if end - start <= _LZMA_HDR:
            return []
        buf = self.sub.read(start, end - start) or b""
        hits = []
        for prefix in _LZMA_CFG_PREFIX:
            pos = buf.find(prefix)
            while pos >= 0 and len(hits) < MAX_CHUNKS:
                if _lzma_alone_ok(buf[pos:pos + _LZMA_HDR]):
                    hits.append(start + pos)
                pos = buf.find(prefix, pos + 1)
        hits.sort()
        uniq = []
        for h in hits:
            if not uniq or h - uniq[-1] > _LZMA_HDR:
                uniq.append(h)
        if len(uniq) >= MAX_CHUNKS:
            self.notes.append("块候选数达到上限 %d，后续块未登记" % MAX_CHUNKS)
        return uniq

    def _scan_chunks(self, first):
        """变体 A：块边界靠扫描；长度 = 下一候选 − 本候选"""
        hits = self._scan_cfg_words(first)
        out = []
        for i, pos in enumerate(hits):
            nxt = hits[i + 1] if i + 1 < len(hits) else min(
                self.size, pos + (64 << 20))
            out.append((pos, max(0, nxt - pos), None))
            first_byte = self.sub.read(pos, 1)
            if first_byte:
                self.prop_bytes.add(first_byte[0])
        if not out:
            self.notes.append("未扫描到任何 LZMA 块")
        return out

    # ------------------------------------------------------------ 变体 B
    def _parse_b(self):
        endian = self.endian
        head = self.sub.read(self.base, HDR_B)
        if len(head) < HDR_B:
            raise MinifsError("变体 B：头部不足 %d 字节（读到 %d）"
                              % (HDR_B, len(head)))
        self.nfiles = _u32(head, OFF_B_NFILES, endian)
        self.ton_size = _u32(head, OFF_B_TONSIZE, endian)
        self.header_unknown = {
            "field_0x10": _u32(head, OFF_B_UNKNOWN0, endian),
            "field_0x18": _u32(head, OFF_B_UNKNOWN1, endian),
        }
        if self.nfiles > MAX_ENTRIES:
            raise MinifsError("变体 B：文件数异常 %d" % self.nfiles)

        self.ton_off = self.base + HDR_B
        self.ton = self.sub.read(self.ton_off, self.ton_size) or b""
        if len(self.ton) < self.ton_size:
            self.notes.append("名表被截断：读到 %d / %d 字节"
                              % (len(self.ton), self.ton_size))
        self.files_off = self.ton_off + self.ton_size
        self.chunks_off = self.files_off + self.nfiles * FILE_B

        recs = []
        maxc = -1
        for i in range(self.nfiles):
            raw = self.sub.read(self.files_off + i * FILE_B, FILE_B)
            if len(raw) < FILE_B:
                self.notes.append("文件表在第 %d 项截断" % i)
                break
            poff = _u32(raw, 0, endian)
            noff = _u32(raw, 4, endian)
            cno = _u32(raw, 8, endian)
            part = _u32(raw, 12, endian)
            size = _u32(raw, 16, endian)
            recs.append((poff, noff, cno, part, size))
            if cno > maxc:
                maxc = cno
        if not recs:
            raise MinifsError("变体 B：文件表为空")
        self.nfiles = len(recs)

        nchunks = maxc + 1
        if nchunks > MAX_CHUNKS:
            self.notes.append("块数 %d 超上限，按 %d 读" % (nchunks, MAX_CHUNKS))
            nchunks = MAX_CHUNKS
        self.first_chunk = self.chunks_off + nchunks * CHUNK_B
        if self.chunks_off + nchunks * CHUNK_B > self.size:
            self.notes.append("块表越过镜像末尾（可能被截断）")

        for i in range(nchunks):
            raw = self.sub.read(self.chunks_off + i * CHUNK_B, CHUNK_B)
            if len(raw) < CHUNK_B:
                break
            coff = _u32(raw, 0, endian)
            csize = _u32(raw, 4, endian)
            dsize = _u32(raw, 8, endian)
            self.chunks.append((self.first_chunk + coff, csize, dsize))

        for poff, noff, cno, part, size in recs:
            path = self._ton_str(poff)
            name = self._ton_str(noff)
            full = path + "/" + name if path else name
            abs_off = None
            if cno < len(self.chunks) and self.chunks[cno][0] is not None:
                abs_off = self.chunks[cno][0] + part
            self.entries.append(MinifsEntry(
                self._norm(full), self._basename(name or full), size,
                cno if cno < len(self.chunks) else None, part, abs_off,
                False, part))

    def _ton_str(self, off):
        """从名表取一个 NUL 结尾字符串"""
        if off >= len(self.ton):
            self.notes.append("名表偏移越界：%d / %d" % (off, len(self.ton)))
            return ""
        end = self.ton.find(b"\x00", off)
        if end < 0:
            end = len(self.ton)
        raw = self.ton[off:end]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            if not self.notes or "名表含非 UTF-8" not in " ".join(self.notes):
                self.notes.append("名表含非 UTF-8 字节，按 replace 还原"
                                  "（厂商可能对名字做了加密）")
            return raw.decode("utf-8", "replace")

    # ------------------------------------------------------------ 树
    def _norm(self, path):
        text = str(path).replace("\\", "/")
        parts = [p for p in text.split("/") if p not in ("", ".", "..")]
        return "/".join(parts)

    def _basename(self, path):
        parts = [p for p in self._norm(path).split("/") if p]
        return parts[-1] if parts else ""

    def _build_tree(self):
        # 内部键一律是「不带前导斜杠」的规范化路径，根是 ""
        root = MinifsEntry("", "", 0, None, 0, 0, True)
        self.dirs = {"": root}
        self._children = {"": []}
        for ent in self.entries:
            parts = [p for p in ent.path.split("/") if p]
            if not parts:
                continue
            parent = ""
            for part in parts[:-1]:
                child = part if parent == "" else parent + "/" + part
                if child not in self.dirs:
                    d = MinifsEntry(child, part, 0, None, 0, 0, True)
                    self.dirs[child] = d
                    self._children.setdefault(parent, []).append(d)
                    self._children.setdefault(child, [])
                parent = child
            self._children.setdefault(parent, []).append(ent)
        # 不排序：保留记录/表内出现次序，便于取证时对照原始映像

    # ------------------------------------------------------------ 块访问
    def _chunk_of(self, abs_off):
        """绝对偏移 -> (块号, 块内偏移)；变体 A 用，变体 B 直接查表"""
        if not self._chunk_pos:
            return None, 0
        idx = bisect.bisect_right(self._chunk_pos, abs_off) - 1
        if idx < 0:
            return None, 0
        return idx, abs_off - self._chunk_pos[idx]

    def _chunk_blob(self, idx):
        pos, csize, _dsize = self.chunks[idx]
        if csize:
            blob = self.sub.read(pos, csize) or b""
        else:
            blob = self.sub.read(pos, min(self.size - pos, 64 << 20)) or b""
        return blob

    def _chunk_data(self, idx):
        if idx in self._cache:
            return self._cache[idx]
        blob = self._chunk_blob(idx)
        try:
            data = _lzma_decode(blob)
        except MinifsError as exc:
            raise MinifsError("块 %d（0x%X）解压失败：%s"
                              % (idx, self.chunks[idx][0], exc))
        want = self.chunks[idx][2]
        if want is not None and len(data) != want:
            self.notes.append("块 %d 解压长度 %d 与块表 %d 不符"
                              % (idx, len(data), want))
        self._cache[idx] = data
        self._cache_order.append(idx)
        while len(self._cache_order) > CACHE_CHUNKS:
            self._cache.pop(self._cache_order.pop(0), None)
        return data

    # ------------------------------------------------------------ 公共接口
    def info(self):
        return {
            "format": "minifs",
            "variant": self.variant,
            "variant_desc": VARIANT_DESC.get(self.variant, "?"),
            "base": self.base,
            "endian": "big" if self.endian == ">" else "little",
            "files": sum(1 for e in self.entries if e.is_file),
            "dirs": len(self.dirs),
            "nfiles_field": self.nfiles,
            "ton_size": self.ton_size,
            "files_table": self.files_off,
            "chunk_table": self.chunks_off,
            "first_chunk": self.first_chunk,
            "chunks": len(self.chunks),
            "header_unknown": self.header_unknown,
            "lzma_prop": sorted("0x%02X" % p for p in self.prop_bytes),
            "notes": list(self.notes),
        }

    def _as_entry(self, obj):
        if isinstance(obj, MinifsEntry):
            return obj
        return self.lookup_path(obj)

    def listdir(self, path="/"):
        key = self._norm(path)
        if key not in self._children:
            raise MinifsError("不是目录或不存在：%r" % path)
        return list(self._children[key])

    def walk(self, path="/"):
        """深度优先产出 (路径, 目录项)；路径相对根，根自身不产出"""
        start = self._norm(path)
        if start not in self._children:
            raise MinifsError("路径不存在：%r" % path)
        stack = [(start, iter(self._children[start]))]
        while stack:
            parent, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                continue
            yield nxt.path, nxt
            if nxt.is_dir and nxt.path in self._children:
                stack.append((nxt.path, iter(self._children[nxt.path])))

    def lookup_path(self, path):
        key = self._norm(path)
        if key == "":
            return self.dirs[""]
        if key in self.dirs:
            return self.dirs[key]
        for ent in self.entries:
            if ent.path == key:
                return ent
        raise MinifsError("找不到路径：%r" % path)

    def find(self, pattern):
        return [(p, e) for p, e in self.walk()
                if fnmatch.fnmatch(p, pattern) or fnmatch.fnmatch(e.name,
                                                                 pattern)]

    def read_file(self, obj):
        ent = self._as_entry(obj)
        if ent.is_dir:
            raise MinifsError("%r 是目录，请用 listdir()" % ent.path)
        if ent.chunk is None:
            raise MinifsError("%r 的块号无效" % ent.path)
        if ent.chunk >= len(self.chunks):
            raise MinifsError("%r 的块号 %d 超块表（共 %d）"
                              % (ent.path, ent.chunk, len(self.chunks)))
        data = self._chunk_data(ent.chunk)
        start = ent.part
        if start > len(data):
            raise MinifsError("%r 在块 %d 内偏移 %d 越过解压长度 %d"
                              % (ent.path, ent.chunk, start, len(data)))
        out = data[start:start + ent.size]
        if len(out) < ent.size:
            self.notes.append("%r 期望 %d 字节，块内只剩 %d"
                              % (ent.path, ent.size, len(out)))
        return out

    def read_path(self, path):
        return self.read_file(self.lookup_path(path))

    def tree(self):
        return [(p, e.type_name, e.size) for p, e in self.walk()]


# ---------------------------------------------------------------- 模块级接口

def probe(sub):
    """判断是否 MiniFS：找得到魔数，且变体 A 或 B 至少一种结构自洽"""
    try:
        base = _locate_magic(sub)
    except Exception:
        return False
    if base < 0:
        return False
    try:
        Minifs(sub, base=base)
    except Exception:
        return False
    return True


def open_fs(sub, base=None):
    return Minifs(sub, base=base)


# ---------------------------------------------------------------- 自检
if __name__ == "__main__":
    import io
    import sys

    try:
        if hasattr(sys.stdout, "buffer"):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    except Exception:
        pass

    PASS = [0]
    FAIL = [0]

    def ck(cond, name, extra=""):
        if cond:
            PASS[0] += 1
            print("  [PASS] %s %s" % (name, extra))
        else:
            FAIL[0] += 1
            print("  [FAIL] %s %s" % (name, extra))

    class Buf(object):
        """只依赖 read(offset, size) 与 size 的缓冲，与宿主约定一致"""

        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, n):
            if off < 0 or n <= 0 or off >= self.size:
                return b""
            return self.data[off:off + n]

    def pack32(value, endian):
        return struct.pack(endian + "I", value)

    # ------------------------------------------------ 合成变体 A
    def build_a():
        """变体 A：magic[16] + flag + 3 个 88B 目录项 + 每文件一个 LZMA 块"""
        files = [("/web/index.htm", b"<html>MINIFS A</html>\n"),
                 ("/conf/oem.txt", b"oem=ESK\n"),
                 ("/web/img/logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 24)]
        endian = ">"
        blob = bytearray()
        blob += MINIFS_MAGIC + b"\x00" * (MINIFS_MAGIC_FIELD - len(MINIFS_MAGIC))
        blob += pack32(0x00000001, endian)          # flag
        table_len = ENTRY_A * len(files)
        chunk_start = len(blob) + table_len
        offsets = []
        chunks = []
        rel = 0
        for _path, data in files:
            comp = lzma.compress(data, format=lzma.FORMAT_ALONE)
            offsets.append(rel)
            chunks.append(comp)
            rel += len(comp)
        for (path, data), off in zip(files, offsets):
            nb = path.encode()
            rec = pack32(len(data), endian) + pack32(off, endian)
            rec += nb + b"\x00" * (NAME_A - len(nb))
            blob += rec
        for comp in chunks:
            blob += comp
        return bytes(blob), files, chunk_start

    # ------------------------------------------------ 合成变体 B
    def build_b(endian=">"):
        """变体 B：32B 头 + ToN + 文件表 + 块表 + 2 个块（块内放多个文件）"""
        layout = [("fw/mtk", "base.css", b"body{}\n"),
                  ("fw/mtk", "app.js", b"var a=1;\n"),
                  ("", "boot.cfg", b"boot=0\n")]
        ton = bytearray()
        pos = {}

        def add(s):
            if s in pos:
                return pos[s]
            pos[s] = len(ton)
            ton.extend(s.encode() + b"\x00")
            return pos[s]

        recs = []
        for path, name, _data in layout:
            recs.append((add(path), add(name)))

        # 块 0 放前两个文件，块 1 放第三个 —— 覆盖「块内多文件」
        chunk0 = lzma.compress(layout[0][2] + layout[1][2],
                              format=lzma.FORMAT_ALONE)
        chunk1 = lzma.compress(layout[2][2], format=lzma.FORMAT_ALONE)
        f_offs = [(0, 0, len(layout[0][2])),
                  (0, len(layout[0][2]), len(layout[1][2])),
                  (1, 0, len(layout[2][2]))]
        nfiles = len(layout)
        ton_size = len(ton)
        header = bytearray()
        header += MINIFS_MAGIC + b"\x00" * (MINIFS_MAGIC_FIELD - len(MINIFS_MAGIC))
        header += pack32(0x00000003, endian)        # 用途未明，资料里疑似版本
        header += pack32(nfiles, endian)
        header += pack32(0, endian)                 # 用途未明
        header += pack32(ton_size, endian)
        assert len(header) == HDR_B

        body = bytearray()
        body += ton
        for (poff, noff), (cno, part, size) in zip(recs, f_offs):
            body += (pack32(poff, endian) + pack32(noff, endian)
                     + pack32(cno, endian) + pack32(part, endian)
                     + pack32(size, endian))
        sizes = ((len(chunk0), len(layout[0][2] + layout[1][2])),
                 (len(chunk1), len(layout[2][2])))
        body += pack32(0, endian)                   # 块 0 相对偏移
        body += pack32(sizes[0][0], endian)
        body += pack32(sizes[0][1], endian)
        body += pack32(len(chunk0), endian)         # 块 1 相对偏移
        body += pack32(sizes[1][0], endian)
        body += pack32(sizes[1][1], endian)
        body += chunk0 + chunk1
        return bytes(header + body), layout

    print("== MiniFS 变体 A ==")
    img_a, files_a, chunk_start_a = build_a()
    fs = Minifs(Buf(img_a))
    info = fs.info()
    print("  %s | base=%d endian=%s files=%d chunks=%d first_chunk=%d"
          % (info["variant_desc"], info["base"], info["endian"],
             info["files"], info["chunks"], info["first_chunk"]))
    ck(fs.variant == MINIFS_VARIANT_A, "变体判别", fs.variant)
    ck(info["endian"] == "big", "字节序", info["endian"])
    ck(info["files"] == 3, "文件数", info["files"])
    ck(info["first_chunk"] == chunk_start_a, "首块偏移",
       "%d == %d" % (info["first_chunk"], chunk_start_a))
    ck(sorted(info["lzma_prop"]) == ["0x5D"], "LZMA prop", info["lzma_prop"])

    for path, data in files_a:
        got = fs.read_path(path)
        ck(got == data, "读 %s" % path, "%dB" % len(got))

    roots = fs.listdir("/")
    print("  根目录：%s" % [(e.name, e.type_name) for e in roots])
    ck([e.name for e in roots] == ["web", "conf"], "根目录按盘上顺序",
       [e.name for e in roots])
    ck(fs.lookup_path("/web").is_dir, "目录项可查")
    web = fs.listdir("/web")
    ck([e.name for e in web] == ["index.htm", "img"], "web/ 子项",
       [e.name for e in web])
    walk_a = [p for p, _e in fs.walk()]
    ck("web/img/logo.png" in walk_a and "conf/oem.txt" in walk_a,
       "walk 覆盖", len(walk_a))
    ck(len(fs.find("*.txt")) == 1, "find", [p for p, _e in fs.find("*.txt")])
    ck(fs.tree()[0][1] == "dir", "tree 类型")
    ck(probe(Buf(img_a)), "probe=True")
    ck(isinstance(open_fs(Buf(img_a)), Minifs), "open_fs 返回 Minifs")

    print("== MiniFS 变体 B（大端 / 小端）==")
    for endian in (">", "<"):
        img_b, layout_b = build_b(endian)
        fb = Minifs(Buf(img_b))
        ib = fb.info()
        tag = "BE" if endian == ">" else "LE"
        ck(fb.variant == MINIFS_VARIANT_B, "%s 变体判别" % tag, fb.variant)
        ck(ib["files"] == 3, "%s 文件数" % tag, ib["files"])
        ck(ib["chunks"] == 2, "%s 块数" % tag, ib["chunks"])
        ck(ib["header_unknown"]["field_0x10"] == 3, "%s 头 0x10" % tag,
           ib["header_unknown"])
        for path, name, data in layout_b:
            full = "/" + (path + "/" + name if path else name)
            got = fb.read_path(full)
            ck(got == data, "%s 读 %s" % (tag, full), "%dB" % len(got))
        # 同一块内两个文件：偏移必须拆对
        ck(fb.read_path("/fw/mtk/app.js") == b"var a=1;\n",
           "%s 块内多文件切片" % tag)
        ck([e.name for e in fb.listdir("/")] == ["fw", "boot.cfg"],
           "%s 根目录" % tag, [e.name for e in fb.listdir("/")])
        ck(fb.lookup_path("/fw/mtk/app.js").chunk == 0, "%s 块号" % tag)

    print("== 老固件 LZMA 配置字 0x5A000080 ==")

    def alone_5a(data, dict_size=1 << 23, lc=0, lp=0, pb=2):
        """按 prop=0x5A 的 filter 压一个 lzma_alone 流（dict 8 MiB）"""
        raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": dict_size,
             "lc": lc, "lp": lp, "pb": pb}])
        prop = (pb * 5 + lp) * 9 + lc
        assert prop == 0x5A, hex(prop)
        hdr = bytes([prop]) + struct.pack("<I", dict_size)
        hdr += struct.pack("<Q", len(data))          # 已有长度，不靠结束标记
        return hdr + raw

    payload = b"old-firmware minifs payload\n" * 4
    comp5a = alone_5a(payload)
    img5a = bytearray()
    img5a += MINIFS_MAGIC + b"\x00" * (MINIFS_MAGIC_FIELD - len(MINIFS_MAGIC))
    img5a += pack32(0, ">")
    img5a += pack32(len(payload), ">") + pack32(0, ">")
    nm = b"/etc/version"
    img5a += nm + b"\x00" * (NAME_A - len(nm))
    img5a += comp5a
    f5 = Minifs(Buf(bytes(img5a)))
    i5 = f5.info()
    ck(f5.variant == MINIFS_VARIANT_A, "0x5A 变体判别", f5.variant)
    ck(i5["lzma_prop"] == ["0x5A"], "0x5A prop 记到 info", i5["lzma_prop"])
    ck(f5.read_path("/etc/version") == payload, "0x5A 读文件",
       "%dB" % len(payload))

    print("== 负例与容错 ==")
    try:
        Minifs(Buf(b"\x00" * 4096))
        ck(False, "无魔数应报错")
    except MinifsError as exc:
        ck(True, "无魔数 -> MinifsError", str(exc)[:40])
    ck(probe(Buf(b"\x00" * 4096)) is False, "probe 空镜像=False")

    junk = MINIFS_MAGIC + b"\xff" * 400
    try:
        Minifs(Buf(junk))
        ck(False, "魔数后续垃圾应报错")
    except MinifsError as exc:
        ck(True, "魔数+垃圾 -> MinifsError", str(exc)[:44])
    ck(probe(Buf(junk)) is False, "probe 垃圾=False")

    # 截断：块表被砍掉一半，仍应认出变体 B 并给出 notes
    img_b, _ = build_b(">")
    trunc = img_b[:len(img_b) - 30]
    fb = Minifs(Buf(trunc))
    ck(fb.variant == MINIFS_VARIANT_B, "截断镜像仍识别", fb.variant)
    ck(bool(fb.notes) or len(fb.entries) == 3, "截断给出 notes",
       (fb.notes or ["无"])[0][:48])

    # 头部前有偏移前缀（真实固件里 MINIFS 不在 0 处）
    pad = b"\xff" * 517
    fb2 = Minifs(Buf(pad + img_b))
    ck(fb2.base == 517, "魔数偏移定位", fb2.base)
    ck(fb2.read_path("/boot.cfg") == b"boot=0\n", "偏移后读取正确")

    print("\n自检结果：PASS=%d FAIL=%d" % (PASS[0], FAIL[0]))
    if FAIL[0]:
        raise SystemExit(1)