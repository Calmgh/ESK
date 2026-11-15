# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""归档与逻辑包解析：TAR 家族 / 7z / Docker-OCI / BCP / 小米 .bak

已实现：
    · TAR / TAR.GZ / TAR.BZ2 / TAR.XZ：标准库 tarfile 流式读头（ustar / GNU /
      PAX 三套头均走同一条 _Stream 路径），成员真实偏移 offset（头）与
      offset_data（数据），同名成员全量保留并标 duplicate / duplicate_of /
      superseded / supersedes —— 取证上"被覆盖的旧版本"必须能看见
    · 7z 只读解码：signature header（StartHeaderCRC 校验）、NextHeader 的
      7z property ID 编码、kEncodedHeader 解压后的真头、PackInfo / UnPackInfo /
      SubStreamsInfo / FilesInfo 全属性位；Folder coder 链 Copy / LZMA / LZMA2 /
      BCJ(x86,PPC,IA64,ARM,ARMT,SPARC) / Delta；solid 块内子流切分；
      UTF-16LE 名、FILETIME 时间戳、Windows 属性、kEmptyStream / kEmptyFile / kAnti
    · Docker save 与 OCI image layout（两者都是 tar 或目录）：manifest.json 与
      index.json + oci-layout 双路径，逐层 tar（含 gzip 层），`.wh.<name>`
      whiteout 与 `.wh..wh..opq` opaque 目录语义；每层变更类型 add / modify /
      delete / opaque 单独留存，最终视图与逐层视图都能取；config.history
    · BCP（SQL Server bcp / BULK INSERT 交换数据）：.fmt 描述驱动（10.0 等版本、
      宿主列序 vs 文件列序、前缀长度、字段终止符、行终止符、NULL 终止符），
      字符模式与原生模式，char/varchar/nchar/nvarchar/int/bigint/smallint/
      tinyint/bit/real/float/money/datetime/decimal 转换；无 .fmt 时启发式
      探测分隔符并推断列类型（标 inferred=True）
    · 小米 .bak：容器探明（tar / 前置头 zip / gzip），descriptor.xml 与
      apps/<pkg> 枚举，password / encrypt 字段检出即拒解

不实现：
    · TAR：GNU sparse 内容重组（1.0 与 0.1 稀疏映射只识别并抛
      NotImplementedError）；zstd 压缩的 tar（3.11 标准库无 zstd）；多卷/增量 tar
    · 7z：写；BCJ2 / PPMd / Deflate64 解码；**AES-256 加密明确抛
      NotImplementedError**（缺的是：SHA-256 迭代 KDF + AES-256-CBC 解密器，
      标准库无 AES，mkit.aes 只有 ECB/CTR 原语且未接 CBC 迭代密钥派生）；
      分卷 .7z.001；损坏头的修复复用
    · Docker / OCI：zstd 层、非 tar 的 layer 媒体类型（如 squashfs 快照）、
      registry 远端拉取、镜像构建；`.wh.` 的白化只按 OverlayFS 语义处理，
      不解释 aufs 的 `.wh..wh.plnk` / `.wh..wh.aufs` 元文件为真实文件
    · BCP：`-w` Unicode 原生模式的全宽度推导（nchar 按 2 字节定长算，不做
      N 前缀 UCSUCS2 全类型表）、sql_variant / UDT / geometry / hierarchyid、
      XML 格式化器、代码页自动识别（仅 utf-8 → latin-1 回退）
    · 小米 .bak：加密备份解密；MIUI 私有二进制头的字段级解释（只做容器探明
      与目录枚举）

口径说明：
    · 每个类只依赖 read(offset, size) + size，可直接喂 mkit.image.Image /
      mkit.image.SubImage，也可直接喂路径字符串
    · 压缩归档（.tar.gz / .tar.bz2 / .tar.xz）的 offset 是「解压后流内偏移」，
      与磁盘字节偏移不同，summary()["offset_basis"] 已标注
    · 自检里 7z 优先调用本机 7-Zip 生成真样本（LZMA1 / LZMA2 / Copy / solid /
      BCJ+LZMA2 / AES 全走一遍）；找不到可执行文件时只跑手工构造的 Copy 编码
      极简 7z，并在自检输出里写明「LZMA 路径未用真实样本验证」
"""

import bz2
import datetime
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zipfile
import zlib

__all__ = [
    "probe", "open_archive",
    "TarArchive", "TarMember", "SevenZip", "DockerImage", "BcpFile",
    "MiuiBak", "BcpSpec", "BcpColumn",
    "SEVENZ_SIG", "HDR_IDS", "CODER_IDS", "TAR_COMPRESSION_MAGIC",
    "OPAQUE_WHITEOUT",
]

WATERMARK = "ESK by Calmgh06"

# ---------------- 通用小工具 ----------------


class _Rec(object):
    """既可按属性访问又可按键访问的记录（统一 info()/layers() 的返回形态）。"""

    __slots__ = ("_d",)

    def __init__(self, **kw):
        object.__setattr__(self, "_d", kw)

    def __setattr__(self, k, v):
        self._d[k] = v

    def __delattr__(self, k):
        self._d.pop(k, None)

    def __getattr__(self, k):
        try:
            return self._d[k]
        except KeyError:
            raise AttributeError(k)

    def __getitem__(self, k):
        return self._d[k]

    def get(self, k, default=None):
        return self._d.get(k, default)

    def __contains__(self, k):
        return k in self._d

    def keys(self):
        return list(self._d.keys())

    def items(self):
        return list(self._d.items())

    def as_dict(self):
        return dict(self._d)

    def __repr__(self):
        bits = []
        for k in ("name", "path", "index", "size", "type", "change"):
            if k in self._d:
                bits.append("%s=%r" % (k, self._d[k]))
        return "<%s %s>" % (type(self).__name__, " ".join(bits))


class _Blob(object):
    """统一只读字节视图：路径 / 带 read(offset,size)+size 的对象。"""

    def __init__(self, src):
        self.path = None
        self._fh = None
        self._obj = None
        self._owned = False
        if isinstance(src, (str, bytes, os.PathLike)):
            self.path = os.path.abspath(os.fsdecode(src))
            self._fh = open(self.path, "rb")
            self.size = os.fstat(self._fh.fileno()).st_size
            self._owned = True
        elif hasattr(src, "read") and hasattr(src, "size"):
            self._obj = src
            self.size = int(src.size)
        else:
            raise TypeError("需要路径或带 read(offset,size)+size 的视图对象，收到 %r"
                            % (type(src),))

    @property
    def readable(self):
        return True

    def read(self, offset, size):
        if size <= 0 or offset < 0 or offset >= self.size:
            return b""
        size = min(size, self.size - offset)
        if self._fh is not None:
            self._fh.seek(offset)
            data = self._fh.read(size)
            while len(data) < size:
                more = self._fh.read(size - len(data))
                if not more:
                    break
                data += more
            return data
        return self._obj.read(offset, size)

    def close(self):
        if self._owned and self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class _SeqFile(io.RawIOBase):
    """把 (read(offset,size)+size) 视图包成可 seek 的文件对象，供 tarfile/zipfile 用。"""

    def __init__(self, blob, base=0):
        io.RawIOBase.__init__(self)
        self._blob = blob
        self._base = base
        self._pos = 0
        self._len = max(0, blob.size - base)

    def readable(self):
        return True

    def seekable(self):
        return True

    def writable(self):
        return False

    def tell(self):
        return self._pos

    def seek(self, offset, whence=0):
        if whence == 0:
            pos = offset
        elif whence == 1:
            pos = self._pos + offset
        elif whence == 2:
            pos = self._len + offset
        else:
            raise ValueError("whence 非 0/1/2")
        pos = max(0, min(int(pos), self._len))
        self._pos = pos
        return self._pos

    def read(self, size=-1):
        if size is None or size < 0:
            size = self._len - self._pos
        size = min(size, self._len - self._pos)
        if size <= 0:
            return b""
        data = self._blob.read(self._base + self._pos, size)
        self._pos += len(data)
        return data

    def readinto(self, buf):
        data = self.read(len(buf))
        buf[:len(data)] = data
        return len(data)


def _crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def _filetime_to_dt(value):
    """Windows FILETIME（1601 起 100ns）→ UTC datetime。"""
    if not value:
        return None
    secs = value / 10000000.0 - 11644473600.0
    try:
        return datetime.datetime.utcfromtimestamp(secs).replace(
            tzinfo=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _iso(dt):
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


# ---------------- TAR ----------------


TAR_COMPRESSION_MAGIC = (
    ("gzip", b"\x1f\x8b"),
    ("bzip2", b"BZh"),
    ("xz", b"\xfd7zXZ\x00"),
    ("zstd", b"\x28\xb5\x2f\xfd"),
)

_TAR_TYPE_NAMES = {
    tarfile.REGTYPE: "file",
    tarfile.AREGTYPE: "file",
    tarfile.LNKTYPE: "hardlink",
    tarfile.SYMTYPE: "symlink",
    tarfile.CHRTYPE: "chardev",
    tarfile.BLKTYPE: "blockdev",
    tarfile.DIRTYPE: "dir",
    tarfile.FIFOTYPE: "fifo",
    tarfile.CONTTYPE: "cont",
    tarfile.GNUTYPE_SPARSE: "sparse",
}


def _tar_compression(blob):
    """按魔数判断 tar 的压缩方式。"""
    head = blob.read(0, 6)
    for name, magic in TAR_COMPRESSION_MAGIC:
        if head[:len(magic)] == magic:
            return name
    return None


def _is_tar_header(block):
    """512 字节块的 tar 头校验（全零块视为合法结束标记）。"""
    if len(block) < 512:
        return False
    if block == b"\x00" * 512:
        return True
    chksum = block[148:156]
    try:
        want = int(chksum.split(b"\x00")[0].strip() or b"0", 8)
    except ValueError:
        return False
    body = block[:148] + b" " * 8 + block[156:]
    unsigned = sum(body) & 0xFFFFFFFF
    signed = sum(b - 256 if b > 127 else b for b in body) & 0xFFFFFFFF
    return want in (unsigned, signed)


def _open_tar_stream(blob, compression):
    """把 blob 包成（解压后的）可 seek 流。"""
    raw = _SeqFile(blob)
    if compression is None:
        return raw
    if compression == "gzip":
        return gzip.GzipFile(fileobj=raw, mode="rb")
    if compression == "bzip2":
        return bz2.BZ2File(raw, mode="rb")
    if compression == "xz":
        return lzma.LZMAFile(raw, mode="rb")
    if compression == "zstd":
        raise NotImplementedError(
            "tar.zst：Python 3.11 标准库无 zstd 解压（3.14 才有 compression.zstd），"
            "本模块不引入第三方依赖")
    raise NotImplementedError("未知 tar 压缩: %r" % (compression,))


class TarMember(_Rec):
    """tar 成员记录。字段：name/size/mtime/uid/gid/mode/type/offset/duplicate…"""

    __slots__ = ()


class TarArchive(object):
    """TAR / TAR.GZ / TAR.BZ2 / TAR.XZ 只读访问（含重复成员取证标记）。

    members 按归档顺序全量保留；每条带：
        index       1 起的成员序号
        name        成员名（PAX/GNU 长名已还原）
        size        数据长度
        mtime       Unix 秒；mtime_iso 为 UTC 文本
        uid / gid / uname / gname
        mode        权限位（八进制值）
        type        file / dir / symlink / hardlink / fifo / chardev / blockdev / sparse
        offset      成员头在归档内的偏移
        offset_data 成员数据起始偏移
        duplicate   是否为同名成员的后写副本
        duplicate_of 首个同名成员序号（非重复为 None）
        superseded  本条是否已被后续同名成员取代（失效副本）
        supersedes  本条取代了哪些更早的序号（仅存活副本非空）
    """

    def __init__(self, src, compression="auto"):
        self._blob = _Blob(src)
        self.path = self._blob.path
        if compression == "auto":
            self.compression = _tar_compression(self._blob)
        else:
            self.compression = compression
        self.truncated = False
        self.members = []
        self._scan()
        self._mark_duplicates()

    # ---- 扫描 ----
    def _scan(self):
        stream = _open_tar_stream(self._blob, self.compression)
        try:
            tf = tarfile.open(fileobj=stream, mode="r|",
                              encoding="utf-8", errors="surrogateescape")
        except tarfile.ReadError:
            # 前面若干字节可能是自定义包壳（如小米 .bak），尝试跳过
            head = self._blob.read(0, 1 << 16)
            pos = head.find(b"ustar")
            if pos < 0:
                raise
            start = max(0, pos - 257)
            stream.close()
            stream = _SeqFile(self._blob, base=start)
            tf = tarfile.open(fileobj=stream, mode="r|",
                              encoding="utf-8", errors="surrogateescape")
            self.prefix_offset = start
        else:
            self.prefix_offset = 0
        while True:
            try:
                ti = tf.next()
            except (tarfile.ReadError, EOFError, OSError):
                self.truncated = True
                break
            except lzma.LZMAError:
                self.truncated = True
                break
            if ti is None:
                break
            self.members.append(self._make_member(ti))
        try:
            tf.close()
        except Exception:
            pass
        try:
            stream.close()
        except Exception:
            pass

    def _make_member(self, ti):
        mtime = ti.mtime
        mt = None
        try:
            mt = datetime.datetime.utcfromtimestamp(mtime).replace(
                tzinfo=datetime.timezone.utc)
        except (OverflowError, OSError, ValueError, TypeError):
            pass
        return TarMember(
            index=len(self.members) + 1,
            name=ti.name,
            size=int(ti.size or 0),
            mtime=mtime,
            mtime_iso=_iso(mt),
            uid=ti.uid,
            gid=ti.gid,
            uname=ti.uname,
            gname=ti.gname,
            mode=ti.mode,
            type=_TAR_TYPE_NAMES.get(ti.type, "unknown:%r" % (ti.type,)),
            offset=int(ti.offset or 0),
            offset_data=int(ti.offset_data or 0),
            linkname=ti.linkname,
            is_dir=ti.isdir(),
            is_file=ti.isfile(),
            is_symlink=ti.issym(),
            is_sparse=bool(getattr(ti, "sparse", None)),
            duplicate=False,
            duplicate_of=None,
            superseded=False,
            supersedes=[],
            live=True,
        )

    def _mark_duplicates(self):
        first = {}
        last = {}
        for m in self.members:
            if m.name in first:
                m.duplicate = True
                m.duplicate_of = first[m.name]
            else:
                first[m.name] = m.index
                m.duplicate_of = None
            last[m.name] = m.index
        for m in self.members:
            if last[m.name] != m.index:
                m.superseded = True
                m.live = False
            else:
                m.supersedes = [x.index for x in self.members
                                if x.name == m.name and x.index != m.index]
                if m.supersedes:
                    m.duplicate = True
                    m.duplicate_of = m.supersedes[0]

    # ---- 统一接口 ----
    def names(self):
        return [m.name for m in self.members]

    def live_names(self):
        """按归档顺序给出仍生效（未被后续同名成员取代）的成员名。"""
        return [m.name for m in self.members if m.live]

    def info(self, name):
        """返回该名最后写入的成员（tar 语义：后者覆盖前者）。"""
        hit = None
        for m in self.members:
            if m.name == name:
                hit = m
        if hit is None:
            raise KeyError(name)
        return hit

    def info_all(self, name):
        return [m for m in self.members if m.name == name]

    def read(self, name, occurrence=None):
        """读成员内容。occurrence=None 读最后写入的副本，1 起可指定副本序号。"""
        if occurrence is None:
            cand = [m for m in self.members if m.name == name]
            if not cand:
                raise KeyError(name)
            m = cand[-1]
        else:
            cand = self.info_all(name)
            if not 1 <= occurrence <= len(cand):
                raise KeyError("%s #%d（共 %d 份）" % (name, occurrence, len(cand)))
            m = cand[occurrence - 1]
        return self.read_member(m)

    def read_member(self, m):
        if m.is_dir:
            return b""
        if m.is_sparse:
            raise NotImplementedError(
                "GNU sparse 成员 %r：稀疏映射未重组（需要用 GNU 稀疏扩展头里的"
                " map 表逐段拼接，本模块只保留偏移不还原空洞内容）" % (m.name,))
        stream = _open_tar_stream(self._blob, self.compression)
        try:
            stream.seek(m.offset_data)
            want = m.size
            out = b""
            while len(out) < want:
                chunk = stream.read(min(1 << 20, want - len(out)))
                if not chunk:
                    break
                out += chunk
            return out
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def walk(self, live_only=False):
        for m in self.members:
            if live_only and not m.live:
                continue
            yield m.name, m

    def summary(self):
        dup = [m for m in self.members if m.superseded]
        return {
            "format": "tar",
            "path": self.path,
            "compression": self.compression,
            "offset_basis": ("文件内偏移（未压缩）" if self.compression is None
                             else "解压后流内偏移（%s）" % self.compression),
            "prefix_offset": getattr(self, "prefix_offset", 0),
            "members": len(self.members),
            "live_members": sum(1 for m in self.members if m.live),
            "duplicate_members": len(dup),
            "duplicate_names": sorted({m.name for m in dup}),
            "dirs": sum(1 for m in self.members if m.is_dir),
            "truncated": self.truncated,
            "size": self._blob.size,
        }

    def close(self):
        self._blob.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __len__(self):
        return len(self.members)


# ---------------- 7z ----------------


SEVENZ_SIG = b"7z\xbc\xaf\x27\x1c"

# 7z property ID（7zFormat.txt）。注意：kEnd 是 0x00，kHeader 是 0x01，
# 与"签名后紧跟的 6 字节"无关；网上常见的 0x01=kEnd 偏移表是错的。
HDR_IDS = {
    "kEnd": 0x00,
    "kHeader": 0x01,
    "kArchiveProperties": 0x02,
    "kAdditionalStreamsInfo": 0x03,
    "kMainStreamsInfo": 0x04,
    "kFilesInfo": 0x05,
    "kPackInfo": 0x06,
    "kUnPackInfo": 0x07,
    "kSubStreamsInfo": 0x08,
    "kSize": 0x09,
    "kCRC": 0x0A,
    "kFolder": 0x0B,
    "kCodersUnPackSize": 0x0C,
    "kNumUnPackStream": 0x0D,
    "kEmptyStream": 0x0E,
    "kEmptyFile": 0x0F,
    "kAnti": 0x10,
    "kName": 0x11,
    "kCTime": 0x12,
    "kATime": 0x13,
    "kMTime": 0x14,
    "kWinAttrib": 0x15,
    "kComment": 0x16,
    "kEncodedHeader": 0x17,
    "kStartPos": 0x18,
    "kDummy": 0x19,
}

K_END = 0x00
K_HEADER = 0x01
K_ARCHIVE_PROPS = 0x02
K_ADDITIONAL_STREAMS = 0x03
K_MAIN_STREAMS = 0x04
K_FILES_INFO = 0x05
K_PACK_INFO = 0x06
K_UNPACK_INFO = 0x07
K_SUBSTREAMS_INFO = 0x08
K_SIZE = 0x09
K_CRC = 0x0A
K_FOLDER = 0x0B
K_CODERS_UNPACK_SIZE = 0x0C
K_NUM_UNPACK_STREAM = 0x0D
K_EMPTY_STREAM = 0x0E
K_EMPTY_FILE = 0x0F
K_ANTI = 0x10
K_NAME = 0x11
K_CTIME = 0x12
K_ATIME = 0x13
K_MTIME = 0x14
K_WIN_ATTRIB = 0x15
K_COMMENT = 0x16
K_ENCODED_HEADER = 0x17
K_START_POS = 0x18
K_DUMMY = 0x19

M_COPY = 0x00
M_DELTA = 0x03
M_LZMA = 0x030101
M_LZMA2 = 0x21
M_PPMD = 0x030401
M_BCJ = 0x03030103
M_BCJ2 = 0x0303011B
M_PPC = 0x03030205
M_IA64 = 0x03030401
M_ARM = 0x03030501
M_ARMT = 0x03030701
M_SPARC = 0x03030805
M_DEFLATE = 0x040108
M_DEFLATE64 = 0x040109
M_BZIP2 = 0x040202
M_AES = 0x06F10701

CODER_IDS = {
    M_COPY: "Copy",
    M_DELTA: "Delta",
    M_LZMA: "LZMA",
    M_LZMA2: "LZMA2",
    M_PPMD: "PPMd",
    M_BCJ: "BCJ",
    M_BCJ2: "BCJ2",
    M_PPC: "PPC",
    M_IA64: "IA64",
    M_ARM: "ARM",
    M_ARMT: "ARMT",
    M_SPARC: "SPARC",
    M_DEFLATE: "Deflate",
    M_DEFLATE64: "Deflate64",
    M_BZIP2: "BZip2",
    M_AES: "AES-256",
}

# 7z BCJ 家族 → 标准库 lzma 的 raw 过滤器
_BCJ_FILTERS = {
    M_BCJ: lzma.FILTER_X86,
    M_PPC: lzma.FILTER_POWERPC,
    M_IA64: lzma.FILTER_IA64,
    M_ARM: lzma.FILTER_ARM,
    M_ARMT: lzma.FILTER_ARMTHUMB,
    M_SPARC: lzma.FILTER_SPARC,
}


class _R(object):
    """7z 头字节游标：可变长整数 + 位向量 + 摘要表。"""

    def __init__(self, buf, pos=0):
        self.b = buf
        self.p = pos

    def left(self):
        return len(self.b) - self.p

    def byte(self):
        if self.p >= len(self.b):
            raise EOFError("7z 头意外结束（偏移 %d/%d）" % (self.p, len(self.b)))
        v = self.b[self.p]
        self.p += 1
        return v

    def take(self, n):
        if n < 0 or self.p + n > len(self.b):
            raise EOFError("7z 头需要 %d 字节，只剩 %d" % (n, len(self.b) - self.p))
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def number(self):
        """7z 可变长整数：首字节高位表示后续字节数，其余位是高位数据。"""
        first = self.byte()
        mask = 0x80
        value = 0
        for i in range(8):
            if first & mask == 0:
                value |= (first & (mask - 1)) << (i * 8)
                return value
            value |= self.byte() << (i * 8)
            mask >>= 1
        return value

    def bitvector(self, n):
        out = []
        cur = 0
        for i in range(n):
            if i % 8 == 0:
                cur = self.byte()
            out.append(bool(cur & (0x80 >> (i % 8))))
        return out

    def digests(self, count):
        """Digests 段：AllAreDefined + 可选位图 + 4 字节 CRC。

        注意：这段**没有**自带的数量字段，数量由上下文（PackInfo 的包流数、
        UnPackInfo 的 folder 数、SubStreamsInfo 的子流数）给出。7z.exe 实际
        产出的头里紧跟 kCRC 的是 AllAreDefined 字节，不是 NumDigests。
        """
        if count == 0:
            return []
        defined = self.byte()
        bits = [True] * count if defined else self.bitvector(count)
        return [self.u32() if b else None for b in bits]


class _Folder(object):
    """7z Folder：一组 coder 串成的解码链（本模块只支持 1 进 1 出的线性链）。"""

    __slots__ = ("coders", "bind_pairs", "packed_in", "unpack_sizes", "crc",
                 "flow", "pack_indices")

    def __init__(self):
        self.coders = []
        self.bind_pairs = []
        self.packed_in = []
        self.unpack_sizes = []
        self.crc = None
        self.flow = []
        self.pack_indices = []

    @property
    def final_size(self):
        if not self.unpack_sizes or not self.flow:
            return 0
        return self.unpack_sizes[self.flow[-1]]

    def methods(self):
        return [self.coders[i]["method"] for i in self.flow]

    def method_names(self):
        return [CODER_IDS.get(m, "0x%X" % m) for m in self.methods()]

    @property
    def is_encrypted(self):
        return any(c["method"] == M_AES for c in self.coders)

    def __repr__(self):
        return "<_Folder %s size=%d>" % ("+".join(self.method_names()),
                                         self.final_size)


def _lzma_props(props):
    """LZMA(LZMA1) coder 属性 5 字节 → lzma raw 过滤器参数。"""
    if len(props) < 5:
        raise ValueError("LZMA 属性长度 %d < 5" % len(props))
    b0 = props[0]
    lc = b0 % 9
    lp = (b0 // 9) % 5
    pb = b0 // 45
    dict_size = struct.unpack("<I", props[1:5])[0]
    return {"id": lzma.FILTER_LZMA1, "dict_size": max(dict_size, 4096),
            "lc": lc, "lp": lp, "pb": pb}


def _lzma2_props(props):
    """LZMA2 coder 属性 1 字节 → 字典大小。"""
    p = props[0] if props else 40
    if p > 40:
        raise ValueError("LZMA2 字典属性非法: %d" % p)
    dict_size = (2 | (p & 1)) << (p // 2 + 11)
    return {"id": lzma.FILTER_LZMA2, "dict_size": dict_size}


def _raw_lzma_decode(data, filters):
    """lzma raw 解码；7z 的 LZMA1 常无结束标记，按"取到无输入为止"处理。"""
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    out = bytearray()
    pos = 0
    step = 1 << 20
    while True:
        chunk = data[pos:pos + step]
        pos += len(chunk)
        if chunk:
            out += dec.decompress(chunk)
        if dec.eof or (not chunk and dec.needs_input):
            break
        if not chunk and not dec.needs_input:
            break
    return bytes(out)


class SevenZip(object):
    """7z 只读解码器（无第三方依赖）。

    info(name) 字段：name / size / crc（十六进制串）/ packed_size / is_dir /
    is_encrypted / mtime / attributes / folder / solid / anti。
    solid 块的 packed_size 只记在块内第一个文件上，其余为 None（避免重复计数）。
    """

    def __init__(self, src):
        self._blob = _Blob(src)
        self.path = self._blob.path
        head = self._blob.read(0, 32)
        if head[:6] != SEVENZ_SIG:
            raise ValueError("不是 7z：signature=%r" % (head[:6],))
        self.version = (head[6], head[7])
        start_crc = struct.unpack_from("<I", head, 8)[0]
        calc = _crc32(head[12:32])
        if calc != start_crc:
            raise ValueError("7z StartHeaderCRC 不符：文件 %08X，计算 %08X"
                             % (start_crc, calc))
        self.next_offset, self.next_size, self.next_crc = struct.unpack_from(
            "<QQI", head, 12)
        self.start_header_crc_ok = True
        self.header_crc_ok = None
        self.header_encoded = False
        self.streams = None
        self.files = []
        self._folder_cache = {}
        self.raw_next_header = b""
        self.physical_size = self._blob.size
        if self.next_size:
            nh = self._blob.read(32 + self.next_offset, self.next_size)
            if len(nh) != self.next_size:
                raise ValueError("NextHeader 被截断：要 %d 字节，得 %d"
                                 % (self.next_size, len(nh)))
            self.header_crc_ok = (_crc32(nh) == self.next_crc)
            self.raw_next_header = nh
            self._parse_next_header(nh)

    # ---- 头解析 ----
    def _parse_next_header(self, buf):
        r = _R(buf)
        pid = r.byte()
        if pid == K_ENCODED_HEADER:
            self.header_encoded = True
            streams = self._read_streams_info(r)
            if self._streams_encrypted(streams):
                raise NotImplementedError(
                    "7z 头已加密（AES-256）：无法枚举成员名。缺的是 AES-256-CBC "
                    "解密器 + 7z 的 SHA-256 迭代 KDF（标准库无 AES，mkit.aes 的 "
                    "ECB/CTR 原语未接 7z 的 CBC 迭代密钥派生）")
            data = self._decode_streams(streams)[0]
            if not data:
                raise ValueError("7z 编码头解码为空")
            self.header_bytes = data
            r = _R(data)
            pid = r.byte()
        if pid != K_HEADER:
            raise ValueError("7z 头首字节应为 kHeader(0x01)，实际 0x%02X" % pid)
        self._parse_header(r)

    def _parse_header(self, r):
        while True:
            pid = r.byte()
            if pid == K_END:
                return
            if pid == K_ARCHIVE_PROPS:
                self._skip_props(r)
            elif pid == K_ADDITIONAL_STREAMS:
                self.additional_streams = self._read_streams_info(r)
            elif pid == K_MAIN_STREAMS:
                self.streams = self._read_streams_info(r)
            elif pid == K_FILES_INFO:
                self._read_files_info(r)
            else:
                raise ValueError("7z 头出现未知 property 0x%02X（偏移 %d）" % (pid, r.p - 1))

    def _skip_props(self, r):
        while True:
            pid = r.byte()
            if pid == K_END:
                return
            size = r.number()
            r.take(size)

    def _read_streams_info(self, r):
        """StreamsInfo 解析的外层重试：子流 CRC 计数口径有两种流行写法，
        先按"仅多子流 folder"读，读崩了换"全部子流"再读一次。"""
        save = r.p
        for mode in ("n_gt_1", "all"):
            r.p = save
            self._crc_mode = mode
            try:
                return self._read_streams_info_once(r)
            except (ValueError, EOFError):
                if mode == "all":
                    r.p = save
                    self._crc_mode = "n_gt_1"
                    raise
        raise AssertionError("不可达")

    def _read_streams_info_once(self, r):
        st = {"pack_pos": 0, "pack_sizes": [], "pack_crcs": [], "folders": [],
              "num_sub": {}, "sub_sizes": [], "sub_crcs": None, "pack_base": 32}
        while True:
            pid = r.byte()
            if pid == K_END:
                break
            if pid == K_PACK_INFO:
                st["pack_pos"] = r.number()
                num_pack = r.number()
                while True:
                    sub = r.byte()
                    if sub == K_END:
                        break
                    if sub == K_SIZE:
                        st["pack_sizes"] = [r.number() for _ in range(num_pack)]
                    elif sub == K_CRC:
                        st["pack_crcs"] = r.digests(num_pack)
                    else:
                        raise ValueError("kPackInfo 内未知 id 0x%02X" % sub)
            elif pid == K_UNPACK_INFO:
                self._read_unpack_info(r, st)
            elif pid == K_SUBSTREAMS_INFO:
                self._read_substreams_info(r, st)
            else:
                raise ValueError("StreamsInfo 内未知 id 0x%02X" % pid)
        self._link_pack_indices(st)
        return st

    def _read_unpack_info(self, r, st):
        pid = r.byte()
        if pid != K_FOLDER:
            raise ValueError("kUnPackInfo 应以 kFolder 开头，实际 0x%02X" % pid)
        num_folders = r.number()
        external = r.byte()
        if external:
            raise NotImplementedError("7z 文件夹定义外置（kExternal=1）未支持")
        folders = []
        for _ in range(num_folders):
            folders.append(self._read_folder(r))
        pid = r.byte()
        if pid != K_CODERS_UNPACK_SIZE:
            raise ValueError("kUnPackInfo 缺 kCodersUnPackSize，实际 0x%02X" % pid)
        for f in folders:
            f.unpack_sizes = [r.number() for _ in range(len(f.coders))]
        while True:
            pid = r.byte()
            if pid == K_END:
                break
            if pid == K_CRC:
                crcs = r.digests(num_folders)
                for f, c in zip(folders, crcs):
                    f.crc = c
            elif pid == K_DUMMY:
                r.take(r.number())
            else:
                raise ValueError("kUnPackInfo 内未知 id 0x%02X" % pid)
        st["folders"] = folders

    def _read_folder(self, r):
        f = _Folder()
        num_coders = r.number()
        total_in = 0
        total_out = 0
        for _ in range(num_coders):
            flag = r.byte()
            id_size = flag & 0x0F
            method = int.from_bytes(r.take(id_size), "big") if id_size else 0
            if flag & 0x10:
                n_in = r.number()
                n_out = r.number()
            else:
                n_in = n_out = 1
            props = r.take(r.number()) if flag & 0x20 else b""
            if flag & 0x80:
                raise NotImplementedError(
                    "7z coder 带 alternative methods（flag 0x80），未支持")
            f.coders.append({"method": method, "n_in": n_in, "n_out": n_out,
                             "props": props})
            total_in += n_in
            total_out += n_out
        for _ in range(total_out - 1):
            in_index = r.number()
            out_index = r.number()
            f.bind_pairs.append((in_index, out_index))
        n_packed = total_in - len(f.bind_pairs)
        if n_packed > 1:
            for _ in range(n_packed):
                f.packed_in.append(r.number())
        if any(c["n_in"] != 1 or c["n_out"] != 1 for c in f.coders):
            raise NotImplementedError(
                "7z Folder 含多输入/多输出 coder（BCJ2 等），本模块只解 1 进 1 出线性链：%s"
                % ([CODER_IDS.get(c["method"], hex(c["method"])) for c in f.coders],))
        bound_in = {p[0] for p in f.bind_pairs}
        packed_in = [i for i in range(total_in) if i not in bound_in]
        if len(packed_in) != 1:
            raise NotImplementedError(
                "7z Folder 有 %d 个打包输入流，非单一线性链" % len(packed_in))
        nxt = {out_i: in_i for in_i, out_i in f.bind_pairs}
        flow = [packed_in[0]]
        cur = packed_in[0]
        guard = 0
        while cur in nxt:
            cur = nxt[cur]
            flow.append(cur)
            guard += 1
            if guard > len(f.coders) + 1:
                raise ValueError("7z Folder bind pair 成环")
        if len(flow) != len(f.coders):
            raise NotImplementedError(
                "7z Folder coder 链不连通（%d coders，链长 %d）"
                % (len(f.coders), len(flow)))
        f.flow = flow
        return f

    def _read_substreams_info(self, r, st):
        while True:
            pid = r.byte()
            if pid == K_END:
                break
            if pid == K_NUM_UNPACK_STREAM:
                for i in range(len(st["folders"])):
                    st["num_sub"][i] = r.number()
            elif pid == K_SIZE:
                counts = self._sub_counts(st)
                need = sum(n - 1 for n in counts if n > 0)
                st["sub_sizes"] = [r.number() for _ in range(need)]
            elif pid == K_CRC:
                st["sub_crcs"] = self._read_sub_crcs(r, st)
            else:
                raise ValueError("kSubStreamsInfo 内未知 id 0x%02X（偏移 %d）"
                                 % (pid, r.p - 1))

    def _sub_counts(self, st):
        """每个 folder 的子流数量（未给 kNumUnPackStream 时按 1）。"""
        folders = st["folders"]
        if not st["num_sub"]:
            return [1] * len(folders)
        return [st["num_sub"].get(i, 1) for i in range(len(folders))]

    def _read_sub_crcs(self, r, st):
        """SubStreamsInfo 的 kCRC：单子流 folder 是否复用 folder CRC 有两种流行
        口径，按当前尝试的口径读，读崩了由 _read_streams_info 的外层重试换口径。"""
        counts = self._sub_counts(st)
        mode = getattr(self, "_crc_mode", "n_gt_1")
        if mode == "all":
            need = sum(n for n in counts if n > 0)
        else:
            need = sum(n for n in counts if n > 1)
        st["sub_crc_mode"] = mode
        return r.digests(need)

    def _link_pack_indices(self, st):
        """把 pack 流按顺序分配给各 folder（7z 的 pack 流顺序即 folder 顺序）。"""
        idx = 0
        for f in st["folders"]:
            n = len(f.packed_in) if f.packed_in else 1
            f.pack_indices = list(range(idx, idx + n))
            idx += n
        if idx and idx != len(st["pack_sizes"]):
            st["pack_count_mismatch"] = (idx, len(st["pack_sizes"]))

    def _streams_encrypted(self, st):
        return any(f.is_encrypted for f in st["folders"])

    # ---- 解码 ----
    def _pack_bytes(self, st, indices):
        """按 pack 流序号取原始字节；基准 = 32 + packPos + 该流之前所有流的长度。"""
        if not indices:
            return b""
        for i in indices:
            if i >= len(st["pack_sizes"]):
                raise ValueError("pack 流序号 %d 越界（共 %d）"
                                 % (i, len(st["pack_sizes"])))
        base = 32 + st["pack_pos"] + sum(st["pack_sizes"][:indices[0]])
        out = b""
        for i in indices:
            size = st["pack_sizes"][i]
            out += self._blob.read(base, size)
            base += size
        return out

    def _filters_for(self, coders, reverse):
        seq = list(reversed(coders)) if reverse else list(coders)
        filters = []
        for c in seq:
            m = c["method"]
            if m == M_COPY:
                continue
            if m == M_LZMA:
                filters.append(_lzma_props(c["props"]))
            elif m == M_LZMA2:
                filters.append(_lzma2_props(c["props"]))
            elif m in _BCJ_FILTERS:
                spec = {"id": _BCJ_FILTERS[m]}
                if len(c["props"]) == 4:
                    spec["start_offset"] = struct.unpack("<I", c["props"])[0]
                filters.append(spec)
            elif m == M_DELTA:
                dist = c["props"][0] if c["props"] else 1
                filters.append({"id": lzma.FILTER_DELTA, "dist": dist + 1})
            else:
                return None
        if not filters:
            return None
        if filters[-1]["id"] not in (lzma.FILTER_LZMA1, lzma.FILTER_LZMA2):
            return None
        return filters

    def _decode_folder(self, folder, streams=None):
        """解出一个 folder 的完整输出（solid 块内多文件共用一次解码）。"""
        key = id(folder)
        if key in self._folder_cache:
            return self._folder_cache[key]
        if streams is None:
            streams = self.streams
        if streams is None:
            raise ValueError("7z 没有 kMainStreamsInfo，无可解数据")
        packed = self._pack_bytes(streams, folder.pack_indices)
        if folder.is_encrypted:
            raise NotImplementedError(
                "7z 成员已 AES-256 加密：缺 SHA-256 迭代 KDF（7z 用 2**19 轮 "
                "SHA-256 派生 key/iv）+ AES-256-CBC 解密器；标准库无 AES，"
                "mkit.aes 的 ECB/CTR 原语尚未接 CBC")
        methods = folder.methods()
        expect = folder.final_size
        if all(m == M_COPY for m in methods):
            out = packed[:expect]
        elif len(methods) == 1 and methods[0] == M_DEFLATE:
            out = zlib.decompress(packed)[:expect]
        elif len(methods) == 1 and methods[0] == M_BZIP2:
            out = bz2.decompress(packed)[:expect]
        else:
            coders = folder.coders
            out = None
            last_err = None
            for reverse in (True, False):
                filters = self._filters_for(coders, reverse)
                if filters is None:
                    continue
                try:
                    got = _raw_lzma_decode(packed, filters)
                except Exception as exc:            # noqa: BLE001 - 换顺序再试
                    last_err = exc
                    continue
                if expect and len(got) < expect:
                    last_err = ValueError("解出 %d 字节，期望 %d" % (len(got), expect))
                    continue
                got = got[:expect] if expect else got
                if folder.crc is not None and _crc32(got) != folder.crc:
                    last_err = ValueError("folder CRC 不符")
                    continue
                out = got
                break
            if out is None:
                raise NotImplementedError(
                    "7z coder 链 %s 无法用标准库 lzma raw 解码（%s）。支持的组合是 "
                    "Copy / LZMA / LZMA2 / BCJ 家族 / Delta 的线性链"
                    % ("+".join(folder.method_names()), last_err))
        if folder.crc is not None and _crc32(out) != folder.crc and expect:
            out = out[:expect]
        self._folder_cache[key] = out
        return out

    def _decode_streams(self, st):
        return [self._decode_folder(f, streams=st) for f in st["folders"]]

    # ---- FilesInfo ----
    def _read_files_info(self, r):
        num = r.number()
        empty_stream = [False] * num
        empty_file = []
        anti = []
        names = []
        ctime = [None] * num
        atime = [None] * num
        mtime = [None] * num
        attribs = [None] * num
        while True:
            pid = r.byte()
            if pid == K_END:
                break
            size = r.number()
            end = r.p + size
            if end > len(r.b):
                raise EOFError("7z FilesInfo 属性 0x%02X 越界" % pid)
            if pid == K_EMPTY_STREAM:
                empty_stream = r.bitvector(num)
            elif pid == K_EMPTY_FILE:
                empty_file = r.bitvector(sum(1 for x in empty_stream if x))
            elif pid == K_ANTI:
                anti = r.bitvector(sum(1 for x in empty_stream if x))
            elif pid == K_NAME:
                external = r.byte()
                if external:
                    raise NotImplementedError("7z 文件名为外部流（kExternal=1）")
                names = self._decode_names(r.take(end - r.p))
            elif pid == K_MTIME:
                mtime = self._read_times(r, num)
            elif pid == K_CTIME:
                ctime = self._read_times(r, num)
            elif pid == K_ATIME:
                atime = self._read_times(r, num)
            elif pid == K_WIN_ATTRIB:
                attribs = self._read_attribs(r, num)
            r.p = end
        self._build_file_records(num, names, empty_stream, empty_file, anti,
                                 mtime, ctime, atime, attribs)

    def _decode_names(self, raw):
        try:
            text = raw.decode("utf-16-le", "surrogatepass")
        except UnicodeDecodeError:
            text = raw.decode("utf-16-le", "replace")
        parts = text.split("\x00")
        while parts and parts[-1] == "":
            parts.pop()
        return parts

    def _read_times(self, r, num):
        all_defined = r.byte()
        external = r.byte()
        if external:
            raise NotImplementedError("7z 时间戳为外部流（kExternal=1）")
        bits = [True] * num if all_defined else r.bitvector(num)
        out = []
        for b in bits:
            out.append(_filetime_to_dt(r.u64()) if b else None)
        return out

    def _read_attribs(self, r, num):
        all_defined = r.byte()
        external = r.byte()
        if external:
            raise NotImplementedError("7z 属性为外部流（kExternal=1）")
        bits = [True] * num if all_defined else r.bitvector(num)
        return [r.u32() if b else None for b in bits]

    def _substream_plan(self):
        """把 folder 输出切成子流：[(folder, offset, size, crc), ...]"""
        st = self.streams
        plan = []
        if st is None:
            return plan
        folders = st["folders"]
        num_sub = st["num_sub"] or {i: 1 for i in range(len(folders))}
        raw_sizes = list(st["sub_sizes"])
        raw_crcs = st["sub_crcs"]
        size_idx = 0
        crc_idx = 0
        for fi, folder in enumerate(folders):
            n = num_sub.get(fi, 1)
            if n == 0:
                continue
            final = folder.final_size
            if n == 1:
                sizes = [final]
            else:
                head = []
                for _ in range(n - 1):
                    head.append(raw_sizes[size_idx])
                    size_idx += 1
                sizes = head + [final - sum(head)]
            mode = st.get("sub_crc_mode", "n_gt_1")
            if raw_crcs is not None and (n > 1 or mode == "all"):
                crcs = list(raw_crcs[crc_idx:crc_idx + n])
                crc_idx += n
                crcs += [None] * (n - len(crcs))
            elif n == 1:
                crcs = [folder.crc]
            else:
                crcs = [None] * (n - 1) + [folder.crc]
            off = 0
            for size, crc in zip(sizes, crcs):
                plan.append((folder, off, size, crc))
                off += size
        return plan

    def _build_file_records(self, num, names, empty_stream, empty_file, anti,
                            mtime, ctime, atime, attribs):
        st = self.streams
        plan = self._substream_plan()
        # kEmptyFile / kAnti 的位图按"空流顺序"排列，先建空流序号表
        empty_idx = {}
        k = 0
        for i in range(num):
            if empty_stream[i]:
                empty_idx[i] = k
                k += 1
        pack_sizes = (st["pack_sizes"] if st else [])
        folders = (st["folders"] if st else [])
        num_sub = st["num_sub"] if st else {}
        folder_pack = {}
        folder_index = {}
        solid = {}
        for fi, folder in enumerate(folders):
            folder_pack[fi] = sum(pack_sizes[i] for i in folder.pack_indices
                                  if i < len(pack_sizes))
            folder_index[id(folder)] = fi
            solid[fi] = num_sub.get(fi, 1) > 1
        first_in_folder = set()
        stream_i = 0
        self.files = []
        for i in range(num):
            name = names[i] if i < len(names) else "<unnamed-%d>" % i
            attr = attribs[i] if i < len(attribs) else None
            rec = {"index": i + 1, "name": name, "size": 0, "crc": None,
                   "packed_size": None, "is_dir": False, "is_encrypted": False,
                   "mtime": mtime[i] if i < len(mtime) else None,
                   "ctime": ctime[i] if i < len(ctime) else None,
                   "atime": atime[i] if i < len(atime) else None,
                   "attributes": attr, "folder": None, "solid": False,
                   "anti": bool(anti and i in empty_idx
                                and empty_idx[i] < len(anti)
                                and anti[empty_idx[i]]),
                   "offset_in_folder": None, "has_stream": False,
                   "_crc_int": None}
            if empty_stream[i]:
                k = empty_idx.get(i, -1)
                rec["is_dir"] = not (0 <= k < len(empty_file) and empty_file[k])
                if attr is not None and attr & 0x10:
                    rec["is_dir"] = True
                self.files.append(rec)
                continue
            if stream_i < len(plan):
                folder, off, size, crc = plan[stream_i]
                fi = folder_index.get(id(folder), -1)
                rec.update(size=size, crc=None if crc is None else "%08X" % crc,
                           folder=fi, solid=solid.get(fi, False),
                           offset_in_folder=off, has_stream=True,
                           is_encrypted=folder.is_encrypted, _crc_int=crc)
                if fi not in first_in_folder:
                    rec["packed_size"] = folder_pack.get(fi)
                    first_in_folder.add(fi)
            stream_i += 1
            self.files.append(rec)

    # ---- 统一接口 ----
    def names(self):
        return [f["name"] for f in self.files]

    def info(self, name):
        for f in self.files:
            if f["name"] == name or f["name"] == name.rstrip("/"):
                return _Rec(**f)
        raise KeyError(name)

    def read(self, name):
        rec = None
        for f in self.files:
            if f["name"] == name or f["name"] == name.rstrip("/"):
                rec = f
        if rec is None:
            raise KeyError(name)
        if not rec["has_stream"]:
            return b""
        if rec["is_encrypted"]:
            raise NotImplementedError(
                "7z 成员 %r 已 AES-256 加密：缺 AES-256-CBC 解密器与 7z 的 "
                "SHA-256 迭代 KDF（2**19 轮），标准库无 AES" % (name,))
        folder = self.streams["folders"][rec["folder"]]
        data = self._decode_folder(folder)
        off = rec["offset_in_folder"]
        out = data[off:off + rec["size"]]
        crc = rec.get("_crc_int")
        if crc is not None and _crc32(out) != crc:
            raise ValueError("7z 成员 %r CRC 不符：期望 %08X，实得 %08X"
                             % (name, crc, _crc32(out)))
        return out

    def walk(self):
        for f in self.files:
            yield f["name"], _Rec(**f)

    def folders(self):
        if not self.streams:
            return []
        out = []
        pack_sizes = self.streams["pack_sizes"]
        for fi, folder in enumerate(self.streams["folders"]):
            out.append(_Rec(index=fi, methods=folder.method_names(),
                            unpack_size=folder.final_size,
                            pack_size=sum(pack_sizes[i] for i in folder.pack_indices
                                          if i < len(pack_sizes)),
                            crc=None if folder.crc is None else "%08X" % folder.crc,
                            is_encrypted=folder.is_encrypted,
                            num_substreams=(self.streams["num_sub"] or {}).get(fi, 1)))
        return out

    def summary(self):
        return {
            "format": "7z",
            "path": self.path,
            "version": "%d.%d" % self.version,
            "header_encoded": self.header_encoded,
            "start_header_crc_ok": self.start_header_crc_ok,
            "next_header_crc_ok": self.header_crc_ok,
            "next_header_offset": self.next_offset,
            "next_header_size": self.next_size,
            "files": len(self.files),
            "dirs": sum(1 for f in self.files if f["is_dir"]),
            "folders": len(self.streams["folders"]) if self.streams else 0,
            "pack_streams": len(self.streams["pack_sizes"]) if self.streams else 0,
            "encrypted": bool(self.streams and self._streams_encrypted(self.streams)),
            "methods": sorted({m for f in (self.folders() if self.streams else [])
                               for m in f.methods}),
            "size": self._blob.size,
        }

    def close(self):
        self._blob.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __len__(self):
        return len(self.files)


# ---------------- Docker / OCI ----------------


OPAQUE_WHITEOUT = ".wh..wh..opq"


def _layer_payload(data):
    """层压缩体解开：gzip 直接解，zstd 明确拒。"""
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    if data[:4] == b"\x28\xb5\x2f\xfd":
        raise NotImplementedError(
            "OCI 层使用 zstd 压缩：Python 3.11 标准库无 zstd，本模块不引第三方")
    return data


def _tar_members_from_bytes(data):
    """内存 tar → [(name, member)]，容忍末尾截断。"""
    out = []
    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    try:
        for m in tf:
            out.append((m.name, m))
    except (tarfile.ReadError, EOFError):
        pass
    finally:
        tf.close()
    return out


class DockerImage(object):
    """Docker save / OCI image layout 只读视图（tar 或目录）。

    取证口径：每一层的变更单独留存（add / modify / delete / opaque），
    被上层删掉的文件在层清单里依然看得到，只是最终视图里消失。

    layers() 每层摘要：index / digest / size / media_type / added / modified /
        deleted / opaque / files / created / created_by
    files(layer=None)：layer=None 给最终视图，给序号给该层叠加后的视图
    read(path)：从最上层包含它的层读内容
    history()：config 里的 history（created / created_by / empty_layer / comment）
    """

    def __init__(self, src):
        self.path = None
        self._blob = None
        self._dir = None
        if isinstance(src, (str, bytes, os.PathLike)) and os.path.isdir(os.fsdecode(src)):
            self._dir = os.path.abspath(os.fsdecode(src))
            self.path = self._dir
        else:
            self._blob = _Blob(src)
            self.path = self._blob.path
        self._names = None
        names = self._list()
        self._names = names
        lower = set(n.lower() for n in names)
        if "manifest.json" in lower:
            self.kind = "docker"
        elif "oci-layout" in lower or "index.json" in lower:
            self.kind = "oci"
        else:
            raise ValueError("既无 manifest.json 也无 index.json / oci-layout，"
                             "不是 Docker save 或 OCI layout")
        self._layers = []
        self._config = {}
        self._history_raw = []
        self._state = {}
        self._changes = []
        self._layer_cache = {}
        self._load_manifest()
        self._index_layers()

    # ---- 源访问 ----
    def _list(self):
        if self._dir:
            out = []
            for root, _dirs, files in os.walk(self._dir):
                for fn in files:
                    p = os.path.join(root, fn)
                    out.append(os.path.relpath(p, self._dir).replace(os.sep, "/"))
            return out
        comp = _tar_compression(self._blob)
        stream = _open_tar_stream(self._blob, comp)
        tf = tarfile.open(fileobj=stream, mode="r:")
        try:
            names = [m.name for m in tf.getmembers()]
        finally:
            tf.close()
            stream.close()
        return names

    def _outer_bytes(self, name):
        name = name.lstrip("./")
        if self._dir:
            p = os.path.join(self._dir, *name.split("/"))
            with open(p, "rb") as f:
                return f.read()
        comp = _tar_compression(self._blob)
        stream = _open_tar_stream(self._blob, comp)
        tf = tarfile.open(fileobj=stream, mode="r:")
        try:
            try:
                info = tf.getmember(name)
            except KeyError:
                cand = [m for m in tf.getmembers()
                        if m.name.lstrip("./") == name]
                if not cand:
                    raise KeyError(name)
                info = cand[0]
            f = tf.extractfile(info)
            data = f.read() if f is not None else b""
        finally:
            tf.close()
            stream.close()
        return data

    def _has(self, name):
        key = name.lstrip("./")
        return any(n.lstrip("./") == key for n in self._names)

    def _json(self, name):
        return json.loads(self._outer_bytes(name).decode("utf-8"))

    # ---- manifest ----
    def _load_manifest(self):
        if self.kind == "docker":
            manifest = self._json("manifest.json")
            if isinstance(manifest, list) and manifest:
                entry = manifest[0]
                self.manifest_raw = manifest
            else:
                raise ValueError("manifest.json 结构异常")
            self.repo_tags = entry.get("RepoTags") or []
            self.config_name = entry.get("Config")
            self._config = self._json(self.config_name) if self.config_name else {}
            self._layers = [{"member": p, "digest": os.path.basename(
                p.rstrip("/")).replace(".tar", ""), "media_type": "docker.layer.tar"}
                for p in entry.get("Layers", [])]
        else:
            index = self._json("index.json")
            self.repo_tags = []
            self._config = {}
            self.config_name = None
            man = self._pick_manifest(index)
            self.manifest = man
            self.repo_tags = list(man.get("annotations", {}).values())[:0]
            cfg = man.get("config") or {}
            if cfg.get("digest"):
                self.config_name = self._digest_path(cfg["digest"])
                self._config = self._json(self.config_name)
            for layer in man.get("layers", []):
                self._layers.append({
                    "member": self._digest_path(layer["digest"]),
                    "digest": layer["digest"],
                    "media_type": layer.get("mediaType", ""),
                    "size": layer.get("size"),
                })
        self._history_raw = list(self._config.get("history") or [])

    def _pick_manifest(self, index):
        """index.json → 具体 image manifest（多架构时取第一个可用）。"""
        seen = 0
        cur = index
        while True:
            mans = cur.get("manifests") or []
            if not mans:
                return cur
            mans = [m for m in mans
                    if "image" in (m.get("mediaType") or "")
                    or (m.get("mediaType") or "") == ""]
            if not mans:
                mans = cur.get("manifests") or []
            digest = mans[0]["digest"]
            data = self._json(self._digest_path(digest))
            seen += 1
            if seen > 4:
                raise ValueError("OCI index 嵌套过深")
            if (data.get("mediaType") or "").endswith("image.manifest.v1+json") \
                    or "layers" in data:
                data.setdefault("mediaType", mans[0].get("mediaType"))
                return data
            cur = data

    @staticmethod
    def _digest_path(digest):
        algo, _, hexd = digest.partition(":")
        return "blobs/%s/%s" % (algo or "sha256", hexd or digest)

    # ---- 层索引 ----
    def _layer_bytes(self, index):
        if index in self._layer_cache:
            return self._layer_cache[index]
        raw = self._outer_bytes(self._layers[index]["member"])
        data = _layer_payload(raw)
        self._layer_cache[index] = data
        return data

    def _history_for_layers(self):
        """非空层（empty_layer 为假）按顺序贴到每一层上。"""
        out = [None] * len(self._layers)
        li = 0
        for h in self._history_raw:
            if h.get("empty_layer"):
                continue
            if li < len(out):
                out[li] = h
                li += 1
        return out

    def _index_layers(self):
        hist = self._history_for_layers()
        for li, desc in enumerate(self._layers):
            data = self._layer_bytes(li)
            members = _tar_members_from_bytes(data)
            whiteouts = []
            plain = []
            for name, m in members:
                nm = name.rstrip("/")
                if nm.endswith("/") or nm == ".":
                    continue
                base = nm.rsplit("/", 1)[-1]
                if base == OPAQUE_WHITEOUT:
                    whiteouts.append((nm.rsplit("/", 1)[0] if "/" in nm else "", "opaque"))
                elif base.startswith(".wh."):
                    target = nm[:len(nm) - len(base)] + base[4:]
                    whiteouts.append((target, "delete"))
                else:
                    plain.append((nm, m))
            changes = []
            deleted = 0
            opaque = 0
            for target, kind in whiteouts:
                if kind == "opaque":
                    opaque += 1
                    prefix = target + "/" if target else ""
                    victims = [p for p in list(self._state)
                               if prefix == "" or p == target or p.startswith(prefix)]
                    for v in victims:
                        del self._state[v]
                        changes.append({"path": v, "change": "opaque",
                                        "layer": li, "type": "dir"})
                        deleted += 1
                else:
                    if target in self._state:
                        rec = self._state.pop(target)
                        changes.append({"path": target, "change": "delete",
                                        "layer": li, "type": rec["type"],
                                        "prev_layer": rec["layer"],
                                        "prev_size": rec["size"]})
                        deleted += 1
                    else:
                        changes.append({"path": target, "change": "delete",
                                        "layer": li, "type": "absent",
                                        "prev_layer": None, "prev_size": 0})
            added = 0
            modified = 0
            for nm, m in plain:
                if m.isdir():
                    mtype = "dir"
                elif m.issym():
                    mtype = "symlink"
                elif m.islnk():
                    mtype = "hardlink"
                elif m.ischr() or m.isblk() or m.isfifo():
                    mtype = "device"
                else:
                    mtype = "file"
                prev = self._state.get(nm)
                if prev is None:
                    change = "add"
                    added += 1
                else:
                    change = "modify"
                    modified += 1
                rec = {"path": nm, "type": mtype, "size": int(m.size or 0),
                       "mode": m.mode, "uid": m.uid, "gid": m.gid,
                       "mtime": m.mtime, "layer": li, "change": change,
                       "linkname": m.linkname}
                self._state[nm] = rec
                changes.append(rec)
            entry = dict(desc)
            h = hist[li] if li < len(hist) else None
            entry.update(index=li, added=added, modified=modified,
                         deleted=deleted, opaque=opaque, changes=len(changes),
                         files=len(plain),
                         created=(h or {}).get("created"),
                         created_by=(h or {}).get("created_by"),
                         comment=(h or {}).get("comment"))
            entry["_changes"] = changes
            self._changes.append(entry)

    # ---- 统一接口 ----
    def names(self):
        return sorted(self._state)

    def info(self, path):
        key = path.lstrip("./").lstrip("/")
        if key not in self._state:
            raise KeyError(path)
        return _Rec(**self._state[key])

    def _state_at(self, layer):
        st = {}
        for li, entry in enumerate(self._changes):
            if li > layer:
                break
            for ch in entry["_changes"]:
                if ch["change"] in ("delete", "opaque"):
                    st.pop(ch["path"], None)
                else:
                    st[ch["path"]] = ch
        return st

    def files(self, layer=None):
        st = self._state if layer is None else self._state_at(layer)
        return [_Rec(**st[p]) for p in sorted(st)]

    def layer_files(self, layer):
        """该层的完整文件清单（含被删项，按 tar 顺序）。"""
        if not 0 <= layer < len(self._changes):
            raise IndexError("层序号越界: %r" % (layer,))
        return [_Rec(**ch) for ch in self._changes[layer]["_changes"]]

    def layers(self):
        out = []
        for entry in self._changes:
            d = {k: v for k, v in entry.items() if k != "_changes"}
            d["first"] = (entry["_changes"][0]["path"] if entry["_changes"] else None)
            out.append(_Rec(**d))
        return out

    def layer_changes(self, layer):
        """该层的变更清单：change ∈ add / modify / delete / opaque。"""
        return [_Rec(**ch) for ch in self._changes[layer]["_changes"]]

    def read(self, path):
        key = path.lstrip("./").lstrip("/")
        rec = self._state.get(key)
        if rec is None:
            raise KeyError(path)
        if rec["type"] in ("symlink", "hardlink"):
            if rec.get("linkname"):
                return self.read(rec["linkname"].lstrip("./").lstrip("/"))
            return b""
        if rec["type"] != "file":
            return b""
        data = self._layer_bytes(rec["layer"])
        for name, m in _tar_members_from_bytes(data):
            if name.rstrip("/") == key and m.isfile():
                f = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
                try:
                    fh = f.extractfile(m)
                    return fh.read() if fh is not None else b""
                finally:
                    f.close()
        raise KeyError("%s 在层 %d 的 tar 里找不到内容" % (path, rec["layer"]))

    def walk(self):
        for path in sorted(self._state):
            yield path, _Rec(**self._state[path])

    def history(self):
        out = []
        layer_of = {}
        li = 0
        for i, h in enumerate(self._history_raw):
            rec = {"index": i, "created": h.get("created"),
                   "created_by": h.get("created_by"),
                   "empty_layer": bool(h.get("empty_layer")),
                   "comment": h.get("comment"), "layer": None}
            if not rec["empty_layer"]:
                rec["layer"] = li
                layer_of[li] = i
                li += 1
            out.append(_Rec(**rec))
        return out

    def image_info(self):
        cfg = self._config or {}
        return {
            "kind": self.kind,
            "repo_tags": self.repo_tags,
            "architecture": cfg.get("architecture"),
            "os": cfg.get("os"),
            "created": cfg.get("created"),
            "author": cfg.get("author"),
            "labels": (cfg.get("config") or {}).get("Labels"),
            "workdir": (cfg.get("config") or {}).get("WorkingDir"),
            "env": (cfg.get("config") or {}).get("Env"),
            "layers": len(self._layers),
            "history_entries": len(self._history_raw),
        }

    def summary(self):
        return {
            "format": self.kind,
            "path": self.path,
            "layers": len(self._layers),
            "files_final": len(self._state),
            "deleted_overall": sum(1 for e in self._changes for ch in e["_changes"]
                                   if ch["change"] == "delete"),
            "config": self.config_name,
            "size": self._blob.size if self._blob else None,
        }

    def close(self):
        if self._blob is not None:
            self._blob.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __len__(self):
        return len(self._layers)


# ---------------- BCP（SQL Server 批量复制）----------------


_FMT_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\S+')

_FMT_ESCAPES = {
    "t": b"\t", "n": b"\n", "r": b"\r", "0": b"\x00", "\\": b"\\",
    '"': b'"', "'": b"'", "a": b"\x07", "b": b"\x08", "f": b"\x0c",
    "v": b"\x0b", "e": b"\x1b",
}

# SQL 类型 → 家族
_BCP_FAMILY = {
    "char": "char", "varchar": "char", "text": "text",
    "nchar": "nchar", "nvarchar": "nchar", "ntext": "ntext",
    "int": "int", "int4": "int", "integer": "int",
    "bigint": "bigint", "int8": "bigint",
    "smallint": "smallint", "int2": "smallint",
    "tinyint": "tinyint",
    "bit": "bit", "bool": "bit",
    "real": "real", "float": "float", "float8": "float",
    "decimal": "decimal", "numeric": "decimal", "dec": "decimal",
    "money": "money", "smallmoney": "money",
    "datetime": "datetime", "datetime2": "datetime", "smalldatetime": "datetime",
    "date": "date", "time": "time",
    "uniqueidentifier": "guid", "guid": "guid",
    "binary": "binary", "varbinary": "binary", "image": "binary",
    "timestamp": "binary", "rowversion": "binary",
    "sql_variant": "variant",
}

# 原生模式定长宽度（prefix_len == 0 时）
_BCP_NATIVE_WIDTH = {
    "int": 4, "bigint": 8, "smallint": 2, "tinyint": 1, "bit": 1,
    "real": 4, "float": 8, "money": 8, "datetime": 8, "date": 3, "time": 5,
    "guid": 16, "decimal": 17,
}

_BCP_DATETIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})([ T](\d{2}):(\d{2})(:(\d{2})(\.\d+)?)?)?$")


def _unescape_fmt(tok):
    """把 .fmt 里的 "\\t" / "\\r\\n" 等还原成字节。"""
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        tok = tok[1:-1]
    out = bytearray()
    i = 0
    while i < len(tok):
        ch = tok[i]
        if ch == "\\" and i + 1 < len(tok):
            nxt = tok[i + 1]
            if nxt in _FMT_ESCAPES:
                out += _FMT_ESCAPES[nxt]
                i += 2
                continue
            if nxt == "x" and i + 3 < len(tok):
                try:
                    out.append(int(tok[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
        out += ch.encode("utf-8", "surrogateescape")
        i += 1
    return bytes(out)


class BcpColumn(object):
    """一列定义（.fmt 的一行）。"""

    __slots__ = ("host_order", "sql_type", "family", "prefix_len", "width",
                 "terminator", "file_order", "name", "collation")

    def __init__(self, host_order, sql_type, prefix_len=0, width=0,
                 terminator=b"\t", file_order=None, name=None, collation=None):
        self.host_order = host_order
        self.sql_type = sql_type
        base = sql_type[3:] if sql_type.startswith("sql") else sql_type
        self.family = _BCP_FAMILY.get(base, "char")
        self.prefix_len = prefix_len
        self.width = width
        self.terminator = terminator
        self.file_order = host_order if file_order is None else file_order
        self.name = name or "col%d" % host_order
        self.collation = collation

    @classmethod
    def from_line(cls, line):
        toks = _FMT_TOKEN_RE.findall(line)
        if len(toks) < 4:
            raise ValueError(".fmt 列定义字段不足: %r" % line)
        sql_type = toks[1].lower()
        prefix = int(toks[2])
        width = int(toks[3])
        term = _unescape_fmt(toks[4]) if len(toks) > 4 else b""
        file_order = int(toks[5]) if len(toks) > 5 else int(toks[0])
        name = _unescape_fmt(toks[6]).decode("utf-8", "replace") if len(toks) > 6 else None
        coll = toks[7] if len(toks) > 7 else None
        return cls(int(toks[0]), sql_type, prefix, width, term, file_order, name, coll)

    def as_dict(self):
        return {"name": self.name, "sql_type": self.sql_type,
                "family": self.family, "prefix_len": self.prefix_len,
                "width": self.width,
                "terminator": self.terminator.decode("latin-1"),
                "file_order": self.file_order, "host_order": self.host_order}

    def __repr__(self):
        return "<BcpColumn %s %s w=%d term=%r>" % (
            self.name, self.sql_type, self.width, self.terminator)


class BcpSpec(object):
    """解析 .fmt 格式描述（SQL Server bcp 10.0 起的行式格式）。"""

    def __init__(self, version, columns):
        self.version = version
        self.columns = sorted(columns, key=lambda c: c.file_order)

    @classmethod
    def parse(cls, text):
        lines = [ln for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
        lines = [ln for ln in lines if ln.strip()]
        if len(lines) < 3:
            raise ValueError(".fmt 至少需要 版本 / 列数 / 列定义 三行")
        version = lines[0].strip()
        if not re.match(r"^\d+(\.\d+)?$", version):
            raise ValueError(".fmt 首行应为版本号，实际 %r" % (version,))
        idx = 1
        try:
            count = int(lines[idx].strip())
            idx += 1
        except ValueError:
            toks = lines[idx].split()
            if len(toks) == 2 and toks[0].isdigit() and toks[1].isdigit():
                count = int(toks[1])
                idx += 1
            else:
                raise
        cols = []
        for ln in lines[idx:idx + count]:
            cols.append(BcpColumn.from_line(ln))
        if len(cols) != count:
            raise ValueError(".fmt 列数声明 %d，实得 %d 行" % (count, len(cols)))
        return cls(version, cols)

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            raw = f.read()
        return cls.parse(_decode_text(raw))

    def __len__(self):
        return len(self.columns)

    def __repr__(self):
        return "<BcpSpec v%s %d 列>" % (self.version, len(self.columns))


def _decode_text(raw):
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", "replace")


class BcpFile(object):
    """BCP 数据文件读取：.fmt 驱动，或启发式推断（inferred=True）。

    参数：
        columns      直接给 BcpColumn 列表（覆盖 fmt）
        fmt          .fmt 路径或 .fmt 正文
        delimiter    分隔符（无 .fmt 且未给 columns 时的回退）
        encoding     字符列编码（默认 utf-8，失败回退 latin-1/replace）
        strip_pad    定长 char(n) 去掉右侧填充空格
        null_as_empty_string  空字段是否返回 "" 而不是 None
    字段空串默认当 NULL（bcp 就是这样表示 NULL 的）。
    """

    def __init__(self, src, columns=None, fmt=None, delimiter=None,
                 encoding="utf-8", strip_pad=True, null_as_empty_string=False):
        self._blob = _Blob(src)
        self.path = self._blob.path
        self.encoding = encoding
        self.strip_pad = strip_pad
        self.null_as_empty_string = null_as_empty_string
        self.fmt_version = None
        self.inferred = False
        self.confidence = None
        self._data = self._blob.read(0, self._blob.size)
        if columns is not None:
            self.columns = sorted(list(columns), key=lambda c: c.file_order)
            self.mode = "native" if any(c.prefix_len for c in self.columns) else "char"
            self.delimiter = delimiter or b"\t"
        elif fmt is not None:
            spec = BcpSpec.parse(fmt) if "\n" in fmt else BcpSpec.from_file(fmt)
            self.columns = spec.columns
            self.fmt_version = spec.version
            self.delimiter = delimiter or b"\t"
            native = any(c.prefix_len for c in self.columns)
            if not native:
                native = all((not c.terminator) and c.width for c in self.columns)
            self.mode = "native" if native else "char"
        else:
            self._infer(delimiter)
        self.row_terminator = self._detect_row_term()

    # ---- 推断 ----
    def _sample_lines(self, limit=40):
        rows = self._raw_rows()
        return rows[:limit]

    def _infer(self, delimiter=None):
        rows = [r for r in self._raw_rows()[:60] if r.strip()]
        if not rows:
            raise ValueError("BCP 数据文件为空，无法推断列结构")
        best = None
        cands = [delimiter] if delimiter else [b"\t", b"|", b",", b";", b"^", b"\x01"]
        for sep in cands:
            if not sep:
                continue
            counts = [r.count(sep) + 1 for r in rows]
            if min(counts) < 2:
                continue
            common = max(set(counts), key=counts.count)
            ratio = counts.count(common) / float(len(counts))
            score = (round(ratio, 3), common)
            if best is None or score > best[0]:
                best = (score, sep, common)
        if best is None:
            self.inferred = True
            self.confidence = 0.0
            self.delimiter = b"\t"
            self.columns = [BcpColumn(1, "varchar", 0, 0, b"\t", 1, "col1")]
            self.mode = "char"
            return
        score, sep, ncol = best
        self.inferred = True
        self.delimiter = sep
        self.mode = "char"
        self.confidence = score[0]
        samples = [r.split(sep) for r in rows if r.count(sep) + 1 == ncol]
        cols = []
        for ci in range(ncol):
            vals = [s[ci] for s in samples if ci < len(s)]
            cols.append(BcpColumn(ci + 1, self._guess_type(vals), 0, 0, sep,
                                  ci + 1, "col%d" % (ci + 1)))
        self.columns = cols

    @staticmethod
    def _guess_type(values):
        values = [v for v in values if v not in (b"", b"NULL", b"\\N")]
        if not values:
            return "varchar"
        if all(re.match(rb"^-?\d{1,9}$", v) for v in values):
            return "int"
        if all(re.match(rb"^-?\d{1,19}$", v) for v in values):
            return "bigint"
        if all(re.match(rb"^-?\d+\.\d+$", v) for v in values):
            return "decimal"
        if all(re.match(rb"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}", v) for v in values):
            return "datetime"
        if all(v in (b"0", b"1") for v in values):
            return "bit"
        return "varchar"

    # ---- 行切分 ----
    def _detect_row_term(self):
        data = self._data
        if b"\r\n" in data:
            return b"\r\n"
        if b"\n" in data:
            return b"\n"
        if b"\r" in data:
            return b"\r"
        return b""

    def _raw_rows(self):
        data = self._data
        rt = self._detect_row_term()
        if not rt:
            return [data] if data else []
        parts = data.split(rt)
        if parts and parts[-1] == b"":
            parts.pop()
        return parts

    def _take_native(self, row, pos, col, is_last):
        raw = None
        if col.prefix_len:
            n = col.prefix_len
            head = row[pos:pos + n]
            pos += n
            if len(head) < n:
                return None, pos
            length = int.from_bytes(head, "little")
            if length == (1 << (8 * n)) - 1:
                return None, pos
            raw = row[pos:pos + length]
            pos += length
            return raw, pos
        width = col.width or _BCP_NATIVE_WIDTH.get(col.family, 0)
        if col.family == "decimal" and col.width in (5, 9, 13, 17):
            width = col.width
        raw = row[pos:pos + width]
        pos += width
        return raw, pos

    def _parse_row(self, row):
        values = []
        pos = 0
        last = len(self.columns) - 1
        for i, col in enumerate(self.columns):
            if self.mode == "native":
                raw, pos = self._take_native(row, pos, col, i == last)
            else:
                sep = col.terminator or self.delimiter
                if i == last:
                    raw = row[pos:]
                    pos = len(row)
                elif sep:
                    idx = row.find(sep, pos)
                    if idx < 0:
                        raw = row[pos:]
                        pos = len(row)
                    else:
                        raw = row[pos:idx]
                        pos = idx + len(sep)
                elif col.width:
                    raw = row[pos:pos + col.width]
                    pos += len(raw)
                else:
                    raw = row[pos:]
                    pos = len(row)
            values.append(self._convert(col, raw))
        return values

    # ---- 类型转换 ----
    def _text(self, raw):
        return raw.decode(self.encoding, "replace")

    def _convert(self, col, raw):
        fam = col.family
        if raw is None:
            return None
        if raw == b"":
            if self.null_as_empty_string and fam in ("char", "nchar", "text", "ntext"):
                return ""
            return None
        if fam == "char" and self.strip_pad and self.mode == "char" and col.width:
            raw = raw.rstrip(b" ")
        if self.mode == "native":
            return self._convert_native(col, raw)
        text = self._text(raw)
        if text == "NULL":
            return None
        if fam in ("char", "text", "nchar", "ntext"):
            return text
        if fam in ("int", "bigint", "smallint", "tinyint"):
            return int(text.strip())
        if fam == "bit":
            t = text.strip().lower()
            if t in ("1", "true", "t"):
                return True
            if t in ("0", "false", "f"):
                return False
            raise ValueError("bit 列 %r 值 %r 无法解析" % (col.name, text))
        if fam in ("real", "float"):
            return float(text.strip())
        if fam == "decimal":
            from decimal import Decimal
            return Decimal(text.strip())
        if fam == "money":
            from decimal import Decimal
            return Decimal(text.strip())
        if fam in ("datetime", "date", "time"):
            return _parse_dt(text.strip())
        if fam == "binary":
            return raw
        return text

    def _convert_native(self, col, raw):
        fam = col.family
        if fam == "char":
            return self._text(raw.rstrip(b" ") if self.strip_pad else raw)
        if fam in ("nchar", "ntext"):
            return raw.decode("utf-16-le", "replace").rstrip("\x00")
        if fam == "tinyint":
            return raw[0]
        if fam in ("int", "bigint", "smallint"):
            fmt = {"int": "<i", "bigint": "<q", "smallint": "<h"}[fam]
            return struct.unpack(fmt, raw[:struct.calcsize(fmt)])[0]
        if fam == "bit":
            return bool(raw[0])
        if fam == "real":
            return struct.unpack("<f", raw[:4])[0]
        if fam == "float":
            return struct.unpack("<d", raw[:8])[0]
        if fam == "money":
            if len(raw) >= 8:
                hi, lo = struct.unpack("<ii", raw[:8])
                return (hi << 32) + lo & 0xFFFFFFFFFFFFFFFF
            return struct.unpack("<i", raw[:4])[0]
        if fam == "datetime":
            if len(raw) >= 8:
                days, ticks = struct.unpack("<iI", raw[:8])
            else:
                days, mins = struct.unpack("<hH", raw[:4])
                ticks = mins * 300
            base = datetime.datetime(1900, 1, 1)
            return base + datetime.timedelta(days=days, seconds=ticks / 300.0)
        if fam == "decimal":
            from decimal import Decimal
            if len(raw) < 3:
                return None
            sign = raw[0]
            scale = raw[1]
            mag = int.from_bytes(raw[2:], "little")
            val = Decimal(mag).scaleb(-scale)
            return -val if sign == 0 else val
        if fam == "guid":
            import uuid
            return str(uuid.UUID(bytes_le=raw.rjust(16, b"\x00")[:16]))
        return raw

    # ---- 统一接口 ----
    def rows(self):
        return [self._parse_row(r) for r in self._raw_rows()]

    def iter_rows(self):
        for r in self._raw_rows():
            yield self._parse_row(r)

    def records(self):
        names = [c.name for c in self.columns]
        for raw in self._raw_rows():
            yield dict(zip(names, self._parse_row(raw)))

    def names(self):
        return [c.name for c in self.columns]

    def info(self, name):
        for c in self.columns:
            if c.name == name:
                return _Rec(**c.as_dict() | {"inferred": self.inferred,
                                             "mode": self.mode})
        raise KeyError(name)

    def walk(self):
        for i, rec in enumerate(self.records()):
            yield i, _Rec(row=i, **rec)

    def summary(self):
        return {
            "format": "bcp",
            "path": self.path,
            "rows": len(self._raw_rows()),
            "columns": len(self.columns),
            "mode": self.mode,
            "fmt_version": self.fmt_version,
            "inferred": self.inferred,
            "confidence": self.confidence,
            "delimiter": self.delimiter.decode("latin-1"),
            "row_terminator": self.row_terminator.decode("latin-1"),
            "size": self._blob.size,
        }

    def close(self):
        self._blob.close()

    def __len__(self):
        return len(self._raw_rows())


def _parse_dt(text):
    text = text.strip()
    if not text:
        return None
    m = _BCP_DATETIME_RE.match(text)
    if not m:
        return text
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if m.group(5) is None:
        return datetime.datetime(y, mo, d)
    hh, mm = int(m.group(5)), int(m.group(6))
    ss = int(m.group(8)) if m.group(8) else 0
    frac = 0
    if m.group(9):
        frac = int(round(float(m.group(9)) * 1e6))
    return datetime.datetime(y, mo, d, hh, mm, ss, frac)


# ---------------- 小米 .bak ----------------


_MIUI_MAGIC_HINTS = (b"MIUI", b"miui", b"Miui", b"BAK", b"bak\x00")
_MIUI_ENC_RE = re.compile(
    r"<(password|passwd|encrypt|encrypted|dataEncrypt|encryptType)>\s*([^<]*)<",
    re.I)
_MIUI_ENC_ATTR_RE = re.compile(r'\b(password|encrypt)\s*=\s*"([^"]*)"', re.I)


class MiuiBak(object):
    """小米手机本机备份 .bak：容器探明 + descriptor.xml + apps 目录枚举。

    容器形态（按样本特征判断）：
        tar            头部无壳，或 MIUI 头之后能找到 ustar
        zip            PK\\x03\\x04 前有 MIUI 私有头（前置偏移），zipfile 直接吃
        gzip           视作 tar.gz
    descriptor.xml 里出现 password / encrypt 字段即视为加密备份：
    解不了，明确抛 NotImplementedError。
    """

    def __init__(self, src):
        self._blob = _Blob(src)
        self.path = self._blob.path
        self.container = None
        self.prefix_offset = 0
        self._tar = None
        self._zip = None
        self._zip_names = []
        head = self._blob.read(0, 1 << 20)
        self.magic = head[:16]
        self.descriptor_name = None
        self._descriptor_text = None
        self._detect(head)
        self._check_encrypted()

    def _detect(self, head):
        if head[:2] == b"PK" or head.find(b"PK\x03\x04", 0, 1 << 16) >= 0:
            pos = 0 if head[:4] == b"PK\x03\x04" else head.find(b"PK\x03\x04")
            self.container = "zip"
            self.prefix_offset = max(0, pos)
            self._zip = zipfile.ZipFile(_SeqFile(self._blob))
            self._zip_names = self._zip.namelist()
            return
        if head[:2] == b"\x1f\x8b":
            self.container = "gzip"
            self._tar = TarArchive(self._blob, compression="gzip")
            return
        if _is_tar_header(head[:512]):
            self.container = "tar"
            self._tar = TarArchive(self._blob)
            return
        pos = head.find(b"ustar")
        if pos >= 257:
            self.container = "tar"
            self.prefix_offset = pos - 257
            self._tar = TarArchive(self._blob)
            return
        if any(h in head[:256] for h in _MIUI_MAGIC_HINTS):
            raise NotImplementedError(
                "小米 .bak 带 MIUI 私有头但内部没找到 tar/zip/gzip 魔数："
                "该头版本（magic=%r）的字段布局未用真实样本验证，无法定位容器起点"
                % (self.magic,))
        raise ValueError("无法识别的小米 .bak 容器（头部 %r）" % (self.magic,))

    # ---- 成员访问 ----
    def _raw_names(self):
        if self._zip is not None:
            return list(self._zip_names)
        return list(self._tar.names())

    def _find_descriptor(self):
        cands = [n for n in self._raw_names()
                 if n.rsplit("/", 1)[-1].lower() == "descriptor.xml"]
        if not cands:
            return None
        cands.sort(key=len)
        return cands[0]

    def _read_member(self, name):
        if self._zip is not None:
            return self._zip.read(name)
        return self._tar.read(name)

    def _check_encrypted(self):
        self.descriptor_name = self._find_descriptor()
        if not self.descriptor_name:
            self.encrypted = False
            return
        raw = self._read_member(self.descriptor_name)
        text = _decode_text(raw)
        self._descriptor_text = text
        hits = [m.group(1) for m in _MIUI_ENC_RE.finditer(text)
                if (m.group(2) or "").strip()]
        hits += [m.group(1) for m in _MIUI_ENC_ATTR_RE.finditer(text)
                 if (m.group(2) or "").strip()]
        self.encrypted = bool(hits)
        if self.encrypted:
            raise NotImplementedError(
                "小米 .bak 为加密备份（descriptor.xml 含 %s 字段）：缺 MIUI 的"
                "密钥派生与 AES-CBC 解密（标准库无 AES），本模块只做容器与"
                "目录枚举" % (sorted(set(hits)),))

    # ---- 统一接口 ----
    def names(self):
        return self._raw_names()

    def info(self, name):
        if self._zip is not None:
            zi = self._zip.getinfo(name)
            return _Rec(name=name, size=zi.file_size, compress_size=zi.compress_size,
                        is_dir=name.endswith("/"), crc="%08X" % (zi.CRC or 0),
                        mtime=zi.date_time, container="zip")
        m = self._tar.info(name)
        return _Rec(name=name, size=m.size, compress_size=None, is_dir=m.is_dir,
                    crc=None, mtime=m.mtime, container="tar")

    def read(self, name):
        return self._read_member(name)

    def walk(self):
        for name in self._raw_names():
            yield name, self.info(name)

    def descriptor(self):
        return {"name": self.descriptor_name, "text": self._descriptor_text,
                "encrypted": getattr(self, "encrypted", False)}

    def apps(self):
        out = {}
        for name in self._raw_names():
            parts = name.replace("\\", "/").split("/")
            if len(parts) >= 2 and parts[0].lower() == "apps":
                pkg = parts[1]
                rec = out.setdefault(pkg, {"package": pkg, "path": "apps/" + pkg,
                                          "files": 0, "size": 0})
                rec["files"] += 1
                try:
                    rec["size"] += self.info(name).size or 0
                except Exception:
                    pass
        for pkg in self._descriptor_packages():
            if pkg not in out:
                out[pkg] = {"package": pkg, "path": None, "files": 0, "size": 0}
        return [_Rec(**out[k]) for k in sorted(out)]

    def _descriptor_packages(self):
        text = self._descriptor_text
        if not text:
            return []
        pkgs = re.findall(r'packageName\s*=\s*"([^"]+)"', text)
        if not pkgs:
            pkgs = re.findall(r"<package[^>]*>([^<]+)<", text)
        seen = []
        for p in pkgs:
            if p not in seen:
                seen.append(p)
        return seen

    def summary(self):
        return {
            "format": "miui-bak",
            "path": self.path,
            "container": self.container,
            "prefix_offset": self.prefix_offset,
            "magic": self.magic.hex(),
            "members": len(self._raw_names()),
            "descriptor": self.descriptor_name,
            "apps": len(self.apps()),
            "encrypted": getattr(self, "encrypted", False),
            "size": self._blob.size,
        }

    def close(self):
        if self._tar is not None:
            self._tar.close()
        if self._zip is not None:
            self._zip.close()
        self._blob.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# ---------------- 探测器与工厂 ----------------


def _tar_names(blob, comp, limit=4000):
    """列出 tar 成员名（只读前 limit 条，用于探明 Docker/OCI 布局）。"""
    stream = None
    names = []
    try:
        stream = _open_tar_stream(blob, comp)
        tf = tarfile.open(fileobj=stream, mode="r|")
        try:
            for m in tf:
                names.append(m.name)
                if len(names) >= limit:
                    break
        finally:
            tf.close()
    except Exception:
        return names
    finally:
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass
    return names


def _sibling_fmt(path):
    if not path:
        return None
    base = os.path.splitext(path)[0]
    for cand in (path + ".fmt", path + ".FMT", base + ".fmt", base + ".FMT"):
        if os.path.isfile(cand):
            return cand
    return None


def probe(sub_or_path, fmt_path=None):
    """判型：tar / tar.gz / tar.bz2 / tar.xz / 7z / docker / oci / bcp / miui-bak / unknown"""
    if isinstance(sub_or_path, (str, bytes, os.PathLike)):
        p = os.fsdecode(sub_or_path)
        if os.path.isdir(p):
            names = set()
            for entry in os.listdir(p):
                names.add(entry)
            if "oci-layout" in names or "index.json" in names:
                return "oci"
            if "manifest.json" in names:
                return "docker"
            return "unknown"
    blob = _Blob(sub_or_path)
    try:
        head = blob.read(0, 512)
        if head[:6] == SEVENZ_SIG:
            return "7z"
        comp = _tar_compression(blob)
        if comp is not None:
            if comp == "zstd":
                raise NotImplementedError(
                    "zstd 压缩归档：Python 3.11 标准库无 zstd，本模块不引第三方依赖")
            names = _tar_names(blob, comp)
            if names:
                if "manifest.json" in names:
                    return "docker"
                if "oci-layout" in names or ("index.json" in names and any(
                        n.startswith("blobs/") for n in names)):
                    return "oci"
                if any(n.rsplit("/", 1)[-1].lower() == "descriptor.xml"
                       for n in names):
                    return "miui-bak"
                return {"gzip": "tar.gz", "bzip2": "tar.bz2",
                        "xz": "tar.xz"}[comp]
        if _is_tar_header(head):
            names = _tar_names(blob, None)
            if "manifest.json" in names:
                return "docker"
            if "oci-layout" in names or ("index.json" in names and any(
                    n.startswith("blobs/") for n in names)):
                return "oci"
            if any(n.rsplit("/", 1)[-1].lower() == "descriptor.xml" for n in names):
                return "miui-bak"
            return "tar"
        if head[:2] == b"PK":
            names = []
            try:
                zf = zipfile.ZipFile(_SeqFile(blob))
                names = zf.namelist()
                zf.close()
            except Exception:
                names = []
            if any(n.rsplit("/", 1)[-1].lower() == "descriptor.xml" for n in names):
                return "miui-bak"
            return "unknown"
        if head.find(b"ustar") > 0:
            return "tar"
        if any(h in head[:256] for h in _MIUI_MAGIC_HINTS):
            return "miui-bak"
        path = blob.path
        if fmt_path or _sibling_fmt(path):
            return "bcp"
        if path and os.path.splitext(path)[1].lower() in (".fmt",):
            return "bcp"
        if head and b"\x00" not in blob.read(0, 4096):
            return "bcp"
        return "unknown"
    finally:
        blob.close()


def open_archive(path, **kw):
    """按 probe 结果返回对应对象，统一暴露 names() / info() / read() / walk()。"""
    kind = probe(path, kw.pop("fmt_path", None))
    if kind in ("tar", "tar.gz", "tar.bz2", "tar.xz"):
        return TarArchive(path, **kw)
    if kind == "7z":
        return SevenZip(path, **kw)
    if kind in ("docker", "oci"):
        return DockerImage(path, **kw)
    if kind == "bcp":
        return BcpFile(path, **kw)
    if kind == "miui-bak":
        return MiuiBak(path, **kw)
    raise ValueError("无法判型的归档：%r（probe=%s）" % (path, kind))


# ---------------- 自检 ----------------


def _seven_zip_exe():
    cands = [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe",
             "/usr/bin/7z", "/usr/local/bin/7z", "/opt/homebrew/bin/7z"]
    for c in cands:
        if os.path.isfile(c):
            return c
    return shutil.which("7z") or shutil.which("7za")


def _run_7z(exe, args, cwd=None):
    try:
        p = subprocess.run([exe] + args, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except OSError as exc:
        return -1, str(exc)


def _varint(n):
    """7z 可变长整数的编码（解码器的逆），用于手工构造样本。"""
    if n < 0x80:
        return bytes([n])
    for e in range(1, 8):
        high = n >> (8 * e)
        if high < (1 << (7 - e)):
            out = bytearray([((0xFF << (8 - e)) & 0xFF) | high])
            for i in range(e):
                out.append((n >> (8 * i)) & 0xFF)
            return bytes(out)
    raise ValueError("数值 %d 超出 7z 变长整数表达范围" % n)


def _build_copy_7z(payload, name="hello.txt"):
    """手工构造一个 Copy（不压缩）编码的最小 7z，不依赖任何外部程序。"""
    name_block = name.encode("utf-16-le") + b"\x00\x00"
    body = bytearray()
    body.append(K_HEADER)
    body.append(K_MAIN_STREAMS)
    body.append(K_PACK_INFO)
    body += _varint(0)                    # packPos
    body += _varint(1)                    # numPackStreams
    body.append(K_SIZE)
    body += _varint(len(payload))
    body.append(K_END)
    body.append(K_UNPACK_INFO)
    body.append(K_FOLDER)
    body += _varint(1)                    # numFolders
    body.append(0)                        # external = 0
    body += _varint(1)                    # numCoders
    body.append(0x01)                     # id 长 1，非复杂，无属性
    body.append(M_COPY)
    body.append(K_CODERS_UNPACK_SIZE)
    body += _varint(len(payload))
    body.append(K_CRC)
    body.append(1)                        # AllAreDefined（该段没有数量字段）
    body += struct.pack("<I", _crc32(payload))
    body.append(K_END)                    # 结束 kUnPackInfo
    body.append(K_END)                    # 结束 kMainStreamsInfo
    body.append(K_FILES_INFO)
    body += _varint(1)                    # numFiles
    body.append(K_NAME)
    body += _varint(len(name_block) + 1)  # 属性长度含 external 字节
    body.append(0)                        # external = 0
    body += name_block
    body.append(K_END)                    # 结束 kFilesInfo
    body.append(K_END)                    # 结束 kHeader
    nh = bytes(body)
    sig = bytearray(SEVENZ_SIG)
    sig += bytes([0, 4])
    start = struct.pack("<QQI", len(payload), len(nh), _crc32(nh))
    sig += struct.pack("<I", _crc32(start))
    sig += start
    return bytes(sig) + payload + nh


def _build_tar_sample(tmp):
    """GNU 头：同名覆盖 + 中文 + 符号链接 + 超长名（@LongLink）。"""
    path = os.path.join(tmp, "sample.tar")
    old = b"OLD VERSION\n" * 10
    new = b"NEW VERSION\n" * 20
    cjk = "中文内容 UTF-8 测试\n".encode("utf-8")
    long_name = "deep/" + ("n" * 180) + ".bin"
    long_payload = b"LONG-NAME-PAYLOAD"
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tf:
        for payload in (old, new):
            ti = tarfile.TarInfo("logs/app.log")
            ti.size = len(payload)
            ti.mtime = 1700000000
            ti.mode = 0o644
            ti.uid, ti.gid = 1000, 1000
            ti.uname, ti.gname = "analyst", "analyst"
            tf.addfile(ti, io.BytesIO(payload))
        d = tarfile.TarInfo("数据")
        d.type = tarfile.DIRTYPE
        d.mode = 0o755
        d.mtime = 1700000001
        tf.addfile(d)
        t = tarfile.TarInfo("数据/中文文件.txt")
        t.size = len(cjk)
        t.mtime = 1700000002
        t.mode = 0o600
        tf.addfile(t, io.BytesIO(cjk))
        ln = tarfile.TarInfo("link-to-log")
        ln.type = tarfile.SYMTYPE
        ln.linkname = "logs/app.log"
        ln.mtime = 1700000003
        tf.addfile(ln)
        lt = tarfile.TarInfo(long_name)
        lt.size = len(long_payload)
        lt.mtime = 1700000004
        tf.addfile(lt, io.BytesIO(long_payload))
    return path, {"old": old, "new": new, "cjk": cjk, "long_name": long_name,
                  "long": long_payload}


def _build_pax_sample(tmp):
    path = os.path.join(tmp, "sample_pax.tar")
    name = "pax/" + ("长" * 60) + ".txt"
    payload = "PAX 头内容\n".encode("utf-8")
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        ti = tarfile.TarInfo(name)
        ti.size = len(payload)
        ti.mtime = 1700000005
        ti.pax_headers = {"comment": "ESK selftest", "mtime": "1700000005.5"}
        tf.addfile(ti, io.BytesIO(payload))
    return path, name, payload


def _layer_tar(entries):
    """entries: [(name, bytes|None, mode)]，None 表示目录。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, payload, mode in entries:
            ti = tarfile.TarInfo(name)
            ti.mode = mode
            ti.mtime = 1700000100
            if payload is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
    return buf.getvalue()


def _build_docker_sample(tmp):
    l1 = _layer_tar([
        ("etc/app.conf", b"v1\n", 0o644),
        ("bin/tool", b"tool-v1", 0o755),
        ("var/log/old.log", b"old-log", 0o644),
        ("opt/cache/c1.bin", b"c1", 0o644),
    ])
    l2 = _layer_tar([
        ("etc/app.conf", b"v2\n", 0o644),
        ("app/new.txt", b"new-file", 0o644),
        ("var/log/.wh.old.log", b"", 0o644),
        ("opt/.wh..wh..opq", b"", 0o644),
        ("opt/cache/c2.bin", b"c2", 0o644),
    ])
    config = {
        "architecture": "amd64", "os": "linux",
        "created": "2024-03-01T10:00:00Z",
        "config": {"Labels": {"maintainer": "ESK"}, "WorkingDir": "/app",
                   "Env": ["PATH=/usr/bin"]},
        "history": [
            {"created": "2024-03-01T10:00:00Z", "created_by": "ADD rootfs l1"},
            {"created": "2024-03-01T10:00:01Z", "created_by": "/bin/sh -c #(nop) WORKDIR /app",
             "empty_layer": True},
            {"created": "2024-03-01T10:00:02Z", "created_by": "ADD l2"},
        ],
        "rootfs": {"type": "layers", "diff_ids": []},
    }
    cfg_name = "cfg.json"
    manifest = [{"Config": cfg_name, "RepoTags": ["esk/sample:1.0"],
                 "Layers": ["l1/layer.tar", "l2/layer.tar"]}]
    path = os.path.join(tmp, "docker-save.tar")
    with tarfile.open(path, "w") as tf:
        for name, data in (("manifest.json", json.dumps(manifest).encode()),
                           (cfg_name, json.dumps(config).encode()),
                           ("l1/layer.tar", l1), ("l2/layer.tar", l2)):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1700000200
            tf.addfile(ti, io.BytesIO(data))
    return path, {"l1": l1, "l2": l2}


def _build_oci_sample(tmp):
    """OCI image layout 目录：index.json + oci-layout + blobs/sha256/*"""
    l1 = _layer_tar([("etc/app.conf", b"oci-v1\n", 0o644),
                     ("opt/cache/old.bin", b"oci-old", 0o644)])
    l2 = _layer_tar([("etc/app.conf", b"oci-v2\n", 0o644),
                     ("opt/.wh..wh..opq", b"", 0o644),
                     ("opt/cache/new.bin", b"oci-new", 0o644)])
    config = {"architecture": "amd64", "os": "linux",
              "created": "2024-04-01T00:00:00Z",
              "config": {"Labels": {"oci": "yes"}},
              "history": [{"created": "2024-04-01T00:00:00Z",
                           "created_by": "OCI layer 1"},
                          {"created": "2024-04-01T00:00:01Z",
                           "created_by": "OCI layer 2"}]}
    root = os.path.join(tmp, "oci-layout")

    def put(data):
        h = hashlib.sha256(data).hexdigest()
        d = os.path.join(root, "blobs", "sha256")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, h), "wb") as f:
            f.write(data)
        return "sha256:" + h

    cfg_digest = put(json.dumps(config).encode())
    layers = [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
               "digest": put(l1), "size": len(l1)},
              {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
               "digest": put(gzip.compress(l2)), "size": len(gzip.compress(l2))}]
    man = {"schemaVersion": 2,
           "mediaType": "application/vnd.oci.image.manifest.v1+json",
           "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                      "digest": cfg_digest, "size": len(json.dumps(config))},
           "layers": layers}
    man_digest = put(json.dumps(man).encode())
    index = {"schemaVersion": 2,
             "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": man_digest, "size": 100}]}
    with open(os.path.join(root, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f)
    with open(os.path.join(root, "oci-layout"), "w", encoding="utf-8") as f:
        json.dump({"imageLayoutVersion": "1.0.0"}, f)
    return root


def _build_bcp_sample(tmp):
    fmt_text = (
        "10.0\n"
        "5\n"
        '1\tSQLINT\t0\t4\t"\\t"\t1\tid\t""\n'
        '2\tSQLVARCHAR\t0\t20\t"\\t"\t2\tname\t""\n'
        '3\tSQLDECIMAL\t0\t10\t"\\t"\t3\tamount\t""\n'
        '4\tSQLDATETIME\t0\t19\t"\\t"\t4\tcreated\t""\n'
        '5\tSQLBIGINT\t0\t8\t"\\r\\n"\t5\tts\t""\n'
    )
    data = (b"1\tAlice\t12.50\t2024-03-01 10:00:00\t1000\r\n"
            b"2\t" + "中文".encode("utf-8") + b"\t0.00\t2024-03-02 00:00:00\t2000\r\n"
            b"3\t\t3.14\t2024-03-03 12:34:56\t3000\r\n")
    fmt_path = os.path.join(tmp, "rows.fmt")
    dat_path = os.path.join(tmp, "rows.dat")
    with open(fmt_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(fmt_text)
    with open(dat_path, "wb") as f:
        f.write(data)
    pipe = os.path.join(tmp, "pipes.txt")
    with open(pipe, "wb") as f:
        f.write(b"10|red|1.5\n11|green|2.5\n12|blue|3.5\n")
    # 原生（定长二进制）模式：int/bigint/datetime/decimal 全部按固定宽度拼字节
    nfmt = ("10.0\n"
            "4\n"
            '1\tSQLINT\t0\t4\t""\t1\tid\t""\n'
            '2\tSQLBIGINT\t0\t8\t""\t2\tbig\t""\n'
            '3\tSQLDATETIME\t0\t8\t""\t3\tdt\t""\n'
            '4\tSQLDECIMAL\t0\t5\t""\t4\tamt\t""\n')
    days = (datetime.date(2024, 3, 1) - datetime.date(1900, 1, 1)).days
    ticks = int((10 * 3600 + 30 * 60) * 300)
    binrow = (struct.pack("<i", 7) + struct.pack("<q", 9000000000)
              + struct.pack("<iI", days, ticks)
              + bytes([1, 2]) + (1234).to_bytes(3, "little"))
    nfmt_path = os.path.join(tmp, "native.fmt")
    nbin_path = os.path.join(tmp, "native.dat")
    with open(nfmt_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(nfmt)
    with open(nbin_path, "wb") as f:
        f.write(binrow)
    return dat_path, fmt_path, pipe, (nbin_path, nfmt_path)


def _build_miui_samples(tmp):
    desc = ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<bak version="2">\n'
            '  <br packageName="com.tencent.mm" appName="微信" backupType="1"/>\n'
            '  <br packageName="com.android.chrome" appName="Chrome"/>\n'
            '</bak>\n')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("descriptor.xml", desc)
        zf.writestr("apps/com.tencent.mm/r/a/msg.db", b"SQLite-format-3-fake")
        zf.writestr("apps/com.android.chrome/f/Bookmarks", b"<bookmarks/>")
        zf.writestr("apps/com.tencent.mm/manifest.xml", b"<manifest/>")
        zf.writestr("misc/empty.txt", b"")
    prefix = b"MIUI_BAK\x00\x01" + b"\x00" * 8
    plain = os.path.join(tmp, "miui_plain.bak")
    with open(plain, "wb") as f:
        f.write(prefix + buf.getvalue())
    enc_desc = ('<?xml version="1.0" encoding="utf-8"?>\n<bak version="2">\n'
                '  <password>AbCdEf0123456789</password>\n'
                '  <br packageName="com.tencent.mm"/>\n</bak>\n')
    buf2 = io.BytesIO()
    with zipfile.ZipFile(buf2, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("descriptor.xml", enc_desc)
        zf.writestr("apps/com.tencent.mm/data.bin", b"\x00" * 32)
    enc = os.path.join(tmp, "miui_locked.bak")
    with open(enc, "wb") as f:
        f.write(prefix + buf2.getvalue())
    tarred = os.path.join(tmp, "miui_tarred.bak")
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        for name, payload in (("descriptor.xml", desc.encode("utf-8")),
                              ("apps/com.tencent.mm/r/a/msg.db",
                               b"SQLite-format-3-fake"),
                              ("apps/com.tencent.mm/manifest.xml", b"<manifest/>")):
            ti = tarfile.TarInfo(name)
            ti.size = len(payload)
            tf.addfile(ti, io.BytesIO(payload))
    with open(tarred, "wb") as f:
        f.write(tar_buf.getvalue())
    return plain, enc, tarred, prefix


def _selftest():
    tmp = tempfile.mkdtemp(prefix="esk_archive_")
    notes = []
    try:
        # ---- 1. TAR ----
        tar_path, exp = _build_tar_sample(tmp)
        ta = TarArchive(tar_path)
        assert ta.compression is None, ta.compression
        names = ta.names()
        assert names.count("logs/app.log") == 2, names
        first, second = ta.info_all("logs/app.log")
        assert first.offset < second.offset, (first.offset, second.offset)
        assert first.superseded is True and first.live is False
        assert second.superseded is False and second.live is True
        assert second.duplicate is True
        assert second.duplicate_of == first.index
        assert second.supersedes == [first.index]
        assert first.size == len(exp["old"]) and second.size == len(exp["new"])
        assert ta.read("logs/app.log") == exp["new"]
        assert ta.read("logs/app.log", occurrence=1) == exp["old"]
        assert ta.read("数据/中文文件.txt") == exp["cjk"]
        assert ta.read(exp["long_name"]) == exp["long"]
        assert ta.info("link-to-log").type == "symlink"
        assert ta.info("link-to-log").linkname == "logs/app.log"
        assert ta.info("数据").type == "dir"
        assert ta.info(exp["long_name"]).type == "file"
        raw = open(tar_path, "rb").read()
        assert raw[first.offset_data:first.offset_data + first.size] == exp["old"]
        assert raw[second.offset_data:second.offset_data + second.size] == exp["new"]
        assert ta.members[0].offset == 0, ta.members[0].offset
        summ = ta.summary()
        assert summ["duplicate_members"] == 1, summ
        assert summ["members"] == 6, summ
        assert probe(tar_path) == "tar", probe(tar_path)
        assert len(list(ta.walk(live_only=True))) == 5
        print("TAR 自检通过: %s members=%d dup=%d 首偏移=%d 次偏移=%d"
              % (os.path.basename(tar_path), summ["members"],
                 summ["duplicate_members"], first.offset, second.offset))

        # ---- 2. TAR.GZ / BZ2 / XZ ----
        for mode, kind in (("w:gz", "gzip"), ("w:bz2", "bzip2"), ("w:xz", "xz")):
            comp_path = os.path.join(tmp, "sample_%s.tar" % kind)
            with tarfile.open(comp_path, mode) as dst:
                with tarfile.open(tar_path) as src:
                    for m in src.getmembers():
                        f = src.extractfile(m) if m.isreg() else None
                        dst.addfile(m, f)
            ca = TarArchive(comp_path)
            assert ca.compression == kind, (kind, ca.compression)
            assert len(ca.members) == 6, (kind, len(ca.members))
            assert ca.read("logs/app.log") == exp["new"]
            assert ca.read(exp["long_name"]) == exp["long"]
            assert ca.summary()["offset_basis"].startswith("解压后流内偏移")
            want = {"gzip": "tar.gz", "bzip2": "tar.bz2", "xz": "tar.xz"}[kind]
            assert probe(comp_path) == want, (kind, probe(comp_path))
        print("TAR.GZ / TAR.BZ2 / TAR.XZ 自检通过: 各 6 成员，重复名与新版本内容一致")

        # ---- 2b. PAX 头 ----
        pax_path, pax_name, pax_payload = _build_pax_sample(tmp)
        pa = TarArchive(pax_path)
        assert pa.names() == [pax_name], pa.names()
        assert pa.read(pax_name) == pax_payload
        assert pa.info(pax_name).mtime_iso is not None
        print("TAR PAX 自检通过: 长中文名 %d 字符 + pax_headers 还原" % len(pax_name))

        # ---- 3. 7z：手工 Copy 样本（恒定可跑）----
        copy_path = os.path.join(tmp, "handmade_copy.7z")
        payload = b"ESK handmade 7z copy payload\n" * 3
        with open(copy_path, "wb") as f:
            f.write(_build_copy_7z(payload, "hello.txt"))
        hz = SevenZip(copy_path)
        assert hz.names() == ["hello.txt"], hz.names()
        assert hz.read("hello.txt") == payload
        assert hz.summary()["start_header_crc_ok"] is True
        assert hz.summary()["next_header_crc_ok"] is True
        assert hz.info("hello.txt").size == len(payload)
        print("7z(手工 Copy) 自检通过: %d 字节，startHeaderCRC/nextHeaderCRC 均校验通过"
              % len(payload))

        # ---- 3b. 7z：本机 7-Zip 真样本 ----
        exe = _seven_zip_exe()
        seven_ok = []
        if not exe:
            notes.append("7z: 本机无 7-Zip 可执行文件，LZMA/LZMA2/BCJ 路径未用真实样本验证")
            print("7z: 找不到 7z 可执行文件，仅验证手工 Copy 样本")
        else:
            src_dir = os.path.join(tmp, "7zsrc")
            os.makedirs(src_dir)
            big = bytes(range(256)) * 40
            files = {
                "a.txt": b"alpha alpha alpha\n" * 30,
                "sub/b.txt": b"bravo\n" * 7,
                "中文.txt": "中文压缩内容\n".encode("utf-8"),
                "empty.txt": b"",
                "big.bin": big,
            }
            for rel, data in files.items():
                p = os.path.join(src_dir, *rel.split("/"))
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "wb") as f:
                    f.write(data)
            targets = ["a.txt", "sub", "中文.txt", "empty.txt", "big.bin"]

            def make(tag, extra, only=None):
                out = os.path.join(tmp, "real_%s.7z" % tag)
                if os.path.exists(out):
                    os.remove(out)
                args = ["a", "-t7z", out] + extra + (only or targets)
                return _run_7z(exe, args, cwd=src_dir)

            for tag, extra in (("lzma2", ["-m0=LZMA2", "-mx=5"]),
                               ("lzma1", ["-m0=LZMA", "-mx=3"]),
                               ("copy", ["-m0=copy"]),
                               ("solid", ["-m0=LZMA2", "-ms=on", "-mx=5"])):
                rc, out = make(tag, extra)
                path = os.path.join(tmp, "real_%s.7z" % tag)
                assert rc == 0 and os.path.isfile(path), (tag, rc, out[-400:])
                sz = SevenZip(path)
                got = sorted(n for n in sz.names() if not n.endswith("/"))
                for rel, data in files.items():
                    assert sz.read(rel) == data, (tag, rel)
                assert sz.info("empty.txt").size == 0
                assert sz.summary()["start_header_crc_ok"] is True
                assert sz.summary()["next_header_crc_ok"] is True
                assert probe(path) == "7z"
                assert sz.read("中文.txt") == files["中文.txt"]
                seven_ok.append("%s(%s)" % (tag, "+".join(sz.summary()["methods"])))
                if tag == "lzma2":
                    assert sz.read("big.bin") == big
            # BCJ + LZMA2：可执行文件式过滤器链
            rc, out = make("bcj", ["-m0=BCJ", "-m1=LZMA2", "-mx=5"], only=["big.bin"])
            path = os.path.join(tmp, "real_bcj.7z")
            if rc == 0 and os.path.isfile(path):
                try:
                    sz = SevenZip(path)
                    assert sz.read("big.bin") == big
                    seven_ok.append("bcj(%s)" % "+".join(sz.summary()["methods"]))
                except NotImplementedError as exc:
                    notes.append("7z BCJ 链未解开（该方法未验证）: %s" % exc)
            else:
                notes.append("7z BCJ 样本生成失败，BCJ 过滤器链未用真实样本验证")
            # 加密：成员加密（头仍可读）与头加密
            rc, out = _run_7z(exe, ["a", "-t7z", "-pESK123", "-m0=LZMA2",
                                    os.path.join(tmp, "real_aes.7z"), "a.txt"],
                              cwd=src_dir)
            aes_path = os.path.join(tmp, "real_aes.7z")
            if rc == 0 and os.path.isfile(aes_path):
                sz = SevenZip(aes_path)
                assert sz.summary()["encrypted"] is True, sz.summary()
                try:
                    sz.read("a.txt")
                except NotImplementedError as exc:
                    assert "AES-256" in str(exc)
                    notes.append("7z AES-256 成员加密：正确抛 NotImplementedError")
                else:
                    raise AssertionError("AES 成员未抛 NotImplementedError")
            rc, out = _run_7z(exe, ["a", "-t7z", "-pESK123", "-mhe=on", "-m0=LZMA2",
                                    os.path.join(tmp, "real_aes_head.7z"), "a.txt"],
                              cwd=src_dir)
            head_path = os.path.join(tmp, "real_aes_head.7z")
            if rc == 0 and os.path.isfile(head_path):
                try:
                    SevenZip(head_path)
                except NotImplementedError as exc:
                    assert "头已加密" in str(exc)
                    notes.append("7z AES-256 头加密：构造即抛 NotImplementedError")
                else:
                    raise AssertionError("加密头未抛 NotImplementedError")
            print("7z(真样本) 自检通过: %s" % ", ".join(seven_ok))

        # ---- 4. Docker save ----
        docker_path, _parts = _build_docker_sample(tmp)
        img = DockerImage(docker_path)
        assert img.kind == "docker", img.kind
        layers = img.layers()
        assert len(layers) == 2, len(layers)
        assert layers[0].created_by == "ADD rootfs l1", layers[0].created_by
        assert layers[1].created_by == "ADD l2", layers[1].created_by
        assert layers[1].modified == 1, layers[1].modified
        assert layers[1].deleted == 2, layers[1].deleted
        assert layers[1].opaque == 1, layers[1].opaque
        ch2 = {(c.path, c.change) for c in img.layer_changes(1)}
        assert ("etc/app.conf", "modify") in ch2, ch2
        assert ("app/new.txt", "add") in ch2, ch2
        assert ("var/log/old.log", "delete") in ch2, ch2
        assert ("opt/cache/c1.bin", "opaque") in ch2, ch2
        assert ("opt/cache/c2.bin", "add") in ch2, ch2
        ch1 = {(c.path, c.change) for c in img.layer_changes(0)}
        assert ("etc/app.conf", "add") in ch1, ch1
        l1_view = {f.path for f in img.files(0)}
        assert "var/log/old.log" in l1_view and "opt/cache/c1.bin" in l1_view
        final = {f.path for f in img.files()}
        assert "var/log/old.log" not in final, final
        assert "opt/cache/c1.bin" not in final, final
        assert "opt/cache/c2.bin" in final and "app/new.txt" in final
        assert img.read("etc/app.conf") == b"v2\n"
        assert img.read("bin/tool") == b"tool-v1"
        hist = img.history()
        assert len(hist) == 3 and hist[1].empty_layer is True
        assert hist[2].created_by == "ADD l2"
        assert img.image_info()["repo_tags"] == ["esk/sample:1.0"]
        assert img.image_info()["labels"] == {"maintainer": "ESK"}
        assert probe(docker_path) == "docker", probe(docker_path)
        print("Docker 自检通过: 2 层，L2 add=%d modify=%d delete=%d opaque=%d，"
              "最终视图 %d 项"
              % (layers[1].added, layers[1].modified, layers[1].deleted,
                 layers[1].opaque, len(final)))

        # ---- 4b. OCI layout（目录形态）----
        oci_root = _build_oci_sample(tmp)
        oci = DockerImage(oci_root)
        assert oci.kind == "oci", oci.kind
        ol = oci.layers()
        assert len(ol) == 2, len(ol)
        och = {(c.path, c.change) for c in oci.layer_changes(1)}
        assert ("opt/cache/old.bin", "opaque") in och, och
        assert ("opt/cache/new.bin", "add") in och, och
        assert oci.read("etc/app.conf") == b"oci-v2\n"
        assert "opt/cache/old.bin" not in {f.path for f in oci.files()}
        assert probe(oci_root) == "oci", probe(oci_root)
        print("OCI 自检通过: 2 层，白化 + opaque 生效，config label=%r"
              % oci.image_info()["labels"])

        # ---- 5. BCP ----
        dat_path, fmt_path, pipe_path, native = _build_bcp_sample(tmp)
        bc = BcpFile(dat_path, fmt=fmt_path)
        from decimal import Decimal
        rows = bc.rows()
        assert len(rows) == 3, rows
        assert rows[0][0] == 1 and isinstance(rows[0][0], int)
        assert rows[0][1] == "Alice"
        assert rows[0][2] == Decimal("12.50"), rows[0][2]
        assert isinstance(rows[0][3], datetime.datetime)
        assert rows[0][3] == datetime.datetime(2024, 3, 1, 10, 0, 0)
        assert rows[0][4] == 1000 and isinstance(rows[0][4], int)
        assert rows[1][1] == "中文", rows[1][1]
        assert rows[2][1] is None, rows[2][1]
        assert bc.names() == ["id", "name", "amount", "created", "ts"]
        assert bc.inferred is False and bc.mode == "char"
        assert bc.info("amount").family == "decimal"
        recs = list(bc.records())
        assert recs[2]["name"] is None and recs[2]["amount"] == Decimal("3.14")
        assert len(bc) == 3
        assert probe(dat_path) == "bcp", probe(dat_path)
        assert isinstance(open_archive(dat_path), BcpFile)
        # 无 .fmt 的启发式
        inf = BcpFile(pipe_path)
        assert inf.inferred is True and inf.confidence == 1.0, inf.confidence
        assert inf.delimiter == b"|"
        assert [r[0] for r in inf.rows()] == [10, 11, 12]
        assert [r[1] for r in inf.rows()] == ["red", "green", "blue"]
        assert inf.rows()[0][2] == Decimal("1.5")
        print("BCP 自检通过: .fmt 3 行 5 列（含 NULL / 中文 / Decimal / datetime），"
              "启发式分隔符=%r 置信度=%.2f 列数=%d"
              % (inf.delimiter, inf.confidence, len(inf.columns)))
        # 原生（定长二进制）模式
        nbin_path, nfmt_path = native
        nb = BcpFile(nbin_path, fmt=nfmt_path)
        assert nb.mode == "native", nb.mode
        nrows = nb.rows()
        assert len(nrows) == 1, nrows
        assert nrows[0][0] == 7 and isinstance(nrows[0][0], int)
        assert nrows[0][1] == 9000000000
        assert nrows[0][2] == datetime.datetime(2024, 3, 1, 10, 30, 0), nrows[0][2]
        assert nrows[0][3] == Decimal("12.34"), nrows[0][3]
        print("BCP 原生模式自检通过: 定长 int/bigint/datetime/decimal → %r"
              % (nrows[0],))

        # ---- 6. 小米 .bak ----
        plain, locked, tarred, miui_prefix = _build_miui_samples(tmp)
        mb = MiuiBak(plain)
        assert mb.container == "zip", mb.container
        assert mb.prefix_offset == len(miui_prefix), (mb.prefix_offset, len(miui_prefix))
        assert mb.descriptor_name == "descriptor.xml"
        assert mb.encrypted is False
        apps = {a.package for a in mb.apps()}
        assert apps == {"com.tencent.mm", "com.android.chrome"}, apps
        pay = b"SQLite-format-3-fake"
        assert mb.read("apps/com.tencent.mm/r/a/msg.db") == pay
        assert mb.info("apps/com.tencent.mm/r/a/msg.db").size == len(pay)
        assert "misc/empty.txt" in mb.names()
        assert probe(plain) == "miui-bak", probe(plain)
        assert isinstance(open_archive(plain), MiuiBak)
        try:
            MiuiBak(locked)
        except NotImplementedError as exc:
            assert "加密" in str(exc)
        else:
            raise AssertionError("加密 .bak 未抛 NotImplementedError")
        print("小米 .bak 自检通过: 容器=%s 前置头=%d 字节 apps=%d descriptor=%s"
              % (mb.container, mb.prefix_offset, len(apps), mb.descriptor_name))
        # tar 形态的小米备份
        mt = MiuiBak(tarred)
        assert mt.container == "tar", mt.container
        assert mt.descriptor_name == "descriptor.xml"
        assert {a.package for a in mt.apps()} == {"com.tencent.mm",
                                                  "com.android.chrome"}
        picked = [a for a in mt.apps() if a.files]
        assert len(picked) == 1 and picked[0].package == "com.tencent.mm"
        assert picked[0].files == 2, picked[0].files
        assert mt.read("apps/com.tencent.mm/r/a/msg.db") == pay
        assert probe(tarred) == "miui-bak", probe(tarred)
        print("小米 .bak(tar 形态) 自检通过: apps=%d descriptor 正常"
              % len(mt.apps()))

        # ---- 7. 判型兜底与工厂分发 ----
        assert isinstance(open_archive(tar_path), TarArchive)
        assert isinstance(open_archive(os.path.join(tmp, "sample_gzip.tar")), TarArchive)
        assert isinstance(open_archive(copy_path), SevenZip)
        assert isinstance(open_archive(docker_path), DockerImage)
        assert isinstance(open_archive(oci_root), DockerImage)
        assert open_archive(docker_path).kind == "docker"
        assert open_archive(oci_root).kind == "oci"
        junk = os.path.join(tmp, "junk.bin")
        with open(junk, "wb") as f:
            f.write(b"\x00\x01\x02\x03random" * 10)
        assert probe(junk) == "unknown", probe(junk)
        try:
            open_archive(junk)
        except ValueError:
            pass
        else:
            raise AssertionError("unknown 类型未抛 ValueError")
        print("判型兜底自检通过: 未知数据 → probe=unknown / open_archive 抛 ValueError")

        print("")
        print("口径说明（哪些路径没有真实样本验证）:")
        if notes:
            for n in notes:
                print("  · " + n)
        else:
            print("  · 无：全部路径均由真实工具/真实格式样本验证")
        print("  · 小米 .bak：样本为按公开特征手工构造（MIUI 前置头 + zip），"
              "未使用真实手机备份")
        print("  · BCP：样本按 SQL Server .fmt 规则构造，未使用真实 bcp 导出文件")
        print("  · Docker/OCI：样本按 docker save / OCI image-spec 手工构造")
        print("")
        print("archive 模块自检全部通过")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    _selftest()
