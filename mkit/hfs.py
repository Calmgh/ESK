# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""HFS / HFS+ 文件系统（Mac OS 标准卷，含 HFSX 大小写敏感变体）

对应 LovelyCarve 的「文件系统」中的 Apple HFS 家族。macOS 安装盘里的
Apple_HFS 分区、Time Machine 备份盘、老款 iPod、Mac 移动硬盘都是这个格式；
APFS 之前的 Mac 检材（10.12 及更早的系统盘、.dmg 分发包）基本全是 HFS+。

只依赖可读对象 sub.read(offset, size) / sub.size，不 import 第三方库。

已实现（HFS+ / HFSX）：
    · 卷头 HFSPlusVolumeHeader @1024（'H+' / 'HX'）；主卷头损坏时自动回退到
      卷尾 1024 处的备份卷头，并在 info() 里标出用的是哪一份
    · 五个特殊文件 fork：allocation / extents / catalog / attributes / startup
      （attributes 与 startup 只报位置和大小，不解析内容）
    · fork 按 extent 表读取；fragment 超过 8 段时查 extents overflow B-tree 续链
    · Catalog B-tree：节点描述符、BTHeaderRec、索引节点下钻、叶子链遍历、
      记录偏移表（表在节点尾部、逆序）、键比较（大小写折叠近似 HFS+ 的
      FastUnicodeCompare）
    · 目录项三类：文件夹(1)/文件(2)/线程(3,4)；UTF-16BE 名字、CNID、POSIX
      权限、Finder 信息、五个时间戳（HFS 1904 纪元）
    · 数据 fork 与资源 fork 双流读取；目录遍历、按名字/按路径查找
    · 卷名（根目录线程记录）、日志区位置、分配位图与未分配块区间
    · 目录项在镜像中的绝对偏移 rec_off，便于雕刻与交叉验证

部分实现：
    · deleted()：HFS+ 删除目录项时会把它从 B-tree 中摘除并合并/回收节点，
      磁盘上不存在 FAT 的 0xE5 那样的删除标记。这里只能做「未链接项」尽力
      检测：catalog 中存在记录、却无法从根目录按名字链到达的条目。真正被
      删除的旧条目要靠 B-tree 节点残余 / 未分配块雕刻，本模块不做。
    · children()/walk() 走的是「整表索引」：首次列目录时把整个 catalog
      读一遍建 {parentID: [HfsEntry]}，之后每个目录 O(1) 取表。几十万条
      记录的卷会占用可观内存（目录项常驻），换来遍历不被逐目录全表扫描拖死。

不实现（HFS+，明确未做）：
    · 任何写操作、journal 重放、Hot File 重定向、硬链接链语义
    · attributes B-tree 的扩展属性内容（只报 fork 位置与大小）
    · 压缩文件（AFS 压缩 / decmpfs）解压、Spotlight 索引、目录计数修复
    · HFS+ 的 B-tree 节点校验（nodeSize 与 fork 长度不整除时按容错处理）

HFS 经典（HFS Standard / Mac OS Standard，签名 'BD'）：
    · 已实现：MDB @1024 字段解析、卷名（MacRoman Pascal 串）、分配块参数、
      文件/目录计数、HFS+ wrapper 内嵌卷定位 embedded_volume()
    · 未实现：经典 HFS 的目录遍历与文件读取。Catalog B-tree 的键是
      parentID + 31 字节 MacRoman 名，与 HFS+ 的 HFSUniStr255 键完全不同，
      本模块不解析。listdir() 会抛 NotImplementedError——请优先用
      embedded_volume() 找到 wrapper 里的 HFS+ 卷再交给 HfsPlus。
"""

import datetime
import struct

__all__ = [
    "HfsPlus", "Hfs", "HfsEntry", "Fork",
    "HFS_EPOCH_DELTA", "HFS_PLUS_SIG", "HFSX_SIG", "HFS_SIG",
    "VOLUME_HEADER_OFFSET", "hfs_time", "hfs_to_unix", "unix_to_hfs",
    "probe", "open_volume",
]

# ------------------------------------------------------------
# 常量
# ------------------------------------------------------------
HFS_EPOCH_DELTA = 2082844800        # 1904-01-01 -> 1970-01-01 的秒数
_EPOCH = datetime.datetime(1904, 1, 1)

VOLUME_HEADER_OFFSET = 1024         # 主卷头 / MDB 都在这里
HFS_PLUS_SIG = 0x482B               # 'H+'
HFSX_SIG = 0x4858                   # 'HX'
HFS_SIG = 0x4244                    # 'BD'

# 卷属性位（Apple hfs_format.h 里的 enum 是位号，值是 1<<bit）
VOL_ATTR = {
    0x00000080: "kHFSVolumeHardwareLockBit",
    0x00000100: "kHFSVolumeUnmountedBit",
    0x00000200: "kHFSVolumeSparedBlocksBit",
    0x00000400: "kHFSVolumeNoCacheRequiredBit",
    0x00000800: "kHFSBootVolumeInconsistentBit",
    0x00001000: "kHFSCatalogNodeIDsReusedBit",
    0x00002000: "kHFSVolumeJournaledBit",
    0x00008000: "kHFSVolumeSoftwareLockBit",
    0x40000000: "kHFSContentProtectionBit",
    0x80000000: "kHFSUnusedNodeFixBit",
}

# 文件 / 文件夹记录 flags
REC_FLAGS = {
    0x0001: "kHFSFileLockedBit",
    0x0002: "kHFSThreadExistsBit",
    0x0004: "kHFSHasAttributesBit",
    0x0008: "kHFSHasSecurityBit",
    0x0010: "kHFSHasFolderCountBit",
    0x0020: "kHFSHasLinkChainBit",
    0x0040: "kHFSHasChildLinkBit",
    0x0080: "kHFSHasDateAddedBit",
}

# Catalog 记录类型
REC_FOLDER = 1
REC_FILE = 2
REC_FOLDER_THREAD = 3
REC_FILE_THREAD = 4

# Extents B-tree 的 forkType
FORK_DATA = 0x00
FORK_RSRC = 0xFF

# 特殊 CNID（Apple hfs_format.h）
CNID_ROOT_PARENT = 1
CNID_ROOT_FOLDER = 2
CNID_EXTENTS_FILE = 3
CNID_CATALOG_FILE = 4
CNID_ALLOCATION_FILE = 6
CNID_STARTUP_FILE = 7
CNID_ATTRIBUTES_FILE = 8
SPECIAL_CNIDS = {
    1: "kHFSRootParentID", 2: "kHFSRootFolderID", 3: "kHFSExtentsFileID",
    4: "kHFSCatalogFileID", 5: "kHFSBadBlockFileID", 6: "kHFSAllocationFileID",
    7: "kHFSStartupFileID", 8: "kHFSAttributesFileID",
    14: "kHFSRepairCatalogFileID", 15: "kHFSBogusExtentFileID",
}
CNID_FIRST_USER = 16            # kHFSFirstUserCatalogNodeID


# ------------------------------------------------------------
# 小工具
# ------------------------------------------------------------
def hfs_to_unix(value):
    """HFS 时间戳（1904 纪元，秒）-> Unix 时间戳（1970 纪元，秒）"""
    return int(value) - HFS_EPOCH_DELTA


def unix_to_hfs(value):
    """Unix 时间戳 -> HFS 时间戳"""
    return int(value) + HFS_EPOCH_DELTA


def hfs_time(value):
    """HFS 时间戳(u32) -> 'YYYY-MM-DD HH:MM:SS'（UTC）；0/越界返回 None"""
    if not value:
        return None
    try:
        dt = _EPOCH + datetime.timedelta(seconds=int(value))
    except (OverflowError, ValueError, OSError):
        return None
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _unistr(buf, off, limit=None):
    """HFSUniStr255：u16 字符数 + UTF-16BE 数据。limit 为可用字节数上限"""
    if off + 2 > len(buf):
        return ""
    (n,) = struct.unpack_from(">H", buf, off)
    avail = len(buf) - (off + 2)
    if limit is not None:
        avail = min(avail, max(0, limit - 2))
    n = min(n, avail // 2, 255)
    raw = buf[off + 2:off + 2 + n * 2]
    return raw.decode("utf-16-be", "replace")


def _fold(name):
    """HFS+ 键比较用的折叠（近似 FastUnicodeCompare；非 ASCII 可能不完全一致）"""
    return (name or "").casefold()


def _pascal(buf, off, enc="mac_roman"):
    """Pascal 串（长度字节 + 数据），用于 drVN 这类字段"""
    if off >= len(buf):
        return ""
    n = buf[off]
    raw = buf[off + 1:off + 1 + min(n, 27)]
    try:
        return raw.decode(enc, "replace").strip("\x00 ")
    except Exception:
        return ""


def _attr_text(bits, table):
    return "|".join(v for k, v in sorted(table.items()) if bits & k) or "-"


# ------------------------------------------------------------
# fork（HFSPlusForkData，80 字节）
# ------------------------------------------------------------
class Fork(object):
    """HFSPlusForkData{ logicalSize u64, clumpSize u32, totalBlocks u32,
    extents[8]{startBlock u32, blockCount u32} }"""

    __slots__ = ("logical_size", "clump_size", "total_blocks", "extents", "_segs")

    def __init__(self, logical_size=0, clump_size=0, total_blocks=0, extents=None):
        self.logical_size = logical_size
        self.clump_size = clump_size
        self.total_blocks = total_blocks
        self.extents = list(extents or [])
        self._segs = None            # 解析后的 [(字节偏移, 字节长度)]

    @classmethod
    def parse(cls, buf, off=0):
        if off + 80 > len(buf):
            return cls()
        (logical, clump, total) = struct.unpack_from(">QII", buf, off)
        exts = []
        for i in range(8):
            (st, cnt) = struct.unpack_from(">II", buf, off + 16 + i * 8)
            if cnt:
                exts.append((st, cnt))
        return cls(logical, clump, total, exts)

    def is_empty(self):
        return self.logical_size == 0 and not self.extents

    def __repr__(self):
        return "<Fork %dB %d extents>" % (self.logical_size, len(self.extents))


# ------------------------------------------------------------
# 目录项
# ------------------------------------------------------------
class HfsEntry(object):
    """HFS+ 目录项（文件夹 / 文件），线程记录不单独列给调用方"""

    __slots__ = ("name", "parent_id", "cnid", "is_dir", "record_type",
                 "size", "rsrc_size", "create", "modify", "attr_modify",
                 "access", "backup", "flags", "mode", "uid", "gid",
                 "link_count", "data_fork", "rsrc_fork",
                 "rec_off", "path")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))
        self.path = self.path or self.name

    @property
    def is_special(self):
        return (self.cnid or 0) in SPECIAL_CNIDS

    @property
    def flags_text(self):
        return _attr_text(self.flags or 0, REC_FLAGS)

    @property
    def mode_text(self):
        m = self.mode or 0
        return "%s%03o" % ("d" if self.is_dir else "-", m & 0o777)

    def __repr__(self):
        return "<HfsEntry %r %s %dB cnid=%s%s>" % (
            self.name, "DIR" if self.is_dir else "FILE", self.size or 0,
            self.cnid, " DELETED" if self.rec_off is None else "")


# ------------------------------------------------------------
# B-tree（Catalog / Extents 共用）
# ------------------------------------------------------------
class _BTree(object):
    """HFS+ 的 B 树读取器。

    节点描述符 BTNodeDescriptor{ fLink u32, bLink u32, kind i8, height u8,
    numRecords u16, reserved u16 } = 14 字节。kind 按 Apple BTree.h：
        kBTLeafNode  = -1    叶子
        kBTIndexNode =  0    索引（记录体是 4 字节子节点号）
        kBTHeaderNode=  1    头节点（描述符后紧跟 BTHeaderRec）
        kBTMapNode   =  2    节点分配位图
    记录偏移表放在节点尾部、逆序存放：第 i 条记录的偏移在 nodeSize-2*(i+1)。
    非头节点的偏移 14 处是「空闲空间偏移」，用作最后一条记录的结束位置。
    """

    KIND_LEAF = -1
    KIND_INDEX = 0
    KIND_HEADER = 1
    KIND_MAP = 2

    def __init__(self, fs, fork, name="btree"):
        self.fs = fs
        self.fork = fork
        self.name = name
        self.error = None
        self.node_size = 0
        self.root = 0
        self.first_leaf = 0
        self.last_leaf = 0
        self.depth = 0
        self.leaf_records = 0
        self.total_nodes = 0
        self.key_compare = 0
        self.attributes = 0
        self._cache = {}
        try:
            self._read_header()
        except Exception as e:                       # 树坏了不能让整个卷读不出来
            self.error = "%s: %s" % (name, e)

    # ---- 头节点 ----
    def _read_header(self):
        head = self.fs._fork_read_at(self.fork, 0, 512)
        if len(head) < 64:
            raise ValueError("B-tree 头节点读不到（fork 为空）")
        (ns,) = struct.unpack_from(">H", head, 32)
        if ns < 512 or ns > 65536 or (ns & (ns - 1)):
            ns = 4096
        self.node_size = ns
        node = self.fs._fork_read_at(self.fork, 0, ns)
        if len(node) < 120:
            raise ValueError("头节点不完整")
        (kind,) = struct.unpack_from(">b", node, 8)
        if kind != self.KIND_HEADER:
            raise ValueError("首节点 kind=%d，不是头节点" % kind)
        (self.depth, self.root, self.leaf_records, self.first_leaf,
         self.last_leaf, ns2, _max_key, self.total_nodes, _free,
         _r1, _clump, _btype, self.key_compare, self.attributes) = \
            struct.unpack_from(">HIIIIHHIHHIBBI", node, 14)
        if 512 <= ns2 <= 65536 and not (ns2 & (ns2 - 1)):
            self.node_size = ns2

    # ---- 节点 ----
    def node(self, n):
        if n < 0 or (self.total_nodes and n >= self.total_nodes):
            return b""
        hit = self._cache.get(n)
        if hit is not None:
            return hit
        data = self.fs._fork_read_at(self.fork, n * self.node_size, self.node_size)
        if len(self._cache) > 256:
            self._cache.clear()
        self._cache[n] = data
        return data

    def records(self, node):
        """-> (kind, [(rec_off, key_len, data_off, data_end), ...])"""
        ns = len(node)
        if ns < 16:
            return (-1, [])
        (kind,) = struct.unpack_from(">b", node, 8)
        (num,) = struct.unpack_from(">H", node, 10)
        num = min(num, max(0, (ns - 14) // 2))
        offs = []
        for i in range(num):
            p = ns - 2 * (i + 1)
            if p < 14:
                break
            (o,) = struct.unpack_from(">H", node, p)
            offs.append(o if 14 <= o <= ns - 2 else None)

        free = None
        if kind != self.KIND_HEADER:
            (free,) = struct.unpack_from(">H", node, 14)

        out = []
        for i, o in enumerate(offs):
            if o is None:
                continue
            (klen,) = struct.unpack_from(">H", node, o)
            dstart = o + 2 + klen
            if dstart & 1:
                dstart += 1
            end = None
            for o2 in offs[i + 1:]:
                if o2 is not None and o2 > o:
                    end = o2
                    break
            if end is None and free and free > dstart:
                end = free
            if end is None or end > ns:
                end = ns
            dstart = min(dstart, ns)
            end = max(end, dstart)
            out.append((o, klen, dstart, end))
        return (kind, out)

    def leaves(self):
        """沿 fLink 走完整条叶子链 -> (node_no, node_bytes)"""
        n = self.first_leaf
        seen = set()
        while n and n not in seen:
            seen.add(n)
            node = self.node(n)
            if not node:
                break
            yield (n, node)
            (n,) = struct.unpack_from(">I", node, 0)

    def iter_records(self):
        """所有叶子记录 -> (node_no, node, rec_off, key_len, data_off, data_end)"""
        for node_no, node in self.leaves():
            _kind, recs = self.records(node)
            for (off, klen, dstart, dend) in recs:
                yield (node_no, node, off, klen, dstart, dend)

    def __repr__(self):
        return "<_BTree %s node=%d nodes=%d depth=%d leaf=%d err=%s>" % (
            self.name, self.node_size, self.total_nodes, self.depth,
            self.leaf_records, self.error)


# ------------------------------------------------------------
# HFS+
# ------------------------------------------------------------
class HfsPlus(object):
    """HFS+ / HFSX 文件系统（只读）"""

    def __init__(self, sub):
        self.sub = sub
        self.using_backup = False
        self.header_off = VOLUME_HEADER_OFFSET
        self._cat = None
        self._ext_tree = None
        self._ext_error = None
        self._by_parent = None          # 懒加载的 parentID -> [HfsEntry]
        self._vol_name = None
        self.deleted_note = ""
        self._read_volume_header()

    # ================= 卷头 =================
    def _read_volume_header(self):
        sig, hdr, off = self._try_header(self.sub.read(VOLUME_HEADER_OFFSET, 512),
                                         VOLUME_HEADER_OFFSET)
        if hdr is None:
            alt = self.sub.size - 1024
            if alt > VOLUME_HEADER_OFFSET:
                sig, hdr, off = self._try_header(self.sub.read(alt, 512), alt)
                self.using_backup = hdr is not None
        if hdr is None:
            raise ValueError("不是 HFS+ 卷：@1024 与卷尾 1024 处都没有 H+/HX 签名")
        self.sig_word = sig
        self.header_off = off
        self.is_hfsx = (sig == HFSX_SIG)

        (self.version,) = struct.unpack_from(">H", hdr, 2)
        (self.attributes, self.last_mounted_version, self.journal_info_block,
         self.create_date, self.modify_date, self.backup_date,
         self.checked_date, self.file_count, self.folder_count,
         self.block_size, self.total_blocks, self.free_blocks,
         self.next_allocation, self.rsrc_clump_size, self.data_clump_size,
         self.next_catalog_id, self.write_count) = \
            struct.unpack_from(">17I", hdr, 4)
        (self.encodings_bitmap,) = struct.unpack_from(">Q", hdr, 72)
        self.finder_info = hdr[80:112]

        self.allocation_file = Fork.parse(hdr, 112)
        self.extents_file = Fork.parse(hdr, 192)
        self.catalog_file = Fork.parse(hdr, 272)
        self.attributes_file = Fork.parse(hdr, 352)
        self.startup_file = Fork.parse(hdr, 432)

        if not self.block_size:
            raise ValueError("卷头 blockSize 为 0")
        self.root_folder_id = CNID_ROOT_FOLDER

    @staticmethod
    def _try_header(buf, off):
        if len(buf) < 512:
            return (None, None, off)
        (sig,) = struct.unpack_from(">H", buf, 0)
        if sig not in (HFS_PLUS_SIG, HFSX_SIG):
            return (None, None, off)
        (version,) = struct.unpack_from(">H", buf, 2)
        (bsize,) = struct.unpack_from(">I", buf, 40)
        if not (4 <= version <= 5) or bsize == 0 or (bsize & (bsize - 1)):
            return (None, None, off)
        return (sig, buf, off)

    def info(self):
        d = {
            "fs": "HFSX" if self.is_hfsx else "HFS+",
            "signature": struct.pack(">H", self.sig_word).decode("ascii"),
            "version": self.version,
            "header_offset": self.header_off,
            "using_backup_header": self.using_backup,
            "journaled": bool(self.attributes & 0x00002000),
            "attributes": "0x%08X" % self.attributes,
            "attribute_names": _attr_text(self.attributes, VOL_ATTR),
            "last_mounted_version": self.last_mounted_version.to_bytes(
                4, "big").decode("ascii", "replace"),
            "journal_info_block": self.journal_info_block,
            "journal_offset": self.journal_info_block * self.block_size,
            "create_date": hfs_time(self.create_date),
            "modify_date": hfs_time(self.modify_date),
            "backup_date": hfs_time(self.backup_date),
            "checked_date": hfs_time(self.checked_date),
            "file_count": self.file_count,
            "folder_count": self.folder_count,
            "block_size": self.block_size,
            "total_blocks": self.total_blocks,
            "free_blocks": self.free_blocks,
            "volume_bytes": self.block_size * self.total_blocks,
            "used_bytes": self.block_size * (self.total_blocks - self.free_blocks),
            "next_allocation": self.next_allocation,
            "next_catalog_id": self.next_catalog_id,
            "write_count": self.write_count,
            "encodings_bitmap": "0x%016X" % self.encodings_bitmap,
            "allocation_file": {"size": self.allocation_file.logical_size,
                                "extents": self.allocation_file.extents},
            "extents_file": {"size": self.extents_file.logical_size,
                             "extents": self.extents_file.extents},
            "catalog_file": {"size": self.catalog_file.logical_size,
                             "extents": self.catalog_file.extents},
            "attributes_file": {"size": self.attributes_file.logical_size,
                                "extents": self.attributes_file.extents},
            "startup_file": {"size": self.startup_file.logical_size,
                             "extents": self.startup_file.extents},
            "volume_name": self.volume_name(),
        }
        if self._ext_error:
            d["extents_overflow_note"] = self._ext_error
        if self._cat is not None and not self._cat.error:
            d["catalog_tree"] = {
                "node_size": self._cat.node_size,
                "total_nodes": self._cat.total_nodes,
                "depth": self._cat.depth,
                "leaf_records": self._cat.leaf_records,
                "key_compare": {0: "FastUnicodeCompare(case-insensitive)",
                                0xBC: "kHFSBinaryCompare(case-sensitive)"}.get(
                                    self._cat.key_compare, self._cat.key_compare),
            }
        elif self._cat is not None:
            d["catalog_tree"] = {"error": self._cat.error}
        return d

    @property
    def case_sensitive(self):
        """HFSX + catalog 键比较类型为 'B'(0xBC) 才是大小写敏感"""
        cat = self._catalog_btree()
        return bool(self.is_hfsx and cat is not None and cat.key_compare == 0xBC)

    # ================= fork 读取 =================
    def _special_fork_id(self, fork):
        """特殊文件的 CNID / forkType（用于查 extents overflow）"""
        for f, cid in ((self.catalog_file, CNID_CATALOG_FILE),
                       (self.allocation_file, CNID_ALLOCATION_FILE),
                       (self.attributes_file, CNID_ATTRIBUTES_FILE),
                       (self.startup_file, CNID_STARTUP_FILE)):
            if fork is f:
                return (cid, FORK_DATA)
        return (None, None)

    def fork_extents(self, fork, file_id=None, fork_type=None):
        """把 fork 展开成 [(字节偏移, 字节长度), ...]（含 extents overflow 续链）

        结果缓存在 Fork._segs 上；extents overflow 文件自己的超出部分无法用
        自身解析（自举问题），只按内联 8 段处理。
        """
        if fork._segs is not None:
            return fork._segs
        segs = [(st * self.block_size, cnt * self.block_size)
                for (st, cnt) in fork.extents if cnt]
        if fork.logical_size > sum(l for _, l in segs):
            if file_id is None:
                file_id, fork_type = self._special_fork_id(fork)
            if fork is self.extents_file:
                file_id = None
            if file_id is not None and fork_type is not None:
                try:
                    for (st, cnt) in self._overflow_extents(file_id, fork_type):
                        segs.append((st * self.block_size, cnt * self.block_size))
                except Exception as e:
                    self._ext_error = str(e)
        fork._segs = segs
        return segs

    def _fork_read_at(self, fork, off, size):
        if size <= 0 or off < 0:
            return b""
        segs = fork._segs
        if segs is None:
            segs = self.fork_extents(fork)
        end_want = off + size
        if fork.logical_size:
            end_want = min(end_want, fork.logical_size)
        if end_want <= off:
            return b""
        out = []
        cur = 0
        for (soff, slen) in segs:
            seg_end = cur + slen
            if seg_end > off and cur < end_want:
                a = max(off, cur)
                b = min(end_want, seg_end)
                chunk = self.sub.read(soff + (a - cur), b - a)
                out.append(chunk)
                if len(chunk) < b - a:
                    break
            cur = seg_end
            if cur >= end_want:
                break
        return b"".join(out)

    def _fork_map(self, fork, foff):
        """fork 内逻辑偏移 -> 卷内绝对偏移（跨 extent 查表）；越界返回 None"""
        if foff < 0:
            return None
        segs = fork._segs if fork._segs is not None else self.fork_extents(fork)
        acc = 0
        for (soff, slen) in segs:
            if foff < acc + slen:
                return soff + (foff - acc)
            acc += slen
        return None

    def read_fork(self, fork, limit=None):
        """读整个 fork（默认按 logicalSize 截断）"""
        size = fork.logical_size or sum(l for _, l in self.fork_extents(fork))
        if limit:
            size = min(size, limit)
        return self._fork_read_at(fork, 0, size)

    # ================= Extents overflow =================
    def _extents_btree(self):
        if self._ext_tree is None:
            if self.extents_file.is_empty():
                self._ext_error = "卷上没有 extents overflow 文件"
                return None
            self._ext_tree = _BTree(self, self.extents_file, "extents")
            if self._ext_tree.error:
                self._ext_error = self._ext_tree.error
        return self._ext_tree

    def _overflow_extents(self, file_id, fork_type):
        """查 extents overflow B-tree，返回该 fork 的全部补充 extent。

        键 HFSPlusExtentKey{ keyLength u16, forkType u8, pad u8, fileID u32,
        startBlock u32 }，记录体是 8 个 extent（64 字节）。这里按
        (forkType, fileID) 前缀顺序收集，不依赖 startBlock 的续接约定。
        """
        tree = self._extents_btree()
        if tree is None:
            return []
        out = []
        for _n, node, off, klen, dstart, _dend in tree.iter_records():
            if klen < 10 or off + 12 > len(node):
                continue
            (ftype, _pad, fid, _start) = struct.unpack_from(">BBII", node, off + 2)
            if ftype != fork_type or fid != file_id:
                continue
            for i in range(8):
                p = dstart + i * 8
                if p + 8 > len(node):
                    break
                (st, cnt) = struct.unpack_from(">II", node, p)
                if cnt:
                    out.append((st, cnt))
        return out

    # ================= Catalog B-tree =================
    def _catalog_btree(self):
        if self._cat is None:
            if self.catalog_file.is_empty():
                self._cat = _BTree(self, Fork(), "catalog")
                self._cat.error = "卷头里 catalogFile 为空（fork 损坏？）"
            else:
                self._cat = _BTree(self, self.catalog_file, "catalog")
                # catalog 自己的 extent 可能要 overflow 续链
                self.fork_extents(self.catalog_file, CNID_CATALOG_FILE, FORK_DATA)
        return self._cat

    @staticmethod
    def _cat_key(node, off, klen):
        """HFSPlusCatalogKey{ keyLength u16, parentID u32, nodeName HFSUniStr255 }"""
        koff = off + 2
        if klen < 6 or koff + 6 > len(node):
            return None
        (parent_id,) = struct.unpack_from(">I", node, koff)
        name = _unistr(node, koff + 4, klen - 4)
        return {"parent_id": parent_id, "name": name}

    def iter_catalog(self):
        """遍历 catalog 全部叶子记录 -> (key, node, data_off, 卷内绝对偏移)"""
        cat = self._catalog_btree()
        if cat is None or cat.error:
            return
        for node_no, node, rec_off, klen, dstart, _dend in cat.iter_records():
            key = self._cat_key(node, rec_off, klen)
            if key is None:
                continue
            foff = node_no * cat.node_size + rec_off
            abs_off = self._fork_map(cat.fork, foff)
            yield (key, node, dstart, foff if abs_off is None else abs_off)

    def _entry_from(self, key, node, dstart, rec_off):
        """把 catalog 记录体解析成 HfsEntry；线程记录返回 record_type 3/4 的字典"""
        if dstart + 2 > len(node):
            return None
        (rtype,) = struct.unpack_from(">h", node, dstart)
        try:
            if rtype == REC_FOLDER:
                (flags, valence, cnid) = struct.unpack_from(">HII", node, dstart + 2)
                (create, modify, attr_mod, access, backup) = \
                    struct.unpack_from(">IIIII", node, dstart + 12)
                (uid, gid, admin_flags, owner_flags, mode, special) = \
                    struct.unpack_from(">IIBBHI", node, dstart + 32)
                return HfsEntry(
                    name=key["name"], parent_id=key["parent_id"], cnid=cnid,
                    is_dir=True, record_type=rtype, size=0, rsrc_size=0,
                    create=hfs_time(create), modify=hfs_time(modify),
                    attr_modify=hfs_time(attr_mod), access=hfs_time(access),
                    backup=hfs_time(backup), flags=flags, mode=mode,
                    uid=uid, gid=gid, link_count=special or 1,
                    data_fork=Fork(), rsrc_fork=Fork(),
                    rec_off=rec_off, path=key["name"],
                )
            if rtype == REC_FILE:
                (flags, _res, cnid) = struct.unpack_from(">HII", node, dstart + 2)
                (create, modify, attr_mod, access, backup) = \
                    struct.unpack_from(">IIIII", node, dstart + 12)
                (uid, gid, _af, _of, mode, special) = \
                    struct.unpack_from(">IIBBHI", node, dstart + 32)
                data_fork = Fork.parse(node, dstart + 88)
                rsrc_fork = Fork.parse(node, dstart + 168)
                return HfsEntry(
                    name=key["name"], parent_id=key["parent_id"], cnid=cnid,
                    is_dir=False, record_type=rtype,
                    size=data_fork.logical_size, rsrc_size=rsrc_fork.logical_size,
                    create=hfs_time(create), modify=hfs_time(modify),
                    attr_modify=hfs_time(attr_mod), access=hfs_time(access),
                    backup=hfs_time(backup), flags=flags, mode=mode,
                    uid=uid, gid=gid, link_count=special or 1,
                    data_fork=data_fork, rsrc_fork=rsrc_fork,
                    rec_off=rec_off, path=key["name"],
                )
            if rtype in (REC_FOLDER_THREAD, REC_FILE_THREAD):
                (parent_id,) = struct.unpack_from(">I", node, dstart + 4)
                return {"record_type": rtype, "thread": True,
                        "cnid": key["parent_id"], "parent_id": parent_id,
                        "name": _unistr(node, dstart + 8, 512)}
        except struct.error:
            return None
        return None

    def _catalog_fast_lookup(self, parent_id, name):
        """沿索引节点下钻到叶子，找到 (parentID, name) 对应记录"""
        cat = self._catalog_btree()
        if cat is None or cat.error:
            return None
        want = _fold(name)
        node_no = cat.root
        for _ in range(32):
            node = cat.node(node_no)
            if not node:
                return None
            kind, recs = cat.records(node)
            if kind == _BTree.KIND_LEAF:
                for (off, klen, dstart, _dend) in recs:
                    k = self._cat_key(node, off, klen)
                    if k and k["parent_id"] == parent_id and _fold(k["name"]) == want:
                        foff = node_no * cat.node_size + off
                        abs_off = self._fork_map(cat.fork, foff)
                        return self._entry_from(
                            k, node, dstart, foff if abs_off is None else abs_off)
                return None
            if kind != _BTree.KIND_INDEX:
                return None
            child = None
            for (off, klen, dstart, _dend) in recs:
                k = self._cat_key(node, off, klen)
                if k is None or dstart + 4 > len(node):
                    continue
                if k["parent_id"] < parent_id or (
                        k["parent_id"] == parent_id and _fold(k["name"]) <= want):
                    (child,) = struct.unpack_from(">I", node, dstart)
            if child is None and recs:
                (child,) = struct.unpack_from(">I", node, recs[0][2])
            if not child:
                return None
            node_no = child
        return None

    def lookup(self, parent_id, name):
        """按 (父 CNID, 名字) 找目录项；先走 B-tree 索引，失败再全扫描兜底"""
        hit = self._catalog_fast_lookup(parent_id, name)
        if hit is not None:
            return hit
        want = _fold(name)
        for key, node, dstart, rec_off in self.iter_catalog():
            if key["parent_id"] != parent_id or _fold(key["name"]) != want:
                continue
            ent = self._entry_from(key, node, dstart, rec_off)
            if isinstance(ent, HfsEntry):
                return ent
        return None

    def lookup_path(self, path):
        """按 / 分隔的路径找目录项，返回 HfsEntry（找不到 None）"""
        cur_id = self.root_folder_id
        cur = None
        parts = [p for p in (path or "").split("/") if p and p != "."]
        for part in parts:
            ent = self.lookup(cur_id, part)
            if ent is None or not isinstance(ent, HfsEntry):
                return None
            cur = ent
            if ent.is_dir:
                cur_id = ent.cnid
            elif part != parts[-1]:
                return None
        if cur is None:
            cur = HfsEntry(name="", parent_id=CNID_ROOT_PARENT,
                           cnid=self.root_folder_id, is_dir=True,
                           record_type=REC_FOLDER, size=0, rsrc_size=0,
                           data_fork=Fork(), rsrc_fork=Fork(), rec_off=None,
                           path="")
        return cur

    # ================= 卷名 / 根 =================
    def volume_name(self):
        """根目录的线程记录里存着卷名（key 为 (CNID=2, 空名)）"""
        if self._vol_name is not None:
            return self._vol_name
        self._vol_name = ""
        for key, node, dstart, rec_off in self.iter_catalog():
            if key["parent_id"] != CNID_ROOT_FOLDER or key["name"]:
                continue
            ent = self._entry_from(key, node, dstart, rec_off)
            if isinstance(ent, dict) and ent.get("thread"):
                self._vol_name = ent.get("name") or ""
                break
        return self._vol_name

    def root_entry(self):
        """伪根目录项（CNID=2），用于 walk 起点"""
        return HfsEntry(name="", parent_id=CNID_ROOT_PARENT,
                        cnid=CNID_ROOT_FOLDER, is_dir=True,
                        record_type=REC_FOLDER, size=0, rsrc_size=0, flags=0,
                        mode=0o40755, uid=0, gid=0, link_count=1,
                        create=hfs_time(self.create_date),
                        modify=hfs_time(self.modify_date),
                        data_fork=Fork(), rsrc_fork=Fork(),
                        rec_off=None, path="")

    # ================= 目录 =================
    def index(self):
        """懒加载的 whole-catalog 索引：{parentID: [HfsEntry, ...]}

        首次调用会把整个 catalog 扫一遍（O(记录数)），之后列目录为 O(1)
        取表。真实卷上 catalog 动辄几十万条记录，这样比每个目录扫一遍全表
        快得多；代价是内存里保留一份目录项。
        """
        if self._by_parent is not None:
            return self._by_parent
        idx = {}
        for key, node, dstart, rec_off in self.iter_catalog():
            ent = self._entry_from(key, node, dstart, rec_off)
            if isinstance(ent, HfsEntry):
                idx.setdefault(key["parent_id"], []).append(ent)
        for lst in idx.values():
            lst.sort(key=lambda e: (not e.is_dir, _fold(e.name), e.cnid or 0))
        self._by_parent = idx
        return idx

    def children(self, cnid=None):
        """某个目录 CNID 下的所有文件夹 / 文件（不含线程记录）"""
        if cnid is None:
            cnid = self.root_folder_id
        return list(self.index().get(cnid, []))

    def listdir(self, entry=None):
        """列目录。entry=None 表示根目录"""
        if entry is None:
            return self.children(self.root_folder_id)
        if not entry.is_dir:
            raise ValueError("不是目录: %r" % entry.name)
        return self.children(entry.cnid)

    def walk(self, entry=None, _depth=0, _max=32, _seen=None):
        """递归遍历，产出 (路径, HfsEntry)"""
        if _seen is None:
            _seen = set()
        if entry is None:
            entry = self.root_entry()
        if entry.cnid in _seen or _depth > _max:
            return
        _seen.add(entry.cnid)
        prefix = (entry.path + "/") if entry.path else ""
        for it in self.children(entry.cnid):
            it.path = prefix + it.name
            yield (it.path, it)
            if it.is_dir and _depth < _max:
                for sub in self.walk(it, _depth + 1, _max, _seen):
                    yield sub

    def read_file(self, entry, rsrc=False, limit=None):
        """读文件内容（默认数据 fork，rsrc=True 读资源 fork）"""
        if entry.is_dir:
            return None
        fork = entry.rsrc_fork if rsrc else entry.data_fork
        if fork is None:
            return b""
        fid = entry.cnid
        self.fork_extents(fork, fid, FORK_RSRC if rsrc else FORK_DATA)
        size = fork.logical_size
        if limit:
            size = min(size, limit)
        return self._fork_read_at(fork, 0, size)

    def find(self, pattern=None):
        """按路径子串筛选（不区分大小写）"""
        needle = (pattern or "").casefold()
        out = []
        for path, it in self.walk():
            if needle and needle not in path.casefold():
                continue
            out.append((path, it))
        return out

    def deleted(self):
        """尽力而为的「删除项」检测。

        HFS+ 不保留删除标记：条目被删除时直接从 Catalog B-tree 摘除，节点可能
        被合并或回收，所以这里只能找出「catalog 里有记录、但无法从根目录到达」
        的未链接项（CNID < 16 的系统文件不算）。
        """
        self.deleted_note = (
            "HFS+ 无删除标记：deleted() 只返回 catalog 中未链接（无法从根目录到达）"
            "的条目；被真正删除的旧条目需靠 B-tree 节点残余或未分配块雕刻恢复。")
        reachable = {CNID_ROOT_FOLDER}
        for path, it in self.walk():
            reachable.add(it.cnid)
        out = []
        for parent_id, lst in self.index().items():
            for ent in lst:
                if ent.cnid < CNID_FIRST_USER or ent.cnid in reachable:
                    continue
                if parent_id in (CNID_ROOT_FOLDER, CNID_ROOT_PARENT):
                    continue
                out.append(("<unlinked:%d>/%s" % (ent.cnid, ent.name), ent))
        return out

    # ================= 分配位图 =================
    def _alloc_bit(self, block):
        """allocation file 位图第 block 位（MSB 优先）"""
        byte_off = block // 8
        if byte_off >= self.allocation_file.logical_size:
            return None
        b = self._fork_read_at(self.allocation_file, byte_off, 1)
        if not b:
            return None
        return (b[0] >> (7 - (block % 8))) & 1

    def is_block_used(self, block):
        bit = self._alloc_bit(block)
        return None if bit is None else bool(bit)

    def unallocated_ranges(self, max_block=None):
        """产出未分配块区间 (字节偏移, 字节长度)，用于雕刻"""
        total = self.total_blocks if max_block is None else min(max_block, self.total_blocks)
        run = None
        cnt = 0
        chunk = 1 << 16
        for base in range(0, total, chunk):
            n = min(chunk, total - base)
            data = self._fork_read_at(self.allocation_file, base // 8, (n + 7) // 8)
            for i in range(n):
                idx = i // 8
                if idx >= len(data):
                    bit = 0
                else:
                    bit = (data[idx] >> (7 - (i % 8))) & 1
                if not bit:
                    if run is None:
                        run, cnt = base + i, 1
                    else:
                        cnt += 1
                else:
                    if run is not None:
                        yield (run * self.block_size, cnt * self.block_size)
                        run, cnt = None, 0
        if run is not None:
            yield (run * self.block_size, cnt * self.block_size)

    def journal_info(self):
        """日志区（journalInfoBlock 指向的块）基本信息；不解析日志内容"""
        return {
            "journal_info_block": self.journal_info_block,
            "offset": self.journal_info_block * self.block_size,
            "journaled": bool(self.attributes & 0x00002000),
            "note": "仅定位日志区；journal 头与事务未解析",
        }

    def __repr__(self):
        return "<HfsPlus %r bs=%d blocks=%d>" % (
            self.volume_name(), self.block_size, self.total_blocks)


# ------------------------------------------------------------
# 经典 HFS（HFS Standard，签名 'BD'）
# ------------------------------------------------------------
class Hfs(object):
    """经典 HFS 卷（HFS Standard / Mac OS Standard）

    已实现：MDB 字段解析、卷名、分配块参数、文件/目录计数、内嵌 HFS+ 卷定位。
    未实现：目录遍历与文件读取（Catalog 键为 parentID + 31 字节 MacRoman 名，
    与 HFS+ 的 HFSUniStr255 键不同，本模块不解析）。
    """

    def __init__(self, sub):
        self.sub = sub
        mdb = sub.read(VOLUME_HEADER_OFFSET, 254)
        if len(mdb) < 162:
            raise ValueError("MDB 读取失败（卷太小）")
        (sig,) = struct.unpack_from(">H", mdb, 0)
        if sig != HFS_SIG:
            raise ValueError("不是经典 HFS 卷：@1024 签名为 0x%04X，期望 'BD'" % sig)
        self.mdb = mdb
        self.sig_word = sig
        (self.create_date, self.modify_date, self.attributes, self.root_file_count,
         self.vbm_start, self.alloc_ptr, self.num_alloc_blocks, self.alloc_block_size,
         self.clump_size, self.first_alloc_block, self.next_cnid, self.free_blocks) = \
            struct.unpack_from(">IIHHHHHIIHIH", mdb, 2)
        # 上面 12 个字段的字节跨度：2..34，接 drVN(28) @36
        self.volume_name_raw = mdb[36:64]
        self.label = _pascal(mdb, 36)
        (self.backup_date,) = struct.unpack_from(">I", mdb, 64)
        (self.backup_seq, self.write_count, self.extents_clump,
         self.catalog_clump, self.root_dir_count) = \
            struct.unpack_from(">HIIIH", mdb, 68)
        (self.file_count, self.dir_count) = struct.unpack_from(">II", mdb, 84)

    def info(self):
        embed = self.embedded_volume()
        return {
            "fs": "HFS",
            "signature": "BD",
            "header_offset": VOLUME_HEADER_OFFSET,
            "volume_name": self.label,
            "create_date": hfs_time(self.create_date),
            "modify_date": hfs_time(self.modify_date),
            "backup_date": hfs_time(self.backup_date),
            "attributes": "0x%04X" % self.attributes,
            "block_size": self.alloc_block_size,
            "total_blocks": self.num_alloc_blocks,
            "free_blocks": self.free_blocks,
            "first_alloc_block": self.first_alloc_block,
            "volume_bitmap_block": self.vbm_start,
            "next_cnid": self.next_cnid,
            "file_count": self.file_count,
            "folder_count": self.dir_count,
            "root_file_count": self.root_file_count,
            "root_folder_count": self.root_dir_count,
            "write_count": self.write_count,
            "embedded_hfs_plus": embed,
            "catalog_supported": False,
            "note": "经典 HFS 目录遍历未实现；若是 HFS+ wrapper 请用 embedded_volume()",
        }

    def embedded_volume(self):
        """HFS+ wrapper：返回 (字节偏移, 字节长度)，否则 None"""
        if len(self.mdb) < 0x82:
            return None
        (esig, estart, ecount) = struct.unpack_from(">HHH", self.mdb, 0x7C)
        if esig != HFS_PLUS_SIG or not ecount:
            return None
        unit = self.alloc_block_size or 512
        return (estart * unit, ecount * unit)

    def listdir(self, entry=None):
        raise NotImplementedError(
            "经典 HFS 的目录遍历未实现（Catalog 键格式不同）。"
            "若该卷是 HFS+ wrapper，请用 embedded_volume() 取内嵌 HFS+ 卷。")

    def read_file(self, entry, rsrc=False, limit=None):
        raise NotImplementedError("经典 HFS 的文件读取未实现")

    def walk(self, *a, **kw):
        raise NotImplementedError("经典 HFS 的目录遍历未实现")

    def deleted(self):
        return []

    def __repr__(self):
        return "<Hfs %r bs=%d blocks=%d>" % (
            self.label, self.alloc_block_size, self.num_alloc_blocks)


# ------------------------------------------------------------
# 探测 / 打开
# ------------------------------------------------------------
def probe(sub):
    """探测 @1024 的卷签名 -> 'hfs+' / 'hfsx' / 'hfs' / None"""
    head = sub.read(VOLUME_HEADER_OFFSET, 2)
    if len(head) < 2:
        return None
    (sig,) = struct.unpack(">H", head)
    return {HFS_PLUS_SIG: "hfs+", HFSX_SIG: "hfsx", HFS_SIG: "hfs"}.get(sig)


def open_volume(sub):
    """按签名返回 HfsPlus 或 Hfs 实例"""
    kind = probe(sub)
    if kind in ("hfs+", "hfsx"):
        return HfsPlus(sub)
    if kind == "hfs":
        return Hfs(sub)
    raise ValueError("不是 HFS/HFS+ 卷：@1024 处签名为 %r" % (kind,))


# ============================================================
# 自检：现场构造合成镜像（不依赖真实检材）
# ============================================================
def _p16(v):
    return struct.pack(">H", v)


def _p32(v):
    return struct.pack(">I", v)


def _fork_bytes(extents, logical_size, clump=4096):
    b = bytearray(80)
    struct.pack_into(">QII", b, 0, logical_size, clump, sum(c for _, c in extents))
    for i, (st, cnt) in enumerate(extents[:8]):
        struct.pack_into(">II", b, 16 + i * 8, st, cnt)
    return bytes(b)


def _cat_key(parent_id, name):
    body = _p32(parent_id) + _p16(len(name)) + name.encode("utf-16-be")
    return _p16(len(body)) + body


def _rec_folder(cnid, dates, mode=0o40755, uid=501, gid=20, valence=0, flags=0):
    b = bytearray(88)
    struct.pack_into(">hHII", b, 0, REC_FOLDER, flags, valence, cnid)
    struct.pack_into(">IIIII", b, 12, *dates)
    struct.pack_into(">IIBBHI", b, 32, uid, gid, 0, 0, mode, 1)
    return bytes(b)


def _rec_file(cnid, dates, data_fork, rsrc_fork, mode=0o100644, uid=501, gid=20, flags=0):
    b = bytearray(248)
    struct.pack_into(">hHII", b, 0, REC_FILE, flags, 0, cnid)
    struct.pack_into(">IIIII", b, 12, *dates)
    struct.pack_into(">IIBBHI", b, 32, uid, gid, 0, 0, mode, 1)
    b[88:168] = data_fork
    b[168:248] = rsrc_fork
    return bytes(b)


def _rec_thread(cnid, kind, parent_id, name):
    body = bytearray(8 + 2 + 2 * len(name))
    struct.pack_into(">hHI", body, 0, REC_FOLDER_THREAD if kind == "folder"
                     else REC_FILE_THREAD, 0, parent_id)
    struct.pack_into(">H", body, 8, len(name))
    body[10:10 + 2 * len(name)] = name.encode("utf-16-be")
    return bytes(body)


def _pack_node(node_size, kind, height, recs, f_link=0, b_link=0):
    """按 HFS+ 规则拼一个 B-tree 节点：记录前向生长，偏移表在尾部逆序"""
    node = bytearray(b"\x00" * node_size)
    struct.pack_into(">IIbBHH", node, 0, f_link, b_link, kind, height,
                     len(recs), 0)
    pos = 14 if kind == _BTree.KIND_HEADER else 16
    offs = []
    for r in recs:
        if pos & 1:
            pos += 1
        offs.append(pos)
        node[pos:pos + len(r)] = r
        pos += len(r)
    if kind != _BTree.KIND_HEADER:
        struct.pack_into(">H", node, 14, pos)          # 空闲空间偏移
    for i, o in enumerate(offs):
        struct.pack_into(">H", node, node_size - 2 * (i + 1), o)
    return bytes(node)


def _bt_header_rec(node_size, root, first_leaf, last_leaf, depth, leaf_recs, total):
    b = bytearray(106)
    struct.pack_into(">HIIIIHHIHHIBBI", b, 0, depth, root, leaf_recs,
                     first_leaf, last_leaf, node_size, 516, total, 0, 0,
                     node_size, 0, 0x00, 0)          # keyCompare: 0=FastUnicode
    return bytes(b)


def _mk_volume_header(sig, version, block_size, total_blocks, free_blocks,
                      file_count, folder_count, next_cat_id, dates,
                      allocation, extents, catalog, attributes=b"\x00" * 80,
                      startup=b"\x00" * 80):
    h = bytearray(512)
    struct.pack_into(">HHII", h, 0, sig, version, 0x00000100, 0x31302E30)  # "10.0"
    struct.pack_into(">IIIII", h, 12, 0, dates[0], dates[1], dates[2], dates[3])
    struct.pack_into(">IIIIIIII", h, 32, file_count, folder_count, block_size,
                     total_blocks, free_blocks, 14, 65536, 65536)
    struct.pack_into(">IIQ", h, 64, next_cat_id, 7, 1)
    h[112:192] = allocation
    h[192:272] = extents
    h[272:352] = catalog
    h[352:432] = attributes
    h[432:512] = startup
    return bytes(h)


class _Mem(object):
    """自检用的内存子镜像，接口与 mkit.image.SubImage 一致"""

    def __init__(self, data):
        self._d = bytearray(data)
        self.size = len(self._d)

    def read(self, off, size):
        if off < 0 or size <= 0 or off >= self.size:
            return b""
        return bytes(self._d[off:off + size])

    def write(self, off, data):
        self._d[off:off + len(data)] = data


def _build_hfs_plus(sig=HFS_PLUS_SIG, version=4, with_primary=True):
    """构造一个合成 HFS+ 卷：/ESK/{readme.txt, second.bin, big.bin}

    块布局（block_size = 4096，total_blocks = 128）：
        1       allocation file（位图）
        2       extents overflow B-tree 头节点
        3..6    catalog B-tree（头节点 + 索引节点 + 2 个叶子节点）
        7       extents overflow B-tree 叶子（1 条记录，给 big.bin 续链）
        10      readme.txt 数据
        11..12  second.bin 数据（两个 extent，验证多段读）
        13      readme.txt 资源 fork
        14      big.bin 第 1 段（内联 extent）
        15      big.bin 第 2 段（只能从 extents overflow 拿到）
    """
    BS = 4096
    TOTAL = 128
    dates = (unix_to_hfs(1714979289), unix_to_hfs(1714979290),
             unix_to_hfs(1714979291), unix_to_hfs(1714979292),
             unix_to_hfs(1714979293))    # 2024-05-06 07:08:09Z 起

    data1 = b"ESK HFS+ selftest\n"
    rsrc1 = b"RSRC\x00\x00\x01"
    data2 = bytes(((i * 37 + 11) & 0xFF) for i in range(5000))
    data3 = bytes(((i * 53 + 7) & 0xFF) for i in range(2 * BS))

    img = _Mem(b"\x00" * (BS * TOTAL))

    # ---- catalog B-tree ----
    recs = [
        (_cat_key(CNID_ROOT_FOLDER, ""), _rec_thread(CNID_ROOT_FOLDER, "folder",
                                                     CNID_ROOT_PARENT, "ESKTEST")),
        (_cat_key(CNID_ROOT_FOLDER, "ESK"), _rec_folder(16, dates, valence=3)),
        (_cat_key(16, ""), _rec_thread(16, "folder", CNID_ROOT_FOLDER, "ESK")),
        (_cat_key(16, "readme.txt"),
         _rec_file(17, dates,
                   _fork_bytes([(10, 1)], len(data1)),
                   _fork_bytes([(13, 1)], len(rsrc1)))),
        (_cat_key(16, "second.bin"),
         _rec_file(18, dates,
                   _fork_bytes([(11, 1), (12, 1)], len(data2)),
                   _fork_bytes([], 0))),
        (_cat_key(16, "big.bin"),
         _rec_file(19, dates,
                   _fork_bytes([(14, 1)], len(data3)),      # 只内联了第 1 段
                   _fork_bytes([], 0))),
        (_cat_key(17, ""), _rec_thread(17, "file", 16, "readme.txt")),
        (_cat_key(18, ""), _rec_thread(18, "file", 16, "second.bin")),
        (_cat_key(19, ""), _rec_thread(19, "file", 16, "big.bin")),
    ]
    # 按 (parentID, 名字) 排序 —— 真实卷就是这么排的
    recs.sort(key=lambda kr: (struct.unpack_from(">I", kr[0], 2)[0], kr[0][6:]))

    payload = [k + d for k, d in recs]
    leaf_a = payload[:5]
    leaf_b = payload[5:]

    cat_nodes = [
        _pack_node(BS, _BTree.KIND_HEADER, 0,
                   [_bt_header_rec(BS, 1, 2, 3, 2, len(payload), 4),
                    b"\x00" * 128, b"\xFF" * 32]),
        _pack_node(BS, _BTree.KIND_INDEX, 2,
                   [recs[0][0] + _p32(2), recs[5][0] + _p32(3)]),
        _pack_node(BS, _BTree.KIND_LEAF, 1, leaf_a, f_link=3),
        _pack_node(BS, _BTree.KIND_LEAF, 1, leaf_b, b_link=2),
    ]
    for i, node in enumerate(cat_nodes):
        img.write((3 + i) * BS, node)

    # ---- extents overflow B-tree：big.bin 的第 2 段 ----
    # 键 HFSPlusExtentKey{ keyLength u16, forkType u8, pad u8, fileID u32,
    #                     startBlock u32 }，keyLength 不含自身 2 字节 = 10
    ext_rec = (_p16(10) + b"\x00\x00" + _p32(19) + _p32(8) +
               _fork_bytes([(15, 1)], BS)[16:24] + b"\x00" * 56)
    img.write(2 * BS, _pack_node(BS, _BTree.KIND_HEADER, 0,
                                 [_bt_header_rec(BS, 1, 1, 1, 1, 1, 2),
                                  b"\x00" * 128, b"\xFF" * 32]))
    img.write(7 * BS, _pack_node(BS, _BTree.KIND_LEAF, 1, [ext_rec]))

    # ---- 分配位图：块 0..15 已用 ----
    bitmap = bytearray(BS)
    for b in range(16):
        bitmap[b // 8] |= 0x80 >> (b % 8)
    img.write(1 * BS, bytes(bitmap))

    # ---- 文件数据 ----
    img.write(10 * BS, data1)
    img.write(11 * BS, data2[:BS])
    img.write(12 * BS, data2[BS:])
    img.write(13 * BS, rsrc1)
    img.write(14 * BS, data3[:BS])
    img.write(15 * BS, data3[BS:])

    # ---- 卷头 ----
    vh = _mk_volume_header(
        sig, version, BS, TOTAL, TOTAL - 16, 3, 2, 20,
        (dates[0], dates[0], 0, dates[0]),
        _fork_bytes([(1, 1)], BS), _fork_bytes([(2, 1), (7, 1)], BS * 2),
        _fork_bytes([(3, len(cat_nodes))], BS * len(cat_nodes)))
    if with_primary:
        img.write(VOLUME_HEADER_OFFSET, vh)
    img.write(BS * TOTAL - 1024, vh)              # 备份卷头
    return img


def _build_hfs_classic(label="HFSVOL", embed=None):
    """构造经典 HFS 的 MDB（只用于验证字段解析）"""
    img = _Mem(b"\x00" * (64 * 1024))
    mdb = bytearray(254)
    struct.pack_into(">H", mdb, 0, HFS_SIG)
    struct.pack_into(">II", mdb, 2, unix_to_hfs(1000000000), unix_to_hfs(1000000123))
    struct.pack_into(">H", mdb, 10, 0x0100)        # drAtrb
    struct.pack_into(">HHH", mdb, 12, 3, 4, 5)     # drNmFls/VBMSt/AllocPtr
    struct.pack_into(">HII", mdb, 18, 32, 4096, 65536)   # NmAlBlks/AlBlkSiz/ClpSiz
    struct.pack_into(">H", mdb, 28, 2)             # drAlBlSt
    struct.pack_into(">IH", mdb, 30, 4096, 12)     # drNxtCNID/drFreeBks
    mdb[36] = len(label)
    mdb[37:37 + len(label)] = label.encode("mac_roman")
    struct.pack_into(">I", mdb, 64, unix_to_hfs(1000000200))
    struct.pack_into(">HIIIH", mdb, 68, 1, 99, 65536, 65536, 1)
    struct.pack_into(">II", mdb, 84, 7, 2)          # drFilCnt/drDirCnt
    if embed:
        struct.pack_into(">HHH", mdb, 0x7C, HFS_PLUS_SIG, embed[0], embed[1])
    img.write(VOLUME_HEADER_OFFSET, bytes(mdb))
    return img


def _selftest():
    ok = 0

    def ck(cond, label, extra=""):
        nonlocal ok
        if not cond:
            raise AssertionError("自检失败: %s %s" % (label, extra))
        ok += 1
        print("  [OK] %-52s %s" % (label, extra))

    print("=" * 68)
    print("HFS+ 合成镜像自检（block=4096, 128 blocks）")
    print("=" * 68)

    img = _build_hfs_plus()
    fs = HfsPlus(img)
    inf = fs.info()

    print("[卷头]")
    ck(inf["signature"] == "H+", "签名 = H+", inf["signature"])
    ck(inf["block_size"] == 4096, "blockSize = 4096", inf["block_size"])
    ck(inf["total_blocks"] == 128, "totalBlocks = 128", inf["total_blocks"])
    ck(inf["volume_name"] == "ESKTEST", "卷名（根线程记录）= ESKTEST", inf["volume_name"])
    ck(inf["create_date"] == "2024-05-06 07:08:09",
       "HFS 纪元换算正确", inf["create_date"])
    ck(hfs_to_unix(unix_to_hfs(0)) == 0 and HFS_EPOCH_DELTA == 2082844800,
       "1904 -> 1970 偏移 = 2082844800")
    ck(inf["catalog_tree"]["node_size"] == 4096, "catalog nodeSize",
       inf["catalog_tree"]["node_size"])
    ck(inf["catalog_tree"]["leaf_records"] == 9, "catalog 叶子记录数 = 9",
       inf["catalog_tree"]["leaf_records"])

    print("\n[目录]")
    root = fs.listdir()
    ck([e.name for e in root] == ["ESK"], "根目录 = ['ESK']", [e.name for e in root])
    esk = root[0]
    ck(esk.is_dir and esk.cnid == 16 and esk.mode_text == "d755",
       "ESK 是目录 CNID=16 mode=d755", "%s %s" % (esk.cnid, esk.mode_text))
    kids = fs.listdir(esk)
    names = [e.name for e in kids]
    ck(names == ["big.bin", "readme.txt", "second.bin"],
       "ESK 下 3 个文件（目录在前、名字排序）", names)
    by_name = {e.name: e for e in kids}
    readme, second, big = by_name["readme.txt"], by_name["second.bin"], by_name["big.bin"]
    ck(readme.cnid == 17 and readme.size == 18, "readme.txt CNID=17 size=18",
       readme.size)

    print("\n[文件读取]")
    ck(fs.read_file(readme) == b"ESK HFS+ selftest\n", "readme.txt 数据 fork 内容")
    ck(fs.read_file(readme, rsrc=True) == b"RSRC\x00\x00\x01",
       "readme.txt 资源 fork 内容")
    blob = fs.read_file(second)
    ck(len(blob) == 5000, "second.bin 读到 5000 字节", len(blob))
    ck(blob == bytes(((i * 37 + 11) & 0xFF) for i in range(5000)),
       "second.bin 跨 2 个 extent 内容一致")
    ck(len(second.data_fork.extents) == 2, "second.bin 数据 fork 有 2 段",
       second.data_fork.extents)
    big_blob = fs.read_file(big)
    ck(big_blob == bytes(((i * 53 + 7) & 0xFF) for i in range(2 * 4096)),
       "big.bin 第 9 段来自 extents overflow B-tree（8192B）", len(big_blob))
    ck(len(big.data_fork.extents) == 1 and
       len(fs.fork_extents(big.data_fork, big.cnid, FORK_DATA)) == 2,
       "big.bin 内联 1 段 + overflow 1 段 = 2 段",
       fs.fork_extents(big.data_fork, big.cnid, FORK_DATA))

    print("\n[遍历 / 查找]")
    paths = [p for p, _ in fs.walk()]
    ck(paths == ["ESK", "ESK/big.bin", "ESK/readme.txt", "ESK/second.bin"],
       "walk 路径顺序", paths)
    ck(len(fs.find("readme")) == 1, "find('readme') = 1 条")
    ck(len(fs.find("SECOND")) == 1, "find('SECOND') 大小写不敏感 = 1 条")
    hit = fs.lookup_path("/ESK/readme.txt")
    ck(hit is not None and hit.cnid == 17, "lookup_path('/ESK/readme.txt')",
       hit.cnid if hit else None)
    ck(fs.lookup_path("/ESK/nope.txt") is None, "lookup_path('/ESK/nope.txt') = None")

    print("\n[删除项 / 分配位图]")
    d = fs.deleted()
    ck(d == [] and fs.deleted_note, "deleted() 空 + 附带说明", fs.deleted_note[:16])
    ck(fs.is_block_used(10) is True and fs.is_block_used(100) is False,
       "分配位图：块 10 已用 / 块 100 空闲")
    spans = list(fs.unallocated_ranges())
    ck(len(spans) == 1 and spans[0][0] == 16 * 4096,
       "未分配区间 = 块 16 起",
       "%d 段 @0x%X" % (len(spans), spans[0][0]) if spans else "无")

    print("\n[HFSX / 备份卷头]")
    fsx = HfsPlus(_build_hfs_plus(HFSX_SIG, 5))
    ck(fsx.info()["fs"] == "HFSX", "HFSX 签名识别")
    ck(fsx.lookup_path("/esk/README.TXT") is not None,
       "HFSX 卷读取 /esk/README.TXT")
    bk = HfsPlus(_build_hfs_plus(with_primary=False))
    ck(bk.using_backup and bk.block_size == 4096,
       "主卷头缺失 -> 用卷尾备份卷头", bk.header_off)

    print("\n[模块级 API]")
    ck(probe(img) == "hfs+" and probe(_build_hfs_plus(HFSX_SIG, 5)) == "hfsx"
       and probe(_build_hfs_classic()) == "hfs", "probe() 三种签名")
    opener = open_volume(img)
    ck(isinstance(opener, HfsPlus) and opener.block_size == 4096,
       "open_volume() -> HfsPlus")
    ck(isinstance(open_volume(_build_hfs_classic()), Hfs), "open_volume() -> Hfs")
    ck(hfs_time(0) is None and hfs_time(2082844800) == "1970-01-01 00:00:00",
       "hfs_time(0)=None / 纪元边界")
    ck(fs.read_file(readme, limit=5) == b"ESK H", "read_file(limit=5) 截断")
    (rec_pid,) = struct.unpack(">I", img.read(readme.rec_off + 2, 4))
    ck(3 * 4096 <= readme.rec_off < 7 * 4096 and rec_pid == 16,
       "rec_off 指向 catalog 内真实记录",
       "0x%X parentID=%d" % (readme.rec_off, rec_pid))
    ck(fs.journal_info()["offset"] == 0, "journal_info() 未启用日志时 offset=0")

    print("\n[经典 HFS]")
    img_hfs = _build_hfs_classic()
    hfs = Hfs(img_hfs)
    hi = hfs.info()
    ck(hi["fs"] == "HFS" and hi["volume_name"] == "HFSVOL",
       "MDB 卷名 = HFSVOL", hi["volume_name"])
    ck(hi["block_size"] == 4096 and hi["total_blocks"] == 32,
       "MDB 分配块 = 4096 x 32")
    ck(hi["create_date"] == "2001-09-09 01:46:40", "MDB 创建时间换算",
       hi["create_date"])
    try:
        hfs.listdir()
        raise AssertionError("经典 HFS listdir 应抛 NotImplementedError")
    except NotImplementedError:
        ck(True, "经典 HFS listdir 抛 NotImplementedError")
    wrap = Hfs(_build_hfs_classic(embed=(4, 40)))
    ck(wrap.embedded_volume() == (4 * 4096, 40 * 4096),
       "HFS+ wrapper 内嵌卷定位", wrap.embedded_volume())

    print("\n" + "=" * 68)
    print("自检通过：%d 项断言" % ok)
    print("=" * 68)
    return ok


if __name__ == "__main__":
    import sys
    try:
        _selftest()
    except AssertionError as e:
        print("\n[FAIL] %s" % e)
        sys.exit(1)
