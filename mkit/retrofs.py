# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""老式文件系统：Amiga OFS/FFS、BeOS BeFS、QNX4、QNX6

格式依据：
    Amiga  : ADFlib `src/adf_blk.h`（块图、字段偏移、secType 取值）
    BeFS   : Linux `fs/befs/befs_fs_types.h`、`fs/befs/super.c`、
             `fs/befs/datastream.c`、`fs/befs/linuxvfs.c`
    QNX4   : Linux `include/uapi/linux/qnx4_fs.h`、`qnxtypes.h`、
             `fs/qnx4/inode.c`、`fs/qnx4/dir.c`
    QNX6   : Linux `include/linux/qnx6_fs.h`、`fs/qnx6/inode.c`、
             `fs/qnx6/dir.c`、`include/uapi/linux/magic.h`

五种格式各自实现到哪一步
------------------------
Amiga OFS / FFS（都实现）：
    已实现：
        · 引导块识别（"DOS" + 版本 0..7，bit0 = FFS，bit1 = 国际版，bit2 = 目录缓存）
        · 块大小推断（512 / 1024 / 2048 / 4096，看块 1 是否像根块）
        · 根块（T_HEADER / secType=1）：卷名 BSTR、位图标志与位图页表、创建与最后访问时间
        · 目录块（secType=2 ST_USERDIR / 4 ST_LINKDIR）：72 项哈希表 + nextSameHash 冲突链
        · 文件头块（secType=-3 ST_FILE / -4 ST_LINKFILE）：highSeq、byteSize、
          data_blocks[72]、extension 扩展块链（T_LIST，可多级）
        · OFS 数据块（24 字节块头，取 dataSize 字节）与 FFS 数据块（整块都是数据）
        · 软链接（secType=3，目标串在 realName[64]）
        · 块校验和验证（整块 u32 之和为 0，checksum 字段按 0 计入）
        · 时间换算（1978-01-01 起，days/mins/ticks，1 tick = 1/50 s）
        · listdir / walk / read_file / read_path / find
    不实现：
        · 写操作
        · 位图分配（只报告 bmFlag / bmPages，不据此判空闲块）
        · 目录缓存块（T_DIRC=33）加速（直接走哈希表，结果等价）
        · 引导块里的 rootBlock 字段（软盘 880）不用于定位根块，根块固定取块 1
        · 硬链接目录项的跨卷解析（只按块号跟随）
        · 目录项 size 恒报 0（块头里没有目录字节数，要列目录才知道项数）

BeOS BeFS：
    已实现：
        · 超级块（偏移 512，132 字节，大小端自适应）：name / magic1 / fs_byte_order /
          block_size / block_shift / num_blocks / used_blocks / inode_size / magic2 /
          blocks_per_ag / ag_shift / num_ags / flags / log_blocks / log_start / log_end /
          magic3 / root_dir / indices
        · 三魔数校验（0x42465331 / 0xDD121031 / 0x15B6830E）+ block_shift 与
          block_size 一致性 + ag_shift 与 blocks_per_ag 一致性
        · 块游程（befs_block_run: ag u32 + start u16 + len u16）→ 物理块号
          (ag << ag_shift) + start
        · inode（magic1=0x3BBE0AD9）：inode_num / uid / gid / mode / flags /
          create_time / last_modified_time / parent / attributes / type / size
        · 数据流：direct[12] + indirect + double_indirect 三级，
          按 max_direct_range / max_indirect_range / max_double_indirect_range 分区
        · 数据流长度以 ds.size 为准；块游程不足时返回已读到的前缀
        · 线性目录（befs_dirent 16 字节：inode_num / offset / dir_end / pad，
          名字从 offset 到 dir_end）
        · 短符号链接（inode->data.symlink，144 字节）
        · 时间：last_modified_time 是 64 位 bigtime（低 16 位是唯一性计数器），
          >>16 得 Unix 秒
    不实现：
        · 目录 B+ 树索引（indices 字段只报告，不遍历；目录数据走线性数组）
        · 属性 / small_data 扩展属性解析（只报告 attributes 游程）
        · 日志重放
        · 写操作

QNX4：
    已实现：
        · 超级块（块 1，512 字节块；也接受 4096 偏移的变体）：RootDir / Inode /
          Boot / AltBoot 四个 64 字节 inode 项
        · inode 项（64 字节）：di_fname[16] / di_size / di_first_xtnt / di_xblk /
          ftime / mtime / atime / ctime / di_num_xtnts / di_mode / di_uid / di_gid /
          di_nlink / di_zero[4] / di_type / di_status
        · inode 号映射：block = ino // 8，slot = ino % 8（每 512 字节块 8 个 inode）
        · 目录：连续 64 字节 inode 项数组，fname[0]==0 为空槽，
          di_status 的 USED(0x01) / LINK(0x08) 判定有效性
        · 链接项（dl_fname[48] + dl_inode_blk + dl_inode_ndx）
        · 数据：di_first_xtnt 首段 + di_xblk 扩展块链（"IamXblk" 签名，
          每块 60 个 8 字节 extent）
        · 时间（Unix 秒）、mode 类型判定
    不实现：
        · 写操作
        · .bitmap / .inodes 特殊文件语义（当普通文件读）
        · 长文件名（QNX4 本身无，超过 16 字符的名字在 link 项里是 48 字节）

QNX6：
    已实现：
        · 超级块定位（bootblock 0x2000 处；找不到再试 0）与大小端自适应
          （magic=0x68191122）
        · 超级块校验和（crc32_be(0, sb[8:512])，与 Linux `fs/qnx6` 一致）
        · 字段：sb_magic / sb_checksum / sb_serial / sb_ctime / sb_atime / sb_flags /
          sb_version1 / sb_version2 / sb_volumeid / sb_blocksize / sb_num_inodes /
          sb_free_inodes / sb_num_blocks / sb_free_blocks / sb_allocgroup /
          Inode / Bitmap / Longfile / Unknown 四个 root_node
        · root_node（80 字节：size u64 + ptr[16] u32 + levels + mode + spare）
        · 块指针解析：devblock = ptr + s_blks_off，
          s_blks_off = bootblock/bs + 0x1000/bs（与 Linux 一致）
        · 多级间接：levels 层，每层 ptrbits = log2(blocksize/4) 个指针
        · inode（128 字节）：di_size / di_uid / di_gid / ftime / mtime / atime / ctime /
          di_mode / di_ext_mode / di_block_ptr[16] / di_filelevels / di_status
        · inode 号 → 偏移 (ino-1)*128，在 Inode 流里定位
        · 目录项（32 字节：de_inode u32 + de_size u8 + de_fname[27]），
          de_size==0xFF 时走长文件名（Longfile 流里的 qnx6_long_filename）
        · 长文件名校验和（qnx6_lfile_checksum 的移位异或算法）
        · 读写权限位来自 di_mode 的 S_IFMT
    不实现：
        · 写操作
        · Audi MMI 3G 变体超级块（qnx6_mmi_super_block，布局不同）
        · 第二份超级块的选择（serial 比较）；只读第一份
        · 位图 / 分配组空闲统计

与题面/常见说法不同的地方（以头文件为准，已查证）
------------------------------------------------
    · Amiga secType：-3 是 ST_FILE，不是目录；ST_USERDIR 是 2。
      完整表：1=ST_ROOT、2=ST_USERDIR、3=ST_SOFTLINK、4=ST_LINKDIR、
      -3=ST_FILE、-4=ST_LINKFILE（ADFlib adf_blk.h 的 ADF_ST_*）。
    · Amiga 根块里 0x0C 是 hashTableSize(=72)、0x08 是 highSeq；
      位图表从 0x138 起（bmFlag=-1 表示有效），0x1A0 是 bmExt。
      文件头块同一区域（0x18 起 72 项）是 dataBlocks[]，不是哈希表。
    · BeFS 超级块第三个魔数是 0x15B6830E，不是 0x00414A53；
      超级块到 indices 就结束（132 字节），没有 blocks 字段。
    · BeFS last_modified_time 是 64 位 bigtime_t，低 16 位是唯一性计数器，
      Unix 秒 = 值 >> 16（Linux fs/befs/linuxvfs.c 的做法）。
    · QNX4 inode 项顺序：di_size(16) / di_first_xtnt(20) / di_xblk(28) /
      四个时间(32..48) / di_num_xtnts(48) / mode(50) / uid(52) / gid(54) /
      nlink(56) / di_zero(58) / di_type(62) / di_status(63)。
    · QNX4 每 512 字节块放 8 个 inode，inode 号 = block*8 + slot
      （Linux qnx4_iget：block = ino/8、slot = ino%8）。题面「inode 号直接是
      块号、每块 1 个 inode」不成立。extent 里的块号是 1 基（dev = blk-1）。
      另注：Linux qnx4_readdir 用 `blk*8+ix-1` 算 ino，与 iget 的映射差 1，
      本实现统一按 iget 的映射，不复制该偏差。
    · QNX6 超级块里没有 RootDir/Inodes 这样的块游程，而是四个 qnx6_root_node
      （Inode / Bitmap / Longfile / Unknown，各 80 字节：size u64 + ptr[16] +
      levels + mode）。根目录靠 inode 号 1 从 Inode 流里取。
    · QNX6 目录项是 32 字节槽：de_inode u32 / de_size u8 / de_fname[27]；
      de_size==0xFF 表示长文件名，后面接 de_long_inode u32 + de_checksum u32。
    · QNX6 超级块校验和是 crc32_be(0, sb[8..512])，不是 u32 求和。
    · QNX6 数据块号要加 s_blks_off（= 0x2000/bs + 0x1000/bs）才是设备块号。

仍是推断、没有权威源可核的
--------------------------
    · BeFS 线性目录项布局按题面给的 16 字节（inode_num / offset / dir_end /
      pad）实现：Linux 的 befs 驱动只走 B+ 树索引，不解析这段线性数组，
      Haiku 的 bfs_disk.h 取不到（404），所以这一项是推断。
    · BeFS double_indirect 的项语义：Linux 的 befs_find_brun_dblindirect 里
      `indir_indx = leftover / diblklen` 恒为 0（diblklen 也重复乘了
      BEFS_DBLINDIR_BRUN_LEN），按源码字面无法遍历整个区。本实现按
      「一个双间接项 -> 4 个块的间接游程，游程内每块 bs/8 个 iaddr，
      每个 iaddr 映射 1 个数据块」实现，自检镜像按同一约定构造。
    · QNX6 Bitmap / Unknown 节点只记录不解析（不据此算空闲块）。

契约：只依赖 sub.read(offset, size) 与 sub.size，零第三方依赖。
"""

import struct

__all__ = [
    "probe", "open_fs", "detect_all",
    "AmigaFS", "AmigaEntry", "amiga_to_unix", "amiga_checksum", "AMIGA_EPOCH_DELTA",
    "BeFS", "BeInode", "BEFS_MAGIC1", "BEFS_MAGIC2", "BEFS_MAGIC3", "BEFS_INODE_MAGIC",
    "Qnx4FS", "Qnx4Inode", "QNX4_BLOCK_SIZE", "QNX4_INODES_PER_BLOCK",
    "Qnx6FS", "Qnx6Inode", "QNX6_MAGIC", "QNX6_SUPER_OFFSET", "crc32_be",
    "RetroFSError",
]


class RetroFSError(ValueError):
    """镜像不是该格式，或结构被截断"""


# ------------------------------------------------------------
# 通用小工具
# ------------------------------------------------------------
def _need(buf, off, n, what="字段"):
    if off < 0 or len(buf) < off + n:
        raise RetroFSError("%s 被截断：需要 %d 字节，只有 %d"
                           % (what, off + n, len(buf)))


def _u8(buf, off):
    _need(buf, off, 1)
    return buf[off]


def _u16(buf, off, e=">"):
    _need(buf, off, 2)
    return struct.unpack_from(e + "H", buf, off)[0]


def _u32(buf, off, e=">"):
    _need(buf, off, 4)
    return struct.unpack_from(e + "I", buf, off)[0]


def _s32(buf, off, e=">"):
    _need(buf, off, 4)
    return struct.unpack_from(e + "i", buf, off)[0]


def _u64(buf, off, e=">"):
    _need(buf, off, 8)
    return struct.unpack_from(e + "Q", buf, off)[0]


def _dec(raw):
    return raw.decode("utf-8", "replace")


def _cstr(raw):
    """NUL 结尾的字节串"""
    z = raw.find(b"\x00")
    return raw[:z] if z >= 0 else raw


def _size_of(sub):
    n = getattr(sub, "size", None)
    if n is None:
        try:
            n = sub.read(0, 1 << 62)
            n = len(n)
        except Exception:
            n = None
    return n


def crc32_be(crc, data):
    """Linux `crc32_be`：MSB-first、多项式 0x04C11DB7、无输入/输出取反

    校验：crc32_be(0xFFFFFFFF, b"123456789") == 0x0376E6E7
    """
    crc &= 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc & 0xFFFFFFFF


# ============================================================
#  A. Amiga OFS / FFS
# ============================================================
AMIGA_EPOCH_DELTA = 252460800        # 1978-01-01 - 1970-01-01，单位秒
AMIGA_TICKS_PER_SEC = 50

A_T_HEADER = 2
A_T_LIST = 16
A_T_DATA = 8

A_ST_ROOT = 1                        # 根块
A_ST_DIR = 2                         # ST_USERDIR
A_ST_SOFTLINK = 3                    # ST_SOFTLINK
A_ST_LINKDIR = 4                     # ST_LINKDIR
A_ST_FILE = -3                       # ST_FILE
A_ST_LINKFILE = -4                   # ST_LINKFILE

A_HT_SIZE = 72
A_MAX_NAME = 30
A_BM_PAGES_ROOT = 25

# 块内偏移（ADFlib src/adf_blk.h 注释里的偏移逐条核对过）
A_TYPE = 0x000
A_HEADERKEY = 0x004
A_HIGHSEQ = 0x008
A_HASHSIZE = 0x00C
A_FIRSTDATA = 0x010
A_CHECKSUM = 0x014
A_HASHTABLE = 0x018
A_BMFLAG = 0x138
A_BMPAGES = 0x13C
A_BMEXT = 0x1A0
A_CDAYS = 0x1A4
A_CMINS = 0x1A8
A_CTICKS = 0x1AC
A_NAMELEN = 0x1B0
A_NAME = 0x1B1
A_ACCESS = 0x140
A_BYTESIZE = 0x144
A_COMMLEN = 0x148
A_COMMENT = 0x149
A_DAYS = 0x1D8
A_MINS = 0x1DC
A_TICKS = 0x1E0
A_CODAYS = 0x1E4
A_COMINS = 0x1E8
A_COTICKS = 0x1EC
A_NEXTHASH = 0x1F0
A_PARENT = 0x1F4
A_EXTENSION = 0x1F8
A_SECTYPE = 0x1FC

A_SECTYPE_NAME = {
    A_ST_ROOT: "root",
    A_ST_DIR: "dir",
    A_ST_SOFTLINK: "softlink",
    A_ST_LINKDIR: "linkdir",
    A_ST_FILE: "file",
    A_ST_LINKFILE: "linkfile",
}


def amiga_to_unix(days, mins, ticks):
    """Amiga 时间 -> Unix 秒。

    days 是 1978-01-01 起的天数，mins 是当日分钟，ticks 是 1/50 秒。
    days=0/mins=0/ticks=0 -> 1978-01-01T00:00:00Z -> 252460800
    """
    return days * 86400 + mins * 60 + ticks / float(AMIGA_TICKS_PER_SEC) \
        + AMIGA_EPOCH_DELTA


def amiga_checksum(block):
    """Amiga 块校验和：先把 checksum 字段当 0，取整块 u32 之和的相反数。

    验证方式：以 checksum 字段为 0 求和，结果应为 0（模 2^32）。
    """
    if len(block) < 0x200:
        raise RetroFSError("Amiga 块至少 512 字节")
    total = 0
    for off in range(0, len(block) - (len(block) % 4), 4):
        total = (total + struct.unpack_from(">I", block, off)[0]) & 0xFFFFFFFF
    return total


def amiga_block_checksum_ok(block):
    return amiga_checksum(block) == 0


class AmigaEntry(object):
    """一个 Amiga 块头（根/目录/文件/链接）"""

    __slots__ = ("block", "sec_type", "name", "hash_size", "parent", "extension",
                 "high_seq", "byte_size", "data_blocks", "access", "days",
                 "mins", "ticks", "link_target", "raw_type")

    def __init__(self):
        self.block = 0
        self.sec_type = 0
        self.name = ""
        self.hash_size = 0
        self.parent = 0
        self.extension = 0
        self.high_seq = 0
        self.byte_size = 0
        self.data_blocks = []
        self.access = 0
        self.days = 0
        self.mins = 0
        self.ticks = 0
        self.link_target = b""
        self.raw_type = 0

    # ---- 类型 ----
    @property
    def is_root(self):
        return self.sec_type == A_ST_ROOT

    @property
    def is_dir(self):
        return self.sec_type in (A_ST_ROOT, A_ST_DIR, A_ST_LINKDIR)

    @property
    def is_file(self):
        return self.sec_type in (A_ST_FILE, A_ST_LINKFILE)

    @property
    def is_softlink(self):
        return self.sec_type == A_ST_SOFTLINK

    @property
    def type_name(self):
        return A_SECTYPE_NAME.get(self.sec_type, "?")

    @property
    def size(self):
        return self.byte_size

    @property
    def mtime(self):
        """最后访问时间 -> Unix 秒（float，含 ticks 的 1/50 秒）"""
        return amiga_to_unix(self.days, self.mins, self.ticks)

    @property
    def mode(self):
        if self.is_dir:
            return 0o040000 | 0o755
        return 0o100000 | 0o644

    def __repr__(self):
        return "<AmigaEntry %s %r blk=%d %dB>" % (self.type_name, self.name,
                                                  self.block, self.byte_size)


def _amiga_guess_bs(sub):
    """Amiga 块大小推断：块 1 得像个根块（T_HEADER / ST_ROOT / bmFlag=-1 / 72 项哈希）"""
    for bs in (512, 1024, 2048, 4096):
        raw = sub.read(bs, 0x200)
        if len(raw) < 0x200:
            continue
        if _u32(raw, A_TYPE) != A_T_HEADER:
            continue
        if _u32(raw, A_SECTYPE) != A_ST_ROOT:
            continue
        if _u32(raw, A_BMFLAG) != 0xFFFFFFFF:
            continue
        hs = _u32(raw, A_HASHSIZE)
        if not (1 <= hs <= 1024):
            continue
        return bs
    return 512


class AmigaFS(object):
    """Amiga OFS/FFS 只读。OFS 与 FFS 共用块头，只差数据块有没有 24 字节头。"""

    def __init__(self, sub, block_size=None):
        self.sub = sub
        self.image_size = _size_of(sub) or 0
        head = sub.read(0, 4)
        if len(head) < 4:
            raise RetroFSError("镜像太短（%d 字节），读不到 Amiga 引导块"
                               % self.image_size)
        if head[:3] != b"DOS":
            raise RetroFSError("不是 Amiga DOS 文件系统（引导块魔数 %r）" % head[:4])
        if head[3] > 7:
            raise RetroFSError("Amiga DOS 版本号非法：%d" % head[3])

        self.dos_version = head[3]
        self.ffs = bool(self.dos_version & 1)
        self.international = bool(self.dos_version & 2)
        self.dircache = bool(self.dos_version & 4)
        self.variant = "ffs" if self.ffs else "ofs"

        self.block_size = block_size or _amiga_guess_bs(sub)
        if self.block_size < 512 or self.block_size % 512:
            raise RetroFSError("Amiga 块大小非法：%r" % (self.block_size,))

        self.root_block = 1
        if self.image_size < (self.root_block + 1) * self.block_size:
            raise RetroFSError("镜像太短（%d 字节），读不到 Amiga 块 %d（根块，需到 %d）"
                               % (self.image_size, self.root_block,
                                  (self.root_block + 1) * self.block_size))
        self.root = self.entry(self.root_block)
        if self.root is None or self.root.raw_type != A_T_HEADER:
            raise RetroFSError("块 1 不是 Amiga 根块（type=%r）"
                               % (None if self.root is None else self.root.raw_type))
        if not self.root.is_root:
            raise RetroFSError("块 1 的 secType=%d，不是 ST_ROOT(1)"
                               % self.root.sec_type)
        self.label = self.root.name

    # ---------------- 基础设施 ----------------
    def _blk(self, blkno):
        # 块 0 是引导块，校验和时要用；只有负块号才算越界
        if blkno < 0 or self.block_size <= 0:
            return b""
        off = blkno * self.block_size
        if off >= self.image_size:
            return b""
        return self.sub.read(off, self.block_size)

    @property
    def block_count(self):
        return self.image_size // self.block_size if self.block_size else 0

    def checksum_ok(self, blkno):
        raw = self._blk(blkno)
        if len(raw) < self.block_size:
            return False
        return amiga_block_checksum_ok(raw)

    def info(self):
        return {
            "format": "amiga-%s" % self.variant,
            "variant": self.variant,
            "dos_version": self.dos_version,
            "international": self.international,
            "dir_cache": self.dircache,
            "block_size": self.block_size,
            "block_count": self.block_count,
            "label": self.label,
            "root_block": self.root_block,
            "hash_size": self.root.hash_size,
            "bm_flag": "0x%08X" % self._bm_flag,
            "bm_pages": self._bm_pages,
            "bm_ext": self.root.extension,
            "created": amiga_to_unix(self._c_days, self._c_mins, self._c_ticks),
            "root_checksum_ok": self.checksum_ok(self.root_block),
        }

    # ---------------- 块头 ----------------
    def entry(self, blkno):
        raw = self._blk(blkno)
        if len(raw) < 0x200:
            return None
        e = AmigaEntry()
        e.block = blkno
        e.raw_type = _u32(raw, A_TYPE)
        e.sec_type = _s32(raw, A_SECTYPE)
        e.hash_size = _u32(raw, A_HASHSIZE)
        e.high_seq = _u32(raw, A_HIGHSEQ)
        e.parent = _u32(raw, A_PARENT)
        e.extension = _u32(raw, A_EXTENSION)
        e.access = _u32(raw, A_ACCESS)
        e.days = _u32(raw, A_DAYS)
        e.mins = _u32(raw, A_MINS)
        e.ticks = _u32(raw, A_TICKS)

        nlen = _u8(raw, A_NAMELEN)
        if nlen > A_MAX_NAME:
            nlen = A_MAX_NAME
        e.name = _dec(raw[A_NAME:A_NAME + nlen])

        if e.is_file:
            e.byte_size = _u32(raw, A_BYTESIZE)
            cnt = e.high_seq if e.high_seq else A_HT_SIZE
            cnt = min(cnt, A_HT_SIZE)
            e.data_blocks = [_u32(raw, A_HASHTABLE + 4 * i) for i in range(cnt)]
        elif e.is_softlink:
            e.link_target = _cstr(raw[0x18:0x18 + 64])
            e.byte_size = len(e.link_target)
        else:
            e.byte_size = 0
        return e

    # ---------------- 目录 ----------------
    def _hash_table(self, block_content):
        """目录/根块里的哈希表项（块号列表）"""
        hs = _u32(block_content, A_HASHSIZE)
        if not (1 <= hs <= 1024):
            hs = A_HT_SIZE
        hs = min(hs, (self.block_size - A_HASHTABLE) // 4)
        return [_u32(block_content, A_HASHTABLE + 4 * i) for i in range(hs)]

    def listdir(self, entry=None):
        """列目录。entry=None 表示根。返回 AmigaEntry 列表。"""
        e = entry if entry is not None else self.root
        if not e.is_dir:
            raise RetroFSError("不是目录：%r（%s）" % (e.name, e.type_name))
        raw = self._blk(e.block)
        if len(raw) < 0x200:
            return []

        out = []
        seen = set()
        for head in self._hash_table(raw):
            b = head
            guard = 0
            while b and b not in seen and guard < 4096:
                guard += 1
                seen.add(b)
                ch = self.entry(b)
                if ch is None:
                    break
                out.append(ch)
                nxt = self._blk(b)
                if len(nxt) < 0x200:
                    break
                b = _u32(nxt, A_NEXTHASH)
        return out

    def lookup(self, entry, name):
        """按名字找目录项（大小写不敏感，Amiga 惯例）"""
        low = name.lower()
        for it in self.listdir(entry):
            if it.name.lower() == low:
                return it
        return None

    def walk(self, entry=None, _depth=0, _max=32):
        prefix = "" if entry is None else entry.name + "/"
        for it in self.listdir(entry):
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            if it.is_dir and _depth < _max:
                for sn, si in self.walk(it, _depth + 1, _max):
                    yield prefix + sn, si

    def find(self, pattern):
        pat = pattern.lower()
        return [(p, e) for p, e in self.walk() if pat in p.lower()]

    # ---------------- 数据 ----------------
    def _data_block_list(self, entry):
        blocks = list(entry.data_blocks)
        ext = entry.extension
        guard = 0
        while ext and guard < 4096:
            guard += 1
            raw = self._blk(ext)
            if len(raw) < 0x200 or _u32(raw, A_TYPE) != A_T_LIST:
                break
            for i in range(A_HT_SIZE):
                b = _u32(raw, A_HASHTABLE + 4 * i)
                if b:
                    blocks.append(b)
            ext = _u32(raw, A_EXTENSION)
        return blocks

    def read_file(self, entry):
        e = entry if entry is not None else self.root
        if e.is_softlink:
            return e.link_target
        if not e.is_file:
            return None
        want = e.byte_size
        if want <= 0:
            return b""
        out = bytearray()
        for b in self._data_block_list(e):
            if len(out) >= want:
                break
            raw = self._blk(b)
            if len(raw) < 0x200:
                continue
            if self.ffs:
                out += raw
            else:
                n = _u32(raw, 0x0C)              # OFS: dataSize
                if n > self.block_size - 24:
                    n = self.block_size - 24
                out += raw[24:24 + n]
        return bytes(out[:want])

    def read_path(self, path):
        cur = None
        for part in [p for p in path.split("/") if p]:
            hit = None
            for it in self.listdir(cur):
                if it.name.lower() == part.lower():
                    hit = it
                    break
            if hit is None:
                raise FileNotFoundError(path)
            cur = hit
        if cur is None:
            return None
        return self.read_file(cur)

    # 根块的位图/创建时间在 entry() 里没暴露，单独补
    @property
    def _bm_flag(self):
        raw = self._blk(self.root_block)
        return _u32(raw, A_BMFLAG) if len(raw) >= 0x200 else 0

    @property
    def _bm_pages(self):
        raw = self._blk(self.root_block)
        if len(raw) < 0x200:
            return []
        return [_s32(raw, A_BMPAGES + 4 * i) for i in range(A_BM_PAGES_ROOT)]

    @property
    def _c_days(self):
        raw = self._blk(self.root_block)
        return _s32(raw, A_CDAYS) if len(raw) >= 0x200 else 0

    @property
    def _c_mins(self):
        raw = self._blk(self.root_block)
        return _s32(raw, A_CMINS) if len(raw) >= 0x200 else 0

    @property
    def _c_ticks(self):
        raw = self._blk(self.root_block)
        return _s32(raw, A_CTICKS) if len(raw) >= 0x200 else 0


def _amiga_probe(sub):
    head = sub.read(0, 4)
    if len(head) < 4 or head[:3] != b"DOS" or head[3] > 7:
        return False
    bs = _amiga_guess_bs(sub)
    raw = sub.read(bs, 0x200)
    if len(raw) < 0x200:
        return False
    return (_u32(raw, A_TYPE) == A_T_HEADER
            and _u32(raw, A_SECTYPE) == A_ST_ROOT
            and _u32(raw, A_BMFLAG) == 0xFFFFFFFF)


# ============================================================
#  B. BeOS BeFS
# ============================================================
BEFS_SUPER_OFFSET = 512
BEFS_MAGIC1 = 0x42465331              # "BFS1"
BEFS_MAGIC2 = 0xDD121031
BEFS_MAGIC3 = 0x15B6830E             # 头文件里是 0x15b6830e，不是 0x00414A53
BEFS_INODE_MAGIC = 0x3BBE0AD9
BEFS_BYTEORDER_NATIVE = 0x42494745   # "BIGE"
BEFS_CLEAN = 0x434C454E
BEFS_DIRTY = 0x44495254
BEFS_NAME_LEN = 255
BEFS_SYMLINK_LEN = 144
BEFS_NUM_DIRECT_BLOCKS = 12
BEFS_DBLINDIR_BRUN_LEN = 4

# 超级块偏移（befs_fs_types.h 逐字段算过，总长 132 = 0x84）
BS_NAME = 0x00
BS_MAGIC1 = 0x20
BS_BYTEORDER = 0x24
BS_BLOCK_SIZE = 0x28
BS_BLOCK_SHIFT = 0x2C
BS_NUM_BLOCKS = 0x30
BS_USED_BLOCKS = 0x38
BS_INODE_SIZE = 0x40
BS_MAGIC2 = 0x44
BS_BLOCKS_PER_AG = 0x48
BS_AG_SHIFT = 0x4C
BS_NUM_AGS = 0x50
BS_FLAGS = 0x54
BS_LOG_BLOCKS = 0x58
BS_LOG_START = 0x60
BS_LOG_END = 0x68
BS_MAGIC3 = 0x70
BS_ROOT_DIR = 0x74
BS_INDICES = 0x7C
BEFS_SUPER_LEN = 0x84

# inode 偏移
BI_MAGIC1 = 0
BI_INODE_NUM = 4
BI_UID = 12
BI_GID = 16
BI_MODE = 20
BI_FLAGS = 24
BI_CTIME = 28
BI_MTIME = 36
BI_PARENT = 44
BI_ATTRIBUTES = 52
BI_TYPE = 60
BI_INODE_SIZE = 64
BI_ETC = 68
BI_DATA = 72
# befs_data_stream（在 inode 里从 72 开始，长 144）
DS_DIRECT = 0
DS_MAX_DIRECT = 96
DS_INDIRECT = 104
DS_MAX_INDIRECT = 112
DS_DOUBLE = 120
DS_MAX_DOUBLE = 128
DS_SIZE = 136
DS_LEN = 144

BEFS_TYPE_NAME = {0: "file", 1: "file", 2: "dir", 3: "symlink"}


class BeInode(object):
    __slots__ = ("block", "inode_num", "uid", "gid", "mode", "flags",
                 "create_time", "last_modified_time", "parent", "attributes",
                 "type", "inode_size", "ds", "symlink", "name")

    def __init__(self):
        self.block = 0
        self.inode_num = (0, 0, 0)
        self.uid = 0
        self.gid = 0
        self.mode = 0
        self.flags = 0
        self.create_time = 0            # 原始 bigtime_t（u64，低 16 位是计数器）
        self.last_modified_time = 0     # 同上
        self.parent = (0, 0, 0)
        self.attributes = (0, 0, 0)
        self.type = 0
        self.inode_size = 0
        self.ds = None
        self.symlink = b""
        self.name = ""

    @property
    def ctime(self):
        """创建时间 -> Unix 秒（高位 48 位）"""
        return self.create_time >> 16

    @property
    def mtime(self):
        """最后修改时间 -> Unix 秒（Linux bef s: fs64 >> 16）"""
        return self.last_modified_time >> 16

    @property
    def is_dir(self):
        if (self.mode & 0o170000) == 0o040000:
            return True
        return (self.mode & 0o170000) == 0 and self.type == 2

    @property
    def is_file(self):
        if (self.mode & 0o170000) == 0o100000:
            return True
        return (self.mode & 0o170000) == 0 and self.type in (0, 1)

    @property
    def is_symlink(self):
        return (self.mode & 0o170000) == 0o120000

    @property
    def size(self):
        return self.ds["size"] if self.ds else 0

    @property
    def type_name(self):
        if self.is_dir:
            return "dir"
        if self.is_symlink:
            return "symlink"
        if self.is_file:
            return "file"
        return "?"

    def __repr__(self):
        return "<BeInode %s blk=%d %dB>" % (self.type_name, self.block,
                                            self.size if self.ds else 0)


class BeFS(object):
    """BeOS BeFS 只读（线性目录；B+ 树索引不遍历）"""

    def __init__(self, sub):
        self.sub = sub
        self.image_size = _size_of(sub) or 0
        raw = sub.read(BEFS_SUPER_OFFSET, BEFS_SUPER_LEN)
        if len(raw) < BEFS_SUPER_LEN:
            raise RetroFSError("镜像太短，读不到 BeFS 超级块（偏移 512 起 %d 字节）"
                               % BEFS_SUPER_LEN)

        be = _u32(raw, BS_MAGIC1, ">")
        le = _u32(raw, BS_MAGIC1, "<")
        if be == BEFS_MAGIC1:
            self.endian = ">"
        elif le == BEFS_MAGIC1:
            self.endian = "<"
        else:
            raise RetroFSError("不是 BeFS（magic1=0x%08X/0x%08X，期望 0x%08X）"
                               % (be, le, BEFS_MAGIC1))

        e = self.endian
        self.raw_super = raw
        self.label = _cstr(raw[BS_NAME:BS_NAME + 32])
        self.magic1 = _u32(raw, BS_MAGIC1, e)
        self.fs_byte_order = _u32(raw, BS_BYTEORDER, e)
        self.block_size = _u32(raw, BS_BLOCK_SIZE, e)
        self.block_shift = _u32(raw, BS_BLOCK_SHIFT, e)
        self.num_blocks = _u64(raw, BS_NUM_BLOCKS, e)
        self.used_blocks = _u64(raw, BS_USED_BLOCKS, e)
        self.inode_size = _u32(raw, BS_INODE_SIZE, e)
        self.magic2 = _u32(raw, BS_MAGIC2, e)
        self.blocks_per_ag = _u32(raw, BS_BLOCKS_PER_AG, e)
        self.ag_shift = _u32(raw, BS_AG_SHIFT, e)
        self.num_ags = _u32(raw, BS_NUM_AGS, e)
        self.flags = _u32(raw, BS_FLAGS, e)
        self.log_blocks = self._brun(raw, BS_LOG_BLOCKS, e)
        self.log_start = _u64(raw, BS_LOG_START, e)
        self.log_end = _u64(raw, BS_LOG_END, e)
        self.magic3 = _u32(raw, BS_MAGIC3, e)
        self.root_dir = self._brun(raw, BS_ROOT_DIR, e)
        self.indices = self._brun(raw, BS_INDICES, e)

        if self.magic2 != BEFS_MAGIC2 or self.magic3 != BEFS_MAGIC3:
            raise RetroFSError("BeFS 超级块魔数不符：magic2=0x%08X magic3=0x%08X"
                               % (self.magic2, self.magic3))
        if self.block_size not in (1024, 2048, 4096, 8192):
            raise RetroFSError("BeFS 块大小非法：%d" % self.block_size)
        if (1 << self.block_shift) != self.block_size:
            raise RetroFSError("BeFS block_shift(%d) 与 block_size(%d) 不一致"
                               % (self.block_shift, self.block_size))
        if (1 << self.ag_shift) != self.blocks_per_ag:
            self.ag_consistent = False
        else:
            self.ag_consistent = True

        self.root = self.read_inode_addr(self.root_dir)
        if self.root is None:
            raise RetroFSError("BeFS 根 inode 读不出来：游程 %r" % (self.root_dir,))
        self.root.name = "/"

    # ---------------- 基础设施 ----------------
    @staticmethod
    def _brun(raw, off, e=">"):
        """befs_block_run：allocation_group u32 + start u16 + len u16"""
        _need(raw, off, 8)
        ag, start, ln = struct.unpack_from(e + "IHH", raw, off)
        return (ag, start, ln)

    def block_of(self, run):
        """块游程 -> 物理块号：(ag << ag_shift) + start"""
        ag, start, ln = run
        return (ag << self.ag_shift) + start

    def _blk(self, phys):
        if phys < 0:
            return b""
        off = phys * self.block_size
        if off >= self.image_size:
            return b""
        return self.sub.read(off, self.block_size)

    def info(self):
        return {
            "format": "befs",
            "label": _dec(self.label),
            "endian": "big" if self.endian == ">" else "little",
            "fs_byte_order": "0x%08X" % self.fs_byte_order,
            "block_size": self.block_size,
            "block_shift": self.block_shift,
            "num_blocks": self.num_blocks,
            "used_blocks": self.used_blocks,
            "inode_size": self.inode_size,
            "blocks_per_ag": self.blocks_per_ag,
            "ag_shift": self.ag_shift,
            "num_ags": self.num_ags,
            "ag_consistent": self.ag_consistent,
            "clean": (self.flags != BEFS_DIRTY and self.log_start == self.log_end),
            "root_dir": self.root_dir,
            "indices": self.indices,
            "magic1": "0x%08X" % self.magic1,
            "magic2": "0x%08X" % self.magic2,
            "magic3": "0x%08X" % self.magic3,
        }

    # ---------------- inode ----------------
    def read_inode_addr(self, run):
        if run[2] == 0:
            return None
        return self.read_inode(self.block_of(run))

    def read_inode(self, phys):
        """inode 号就是块号（Linux 里 sb_bread(sb, inode->i_ino)）"""
        raw = self._blk(phys)
        if len(raw) < 232:
            return None
        if _u32(raw, BI_MAGIC1, self.endian) != BEFS_INODE_MAGIC:
            return None
        e = self.endian
        ino = BeInode()
        ino.block = phys
        ino.inode_num = self._brun(raw, BI_INODE_NUM, e)
        ino.uid = _u32(raw, BI_UID, e)
        ino.gid = _u32(raw, BI_GID, e)
        ino.mode = _u32(raw, BI_MODE, e)
        ino.flags = _u32(raw, BI_FLAGS, e)
        ino.create_time = _u64(raw, BI_CTIME, e)
        ino.last_modified_time = _u64(raw, BI_MTIME, e)
        ino.parent = self._brun(raw, BI_PARENT, e)
        ino.attributes = self._brun(raw, BI_ATTRIBUTES, e)
        ino.type = _u32(raw, BI_TYPE, e)
        ino.inode_size = _u32(raw, BI_INODE_SIZE, e)
        ino.symlink = raw[BI_DATA:BI_DATA + BEFS_SYMLINK_LEN]
        ino.ds = self._read_ds(raw, BI_DATA)
        return ino

    def _read_ds(self, raw, base):
        e = self.endian
        ds = {"direct": [], "max_direct": 0, "indirect": (0, 0, 0),
              "max_indirect": 0, "double": (0, 0, 0), "max_double": 0, "size": 0}
        for i in range(BEFS_NUM_DIRECT_BLOCKS):
            ds["direct"].append(self._brun(raw, base + DS_DIRECT + 8 * i, e))
        ds["max_direct"] = _u64(raw, base + DS_MAX_DIRECT, e)
        ds["indirect"] = self._brun(raw, base + DS_INDIRECT, e)
        ds["max_indirect"] = _u64(raw, base + DS_MAX_INDIRECT, e)
        ds["double"] = self._brun(raw, base + DS_DOUBLE, e)
        ds["max_double"] = _u64(raw, base + DS_MAX_DOUBLE, e)
        ds["size"] = _u64(raw, base + DS_SIZE, e)
        return ds

    # ---------------- 数据流 ----------------
    def _ds_block(self, ds, blockno):
        """逻辑块 -> 物理块（对应 befs_fblock2brun）"""
        e = self.endian
        bs = self.block_size
        per_block = bs // 8
        byte = blockno * bs

        if byte < ds["max_direct"]:
            total = 0
            for run in ds["direct"]:
                if run[2] and total <= blockno < total + run[2]:
                    return self.block_of((run[0], run[1], run[2])) + (blockno - total)
                total += run[2]
            return None

        if byte < ds["max_indirect"]:
            start = ds["max_direct"] >> self.block_shift
            search = blockno - start
            base = self.block_of(ds["indirect"])
            total = 0
            for i in range(ds["indirect"][2]):
                raw = self._blk(base + i)
                if len(raw) < bs:
                    return None
                for j in range(per_block):
                    run = self._brun(raw, j * 8, e)
                    ln = run[2]
                    if ln and total <= search < total + ln:
                        return self.block_of(run) + (search - total)
                    total += ln
            return None

        if byte < ds["max_double"]:
            # 双间接：数组项指向「间接游程」（BEFS_DBLINDIR_BRUN_LEN 个块），
            # 每个间接游程块里有 bs/8 个 iaddr，每个 iaddr 映射 1 个数据块
            start = ds["max_indirect"] >> self.block_shift
            search = blockno - start
            if search < 0:
                return None
            span = BEFS_DBLINDIR_BRUN_LEN * per_block    # 每个双间接项覆盖的数据块
            idx = search // span
            within = search % span
            base = self.block_of(ds["double"])
            if idx >= ds["double"][2] * per_block:
                return None
            raw = self._blk(base + idx // per_block)
            if len(raw) < bs:
                return None
            run = self._brun(raw, (idx % per_block) * 8, e)   # -> 间接游程
            if run[2] == 0:
                return None
            ind = self.block_of(run)
            raw2 = self._blk(ind + within // per_block)
            if len(raw2) < bs:
                return None
            run2 = self._brun(raw2, (within % per_block) * 8, e)
            if run2[2] == 0:
                return None
            return self.block_of(run2)
        return None

    def read_stream(self, ds, size=None):
        if ds is None:
            return b""
        want = ds["size"] if size is None else size
        if want <= 0:
            return b""
        out = bytearray()
        nblocks = (want + self.block_size - 1) // self.block_size
        for i in range(nblocks):
            p = self._ds_block(ds, i)
            if p is None:
                break
            raw = self._blk(p)
            if not raw:
                break
            out += raw
        return bytes(out[:want])

    # ---------------- 目录 ----------------
    def listdir(self, inode=None):
        ino = inode if inode is not None else self.root
        if not ino.is_dir:
            raise RetroFSError("不是 BeFS 目录：块 %d（%s）" % (ino.block, ino.type_name))
        data = self.read_stream(ino.ds)
        n = len(data)
        out = []
        pos = 0
        guard = 0
        while pos + 16 <= n and guard < 1 << 20:
            guard += 1
            inum = _u32(data, pos, self.endian)
            noff = _u32(data, pos + 4, self.endian)
            dend = _u32(data, pos + 8, self.endian)
            if dend == 0 or pos + dend > n:
                break
            if noff < 16 or noff > dend:
                break
            name = _dec(_cstr(data[pos + noff:pos + dend]))
            child = self.read_inode(inum) if inum else None
            if child is None:
                child = BeInode()
                child.block = inum
                child.mode = 0
            child.name = name
            out.append(child)
            pos += dend
        return out

    def lookup(self, inode, name):
        for it in self.listdir(inode):
            if it.name == name:
                return it
        return None

    def walk(self, inode=None, _depth=0, _max=32):
        prefix = "" if inode is None else inode.name + "/"
        for it in self.listdir(inode):
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            if it.is_dir and _depth < _max:
                for sn, si in self.walk(it, _depth + 1, _max):
                    yield prefix + sn, si

    def find(self, pattern):
        pat = pattern.lower()
        return [(p, e) for p, e in self.walk() if pat in p.lower()]

    # ---------------- 数据 ----------------
    def read_file(self, inode):
        ino = inode if inode is not None else self.root
        if ino.is_dir:
            return None
        if ino.is_symlink:
            if ino.flags & 0x40:              # BEFS_LONG_SYMLINK
                return self.read_stream(ino.ds)
            return _cstr(ino.symlink)
        return self.read_stream(ino.ds)

    def read_path(self, path):
        cur = None
        for part in [p for p in path.split("/") if p]:
            hit = None
            for it in self.listdir(cur):
                if it.name == part:
                    hit = it
                    break
            if hit is None:
                raise FileNotFoundError(path)
            cur = hit
        if cur is None:
            return None
        return self.read_file(cur)


def _befs_probe(sub):
    raw = sub.read(BEFS_SUPER_OFFSET, BEFS_SUPER_LEN)
    if len(raw) < BEFS_SUPER_LEN:
        return False
    be = _u32(raw, BS_MAGIC1, ">")
    if be == BEFS_MAGIC1:
        e = ">"
    elif _u32(raw, BS_MAGIC1, "<") == BEFS_MAGIC1:
        e = "<"
    else:
        return False
    if _u32(raw, BS_MAGIC2, e) != BEFS_MAGIC2:
        return False
    if _u32(raw, BS_MAGIC3, e) != BEFS_MAGIC3:
        return False
    bs = _u32(raw, BS_BLOCK_SIZE, e)
    shift = _u32(raw, BS_BLOCK_SHIFT, e)
    if bs not in (1024, 2048, 4096, 8192):
        return False
    if shift > 20 or (1 << shift) != bs:
        return False
    return True


# ============================================================
#  C1. QNX4
# ============================================================
QNX4_SUPER_OFFSETS = (512, 4096)
QNX4_BLOCK_SIZE = 0x200
QNX4_INODES_PER_BLOCK = 8
QNX4_DIR_ENTRY_SIZE = 64
QNX4_MAX_XTNTS = 60
QNX4_BMNAME = ".bitmap"

Q4_FILE_USED = 0x01
Q4_FILE_MODIFIED = 0x02
Q4_FILE_BUSY = 0x04
Q4_FILE_LINK = 0x08
Q4_FILE_INODE = 0x10

# inode 项偏移（qnx4_fs.h + qnxtypes.h 逐字段核对，共 64 字节）
Q4_FNAME = 0
Q4_SIZE = 16
Q4_FIRST_XTNT = 20
Q4_XBLK = 28
Q4_FTIME = 32
Q4_MTIME = 36
Q4_ATIME = 40
Q4_CTIME = 44
Q4_NUM_XTNTS = 48
Q4_MODE = 50
Q4_UID = 52
Q4_GID = 54
Q4_NLINK = 56
Q4_ZERO = 58
Q4_TYPE = 62
Q4_STATUS = 63
QNX4_INODE_LEN = 64

# 扩展块 qnx4_xblk
X_NEXT = 0
X_PREV = 4
X_NUM_XTNTS = 8
X_SPARE = 9
X_NUM_BLOCKS = 12
X_XTNTS = 16
X_SIGNATURE = 496
X_FIRST_XTNT = 504
QNX4_XBLK_SIG = b"IamXblk"


class Qnx4Inode(object):
    __slots__ = ("blk", "slot", "name", "size", "extents", "xblk", "ftime",
                 "mtime", "atime", "ctime", "num_xtnts", "mode", "uid", "gid",
                 "nlink", "ftype", "status", "raw")

    def __init__(self):
        self.blk = 0
        self.slot = 0
        self.name = ""
        self.size = 0
        self.extents = []
        self.xblk = 0
        self.ftime = 0
        self.mtime = 0
        self.atime = 0
        self.ctime = 0
        self.num_xtnts = 0
        self.mode = 0
        self.uid = 0
        self.gid = 0
        self.nlink = 0
        self.ftype = 0
        self.status = 0
        self.raw = b""

    @property
    def ino(self):
        return self.blk * QNX4_INODES_PER_BLOCK + self.slot

    @property
    def is_dir(self):
        return (self.mode & 0o170000) == 0o040000

    @property
    def is_file(self):
        return (self.mode & 0o170000) == 0o100000

    @property
    def is_symlink(self):
        return (self.mode & 0o170000) == 0o120000

    @property
    def is_link_entry(self):
        return bool(self.status & Q4_FILE_LINK)

    @property
    def type_name(self):
        if self.is_dir:
            return "dir"
        if self.is_symlink:
            return "symlink"
        if self.is_file:
            return "file"
        return "ftype%d" % self.ftype

    def __repr__(self):
        return "<Qnx4Inode %s %r ino=%d %dB>" % (self.type_name, self.name,
                                                 self.ino, self.size)


class Qnx4FS(object):
    """QNX4 只读（512 字节块，每块 8 个 inode，extent 从 1 开始编号）"""

    def __init__(self, sub):
        self.sub = sub
        self.image_size = _size_of(sub) or 0
        if self.image_size < 1024:
            raise RetroFSError("镜像太短（%d 字节），读不到 QNX4 超级块"
                               % self.image_size)
        self.super_offset = None
        for off in QNX4_SUPER_OFFSETS:
            raw = sub.read(off, QNX4_INODE_LEN)
            if len(raw) < QNX4_INODE_LEN:
                continue
            if raw[Q4_FNAME:Q4_FNAME + 2] == b"/\x00":
                self.super_offset = off
                break
        if self.super_offset is None:
            raise RetroFSError("不是 QNX4（块 1 / 4096 偏移处的 RootDir 名字不是 \"/\"）")

        self.block_size = QNX4_BLOCK_SIZE
        self.raw_super = sub.read(self.super_offset, 4 * QNX4_INODE_LEN)
        self.root = self.inode_at(self.super_offset // QNX4_BLOCK_SIZE, 0)
        self.root.name = "/"
        self.inodes_entry = self._parse_inode(
            self.raw_super[QNX4_INODE_LEN:2 * QNX4_INODE_LEN], 1, 1)
        self.boot_entry = self._parse_inode(
            self.raw_super[2 * QNX4_INODE_LEN:3 * QNX4_INODE_LEN], 1, 2)
        self.altboot_entry = self._parse_inode(
            self.raw_super[3 * QNX4_INODE_LEN:4 * QNX4_INODE_LEN], 1, 3)
        if self.root.size <= 0:
            raise RetroFSError("QNX4 根目录 size=%d，镜像不可用" % self.root.size)
        # 根目录数据必须能在镜像里读全，否则视为截断
        got = len(self.read_stream(self.root))
        if got < self.root.size:
            raise RetroFSError("QNX4 根目录数据越界：需要 %d 字节，只读到 %d 字节"
                               % (self.root.size, got))

    # ---------------- 基础设施 ----------------
    def _blk(self, blkno):
        if blkno < 0:
            return b""
        off = blkno * self.block_size
        if off >= self.image_size:
            return b""
        return self.sub.read(off, self.block_size)

    def info(self):
        return {
            "format": "qnx4",
            "super_offset": self.super_offset,
            "block_size": self.block_size,
            "blocks": self.image_size // self.block_size,
            "root_ino": self.root.ino,
            "root_size": self.root.size,
            "root_extents": self.root.extents,
            "inodes_file": (self.inodes_entry.size, self.inodes_entry.extents),
            "boot_file": (self.boot_entry.size, self.boot_entry.extents),
            "altboot_file": (self.altboot_entry.size, self.altboot_entry.extents),
        }

    def _parse_inode(self, raw, blk, slot):
        ino = Qnx4Inode()
        if len(raw) < QNX4_INODE_LEN:
            return ino
        ino.blk = blk
        ino.slot = slot
        ino.raw = raw[:QNX4_INODE_LEN]
        ino.name = _dec(_cstr(raw[Q4_FNAME:Q4_FNAME + 16]))
        ino.size = _u32(raw, Q4_SIZE, "<")
        extent = (_u32(raw, Q4_FIRST_XTNT, "<"), _u32(raw, Q4_FIRST_XTNT + 4, "<"))
        ino.xblk = _u32(raw, Q4_XBLK, "<")
        ino.ftime = _u32(raw, Q4_FTIME, "<")
        ino.mtime = _u32(raw, Q4_MTIME, "<")
        ino.atime = _u32(raw, Q4_ATIME, "<")
        ino.ctime = _u32(raw, Q4_CTIME, "<")
        ino.num_xtnts = _u16(raw, Q4_NUM_XTNTS, "<")
        ino.mode = _u16(raw, Q4_MODE, "<")
        ino.uid = _u16(raw, Q4_UID, "<")
        ino.gid = _u16(raw, Q4_GID, "<")
        ino.nlink = _u16(raw, Q4_NLINK, "<")
        ino.ftype = _u8(raw, Q4_TYPE)
        ino.status = _u8(raw, Q4_STATUS)
        ino.extents = self._build_extents(extent, ino.num_xtnts, ino.xblk)
        return ino

    def _build_extents(self, first, num_xtnts, xblk):
        """首段 + 扩展块链 -> [(起始块(1 基), 块数)]"""
        out = []
        if first[1]:
            out.append(first)
        need = num_xtnts if num_xtnts else 1
        cur = xblk
        guard = 0
        while len(out) < need and cur and guard < 4096:
            guard += 1
            raw = self._blk(cur - 1)              # xblk 也是 1 基
            if len(raw) < QNX4_BLOCK_SIZE:
                break
            if _cstr(raw[X_SIGNATURE:X_SIGNATURE + 8]) != QNX4_XBLK_SIG:
                break
            n = _u8(raw, X_NUM_XTNTS)
            n = min(n, QNX4_MAX_XTNTS)
            for i in range(n):
                b = _u32(raw, X_XTNTS + 8 * i, "<")
                c = _u32(raw, X_XTNTS + 8 * i + 4, "<")
                if c:
                    out.append((b, c))
            cur = _u32(raw, X_NEXT, "<")
        return out

    def inode_at(self, blk, slot):
        raw = self._blk(blk)
        off = slot * QNX4_DIR_ENTRY_SIZE
        return self._parse_inode(raw[off:off + QNX4_DIR_ENTRY_SIZE], blk, slot)

    def read_inode(self, ino):
        return self.inode_at(ino // QNX4_INODES_PER_BLOCK, ino % QNX4_INODES_PER_BLOCK)

    # ---------------- 数据 ----------------
    def read_stream(self, ino, size=None):
        want = ino.size if size is None else size
        if want <= 0:
            return b""
        out = bytearray()
        for (blk, cnt) in ino.extents:
            if len(out) >= want:
                break
            phys = (blk - 1) * self.block_size
            if phys < 0 or phys >= self.image_size:
                continue
            out += self.sub.read(phys, cnt * self.block_size)
        return bytes(out[:want])

    def read_file(self, ino):
        if ino.is_dir:
            return None
        return self.read_stream(ino)

    # ---------------- 目录 ----------------
    def listdir(self, ino=None):
        d = ino if ino is not None else self.root
        if not d.is_dir:
            raise RetroFSError("不是 QNX4 目录：%r（%s）" % (d.name, d.type_name))
        data = self.read_stream(d)
        out = []
        for pos in range(0, len(data) - QNX4_DIR_ENTRY_SIZE + 1, QNX4_DIR_ENTRY_SIZE):
            raw = data[pos:pos + QNX4_DIR_ENTRY_SIZE]
            if not raw[Q4_FNAME]:
                continue
            status = _u8(raw, Q4_STATUS)
            if not (status & (Q4_FILE_USED | Q4_FILE_LINK)):
                continue
            if status & Q4_FILE_LINK:
                name = _dec(_cstr(raw[0:48]))
                target_blk = _u32(raw, 48, "<")
                target_ndx = _u8(raw, 52)
                ent = Qnx4Inode()
                ent.blk = target_blk - 1
                ent.slot = target_ndx
                ent.name = name
                ent.status = status
                tgt = self.inode_at(ent.blk, ent.slot)
                tgt.name = name
                out.append(tgt)
                continue
            blk = (d.extents[0][0] - 1) + pos // self.block_size if d.extents else 0
            slot = (pos // QNX4_DIR_ENTRY_SIZE) % QNX4_INODES_PER_BLOCK
            ent = self._parse_inode(raw, blk, slot)
            out.append(ent)
        return out

    def lookup(self, ino, name):
        for it in self.listdir(ino):
            if it.name == name:
                return it
        return None

    def walk(self, ino=None, _depth=0, _max=32):
        prefix = "" if ino is None else ino.name + "/"
        for it in self.listdir(ino):
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            if it.is_dir and _depth < _max:
                for sn, si in self.walk(it, _depth + 1, _max):
                    yield prefix + sn, si

    def find(self, pattern):
        pat = pattern.lower()
        return [(p, e) for p, e in self.walk() if pat in p.lower()]

    def read_path(self, path):
        cur = None
        for part in [p for p in path.split("/") if p]:
            hit = self.lookup(cur, part)
            if hit is None:
                raise FileNotFoundError(path)
            cur = hit
        if cur is None:
            return None
        return self.read_file(cur)


def _qnx4_probe(sub):
    for off in QNX4_SUPER_OFFSETS:
        raw = sub.read(off, QNX4_INODE_LEN)
        if len(raw) < QNX4_INODE_LEN:
            continue
        if raw[Q4_FNAME:Q4_FNAME + 2] != b"/\x00":
            continue
        size = _u32(raw, Q4_SIZE, "<")
        blk = _u32(raw, Q4_FIRST_XTNT, "<")
        cnt = _u32(raw, Q4_FIRST_XTNT + 4, "<")
        if size <= 0 or blk == 0 or cnt == 0:
            continue
        if size % QNX4_DIR_ENTRY_SIZE:
            continue
        if size > 64 << 20:
            continue
        mode = _u16(raw, Q4_MODE, "<")
        if (mode & 0o170000) != 0o040000:
            continue
        return True
    return False


# ============================================================
#  C2. QNX6
# ============================================================
QNX6_MAGIC = 0x68191122
QNX6_SUPER_OFFSET = 0x2000            # QNX6_BOOTBLOCK_SIZE
QNX6_SUPER_AREA = 0x1000
QNX6_SUPER_SIZE = 0x200
QNX6_INODE_SIZE = 0x80
QNX6_INODE_SHIFT = 7
QNX6_DIR_ENTRY_SIZE = 0x20
QNX6_SHORT_NAME_MAX = 27
QNX6_LONG_NAME_MAX = 510
QNX6_NO_DIRECT_POINTERS = 16
QNX6_PTR_MAX_LEVELS = 5
QNX6_FILE_DIRECTORY = 0x01
QNX6_FILE_DELETED = 0x02
QNX6_FILE_NORMAL = 0x03
QNX6_ROOT_INO = 1


def qnx6_lfile_checksum(name):
    """QNX6 长文件名校验和（Linux `qnx6_lfile_checksum`：移位异或）"""
    crc = 0
    for ch in name:
        crc = ((crc >> 1) + ch) ^ (0x80000000 if (crc & 1) else 0)
        crc &= 0xFFFFFFFF
    return crc

# 超级块偏移（include/linux/qnx6_fs.h 逐字段核对）
S_MAGIC = 0
S_CHECKSUM = 4
S_SERIAL = 8
S_CTIME = 16
S_ATIME = 20
S_FLAGS = 24
S_VERSION1 = 28
S_VERSION2 = 30
S_VOLUMEID = 32
S_BLOCKSIZE = 48
S_NUM_INODES = 52
S_FREE_INODES = 56
S_NUM_BLOCKS = 60
S_FREE_BLOCKS = 64
S_ALLOCGROUP = 68
S_INODE = 72
S_BITMAP = 152
S_LONGFILE = 232
S_UNKNOWN = 312

# root_node（80 字节）
RN_SIZE = 0
RN_PTR = 8
RN_LEVELS = 72
RN_MODE = 73

# inode（128 字节）
Q6I_SIZE = 0
Q6I_UID = 8
Q6I_GID = 12
Q6I_FTIME = 16
Q6I_MTIME = 20
Q6I_ATIME = 24
Q6I_CTIME = 28
Q6I_MODE = 32
Q6I_EXTMODE = 34
Q6I_PTR = 36
Q6I_LEVELS = 100
Q6I_STATUS = 101


class Qnx6Node(object):
    """QNX6 的 root_node / inode 共同结构：size + 16 个指针 + 层数"""

    __slots__ = ("size", "ptrs", "levels", "mode")

    def __init__(self, size=0, ptrs=None, levels=0, mode=0):
        self.size = size
        self.ptrs = list(ptrs) if ptrs is not None else [0] * QNX6_NO_DIRECT_POINTERS
        self.levels = levels
        self.mode = mode


class Qnx6Inode(object):
    __slots__ = ("ino", "blk", "node", "uid", "gid", "ftime", "mtime", "atime",
                 "ctime", "mode", "ext_mode", "status", "name",
                 "name_checksum_ok")

    def __init__(self):
        self.ino = 0
        self.blk = 0
        self.node = Qnx6Node()
        self.uid = 0
        self.gid = 0
        self.ftime = 0
        self.mtime = 0
        self.atime = 0
        self.ctime = 0
        self.mode = 0
        self.ext_mode = 0
        self.status = 0
        self.name = ""
        self.name_checksum_ok = True

    @property
    def size(self):
        return self.node.size

    @property
    def is_dir(self):
        return (self.mode & 0o170000) == 0o040000

    @property
    def is_file(self):
        return (self.mode & 0o170000) == 0o100000

    @property
    def is_symlink(self):
        return (self.mode & 0o170000) == 0o120000

    @property
    def type_name(self):
        if self.is_dir:
            return "dir"
        if self.is_symlink:
            return "symlink"
        if self.is_file:
            return "file"
        return "special"

    def __repr__(self):
        return "<Qnx6Inode %s %r ino=%d %dB>" % (self.type_name, self.name,
                                                 self.ino, self.size)


class Qnx6FS(object):
    """QNX6 只读（大端或小端自适应；支持 0..5 级间接）"""

    def __init__(self, sub):
        self.sub = sub
        self.image_size = _size_of(sub) or 0
        if self.image_size < QNX6_SUPER_SIZE:
            raise RetroFSError("镜像太短（%d 字节），读不到 QNX6 超级块"
                               % self.image_size)

        self.super_offset = None
        raw = b""
        for off in (QNX6_SUPER_OFFSET, 0):
            cand = sub.read(off, QNX6_SUPER_SIZE)
            if len(cand) < QNX6_SUPER_SIZE:
                continue
            if _u32(cand, S_MAGIC, ">") == QNX6_MAGIC:
                self.endian = ">"
            elif _u32(cand, S_MAGIC, "<") == QNX6_MAGIC:
                self.endian = "<"
            else:
                continue
            self.super_offset = off
            raw = cand
            break
        if self.super_offset is None:
            raise RetroFSError("不是 QNX6（0x2000 与 0 偏移都没有 magic 0x%08X）"
                               % QNX6_MAGIC)

        e = self.endian
        self.raw_super = raw
        self.magic = _u32(raw, S_MAGIC, e)
        self.checksum = _u32(raw, S_CHECKSUM, e)
        self.serial = _u64(raw, S_SERIAL, e)
        self.ctime = _u32(raw, S_CTIME, e)
        self.atime = _u32(raw, S_ATIME, e)
        self.flags = _u32(raw, S_FLAGS, e)
        self.version1 = _u16(raw, S_VERSION1, e)
        self.version2 = _u16(raw, S_VERSION2, e)
        self.volumeid = _cstr(raw[S_VOLUMEID:S_VOLUMEID + 16])
        self.block_size = _u32(raw, S_BLOCKSIZE, e)
        self.num_inodes = _u32(raw, S_NUM_INODES, e)
        self.free_inodes = _u32(raw, S_FREE_INODES, e)
        self.num_blocks = _u32(raw, S_NUM_BLOCKS, e)
        self.free_blocks = _u32(raw, S_FREE_BLOCKS, e)
        self.allocgroup = _u32(raw, S_ALLOCGROUP, e)
        self.inodes_node = self._root_node(raw, S_INODE)
        self.bitmap_node = self._root_node(raw, S_BITMAP)
        self.longfile_node = self._root_node(raw, S_LONGFILE)
        self.unknown_node = self._root_node(raw, S_UNKNOWN)

        if self.block_size < 512 or self.block_size > (64 << 10) \
                or (self.block_size & (self.block_size - 1)):
            raise RetroFSError("QNX6 块大小非法：%d" % self.block_size)
        if self.inodes_node.levels > QNX6_PTR_MAX_LEVELS:
            raise RetroFSError("QNX6 Inode.levels=%d 超过 %d"
                               % (self.inodes_node.levels, QNX6_PTR_MAX_LEVELS))
        if self.longfile_node.levels > QNX6_PTR_MAX_LEVELS:
            raise RetroFSError("QNX6 Longfile.levels=%d 超过 %d"
                               % (self.longfile_node.levels, QNX6_PTR_MAX_LEVELS))

        self.ptrbits = max(1, (self.block_size // 4).bit_length() - 1)
        # Linux: s_blks_off = bootblock_offset/bs + 0x1000/bs
        self.blocks_off = (self.super_offset // self.block_size) \
            + (QNX6_SUPER_AREA // self.block_size)
        per_block = self.block_size // 4
        if (1 << self.ptrbits) != per_block:
            self.ptrbits = per_block.bit_length() - 1

        self.root = self.read_inode(QNX6_ROOT_INO)
        self.root.name = "/"

    # ---------------- 基础设施 ----------------
    def _root_node(self, raw, off):
        _need(raw, off, 80)
        e = self.endian
        ptrs = [_u32(raw, off + RN_PTR + 4 * i, e) for i in range(QNX6_NO_DIRECT_POINTERS)]
        return Qnx6Node(_u64(raw, off + RN_SIZE, e), ptrs,
                        _u8(raw, off + RN_LEVELS), _u8(raw, off + RN_MODE))

    def _blk(self, blkno):
        if blkno < 0:
            return b""
        off = blkno * self.block_size
        if off >= self.image_size:
            return b""
        return self.sub.read(off, self.block_size)

    def checksum_ok(self):
        return self.checksum == crc32_be(0, self.raw_super[S_CHECKSUM + 4:
                                                           QNX6_SUPER_SIZE])

    def info(self):
        return {
            "format": "qnx6",
            "super_offset": self.super_offset,
            "endian": "big" if self.endian == ">" else "little",
            "magic": "0x%08X" % self.magic,
            "checksum": "0x%08X" % self.checksum,
            "checksum_ok": self.checksum_ok(),
            "serial": self.serial,
            "version": (self.version1, self.version2),
            "volumeid": _dec(self.volumeid),
            "block_size": self.block_size,
            "blocks_off": self.blocks_off,
            "ptrbits": self.ptrbits,
            "num_inodes": self.num_inodes,
            "free_inodes": self.free_inodes,
            "num_blocks": self.num_blocks,
            "free_blocks": self.free_blocks,
            "allocgroup": self.allocgroup,
            "created": self.ctime,
            "accessed": self.atime,
            "inode_node": (self.inodes_node.size, self.inodes_node.levels),
            "longfile_node": (self.longfile_node.size, self.longfile_node.levels),
            "root_ino": self.root.ino,
        }

    # ---------------- 多级指针 ----------------
    def map_block(self, node, blockno):
        """逻辑块 -> 物理块（对应 qnx6_block_map，devblock = ptr + s_blks_off）"""
        if blockno < 0:
            return None
        depth = node.levels
        if depth > QNX6_PTR_MAX_LEVELS:
            return None
        ptrbits = self.ptrbits
        mask = (1 << ptrbits) - 1
        bitdelta = ptrbits * depth
        level = blockno >> bitdelta
        if level > QNX6_NO_DIRECT_POINTERS - 1:
            return None
        blk = node.ptrs[level]
        if blk == 0xFFFFFFFF:
            return None
        blk += self.blocks_off
        for i in range(depth):
            raw = self._blk(blk)
            if len(raw) < self.block_size:
                return None
            bitdelta -= ptrbits
            level = (blockno >> bitdelta) & mask
            ptr = _u32(raw, level * 4, self.endian)
            if ptr == 0xFFFFFFFF:
                return None
            blk = ptr + self.blocks_off
        return blk

    def read_node(self, node, size=None, max_bytes=None):
        want = node.size if size is None else size
        if want <= 0:
            return b""
        if max_bytes is not None and want > max_bytes:
            want = max_bytes
        out = bytearray()
        nblocks = (want + self.block_size - 1) // self.block_size
        for i in range(nblocks):
            p = self.map_block(node, i)
            if p is None:
                break
            raw = self._blk(p)
            if not raw:
                break
            out += raw
        return bytes(out[:want])

    # ---------------- inode ----------------
    def read_inode(self, ino):
        """inode 号 -> Inode 流里的 (ino-1)*128 偏移"""
        if ino <= 0:
            raise RetroFSError("QNX6 inode 号非法：%d" % ino)
        off = (ino - 1) << QNX6_INODE_SHIFT
        if off + QNX6_INODE_SIZE > self.inodes_node.size:
            raise RetroFSError("QNX6 inode %d 超出 Inode 流（%d 字节）"
                               % (ino, self.inodes_node.size))
        first = off // self.block_size
        within = off % self.block_size
        raw = b""
        for i in range(first, first + 2):
            p = self.map_block(self.inodes_node, i)
            if p is None:
                break
            raw += self._blk(p)
        if len(raw) < within + QNX6_INODE_SIZE:
            raise RetroFSError("QNX6 inode %d 读取越界" % ino)
        raw = raw[within:within + QNX6_INODE_SIZE]

        e = self.endian
        inode = Qnx6Inode()
        inode.ino = ino
        inode.uid = _u32(raw, Q6I_UID, e)
        inode.gid = _u32(raw, Q6I_GID, e)
        inode.ftime = _u32(raw, Q6I_FTIME, e)
        inode.mtime = _u32(raw, Q6I_MTIME, e)
        inode.atime = _u32(raw, Q6I_ATIME, e)
        inode.ctime = _u32(raw, Q6I_CTIME, e)
        inode.mode = _u16(raw, Q6I_MODE, e)
        inode.ext_mode = _u16(raw, Q6I_EXTMODE, e)
        inode.status = _u8(raw, Q6I_STATUS)
        inode.node = Qnx6Node(
            _u64(raw, Q6I_SIZE, e),
            [_u32(raw, Q6I_PTR + 4 * i, e) for i in range(QNX6_NO_DIRECT_POINTERS)],
            _u8(raw, Q6I_LEVELS), inode.mode)
        return inode

    def read_file(self, inode):
        if inode.is_dir:
            return None
        return self.read_node(inode.node)

    def read_stream(self, inode):
        """任意类型的数据流（目录/长文件名也用）"""
        return self.read_node(inode.node)

    # ---------------- 目录 ----------------
    def _long_name(self, de_long_inode):
        """长文件名：Longfile 流里 block de_long_inode 处，u16 长度 + 名字"""
        if not self.longfile_node.size:
            return None
        off = de_long_inode * self.block_size
        if off >= self.longfile_node.size:
            return None
        blkno = off // self.block_size
        p = self.map_block(self.longfile_node, blkno)
        if p is None:
            return None
        raw = self._blk(p)
        if len(raw) < 2:
            return None
        n = _u16(raw, 0, self.endian)
        if n > QNX6_LONG_NAME_MAX or 2 + n > len(raw):
            return None
        return raw[2:2 + n]

    def listdir(self, inode=None):
        d = inode if inode is not None else self.root
        if not d.is_dir:
            raise RetroFSError("不是 QNX6 目录：%r（%s）" % (d.name, d.type_name))
        data = self.read_node(d.node)
        e = self.endian
        out = []
        for pos in range(0, len(data) - QNX6_DIR_ENTRY_SIZE + 1, QNX6_DIR_ENTRY_SIZE):
            eno = _u32(data, pos, e)
            nlen = _u8(data, pos + 4)
            if eno == 0 or nlen == 0:
                continue
            if nlen == 0xFF:
                long_ino = _u32(data, pos + 8, e)
                chk = _u32(data, pos + 12, e)
                name_raw = self._long_name(long_ino)
                if name_raw is None:
                    name = ""
                    ok = False
                else:
                    name = _dec(name_raw)
                    ok = (qnx6_lfile_checksum(name_raw) == chk)
                child = None
            else:
                if nlen > QNX6_SHORT_NAME_MAX:
                    continue
                name = _dec(_cstr(data[pos + 5:pos + 5 + nlen]))
                ok = True
                child = None
            if child is None:
                try:
                    child = self.read_inode(eno)
                except RetroFSError:
                    child = Qnx6Inode()
                    child.ino = eno
            child.name = name
            child.name_checksum_ok = ok
            out.append(child)
        return out

    def lookup(self, inode, name):
        for it in self.listdir(inode):
            if it.name == name:
                return it
        return None

    def walk(self, inode=None, _depth=0, _max=32):
        prefix = "" if inode is None else inode.name + "/"
        for it in self.listdir(inode):
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            if it.is_dir and _depth < _max:
                for sn, si in self.walk(it, _depth + 1, _max):
                    yield prefix + sn, si

    def find(self, pattern):
        pat = pattern.lower()
        return [(p, e) for p, e in self.walk() if pat in p.lower()]

    def read_path(self, path):
        cur = None
        for part in [p for p in path.split("/") if p]:
            hit = self.lookup(cur, part)
            if hit is None:
                raise FileNotFoundError(path)
            cur = hit
        if cur is None:
            return None
        return self.read_file(cur)


def _qnx6_probe(sub):
    for off in (QNX6_SUPER_OFFSET, 0):
        raw = sub.read(off, QNX6_SUPER_SIZE)
        if len(raw) < QNX6_SUPER_SIZE:
            continue
        for e in (">", "<"):
            if _u32(raw, S_MAGIC, e) != QNX6_MAGIC:
                continue
            bs = _u32(raw, S_BLOCKSIZE, e)
            if bs < 512 or bs > (64 << 10) or (bs & (bs - 1)):
                continue
            if _u8(raw, S_INODE + RN_LEVELS) > QNX6_PTR_MAX_LEVELS:
                continue
            return True
    return False


# ============================================================
# 统一入口
# ============================================================
PROBES = (
    ("amiga", _amiga_probe),
    ("befs", _befs_probe),
    ("qnx4", _qnx4_probe),
    ("qnx6", _qnx6_probe),
)

FORMATS = ("amiga-ofs", "amiga-ffs", "befs", "qnx4", "qnx6")


def detect_all(sub):
    """逐个格式试探测，返回命中的格式名列表与探针结果"""
    hits = []
    flags = {"amiga": False, "befs": False, "qnx4": False, "qnx6": False}
    for name, fn in PROBES:
        try:
            ok = bool(fn(sub))
        except (RetroFSError, struct.error, ValueError, IndexError):
            ok = False
        flags[name] = ok
        if ok:
            hits.append(name)

    fmt = "unknown"
    if flags["befs"]:
        fmt = "befs"
    elif flags["qnx6"]:
        fmt = "qnx6"
    elif flags["amiga"]:
        head = sub.read(3, 1)
        fmt = "amiga-ffs" if (head and (head[0] & 1)) else "amiga-ofs"
    elif flags["qnx4"]:
        fmt = "qnx4"

    return {
        "format": fmt,
        "hits": hits,
        "amiga": flags["amiga"],
        "befs": flags["befs"],
        "qnx4": flags["qnx4"],
        "qnx6": flags["qnx6"],
    }


def probe(sub):
    """识别格式：amiga-ofs / amiga-ffs / befs / qnx4 / qnx6 / unknown"""
    try:
        d = detect_all(sub)
    except Exception:
        return "unknown"
    if len(d["hits"]) == 1:
        return d["format"]
    if not d["hits"]:
        return "unknown"
    # 多命中时按置信度取
    return d["format"]


def open_fs(sub, fmt=None, **kw):
    """按格式打开。fmt 省略时用 probe()。"""
    name = fmt or probe(sub)
    if name == "amiga-ofs" or name == "amiga-ffs":
        fs = AmigaFS(sub, **kw)
        if name != "amiga-" + fs.variant:
            raise RetroFSError("声明为 %s，实际引导块是 DOS\\%d（%s）"
                               % (name, fs.dos_version, fs.variant))
        return fs
    if name == "befs":
        return BeFS(sub, **kw)
    if name == "qnx4":
        return Qnx4FS(sub, **kw)
    if name == "qnx6":
        return Qnx6FS(sub, **kw)
    raise RetroFSError("未知格式：%r（候选 %s）" % (name, ", ".join(FORMATS)))


# ============================================================
# 自检：五种合成镜像
# ============================================================
if __name__ == "__main__":
    import datetime

    class Buf(object):
        """最小 sub：只有 read(offset, size) 与 size"""

        def __init__(self, data):
            self.data = data
            self.size = len(data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    def u32(img, off, val, e=">"):
        struct.pack_into(e + "I", img, off, val & 0xFFFFFFFF)

    def u64(img, off, val, e=">"):
        struct.pack_into(e + "Q", img, off, val & 0xFFFFFFFFFFFFFFFF)

    def put(img, off, raw):
        img[off:off + len(raw)] = raw

    # ---------------- Amiga ----------------
    def amiga_build(variant, content=b"Hello Amiga!\n"):
        BS = 512
        img = bytearray(BS * 5)
        img[0:4] = b"DOS" + bytes([1 if variant == "ffs" else 0])

        def name(blk, nm):
            b = nm.encode()
            img[blk * BS + A_NAMELEN] = len(b)
            put(img, blk * BS + A_NAME, b)

        def hdr(blk, header_key, high_seq, hash_size, sec_type):
            u32(img, blk * BS + A_TYPE, A_T_HEADER)
            u32(img, blk * BS + A_HEADERKEY, header_key)
            u32(img, blk * BS + A_HIGHSEQ, high_seq)
            u32(img, blk * BS + A_HASHSIZE, hash_size)
            u32(img, blk * BS + A_FIRSTDATA, 0)
            u32(img, blk * BS + A_SECTYPE, sec_type)

        def times(blk, days, mins, ticks):
            u32(img, blk * BS + A_DAYS, days)
            u32(img, blk * BS + A_MINS, mins)
            u32(img, blk * BS + A_TICKS, ticks)

        def cks(blk):
            off = blk * BS
            u32(img, off + A_CHECKSUM, 0)
            total = 0
            for i in range(0, BS, 4):
                total = (total + struct.unpack_from(">I", img, off + i)[0]) & 0xFFFFFFFF
            u32(img, off + A_CHECKSUM, (-total) & 0xFFFFFFFF)

        # 块 1：根块
        hdr(1, 0, 0, A_HT_SIZE, A_ST_ROOT)
        u32(img, 1 * BS + A_BMFLAG, 0xFFFFFFFF)
        u32(img, 1 * BS + A_HASHTABLE + 4 * 0, 2)
        times(1, 0, 0, 0)
        name(1, "ESK")
        u32(img, 1 * BS + A_PARENT, 0)

        # 块 2：子目录
        hdr(2, 2, 0, A_HT_SIZE, A_ST_DIR)
        u32(img, 2 * BS + A_HASHTABLE + 4 * 0, 3)
        times(2, 1, 60, 50)                 # 1978-01-02 01:00:01
        name(2, "sub")
        u32(img, 2 * BS + A_PARENT, 1)

        # 块 3：文件头
        hdr(3, 3, 1, 0, A_ST_FILE)
        u32(img, 3 * BS + A_HASHTABLE + 4 * 0, 4)
        u32(img, 3 * BS + A_BYTESIZE, len(content))
        u32(img, 3 * BS + A_ACCESS, 0x0F)
        times(3, 2, 0, 0)
        name(3, "hello.txt")
        u32(img, 3 * BS + A_PARENT, 2)

        # 块 4：数据块
        if variant == "ofs":
            u32(img, 4 * BS + A_TYPE, A_T_DATA)
            u32(img, 4 * BS + A_HEADERKEY, 3)
            u32(img, 4 * BS + 0x08, 1)                    # seqNum
            u32(img, 4 * BS + 0x0C, len(content))         # dataSize
            u32(img, 4 * BS + 0x10, 0)                    # nextData
            put(img, 4 * BS + 24, content)
            cks(4)
        else:
            put(img, 4 * BS, content)

        for b in (1, 2, 3):
            cks(b)
        # 引导块校验和（DOS 引导块也是 u32 和为 0）
        u32(img, A_CHECKSUM, 0)
        total = sum(struct.unpack_from(">I", img, i)[0] for i in range(0, BS, 4))
        u32(img, A_CHECKSUM, (-total) & 0xFFFFFFFF)
        return bytes(img), content

    # ---------------- BeFS ----------------
    def befs_build(content=b"BeOS payload 0123456789\n", secs=0x5F5E1000):
        BS = 1024
        img = bytearray(BS * 5)
        so = BEFS_SUPER_OFFSET
        put(img, so, b"ESKBFS")
        u32(img, so + BS_MAGIC1, BEFS_MAGIC1)
        u32(img, so + BS_BYTEORDER, BEFS_BYTEORDER_NATIVE)
        u32(img, so + BS_BLOCK_SIZE, BS)
        u32(img, so + BS_BLOCK_SHIFT, 10)
        u64(img, so + BS_NUM_BLOCKS, 5)
        u64(img, so + BS_USED_BLOCKS, 4)
        u32(img, so + BS_INODE_SIZE, 512)
        u32(img, so + BS_MAGIC2, BEFS_MAGIC2)
        u32(img, so + BS_BLOCKS_PER_AG, 1 << 10)
        u32(img, so + BS_AG_SHIFT, 10)
        u32(img, so + BS_NUM_AGS, 1)
        u32(img, so + BS_FLAGS, BEFS_CLEAN)
        u32(img, so + BS_MAGIC3, BEFS_MAGIC3)
        struct.pack_into(">IHH", img, so + BS_ROOT_DIR, 0, 1, 1)     # 根 inode @ 块 1
        struct.pack_into(">IHH", img, so + BS_INDICES, 0, 0, 0)

        def put_inode(blk, addr, mode, dtype, run, size, mtime, name):
            o = blk * BS
            u32(img, o + BI_MAGIC1, BEFS_INODE_MAGIC)
            struct.pack_into(">IHH", img, o + BI_INODE_NUM, *addr)
            u32(img, o + BI_UID, 0)
            u32(img, o + BI_GID, 0)
            u32(img, o + BI_MODE, mode)
            u32(img, o + BI_FLAGS, 0x00000001)                # BEFS_INODE_IN_USE
            u64(img, o + BI_CTIME, mtime << 16)
            u64(img, o + BI_MTIME, mtime << 16)
            struct.pack_into(">IHH", img, o + BI_PARENT, 0, 0, 0)
            struct.pack_into(">IHH", img, o + BI_ATTRIBUTES, 0, 0, 0)
            u32(img, o + BI_TYPE, dtype)
            u32(img, o + BI_INODE_SIZE, 512)
            u32(img, o + BI_ETC, 0)
            struct.pack_into(">IHH", img, o + BI_DATA, *run)  # direct[0]
            u64(img, o + BI_DATA + DS_MAX_DIRECT, BS)
            u64(img, o + BI_DATA + DS_SIZE, size)

        fname = b"hello.txt"
        dent = struct.pack(">IIII", 3, 16, 16 + len(fname), 0) + fname
        put(img, 2 * BS, dent)
        put(img, 4 * BS, content)

        put_inode(1, (0, 1, 1), 0o040000 | 0o755, 2, (0, 2, 1), len(dent), secs, "/")
        put_inode(3, (0, 3, 1), 0o100000 | 0o644, 1, (0, 4, 1), len(content), secs,
                  "hello.txt")
        return bytes(img), content, dent

    # ---------------- QNX4 ----------------
    def qnx4_build(content=b"QNX4 payload...\n"):
        BS = 512
        img = bytearray(BS * 4)

        def put_inode(off, fname, size, xtnt_blk, xtnt_n, mode, ftype, status=1):
            put(img, off, fname)
            u32(img, off + Q4_SIZE, size, "<")
            u32(img, off + Q4_FIRST_XTNT, xtnt_blk, "<")
            u32(img, off + Q4_FIRST_XTNT + 4, xtnt_n, "<")
            u32(img, off + Q4_XBLK, 0, "<")
            u32(img, off + Q4_FTIME, 0x40000000, "<")
            u32(img, off + Q4_MTIME, 0x40000001, "<")
            u32(img, off + Q4_ATIME, 0x40000002, "<")
            u32(img, off + Q4_CTIME, 0x40000003, "<")
            struct.pack_into("<H", img, off + Q4_NUM_XTNTS, 1)
            struct.pack_into("<H", img, off + Q4_MODE, mode)
            struct.pack_into("<H", img, off + Q4_UID, 0)
            struct.pack_into("<H", img, off + Q4_GID, 0)
            struct.pack_into("<H", img, off + Q4_NLINK, 1)
            img[off + Q4_TYPE] = ftype
            img[off + Q4_STATUS] = status

        # 块 1：超级块（RootDir / Inodes / Boot / AltBoot）
        put_inode(BS + 0, b"/\x00", 2 * 64, 3, 1, 0o040755, 1)
        put_inode(BS + 64, b".inodes\x00", 64, 4, 1, 0o100644, 2)
        put_inode(BS + 128, b".boot\x00", 0, 0, 0, 0o100644, 2)
        put_inode(BS + 192, b".altboot\x00", 0, 0, 0, 0o100644, 2)

        # 块 2：根目录数据（"." + "hello.txt"），数据块 2 -> xtnt_blk 3
        put_inode(2 * BS + 0, b".\x00", 2 * 64, 3, 1, 0o040755, 1)
        put_inode(2 * BS + 64, b"hello.txt\x00", len(content), 4, 1, 0o100644, 2)
        put(img, 3 * BS, content)
        return bytes(img), content

    # ---------------- QNX6 ----------------
    def qnx6_build(content=b"QNX6 payload 0123456789\n"):
        BS = 4096
        img = bytearray(BS * 6)
        so = QNX6_SUPER_OFFSET

        def rnode(off, size, ptr0, levels):
            u64(img, so + off + RN_SIZE, size)
            for i in range(QNX6_NO_DIRECT_POINTERS):
                u32(img, so + off + RN_PTR + 4 * i,
                    0xFFFFFFFF if i else ptr0)
            img[so + off + RN_LEVELS] = levels

        u32(img, so + S_MAGIC, QNX6_MAGIC)
        u64(img, so + S_SERIAL, 0x0000000100000002)
        u32(img, so + S_CTIME, 0x5F5E1000)
        u32(img, so + S_ATIME, 0x5F5E1001)
        u32(img, so + S_FLAGS, 1)
        struct.pack_into(">H", img, so + S_VERSION1, 1)
        struct.pack_into(">H", img, so + S_VERSION2, 0)
        put(img, so + S_VOLUMEID, b"ESKQNX6")
        u32(img, so + S_BLOCKSIZE, BS)
        u32(img, so + S_NUM_INODES, 2)
        u32(img, so + S_FREE_INODES, BS // QNX6_INODE_SIZE - 2)
        u32(img, so + S_NUM_BLOCKS, 6)
        u32(img, so + S_FREE_BLOCKS, 1)
        u32(img, so + S_ALLOCGROUP, 1 << 10)
        rnode(S_INODE, BS, 0, 0)              # inode 表在 dev 块 0 (+3)
        rnode(S_BITMAP, 0, 0xFFFFFFFF, 0)
        rnode(S_LONGFILE, 0, 0xFFFFFFFF, 0)
        rnode(S_UNKNOWN, 0, 0xFFFFFFFF, 0)
        u32(img, so + S_CHECKSUM, crc32_be(0, bytes(img[so + 8:so + QNX6_SUPER_SIZE])))

        def put_inode(off, size, mode, ptr0, levels, status):
            o = off
            u64(img, o + Q6I_SIZE, size)
            u32(img, o + Q6I_UID, 0)
            u32(img, o + Q6I_GID, 0)
            u32(img, o + Q6I_FTIME, 0x5F5E1000)
            u32(img, o + Q6I_MTIME, 0x5F5E1001)
            u32(img, o + Q6I_ATIME, 0x5F5E1002)
            u32(img, o + Q6I_CTIME, 0x5F5E1003)
            struct.pack_into(">H", img, o + Q6I_MODE, mode)
            struct.pack_into(">H", img, o + Q6I_EXTMODE, 0)
            for i in range(QNX6_NO_DIRECT_POINTERS):
                u32(img, o + Q6I_PTR + 4 * i, 0xFFFFFFFF if i else ptr0)
            img[o + Q6I_LEVELS] = levels
            img[o + Q6I_STATUS] = status

        # inode 表：dev 块 3（ptr 0 + blocks_off 3）
        base = 3 * BS
        ents = [(QNX6_ROOT_INO, b"."), (1, b".."), (2, b"hello.txt")]
        dirdata = bytearray()
        for ino, nm in ents:
            dirdata += struct.pack(">IB", ino, len(nm)) + nm.ljust(27, b"\x00")
        put_inode(base + 0, len(dirdata), 0o040755, 1, 0, QNX6_FILE_DIRECTORY)
        put_inode(base + QNX6_INODE_SIZE, len(content), 0o100644, 2, 0,
                  QNX6_FILE_NORMAL)
        put(img, 4 * BS, bytes(dirdata[:BS]))
        put(img, 5 * BS, content)
        return bytes(img), content, bytes(dirdata)

    # ================= 开跑 =================
    print("crc32_be 自检: %08X" % crc32_be(0xFFFFFFFF, b"123456789"))
    assert crc32_be(0xFFFFFFFF, b"123456789") == 0x0376E6E7, "crc32_be 实现不对"

    # ---- Amiga 时间 ----
    assert AMIGA_EPOCH_DELTA == 252460800, AMIGA_EPOCH_DELTA
    t = amiga_to_unix(0, 0, 0)
    print("Amiga 时间 0/0/0 -> %d -> %s" % (t, datetime.datetime.fromtimestamp(
        t, datetime.timezone.utc).isoformat()))
    assert t == 252460800.0
    assert datetime.datetime.fromtimestamp(t, datetime.timezone.utc).date() \
        == datetime.date(1978, 1, 1)
    assert amiga_to_unix(1, 0, 0) - amiga_to_unix(0, 0, 0) == 86400
    assert amiga_to_unix(0, 1, 0) - amiga_to_unix(0, 0, 0) == 60
    # 1 tick = 1/50 s；浮点相减有 ~1e-8 误差，按容差比较
    assert abs((amiga_to_unix(0, 0, 1) - amiga_to_unix(0, 0, 0)) - 0.02) < 1e-6
    assert abs(amiga_to_unix(0, 0, 50) - amiga_to_unix(0, 0, 0) - 1.0) < 1e-6

    images = {}

    # ---- Amiga OFS / FFS ----
    for variant in ("ofs", "ffs"):
        img, content = amiga_build(variant)
        images["amiga-" + variant] = img
        fs = open_fs(Buf(img))
        assert isinstance(fs, AmigaFS), "open_fs 没给出 AmigaFS"
        info = fs.info()
        print("Amiga %s: bs=%d label=%r root=blk%d blocks=%d 版本=%d"
              % (variant.upper(), info["block_size"], info["label"],
                 info["root_block"], info["block_count"], info["dos_version"]))
        assert fs.variant == variant
        assert fs.dos_version == (1 if variant == "ffs" else 0)
        assert fs.block_size == 512
        assert fs.label == "ESK"
        assert fs.root.sec_type == A_ST_ROOT == 1, fs.root.sec_type
        assert fs.root.is_root, "根块 secType 应为 1"
        assert fs.checksum_ok(1) and fs.checksum_ok(2) and fs.checksum_ok(3)
        assert fs.checksum_ok(0), "引导块校验和"

        ents = fs.listdir()
        print("  根目录 %d 项: %s" % (len(ents), [e.name for e in ents]))
        assert len(ents) == 1 and ents[0].name == "sub"
        sub = ents[0]
        assert sub.is_dir and sub.sec_type == A_ST_DIR
        assert abs(sub.mtime - (252460800 + 86400 + 3600 + 1)) < 1e-9

        kids = fs.listdir(sub)
        print("  sub/ %d 项: %s" % (len(kids), [k.name for k in kids]))
        assert len(kids) == 1 and kids[0].name == "hello.txt"
        f = kids[0]
        assert f.is_file and f.sec_type == A_ST_FILE
        assert f.byte_size == len(content)
        data = fs.read_file(f)
        print("  hello.txt -> %r" % data)
        assert data == content, "OFS/FFS 读出的内容不一致：%r" % data
        assert fs.read_path("/sub/hello.txt") == content
        assert [p for p, _ in fs.walk()] == ["sub", "sub/hello.txt"]
        assert fs.lookup(sub, "HELLO.TXT") is not None

    assert probe(Buf(images["amiga-ofs"])) == "amiga-ofs"
    assert probe(Buf(images["amiga-ffs"])) == "amiga-ffs"

    # ---- BeFS ----
    img, content, dent = befs_build()
    images["befs"] = img
    fs = open_fs(Buf(img))
    assert isinstance(fs, BeFS)
    info = fs.info()
    print("BeFS: label=%r endian=%s bs=%d shift=%d blocks=%d/%d inode=%dB"
          % (info["label"], info["endian"], info["block_size"],
             info["block_shift"], info["used_blocks"], info["num_blocks"],
             info["inode_size"]))
    assert _u32(img, 512 + BS_MAGIC1) == 0x42465331, "magic1 @0x200"
    assert info["magic1"] == "0x42465331"
    assert info["magic2"] == "0xDD121031" and info["magic3"] == "0x15B6830E"
    assert fs.block_size == 1024 and info["block_shift"] == 10
    assert fs.ag_consistent, "ag_shift 与 blocks_per_ag 应一致"
    assert info["root_dir"] == (0, 1, 1)

    ents = fs.listdir()
    print("  根目录 %d 项: %s" % (len(ents), [e.name for e in ents]))
    assert len(ents) == 1 and ents[0].name == "hello.txt"
    assert ents[0].is_file and ents[0].block == 3
    assert fs.read_file(ents[0]) == content
    assert fs.read_file(fs.root) is None
    assert fs.read_path("/hello.txt") == content
    assert ents[0].mtime == 0x5F5E1000, ents[0].mtime
    assert fs.root.is_dir and fs.root.mode & 0o170000 == 0o040000

    # ---- QNX4 ----
    img, content = qnx4_build()
    images["qnx4"] = img
    fs = open_fs(Buf(img))
    assert isinstance(fs, Qnx4FS)
    info = fs.info()
    print("QNX4: blocksize=%d blocks=%d root_ino=%d root_size=%d root_xtents=%s"
          % (info["block_size"], info["blocks"], info["root_ino"],
             info["root_size"], info["root_extents"]))
    assert info["super_offset"] == 512
    assert fs.root.is_dir and fs.root.name == "/"
    assert fs.root.extents == [(3, 1)]

    ents = fs.listdir()
    print("  根目录 %d 项: %s" % (len(ents), [e.name for e in ents]))
    assert [e.name for e in ents] == [".", "hello.txt"], [e.name for e in ents]
    hf = ents[1]
    assert hf.is_file and hf.size == len(content)
    assert hf.uid == 0 and hf.gid == 0 and hf.nlink == 1
    assert hf.ino == 2 * QNX4_INODES_PER_BLOCK + 1, hf.ino
    assert fs.read_file(hf) == content
    assert fs.read_path("/hello.txt") == content
    assert fs.read_inode(hf.ino).name == "hello.txt"

    # ---- QNX6 ----
    img, content, dirdata = qnx6_build()
    images["qnx6"] = img
    fs = open_fs(Buf(img))
    assert isinstance(fs, Qnx6FS)
    info = fs.info()
    print("QNX6: magic=%s bs=%d ver=%s blocks_off=%d ptrbits=%d serial=%#x"
          % (info["magic"], info["block_size"], info["version"],
             info["blocks_off"], info["ptrbits"], info["serial"]))
    assert _u32(img, 0x2000) == 0x68191122, "magic @0x2000"
    assert info["super_offset"] == 0x2000
    assert info["block_size"] == 4096
    assert info["version"] == (1, 0)
    assert info["checksum_ok"], "QNX6 超级块 crc32_be 校验失败"
    assert info["blocks_off"] == 3 and info["ptrbits"] == 10
    assert fs.root.ino == 1 and fs.root.is_dir

    ents = fs.listdir()
    print("  根目录 %d 项: %s" % (len(ents), [e.name for e in ents]))
    assert [e.name for e in ents] == [".", "..", "hello.txt"], [e.name for e in ents]
    hf = ents[2]
    assert hf.is_file and hf.size == len(content)
    assert fs.read_file(hf) == content
    assert fs.read_path("/hello.txt") == content
    assert fs.map_block(fs.root.node, 0) == 4, fs.map_block(fs.root.node, 0)

    # ================= 扩展路径：多块 / 间接 / 扩展块 / 长名 =================
    print("-- 扩展路径 --")

    def amiga_cks(img, blk, BS):
        off = blk * BS
        u32(img, off + A_CHECKSUM, 0)
        total = amiga_checksum(bytes(img[off:off + BS]))
        u32(img, off + A_CHECKSUM, (-total) & 0xFFFFFFFF)

    def amiga_build_ext(variant, content):
        """3 个数据块 + 1 个 T_LIST 扩展块，验证多块拼接与扩展链"""
        BS = 512
        img = bytearray(BS * 8)
        img[0:4] = b"DOS" + bytes([1 if variant == "ffs" else 0])

        def setname(blk, nm):
            b = nm.encode()
            img[blk * BS + A_NAMELEN] = len(b)
            put(img, blk * BS + A_NAME, b)

        def head(blk, key, hs, st):
            u32(img, blk * BS + A_TYPE, A_T_HEADER)
            u32(img, blk * BS + A_HEADERKEY, key)
            u32(img, blk * BS + A_HASHSIZE, hs)
            u32(img, blk * BS + A_SECTYPE, st)

        head(1, 0, A_HT_SIZE, A_ST_ROOT)
        u32(img, 1 * BS + A_BMFLAG, 0xFFFFFFFF)
        u32(img, 1 * BS + A_HASHTABLE, 3)
        setname(1, "ESKEXT")

        # 文件头直接挂在根下
        head(3, 3, 0, A_ST_FILE)
        u32(img, 3 * BS + A_HIGHSEQ, 1)
        u32(img, 3 * BS + A_HASHTABLE, 5)          # dataBlocks[0] = 5
        u32(img, 3 * BS + A_EXTENSION, 4)          # -> 扩展块 4
        u32(img, 3 * BS + A_BYTESIZE, len(content))
        setname(3, "big.bin")

        # 扩展块（T_LIST）
        u32(img, 4 * BS + A_TYPE, A_T_LIST)
        u32(img, 4 * BS + A_HEADERKEY, 4)
        u32(img, 4 * BS + A_HASHTABLE, 6)
        u32(img, 4 * BS + A_HASHTABLE + 4, 7)

        per = BS - 24 if variant == "ofs" else BS
        for i, blk in enumerate((5, 6, 7)):
            chunk = content[i * per:(i + 1) * per]
            if variant == "ofs":
                u32(img, blk * BS + A_TYPE, A_T_DATA)
                u32(img, blk * BS + A_HEADERKEY, 3)
                u32(img, blk * BS + 0x08, i + 1)
                u32(img, blk * BS + 0x0C, len(chunk))
                put(img, blk * BS + 24, chunk)
            else:
                put(img, blk * BS, chunk)

        for blk in (1, 3, 4):
            amiga_cks(img, blk, BS)
        if variant == "ofs":
            for blk in (5, 6, 7):
                amiga_cks(img, blk, BS)
        u32(img, A_CHECKSUM, 0)
        total = sum(struct.unpack_from(">I", img, i)[0] for i in range(0, BS, 4))
        u32(img, A_CHECKSUM, (-total) & 0xFFFFFFFF)
        return bytes(img)

    big = bytes((i * 7 + 3) & 0xFF for i in range(1200))
    for variant in ("ofs", "ffs"):
        fs = AmigaFS(Buf(amiga_build_ext(variant, big)))
        f = fs.listdir()[0]
        print("  Amiga %s 多块: %r %dB(头部 %d 块)"
              % (variant.upper(), f.name, f.byte_size, f.high_seq))
        assert f.is_file and f.byte_size == len(big)
        assert fs.read_file(f) == big, "%s 多块拼接不对" % variant
        assert f.extension == 4
        assert f.data_blocks == [5]
        for blk in (1, 3, 4):
            assert fs.checksum_ok(blk)

    # ---- BeFS：indirect 数据流 ----
    def befs_build_indirect(content):
        BS = 1024
        img = bytearray(BS * 8)
        so = BEFS_SUPER_OFFSET
        put(img, so, b"ESKIND")
        u32(img, so + BS_MAGIC1, BEFS_MAGIC1)
        u32(img, so + BS_BYTEORDER, BEFS_BYTEORDER_NATIVE)
        u32(img, so + BS_BLOCK_SIZE, BS)
        u32(img, so + BS_BLOCK_SHIFT, 10)
        u64(img, so + BS_NUM_BLOCKS, 8)
        u64(img, so + BS_USED_BLOCKS, 7)
        u32(img, so + BS_INODE_SIZE, 512)
        u32(img, so + BS_MAGIC2, BEFS_MAGIC2)
        u32(img, so + BS_BLOCKS_PER_AG, 1 << 10)
        u32(img, so + BS_AG_SHIFT, 10)
        u32(img, so + BS_NUM_AGS, 1)
        u32(img, so + BS_FLAGS, BEFS_CLEAN)
        u32(img, so + BS_MAGIC3, BEFS_MAGIC3)
        struct.pack_into(">IHH", img, so + BS_ROOT_DIR, 0, 1, 1)

        def inode(blk, addr, mode, dtype, size, direct, indirect, max_direct,
                  max_indirect):
            o = blk * BS
            u32(img, o + BI_MAGIC1, BEFS_INODE_MAGIC)
            struct.pack_into(">IHH", img, o + BI_INODE_NUM, *addr)
            u32(img, o + BI_MODE, mode)
            u32(img, o + BI_FLAGS, 1)
            u64(img, o + BI_MTIME, 0x5F5E1000 << 16)
            u32(img, o + BI_TYPE, dtype)
            u32(img, o + BI_INODE_SIZE, 512)
            struct.pack_into(">IHH", img, o + BI_DATA, *direct)
            u64(img, o + BI_DATA + DS_MAX_DIRECT, max_direct)
            struct.pack_into(">IHH", img, o + BI_DATA + DS_INDIRECT, *indirect)
            u64(img, o + BI_DATA + DS_MAX_INDIRECT, max_indirect)
            u64(img, o + BI_DATA + DS_SIZE, size)

        fname = b"ind.bin"
        dent = struct.pack(">IIII", 3, 16, 16 + len(fname), 0) + fname
        put(img, 2 * BS, dent)
        put(img, 4 * BS, content[:BS])                       # direct 第 0 块
        struct.pack_into(">IHH", img, 5 * BS, 0, 6, 2)        # 间接表：块 6、7
        put(img, 6 * BS, content[BS:2 * BS])
        put(img, 7 * BS, content[2 * BS:3 * BS])

        inode(1, (0, 1, 1), 0o040000 | 0o755, 2, len(dent), (0, 2, 1), (0, 0, 0),
              BS, 0)
        inode(3, (0, 3, 1), 0o100000 | 0o644, 1, 3 * BS,
              (0, 4, 1), (0, 5, 1), BS, 3 * BS)
        return bytes(img)

    bign = bytes((i * 11 + 5) & 0xFF for i in range(3 * 1024))
    fs = BeFS(Buf(befs_build_indirect(bign)))
    f = fs.listdir()[0]
    print("  BeFS indirect: %r size=%d direct_max=%d indirect_max=%d"
          % (f.name, f.size, f.ds["max_direct"], f.ds["max_indirect"]))
    assert f.is_file and f.size == 3 * 1024
    assert fs.read_file(f) == bign, "BeFS indirect 读出的内容不对"
    assert fs._ds_block(f.ds, 0) == 4
    assert fs._ds_block(f.ds, 1) == 6 and fs._ds_block(f.ds, 2) == 7

    # ---- BeFS：double_indirect 数据流 ----
    def befs_build_double(content):
        BS = 1024
        img = bytearray(BS * 12)
        so = BEFS_SUPER_OFFSET
        put(img, so, b"ESKDBL")
        u32(img, so + BS_MAGIC1, BEFS_MAGIC1)
        u32(img, so + BS_BYTEORDER, BEFS_BYTEORDER_NATIVE)
        u32(img, so + BS_BLOCK_SIZE, BS)
        u32(img, so + BS_BLOCK_SHIFT, 10)
        u64(img, so + BS_NUM_BLOCKS, 12)
        u64(img, so + BS_USED_BLOCKS, 10)
        u32(img, so + BS_INODE_SIZE, 512)
        u32(img, so + BS_MAGIC2, BEFS_MAGIC2)
        u32(img, so + BS_BLOCKS_PER_AG, 1 << 10)
        u32(img, so + BS_AG_SHIFT, 10)
        u32(img, so + BS_NUM_AGS, 1)
        u32(img, so + BS_FLAGS, BEFS_CLEAN)
        u32(img, so + BS_MAGIC3, BEFS_MAGIC3)
        struct.pack_into(">IHH", img, so + BS_ROOT_DIR, 0, 1, 1)

        def inode(blk, mode, dtype, size, direct, max_direct, indirect,
                  max_indirect, dbl, max_double):
            o = blk * BS
            u32(img, o + BI_MAGIC1, BEFS_INODE_MAGIC)
            struct.pack_into(">IHH", img, o + BI_INODE_NUM, 0, blk, 1)
            u32(img, o + BI_MODE, mode)
            u32(img, o + BI_FLAGS, 1)
            u32(img, o + BI_TYPE, dtype)
            u32(img, o + BI_INODE_SIZE, 512)
            struct.pack_into(">IHH", img, o + BI_DATA, *direct)
            u64(img, o + BI_DATA + DS_MAX_DIRECT, max_direct)
            struct.pack_into(">IHH", img, o + BI_DATA + DS_INDIRECT, *indirect)
            u64(img, o + BI_DATA + DS_MAX_INDIRECT, max_indirect)
            struct.pack_into(">IHH", img, o + BI_DATA + DS_DOUBLE, *dbl)
            u64(img, o + BI_DATA + DS_MAX_DOUBLE, max_double)
            u64(img, o + BI_DATA + DS_SIZE, size)

        fname = b"dbl.bin"
        dent = struct.pack(">IIII", 3, 16, 16 + len(fname), 0) + fname
        put(img, 2 * BS, dent)
        put(img, 4 * BS, content[:BS])
        struct.pack_into(">IHH", img, 5 * BS, 0, 6, 4)     # 双间接[0] -> 间接游程 6..9
        struct.pack_into(">IHH", img, 6 * BS, 0, 10, 1)    # 间接游程块 6 第 0 项 -> 10
        struct.pack_into(">IHH", img, 6 * BS + 8, 0, 11, 1)
        put(img, 10 * BS, content[BS:2 * BS])
        put(img, 11 * BS, content[2 * BS:3 * BS])

        inode(1, 0o040000 | 0o755, 2, len(dent), (0, 2, 1), BS,
              (0, 0, 0), 0, (0, 0, 0), 0)
        inode(3, 0o100000 | 0o644, 1, 3 * BS, (0, 4, 1), BS,
              (0, 0, 0), BS, (0, 5, 1), 3 * BS)
        return bytes(img)

    dbn = bytes((i * 17 + 9) & 0xFF for i in range(3 * 1024))
    fs = BeFS(Buf(befs_build_double(dbn)))
    f = fs.listdir()[0]
    print("  BeFS double: %r size=%d dbl_max=%d"
          % (f.name, f.size, f.ds["max_double"]))
    assert f.size == 3 * 1024
    assert fs._ds_block(f.ds, 1) == 10 and fs._ds_block(f.ds, 2) == 11
    assert fs.read_file(f) == dbn, "BeFS double_indirect 读出的内容不对"

    # ---- QNX4：扩展块（xblk）链 ----
    def qnx4_build_xblk(content):
        BS = 512
        img = bytearray(BS * 6)

        def ent(off, fname, size, xt0, xt0n, mode, ftype, num=1, xblk=0,
                status=1):
            put(img, off, fname)
            u32(img, off + Q4_SIZE, size, "<")
            u32(img, off + Q4_FIRST_XTNT, xt0, "<")
            u32(img, off + Q4_FIRST_XTNT + 4, xt0n, "<")
            u32(img, off + Q4_XBLK, xblk, "<")
            struct.pack_into("<H", img, off + Q4_NUM_XTNTS, num)
            struct.pack_into("<H", img, off + Q4_MODE, mode)
            img[off + Q4_TYPE] = ftype
            img[off + Q4_STATUS] = status

        ent(BS + 0, b"/\x00", 2 * 64, 3, 1, 0o040755, 1)
        ent(2 * BS + 0, b".\x00", 2 * 64, 3, 1, 0o040755, 1)
        # 两个 extent：首段 (4,1)，第二段在 xblk（块 5 指向 (6,1)）
        ent(2 * BS + 64, b"span.bin\x00", len(content), 4, 1, 0o100644, 2,
            num=2, xblk=5)
        # xblk 在 dev 块 4，签名 + 1 个 extent
        xo = 4 * BS
        u32(img, xo + X_NUM_BLOCKS, 1, "<")
        img[xo + X_NUM_XTNTS] = 1
        u32(img, xo + X_XTNTS, 6, "<")
        u32(img, xo + X_XTNTS + 4, 1, "<")
        put(img, xo + X_SIGNATURE, QNX4_XBLK_SIG)
        put(img, 3 * BS, content[:BS])
        put(img, 5 * BS, content[BS:2 * BS])
        return bytes(img)

    span = bytes((i * 13 + 1) & 0xFF for i in range(1024))
    fs = Qnx4FS(Buf(qnx4_build_xblk(span)))
    f = [e for e in fs.listdir() if e.name == "span.bin"][0]
    print("  QNX4 xblk: %r size=%d extents=%s" % (f.name, f.size, f.extents))
    assert f.extents == [(4, 1), (6, 1)], f.extents
    assert fs.read_file(f) == span, "QNX4 扩展块链读出的内容不对"

    # ---- QNX6：长文件名 + 一级 / 二级间接 ----
    def qnx6_build_ext(content_hello, content_ind, longname, deep):
        BS = 4096
        nblk = 13
        img = bytearray(BS * nblk)
        so = QNX6_SUPER_OFFSET

        def rnode(off, size, ptr0, levels):
            u64(img, so + off + RN_SIZE, size)
            for i in range(QNX6_NO_DIRECT_POINTERS):
                u32(img, so + off + RN_PTR + 4 * i, 0xFFFFFFFF if i else ptr0)
            img[so + off + RN_LEVELS] = levels

        u32(img, so + S_MAGIC, QNX6_MAGIC)
        u64(img, so + S_SERIAL, 3)
        u32(img, so + S_CTIME, 0x5F5E1000)
        struct.pack_into(">H", img, so + S_VERSION1, 1)
        put(img, so + S_VOLUMEID, b"ESKQNX6EXT")
        u32(img, so + S_BLOCKSIZE, BS)
        u32(img, so + S_NUM_INODES, 4)
        u32(img, so + S_FREE_INODES, BS // QNX6_INODE_SIZE - 4)
        u32(img, so + S_NUM_BLOCKS, nblk)
        u32(img, so + S_FREE_BLOCKS, 1)
        u32(img, so + S_ALLOCGROUP, 1 << 10)
        rnode(S_INODE, BS, 0, 0)         # inode 表 -> dev 3
        rnode(S_BITMAP, 0, 0xFFFFFFFF, 0)
        rnode(S_LONGFILE, BS, 3, 0)      # 长名区 -> dev 6
        rnode(S_UNKNOWN, 0, 0xFFFFFFFF, 0)
        u32(img, so + S_CHECKSUM, crc32_be(0, bytes(img[so + 8:so + QNX6_SUPER_SIZE])))

        def inode(off, size, mode, ptr0, levels, status):
            u64(img, off + Q6I_SIZE, size)
            u32(img, off + Q6I_MTIME, 0x5F5E1001)
            struct.pack_into(">H", img, off + Q6I_MODE, mode)
            for i in range(QNX6_NO_DIRECT_POINTERS):
                u32(img, off + Q6I_PTR + 4 * i, 0xFFFFFFFF if i else ptr0)
            img[off + Q6I_LEVELS] = levels
            img[off + Q6I_STATUS] = status

        base = 3 * BS
        ents = [(1, b"."), (1, b".."), (2, b"hello.txt"), (3, b"ind.bin"),
                (5, b"lvl2.bin")]
        dirdata = bytearray()
        for ino, nm in ents:
            dirdata += struct.pack(">IB", ino, len(nm)) + nm.ljust(27, b"\x00")
        # 长名项：de_size=0xff，de_long_inode 指向 Longfile 流第 0 块
        dirdata += (struct.pack(">IB", 4, 0xFF) + b"\x00" * 3
                    + struct.pack(">II", 0, qnx6_lfile_checksum(longname)))
        # long_dir_entry 只占前 16 字节，整槽仍是 32 字节
        dirdata += b"\x00" * (QNX6_DIR_ENTRY_SIZE - 16)

        inode(base + 0 * QNX6_INODE_SIZE, len(dirdata), 0o040755, 1, 0,
              QNX6_FILE_DIRECTORY)
        inode(base + 1 * QNX6_INODE_SIZE, len(content_hello), 0o100644, 2, 0,
              QNX6_FILE_NORMAL)
        inode(base + 2 * QNX6_INODE_SIZE, len(content_ind), 0o100644, 4, 1,
              QNX6_FILE_NORMAL)
        inode(base + 3 * QNX6_INODE_SIZE, 10, 0o100644, 6, 0, QNX6_FILE_NORMAL)
        # ino 5：二级间接 —— ptr[0]=7 -> dev 10（一级表）-> 8 -> dev 11（0 级表）
        #          -> 9 -> dev 12（数据）
        inode(base + 4 * QNX6_INODE_SIZE, len(deep), 0o100644, 7, 2,
              QNX6_FILE_NORMAL)

        put(img, 4 * BS, bytes(dirdata))
        put(img, 5 * BS, content_hello)
        # ind.bin：一级间接 —— 4 -> dev 7（间接表）-> 5 -> dev 8（数据）
        u32(img, 7 * BS, 5)
        put(img, 8 * BS, content_ind)
        put(img, 9 * BS, b"long name!")
        put(img, 6 * BS, struct.pack(">H", len(longname)) + longname)
        u32(img, 10 * BS, 8)
        u32(img, 11 * BS, 9)
        put(img, 12 * BS, deep)
        return bytes(img)

    longname = b"a_very_long_filename_over_27chars.dat"
    assert len(longname) > QNX6_SHORT_NAME_MAX
    deep = b"two level qnx6\n"
    fs = Qnx6FS(Buf(qnx6_build_ext(b"hi qnx6\n", b"indirect qnx6\n", longname,
                                   deep)))
    names = [(e.name, e.ino, e.name_checksum_ok) for e in fs.listdir()]
    print("  QNX6 扩展: %s" % names)
    assert [n for n, _, _ in names] == [".", "..", "hello.txt", "ind.bin",
                                        "lvl2.bin", _dec(longname)], names
    assert names[5][2], "长文件名校验和应为 True"
    ind = [e for e in fs.listdir() if e.name == "ind.bin"][0]
    assert ind.node.levels == 1
    assert fs.read_file(ind) == b"indirect qnx6\n", "QNX6 一级间接读错了"
    assert fs.map_block(ind.node, 0) == 8, fs.map_block(ind.node, 0)
    lv2 = [e for e in fs.listdir() if e.name == "lvl2.bin"][0]
    assert lv2.node.levels == 2
    assert fs.map_block(lv2.node, 0) == 12, fs.map_block(lv2.node, 0)
    assert fs.read_file(lv2) == deep, "QNX6 二级间接读错了"
    ln = fs.listdir()[5]
    assert fs.read_file(ln) == b"long name!"

    print("-- 扩展路径通过 --")

    # ---- 互不误判 ----
    expect = {"amiga-ofs": "amiga", "amiga-ffs": "amiga", "befs": "befs",
              "qnx4": "qnx4", "qnx6": "qnx6"}
    for name, img in images.items():
        d = detect_all(Buf(img))
        got = probe(Buf(img))
        print("  %-9s -> probe=%-9s hits=%s" % (name, got, d["hits"]))
        assert got == name, "%s 被识别成 %s" % (name, got)
        assert d["hits"] == [expect[name]], "%s 命中多个：%s" % (name, d["hits"])
        assert d["format"] == name

    # 交叉构造应立刻失败
    fb = Buf(befs_build()[0])
    f4 = Buf(qnx4_build()[0])
    f6 = Buf(qnx6_build()[0])
    for bad, cls in ((fb, Qnx4FS), (fb, Qnx6FS), (f4, BeFS), (f4, Qnx6FS),
                     (f6, BeFS), (f6, Qnx4FS)):
        try:
            cls(bad)
        except RetroFSError:
            pass
        else:
            raise AssertionError("%s 竟然接受了别的格式的镜像" % cls.__name__)

    # ---- 未知 / 截断 ----
    assert probe(Buf(b"\x00" * 65536)) == "unknown"
    assert probe(Buf(b"NOTAFS!!" * 4096)) == "unknown"
    assert probe(Buf(b"DOS\x09" + b"\x00" * 65532)) == "unknown"
    print("  随机/零填充 -> unknown")

    trunc = [
        (lambda: AmigaFS(Buf(images["amiga-ofs"][:300])), "Amiga 300 B"),
        (lambda: AmigaFS(Buf(images["amiga-ofs"][:700])), "Amiga 700 B"),
        (lambda: AmigaFS(Buf(b"DOS\x00" + b"\x00" * 2000)), "Amiga 无根块"),
        (lambda: BeFS(Buf(images["befs"][:600])), "BeFS 600 B"),
        (lambda: BeFS(Buf(images["befs"][:1100])), "BeFS 根 inode 被截掉"),
        (lambda: Qnx4FS(Buf(images["qnx4"][:200])), "QNX4 200 B"),
        (lambda: Qnx4FS(Buf(images["qnx4"][:1100])), "QNX4 根目录越界"),
        (lambda: Qnx6FS(Buf(images["qnx6"][:500])), "QNX6 500 B"),
        (lambda: Qnx6FS(Buf(images["qnx6"][:0x2400])), "QNX6 inode 表越界"),
    ]
    for fn, why in trunc:
        try:
            fn()
        except RetroFSError as ex:
            print("  截断用例 OK（%s）：%s" % (why, ex))
        else:
            raise AssertionError("截断用例未抛异常：%s" % why)

    print("自检通过")
