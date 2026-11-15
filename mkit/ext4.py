# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""自研 ext2/ext3/ext4 解析器 —— 纯标准库。

覆盖：superblock、flex_bg、64bit 组描述符、inode 表、extent tree(深度任意)、
      indirect block(ext2/3)、inline data、htree 目录、稀疏文件、删除 inode 枚举。
"""
import struct
import datetime
import stat as statmod

EXT4_EXTENTS_FL = 0x00080000
EXT4_INLINE_DATA_FL = 0x10000000
EXT4_INDEX_FL = 0x00001000
EXT4_HUGE_FILE_FL = 0x00040000

INCOMPAT_64BIT = 0x0080
RO_COMPAT_HUGE_FILE = 0x0008

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000


def _ts(sec):
    try:
        return datetime.datetime.fromtimestamp(sec, datetime.timezone.utc)
    except Exception:
        return None


class Inode:
    __slots__ = ("fs", "num", "raw", "mode", "uid", "gid", "size", "atime", "ctime",
                 "mtime", "dtime", "links", "blocks", "flags", "extra_isize", "crtime",
                 "ftype", "index", "generation")

    def __init__(self, fs, num, raw, index):
        self.fs = fs
        self.num = num
        self.raw = raw
        self.index = index
        (self.mode, self.uid, size_lo, at, ct, mt, dt, self.gid, self.links, self.blocks,
         self.flags) = struct.unpack_from("<HHIIIIIHHII", raw, 0)
        self.size = size_lo
        if fs.inode_size > 108:
            hi = struct.unpack_from("<I", raw, 108)[0]
            if self.flags & EXT4_HUGE_FILE_FL:
                self.size = size_lo | (hi << 32)
            else:
                self.size = size_lo | (hi << 32)
        self.atime, self.ctime = _ts(at), _ts(ct)
        self.mtime, self.dtime = _ts(mt), _ts(dt)
        self.crtime = None
        self.extra_isize = 0
        if fs.inode_size > 128:
            self.extra_isize = struct.unpack_from("<H", raw, 128)[0]
            if self.extra_isize >= 24 and len(raw) >= 0x94:
                cr, = struct.unpack_from("<I", raw, 0x90)
                self.crtime = _ts(cr)
        self.ftype = self.mode & S_IFMT
        self.generation, = struct.unpack_from("<I", raw, 100)

    @property
    def is_dir(self):
        return self.ftype == S_IFDIR

    @property
    def is_file(self):
        return self.ftype == S_IFREG

    @property
    def is_link(self):
        return self.ftype == S_IFLNK

    @property
    def is_deleted(self):
        return self.links == 0 and (self.dtime is None or self.dtime.year > 1970)

    def __repr__(self):
        return f"<inode {self.num} size={self.size} links={self.links}>"


class DirEntry:
    __slots__ = ("name", "inode", "file_type", "entry_inode")

    def __init__(self, name, inode, file_type):
        self.name = name
        self.inode = inode
        self.file_type = file_type

    def __repr__(self):
        return f"<{self.name} -> {self.inode}>"


class Ext4:
    def __init__(self, sub):
        self.sub = sub
        sb = sub.read(1024, 1024)
        if len(sb) < 1024 or struct.unpack_from("<H", sb, 0x38)[0] != 0xEF53:
            raise ValueError("not ext2/3/4 (bad magic)")
        self.sb = sb
        self.inodes_count, self.blocks_count_lo = struct.unpack_from("<II", sb, 0x00)
        (self.first_data_block, log_bs, log_cs, self.blocks_per_group,
         self.clusters_per_group) = struct.unpack_from("<IIIII", sb, 0x14)
        self.inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0]
        self.block_size = 1024 << log_bs
        self.cluster_size = 1024 << log_cs
        self.blocks_count = self.blocks_count_lo
        self.mtime, self.wtime = _ts(struct.unpack_from("<I", sb, 0x2C)[0]), _ts(struct.unpack_from("<I", sb, 0x30)[0])
        self.mnt_count, self.max_mnt_count = struct.unpack_from("<HH", sb, 0x34)
        self.state, self.errors = struct.unpack_from("<HH", sb, 0x3A)
        self.lastcheck = _ts(struct.unpack_from("<I", sb, 0x40)[0])
        self.creator_os, self.rev_level = struct.unpack_from("<II", sb, 0x48)
        self.first_ino = struct.unpack_from("<I", sb, 0x54)[0]
        self.inode_size, self.bg_nr = struct.unpack_from("<HH", sb, 0x58)
        (self.feat_compat, self.feat_incompat, self.feat_ro) = struct.unpack_from("<III", sb, 0x5C)
        self.uuid = sb[0x68:0x78].hex()
        self.volume_name = sb[0x78:0x88].split(b"\x00")[0].decode("utf8", "replace")
        self.last_mounted = sb[0x88:0xC8].split(b"\x00")[0].decode("utf8", "replace")
        self.desc_size = struct.unpack_from("<H", sb, 0xFE)[0]
        if self.feat_incompat & INCOMPAT_64BIT:
            self.blocks_count |= struct.unpack_from("<I", sb, 0x150)[0] << 32
            if self.desc_size < 64:
                self.desc_size = 64
        if self.desc_size == 0 or self.desc_size < 32:
            self.desc_size = 32
        self.mkfs_time = _ts(struct.unpack_from("<I", sb, 0x108)[0])
        self.has_extents = bool(self.feat_incompat & 0x40)
        self.has_filetype = bool(self.feat_incompat & 0x2) or (self.feat_incompat & 0x40)
        self.group_count = (self.blocks_count - self.first_data_block + self.blocks_per_group - 1) // self.blocks_per_group
        self._desc_tab = self._read_desc_table()
        self._inode_cache = {}

    # ---------- 底层 ----------
    def bref(self, blk):
        return blk * self.block_size

    def read_block(self, blk):
        return self.sub.read(self.bref(blk), self.block_size)

    def _read_desc_table(self):
        bs = self.block_size
        start = (self.first_data_block + 1) * bs
        need = self.group_count * self.desc_size
        blob = self.sub.read(start, need)
        descs = []
        for i in range(self.group_count):
            d = blob[i * self.desc_size: (i + 1) * self.desc_size]
            if len(d) < 32:
                break
            bb_lo, ib_lo, it_lo = struct.unpack_from("<III", d, 0)
            free_b, free_i, used_d = struct.unpack_from("<HHH", d, 0x0C)
            flags, = struct.unpack_from("<H", d, 0x18)
            bb, ib, it = bb_lo, ib_lo, it_lo
            if self.desc_size >= 64 and self.feat_incompat & INCOMPAT_64BIT:
                bb_hi, ib_hi, it_hi = struct.unpack_from("<III", d, 0x20)
                bb |= bb_hi << 32
                ib |= ib_hi << 32
                it |= it_hi << 32
            descs.append(dict(block_bitmap=bb, inode_bitmap=ib, inode_table=it,
                              free_blocks=free_b, free_inodes=free_i, used_dirs=used_d, flags=flags))
        return descs

    # ---------- inode ----------
    def inode_offset(self, num):
        grp = (num - 1) // self.inodes_per_group
        idx = (num - 1) % self.inodes_per_group
        if grp >= len(self._desc_tab):
            return None
        return self._desc_tab[grp]["inode_table"] * self.block_size + idx * self.inode_size

    def inode(self, num):
        if num in self._inode_cache:
            return self._inode_cache[num]
        if num < 1 or num > self.inodes_count:
            return None
        off = self.inode_offset(num)
        raw = self.sub.read(off, self.inode_size)
        if len(raw) < 128 or raw == b"\x00" * len(raw):
            return None
        ino = Inode(self, num, raw, off)
        self._inode_cache[num] = ino
        if len(self._inode_cache) > 20000:
            self._inode_cache.clear()
        return ino

    # ---------- 数据块映射 ----------
    def blockmap(self, ino):
        """返回 [(file_offset, block, length)]，稀疏洞为 block=None。"""
        if ino.flags & EXT4_EXTENTS_FL:
            return self._extent_map(ino)
        return self._indirect_map(ino)

    def _extent_map(self, ino):
        out = []
        i_block = ino.raw[0x28:0x28 + 60]
        self._extent_walk(i_block, out, 0)
        return out

    def _extent_walk(self, node, out, depth):
        if len(node) < 12:
            return
        magic, entries, emax, edepth = struct.unpack_from("<HHHH", node, 0)
        if magic != 0xF30A or entries == 0 or entries > emax:
            return
        if edepth == 0:
            for i in range(entries):
                off = 12 + i * 12
                if off + 12 > len(node):
                    break
                ee_block, ee_len, start_hi, start_lo = struct.unpack_from("<IHHI", node, off)
                uninit = bool(ee_len & 0x8000)
                length = ee_len & 0x7FFF
                if length > 32768:
                    length -= 32768
                start = start_lo | (start_hi << 32)
                out.append((ee_block * self.block_size, None if uninit else start, length * self.block_size))
        else:
            for i in range(entries):
                off = 12 + i * 12
                if off + 12 > len(node):
                    break
                ei_block, leaf_lo, leaf_hi = struct.unpack_from("<IIH", node, off)
                child = self.read_block(leaf_lo | (leaf_hi << 32))
                self._extent_walk(child, out, depth + 1)

    def _indirect_map(self, ino):
        out = []
        ptrs = struct.unpack_from("<15I", ino.raw, 0x28)
        bs = self.block_size
        per = bs // 4
        for i in range(12):
            if ptrs[i]:
                out.append((i * bs, ptrs[i], bs))
        base = 12

        def walk(blk, level, start_blk):
            data = self.read_block(blk)
            arr = struct.unpack_from(f"<{per}I", data, 0)
            span = per ** level
            for k, p in enumerate(arr):
                if not p:
                    continue
                off = (start_blk + k * span) * bs
                if level == 1:
                    out.append((off, p, bs))
                else:
                    walk(p, level - 1, start_blk + k * span)

        if ptrs[12]:
            walk(ptrs[12], 1, base)
            base += per
        if ptrs[13]:
            walk(ptrs[13], 2, base)
            base += per * per
        if ptrs[14]:
            walk(ptrs[14], 3, base)
        return out

    def read_data(self, ino, size=None, offset=0):
        size = ino.size if size is None else size
        if ino.flags & EXT4_INLINE_DATA_FL and size <= 60:
            raw = ino.raw[0x28:0x28 + 60]
            return raw[offset:offset + size]
        if ino.is_link and size <= 60 and not (ino.flags & EXT4_EXTENTS_FL):
            return ino.raw[0x28:0x28 + size][offset:]
        bs = self.block_size
        chunks = []
        for foff, blk, length in self.blockmap(ino):
            if foff >= offset + size:
                break
            if blk is None:
                continue
            seg = min(length, offset + size - foff)
            if seg <= 0:
                continue
            start = max(0, offset - foff)
            chunks.append((foff, blk, length, start, seg))
        out = bytearray(size)
        for foff, blk, length, start, seg in chunks:
            pos = foff + start
            take = min(seg, size - (pos - offset))
            if take <= 0:
                continue
            if blk * bs + start >= self.sub.size:
                continue
            data = self.sub.read(blk * bs + start, take)
            out[pos - offset: pos - offset + len(data)] = data
        return bytes(out)

    # ---------- 目录 ----------
    def listdir(self, ino):
        if not ino.is_dir:
            raise ValueError("not a directory")
        bs = self.block_size
        if ino.flags & EXT4_INLINE_DATA_FL:
            data = ino.raw[0x28:0x28 + 60]
            return self._parse_dirents(data, ino.size)
        entries = []
        seen = set()
        if ino.size == 0:
            return entries
        first = True
        for foff, blk, length in self.blockmap(ino):
            if blk is None:
                continue
            for b in range(length // bs):
                data = self.read_block(blk + b)
                if not data:
                    continue
                ents = self._parse_dirents(data, bs, skip_dx=(first and b == 0))
                first = False
                for e in ents:
                    key = (e.name, e.inode)
                    if key in seen:
                        continue
                    seen.add(key)
                    entries.append(e)
        return entries

    def _parse_dirents(self, data, limit, skip_dx=False):
        out = []
        off = 0
        n = min(len(data), limit if limit else len(data))
        if skip_dx:
            # htree 根块：'.'(12) '..'(blocksize-12) 后是 dx_root_info
            if n >= 24 and data[6] == 0 and data[0] == 12:
                pass
        while off + 8 <= n:
            inum, rec_len, name_len, ftype = struct.unpack_from("<IHBB", data, off)
            if name_len == 0 and rec_len in (0, 0xFFFF):
                pass
            if rec_len < 8 or off + rec_len > n:
                if skip_dx and off == 0:
                    break
                break
            if inum and name_len and name_len <= rec_len - 8:
                name = data[off + 8: off + 8 + name_len]
                try:
                    nm = name.decode("utf8")
                except UnicodeDecodeError:
                    nm = name.decode("latin1")
                out.append(DirEntry(nm, inum, ftype))
            elif inum and name_len == 0:
                pass
            elif not inum and name_len and skip_dx:
                # dx 索引块：跳过其后的索引数组，避免误判
                pass
            off += rec_len
        if skip_dx and not out:
            out = self._scan_dirents(data, n)
        return out

    def _scan_dirents(self, data, n):
        out = []
        base = 24 + 8  # dx_root_info(8) 之后
        off = base
        while off + 8 <= n:
            inum, rec_len, name_len, ftype = struct.unpack_from("<IHBB", data, off)
            if rec_len < 8 or off + rec_len > n or not inum or name_len == 0 or name_len > rec_len - 8:
                break
            try:
                nm = data[off + 8: off + 8 + name_len].decode("utf8")
            except UnicodeDecodeError:
                nm = data[off + 8: off + 8 + name_len].decode("latin1")
            out.append(DirEntry(nm, inum, ftype))
            off += rec_len
        return out

    # ---------- 路径 ----------
    def lookup(self, path):
        cur = self.inode(2)
        parts = [p for p in path.replace("\\", "/").split("/") if p and p != "."]
        for p in parts:
            if p == "..":
                cur = self._parent(cur)
                continue
            found = None
            for e in self.listdir(cur):
                if e.name == p:
                    found = e
                    break
            if found is None:
                return None
            cur = self.inode(found.inode)
            if cur is None:
                return None
        return cur

    def _parent(self, ino):
        for e in self.listdir(ino):
            if e.name == "..":
                return self.inode(e.inode)
        return self.inode(2)

    def walk(self, path="/", deleted=False):
        stack = [self.lookup(path)] if isinstance(path, str) else [path]
        roots = []
        while stack:
            d = stack.pop()
            if d is None:
                continue
            try:
                ents = self.listdir(d)
            except Exception:
                continue
            for e in ents:
                if e.name in (".", ".."):
                    continue
                ch = self.inode(e.inode)
                if ch is None:
                    continue
                yield e.name, ch
                if ch.is_dir:
                    stack.append(ch)

    def find(self, name, root="/"):
        low = name.lower()
        for nm, ino in self.walk(root):
            if nm.lower() == low:
                yield ino

    def iter_all_inodes(self):
        for num in range(1, self.inodes_count + 1):
            ino = self.inode(num)
            if ino is not None:
                yield ino

    def path_of(self, ino, max_depth=64):
        """回溯父目录（依赖 .. 链接，对未链接文件无效）。"""
        names = []
        cur = ino
        for _ in range(max_depth):
            if cur is None or cur.num == 2:
                break
            par = self._parent(cur)
            if par is None:
                break
            nm = None
            try:
                for e in self.listdir(par):
                    if e.inode == cur.num:
                        nm = e.name
                        break
            except Exception:
                break
            if nm is None:
                break
            names.append(nm)
            cur = par
        return "/" + "/".join(reversed(names))
