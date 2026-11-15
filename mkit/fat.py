# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""FAT12 / FAT16 / FAT32 文件系统

对应 LovelyCarve 的「文件系统 / 文件恢复」中的 FAT 部分。

只依赖可读对象 sub.read(offset, size) / sub.size，不依赖第三方库。

已实现：
    · 引导扇区解析（BPB），含 FAT 类型自动判定
    · FAT 表读取与簇链跟踪（含坏簇、EOC 判断）
    · 目录遍历（8.3 短名 + VFAT 长名）
    · 已删除条目（首字节 0xE5）枚举与恢复
    · 按路径读文件、列目录
    · 未分配簇区间（用于雕刻）

不实现：写操作、格式化、chkdsk。
"""

import struct
import time

__all__ = ["Fat", "ENTRY", "deleted", "listdir"]

ATTR = {
    0x01: "RO", 0x02: "HIDDEN", 0x04: "SYSTEM", 0x08: "VOLUME",
    0x10: "DIR", 0x20: "ARCHIVE", 0x0F: "LFN",
}


class DirEntry(object):
    """目录项"""

    __slots__ = ("name", "short_name", "attr", "cluster", "size",
                 "mtime", "ctime", "atime", "deleted", "slot_off", "is_dir")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def attr_text(self):
        return "|".join(v for k, v in ATTR.items() if self.attr & k) or "-"

    def __repr__(self):
        return "<DirEntry %r %s %dB%s>" % (
            self.name, "DIR" if self.is_dir else "FILE", self.size or 0,
            " DELETED" if self.deleted else "")


def _fdate(d, t):
    """FAT 日期/时间 -> 'YYYY-MM-DD HH:MM:SS'"""
    if not d:
        return None
    y = 1980 + ((d >> 9) & 0x7F)
    mo = (d >> 5) & 0x0F
    da = d & 0x1F
    hh = (t >> 11) & 0x1F
    mi = (t >> 5) & 0x3F
    ss = (t & 0x1F) * 2
    try:
        return "%04d-%02d-%02d %02d:%02d:%02d" % (y, mo, da, hh, mi, ss)
    except Exception:
        return None


def _lfn_char(chunk):
    """LFN 项里的 13 个 UTF-16 字符"""
    s = chunk.decode("utf-16-le", "ignore")
    return s.split("\x00")[0]


class Fat(object):
    """FAT 文件系统"""

    def __init__(self, sub):
        self.sub = sub
        self._read_bpb()

    # ---------------- 引导扇区 ----------------
    def _read_bpb(self):
        s = self.sub.read(0, 512)
        if len(s) < 512 or s[510:512] != b"\x55\xaa":
            raise ValueError("不是 FAT 引导扇区（缺 55AA）")

        (self.bytes_per_sector,) = struct.unpack_from("<H", s, 11)
        (self.sectors_per_cluster,) = struct.unpack_from("<B", s, 13)
        (reserved,) = struct.unpack_from("<H", s, 14)
        (self.num_fats,) = struct.unpack_from("<B", s, 16)
        (self.root_entries,) = struct.unpack_from("<H", s, 17)
        (tot16,) = struct.unpack_from("<H", s, 19)
        (self.media,) = struct.unpack_from("<B", s, 21)
        (fat16,) = struct.unpack_from("<H", s, 22)
        (tot32,) = struct.unpack_from("<I", s, 32)
        (fat32,) = struct.unpack_from("<I", s, 36)

        self.boot_off = 0
        # 有些镜像前面有分区偏移，由调用方保证 sub 已指向分区起点
        self.reserved = reserved
        self.bytes_per_sector = self.bytes_per_sector or 512
        self.sectors_per_cluster = self.sectors_per_cluster or 1
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        self.total_sectors = tot32 or tot16
        if not self.total_sectors:
            raise ValueError("BPB 的 total_sectors 为 0，不是有效 FAT 卷")

        # 根目录占用的扇区（仅 FAT12/16 有固定根区）
        self.root_sectors = ((self.root_entries * 32) + self.bytes_per_sector - 1) \
            // self.bytes_per_sector

        # ---- FAT 类型判定（标准算法）----
        # 先用 fat16 试算；若簇数超出 16 位阈值，才认为是 FAT32 并改读 offset 36
        fat_size = fat16
        data_sectors = self.total_sectors - (self.reserved
                                             + self.num_fats * fat_size
                                             + self.root_sectors)
        clusters = max(0, data_sectors // self.sectors_per_cluster)

        if clusters < 4085:
            self.type = 12
        elif clusters < 65525:
            self.type = 16
        else:
            self.type = 32
            fat_size = fat32
            data_sectors = self.total_sectors - (self.reserved + self.num_fats * fat_size)
            clusters = max(0, data_sectors // self.sectors_per_cluster)

        self.fat_size = fat_size
        self.count_of_clusters = clusters

        self.fat_off = self.reserved * self.bytes_per_sector
        self.root_off = self.fat_off + self.num_fats * self.fat_size * self.bytes_per_sector
        self.data_off = self.root_off + self.root_sectors * self.bytes_per_sector

        if self.type == 32:
            (self.root_cluster,) = struct.unpack_from("<I", s, 44)
            (self.fsinfo_sector,) = struct.unpack_from("<H", s, 48)
            (self.backup_boot,) = struct.unpack_from("<H", s, 50)
            self.data_off = self.fat_off + self.num_fats * self.fat_size * self.bytes_per_sector
            self.root_off = self._cluster_off(self.root_cluster)
            vid_off, lab_off, fs_off = 67, 71, 82
        else:
            self.root_cluster = 0
            self.fsinfo_sector = self.backup_boot = 0
            vid_off, lab_off, fs_off = 39, 43, 54

        (self.volume_id,) = struct.unpack_from("<I", s, vid_off)
        self.label = s[lab_off:lab_off + 11].decode("ascii", "ignore").strip()
        self.fs_type_text = s[fs_off:fs_off + 8].decode("ascii", "ignore").strip()

    def info(self):
        return {
            "type": "FAT%d" % self.type,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "num_fats": self.num_fats,
            "fat_size_sectors": self.fat_size,
            "total_sectors": self.total_sectors,
            "clusters": self.count_of_clusters,
            "root_entries": self.root_entries,
            "root_cluster": self.root_cluster,
            "volume_id": "0x%08X" % self.volume_id,
            "label": self.label,
            "fs_type_text": self.fs_type_text,
            "fat_off": self.fat_off,
            "data_off": self.data_off,
        }

    # ---------------- FAT 表 ----------------
    def fat_next(self, cluster):
        """取簇链的下一簇；0x0FFFFFFF 类返回值表示结束"""
        if self.type == 12:
            off = self.fat_off + cluster + cluster // 2
            v = struct.unpack("<H", self.sub.read(off, 2))[0]
            v = (v >> 4) if (cluster & 1) else (v & 0x0FFF)
            return v, 0x0FF8 <= v <= 0x0FFF
        if self.type == 16:
            off = self.fat_off + cluster * 2
            v = struct.unpack("<H", self.sub.read(off, 2))[0]
            return v, 0xFFF8 <= v <= 0xFFFF
        off = self.fat_off + cluster * 4
        v = struct.unpack("<I", self.sub.read(off, 4))[0] & 0x0FFFFFFF
        return v, 0x0FFFFFF8 <= v <= 0x0FFFFFFF

    def _cluster_off(self, cluster):
        return self.data_off + (cluster - 2) * self.cluster_size

    def chain(self, start, limit=None):
        """跟随簇链"""
        out = []
        c = start
        maxc = limit or (self.count_of_clusters + 2)
        seen = set()
        while 2 <= c < maxc:
            if c in seen:
                break
            seen.add(c)
            out.append(c)
            nxt, eoc = self.fat_next(c)
            if eoc or nxt == 0 or nxt < 2:
                break
            c = nxt
        return out

    def read_clusters(self, start, size=None):
        """按簇链读数据"""
        buf = b""
        for c in self.chain(start):
            buf += self.sub.read(self._cluster_off(c), self.cluster_size)
            if size and len(buf) >= size:
                break
        return buf[:size] if size else buf

    def read_file(self, entry):
        if entry.is_dir:
            return None
        if entry.cluster == 0:
            return b""
        return self.read_clusters(entry.cluster, entry.size)

    # ---------------- 目录 ----------------
    def _parse_dir(self, data, base_off):
        """解析目录区数据，返回 DirEntry 列表（含已删除）"""
        out = []
        lfn = []
        lfn_off = None
        for i in range(0, len(data) - 31, 32):
            e = data[i:i + 32]
            first = e[0]
            if first == 0x00:
                break                        # 目录结束
            attr = e[11]
            if attr == 0x0F:
                # LFN 项
                chunk = e[1:11] + e[14:26] + e[28:32]
                ch = _lfn_char(chunk)
                if first & 0x40:             # 最后一项（顺序最高）
                    lfn = []
                    lfn_off = base_off + i
                lfn.insert(0, ch)
                continue

            short = e[0:8].decode("ascii", "ignore").rstrip()
            ext = e[8:11].decode("ascii", "ignore").rstrip()
            deleted = (first == 0xE5)
            if deleted:
                short = "?" + short[1:]      # 首字符已丢失
            name = "".join(lfn) if lfn else (short + ("." + ext if ext else ""))
            lfn = []

            (clus_hi,) = struct.unpack_from("<H", e, 20)
            (clus_lo,) = struct.unpack_from("<H", e, 26)
            cluster = (clus_hi << 16) | clus_lo if self.type == 32 else clus_lo
            (size,) = struct.unpack_from("<I", e, 28)
            (mtime,) = struct.unpack_from("<H", e, 22)
            (mdate,) = struct.unpack_from("<H", e, 24)
            (ctime,) = struct.unpack_from("<H", e, 14)
            (cdate,) = struct.unpack_from("<H", e, 16)

            out.append(DirEntry(
                name=name, short_name=(short + ("." + ext if ext else "")),
                attr=attr, cluster=cluster, size=size,
                mtime=_fdate(mdate, mtime), ctime=_fdate(cdate, ctime),
                atime=None, deleted=deleted,
                slot_off=base_off + i,
                is_dir=bool(attr & 0x10),
            ))
        return out

    def root_dir(self):
        """根目录（FAT12/16 是固定区，FAT32 是簇链）"""
        if self.type == 32:
            data = self.read_clusters(self.root_cluster)
            base = self._cluster_off(self.root_cluster)
        else:
            data = self.sub.read(self.root_off, self.root_entries * 32)
            base = self.root_off
        return self._parse_dir(data, base)

    def listdir(self, entry=None):
        """列目录。entry=None 表示根目录"""
        if entry is None:
            return self.root_dir()
        if not entry.is_dir:
            raise ValueError("不是目录: %r" % entry.name)
        data = self.read_clusters(entry.cluster)
        base = self._cluster_off(entry.cluster)
        return self._parse_dir(data, base)

    def walk(self, entry=None, _depth=0, _max=16):
        """递归遍历，产出 (路径, DirEntry)"""
        items = self.listdir(entry)
        prefix = "" if entry is None else entry.name + "/"
        for it in items:
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            if it.is_dir and not it.deleted and _depth < _max and it.cluster >= 2:
                for sub_name, sub_it in self.walk(it, _depth + 1, _max):
                    yield prefix + sub_name, sub_it

    def find(self, pattern=None, deleted_only=False):
        """按名字筛选（子串匹配）"""
        out = []
        for path, it in self.walk():
            if deleted_only and not it.deleted:
                continue
            if pattern and pattern.lower() not in path.lower():
                continue
            out.append((path, it))
        return out

    def deleted(self, recurse=True):
        """列出已删除的条目"""
        out = []
        for path, it in self.walk():
            if it.deleted:
                out.append((path, it))
        return out

    # ---------------- 未分配簇 ----------------
    def unallocated_ranges(self):
        """产出未分配簇的线性区间 (offset, length)

        FAT 表里值为 0（空闲）且不在任何链上的簇才算真未分配。
        这里用简单策略：值为 0 的簇视为空闲。
        """
        run_start = None
        run_len = 0
        for c in range(2, self.count_of_clusters + 2):
            v, eoc = self.fat_next(c)
            free = (v == 0)
            if free:
                if run_start is None:
                    run_start = c
                    run_len = 1
                else:
                    run_len += 1
            else:
                if run_start is not None:
                    yield (self._cluster_off(run_start), run_len * self.cluster_size)
                    run_start = None
                    run_len = 0
        if run_start is not None:
            yield (self._cluster_off(run_start), run_len * self.cluster_size)


def listdir(fs, path=None):
    """便捷：列目录（路径用 / 分隔）"""
    if not path:
        return fs.root_dir()
    cur = None
    for part in [p for p in path.split("/") if p]:
        for it in fs.listdir(cur):
            if it.name.lower() == part.lower() and it.is_dir:
                cur = it
                break
        else:
            raise FileNotFoundError(path)
    return fs.listdir(cur)


def deleted(fs):
    """便捷：所有已删除条目"""
    return fs.deleted()


if __name__ == "__main__":
    import io

    print("FAT 模块已加载。用真实镜像测试：")
    print("    from mkit.image import Image, SubImage")
    print("    fs = Fat(SubImage(img, 0x100000, 64<<20))")
    print("    print(fs.info())")
    print("    for p, e in fs.walk(): print(p, e.attr_text, e.size)")
    print("    print(fs.deleted())")
