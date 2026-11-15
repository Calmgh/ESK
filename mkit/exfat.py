# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""exFAT 文件系统

对应 LovelyCarve 的「文件系统」中的 exFAT。

exFAT 常见于 SD 卡、大容量 U 盘、相机存储卡——CTF 与真实案件都高频。

已实现：
    · 引导扇区（VBR）解析，含 512B / 4Kn 两种扇区
    · 簇堆定位与任意簇读取
    · 目录项三种类型：0x85 文件项 / 0xC0 流扩展 / 0xC1 文件名
    · 长文件名、时间戳、删除标记（条目类型 bit7 = 未使用）
    · 按路径读取、递归遍历、未分配簇枚举

只读；不实现写、不实现 TexFAT 双 FAT 切换。
"""

import struct

__all__ = ["Exfat", "ENTRY_FILE", "ENTRY_STREAM", "ENTRY_NAME"]

# 目录项类型。bit7 = in-use 标志，比较时要先掩掉
ENTRY_FILE = 0x85
ENTRY_STREAM = 0xC0
ENTRY_NAME = 0xC1
ENTRY_FILE_M = 0x05          # 0x85 & 0x7F
ENTRY_STREAM_M = 0x40        # 0xC0 & 0x7F
ENTRY_NAME_M = 0x41          # 0xC1 & 0x7F
ENTRY_DELETED_BIT = 0x80


def _dos_time(d, t, cs=0):
    """exFAT 时间 -> 'YYYY-MM-DD HH:MM:SS'"""
    if not d:
        return None
    y = 1980 + ((d >> 9) & 0x7F)
    mo = (d >> 5) & 0x0F
    da = d & 0x1F
    hh = (t >> 11) & 0x1F
    mi = (t >> 5) & 0x3F
    ss = (t & 0x1F) * 2 + (cs // 100 if cs else 0)
    try:
        return "%04d-%02d-%02d %02d:%02d:%02d" % (y, mo, da, hh, mi, ss)
    except Exception:
        return None


class Entry(object):
    __slots__ = ("name", "attr", "cluster", "size", "mtime", "ctime",
                 "atime", "deleted", "is_dir", "slot_off", "contiguous", "valid_size")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def __repr__(self):
        return "<Entry %r %s %dB%s>" % (
            self.name, "DIR" if self.is_dir else "FILE",
            self.size or 0, " DELETED" if self.deleted else "")


class Exfat(object):
    def __init__(self, sub):
        self.sub = sub
        self._read_vbr()

    def _read_vbr(self):
        s = self.sub.read(0, 512)
        if len(s) < 512 or s[3:11] != b"EXFAT   ":
            raise ValueError("不是 exFAT（FSName 不符）")

        (self.fat_offset,) = struct.unpack_from("<I", s, 80)
        (self.fat_length,) = struct.unpack_from("<I", s, 84)
        (self.cluster_heap_offset,) = struct.unpack_from("<I", s, 88)
        (self.cluster_count,) = struct.unpack_from("<I", s, 92)
        (self.root_dir_cluster,) = struct.unpack_from("<I", s, 96)
        (self.volume_serial,) = struct.unpack_from("<I", s, 100)
        (self.fs_revision,) = struct.unpack_from("<H", s, 104)
        (self.volume_flags,) = struct.unpack_from("<H", s, 106)
        (self.bytes_per_sector_shift,) = struct.unpack_from("<B", s, 108)
        (self.sectors_per_cluster_shift,) = struct.unpack_from("<B", s, 109)
        (self.number_of_fats,) = struct.unpack_from("<B", s, 110)
        (self.percent_in_use,) = struct.unpack_from("<B", s, 112)

        self.bytes_per_sector = 1 << self.bytes_per_sector_shift
        self.sectors_per_cluster = 1 << self.sectors_per_cluster_shift
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.heap_off = self.cluster_heap_offset * self.bytes_per_sector
        self.fat_off = self.fat_offset * self.bytes_per_sector
        self.label = s[11:11 + 22].split(b"\x00")[0].decode("utf-16-le", "replace")

    def info(self):
        return {
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "cluster_count": self.cluster_count,
            "root_dir_cluster": self.root_dir_cluster,
            "volume_serial": "0x%08X" % self.volume_serial,
            "fs_revision": "%d.%d" % (self.fs_revision >> 8, self.fs_revision & 0xFF),
            "number_of_fats": self.number_of_fats,
            "percent_in_use": self.percent_in_use,
            "total_size": self.cluster_count * self.cluster_size,
        }

    # ---------------- 簇 ----------------
    def _cluster_off(self, cluster):
        return self.heap_off + (cluster - 2) * self.cluster_size

    def read_cluster(self, cluster):
        return self.sub.read(self._cluster_off(cluster), self.cluster_size)

    def fat_next(self, cluster):
        off = self.fat_off + cluster * 4
        (v,) = struct.unpack("<I", self.sub.read(off, 4))
        return v

    def chain(self, start):
        out = []
        c = start
        guard = self.cluster_count + 2
        while 2 <= c < guard:
            out.append(c)
            nxt = self.fat_next(c)
            if nxt >= 0xFFFFFFF8 or nxt < 2:
                break
            c = nxt
        return out

    def read_data(self, start_cluster, size, contiguous=False):
        if contiguous or True:
            # exFAT 的 NoFatChain 标志为真时是连续块；两种都按簇链读更稳
            pass
        if size == 0:
            return b""
        if contiguous:
            out = self.sub.read(self._cluster_off(start_cluster), size)
            return out
        buf = b""
        for c in self.chain(start_cluster):
            buf += self.read_cluster(c)
            if len(buf) >= size:
                break
        return buf[:size]

    # ---------------- 目录 ----------------
    def _parse_dir(self, data, base):
        out = []
        i = 0
        n = len(data)
        pending = None          # 收集中的文件项
        while i + 32 <= n:
            e = data[i:i + 32]
            etype = e[0]

            if etype == 0x00:                       # 目录结束
                break

            if etype & 0x7F == ENTRY_FILE_M:          # 0x85 / 0x05
                pending = {
                    "deleted": bool(etype & ENTRY_DELETED_BIT),
                    "attr": struct.unpack_from("<H", e, 4)[0],
                    "ctime": _dos_time(struct.unpack_from("<H", e, 12)[0],
                                       struct.unpack_from("<H", e, 14)[0]),
                    "mtime": _dos_time(struct.unpack_from("<H", e, 16)[0],
                                       struct.unpack_from("<H", e, 18)[0]),
                    "atime": _dos_time(struct.unpack_from("<H", e, 20)[0],
                                       struct.unpack_from("<H", e, 22)[0]),
                    "slot_off": base + i,
                    "chars": 0,
                    "name_parts": [],
                }
                i += 32
                continue

            if pending is not None and etype & 0x7F == ENTRY_STREAM_M:   # 0xC0 / 0x40
                pending["cluster"] = struct.unpack_from("<I", e, 20)[0]
                pending["valid_size"] = struct.unpack_from("<Q", e, 8)[0]
                pending["size"] = struct.unpack_from("<Q", e, 24)[0]
                flags = e[1]
                pending["contiguous"] = bool(flags & 0x02)     # NoFatChain
                pending["chars"] = e[3]
                i += 32
                continue

            if pending is not None and etype & 0x7F == ENTRY_NAME_M:    # 0xC1 / 0x41
                pending["name_parts"].append(e[2:32])
                got = len(pending["name_parts"]) * 15
                if got >= pending.get("chars", 0) or len(pending["name_parts"]) >= 17:
                    raw = b"".join(pending["name_parts"])
                    name = raw[:pending.get("chars", len(raw)) * 2]
                    out.append(Entry(
                        name=name.decode("utf-16-le", "replace"),
                        attr=pending["attr"],
                        cluster=pending.get("cluster", 0),
                        size=pending.get("size", 0),
                        valid_size=pending.get("valid_size", 0),
                        mtime=pending["mtime"],
                        ctime=pending["ctime"],
                        atime=pending["atime"],
                        deleted=pending["deleted"],
                        is_dir=bool(pending["attr"] & 0x10),
                        slot_off=pending["slot_off"],
                        contiguous=pending.get("contiguous", False),
                    ))
                    pending = None
                i += 32
                continue

            i += 32
        return out

    def root_dir(self):
        data = self.read_data(self.root_dir_cluster,
                              self.cluster_size * max(1, len(self.chain(self.root_dir_cluster))),
                              contiguous=False)
        return self._parse_dir(data, self._cluster_off(self.root_dir_cluster))

    def listdir(self, entry=None):
        if entry is None:
            return self.root_dir()
        if not entry.is_dir:
            raise ValueError("不是目录: %r" % entry.name)
        cn = self.chain(entry.cluster)
        data = self.read_data(entry.cluster, self.cluster_size * max(1, len(cn)))
        return self._parse_dir(data, self._cluster_off(entry.cluster))

    def read_file(self, entry):
        if entry.is_dir:
            return None
        return self.read_data(entry.cluster, entry.size, entry.contiguous)

    def walk(self, entry=None, _depth=0, _max=16):
        prefix = "" if entry is None else entry.name + "/"
        for it in self.listdir(entry):
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            if it.is_dir and not it.deleted and it.cluster >= 2 and _depth < _max:
                for sn, si in self.walk(it, _depth + 1, _max):
                    yield prefix + sn, si

    def deleted(self):
        return [(p, e) for p, e in self.walk() if e.deleted]

    def unallocated_ranges(self):
        """FAT 中值为 0 的簇视为空闲"""
        run = None
        cnt = 0
        for c in range(2, self.cluster_count + 2):
            if self.fat_next(c) == 0:
                if run is None:
                    run, cnt = c, 1
                else:
                    cnt += 1
            else:
                if run is not None:
                    yield (self._cluster_off(run), cnt * self.cluster_size)
                    run, cnt = None, 0
        if run is not None:
            yield (self._cluster_off(run), cnt * self.cluster_size)


if __name__ == "__main__":
    print("exFAT 模块已加载。用法：")
    print("    from mkit.image import Image, SubImage")
    print("    from mkit.exfat import Exfat")
    print("    fs = Exfat(SubImage(img, 0x100000, 512<<20))")
    print("    print(fs.info())")
    print("    for p, e in fs.walk(): print(p, e.size)")
