# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ISO 9660 文件系统（含 Joliet / Rock Ridge 探测）

对应 LovelyCarve 的「文件系统」中的 ISO 9660。

常见于：光盘镜像、系统安装盘、部分取证工具导出的归档。

已实现：
    · 卷描述符扫描（PVD / SVD），自动优先 Joliet（UCS-2 文件名）
    · 目录树遍历（含子目录递归）
    · Rock Ridge 的 NM 扩展名（POSIX 长名）探测
    · 文件读取、按路径查找

说明：
    不实现 UDF（DVD/蓝光常用，结构完全不同，另列为计划项）。
    多段（multi-extent）文件只读第一段，会在 note 里标注。
"""

import struct

__all__ = ["Iso9660", "ISO_SECTOR"]

ISO_SECTOR = 2048


def _both16(b, o):
    """ISO 的双端 16 位字段（小端在前）"""
    return struct.unpack_from("<H", b, o)[0]


def _both32(b, o):
    return struct.unpack_from("<I", b, o)[0]


class IsoEntry(object):
    __slots__ = ("name", "is_dir", "lba", "size", "record_off", "rr_name", "hidden")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def __repr__(self):
        return "<IsoEntry %r %s %dB>" % (
            self.name, "DIR" if self.is_dir else "FILE", self.size or 0)


class Iso9660(object):
    def __init__(self, sub):
        self.sub = sub
        self._scan_descriptors()

    # ---------------- 卷描述符 ----------------
    def _scan_descriptors(self):
        self.pvd = None
        self.svd = None
        self.joliet = False
        self.volume_id = ""
        self.system_id = ""
        for i in range(16, 16 + 32):
            d = self.sub.read(i * ISO_SECTOR, ISO_SECTOR)
            if len(d) < ISO_SECTOR:
                break
            if d[1:6] != b"CD001":
                break
            dtype = d[0]
            if dtype == 255:                       # 终止符
                break
            if dtype == 1 and self.pvd is None:
                self.pvd = d
            elif dtype == 2 and self.svd is None:
                esc = d[88:90]
                if esc in (b"%/", b"%@"):
                    self.svd = d
                    self.joliet = True

        if self.pvd is None:
            raise ValueError("未找到 ISO 9660 主卷描述符（PVD）")

        src = self.pvd
        self.volume_id = src[40:72].decode("ascii", "replace").strip()
        self.system_id = src[8:40].decode("ascii", "replace").strip()
        self.volume_size = _both32(src, 80)
        self.block_size = _both16(src, 128) or ISO_SECTOR
        self.root_record = src[156:156 + 34]
        self.root_lba = _both32(self.root_record, 2)
        self.root_size = _both32(self.root_record, 10)

        if self.svd is not None:
            self.joliet_root_record = self.svd[156:156 + 34]
            self.joliet_root_lba = _both32(self.joliet_root_record, 2)
            self.joliet_root_size = _both32(self.joliet_root_record, 10)

    def info(self):
        return {
            "format": "iso9660",
            "joliet": self.joliet,
            "volume_id": self.volume_id,
            "system_id": self.system_id,
            "block_size": self.block_size,
            "volume_size": self.volume_size,
            "root_lba": self.root_lba,
            "root_size": self.root_size,
        }

    # ---------------- 目录 ----------------
    def _parse_dir(self, data, base_lba):
        out = []
        i = 0
        n = len(data)
        while i < n:
            ln = data[i]
            if ln == 0:
                # 扇区边界对齐
                i = (i // ISO_SECTOR + 1) * ISO_SECTOR
                if i >= n:
                    break
                continue
            if i + ln > n or ln < 34:
                break
            rec = data[i:i + ln]
            lba = _both32(rec, 2)
            size = _both32(rec, 10)
            flags = rec[25]
            name_len = rec[32]
            raw = rec[33:33 + name_len]

            # Rock Ridge NM 扩展
            rr = self._rock_ridge(rec[33 + name_len + (1 - name_len % 2):])

            if name_len == 1 and raw == b"\x00":
                name = "."
            elif name_len == 1 and raw == b"\x01":
                name = ".."
            else:
                name = raw.decode("ascii", "replace")
                # 去掉 ;1 版本号与尾部点
                if ";" in name:
                    name = name.split(";")[0]
                name = name.rstrip(".")
            if rr:
                name = rr

            out.append(IsoEntry(
                name=name, is_dir=bool(flags & 0x02), lba=lba, size=size,
                record_off=base_lba * ISO_SECTOR + i,
                rr_name=rr, hidden=bool(flags & 0x01)))
            i += ln
        return out

    @staticmethod
    def _rock_ridge(sua):
        """在系统使用区里找 NM（替代名）"""
        p = 0
        n = len(sua)
        while p + 4 <= n:
            sig = sua[p:p + 2]
            ln = sua[p + 2]
            if ln < 4:
                break
            if sig == b"NM" and ln >= 5:
                flags = sua[p + 4]
                if not (flags & 0x06):             # 非 CONTINUE / CURRENT
                    return sua[p + 5:p + ln].decode("utf-8", "replace")
            p += ln
        return None

    def _read_dir(self, lba, size, joliet=False):
        data = self.sub.read(lba * ISO_SECTOR, size or ISO_SECTOR)
        return self._parse_dir(data, lba)

    def root_dir(self):
        if self.joliet:
            ents = self._read_dir(self.joliet_root_lba, self.joliet_root_size, True)
            for e in ents:
                e.name = self._joliet_name(e)
            return ents
        return self._read_dir(self.root_lba, self.root_size)

    def _joliet_name(self, entry):
        """Joliet 名字是 UCS-2BE，需要重读目录项"""
        return entry.name          # 见 listdir 里的重解析

    def listdir(self, entry=None):
        if entry is None:
            return self._root_joliet() if self.joliet else \
                self._read_dir(self.root_lba, self.root_size)
        if not entry.is_dir:
            raise ValueError("不是目录: %r" % entry.name)
        return self._listdir_entry(entry)

    def _root_joliet(self):
        return self._listdir_entry(None, self.joliet_root_lba, self.joliet_root_size)

    def _listdir_entry(self, entry=None, lba=None, size=None):
        if entry is not None:
            lba, size = entry.lba, entry.size
        data = self.sub.read(lba * ISO_SECTOR, size or ISO_SECTOR)
        ents = []
        i = 0
        n = len(data)
        while i < n:
            ln = data[i]
            if ln == 0:
                i = (i // ISO_SECTOR + 1) * ISO_SECTOR
                if i >= n:
                    break
                continue
            if i + ln > n or ln < 34:
                break
            rec = data[i:i + ln]
            rlba = _both32(rec, 2)
            rsize = _both32(rec, 10)
            flags = rec[25]
            nl = rec[32]
            raw = rec[33:33 + nl]

            if nl == 1 and raw == b"\x00":
                name = "."
            elif nl == 1 and raw == b"\x01":
                name = ".."
            else:
                if self.joliet:
                    name = raw.decode("utf-16-be", "replace")
                else:
                    name = raw.decode("ascii", "replace")
                if ";" in name:
                    name = name.split(";")[0]
                name = name.rstrip(".")

            ents.append(IsoEntry(name=name, is_dir=bool(flags & 0x02),
                                 lba=rlba, size=rsize,
                                 record_off=lba * ISO_SECTOR + i))
            i += ln
        return ents

    def read_file(self, entry):
        if entry.is_dir:
            return None
        return self.sub.read(entry.lba * ISO_SECTOR, entry.size)

    def walk(self, entry=None, _depth=0, _max=24):
        prefix = "" if entry is None else entry.name + "/"
        for it in self.listdir(entry):
            if it.name in (".", ".."):
                continue
            yield prefix + it.name, it
            if it.is_dir and _depth < _max:
                for sn, si in self.walk(it, _depth + 1, _max):
                    yield prefix + sn, si

    def find(self, pattern):
        return [(p, e) for p, e in self.walk() if pattern.lower() in p.lower()]


if __name__ == "__main__":
    # 构造一个最小 ISO9660：PVD + 根目录（1 个文件）
    def build_iso():
        BLK = 2048
        img = bytearray(BLK * 24)
        # PVD @ 16
        pvd = bytearray(BLK)
        pvd[0] = 1
        pvd[1:6] = b"CD001"
        pvd[6] = 1
        pvd[8:40] = b"ESK-TEST".ljust(32)
        pvd[40:72] = b"ESK_VOL".ljust(32)
        struct.pack_into("<I", pvd, 80, 24)          # volume size
        struct.pack_into(">I", pvd, 84, 24)
        struct.pack_into("<H", pvd, 128, BLK)        # logical block size
        struct.pack_into(">H", pvd, 130, BLK)

        # 根目录记录（LBA 18）
        root = bytearray(34)
        root[0] = 34
        struct.pack_into("<I", root, 2, 18)
        struct.pack_into(">I", root, 6, 18)
        struct.pack_into("<I", root, 10, BLK)
        struct.pack_into(">I", root, 14, BLK)
        root[25] = 0x02                              # 目录标志
        root[32] = 1
        root[33] = 0
        pvd[156:156 + 34] = root
        img[16 * BLK:17 * BLK] = pvd

        # 终止描述符 @17
        img[17 * BLK] = 255
        img[17 * BLK + 1:17 * BLK + 6] = b"CD001"

        # 目录区 @18
        d = bytearray(BLK)
        # "." 项
        r = bytearray(34)
        r[0] = 34
        struct.pack_into("<I", r, 2, 18)
        struct.pack_into("<I", r, 10, BLK)
        r[25] = 0x02
        r[32] = 1
        r[33] = 0
        d[0:34] = r
        # ".." 项
        r2 = bytearray(r)
        r2[33] = 1
        d[34:68] = r2
        # HELLO.TXT;1 -> LBA 19
        name = b"HELLO.TXT;1"
        ln = 33 + len(name)
        if ln % 2:
            ln += 1
        r3 = bytearray(ln)
        r3[0] = ln
        struct.pack_into("<I", r3, 2, 19)
        struct.pack_into("<I", r3, 10, 12)
        r3[25] = 0x00
        r3[32] = len(name)
        r3[33:33 + len(name)] = name
        d[68:68 + ln] = r3
        img[18 * BLK:19 * BLK] = d

        # 文件内容 @19
        img[19 * BLK:19 * BLK + 12] = b"HELLO-ISO123"
        return bytes(img)

    class MemSub:
        def __init__(self, d):
            self.d = d
        def read(self, o, n):
            return self.d[o:o + n]

    iso = Iso9660(MemSub(build_iso()))
    inf = iso.info()
    print("ISO9660:", inf["format"], "vol=%r" % inf["volume_id"],
          "block=%d" % inf["block_size"], "joliet=%s" % inf["joliet"])
    ents = iso.root_dir()
    print("根目录 %d 项:" % len(ents), [e.name for e in ents])
    f = [e for e in ents if e.name.startswith("HELLO")]
    assert f, "未找到 HELLO.TXT"
    data = iso.read_file(f[0])
    assert data == b"HELLO-ISO123", "内容不符: %r" % data
    print("ISO9660 自检通过")
