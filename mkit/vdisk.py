# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""虚拟机磁盘容器 —— QCOW2 与 VirtualBox VDI

对应 LovelyCarve 的「镜像容器」里的 QCOW2 / VDI 两项。

提供统一的只读设备接口：
    dev = Qcow2(f)      # 或 Vdi(f)
    dev.size            # 虚拟容量（字节）
    dev.read(off, n)    # 任意偏移读取，自动做块映射
    dev.info()          # 头部信息

只读，不实现写回、快照回滚、加密（LUKS/BitLocker 另见 mkit.luks）。

QCOW2 结构要点：
    · magic = "QFI\\xfb"，version 2 或 3
    · cluster_bits 通常 16（64 KiB）
    · L1 表 → L2 表 → 数据簇，每级都按 cluster 对齐
    · L2 项低 9 位是标志位，取 host 偏移要 & 0x00ffffffffffe00
    · 未分配的簇读出全零（稀疏）

VDI 结构要点：
    · magic = 7f 10 da be @0（小端读是 0xbeda107f）
    · block map 在 offset_bmap，每项 4 字节，0xFFFFFFFF 表示未分配
    · 数据块从 offset_data 起，每块 block_size 字节，可能带 extra 数据
"""

import struct

__all__ = ["Qcow2", "Vdi", "open_disk"]


class _Sub(object):
    """把一个 dev 切成子区间，方便套给 mkit.ntfs / Ext4 等"""

    def __init__(self, dev, offset, size):
        self.dev = dev
        self.offset = offset
        self.size = size

    def read(self, off, n):
        if off >= self.size:
            return b""
        n = min(n, self.size - off)
        return self.dev.read(self.offset + off, n)


# ============================================================
# QCOW2
# ============================================================
QCOW_MAGIC = 0x514649FB
QCOW_OFLAG_COPIED = 1 << 63
QCOW_OFLAG_COMPRESSED = 1 << 62


class Qcow2(object):
    """QCOW2 v2 / v3 只读设备"""

    def __init__(self, f):
        self.f = f
        self._cache = {}
        self._read_header()

    def _read4(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def _read_header(self):
        h = self._read4(0, 104)
        if len(h) < 72:
            raise ValueError("文件太短，不是 QCOW2")
        (magic,) = struct.unpack_from(">I", h, 0)
        if magic != QCOW_MAGIC:
            raise ValueError("不是 QCOW2（magic=0x%08X）" % magic)

        (self.version,) = struct.unpack_from(">I", h, 4)
        if self.version not in (2, 3):
            raise ValueError("不支持的 QCOW2 版本: %d" % self.version)

        (self.backing_off,) = struct.unpack_from(">Q", h, 8)
        (self.backing_size,) = struct.unpack_from(">I", h, 16)
        (self.cluster_bits,) = struct.unpack_from(">I", h, 20)
        (self.size,) = struct.unpack_from(">Q", h, 24)
        (self.crypt_method,) = struct.unpack_from(">I", h, 32)
        (self.l1_size,) = struct.unpack_from(">I", h, 36)
        (self.l1_off,) = struct.unpack_from(">Q", h, 40)
        (self.refcount_off,) = struct.unpack_from(">Q", h, 48)
        (self.refcount_clusters,) = struct.unpack_from(">I", h, 56)
        (self.nb_snapshots,) = struct.unpack_from(">I", h, 60)
        (self.snapshots_off,) = struct.unpack_from(">Q", h, 64)

        self.cluster_size = 1 << self.cluster_bits
        self.l2_entries = self.cluster_size // 8
        self.l2_bits = self.cluster_bits - 3          # log2(l2_entries)

        self.backing_file = b""
        if self.backing_off and self.backing_size:
            self.backing_file = self._read4(self.backing_off, self.backing_size)

        # 读 L1 表（可能很大，但通常几十 KB）
        raw = self._read4(self.l1_off, self.l1_size * 8)
        self.l1 = list(struct.unpack(">%dQ" % self.l1_size, raw)) if raw else []

    def info(self):
        return {
            "format": "qcow2",
            "version": self.version,
            "virtual_size": self.size,
            "cluster_bits": self.cluster_bits,
            "cluster_size": self.cluster_size,
            "l1_size": self.l1_size,
            "l1_offset": self.l1_off,
            "crypt_method": self.crypt_method,
            "nb_snapshots": self.nb_snapshots,
            "backing_file": self.backing_file.decode("utf-8", "replace"),
            "encrypted": self.crypt_method != 0,
        }

    def _l2_table(self, l1_index):
        """取（并缓存）第 l1_index 张 L2 表"""
        if l1_index in self._cache:
            return self._cache[l1_index]
        if l1_index >= len(self.l1):
            return None
        ent = self.l1[l1_index]
        host = ent & 0x00FFFFFFFFFFFE00
        if host == 0:
            self._cache[l1_index] = None
            return None
        raw = self._read4(host, self.cluster_size)
        tbl = struct.unpack(">%dQ" % self.l2_entries, raw) if len(raw) == self.cluster_size else None
        self._cache[l1_index] = tbl
        return tbl

    def read(self, off, n):
        if off >= self.size:
            return b""
        n = min(n, self.size - off)
        out = bytearray()
        pos = off
        end = off + n
        while pos < end:
            l1i = pos >> (self.cluster_bits + self.l2_bits)
            l2i = (pos >> self.cluster_bits) & (self.l2_entries - 1)
            within = pos & (self.cluster_size - 1)
            take = min(self.cluster_size - within, end - pos)

            tbl = self._l2_table(l1i)
            host = 0
            if tbl is not None and l2i < len(tbl):
                e = tbl[l2i]
                if not (e & QCOW_OFLAG_COMPRESSED):
                    host = e & 0x00FFFFFFFFFFFE00

            if host == 0:
                out += b"\x00" * take                      # 稀疏块
            else:
                data = self._read4(host + within, take)
                out += data + b"\x00" * (take - len(data)) if len(data) < take else data
            pos += take
        return bytes(out)

    def sub(self, offset, size=None):
        return _Sub(self, offset, size if size is not None else self.size - offset)


# ============================================================
# VDI
# ============================================================
VDI_MAGIC = 0xBEDA107F
VDI_BLOCK_FREE = 0xFFFFFFFF


class Vdi(object):
    """VirtualBox VDI 只读设备"""

    def __init__(self, f):
        self.f = f
        self._bmap = None
        self._read_header()

    def _read4(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def _read_header(self):
        h = self._read4(0, 0x200)
        if len(h) < 0x190:
            raise ValueError("文件太短，不是 VDI")
        (magic,) = struct.unpack_from("<I", h, 0x00)
        if magic != VDI_MAGIC:
            raise ValueError("不是 VDI（magic=0x%08X）" % magic)

        (self.version,) = struct.unpack_from("<I", h, 0x04)
        (self.header_size,) = struct.unpack_from("<I", h, 0x08)
        (self.image_type,) = struct.unpack_from("<I", h, 0x0C)
        (self.offset_data,) = struct.unpack_from("<I", h, 0x10)
        (self.offset_blocks,) = struct.unpack_from("<I", h, 0x14)
        (self.offset_disk,) = struct.unpack_from("<I", h, 0x18)
        (self.disk_size,) = struct.unpack_from("<Q", h, 0x170)
        (self.block_size,) = struct.unpack_from("<I", h, 0x178)
        (self.block_extra,) = struct.unpack_from("<I", h, 0x17C)
        (self.blocks_allocated,) = struct.unpack_from("<I", h, 0x16C)
        (self.offset_bmap,) = struct.unpack_from("<I", h, 0x154)

        self.uuid = h[0x188:0x188 + 16].hex()
        self.size = self.disk_size
        self.block_count = (self.disk_size + self.block_size - 1) // self.block_size

    def info(self):
        return {
            "format": "vdi",
            "version": "%d.%d" % (self.version >> 16, self.version & 0xFFFF),
            "virtual_size": self.size,
            "block_size": self.block_size,
            "block_extra": self.block_extra,
            "blocks_total": self.block_count,
            "blocks_allocated": self.blocks_allocated,
            "image_type": self.image_type,
            "uuid": self.uuid,
        }

    def _load_bmap(self):
        if self._bmap is not None:
            return
        raw = self._read4(self.offset_bmap, self.block_count * 4)
        n = len(raw) // 4
        self._bmap = list(struct.unpack("<%dI" % n, raw[:n * 4]))

    def read(self, off, n):
        if off >= self.size:
            return b""
        n = min(n, self.size - off)
        self._load_bmap()
        stride = self.block_size + self.block_extra
        out = bytearray()
        pos = off
        end = off + n
        while pos < end:
            bi = pos // self.block_size
            within = pos % self.block_size
            take = min(self.block_size - within, end - pos)
            if bi >= len(self._bmap):
                out += b"\x00" * take
            else:
                bno = self._bmap[bi]
                if bno == VDI_BLOCK_FREE:
                    out += b"\x00" * take
                else:
                    host = self.offset_data + bno * stride + within
                    data = self._read4(host, take)
                    out += data + b"\x00" * (take - len(data)) if len(data) < take else data
            pos += take
        return bytes(out)

    def sub(self, offset, size=None):
        return _Sub(self, offset, size if size is not None else self.size - offset)


# ============================================================
# 自动识别
# ============================================================
def open_disk(f):
    """按魔数自动识别 VMDK / QCOW2 / VDI 并返回设备对象

    f 需为已打开的二进制文件对象（只读）。
    返回 (设备, 格式名)；无法识别时抛 ValueError。
    """
    f.seek(0)
    head = f.read(512)
    f.seek(0)
    if head[:4] == b"KDMV":
        try:
            import webvm3_dev
            return webvm3_dev.Dev1_fp(f), "vmdk"
        except Exception:
            return None, "vmdk(需 ext/webvm3_dev.py)"
    if len(head) >= 4 and struct.unpack_from(">I", head, 0)[0] == QCOW_MAGIC:
        return Qcow2(f), "qcow2"
    if len(head) >= 4 and struct.unpack_from("<I", head, 0)[0] == VDI_MAGIC:
        return Vdi(f), "vdi"
    if head[:8] == b"vhdxfile":
        return None, "vhdx(需 ext/ans_c02_vhdx.py)"
    raise ValueError("无法识别的磁盘格式")


if __name__ == "__main__":
    import io

    # ---- 构造合成 QCOW2（v3，1 个簇的数据）----
    def build_qcow2():
        CB = 16
        CS = 1 << CB
        size = CS * 4                       # 4 个簇的虚拟盘
        buf = bytearray(CS * 8)             # header + l1 + l2 + data
        # header
        struct.pack_into(">I", buf, 0, QCOW_MAGIC)
        struct.pack_into(">I", buf, 4, 3)
        struct.pack_into(">Q", buf, 8, 0)                  # backing off
        struct.pack_into(">I", buf, 16, 0)                 # backing size
        struct.pack_into(">I", buf, 20, CB)                # cluster_bits
        struct.pack_into(">Q", buf, 24, size)              # virtual size
        struct.pack_into(">I", buf, 32, 0)                 # crypt
        struct.pack_into(">I", buf, 36, 1)                 # l1_size
        struct.pack_into(">Q", buf, 40, CS)                # l1_off = 1 簇
        struct.pack_into(">Q", buf, 48, CS * 6)            # refcount off
        l2_off = CS * 2
        data_off = CS * 3
        # L1[0] -> l2_off
        struct.pack_into(">Q", buf, CS, l2_off)
        # L2[0] -> data_off（标志位 Copied）
        struct.pack_into(">Q", buf, l2_off, data_off | QCOW_OFLAG_COPIED)
        # 数据
        payload = b"QCOW2-PAYLOAD!" * 100
        buf[data_off:data_off + len(payload)] = payload
        return bytes(buf), payload, CS

    img, payload, CS = build_qcow2()
    q = Qcow2(io.BytesIO(img))
    inf = q.info()
    print("QCOW2:", inf["format"], "v%d" % inf["version"],
          "size=%d" % inf["virtual_size"], "cluster=%d" % inf["cluster_size"])
    got = q.read(0, len(payload))
    assert got == payload, "QCOW2 数据不符"
    assert q.read(CS * 1, 16) == b"\x00" * 16, "稀疏块应为零"
    print("QCOW2 自检通过")

    # ---- 构造合成 VDI ----
    def build_vdi():
        BS = 4096
        nblocks = 4
        hdr = bytearray(0x200)
        struct.pack_into("<I", hdr, 0x00, VDI_MAGIC)
        struct.pack_into("<I", hdr, 0x04, 0x00010003)       # 1.3
        struct.pack_into("<I", hdr, 0x08, 0x180)
        struct.pack_into("<I", hdr, 0x0C, 0)
        offset_data = 0x200 + nblocks * 4
        struct.pack_into("<I", hdr, 0x10, offset_data)
        struct.pack_into("<I", hdr, 0x14, 0x200)            # bmap 紧跟头
        struct.pack_into("<Q", hdr, 0x170, nblocks * BS)    # disk size
        struct.pack_into("<I", hdr, 0x178, BS)              # block size
        struct.pack_into("<I", hdr, 0x17C, 0)               # extra
        struct.pack_into("<I", hdr, 0x16C, 2)               # allocated
        struct.pack_into("<I", hdr, 0x154, 0x200)           # bmap offset
        hdr[0x188:0x198] = bytes(range(16))
        buf = bytearray(offset_data + nblocks * BS)
        buf[0:0x200] = hdr
        # bmap: 块0=0, 块1=未分配, 块2=1, 块3=未分配
        struct.pack_into("<I", buf, 0x200 + 0 * 4, 0)
        struct.pack_into("<I", buf, 0x200 + 1 * 4, VDI_BLOCK_FREE)
        struct.pack_into("<I", buf, 0x200 + 2 * 4, 1)
        struct.pack_into("<I", buf, 0x200 + 3 * 4, VDI_BLOCK_FREE)
        d0 = b"VDI-BLOCK-ZERO" * 100
        d2 = b"VDI-BLOCK-TWO!" * 100
        buf[offset_data:offset_data + len(d0)] = d0
        buf[offset_data + BS:offset_data + BS + len(d2)] = d2
        return bytes(buf), d0, d2, BS

    vimg, d0, d2, BS = build_vdi()
    v = Vdi(io.BytesIO(vimg))
    vi = v.info()
    print("VDI:", vi["format"], "v%s" % vi["version"],
          "size=%d" % vi["virtual_size"], "block=%d" % vi["block_size"])
    assert v.read(0, len(d0)) == d0, "VDI 块0 数据不符"
    assert v.read(2 * BS, len(d2)) == d2, "VDI 块2 数据不符"
    assert v.read(BS, 16) == b"\x00" * 16, "未分配块应为零"
    print("VDI 自检通过")
