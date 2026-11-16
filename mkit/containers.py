# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""冷门镜像 / 固件容器格式的识别与解包

只依赖可读对象的 `read(offset, size)` 与 `size`。

每个格式都产出「载荷区间」（偏移 + 长度 + 说明），`Container` 再把某个区间
包成 `read(offset,size)+size` 的设备对象，可以直接喂 `mkit.fat.Fat`、
`mkit.squashfs.Squashfs`、`mkit.iso.Iso9660` 等。

============================================================================
已实现（头部字段按上游源码核对过）
============================================================================
1. U-Boot legacy uImage —— `include/image.h`
   · 64 字节大端头：ih_magic(0x27051956) / ih_hcrc / ih_time / ih_size /
     ih_load / ih_ep / ih_dcrc / ih_os / ih_arch / ih_type / ih_comp /
     ih_name[32]
   · ih_hcrc 校验（计算时该字段置 0）、ih_dcrc 校验
   · 载荷按 ih_comp 解压：gzip / bzip2 / lzma(xz)
   · ih_os / ih_arch / ih_type / ih_comp 给出可读名

2. Netgear CHK —— `openwrt/firmware-utils` 的 `mkchkimg.c`
   · `struct chk_header` 40 字节大端：magic(0x2A23245E) / header_len /
     reserved[8] / kernel_chksum / rootfs_chksum / kernel_len / rootfs_len /
     image_chksum / header_chksum
   · header_len = 40 + strlen(board_id)，board_id 紧跟头部
   · reserved[0] 是区域码（1=WW、2=NA），reserved[1..7] 是版本 A–G
   · 切出 kernel 与 rootfs 两段

3. TP-Link SafeLoader —— `firmware-utils` 的 `mktplinkfw2.c`
   · `struct fw_header` 512 字节：version / fw_version[48] / hw_id /
     hw_rev / hw_ver_add / md5sum1[16] / unk2 / md5sum2[16] / unk3 /
     kernel_la / kernel_ep / fw_length / kernel_ofs / kernel_len /
     rootfs_ofs / rootfs_len / boot_ofs / boot_len / unk4(0x55AA) /
     sver / unk5(0xA5) / ver_hi / ver_mid / ver_lo / pad
   · 用 `unk5 == 0xA5` 与 `unk4 == 0x55AA` 双重确认，避免把别的 512 字节
     头误判成 SafeLoader
   · 按 kernel_ofs/rootfs_ofs/boot_ofs 切段

4. Sercomm / Netgear 固件 —— `firmware-utils` 的 `mksercommfw.c`
   · 512 字节头，魔数 `"sErCoMm"` 在 **0–6** 与 **63–69** 各出现一次
   · version[4] 在 0x07 附近（`00 01 00 00`）
   · 校验和在偏移 **511**：把该字节当 0x00 算全镜像校验和再取反
   · 载荷从 512 起，长度 = size - 512（- 尾部若存在）

5. Buffalo DNI —— `firmware-utils` 的 `mkbuffaloimg.c`
   · 128 字节 ASCII 头：`device:<board>\nversion:<ver>\nregion:<region>\n
     RootfsSize:<n>\nKernelSize:<n>\nInfoHeadSize:128\n`
   · 按 InfoHeadSize 定位载荷起点，按 KernelSize / RootfsSize 切两段

6. TRX（Broadcom / OpenWrt）
   · 28 字节小端头：magic `"HDR0"` / len / crc32 / flag+version / offsets[3]
   · 校验 CRC32（计算时 crc 字段置 0）
   · 按 offsets[0..2] 切出 loader / kernel / rootfs

7. Parallels PHD —— QEMU `block/parallels.c`
   · 头魔数 `"WithoutFreeSpace"` 或 `"WithouFreSpacExt"`（各 16 字节）
   · 小端字段：version / heads / cylinders / tracks / catalog_entries /
     nb_sectors / inuse / data_off / flags /（扩展版另有 ext_off）
   · BAT 每项 u32：bit31 = 空闲，低 31 位 = 扇区号（512 字节/扇区）
   · `Container` 按 BAT 做稀疏读，未分配块返回零

============================================================================
不实现（没有公开规范，只做识别，绝不编造字段）
============================================================================
· **DiskGenius PMFX**：只按文件名/伴随文件特征与常见魔数做「疑似」识别，
  不解析字段。查不到公开的头部规范，不猜
· **雷电模拟器 LDBK**：同上，只识别
· **小米 HDR1**：同上，只识别
  （这三个的 `describe()` 会返回 `spec_known=False` 并在 notes 里写明原因；
   不做任何字段解码，也不假装能切出载荷）
· 加密固件（Buffalo ENC 的加密体、Sercomm 的加密变体）：只识别，
  不做解密——没有密钥材料
· 写回与重打包：只读
· 除 uImage 的 gzip/bzip2/xz 外，其余格式的内嵌压缩一律不自动解
  （切出载荷后交给调用方用 `mkit.archive` 或 `mkit.squashfs` 处理）
"""

import bz2
import gzip
import lzma
import struct

__all__ = [
    "detect", "describe", "extract", "load", "Container",
    "probe_signatures",
    "UIMAGE_MAGIC", "CHK_MAGIC", "TRX_MAGIC",
    "PHD_MAGIC_BASIC", "PHD_MAGIC_EXT", "SERCOMM_MAGIC",
    "SIGNATURES", "FORMATS",
]

UIMAGE_MAGIC = 0x27051956
CHK_MAGIC = 0x2A23245E
TRX_MAGIC = b"HDR0"
PHD_MAGIC_BASIC = b"WithoutFreeSpace"
PHD_MAGIC_EXT = b"WithouFreSpacExt"
SERCOMM_MAGIC = b"sErCoMm"

SIGNATURES = [
    ("uimage", "U-Boot legacy uImage"),
    ("chk", "Netgear CHK"),
    ("trx", "TRX (Broadcom / OpenWrt)"),
    ("phd", "Parallels PHD"),
    ("sercomm", "Sercomm / Netgear 固件"),
    ("tplink", "TP-Link SafeLoader"),
    ("buffalo", "Buffalo DNI"),
    ("pmfx", "DiskGenius PMFX（无公开规范）"),
    ("ldbk", "雷电模拟器 LDBK（无公开规范）"),
    ("hdr1", "小米 HDR1（无公开规范）"),
]

FORMATS = [k for k, _ in SIGNATURES]

# uImage 枚举表（include/image.h）
UIMAGE_OS = {
    0: "invalid", 1: "openbsd", 2: "netbsd", 3: "freebsd", 4: "4_4bsd",
    5: "linux", 6: "svr4", 7: "esix", 8: "solaris", 9: "irix", 10: "sco",
    11: "dell", 12: "ncr", 13: "lynxos", 14: "vxworks", 15: "psos",
    16: "qnx", 17: "u-boot", 18: "rtems", 19: "artos", 20: "unity",
    21: "integrity", 22: "ose", 23: "plan9", 24: "openrtos", 25: "arm-trusted-firmware",
    26: "tee", 27: "opensbi", 28: "efi",
}
UIMAGE_ARCH = {
    0: "invalid", 1: "alpha", 2: "arm", 3: "x86", 4: "ia64", 5: "mips",
    6: "mips64", 7: "powerpc", 8: "ppc64", 9: "sh", 10: "sparc",
    11: "sparc64", 12: "m68k", 13: "nios", 14: "microblaze", 15: "nios2",
    16: "blackfin", 17: "avr32", 18: "st200", 19: "sandbox", 20: "nds32",
    21: "or1k", 22: "arm64", 23: "arc", 24: "x86_64", 25: "xtensa",
    26: "riscv", 27: "loongarch",
}
UIMAGE_TYPE = {
    0: "invalid", 1: "standalone", 2: "kernel", 3: "ramdisk",
    4: "multi", 5: "firmware", 6: "script", 7: "filesystem",
    8: "flat_dt", 9: "kwbimage", 10: "imximage", 11: "ubl",
    12: "omapimage", 13: "kernel_noload", 14: "pblimage",
    15: "vybridimage", 16: "kernel_secure",
}
UIMAGE_COMP = {
    0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4",
    6: "zstd",
}

CHK_REGION = {1: "WW", 2: "NA"}


def _u16be(b, o):
    return struct.unpack_from(">H", b, o)[0]


def _u32be(b, o):
    return struct.unpack_from(">I", b, o)[0]


def _u16le(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32le(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _cstr(raw):
    if not raw:
        return ""
    raw = raw.split(b"\x00")[0]
    return raw.decode("utf-8", "replace").strip()


def _crc32(data, init=0):
    """标准 CRC32（zlib 多项式，DDF/TRX/uImage 都按这个算）"""
    import zlib
    v = zlib.crc32(bytes(data)) & 0xFFFFFFFF
    return v


class Container(object):
    """把一个载荷区间包成 read(offset,size)+size 的设备对象"""

    def __init__(self, sub, offset, size, label="payload"):
        self.sub = sub
        self.offset = int(offset)
        self.size = max(0, int(size))
        self.label = label

    def read(self, off, n):
        if off >= self.size or n <= 0:
            return b""
        n = min(n, self.size - off)
        return self.sub.read(self.offset + off, n)

    def __repr__(self):
        return "<Container %s @0x%X +0x%X>" % (self.label, self.offset, self.size)


# ------------------------------------------------------------
# 1) U-Boot uImage
# ------------------------------------------------------------
def _parse_uimage(sub):
    head = sub.read(0, 64)
    if len(head) < 64 or _u32be(head, 0) != UIMAGE_MAGIC:
        return None
    ih_hcrc = _u32be(head, 0x04)
    ih_time = _u32be(head, 0x08)
    ih_size = _u32be(head, 0x0C)
    ih_load = _u32be(head, 0x10)
    ih_ep = _u32be(head, 0x14)
    ih_dcrc = _u32be(head, 0x18)
    ih_os = head[0x1C]
    ih_arch = head[0x1D]
    ih_type = head[0x1E]
    ih_comp = head[0x1F]
    ih_name = _cstr(head[0x20:0x40])

    # ih_hcrc：把该字段置 0 后对 64 字节头求 CRC32
    tmp = bytearray(head)
    tmp[0x04:0x08] = b"\x00\x00\x00\x00"
    hcrc_ok = (_crc32(tmp) == ih_hcrc)

    total = int(getattr(sub, "size", 0) or 0)
    avail = max(0, total - 64)
    payload_len = min(ih_size, avail) if ih_size else avail
    payload = sub.read(64, payload_len) if payload_len else b""
    dcrc_ok = None
    if payload and ih_size and len(payload) == ih_size:
        dcrc_ok = (_crc32(payload) == ih_dcrc)

    notes = []
    if not hcrc_ok:
        notes.append("ih_hcrc 校验不过（算得 0x%08X，存 0x%08X）"
                     % (_crc32(tmp), ih_hcrc))
    if dcrc_ok is False:
        notes.append("ih_dcrc 校验不过")
    if ih_size > avail:
        notes.append("ih_size=%d 超出镜像可用长度 %d，按可用长度截断"
                     % (ih_size, avail))

    decomp, decomp_note = None, None
    if payload:
        if ih_comp == 1:
            try:
                decomp = gzip.decompress(payload)
            except Exception as e:
                decomp_note = "gzip 解压失败：%s" % e
        elif ih_comp == 2:
            try:
                decomp = bz2.decompress(payload)
            except Exception as e:
                decomp_note = "bzip2 解压失败：%s" % e
        elif ih_comp == 3:
            try:
                decomp = lzma.decompress(payload)
            except Exception as e:
                decomp_note = "lzma 解压失败：%s" % e
        elif ih_comp in (4, 5, 6):
            decomp_note = ("ih_comp=%s 标准库没有该算法，未解压"
                           % UIMAGE_COMP.get(ih_comp, ih_comp))
    if decomp_note:
        notes.append(decomp_note)

    return {
        "format": "uimage",
        "spec_known": True,
        "header_size": 64,
        "magic": "0x%08X" % UIMAGE_MAGIC,
        "name": ih_name,
        "timestamp": ih_time,
        "data_size": ih_size,
        "load_addr": "0x%08X" % ih_load,
        "entry_point": "0x%08X" % ih_ep,
        "os": UIMAGE_OS.get(ih_os, str(ih_os)),
        "arch": UIMAGE_ARCH.get(ih_arch, str(ih_arch)),
        "image_type": UIMAGE_TYPE.get(ih_type, str(ih_type)),
        "compression": UIMAGE_COMP.get(ih_comp, str(ih_comp)),
        "header_crc_ok": hcrc_ok,
        "data_crc_ok": dcrc_ok,
        "decompressed_size": len(decomp) if decomp else None,
        "regions": [{"label": "payload", "offset": 64, "size": payload_len,
                     "note": "已按 ih_comp 解压" if decomp else "原始载荷"}],
        "notes": notes,
        "_decompressed": decomp,
    }


# ------------------------------------------------------------
# 2) Netgear CHK
# ------------------------------------------------------------
def _parse_chk(sub):
    head = sub.read(0, 40)
    if len(head) < 40 or _u32be(head, 0) != CHK_MAGIC:
        return None
    header_len = _u32be(head, 0x04)
    reserved = head[0x08:0x10]
    kernel_chksum = _u32be(head, 0x10)
    rootfs_chksum = _u32be(head, 0x14)
    kernel_len = _u32be(head, 0x18)
    rootfs_len = _u32be(head, 0x1C)
    image_chksum = _u32be(head, 0x20)
    header_chksum = _u32be(head, 0x24)

    total = int(getattr(sub, "size", 0) or 0)
    board_id = b""
    if header_len > 40 and header_len <= total:
        board_id = sub.read(40, header_len - 40)
    board_txt = _cstr(board_id)

    # header_chksum：把该字段置 0 后对 header_len 字节求 CRC32
    notes = []
    if 40 <= header_len <= total:
        hb = bytearray(sub.read(0, header_len))
        hb[0x24:0x28] = b"\x00\x00\x00\x00"
        if _crc32(hb) != header_chksum:
            notes.append("header_chksum 校验不过（算得 0x%08X，存 0x%08X）"
                         % (_crc32(hb), header_chksum))
    else:
        notes.append("header_len=%d 不合理（镜像总长 %d）" % (header_len, total))

    regions = []
    pos = header_len
    if kernel_len:
        take = min(kernel_len, max(0, total - pos))
        regions.append({"label": "kernel", "offset": pos, "size": take,
                        "note": "chksum 0x%08X" % kernel_chksum})
        pos += take
    if rootfs_len:
        take = min(rootfs_len, max(0, total - pos))
        regions.append({"label": "rootfs", "offset": pos, "size": take,
                        "note": "chksum 0x%08X" % rootfs_chksum})

    region_code = reserved[0]
    ver = ".".join(str(b) for b in reserved[1:8]) if any(reserved[1:8]) else None
    return {
        "format": "chk",
        "spec_known": True,
        "header_size": header_len,
        "magic": "0x%08X" % CHK_MAGIC,
        "board_id": board_txt,
        "region": CHK_REGION.get(region_code, "0x%02X" % region_code),
        "fw_version": ver,
        "kernel_len": kernel_len,
        "rootfs_len": rootfs_len,
        "image_chksum": "0x%08X" % image_chksum,
        "header_chksum": "0x%08X" % header_chksum,
        "regions": regions,
        "notes": notes,
    }


# ------------------------------------------------------------
# 3) TRX
# ------------------------------------------------------------
def _parse_trx(sub):
    head = sub.read(0, 28)
    if len(head) < 28 or head[:4] != TRX_MAGIC:
        return None
    length = _u32le(head, 0x04)
    crc = _u32le(head, 0x08)
    flags_ver = _u32le(head, 0x0C)
    offs = [_u32le(head, 0x10 + 4 * i) for i in range(3)]

    total = int(getattr(sub, "size", 0) or 0)
    notes = []
    span = min(length, total) if length else total
    if length and length > total:
        notes.append("len=%d 超出镜像长度 %d" % (length, total))
    # CRC：把 crc 字段置 0 后对 span 求 CRC32
    if 28 <= span <= total:
        buf = bytearray(sub.read(0, span))
        buf[0x08:0x0C] = b"\x00\x00\x00\x00"
        if _crc32(buf) != crc:
            notes.append("crc32 校验不过（算得 0x%08X，存 0x%08X）"
                         % (_crc32(buf), crc))

    labels = ["loader", "kernel", "rootfs"]
    regions = []
    bounds = sorted(set([0] + [o for o in offs if 0 < o < span] + [span]))
    for i, st in enumerate(bounds[:-1]):
        en = bounds[i + 1]
        if en <= st:
            continue
        # 该段对应第一个 <= st 的 offsets 下标
        idx = max([j for j, o in enumerate(offs) if o <= st] or [0])
        regions.append({"label": labels[min(idx, 2)], "offset": st,
                        "size": en - st, "note": "TRX 分段"})

    return {
        "format": "trx",
        "spec_known": True,
        "header_size": 28,
        "magic": "HDR0",
        "length": length,
        "crc32": "0x%08X" % crc,
        "flag": (flags_ver >> 16) & 0xFFFF,
        "version": flags_ver & 0xFFFF,
        "offsets": offs,
        "regions": regions,
        "notes": notes,
    }


# ------------------------------------------------------------
# 4) Parallels PHD
# ------------------------------------------------------------
def _parse_phd(sub):
    head = sub.read(0, 64)
    if len(head) < 56:
        return None
    if head[:16] == PHD_MAGIC_BASIC:
        magic = PHD_MAGIC_BASIC
        ext = False
    elif head[:16] == PHD_MAGIC_EXT:
        magic = PHD_MAGIC_EXT
        ext = True
    else:
        return None

    version = _u32le(head, 0x10)
    heads = _u32le(head, 0x14)
    cylinders = _u32le(head, 0x18)
    tracks = _u32le(head, 0x1C)
    catalog_entries = _u32le(head, 0x20)
    nb_sectors = _u32le(head, 0x24)
    inuse = _u32le(head, 0x28)
    data_off = _u32le(head, 0x2C)
    flags = _u32le(head, 0x30)
    ext_off = _u32le(head, 0x34) if ext and len(head) >= 0x38 else None

    total = int(getattr(sub, "size", 0) or 0)
    notes = []
    bat = []
    # BAT 紧跟 ParallelsHeader：BASIC 56 字节 / EXT 60 字节（QEMU sizeof）
    bat_off = 60 if ext else 56
    if catalog_entries and catalog_entries <= (1 << 24):
        raw = sub.read(bat_off, catalog_entries * 4)
        for i in range(len(raw) // 4):
            bat.append(_u32le(raw, i * 4))
    else:
        notes.append("catalog_entries=%d 不合理，BAT 未读" % catalog_entries)

    used = sum(1 for v in bat if not (v & 0x80000000))
    if not nb_sectors:
        nb_sectors = used
        notes.append("nb_sectors 为 0，按已分配的 BAT 项数 %d 推断" % used)

    logical = max(0, nb_sectors) * 512
    return {
        "format": "phd",
        "spec_known": True,
        "header_size": 60 if ext else 56,
        "magic": magic.decode(),
        "version": version,
        "heads": heads,
        "cylinders": cylinders,
        "tracks": tracks,
        "catalog_entries": catalog_entries,
        "nb_sectors": nb_sectors,
        "inuse_bat": used,
        "data_offset": data_off,
        "flags": "0x%08X" % flags,
        "ext_offset": ext_off,
        "logical_size": logical,
        "regions": [{"label": "disk", "offset": 0, "size": logical,
                     "note": "按 BAT 稀疏读（未分配块为零）"}],
        "notes": notes,
        "_bat": bat,
        "_data_off": data_off,
        "_total": total,
    }


class PhdDevice(object):
    """按 PHD 的 BAT 做稀疏读；未分配扇区返回零"""

    def __init__(self, sub, bat, data_off, logical_size):
        self.sub = sub
        self.bat = bat
        self.data_off = data_off
        self.size = logical_size

    def read(self, off, n):
        if off >= self.size or n <= 0:
            return b""
        n = min(n, self.size - off)
        out = bytearray()
        pos = off
        end = off + n
        while pos < end:
            idx = pos // 512
            inner = pos % 512
            take = min(512 - inner, end - pos)
            if idx >= len(self.bat):
                out += b"\x00" * take
            else:
                v = self.bat[idx]
                if v & 0x80000000:
                    out += b"\x00" * take
                else:
                    base = self.data_off + (v & 0x7FFFFFFF) * 512 + inner
                    d = self.sub.read(base, take)
                    out += d + b"\x00" * (take - len(d))
            pos += take
        return bytes(out)


# ------------------------------------------------------------
# 5) Sercomm / Netgear
# ------------------------------------------------------------
def _parse_sercomm(sub):
    head = sub.read(0, 512)
    if len(head) < 512:
        return None
    if head[0:7] != SERCOMM_MAGIC or head[63:70] != SERCOMM_MAGIC:
        return None
    version = head[7:11].hex()
    checksum = head[511]
    total = int(getattr(sub, "size", 0) or 0)

    notes = []
    # 校验和：把偏移 511 当 0x00 算全镜像校验和再取反，应与存储值一致
    calc = None
    if total and total <= (64 << 20):
        buf = bytearray(sub.read(0, total))
        buf[511] = 0x00
        calc = (~sum(buf)) & 0xFF
        if calc != checksum:
            notes.append("偏移 511 校验和不过（算得 0x%02X，存 0x%02X）"
                         % (calc, checksum))
    else:
        notes.append("镜像过大（%d 字节），跳过整体校验和验证" % total)

    body = max(0, total - 512)
    return {
        "format": "sercomm",
        "spec_known": True,
        "header_size": 512,
        "magic": SERCOMM_MAGIC.decode(),
        "magic_repeat_at": [0, 63],
        "version": version,
        "stored_checksum": "0x%02X" % checksum,
        "computed_checksum": None if calc is None else "0x%02X" % calc,
        "regions": [{"label": "firmware", "offset": 512, "size": body,
                     "note": "头部之后的固件体"}],
        "notes": notes,
    }


# ------------------------------------------------------------
# 6) TP-Link SafeLoader
# ------------------------------------------------------------
def _parse_tplink(sub):
    head = sub.read(0, 512)
    if len(head) < 512:
        return None
    if head[0x90] != 0xA5:
        return None
    if _u16le(head, 0x8C) != 0x55AA:
        return None

    version = _u32le(head, 0x00)
    fw_version = _cstr(head[0x04:0x34])
    hw_id = _u32le(head, 0x34)
    hw_rev = _u32le(head, 0x38)
    hw_ver_add = _u32le(head, 0x3C)
    md5sum1 = head[0x40:0x50].hex()
    md5sum2 = head[0x54:0x64].hex()
    kernel_la = _u32le(head, 0x68)
    kernel_ep = _u32le(head, 0x6C)
    fw_length = _u32le(head, 0x70)
    kernel_ofs = _u32le(head, 0x74)
    kernel_len = _u32le(head, 0x78)
    rootfs_ofs = _u32le(head, 0x7C)
    rootfs_len = _u32le(head, 0x80)
    boot_ofs = _u32le(head, 0x84)
    boot_len = _u32le(head, 0x88)
    sver = (head[0x8E], head[0x8F])
    ver = (head[0x91], head[0x92], head[0x93])

    total = int(getattr(sub, "size", 0) or 0)
    notes = []
    if md5sum1 and md5sum1 != "00" * 16:
        notes.append("md5sum1 已给出（未与之比对：需要知道覆盖范围）")

    regions = []
    for label, ofs, ln in (("boot", boot_ofs, boot_len),
                           ("kernel", kernel_ofs, kernel_len),
                           ("rootfs", rootfs_ofs, rootfs_len)):
        if ofs and ln and ofs < total:
            take = min(ln, total - ofs)
            regions.append({"label": label, "offset": ofs, "size": take,
                            "note": "头部字段给定"})
            if take < ln:
                notes.append("%s 声明 %d 字节，实际只有 %d" % (label, ln, take))

    return {
        "format": "tplink",
        "spec_known": True,
        "header_size": 512,
        "version": version,
        "fw_version": fw_version,
        "hw_id": "0x%08X" % hw_id,
        "hw_rev": "0x%08X" % hw_rev,
        "hw_ver_add": "0x%08X" % hw_ver_add,
        "md5sum1": md5sum1,
        "md5sum2": md5sum2,
        "kernel_load_addr": "0x%08X" % kernel_la,
        "kernel_entry": "0x%08X" % kernel_ep,
        "fw_length": fw_length,
        "software_version": "%d.%d" % sver,
        "firmware_version_bytes": "%d.%d.%d" % ver,
        "magic_a5": True,
        "magic_55aa": True,
        "regions": regions,
        "notes": notes,
    }


# ------------------------------------------------------------
# 7) Buffalo DNI
# ------------------------------------------------------------
def _parse_buffalo(sub):
    head = sub.read(0, 128)
    if len(head) < 128 or not head.startswith(b"device:"):
        return None
    txt = head.rstrip(b"\x00").decode("utf-8", "replace")
    fields = {}
    for line in txt.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip()] = v.strip()
    if "InfoHeadSize" not in fields and "RootfsSize" not in fields:
        return None

    def as_int(name, default=0):
        try:
            return int(fields.get(name, default))
        except Exception:
            return default

    info_hdr = as_int("InfoHeadSize", 128)
    rootfs_size = as_int("RootfsSize")
    kernel_size = as_int("KernelSize")
    total = int(getattr(sub, "size", 0) or 0)

    notes = []
    if info_hdr != 128:
        notes.append("InfoHeadSize=%d 与规范里的 128 不同" % info_hdr)
    regions = []
    pos = info_hdr
    if kernel_size:
        take = min(kernel_size, max(0, total - pos))
        regions.append({"label": "kernel", "offset": pos, "size": take,
                        "note": "KernelSize"})
        pos += take
    if rootfs_size:
        take = min(rootfs_size, max(0, total - pos))
        regions.append({"label": "rootfs", "offset": pos, "size": take,
                        "note": "RootfsSize"})

    return {
        "format": "buffalo",
        "spec_known": True,
        "header_size": info_hdr,
        "device": fields.get("device"),
        "version": fields.get("version"),
        "region": fields.get("region"),
        "rootfs_size": rootfs_size,
        "kernel_size": kernel_size,
        "info_head_size": info_hdr,
        "raw_fields": fields,
        "regions": regions,
        "notes": notes,
    }


# ------------------------------------------------------------
# 无公开规范的三种：只识别，不解析
# ------------------------------------------------------------
_NO_SPEC_NOTE = ("没有查到该格式的公开头部规范，本模块只做识别与提示，"
                 "不解析任何字段、不切分载荷——不猜。")


def _parse_unknown_but_known_name(fmt, label):
    return {
        "format": fmt,
        "spec_known": False,
        "header_size": None,
        "regions": [],
        "notes": [_NO_SPEC_NOTE],
        "format_label": label,
    }


def _looks_like_pmfx(sub):
    """PMFX 无公开规范：只在文件很小且头部出现 PMFX 字样时给「疑似」"""
    head = sub.read(0, 64)
    return b"PMFX" in head or head.startswith(b"DiskGenius")


def _looks_like_ldbk(sub):
    head = sub.read(0, 64)
    return head.startswith(b"LDBK") or b"LDBK" in head


def _looks_like_hdr1(sub):
    head = sub.read(0, 64)
    return head.startswith(b"HDR1") or b"HDR1" in head


# ------------------------------------------------------------
# 对外
# ------------------------------------------------------------
def _probe(sub):
    """返回 (format, parsed_dict 或 None)"""
    for name, fn in (("uimage", _parse_uimage), ("chk", _parse_chk),
                     ("trx", _parse_trx), ("phd", _parse_phd),
                     ("sercomm", _parse_sercomm), ("tplink", _parse_tplink),
                     ("buffalo", _parse_buffalo)):
        try:
            r = fn(sub)
        except Exception:
            r = None
        if r is not None:
            return name, r
    # 无公开规范的三种，只认特征
    try:
        if _looks_like_pmfx(sub):
            return "pmfx", _parse_unknown_but_known_name("pmfx", "DiskGenius PMFX")
        if _looks_like_ldbk(sub):
            return "ldbk", _parse_unknown_but_known_name("ldbk", "雷电模拟器 LDBK")
        if _looks_like_hdr1(sub):
            return "hdr1", _parse_unknown_but_known_name("hdr1", "小米 HDR1")
    except Exception:
        pass
    return "unknown", None


def detect(sub):
    name, _ = _probe(sub)
    return name


def probe_signatures(sub):
    """所有格式各试一遍，返回命中的格式名列表（正常只会有一个）"""
    hits = []
    for name, fn in (("uimage", _parse_uimage), ("chk", _parse_chk),
                     ("trx", _parse_trx), ("phd", _parse_phd),
                     ("sercomm", _parse_sercomm), ("tplink", _parse_tplink),
                     ("buffalo", _parse_buffalo)):
        try:
            if fn(sub) is not None:
                hits.append(name)
        except Exception:
            continue
    return hits


def describe(sub):
    name, info = _probe(sub)
    if info is None:
        return {"format": "unknown", "spec_known": False, "regions": [],
                "notes": ["未命中任何已知容器特征"]}
    out = dict(info)
    out.pop("_decompressed", None)
    out.pop("_bat", None)
    out.pop("_data_off", None)
    out.pop("_total", None)
    return out


def extract(sub, out_dir=None):
    """按 describe() 里的 regions 抽出载荷

    只导出能确定边界的段；无公开规范的格式返回 []。
    """
    name, info = _probe(sub)
    if info is None:
        return []
    regions = info.get("regions") or []
    result = []
    total = int(getattr(sub, "size", 0) or 0)

    # uImage 若已解压，优先给解压后的内容
    decomp = info.get("_decompressed")
    if decomp is not None:
        result.append({"label": "payload.decompressed", "offset": 64,
                       "size": len(decomp), "data": decomp,
                       "note": "已按 ih_comp 解压"})
    for r in regions:
        off = r.get("offset") or 0
        ln = r.get("size") or 0
        if ln <= 0 or off >= total:
            continue
        data = sub.read(off, ln)
        item = {"label": r.get("label"), "offset": off, "size": len(data),
                "data": data, "note": r.get("note")}
        result.append(item)

    if out_dir:
        import os
        os.makedirs(out_dir, exist_ok=True)
        for item in result:
            safe = "".join(c if c.isalnum() or c in "._-" else "_"
                           for c in str(item["label"] or "seg"))
            path = os.path.join(out_dir, "%s_%s.bin" % (name, safe))
            with open(path, "wb") as f:
                f.write(item["data"])
            item["path"] = path
    return result


def load(sub, label=None):
    """按 describe() 的 regions 取一个可读设备对象

    label 为空时取第一个非零长度的段。
    """
    name, info = _probe(sub)
    if info is None:
        return None
    if name == "phd":
        return PhdDevice(sub, info.get("_bat") or [],
                         info.get("_data_off") or 0,
                         info.get("logical_size") or 0)
    regions = info.get("regions") or []
    if not regions:
        return None
    pick = None
    if label:
        for r in regions:
            if r.get("label") == label:
                pick = r
                break
    if pick is None:
        for r in regions:
            if (r.get("size") or 0) > 0:
                pick = r
                break
    if pick is None:
        return None
    return Container(sub, pick["offset"], pick["size"], pick.get("label") or "payload")


# ------------------------------------------------------------
# 自检
# ------------------------------------------------------------
if __name__ == "__main__":
    import io
    import sys
    import zlib

    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    PASS = [0]
    FAIL = [0]

    def ck(cond, name, extra=""):
        if cond:
            PASS[0] += 1
            print("  [PASS] %s %s" % (name, extra))
        else:
            FAIL[0] += 1
            print("  [FAIL] %s %s" % (name, extra))

    class MemSub(object):
        def __init__(self, data):
            self.data = bytes(data)
            self.size = len(self.data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    def crc32(data):
        return zlib.crc32(bytes(data)) & 0xFFFFFFFF

    # ---------- uImage ----------
    def build_uimage(payload, comp=0, name="ESK Test Image",
                     os_id=5, arch=2, itype=2, bad_crc=False):
        body = bytearray(payload)
        h = bytearray(64)
        struct.pack_into(">I", h, 0x00, UIMAGE_MAGIC)
        struct.pack_into(">I", h, 0x08, 0x60000000)      # ih_time
        struct.pack_into(">I", h, 0x0C, len(body))       # ih_size
        struct.pack_into(">I", h, 0x10, 0x80008000)      # ih_load
        struct.pack_into(">I", h, 0x14, 0x80008000)      # ih_ep
        struct.pack_into(">I", h, 0x18, crc32(body))     # ih_dcrc
        h[0x1C] = os_id
        h[0x1D] = arch
        h[0x1E] = itype
        h[0x1F] = comp
        h[0x20:0x20 + len(name)] = name.encode()[:32]
        struct.pack_into(">I", h, 0x04, 0)               # 先清零再算
        hc = crc32(h)
        if bad_crc:
            hc = (hc + 1) & 0xFFFFFFFF
        struct.pack_into(">I", h, 0x04, hc)
        return bytes(h) + bytes(body)

    print("=== 1) U-Boot uImage ===")
    raw = b"KERNEL-DATA-" * 100
    img = build_uimage(raw, comp=0)
    sub = MemSub(img)
    ck(detect(sub) == "uimage", "detect 命中 uimage", detect(sub))
    d = describe(sub)
    ck(d["header_crc_ok"] is True, "ih_hcrc 校验通过")
    ck(d["data_crc_ok"] is True, "ih_dcrc 校验通过")
    ck(d["name"] == "ESK Test Image", "镜像名", d["name"])
    ck(d["os"] == "linux", "ih_os -> linux", d["os"])
    ck(d["arch"] == "arm", "ih_arch -> arm", d["arch"])
    ck(d["image_type"] == "kernel", "ih_type -> kernel", d["image_type"])
    ck(d["compression"] == "none", "ih_comp -> none", d["compression"])
    ck(d["data_size"] == len(raw), "ih_size", d["data_size"])
    ck(d["load_addr"] == "0x80008000", "load 地址", d["load_addr"])
    c = load(sub)
    ck(c is not None and c.read(0, len(raw)) == raw, "载荷逐字节一致")

    gz = build_uimage(gzip.compress(raw), comp=1, name="gz test")
    dg = describe(MemSub(gz))
    ck(dg["compression"] == "gzip", "gzip 头识别")
    ck(dg["decompressed_size"] == len(raw), "gzip 解压后长度",
       dg["decompressed_size"])
    ex = extract(MemSub(gz))
    ck(any(e["label"] == "payload.decompressed" and e["data"] == raw
           for e in ex), "extract 给出解压后载荷")

    bz = build_uimage(bz2.compress(raw), comp=2, name="bz test")
    ck(describe(MemSub(bz))["decompressed_size"] == len(raw), "bzip2 解压后长度")

    bad = build_uimage(raw, comp=0, bad_crc=True)
    db = describe(MemSub(bad))
    ck(db["header_crc_ok"] is False, "坏 ih_hcrc 被如实报告")
    ck(any("ih_hcrc" in n for n in db["notes"]), "坏 CRC 有 note")

    print()
    print("=== 2) Netgear CHK ===")
    def build_chk(kernel, rootfs, board="EX3700", region=1, ver=(1, 0, 0, 58, 1, 0, 38)):
        bid = board.encode()
        hlen = 40 + len(bid)
        h = bytearray(40)
        struct.pack_into(">I", h, 0x00, CHK_MAGIC)
        struct.pack_into(">I", h, 0x04, hlen)
        h[0x08] = region
        for i, v in enumerate(ver[:7]):
            h[0x09 + i] = v
        struct.pack_into(">I", h, 0x10, crc32(kernel))
        struct.pack_into(">I", h, 0x14, crc32(rootfs))
        struct.pack_into(">I", h, 0x18, len(kernel))
        struct.pack_into(">I", h, 0x1C, len(rootfs))
        body = bytes(kernel) + bytes(rootfs)
        struct.pack_into(">I", h, 0x20, crc32(body))
        struct.pack_into(">I", h, 0x24, 0)
        full = bytearray(h + bid)
        struct.pack_into(">I", full, 0x24, crc32(full))
        return bytes(full) + body

    kern, root = b"K" * 500, b"R" * 700
    chk = build_chk(kern, root)
    sub = MemSub(chk)
    ck(detect(sub) == "chk", "detect 命中 chk", detect(sub))
    d = describe(sub)
    ck(d["board_id"] == "EX3700", "board_id", d["board_id"])
    ck(d["region"] == "WW", "reserved[0]=1 -> WW", d["region"])
    ck(d["kernel_len"] == 500 and d["rootfs_len"] == 700, "kernel/rootfs 长度",
       "%d/%d" % (d["kernel_len"], d["rootfs_len"]))
    ck(d["fw_version"] == "1.0.0.58.1.0.38", "版本 A–G", d["fw_version"])
    ck(not d["notes"], "校验和全过（无 note）", d["notes"])
    ks = load(sub, "kernel")
    rs = load(sub, "rootfs")
    ck(ks.read(0, 500) == kern, "kernel 段内容一致")
    ck(rs.read(0, 700) == root, "rootfs 段内容一致")

    print()
    print("=== 3) TRX ===")
    def build_trx(loader, kernel, rootfs):
        offs = [28, 28 + len(loader), 28 + len(loader) + len(kernel)]
        total = offs[2] + len(rootfs)
        h = bytearray(28)
        h[0:4] = TRX_MAGIC
        struct.pack_into("<I", h, 0x04, total)
        struct.pack_into("<I", h, 0x08, 0)
        struct.pack_into("<I", h, 0x0C, (1 << 16) | 2)      # flag=1 ver=2
        for i, o in enumerate(offs):
            struct.pack_into("<I", h, 0x10 + 4 * i, o)
        body = bytes(loader) + bytes(kernel) + bytes(rootfs)
        full = bytearray(bytes(h) + body)
        struct.pack_into("<I", full, 0x08, crc32(full))
        return bytes(full)

    trx = build_trx(b"L" * 10, b"K" * 200, b"R" * 300)
    sub = MemSub(trx)
    ck(detect(sub) == "trx", "detect 命中 trx", detect(sub))
    d = describe(sub)
    ck(d["flag"] == 1 and d["version"] == 2, "flag/version",
       "%d/%d" % (d["flag"], d["version"]))
    ck(d["length"] == len(trx), "len 字段", d["length"])
    ck(not d["notes"], "TRX CRC 通过", d["notes"])
    ck(load(sub, "kernel").read(0, 200) == b"K" * 200, "kernel 段内容一致")
    ck(load(sub, "rootfs").read(0, 300) == b"R" * 300, "rootfs 段内容一致")

    print()
    print("=== 4) Parallels PHD（BAT 稀疏读）===")
    def build_phd(blocks, ext=False, version=2):
        magic = PHD_MAGIC_EXT if ext else PHD_MAGIC_BASIC
        hsize = 60 if ext else 56
        n = len(blocks)
        h = bytearray(hsize)
        h[0:16] = magic
        struct.pack_into("<I", h, 0x10, version)
        struct.pack_into("<I", h, 0x14, 16)          # heads
        struct.pack_into("<I", h, 0x18, 4)           # cylinders
        struct.pack_into("<I", h, 0x1C, 63)          # tracks
        struct.pack_into("<I", h, 0x20, n)           # catalog_entries
        struct.pack_into("<I", h, 0x24, n)           # nb_sectors
        struct.pack_into("<I", h, 0x28, 0)           # inuse
        struct.pack_into("<I", h, 0x2C, hsize + n * 4)  # data_off
        struct.pack_into("<I", h, 0x30, 0)           # flags
        if ext:
            struct.pack_into("<I", h, 0x34, 0)
        # BAT 是「逻辑扇区 -> 物理扇区」映射；物理扇区按实际写入顺序紧凑分配，
        # 因此遇到空洞时后面的块会前移，不能用逻辑号直接当物理号。
        bat = bytearray(len(blocks) * 4)
        phys = 0
        for i, b in enumerate(blocks):
            if b is None:
                struct.pack_into("<I", bat, i * 4, 0x80000000)
            else:
                struct.pack_into("<I", bat, i * 4, phys)
                phys += 1
        data = bytearray()
        for b in blocks:
            if b is not None:
                data += b
        return bytes(h) + bytes(bat) + bytes(data)

    blk0 = b"A" * 512
    blk2 = b"C" * 512
    phd = build_phd([blk0, None, blk2])
    sub = MemSub(phd)
    ck(detect(sub) == "phd", "detect 命中 phd", detect(sub))
    d = describe(sub)
    ck(d["magic"] == "WithoutFreeSpace", "magic（基础版）", d["magic"])
    ck(d["catalog_entries"] == 3, "catalog_entries", d["catalog_entries"])
    ck(d["inuse_bat"] == 2, "已分配 BAT 项 2 个", d["inuse_bat"])
    ck(d["nb_sectors"] == 3, "nb_sectors", d["nb_sectors"])
    dev = load(sub)
    ck(dev.size == 3 * 512, "逻辑容量 3 扇区", dev.size)
    ck(dev.read(0, 512) == blk0, "第 0 扇区内容")
    ck(dev.read(512, 512) == b"\x00" * 512, "第 1 扇区未分配 -> 全零")
    ck(dev.read(1024, 512) == blk2, "第 2 扇区内容")
    ck(dev.read(500, 20) == b"A" * 12 + b"\x00" * 8, "跨扇区边界读取")
    phd_ext = build_phd([blk0, None], ext=True)
    ck(describe(MemSub(phd_ext))["magic"] == "WithouFreSpacExt",
       "magic（扩展版）")

    print()
    print("=== 5) Sercomm ===")
    def build_sercomm(body, version=b"\x00\x01\x00\x00"):
        h = bytearray(512)
        h[0:7] = SERCOMM_MAGIC
        h[7:11] = version
        h[63:70] = SERCOMM_MAGIC
        h[511] = 0x00
        return bytes(h) + bytes(body)

    sc = bytearray(build_sercomm(b"S" * 1000))
    sc[511] = (~sum(sc)) & 0xFF
    sub = MemSub(bytes(sc))
    ck(detect(sub) == "sercomm", "detect 命中 sercomm", detect(sub))
    d = describe(sub)
    ck(d["magic_repeat_at"] == [0, 63], "魔数出现在 0 与 63", d["magic_repeat_at"])
    ck(d["version"] == "00010000", "version 字节", d["version"])
    ck(d["computed_checksum"] == d["stored_checksum"], "偏移 511 校验和一致",
       d["stored_checksum"])
    ck(load(sub).read(0, 1000) == b"S" * 1000, "固件体内容一致")

    print()
    print("=== 6) TP-Link SafeLoader ===")
    def build_tplink(kernel, rootfs, hw_id=0x03600000, fwver="3.16.9"):
        h = bytearray(512)
        struct.pack_into("<I", h, 0x00, 1)                    # version
        h[0x04:0x04 + len(fwver)] = fwver.encode()
        struct.pack_into("<I", h, 0x34, hw_id)
        struct.pack_into("<I", h, 0x38, 0)
        struct.pack_into("<I", h, 0x3C, 0)
        h[0x40:0x50] = bytes(range(16))                       # md5sum1
        h[0x54:0x64] = bytes(range(16, 32))                   # md5sum2
        struct.pack_into("<I", h, 0x68, 0x80060000)           # kernel_la
        struct.pack_into("<I", h, 0x6C, 0x80060000)           # kernel_ep
        k_ofs = 512
        r_ofs = 512 + len(kernel)
        struct.pack_into("<I", h, 0x70, r_ofs + len(rootfs))  # fw_length
        struct.pack_into("<I", h, 0x74, k_ofs)
        struct.pack_into("<I", h, 0x78, len(kernel))
        struct.pack_into("<I", h, 0x7C, r_ofs)
        struct.pack_into("<I", h, 0x80, len(rootfs))
        struct.pack_into("<H", h, 0x8C, 0x55AA)
        h[0x8E] = 3
        h[0x8F] = 16
        h[0x90] = 0xA5
        h[0x91], h[0x92], h[0x93] = 3, 16, 9
        return bytes(h) + bytes(kernel) + bytes(rootfs)

    tp = build_tplink(b"K" * 400, b"R" * 600)
    sub = MemSub(tp)
    ck(detect(sub) == "tplink", "detect 命中 tplink", detect(sub))
    d = describe(sub)
    ck(d["fw_version"] == "3.16.9", "fw_version", d["fw_version"])
    ck(d["hw_id"] == "0x03600000", "hw_id", d["hw_id"])
    ck(d["magic_a5"] and d["magic_55aa"], "0xA5 与 0x55AA 双重确认")
    ck(d["software_version"] == "3.16", "software_version", d["software_version"])
    ck(load(sub, "kernel").read(0, 400) == b"K" * 400, "kernel 段内容一致")
    ck(load(sub, "rootfs").read(0, 600) == b"R" * 600, "rootfs 段内容一致")

    print()
    print("=== 7) Buffalo DNI ===")
    def build_buffalo(kernel, rootfs, board="WZR-HP-AG300H",
                      version="1.85", region="JP"):
        hdr = ("device:%s\nversion:%s\nregion:%s\nRootfsSize:%d\n"
               "KernelSize:%d\nInfoHeadSize:128\n"
               % (board, version, region, len(rootfs), len(kernel))).encode()
        h = bytearray(128)
        h[0:len(hdr)] = hdr
        return bytes(h) + bytes(kernel) + bytes(rootfs)

    bf = build_buffalo(b"K" * 300, b"R" * 500)
    sub = MemSub(bf)
    ck(detect(sub) == "buffalo", "detect 命中 buffalo", detect(sub))
    d = describe(sub)
    ck(d["device"] == "WZR-HP-AG300H", "device", d["device"])
    ck(d["version"] == "1.85", "version", d["version"])
    ck(d["region"] == "JP", "region", d["region"])
    ck(d["kernel_size"] == 300 and d["rootfs_size"] == 500,
       "KernelSize/RootfsSize", "%d/%d" % (d["kernel_size"], d["rootfs_size"]))
    ck(load(sub, "kernel").read(0, 300) == b"K" * 300, "kernel 段内容一致")
    ck(load(sub, "rootfs").read(0, 500) == b"R" * 500, "rootfs 段内容一致")

    print()
    print("=== 8) 无公开规范的三种：只识别不解析 ===")
    for fmt, blob, checker in (
            ("pmfx", b"PMFX" + b"\x00" * 60, _looks_like_pmfx),
            ("ldbk", b"LDBK" + b"\x00" * 60, _looks_like_ldbk),
            ("hdr1", b"HDR1" + b"\x00" * 60, _looks_like_hdr1),
    ):
        s = MemSub(blob)
        ck(checker(s), "%s 特征命中" % fmt)
        dd = describe(s)
        ck(dd.get("spec_known") is False,
           "%s spec_known=False" % fmt, dd.get("spec_known"))
        ck(dd.get("regions") == [], "%s 不给载荷段（不猜）" % fmt)
        ck(any("没有查到" in n for n in dd.get("notes") or []),
           "%s notes 写明没有公开规范" % fmt)

    print()
    print("=== 9) 未命中与容错 ===")
    ck(detect(MemSub(bytes(4096))) == "unknown", "全零 -> unknown")
    ck(describe(MemSub(bytes(4096)))["format"] == "unknown", "describe -> unknown")
    ck(extract(MemSub(bytes(4096))) == [], "unknown 的 extract 返回空")
    ck(load(MemSub(bytes(4096))) is None, "unknown 的 load 返回 None")
    ck(detect(MemSub(b"")) == "unknown", "零长 -> unknown")
    ck(probe_signatures(MemSub(img)) == ["uimage"], "probe_signatures 只命中 uimage",
       probe_signatures(MemSub(img)))
    # 截断的 uImage 头
    ck(detect(MemSub(img[:30])) == "unknown", "截断的 uImage 头不误判")
    # 只有单个 sErCoMm（缺 63 处那个）不该命中
    half = bytearray(512)
    half[0:7] = SERCOMM_MAGIC
    ck(detect(MemSub(bytes(half))) == "unknown", "只出现一次 sErCoMm 不命中")

    print()
    print("=== 10) 多格式互不误判 ===")
    cases = [(img, "uimage"), (chk, "chk"), (trx, "trx"), (phd, "phd"),
             (bytes(sc), "sercomm"), (tp, "tplink"), (bf, "buffalo")]
    ok = True
    detail = []
    for blob, want in cases:
        s = MemSub(blob)
        hits = probe_signatures(s)
        if hits != [want]:
            ok = False
            detail.append((want, hits))
    ck(ok, "七种格式各自的签名不串味", detail if not ok else "")

    print()
    print("=" * 62)
    print("uImage（含 gzip/bzip2 解压与 CRC）/ CHK / TRX / PHD（BAT 稀疏读）/")
    print("Sercomm（512 校验和）/ TP-Link SafeLoader（双 magic 确认）/ Buffalo DNI /")
    print("PMFX·LDBK·HDR1（只识别，spec_known=False）")
    print("通过 %d 项，失败 %d 项" % (PASS[0], FAIL[0]))
    if FAIL[0]:
        raise SystemExit(1)
    print("containers 模块自检全部通过")
