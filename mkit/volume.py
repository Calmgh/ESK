# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""分区表解析：MBR(含扩展分区链) / GPT(含备份表校验)。"""
import struct

from .image import SubImage

FS_TYPES = {
    0x01: "FAT12", 0x04: "FAT16<32M", 0x05: "Extended", 0x06: "FAT16",
    0x07: "NTFS/HPFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32(LBA)", 0x0E: "FAT16(LBA)",
    0x0F: "Extended(LBA)", 0x11: "Hidden FAT12", 0x12: "Hidden FAT16", 0x14: "Hidden FAT16(LBA)",
    0x17: "Hidden NTFS", 0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32(LBA)", 0x1E: "Hidden FAT16(LBA)",
    0x27: "WinRE(NTFS)", 0x42: "LVM2", 0x63: "UNIX SysV", 0x82: "Linux swap",
    0x83: "Linux", 0x85: "Linux Extended", 0x86: "NTFS volume set", 0x87: "NTFS volume set",
    0x8E: "Linux LVM", 0x93: "Linux/Ameba", 0xA5: "FreeBSD", 0xAB: "macOS boot",
    0xAF: "macOS HFS+", 0xEE: "GPT protective", 0xEF: "EFI System", 0xFD: "Linux RAID",
}


def parse(image):
    """返回 [dict(index, scheme, start, size, type_id, type_name, flags, extra)]"""
    head = image.read(0, 512)
    parts = []
    if len(head) < 512:
        return parts
    if head[510:512] != b"\x55\xaa":
        return parts
    if head[450:454] == b"EFI PART":
        return _gpt(image, head)
    return _mbr(image, head)


def _mbr(image, head):
    parts = []
    ext = None
    for i in range(4):
        e = head[446 + 16 * i: 446 + 16 * (i + 1)]
        ptype = e[4]
        lba, cnt = struct.unpack_from("<II", e, 8)
        if ptype == 0 or cnt == 0:
            continue
        parts.append(dict(index=len(parts), scheme="mbr", start=lba * 512, sectors=cnt,
                          size=cnt * 512, type_id=ptype,
                          type_name=FS_TYPES.get(ptype, f"0x{ptype:02x}"),
                          boot=bool(e[0] == 0x80), raw_offset=446 + 16 * i))
        if ptype in (0x05, 0x0F, 0x85):
            ext = lba
    if ext:
        cur = ext
        guard = 0
        while cur and guard < 64:
            guard += 1
            eb = image.read(cur * 512, 512)
            if len(eb) < 512 or eb[510:512] != b"\x55\xaa":
                break
            for i in range(4):
                e = eb[446 + 16 * i: 446 + 16 * (i + 1)]
                ptype = e[4]
                rlba, cnt = struct.unpack_from("<II", e, 8)
                if ptype == 0 or cnt == 0:
                    continue
                if ptype in (0x05, 0x0F, 0x85):
                    cur = ext + rlba
                    break
                start = (cur + rlba) * 512
                parts.append(dict(index=len(parts), scheme="mbr/logical", start=start,
                                  sectors=cnt, size=cnt * 512, type_id=ptype,
                                  type_name=FS_TYPES.get(ptype, f"0x{ptype:02x}"),
                                  boot=False, raw_offset=None))
            else:
                break
    return parts


def _guid(b):
    import uuid
    return str(uuid.UUID(bytes_le=bytes(b)))


def _gpt(image, mbr_head, sector=512):
    hdr = image.read(sector, sector)
    if hdr[:8] != b"EFI PART":
        return []
    hsize = struct.unpack_from("<I", hdr, 12)[0]
    entries_lba = struct.unpack_from("<Q", hdr, 72)[0]
    num = struct.unpack_from("<I", hdr, 80)[0]
    esize = struct.unpack_from("<I", hdr, 84)[0]
    ent = image.read(entries_lba * sector, min(num, 128) * esize)
    parts = []
    for i in range(min(num, 128)):
        e = ent[i * esize: (i + 1) * esize]
        if len(e) < 128:
            break
        if e[:16] == b"\x00" * 16:
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        parts.append(dict(index=len(parts), scheme="gpt", start=first * sector,
                          sectors=(last - first + 1), size=(last - first + 1) * sector,
                          type_id=_guid(e[:16]), type_name=_guid(e[:16]),
                          name=e[56:128].decode("utf-16le", "replace").rstrip("\x00"),
                          boot=False, raw_offset=None))
    return parts


def sub(image, part):
    return SubImage(image, part["start"], part["size"])


def guess_filesystem(image, offset, size):
    """按签名猜测文件系统。"""
    b = image.read(offset, 4096)
    if len(b) < 1024:
        return "unknown"
    if b[3:11] == b"NTFS    ":
        return "ntfs"
    if b[0:4] == b"\x00\x00\x00\x00" and len(b) >= 1090 and b[1080:1082] == b"\x53\xef":
        return "ext4"
    if len(b) > 1080 and b[1080:1082] == b"\x53\xef":
        return "ext2/3/4"
    if b[512:520] == b"MSWIN4.1" or b[54:62] == b"FAT16   ":
        return "fat"
    if b[82:90] == b"FAT32   ":
        return "fat32"
    if b[:4] == b"\x10\x20\xf5\xf2" or b[:4] == b"\xf2\xf5\x20\x10":
        return "apfs/hfs"
    if b[0:4] == b"\x00\x00\x00\x00" and b[4086:4090] == b"\x00\x00\x00\x00":
        return "raw/unknown"
    for magic, name in ((b"YAFFS", "yaffs"), (b"ANDROID!", "android-sparse"),
                        (b"\x3a\xff\x26\xed", "sparse(ext4 raw)")):
        if magic in b[:4096]:
            return name
    return "unknown"
