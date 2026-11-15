# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
import struct, sys, uuid

class VHDX:
    """最小 VHDX 动态盘读取器（只读），提供 read(offset,size) 接口。"""
    def __init__(self, img, base, length=None):
        self.img = img
        self.base = base
        hdr = img.read(base, 0x30000 + 0x1000 if hasattr(img, 'read') else 0)
        self.bsz = hdr[0:8]
        assert hdr[0:8] == b'vhdxfile', hdr[0:8]
        # region table at 0x30000
        rt = img.read(base + 0x30000, 64 * 1024)
        assert rt[0:4] == b'regi', rt[0:4]
        cnt = struct.unpack_from('<I', rt, 8)[0]
        self.regions = {}
        for i in range(cnt):
            off = 16 + 32 * i
            g = rt[off:off + 16]
            fo, ln = struct.unpack_from('<QI', rt, off + 16)
            self.regions[uuid.UUID(bytes_le=g)] = (fo, ln)
        BAT_G = uuid.UUID('2DC27766-F623-4200-9D64-115E9BFD4A08')
        META_G = uuid.UUID('8B7CA206-4790-4B9A-B8FE-575F050F886E')
        bat_off, bat_len = self.regions[BAT_G]
        meta_off, meta_len = self.regions[META_G]
        self.bat_off = base + bat_off
        self.bat_len = bat_len
        # metadata
        md = img.read(base + meta_off, min(meta_len, 0x10000))
        assert md[0:8] == b'metadata', md[0:8]
        n = struct.unpack_from('<H', md, 10)[0]
        items = {}
        for i in range(n):
            off = 32 + 32 * i
            g = uuid.UUID(bytes_le=md[off:off + 16])
            io, il = struct.unpack_from('<II', md, off + 16)
            items[g] = md[io:io + il]
        GP = {
            'file_params': 'CAA16737-FA36-4D43-BAA4-2F7B109B771C',
            'virtual_size': '2FA54224-CD1B-4876-B211-5DBED83BF4B8',
            'logical_sector': '8141BF1D-A96F-4709-BA47-F233A8FAAB5F',
            'physical_sector': 'CDA348C7-445D-4471-9CC9-E9885251C556',
        }
        fp = items[uuid.UUID(GP['file_params'])]
        self.block_size_mb, self.flags = struct.unpack_from('<II', fp, 0)
        self.payload_block = self.block_size_mb * 1024 * 1024
        self.virtual_size = struct.unpack_from('<Q', items[uuid.UUID(GP['virtual_size'])], 0)[0]
        self.logical_sector = struct.unpack_from('<I', items[uuid.UUID(GP['logical_sector'])], 0)[0]
        self.vhdx_len = self.virtual_size
        # BAT header: signature 'bat ' + chunk ratio
        bh = img.read(self.bat_off, 32)
        assert bh[0:4] == b'bat ', bh[0:4]
        self.chunk_ratio = struct.unpack_from('<I', bh, 8)[0]
        if self.chunk_ratio == 0:
            self.chunk_ratio = 1
        self._cache = {}

    def _bat_entry(self, idx):
        b = self.img.read(self.bat_off + 32 + idx * 8, 8)
        v = struct.unpack('<Q', b)[0]
        return ((v >> 20) & 0xFFFFFFFFFF) * 1024 * 1024, v & 7

    def v2p(self, off):
        blk = off // self.payload_block
        if self.chunk_ratio == 1:
            idx = blk
        else:
            chunk = blk // self.chunk_ratio
            idx = chunk * (self.chunk_ratio + 1) + (blk % self.chunk_ratio) + 1
        p, st = self._bat_entry(idx)
        if st == 0:
            return None
        return p + (off % self.payload_block)

    def read(self, off, size=None):
        if size is None:
            size = self.virtual_size - off
        out = bytearray()
        cur = off
        end = off + size
        while cur < end:
            p = self.v2p(cur)
            n = min(end - cur, self.payload_block - (cur % self.payload_block))
            if p is None:
                out += b'\x00' * n
            else:
                out += self.img.read(p, n)
            cur += n
        return bytes(out)
