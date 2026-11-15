# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""zip 内镜像直读 —— 不必把 418GB 检材全解压。

支持 store(0)/deflate(8) 成员，加密 zip 用标准库 zipfile 解密后仍需顺序流；
本模块对流式成员做顺序访问 + 块缓存，适合"先在 zip 里 grep / 只取某个文件"的场景。
"""
import os
import struct
import zipfile
import zlib


class ZipMemberView:
    """把 zip 内一个成员当作随机访问镜像。"""

    CHUNK = 1 << 20

    def __init__(self, zip_path, member, password=None):
        self.zf = zipfile.ZipFile(zip_path)
        self.info = self.zf.getinfo(member)
        self.name = member
        self.size = self.info.file_size
        self.password = password.encode() if isinstance(password, str) else password
        self._fp = None
        self._decomp = None
        self._pos = 0            # 当前流位置
        self._buf = b""          # 从 _pos 起已解出的数据
        self._open_stream()

    def _open_stream(self):
        if self._fp is not None:
            try:
                self._fp.close()
            except Exception:
                pass
        self._fp = self.zf.open(self.info, "r", pwd=self.password)
        self._decomp = None
        self._pos = 0
        self._buf = b""

    def _advance(self, n):
        """向前丢弃 n 字节。"""
        while n > 0:
            if self._buf:
                take = min(n, len(self._buf))
                self._buf = self._buf[take:]
                self._pos += take
                n -= take
                continue
            data = self._fp.read(min(self.CHUNK, max(n, self.CHUNK)))
            if not data:
                break
            self._buf = data
        return

    def read(self, offset, size):
        if offset >= self.size or size <= 0:
            return b""
        size = min(size, self.size - offset)
        if offset < self._pos or offset > self._pos + len(self._buf):
            if offset < self._pos:
                self._open_stream()
            self._advance(offset - self._pos)
        out = self._buf[:size]
        self._buf = self._buf[size:]
        self._pos += len(out)
        return out

    def close(self):
        try:
            if self._fp:
                self._fp.close()
        finally:
            self.zf.close()


def list_members(zip_path, password=None):
    zf = zipfile.ZipFile(zip_path)
    rows = []
    for i in zf.infolist():
        rows.append((i.filename, i.file_size, i.compress_type, bool(i.flag_bits & 0x1)))
    zf.close()
    return rows


def extract(zip_path, member, out_path, password=None):
    zf = zipfile.ZipFile(zip_path)
    pwd = password.encode() if isinstance(password, str) else password
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with zf.open(member, "r", pwd=pwd) as src, open(out_path, "wb") as dst:
        while True:
            b = src.read(8 << 20)
            if not b:
                break
            dst.write(b)
    zf.close()
    return os.path.getsize(out_path)


def sniff_member_kind(view):
    """看成员头判断是 E01 / dd 镜像 / 其它。"""
    head = view.read(0, 512)
    if head[:8] == b"EVF\x09\x0d\x0a\xff\x00":
        return "ewf"
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        return "raw-mbr"
    if head[450:454] == b"EFI PART" or (len(head) >= 512 and head[510:512] == b"\x55\xaa"):
        return "raw"
    for magic, name in ((b"SQLite format 3\x00", "sqlite"), (b"regf", "registry"),
                        (b"PK\x03\x04", "zip"), (b"\xd0\xcf\x11\xe0", "ole"),
                        (b"\x0a\x0d\x0d\x0a", "pcapng"), (b"bplist00", "bplist"),
                        (b"ANDROID!", "sparse")):
        if head.startswith(magic):
            return name
    if head[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    if head[:4] == b"\x1f\x8b\x08\x00" or head[:2] == b"\x1f\x8b":
        return "gzip"
    return "unknown"
