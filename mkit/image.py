# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""统一镜像访问层：raw(.dd/.img/.bin/.001) 与 EWF(.E01..) 透明读取。

EWF 优先使用 libewf(pyewf)（权威实现），不可用或失败时退回自研 mkit.ewf。
"""
import os

from .ewf import SIG as EWF_SIG


class Image:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        with open(self.path, "rb") as f:
            head = f.read(8)
        if head == EWF_SIG:
            self.kind = "ewf"
            from .ewf_external import PyEwfImage, find_segments, has_pyewf
            self.segments = find_segments(self.path)
            self._ewf = None
            self._fh = None
            self.size = 0
            if has_pyewf():
                try:
                    self._ewf = PyEwfImage(self.segments)
                    self.size = self._ewf.size
                    self.engine = "libewf"
                except Exception:
                    self._ewf = None
            if self._ewf is None:
                from .ewf import EWF
                self._ewf = EWF(self.segments)
                self.size = self._ewf.media_size
                self.engine = "mkit"
        else:
            self.kind = "raw"
            self.segments = [self.path]
            self._fh = open(self.path, "rb")
            self.size = os.path.getsize(self.path)
            self.engine = "raw"

    def read(self, offset, size):
        if size <= 0 or offset < 0 or offset >= self.size:
            return b""
        size = min(size, self.size - offset)
        if self.kind == "raw":
            self._fh.seek(offset)
            return self._fh.read(size)
        return self._ewf.read(offset, size)

    def close(self):
        if self._fh:
            self._fh.close()
        if self.kind == "ewf" and self._ewf is not None:
            self._ewf.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class SubImage:
    """以偏移+长度截取的子视图（用于分区/文件系统）。"""

    def __init__(self, img, offset, size):
        self.img = img
        self.offset = offset
        self.size = size

    def read(self, offset, size):
        if offset >= self.size or size <= 0:
            return b""
        size = min(size, self.size - offset)
        return self.img.read(self.offset + offset, size)
