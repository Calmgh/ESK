# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""EWF 读取：优先 libewf(pyewf) 作为权威实现，自研解析器作为兜底。

自研 mkit.ewf 在部分 XWF/非标准 EWF 上会索引错位（读出来是段头而非扇区），
因此 Image 优先用 pyewf；pyewf 不可用时再退回自研实现。
"""
import os


class PyEwfImage:
    """用 pyewf 读 EWF，接口与 mkit.image.Image 兼容。"""

    def __init__(self, segments):
        import pyewf
        self.segments = list(segments)
        self._f = pyewf.handle()
        self._f.open(self.segments)
        self._f.read(1)                 # 触发段表/纠错表加载
        self.size = self._f.media_size
        self.kind = "ewf"
        self._cache_off = -1
        self._cache = b""
        self.block_size = 1 << 20

    def read(self, offset, size):
        if size <= 0 or offset < 0 or offset >= self.size:
            return b""
        size = min(size, self.size - offset)
        # 命中缓存
        if self._cache_off >= 0 and self._cache_off <= offset and \
                offset + size <= self._cache_off + len(self._cache):
            s = offset - self._cache_off
            return self._cache[s:s + size]
        if size >= self.block_size:
            return self._f.read_buffer_at_offset(size, offset)
        # 小块：预取一个 block，减少系统调用
        want = min(self.block_size, self.size - (offset - offset % self.block_size))
        base = offset - offset % self.block_size
        try:
            self._cache = self._f.read_buffer_at_offset(want, base)
            self._cache_off = base
            s = offset - base
            if len(self._cache) >= s + size:
                return self._cache[s:s + size]
        except Exception:
            pass
        return self._f.read_buffer_at_offset(size, offset)

    def close(self):
        try:
            self._f.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def has_pyewf():
    try:
        import pyewf  # noqa: F401
        return True
    except Exception:
        return False


def find_segments(path):
    base, ext = os.path.splitext(path)
    segs = [path]
    if ext.lower() in (".e01", ".e02", ".ex01"):
        i = 2
        while i < 1000:
            found = None
            for tpl in ("{}.E{:02d}", "{}.e{:02d}"):
                cand = tpl.format(base, i)
                if os.path.exists(cand):
                    found = cand
                    break
            if not found:
                break
            segs.append(found)
            i += 1
    return segs
