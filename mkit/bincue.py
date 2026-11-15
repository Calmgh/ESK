# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""光盘镜像（BIN/CUE 及同族 CCD / MDS）解析

对应 LovelyCarve 的「镜像容器」里的 CD 映像一族。

用途：把光盘轨道里的**用户数据区**抽成逻辑 2048 字节流，直接喂
mkit.iso.Iso9660 / mkit.udf 等文件系统解析器：

    bc = BinCue.open(r"disc.cue")
    iso = bc.iso()                 # 自动从第一条数据轨开头对齐
    iso.root_dir()

    # 或自己接：
    from mkit.image import SubImage
    fs = Iso9660(SubImage(bc, 0, bc.size))

═══ 只依赖 read(offset, size) + size ═══
BinCue / CueSheet 自身就满足这个鸭子类型，可以当 Image 用，也可以被
SubImage 再切一刀。

─── 时间与 LBA ───
    1 秒 = 75 帧（sector）
    LBA = (mm * 60 + ss) * 75 + ff
    00:02:00 → 150，这是光盘首扇区的惯例起点（lead-in 占 150 帧）

─── 扇区布局（常数见 SECTOR_MODES）───
    模式            扇区字节  用户数据偏移  用户数据长
    MODE1/2048         2048          0        2048
    MODE1/2352         2352         16        2048
    MODE2/2352 Form1   2352         24        2048
    MODE2/2352 Form2   2352         24        2324
    MODE2/2336 Form1   2336          8        2048
    MODE2/2336 Form2   2336          8        2324
    AUDIO              2352          —          —

    注：MODE2/2336 那一行不能写成「偏移 8、长 2336」——8 + 2336 = 2344
    超出扇区。2336 扇区里 8 字节子头之后只剩 2328 字节：Form1 是
    2048 数据 + 4 EDC + 276 备用，Form2 是 2324 数据 + 4 EDC。
    本文件按 Form 分别取 2048 / 2324，不做「抄表」。

    Mode2 的 Form 由**子头第 3 字节（subheader[2]）的 submode 位**判定：
    bit5（0x20）置位 = Form2，否则 Form1。2352 扇区的子头在 16..23，
    2336 扇区的子头在 0..7。

─── 已实现 ───
    · CUE 表：FILE（BINARY/WAVE/MOTOROLA/AIFF/MP3）、TRACK（MODE1/2048、
      MODE1/2352、MODE2/2048、MODE2/2324、MODE2/2336、MODE2/2352、
      AUDIO、CDI/2336、CDI/2352）、INDEX 00..99、PREGAP、POSTGAP、
      FLAGS、ISRC、REM、CATALOG / TITLE / PERFORMER / SONGWRITER（CD-TEXT）
    · 编码探测：UTF-8（含 BOM）→ GBK → Shift-JIS(cp932) → Big5 → latin-1，
      命中的编码记在 CueSheet.encoding
    · 多轨 + 多文件：每个 TRACK 归属它当时的 FILE，read() 按轨路由到
      对应文件与字节偏移；文件内 TRACK 之间用下一轨的 INDEX 01 差值定长
    · PREGAP（合成间隙，文件里没有的）按帧数撑开逻辑 LBA，读出来全零；
      INDEX 00（文件里真实存在的预间隙）不进逻辑流，但可用
      read_sector_raw / read_user_raw 原样取字节
    · 逻辑数据抽取 read_data(lba, n) / CueSheet.read(lba, n)：每扇区恒
      2048 字节；MODE2/2352 Form2 只取前 2048（2324 → 2048 截断）
    · read_sector(lba) 原始扇区、read_user_raw(lba) 完整用户窗口
    · BinCue：字节流 size / read(off, n)，直接喂 mkit.iso.Iso9660
    · CCD/IMG/SUB（CloneCD）：INI 全量解析，[CloneCD]/[Disc]/[Session n]/
      [Entry n]/[TRACK n] 段，轨道起点按 AMSF-150 换算并与 ALBA 交叉校验
    · MDS/MDF（Alcohol 120%）：「MEDIA DESCRIPTOR」魔数、版本、介质类型、
      会话数与轨道表（自校验解析，失败降级为仅头部）
    · SUB 子通道：每扇区 96 字节，解析 Q 通道（ADR/CONTROL/TNO/INDEX/
      相对 MSF/绝对 MSF/绝对 LBA）并做 CRC16-CCITT 反码校验；Q 在记录
      内的偏移（0 或 12）按 CRC 命中自动判定
    · 模块级 probe(path)、parse_cue(text)、msf_to_lba / lba_to_msf

─── 不实现 ───
    · CCD/IMG 与 MDS/MDF 的**数据抽取**：只识别头部与轨道表，read /
      read_data / read_sector 一律抛 NotImplementedError。原因：跑马灯
      交织（DataTracksScrambled）、MDS 轨道块字段在不同 Alcohol 版本里
      偏移不一致，硬解会把垃圾当数据。需要数据时用同名 .img/.mdf 走
      raw 或转成 cue。
    · 音频解码（AUDIO 轨按零填充返回，不做 WAV 封装 / 去加重）
    · CUE 的 WAVE/MOTOROLA 容器内嵌偏移（当成整块裸流，付之一笑）
    · MP3 轨、CD+G（CDG）子码图形、DVD/BD 的 UDF 轨道
"""

import codecs
import os
import re
import struct

__all__ = [
    "Track", "CueSheet", "BinCue", "CloneCD", "Mds", "SubChannel",
    "parse_cue", "probe", "msf_to_lba", "lba_to_msf",
    "SECTOR_MODES", "SYNC", "LEADIN", "FRAMES_PER_SEC",
]

# ---------------- 常数 ----------------
FRAMES_PER_SEC = 75            # 光盘 1 秒 75 帧
LEADIN = 150                   # 00:02:00 对应的帧数

SYNC = b"\x00" + b"\xff" * 10 + b"\x00"      # 12 字节同步头

SECTOR_MODES = {
    # 名称:         扇区字节, 用户数据偏移, 用户数据长, 是否数据轨
    "MODE1/2048":  (2048, 0, 2048, True),
    "MODE1/2352":  (2352, 16, 2048, True),
    "MODE2/2048":  (2048, 0, 2048, True),
    "MODE2/2324":  (2324, 0, 2324, True),
    "MODE2/2336":  (2336, 8, 2328, True),       # Form 决定 2048 / 2324
    "MODE2/2352":  (2352, 24, 2328, True),      # Form 决定 2048 / 2324
    "CDI/2336":    (2336, 8, 2328, True),
    "CDI/2352":    (2352, 24, 2328, True),
    "AUDIO":       (2352, None, None, False),
}

MODE2_MODES = ("MODE2/2352", "CDI/2352", "MODE2/2336", "CDI/2336")

# 子通道
SUB_RECORD = 96                # 每扇区 96 字节 = 8 通道 × 12 字节
SUB_Q_OFFSETS = (12, 0)        # CloneCD 的 .sub 是 P 在前（Q@12），也有 Q 在前的

CUE_ENCODINGS = ("utf-8", "gbk", "cp932", "big5", "latin-1")

_MSF_RE = re.compile(r"^(\d{1,3}):(\d{1,2}):(\d{1,2})$")


# ---------------- MSF / LBA ----------------
def msf_to_lba(text):
    """'mm:ss:ff' -> LBA 帧号。00:02:00 -> 150"""
    if isinstance(text, (int,)):
        return int(text)
    s = str(text).strip()
    m = _MSF_RE.match(s)
    if not m:
        raise ValueError("非法 MSF 时间: %r" % (text,))
    mm, ss, ff = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if ss > 59 or ff > 74:
        raise ValueError("MSF 越界（ss<=59, ff<=74）: %r" % (text,))
    return (mm * 60 + ss) * FRAMES_PER_SEC + ff


def lba_to_msf(lba):
    """LBA 帧号 -> 'mm:ss:ff'（负值按 0 处理）"""
    lba = max(0, int(lba))
    return "%02d:%02d:%02d" % (lba // (60 * FRAMES_PER_SEC),
                               (lba // FRAMES_PER_SEC) % 60,
                               lba % FRAMES_PER_SEC)


def _bcd(v):
    """BCD 字节 -> 十进制（非 BCD 位保留原值，容错）"""
    hi, lo = (v >> 4) & 0x0F, v & 0x0F
    if hi > 9 or lo > 9:
        return v
    return hi * 10 + lo


def _to_bcd(v):
    return ((v // 10) << 4) | (v % 10)


def _pad(data, n, fill=b"\x00"):
    return data if len(data) >= n else data + fill * (n - len(data))


# ---------------- 文本解码 ----------------
def decode_text(raw):
    """探测 cue/ccd 编码：BOM → UTF-8 → GBK → Shift-JIS → Big5 → latin-1

    返回 (text, encoding)。
    """
    if isinstance(raw, str):
        return raw, "unicode"
    if raw.startswith(codecs.BOM_UTF8):
        return raw[3:].decode("utf-8", "replace"), "utf-8-sig"
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        return raw.decode("utf-16", "replace"), "utf-16"
    for enc in CUE_ENCODINGS:
        try:
            return raw.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "replace"), "latin-1"


def _tokenize(line):
    """按空白切分，双引号内视为一个 token（cue 的 FILE 名可能带空格）"""
    out = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch in " \t":
            i += 1
        elif ch == '"':
            j = line.find('"', i + 1)
            if j < 0:
                out.append(line[i + 1:])
                break
            out.append(line[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < n and line[j] not in " \t":
                j += 1
            out.append(line[i:j])
            i = j
    return out


# ---------------- 轨道 ----------------
class Track(object):
    """一条轨道

    number      轨号（1..99，AUDIO 也可能是 1）
    mode        模式名（MODE1/2352 ... AUDIO）
    start_lba   该轨 INDEX 01 在逻辑流里的绝对 LBA
    pregap      间隙帧数（INDEX 00 与 INDEX 01 之差，或 PREGAP 命令值）
    file        所属文件名（cue 里写的原样）
    file_offset 该轨 INDEX 01 在文件内的字节偏移
    sector_size 扇区字节数
    """

    __slots__ = ("number", "mode", "sector_size", "user_off", "user_len",
                 "is_data", "file", "file_index", "file_lba", "file_offset",
                 "start_lba", "pregap", "postgap", "length", "indexes",
                 "pregap_in_file", "title", "flags", "isrc")

    def __init__(self, number, mode, fname=None, file_index=None):
        if mode not in SECTOR_MODES:
            raise ValueError("不认识的轨道模式: %r" % (mode,))
        sec, uoff, ulen, is_data = SECTOR_MODES[mode]
        self.number = int(number)
        self.mode = mode
        self.sector_size = sec
        self.user_off = uoff
        self.user_len = ulen
        self.is_data = is_data
        self.file = fname
        self.file_index = file_index
        self.file_lba = None          # 文件内的 LBA（INDEX 01）
        self.file_offset = None       # 文件内的字节偏移
        self.start_lba = None         # 逻辑流里的绝对 LBA
        self.pregap = 0
        self.postgap = 0
        self.length = None            # 帧数；None = 未知（文件大小缺）
        self.indexes = {}             # {index 号: 文件内 LBA}
        self.pregap_in_file = False   # True = 预间隙的字节真在文件里
        self.title = None
        self.flags = []
        self.isrc = None

    # -- 派生量 --
    @property
    def end_lba(self):
        return (self.start_lba or 0) + (self.length or 0)

    @property
    def pregap_start_lba(self):
        return (self.start_lba or 0) - (self.pregap or 0)

    def __repr__(self):
        return "<Track %02d %s lba=%s len=%s pregap=%d%s>" % (
            self.number, self.mode, self.start_lba, self.length, self.pregap,
            (" form?" if self.mode in MODE2_MODES else ""))

    def as_dict(self):
        return {
            "number": self.number, "mode": self.mode,
            "sector_size": self.sector_size,
            "start_lba": self.start_lba,
            "start_msf": lba_to_msf(self.start_lba) if self.start_lba is not None else None,
            "pregap": self.pregap, "pregap_in_file": self.pregap_in_file,
            "postgap": self.postgap, "length": self.length,
            "end_lba": self.end_lba,
            "file": self.file, "file_offset": self.file_offset,
            "indexes": {k: lba_to_msf(v) for k, v in sorted(self.indexes.items())},
        }


# ---------------- CUE 表 ----------------
class CueSheet(object):
    """CUE 表 + 按轨路由的数据读取

    parse(path) 会把文件句柄惰性挂在 self 上，read 即可用；
    parse(text) 只有元数据，read 会抛 RuntimeError（除非绑定了 reader）。
    """

    def __init__(self):
        self.tracks_list = []
        self.files = []               # [{"index","name","type","size","base_lba","tracks"}]
        self.encoding = None
        self.catalog = None
        self.title = None
        self.performer = None
        self.songwriter = None
        self.rems = []
        self.unknown = []
        self.path = None
        self.base_dir = None
        self.missing = []
        self.notes = []
        self._fh = {}

    # -- 构造 --
    @classmethod
    def parse(cls, text_or_path, base_dir=None):
        """text 或路径；路径按扩展名/内容判断，读到文件才 stat 大小"""
        self = cls()
        src = None
        if isinstance(text_or_path, (bytes, bytearray)):
            text, enc = decode_text(bytes(text_or_path))
            self.encoding = enc
        elif isinstance(text_or_path, str) and _looks_like_path(text_or_path):
            self.path = os.path.abspath(text_or_path)
            self.base_dir = base_dir or os.path.dirname(self.path)
            with open(self.path, "rb") as f:
                raw = f.read()
            text, enc = decode_text(raw)
            self.encoding = enc
            src = self.path
        else:
            self.encoding = "unicode"
            text = text_or_path if isinstance(text_or_path, str) else str(text_or_path)
            self.base_dir = base_dir

        self._parse_text(text)
        if src is not None:
            self._stat_files()
        self._layout()
        return self

    # -- 解析 --
    def _parse_text(self, text):
        cur_file = None
        cur_track = None
        seen_track = False

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            tok = _tokenize(line)
            if not tok:
                continue
            kw = tok[0].upper()

            if kw == "REM":
                self.rems.append(line[3:].strip())
                continue

            if kw == "FILE":
                name = tok[1] if len(tok) > 1 else ""
                ftype = tok[2].upper() if len(tok) > 2 else "BINARY"
                cur_file = {"index": len(self.files), "name": name,
                            "type": ftype, "size": None, "base_lba": 0,
                            "tracks": []}
                self.files.append(cur_file)
                cur_track = None
                continue

            if kw == "TRACK":
                if len(tok) < 3:
                    self.unknown.append(line)
                    continue
                try:
                    num = int(tok[1], 10)
                except ValueError:
                    self.unknown.append(line)
                    continue
                mode = tok[2].upper()
                if mode not in SECTOR_MODES:
                    alt = _normalize_mode(mode)
                    if alt:
                        mode = alt
                    else:
                        self.unknown.append(line)
                        continue
                if cur_file is None:          # 有的 cue 省略 FILE
                    cur_file = {"index": len(self.files), "name": "",
                                "type": "BINARY", "size": None, "base_lba": 0,
                                "tracks": []}
                    self.files.append(cur_file)
                cur_track = Track(num, mode, cur_file["name"], cur_file["index"])
                cur_file["tracks"].append(cur_track)
                self.tracks_list.append(cur_track)
                seen_track = True
                continue

            if kw == "INDEX":
                if cur_track is None or len(tok) < 3:
                    self.unknown.append(line)
                    continue
                try:
                    idx = int(tok[1], 10)
                    lba = msf_to_lba(tok[2])
                except (ValueError, TypeError):
                    self.unknown.append(line)
                    continue
                cur_track.indexes[idx] = lba
                if idx == 1:
                    cur_track.file_lba = lba
                continue

            if kw == "PREGAP":
                if cur_track is not None and len(tok) > 1:
                    cur_track.pregap = msf_to_lba(tok[1])
                    cur_track.pregap_in_file = False
                continue

            if kw == "POSTGAP":
                if cur_track is not None and len(tok) > 1:
                    cur_track.postgap = msf_to_lba(tok[1])
                continue

            if kw == "FLAGS":
                if cur_track is not None:
                    cur_track.flags = [t.upper() for t in tok[1:]]
                continue

            if kw == "ISRC":
                if cur_track is not None and len(tok) > 1:
                    cur_track.isrc = tok[1]
                continue

            if kw == "CATALOG":
                self.catalog = tok[1] if len(tok) > 1 else None
                continue

            if kw in ("TITLE", "PERFORMER", "SONGWRITER"):
                val = " ".join(tok[1:]).strip()
                if cur_track is not None and kw == "TITLE":
                    cur_track.title = val
                elif kw == "TITLE":
                    self.title = val
                elif kw == "PERFORMER":
                    self.performer = val
                else:
                    self.songwriter = val
                continue

            self.unknown.append(line)

        if not seen_track:
            raise ValueError("CUE 表里没有 TRACK 行")

        # 收尾：INDEX 00 才是文件内的预间隙
        for t in self.tracks_list:
            i0 = t.indexes.get(0)
            i1 = t.indexes.get(1)
            if i0 is not None and i1 is not None and i1 > i0:
                t.pregap = i1 - i0
                t.pregap_in_file = True
            if t.file_lba is None:
                t.file_lba = 0
                self.notes.append("轨道 %02d 缺 INDEX 01，按 0 处理" % t.number)

    # -- 文件 --
    def _stat_files(self):
        for f in self.files:
            if not f["name"]:
                continue
            p = self._resolve(f["name"])
            try:
                f["size"] = os.path.getsize(p)
            except OSError:
                f["size"] = None
                self.missing.append(f["name"])

    def _resolve(self, name):
        name = name.replace("/", os.sep)
        if os.path.isabs(name) or self.base_dir is None:
            return name
        return os.path.join(self.base_dir, name)

    def _file_read(self, index, offset, size):
        key = index
        fh = self._fh.get(key)
        if fh is None:
            f = self.files[index]
            path = self._resolve(f["name"])
            try:
                fh = open(path, "rb")
            except OSError:
                return b""
            self._fh[key] = fh
        if offset < 0 or size <= 0:
            return b""
        fh.seek(offset)
        return fh.read(size)

    def close(self):
        for fh in self._fh.values():
            try:
                fh.close()
            except OSError:
                pass
        self._fh.clear()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # -- 布局：绝对 LBA --
    def _layout(self):
        cursor = 0
        for f in self.files:
            f["base_lba"] = cursor
            # 文件总帧数按该文件第一轨的扇区尺寸估（同一文件内模式通常一致）
            fsec = None
            if f["size"] and f["tracks"]:
                fsec = f["size"] // f["tracks"][0].sector_size
            for i, t in enumerate(f["tracks"]):
                t.file_offset = (t.file_lba or 0) * t.sector_size
                if t.pregap and not t.pregap_in_file:
                    cursor += t.pregap                 # 合成间隙占 LBA，读出来零
                start = f["base_lba"] + (t.file_lba or 0)
                t.start_lba = start if start > cursor else cursor
                nxt = f["tracks"][i + 1] if i + 1 < len(f["tracks"]) else None
                if nxt is not None:
                    t.length = max(0, (nxt.file_lba or 0) - (t.file_lba or 0))
                elif fsec is not None:
                    t.length = max(0, fsec - (t.file_lba or 0))
                else:
                    t.length = None
                cursor = t.start_lba + (t.length or 0)
        self.total_lba = cursor

    # -- 查询 --
    def tracks(self):
        return list(self.tracks_list)

    def track_at(self, lba):
        """命中 [start_lba, end_lba) 的轨道；间隙返回 None"""
        for t in self.tracks_list:
            if t.start_lba is None:
                continue
            if t.start_lba <= lba < t.end_lba:
                return t
        return None

    def track_by_number(self, num):
        for t in self.tracks_list:
            if t.number == num:
                return t
        return None

    def first_data_track(self):
        for t in self.tracks_list:
            if t.is_data:
                return t
        return self.tracks_list[0] if self.tracks_list else None

    # -- 读 --
    def _raw_sector(self, track, idx):
        """文件里的原始扇区（不足补零）；idx<0 只允许落在文件内的预间隙上"""
        if track is None or track.file_offset is None:
            return b""
        if idx < 0:
            if not (track.pregap_in_file and idx >= -track.pregap):
                return b""
        off = track.file_offset + idx * track.sector_size
        d = self._file_read(track.file_index, off, track.sector_size)
        return _pad(d, track.sector_size)

    def _pregap_track_at(self, lba):
        """命中「文件内预间隙」的轨道（INDEX 00 起的真实字节）"""
        for t in self.tracks_list:
            if t.start_lba is None or not t.pregap or not t.pregap_in_file:
                continue
            if t.start_lba - t.pregap <= lba < t.start_lba:
                return t
        return None

    def read_sector_raw(self, lba):
        """绝对 LBA 的原始扇区（含 INDEX 00 预间隙的真实字节）；间隙返回全零"""
        t = self.track_at(lba) or self._pregap_track_at(lba)
        if t is None:
            return b""
        return self._raw_sector(t, lba - t.start_lba)

    def sector_form(self, raw, mode):
        """从扇区字节判 Form：subheader[2] 的 bit5 置位 = Form2"""
        if mode in ("MODE2/2352", "CDI/2352"):
            if len(raw) < 24:
                return 1
            return 2 if (raw[18] & 0x20) else 1
        if mode in ("MODE2/2336", "CDI/2336"):
            if len(raw) < 8:
                return 1
            return 2 if (raw[2] & 0x20) else 1
        return None

    def _window(self, track, raw):
        """(用户数据偏移, 用户数据长)"""
        mode = track.mode
        if mode in ("MODE2/2352", "CDI/2352"):
            return (24, 2324) if self.sector_form(raw, mode) == 2 else (24, 2048)
        if mode in ("MODE2/2336", "CDI/2336"):
            return (8, 2324) if self.sector_form(raw, mode) == 2 else (8, 2048)
        if track.user_off is None:
            return (None, None)
        return (track.user_off, track.user_len)

    def form(self, lba):
        """该 LBA 的 Form（1/2）；非 Mode2 或空轨返回 None"""
        t = self.track_at(lba)
        if t is None or t.mode not in MODE2_MODES:
            return None
        return self.sector_form(self._raw_sector(t, lba - t.start_lba), t.mode)

    def read_user_raw(self, lba):
        """完整用户数据窗口（Form2 是 2324 字节），不做 2048 截断

        同样支持文件内预间隙（INDEX 00 起）的物理访问。
        """
        t = self.track_at(lba) or self._pregap_track_at(lba)
        if t is None or not t.is_data:
            return b""
        raw = self._raw_sector(t, lba - t.start_lba)
        off, ln = self._window(t, raw)
        if off is None:
            return b""
        return raw[off:off + ln]

    def _data_sector(self, lba):
        """一个扇区的逻辑 2048 字节"""
        t = self.track_at(lba)
        if t is None or not t.is_data:
            return b"\x00" * 2048
        raw = self._raw_sector(t, lba - t.start_lba)
        if not raw:
            return b"\x00" * 2048
        off, ln = self._window(t, raw)
        if off is None:
            return b"\x00" * 2048
        return _pad(raw[off:off + ln][:2048], 2048)

    def read_data(self, lba, count=1):
        """逻辑 2048 字节用户数据，共 count 个扇区；间隙/音频轨填零"""
        if count <= 0:
            return b""
        out = bytearray()
        for i in range(int(count)):
            out += self._data_sector(int(lba) + i)
        return bytes(out)

    def read(self, lba, n=1):
        """同 read_data（LBA 语义，不是字节偏移）"""
        return self.read_data(lba, n)

    def read_sector(self, lba):
        """原始扇区（按该轨扇区尺寸）；间隙返回全零同尺寸块"""
        t = self.track_at(lba)
        if t is None:
            nt = self._next_track(lba)
            size = nt.sector_size if nt else 2352
            return b"\x00" * size
        raw = self._raw_sector(t, lba - t.start_lba)
        return raw if raw else b"\x00" * t.sector_size

    def _next_track(self, lba):
        cand = [t for t in self.tracks_list if t.start_lba is not None and t.start_lba >= lba]
        return min(cand, key=lambda t: t.start_lba) if cand else None

    def info(self):
        modes = {}
        for t in self.tracks_list:
            modes[t.mode] = modes.get(t.mode, 0) + 1
        return {
            "format": "cue",
            "cue": self.path,
            "encoding": self.encoding,
            "catalog": self.catalog,
            "title": self.title,
            "performer": self.performer,
            "tracks": len(self.tracks_list),
            "total_lba": getattr(self, "total_lba", 0),
            "modes": modes,
            "files": [{"name": f["name"], "type": f["type"], "size": f["size"],
                       "tracks": [t.number for t in f["tracks"]]}
                      for f in self.files],
            "missing": list(self.missing),
            "notes": list(self.notes),
        }


def _normalize_mode(mode):
    """大小写/空格归一；CDI/2352、MODE2/2336 之类映射到表里的名字"""
    m = str(mode).upper().replace(" ", "")
    if m in SECTOR_MODES:
        return m
    g = re.match(r"^CDI/(\d{3,4})$", m)
    if g:
        size = int(g.group(1))
        for cand in ("CDI/%d" % size, "MODE2/%d" % size):
            if cand in SECTOR_MODES:
                return cand
        return None
    g = re.match(r"^MODE([12])/(\d{3,4})$", m)
    if g:
        cand = "MODE%s/%d" % (g.group(1), int(g.group(2)))
        return cand if cand in SECTOR_MODES else None
    return None


def _looks_like_path(s):
    """短、无换行、存在 -> 当路径"""
    if not s or "\n" in s or "\r" in s or len(s) > 4096:
        return False
    if s.strip().upper().startswith(("FILE", "TRACK", "REM", "[")):
        return False
    try:
        return os.path.exists(s)
    except (OSError, ValueError):
        return False


def parse_cue(text):
    """便捷入口：text 或路径 -> CueSheet"""
    return CueSheet.parse(text)


# ---------------- BinCue ----------------
class _View(object):
    """把 BinCue 的一段 LBA 区间切成独立设备（供 Iso9660 / udf 用）"""

    def __init__(self, bc, start_lba, count):
        self.bc = bc
        self.start_lba = start_lba
        self.count = count
        self.size = count * 2048

    def read(self, offset, size):
        if size <= 0 or offset < 0 or offset >= self.size:
            return b""
        size = min(size, self.size - offset)
        return self.bc._read_bytes(self.start_lba * 2048 + offset, size)

    def __repr__(self):
        return "<View lba=%d count=%d %dB>" % (self.start_lba, self.count, self.size)


class BinCue(object):
    """BIN/CUE 逻辑流：每扇区 2048 字节，可直接喂 Iso9660

    bc.size / bc.read(off, n)  → 鸭子类型 Image
    bc.iso()                   → Iso9660（自动对齐到首条数据轨起点）
    """

    def __init__(self, cue_path, base_dir=None):
        self.path = os.path.abspath(cue_path)
        self.backend = "cue"
        self.cue = CueSheet.parse(self.path, base_dir=base_dir)
        self.missing = self.cue.missing

    @classmethod
    def open(cls, cue_path, base_dir=None):
        """按扩展名/魔数分派：.cue → CUE，.ccd → CloneCD，.mds → Mds"""
        kind = probe(cue_path)
        if kind == "ccd":
            return CloneCD(cue_path, base_dir=base_dir)
        if kind == "mds":
            return Mds(cue_path, base_dir=base_dir)
        return cls(cue_path, base_dir=base_dir)

    # -- 逻辑流 --
    @property
    def size(self):
        return self.cue.total_lba * 2048

    def _read_bytes(self, offset, size):
        if size <= 0 or offset < 0 or offset >= self.size:
            return b""
        size = min(size, self.size - offset)
        out = bytearray()
        lba = offset // 2048
        skip = offset % 2048
        while size > 0:
            blk = self.cue._data_sector(lba)
            take = blk[skip:skip + size]
            out += take
            size -= len(take)
            skip = 0
            lba += 1
        return bytes(out)

    def read(self, offset, size):
        return self._read_bytes(offset, size)

    # -- 轨道视图 --
    def track_view(self, track=None, count=None):
        """某条轨道（默认首条数据轨）的独立设备，LBA 0 = 该轨 INDEX 01"""
        t = track or self.cue.first_data_track()
        if t is None:
            raise ValueError("没有可用轨道")
        n = t.length if count is None else count
        if not n:
            raise ValueError("轨道长度未知（文件缺失？）")
        return _View(self, t.start_lba, n)

    def iso(self, track=None):
        """便捷：返回 mkit.iso.Iso9660，起点对齐到数据轨 INDEX 01"""
        Iso9660 = _load_iso()
        return Iso9660(self.track_view(track))

    def info(self):
        d = self.cue.info()
        d["format"] = "bin/cue"
        d["size"] = self.size
        d["total_bytes"] = self.size
        d["path"] = self.path
        d["tracks"] = len(self.cue.tracks_list)
        d["track_detail"] = [t.as_dict() for t in self.cue.tracks_list]
        return d

    def close(self):
        self.cue.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __repr__(self):
        return "<BinCue %r tracks=%d lba=%d>" % (
            os.path.basename(self.path), len(self.cue.tracks_list),
            self.cue.total_lba)


def _load_iso():
    """惰性导入 Iso9660（包内 / 直接跑脚本两种路径都行）"""
    try:
        from .iso import Iso9660
    except ImportError:
        from iso import Iso9660
    return Iso9660


# ---------------- CloneCD（CCD/IMG/SUB）----------------
def _parse_ini(text):
    """极简 INI：[节] + key=value，重复键后值覆盖"""
    sections = {}
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1].strip()
            sections.setdefault(cur, {})
            continue
        if "=" in line and cur is not None:
            k, v = line.split("=", 1)
            sections[cur][k.strip()] = v.strip()
    return sections


def _int(v, default=0):
    try:
        return int(str(v).strip(), 0)
    except (TypeError, ValueError):
        return default


class CloneCD(object):
    """CloneCD 的 CCD（表）+ IMG（数据）+ SUB（子通道）

    只识别头部与轨道表，不做数据抽取（read* 抛 NotImplementedError）。
    """

    def __init__(self, ccd_path, base_dir=None):
        self.path = os.path.abspath(ccd_path)
        self.backend = "ccd"
        self.base_dir = base_dir or os.path.dirname(self.path)
        with open(self.path, "rb") as f:
            raw = f.read()
        text, self.encoding = decode_text(raw)
        self.ini = _parse_ini(text)
        self.notes = []
        self.missing = []
        if "CloneCD" not in self.ini:
            self.notes.append("缺 [CloneCD] 段，仍按 CCD 解析")

        disc = self.ini.get("Disc", {})
        self.version = self.ini.get("CloneCD", {}).get("Version")
        self.toc_entries = _int(disc.get("TocEntries"), 0)
        self.sessions = _int(disc.get("Sessions"), 1)
        self.scrambled = bool(_int(disc.get("DataTracksScrambled"), 0))
        self.cdtext_length = _int(disc.get("CDTextLength"), 0)

        self.tracks = []
        self.leadout_lba = None
        self.disc_id = None
        for name in self.ini:
            if not name.lower().startswith("entry"):
                continue
            e = self.ini[name]
            point = _int(e.get("Point"), -1)
            if 1 <= point <= 0x63:
                self.tracks.append(self._track_from_entry(point, e))
            elif point == 0xA2:
                self.leadout_lba = self._entry_lba(e)
        self.tracks.sort(key=lambda t: t["number"])
        if 0xA0 in [p for p in self._points()]:
            self.notes.append("含 [Entry] Point=0xA0（首轨/盘型描述）")

        stem = os.path.splitext(self.path)[0]
        self.img_path = self._pick(stem, (".img", ".IMG"))
        self.sub_path = self._pick(stem, (".sub", ".SUB"))
        self.raw_size = None
        if self.img_path:
            try:
                self.raw_size = os.path.getsize(self.img_path)
            except OSError:
                self.missing.append(os.path.basename(self.img_path))
        else:
            self.missing.append(os.path.basename(stem) + ".img")
        self._layout()

    def _points(self):
        out = []
        for name in self.ini:
            if name.lower().startswith("entry"):
                out.append(_int(self.ini[name].get("Point"), -1))
        return out

    def _pick(self, stem, exts):
        for ext in exts:
            p = stem + ext
            if os.path.exists(p):
                return p
        return None

    def _entry_lba(self, e):
        """AMin/ASec/AFrame 是绝对 MSF，减 150 得 LBA；缺 MSF 时退回 ALBA"""
        if "AMin" in e and "ASec" in e and "AFrame" in e:
            lba = (_int(e["AMin"]) * 60 + _int(e["ASec"])) * FRAMES_PER_SEC + _int(e["AFrame"])
            alt = _int(e.get("ALBA"), lba)
            if alt != lba and abs(alt - lba) > 1:
                self.notes.append("Entry Point=0x%02x: ALBA=%d 与 AMSF-150=%d 不一致，用 AMSF"
                                  % (_int(e.get("Point"), 0), alt, lba))
            return lba - LEADIN
        return _int(e.get("ALBA"), 0)

    def _track_from_entry(self, number, e):
        control = _int(e.get("Control"), 0)
        start = self._entry_lba(e)
        return {
            "number": number,
            "start_lba": start,
            "start_msf": lba_to_msf(start + LEADIN),
            "control": control,
            "adr": _int(e.get("ADR"), 0),
            "is_data": bool(control & 0x04),
            "is_audio": not bool(control & 0x04),
            "pre_emphasis": bool(control & 0x01),
            "copy_permitted": not bool(control & 0x02),
            "four_channel": bool(control & 0x08),
            "end_lba": None,
        }

    def _layout(self):
        for i, t in enumerate(self.tracks):
            nxt = self.tracks[i + 1] if i + 1 < len(self.tracks) else None
            if nxt is not None:
                t["end_lba"] = nxt["start_lba"]
            else:
                t["end_lba"] = self.leadout_lba
        self.total_lba = (self.leadout_lba
                          or (self.tracks[-1]["end_lba"] if self.tracks else 0) or 0)

    # -- 不做数据抽取 --
    def _refuse(self):
        raise NotImplementedError(
            "CCD/IMG 只识别头部与轨道表，不做数据抽取（跑马灯/交织未处理）；"
            "请用 %s 走 raw 或转成 cue" % (os.path.basename(self.img_path)
                                           if self.img_path else "同名 .img"))

    def read(self, offset, size):
        self._refuse()

    def read_data(self, lba, count=1):
        self._refuse()

    def read_sector(self, lba):
        self._refuse()

    @property
    def size(self):
        return self.raw_size or 0

    def sub(self):
        return SubChannel(self.sub_path) if self.sub_path else None

    def info(self):
        return {
            "format": "ccd",
            "path": self.path,
            "encoding": self.encoding,
            "version": self.version,
            "sessions": self.sessions,
            "toc_entries": self.toc_entries,
            "data_scrambled": self.scrambled,
            "cdtext_length": self.cdtext_length,
            "leadout_lba": self.leadout_lba,
            "total_lba": self.total_lba,
            "tracks": len(self.tracks),
            "track_detail": [dict(t) for t in self.tracks],
            "img": self.img_path,
            "img_size": self.raw_size,
            "sub": self.sub_path,
            "missing": list(self.missing),
            "notes": list(self.notes),
            "data_extraction": False,
        }

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __repr__(self):
        return "<CloneCD %r tracks=%d lba=%d>" % (
            os.path.basename(self.path), len(self.tracks), self.total_lba)


# ---------------- MDS/MDF（Alcohol 120%）----------------
MDS_MAGIC = b"MEDIA DESCRIPTOR"
MDS_HEADER_SIZE = 88
# 会话表偏移在头部里的候选位置（不同版本写过 0x4C/0x50/0x54/0x58/0x5C/0x60）
MDS_SESSION_PTR_OFFS = (0x50, 0x54, 0x4C, 0x58, 0x5C, 0x60, 0x48, 0x64)


class Mds(object):
    """Alcohol 120% 的 MDS（描述）+ MDF（数据）

    只识别头部与轨道表，不做数据抽取（read* 抛 NotImplementedError）。
    轨道表字段在 1.10 / 1.15 / 2.0 之间偏移不一致，故：
      1) 先取魔数、版本、介质类型、会话数（这些位置稳定）
      2) 会话表偏移按候选列表逐个尝试，并用「轨道数 1..99 且
         Last-First+1 == 轨道数」做结构自校验
      3) 校验不通过就只留头部 + 原始字节转储，绝不给假轨道
    """

    def __init__(self, mds_path, base_dir=None):
        self.path = os.path.abspath(mds_path)
        self.backend = "mds"
        self.base_dir = base_dir or os.path.dirname(self.path)
        with open(self.path, "rb") as f:
            head = f.read(MDS_HEADER_SIZE)
            self.file_size = os.path.getsize(self.path)
        if not head.startswith(MDS_MAGIC):
            raise ValueError("不是 MDS：缺少 'MEDIA DESCRIPTOR' 魔数")
        self.notes = []
        self.missing = []
        self.session_ptr = None
        self.sessions = []
        self.tracks = []

        self.version_raw = head[0x10:0x14]
        self.version = self._version_str(self.version_raw)
        self.medium_type = struct.unpack_from("<H", head, 0x14)[0] if len(head) >= 0x16 else None
        self.session_count = struct.unpack_from("<H", head, 0x16)[0] if len(head) >= 0x18 else 0
        self.medium_name = MEDIUM_TYPES.get(self.medium_type, "未知介质(%s)" % self.medium_type)
        self.header_hex = head.hex()

        self._parse_sessions(head)
        stem = os.path.splitext(self.path)[0]
        self.mdf_path = self._pick(stem, (".mdf", ".MDF"))
        self.mdf_size = None
        if self.mdf_path:
            try:
                self.mdf_size = os.path.getsize(self.mdf_path)
            except OSError:
                self.missing.append(os.path.basename(self.mdf_path))
        else:
            self.missing.append(os.path.basename(stem) + ".mdf")
        self.total_lba = max([t["start_lba"] + (t["length"] or 0) for t in self.tracks],
                             default=0)

    @staticmethod
    def _version_str(raw):
        """版本 4 字节：见过 01 0A 00 00（1.10）与 ASCII '1.10' 两种"""
        if not raw:
            return None
        if raw[0:1].isdigit() and b"." in raw:
            return raw.split(b"\x00")[0].decode("ascii", "replace")
        return "%d.%02d" % (raw[0], raw[1])

    @staticmethod
    def _pick(stem, exts):
        for ext in exts:
            p = stem + ext
            if os.path.exists(p):
                return p
        return None

    def _parse_sessions(self, head):
        sess = None
        for off in MDS_SESSION_PTR_OFFS:
            if off + 4 > len(head):
                continue
            ptr = struct.unpack_from("<I", head, off)[0]
            if not (0 < ptr < self.file_size):
                continue
            cand = self._read_session_block(ptr)
            if cand is not None:
                self.session_ptr = ptr
                sess = cand
                break
        if sess is None:
            self.notes.append("未定位会话表（%d 个候选偏移均未通过结构校验）"
                              % len(MDS_SESSION_PTR_OFFS))
            return
        self.sessions = sess

    def _read_session_block(self, offset):
        """会话块自校验解析；失败返回 None"""
        blk = self._read(offset, 32)
        if len(blk) < 24:
            return None
        ntr = blk[12]
        first, last = blk[13], blk[14]
        if not (1 <= ntr <= 99 and 1 <= first <= 99 and last >= first
                and last - first + 1 == ntr):
            return None
        track_ptr = struct.unpack_from("<H", blk, 20)[0]
        tracks = []
        if 0 < track_ptr < 4096:
            for i in range(ntr):
                tb = self._read(offset + track_ptr + i * 0x50, 0x50)
                if len(tb) < 0x20:
                    break
                tracks.append({
                    "number": first + i,
                    "adr": tb[4] >> 4,
                    "control": tb[4] & 0x0F,
                    "index": _bcd(tb[5]) if tb[5] else 0,
                    "start_msf": "%02d:%02d:%02d" % (_bcd(tb[8]), _bcd(tb[9]), _bcd(tb[10])),
                    "start_lba": msf_to_lba("%02d:%02d:%02d"
                                            % (_bcd(tb[8]), _bcd(tb[9]), _bcd(tb[10]))) - LEADIN,
                    "length": struct.unpack_from("<I", tb, 0x14)[0] if len(tb) >= 0x18 else None,
                })
            for i, t in enumerate(tracks):
                nxt = tracks[i + 1] if i + 1 < len(tracks) else None
                t["end_lba"] = nxt["start_lba"] if nxt else None
        self.tracks = tracks
        return [{"index": 0, "num_tracks": ntr, "first_track": first,
                 "last_track": last, "track_table_offset": track_ptr,
                 "tracks": tracks}]

    def _read(self, offset, size):
        try:
            with open(self.path, "rb") as f:
                f.seek(offset)
                return f.read(size)
        except OSError:
            return b""

    def _refuse(self):
        raise NotImplementedError(
            "MDS/MDF 只识别头部与轨道表，不做数据抽取（版本间轨道块布局不一致）")

    def read(self, offset, size):
        self._refuse()

    def read_data(self, lba, count=1):
        self._refuse()

    def read_sector(self, lba):
        self._refuse()

    @property
    def size(self):
        return self.mdf_size or 0

    def info(self):
        return {
            "format": "mds",
            "path": self.path,
            "version": self.version,
            "medium_type": self.medium_type,
            "medium_name": self.medium_name,
            "session_count": self.session_count,
            "session_ptr": self.session_ptr,
            "sessions": [{"num_tracks": s["num_tracks"],
                          "first_track": s["first_track"],
                          "last_track": s["last_track"]} for s in self.sessions],
            "tracks": len(self.tracks),
            "track_detail": [dict(t) for t in self.tracks],
            "total_lba": self.total_lba,
            "mdf": self.mdf_path,
            "mdf_size": self.mdf_size,
            "header_hex": self.header_hex,
            "missing": list(self.missing),
            "notes": list(self.notes),
            "data_extraction": False,
        }

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __repr__(self):
        return "<Mds %r v%s sessions=%d tracks=%d>" % (
            os.path.basename(self.path), self.version, len(self.sessions),
            len(self.tracks))


MEDIUM_TYPES = {
    0x00: "CD-ROM", 0x01: "CD-I", 0x02: "CD-ROM XA", 0x03: "CD-R",
    0x04: "CD-RW", 0x05: "DVD-ROM", 0x06: "DVD-R", 0x07: "DVD-RW",
    0x08: "DVD+R", 0x09: "DVD+RW", 0x0A: "DVD-RAM", 0x10: "BD-ROM",
}


# ---------------- 子通道（SUB）----------------
def crc16_ccitt(data):
    """CRC16-CCITT（poly 0x1021，init 0），子通道 Q 用的是它的反码"""
    crc = 0
    for b in data:
        crc ^= (b & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


class SubChannel(object):
    """CloneCD 的 .sub：每扇区 96 字节 = P..W 共 8 通道 × 12 字节

    Q 通道 12 字节布局：
        0     ADR(高 4 位) + CONTROL(低 4 位)
        1     TNO（BCD）
        2     INDEX（BCD）
        3..5  轨内相对 MSF（BCD）
        6     0
        7..9  盘绝对 MSF（BCD）
        10..11 CRC16 反码（大端）
    P 通道在 CloneCD 里排在 Q 前面（Q 从 12 起），但也有 Q 在 0 的实现，
    所以两个位置都试，按 CRC 命中率定。
    """

    def __init__(self, path, record=SUB_RECORD):
        self.path = os.path.abspath(path)
        self.record = record
        self.size = os.path.getsize(self.path)
        self.sectors = self.size // record
        self.q_offset = self._detect_q_offset()

    def _read(self, offset, size):
        try:
            with open(self.path, "rb") as f:
                f.seek(offset)
                return f.read(size)
        except OSError:
            return b""

    def record_at(self, lba):
        return self._read(lba * self.record, self.record)

    @staticmethod
    def _safe_msf(mm, ss, ff):
        """BCD 解出来的三元组 -> (字符串, LBA)；非法返回 (None, None)"""
        if ss > 59 or ff > 74 or mm > 99:
            return None, None
        return "%02d:%02d:%02d" % (mm, ss, ff), (mm * 60 + ss) * FRAMES_PER_SEC + ff

    @classmethod
    def q_from(cls, rec, offset):
        if not rec or len(rec) < offset + 12:
            return None
        q = rec[offset:offset + 12]
        crc = struct.unpack(">H", q[10:12])[0]
        ok = ((~crc16_ccitt(q[:10])) & 0xFFFF) == crc
        rel_msf, _rel = cls._safe_msf(_bcd(q[3]), _bcd(q[4]), _bcd(q[5]))
        abs_msf, abs_frames = cls._safe_msf(_bcd(q[7]), _bcd(q[8]), _bcd(q[9]))
        return {
            "adr": q[0] >> 4,
            "control": q[0] & 0x0F,
            "tno": _bcd(q[1]),
            "index": _bcd(q[2]),
            "rel_msf": rel_msf,
            "abs_msf": abs_msf,
            "abs_lba": None if abs_frames is None else abs_frames - LEADIN,
            "crc": crc,
            "crc_ok": ok,
            "raw": q,
        }

    def _detect_q_offset(self):
        hits = {off: 0 for off in SUB_Q_OFFSETS}
        n = min(self.sectors, 64)
        for i in range(n):
            rec = self.record_at(i)
            for off in SUB_Q_OFFSETS:
                q = self.q_from(rec, off)
                if q and q["crc_ok"] and 1 <= q["adr"] <= 3:
                    hits[off] += 1
        best = max(hits, key=lambda o: hits[o])
        return best if hits[best] else SUB_Q_OFFSETS[0]

    def palette(self, lba):
        """返回该扇区 P..W 八个通道的 12 字节切片"""
        rec = self.record_at(lba)
        return {ch: rec[i * 12:(i + 1) * 12]
                for i, ch in enumerate("PQRSTUVW")}

    def q(self, lba):
        return self.q_from(self.record_at(lba), self.q_offset)

    def q_all(self, limit=None):
        n = self.sectors if limit is None else min(self.sectors, limit)
        for i in range(n):
            yield i, self.q(i)

    def track_starts(self):
        """扫出 {轨号: INDEX 01 的绝对 LBA}"""
        out = {}
        for lba, q in self.q_all():
            if not q or not q["crc_ok"] or q["adr"] < 1:
                continue
            if q["index"] == 1 and q["tno"] not in out:
                out[q["tno"]] = q["abs_lba"]
        return out

    def info(self):
        return {
            "format": "sub",
            "path": self.path,
            "size": self.size,
            "record": self.record,
            "sectors": self.sectors,
            "q_offset": self.q_offset,
        }

    def __repr__(self):
        return "<SubChannel %r sectors=%d q@%d>" % (
            os.path.basename(self.path), self.sectors, self.q_offset)


# ---------------- 探测 ----------------
def probe(path):
    """按扩展名 + 头部字节判类型：'cue' / 'ccd' / 'mds' / 'bin' / 'unknown'"""
    p = os.path.abspath(path)
    if not os.path.exists(p):
        return "unknown"
    try:
        with open(p, "rb") as f:
            head = f.read(32)
    except OSError:
        return "unknown"
    ext = os.path.splitext(p)[1].lower()
    if head.startswith(MDS_MAGIC):
        return "mds"
    if ext == ".mds":
        return "mds"
    if ext == ".ccd":
        return "ccd"
    if ext == ".cue":
        return "cue"
    if ext == ".sub":
        return "sub"
    if ext in (".bin", ".img", ".iso", ".mdf"):
        return "bin"
    # 内容判定：cue 是文本，头几行会出现 FILE/TRACK
    if head[:1] not in (b"\x00", b"\xff") and b"\x00" not in head:
        text, _enc = decode_text(head)
        up = text.upper()
        if "FILE" in up or "TRACK" in up or up.lstrip().startswith("["):
            return "cue" if "TRACK" in up else "ccd"
    if head.startswith(b"[CloneCD]"):
        return "ccd"
    if head[:6] == SYNC:
        return "bin"
    return "unknown"


# ---------------- 自检 ----------------
if __name__ == "__main__":
    import shutil
    import tempfile

    # ---- 合成扇区 ----
    def msf_header(lba):
        """12 字节同步 + 3 字节 BCD MSF（LBA+150）+ 1 字节 mode"""
        lba = lba + LEADIN
        return SYNC + bytes([_to_bcd(lba // (60 * FRAMES_PER_SEC)),
                             _to_bcd((lba // FRAMES_PER_SEC) % 60),
                             _to_bcd(lba % FRAMES_PER_SEC)])

    def mode1_sector(lba, data):
        data = _pad(data, 2048)
        return (msf_header(lba) + b"\x01" + data + b"\x00" * 288)

    def mode2_sector(lba, data, form=1, submode=None):
        sub = submode if submode is not None else (0x28 if form == 2 else 0x08)
        subh = bytes([0x00, 0x00, sub, 0x00]) * 2
        if form == 2:
            payload = _pad(data, 2324) + b"\x00" * 4          # 2324 + EDC
        else:
            payload = _pad(data, 2048) + b"\x00" * 4 + b"\x00" * 276
        body = msf_header(lba) + b"\x02" + subh + payload
        assert len(body) == 2352, len(body)
        return body

    # ---- 合成一个最小 ISO9660（轨道内 LBA 0 起）----
    def build_iso1024(payload=b"HELLO-BINCUE"):
        BLK = 2048
        img = bytearray(BLK * 24)
        pvd = bytearray(BLK)
        pvd[0] = 1
        pvd[1:6] = b"CD001"
        pvd[6] = 1
        pvd[8:40] = b"ESK-BINCUE".ljust(32)
        pvd[40:72] = b"ESK_VOL".ljust(32)
        struct.pack_into("<I", pvd, 80, 24)
        struct.pack_into(">I", pvd, 84, 24)
        struct.pack_into("<H", pvd, 128, BLK)
        struct.pack_into(">H", pvd, 130, BLK)

        root = bytearray(34)
        root[0] = 34
        struct.pack_into("<I", root, 2, 18)
        struct.pack_into(">I", root, 6, 18)
        struct.pack_into("<I", root, 10, BLK)
        struct.pack_into(">I", root, 14, BLK)
        root[25] = 0x02
        root[32] = 1
        root[33] = 0
        pvd[156:156 + 34] = root
        img[16 * BLK:17 * BLK] = pvd

        img[17 * BLK] = 255
        img[17 * BLK + 1:17 * BLK + 6] = b"CD001"

        d = bytearray(BLK)
        r = bytearray(34)
        r[0] = 34
        struct.pack_into("<I", r, 2, 18)
        struct.pack_into("<I", r, 10, BLK)
        r[25] = 0x02
        r[32] = 1
        d[0:34] = r
        r2 = bytearray(r)
        r2[33] = 1
        d[34:68] = r2
        name = b"HELLO.TXT;1"
        ln = 33 + len(name)
        if ln % 2:
            ln += 1
        r3 = bytearray(ln)
        r3[0] = ln
        struct.pack_into("<I", r3, 2, 19)
        struct.pack_into("<I", r3, 10, len(payload))
        r3[25] = 0x00
        r3[32] = len(name)
        r3[33:33 + len(name)] = name
        d[68:68 + ln] = r3
        img[18 * BLK:19 * BLK] = d
        img[19 * BLK:19 * BLK + len(payload)] = payload
        return bytes(img)

    def to_mode1_bin(iso_img, leadin=150):
        """2048 块流 → MODE1/2352，前面塞 leadin 帧"""
        out = bytearray()
        for i in range(leadin):
            out += mode1_sector(i, b"")
        n = (len(iso_img) + 2047) // 2048
        for i in range(n):
            out += mode1_sector(i, iso_img[i * 2048:(i + 1) * 2048])
        return bytes(out)

    # ---- SUB 记录 ----
    def q_record(tno, index, rel, abso, control=0x01, break_crc=False):
        q = bytearray(12)
        q[0] = ((1 << 4) | control) & 0xFF
        q[1] = _to_bcd(tno)
        q[2] = _to_bcd(index)
        q[3], q[4], q[5] = _to_bcd(rel[0]), _to_bcd(rel[1]), _to_bcd(rel[2])
        q[6] = 0
        q[7], q[8], q[9] = _to_bcd(abso[0]), _to_bcd(abso[1]), _to_bcd(abso[2])
        crc = (~crc16_ccitt(bytes(q[:10]))) & 0xFFFF
        if break_crc:
            crc ^= 0xFFFF
        q[10:12] = struct.pack(">H", crc)
        return bytes(q)

    tmp = tempfile.mkdtemp(prefix="esk_bincue_")
    try:
        # ========== 1. MSF / LBA ==========
        assert msf_to_lba("00:02:00") == 150, msf_to_lba("00:02:00")
        assert msf_to_lba("00:00:00") == 0
        assert msf_to_lba("01:00:00") == 4500
        assert msf_to_lba("00:00:74") == 74
        assert lba_to_msf(150) == "00:02:00", lba_to_msf(150)
        assert lba_to_msf(0) == "00:00:00"
        for lba in (0, 74, 75, 149, 150, 4499, 4500, 123456):
            assert msf_to_lba(lba_to_msf(lba)) == lba
        try:
            msf_to_lba("00:60:00")
        except ValueError:
            pass
        else:
            raise AssertionError("ss=60 应拒绝")
        print("[1] MSF/LBA 换算 ok（00:02:00 -> 150）")

        # ========== 2. MODE1/2352 单轨（含 150 帧 lead-in）==========
        t1 = os.path.join(tmp, "t1.bin")
        d1 = msf_header(0) + b"\x01" + b"MODE1-2352-A".ljust(2048, b"\x00") + b"\x00" * 288
        d2 = msf_header(1) + b"\x01" + b"MODE1-2352-B".ljust(2048, b"\x00") + b"\x00" * 288
        with open(t1, "wb") as f:
            f.write(b"\x00" * (150 * 2352) + d1 + d2)
        cue1 = os.path.join(tmp, "t1.cue")
        with open(cue1, "w", encoding="utf-8", newline="\n") as f:
            f.write('REM 合成单轨\nCATALOG 1234567890123\nTITLE "测试盘"\n'
                    'FILE "t1.bin" BINARY\n'
                    '  TRACK 01 MODE1/2352\n    INDEX 01 00:02:00\n')
        bc = BinCue.open(cue1)
        tr = bc.cue.tracks()
        assert len(tr) == 1, len(tr)
        assert tr[0].number == 1 and tr[0].mode == "MODE1/2352"
        assert tr[0].sector_size == 2352 and tr[0].file_offset == 150 * 2352
        assert tr[0].start_lba == 150, tr[0].start_lba
        assert tr[0].pregap == 0
        assert bc.cue.total_lba == 152, bc.cue.total_lba
        assert bc.size == 152 * 2048, bc.size
        assert bc.cue.read_data(150, 1)[:12] == b"MODE1-2352-A"
        assert bc.cue.read_data(151, 1)[:12] == b"MODE1-2352-B"
        assert bc.cue.read_data(0, 1) == b"\x00" * 2048
        s = bc.cue.read_sector(150)
        assert len(s) == 2352 and s[:12] == SYNC and s[15] == 1
        assert bc.read(150 * 2048, 12) == b"MODE1-2352-A"
        assert bc.read(0, 4) == b"\x00" * 4
        assert bc.read(bc.size, 4) == b""
        assert bc.read(-1, 4) == b""
        assert bc.cue.info()["catalog"] == "1234567890123"
        assert bc.cue.title == "测试盘", bc.cue.title
        print("[2] MODE1/2352 单轨 ok：start_lba=150 file_offset=%d 用户数据=%r"
              % (tr[0].file_offset, bc.cue.read_data(150, 1)[:12]))

        # ========== 3. MODE2/2352 Form1+Form2 + 多轨 + 合成 pregap ==========
        t2 = os.path.join(tmp, "t2.bin")
        f1 = mode2_sector(0, b"FORM1-AAAA", form=1)
        f2 = mode2_sector(1, b"FORM2-" + b"B" * 2318, form=2)
        f3 = mode2_sector(2, b"FORM1-CCCC", form=1)
        f4 = mode2_sector(3, b"FORM1-DDDD", form=1)
        with open(t2, "wb") as f:
            f.write(f1 + f2 + f3 + f4)
        t3 = os.path.join(tmp, "t3.bin")
        with open(t3, "wb") as f:
            for i in range(4):
                f.write(b"PLAIN-2048-%d" % i + b"." * (2048 - 12))
        cue2 = os.path.join(tmp, "t2.cue")
        with open(cue2, "w", encoding="utf-8", newline="\n") as f:
            f.write('FILE "t2.bin" BINARY\n'
                    '  TRACK 02 MODE2/2352\n    INDEX 01 00:00:00\n'
                    '  TRACK 03 MODE2/2352\n'
                    '    PREGAP 00:00:10\n'
                    '    INDEX 01 00:00:02\n'
                    'FILE "t3.bin" BINARY\n'
                    '  TRACK 04 MODE1/2048\n    INDEX 01 00:00:01\n')
        bc2 = BinCue.open(cue2)
        tks = bc2.cue.tracks()
        assert [t.number for t in tks] == [2, 3, 4], [t.number for t in tks]
        assert len(bc2.cue.files) == 2
        assert tks[0].start_lba == 0 and tks[0].length == 2, (tks[0].start_lba, tks[0].length)
        assert tks[1].pregap == 10 and tks[1].pregap_in_file is False
        assert tks[1].start_lba == 12, tks[1].start_lba
        assert tks[2].mode == "MODE1/2048" and tks[2].start_lba == 15, tks[2].start_lba
        assert bc2.cue.total_lba == 18, bc2.cue.total_lba
        # Form 判定
        assert bc2.cue.form(0) == 1 and bc2.cue.form(1) == 2, (bc2.cue.form(0), bc2.cue.form(1))
        assert len(bc2.cue.read_user_raw(0)) == 2048
        assert len(bc2.cue.read_user_raw(1)) == 2324
        assert bc2.cue.read_data(0, 1)[:10] == b"FORM1-AAAA"
        assert bc2.cue.read_data(1, 1)[:6] == b"FORM2-"
        # pregap 全零
        gap = bc2.cue.read_data(2, 10)
        assert gap == b"\x00" * (10 * 2048), "合成 pregap 应全零"
        assert bc2.cue.read_data(12, 1)[:10] == b"FORM1-CCCC", \
            (bc2.cue.read_data(12, 1)[:16], bc2.cue.track_at(12),
             bc2.cue.total_lba, [t.start_lba for t in bc2.cue.tracks()])
        assert bc2.cue.read_data(13, 1)[:10] == b"FORM1-DDDD"
        assert bc2.cue.read_data(14, 1) == b"\x00" * 2048
        assert bc2.cue.read_data(15, 1)[:12] == b"PLAIN-2048-1"
        assert bc2.cue.read_data(17, 1)[:12] == b"PLAIN-2048-3"
        # 跨扇区字节读
        # 跨扇区字节读：等价于两扇区拼接
        assert bc2.read(15 * 2048 + 2040, 16) == \
            (bc2.cue.read_data(15, 1)[2040:] + bc2.cue.read_data(16, 1)[:8])
        assert bc2.cue.read_data(1, 1)[2040:2048] == b"B" * 8      # Form2 截到 2048
        print("[3] 多轨/多文件 ok：Form1=2048 Form2=2324 pregap(2..11) 全零 总LBA=%d"
              % bc2.cue.total_lba)

        # ========== 4. iso() 把 MODE1/2352 数据区当 ISO ==========
        t4 = os.path.join(tmp, "iso.bin")
        payload = b"HELLO-BINCUE"
        with open(t4, "wb") as f:
            f.write(to_mode1_bin(build_iso1024(payload), leadin=150))
        cue3 = os.path.join(tmp, "iso.cue")
        with open(cue3, "w", encoding="utf-8", newline="\n") as f:
            f.write('FILE "iso.bin" BINARY\n  TRACK 01 MODE1/2352\n'
                    '    INDEX 01 00:02:00\n')
        bc3 = BinCue.open(cue3)
        iso = bc3.iso()
        assert iso.info()["volume_id"] == "ESK_VOL", iso.info()
        names = [e.name for e in iso.root_dir()]
        assert "HELLO.TXT" in names, names
        ent = [e for e in iso.root_dir() if e.name.startswith("HELLO")][0]
        assert iso.read_file(ent) == payload, iso.read_file(ent)
        print("[4] iso() ok：vol=%r 目录=%r 文件=%r"
              % (iso.info()["volume_id"], names, iso.read_file(ent)))

        # ========== 5. INDEX 00 预间隙 + 编码探测 ==========
        t5 = os.path.join(tmp, "t5.bin")
        with open(t5, "wb") as f:
            for i in range(6):
                f.write(mode1_sector(i, b"IDX00-GAP-%d" % i if i < 2 else b"IDX01-DATA-%d" % i))
        gbk_cue = os.path.join(tmp, "gbk.cue")
        body = ('TITLE "中文测试盘"\r\nPERFORMER "某人"\r\n'
                'FILE "t5.bin" BINARY\r\n'
                '  TRACK 01 MODE1/2352\r\n'
                '    INDEX 00 00:00:00\r\n    INDEX 01 00:00:02\r\n')
        with open(gbk_cue, "wb") as f:
            f.write(body.encode("gbk"))
        cs = CueSheet.parse(gbk_cue)
        assert cs.encoding == "gbk", cs.encoding
        assert cs.title == "中文测试盘", cs.title
        assert cs.performer == "某人"
        tk = cs.tracks()[0]
        assert tk.pregap == 2 and tk.pregap_in_file is True, (tk.pregap, tk.pregap_in_file)
        assert tk.indexes[0] == 0 and tk.indexes[1] == 2
        assert cs.read_data(2, 1)[:12] == b"IDX01-DATA-2"
        assert cs.read_sector_raw(0)[16:27] == b"IDX00-GAP-0"      # 物理预间隙可读
        assert cs.read_user_raw(0)[:11] == b"IDX00-GAP-0"          # 同上（用户窗口）
        assert cs.read_data(0, 1) == b"\x00" * 2048                # 逻辑流不含预间隙
        print("[5] INDEX 00 预间隙 ok：pregap=%d(文件内) 物理=%r 逻辑=零 编码=%s"
              % (tk.pregap, cs.read_sector_raw(0)[16:28], cs.encoding))

        # ========== 6. CCD ==========
        ccd = os.path.join(tmp, "disc.ccd")
        with open(ccd, "w", encoding="utf-8", newline="\r\n") as f:
            f.write("[CloneCD]\nVersion=3\n\n[Disc]\nTocEntries=3\nSessions=1\n"
                    "DataTracksScrambled=0\nCDTextLength=0\n\n"
                    "[Entry 0]\nSession=1\nPoint=0x01\nADR=0x01\nControl=0x04\n"
                    "TrackNo=1\nAMin=0\nASec=2\nAFrame=0\nALBA=0\n\n"
                    "[Entry 1]\nSession=1\nPoint=0x01\nADR=0x01\nControl=0x04\n"
                    "TrackNo=1\nAMin=0\nASec=4\nAFrame=0\nALBA=150\n\n"
                    "[Entry 2]\nSession=1\nPoint=0xa2\nADR=0x01\nControl=0x04\n"
                    "TrackNo=0\nAMin=10\nASec=0\nAFrame=0\nALBA=4350\n")
        with open(os.path.join(tmp, "disc.img"), "wb") as f:
            f.write(b"\x00" * 4096)
        cc = CloneCD(ccd)
        assert cc.version == "3" and cc.sessions == 1
        assert len(cc.tracks) == 2, cc.tracks
        assert cc.tracks[0]["start_lba"] == 0 and cc.tracks[0]["is_data"]
        assert cc.leadout_lba == (10 * 60) * 75 - 150, cc.leadout_lba
        assert cc.tracks[1]["start_lba"] == 150
        try:
            cc.read_data(0, 1)
        except NotImplementedError:
            pass
        else:
            raise AssertionError("CCD 数据抽取应抛 NotImplementedError")
        assert cc.info()["data_extraction"] is False
        print("[6] CCD ok：tracks=%d leadout=%d 数据抽取=NotImplemented"
              % (len(cc.tracks), cc.leadout_lba))

        # ========== 7. MDS ==========
        mds = os.path.join(tmp, "disc.mds")
        hdr = bytearray(MDS_HEADER_SIZE)
        hdr[0:16] = MDS_MAGIC
        hdr[0x10:0x14] = bytes([1, 10, 0, 0])
        struct.pack_into("<H", hdr, 0x14, 0x00)
        struct.pack_into("<H", hdr, 0x16, 1)
        struct.pack_into("<I", hdr, 0x50, MDS_HEADER_SIZE)      # 会话表紧跟头部
        sess = bytearray(32)
        sess[12] = 1                                            # 轨道数
        sess[13] = 1                                            # 首轨
        sess[14] = 1                                            # 末轨
        struct.pack_into("<H", sess, 20, 32)                    # 轨道块偏移
        trk = bytearray(0x50)
        trk[4] = (1 << 4) | 0x04                                # ADR=1 CTRL=4
        trk[5] = 1
        trk[8], trk[9], trk[10] = 0, 2, 0                       # 00:02:00
        struct.pack_into("<I", trk, 0x14, 1000)                 # 长度帧
        with open(mds, "wb") as f:
            f.write(bytes(hdr) + bytes(sess) + bytes(trk))
        with open(os.path.join(tmp, "disc.mdf"), "wb") as f:
            f.write(b"\x00" * 2048)
        md = Mds(mds)
        assert md.version == "1.10", md.version
        assert md.medium_type == 0 and md.session_count == 1
        assert md.sessions and md.sessions[0]["num_tracks"] == 1, md.info()
        assert md.tracks[0]["number"] == 1 and md.tracks[0]["start_lba"] == 0
        assert md.tracks[0]["length"] == 1000
        try:
            md.read(0, 2048)
        except NotImplementedError:
            pass
        else:
            raise AssertionError("MDS 数据抽取应抛 NotImplementedError")
        print("[7] MDS ok：v%s 介质=%r 会话=%d 轨道=%d 数据抽取=NotImplemented"
              % (md.version, md.medium_name, len(md.sessions), len(md.tracks)))

        # ========== 8. SUB 的 Q 通道 ==========
        sub = os.path.join(tmp, "disc.sub")

        def sub_record(pbyte, q):
            rec = (bytes([pbyte]) * 12) + q + b"\x00" * 72      # P(12)+Q(12)+R..W(72)
            assert len(rec) == SUB_RECORD, len(rec)
            return rec

        recs = bytearray()
        recs += sub_record(0xFF, q_record(1, 0, (0, 0, 0), (0, 2, 0)))
        recs += sub_record(0x00, q_record(1, 1, (0, 0, 0), (0, 2, 1)))
        recs += sub_record(0x00, q_record(2, 1, (0, 0, 0), (0, 2, 3)))
        recs += sub_record(0x00, q_record(2, 1, (0, 0, 0), (0, 2, 4), break_crc=True))
        with open(sub, "wb") as f:
            f.write(bytes(recs))
        sc = SubChannel(sub)
        assert sc.sectors == 4 and sc.q_offset == 12, (sc.sectors, sc.q_offset)
        q0 = sc.q(0)
        assert q0["crc_ok"] and q0["adr"] == 1 and q0["control"] == 1, q0
        assert q0["tno"] == 1 and q0["index"] == 0 and q0["abs_msf"] == "00:02:00"
        assert q0["abs_lba"] == 0, q0["abs_lba"]
        assert sc.q(1)["index"] == 1 and sc.q(1)["abs_lba"] == 1
        assert sc.q(3)["crc_ok"] is False
        assert sc.track_starts() == {1: 1, 2: 3}, sc.track_starts()
        assert len(sc.palette(0)["P"]) == 12 and len(sc.palette(0)["W"]) == 12
        print("[8] SUB ok：Q@%d tno/index=%d/%d MSF=%s CRC=%s 轨起点=%r"
              % (sc.q_offset, q0["tno"], q0["index"], q0["abs_msf"],
                 q0["crc_ok"], sc.track_starts()))

        # ========== 9. probe ==========
        assert probe(cue1) == "cue", probe(cue1)
        assert probe(t1) == "bin", probe(t1)
        assert probe(ccd) == "ccd"
        assert probe(mds) == "mds"
        assert probe(sub) == "sub"
        assert probe(os.path.join(tmp, "nonexist.cue")) == "unknown"
        txt = os.path.join(tmp, "noext")
        with open(txt, "w", encoding="utf-8") as f:
            f.write('FILE "t1.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:02:00\n')
        assert probe(txt) == "cue", probe(txt)
        print("[9] probe ok：cue/bin/ccd/mds/sub/unknown 全命中")

        # ========== 10. 缺失文件容错 + 模式归一 ==========
        badcue = os.path.join(tmp, "missing.cue")
        with open(badcue, "w", encoding="utf-8") as f:
            f.write('FILE "nope.bin" BINARY\n  TRACK 01 MODE2/2336\n'
                    '    INDEX 01 00:00:00\n')
        bc4 = BinCue.open(badcue)
        assert "nope.bin" in bc4.missing, bc4.missing
        assert bc4.cue.read_data(0, 1) == b"\x00" * 2048
        assert _normalize_mode("CDI/2352") == "CDI/2352"
        assert _normalize_mode("MODE2/2352") == "MODE2/2352"
        print("[10] 缺失文件容错 ok：missing=%r（读出零，不崩）" % (bc4.missing,))

        for o in (bc, bc2, bc3, bc4):
            o.close()
        print("自检通过")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
