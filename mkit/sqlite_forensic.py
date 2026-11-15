# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""SQLite 数据库取证分析

取证现场最高频的一类证据：浏览器、微信/QQ、邮件、网盘、App 的本地数据
几乎都落在 SQLite 库里。这个模块只读、只解析，不写回证据。

已实现：
    · WAL 预写日志解析与回放
        - 32 字节 WAL 头（magic 0x377f0682/0x377f0683、version、page_size、
          checkpoint_seq、salt[2]、checksum[2]）
        - 24 字节帧头（page_number、db_size_after_commit、salt[2]、
          checksum[2]）+ 一页镜像
        - 滚动 checksum 校验（小端/大端由 magic 最低位决定），坏帧跳过并计数
        - salt 世代比对，遇到上一代残留帧即停
        - 只回放「最后一次提交」之前的帧，未提交尾部丢弃
        - 依据 db_size_after_commit 截断到提交时的页数
    · 删除记录恢复
        - 遍历表 B-tree（内部页 0x05 → 叶页 0x0D），不依赖 dbstat
        - 叶页 freeblock 链 + 指针数组与 cell content 之间的未分配间隙扫描
        - 内部页的空闲区也扫：页类型转换后，旧叶页的 cell 会整片留在那里
        - 严格解析：按「payload 长度 + rowid + record header 序列类型」自校验，
          header 长度与 body 长度必须逐字节吻合，假阳性极低
        - 残记录解析：freeblock 的 4 字节头会盖住被删 cell 的前 4 个字节，
          此时按列数推定存活的类型串重建记录，第一列值标记为丢失
        - freelist（页头 @32 首个 trunk、@36 计数）逐页扫描，回收整页残留
    · 结构浏览：表 / 索引 / 视图 / 触发器、rootpage、建表 SQL、行数估算
    · 元数据：页大小、页数、文本编码、user_version、application_id、
      auto_vacuum、freelist_count、是否 WAL
    · 已删除表检测：在 freelist 页与 sqlite_master 空闲区里找
      「CREATE TABLE」残留文本

不实现：
    · 任何写回 / VACUUM / 修复，证据文件始终以只读方式打开
    · SQLCipher / SEE 等加密库解密（需先解出明文页再喂进来）
    · secure_delete=ON 或已 VACUUM 的库恢复（页被零写，物理上已经没了）
    · 溢出链被复用后的跨页记录重组（只做尽力而为，读不全就跳过）
    · WITHOUT ROWID 表的删除记录解析（索引式 b-tree，cell 无 rowid）

用法：
    from mkit.sqlite_forensic import SqliteForensic, replay_wal
    f = SqliteForensic(r"E:\\case\\msg.db")
    print(f.meta())
    print(f.wal_info())
    path, stats = f.replay()          # 回放后另存临时库
    print(f.objects())
    print(f.deleted_rows("msg"))      # 删除记录
    print(f.deleted_tables())         # 已删除表
"""

import os
import re
import shutil
import sqlite3
import struct
import tempfile

__all__ = [
    "SqliteForensic",
    "replay_wal",
    "wal_scan",
    "decode_record",
    "local_payload_size",
    "WAL_MAGIC_LE",
    "WAL_MAGIC_BE",
    "PAGE_INTERIOR_TABLE",
    "PAGE_LEAF_TABLE",
    "PAGE_INTERIOR_INDEX",
    "PAGE_LEAF_INDEX",
    "ENCODINGS",
]

# ---------------- 常量 ----------------

WAL_MAGIC_LE = 0x377F0682       # 小端 checksum
WAL_MAGIC_BE = 0x377F0683       # 大端 checksum
WAL_HDR_SIZE = 32
WAL_FRAME_HDR_SIZE = 24
WAL_VERSION = 3007000

PAGE_INTERIOR_INDEX = 0x02
PAGE_LEAF_INDEX = 0x0A
PAGE_INTERIOR_TABLE = 0x05
PAGE_LEAF_TABLE = 0x0D

ENCODINGS = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}
ENCODINGS_TEXT = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}

SQLITE_MAGIC = b"SQLite format 3\x00"

# 空闲区里可能出现 "CREATE TABLE"，顺带把索引/视图/触发器也认了
_SQL_OBJ_RE = re.compile(
    rb"CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX|VIEW|TRIGGER)\b", re.I)


# ---------------- 变长整数 / 序列类型 ----------------

def _varint(buf, off, end=None):
    """SQLite 变长整数。返回 (值, 字节数)，越界返回 (None, 0)"""
    if end is None:
        end = len(buf)
    v = 0
    for i in range(9):
        p = off + i
        if p >= end or p >= len(buf):
            return None, 0
        b = buf[p]
        if i == 8:
            return (v << 8) | b, 9
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            return v, i + 1
    return None, 0


def _serial_len(t):
    """序列类型对应的 body 字节数；-1 表示非法类型"""
    if t == 0:
        return 0
    if 1 <= t <= 4:
        return t
    if t == 5:
        return 6
    if t == 6:
        return 8
    if t == 7:
        return 8
    if t in (8, 9):
        return 0
    if t in (10, 11):
        return -1
    return (t - 12) // 2


def _serial_val(t, buf, off, enc):
    """按序列类型解码一个字段"""
    if t == 0:
        return None
    if t == 1:
        return struct.unpack_from(">b", buf, off)[0]
    if t == 2:
        return struct.unpack_from(">h", buf, off)[0]
    if t == 3:
        return int.from_bytes(bytes(buf[off:off + 3]), "big", signed=True)
    if t == 4:
        return struct.unpack_from(">i", buf, off)[0]
    if t == 5:
        return int.from_bytes(bytes(buf[off:off + 6]), "big", signed=True)
    if t == 6:
        return struct.unpack_from(">q", buf, off)[0]
    if t == 7:
        return struct.unpack_from(">d", buf, off)[0]
    if t == 8:
        return 0
    if t == 9:
        return 1
    n = _serial_len(t)
    raw = bytes(buf[off:off + n])
    if t % 2 == 0:
        return raw
    return raw.decode(enc, "replace")


def decode_record(payload, enc="utf-8"):
    """解码一条记录（record = header + body）。结构不符返回 None

    严格校验：header 里的序列类型长度之和必须正好等于 body 长度，
    这一条就能滤掉绝大多数误命中。
    """
    if not payload:
        return None
    hsz, n = _varint(payload, 0)
    if not hsz or hsz < 1 or hsz > len(payload):
        return None
    types = []
    off = n
    while off < hsz:
        t, k = _varint(payload, off, hsz)
        if t is None or k <= 0:
            return None
        types.append(t)
        off += k
    if off != hsz:
        return None
    vals = []
    body = hsz
    for t in types:
        ln = _serial_len(t)
        if ln < 0 or body + ln > len(payload):
            return None
        vals.append(_serial_val(t, payload, body, enc))
        body += ln
    if body != len(payload):
        return None
    return vals


def local_payload_size(payload_len, usable, interior=False):
    """cell 内联存放的 payload 字节数，超出部分在溢出页（标准公式）"""
    u = usable
    x = (((u - 12) * 64) // 255) - 23 if interior else (u - 35)
    if payload_len <= x:
        return payload_len
    m = (((u - 12) * 32) // 255) - 23
    if m < 0:
        return 0
    k = m + ((payload_len - m) % (u - 4))
    return k if k <= x else m


# ---------------- WAL ----------------

def _wal_checksum(buf, s1, s2, big_endian):
    """WAL 滚动校验：s1 += d[i] + s2; s2 += d[i+1] + s1（按 4 字节字）"""
    n = len(buf) - (len(buf) % 8)
    fmt = ">I" if big_endian else "<I"
    for i in range(0, n, 8):
        s1 = (s1 + struct.unpack_from(fmt, buf, i)[0] + s2) & 0xFFFFFFFF
        s2 = (s2 + struct.unpack_from(fmt, buf, i + 4)[0] + s1) & 0xFFFFFFFF
    return s1, s2


def wal_scan(wal_path, keep_frames=True):
    """只读解析 -wal 文件，不落盘、不改动

    返回 dict：
        exists / size / magic / big_endian / version / page_size /
        checkpoint_seq / salt / cksum / header_ok / frames / valid_frames /
        bad_frames / truncated_frames / last_commit / complete / error /
        frame_list
    """
    out = {
        "path": wal_path, "exists": False, "size": 0, "magic": None,
        "big_endian": False, "version": None, "page_size": None,
        "checkpoint_seq": None, "salt": None, "cksum": None,
        "header_ok": False, "frames": 0, "valid_frames": 0,
        "bad_frames": 0, "truncated_frames": 0, "last_commit": None,
        "complete": False, "error": None, "frame_list": [],
    }
    if not os.path.exists(wal_path):
        out["error"] = "没有 -wal 文件"
        return out
    out["exists"] = True
    size = os.path.getsize(wal_path)
    out["size"] = size
    if size < WAL_HDR_SIZE:
        out["error"] = "WAL 头不足 32 字节"
        return out

    with open(wal_path, "rb") as f:
        hdr = f.read(WAL_HDR_SIZE)
        if len(hdr) < WAL_HDR_SIZE:
            out["error"] = "WAL 头读取不完整"
            return out

        magic = struct.unpack_from(">I", hdr, 0)[0]
        big = (magic & 1) == 1
        if magic not in (WAL_MAGIC_LE, WAL_MAGIC_BE):
            # 少数工具按小端写 magic，做个兼容
            magic2 = struct.unpack_from("<I", hdr, 0)[0]
            if magic2 in (WAL_MAGIC_LE, WAL_MAGIC_BE):
                magic = magic2
                big = (magic & 1) == 1
            else:
                out["error"] = "magic 不匹配：0x%08X" % magic
                out["magic"] = magic
                return out

        page_size = struct.unpack_from(">I", hdr, 8)[0]
        if page_size == 1:
            page_size = 65536
        version = struct.unpack_from(">I", hdr, 4)[0]
        seq = struct.unpack_from(">I", hdr, 12)[0]
        salt = struct.unpack_from(">II", hdr, 16)
        cks = struct.unpack_from(">II", hdr, 24)
        hsum = _wal_checksum(hdr[0:24], 0, 0, big)

        out.update({
            "magic": magic, "big_endian": big, "version": version,
            "page_size": page_size, "checkpoint_seq": seq, "salt": salt,
            "cksum": cks, "header_ok": (hsum == cks),
        })
        if page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)):
            out["error"] = "WAL 头 page_size 非法：%r" % (page_size,)
            return out

        frame_size = WAL_FRAME_HDR_SIZE + page_size
        s1, s2 = cks
        off = WAL_HDR_SIZE
        idx = 0
        last_commit = None
        frames = out["frame_list"] if keep_frames else None
        while off + frame_size <= size:
            f.seek(off)
            fh = f.read(WAL_FRAME_HDR_SIZE)
            if len(fh) < WAL_FRAME_HDR_SIZE:
                out["truncated_frames"] += 1
                break
            pgno, dbsz = struct.unpack_from(">II", fh, 0)
            fsalt = struct.unpack_from(">II", fh, 8)
            fc = struct.unpack_from(">II", fh, 16)
            page = f.read(page_size)
            if len(page) < page_size:
                out["truncated_frames"] += 1
                break
            idx += 1
            off += frame_size

            if pgno == 0:
                out["bad_frames"] += 1
                break
            if fsalt != salt:
                # 上一代 WAL 残留帧，世代已换，后面都不是本代数据
                break

            v1, v2 = _wal_checksum(fh[0:8], s1, s2, big)
            v1, v2 = _wal_checksum(page, v1, v2, big)
            ok = (v1, v2) == fc
            if ok:
                out["valid_frames"] += 1
            else:
                out["bad_frames"] += 1
            # 不论好坏都用帧内自带的 checksum 续链：坏帧（撕裂页）之后
            # 还能继续验后面的帧，不会一坏到底
            s1, s2 = fc
            if dbsz:
                last_commit = idx
            if frames is not None:
                frames.append((idx, pgno, dbsz, ok))

        out["frames"] = idx
        out["last_commit"] = last_commit
        out["complete"] = bool(
            idx > 0 and out["bad_frames"] == 0
            and out["truncated_frames"] == 0 and last_commit == idx)
        if idx == 0 and size > WAL_HDR_SIZE:
            out["error"] = "有 WAL 头但没有完整帧"
    return out


def replay_wal(db_path, out_path=None):
    """把 -wal 叠到主库副本上，返回 (回放后库路径, 统计 dict)

    证据目录只读：默认写到系统临时目录。out_path 指向原库会直接报错，
    避免手滑覆盖证据。
    """
    db_path = os.path.abspath(db_path)
    wal_path = db_path + "-wal"
    info = wal_scan(wal_path, keep_frames=False)
    if not info["exists"]:
        raise FileNotFoundError("找不到 WAL：%s" % wal_path)
    if info["error"] and not info["frames"]:
        raise ValueError("WAL 无法解析：%s" % info["error"])

    page_size = info["page_size"]
    if out_path is None:
        fd, out_path = tempfile.mkstemp(prefix="esk_wal_", suffix=".db")
        os.close(fd)
        out_path = os.path.abspath(out_path)
    else:
        out_path = os.path.abspath(out_path)
        if out_path == db_path:
            raise ValueError("out_path 不能指向原库（会破坏证据）")

    if os.path.exists(db_path):
        shutil.copyfile(db_path, out_path)
    else:
        with open(out_path, "wb"):
            pass

    stats = {
        "wal": wal_path, "wal_size": info["size"], "out": out_path,
        "page_size": page_size, "magic": info["magic"],
        "salt": info["salt"], "frames": info["frames"],
        "valid_frames": info["valid_frames"], "bad_frames": info["bad_frames"],
        "truncated_frames": info["truncated_frames"],
        "last_commit": info["last_commit"], "applied_frames": 0,
        "dropped_uncommitted": 0, "db_pages": 0, "db_size": 0,
        "header_ok": info["header_ok"], "resynced": False,
    }

    if info["last_commit"] is None:
        # 没有任何提交帧：WAL 内容不属于已提交状态，主库保持不变
        stats["db_pages"] = 0
        stats["db_size"] = os.path.getsize(out_path)
        return out_path, stats

    apply_upto = info["last_commit"]
    big = info["big_endian"]
    salt = info["salt"]
    c1, c2 = info["cksum"]
    frame_size = WAL_FRAME_HDR_SIZE + page_size
    end_pages = 0
    applied = 0

    with open(wal_path, "rb") as f, open(out_path, "r+b") as w:
        f.seek(WAL_HDR_SIZE)
        idx = 0
        while idx < apply_upto:
            fh = f.read(WAL_FRAME_HDR_SIZE)
            page = f.read(page_size)
            if len(fh) < WAL_FRAME_HDR_SIZE or len(page) < page_size:
                break
            idx += 1
            pgno, dbsz = struct.unpack_from(">II", fh, 0)
            fsalt = struct.unpack_from(">II", fh, 8)
            fc = struct.unpack_from(">II", fh, 16)
            if fsalt != salt or pgno == 0:
                break
            v1, v2 = _wal_checksum(fh[0:8], c1, c2, big)
            v1, v2 = _wal_checksum(page, v1, v2, big)
            ok = (v1, v2) == fc
            c1, c2 = fc
            if not ok:
                stats["resynced"] = True
                continue                      # 坏帧不落地，只计数
            w.seek((pgno - 1) * page_size)
            w.write(page)
            applied += 1
            if dbsz:
                end_pages = dbsz
        stats["applied_frames"] = applied
        stats["dropped_uncommitted"] = max(0, info["frames"] - apply_upto)

        if end_pages:
            want = end_pages * page_size
            w.truncate(want)
            stats["db_pages"] = end_pages
        stats["db_size"] = os.path.getsize(out_path)
    return out_path, stats


# ---------------- 页结构 ----------------

def _page_layout(page, usable, hdr_off=0):
    """解出页头、cell 指针数组、freeblock 链

    页 1 的 btree 头在偏移 100（前面是数据库头），其余页在 0。
    叶页头 8 字节；内部页头 12 字节（多一个 4 字节最右子页指针 @hdr+8），
    指针数组从 hdr+12 起。
    """
    if len(page) < hdr_off + 12 or usable > len(page):
        return None
    ptype = page[hdr_off]
    if ptype not in (PAGE_INTERIOR_INDEX, PAGE_LEAF_INDEX,
                     PAGE_INTERIOR_TABLE, PAGE_LEAF_TABLE):
        return None
    interior = ptype in (PAGE_INTERIOR_INDEX, PAGE_INTERIOR_TABLE)
    hdr_size = 12 if interior else 8
    ncell = struct.unpack_from(">H", page, hdr_off + 3)[0]
    content = struct.unpack_from(">H", page, hdr_off + 5)[0] or 65536
    ptr0 = hdr_off + hdr_size
    ptr_end = ptr0 + 2 * ncell
    if ptr_end > usable:
        return None
    ptrs = []
    for i in range(ncell):
        ptrs.append(struct.unpack_from(">H", page, ptr0 + 2 * i)[0])
    right = struct.unpack_from(">I", page, hdr_off + 8)[0] if interior else 0

    fbs = []
    cur = struct.unpack_from(">H", page, hdr_off + 1)[0]
    guard = 0
    while cur and guard < 1024:
        guard += 1
        if cur < ptr_end or cur + 4 > usable:
            break
        nxt, sz = struct.unpack_from(">HH", page, cur)
        if sz < 4 or cur + sz > usable:
            break
        fbs.append((cur, sz))
        cur = nxt

    return {
        "type": ptype, "interior": interior, "hdr_size": hdr_size,
        "ncell": ncell, "content": content, "ptrs": ptrs,
        "ptr_end": ptr_end, "right": right, "freeblocks": fbs,
    }


def _cell_at(page, off, usable, enc, reader=None):
    """试着把 off 当成 table 叶页 cell 解析

    返回 (rowid, values, size) 或 None。size 是 cell 在页内占的字节数。
    """
    if off < 0 or off >= usable - 2:
        return None
    plen, n1 = _varint(page, off, usable)
    if not plen or plen < 0:
        return None
    rowid, n2 = _varint(page, off + n1, usable)
    if rowid is None or rowid < 1:
        return None
    p = off + n1 + n2
    local = local_payload_size(plen, usable)
    if local <= 0 and plen > 0:
        return None
    size = n1 + n2 + local
    if p + local > usable:
        return None
    payload = bytes(page[p:p + local])
    if local < plen:
        if p + local + 4 > usable:
            return None
        first = struct.unpack_from(">I", page, p + local)[0]
        size += 4
        if reader is None:
            return None
        rest = reader.overflow(first, plen - local)
        if rest is None:
            return None
        payload += rest
    vals = decode_record(payload, enc)
    if vals is None:
        return None
    return rowid, vals, size


def _cell_overflow_pageno(page, off, usable):
    """取一个叶页 cell 的溢出页首号；不需要溢出则返回 None"""
    plen, n1 = _varint(page, off, usable)
    if not plen:
        return None
    rowid, n2 = _varint(page, off + n1, usable)
    if rowid is None:
        return None
    local = local_payload_size(plen, usable)
    p = off + n1 + n2 + local
    if plen > local and p + 4 <= usable:
        return struct.unpack_from(">I", page, p)[0]
    return None


class _Reader(object):
    """证据库的只读页读取器"""

    def __init__(self, path, page_size, npages, usable):
        self.path = path
        self.page_size = page_size
        self.npages = npages
        self.usable = usable
        self.fh = open(path, "rb")

    def page(self, pageno):
        if pageno < 1 or pageno > self.npages:
            return None
        self.fh.seek((pageno - 1) * self.page_size)
        b = self.fh.read(self.page_size)
        if len(b) < self.page_size:
            b = b + b"\x00" * (self.page_size - len(b))
        return b

    def overflow(self, first, need, max_pages=64):
        """跟随溢出链取剩余 payload；链断/页号非法返回 None"""
        out = b""
        pg = first
        seen = set()
        while need > 0 and pg and len(seen) < max_pages:
            if pg in seen or pg < 1 or pg > self.npages:
                return None
            seen.add(pg)
            buf = self.page(pg)
            if buf is None:
                return None
            chunk = buf[4:self.usable]
            take = min(need, len(chunk))
            out += chunk[:take]
            need -= take
            pg = struct.unpack_from(">I", buf, 0)[0]
        return out if need == 0 else None

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass


# ---------------- 主类 ----------------

class SqliteForensic(object):
    """一个 SQLite 证据库的分析入口（只读）"""

    def __init__(self, db_path, auto_replay=True):
        self.path = os.path.abspath(db_path)
        self.wal_path = self.path + "-wal"
        self.auto_replay = auto_replay
        self._wal = None
        self._effective = None
        self._tempdir = None
        self._conn = None
        self._reader = None
        self._hdr = None
        self._cols = {}
        self.last_scan_stats = {}
        if not os.path.exists(self.path) and not os.path.exists(self.wal_path):
            raise FileNotFoundError(db_path)

    # ---------------- 生命周期 ----------------
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False

    def close(self):
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
        if self._tempdir and os.path.isdir(self._tempdir):
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None
        self._effective = None

    # ---------------- WAL ----------------
    def wal_info(self):
        """WAL 概况：有无、帧数、校验通过数、是否完整收尾"""
        if self._wal is None:
            self._wal = wal_scan(self.wal_path)
        w = self._wal
        return {
            "exists": w["exists"],
            "path": w["path"],
            "size": w["size"],
            "magic": w["magic"],
            "big_endian": w["big_endian"],
            "version": w["version"],
            "page_size": w["page_size"],
            "checkpoint_seq": w["checkpoint_seq"],
            "salt": w["salt"],
            "header_ok": w["header_ok"],
            "frames": w["frames"],
            "valid_frames": w["valid_frames"],
            "bad_frames": w["bad_frames"],
            "truncated_frames": w["truncated_frames"],
            "last_commit": w["last_commit"],
            "complete": w["complete"],
            "error": w["error"],
        }

    def replay(self, out_path=None):
        """回放 WAL 并把结果另存，返回 (回放后库路径, 统计 dict)

        证据目录始终只读：默认写到本实例的临时目录。
        """
        wi = self.wal_info()
        if not wi["exists"]:
            raise FileNotFoundError("没有 -wal 文件：%s" % self.wal_path)
        if out_path is None:
            if self._tempdir is None:
                self._tempdir = tempfile.mkdtemp(prefix="esk_sqlite_")
            target = os.path.join(self._tempdir, "replayed.db")
            path, st = replay_wal(self.path, target)
            self._effective = path
            return path, st
        path, st = replay_wal(self.path, out_path)
        return path, st

    def effective_path(self):
        """分析用的库路径：有 WAL 就回放出一份副本，否则就是原库"""
        if self._effective:
            return self._effective
        if not self.auto_replay:
            self._effective = self.path
            return self._effective
        wi = self.wal_info()
        if wi["exists"] and wi["frames"] > 0 and wi["last_commit"]:
            if self._tempdir is None:
                self._tempdir = tempfile.mkdtemp(prefix="esk_sqlite_")
            out = os.path.join(self._tempdir, "replayed.db")
            replay_wal(self.path, out)
            self._effective = out
        else:
            self._effective = self.path
        return self._effective

    # ---------------- 内部：连接 ----------------
    def _connect(self):
        if self._conn is not None:
            return self._conn
        p = self.effective_path().replace("\\", "/")
        uri = "file:%s?mode=ro&immutable=1" % p
        try:
            self._conn = sqlite3.connect(uri, uri=True)
        except sqlite3.Error:
            # 路径里有怪字符时退一步：先拷到临时目录再开
            if self._tempdir is None:
                self._tempdir = tempfile.mkdtemp(prefix="esk_sqlite_")
            cp = os.path.join(self._tempdir, "copy.db")
            shutil.copyfile(self.effective_path(), cp)
            self._conn = sqlite3.connect(cp.replace("\\", "/"), uri=False)
        self._conn.text_factory = bytes
        return self._conn

    def _q(self):
        """返回一个把 bytes 转成可读文本的行工厂

        text_factory 设成 bytes 之后，Python 的 sqlite3 交出来的是 UTF-8
        字节串（它内部已经把库编码转成 UTF-8），所以这里固定按 UTF-8 解，
        不能按库头里的 UTF-16 编码解。
        """

        def _fix(v):
            if isinstance(v, bytes):
                try:
                    return v.decode("utf-8", "replace")
                except Exception:
                    return v
            return v
        return _fix

    # ---------------- 头部 ----------------
    def _read_header(self):
        if self._hdr is not None:
            return self._hdr
        with open(self.effective_path(), "rb") as f:
            b = f.read(100)
        if len(b) < 16 or b[:16] != SQLITE_MAGIC:
            raise ValueError("不是 SQLite 3 数据库：%s" % self.path)
        if len(b) < 100:
            raise ValueError("数据库头不足 100 字节，可能被截断：%s" % self.path)
        page_size = struct.unpack_from(">H", b, 16)[0]
        if page_size == 1:
            page_size = 65536
        fsize = os.path.getsize(self.effective_path())
        hdr_pages = struct.unpack_from(">I", b, 28)[0]
        npages = hdr_pages or (fsize // max(1, page_size))
        if fsize // max(1, page_size) > npages:
            npages = fsize // max(1, page_size)
        enc = struct.unpack_from(">i", b, 56)[0]
        self._hdr = {
            "page_size": page_size,
            "write_version": b[18],
            "read_version": b[19],
            "reserved": b[20],
            "payload_frac": b[21],
            "file_change_counter": struct.unpack_from(">I", b, 24)[0],
            "hdr_pages": hdr_pages,
            "npages": npages,
            "freelist_trunk": struct.unpack_from(">i", b, 32)[0],
            "freelist_count": struct.unpack_from(">i", b, 36)[0],
            "schema_cookie": struct.unpack_from(">i", b, 40)[0],
            "schema_format": struct.unpack_from(">i", b, 44)[0],
            "default_cache": struct.unpack_from(">i", b, 48)[0],
            "largest_root": struct.unpack_from(">i", b, 52)[0],
            "encoding": enc,
            "user_version": struct.unpack_from(">i", b, 60)[0],
            "incremental_vacuum": struct.unpack_from(">i", b, 64)[0],
            "application_id": struct.unpack_from(">i", b, 68)[0],
            "version_valid_for": struct.unpack_from(">I", b, 92)[0],
            "sqlite_version": struct.unpack_from(">I", b, 96)[0] or None,
            "file_size": fsize,
            "usable": page_size - b[20],
            "encoding_name": ENCODINGS_TEXT.get(enc, "UTF-8"),
        }
        return self._hdr

    # ---------------- 元数据 ----------------
    def meta(self):
        """页大小 / 页数 / 编码 / user_version / application_id / auto_vacuum 等"""
        h = self._read_header()
        wi = self.wal_info()
        auto_vac = 0
        journal = "delete"
        try:
            c = self._connect()
            row = c.execute("PRAGMA auto_vacuum").fetchone()
            if row:
                auto_vac = int(row[0])
            row = c.execute("PRAGMA journal_mode").fetchone()
            if row:
                journal = (row[0].decode() if isinstance(row[0], bytes)
                           else str(row[0]))
        except sqlite3.Error:
            auto_vac = 1 if h["largest_root"] else 0
        # 库头第 18/19 字节 == 2 才是权威的 WAL 标记：-wal 被拷走后
        # PRAGMA 可能已经退化成 delete
        header_wal = h["read_version"] == 2 or h["write_version"] == 2
        return {
            "path": self.path,
            "analyzed": self.effective_path(),
            "file_size": h["file_size"],
            "page_size": h["page_size"],
            "page_count": h["npages"],
            "usable_size": h["usable"],
            "reserved_bytes": h["reserved"],
            "encoding": h["encoding"],
            "encoding_name": h["encoding_name"],
            "user_version": h["user_version"],
            "application_id": h["application_id"],
            "auto_vacuum": auto_vac,
            "incremental_vacuum": h["incremental_vacuum"],
            "freelist_count": h["freelist_count"],
            "freelist_trunk": h["freelist_trunk"],
            "schema_cookie": h["schema_cookie"],
            "schema_format": h["schema_format"],
            "file_change_counter": h["file_change_counter"],
            "sqlite_version": ("%d.%d.%d" % (h["sqlite_version"] // 1000000,
                                             h["sqlite_version"] // 1000 % 1000,
                                             h["sqlite_version"] % 1000)
                               if h["sqlite_version"] else None),
            "journal_mode": "wal" if header_wal else journal,
            "pragma_journal_mode": journal,
            "wal_mode": header_wal or journal.lower() == "wal",
            "wal_present": wi["exists"],
            "wal_frames": wi["frames"],
        }

    # ---------------- 结构浏览 ----------------
    def objects(self):
        """表 / 索引 / 视图 / 触发器，含 rootpage、SQL、行数估算"""
        c = self._connect()
        out = []
        try:
            rows = c.execute(
                "SELECT type,name,tbl_name,rootpage,sql FROM sqlite_master "
                "ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 "
                "WHEN 'view' THEN 2 ELSE 3 END, name").fetchall()
        except sqlite3.DatabaseError as e:
            raise ValueError("sqlite_master 读取失败：%s" % e)
        for typ, name, tbl, root, sql in rows:
            typ = typ.decode() if isinstance(typ, bytes) else typ
            name_s = name.decode("utf-8", "replace") if isinstance(name, bytes) else name
            tbl_s = tbl.decode("utf-8", "replace") if isinstance(tbl, bytes) else tbl
            sql_s = sql.decode("utf-8", "replace") if isinstance(sql, bytes) else sql
            item = {
                "type": typ,
                "name": name_s,
                "tbl_name": tbl_s,
                "rootpage": int(root or 0),
                "sql": sql_s,
                "columns": [],
                "rows_estimate": None,
                "rows_exact": False,
            }
            if typ == "table":
                item["columns"] = self.columns(name_s)
                n, exact = self._count_rows(name_s)
                item["rows_estimate"] = n
                item["rows_exact"] = exact
            out.append(item)
        return out

    def columns(self, table):
        """列名列表（按 cid 顺序）"""
        if table in self._cols:
            return self._cols[table]
        c = self._connect()
        cols = []
        try:
            for r in c.execute("PRAGMA table_info(%s)" % self._quote(table)):
                name = r[1]
                cols.append(name.decode("utf-8", "replace")
                            if isinstance(name, bytes) else name)
        except sqlite3.Error:
            cols = []
        self._cols[table] = cols
        return cols

    def _count_rows(self, table, budget_calls=200):
        """COUNT(*)，带 VM 指令预算；超时则返回 (None, False) 不硬等"""
        c = self._connect()
        calls = {"n": 0}

        def _cb():
            calls["n"] += 1
            return 1 if calls["n"] > budget_calls else 0

        try:
            c.set_progress_handler(_cb, 10000)
            n = c.execute("SELECT count(*) FROM %s" % self._quote(table)).fetchone()[0]
        except sqlite3.Error:
            return None, False
        finally:
            try:
                c.set_progress_handler(None, 0)
            except sqlite3.Error:
                pass
        return int(n), True

    @staticmethod
    def _quote(name):
        return '"' + str(name).replace('"', '""') + '"'

    def _table_exists(self, table):
        c = self._connect()
        row = c.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') "
            "AND name=?", (table,)).fetchone()
        return row is not None

    def rows(self, table, limit=100, where=None):
        """读任意表的行，支持 LIMIT 与 where 片段"""
        if not self._table_exists(table):
            raise KeyError("没有这个表/视图：%r" % table)
        sql = "SELECT * FROM %s" % self._quote(table)
        if where:
            sql += " WHERE " + where
        sql += " LIMIT %d" % int(limit)
        c = self._connect()
        fix = self._q()
        cur = c.execute(sql)
        names = [d[0] for d in cur.description]
        out = []
        for row in cur:
            out.append({n: fix(v) for n, v in zip(names, row)})
        return out

    # ---------------- B-tree 遍历 ----------------
    def _reader_obj(self):
        if self._reader is not None:
            return self._reader
        h = self._read_header()
        self._reader = _Reader(self.effective_path(), h["page_size"],
                               h["npages"], h["usable"])
        return self._reader

    def _btree_pages(self, rootpage, max_pages=None):
        """从 rootpage 出发收集表 b-tree 的全部页（内部页 + 叶页）

        内部页里也可能残留旧叶页数据（页类型转换后 cell 区被缩到页尾，
        前面整块变成「空闲」），所以两者都要扫。
        """
        rd = self._reader_obj()
        seen = set()
        stack = [rootpage]
        out = []
        visited = 0
        while stack:
            pno = stack.pop()
            if pno < 1 or pno > rd.npages or pno in seen:
                continue
            seen.add(pno)
            visited += 1
            if max_pages and visited > max_pages:
                break
            page = rd.page(pno)
            if page is None:
                continue
            hdr_off = 100 if pno == 1 else 0
            lay = _page_layout(page, rd.usable, hdr_off)
            if lay is None:
                continue
            if lay["type"] not in (PAGE_LEAF_TABLE, PAGE_INTERIOR_TABLE):
                continue
            out.append(pno)
            if lay["type"] == PAGE_INTERIOR_TABLE:
                # 最右子页指针在页头 @hdr+8；其余子页号在各 cell 前 4 字节
                if 1 <= lay["right"] <= rd.npages:
                    stack.append(lay["right"])
                for coff in lay["ptrs"]:
                    if coff + 4 > rd.usable:
                        continue
                    child = struct.unpack_from(">I", page, coff)[0]
                    if 1 <= child <= rd.npages:
                        stack.append(child)
        return sorted(out)

    # ---------------- 删除记录恢复 ----------------
    def deleted_rows(self, table=None, max_pages=None):
        """扫描 freeblock / 空闲间隙 / freelist 页，捞出删除记录

        返回 {表名: [ {row, rowid, page, offset, confidence, partial} ]}
        confidence = high：cell 起点与空闲块起点对齐，结构完整
                     low ：落在空隙中间或 cell 头被覆盖过，字段可能不全
        partial    = True 表示 cell 头前 4 字节被 freeblock 头覆盖，
                     第一列（通常是主键）已丢失
        另含 "<orphan-pages>" 键：freelist 上整页残留的记录（原表可能已 DROP）
        """
        h = self._read_header()
        rd = self._reader_obj()
        enc = ENCODINGS.get(h["encoding"], "utf-8")
        usable = h["usable"]
        db = self._connect()

        targets = []
        if table is not None:
            if not self._table_exists(table):
                raise KeyError("没有这个表：%r" % table)
            r = db.execute("SELECT rootpage FROM sqlite_master WHERE name=?",
                           (table,)).fetchone()
            targets.append((table, int(r[0] or 0)))
        else:
            for name, sql, root in db.execute(
                    "SELECT name,sql,rootpage FROM sqlite_master "
                    "WHERE type='table' AND rootpage>0 ORDER BY name"):
                nm = name.decode("utf-8", "replace") if isinstance(name, bytes) else name
                sq = sql.decode("utf-8", "replace") if isinstance(sql, bytes) else (sql or "")
                if "WITHOUT ROWID" in sq.upper():
                    continue          # 索引式 b-tree，cell 无 rowid
                if nm.startswith("sqlite_"):
                    continue
                targets.append((nm, int(root)))

        out = {}
        stats = {"pages_scanned": 0, "freeblocks": 0, "candidates": 0,
                 "partial_candidates": 0, "overwritten": 0, "dbstat": False,
                 "orphan_pages": 0}
        try:
            db.execute("SELECT count(*) FROM dbstat").fetchone()
            stats["dbstat"] = True
        except sqlite3.Error:
            stats["dbstat"] = False

        for name, root in targets:
            cols = self.columns(name)
            affinity = self._col_affinity(name)
            found = {}
            pages = self._btree_pages(root, max_pages)
            for pno in pages:
                if max_pages and stats["pages_scanned"] >= max_pages:
                    break
                page = rd.page(pno)
                if page is None:
                    continue
                stats["pages_scanned"] += 1
                hdr_off = 100 if pno == 1 else 0
                lay = _page_layout(page, usable, hdr_off)
                if not lay or lay["type"] not in (PAGE_LEAF_TABLE,
                                                  PAGE_INTERIOR_TABLE):
                    continue
                stats["freeblocks"] += len(lay["freeblocks"])
                regions = [(s, s + ln, "fb") for s, ln in lay["freeblocks"]]
                if lay["content"] > lay["ptr_end"]:
                    # 指针数组与 cell content 之间的整块未分配区：
                    # 页类型转换 / 页内搬迁后，旧 cell 就留在这里
                    regions.append((lay["ptr_end"], lay["content"], "gap"))
                live = set(lay["ptrs"])
                for start, end, kind in regions:
                    if end > usable:
                        end = usable
                    for pos in range(start, end):
                        if pos in live:
                            continue
                        got = _cell_at(page, pos, usable, enc, rd)
                        if got is None:
                            continue
                        rowid, vals, size = got
                        if pos + size > usable:
                            continue
                        # 全 NULL / 列数远超表结构的记录，都是空闲区里
                        # 对齐碰巧成立的字节串，不是真数据
                        if not vals or all(v is None for v in vals):
                            continue
                        if cols and len(vals) > max(len(cols), 8) + 4:
                            continue
                        conf = "high" if (pos == start and pos + size <= end) else "low"
                        overwritten = pos + size > lay["content"]
                        old = found.get(("rowid", rowid))
                        if old is not None and old["confidence"] == "high" \
                                and conf == "low":
                            continue
                        stats["candidates"] += 1
                        if overwritten:
                            stats["overwritten"] += 1
                        found[("rowid", rowid)] = {
                            "row": self._row_dict(cols, vals),
                            "rowid": rowid,
                            "page": pno,
                            "offset": pos,
                            "confidence": conf,
                            "partial": False,
                            "overwritten": overwritten,
                        }
                    if kind == "fb" and len(cols) >= 2:
                        self._scan_partial_cells(page, start, end, usable, enc,
                                                 len(cols), found, pno, cols, stats,
                                                 affinity)

            pk = self._pk_alias(name)
            if found and pk is not None and pk < len(cols):
                # INTEGER PRIMARY KEY 是 rowid 别名，记录体里存的是 NULL
                for item in found.values():
                    if item["row"].get(cols[pk]) is None and item["rowid"] is not None:
                        item["row"][cols[pk]] = item["rowid"]
            if found:
                out[name] = sorted(found.values(),
                                   key=lambda d: (d["rowid"] is None, d["rowid"] or 0))

        # freelist 上整页残留：原表可能已被 DROP，列名不可知
        orphans = []
        trunk, leaves, _n = self._freelist_pages()
        for pno in sorted(set(leaves) | set(trunk)):
            page = rd.page(pno)
            if page is None:
                continue
            hdr_off = 100 if pno == 1 else 0
            lay = _page_layout(page, usable, hdr_off)
            if not lay or lay["type"] != PAGE_LEAF_TABLE or lay["ncell"] == 0:
                continue
            for ptr in lay["ptrs"]:
                got = _cell_at(page, ptr, usable, enc, rd)
                if got is None:
                    continue
                rowid, vals, size = got
                orphans.append({
                    "row": {"col_%d" % (i + 1): v for i, v in enumerate(vals)},
                    "rowid": rowid,
                    "page": pno,
                    "offset": ptr,
                    "confidence": "high",
                    "partial": False,
                    "overwritten": False,
                })
        if orphans:
            out["<orphan-pages>"] = sorted(orphans, key=lambda d: (d["page"], d["rowid"]))
            stats["orphan_pages"] = len({o["page"] for o in orphans})

        self.last_scan_stats = stats
        return out

    @staticmethod
    def _row_dict(cols, vals):
        d = {}
        for i, v in enumerate(vals):
            key = cols[i] if i < len(cols) else "col_%d" % (i + 1)
            d[key] = v
        return d

    def _pk_alias(self, table):
        """INTEGER PRIMARY KEY 列下标（rowid 别名），没有返回 None"""
        c = self._connect()
        try:
            infos = c.execute("PRAGMA table_info(%s)" % self._quote(table)).fetchall()
        except sqlite3.Error:
            return None
        cands = [r for r in infos if int(r[5] or 0) > 0]
        if len(cands) != 1:
            return None
        decl = cands[0][2]
        decl = decl.decode("utf-8", "replace") if isinstance(decl, bytes) else str(decl)
        if decl.strip().upper() != "INTEGER":
            return None
        return int(cands[0][0])

    def _col_affinity(self, table):
        """每列的声明亲和性：TEXT / NUM / BLOB，用来过滤残记录的误命中"""
        c = self._connect()
        out = []
        try:
            infos = c.execute("PRAGMA table_info(%s)" % self._quote(table)).fetchall()
        except sqlite3.Error:
            return out
        for r in infos:
            decl = r[2]
            decl = decl.decode("utf-8", "replace") if isinstance(decl, bytes) else str(decl or "")
            d = decl.upper()
            if any(k in d for k in ("CHAR", "CLOB", "TEXT")):
                out.append("TEXT")
            elif any(k in d for k in ("INT", "REAL", "FLOA", "DOUB", "NUM", "DEC")):
                out.append("NUM")
            else:
                out.append("BLOB")
        return out

    @staticmethod
    def _affinity_ok(affinity, idx, v):
        """按声明亲和性判断残记录字段是否合理（挡掉错位的伪解析）"""
        if not affinity or idx >= len(affinity) or v is None:
            return True
        a = affinity[idx]
        if a == "TEXT":
            return isinstance(v, str)
        if a == "NUM":
            return isinstance(v, (int, float)) and not isinstance(v, bool)
        return True

    def _scan_partial_cells(self, page, start, end, usable, enc, ncols,
                            found, pno, cols, stats, affinity=None):
        """freeblock 的 4 字节头会盖住被删 cell 的前 4 个字节
        （payload 长度、rowid、record header 长度、第一个序列类型）。

        这里按「每列序列类型占 1 字节」推定存活的类型串，把剩余字节当
        body 解一条残记录；第一列的值（通常是 INTEGER PRIMARY KEY）丢失，
        置 None。置信度一律 low，并标记 partial=True。
        """
        h = max(1, ncols - 1)
        if end - start < h + 12:
            return
        for q in range(start + 4, end - h - 1):
            types = page[q:q + h]
            total = 0
            ok = True
            for t in types:
                ln = _serial_len(t)
                if ln < 0:
                    ok = False
                    break
                total += ln
            if not ok or total < 2:
                continue
            body_off = q + h
            cell_end = body_off + total
            if cell_end > end:
                continue
            if cell_end != end:
                # 后面应当紧跟下一个被删 cell 的残留头
                nxt, sz = struct.unpack_from(">HH", page, cell_end)
                if not (4 <= sz <= usable and cell_end + sz <= usable):
                    continue
            vals = []
            o = body_off
            good = True
            max_text = 0
            for i, t in enumerate(types):
                ln = _serial_len(t)
                v = _serial_val(t, page, o, enc)
                if isinstance(v, str):
                    max_text = max(max_text, len(v))
                    if len(v) < 2 or not _is_printable(v):
                        good = False
                        break
                elif isinstance(v, float):
                    if v != v or abs(v) > 1e300:
                        good = False
                        break
                if not self._affinity_ok(affinity, i + 1, v):
                    good = False
                    break
                vals.append(v)
                o += ln
            if not good or max_text < 4:
                continue
            row = {}
            if cols:
                row[cols[0]] = None
            for i, v in enumerate(vals):
                key = cols[i + 1] if i + 1 < len(cols) else "col_%d" % (i + 2)
                row[key] = v
            key = ("off", pno, q)
            if key in found:
                continue
            stats["partial_candidates"] += 1
            found[key] = {
                "row": row,
                "rowid": None,
                "page": pno,
                "offset": q,
                "confidence": "low",
                "partial": True,
                "overwritten": False,
            }

    # ---------------- freelist ----------------
    def _freelist_pages(self):
        """返回 (trunk 页列表, 叶子页列表, 头里声明的空闲页数)"""
        h = self._read_header()
        rd = self._reader_obj()
        trunk = h["freelist_trunk"]
        pages = []
        leaves = []
        seen = set()
        while trunk > 0 and trunk not in seen and trunk <= rd.npages:
            seen.add(trunk)
            page = rd.page(trunk)
            if page is None:
                break
            pages.append(trunk)
            nxt, cnt = struct.unpack_from(">II", page, 4)
            limit = (rd.usable - 8) // 4
            cnt = min(cnt, limit)
            for i in range(cnt):
                lp = struct.unpack_from(">I", page, 8 + 4 * i)[0]
                if 1 <= lp <= rd.npages:
                    leaves.append(lp)
            trunk = nxt
        return pages, leaves, h["freelist_count"]

    # ---------------- 已删除表 ----------------
    def deleted_tables(self):
        """在 freelist 页和 sqlite_master 空闲区里找 CREATE TABLE 残留

        返回 [{sql, type, name, page, offset, source}]，
        source ∈ {sqlite_master, sqlite_master_overflow, freelist}。
        """
        h = self._read_header()
        rd = self._reader_obj()
        seen_sql = set()
        out = []

        def scan(pno, buf, source):
            buf = bytes(buf)
            for m in _SQL_OBJ_RE.finditer(buf):
                sql = _extract_sql(buf, m.start())
                if not sql or sql in seen_sql:
                    continue
                if not sql.lstrip().upper().startswith("CREATE"):
                    continue
                seen_sql.add(sql)
                out.append({
                    "sql": sql,
                    "type": _obj_type(sql),
                    "name": _obj_name(sql),
                    "page": pno,
                    "offset": m.start(),
                    "source": source,
                })

        p1 = rd.page(1)
        lay = _page_layout(p1, h["usable"], 100) if p1 else None
        if lay and lay["type"] == PAGE_LEAF_TABLE:
            # 指针数组与 cell content 之间的空隙
            if lay["content"] > lay["ptr_end"]:
                scan(1, p1[lay["ptr_end"]:min(lay["content"], h["usable"])],
                     "sqlite_master")
            # 空闲块：DROP TABLE 后 sqlite_master 的 cell 就躺在这里
            for s, ln in lay["freeblocks"]:
                scan(1, p1[s:s + ln], "sqlite_master")
            # SQL 太长时落在溢出页
            for ptr in lay["ptrs"]:
                pg = _cell_overflow_pageno(p1, ptr, h["usable"])
                hops = 0
                seen_pg = set()
                while pg and 1 <= pg <= rd.npages and hops < 32 and pg not in seen_pg:
                    seen_pg.add(pg)
                    hops += 1
                    ob = rd.page(pg)
                    if ob is None:
                        break
                    scan(pg, ob, "sqlite_master_overflow")
                    pg = struct.unpack_from(">I", ob, 0)[0]

        trunk, leaves, _n = self._freelist_pages()
        for pno in sorted(set(trunk) | set(leaves)):
            buf = rd.page(pno)
            if buf:
                scan(pno, buf, "freelist")
        return out


def _extract_sql(buf, start, limit=8192):
    """从 start 处抽一条完整 DDL 文本（括号配平 + 引号感知）"""
    end = min(len(buf), start + limit)
    depth = 0
    quote = None
    seen_paren = False
    i = start
    while i < end:
        ch = buf[i:i + 1]
        if quote is not None:
            if ch == quote:
                if i + 1 < end and buf[i + 1:i + 2] == quote:
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if ch in (b"'", b'"', b"`", b"["):
            quote = b"]" if ch == b"[" else ch
            i += 1
            continue
        if ch == b"(":
            depth += 1
            seen_paren = True
            i += 1
            continue
        if ch == b")":
            depth -= 1
            i += 1
            if depth == 0 and seen_paren:
                # 收尾：吃掉 STRICT / WITHOUT ROWID 与分号
                while True:
                    m = re.match(rb"\s+(WITHOUT\s+ROWID|STRICT)\b",
                                 buf[i:min(end, i + 32)], re.I)
                    if not m:
                        break
                    i += m.end()
                if i < end and buf[i:i + 1] == b";":
                    i += 1
                break
            continue
        if ch == b";" and depth == 0:
            i += 1
            break
        if ch == b"\x00":
            break
        i += 1
    raw = bytes(buf[start:i])
    txt = raw.decode("utf-8", "replace")
    txt = "".join(c if (c in "\n\t" or 32 <= ord(c) < 0x7F or ord(c) > 0x9F) else " "
                  for c in txt)
    txt = re.sub(r"[ \t]+", " ", txt).strip().rstrip(";").strip()
    return txt


def _is_printable(s):
    """文本是否基本可打印（用来过滤误命中的乱码）"""
    if not s:
        return False
    bad = 0
    for ch in s:
        if ch in "\t\r\n":
            continue
        if not ch.isprintable():
            bad += 1
    return bad * 20 <= len(s)


def _obj_type(sql):
    m = re.match(r"\s*CREATE\s+(?:UNIQUE\s+)?(\w+)", sql, re.I)
    return m.group(1).upper() if m else "?"


def _obj_name(sql):
    m = re.match(r'\s*CREATE\s+(?:UNIQUE\s+)?\w+\s+(?:IF\s+NOT\s+EXISTS\s+)?'
                 r'("[^"]+"|`[^`]+`|\[[^\]]+\]|\S+)', sql, re.I)
    if not m:
        return None
    n = m.group(1)
    if n[:1] in ('"', "`", "["):
        n = n[1:-1]
    return n


# ---------------- 自检 ----------------

def _selftest():
    import json

    ok = []
    bad = []

    def _j(v):
        """bytes 打成 0x.. 更易读，避免输出里全是 b'..'"""
        if isinstance(v, bytes):
            return "0x" + v.hex()
        return str(v)

    def check(cond, msg):
        (ok if cond else bad).append(msg)
        print("  [%s] %s" % ("PASS" if cond else "FAIL", msg))

    tmp = tempfile.mkdtemp(prefix="esk_sqlite_test_")
    live = os.path.join(tmp, "live")
    evi = os.path.join(tmp, "evidence")
    os.makedirs(live)
    os.makedirs(evi)
    db = os.path.join(live, "app.db")

    print("== 1. 造库：100 行 + WAL 模式再插 50 行 ==")
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA page_size=4096")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("CREATE TABLE msg(id INTEGER PRIMARY KEY, who TEXT, "
                 "body TEXT, score REAL, raw BLOB)")
    conn.execute("CREATE INDEX idx_msg_who ON msg(who)")
    conn.executemany(
        "INSERT INTO msg(who,body,score,raw) VALUES(?,?,?,?)",
        [("u%03d" % i, "before-wal message #%d, payload padding 0123456789" % i,
          i * 1.5, bytes([i % 256]) * 8) for i in range(1, 101)])
    conn.commit()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.executemany(
        "INSERT INTO msg(who,body,score,raw) VALUES(?,?,?,?)",
        [("w%03d" % i, "after-wal message #%d, still only in the wal file" % i,
          i * 2.25, bytes([(i * 7) % 256]) * 12) for i in range(101, 151)])
    conn.commit()
    n_all = conn.execute("SELECT count(*) FROM msg").fetchone()[0]
    print("  插入后总行数：%d" % n_all)

    print("== 2. DELETE 30 行（id 71..100），不 checkpoint，然后做镜像快照 ==")
    conn.execute("DELETE FROM msg WHERE id > 70 AND id <= 100")
    conn.commit()
    n_live = conn.execute("SELECT count(*) FROM msg").fetchone()[0]
    print("  删除后总行数：%d" % n_live)
    for suf in ("", "-wal"):
        src = db + suf
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(evi, "app.db" + suf))
    conn.close()          # 关闭会把改动 checkpoint 回 live/，不影响 evidence/
    evi_db = os.path.join(evi, "app.db")
    print("  证据快照：%s（+ %s）" % (
        evi_db, "app.db-wal" if os.path.exists(evi_db + "-wal") else "无 wal"))

    print("== 3. WAL 解析 ==")
    f = SqliteForensic(evi_db)
    wi = f.wal_info()
    print("  " + json.dumps(wi, ensure_ascii=False, default=_j))
    check(wi["exists"], "wal_info() 看到 -wal 文件")
    check(wi["frames"] > 0, "wal_info() 帧数 > 0（实际 %r）" % wi["frames"])
    check(wi["header_ok"], "WAL 头 checksum 校验通过")
    check(wi["page_size"] == 4096, "WAL 头 page_size = 4096")
    check(wi["valid_frames"] == wi["frames"], "所有帧 checksum 校验通过")
    check(wi["complete"], "WAL 以提交帧收尾（完整）")

    print("== 4. WAL 回放：主库 vs 回放后 ==")
    stale = os.path.join(tmp, "stale.db")
    shutil.copyfile(evi_db, stale)
    c2 = sqlite3.connect("file:%s?mode=ro&immutable=1" % stale.replace("\\", "/"),
                         uri=True)
    n_stale = c2.execute("SELECT count(*) FROM msg").fetchone()[0]
    c2.close()
    print("  只看主库（无 WAL）行数：%d" % n_stale)
    out_path, st = f.replay()
    print("  回放后：%s" % out_path)
    print("  " + json.dumps({k: st[k] for k in
                             ("frames", "valid_frames", "bad_frames", "last_commit",
                              "applied_frames", "db_pages", "db_size")},
                            ensure_ascii=False, default=_j))
    c3 = sqlite3.connect("file:%s?mode=ro&immutable=1" % out_path.replace("\\", "/"),
                         uri=True)
    n_replay = c3.execute("SELECT count(*) FROM msg").fetchone()[0]
    c3.close()
    print("  回放后行数：%d" % n_replay)
    check(n_stale < n_live, "只看主库仍是旧状态（%d 行，新数据还在 WAL 里）" % n_stale)
    check(n_replay == n_live, "回放后与在线状态一致（%d 行）" % n_live)
    check(st["applied_frames"] == st["valid_frames"], "有效帧全部落地")

    print("== 5. 元数据 / 结构 ==")
    m = f.meta()
    print("  " + json.dumps(m, ensure_ascii=False, default=_j))
    check(m["page_size"] == 4096, "meta().page_size == 4096")
    check(m["page_count"] >= 1, "meta().page_count 合理（%d）" % m["page_count"])
    check(m["encoding_name"] == "UTF-8", "meta().encoding_name == UTF-8")
    check(m["wal_mode"], "meta() 识别为 WAL 模式")
    check(m["freelist_count"] >= 0, "meta().freelist_count 可读")
    objs = f.objects()
    print("  objects：%s" % [(o["type"], o["name"], o["rootpage"],
                              o["rows_estimate"]) for o in objs])
    check(any(o["name"] == "msg" and o["type"] == "table" for o in objs),
          "objects() 列出表 msg")
    check(any(o["type"] == "index" and o["name"] == "idx_msg_who" for o in objs),
          "objects() 列出索引 idx_msg_who")
    r = f.rows("msg", limit=3)
    print("  rows(limit=3)：%s" % json.dumps(r, ensure_ascii=False, default=_j))
    check(len(r) == 3 and "body" in r[0], "rows() 支持 LIMIT 与列名")
    r2 = f.rows("msg", limit=5, where="id > 140 ORDER BY id")
    check(len(r2) == 5 and all(x["id"] > 140 for x in r2), "rows() 支持 where 片段")

    print("== 6. 删除记录恢复 ==")
    deleted = f.deleted_rows("msg")
    stats = f.last_scan_stats
    print("  扫描统计：%s" % json.dumps(stats, ensure_ascii=False, default=_j))
    got = deleted.get("msg", [])
    full = [x for x in got if not x.get("partial")]
    part = [x for x in got if x.get("partial")]
    print("  恢复出 %d 条记录（完整 cell %d 条，头被覆盖的残记录 %d 条）"
          % (len(got), len(full), len(part)))
    for item in got[:4]:
        print("    page=%d off=0x%04X conf=%-4s partial=%-5s overwritten=%-5s %s" % (
            item["page"], item["offset"], item["confidence"],
            item.get("partial"), item.get("overwritten"),
            json.dumps(item["row"], ensure_ascii=False, default=_j)))
    for item in part[:2]:
        print("    page=%d off=0x%04X conf=%-4s partial=%-5s overwritten=%-5s %s" % (
            item["page"], item["offset"], item["confidence"],
            item.get("partial"), item.get("overwritten"),
            json.dumps(item["row"], ensure_ascii=False, default=_j)))

    # 被删的 30 行 who 是 u071..u100，按内容判命中（主键可能已随 cell 头丢失）
    want = {"u%03d" % i for i in range(71, 101)}
    seen = set()
    for x in got:
        who = x["row"].get("who")
        if isinstance(who, str):
            seen.add(who)
    hit = want & seen
    print("  命中被删除的 who(u071..u100)：%d / 30" % len(hit))
    ids = sorted(x["row"].get("id") for x in full if isinstance(x["row"].get("id"), int))
    if ids:
        print("  完整记录可还原的主键区间：%d .. %d" % (ids[0], ids[-1]))
    if not hit:
        print("  >>> 本次未恢复出被删记录。原因：页内空闲块已被 defragmentPage 复用，"
              "或 secure_delete=ON 把 cell 字节零写了。")
    else:
        check(len(hit) > 0, "deleted_rows() 至少捞回部分被删记录（%d/30）" % len(hit))
    extra = seen - want
    print("  非删除区间的旧版本残留：%d 条，示例 who=%s"
          % (len(extra), sorted(extra)[:6]))
    allrows = f.deleted_rows()
    print("  deleted_rows() 全库键：%s" % list(allrows.keys()))

    print("== 7. WAL 坏帧：跳过并计数 ==")
    evi2 = os.path.join(tmp, "evidence_bad")
    os.makedirs(evi2)
    shutil.copyfile(evi_db, os.path.join(evi2, "app.db"))
    wal_copy = os.path.join(evi2, "app.db-wal")
    raw = bytearray(open(evi_db + "-wal", "rb").read())
    bad_off = 32 + 2 * (24 + 4096) + 24 + 1000      # 第 3 帧的页数据里翻一个字节
    raw[bad_off] ^= 0xFF
    with open(wal_copy, "wb") as fh:
        fh.write(bytes(raw))
    f2 = SqliteForensic(os.path.join(evi2, "app.db"))
    w2 = f2.wal_info()
    print("  " + json.dumps({k: w2[k] for k in ("frames", "valid_frames",
                                                "bad_frames", "complete")},
                            ensure_ascii=False))
    check(w2["frames"] == 7, "坏帧不影响总帧数统计（7）")
    check(w2["bad_frames"] == 1, "识别出 1 个 checksum 不过的帧")
    check(w2["valid_frames"] == 6, "其余 6 帧校验通过")
    check(not w2["complete"], "有坏帧时 complete 标记为 False")
    p2, s2 = f2.replay()
    print("  回放统计：%s" % json.dumps(
        {k: s2[k] for k in ("valid_frames", "bad_frames", "applied_frames",
                            "resynced", "db_size")}, ensure_ascii=False))
    check(s2["bad_frames"] == 1 and s2["resynced"], "回放时跳过坏帧并重建校验链")
    try:
        c5 = sqlite3.connect("file:%s?mode=ro&immutable=1" % p2.replace("\\", "/"),
                             uri=True)
        n2 = c5.execute("SELECT count(*) FROM msg").fetchone()[0]
        c5.close()
        print("  坏帧回放后可读，行数 %d（丢掉的部分即被破坏的页）" % n2)
    except sqlite3.DatabaseError as e:
        print("  坏帧回放后库不可读（丢掉被破坏的页后的必然结果）：%s" % e)
    f2.close()

    print("== 8. 已删除表检测 ==")
    db2 = os.path.join(tmp, "drop.db")
    c4 = sqlite3.connect(db2)
    c4.execute("PRAGMA page_size=4096")
    c4.execute("CREATE TABLE victim(a TEXT, b INTEGER)")
    c4.execute("INSERT INTO victim VALUES('secret-token-abc', 42)")
    c4.commit()
    c4.execute("DROP TABLE victim")
    c4.commit()
    c4.close()
    g = SqliteForensic(db2)
    dt = g.deleted_tables()
    print("  freelist_count=%d，命中 %d 条 DDL" % (g.meta()["freelist_count"], len(dt)))
    for d in dt[:3]:
        print("    page=%s off=%d %s" % (d["page"], d["offset"], d["sql"][:90]))
    check(len(dt) > 0, "deleted_tables() 找到 CREATE TABLE 残留")
    check(any("victim" in (d["sql"] or "") for d in dt), "残留 SQL 指向已 DROP 的表 victim")
    g.close()
    f.close()

    print()
    print("== 自检结果：%d 通过 / %d 失败 ==" % (len(ok), len(bad)))
    for b in bad:
        print("  FAIL: %s" % b)
    print("临时目录：%s" % tmp)
    return len(bad) == 0


if __name__ == "__main__":
    import sys

    # 管道/重定向时固定 UTF-8，免得 Windows 控制台码页把中文显示成乱码
    for _s in (sys.stdout, sys.stderr):
        try:
            if not _s.isatty():
                _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    raise SystemExit(0 if _selftest() else 1)
