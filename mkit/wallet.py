# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""wallet.py —— 虚拟货币钱包取证解析（纯标准库 + 可选 pycryptodome）。

覆盖
    * 钱包应用发现：MetaMask / imToken / Trust / TokenPocket / BitKeep / Coinbase /
      Exodus / TronLink / MathWallet / Electrum / Bitcoin Core（Android 包名 + Windows 目录）
    * MetaMask vault：PBKDF2-HMAC-SHA256(600000, dklen=32) + AES-256-GCM 解密
      （iv 由 vault 给出，通常 12 字节；WebCrypto 约定 tag 附在密文末尾）
    * Chromium LevelDB（.ldb/.sst + .log WAL）：footer → index block → data block
      自解析，含纯 Python snappy 解压；任一步失败自动降级为二进制扫
    * Electrum json 钱包（BIE1 AES-256-CBC 加密 seed 可解）
    * Bitcoin Core wallet.dat（BDB best-effort：mkey/ckey/name/addr/pkey）
    * 全盘地址提取（文本 / SQLite / leveldb / plist / 二进制）

fs 适配
    只依赖 mkit.ext4.Ext4（lookup/listdir/inode/read_data）与 mkit.ntfs.NTFS
    （lookup/ls_entry/read_data）的公共子集，由 FsView 自动识别；自测里的 DirFS
    等“类 Ext4”适配器同样可用。
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import hmac
import json
import re
import struct

try:
    from .chain import (
        scan_addresses, parse_eth_tx, keccak256, base58check_encode, hash160,
        KNOWN_CONTRACTS, eth_address_from_privkey,
    )
except ImportError:  # 直接以脚本方式运行
    from mkit.chain import (  # type: ignore
        scan_addresses, parse_eth_tx, keccak256, base58check_encode, hash160,
        KNOWN_CONTRACTS, eth_address_from_privkey,
    )

try:  # 老版本 chain.py 里没有这个名字；缺失时降级为 None（本模块不硬依赖）
    from .chain import secp256k1  # type: ignore  # noqa: F401
except (ImportError, AttributeError):
    secp256k1 = None

__all__ = [
    "FsView", "WalletFinder", "MetaMaskVault", "ElectrumWallet", "BitcoinCoreWallet",
    "find_addresses_in_fs", "AddressList", "extract_json_objects", "leveldb_pairs",
    "leveldb_wal_records", "snappy_decompress", "WALLET_APPS",
]


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

_ADDR_ETH = re.compile(rb"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_ADDR_BTC = re.compile(rb"(?<![0-9A-Za-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![0-9A-Za-z])")
_ADDR_TRON = re.compile(rb"T[1-9A-HJ-NP-Za-km-z]{33}")
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

#: 钱包应用特征：包名（Android）/目录名（Windows）/落盘标记文件
WALLET_APPS = {
    "MetaMask": {
        "android": ["io.metamask", "com.metamask", "io.metamask.chromium"],
        "win": ["MetaMask"],
        "markers": ["vault.json", "app_chrome", "localstorage", "rkstorage"],
    },
    "imToken": {
        "android": ["im.token.app", "im.token.app.pro", "com.token.im", "im.token.www"],
        "win": [],
        "markers": ["wallets.db", "token.im"],
    },
    "Trust": {
        "android": ["com.wallet.crypto.trustapp", "com.trustwallet.app"],
        "win": [],
        "markers": ["trustwallet"],
    },
    "TokenPocket": {
        "android": ["vip.mytokenpocket", "com.tokenpocket.pro", "vip.mytokenpocket.pro"],
        "win": [],
        "markers": ["tokenpocket", "tpsettings"],
    },
    "BitKeep": {
        "android": ["com.bitkeep.wallet", "com.bitkeep.os", "com.bitkeep.wallet.pro"],
        "win": [],
        "markers": ["bitkeep"],
    },
    "Coinbase": {
        "android": ["co.invest.android", "com.coinbase.android", "com.coinbase.wallet"],
        "win": [],
        "markers": ["coinbase"],
    },
    "Exodus": {
        "android": ["exodus.mobile", "com.exodus.wallet", "io.exodus.mobile"],
        "win": ["Exodus", "Exodus Wallet"],
        "markers": ["exodus.wallet", "seed.seco", "exodus.conf.json"],
    },
    "TronLink": {
        "android": ["com.tronlinkpro.wallet", "com.tronlink.wallet", "com.tronlink.wallet.pro"],
        "win": [],
        "markers": ["tronlink"],
    },
    "MathWallet": {
        "android": ["com.mathwallet.android", "mediun.mathwallet", "com.mathwallet.www"],
        "win": [],
        "markers": ["mathwallet"],
    },
    "Electrum": {
        "android": ["org.electrum.electrum"],
        "win": ["Electrum"],
        "markers": ["default_wallet", "wallets", "config"],
    },
    "BitcoinCore": {
        "android": ["de.schildbach.wallet", "com.bitcoin.wallet"],
        "win": ["Bitcoin", "Bitcoin Core"],
        "markers": ["wallet.dat", "blocks", "chainstate"],
    },
}

#: 目录名 -> 应用（小写，用于 Windows 目录 / Android 外部存储）
_NAME_INDEX = {}
for _app, _spec in WALLET_APPS.items():
    for _n in list(_spec["android"]) + list(_spec["win"]):
        _NAME_INDEX.setdefault(_n.lower(), _app)

_ANDROID_DATA_ROOTS = [
    "/data/data", "/data/user/0", "/data/user/0/../10", "/data/user_de/0",
    "/data/user/10", "/data/user/11", "/data/user/999",
    "/persist-root/data/data", "/persist/data/data", "/data/persist-root/data/data",
    "/oem/persist-root/data/data", "/data/vendor/persist/data/data",
    "/data/media/0/Android/data", "/sdcard/Android/data",
    "/storage/emulated/0/Android/data", "/storage/emulated/10/Android/data",
    "/app", "/data/app", "/data/app-private",
]

_WIN_ROOTS = [
    "/Users", "/Documents and Settings", "/Program Files", "/Program Files (x86)",
    "/ProgramData", "/Tools", "/tools",
]

_WIN_USER_SUFFIX = [
    "/AppData/Roaming", "/AppData/Local", "/AppData/LocalLow",
    "/AppData/Roaming/Electrum", "/AppData/Roaming/Bitcoin",
]

#: 值得读的文本/结构化扩展名
_TEXT_EXT = {
    ".json", ".txt", ".log", ".conf", ".cfg", ".ini", ".xml", ".html", ".htm",
    ".js", ".sql", ".csv", ".yaml", ".yml", ".plist", ".properties", ".ovpn",
    ".ldb", ".sst", ".db", ".sqlite", ".sqlite3", ".bak", ".dat", ".wallet",
    ".torrc", ".mid", ".vcf",
}
_SKIP_EXT = {
    ".apk", ".dex", ".odex", ".vdex", ".so", ".jar", ".zip", ".7z", ".rar",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".heif",
    ".mp4", ".3gp", ".mkv", ".avi", ".mov", ".mp3", ".m4a", ".wav", ".ogg",
    ".ttf", ".ttc", ".otf", ".woff", ".woff2", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".class", ".pyc", ".elf", ".bin",
}

VAULT_ITER = 600000          # MetaMask 默认 PBKDF2 迭代次数
VAULT_DKLEN = 32


def _now_iso(ts=None):
    if ts is None:
        ts = datetime.datetime.now(datetime.timezone.utc)
    return ts.isoformat()


# ---------------------------------------------------------------------------
# fs 适配
# ---------------------------------------------------------------------------

class FsView:
    """把 Ext4 / NTFS / 自测 DirFS 统一成 path 视图。

    - Ext4 与 DirFS：lookup(path) -> inode；listdir(inode) -> [DirEntry]；read_data(inode)
    - NTFS：lookup(path) -> MftEntry；ls_entry(entry) -> [MftEntry]；entry.read_data()
    """

    def __init__(self, fs):
        self.fs = fs
        self.kind = "ntfs" if (hasattr(fs, "ls_entry") or hasattr(fs, "ls")) else "posix"
        if hasattr(fs, "listdir") and hasattr(fs, "read_data"):
            self.kind = "posix"
        self.notes = []

    # ---------------- 路径 ----------------
    @staticmethod
    def norm(path):
        p = str(path).replace("\\", "/")
        while "//" in p:
            p = p.replace("//", "/")
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1:
            p = p.rstrip("/") or "/"
        return p

    def lookup(self, path):
        p = self.norm(path)
        try:
            if self.kind == "ntfs":
                return self.fs.lookup(p, include_deleted=True)
            return self.fs.lookup(p)
        except Exception as e:  # 损坏目录 / 越界
            self.notes.append("lookup %s: %s" % (p, e))
            return None

    def inode(self, num):
        try:
            return self.fs.inode(num)
        except Exception:
            return None

    def exists(self, path):
        return self.lookup(path) is not None

    def isdir(self, path):
        o = self.lookup(path)
        return bool(o is not None and getattr(o, "is_dir", False))

    def isfile(self, path):
        o = self.lookup(path)
        return bool(o is not None and not getattr(o, "is_dir", False))

    def size(self, path_or_obj):
        o = path_or_obj if not isinstance(path_or_obj, str) else self.lookup(path_or_obj)
        s = getattr(o, "size", 0) or 0
        return int(s)

    def mtime(self, path_or_obj):
        o = path_or_obj if not isinstance(path_or_obj, str) else self.lookup(path_or_obj)
        return getattr(o, "mtime", None)

    # ---------------- 目录 ----------------
    def listdir(self, path):
        """-> [(name, is_dir, obj)]"""
        o = self.lookup(path)
        if o is None:
            return []
        return list(self._children(o))

    def _children(self, obj):
        if self.kind == "ntfs":
            try:
                ents = self.fs.ls_entry(obj, include_deleted=True)
            except Exception as e:
                self.notes.append("ls_entry: %s" % e)
                return
            for e in ents:
                nm = getattr(e, "name", None)
                if not nm or nm in (".", ".."):
                    continue
                yield nm, bool(getattr(e, "is_dir", False)), e
            return
        try:
            ents = self.fs.listdir(obj)
        except Exception as e:
            self.notes.append("listdir: %s" % e)
            return
        for e in ents:
            nm = getattr(e, "name", None)
            if not nm or nm in (".", ".."):
                continue
            yield nm, self._entry_is_dir(e), self._obj_for(e)

    def _entry_is_dir(self, e):
        ft = getattr(e, "file_type", None)
        if ft is not None:
            return ft == 2
        if hasattr(e, "is_dir"):
            return bool(e.is_dir)
        o = self._obj_for(e)
        return bool(o is not None and getattr(o, "is_dir", False))

    def _obj_for(self, e):
        if hasattr(e, "inode"):
            o = self.inode(e.inode)
            if o is not None:
                return o
        return e

    def walk(self, root="/", maxdepth=8, limit=None):
        """先序递归，yield (path, is_dir, obj)。maxdepth 为相对 root 的层数。"""
        r = self.norm(root)
        ro = self.lookup(r)
        if ro is None:
            return
        stack = [(r, ro, 0)]
        seen = set()
        n = 0
        while stack:
            path, obj, depth = stack.pop()
            key = (self.kind, getattr(obj, "num", id(obj)))
            if key in seen:
                continue
            seen.add(key)
            for name, is_dir, child in self._children(obj):
                n += 1
                if limit is not None and n > limit:
                    return
                cpath = (path.rstrip("/") or "") + "/" + name
                yield cpath, is_dir, child
                if is_dir and depth + 1 <= maxdepth:
                    stack.append((cpath, child, depth + 1))

    # ---------------- 读取 ----------------
    def read_obj(self, obj, limit=None, max_size=None):
        if obj is None:
            return b""
        size = self.size(obj)
        if max_size is not None and size > max_size:
            self.notes.append("skip %d bytes > max_size %d" % (size, max_size))
            return b""
        if self.kind == "ntfs":
            try:
                data = obj.read_data()
            except Exception as e:
                self.notes.append("read_data: %s" % e)
                return b""
            return data if limit is None else data[:limit]
        take = None
        if limit is not None:
            take = min(size, limit) if size else limit
        try:
            if take is None:
                return self.fs.read_data(obj)
            return self.fs.read_data(obj, take)
        except Exception as e:
            self.notes.append("read_data: %s" % e)
            return b""

    def read(self, path, limit=None, max_size=None):
        return self.read_obj(self.lookup(path), limit=limit, max_size=max_size)

    def read_text(self, path, limit=None, max_size=None, encoding="utf-8"):
        data = self.read(path, limit=limit, max_size=max_size)
        return data.decode(encoding, "replace")

    # ---------------- 便捷 ----------------
    def find_named(self, roots, wanted, maxdepth=10, casefold=True):
        """在 roots 下找 basename 命中 wanted 的文件/目录，返回 [(path, is_dir, obj)]。"""
        want = {w.lower() for w in wanted} if casefold else set(wanted)
        out = []
        for root in roots:
            for path, is_dir, obj in self.walk(root, maxdepth=maxdepth):
                base = path.rsplit("/", 1)[-1]
                key = base.lower() if casefold else base
                if key in want:
                    out.append((path, is_dir, obj))
        return out

    def find_ext(self, roots, exts, maxdepth=10, limit=2000):
        """在 roots 下按扩展名找文件，返回 [(path, obj)]。"""
        want = {e.lower() for e in exts}
        out = []
        for root in roots:
            for path, is_dir, obj in self.walk(root, maxdepth=maxdepth):
                if is_dir:
                    continue
                base = path.rsplit("/", 1)[-1].lower()
                if any(base.endswith(e) for e in want):
                    out.append((path, obj))
                    if len(out) >= limit:
                        return out
        return out

    def find_in_text_files(self, roots, needle, maxdepth=10, max_size=8 << 20,
                           exts=None, limit=200):
        """在 roots 下的文本类文件里找 needle（bytes 或 str），返回 [(path, data)]。"""
        nb = needle.encode("utf-8") if isinstance(needle, str) else needle
        hits = []
        for root in roots:
            for path, is_dir, obj in self.walk(root, maxdepth=maxdepth):
                if is_dir or len(hits) >= limit:
                    continue
                low = path.lower()
                ext = low.rsplit(".", 1)[-1] if "." in low.rsplit("/", 1)[-1] else ""
                if exts is not None and ("." + ext) not in exts:
                    continue
                if self.size(obj) > max_size:
                    continue
                data = self.read_obj(obj, max_size=max_size)
                if nb in data:
                    hits.append((path, data))
        return hits


# ---------------------------------------------------------------------------
# 通用二进制工具：snappy / leveldb / JSON 抽取
# ---------------------------------------------------------------------------

def _varint(buf, pos):
    shift = 0
    val = 0
    while True:
        if pos >= len(buf):
            raise ValueError("varint eof")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, pos
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")


def snappy_decompress(buf, max_out=64 << 20):
    """纯 Python Snappy raw block 解压（leveldb data block 用）。"""
    buf = bytes(buf)
    n = len(buf)
    pos = 0
    shift = 0
    ulen = 0
    while pos < n:
        b = buf[pos]
        pos += 1
        ulen |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    if ulen > max_out:
        raise ValueError("snappy too large: %d" % ulen)
    out = bytearray()
    while pos < n:
        tag = buf[pos]
        pos += 1
        t = tag & 3
        if t == 0:                                   # literal
            ln = tag >> 2
            if ln < 60:
                ln += 1
            else:
                extra = ln - 59
                if pos + extra > n:
                    raise ValueError("snappy literal len eof")
                ln = int.from_bytes(buf[pos:pos + extra], "little") + 1
                pos += extra
            if pos + ln > n:
                raise ValueError("snappy literal eof")
            out += buf[pos:pos + ln]
            pos += ln
        else:                                        # copy
            if t == 1:
                ln = ((tag >> 2) & 0x7) + 4
                if pos >= n:
                    raise ValueError("snappy copy1 eof")
                off = ((tag >> 5) << 8) | buf[pos]
                pos += 1
            elif t == 2:
                ln = (tag >> 2) + 1
                if pos + 2 > n:
                    raise ValueError("snappy copy2 eof")
                off = int.from_bytes(buf[pos:pos + 2], "little")
                pos += 2
            else:
                ln = (tag >> 2) + 1
                if pos + 4 > n:
                    raise ValueError("snappy copy4 eof")
                off = int.from_bytes(buf[pos:pos + 4], "little")
                pos += 4
            if off <= 0 or off > len(out):
                raise ValueError("snappy bad offset %d at %d" % (off, pos))
            start = len(out) - off
            for i in range(ln):
                out.append(out[start + i])
        if len(out) > max_out:
            raise ValueError("snappy overrun")
    if ulen and len(out) != ulen:
        raise ValueError("snappy length mismatch %d != %d" % (len(out), ulen))
    return bytes(out)


_LDB_MAGIC = 0xDB4775248B80FB57


def _leveldb_block(data, off, size):
    if off < 0 or size < 0 or off + size > len(data):
        raise ValueError("block out of range")
    raw = data[off:off + size]
    ctype = data[off + size] if off + size < len(data) else 0
    if ctype == 1:
        return snappy_decompress(raw)
    if ctype != 0:
        raise ValueError("unknown block compression %d" % ctype)
    return raw


def _block_entries(block):
    """解析一个（已解压的）leveldb block，返回 [(key, value)]。"""
    if len(block) < 8:
        return []
    nrestarts = struct.unpack_from("<I", block, len(block) - 4)[0]
    if nrestarts * 4 + 4 > len(block):
        raise ValueError("bad restart count")
    limit = len(block) - 4 - 4 * nrestarts
    out = []
    pos = 0
    key = b""
    while pos < limit:
        shared, pos = _varint(block, pos)
        nonshared, pos = _varint(block, pos)
        vlen, pos = _varint(block, pos)
        if pos + nonshared + vlen > len(block):
            break
        key = key[:shared] + block[pos:pos + nonshared]
        pos += nonshared
        val = block[pos:pos + vlen]
        pos += vlen
        out.append((key, val))
    return out


def leveldb_pairs(data):
    """解析 Chromium LevelDB 表文件（.ldb/.sst）的全部 (key, value)。

    结构：footer(48B, 尾部 8B magic) -> index block -> 每个 data block。
    失败抛 ValueError（调用方降级为二进制扫）。
    """
    data = bytes(data)
    if len(data) < 48:
        raise ValueError("table too short")
    footer = data[-48:]
    if struct.unpack_from("<Q", footer, 40)[0] != _LDB_MAGIC:
        raise ValueError("bad table magic")
    pos = 0
    _, pos = _varint(footer, pos)        # metaindex offset
    _, pos = _varint(footer, pos)        # metaindex size
    idx_off, pos = _varint(footer, pos)
    idx_size, pos = _varint(footer, pos)
    index = _leveldb_block(data, idx_off, idx_size)
    pairs = []
    for _ikey, ival in _block_entries(index):
        p = 0
        boff, p = _varint(ival, p)
        bsize, p = _varint(ival, p)
        pairs.extend(_block_entries(_leveldb_block(data, boff, bsize)))
    return pairs


_LOG_FULL, _LOG_FIRST, _LOG_MIDDLE, _LOG_LAST = 1, 2, 3, 4


def leveldb_wal_records(data):
    """解析 leveldb Write-Ahead Log（.log）：32KB 物理块 + 7 字节头。"""
    data = bytes(data)
    bs = 32768
    out = []
    off = 0
    frag = None
    n = len(data)
    while off + 7 <= n:
        blk_left = bs - (off % bs)
        if blk_left < 7:                      # 块尾 padding
            off += blk_left
            continue
        _crc, ln, typ = struct.unpack_from("<IHB", data, off)
        off += 7
        if typ == 0 and ln == 0:              # 预分配/padding 区
            off += bs - (off % bs) if (off % bs) else 0
            continue
        if ln > bs or off + ln > n:
            break
        payload = data[off:off + ln]
        off += ln
        if typ == _LOG_FULL:
            out.append(payload)
            frag = None
        elif typ == _LOG_FIRST:
            frag = bytearray(payload)
        elif typ == _LOG_MIDDLE and frag is not None:
            frag += payload
        elif typ == _LOG_LAST and frag is not None:
            frag += payload
            out.append(bytes(frag))
            frag = None
    return out


def _match_brace(blob, start, max_len=1 << 20):
    depth = 0
    i = start
    n = min(len(blob), start + max_len)
    in_str = False
    esc = False
    while i < n:
        c = blob[i]
        if in_str:
            if esc:
                esc = False
            elif c == 0x5C:
                esc = True
            elif c == 0x22:
                in_str = False
        else:
            if c == 0x22:
                in_str = True
            elif c == 0x7B:
                depth += 1
            elif c == 0x7D:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def extract_json_objects(blob, max_objects=2000, min_len=10):
    """从任意二进制块里抽出能 json.loads 的 {...} 对象（大括号配平，遇串跳过）。"""
    blob = bytes(blob)
    out = []
    i = 0
    n = len(blob)
    while i < n and len(out) < max_objects:
        i = blob.find(b"{", i)
        if i < 0:
            break
        end = _match_brace(blob, i)
        if end < 0:
            i += 1
            continue
        frag = blob[i:end + 1]
        if len(frag) < min_len:
            i = end + 1
            continue
        obj = None
        try:
            obj = json.loads(frag.decode("utf-8"))
        except Exception:
            try:
                obj = json.loads(frag.decode("utf-8", "replace"))
            except Exception:
                obj = None
        if isinstance(obj, (dict, list)):
            out.append(obj)
            i = end + 1
        else:
            i += 1
    return out


# ---------------------------------------------------------------------------
# 钱包应用发现
# ---------------------------------------------------------------------------

class WalletFinder:
    """在 Ext4 / NTFS 镜像里定位虚拟货币钱包落盘数据。"""

    def __init__(self, fs):
        self.fs = fs if isinstance(fs, FsView) else FsView(fs)
        self.notes = []

    # ---------------- 内部 ----------------
    @staticmethod
    def _app_of(name):
        return _NAME_INDEX.get(name.lower())

    def _markers_in(self, path, is_dir, app, depth=3):
        """在应用目录里找特征文件，返回命中的 marker 列表。"""
        if not is_dir:
            return []
        spec = WALLET_APPS.get(app, {})
        markers = set(spec.get("markers", []))
        hits = []
        try:
            for sub, is_subdir, obj in self.fs.walk(path, maxdepth=depth):
                base = sub.rsplit("/", 1)[-1].lower()
                for m in markers:
                    if m == base or m in base:
                        hits.append(sub)
                        break
                if len(hits) >= 6:
                    break
        except Exception as e:
            self.notes.append("marker scan %s: %s" % (path, e))
        return hits

    def _scan_base(self, base, out, seen):
        if not base or not self.fs.isdir(base):
            return
        for name, is_dir, obj in self.fs.listdir(base):
            app = self._app_of(name)
            if app is None:
                continue
            path = (base.rstrip("/") or "") + "/" + name
            key = (app, path.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "app": app,
                "path": path,
                "kind": "android-app" if "data" in base else "dir",
                "is_dir": is_dir,
                "markers": self._markers_in(path, is_dir, app),
                "source": base,
            })

    def _scan_win_users(self, out, seen):
        for base in ("/Users", "/Documents and Settings"):
            if not self.fs.isdir(base):
                continue
            for uname, is_dir, _obj in self.fs.listdir(base):
                if not is_dir or uname in ("All Users", "Default", "Public", "Default User"):
                    continue
                for suffix in _WIN_USER_SUFFIX:
                    root = "%s/%s%s" % (base.rstrip("/"), uname, suffix)
                    if not self.fs.isdir(root):
                        continue
                    for name, sd, _o in self.fs.listdir(root):
                        app = self._app_of(name)
                        if app is None:
                            continue
                        path = root.rstrip("/") + "/" + name
                        key = (app, path.lower())
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append({
                            "app": app, "path": path, "kind": "win-app",
                            "is_dir": sd,
                            "markers": self._markers_in(path, sd, app),
                            "source": root,
                        })

    # ---------------- 公共 ----------------
    def discover(self):
        """全盘搜钱包应用，返回 [{app, path, kind, markers, source}]。"""
        out = []
        seen = set()
        roots = list(_ANDROID_DATA_ROOTS) + list(_WIN_ROOTS)
        for base in roots:
            try:
                self._scan_base(base, out, seen)
            except Exception as e:
                self.notes.append("scan %s: %s" % (base, e))
        try:
            self._scan_win_users(out, seen)
        except Exception as e:
            self.notes.append("scan win users: %s" % e)

        # 包名出现在 /data/app 的 apk 文件名里（如 io.metamask-1/base.apk）
        for base in ("/data/app", "/app"):
            if not self.fs.isdir(base):
                continue
            for name, is_dir, _obj in self.fs.listdir(base):
                low = name.lower()
                for app, spec in WALLET_APPS.items():
                    for pkg in spec["android"]:
                        if low.startswith(pkg):
                            path = base.rstrip("/") + "/" + name
                            key = (app, path.lower())
                            if key in seen:
                                continue
                            seen.add(key)
                            out.append({
                                "app": app, "path": path, "kind": "apk",
                                "is_dir": is_dir, "markers": [], "source": base,
                            })
                            break
        # 通用标记：任意目录里出现 vault.json / default_wallet / wallet.dat
        marker_names = ("vault.json", "default_wallet", "wallet.dat", "seed.seco",
                        "exodus.conf.json", "wallets.db")
        for base in ("/data/data", "/data/user/0", "/persist-root/data/data",
                     "/sdcard", "/storage/emulated/0", "/Users"):
            if not self.fs.isdir(base):
                continue
            try:
                found = self.fs.find_named([base], marker_names, maxdepth=6)
            except Exception as e:
                self.notes.append("marker find %s: %s" % (base, e))
                continue
            for path, is_dir, _obj in found:
                if is_dir:
                    continue
                base_name = path.rsplit("/", 1)[-1].lower()
                app = {
                    "vault.json": "MetaMask", "default_wallet": "Electrum",
                    "wallet.dat": "BitcoinCore", "seed.seco": "Exodus",
                    "exodus.conf.json": "Exodus", "wallets.db": "imToken",
                }.get(base_name, "unknown")
                parent = path.rsplit("/", 1)[0]
                key = (app, parent.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "app": app, "path": parent, "kind": "marker",
                    "is_dir": True, "markers": [path], "source": base,
                })
        out.sort(key=lambda d: (d["app"], d["path"]))
        return out


# ---------------------------------------------------------------------------
# MetaMask
# ---------------------------------------------------------------------------

class MetaMaskVault:
    """MetaMask（io.metamask）vault / 账户 / 交易 提取与解密。"""

    _EXT_OK = (".ldb", ".log", ".sst", ".json", ".db", ".sqlite", ".sqlite3",
               ".plist", ".txt", ".manifest-*")
    _NAME_OK = ("rkstorage", "localstorage", "manifest.json", "vault.json", "indexeddb")

    def __init__(self, fs, root="/data/data/io.metamask"):
        self.fs = fs if isinstance(fs, FsView) else FsView(fs)
        self.root = self.fs.norm(root)
        self.notes = []
        self._blobs_cache = None
        self._vault_cache = None

    # ---------------- 磁盘布局 ----------------
    def _interesting(self, path):
        base = path.rsplit("/", 1)[-1].lower()
        if base in self._NAME_OK:
            return True
        for ext in self._EXT_OK:
            if base.endswith(ext):
                return True
        return base.endswith(".ldb") or base.endswith(".log")

    def blobs(self):
        """[(path, bytes)]：root 下所有可能有用的文件（含 leveldb/RKStorage）。"""
        if self._blobs_cache is not None:
            return self._blobs_cache
        out = []
        for path, is_dir, obj in self.fs.walk(self.root, maxdepth=8):
            if is_dir:
                continue
            if not self._interesting(path):
                continue
            data = self.fs.read_obj(obj, max_size=64 << 20)
            if data:
                out.append((path, data))
        self._blobs_cache = out
        return out

    def _pairs(self):
        """[(path, key, value)]：leveldb 结构化解析结果（失败的文件跳过）。"""
        out = []
        for path, data in self.blobs():
            low = path.lower()
            try:
                if low.endswith((".ldb", ".sst")):
                    for k, v in leveldb_pairs(data):
                        out.append((path, k, v))
                elif low.endswith(".log"):
                    for rec in leveldb_wal_records(data):
                        # WAL 记录 = 批量写：seq(8) count(4) [type(1) key(v) value(v)]*
                        pos = 12
                        for _ in range(len(rec)):
                            if pos >= len(rec):
                                break
                            t = rec[pos]
                            pos += 1
                            if t == 0:      # 删除标记：只有 key
                                try:
                                    kl, pos = _varint(rec, pos)
                                except ValueError:
                                    break
                                out.append((path, rec[pos:pos + kl], b""))
                                pos += kl
                            elif t == 1:
                                try:
                                    kl, pos = _varint(rec, pos)
                                    key = rec[pos:pos + kl]
                                    pos += kl
                                    vl, pos = _varint(rec, pos)
                                    val = rec[pos:pos + vl]
                                    pos += vl
                                except ValueError:
                                    break
                                out.append((path, key, val))
                            else:
                                break
            except Exception as e:
                self.notes.append("leveldb %s: %s" % (path, e))
        return out

    # ---------------- vault ----------------
    @staticmethod
    def _looks_vault(obj):
        return isinstance(obj, dict) and all(k in obj for k in ("salt", "iv", "data"))

    def _vault_from_obj(self, obj):
        if not isinstance(obj, dict):
            return None
        if self._looks_vault(obj):
            return obj
        for key in ("vault", "Vault", "metamask_vault"):
            v = obj.get(key)
            if isinstance(v, str):
                try:
                    v = json.loads(v)
                except Exception:
                    v = None
            if self._looks_vault(v):
                return v
        return None

    def vaults(self):
        """所有 vault 候选：[(source, vault_dict)]。"""
        out = []
        if self._vault_cache is not None:
            return self._vault_cache
        # 1) 明文 vault.json / sqlite 表
        for path, data in self.blobs():
            base = path.rsplit("/", 1)[-1].lower()
            if data[:15] == b"SQLite format 3":
                for src, obj in self._sqlite_json(path, data):
                    v = self._vault_from_obj(obj)
                    if v:
                        out.append((src, v))
                continue
            if base.endswith(".json"):
                try:
                    j = json.loads(data.decode("utf-8", "replace"))
                except Exception:
                    j = None
                v = self._vault_from_obj(j)
                if v:
                    out.append((path, v))
                    continue
            for obj in extract_json_objects(data, max_objects=600):
                v = self._vault_from_obj(obj)
                if v:
                    out.append((path, v))
        # 2) leveldb 结构化键值（值里常是 JSON 字符串）
        for path, _k, val in self._pairs():
            if b"salt" not in val:
                continue
            for obj in extract_json_objects(val, max_objects=20):
                v = self._vault_from_obj(obj)
                if v:
                    out.append((path, v))
        self._vault_cache = out
        return out

    def vault(self):
        """返回第一个 vault dict（salt/iv/data + keyMetadata），没有则 {}。"""
        vs = self.vaults()
        if not vs:
            self.notes.append("未找到 vault：已扫 %d 个文件" % len(self.blobs()))
            return {}
        src, v = vs[0]
        out = dict(v)
        out["_source"] = src
        return out

    # ---------------- SQLite ----------------
    def _sqlite_json(self, path, data):
        """把 SQLite 表里的文本值当 JSON 候选吐出：[(source, obj)]。"""
        out = []
        try:
            from .mobile import SqliteTriage
        except ImportError:
            from mkit.mobile import SqliteTriage  # type: ignore
        try:
            db = SqliteTriage(data)
        except Exception as e:
            self.notes.append("sqlite %s: %s" % (path, e))
            return out
        try:
            tables = db.tables()
        except Exception:
            tables = {}
        for tbl in tables:
            if not re.search(r"(?i)storage|pref|kv|setting|keyvalue|cache|state", tbl):
                continue
            try:
                rows = db.query_dicts('select * from "%s"' % tbl, limit=4000)
            except Exception:
                continue
            for row in rows:
                for v in row.values():
                    if not isinstance(v, str):
                        continue
                    for obj in extract_json_objects(v.encode("utf-8", "replace"),
                                                  max_objects=40):
                        out.append(("%s#%s" % (path, tbl), obj))
                    # 单层 JSON 字符串（如 {"salt":..,"iv":..,"data":..}）
                    try:
                        j = json.loads(v)
                    except Exception:
                        j = None
                    if isinstance(j, dict):
                        out.append(("%s#%s" % (path, tbl), j))
        try:
            db.close()
        except Exception:
            pass
        return out

    # ---------------- 账户 ----------------
    @staticmethod
    def _identities(obj, depth=0):
        """从任意 JSON 结构里挖 {address: name}。"""
        found = {}
        if depth > 6:
            return found
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", k):
                    nm = v.get("name") if isinstance(v, dict) else None
                    found[k] = nm
                    if isinstance(v, dict):
                        found.update(MetaMaskVault._identities(v, depth + 1))
                elif isinstance(v, (dict, list)):
                    found.update(MetaMaskVault._identities(v, depth + 1))
        elif isinstance(obj, list):
            for it in obj:
                found.update(MetaMaskVault._identities(it, depth + 1))
        return found

    def accounts(self):
        """账户地址列表（0x 地址去重），标注来源与可读名字。"""
        acc = {}
        for path, data in self.blobs():
            for m in _ADDR_ETH.finditer(data):
                addr = m.group(0).decode()
                acc.setdefault(addr.lower(), {"address": addr, "source": path,
                                              "name": None, "via": "regex"})
        for path, _k, val in self._pairs():
            for obj in extract_json_objects(val, max_objects=40):
                for addr, nm in self._identities(obj).items():
                    key = addr.lower()
                    rec = acc.setdefault(key, {"address": addr, "source": path,
                                               "name": None, "via": "identities"})
                    if nm:
                        rec["name"] = nm
                    rec["via"] = "identities"
        for src, obj in self._vaults_plain():
            for addr, nm in self._identities(obj).items():
                key = addr.lower()
                rec = acc.setdefault(key, {"address": addr, "source": src,
                                           "name": None, "via": "vault-plain"})
                if nm:
                    rec["name"] = nm
        out = []
        for rec in acc.values():
            low = rec["address"].lower()
            rec["contract"] = bool(KNOWN_CONTRACTS.get(low))
            rec["label"] = KNOWN_CONTRACTS.get(low) if rec["contract"] else None
            out.append(rec)
        out.sort(key=lambda d: (d["contract"], d["address"].lower()))
        return out

    def _vaults_plain(self):
        """vault 里已经明文的 identities（未加密桌面版 / 已解 context）。"""
        out = []
        for path, data in self.blobs():
            for obj in extract_json_objects(data, max_objects=200):
                if self._identities(obj):
                    out.append((path, obj))
                    break
        return out

    # ---------------- 交易 ----------------
    @staticmethod
    def _norm_tx(obj, source):
        if not isinstance(obj, dict):
            return None
        low = {str(k).lower(): v for k, v in obj.items()}
        to = low.get("to") or low.get("toaddress") or low.get("recipient")
        val = low.get("value") or low.get("amount") or low.get("valuetransfer")
        if not isinstance(to, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", to):
            return None
        if val is None:
            return None
        ts = None
        for k in ("time", "timestamp", "date", "createdat", "created_at"):
            if k in low:
                ts = low[k]
                break
        ts_iso = None
        if isinstance(ts, (int, float)):
            v = float(ts)
            if v > 1e12:
                v /= 1000.0
            try:
                ts_iso = datetime.datetime.fromtimestamp(v, datetime.timezone.utc).isoformat()
            except Exception:
                ts_iso = None
        return {
            "hash": low.get("hash") or low.get("txhash") or low.get("transactionhash"),
            "from": low.get("from"),
            "to": to,
            "value": val,
            "value_eth": _to_eth(val),
            "gas": low.get("gas") or low.get("gaslimit"),
            "gas_price": low.get("gasprice") or low.get("maxfee") or low.get("maxfeepergas"),
            "nonce": low.get("nonce"),
            "time": ts_iso or (ts if isinstance(ts, str) else None),
            "status": low.get("status") or low.get("state"),
            "error": low.get("error") or low.get("errormessage"),
            "chain_id": low.get("chainid"),
            "source": source,
        }

    def txs(self):
        """交易记录：从 leveldb / IndexedDB / SQLite 的 JSON 里还原。"""
        out = []
        seen = set()

        def push(tx):
            if not tx:
                return
            key = (tx.get("hash"), tx.get("to"), str(tx.get("value")), tx.get("time"))
            if key in seen:
                return
            seen.add(key)
            out.append(tx)

        for path, data in self.blobs():
            for obj in extract_json_objects(data, max_objects=600):
                push(self._norm_tx(obj, path))
                # leveldb 里可能是 JSON 字符串套 JSON
                if isinstance(obj, dict):
                    for v in obj.values():
                        if isinstance(v, str) and v.startswith("{"):
                            try:
                                push(self._norm_tx(json.loads(v), path))
                            except Exception:
                                pass
        for path, _k, val in self._pairs():
            if b'"to"' not in val and b'"to":' not in val:
                continue
            for obj in extract_json_objects(val, max_objects=60):
                push(self._norm_tx(obj, path))
        # RPC 原始交易（0xf86...）走 chain.parse_eth_tx
        for path, data in self.blobs():
            for m in re.finditer(rb"0x[fF][89ab][0-9a-fA-F]{180,}", data):
                try:
                    tx = parse_eth_tx(m.group(0)[2:].decode())
                except Exception:
                    continue
                push({
                    "hash": tx.get("hash"), "from": tx.get("from"), "to": tx.get("to"),
                    "value": tx.get("value_wei"), "value_eth": tx.get("value_eth"),
                    "gas": tx.get("gas"), "gas_price": tx.get("gas_price"),
                    "nonce": tx.get("nonce"), "time": None, "status": None,
                    "chain_id": tx.get("chain_id"), "source": path + "#rawtx",
                })
        out.sort(key=lambda d: (str(d.get("time") or "")))
        return out

    # ---------------- 解密 ----------------
    def decrypt_vault(self, password, vault=None):
        """解密 MetaMask vault，返回 {ok, mnemonic, private_keys, accounts, ...}。"""
        v = vault if vault is not None else self.vault()
        if not v:
            return {"ok": False, "error": "未找到 vault（salt/iv/data）", "notes": self.notes}
        try:
            salt = bytes.fromhex(str(v["salt"]))
            iv = bytes.fromhex(str(v["iv"]))
            ct = bytes.fromhex(str(v["data"]))
        except Exception as e:
            return {"ok": False, "error": "vault 字段不是 hex: %s" % e}
        meta = v.get("keyMetadata") or {}
        iters = int(meta.get("params", {}).get("iterations", VAULT_ITER) or VAULT_ITER) \
            if isinstance(meta, dict) else VAULT_ITER
        if isinstance(password, str):
            password = password.encode("utf-8")
        key = hashlib.pbkdf2_hmac("sha256", password, salt, iters, VAULT_DKLEN)
        try:
            from Crypto.Cipher import AES
        except ImportError as e:                     # pragma: no cover
            return {"ok": False, "error": "需要 pycryptodome 才能解 AES-GCM: %s" % e}
        if len(ct) <= 16:
            return {"ok": False, "error": "密文太短（%d 字节）" % len(ct)}
        body, tag = ct[:-16], ct[-16:]
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            plain = cipher.decrypt_and_verify(body, tag)
        except Exception as e:
            return {"ok": False, "error": "解密失败（口令错误或 vault 损坏）: %s" % e,
                    "iterations": iters, "iv_len": len(iv)}
        try:
            data = json.loads(plain.decode("utf-8"))
        except Exception as e:
            return {"ok": False, "error": "明文不是 JSON: %s" % e,
                    "plain_head": plain[:64].hex()}
        return _describe_vault_plain(data, key=key, iterations=iters, iv=iv, salt=salt)


def _to_eth(val):
    """value 转 ETH 数量（十进制字符串）。十进制串按 wei 解释，带小数点视为已换算。"""
    try:
        if isinstance(val, dict):
            val = val.get("value") or val.get("hex")
        if isinstance(val, str):
            s = val.strip()
            if "." in s:
                return s
            if s.lower().startswith("0x"):
                wei = int(s, 16)
            else:
                wei = int(s)
        else:
            wei = int(val)
    except Exception:
        return None
    q, r = divmod(wei, 10 ** 18)
    frac = ("%018d" % r).rstrip("0")
    return str(q) + ("." + frac if frac else "")


def _describe_vault_plain(data, key=None, iterations=None, iv=None, salt=None):
    """把 vault 明文整理成 {mnemonic, keyrings, accounts, private_keys}。"""
    out = {"ok": True, "iterations": iterations,
           "iv_len": len(iv) if iv else None, "salt_hex": salt.hex() if salt else None}
    body = data.get("data") if isinstance(data, dict) else None
    meta = data.get("meta") if isinstance(data, dict) else None
    if meta is not None:
        out["meta"] = meta
    node = body if isinstance(body, dict) else (data if isinstance(data, dict) else {})
    keyrings = node.get("keyrings") or []
    out["keyrings"] = keyrings
    mnemonics = []
    privs = []
    for kr in keyrings:
        krd = kr.get("data") if isinstance(kr, dict) else None
        if not isinstance(krd, dict):
            krd = kr if isinstance(kr, dict) else {}
        mn = krd.get("mnemonic")
        if isinstance(mn, list):
            mnemonics.append(" ".join(str(w) for w in mn))
        elif isinstance(mn, str):
            mnemonics.append(mn)
        pk = krd.get("privateKey") or krd.get("private_key")
        if isinstance(pk, str):
            privs.append(pk)
        for kid, kd in (krd.get("keypairs") or {}).items() if isinstance(
                krd.get("keypairs"), dict) else []:
            pass
    top_mn = node.get("mnemonic")
    if isinstance(top_mn, list):
        mnemonics.insert(0, " ".join(str(w) for w in top_mn))
    elif isinstance(top_mn, str):
        mnemonics.insert(0, top_mn)
    # 逐个 keyring 里的 keypairs（MetaMask 的 HD Key Tree 里 keypairs 是明文私钥）
    for kr in keyrings:
        krd = kr.get("data") if isinstance(kr, dict) else None
        if not isinstance(krd, dict):
            continue
        kps = krd.get("keypairs")
        if isinstance(kps, dict):
            for _addr, kp in kps.items():
                if isinstance(kp, dict):
                    pk = kp.get("privateKey")
                    if isinstance(pk, str):
                        privs.append(pk if pk.startswith("0x") else "0x" + pk)
        for kp in (krd.get("keypairs") or []) if isinstance(krd.get("keypairs"), list) else []:
            if isinstance(kp, dict) and isinstance(kp.get("privateKey"), str):
                privs.append(kp["privateKey"])
    out["mnemonic"] = mnemonics[0] if mnemonics else None
    out["mnemonics"] = mnemonics
    out["private_keys"] = sorted(set(privs))
    # 私钥 -> 地址（自校验，顺便确认解出来的东西自洽）
    derived = []
    for pk in out["private_keys"]:
        try:
            derived.append({"private_key": pk,
                            "address": eth_address_from_privkey(pk)})
        except Exception:
            continue
    out["derived"] = derived
    accounts = node.get("accounts") if isinstance(node, dict) else None
    if isinstance(accounts, dict):
        out["accounts"] = [{"address": a, "name": (v or {}).get("name")
                            if isinstance(v, dict) else None} for a, v in accounts.items()]
    elif isinstance(accounts, list):
        out["accounts"] = accounts
    else:
        out["accounts"] = []
    out["raw_plaintext_keys"] = sorted(node.keys()) if isinstance(node, dict) else []
    return out


# ---------------------------------------------------------------------------
# Electrum
# ---------------------------------------------------------------------------

class ElectrumWallet:
    """Electrum json 钱包（default_wallet）。"""

    def __init__(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.raw = bytes(data)
        self.notes = []
        try:
            self.json = json.loads(self.raw.decode("utf-8", "replace"))
        except Exception as e:
            self.json = {}
            self.notes.append("json 解析失败: %s" % e)

    # ---------------- seed ----------------
    @staticmethod
    def _decrypt_seed(b64, password):
        """Electrum pw_decode：BIE1 + PBKDF2-SHA512('Satoshi',1024) + AES-256-CBC。"""
        from Crypto.Cipher import AES
        blob = base64.b64decode(b64 + "==")
        if blob[:4] != b"BIE1":
            raise ValueError("不是 Electrum BIE1 加密串")
        key = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), b"Satoshi", 1024, 32)
        ct = blob[4:]
        iv, body = ct[:16], ct[16:]
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
        pad = plain[-1]
        if 1 <= pad <= 16:
            plain = plain[:-pad]
        return plain.decode("utf-8")

    def info(self, password=None):
        j = self.json if isinstance(self.json, dict) else {}
        ks = j.get("keystore") if isinstance(j.get("keystore"), dict) else {}
        seed_obj = j.get("seed") or ks.get("seed")
        seed_version = j.get("seed_version", ks.get("seed_version"))
        use_enc = bool(j.get("use_encryption") or ks.get("use_encryption"))
        encrypted = isinstance(seed_obj, str) and seed_obj.startswith("BIE1")
        use_enc = use_enc or encrypted
        seed = None
        seed_kind = None
        err = None
        if isinstance(seed_obj, str) and seed_obj:
            if encrypted or use_enc:
                if password:
                    try:
                        seed = self._decrypt_seed(seed_obj, password)
                        seed_kind = "decrypted"
                    except Exception as e:
                        err = "解密失败: %s" % e
                else:
                    err = "seed 已加密，需要 password"
            else:
                seed = seed_obj
                seed_kind = "plain"
        elif isinstance(seed_obj, list):
            seed = " ".join(str(w) for w in seed_obj)
            seed_kind = "plain"
        elif isinstance(ks.get("keypairs"), dict) and ks["keypairs"]:
            seed_kind = "keypairs"
        # seed 形态判定
        seed_hex = None
        words = None
        if seed:
            s = seed.strip()
            if re.fullmatch(r"[0-9a-fA-F]{16,128}", s):
                seed_hex = s.lower()
                if len(s) == 64:
                    seed_kind = (seed_kind or "") + "+hex32"
            elif re.fullmatch(r"[a-zA-Z]+([ \-][a-zA-Z]+){11,23}", s):
                words = re.split(r"[ \-]", s)
                seed_kind = "mnemonic"

        # 地址
        addrs = []
        bal = 0.0
        for bucket in ("addresses", "change_addresses", "receiving", "change"):
            cont = j.get(bucket)
            if isinstance(cont, dict):
                for sub in cont.values():
                    addrs.extend(self._addrs(sub))
            elif isinstance(cont, list):
                addrs.extend(self._addrs(cont))
        for acc in (j.get("accounts") or {}).values() if isinstance(j.get("accounts"), dict) else []:
            if isinstance(acc, dict):
                for k in ("addresses", "change_addresses"):
                    addrs.extend(self._addrs(acc.get(k)))
        # 余额：addr_history 里 role/value 求和
        hist = j.get("addr_history")
        history_total = None
        if isinstance(hist, dict):
            history_total = 0
            for items in hist.values():
                if isinstance(items, list):
                    for it in items:
                        if isinstance(it, dict) and isinstance(it.get("value"), int):
                            history_total += it["value"]
        for a in addrs:
            if isinstance(a.get("balance"), (int, float)):
                bal += a["balance"] / 1e8
        uniq = {}
        for a in addrs:
            if a.get("address"):
                uniq.setdefault(a["address"], a)
        return {
            "wallet_type": j.get("wallet_type"),
            "seed_version": seed_version,
            "use_encryption": use_enc,
            "encrypted": encrypted,
            "seed": seed,
            "seed_kind": seed_kind,
            "seed_hex": seed_hex,
            "seed_words": words,
            "seed_error": err,
            "xpub": ks.get("xpub") or j.get("master_public_key"),
            "derivation": ks.get("derivation"),
            "root_fingerprint": ks.get("root_fingerprint"),
            "keystore_type": ks.get("type"),
            "addresses": list(uniq.values()),
            "address_count": len(uniq),
            "balance_btc": round(bal, 8) if bal else 0.0,
            "history_total_satoshi": history_total,
            "labels": j.get("labels") if isinstance(j.get("labels"), dict) else {},
            "gap_limit": j.get("gap_limit"),
            "notes": self.notes,
        }

    @staticmethod
    def _addrs(cont):
        out = []
        if isinstance(cont, list):
            for it in cont:
                if isinstance(it, dict):
                    out.append(it)
                elif isinstance(it, str):
                    out.append({"address": it})
        elif isinstance(cont, dict):
            for k, v in cont.items():
                if isinstance(v, dict):
                    rec = dict(v)
                    rec.setdefault("address", k)
                    out.append(rec)
                elif isinstance(v, str) and re.fullmatch(r"[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-z0-9]{20,60}", k):
                    out.append({"address": k, "label": v})
        return out


# ---------------------------------------------------------------------------
# Bitcoin Core wallet.dat（BDB）
# ---------------------------------------------------------------------------

class BitcoinCoreWallet:
    """wallet.dat（Berkeley DB BTree）best-effort 提取。

    BDB 的 key 是 0x00 + 记录名 + 主键，因此直接扫 b'\\x00mkey'/b'\\x00ckey'/b'\\x00name'
    /b'\\x00addr'/b'\\x00pkey' 就能定位记录起点；value 紧随其后（长度前缀）。
    """

    TAGS = (b"\x00mkey", b"\x00ckey", b"\x00key", b"\x00pkey",
            b"\x00name", b"\x00addr", b"\x00pool", b"\x00version", b"\x00bestblock")

    def __init__(self, data):
        if isinstance(data, str):
            with open(data, "rb") as f:
                data = f.read()
        self.raw = bytes(data)
        self.notes = []
        self._items = None

    # ---------------- 工具 ----------------
    @staticmethod
    def _csize(buf, pos):
        """Bitcoin compact size。"""
        if pos >= len(buf):
            raise ValueError("csize eof")
        v = buf[pos]
        if v < 0xFD:
            return v, pos + 1
        if v == 0xFD:
            return int.from_bytes(buf[pos + 1:pos + 3], "little"), pos + 3
        if v == 0xFE:
            return int.from_bytes(buf[pos + 1:pos + 5], "little"), pos + 5
        return int.from_bytes(buf[pos + 1:pos + 9], "little"), pos + 9

    def _scan(self):
        if self._items is not None:
            return self._items
        items = []
        raw = self.raw
        for tag in self.TAGS:
            start = 0
            while True:
                i = raw.find(tag, start)
                if i < 0:
                    break
                start = i + 1
                name = tag[1:].decode("ascii")
                body = raw[i + len(tag): i + len(tag) + 256]
                rec = {"tag": name, "offset": i}
                if name == "addr":
                    h = body[:20]
                    rec["hash160"] = h.hex()
                    rec["address"] = self._addr_from_hash160(h)
                    items.append(rec)
                elif name == "pkey":
                    h = body[:20]
                    rec["hash160"] = h.hex()
                    rec["address"] = self._addr_from_hash160(h)
                    items.append(rec)
                elif name in ("mkey", "key"):
                    try:
                        ver = int.from_bytes(body[0:4], "little")
                        publen, p = self._csize(body, 4)
                        pub = body[p:p + publen]
                        p2 = p + publen
                        elen, p2 = self._csize(body, p2)
                        enc = body[p2:p2 + elen]
                        rec.update({
                            "version": ver, "pubkey_hex": pub.hex() if pub else None,
                            "encrypted_key_hex": enc.hex() if enc else None,
                            "key_len": len(enc), "crypted": bool(enc),
                        })
                        if pub and len(pub) in (33, 65):
                            h = hash160(pub)
                            rec["hash160"] = h.hex()
                            rec["address"] = self._addr_from_hash160(h)
                    except Exception as e:
                        rec["parse_error"] = str(e)
                    items.append(rec)
                elif name == "ckey":
                    h = body[:20]
                    try:
                        elen, p = self._csize(body, 20)
                        enc = body[p:p + elen]
                    except Exception:
                        enc = body[20:68]
                        rec["parse_error"] = "csize fallback"
                    rec.update({"hash160": h.hex(), "address": self._addr_from_hash160(h),
                                "encrypted_key_hex": enc.hex() if enc else None,
                                "key_len": len(enc), "crypted": True})
                    items.append(rec)
                elif name == "name":
                    txt = bytearray()
                    for b in body:
                        if 32 <= b < 127:
                            txt.append(b)
                        else:
                            break
                    rec["name"] = txt.decode("ascii", "replace")
                    rec["address"] = rec["name"]
                    items.append(rec)
                elif name == "pool":
                    rec["raw"] = body[:16].hex()
                    items.append(rec)
        # 去重（同一记录在 mkey 与 key 两个 tag 下会重复）
        uniq = {}
        for it in items:
            key = (it["tag"], it.get("address"), it.get("offset"))
            uniq.setdefault(key, it)
        self._items = list(uniq.values())
        if not self._items:
            self.notes.append(
                "未找到 BDB 记录：wallet.dat 可能使用了 Berkeley DB 页压缩/加密，"
                "或文件已被截断（已扫 tag: %s）"
                % ", ".join(t.lstrip(b"\x00").decode() for t in self.TAGS))
        elif not any(i.get("address") for i in self._items):
            self.notes.append("找到记录但无法还原地址（长度前缀解析失败）")
        return self._items

    @staticmethod
    def _addr_from_hash160(h):
        if not h or len(h) != 20:
            return None
        try:
            return base58check_encode(0, h)
        except Exception:
            return None

    # ---------------- 公共 ----------------
    def addresses(self):
        out = []
        for it in self._scan():
            a = it.get("address")
            if a and a.startswith(("1", "3")) and a not in out:
                out.append(a)
        return out

    def keys(self):
        out = []
        for it in self._scan():
            if it["tag"] not in ("mkey", "ckey", "key", "pkey"):
                continue
            out.append({
                "tag": it["tag"], "offset": it.get("offset"),
                "hash160": it.get("hash160"), "address": it.get("address"),
                "pubkey_hex": it.get("pubkey_hex"),
                "encrypted_key_hex": it.get("encrypted_key_hex"),
                "key_len": it.get("key_len"), "crypted": it.get("crypted"),
                "version": it.get("version"),
            })
        return out

    def names(self):
        return [{"name": it.get("name"), "offset": it.get("offset")}
                for it in self._scan() if it.get("tag") == "name"]

    def summary(self):
        return {
            "size": len(self.raw),
            "is_bdb": self.raw[:4] in (b"\x00\x05\x31\x62", b"\x00\x06\x15\x61")
                      or b"Berkeley DB" in self.raw[:4096],
            "addresses": self.addresses(),
            "keys": len(self.keys()),
            "names": self.names()[:20],
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# 全盘地址提取
# ---------------------------------------------------------------------------

def _guess_source(path, data):
    low = path.lower()
    if data[:15] == b"SQLite format 3":
        return "sqlite"
    if data[:8] == b"bplist00":
        return "plist"
    if low.endswith((".ldb", ".sst", ".log")):
        return "leveldb"
    if low.endswith((".json", ".txt", ".xml", ".html", ".conf", ".ovpn", ".log")):
        return "text"
    printable = sum(1 for b in data[:4096] if 9 <= b <= 13 or 32 <= b <= 126)
    if data and printable / max(1, min(len(data), 4096)) > 0.9:
        return "text"
    return "binary"


class AddressList(list):
    """list[dict] 子类，附带扫描统计（stats），保持 `-> list[dict]` 契约。"""

    stats = {}

    def __init__(self, items=(), stats=None):
        super().__init__(items)
        self.stats = dict(stats or {})


def find_addresses_in_fs(fs, roots=("/data",), limit=500, maxdepth=16,
                         max_file=8 << 20, budget=768 << 20, include_bitcoin=True):
    """扫 roots 下的文本/SQLite/leveldb，提取地址并标注来源与类型。

    返回 list[dict]（AddressList）：address / type / valid / checksum / path /
    source / context / note；扫描统计见 `.stats`。
    """
    view = fs if isinstance(fs, FsView) else FsView(fs)
    if isinstance(roots, str):
        roots = [roots]
    out = []
    seen = set()
    spent = 0
    scanned = 0
    skipped = []

    def push(addr, atype, valid, checksum, path, source, context, note=None):
        key = (addr.lower(), atype, path)
        if key in seen:
            return
        seen.add(key)
        out.append({
            "address": addr, "type": atype, "valid": valid, "checksum": checksum,
            "path": path, "source": source, "context": (context or "")[:160],
            "note": note or "",
        })

    for root in roots:
        for path, is_dir, obj in view.walk(root, maxdepth=maxdepth):
            if len(out) >= limit:
                break
            if is_dir:
                continue
            size = view.size(obj)
            base = path.rsplit("/", 1)[-1]
            ext = ("." + base.rsplit(".", 1)[-1].lower()) if "." in base else ""
            if ext in _SKIP_EXT:
                continue
            if size > max_file:
                skipped.append((path, size, "too-large"))
                continue
            if spent + size > budget:
                skipped.append((path, size, "budget"))
                break
            data = view.read_obj(obj, max_size=max_file)
            if not data:
                continue
            spent += len(data)
            scanned += 1
            if not (_ADDR_ETH.search(data) or (include_bitcoin and _ADDR_BTC.search(data))
                    or _ADDR_TRON.search(data)):
                continue
            source = _guess_source(path, data)
            text = data.decode("utf-8", "replace")
            try:
                hits = scan_addresses(text)
            except Exception:
                hits = []
            if not hits:
                for m in _ADDR_ETH.finditer(data):
                    push(m.group(0).decode(), "eth", True, "unchecked", path, source, "")
                if include_bitcoin:
                    for m in _ADDR_BTC.finditer(data):
                        push(m.group(0).decode(), "btc_p2pkh", True, "unchecked",
                             path, source, "")
                continue
            for h in hits:
                push(h["address"], h["type"], h.get("valid"), h.get("checksum"),
                     path, source, h.get("context"), h.get("note"))
    return AddressList(out[:limit], stats={
        "scanned_files": scanned,
        "scanned_bytes": spent,
        "skipped": skipped[:40],
        "notes": view.notes[-20:],
        "roots": list(roots),
    })
