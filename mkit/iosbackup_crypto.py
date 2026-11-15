# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""iOS 加密（iTunes/Finder）备份解密：keybag 解析 + AES-256-KW + AES-256-CBC。

对应 2024 美亚杯团体赛：加密 iTunes 备份（备份密码 1234）里 WhatsApp 群创建时间 /
照片创建时间这类题。

实现依据（Apple 备份格式，iOS 10.2 及以后）
--------------------------------------------
1. ``Manifest.plist`` 的 ``BackupKeyBag`` 是一串 TLV：``4 字节 tag + 4 字节大端长度 + 值``。
   常见 tag：``VERS TYPE UUID HMCK WRAP SALT ITER DPWT DPIC DPSL``；
   每个保护类一段：``UUID`` 开头，包 ``CLAS``(类号) ``WRAP``(包裹方式位) ``KTYP``(密钥类型)
   ``WPKY``(被 AES-KW 包裹的 32 字节类密钥) ``PBKY``。
2. 口令派生（两轮）::

       temp = PBKDF2-HMAC-SHA256(password, DPSL, DPIC, 32)
       kek  = PBKDF2-HMAC-SHA1  (temp,     SALT, ITER, 32)

   注：早期资料里的"两轮 PBKDF2-SHA256"说法有误；iOS >= 10.2 的第二轮是 SHA1。
   本模块内置多组派生候选，并以 AES-KW 的 A6A6A6A6A6A6A6A6 完整性校验自动挑选正确的一组，
   所以既兼容老备份也兼容 iOS 10.2+。
3. ``class_key = AES-KW-unwrap(kek, WPKY)``（仅当 ``WRAP & 2``，即位 1 = 口令保护）。
4. ``Manifest.db``：``Manifest.plist`` 的 ``ManifestKey`` = 4 字节类号 + 40 字节包裹密钥；
   ``manifest_key = AES-KW-unwrap(class_key, ManifestKey[4:])``；
   整库用 AES-256-CBC 解密，IV = 全 0（个别工具/样本用文件头 16 字节，本模块两种都试，
   以解密结果的 ``"SQLite format 3\\x00"`` 魔数判定）。
5. 单个文件：``Manifest.db`` 里每个文件行的 ``EncryptionKey`` = 4 字节类号 + 40 字节包裹密钥；
   ``file_key = AES-KW-unwrap(class_key, EncryptionKey[4:])``；
   文件用 AES-256-CBC 解密（IV 全 0），末尾做 PKCS#7 去填充。

AES 原语由 pycryptodome 提供；AES-256-KW（RFC 3394）是本文件自己实现的，不依赖第三方。
"""
import hashlib
import os
import plistlib
import sqlite3
import struct
import tempfile

from Crypto.Cipher import AES

__all__ = [
    "BackupCrypto", "KeyBag", "BackupDir",
    "aes_key_unwrap", "aes_key_wrap", "aes_cbc_encrypt", "aes_cbc_decrypt",
    "pkcs7_pad", "pkcs7_unpad", "build_test_keybag", "build_test_manifest_plist",
]

KW_IV = 0xA6A6A6A6A6A6A6A6          # RFC 3394 默认初始值
SQLITE_MAGIC = b"SQLite format 3\x00"
WRAP_PASSCODE = 2                  # 类密钥 WRAP 字段的"口令保护"位


# ---------------------------------------------------------------------------
# 基础密码学原语
# ---------------------------------------------------------------------------

def _ecb_decrypt(kek, block):
    return AES.new(kek, AES.MODE_ECB).decrypt(block)


def _ecb_encrypt(kek, block):
    return AES.new(kek, AES.MODE_ECB).encrypt(block)


def aes_key_unwrap(kek, wrapped):
    """RFC 3394 AES Key Unwrap。成功返回明文密钥，完整性校验失败返回 None。"""
    if kek is None or wrapped is None:
        return None
    if len(wrapped) % 8 or len(wrapped) < 16:
        return None
    if len(kek) not in (16, 24, 32):
        return None
    n = len(wrapped) // 8 - 1
    a = int.from_bytes(wrapped[:8], "big")
    r = [int.from_bytes(wrapped[8 * (i + 1):8 * (i + 2)], "big") for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = (a ^ (n * j + i)) & 0xFFFFFFFFFFFFFFFF
            block = t.to_bytes(8, "big") + r[i - 1].to_bytes(8, "big")
            b = _ecb_decrypt(kek, block)
            a = int.from_bytes(b[:8], "big")
            r[i - 1] = int.from_bytes(b[8:], "big")
    if a != KW_IV:
        return None
    return b"".join(x.to_bytes(8, "big") for x in r)


def aes_key_wrap(kek, key):
    """RFC 3394 AES Key Wrap（生成测试样本用）。"""
    if len(key) % 8:
        raise ValueError("被包裹密钥长度必须是 8 的倍数")
    n = len(key) // 8
    a = KW_IV
    r = [int.from_bytes(key[8 * i:8 * (i + 1)], "big") for i in range(n)]
    for j in range(6):
        for i in range(1, n + 1):
            block = a.to_bytes(8, "big") + r[i - 1].to_bytes(8, "big")
            b = _ecb_encrypt(kek, block)
            a = (int.from_bytes(b[:8], "big") ^ (n * j + i)) & 0xFFFFFFFFFFFFFFFF
            r[i - 1] = int.from_bytes(b[8:], "big")
    return a.to_bytes(8, "big") + b"".join(x.to_bytes(8, "big") for x in r)


def pkcs7_pad(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def pkcs7_unpad(data, block=16):
    """返回 (去填充数据, 是否合法)。"""
    if not data or len(data) % block:
        return data, False
    n = data[-1]
    if 1 <= n <= block and data[-n:] == bytes([n]) * n:
        return data[:-n], True
    return data, False


def aes_cbc_encrypt(key, data, iv=None, pad=True):
    iv = iv or b"\x00" * 16
    body = pkcs7_pad(data) if pad else data
    body = body[:len(body) // 16 * 16]
    return AES.new(key, AES.MODE_CBC, iv).encrypt(body)


def aes_cbc_decrypt(key, data, iv=None, unpad=False):
    """AES-256-CBC 解密；``unpad=True`` 时按 PKCS#7 去填充（不合法则原样返回）。"""
    iv = iv or b"\x00" * 16
    body = data[:len(data) // 16 * 16]
    out = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
    if unpad:
        out, _ok = pkcs7_unpad(out)
    return out


def _cbc_try(key, data):
    """两种 IV 约定都试一遍，返回 [(iv_name, plaintext)]，零 IV 优先。"""
    out = []
    out.append(("zero-iv", aes_cbc_decrypt(key, data, b"\x00" * 16)))
    if len(data) > 32:
        out.append(("file-iv", aes_cbc_decrypt(key, data[16:], data[:16])))
    return out


def _strip_padding(plain):
    """CBC 明文若是合法 PKCS#7 填充则去掉（备份里的文件/数据库都带填充）。"""
    if len(plain) % 16:
        return plain
    stripped, ok = pkcs7_unpad(plain)
    return stripped if ok else plain


# ---------------------------------------------------------------------------
# KeyBag
# ---------------------------------------------------------------------------

_BAG_TAGS = {b"VERS", b"TYPE", b"UUID", b"HMCK", b"WRAP", b"SALT", b"ITER",
             b"DPWT", b"DPIC", b"DPSL"}
_CLASS_TAGS = {b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"}


def _as_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, (bytes, bytearray)) and len(v) in (1, 2, 4, 8):
        return int.from_bytes(v, "big")
    return None


class KeyBag:
    """``BackupKeyBag`` TLV 解析 + 口令派生 + 类密钥解包。"""

    def __init__(self, blob):
        self.blob = bytes(blob or b"")
        self.attrs = {}        # tag(bytes) -> bytes|int
        self.classes = {}      # CLAS(int) -> {tag(bytes): value}
        self.uuid = None
        self.wrap = None
        self.derivation = None
        self.kek = None
        self._parse()
        self._unlock_class_keys = {}

    # -- TLV -----------------------------------------------------------
    def _parse(self):
        i, n = 0, len(self.blob)
        cur = None
        classes_started = False

        def flush():
            if cur and b"CLAS" in cur:
                cls = _as_int(cur[b"CLAS"])
                if cls is not None:
                    self.classes[cls] = dict(cur)

        while i + 8 <= n:
            tag = self.blob[i:i + 4]
            ln = struct.unpack_from(">I", self.blob, i + 4)[0]
            val = self.blob[i + 8:i + 8 + ln]
            i += 8 + ln
            if tag == b"UUID":
                if self.uuid is None and not classes_started:
                    self.uuid = val
                else:
                    flush()
                    cur = {b"UUID": val}
                    classes_started = True
            elif tag == b"CLAS":
                if cur is None or b"CLAS" in cur:
                    flush()
                    cur = {}
                    classes_started = True
                cur[b"CLAS"] = val
            elif tag in _CLASS_TAGS and cur is not None:
                cur[tag] = val
            elif tag == b"WRAP" and self.wrap is None:
                self.wrap = val
                self.attrs[tag] = val
            else:
                self.attrs[tag] = val
        flush()

    # -- 便捷属性 -------------------------------------------------------
    def get(self, tag, default=None):
        return self.attrs.get(tag, default)

    @property
    def type(self):
        return _as_int(self.attrs.get(b"TYPE"))

    @property
    def versions(self):
        return _as_int(self.attrs.get(b"VERS"))

    @property
    def salt(self):
        return self.attrs.get(b"SALT")

    @property
    def iterations(self):
        return _as_int(self.attrs.get(b"ITER"))

    @property
    def dpsl(self):
        return self.attrs.get(b"DPSL")

    @property
    def dpic(self):
        return _as_int(self.attrs.get(b"DPIC"))

    @property
    def dpwt(self):
        return _as_int(self.attrs.get(b"DPWT"))

    # -- 口令派生 -------------------------------------------------------
    def derivation_candidates(self, password):
        """返回 [(名称, 32 字节 kek)]，按"最可能正确"排序。"""
        pwd = password.encode("utf-8") if isinstance(password, str) else bytes(password)
        salt, it = self.salt, self.iterations or 1
        dpsl, dpic = self.dpsl, self.dpic
        out = []
        if dpsl and dpic:
            temp = hashlib.pbkdf2_hmac("sha256", pwd, dpsl, dpic, 32)
            if salt:
                out.append(("pbkdf2-sha256(dpsl)->sha1(salt)",
                            hashlib.pbkdf2_hmac("sha1", temp, salt, it, 32)))
                out.append(("pbkdf2-sha256(dpsl)->sha256(salt)",
                            hashlib.pbkdf2_hmac("sha256", temp, salt, it, 32)))
            out.append(("pbkdf2-sha256(dpsl)", temp))
        if salt:
            out.append(("pbkdf2-sha1(salt)", hashlib.pbkdf2_hmac("sha1", pwd, salt, it, 32)))
            out.append(("pbkdf2-sha256(salt)", hashlib.pbkdf2_hmac("sha256", pwd, salt, it, 32)))
        if dpsl:
            out.append(("pbkdf2-sha256(dpsl,iter)",
                        hashlib.pbkdf2_hmac("sha256", pwd, dpsl, it, 32)))
        return out

    def passcode_class_keys(self):
        """可被口令解包的类（WRAP 位 1 = 口令保护），返回 [(cls, entry)]。"""
        res = []
        for cls, ent in sorted(self.classes.items()):
            if b"WPKY" not in ent:
                continue
            wrap = _as_int(ent.get(b"WRAP"))
            if wrap is None or (wrap & WRAP_PASSCODE):
                res.append((cls, ent))
        return res

    def unlock(self, password):
        """试所有派生候选；用 AES-KW 完整性校验判定口令是否正确。"""
        targets = self.passcode_class_keys()
        if not targets:
            return False
        for name, kek in self.derivation_candidates(password):
            keys = {}
            ok = True
            for cls, ent in targets:
                k = aes_key_unwrap(kek, ent[b"WPKY"])
                if k is None:
                    ok = False
                    break
                keys[cls] = k
            if ok and keys:
                self.derivation = name
                self.kek = kek
                self._unlock_class_keys = keys
                return True
        return False

    def class_key(self, protection_class):
        return self._unlock_class_keys.get(protection_class)

    @property
    def class_kinds(self):
        """Apple 保护类说明（1..11 + 100）。"""
        return {
            1: "NSFileProtectionComplete",
            2: "NSFileProtectionCompleteUnlessOpen",
            3: "NSFileProtectionCompleteUntilFirstUserAuthentication",
            4: "NSFileProtectionNone / ManifestKey",
            5: "NSFileProtectionCompleteUntilFirstUserAuthentication(5)",
            6: "NSFileProtectionCompleteUnlessOpen(6)",
            7: "NSFileProtectionCompleteUntilFirstUserAuthentication(7)",
            8: "NSFileProtectionCompleteAlways(8)",
            9: "NSFileProtectionCompleteUnlessOpen(9)",
            10: "NSFileProtectionCompleteUntilFirstUserAuthentication(10)",
            11: "NSFileProtectionCompleteAlways(11)/ApplePay",
            100: "NSFileProtectionCompleteWhenUserInactive",
        }

    def info(self):
        classes = []
        for cls, ent in sorted(self.classes.items()):
            classes.append({
                "class": cls,
                "name": self.class_kinds.get(cls, "?"),
                "ktyp": _as_int(ent.get(b"KTYP")),
                "wrap_flags": _as_int(ent.get(b"WRAP")),
                "has_wpky": b"WPKY" in ent,
                "wpky_len": len(ent.get(b"WPKY") or b""),
                "unlocked": cls in self._unlock_class_keys,
            })
        dpwt = self.dpwt
        return {
            "type": self.type,
            "versions": self.versions,
            "uuid": self.uuid.hex() if self.uuid else None,
            "iterations": self.iterations,
            "dpic": self.dpic,
            "dpwt": dpwt,
            "salt_len": len(self.salt or b""),
            "dpsl_len": len(self.dpsl or b""),
            "has_hmck": b"HMCK" in self.attrs,
            "has_bag_wrap": self.wrap is not None,
            "secure_enclave": bool(self.dpsl is None or self.dpic is None
                                   or (dpwt not in (None, 0, 1))),
            "derivation": self.derivation,
            "unlocked": bool(self._unlock_class_keys),
            "classes": classes,
        }


# ---------------------------------------------------------------------------
# NSKeyedArchiver（Manifest.db 的 file 列）
# ---------------------------------------------------------------------------

def _resolve(obj, objects, depth=0):
    """把 NSKeyedArchiver 的 UID 引用解析成普通 Python 值。"""
    if depth > 12:
        return None
    if isinstance(obj, plistlib.UID):
        idx = obj.data
        if 0 <= idx < len(objects):
            return _resolve(objects[idx], objects, depth + 1)
        return None
    if isinstance(obj, dict):
        if "NS.data" in obj and isinstance(obj["NS.data"], (bytes, bytearray)):
            return bytes(obj["NS.data"])
        if "NS.bytes" in obj and isinstance(obj["NS.bytes"], (bytes, bytearray)):
            return bytes(obj["NS.bytes"])
        if "NS.string" in obj:
            return obj["NS.string"]
        if "NS.objects" in obj:
            return [_resolve(x, objects, depth + 1) for x in obj["NS.objects"]]
        out = {}
        for k, v in obj.items():
            if k in ("$class",):
                continue
            out[k] = _resolve(v, objects, depth + 1)
        return out
    if isinstance(obj, list):
        return [_resolve(x, objects, depth + 1) for x in obj]
    return obj


def parse_file_meta(blob):
    """把 Manifest.db ``file`` 列（NSKeyedArchiver plist）解析成 dict。"""
    if not blob:
        return {}
    try:
        pl = plistlib.loads(blob)
    except Exception:
        return {}
    if isinstance(pl, dict) and "$objects" in pl:
        objects = pl["$objects"]
        top = pl.get("$top") or {}
        root_ref = top.get("root")
        root = _resolve(root_ref, objects) if root_ref is not None else None
        obj = root if isinstance(root, dict) else {}
    elif isinstance(pl, dict):
        obj = pl
    else:
        return {}
    enc = obj.get("EncryptionKey")
    if isinstance(enc, (bytes, bytearray)):
        enc = bytes(enc)
    else:
        enc = None
    return {
        "protection_class": obj.get("ProtectionClass"),
        "encryption_key": enc,
        "size": obj.get("Size"),
        "birth": obj.get("Birth"),
        "last_modified": obj.get("LastModified"),
        "last_status_change": obj.get("LastStatusChange"),
        "mode": obj.get("Mode") or obj.get("Flags"),
        "user_id": obj.get("UserID"),
        "group_id": obj.get("GroupID"),
        "inode": obj.get("InodeNumber"),
        "relative_path": obj.get("RelativePath"),
        "flags": obj.get("Flags"),
        "raw": obj,
    }


# ---------------------------------------------------------------------------
# BackupCrypto
# ---------------------------------------------------------------------------

class BackupCrypto:
    """用 ``Manifest.plist`` 解密 iOS 加密备份。"""

    def __init__(self, manifest_plist_bytes=None, plist_path=None):
        if manifest_plist_bytes is None and plist_path is None:
            raise ValueError("需要 manifest_plist_bytes 或 plist_path")
        if manifest_plist_bytes is None:
            with open(plist_path, "rb") as f:
                manifest_plist_bytes = f.read()
        if isinstance(manifest_plist_bytes, (str, os.PathLike)):
            with open(manifest_plist_bytes, "rb") as f:
                manifest_plist_bytes = f.read()
        self.raw = bytes(manifest_plist_bytes)
        self.manifest = plistlib.loads(self.raw)
        self.keybag = KeyBag(self.manifest.get("BackupKeyBag") or b"")
        self.password = None

    # -- 状态 -----------------------------------------------------------
    @property
    def encrypted(self):
        return bool(self.manifest.get("IsEncrypted"))

    @property
    def unlocked(self):
        return bool(self.keybag.derivation)

    def has_manifest_key(self):
        return bool(self.manifest.get("ManifestKey"))

    def unlock(self, password):
        """口令正确返回 True（用 AES-KW 完整性校验验证，不靠试错）。"""
        if not self.encrypted or password is None:
            return False
        if not self.keybag.unlock(password):
            return False
        if self.has_manifest_key() and not self._manifest_key():
            # 极端情况：口令派生能解类密钥却解不出 ManifestKey
            return False
        self.password = password
        return True

    # -- ManifestKey ----------------------------------------------------
    def _manifest_key(self):
        mk = self.manifest.get("ManifestKey")
        if not mk:
            return None
        if isinstance(mk, (bytes, bytearray)):
            mk = bytes(mk)
            if len(mk) >= 44:
                cls = struct.unpack("<i", mk[:4])[0]
                wrapped = mk[4:44]
            else:
                cls, wrapped = 4, mk
        else:
            return None
        ck = self.keybag.class_key(cls)
        if ck is None:
            return None
        return aes_key_unwrap(ck, wrapped)

    def manifest_key(self):
        return self._manifest_key()

    # -- Manifest.db ----------------------------------------------------
    def decrypt_manifest_db(self, encrypted_db):
        """解 ``Manifest.db``；返回明文 bytes（已是明文则原样返回）。"""
        data = bytes(encrypted_db)
        if data[:16] == SQLITE_MAGIC:
            return data
        if not self.encrypted:
            return data
        key = self._manifest_key()
        if key is None:
            raise RuntimeError("ManifestKey 解不出：口令未解或 keybag 缺类密钥")
        best = None
        for iv_name, plain in _cbc_try(key, data):
            plain = _strip_padding(plain)
            if plain[:16] == SQLITE_MAGIC:
                return plain
            if best is None:
                best = plain
            elif b"SQLite format 3" in plain[:64]:
                return plain
        return best or b""

    def decrypt_manifest_db_file(self, path):
        with open(path, "rb") as f:
            return self.decrypt_manifest_db(f.read())

    # -- 单文件 ---------------------------------------------------------
    def class_key(self, protection_class):
        return self.keybag.class_key(int(protection_class))

    def file_key(self, protection_class, wrapped_key):
        """EncryptionKey（4 字节类号 + 40 字节包裹密钥）→ 32 字节文件密钥。"""
        if wrapped_key is None:
            return None
        wk = bytes(wrapped_key)
        if len(wk) == 44:
            cls = struct.unpack("<i", wk[:4])[0]
            wk = wk[4:]
            protection_class = protection_class if protection_class is not None else cls
        ck = self.class_key(protection_class)
        if ck is None:
            return None
        return aes_key_unwrap(ck, wk)

    def decrypt_file(self, encrypted, protection_class, wrapped_key=None, iv=None):
        """解密备份里的单个文件。

        ``wrapped_key`` 给 Manifest.db 里的 ``EncryptionKey``；缺省时直接把
        ``protection_class`` 的类密钥当文件密钥（少数样本如此）。
        """
        data = bytes(encrypted)
        key = None
        if wrapped_key:
            key = self.file_key(protection_class, wrapped_key)
        if key is None:
            key = self.class_key(protection_class)
        if key is None:
            raise RuntimeError("保护类 %s 的类密钥不可用（口令未解？）" % protection_class)
        if iv is not None:
            return aes_cbc_decrypt(key, data, iv, unpad=True)
        zero = aes_cbc_decrypt(key, data, b"\x00" * 16)
        zero_un, ok0 = pkcs7_unpad(zero)
        if ok0:
            return zero_un
        if len(data) > 32:
            fiv = aes_cbc_decrypt(key, data[16:], data[:16])
            fiv_un, ok1 = pkcs7_unpad(fiv)
            if ok1:
                return fiv_un
        return zero  # 无填充（.db/.sqlite 等自行处理）

    # -- Manifest.db 行 --------------------------------------------------
    def manifest_rows(self, db_bytes):
        """解析 Manifest.db 的 Files 表，返回行 dict 列表。"""
        plain = self.decrypt_manifest_db(db_bytes) if self.encrypted else bytes(db_bytes)
        tmp = tempfile.NamedTemporaryFile(suffix="-Manifest.db", delete=False)
        try:
            tmp.write(plain)
            tmp.close()
            con = sqlite3.connect(tmp.name)
            try:
                cur = con.execute(
                    "SELECT fileID, domain, relativePath, flags, file FROM Files")
                rows = []
                for fid, domain, rel, flags, blob in cur:
                    meta = parse_file_meta(blob)
                    rows.append({
                        "file_id": fid, "domain": domain, "relative_path": rel,
                        "flags": flags, "meta": meta,
                        "protection_class": meta.get("protection_class"),
                        "encryption_key": meta.get("encryption_key"),
                        "size": meta.get("size"),
                        "modified": meta.get("last_modified"),
                        "created": meta.get("birth"),
                        "is_dir": meta.get("encryption_key") is None,
                    })
                return rows
            finally:
                con.close()
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def keybag_info(self):
        info = self.keybag.info()
        info["encrypted"] = self.encrypted
        info["has_manifest_key"] = self.has_manifest_key()
        info["product_version"] = (self.manifest.get("Lockdown") or {}).get("ProductVersion")
        info["device_name"] = (self.manifest.get("Lockdown") or {}).get("DeviceName")
        info["manifest_key_ok"] = self._manifest_key() is not None if self.unlocked else False
        return info


# ---------------------------------------------------------------------------
# 整个备份目录
# ---------------------------------------------------------------------------

class BackupDir:
    """打开一个 iTunes/Finder 备份目录（加密或明文）。

    典型用法::

        bk = BackupDir(r"D:\\iPhone_backup", password="1234")
        for r in bk.rows("AppDomain-com.apple.mobileslideshow"):
            data = bk.read(r)            # 解密后的文件内容
    """

    def __init__(self, root, password=None, udid=None):
        self.root = root
        self.manifest_plist = None
        self.udid_dir = None
        for cand in self._candidate_dirs(root, udid):
            if os.path.isfile(os.path.join(cand, "Manifest.plist")):
                self.udid_dir = cand
                self.manifest_plist = os.path.join(cand, "Manifest.plist")
                break
        if not self.manifest_plist:
            raise FileNotFoundError("找不到 Manifest.plist: %s" % root)
        with open(self.manifest_plist, "rb") as f:
            self.crypto = BackupCrypto(f.read())
        self.unlocked = False
        if self.crypto.encrypted:
            if password is not None:
                self.unlocked = self.crypto.unlock(password)
        else:
            self.unlocked = True
        self._db_bytes = None
        self._rows = None

    @staticmethod
    def _candidate_dirs(root, udid=None):
        out = []
        if udid:
            out.append(os.path.join(root, udid))
        out.append(root)
        try:
            for name in sorted(os.listdir(root)):
                p = os.path.join(root, name)
                if os.path.isdir(p) and len(name) in (40, 24):
                    out.append(p)
        except OSError:
            pass
        return out

    # -- Manifest.db -----------------------------------------------------
    def manifest_db_bytes(self):
        if self._db_bytes is None:
            path = os.path.join(self.udid_dir, "Manifest.db")
            with open(path, "rb") as f:
                raw = f.read()
            self._db_bytes = (self.crypto.decrypt_manifest_db(raw)
                              if self.crypto.encrypted else raw)
        return self._db_bytes

    def rows(self, domain=None, like=None):
        if self._rows is None:
            self._rows = self.crypto.manifest_rows(self.manifest_db_bytes()) \
                if self.crypto.encrypted else self._plain_rows()
        res = self._rows
        if domain:
            res = [r for r in res if r["domain"] == domain]
        if like:
            needle = like.lower()
            res = [r for r in res if needle in (r["relative_path"] or "").lower()]
        return res

    def _plain_rows(self):
        plain = self.manifest_db_bytes()
        tmp = tempfile.NamedTemporaryFile(suffix="-Manifest.db", delete=False)
        try:
            tmp.write(plain)
            tmp.close()
            con = sqlite3.connect(tmp.name)
            try:
                rows = []
                for fid, domain, rel, flags, blob in con.execute(
                        "SELECT fileID, domain, relativePath, flags, file FROM Files"):
                    meta = parse_file_meta(blob)
                    rows.append({"file_id": fid, "domain": domain, "relative_path": rel,
                                 "flags": flags, "meta": meta,
                                 "protection_class": meta.get("protection_class"),
                                 "encryption_key": meta.get("encryption_key"),
                                 "size": meta.get("size"),
                                 "modified": meta.get("last_modified"),
                                 "created": meta.get("birth"),
                                 "is_dir": meta.get("encryption_key") is None})
                return rows
            finally:
                con.close()
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    # -- 文件 -----------------------------------------------------------
    def blob_path(self, file_id):
        return os.path.join(self.udid_dir, file_id[:2], file_id)

    def read(self, row):
        """按行解密文件内容（目录行返回 b""）。"""
        fid = row["file_id"] if isinstance(row, dict) else str(row)
        meta = row.get("meta", {}) if isinstance(row, dict) else {}
        p = self.blob_path(fid)
        if not os.path.isfile(p):
            return b""
        with open(p, "rb") as f:
            data = f.read()
        if not self.crypto.encrypted:
            return data
        cls = row.get("protection_class") if isinstance(row, dict) else None
        wkey = row.get("encryption_key") if isinstance(row, dict) else None
        if wkey is None:
            wkey = meta.get("encryption_key")
        if wkey is None:
            return data
        return self.crypto.decrypt_file(data, cls if cls is not None else 4, wkey)

    def extract(self, domain, relative_path):
        for r in self.rows(domain=domain):
            if r["relative_path"] == relative_path:
                return self.read(r)
        return None


# ---------------------------------------------------------------------------
# 测试样本生成器（造 keybag / Manifest.plist，用于自校验解密链路）
# ---------------------------------------------------------------------------

def build_test_keybag(password="1234", classes=(1, 2, 3, 4), iterations=10000,
                      dpic=10000, ktyp=0, seed=b"mkit-test-keybag"):
    """按真实 BackupKeyBag 结构造一个 keybag，返回 dict。

    返回 ``{"keybag": bytes, "class_keys": {cls: key}, "bag": KeyBag,
    "kek": kek, "salt": ..., "dpsl": ...}``。
    """
    def det(tag):
        return hashlib.sha256(seed + tag).digest()

    salt = det(b"salt")[:20]
    dpsl = hashlib.sha256(seed + b"dpsl").digest()[:20]
    temp = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), dpsl, dpic, 32)
    kek = hashlib.pbkdf2_hmac("sha1", temp, salt, iterations, 32)

    class_keys = {c: hashlib.sha256(seed + b"class" + bytes([c])).digest()
                  for c in classes}
    bag_uuid = det(b"uuid")[:16]

    def tlv(tag, val):
        return tag + struct.pack(">I", len(val)) + val

    def int4(v):
        return struct.pack(">I", v)

    blob = b""
    blob += tlv(b"VERS", int4(4))
    blob += tlv(b"TYPE", int4(1))                 # 1 = 备份 keybag
    blob += tlv(b"UUID", bag_uuid)
    blob += tlv(b"HMCK", det(b"hmck")[:40])
    blob += tlv(b"WRAP", det(b"bagwrap")[:40])
    blob += tlv(b"SALT", salt)
    blob += tlv(b"ITER", int4(iterations))
    blob += tlv(b"DPWT", int4(1))                 # 1 = 口令保护
    blob += tlv(b"DPIC", int4(dpic))
    blob += tlv(b"DPSL", dpsl)
    for cls in classes:
        blob += tlv(b"UUID", det(b"classuuid" + bytes([cls]))[:16])
        blob += tlv(b"CLAS", int4(cls))
        blob += tlv(b"WRAP", int4(WRAP_PASSCODE))  # 位 1：口令保护
        blob += tlv(b"KTYP", int4(ktyp))
        blob += tlv(b"WPKY", aes_key_wrap(kek, class_keys[cls]))
    return {"keybag": blob, "class_keys": class_keys, "bag": KeyBag(blob),
            "kek": kek, "salt": salt, "dpsl": dpsl, "password": password}


def build_test_manifest_plist(password="1234", manifest_class=4,
                              iterations=10000, dpic=10000,
                              product_version="16.7.2"):
    """造一个和真机同构的 ``Manifest.plist``（含 BackupKeyBag + ManifestKey）。"""
    built = build_test_keybag(password=password, iterations=iterations, dpic=dpic)
    manifest_key = hashlib.sha256(b"mkit-manifest-key" + password.encode()).digest()
    wrapped = aes_key_wrap(built["class_keys"][manifest_class], manifest_key)
    manifest_key_blob = struct.pack("<i", manifest_class) + wrapped
    pl = {
        "IsEncrypted": True,
        "Version": "10.0",
        "Date": None,
        "SystemDomainsVersion": "20.0",
        "WasPasscodeSet": True,
        "ManifestKey": manifest_key_blob,
        "BackupKeyBag": built["keybag"],
        "Lockdown": {"ProductVersion": product_version,
                     "DeviceName": "mkit-test-iphone",
                     "BuildVersion": "20H31"},
        "Applications": {},
    }
    import datetime
    pl["Date"] = datetime.datetime(2024, 5, 4, 12, 0, 0)
    return {
        "plist": plistlib.dumps(pl, fmt=plistlib.FMT_BINARY),
        "manifest_key": manifest_key,
        "class_keys": built["class_keys"],
        "keybag": built["keybag"],
        "built": built,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        bc = BackupCrypto(plist_path=sys.argv[1])
        info = bc.keybag_info()
        ok = bc.unlock(sys.argv[2]) if len(sys.argv) > 2 else None
        info["unlock_result"] = ok
        for k, v in info.items():
            print("%-22s %s" % (k, v))
