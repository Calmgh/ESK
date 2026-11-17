# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""LUKS1 / LUKS2 头部解析 + 口令解锁 + 扇区解密

对应 LovelyCarve 的「加密与快照」里的 LUKS 部分。

能力范围：
    ✓ 识别 LUKS1 / LUKS2
    ✓ 解析加密算法、模式、哈希、密钥长度、UUID、payload 偏移
    ✓ 枚举密钥槽（哪些是激活的、PBKDF2 迭代次数、盐）
    ✓ 解析 LUKS2 的 JSON 元数据（cipher / pbkdf / slots / segments）
    ✓ LUKS1 口令解锁：PBKDF2 → 密钥材料解密 → AF_merge → mk_digest 校验
    ✓ LUKS2 口令解锁：仅 pbkdf2 类型的 keyslot（Argon2 抛 NotImplementedError）
    ✓ 用解出的 master key 解密/加密数据扇区（AES-XTS / AES-CBC）
    ✗ 不支持 keyring / token / 恢复密码等非口令方式

支持的 cipher / mode（大小写不敏感）：
    cipher : aes
    mode   : xts-plain64、xts-plain（128 位小端 tweak，扇区号 < 2^32 时两者等价）、
             cbc-plain64、cbc-plain、cbc-essiv:<hash>（如 cbc-essiv:sha256）
    其余（serpent、twofish、aes-lrw-benbi、aes-cbc-benbi 等）抛 NotImplementedError。

实现依据（cryptsetup 语义，非猜测）：
    · LUKS1 密钥材料按 512 B 扇区、以 slot.keyMaterialOffset 为 IV 基准解密
      （lib/luks1/keyencryption.c：LUKS_decrypt_from_storage(..., keyMaterialOffset)，
       crypt_storage 内部 IV = iv_offset + i）
    · LUKS1 AF_merge 是纯哈希 diffuse（lib/luks1/af.c：4 字节大端块号 ‖ 数据）
    · LUKS2 keyslot area 解密 IV 基准为 0（lib/luks2/luks2_keyslot_luks2.c 传入 iv_offset=0），
      AF stripes 固定 LUKS_STRIPES = 4000
    · 数据区 IV 从 payload 起点按扇区 0 起算（dm-crypt 映射语义）

诚实标注：
    没有用真实 cryptsetup 创建的 LUKS1/LUKS2 镜像做过回归——手边没有可用样本，
    全部验证来自本文件自造的合成镜像 + 独立实现交叉对拍（NIST CAVP XTS 向量曾用
    cryptography 的 modes.XTS 复核）。因此「能解开真实卷」仍需实测确认；
    对真实卷解不开时应怀疑：cipher/mode 变体、Argon2、keyslot 类型，而不是密码。
"""

import hashlib
import hmac
import json
import os
import struct

try:                                            # 作为包导入
    from .aes import AES, cbc_encrypt, cbc_decrypt
except ImportError:                             # 直接以脚本运行（自检）
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from mkit.aes import AES, cbc_encrypt, cbc_decrypt

__all__ = [
    "Luks", "detect", "describe",
    "af_merge", "af_split", "diffuse",
    "xts_encrypt", "xts_decrypt", "xts_alpha", "sector_tweak",
    "SECTOR_SIZE", "LUKS_STRIPES",
]

LUKS_MAGIC = b"LUKS\xba\xbe"

LUKS1_HEADER_SIZE = 592
LUKS2_BINARY_HEADER_SIZE = 4096

SECTOR_SIZE = 512
LUKS_STRIPES = 4000                    # cryptsetup 的 LUKS_STRIPES，LUKS2 keyslot 也用这个
LUKS_KEY_ENABLED = 0x00AC71F3

_MAX_AF_BYTES = 64 << 20               # AF 区上限，防坏头导致巨额读取


# ------------------------------------------------------------
# 小工具
# ------------------------------------------------------------
def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _as_bytes(passphrase):
    """口令统一成 bytes：str 走 UTF-8，bytes 原样"""
    if passphrase is None:
        return b""
    if isinstance(passphrase, bytes):
        return passphrase
    if isinstance(passphrase, bytearray):
        return bytes(passphrase)
    return str(passphrase).encode("utf-8")


def _int_like(value, default=0):
    """LUKS2 的 JSON 里数值有 int 也有字符串两种写法"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _hash_size(hash_name):
    """哈希输出长度；名字不可用时给明确错误"""
    try:
        return hashlib.new(str(hash_name)).digest_size
    except (ValueError, TypeError) as exc:
        raise ValueError("未知/不可用的哈希 %r: %s" % (hash_name, exc))


def _split_cipher(cipher, mode):
    """拆 cipher/mode。

    LUKS1 是两个独立字段（"aes" + "xts-plain64"）；
    LUKS2 的 segments/area 是一个整体串（"aes-xts-plain64"）。
    """
    c = str(cipher or "").strip().lower()
    m = str(mode or "").strip().lower()
    if not m and "-" in c:
        cut = c.index("-")
        c, m = c[:cut], c[cut + 1:]
    return c, m


# ------------------------------------------------------------
# AES-XTS（IEEE 1619，128 位小端 tweak）
# ------------------------------------------------------------
_M64 = (1 << 64) - 1
_M128 = (1 << 128) - 1


def xts_alpha(t):
    """GF(2^128) 乘 x（小端表示，溢出异或 0x87）"""
    carry = t >> 127
    t = (t << 1) & _M128
    if carry:
        t ^= 0x87
    return t


def sector_tweak(sector):
    """扇区号 → 16 字节小端 tweak（plain64 语义）"""
    n = int(sector) & _M128
    return struct.pack("<QQ", n & _M64, (n >> 64) & _M64)


def xts_crypt(key, tweak, data, encrypt):
    """单数据单元 XTS；key = 数据密钥 ‖ tweak 密钥"""
    key = bytes(key)
    tweak = bytes(tweak)
    if len(key) not in (32, 64):
        raise ValueError("XTS 密钥必须是 32 或 64 字节，收到 %d" % len(key))
    if len(tweak) != 16:
        raise ValueError("XTS tweak 必须是 16 字节，收到 %d" % len(tweak))
    data = bytes(data)
    if len(data) % 16:
        raise ValueError("XTS 数据长度必须是 16 的倍数，收到 %d" % len(data))
    if not data:
        return b""
    half = len(key) // 2
    data_cipher = AES(key[:half])
    tweak_cipher = AES(key[half:])
    t = int.from_bytes(tweak_cipher.encrypt_block(tweak), "little")
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        tb = t.to_bytes(16, "little")
        block = _xor(data[off:off + 16], tb)
        block = data_cipher.encrypt_block(block) if encrypt else data_cipher.decrypt_block(block)
        out[off:off + 16] = _xor(block, tb)
        t = xts_alpha(t)
    return bytes(out)


def xts_encrypt(key, tweak, data):
    return xts_crypt(key, tweak, data, True)


def xts_decrypt(key, tweak, data):
    return xts_crypt(key, tweak, data, False)


# ------------------------------------------------------------
# CBC 的 IV（dm-crypt 的 plain / plain64 / essiv）
# ------------------------------------------------------------
def _cbc_iv(mode_name, sector, key):
    m = str(mode_name or "").strip().lower()
    n = int(sector)
    if m == "cbc-plain":
        return struct.pack("<I", n & 0xFFFFFFFF) + b"\x00" * 12
    if m == "cbc-plain64":
        return struct.pack("<Q", n & _M64) + b"\x00" * 8
    if m.startswith("cbc-essiv:"):
        hname = m.split(":", 1)[1] or "sha256"
        salt = hashlib.new(hname, bytes(key)).digest()
        if len(salt) not in (16, 24, 32):
            raise NotImplementedError(
                "ESSIV 盐长度 %d 不是合法 AES 密钥长度（hash=%s）" % (len(salt), hname))
        return AES(salt).encrypt_block(struct.pack("<Q", n & _M64) + b"\x00" * 8)
    raise NotImplementedError("未实现的 CBC IV 模式: %r" % mode_name)


def _crypt_units(key, data, cipher_name, mode_name, base_sector, decrypt):
    """按 512 B 扇区（一个数据单元）加/解密；base_sector 是这一段的扇区基准号"""
    data = bytes(data)
    if not data:
        return b""
    if len(data) % 16:
        raise ValueError("数据长度必须是 16 的倍数，收到 %d" % len(data))
    name = str(cipher_name or "").strip().lower()
    mode = str(mode_name or "").strip().lower()
    if name != "aes":
        raise NotImplementedError(
            "本模块只实现 AES（cipher=%r）；%s 需要额外算法实现" % (cipher_name, cipher_name))
    key = bytes(key)

    if mode.startswith("xts"):
        if mode not in ("xts-plain", "xts-plain64"):
            raise NotImplementedError("未实现的 XTS IV 模式: %r" % mode_name)
        if len(key) not in (32, 64):
            raise ValueError("XTS 密钥必须是 32 或 64 字节，收到 %d" % len(key))
        out = bytearray()
        for i, off in enumerate(range(0, len(data), SECTOR_SIZE)):
            out += xts_crypt(key, sector_tweak(base_sector + i),
                             data[off:off + SECTOR_SIZE], not decrypt)
        return bytes(out)

    if mode.startswith("cbc"):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES 密钥必须是 16/24/32 字节，收到 %d" % len(key))
        out = bytearray()
        for i, off in enumerate(range(0, len(data), SECTOR_SIZE)):
            chunk = data[off:off + SECTOR_SIZE]
            iv = _cbc_iv(mode, base_sector + i, key)
            out += cbc_decrypt(key, iv, chunk) if decrypt else cbc_encrypt(key, iv, chunk)
        return bytes(out)

    raise NotImplementedError("未实现的 cipher mode: %r" % mode_name)


# ------------------------------------------------------------
# AF splitter（cryptsetup lib/luks1/af.c 的等价实现）
# ------------------------------------------------------------
def diffuse(data, hash_name="sha256"):
    """信息扩散：按 hash 输出长度切块，每块 hash(be32(块号) ‖ 块) 截断回原长"""
    data = bytes(data)
    dsize = _hash_size(hash_name)
    name = str(hash_name)
    out = bytearray(len(data))
    for i, off in enumerate(range(0, len(data), dsize)):
        chunk = data[off:off + dsize]
        h = hashlib.new(name)
        h.update(struct.pack(">I", i))
        h.update(chunk)
        out[off:off + len(chunk)] = h.digest()[:len(chunk)]
    return bytes(out)


def af_split(secret, key_bytes, stripes, hash_name="sha256", rng=None):
    """把 secret 拆成 stripes 份（写盘用；自检里也拿它造镜像）"""
    secret = bytes(secret)
    key_bytes = int(key_bytes)
    stripes = int(stripes)
    if len(secret) != key_bytes:
        raise ValueError("secret 长度 %d 与 key_bytes %d 不符" % (len(secret), key_bytes))
    if stripes < 1:
        raise ValueError("stripes 必须 >= 1，收到 %d" % stripes)
    rng = rng or os.urandom
    buf = bytes(key_bytes)
    out = bytearray()
    for _ in range(stripes - 1):
        r = bytes(rng(key_bytes))
        if len(r) != key_bytes:
            raise ValueError("随机源返回长度不对")
        out += r
        buf = diffuse(_xor(buf, r), hash_name)
    out += _xor(buf, secret)
    return bytes(out)


def af_merge(material, key_bytes, stripes, hash_name="sha256"):
    """AF_merge：读回的密钥材料 → 候选 master key"""
    material = bytes(material)
    key_bytes = int(key_bytes)
    stripes = int(stripes)
    if key_bytes <= 0 or stripes < 1:
        raise ValueError("key_bytes/stripes 非法: %d/%d" % (key_bytes, stripes))
    need = key_bytes * stripes
    if len(material) < need:
        raise ValueError("密钥材料不足：需要 %d 字节，只有 %d" % (need, len(material)))
    buf = bytes(key_bytes)
    for i in range(stripes - 1):
        buf = diffuse(_xor(buf, material[i * key_bytes:(i + 1) * key_bytes]), hash_name)
    return _xor(buf, material[(stripes - 1) * key_bytes:stripes * key_bytes])


def _af_size(key_bytes, stripes):
    """AF_split_sectors() × 512：整扇区对齐后的密钥材料区长度"""
    key_bytes = int(key_bytes)
    stripes = int(stripes)
    if key_bytes <= 0 or stripes <= 0:
        raise ValueError("key_bytes/stripes 非法: %d/%d" % (key_bytes, stripes))
    total = key_bytes * stripes
    if total > _MAX_AF_BYTES:
        raise ValueError("AF 区长度异常（%d 字节），拒绝读取" % total)
    return (total + SECTOR_SIZE - 1) // SECTOR_SIZE * SECTOR_SIZE


def _pbkdf2(passphrase, salt, iterations, dklen, hash_name="sha256"):
    dklen = int(dklen)
    it = int(iterations)
    if dklen <= 0:
        raise ValueError("PBKDF2 输出长度必须为正，收到 %d" % dklen)
    if it <= 0:
        raise ValueError("PBKDF2 迭代次数必须为正，收到 %d" % it)
    name = str(hash_name or "sha256").strip().lower()
    try:
        return hashlib.pbkdf2_hmac(name, _as_bytes(passphrase), bytes(salt), it, dklen)
    except (ValueError, TypeError) as exc:
        raise ValueError("PBKDF2 无法使用哈希 %r: %s" % (name, exc))


class KeySlot(object):
    """LUKS1 密钥槽（LUKS2 的 keyslot 也复用这个容器）"""

    __slots__ = ("index", "active", "iterations", "salt", "key_material_offset",
                 "stripes")

    def __init__(self, index, active, iterations, salt, kmo, stripes):
        self.index = index
        self.active = active
        self.iterations = iterations
        self.salt = salt
        self.key_material_offset = kmo
        self.stripes = stripes

    def __repr__(self):
        return "<KeySlot %d %s iter=%d>" % (
            self.index, "ACTIVE" if self.active else "empty", self.iterations)


class Luks(object):
    """LUKS 头部（1 或 2）+ 口令解锁 + 数据扇区解密"""

    def __init__(self, sub):
        """sub: 有 read(offset, size) 的对象（分区或镜像）"""
        self.sub = sub
        self.master_key = None          # 解锁成功后填充
        self.unlocked_slot = None
        self.unlocked_kdf = None
        h = sub.read(0, LUKS2_BINARY_HEADER_SIZE)
        if len(h) < 8 or h[:6] != LUKS_MAGIC:
            raise ValueError("不是 LUKS（magic 不符）")
        (self.version,) = struct.unpack_from(">H", h, 6)
        if self.version == 1:
            self._parse_v1(h[:LUKS1_HEADER_SIZE])
        elif self.version == 2:
            self._parse_v2(h)
        else:
            raise ValueError("不支持的 LUKS 版本: %d" % self.version)

    # ---------------- LUKS1 ----------------
    def _parse_v1(self, h):
        self.cipher = h[8:40].split(b"\x00")[0].decode("ascii", "replace")
        self.mode = h[40:72].split(b"\x00")[0].decode("ascii", "replace")
        self.hash_spec = h[72:104].split(b"\x00")[0].decode("ascii", "replace")
        (self.payload_offset,) = struct.unpack_from(">I", h, 104)
        (self.key_bytes,) = struct.unpack_from(">I", h, 108)
        self.mk_digest = h[112:132]
        self.mk_digest_salt = h[132:164]
        (self.mk_digest_iter,) = struct.unpack_from(">I", h, 164)
        self.uuid = h[168:208].split(b"\x00")[0].decode("ascii", "replace")

        self.slots = []
        for i in range(8):
            base = 208 + i * 48
            (active,) = struct.unpack_from(">I", h, base)
            (iters,) = struct.unpack_from(">I", h, base + 4)
            salt = h[base + 8:base + 40]
            (kmo,) = struct.unpack_from(">I", h, base + 40)
            (stripes,) = struct.unpack_from(">I", h, base + 44)
            self.slots.append(KeySlot(i, active == 0x00AC71F3, iters, salt, kmo, stripes))

        self.active_slots = [s for s in self.slots if s.active]
        self.json = None
        self.pbkdf = "pbkdf2"

    # ---------------- LUKS2 ----------------
    def _parse_v2(self, h):
        (self.header_size,) = struct.unpack_from(">Q", h, 8)
        (self.seqid,) = struct.unpack_from(">Q", h, 16)
        self.label = h[24:72].split(b"\x00")[0].decode("utf-8", "replace")
        self.checksum_alg = h[72:104].split(b"\x00")[0].decode("ascii", "replace")
        self.uuid = h[168:208].split(b"\x00")[0].decode("ascii", "replace")

        # JSON 元数据紧跟在 4096 字节二进制头之后
        js_raw = self.sub.read(LUKS2_BINARY_HEADER_SIZE, 16 << 20)
        # JSON 以 \x00 结尾
        z = js_raw.find(b"\x00")
        if z >= 0:
            js_raw = js_raw[:z]
        try:
            self.json = json.loads(js_raw.decode("utf-8", "replace"))
        except Exception:
            self.json = None

        self.slots = []
        self.active_slots = []
        self.cipher = self.mode = self.hash_spec = ""
        self.key_bytes = 0
        self.payload_offset = 0
        self.pbkdf = ""
        self.mk_digest = b""
        self.mk_digest_salt = b""
        self.mk_digest_iter = 0

        if not self.json:
            return
        j = self.json

        def _int(v, d=0):
            """LUKS2 的 JSON 里数值有 int 也有字符串两种写法"""
            try:
                return int(v)
            except (TypeError, ValueError):
                return d

        segs = j.get("segments") or {}
        if segs:
            seg = next(iter(segs.values()))
            self.cipher = seg.get("encryption", "")
            self.payload_offset = _int(seg.get("offset")) // 512
            self.key_bytes = _int(seg.get("key_size")) // 8

        dt = j.get("digests") or {}
        if dt:
            dig = next(iter(dt.values()))
            self.hash_spec = dig.get("hash", "")
            self.mk_digest_iter = _int(dig.get("iterations"))
            self.mk_digest_salt = bytes.fromhex(dig.get("salt", "") or "")
            self.mk_digest = bytes.fromhex(dig.get("digest", "") or "")

        for sid, slot in (j.get("keyslots") or {}).items():
            kdf = slot.get("kdf") or {}
            area = slot.get("area") or {}
            self.slots.append(KeySlot(
                _int(sid), True,
                _int(kdf.get("iterations")),
                bytes.fromhex(kdf.get("salt", "") or ""),
                _int(area.get("offset")),
                _int(area.get("size"))))
            self.pbkdf = kdf.get("type", self.pbkdf)
        self.active_slots = list(self.slots)

    # ---------------- 输出 ----------------
    def info(self):
        return {
            "version": self.version,
            "cipher": self.cipher,
            "mode": self.mode,
            "hash": self.hash_spec,
            "key_bytes": self.key_bytes,
            "payload_offset_sectors": self.payload_offset,
            "uuid": self.uuid,
            "pbkdf": self.pbkdf,
            "mk_digest": self.mk_digest.hex(),
            "mk_digest_iterations": self.mk_digest_iter,
            "slots_total": len(self.slots),
            "slots_active": len(self.active_slots),
            "active_slot_ids": [s.index for s in self.active_slots],
            "unlocked": self.master_key is not None,
        }

    def slot_summary(self):
        """每个槽一行，便于报告"""
        out = []
        for s in self.slots:
            out.append({
                "slot": s.index,
                "active": s.active,
                "iterations": s.iterations,
                "salt_hex": s.salt.hex()[:32],
                "key_material_offset": s.key_material_offset,
            })
        return out

    def strength_note(self):
        """基于迭代次数给出密码强度线索（粗判，仅供参考）"""
        if not self.active_slots:
            return "无激活槽"
        it = max(s.iterations for s in self.active_slots)
        if self.version == 2 and self.pbkdf.startswith("argon2"):
            return "LUKS2 + %s（抗 GPU，强度高）" % self.pbkdf
        if it >= 1_000_000:
            return "PBKDF2 %d 次（强度高）" % it
        if it >= 100_000:
            return "PBKDF2 %d 次（强度中等）" % it
        return "PBKDF2 %d 次（强度偏低，可能被快速爆破）" % it

    # ============================================================
    # 口令解锁
    # ============================================================
    def unlock(self, passphrase, slot=None):
        """用口令解出 master key。

        slot=None 时按顺序试全部激活槽；指定 slot 则只试该槽。
        成功返回 {"slot", "master_key"(hex), "cipher", "mode", ...}，失败返回 None。
        Argon2 / 未实现的 cipher 会抛 NotImplementedError。
        """
        if self.version == 1:
            return self._unlock_v1(passphrase, slot)
        return self._unlock_v2(passphrase, slot)

    # ---------------- LUKS1 解锁 ----------------
    def _unlock_v1(self, passphrase, slot=None):
        cipher_name, mode = _split_cipher(self.cipher, self.mode)
        key_bytes = _int_like(self.key_bytes)
        if key_bytes <= 0:
            raise ValueError("LUKS1 keyBytes 非法: %r" % (self.key_bytes,))
        if not self.hash_spec:
            raise ValueError("LUKS1 缺少 hashSpec，无法解锁")
        _hash_size(self.hash_spec)                     # 名字不可用则立刻报错
        secret = _as_bytes(passphrase)

        for ks in self._slots_to_try_v1(slot):
            try:
                stripes = _int_like(ks.stripes)
                material_len = _af_size(key_bytes, stripes)
            except ValueError:
                continue                                # 坏槽，跳过
            if _int_like(ks.iterations) <= 0 or len(ks.salt) != 32:
                continue
            base_sector = _int_like(ks.key_material_offset)
            raw = self.sub.read(base_sector * SECTOR_SIZE, material_len)
            if len(raw) < material_len:
                continue                                # 镜像被截断
            derived = _pbkdf2(secret, ks.salt, ks.iterations, key_bytes, self.hash_spec)
            material = _crypt_units(derived, raw, cipher_name, mode, base_sector, True)
            cand = af_merge(material[:key_bytes * stripes], key_bytes, stripes, self.hash_spec)
            if self._verify_digest_v1(cand):
                return self._accept(cand, ks.index, "pbkdf2")
        return None

    def _slots_to_try_v1(self, slot):
        if slot is None:
            return list(self.active_slots)
        idx = int(slot)
        if idx < 0 or idx >= len(self.slots):
            raise ValueError("LUKS1 只有 0..%d 号槽，收到 %d" % (len(self.slots) - 1, idx))
        ks = self.slots[idx]
        return [ks] if ks.active else []

    def _verify_digest_v1(self, candidate):
        if len(self.mk_digest) != 20 or len(self.mk_digest_salt) != 32:
            return False
        if _int_like(self.mk_digest_iter) <= 0:
            return False
        got = _pbkdf2(candidate, self.mk_digest_salt, self.mk_digest_iter, 20,
                      self.hash_spec)
        return hmac.compare_digest(got, self.mk_digest)

    # ---------------- LUKS2 解锁 ----------------
    def _unlock_v2(self, passphrase, slot=None):
        j = self.json
        if not j:
            raise ValueError("LUKS2 JSON 元数据不可用，无法解锁")
        slots = j.get("keyslots") or {}
        if not slots:
            return None
        key_bytes = self._v2_key_bytes()
        if key_bytes <= 0:
            raise ValueError("LUKS2 取不到 master key 长度（segments.key_size）")
        secret = _as_bytes(passphrase)

        for ksid in self._slots_to_try_v2(slots, slot):
            entry = slots[ksid] or {}
            kdf = entry.get("kdf") or {}
            ktype = str(kdf.get("type") or "").strip().lower()
            if ktype.startswith("argon2"):
                raise NotImplementedError(
                    "LUKS2 keyslot %s 的 KDF 是 %s：Argon2 需要 BLAKE2b 压缩函数、"
                    "可调内存的填充与多轮寻址，零第三方依赖下未实现；"
                    "本模块只解 pbkdf2 类型的 keyslot" % (ksid, kdf.get("type")))
            if ktype != "pbkdf2":
                raise NotImplementedError(
                    "LUKS2 keyslot %s 的 KDF %r 未实现" % (ksid, kdf.get("type")))

            area = entry.get("area") or {}
            af = entry.get("af") or {}
            af_type = str(af.get("type") or "luks1").strip().lower()
            if af_type not in ("luks1",):
                raise NotImplementedError(
                    "LUKS2 keyslot %s 的 AF 类型 %r 未实现" % (ksid, af.get("type")))

            stripes = _int_like(af.get("stripes")) or LUKS_STRIPES
            af_hash = str(af.get("hash") or "").strip().lower()
            if not af_hash:
                for d in (j.get("digests") or {}).values():
                    if (d or {}).get("hash"):
                        af_hash = str(d["hash"]).lower()
                        break
            af_hash = af_hash or "sha256"
            area_off = _int_like(area.get("offset"))
            area_size = _int_like(area.get("size"))
            derived_len = _int_like(area.get("key_size")) or _int_like(entry.get("key_size"))
            salt = bytes.fromhex(kdf.get("salt") or "")
            iters = _int_like(kdf.get("iterations"))
            if derived_len <= 0 or not salt or iters <= 0:
                continue

            try:
                af_len = _af_size(key_bytes, stripes)
            except ValueError:
                continue
            if area_size and af_len > area_size:
                continue

            area_cipher, area_mode = _split_cipher(area.get("encryption") or "", "")
            if not area_cipher:
                area_cipher, area_mode = _split_cipher(self.cipher, self.mode)

            raw = self.sub.read(area_off, af_len)
            if len(raw) < af_len:
                continue
            derived = _pbkdf2(secret, salt, iters, derived_len,
                              kdf.get("hash") or "sha256")
            material = _crypt_units(derived, raw, area_cipher, area_mode, 0, True)
            cand = af_merge(material[:key_bytes * stripes], key_bytes, stripes, af_hash)
            if self._verify_digest_v2(cand, ksid, j):
                return self._accept(cand, _int_like(ksid), ktype)
        return None

    def _slots_to_try_v2(self, slots, slot):
        ids = sorted(slots.keys(), key=lambda x: _int_like(x))
        if slot is None:
            return ids
        key = str(int(slot))
        if key not in slots:
            raise ValueError("LUKS2 没有 %s 号 keyslot（现有: %s）"
                             % (key, ", ".join(ids)))
        return [key]

    def _v2_key_bytes(self):
        segs = (self.json or {}).get("segments") or {}
        for seg in segs.values():
            n = _int_like((seg or {}).get("key_size")) // 8
            if n > 0:
                return n
        return _int_like(self.key_bytes)

    def _verify_digest_v2(self, candidate, ksid, j):
        digests = j.get("digests") or {}
        for did in sorted(digests.keys(), key=lambda x: _int_like(x)):
            d = digests[did] or {}
            owners = d.get("keyslots")
            if owners and str(ksid) not in [str(x) for x in owners]:
                continue
            dtype = str(d.get("type") or "pbkdf2").strip().lower()
            if dtype != "pbkdf2":
                raise NotImplementedError(
                    "LUKS2 digest %s 的类型 %r 未实现" % (did, d.get("type")))
            expect = bytes.fromhex(d.get("digest") or "")
            salt = bytes.fromhex(d.get("salt") or "")
            iters = _int_like(d.get("iterations"))
            if not expect or not salt or iters <= 0:
                continue
            got = _pbkdf2(candidate, salt, iters, len(expect), d.get("hash") or "sha256")
            if hmac.compare_digest(got, expect):
                return True
        return False

    def _accept(self, master_key, slot_index, kdf):
        self.master_key = bytes(master_key)
        self.unlocked_slot = int(slot_index)
        self.unlocked_kdf = kdf
        cipher_name, mode = _split_cipher(self.cipher, self.mode)
        return {
            "slot": int(slot_index),
            "master_key": bytes(master_key).hex(),
            "cipher": cipher_name,
            "mode": mode,
            "cipher_spec": ("%s-%s" % (cipher_name, mode)) if mode else cipher_name,
            "key_bytes": len(master_key),
            "kdf": kdf,
            "version": self.version,
        }

    # ============================================================
    # 数据扇区
    # ============================================================
    def _require_master_key(self):
        if not self.master_key:
            raise ValueError("尚未解锁：先调用 unlock(passphrase)")

    def _payload_spec(self):
        return _split_cipher(self.cipher, self.mode)

    def decrypt_sector(self, sector, data):
        """解密从 payload 第 sector 号扇区起的数据（sector 相对 payload 起点，tweak 即扇区号）"""
        self._require_master_key()
        cipher_name, mode = self._payload_spec()
        return _crypt_units(self.master_key, data, cipher_name, mode, int(sector), True)

    def encrypt_sector(self, sector, data):
        """decrypt_sector 的逆（自检与写回用）"""
        self._require_master_key()
        cipher_name, mode = self._payload_spec()
        return _crypt_units(self.master_key, data, cipher_name, mode, int(sector), False)

    def read_decrypted(self, offset, size):
        """从 payload 内 offset（字节，0 = 第一个加密扇区）解出 size 字节"""
        self._require_master_key()
        size = int(size)
        if size <= 0:
            return b""
        offset = int(offset)
        if offset < 0:
            raise ValueError("offset 不能为负: %d" % offset)
        cipher_name, mode = self._payload_spec()
        first = offset // SECTOR_SIZE
        delta = offset % SECTOR_SIZE
        need = delta + size
        sectors = (need + SECTOR_SIZE - 1) // SECTOR_SIZE
        disk_off = _int_like(self.payload_offset) * SECTOR_SIZE + first * SECTOR_SIZE
        raw = self.sub.read(disk_off, sectors * SECTOR_SIZE)
        if not raw:
            return b""
        avail = max(0, len(raw) - delta)
        if avail <= 0:
            return b""
        want = min(size, avail)
        # 必须整扇区解密后再切片：XTS 是逐块（16 B）依赖，截断密文会毁掉末块
        buf = raw
        if len(buf) % SECTOR_SIZE:
            buf += b"\x00" * (SECTOR_SIZE - len(buf) % SECTOR_SIZE)
        plain = _crypt_units(self.master_key, buf, cipher_name, mode, first, True)
        return plain[delta:delta + want]


def detect(sub):
    """快速判断某处是不是 LUKS；是则返回版本号，否则 None"""
    try:
        h = sub.read(0, 8)
    except Exception:
        return None
    if len(h) >= 8 and h[:6] == LUKS_MAGIC:
        v = struct.unpack_from(">H", h, 6)[0]
        return v if v in (1, 2) else None
    return None


def describe(sub):
    """一行摘要，适合批量扫描时打印"""
    v = detect(sub)
    if not v:
        return "非 LUKS"
    try:
        lk = Luks(sub)
        i = lk.info()
        return "LUKS%d  %s-%s  key=%dB  槽 %d/%d  %s" % (
            v, i["cipher"], i["mode"], i["key_bytes"],
            i["slots_active"], i["slots_total"], lk.strength_note())
    except Exception as e:
        return "LUKS%d（解析失败: %s）" % (v, e)


if __name__ == "__main__":
    class MemSub:
        def __init__(self, d):
            self.d = d
        def read(self, o, n):
            return self.d[o:o + n]

    # ---- 构造合成 LUKS1 头 ----
    h = bytearray(LUKS1_HEADER_SIZE)
    h[0:6] = LUKS_MAGIC
    struct.pack_into(">H", h, 6, 1)
    h[8:8 + 9] = b"aes"
    h[40:40 + 16] = b"xts-plain64"
    h[72:72 + 6] = b"sha256"
    struct.pack_into(">I", h, 104, 4096)          # payload offset
    struct.pack_into(">I", h, 108, 32)            # key bytes
    h[112:132] = bytes(range(20))                 # mk digest
    h[132:164] = b"\xAA" * 32                     # mk digest salt
    struct.pack_into(">I", h, 164, 200000)
    h[168:168 + 36] = b"12345678-1234-1234-1234-123456789012"
    # slot0 激活
    struct.pack_into(">I", h, 208, 0x00AC71F3)
    struct.pack_into(">I", h, 212, 500000)
    h[216:248] = b"\xBB" * 32
    struct.pack_into(">I", h, 248, 4096)
    struct.pack_into(">I", h, 252, 4000)

    sub = MemSub(bytes(h) + b"\x00" * 4096)
    assert detect(sub) == 1
    lk = Luks(sub)
    i = lk.info()
    print("LUKS1 解析：")
    for k in ("version", "cipher", "mode", "hash", "key_bytes",
              "payload_offset_sectors", "slots_total", "slots_active",
              "active_slot_ids"):
        print("  %-24s %s" % (k, i[k]))
    print("  强度:", lk.strength_note())
    print("  摘要:", describe(sub))
    assert i["cipher"] == "aes" and i["mode"] == "xts-plain64"
    assert i["slots_active"] == 1
    assert i["active_slot_ids"] == [0]
    print("LUKS1 自检通过")

    # ---- 构造合成 LUKS2 头 ----
    meta = {
        "keyslots": {"0": {"type": "luks2", "key_size": 64,
                           "kdf": {"type": "argon2id", "iterations": 4,
                                   "salt": "aabbccdd" * 8},
                           "area": {"offset": "4096", "size": "258048"}}},
        "segments": {"0": {"type": "crypt", "encryption": "aes-xts-plain64",
                           "key_size": 512, "offset": "16777216"}},
        "digests": {"0": {"type": "pbkdf2", "hash": "sha256", "iterations": 285376,
                          "salt": "11223344" * 8, "digest": "55667788" * 8}},
    }
    js = json.dumps(meta).encode()
    h2 = bytearray(LUKS2_BINARY_HEADER_SIZE)
    h2[0:6] = LUKS_MAGIC
    struct.pack_into(">H", h2, 6, 2)
    struct.pack_into(">Q", h2, 8, 16384)              # header_size
    struct.pack_into(">Q", h2, 16, 1)                 # seqid
    h2[72:72 + 6] = b"sha256"
    h2[168:168 + 36] = b"abcdef01-2345-6789-abcd-ef0123456789"
    blob = bytes(h2) + js + b"\x00" * (16384 - LUKS2_BINARY_HEADER_SIZE - len(js))
    sub2 = MemSub(blob)
    assert detect(sub2) == 2
    lk2 = Luks(sub2)
    i2 = lk2.info()
    print("\nLUKS2 解析：")
    for k in ("version", "cipher", "hash", "key_bytes", "pbkdf", "slots_active"):
        print("  %-24s %s" % (k, i2[k]))
    print("  摘要:", describe(sub2))
    assert i2["cipher"] == "aes-xts-plain64"
    assert i2["pbkdf"] == "argon2id"
    assert i2["key_bytes"] == 64
    print("LUKS2 自检通过")

    # ========================================================
    # 以下为解锁 / 扇区解密自检：自己造镜像，自己算摘要
    # ========================================================
    print("\n=== 3) AES-XTS 已知答案（NIST CAVP 向量）===")
    kat_key = bytes.fromhex("c43cd0b23798ee3db0053d1e4d185e965d67fdda8c5325cc709fc3973f05cd17")
    kat_tw = bytes.fromhex("7900432e6021bc0e627c7b96ca08b4d0")
    kat_ct = bytes.fromhex("3454f7d34c0caffa12e9d2850b037fff")
    kat_pt = bytes.fromhex("07f2c2d4e6db6e1200bc165d154e0698")
    assert xts_decrypt(kat_key, kat_tw, kat_ct) == kat_pt
    assert xts_encrypt(kat_key, kat_tw, kat_pt) == kat_ct
    # tweak 换一个必须变结果（否则 tweak 没真正参与）
    assert xts_encrypt(kat_key, sector_tweak(1), kat_pt) != kat_ct
    print("  XTS 加解密与 NIST 向量一致")

    print("\n=== 4) AF split / merge 往返 ===")
    af_secret = bytes((i * 11 + 5) & 0xFF for i in range(32))
    af_material = af_split(af_secret, 32, 64, "sha256",
                           rng=lambda n: bytes((j * 7 + 1) & 0xFF for j in range(n)))
    assert len(af_material) == 32 * 64
    assert af_merge(af_material, 32, 64, "sha256") == af_secret
    # 去掉一份分片里的一个字节 → 结果必须不同
    broken = bytearray(af_material)
    broken[0] ^= 0x01
    assert af_merge(bytes(broken), 32, 64, "sha256") != af_secret
    print("  AF_split/AF_merge 互逆，篡改后被察觉")

    # ---- 合成 LUKS1 镜像 ----
    ITERS = 1000
    STRIPES = LUKS_STRIPES
    KB = 32
    KMO = 4096                     # 密钥材料起始扇区（= 2 MiB）
    PAYLOAD = 4400                 # payload 起始扇区（必须落在密钥材料之后）
    MK = bytes(range(32))          # 已知 master key
    PASS = "correct horse battery staple"
    KM_SALT = bytes.fromhex("11" * 32)
    MK_SALT = bytes.fromhex("22" * 32)

    def _det_rng(tag):
        """确定性"随机"源：合成镜像可复现，且同一次 split 里各分片互不相同"""
        state = {"calls": 0}

        def rng(n):
            out = b""
            while len(out) < n:
                out += hashlib.sha256(
                    tag + struct.pack(">I", state["calls"]) + struct.pack(">I", len(out))
                ).digest()
            state["calls"] += 1
            return out[:n]
        return rng

    derived1 = _pbkdf2(PASS, KM_SALT, ITERS, KB, "sha256")
    material1 = af_split(MK, KB, STRIPES, "sha256", rng=_det_rng(b"esk-luks1"))
    assert len(material1) == KB * STRIPES
    mat1 = material1 + b"\x00" * ((-len(material1)) % SECTOR_SIZE)
    enc_mat1 = _crypt_units(derived1, mat1, "aes", "xts-plain64", KMO, False)
    mk_digest1 = _pbkdf2(MK, MK_SALT, ITERS, 20, "sha256")

    hdr1 = bytearray(LUKS1_HEADER_SIZE)
    hdr1[0:6] = LUKS_MAGIC
    struct.pack_into(">H", hdr1, 6, 1)
    hdr1[8:8 + 3] = b"aes"
    hdr1[40:40 + 11] = b"xts-plain64"
    hdr1[72:72 + 6] = b"sha256"
    struct.pack_into(">I", hdr1, 104, PAYLOAD)
    struct.pack_into(">I", hdr1, 108, KB)
    hdr1[112:132] = mk_digest1
    hdr1[132:164] = MK_SALT
    struct.pack_into(">I", hdr1, 164, ITERS)
    hdr1[168:168 + 36] = b"deadbeef-0000-1111-2222-333344445555"
    struct.pack_into(">I", hdr1, 208, LUKS_KEY_ENABLED)
    struct.pack_into(">I", hdr1, 212, ITERS)
    hdr1[216:248] = KM_SALT
    struct.pack_into(">I", hdr1, 248, KMO)
    struct.pack_into(">I", hdr1, 252, STRIPES)

    img1 = bytearray(PAYLOAD * SECTOR_SIZE + 8 * SECTOR_SIZE)
    img1[0:LUKS1_HEADER_SIZE] = hdr1
    off = KMO * SECTOR_SIZE
    img1[off:off + len(enc_mat1)] = enc_mat1

    # payload 里放两个"已加密"的扇区，明文已知
    plain3 = bytes((i * 3 + 9) & 0xFF for i in range(SECTOR_SIZE))
    plain4 = bytes((i * 5 + 2) & 0xFF for i in range(SECTOR_SIZE))
    ct3 = xts_encrypt(MK, sector_tweak(3), plain3)
    ct4 = xts_encrypt(MK, sector_tweak(4), plain4)
    img1[(PAYLOAD + 3) * SECTOR_SIZE:(PAYLOAD + 4) * SECTOR_SIZE] = ct3
    img1[(PAYLOAD + 4) * SECTOR_SIZE:(PAYLOAD + 5) * SECTOR_SIZE] = ct4
    image1 = bytes(img1)

    print("\n=== 5) LUKS1 口令解锁 ===")
    lk1 = Luks(MemSub(image1))
    assert lk1.info()["slots_active"] == 1
    assert lk1.master_key is None and lk1.info()["unlocked"] is False
    got = lk1.unlock(PASS)
    assert got is not None
    assert got["slot"] == 0 and got["key_bytes"] == KB
    assert got["master_key"] == MK.hex(), "解出的 master key 与写入的不一致"
    assert got["cipher"] == "aes" and got["mode"] == "xts-plain64"
    assert lk1.info()["unlocked"] is True
    print("  正确口令 → slot=%d master_key=%s…" % (got["slot"], got["master_key"][:16]))
    got2 = Luks(MemSub(image1)).unlock(PASS, slot=0)
    assert got2 is not None and got2["master_key"] == MK.hex()
    print("  指定 slot=0 同样解出")

    print("\n=== 6) 错口令 / 坏摘要 ===")
    assert Luks(MemSub(image1)).unlock("wrong passphrase") is None
    assert Luks(MemSub(image1)).unlock("") is None
    assert Luks(MemSub(image1)).unlock(PASS.encode("utf-8")) is not None
    bad = bytearray(image1)
    bad[112] ^= 0x01                      # mk_digest 第一个字节
    lk_bad = Luks(MemSub(bytes(bad)))
    assert lk_bad.mk_digest != mk_digest1
    assert lk_bad.unlock(PASS) is None, "摘要被改过还解开了？"
    assert Luks(MemSub(image1)).unlock(PASS, slot=5) is None     # 未激活槽
    try:
        Luks(MemSub(image1)).unlock(PASS, slot=9)
    except ValueError:
        pass
    else:
        raise AssertionError("slot 越界应抛 ValueError")
    try:
        Luks(MemSub(bytes(image1))).decrypt_sector(0, b"\x00" * 512)
    except ValueError:
        pass
    else:
        raise AssertionError("未解锁就解密应抛 ValueError")
    print("  错口令→None，篡改 mk_digest→None 且不崩，越界 slot 报错")

    print("\n=== 7) 数据扇区解密（AES-XTS，tweak=扇区号）===")
    lk1b = Luks(MemSub(image1))
    lk1b.unlock(PASS)
    assert lk1b.decrypt_sector(3, ct3) == plain3
    assert lk1b.decrypt_sector(4, ct4) == plain4
    assert lk1b.encrypt_sector(3, plain3) == ct3
    assert lk1b.decrypt_sector(9, ct3) != plain3, "换扇区号必须解出不同内容"
    assert lk1b.read_decrypted(3 * SECTOR_SIZE, SECTOR_SIZE) == plain3
    assert lk1b.read_decrypted(4 * SECTOR_SIZE, SECTOR_SIZE) == plain4
    straddle = lk1b.read_decrypted(3 * SECTOR_SIZE + 100, 200)
    assert straddle == (plain3 + plain4)[100:300], "跨扇区读取不符"
    assert lk1b.read_decrypted(3 * SECTOR_SIZE + 500, 24) == \
        (plain3 + plain4)[500:524], "真跨扇区（500..524）读取不符"
    assert lk1b.read_decrypted(3 * SECTOR_SIZE, SECTOR_SIZE + 10) == \
        (plain3 + plain4)[:SECTOR_SIZE + 10]
    assert lk1b.read_decrypted(0, 0) == b""
    print("  单扇区、跨扇区、超界截断均正确")

    # ---- 合成 LUKS2 镜像（pbkdf2 keyslot）----
    print("\n=== 8) LUKS2 pbkdf2 keyslot 解锁 ===")
    MK2 = bytes((i * 2 + 1) & 0xFF for i in range(64))
    PASS2 = "luks2-pass"
    KM_SALT2 = bytes.fromhex("33" * 32)
    MK_SALT2 = bytes.fromhex("44" * 32)
    AREA_OFF = 32768
    PAYLOAD2 = 1048576
    derived2 = _pbkdf2(PASS2, KM_SALT2, ITERS, 64, "sha256")
    material2 = af_split(MK2, 64, STRIPES, "sha256", rng=_det_rng(b"esk-luks2"))
    mat2 = material2 + b"\x00" * ((-len(material2)) % SECTOR_SIZE)
    enc_mat2 = _crypt_units(derived2, mat2, "aes", "xts-plain64", 0, False)
    dig2 = _pbkdf2(MK2, MK_SALT2, ITERS, 64, "sha256")
    area_size = (len(mat2) + 4095) // 4096 * 4096

    def build_v2(kdf_type):
        meta2 = {
            "keyslots": {"0": {
                "type": "luks2", "key_size": 64,
                "af": {"type": "luks1", "hash": "sha256", "stripes": STRIPES},
                "area": {"type": "raw", "offset": str(AREA_OFF),
                         "size": str(area_size), "encryption": "aes-xts-plain64",
                         "key_size": 64},
                "kdf": {"type": kdf_type, "hash": "sha256",
                        "iterations": str(ITERS), "salt": KM_SALT2.hex()},
            }},
            "segments": {"0": {"type": "crypt", "offset": str(PAYLOAD2),
                               "size": "1048576", "encryption": "aes-xts-plain64",
                               "key_size": 512}},
            "digests": {"0": {"type": "pbkdf2", "keyslots": ["0"], "segments": ["0"],
                              "hash": "sha256", "iterations": ITERS,
                              "salt": MK_SALT2.hex(), "digest": dig2.hex()}},
            "tokens": {},
        }
        js2 = json.dumps(meta2).encode()
        hdr2 = bytearray(LUKS2_BINARY_HEADER_SIZE)
        hdr2[0:6] = LUKS_MAGIC
        struct.pack_into(">H", hdr2, 6, 2)
        struct.pack_into(">Q", hdr2, 8, 16384)
        struct.pack_into(">Q", hdr2, 16, 1)
        hdr2[72:72 + 6] = b"sha256"
        hdr2[168:168 + 36] = b"cafebabe-1111-2222-3333-444455556666"
        buf = bytearray(PAYLOAD2 + 8 * SECTOR_SIZE)
        buf[0:LUKS2_BINARY_HEADER_SIZE] = hdr2
        buf[LUKS2_BINARY_HEADER_SIZE:LUKS2_BINARY_HEADER_SIZE + len(js2)] = js2
        buf[AREA_OFF:AREA_OFF + len(enc_mat2)] = enc_mat2
        return bytes(buf)

    v2img = build_v2("pbkdf2")
    lk3 = Luks(MemSub(v2img))
    assert lk3.version == 2 and lk3.info()["key_bytes"] == 64
    got3 = lk3.unlock(PASS2)
    assert got3 is not None, "LUKS2 pbkdf2 槽解不开"
    assert got3["master_key"] == MK2.hex()
    assert got3["slot"] == 0 and got3["version"] == 2
    assert got3["cipher"] == "aes" and got3["mode"] == "xts-plain64"
    plain2 = bytes((i * 13 + 4) & 0xFF for i in range(SECTOR_SIZE))
    ct2 = xts_encrypt(MK2, sector_tweak(0), plain2)
    assert lk3.decrypt_sector(0, ct2) == plain2
    assert Luks(MemSub(v2img)).unlock("nope") is None
    print("  pbkdf2 keyslot → slot=0，master key 与数据扇区均正确")

    print("\n=== 9) Argon2 路径 ===")
    lk4 = Luks(MemSub(build_v2("argon2id")))
    try:
        lk4.unlock(PASS2)
    except NotImplementedError as exc:
        assert "argon2" in str(exc).lower() or "Argon2" in str(exc)
        print("  argon2id → NotImplementedError:", str(exc)[:60], "…")
    else:
        raise AssertionError("Argon2 keyslot 应抛 NotImplementedError")

    print("\n=== 10) 不支持的 cipher / mode ===")
    sub_serpent = bytearray(image1)
    sub_serpent[8:11] = b"ser"                  # 长度不变，把 cipher 改成 serpent
    try:
        Luks(MemSub(bytes(sub_serpent))).unlock(PASS)
    except NotImplementedError as exc:
        print("  cipher=serpent → NotImplementedError:", str(exc)[:50], "…")
    else:
        raise AssertionError("非 AES 应抛 NotImplementedError")
    try:
        _crypt_units(bytes(32), b"\x00" * 512, "aes", "lrw-benbi", 0, True)
    except NotImplementedError:
        pass
    else:
        raise AssertionError("lrw-benbi 应抛 NotImplementedError")

    print("\n全部自检通过：8 项原有头解析断言 + 解锁/扇区/AF/XTS/LUKS2/异常路径")
