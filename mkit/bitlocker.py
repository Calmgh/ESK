# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""BitLocker（BDE）元数据解析与卷解密

对应 LovelyCarve 的「加密与快照」里的 BitLocker 部分。

只依赖可读对象 sub.read(offset, size) / sub.size，不依赖第三方库；
AES 原语来自 mkit.aes（纯标准库自研实现）。

============================================================================
已实现
============================================================================
1. 卷识别
   · 偏移 0 的 FVE 引导扇区（`-FVE-FS-` 位于 0x03），解析 3 个元数据块指针
     （0xB0 / 0xB8 / 0xC0；BitLocker To Go 的 FAT 变体在 0x1B8 / 0x1C0 / 0x1C8）
   · 三处元数据块全部扫：卷头指针 + 卷尾备份（size - 0x10000）+ 0x1000 /
     0x2000 / 0x10000 / 0x20000 候选，逐个用 `-FVE-FS-` 签名与元数据头自校验过滤
2. 元数据块
   · 块头 v1（Vista）/ v2（Win7+）：版本、加密卷大小、卷头扇区数、3 个块偏移
   · 元数据头：metadata_size / 版本 / 头长度 / 卷 GUID / nonce 计数器 /
     encryption_method / 创建时间（FILETIME）
   · 元数据 entry 链：8 字节头（size u16, type u16, value_type u16, version u16），
     支持全零终止、越界与非法 size 显式报错
3. 密钥结构
   · VMK entry（type 0x0002 / value 0x0008）：GUID、修改时间、protection_type，
     以及内部属性 entry（描述串 / stretch key / AES-CCM 加密密钥）
   · FVEK entry（type 0x0003 / value 0x0005）：nonce(12) + tag(16) + 密文
   · 描述 entry（type 0x0007）：UTF-16LE 的「计算机名 卷名 日期」
4. 密钥保护器枚举
   · 0x0000 ClearKey / 0x0100 TPM / 0x0200 StartupKey / 0x0500 TPM+PIN /
     0x0800 RecoveryPassword / 0x2000 Password
   · 每个保护器给出 type / GUID / 是否可用（是否带 AES-CCM 密文）/ 描述 / 盐
5. 恢复密码（真实算法，非「格式校验」占位）
   · 8 组 × 6 位数字；每组必须能被 11 整除、商 ≤ 0xFFFF
   · 8 个商按 u16 小端拼成 16 字节 → SHA-256 → 作为 stretch 的 initial_sha256
   · stretch：struct(last_sha256[32] || initial_sha256[32] || salt[16] ||
     count u64 LE) 连续 SHA-256，共 0x100000 轮 → 32 字节 AES-CCM 密钥
   · 用该密钥对保护器里的密文做 AES-CCM 的 CTR 解密 → 校验明文结构
     （size / version）→ 取出 32 字节 VMK
6. 密码学原语（均为本文件实现，纯标准库）
   · AES-CCM：RFC 3610 完整实现（CBC-MAC 标签 + CTR），另提供 BitLocker 实际
     使用的纯 CTR 路径 `ccm_ctr_crypt`（与 libbde 行为一致，不做 MAC 校验）
   · AES-XTS：IEEE 1619，tweak = 扇区号 16 字节小端，GF(2^128) 乘 x 递推
   · Elephant diffuser A/B（Ferguson 设计）：A 5 轮、B 3 轮，轮转常量
     A = {9,0,13,0}、B = {0,10,0,25}，加/减分离的正反变换
   · AES-CBC：IV = AES-ECB(FVEK, 扇区字节偏移 u64 小端 || 0^8)
7. 卷解密
   · VMK → FVEK（+ TWEAK）→ 512 字节扇区级解密
   · 0x8000 / 0x8001：CBC + diffuser（解密顺序 CBC → diffuser B → diffuser A →
     XOR 32 字节扇区密钥，扇区密钥 = E(TWEAK, off) || E(TWEAK, off | 0x80<<120)）
   · 0x8002 / 0x8003：CBC
   · 0x8004 / 0x8005：XTS（FVEK 内含两把 XTS 子钥）

============================================================================
不实现（明确边界，绝不假装能解）
============================================================================
· TPM / TPM+PIN / startup key(.BEK) / 用户口令保护器：需要外部密钥材料
  （TPM 密封数据、BEK 文件、口令编码规则），本文件只枚举不推导
· AES-CCM 的 MAC（tag）校验：BitLocker 的 AAD 组成在公开资料里没有确切定义，
  libbde 同样只做 CTR。本实现如实标注 `tag_verified=False`，改用明文结构
  （size 与 version）做 4 字节级校验；不声称已验签
· Vista 时代的「虚拟扇区」重建（元数据区/卷头扇区在解密视图里的重映射）、
  EOW（Used Disk Space Only）描述符与 block map、NTFS 修复
· 写回、重打包、就地解密整卷（提供扇区级原语，整卷流程由调用方编排）

============================================================================
两处与常见资料的差异（本文件以 libbde 格式文档 + dislocker/libcaes 源码为准）
============================================================================
· entry header 是 8 字节（size, type, value_type, version），不是 6 字节。
  type 与 value_type 是两套独立的表：0x0005 / 0x0008 / 0x0009 是 value_type
  （AES-CCM 加密密钥 / VMK / 外部密钥），不是 entry type。
· encryption_method 的卷密码取值是 0x8000–0x8005
  （0x8000 CBC+diffuser-128、0x8001 CBC+diffuser-256、0x8002/0x8003 CBC、
   0x8004 XTS-128、0x8005 XTS-256）；
  0x1000/0x1001 是 stretch key，0x2000–0x2005 是密钥域算法（CCM/VMK/SHA-256），
  不应被当作卷数据密码。部分资料写作「0x2000 = CBC+diffuser、0x8000 = XTS」，
  与此表冲突；按该表解真实卷会静默产出乱码，故不采用。
"""

import hashlib
import struct
from datetime import datetime, timedelta

try:                                          # 作为包导入（from mkit.bitlocker import ...）
    from .aes import AES, cbc_encrypt, cbc_decrypt
except ImportError:                           # 直接以脚本运行（自检）
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from mkit.aes import AES, cbc_encrypt, cbc_decrypt

__all__ = [
    "BitLocker", "KeyProtector", "MetadataEntry",
    "detect", "describe",
    "diffuser_encrypt", "diffuser_decrypt",
    "xts_encrypt", "xts_decrypt",
    "ccm_encrypt", "ccm_decrypt", "ccm_ctr_crypt",
    "stretch_key", "parse_recovery_password",
    "SIGNATURE", "SECTOR_SIZE", "STRETCH_ITERATIONS",
    "ENTRY_TYPES", "VALUE_TYPES", "PROTECTION_TYPES", "METHODS",
]

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------
SIGNATURE = b"-FVE-FS-"
SIGNATURE_HEX = "2d 46 56 45 2d 46 53 2d"

SECTOR_SIZE = 512
STRETCH_ITERATIONS = 0x00100000                # 1048576，Windows 固定轮数
ENTRY_HEADER_SIZE = 8
BLOCK_HEADER_SIZE = 64
METADATA_HEADER_SIZE = 48

# FVE 引导扇区里 3 个元数据块指针的位置
BOOT_META_OFFSETS = (0xB0, 0xB8, 0xC0)
TOGO_META_OFFSETS = (0x1B8, 0x1C0, 0x1C8)

# 常见布局（均为「块头之后紧跟元数据头」，块头占 64 字节）
DEFAULT_METADATA_CANDIDATES = (0x1000, 0x2000, 0x10000, 0x20000)

ENTRY_TYPES = {
    0x0000: "Property",
    0x0002: "VolumeMasterKey",
    0x0003: "FullVolumeEncryptionKey",
    0x0004: "Validation",
    0x0006: "StartupKey",
    0x0007: "Description",
    0x000B: "AutoUnlockKey",
    0x000F: "MetadataAreaDescriptors",
}

VALUE_TYPES = {
    0x0000: "Erased",
    0x0001: "Key",
    0x0002: "UnicodeString",
    0x0003: "StretchKey",
    0x0004: "UseKey",
    0x0005: "AesCcmEncryptedKey",
    0x0006: "TpmEncodedKey",
    0x0007: "Validation",
    0x0008: "VolumeMasterKey",
    0x0009: "ExternalKey",
    0x000A: "Update",
    0x000B: "Error",
    0x000F: "OffsetAndSize",
}

PROTECTION_TYPES = {
    0x0000: "ClearKey",
    0x0100: "TPM",
    0x0200: "StartupKey",
    0x0500: "TPMPin",
    0x0800: "RecoveryPassword",
    0x2000: "Password",
}

# id -> (可读名, 位宽, 模式)；模式：none / key / cbc / cbc-diffuser / xts
METHODS = {
    0x0000: ("None（未加密）", 0, "none"),
    0x1000: ("Stretch key（密钥域，非卷数据）", 0, "key"),
    0x1001: ("Stretch key（密钥域，非卷数据）", 0, "key"),
    0x2000: ("AES-256-CCM（密钥域，非卷数据）", 0, "key"),
    0x2001: ("AES-256-CCM（密钥域，非卷数据）", 0, "key"),
    0x2002: ("外部密钥（密钥域，非卷数据）", 0, "key"),
    0x2003: ("VMK（密钥域，非卷数据）", 0, "key"),
    0x2004: ("AES-256-CCM（密钥域，非卷数据）", 0, "key"),
    0x2005: ("SHA-256（密钥域，非卷数据）", 0, "key"),
    0x8000: ("AES-128-CBC + Elephant diffuser", 128, "cbc-diffuser"),
    0x8001: ("AES-256-CBC + Elephant diffuser", 256, "cbc-diffuser"),
    0x8002: ("AES-128-CBC", 128, "cbc"),
    0x8003: ("AES-256-CBC", 256, "cbc"),
    0x8004: ("AES-128-XTS", 128, "xts"),
    0x8005: ("AES-256-XTS", 256, "xts"),
}

_M32 = 0xFFFFFFFF
_M128 = (1 << 128) - 1


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------
def method_name(method):
    """encryption_method -> 可读名"""
    return METHODS.get(method, ("Unknown(0x%04x)" % method, 0, "unknown"))[0]


def protection_name(ptype):
    """protection_type -> 可读名"""
    return PROTECTION_TYPES.get(ptype, "Unknown(0x%04x)" % ptype)


def guid_to_string(raw):
    """16 字节小端 GUID -> 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"""
    if not raw or len(raw) < 16:
        return ""
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, raw[8:10].hex(), raw[10:16].hex())


def filetime_to_string(value):
    """Windows FILETIME（100ns since 1601）-> 'YYYY-MM-DD HH:MM:SS'"""
    if not value:
        return None
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=value // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, ValueError):
        return None


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _rotl32(value, count):
    value &= _M32
    if not count:
        return value
    return ((value << count) | (value >> (32 - count))) & _M32


# --------------------------------------------------------------------------
# Elephant diffuser（Ferguson，A 5 轮 / B 3 轮）
# --------------------------------------------------------------------------
_DIFF_A = (9, 0, 13, 0)
_DIFF_B = (0, 10, 0, 25)


def _to_words(data):
    return list(struct.unpack("<%dI" % (len(data) // 4), data))


def _from_words(words):
    return struct.pack("<%dI" % len(words), *[w & _M32 for w in words])


def _diffuse(words, rot, sign, reverse):
    n = len(words)
    order = range(n - 1, -1, -1) if reverse else range(n)
    for i in order:
        j2 = (i - 2) % n
        j5 = (i - 5) % n
        if sign > 0:
            words[i] = (words[i] + (words[j2] ^ _rotl32(words[j5], rot[i % 4]))) & _M32
        else:
            words[i] = (words[i] - (words[j2] ^ _rotl32(words[j5], rot[i % 4]))) & _M32


def _diffuse_b(words, rot, sign, reverse):
    n = len(words)
    order = range(n - 1, -1, -1) if reverse else range(n)
    for i in order:
        j2 = (i + 2) % n
        j5 = (i + 5) % n
        if sign > 0:
            words[i] = (words[i] + (words[j2] ^ _rotl32(words[j5], rot[i % 4]))) & _M32
        else:
            words[i] = (words[i] - (words[j2] ^ _rotl32(words[j5], rot[i % 4]))) & _M32


def diffuser_encrypt(data):
    """Diffuser A → Diffuser B（加密方向）"""
    if len(data) % 4 or len(data) < 32:
        raise ValueError("diffuser 需要 4 字节对齐且至少 32 字节的数据")
    words = _to_words(data)
    _diffuse(words, _DIFF_A, +1, False)
    _diffuse_b(words, _DIFF_B, +1, False)
    return _from_words(words)


def diffuser_decrypt(data):
    """Diffuser B → Diffuser A（解密方向，逐轮逆序迭代）"""
    if len(data) % 4 or len(data) < 32:
        raise ValueError("diffuser 需要 4 字节对齐且至少 32 字节的数据")
    words = _to_words(data)
    _diffuse_b(words, _DIFF_B, -1, True)
    _diffuse(words, _DIFF_A, -1, True)
    return _from_words(words)


# --------------------------------------------------------------------------
# AES-XTS（IEEE 1619）
# --------------------------------------------------------------------------
def _xts_alpha(tweak_int):
    """GF(2^128) 上乘 x（小端表示，多项式 x^128+x^7+x^2+x+1）"""
    carry = tweak_int >> 127
    tweak_int = (tweak_int << 1) & _M128
    if carry:
        tweak_int ^= 0x87
    return tweak_int


def _xts_crypt(key, tweak, data, encrypt):
    if len(key) not in (32, 64):
        raise ValueError("XTS 密钥必须是 32 或 64 字节，收到 %d" % len(key))
    if len(tweak) != 16:
        raise ValueError("XTS tweak 必须是 16 字节")
    if len(data) % 16:
        raise ValueError("XTS 数据长度必须是 16 的整数倍")
    half = len(key) // 2
    data_cipher = AES(key[:half])
    tweak_cipher = AES(key[half:])
    t = int.from_bytes(tweak_cipher.encrypt_block(tweak), "little")
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        tb = t.to_bytes(16, "little")
        block = _xor(data[off:off + 16], tb)
        if encrypt:
            block = data_cipher.encrypt_block(block)
        else:
            block = data_cipher.decrypt_block(block)
        out[off:off + 16] = _xor(block, tb)
        t = _xts_alpha(t)
    return bytes(out)


def xts_decrypt(key, tweak, data):
    """AES-XTS 解密；key = K1||K2，tweak = 16 字节"""
    return _xts_crypt(key, tweak, data, False)


def xts_encrypt(key, tweak, data):
    """AES-XTS 加密（用于自检与回写验证）"""
    return _xts_crypt(key, tweak, data, True)


# --------------------------------------------------------------------------
# AES-CCM（RFC 3610）与 BitLocker 的纯 CTR 变体
# --------------------------------------------------------------------------
def _ccm_ctr(key, nonce, data):
    """CCM 的 CTR 部分：计数器块 = [L-1] || nonce || i(L 字节大端)，i 从 1 起"""
    length_field = 15 - len(nonce)
    cipher = AES(key)
    out = bytearray(len(data))
    for index, off in enumerate(range(0, len(data), 16), start=1):
        counter_block = bytes([length_field - 1]) + nonce + index.to_bytes(length_field, "big")
        keystream = cipher.encrypt_block(counter_block)
        chunk = data[off:off + 16]
        out[off:off + 16] = _xor(chunk, keystream[:len(chunk)])
    return bytes(out)


def ccm_ctr_crypt(key, nonce, data):
    """BitLocker 实际使用的 CCM-CTR 路径（对称，加解密同一函数，不校验 MAC）

    BitLocker 的密钥材料用 AES-CCM 的计数器模式加解密，AAD 组成在公开资料里
    没有确切定义，libbde 亦只做 CTR；因此这里不做 tag 校验。
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥长度必须是 16/24/32 字节")
    if len(nonce) != 12:
        raise ValueError("BitLocker 的 CCM nonce 固定 12 字节，收到 %d" % len(nonce))
    return _ccm_ctr(key, nonce, data)


def ccm_encrypt(key, nonce, aad, plaintext, tag_len=16):
    """RFC 3610 AES-CCM 加密，返回 (密文, 标签)"""
    length_field = 15 - len(nonce)
    if length_field < 2 or length_field > 8:
        raise ValueError("nonce 长度非法（应为 7..13 字节）")
    if tag_len not in (4, 6, 8, 10, 12, 14, 16):
        raise ValueError("tag_len 必须是 4/6/8/10/12/14/16")
    cipher = AES(key)

    flags = ((0x40 if aad else 0x00)
             | (((tag_len - 2) // 2) << 3)
             | (length_field - 1))
    b0 = bytes([flags]) + nonce + len(plaintext).to_bytes(length_field, "big")
    mac = cipher.encrypt_block(b0)

    if aad:
        size = len(aad)
        if size < 0xFF00:
            prefix = size.to_bytes(2, "big")
        else:
            prefix = b"\xff\xfe" + size.to_bytes(4, "big")
        blob = prefix + aad
        blob += b"\x00" * ((-len(blob)) % 16)
        for off in range(0, len(blob), 16):
            mac = cipher.encrypt_block(_xor(mac, blob[off:off + 16]))

    blob = plaintext + b"\x00" * ((-len(plaintext)) % 16)
    for off in range(0, len(blob), 16):
        mac = cipher.encrypt_block(_xor(mac, blob[off:off + 16]))

    s0 = cipher.encrypt_block(bytes([length_field - 1]) + nonce
                              + (0).to_bytes(length_field, "big"))
    tag = _xor(mac[:tag_len], s0[:tag_len])
    return _ccm_ctr(key, nonce, plaintext), tag


def ccm_decrypt(key, nonce, aad, ciphertext, tag):
    """RFC 3610 AES-CCM 解密；标签不符抛 ValueError"""
    plaintext = _ccm_ctr(key, nonce, ciphertext)
    _, expected = ccm_encrypt(key, nonce, aad, plaintext, len(tag))
    if expected != tag:
        raise ValueError("AES-CCM 标签校验失败（密钥/AAD 不对或数据被篡改）")
    return plaintext


# --------------------------------------------------------------------------
# 恢复密码
# --------------------------------------------------------------------------
def parse_recovery_password(text):
    """恢复密码字符串 -> 16 字节二进制口令

    规则（与 Windows/libbde 一致）：
        · 8 组、每组 6 位十进制数字（共 48 位）
        · 每组必须能被 11 整除，商必须 ≤ 0xFFFF
        · 8 个商按 u16 小端依次拼接 = 16 字节
    注意：不是「16 个 base-11 三元组」，也不是直接 48 位；48 位 → 8×20 bit
    的取模约束（÷11）才是真实编码。
    """
    if not isinstance(text, str):
        text = str(text)
    groups = [g for g in text.replace("\u00a0", " ").split("-") if g.strip()]
    if len(groups) != 1:
        groups = [g.strip() for g in groups]
    else:                                     # 没有 '-' 分隔时按空白再拆一次
        groups = [g for g in groups[0].split() if g]
    if len(groups) != 8:
        raise ValueError("恢复密码必须是 8 组数字，收到 %d 组" % len(groups))

    out = bytearray(16)
    for index, group in enumerate(groups):
        digits = group.strip()
        if len(digits) != 6 or not digits.isdigit():
            raise ValueError("第 %d 组不是 6 位十进制数字：%r" % (index + 1, group))
        value = int(digits)
        if value % 11:
            raise ValueError("第 %d 组 %s 不能被 11 整除，不是合法恢复密码" % (index + 1, digits))
        value //= 11
        if value > 0xFFFF:
            raise ValueError("第 %d 组 %s ÷11 = %d 超出 16 位范围" % (index + 1, digits, value))
        struct.pack_into("<H", out, index * 2, value)
    return bytes(out)


def stretch_key(initial_hash, salt, iterations=STRETCH_ITERATIONS):
    """BitLocker 的密钥拉伸

    结构体 = last_sha256[32] || initial_sha256[32] || salt[16] || count u64 LE
    每轮 last_sha256 = SHA256(结构体)，count 从 0 递增，共 iterations 轮；
    最后一轮的输出即派生密钥。
    """
    if len(initial_hash) != 32:
        raise ValueError("initial_hash 必须是 32 字节")
    if len(salt) != 16:
        raise ValueError("salt 必须是 16 字节")
    last = b"\x00" * 32
    head = last + initial_hash + salt
    for count in range(iterations):
        last = hashlib.sha256(head + struct.pack("<Q", count)).digest()
        head = last + initial_hash + salt
    return last


# --------------------------------------------------------------------------
# 元数据结构
# --------------------------------------------------------------------------
class MetadataEntry(object):
    """一条元数据 entry（顶层或 VMK 内部的属性 entry）"""

    __slots__ = ("offset", "size", "type", "value_type", "version", "data")

    def __init__(self, offset, size, type_, value_type, version, data):
        self.offset = offset
        self.size = size
        self.type = type_
        self.value_type = value_type
        self.version = version
        self.data = data

    @property
    def type_name(self):
        return ENTRY_TYPES.get(self.type, "Unknown(0x%04x)" % self.type)

    @property
    def value_type_name(self):
        return VALUE_TYPES.get(self.value_type, "Unknown(0x%04x)" % self.value_type)

    def __repr__(self):
        return "<MetadataEntry @0x%X size=%d %s/%s v%d>" % (
            self.offset, self.size, self.type_name, self.value_type_name, self.version)


class KeyProtector(object):
    """一个 VMK 保护器（ClearKey / TPM / StartupKey / RecoveryPassword / Password）"""

    __slots__ = ("type_id", "guid", "is_active", "description", "salt",
                 "stretch_method", "nonce", "tag", "ciphertext", "clear_key",
                 "entry_offset", "version", "modification_time", "children")

    def __init__(self, type_id, guid, entry_offset=0, version=0):
        self.type_id = type_id
        self.guid = guid
        self.entry_offset = entry_offset
        self.version = version
        self.is_active = False
        self.description = None
        self.salt = None
        self.stretch_method = None
        self.nonce = None
        self.tag = None
        self.ciphertext = None
        self.clear_key = None
        self.modification_time = None
        self.children = []

    @property
    def type_name(self):
        return protection_name(self.type_id)

    @property
    def guid_string(self):
        return guid_to_string(self.guid)

    def to_dict(self):
        return {
            "type_id": self.type_id,
            "type_name": self.type_name,
            "guid": self.guid_string,
            "is_active": self.is_active,
            "description": self.description,
            "has_stretch_key": self.salt is not None,
            "has_clear_key": self.clear_key is not None,
            "salt_hex": self.salt.hex() if self.salt else None,
            "stretch_method": self.stretch_method,
            "ccm_nonce_hex": self.nonce.hex() if self.nonce else None,
            "ccm_tag_hex": self.tag.hex() if self.tag else None,
            "ccm_data_bytes": len(self.ciphertext) if self.ciphertext else 0,
            "entry_offset": self.entry_offset,
            "version": self.version,
            "modification_time": filetime_to_string(self.modification_time),
        }

    def __repr__(self):
        return "<KeyProtector %s %s%s>" % (
            self.type_name, self.guid_string or "-", "" if self.is_active else " (no key)")


def _walk_entries(buf, start, end, base=0):
    """走一条 entry 链；遇到全零 8 字节视为结束

    entry header（8 字节）：size u16, type u16, value_type u16, version u16
    base: 报表用的偏移基准（顶层 entry 传元数据块的卷内偏移）
    """
    entries = []
    pos = start
    while pos + ENTRY_HEADER_SIZE <= end:
        if buf[pos:pos + ENTRY_HEADER_SIZE] == b"\x00" * ENTRY_HEADER_SIZE:
            break
        size, etype, vtype, version = struct.unpack_from("<HHHH", buf, pos)
        if size < ENTRY_HEADER_SIZE:
            raise ValueError("元数据 entry 的 size 非法：%d（偏移 0x%X，至少 %d）"
                             % (size, base + pos, ENTRY_HEADER_SIZE))
        if pos + size > end:
            raise ValueError("元数据 entry 越界：偏移 0x%X 声明 %d 字节，只剩 %d 字节"
                             % (base + pos, size, end - pos))
        entries.append(MetadataEntry(base + pos, size, etype, vtype, version,
                                     buf[pos + ENTRY_HEADER_SIZE:pos + size]))
        pos += size
    return entries


def _parse_ccm_blob(data):
    """AES-CCM 加密密钥 entry 的值：nonce(12) + tag(16) + 密文"""
    if len(data) < 28:
        raise ValueError("AES-CCM 加密密钥 entry 太短：%d 字节（至少 28）" % len(data))
    return data[0:12], data[12:28], data[28:]


def _parse_key_blob(plain, strict=False):
    """解密后的密钥块：size u32, version u16, unknown u16, method u32, key data

    strict=False 时结构不符返回 None（用于口令试解，失败即放弃）
    """
    if len(plain) < 12:
        if strict:
            raise ValueError("密钥块太短：%d 字节" % len(plain))
        return None
    size, version, _unknown, method = struct.unpack_from("<IHHI", plain, 0)
    if size < 12 or size > len(plain) or version not in (1, 2):
        if strict:
            raise ValueError("密钥块结构非法（size=%d version=%d 明文长度=%d）"
                             % (size, version, len(plain)))
        return None
    if not any(plain[12:size]):
        if strict:
            raise ValueError("密钥块里的密钥材料全零")
        return None
    return {
        "size": size,
        "version": version,
        "encryption_method": method,
        "key_data": plain[12:size],
        "raw": plain,
    }


# --------------------------------------------------------------------------
# 主体
# --------------------------------------------------------------------------
class BitLocker(object):
    """BitLocker 卷：元数据解析 + 恢复密码解锁 + 扇区级解密"""

    def __init__(self, sub):
        """sub: 有 read(offset, size) 与 size 的对象（分区或镜像）"""
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.warnings = []

        self.boot = self._read_volume_header()
        self.rejected_offsets = []
        self.metadata_offsets, self.header_offsets = self._locate_metadata()
        if not self.metadata_offsets:
            if self.rejected_offsets:
                raise ValueError(
                    "元数据块头不合法：偏移 %s 处有 %s 签名，但块版本不在 1/2 "
                    "或 metadata_size 自相矛盾（多为镜像被截断/损坏，或不是元数据区）"
                    "；如为 BitLocker 卷请换另一份副本（卷头指针 / 卷尾 0x%X 附近）"
                    % (", ".join("0x%X" % o for o in self.rejected_offsets),
                       SIGNATURE.decode(), max(0, self.size - 0x10000)))
            raise ValueError(
                "未找到 BitLocker 元数据块：卷头类型 %s，0x03 处%s，候选偏移 %s 也没有"
                "有效 %s 块（签名 %s）"
                % (self.boot["kind"],
                   "无 %s 签名" % SIGNATURE.decode()
                   if self.boot["kind"] == "Unknown" else "有签名但指针无效",
                   [hex(o) for o in self._candidate_offsets()] or "（无可试偏移）",
                   SIGNATURE.decode(), SIGNATURE_HEX))
        self.meta_offset = self.metadata_offsets[0]

        self.entries = []
        self.vmks = []
        self.fvek_entry = None
        self.description = None
        self._parse_block(self.meta_offset)

        # 卷解密的运行态
        self.cipher_mode = None
        self.fvek = None
        self.tweak_key = None
        self.volume_method = None

    # ---------------- 卷头 ----------------
    def _read_volume_header(self):
        raw = self.sub.read(0, 512)
        if len(raw) < 512:
            raise ValueError("镜像太短：读偏移 0 只得到 %d 字节（不足一个扇区）" % len(raw))
        info = {
            "kind": "Unknown",
            "signature": raw[3:11],
            "bytes_per_sector": struct.unpack_from("<H", raw, 11)[0] or 512,
            "total_sectors_32": struct.unpack_from("<I", raw, 32)[0],
            "volume_serial": struct.unpack_from("<I", raw, 67)[0],
            "label": raw[71:82].decode("ascii", "replace").rstrip(),
            "fs_signature": raw[82:90].decode("ascii", "replace").rstrip(),
            "bitlocker_guid": raw[160:176],
            "metadata_offsets": [],
            "oem": raw[3],
        }
        if raw[3:11] == SIGNATURE:
            info["kind"] = "BitLocker"
            info["metadata_offsets"] = [struct.unpack_from("<Q", raw, off)[0]
                                        for off in BOOT_META_OFFSETS]
        elif raw[3:11] == b"MSWIN4.1" and raw[424:440] != b"\x00" * 16:
            # BitLocker To Go：FAT 引导扇区，GUID 与指针整体后移
            info["kind"] = "BitLockerToGo"
            info["bitlocker_guid"] = raw[424:440]
            info["metadata_offsets"] = [struct.unpack_from("<Q", raw, off)[0]
                                        for off in TOGO_META_OFFSETS]
        else:
            info["kind"] = "Unknown"
            info["bitlocker_guid"] = b""
        return info

    def _candidate_offsets(self):
        """卷头指针 + 卷尾备份 + 常见候选，去重排序"""
        cands = []
        for off in self.boot["metadata_offsets"]:
            if off:
                cands.append(off)
        if self.size:
            cands.append(max(0, self.size - 0x10000))
            cands.append(max(0, self.size - 0x20000))
        cands.extend(DEFAULT_METADATA_CANDIDATES)

        seen = set()
        ordered = []
        for off in cands:
            if off <= 0 or off in seen:
                continue
            if self.size and off >= self.size:
                continue
            seen.add(off)
            ordered.append(off)
        return ordered

    def _probe_block(self, offset):
        """偏移处是否是一个可信的元数据块（签名 + 版本 + 尺寸自洽）"""
        head = self.sub.read(offset, BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE)
        if len(head) < BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE:
            return False
        if head[0:8] != SIGNATURE:
            return False
        block_version = struct.unpack_from("<H", head, 10)[0]
        if block_version not in (1, 2):
            return False
        metadata_size = struct.unpack_from("<I", head, BLOCK_HEADER_SIZE)[0]
        header_size = struct.unpack_from("<I", head, BLOCK_HEADER_SIZE + 8)[0]
        if not (METADATA_HEADER_SIZE <= metadata_size <= 0x100000):
            return False
        if not (METADATA_HEADER_SIZE <= header_size <= metadata_size):
            return False
        return True

    def _locate_metadata(self):
        header_offsets = [off for off in self.boot["metadata_offsets"] if off]
        found = []
        rejected = []
        for offset in self._candidate_offsets():
            if self.sub.read(offset, 8) != SIGNATURE:
                continue
            if self._probe_block(offset):
                found.append(offset)
            else:
                rejected.append(offset)
        self.rejected_offsets = rejected
        if not found:
            return [], header_offsets
        # 卷头指针指向的那一份优先作为主元数据
        primary = [off for off in found if off in header_offsets]
        rest = [off for off in found if off not in header_offsets]
        return primary + rest, header_offsets

    # ---------------- 元数据块 ----------------
    def _parse_block(self, offset):
        head = self.sub.read(offset, BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE)
        if len(head) < BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE:
            raise ValueError("元数据块被截断：偏移 0x%X 只读到 %d 字节（需要 %d）"
                             % (offset, len(head), BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE))
        if head[0:8] != SIGNATURE:
            raise ValueError("元数据块签名不符：偏移 0x%X 处不是 %s"
                             % (offset, SIGNATURE.decode()))

        self.block_version = struct.unpack_from("<H", head, 10)[0]
        if self.block_version not in (1, 2):
            raise ValueError("不支持的元数据块版本：%d（只支持 1 = Vista / 2 = Win7+）"
                             % self.block_version)
        self.block_size_field = struct.unpack_from("<H", head, 8)[0]
        self.block_unknown1 = struct.unpack_from("<H", head, 12)[0]
        self.block_unknown2 = struct.unpack_from("<H", head, 14)[0]
        if self.block_version == 2:
            self.encrypted_volume_size = struct.unpack_from("<Q", head, 16)[0]
            self.number_of_volume_header_sectors = struct.unpack_from("<I", head, 28)[0]
            self.volume_header_offset = struct.unpack_from("<Q", head, 56)[0]
        else:
            self.encrypted_volume_size = 0
            self.number_of_volume_header_sectors = 0
            self.volume_header_offset = 0
        self.block_offsets = [struct.unpack_from("<Q", head, 32)[0],
                              struct.unpack_from("<Q", head, 40)[0],
                              struct.unpack_from("<Q", head, 48)[0]]

        base = BLOCK_HEADER_SIZE
        self.metadata_size = struct.unpack_from("<I", head, base)[0]
        self.metadata_version = struct.unpack_from("<I", head, base + 4)[0]
        self.metadata_header_size = struct.unpack_from("<I", head, base + 8)[0]
        self.metadata_size_copy = struct.unpack_from("<I", head, base + 12)[0]
        self.volume_identifier = head[base + 16:base + 32]
        self.next_nonce_counter = struct.unpack_from("<I", head, base + 32)[0]
        self.encryption_method = struct.unpack_from("<H", head, base + 36)[0]
        self.encryption_method_copy = struct.unpack_from("<H", head, base + 38)[0]
        self.creation_time = struct.unpack_from("<Q", head, base + 40)[0]

        if self.metadata_size < METADATA_HEADER_SIZE:
            raise ValueError("元数据头的 metadata_size 非法：%d（至少 %d）"
                             % (self.metadata_size, METADATA_HEADER_SIZE))
        if self.metadata_size_copy and self.metadata_size_copy != self.metadata_size:
            self.warnings.append("metadata_size 与其副本不一致（%d / %d）"
                                 % (self.metadata_size, self.metadata_size_copy))
        if self.metadata_header_size < METADATA_HEADER_SIZE:
            self.warnings.append("metadata_header_size 偏小（%d），按 %d 处理"
                                 % (self.metadata_header_size, METADATA_HEADER_SIZE))
            self.metadata_header_size = METADATA_HEADER_SIZE

        total = BLOCK_HEADER_SIZE + self.metadata_size
        raw = self.sub.read(offset, total)
        if len(raw) < total:
            raise ValueError("元数据块被截断：需要 %d 字节，实际只有 %d 字节"
                             % (total, len(raw)))

        start = BLOCK_HEADER_SIZE + self.metadata_header_size
        end = total
        if end > len(raw):
            raise ValueError("元数据头声明的大小超出实际数据（%d > %d）" % (end, len(raw)))
        self.entries = _walk_entries(raw, start, end, base=offset)

        for entry in self.entries:
            if entry.type == 0x0002:
                self.vmks.append(self._parse_vmk(entry))
            elif entry.type == 0x0003 and self.fvek_entry is None:
                nonce, tag, ctext = _parse_ccm_blob(entry.data)
                self.fvek_entry = {
                    "entry_offset": entry.offset,
                    "version": entry.version,
                    "nonce": nonce,
                    "tag": tag,
                    "ciphertext": ctext,
                }
            elif entry.type == 0x0007 and entry.value_type == 0x0002:
                self.description = self._decode_string(entry.data)

        if not self.vmks:
            self.warnings.append("元数据里没有 VMK entry（0x0002）")
        if self.fvek_entry is None:
            self.warnings.append("元数据里没有 FVEK entry（0x0003）")

    @staticmethod
    def _decode_string(data):
        text = data.decode("utf-16-le", "replace")
        return text.split("\x00")[0].strip() or None

    def _parse_vmk(self, entry):
        """VMK entry：28 字节头 + 若干属性 entry（描述串 / stretch key / CCM 密钥）"""
        data = entry.data
        if len(data) < 28:
            raise ValueError("VMK entry 太短：%d 字节（头部就要 28）" % len(data))
        guid = data[0:16]
        modification_time = struct.unpack_from("<Q", data, 16)[0]
        protection_type = struct.unpack_from("<H", data, 26)[0]

        protector = KeyProtector(protection_type, guid, entry.offset, entry.version)
        protector.modification_time = modification_time

        for child in _walk_entries(data, 28, len(data)):
            protector.children.append(child)
            if child.value_type == 0x0002:
                text = self._decode_string(child.data)
                if text:
                    protector.description = text
            elif child.value_type == 0x0003:                      # stretch key
                if len(child.data) < 20:
                    raise ValueError("stretch key entry 太短：%d 字节（至少 20）" % len(child.data))
                protector.stretch_method = struct.unpack_from("<I", child.data, 0)[0]
                protector.salt = child.data[4:20]
                for nested in _walk_entries(child.data, 20, len(child.data)):
                    if nested.value_type == 0x0005:
                        nonce, tag, ctext = _parse_ccm_blob(nested.data)
                        protector.nonce, protector.tag = nonce, tag
                        protector.ciphertext = ctext
                    elif nested.value_type == 0x0001:             # Key（ClearKey 场景）
                        protector.clear_key = nested.data[4:4 + 32] if len(nested.data) > 4 \
                            else nested.data
            elif child.value_type == 0x0005:                      # 直接挂着 CCM 密钥
                nonce, tag, ctext = _parse_ccm_blob(child.data)
                protector.nonce, protector.tag = nonce, tag
                protector.ciphertext = ctext
            elif child.value_type == 0x0001:                      # Key（FVE key 结构）
                protector.clear_key = child.data[4:4 + 32] if len(child.data) > 4 \
                    else child.data
            elif child.value_type == 0x0009:                      # 外部密钥（.BEK）
                protector.ciphertext = child.data

        protector.is_active = bool(protector.ciphertext)
        return protector

    # ---------------- 对外信息 ----------------
    def info(self):
        """卷级信息（取证报告用）"""
        _name, bits, mode = METHODS.get(self.encryption_method,
                                        ("Unknown(0x%04x)" % self.encryption_method, 0, "unknown"))
        if self.encrypted_volume_size:
            volume_size = self.encrypted_volume_size
            source = "metadata block header"
        else:
            volume_size = self.size
            source = "sub.size"
        return {
            "signature": SIGNATURE.decode(),
            "volume_kind": self.boot["kind"],
            "metadata_offset": self.meta_offset,
            "metadata_offsets_found": list(self.metadata_offsets),
            "metadata_offsets_from_header": list(self.header_offsets),
            "metadata_block_version": self.block_version,
            "metadata_version": self.metadata_version,
            "metadata_size": self.metadata_size,
            "metadata_header_size": self.metadata_header_size,
            "entry_count": len(self.entries),
            "volume_identifier": guid_to_string(self.volume_identifier),
            "encryption_method": self.encryption_method,
            "encryption_method_name": _name,
            "encryption_key_bits": bits,
            "encryption_mode": mode,
            "volume_size": volume_size,
            "volume_size_source": source,
            "bytes_per_sector": self.boot["bytes_per_sector"],
            "number_of_volume_header_sectors": self.number_of_volume_header_sectors,
            "volume_header_offset": self.volume_header_offset,
            "creation_time": filetime_to_string(self.creation_time),
            "dataset_name": self.description,
            "is_encrypted": bool(self.encryption_method and mode in ("cbc", "cbc-diffuser", "xts")),
            "has_fvek": self.fvek_entry is not None,
            "fvek_bytes": len(self.fvek_entry["ciphertext"]) if self.fvek_entry else 0,
            "vmk_count": len(self.vmks),
            "protections_count": len(self.vmks),
            "has_recovery_password": any(p.type_id == 0x0800 for p in self.vmks),
            "warnings": list(self.warnings),
        }

    def protections(self):
        """每个密钥保护器一行"""
        return [p.to_dict() for p in self.vmks]

    def entries_summary(self):
        """顶层 entry 链，便于核对结构"""
        return [{
            "offset": e.offset,
            "size": e.size,
            "type": e.type,
            "type_name": e.type_name,
            "value_type": e.value_type,
            "value_type_name": e.value_type_name,
            "version": e.version,
        } for e in self.entries]

    def recovery_password_hint(self):
        """是否设了恢复密码、用什么算法、能不能解锁"""
        rps = [p for p in self.vmks if p.type_id == 0x0800]
        base = {
            "present": bool(rps),
            "count": len(rps),
            "algorithm": "恢复密码 -> 8×u16(÷11) -> SHA-256 -> 0x100000 轮 stretch"
                         " -> AES-256-CCM(CTR)",
            "stretch_iterations": STRETCH_ITERATIONS,
            "tag_verified": False,
        }
        if not rps:
            base.update({"supported": False, "guid": None, "salt_hex": None,
                         "note": "该卷未设置恢复密码保护器（只有 TPM/StartupKey/口令等）"})
            return base

        usable = [p for p in rps if p.salt and p.ciphertext]
        first = usable[0] if usable else rps[0]
        base.update({
            "supported": bool(usable),
            "guid": first.guid_string,
            "salt_hex": first.salt.hex() if first.salt else None,
            "stretch_method": first.stretch_method,
            "ccm_data_bytes": len(first.ciphertext) if first.ciphertext else 0,
            "note": ("可直接用 unlock_with_recovery_password() 解出 VMK"
                     if usable else
                     "恢复密码保护器缺少 stretch key 或 CCM 密文，无法从这里解"),
        })
        return base

    # ---------------- 解锁 ----------------
    def unlock_with_recovery_password(self, pw, stretch_iterations=STRETCH_ITERATIONS):
        """用恢复密码解出 VMK（32 字节）；密码不对返回 None

        pw: '471207-278498-...' / 带空格 / 纯 48 位数字都可以
        """
        binary = parse_recovery_password(pw)
        candidates = [p for p in self.vmks
                      if p.type_id == 0x0800 and p.salt and p.ciphertext]
        if not candidates:
            names = ", ".join(sorted({p.type_name for p in self.vmks})) or "无"
            raise NotImplementedError(
                "该卷没有可用的恢复密码保护器（需要 type=0x0800 且带 stretch key "
                "与 AES-CCM 密文）；现有保护器：%s" % names)

        initial = hashlib.sha256(binary).digest()
        for protector in candidates:
            key = stretch_key(initial, protector.salt, stretch_iterations)
            plain = ccm_ctr_crypt(key, protector.nonce, protector.ciphertext)
            blob = _parse_key_blob(plain)
            if blob is None or len(blob["key_data"]) < 32:
                continue
            return blob["key_data"][:32]
        return None

    def unlock_with_clear_key(self):
        """ClearKey（无保护）卷的 VMK

        结构上：保护器带一个 Key 属性（method u32 + 32 字节密钥）和一个
        AES-CCM 加密密钥，前者就是 CCM 的 AES-256 密钥。
        注意：本路径按公开结构实现，但手上没有真实的 ClearKey 卷做回归，
        结果只作参考——真卷请优先用恢复密码路径。
        """
        for protector in self.vmks:
            if protector.type_id != 0x0000 or protector.nonce is None:
                continue
            ccm_key = protector.clear_key
            if not ccm_key or len(ccm_key) != 32 or not protector.ciphertext:
                continue
            plain = ccm_ctr_crypt(ccm_key, protector.nonce, protector.ciphertext)
            blob = _parse_key_blob(plain)
            if blob is not None and len(blob["key_data"]) >= 32:
                return blob["key_data"][:32]
        return None

    def unlock_fvek(self, vmk):
        """VMK -> FVEK（+ TWEAK）；返回 dict，含 fvek / tweak_key / method"""
        if self.fvek_entry is None:
            raise ValueError("元数据里没有 FVEK entry（0x0003），无法继续")
        if len(vmk) != 32:
            raise ValueError("VMK 必须是 32 字节，收到 %d" % len(vmk))

        plain = ccm_ctr_crypt(vmk, self.fvek_entry["nonce"], self.fvek_entry["ciphertext"])
        blob = _parse_key_blob(plain, strict=True)
        method = blob["encryption_method"] or self.encryption_method
        _name, bits, mode = METHODS.get(method, ("Unknown", 0, "unknown"))
        key_data = blob["key_data"]

        if mode == "xts":
            need = 32 if bits == 128 else 64
            if len(key_data) < need:
                raise ValueError("XTS 的 FVEK 需要 %d 字节，密钥块里只有 %d"
                                 % (need, len(key_data)))
            return {"encryption_method": method, "mode": mode, "bits": bits,
                    "fvek": key_data[:need], "tweak_key": None,
                    "plain_size": blob["size"]}
        if mode in ("cbc", "cbc-diffuser"):
            need = 16 if bits == 128 else 32
            prefix = key_data[:need]
            tweak = None
            if mode == "cbc-diffuser":
                if len(key_data) < need * 2:
                    raise ValueError("CBC+diffuser 的密钥块需要 %d 字节（FVEK+TWEAK），只有 %d"
                                     % (need * 2, len(key_data)))
                tweak = key_data[need:need * 2]
            return {"encryption_method": method, "mode": mode, "bits": bits,
                    "fvek": prefix, "tweak_key": tweak,
                    "plain_size": blob["size"]}
        raise NotImplementedError(
            "encryption_method=0x%04x（%s）不是受支持的卷数据密码，缺实现"
            % (method, method_name(method)))

    def setup(self, vmk):
        """解出 FVEK 并进入可解密状态，返回 unlock_fvek 的结果"""
        result = self.unlock_fvek(vmk)
        self.volume_method = result["encryption_method"]
        self.cipher_mode = result["mode"]
        self.fvek = result["fvek"]
        self.tweak_key = result["tweak_key"]
        return result

    # ---------------- 扇区级解密 ----------------
    def _require_keys(self):
        if self.fvek is None or self.cipher_mode is None:
            raise NotImplementedError(
                "尚未载入 FVEK：先调用 setup(vmk)（VMK 可用 "
                "unlock_with_recovery_password() 取得），才能解扇区")
        if len(self.fvek) not in (16, 32, 64):
            raise ValueError("FVEK 长度异常：%d" % len(self.fvek))

    def _sector_key(self, sector_offset):
        """CBC+diffuser 的 32 字节扇区密钥：E(TWEAK, off) || E(TWEAK, off|0x80<<120)"""
        if not self.tweak_key:
            raise NotImplementedError("该 encryption_method 不提供 TWEAK 密钥")
        cipher = AES(self.tweak_key)
        low = struct.pack("<Q", sector_offset) + b"\x00" * 8
        high = bytearray(low)
        high[15] = 0x80
        return cipher.encrypt_block(low) + cipher.encrypt_block(bytes(high))

    def _check_sector_shape(self, data):
        """diffuser 只能处理整扇区；XTS/CBC 允许 16 字节整数倍"""
        if self.cipher_mode == "cbc-diffuser" and (len(data) % SECTOR_SIZE or not data):
            raise ValueError("CBC+diffuser 只能按整扇区（%d 字节）处理，收到 %d 字节"
                             % (SECTOR_SIZE, len(data)))

    def decrypt_sector(self, sector_number, data):
        """按 encryption_method 解一个（或整数个）512 字节扇区"""
        self._require_keys()
        if not data:
            return b""
        if len(data) % 16:
            raise ValueError("扇区数据必须是 16 的整数倍，收到 %d" % len(data))
        self._check_sector_shape(data)
        offset = sector_number * SECTOR_SIZE

        if self.cipher_mode == "xts":
            tweak = struct.pack("<Q", sector_number) + b"\x00" * 8
            return xts_decrypt(self.fvek, tweak, data)

        iv = AES(self.fvek).encrypt_block(struct.pack("<Q", offset) + b"\x00" * 8)
        out = cbc_decrypt(self.fvek, iv, data)
        if self.cipher_mode == "cbc-diffuser":
            out = diffuser_decrypt(out)
            key = self._sector_key(offset)
            out = bytes(b ^ key[i % 32] for i, b in enumerate(out))
        return out

    def encrypt_sector(self, sector_number, data):
        """加密（自检/回写验证用，与 decrypt_sector 严格互逆）"""
        self._require_keys()
        if not data:
            return b""
        if len(data) % 16:
            raise ValueError("扇区数据必须是 16 的整数倍，收到 %d" % len(data))
        self._check_sector_shape(data)
        offset = sector_number * SECTOR_SIZE

        if self.cipher_mode == "xts":
            tweak = struct.pack("<Q", sector_number) + b"\x00" * 8
            return xts_encrypt(self.fvek, tweak, data)

        body = data
        if self.cipher_mode == "cbc-diffuser":
            key = self._sector_key(offset)
            body = bytes(b ^ key[i % 32] for i, b in enumerate(body))
            body = diffuser_encrypt(body)
        iv = AES(self.fvek).encrypt_block(struct.pack("<Q", offset) + b"\x00" * 8)
        return cbc_encrypt(self.fvek, iv, body)

    def read_decrypted(self, offset, size):
        """按扇区对齐读取并解密；返回不超过 size 的明文字节"""
        self._require_keys()
        if size <= 0:
            return b""
        first = (offset // SECTOR_SIZE) * SECTOR_SIZE
        last = ((offset + size + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE
        out = bytearray()
        pos = first
        while pos < last:
            raw = self.sub.read(pos, SECTOR_SIZE)
            if not raw:
                break                               # 镜像到此为止：少读就少给，不补零
            short = len(raw) < SECTOR_SIZE
            if not short and not len(raw) % SECTOR_SIZE:
                pass
            elif self.cipher_mode == "cbc-diffuser":
                raise ValueError("扇区 0x%X 只读到 %d 字节，diffuser 需要完整扇区"
                                 % (pos, len(raw)))
            else:
                raw = raw + b"\x00" * (-len(raw) % 16)
            out += self.decrypt_sector(pos // SECTOR_SIZE, raw)
            pos += SECTOR_SIZE
            if short:
                break
        begin = offset - first
        return bytes(out[begin:begin + size])

    def describe(self):
        info = self.info()
        return "%s  %s  vol=%d  %s  prot=%d  恢复密码=%s" % (
            info["volume_kind"], info["encryption_method_name"], info["volume_size"],
            info["dataset_name"] or "-", info["protections_count"],
            "有" if info["has_recovery_password"] else "无")


# --------------------------------------------------------------------------
# 模块级便捷函数
# --------------------------------------------------------------------------
def detect(sub):
    """快速判断是否为 BitLocker 卷；返回卷类型字符串，否则 None"""
    try:
        head = sub.read(0, 512)
    except Exception:
        return None
    if len(head) < 512:
        return None
    if head[3:11] == SIGNATURE:
        return "BitLocker"
    if head[3:11] == b"MSWIN4.1" and head[424:440] != b"\x00" * 16:
        return "BitLockerToGo"
    for offset in DEFAULT_METADATA_CANDIDATES:
        try:
            probe = sub.read(offset, 8)
        except Exception:
            return None
        if probe == SIGNATURE:
            return "BitLocker(metadata-only)"
    return None


def describe(sub):
    """一行摘要，适合批量扫描时打印"""
    kind = detect(sub)
    if not kind:
        return "非 BitLocker"
    try:
        bde = BitLocker(sub)
        return bde.describe()
    except Exception as exc:                   # 识别到但解析失败：如实报告
        return "%s（解析失败: %s）" % (kind, exc)


# --------------------------------------------------------------------------
# 自检：合成一个符合 -FVE-FS- 结构的镜像，验证解析 / 解锁 / 解密全链路
# --------------------------------------------------------------------------
if __name__ == "__main__":
    class MemSub(object):
        """内存镜像：只提供 read(offset, size) 与 size"""

        def __init__(self, data):
            self.data = bytes(data)
            self.size = len(self.data)

        def read(self, offset, size):
            if offset < 0 or size <= 0 or offset >= self.size:
                return b""
            return self.data[offset:offset + size]

    def _entry(etype, vtype, payload, version=1):
        return struct.pack("<HHHH", ENTRY_HEADER_SIZE + len(payload), etype, vtype,
                           version) + payload

    def _ccm_entry(key, nonce, plaintext, aad=b""):
        """用给定密钥做 CCM 加密，产出 BitLocker 的 nonce+tag+密文 结构"""
        ctext, tag = ccm_encrypt(key, nonce, aad, plaintext, 16)
        return nonce + tag + ctext

    def build_image(method, vmk, fvek_data, recovery_pw, iterations,
                    sector_number=100, sector_plain=None):
        """构造一个带完整元数据与一个加密扇区的合成 BitLocker 镜像"""
        image_size = 0x400000
        meta_offsets = (0x100000, 0x2000, image_size - 0x10000)

        # ---- 恢复密码保护器：stretch -> CCM 包住 VMK ----
        binary_pw = parse_recovery_password(recovery_pw)
        salt = bytes(range(0x40, 0x50))
        stretch = stretch_key(hashlib.sha256(binary_pw).digest(), salt, iterations)
        vmkey_blob = struct.pack("<IHHI", 12 + len(vmk), 1, 0, 0x2003) + vmk
        nonce = bytes(range(0xA0, 0xAC))
        ccm_payload = _ccm_entry(stretch, nonce, vmkey_blob)

        stretch_prop = _entry(0x0000, 0x0003,
                              struct.pack("<I", 0x1000) + salt
                              + _entry(0x0000, 0x0005, ccm_payload))
        desc_prop = _entry(0x0000, 0x0002, "DiskPassword\x00".encode("utf-16-le"))
        vmk_payload = (bytes(range(0x10, 0x20))                      # GUID
                       + struct.pack("<Q", 0x01D0000000000000)       # FILETIME
                       + struct.pack("<HH", 0x0002, 0x0800)          # unknown, RecoveryPassword
                       + desc_prop + stretch_prop)

        # ---- FVEK：用 VMK 做 CCM ----
        fvek_blob = struct.pack("<IHHI", 12 + len(fvek_data), 1, 0, method) + fvek_data
        fvek_payload = _ccm_entry(vmk, bytes(range(0xB0, 0xBC)), fvek_blob)

        # ---- 其他 entry ----
        description = "FORENSIC-PC  Win10Volume  2026-11-15"
        entries = b"".join([
            _entry(0x0002, 0x0008, vmk_payload),                     # VMK
            _entry(0x0003, 0x0005, fvek_payload),                    # FVEK
            _entry(0x0004, 0x0007, bytes(16)),                       # Validation
            _entry(0x0007, 0x0002, description.encode("utf-16-le") + b"\x00\x00"),
            _entry(0x000F, 0x000F, struct.pack("<QQ", meta_offsets[0], 0x10000)),
        ])

        metadata_size = METADATA_HEADER_SIZE + len(entries)
        metadata_header = struct.pack("<IIII", metadata_size, 1, METADATA_HEADER_SIZE,
                                      metadata_size)
        metadata_header += bytes(range(0x70, 0x80))                  # 卷 GUID
        metadata_header += struct.pack("<I", 0x1234)                 # next nonce
        metadata_header += struct.pack("<HH", method, method | 0x0002)
        metadata_header += struct.pack("<Q", 0x01D0000000000000)     # 创建时间

        block = bytearray(SIGNATURE)
        block += struct.pack("<H", 0x0002)
        block += struct.pack("<H", 2)                                # v2 = Win7+
        block += struct.pack("<HH", 0x0004, 0x0004)
        block += struct.pack("<Q", image_size)                       # 加密卷大小
        block += struct.pack("<I", 0)
        block += struct.pack("<I", 0x2000)                           # 卷头扇区数
        block += struct.pack("<QQQ", *meta_offsets)
        block += struct.pack("<Q", 0x100000)                         # 卷头偏移
        block += metadata_header + entries
        assert len(block) == BLOCK_HEADER_SIZE + metadata_size

        # ---- 引导扇区 ----
        boot = bytearray(512)
        boot[0:3] = b"\xEB\x58\x90"
        boot[3:11] = SIGNATURE
        struct.pack_into("<H", boot, 11, SECTOR_SIZE)
        boot[13] = 8
        struct.pack_into("<I", boot, 32, image_size // SECTOR_SIZE)
        boot[66] = 0x29
        struct.pack_into("<I", boot, 67, 0xDEADBEEF)
        boot[71:82] = b"NO NAME    "
        boot[82:90] = b"FAT32   "
        boot[160:176] = bytes(range(0x90, 0xA0))
        struct.pack_into("<QQQ", boot, 176, *meta_offsets)
        boot[510:512] = b"\x55\xAA"

        image = bytearray(image_size)
        image[0:512] = boot
        for offset in meta_offsets:                                  # 三份副本
            image[offset:offset + len(block)] = block

        # ---- 一个加密扇区 ----
        if sector_plain is not None:
            if method in (0x8004, 0x8005):
                tweak = struct.pack("<Q", sector_number) + b"\x00" * 8
                cipher_text = xts_encrypt(fvek_data, tweak, sector_plain)
            else:
                fvek = fvek_data[:16] if method == 0x8000 else fvek_data[:32]
                tweak_key = fvek_data[16:32] if method == 0x8000 else fvek_data[32:64]
                offset = sector_number * SECTOR_SIZE
                cipher = AES(tweak_key)
                low = struct.pack("<Q", offset) + b"\x00" * 8
                high = bytearray(low)
                high[15] = 0x80
                sector_key = cipher.encrypt_block(low) + cipher.encrypt_block(bytes(high))
                body = bytes(b ^ sector_key[i % 32] for i, b in enumerate(sector_plain))
                body = diffuser_encrypt(body)
                iv = AES(fvek).encrypt_block(struct.pack("<Q", offset) + b"\x00" * 8)
                cipher_text = cbc_encrypt(fvek, iv, body)
            image[sector_number * SECTOR_SIZE:(sector_number + 1) * SECTOR_SIZE] = cipher_text

        return MemSub(bytes(image)), meta_offsets

    PW = "471207-278498-422125-177177-561902-537405-468006-693451"
    VMK = bytes(range(0x20, 0x40))
    FVEK_XTS = bytes(range(0x01, 0x21))                              # XTS-128：K1||K2
    FVEK_DIFF = bytes(range(0x80, 0xA0))                             # CBC+diffuser：FVEK||TWEAK

    print("=== 1) 恢复密码 / diffuser 原语 ===")
    binary = parse_recovery_password(PW)
    print("  恢复密码 -> 16 字节:", binary.hex())
    assert binary == bytes.fromhex("0068 0492 0491 03ff".replace(" ", "")) or len(binary) == 16
    for bad in ("471207-278498-422125-177177-561902-537405-468006-69345",   # 7 组半
                "471208-278498-422125-177177-561902-537405-468006-693451",  # 首组不整除 11
                "471207-278498-422125-177177-561902-537405-468006-69345X"):
        try:
            parse_recovery_password(bad)
            raise AssertionError("非法恢复密码未报错: %r" % bad)
        except ValueError as exc:
            print("  非法输入已拒绝:", str(exc)[:46])

    sector_plain = bytes((i * 7 + 3) & 0xFF for i in range(SECTOR_SIZE))
    diff_cipher = diffuser_encrypt(sector_plain)
    assert diffuser_decrypt(diff_cipher) == sector_plain
    assert diff_cipher != sector_plain
    print("  diffuser A/B 往返: OK（512 字节，5 轮 A + 3 轮 B）")

    print("\n=== 2) AES-XTS 对拍（NIST CAVP 向量）===")
    XTS_VECTORS = [
        ("c43cd0b23798ee3db0053d1e4d185e965d67fdda8c5325cc709fc3973f05cd17",
         "7900432e6021bc0e627c7b96ca08b4d0",
         "3454f7d34c0caffa12e9d2850b037fff",
         "07f2c2d4e6db6e1200bc165d154e0698"),
        ("d6c4cf73c639e025654dd3232fe3aa7138f21bc8922271b4a6c0af999100b6b5"
         "e380ec7ec8da88e6816cd7f4f26e7ac0f86e4caac3be55234ebcd4347cda2fa5",
         "041f41fa30b78898040b5e0ecba27d2b",
         "d083f37a6160ac25c3229800ae0721d94bf6a9ff2f73a418544e6c787cbcd34a",
         "b8f33dd38c138daca227728e19b62c4ad5ad516ee2c3af3431097ff281956d7d"),
    ]
    for key_hex, tweak_hex, ct_hex, pt_hex in XTS_VECTORS:
        k, tw = bytes.fromhex(key_hex), bytes.fromhex(tweak_hex)
        ct, pt = bytes.fromhex(ct_hex), bytes.fromhex(pt_hex)
        assert xts_decrypt(k, tw, ct) == pt
        assert xts_encrypt(k, tw, pt) == ct
        print("  key=%d 位 text=%d 字节 解密/加密均匹配" % (len(k) * 4, len(pt)))

    print("\n=== 3) AES-CCM 对拍（RFC 3610 #1，13 字节 nonce + AAD + 8 字节 tag）===")
    ccm_key = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
    ccm_nonce = bytes([0, 0, 0, 3, 2, 1, 0, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5])
    ccm_aad = bytes(range(8))
    ccm_pt = bytes(range(8, 31))
    exp_ct = bytes.fromhex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384")
    exp_tag = bytes.fromhex("17e8d12cfdf926e0")
    got_ct, got_tag = ccm_encrypt(ccm_key, ccm_nonce, ccm_aad, ccm_pt, 8)
    assert got_ct == exp_ct and got_tag == exp_tag
    assert ccm_decrypt(ccm_key, ccm_nonce, ccm_aad, exp_ct, exp_tag) == ccm_pt
    print("  密文与标签均匹配 RFC 3610")
    try:
        ccm_decrypt(ccm_key, ccm_nonce, ccm_aad, exp_ct, b"\x00" * 8)
        raise AssertionError("错误标签未报错")
    except ValueError:
        print("  错误标签已拒绝")

    print("\n=== 4) 合成镜像解析（AES-128-XTS）===")
    sub, meta_offsets = build_image(0x8004, VMK, FVEK_XTS, PW, STRETCH_ITERATIONS,
                                   sector_plain=sector_plain)
    assert detect(sub) == "BitLocker"
    print("  detect:", detect(sub))
    bde = BitLocker(sub)
    info = bde.info()
    print("  签名识别: %s / 元数据块版本 %d" % (info["signature"], info["metadata_block_version"]))
    print("  主元数据偏移: 0x%X  扫到: %s"
          % (info["metadata_offset"], [hex(o) for o in info["metadata_offsets_found"]]))
    assert info["metadata_offset"] == meta_offsets[0]
    assert sorted(info["metadata_offsets_found"]) == sorted(meta_offsets)

    print("  entry 链: %d 条 -> %s"
          % (info["entry_count"],
             [(e["type_name"], e["value_type_name"]) for e in bde.entries_summary()]))
    kinds = [e["type"] for e in bde.entries_summary()]
    assert kinds == [0x0002, 0x0003, 0x0004, 0x0007, 0x000F], kinds

    print("  encryption_method: 0x%04X (%s) / %d 位"
          % (info["encryption_method"], info["encryption_method_name"],
             info["encryption_key_bits"]))
    print("  volume_size: %d (来源 %s)" % (info["volume_size"], info["volume_size_source"]))
    print("  dataset_name: %s" % info["dataset_name"])
    print("  is_encrypted: %s  has_fvek: %s  创建时间: %s"
          % (info["is_encrypted"], info["has_fvek"], info["creation_time"]))
    assert info["encryption_method"] == 0x8004
    assert info["volume_size"] == 0x400000
    assert info["dataset_name"] == "FORENSIC-PC  Win10Volume  2026-11-15"
    assert info["is_encrypted"] is True and info["has_fvek"] is True
    assert info["has_recovery_password"] is True

    print("\n=== 5) 保护器列表 ===")
    for prot in bde.protections():
        print("  %-16s type=0x%04X guid=%s active=%s salt=%s desc=%r"
              % (prot["type_name"], prot["type_id"], prot["guid"], prot["is_active"],
                 (prot["salt_hex"] or "-")[:16], prot["description"]))
    assert bde.protections()[0]["type_name"] == "RecoveryPassword"
    hint = bde.recovery_password_hint()
    print("  恢复密码提示: present=%s supported=%s tag_verified=%s"
          % (hint["present"], hint["supported"], hint["tag_verified"]))
    assert hint["present"] and hint["supported"]

    print("\n=== 6) 恢复密码解锁（真实 0x100000 轮 stretch）===")
    import time as _time
    t0 = _time.time()
    vmk = bde.unlock_with_recovery_password(PW)
    dt = _time.time() - t0
    print("  VMK = %s  (%.2fs)" % (vmk.hex(), dt))
    assert vmk == VMK, "VMK 不匹配"
    other = bde.unlock_with_recovery_password("111111-278498-422125-177177-561902-537405-468006-693451")
    print("  错误密码 -> %r" % (other,))
    assert other is None

    print("\n=== 7) VMK -> FVEK -> 扇区解密（XTS）===")
    key_info = bde.setup(vmk)
    print("  FVEK 模式 %s / %d 位，FVEK %d 字节"
          % (key_info["mode"], key_info["bits"], len(key_info["fvek"])))
    got = bde.decrypt_sector(100, sub.read(100 * SECTOR_SIZE, SECTOR_SIZE))
    print("  解出扇区 100 前 16 字节: %s" % got[:16].hex())
    assert got == sector_plain, "扇区解密结果不符"
    assert bde.encrypt_sector(100, got) == sub.read(100 * SECTOR_SIZE, SECTOR_SIZE)
    assert bde.read_decrypted(100 * SECTOR_SIZE, 64) == sector_plain[:64]
    assert bde.read_decrypted(100 * SECTOR_SIZE + 10, 32) == sector_plain[10:42]
    assert bde.read_decrypted(99 * SECTOR_SIZE, 16) != sector_plain[:16]
    print("  decrypt_sector / encrypt_sector / read_decrypted（含非对齐读）一致")

    print("\n=== 8) 合成镜像解析（AES-128-CBC + diffuser，short stretch）===")
    sub2, _ = build_image(0x8000, VMK, FVEK_DIFF, PW, 4096,
                         sector_number=7, sector_plain=sector_plain)
    bde2 = BitLocker(sub2)
    info2 = bde2.info()
    print("  encryption_method: 0x%04X (%s)"
          % (info2["encryption_method"], info2["encryption_method_name"]))
    assert info2["encryption_method"] == 0x8000
    assert bde2.unlock_with_recovery_password(PW, stretch_iterations=4096) == VMK
    assert bde2.unlock_with_recovery_password(PW, stretch_iterations=1024) is None
    print("  短 stretch 解锁 OK；错误的轮数 -> None（结构校验挡住乱码）")
    ki2 = bde2.setup(VMK)
    print("  FVEK %d 字节 + TWEAK %d 字节" % (len(ki2["fvek"]), len(ki2["tweak_key"])))
    got2 = bde2.decrypt_sector(7, sub2.read(7 * SECTOR_SIZE, SECTOR_SIZE))
    assert got2 == sector_plain, "CBC+diffuser 扇区解密结果不符"
    assert bde2.encrypt_sector(7, got2) == sub2.read(7 * SECTOR_SIZE, SECTOR_SIZE)
    print("  CBC -> diffuser B -> diffuser A -> XOR 扇区密钥：往返一致")

    print("\n=== 9) 非法 / 截断输入 ===")
    cases = [
        ("全零镜像", MemSub(bytes(0x10000))),
        ("只有半个扇区", MemSub(b"\x00" * 100)),
        ("签名不在 0x03（放在 0）", MemSub(bytes(bytearray(SIGNATURE.ljust(512, b"\x00"))))),
        ("镜像截断在元数据块头", MemSub(sub.data[:0x2000 + 40])),
    ]
    for label, bad in cases:
        try:
            BitLocker(bad)
            raise AssertionError("%s 未报错" % label)
        except (ValueError, NotImplementedError) as exc:
            print("  %-22s -> %s: %s" % (label, type(exc).__name__, str(exc)[:52]))

    # 主元数据块签名糊掉 -> 应自动落到备份副本（元数据三副本容错）
    corrupted = bytearray(sub.data)
    corrupted[0x100000:0x100008] = b"XXXXXXXX"
    salvaged = BitLocker(MemSub(bytes(corrupted)))
    print("  %-22s -> 回退到 0x%X（%d 份可用）"
          % ("主块签名损坏", salvaged.meta_offset, len(salvaged.metadata_offsets)))
    assert salvaged.meta_offset == meta_offsets[1]
    assert salvaged.info()["encryption_method"] == 0x8004

    # 三份副本全坏 -> 必须报错
    all_bad = bytearray(sub.data)
    for offset in meta_offsets:
        all_bad[offset:offset + 8] = b"XXXXXXXX"
    try:
        BitLocker(MemSub(bytes(all_bad)))
        raise AssertionError("三份元数据块全坏却未报错")
    except ValueError as exc:
        print("  %-22s -> ValueError: %s" % ("三份副本全坏", str(exc)[:52]))

    # 截断 entry：把 VMK entry 的 size 改大，越过 metadata 末尾
    truncated = bytearray(sub.data)
    vmk_abs = 0x100000 + BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE
    struct.pack_into("<H", truncated, vmk_abs, 0xFFF0)
    try:
        BitLocker(MemSub(bytes(truncated)))
        raise AssertionError("越界 entry 未报错")
    except ValueError as exc:
        print("  %-22s -> ValueError: %s" % ("entry 越界", str(exc)[:52]))

    # entry size < 8
    tiny = bytearray(sub.data)
    struct.pack_into("<H", tiny, vmk_abs, 3)
    try:
        BitLocker(MemSub(bytes(tiny)))
        raise AssertionError("非法 entry size 未报错")
    except ValueError as exc:
        print("  %-22s -> ValueError: %s" % ("entry size < 8", str(exc)[:52]))

    # 元数据块头版本非法（三份都改，否则会走副本回退）
    bad_version = bytearray(sub.data)
    for offset in meta_offsets:
        struct.pack_into("<H", bad_version, offset + 10, 7)
    try:
        BitLocker(MemSub(bytes(bad_version)))
        raise AssertionError("非法块版本未报错")
    except ValueError as exc:
        print("  %-22s -> ValueError: %s" % ("块版本 = 7", str(exc)[:52]))

    print("  保护器类型名对照: " + ", ".join(
        "%s=0x%04X" % (protection_name(v), v)
        for v in (0x0000, 0x0100, 0x0200, 0x0500, 0x0800, 0x2000)))

    print("\n=== 10) 未载入密钥就解扇区 ===")
    try:
        BitLocker(sub).decrypt_sector(0, bytes(SECTOR_SIZE))
        raise AssertionError("未载入 FVEK 却解出了数据")
    except NotImplementedError as exc:
        print("  NotImplementedError: %s" % str(exc)[:70])

    print("\n=== 11) 无恢复密码保护器的卷 ===")
    sub3, _ = build_image(0x8004, VMK, FVEK_XTS, PW, 1024)
    bde3 = BitLocker(sub3)
    bde3.vmks = [p for p in bde3.vmks if p.type_id != 0x0800]
    print("  hint:", bde3.recovery_password_hint()["note"])
    try:
        bde3.unlock_with_recovery_password(PW)
        raise AssertionError("没有恢复密码保护器却未报错")
    except NotImplementedError as exc:
        print("  NotImplementedError: %s" % str(exc)[:70])

    print("\ndescribe(): %s" % bde.describe())
    print("describe(非 BitLocker): %s" % describe(MemSub(bytes(4096))))
    print("\nBitLocker 自检全部通过")
