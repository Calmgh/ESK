# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""VeraCrypt / TrueCrypt 卷头解析与口令解锁

对应 LovelyCarve 的「加密与快照」里的 VeraCrypt / TrueCrypt 部分。

格式依据 VeraCrypt《Volume Format Specification》、TrueCrypt 7.1a 的
同名文档，以及 cryptsetup `lib/tcrypt/tcrypt.c` / `tcrypt.h`
（迭代次数与 PIM 公式以 cryptsetup 的表为准，它是逐行对着 VeraCrypt 源码核的）。

只依赖可读对象 sub.read(offset, size) / sub.size，不依赖第三方库；
AES 原语来自 mkit.aes（纯标准库自研实现），PBKDF2 用 hashlib.pbkdf2_hmac。

============================================================================
1. 卷头物理布局
============================================================================
· 卷头区各 64 KiB，其中有效头部 512 字节：前 **64 字节 salt 不加密**，
  其后 **448 字节是 AES-XTS 密文**（`TCRYPT_HDR_LEN = 448` = 28 × 16）
    偏移 0                     主头（outer / normal volume）
    偏移 65536                 隐藏卷主头（hidden volume）
    偏移 size-131072           主头备份
    偏移 size-65536-131072     隐藏卷头备份
· 隐藏卷头用**不同 salt、不同口令**，只有解出来才知道是隐藏卷；
  同一位置不可能同时解出两个头
· 解密：对 salt 之后 448 字节整体做 AES-XTS，tweak 全零——即按 512 字节
  数据单元的第 0 个单元处理（448 < 512，单元内 α 递推 28 个分组）
· PBKDF2 派生 **192 字节**（`TCRYPT_HDR_KEY_LEN`）；AES-256-XTS 取前 64：
  [0:32] 数据密钥、[32:64] tweak 密钥（级联算法才用后 128 字节）

============================================================================
2. 解密后的 448 字节（**大端**；偏移是「解密区相对偏移」= 卷内偏移 − 64）
============================================================================
    0x00  magic            "VERA"(VeraCrypt) / "TRUE"(TrueCrypt)   ← 卷内 64
    0x04  header version   u16                                     ← 卷内 68
    0x06  required version u16（打包该卷的最低程序版本）
    0x08  key area CRC-32  u32  （覆盖 0xC0..0x1BF 共 256 B，卷内 0x100..0x1FF）
    0x0C  reserved[16]
    0x1C  hidden volume size      u64（外层卷头记录隐藏卷大小，挂载时保护用）
    0x24  volume size             u64
    0x2C  encrypted area start    u64
    0x34  encrypted area length   u64
    0x3C  flags                   u32（bit0 系统卷 / bit1 非系统就地加密）
    0x40  sector size             u32
    0x44  reserved[120]
    0xBC  header CRC-32           u32 ← 卷内 252，覆盖解密区 0x00..0xBB
    0xC0  master key area 256 B        ← 卷内 256..511

  **常见资料的坑**：密钥区常被写成 0x100、头 CRC 常被写成 0xFC，那是
  「卷内绝对偏移」；解密区相对偏移分别是 0xC0 和 0xBC（448 − 256 = 192，
  0xBC + 4 = 0xC0 自洽）。两者相差正好 64 字节的 salt。

============================================================================
3. 已实现
============================================================================
· 识别：VeraCrypt 卷头**没有明文特征**（salt 是随机数），只能结构启发：
  salt/头区熵、明文文件系统签名排除、卷尺寸下限、备份头区熵。
  probe() 对全零、ASCII、NTFS/FAT/ext/APFS/LUKS/BitLocker 明文一律 False
· headers()：四个头槽的偏移、随机性判定、当前解锁状态（短镜像跳过越界槽）
· unlock()：PBKDF2-HMAC 逐 (头槽 × PRF × 迭代数) 试解，以 magic + 两个
  CRC-32 三重校验判定成功，绝不「解出乱码也算成功」
    迭代次数：TrueCrypt  ripemd160 2000 / 系统 1000 / sha512 1000 / whirlpool 1000
              VeraCrypt  sha512、whirlpool、sha256、blake2s-256、stribog512 = 500000
                         ripemd160 655331；系统 sha256/blake2s/stribog 200000、
                         ripemd160 327661
    PIM     ：非系统 15000 + PIM*1000；系统（sha256/blake2s/stribog）PIM*2048
· 密钥文件：复刻 TrueCrypt/VeraCrypt 的 64 字节 keyfile pool（CRC-32 四字节
  逐段累加，写指针跨文件连续），与口令拼接后参与 PBKDF2
· 扇区解密：AES-256-XTS，tweak = 卷内绝对扇区号（16 字节小端，高 8 字节零）
· 取证记录：magic 命中但 CRC 不符 → 写进 notes 并标 crc-mismatch；
  跳过的 PRF、越界头槽、读失败偏移都显式记录，不静默

============================================================================
4. 不实现（明确边界，绝不假装能解）
============================================================================
· **Serpent / Twofish / 任意级联 → NotImplementedError**。算法不存于卷头
  （VeraCrypt 的设计，避免给攻击者提示），只能靠试；本文件只实现 AES，
  调用方知道是别的算法就显式指定，本文件宁可报错也不解出乱码
· whirlpool / stribog512：本机 hashlib/OpenSSL 3.0 不带 legacy provider，
  显式指定 → NotImplementedError；自动扫描跳过并记录
· Argon2id（VeraCrypt 1.26 的新 PRF）：标准库没有，未做
· TrueCrypt 4.x 及更早的遗留卷头（PBKDF2 与字段位置不同）：不实现
· 系统加密卷头的自动定位（第一个逻辑磁道末 512 字节）：可用
  header_offset= 显式指定，不自动探测
· 写回 / 建卷 / 改口令 / 整卷批量解密（只给扇区原语，编排交给调用方）
· **真实卷回归：没有**。自检全部基于自造的合成镜像，unlock() 返回值里
  reals_volume_verified 恒为 False；未验证项见文件末尾清单
"""

import binascii
import hashlib
import math
import os
import struct

try:                                            # 作为包导入
    from .aes import AES, cbc_encrypt, cbc_decrypt
except ImportError:                             # 直接以脚本运行（自检）
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from mkit.aes import AES, cbc_encrypt, cbc_decrypt

__all__ = [
    "VeraCrypt", "VeraCryptError", "probe", "describe", "parse_header",
    "build_header", "seal_header", "pim_iterations", "prf_iterations",
    "keyfile_pool", "require_cipher", "prf_available", "available_prfs",
    "unavailable_prfs", "xts_decrypt", "xts_encrypt", "xts_alpha", "crc32",
    "VERA_MAGIC", "TRUE_MAGIC", "SALT_LEN", "HDR_LEN", "KEY_LEN",
    "KEY_AREA_OFF", "KEY_AREA_LEN", "HDR_CRC_OFF", "PRF_TABLE",
    "DEFAULT_ITERATIONS", "SUPPORTED_CIPHERS", "MAGICS",
]

# ------------------------------------------------------------
# 常量
# ------------------------------------------------------------
VERA_MAGIC = b"VERA"
TRUE_MAGIC = b"TRUE"
MAGICS = {VERA_MAGIC: "VeraCrypt", TRUE_MAGIC: "TrueCrypt"}

SALT_LEN = 64                                   # PKCS5_SALT_SIZE
HDR_LEN = 448                                   # TCRYPT_HDR_LEN（加密区）
KEY_LEN = 192                                   # TCRYPT_HDR_KEY_LEN（PBKDF2 输出）
HEADER_SIZE = SALT_LEN + HDR_LEN                # 磁盘上有效头部 512 字节
KEY_AREA_LEN = 256                              # MASTER_KEYDATA_SIZE
KEY_AREA_OFF = HDR_LEN - KEY_AREA_LEN           # 0xC0（卷内 0x100）
HDR_CRC_OFF = 0xBC                              # 卷内 252
HDR_CRC_LEN = HDR_CRC_OFF                       # 覆盖 0x00..0xBB
KEY_CRC_OFF = 0x08
DATA_UNIT = 512                                 # ENCRYPTION_DATA_UNIT_SIZE

HEADER_AREA = 0x10000                           # 每个卷头区 64 KiB
HIDDEN_HDR_OFFSET = HEADER_AREA                 # 65536
BACKUP_HDR_DELTA = -131072                      # 备份头距卷尾
HIDDEN_BACKUP_DELTA = -65536                    # 隐藏卷备份头相对备份头再回退
SYSTEM_HDR_OFFSET = 31744                       # 首个逻辑磁道末 512B（不自动探测）

FLAG_SYSTEM = 1 << 0
FLAG_NONSYSTEM_INPLACE = 1 << 1

SUPPORTED_CIPHERS = ("AES",)

# (族, prf) -> 迭代次数；"-system" 后缀为系统加密档
DEFAULT_ITERATIONS = {
    ("truecrypt", "ripemd160"): 2000,
    ("truecrypt", "ripemd160-system"): 1000,
    ("truecrypt", "sha512"): 1000,
    ("truecrypt", "sha512-system"): 1000,
    ("truecrypt", "whirlpool"): 1000,
    ("truecrypt", "whirlpool-system"): 1000,
    ("veracrypt", "sha512"): 500000,
    ("veracrypt", "sha512-system"): 200000,
    ("veracrypt", "whirlpool"): 500000,
    ("veracrypt", "whirlpool-system"): 500000,
    ("veracrypt", "sha256"): 500000,
    ("veracrypt", "sha256-system"): 200000,
    ("veracrypt", "blake2s"): 500000,
    ("veracrypt", "blake2s-system"): 200000,
    ("veracrypt", "ripemd160"): 655331,
    ("veracrypt", "ripemd160-system"): 327661,
    ("veracrypt", "stribog512"): 500000,
    ("veracrypt", "stribog512-system"): 200000,
}

# 自动扫描顺序：sha512 在首（VeraCrypt 默认），ripemd160 紧随
# （TrueCrypt 默认，非系统只有 2000 轮，命中成本毫秒级）
PRF_TABLE = ["sha512", "ripemd160", "sha256", "blake2s", "whirlpool", "stribog512"]

PIM_NONSYSTEM_BASE = 15000
PIM_NONSYSTEM_MULT = 1000
PIM_SYSTEM_MULT = 2048
PIM_SYSTEM_PRFS = ("sha256", "blake2s", "stribog512")

_PRF_ALIASES = {
    "sha-512": "sha512", "sha2-512": "sha512",
    "sha-256": "sha256", "sha2-256": "sha256",
    "rmd160": "ripemd160", "ripemd-160": "ripemd160", "ripemd": "ripemd160",
    "blake2s-256": "blake2s", "blake2s256": "blake2s",
    "streebog512": "stribog512", "gost3411-2012-512": "stribog512",
}

_CIPHER_ALIASES = {
    "aes": "AES", "aes-256": "AES", "aes256": "AES", "aes-xts": "AES",
    "aes-256-xts": "AES", "aes256-xts": "AES", "aes-128": "AES",
}


class VeraCryptError(ValueError):
    """VeraCrypt 卷头解析 / 解锁错误"""


# ------------------------------------------------------------
# 基础工具：CRC-32 / 熵
# ------------------------------------------------------------
def crc32(data):
    """标准 CRC-32（IEEE，reflected，init/final 0xFFFFFFFF），同 zlib.crc32"""
    return binascii.crc32(bytes(data)) & 0xFFFFFFFF


def entropy(data):
    """字节熵（bit/byte）；全零 = 0，随机 512 字节 ≈ 7.6~7.9"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = float(len(data))
    value = 0.0
    for c in counts:
        if c:
            p = c / total
            value -= p * math.log(p, 2)
    return value


# ------------------------------------------------------------
# XTS（IEEE 1619，128 位小端 tweak）
# ------------------------------------------------------------
_M128 = (1 << 128) - 1


def xts_alpha(t):
    """GF(2^128) 乘 x（小端表示，多项式 0x87）"""
    carry = t >> 127
    t = (t << 1) & _M128
    if carry:
        t ^= 0x87
    return t


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def xts_crypt(key, tweak, data, encrypt):
    """单数据单元 XTS 加解密；key = 数据密钥 ‖ tweak 密钥"""
    if len(key) not in (32, 64):
        raise VeraCryptError("XTS 密钥必须 32 或 64 字节，收到 %d" % len(key))
    if len(tweak) != 16:
        raise VeraCryptError("tweak 必须是 16 字节")
    if len(data) % 16:
        raise VeraCryptError("XTS 数据长度必须是 16 的倍数（实际 %d）" % len(data))
    half = len(key) // 2
    data_cipher = AES(key[:half])
    tweak_cipher = AES(key[half:])
    t = int.from_bytes(tweak_cipher.encrypt_block(bytes(tweak)), "little")
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        tb = t.to_bytes(16, "little")
        blk = _xor(data[off:off + 16], tb)
        blk = data_cipher.encrypt_block(blk) if encrypt else data_cipher.decrypt_block(blk)
        out[off:off + 16] = _xor(blk, tb)
        t = xts_alpha(t)
    return bytes(out)


def xts_encrypt(key, tweak, data):
    return xts_crypt(key, tweak, data, True)


def xts_decrypt(key, tweak, data):
    return xts_crypt(key, tweak, data, False)


def _unit_tweak(unit_no):
    """数据单元号 → 16 字节 tweak（低 8 字节小端，余零）；卷头即 unit 0"""
    return struct.pack("<Q", int(unit_no) & 0xFFFFFFFFFFFFFFFF) + b"\x00" * 8


# ------------------------------------------------------------
# PRF：名称 / 可用性 / 迭代数 / PIM / PBKDF2
# ------------------------------------------------------------
def canonical_prf(name):
    """PRF 名称规范化；无法识别时返回小写原名"""
    if not name:
        return ""
    key = str(name).strip().lower()
    key = _PRF_ALIASES.get(key, key)
    key = key.replace("_", "-")
    if key in PRF_TABLE:
        return key
    flat = key.replace("-", "")
    for known in PRF_TABLE:
        if known == flat:
            return known
    return key


def prf_available(name):
    """本机 hashlib/OpenSSL 是否提供该 PRF（whirlpool / stribog512 通常没有）"""
    key = canonical_prf(name)
    if key not in PRF_TABLE:
        return False
    try:
        hashlib.new(key)
        return True
    except Exception:
        return False


def available_prfs():
    return [n for n in PRF_TABLE if prf_available(n)]


def unavailable_prfs():
    return [n for n in PRF_TABLE if not prf_available(n)]


def _require_prf(name):
    """返回可用于 pbkdf2_hmac 的摘要名；不可用 → NotImplementedError"""
    key = canonical_prf(name)
    if key not in PRF_TABLE:
        raise NotImplementedError(
            "未知 PRF %r：本文件支持 %s" % (name, ", ".join(PRF_TABLE)))
    if not prf_available(key):
        raise NotImplementedError(
            "PRF %s 不可用：本机 hashlib/OpenSSL（%s）没有 %s 摘要实现。"
            "VeraCrypt / TrueCrypt 都支持它，但 Python 标准库在当前 OpenSSL 3.0 下"
            "不带 legacy provider；本文件不静默跳过，可用的 PRF 是 %s"
            % (key, _openssl_version(), key, ", ".join(available_prfs()) or "无"))
    return key


def _openssl_version():
    try:
        import ssl
        return ssl.OPENSSL_VERSION
    except Exception:                            # pragma: no cover
        return "未知版本"


def pim_iterations(prf, pim, system=False):
    """PIM → 迭代数

    非系统：15000 + PIM*1000（全 PRF）
    系统  ：sha256 / blake2s / stribog512 → PIM*2048
            ripemd160 / sha512 / whirlpool → 15000 + PIM*1000（VeraCrypt 行为）
    """
    key = canonical_prf(prf)
    if pim is None:
        return None
    pim = int(pim)
    if pim <= 0:
        return None
    if system and key in PIM_SYSTEM_PRFS:
        return pim * PIM_SYSTEM_MULT
    return PIM_NONSYSTEM_BASE + pim * PIM_NONSYSTEM_MULT


def prf_iterations(family, prf, pim=None, system=False):
    """取某族 / 某 PRF 的迭代数（显式 PIM 优先）；不支持时返回 None"""
    key = canonical_prf(prf)
    if pim:
        value = pim_iterations(key, pim, system=system)
        if value:
            return value
    if system:
        value = DEFAULT_ITERATIONS.get((family, key + "-system"))
        if value:
            return value
    return DEFAULT_ITERATIONS.get((family, key))


def iteration_candidates(family, prf, iterations=None, pim=None, system=None):
    """某 (族, PRF) 下应尝试的迭代数（去重保序）

    iterations 显式 → 只用它；pim 显式 → PIM 公式（system 未知时两种都试）；
    都给 None → 默认表，非系统档在前（TrueCrypt 的 1000/2000 秒级命中）
    """
    if iterations:
        value = int(iterations)
        if value <= 0:
            raise VeraCryptError("iterations 必须 > 0，收到 %d" % value)
        return [value]
    order = []
    if system is not True:
        order.append(prf_iterations(family, prf, pim=pim, system=False))
    if system is not False:
        order.append(prf_iterations(family, prf, pim=pim, system=True))
    seen = set()
    out = []
    for value in order:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(int(value))
    return out


def pbkdf2(prf, password, salt, iterations, dklen=KEY_LEN):
    """PBKDF2-HMAC；PRF 不可用 → NotImplementedError（不静默降级）"""
    name = _require_prf(prf)
    if iterations <= 0:
        raise VeraCryptError("iterations 必须 > 0")
    raw = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    return hashlib.pbkdf2_hmac(name, raw, bytes(salt), int(iterations), dklen)


# ------------------------------------------------------------
# 算法名
# ------------------------------------------------------------
def canonical_cipher(name):
    if not name:
        return "AES"
    key = str(name).strip().lower()
    if key in _CIPHER_ALIASES:
        return _CIPHER_ALIASES[key]
    return key.replace("_", "-")


def require_cipher(name="AES"):
    """只支持 AES；其余 → NotImplementedError 并说明原因"""
    cipher = canonical_cipher(name)
    if cipher != "AES":
        raise NotImplementedError(
            "只实现 AES-256-XTS，%s 未实现。VeraCrypt 卷头**不保存**加密算法"
            "（设计如此，避免给攻击者提示），只能靠试；Serpent / Twofish 与任意"
            "级联（AES-Twofish、Serpent-Twofish-AES 等）需要额外的分组密码实现。"
            "调用方知道算法就必须显式指定 AES，本文件宁可报错也不解出乱码"
            % name)
    return "AES"


# ------------------------------------------------------------
# 密钥文件池（TrueCrypt / VeraCrypt 的 64 字节混池算法）
# ------------------------------------------------------------
_CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC_TABLE.append(_c)
del _n, _c


def expand_keyfiles(keyfiles):
    """展开密钥文件参数：字符串 / 路径对象 / 序列；目录递归收集（按名排序）"""
    if keyfiles is None:
        return []
    if isinstance(keyfiles, (str, bytes, os.PathLike)):
        keyfiles = [keyfiles]
    out = []
    for item in keyfiles:
        path = os.fspath(item)
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs.sort()
                for name in sorted(files):
                    out.append(os.path.join(root, name))
        else:
            out.append(path)
    return out


def keyfile_pool(keyfiles):
    """按 TrueCrypt/VeraCrypt 算法把密钥文件混成 64 字节池

    逐文件逐字节：crc = UPDC32(byte, crc)，再把 crc 的 4 个字节依次累加进
    pool（写指针跨文件连续、回绕到 0），与口令拼接后参与 PBKDF2。
    返回 (pool, 总字节数)。未在真实卷上验证（见文件末尾清单）。
    """
    pool = bytearray(SALT_LEN)
    pos = 0
    total = 0
    for path in expand_keyfiles(keyfiles):
        crc = 0xFFFFFFFF
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                for byte in chunk:
                    crc = _CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
                    for shift in (24, 16, 8, 0):
                        pool[pos] = (pool[pos] + ((crc >> shift) & 0xFF)) & 0xFF
                        pos = (pos + 1) % SALT_LEN
    return bytes(pool), total


def password_with_keyfiles(password, keyfiles=None):
    """口令字节 + 64 字节 keyfile 池（VC 的拼接方式）"""
    raw = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if keyfiles:
        pool, _ = keyfile_pool(keyfiles)
        raw = raw + pool
    return raw


# ------------------------------------------------------------
# 卷头明文解析 / 构造
# ------------------------------------------------------------
def parse_header(plain, kind="primary", offset=0):
    """解析 448 字节解密后的卷头（**大端**），返回字段 dict（含两个 CRC 结果）"""
    plain = bytes(plain)
    if len(plain) < HDR_LEN:
        raise VeraCryptError("卷头明文至少 %d 字节，收到 %d" % (HDR_LEN, len(plain)))
    magic = plain[0:4]
    header_version, required_version = struct.unpack_from(">HH", plain, 0x04)
    (key_crc,) = struct.unpack_from(">I", plain, KEY_CRC_OFF)
    hidden_size, volume_size, area_start, area_len = struct.unpack_from(">QQQQ", plain, 0x1C)
    (flags,) = struct.unpack_from(">I", plain, 0x3C)
    (sector_size,) = struct.unpack_from(">I", plain, 0x40)
    (header_crc,) = struct.unpack_from(">I", plain, HDR_CRC_OFF)
    key_area = plain[KEY_AREA_OFF:KEY_AREA_OFF + KEY_AREA_LEN]
    key_crc_calc = crc32(key_area)
    header_crc_calc = crc32(plain[:HDR_CRC_LEN])
    return {
        "kind": kind,
        "offset": offset,
        "magic": magic.decode("latin-1"),
        "magic_raw": magic,
        "product": MAGICS.get(magic),
        "header_version": header_version,
        "required_version": required_version,
        "required_version_text": "%d.%d" % (required_version >> 8, required_version & 0xFF),
        "key_crc": key_crc,
        "key_crc_calc": key_crc_calc,
        "key_crc_ok": key_crc == key_crc_calc,
        "header_crc": header_crc,
        "header_crc_calc": header_crc_calc,
        "header_crc_ok": header_crc == header_crc_calc,
        "hidden_volume_size": hidden_size,
        "volume_size": volume_size,
        "encrypted_area_start": area_start,
        "encrypted_area_length": area_len,
        "flags": flags,
        "is_system": bool(flags & FLAG_SYSTEM),
        "inplace_encryption": bool(flags & FLAG_NONSYSTEM_INPLACE),
        "sector_size": sector_size,
        "key_area": key_area,
        "master_key": key_area[:64],             # AES-256-XTS：数据密钥 ‖ tweak 密钥
        "master_key_hex": key_area[:64].hex(),
    }


def build_header(magic=VERA_MAGIC, master_key=b"", volume_size=0,
                 encrypted_area_start=0x20000, encrypted_area_length=0,
                 hidden_volume_size=0, flags=0, sector_size=DATA_UNIT,
                 header_version=5, required_version=0x010C):
    """构造 448 字节卷头明文（自检 / 合成镜像用，写工具可复用）"""
    if magic not in MAGICS:
        raise VeraCryptError("magic 必须是 VERA 或 TRUE")
    plain = bytearray(HDR_LEN)
    plain[0:4] = magic
    struct.pack_into(">HH", plain, 0x04, header_version, required_version)
    struct.pack_into(">QQQQ", plain, 0x1C, hidden_volume_size, volume_size,
                     encrypted_area_start, encrypted_area_length)
    struct.pack_into(">II", plain, 0x3C, flags, sector_size)
    key = bytes(master_key)[:KEY_AREA_LEN]
    plain[KEY_AREA_OFF:KEY_AREA_OFF + len(key)] = key
    struct.pack_into(">I", plain, KEY_CRC_OFF,
                     crc32(plain[KEY_AREA_OFF:KEY_AREA_OFF + KEY_AREA_LEN]))
    struct.pack_into(">I", plain, HDR_CRC_OFF, crc32(plain[:HDR_CRC_LEN]))
    return bytes(plain)


def seal_header(plain, password, salt, prf="sha512", iterations=1000,
                keyfile_data=None):
    """把 448 字节明文封装成 512 字节磁盘卷头（salt ‖ XTS 密文）"""
    if len(salt) != SALT_LEN:
        raise VeraCryptError("salt 必须 %d 字节，收到 %d" % (SALT_LEN, len(salt)))
    if len(plain) != HDR_LEN:
        raise VeraCryptError("明文必须 %d 字节，收到 %d" % (HDR_LEN, len(plain)))
    raw = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if keyfile_data:
        raw = raw + bytes(keyfile_data)
    derived = pbkdf2(prf, raw, salt, iterations, KEY_LEN)
    return bytes(salt) + xts_encrypt(derived[:64], _unit_tweak(0), bytes(plain))


# ------------------------------------------------------------
# 主类
# ------------------------------------------------------------
class VeraCrypt(object):
    """VeraCrypt / TrueCrypt 卷：卷头枚举 + 口令解锁 + 扇区级解密（只读）"""

    def __init__(self, sub):
        """sub: 有 read(offset, size) 与 size 的对象（分区或镜像）"""
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.notes = []
        self.header_status = {}                  # offset → {"kind", "state", "hint"}
        self.unlocked_headers = []               # 解出过的头偏移
        self.state = None                        # 解锁后的运行态
        self.last_attempt = None
        self.slots = self._scan_headers()

    # ---- 卷头槽位 ----
    def candidate_offsets(self):
        """(kind, offset) 列表；越界 / 重复槽位跳过"""
        raw = [("main", 0), ("hidden", HIDDEN_HDR_OFFSET)]
        if self.size:
            raw.append(("backup", self.size + BACKUP_HDR_DELTA))
            raw.append(("hidden_backup", self.size + BACKUP_HDR_DELTA + HIDDEN_BACKUP_DELTA))
        seen = set()
        out = []
        for name, off in raw:
            if off < 0 or (self.size and off + HEADER_SIZE > self.size):
                continue
            if off in seen:
                continue
            seen.add(off)
            out.append((name, off))
        return out

    def _read_header_area(self, off):
        try:
            raw = self.sub.read(off, HEADER_SIZE)
        except Exception as exc:                 # 坏镜像不该让解析器炸掉
            self.notes.append("读偏移 0x%X 失败：%s" % (off, exc))
            return None
        if raw is None or len(raw) < HEADER_SIZE:
            return None
        return raw[:SALT_LEN], raw[SALT_LEN:HEADER_SIZE]

    def _scan_headers(self):
        """枚举四个头槽，记录 salt / 头区熵（不需要口令）"""
        slots = []
        for name, off in self.candidate_offsets():
            got = self._read_header_area(off)
            info = {"name": name, "kind": name, "offset": off,
                    "offset_hex": "0x%X" % off, "readable": got is not None,
                    "salt_entropy": 0.0, "header_entropy": 0.0,
                    "random": False, "state": "unknown", "hint": "",
                    "salt_hex": None}
            if got is None:
                info["state"] = "unreadable"
                info["hint"] = "偏移 0x%X 读不到完整 %d 字节" % (off, HEADER_SIZE)
            else:
                salt, body = got
                info["salt_entropy"] = round(entropy(salt), 3)
                info["header_entropy"] = round(entropy(salt + body), 3)
                info["salt_hex"] = salt[:8].hex() + "…"
                info["random"] = (info["salt_entropy"] >= 4.5
                                  and info["header_entropy"] >= 7.0)
                info["state"] = "locked" if info["random"] else "non-random"
                if not info["random"]:
                    info["hint"] = "salt / 头区熵低，不像加密卷头"
            slots.append(info)
            self.header_status[off] = {"kind": name, "state": info["state"],
                                       "hint": info["hint"]}
        return slots

    # ---- 识别 ----
    def detect(self):
        """结构判定：是否像 VeraCrypt / TrueCrypt（无明文特征，只能启发式）"""
        possible = any(s["random"] for s in self.slots)
        return {
            "possible": possible,
            "looks_like_veracrypt": possible,
            "size": self.size,
            "signature": "none（卷头整体加密，无明文魔数）",
            "header_slots": len(self.slots),
            "readable_headers": sum(1 for s in self.slots if s["readable"]),
            "random_headers": sum(1 for s in self.slots if s["random"]),
            "solvable_headers": len(self.unlocked_headers) or None,
            "solvable_note": ("需口令才能确定有几个头可解；已解出的头会计入 "
                              "unlocked_headers"),
            "headers": [dict(s) for s in self.slots],
            "prfs_available": available_prfs(),
            "prfs_unavailable": unavailable_prfs(),
            "ciphers": list(SUPPORTED_CIPHERS),
            "cipher_note": "卷头不存算法，只能试；本实现仅 AES-256-XTS",
            "keyfile_note": "keyfile 池按 TrueCrypt 算法实现，未在真实卷上验证",
            "real_volume_verified": False,
            "notes": list(self.notes),
        }

    def headers(self):
        """主头 / 隐藏头 / 备份头 / 隐藏头备份：偏移、状态、熵"""
        return [dict(s) for s in self.slots]

    def summary(self):
        """精简版：适合打印成表"""
        rows = []
        for slot in self.slots:
            status = self.header_status.get(slot["offset"], {})
            rows.append({"name": slot["name"],
                         "offset": slot["offset"],
                         "offset_hex": slot["offset_hex"],
                         "random": slot["random"],
                         "state": status.get("state", slot["state"]),
                         "hint": status.get("hint", slot["hint"])})
        return rows

    # ---- 口令解锁 ----
    def _candidates(self, prf=None, iterations=None, pim=None, system=None):
        """(族, PRF, 迭代数) 候选序列；显式 PRF 不可用 → NotImplementedError"""
        families = ["veracrypt", "truecrypt"]
        names = [canonical_prf(prf)] if prf else list(PRF_TABLE)
        out = []
        for name in names:
            if not prf_available(name):
                if prf:
                    _require_prf(name)        # 显式指定 → 抛 NotImplementedError
                self.notes.append(
                    "PRF %s 本机不可用（%s），自动扫描已跳过：显式指定可复现该错误"
                    % (name, _openssl_version()))
                continue
            for family in families:
                for count in iteration_candidates(family, name, iterations, pim, system):
                    item = (family, name, count)
                    if item not in out:
                        out.append(item)
        if not out:
            raise NotImplementedError(
                "没有任何可用 PRF：本机只有 %s" % (", ".join(available_prfs()) or "无"))
        return out

    def unlock(self, password, keyfiles=None, prf=None, iterations=None,
               pim=None, header_offset=None, system=None, cipher="AES"):
        """用口令（可带密钥文件）解卷头；成功返回 dict，失败 None

        password      : str / bytes
        keyfiles      : 路径或序列（目录递归），按 TrueCrypt 混池算法处理
        prf           : 指定 PRF（whirlpool / stribog512 → NotImplementedError）
        iterations    : 指定迭代数，覆盖默认表与 PIM
        pim           : 指定 PIM（非系统 15000+PIM*1000；系统 sha256/blake2s 为 PIM*2048）
        header_offset : 只试该偏移；None 则四个头槽全试
        system        : True/False 限定迭代数档；None 两档都试
        cipher        : 只接受 AES（其它 → NotImplementedError）
        """
        family_hint = require_cipher(cipher)
        password_bytes = password_with_keyfiles(password, keyfiles)

        targets = self.candidate_offsets()
        if header_offset is not None:
            off = int(header_offset)
            name = next((n for n, o in targets if o == off), "manual")
            targets = [(name, off)]

        candidates = self._candidates(prf, iterations, pim, system)

        attempted = 0
        magic_hits = []
        for name, off in targets:
            got = self._read_header_area(off)
            if got is None:
                self.header_status[off] = {"kind": name, "state": "unreadable",
                                           "hint": "读不到完整 %d 字节" % HEADER_SIZE}
                continue
            salt, body = got
            for family, prf_name, count in candidates:
                attempted += 1
                derived = pbkdf2(prf_name, password_bytes, salt, count, KEY_LEN)
                plain = xts_decrypt(derived[:64], _unit_tweak(0), body)
                if plain[0:4] not in MAGICS:
                    continue
                parsed = parse_header(plain, kind=name, offset=off)
                magic_hits.append({"offset": off, "name": name, "family": family,
                                   "prf": prf_name, "iterations": count})
                if not (parsed["key_crc_ok"] and parsed["header_crc_ok"]):
                    bad = []
                    if not parsed["key_crc_ok"]:
                        bad.append("key CRC 0x%08X≠0x%08X"
                                   % (parsed["key_crc"], parsed["key_crc_calc"]))
                    if not parsed["header_crc_ok"]:
                        bad.append("header CRC 0x%08X≠0x%08X"
                                   % (parsed["header_crc"], parsed["header_crc_calc"]))
                    self.notes.append(
                        "偏移 0x%X（%s）解出 magic %s 但 CRC 不符：%s——头被篡改/损坏，"
                        "或密钥恰好命中 magic（概率极低）；按损坏处理，不返回主密钥"
                        % (off, name, parsed["magic"], "；".join(bad)))
                    self.header_status[off] = {"kind": name, "state": "crc-mismatch",
                                               "hint": "magic 命中但 CRC 失败"}
                    continue
                result = self._make_result(parsed, family, prf_name, count,
                                           pim, system, family_hint, password_bytes)
                self.unlocked_headers.append(off)
                self.header_status[off] = {
                    "kind": name, "state": "unlocked",
                    "hint": "%s / %s / %d 轮" % (result["product"], prf_name, count)}
                self.state = {
                    "cipher": family_hint,
                    "master_key": parsed["master_key"],
                    "sector_size": parsed["sector_size"] or DATA_UNIT,
                    "volume_size": parsed["volume_size"],
                    "encrypted_area_start": parsed["encrypted_area_start"],
                    "encrypted_area_length": parsed["encrypted_area_length"],
                    "header_offset": off,
                    "header": parsed,
                }
                self.last_attempt = {"targets": targets, "attempts": attempted,
                                     "magic_hits": magic_hits}
                return result

        self.last_attempt = {"targets": targets, "attempts": attempted,
                             "magic_hits": magic_hits}
        if not magic_hits:
            self.notes.append(
                "试了 %d 个 (头槽 × 族 × PRF × 迭代数) 组合，无一次命中 magic："
                "口令错 / 卷不是 AES-XTS（算法不存于头，需显式指定）/ 头已损坏"
                % attempted)
        return None

    def _make_result(self, parsed, family, prf, iterations, pim, system,
                     cipher, password_bytes):
        """组装成功返回值（含取证需要的字段与诚实标记）"""
        hidden = parsed["kind"].startswith("hidden") or bool(parsed["hidden_volume_size"])
        return {
            "product": parsed["product"],
            "family": family,
            "magic": parsed["magic"],
            "header": parsed["kind"],
            "header_kind": parsed["kind"],
            "header_offset": parsed["offset"],
            "prf": prf,
            "iterations": iterations,
            "pim": pim,
            "system": parsed["is_system"] if system is None else bool(system),
            "cipher": cipher,
            "cipher_key_size": 32,
            "cipher_mode": "XTS",
            "algorithm": "AES-XTS",
            "algorithm_verified": False,
            "cipher_note": "卷头不保存算法；此处是「用 AES 解开了」的结论，非头部字段",
            "master_key": parsed["master_key"],
            "master_key_hex": parsed["master_key_hex"],
            "secondary_key": parsed["key_area"][32:64],
            "secondary_key_hex": parsed["key_area"][32:64].hex(),
            "xts_key_hex": parsed["master_key_hex"],
            "key_area_hex": parsed["key_area"].hex(),
            "hidden_volume": hidden,
            "hidden_volume_size": parsed["hidden_volume_size"],
            "volume_size": parsed["volume_size"],
            "encrypted_area_start": parsed["encrypted_area_start"],
            "encrypted_area_length": parsed["encrypted_area_length"],
            "sector_size": parsed["sector_size"] or DATA_UNIT,
            "flags": parsed["flags"],
            "flags_text": "0x%08X" % parsed["flags"],
            "header_version": parsed["header_version"],
            "required_version": parsed["required_version_text"],
            "header_crc_ok": parsed["header_crc_ok"],
            "key_crc_ok": parsed["key_crc_ok"],
            "password_bytes": len(password_bytes),
            "keyfiles_supported": True,
            "verified_on_real_volume": False,
            "real_volume_verified": False,
            "header_fields": parsed,
            "notes": list(self.notes),
        }

    # ---- 扇区解密 ----
    def _require_state(self):
        if self.state is None:
            raise VeraCryptError("卷未解锁：请先调用 unlock(password=...)")
        require_cipher(self.state["cipher"])
        return self.state

    def decrypt_sector(self, sector, data):
        """解密一个或多个 512 字节数据单元；sector = 卷内绝对扇区号"""
        state = self._require_state()
        data = bytes(data)
        if not data:
            return b""
        if len(data) % DATA_UNIT:
            raise VeraCryptError("XTS 数据单元 %d 字节，长度必须是其整数倍（收到 %d）"
                                 % (DATA_UNIT, len(data)))
        key = state["master_key"][:64]
        out = bytearray()
        for index in range(len(data) // DATA_UNIT):
            chunk = data[index * DATA_UNIT:(index + 1) * DATA_UNIT]
            out += xts_decrypt(key, _unit_tweak(sector + index), chunk)
        return bytes(out)

    def encrypt_sector(self, sector, data):
        """加密（自检 / 回写验证用，与 decrypt_sector 严格互逆）"""
        state = self._require_state()
        data = bytes(data)
        if not data:
            return b""
        if len(data) % DATA_UNIT:
            raise VeraCryptError("长度必须是 %d 的整数倍（收到 %d）"
                                 % (DATA_UNIT, len(data)))
        key = state["master_key"][:64]
        out = bytearray()
        for index in range(len(data) // DATA_UNIT):
            chunk = data[index * DATA_UNIT:(index + 1) * DATA_UNIT]
            out += xts_encrypt(key, _unit_tweak(sector + index), chunk)
        return bytes(out)

    def read_decrypted(self, offset, size, sector_size=None):
        """按扇区对齐读并解密；offset/size 是卷内绝对字节偏移"""
        state = self._require_state()
        if size <= 0:
            return b""
        unit = sector_size or state["sector_size"] or DATA_UNIT
        first = (offset // unit) * unit
        last = ((offset + size + unit - 1) // unit) * unit
        out = bytearray()
        pos = first
        while pos < last:
            raw = self.sub.read(pos, unit)
            if not raw:
                break                            # 镜像到底：少读就少给，不补零
            out += self.decrypt_sector(pos // unit, raw + b"\x00" * (-len(raw) % DATA_UNIT))
            pos += unit
            if len(raw) < unit:
                break
        begin = offset - first
        return bytes(out[begin:begin + size])


# ------------------------------------------------------------
# 模块级便捷函数
# ------------------------------------------------------------
def _plaintext_signature(head):
    """明文文件系统 / 容器签名（命中即「不是 VeraCrypt 头」）"""
    if head[0:4] in MAGICS:
        return MAGICS[head[0:4]] + "-plaintext"
    if head[3:11] == b"NTFS    ":
        return "NTFS"
    if head[3:11] == b"-FVE-FS-":
        return "BitLocker"
    if head[54:62] in (b"FAT12   ", b"FAT16   ") or head[82:90] == b"FAT32   ":
        return "FAT"
    if head[0:6] == b"LUKS\xba\xbe":
        return "LUKS"
    if head[0:4] == b"\x10\x20\xf5\xf2" or head[32:36] == b"NXSB":
        return "APFS"
    if head[0:4] == b"_BHR" or head[0:4] == b"XFSB":
        return "btrfs/XFS"
    if len(head) > 1082 and head[1080:1082] == b"\x53\xef":
        return "ext"
    if head[0:2] == b"PK" or head[0:2] == b"\x1f\x8b" or head[0:3] == b"BZh":
        return "archive"
    if head[510:512] == b"\x55\xaa":
        return "MBR/boot sector"
    return None


def probe(sub):
    """结构上是否像 VeraCrypt / TrueCrypt 卷（无明文特征，只能启发式）

    返回 False 的判据：太短、命中明文文件系统/容器签名、salt 或头区熵低
    （全零、文本、重复填充都在这里被排除）、卷尺寸小于最小卷、
    备份头区 salt 熵低。返回 True 仅表示「结构上像」，确认仍需 unlock()。
    """
    try:
        head = sub.read(0, HEADER_SIZE)
    except Exception:
        return False
    if head is None or len(head) < HEADER_SIZE:
        return False
    if _plaintext_signature(head):
        return False
    size = int(getattr(sub, "size", 0) or 0)
    if size and size < 2 * HEADER_AREA + abs(BACKUP_HDR_DELTA):   # 最小卷 296 KiB 级
        return False

    primary_ok = (entropy(head[:SALT_LEN]) >= 4.5 and entropy(head) >= 7.0)
    if primary_ok:
        if not size:
            return True
        try:
            tail = sub.read(size + BACKUP_HDR_DELTA, SALT_LEN)
        except Exception:
            tail = b""
        # 备份头区是随机数：随机卷正常，明文卷/全零镜像会露馅
        if tail and len(tail) == SALT_LEN and entropy(tail) < 4.5:
            return False
        return True

    # 主头被抹掉（全零 / 随机填充）但备份头仍在：仍算「像」，靠 unlock 的
    # header_offset=size-131072 或自动回落去救
    if not size:
        return False
    try:
        backup = sub.read(size + BACKUP_HDR_DELTA, HEADER_SIZE)
    except Exception:
        return False
    if backup is None or len(backup) < HEADER_SIZE:
        return False
    return entropy(backup[:SALT_LEN]) >= 4.5 and entropy(backup) >= 7.0


def describe(sub):
    """一行摘要（批量扫描时打印用）；非 VeraCrypt 数据返回「非…」"""
    try:
        volume = VeraCrypt(sub)
        info = volume.detect()
    except Exception as exc:
        return "非 VeraCrypt/TrueCrypt（解析失败：%s）" % exc
    if not info["possible"]:
        return "非 VeraCrypt/TrueCrypt（头区熵低或无随机 salt）"
    names = ",".join(s["name"] for s in info["headers"] if s["random"])
    return ("VeraCrypt/TrueCrypt 疑似  size=%d  随机头 %d/%d [%s]  "
            "PRF 可用 %s  算法仅 AES（头内不存）"
            % (info["size"], info["random_headers"], info["header_slots"],
               names or "-", "/".join(info["prfs_available"])))


# ------------------------------------------------------------
# 自检：合成镜像，全部离线
# ------------------------------------------------------------
if __name__ == "__main__":
    import io
    import sys

    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    PASS = [0]
    FAIL = [0]

    def chk(label, cond, extra=""):
        if cond:
            PASS[0] += 1
            print("  [PASS] %s %s" % (label, extra))
        else:
            FAIL[0] += 1
            print("  [FAIL] %s %s" % (label, extra))

    class MemSub(object):
        """最小 sub 接口：read(offset, size) + size"""

        def __init__(self, data):
            self.data = bytes(data)
            self.size = len(self.data)

        def read(self, off, n):
            off = max(0, int(off))
            n = max(0, int(n))
            return self.data[off:off + n]

    def prng(count, seed=b"esk-veracrypt"):
        """确定性伪随机（自检可复现，不依赖 os.urandom）"""
        out = bytearray()
        counter = 0
        while len(out) < count:
            out += hashlib.sha512(seed + struct.pack(">I", counter)).digest()
            counter += 1
        return bytes(out[:count])

    def put(img, offset, blob):
        img[offset:offset + len(blob)] = blob

    IMAGE_SIZE = 1 << 20                            # 1 MiB
    PASSWORD = "correct horse battery staple"
    HIDDEN_PASSWORD = "battery staple, hidden"
    ITERS = 1000                                    # 自检把迭代数调小
    MASTER = bytes((0x10 + i) & 0xFF for i in range(64))
    HIDDEN_MASTER = bytes((0xA0 + i) & 0xFF for i in range(64))
    SALT = prng(64, b"esk-vc-salt-main")
    HIDDEN_SALT = prng(64, b"esk-vc-salt-hidden")
    BACKUP_OFF = IMAGE_SIZE + BACKUP_HDR_DELTA
    HIDDEN_OFF = HIDDEN_HDR_OFFSET
    HIDDEN_BACKUP_OFF = IMAGE_SIZE + BACKUP_HDR_DELTA + HIDDEN_BACKUP_DELTA

    print("=" * 74)
    print("VeraCrypt / TrueCrypt 自检（合成镜像，未使用真实卷）")
    print("=" * 74)

    # ---- 合成卷头 ----
    main_plain = build_header(VERA_MAGIC, MASTER, volume_size=IMAGE_SIZE,
                              encrypted_area_start=abs(BACKUP_HDR_DELTA),
                              encrypted_area_length=IMAGE_SIZE - abs(BACKUP_HDR_DELTA))
    hidden_plain = build_header(VERA_MAGIC, HIDDEN_MASTER, volume_size=IMAGE_SIZE // 4,
                                encrypted_area_start=HIDDEN_BACKUP_OFF - IMAGE_SIZE // 4,
                                encrypted_area_length=IMAGE_SIZE // 4,
                                hidden_volume_size=IMAGE_SIZE // 4)

    main_hdr = seal_header(main_plain, PASSWORD, SALT, "sha512", ITERS)
    backup_hdr = seal_header(main_plain, PASSWORD, SALT, "sha512", ITERS)
    hidden_hdr = seal_header(hidden_plain, HIDDEN_PASSWORD, HIDDEN_SALT, "sha512", ITERS)

    image = bytearray(prng(IMAGE_SIZE, b"esk-vc-image"))
    put(image, 0, main_hdr)
    put(image, BACKUP_OFF, backup_hdr)
    put(image, HIDDEN_OFF, hidden_hdr)
    image = bytes(image)

    # ==== 1) 正确口令 → 主密钥 ====
    print("\n=== 1) 正确口令解出主密钥 ===")
    vol = VeraCrypt(MemSub(image))
    got = vol.unlock(PASSWORD, prf="sha512", iterations=ITERS)
    chk("unlock 返回 dict", got is not None)
    chk("主密钥 64 字节一致", got and got["master_key"] == MASTER,
        got and got["master_key_hex"][:16])
    chk("product = VeraCrypt", got and got["product"] == "VeraCrypt")
    chk("头槽 = main / 偏移 0", got and got["header"] == "main" and got["header_offset"] == 0)
    chk("PRF / 迭代数记录正确", got and got["prf"] == "sha512" and got["iterations"] == ITERS)
    chk("volume_size 大端解析正确", got and got["volume_size"] == IMAGE_SIZE,
        got and got["volume_size"])
    chk("两个 CRC 都通过", got and got["header_crc_ok"] and got["key_crc_ok"])
    chk("算法标为 AES-XTS 且未验证", got and got["algorithm"] == "AES-XTS"
        and got["algorithm_verified"] is False)

    # ==== 2) 错口令 → None ====
    print("\n=== 2) 错口令返回 None ===")
    vol2 = VeraCrypt(MemSub(image))
    chk("错口令 → None", vol2.unlock("wrong", prf="sha512", iterations=ITERS) is None)
    chk("state 仍为空", vol2.state is None)
    chk("notes 记录尝试次数", any("无一次命中 magic" in n for n in vol2.notes))

    # ==== 3) 篡改 → CRC 失败进 notes ====
    print("\n=== 3) 篡改一字节 → CRC 失败被记录 ===")
    tampered = bytearray(main_plain)
    tampered[0x24] ^= 0x01                      # 改 volume size，CRC 不再匹配
    tamper_img = bytearray(image)
    put(tamper_img, 0, seal_header(bytes(tampered), PASSWORD, SALT, "sha512", ITERS))
    vol3 = VeraCrypt(MemSub(bytes(tamper_img)))
    chk("篡改头单独解 → None（不返回主密钥）",
        vol3.unlock(PASSWORD, prf="sha512", iterations=ITERS,
                    header_offset=0) is None)
    crc_notes = [n for n in vol3.notes if "CRC 不符" in n]
    chk("notes 记录 CRC 不符", bool(crc_notes), crc_notes[0][:42] + "…" if crc_notes else "")
    chk("头状态标 crc-mismatch", vol3.header_status[0]["state"] == "crc-mismatch")
    chk("last_attempt 记录 magic 命中", bool(vol3.last_attempt["magic_hits"]))
    chk("不指定偏移时备份头仍能救回（篡改不掩盖真相）",
        VeraCrypt(MemSub(bytes(tamper_img))).unlock(
            PASSWORD, prf="sha512", iterations=ITERS)["header"] == "backup")

    # ==== 4) 备份头 ====
    print("\n=== 4) 备份头 size-131072 ===")
    vol4 = VeraCrypt(MemSub(image))
    got4 = vol4.unlock(PASSWORD, prf="sha512", iterations=ITERS, header_offset=BACKUP_OFF)
    chk("备份头可解", got4 is not None)
    chk("备份头主密钥相同", got4 and got4["master_key"] == MASTER)
    chk("头槽标 backup", got4 and got4["header"] == "backup")
    names = {s["name"]: s["offset"] for s in vol4.headers()}
    chk("headers() 列出四个槽",
        names.get("backup") == BACKUP_OFF and names.get("hidden") == HIDDEN_OFF
        and names.get("hidden_backup") == HIDDEN_BACKUP_OFF, len(names))
    broken = bytearray(image)
    put(broken, 0, prng(HEADER_SIZE, b"esk-vc-broken"))
    got4b = VeraCrypt(MemSub(bytes(broken))).unlock(PASSWORD, prf="sha512",
                                                    iterations=ITERS)
    chk("主头损坏时回落到备份头", got4b is not None and got4b["header_offset"] == BACKUP_OFF)

    # ==== 5) 隐藏卷头 ====
    print("\n=== 5) 隐藏卷头 65536 ===")
    vol5 = VeraCrypt(MemSub(image))
    got5 = vol5.unlock(HIDDEN_PASSWORD, prf="sha512", iterations=ITERS,
                       header_offset=HIDDEN_OFF)
    chk("隐藏头用独立口令可解", got5 is not None)
    chk("隐藏头主密钥正确", got5 and got5["master_key"] == HIDDEN_MASTER)
    chk("标记 hidden_volume", got5 and got5["hidden_volume"] is True)
    chk("hidden_volume_size 解出", got5 and got5["hidden_volume_size"] == IMAGE_SIZE // 4)
    chk("主口令解不开隐藏头",
        VeraCrypt(MemSub(image)).unlock(PASSWORD, prf="sha512", iterations=ITERS,
                                        header_offset=HIDDEN_OFF) is None)

    # ==== 6) 不可用 PRF ====
    print("\n=== 6) 不可用 PRF → NotImplementedError ===")
    for bad in ("whirlpool", "stribog512", "streebog512"):
        try:
            VeraCrypt(MemSub(image)).unlock(PASSWORD, prf=bad, iterations=ITERS)
        except NotImplementedError as exc:
            chk("%s 抛 NotImplementedError" % bad, "不可用" in str(exc) or "未知" in str(exc),
                str(exc)[:40])
        else:
            chk("%s 抛 NotImplementedError" % bad, False, "返回了 None（静默失败）")
    vol6 = VeraCrypt(MemSub(image))
    auto = vol6._candidates(None, iterations=ITERS)
    chk("自动扫描第一个是 sha512", auto[0][1] == "sha512", auto[0])
    chk("自动扫描不含不可用 PRF",
        all(p not in ("whirlpool", "stribog512") for _, p, _ in auto))
    chk("自动扫描跳过写进 notes", any("跳过" in n for n in vol6.notes))

    # ==== 7) Serpent / Twofish / 级联 ====
    print("\n=== 7) Serpent / Twofish / 级联 → NotImplementedError ===")
    for bad in ("Serpent", "Twofish", "AES-Twofish-Serpent", "serpent-twofish"):
        try:
            VeraCrypt(MemSub(image)).unlock(PASSWORD, prf="sha512",
                                            iterations=ITERS, cipher=bad)
        except NotImplementedError as exc:
            chk("%s 抛 NotImplementedError" % bad, "不保存" in str(exc), str(exc)[:34])
        else:
            chk("%s 抛 NotImplementedError" % bad, False, "静默通过")
    vol7 = VeraCrypt(MemSub(image))
    vol7.unlock(PASSWORD, prf="sha512", iterations=ITERS)
    vol7.state["cipher"] = "Serpent"
    try:
        vol7.decrypt_sector(0, b"\x00" * DATA_UNIT)
    except NotImplementedError:
        chk("decrypt_sector 对 Serpent 也拒绝", True)
    else:
        chk("decrypt_sector 对 Serpent 也拒绝", False)

    # ==== 8) probe ====
    print("\n=== 8) 非 VeraCrypt 数据 probe() 为 False ===")
    ntfs = bytearray(IMAGE_SIZE)
    ntfs[3:11] = b"NTFS    "
    ntfs[510:512] = b"\x55\xaa"
    cases = [("全零", MemSub(b"\x00" * IMAGE_SIZE), False),
             ("ASCII 文本", MemSub(b"ESK forensic notes\n" * (IMAGE_SIZE // 19)), False),
             ("NTFS 引导扇区", MemSub(bytes(ntfs)), False),
             ("过短输入", MemSub(prng(1024)), False),
             ("合成 VeraCrypt 卷", MemSub(image), True)]
    for label, sub, expect in cases:
        chk("probe(%s) = %s" % (label, expect), probe(sub) is expect)
    chk("describe 对全零返回非 VeraCrypt",
        describe(cases[0][1]).startswith("非 VeraCrypt"), describe(cases[0][1])[:22])
    chk("describe 对合成卷给出「疑似」", "疑似" in describe(cases[4][1]))
    wiped = bytearray(image)
    put(wiped, 0, b"\x00" * HEADER_SIZE)          # 主头被抹掉，备份头还在
    chk("probe(主头被抹/备份完好) = True", probe(MemSub(bytes(wiped))) is True)
    print("    已知局限：纯随机数据也会被判 True（卷头无明文特征，只能靠熵）")
    print("    describe: %s" % describe(cases[4][1]))

    # ==== 9) PIM ====
    print("\n=== 9) PIM 公式与实解 ===")
    chk("15000 + 5*1000 = 20000", 15000 + 5 * 1000 == 20000, 15000 + 5 * 1000)
    chk("pim_iterations(sha512, 5) = 20000", pim_iterations("sha512", 5) == 20000,
        pim_iterations("sha512", 5))
    chk("系统 sha256 PIM 5 = 5*2048 = 10240",
        pim_iterations("sha256", 5, system=True) == 5 * 2048 == 10240)
    chk("系统 ripemd160 仍走 15000+5000",
        pim_iterations("ripemd160", 5, system=True) == 20000)
    pim = 1
    pim_iters = pim_iterations("sha512", pim)
    chk("PIM=1 → 16000 轮", pim_iters == 16000, pim_iters)
    pim_img = bytearray(image)
    put(pim_img, 0, seal_header(main_plain, PASSWORD, SALT, "sha512", pim_iters))
    got9 = VeraCrypt(MemSub(bytes(pim_img))).unlock(PASSWORD, prf="sha512", pim=pim)
    chk("PIM=1 实解成功", got9 is not None and got9["master_key"] == MASTER)
    chk("返回值带 PIM 与迭代数", got9 and got9["pim"] == pim and got9["iterations"] == 16000)

    # ==== 10) decrypt_sector 往返 ====
    print("\n=== 10) decrypt_sector / read_decrypted 往返 ===")
    vol10 = VeraCrypt(MemSub(image))
    vol10.unlock(PASSWORD, prf="sha512", iterations=ITERS)
    plain_sector = prng(DATA_UNIT, b"esk-vc-sector-7")
    ct = vol10.encrypt_sector(7, plain_sector)
    chk("密文 ≠ 明文", ct != plain_sector)
    chk("sector 7 往返一致", vol10.decrypt_sector(7, ct) == plain_sector)
    chk("换 sector 号结果不同（tweak 生效）",
        vol10.decrypt_sector(8, ct) != plain_sector)
    data_off = 2 * 1024                               # 备份头之前的普通数据区
    sec = data_off // DATA_UNIT
    rt_img = bytearray(image)
    put(rt_img, data_off, vol10.encrypt_sector(sec, plain_sector))
    vol10b = VeraCrypt(MemSub(bytes(rt_img)))
    vol10b.unlock(PASSWORD, prf="sha512", iterations=ITERS)
    chk("read_decrypted 整扇区", vol10b.read_decrypted(data_off, DATA_UNIT) == plain_sector)
    chk("read_decrypted 偏移 100/400",
        vol10b.read_decrypted(data_off + 100, 400) == plain_sector[100:500])
    try:
        VeraCrypt(MemSub(image)).decrypt_sector(0, b"\x00" * 16)
    except VeraCryptError:
        chk("未解锁读扇区报错", True)
    else:
        chk("未解锁读扇区报错", False)

    # ==== 附加：TrueCrypt 族 / keyfile / XTS 互校 ====
    print("\n=== 附加) TrueCrypt 族 / keyfile 池 / XTS 互校 ===")
    tc_plain = build_header(TRUE_MAGIC, MASTER, volume_size=IMAGE_SIZE,
                            header_version=3, required_version=0x0700)
    tc_img = bytearray(prng(IMAGE_SIZE, b"esk-vc-tc"))
    put(tc_img, 0, seal_header(tc_plain, PASSWORD, SALT, "ripemd160", 2000))
    got_tc = VeraCrypt(MemSub(bytes(tc_img))).unlock(PASSWORD)
    chk("TrueCrypt magic + ripemd160 2000 轮自动命中",
        got_tc is not None and got_tc["product"] == "TrueCrypt"
        and got_tc["prf"] == "ripemd160", got_tc and got_tc["prf"])
    kf = os.path.join(os.environ.get("TEMP", "."), "_esk_vc_keyfile.bin")
    with open(kf, "wb") as fh:
        fh.write(prng(4096, b"esk-vc-keyfile"))
    pool, total = keyfile_pool([kf])
    chk("keyfile 池 64 字节", len(pool) == 64 and total == 4096, total)
    put(tc_img, 0, seal_header(tc_plain, PASSWORD, SALT, "sha512", 2000,
                               keyfile_data=pool))
    got_kf = VeraCrypt(MemSub(bytes(tc_img))).unlock(PASSWORD, keyfiles=[kf],
                                                     prf="sha512", iterations=2000)
    chk("keyfile 参与派生后可解", got_kf is not None and got_kf["master_key"] == MASTER)
    os.remove(kf)
    try:
        from mkit.bitlocker import xts_encrypt as ref_xts
        chk("与 bitlocker.xts_encrypt 逐字节一致",
            ref_xts(MASTER, b"\x00" * 16, main_plain) == xts_encrypt(MASTER, b"\x00" * 16, main_plain))
    except ImportError:
        print("  [SKIP] 缺少 mkit.bitlocker，跳过 XTS 互校")

    print("\n" + "=" * 74)
    print("VeraCrypt：卷头定位 / 大端字段 / PBKDF2 与迭代表 / 解锁与 CRC /")
    print("错口令与篡改 / 备份头与隐藏头 / PRF 边界 / Serpent 拒绝 / PIM /")
    print("扇区往返 / TrueCrypt 族 / keyfile 池 / XTS 互校")
    print("通过 %d 项，失败 %d 项" % (PASS[0], FAIL[0]))
    print("PRF 可用  : %s" % ", ".join(available_prfs()))
    print("PRF 不可用: %s（显式指定 → NotImplementedError）"
          % (", ".join(unavailable_prfs()) or "无"))
    print("算法      : AES-256-XTS；Serpent / Twofish / 级联 → NotImplementedError")
    print("未在真实卷上验证：口令→主密钥完整链路（含 keyfile 混池、PIM）、")
    print("                  系统加密头、TrueCrypt 4.x 遗留布局、非 512 字节扇区")
    if FAIL[0]:
        print("FAILED: %d 项未通过" % FAIL[0])
        raise SystemExit(1)
    print("veracrypt 模块自检全部通过")
    print("=" * 74)
