# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""Apple FileVault 2（CoreStorage）卷解析与口令解锁

对应 LovelyCarve 的「加密与快照」里的 FileVault 2 部分。

只依赖可读对象 sub.read(offset, size) / sub.size，不依赖第三方库；
AES 块原语来自 mkit.aes，PBKDF2 来自 hashlib.pbkdf2_hmac，plist 来自标准库
plistlib。AES 密钥包装（RFC 3394 AES-KW）本文件自实现。

============================================================================
已实现
============================================================================
1. 物理卷头（512 B，小端）
   · 0x00 CRC-32C（覆盖 8..511，init 0xFFFFFFFF，**无最终异或**，即 libfvde
     所称 weak CRC-32）、0x04 init、0x08 version、0x0A block type 0x0010
   · 0x30 bytes per sector、0x40 物理卷大小、0x58 签名 "CS"、0x5A 校验算法
     （1 = CRC-32C）、0x5E 元数据块数、0x60 block size、0x64 metadata size、
     0x68 元数据块号数组（4 × u64，实际偏移 = 块号 × block size）
   · 0xA8 key data size、0xAC encryption method（2 = AES-XTS）、0xB0 key data
   · 0x130 physical volume identifier（**同时是加密元数据与
     EncryptedRoot.plist.wipekey 的 XTS 密钥**）、0x140 logical volume group
     identifier
   · 卷尾 512 B 的副本（size - 512）同样解析，两份都给
2. 元数据块头（64 B）
   · checksum@0（CRC-32C 覆盖 8..8191）、init@4、version@8、block type@0x0A、
     serial@0x0C、transaction id@0x10、object id@0x18、block number@0x20、
     备用 object id@0x28、block size@0x30、flags@0x34
   · 从物理卷头给出的块号开始顺序走块，CRC 自校验，坏块停止并记录
3. 卷组描述符（block type 0x0011）
   · 描述符偏移 / XML plist 偏移 / plist 大小（块数据内 156 / 160 / 164）
   · 记录 48 B 一项：status@0（0 未加密 / 1 加密 / 2 解密中）、
     加密元数据块数@8、primary 加密元数据块号@0x20（6 B）+ pv index@0x26、
     secondary@0x28
     **注**：本文件用 48 B 步长而不是 24 B——primary 落在 0x20，24 B 步长装不下
     第二个描述符，且与 libfvde 文档的描述符表一致
   · 卷组 plist（lvg.uuid / lvg.name / pv.uuid / physicalVolumes）
4. 逻辑卷 plist（block type 0x001a）
   · lv.familyUUID（**tweak 密钥的输入之一**）、lv.uuid、lv.name、lv.size、
     lv.contenthint、lv.groupUUID
5. 加密上下文 plist（encryption context）
   · 三种来源依次尝试：
     a) 调用方给的 EncryptedRoot.plist.wipekey 原始内容（构造参数 wipekey）
     b) 卷组描述符指向的加密元数据区：用 XTS(PV UUID || 0^16, tweak=块号或 0,
        数据单元 8192) 解密后找 block type 0x0019
     c) 未加密元数据区里直接出现的 0x0019
   · 0x0019 块内 plist 偏移 48 / 大小 52（相对块头）；压缩数据（zlib）
     按 compressed/uncompressed 大小自动解压
   · 解析 CryptoUsers[] 与 WrappedVolumeKeys[]
6. 密钥链（全部为真实算法）
   · PassphraseWrappedKEKStruct 284 B：salt@8、WrappedKEK@32、迭代次数@172
   · PBKDF2-HMAC-SHA256(口令, salt, 迭代, 16) → 16 B AES-KW 密钥
   · AES-KW(RFC 3394) 解 WrappedKEK 24 B（8 B A 寄存器 + 16 B 密文）
     → 16 B KEK；A 寄存器必须回到 0xA6×8，否则视为口令错误
   · 再 AES-KW 解 KEKWrappedVolumeKeyStruct 里的 24 B → 16 B VMK
   · 口令与恢复密钥走同一条通路（恢复密钥就是带连字符的字符串）
7. 卷解密
   · tweak 密钥 = SHA256(VMK || lv.familyUUID)[:16]
   · XTS 密钥 = VMK || tweak_key；tweak = 扇区号（128 位小端）；
     数据单元 512 B（IEEE 1619 / GF(2^128) 乘 x 递推，末位触发 0x87）
   · decrypt_sector / read_decrypted 扇区级读取

============================================================================
已做过的独立交叉验证（不入依赖，仅开发期跑过）
============================================================================
· AES-KW：RFC 3394 §4.1 / §4.3 / §4.6 三组官方向量 + cryptography 的
  aes_key_wrap 20 组随机用例（KEK 16/24/32 B，数据 16~64 B）逐字节一致
· AES-XTS：IEEE 1619 语义，与 cryptography 的 modes.XTS 12 组随机用例
  （AES-128/256 XTS、随机扇区号、512/1024 B 数据单元）逐字节一致；
  自检里另有固化的已知答案（密文 sha256）
· CRC-32C：b"123456789" 弱版 0x1CF96D7C / 标准版 0xE3069283（已知校验值）

============================================================================
未在真实镜像上验证（如实标注）
============================================================================
· 加密上下文位于加密元数据区时的块号选择：本文件对每个候选块同时试
  tweak = 0 与 tweak = 块号，靠 64 B 块头 CRC 与 block type 0x0019 判定；
  真实 CoreStorage 到底用哪一种，手上没有样本可证。
· 0x0011 / 0x0019 的“块内偏移”基准：文档对 0x0019 明说相对块头，对 0x0011
  没说。本文件两种基准（块头起算 / 块数据起算）都试，取 plist 能解析的那个。
· 描述符步长 48 B 与题述 24 B 的差异见上；两者都会用 48，若某天遇到步长
  确实是 24 的较早格式，需要再改。
· 多物理卷（pv index > 0）只解析不重组：跨 PV 的逻辑卷没有拼接。
· 系统卷（加密上下文标记为 LVFwiped）在这里拿不到 VMK：那种卷必须借助
  Recovery HD 上的 EncryptedRoot.plist.wipekey，请用 wipekey= 传入。
· Apple_HFS / APFS 解析不属本文件范围。
"""

import hashlib
import plistlib
import struct
import uuid
import zlib

try:                                          # 作为包导入（from mkit.filevault2 import ...）
    from .aes import AES
except ImportError:                           # 直接以脚本运行（自检）
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from mkit.aes import AES

__all__ = [
    "FileVault2", "VolumeGroupDescriptor",
    "probe", "describe", "detect",
    "crc32c", "aes_kw_wrap", "aes_kw_unwrap", "aes_kw_unwrap_raw",
    "xts_encrypt", "xts_decrypt", "pbkdf2_sha256",
    "parse_encryption_context", "parse_passphrase_wrapped_kek",
    "parse_volume_group_descriptors", "load_plist", "uuid_to_bytes",
    "SIGNATURE", "SECTOR_SIZE",
]

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------
SIGNATURE = b"CS"
PV_HEADER_SIZE = 512
BLOCK_HEADER_SIZE = 64
BLOCK_DATA_OFFSET = 64               # 块数据起点（绝大多数偏移以此为准）
BLOCK_CHECKSUM_SPAN = 8192           # 元数据块 CRC 覆盖 8..8191
SECTOR_SIZE = 512
METADATA_XTS_UNIT = 8192             # 加密元数据的数据单元

WEAK_CRC_INIT = 0xFFFFFFFF
KEY_DATA_SIZE = 16
KW_IV = b"\xA6" * 8                  # RFC 3394 默认 A 初值

BLOCK_TYPE_PV_HEADER = 0x0010
BLOCK_TYPE_VOLUME_GROUP = 0x0011
BLOCK_TYPE_LOGICAL_VOLUME = 0x001A
BLOCK_TYPE_ENCRYPTION_CONTEXT = 0x0019

ENCRYPTION_METHODS = {
    0: ("None（未加密）", 0),
    2: ("AES-XTS", 128),
}

DESCRIPTOR_STATUS = {
    0: "未加密",
    1: "加密",
    2: "解密中",
}

GROUP_STATUS_NAMES = {
    "Complete": "已完成",
    "Converting": "转换中",
    "NoConversion": "无转换",
    "Pending": "待转换",
}

DESCRIPTOR_STRIDE = 48               # 见模块文档：primary 在 0x20，24 B 装不下

_M64 = 0xFFFFFFFFFFFFFFFF
_M128 = (1 << 128) - 1


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------
def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def encryption_method_name(method):
    """encryption method -> 可读名"""
    return ENCRYPTION_METHODS.get(method, ("Unknown(0x%X)" % method, 0))[0]


def encryption_key_size(method):
    """encryption method -> 密钥位数（0 表示无密钥）"""
    return ENCRYPTION_METHODS.get(method, ("", 0))[1]


def uuid_to_bytes(text):
    """'AC C53457-...' 形式的 UUID 字符串 -> 16 字节大端；失败返回 b''"""
    if not text:
        return b""
    raw = "".join(ch for ch in str(text) if ch not in " -")
    if len(raw) != 32:
        return b""
    try:
        return uuid.UUID(raw).bytes
    except (ValueError, AttributeError):
        return b""


def uuid_to_string(raw):
    """16 字节 -> 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"""
    if not raw or len(raw) < 16:
        return ""
    return str(uuid.UUID(bytes=bytes(raw[:16])))


def load_plist(blob):
    """尽力解析 plist：二进制 / 带 XML 头 / 裸 <dict> 三种都吃，失败返回 None"""
    if not blob:
        return None
    data = bytes(blob)
    if data.startswith(b"bplist"):               # 二进制 plist 内部含 0x00，不能截断
        try:
            return plistlib.loads(data)
        except Exception:
            return None
    data = data.split(b"\x00")[0]                # XML 变体末尾常见零填充
    if not data.strip():
        return None
    if b"<plist" not in data[:1024]:
        head = data.lstrip()
        if not head.startswith(b"<"):
            return None
        # 真实加密上下文常常没有 XML 声明与 plist 包装，补上再解析
        data = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
                b'<plist version="1.0">' + head + b"</plist>")
    try:
        return plistlib.loads(data)
    except Exception:
        return None


# --------------------------------------------------------------------------
# CRC-32C（Castagnoli 0x1EDC6F41，反射式 0x82F63B78）
# CoreStorage 用的是「弱」CRC：无最终异或
# --------------------------------------------------------------------------
def _build_crc32c_table():
    poly = 0x82F63B78
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (poly if crc & 1 else 0)
        table.append(crc & 0xFFFFFFFF)
    return tuple(table)


_CRC32C_TABLE = _build_crc32c_table()


def crc32c(data, init=WEAK_CRC_INIT):
    """CRC-32C；默认 init 0xFFFFFFFF，**不做**最终异或（CoreStorage 的算法）"""
    crc = init & 0xFFFFFFFF
    table = _CRC32C_TABLE
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc & 0xFFFFFFFF


# --------------------------------------------------------------------------
# AES 密钥包装（RFC 3394）
# --------------------------------------------------------------------------
def aes_kw_wrap(kek, key):
    """AES-KW 包装；返回 8 + len(key)，key 必须是 8 的整数倍且至少 16 B"""
    kek = bytes(kek)
    key = bytes(key)
    if len(kek) not in (16, 24, 32):
        raise ValueError("AES-KW 的 KEK 必须是 16/24/32 字节，收到 %d" % len(kek))
    if len(key) < 16 or len(key) % 8:
        raise ValueError("AES-KW 待包装密钥必须是 >=16 且 8 的整数倍，收到 %d" % len(key))
    n = len(key) // 8
    cipher = AES(kek)
    a = int.from_bytes(KW_IV, "big")
    r = [int.from_bytes(key[8 * i:8 * i + 8], "big") for i in range(n)]
    for j in range(6):
        for i in range(n):
            block = cipher.encrypt_block(a.to_bytes(8, "big") + r[i].to_bytes(8, "big"))
            a = int.from_bytes(block[:8], "big") ^ (n * j + i + 1)
            r[i] = int.from_bytes(block[8:], "big")
    return a.to_bytes(8, "big") + b"".join(x.to_bytes(8, "big") for x in r)


def aes_kw_unwrap_raw(kek, wrapped):
    """AES-KW 解包，返回 (A 寄存器 8 B, 明文密钥)；不做 0xA6 校验

    调用方可以用它检查 A 是否回到 0xA6×8（FileVault 的 WrappedKEK 就是这么判定的）。
    """
    kek = bytes(kek)
    wrapped = bytes(wrapped)
    if len(kek) not in (16, 24, 32):
        raise ValueError("AES-KW 的 KEK 必须是 16/24/32 字节，收到 %d" % len(kek))
    if len(wrapped) < 24 or len(wrapped) % 8:
        raise ValueError("AES-KW 密文必须 >=24 且 8 的整数倍，收到 %d" % len(wrapped))
    n = len(wrapped) // 8 - 1
    cipher = AES(kek)
    a = int.from_bytes(wrapped[:8], "big")
    r = [int.from_bytes(wrapped[8 + 8 * i:16 + 8 * i], "big") for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n - 1, -1, -1):
            t = n * j + i + 1
            block = cipher.decrypt_block((a ^ t).to_bytes(8, "big") + r[i].to_bytes(8, "big"))
            a = int.from_bytes(block[:8], "big")
            r[i] = int.from_bytes(block[8:], "big")
    return a.to_bytes(8, "big"), b"".join(x.to_bytes(8, "big") for x in r)


def aes_kw_unwrap(kek, wrapped):
    """AES-KW 解包；A 寄存器不是 0xA6×8（口令/密钥不对）时返回 None"""
    try:
        iv, key = aes_kw_unwrap_raw(kek, wrapped)
    except (ValueError, TypeError):
        return None
    return key if iv == KW_IV else None


def pbkdf2_sha256(passphrase, salt, iterations, length=16):
    """PBKDF2-HMAC-SHA256；passphrase 与 salt 都允许 str（按 UTF-8 编码）"""
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("utf-8")
    if not iterations or iterations <= 0:
        raise ValueError("PBKDF2 迭代次数必须是正整数，收到 %r" % (iterations,))
    return hashlib.pbkdf2_hmac("sha256", bytes(passphrase), bytes(salt),
                               int(iterations), int(length))


# --------------------------------------------------------------------------
# AES-XTS（IEEE 1619）
# --------------------------------------------------------------------------
def _xts_mul_alpha(value):
    """GF(2^128) 乘 x（小端位序，溢出时异或 0x87）"""
    carry = value >> 127
    value = (value << 1) & _M128
    if carry:
        value ^= 0x87
    return value


def _xts_crypt(key, tweak, data, encrypt):
    key = bytes(key)
    if len(key) == 32:
        data_key, tweak_key = key[:16], key[16:]
    elif len(key) == 64:
        data_key, tweak_key = key[:32], key[32:]
    else:
        raise ValueError("XTS 密钥必须是 32 或 64 字节（两块子钥），收到 %d" % len(key))
    tweak = bytes(tweak)
    if len(tweak) != 16:
        raise ValueError("XTS tweak 必须是 16 字节，收到 %d" % len(tweak))
    if not data or len(data) % 16:
        raise ValueError("XTS 数据长度必须是 16 的正整数倍，收到 %d" % len(data))
    data_cipher = AES(data_key)
    tweak_cipher = AES(tweak_key)
    t = int.from_bytes(tweak_cipher.encrypt_block(tweak), "little")
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        tb = t.to_bytes(16, "little")
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], tb))
        block = data_cipher.encrypt_block(block) if encrypt else data_cipher.decrypt_block(block)
        out[off:off + 16] = bytes(a ^ b for a, b in zip(block, tb))
        t = _xts_mul_alpha(t)
    return bytes(out)


def xts_encrypt(key, tweak, data):
    return _xts_crypt(key, tweak, data, True)


def xts_decrypt(key, tweak, data):
    return _xts_crypt(key, tweak, data, False)


def sector_tweak(sector_number):
    """扇区号 -> 128 位小端 tweak"""
    n = int(sector_number)
    return struct.pack("<QQ", n & _M64, (n >> 64) & _M64)


# --------------------------------------------------------------------------
# 卷组描述符
# --------------------------------------------------------------------------
class VolumeGroupDescriptor(object):
    """一条卷组描述符记录（默认 48 B 步长）"""

    __slots__ = ("index", "offset", "status", "encrypted_metadata_blocks",
                 "primary_block_number", "primary_pv_index",
                 "secondary_block_number", "secondary_pv_index", "raw")

    def __init__(self, index, offset, raw):
        self.index = index
        self.offset = offset
        self.raw = bytes(raw)
        self.status = _u64(raw, 0)
        self.encrypted_metadata_blocks = _u64(raw, 8)
        self.primary_block_number = int.from_bytes(raw[32:38], "little")
        self.primary_pv_index = _u16(raw, 38)
        self.secondary_block_number = int.from_bytes(raw[40:46], "little")
        self.secondary_pv_index = _u16(raw, 46)

    @property
    def status_name(self):
        return DESCRIPTOR_STATUS.get(self.status, "Unknown(%d)" % self.status)

    @property
    def encrypted(self):
        return self.status == 1

    def to_dict(self):
        return {
            "index": self.index,
            "status": self.status,
            "status_name": self.status_name,
            "encrypted_metadata_blocks": self.encrypted_metadata_blocks,
            "primary_block_number": self.primary_block_number,
            "primary_pv_index": self.primary_pv_index,
            "secondary_block_number": self.secondary_block_number,
            "secondary_pv_index": self.secondary_pv_index,
        }

    def __repr__(self):
        return "VolumeGroupDescriptor(%d, %s, blocks=%d, primary=0x%X)" % (
            self.index, self.status_name, self.encrypted_metadata_blocks,
            self.primary_block_number)


def parse_volume_group_descriptors(buf, start=0, end=None,
                                   stride=DESCRIPTOR_STRIDE, valid_status=None):
    """解析卷组描述符数组

    end 缺省时读到 buf 末尾；valid_status 给出后，status 不在清单里的记录视为
    越过描述符数组（后面就是 XML plist 数据），立即停止。
    """
    buf = bytes(buf)
    end = len(buf) if end is None else min(end, len(buf))
    out = []
    index = 0
    pos = start
    while pos + stride <= end:
        record = buf[pos:pos + stride]
        if len(record) < stride:
            break
        if record == b"\x00" * stride:
            break                            # 全零：描述符数组结束
        descriptor = VolumeGroupDescriptor(index, pos, record)
        if valid_status is not None and descriptor.status not in valid_status:
            break
        if descriptor.encrypted_metadata_blocks > (1 << 24):
            break
        out.append(descriptor)
        index += 1
        pos += stride
    return out


# --------------------------------------------------------------------------
# PassphraseWrappedKEKStruct / KEKWrappedVolumeKeyStruct
# --------------------------------------------------------------------------
def parse_passphrase_wrapped_kek(blob):
    """284 B 的 PassphraseWrappedKEKStruct -> dict；结构不符返回 None"""
    blob = bytes(blob)
    if len(blob) < 176:
        return None
    info = {
        "value_type": _u32(blob, 0),
        "value_size": _u32(blob, 4),
        "salt": blob[8:24],
        "primary_key_type": _u32(blob, 24),
        "primary_key_size": _u32(blob, 28),
        "wrapped_kek": blob[32:56],
        "iterations": _u32(blob, 172) if len(blob) >= 176 else 0,
        "size": len(blob),
    }
    if info["value_type"] != 3 or info["primary_key_type"] != 16:
        return None
    return info


def parse_wrapped_volume_key(blob):
    """256 B 的 KEKWrappedVolumeKeyStruct -> dict；取 offset 8 的 24 B 包装卷密钥"""
    blob = bytes(blob)
    if len(blob) < 32:
        return None
    if _u32(blob, 0) != 2 or _u32(blob, 4) != 24:
        return None
    return {"wrapped_volume_key": blob[8:32], "size": len(blob)}


def parse_encryption_context(blob):
    """加密上下文 plist（字节） -> 规范化 dict；解析不出返回 None"""
    data = load_plist(blob)
    if not isinstance(data, dict):
        return None
    users = []
    for index, user in enumerate(data.get("CryptoUsers") or []):
        if not isinstance(user, dict):
            continue
        kek = parse_passphrase_wrapped_kek(user.get("PassphraseWrappedKEKStruct") or b"")
        if kek is None:
            # 结构不合法的条目照样列出来（取证上“有一个用户但读不出盐”也是信息）
            raw = user.get("PassphraseWrappedKEKStruct")
            kek = {
                "value_type": None, "value_size": None, "salt": b"",
                "primary_key_type": None, "primary_key_size": None,
                "wrapped_kek": b"", "iterations": 0,
                "size": len(raw) if isinstance(raw, (bytes, bytearray)) else 0,
                "valid": False,
            }
        else:
            kek["valid"] = True
        users.append({
            "index": index,
            "user_ident": user.get("UserIdent"),
            "key_ident": user.get("KeyEncryptingKeyIdent"),
            "user_type": user.get("UserType"),
            "hint": user.get("PassphraseHint"),
            "kek": kek,
        })

    volume_keys = []
    for index, item in enumerate(data.get("WrappedVolumeKeys") or []):
        if not isinstance(item, dict):
            continue
        parsed = parse_wrapped_volume_key(item.get("KEKWrappedVolumeKeyStruct") or b"")
        volume_keys.append({
            "index": index,
            "block_algorithm": item.get("BlockAlgorithm"),
            "volume_key_index": item.get("VolumeKeyIndex"),
            "volume_key_ident": item.get("VolumeKeyIdent"),
            "key_ident": item.get("KeyEncryptingKeyIdent"),
            "wrapped_volume_key": parsed["wrapped_volume_key"] if parsed else b"",
            "valid": parsed is not None,
        })

    conversion = data.get("ConversionInfo") or {}
    return {
        "users": users,
        "volume_keys": volume_keys,
        "conversion_status": conversion.get("ConversionStatus") if isinstance(conversion, dict) else None,
        "last_update_time": data.get("LastUpdateTime"),
    }


# --------------------------------------------------------------------------
# 主体
# --------------------------------------------------------------------------
class FileVault2(object):
    """FileVault 2 / CoreStorage 卷：头解析 + 口令解锁 + 扇区级解密"""

    def __init__(self, sub, wipekey=None):
        """sub: 有 read(offset, size) 与 size 的对象（分区或镜像）

        wipekey: 可选，Recovery HD 上 EncryptedRoot.plist.wipekey 的原始内容
                 （加密或未加密都可以），系统卷必须靠它。
        """
        self.sub = sub
        self.size = int(getattr(sub, "size", 0) or 0)
        self.warnings = []

        raw = self._read(0, PV_HEADER_SIZE)
        if len(raw) < PV_HEADER_SIZE:
            raise ValueError("镜像太短：偏移 0 只读到 %d 字节（物理卷头要 %d 字节）"
                             % (len(raw), PV_HEADER_SIZE))
        self.header = self._parse_pv_header(raw, 0)
        if not self.header["valid"]:
            raise ValueError(
                "不是 CoreStorage 物理卷：version=%d（要 1）、block type=0x%04X"
                "（要 0x0010）、0x58 处签名=%r（要 b'CS'）"
                % (self.header["version"], self.header["block_type"],
                   self.header["signature"]))

        self.block_size = self.header["block_size"] or 0x8000
        self.metadata_size = self.header["metadata_size"] or self.block_size
        self.metadata_block_numbers = self.header["metadata_block_numbers"]
        self.pv_uuid = self.header["pv_uuid"]
        self.lvg_uuid = self.header["lvg_uuid"]

        self.backup_header = None
        backup_offset = self.size - PV_HEADER_SIZE if self.size >= PV_HEADER_SIZE else -1
        if backup_offset > 0:
            tail = self._read(backup_offset, PV_HEADER_SIZE)
            if len(tail) == PV_HEADER_SIZE:
                parsed = self._parse_pv_header(tail, backup_offset)
                if parsed["valid"]:
                    self.backup_header = parsed
                elif parsed["signature"] == SIGNATURE:
                    self.warnings.append("卷尾物理卷头签名正确但 version/block type 不符")

        # 走元数据块
        self.blocks = []
        self.group_plist = None
        self.descriptors = []
        self.lv_plist = None
        self.family_uuid = b""
        self._walk_metadata()

        # 加密上下文
        self.context = None
        self.context_source = None
        self._wipekey = bytes(wipekey) if wipekey else None
        self._load_context()

        # 解密的运行态
        self.vmk = None
        self.tweak_key = None
        self.xts_key = None
        self._unlock_source = None

    # ---------------- 底层读 ----------------
    def _read(self, offset, size):
        if size <= 0 or offset < 0:
            return b""
        if self.size and offset >= self.size:
            return b""
        return self.sub.read(offset, size) or b""

    # ---------------- 物理卷头 ----------------
    def _parse_pv_header(self, raw, offset):
        header = {
            "offset": offset,
            "checksum": _u32(raw, 0x00),
            "checksum_init": _u32(raw, 0x04),
            "version": _u16(raw, 0x08),
            "block_type": _u16(raw, 0x0A),
            "serial": _u32(raw, 0x0C),
            "bytes_per_sector": _u32(raw, 0x30) or SECTOR_SIZE,
            "volume_size": _u64(raw, 0x40),
            "signature": raw[0x58:0x5A],
            "checksum_algorithm": _u16(raw, 0x5A),
            "metadata_block_count": _u16(raw, 0x5E),
            "block_size": _u32(raw, 0x60),
            "metadata_size": _u32(raw, 0x64),
            "metadata_block_numbers": [_u64(raw, 0x68 + 8 * i) for i in range(4)],
            "key_data_size": _u32(raw, 0xA8),
            "encryption_method": _u32(raw, 0xAC),
            "key_data": raw[0xB0:0xB0 + 16],
            "pv_uuid": raw[0x130:0x140],
            "lvg_uuid": raw[0x140:0x150],
        }
        init = header["checksum_init"]
        if init != WEAK_CRC_INIT:
            self.warnings.append(
                "物理卷头 0x%X：CRC 初值不是 0xFFFFFFFF（实际 0x%08X），按实际值校验"
                % (offset, init))
        header["checksum_ok"] = (crc32c(raw[8:PV_HEADER_SIZE], init) == header["checksum"])
        header["encryption_method_name"] = encryption_method_name(header["encryption_method"])
        header["key_size"] = encryption_key_size(header["encryption_method"])
        header["valid"] = (header["version"] == 1
                           and header["block_type"] == BLOCK_TYPE_PV_HEADER
                           and header["signature"] == SIGNATURE)
        return header

    # ---------------- 元数据块 ----------------
    def _parse_block_header(self, offset):
        """读并校验一个 64 B 元数据块头；不可信返回 None"""
        raw = self._read(offset, BLOCK_HEADER_SIZE)
        if len(raw) < BLOCK_HEADER_SIZE:
            return None
        info = {
            "offset": offset,
            "checksum": _u32(raw, 0x00),
            "checksum_init": _u32(raw, 0x04),
            "version": _u16(raw, 0x08),
            "block_type": _u16(raw, 0x0A),
            "serial": _u32(raw, 0x0C),
            "transaction_id": _u64(raw, 0x10),
            "object_id": _u64(raw, 0x18),
            "block_number": _u64(raw, 0x20),
            "object_id_copy": _u64(raw, 0x28),
            "block_size": _u32(raw, 0x30),
            "flags": _u32(raw, 0x34),
        }
        full = self._read(offset, BLOCK_CHECKSUM_SPAN)
        info["checksum_ok"] = (len(full) == BLOCK_CHECKSUM_SPAN
                               and crc32c(full[8:BLOCK_CHECKSUM_SPAN],
                                          info["checksum_init"]) == info["checksum"])
        info["valid"] = (info["version"] == 1 and info["checksum_ok"]
                         and BLOCK_HEADER_SIZE <= info["block_size"] <= 0x4000000)
        return info

    def _walk_metadata(self):
        """从物理卷头给的块号顺序走块，直到 CRC 失败或越界"""
        seen = set()
        limit = max(1, self.metadata_size // (self.block_size or 1))
        for start in self.metadata_block_numbers:
            if not start:
                continue
            count = 0
            while count < max(limit, 1):
                block_number = start + count
                if block_number in seen:
                    break
                offset = block_number * self.block_size
                info = self._parse_block_header(offset)
                if info is None:
                    break
                if not info["valid"]:
                    self.warnings.append(
                        "元数据块 0x%X（块号 %d）头不可信：CRC %s，version=%d，block_size=%d"
                        % (offset, block_number,
                           "OK" if info["checksum_ok"] else "不符",
                           info["version"], info["block_size"]))
                    break
                seen.add(block_number)
                info["parsed"] = self._parse_block_data(info)
                self.blocks.append(info)
                count += 1

    def _block_data(self, info):
        """块数据（块头之后的部分）"""
        offset = info["offset"] + BLOCK_HEADER_SIZE
        size = min(info["block_size"], self.block_size or info["block_size"])
        return self._read(offset, max(0, size - BLOCK_HEADER_SIZE))

    def _plist_in_block(self, info, relative_offset, size, data_base):
        """按给定基准取 plist；取不到返回 None"""
        absolute = info["offset"] + data_base + relative_offset
        if size <= 0:
            return None
        return load_plist(self._read(absolute, size))

    def _parse_block_data(self, info):
        """按块类型解析块数据；只做本文件关心的三种"""
        block_type = info["block_type"]
        if block_type == BLOCK_TYPE_VOLUME_GROUP:
            return self._parse_volume_group_block(info)
        if block_type == BLOCK_TYPE_LOGICAL_VOLUME:
            return self._parse_logical_volume_block(info)
        return None

    def _parse_volume_group_block(self, info):
        data = self._block_data(info)
        if len(data) < 168:
            self.warnings.append("卷组块 0x%X 数据不足 168 字节" % info["offset"])
            return None
        descriptor_offset = _u32(data, 156)
        plist_offset = _u32(data, 160)
        plist_size = _u32(data, 164)
        result = {
            "descriptor_offset": descriptor_offset,
            "plist_offset": plist_offset,
            "plist_size": plist_size,
            "plist": None,
            "descriptors": [],
        }
        # plist 的基准：先按块数据起算，不行再按块头起算
        plist = None
        for base in (BLOCK_DATA_OFFSET, 0):
            plist = self._plist_in_block(info, plist_offset, plist_size, base)
            if isinstance(plist, dict):
                result["plist_base"] = base
                break
        # 文档说 plist 常放在“下一个块”，两种基准都不成就在紧随的块里找
        if not isinstance(plist, dict):
            for delta in (1, 2, -1):
                neighbour = self._parse_block_header(
                    info["offset"] + delta * self.block_size)
                if not neighbour or not neighbour["valid"]:
                    continue
                candidate = self._read(neighbour["offset"] + BLOCK_HEADER_SIZE,
                                       min(self.block_size, 0x10000))
                start = candidate.find(b"<dict>")
                if start < 0:
                    start = candidate.find(b"bplist00")
                if start >= 0:
                    plist = load_plist(candidate[start:])
                    if isinstance(plist, dict):
                        result["plist_base"] = "neighbour+%+d" % delta
                        break
        if isinstance(plist, dict):
            result["plist"] = plist
            self.group_plist = plist
        else:
            self.warnings.append("卷组块 0x%X：卷组 plist 未取到" % info["offset"])

        # 描述符数组紧接在 plist 之前，用它当上界，避免把 plist 字节当成描述符
        end = len(data)
        if 0 < plist_offset <= len(data):
            end = plist_offset
        descriptors = parse_volume_group_descriptors(
            data, descriptor_offset, end,
            valid_status=tuple(DESCRIPTOR_STATUS.keys()))
        result["descriptors"] = descriptors
        if descriptors:
            self.descriptors = descriptors
        return result

    def _parse_logical_volume_block(self, info):
        data = self._block_data(info)
        if len(data) < 72:
            self.warnings.append("逻辑卷块 0x%X 数据不足 72 字节" % info["offset"])
            return None
        plist_offset = _u32(data, 64)
        plist_size = _u32(data, 68)
        result = {"plist_offset": plist_offset, "plist_size": plist_size, "plist": None}
        plist = None
        for base in (BLOCK_DATA_OFFSET, 0):
            plist = self._plist_in_block(info, plist_offset, plist_size, base)
            if isinstance(plist, dict):
                result["plist_base"] = base
                break
        if isinstance(plist, dict):
            result["plist"] = plist
            if self.lv_plist is None:
                self.lv_plist = plist
            family = plist.get("com.apple.corestorage.lv.familyUUID")
            raw = uuid_to_bytes(family)
            if raw and not self.family_uuid:
                self.family_uuid = raw
        return result

    # ---------------- 加密上下文 ----------------
    def _decrypt_metadata_block(self, offset, tweak_bytes):
        raw = self._read(offset, METADATA_XTS_UNIT)
        if len(raw) < METADATA_XTS_UNIT:
            return None
        key = self.pv_uuid + b"\x00" * 16          # primary = PV UUID，secondary = 0
        try:
            return xts_decrypt(key, tweak_bytes, raw)
        except ValueError:
            return None

    def _context_from_encrypted_metadata(self):
        """在卷组描述符指向的加密元数据区里找 block type 0x0019"""
        for descriptor in self.descriptors:
            if not descriptor.primary_block_number:
                continue
            base = descriptor.primary_block_number * self.block_size
            count = max(1, min(descriptor.encrypted_metadata_blocks or 1, 16))
            for index in range(count):
                offset = base + index * METADATA_XTS_UNIT
                for tweak_bytes in (sector_tweak(index), b"\x00" * 16):
                    plain = self._decrypt_metadata_block(offset, tweak_bytes)
                    if plain is None:
                        continue
                    got = self._plist_from_0x0019(plain)
                    if got is not None:
                        return got
        return None

    def _plist_from_0x0019(self, plain):
        """加密元数据块明文 -> (plist 数据, 说明)；不是 0x0019 返回 None"""
        if len(plain) < BLOCK_HEADER_SIZE:
            return None
        if crc32c(plain[8:BLOCK_CHECKSUM_SPAN], _u32(plain, 4)) != _u32(plain, 0):
            return None
        if _u16(plain, 0x0A) != BLOCK_TYPE_ENCRYPTION_CONTEXT:
            return None
        offset = _u32(plain, 48)
        size = _u32(plain, 52)
        if size <= 0:
            return None
        blob = plain[offset:offset + size]
        if not blob:
            return None
        compressed = _u32(plain, 40)
        uncompressed = _u32(plain, 44)
        if compressed and uncompressed and compressed != uncompressed:
            try:
                blob = zlib.decompress(blob)
            except zlib.error as exc:
                self.warnings.append("加密上下文 zlib 解压失败：%s" % exc)
                return None
        return blob

    def _load_context(self):
        sources = []
        if self._wipekey:
            sources.append(("wipekey", self._wipekey))
        for info in self.blocks:
            if info["block_type"] == BLOCK_TYPE_ENCRYPTION_CONTEXT:
                data = self._block_data(info)
                if len(data) >= 56:
                    offset = _u32(data, 48)
                    size = _u32(data, 52)
                    blob = self._read(info["offset"] + offset, size)
                    if blob:
                        sources.append(("metadata-0x0019@0x%X" % info["offset"], blob))
        for label, blob in sources:
            parsed = parse_encryption_context(blob)
            if parsed is None:
                # 可能是加密过的 wipekey：XTS(PV UUID || 0^16, tweak=0, 整个文件)
                key = self.pv_uuid + b"\x00" * 16
                if self.pv_uuid:
                    for tweak_bytes in (b"\x00" * 16, sector_tweak(0)):
                        try:
                            plain = xts_decrypt(key, tweak_bytes,
                                                blob[:len(blob) - len(blob) % 16])
                        except ValueError:
                            continue
                        parsed = parse_encryption_context(plain)
                        if parsed is not None:
                            label += "+XTS"
                            break
            if parsed is not None:
                self.context = parsed
                self.context_source = label
                return
        encrypted = self._context_from_encrypted_metadata()
        if encrypted is not None:
            parsed = parse_encryption_context(encrypted)
            if parsed is not None:
                self.context = parsed
                self.context_source = "encrypted-metadata"
                return
        self.warnings.append("未取到加密上下文 plist（口令解锁需要它）")

    def _load_family_uuid(self):
        if self.family_uuid:
            return self.family_uuid
        if isinstance(self.lv_plist, dict):
            raw = uuid_to_bytes(self.lv_plist.get("com.apple.corestorage.lv.familyUUID"))
            if raw:
                self.family_uuid = raw
        return self.family_uuid

    # ---------------- 对外：识别信息 ----------------
    def detect(self):
        """是否 CoreStorage / 是否加密 / 加密方法 / 密钥长度"""
        method = self.header["encryption_method"]
        descriptors = [d.to_dict() for d in self.descriptors]
        encrypted = bool(self.descriptors and any(d.encrypted for d in self.descriptors))
        if not descriptors:
            encrypted = method == 2 and self.header["key_data"] != b"\x00" * 16
        status = None
        if self.group_plist:
            status = self.group_plist.get("com.apple.corestorage.lv.encryption.type")
        return {
            "corestorage": True,
            "encrypted": encrypted,
            "encryption_method": method,
            "encryption_method_name": self.header["encryption_method_name"],
            "key_size": self.header["key_size"],
            "status": status,
            "signature": self.header["signature"],
            "version": self.header["version"],
            "block_type": self.header["block_type"],
            "bytes_per_sector": self.header["bytes_per_sector"],
            "block_size": self.block_size,
            "metadata_size": self.metadata_size,
            "volume_size": self.header["volume_size"],
            "pv_uuid": uuid_to_string(self.header["pv_uuid"]),
            "lvg_uuid": uuid_to_string(self.header["lvg_uuid"]),
            "descriptors": descriptors,
            "metadata_blocks": len(self.blocks),
            "has_context": self.context is not None,
            "unlock_source": self._unlock_source,
        }

    def headers(self):
        """物理卷头（正 / 尾）与全部元数据块头"""
        out = [dict(self.header)]
        if self.backup_header:
            out.append(dict(self.backup_header))
        for info in self.blocks:
            out.append(dict(info))
        return out

    def info(self):
        """完整取证信息（含 plist 摘要与用户条目）"""
        base = self.detect()
        group = self.group_plist or {}
        volume = self.lv_plist or {}
        base.update({
            "lvg_name": group.get("com.apple.corestorage.lvg.name"),
            "lvg_physical_volumes": group.get("com.apple.corestorage.lvg.physicalVolumes") or [],
            "label_sequence": group.get("com.apple.corestorage.label.sequence"),
            "lv_name": volume.get("com.apple.corestorage.lv.name"),
            "lv_size": volume.get("com.apple.corestorage.lv.size"),
            "lv_uuid": volume.get("com.apple.corestorage.lv.uuid"),
            "lv_family_uuid": volume.get("com.apple.corestorage.lv.familyUUID"),
            "lv_content_hint": volume.get("com.apple.corestorage.lv.contenthint"),
            "context_source": self.context_source,
            "users": self._users_summary(),
            "warnings": list(self.warnings),
        })
        if self.context:
            base["conversion_status"] = self.context.get("conversion_status")
            base["last_update_time"] = self.context.get("last_update_time")
            base["volume_key_count"] = len(self.context.get("volume_keys") or [])
        return base

    def _users_summary(self):
        out = []
        for user in (self.context or {}).get("users") or []:
            kek = user["kek"]
            out.append({
                "index": user["index"],
                "user_ident": user["user_ident"],
                "hint": user["hint"],
                "user_type": user["user_type"],
                "iterations": kek.get("iterations", 0),
                "salt": kek.get("salt", b"").hex(),
                "has_wrapped_kek": len(kek.get("wrapped_kek") or b"") == 24,
            })
        return out

    # ---------------- 解锁 ----------------
    def _derive_kek(self, passphrase, salt, iterations):
        derived = pbkdf2_sha256(passphrase, salt, iterations, 16)
        return derived

    def _candidate_passphrases(self, password, recovery_key):
        out = []
        if password is not None:
            if isinstance(password, bytes):
                out.append(("password", password))
            else:
                out.append(("password", str(password).encode("utf-8")))
        if recovery_key is not None:
            if isinstance(recovery_key, bytes):
                text = recovery_key.decode("ascii", "ignore")
            else:
                text = str(recovery_key)
            text = text.strip()
            variants = [text, text.upper(), text.replace("-", "").replace(" ", "").upper()]
            seen = set()
            for variant in variants:
                if variant and variant not in seen:
                    seen.add(variant)
                    out.append(("recovery_key", variant.encode("ascii", "ignore")))
        return out

    def unlock(self, password=None, recovery_key=None):
        """用口令 / 恢复密钥解出 VMK；成功返回 16 字节卷主密钥，失败返回 None"""
        if self.context is None:
            return None
        users = [u for u in (self.context.get("users") or [])
                 if u["kek"].get("valid") and u["kek"].get("wrapped_kek")]
        volume_keys = [v for v in (self.context.get("volume_keys") or [])
                       if v["wrapped_volume_key"]]
        if not users or not volume_keys:
            return None

        for label, passphrase in self._candidate_passphrases(password, recovery_key):
            for user in users:
                kek_info = user["kek"]
                iterations = kek_info.get("iterations") or 0
                if iterations <= 0:
                    continue
                try:
                    kek = self._derive_kek(passphrase, kek_info["salt"], iterations)
                except ValueError:
                    continue
                kek_plain = aes_kw_unwrap(kek, kek_info["wrapped_kek"])
                if kek_plain is None:
                    continue
                for volume_key in volume_keys:
                    vmk = aes_kw_unwrap(kek_plain, volume_key["wrapped_volume_key"])
                    if vmk is None:
                        continue
                    self._install_vmk(vmk)
                    self._unlock_source = "%s/user-%d" % (label, user["index"])
                    return vmk
        return None

    def _install_vmk(self, vmk):
        self.vmk = bytes(vmk)
        family_uuid = self._load_family_uuid()
        if not family_uuid:
            self.warnings.append(
                "缺少 lv.familyUUID：tweak 密钥无法计算，扇区解密不可用")
            self.tweak_key = None
            self.xts_key = None
            return
        self.tweak_key = hashlib.sha256(self.vmk + family_uuid).digest()[:16]
        self.xts_key = self.vmk + self.tweak_key

    def _require_keys(self):
        if not self.xts_key:
            raise ValueError("卷未解锁：请先 unlock(password=...) 或 "
                             "unlock(recovery_key=...)；有 VMK 但缺 familyUUID 时也无法解密")

    # ---------------- 卷解密 ----------------
    def decrypt_sector(self, sector, data):
        """解密一个 512 字节扇区（也接受 512 的整数倍）"""
        self._require_keys()
        if len(data) == 0 or len(data) % 16:
            raise ValueError("扇区数据长度必须是 16 的正整数倍，收到 %d" % len(data))
        return xts_decrypt(self.xts_key, sector_tweak(sector), data)

    def encrypt_sector(self, sector, data):
        """加密一个扇区（自检与写回用）"""
        self._require_keys()
        if len(data) == 0 or len(data) % 16:
            raise ValueError("扇区数据长度必须是 16 的正整数倍，收到 %d" % len(data))
        return xts_encrypt(self.xts_key, sector_tweak(sector), data)

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
            raw = self._read(pos, SECTOR_SIZE)
            if not raw:
                break                            # 镜像到此为止：少读就少给，不补零
            short = len(raw) < SECTOR_SIZE
            if short:
                raw = raw + b"\x00" * (-len(raw) % 16)
            out += self.decrypt_sector(pos // SECTOR_SIZE, raw)
            pos += SECTOR_SIZE
            if short:
                break
        begin = offset - first
        return bytes(out[begin:begin + size])

    def describe(self):
        info = self.info()
        return "%s  %s  pv=%s  用户=%d  上下文=%s  卷大小=%s" % (
            "CoreStorage",
            info["encryption_method_name"],
            info["pv_uuid"] or "-",
            len(info["users"]),
            self.context_source or "缺",
            info["volume_size"] or "-")


# --------------------------------------------------------------------------
# 模块级便捷函数
# --------------------------------------------------------------------------
def probe(sub):
    """快速判断是否为 CoreStorage 物理卷（只读 512 B，不校验 CRC）"""
    try:
        head = sub.read(0, PV_HEADER_SIZE)
    except Exception:
        return False
    if not head or len(head) < PV_HEADER_SIZE:
        return False
    return (_u16(head, 0x08) == 1
            and _u16(head, 0x0A) == BLOCK_TYPE_PV_HEADER
            and head[0x58:0x5A] == SIGNATURE)


def detect(sub):
    """返回 'CoreStorage' / 'CoreStorage(encrypted)' / None"""
    if not probe(sub):
        return None
    try:
        volume = FileVault2(sub)
    except (ValueError, struct.error):
        return "CoreStorage"
    info = volume.detect()
    return "CoreStorage(encrypted)" if info["encrypted"] else "CoreStorage"


def describe(sub):
    """一行摘要，适合批量扫描时打印"""
    if not probe(sub):
        return "非 CoreStorage"
    try:
        return FileVault2(sub).describe()
    except Exception as exc:                   # 识别到但解析失败：如实报告
        return "CoreStorage（解析失败: %s）" % exc


# --------------------------------------------------------------------------
# 自检：合成镜像 + 官方测试向量，验证原语 / 头解析 / 密钥链 / 扇区解密
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

    VMK = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    KEK = bytes.fromhex("0F0E0D0C0B0A09080706050403020100")
    PV_UUID = bytes.fromhex("11223344556677889900AABBCCDDEEFF")
    LVG_UUID = bytes.fromhex("FFEEDDCCBBAA00998877665544332211")
    FAMILY_UUID = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
    PASSWORD = "correct horse battery staple"
    ITERATIONS = 1024

    def _pv_header(block_numbers, block_size=0x2000, metadata_size=0x4000,
                   method=2, pv_uuid=PV_UUID):
        buf = bytearray(PV_HEADER_SIZE)
        struct.pack_into("<I", buf, 0x04, WEAK_CRC_INIT)
        struct.pack_into("<H", buf, 0x08, 1)
        struct.pack_into("<H", buf, 0x0A, BLOCK_TYPE_PV_HEADER)
        struct.pack_into("<I", buf, 0x0C, 0x12345678)
        struct.pack_into("<I", buf, 0x30, SECTOR_SIZE)
        struct.pack_into("<Q", buf, 0x40, 0x400000)
        buf[0x58:0x5A] = SIGNATURE
        struct.pack_into("<H", buf, 0x5A, 1)
        struct.pack_into("<H", buf, 0x5E, 4)
        struct.pack_into("<I", buf, 0x60, block_size)
        struct.pack_into("<I", buf, 0x64, metadata_size)
        for i, number in enumerate(block_numbers):
            struct.pack_into("<Q", buf, 0x68 + 8 * i, number)
        struct.pack_into("<I", buf, 0xA8, KEY_DATA_SIZE)
        struct.pack_into("<I", buf, 0xAC, method)
        buf[0xB0:0xB0 + 16] = bytes(range(16))
        buf[0x130:0x140] = pv_uuid
        buf[0x140:0x150] = LVG_UUID
        struct.pack_into("<I", buf, 0x00, crc32c(bytes(buf[8:PV_HEADER_SIZE])))
        return bytes(buf)

    def _block_header(block_type, object_id, block_number, block_size=0x2000,
                      flags=0):
        buf = bytearray(block_size)
        struct.pack_into("<I", buf, 0x04, WEAK_CRC_INIT)
        struct.pack_into("<H", buf, 0x08, 1)
        struct.pack_into("<H", buf, 0x0A, block_type)
        struct.pack_into("<I", buf, 0x0C, 0x12345678)
        struct.pack_into("<Q", buf, 0x10, 7)
        struct.pack_into("<Q", buf, 0x18, object_id)
        struct.pack_into("<Q", buf, 0x20, block_number)
        struct.pack_into("<Q", buf, 0x28, object_id)
        struct.pack_into("<I", buf, 0x30, block_size)
        struct.pack_into("<I", buf, 0x34, flags)
        return buf

    def _seal_block(buf, span=BLOCK_CHECKSUM_SPAN):
        struct.pack_into("<I", buf, 0x00, crc32c(bytes(buf[8:span])))

    def _kek_struct(passphrase, kek, salt, iterations):
        buf = bytearray(284)
        struct.pack_into("<I", buf, 0, 3)
        struct.pack_into("<I", buf, 4, 16)
        buf[8:24] = salt
        struct.pack_into("<I", buf, 24, 16)
        struct.pack_into("<I", buf, 28, 24)
        derived = pbkdf2_sha256(passphrase, salt, iterations, 16)
        buf[32:56] = aes_kw_wrap(derived, kek)
        struct.pack_into("<I", buf, 56, 8)
        struct.pack_into("<I", buf, 68, 1)
        struct.pack_into("<I", buf, 144, 1)
        struct.pack_into("<I", buf, 148, 3)
        struct.pack_into("<I", buf, 152, 10)
        struct.pack_into("<I", buf, 172, iterations)
        struct.pack_into("<I", buf, 176, 1)
        struct.pack_into("<I", buf, 180, 3)
        struct.pack_into("<I", buf, 184, 10)
        return bytes(buf)

    def _volume_key_struct(kek, vmk):
        buf = bytearray(256)
        struct.pack_into("<I", buf, 0, 2)
        struct.pack_into("<I", buf, 4, 24)
        buf[8:32] = aes_kw_wrap(kek, vmk)
        struct.pack_into("<I", buf, 32, 8)
        struct.pack_into("<I", buf, 44, 1)
        struct.pack_into("<I", buf, 52, 1)
        struct.pack_into("<I", buf, 56, 8)
        struct.pack_into("<I", buf, 68, 1)
        struct.pack_into("<I", buf, 144, 1)
        struct.pack_into("<I", buf, 148, 3)
        struct.pack_into("<I", buf, 152, 10)
        struct.pack_into("<I", buf, 252, 1)
        return bytes(buf)

    def build_image(passphrase=PASSWORD, iterations=ITERATIONS, vmk=VMK, kek=KEK,
                    block_size=0x2000, metadata_block=1, lv_block=2,
                    data_start_block=8):
        """合成一个带完整密钥链的 CoreStorage 物理卷"""
        salt = bytes(range(0xA0, 0xB0))
        context = {
            "ConversionInfo": {"ConversionStatus": "Complete", "TargetContext": 1},
            "CryptoUsers": [{
                "UserIdent": "11111111-2222-3333-4444-555555555555",
                "KeyEncryptingKeyIdent": "66666666-7777-8888-9999-AAAAAAAAAAAA",
                "UserType": 1,
                "PassphraseHint": "dummy hint",
                "PassphraseWrappedKEKStruct": _kek_struct(passphrase, kek, salt, iterations),
            }],
            "WrappedVolumeKeys": [{
                "BlockAlgorithm": "AES-XTS",
                "VolumeKeyIndex": 1,
                "KEKWrappedVolumeKeyStruct": _volume_key_struct(kek, vmk),
            }],
            "LastUpdateTime": 1323243315,
        }
        context_xml = plistlib.dumps(context)
        family_text = str(uuid.UUID(bytes=FAMILY_UUID)).upper()

        size = 0x200000
        image = bytearray(size)
        image[0:PV_HEADER_SIZE] = _pv_header([metadata_block], block_size,
                                             block_size * 2)
        # 卷尾副本
        image[size - PV_HEADER_SIZE:size] = _pv_header(
            [metadata_block], block_size, block_size * 2)

        # ---- 0x0011 卷组块 ----
        group_block = _block_header(BLOCK_TYPE_VOLUME_GROUP, 0x11,
                                    metadata_block, block_size)
        group_plist = {
            "com.apple.corestorage.label.sequence": 1,
            "com.apple.corestorage.lvg.uuid": str(uuid.UUID(bytes=LVG_UUID)).upper(),
            "com.apple.corestorage.lvg.name": "TestLVG",
            "com.apple.corestorage.pv.uuid": str(uuid.UUID(bytes=PV_UUID)).upper(),
            "com.apple.corestorage.lvg.physicalVolumes": [
                str(uuid.UUID(bytes=PV_UUID)).upper()],
        }
        group_xml = plistlib.dumps(group_plist)
        descriptor_offset = 0x100
        descriptor = bytearray(DESCRIPTOR_STRIDE)
        struct.pack_into("<Q", descriptor, 0, 1)                 # status = 加密
        struct.pack_into("<Q", descriptor, 8, 1)                 # 加密元数据块数
        primary = 4                                              # 加密元数据起始块号
        descriptor[32:38] = int(primary).to_bytes(6, "little")
        struct.pack_into("<H", descriptor, 38, 0)
        plist_offset = descriptor_offset + DESCRIPTOR_STRIDE
        plist_offset += (-plist_offset) % 16
        body = descriptor_offset + DESCRIPTOR_STRIDE + len(group_xml) + 16
        assert body < block_size, "卷组块放不下"
        data = bytearray(group_block)                 # 保留 64 B 块头
        struct.pack_into("<I", data, BLOCK_HEADER_SIZE + 156, descriptor_offset)
        struct.pack_into("<I", data, BLOCK_HEADER_SIZE + 160, plist_offset)
        struct.pack_into("<I", data, BLOCK_HEADER_SIZE + 164, len(group_xml))
        data[BLOCK_HEADER_SIZE + descriptor_offset:
             BLOCK_HEADER_SIZE + descriptor_offset + DESCRIPTOR_STRIDE] = descriptor
        data[BLOCK_HEADER_SIZE + plist_offset:
             BLOCK_HEADER_SIZE + plist_offset + len(group_xml)] = group_xml
        group_block = data
        _seal_block(group_block)
        group_offset = metadata_block * block_size
        image[group_offset:group_offset + block_size] = group_block

        # ---- 0x001a 逻辑卷块 ----
        lv_block_buf = _block_header(BLOCK_TYPE_LOGICAL_VOLUME, 0x1A,
                                     lv_block, block_size)
        lv_plist = {
            "com.apple.corestorage.lv.familyUUID": family_text,
            "com.apple.corestorage.lv.groupUUID": str(uuid.UUID(bytes=LVG_UUID)).upper(),
            "com.apple.corestorage.lv.name": "TestLV",
            "com.apple.corestorage.lv.size": size - data_start_block * block_size,
            "com.apple.corestorage.lv.uuid": "BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF",
            "com.apple.corestorage.lv.contenthint": "Apple_HFS",
            "com.apple.corestorage.lv.sequence": 3,
        }
        lv_xml = plistlib.dumps(lv_plist)
        lv_plist_offset = 0x100
        lv_data = bytearray(lv_block_buf)              # 保留 64 B 块头
        struct.pack_into("<I", lv_data, BLOCK_HEADER_SIZE + 64, lv_plist_offset)
        struct.pack_into("<I", lv_data, BLOCK_HEADER_SIZE + 68, len(lv_xml))
        lv_data[BLOCK_HEADER_SIZE + lv_plist_offset:
                BLOCK_HEADER_SIZE + lv_plist_offset + len(lv_xml)] = lv_xml
        lv_block_buf = lv_data
        _seal_block(lv_block_buf)
        lv_offset = lv_block * block_size
        image[lv_offset:lv_offset + block_size] = lv_block_buf

        # ---- 加密元数据：0x0019 块，XTS(PV UUID || 0^16) 加密 ----
        context_block = _block_header(BLOCK_TYPE_ENCRYPTION_CONTEXT, 0x19,
                                      primary, METADATA_XTS_UNIT)
        ctx_offset_in_block = 0x100
        ctx_data = bytearray(METADATA_XTS_UNIT)
        ctx_data[:] = context_block
        struct.pack_into("<I", ctx_data, 40, len(context_xml))
        struct.pack_into("<I", ctx_data, 44, len(context_xml))
        struct.pack_into("<I", ctx_data, 48, ctx_offset_in_block)
        struct.pack_into("<I", ctx_data, 52, len(context_xml))
        ctx_data[ctx_offset_in_block:ctx_offset_in_block + len(context_xml)] = context_xml
        _seal_block(ctx_data)
        meta_key = PV_UUID + b"\x00" * 16
        encrypted_meta = xts_encrypt(meta_key, sector_tweak(0), bytes(ctx_data))
        meta_offset = primary * block_size
        image[meta_offset:meta_offset + METADATA_XTS_UNIT] = encrypted_meta

        # ---- 明文数据扇区 ----
        tweak_key = hashlib.sha256(vmk + FAMILY_UUID).digest()[:16]
        xts_key = vmk + tweak_key
        plain_sector = (b"FILEVAULT2 SELF TEST 0123456789ABCDEF" * 16)[:SECTOR_SIZE]
        sector_number = (data_start_block * block_size) // SECTOR_SIZE
        for extra in range(4):
            number = sector_number + extra
            payload = bytes((plain_sector[i] ^ extra) for i in range(SECTOR_SIZE))
            cipher = xts_encrypt(xts_key, sector_tweak(number), payload)
            off = number * SECTOR_SIZE
            image[off:off + SECTOR_SIZE] = cipher
        return bytes(image), sector_number, plain_sector, xts_key

    print("FileVault 2 / CoreStorage 自检")

    # ---- 1. AES-KW：RFC 3394 官方向量 ----
    print("[1] AES-KW RFC 3394 官方向量")
    kw_kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    kw_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    kw_expect = bytes.fromhex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    assert aes_kw_wrap(kw_kek, kw_key) == kw_expect, "AES-KW 包装与 RFC 3394 向量不符"
    assert aes_kw_unwrap(kw_kek, kw_expect) == kw_key, "AES-KW 解包与 RFC 3394 向量不符"
    iv, raw_key = aes_kw_unwrap_raw(kw_kek, kw_expect)
    assert iv == b"\xA6" * 8, "解包出的 A 寄存器不是 0xA6×8：%s" % iv.hex()
    assert raw_key == kw_key
    # 另外三条 RFC 3394 官方向量：§4.1（256 位 KEK / 128 位数据）、
    # §4.3（256 位 KEK / 256 位数据）、§4.6（192 位 KEK / 128 位数据）
    for label, kek_hex, data_hex, expect_hex in (
            ("4.1", "000102030405060708090A0B0C0D0E0F"
                    "101112131415161718191A1B1C1D1E1F",
             "00112233445566778899AABBCCDDEEFF",
             "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
            ("4.3", "000102030405060708090A0B0C0D0E0F"
                    "101112131415161718191A1B1C1D1E1F",
             "00112233445566778899AABBCCDDEEFF0001020304050607",
             "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"),
            ("4.6", "000102030405060708090A0B0C0D0E0F1011121314151617",
             "00112233445566778899AABBCCDDEEFF",
             "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"),
    ):
        kek_bytes = bytes.fromhex(kek_hex)
        data_bytes = bytes.fromhex(data_hex)
        expect_bytes = bytes.fromhex(expect_hex)
        got = aes_kw_wrap(kek_bytes, data_bytes)
        assert got == expect_bytes, "RFC 3394 §%s 包装不符：%s" % (label, got.hex().upper())
        assert aes_kw_unwrap(kek_bytes, expect_bytes) == data_bytes, \
            "RFC 3394 §%s 解包不符" % label
    # 错 KEK 必须返回 None（不能给出乱码密钥）
    assert aes_kw_unwrap(bytes(16), kw_expect) is None
    print("  wrap/unwrap 双向一致；A 寄存器 = 0xA6×8；错 KEK -> None")

    # ---- 2. PBKDF2-HMAC-SHA256 ----
    print("[2] PBKDF2-HMAC-SHA256 已知向量")
    for count, expect in (
            (1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
            (2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
            (4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
    ):
        got = pbkdf2_sha256("password", "salt", count, 32).hex()
        assert got == expect, "PBKDF2 c=%d 不符：%s" % (count, got)
    print("  c=1 / 2 / 4096 三个向量全部命中")

    # ---- 3/4/5. 合成镜像：头解析 / CRC / 密钥链 ----
    print("[3] 合成 CoreStorage 镜像的识别与字段解析")
    image, sector_number, plain_sector, expect_xts_key = build_image()
    sub = MemSub(image)
    assert probe(sub), "probe() 未命中合成镜像"
    fv = FileVault2(sub)
    info = fv.detect()
    assert info["corestorage"] and info["encrypted"]
    assert info["encryption_method"] == 2
    assert info["encryption_method_name"] == "AES-XTS"
    assert info["key_size"] == 128
    assert info["block_size"] == 0x2000 and info["metadata_size"] == 0x4000
    assert info["descriptors"] and info["descriptors"][0]["status_name"] == "加密"
    assert info["metadata_blocks"] == 2, "应走通 2 个元数据块，实际 %d" % info["metadata_blocks"]
    assert fv.family_uuid == FAMILY_UUID, "familyUUID 解析不符"
    assert fv.context is not None and len(fv.context["users"]) == 1
    print("  方法=%s 密钥=%d 位 块大小=%d 描述符=%d 用户=%d 上下文=%s"
          % (info["encryption_method_name"], info["key_size"], info["block_size"],
             len(info["descriptors"]),
             len((fv.context or {}).get("users") or []), fv.context_source))

    print("[4] CRC-32C：正确时通过，改一字节失败")
    # 标准校验值（init 0xFFFFFFFF + 最终异或）= 0xE3069283；CoreStorage 是弱版
    assert crc32c(b"123456789") == 0x1CF96D7C, "CRC-32C 弱版校验值不符"
    assert (crc32c(b"123456789") ^ 0xFFFFFFFF) == 0xE3069283, "标准 CRC-32C 校验值不符"
    head = bytearray(image[0:PV_HEADER_SIZE])
    stored = struct.unpack_from("<I", head, 0)[0]
    assert crc32c(bytes(head[8:]), WEAK_CRC_INIT) == stored, "PV 头 CRC 应通过"
    head[0x30] ^= 0x01
    assert crc32c(bytes(head[8:]), WEAK_CRC_INIT) != stored, "改一字节后 CRC 应失败"
    assert not FileVault2(MemSub(bytes(head) + image[PV_HEADER_SIZE:])).header["checksum_ok"]
    block_off = 1 * 0x2000
    blk = bytearray(image[block_off:block_off + BLOCK_CHECKSUM_SPAN])
    blk_crc = struct.unpack_from("<I", blk, 0)[0]
    assert crc32c(bytes(blk[8:BLOCK_CHECKSUM_SPAN])) == blk_crc, "块头 CRC 应通过"
    blk[0x18] ^= 0x40
    assert crc32c(bytes(blk[8:BLOCK_CHECKSUM_SPAN])) != blk_crc, "块 CRC 改字节应失败"
    print("  PV 头 / 元数据块 CRC 均按 8..N 覆盖，篡改一字节即失败")

    print("[5] 完整密钥链：口令 -> KEK -> VMK")
    wrong = FileVault2(sub)
    assert wrong.unlock(password="wrong password") is None, "错口令应返回 None"
    assert wrong.unlock(recovery_key="AAAA-BBBB-CCCC-DDDD-EEEE-FFFF") is None
    assert wrong.xts_key is None
    vmk = fv.unlock(password=PASSWORD)
    assert vmk == VMK, "口令解出的 VMK 不符：%s" % (vmk.hex() if vmk else None)
    assert fv.tweak_key == hashlib.sha256(VMK + FAMILY_UUID).digest()[:16]
    assert fv.xts_key == expect_xts_key
    print("  unlock(口令) -> VMK %s；错口令 -> None" % vmk.hex())

    # 恢复密钥走同一条通路（把它当口令一样派生）
    image_rk, _, _, _ = build_image(passphrase="ABCD-EFGH-IJKL-MNOP-QRST-UVWX")
    fv_rk = FileVault2(MemSub(image_rk))
    assert fv_rk.unlock(recovery_key="abcd-efgh-ijkl-mnop-qrst-uvwx") == VMK, \
        "恢复密钥（大写变体）应能解锁"
    print("  恢复密钥（含大写归一）-> VMK 一致")

    # ---- 6. 非 CoreStorage / 截断 ----
    print("[6] 非 CoreStorage 与截断输入")
    assert not probe(MemSub(b"\x00" * 4096)), "全零数据不应被认成 CoreStorage"
    assert not probe(MemSub(b"MSWIN4.1" + b"\x00" * 1024))
    assert describe(MemSub(b"\x00" * 4096)) == "非 CoreStorage"
    try:
        FileVault2(MemSub(b"\x00" * 100))
    except ValueError as exc:
        print("  截断 100 B -> ValueError: %s" % str(exc)[:56])
    else:
        raise AssertionError("截断输入应抛 ValueError")
    try:
        FileVault2(MemSub(b"\x55" * 512))
    except ValueError as exc:
        print("  非 CS 512 B -> ValueError: %s" % str(exc)[:56])
    else:
        raise AssertionError("非 CoreStorage 应抛 ValueError")
    assert probe(MemSub(image[:200])) is False, "截断到 200 B 时 probe 应为 False"

    # ---- 7. 扇区往返 ----
    print("[7] decrypt_sector / read_decrypted 往返")
    # XTS 已知答案（IEEE 1619 语义；密文由 cryptography 的 modes.XTS 交叉验证过）
    kat_key = bytes(range(32))
    kat_tweak = sector_tweak(0x1234)
    kat_plain = bytes((i * 3 + 7) & 0xFF for i in range(SECTOR_SIZE))
    kat_cipher = xts_encrypt(kat_key, kat_tweak, kat_plain)
    assert hashlib.sha256(kat_cipher).hexdigest() == \
        "7c0214af84255df63ab1ded6ce384047418300338dfdebd0bbbf875937b3950e", \
        "XTS 已知答案不符"
    assert kat_cipher[:16].hex().upper() == "6BD6520FE32C2893D1FB412307F73D2F"
    assert kat_cipher[-16:].hex().upper() == "9E45974F819BDA67A91D53F15C33E93E"
    assert xts_decrypt(kat_key, kat_tweak, kat_cipher) == kat_plain
    print("  XTS 已知答案命中（sha256 7c0214af…）")
    for number in (0, 1, 7, sector_number, 0xFFFFFFFFFF):
        payload = bytes((i * 7 + 3) & 0xFF for i in range(SECTOR_SIZE))
        cipher = fv.encrypt_sector(number, payload)
        assert cipher != payload
        assert fv.decrypt_sector(number, cipher) == payload, "扇区 %d 往返失败" % number
    got = fv.read_decrypted(sector_number * SECTOR_SIZE, SECTOR_SIZE)
    assert got == plain_sector, "read_decrypted 解出的明文不符"
    straddle = fv.read_decrypted(sector_number * SECTOR_SIZE + 100, 200)
    assert straddle == plain_sector[100:300], "跨界读取不符"
    # XTS 数据单元独立性：同一扇区号不同内容互不影响
    assert fv.decrypt_sector(sector_number, fv.encrypt_sector(sector_number,
                                                             bytes(512))) == bytes(512)
    print("  扇区号 0 / 1 / 7 / 0x%X / 0xFFFFFFFFFF 往返一致；跨界读取一致" % sector_number)

    # 未解锁时解密必须明确报错
    locked = FileVault2(sub)
    try:
        locked.decrypt_sector(0, bytes(512))
    except ValueError as exc:
        print("  未解锁 -> ValueError: %s" % str(exc)[:48])
    else:
        raise AssertionError("未解锁时 decrypt_sector 应抛 ValueError")

    # 加密上下文也能从加密元数据块里取到（构造时已加密）
    fv2 = FileVault2(sub)
    assert fv2.context is not None
    print("  加密上下文来源：%s" % fv2.context_source)

    # ---- 8. 接口完整性 / 真实 plist 变体 ----
    print("[8] headers() / info() / describe() 与 plist 变体")
    heads = FileVault2(sub).headers()
    assert len(heads) >= 3, "应至少给出正/尾物理卷头 + 2 个元数据块头"
    assert heads[0]["checksum_ok"] and heads[0]["valid"]
    assert heads[1]["offset"] == len(image) - PV_HEADER_SIZE
    assert any(h.get("block_type") == BLOCK_TYPE_VOLUME_GROUP for h in heads)
    assert any(h.get("block_type") == BLOCK_TYPE_LOGICAL_VOLUME for h in heads)
    full = FileVault2(sub).info()
    assert full["lvg_name"] == "TestLVG"
    assert full["lv_name"] == "TestLV"
    assert full["lv_content_hint"] == "Apple_HFS"
    assert full["conversion_status"] == "Complete"
    assert full["users"][0]["iterations"] == ITERATIONS
    assert full["users"][0]["has_wrapped_kek"] is True
    assert full["encrypted"] is True and full["key_size"] == 128
    print("  头 %d 条 / 卷组=%s 逻辑卷=%s 用户迭代=%d"
          % (len(heads), full["lvg_name"], full["lv_name"], full["users"][0]["iterations"]))
    assert describe(sub).startswith("CoreStorage  AES-XTS")
    assert detect(sub) == "CoreStorage(encrypted)"
    assert detect(MemSub(b"\x00" * 4096)) is None
    print("  describe=%s" % describe(sub))

    # 真实加密上下文 plist 常常没有 XML 头（libfvde 文档明说），要能解析
    bare = plistlib.dumps({"CryptoUsers": [], "WrappedVolumeKeys": []})
    bare = bare.split(b"?>", 1)[1].split(b"<plist version=\"1.0\">", 1)[1].rsplit(b"</plist>", 1)[0]
    assert load_plist(bare) == {"CryptoUsers": [], "WrappedVolumeKeys": []}, "裸 <dict> 应能解析"
    assert load_plist(plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY)) == {"a": 1}
    assert load_plist(b"") is None and load_plist(b"not a plist") is None
    assert parse_encryption_context(b"\x00" * 64) is None
    print("  裸 <dict> / 二进制 plist / 垃圾数据 三种入参符合预期")

    print("\nFileVault 2 / CoreStorage 自检全部通过")
