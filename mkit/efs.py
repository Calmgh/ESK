#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  ESK  路  Calmgh06
#  Electronic Software Kit  |  EFS / "$EFS" 属性解析
# ============================================================

"""Windows EFS（Encrypting File System）``$EFS`` 属性解析。

输入边界
--------
本模块只接受 **已经是 ``$EFS`` 属性内容的那段字节**，即 NTFS 里类型
``0x100 LOGGED_UTILITY_STREAM``、名字为 ``$EFS`` 的流数据本身。
在 MFT / 属性列表里定位这个流 **不是本模块的职责**，那是
``mkit/ntfs.py`` 的事。所以调用方应当先取出属性内容再交给这里，
不要直接把整个文件或整个 MFT 记录传进来。

结构来源（逐条核对过）
----------------------
* ntfs-3g ``include/ntfs-3g/layout.h`` 里 ``$EFS Data Structure`` 注释段，
  定义了 ``EFS_ATTR_HEADER`` / ``EFS_DF_ARRAY_HEADER`` / ``EFS_DF_HEADER`` /
  ``EFS_DF_CREDENTIAL_HEADER`` / ``EFS_DF_CERTIFICATE_THUMBPRINT_HEADER``。
  **本文件的字段偏移全部以这份定义为准。**
* libfsntfs 文档 ``New Technologies File System (NTFS).asciidoc`` 只在属性
  类型表里列出 ``$EFS``，不含内部结构，参考价值仅限属性名与类型号 0x100。
* MS-EFSR 描述的是 ``\\pipe\\efsrpc`` 上的 RPC 接口（EfsRpcOpenFileRaw 等），
  不是磁盘上的属性格式，与本模块无关。

与任务书的差异（以 ntfs-3g 为准，如实记录）
-------------------------------------------
任务书写的头部 ``header_len / state / type / data_len`` 与真实结构不符。
``$EFS`` 头里 **没有** 独立的 ``type`` 与 ``data_len`` 字段，实际是：

    0x00 u32 length              整个 EFS 属性长度（字节）
    0x04 u32 state               状态位（ntfs-3g 注为 "Always 0?"）
    0x08 u32 version             EFS 版本（通常 2）
    0x0C u32 crypto_api_version  CryptoAPI 版本
    0x10 16B  file GUID          （UuidCreate 生成的文件 GUID）
    0x20 16B  ddf_digest         DDF 的 MD5（语义为推断）
    0x30 16B  drf_digest         DRF 的 MD5（语义为推断）
    0x40 u32 offset_to_ddf_array 0 = 无 DDF
    0x44 u32 offset_to_drf_array 0 = 无 DRF
    0x48 u32 reserved            合计 0x4C 字节

``info()`` 用真实字段名，同时保留 ``header_len`` 作为 ``length`` 的别名，
避免调用方按任务书写的字段名取不到值。

能力边界（重要，不夸大）
------------------------
能做到：
  * 识别 ``$EFS`` 属性（头部长度 / 版本 / 偏移一致性 + 数组可解析性）。
  * 枚举 DDF（数据解密字段）与 DRF（数据恢复字段），逐字段给出偏移与长度。
  * 从凭据里取二进制 SID（转成 ``S-1-5-21-...`` 字符串）、用户名、容器名、
    提供者名、证书指纹、公钥 blob 的长度 / 前 16 字节 / 算法 OID 前缀。
  * 取出被 RSA 加密的 FEK 原始字节。
  * 给定 **已解出的明文 FEK** 时，用 AES 解密文件数据
    （``decrypt_with_fek``，支持 CBC / ECB / CFB128）。
做不到（本模块明确不实现，绝不返回假数据）：
  * **解不出 FEK。** FEK 是用用户 X.509 证书公钥（RSA）加密的，没有对应
    私钥（PFX / 证书+私钥，或域 DPAPI 恢复代理私钥）就无法还原。
  * 不做 RSA 解密、不做私钥恢复、不做 DPAPI 主密钥、不做证书爆破。
  * ``decrypt_file()`` 直接抛 ``NotImplementedError``，不返回空 bytes
    假装成功。
  * 不解析 X.509 证书内部（只报长度与算法 OID 前缀）。
  * 不实现 NTFS ADS 定位（见上文「输入边界」）。

推断部分（返回值里都带 ``inferred`` / ``notes`` 标注）
------------------------------------------------------
1. ``EFS_KEY_INFO`` 前缀：真实 Windows SDK 里有 ``EFS_KEY_INFO``，但
   ntfs-3g 文档没有给出它相对 FEK 的精确位置。本模块按
   ``version / entropy_size / algid / key_size``（各 u32）猜测 FEK 开头
   16 字节，**只有在取值落在已知 CALG 集合内时才采用**，否则报 ``None``。
2. 字符串编码：按 UTF-16LE 读（EFS 的显示名/容器名是宽字符串），
   解不出可打印字符时回退单字节 UTF-8 / latin-1。
3. ``0x20`` / ``0x30`` 两段 16 字节是 DDF / DRF 摘要，仅沿用 ntfs-3g
   注释里 "MD5 hash of DDFs/DRFs?" 的猜测。

以上三条都有合成数据自检覆盖，但自检只证明解析自洽，
**不证明与真实 EFS 样本逐字节一致**。
"""

import hashlib
import struct

try:  # 包内导入
    from .aes import AES, cbc_decrypt, cbc_encrypt
except ImportError:  # 直接以脚本运行 mkit/efs.py
    import os as _os
    import sys as _sys

    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from mkit.aes import AES, cbc_decrypt, cbc_encrypt

__all__ = [
    "EfsError",
    "EfsAttribute",
    "is_efs_attribute",
    "describe",
    "decrypt_with_fek",
    "decrypt_file",
]


# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------
EFS_HEADER_SIZE = 0x4C      # EFS_ATTR_HEADER
DF_HEADER_SIZE = 0x14       # EFS_DF_HEADER
DF_ARRAY_HEADER_SIZE = 0x04  # EFS_DF_ARRAY_HEADER（只有 df_count）
CRED_HEADER_SIZE = 0x1C     # EFS_DF_CREDENTIAL_HEADER
THUMBPRINT_HEADER_SIZE = 0x14  # EFS_DF_CERTIFICATE_THUMBPRINT_HEADER

# ntfs.sys 会 BSOD 的长度：<= 0x54 或 > 0x40000 视为非法属性。
MIN_EFS_LENGTH = 0x54
MAX_EFS_LENGTH = 0x40000

MAX_DF_COUNT = 256          # 防御：字段数上限

CRED_TYPE_NAMES = {
    0: "unknown",
    1: "cryptoapi-container",
    2: "unexpected",
    3: "certificate-thumbprint",
}

# CALG_* 里 EFS 可能用到的对称算法 ID（用于判断 EFS_KEY_INFO 猜测是否可信）
KNOWN_ALGIDS = {
    0x00000000: "CALG_NONE",
    0x00006602: "CALG_3DES",
    0x00006603: "CALG_3DES_112",
    0x0000660E: "CALG_AES_128",
    0x0000660F: "CALG_AES_192",
    0x00006610: "CALG_AES_256",
    0x00006801: "CALG_RC4",
}

# 常见公钥算法 OID（只做字符串匹配，不解析证书语义）
KNOWN_OIDS = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.3.14.3.2.26": "sha1",
}


class EfsError(ValueError):
    """``$EFS`` 属性格式错误（长度/偏移越界、结构不自洽等）。"""


# --------------------------------------------------------------------------
# 基础读取
# --------------------------------------------------------------------------
def _u32(buf, off):
    if off < 0 or off + 4 > len(buf):
        raise EfsError("读取 u32 越界：偏移 0x%X，缓冲区 %d 字节" % (off, len(buf)))
    return struct.unpack_from("<I", buf, off)[0]


def _slice(buf, off, size, what="数据"):
    if off < 0 or size < 0 or off + size > len(buf):
        raise EfsError(
            "%s 越界：偏移 0x%X + 长度 0x%X，缓冲区 %d 字节"
            % (what, off, size, len(buf))
        )
    return bytes(buf[off:off + size])


def _sid_to_str(raw):
    """二进制 SID -> ``S-1-5-21-...``；格式不对返回 None。"""
    if not raw or len(raw) < 8:
        return None
    rev = raw[0]
    count = raw[1]
    if rev != 1:
        return None
    if len(raw) < 8 + 4 * count:
        return None
    auth = int.from_bytes(raw[2:8], "big")
    parts = ["S", str(rev), str(auth)]
    for i in range(count):
        parts.append(str(int.from_bytes(raw[8 + 4 * i:12 + 4 * i], "little")))
    return "-".join(parts)


def _read_string(buf, off, limit=None):
    """读 NUL 结尾字符串。

    EFS 里容器名 / 提供者名 / 用户名（lpDisplayInformation）是 UTF-16LE
    宽字符串，所以先按两字节步进扫 ``00 00`` 终止符并按 UTF-16LE 解码；
    解不出可打印字符时再回退单字节 UTF-8 / latin-1。
    编码判定属推断，见模块 docstring「推断部分」第 2 条。
    """
    n = len(buf) if limit is None else min(limit, len(buf))
    if off <= 0 or off >= n:
        return ""
    end = off
    while end + 1 < n and not (buf[end] == 0 and buf[end + 1] == 0):
        end += 2
    raw = bytes(buf[off:end])
    if raw:
        try:
            cand = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            cand = ""
        if cand and all(ch.isprintable() for ch in cand):
            return cand
    end = off
    while end < n and buf[end] != 0:
        end += 1
    raw = bytes(buf[off:end])
    for enc in ("utf-8", "latin-1"):
        try:
            s = raw.decode(enc).strip()
        except UnicodeDecodeError:
            continue
        if s and all(ch.isprintable() for ch in s):
            return s
    return ""


def _oid_to_str(body):
    """DER OBJECT IDENTIFIER 内容字节 -> 点分 OID 字符串。"""
    if not body:
        return None
    first = body[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    val = 0
    pending = False
    for byte in body[1:]:
        val = (val << 7) | (byte & 0x7F)
        pending = bool(byte & 0x80)
        if not pending:
            arcs.append(val)
            val = 0
    if pending:  # 截断的 OID
        return None
    return ".".join(str(a) for a in arcs)


def _der_prefix_oid(blob, max_scan=64):
    """在 DER 前缀里找第一个 OBJECT IDENTIFIER 并解出点分 OID。

    只做浅层 tag 扫描，不解析 X.509 语义（本模块刻意不碰证书内部）。
    """
    limit = min(len(blob), max_scan)
    i = 0
    while i + 1 < limit:
        if blob[i] == 0x06:
            ln = blob[i + 1]
            if 0 < ln < 0x80 and i + 2 + ln <= limit:
                oid = _oid_to_str(blob[i + 2:i + 2 + ln])
                if oid:
                    return oid
        i += 1
    return None


def _guess_key_info(fek_blob):
    """猜测 FEK 开头的 ``EFS_KEY_INFO``（version/entropy_size/algid/key_size）。

    推断项，见模块 docstring「推断部分」第 1 条。只有在 algid 落在已知
    CALG 集合、且各字段取值合理时才返回，否则返回 None。
    """
    if len(fek_blob) < 16:
        return None
    version, entropy_size, algid, key_size = struct.unpack_from("<IIII", fek_blob, 0)
    if version not in (0, 1, 2):
        return None
    if entropy_size > 0x100:
        return None
    if algid not in KNOWN_ALGIDS:
        return None
    return {
        "version": version,
        "entropy_size": entropy_size,
        "algid": algid,
        "algid_name": KNOWN_ALGIDS[algid],
        "key_size": key_size,
        "inferred": True,
    }


# --------------------------------------------------------------------------
# 主体
# --------------------------------------------------------------------------
class EfsAttribute:
    """一个 ``$EFS`` 属性（NTFS 0x100 命名流 ``$EFS``）的解析器。

    构造时严格校验头部，校验不过抛 :class:`EfsError`。
    解析结果全部缓存在实例上，重复调用不会重复解析。
    """

    def __init__(self, data):
        if isinstance(data, memoryview):
            data = data.tobytes()
        if not isinstance(data, (bytes, bytearray)):
            raise EfsError("需要 bytes/bytearray，收到 %r" % type(data).__name__)
        self.data = bytes(data)
        self.header = self._parse_header()
        self.ddfs = self._parse_df_array(self.header["offset_to_ddf_array"], "ddf")
        self.drfs = self._parse_df_array(self.header["offset_to_drf_array"], "drf")

    # -- 头部 --------------------------------------------------------------
    def _parse_header(self):
        buf = self.data
        if len(buf) < EFS_HEADER_SIZE:
            raise EfsError(
                "缓冲区只有 %d 字节，放不下 %d 字节的 $EFS 头"
                % (len(buf), EFS_HEADER_SIZE)
            )
        length, state, version, crypto_api_version = struct.unpack_from("<IIII", buf, 0)
        if length < MIN_EFS_LENGTH or length > MAX_EFS_LENGTH:
            raise EfsError(
                "$EFS 头 length=0x%X 越界（合法区间 0x%X..0x%X）"
                % (length, MIN_EFS_LENGTH, MAX_EFS_LENGTH)
            )
        if length > len(buf):
            raise EfsError(
                "$EFS 头 length=0x%X 超过缓冲区 %d 字节" % (length, len(buf))
            )
        if state > 0xFF:
            raise EfsError("$EFS 头 state=0x%X 不合理" % state)
        if version > 8:
            raise EfsError("$EFS 头 version=0x%X 不合理" % version)
        if crypto_api_version > 8:
            raise EfsError(
                "$EFS 头 crypto_api_version=0x%X 不合理" % crypto_api_version
            )
        ddf_off, drf_off, reserved = struct.unpack_from("<III", buf, 0x40)
        for name, off in (
            ("offset_to_ddf_array", ddf_off),
            ("offset_to_drf_array", drf_off),
        ):
            if off and not (EFS_HEADER_SIZE <= off < length):
                raise EfsError(
                    "$EFS 头 %s=0x%X 落在合法区间 [0x%X, 0x%X) 之外"
                    % (name, off, EFS_HEADER_SIZE, length)
                )
        return {
            "length": length,
            "header_len": length,  # 别名，兼容任务书里的字段名
            "state": state,
            "version": version,
            "crypto_api_version": crypto_api_version,
            "file_guid": self._guid(buf[0x10:0x20]),
            "ddf_digest": buf[0x20:0x30].hex(),
            "drf_digest": buf[0x30:0x40].hex(),
            "offset_to_ddf_array": ddf_off,
            "offset_to_drf_array": drf_off,
            "reserved": reserved,
        }

    @staticmethod
    def _guid(raw):
        if len(raw) != 16:
            return ""
        d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
        rest = raw[8:16]
        return "{%08X-%04X-%04X-%s-%s}" % (
            d1, d2, d3, rest[:2].hex().upper(), rest[2:].hex().upper()
        )

    # -- DDF / DRF 数组 ----------------------------------------------------
    def _parse_df_array(self, offset, kind):
        if not offset:
            return []
        buf = self.data
        limit = self.header["length"]
        if offset + DF_ARRAY_HEADER_SIZE > limit:
            raise EfsError(
                "%s 数组头偏移 0x%X 越界（属性长度 0x%X）" % (kind, offset, limit)
            )
        count = _u32(buf, offset)
        if count > MAX_DF_COUNT:
            raise EfsError("%s 数组字段数 %d 超过上限 %d" % (kind, count, MAX_DF_COUNT))
        out = []
        pos = offset + DF_ARRAY_HEADER_SIZE
        for i in range(count):
            if pos + DF_HEADER_SIZE > limit:
                raise EfsError(
                    "%s[%d] 偏移 0x%X 越界（属性长度 0x%X）" % (kind, i, pos, limit)
                )
            field = self._parse_df(pos, i, kind)
            out.append(field)
            pos += field["length"]
        return out

    def _parse_df(self, offset, index, kind):
        buf = self.data
        limit = self.header["length"]
        df_length, cred_offset, fek_size, fek_offset, unknown1 = struct.unpack_from(
            "<IIIII", buf, offset
        )
        if df_length < DF_HEADER_SIZE:
            raise EfsError(
                "%s[%d] df_length=0x%X 小于头部大小 0x%X"
                % (kind, index, df_length, DF_HEADER_SIZE)
            )
        if offset + df_length > limit:
            raise EfsError(
                "%s[%d] df_length=0x%X 超出属性长度 0x%X（起点 0x%X）"
                % (kind, index, df_length, limit, offset)
            )
        fek = b""
        fek_abs = 0
        if fek_size:
            fek_abs = offset + fek_offset
            if fek_offset < DF_HEADER_SIZE or fek_abs + fek_size > offset + df_length:
                raise EfsError(
                    "%s[%d] FEK 越界：偏移 0x%X + 长度 0x%X 超出字段长度 0x%X"
                    % (kind, index, fek_offset, fek_size, df_length)
                )
            fek = _slice(buf, fek_abs, fek_size, "加密 FEK")
        credential = None
        if cred_offset:
            if cred_offset < DF_HEADER_SIZE or offset + cred_offset >= offset + df_length:
                raise EfsError(
                    "%s[%d] cred_header_offset=0x%X 越界（字段长度 0x%X）"
                    % (kind, index, cred_offset, df_length)
                )
            credential = self._parse_credential(
                offset + cred_offset, offset + df_length, kind, index
            )
        return {
            "source": kind,
            "index": index,
            "offset": offset,
            "length": df_length,
            "cred_header_offset": cred_offset,
            "fek_size": fek_size,
            "fek_offset": fek_offset,
            "fek_abs_offset": fek_abs,
            "unknown1": unknown1,
            "encrypted_fek": fek,
            "credential": credential,
        }

    # -- 凭据 --------------------------------------------------------------
    def _parse_credential(self, base, limit, kind, index):
        buf = self.data
        if base + CRED_HEADER_SIZE > limit:
            raise EfsError(
                "%s[%d] 凭据头偏移 0x%X 越界（字段结束 0x%X）"
                % (kind, index, base, limit)
            )
        cred_length, sid_offset, cred_type = struct.unpack_from("<III", buf, base)
        if cred_length < CRED_HEADER_SIZE:
            raise EfsError(
                "%s[%d] cred_length=0x%X 小于头部大小 0x%X"
                % (kind, index, cred_length, CRED_HEADER_SIZE)
            )
        if base + cred_length > limit:
            raise EfsError(
                "%s[%d] cred_length=0x%X 超出所属字段（结束 0x%X）"
                % (kind, index, cred_length, limit)
            )
        sid = None
        if sid_offset:
            if sid_offset < CRED_HEADER_SIZE or sid_offset >= cred_length:
                raise EfsError(
                    "%s[%d] sid_offset=0x%X 越界（cred_length=0x%X）"
                    % (kind, index, sid_offset, cred_length)
                )
            sid = _sid_to_str(buf[base + sid_offset:base + cred_length])

        out = {
            "source": kind,
            "field_index": index,
            "type": cred_type,
            "type_name": CRED_TYPE_NAMES.get(cred_type, "unknown"),
            "cred_length": cred_length,
            "sid_offset": sid_offset,
            "sid": sid,
            "user_name": "",
            "container_name": "",
            "provider_name": "",
            "certificate": None,
            "public_key": None,
            "thumbprint": None,
        }

        if cred_type == 1:
            # CryptoAPI 容器
            cont_off, prov_off, pk_off, pk_size = struct.unpack_from(
                "<IIII", buf, base + 0x0C
            )
            out["container_name"] = _read_string(buf, base + cont_off if cont_off else 0, base + cred_length)
            out["provider_name"] = _read_string(buf, base + prov_off if prov_off else 0, base + cred_length)
            if pk_off and pk_size:
                if pk_off >= cred_length or pk_off + pk_size > cred_length:
                    raise EfsError(
                        "%s[%d] 公钥 blob 越界：偏移 0x%X + 长度 0x%X > cred_length 0x%X"
                        % (kind, index, pk_off, pk_size, cred_length)
                    )
                blob = _slice(buf, base + pk_off, pk_size, "公钥 blob")
                oid = _der_prefix_oid(blob)
                out["public_key"] = {
                    "length": pk_size,
                    "offset": pk_off,
                    "prefix_hex": blob[:16].hex(),
                    "algorithm_oid": oid,
                    "algorithm_name": KNOWN_OIDS.get(oid),
                    "sha1": hashlib.sha1(blob).hexdigest(),
                }
                out["certificate"] = out["public_key"]
        elif cred_type == 3:
            # 证书指纹
            tp_hdr_size, tp_hdr_off = struct.unpack_from("<II", buf, base + 0x0C)
            if tp_hdr_off:
                if tp_hdr_off < CRED_HEADER_SIZE or tp_hdr_off + THUMBPRINT_HEADER_SIZE > cred_length:
                    raise EfsError(
                        "%s[%d] 证书指纹头越界：偏移 0x%X（cred_length=0x%X）"
                        % (kind, index, tp_hdr_off, cred_length)
                    )
                tbase = base + tp_hdr_off
                t_off, t_size, tc_off, tp_off, tu_off = struct.unpack_from(
                    "<IIIII", buf, tbase
                )
                if t_size:
                    if t_off + t_size > cred_length:
                        raise EfsError(
                            "%s[%d] 证书指纹越界：偏移 0x%X + 长度 0x%X > cred_length 0x%X"
                            % (kind, index, t_off, t_size, cred_length)
                        )
                    thumb = _slice(buf, tbase + t_off, t_size, "证书指纹")
                    out["thumbprint"] = {
                        "length": t_size,
                        "offset": t_off,
                        "hex": thumb.hex(),
                    }
                out["thumbprint_header_size"] = tp_hdr_size
                out["thumbprint_header_offset"] = tp_hdr_off
                out["container_name"] = _read_string(
                    buf, tbase + tc_off if tc_off else 0, base + cred_length
                )
                out["provider_name"] = _read_string(
                    buf, tbase + tp_off if tp_off else 0, base + cred_length
                )
                out["user_name"] = _read_string(
                    buf, tbase + tu_off if tu_off else 0, base + cred_length
                )
        return out

    # -- 公开接口 ----------------------------------------------------------
    def info(self):
        """结构化摘要（只含头部与计数，不含大块字节）。"""
        h = dict(self.header)
        h["is_efs"] = True
        h["buffer_len"] = len(self.data)
        h["trailing_bytes"] = len(self.data) - self.header["length"]
        h["ddf_count"] = len(self.ddfs)
        h["drf_count"] = len(self.drfs)
        creds = self.credentials()
        h["credential_count"] = len(creds)
        h["user_sids"] = [c["sid"] for c in creds if c["sid"]]
        h["user_names"] = [c["user_name"] for c in creds if c["user_name"]]
        h["key_info_count"] = len(self.key_infos())
        h["notes"] = [
            "字段名以 ntfs-3g layout.h 的 EFS_ATTR_HEADER 为准；"
            "任务书里的 type/data_len 实为 version/crypto_api_version。",
            "file_guid 之外的 0x20/0x30 两段 16 字节语义（DDF/DRF 摘要）为推断。",
            "FEK 需要用户私钥才能解出，本模块不解 RSA。",
        ]
        return h

    def credentials(self):
        """DDF / DRF 里的凭据列表（每项含 SID、用户名、容器名、公钥 blob 摘要）。"""
        out = []
        for field in self.ddfs + self.drfs:
            if field["credential"] is not None:
                out.append(dict(field["credential"]))
        return out

    def recovery_fields(self):
        """DRF（数据恢复字段）列表。"""
        return [self._public_field(f) for f in self.drfs]

    def key_infos(self):
        """每个 DDF/DRF 的 FEK 信息（含加密后的 FEK 原始字节）。"""
        out = []
        for field in self.ddfs + self.drfs:
            fek = field["encrypted_fek"]
            guess = _guess_key_info(fek)
            out.append({
                "source": field["source"],
                "index": field["index"],
                "fek_size": field["fek_size"],
                "fek_offset": field["fek_offset"],
                "fek_abs_offset": field["fek_abs_offset"],
                "encrypted_fek": fek,
                "encrypted_fek_hex": fek.hex(),
                "encrypted_fek_len": len(fek),
                "key_info": guess,
                "inferred": guess is not None,
                "note": "FEK 由用户 X.509 公钥 RSA 加密，无私钥无法还原",
            })
        return out

    @staticmethod
    def _public_field(field):
        out = dict(field)
        out.pop("encrypted_fek", None)
        if out.get("credential"):
            out["credential"] = dict(out["credential"])
        return out

    def __repr__(self):
        return "<EfsAttribute len=%d ddf=%d drf=%d creds=%d>" % (
            self.header["length"],
            len(self.ddfs),
            len(self.drfs),
            len(self.credentials()),
        )


# --------------------------------------------------------------------------
# 模块级函数
# --------------------------------------------------------------------------
def is_efs_attribute(data):
    """判断一段字节是否是合法的 ``$EFS`` 属性内容。

    判定依据：头部 length/state/version 合理性 + DDF/DRF 偏移可解析，
    并要求至少两个正向信号（数组可解析 / 长度吻合 / state+version 正常）。
    """
    try:
        attr = EfsAttribute(data)
    except Exception:
        return False
    score = 0
    if attr.header["offset_to_ddf_array"]:
        if not attr.ddfs:
            return False
        score += 2
    if attr.header["offset_to_drf_array"]:
        if not attr.drfs:
            return False
        score += 2
    if attr.header["length"] == len(attr.data):
        score += 1
    if attr.header["version"] in (1, 2) and attr.header["state"] in (0, 1):
        score += 1
    return score >= 2


def describe(data):
    """容错版摘要：不是 ``$EFS`` 时返回 ``{"is_efs": False, ...}``，不抛异常。"""
    try:
        attr = EfsAttribute(data)
    except Exception as exc:
        size = None
        try:
            size = len(data)
        except TypeError:
            pass
        return {"is_efs": False, "error": str(exc), "buffer_len": size}
    out = attr.info()
    out["credentials"] = attr.credentials()
    out["recovery_fields"] = attr.recovery_fields()
    out["key_infos"] = [
        {k: v for k, v in ki.items() if k != "encrypted_fek"}
        for ki in attr.key_infos()
    ]
    return out


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _cfb128_decrypt(key, iv, data):
    cipher = AES(key)
    out = bytearray(len(data))
    prev = bytes(iv)
    for off in range(0, len(data), 16):
        blk = data[off:off + 16]
        keystream = cipher.encrypt_block(prev)
        out[off:off + len(blk)] = _xor(blk, keystream[:len(blk)])
        prev = blk + prev[len(blk):] if len(blk) < 16 else blk
    return bytes(out)


def _strip_pkcs7(data):
    if not data:
        return data
    pad = data[-1]
    if 0 < pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def decrypt_with_fek(fek, data, algorithm="aes-cbc", iv=None, unpad=False):
    """用 **已解出的明文 FEK** 解文件数据。

    参数
    ----
    fek : bytes
        16 / 24 / 32 字节的 AES 密钥（明文 FEK，来自用户私钥解密后的结果）。
    data : bytes
        密文。``aes-cbc`` / ``aes-cfb`` 且未给 ``iv`` 时，把前 16 字节当 IV。
    algorithm : str
        ``"aes-cbc"`` / ``"aes-ecb"`` / ``"aes-cfb"``（CFB128）。
    iv : bytes | None
        显式 IV，给了就不再从 ``data`` 头部切。
    unpad : bool
        是否剥离 PKCS#7 填充。

    说明
    ----
    EFS 在文件数据层面用什么组合（CBC 的 IV 是否前置、是否带填充）没有在
    ntfs-3g 文档里确认，所以这里把 IV 与填充都做成显式参数，不做猜测。
    """
    if not isinstance(fek, (bytes, bytearray)):
        raise EfsError("fek 需要 bytes/bytearray")
    fek = bytes(fek)
    if len(fek) not in (16, 24, 32):
        raise EfsError("FEK 长度 %d 字节不合法（只支持 16/24/32）" % len(fek))
    if not isinstance(data, (bytes, bytearray)):
        raise EfsError("data 需要 bytes/bytearray")
    data = bytes(data)
    alg = (algorithm or "").strip().lower().replace("_", "-").replace(" ", "")

    if alg in ("aes-cbc", "aes-cfb", "aes-cfb128", "cbc", "cfb"):
        if iv is None:
            if len(data) < 16:
                raise EfsError("密文不足 16 字节，无法从中取 IV")
            iv = data[:16]
            data = data[16:]
        iv = bytes(iv)
        if len(iv) != 16:
            raise EfsError("IV 必须是 16 字节")
        if len(data) % 16:
            raise EfsError("密文长度 %d 不是 16 的倍数" % len(data))
        if alg in ("aes-cbc", "cbc"):
            out = cbc_decrypt(fek, iv, data)
        else:
            out = _cfb128_decrypt(fek, iv, data)
    elif alg in ("aes-ecb", "ecb"):
        if len(data) % 16:
            raise EfsError("密文长度 %d 不是 16 的倍数" % len(data))
        cipher = AES(fek)
        out = b"".join(cipher.decrypt_block(data[o:o + 16]) for o in range(0, len(data), 16))
    else:
        raise EfsError("不支持的算法 %r（支持 aes-cbc / aes-ecb / aes-cfb）" % algorithm)

    return _strip_pkcs7(out) if unpad else out


def decrypt_file(*args, **kwargs):
    """**不实现。** EFS 的 FEK 用用户公钥加密，没有私钥就解不出。"""
    raise NotImplementedError(
        "decrypt_file() 未实现：需要用户私钥/PFX 才能解出 FEK"
        "（EFS 用用户 X.509 公钥 RSA 加密 FEK，没有私钥或域恢复代理私钥就"
        "无法还原）；本模块只做 $EFS 属性解析。拿到明文 FEK 后请调用 "
        "decrypt_with_fek(fek, data, algorithm)。"
    )


# --------------------------------------------------------------------------
# 自检（全部合成数据）
# --------------------------------------------------------------------------
def _sid_bytes(subs, authority=5, revision=1):
    raw = bytes([revision, len(subs)]) + int(authority).to_bytes(6, "big")
    for s in subs:
        raw += int(s).to_bytes(4, "little")
    return raw


def _wide(text):
    return text.encode("utf-16-le") + b"\x00\x00"


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag, payload):
    return bytes([tag]) + _der_len(len(payload)) + payload


def _fake_cert():
    """合成一个 DER 结构，前缀是 rsaEncryption 的 AlgorithmIdentifier。"""
    oid = bytes.fromhex("06092A864886F70D010101")
    alg_id = _der(0x30, oid + b"\x05\x00")
    bit_string = _der(0x03, b"\x00" + bytes(range(64)))
    return _der(0x30, _der(0x30, alg_id + bit_string))


def _build_cred_type3(sid_raw, user, thumb, container, provider):
    """凭据类型 3（证书指纹）。返回 (cred_bytes, 参考字段)。"""
    off_thumb = CRED_HEADER_SIZE + THUMBPRINT_HEADER_SIZE
    off_cont = off_thumb + len(thumb)
    off_prov = off_cont + len(container)
    off_user = off_prov + len(provider)
    off_sid = off_user + len(user)
    total = off_sid + len(sid_raw)

    t_off = THUMBPRINT_HEADER_SIZE
    t_cont = t_off + len(thumb)
    t_prov = t_cont + len(container)
    t_user = t_prov + len(provider)
    thumb_hdr = struct.pack("<IIIII", t_off, len(thumb), t_cont, t_prov, t_user)

    cred_hdr = struct.pack(
        "<IIIIIII",
        total,            # cred_length
        off_sid,          # sid_offset
        3,                # type = certificate thumbprint
        THUMBPRINT_HEADER_SIZE,  # cert_thumbprint_header_size
        CRED_HEADER_SIZE,        # cert_thumbprint_header_offset
        0,                # unknown1
        0,                # unknown2
    )
    body = cred_hdr + thumb_hdr + thumb + container + provider + user + sid_raw
    assert len(body) == total, (len(body), total)
    return body


def _build_cred_type1(sid_raw, container, provider, pubkey):
    """凭据类型 1（CryptoAPI 容器）。返回 cred_bytes。"""
    off_cont = CRED_HEADER_SIZE
    off_prov = off_cont + len(container)
    off_pk = off_prov + len(provider)
    off_sid = off_pk + len(pubkey)
    total = off_sid + len(sid_raw)
    cred_hdr = struct.pack(
        "<IIIIIII",
        total,            # cred_length
        off_sid,          # sid_offset
        1,                # type = CryptoAPI container
        off_cont,         # container_name_offset
        off_prov,         # provider_name_offset
        off_pk,           # public_key_blob_offset
        len(pubkey),      # public_key_blob_size
    )
    body = cred_hdr + container + provider + pubkey + sid_raw
    assert len(body) == total, (len(body), total)
    return body


def _build_df(cred_bytes, fek_blob):
    """EFS_DF_HEADER + 凭据 + 加密 FEK。"""
    cred_off = DF_HEADER_SIZE
    fek_off = cred_off + len(cred_bytes)
    df_len = fek_off + len(fek_blob)
    head = struct.pack("<IIIII", df_len, cred_off, len(fek_blob), fek_off, 0)
    return head + cred_bytes + fek_blob


def _build_efs(dfs, state=0, version=2, capi=1, drfs=None, guid=b"\xAA" * 16):
    """组装完整 ``$EFS`` 属性；返回 (bytes, 参考字典)。"""
    ddf_off = EFS_HEADER_SIZE
    ddf_array = struct.pack("<I", len(dfs)) + b"".join(dfs)
    body = ddf_array
    drf_off = 0
    if drfs:
        drf_off = EFS_HEADER_SIZE + len(ddf_array)
        body += struct.pack("<I", len(drfs)) + b"".join(drfs)
    total = EFS_HEADER_SIZE + len(body)
    head = struct.pack("<IIII", total, state, version, capi)
    head += guid
    head += bytes(range(16))       # ddf_digest 占位
    head += bytes(range(16, 32))   # drf_digest 占位
    head += struct.pack("<III", ddf_off, drf_off, 0)
    assert len(head) == EFS_HEADER_SIZE, len(head)
    return head + body


def _sample():
    """构造固定样本：2 个 DDF 凭据（类型 3 中文用户名 + 类型 1 公钥）。"""
    sid3 = _sid_bytes([21, 1111111111, 2222222222, 3333333333, 1001])
    cred3 = _build_cred_type3(
        sid3,
        _wide("CORP\\张三"),
        b"\x11" * 20,
        _wide("EFS-Container-A"),
        _wide("Microsoft Enhanced RSA and AES Cryptographic Provider"),
    )
    cert = _fake_cert()
    sid1 = _sid_bytes([21, 1111111111, 2222222222, 3333333333, 1002])
    cred1 = _build_cred_type1(
        sid1,
        _wide("EFS-Container-B"),
        _wide("Microsoft Software Key Storage Provider"),
        cert,
    )
    fek3 = struct.pack("<IIII", 1, 0, 0x6610, 256) + b"\x5A" * 128
    fek1 = struct.pack("<IIII", 1, 0, 0x660E, 128) + b"\x5B" * 128
    df3 = _build_df(cred3, fek3)
    df1 = _build_df(cred1, fek1)
    return _build_efs([df3, df1]), {
        "sid3": "S-1-5-21-1111111111-2222222222-3333333333-1001",
        "sid1": "S-1-5-21-1111111111-2222222222-3333333333-1002",
        "user3": "CORP\\张三",
        "cert_len": len(cert),
        "fek3_len": len(fek3),
        "df3_len": len(df3),
    }


def self_test():
    import os
    import random

    passed = []
    failed = []

    def check(name, cond, extra=""):
        if cond:
            passed.append(name)
            print("  [OK]   %s%s" % (name, (" | " + extra) if extra else ""))
        else:
            failed.append(name)
            print("  [FAIL] %s%s" % (name, (" | " + extra) if extra else ""))

    raw, ref = _sample()

    print("[1] 合法 $EFS 属性识别")
    check("is_efs_attribute(合成样本)", is_efs_attribute(raw), "len=%d" % len(raw))
    attr = EfsAttribute(raw)
    check("EfsAttribute 可构造", attr is not None)

    print("[2] 随机 / 全零 / 过短 必须为 False")
    check("全零 512B", is_efs_attribute(b"\x00" * 512) is False)
    check("空字节串", is_efs_attribute(b"") is False)
    check("4 字节", is_efs_attribute(b"\x01\x02\x03\x04") is False)
    rnd_bad = 0
    for _ in range(200):
        blob = bytes(random.randrange(256) for _ in range(random.choice((64, 200, 1024))))
        if is_efs_attribute(blob):
            rnd_bad += 1
    check("200 组随机数据无假阳性", rnd_bad == 0, "假阳性=%d" % rnd_bad)

    print("[3] info() 字段与预置值一致；凭据 SID / 中文用户名")
    info = attr.info()
    check("length == 缓冲区长度", info["length"] == len(raw))
    check("header_len 别名", info["header_len"] == info["length"])
    check("state=0", info["state"] == 0)
    check("version=2", info["version"] == 2)
    check("crypto_api_version=1", info["crypto_api_version"] == 1)
    check("offset_to_ddf_array=0x4C", info["offset_to_ddf_array"] == EFS_HEADER_SIZE)
    check("ddf_count=2", info["ddf_count"] == 2, str(info["ddf_count"]))
    check("drf_count=0", info["drf_count"] == 0)
    check("credential_count=2", info["credential_count"] == 2)
    check("trailing_bytes=0", info["trailing_bytes"] == 0)

    print("[4] 凭据解析（2 条）")
    creds = attr.credentials()
    check("credentials() 返回 2 条", len(creds) == 2, str(len(creds)))
    check("第 1 条 type=3", creds[0]["type"] == 3 and creds[0]["type_name"] == "certificate-thumbprint")
    check("第 1 条 SID", creds[0]["sid"] == ref["sid3"], str(creds[0]["sid"]))
    check("第 1 条中文用户名", creds[0]["user_name"] == ref["user3"], repr(creds[0]["user_name"]))
    check("第 1 条容器名", creds[0]["container_name"] == "EFS-Container-A")
    check("第 2 条 type=1", creds[1]["type"] == 1 and creds[1]["type_name"] == "cryptoapi-container")
    check("第 2 条 SID", creds[1]["sid"] == ref["sid1"], str(creds[1]["sid"]))
    check("第 2 条提供者名", creds[1]["provider_name"] == "Microsoft Software Key Storage Provider")
    pk = creds[1]["public_key"]
    check("公钥 blob 长度", pk and pk["length"] == ref["cert_len"], str(pk and pk["length"]))
    check("公钥算法 OID", pk and pk["algorithm_oid"] == "1.2.840.113549.1.1.1", str(pk and pk["algorithm_oid"]))
    check("公钥算法名", pk and pk["algorithm_name"] == "rsaEncryption")
    check("证书指纹长度 20", creds[0]["thumbprint"]["length"] == 20)

    print("[5] key_infos()")
    kis = attr.key_infos()
    check("key_infos 2 条", len(kis) == 2)
    check("第 1 条 fek_size", kis[0]["fek_size"] == ref["fek3_len"], str(kis[0]["fek_size"]))
    check("第 1 条加密 FEK 字节可取出", len(kis[0]["encrypted_fek"]) == ref["fek3_len"])
    check("第 1 条 EFS_KEY_INFO 猜测", kis[0]["key_info"] and kis[0]["key_info"]["algid"] == 0x6610)
    check("推断标记为 True", kis[0]["inferred"] is True)

    print("[6] recovery_fields()")
    check("无 DRF 时为空列表", attr.recovery_fields() == [])

    print("[7] 篡改 header_len -> EfsError")
    bad = bytearray(raw)
    struct.pack_into("<I", bad, 0, len(raw) + 0x1000)
    try:
        EfsAttribute(bytes(bad))
        check("篡改 length 抛 EfsError", False, "未抛异常")
    except EfsError as exc:
        check("篡改 length 抛 EfsError", True, str(exc)[:56])
    except Exception as exc:
        check("篡改 length 抛 EfsError", False, "抛了 %s" % type(exc).__name__)
    check("篡改后 is_efs_attribute=False", is_efs_attribute(bytes(bad)) is False)

    bad2 = bytearray(raw)
    struct.pack_into("<I", bad2, 0x40, 0x7FFFFFF0)  # offset_to_ddf_array 越界
    try:
        EfsAttribute(bytes(bad2))
        check("篡改 DDF 偏移抛 EfsError", False, "未抛异常")
    except EfsError:
        check("篡改 DDF 偏移抛 EfsError", True)

    bad3 = bytearray(raw)
    struct.pack_into("<I", bad3, 0x04, 0xFFFFFFFF)  # state 不合理
    try:
        EfsAttribute(bytes(bad3))
        check("篡改 state 抛 EfsError", False, "未抛异常")
    except EfsError:
        check("篡改 state 抛 EfsError", True)

    print("[8] 尾部填充容忍 / describe()")
    padded = raw + b"\x00" * 8
    check("尾部 8 字节填充仍可解析", EfsAttribute(padded).info()["trailing_bytes"] == 8)
    d_bad = describe(b"\x00" * 64)
    check("describe(垃圾) is_efs=False", d_bad["is_efs"] is False and "error" in d_bad)
    d_ok = describe(raw)
    check("describe(样本) is_efs=True", d_ok["is_efs"] is True)
    check("describe 含 2 条凭据", len(d_ok["credentials"]) == 2)

    print("[9] decrypt_file 必须抛 NotImplementedError")
    try:
        decrypt_file(b"\x00" * 32, b"\x00" * 64)
        check("decrypt_file 抛 NotImplementedError", False, "未抛异常")
    except NotImplementedError as exc:
        check("decrypt_file 抛 NotImplementedError", True, str(exc)[:40] + "...")
    except Exception as exc:
        check("decrypt_file 抛 NotImplementedError", False, "抛了 %s" % type(exc).__name__)

    print("[10] decrypt_with_fek 往返")
    key = bytes(range(32))
    iv = bytes(range(16, 32))
    plain = b"ESK self-test payload 0123456789abcdef" * 3
    pad = 16 - (len(plain) % 16)
    pt = plain + bytes([pad]) * pad
    ct = cbc_encrypt(key, iv, pt)
    check("AES-CBC 往返（IV 显式）", decrypt_with_fek(key, ct, "aes-cbc", iv=iv) == pt)
    check("AES-CBC 往返（IV 前置）", decrypt_with_fek(key, iv + ct) == pt)
    check("AES-CBC + PKCS#7 去填充", decrypt_with_fek(key, ct, iv=iv, unpad=True) == plain)

    cipher = AES(key)
    ecb = b"".join(cipher.encrypt_block(pt[o:o + 16]) for o in range(0, len(pt), 16))
    check("AES-ECB 往返", decrypt_with_fek(key, ecb, "aes-ecb") == pt)

    # CFB128：用同一反馈逻辑自造密文
    cfb_ct = bytearray()
    prev = iv
    for o in range(0, len(pt), 16):
        blk = pt[o:o + 16]
        ks = cipher.encrypt_block(prev)
        enc = _xor(blk, ks)
        cfb_ct += enc
        prev = enc
    check("AES-CFB128 往返", decrypt_with_fek(key, iv + bytes(cfb_ct), "aes-cfb") == pt)

    try:
        decrypt_with_fek(b"\x00" * 7, pt)
        check("非法 FEK 长度抛 EfsError", False, "未抛异常")
    except EfsError:
        check("非法 FEK 长度抛 EfsError", True)
    try:
        decrypt_with_fek(key, pt, "aes-xts")
        check("未知算法抛 EfsError", False, "未抛异常")
    except EfsError:
        check("未知算法抛 EfsError", True)

    print("[11] 单凭据 / DRF 变体")
    one = _build_efs([_build_df(cred3_only(), struct.pack("<IIII", 1, 0, 0x6610, 256) + b"\x5A" * 128)])
    check("单凭据 is_efs=True", is_efs_attribute(one))
    check("单凭据 credentials=1", len(EfsAttribute(one).credentials()) == 1)

    drf = _build_df(cred3_only(), struct.pack("<IIII", 1, 0, 0x6610, 256) + b"\x5C" * 128)
    with_drf = _build_efs(
        [_build_df(cred3_only(), struct.pack("<IIII", 1, 0, 0x6610, 256) + b"\x5A" * 128)],
        drfs=[drf],
    )
    a2 = EfsAttribute(with_drf)
    check("DRF 计数=1", a2.info()["drf_count"] == 1)
    check("recovery_fields 1 条", len(a2.recovery_fields()) == 1)
    check("DRF 凭据可读", a2.recovery_fields()[0]["credential"]["sid"] == ref["sid3"])

    total = len(passed) + len(failed)
    print("\n自检结果：%d/%d 通过，%d 失败" % (len(passed), total, len(failed)))
    if failed:
        print("失败项：")
        for name in failed:
            print("  - " + name)
    return len(failed) == 0


def cred3_only():
    """自检辅助：只构造一个类型 3 凭据（SID + 中文用户名）。"""
    sid = _sid_bytes([21, 1111111111, 2222222222, 3333333333, 1001])
    return _build_cred_type3(
        sid,
        _wide("CORP\\张三"),
        b"\x11" * 20,
        _wide("EFS-Container-A"),
        _wide("Microsoft Enhanced RSA and AES Cryptographic Provider"),
    )


if __name__ == "__main__":
    import sys

    print("mkit.efs 自检（全部合成数据）")
    print("=" * 60)
    sys.exit(0 if self_test() else 1)
