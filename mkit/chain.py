# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""chain.py —— 区块链 / 虚拟货币取证解析（纯标准库，自研实现）

覆盖范围
    * Keccak-f[1600] / keccak256（以太坊原始 Keccak，0x01 域填充，非 SHA3）
    * secp256k1：点加/点倍/标量乘、公钥恢复、ECDSA 签名(RFC6979)/验签
    * Base58 / Base58Check / Bech32 / Bech32m（BIP173 / BIP350）
    * RLP 编解码
    * 以太坊交易解析：Legacy / EIP-2930(type 1) / EIP-1559(type 2)，含 EIP-155 chainId 与 from 恢复
    * 比特币交易 / 区块解析，脚本地址解析 p2pkh / p2sh / p2wpkh / p2wsh / p2tr / p2pk
    * 任意文本地址提取（BTC / EVM / TRON / USDT 合约），带 EIP-55、Base58Check、Bech32 校验
    * DeFi 事件解码：ERC20/721 Transfer、Uniswap V2 Swap、Uniswap V3 Swap、Approval、Sync、WETH

所有算法均在本文件内实现，不依赖 eth / web3 / bitcoinlib / coincurve / hashlib.sha3。
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from decimal import Decimal

__all__ = [
    "keccak256", "keccak256_hex",
    "SECP256K1_N", "SECP256K1_P", "SECP256K1_G",
    "point_mul", "point_add", "pubkey_from_privkey", "pubkey_decompress",
    "ecdsa_sign", "ecdsa_verify", "ecdsa_recover",
    "eth_address_from_privkey", "eth_address_from_pubkey", "eip55_checksum",
    "base58_encode", "base58_decode", "base58check_encode", "base58check_decode",
    "bech32_encode", "bech32_decode", "convertbits",
    "encode_segwit_address", "decode_segwit_address",
    "rlp_encode", "rlp_decode",
    "parse_eth_tx", "eth_tx_hash",
    "parse_bitcoin_tx", "parse_block", "script_to_address", "hash160",
    "scan_addresses", "defi_swap_decode", "token_transfers_from_receipts",
    "decode_calldata", "token_amount",
    "EVENT_TOPICS", "KNOWN_CONTRACTS",
]

# ---------------------------------------------------------------------------
# 字节 / 十六进制小工具
# ---------------------------------------------------------------------------


def _as_bytes(v):
    """接受 bytes / bytearray / memoryview / '0x..' / 纯 hex 字符串。"""
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, str):
        s = v.strip()
        if s[:2].lower() == "0x":
            s = s[2:]
        s = "".join(s.split())
        if len(s) % 2:
            s = "0" + s
        return bytes.fromhex(s)
    raise TypeError("cannot convert %r to bytes" % (type(v),))


def _as_int(v, default=0):
    """RLP 解码结果是 bytes，这里统一转整数。"""
    if v is None:
        return default
    if isinstance(v, int):
        return v
    b = _as_bytes(v) if not isinstance(v, (bytes, bytearray)) else bytes(v)
    return int.from_bytes(b, "big") if b else 0


def _int_to_bytes(v):
    if v == 0:
        return b""
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


# ---------------------------------------------------------------------------
# Keccak-f[1600] / keccak256（以太坊原始 padding 0x01 .. 0x80）
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

# rho 旋转偏移，索引 [x][y]
_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rol64(v, n):
    n &= 63
    if n == 0:
        return v & _MASK64
    return ((v << n) | (v >> (64 - n))) & _MASK64


def _keccak_f1600(a):
    """就地置换 25 个 64 位 lane，a[x + 5*y]。"""
    for rnd in range(24):
        # theta
        c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]
        c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]
        c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]
        c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]
        c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]
        d0 = c4 ^ _rol64(c1, 1)
        d1 = c0 ^ _rol64(c2, 1)
        d2 = c1 ^ _rol64(c3, 1)
        d3 = c2 ^ _rol64(c4, 1)
        d4 = c3 ^ _rol64(c0, 1)
        for y in (0, 5, 10, 15, 20):
            a[y] ^= d0
            a[y + 1] ^= d1
            a[y + 2] ^= d2
            a[y + 3] ^= d3
            a[y + 4] ^= d4
        # rho + pi : B[y][2x+3y] = rol(A[x][y])
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(a[x + 5 * y], _RHO[x][y])
        # chi
        for y in (0, 5, 10, 15, 20):
            a[y] = b[y] ^ ((~b[y + 1] & _MASK64) & b[y + 2])
            a[y + 1] = b[y + 1] ^ ((~b[y + 2] & _MASK64) & b[y + 3])
            a[y + 2] = b[y + 2] ^ ((~b[y + 3] & _MASK64) & b[y + 4])
            a[y + 3] = b[y + 3] ^ ((~b[y + 4] & _MASK64) & b[y])
            a[y + 4] = b[y + 4] ^ ((~b[y] & _MASK64) & b[y + 1])
        # iota
        a[0] ^= _RC[rnd]
    return a


def keccak256(data):
    """以太坊 keccak256，返回 32 字节。data 可为 str（utf-8）。"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = bytes(data)
    rate = 136                      # (1600 - 2*256) / 8
    state = [0] * 25

    padded = bytearray(data)
    padlen = rate - (len(data) % rate)
    padded += b"\x00" * padlen
    padded[len(data)] ^= 0x01       # Keccak 原始域分隔
    padded[-1] ^= 0x80

    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f1600(state)

    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out


def keccak256_hex(data, prefix=False):
    h = keccak256(data).hex()
    return "0x" + h if prefix else h


# ---------------------------------------------------------------------------
# secp256k1
# ---------------------------------------------------------------------------

SECP256K1_P = 2 ** 256 - 2 ** 32 - 977
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_G = (_GX, _GY)
SECP256K1_A = 0
SECP256K1_B = 7

_INF = (0, 0, 0)          # Jacobian 无穷远点


def _jac_double(p):
    x, y, z = p
    if z == 0 or y == 0:
        return _INF
    p_ = SECP256K1_P
    yy = y * y % p_
    s = 4 * x * yy % p_
    m = 3 * x * x % p_
    x3 = (m * m - 2 * s) % p_
    y3 = (m * (s - x3) - 8 * yy * yy) % p_
    z3 = 2 * y * z % p_
    return (x3, y3, z3)


def _jac_add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    p_ = SECP256K1_P
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1 = z1 * z1 % p_
    z2z2 = z2 * z2 % p_
    u1 = x1 * z2z2 % p_
    u2 = x2 * z1z1 % p_
    s1 = y1 * z2 * z2z2 % p_
    s2 = y2 * z1 * z1z1 % p_
    if u1 == u2:
        if s1 != s2:
            return _INF
        return _jac_double(p)
    h = (u2 - u1) % p_
    r = (s2 - s1) % p_
    hh = h * h % p_
    hhh = h * hh % p_
    v = u1 * hh % p_
    x3 = (r * r - hhh - 2 * v) % p_
    y3 = (r * (v - x3) - s1 * hhh) % p_
    z3 = h * z1 * z2 % p_
    return (x3, y3, z3)


def _jac_mul(k, pt):
    k %= SECP256K1_N
    if k == 0 or pt is None:
        return _INF
    r = _INF
    p = (pt[0], pt[1], 1)
    while k:
        if k & 1:
            r = _jac_add(r, p)
        p = _jac_double(p)
        k >>= 1
    return r


def _to_affine(p):
    if p[2] == 0:
        return None
    p_ = SECP256K1_P
    zinv = pow(p[2], -1, p_)
    zinv2 = zinv * zinv % p_
    return (p[0] * zinv2 % p_, p[1] * zinv2 * zinv % p_)


def point_add(p1, p2):
    """仿射点加，点为 (x, y) 元组或 None（无穷远）。"""
    j1 = _INF if p1 is None else (p1[0], p1[1], 1)
    j2 = _INF if p2 is None else (p2[0], p2[1], 1)
    return _to_affine(_jac_add(j1, j2))


def point_mul(k, pt=SECP256K1_G):
    """标量乘 k*pt，返回仿射点。"""
    return _to_affine(_jac_mul(k, pt))


def _on_curve(pt):
    if pt is None:
        return False
    x, y = pt
    if not (0 <= x < SECP256K1_P and 0 <= y < SECP256K1_P):
        return False
    return (y * y - (x * x * x + 7)) % SECP256K1_P == 0


def pubkey_from_privkey(priv):
    """私钥 -> 未压缩公钥 64 字节（x||y，不带 0x04）。"""
    d = priv if isinstance(priv, int) else int.from_bytes(_as_bytes(priv), "big")
    if not 1 <= d < SECP256K1_N:
        raise ValueError("private key out of range")
    pt = point_mul(d)
    if pt is None:
        raise ValueError("invalid private key")
    return pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def pubkey_decompress(pub):
    """接受 33B 压缩 / 65B 未压缩 / 64B 裸 x||y，统一返回 64 字节。"""
    b = _as_bytes(pub)
    if len(b) == 64:
        pt = (int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big"))
        if not _on_curve(pt):
            raise ValueError("public key not on curve")
        return b
    if len(b) == 65 and b[0] == 0x04:
        pt = (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
        if not _on_curve(pt):
            raise ValueError("public key not on curve")
        return b[1:]
    if len(b) == 65 and b[0] in (0x06, 0x07):
        raise ValueError("hybrid public key encoding not supported")
    if len(b) == 33 and b[0] in (0x02, 0x03):
        x = int.from_bytes(b[1:], "big")
        alpha = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
        beta = pow(alpha, (SECP256K1_P + 1) // 4, SECP256K1_P)
        y = beta if (beta & 1) == (b[0] & 1) else SECP256K1_P - beta
        pt = (x, y)
        if not _on_curve(pt):
            raise ValueError("public key not on curve")
        return pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    raise ValueError("unsupported public key length %d" % len(b))


# ---------------------------------------------------------------------------
# ECDSA
# ---------------------------------------------------------------------------


def _rfc6979_k(msg_hash, priv, extra=b""):
    """RFC 6979 确定性 k（HMAC-SHA256）。"""
    x = priv.to_bytes(32, "big")
    h1 = (int.from_bytes(msg_hash, "big") % SECP256K1_N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1 + extra, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1 + extra, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < SECP256K1_N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign(msg_hash, priv, low_s=True):
    """返回 (r, s, recid)。recid ∈ {0,1,2,3}。"""
    h = _as_bytes(msg_hash) if not isinstance(msg_hash, int) else msg_hash.to_bytes(32, "big")
    e = int.from_bytes(h, "big")
    d = priv if isinstance(priv, int) else int.from_bytes(_as_bytes(priv), "big")
    if not 1 <= d < SECP256K1_N:
        raise ValueError("private key out of range")
    k = _rfc6979_k(h, d)
    pt = point_mul(k)
    if pt is None:
        raise ValueError("bad nonce")
    r = pt[0] % SECP256K1_N
    if r == 0:
        raise ValueError("bad nonce r")
    s = pow(k, -1, SECP256K1_N) * (e + r * d) % SECP256K1_N
    if s == 0:
        raise ValueError("bad nonce s")
    recid = (pt[1] & 1) | (2 if pt[0] >= SECP256K1_N else 0)
    if low_s and s > SECP256K1_N // 2:
        s = SECP256K1_N - s
        recid ^= 1
    return r, s, recid


def ecdsa_verify(msg_hash, r, s, pub):
    """标准 ECDSA 验签。"""
    n = SECP256K1_N
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(_as_bytes(msg_hash), "big")
    b = pubkey_decompress(pub)
    q = (int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big"))
    w = pow(s, -1, n)
    u1 = e * w % n
    u2 = r * w % n
    pt = point_add(point_mul(u1), point_mul(u2, q))
    if pt is None:
        return False
    return pt[0] % n == r


def ecdsa_recover(msg_hash, r, s, v):
    """从签名恢复签名者公钥。

    v 允许：0/1（yParity）、27/28（比特币风格）、EIP-155 的 37/38 等；后者请先用
    parse_eth_tx 归一化（那里能拿到 chainId）。
    """
    v = _as_int(v)
    if v in (27, 28):
        recid = v - 27
    elif v in (0, 1, 2, 3):
        recid = v
    elif v >= 35:
        # 缺 chainId 时只能按 recid 的最低位猜测（EIP-155: v = chainId*2 + 35 + recid）
        recid = (v - 35) & 1
    else:
        raise ValueError("bad recovery id %r" % (v,))
    return _recover_with_recid(msg_hash, _as_int(r), _as_int(s), recid)


def _recover_with_recid(msg_hash, r, s, recid):
    n = SECP256K1_N
    p_ = SECP256K1_P
    if not (1 <= r < n and 1 <= s < n):
        raise ValueError("r/s out of range")
    x = r + (recid >> 1) * n
    if x >= p_:
        raise ValueError("x >= p")
    alpha = (pow(x, 3, p_) + 7) % p_
    beta = pow(alpha, (p_ + 1) // 4, p_)
    if (beta * beta - alpha) % p_ != 0:
        raise ValueError("point not on curve")
    y = beta if (beta & 1) == (recid & 1) else p_ - beta
    R = (x, y)
    e = int.from_bytes(_as_bytes(msg_hash), "big") % n
    rinv = pow(r, -1, n)
    sr = _jac_mul(s, R)
    eg = _jac_mul(e, SECP256K1_G)
    neg_eg = (eg[0], (-eg[1]) % p_, eg[2]) if eg[2] else _INF
    q = _jac_add(sr, neg_eg)
    if q[2] == 0:
        raise ValueError("recovered point at infinity")
    # rinv * Q ：先转仿射再做标量乘，避免把 Jacobian 坐标当仿射输入
    qa = _to_affine(q)
    pt = point_mul(rinv, qa)
    if pt is None or not _on_curve(pt):
        raise ValueError("recovered point invalid")
    return pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


# ---------------------------------------------------------------------------
# 以太坊地址
# ---------------------------------------------------------------------------


def eip55_checksum(address):
    """EIP-55 大小写校验，输入任意 hex 地址，返回校验形态。"""
    a = _as_bytes(address).hex()
    if len(a) != 40:
        raise ValueError("address must be 20 bytes")
    h = keccak256(a.encode("ascii")).hex()
    out = []
    for i, ch in enumerate(a):
        if ch in "0123456789":
            out.append(ch)
        else:
            out.append(ch.upper() if int(h[i], 16) >= 8 else ch.lower())
    return "0x" + "".join(out)


def eip55_check(address):
    """返回 (ok, mode)。mode ∈ mixed / all-lower / all-upper / invalid。

    只有 mixed 大小写才携带校验信息；全小写、全大写都不含校验（合法但不可验证），
    取证时应与 mixed 区分对待 —— 攻击者常把 mixed 改成 all-lower 隐藏特征。
    """
    s = address.strip()
    if s[:2].lower() == "0x":
        s = s[2:]
    if len(s) != 40:
        return False, "invalid"
    has_lower = any(c.islower() for c in s)
    has_upper = any(c.isupper() for c in s)
    if has_lower and has_upper:
        return (eip55_checksum(s)[2:] == s), "mixed"
    if has_upper:
        return True, "all-upper"
    return True, "all-lower"


def eth_address_from_pubkey(pub, checksum=True):
    b = pubkey_decompress(pub)
    raw = keccak256(b)[-20:].hex()
    return eip55_checksum(raw) if checksum else "0x" + raw


def eth_address_from_privkey(priv, checksum=True):
    return eth_address_from_pubkey(pubkey_from_privkey(priv), checksum=checksum)


# ---------------------------------------------------------------------------
# Base58 / Base58Check
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def base58_encode(data):
    b = _as_bytes(data)
    n = int.from_bytes(b, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def base58_decode(s):
    s = "".join(s.split())
    n = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise ValueError("invalid base58 character %r" % ch)
        n = n * 58 + _B58_INDEX[ch]
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    body = b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * pad + body


def _sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def base58check_encode(version, payload):
    """version 可为 int 或 bytes（多字节版本前缀，如 TRON 0x41、Zcash 0x1CB8）。"""
    if isinstance(version, int):
        vb = _int_to_bytes(version) or b"\x00"
    else:
        vb = _as_bytes(version)
    body = vb + _as_bytes(payload)
    return base58_encode(body + _sha256d(body)[:4])


def base58check_decode(s, expected_version=None):
    """返回 dict：version / payload / payload_hex / checksum_ok / valid。

    校验失败不抛异常（取证场景需要保留原始串），由 valid 字段判定。
    """
    out = {"input": s, "valid": False, "checksum_ok": False,
           "version": None, "payload": None, "payload_hex": None,
           "version_hex": None, "raw_hex": None, "error": None}
    try:
        raw = base58_decode(s)
    except ValueError as exc:
        out["error"] = str(exc)
        return out
    out["raw_hex"] = raw.hex()
    if len(raw) < 5:
        out["error"] = "too short for base58check (%d bytes)" % len(raw)
        return out
    body, cksum = raw[:-4], raw[-4:]
    out["checksum_ok"] = _sha256d(body)[:4] == cksum
    # 版本字节长度：常见 1 字节；Zcash 等为 2 字节。用「载荷长度」反推。
    vlen = 1
    if out["checksum_ok"]:
        payload_len = len(body) - vlen
        if expected_version is not None:
            if isinstance(expected_version, int):
                cand = [_int_to_bytes(expected_version) or b"\x00"]
            else:
                cand = [_as_bytes(expected_version)]
            for cb in cand:
                if body[:len(cb)] == cb:
                    vlen = len(cb)
                    break
        elif payload_len not in (20, 32):
            for l in (2,):
                if len(body) - l in (20, 32):
                    vlen = l
                    break
    vb = body[:vlen]
    payload = body[vlen:]
    out["version"] = int.from_bytes(vb, "big")
    out["version_hex"] = vb.hex()
    out["payload"] = payload
    out["payload_hex"] = payload.hex()
    ok = out["checksum_ok"]
    if expected_version is not None:
        ev = expected_version
        ev_b = (_int_to_bytes(ev) or b"\x00") if isinstance(ev, int) else _as_bytes(ev)
        ok = ok and vb == ev_b
    out["valid"] = bool(ok)
    return out


# ---------------------------------------------------------------------------
# Bech32 / Bech32m（BIP173 / BIP350）
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_INDEX = {c: i for i, c in enumerate(_BECH32_CHARSET)}
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values):
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data, spec):
    const = _BECH32M_CONST if spec == "bech32m" else _BECH32_CONST
    values = _bech32_hrp_expand(hrp) + list(data)
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_verify_checksum(hrp, data):
    """返回 'bech32' / 'bech32m' / None。"""
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + list(data))
    if const == _BECH32_CONST:
        return "bech32"
    if const == _BECH32M_CONST:
        return "bech32m"
    return None


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp, data, spec="bech32"):
    """data 为 5-bit 整数序列。"""
    hrp = hrp.lower()
    combined = list(data) + _bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)


def bech32_decode(bech):
    """返回 (hrp, data5, spec)；校验失败抛 ValueError。"""
    if not isinstance(bech, str):
        raise TypeError("bech32 needs str")
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        raise ValueError("bech32: invalid character range")
    if bech.lower() != bech and bech.upper() != bech:
        raise ValueError("bech32: mixed case")
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        raise ValueError("bech32: invalid separator position / length")
    hrp = bech[:pos]
    data = []
    for ch in bech[pos + 1:]:
        if ch not in _BECH32_INDEX:
            raise ValueError("bech32: invalid data character %r" % ch)
        data.append(_BECH32_INDEX[ch])
    spec = _bech32_verify_checksum(hrp, data)
    if spec is None:
        raise ValueError("bech32: checksum mismatch")
    return hrp, data[:-6], spec


def decode_segwit_address(addr):
    """返回 dict(hrp, witver, witprog bytes, spec, valid)。"""
    out = {"input": addr, "valid": False, "hrp": None, "witver": None,
           "witprog": None, "witprog_hex": None, "spec": None, "error": None}
    try:
        hrp, data, spec = bech32_decode(addr)
    except ValueError as exc:
        out["error"] = str(exc)
        return out
    out["hrp"] = hrp
    out["spec"] = spec
    if not data:
        out["error"] = "empty data"
        return out
    witver = data[0]
    prog = convertbits(data[1:], 5, 8, False)
    if prog is None:
        out["error"] = "invalid padding"
        return out
    out["witver"] = witver
    out["witprog"] = bytes(prog)
    out["witprog_hex"] = bytes(prog).hex()
    if witver > 16:
        out["error"] = "witness version > 16"
        return out
    if len(prog) < 2 or len(prog) > 40:
        out["error"] = "invalid program length %d" % len(prog)
        return out
    if witver == 0 and len(prog) not in (20, 32):
        out["error"] = "v0 program must be 20 or 32 bytes"
        return out
    if witver == 0 and spec != "bech32":
        out["error"] = "v0 requires bech32 checksum"
        return out
    if witver != 0 and spec != "bech32m":
        out["error"] = "v1+ requires bech32m checksum"
        return out
    out["valid"] = True
    return out


def encode_segwit_address(hrp, witver, witprog):
    spec = "bech32" if witver == 0 else "bech32m"
    data = [witver] + convertbits(list(_as_bytes(witprog)), 8, 5, True)
    return bech32_encode(hrp, data, spec)


# ---------------------------------------------------------------------------
# RLP
# ---------------------------------------------------------------------------


def _rlp_len_prefix(length, offset):
    if length < 56:
        return bytes([offset + length])
    bl = _int_to_bytes(length)
    return bytes([offset + 55 + len(bl)]) + bl


def rlp_encode(obj):
    """bytes/str/int/list/tuple/dict -> RLP bytes。

    dict 编码为按键排序的 [key, value] 对列表（以太坊 accessList 等结构化数据常用此约定），
    解码会得到同样的嵌套列表，可再编码回完全相同的字节。
    """
    if obj is None:
        return rlp_encode(b"")
    if isinstance(obj, bool):
        return rlp_encode(b"\x01" if obj else b"")
    if isinstance(obj, int):
        if obj < 0:
            raise ValueError("RLP cannot encode negative int")
        return rlp_encode(_int_to_bytes(obj))
    if isinstance(obj, str):
        return rlp_encode(obj.encode("utf-8"))
    if isinstance(obj, (bytes, bytearray, memoryview)):
        b = bytes(obj)
        if len(b) == 1 and b[0] < 0x80:
            return b
        return _rlp_len_prefix(len(b), 0x80) + b
    if isinstance(obj, dict):
        items = [[k, obj[k]] for k in sorted(obj, key=lambda x: (str(type(x)), x))]
        return rlp_encode(items)
    if isinstance(obj, (list, tuple)):
        payload = b"".join(rlp_encode(x) for x in obj)
        return _rlp_len_prefix(len(payload), 0xC0) + payload
    raise TypeError("cannot RLP encode %r" % (type(obj),))


def _rlp_decode_at(buf, pos):
    if pos >= len(buf):
        raise ValueError("RLP: unexpected end of data")
    b0 = buf[pos]
    if b0 < 0x80:
        return bytes(buf[pos:pos + 1]), pos + 1
    if b0 < 0xB8:
        ln = b0 - 0x80
        start = pos + 1
        end = start + ln
        if end > len(buf):
            raise ValueError("RLP: short string overflow")
        return bytes(buf[start:end]), end
    if b0 < 0xC0:
        ll = b0 - 0xB7
        start = pos + 1
        if start + ll > len(buf):
            raise ValueError("RLP: short length overflow")
        ln = int.from_bytes(buf[start:start + ll], "big")
        start += ll
        end = start + ln
        if end > len(buf):
            raise ValueError("RLP: long string overflow")
        if ln < 56:
            raise ValueError("RLP: non-canonical long string")
        return bytes(buf[start:end]), end
    if b0 < 0xF8:
        ln = b0 - 0xC0
        start = pos + 1
        end = start + ln
        if end > len(buf):
            raise ValueError("RLP: short list overflow")
    else:
        ll = b0 - 0xF7
        start = pos + 1
        if start + ll > len(buf):
            raise ValueError("RLP: long length overflow")
        ln = int.from_bytes(buf[start:start + ll], "big")
        start += ll
        end = start + ln
        if end > len(buf):
            raise ValueError("RLP: long list overflow")
        if ln < 56:
            raise ValueError("RLP: non-canonical long list")
    items = []
    p = start
    while p < end:
        item, p = _rlp_decode_at(buf, p)
        items.append(item)
    if p != end:
        raise ValueError("RLP: list payload length mismatch")
    return items, end


def rlp_decode(data, strict=True):
    """RLP bytes -> 嵌套 list / bytes。"""
    buf = _as_bytes(data)
    obj, pos = _rlp_decode_at(buf, 0)
    if strict and pos != len(buf):
        raise ValueError("RLP: %d trailing bytes" % (len(buf) - pos))
    return obj


# ---------------------------------------------------------------------------
# 以太坊交易
# ---------------------------------------------------------------------------

KNOWN_CONTRACTS = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT (ERC20, Ethereum)",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC (ERC20, Ethereum)",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI (ERC20, Ethereum)",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC (ERC20, Ethereum)",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH9 (Ethereum)",
    "0x55d398326f99059ff775485246999027b3197955": "USDT (BEP20, BSC)",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router02",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
    "tr7nhqjekqxgtci8q8zy4pl8otszgjlj6t": "USDT (TRC20, TRON)",
}

_ETH_WEI = Decimal(10) ** 18


def _wei_to_eth(v):
    return str(Decimal(v) / _ETH_WEI)


def _ts_iso(ts):
    """Unix 时间戳 -> UTC ISO8601（不依赖已弃用的 utcfromtimestamp）。"""
    import datetime as _dt
    return _dt.datetime.fromtimestamp(int(ts), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _method_selector(data):
    return data[:4].hex() if len(data) >= 4 else None


def _selector_name(sel):
    """常见选择器 -> 名称，未知返回 None。"""
    table = {
        "a9059cbb": "transfer(address,uint256)",
        "23b872dd": "transferFrom(address,address,uint256)",
        "095ea7b3": "approve(address,uint256)",
        "70a08231": "balanceOf(address)",
        "dd62ed3e": "allowance(address,address)",
        "38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        "7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
        "18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
        "fb3bdb41": "swapETHForExactTokens(uint256,address[],address,uint256)",
        "4a25d94a": "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
        "8803dbee": "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
        "b6f9de95": "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)",
        "791ac947": "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
        "5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
        "3593564c": "execute(bytes,bytes[],uint256)",           # Uniswap Universal Router
        "c04b8d59": "exactInput((bytes,address,uint256,uint256,uint256))",  # V3 exactInput
        "414bf389": "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
        "db3e2198": "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
        "ac9650d8": "multicall(bytes[])",
        "5ae401dc": "multicall(uint256,bytes[])",
        "1cff79cd": "execute(address,bytes)",                    # Gnosis Safe
        "6a761202": "execTransaction(...)",                      # Gnosis Safe
        "f2fde38b": "transferOwnership(address)",
        "715018a6": "renounceOwnership()",
        "8da5cb5b": "owner()",
        "a22cb465": "setApprovalForAll(address,bool)",
        "42842e0e": "safeTransferFrom(address,address,uint256)",
        "b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
        "d0e30db0": "deposit()",                                 # WETH
        "2e1a7d4d": "withdraw(uint256)",                         # WETH
    }
    return table.get(sel)


def eth_tx_hash(raw):
    return keccak256(_as_bytes(raw)).hex()


def parse_eth_tx(raw):
    """解析以太坊原始交易（Legacy / type1 EIP-2930 / type2 EIP-1559）。

    返回 dict，字段包含 nonce / gasPrice / gas / to / value / data / v / r / s /
    chainId / from / 合约调用标识 / 方法选择器等。
    """
    buf = _as_bytes(raw)
    if not buf:
        raise ValueError("empty transaction")

    tx_type = 0
    pos = 0
    if buf[0] >= 0xC0:
        payload = buf
    elif buf[0] <= 0x7F:
        tx_type = buf[0]
        payload = buf[1:]
    else:
        raise ValueError("bad transaction prefix 0x%02x" % buf[0])

    if tx_type not in (0, 1, 2, 3, 4):
        raise ValueError("unsupported transaction type %d" % tx_type)

    items, _end = _rlp_decode_at(payload, 0)

    out = {
        "type": tx_type,
        "type_name": {0: "legacy", 1: "eip2930", 2: "eip1559", 3: "eip4844", 4: "eip7702"}.get(tx_type, "?"),
        "hash": eth_tx_hash(buf),
        "raw_len": len(buf),
        "nonce": 0, "gasPrice": 0, "gas": 0,
        "maxPriorityFeePerGas": None, "maxFeePerGas": None,
        "to": None, "value": 0, "value_eth": "0",
        "data": b"", "data_hex": "", "data_len": 0,
        "v": 0, "r": 0, "s": 0, "yParity": None,
        "chainId": None, "sign_hash": None, "from": None,
        "accessList": [], "is_contract_call": False, "is_contract_creation": False,
        "method_selector": None, "method_name": None,
    }

    if tx_type == 0:
        if len(items) not in (6, 9):
            raise ValueError("legacy tx field count %d" % len(items))
        nonce, gas_price, gas, to, value, data = items[:6]
        out.update({
            "nonce": _as_int(nonce), "gasPrice": _as_int(gas_price), "gas": _as_int(gas),
            "to": "0x" + to.hex() if to else None, "value": _as_int(value),
            "data": data, "data_hex": data.hex(), "data_len": len(data),
        })
        if len(items) == 9:
            v, r, s = (_as_int(x) for x in items[6:9])
            out.update({"v": v, "r": r, "s": s})
            if v >= 35:
                chain_id = (v - 35) // 2
                recid = v - 35 - 2 * chain_id
                out["chainId"] = chain_id
                out["yParity"] = recid
                sign_hash = keccak256(rlp_encode(
                    [nonce, gas_price, gas, to, value, data, chain_id, b"", b""]))
            elif v in (27, 28):
                recid = v - 27
                out["yParity"] = recid
                sign_hash = keccak256(rlp_encode([nonce, gas_price, gas, to, value, data]))
            else:
                raise ValueError("invalid legacy v=%d" % v)
            out["sign_hash"] = sign_hash.hex()
        else:
            out["unsigned"] = True
            out["v"] = out["r"] = out["s"] = None
            recid = None
            sign_hash = None

    elif tx_type == 1:
        if len(items) != 11:
            raise ValueError("type1 field count %d" % len(items))
        chain_id, nonce, gas_price, gas, to, value, data, access, yparity, r, s = items
        out.update({
            "chainId": _as_int(chain_id), "nonce": _as_int(nonce), "gasPrice": _as_int(gas_price),
            "gas": _as_int(gas), "to": "0x" + to.hex() if to else None,
            "value": _as_int(value), "data": data, "data_hex": data.hex(), "data_len": len(data),
            "accessList": access, "v": _as_int(yparity), "yParity": _as_int(yparity),
            "r": _as_int(r), "s": _as_int(s),
        })
        recid = _as_int(yparity)
        sign_hash = keccak256(b"\x01" + rlp_encode(items[:8]))
        out["sign_hash"] = sign_hash.hex()

    else:  # type 2 (258 for 4844/7702 not fully wired)
        if len(items) != 12:
            raise ValueError("type%d field count %d" % (tx_type, len(items)))
        chain_id, nonce, prio, maxfee, gas, to, value, data, access, yparity, r, s = items
        out.update({
            "chainId": _as_int(chain_id), "nonce": _as_int(nonce),
            "maxPriorityFeePerGas": _as_int(prio), "maxFeePerGas": _as_int(maxfee),
            "gasPrice": _as_int(maxfee), "gas": _as_int(gas),
            "to": "0x" + to.hex() if to else None, "value": _as_int(value),
            "data": data, "data_hex": data.hex(), "data_len": len(data),
            "accessList": access, "v": _as_int(yparity), "yParity": _as_int(yparity),
            "r": _as_int(r), "s": _as_int(s),
        })
        recid = _as_int(yparity)
        sign_hash = keccak256(bytes([tx_type]) + rlp_encode(items[:9]))
        out["sign_hash"] = sign_hash.hex()

    out["value_eth"] = _wei_to_eth(out["value"] if isinstance(out["value"], int) else 0)
    out["is_contract_creation"] = out["to"] is None
    sel = _method_selector(out["data"])
    out["method_selector"] = sel
    out["method_name"] = _selector_name(sel) if sel else None
    out["is_contract_call"] = bool(out["to"]) and len(out["data"]) >= 4

    if sign_hash is not None:
        try:
            pub = _recover_with_recid(sign_hash, out["r"], out["s"], recid)
            raw20 = keccak256(pub)[-20:].hex()
            out["from"] = eip55_checksum(raw20)
            out["from_lower"] = "0x" + raw20
        except ValueError as exc:
            out["from"] = None
            out["recover_error"] = str(exc)

    if out["to"]:
        out["to"] = eip55_checksum(out["to"][2:])
        out["to_known"] = KNOWN_CONTRACTS.get(out["to"].lower())
    return out


# ---------------------------------------------------------------------------
# 比特币
# ---------------------------------------------------------------------------


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(bytes(data)).digest()).digest()


def _btc_varint(buf, pos):
    if pos >= len(buf):
        raise ValueError("varint: out of range")
    b = buf[pos]
    pos += 1
    if b < 0xFD:
        return b, pos
    if b == 0xFD:
        return struct.unpack_from("<H", buf, pos)[0], pos + 2
    if b == 0xFE:
        return struct.unpack_from("<I", buf, pos)[0], pos + 4
    return struct.unpack_from("<Q", buf, pos)[0], pos + 8


def _varint_encode(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _read_varbytes(buf, pos):
    n, pos = _btc_varint(buf, pos)
    return buf[pos:pos + n], pos + n


def _script_pushes(script):
    """拆出脚本里的 data push 列表（不执行脚本，仅做静态取证）。"""
    pushes = []
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        if 0x01 <= op <= 0x4B:
            ln = op
            i += 1
            if i + ln > n:
                pushes.append(script[i:])
                break
            pushes.append(script[i:i + ln])
            i += ln
            continue
        if op == 0x4C and i + 1 < n:          # OP_PUSHDATA1
            ln = script[i + 1]
            i += 2
            pushes.append(script[i:i + ln])
            i += ln
            continue
        if op == 0x4D and i + 2 < n:          # OP_PUSHDATA2
            ln = struct.unpack_from("<H", script, i + 1)[0]
            i += 3
            pushes.append(script[i:i + ln])
            i += ln
            continue
        if op == 0x4E and i + 4 < n:          # OP_PUSHDATA4
            ln = struct.unpack_from("<I", script, i + 1)[0]
            i += 5
            pushes.append(script[i:i + ln])
            i += ln
            continue
        i += 1
    return pushes


def script_to_address(script, network="mainnet"):
    """输出脚本 -> (地址, 类型)。无法识别返回 (None, 'nonstandard' 等)。"""
    script = _as_bytes(script)
    hrp = {"mainnet": "bc", "testnet": "tb", "regtest": "bcrt"}.get(network, "bc")
    p2pkh_v = {"mainnet": 0x00, "testnet": 0x6F, "regtest": 0x6F}.get(network, 0x00)
    p2sh_v = {"mainnet": 0x05, "testnet": 0xC4, "regtest": 0xC4}.get(network, 0x05)

    if (len(script) == 25 and script[0] == 0x76 and script[1] == 0xA9 and script[2] == 0x14
            and script[23] == 0x88 and script[24] == 0xAC):
        return base58check_encode(p2pkh_v, script[3:23]), "p2pkh"
    if len(script) == 23 and script[0] == 0xA9 and script[1] == 0x14 and script[22] == 0x87:
        return base58check_encode(p2sh_v, script[2:22]), "p2sh"
    if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
        return encode_segwit_address(hrp, 0, script[2:]), "p2wpkh"
    if len(script) == 34 and script[0] == 0x00 and script[1] == 0x20:
        return encode_segwit_address(hrp, 0, script[2:]), "p2wsh"
    if len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
        return encode_segwit_address(hrp, 1, script[2:]), "p2tr"
    if len(script) in (35, 67) and script[-1] == 0xAC and script[0] in (0x21, 0x41):
        pub = script[1:-1]
        return base58check_encode(p2pkh_v, hash160(pub)), "p2pk"
    if len(script) == 0:
        return None, "empty"
    if script[0] == 0x6A:
        return None, "op_return"
    return None, "nonstandard"


def _input_addresses(script_sig, witness):
    """从 scriptSig / witness 里静态提取地址（不做脚本执行）。"""
    found = []
    for push in _script_pushes(script_sig):
        if len(push) in (33, 65) and push[0] in (0x02, 0x03, 0x04):
            addr = base58check_encode(0x00, hash160(push))
            found.append({"address": addr, "type": "p2pkh(from pubkey in scriptSig)"})
        elif push and push[0] == 0xA9 and len(push) == 23 and push[-1] == 0x87:
            addr = base58check_encode(0x05, push[2:22])
            found.append({"address": addr, "type": "p2sh(redeem script in scriptSig)"})
        elif len(push) == 22 and push[0] == 0x00 and push[1] == 0x14:
            found.append({"address": encode_segwit_address("bc", 0, push[2:]), "type": "p2wpkh(scriptSig)"})
    if witness:
        if len(witness) == 2 and len(witness[1]) == 33 and witness[1][0] in (0x02, 0x03):
            found.append({"address": encode_segwit_address("bc", 0, hash160(witness[1])),
                          "type": "p2wpkh(witness)"})
        elif len(witness) == 2 and len(witness[0]) == 20:
            found.append({"address": encode_segwit_address("bc", 0, witness[0]), "type": "p2wpkh(witness)"})
        elif witness and len(witness[0]) == 32:
            found.append({"address": encode_segwit_address("bc", 0, witness[0]), "type": "p2wsh(witness)"})
    # 去重
    uniq, seen = [], set()
    for f in found:
        if f["address"] not in seen:
            seen.add(f["address"])
            uniq.append(f)
    return uniq


def parse_bitcoin_tx(raw_hex, network="mainnet"):
    """解析原始比特币交易（hex 或 bytes），支持 SegWit。"""
    buf = _as_bytes(raw_hex)
    if len(buf) < 10:
        raise ValueError("transaction too short")
    out = {"network": network, "segwit": False, "version": struct.unpack_from("<i", buf, 0)[0],
           "inputs": [], "outputs": [], "locktime": 0,
           "size": len(buf), "txid": None, "wtxid": None,
           "total_out": 0, "error": None}
    pos = 4
    if buf[pos] == 0x00 and pos + 1 < len(buf) and buf[pos + 1] == 0x01:
        out["segwit"] = True
        pos += 2

    n_in, pos = _btc_varint(buf, pos)
    if n_in > 100000:
        raise ValueError("implausible input count %d" % n_in)
    wit_start = pos
    for _ in range(n_in):
        if pos + 36 > len(buf):
            raise ValueError("truncated input")
        prev_txid = buf[pos:pos + 32][::-1].hex()
        pos += 32
        vout = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        script_sig, pos = _read_varbytes(buf, pos)
        seq = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        addr, stype = script_to_address(script_sig, network)
        out["inputs"].append({
            "prev_txid": prev_txid, "vout": vout,
            "scriptSig_hex": script_sig.hex(), "scriptSig_len": len(script_sig),
            "sequence": seq,
            "script_type": stype,
            "scriptSig_address": addr,
            "addresses": [],
        })

    n_out, pos = _btc_varint(buf, pos)
    if n_out > 100000:
        raise ValueError("implausible output count %d" % n_out)
    for i in range(n_out):
        if pos + 8 > len(buf):
            raise ValueError("truncated output")
        value = struct.unpack_from("<q", buf, pos)[0]
        pos += 8
        script, pos = _read_varbytes(buf, pos)
        addr, stype = script_to_address(script, network)
        out["outputs"].append({
            "n": i, "value": value, "value_btc": str(Decimal(value) / Decimal(10 ** 8)),
            "script_hex": script.hex(), "script_type": stype, "address": addr,
            "op_return": script.hex() if script[:1] == b"\x6a" else None,
        })
        out["total_out"] += value

    if out["segwit"]:
        for inp in out["inputs"]:
            cnt, pos = _btc_varint(buf, pos)
            items = []
            for _ in range(cnt):
                item, pos = _read_varbytes(buf, pos)
                items.append(item)
            inp["witness"] = [i.hex() for i in items]
            inp["witness_count"] = cnt

    if pos + 4 > len(buf):
        raise ValueError("truncated locktime")
    out["locktime"] = struct.unpack_from("<I", buf, pos)[0]
    pos += 4
    if pos != len(buf):
        out["trailing_bytes"] = len(buf) - pos

    # txid：non-witness 序列化
    non_wit = bytearray()
    non_wit += struct.pack("<i", out["version"])
    non_wit += _varint_encode(len(out["inputs"]))
    for inp in out["inputs"]:
        non_wit += bytes.fromhex(inp["prev_txid"])[::-1]
        non_wit += struct.pack("<I", inp["vout"])
        ss = bytes.fromhex(inp["scriptSig_hex"])
        non_wit += _varint_encode(len(ss)) + ss
        non_wit += struct.pack("<I", inp["sequence"])
    non_wit += _varint_encode(len(out["outputs"]))
    for o in out["outputs"]:
        non_wit += struct.pack("<q", o["value"])
        sc = bytes.fromhex(o["script_hex"])
        non_wit += _varint_encode(len(sc)) + sc
    non_wit += struct.pack("<I", out["locktime"])
    out["txid"] = _sha256d(bytes(non_wit))[::-1].hex()
    out["wtxid"] = _sha256d(buf)[::-1].hex() if out["segwit"] else out["txid"]
    out["vsize"] = (len(non_wit) * 3 + len(buf)) // 4

    for inp in out["inputs"]:
        inp["addresses"] = _input_addresses(bytes.fromhex(inp["scriptSig_hex"]),
                                           [bytes.fromhex(w) for w in inp.get("witness", [])])
    return out


def parse_block(raw_hex, network="mainnet"):
    """解析区块：80 字节头 + 交易计数（可继续解析各交易）。"""
    buf = _as_bytes(raw_hex)
    if len(buf) < 81:
        raise ValueError("block too short")
    hdr = buf[:80]
    version = struct.unpack_from("<i", hdr, 0)[0]
    prev = hdr[4:36][::-1].hex()
    merkle = hdr[36:68][::-1].hex()
    ts, bits, nonce = struct.unpack_from("<III", hdr, 68)
    tx_count, pos = _btc_varint(buf, 80)
    out = {
        "network": network, "header_hex": hdr.hex(), "version": version,
        "hash": _sha256d(hdr)[::-1].hex(), "prev_block": prev, "merkle_root": merkle,
        "time": ts, "time_iso": _ts_iso(ts),
        "bits": "%08x" % bits, "nonce": nonce, "tx_count": tx_count,
        "size": len(buf), "tx_offsets": [], "txids": [], "error": None,
    }
    offsets = []
    p = pos
    try:
        for _ in range(tx_count):
            start = p
            # 粗略推进：用 varint + 结构解析得到长度
            tstart = p
            p += 4
            segwit = False
            if p + 2 <= len(buf) and buf[p] == 0 and buf[p + 1] == 1:
                segwit = True
                p += 2
            n_in, p = _btc_varint(buf, p)
            for _ in range(n_in):
                p += 36
                ln, p = _btc_varint(buf, p)
                p += ln
                p += 4
            n_out, p = _btc_varint(buf, p)
            for _ in range(n_out):
                p += 8
                ln, p = _btc_varint(buf, p)
                p += ln
            if segwit:
                for _ in range(n_in):
                    cnt, p = _btc_varint(buf, p)
                    for _ in range(cnt):
                        ln, p = _btc_varint(buf, p)
                        p += ln
            p += 4
            offsets.append((start, p - start))
    except (ValueError, struct.error):
        pass
    out["tx_offsets"] = offsets
    return out


# ---------------------------------------------------------------------------
# 文本地址提取
# ---------------------------------------------------------------------------

_ADDR_ETH = re.compile(r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_ADDR_BTC_B58 = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[13][1-9A-HJ-NP-Za-km-z]{24,33}"
                           r"(?![1-9A-HJ-NP-Za-km-z])")
_ADDR_BECH32 = re.compile(r"(?<![0-9A-Za-z])(?:bc|tb|bcrt)1[02-9ac-hj-np-z]{6,87}"
                          r"(?![0-9A-Za-z])", re.IGNORECASE)
_ADDR_TRON = re.compile(r"(?<![0-9A-Za-z])T[1-9A-HJ-NP-Za-km-z]{33}(?![0-9A-Za-z])")
# 兼容表格里常见的「带空格/分段」写法：0x1234 5678 ... 不做展开，只加提示


def _label_for_addr(addr_lower):
    return KNOWN_CONTRACTS.get(addr_lower)


def scan_addresses(text):
    """从任意文本中提取地址，返回 list[dict]。

    每条记录：address / type / valid / checksum / note / line / column / context
    type ∈ {eth, btc_p2pkh, btc_p2sh, btc_bech32, tron, usdt_contract}
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    results = []
    seen = set()

    def push(addr, atype, valid, checksum, note, line, col, context):
        key = (addr, atype)
        if key in seen:
            return
        seen.add(key)
        results.append({
            "address": addr, "type": atype, "valid": valid, "checksum": checksum,
            "note": note, "line": line, "column": col, "context": context,
        })

    offset = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in _ADDR_ETH.finditer(line):
            addr = m.group(0)
            ok, mode = eip55_check(addr)
            note = _label_for_addr(addr.lower()) or ""
            valid = ok
            if mode == "mixed":
                checksum = "eip55-ok" if ok else "eip55-BAD"
            else:
                checksum = mode
            if not ok:
                note = (note + "; " if note else "") + "EIP-55 大小写校验失败（疑似篡改）"
            atype = "usdt_contract" if note.startswith("USDT (ERC20") else "eth"
            push(addr, atype, valid, checksum, note, lineno, m.start() + 1, line.strip()[:160])
        for m in _ADDR_TRON.finditer(line):
            addr = m.group(0)
            dec = base58check_decode(addr, expected_version=0x41)
            note = _label_for_addr(addr.lower()) or ""
            atype = "usdt_contract" if "USDT" in note else "tron"
            push(addr, atype, dec["valid"], "base58check-ok" if dec["valid"] else "base58check-BAD",
                 note, lineno, m.start() + 1, line.strip()[:160])
        for m in _ADDR_BECH32.finditer(line):
            addr = m.group(0)
            dec = decode_segwit_address(addr)
            kind = {0: "btc_bech32_p2wpkh", 1: "btc_bech32_p2tr"}.get(dec["witver"], "btc_bech32")
            if dec["valid"]:
                if dec["witver"] == 0 and len(dec["witprog"]) == 32:
                    kind = "btc_bech32_p2wsh"
            push(addr.lower() if dec["valid"] else addr, kind, dec["valid"],
                 ("%s-ok" % dec["spec"]) if dec["valid"] else "checksum-BAD",
                 dec["error"] or "", lineno, m.start() + 1, line.strip()[:160])
        for m in _ADDR_BTC_B58.finditer(line):
            addr = m.group(0)
            dec = base58check_decode(addr)
            if dec["checksum_ok"] and dec["version"] in (0x00, 0x05) and len(dec["payload"]) == 20:
                atype = "btc_p2pkh" if dec["version"] == 0 else "btc_p2sh"
                push(addr, atype, True, "base58check-ok", _label_for_addr(addr.lower()) or "",
                     lineno, m.start() + 1, line.strip()[:160])
        offset += len(line) + 1
    return results


# ---------------------------------------------------------------------------
# DeFi / 事件解码
# ---------------------------------------------------------------------------

EVENT_TOPICS = {
    "Transfer(address,address,uint256)": keccak256(b"Transfer(address,address,uint256)"),
    "Approval(address,address,uint256)": keccak256(b"Approval(address,address,uint256)"),
    "Swap(address,uint256,uint256,uint256,uint256,address)":
        keccak256(b"Swap(address,uint256,uint256,uint256,uint256,address)"),
    "Swap(address,address,int256,int256,uint160,uint128,int24)":
        keccak256(b"Swap(address,address,int256,int256,uint160,uint128,int24)"),
    "Sync(uint112,uint112)": keccak256(b"Sync(uint112,uint112)"),
    "Deposit(address,uint256)": keccak256(b"Deposit(address,uint256)"),
    "Withdrawal(address,uint256)": keccak256(b"Withdrawal(address,uint256)"),
    "Mint(address,uint256,uint256)": keccak256(b"Mint(address,uint256,uint256)"),
    "Burn(address,uint256,uint256,address)": keccak256(b"Burn(address,uint256,uint256,address)"),
    "PairCreated(address,address,address,uint256)":
        keccak256(b"PairCreated(address,address,address,uint256)"),
}


def _word(data, i):
    return data[i * 32:(i + 1) * 32]


def _word_addr(data, i):
    w = _word(data, i)
    if len(w) < 32:
        return None
    return eip55_checksum(w[12:])


def _word_uint(data, i):
    w = _word(data, i)
    return int.from_bytes(w, "big") if w else None


def _word_int(data, i):
    w = _word(data, i)
    if not w:
        return None
    v = int.from_bytes(w, "big")
    if v >= 2 ** 255:
        v -= 2 ** 256
    return v


def defi_swap_decode(topic0, data, topics=None):
    """解码常见 DeFi / ERC20 事件。

    topic0 可以是 32 字节 topic 或事件签名文本；topics 传入完整 topics 列表时
    （logs 里的 topics），indexed 参数从 topics 取，否则从 data 取。
    """
    if isinstance(topic0, str):
        key = topic0.strip()
        if key in EVENT_TOPICS:
            t0 = EVENT_TOPICS[key]
        elif key.startswith("0x") or re.fullmatch(r"[0-9a-fA-F]{64}", key):
            t0 = _as_bytes(key)
        else:
            t0 = keccak256(key.encode())
    else:
        t0 = bytes(topic0)
    d = _as_bytes(data) if data else b""
    topics = [_as_bytes(t) for t in (topics or [])]
    indexed = []
    if len(topics) > 1:
        # 跳过 topic0
        start = 1 if topics and topics[0] == t0 else 0
        indexed = [t for t in topics[start:]]

    def addr_from_topic(t):
        return eip55_checksum(t[-20:])

    out = {"topic0": "0x" + t0.hex(), "data_hex": d.hex(), "decoded": False}

    if t0 == EVENT_TOPICS["Transfer(address,address,uint256)"]:
        out["event"] = "Transfer"
        if len(indexed) >= 3:              # ERC721 / ERC1155 风格：from, to, tokenId 都 indexed
            out.update({"standard": "ERC721",
                        "from": addr_from_topic(indexed[0]),
                        "to": addr_from_topic(indexed[1]),
                        "token_id": int.from_bytes(indexed[2], "big"),
                        "value": 1, "decoded": True})
        elif len(indexed) == 2:            # 标准 ERC20：from/to indexed，value 在 data
            out.update({"standard": "ERC20",
                        "from": addr_from_topic(indexed[0]),
                        "to": addr_from_topic(indexed[1]),
                        "value": _word_uint(d, 0), "decoded": True})
        else:                              # 只有 topic0：全部在 data（非规范但常见于手工构造样本）
            out.update({"standard": "ERC20",
                        "from": _word_addr(d, 0),
                        "to": _word_addr(d, 1),
                        "value": _word_uint(d, 2), "decoded": True})
        v = out.get("value")
        if v is not None:
            out["value_raw"] = str(v)
        return out

    if t0 == EVENT_TOPICS["Approval(address,address,uint256)"]:
        out["event"] = "Approval"
        if len(indexed) >= 3:
            out.update({"owner": addr_from_topic(indexed[0]), "spender": addr_from_topic(indexed[1]),
                        "value": int.from_bytes(indexed[2], "big"), "decoded": True})
        elif len(indexed) == 2:
            out.update({"owner": addr_from_topic(indexed[0]), "spender": addr_from_topic(indexed[1]),
                        "value": _word_uint(d, 0), "decoded": True})
        else:
            out.update({"owner": _word_addr(d, 0), "spender": _word_addr(d, 1),
                        "value": _word_uint(d, 2), "decoded": True})
        return out

    if t0 == EVENT_TOPICS["Swap(address,uint256,uint256,uint256,uint256,address)"]:
        out["event"] = "UniswapV2Swap"
        out.update({
            "sender": addr_from_topic(indexed[0]) if len(indexed) >= 1 else _word_addr(d, 4),
            "to": addr_from_topic(indexed[1]) if len(indexed) >= 2 else _word_addr(d, 5),
            "amount0In": _word_uint(d, 0),
            "amount1In": _word_uint(d, 1),
            "amount0Out": _word_uint(d, 2),
            "amount1Out": _word_uint(d, 3),
            "decoded": True,
        })
        return out

    if t0 == EVENT_TOPICS["Swap(address,address,int256,int256,uint160,uint128,int24)"]:
        out["event"] = "UniswapV3Swap"
        out.update({
            "sender": addr_from_topic(indexed[0]) if len(indexed) >= 1 else _word_addr(d, 5),
            "recipient": addr_from_topic(indexed[1]) if len(indexed) >= 2 else _word_addr(d, 6),
            "amount0": _word_int(d, 0),
            "amount1": _word_int(d, 1),
            "sqrtPriceX96": _word_uint(d, 2),
            "liquidity": _word_uint(d, 3),
            "tick": _word_int(d, 4),
            "decoded": True,
        })
        return out

    if t0 == EVENT_TOPICS["Sync(uint112,uint112)"]:
        out["event"] = "UniswapV2Sync"
        out.update({"reserve0": _word_uint(d, 0), "reserve1": _word_uint(d, 1), "decoded": True})
        return out

    if t0 == EVENT_TOPICS["Deposit(address,uint256)"]:
        out["event"] = "WETHDeposit"
        out.update({"dst": addr_from_topic(indexed[0]) if indexed else _word_addr(d, 0),
                    "wad": _word_uint(d, 0 if indexed else 1), "decoded": True})
        return out

    if t0 == EVENT_TOPICS["Withdrawal(address,uint256)"]:
        out["event"] = "WETHWithdrawal"
        out.update({"src": addr_from_topic(indexed[0]) if indexed else _word_addr(d, 0),
                    "wad": _word_uint(d, 0 if indexed else 1), "decoded": True})
        return out

    out["event"] = "unknown"
    return out


def token_amount(raw, decimals):
    """原始最小单位 -> 人类可读字符串（USDT=6, ETH/DAI=18, WBTC=8）。"""
    return str(Decimal(int(raw)) / (Decimal(10) ** int(decimals)))


def decode_calldata(data):
    """解码带 4 字节选择器的合约调用 calldata。

    覆盖 ERC20 常用方法与 Uniswap V2 Router 的 swap* 系列（含动态 address[] path）。
    返回 dict：selector / name / signature / args(dict) / args_raw(list) / decoded。
    """
    d = _as_bytes(data) if data else b""
    out = {"selector": d[:4].hex() if len(d) >= 4 else None, "name": None,
           "signature": None, "args": {}, "args_raw": [], "decoded": False}
    if len(d) < 4:
        out["error"] = "calldata shorter than 4 bytes"
        return out
    sel = d[:4].hex()
    body = d[4:]
    name = _selector_name(sel)
    out["signature"] = name

    def words(n):
        return [body[i * 32:(i + 1) * 32] for i in range(n)]

    if sel == "a9059cbb":                       # transfer(address,uint256)
        w = words(2)
        out.update({"name": "transfer", "decoded": True,
                    "args": {"to": eip55_checksum(w[0][12:]), "amount": int.from_bytes(w[1], "big")},
                    "args_raw": [w[0].hex(), w[1].hex()]})
        return out
    if sel == "23b872dd":                       # transferFrom(address,address,uint256)
        w = words(3)
        out.update({"name": "transferFrom", "decoded": True,
                    "args": {"from": eip55_checksum(w[0][12:]), "to": eip55_checksum(w[1][12:]),
                             "amount": int.from_bytes(w[2], "big")},
                    "args_raw": [x.hex() for x in w]})
        return out
    if sel == "095ea7b3":                       # approve(address,uint256)
        w = words(2)
        out.update({"name": "approve", "decoded": True,
                    "args": {"spender": eip55_checksum(w[0][12:]), "amount": int.from_bytes(w[1], "big")},
                    "args_raw": [x.hex() for x in w]})
        return out
    if sel == "70a08231":                       # balanceOf(address)
        w = words(1)
        out.update({"name": "balanceOf", "decoded": True,
                    "args": {"owner": eip55_checksum(w[0][12:])}, "args_raw": [w[0].hex()]})
        return out
    if sel == "dd62ed3e":                       # allowance(address,address)
        w = words(2)
        out.update({"name": "allowance", "decoded": True,
                    "args": {"owner": eip55_checksum(w[0][12:]), "spender": eip55_checksum(w[1][12:])},
                    "args_raw": [x.hex() for x in w]})
        return out

    swap_v2 = {
        "38ed1739": ("swapExactTokensForTokens", "amountIn", "amountOutMin", "to", "deadline"),
        "8803dbee": ("swapTokensForExactTokens", "amountOut", "amountInMax", "to", "deadline"),
        "18cbafe5": ("swapExactTokensForETH", "amountIn", "amountOutMin", "to", "deadline"),
        "4a25d94a": ("swapTokensForExactETH", "amountOut", "amountInMax", "to", "deadline"),
        "7ff36ab5": ("swapExactETHForTokens", None, "amountOutMin", "to", "deadline"),
        "fb3bdb41": ("swapETHForExactTokens", None, "amountOut", "to", "deadline"),
        "5c11d795": ("swapExactTokensForTokensSupportingFeeOnTransferTokens",
                     "amountIn", "amountOutMin", "to", "deadline"),
        "791ac947": ("swapExactTokensForETHSupportingFeeOnTransferTokens",
                     "amountIn", "amountOutMin", "to", "deadline"),
        "b6f9de95": ("swapExactETHForTokensSupportingFeeOnTransferTokens",
                     None, "amountOutMin", "to", "deadline"),
    }
    if sel in swap_v2:
        fname, amt_in, amt_out, to_lbl, dl_lbl = swap_v2[sel]
        # ABI 头：(amountIn?)(amountOutMin|amountOut) offset(path) to deadline
        n_head = 5 if amt_in else 4
        w = words(n_head)
        args = {}
        idx = 0
        if amt_in:
            args[amt_in] = int.from_bytes(w[idx], "big")
            idx += 1
        args[amt_out] = int.from_bytes(w[idx], "big")
        idx += 1
        path_off = int.from_bytes(w[idx], "big")
        idx += 1
        args[to_lbl] = eip55_checksum(w[idx][12:])
        idx += 1
        args[dl_lbl] = int.from_bytes(w[idx], "big")
        # 动态 address[] path
        if path_off and path_off + 32 <= len(body):
            ln = int.from_bytes(body[path_off:path_off + 32], "big")
            path = []
            for k in range(min(ln, 8)):
                s = path_off + 32 + k * 32
                if s + 32 > len(body):
                    break
                path.append(eip55_checksum(body[s + 12:s + 32]))
            args["path"] = path
        out.update({"name": fname, "decoded": True, "args": args,
                    "args_raw": [x.hex() for x in w]})
        return out

    out["name"] = None
    out["args_raw"] = [body[i * 32:(i + 1) * 32].hex() for i in range(len(body) // 32)]
    return out


def token_transfers_from_receipts(receipts):
    """从交易回执列表里汇总 ERC20/721 Transfer。

    receipts 元素需含 logs（address/topics/data），可带 txHash/blockNumber/logIndex。
    """
    transfers = []
    for rc in receipts:
        if not isinstance(rc, dict):
            continue
        for idx, log in enumerate(rc.get("logs") or []):
            topics = log.get("topics") or []
            if not topics:
                continue
            t0 = _as_bytes(topics[0])
            if t0 != EVENT_TOPICS["Transfer(address,address,uint256)"]:
                continue
            dec = defi_swap_decode(t0, log.get("data") or b"", topics)
            token = log.get("address")
            token_l = token.lower() if token else None
            rec = {
                "tx_hash": rc.get("transactionHash") or rc.get("txHash"),
                "block": rc.get("blockNumber"),
                "log_index": log.get("logIndex", idx),
                "token": eip55_checksum(token) if token else None,
                "token_known": KNOWN_CONTRACTS.get(token_l) if token_l else None,
                "standard": dec.get("standard"),
                "from": dec.get("from"),
                "to": dec.get("to"),
                "value": dec.get("value"),
                "token_id": dec.get("token_id"),
                "raw": dec,
            }
            v = rec["value"]
            if rec["token_known"] and "USDT" in rec["token_known"] and isinstance(v, int):
                rec["value_usdt"] = str(Decimal(v) / Decimal(10 ** 6))
            transfers.append(rec)
    return transfers


# ---------------------------------------------------------------------------
# 便捷自检
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("keccak256(b'') =", keccak256(b"").hex())
    print("keccak256(b'abc') =", keccak256(b"abc").hex())
    print("addr(0x01) =", eth_address_from_privkey(1))
    print("transfer selector =", keccak256(b"transfer(address,uint256)")[:4].hex())
