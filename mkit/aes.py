# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""自研 AES 实现（纯标准库，无第三方依赖）。

支持 AES-128 / AES-192 / AES-256 的单块加解密与 CBC 模式。
S-box 与 T-table 在导入时由 GF(2^8) 运算生成，不使用硬编码查表，便于审计。

正确性基准：
  * FIPS-197 附录 B/C 官方测试向量（单块，128/192/256 位密钥）
  * NIST SP 800-38A CBC 测试向量
  * 与 pycryptodome 随机对拍（见 verify_mobile.py）
"""

__all__ = ["AES", "cbc_encrypt", "cbc_decrypt", "encrypt_block", "decrypt_block"]


# --------------------------------------------------------------------------
# GF(2^8) 与查表生成
# --------------------------------------------------------------------------
def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = _xtime(a)
    return r


def _build_sbox():
    """用 GF(2^8) 乘法逆元 + 仿射变换生成 S-box（FIPS-197 5.1.1）。"""
    sbox = [0] * 256
    p = q = 1
    while True:
        # p 遍历 GF(2^8) 乘法群，q 为 p 的逆元（q *= 3 的等价变形）
        p = p ^ _xtime(p)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
            ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


SBOX = _build_sbox()
INV_SBOX = bytearray(256)
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
INV_SBOX = bytes(INV_SBOX)


def _ror32(w, n):
    return ((w >> n) | (w << (32 - n))) & 0xFFFFFFFF


def _build_tables():
    te0 = [0] * 256
    td0 = [0] * 256
    for i in range(256):
        s = SBOX[i]
        te0[i] = ((_gmul(s, 2) << 24) | (s << 16) | (s << 8) | _gmul(s, 3)) & 0xFFFFFFFF
        si = INV_SBOX[i]
        td0[i] = ((_gmul(si, 14) << 24) | (_gmul(si, 9) << 16)
                  | (_gmul(si, 13) << 8) | _gmul(si, 11)) & 0xFFFFFFFF
    te = [te0]
    td = [td0]
    for n in (1, 2, 3):
        te.append([_ror32(w, 8 * n) for w in te0])
        td.append([_ror32(w, 8 * n) for w in td0])
    return te, td


TE0, TE1, TE2, TE3 = None, None, None, None
TD0, TD1, TD2, TD3 = None, None, None, None
_te, _td = _build_tables()
TE0, TE1, TE2, TE3 = _te
TD0, TD1, TD2, TD3 = _td

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D]


class AES:
    """单密钥 AES 上下文，复用轮密钥做多块加解密。"""

    __slots__ = ("key", "nrounds", "rk", "drk")

    def __init__(self, key):
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16/24/32 bytes, got %d" % len(key))
        self.key = key
        self.nrounds = {16: 10, 24: 12, 32: 14}[len(key)]
        self.rk = self._expand(key)
        self.drk = self._decrypt_schedule()

    # ---------------- 密钥扩展 ----------------
    def _expand(self, key):
        nk = len(key) // 4
        nr = self.nrounds
        w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            t = w[i - 1]
            if i % nk == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = ((SBOX[(t >> 24) & 0xFF] << 24) | (SBOX[(t >> 16) & 0xFF] << 16)
                     | (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF])
                t ^= RCON[i // nk - 1] << 24
            elif nk > 6 and i % nk == 4:
                t = ((SBOX[(t >> 24) & 0xFF] << 24) | (SBOX[(t >> 16) & 0xFF] << 16)
                     | (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF])
            w.append(w[i - nk] ^ t)
        return w

    def _decrypt_schedule(self):
        """等价逆密码的轮密钥（FIPS-197 5.3.5）。"""
        nr = self.nrounds
        rk = self.rk
        drk = list(rk[4 * nr:4 * nr + 4])
        for r in range(nr - 1, 0, -1):
            for j in range(4):
                t = rk[4 * r + j]
                if r > 0:
                    t = (TD0[SBOX[(t >> 24) & 0xFF]] ^ TD1[SBOX[(t >> 16) & 0xFF]]
                         ^ TD2[SBOX[(t >> 8) & 0xFF]] ^ TD3[SBOX[t & 0xFF]])
                drk.append(t)
        drk.extend(rk[0:4])
        return drk

    # ---------------- 单块 ----------------
    def encrypt_block(self, block):
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        rk = self.rk
        s0 = int.from_bytes(block[0:4], "big") ^ rk[0]
        s1 = int.from_bytes(block[4:8], "big") ^ rk[1]
        s2 = int.from_bytes(block[8:12], "big") ^ rk[2]
        s3 = int.from_bytes(block[12:16], "big") ^ rk[3]
        k = 4
        for _ in range(self.nrounds - 1):
            t0 = TE0[s0 >> 24] ^ TE1[(s1 >> 16) & 0xFF] ^ TE2[(s2 >> 8) & 0xFF] ^ TE3[s3 & 0xFF] ^ rk[k]
            t1 = TE0[s1 >> 24] ^ TE1[(s2 >> 16) & 0xFF] ^ TE2[(s3 >> 8) & 0xFF] ^ TE3[s0 & 0xFF] ^ rk[k + 1]
            t2 = TE0[s2 >> 24] ^ TE1[(s3 >> 16) & 0xFF] ^ TE2[(s0 >> 8) & 0xFF] ^ TE3[s1 & 0xFF] ^ rk[k + 2]
            t3 = TE0[s3 >> 24] ^ TE1[(s0 >> 16) & 0xFF] ^ TE2[(s1 >> 8) & 0xFF] ^ TE3[s2 & 0xFF] ^ rk[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        sb = SBOX
        o0 = ((sb[s0 >> 24] << 24) | (sb[(s1 >> 16) & 0xFF] << 16)
              | (sb[(s2 >> 8) & 0xFF] << 8) | sb[s3 & 0xFF]) ^ rk[k]
        o1 = ((sb[s1 >> 24] << 24) | (sb[(s2 >> 16) & 0xFF] << 16)
              | (sb[(s3 >> 8) & 0xFF] << 8) | sb[s0 & 0xFF]) ^ rk[k + 1]
        o2 = ((sb[s2 >> 24] << 24) | (sb[(s3 >> 16) & 0xFF] << 16)
              | (sb[(s0 >> 8) & 0xFF] << 8) | sb[s1 & 0xFF]) ^ rk[k + 2]
        o3 = ((sb[s3 >> 24] << 24) | (sb[(s0 >> 16) & 0xFF] << 16)
              | (sb[(s1 >> 8) & 0xFF] << 8) | sb[s2 & 0xFF]) ^ rk[k + 3]
        return o0.to_bytes(4, "big") + o1.to_bytes(4, "big") + o2.to_bytes(4, "big") + o3.to_bytes(4, "big")

    def decrypt_block(self, block):
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        drk = self.drk
        s0 = int.from_bytes(block[0:4], "big") ^ drk[0]
        s1 = int.from_bytes(block[4:8], "big") ^ drk[1]
        s2 = int.from_bytes(block[8:12], "big") ^ drk[2]
        s3 = int.from_bytes(block[12:16], "big") ^ drk[3]
        k = 4
        for _ in range(self.nrounds - 1):
            t0 = TD0[s0 >> 24] ^ TD1[(s3 >> 16) & 0xFF] ^ TD2[(s2 >> 8) & 0xFF] ^ TD3[s1 & 0xFF] ^ drk[k]
            t1 = TD0[s1 >> 24] ^ TD1[(s0 >> 16) & 0xFF] ^ TD2[(s3 >> 8) & 0xFF] ^ TD3[s2 & 0xFF] ^ drk[k + 1]
            t2 = TD0[s2 >> 24] ^ TD1[(s1 >> 16) & 0xFF] ^ TD2[(s0 >> 8) & 0xFF] ^ TD3[s3 & 0xFF] ^ drk[k + 2]
            t3 = TD0[s3 >> 24] ^ TD1[(s2 >> 16) & 0xFF] ^ TD2[(s1 >> 8) & 0xFF] ^ TD3[s0 & 0xFF] ^ drk[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        ib = INV_SBOX
        o0 = ((ib[s0 >> 24] << 24) | (ib[(s3 >> 16) & 0xFF] << 16)
              | (ib[(s2 >> 8) & 0xFF] << 8) | ib[s1 & 0xFF]) ^ drk[k]
        o1 = ((ib[s1 >> 24] << 24) | (ib[(s0 >> 16) & 0xFF] << 16)
              | (ib[(s3 >> 8) & 0xFF] << 8) | ib[s2 & 0xFF]) ^ drk[k + 1]
        o2 = ((ib[s2 >> 24] << 24) | (ib[(s1 >> 16) & 0xFF] << 16)
              | (ib[(s0 >> 8) & 0xFF] << 8) | ib[s3 & 0xFF]) ^ drk[k + 2]
        o3 = ((ib[s3 >> 24] << 24) | (ib[(s2 >> 16) & 0xFF] << 16)
              | (ib[(s1 >> 8) & 0xFF] << 8) | ib[s0 & 0xFF]) ^ drk[k + 3]
        return o0.to_bytes(4, "big") + o1.to_bytes(4, "big") + o2.to_bytes(4, "big") + o3.to_bytes(4, "big")


# --------------------------------------------------------------------------
# CBC 模式（无填充：调用方保证长度为 16 的整数倍）
# --------------------------------------------------------------------------
def cbc_encrypt(key, iv, data):
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    if len(data) % 16:
        raise ValueError("data length must be a multiple of 16")
    c = AES(key)
    out = bytearray(len(data))
    prev = bytes(iv)
    for off in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        prev = c.encrypt_block(blk)
        out[off:off + 16] = prev
    return bytes(out)


def cbc_decrypt(key, iv, data):
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    if len(data) % 16:
        raise ValueError("data length must be a multiple of 16")
    c = AES(key)
    out = bytearray(len(data))
    prev = bytes(iv)
    for off in range(0, len(data), 16):
        cur = data[off:off + 16]
        plain = c.decrypt_block(cur)
        out[off:off + 16] = bytes(a ^ b for a, b in zip(plain, prev))
        prev = cur
    return bytes(out)


def encrypt_block(key, block):
    return AES(key).encrypt_block(block)


def decrypt_block(key, block):
    return AES(key).decrypt_block(block)
