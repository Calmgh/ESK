# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""LUKS1 / LUKS2 头部解析

对应 LovelyCarve 的「加密与快照」里的 LUKS 部分——**只做识别与取证信息提取**。

能力范围（重要）：
    ✓ 识别 LUKS1 / LUKS2
    ✓ 解析加密算法、模式、哈希、密钥长度、UUID、payload 偏移
    ✓ 枚举密钥槽（哪些是激活的、PBKDF2 迭代次数、盐）
    ✓ 解析 LUKS2 的 JSON 元数据（cipher / pbkdf / slots / segments）
    ✗ 不实现解锁（af_split/af_merge 尚未在真实卷上验证，不放进发行版）

为什么不做解锁：
    解 LUKS 需要 PBKDF2 + AF 分联合并 + 密码模式实现三步全部正确，
    任何一步有细微偏差都会静默解出乱码——比"报告不能解"更危险。
    当前没有可用的真实 LUKS 卷做回归验证，所以只做到头部，如实标注。

取证价值：
    拿到头部就能回答「这盘是不是加密的、用的什么算法、有几个槽、
    密码强度线索（迭代次数）」，已经够定位方向和写报告了。
"""

import json
import struct

__all__ = ["Luks", "detect", "describe"]

LUKS_MAGIC = b"LUKS\xba\xbe"

LUKS1_HEADER_SIZE = 592
LUKS2_BINARY_HEADER_SIZE = 4096


class KeySlot(object):
    """LUKS1 密钥槽"""

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
    """LUKS 头部（1 或 2）"""

    def __init__(self, sub):
        """sub: 有 read(offset, size) 的对象（分区或镜像）"""
        self.sub = sub
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
