"""mkit.tpmseal —— BitLocker TPM 保护者元数据取证枚举与「离线可行性」判定。

范围（刻意收窄）
----------------
本模块**只解析结构、只做判定**：

* TPML_PCR_SELECTION（PCR 策略：哪些 PCR、哪些哈希算法）
* TPM2B_PUBLIC（密封对象的类型 / 属性 / 算法参数 / 曲线）
* TPM2B_PRIVATE（integrity TPM2B 的长度与尾部剩余字节）
* BitLocker FVEK 保护者类型（恢复密码 / TPM / 启动密钥 / 明文密钥 /
  用户密码 / 用户证书）

为什么不解封
------------
TPM 2.0 的 BitLocker 保护者是把 VMK 用 **SRK（storage root key）之下的
storage key** 做 TPM2_Create/TPM2_Unseal 封装的。SRK 的私钥部分由芯片内的
Storage Primary Seed 派生，**永远不出芯片**；PCR 策略又是在 TPM 内部对
TPM2_PolicyPCR 的 digest 做比对。也就是说：

  * 没有可用的 TPM（或没有该 TPM 的 seed / 没有 owner 授权）时，
    TPM2B_PRIVATE 里的 sensitive 部分是**密码学不可解**的，不是"缺代码"；
  * 离线取证镜像里**不含**任何能替代芯片的材料；
  * 因此本模块只回答"这台机器的卷能不能用现有材料解开"，并且当保护者是
    TPM 时**明确报告不能**。

刻意不提供 unseal / decrypt / derive / unwrap 之类入口 —— 见 `__main__`
里的边界断言。真实可行的路径只有：恢复密码、.BEK 启动密钥、clear key，
这三者在 `can_unlock_offline()` 里被标为 offline=True。
"""

from __future__ import annotations

import struct

__all__ = [
    "TpmSealError",
    "PCR_ALGS",
    "PCR_ALG_NAMES",
    "OBJECT_TYPES",
    "PROTECTOR_TYPES",
    "CURVES",
    "parse_pcr_selection",
    "format_pcrs",
    "parse_public",
    "parse_private",
    "describe_protector",
    "can_unlock_offline",
    "describe",
]


class TpmSealError(ValueError):
    """TPM / BitLocker 保护者元数据结构解析失败。"""


# ---------------------------------------------------------------- 常量表

PCR_ALGS = {"SHA1": 0x0004, "SHA256": 0x000B, "SHA384": 0x000C, "SHA512": 0x000D}
PCR_ALG_NAMES = {v: k for k, v in PCR_ALGS.items()}

#: TPM2_ALG_ID -> TPMI_ALG_PUBLIC 名称（仅本模块关心的四种）
OBJECT_TYPES = {
    0x0001: "RSA",
    0x0008: "KEYEDHASH",
    0x0023: "ECC",
    0x0025: "SYMCIPHER",
}

#: BitLocker FVEK 保护者类型（FVEK protector type）
PROTECTOR_TYPES = {
    0x0000: "recovery password",
    0x0100: "TPM",
    0x0200: "startup key (.BEK)",
    0x0400: "clear key",
    0x0800: "user password",
    0x1000: "user certificate",
}

CURVES = {0x0003: "NIST P256", 0x0004: "NIST P384", 0x0005: "NIST P521"}

#: 保护者 -> 是否可能用「镜像里已有的材料」离线解开（不解封，只判定）
_PROTECTOR_OFFLINE = {
    0x0000: (True, "48 位数字恢复密码可直接离线提供，与 TPM 无关"),
    0x0100: (False, "需要 TPM 解封（SRK/storage key 在芯片内，镜像里没有）"),
    0x0200: (True, "启动密钥 .BEK 文件可离线提供（U 盘/外部介质）"),
    0x0400: (True, "FVEK 以明文存放（clear key），无需任何解封"),
    0x0800: (False, "需要用户口令"),
    0x1000: (False, "需要证书私钥（智能卡/证书存储）"),
}


# ---------------------------------------------------------------- 底层读取

def _as_bytes(data):
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    raise TpmSealError("expected bytes-like input, got %r" % type(data).__name__)


def _need(data, off, n, what="field"):
    if off < 0 or off + n > len(data):
        raise TpmSealError(
            "truncated %s: need %d byte(s) at offset %d, have %d"
            % (what, n, off, max(0, len(data) - off))
        )


def _u8(data, off, what="u8"):
    _need(data, off, 1, what)
    return data[off], off + 1


def _u16(data, off, what="u16"):
    _need(data, off, 2, what)
    return struct.unpack_from(">H", data, off)[0], off + 2


def _u32(data, off, what="u32"):
    _need(data, off, 4, what)
    return struct.unpack_from(">I", data, off)[0], off + 4


def _tpm2b(data, off, what="tpm2b"):
    size, p = _u16(data, off, what + " size")
    _need(data, p, size, what + " body")
    return data[p:p + size], p + size


def _alg_name(alg):
    return PCR_ALG_NAMES.get(alg, "0x%04X" % alg)


def _hexs(b, n=8):
    return bytes(b[:n]).hex()


# ---------------------------------------------------------------- 1. PCR

def parse_pcr_selection(data, off=0):
    """解析 TPML_PCR_SELECTION。

    布局::

        UINT32 count
        repeat count:
            UINT16 hash_alg          (0x0004 SHA1 / 0x000B SHA256 / 0x000C SHA384 / 0x000D SHA512)
            UINT8  sizeofSelect
            BYTE   pcrSelect[sizeofSelect]   # 位图，第 i 位 = PCR i（跨字节）

    返回 {"size", "count", "pcrs": {alg_name: [i, ...]}, "selections": [...]}
    """
    data = _as_bytes(data)
    count, p = _u32(data, off, "PCR selection count")
    if count == 0:
        raise TpmSealError("PCR selection count is zero (not a TPML_PCR_SELECTION)")
    if count > 64:
        raise TpmSealError("PCR selection count %d is implausible" % count)

    selections = []
    for idx in range(count):
        alg, p = _u16(data, p, "PCR selection[%d].hash_alg" % idx)
        nsel, p = _u8(data, p, "PCR selection[%d].sizeofSelect" % idx)
        if nsel == 0 or nsel > 8:
            raise TpmSealError("PCR selection[%d].sizeofSelect %d out of range 1..8" % (idx, nsel))
        _need(data, p, nsel, "PCR selection[%d].pcrSelect" % idx)
        bitmap = data[p:p + nsel]
        p += nsel
        pcrs = []
        for byte_index, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (1 << bit):
                    pcrs.append(byte_index * 8 + bit)
        selections.append({
            "hash_alg": alg,
            "hash_alg_name": _alg_name(alg),
            "sizeofSelect": nsel,
            "pcrSelect": bytes(bitmap).hex(),
            "pcrs": pcrs,
        })

    merged = {}
    for sel in selections:
        bucket = merged.setdefault(sel["hash_alg_name"], [])
        for v in sel["pcrs"]:
            if v not in bucket:
                bucket.append(v)
    for key in merged:
        merged[key].sort()

    return {
        "size": p - off,
        "count": count,
        "pcrs": merged,
        "selections": selections,
    }


def format_pcrs(info):
    """把 PCR 选择渲染成 `"SHA256: 0,2,4,7 | SHA1: 0"`。"""
    if isinstance(info, dict) and "pcrs" in info:
        pcrs = info["pcrs"]
    elif isinstance(info, dict):
        pcrs = info
    else:
        raise TpmSealError("format_pcrs expects a dict from parse_pcr_selection")

    # 展示顺序：PCR 数量多的算法优先（信息量大的策略在前），同数量按名字
    order = sorted(pcrs, key=lambda n: (-len({int(v) for v in pcrs[n]}), str(n)))
    parts = []
    for name in order:
        values = sorted({int(v) for v in pcrs[name]})
        parts.append("%s: %s" % (name, ",".join(str(v) for v in values) if values else "(none)"))
    return " | ".join(parts)


# ---------------------------------------------------------------- 2. PUBLIC

def _parse_sym_def(data, off, what):
    alg, p = _u16(data, off, what + ".alg")
    key_bits, p = _u16(data, p, what + ".keyBits")
    mode, p = _u16(data, p, what + ".mode")
    return {"alg": alg, "alg_name": _alg_name(alg), "keyBits": key_bits, "mode": mode}, p


def _parse_scheme(data, off, what):
    alg, p = _u16(data, off, what + ".scheme")
    detail, p = _u16(data, p, what + ".details")
    return {"alg": alg, "alg_name": _alg_name(alg), "details": detail}, p


def parse_public(data, off=0):
    """解析 TPM2B_PUBLIC（不含外层 size，即 TPMT_PUBLIC 本体）。

    返回 dict：type / type_name / nameAlg / nameAlg_name / objectAttributes /
    authPolicy_len / rsa{...} 或 ecc{...} / size。
    """
    data = _as_bytes(data)
    start = off

    obj_type, p = _u16(data, off, "TPMT_PUBLIC.type")
    if obj_type not in OBJECT_TYPES:
        raise TpmSealError("unknown TPMT_PUBLIC type 0x%04X" % obj_type)

    name_alg, p = _u16(data, p, "TPMT_PUBLIC.nameAlg")
    attrs, p = _u32(data, p, "TPMT_PUBLIC.objectAttributes")
    auth_policy, p = _tpm2b(data, p, "TPMT_PUBLIC.authPolicy")

    out = {
        "offset": start,
        "type": obj_type,
        "type_name": OBJECT_TYPES[obj_type],
        "nameAlg": name_alg,
        "nameAlg_name": _alg_name(name_alg),
        "objectAttributes": attrs,
        "objectAttributes_hex": "0x%08X" % attrs,
        "authPolicy_len": len(auth_policy),
        "authPolicy": bytes(auth_policy).hex(),
        "rsa": None,
        "ecc": None,
        "symcipher": None,
        "keyedhash": None,
        "params_len": 0,
    }

    if obj_type == 0x0001:  # RSA
        sym, p = _parse_sym_def(data, p, "TPMS_RSA_PARMS.symmetric")
        scheme, p = _parse_scheme(data, p, "TPMT_RSA_SCHEME")
        key_bits, p = _u16(data, p, "TPMS_RSA_PARMS.keyBits")
        exp_raw, p = _u32(data, p, "TPMS_RSA_PARMS.exponent")
        modulus_len = None
        modulus_head = None
        if p + 2 <= len(data):
            # TPM2B_PUBLIC_KEY_RSA 可能被省略（仅参数区）
            try:
                modulus, q = _tpm2b(data, p, "TPM2B_PUBLIC_KEY_RSA")
            except TpmSealError:
                modulus, q = None, p
            if modulus is not None:
                modulus_len = len(modulus)
                modulus_head = _hexs(modulus)
                p = q
        out["rsa"] = {
            "symmetric": sym,
            "scheme": scheme,
            "keyBits": key_bits,
            "exponent_raw": exp_raw,
            # TPM/FIPS 约定：exponent = 0 等价于 65537（2^16+1）
            "exponent": 65537 if exp_raw == 0 else exp_raw,
            "modulus_len": modulus_len,
            "modulus_head": modulus_head,
        }

    elif obj_type == 0x0023:  # ECC
        sym, p = _parse_sym_def(data, p, "TPMS_ECC_PARMS.symmetric")
        scheme, p = _parse_scheme(data, p, "TPMT_ECC_SCHEME")
        curve_id, p = _u16(data, p, "TPMS_ECC_PARMS.curveID")
        kdf, p = _parse_scheme(data, p, "TPMT_KDF_SCHEME")
        point_len = None
        point_head = None
        if p + 2 <= len(data):
            try:
                point, q = _tpm2b(data, p, "TPM2B_ECC_POINT")
            except TpmSealError:
                point, q = None, p
            if point is not None:
                point_len = len(point)
                point_head = _hexs(point)
                p = q
        out["ecc"] = {
            "symmetric": sym,
            "scheme": scheme,
            "curveID": curve_id,
            "curve_name": CURVES.get(curve_id, "0x%04X" % curve_id),
            "kdf": kdf,
            "point_len": point_len,
            "point_head": point_head,
        }

    elif obj_type == 0x0008:  # KEYEDHASH
        scheme, p = _parse_scheme(data, p, "TPMT_KEYEDHASH_SCHEME")
        out["keyedhash"] = {"scheme": scheme, "unique_len": None}
        if p + 2 <= len(data):
            try:
                unique, q = _tpm2b(data, p, "TPM2B_DIGEST")
            except TpmSealError:
                unique, q = None, p
            if unique is not None:
                out["keyedhash"]["unique_len"] = len(unique)
                p = q

    else:  # 0x0025 SYMCIPHER
        sym, p = _parse_sym_def(data, p, "TPMS_SYMCIPHER_PARMS.symmetric")
        out["symcipher"] = {"symmetric": sym, "unique_len": None}
        if p + 2 <= len(data):
            try:
                unique, q = _tpm2b(data, p, "TPM2B_DIGEST")
            except TpmSealError:
                unique, q = None, p
            if unique is not None:
                out["symcipher"]["unique_len"] = len(unique)
                p = q

    out["params_len"] = p - start
    out["size"] = p - start
    return out


# ---------------------------------------------------------------- 3. PRIVATE

def parse_private(data):
    """解析 TPM2B_PRIVATE 的头部结构。

    布局：`UINT16 integrity_size + BYTE integrity[integrity_size] + sensitive[...]`

    只报告 integrity 长度与尾部未消费字节数；sensitive 部分是芯片内密钥
    加密的，这里不解、不猜。
    """
    data = _as_bytes(data)
    if len(data) < 4:
        raise TpmSealError("TPM2B_PRIVATE too short (%d bytes)" % len(data))
    size, p = _u16(data, 0, "TPM2B_PRIVATE.integrity size")
    if size == 0:
        raise TpmSealError("TPM2B_PRIVATE integrity size is zero (not a sealed blob)")
    _need(data, p, size, "TPM2B_PRIVATE.integrity")
    p += size
    trailing = len(data) - p
    return {
        "total": len(data),
        "integrity_len": size,
        "consumed": p,
        "sensitive_len": trailing,
        "trailing": trailing,
        "has_trailing": trailing > 0,
        "integrity_head": _hexs(data[2:2 + min(size, 8)]),
    }


# ---------------------------------------------------------------- 4. 保护者

def _protector_id(kind):
    """把 int / 十六进制字符串 / 名称统一成 (type_id, name)。"""
    if isinstance(kind, dict):
        for key in ("type_id", "id", "kind", "type"):
            if key in kind:
                return _protector_id(kind[key])
        raise TpmSealError("protector dict has no type field: %r" % sorted(kind))
    if isinstance(kind, bool):
        raise TpmSealError("protector type must not be bool")
    if isinstance(kind, int):
        tid = kind
    elif isinstance(kind, str):
        text = kind.strip()
        low = text.lower()
        for tid_, name in PROTECTOR_TYPES.items():
            if low == name.lower() or low == "0x%04x" % tid_ or low == "0x%x" % tid_:
                return tid_, name
        try:
            tid = int(text, 0)
        except ValueError:
            raise TpmSealError("unknown protector type name %r" % kind) from None
    else:
        raise TpmSealError("unsupported protector type %r" % type(kind).__name__)

    if tid not in PROTECTOR_TYPES:
        raise TpmSealError(
            "unknown BitLocker protector type 0x%04X (known: %s)"
            % (tid, ", ".join("0x%04X" % k for k in sorted(PROTECTOR_TYPES)))
        )
    return tid, PROTECTOR_TYPES[tid]


def describe_protector(kind, data=b""):
    """枚举单个保护者：类型、是否可离线、原因、携带的 TPM 元数据。"""
    tid, name = _protector_id(kind)
    offline, reason = _PROTECTOR_OFFLINE[tid]
    try:
        raw = _as_bytes(data) if data is not None else b""
    except TpmSealError:
        raw = b""

    info = {
        "type": name,
        "type_id": tid,
        "type_hex": "0x%04X" % tid,
        "offline": offline,
        "reason": reason,
        "size": len(raw),
    }
    if tid == 0x0100 and raw:
        # TPM 保护者：附带结构枚举结果（describe 自身容错，不会抛）
        info["tpm"] = describe(raw)
    elif raw:
        info["head"] = _hexs(raw, 16)
    return info


def can_unlock_offline(protectors):
    """逐个保护者判定「现有材料能否离线解开」。不解封，只出结论。"""
    if protectors is None:
        raise TpmSealError("protectors must be a sequence")
    if isinstance(protectors, (int, str, dict)):
        protectors = [protectors]

    results = []
    for item in protectors:
        if isinstance(item, dict) and "offline" in item and "type" in item:
            # 已经是 describe_protector 的输出，补齐 type_id 即可
            tid, name = _protector_id(item.get("type_id", item["type"]))
            offline, reason = _PROTECTOR_OFFLINE[tid]
            results.append({
                "type": name,
                "type_id": tid,
                "offline": bool(offline),
                "reason": reason,
            })
            continue
        tid, name = _protector_id(item)
        offline, reason = _PROTECTOR_OFFLINE[tid]
        results.append({
            "type": name,
            "type_id": tid,
            "offline": bool(offline),
            "reason": reason,
        })
    return results


# ---------------------------------------------------------------- describe

def _scan_public(raw, limit=2048):
    """在 blob 里找第一个看起来合法的 TPMT_PUBLIC（启发式）。"""
    end = min(len(raw) - 6, limit)
    for off in range(0, max(0, end)):
        obj_type = int.from_bytes(raw[off:off + 2], "big")
        if obj_type not in OBJECT_TYPES:
            continue
        name_alg = int.from_bytes(raw[off + 2:off + 4], "big")
        if name_alg not in PCR_ALG_NAMES:
            continue
        try:
            info = parse_public(raw, off)
        except TpmSealError:
            continue
        # 合理性过滤：压低随机字节造成的假阳性
        if info["authPolicy_len"] > 64:
            continue
        ok = True
        if info["type_name"] == "RSA":
            ok = info["rsa"]["keyBits"] in (1024, 2048, 3072, 4096) and \
                info["rsa"]["exponent"] in (3, 65537)
        elif info["type_name"] == "ECC":
            ok = info["ecc"]["curveID"] in CURVES
        elif info["type_name"] == "SYMCIPHER":
            ok = info["symcipher"]["symmetric"]["alg"] not in (0, 0xFFFF)
        if not ok:
            continue
        info["heuristic"] = off != 0
        return info
    return None


def describe(data):
    """容错总入口：能认就给出结构化结果，认不出就 is_tpm=False + error。"""
    info = {"is_tpm": False, "size": 0, "error": None}
    try:
        raw = _as_bytes(data)
    except TpmSealError as exc:
        info["error"] = "bad input: %s" % exc
        return info

    info["size"] = len(raw)
    if len(raw) < 8:
        info["error"] = "too short (%d bytes) for TPM metadata" % len(raw)
        return info

    errors = []

    try:
        pcr = parse_pcr_selection(raw, 0)
        info["pcr_selection"] = pcr
        info["pcrs"] = pcr["pcrs"]
        info["pcrs_text"] = format_pcrs(pcr)
        info["is_tpm"] = True
    except TpmSealError as exc:
        errors.append("pcr: %s" % exc)

    pub = _scan_public(raw)
    if pub is not None:
        info["public"] = pub
        info["is_tpm"] = True
    else:
        errors.append("public: no TPMT_PUBLIC candidate found")

    if not info.get("pcr_selection"):
        try:
            info["private"] = parse_private(raw)
            info["is_tpm"] = True
        except TpmSealError as exc:
            errors.append("private: %s" % exc)

    if not info["is_tpm"] and errors:
        info["error"] = "; ".join(errors)
    return info


# ---------------------------------------------------------------- 自检

def _mk_pcr_selection(entries):
    body = struct.pack(">I", len(entries))
    for alg, pcrs in entries:
        nsel = max(3, (max(pcrs) // 8 + 1) if pcrs else 3)
        bitmap = bytearray(nsel)
        for i in pcrs:
            bitmap[i // 8] |= 1 << (i % 8)
        body += struct.pack(">HB", alg, nsel) + bytes(bitmap)
    return body


def _mk_public_rsa(key_bits=2048, exponent=0, include_modulus=True):
    b = struct.pack(">HHI", 0x0001, 0x000B, 0x00040072)
    b += struct.pack(">H", 0)                                # authPolicy size
    b += struct.pack(">HHH", 0x0010, 128, 0x0043)            # symmetric AES-128-CFB
    b += struct.pack(">HH", 0x0010, 0x0008)                  # scheme RSAPSS + SHA256
    b += struct.pack(">H", key_bits)
    b += struct.pack(">I", exponent)
    if include_modulus:
        modulus = bytes((i * 7 + 3) & 0xFF for i in range(key_bits // 8))
        b += struct.pack(">H", len(modulus)) + modulus
    return b


def _mk_public_ecc(curve=0x0003):
    b = struct.pack(">HHI", 0x0023, 0x000B, 0x00040072)
    b += struct.pack(">H", 0)
    b += struct.pack(">HHH", 0x0010, 128, 0x0043)            # symmetric
    b += struct.pack(">HH", 0x0010, 0x0008)                  # scheme
    b += struct.pack(">H", curve)                            # curveID
    b += struct.pack(">HH", 0x0010, 0x0008)                  # kdf
    point = b"\x04" + bytes(range(1, 33)) + bytes(range(33, 65))
    b += struct.pack(">H", len(point)) + point
    return b


def _mk_private(integrity_len=32, sensitive_len=170):
    integrity = bytes((i * 11 + 5) & 0xFF for i in range(integrity_len))
    sensitive = bytes((i * 13 + 1) & 0xFF for i in range(sensitive_len))
    return struct.pack(">H", len(integrity)) + integrity + sensitive


def _selftest():
    import sys
    # 自检输出刻意只用 ASCII：无论控制台是 cp936 还是 utf-8、无论 stdout 是否
    # 被管道/子进程捕获，都不会因编码炸掉或乱码。
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass
    module = sys.modules[__name__]
    passed = []

    def check(label, fn):
        fn()
        passed.append(label)
        print("PASS %02d %s" % (len(passed), label))

    # 1. PCR 位图跨字节
    def t01():
        raw = _mk_pcr_selection([(PCR_ALGS["SHA256"], [0, 7, 11, 17])])
        info = parse_pcr_selection(raw)
        assert info["count"] == 1, info
        assert info["pcrs"]["SHA256"] == [0, 7, 11, 17], info["pcrs"]
        # 17 号 PCR 落在第 3 字节的第 1 位
        assert info["selections"][0]["pcrSelect"] == "810802", info["selections"][0]
        assert info["size"] == 4 + 3 + 3, info["size"]
    check("PCR bitmap crosses byte boundaries (0/7/11/17 -> 81 08 02)", t01)

    # 2. 多算法
    def t02():
        raw = _mk_pcr_selection([(PCR_ALGS["SHA1"], [0]), (PCR_ALGS["SHA256"], [0, 2, 4, 7])])
        info = parse_pcr_selection(raw)
        assert set(info["pcrs"]) == {"SHA1", "SHA256"}, info["pcrs"]
        assert info["pcrs"]["SHA1"] == [0], info["pcrs"]
        assert info["pcrs"]["SHA256"] == [0, 2, 4, 7], info["pcrs"]
    check("multi-algorithm selection (SHA1 + SHA256 keys both present)", t02)

    # 3. format_pcrs
    def t03():
        raw = _mk_pcr_selection([(PCR_ALGS["SHA1"], [0]), (PCR_ALGS["SHA256"], [0, 2, 4, 7])])
        text = format_pcrs(parse_pcr_selection(raw))
        assert text == "SHA256: 0,2,4,7 | SHA1: 0", repr(text)
    check("format_pcrs output layout", t03)

    # 4. RSA-2048
    def t04():
        info = parse_public(_mk_public_rsa(2048, 0))
        assert info["type_name"] == "RSA", info
        assert info["nameAlg_name"] == "SHA256", info
        assert info["rsa"]["keyBits"] == 2048, info["rsa"]
        assert info["rsa"]["exponent_raw"] == 0 and info["rsa"]["exponent"] == 65537, info["rsa"]
        assert info["rsa"]["modulus_len"] == 256, info["rsa"]
        assert info["rsa"]["symmetric"]["keyBits"] == 128, info["rsa"]
        info2 = parse_public(_mk_public_rsa(2048, 65537))
        assert info2["rsa"]["exponent"] == 65537, info2["rsa"]
    check("parse_public RSA-2048 (exponent 0 normalised to 65537)", t04)

    # 5. ECC P-256
    def t05():
        info = parse_public(_mk_public_ecc(0x0003))
        assert info["type_name"] == "ECC", info
        assert info["ecc"]["curveID"] == 0x0003, info["ecc"]
        assert info["ecc"]["curve_name"] == CURVES[0x0003] == "NIST P256", info["ecc"]
        assert info["ecc"]["point_len"] == 65, info["ecc"]
        for cid, name in ((0x0004, "NIST P384"), (0x0005, "NIST P521")):
            assert parse_public(_mk_public_ecc(cid))["ecc"]["curve_name"] == name
    check("parse_public ECC P-256 (curveID + curve name)", t05)

    # 6. TPM2B_PRIVATE
    def t06():
        blob = _mk_private(32, 170)
        info = parse_private(blob)
        assert info["integrity_len"] == 32, info
        assert info["trailing"] == 170 and info["has_trailing"] is True, info
        assert info["consumed"] == 34, info
        info0 = parse_private(_mk_private(32, 0))
        assert info0["trailing"] == 0 and info0["has_trailing"] is False, info0
        try:
            parse_private(blob[:20])   # 声称 32 字节 integrity，实际只有 18 字节
        except TpmSealError as exc:
            assert "truncated" in str(exc), exc
        else:
            raise AssertionError("truncated TPM2B_PRIVATE did not raise")
    check("parse_private integrity_len + truncation raises TpmSealError", t06)

    # 7. describe_protector 五种
    def t07():
        tpm_blob = _mk_pcr_selection([(PCR_ALGS["SHA256"], [0, 7, 11])]) + _mk_public_rsa() + _mk_private()
        cases = [0x0000, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000]
        for tid in cases:
            payload = tpm_blob if tid == 0x0100 else b"\x11" * 8
            info = describe_protector(tid, payload)
            assert info["type"] == PROTECTOR_TYPES[tid], info
            assert isinstance(info["offline"], bool), info
            assert info["reason"], info
            assert info["type_hex"] == "0x%04X" % tid, info
        named = describe_protector("TPM", tpm_blob)
        assert named["type_id"] == 0x0100 and named["tpm"]["is_tpm"] is True, named
        assert named["tpm"]["pcrs_text"] == "SHA256: 0,7,11", named["tpm"]
        assert describe_protector("0x0200")["offline"] is True
        try:
            describe_protector(0x9999)
        except TpmSealError:
            pass
        else:
            raise AssertionError("unknown protector type did not raise")
    check("describe_protector covers all protector types (6 ids + by name)", t07)

    # 8. can_unlock_offline
    def t08():
        only_tpm = can_unlock_offline([0x0100])
        assert len(only_tpm) == 1 and only_tpm[0]["offline"] is False, only_tpm
        assert "TPM 解封" in only_tpm[0]["reason"], only_tpm
        with_rec = can_unlock_offline([0x0100, 0x0000])
        assert with_rec[0]["offline"] is False and with_rec[1]["offline"] is True, with_rec
        assert can_unlock_offline("startup key (.BEK)")[0]["offline"] is True
        assert can_unlock_offline([0x0400])[0]["offline"] is True
        assert can_unlock_offline([0x0800])[0]["reason"].startswith("需要用户口令")
        assert can_unlock_offline([0x1000])[0]["reason"].startswith("需要证书私钥")
        assert can_unlock_offline(describe_protector(0x0100))[0]["offline"] is False
    check("can_unlock_offline (TPM only -> False, +recovery -> True)", t08)

    # 9. 退化输入
    def t09():
        bad = [b"", b"\x00", b"\x00\x00\x00", bytes(64), b"\xff" * 16]
        for blob in bad:
            for fn in (lambda b: parse_pcr_selection(b),
                       lambda b: parse_public(b),
                       lambda b: parse_private(b)):
                try:
                    fn(blob)
                except TpmSealError:
                    continue
                except Exception as exc:  # noqa: BLE001
                    raise AssertionError("wrong exception %r for %r" % (exc, blob))
                raise AssertionError("degenerate input %r was accepted" % blob)
        assert describe(bytes(64))["is_tpm"] is False
        assert describe(b"")["is_tpm"] is False
    check("all-zero / empty / short input raises TpmSealError, never crashes", t09)

    # 10. describe 容错
    def t10():
        assert describe(None)["is_tpm"] is False
        assert describe("not bytes")["is_tpm"] is False
        assert describe(b"\x00" * 4096)["is_tpm"] is False
        assert describe(b"\x5a" * 512)["is_tpm"] is False
        # 顺序字节坡道：可能撞上启发式候选，只要求不抛且有结构
        ramp = describe(bytes(range(256)))
        assert isinstance(ramp, dict) and "is_tpm" in ramp, ramp
        d = describe(_mk_pcr_selection([(PCR_ALGS["SHA256"], [0, 7])]))
        assert d["is_tpm"] is True and d["pcrs_text"] == "SHA256: 0,7", d
        d2 = describe(_mk_public_rsa())
        assert d2["is_tpm"] is True and d2["public"]["rsa"]["keyBits"] == 2048, d2
    check("describe stays tolerant (None / str / garbage / valid)", t10)

    # 11. 边界：不解封
    def t11():
        forbidden = ("unseal", "decrypt", "derive", "unwrap", "recover", "decryptor",
                     "squash", "vmk", "fvek")
        public = [n for n in dir(module) if not n.startswith("_")]
        for name in public:
            low = name.lower()
            for word in forbidden:
                assert word not in low, "forbidden entry point surface: %s" % name
        for name in ("unseal", "decrypt", "unseal_vmk", "derive_key", "SquashfsLike"):
            assert not hasattr(module, name), name
        entry_points = {
            name for name in public
            if callable(getattr(module, name)) and not isinstance(getattr(module, name), type)
        }
        assert entry_points == {
            "parse_pcr_selection", "format_pcrs", "parse_public", "parse_private",
            "describe_protector", "can_unlock_offline", "describe",
        }, entry_points
        # 判定结论必须把「TPM -> 不能离线解」写死
        verdict = can_unlock_offline([0x0100])[0]
        assert verdict["offline"] is False and "TPM 解封" in verdict["reason"], verdict
    check("boundary assertion: no unseal/decrypt entry point, API whitelist", t11)

    print()
    print("TPM boundary: this module never unseals.")
    print("  TPM2B_PRIVATE sensitive part is protected by the on-chip SRK/storage")
    print("  key (derived from the chip Storage Primary Seed); an offline image")
    print("  holds no substitute material, so only parsing + feasibility verdicts")
    print("  are provided. TPM protectors are reported as NOT offline-unlockable.")
    print("self-checks: %d/%d passed" % (len(passed), 11))
    assert len(passed) == 11
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())