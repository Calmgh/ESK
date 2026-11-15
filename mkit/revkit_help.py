# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""revkit_help.py —— revkit 的关键词库与提示文本库（可自由扩充，不影响 revkit 逻辑）。

分四块：
  1 DEFAULT_PATTERNS  默认关键词（登录/校验/授权/加解密/中英文关键词）
  2 PATTERN_GROUPS    按语义分组，便于只跑某一组
  3 SUSPICIOUS_APIS   与"输入 -> 比较 -> 分支"流程强相关的导入函数
  4 JCC / BYPASS_HINT 条件跳转表与对应补丁建议文案

用法：
    from mkit.revkit_help import DEFAULT_PATTERNS, PATTERN_GROUPS, build_regex
    rx = build_regex(PATTERN_GROUPS["login"])
"""

import re

# --------------------------------------------------------------------------- #
# 1. 默认关键词库
# --------------------------------------------------------------------------- #
DEFAULT_PATTERNS = [
    # 凭据
    "password", "passwd", "passphrase", "pwd", "login", "logon", "signin",
    "sign in", "signon", "username", "user name", "userid", "user id",
    "account", "credential", "auth", "token",
    # 结果
    "success", "succeed", "successful", "fail", "failed", "failure",
    "denied", "invalid", "error", "incorrect", "bad", "correct", "welcome",
    "access", "granted", "forbidden", "verified", "verify", "valid",
    # 加密 / 密钥
    "bitlocker", "recovery", "key", "decrypt", "encrypt", "unlock",
    "cipher", "aes", "rsa",
    # 授权 / 序列号
    "serial", "license", "licence", "activation", "activate", "register",
    "trial", "expired", "expire",
    # 中文
    "注册码", "密码", "口令", "成功", "失败", "验证", "登录", "授权",
    "密钥", "解密", "加密", "注册", "试用", "过期", "用户名",
]

# --------------------------------------------------------------------------- #
# 2. 语义分组
# --------------------------------------------------------------------------- #
PATTERN_GROUPS = {
    "login": [
        "password", "passwd", "pwd", "login", "logon", "signin", "username",
        "user", "account", "success", "fail", "denied", "invalid", "welcome",
        "access", "correct", "incorrect", "bad", "error",
        "密码", "登录", "用户名", "成功", "失败",
    ],
    "crypto": [
        "bitlocker", "key", "decrypt", "encrypt", "unlock", "recovery",
        "cipher", "aes", "rsa", "密钥", "解密", "加密",
    ],
    "license": [
        "serial", "license", "licence", "activation", "activate", "register",
        "trial", "expired", "注册码", "注册", "授权", "试用", "过期",
    ],
    "network": [
        "http://", "https://", "ftp://", "socket", "connect", "recv", "send",
        "user-agent", "host:", "post ", "get ",
    ],
    "dbg": [
        "debug", "ollydbg", "x64dbg", "windbg", "ida", "vmware", "virtualbox",
        "sandbox", "isdebuggerpresent",
    ],
}

# --------------------------------------------------------------------------- #
# 3. 与登录校验强相关的导入函数（用于给 suggest_login_bypass 打权重）
# --------------------------------------------------------------------------- #
SUSPICIOUS_APIS = {
    # 字符串 / 内存比较
    "strcmp": 3, "strcmpi": 3, "_stricmp": 3, "lstrcmp": 3, "lstrcmpi": 3,
    "wcscmp": 3, "wcsicmp": 3, "memcmp": 3, "strncmp": 3, "_strnicmp": 3,
    "CompareStringA": 3, "CompareStringW": 3, "CompareStringOrdinal": 3,
    "RtlCompareMemory": 2, "lstrlenA": 2, "lstrlenW": 2, "strlen": 2,
    # 输入采集
    "GetWindowTextA": 2, "GetWindowTextW": 2, "GetDlgItemTextA": 2,
    "GetDlgItemTextW": 2, "GetDlgItemInt": 2, "GetWindowTextLengthA": 1,
    "ReadConsoleA": 2, "ReadConsoleW": 2, "fgets": 2, "scanf": 2, "gets": 2,
    # 结果呈现
    "MessageBoxA": 1, "MessageBoxW": 1, "SetWindowTextA": 1,
    "SetWindowTextW": 1, "printf": 1, "puts": 1, "cout": 1,
    # 解密 / 密钥
    "CryptDecrypt": 3, "BCryptDecrypt": 3, "CryptUnprotectData": 3,
    "CryptImportKey": 2, "BCryptGenerateSymmetricKey": 2,
    # 反调试
    "IsDebuggerPresent": 2, "CheckRemoteDebuggerPresent": 2,
    "NtQueryInformationProcess": 2, "OutputDebugStringA": 1,
}

# --------------------------------------------------------------------------- #
# 4. 条件跳转
# --------------------------------------------------------------------------- #
JCC = {
    # mnemonic: (语义, 补丁动作, 说明)
    "je":   ("相等则跳", "jmp",  "改成无条件 jmp，或改 74->EB"),
    "jz":   ("为零则跳", "jmp",  "改成无条件 jmp，或改 74->EB"),
    "jne":  ("不等则跳", "nop",  "NOP 掉两条（75 xx -> 90 90）即恒走成功分支"),
    "jnz":  ("非零则跳", "nop",  "NOP 掉两条（75 xx -> 90 90）"),
    "jg":   ("大于则跳", "nop",  "NOP 掉"),
    "jnle": ("大于则跳", "nop",  "NOP 掉"),
    "jge":  ("大于等于则跳", "nop", "NOP 掉"),
    "jnl":  ("大于等于则跳", "nop", "NOP 掉"),
    "jl":   ("小于则跳", "nop",  "NOP 掉"),
    "jnge": ("小于则跳", "nop",  "NOP 掉"),
    "jle":  ("小于等于则跳", "nop", "NOP 掉"),
    "jng":  ("小于等于则跳", "nop", "NOP 掉"),
    "ja":   ("无符号大于则跳", "nop", "NOP 掉"),
    "jnbe": ("无符号大于则跳", "nop", "NOP 掉"),
    "jae":  ("无符号大于等于则跳", "nop", "NOP 掉"),
    "jnb":  ("无符号大于等于则跳", "nop", "NOP 掉"),
    "jb":   ("无符号小于则跳", "nop", "NOP 掉"),
    "jnae": ("无符号小于则跳", "nop", "NOP 掉"),
    "jbe":  ("无符号小于等于则跳", "nop", "NOP 掉"),
    "jna":  ("无符号小于等于则跳", "nop", "NOP 掉"),
    "js":   ("符号位置位则跳", "nop", "NOP 掉"),
    "jns":  ("符号位清零则跳", "nop", "NOP 掉"),
    "jo":   ("溢出则跳", "nop",  "NOP 掉"),
    "jno":  ("未溢出则跳", "nop", "NOP 掉"),
    "jp":   ("奇偶位置位则跳", "nop", "NOP 掉"),
    "jpe":  ("奇偶位置位则跳", "nop", "NOP 掉"),
    "jnp":  ("奇偶位清零则跳", "nop", "NOP 掉"),
    "jpo":  ("奇偶位清零则跳", "nop", "NOP 掉"),
    "jecxz": ("ecx 为 0 则跳", "nop", "NOP 掉"),
    "jrcxz": ("rcx 为 0 则跳", "nop", "NOP 掉"),
}

# 用于"校验点识别"的判定类指令（只收真正影响标志位的比较指令，
# 零填充区会解出大量 add byte ptr [rax], al，故 add/sub/and/or 不计入）
CMP_MNEMONICS = ("cmp", "test", "bt")

# 引用字符串的指令形式
REF_MNEMONICS = ("lea", "push", "mov", "movabs", "call", "cmp")

# 登录成功 / 失败的典型文案（用于判定哪个分支是成功分支）
SUCCESS_WORDS = ("success", "successful", "welcome", "granted", "correct",
                 "ok", "verified", "valid", "成功")
FAILURE_WORDS = ("fail", "failed", "failure", "denied", "invalid", "error",
                 "incorrect", "bad", "forbidden", "wrong", "失败", "错误")


def build_regex(patterns=None, ignore_case=True):
    """把关键词列表编译成 bytes 正则（用于在原始字节里搜 ASCII / UTF-16LE）。"""
    import re
    pats = list(patterns if patterns is not None else DEFAULT_PATTERNS)
    pats = [p for p in pats if p]
    if not pats:
        return None
    # 长词优先，避免 "pass" 抢先吃掉 "password" 的匹配位置
    pats.sort(key=len, reverse=True)
    body = "|".join(re.escape(p) for p in pats)
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(body.encode("utf-8"), flags)


def category_of(word):
    """判断一个字符串属于哪一类（login/crypto/license/network/dbg/other）。"""
    low = str(word).lower()
    for name, words in PATTERN_GROUPS.items():
        for w in words:
            if w.lower() in low:
                return name
    return "other"


def classify_result(text):
    """区分"成功"分支文案与"失败"分支文案，供 suggest_login_bypass 用。

    先判失败词（"invalid" 里含 "valid"，顺序不能反），成功词按词边界匹配。
    """
    low = str(text).lower()
    for w in FAILURE_WORDS:
        if w in low:
            return "failure"
    for w in SUCCESS_WORDS:
        if re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(w), low):
            return "success"
    return "unknown"


def bypass_hint(mnemonic):
    """给一条条件跳转返回 (动作, 说明)。"""
    return JCC.get(str(mnemonic).lower(), ("nop", "非典型条件跳转，直接 NOP 掉 2 字节"))


def api_weight(name):
    """导入函数在"校验链"里的可疑权重（0 表示无关）。"""
    if name in SUSPICIOUS_APIS:
        return SUSPICIOUS_APIS[name]
    for k, v in SUSPICIOUS_APIS.items():
        if k.lower() == str(name).lower():
            return v
    return 0


__all__ = [
    "DEFAULT_PATTERNS", "PATTERN_GROUPS", "SUSPICIOUS_APIS", "JCC",
    "CMP_MNEMONICS", "REF_MNEMONICS", "SUCCESS_WORDS", "FAILURE_WORDS",
    "build_regex", "category_of", "classify_result", "bypass_hint", "api_weight",
]
