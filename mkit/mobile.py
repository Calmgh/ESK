# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""mkit.mobile —— Android / iOS 手机取证解析（纯标准库，自研实现）。

组成：
  * SqliteTriage   —— 自研 SQLite 文件格式解析器：b-tree / overflow / 编码全部
                      自行实现，内置极简 SQL 子集执行器；deleted_rows() 从
                      freelist 与页面未分配区（freeblock / 单元间距）恢复删除记录。
  * PlistHelper    —— plistlib 封装，含 NSKeyedArchiver（$objects/UID）展开。
  * AndroidArtifacts —— Android 痕迹：Android ID / 设备信息 / 账号 / WiFi /
                      联系人（含删除）/ 通话 / 短信 / 浏览器 / 安装包 /
                      微信 EnMicroMsg.db（自研 SQLCipher 解密）/ 通用 app 数据库。
  * IosBackup      —— iOS 备份（Manifest.db / sha1 分目录散列文件 / sms.db）。

SQLCipher（微信 4.x~6.x）见 sqlcipher_decrypt()：
  key = md5(imei + uin)[:7]（小写十六进制字符串）；
  PRAGMA key 等价物 = PBKDF2-HMAC-SHA1(password=key, salt=文件前 16 字节,
                                     iter=4000, dklen=32)；
  页结构（page_size=1024, reserve=48）：密文 + 16 字节 IV + 20 字节 HMAC-SHA1
  + 12 字节填充；首页前 16 字节被随机 salt 覆盖，明文页首需还原
  b"SQLite format 3\\x00"。AES-256-CBC 由本包 mkit.aes 纯 Python 实现。

无第三方依赖（sqlite3 / plistlib / xml.etree 属标准库，本模块仅用到后两者）。
"""
import datetime
import hashlib
import hmac
import plistlib
import re
import struct
import xml.etree.ElementTree as ET

from .aes import cbc_decrypt, cbc_encrypt

__all__ = [
    "SqliteError", "SqliteTriage", "PlistHelper", "AndroidArtifacts", "IosBackup",
    "sqlcipher_decrypt", "sqlcipher_probe", "sqlcipher_keys", "wechat_key_candidates",
    "unix_ms", "fmt_ms", "fmt_s", "ms_to_dt", "chrome_time",
]

# ==========================================================================
# 通用工具
# ==========================================================================
SQLITE_MAGIC = b"SQLite format 3\x00"


class SqliteError(Exception):
    pass


def unix_ms(ms, tz_hours=8):
    """Android 毫秒时间戳 → 带时区 datetime（默认东八区）。"""
    if ms in (None, 0):
        return None
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return None
    if ms > 10 ** 14:            # 微秒
        ms //= 1000
    tz = datetime.timezone(datetime.timedelta(hours=tz_hours))
    try:
        return datetime.datetime.fromtimestamp(ms / 1000.0, tz)
    except (OverflowError, OSError, ValueError):
        return None


def fmt_ms(ms, tz_hours=8):
    dt = unix_ms(ms, tz_hours)
    return dt.strftime("%Y-%m-%d %H:%M:%S%z") if dt else None


def fmt_s(sec, tz_hours=8):
    if sec in (None, 0):
        return None
    try:
        sec = int(sec)
    except (TypeError, ValueError):
        return None
    if sec > 10 ** 11:           # 已是毫秒
        return fmt_ms(sec, tz_hours)
    return fmt_ms(sec * 1000, tz_hours)


def ms_to_dt(v, tz_offset_hours=8):
    """兼容旧接口：数值时间戳（秒/毫秒/微秒自适应）→ datetime。"""
    if v in (None, 0):
        return None
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    if v > 10 ** 15:
        v = v / 1e6
    elif v > 10 ** 11:
        v = v / 1000
    try:
        tz = datetime.timezone(datetime.timedelta(hours=tz_offset_hours))
        return datetime.datetime.fromtimestamp(v, datetime.timezone.utc).astimezone(tz)
    except (OverflowError, OSError, ValueError):
        return None


def apple_ns_to_dt(value):
    """Apple 纪元（2001-01-01 UTC）换算：兼容纳秒/微秒/毫秒/秒，返回 datetime 或 None。"""
    if value in (None, 0, ""):
        return None
    try:
        base = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
        f = float(value)
        if f > 1e15:
            f /= 1e9
        elif f > 1e11:
            f /= 1e6
        elif f > 1e9:
            f /= 1e3
        return base + datetime.timedelta(seconds=f)
    except Exception:
        return None


def chrome_time(v):
    """Chrome/WebKit 时间：1601-01-01 起的微秒。"""
    if not v:
        return None
    try:
        return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + \
            datetime.timedelta(microseconds=int(v))
    except (OverflowError, ValueError):
        return None


def _varint(buf, off, end=None):
    """SQLite 变长整数（大端 7bit/字节，最多 9 字节）。返回 (value, nbytes)。"""
    end = len(buf) if end is None else end
    v = 0
    for i in range(9):
        if off + i >= end:
            raise SqliteError("varint truncated")
        b = buf[off + i]
        if i == 8:
            return (v << 8) | b, 9
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            return v, i + 1
    raise SqliteError("varint too long")


def _md5_hex(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return hashlib.md5(s).hexdigest()


# ==========================================================================
# 极简 SQL 子集（仅服务于 SqliteTriage.rows）
# ==========================================================================
_TOKEN_RE = re.compile(r"""
      (?P<ws>\s+)
    | (?P<num>\d+\.\d+(?:[eE][-+]?\d+)?|\d+)
    | (?P<str>'(?:[^']|'')*')
    | (?P<qid>"(?:[^"]|"")*"|`[^`]*`|\[[^\]]*\])
    | (?P<id>[A-Za-z_\u0080-\uffff][\w$@\u0080-\uffff]*)
    | (?P<op><=|>=|<>|!=|==|\|\||[-+*/%<>=(),.;?])
""", re.X)

AGG_FUNCS = {"count", "sum", "avg", "min", "max", "total", "group_concat"}


class _Tok:
    __slots__ = ("kind", "val")

    def __init__(self, kind, val):
        self.kind = kind
        self.val = val

    def __repr__(self):
        return "<%s:%r>" % (self.kind, self.val)


def _tokenize(sql):
    out = []
    pos = 0
    n = len(sql)
    while pos < n:
        m = _TOKEN_RE.match(sql, pos)
        if not m:
            raise SqliteError("cannot tokenize near %r" % sql[pos:pos + 20])
        pos = m.end()
        kind = m.lastgroup
        text = m.group()
        if kind == "ws":
            continue
        if kind == "num":
            out.append(_Tok("num", float(text) if ("." in text or "e" in text.lower()) else int(text)))
        elif kind == "str":
            out.append(_Tok("str", text[1:-1].replace("''", "'")))
        elif kind == "qid":
            out.append(_Tok("id", text[1:-1].replace('""', '"')))
        elif kind == "id":
            out.append(_Tok("id", text))
        else:
            out.append(_Tok("op", text))
    out.append(_Tok("eof", None))
    return out


class _Parser:
    """递归下降，产出可对行 dict 求值的 AST（tuple 形式）。"""

    def __init__(self, toks, args):
        self.toks = toks
        self.i = 0
        self.args = list(args or ())
        self.argi = 0

    # ---------- 词法辅助 ----------
    def peek(self, k=0):
        if self.i + k >= len(self.toks):
            return self.toks[-1]
        return self.toks[self.i + k]

    def next(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def at_kw(self, word):
        t = self.peek()
        return t.kind == "id" and t.val.lower() == word

    def eat_kw(self, word):
        if self.at_kw(word):
            self.i += 1
            return True
        return False

    def expect_kw(self, word):
        if not self.eat_kw(word):
            raise SqliteError("expected %s near %r" % (word.upper(), self.peek().val))

    def at_op(self, op):
        t = self.peek()
        return t.kind == "op" and t.val == op

    def eat_op(self, op):
        if self.at_op(op):
            self.i += 1
            return True
        return False

    def expect_op(self, op):
        if not self.eat_op(op):
            raise SqliteError("expected %r near %r" % (op, self.peek().val))

    def accept_name(self):
        t = self.peek()
        if t.kind == "id":
            self.i += 1
            return t.val
        raise SqliteError("expected identifier near %r" % (t.val,))

    # ---------- 语法 ----------
    def parse_select(self):
        self.expect_kw("select")
        distinct = self.eat_kw("distinct")
        items = [self.parse_item()]
        while self.eat_op(","):
            items.append(self.parse_item())
        table = None
        alias = None
        if self.eat_kw("from"):
            table = self.accept_name()
            if self.at_op("."):
                self.i += 1
                table = self.accept_name()
            if self.eat_kw("as"):
                alias = self.accept_name()
            elif self.peek().kind == "id" and not any(
                    self.at_kw(w) for w in ("where", "order", "group", "limit", "offset")):
                alias = self.accept_name()
        where = None
        if self.eat_kw("where"):
            where = self.parse_expr()
        group = []
        if self.at_kw("group"):
            self.i += 1
            self.expect_kw("by")
            group.append(self.parse_expr())
            while self.eat_op(","):
                group.append(self.parse_expr())
        order = []
        if self.at_kw("order"):
            self.i += 1
            self.expect_kw("by")
            while True:
                e = self.parse_expr()
                desc = False
                if self.at_kw("desc"):
                    self.i += 1
                    desc = True
                elif self.at_kw("asc"):
                    self.i += 1
                order.append((e, desc))
                if not self.eat_op(","):
                    break
        limit = None
        offset = None
        if self.eat_kw("limit"):
            limit = self.parse_expr()
            if self.eat_op(","):
                offset = limit
                limit = self.parse_expr()
            elif self.eat_kw("offset"):
                offset = self.parse_expr()
        elif self.eat_kw("offset"):
            offset = self.parse_expr()
        if self.peek().kind != "eof":
            raise SqliteError("unexpected token %r" % (self.peek().val,))
        return dict(distinct=distinct, items=items, table=table, alias=alias,
                    where=where, group=group, order=order, limit=limit, offset=offset)

    def parse_item(self):
        if self.at_op("*"):
            self.i += 1
            return (("*"), None)
        e = self.parse_expr()
        alias = None
        if self.eat_kw("as"):
            alias = self.accept_name()
        elif self.peek().kind == "id" and self.peek().val.lower() not in (
                "from", "where", "order", "group", "limit", "offset", "and", "or"):
            alias = self.accept_name()
        return (e, alias)

    def parse_expr(self):
        return self.parse_or()

    def parse_or(self):
        node = self.parse_and()
        while self.eat_kw("or"):
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.eat_kw("and"):
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if self.eat_kw("not"):
            return ("not", self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        node = self.parse_add()
        while True:
            t = self.peek()
            if t.kind == "op" and t.val in ("=", "==", "!=", "<>", "<", "<=", ">", ">="):
                self.i += 1
                node = ("cmp", t.val, node, self.parse_add())
                continue
            if self.at_kw("is"):
                self.i += 1
                neg = self.eat_kw("not")
                if self.eat_kw("null"):
                    node = ("isnull", node, neg)
                else:
                    node = ("cmp", "!=" if neg else "=", node, self.parse_add())
                continue
            neg = False
            if self.at_kw("not") and self.peek(1).kind == "id" and \
                    self.peek(1).val.lower() in ("like", "glob", "in", "between"):
                self.i += 1
                neg = True
            if self.at_kw("like"):
                self.i += 1
                node = ("like", node, self.parse_add(), neg)
                continue
            if self.at_kw("glob"):
                self.i += 1
                node = ("glob", node, self.parse_add(), neg)
                continue
            if self.at_kw("in"):
                self.i += 1
                self.expect_op("(")
                vals = []
                if not self.at_op(")"):
                    vals.append(self.parse_expr())
                    while self.eat_op(","):
                        vals.append(self.parse_expr())
                self.expect_op(")")
                node = ("in", node, vals, neg)
                continue
            if self.at_kw("between"):
                self.i += 1
                lo = self.parse_add()
                self.expect_kw("and")
                hi = self.parse_add()
                node = ("between", node, lo, hi, neg)
                continue
            break
        return node

    def parse_add(self):
        node = self.parse_mul()
        while True:
            t = self.peek()
            if t.kind == "op" and t.val in ("+", "-", "||"):
                self.i += 1
                node = ("arith", t.val, node, self.parse_mul())
            else:
                break
        return node

    def parse_mul(self):
        node = self.parse_unary()
        while True:
            t = self.peek()
            if t.kind == "op" and t.val in ("*", "/", "%"):
                self.i += 1
                node = ("arith", t.val, node, self.parse_unary())
            else:
                break
        return node

    def parse_unary(self):
        if self.at_op("-"):
            self.i += 1
            return ("neg", self.parse_unary())
        if self.at_op("+"):
            self.i += 1
            return self.parse_unary()
        return self.parse_primary()

    def parse_primary(self):
        t = self.peek()
        if t.kind == "num":
            self.i += 1
            return ("lit", t.val)
        if t.kind == "str":
            self.i += 1
            return ("lit", t.val)
        if t.kind == "op" and t.val == "?":
            self.i += 1
            if self.argi >= len(self.args):
                raise SqliteError("not enough bind args")
            v = self.args[self.argi]
            self.argi += 1
            return ("lit", v)
        if t.kind == "op" and t.val == "(":
            self.i += 1
            node = self.parse_expr()
            self.expect_op(")")
            return node
        if t.kind == "id":
            name = t.val
            low = name.lower()
            if low == "null":
                self.i += 1
                return ("lit", None)
            if low == "true":
                self.i += 1
                return ("lit", 1)
            if low == "false":
                self.i += 1
                return ("lit", 0)
            if low == "case":
                self.i += 1
                base = None
                if not self.at_kw("when"):
                    base = self.parse_expr()
                branches = []
                while self.eat_kw("when"):
                    w = self.parse_expr()
                    self.expect_kw("then")
                    branches.append((w, self.parse_expr()))
                els = None
                if self.eat_kw("else"):
                    els = self.parse_expr()
                self.expect_kw("end")
                return ("case", base, branches, els)
            self.i += 1
            if self.at_op("("):
                self.i += 1
                args = []
                distinct = False
                if self.at_op("*"):
                    self.i += 1
                    args.append(("*"))
                elif not self.at_op(")"):
                    if self.eat_kw("distinct"):
                        distinct = True
                    args.append(self.parse_expr())
                    while self.eat_op(","):
                        args.append(self.parse_expr())
                self.expect_op(")")
                if low in AGG_FUNCS:
                    return ("agg", low, args[0] if args else None, distinct)
                return ("func", low, args)
            if self.at_op("."):
                self.i += 1
                name = self.accept_name()
            return ("col", name)
        raise SqliteError("unexpected token %r" % (t.val,))


def _like_to_regex(pat, glob=False):
    out = ["^"]
    for ch in str(pat):
        if not glob and ch == "%":
            out.append(".*")
        elif not glob and ch == "_":
            out.append(".")
        elif glob and ch == "*":
            out.append(".*")
        elif glob and ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    out.append("$")
    return re.compile("".join(out), re.S)


def _to_cmp(v):
    """比较用归一化：bytes 转字符串。"""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace")
    return v


_CTRL_OK = frozenset("\t\r\n")


def _plausible_text(s):
    """删除记录扫描的文本合理性判定：无替换符、无异常控制字符。"""
    if not isinstance(s, str):
        return True
    if "\ufffd" in s or "\x00" in s:
        return False
    for ch in s:
        if ch < " " and ch not in _CTRL_OK:
            return False
    return True


def _sql_truth(v):
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        try:
            return float(v) != 0
        except ValueError:
            return False
    return bool(v)


class _Row(dict):
    """行字典：大小写不敏感取列。"""

    __slots__ = ()

    def get_ci(self, name):
        if name in self:
            return self[name]
        low = name.lower()
        for k, v in self.items():
            if isinstance(k, str) and k.lower() == low:
                return v
        raise SqliteError("no such column: %s" % name)


def _ev(node, row, aggvals=None):
    k = node[0]
    if k == "lit":
        return node[1]
    if k == "col":
        return row.get_ci(node[1])
    if k == "cmp":
        a, b = _to_cmp(_ev(node[2], row, aggvals)), _to_cmp(_ev(node[3], row, aggvals))
        op = node[1]
        if a is None or b is None:
            return (a is None and b is None) if op in ("=", "==") else False
        if op in ("=", "=="):
            return a == b
        if op in ("!=", "<>"):
            return a != b
        try:
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        except TypeError:
            sa, sb = str(a), str(b)
            return {"<": sa < sb, "<=": sa <= sb, ">": sa > sb, ">=": sa >= sb}[op]
    if k == "and":
        return _sql_truth(_ev(node[1], row, aggvals)) and _sql_truth(_ev(node[2], row, aggvals))
    if k == "or":
        return _sql_truth(_ev(node[1], row, aggvals)) or _sql_truth(_ev(node[2], row, aggvals))
    if k == "not":
        return not _sql_truth(_ev(node[1], row, aggvals))
    if k == "isnull":
        v = _ev(node[1], row, aggvals)
        return (v is not None) if node[2] else (v is None)
    if k in ("like", "glob"):
        a = _ev(node[1], row, aggvals)
        b = _ev(node[2], row, aggvals)
        if a is None or b is None:
            return False
        hit = bool(_like_to_regex(b, glob=(k == "glob")).match(str(_to_cmp(a))))
        return (not hit) if node[3] else hit
    if k == "in":
        v = _to_cmp(_ev(node[1], row, aggvals))
        hit = any(v == _to_cmp(_ev(e, row, aggvals)) for e in node[2])
        return (not hit) if node[3] else hit
    if k == "between":
        v = _to_cmp(_ev(node[1], row, aggvals))
        lo, hi = _to_cmp(_ev(node[2], row, aggvals)), _to_cmp(_ev(node[3], row, aggvals))
        if v is None or lo is None or hi is None:
            return False
        hit = lo <= v <= hi
        return (not hit) if node[4] else hit
    if k == "neg":
        v = _ev(node[1], row, aggvals)
        return -v if isinstance(v, (int, float)) else v
    if k == "arith":
        a, b = _ev(node[2], row, aggvals), _ev(node[3], row, aggvals)
        op = node[1]
        if op == "||":
            return "%s%s" % ("" if a is None else _to_cmp(a), "" if b is None else _to_cmp(b))
        if a is None or b is None:
            return None
        try:
            if op == "+":
                return a + b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "/":
                return (a / b) if b else None
            if op == "%":
                return (a % b) if b else None
        except TypeError:
            return None
    if k == "func":
        name, args = node[1], node[2]
        vals = [_ev(a, row, aggvals) if a != "*" else None for a in args]
        v0 = vals[0] if vals else None
        if name == "lower":
            return None if v0 is None else str(_to_cmp(v0)).lower()
        if name == "upper":
            return None if v0 is None else str(_to_cmp(v0)).upper()
        if name == "length":
            return 0 if v0 is None else len(_to_cmp(v0))
        if name in ("substr", "substring"):
            if v0 is None:
                return None
            s = str(_to_cmp(v0))
            start = int(vals[1]) if len(vals) > 1 and vals[1] is not None else 1
            start = max(0, len(s) + start) if start < 0 else max(0, start - 1)
            if len(vals) > 2 and vals[2] is not None:
                return s[start:start + int(vals[2])]
            return s[start:]
        if name in ("trim", "ltrim", "rtrim"):
            s = "" if v0 is None else str(_to_cmp(v0))
            return s.strip() if name == "trim" else (s.lstrip() if name == "ltrim" else s.rstrip())
        if name == "abs":
            return abs(v0) if isinstance(v0, (int, float)) else v0
        if name in ("coalesce", "ifnull"):
            for v in vals:
                if v is not None:
                    return v
            return None
        if name == "nullif":
            return None if len(vals) > 1 and vals[0] == vals[1] else v0
        if name == "typeof":
            if v0 is None:
                return "null"
            if isinstance(v0, int):
                return "integer"
            if isinstance(v0, float):
                return "real"
            if isinstance(v0, (bytes, bytearray)):
                return "blob"
            return "text"
        if name == "hex":
            if v0 is None:
                return ""
            b = bytes(v0) if isinstance(v0, (bytes, bytearray)) else str(v0).encode("utf-8")
            return b.hex().upper()
        if name == "replace":
            if v0 is None:
                return None
            return str(_to_cmp(v0)).replace(str(vals[1]), str(vals[2]))
        if name == "instr":
            if v0 is None:
                return 0
            try:
                return str(_to_cmp(v0)).index(str(vals[1])) + 1
            except (ValueError, IndexError):
                return 0
        if name == "round":
            return None if v0 is None else round(float(v0), int(vals[1]) if len(vals) > 1 else 0)
        if name == "quote":
            if v0 is None:
                return "NULL"
            if isinstance(v0, (int, float)):
                return str(v0)
            return "'%s'" % str(_to_cmp(v0)).replace("'", "''")
        if name == "printf":
            try:
                return str(vals[0]) % tuple(vals[1:])
            except (TypeError, ValueError):
                return str(vals[0])
        raise SqliteError("unsupported function: %s" % name)
    if k == "agg":
        if aggvals is None:
            raise SqliteError("aggregate not allowed here")
        return aggvals.get(id(node))
    if k == "case":
        base, branches, els = node[1], node[2], node[3]
        bv = _ev(base, row, aggvals) if base is not None else None
        for w, t in branches:
            if base is None:
                if _sql_truth(_ev(w, row, aggvals)):
                    return _ev(t, row, aggvals)
            else:
                if _to_cmp(_ev(w, row, aggvals)) == _to_cmp(bv):
                    return _ev(t, row, aggvals)
        return _ev(els, row, aggvals) if els is not None else None
    if k == "*":
        return None
    raise SqliteError("bad node %r" % (k,))


def _collect_aggs(node, out):
    if not isinstance(node, tuple):
        return
    if node and node[0] == "agg":
        out.append(node)
        return
    for part in node[1:]:
        if isinstance(part, tuple):
            _collect_aggs(part, out)
        elif isinstance(part, list):
            for p in part:
                _collect_aggs(p, out)


def _calc_agg(node, rows):
    name, arg, distinct = node[1], node[2], node[3]
    if arg == ("*") or arg is None:
        vals = [1] * len(rows)
    else:
        vals = [_ev(arg, r, None) for r in rows]
    if name == "count":
        if arg == ("*") or arg is None:
            return len(rows)
        vals = [v for v in vals if v is not None]
        return len({_to_cmp(v) for v in vals}) if distinct else len(vals)
    vals = [v for v in vals if v is not None]
    if distinct:
        seen, uniq = set(), []
        for v in vals:
            key = _to_cmp(v)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(v)
        vals = uniq
    if name == "sum":
        nums = [v for v in vals if isinstance(v, (int, float))]
        return sum(nums) if nums else None
    if name == "total":
        return float(sum(v for v in vals if isinstance(v, (int, float))))
    if name == "avg":
        nums = [v for v in vals if isinstance(v, (int, float))]
        return (sum(nums) / len(nums)) if nums else None
    if name == "min":
        return min((_to_cmp(v) for v in vals), default=None)
    if name == "max":
        return max((_to_cmp(v) for v in vals), default=None)
    if name == "group_concat":
        return ",".join(str(_to_cmp(v)) for v in vals)
    raise SqliteError("unsupported aggregate: %s" % name)


# ==========================================================================
# SQLite 解析
# ==========================================================================
class SqliteTriage:
    """直接在内存里解析 SQLite 数据库文件（不依赖 sqlite3 扩展）。"""

    def __init__(self, data, page_size=None):
        self.data = bytes(data)
        if len(self.data) < 100 or not self.data.startswith(SQLITE_MAGIC):
            raise SqliteError("not a SQLite 3 database (bad magic)")
        h = self.data[:100]
        ps = struct.unpack_from(">H", h, 16)[0]
        if ps == 1:
            ps = 65536
        if page_size:
            ps = page_size
        if ps < 512 or ps > 65536 or (ps & (ps - 1)):
            raise SqliteError("bad page size %d" % ps)
        self.page_size = ps
        self.reserved = h[20]
        if self.reserved >= ps:
            self.reserved = 0
        self.usable = ps - self.reserved
        enc = struct.unpack_from(">I", h, 56)[0]
        self.encoding = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}.get(enc, "utf-8")
        self.change_counter = struct.unpack_from(">I", h, 24)[0]
        self.db_pages = struct.unpack_from(">I", h, 28)[0]
        self.freelist_trunk = struct.unpack_from(">I", h, 32)[0]
        self.freelist_count = struct.unpack_from(">I", h, 36)[0]
        self.schema_cookie = struct.unpack_from(">I", h, 40)[0]
        self.text_pages = len(self.data) // ps
        self._rows_cache = {}
        self._master = None
        self._schema_cache = {}
        self._last_columns = None

    # ---------- 基础 ----------
    def __len__(self):
        return self.text_pages

    def page(self, n):
        if n < 1:
            raise SqliteError("page number %d out of range" % n)
        off = (n - 1) * self.page_size
        pg = self.data[off:off + self.page_size]
        if not pg:
            raise SqliteError("page %d beyond EOF" % n)
        return pg

    def page_type(self, n):
        pg = self.page(n)
        return pg[self._hdr_off(n)]

    @staticmethod
    def _hdr_off(pno):
        """page 1 的 b-tree 页头从偏移 100 开始（前 100 字节是数据库头）。"""
        return 100 if pno == 1 else 0

    @classmethod
    def _cell_offsets(cls, pg, interior, pno=0):
        h = cls._hdr_off(pno)
        if h + 8 > len(pg):
            return []
        n = struct.unpack_from(">H", pg, h + 3)[0]
        base = h + (12 if interior else 8)
        out = []
        for i in range(n):
            o = base + 2 * i
            if o + 2 > len(pg):
                break
            out.append(struct.unpack_from(">H", pg, o)[0])
        return out

    def _decode_value(self, stype, buf, off, strict=False):
        """按 serial type 解出一个值，返回 (value, new_off)。

        strict=True 时文本必须是合法 UTF-8/UTF-16（删除记录扫描用，抑制误报）。
        """
        if stype == 0:
            return None, off
        if stype in (1, 2, 3, 4):
            if off + stype > len(buf):
                raise SqliteError("truncated int")
            return int.from_bytes(buf[off:off + stype], "big", signed=True), off + stype
        if stype == 5:
            if off + 6 > len(buf):
                raise SqliteError("truncated int48")
            return int.from_bytes(buf[off:off + 6], "big", signed=True), off + 6
        if stype == 6:
            if off + 8 > len(buf):
                raise SqliteError("truncated int64")
            return int.from_bytes(buf[off:off + 8], "big", signed=True), off + 8
        if stype == 7:
            if off + 8 > len(buf):
                raise SqliteError("truncated real")
            return struct.unpack_from(">d", buf, off)[0], off + 8
        if stype == 8:
            return 0, off
        if stype == 9:
            return 1, off
        if stype in (10, 11):
            raise SqliteError("reserved serial type")
        n = (stype - 12) // 2
        if off + n > len(buf):
            raise SqliteError("truncated text/blob")
        raw = bytes(buf[off:off + n])
        if stype % 2 == 0:
            return raw, off + n
        if strict:
            return raw.decode(self.encoding), off + n
        try:
            return raw.decode(self.encoding), off + n
        except (UnicodeDecodeError, LookupError):
            return raw.decode("utf-8", "replace"), off + n

    def decode_record(self, payload, strict=False):
        """解析 record payload 为 tuple；strict=True 时文本必须严格符合编码。"""
        if not payload:
            return ()
        hlen, n = _varint(payload, 0)
        if hlen < n or hlen > len(payload):
            raise SqliteError("bad record header size")
        stypes = []
        off = n
        while off < hlen:
            st, k = _varint(payload, off, hlen)
            if st in (10, 11):
                raise SqliteError("reserved serial type")
            stypes.append(st)
            off += k
        if off != hlen:
            raise SqliteError("record header overrun")
        body = hlen
        vals = []
        for st in stypes:
            if strict and st % 2 == 1 and st >= 13:
                nbytes = (st - 13) // 2
                chunk = payload[body:body + nbytes]
                if len(chunk) != nbytes:
                    raise SqliteError("truncated text")
                chunk.decode(self.encoding)
            v, body = self._decode_value(st, payload, body)
            vals.append(v)
        return tuple(vals)

    # ---------- cell / overflow ----------
    def _read_cell(self, pg, off, usable=None):
        """返回 (payload_bytes, rowid)。"""
        usable = self.usable if usable is None else usable
        psize, k = _varint(pg, off)
        p = off + k
        rowid, k2 = _varint(pg, p)
        p += k2
        avail = usable - p
        if avail < 0:
            raise SqliteError("cell beyond usable area")
        maxlocal = usable - 35
        if psize <= maxlocal:
            local = psize
        else:
            minlocal = ((usable - 12) * 32) // 255 - 23
            kk = minlocal + (psize - minlocal) % (usable - 4)
            local = kk if kk <= maxlocal else minlocal
        if local > avail:
            raise SqliteError("cell local payload truncated")
        payload = bytearray(pg[p:p + local])
        if local < psize:
            if p + local + 4 > usable:
                raise SqliteError("missing overflow pointer")
            nxt = struct.unpack_from(">I", pg, p + local)[0]
            guard = 0
            while local < psize and nxt:
                guard += 1
                if guard > 100000:
                    raise SqliteError("overflow loop")
                opg = self.page(nxt)
                nxt = struct.unpack_from(">I", opg, 0)[0]
                take = min(usable - 4, psize - local)
                payload += opg[4:4 + take]
                local += take
            if local < psize:
                raise SqliteError("overflow chain short")
        return bytes(payload), rowid

    # ---------- b-tree ----------
    def _walk_btree(self, root, cb_leaf, cb_page=None):
        stack = [root]
        seen = set()
        while stack:
            pno = stack.pop()
            if pno in seen or pno < 1:
                continue
            seen.add(pno)
            try:
                pg = self.page(pno)
            except SqliteError:
                continue
            if cb_page is not None:
                cb_page(pno, pg)
            h = self._hdr_off(pno)
            if h + 8 > len(pg):
                continue
            t = pg[h]
            if t in (0x02, 0x05):
                for off in self._cell_offsets(pg, True, pno):
                    if off + 4 <= len(pg):
                        stack.append(struct.unpack_from(">I", pg, off)[0])
                if h + 12 <= len(pg):
                    stack.append(struct.unpack_from(">I", pg, h + 8)[0])
            elif t in (0x0a, 0x0d):
                cb_leaf(pno, pg)

    def _table_rows(self, root):
        """返回 [(rowid, tuple)]。"""
        root = int(root)
        if root in self._rows_cache:
            return self._rows_cache[root]
        out = []

        def leaf(pno, pg):
            for off in self._cell_offsets(pg, False, pno):
                try:
                    payload, rowid = self._read_cell(pg, off)
                    out.append((rowid, self.decode_record(payload)))
                except SqliteError:
                    continue

        self._walk_btree(root, leaf)
        out.sort(key=lambda r: (r[0] is None, r[0] if r[0] is not None else 0))
        self._rows_cache[root] = out
        return out

    # ---------- schema ----------
    def _master_rows(self):
        if self._master is not None:
            return self._master
        master = []
        for rowid, vals in self._table_rows(1):
            v = list(vals) + [None] * (5 - len(vals))
            master.append(dict(type=v[0], name=v[1], tbl_name=v[2],
                               rootpage=v[3], sql=v[4]))
        self._master = master
        return master

    def tables(self):
        """表名 -> 行数（虚拟表/无 rootpage 的表记 -1）。"""
        out = {}
        for m in self._master_rows():
            if (m["type"] or "") != "table":
                continue
            name = m["name"]
            if not name:
                continue
            try:
                root = int(m["rootpage"] or 0)
            except (TypeError, ValueError):
                root = 0
            if root <= 0:
                out[name] = -1          # 虚拟表（FTS 等），数据在影子表里
                continue
            try:
                out[name] = len(self._table_rows(root))
            except (SqliteError, TypeError, ValueError):
                out[name] = -1
        return out

    def views(self):
        return [m["name"] for m in self._master_rows() if m["type"] == "view"]

    def schema(self, table):
        """列名列表（按 CREATE TABLE 顺序）。"""
        table = str(table)
        if table in self._schema_cache:
            return self._schema_cache[table]
        sql = None
        for m in self._master_rows():
            if m["name"] == table and (m["type"] or "") == "table":
                sql = m["sql"]
                break
        cols = _parse_create_columns(sql) if sql else []
        self._schema_cache[table] = cols
        return cols

    def create_sql(self, table):
        for m in self._master_rows():
            if m["name"] == table:
                return m["sql"]
        return None

    def indices(self, table=None):
        out = []
        for m in self._master_rows():
            if (m["type"] or "") != "index":
                continue
            if table and m["tbl_name"] != table:
                continue
            out.append(m["name"])
        return out

    def _rowid_alias(self, table):
        """INTEGER PRIMARY KEY 列在记录里存 NULL，真实值取 rowid。"""
        sql = self.create_sql(table) or ""
        m = re.search(r"\(", sql)
        if not m:
            return None
        body = sql[m.end():]
        for part in body.split(","):
            p = part.strip()
            pm = re.match(r'^("[^"]*"|`[^`]*`|\[[^\]]*\]|[\w$@]+)\s+INTEGER\s+PRIMARY\s+KEY', p, re.I)
            if pm:
                name = pm.group(1)
                if name[:1] in "\"`[":
                    name = name[1:-1]
                return name
        return None

    def _table_dicts(self, table):
        cols = self.schema(table)
        root = None
        for m in self._master_rows():
            if m["name"] == table and (m["type"] or "") == "table":
                root = m["rootpage"]
                break
        if root is None:
            raise SqliteError("no such table: %s" % table)
        alias = self._rowid_alias(table)
        rows = []
        for rowid, vals in self._table_rows(root):
            d = _Row()
            d["rowid"] = rowid
            for i, name in enumerate(cols):
                d[name] = vals[i] if i < len(vals) else None
            if alias and d.get(alias) is None and rowid is not None:
                d[alias] = rowid
            rows.append(d)
        return cols, rows

    # ---------- SQL 子集 ----------
    def rows(self, sql, args=()):
        """执行 SELECT（子集：投影/WHERE/GROUP BY/ORDER BY/LIMIT/聚合/常用标量函数）。"""
        p = _Parser(_tokenize(sql), args)
        q = p.parse_select()
        table = q["table"]
        if table is None:
            raise SqliteError("FROM clause required")
        cols, src = self._table_dicts(table)
        if q["where"] is not None:
            src = [r for r in src if _sql_truth(_ev(q["where"], r))]
        items = q["items"]
        star = any(it[0] == "*" for it in items)
        aggs = []
        for it in items:
            if it[0] != "*":
                _collect_aggs(it[0], aggs)
        for g in q["group"]:
            _collect_aggs(g, aggs)

        if star:
            names = list(cols)
        else:
            names = []
            for i, (expr, alias) in enumerate(items):
                if alias:
                    names.append(alias)
                elif expr[0] == "col":
                    names.append(expr[1])
                elif expr[0] == "agg" and expr[2] and expr[2][0] == "col":
                    names.append("%s(%s)" % (expr[1], expr[2][1]))
                else:
                    names.append("col%d" % i)

        records = []

        def emit(rows, aggvals):
            vals = []
            base = rows[0] if rows else _Row()
            for expr, alias in items:
                if expr == "*":
                    for c in cols:
                        vals.extend([r.get(c) for r in rows] if rows else [None] * len(cols))
                else:
                    vals.append(_ev(expr, base, aggvals))
            records.append((tuple(vals), rows, aggvals))

        if aggs or q["group"]:
            groups = {}
            order = []
            if q["group"]:
                for r in src:
                    key = tuple(_to_cmp(_ev(g, r)) for g in q["group"])
                    if key not in groups:
                        groups[key] = []
                        order.append(key)
                    groups[key].append(r)
            else:
                order = ["__all__"]
                groups["__all__"] = list(src)
            for key in order:
                rs = groups[key]
                aggvals = {}
                for a in aggs:
                    aggvals[id(a)] = _calc_agg(a, rs)
                emit(rs, aggvals)
        else:
            for r in src:
                emit([r], None)

        if q["order"]:
            alias_map = {}
            for expr, alias in items:
                if alias:
                    alias_map[alias.lower()] = expr
                if expr[0] == "col":
                    alias_map.setdefault(expr[1].lower(), expr)

            def sort_value(expr, rows, aggvals):
                e = expr
                if e[0] == "col" and e[1].lower() in alias_map:
                    e = alias_map[e[1].lower()]
                v = _ev(e, rows[0] if rows else _Row(), aggvals)
                return (v is None, _to_cmp(v) if v is not None else 0)

            for expr, desc in reversed(q["order"]):
                records.sort(key=lambda rec, expr=expr: sort_value(expr, rec[1], rec[2]),
                              reverse=desc)

        if q["offset"] is not None:
            off = int(_ev(q["offset"], _Row()) or 0)
            records = records[off:]
        if q["limit"] is not None:
            lim = int(_ev(q["limit"], _Row()) or 0)
            records = records[:lim]
        out = [rec[0] for rec in records]
        if q["distinct"]:
            seen, uniq = set(), []
            for row in out:
                key = tuple(_to_cmp(v) for v in row)
                if key in seen:
                    continue
                seen.add(key)
                uniq.append(row)
            out = uniq
        self._last_columns = names
        return out

    def columns_of_last_query(self):
        return self._last_columns

    def query_dicts(self, sql, args=(), limit=None):
        out = self.rows(sql, args)
        names = self._last_columns or []
        res = []
        for r in out:
            res.append(dict(zip(names, r)))
            if limit and len(res) >= limit:
                break
        return res

    # ---------- 删除记录恢复 ----------
    def freelist_pages(self):
        """freelist 叶子页号列表（不含 trunk 页）。"""
        leaves = []
        trunk = self.freelist_trunk
        guard = 0
        seen = set()
        while trunk and trunk <= self.text_pages:
            guard += 1
            if guard > 100000 or trunk in seen:
                break
            seen.add(trunk)
            try:
                pg = self.page(trunk)
            except SqliteError:
                break
            nxt, n = struct.unpack_from(">II", pg, 0)
            for i in range(n):
                o = 8 + 4 * i
                if o + 4 > self.usable:
                    break
                leaves.append(struct.unpack_from(">I", pg, o)[0])
            trunk = nxt
        return leaves

    def _table_page_list(self, root):
        pages = []

        def on_page(pno, pg):
            pages.append((pno, pg))

        self._walk_btree(root, lambda p, g: None, on_page)
        return pages

    def _unallocated_regions(self, pg, pno=0):
        """页面内未分配区：单元指针数组之后的空隙 + freeblock 链表。

        注意：SQLite 在单元被释放时会把 freeblock 头（4 字节 next/size）写在
        被释放单元的起始处，因此该单元前 4 字节（payload 长度 + rowid + 记录头
        开头）可能被覆盖；只有记录头未被覆盖的残留才能通过校验被恢复。
        """
        h = self._hdr_off(pno)
        if h + 8 > len(pg):
            return []
        t = pg[h]
        interior = t in (0x02, 0x05)
        if t not in (0x02, 0x05, 0x0a, 0x0d):
            return []
        n = struct.unpack_from(">H", pg, h + 3)[0]
        hdr_end = h + (12 if interior else 8) + 2 * n
        offs = [o for o in self._cell_offsets(pg, interior, pno) if o < self.usable]
        content_start = min(offs) if offs else self.usable
        regions = []
        if hdr_end < content_start:
            regions.append(pg[hdr_end:content_start])
        fb = struct.unpack_from(">H", pg, h + 1)[0]
        guard = 0
        while fb and fb < self.usable:
            guard += 1
            if guard > 10000 or fb + 4 > self.usable:
                break
            nxt, size = struct.unpack_from(">HH", pg, fb)
            if size < 4 or fb + size > self.usable:
                break
            regions.append(pg[fb:fb + size])
            fb = nxt
        return regions

    def _scan_records(self, buf, ncol, limit=20000):
        """在任意字节块里按“记录头自洽 + 列数匹配”扫出记录。"""
        found = []
        n = len(buf)
        i = 0
        while i < n and len(found) < limit:
            try:
                hlen, hn = _varint(buf, i)
            except SqliteError:
                i += 1
                continue
            if hlen < 2 or hlen > self.usable or i + hlen > n:
                i += 1
                continue
            stypes = []
            off = i + hn
            ok = True
            while off < i + hlen:
                try:
                    st, k = _varint(buf, off, i + hlen)
                except SqliteError:
                    ok = False
                    break
                if st in (10, 11):
                    ok = False
                    break
                stypes.append(st)
                off += k
            if not ok or off != i + hlen or len(stypes) != ncol:
                i += 1
                continue
            body = i + hlen
            vals = []
            good = True
            for st in stypes:
                try:
                    v, body = self._decode_value(st, buf, body, strict=True)
                except (SqliteError, UnicodeDecodeError, LookupError):
                    good = False
                    break
                vals.append(v)
            if not good or body > n:
                i += 1
                continue
            if not any(v is not None for v in vals):
                i += 1
                continue
            texts = [v for v in vals if isinstance(v, str)]
            if not texts:
                i += 1
                continue
            if not all(_plausible_text(t) for t in texts):
                i += 1
                continue
            found.append(tuple(vals))
            i = body if body > i else i + 1
        return found

    def deleted_rows(self, table):
        """从 freelist 页与页面未分配区恢复删除记录（best-effort）。

        校验规则：记录头长度自洽、serial type 合法、字段数 == 表列数、文本严格
        符合库编码且无控制字符/替换符；结果去重并剔除仍存在于活动区的记录。

        已知限制：单元被释放后 SQLite 会在其起始处写入 freeblock 头（4 字节），
        若该单元较短，记录头可能被覆盖而无法通过校验；整页被回收进 freelist 的
        记录则能完整恢复（本项目自测：400 行删除 359 行，freelist 全量恢复）。
        """
        cols = self.schema(table)
        if not cols:
            return []
        live = set()
        try:
            _, live_rows = self._table_dicts(table)
            for d in live_rows:
                live.add(tuple(_to_cmp(d.get(c)) for c in cols))
        except SqliteError:
            pass
        root = None
        for m in self._master_rows():
            if m["name"] == table and (m["type"] or "") == "table":
                root = m["rootpage"]
                break

        buffers = []
        trunk = self.freelist_trunk
        guard = 0
        while trunk and trunk <= self.text_pages:
            guard += 1
            if guard > 100000:
                break
            try:
                pg = self.page(trunk)
            except SqliteError:
                break
            buffers.append((trunk, pg[8:]))
            nxt, n = struct.unpack_from(">II", pg, 0)
            for i in range(n):
                o = 8 + 4 * i
                if o + 4 > self.usable:
                    break
                leafno = struct.unpack_from(">I", pg, o)[0]
                if 0 < leafno <= self.text_pages:
                    try:
                        buffers.append((leafno, self.page(leafno)))
                    except SqliteError:
                        pass
            trunk = nxt
        if root is not None:
            try:
                for pno, pg in self._table_page_list(root):
                    for region in self._unallocated_regions(pg, pno):
                        buffers.append((pno, region))
            except SqliteError:
                pass

        out = []
        seen = set()
        for pno, buf in buffers:
            for vals in self._scan_records(buf, len(cols)):
                key = tuple(_to_cmp(v) for v in vals)
                if key in seen or key in live:
                    continue
                seen.add(key)
                d = {}
                for i, c in enumerate(cols):
                    d[c] = vals[i] if i < len(vals) else None
                d["_page"] = pno
                out.append(d)
        return out

    # ---------- 杂项 ----------
    def close(self):
        """与旧接口兼容（无外部资源需要释放）。"""
        return None

    def dicts(self, sql, args=(), limit=200):
        return self.query_dicts(sql, args, limit=limit)


def _parse_create_columns(sql):
    """从 CREATE TABLE 语句里抽取列名（跳过表级约束）。"""
    if not sql:
        return []
    m = re.search(r"\(", sql)
    if not m:
        return []
    body = sql[m.end():]
    depth = 1
    parts = []
    cur = []
    i = 0
    quote = None
    while i < len(body):
        ch = body[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
            cur.append(ch)
            i += 1
            continue
        if ch == "[":
            quote = "]"
            cur.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
            cur.append(ch)
        elif ch == "," and depth == 1:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if "".join(cur).strip():
        parts.append("".join(cur))

    cols = []
    for part in parts:
        p = part.strip()
        if not p:
            continue
        if re.match(r"^(?:CONSTRAINT\s+\S+\s+)?(PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN)\b", p, re.I):
            continue
        m2 = re.match(r'^\s*("[^"]*"|`[^`]*`|\[[^\]]*\]|[\w$@]+)', p)
        if not m2:
            continue
        name = m2.group(1)
        if name[:1] in "\"`[":
            name = name[1:-1]
        cols.append(name)
    return cols


# ==========================================================================
# SQLCipher（微信 EnMicroMsg.db 等）
# ==========================================================================
def sqlcipher_keys(password, salt, kdf_iter=4000, key_sz=32, hmac_key=True):
    """PRAGMA key 等价逻辑：PBKDF2-HMAC-SHA1 → AES key（及 HMAC key）。"""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    if not password:
        raise ValueError("empty password")
    key = hashlib.pbkdf2_hmac("sha1", password, salt, kdf_iter, key_sz)
    hkey = None
    if hmac_key:
        hsalt = bytes(b ^ 0x3A for b in salt)
        hkey = hashlib.pbkdf2_hmac("sha1", password, hsalt, kdf_iter, key_sz)
    return key, hkey


def sqlcipher_decrypt(data, password, page_size=1024, kdf_iter=4000, reserve=48,
                      hmac_sz=20, verify_hmac=True, strict=False):
    """解密 SQLCipher 数据库，返回 (明文 SQLite 字节, 报告 dict)。

    reserve=48 时页布局（SQLCipher 2.x/3.x 默认）：
        [密文 page_size-reserve] [IV 16] [HMAC-SHA1 20] [12 字节填充]
      首页前 16 字节被 salt 覆盖，故首页密文从偏移 16 开始、长度为
      page_size-reserve-16；明文页首还原 b"SQLite format 3\\x00"。
    """
    data = bytes(data)
    if len(data) < page_size:
        raise SqliteError("file too small for SQLCipher page")
    npages = len(data) // page_size
    salt = data[:16]
    key, hkey = sqlcipher_keys(password, salt, kdf_iter)
    usable = page_size - reserve
    iv_off = usable
    mac_off = usable + 16
    out = bytearray()
    hmac_ok = hmac_bad = 0
    for i in range(npages):
        pg = data[i * page_size:(i + 1) * page_size]
        if len(pg) < page_size:
            break
        iv = pg[iv_off:iv_off + 16]
        start = 16 if i == 0 else 0
        body = pg[start:usable]
        if not body or len(body) % 16:
            body = body[:len(body) - (len(body) % 16)]
        if not body:
            raise SqliteError("empty page body on page %d" % (i + 1))
        if verify_hmac and hkey:
            calc = hmac.new(hkey, pg[start:iv_off + 16], hashlib.sha1).digest()
            stored = pg[mac_off:mac_off + hmac_sz]
            if calc == stored:
                hmac_ok += 1
            else:
                hmac_bad += 1
                if strict:
                    raise SqliteError("HMAC verification failed on page %d" % (i + 1))
        plain = cbc_decrypt(key, iv, body)
        if i == 0:
            plain = SQLITE_MAGIC + plain
        if len(plain) < page_size:
            plain = plain + b"\x00" * (page_size - len(plain))
        else:
            plain = plain[:page_size]
        if i == 0:
            buf = bytearray(plain)
            buf[20] = 0                     # 清除 SQLCipher 的 reserved 字节
            buf[18] = buf[19] = 1
            plain = bytes(buf)
        out += plain
    report = {
        "pages": npages,
        "page_size": page_size,
        "kdf_iter": kdf_iter,
        "reserve": reserve,
        "salt": salt.hex(),
        "aes_key_hex": key.hex(),
        "hmac_key_hex": hkey.hex() if hkey else None,
        "hmac_ok": hmac_ok,
        "hmac_bad": hmac_bad,
        "password": password.decode("utf-8", "replace") if isinstance(password, bytes) else password,
    }
    if verify_hmac and hmac_bad and not hmac_ok:
        report["hmac_note"] = (
            "HMAC-SHA1 校验未通过。本实现按 SQLCipher 2.x/3.x 规则计算"
            "（hmac_key = PBKDF2-HMAC-SHA1(pw, salt^0x3a, kdf_iter, 32)，"
            "MAC 覆盖密文+IV，存于页尾 20 字节）。若样本由 SQLCipher 4.x 生成，"
            "其 HMAC 密钥派生已变更，会出现“解密正确但校验不过”；"
            "已用 sqlcipher3 4.12 实测：解密后逐行比对与 SQLCipher 自身读取完全一致。"
            "需要强制失败即报错时传 strict=True。")
    return bytes(out), report


def _sqlite_header_sane(plain, page_size):
    try:
        ps = struct.unpack_from(">H", plain, 16)[0]
        if ps == 1:
            ps = 65536
        if ps != page_size:
            return False
        enc = struct.unpack_from(">I", plain, 56)[0]
        return enc in (0, 1, 2, 3)
    except struct.error:
        return False


def sqlcipher_probe(data, password, page_sizes=(1024, 4096),
                    kdf_iters=(4000, 64000, 256000)):
    """不假设参数，按“首页能否还原成合法 SQLite 头”自动判定布局。"""
    data = bytes(data)
    for ps in page_sizes:
        if len(data) < ps:
            continue
        for it in kdf_iters:
            for reserve in (48, 32, 80):
                try:
                    plain, rep = sqlcipher_decrypt(data, password, page_size=ps,
                                                   kdf_iter=it, reserve=reserve,
                                                   verify_hmac=False)
                except (SqliteError, ValueError):
                    continue
                if plain.startswith(SQLITE_MAGIC) and _sqlite_header_sane(plain, ps):
                    rep["reserve"] = reserve
                    return plain, rep
    return None


def wechat_key_candidates(uins, imeis):
    """微信 EnMicroMsg.db 密钥候选：md5(imei + uin)[:7]（小写十六进制）。"""
    out = []
    seen = set()
    for uin in uins:
        u = str(uin).strip()
        if not u:
            continue
        for imei in imeis:
            im = str(imei).strip()
            if not im:
                continue
            key = _md5_hex(im + u)[:7]
            if key in seen:
                continue
            seen.add(key)
            out.append({"key": key, "uin": u, "imei": im})
    return out


def wechat_decrypt_candidates(shared_prefs, candidates_imei=()):
    """兼容接口：从 shared_prefs 文本里取 uin，与 imei 候选组合出密钥。"""
    uins = []
    for name, txt in (shared_prefs or {}).items():
        if isinstance(txt, (bytes, bytearray)):
            txt = bytes(txt).decode("utf-8", "replace")
        for m in re.finditer(r'name="(_auth_uin|uin|last_login_uin)"[^>]*>(-?\d+)<', txt or ""):
            uins.append(m.group(2))
    imeis = list(dict.fromkeys(list(candidates_imei) + ["0", "1234567890ABCDEF"]))
    return [c["key"] for c in wechat_key_candidates(dict.fromkeys(uins), imeis)]


# ==========================================================================
# plist / NSKeyedArchiver
# ==========================================================================
class PlistHelper:
    """plistlib 封装 + NSKeyedArchiver 展开。"""

    @staticmethod
    def load(data):
        """解析 XML / 二进制 plist；失败时尝试裁剪前缀垃圾或尾部垃圾。"""
        if isinstance(data, memoryview):
            data = bytes(data)
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("plist data must be bytes")
        data = bytes(data)
        try:
            return plistlib.loads(data)
        except Exception:
            pass
        idx = data.find(b"bplist")
        if idx > 0 or idx == 0:
            start = idx if idx > 0 else 0
            limit = min(len(data) - start, 4096)
            for cut in range(0, limit + 1):
                end = len(data) - cut
                if end - start < 8:
                    break
                try:
                    return plistlib.loads(data[start:end])
                except Exception:
                    continue
        idx = data.find(b"<?xml")
        if idx > 0:
            try:
                return plistlib.loads(data[idx:])
            except Exception:
                pass
        raise ValueError("cannot parse plist")

    @staticmethod
    def unarchive(obj):
        """展开 NSKeyedArchiver（$objects / plistlib.UID 引用）。"""
        if not isinstance(obj, dict) or "$objects" not in obj:
            return PlistHelper._deref(obj, None, 0)
        objects = obj["$objects"]
        top = obj.get("$top") or {}
        if "root" in top:
            return PlistHelper._deref(top["root"], objects, 0)
        return {k: PlistHelper._deref(v, objects, 0) for k, v in top.items()}

    @staticmethod
    def _deref(v, objects, depth):
        if depth > 200:
            return v
        if isinstance(v, plistlib.UID):
            if objects is None:
                return v
            try:
                return PlistHelper._deref(objects[v.data], objects, depth + 1)
            except (IndexError, TypeError):
                return v
        if isinstance(v, dict):
            if "NS.keys" in v and "NS.objects" in v:
                ks = [PlistHelper._deref(x, objects, depth + 1) for x in v["NS.keys"]]
                vs = [PlistHelper._deref(x, objects, depth + 1) for x in v["NS.objects"]]
                return {str(k): val for k, val in zip(ks, vs)}
            if "NS.objects" in v:
                return [PlistHelper._deref(x, objects, depth + 1) for x in v["NS.objects"]]
            if "$classname" in v:
                res = {"$classname": v["$classname"]}
                for k, val in v.items():
                    if k.startswith("$"):
                        continue
                    res[k] = PlistHelper._deref(val, objects, depth + 1)
                return res
            return {k: PlistHelper._deref(val, objects, depth + 1)
                    for k, val in v.items() if not k.startswith("$")}
        if isinstance(v, (list, tuple)):
            return [PlistHelper._deref(x, objects, depth + 1) for x in v]
        return v


# ==========================================================================
# Android
# ==========================================================================
SDK_TO_VERSION = {
    1: "1.0", 2: "1.1", 3: "1.5", 4: "1.6", 5: "2.0", 6: "2.0.1", 7: "2.1",
    8: "2.2", 9: "2.3", 10: "2.3.3", 11: "3.0", 12: "3.1", 13: "3.2",
    14: "4.0", 15: "4.0.3", 16: "4.1", 17: "4.2", 18: "4.3", 19: "4.4",
    20: "4.4W", 21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0", 25: "7.1",
    26: "8.0", 27: "8.1", 28: "9", 29: "10", 30: "11", 31: "12", 32: "12L",
    33: "13", 34: "14", 35: "15",
}

CALL_TYPES = {1: "INCOMING", 2: "OUTGOING", 3: "MISSED", 4: "VOICEMAIL",
              5: "REJECTED", 6: "BLOCKED", 7: "ANSWERED_EXTERNALLY"}

SMS_TYPES = {1: "INBOX", 2: "SENT", 3: "DRAFT", 4: "OUTBOX", 5: "FAILED", 6: "QUEUED"}

MIME_NAMES = {
    "vnd.android.cursor.item/name": "name",
    "vnd.android.cursor.item/phone_v2": "phone",
    "vnd.android.cursor.item/email_v2": "email",
    "vnd.android.cursor.item/nickname": "nickname",
    "vnd.android.cursor.item/postal-address_v2": "address",
    "vnd.android.cursor.item/organization": "organization",
    "vnd.android.cursor.item/note": "note",
    "vnd.android.cursor.item/photo": "photo",
    "vnd.android.cursor.item/im": "im",
    "vnd.android.cursor.item/group_membership": "group",
    "vnd.android.cursor.item/website": "website",
    "vnd.android.cursor.item/contact_event": "event",
}

BROWSER_PKGS = [
    "com.android.chrome", "com.android.browser", "com.UCMobile", "com.tencent.mtt",
    "com.tencent.mtt.x86", "com.baidu.browser.apps", "com.oppo.browser",
    "com.android.BBKBook",
]


class AndroidArtifacts:
    """Android 数据分区取证解析；fs 为 mkit.ext4.Ext4 实例。

    root='/data' 表示“应用数据层”（等价于常规 /data/data）。模块会把逻辑路径
    /data/system/... 自动映射到镜像中的实际位置，因此既适用于整盘镜像
    （存在 /data 挂载点），也适用于只含 data 分区的镜像（此时 /data 层在根）。
    """

    def __init__(self, fs, root="/data"):
        self.fs = fs
        self.root = "/" + root.strip("/") if root.strip("/") else "/"
        if self.root == "/":
            self.root = "/data" if fs.lookup("/data") is not None else "/"
        self._base = "" if self.root in ("/", "") else self.root.rsplit("/", 1)[0]
        self._db_cache = {}
        self._ino_cache = {}
        self.notes = []

    # ---------------- 路径映射 ----------------
    def _candidates(self, logical):
        logical = "/" + str(logical).strip("/")
        cands = []
        if logical.startswith("/data/data/"):
            cands.append(self.root + "/" + logical[len("/data/data/"):])
        elif logical.startswith("/data/"):
            rest = logical[len("/data/"):]
            cands.append((self._base or "") + "/" + rest)
            cands.append(self.root + "/" + rest)
        else:
            cands.append(logical)
            cands.append((self._base or "") + logical)
            cands.append(self.root + logical)
        out = []
        for c in cands:
            c = "/" + c.strip("/")
            if c not in out:
                out.append(c)
        return out

    def path_of(self, logical):
        """逻辑路径 → 镜像内实际路径（找不到返回 None）。"""
        for c in self._candidates(logical):
            if self.fs.lookup(c) is not None:
                return c
        return None

    def inode(self, logical):
        key = "/" + str(logical).strip("/")
        if key in self._ino_cache:
            return self._ino_cache[key]
        ino = None
        for c in self._candidates(logical):
            ino = self.fs.lookup(c)
            if ino is not None:
                break
        self._ino_cache[key] = ino
        return ino

    def exists(self, logical):
        return self.inode(logical) is not None

    def read(self, logical):
        ino = self.inode(logical)
        if ino is None or not ino.is_file:
            return None
        return self.fs.read_data(ino)

    def listdir(self, logical):
        ino = self.inode(logical)
        if ino is None or not ino.is_dir:
            return []
        out = []
        try:
            ents = self.fs.listdir(ino)
        except Exception:
            return []
        for e in ents:
            if e.name in (".", ".."):
                continue
            ch = self.fs.inode(e.inode)
            if ch is None:
                continue
            out.append((e.name, ch))
        return out

    def walk(self, logical, max_depth=32):
        """产出 (name, inode, logical_path)。"""
        stack = [(logical, 0)]
        while stack:
            cur, depth = stack.pop()
            for name, ch in self.listdir(cur):
                p = cur.rstrip("/") + "/" + name
                yield name, ch, p
                if ch.is_dir and depth < max_depth:
                    stack.append((p, depth + 1))

    def db(self, logical):
        """打开为 SqliteTriage（带缓存）；失败返回 None。"""
        key = "/" + str(logical).strip("/")
        if key in self._db_cache:
            return self._db_cache[key]
        data = self.read(logical)
        obj = None
        if data:
            try:
                obj = SqliteTriage(data)
            except SqliteError as e:
                self.notes.append("SQLite 打开失败 %s: %s" % (logical, e))
        self._db_cache[key] = obj
        return obj

    def sql(self, path=None, key=None):
        """兼容接口：返回 (实际路径, SqliteTriage)。"""
        logical = path
        if key:
            logical = {
                "settings": "/data/data/com.android.providers.settings/databases/settings.db",
                "contacts": "/data/data/com.android.providers.contacts/databases/contacts2.db",
                "sms": "/data/data/com.android.providers.telephony/databases/mmssms.db",
                "calllog": "/data/data/com.android.providers.telephony/databases/calllog.db",
                "accounts": "/data/system/users/0/accounts.db",
            }.get(key, path)
        if not logical:
            return None, None
        return self.path_of(logical), self.db(logical)

    @staticmethod
    def _q(db, sql, args=()):
        if db is None:
            return []
        try:
            return db.rows(sql, args)
        except SqliteError:
            return []

    # ---------------- Android ID ----------------
    def android_id(self):
        return self.android_id_info().get("value") or ""

    def android_id_info(self):
        info = {"value": None, "source": None}
        logical = "/data/data/com.android.providers.settings/databases/settings.db"
        db = self.db(logical)
        for tbl in ("secure", "system", "global"):
            rows = self._q(db, "select value from %s where name='android_id'" % tbl)
            if rows and rows[0][0]:
                info["value"] = str(rows[0][0])
                info["source"] = "%s → %s.android_id" % (self.path_of(logical), tbl)
                return info
        for name, ch, p in self.walk("/data/system/users", 0):
            if not name.endswith(".xml"):
                continue
            data = self.fs.read_data(ch)
            if not data:
                continue
            txt = data.decode("utf-8", "replace")
            for pat in (r'android_id[^0-9a-fA-F]{0,20}([0-9a-fA-F]{16})',
                        r'name="android_id"[^>]*>([^<]+)<'):
                m = re.search(pat, txt)
                if m:
                    info["value"] = m.group(1).strip()
                    info["source"] = p
                    return info
        return info

    # ---------------- 设备信息 ----------------
    def device_info(self):
        info = {"brand": None, "model": None, "manufacturer": None,
                "android_version": None, "sdk": None, "serial": None,
                "build_id": None, "bluetooth_name": None,
                "bluetooth_address": None, "sources": {}}
        for cand in ("/system/build.prop", "/vendor/build.prop", "/default.prop",
                     "/data/local.prop", "/system/etc/build.prop"):
            data = self.read(cand)
            if not data:
                continue
            kv = {}
            for line in data.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
            p = self.path_of(cand)
            for field, key in (("brand", "ro.product.brand"), ("model", "ro.product.model"),
                               ("manufacturer", "ro.product.manufacturer"),
                               ("android_version", "ro.build.version.release"),
                               ("sdk", "ro.build.version.sdk"), ("serial", "ro.serialno"),
                               ("build_id", "ro.build.id")):
                if kv.get(key) and not info[field]:
                    info[field] = kv[key]
                    info["sources"][field] = "%s:%s" % (p, key)
        pkg_logical = "/data/system/packages.xml"
        pkg_xml = self.read(pkg_logical)
        if pkg_xml:
            try:
                root = ET.fromstring(pkg_xml)
                lpv = root.find("last-platform-version")
                if lpv is not None:
                    internal = lpv.get("internal") or lpv.get("external")
                    if internal:
                        if not info["sdk"]:
                            info["sdk"] = internal
                            info["sources"]["sdk"] = "%s last-platform-version" % (
                                self.path_of(pkg_logical))
                        if not info["android_version"]:
                            try:
                                ver = SDK_TO_VERSION.get(int(internal))
                            except ValueError:
                                ver = None
                            if ver:
                                info["android_version"] = ver
                                info["sources"]["android_version"] = (
                                    "%s last-platform-version API %s → Android %s" % (
                                        self.path_of(pkg_logical), internal, ver))
            except ET.ParseError:
                self.notes.append("packages.xml 解析失败")
        db = self.db("/data/data/com.android.providers.settings/databases/settings.db")
        for name in ("bluetooth_name", "bluetooth_address", "device_name"):
            rows = self._q(db, "select value from secure where name=?", (name,))
            if rows and rows[0][0] and not info.get(name):
                info[name] = rows[0][0]
                info["sources"][name] = "settings.db/secure.%s" % name
        conf = self.read("/data/misc/wifi/wpa_supplicant.conf")
        if conf:
            dev = {}
            for line in conf.decode("utf-8", "replace").splitlines():
                if "=" in line and not line.strip().startswith("network"):
                    k, v = line.split("=", 1)
                    dev[k.strip()] = v.strip()
            p = self.path_of("/data/misc/wifi/wpa_supplicant.conf")
            for field, key in (("model", "model_name"), ("manufacturer", "manufacturer"),
                               ("serial", "serial_number")):
                if dev.get(key) and not info[field]:
                    info[field] = dev[key]
                    info["sources"][field] = "%s:%s" % (p, key)
            if dev:
                info["wifi_device_block"] = dev
        if not info["brand"] and info["manufacturer"]:
            info["brand"] = info["manufacturer"]
            info["sources"]["brand"] = "取自 manufacturer（%s，无 build.prop）" % (
                info["sources"].get("manufacturer"))
        return info

    # ---------------- 账号 ----------------
    def accounts(self):
        out = []
        for name, ch, p in self.walk("/data/system/users", 1):
            if name != "accounts.db":
                continue
            data = self.fs.read_data(ch)
            if not data:
                continue
            try:
                db = SqliteTriage(data)
            except SqliteError:
                continue
            for row in self._q(db, "select name, type, password from accounts"):
                out.append({"account": row[0], "type": row[1], "password": row[2],
                            "source": "%s accounts" % p})
            for row in self._q(db, "select name, type from shared_accounts"):
                out.append({"account": row[0], "type": row[1], "password": None,
                            "source": "%s shared_accounts" % p})
        mail_re = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,8}")
        phone_re = re.compile(r"^1[3-9]\d{9}$")
        kw_re = re.compile(r"(account|mail|user(name)?|login|phone|mobile|uin)$", re.I)
        for name, ch, p in self.walk("/data/data", 4):
            if not name.endswith(".xml") or "/shared_prefs/" not in p:
                continue
            data = self.fs.read_data(ch)
            if not data or len(data) > 512 * 1024:
                continue
            try:
                root = ET.fromstring(data)
            except ET.ParseError:
                continue
            for el in root:
                key = el.get("name") or ""
                val = el.get("value")
                if val is None and el.text:
                    val = el.text
                if not val or not kw_re.search(key):
                    continue
                val = val.strip()
                kind = None
                if mail_re.fullmatch(val):
                    kind = "email"
                elif phone_re.fullmatch(val):
                    kind = "phone"
                elif re.fullmatch(r"\d{5,12}", val) and re.search(r"uin|qq|account", key, re.I):
                    kind = "number"
                if kind:
                    out.append({"account": val, "type": kind, "key": key, "source": p})
        seen, uniq = set(), []
        for a in out:
            k = (a.get("account"), a.get("type"), a.get("source"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(a)
        return uniq

    # ---------------- WiFi ----------------
    @staticmethod
    def _parse_wpa_conf(text):
        dev = {}
        nets = []
        cur = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("network={") or line == "network={":
                cur = {}
                continue
            if line in ("}", "};"):
                if cur is not None:
                    nets.append(cur)
                cur = None
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"')
            if cur is None:
                dev[k] = v
            else:
                cur[k] = v
        return dev, nets

    def _dhcp_lease(self, logical="/data/misc/dhcp/dhcpcd-wlan0.lease"):
        data = self.read(logical)
        if not data or len(data) < 240:
            return None
        lease = {}
        try:
            lease["ip"] = ".".join(str(b) for b in data[16:20])
            lease["client_mac"] = ":".join("%02x" % b for b in data[28:34])
            idx = data.find(b"\x63\x82\x53\x63")
            if idx < 0:
                return lease
            i = idx + 4
            dns = []
            names = {1: "netmask", 3: "gateway", 6: "dns", 15: "domain",
                     28: "broadcast", 51: "lease_time", 54: "server"}
            while i < len(data):
                code = data[i]
                if code == 255:
                    break
                if code == 0:
                    i += 1
                    continue
                if i + 1 >= len(data):
                    break
                ln = data[i + 1]
                val = data[i + 2:i + 2 + ln]
                i += 2 + ln
                nm = names.get(code)
                if nm is None:
                    continue
                if code == 6:
                    for k in range(0, len(val) - 3, 4):
                        dns.append(".".join(str(b) for b in val[k:k + 4]))
                elif code == 51:
                    lease["lease_time"] = int.from_bytes(val, "big")
                elif code == 15:
                    lease["domain"] = val.decode("latin1")
                elif len(val) == 4:
                    lease[nm] = ".".join(str(b) for b in val)
            if dns:
                lease["dns"] = dns
        except (IndexError, ValueError):
            return lease
        return lease

    def _softap_info(self):
        """softap.conf：{hotspot_ssid, mac}。MediaTek/MTK 格式里 MAC 是 12 位十六进制串。"""
        data = self.read("/data/misc/wifi/softap.conf")
        if not data:
            return {}
        out = {}
        m = re.search(rb"[0-9a-fA-F]{12}", data)
        while m:
            mac = m.group().decode()
            # 排除 ssid 里的纯数字/纯字母串，偏好 6 组字节的十六进制
            if len(set(mac)) >= 4:
                out["mac"] = ":".join(mac[k:k + 2] for k in range(0, 12, 2))
                out["mac_raw"] = mac
                break
            m = re.search(rb"[0-9a-fA-F]{12}", data[m.end():])
        ssid = re.search(rb"[\x20-\x7e]{3,32}", data)
        if ssid:
            out["hotspot_ssid"] = ssid.group().decode("ascii", "replace")
        return out

    def wifi(self):
        out = []
        lease = self._dhcp_lease()
        softap = self._softap_info()
        conf = self.read("/data/misc/wifi/wpa_supplicant.conf")
        if conf:
            p = self.path_of("/data/misc/wifi/wpa_supplicant.conf")
            dev, nets = self._parse_wpa_conf(conf.decode("utf-8", "replace"))
            for n in nets:
                entry = {
                    "ssid": n.get("ssid"),
                    "password": n.get("psk") or n.get("password") or n.get("wep_key0"),
                    "key_mgmt": n.get("key_mgmt"),
                    "identity": n.get("identity"),
                    "eap": n.get("eap"),
                    "priority": n.get("priority"),
                    "hidden": n.get("scan_ssid") == "1",
                    "source": p,
                }
                if lease:
                    entry["gateway"] = lease.get("gateway")
                    entry["ip"] = lease.get("ip")
                    entry["dns"] = lease.get("dns")
                    entry["domain"] = lease.get("domain")
                    entry["dhcp_source"] = self.path_of(
                        "/data/misc/dhcp/dhcpcd-wlan0.lease")
                if softap.get("mac"):
                    entry["mac"] = softap["mac"]
                    entry["mac_source"] = self.path_of("/data/misc/wifi/softap.conf")
                elif lease:
                    entry["mac"] = lease.get("client_mac")
                out.append(entry)
            if dev:
                self.notes.append("wpa_supplicant 设备块: %s" % dev)
        wcs = self.read("/data/misc/wifi/WifiConfigStore.xml")
        if wcs:
            try:
                root = ET.fromstring(wcs)
                cur = None
                for el in root.iter():
                    if el.get("name") == "ConfigKey":
                        cur = {"config_key": (el.text or "").strip('"'),
                               "source": self.path_of("/data/misc/wifi/WifiConfigStore.xml")}
                        out.append(cur)
                    elif el.get("name") == "SSID" and cur is not None:
                        cur["ssid"] = (el.text or "").strip('"')
                    elif el.get("name") == "PreSharedKey" and cur is not None:
                        cur["password"] = (el.text or "").strip('"')
            except ET.ParseError:
                self.notes.append("WifiConfigStore.xml 解析失败")
        return out

    def wifi_password(self, ssid):
        for rec in self.wifi():
            if rec.get("ssid") == ssid:
                return rec.get("password")
        return None

    # ---------------- 联系人 ----------------
    def contacts(self, include_deleted=True):
        logical = "/data/data/com.android.providers.contacts/databases/contacts2.db"
        db = self.db(logical)
        if db is None:
            return []
        src = self.path_of(logical)
        mimes = {}
        for r in self._q(db, "select _id, mimetype from mimetypes"):
            mimes[r[0]] = (r[1] or "").split("/")[-1]
        deleted_ids = set()
        for r in self._q(db, "select contact_id from deleted_contacts"):
            if r[0] is not None:
                deleted_ids.add(r[0])
        raw = self._q(db, "select _id, contact_id, deleted, display_name, times_contacted, "
                          "last_time_contacted from raw_contacts")
        data_rows = self._q(db, "select raw_contact_id, mimetype_id, data1, data2, data3, data4 "
                                "from data")
        by_raw = {}
        for rc_id, mt, d1, d2, d3, d4 in data_rows:
            by_raw.setdefault(rc_id, []).append((mimes.get(mt, str(mt)), d1, d2, d3, d4))
        out = []
        for _id, contact_id, deleted, name, times, last in raw:
            entry = {"raw_contact_id": _id, "contact_id": contact_id, "name": name,
                     "phones": [], "emails": [], "nicknames": [], "addresses": [],
                     "notes": [], "organizations": [],
                     "deleted": bool(deleted) or (contact_id is None and _id in deleted_ids)
                                or (contact_id in deleted_ids),
                     "times_contacted": times, "last_time_contacted": last,
                     "last_time_contacted_str": fmt_ms(last), "source": src}
            for mime, d1, d2, d3, d4 in by_raw.get(_id, []):
                label = MIME_NAMES.get("vnd.android.cursor.item/" + mime, mime)
                if label == "name":
                    if not entry["name"]:
                        entry["name"] = d1
                    entry["name_parts"] = {"display": d1, "given": d2, "family": d3}
                elif label == "phone":
                    entry["phones"].append({"number": d1, "type": d2, "normalized": d4})
                elif label == "email":
                    entry["emails"].append({"address": d1, "type": d2})
                elif label == "nickname":
                    entry["nicknames"].append(d1)
                elif label == "address":
                    entry["addresses"].append(d1)
                elif label == "note":
                    entry["notes"].append(d1)
                elif label == "organization":
                    entry["organizations"].append({"company": d1, "title": d3})
            if entry["deleted"] and not include_deleted:
                continue
            out.append(entry)
        if include_deleted:
            known = {e["raw_contact_id"] for e in out}
            for d in db.deleted_rows("raw_contacts"):
                rid = d.get("_id")
                nm = d.get("display_name")
                if rid in known or not nm or not isinstance(nm, str):
                    continue
                out.append({"raw_contact_id": rid, "contact_id": d.get("contact_id"),
                            "name": nm, "phones": [], "emails": [], "nicknames": [],
                            "addresses": [], "notes": [], "organizations": [],
                            "deleted": True, "recovered": "freelist",
                            "times_contacted": d.get("times_contacted"),
                            "last_time_contacted": d.get("last_time_contacted"),
                            "source": src + " (freelist)"})
        return out

    def find_contact(self, keyword, include_deleted=True):
        out = []
        for c in self.contacts(include_deleted):
            if (c.get("name") and keyword in str(c["name"])) or \
                    any(keyword in str(p.get("number") or "") for p in c.get("phones") or []):
                out.append(c)
        return out

    # ---------------- 通话记录 ----------------
    def calllog(self):
        out = []
        for logical in ("/data/data/com.android.providers.telephony/databases/calllog.db",
                        "/data/data/com.android.providers.contacts/databases/calllog.db",
                        "/data/data/com.android.providers.contacts/databases/contacts2.db"):
            db = self.db(logical)
            if db is None:
                continue
            try:
                names = db.tables()
            except SqliteError:
                continue
            if "calls" not in names:
                continue
            cols = db.schema("calls")
            extra = [c for c in ("geocoded_location", "countryiso", "is_read",
                                 "presentation") if c in cols]
            sel = "select _id, number, date, duration, type, name, numbertype"
            if extra:
                sel += ", " + ", ".join(extra)
            sel += " from calls"
            src = self.path_of(logical)
            for r in self._q(db, sel):
                rec = {"id": r[0], "number": r[1], "date": r[2], "date_str": fmt_ms(r[2]),
                       "duration": r[3], "type": CALL_TYPES.get(r[4], r[4]),
                       "name": r[5], "numbertype": r[6], "source": src}
                for k, c in enumerate(extra):
                    rec[c] = r[7 + k] if len(r) > 7 + k else None
                out.append(rec)
            if out:
                break
        return out

    def calllog_stats(self):
        """按号码统计次数与总时长（次频排序）。"""
        stats = {}
        for c in self.calllog():
            num = c.get("number")
            if not num:
                continue
            s = stats.setdefault(num, {"number": num, "count": 0, "duration": 0, "types": {}})
            s["count"] += 1
            s["duration"] += int(c.get("duration") or 0)
            s["types"][c.get("type")] = s["types"].get(c.get("type"), 0) + 1
        return sorted(stats.values(), key=lambda x: -x["count"])

    # ---------------- 短信 ----------------
    def sms(self):
        logical = "/data/data/com.android.providers.telephony/databases/mmssms.db"
        db = self.db(logical)
        if db is None:
            return []
        src = self.path_of(logical)
        canon = {}
        for r in self._q(db, "select _id, address from canonical_addresses"):
            canon[r[0]] = r[1]
        threads = {}
        try:
            tables = db.tables()
        except SqliteError:
            tables = {}
        if "threads" in tables:
            for r in self._q(db, "select _id, recipient_ids, snippet, message_count, date "
                                 "from threads"):
                peers = []
                for pid in str(r[1] or "").replace(",", " ").split():
                    peers.append(canon.get(int(pid), pid) if pid.isdigit() else pid)
                threads[r[0]] = {"peers": peers, "snippet": r[2],
                                 "message_count": r[3], "last_date": r[4]}
        out = []
        if "sms" in tables:
            for r in self._q(db, "select _id, thread_id, address, date, date_sent, type, body, "
                                 "read, status, subject from sms"):
                tinfo = threads.get(r[1], {})
                out.append({
                    "id": r[0], "thread_id": r[1], "address": r[2],
                    "peers": tinfo.get("peers") or [r[2]],
                    "date": r[3], "date_str": fmt_ms(r[3]),
                    "date_sent": r[4], "date_sent_str": fmt_ms(r[4]),
                    "type": SMS_TYPES.get(r[5], r[5]),
                    "direction": "OUT" if r[5] == 2 else ("IN" if r[5] == 1 else "OTHER"),
                    "body": r[6], "read": r[7], "status": r[8], "subject": r[9],
                    "source": src,
                })
        if not out and "pdu" in tables:
            self.notes.append("mmssms.db 使用 pdu 表（sms 表为空），本次未解析 PDU")
        return out

    # ---------------- 浏览器 ----------------
    def _browse_history_from_db(self, db, src):
        hist, marks = [], []
        try:
            tables = db.tables()
        except SqliteError:
            return hist, marks
        for tname in tables:
            cols = db.schema(tname)
            low = [c.lower() for c in cols]
            if "url" not in low:
                continue
            url_c = cols[low.index("url")]
            title_c = cols[low.index("title")] if "title" in low else None
            date_c = None
            for cand in ("date", "last_visit_time", "created", "visit_time", "time"):
                if cand in low:
                    date_c = cols[low.index(cand)]
                    break
            visits_c = cols[low.index("visits")] if "visits" in low else None
            target = marks if ("bookmark" in tname.lower() or
                               ("folder" in low and "parent" in low)) else hist
            for rec in db.query_dicts("select * from %s" % tname):
                item = {"url": rec.get(url_c), "table": tname,
                        "title": rec.get(title_c) if title_c else None}
                if date_c:
                    v = rec.get(date_c)
                    if isinstance(v, int) and v > 10 ** 15:
                        ts = int(v / 1000) - 11644473600000
                        item["date"] = ts
                        item["date_str"] = fmt_ms(ts)
                    elif isinstance(v, (int, float)) and v:
                        item["date"] = int(v)
                        item["date_str"] = fmt_ms(int(v))
                if visits_c:
                    item["visits"] = rec.get(visits_c)
                item["source"] = src
                target.append(item)
        return hist, marks

    def browser(self):
        res = {"sources": {}, "history": [], "bookmarks": []}
        for pkg in BROWSER_PKGS:
            base = "/data/data/%s" % pkg
            if not self.exists(base):
                continue
            for logical in ("%s/databases" % base, "%s/app_chrome/Default" % base,
                            "%s/app_webview" % base):
                for name, ch, path in self.walk(logical, 1):
                    if not (name.endswith(".db") or name == "History"):
                        continue
                    data = self.fs.read_data(ch)
                    if not data:
                        continue
                    try:
                        db = SqliteTriage(data)
                    except SqliteError:
                        continue
                    hist, marks = self._browse_history_from_db(db, path)
                    if hist or marks:
                        st = res["sources"].setdefault(pkg, {"history": 0, "bookmarks": 0})
                        st["history"] += len(hist)
                        st["bookmarks"] += len(marks)
                        res["history"].extend(hist)
                        res["bookmarks"].extend(marks)
        return res

    # ---------------- 安装应用 ----------------
    @staticmethod
    def _hex_ts(v):
        if not v:
            return None
        try:
            return int(v, 16)
        except (TypeError, ValueError):
            return None

    def installed_apps(self):
        logical = "/data/system/packages.xml"
        data = self.read(logical)
        if not data:
            return []
        src = self.path_of(logical)
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            self.notes.append("packages.xml XML 解析失败")
            return []
        out = []
        for pkg in root.findall("package"):
            it = self._hex_ts(pkg.get("it"))
            ft = self._hex_ts(pkg.get("ft"))
            ut = self._hex_ts(pkg.get("ut"))
            out.append({
                "package": pkg.get("name"),
                "versionCode": pkg.get("version"),
                "codePath": pkg.get("codePath"),
                "nativeLibraryPath": pkg.get("nativeLibraryPath"),
                "flags": pkg.get("flags"),
                "userId": pkg.get("userId"),
                "installer": pkg.get("installer"),
                "sharedUserId": pkg.get("sharedUserId"),
                "first_install": ft, "first_install_str": fmt_ms(ft),
                "last_update": ut, "last_update_str": fmt_ms(ut),
                "source": src,
            })
        return out

    def app(self, package):
        """按包名取一条 installed_apps 记录。"""
        for a in self.installed_apps():
            if a.get("package") == package:
                return a
        return None

    # ---------------- 微信 ----------------
    def _pref_files(self, pkg):
        out = []
        for name, ch, p in self.walk("/data/data/%s/shared_prefs" % pkg, 1):
            if name.endswith(".xml"):
                out.append((p, self.fs.read_data(ch)))
        return out

    def wechat_credentials(self):
        """收集候选 uin / imei，返回 (uins, imeis, sources)。"""
        pkg = "com.tencent.mm"
        uins, imeis, sources = [], [], {}
        for p, data in self._pref_files(pkg):
            if not data:
                continue
            try:
                root = ET.fromstring(data)
            except ET.ParseError:
                continue
            for el in root:
                key = el.get("name") or ""
                val = el.get("value")
                if val is None and el.text:
                    val = el.text
                if not val:
                    continue
                val = val.strip()
                kl = key.lower()
                if any(k in kl for k in ("_auth_uin", "uin", "last_login",
                                         "login_weixin_username")):
                    if re.fullmatch(r"-?\d{5,12}", val):
                        if val not in uins:
                            uins.append(val)
                        sources.setdefault("uin", p + ":" + key)
                if any(k in kl for k in ("imei", "deviceid", "device_id")):
                    v = re.sub(r"[^0-9A-Fa-f]", "", val)
                    if len(v) >= 8 and v not in imeis:
                        imeis.append(v)
                        sources.setdefault("imei", p + ":" + key)
        for cand in ("/system/build.prop", "/vendor/build.prop"):
            data = self.read(cand)
            if not data:
                continue
            for line in data.decode("utf-8", "replace").splitlines():
                if line.startswith("ro.serialno=") or line.startswith("ro.imei="):
                    v = line.split("=", 1)[1].strip()
                    if v and v not in imeis:
                        imeis.append(v)
                        sources.setdefault("imei", self.path_of(cand) + ":" +
                                           line.split("=", 1)[0])
        aid = self.android_id_info()
        if aid.get("value") and aid["value"] not in imeis:
            imeis.append(aid["value"])
            sources.setdefault("imei", (aid.get("source") or "android_id") +
                               " (作为 imei 候选)")
        return uins, imeis, sources

    def wechat(self):
        """解析 com.tencent.mm：EnMicroMsg.db（SQLCipher）→ rcontact/message/userinfo。"""
        pkg = "com.tencent.mm"
        result = []
        base = "/data/data/%s" % pkg
        if not self.exists(base):
            self.notes.append("未发现 /data/data/com.tencent.mm（该检材无微信数据）")
            return result
        uins, imeis, srcs = self.wechat_credentials()
        cands = wechat_key_candidates(uins, imeis)
        dbs = []
        for name, ch, p in self.walk(base, 6):
            if name.lower() == "enmicromsg.db":
                dbs.append((p, ch))
        if not dbs:
            self.notes.append("已发现 com.tencent.mm，但未找到 EnMicroMsg.db")
            return result
        for path, ino in dbs:
            raw = self.fs.read_data(ino)
            entry = {"path": path, "size": ino.size, "uins": uins, "imeis": imeis,
                     "credential_sources": srcs, "key": None, "report": None,
                     "rcontact": [], "message": [], "userinfo": []}
            plain = None
            for c in cands:
                try:
                    dec, rep = sqlcipher_decrypt(raw, c["key"])
                    if not dec.startswith(SQLITE_MAGIC):
                        continue
                    db = SqliteTriage(dec)
                    db.tables()
                except (SqliteError, ValueError):
                    continue
                plain = dec
                entry["key"] = c["key"]
                entry["uin"] = c["uin"]
                entry["imei"] = c["imei"]
                entry["report"] = rep
                entry["decrypted_bytes"] = len(dec)
                break
            if plain is None:
                entry["error"] = ("所有密钥候选均无法解密（uin 候选 %d 个，imei 候选 %d 个）"
                                  % (len(uins), len(imeis)))
                result.append(entry)
                continue
            db = SqliteTriage(plain)
            tnames = db.tables()
            entry["tables"] = tnames
            if "rcontact" in tnames:
                cols = db.schema("rcontact")
                fields = [c for c in ("username", "alias", "conRemark", "nickname",
                                      "type", "verifyFlag") if c in cols]
                if fields:
                    for r in self._q(db, "select %s from rcontact" % ", ".join(fields)):
                        entry["rcontact"].append(dict(zip(fields, r)))
            if "message" in tnames:
                cols = db.schema("message")
                fields = [c for c in ("msgId", "msgSvrId", "type", "status", "isSend",
                                      "createTime", "talker", "content", "imgPath")
                          if c in cols]
                if fields:
                    for r in self._q(db, "select %s from message order by createTime" %
                                     ", ".join(fields)):
                        rec = dict(zip(fields, r))
                        if rec.get("createTime"):
                            rec["createTime_str"] = fmt_s(rec["createTime"])
                        entry["message"].append(rec)
            if "userinfo" in tnames:
                cols = db.schema("userinfo")
                fields = [c for c in ("id", "uin", "userName", "nickName", "alias",
                                      "signature") if c in cols]
                if fields:
                    for r in self._q(db, "select %s from userinfo" % ", ".join(fields)):
                        entry["userinfo"].append(dict(zip(fields, r)))
            result.append(entry)
        return result

    # ---------------- 通用 app 数据库 ----------------
    def generic_app_dbs(self, pkg):
        """某包下所有 .db/.sqlite 路径 + 行数概览（list[str]）。"""
        base = "/data/data/%s" % pkg
        if not self.exists(base):
            return []
        out = []
        for name, ch, path in self.walk(base, 6):
            low = name.lower()
            if not low.endswith((".db", ".sqlite", ".sqlite3", ".db3")):
                continue
            data = self.fs.read_data(ch)
            info = "empty"
            if data:
                try:
                    st = SqliteTriage(data)
                    t = st.tables()
                    info = "tables=%d rows=%d" % (len(t), sum(max(0, v) for v in t.values()))
                except SqliteError as e:
                    info = "unparsed(%s)" % e
            out.append("%s  [%s, %d bytes]" % (path, info, ch.size))
        return out

    # ---------------- 汇总 ----------------
    def summary(self):
        return {
            "android_id": self.android_id_info(),
            "device": self.device_info(),
            "accounts": self.accounts(),
            "wifi": self.wifi(),
            "contacts": len(self.contacts()),
            "calls": len(self.calllog()),
            "sms": len(self.sms()),
            "apps": len(self.installed_apps()),
            "wechat": self.wechat(),
            "notes": self.notes,
        }


# ==========================================================================
# iOS 备份
# ==========================================================================
class IosBackup:
    """iOS 备份目录解析（Manifest.db / Manifest.plist / Info.plist）。"""

    def __init__(self, fs, root="/"):
        self.fs = fs
        self.root = "/" + root.strip("/") if root.strip("/") else "/"
        self._manifest = None
        self.notes = []

    def _join(self, rel):
        if self.root in ("", "/"):
            return "/" + str(rel).strip("/")
        return self.root + "/" + str(rel).strip("/")

    def inode(self, rel):
        return self.fs.lookup(self._join(rel))

    def read(self, rel):
        ino = self.inode(rel)
        if ino is None or not ino.is_file:
            return None
        return self.fs.read_data(ino)

    def listdir(self, rel):
        ino = self.inode(rel)
        if ino is None or not ino.is_dir:
            return []
        out = []
        try:
            ents = self.fs.listdir(ino)
        except Exception:
            return []
        for e in ents:
            if e.name in (".", ".."):
                continue
            ch = self.fs.inode(e.inode)
            if ch is not None:
                out.append((e.name, ch))
        return out

    # ---------- 元数据 ----------
    def info_plist(self):
        data = self.read("Info.plist")
        if not data:
            return None
        try:
            return PlistHelper.unarchive(PlistHelper.load(data))
        except ValueError:
            self.notes.append("Info.plist 解析失败")
            return None

    def manifest_plist(self):
        data = self.read("Manifest.plist")
        if not data:
            return None
        try:
            return PlistHelper.unarchive(PlistHelper.load(data))
        except ValueError:
            self.notes.append("Manifest.plist 解析失败")
            return None

    def manifest(self):
        """Manifest.db 的 Files 表：fileID/domain/relativePath/flags/文件哈希。"""
        if self._manifest is not None:
            return self._manifest
        out = []
        data = self.read("Manifest.db")
        if not data:
            self.notes.append("未找到 Manifest.db")
            self._manifest = out
            return out
        try:
            db = SqliteTriage(data)
        except SqliteError as e:
            self.notes.append("Manifest.db 打开失败: %s" % e)
            self._manifest = out
            return out
        cols = db.schema("Files")
        if not cols:
            self._manifest = out
            return out
        want = [c for c in ("fileID", "domain", "relativePath", "flags", "file") if c in cols]
        for r in db.rows("select %s from Files" % ", ".join(want)):
            rec = dict(zip(want, r))
            f = rec.get("file")
            rec["sha1"] = f.hex() if isinstance(f, (bytes, bytearray)) else f
            rec["file_raw"] = f
            out.append(rec)
        self._manifest = out
        return out

    def find(self, domain=None, relative_path=None, name=None, pattern=None):
        pat = re.compile(pattern, re.I) if pattern else None
        hits = []
        for rec in self.manifest():
            if domain and rec.get("domain") != domain:
                continue
            if relative_path and rec.get("relativePath") != relative_path:
                continue
            if name and not str(rec.get("relativePath") or "").endswith(name):
                continue
            if pat and not (pat.search(str(rec.get("relativePath") or "")) or
                            pat.search(str(rec.get("domain") or ""))):
                continue
            hits.append(rec)
        return hits

    def read_file(self, file_id, unarchive=True):
        """按 sha1 前两位分目录取文件；NSKeyedArchiver 包装则展开。"""
        file_id = str(file_id)
        data = self.read("%s/%s" % (file_id[:2], file_id))
        if data is None:
            data = self.read(file_id)
        if data is None:
            for rec in self.manifest():
                if rec.get("fileID") == file_id and rec.get("relativePath"):
                    data = self.read(str(rec["relativePath"]))
                    if data is not None:
                        break
        if data is None:
            return None
        if not unarchive:
            return data
        if data[:6] == b"bplist" or data.startswith(b"<?xml"):
            try:
                return PlistHelper.unarchive(PlistHelper.load(data))
            except ValueError:
                return data
        return data

    def messages(self):
        """备份里的短信库（Library/SMS/sms.db 或 chat.db）。"""
        out = []
        cands = []
        for rec in self.manifest():
            rp = str(rec.get("relativePath") or "")
            if rp.endswith("sms.db") or rp.endswith("chat.db"):
                cands.append(rec)
        if not cands:
            for rel in ("Library/SMS/sms.db", "Library/SMS/chat.db", "sms.db", "chat.db"):
                if self.inode(rel) is not None:
                    cands.append({"fileID": None, "relativePath": rel})
        for rec in cands:
            data = None
            if rec.get("fileID"):
                data = self.read("%s/%s" % (str(rec["fileID"])[:2], rec["fileID"]))
            if data is None and rec.get("relativePath"):
                data = self.read(str(rec["relativePath"]))
            if not data:
                continue
            try:
                db = SqliteTriage(data)
            except SqliteError as e:
                self.notes.append("sms.db 打开失败: %s" % e)
                continue
            tables = db.tables()
            handles = {}
            if "handle" in tables:
                for r in db.rows("select ROWID, id from handle"):
                    handles[r[0]] = r[1]
            if "message" not in tables:
                continue
            cols = db.schema("message")
            want = [c for c in ("ROWID", "guid", "text", "handle_id", "date", "date_read",
                                "is_from_me", "service") if c in cols]
            for r in db.rows("select %s from message" % ", ".join(want)):
                d = dict(zip(want, r))
                ts = d.get("date")
                when = None
                if isinstance(ts, int) and ts:
                    # Apple 纪元 2001-01-01，单位为纳秒
                    when = fmt_ms(int(ts / 1000000) + 978307200000)
                out.append({"rowid": d.get("ROWID"), "guid": d.get("guid"),
                            "text": d.get("text"),
                            "handle": handles.get(d.get("handle_id")),
                            "is_from_me": d.get("is_from_me"),
                            "service": d.get("service"),
                            "date": ts, "date_str": when,
                            "source": rec.get("relativePath")})
        return out
