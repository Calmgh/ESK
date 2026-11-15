# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""自研邮件取证（纯标准库）：.eml / .mbox 解析、邮箱目录统计、
Android Gmail（mailstore.db，表结构自适应）与 iOS Mail（Envelope Index / .emlx）。

对外：
    Eml / Mbox / MailStore / scan_mail(fs, roots) / AndroidMail / IosMail
    parse_date(v) -> (datetime|None, 原始值)
    open_image_fs(image_path) -> (fs, sub)   直连 E01/DD 镜像

依赖 mkit.image / mkit.volume / mkit.ext4 / mkit.ntfs / mkit.regf / mkit.mobile。
"""
import datetime as _dt
import email
import email.policy
import email.utils
import hashlib
import html as _html
import os
import re
import zlib

from .ext4 import Ext4
from .image import Image, SubImage
from .mobile import PlistHelper, SqliteError, SqliteTriage, apple_ns_to_dt
from .ntfs import NTFS
from .regf import Hive
from . import volume

UTC = _dt.timezone.utc

MAIL_EXTS = (".eml", ".emlx", ".mbox", ".mbx")
STORE_EXTS = MAIL_EXTS + (".db", ".sqlite", ".xml")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
ADDR_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


# ---------------- 时间 ----------------
def parse_date(v):
    """任意时间字段 -> (datetime|None, 原始值)。

    兼容 epoch 秒/毫秒/微秒、Apple 纳秒（2001 起）、ISO8601、RFC2822、常见字符串。
    """
    if v is None or v == "":
        return None, v
    if isinstance(v, _dt.datetime):
        return (v if v.tzinfo else v.replace(tzinfo=UTC)), v
    if isinstance(v, bool):
        return None, v
    num = None
    if isinstance(v, (int, float)):
        num = float(v)
    elif isinstance(v, str) and re.fullmatch(r"-?\d+(\.\d+)?", v.strip() or "x"):
        num = float(v.strip())
    if num is not None:
        return _dt_from_number(num), v
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    s = str(v).strip()
    if not s:
        return None, v
    try:
        dt = email.utils.parsedate_to_datetime(s)
        if dt is not None:
            return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)), v
    except Exception:
        pass
    t = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = _dt.datetime.fromisoformat(t)
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)), v
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M",
                "%Y-%m-%d", "%d/%m/%Y %H:%M:%S"):
        try:
            return _dt.datetime.strptime(s, fmt).replace(tzinfo=UTC), v
        except Exception:
            continue
    return None, v


def _dt_from_number(f):
    if f <= 0:
        return None
    try:
        if f >= 1e17:                     # Apple 纳秒（2001-01-01 起）
            return apple_ns_to_dt(f)
        if f >= 1e15:                     # 微秒（1970 起）
            return _dt.datetime.fromtimestamp(f / 1e6, UTC)
        if f >= 1e11:                     # 毫秒
            return _dt.datetime.fromtimestamp(f / 1e3, UTC)
        return _dt.datetime.fromtimestamp(f, UTC)
    except Exception:
        return None


def _iso(dt):
    return dt.isoformat() if dt else None


def _apple_date(v):
    """CoreFoundation 绝对时间（2001-01-01 秒 / 纳秒）-> (datetime, 原始值)。

    Envelope Index 的 date_received、Info.plist 的日期都是这个纪元；
    值超出合理范围时退回通用 parse_date。
    """
    if v in (None, "", 0):
        return None, v
    num = None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        num = float(v)
    elif isinstance(v, str) and re.fullmatch(r"-?\d+(\.\d+)?", v.strip() or "x"):
        num = float(v.strip())
    if num is not None and 0 < num < 1.2e9:        # 2001 起秒数(2024≈7.5e8)，超过则按 epoch
        return apple_ns_to_dt(num), v
    return parse_date(v)


def _text(v):
    """任意值 -> 干净字符串（bytes 按 utf8，去 NUL）。"""
    if v is None:
        return ""
    if isinstance(v, bytes):
        b = v.replace(b"\x00", b"")
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.decode("latin1", "replace")
    if isinstance(v, (list, tuple)):
        return ", ".join(_text(x) for x in v if x is not None)
    return str(v)


def _unzlib(data):
    """zlib / raw deflate / gzip 解压，失败返回 None。"""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 16 + zlib.MAX_WBITS):
        try:
            return zlib.decompress(bytes(data), wbits)
        except Exception:
            continue
    return None


def _md5(data):
    return hashlib.md5(data).hexdigest()


def _open_db(data):
    """打开 SQLite（内存），失败返回 (None, 错误说明)。"""
    if not data:
        return None, "空文件"
    try:
        tri = SqliteTriage(data)
    except SqliteError as ex:
        return None, "非 SQLite / 已加密 (%s)" % ex
    except Exception as ex:
        return None, "打开失败 (%s)" % ex
    try:
        if not tri.tables():
            return None, "无用户表"
    except Exception as ex:
        return None, "读表失败 (%s)" % ex
    return tri, None


def _plist_obj(data):
    """bytes 或已展开的 plist 对象 -> 统一按 NSKeyedArchiver 展开后的对象返回。"""
    if data is None:
        return None
    if isinstance(data, (dict, list)):
        return PlistHelper.unarchive(data)
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            return PlistHelper.unarchive(PlistHelper.load(bytes(data)))
        except Exception:
            return None
    return None


def _is_email(s):
    return bool(s) and bool(EMAIL_RE.match(s.strip()))


def _addr_of(hdr):
    """'Clara <c@x.com>' -> 'c@x.com'"""
    if not hdr:
        return ""
    m = ADDR_RE.search(hdr)
    return m.group(0) if m else hdr.strip()


def _addr_list(hdr):
    if not hdr:
        return []
    out = []
    for part in re.split(r"[,;]", hdr):
        a = _addr_of(part.strip())
        if a:
            out.append(a)
    return out


def _guessed_name(ctype):
    return "unnamed" + {"application/pdf": ".pdf", "image/jpeg": ".jpg",
                        "image/png": ".png"}.get(ctype, ".bin")


# ---------------- 统一文件系统访问 ----------------
class _FSWalker:
    """把 Ext4 / NTFS / DirFS / 本地目录 归一成 path 级接口。

    posix 分支（Ext4、测试用 DirFS）：lookup / listdir / inode / read_data
    ntfs  分支：lookup / ls_entry / read_file
    local 分支：os.*（roots 直接指向导出的邮箱目录）
    """

    def __init__(self, fs=None):
        self.fs = fs
        self.kind = "local"
        if fs is not None and not isinstance(fs, (str, bytes, os.PathLike)):
            if callable(getattr(fs, "ls_entry", None)) and callable(getattr(fs, "read_file", None)):
                self.kind = "ntfs"
            elif callable(getattr(fs, "listdir", None)) and callable(getattr(fs, "lookup", None)):
                self.kind = "posix"
            else:
                self.kind = "unknown"

    def _ino(self, path):
        try:
            return self.fs.lookup(path)
        except Exception:
            return None

    def exists(self, path):
        if self.kind == "local":
            return os.path.exists(path)
        return self._ino(path) is not None

    def is_dir(self, path):
        if self.kind == "local":
            return os.path.isdir(path)
        ino = self._ino(path)
        return bool(ino is not None and getattr(ino, "is_dir", False))

    def size(self, path):
        if self.kind == "local":
            try:
                return os.path.getsize(path)
            except OSError:
                return 0
        ino = self._ino(path)
        return int(getattr(ino, "size", 0) or 0)

    def read(self, path):
        try:
            if self.kind == "local":
                with open(path, "rb") as fh:
                    return fh.read()
            if self.kind == "ntfs":
                return self.fs.read_file(path)
            ino = self._ino(path)
            if ino is None or getattr(ino, "is_dir", False):
                return None
            return self.fs.read_data(ino)
        except Exception:
            return None

    def listdir(self, path):
        out = []
        if self.kind == "local":
            try:
                names = os.listdir(path)
            except OSError:
                return out
            for n in names:
                p = os.path.join(path, n)
                try:
                    st = os.stat(p)
                    out.append((n, os.path.isdir(p), st.st_size))
                except OSError:
                    out.append((n, False, 0))
            return out
        if self.kind == "ntfs":
            try:
                ents = self.fs.ls(path, include_deleted=False)
            except Exception:
                return out
            for e in ents:
                out.append((_text(getattr(e, "name", "")), bool(getattr(e, "is_dir", False)),
                            int(getattr(e, "size", 0) or 0)))
            return out
        ino = self._ino(path)
        if ino is None or not getattr(ino, "is_dir", False):
            return out
        try:
            ents = self.fs.listdir(ino)
        except Exception:
            return out
        base = path.rstrip("/")
        for e in ents:
            name = getattr(e, "name", None)
            if not name or name in (".", ".."):
                continue
            child = None
            num = getattr(e, "inode", None)
            if num is not None and callable(getattr(self.fs, "inode", None)):
                try:
                    child = self.fs.inode(num)
                except Exception:
                    child = None
            if child is None:
                child = self._ino(base + "/" + _text(name))
            is_dir = bool(getattr(e, "is_dir", False) or
                          (child is not None and getattr(child, "is_dir", False)))
            size = int(getattr(child, "size", 0) or 0) if child is not None else 0
            out.append((_text(name), is_dir, size))
        return out

    def walk(self, root="/", max_depth=12, max_files=100000):
        """yield (path, name, size, is_dir)，先序，带深度与文件数上限。"""
        if not self.exists(root):
            return
        if not self.is_dir(root):
            name = root.rstrip("/").rsplit("/", 1)[-1] or root
            yield root, name, self.size(root), False
            return
        stack = [(root, 0)]
        seen = set()
        n = 0
        while stack:
            d, depth = stack.pop()
            if d in seen:
                continue
            seen.add(d)
            for name, is_dir, size in self.listdir(d):
                p = (d.rstrip("/") or "") + "/" + name
                if is_dir:
                    if depth < max_depth:
                        stack.append((p, depth + 1))
                    yield p, name, 0, True
                else:
                    n += 1
                    if n > max_files:
                        return
                    yield p, name, size, False

    def find(self, root, patterns, max_depth=12, max_files=100000):
        """路径正则过滤遍历，yield (path, name, size)。"""
        pats = [re.compile(p, re.I) for p in
                ([patterns] if isinstance(patterns, (str, re.Pattern)) else patterns)]
        for path, name, size, is_dir in self.walk(root, max_depth, max_files):
            if is_dir:
                continue
            for p in pats:
                if p.search(path):
                    yield path, name, size
                    break


# ---------------- .eml ----------------
def _part_text(part):
    try:
        txt = part.get_content()
        if isinstance(txt, str):
            return txt
    except Exception:
        pass
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, "replace")
    except Exception:
        return payload.decode("utf-8", "replace")


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_NL_RE = re.compile(r"\n{3,}")


def _html_to_text(s):
    s = re.sub(r"(?is)<(script|style).*?</\1>", " ", s)
    s = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>", "\n", s)
    s = _TAG_RE.sub(" ", s)
    s = _html.unescape(s)
    s = _WS_RE.sub(" ", s)
    return _NL_RE.sub("\n\n", s).strip()


class Eml:
    """单封 .eml（.emlx 由 parse_emlx 去壳后同样喂进来）。"""

    def __init__(self, data, path=None):
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        self.data = bytes(data or b"")
        self.path = path
        self.msg = email.message_from_bytes(self.data, policy=email.policy.default)
        self.from_ = ""
        self.to = ""
        self.cc = ""
        self.subject = ""
        self.message_id = ""
        self.date = None
        self.date_raw = None
        self.body = ""
        self.body_html = ""
        self.attachments = []
        self._parse()

    def _parse(self):
        msg = self.msg
        self.from_ = _text(msg.get("From")).strip()
        self.to = _text(msg.get("To")).strip()
        self.cc = _text(msg.get("Cc")).strip()
        self.subject = _text(msg.get("Subject")).replace("\n", " ").strip()
        self.message_id = _text(msg.get("Message-ID")).strip()
        self.date, self.date_raw = parse_date(msg.get("Date"))
        if self.date is None:
            self.date, self.date_raw = parse_date(msg.get("Received"))
        plain = []
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            disp = (part.get_content_disposition() or "").lower()
            fname = part.get_filename()
            if disp == "attachment" or fname or (not ctype.startswith("text/") and
                                                 ctype not in ("multipart/related",
                                                               "message/rfc822")):
                payload = part.get_payload(decode=True) or b""
                self.attachments.append(dict(
                    filename=_text(fname) or _guessed_name(ctype),
                    size=len(payload),
                    md5=_md5(payload),
                    content_type=ctype,
                    disposition=disp or ("attachment" if fname else "inline"),
                ))
            elif ctype == "text/plain":
                plain.append(_part_text(part))
            elif ctype == "text/html":
                self.body_html += _part_text(part)
        self.body = "\n".join(plain).strip()
        if not self.body and self.body_html:
            self.body = _html_to_text(self.body_html)

    @property
    def from_address(self):
        return _addr_of(self.from_)

    @property
    def to_addresses(self):
        return _addr_list(self.to)

    @property
    def cc_addresses(self):
        return _addr_list(self.cc)

    @property
    def has_attach(self):
        return bool(self.attachments)

    def to_dict(self, body_limit=4000):
        return dict(
            path=self.path, kind="eml",
            from_=self.from_, from_address=self.from_address,
            to=self.to, to_addresses=self.to_addresses,
            cc=self.cc,
            subject=self.subject,
            date=_iso(self.date), date_raw=self.date_raw,
            message_id=self.message_id,
            body=self.body[:body_limit], body_len=len(self.body),
            has_attach=self.has_attach,
            attachments=list(self.attachments),
        )

    def __repr__(self):
        return "<Eml %r from=%r at=%r>" % (self.subject[:40], self.from_address,
                                           _iso(self.date))


# ---------------- mbox ----------------
def split_mbox(data):
    """按行首 'From ' 分封；'From:' 头行不误判，'>From ' 反转义。"""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    chunks, cur = [], None
    for raw in data.split(b"\n"):
        line = raw[:-1] if raw.endswith(b"\r") else raw
        if line.startswith(b"From ") and not line.startswith(b"From:"):
            if cur:
                chunks.append(b"\n".join(cur))
            cur = []
            continue
        if cur is None:
            cur = []
        cur.append(line)
    if cur:
        chunks.append(b"\n".join(cur))
    out = []
    for c in chunks:
        c = re.sub(rb"(?m)^>From ", b"From ", c)
        if c.strip():
            out.append(c)
    return out


def parse_emlx(data):
    """.emlx = 十进制长度行 + plist 元数据 + 原始 RFC822 报文。"""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    i = data.find(b"\n")
    if i <= 0:
        return data
    try:
        n = int(data[:i].strip())
    except Exception:
        return data
    start = i + 1 + n
    if start >= len(data):
        return data[i + 1:]
    return data[start:].lstrip(b"\r\n")


class Mbox:
    """mbox/mbx：分封后交给 Eml 解析。"""

    def __init__(self, data, path=None):
        self.data = data
        self.path = path
        self._msgs = None

    def messages(self):
        if self._msgs is None:
            self._msgs = []
            for i, chunk in enumerate(split_mbox(self.data)):
                try:
                    e = Eml(chunk, self.path)
                except Exception:
                    continue
                e.index = i
                self._msgs.append(e)
        return self._msgs

    def __len__(self):
        return len(self.messages())

    def to_dict(self, body_limit=4000):
        return dict(path=self.path, kind="mbox", count=len(self.messages()),
                    messages=[m.to_dict(body_limit) for m in self.messages()])


# ---------------- 通用邮箱目录 ----------------
class MailStore:
    """任意目录（本地目录树或镜像文件系统）里的邮箱文件统计与解析。"""

    EXTS = STORE_EXTS

    def __init__(self, root="/", fs=None, walker=None, max_depth=12, max_files=100000):
        self.root = root
        self.w = walker or _FSWalker(fs)
        self.max_depth = max_depth
        self.max_files = max_files
        self.errors = []
        self._files = None

    def files(self):
        if self._files is not None:
            return self._files
        out = []
        for path, name, size, is_dir in self.w.walk(self.root, self.max_depth, self.max_files):
            if is_dir:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in self.EXTS:
                out.append(dict(path=path, name=name, ext=ext, size=size or 0))
        self._files = out
        return out

    def stats(self):
        files = self.files()
        by_ext, total = {}, 0
        for f in files:
            by_ext[f["ext"]] = by_ext.get(f["ext"], 0) + 1
            total += f["size"]
        return dict(root=self.root, files=len(files), by_ext=by_ext, total_size=total,
                    eml=by_ext.get(".eml", 0) + by_ext.get(".emlx", 0),
                    mbox=by_ext.get(".mbox", 0) + by_ext.get(".mbx", 0),
                    db=by_ext.get(".db", 0) + by_ext.get(".sqlite", 0),
                    xml=by_ext.get(".xml", 0))

    def messages(self, limit=1000, emlx_limit=200):
        out = []
        emlx_seen = 0
        for f in self.files():
            if len(out) >= limit:
                break
            ext = f["ext"]
            if ext not in (".eml", ".emlx", ".mbox", ".mbx"):
                continue
            if ext == ".emlx":
                emlx_seen += 1
                if emlx_seen > emlx_limit:
                    continue
            data = self.w.read(f["path"])
            if not data:
                continue
            try:
                if ext in (".mbox", ".mbx"):
                    for msg in Mbox(data, f["path"]).messages():
                        d = msg.to_dict()
                        d["kind"] = "mbox"
                        d["index"] = getattr(msg, "index", 0)
                        out.append(d)
                else:
                    if ext == ".emlx":
                        data = parse_emlx(data)
                    out.append(Eml(data, f["path"]).to_dict())
            except Exception as ex:
                self.errors.append("%s: %s" % (f["path"], ex))
            if len(out) >= limit:
                break
        return out[:limit]

    def attachments(self, limit=1000):
        out = []
        for m in self.messages(limit=limit):
            for a in m.get("attachments") or []:
                rec = dict(a)
                rec["message_path"] = m.get("path")
                rec["message_subject"] = m.get("subject")
                rec["message_date"] = m.get("date")
                out.append(rec)
        return out

    def accounts(self, limit=1000):
        seen, out = set(), []
        for m in self.messages(limit=limit):
            for key in ("from_address", "to_addresses", "cc_addresses"):
                vals = m.get(key)
                if isinstance(vals, str):
                    vals = [vals]
                for a in vals or []:
                    a = _addr_of(a)
                    if _is_email(a) and a.lower() not in seen:
                        seen.add(a.lower())
                        out.append(dict(address=a, source=m.get("path"), kind="header"))
        return out


# ---------------- Gmail / Android mailstore.db ----------------
_DATE_COLS = ("datereceivedms", "datereceived", "datesentms", "datesent",
              "receiveddate", "internaldate", "timestamp", "date", "time")
_FROM_COLS = ("fromaddress", "from_address", "senderaddress", "sender", "fromemail", "from")
_TO_COLS = ("toaddresses", "to_addresses", "toaddress", "recipients", "to")
_SUBJECT_COLS = ("subject", "subjectheader", "title")
_BODY_COLS = ("body", "bodycompressed", "htmlbody", "bodytext", "text", "snippet")
_ACCT_COLS = ("address", "email", "emailaddress", "accountname", "username", "login")


def _lower_map(cols):
    return {str(c).lower(): c for c in cols}


def _first_col(lmap, cands, skip=()):
    for c in cands:
        if c in lmap and c not in skip:
            return lmap[c]
    return None


def _pick_message_table(tri, prefer=("message", "messages", "mail", "mails")):
    best, best_score = None, 0
    for t in tri.tables():
        cols = tri.schema(t)
        if not cols:
            continue
        lm = _lower_map(cols)
        score = 0
        if _first_col(lm, _DATE_COLS):
            score += 3
        if _first_col(lm, _SUBJECT_COLS):
            score += 2
        if _first_col(lm, _FROM_COLS):
            score += 2
        if _first_col(lm, _BODY_COLS):
            score += 1
        if t.lower() in prefer:
            score += 3
        if score > best_score:
            best, best_score = t, score
    return best if best_score >= 4 else None


def _body_text(value, colname=""):
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        low = (colname or "").lower()
        if "compress" in low or raw[:1] == b"\x78" or raw[:2] == b"\x1f\x8b":
            dec = _unzlib(raw)
            if dec is not None:
                raw = dec
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("utf-8", "replace")
    return str(value)


def _attachment_counts(tri):
    """{messageKey: 附件数}，无附件表返回 {}。"""
    tname = None
    for t in tri.tables():
        if t.lower() in ("attachment", "attachments"):
            tname = t
            break
    if not tname:
        return {}
    lm = _lower_map(tri.schema(tname))
    kcol = _first_col(lm, ("messagekey", "message_key", "messageid", "message_id", "msgid"))
    if not kcol:
        return {}
    out = {}
    for r in tri.rows('select "%s", count(*) from "%s" group by "%s"' % (kcol, tname, kcol)):
        try:
            out[str(r[0])] = int(r[1])
        except Exception:
            continue
    return out


def gmail_accounts(tri):
    """从 mailstore.db 的 account 表取账号；无 account 表则退化为 fromAddress。"""
    out = []
    for t in tri.tables():
        if t.lower() not in ("account", "accounts", "accountinfo", "user", "useraccount"):
            continue
        lm = _lower_map(tri.schema(t))
        c_addr = _first_col(lm, _ACCT_COLS)
        if not c_addr:
            continue
        c_name = _first_col(lm, ("displayname", "name", "accountname", "fullname"), skip=(c_addr.lower(),))
        c_proto = _first_col(lm, ("protocol", "type", "accounttype", "servicetype"))
        c_id = _first_col(lm, ("_id", "id", "accountid"))
        for r in tri.dicts('select * from "%s" limit 50' % t, limit=50):
            addr = _text(r.get(c_addr)).strip()
            if not _is_email(addr):
                continue
            out.append(dict(address=addr,
                            name=_text(r.get(c_name)) if c_name else None,
                            protocol=_text(r.get(c_proto)) if c_proto else None,
                            id=r.get(c_id) if c_id else None,
                            source="mailstore.db:%s" % t))
    if not out:
        tname = _pick_message_table(tri)
        if tname:
            lm = _lower_map(tri.schema(tname))
            c_from = _first_col(lm, _FROM_COLS)
            if c_from:
                seen = set()
                for r in tri.rows('select distinct "%s" from "%s" limit 50' % (c_from, tname)):
                    addr = _text(r[0]).strip()
                    if _is_email(addr) and addr.lower() not in seen:
                        seen.add(addr.lower())
                        out.append(dict(address=addr, name=None, protocol=None, id=None,
                                        source="mailstore.db:%s.%s" % (tname, c_from)))
    return out


def gmail_messages(tri, limit=500, table=None):
    """自适应列名取 message 表：主题/发件人/收件人/日期/正文（自动解压）。"""
    t = table or _pick_message_table(tri)
    if not t:
        return []
    cols = tri.schema(t)
    lm = _lower_map(cols)
    c_date = _first_col(lm, _DATE_COLS)
    c_sub = _first_col(lm, _SUBJECT_COLS)
    c_from = _first_col(lm, _FROM_COLS)
    c_to = _first_col(lm, _TO_COLS)
    c_body = _first_col(lm, ("body", "bodytext", "htmlbody", "text"))
    c_bodyz = _first_col(lm, ("bodycompressed",))
    c_snip = _first_col(lm, ("snippet",))
    c_id = _first_col(lm, ("messageid", "message_id", "msgid", "_id", "id"))
    if not c_body:
        c_body = _first_col(lm, _BODY_COLS)
    sel = [c for c in (c_date, c_sub, c_from, c_to, c_body, c_bodyz, c_snip, c_id) if c]
    if not sel:
        return []
    sql = 'select %s from "%s"' % (", ".join('"%s"' % c for c in sel), t)
    if c_date:
        sql += ' order by "%s" desc' % c_date
    sql += " limit %d" % int(limit)
    rows = tri.dicts(sql, limit=limit)
    att = _attachment_counts(tri) if c_id else {}
    out = []
    for r in rows:
        dt, raw = parse_date(r.get(c_date)) if c_date else (None, None)
        body = _body_text(r.get(c_body), c_body) if c_body else ""
        if not body and c_bodyz and c_bodyz != c_body:
            body = _body_text(r.get(c_bodyz), c_bodyz)
        msg_id = _text(r.get(c_id)) if c_id else ""
        snip = _text(r.get(c_snip)) if c_snip else ""
        out.append(dict(
            db=None, table=t,
            subject=_text(r.get(c_sub)) if c_sub else "",
            from_=_text(r.get(c_from)) if c_from else "",
            to=_text(r.get(c_to)) if c_to else "",
            message_id=msg_id,
            date=_iso(dt), date_raw=raw, time=dt,
            body=body, body_len=len(body),
            snippet=snip or body[:120],
            has_attach=bool(att.get(msg_id)) if (att and msg_id) else None,
            attachment_count=att.get(msg_id, 0) if (att and msg_id) else 0,
        ))
    return out


def gmail_folders(tri):
    """label/folder 表 -> {名称: 邮件数}。"""
    out = {}
    lname = None
    for t in tri.tables():
        if t.lower() in ("label", "labels", "folder", "folders"):
            lname = t
            break
    if not lname:
        return out
    lm = _lower_map(tri.schema(lname))
    c_nm = _first_col(lm, ("name", "labelname", "displayname", "title"))
    c_id = _first_col(lm, ("_id", "id", "labelid", "folderid"))
    if not c_nm:
        return out
    counts = {}
    for t in tri.tables():
        if t.lower() in ("message_label", "message_labels", "messagelabel", "label_message"):
            mlm = _lower_map(tri.schema(t))
            k = _first_col(mlm, ("labelid", "label_id", "folderid", "folder_id"))
            if not k:
                continue
            for r in tri.rows('select "%s", count(*) from "%s" group by "%s"' % (k, t, k)):
                counts[str(r[0])] = int(r[1])
            break
    for r in tri.rows('select "%s", "%s" from "%s" limit 500'
                      % (c_id, c_nm, lname)) if c_id else []:
        out[_text(r[1])] = counts.get(str(r[0]), 0)
    if not out:
        for r in tri.rows('select "%s" from "%s" limit 500' % (c_nm, lname)):
            out[_text(r[0])] = 0
    return out


# ---------------- Android 邮件 App ----------------
class AndroidMail:
    """Gmail / 网易 / QQ / Outlook 等 App 数据。

    Gmail 库表结构随版本变化：先 enumerate tables，再按候选列名自适应取列；
    bodyCompressed 为 zlib 压缩时自动解压；日期兼容毫秒/秒/字符串。
    """

    PKGS = {
        "gmail": "com.google.android.gm",
        "netease": "com.netease.mail",
        "qqmail": "com.tencent.androidqqmail",
        "outlook": "com.microsoft.office.outlook",
        "samsung": "com.samsung.android.email.provider",
        "aosp": "com.android.email",
        "yahoo": "com.yahoo.mobile.client.android.mail",
    }
    ROOTS = ("/data/data", "/data/user/0", "/data/user_de/0")
    DB_RE = r"mailstore.*\.db$"

    def __init__(self, fs):
        self.fs = fs
        self.w = _FSWalker(fs)
        self.searched = []
        self.notes = []
        self._dbs = None

    # ---- 定位数据库 ----
    def pkg_dir(self, pkg):
        for base in self.ROOTS:
            p = base + "/" + pkg
            if self.w.exists(p):
                return p
        return None

    def databases(self):
        if self._dbs is not None:
            return self._dbs
        self._dbs = []
        seen = set()

        def add(path):
            if path in seen:
                return
            seen.add(path)
            data = self.w.read(path)
            if not data:
                return
            tri, err = _open_db(data)
            if tri is not None:
                self._dbs.append((path, tri))
            else:
                self.notes.append("%s: %s" % (path, err))

        for pkg in self.PKGS.values():
            base = self.pkg_dir(pkg)
            if not base:
                continue
            for path, name, _ in self.w.find(base, self.DB_RE, max_depth=4):
                add(path)
            gdb = base + "/databases/mailstore.db"
            if self.w.exists(gdb):
                add(gdb)
        if not self._dbs:
            for root in self.ROOTS:
                for path, name, _ in self.w.find(root, self.DB_RE, max_depth=6, max_files=50000):
                    if "gm" in path.lower() or "mail" in path.lower():
                        add(path)
        self.searched = [p for p, _ in self._dbs]
        return self._dbs

    # ---- 账号 ----
    def accounts(self):
        out, seen = [], set()
        for path, tri in self.databases():
            for a in gmail_accounts(tri):
                key = a["address"].lower()
                if key in seen:
                    continue
                seen.add(key)
                rec = dict(a)
                rec["db"] = path
                out.append(rec)
        for a in self.shared_prefs_accounts():
            if a["address"].lower() in seen:
                continue
            seen.add(a["address"].lower())
            out.append(a)
        if not out:
            self.notes.append("未找到账号；已搜索: %s" %
                              (", ".join(self.searched) or "无 mailstore.db"))
        return out

    def shared_prefs_accounts(self):
        out = []
        prefs = (("gmail", "com.google.android.gm"), ("netease", "com.netease.mail"),
                 ("qqmail", "com.tencent.androidqqmail"),
                 ("outlook", "com.microsoft.office.outlook"),
                 ("samsung", "com.samsung.android.email.provider"),
                 ("aosp", "com.android.email"))
        for label, pkg in prefs:
            base = self.pkg_dir(pkg)
            if not base:
                continue
            d = base + "/shared_prefs"
            for name, is_dir, _ in self.w.listdir(d):
                if is_dir or not name.lower().endswith(".xml"):
                    continue
                data = self.w.read(d + "/" + name)
                if not data:
                    continue
                txt = data.decode("utf-8", "replace")
                for m in ADDR_RE.finditer(txt):
                    addr = m.group(0)
                    if not _is_email(addr) or addr.lower().endswith("@android.com"):
                        continue
                    out.append(dict(address=addr, name=None, protocol=None, id=None,
                                    source="%s/shared_prefs/%s" % (pkg, name), app=label))
        return out

    # ---- 邮件 ----
    def messages(self, limit=500):
        out = []
        for path, tri in self.databases():
            for m in gmail_messages(tri, limit=limit):
                m["db"] = path
                out.append(m)
            if len(out) >= limit:
                break
        if not out:
            self.notes.append("未解析到邮件；已搜索: %s" %
                              (", ".join(self.searched) or "无 mailstore.db"))
        out.sort(key=lambda x: (x.get("time") is None, x.get("time") or 0), reverse=False)
        return out[:limit]

    def folders(self):
        out = {}
        for path, tri in self.databases():
            for k, v in gmail_folders(tri).items():
                out[k] = out.get(k, 0) + v
        if not out:
            self.notes.append("未找到 label/folder 表")
        return out

    def report(self, limit=500):
        return dict(accounts=self.accounts(), messages=self.messages(limit=limit),
                    folders=self.folders(), searched=self.searched, notes=self.notes)


# ---------------- iOS Mail ----------------
class IosMail:
    """iOS 备份内 Mail：Accounts3.sqlite 账号 + Envelope Index / .emlx 收件箱。"""

    def __init__(self, backup):
        self.bk = backup
        self.searched = []
        self.notes = []

    def _read(self, rec):
        try:
            return self.bk.read_file(rec.get("fileID") or rec.get("relativePath"))
        except Exception:
            return None

    def _sqls(self, patterns, domain=None, limit=8):
        out = []
        seen = set()
        for pat in patterns:
            for rec in self.bk.find(domain=domain, pattern=pat):
                key = rec.get("fileID") or rec.get("relativePath")
                if key in seen:
                    continue
                seen.add(key)
                self.searched.append(str(rec.get("relativePath")))
                data = self._read(rec)
                if not data:
                    continue
                tri, err = _open_db(data)
                if tri is not None:
                    out.append((rec, tri))
                else:
                    self.notes.append("%s: %s" % (rec.get("relativePath"), err))
                if len(out) >= limit:
                    return out
        return out

    def _plists(self, patterns, limit=200):
        out = []
        seen = set()
        for pat in patterns:
            for rec in self.bk.find(pattern=pat):
                key = rec.get("fileID") or rec.get("relativePath")
                if key in seen:
                    continue
                seen.add(key)
                obj = _plist_obj(self._read(rec))
                if obj is None:
                    continue
                out.append((str(rec.get("relativePath")), str(rec.get("domain") or ""), obj))
                if len(out) >= limit:
                    return out
        return out

    # ---- 账号 ----
    def accounts(self):
        out, seen = [], set()
        for rec, tri in self._sqls([r"Accounts3\.sqlite$", r"Accounts\.sqlite$"]):
            tables = tri.tables()
            tname = None
            for t in ("ZACCOUNT", "account", "Z_ACCOUNT", "accounts"):
                if t in tables:
                    tname = t
                    break
            if not tname:
                self.notes.append("%s 无 ZACCOUNT 表，现表: %s"
                                  % (rec.get("relativePath"), ", ".join(sorted(tables)) or "无"))
                continue
            lm = _lower_map(tri.schema(tname))
            c_user = _first_col(lm, ("zusername", "username", "zaccountname", "accountname"))
            c_desc = _first_col(lm, ("zaccountdescription", "zdescription", "description",
                                     "zaccounttype", "ztypename"))
            c_bundle = _first_col(lm, ("zowningbundleid", "zbundleid", "zparentaccount"))
            for r in tri.dicts('select * from "%s" limit 200' % tname, limit=200):
                user = _text(r.get(c_user)) if c_user else ""
                desc = _text(r.get(c_desc)) if c_desc else ""
                if not user and not desc:
                    continue
                key = (user or desc).lower()
                if key in seen:
                    continue
                seen.add(key)
                out.append(dict(username=user, description=desc,
                                bundle=_text(r.get(c_bundle)) if c_bundle else None,
                                source="%s:%s" % (rec.get("relativePath"), tname),
                                kind="sqlite"))
        for rel, dom, obj in self._plists([r"(?i)com\.apple\.account.*\.plist$",
                                           r"(?i)mobilemail.*\.plist$"], limit=60):
            for key, val in _deep_items(obj):
                if not isinstance(val, str):
                    continue
                lk = key.lower()
                if lk in ("accountname", "username", "appleid", "accountusername",
                          "emailaddress", "primaryemail") and _is_email(val):
                    if val.lower() in seen:
                        continue
                    seen.add(val.lower())
                    out.append(dict(username=val, description=key, bundle=None,
                                    source="%s:%s" % (rel, key), kind="plist"))
        if not out:
            self.notes.append("未找到 Mail 账号；已搜索: %s"
                              % (", ".join(sorted(set(self.searched))) or "Manifest 无匹配文件"))
        return out

    # ---- 收件箱 ----
    def inbox(self, limit=500):
        out = []
        for rec, tri in self._sqls([r"Envelope Index$", r"Envelope Index\.sqlite$"]):
            out += self._envelope(rec, tri, limit)
            if len(out) >= limit:
                break
        if not out:
            out += self._emlx(limit)
        if not out:
            self.notes.append("未找到 Envelope Index / .emlx；已搜索: %s"
                              % (", ".join(sorted(set(self.searched))) or "无"))
        return out[:limit]

    def _lookup_map(self, tri, table, keycol=None, valcol=("subject", "address", "comment")):
        if table not in tri.tables():
            return {}
        lm = _lower_map(tri.schema(table))
        vc = _first_col(lm, valcol)
        if not vc:
            return {}
        return {int(r[0]): _text(r[1]) for r in
                tri.rows('select ROWID, "%s" from "%s"' % (vc, table))}

    def _envelope(self, rec, tri, limit):
        tname = None
        for t in ("messages", "message", "ZMAILMESSAGE"):
            if t in tri.tables():
                tname = t
                break
        if not tname:
            self.notes.append("%s 无 messages 表，现表: %s"
                              % (rec.get("relativePath"), ", ".join(sorted(tri.tables()))))
            return []
        lm = _lower_map(tri.schema(tname))
        c_date = _first_col(lm, ("date_received", "date_sent", "date", "zdate"))
        c_subj = _first_col(lm, ("subject", "zsubject"))
        c_send = _first_col(lm, ("sender", "sender_address", "address", "zsender"))
        c_mbox = _first_col(lm, ("mailbox", "mailbox_id"))
        c_read = _first_col(lm, ("read", "flags"))
        subj_map = self._lookup_map(tri, "subjects", valcol=("subject",))
        addr_map = self._lookup_map(tri, "addresses", valcol=("address", "comment"))
        if not addr_map:
            addr_map = self._lookup_map(tri, "sender_addresses", valcol=("address", "comment"))
        box_map = self._lookup_map(tri, "mailboxes", valcol=("url", "path"))
        sel = [c for c in (c_date, c_subj, c_send, c_mbox, c_read) if c]
        sql = 'select ROWID, %s from "%s"' % (", ".join('"%s"' % c for c in sel), tname)
        if c_date:
            sql += ' order by "%s" desc' % c_date
        sql += " limit %d" % int(limit)
        out = []
        for r in tri.dicts(sql, limit=limit):
            subj = r.get(c_subj) if c_subj else None
            sender = r.get(c_send) if c_send else None
            box = r.get(c_mbox) if c_mbox else None
            if isinstance(subj, int) and subj in subj_map:
                subj = subj_map[subj]
            if isinstance(sender, int) and sender in addr_map:
                sender = addr_map[sender]
            if isinstance(box, int) and box in box_map:
                box = box_map[box]
            dt, raw = _apple_date(r.get(c_date)) if c_date else (None, None)
            out.append(dict(source="%s:%s" % (rec.get("relativePath"), tname),
                            rowid=r.get("ROWID"), mailbox=_text(box), subject=_text(subj),
                            sender=_text(sender), date=_iso(dt), date_raw=raw,
                            read=r.get(c_read) if c_read else None, body=None))
        return out

    def _emlx(self, limit):
        out = []
        for rec in self.bk.find(r"\.emlx$")[:limit]:
            data = self._read(rec)
            if not data:
                continue
            try:
                e = Eml(parse_emlx(data), str(rec.get("relativePath")))
            except Exception:
                continue
            d = e.to_dict(2000)
            d["source"] = str(rec.get("relativePath"))
            out.append(d)
        return out

    def report(self, limit=500):
        return dict(accounts=self.accounts(), inbox=self.inbox(limit=limit),
                    searched=sorted(set(self.searched)), notes=self.notes)


# ---------------- plist 深度遍历 ----------------
def _deep_items(obj, depth=0):
    """yield (键名, 值)：递归展开 dict/list，用于跨 iOS 版本找同义键。"""
    if depth > 12:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k), v
            yield from _deep_items(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _deep_items(v, depth + 1)


# ---------------- 一揽子扫描 ----------------
def scan_mail(fs=None, roots=("/",), limit=1000, max_files=100000, max_depth=12):
    """在给定文件系统/目录的多条根路径下找邮箱，返回统计与解析结果。

    fs: Ext4 / NTFS / DirFS 实例；传 None 或路径字符串则按本地目录读。
    roots: 待搜路径列表（如 ("/data/data", "/sdcard") 或本地目录）。
    返回 {roots, searched, missing, accounts, messages, attachments, stores,
          counts, errors, notes}
    """
    w = _FSWalker(fs)
    res = dict(roots=list(roots), searched=[], missing=[], accounts=[], messages=[],
               attachments=[], stores=[], counts=dict(files=0, eml=0, mbox=0, db=0,
                                                      xml=0, messages=0),
               errors=[], notes=[])
    seen_acct = {}

    def add_acct(rec):
        addr = _addr_of(rec.get("address") or "")
        if not _is_email(addr):
            return
        key = addr.lower()
        if key in seen_acct:
            return
        seen_acct[key] = True
        rec = dict(rec)
        rec["address"] = addr
        res["accounts"].append(rec)

    for root in roots:
        if not w.exists(root):
            res["missing"].append(root)
            continue
        store = MailStore(root, walker=w, max_depth=max_depth, max_files=max_files)
        try:
            st = store.stats()
        except Exception as ex:
            res["errors"].append("%s: %s" % (root, ex))
            continue
        res["searched"].append(root)
        res["stores"].append(st)
        for k in ("files", "eml", "mbox", "db", "xml"):
            res["counts"][k] += st.get(k, 0)
        remaining = max(0, limit - len(res["messages"]))
        if remaining:
            try:
                msgs = store.messages(limit=remaining)
            except Exception as ex:
                res["errors"].append("%s: %s" % (root, ex))
                msgs = []
            for m in msgs:
                m["store"] = root
            res["messages"] += msgs
            for m in msgs:
                for a in m.get("attachments") or []:
                    rec = dict(a)
                    rec["message_path"] = m.get("path")
                    rec["message_subject"] = m.get("subject")
                    res["attachments"].append(rec)
                for key in ("from_address",):
                    add_acct(dict(address=m.get(key), source=m.get("path"), kind="header"))
                for a in m.get("to_addresses") or []:
                    add_acct(dict(address=a, source=m.get("path"), kind="header"))
        res["errors"] += store.errors
        for f in store.files():
            low = f["name"].lower()
            if f["ext"] in (".db", ".sqlite") and "mailstore" in low:
                data = w.read(f["path"])
                if not data:
                    continue
                tri, err = _open_db(data)
                if tri is None:
                    res["errors"].append("%s: %s" % (f["path"], err))
                    continue
                for a in gmail_accounts(tri):
                    rec = dict(a)
                    rec["db"] = f["path"]
                    add_acct(rec)
                if remaining:
                    for m in gmail_messages(tri, limit=remaining):
                        m["db"] = f["path"]
                        m["store"] = root
                        res["messages"].append(m)
                tri.close()
            elif f["ext"] == ".xml" and "shared_prefs" in f["path"].lower():
                data = w.read(f["path"])
                if not data:
                    continue
                for m in ADDR_RE.finditer(data.decode("utf-8", "replace")):
                    add_acct(dict(address=m.group(0), source=f["path"], kind="shared_prefs"))
    res["counts"]["messages"] = len(res["messages"])
    if not res["messages"]:
        res["notes"].append("未解析到任何邮件；已搜索 %s" % (", ".join(res["searched"]) or "无"))
    return res


def open_image_fs(image_path, offset=None, length=None):
    """打开 E01/DD 镜像并按签名返回 (文件系统, 子视图)。

    未指定 offset 时依次尝试分区表里的各分区与整盘偏移 0。
    """
    img = Image(image_path)
    cands = []
    if offset is not None:
        cands.append((offset, length if length is not None else img.size - offset))
    else:
        try:
            for p in volume.parse(img):
                if str(p.get("type_name", "")).startswith("Extended"):
                    continue
                cands.append((p["start"], p["size"]))
        except Exception:
            pass
        cands.append((0, img.size))
    for off, size in cands:
        try:
            kind = volume.guess_filesystem(img, off, size)
        except Exception:
            kind = "unknown"
        sub = SubImage(img, off, size)
        try:
            if kind.startswith("ext"):
                return Ext4(sub), sub
            if kind == "ntfs":
                return NTFS(sub), sub
        except Exception:
            continue
    try:
        img.close()
    except Exception:
        pass
    return None, None


def windows_store_roots(hive):
    """从 SOFTWARE hive 取 Windows Live Mail / Mail 存储根目录。

    hive: mkit.regf.Hive 实例，或 hive 文件路径 / 原始字节（内部自建 Hive）。
    返回 [{hive, value, path}]
    """
    own = None
    if isinstance(hive, (bytes, bytearray, memoryview)):
        hive = own = Hive(bytes(hive), name="<bytes>")
    elif isinstance(hive, (str, os.PathLike)):
        with open(hive, "rb") as fh:
            hive = own = Hive(fh.read(), name=os.path.basename(str(hive)))
    out = []
    try:
        for path in ("Microsoft\\Windows Live Mail",
                     "Microsoft\\Windows Mail",
                     "Microsoft\\Office\\16.0\\Outlook\\Profiles",
                     "Microsoft\\Office\\15.0\\Outlook\\Profiles"):
            try:
                key = hive.open("SOFTWARE\\" + path)
            except Exception:
                key = None
            if key is None:
                continue
            for name in ("Store Root", "StoreRoot", "Path", "Root"):
                try:
                    v = key.value(name)
                except Exception:
                    v = None
                if v and isinstance(v[1], str) and v[1].strip():
                    out.append(dict(hive=path, value=name, path=v[1].strip()))
    finally:
        if own is not None:
            try:
                own.close()
            except Exception:
                pass
    return out


__all__ = ["Eml", "Mbox", "MailStore", "scan_mail", "AndroidMail", "IosMail",
           "parse_date", "parse_emlx", "split_mbox", "open_image_fs",
           "windows_store_roots", "gmail_accounts", "gmail_messages", "gmail_folders"]

