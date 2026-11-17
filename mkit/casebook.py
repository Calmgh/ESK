# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""取证案件管理 + 哈希链审计 + 文件索引落盘 —— 纯 stdlib 实现

能力范围
    * Case        案件目录：case.json（UTF-8 无 BOM）+ index.sqlite + audit.jsonl
    * AuditLog    哈希链审计日志（逐条 sha256 链接，可定位断链位置）
    * ingest_tree 把文件系统对象（walk/read_file/info）的目录树灌进索引
    * export_csv / export_json  索引导出（CSV 带 BOM，Excel 直接双击可用）
    * manifest / verify_evidence  证据封存清单与哈希复核

依赖
    mkit.hashcalc.file_hash / bytes_hash —— 文件与内存哈希（sha256/md5/…）
    mkit.chain.keccak256_hex             —— 清单封存戳（与链上口径一致）
    除此之外只用 json / hashlib / sqlite3 / os / csv / tempfile / datetime。

注意
    * 只做逻辑层，不解析任何磁盘格式；镜像解析交给 ntfs/ext4/… 等模块，
      它们的 walk() 结果直接喂给 ingest_tree()。
    * 大文件哈希用 hash_limit 截断，截断会在 meta 里标 hash_partial=True，
      不冒充整文件哈希。
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime

try:                                     # 包内导入
    from .hashcalc import file_hash, bytes_hash
    from .chain import keccak256_hex
except ImportError:                      # 直接运行本文件（python mkit/casebook.py）
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from mkit.hashcalc import file_hash, bytes_hash
    from mkit.chain import keccak256_hex

__all__ = ["Case", "AuditLog", "CaseError", "ingest_tree",
           "export_csv", "export_json", "manifest", "verify_evidence"]

CASE_FORMAT = "ESK-CASE"
CASE_VERSION = 1
SCHEMA_VERSION = 1
MANIFEST_FORMAT = "ESK-MANIFEST"

# 默认整文件哈希算法（证据封存口径）
EVIDENCE_ALGOS = ("sha256", "md5")
# ingest_tree 默认只算前 4 MiB
DEFAULT_HASH_LIMIT = 4 << 20

_ARTIFACT_COLUMNS = ("id", "evidence_id", "path", "inode", "size",
                     "mtime", "kind", "sha256", "md5", "meta_json")


class CaseError(Exception):
    """案件操作错误（路径不存在、只读写入、证据缺失等）"""


# ============================================================
# 小工具
# ============================================================
def _now_iso():
    """本地时区 ISO 8601，带偏移（审计用）"""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _iso(ts):
    """把 epoch 秒 / 字符串统一成可读时间"""
    if ts is None or ts == "":
        return ""
    if isinstance(ts, str):
        return ts
    try:
        v = float(ts)
    except (TypeError, ValueError):
        return str(ts)
    try:
        return datetime.fromtimestamp(v).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return str(ts)


def _jsonable(obj):
    """递归转成 json 可序列化结构（bytes → hex，其它 → str）"""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _canonical(obj):
    """规范化 JSON：键排序、紧凑分隔符、保留非 ASCII（中文不转义）"""
    return json.dumps(_jsonable(obj), ensure_ascii=False,
                      sort_keys=True, separators=(",", ":"))


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _atomic_write_text(path, text):
    """原子写 UTF-8 无 BOM 文本（同目录临时文件 + os.replace）"""
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, ".%s.tmp%d" % (os.path.basename(path), os.getpid()))
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


_EXT_KIND = {
    ".txt": "text", ".log": "text", ".csv": "text", ".json": "json",
    ".xml": "xml", ".html": "html", ".htm": "html",
    ".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image",
    ".bmp": "image", ".heic": "image", ".webp": "image", ".tif": "image",
    ".mp4": "video", ".mov": "video", ".avi": "video", ".mkv": "video",
    ".mp3": "audio", ".wav": "audio", ".flac": "audio", ".amr": "audio",
    ".pdf": "pdf", ".doc": "doc", ".docx": "doc", ".xls": "sheet",
    ".xlsx": "sheet", ".ppt": "slide", ".pptx": "slide",
    ".db": "database", ".sqlite": "database", ".sqlite3": "database",
    ".exe": "executable", ".dll": "executable", ".so": "executable",
    ".zip": "archive", ".rar": "archive", ".7z": "archive",
    ".gz": "archive", ".tar": "archive", ".apk": "archive",
    ".evtx": "eventlog", ".pf": "prefetch", ".lnk": "lnk",
}


def _kind_by_ext(path):
    ext = os.path.splitext(path or "")[1].lower()
    return _EXT_KIND.get(ext, "other")


def _first_attr(obj, names, default=None):
    """按候选名依次取属性（兼容不同文件系统模块的字段命名）"""
    for n in names:
        try:
            if hasattr(obj, n):
                v = getattr(obj, n)
                return v() if callable(v) and not isinstance(v, type) else v
        except Exception:
            continue
    return default


# ============================================================
# B. 哈希链审计
# ============================================================
_AUDIT_FIELDS = ("seq", "ts", "action", "target", "operator", "detail")


class AuditLog:
    """逐条链接的审计日志（JSONL），任一条被改动都能定位到位置

    行结构：seq / ts / action / target / operator / detail / prev / hash
    hash = sha256(canonical(本条内容，不含 hash) + prev.encode())，hex
    首条 prev = "0" * 64
    """

    ZERO = "0" * 64

    def __init__(self, path, operator="", readonly=False, fsync=True):
        self.path = os.path.abspath(path)
        self.default_operator = operator
        self.readonly = bool(readonly)
        self.fsync = bool(fsync)
        self._tail_cache = None      # (size, mtime, seq, hash)
        if not self.readonly:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            if not os.path.exists(self.path):
                with open(self.path, "a", encoding="utf-8", newline="\n"):
                    pass
        self.name = os.path.basename(self.path)

    # ---------------- 哈希口径 ----------------
    @staticmethod
    def record_hash(rec, prev):
        """本条记录的哈希：规范化内容（不含 hash）+ prev"""
        body = {k: rec.get(k) for k in _AUDIT_FIELDS}
        return _sha256_text(_canonical(body) + str(prev))

    # ---------------- 读 ----------------
    def _lines(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8", errors="replace",
                  newline="") as f:
            return f.read().splitlines()

    def entries(self):
        """返回全部记录（按写入顺序）；坏行以 _bad 标记原样保留"""
        out = []
        for lineno, raw in enumerate(self._lines(), 1):
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except Exception as e:
                out.append({"_bad": True, "_line": lineno,
                            "_raw": raw, "_error": str(e)})
                continue
            if not isinstance(rec, dict):
                out.append({"_bad": True, "_line": lineno,
                            "_raw": raw, "_error": "不是 JSON 对象"})
                continue
            out.append(rec)
        return out

    def __len__(self):
        return len([e for e in self.entries() if not e.get("_bad")])

    def tail(self):
        """当前链尾 (seq, hash)"""
        st = self._tail_state()
        return st[0], st[1]

    def _tail_state(self):
        try:
            st = os.stat(self.path)
            key = (st.st_size, st.st_mtime_ns)
        except OSError:
            return (0, self.ZERO)
        if self._tail_cache and self._tail_cache[0] == key:
            return self._tail_cache[1], self._tail_cache[2]
        seq, h = self._scan_tail()
        self._tail_cache = (key, seq, h)
        return seq, h

    def _scan_tail(self, window=8192):
        """只读文件尾 8 KiB 取最后一条记录（追加是 O(1)，不重解析整份日志）"""
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                back = min(size, window)
                f.seek(size - back)
                blob = f.read()
        except OSError:
            return 0, self.ZERO
        for raw in reversed(blob.splitlines()):
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                continue
            if not isinstance(rec, dict):
                continue
            try:
                s = int(rec.get("seq") or 0)
            except (TypeError, ValueError):
                s = 0
            return s, (rec.get("hash") or self.ZERO)
        if size > back:                      # 窗口里没有整行（单行超长）→ 退回全量
            recs = [e for e in self.entries() if not e.get("_bad")]
            if recs:
                last = recs[-1]
                try:
                    s = int(last.get("seq") or 0)
                except (TypeError, ValueError):
                    s = len(recs)
                return s, (last.get("hash") or self.ZERO)
        return 0, self.ZERO

    # ---------------- 写 ----------------
    def append(self, action, target="", detail=None, operator=""):
        """追加一条审计记录，返回写入的记录（含 hash）"""
        if self.readonly:
            raise CaseError("审计日志以只读方式打开：%s" % self.path)
        seq, last = self._tail_state()
        rec = {
            "seq": seq + 1,
            "ts": _now_iso(),
            "action": str(action),
            "target": str(target or ""),
            "operator": str(operator or self.default_operator or ""),
            "detail": _jsonable(detail) if detail is not None else None,
            "prev": last,
        }
        rec["hash"] = self.record_hash(rec, last)
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
            f.flush()
            if self.fsync:
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
        try:
            st = os.stat(self.path)
            self._tail_cache = ((st.st_size, st.st_mtime_ns), rec["seq"], rec["hash"])
        except OSError:
            self._tail_cache = None
        return rec

    # ---------------- 校验 ----------------
    def verify(self):
        """逐条重算：seq 连续 + prev 链接 + 自身 hash

        返回 {"ok": bool, "count": n, "broken_at": idx|None, "reason": str,
              "checked": n, "tail": hex}
        broken_at 从 1 开始计数（第几条记录，空行不计）。
        """
        lines = [(i, raw) for i, raw in enumerate(self._lines(), 1) if raw.strip()]
        prev = self.ZERO
        prev_seq = 0
        checked = 0
        for n, (lineno, raw) in enumerate(lines, 1):
            try:
                rec = json.loads(raw)
            except Exception as e:
                return self._broken(n, n - 1, prev,
                                    "第 %d 条（文件第 %d 行）不是合法 JSON：%s"
                                    % (n, lineno, e))
            if not isinstance(rec, dict):
                return self._broken(n, n - 1, prev,
                                    "第 %d 条（文件第 %d 行）不是 JSON 对象"
                                    % (n, lineno))
            seq = rec.get("seq")
            if seq != prev_seq + 1:
                return self._broken(n, n - 1, prev,
                                    "第 %d 条序号断链：期望 %d，实际 %r"
                                    "（可能有记录被删除或插入）"
                                    % (n, prev_seq + 1, seq))
            if rec.get("prev") != prev:
                return self._broken(n, n - 1, prev,
                                    "第 %d 条 prev 与上一条 hash 不符"
                                    "（上一条被改动，或本条 prev 被改）" % n)
            want = self.record_hash(rec, prev)
            if (rec.get("hash") or "") != want:
                return self._broken(n, n - 1, prev,
                                    "第 %d 条自身 hash 不匹配（该条内容被改动）" % n)
            prev = rec["hash"]
            prev_seq = seq
            checked = n
        return {"ok": True, "count": len(lines), "broken_at": None,
                "reason": "", "checked": checked, "tail": prev}

    @staticmethod
    def _broken(idx, checked, tail, reason):
        return {"ok": False, "count": idx, "broken_at": idx,
                "reason": reason, "checked": checked, "tail": tail}

    def close(self):
        self._tail_cache = None

    def __repr__(self):
        return "<AuditLog %s%s>" % (self.path, " [ro]" if self.readonly else "")


# ============================================================
# A. 案件
# ============================================================
_SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT,
    path        TEXT NOT NULL,
    inode       INTEGER,
    size        INTEGER,
    mtime       REAL,
    kind        TEXT,
    sha256      TEXT,
    md5         TEXT,
    meta_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_path   ON artifacts(path);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
CREATE INDEX IF NOT EXISTS idx_artifacts_ev     ON artifacts(evidence_id);
"""


def _glob_to_like(pattern):
    """glob → SQL LIKE 片段（* → %，? → _，字面 % _ 转义）"""
    out = []
    for ch in pattern:
        if ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        elif ch in ("%", "_"):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


class Case:
    """一个取证案件目录

    path/
        case.json     案件元信息（UTF-8 无 BOM）
        index.sqlite  artifact 索引
        audit.jsonl   哈希链审计
    """

    def __init__(self, path, name, examiner="", notes="", **meta):
        self.path = os.path.abspath(os.fspath(path))
        os.makedirs(self.path, exist_ok=True)
        self.case_json = os.path.join(self.path, "case.json")
        self.db_path = os.path.join(self.path, "index.sqlite")
        self.audit_path = os.path.join(self.path, "audit.jsonl")
        self.readonly = False
        self._db = None
        self._audit = None

        exists = os.path.exists(self.case_json)
        if exists:
            data = self._load_json()
            old = data.get("name") or ""
            if name and old and name != old:
                raise CaseError(
                    "案件已存在且名称不同（现有 %r，传入 %r）；"
                    "读取请用 Case.open(path)" % (old, name))
            touched = False
            if examiner and data.get("examiner") != examiner:
                data["examiner"] = examiner
                touched = True
            if notes and data.get("notes") != notes:
                data["notes"] = notes
                touched = True
            if meta:
                data.setdefault("meta", {}).update(_jsonable(meta))
                touched = True
            self._data = data
            if touched:
                _atomic_write_text(
                    self.case_json,
                    json.dumps(self._data, ensure_ascii=False, indent=2) + "\n")
        else:
            created = _now_iso()
            self._data = {
                "format": CASE_FORMAT,
                "version": CASE_VERSION,
                "case_id": self._make_case_id(name, created),
                "name": name,
                "examiner": examiner,
                "notes": notes,
                "created": created,
                "updated": created,
                "meta": _jsonable(meta),
                "evidences": [],
            }
            self._save()

        self._db = self._open_db(readonly=False)
        self._audit = AuditLog(self.audit_path, operator=examiner)
        if not exists:
            self._audit.append("case.create", target=self.path,
                               detail={"name": name, "case_id": self._data["case_id"]},
                               operator=examiner)

    # ---------------- 内部 ----------------
    @staticmethod
    def _make_case_id(name, created):
        return "CASE-" + _sha256_text("%s|%s" % (name, created))[:16].upper()

    def _load_json(self):
        try:
            with open(self.case_json, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception as e:
            raise CaseError("case.json 读取失败：%s" % e)
        if not isinstance(data, dict):
            raise CaseError("case.json 结构异常（不是对象）")
        data.setdefault("format", CASE_FORMAT)
        data.setdefault("version", CASE_VERSION)
        data.setdefault("evidences", [])
        return data

    def _save(self):
        if getattr(self, "readonly", False):
            raise CaseError("案件以只读方式打开，不能写入：%s" % self.path)
        self._data["updated"] = _now_iso()
        _atomic_write_text(self.case_json,
                           json.dumps(self._data, ensure_ascii=False, indent=2) + "\n")

    def _open_db(self, readonly):
        if readonly:
            if not os.path.exists(self.db_path):
                raise CaseError("index.sqlite 不存在：%s" % self.db_path)
            uri = "file:%s?mode=ro" % self.db_path.replace("\\", "/").replace("?", "%3f").replace("#", "%23")
            conn = sqlite3.connect(uri, uri=True)
        else:
            conn = sqlite3.connect(self.db_path)
            conn.executescript(_SCHEMA)
            conn.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)
            conn.commit()
        conn.row_factory = sqlite3.Row
        return conn

    def _writable(self):
        if self.readonly:
            raise CaseError("案件以只读方式打开，拒绝写入：%s" % self.path)

    def _find_evidence(self, evidence_id):
        for ev in self._data.get("evidences", []):
            if ev.get("evidence_id") == evidence_id:
                return ev
        return None

    # ---------------- 打开 ----------------
    @classmethod
    def open(cls, path, readonly=True):
        """打开已有案件；readonly=True 时 sqlite 以 mode=ro 打开"""
        obj = cls.__new__(cls)
        obj.path = os.path.abspath(os.fspath(path))
        obj.case_json = os.path.join(obj.path, "case.json")
        obj.db_path = os.path.join(obj.path, "index.sqlite")
        obj.audit_path = os.path.join(obj.path, "audit.jsonl")
        obj.readonly = bool(readonly)
        if not os.path.exists(obj.case_json):
            raise CaseError("不是案件目录（缺少 case.json）：%s" % obj.path)
        obj._data = obj._load_json()
        obj._db = obj._open_db(readonly=obj.readonly)
        obj._audit = AuditLog(obj.audit_path, readonly=obj.readonly,
                              operator=obj._data.get("examiner", ""))
        return obj

    # ---------------- 元信息 ----------------
    @property
    def name(self):
        return self._data.get("name", "")

    @property
    def examiner(self):
        return self._data.get("examiner", "")

    @property
    def case_id(self):
        return self._data.get("case_id", "")

    @property
    def audit(self):
        return self._audit

    def info(self):
        """案件概况（含索引计数）"""
        n_art = self._db.execute("SELECT COUNT(*) AS c FROM artifacts").fetchone()["c"]
        db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        return {
            "format": self._data.get("format", CASE_FORMAT),
            "version": self._data.get("version", CASE_VERSION),
            "case_id": self.case_id,
            "name": self.name,
            "examiner": self.examiner,
            "notes": self._data.get("notes", ""),
            "created": self._data.get("created", ""),
            "updated": self._data.get("updated", ""),
            "path": self.path,
            "readonly": self.readonly,
            "evidence_count": len(self._data.get("evidences", [])),
            "artifact_count": n_art,
            "db_size": db_size,
            "files": {"case": self.case_json, "index": self.db_path,
                      "audit": self.audit_path},
        }

    # ---------------- 证据 ----------------
    def _resolve_evidence_path(self, path_or_sub, must_exist=True):
        p = os.fspath(path_or_sub)
        if not os.path.isabs(p):
            p = os.path.join(self.path, p)
        p = os.path.abspath(p)
        if must_exist and not os.path.exists(p):
            raise CaseError("证据路径不存在：%s" % p)
        return p

    def _portable(self, abspath):
        """案件目录内的证据存相对路径（可整体搬迁），否则存绝对路径"""
        try:
            rel = os.path.relpath(abspath, self.path)
        except ValueError:                  # 不同盘符
            return abspath
        if rel.startswith(".."):
            return abspath
        return rel.replace("\\", "/")

    def add_evidence(self, path_or_sub, label, kind="image", **meta):
        """登记一份证据（整文件 sha256 + md5），返回 evidence_id（EV-0001）"""
        self._writable()
        absp = self._resolve_evidence_path(path_or_sub)
        if os.path.isdir(absp):
            raise CaseError("证据必须是文件，不是目录：%s（目录内容请用 add_artifact）" % absp)
        size = os.path.getsize(absp)
        h = file_hash(absp, EVIDENCE_ALGOS)
        evs = self._data.setdefault("evidences", [])
        seq = len(evs) + 1
        existing = set(e.get("evidence_id") for e in evs)
        while ("EV-%04d" % seq) in existing:
            seq += 1
        ev_id = "EV-%04d" % seq
        ev = {
            "evidence_id": ev_id,
            "label": str(label),
            "kind": str(kind),
            "path": self._portable(absp),
            "abs_path": absp,
            "size": size,
            "sha256": h.get("sha256", ""),
            "md5": h.get("md5", ""),
            "added": _now_iso(),
            "meta": _jsonable(meta),
        }
        evs.append(ev)
        self._save()
        self._audit.append("evidence.add", target=ev_id,
                           detail={"label": ev["label"], "path": ev["path"],
                                   "size": size, "sha256": ev["sha256"],
                                   "md5": ev["md5"], "kind": ev["kind"]})
        return ev_id

    def evidences(self):
        """返回证据列表（副本）"""
        return [dict(e) for e in self._data.get("evidences", [])]

    def evidence(self, evidence_id):
        ev = self._find_evidence(evidence_id)
        return dict(ev) if ev else None

    def evidence_path(self, evidence_id, root=None):
        """把证据记录还原成可访问路径（root 用于换挂载点复核）"""
        ev = self._find_evidence(evidence_id)
        if not ev:
            raise CaseError("证据不存在：%s" % evidence_id)
        p = ev.get("path") or ""
        if os.path.isabs(p):
            return p
        base = os.path.abspath(os.fspath(root)) if root else self.path
        return os.path.abspath(os.path.join(base, p))

    # ---------------- artifact 索引 ----------------
    def add_artifact(self, evidence_id, path, inode=None, size=None,
                     mtime=None, kind=None, hashes=None, **meta):
        """登记从镜像解析出的一个条目，返回 artifact id"""
        self._writable()
        if evidence_id and not self._find_evidence(evidence_id):
            raise CaseError("证据不存在，不能挂索引：%s" % evidence_id)
        write_audit = bool(meta.pop("_audit", True))
        sha = md5 = None
        if isinstance(hashes, str):
            sha = hashes.strip().lower()
        elif isinstance(hashes, dict):
            for k, v in hashes.items():
                if v is None:
                    continue
                k = str(k).lower().replace("-", "")
                if k == "sha256":
                    sha = str(v).lower()
                elif k == "md5":
                    md5 = str(v).lower()
                else:
                    meta.setdefault("other_hashes", {})[k] = str(v)
        elif hashes:
            raise CaseError("hashes 需为 dict 或 sha256 字符串")

        meta_json = json.dumps(_jsonable(meta), ensure_ascii=False) if meta else ""
        cur = self._db.execute(
            "INSERT INTO artifacts (evidence_id, path, inode, size, mtime,"
            " kind, sha256, md5, meta_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (evidence_id or "", str(path), _int_or_none(inode),
             _int_or_none(size), _float_or_none(mtime),
             kind or _kind_by_ext(path), sha, md5, meta_json))
        self._db.commit()
        aid = int(cur.lastrowid)
        if write_audit:
            self._audit.append("artifact.add", target="%s:%s" % (evidence_id or "-", path),
                               detail={"id": aid, "size": size, "sha256": sha,
                                       "kind": kind or _kind_by_ext(path)})
        return aid

    def find_artifacts(self, pattern="*", evidence_id=None, limit=None):
        """按路径 glob 查询（* ? 通配；无通配符按子串）；支持 re: 前缀正则"""
        sql = "SELECT * FROM artifacts WHERE 1=1"
        args = []
        if evidence_id:
            sql += " AND evidence_id = ?"
            args.append(evidence_id)
        regex = None
        if isinstance(pattern, str) and pattern.startswith("re:"):
            regex = re.compile(pattern[3:])
        elif pattern and pattern != "*":
            pat = pattern if ("*" in pattern or "?" in pattern) else "*" + pattern + "*"
            sql += " AND path LIKE ? ESCAPE '\\'"
            args.append(_glob_to_like(pat))
        sql += " ORDER BY path, id"
        rows = [self._artifact_row(r) for r in self._db.execute(sql, args)]
        if regex is not None:
            rows = [r for r in rows
                    if regex.search(r.get("path") or "") or
                    regex.search(os.path.basename(r.get("path") or ""))]
        if limit:
            rows = rows[:int(limit)]
        return rows

    def by_hash(self, h):
        """按 sha256（64 hex）或 md5（32 hex）反查条目"""
        if not h:
            raise CaseError("哈希不能为空")
        v = str(h).strip().lower()
        if v.startswith("0x"):
            v = v[2:]
        if len(v) == 64:
            rows = self._db.execute(
                "SELECT * FROM artifacts WHERE sha256 = ? ORDER BY path", (v,))
        elif len(v) == 32:
            rows = self._db.execute(
                "SELECT * FROM artifacts WHERE md5 = ? ORDER BY path", (v,))
        else:
            raise CaseError("哈希长度异常（需 sha256 64 位或 md5 32 位）：%r" % h)
        return [self._artifact_row(r) for r in rows]

    # ---------------- 卷快照 ----------------
    # 快照把「当前分析状态」冻结成一份可复核的副本：
    #   snapshots/SNAP-0001/meta.json      计数、时间、审计锚点、内容 sha256
    #   snapshots/SNAP-0001/artifacts.jsonl artifacts 全量（按 key 排序，逐行 JSON）
    # 快照本身也进审计链，且 meta 里记 artifacts.jsonl 的 sha256，
    # 所以事后改快照文件能被 verify_snapshot 抓出来。

    def _snapshot_root(self):
        return os.path.join(self.path, "snapshots")

    def _snapshot_dir(self, snap_id):
        return os.path.join(self._snapshot_root(), snap_id)

    def _snapshot_metas(self):
        if not isinstance(self._data.get("snapshots"), list):
            self._data["snapshots"] = []
        return self._data["snapshots"]

    @staticmethod
    def _art_key(r):
        return (r.get("evidence_id") or "", r.get("path") or "")

    def _all_artifact_keys(self):
        return set(self._art_key(self._artifact_row(r))
                   for r in self._db.execute("SELECT * FROM artifacts"))

    def snapshot(self, label="", note=""):
        """对当前分析状态做一次快照，返回该快照的 meta"""
        self._writable()
        metas = self._snapshot_metas()
        n = len(metas) + 1
        snap_id = "SNAP-%04d" % n
        while os.path.exists(self._snapshot_dir(snap_id)):
            n += 1
            snap_id = "SNAP-%04d" % n
        rows = self.find_artifacts("*")
        rows.sort(key=self._art_key)
        d = self._snapshot_dir(snap_id)
        os.makedirs(d, exist_ok=True)
        body = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                       for r in rows)
        _atomic_write_text(os.path.join(d, "artifacts.jsonl"), body)
        t = self._audit.tail()
        if isinstance(t, dict):
            tail_hash = t.get("hash") or t.get("record_hash") or ""
        elif isinstance(t, str):
            tail_hash = t
        else:
            tail_hash = ""
        meta = {
            "snapshot_id": snap_id,
            "label": label or "",
            "note": note or "",
            "created": _now_iso(),
            "artifact_count": len(rows),
            "evidence_count": len(self._data.get("evidences", [])),
            "audit_count": len(self._audit),
            "audit_tail": tail_hash,
            "artifacts_sha256": _sha256_text(body),
        }
        _atomic_write_text(
            os.path.join(d, "meta.json"),
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
        metas.append(meta)
        self._save()
        self._audit.append(
            "snapshot.create", target=snap_id,
            detail={"label": meta["label"],
                    "artifact_count": meta["artifact_count"]})
        return dict(meta)

    def snapshots(self):
        """列出全部快照摘要（以磁盘上的 meta.json 为准）"""
        out = []
        for m in self._snapshot_metas():
            sid = m.get("snapshot_id")
            if not sid:
                continue
            p = os.path.join(self._snapshot_dir(sid), "meta.json")
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8-sig") as f:
                        out.append(json.load(f))
                    continue
                except Exception:
                    pass
            out.append(dict(m))
        return out

    def _load_snapshot_rows(self, snap_id):
        p = os.path.join(self._snapshot_dir(snap_id), "artifacts.jsonl")
        if not os.path.exists(p):
            raise CaseError("快照不存在或缺少 artifacts.jsonl：%s" % snap_id)
        rows = []
        with open(p, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception as e:
                    raise CaseError("快照 %s 的 artifacts.jsonl 有坏行：%s"
                                    % (snap_id, e))
        return rows

    def diff_snapshots(self, a, b):
        """比对两个快照的 artifacts（按 evidence_id+path 判等）"""
        ra = dict((self._art_key(r), r) for r in self._load_snapshot_rows(a))
        rb = dict((self._art_key(r), r) for r in self._load_snapshot_rows(b))
        added = sorted((rb[k].get("path") or "") for k in rb if k not in ra)
        removed = sorted((ra[k].get("path") or "") for k in ra if k not in rb)
        changed = []
        same = 0
        for k in ra:
            if k not in rb:
                continue
            x, y = ra[k], rb[k]
            if (x.get("sha256") != y.get("sha256")
                    or x.get("md5") != y.get("md5")
                    or x.get("size") != y.get("size")):
                changed.append(y.get("path") or "")
            else:
                same += 1
        return {"a": a, "b": b, "added": added, "removed": removed,
                "changed": sorted(changed), "same_count": same}

    def restore_snapshot(self, snap_id, replace=False):
        """把 artifacts 表恢复成快照状态

        replace=True  先清空再按快照重建
        replace=False 只补快照里有、现在缺的条目，不删任何现有条目
        """
        self._writable()
        rows = self._load_snapshot_rows(snap_id)
        inserted = 0
        deleted = 0
        existing = self._all_artifact_keys()
        if replace:
            cur = self._db.execute("DELETE FROM artifacts")
            deleted = cur.rowcount if (cur.rowcount or 0) > 0 else 0
            existing = set()
        for r in rows:
            if self._art_key(r) in existing:
                continue
            self._db.execute(
                "INSERT INTO artifacts (evidence_id, path, inode, size, mtime,"
                " kind, sha256, md5, meta_json) VALUES (?,?,?,?,?,?,?,?,?)",
                (r.get("evidence_id") or "", r.get("path") or "",
                 _int_or_none(r.get("inode")), _int_or_none(r.get("size")),
                 _float_or_none(r.get("mtime")), r.get("kind"),
                 r.get("sha256"), r.get("md5"), r.get("meta_json") or ""))
            inserted += 1
        self._db.commit()
        skipped = len(rows) - inserted
        self._audit.append(
            "snapshot.restore", target=snap_id,
            detail={"replace": bool(replace), "inserted": inserted,
                    "deleted": deleted, "skipped": skipped})
        return {"snapshot_id": snap_id, "replace": bool(replace),
                "inserted": inserted, "deleted": deleted, "skipped": skipped}

    def verify_snapshot(self, snap_id):
        """校验快照文件是否被改动，并报告审计锚点是否仍在链上"""
        d = self._snapshot_dir(snap_id)
        meta_p = os.path.join(d, "meta.json")
        art_p = os.path.join(d, "artifacts.jsonl")
        if not os.path.exists(meta_p) or not os.path.exists(art_p):
            raise CaseError("快照不存在：%s" % snap_id)
        try:
            with open(meta_p, "r", encoding="utf-8-sig") as f:
                meta = json.load(f)
        except Exception as e:
            return {"ok": False, "snapshot_id": snap_id,
                    "reason": "meta.json 解析失败：%s" % e}
        with open(art_p, "r", encoding="utf-8-sig") as f:
            body = f.read()
        want = meta.get("artifacts_sha256")
        got = _sha256_text(body)
        if want != got:
            return {"ok": False, "snapshot_id": snap_id,
                    "reason": "artifacts.jsonl 内容被改动（记录 %s，实际 %s）"
                              % (want, got)}
        lines = sum(1 for ln in body.splitlines() if ln.strip())
        if lines != meta.get("artifact_count"):
            return {"ok": False, "snapshot_id": snap_id,
                    "reason": "条数不符（记录 %s，实际 %d）"
                              % (meta.get("artifact_count"), lines)}
        rec = meta.get("audit_count") or 0
        now = len(self._audit)
        return {"ok": True, "snapshot_id": snap_id, "artifact_count": lines,
                "audit_recorded": rec, "audit_now": now,
                "audit_extended": now > rec, "reason": ""}

    def stats(self):
        """索引统计"""
        db = self._db
        n = db.execute("SELECT COUNT(*) c FROM artifacts").fetchone()["c"]
        total = db.execute("SELECT COALESCE(SUM(size),0) s FROM artifacts").fetchone()["s"]
        hashed = db.execute(
            "SELECT COUNT(*) c FROM artifacts WHERE sha256 IS NOT NULL AND sha256 <> ''"
        ).fetchone()["c"]
        distinct = db.execute(
            "SELECT COUNT(DISTINCT sha256) c FROM artifacts"
            " WHERE sha256 IS NOT NULL AND sha256 <> ''").fetchone()["c"]
        by_kind = {r["kind"] or "other": r["c"] for r in db.execute(
            "SELECT kind, COUNT(*) c FROM artifacts GROUP BY kind ORDER BY c DESC")}
        by_ev = {r["evidence_id"] or "": r["c"] for r in db.execute(
            "SELECT evidence_id, COUNT(*) c FROM artifacts"
            " GROUP BY evidence_id ORDER BY c DESC")}
        return {
            "case": self.name,
            "case_id": self.case_id,
            "artifacts": n,
            "bytes": int(total or 0),
            "with_sha256": hashed,
            "distinct_sha256": distinct,
            "evidences": len(self._data.get("evidences", [])),
            "by_kind": by_kind,
            "by_evidence": by_ev,
            "db_size": os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0,
        }

    @staticmethod
    def _artifact_row(row):
        d = dict(row)
        raw = d.get("meta_json") or ""
        try:
            d["meta"] = json.loads(raw) if raw else {}
        except Exception:
            d["meta"] = {"_raw": raw}
        d["meta_json"] = raw
        d["mtime_iso"] = _iso(d.get("mtime"))
        return d

    def export_rows(self):
        """全部 artifact（导出用）"""
        return [self._artifact_row(r) for r in
                self._db.execute("SELECT * FROM artifacts ORDER BY path, id")]

    def close(self):
        if self._db is not None:
            try:
                self._db.close()
            except Exception:
                pass
            self._db = None
        if self._audit is not None:
            self._audit.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __repr__(self):
        return "<Case %s %r evidences=%d%s>" % (
            self.case_id, self.name, len(self._data.get("evidences", [])),
            " [ro]" if self.readonly else "")


def _int_or_none(v):
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _float_or_none(v):
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.timestamp()
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if f > 1e11:                       # 纳秒时间戳（NTFS/ext4 常见）
        f /= 1e9
    return f


# ============================================================
# C. 导出
# ============================================================
_PREFERRED_FIELDS = ["id", "evidence_id", "path", "inode", "size", "mtime",
                     "kind", "sha256", "md5", "meta_json"]


def _rows_of(rows):
    """接受 Case / list[dict] / list[sqlite3.Row] / 单个 dict"""
    if isinstance(rows, Case):
        return rows.export_rows()
    if isinstance(rows, dict):
        return [rows]
    if rows is None:
        return []
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append(dict(r))
        elif isinstance(r, sqlite3.Row):
            out.append(dict(r))
        else:
            try:
                out.append(dict(r))
            except Exception:
                raise CaseError("无法导出的行类型：%r" % (type(r),))
    return out


def _fields_of(rows, fieldnames=None):
    if fieldnames:
        return list(fieldnames)
    seen = []
    for r in rows:
        for k in _PREFERRED_FIELDS:
            if k in r and k not in seen:
                seen.append(k)
        for k in r:
            if k not in seen:
                seen.append(k)
    return seen or list(_PREFERRED_FIELDS)


def _cell(v):
    """CSV 单元：None → 空；dict/list → JSON；bytes → hex"""
    if v is None:
        return ""
    if isinstance(v, (dict, list, tuple)):
        return json.dumps(_jsonable(v), ensure_ascii=False, separators=(",", ":"))
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()
    return v


def export_csv(rows, path, fieldnames=None, encoding="utf-8-sig",
               delimiter=",", lineterminator="\r\n"):
    """导出 artifact 列表为 CSV（默认 UTF-8 带 BOM，Excel 双击不乱码）"""
    data = _rows_of(rows)
    fields = _fields_of(data, fieldnames)
    p = os.path.abspath(os.fspath(path))
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(p, "w", encoding=encoding, newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore",
                           delimiter=delimiter, lineterminator=lineterminator)
        w.writeheader()
        for r in data:
            w.writerow({k: _cell(r.get(k)) for k in fields})
    return p


def export_json(rows, path, indent=2, ensure_ascii=False):
    """导出 artifact 列表为 JSON（UTF-8 无 BOM）"""
    data = _rows_of(rows)
    p = os.path.abspath(os.fspath(path))
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    payload = {
        "format": "ESK-ARTIFACTS",
        "version": 1,
        "generated": _now_iso(),
        "count": len(data),
        "artifacts": [_jsonable(r) for r in data],
    }
    _atomic_write_text(p, json.dumps(payload, ensure_ascii=ensure_ascii,
                                     indent=indent) + "\n")
    return p


# ============================================================
# C'. 目录树灌库
# ============================================================
def _norm_walk_item(item, root="/"):
    """把各文件系统模块 walk() 的产出归一成
    (path, entry, inode, size, mtime, kind, is_dir)

    兼容：("path", entry) / 4 元组 (path, typ, ref, ino) / 裸 path /
          NTFS 式直接 yield entry 对象。
    """
    path = None
    entry = None
    extra = ()
    if isinstance(item, (tuple, list)):
        if item and isinstance(item[0], str):
            path = item[0]
            if len(item) > 1:
                entry = item[1]
            extra = tuple(item[2:])
        elif item:
            entry = item[0]
            extra = tuple(item[1:])
    elif isinstance(item, str):
        path = item
    else:
        entry = item

    inode = size = mtime = kind = None
    is_dir = False

    if entry is not None and not isinstance(entry, (str, bytes, int, float)):
        inode = _first_attr(entry, ("inode", "ino", "num", "mft_num", "idx", "id"))
        size = _first_attr(entry, ("size", "length", "file_size", "data_size"))
        mtime = _first_attr(entry, ("mtime", "mtime_unix", "modified", "mod_time"))
        is_dir = bool(_first_attr(entry, ("is_dir", "isdir", "is_directory", "dir"), False))
        kind = _first_attr(entry, ("kind", "ftype", "type_name"))
        name = _first_attr(entry, ("name", "filename"), None)
        if not path and name:
            path = ("/" + str(name)).replace("//", "/")
    elif isinstance(entry, int):
        # 形如 (path, typ_code, ref_inode, real_inode) 的 squashfs 风格
        inode = entry
        kind = None
    if extra and inode is None:
        inode = extra[0]

    if not path:
        path = "/"
    path = str(path).replace("\\", "/")
    if not path.startswith("/"):
        path = "/" + path.lstrip("/")
    if kind is not None and not isinstance(kind, str):
        kind = None
    return path, entry, inode, size, mtime, kind, is_dir


def _read_fs(fs, entry, path):
    """调用 fs.read_file()，entry 优先，失败退回 path"""
    for arg in (entry, path):
        if arg is None:
            continue
        try:
            data = fs.read_file(arg)
        except Exception:
            continue
        if data is None:
            continue
        if isinstance(data, str):
            data = data.encode("utf-8")
        try:
            return bytes(data)
        except Exception:
            continue
    return None


def _walk_items(fs, root="/"):
    """调用 fs.walk()，兼容两类签名

    * walk(path="/")     —— ntfs / ext4 / btrfs / refs / zfs
    * walk(entry=None)   —— fat / iso / romfs / squashfs（传字符串会炸）
    策略：先按 root 调用；一条都没产出就报错时退回无参调用（整卷根）。
    """
    plain = root in (None, "", "/", "\\")
    attempts = [(), (root,)] if plain else [(root,), ()]
    last = None
    for args in attempts:
        emitted = 0
        try:
            for item in fs.walk(*args):
                emitted += 1
                yield item
            return
        except Exception as e:            # 生成器体内报错：没吐过数据才换签名重试
            if emitted:
                raise
            last = e
            continue
    raise CaseError("fs.walk() 调用失败（已尝试 %d 种签名）：%s"
                    % (len(attempts), last))


def ingest_tree(fs, root="/", case=None, evidence_id=None, hashes=False,
                hash_limit=DEFAULT_HASH_LIMIT, hash_algo="sha256",
                include_dirs=False, max_entries=None, replace=False,
                audit=True, progress=None):
    """把一个文件系统对象的目录树灌进索引

    fs 需提供 walk(root) / read_file(x) / info()（ESK 各 fs 模块均满足）。
    hashes=True 时读入内容算 sha256（同一缓冲顺带算 md5）；
    hash_limit 限制参与哈希的字节数（默认 4 MiB），截断会在 meta 里
    标 hash_partial=True 并注明 hashed_bytes，绝不冒充整文件哈希。
    传 hash_limit=None 表示整文件哈希。

    返回行列表（dict）；case 不为 None 时这些行已写进 index.sqlite，
    且每个 dict 带 "id"。
    """
    if hash_limit is not None:
        hash_limit = int(hash_limit)
        if hash_limit <= 0:
            hash_limit = None
    algo = (hash_algo or "sha256").lower().replace("-", "")
    if algo not in ("sha256", "md5"):
        raise CaseError("hash_algo 仅支持 sha256 / md5：%r" % hash_algo)

    rows = []
    if case is not None:
        if not evidence_id:
            raise CaseError("写入案件时必须给 evidence_id（先 add_evidence）")
        if replace:
            case._writable()
            case._db.execute("DELETE FROM artifacts WHERE evidence_id = ?",
                             (evidence_id,))
            case._db.commit()

    n = 0
    for item in _walk_items(fs, root):
        path, entry, inode, size, mtime, kind, is_dir = _norm_walk_item(item, root)
        if is_dir and not include_dirs:
            continue
        row = {"evidence_id": evidence_id or "", "path": path,
               "inode": inode, "size": size, "mtime": _float_or_none(mtime),
               "kind": kind or _kind_by_ext(path),
               "sha256": None, "md5": None, "meta": {}}
        if hashes:
            data = _read_fs(fs, entry, path)
            if data is None:
                row["meta"]["hash_error"] = "read_file 失败"
            else:
                cut = data if hash_limit is None else data[:hash_limit]
                algos = (algo, "md5") if algo != "md5" else (algo,)
                h = bytes_hash(cut, algos)          # mkit.hashcalc，一次读一次算
                row[algo] = h.get(algo)
                if algo != "md5":
                    row["md5"] = h.get("md5")
                if len(cut) != len(data):
                    row["meta"]["hash_partial"] = True
                row["meta"]["hashed_bytes"] = len(cut)
                if size is None:
                    row["size"] = len(data)
        if row["size"] is not None:
            row["size"] = _int_or_none(row["size"])
        if case is not None:
            h = {k: row[k] for k in ("sha256", "md5") if row[k]}
            meta = dict(row["meta"])
            meta["_audit"] = False
            row["id"] = case.add_artifact(evidence_id, path, inode=row["inode"],
                                          size=row["size"], mtime=row["mtime"],
                                          kind=row["kind"], hashes=h or None,
                                          **meta)
        rows.append(row)
        n += 1
        if progress:
            try:
                progress(n, path)
            except Exception:
                pass
        if max_entries and n >= max_entries:
            break

    if case is not None and audit:
        case.audit.append("index.ingest", target=evidence_id or "",
                          detail={"root": root, "count": n,
                                  "hashes": bool(hashes),
                                  "hash_algo": algo if hashes else None,
                                  "hash_limit": hash_limit if hashes else None})
    return rows


# ============================================================
# D. 完整性报告
# ============================================================
def manifest(case):
    """证据哈希清单（可存 JSON 归档），带 keccak256 封存戳"""
    evs = []
    total = 0
    for ev in case.evidences():
        total += int(ev.get("size") or 0)
        evs.append({
            "evidence_id": ev.get("evidence_id", ""),
            "label": ev.get("label", ""),
            "kind": ev.get("kind", ""),
            "path": ev.get("path", ""),
            "size": ev.get("size"),
            "sha256": ev.get("sha256", ""),
            "md5": ev.get("md5", ""),
            "added": ev.get("added", ""),
            "meta": ev.get("meta") or {},
        })
    body = {
        "format": MANIFEST_FORMAT,
        "version": 1,
        "generated": _now_iso(),
        "case": {
            "case_id": case.case_id,
            "name": case.name,
            "examiner": case.examiner,
            "created": case._data.get("created", ""),
            "notes": case._data.get("notes", ""),
        },
        "algorithms": {"whole_file": list(EVIDENCE_ALGOS), "seal": "keccak256"},
        "count": len(evs),
        "total_bytes": total,
        "evidence": evs,
    }
    # 封存戳只覆盖证据集合（不含 generated），同一份证据可复算出同一个戳
    sealed = {k: v for k, v in body.items() if k != "generated"}
    body["seal"] = {"algorithm": "keccak256",
                    "value": keccak256_hex(_canonical(sealed)),
                    "covered": [k for k in sealed if k != "seal"]}
    return body


def manifest_json(case):
    """清单直接出 JSON 文本（UTF-8 无 BOM，供归档保存）"""
    return json.dumps(manifest(case), ensure_ascii=False, indent=2) + "\n"


def verify_evidence(case, root=None):
    """重算证据哈希并与登记值比对

    返回 list[dict]：evidence_id / path / status(ok|missing|mismatch|error)
    / expected_* / actual_* / detail。
    任一条 status != "ok" 即视为封存失效。
    """
    out = []
    for ev in case.evidences():
        eid = ev.get("evidence_id", "")
        p = ev.get("path") or ""
        if not os.path.isabs(p):
            base = os.path.abspath(os.fspath(root)) if root else case.path
            p = os.path.abspath(os.path.join(base, p))
        rec = {"evidence_id": eid, "label": ev.get("label", ""),
               "path": p, "status": "ok",
               "expected_sha256": ev.get("sha256", ""),
               "actual_sha256": "", "expected_md5": ev.get("md5", ""),
               "actual_md5": "", "expected_size": ev.get("size"),
               "actual_size": None, "detail": ""}
        if not os.path.exists(p):
            rec["status"] = "missing"
            rec["detail"] = "文件不存在（用 root= 指定新挂载点）"
            out.append(rec)
            continue
        if os.path.isdir(p):
            rec["status"] = "error"
            rec["detail"] = "登记路径现在是目录"
            out.append(rec)
            continue
        try:
            got = file_hash(p, EVIDENCE_ALGOS)
            rec["actual_sha256"] = got.get("sha256", "")
            rec["actual_md5"] = got.get("md5", "")
            rec["actual_size"] = os.path.getsize(p)
        except Exception as e:
            rec["status"] = "error"
            rec["detail"] = "计算失败：%s" % e
            out.append(rec)
            continue
        bad = []
        if rec["expected_sha256"] and rec["actual_sha256"] != rec["expected_sha256"]:
            bad.append("sha256")
        if rec["expected_md5"] and rec["actual_md5"] != rec["expected_md5"]:
            bad.append("md5")
        if rec["expected_size"] is not None and rec["actual_size"] != rec["expected_size"]:
            bad.append("size")
        if bad:
            rec["status"] = "mismatch"
            rec["detail"] = "不一致字段：" + ",".join(bad)
        out.append(rec)
    return out


# ============================================================
# 自检
# ============================================================
def _fake_fs():
    """假的文件系统对象：walk / read_file / info"""

    class _Entry(object):
        def __init__(self, name, is_dir, size, mtime, inode):
            self.name = name
            self.is_dir = is_dir
            self.size = size
            self.mtime = mtime
            self.inode = inode

    files = {
        "/a.txt": b"alpha\n",
        "/sub/b.txt": "贝塔 内容\n".encode("utf-8"),
        "/sub/c.bin": bytes(range(16)) * 4,
    }
    now = 1700000000.0

    class FS(object):
        def walk(self, root="/"):
            yield "/a.txt", _Entry("a.txt", False, len(files["/a.txt"]), now, 11)
            yield "/sub", _Entry("sub", True, 0, now, 12)
            yield "/sub/b.txt", _Entry("b.txt", False, len(files["/sub/b.txt"]), now, 13)
            yield "/sub/c.bin", _Entry("c.bin", False, len(files["/sub/c.bin"]), now, 14)

        def read_file(self, ent):
            p = ent if isinstance(ent, str) else "/" + ent.name
            if p in files:
                return files[p]
            for k, v in files.items():
                if k.endswith("/" + str(getattr(ent, "name", ""))):
                    return v
            raise FileNotFoundError(p)

        def info(self, path=None):
            return {"kind": "fakefs", "files": len(files)}

    return FS(), files


def _selfcheck():
    tmp = tempfile.mkdtemp(prefix="esk-casebook-")
    case_dir = os.path.join(tmp, "案件-2026")
    work = os.path.join(tmp, "证据")
    os.makedirs(work, exist_ok=True)
    lines = []
    case = None
    try:
        # ---------- 1. 建案件 + 3 条证据（含案件内相对路径） ----------
        f1 = os.path.join(work, "镜像一号.E01")
        f2 = os.path.join(work, "报告.txt")
        c1 = b"ESK evidence one\n"
        c2 = "第二份证据：中文内容\n".encode("utf-8")
        c3 = "案件内相对路径证据\n".encode("utf-8")
        with open(f1, "wb") as f:
            f.write(c1)
        with open(f2, "wb") as f:
            f.write(c2)

        case = Case(case_dir, "某案-2026", examiner="张三", notes="自检用")
        os.makedirs(os.path.join(case_dir, "原始"), exist_ok=True)
        with open(os.path.join(case_dir, "原始", "读取说明.txt"), "wb") as f:
            f.write(c3)
        ev1 = case.add_evidence(f1, "主机镜像", kind="image", source="disk0")
        ev2 = case.add_evidence(f2, "勘验报告", kind="document")
        ev3 = case.add_evidence(os.path.join("原始", "读取说明.txt"), "读取说明")
        evs = case.evidences()
        assert len(evs) == 3, evs
        assert (ev1, ev2, ev3) == ("EV-0001", "EV-0002", "EV-0003"), (ev1, ev2, ev3)
        got = {e["evidence_id"]: e for e in evs}
        assert got["EV-0001"]["sha256"] == hashlib.sha256(c1).hexdigest()
        assert got["EV-0002"]["sha256"] == hashlib.sha256(c2).hexdigest()
        assert got["EV-0003"]["sha256"] == hashlib.sha256(c3).hexdigest()
        assert got["EV-0001"]["md5"] == hashlib.md5(c1).hexdigest()
        assert got["EV-0001"]["size"] == len(c1)
        assert got["EV-0002"]["meta"].get("source") is None
        assert got["EV-0001"]["meta"].get("source") == "disk0"
        assert got["EV-0003"]["path"] == "原始/读取说明.txt", got["EV-0003"]["path"]
        assert case.info()["evidence_count"] == 3
        # case.json 无 BOM
        raw = open(case.case_json, "rb").read()
        assert not raw.startswith(b"\xef\xbb\xbf"), "case.json 有 BOM"
        assert "张三" in raw.decode("utf-8")
        lines.append("1 建案件/证据  OK  3 条 / EV-0001 sha256=%s…"
                     % got["EV-0001"]["sha256"][:12])

        # ---------- 2. 审计链 + 篡改定位 ----------
        al = AuditLog(os.path.join(tmp, "audit-1.jsonl"), operator="张三")
        for i in range(5):
            al.append("step.%d" % (i + 1), target="t%d" % i, detail={"i": i})
        v = al.verify()
        assert v["ok"] and v["count"] == 5, v
        assert len(al.entries()) == 5
        assert al.entries()[0]["prev"] == "0" * 64

        p = al.path
        body = open(p, "r", encoding="utf-8").read().splitlines()
        rec3 = json.loads(body[2])
        rec3["action"] = "step.3-被篡改"
        body[2] = json.dumps(rec3, ensure_ascii=False, separators=(",", ":"))
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(body) + "\n")
        v = al.verify()
        assert v["ok"] is False, v
        assert v["broken_at"] == 3, v
        assert "hash" in v["reason"] or "改动" in v["reason"], v["reason"]
        lines.append("2 审计篡改  OK  broken_at=%d  reason=%s"
                     % (v["broken_at"], v["reason"]))

        # ---------- 3. 删中间一行 ----------
        al2 = AuditLog(os.path.join(tmp, "audit-2.jsonl"), operator="张三")
        for i in range(5):
            al2.append("op%d" % i, detail={"i": i})
        body = open(al2.path, "r", encoding="utf-8").read().splitlines()
        body.pop(2)
        with open(al2.path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(body) + "\n")
        v2 = al2.verify()
        assert v2["ok"] is False and v2["broken_at"] == 3, v2
        assert "序号" in v2["reason"], v2["reason"]
        lines.append("3 删行断链  OK  broken_at=%d  reason=%s"
                     % (v2["broken_at"], v2["reason"][:34]))

        # ---------- 4. artifact 索引 ----------
        h_a = hashlib.sha256(b"aaa").hexdigest()
        id1 = case.add_artifact(ev1, "/Windows/a.txt", inode=101, size=3,
                                mtime=1700000000, kind="text",
                                hashes={"sha256": h_a, "md5": hashlib.md5(b"aaa").hexdigest()})
        id2 = case.add_artifact(ev1, "/Users/张三/笔记.txt", inode=102, size=12,
                                mtime=1700000100, hashes=h_a, author="张三")
        id3 = case.add_artifact(ev2, "/报告.txt", inode=103, size=99,
                                mtime=1700000200, kind="document")
        assert (id1, id2, id3) == (1, 2, 3), (id1, id2, id3)
        hits = case.find_artifacts("*txt*")
        assert len(hits) == 3, [h["path"] for h in hits]
        hits2 = case.find_artifacts("*笔记*")
        assert len(hits2) == 1 and hits2[0]["inode"] == 102, hits2
        bh = case.by_hash(h_a)
        assert len(bh) == 2, bh
        assert case.by_hash(hashlib.md5(b"aaa").hexdigest())[0]["id"] == 1
        st = case.stats()
        assert st["artifacts"] == 3 and st["with_sha256"] == 2, st
        assert st["distinct_sha256"] == 1 and st["bytes"] == 3 + 12 + 99, st
        assert st["by_evidence"]["EV-0001"] == 2, st["by_evidence"]
        lines.append("4 artifact   OK  3 条 / find=3 / by_hash=2 / kind=%s"
                     % list(st["by_kind"]))
        case.audit.append("artifact.query", target="*txt*", detail={"hits": len(hits)})

        # ---------- 5. 导出 ----------
        rows = case.export_rows()
        csv_p = os.path.join(tmp, "out", "artifacts.csv")
        json_p = os.path.join(tmp, "out", "artifacts.json")
        export_csv(rows, csv_p)
        export_json(rows, json_p)
        raw = open(csv_p, "rb").read()
        assert raw.startswith(b"\xef\xbb\xbf"), "CSV 缺 BOM"
        text = raw.decode("utf-8-sig")
        assert len(text.splitlines()) == 4, text
        assert "笔记.txt" in text
        js = json.load(open(json_p, "r", encoding="utf-8"))
        assert js["count"] == 3 and len(js["artifacts"]) == 3, js
        lines.append("5 导出       OK  CSV 1+3 行带 BOM / JSON count=3")

        # ---------- 6. ingest_tree ----------
        fs, files = _fake_fs()
        rw = ingest_tree(fs, root="/", case=case, evidence_id=ev1, hashes=True)
        assert len(rw) == 3, [r["path"] for r in rw]
        byp = {r["path"]: r for r in rw}
        for p_, content in files.items():
            assert byp[p_]["sha256"] == hashlib.sha256(content).hexdigest(), p_
            assert byp[p_]["md5"] == hashlib.md5(content).hexdigest(), p_
            assert byp[p_]["size"] == len(content), p_
        assert all(r["id"] for r in rw)
        st = case.stats()
        assert st["artifacts"] == 6, st
        assert st["by_evidence"]["EV-0001"] == 5, st["by_evidence"]
        # 截断哈希：只算前 4 字节（/a.txt 只有 6 字节，>4 才会被截断）
        rw2 = ingest_tree(fs, root="/", case=case, evidence_id=ev1,
                          hashes=True, hash_limit=4, replace=False)
        part = [r for r in rw2 if r["meta"].get("hash_partial")]
        assert len(part) == 3, rw2
        assert part[0]["meta"]["hashed_bytes"] == 4
        assert part[0]["sha256"] == hashlib.sha256(files["/a.txt"][:4]).hexdigest()
        assert part[0]["sha256"] != hashlib.sha256(files["/a.txt"]).hexdigest()
        lines.append("6 ingest     OK  3 条全哈希 + 3 条截断标 partial")
        # 清掉这批行，便于后面计数
        case._db.execute("DELETE FROM artifacts")
        case._db.commit()

        # ---------- 7. manifest / verify_evidence ----------
        man = manifest(case)
        assert man["count"] == 3, man
        assert man["total_bytes"] == len(c1) + len(c2) + len(c3), man
        assert man["evidence"][0]["sha256"] == hashlib.sha256(c1).hexdigest()
        assert man["seal"]["value"] and len(man["seal"]["value"]) == 64
        man2 = manifest(case)
        assert man2["seal"]["value"] == man["seal"]["value"], "封存戳应可复算"
        ok_before = verify_evidence(case)
        assert [r["status"] for r in ok_before] == ["ok", "ok", "ok"], ok_before

        with open(f1, "wb") as f:           # 篡改证据
            f.write(b"ESK evidence TAMPERED\n")
        rep = verify_evidence(case)
        bad = [r for r in rep if r["status"] != "ok"]
        assert len(bad) == 1 and bad[0]["evidence_id"] == ev1, rep
        assert bad[0]["status"] == "mismatch"
        assert "sha256" in bad[0]["detail"], bad[0]
        assert rep[1]["status"] == "ok" and rep[2]["status"] == "ok", rep
        lines.append("7 完整性     OK  篡改 %s → %s（%s）"
                     % (ev1, bad[0]["status"], bad[0]["detail"]))

        # ---------- 8. 只读打开 ----------
        case.add_artifact(ev2, "/keep.txt", size=1, mtime=1700000300)
        n_ev = len(case.evidences())
        n_art = case.stats()["artifacts"]
        audit_verify = case.audit.verify()
        assert audit_verify["ok"], audit_verify
        case.close()
        case = Case.open(case_dir)
        assert case.readonly is True
        assert case.name == "某案-2026" and case.examiner == "张三"
        assert len(case.evidences()) == n_ev
        assert case.stats()["artifacts"] == n_art == 1, (n_art, case.stats())
        assert case.find_artifacts("*keep*")[0]["path"] == "/keep.txt"
        refused = 0
        for fn in (lambda: case.add_evidence(f2, "只读测试"),
                   lambda: case.add_artifact(ev2, "/x.txt"),
                   lambda: case.audit.append("nope")):
            try:
                fn()
            except CaseError:
                refused += 1
        assert refused == 3, "只读案件的三类写入都应被拒：%d/3" % refused
        case.close()
        case = None
        lines.append("8 只读打开   OK  证据 %d / 索引 %d / 3 类写入被拒" % (n_ev, n_art))

        # ---------- 9. 中文全程 ----------
        manifest_text = json.dumps(man, ensure_ascii=False)
        assert "某案-2026" in manifest_text and "张三" in manifest_text
        assert os.path.exists(os.path.join(case_dir, "case.json"))
        raw = open(os.path.join(case_dir, "case.json"), "rb").read().decode("utf-8")
        assert "勘验报告" in raw
        lines.append("9 中文       OK  案件名/检查员/文件名/case.json 往返无损")

        # ---------- 9.5 卷快照 ----------
        # 这里要重建一个干净的 case（前面的 case 已经用于只读验证）
        snap_case = Case(tmp, "快照案", examiner="张三")
        snap_root = os.path.join(os.path.dirname(tmp), "snap-src-%d" % os.getpid())
        os.makedirs(snap_root, exist_ok=True)
        p1 = os.path.join(snap_root, "a.bin")
        open(p1, "wb").write(b"A" * 16)
        ev_s = snap_case.add_evidence(p1, "证据一", kind="image")
        snap_case.add_artifact(ev_s, "/a.txt", size=11, hashes={"sha256": "aa" * 32})
        snap_case.add_artifact(ev_s, "/b.txt", size=22, hashes={"sha256": "bb" * 32})
        snap_case.add_artifact(ev_s, "/c.txt", size=33, hashes={"sha256": "cc" * 32})
        assert len(snap_case.find_artifacts("*")) == 3

        m1 = snap_case.snapshot("v1", "基线")
        assert m1["snapshot_id"] == "SNAP-0001", m1["snapshot_id"]
        assert m1["artifact_count"] == 3
        assert len(snap_case.snapshots()) == 1
        m2 = snap_case.snapshot("v2", "第二份")
        assert m2["snapshot_id"] == "SNAP-0002", m2["snapshot_id"]
        assert len(snap_case.snapshots()) == 2

        d0 = snap_case.diff_snapshots("SNAP-0001", "SNAP-0002")
        assert d0["added"] == [] and d0["removed"] == [] and d0["changed"] == []
        assert d0["same_count"] == 3, d0["same_count"]

        # 改一条的哈希、加一条、删一条
        snap_case._db.execute(
            "UPDATE artifacts SET sha256 = ? WHERE path = '/b.txt'", ("dd" * 32,))
        snap_case._db.commit()
        snap_case.add_artifact(ev_s, "/d.txt", size=44, hashes={"sha256": "ee" * 32})
        snap_case._db.execute("DELETE FROM artifacts WHERE path = '/c.txt'")
        snap_case._db.commit()
        m3 = snap_case.snapshot("v3", "改动后")
        d1 = snap_case.diff_snapshots("SNAP-0002", m3["snapshot_id"])
        assert d1["added"] == ["/d.txt"], d1["added"]
        assert d1["removed"] == ["/c.txt"], d1["removed"]
        assert d1["changed"] == ["/b.txt"], d1["changed"]

        # verify_snapshot：正常 ok，且报告审计链已延伸
        v = snap_case.verify_snapshot("SNAP-0001")
        assert v["ok"] is True and v["artifact_count"] == 3, v
        assert v["audit_extended"] is True, v
        # 手工改快照文件一个字节 -> 必须被抓出来
        art_p = os.path.join(snap_case.path, "snapshots", "SNAP-0001",
                            "artifacts.jsonl")
        bad = open(art_p, "r", encoding="utf-8").read().replace("aa", "zz", 1)
        open(art_p, "w", encoding="utf-8", newline="\n").write(bad)
        v2 = snap_case.verify_snapshot("SNAP-0001")
        assert v2["ok"] is False and "被改动" in v2["reason"], v2

        # restore：replace=True 清空重建
        r1 = snap_case.restore_snapshot("SNAP-0002", replace=True)
        paths = sorted(a["path"] for a in snap_case.find_artifacts("*"))
        assert paths == ["/a.txt", "/b.txt", "/c.txt"], paths
        assert r1["inserted"] == 3 and r1["deleted"] >= 1, r1
        # replace=False 只补缺失、不删
        snap_case._db.execute("DELETE FROM artifacts WHERE path = '/a.txt'")
        snap_case._db.commit()
        r2 = snap_case.restore_snapshot("SNAP-0002", replace=False)
        paths2 = sorted(a["path"] for a in snap_case.find_artifacts("*"))
        assert paths2 == ["/a.txt", "/b.txt", "/c.txt"], paths2
        assert r2["inserted"] == 1 and r2["deleted"] == 0, r2

        # 只读案件拒绝快照与恢复
        snap_case.close()
        ro = Case.open(tmp, readonly=True)
        refused = 0
        for fn, args in ((ro.snapshot, ()), (ro.restore_snapshot, ("SNAP-0001",))):
            try:
                fn(*args)
            except CaseError:
                refused += 1
        ro.close()
        assert refused == 2, "只读案件应拒快照与恢复：%d/2" % refused

        # 快照动作进审计链，链仍然自洽
        au = AuditLog(os.path.join(tmp, "audit.jsonl"))
        assert au.verify()["ok"] is True
        acts = [e.get("action") for e in au.entries()]
        assert "snapshot.create" in acts and "snapshot.restore" in acts, acts
        au.close()
        # 中文 label / note 无損
        re_open = Case.open(tmp)
        m = re_open.snapshots()[0]
        assert m["label"] == "v1" and m["note"] == "基线", m
        re_open.close()
        shutil.rmtree(snap_root, ignore_errors=True)
        lines.append("9.5 卷快照    OK  SNAP 递增 / diff 三类 / 篡改可检出 / "
                     "restore+只读拒写 / 审计留痕")

    finally:
        if case is not None:
            try:
                case.close()
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)

    # ---------- 10. 清理 ----------
    assert not os.path.exists(tmp), "临时目录未清理：%s" % tmp
    lines.append("10 清理      OK  %s 已删除" % tmp)
    return lines


if __name__ == "__main__":
    started = time.time()
    out = _selfcheck()
    banner_txt = "ESK casebook 自检"
    print("=" * 58)
    print(banner_txt)
    print("=" * 58)
    for ln in out:
        print(" ", ln)
    print("-" * 58)
    print("全部 %d 项通过，用时 %.2fs" % (len(out), time.time() - started))
