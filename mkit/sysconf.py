# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""sysconf.py —— 系统/应用配置取证（Tor、OpenVPN、SD 卡、Wi-Fi MAC）。

覆盖
    * TorConfig：Tor Browser / Orbot 配置目录、torrc 指令（SocksPort/ControlPort）、
      prefs.js（network.proxy.socks_port / privacy.resistFingerprinting /
      browser.startup.homepage）、onion 书签（places.sqlite / bookmarks.html）
    * VpnConfig：.ovpn 指令（remote/cipher/data-ciphers/tls）、使用日志（OpenVPN 文本日志、
      Windows 事件日志尽力而为）、usage_days() 算首末连接日期与跨天数
    * SdCard：DCIM 目录结构统计、相机加密卡判定（Xard/厂商加密）与依据
    * WifiMac：/sys/class/net/*/address、/data/misc/wifi、/persist/wifi、
      WifiConfigStore.xml、Windows 注册表 NetworkList

纯标准库；fs 适配复用 mkit.wallet.FsView（Ext4 / NTFS / DirFS 通用）。
"""

from __future__ import annotations

import datetime
import json
import math
import re

try:
    from .wallet import FsView
except ImportError:  # 直接以脚本方式运行
    from mkit.wallet import FsView  # type: ignore

__all__ = ["TorConfig", "VpnConfig", "SdCard", "WifiMac", "parse_torrc", "parse_prefs_js",
           "parse_ovpn", "MAC_RE"]

MAC_RE = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![0-9a-fA-F:])")


def _is_zero_mac(mac):
    return mac.replace(":", "") in ("000000000000", "ffffffffffff")


# ---------------------------------------------------------------------------
# 解析器（纯函数，便于单测）
# ---------------------------------------------------------------------------

def parse_torrc(text):
    """解析 torrc：返回 {directive_lower: [values...]} 与有序行。"""
    out = {"directives": {}, "lines": []}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        key = parts[0].lower()
        vals = parts[1:]
        out["directives"].setdefault(key, []).append(" ".join(vals) if len(vals) > 1 else
                                                     (vals[0] if vals else ""))
        out["lines"].append((key, vals))
    return out


def _port_of(value):
    """从 'SocksPort 9150 IsolateDestAddr' 这类值里取端口号。"""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    m = re.search(r"\b(\d{2,5})\b", str(value))
    return int(m.group(1)) if m else None


def parse_prefs_js(text):
    """解析 Firefox/Tor Browser 的 prefs.js -> {name: value}。"""
    out = {}
    for m in re.finditer(r'user_pref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;', text, re.S):
        key, raw = m.group(1), m.group(2).strip()
        if raw.startswith('"') and raw.endswith('"'):
            val = raw[1:-1]
        elif raw in ("true", "false"):
            val = raw == "true"
        else:
            try:
                val = json.loads(raw)
            except Exception:
                val = raw
        out[key] = val
    return out


_OVPN_KEY = {
    "remote": "remotes", "port": "ports", "proto": "proto", "dev": "dev",
    "cipher": "cipher", "data-ciphers": "data_ciphers", "ncp-ciphers": "data_ciphers",
    "auth": "auth", "tls-auth": "tls_auth", "tls-crypt": "tls_crypt",
    "tls-version-min": "tls_version_min", "ca": "ca", "cert": "cert", "key": "key",
    "remote-cert-tls": "remote_cert_tls", "auth-user-pass": "auth_user_pass",
    "verb": "verb", "comp-lzo": "comp_lzo", "compress": "compress",
    "dh": "dh", "server": "server", "client": "client", "pull": "pull",
    "key-direction": "key_direction", "explicit-exit-notify": "exit_notify",
    "sndbuf": "sndbuf", "rcvbuf": "rcvbuf", "mute-replay-warnings": "mute_replay",
    "nobind": "nobind", "persist-key": "persist_key", "persist-tun": "persist_tun",
    "resolv-retry": "resolv_retry", "tun-mtu": "tun_mtu", "fragment": "fragment",
    "keepalive": "keepalive", "route": "routes", "register-dns": "register_dns",
}


def parse_ovpn(text):
    """解析 .ovpn 客户端配置。"""
    info = {"remotes": [], "ports": [], "inline_sections": [], "unknown": []}
    inline_tag = None
    inline_buf = []
    for line in text.splitlines():
        s = line.strip()
        if inline_tag:
            if s.lower() == "</%s>" % inline_tag.lower():
                info["inline_sections"].append({"tag": inline_tag,
                                                "bytes": len("\n".join(inline_buf))})
                inline_tag = None
                inline_buf = []
            else:
                inline_buf.append(s)
            continue
        if s.startswith("<") and s.endswith(">") and not s.startswith("</"):
            inline_tag = s[1:-1].split()[0]
            inline_buf = []
            continue
        if not s or s.startswith(("#", ";")):
            continue
        parts = s.split()
        key = parts[0].lower()
        args = parts[1:]
        if key == "remote":
            info["remotes"].append({
                "host": args[0] if args else None,
                "port": args[1] if len(args) > 1 else None,
                "proto": args[2] if len(args) > 2 else None,
            })
        elif key in ("data-ciphers", "ncp-ciphers"):
            info["data_ciphers"] = [c for c in ":".join(args).split(":") if c]
        elif key == "cipher":
            info["cipher"] = args[0] if args else None
        elif key in _OVPN_KEY:
            dst = _OVPN_KEY[key]
            info[dst] = " ".join(args) if len(args) > 1 else (args[0] if args else True)
        else:
            info["unknown"].append(s[:80])
    if info["ports"]:
        for r in info["remotes"]:
            if not r.get("port") and info["ports"]:
                r["port"] = str(info["ports"][0])
    enc = info.get("cipher") or (info.get("data_ciphers") or [None])[0]
    info["encryption"] = enc
    if info.get("cipher") and info.get("data_ciphers"):
        info["encryption_note"] = (
            "cipher %s（OpenVPN 2.4 及更早），data-ciphers 协商首选 %s（2.5+）"
            % (info["cipher"], info["data_ciphers"][0]))
    return info


def _parse_ts(line, default_year=None):
    """从一行日志里抠时间戳（多格式）。"""
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", line)
    if m:
        try:
            return datetime.datetime(*[int(x) for x in m.groups()],
                                     tzinfo=datetime.timezone.utc)
        except ValueError:
            return None
    m = re.search(r"(\d{4})/(\d{1,2})/(\d{1,2})[ T](\d{1,2}):(\d{2}):(\d{2})", line)
    if m:
        try:
            return datetime.datetime(*[int(x) for x in m.groups()],
                                     tzinfo=datetime.timezone.utc)
        except ValueError:
            return None
    # OpenVPN 默认日志前缀：Tue Mar 12 10:22:31 2024
    m = re.search(r"([A-Z][a-z]{2}) ([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})",
                  line)
    if m:
        try:
            return datetime.datetime.strptime(
                "%s %s %s %s:%s:%s %s" % m.groups(), "%a %b %d %H:%M:%S %Y"
            ).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return None
    m = re.search(r"\[(\d{1,2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})", line)
    if m:  # Apache 风格 12/Mar/2024:10:22:31
        try:
            return datetime.datetime.strptime(
                "%s/%s/%s:%s:%s:%s" % m.groups(), "%d/%b/%Y:%H:%M:%S"
            ).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Tor
# ---------------------------------------------------------------------------

class TorConfig:
    """Tor Browser / Orbot 配置取证。"""

    CANDIDATE_ROOTS = [
        "/data/data/org.torproject.torbrowser",
        "/data/data/org.torproject.torbrowser_alpha",
        "/data/data/org.torproject.torbrowser/files",
        "/data/data/org.torproject.android",
        "/data/data/org.torproject.android/files",
        "/sdcard/TorBrowser", "/storage/emulated/0/TorBrowser",
        "/sdcard/Orbot", "/sdcard/tor",
        "/Users", "/Program Files", "/Program Files (x86)", "/Tools", "/tools",
        "/ProgramData", "/Desktop", "/Downloads", "/home", "/root",
        "/", "/mnt", "/media",
    ]

    def __init__(self, fs):
        self.fs = fs if isinstance(fs, FsView) else FsView(fs)
        self.notes = []
        self._roots = None
        self._bookmarks = None

    # ---------------- 目录探测 ----------------
    @staticmethod
    def _profile_root(path):
        """从 torrc / prefs.js 路径回溯到 profile 根（TorBrowser 数据目录的上一层）。"""
        parts = path.strip("/").split("/")
        # 首选大写的 "Data"（Tor Browser 的 Browser/TorBrowser/Data/...）
        for i in range(len(parts) - 1, -1, -1):
            if parts[i] == "Data":
                return "/" + "/".join(parts[:i])
        # 退化：形如 .../profile.default/xxx -> 去掉 profile.default
        for i in range(len(parts) - 1, -1, -1):
            if parts[i].lower().startswith("profile"):
                return "/" + "/".join(parts[:i])
        if len(parts) >= 2:
            return "/" + "/".join(parts[:-1])
        return "/"

    def _find_roots(self):
        if self._roots is not None:
            return self._roots
        roots = {}
        found = self.fs.find_named(self.CANDIDATE_ROOTS,
                                  ("torrc", "torrc-defaults", "prefs.js"),
                                  maxdepth=8)
        for path, is_dir, _obj in found:
            if is_dir:
                continue
            base = path.rsplit("/", 1)[-1].lower()
            root = self._profile_root(path)
            roots.setdefault(root, set()).add(base)
        # 只看像 Tor 的：路径含 tor，或有 torrc，或 prefs.js 里有 torlauncher
        keep = {}
        for root, kinds in roots.items():
            is_tor = ("tor" in root.lower()) or ("torrc" in kinds) or ("torrc-defaults" in kinds)
            if not is_tor:
                prefs = self._find_prefs(root)
                if prefs:
                    txt = self.fs.read(prefs, max_size=4 << 20).decode("utf-8", "replace")
                    if "torlauncher" in txt.lower() or "network.proxy.socks_remote_dns" in txt:
                        is_tor = True
            if is_tor:
                keep[root] = kinds
        if not keep:
            self.notes.append("未找到 Tor 配置目录；已试 roots: %s"
                              % ", ".join(self.CANDIDATE_ROOTS[:12]))
        self._roots = keep
        return keep

    def _find_prefs(self, root):
        cands = [
            root + "/Browser/TorBrowser/Data/Browser/profile.default/prefs.js",
            root + "/Data/Browser/profile.default/prefs.js",
            root + "/profile.default/prefs.js",
            root + "/prefs.js",
        ]
        for c in cands:
            if self.fs.isfile(c):
                return c
        hits = self.fs.find_named([root], ("prefs.js",), maxdepth=6)
        return hits[0][0] if hits else None

    def _find_torrc(self, root):
        cands = [
            root + "/Browser/TorBrowser/Data/Tor/torrc",
            root + "/Data/Tor/torrc",
            root + "/Tor/torrc",
            root + "/torrc",
            root + "/files/tor/torrc",
        ]
        for c in cands:
            if self.fs.isfile(c):
                return c
        hits = self.fs.find_named([root], ("torrc",), maxdepth=6)
        return hits[0][0] if hits else None

    def _find_places(self, root):
        cands = [
            root + "/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite",
            root + "/Data/Browser/profile.default/places.sqlite",
            root + "/profile.default/places.sqlite",
        ]
        for c in cands:
            if self.fs.isfile(c):
                return c
        hits = self.fs.find_named([root], ("places.sqlite",), maxdepth=6)
        return hits[0][0] if hits else None

    # ---------------- 公共 ----------------
    def profiles(self):
        out = []
        for root, kinds in sorted(self._find_roots().items()):
            torrc = self._find_torrc(root)
            prefs_path = self._find_prefs(root)
            places = self._find_places(root)
            prof = {"root": root, "torrc": torrc, "prefs": prefs_path,
                    "places": places, "kinds": sorted(kinds)}
            if torrc:
                txt = self.fs.read(torrc, max_size=4 << 20).decode("utf-8", "replace")
                parsed = parse_torrc(txt)
                d = parsed["directives"]
                prof["torrc_directives"] = {k: v for k, v in d.items()}
                prof["socks_port"] = _port_of((d.get("socksport") or [None])[0])
                prof["control_port"] = _port_of((d.get("controlport") or [None])[0])
                prof["cookie_auth"] = (d.get("cookieauthentication") or [None])[0]
                prof["hashed_control_password"] = bool(d.get("hashedcontrolpassword"))
                prof["data_directory"] = (d.get("datadirectory") or [None])[0]
                prof["bridges_used"] = bool(d.get("bridges") or d.get("bridge"))
                prof["torrc_lines"] = len(parsed["lines"])
            if prefs_path:
                txt = self.fs.read(prefs_path, max_size=8 << 20).decode("utf-8", "replace")
                prefs = parse_prefs_js(txt)
                prof["prefs_count"] = len(prefs)
                prof["socks_port"] = prof.get("socks_port") or prefs.get("network.proxy.socks_port")
                prof["socks_host"] = prefs.get("network.proxy.socks")
                prof["proxy_type"] = prefs.get("network.proxy.type")
                prof["socks_remote_dns"] = prefs.get("network.proxy.socks_remote_dns")
                prof["resist_fingerprinting"] = prefs.get("privacy.resistFingerprinting")
                prof["homepage"] = prefs.get("browser.startup.homepage")
                prof["control_port"] = prof.get("control_port") or prefs.get(
                    "extensions.torlauncher.control_port")
                prof["torlauncher_bridge"] = prefs.get("extensions.torlauncher.default_bridge_type")
                prof["torbrowser_version"] = prefs.get(
                    "extensions.torbutton.versioncheck_url")
                prof["_prefs"] = prefs
            bms = self.onion_bookmarks()
            prof["onion_bookmarks"] = len([b for b in bms if b.get("root") == root]) if bms else 0
            out.append(prof)
        return out

    def onion_bookmarks(self):
        """所有 .onion 书签：[{title, url, host, source, profile}]。"""
        if self._bookmarks is not None:
            return self._bookmarks
        out = []
        seen = set()

        def push(url, title, source, root, added=None):
            u = (url or "").strip()
            if ".onion" not in u.lower():
                return
            host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0]
            key = u.lower()
            if key in seen:
                return
            seen.add(key)
            out.append({"title": (title or "").strip() or None, "url": u, "host": host,
                        "source": source, "profile": root, "added": added})

        for root in self._find_roots():
            places = self._find_places(root)
            if places:
                data = self.fs.read(places, max_size=64 << 20)
                if data:
                    for rec in self._bookmarks_from_places(data):
                        push(rec.get("url"), rec.get("title"), "places.sqlite", root,
                             rec.get("added"))
            for path, _obj in self.fs.find_ext([root], (".html", ".htm", ".json"),
                                              maxdepth=6):
                base = path.rsplit("/", 1)[-1].lower()
                if "bookmark" not in base and "places" not in base:
                    continue
                txt = self.fs.read(path, max_size=16 << 20).decode("utf-8", "replace")
                if ".onion" not in txt.lower():
                    continue
                for m in re.finditer(r'<A\s+HREF="([^"]+)"[^>]*>(.*?)</A>', txt,
                                     re.I | re.S):
                    push(m.group(1), re.sub(r"<[^>]+>", "", m.group(2)), path, root)
                for m in re.finditer(r'"(https?://[^"]*\.onion[^"]*)"', txt, re.I):
                    push(m.group(1), None, path, root)
        # 全盘兜底：任意文本里的 onion URL（未在 profile 里也能报）
        if not out:
            for path, _obj in self.fs.find_ext(["/"], (".html", ".htm"), maxdepth=5):
                txt = self.fs.read(path, max_size=8 << 20).decode("utf-8", "replace")
                if ".onion" not in txt.lower():
                    continue
                for m in re.finditer(r'<A\s+HREF="([^"]+)"[^>]*>(.*?)</A>', txt,
                                     re.I | re.S):
                    push(m.group(1), re.sub(r"<[^>]+>", "", m.group(2)), path, "/")
        self._bookmarks = out
        return out

    def _bookmarks_from_places(self, data):
        """places.sqlite -> [{url,title,added}]（moz_bookmarks JOIN moz_places，手工连表）。"""
        try:
            from .mobile import SqliteTriage
        except ImportError:
            from mkit.mobile import SqliteTriage  # type: ignore
        try:
            db = SqliteTriage(data)
        except Exception as e:
            self.notes.append("places.sqlite 打不开: %s" % e)
            return []
        out = []
        try:
            places = db.query_dicts("select id, url, title, last_visit_date from moz_places",
                                    limit=20000)
        except Exception as e:
            self.notes.append("moz_places 查询失败: %s" % e)
            places = []
        try:
            bms = db.query_dicts("select id, fk, title, dateAdded, type from moz_bookmarks",
                                 limit=20000)
        except Exception:
            bms = []
        by_id = {}
        for p in places:
            pid = p.get("id")
            if pid is None:
                continue
            by_id[pid] = p
        if bms:
            for b in bms:
                pid = b.get("fk")
                if pid is None:
                    continue
                p = by_id.get(pid)
                if not p:
                    continue
                out.append({"url": p.get("url"), "title": b.get("title") or p.get("title"),
                            "added": _moz_ts(b.get("dateAdded"))})
        for p in places:
            u = (p.get("url") or "")
            if ".onion" in u.lower():
                out.append({"url": u, "title": p.get("title"),
                            "added": _moz_ts(p.get("last_visit_date"))})
        try:
            db.close()
        except Exception:
            pass
        return out

    def ports(self):
        """推断的 Tor SOCKS / 控制端口列表。"""
        ports = []
        default_seen = False
        for prof in self.profiles():
            for k in ("socks_port", "control_port"):
                p = prof.get(k)
                if isinstance(p, int) and p not in ports:
                    ports.append(p)
            if prof.get("_prefs"):
                for key in ("network.proxy.socks_port", "extensions.torlauncher.control_port"):
                    p = prof["_prefs"].get(key)
                    if isinstance(p, int) and p not in ports:
                        ports.append(p)
            default_seen = True
        if not ports and default_seen:
            ports = [9050, 9051]
        return sorted(ports)


def _moz_ts(v):
    """Firefox 的 PRTime（微秒，1970 起）-> ISO。"""
    if not isinstance(v, (int, float)) or v <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            float(v) / 1e6, datetime.timezone.utc).isoformat()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# VPN / OpenVPN
# ---------------------------------------------------------------------------

class VpnConfig:
    """OpenVPN 配置与使用记录。"""

    CANDIDATE_ROOTS = [
        "/data/data/de.blinkt.openvpn", "/data/data/net.openvpn.openvpn",
        "/data/data/com.openvpn.client", "/data/local/tmp",
        "/sdcard/Download", "/sdcard/openvpn", "/sdcard",
        "/storage/emulated/0/Download", "/storage/emulated/0/openvpn",
        "/storage/emulated/0",
        "/Users", "/Program Files", "/Program Files (x86)", "/ProgramData",
        "/ProgramData/OpenVPN", "/etc/openvpn", "/home", "/root", "/var/log",
        "/Windows/System32/winevt/Logs",
        "/logs", "/data", "/",
    ]

    EVENT_RULES = [
        (re.compile(r"Initialization Sequence Completed", re.I), "connected"),
        (re.compile(r"OpenVPN\s+(\d[\w.]*)[^\n]*\sbuilt on", re.I), "start"),
        (re.compile(r"SIGTERM\[hard,\]|SIGUSR1\[soft\]|process exiting|Inactivity timeout",
                    re.I), "stop"),
        (re.compile(r"Peer Connection Initiated with", re.I), "peer"),
        (re.compile(r"AUTH_FAILED|TLS Error|TLS handshake failed|Cannot resolve host|"
                    r"Connection reset|Network is unreachable", re.I), "error"),
    ]

    def __init__(self, fs):
        self.fs = fs if isinstance(fs, FsView) else FsView(fs)
        self.notes = []
        self._profiles = None
        self._events = None

    # ---------------- 配置 ----------------
    def openvpn(self):
        if self._profiles is not None:
            return self._profiles
        out = []
        seen = set()
        for path, obj in self.fs.find_ext(self.CANDIDATE_ROOTS, (".ovpn",), maxdepth=9):
            key = path.lower()
            if key in seen:
                continue
            seen.add(key)
            txt = self.fs.read_obj(obj, max_size=4 << 20).decode("utf-8", "replace")
            info = parse_ovpn(txt)
            rec = {"path": path, "bytes": self.fs.size(obj)}
            rec.update(info)
            rec["host"] = info["remotes"][0]["host"] if info["remotes"] else None
            rec["port"] = info["remotes"][0]["port"] if info["remotes"] else None
            out.append(rec)
        # OpenVPN 也可能把配置写在 Android 的 .conf/.txt 里
        if not out:
            for path, obj in self.fs.find_ext(self.CANDIDATE_ROOTS, (".conf", ".txt"),
                                              maxdepth=6, limit=400):
                base = path.rsplit("/", 1)[-1].lower()
                if "openvpn" not in path.lower() and "vpn" not in base:
                    continue
                data = self.fs.read_obj(obj, max_size=2 << 20)
                if b"remote " not in data or b"dev tun" not in data:
                    continue
                info = parse_ovpn(data.decode("utf-8", "replace"))
                rec = {"path": path, "bytes": len(data)}
                rec.update(info)
                rec["host"] = info["remotes"][0]["host"] if info["remotes"] else None
                rec["port"] = info["remotes"][0]["port"] if info["remotes"] else None
                out.append(rec)
        if not out:
            self.notes.append("未找到 .ovpn 配置；已试 roots: %s"
                              % ", ".join(self.CANDIDATE_ROOTS[:10]))
        self._profiles = out
        return out

    # ---------------- 日志 ----------------
    def events(self):
        """所有 VPN 相关日志事件：[{time, event, host, line, source}]。"""
        if self._events is not None:
            return self._events
        evs = []
        seen_paths = set()
        # 1) 文本日志
        for path, obj in self.fs.find_ext(self.CANDIDATE_ROOTS,
                                          (".log", ".txt"), maxdepth=8, limit=600):
            if path.lower() in seen_paths:
                continue
            seen_paths.add(path.lower())
            size = self.fs.size(obj)
            if size == 0 or size > 32 << 20:
                continue
            data = self.fs.read_obj(obj, max_size=32 << 20)
            low = data.lower()
            if (b"openvpn" not in low and b"initialization sequence completed" not in low
                    and b"sigterm[hard" not in low and b"peer connection initiated" not in low):
                continue
            evs.extend(self._events_from_text(path, data))
        # 2) Windows 事件日志（尽力而为）
        evtx_files = []
        for path, obj in self.fs.find_ext(["/Windows/System32/winevt/Logs",
                                           "/Windows/System32/config",
                                           "/Users", "/ProgramData"],
                                          (".evtx",), maxdepth=6, limit=20):
            if path.lower() in seen_paths:
                continue
            seen_paths.add(path.lower())
            if self.fs.size(obj) > 128 << 20:
                continue
            evtx_files.append((path, obj))
        for path, obj in evtx_files:
            data = self.fs.read_obj(obj, max_size=128 << 20)
            if b"OpenVPN" not in data and "OpenVPN".encode("utf-16-le") not in data:
                continue
            evs.extend(self._events_from_evtx(path, data))
        evs.sort(key=lambda e: (e.get("time") or ""))
        self._events = evs
        return evs

    def _events_from_text(self, path, data):
        out = []
        for raw in data.decode("utf-8", "replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            kind = None
            for rx, name in self.EVENT_RULES:
                if rx.search(line):
                    kind = name
                    break
            if kind is None:
                continue
            ts = _parse_ts(line)
            host = None
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|\b[a-z0-9.-]+\.(?:com|net|org|io|me|"
                          r"xyz|top|info|cn|ru)\b)", line, re.I)
            if m:
                host = m.group(1)
            out.append({
                "time": ts.isoformat() if ts else None,
                "event": kind, "host": host, "line": line[:300], "source": path,
            })
        return out

    def _events_from_evtx(self, path, data):
        """EVTX 尽力而为：优先自研解析器，否则 UTF-16 串扫。"""
        out = []
        recs = None
        try:
            from .winart import evtx_records
        except ImportError:
            try:
                from mkit.winart import evtx_records  # type: ignore
            except ImportError:
                evtx_records = None
        if evtx_records is not None:
            try:
                recs, mode = evtx_records(data)
            except Exception as e:
                recs, mode = None, "failed: %s" % e
            if recs:
                for r in recs:
                    text = str(r)
                    if "openvpn" not in text.lower():
                        continue
                    ts = _parse_ts(text)
                    out.append({"time": ts.isoformat() if ts else str(r.get("time") or ""),
                                "event": "evtx", "host": None, "line": text[:300],
                                "source": path + "#evtx"})
                if out:
                    return out
                self.notes.append("%s: evtx 解析成功但无 OpenVPN 记录" % path)
                return out
            self.notes.append("%s: evtx 解析器不可用（%s），改 UTF-16 串扫" % (path, mode))
        # UTF-16 串扫：抽 "OpenVPN ..." 片段
        text = data.decode("utf-16-le", "ignore")
        for m in re.finditer(r"OpenVPN[^\x00]{0,200}", text):
            seg = m.group(0)
            ts = _parse_ts(seg)
            out.append({"time": ts.isoformat() if ts else None, "event": "evtx-string",
                        "host": None, "line": seg[:300], "source": path + "#utf16"})
        if not out:
            self.notes.append("%s: 未在 evtx 中定位 OpenVPN 记录（精度有限）" % path)
        return out

    # ---------------- 使用天数 ----------------
    def usage_days(self, host=None):
        """按日志算首末连接日期与跨天数。host 为空则统计全部。"""
        evs = self.events()
        if host:
            hl = host.lower()
            evs = [e for e in evs if hl in (e.get("line") or "").lower()
                   or hl == (e.get("host") or "").lower()]
        timed = []
        for e in evs:
            t = e.get("time")
            if not t:
                continue
            try:
                timed.append((datetime.datetime.fromisoformat(t), e))
            except Exception:
                continue
        timed.sort(key=lambda x: x[0])
        result = {
            "host": host,
            "events": len(evs),
            "timed_events": len(timed),
            "first": None, "last": None, "days": 0, "span_hours": 0.0,
            "connections": 0, "sessions": [], "sources": sorted({e["source"] for e in evs}),
            "notes": list(self.notes),
        }
        if not timed:
            if not evs:
                result["notes"].append("没有带时间戳的 VPN 事件（日志缺失或格式未识别）")
            return result
        first, last = timed[0][0], timed[-1][0]
        result["first"] = first.isoformat()
        result["last"] = last.isoformat()
        result["days"] = (last.date() - first.date()).days + 1
        result["span_hours"] = round((last - first).total_seconds() / 3600.0, 2)
        result["connections"] = sum(1 for _t, e in timed if e["event"] == "connected")
        if not result["connections"]:
            result["connections"] = sum(1 for _t, e in timed if e["event"] == "start")
        # 会话：start/connected 起，stop 止
        cur = None
        for t, e in timed:
            if e["event"] in ("start", "connected"):
                if cur is None:
                    cur = {"start": t, "end": None, "host": e.get("host")}
                else:
                    cur["end"] = cur.get("end") or t
            elif e["event"] == "stop":
                if cur is not None:
                    cur["end"] = t
                    result["sessions"].append({
                        "start": cur["start"].isoformat(),
                        "end": cur["end"].isoformat() if cur["end"] else None,
                        "hours": round((cur["end"] - cur["start"]).total_seconds() / 3600.0, 2)
                        if cur["end"] else None,
                        "host": cur.get("host"),
                    })
                    cur = None
        if cur is not None:
            result["sessions"].append({"start": cur["start"].isoformat(), "end": None,
                                       "hours": None, "host": cur.get("host"),
                                       "note": "会话未闭合（日志截断/未正常退出）"})
        return result


# ---------------------------------------------------------------------------
# SD 卡
# ---------------------------------------------------------------------------

class SdCard:
    """SD 卡取证：DCIM 结构统计与加密卡判定。"""

    CANDIDATE_ROOTS = ["/DCIM", "/dcim", "/sdcard/DCIM", "/storage/emulated/0/DCIM",
                       "/storage/sdcard1/DCIM", "/mnt/sdcard/DCIM", "/", "/data/media/0"]

    _MAGIC = {
        b"\xff\xd8\xff": "jpeg", b"\x89PNG": "png", b"\x00\x00\x00": "mp4(ftyp)",
        b"GIF8": "gif", b"II*\x00": "tiff", b"MM\x00*": "tiff",
        b"\x00\x00\x00\x18ftyp": "mp4", b"\x00\x00\x00\x20ftyp": "mp4",
        b"RIFF": "riff", b"BM": "bmp", b"HEIC": "heic", b"ftyp": "mp4",
    }

    def __init__(self, fs):
        self.fs = fs if isinstance(fs, FsView) else FsView(fs)
        self.notes = []

    def _dcim_dirs(self):
        out = []
        for root in self.CANDIDATE_ROOTS:
            if not self.fs.isdir(root):
                continue
            hits = self.fs.find_named([root], ("dcim",), maxdepth=3)
            for path, is_dir, _obj in hits:
                if is_dir and path not in out:
                    out.append(path)
        if not out:
            self.notes.append("未找到 DCIM 目录；已试 %s" % ", ".join(self.CANDIDATE_ROOTS))
        return out

    def dcim(self):
        """相机目录结构统计。"""
        report = {"dirs": [], "count": 0}
        for dcim in self._dcim_dirs():
            node = {"path": dcim, "subdirs": [], "files": 0, "bytes": 0, "exts": {},
                    "newest": None, "loose_files": []}
            for name, is_dir, obj in self.fs.listdir(dcim):
                if is_dir:
                    sub = {"name": name, "files": 0, "bytes": 0, "exts": {},
                           "newest": None, "samples": []}
                    for sname, s_is_dir, sobj in self.fs.listdir(
                            dcim.rstrip("/") + "/" + name):
                        if s_is_dir:
                            continue
                        sub["files"] += 1
                        sz = self.fs.size(sobj)
                        sub["bytes"] += sz
                        ext = ("." + sname.rsplit(".", 1)[-1].lower()) if "." in sname else ""
                        sub["exts"][ext] = sub["exts"].get(ext, 0) + 1
                        mt = self.fs.mtime(sobj)
                        if mt and (sub["newest"] is None or str(mt) > str(sub["newest"])):
                            sub["newest"] = str(mt)
                        if len(sub["samples"]) < 5:
                            sub["samples"].append(sname)
                    sub["newest"] = sub["newest"]
                    node["files"] += sub["files"]
                    node["bytes"] += sub["bytes"]
                    for k, v in sub["exts"].items():
                        node["exts"][k] = node["exts"].get(k, 0) + v
                    if sub["newest"] and (node["newest"] is None
                                          or sub["newest"] > node["newest"]):
                        node["newest"] = sub["newest"]
                    node["subdirs"].append(sub)
                else:
                    node["files"] += 1
                    node["bytes"] += self.fs.size(obj)
                    ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
                    node["exts"][ext] = node["exts"].get(ext, 0) + 1
                    node["loose_files"].append(name)
            report["dirs"].append(node)
        report["count"] = len(report["dirs"])
        return report

    def encrypted_hint(self):
        """判定是否相机加密卡（Xard/厂商加密），给出依据列表。"""
        evidence = []
        score = 0
        dcims = self._dcim_dirs()
        # 1) Xard / 厂商加密标记
        markers = []
        for root in ("/", "/DCIM"):
            if not self.fs.isdir(root):
                continue
            for path, is_dir, _obj in self.fs.walk(root, maxdepth=4, limit=20000):
                base = path.rsplit("/", 1)[-1]
                if re.search(r"(?i)xard", base):
                    markers.append(path)
                    if len(markers) >= 20:
                        break
        if markers:
            score += 3
            evidence.append("发现 Xard 相关路径 %d 处：%s"
                            % (len(markers), ", ".join(markers[:5])))
        # 2) DCIM 内样本的 magic 失配率 + 熵
        sampled = 0
        bad_magic = 0
        high_entropy = 0
        odd_ext = {}
        for dcim in dcims:
            for name, is_dir, obj in self.fs.listdir(dcim):
                if is_dir:
                    for sname, s_is_dir, sobj in self.fs.listdir(
                            dcim.rstrip("/") + "/" + name):
                        if s_is_dir or sampled >= 200:
                            continue
                        head = self.fs.read_obj(sobj, limit=4096) or b""
                        if not head:
                            continue
                        sampled += 1
                        if not self._is_media(head):
                            bad_magic += 1
                        if _entropy(head[:2048]) > 7.5:
                            high_entropy += 1
                        ext = ("." + sname.rsplit(".", 1)[-1].lower()) if "." in sname else ""
                        odd_ext[ext] = odd_ext.get(ext, 0) + 1
                else:
                    head = self.fs.read_obj(obj, limit=4096) or b""
                    if not head:
                        continue
                    sampled += 1
                    if not self._is_media(head):
                        bad_magic += 1
                    if _entropy(head[:2048]) > 7.5:
                        high_entropy += 1
        if sampled:
            ratio = bad_magic / sampled
            if ratio >= 0.7:
                score += 2
                evidence.append("DCIM 样本 %d 个中 %d 个无合法媒体文件头（%.0f%%），"
                                "疑似密文" % (sampled, bad_magic, ratio * 100))
            elif ratio >= 0.3:
                score += 1
                evidence.append("DCIM 样本 %d 个中 %d 个无合法媒体头（%.0f%%）"
                                % (sampled, bad_magic, ratio * 100))
            else:
                evidence.append("DCIM 样本 %d 个中仅 %d 个无合法媒体头（%.0f%%），"
                                "文件头正常" % (sampled, bad_magic, ratio * 100))
            if high_entropy and high_entropy / sampled >= 0.6:
                score += 1
                evidence.append("%d/%d 样本 4KB 熵 > 7.5（接近随机）"
                                % (high_entropy, sampled))
        if odd_ext:
            weird = {k: v for k, v in odd_ext.items()
                     if k not in ("", ".jpg", ".jpeg", ".png", ".mp4", ".3gp", ".mov",
                                  ".heic", ".avi", ".mkv", ".gif", ".bmp", ".dng", ".cr2",
                                  ".nef", ".arw", ".thm", ".lrv", ".insv")}
            if weird:
                score += 1
                evidence.append("DCIM 出现非标准扩展名：%s" % weird)
        if not dcims:
            evidence.append("未找到 DCIM 目录（该卷可能不是相机卡或目录已被加密/删除）")
        if score >= 3:
            verdict = "likely-encrypted"
        elif score >= 1:
            verdict = "inconclusive"
        else:
            verdict = "plain" if dcims else "no-evidence"
        return {"verdict": verdict, "score": score, "evidence": evidence,
                "sampled_files": sampled, "dcim_dirs": dcims,
                "xard_markers": markers[:20], "notes": self.notes}

    @staticmethod
    def _is_media(head):
        for magic, _name in SdCard._MAGIC.items():
            if head.startswith(magic):
                return True
        if b"ftyp" in head[:16]:
            return True
        return False


def _entropy(buf):
    if not buf:
        return 0.0
    freq = [0] * 256
    for b in buf:
        freq[b] += 1
    n = len(buf)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# ---------------------------------------------------------------------------
# Wi-Fi MAC
# ---------------------------------------------------------------------------

class WifiMac:
    """MAC 地址取证：sysfs / Android 配置 / Windows 注册表。"""

    def __init__(self, fs):
        self.fs = fs if isinstance(fs, FsView) else FsView(fs)
        self.notes = []

    # ---------------- 内部 ----------------
    def _from_sysfs(self, out, seen):
        root = "/sys/class/net"
        if not self.fs.isdir(root):
            return
        for iface, is_dir, _obj in self.fs.listdir(root):
            if not is_dir:
                continue
            path = root + "/" + iface + "/address"
            if not self.fs.isfile(path):
                continue
            val = self.fs.read(path, limit=64).decode("ascii", "replace").strip()
            m = MAC_RE.search(val)
            if not m:
                continue
            mac = m.group(0).lower()
            key = ("sysfs", iface, mac)
            if key in seen:
                continue
            seen.add(key)
            out.append({"mac": mac, "iface": iface, "source": "sysfs",
                        "path": path, "extra": {}})

    def _from_android_wifi(self, out, seen):
        bases = ["/data/misc/wifi", "/persist/wifi", "/data/vendor/wifi",
                 "/data/misc/apexdata/com.android.wifi", "/data/misc/dhcp"]
        for base in bases:
            if not self.fs.isdir(base):
                continue
            for name, is_dir, obj in self.fs.listdir(base):
                if is_dir:
                    continue
                path = base.rstrip("/") + "/" + name
                data = self.fs.read_obj(obj, max_size=4 << 20)
                if not data:
                    continue
                low = name.lower()
                if low.endswith(".xml") or b"<" in data[:256]:
                    text = data.decode("utf-8", "replace")
                    for m in re.finditer(r'name="([^"]*[Mm]ac[^"]*)"[^>]*>\s*'
                                         r'([0-9a-fA-F:]{17})', text):
                        mac = m.group(2).lower()
                        key = ("xml", path, mac)
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append({"mac": mac, "iface": m.group(1),
                                    "source": "android-wifi-xml", "path": path,
                                    "extra": {}})
                    for m in MAC_RE.finditer(text):
                        mac = m.group(0).lower()
                        key = ("xml-re", path, mac)
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append({"mac": mac, "iface": None,
                                    "source": "android-wifi-xml", "path": path,
                                    "extra": {}})
                    continue
                text = data.decode("utf-8", "replace")
                for m in re.finditer(r"(?im)^\s*(mac_addr|p2p_device_address|device_name|"
                                     r"interface_macaddr|randomizedmac)\s*=\s*"
                                     r"([0-9a-fA-F:]{17})", text):
                    mac = m.group(2).lower()
                    key = ("conf", path, mac)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({"mac": mac, "iface": m.group(1),
                                "source": "android-wifi-conf", "path": path,
                                "extra": {}})
                # wpa_supplicant 里的 network{} 段：SSID -> 便于和 MAC 关联
                for m in re.finditer(r'network\s*=\s*\{(.*?)\}', text, re.S):
                    block = m.group(1)
                    mm = MAC_RE.search(block)
                    ss = re.search(r'ssid\s*=\s*"?([^"\n]+)"?', block)
                    if mm:
                        mac = mm.group(0).lower()
                        key = ("conf-net", path, mac)
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append({"mac": mac, "iface": "wlan0",
                                    "source": "android-wifi-ap-bssid", "path": path,
                                    "extra": {"ssid": ss.group(1) if ss else None,
                                              "role": "AP BSSID（关联过的热点）"}})

    def _from_registry(self, out, seen):
        hives = []
        for base_dir in ("/Windows/System32/config", "/WINDOWS/system32/config",
                         "/Windows.old/Windows/System32/config",
                         "/Users"):
            if not self.fs.isdir(base_dir):
                continue
            for path, is_dir, obj in self.fs.find_named([base_dir], ("software", "system"),
                                                        maxdepth=4):
                if is_dir:
                    continue
                hives.append((path, obj))
        if not hives:
            self.notes.append("未找到 Windows SOFTWARE/SYSTEM 注册表配置单元")
        for path, obj in hives:
            size = self.fs.size(obj)
            if size > 512 << 20:
                self.notes.append("%s 过大（%d 字节），跳过" % (path, size))
                continue
            data = self.fs.read_obj(obj, max_size=512 << 20)
            if not data or data[:4] != b"regf":
                continue
            try:
                from .regf import Hive
            except ImportError:
                from mkit.regf import Hive  # type: ignore
            try:
                hive = Hive(data, name=path.rsplit("/", 1)[-1])
            except Exception as e:
                self.notes.append("注册表打不开 %s: %s" % (path, e))
                continue
            for base_key in (
                "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
                "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed",
            ):
                try:
                    key = hive.open(base_key)
                except Exception:
                    key = None
                if key is None:
                    continue
                for sub in key.subkeys():
                    try:
                        vals = sub.values()
                    except Exception:
                        continue
                    mac_bytes = None
                    desc = ""
                    for name, (_t, v) in vals.items():
                        low = name.lower()
                        if low in ("defaultgatewaymac", "gatewaymac") and \
                                isinstance(v, (bytes, bytearray)):
                            mac_bytes = bytes(v)
                        elif low == "description" and isinstance(v, str):
                            desc = v
                    if mac_bytes and len(mac_bytes) == 6:
                        mac = ":".join("%02x" % b for b in mac_bytes)
                        key2 = ("reg", mac, desc)
                        if key2 in seen:
                            continue
                        seen.add(key2)
                        out.append({"mac": mac, "iface": desc or None,
                                    "source": "registry-networklist",
                                    "path": path + "#" + base_key,
                                    "extra": {"description": desc, "subkey": sub.name}})
            try:
                hive.close()
            except Exception:
                pass
            # 兜底：DhcpMACAddr / NetworkAddress 等值里的 MAC（ASCII 或 6 字节裸二进制）
            for m in re.finditer(rb"(?i)(?:dhcpmacaddr|networkaddress|macaddress)", data):
                seg = data[m.end():m.end() + 96]
                mm = MAC_RE.search(seg.decode("latin-1"))
                if mm:
                    mac = mm.group(0).lower()
                    if _is_zero_mac(mac):
                        continue
                    key2 = ("reg-raw", path, mac)
                    if key2 in seen:
                        continue
                    seen.add(key2)
                    out.append({"mac": mac, "iface": None,
                                "source": "registry-raw", "path": path,
                                "extra": {"value": m.group(0).decode("latin-1")}})
                    continue
                for i in range(0, min(24, max(0, len(seg) - 5))):
                    cand = seg[i:i + 6]
                    if len(cand) == 6 and all(c <= 0xFF for c in cand) and any(cand):
                        mac = ":".join("%02x" % b for b in cand)
                        if cand[0] & 1 or _is_zero_mac(mac):
                            continue
                        key2 = ("reg-bin", path, mac)
                        if key2 in seen:
                            continue
                        seen.add(key2)
                        out.append({"mac": mac, "iface": None,
                                    "source": "registry-raw-bin", "path": path,
                                    "extra": {"value": m.group(0).decode("latin-1"),
                                              "offset": m.end() + i}})
                        break

    # ---------------- 公共 ----------------
    def interfaces(self):
        """所有 MAC 来源：[{mac, iface, source, path, extra}]。"""
        out = []
        seen = set()
        self._from_sysfs(out, seen)
        self._from_android_wifi(out, seen)
        try:
            self._from_registry(out, seen)
        except Exception as e:
            self.notes.append("注册表扫描失败: %s" % e)
        if not out:
            self.notes.append("未找到 MAC：已试 /sys/class/net、/data/misc/wifi、"
                              "/persist/wifi、Windows 注册表 NetworkList")
        out.sort(key=lambda d: (d["source"], d["mac"]))
        return out
