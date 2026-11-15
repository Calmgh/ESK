# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""Windows 账户与软件取证补充：SID、软件密钥、远程工具、DHCP、时区。

对应真题：
  2018/2019/2024 —— 用户 SID / RID（`用户"Lily"的 SID 是什么`）
  2021 —— `Microsoft Office 2007 的密钥`、`Windows 产品标识符`、`TeamViewer ID`
  2024 —— `DHCP 分配的 IP`、`TeamViewer ClientID`、`用户 DESKTOP-xxx 的 SID`
  2020 —— `FTK Imager.exe 的父应用程序`、`预设安装的浏览器`
"""
import datetime
import re
import struct


class WindowsAccounts:
    """从 SAM + SOFTWARE 取 SID/RID/账户状态。"""

    def __init__(self, sam_hive=None, software_hive=None, system_hive=None):
        self.sam = sam_hive
        self.software = software_hive
        self.system = system_hive
        self.notes = []

    # ---- SID ----
    def machine_sid(self):
        r"""SAM\Domains\Account 的 V 值里含机器 SID。"""
        try:
            k = self.sam.open(r"SAM\Domains\Account")
            if not k:
                return None
            v = k.value("V")
            if not v:
                return None
            blob = v[1] if isinstance(v, tuple) else v
            if not isinstance(blob, (bytes, bytearray)):
                return None
            sid = self._find_sid(blob)
            return sid
        except Exception as e:
            self.notes.append(f"machine_sid 失败: {e}")
            return None

    @staticmethod
    def _find_sid(blob):
        """在二进制里找 S-1-5-21-x-y-z（结构: rev, count, authority[6], subauth...)"""
        for i in range(len(blob) - 8):
            if blob[i] != 1:
                continue
            cnt = blob[i + 1]
            if not 3 <= cnt <= 15:
                continue
            auth = int.from_bytes(blob[i + 2:i + 8], "big")
            if auth != 5:
                continue
            need = 8 + 4 * cnt
            if i + need > len(blob):
                continue
            subs = struct.unpack_from("<%dI" % cnt, blob, i + 8)
            if subs and subs[0] == 21:
                return "S-" + "-".join(str(x) for x in (1, auth) + tuple(subs))
        return None

    def users(self):
        """返回 [{name, rid, sid, logon_count, last_logon, disabled, full_sid}]"""
        out = []
        try:
            names = self.sam.open(r"SAM\Domains\Account\Users\Names")
            users = self.sam.open(r"SAM\Domains\Account\Users")
        except Exception as e:
            self.notes.append(f"打开 Users 失败: {e}")
            return out
        if not users:
            return out
        name_map = {}
        if names:
            for sub in names.subkeys():
                try:
                    val = sub.value("")
                    rid = None
                    if val:
                        raw = val[1]
                        if isinstance(raw, int):
                            rid = raw
                        elif raw in (None, b"", ""):
                            raw = None
                        elif isinstance(raw, (bytes, bytearray)) and len(raw) >= 4:
                            rid = struct.unpack_from("<I", raw, 0)[0]
                    if rid is None and val and isinstance(val[0], int) and val[0] > 0:
                        rid = val[0]
                    if rid is None and sub.values():
                        for nm, (vt, vv) in sub.values().items():
                            if isinstance(vv, int) and vt in (3, 4):
                                rid = vv
                                break
                    name_map[sub.name] = rid
                except Exception:
                    continue
        msid = self.machine_sid()
        for sub in users.subkeys():
            if not re.fullmatch(r"[0-9A-Fa-f]{8}", sub.name):
                continue
            rid = int(sub.name, 16)
            name = None
            for n, r in name_map.items():
                if r == rid:
                    name = n
                    break
            rec = dict(rid=rid, name=name,
                       sid=f"{msid}-{rid}" if msid else f"S-1-5-21-?-{rid}",
                       logon_count=None, last_logon=None, bad_pw=None, disabled=None)
            try:
                fval = sub.value("F")
                if fval:
                    f = fval[1]
                    rec["last_logon"] = _filetime(struct.unpack_from("<Q", f, 8)[0])
                    rec["last_pw_set"] = _filetime(struct.unpack_from("<Q", f, 0x18)[0])
                    rec["acct_expiry"] = _filetime(struct.unpack_from("<Q", f, 0x20)[0])
                    rec["last_bad_pw"] = _filetime(struct.unpack_from("<Q", f, 0x28)[0])
                    rec["bad_pw"] = struct.unpack_from("<H", f, 0x40)[0]
                    rec["logon_count"] = struct.unpack_from("<H", f, 0x42)[0]
            except Exception:
                pass
            try:
                uac = sub.value("V")
                if uac:
                    v = uac[1]
                    if isinstance(v, (bytes, bytearray)) and len(v) > 0x38:
                        flags = struct.unpack_from("<H", v, 0x38)[0]
                        rec["disabled"] = bool(flags & 0x0002)
            except Exception:
                pass
            out.append(rec)
        return out

    def find_user(self, keyword):
        for u in self.users():
            if keyword.lower() in (u.get("name") or "").lower():
                return u
        return None

    # ---- Windows 产品标识 / 安装信息 ----
    def product_id(self):
        """ProductId（20 位，去掉连字符即真题答案格式）"""
        try:
            k = self.software.open(r"Microsoft\Windows NT\CurrentVersion")
            if not k:
                return None
            v = k.values()
            pid = v.get("ProductId") or v.get("ProductID")
            return pid[1] if pid else None
        except Exception:
            return None

    def install_date(self):
        try:
            k = self.software.open(r"Microsoft\Windows NT\CurrentVersion")
            v = k.values().get("InstallDate")
            if v:
                return datetime.datetime.fromtimestamp(v[1], datetime.timezone.utc)
        except Exception:
            pass
        return None

    def timezone(self):
        """时区：SYSTEM\ControlSet00x\Control\TimeZoneInformation"""
        for cs in ("ControlSet001", "CurrentControlSet", "ControlSet002"):
            try:
                k = self.system.open(cs + r"\Control\TimeZoneInformation")
                if k:
                    v = k.values()
                    name = v.get("TimeZoneKeyName") or v.get("StandardName")
                    bias = v.get("ActiveTimeBias") or v.get("Bias")
                    out = {}
                    if name:
                        val = name[1]
                        out["name"] = val.decode("utf-16le", "ignore").rstrip("\x00") if isinstance(val, bytes) else val
                    if bias:
                        bv = bias[1]
                        if isinstance(bv, int) and bv > 0x7FFFFFFF:
                            bv -= 0x100000000
                        out["bias_minutes"] = bv
                        out["utc_offset"] = -bv / 60
                    return out
            except Exception:
                continue
        return {}

    def dhcp_ip(self):
        r"""SYSTEM\...\Services\Tcpip\Parameters\Interfaces\* 取 DHCP 分配的 IP / 网关 / MAC。"""
        out = []
        for cs in ("ControlSet001", "CurrentControlSet"):
            try:
                k = self.system.open(cs + r"\Services\Tcpip\Parameters\Interfaces")
                if not k:
                    continue
                for sub in k.subkeys():
                    v = sub.values()
                    get = lambda n: (v[n][1] if n in v else None)
                    rec = dict(interface=sub.name,
                               dhcp_ip=get("DhcpIPAddress"),
                               ip=get("IPAddress"),
                               gateway=get("DhcpDefaultGateway") or get("DefaultGateway"),
                               dhcp_server=get("DhcpServer"),
                               mac=get("DhcpHardwareAddress") or get("NetworkAddress"),
                               subnet=get("DhcpSubnetMask"))
                    if rec["dhcp_ip"] or rec["ip"]:
                        out.append(rec)
                if out:
                    break
            except Exception:
                continue
        return out

    def wifi_profiles(self):
        r"""SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles：SSID/首次最后连接。"""
        out = []
        try:
            k = self.software.open(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
            if not k:
                return out
            for sub in k.subkeys():
                v = sub.values()
                name = v.get("ProfileName") or v.get("Description")
                ssid = v.get("ProfileName")
                rec = dict(profile=sub.name)
                if ssid:
                    val = ssid[1]
                    rec["ssid"] = val.decode("utf-16le", "ignore").rstrip("\x00") if isinstance(val, bytes) else val
                for dt_key, label in (("DateCreated", "created"), ("DateLastConnected", "last_connected")):
                    if dt_key in v:
                        raw = v[dt_key][1]
                        if isinstance(raw, (bytes, bytearray)) and len(raw) >= 16:
                            rec[label] = _systemtime(raw)
                out.append(rec)
        except Exception as e:
            self.notes.append(f"wifi_profiles 失败: {e}")
        return out


def _filetime(v):
    if not v:
        return None
    try:
        return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + \
            datetime.timedelta(microseconds=int(v) / 10)
    except Exception:
        return None


def _systemtime(raw):
    """SYSTEMTIME: year,month,dow,day,hour,min,sec,ms (各 2 字节 LE)"""
    try:
        y, mo, _, d, h, mi, s, ms = struct.unpack_from("<8H", raw, 0)
        return datetime.datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=datetime.timezone.utc)
    except Exception:
        return None


class SoftwareKeys:
    """软件许可证/密钥：Office、Windows、第三方。"""

    OFFICE_PATHS = [
        r"Microsoft\Office\12.0\Registration",
        r"Microsoft\Office\14.0\Registration",
        r"Microsoft\Office\15.0\Registration",
        r"Microsoft\Office\16.0\Registration",
    ]

    def __init__(self, software_hive):
        self.software = software_hive
        self.notes = []

    def office_keys(self):
        out = []
        for p in self.OFFICE_PATHS:
            try:
                k = self.software.open(p)
                if not k:
                    continue
                for sub in k.subkeys():
                    v = sub.values()
                    rec = dict(product=sub.name.split("\\")[-1], path=p)
                    for key, label in (("DigitalProductId", "dpid"), ("ProductID", "product_id"),
                                       ("ProductName", "product_name")):
                        if key in v:
                            val = v[key][1]
                            if isinstance(val, bytes):
                                rec[label] = val
                            else:
                                rec[label] = val
                    if "dpid" in rec and isinstance(rec["dpid"], (bytes, bytearray)):
                        rec["key"] = decode_office_key(rec["dpid"])
                    out.append(rec)
            except Exception:
                continue
        return out

    def windows_key(self):
        """Windows 数字产品密钥（从 DigitalProductId 解 25 位）"""
        try:
            k = self.software.open(r"Microsoft\Windows NT\CurrentVersion")
            v = k.values()
            if "DigitalProductId" in v:
                return decode_windows_key(v["DigitalProductId"][1])
        except Exception:
            pass
        return None

    def generic(self, keyword):
        """在 SOFTWARE 里搜名称含关键词的键，返回其值（用于第三方软件序列号）。"""
        hits = []
        stack = [self.software.root()]
        while stack and len(hits) < 50:
            key = stack.pop()
            try:
                if keyword.lower() in key.name.lower():
                    hits.append(dict(path=key.path, values={k: v[1] for k, v in key.values().items()}))
                stack.extend(key.subkeys())
            except Exception:
                continue
        return hits


# ---------------- Office / Windows 密钥解码 ----------------
OFFICE_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def decode_office_key(dpid):
    """Office 2007/2010 DigitalProductId -> 25 位密钥（含校验位）。"""
    try:
        b = bytearray(dpid)
        if len(b) < 0x68:
            return None
        offset = 0x34 if len(b) > 0x66 else 0x34
        raw = b[offset:offset + 15][::-1]
        digits = []
        for i in range(15):
            digits.append(raw[i] & 0x1F)
        key = ""
        for i in range(25):
            carry = 0
            for j in range(14, -1, -1):
                cur = (digits[j] << 8) | carry
                digits[j] = cur // 24
                carry = cur % 24
            key += OFFICE_B64[carry] if i < 24 else ""
            if i == 4 or i == 9 or i == 14 or i == 19:
                key += "-"
        return key.rstrip("-")
    except Exception:
        return None


def decode_windows_key(dpid):
    """Windows 8+ DigitalProductId -> XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"""
    try:
        b = bytearray(dpid)
        key_chars = "BCDFGHJKMPQRTVWXY2346789"
        key = []
        last = 0
        if len(b) < 66:
            return None
        for i in range(25):
            cur = 0
            for j in range(14, -1, -1):
                cur = (cur << 8) + b[66 - 1 - j + 52 - 52 + 52 - 52] if False else cur
            # 标准实现：从 52 开始的 15 字节
            cur = 0
            for j in range(14, -1, -1):
                idx = 52 + j
                if idx >= len(b):
                    return None
                cur = (cur << 8) + b[idx]
                b[idx] = cur // 24
                cur %= 24
            last = cur
            key.insert(0, key_chars[cur])
        if 0 <= last < len(key):
            key[last] = "N"
        s = "".join(key)
        return "-".join(s[i:i + 5] for i in range(0, 25, 5))
    except Exception:
        return None


class RemoteTools:
    """TeamViewer / AnyDesk / RDP 的 ID 与连接记录。"""

    def __init__(self, fs=None, software_hive=None):
        self.fs = fs
        self.software = software_hive
        self.notes = []

    def teamviewer_id(self):
        r"""TeamViewer ID：注册表 Software\TeamViewer 的 ClientID 或 %APPDATA%\TeamViewer\...\TeamViewer15_Logfile.log"""
        out = {}
        try:
            k = self.software.open(r"TeamViewer")
            if k:
                v = k.values()
                for name in ("ClientID", "ClientIDString"):
                    if name in v:
                        out[name] = v[name][1]
        except Exception:
            pass
        if self.fs:
            for p in ("/Program Files/TeamViewer/Connections.txt",
                      "/Program Files (x86)/TeamViewer/Connections.txt"):
                try:
                    d = self.fs.read_data(self.fs.lookup(p))
                    if d:
                        out["connections_txt"] = d.decode("utf-8", "replace")[:2000]
                except Exception:
                    continue
        return out

    def teamviewer_logs(self, fs):
        """从日志里抽 ID 与连接对端。"""
        hits = []
        try:
            for path, ino in fs.walk("/"):
                if re.search(r"TeamViewer.*\.log$", path, re.I):
                    try:
                        d = fs.read_data(ino).decode("utf-8", "replace")
                    except Exception:
                        continue
                    ids = re.findall(r"ID\s*[:=]\s*(\d{9,12})", d)
                    if ids:
                        hits.append(dict(path=path, ids=sorted(set(ids))[:20]))
        except Exception:
            pass
        return hits

    def anydesk_id(self):
        out = {}
        try:
            k = self.software.open(r"AnyDesk")
            if k:
                out.update({n: v[1] for n, v in k.values().items()})
        except Exception:
            pass
        return out

    def rdp_targets(self, ntuser_hive):
        """Terminal Server Client MRU：远程连接过的主机。"""
        out = []
        try:
            k = ntuser_hive.open(r"Software\Microsoft\Terminal Server Client\Servers")
            if k:
                for sub in k.subkeys():
                    v = sub.values()
                    out.append(dict(host=sub.name,
                                    username=(v.get("UsernameHint") or (None, None))[1]))
            d = ntuser_hive.open(r"Software\Microsoft\Terminal Server Client\Default")
            if d:
                for name, (vt, val) in d.values().items():
                    if name.startswith("MRU"):
                        out.append(dict(mru=name, host=val))
        except Exception:
            pass
        return out


class Browsers:
    """预设/最常用浏览器判定（真题多次问"预设浏览器""最常用浏览器"）。"""

    def __init__(self, fs=None, ntuser_hive=None):
        self.fs = fs
        self.ntuser = ntuser_hive

    def default_browser(self):
        if not self.ntuser:
            return None
        try:
            k = self.ntuser.open(r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice")
            if k:
                v = k.values()
                if "ProgId" in v:
                    return v["ProgId"][1]
        except Exception:
            pass
        return None

    def usage_counts(self, fs):
        """用 SRUM/UserAssist/各浏览器 History 的行数做"最常用"判据。"""
        out = {}
        for path, ino in fs.walk("/Users"):
            if path.endswith("/History") and ("Chrome" in path or "Edge" in path or "Brave" in path):
                try:
                    from .mobile import SqliteTriage
                    t = SqliteTriage(fs.read_data(ino))
                    rows = t.rows("select count(*) from urls")
                    out.setdefault(path.split("/")[-3], rows[0][0] if rows else 0)
                except Exception:
                    continue
            if path.endswith("/places.sqlite"):
                try:
                    from .mobile import SqliteTriage
                    t = SqliteTriage(fs.read_data(ino))
                    rows = t.rows("select count(*) from moz_places")
                    out["Firefox"] = rows[0][0] if rows else 0
                except Exception:
                    continue
        return out
