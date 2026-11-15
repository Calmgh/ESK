# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""iOS 备份取证补充件：SIM / 蓝牙 / WiFi / 个人热点 / 账号 / 钥匙串线索 / 日历通讯录概览。

覆盖 2024/2025 美亚杯 iOS 考点：ICCID、蓝牙设备 UUID、热点密码、Apple ID 注册邮箱。
所有 plist 读写走 mkit.mobile.PlistHelper（含 NSKeyedArchiver 拆包），键名按多版本同义集合匹配。

用法：
    from mkit.mobile import IosBackup
    from mkit.iosart import IosArtifacts
    art = IosArtifacts(IosBackup(fs))
    print(art.sim(), art.bluetooth(), art.wifi(), art.hotspot())
"""
import re

from .mobile import PlistHelper, SqliteError, SqliteTriage, apple_ns_to_dt

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
ICCID_RE = re.compile(r"^\d{18,22}[A-Fa-f]?$")
ICCID_SCAN_RE = re.compile(r"\b(89\d{17,20})\b")
PHONE_RE = re.compile(r"^\+?[\d\-\s()]{5,20}$")

NAME_KEYS = ("DeviceName", "deviceName", "Name", "BRDeviceName", "kDeviceName",
             "DeviceNameString", "DisplayName")
UUID_KEYS = ("DeviceUUID", "deviceUUID", "kDeviceUUID", "UUID", "Identifier",
             "DeviceIdentifier", "BTUUID", "PairedDeviceUUID")
ADDR_KEYS = ("DeviceAddress", "deviceAddress", "BD_ADDR", "Address", "BTAddress",
             "DeviceAddressString", "MAC")
TIME_KEYS = ("LastConnectedTime", "lastConnectedTime", "LastSeenTime", "LastConnectTime",
             "LastConnected", "ConnectedTime", "LastUsedTime", "LastDisconnectTime")
CLASS_KEYS = ("ClassOfDevice", "MinorClass", "MajorClass", "ServiceClass", "DeviceClass")

WIFI_SSID_KEYS = ("SSID", "ssid", "SSIDString", "NetworkName")
WIFI_BSSID_KEYS = ("BSSID", "bssid", "LastBSSID", "BSSIDString")
WIFI_PSK_KEYS = ("PSK", "PSKData", "Password", "Passphrase", "WPAKey", "PreSharedKey",
                 "WEPKey", "Key")
WIFI_TIME_KEYS = ("LastJoined", "lastJoined", "LastAutoJoinAt", "AddedAt", "JoinedTime",
                  "LastJoinedTime")

SIM_FIELDS = {
    "iccid": ("ICCID", "Iccid", "SimUniqueIdentifier", "SimIccid", "ICC_ID", "kICCID",
              "CardIdentifier", "SimCardIdentifier"),
    "imsi": ("IMSI", "Imsi", "SimImsi", "kIMSI", "SubscriberId"),
    "phone": ("PhoneNumber", "SimPhoneNumber", "MSISDN", "MyNumber", "kPhoneNumber",
              "SubscriberNumber"),
    "carrier": ("CarrierName", "SimOperatorName", "OperatorName", "Carrier",
                "SimCarrierName", "ProviderName"),
    "mcc": ("MCC", "SimMcc", "MobileCountryCode"),
    "mnc": ("MNC", "SimMnc", "MobileNetworkCode"),
    "meid": ("MEID", "kMEID", "Meid"),
    "eid": ("EID", "kEID", "Eid", "EuiccIdentifier"),
}

HOTSPOT_PWD_KEYS = ("Password", "Passphrase", "PasswordString", "SharingPassword",
                    "HotspotPassword", "WPAKey", "PSK", "APPassword")

ACCT_USER_KEYS = ("username", "accountname", "appleid", "accountusername",
                  "emailaddress", "primaryemail", "zusername", "accountidentifier")


# ---------------- 通用工具 ----------------
def _deep(obj, path=(), depth=0):
    """yield (键路径元组, 节点)，递归展开 dict/list。"""
    if depth > 14:
        return
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _deep(v, path + (str(k),), depth + 1)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _deep(v, path + ("[%d]" % i,), depth + 1)


def _items(obj):
    """yield (键名, 值)，只要 dict 里的键值对。"""
    for _path, node in _deep(obj):
        if isinstance(node, dict):
            for k, v in node.items():
                yield str(k), v


def _text(v):
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


def _get(node, keys):
    """按同义键集合取值（大小写不敏感），返回 (键名, 值) 或 (None, None)。"""
    if not isinstance(node, dict):
        return None, None
    low = {str(k).lower(): k for k in node}
    for want in keys:
        k = low.get(want.lower())
        if k is not None:
            v = node[k]
            if v not in (None, "", b""):
                return k, v
    return None, None


def _apple_dt(v):
    if v is None or isinstance(v, str):
        return None
    try:
        f = float(v)
    except Exception:
        return None
    if f <= 0:
        return None
    return apple_ns_to_dt(f)


def _plist_obj(data):
    """read_file 可能已展开 NSKeyedArchiver；bytes 则走 PlistHelper。"""
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


def _open_db(data):
    """打开 SQLite，返回 (tri|None, 错误说明)。"""
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


class IosArtifacts:
    """iOS 备份（mkit.mobile.IosBackup）里的补充痕迹。"""

    def __init__(self, backup):
        self.bk = backup
        self.searched = []
        self.notes = []
        self._cache = {}

    # ---- plist / sqlite 取样 ----
    def _read(self, rec):
        try:
            return self.bk.read_file(rec.get("fileID") or rec.get("relativePath"))
        except Exception:
            return None

    def plists(self, patterns, domain=None, limit=300):
        """按相对路径正则取 plist，自动拆 NSKeyedArchiver。

        yield (relativePath, domain, obj)
        """
        out = []
        seen = set()
        for pat in patterns:
            for rec in self.bk.find(domain=domain, pattern=pat):
                fid = rec.get("fileID") or rec.get("relativePath")
                if fid in seen:
                    continue
                seen.add(fid)
                rel = str(rec.get("relativePath"))
                obj = _plist_obj(self._read(rec))
                if obj is None:
                    continue
                out.append((rel, str(rec.get("domain") or ""), obj))
                if len(out) >= limit:
                    return out
        return out

    def sqlites(self, patterns, domain=None, limit=6):
        out = []
        seen = set()
        for pat in patterns:
            for rec in self.bk.find(domain=domain, pattern=pat):
                fid = rec.get("fileID") or rec.get("relativePath")
                if fid in seen:
                    continue
                seen.add(fid)
                data = self._read(rec)
                if not data:
                    continue
                tri, err = _open_db(data)
                if tri is not None:
                    out.append((rec, tri))
                else:
                    self.notes.append("%s 不可读: %s" % (rec.get("relativePath"), err))
                if len(out) >= limit:
                    return out
        return out

    # ---------------- SIM ----------------
    SIM_PLISTS = [r"(?i)com\.apple\.CommCenter.*\.plist$",
                  r"(?i)com\.apple\.MobileActivation.*\.plist$",
                  r"(?i)(?<![\w.])(sim|carrier|operator|telephony)[\w.]*\.plist$",
                  r"(?i)Library/Preferences/.*(sim|carrier|comm).*\.plist$"]

    def sim(self):
        """ICCID / IMSI / 手机号 / 运营商 / MEID / EID。"""
        res = {k: None for k in SIM_FIELDS}
        src = {}
        searched = []
        plists = self.plists(self.SIM_PLISTS, limit=400)
        searched += [rel for rel, _d, _o in plists]
        for rel, dom, obj in plists:
            for key, val in _items(obj):
                for field, keys in SIM_FIELDS.items():
                    if res[field] is not None:
                        continue
                    if key.lower() not in {k.lower() for k in keys}:
                        continue
                    txt = _text(val).strip()
                    if not txt:
                        continue
                    if field == "iccid" and not ICCID_RE.match(txt):
                        if not ICCID_SCAN_RE.search(txt):
                            continue
                        txt = ICCID_SCAN_RE.search(txt).group(1)
                    if field == "phone" and not PHONE_RE.match(txt):
                        continue
                    res[field] = txt
                    src[field] = "%s:%s" % (rel, key)
        if res["iccid"] is None:
            for rel, dom, obj in plists:
                for _path, node in _deep(obj):
                    if not isinstance(node, (str, bytes)):
                        continue
                    m = ICCID_SCAN_RE.search(_text(node))
                    if m:
                        res["iccid"] = m.group(1)
                        src["iccid"] = rel + ":(字符串扫描)"
                        break
                if res["iccid"]:
                    break
        if res["iccid"] is None:
            info = {}
            for getter in ("info_plist", "info", "device_info"):
                fn = getattr(self.bk, getter, None)
                if not callable(fn):
                    continue
                try:
                    info = fn() or {}
                except Exception:
                    info = {}
                if isinstance(info, dict) and info:
                    break
            if not res.get("imei"):
                for k in ("IMEI", "imei", "Meid", "MEID"):
                    if info.get(k):
                        res["imei"] = info[k]
                        src["imei"] = "Info.plist:%s" % k
                        break
            searched.append("Info.plist")
            res["note"] = "未找到（备份默认不含 SIM 信息，需从设备或全备份获取）"
            self.notes.append("sim(): " + res["note"])
        res["sources"] = src
        res["searched"] = sorted(set(searched))
        res["patterns"] = list(self.SIM_PLISTS)
        return res

    # ---------------- 蓝牙 ----------------
    def bluetooth(self):
        """已配对蓝牙设备：名称 / UUID / 地址 / 最后连接时间。"""
        plists = self.plists([r"(?i)com\.apple\.MobileBluetooth.*\.plist$",
                              r"(?i)MobileBluetooth.*ledevices.*\.plist$"],
                             limit=60)
        out, seen = [], set()
        for rel, dom, obj in plists:
            self.searched.append(rel)
            for path, node in _deep(obj):
                if not isinstance(node, dict):
                    continue
                k_name, v_name = _get(node, NAME_KEYS)
                k_uuid, v_uuid = _get(node, UUID_KEYS)
                k_addr, v_addr = _get(node, ADDR_KEYS)
                k_time, v_time = _get(node, TIME_KEYS)
                if not (k_name or k_uuid):
                    continue
                name = _text(v_name)
                uuid = _text(v_uuid)
                addr = _text(v_addr)
                if not (name or uuid or addr):
                    continue
                key = (uuid or addr or name).lower()
                if key in seen:
                    continue
                seen.add(key)
                dt = _apple_dt(v_time)
                k_class, v_class = _get(node, CLASS_KEYS)
                out.append(dict(
                    name=name or None, uuid=uuid or None, address=addr or None,
                    class_of_device=v_class if k_class else None,
                    last_connected=dt.isoformat() if dt else None,
                    last_connected_raw=v_time if k_time else None,
                    plist=rel, domain=dom, keypath="/".join(path),
                    matched_keys=[k for k in (k_name, k_uuid, k_addr, k_time) if k],
                ))
        if not out:
            self.notes.append("bluetooth(): 未找到配对设备；已搜索 %s"
                              % (", ".join(sorted(set(self.searched))) or "无 MobileBluetooth plist"))
        out.sort(key=lambda r: (r.get("last_connected") is None, r.get("last_connected") or ""))
        return out

    # ---------------- WiFi ----------------
    def wifi(self):
        """已知 WiFi 网络：SSID / BSSID / PSK / 最后加入时间。"""
        plists = self.plists([r"(?i)com\.apple\.wifi.*\.plist$",
                              r"(?i)com\.apple\.AirPort.*\.plist$",
                              r"(?i)known-networks.*\.plist$"], limit=40)
        out, seen = [], set()
        for rel, dom, obj in plists:
            self.searched.append(rel)
            for path, node in _deep(obj):
                if not isinstance(node, dict):
                    continue
                k_ssid, v_ssid = _get(node, WIFI_SSID_KEYS)
                if not k_ssid:
                    continue
                ssid = _text(v_ssid)
                if not ssid:
                    continue
                k_bssid, v_bssid = _get(node, WIFI_BSSID_KEYS)
                k_psk, v_psk = _get(node, WIFI_PSK_KEYS)
                k_time, v_time = _get(node, WIFI_TIME_KEYS)
                psk, psk_note = None, None
                if k_psk:
                    psk, psk_note = _psk_text(v_psk)
                key = (ssid + "|" + _text(v_bssid)).lower()
                if key in seen:
                    continue
                seen.add(key)
                dt = _apple_dt(v_time)
                out.append(dict(
                    ssid=ssid, bssid=_text(v_bssid) or None,
                    psk=psk, psk_note=psk_note,
                    last_joined=dt.isoformat() if dt else None,
                    last_joined_raw=v_time if k_time else None,
                    plist=rel, domain=dom, keypath="/".join(path),
                ))
        if not out:
            self.notes.append("wifi(): 未找到已知网络；已搜索 %s"
                              % (", ".join(sorted(set(self.searched))) or "无 wifi plist"))
        return out

    # ---------------- 个人热点 ----------------
    def hotspot(self):
        """个人热点密码（MobileInternetSharing / 相关 plist）。"""
        res = dict(password=None, source=None, plist=None, keypath=None, searched=[])
        plists = self.plists([r"(?i)MobileInternetSharing.*\.plist$",
                              r"(?i).*hotspot.*\.plist$",
                              r"(?i)com\.apple\.PersonalHotspot.*\.plist$",
                              r"(?i)com\.apple\.wifid.*\.plist$"], limit=40)
        best = None
        for rel, dom, obj in plists:
            self.searched.append(rel)
            res["searched"].append(rel)
            for path, node in _deep(obj):
                if not isinstance(node, dict):
                    continue
                for key, val in node.items():
                    if str(key).lower() not in {k.lower() for k in HOTSPOT_PWD_KEYS}:
                        continue
                    txt = _text(val).strip()
                    if not txt:
                        continue
                    if len(txt) < 8:          # WPA 最短 8 位
                        continue
                    score = 0
                    jp = "/".join(path).lower()
                    if "hostap" in jp or "sharing" in jp or "hotspot" in jp:
                        score += 2
                    if str(key).lower() in ("password", "passphrase", "sharingpassword"):
                        score += 1
                    cand = dict(password=txt, source="%s:%s" % (rel, key),
                                plist=rel, keypath="/".join(path + (str(key),)),
                                score=score)
                    if best is None or cand["score"] > best["score"]:
                        best = cand
        if best is None:
            self.notes.append("hotspot(): 未找到热点密码；已搜索 %s"
                              % (", ".join(res["searched"]) or "无相关 plist"))
            res["note"] = "未找到（可能未开启过个人热点，或被加密备份保护）"
            return res
        res.update(password=best["password"], source=best["source"],
                   plist=best["plist"], keypath=best["keypath"])
        return res

    # ---------------- 账号 ----------------
    def accounts(self):
        """Apple ID / iCloud / 三方账号：Accounts3.sqlite + accountsd plist。"""
        out, seen = [], set()
        for rec, tri in self.sqlites([r"(?i)Accounts3\.sqlite$", r"(?i)Accounts\.sqlite$"]):
            self.searched.append(str(rec.get("relativePath")))
            tname = None
            for t in ("ZACCOUNT", "Z_ACCOUNT", "account", "accounts"):
                if t in tri.tables():
                    tname = t
                    break
            if not tname:
                self.notes.append("%s 无 ZACCOUNT 表" % rec.get("relativePath"))
                continue
            cols = tri.schema(tname)
            low = {c.lower(): c for c in cols}
            c_user = None
            for cand in ("zusername", "username", "zaccountname", "accountname"):
                if cand in low:
                    c_user = low[cand]
                    break
            c_desc = None
            for cand in ("zaccountdescription", "zdescription", "description", "zaccounttype"):
                if cand in low:
                    c_desc = low[cand]
                    break
            c_bundle = None
            for cand in ("zowningbundleid", "zbundleid"):
                if cand in low:
                    c_bundle = low[cand]
                    break
            c_auth = None
            for cand in ("zauthenticated", "zactive", "zvisible"):
                if cand in low:
                    c_auth = low[cand]
                    break
            for r in tri.dicts('select * from "%s" limit 300' % tname, limit=300):
                user = _text(r.get(c_user)) if c_user else ""
                desc = _text(r.get(c_desc)) if c_desc else ""
                if not user and not desc:
                    continue
                key = (user or desc).lower()
                if key in seen:
                    continue
                seen.add(key)
                out.append(dict(type=desc or "account", username=user or None,
                                bundle=_text(r.get(c_bundle)) if c_bundle else None,
                                active=r.get(c_auth) if c_auth else None,
                                source="%s:%s" % (rec.get("relativePath"), tname),
                                kind="sqlite"))
        for rel, dom, obj in self.plists([r"(?i)com\.apple\.account.*\.plist$",
                                          r"(?i)Accounts.*\.plist$",
                                          r"(?i)com\.apple\.mobilemail.*\.plist$"], limit=80):
            self.searched.append(rel)
            for key, val in _items(obj):
                if not isinstance(val, str) or not EMAIL_RE.match(val.strip()):
                    continue
                if key.lower() not in ACCT_USER_KEYS:
                    continue
                txt = val.strip()
                if txt.lower() in seen:
                    continue
                seen.add(txt.lower())
                out.append(dict(type=key, username=txt, bundle=None, active=None,
                                source="%s:%s" % (rel, key), kind="plist"))
        if not out:
            self.notes.append("accounts(): 未找到账号；已搜索 %s"
                              % (", ".join(sorted(set(self.searched))) or "无 Accounts3.sqlite"))
        return out

    # ---------------- 钥匙串线索 ----------------
    def keychain_hint(self):
        """Keychain-backup.plist 里可读的服务名/账号名（不解密）。"""
        out, seen = [], set()
        for rel, dom, obj in self.plists([r"(?i)Keychain.*\.plist$",
                                          r"(?i)keychain-backup\.plist$"], limit=20):
            self.searched.append(rel)
            for path, node in _deep(obj):
                if not isinstance(node, dict):
                    continue
                k_s, v_s = _get(node, ("svce", "service", "Svc", "ServiceName"))
                k_a, v_a = _get(node, ("acct", "account", "Acct", "AccountName"))
                if k_s or k_a:
                    svce = _text(v_s)
                    acct = _text(v_a)
                    key = (svce + "|" + acct).lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(dict(service=svce or None, account=acct or None,
                                    plist=rel, keypath="/".join(path)))
        if not out:
            for rel, dom, obj in self.plists([r"(?i)Keychain.*\.plist$"], limit=5):
                for path, node in _deep(obj):
                    if isinstance(node, dict):
                        for k in node:
                            ks = str(k)
                            if re.match(r"^([a-z0-9\-]+\.){2,}", ks) or ks in (
                                    "AirPort", "WiFi", "Internet", "Passpoint"):
                                kk = ks.lower()
                                if kk in seen:
                                    continue
                                seen.add(kk)
                                out.append(dict(service=ks, account=None,
                                                plist=rel, keypath="/".join(path)))
        if not out:
            self.notes.append("keychain_hint(): 未找到可读服务名；已搜索 %s"
                              % (", ".join(sorted(set(self.searched))) or "无 Keychain plist"))
        return out

    # ---------------- 日历 / 通讯录 ----------------
    def calendar_contacts(self):
        """Calendar.sqlitedb / AddressBook.sqlitedb 计数概览。"""
        res = dict(calendar=None, contacts=None, searched=[], notes=[])
        for rec, tri in self.sqlites([r"(?i)Calendar\.sqlitedb$"], limit=3):
            rel = str(rec.get("relativePath"))
            self.searched.append(rel)
            tables = tri.tables()
            info = dict(path=rel, tables=len(tables), counts={})
            for name, cnt in tables.items():
                info["counts"][name] = cnt
            for key in ("CalendarItem", "ZCALENDARITEM", "Event", "ZEVENT"):
                if key in tables:
                    info["events"] = tables[key]
                    break
            if "calendar" not in info:
                info["calendars"] = sum(tables.get(t, 0)
                                        for t in ("Calendar", "ZCALENDAR") if t in tables)
            cal = tri.dicts("select title, rowid from Calendar limit 50") if "Calendar" in tables else []
            if cal:
                info["calendar_titles"] = [_text(c.get("title")) for c in cal]
            res["calendar"] = info
        for rec, tri in self.sqlites([r"(?i)AddressBook\.sqlitedb$"], limit=3):
            rel = str(rec.get("relativePath"))
            self.searched.append(rel)
            tables = tri.tables()
            info = dict(path=rel, tables=len(tables), counts={})
            for name, cnt in tables.items():
                info["counts"][name] = cnt
            for key in ("ABPerson", "ZABPERSON"):
                if key in tables:
                    info["people"] = tables[key]
                    break
            for key in ("ABMultiValue",):
                if key in tables:
                    info["multi_values"] = tables[key]
                    break
            res["contacts"] = info
        if res["calendar"] is None:
            res["notes"].append("calendar: 未找到 Calendar.sqlitedb")
        if res["contacts"] is None:
            res["notes"].append("contacts: 未找到 AddressBook.sqlitedb")
        res["searched"] = sorted(set(self.searched))
        return res

    # ---------------- 汇总 ----------------
    def report(self):
        return dict(sim=self.sim(), bluetooth=self.bluetooth(), wifi=self.wifi(),
                    hotspot=self.hotspot(), accounts=self.accounts(),
                    keychain_hint=self.keychain_hint(),
                    calendar_contacts=self.calendar_contacts(),
                    notes=self.notes)


def _psk_text(v):
    """PSK 可能是明文 / NSData / 钥匙串引用。返回 (明文, 说明)。"""
    if isinstance(v, str):
        s = v.strip()
        if len(s) >= 8:
            return s, None
        return None, "值过短(%r)，可能不是 PSK" % s
    if isinstance(v, (bytes, bytearray)):
        raw = bytes(v)
        try:
            s = raw.replace(b"\x00", b"").decode("utf-8").strip()
            if s and all(32 <= ord(c) < 127 for c in s) and len(s) >= 8:
                return s, None
        except Exception:
            pass
        return None, "二进制(%d 字节, hex=%s)，通常为钥匙串引用" % (
            len(raw), raw[:16].hex())
    return None, "未知类型 %s" % type(v).__name__


__all__ = ["IosArtifacts"]

