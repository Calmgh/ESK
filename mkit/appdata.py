# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""mkit.appdata —— 应用级数据取证（纯标准库；pycryptodome 可选）。

目标：给定一个手机镜像/目录，回答“某个 App 里的某条信息是什么”。
本模块只做**应用数据层**：包名 → 数据目录 → 库文件 → 结构化记录。

组成
  APPS / IOS_APPS   应用画像表：包名或 iOS bundle -> 中文名、类型、关键库文件
  FsView            文件系统薄封装：同时吃 mkit.ext4.Ext4 / mkit.ntfs.NTFS /
                    测试用 DirFS；路径级访问 + inode 快路径
  AppProfiler       installed() / locate() / profile() / auto_scan()
  ChatApp           WhatsApp/Telegram/Signal/LINE/QQ/WeChat 统一消息与群组
  BookingApp        Agoda/Booking/Airbnb/携程 订单
  BankApp           汇丰/恒生/中银/PayPal/支付宝 交易流水
  NotesApp          iOS Notes / Keep / 华为备忘录 / 小米便签
  MapApp            地图与站点（含 nearest() 按坐标找最近记录）
  EbookApp          书库 + 标注/高亮
  CalendarApp       日历库与 .ics
  ShoppingApp       电商/快递订单

约定
  * 所有 SQLite 读取都走 mkit.mobile.SqliteTriage（自研格式解析器，无 sqlite3）；
    没有 .con 属性，SQL 子集不支持 `GROUP BY 1` 这类序号，一律写列名。
  * 时间字段统一返回 (datetime, raw)：norm_time() 兼容 毫秒/秒/Apple 2001 纳秒/
    Chrome 1601 微秒/字符串；记录里分别落在 "time" 与 "time_raw"。
  * 任何方法在“该 App 不存在”时返回 []，并把原因追加到 self.notes。
"""
import datetime
import plistlib
import re
import xml.etree.ElementTree as ET

from .mobile import SqliteTriage, PlistHelper, SqliteError, apple_ns_to_dt, chrome_time
from .ext4 import Ext4
from .ntfs import NTFS
from .regf import Hive
from .stego import exif_all

__all__ = [
    "APPS", "IOS_APPS", "TYPE_NAMES", "FsView", "AppProfiler", "AppKit",
    "ChatApp", "BookingApp", "BankApp", "NotesApp", "MapApp", "EbookApp",
    "CalendarApp", "ShoppingApp", "auto_scan", "norm_time", "open_fs",
    "installed_from_hive",
]

TZ = datetime.timezone(datetime.timedelta(hours=8))
_APPLE_BASE = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
_CHROME_BASE = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

TYPE_NAMES = {
    "chat": "社交", "social": "社交", "booking": "订房", "bank": "银行",
    "notes": "笔记", "map": "地图", "ebook": "阅读", "calendar": "日历",
    "shopping": "电商", "browser": "浏览器", "email": "邮件", "cloud": "云盘",
    "wallet": "钱包", "travel": "出行", "system": "系统", "security": "安全/工具",
    "ime": "输入法", "filemanager": "文件管理", "media": "媒体", "unknown": "未知",
}

# ==========================================================================
# 应用画像表
#   conf: high = 包名/库名可靠；guess = 按厂商习惯推定（结论里会标出）
# ==========================================================================
APPS = {
    # ---------------- 社交 / 聊天 ----------------
    "com.whatsapp": {"name": "WhatsApp", "kind": "chat", "conf": "high",
                     "dbs": ["databases/msgstore.db", "msgstore.db"]},
    "com.tencent.mm": {"name": "微信", "kind": "chat", "conf": "high",
                       "dbs": ["databases/EnMicroMsg.db", "databases/MicroMsg.db",
                               "databases/wxFileIndex.db"]},
    "com.tencent.mobileqq": {"name": "QQ", "kind": "chat", "conf": "high",
                             "dbs": ["databases/QQ.db", "databases/qq.db"]},
    "org.telegram.messenger": {"name": "Telegram", "kind": "chat", "conf": "high",
                               "dbs": ["files/cache4.db", "databases/cache4.db"]},
    "org.thoughtcrime.securesms": {"name": "Signal", "kind": "chat", "conf": "high",
                                   "dbs": ["databases/signal.db"]},
    "org.whispersystems.signal": {"name": "Signal", "kind": "chat", "conf": "high"},
    "jp.naver.line.android": {"name": "LINE", "kind": "chat", "conf": "high",
                              "dbs": ["databases/naver_line"]},
    "com.facebook.orca": {"name": "Messenger", "kind": "chat", "conf": "high"},
    "com.loudtalks": {"name": "Zello（对讲）", "kind": "chat", "conf": "high"},
    "com.instagram.android": {"name": "Instagram", "kind": "social", "conf": "high"},
    "com.facebook.katana": {"name": "Facebook", "kind": "social", "conf": "high"},
    "com.twitter.android": {"name": "X / Twitter", "kind": "social", "conf": "high"},
    "com.sina.weibo": {"name": "微博", "kind": "social", "conf": "high"},
    "com.ss.android.ugc.aweme": {"name": "抖音", "kind": "social", "conf": "high"},
    "com.zhiliaoapp.musically": {"name": "TikTok", "kind": "social", "conf": "high"},
    # ---------------- 订房 / 出行 ----------------
    "com.booking": {"name": "Booking.com", "kind": "booking", "conf": "high"},
    "com.airbnb.android": {"name": "Airbnb", "kind": "booking", "conf": "high"},
    "com.agoda.mobile": {"name": "Agoda", "kind": "booking", "conf": "guess"},
    "ctrip.android.view": {"name": "携程旅行", "kind": "travel", "conf": "high"},
    "ctrip.english": {"name": "Trip.com", "kind": "travel", "conf": "guess"},
    "com.ubercab": {"name": "Uber", "kind": "travel", "conf": "high"},
    "com.sdu.didi.psnger": {"name": "滴滴出行", "kind": "travel", "conf": "high"},
    # ---------------- 银行 / 支付 / 钱包 ----------------
    "com.paypal.android.p2pmobile": {"name": "PayPal", "kind": "bank", "conf": "high"},
    "com.eg.android.AlipayGphone": {"name": "支付宝", "kind": "bank", "conf": "high"},
    "io.metamask": {"name": "MetaMask", "kind": "wallet", "conf": "high"},
    "com.wallet.crypto.trustapp": {"name": "Trust Wallet", "kind": "wallet", "conf": "high"},
    "im.token.app": {"name": "imToken", "kind": "wallet", "conf": "high"},
    "com.bitkeep.wallet": {"name": "BitKeep", "kind": "wallet", "conf": "guess"},
    "com.mymoney": {"name": "随手记（记账）", "kind": "bank", "conf": "guess"},
    # ---------------- 地图 / 出行线路 ----------------
    "com.google.android.apps.maps": {"name": "Google 地图", "kind": "map", "conf": "high"},
    "com.autonavi.minimap": {"name": "高德地图", "kind": "map", "conf": "high"},
    "com.baidu.BaiduMap": {"name": "百度地图", "kind": "map", "conf": "high"},
    "com.kmb.app1933": {"name": "KMB 1933（九巴）", "kind": "map", "conf": "guess"},
    # ---------------- 笔记 ----------------
    "com.google.android.keep": {"name": "Google Keep", "kind": "notes", "conf": "high"},
    "com.miui.notes": {"name": "小米便签", "kind": "notes", "conf": "high"},
    "com.huawei.notepad": {"name": "华为备忘录", "kind": "notes", "conf": "high"},
    "com.mediatek.notebook": {"name": "MTK 记事本", "kind": "notes", "conf": "high",
                              "dbs": ["databases/note_pad.db"]},
    "com.yulong.android.notes": {"name": "酷派便签", "kind": "notes", "conf": "guess"},
    # ---------------- 阅读 ----------------
    "com.amazon.kindle": {"name": "Kindle", "kind": "ebook", "conf": "high"},
    "com.tencent.weread": {"name": "微信读书", "kind": "ebook", "conf": "high"},
    "com.chaozh.iReaderFree": {"name": "掌阅", "kind": "ebook", "conf": "high"},
    # ---------------- 日历 ----------------
    "com.google.android.calendar": {"name": "Google 日历", "kind": "calendar", "conf": "high"},
    "com.android.calendar": {"name": "系统日历", "kind": "calendar", "conf": "high"},
    # ---------------- 电商 / 快递 ----------------
    "com.taobao.taobao": {"name": "淘宝", "kind": "shopping", "conf": "high"},
    "com.tmall.wireless": {"name": "天猫", "kind": "shopping", "conf": "high"},
    "com.jingdong.app.mall": {"name": "京东", "kind": "shopping", "conf": "high"},
    "com.xunmeng.pinduoduo": {"name": "拼多多", "kind": "shopping", "conf": "high"},
    "com.amazon.mShop.android.shopping": {"name": "Amazon", "kind": "shopping", "conf": "high"},
    "com.alibaba.aliexpresshd": {"name": "AliExpress", "kind": "shopping", "conf": "high"},
    # ---------------- 浏览器 / 邮件 / 云盘 ----------------
    "com.android.browser": {"name": "Android 浏览器", "kind": "browser", "conf": "high",
                            "dbs": ["databases/browser2.db"]},
    "com.UCMobile": {"name": "UC 浏览器", "kind": "browser", "conf": "high"},
    "com.android.chrome": {"name": "Chrome", "kind": "browser", "conf": "high"},
    "com.tencent.mtt": {"name": "QQ 浏览器", "kind": "browser", "conf": "high"},
    "com.android.email": {"name": "系统邮件", "kind": "email", "conf": "high",
                          "dbs": ["databases/EmailProvider.db"]},
    "com.google.android.gm": {"name": "Gmail", "kind": "email", "conf": "high"},
    "com.microsoft.office.outlook": {"name": "Outlook", "kind": "email", "conf": "high"},
    "com.baidu.netdisk": {"name": "百度网盘", "kind": "cloud", "conf": "high"},
    "com.google.android.apps.docs": {"name": "Google Drive", "kind": "cloud", "conf": "high"},
    "com.microsoft.skydrive": {"name": "OneDrive", "kind": "cloud", "conf": "high"},
    # ---------------- 系统 / 工具 ----------------
    "com.kingroot.kinguser": {"name": "KingRoot（root 工具）", "kind": "security", "conf": "high"},
    "com.kingroot.krhelper4pc": {"name": "KingRoot PC 助手", "kind": "security", "conf": "high"},
    "com.wandoujia.phoenix2": {"name": "豌豆荚", "kind": "filemanager", "conf": "high"},
    "com.nd.assistance": {"name": "豌豆荚助手", "kind": "filemanager", "conf": "guess"},
    "com.android.mms": {"name": "短信", "kind": "chat", "conf": "high"},
    "com.android.providers.media": {"name": "媒体存储", "kind": "media", "conf": "high"},
    "com.iflytek.inputmethod.oem": {"name": "讯飞输入法", "kind": "ime", "conf": "high"},
    "com.android.inputmethod.latin": {"name": "Android 键盘", "kind": "ime", "conf": "high"},
    "android": {"name": "Android 框架", "kind": "system", "conf": "high"},
    "com.android.contacts": {"name": "通讯录", "kind": "system", "conf": "high"},
    "com.android.providers.contacts": {"name": "联系人存储", "kind": "system", "conf": "high",
                                       "dbs": ["databases/contacts2.db"]},
    "com.android.providers.telephony": {"name": "短信/通话存储", "kind": "system", "conf": "high",
                                        "dbs": ["databases/mmssms.db", "databases/calllog.db"]},
    "com.android.providers.settings": {"name": "系统设置存储", "kind": "system", "conf": "high",
                                       "dbs": ["databases/settings.db"]},
    "com.android.providers.calendar": {"name": "系统日历存储", "kind": "calendar", "conf": "high",
                                       "dbs": ["databases/calendar.db"]},
    "com.android.providers.downloads": {"name": "下载管理", "kind": "system", "conf": "high"},
    "com.android.settings": {"name": "设置", "kind": "system", "conf": "high"},
    "com.android.dialer": {"name": "拨号", "kind": "system", "conf": "high"},
    "com.android.deskclock": {"name": "时钟", "kind": "system", "conf": "high"},
    "com.android.calculator2": {"name": "计算器", "kind": "system", "conf": "high"},
    "com.android.gallery3d": {"name": "图库", "kind": "media", "conf": "high"},
    "com.android.music": {"name": "音乐", "kind": "media", "conf": "high"},
    "com.android.systemui": {"name": "系统界面", "kind": "system", "conf": "high"},
    "com.android.packageinstaller": {"name": "安装器", "kind": "system", "conf": "high"},
    "com.android.documentsui": {"name": "文件选择器", "kind": "system", "conf": "high"},
    "com.android.keychain": {"name": "密钥库", "kind": "system", "conf": "high"},
    "com.android.bluetooth": {"name": "蓝牙", "kind": "system", "conf": "high"},
    "com.android.phone": {"name": "电话", "kind": "system", "conf": "high"},
    "com.android.shell": {"name": "Shell", "kind": "system", "conf": "high"},
    "com.android.wallpaper": {"name": "壁纸", "kind": "system", "conf": "high"},
    "com.mediatek.filemanager": {"name": "MTK 文件管理", "kind": "filemanager", "conf": "high"},
    "com.mediatek.mtklogger": {"name": "MTK 日志", "kind": "system", "conf": "high"},
    "com.mediatek.engineermode": {"name": "MTK 工程模式", "kind": "security", "conf": "high"},
    "com.mediatek.calendarimporter": {"name": "日历导入", "kind": "calendar", "conf": "high"},
    "com.baidu.appsearch": {"name": "百度手机助手", "kind": "filemanager", "conf": "high"},
    "com.tencent.qqpimsecure": {"name": "腾讯手机管家", "kind": "security", "conf": "high"},
    "com.fota.update": {"name": "系统升级", "kind": "system", "conf": "high"},
    "mcube": {"name": "MTK mCube", "kind": "system", "conf": "guess"},
}

IOS_APPS = {
    "net.whatsapp.WhatsApp": {"name": "WhatsApp", "kind": "chat", "conf": "high",
                              "dbs": ["Library/ChatStorage.sqlite"]},
    "ph.telegra.Telegraph": {"name": "Telegram", "kind": "chat", "conf": "high",
                             "dbs": ["Library/Telegram-%s.db"]},
    "org.whispersystems.signal": {"name": "Signal", "kind": "chat", "conf": "high",
                                  "dbs": ["Library/signal.sqlite"]},
    "jp.naver.line": {"name": "LINE", "kind": "chat", "conf": "high"},
    "com.tencent.xin": {"name": "微信", "kind": "chat", "conf": "high"},
    "com.apple.mobilenotes": {"name": "iOS 备忘录", "kind": "notes", "conf": "high",
                              "dbs": ["NoteStore.sqlite"]},
    "com.apple.mobilecal": {"name": "iOS 日历", "kind": "calendar", "conf": "high",
                            "dbs": ["Calendar.sqlitedb"]},
    "com.apple.iBooks": {"name": "Apple Books", "kind": "ebook", "conf": "high",
                         "dbs": ["BKLibrary.sqlite", "AEAnnotation.sqlite"]},
    "com.apple.Maps": {"name": "Apple 地图", "kind": "map", "conf": "high"},
    "com.booking.Booking": {"name": "Booking.com", "kind": "booking", "conf": "guess"},
    "com.airbnb.Airbnb": {"name": "Airbnb", "kind": "booking", "conf": "guess"},
    "com.apple.mobilemail": {"name": "iOS 邮件", "kind": "email", "conf": "high"},
    "com.apple.mobilesafari": {"name": "Safari", "kind": "browser", "conf": "high"},
}

# 包名关键词 -> 类型（未知 App 兜底）
_KEYWORDS = [
    ("whatsapp", "chat"), ("telegram", "chat"), ("signal", "chat"), ("messenger", "chat"),
    ("kik", "chat"), ("viber", "chat"), ("zello", "chat"), ("wechat", "chat"),
    ("chat", "chat"), ("talk", "chat"), ("im", "chat"), ("qq", "chat"), ("line", "chat"),
    ("instagram", "social"), ("weibo", "social"), ("aweme", "social"), ("musically", "social"),
    ("facebook", "social"), ("twitter", "social"), ("tiktok", "social"),
    ("agoda", "booking"), ("booking", "booking"), ("airbnb", "booking"), ("hotel", "booking"),
    ("ctrip", "travel"), ("trip", "travel"), ("uber", "travel"), ("didi", "travel"),
    ("taxi", "travel"), ("air", "travel"), ("metro", "travel"),
    ("bank", "bank"), ("hsbc", "bank"), ("hangseng", "bank"), ("bochk", "bank"),
    ("boc", "bank"), ("icbc", "bank"), ("paypal", "bank"), ("alipay", "bank"),
    ("unionpay", "bank"), ("money", "bank"), ("pay", "bank"),
    ("wallet", "wallet"), ("metamask", "wallet"), ("token", "wallet"), ("bitkeep", "wallet"),
    ("note", "notes"), ("memo", "notes"), ("keep", "notes"), ("notepad", "notes"),
    ("map", "map"), ("amap", "map"), ("autonavi", "map"), ("app1933", "map"), ("kmb", "map"),
    ("book", "ebook"), ("reader", "ebook"), ("kindle", "ebook"), ("weread", "ebook"),
    ("calendar", "calendar"),
    ("shop", "shopping"), ("mall", "shopping"), ("taobao", "shopping"), ("tmall", "shopping"),
    ("jingdong", "shopping"), ("amazon", "shopping"), ("pinduoduo", "shopping"),
    ("browser", "browser"), ("chrome", "browser"), ("ucmobile", "browser"), ("mtt", "browser"),
    ("mail", "email"), ("gmail", "email"), ("outlook", "email"),
    ("cloud", "cloud"), ("netdisk", "cloud"), ("drive", "cloud"), ("skydrive", "cloud"),
    ("root", "security"), ("security", "security"), ("keyboard", "ime"),
    ("inputmethod", "ime"), ("launcher", "system"), ("wallpaper", "system"),
]


# ==========================================================================
# 时间归一化
# ==========================================================================
_TEXT_FMTS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M",
    "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d", "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y", "%d-%m-%Y %H:%M",
    "%Y年%m月%d日 %H:%M", "%Y年%m月%d日",
)


def _plausible(dt, y0=1990, y1=2100):
    return dt is not None and y0 <= dt.year <= y1


def _from_unix(v, div):
    try:
        return datetime.datetime.fromtimestamp(float(v) / div, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _from_apple(v, div):
    try:
        return _APPLE_BASE + datetime.timedelta(seconds=float(v) / div)
    except (OverflowError, ValueError):
        return None


def _from_chrome(v):
    try:
        return _CHROME_BASE + datetime.timedelta(microseconds=float(v))
    except (OverflowError, ValueError):
        return None


def _pick(cands):
    for dt in cands:
        if _plausible(dt):
            return dt
    for dt in cands:
        if dt is not None:
            return dt
    return None


def norm_time(value, hint=None, tz=TZ):
    """任意时间字段 → (datetime|None, raw)。hint 可指定 apple_ns/apple_s/unix_ms/
    unix_s/unix_us/chrome_us；不给则按数量级 + 合理性自动判定。"""
    raw = value
    if value is None or value == "":
        return None, raw
    if isinstance(value, datetime.datetime):
        return (value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)).astimezone(tz), raw
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8", "replace")
        except Exception:
            return None, raw

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None, raw
        if re.fullmatch(r"-?\d{8,}", s):
            value = int(s)
        else:
            iso = s.replace("Z", "+00:00")
            try:
                dt = datetime.datetime.fromisoformat(iso)
                return (dt.astimezone(tz) if dt.tzinfo else dt.replace(tzinfo=tz)), raw
            except ValueError:
                pass
            for f in _TEXT_FMTS:
                try:
                    dt = datetime.datetime.strptime(s, f)
                    return dt.replace(tzinfo=tz), raw    # 无时区字符串按本地(+8)解释
                except ValueError:
                    continue
            return None, raw

    try:
        v = float(value)
    except (TypeError, ValueError):
        return None, raw
    if v <= 0:
        return None, raw

    table = {
        "apple_ns": lambda: _from_apple(v, 1e9),
        "apple_s": lambda: _from_apple(v, 1.0),
        "apple_ms": lambda: _from_apple(v, 1e3),
        "unix_ms": lambda: _from_unix(v, 1e3),
        "unix_s": lambda: _from_unix(v, 1.0),
        "unix_us": lambda: _from_unix(v, 1e6),
        "unix_ns": lambda: _from_unix(v, 1e9),
        "chrome_us": lambda: _from_chrome(v),
    }
    if hint in table:
        dt = table[hint]()
        return (dt.astimezone(tz) if dt else None), raw

    n = int(v)
    if n >= 10 ** 16:
        dt = _pick([_from_chrome(n), _from_apple(n, 1e9)])
    elif n >= 10 ** 15:
        dt = _pick([_from_unix(n, 1e6), _from_apple(n, 1e9)])
    elif n >= 10 ** 12:
        dt = _pick([_from_unix(n, 1e3), _from_unix(n, 1e6)])
    elif n >= 10 ** 10:
        dt = _pick([_from_unix(n, 1e3), _from_unix(n, 1.0)])
    elif n >= 10 ** 8:
        dt = _pick([_from_unix(n, 1.0), _from_apple(n, 1.0)])
    else:
        dt = _from_unix(n, 1.0)
    return (dt.astimezone(tz) if dt else None), raw


def _tstr(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S%z") if dt else None


# ==========================================================================
# 文件系统薄封装
# ==========================================================================
class _Node:
    __slots__ = ("path", "ino", "is_dir", "size")

    def __init__(self, path, ino, is_dir, size):
        self.path = path
        self.ino = ino
        self.is_dir = is_dir
        self.size = size

    def __repr__(self):
        return "<%s %s %d>" % ("dir" if self.is_dir else "file", self.path, self.size)


class FsView:
    """统一 Ext4 / NTFS / DirFS 的路径级访问。"""

    def __init__(self, fs):
        self.fs = fs
        self.ntfs = (not hasattr(fs, "listdir")) and hasattr(fs, "ls")
        self._nodes = {}
        self._cache = {}

    # ---------- 基础 ----------
    def node(self, path):
        if not path:
            return None
        key = path if path.startswith("/") else "/" + path
        if key in self._nodes:
            return self._nodes[key]
        obj = None
        try:
            obj = self.fs.lookup(key)
        except Exception:
            obj = None
        if obj is None:
            self._nodes[key] = None
            return None
        n = _Node(key, obj, bool(getattr(obj, "is_dir", False)),
                  int(getattr(obj, "size", 0) or 0))
        if self.ntfs and not n.size:
            try:
                n.size = int(obj.size or 0)
            except Exception:
                n.size = 0
        self._nodes[key] = n
        return n

    def exists(self, path):
        return self.node(path) is not None

    def isdir(self, path):
        n = self.node(path)
        return bool(n and n.is_dir)

    def isfile(self, path):
        n = self.node(path)
        return bool(n and not n.is_dir)

    def size(self, path):
        n = self.node(path)
        return n.size if n else 0

    def read(self, path, size=None):
        n = self.node(path) if isinstance(path, str) else path
        if n is None or n.is_dir:
            return b""
        try:
            if self.ntfs:
                data = self.fs.read_file(n.path)
            else:
                data = self.fs.read_data(n.ino, size)
        except Exception:
            return b""
        if data is None:
            return b""
        return data if size is None else data[:size]

    def head(self, path, n=16):
        return self.read(path, n)

    # ---------- 目录 ----------
    def listdir(self, path):
        """→ [(name, _Node)]，自动跳过 . / .."""
        n = self.node(path)
        if n is None or not n.is_dir:
            return []
        out = []
        try:
            if self.ntfs:
                ents = self.fs.ls(n.path)
            else:
                ents = self.fs.listdir(n.ino)
        except Exception:
            return []
        for e in ents:
            name = getattr(e, "name", None)
            if not name or name in (".", ".."):
                continue
            child = None
            num = getattr(e, "inode", None)
            if isinstance(num, int) and num > 0 and not self.ntfs:
                try:
                    obj = self.fs.inode(num)
                except Exception:
                    obj = None
                if obj is not None:
                    child = _Node(n.path.rstrip("/") + "/" + name, obj,
                                  bool(getattr(obj, "is_dir", False)),
                                  int(getattr(obj, "size", 0) or 0))
            if child is None:
                cp = (n.path.rstrip("/") + "/" + name)
                if self.ntfs:
                    obj = getattr(e, "_ent", None)
                    child = _Node(cp, obj if obj is not None else e,
                                  bool(getattr(e, "is_dir", False)),
                                  int(getattr(e, "size", 0) or 0))
                    self._nodes[cp] = child
                else:
                    child = self.node(cp)
            if child is None:
                continue
            out.append((name, child))
        return out

    def walk(self, path, max_depth=6, max_files=20000):
        """→ 产出 (relpath, _Node)；relpath 相对 path。"""
        base = path.rstrip("/")
        stack = [(base, "", 0)]
        seen = 0
        while stack:
            cur, rel, depth = stack.pop()
            for name, child in self.listdir(cur):
                r = (rel + "/" + name) if rel else name
                if not child.is_dir:
                    yield r, child
                    seen += 1
                    if seen >= max_files:
                        return
                elif depth < max_depth:
                    stack.append((child.path, r, depth + 1))

    def dbfiles(self, path, max_depth=6):
        """该目录下所有 SQLite 数据库文件（按 magic 判定，不靠扩展名）。"""
        out = []
        for rel, n in self.walk(path, max_depth=max_depth):
            low = rel.lower()
            if not (low.endswith((".db", ".sqlite", ".sqlite3", ".db3", ".db-journal"))
                    or ".db" in low.split("/")[-1]):
                continue
            if low.endswith((".db-journal", ".db-wal", ".db-shm")):
                continue
            if self.head(n.path, 16) == b"SQLite format 3\x00":
                out.append((rel, n))
        return out


# ==========================================================================
# 数据库操作小工具（全部基于 SqliteTriage 的内部读取器，保证不依赖 sqlite3）
# ==========================================================================
def _table_names(db):
    out = []
    for m in db._master_rows():
        if (m.get("type") or "") != "table":
            continue
        name = m.get("name")
        if not name or name.lower().startswith(("sqlite_", "android_metadata")):
            continue
        out.append(name)
    return out


def _rootpage(db, table):
    for m in db._master_rows():
        if m.get("name") == table and (m.get("type") or "") == "table":
            try:
                r = int(m.get("rootpage") or 0)
            except (TypeError, ValueError):
                return 0
            return r
    return 0


class _Rec(dict):
    """大小写不敏感取值的行 dict：iOS 表列名全大写也能用 snake_case 读。

    键在行填充过程中逐个写入，所以大小写映射表延迟构建，未命中时重建一次。
    """

    __slots__ = ("_ci",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._ci = None

    def _ci_map(self):
        self._ci = {str(k).lower(): k for k in self.keys()}
        return self._ci

    def get(self, key, default=None):
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        m = self._ci if self._ci is not None else self._ci_map()
        k = m.get(str(key).lower())
        if k is None:
            m = self._ci_map()
            k = m.get(str(key).lower())
        return dict.__getitem__(self, k) if k is not None else default

    def __contains__(self, key):
        if dict.__contains__(self, key):
            return True
        return any(str(k).lower() == str(key).lower() for k in self.keys())

def _stream(db, table, limit=None):
    """流式产出该表的行 dict（含 rowid），limit 早停。"""
    root = _rootpage(db, table)
    if root <= 0:
        return
    cols = db.schema(table)
    if not cols:
        return
    alias = db._rowid_alias(table)
    n = 0
    for rowid, vals in db._table_rows(root):
        d = _Rec(rowid=rowid)
        for i, c in enumerate(cols):
            d[c] = vals[i] if i < len(vals) else None
        if alias and d.get(alias) is None:
            d[alias] = rowid
        yield d
        n += 1
        if limit and n >= limit:
            return


def _count(db, table):
    try:
        r = db.rows("select count(*) from %s" % table)
        return int(r[0][0]) if r and r[0] and r[0][0] is not None else 0
    except Exception:
        try:
            return sum(1 for _ in _stream(db, table))
        except Exception:
            return -1


def _head3(db, table):
    out = []
    try:
        for d in _stream(db, table, 3):
            out.append(d)
    except Exception:
        pass
    return out


def _low_cols(db, table):
    return [c.lower() for c in db.schema(table)]


def _col(cols, aliases, used=()):
    """列名匹配：先精确，再包含；跳过已被占用的列。"""
    for a in aliases:
        for c in cols:
            if c == a and c not in used:
                return c
    for a in aliases:
        for c in cols:
            if a in c and c not in used:
                return c
    return None


def _num(v):
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().replace(",", "").replace("HK$", "").replace("$", "")
    s = s.replace("HKD", "").replace("CNY", "").replace("USD", "").strip()
    try:
        return float(s)
    except ValueError:
        return None


def _txt(v):
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace").strip("\x00 ").strip()
    s = str(v)
    return s.strip()


def _haversine(lat1, lon1, lat2, lon2):
    import math
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, a ** 0.5))


# ==========================================================================
# iOS 备份 Manifest 索引（Manifest.db + 散列文件）
# ==========================================================================
class _ManifestIndex:
    def __init__(self, view):
        self.view = view
        self.rows = []          # dict(fileID, domain, relativePath)
        self.by_domain = {}     # domain -> {relpath: fileID}
        self.notes = []
        self._load()

    def _load(self):
        data = self.view.read("/Manifest.db")
        if not data:
            return
        try:
            db = SqliteTriage(data)
        except SqliteError as e:
            self.notes.append("Manifest.db 解析失败: %s" % e)
            return
        cols = [c.lower() for c in db.schema("Files")]
        fid_col = _col(cols, ["fileid"]) or "fileid"
        dom_col = _col(cols, ["domain"]) or "domain"
        rel_col = _col(cols, ["relativepath", "relative_path"]) or "relativepath"
        try:
            for d in _stream(db, "Files"):
                fid = d.get(fid_col) if fid_col in d else d.get("fileID")
                dom = d.get(dom_col)
                rel = d.get(rel_col) or ""
                if not fid or not dom:
                    continue
                self.rows.append({"fileID": fid, "domain": dom, "relativePath": rel})
                self.by_domain.setdefault(dom, {})[rel] = fid
        except Exception as e:      # noqa: BLE001
            self.notes.append("Manifest Files 遍历失败: %s" % e)

    def app_domains(self):
        return sorted(d[10:] for d in self.by_domain if d.startswith("AppDomain-"))

    def files(self, bundle):
        return dict(self.by_domain.get("AppDomain-%s" % bundle, {}))

    def read(self, bundle, rel):
        fid = self.files(bundle).get(rel)
        if not fid:
            return b""
        return self.view.read("/%s/%s" % (fid[:2], fid))


class _AppRoot:
    """一个 App 的数据根：Adnroid 目录 or iOS 备份 domain。"""

    def __init__(self, prof, pkg):
        self.prof = prof
        self.pkg = pkg
        self.view = prof.view
        self.dir = None
        self._manifest = None
        self._files = None
        if prof.mode == "ios_backup":
            self._manifest = prof.manifest
            self._files = dict(self._manifest.files(pkg))
        else:
            self.dir = prof.app_dir(pkg)

    @property
    def exists(self):
        if self.dir is not None:
            return self.view.isdir(self.dir)
        return bool(self._files)

    def read(self, rel):
        if self.dir is not None:
            return self.view.read(self.dir.rstrip("/") + "/" + rel)
        return self._manifest.read(self.pkg, rel)

    def list(self):
        if self.dir is not None:
            return [(rel, n) for rel, n in self.view.walk(self.dir, max_depth=6)]
        return [(rel, None) for rel in sorted(self._files)]

    def size(self, rel):
        if self.dir is not None:
            return self.view.size(self.dir.rstrip("/") + "/" + rel)
        if self._files:
            try:
                base = self._files.get(rel)
                return self.view.size("/%s/%s" % (base[:2], base)) if base else 0
            except Exception:
                return 0
        return 0

    def dbs(self):
        out = []
        for rel, n in self.list():
            low = rel.lower()
            if low.endswith((".db-journal", ".db-wal", ".db-shm")):
                continue
            if not low.endswith((".db", ".sqlite", ".sqlite3", ".db3")) and ".db" not in low:
                continue
            if self.dir is not None:
                if self.view.head(n.path, 16) != b"SQLite format 3\x00":
                    continue
            out.append(rel)
        return out


# ==========================================================================
# 设备文件系统打开辅助
# ==========================================================================
def open_fs(path, offset=0, size=None):
    """打开镜像/分区 → Ext4 或 NTFS（自动判定）。返回 (fs, kind)。"""
    from .image import Image
    img = Image(path)
    src = img
    if offset or size:
        from .image import SubImage
        src = SubImage(img, offset, size) if size else SubImage(img, offset, img.size - offset)
    try:
        return Ext4(src), "ext4"
    except Exception:
        pass
    return NTFS(src), "ntfs"


def installed_from_hive(hive_or_path):
    """Windows 注册表 Software hive → 已安装程序（DisplayName/版本/安装位置）。"""
    hv = None
    if isinstance(hive_or_path, Hive):
        hv = hive_or_path
    else:
        with open(hive_or_path, "rb") as fh:
            hv = Hive(fh.read())
    out = []
    base = "Microsoft\\Windows\\CurrentVersion\\Uninstall"
    node = hv.open(base)
    if node is None:
        return out
    for name in node.keys():
        sub = node.open(name)
        if sub is None:
            continue
        vals = sub.values()
        dn = vals.get("DisplayName")
        if not dn:
            continue
        if isinstance(dn, bytes):
            dn = dn.decode("utf-16-le", "replace").strip("\x00")
        out.append({
            "key": name, "name": dn,
            "version": (vals.get("DisplayVersion") or ""),
            "publisher": (vals.get("Publisher") or ""),
            "install_location": (vals.get("InstallLocation") or ""),
            "install_date": (vals.get("InstallDate") or ""),
        })
    return out


# ==========================================================================
# 应用画像
# ==========================================================================
class AppProfiler:
    """安装清单 / 数据目录定位 / 类型判定 / 未知 App 兜底勘查。"""

    def __init__(self, fs, root=None):
        self.view = FsView(fs)
        self.notes = []
        self.mode = "android"
        self.manifest = None
        self._installed = None
        self._dbs_cache = {}
        if self.view.exists("/Manifest.db") or self.view.exists("/Manifest.plist"):
            self.mode = "ios_backup"
            self.manifest = _ManifestIndex(self.view)
            self.notes.extend(self.manifest.notes)
            self.root = "/"
        else:
            self.root = root or self._find_pkg_root()

    # ---------- 基础设施 ----------
    def _find_pkg_root(self):
        best, best_score = "/", 0
        for cand in ("/data/data", "/data", "/"):
            if not self.view.isdir(cand):
                continue
            score = 0
            for name, n in self.view.listdir(cand):
                if not n.is_dir:
                    continue
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_-]+){1,4}", name):
                    score += 1
            if score > best_score:
                best, best_score = cand, score
        if best_score < 3:
            self.notes.append("未找到包名目录集合（score=%d），按根目录处理" % best_score)
            return "/"
        return best

    def app_dir(self, pkg):
        return self.root.rstrip("/") + "/" + pkg

    def _info(self, pkg):
        info = APPS.get(pkg) or IOS_APPS.get(pkg)
        return dict(info) if info else None

    def _kind_by_keyword(self, pkg):
        segs = [s for s in re.split(r"[.\-_]", pkg.lower()) if s]
        blob = pkg.lower()
        for key, kind in _KEYWORDS:
            if key in segs:
                return kind, key
        for key, kind in _KEYWORDS:
            if len(key) >= 4 and key in blob:
                return kind, key
        return None, None

    # ---------- 安装清单 ----------
    def _packages_xml(self):
        for p in ("/system/packages.xml", "/data/system/packages.xml", "/packages.xml"):
            if self.view.isfile(p):
                return p
        return None

    def installed(self):
        """→ [{package, name, type, kind, version, first_install, ..., source}]"""
        if self._installed is not None:
            return self._installed

        out = []
        if self.mode == "ios_backup":
            for bundle in self.manifest.app_domains():
                info = self._info(bundle) or {}
                kind = info.get("kind") or self._kind_by_keyword(bundle)[0] or "unknown"
                out.append({
                    "package": bundle, "name": info.get("name"),
                    "kind": kind, "type": TYPE_NAMES.get(kind, "未知"),
                    "version": None, "first_install": None, "first_install_str": None,
                    "platform": "ios", "source": "Manifest.db:AppDomain-%s" % bundle,
                    "dir": None, "files": len(self.manifest.files(bundle)),
                })
            self._installed = out
            return out

        src = self._packages_xml()
        seen = set()
        if src:
            data = self.view.read(src)
            try:
                root = ET.fromstring(data)
            except ET.ParseError as e:
                self.notes.append("packages.xml 解析失败: %s" % e)
                root = None
            if root is not None:
                for pkg in root.findall("package"):
                    name = pkg.get("name")
                    if not name:
                        continue
                    try:
                        ft = int(pkg.get("ft"), 16) if pkg.get("ft") else None
                    except (TypeError, ValueError):
                        ft = None
                    info = self._info(name) or {}
                    kind = info.get("kind") or self._kind_by_keyword(name)[0] or "unknown"
                    seen.add(name)
                    out.append({
                        "package": name, "name": info.get("name"),
                        "kind": kind, "type": TYPE_NAMES.get(kind, "未知"),
                        "version": pkg.get("version"), "first_install": ft,
                        "first_install_str": _tstr(norm_time(ft)[0]) if ft else None,
                        "platform": "android", "source": src,
                        "codePath": pkg.get("codePath"),
                        "dir": self.app_dir(name) if self.view.isdir(self.app_dir(name)) else None,
                    })
        # 目录兜底（没有 packages.xml 或镜像只含数据分区）
        for name, n in self.view.listdir(self.root):
            if not n.is_dir or name in seen:
                continue
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_-]+){1,4}", name):
                continue
            info = self._info(name) or {}
            kind = info.get("kind") or self._kind_by_keyword(name)[0] or "unknown"
            out.append({
                "package": name, "name": info.get("name"), "kind": kind,
                "type": TYPE_NAMES.get(kind, "未知"), "version": None,
                "first_install": None, "first_install_str": None,
                "platform": "android", "source": "目录枚举:" + n.path,
                "dir": n.path,
            })
        out.sort(key=lambda r: r["package"])
        self._installed = out
        if not out:
            self.notes.append("installed(): 未发现任何 App（root=%s）" % self.root)
        return out

    def apks(self):
        """镜像里出现的安装包（/app、/data/app）。"""
        out = []
        for d in ("/app", "/data/app", "/system/app"):
            if not self.view.isdir(d):
                continue
            for name, n in self.view.listdir(d):
                if n.is_dir:
                    for sub, sn in self.view.listdir(n.path):
                        if sn.path.lower().endswith(".apk"):
                            out.append({"path": sn.path, "size": sn.size})
                elif name.lower().endswith(".apk"):
                    out.append({"path": n.path, "size": n.size})
        return out

    # ---------- 数据目录定位 ----------
    def locate(self, pkg):
        r = _AppRoot(self, pkg)
        res = {"pkg": pkg, "platform": "ios" if self.mode == "ios_backup" else "android",
               "dir": r.dir, "exists": r.exists, "files": [], "databases": [],
               "total_size": 0}
        if not r.exists:
            self.notes.append("locate(%s): App 数据目录不存在" % pkg)
            return res
        for rel, n in r.list():
            size = n.size if n is not None else r.size(rel)
            res["files"].append({"rel": rel, "size": size})
            res["total_size"] += size
        for rel in r.dbs():
            res["databases"].append(rel)
        return res

    # ---------- 类型判定 ----------
    def profile(self, pkg, deep=False):
        info = self._info(pkg)
        kw_kind, kw = self._kind_by_keyword(pkg)
        r = _AppRoot(self, pkg)
        res = {"pkg": pkg, "name": None, "kind": "unknown", "type": "未知",
               "confidence": 0.0, "evidence": [], "exists": r.exists,
               "dir": r.dir, "dbs": []}
        conf = 0.0
        if info:
            res["name"] = info.get("name")
            if info.get("kind"):
                res["kind"] = info["kind"]
                conf = 0.9 if info.get("conf") == "high" else 0.65
                res["evidence"].append("画像表命中(%s)" % info.get("conf", "high"))
        if kw_kind and conf < 0.9:
            res["evidence"].append("包名关键词 '%s'" % kw)
            if res["kind"] == "unknown":
                res["kind"] = kw_kind
                conf = max(conf, 0.55)
            else:
                conf = max(conf, 0.7)
        if res["kind"] == "unknown" and self._system_guess(pkg):
            res["kind"] = "system"
            conf = max(conf, 0.35)
            res["evidence"].append("系统包名前缀")
        if not res["name"]:
            res["name"] = pkg

        if deep and r.exists:
            kind2, ev = self._schema_kind(pkg)
            if kind2:
                res["evidence"].extend(ev)
                if res["kind"] == "unknown":
                    res["kind"] = kind2
                    conf = max(conf, 0.5)
                elif kind2 == res["kind"]:
                    conf = min(0.98, conf + 0.08)
                else:
                    res["evidence"].append("库结构提示 %s 与画像 %s 不一致" % (kind2, res["kind"]))
        res["confidence"] = round(conf, 2)
        res["type"] = TYPE_NAMES.get(res["kind"], "未知")
        res["dbs"] = r.dbs()
        return res

    def _schema_kind(self, pkg):
        """从库表/列名猜类型（画像表未命中时的证据）。

        判定要同时满足表名与列名，避免 bookmarks/t_jct_syncbookfilelist 这类
        误命中（表名包含 book 但其实是浏览器的书签表）。
        """
        sigs = [
            ("chat", ("message", "messages", "chat", "sms", "msg"),
             ("body", "text", "key_remote_jid", "timestamp")),
            ("bank", ("transaction", "txn", "bill", "流水"),
             ("amount", "balance", "currency")),
            ("booking", ("booking", "reservation"),
             ("checkin", "check_in", "hotel", "check_out")),
            ("notes", ("note", "notes", "memo"),
             ("title", "content", "modified")),
            ("map", ("place", "stop", "station", "location", "poi"),
             ("lat", "latitude", "lng", "lon")),
            ("ebook", ("book", "library", "annotation", "highlight"),
             ("title", "author", "highlight", "assetid")),
            ("calendar", ("event", "events", "calendar"),
             ("dtstart", "start", "summary")),
            ("shopping", ("order", "orders", "cart", "trade"),
             ("order_id", "total", "address", "sku")),
        ]
        hits = {}
        for rel, db in self._dbs(pkg):
            for t in _table_names(db):
                low = t.lower()
                cols = _low_cols(db, t)
                for kind, tnames, cnames in sigs:
                    if kind in hits:
                        continue
                    col_hits = sum(1 for c in cnames if any(c in x for x in cols))
                    exact = any(tn == low for tn in tnames)
                    near = any(tn in low for tn in tnames)
                    if (exact and col_hits >= 1) or (near and col_hits >= 2):
                        hits[kind] = "%s:%s(列命中%d)" % (rel, t, col_hits)
        if not hits:
            return None, []
        kind = max(hits, key=lambda k: len(hits[k]))
        return kind, ["库结构证据 %s" % hits[kind]]

    # ---------- 系统包兜底 ----------
    SYSTEM_PREFIXES = ("com.android.", "android.", "com.mediatek.", "com.yulong.",
                       "com.google.android.", "com.htc.", "com.samsung.", "com.miui.",
                       "com.huawei.", "com.lenovo.", "com.oppo.", "com.vivo.")

    def _system_guess(self, pkg):
        for pre in self.SYSTEM_PREFIXES:
            if pkg.startswith(pre) or pkg == pre.rstrip("."):
                return True
        return pkg in ("android", "mcube", "com.fota.update")
    # ---------- 库句柄 ----------
    def _dbs(self, pkg):
        if pkg in self._dbs_cache:
            return self._dbs_cache[pkg]
        r = _AppRoot(self, pkg)
        out = []
        declared = (self._info(pkg) or {}).get("dbs") or []
        order = []
        for rel in declared:
            if "%s" in rel:
                continue
            order.append(rel)
        for rel in r.dbs():
            if rel not in order:
                order.append(rel)
        for rel in order:
            data = r.read(rel)
            if not data or not data.startswith(b"SQLite format 3\x00"):
                continue
            try:
                out.append((rel, SqliteTriage(data)))
            except SqliteError as e:
                self.notes.append("打开 %s/%s 失败: %s" % (pkg, rel, e))
        self._dbs_cache[pkg] = out
        if not out:
            self.notes.append("%s: 没有可解析的 SQLite（可能已加密或只有 plist/xml）" % pkg)
        return out

    def db(self, pkg, rel):
        for r, db in self._dbs(pkg):
            if r == rel:
                return db
        data = _AppRoot(self, pkg).read(rel)
        if data.startswith(b"SQLite format 3\x00"):
            try:
                return SqliteTriage(data)
            except SqliteError:
                return None
        return None

    # ---------- 未知 App 兜底 ----------
    def auto_scan(self, pkg):
        return auto_scan(self, pkg)


def auto_scan(prof, pkg):
    """遍历 App 目录下所有 .db/.sqlite/.plist/.xml，列出结构 + 3 行样本。"""
    if isinstance(prof, AppProfiler):
        p = prof
    else:
        p = AppProfiler(prof)
    r = _AppRoot(p, pkg)
    res = {"pkg": pkg, "base": r.dir, "exists": r.exists, "files": [], "summary": {}}
    if not r.exists:
        p.notes.append("auto_scan(%s): App 不存在" % pkg)
        return res
    for rel, n in r.list():
        low = rel.lower()
        if low.endswith((".db-journal", ".db-wal", ".db-shm", "-journal")):
            continue                    # 日志/回滚文件不是库本体
        item = {"rel": rel, "size": n.size if n is not None else r.size(rel), "kind": None}
        if low.endswith((".db", ".sqlite", ".sqlite3", ".db3")) or ".db" in low:
            data = r.read(rel)
            if not data.startswith(b"SQLite format 3\x00"):
                item["kind"] = "db(非 SQLite)"
                res["files"].append(item)
                continue
            item["kind"] = "sqlite"
            try:
                db = SqliteTriage(data)
            except SqliteError as e:
                item["error"] = str(e)
                res["files"].append(item)
                continue
            tabs = {}
            for t in _table_names(db):
                cols = db.schema(t)
                tabs[t] = {"rows": _count(db, t), "cols": cols,
                           "sample": _head3(db, t)}
            item["tables"] = tabs
            item["table_count"] = len(tabs)
        elif low.endswith(".plist"):
            data = r.read(rel)
            item["kind"] = "plist"
            try:
                obj = PlistHelper.load(data)
            except Exception as e:      # noqa: BLE001
                item["error"] = str(e)
                res["files"].append(item)
                continue
            if isinstance(obj, dict):
                item["keys"] = list(obj.keys())[:12]
                item["sample"] = {k: obj[k] for k in list(obj.keys())[:3]}
                item["entries"] = len(obj)
            elif isinstance(obj, list):
                item["entries"] = len(obj)
                item["sample"] = obj[:3]
            else:
                item["sample"] = obj
        elif low.endswith(".xml"):
            data = r.read(rel)
            item["kind"] = "xml"
            try:
                root = ET.fromstring(data)
            except ET.ParseError as e:
                item["error"] = str(e)
                res["files"].append(item)
                continue
            item["root"] = root.tag
            item["children"] = len(list(root))
            item["sample"] = [{k: (v[:40] if isinstance(v, str) else v)
                               for k, v in list(el.attrib.items())[:4]}
                              for el in list(root)[:3]]
        else:
            continue
        res["files"].append(item)
    res["summary"] = {
        "files": len(res["files"]),
        "sqlite": sum(1 for f in res["files"] if f["kind"] == "sqlite"),
        "tables": sum(f.get("table_count", 0) for f in res["files"]),
        "plist": sum(1 for f in res["files"] if f["kind"] == "plist"),
        "xml": sum(1 for f in res["files"] if f["kind"] == "xml"),
    }
    return res


# ==========================================================================
# 解析器基类
# ==========================================================================
class _AppBase:
    KIND = None

    def __init__(self, fs_or_prof):
        if isinstance(fs_or_prof, AppProfiler):
            self.prof = fs_or_prof
        else:
            self.prof = AppProfiler(fs_or_prof)
        self._log = self.prof.notes   # 与 AppProfiler 共享同一日志
        self.view = self.prof.view

    @property
    def notes(self):
        return self._log

    # ---------- 通用 ----------
    def _root(self, pkg):
        r = _AppRoot(self.prof, pkg)
        if not r.exists:
            self.notes.append("%s(%s): App 数据目录不存在" % (self.__class__.__name__, pkg))
        return r

    def _dbs(self, pkg):
        return self.prof._dbs(pkg)

    def _harvest(self, pkg, fields, require=(), name_hints=(), limit=3000,
                 skip_tables=(), min_fields=2):
        """列名启发式抽取：把任意表映射到业务字段。

        fields: {field: [aliases]} 或 {field: ([aliases], time_hint)}
        → [ {field: value, "_rel","_table","_hint", time字段附 time_raw} ]
        """
        out = []
        for rel, db in self._dbs(pkg):
            for t in _table_names(db):
                if t.lower() in skip_tables:
                    continue
                cols = _low_cols(db, t)
                if not cols:
                    continue
                mapping, hints, used = {}, {}, set()
                for f, spec in fields.items():
                    aliases, hint = (spec, None) if isinstance(spec, list) else spec
                    c = _col(cols, aliases, used)
                    if c:
                        mapping[f] = c
                        used.add(c)
                        if hint:
                            hints[f] = hint
                if any(r not in mapping for r in require):
                    continue
                if len(mapping) < max(min_fields, len(require)):
                    continue
                score = len(mapping)
                if name_hints and any(h in t.lower() for h in name_hints):
                    score += 3
                try:
                    rows = list(_stream(db, t, limit))
                except Exception as e:      # noqa: BLE001
                    self.notes.append("%s:%s 读取失败 (%s)" % (rel, t, e))
                    continue
                for d in rows:
                    rec = {}
                    empty = True
                    for f, c in mapping.items():
                        v = d.get(c)
                        if f == "time" or f.endswith("_time"):
                            dt, raw = norm_time(v, hints.get(f))
                            rec[f] = dt
                            rec[f + "_raw"] = raw
                            rec[f + "_str"] = _tstr(dt)
                            if dt is not None:
                                empty = False
                        else:
                            rec[f] = _txt(v) if not isinstance(v, (int, float)) else v
                            if v not in (None, ""):
                                empty = False
                    if empty:
                        continue
                    rec["_rel"] = rel
                    rec["_table"] = t
                    rec["_score"] = score
                    out.append(rec)
                if len(out) > 5000:
                    self.notes.append("%s: 记录过多，已截断到 5000 条" % pkg)
                    return out
        out.sort(key=lambda r: (r.get("time") or datetime.datetime.min.replace(tzinfo=TZ)),
                 reverse=True)
        return out


# ==========================================================================
# 聊天
# ==========================================================================
class ChatApp(_AppBase):
    KIND = "chat"
    WA_PKGS = ("com.whatsapp", "net.whatsapp.WhatsApp")
    TG_PKGS = ("org.telegram.messenger", "ph.telegra.Telegraph")
    WX_PKGS = ("com.tencent.mm", "com.tencent.xin")
    SG_PKGS = ("org.thoughtcrime.securesms", "org.whispersystems.signal")
    QQ_PKGS = ("com.tencent.mobileqq",)

    # ---------- 消息 ----------
    def messages(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        if pkg in self.WA_PKGS:
            out = self._wa_messages(pkg)
            if out:
                return out
        if pkg in self.TG_PKGS:
            out = self._tg_messages(pkg)
            if out:
                return out
        if pkg in self.WX_PKGS:
            out = self._wx_messages(pkg)
            if out:
                return out
        out = self._generic_messages(pkg)
        if not out:
            self.notes.append("messages(%s): 未匹配到消息表" % pkg)
        return out

    # ---- WhatsApp ----
    def _wa_messages(self, pkg):
        db = None
        for rel in ("databases/msgstore.db", "msgstore.db", "Library/ChatStorage.sqlite"):
            db = self.prof.db(pkg, rel)
            if db is not None:
                break
        if db is None:
            return []
        tabs = {t.lower(): t for t in _table_names(db)}
        if "zwamessage" in tabs:                    # iOS
            return self._wa_ios(db, tabs)
        if "message" not in tabs:
            return []
        tmsg = tabs["message"]
        cols = _low_cols(db, tmsg)
        c_body = _col(cols, ["text_data", "data"])
        c_from = _col(cols, ["from_me", "key_from_me"])
        c_time = _col(cols, ["timestamp", "date"])
        c_chat = _col(cols, ["chat_row_id", "key_remote_jid"])
        c_send = _col(cols, ["sender_jid_row_id", "remote_resource", "sender_jid"])
        c_type = _col(cols, ["message_type", "media_wa_type"])
        if not (c_body and c_from and c_time):
            return []
        jid_map, chat_map, chat_subject = {}, {}, {}
        if "jid" in tabs:
            jc = _low_cols(db, tabs["jid"])
            j_id = _col(jc, ["_id", "id"])
            j_raw = _col(jc, ["jid", "raw_string", "user"])
            j_name = _col(jc, ["display_name", "name"])
            for d in _stream(db, tabs["jid"]):
                if j_raw:
                    jid_map[d.get(j_id)] = _txt(d.get(j_raw))
                    if j_name and d.get(j_name):
                        chat_subject[_txt(d.get(j_raw))] = _txt(d.get(j_name))
        if "chat" in tabs:
            cc = _low_cols(db, tabs["chat"])
            c_id = _col(cc, ["_id", "id"])
            c_jid = _col(cc, ["jid_row_id", "jid"])
            c_sub = _col(cc, ["subject"])
            for d in _stream(db, tabs["chat"]):
                cid = d.get(c_id)
                jid = _txt(d.get(c_jid))
                if jid and jid.isdigit():
                    jid = jid_map.get(int(jid), jid)
                chat_map[cid] = jid
                if c_sub and d.get(c_sub):
                    chat_subject[jid] = _txt(d.get(c_sub))
        out = []
        for d in _stream(db, tmsg):
            peer = d.get(c_chat)
            if isinstance(peer, (int, float)) and not isinstance(peer, bool):
                peer = chat_map.get(peer)
            peer = _txt(peer) or ""
            sender = d.get(c_send)
            if isinstance(sender, (int, float)):
                sender = jid_map.get(int(sender))
            sender = _txt(sender)
            dt, raw = norm_time(d.get(c_time), "unix_ms")
            body = _txt(d.get(c_body))
            is_group = peer.endswith("@g.us") or ("@" not in peer and peer.startswith("[")) or \
                       bool(chat_subject.get(peer)) and peer.endswith("@g.us")
            is_group = peer.endswith("@g.us")
            out.append({
                "time": dt, "time_raw": raw, "time_str": _tstr(dt),
                "direction": "发出" if d.get(c_from) in (1, "1", True) else "收到",
                "peer": peer, "chat_name": chat_subject.get(peer) or peer,
                "sender": sender, "body": body, "is_group": is_group,
                "chat_type": _txt(d.get(c_type)) if c_type else None,
                "source": "%s:%s" % ("databases/msgstore.db", tmsg),
            })
        return out

    def _wa_ios(self, db, tabs):
        tmsg = tabs["zwamessage"]
        cols = _low_cols(db, tmsg)
        c_body = _col(cols, ["ztext"])
        c_from = _col(cols, ["zisfromme"])
        c_time = _col(cols, ["zmessagedate"])
        c_chat = _col(cols, ["zchatsession"])
        chats = {}
        if "zwachat" in tabs:
            cc = _low_cols(db, tabs["zwachat"])
            c_id = _col(cc, ["z_pk"])
            c_jid = _col(cc, ["zcontactjid"])
            c_name = _col(cc, ["zpartnername"])
            for d in _stream(db, tabs["zwachat"]):
                chats[d.get(c_id)] = {"jid": _txt(d.get(c_jid)), "name": _txt(d.get(c_name))}
        out = []
        for d in _stream(db, tmsg):
            ch = chats.get(d.get(c_chat)) or {}
            dt, raw = norm_time(d.get(c_time), "apple_s")
            peer = ch.get("jid") or ""
            out.append({
                "time": dt, "time_raw": raw, "time_str": _tstr(dt),
                "direction": "发出" if d.get(c_from) in (1, "1", True) else "收到",
                "peer": peer, "chat_name": ch.get("name") or peer, "sender": None,
                "body": _txt(d.get(c_body)), "is_group": peer.endswith("@g.us"),
                "chat_type": None, "source": "Library/ChatStorage.sqlite:%s" % tmsg,
            })
        return out

    # ---- Telegram（TL 二进制）----
    def _tl_text(self, blob):
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < 8:
            return None
        buf = bytes(blob)
        best = None
        for off in range(4, min(len(buf) - 4, 96)):
            n = int.from_bytes(buf[off:off + 4], "little")
            if n < 2 or n > 512 or off + 4 + n > len(buf):
                continue
            try:
                s = buf[off + 4:off + 4 + n].decode("utf-8")
            except UnicodeDecodeError:
                continue
            printable = sum(1 for ch in s if ch.isprintable() or ch in "\n\t")
            if printable / max(1, len(s)) < 0.9:
                continue
            letters = sum(1 for ch in s if ch.isalpha())
            if letters < 2:
                continue
            if best is None or len(s) > len(best):
                best = s
        return best

    def _tg_messages(self, pkg):
        out = []
        for rel, db in self._dbs(pkg):
            tabs = {t.lower(): t for t in _table_names(db)}
            t = tabs.get("messages_v2") or tabs.get("messages")
            if not t:
                continue
            cols = _low_cols(db, t)
            c_data = _col(cols, ["data", "message"])
            c_date = _col(cols, ["date"])
            c_out = _col(cols, ["out", "is_out"])
            c_dialog = _col(cols, ["dialog_id", "uid"])
            if not (c_data and c_date):
                continue
            for d in _stream(db, t):
                blob = d.get(c_data)
                text = self._tl_text(blob) or ""
                dt, raw = norm_time(d.get(c_date), "unix_s")
                out.append({
                    "time": dt, "time_raw": raw, "time_str": _tstr(dt),
                    "direction": "发出" if d.get(c_out) in (1, True, "1") else "收到",
                    "peer": _txt(d.get(c_dialog)), "chat_name": _txt(d.get(c_dialog)),
                    "sender": None, "body": text,
                    "is_group": bool(d.get(c_dialog) and int(d.get(c_dialog) or 0) < 0),
                    "chat_type": None, "source": "%s:%s" % (rel, t),
                    "parse": "TL 启发式",
                })
        return out

    # ---- 微信 ----
    def _wx_messages(self, pkg):
        out = []
        for rel, db in self._dbs(pkg):
            tabs = {t.lower(): t for t in _table_names(db)}
            t = tabs.get("message")
            if not t:
                continue
            cols = _low_cols(db, t)
            c_body = _col(cols, ["content"])
            c_time = _col(cols, ["createtime"])
            c_talker = _col(cols, ["talker"])
            c_send = _col(cols, ["issend"])
            c_type = _col(cols, ["type"])
            if not (c_body and c_time and c_talker):
                continue
            names = {}
            if "rcontact" in tabs:
                rc = _low_cols(db, tabs["rcontact"])
                n_user = _col(rc, ["username"])
                n_nick = _col(rc, ["nickname", "conremark"])
                for d in _stream(db, tabs["rcontact"], 5000):
                    if n_user:
                        names[_txt(d.get(n_user))] = _txt(d.get(n_nick))
            for d in _stream(db, t):
                talker = _txt(d.get(c_talker))
                dt, raw = norm_time(d.get(c_time), "unix_s")
                out.append({
                    "time": dt, "time_raw": raw, "time_str": _tstr(dt),
                    "direction": "发出" if d.get(c_send) in (1, "1", True) else "收到",
                    "peer": talker, "chat_name": names.get(talker) or talker,
                    "sender": None, "body": _txt(d.get(c_body)),
                    "is_group": talker.endswith("@chatroom"),
                    "chat_type": _txt(d.get(c_type)) if c_type else None,
                    "source": "%s:%s" % (rel, t),
                })
        return out

    # ---- 通用兜底（Signal/LINE/QQ/flash_chat 等）----
    def _generic_messages(self, pkg):
        fields = {
            "time": (["timestamp", "date", "sent_at", "created_at", "createtime",
                      "created_time", "time", "date_sent", "createdtime"], None),
            "body": (["text_data", "body", "content", "text", "message", "msg", "snippet"], None),
            "peer": (["key_remote_jid", "address", "peer", "jid", "talker", "from_jid",
                      "handle", "remote_resource", "recipient", "username"], None),
            "from_me": (["is_from_me", "from_me", "key_from_me", "out", "issend", "is_send"], None),
            "sender": (["sender", "author", "sender_jid", "from_address"], None),
            "chat": (["chat_row_id", "thread_id", "conversation_id", "chat_id", "dialog_id"], None),
        }
        recs = self._harvest(pkg, fields, require=("time",),
                             name_hints=("message", "msg", "chat", "sms", "history"),
                             skip_tables=("threads", "thread", "conversation", "conversations",
                                          "words", "words_content", "words_segments"),
                             min_fields=2)
        out = []
        seen = set()
        for r in recs:
            peer = r.get("peer") or r.get("chat") or ""
            body = r.get("body")
            if body is None and peer is None:
                continue
            fm = r.get("from_me")
            key = (str(r.get("time_raw")), str(body)[:80], str(peer))
            if key in seen:                 # threads 与 sms 双写同一句，去重
                continue
            seen.add(key)
            out.append({
                "time": r.get("time"), "time_raw": r.get("time_raw"),
                "time_str": r.get("time_str"),
                "direction": "发出" if fm in (1, True, "1", "out", "sent") else "收到",
                "peer": peer, "chat_name": peer or "", "sender": r.get("sender"),
                "body": body, "is_group": str(peer).endswith(("@g.us", "@chatroom")),
                "chat_type": None, "source": "%s:%s" % (r.get("_rel"), r.get("_table")),
            })
        return out

    # ---------- 群组 ----------
    def groups(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        out = []
        for rel, db in self._dbs(pkg):
            tabs = {t.lower(): t for t in _table_names(db)}
            if "chat" in tabs and pkg in self.WA_PKGS:
                tc = tabs["chat"]
                cols = _low_cols(db, tc)
                c_id = _col(cols, ["_id", "id"])
                c_jid = _col(cols, ["jid_row_id", "jid"])
                c_sub = _col(cols, ["subject"])
                c_ct = _col(cols, ["created_timestamp"])
                members = {}
                if "group_participants" in tabs:
                    gp = _low_cols(db, tabs["group_participants"])
                    g_gj = _col(gp, ["gjid", "group_jid"])
                    g_m = _col(gp, ["jid", "member"])
                    for d in _stream(db, tabs["group_participants"]):
                        key = _txt(d.get(g_gj))
                        members.setdefault(key, set()).add(_txt(d.get(g_m)))
                jid_map = {}
                if "jid" in tabs:
                    jc = _low_cols(db, tabs["jid"])
                    j_id = _col(jc, ["_id", "id"])
                    j_raw = _col(jc, ["jid", "raw_string", "user"])
                    for d in _stream(db, tabs["jid"]):
                        jid_map[d.get(j_id)] = _txt(d.get(j_raw))
                for d in _stream(db, tc):
                    jid = _txt(d.get(c_jid))
                    if jid and jid.isdigit():
                        jid = jid_map.get(int(jid), jid)
                    subj = _txt(d.get(c_sub)) if c_sub else None
                    if not (jid and jid.endswith("@g.us")):
                        continue
                    dt, raw = norm_time(d.get(c_ct), "unix_ms") if c_ct else (None, None)
                    cnt = len(members.get(jid, ()))
                    if not cnt:
                        tmsg = tabs.get("message")
                        if tmsg:
                            mc = _low_cols(db, tmsg)
                            m_chat = _col(mc, ["key_remote_jid", "chat_row_id"])
                            m_from = _col(mc, ["key_from_me", "from_me"])
                            senders = set()
                            for m in _stream(db, tmsg):
                                jv = _txt(m.get(m_chat))
                                if jv == jid or (m_chat == "chat_row_id" and str(jv) == str(d.get(c_id))):
                                    senders.add(_txt(m.get("remote_resource")))
                            cnt = len(senders)
                    out.append({
                        "name": subj or jid, "jid": jid, "created": dt,
                        "created_raw": raw, "created_str": _tstr(dt),
                        "members": cnt, "source": "%s:%s" % (rel, tc),
                    })
                continue
            # 通用群组表
            for t in _table_names(db):
                low = t.lower()
                if low not in ("groups", "group", "groupinfo", "chat_group"):
                    continue
                cols = _low_cols(db, t)
                c_name = _col(cols, ["subject", "name", "title"])
                c_ct = _col(cols, ["created", "created_at", "creation_date", "date"])
                c_cnt = _col(cols, ["members", "member_count", "size"])
                for d in _stream(db, t):
                    dt, raw = norm_time(d.get(c_ct), "apple_s") if c_ct else (None, None)
                    out.append({
                        "name": _txt(d.get(c_name)) if c_name else None,
                        "jid": _txt(d.get(_col(cols, ["jid", "group_id", "id"])))
                        if _col(cols, ["jid", "group_id", "id"]) else None,
                        "created": dt, "created_raw": raw, "created_str": _tstr(dt),
                        "members": d.get(c_cnt) if c_cnt else None,
                        "source": "%s:%s" % (rel, t),
                    })
        if not out:
            self.notes.append("groups(%s): 未找到群组表" % pkg)
        return out


# ==========================================================================
# 订房
# ==========================================================================
class BookingApp(_AppBase):
    KIND = "booking"

    def bookings(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        fields = {
            "hotel": (["hotel_name", "hotel", "property_name", "property", "accommodation"], None),
            "check_in": (["check_in", "checkin", "arrival", "check_in_date", "from_date"], None),
            "check_out": (["check_out", "checkout", "departure", "check_out_date", "to_date"], None),
            "order_no": (["booking_id", "order_id", "confirmation_number", "booking_no",
                          "reservation_id", "order_no"], None),
            "amount": (["total_amount", "amount", "price", "total_price", "total"], None),
            "currency": (["currency", "currency_code", "ccy"], None),
            "guest": (["guest_name", "guest", "customer_name", "traveler_name", "name"], None),
            "time": (["created_at", "booking_date", "created", "timestamp"], None),
        }
        recs = self._harvest(pkg, fields, require=("hotel",),
                             name_hints=("booking", "order", "reservation", "hotel"),
                             min_fields=3)
        out = []
        for r in recs:
            out.append({
                "hotel": r.get("hotel"), "check_in": r.get("check_in"),
                "check_out": r.get("check_out"), "order_no": r.get("order_no"),
                "amount": _num(r.get("amount")), "currency": r.get("currency"),
                "guest": r.get("guest"), "booked_at": r.get("time"),
                "booked_at_raw": r.get("time_raw"), "source": "%s:%s" % (r["_rel"], r["_table"]),
            })
        if not out:
            self.notes.append("bookings(%s): 未匹配到含 hotel/check_in 列的表" % pkg)
        return out


# ==========================================================================
# 银行 / 支付
# ==========================================================================
class BankApp(_AppBase):
    KIND = "bank"

    def transactions(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        fields = {
            "time": (["txn_time", "transaction_time", "trans_time", "time", "date",
                      "timestamp", "created_at", "bill_date", "trade_time"], None),
            "amount": (["amount", "txn_amount", "trans_amount", "money", "value", "sum"], None),
            "currency": (["currency", "ccy", "currency_code"], None),
            "counterparty": (["counterparty", "payee", "merchant", "counter_party", "peer",
                              "to_account", "other_name", "opponent"], None),
            "memo": (["remark", "memo", "description", "summary", "narrative", "note",
                      "detail", "title"], None),
            "balance": (["balance", "available_balance", "after_balance"], None),
            "direction": (["direction", "dc_flag", "txn_type", "type", "in_out"], None),
        }
        recs = self._harvest(pkg, fields, require=("amount",),
                             name_hints=("txn", "transaction", "trans", "bill", "trade", "account"),
                             min_fields=2)
        out = []
        for r in recs:
            amt = _num(r.get("amount"))
            d = str(r.get("direction") or "").lower()
            if amt is None:
                continue
            if d in ("d", "debit", "expense", "支出", "out", "dr"):
                flow = "支出"
            elif d in ("c", "credit", "income", "收入", "in", "cr", "存入"):
                flow = "收入"
            else:
                flow = "收入" if amt >= 0 else "支出"
            out.append({
                "time": r.get("time"), "time_raw": r.get("time_raw"),
                "time_str": r.get("time_str"), "amount": amt, "currency": r.get("currency"),
                "counterparty": r.get("counterparty"), "memo": r.get("memo"),
                "balance": _num(r.get("balance")), "flow": flow,
                "source": "%s:%s" % (r["_rel"], r["_table"]),
            })
        if not out:
            self.notes.append("transactions(%s): 未匹配到含 amount 列的流水表" % pkg)
        return out


# ==========================================================================
# 笔记
# ==========================================================================
class NotesApp(_AppBase):
    KIND = "notes"

    def notes(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        fields = {
            "title": (["title", "subject", "name", "ztitle1", "note_title"], None),
            "body": (["content", "body", "text", "snippet", "note", "zcontent",
                      "zplaintext", "ztitle1"], None),
            "time": (["modified_at", "modified", "update_time", "last_modified", "mtime",
                      "zmodificationdate", "date_modified", "created_at", "time"], None),
            "locked": (["locked", "is_locked", "password_protected", "zispasswordprotected",
                        "is_password_protected", "lock", "encrypted", "zispinned"], None),
        }
        recs = self._harvest(pkg, fields, require=("title", "body"),
                             name_hints=("note", "memo", "notepad", "keep"),
                             min_fields=3)
        out = []
        for r in recs:
            lk = r.get("locked")
            if isinstance(lk, str):
                locked = lk.strip().lower() not in ("", "0", "no", "false", "null", "none")
            else:
                locked = bool(lk)
            out.append({
                "title": r.get("title"), "body": r.get("body"),
                "modified": r.get("time"), "modified_raw": r.get("time_raw"),
                "modified_str": r.get("time_str"), "locked": locked,
                "locked_raw": r.get("locked_raw") if "locked_raw" in r else lk,
                "source": "%s:%s" % (r["_rel"], r["_table"]),
            })
        if not out:
            self._log.append("notes(%s): 未匹配到含 title/content 列的表" % pkg)
        return out


# ==========================================================================
# 地图 / 站点
# ==========================================================================
class MapApp(_AppBase):
    KIND = "map"
    LAT = ["latitude", "lat", "geo_lat", "y", "wd", "point_y"]
    LON = ["longitude", "lon", "lng", "long", "x", "jd", "point_x"]

    def places(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        out = []
        for rel, db in self._dbs(pkg):
            for t in _table_names(db):
                cols = _low_cols(db, t)
                c_lat = _col(cols, self.LAT)
                c_lon = _col(cols, self.LON)
                if not (c_lat and c_lon):
                    continue
                used = {c_lat, c_lon}
                c_name = _col(cols, ["name", "title", "station_name", "stop_name", "place",
                                     "address", "label"], used)
                if c_name:
                    used.add(c_name)
                c_time = _col(cols, ["timestamp", "time", "date", "created_at", "visit_time"], used)
                if c_time:
                    used.add(c_time)
                c_kind = _col(cols, ["category", "kind", "type", "poi_type"], used)
                for d in _stream(db, t):
                    lat = _num(d.get(c_lat))
                    lon = _num(d.get(c_lon))
                    if lat is None or lon is None:
                        continue
                    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                        continue
                    dt, raw = norm_time(d.get(c_time)) if c_time else (None, None)
                    out.append({
                        "name": _txt(d.get(c_name)) if c_name else None,
                        "lat": lat, "lon": lon,
                        "time": dt, "time_raw": raw, "time_str": _tstr(dt),
                        "category": _txt(d.get(c_kind)) if c_kind else None,
                        "source": "%s:%s" % (rel, t), "table": t,
                    })
        if not out:
            self.notes.append("places(%s): 未找到含经纬度列的表" % pkg)
        return out

    def nearest(self, pkg, lat, lon, kind=None):
        places = self.places(pkg)
        if not places:
            return []
        res = []
        for p in places:
            if kind and kind.lower() not in (str(p.get("table", "")) + " " +
                                             str(p.get("category") or "") +
                                             " " + str(p.get("name") or "")).lower():
                continue
            d = _haversine(lat, lon, p["lat"], p["lon"])
            q = dict(p)
            q["distance_m"] = round(d, 1)
            res.append(q)
        res.sort(key=lambda x: x["distance_m"])
        if not res:
            self.notes.append("nearest(%s): kind=%r 过滤后无记录" % (pkg, kind))
        return res

    def photo_places(self, paths):
        """本地照片目录 → GPS（复用 mkit.stego.exif_all）。"""
        out = []
        for p in paths:
            try:
                r = exif_all(p)
            except Exception as e:      # noqa: BLE001
                self.notes.append("exif %s 失败: %s" % (p, e))
                continue
            g = r.get("gps") or {}
            if g.get("lat") is None:
                continue
            out.append({"path": p, "lat": g.get("lat"), "lon": g.get("lon"),
                        "time": (r.get("datetime") or {}).get("original"),
                        "camera": (r.get("camera") or {}).get("model")})
        return out


# ==========================================================================
# 电子书
# ==========================================================================
class EbookApp(_AppBase):
    KIND = "ebook"

    def books(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        out = []
        ann_by_key = {}
        dbs = self._dbs(pkg)
        # 先收集标注
        for rel, db in dbs:
            for t in _table_names(db):
                cols = _low_cols(db, t)
                c_text = _col(cols, ["selected_text", "highlight", "zannotationselectedtext",
                                     "text", "selectedtext"])
                if not c_text or "annotation" not in (t + rel).lower():
                    continue
                c_note = _col(cols, ["note", "zannotationnote", "comment"])
                c_key = _col(cols, ["asset_id", "zannotationassetid", "book_id", "bookid",
                                    "zassetid", "doc_id"])
                c_loc = _col(cols, ["location", "zannotationlocation", "page", "position"])
                c_time = _col(cols, ["date", "zannotationmodificationdate", "created_at"])
                for d in _stream(db, t):
                    dt, raw = norm_time(d.get(c_time), "apple_s") if c_time else (None, None)
                    a = {"text": _txt(d.get(c_text)),
                         "note": _txt(d.get(c_note)) if c_note else None,
                         "location": _txt(d.get(c_loc)) if c_loc else None,
                         "time": dt, "time_str": _tstr(dt),
                         "source": "%s:%s" % (rel, t)}
                    key = _txt(d.get(c_key)) if c_key else None
                    ann_by_key.setdefault(key, []).append(a)
                    ann_by_key.setdefault("*", []).append(a)
        for rel, db in dbs:
            for t in _table_names(db):
                cols = _low_cols(db, t)
                c_title = _col(cols, ["title", "ztitle", "book_name", "name"])
                c_path = _col(cols, ["path", "zpath", "file_path", "filepath", "url",
                                     "zassetid", "asset_id"])
                if not c_title:
                    continue
                if not (c_path or "book" in t.lower() or "library" in t.lower()):
                    continue
                c_author = _col(cols, ["author", "zauthor", "writer"])
                c_prog = _col(cols, ["reading_progress", "zreadingprogress", "progress",
                                     "percent", "zlastopeneddate"])
                c_pos = _col(cols, ["last_position", "zlastlocation", "position", "page",
                                    "zlastebookcurrentlocation"])
                c_time = _col(cols, ["zlastopeneddate", "last_read_time", "last_open_time",
                                     "date"])
                c_key = _col(cols, ["zassetid", "asset_id", "book_id", "bookid", "z_pk"])
                for d in _stream(db, t):
                    title = _txt(d.get(c_title))
                    if not title:
                        continue
                    key = _txt(d.get(c_key)) if c_key else None
                    p = _txt(d.get(c_path)) if c_path else None
                    fmt = None
                    if p:
                        m = re.search(r"\.([A-Za-z0-9]{2,5})$", p)
                        fmt = m.group(1).lower() if m else None
                    dt, raw = norm_time(d.get(c_time), "apple_s") if c_time else (None, None)
                    out.append({
                        "title": title,
                        "author": _txt(d.get(c_author)) if c_author else None,
                        "path": p, "format": fmt,
                        "last_position": _txt(d.get(c_pos)) if c_pos else None,
                        "progress": d.get(c_prog) if c_prog else None,
                        "last_read": dt, "last_read_str": _tstr(dt),
                        "annotations": ann_by_key.get(key) or ann_by_key.get("*", []),
                        "source": "%s:%s" % (rel, t),
                    })
        if not out:
            self.notes.append("books(%s): 未匹配到书库表" % pkg)
        return out


# ==========================================================================
# 日历
# ==========================================================================
class CalendarApp(_AppBase):
    KIND = "calendar"

    def events(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        out = []
        for rel, db in self._dbs(pkg):
            tabs = {t.lower(): t for t in _table_names(db)}
            att = {}
            if "attendees" in tabs:
                ac = _low_cols(db, tabs["attendees"])
                a_ev = _col(ac, ["event_id"])
                a_nm = _col(ac, ["attendeename", "name"])
                a_em = _col(ac, ["attendeeemail", "email"])
                for d in _stream(db, tabs["attendees"]):
                    att.setdefault(d.get(a_ev), []).append(
                        _txt(d.get(a_nm)) or _txt(d.get(a_em)) if (a_nm or a_em) else None)
            for t in _table_names(db):
                low = t.lower()
                cols = _low_cols(db, t)
                c_title = _col(cols, ["title", "summary", "name"])
                c_start = _col(cols, ["dtstart", "start", "start_time", "begins", "begin"])
                c_end = _col(cols, ["dtend", "end", "end_time", "ends"])
                if not (c_title and c_start):
                    if low not in ("events", "event", "calendar_events"):
                        continue
                    if not (c_title and c_start):
                        continue
                c_loc = _col(cols, ["eventlocation", "location", "place", "where"])
                c_desc = _col(cols, ["description", "desc", "memo"])
                c_id = _col(cols, ["_id", "id"])
                c_cal = _col(cols, ["calendar_id", "calendar"])
                for d in _stream(db, t):
                    dt1, raw1 = norm_time(d.get(c_start), "unix_ms")
                    dt2, raw2 = norm_time(d.get(c_end), "unix_ms") if c_end else (None, None)
                    out.append({
                        "title": _txt(d.get(c_title)),
                        "start": dt1, "start_raw": raw1, "start_str": _tstr(dt1),
                        "end": dt2, "end_raw": raw2, "end_str": _tstr(dt2),
                        "location": _txt(d.get(c_loc)) if c_loc else None,
                        "description": _txt(d.get(c_desc)) if c_desc else None,
                        "calendar_id": d.get(c_cal) if c_cal else None,
                        "attendees": att.get(d.get(c_id), []) if c_id else [],
                        "source": "%s:%s" % (rel, t),
                    })
        # .ics
        if r.dir is not None:
            for rel, n in r.list():
                if rel.lower().endswith(".ics"):
                    out.extend(self._parse_ics(r.read(rel), rel))
        if not out:
            self.notes.append("events(%s): 未匹配到日历表或 .ics" % pkg)
        return out

    def _parse_ics(self, data, rel):
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            return []
        text = re.sub(r"\r\n[ \t]", "", text)
        out = []
        cur = None
        for line in text.splitlines():
            if line == "BEGIN:VEVENT":
                cur = {"title": None, "start": None, "start_raw": None, "start_str": None,
                       "end": None, "end_raw": None, "end_str": None, "location": None,
                       "description": None, "attendees": [], "source": rel}
                continue
            if line == "END:VEVENT":
                if cur:
                    out.append(cur)
                cur = None
                continue
            if cur is None or ":" not in line:
                continue
            k, v = line.split(":", 1)
            key = k.split(";")[0].upper()
            if key == "SUMMARY":
                cur["title"] = v.strip()
            elif key in ("DTSTART", "DTSTAMP") and not cur["start"]:
                dt, raw = norm_time(v.strip().replace("Z", ""), "ics")
                cur["start"], cur["start_raw"] = dt, v
                cur["start_str"] = _tstr(dt)
            elif key == "DTEND":
                dt, raw = norm_time(v.strip().replace("Z", ""), "ics")
                cur["end"], cur["end_raw"] = dt, v
                cur["end_str"] = _tstr(dt)
            elif key == "LOCATION":
                cur["location"] = v.strip()
            elif key == "DESCRIPTION":
                cur["description"] = v.strip()
            elif key == "ATTENDEE":
                cur["attendees"].append(v.strip())
        return out


# ==========================================================================
# 电商 / 快递
# ==========================================================================
class ShoppingApp(_AppBase):
    KIND = "shopping"

    def orders(self, pkg):
        r = self._root(pkg)
        if not r.exists:
            return []
        fields = {
            "order_no": (["order_id", "order_no", "trade_no", "order_number", "tid",
                          "waybill", "tracking_no", "express_no"], None),
            "item": (["goods_name", "product_name", "item_name", "sku_name", "title",
                      "goods", "product", "shop_name"], None),
            "amount": (["pay_amount", "total_amount", "amount", "total_fee", "payment",
                        "price", "total"], None),
            "time": (["created_at", "create_time", "order_time", "pay_time", "time",
                      "date", "timestamp"], None),
            "address": (["address", "receiver_address", "ship_to", "consignee_address",
                         "delivery_address"], None),
            "status": (["status", "order_status", "state"], None),
            "consignee": (["consignee", "receiver", "buyer_name", "recipient"], None),
        }
        recs = self._harvest(pkg, fields, require=("order_no",),
                             name_hints=("order", "cart", "trade", "goods", "express",
                                         "waybill", "shipment"),
                             min_fields=2)
        out = []
        for r in recs:
            out.append({
                "order_no": r.get("order_no"), "item": r.get("item"),
                "amount": _num(r.get("amount")), "time": r.get("time"),
                "time_raw": r.get("time_raw"), "time_str": r.get("time_str"),
                "address": r.get("address"), "consignee": r.get("consignee"),
                "status": r.get("status"),
                "source": "%s:%s" % (r["_rel"], r["_table"]),
            })
        if not out:
            self.notes.append("orders(%s): 未匹配到含 order_id 列的表" % pkg)
        return out


# ==========================================================================
# 聚合入口
# ==========================================================================
class AppKit:
    """一次拿到全部解析器；.profile/.chat/.bank ... 直接可用。"""

    def __init__(self, fs, root=None):
        self.prof = AppProfiler(fs, root=root)
        self.notes = self.prof.notes
        self.chat = ChatApp(self.prof)
        self.booking = BookingApp(self.prof)
        self.bank = BankApp(self.prof)
        self.notes_app = NotesApp(self.prof)
        self.map = MapApp(self.prof)
        self.ebook = EbookApp(self.prof)
        self.calendar = CalendarApp(self.prof)
        self.shopping = ShoppingApp(self.prof)

    def any(self, pkg):
        return {
            "profile": self.prof.profile(pkg, deep=True),
            "messages": self.chat.messages(pkg),
            "groups": self.chat.groups(pkg),
            "bookings": self.booking.bookings(pkg),
            "transactions": self.bank.transactions(pkg),
            "notes": self.notes_app.notes(pkg),
            "places": self.map.places(pkg),
            "books": self.ebook.books(pkg),
            "events": self.calendar.events(pkg),
            "orders": self.shopping.orders(pkg),
        }


class AutoApp(_AppBase):
    """未知 App 兜底：只用 auto_scan 结果给出可读摘要。"""

    KIND = "unknown"

    def scan(self, pkg):
        return auto_scan(self.prof, pkg)
