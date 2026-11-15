# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""联网即查（明天可联网时用）：区块链 / IP / 域名 / 哈希 / 搜索。

只用标准库 urllib；所有函数失败时返回 dict(error=...) 而不抛异常。
无需 API Key 的端点优先。
"""
import json
import socket
import ssl
import urllib.parse
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) forensic-toolkit/1.0"}
TIMEOUT = 20


def _get(url, headers=None, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read()


def _json(url, headers=None, timeout=TIMEOUT):
    return json.loads(_get(url, headers, timeout).decode("utf8", "replace"))


# ---------------- 区块链 ----------------
def btc_address(addr, limit=50):
    """BTC 地址余额与交易（blockstream.info 公共接口，稳定）。"""
    try:
        info = _json(f"https://blockstream.info/api/address/{addr}")
        cs = info.get("chain_stats", {})
        ms = info.get("mempool_stats", {})
        txs = _json(f"https://blockstream.info/api/address/{addr}/txs")
        return dict(address=addr,
                    funded_btc=cs.get("funded_txo_sum", 0) / 1e8,
                    spent_btc=cs.get("spent_txo_sum", 0) / 1e8,
                    balance_btc=(cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)) / 1e8,
                    n_tx=cs.get("tx_count"),
                    mempool_tx=ms.get("tx_count"),
                    txs=[dict(txid=t.get("txid"), status=t.get("status", {}).get("block_time"))
                         for t in (txs if isinstance(txs, list) else [])])
    except Exception as e:
        return dict(address=addr, error=str(e))


def btc_tx(txid):
    try:
        t = _json(f"https://blockstream.info/api/tx/{txid}")
        return dict(txid=txid, status=t.get("status", {}).get("block_time"),
                    vin=[dict(addr=v.get("prevout", {}).get("scriptpubkey_address"),
                              value=v.get("prevout", {}).get("value", 0) / 1e8)
                         for v in t.get("vin", [])],
                    vout=[dict(addr=o.get("scriptpubkey_address"),
                               value=o.get("value", 0) / 1e8) for o in t.get("vout", [])])
    except Exception as e:
        return dict(txid=txid, error=str(e))


def eth_address(addr):
    """ETH 地址余额/交易数（需 Etherscan API Key；无 key 则用公共 RPC）。"""
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                           "params": [addr, "latest"]}).encode()
        req = urllib.request.Request("https://cloudflare-eth.com", data=body,
                                     headers={**UA, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            bal = json.loads(r.read().decode())
        body2 = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount",
                            "params": [addr, "latest"]}).encode()
        req2 = urllib.request.Request("https://cloudflare-eth.com", data=body2,
                                      headers={**UA, "Content-Type": "application/json"})
        with urllib.request.urlopen(req2, timeout=TIMEOUT) as r:
            nonce = json.loads(r.read().decode())
        hexbal = int(bal.get("result", "0x0"), 16) if bal.get("result") else 0
        return dict(address=addr, balance_wei=hexbal, balance_eth=hexbal / 1e18,
                    nonce=int(nonce.get("result", "0x0"), 16) if nonce.get("result") else None)
    except Exception as e:
        return dict(address=addr, error=str(e))


def eth_token_transfers(addr, api_key=""):
    """ERC20 转账（Etherscan，需 key）。"""
    if not api_key:
        return dict(address=addr, error="需要 Etherscan API Key")
    try:
        u = ("https://api.etherscan.io/api?module=account&action=tokentx"
             f"&address={addr}&page=1&offset=100&sort=desc&apikey={api_key}")
        return _json(u)
    except Exception as e:
        return dict(address=addr, error=str(e))


def tron_address(addr):
    try:
        return _json(f"https://apilist.tronscanapi.com/api/account?address={addr}")
    except Exception as e:
        return dict(address=addr, error=str(e))


# ---------------- IP / 域名 ----------------
def ip_info(ip):
    try:
        d = _json(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query,timezone")
        return d
    except Exception as e:
        return dict(query=ip, error=str(e))


def ip_batch(ips):
    try:
        payload = json.dumps([{"query": i, "fields": "status,country,regionName,city,isp,org,query"}
                              for i in ips]).encode()
        req = urllib.request.Request("http://ip-api.com/batch", data=payload,
                                     headers={**UA, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return [dict(error=str(e))]


def dns_lookup(name):
    out = {}
    try:
        out["A"] = sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET)})
    except Exception as e:
        out["A_error"] = str(e)
    try:
        out["AAAA"] = sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET6)})
    except Exception:
        pass
    return out


def whois_domain(domain):
    """RDAP（结构化 JSON，比 whois 端口稳）。"""
    try:
        d = _json(f"https://rdap.org/domain/{domain}")
        out = dict(domain=domain, handle=d.get("handle"))
        for e in d.get("events", []):
            out[e.get("eventAction")] = e.get("eventDate")
        for ent in d.get("entities", []):
            v = ent.get("vcardArray")
            if v and len(v) > 1:
                for item in v[1]:
                    if item[0] in ("fn", "email"):
                        out.setdefault(item[0], item[3])
        out["nameservers"] = [n.get("ldhName") for n in d.get("nameservers", [])]
        return out
    except Exception as e:
        return dict(domain=domain, error=str(e))


def whois_ip(ip):
    try:
        d = _json(f"https://rdap.org/ip/{ip}")
        return dict(ip=ip, handle=d.get("handle"), name=d.get("name"),
                    start=d.get("startAddress"), end=d.get("endAddress"),
                    country=d.get("country"), type=d.get("type"))
    except Exception as e:
        return dict(ip=ip, error=str(e))


def url_headers(url):
    """取 HTTP 响应头（判断站点框架/服务器）。"""
    try:
        req = urllib.request.Request(url, headers=UA)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return dict(status=r.status, headers=dict(r.headers), final_url=r.geturl())
    except Exception as e:
        return dict(url=url, error=str(e))


def fetch_text(url, limit=200000):
    try:
        return _get(url)[:limit].decode("utf8", "replace")
    except Exception as e:
        return f"ERROR: {e}"


# ---------------- 检索类 ----------------
def search_web(query, engine="duckduckgo"):
    """轻量网页检索（HTML 端点，返回标题+链接）。"""
    try:
        q = urllib.parse.quote(query)
        if engine == "bing":
            url = f"https://www.bing.com/search?q={q}"
        elif engine == "sogou":
            url = f"https://www.sogou.com/web?query={q}"
        else:
            url = f"https://html.duckduckgo.com/html/?q={q}"
        html = _get(url).decode("utf8", "replace")
        import re
        out = []
        for m in re.finditer(r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html, re.S):
            out.append(dict(url=urllib.parse.unquote(m.group(1)),
                            title=re.sub("<[^>]+>", "", m.group(2))[:120]))
        if not out:
            for m in re.finditer(r'<h2><a href="([^"]+)"[^>]*>(.*?)</a></h2>', html, re.S):
                out.append(dict(url=m.group(1), title=re.sub("<[^>]+>", "", m.group(2))[:120]))
        return out[:15]
    except Exception as e:
        return [dict(error=str(e))]


def app_package(pkg):
    """查 Android 包名（Play 商店页面标题）。"""
    try:
        html = _get(f"https://play.google.com/store/apps/details?id={pkg}&hl=zh-CN").decode("utf8", "replace")
        import re
        m = re.search(r"<title>(.*?)</title>", html, re.S)
        dev = re.search(r'href="/store/apps/dev(?:eloper)?\?id=([^"]+)"', html)
        return dict(package=pkg, title=(m.group(1).split(" - ")[0] if m else None),
                    developer=dev.group(1) if dev else None)
    except Exception as e:
        return dict(package=pkg, error=str(e))


def cve_lookup(keyword):
    """文件/组件 -> CVE（NVD 关键词检索）。"""
    try:
        u = ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
             + urllib.parse.quote(keyword) + "&resultsPerPage=10")
        d = _json(u, timeout=30)
        out = []
        for v in d.get("vulnerabilities", []):
            c = v["cve"]
            desc = ""
            for dd in c.get("descriptions", []):
                if dd.get("lang") == "en":
                    desc = dd.get("value", "")
                    break
            out.append(dict(id=c.get("id"), published=c.get("published"), desc=desc[:200]))
        return out
    except Exception as e:
        return [dict(error=str(e))]


def timestamp_decode(ts):
    """多单位时间戳解码（秒/毫秒/微秒/WebKit/FILETIME/纳秒），越界只跳过。"""
    import datetime
    ts = int(ts)
    out = {}
    base1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

    def safe(label, fn):
        try:
            out[label] = str(fn())
        except Exception:
            pass

    if ts > 1e17:
        safe("filetime", lambda: base1601 + datetime.timedelta(microseconds=ts / 10))
    if ts > 1e14:
        safe("webkit_us", lambda: base1601 + datetime.timedelta(microseconds=ts))
    if 1e11 < ts < 1e14:
        safe("unix_ms", lambda: datetime.datetime.fromtimestamp(ts / 1000, datetime.timezone.utc))
    if 1e8 < ts < 1e11:
        safe("unix_s", lambda: datetime.datetime.fromtimestamp(ts, datetime.timezone.utc))
    for off in (8, 0):
        tz = datetime.timezone(datetime.timedelta(hours=off))

        def f(tz=tz):
            v = ts / 1000 if 1e11 < ts < 1e14 else ts
            return datetime.datetime.fromtimestamp(v, tz)
        safe(f"utc{off:+d}", f)
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: python -m mkit.online <ip|domain|btc|eth|ts> <value>")
        raise SystemExit(0)
    cmd, val = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
    fn = {"ip": ip_info, "domain": whois_domain, "btc": btc_address,
          "eth": eth_address, "ts": timestamp_decode, "app": app_package,
          "search": search_web}.get(cmd)
    print(json.dumps(fn(val), ensure_ascii=False, indent=2) if fn else "unknown cmd")
