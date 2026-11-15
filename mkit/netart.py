# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""自研 pcap/pcapng 解析与网络取证 —— 纯标准库。

覆盖：libpcap(us/ns)、pcapng、以太网/VLAN/IPv4/IPv6/TCP/UDP/DNS/HTTP/TLS SNI、
      TCP 流重组、HTTP 文件还原、802.11 wifi 分析、明文凭据提取。
"""
import datetime
import gzip
import io
import os
import struct
import zlib

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000000),
    b"\xa1\xb2\xc3\xd4": (">", 1000000),
    b"\x4d\x3c\xb2\xa1": ("<", 1000000000),
    b"\xa1\xb2\x3c\x4d": (">", 1000000000),
}


class Pkt:
    __slots__ = ("ts", "data", "linktype", "ifname", "num")

    def __init__(self, ts, data, linktype, ifname="", num=0):
        self.ts = ts
        self.data = data
        self.linktype = linktype
        self.ifname = ifname
        self.num = num


class Flow:
    """解出的一个网络层报文"""
    __slots__ = ("pkt", "eth_src", "eth_dst", "ethertype", "ip_src", "ip_dst", "proto",
                 "sport", "dport", "payload", "tcp_flags", "seq", "ack", "vlan", "raw_l4")

    def __repr__(self):
        return f"<{self.ip_src}:{self.sport} -> {self.ip_dst}:{self.dport} {self.proto} {len(self.payload or b'')}B>"


def _safe_dt(ts):
    """把秒级时间戳安全转 datetime；越界返回 None。"""
    try:
        if ts is None:
            return None
        if ts > 1e12:      # 明显是毫秒/微秒误判
            ts = ts / 1e3 if ts < 1e15 else ts / 1e6
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    except Exception:
        return None


def _ts(sec, frac, scale):
    return datetime.datetime.fromtimestamp(sec + frac / scale, datetime.timezone.utc)


class PcapReader:
    def __init__(self, path, max_packets=None):
        self.path = path
        self.max_packets = max_packets
        with open(path, "rb") as f:
            self.head = f.read(4)
        self.kind = "pcapng" if self.head == b"\x0a\x0d\x0d\x0a" else "pcap"

    def packets(self):
        if self.kind == "pcap":
            yield from self._pcap()
        else:
            yield from self._pcapng()

    def _pcap(self):
        with open(self.path, "rb") as f:
            head = f.read(24)
            magic = head[:4]
            if magic not in PCAP_MAGICS:
                raise ValueError("not a pcap file")
            endian, scale = PCAP_MAGICS[magic]
            linktype = struct.unpack_from(endian + "I", head, 20)[0]
            n = 0
            while True:
                if self.max_packets and n >= self.max_packets:
                    return
                hdr = f.read(16)
                if len(hdr) < 16:
                    return
                sec, frac, caplen, wirelen = struct.unpack(endian + "IIII", hdr)
                data = f.read(caplen)
                if len(data) < caplen:
                    return
                n += 1
                yield Pkt(_ts(sec, frac, scale), data, linktype, "", n)

    def _pcapng(self):
        with open(self.path, "rb") as f:
            endian = "<"
            linktypes = []
            ifaces = []
            self._tsresol = []
            n = 0
            while True:
                if self.max_packets and n >= self.max_packets:
                    return
                bh = f.read(8)
                if len(bh) < 8:
                    return
                btype = struct.unpack_from(endian + "I", bh, 0)[0]
                blen = struct.unpack_from(endian + "I", bh, 4)[0]
                if blen < 12 or blen > (1 << 28):
                    return
                body = f.read(blen - 12)
                if len(body) < blen - 12:
                    return
                f.read(4)
                if btype == 0x0A0D0D0A:
                    bom = body[:4]
                    endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                elif btype == 1:  # IDB
                    lt = struct.unpack_from(endian + "H", body, 0)[0]
                    linktypes.append(lt)
                    name = ""
                    tsresol = 6          # 默认微秒
                    o = 8
                    while o + 4 <= len(body):
                        code, ln = struct.unpack_from(endian + "HH", body, o)
                        if code == 0 or ln == 0:
                            break
                        val = body[o + 4: o + 4 + ln]
                        if code == 2:
                            name = val.decode("utf8", "replace").rstrip("\x00")
                        elif code == 9 and ln >= 1:      # if_tsresol
                            v = val[0]
                            tsresol = (v & 0x7F) if not (v & 0x80) else (1 << (v & 0x7F))
                        o += 4 + ((ln + 3) // 4) * 4
                    ifaces.append(name)
                    self._tsresol.append(tsresol if (tsresol and tsresol <= 9) else 6)
                elif btype == 6:  # EPB
                    iface, th, tl, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
                    data = body[20:20 + caplen]
                    raw_ts = (th << 32) | tl
                    res = self._tsresol[iface] if iface < len(self._tsresol) else 6
                    ts = raw_ts / (10 ** res) if isinstance(res, int) and res >= 0 else raw_ts / 1e6
                    n += 1
                    yield Pkt(_safe_dt(ts), data,
                              linktypes[iface] if iface < len(linktypes) else 1,
                              ifaces[iface] if iface < len(ifaces) else "", n)
                elif btype == 3:  # SPB
                    origlen = struct.unpack_from(endian + "I", body, 0)[0]
                    data = body[4:]
                    n += 1
                    yield Pkt(None, data, linktypes[0] if linktypes else 1, "", n)
                elif btype == 2:  # obsolete PB
                    iface, drops, th, tl, caplen, origlen = struct.unpack_from(endian + "HHIIII", body, 0)
                    data = body[20:20 + caplen]
                    raw_ts = (th << 32) | tl
                    ts = raw_ts / 1e6
                    n += 1
                    yield Pkt(_safe_dt(ts), data,
                              linktypes[iface] if iface < len(linktypes) else 1, "", n)


# ---------------- 协议解包 ----------------
def _ip(proto):
    return {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE"}.get(proto, str(proto))


def decode(pkt):
    """以太网/radiotap 帧 -> Flow 或 None"""
    d = pkt.data
    fl = Flow()
    fl.pkt = pkt
    fl.eth_src = fl.eth_dst = None
    fl.vlan = None
    fl.tcp_flags = 0
    fl.seq = fl.ack = 0
    fl.raw_l4 = b""
    off = 0
    if pkt.linktype == 1:      # Ethernet
        if len(d) < 14:
            return None
        fl.eth_dst = d[0:6].hex(":")
        fl.eth_src = d[6:12].hex(":")
        etype = struct.unpack_from(">H", d, 12)[0]
        off = 14
        while etype in (0x8100, 0x88A8):
            fl.vlan = struct.unpack_from(">H", d, off)[0] & 0xFFF
            etype = struct.unpack_from(">H", d, off + 2)[0]
            off += 4
        fl.ethertype = etype
    elif pkt.linktype in (113, 127, 276):   # Linux cooked v1/v2
        if len(d) < 16:
            return None
        fl.eth_src = fl.eth_dst = None
        fl.ethertype = struct.unpack_from(">H", d, 14)[0]
        off = 16
    elif pkt.linktype == 105:          # 802.11
        return _wifi_flow(pkt, d, fl)
    elif pkt.linktype in (101, 228, 229, 12, 14):
        # Raw IP / RAW / IPv4 / IPv6 —— 无链路层
        fl.eth_src = fl.eth_dst = None
        first = d[0] >> 4 if d else 0
        fl.ethertype = 0x0800 if first == 4 else (0x86DD if first == 6 else 0)
        off = 0
    else:
        return None

    if fl.ethertype == 0x0800:
        if len(d) < off + 20:
            return None
        ihl = (d[off] & 0x0F) * 4
        proto = d[off + 9]
        fl.proto = _ip(proto)
        fl.ip_src = ".".join(str(b) for b in d[off + 12: off + 16])
        fl.ip_dst = ".".join(str(b) for b in d[off + 16: off + 20])
        l4 = off + ihl
    elif fl.ethertype == 0x86DD:
        if len(d) < off + 40:
            return None
        nh = d[off + 6]
        fl.proto = _ip(nh)
        fl.ip_src = _ipv6(d[off + 8: off + 24])
        fl.ip_dst = _ipv6(d[off + 24: off + 40])
        l4 = off + 40
    elif fl.ethertype in (0x0806,):
        fl.proto = "ARP"
        fl.ip_src = fl.ip_dst = None
        fl.sport = fl.dport = None
        fl.payload = d[off:]
        return fl
    else:
        fl.proto = f"0x{fl.ethertype:04x}"
        fl.ip_src = fl.ip_dst = None
        fl.sport = fl.dport = None
        fl.payload = d[off:]
        return fl

    fl.raw_l4 = d[l4:]
    if fl.proto == "TCP":
        if len(d) < l4 + 20:
            return None
        fl.sport, fl.dport = struct.unpack_from(">HH", d, l4)
        doff = (d[l4 + 12] >> 4) * 4
        fl.tcp_flags = d[l4 + 13]
        fl.seq, fl.ack = struct.unpack_from(">II", d, l4 + 4)
        fl.payload = d[l4 + doff:]
    elif fl.proto == "UDP":
        if len(d) < l4 + 8:
            return None
        fl.sport, fl.dport = struct.unpack_from(">HH", d, l4)
        fl.payload = d[l4 + 8:]
    else:
        fl.sport = fl.dport = None
        fl.payload = d[l4:]
    return fl


def _ipv6(b):
    parts = [b[i:i + 2].hex() for i in range(0, 16, 2)]
    return ":".join(parts)


def _wifi_flow(pkt, d, fl):
    off = 0
    if len(d) > 4 and d[0:2] == b"\x00\x00":   # radiotap
        rl = struct.unpack_from("<H", d, 2)[0] if len(d) >= 4 else 0
        off = rl
    if len(d) < off + 24:
        return None
    fc = struct.unpack_from("<H", d, off)[0]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    fl.eth_src = d[off + 10: off + 16].hex(":")
    fl.eth_dst = d[off + 4: off + 10].hex(":")
    fl.proto = f"802.11 type{ftype} sub{subtype}"
    fl.ip_src = fl.ip_dst = None
    fl.sport = fl.dport = None
    fl.payload = d[off:]
    fl.raw_l4 = b""
    return fl


# ---------------- 应用层 ----------------
def http_extract(path, max_packets=None):
    out = []
    for pkt in PcapReader(path, max_packets).packets():
        fl = decode(pkt)
        if not fl or fl.proto != "TCP" or not fl.payload:
            continue
        if fl.sport not in (80, 8080, 8000, 8888) and fl.dport not in (80, 8080, 8000, 8888, 443):
            continue
        body = fl.payload
        if not body:
            continue
        if body[:1] in (b"G", b"P", b"H", b"D", b"O", b"T", b"C") and b" HTTP/" in body[:64]:
            head = body.split(b"\r\n\r\n", 1)
            lines = head[0].split(b"\r\n")
            req = lines[0].decode("latin1", "replace")
            hdrs = {}
            for ln in lines[1:]:
                if b":" in ln:
                    k, v = ln.split(b":", 1)
                    hdrs[k.strip().lower().decode("latin1")] = v.strip().decode("latin1", "replace")
            out.append(dict(kind="request", ts=fl.pkt.ts, src=fl.ip_src, dst=fl.ip_dst,
                            request=req, host=hdrs.get("host"), ua=hdrs.get("user-agent"),
                            referer=hdrs.get("referer"), cookie=hdrs.get("cookie"),
                            body_len=len(head[1]) if len(head) > 1 else 0,
                            body=(head[1] if len(head) > 1 else b"")[:4096]))
        elif body[:5] == b"HTTP/":
            head = body.split(b"\r\n\r\n", 1)
            lines = head[0].split(b"\r\n")
            st = lines[0].decode("latin1", "replace")
            hdrs = {}
            for ln in lines[1:]:
                if b":" in ln:
                    k, v = ln.split(b":", 1)
                    hdrs[k.strip().lower().decode("latin1")] = v.strip().decode("latin1", "replace")
            out.append(dict(kind="response", ts=fl.pkt.ts, src=fl.ip_src, dst=fl.ip_dst,
                            status=st, ctype=hdrs.get("content-type"),
                            body_len=len(head[1]) if len(head) > 1 else 0,
                            body=(head[1] if len(head) > 1 else b"")[:4096]))
    return out


def dns_extract(path, max_packets=None):
    out = []
    for pkt in PcapReader(path, max_packets).packets():
        fl = decode(pkt)
        if not fl or fl.proto != "UDP" or not fl.payload or len(fl.payload) < 12:
            continue
        if fl.sport != 53 and fl.dport != 53:
            continue
        q = _parse_dns(fl.payload)
        if q:
            q.update(ts=fl.pkt.ts, src=fl.ip_src, dst=fl.ip_dst)
            out.append(q)
    return out


def _parse_dns(b):
    try:
        tid, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", b, 0)
        off = 12
        names = []
        for _ in range(min(qd, 8)):
            name, off = _dns_name(b, off)
            qtype, qclass = struct.unpack_from(">HH", b, off)
            off += 4
            names.append((name, qtype))
        answers = []
        for _ in range(min(an, 16)):
            name, off = _dns_name(b, off)
            rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", b, off)
            off += 10
            rdata = b[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                answers.append((".".join(str(x) for x in rdata), name))
            elif rtype == 28 and rdlen == 16:
                answers.append((_ipv6(rdata), name))
            elif rtype == 5:
                tgt, _ = _dns_name(b, off - rdlen)
                answers.append((tgt, name))
        return dict(query=[n for n, t in names], qtype=[t for n, t in names],
                    answers=answers, is_response=bool(flags & 0x8000))
    except Exception:
        return None


def _dns_name(b, off):
    labels = []
    jumped = False
    start = off
    while True:
        if off >= len(b):
            break
        ln = b[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | b[off + 1]
            if not jumped:
                start = off + 2
            off = ptr
            jumped = True
            continue
        labels.append(b[off + 1: off + 1 + ln].decode("latin1", "replace"))
        off += 1 + ln
    return ".".join(labels), (start if jumped else off)


def tls_sni(path, max_packets=None):
    out = []
    for pkt in PcapReader(path, max_packets).packets():
        fl = decode(pkt)
        if not fl or fl.proto != "TCP" or not fl.payload or len(fl.payload) < 6:
            continue
        b = fl.payload
        if b[0] != 0x16 or b[5] != 0x01:
            continue
        sni, alpn = _tls_client_hello(b)
        out.append(dict(ts=fl.pkt.ts, src=fl.ip_src, dst=fl.ip_dst, dport=fl.dport,
                        sni=sni, alpn=alpn))
    return out


def _tls_client_hello(b):
    try:
        p = 5 + 4 + 2 + 32
        sid_len = b[p]
        p += 1 + sid_len
        cs_len = struct.unpack_from(">H", b, p)[0]
        p += 2 + cs_len
        cm_len = b[p]
        p += 1 + cm_len
        ext_len = struct.unpack_from(">H", b, p)[0]
        p += 2
        end = min(len(b), p + ext_len)
        sni = None
        alpn = []
        while p + 4 <= end:
            etype, elen = struct.unpack_from(">HH", b, p)
            p += 4
            edata = b[p:p + elen]
            p += elen
            if etype == 0 and len(edata) > 5:
                nlen = struct.unpack_from(">H", edata, 3)[0]
                sni = edata[5:5 + nlen].decode("latin1", "replace")
            elif etype == 16 and len(edata) > 2:
                q = 2
                while q < len(edata):
                    ln = edata[q]
                    alpn.append(edata[q + 1: q + 1 + ln].decode("latin1", "replace"))
                    q += 1 + ln
        return sni, alpn
    except Exception:
        return None, []


def tcp_streams(path, max_packets=None):
    """按 (src,dst,sport,dport) 单向重组，返回 {(k): bytearray}"""
    streams = {}
    expected = {}
    for pkt in PcapReader(path, max_packets).packets():
        fl = decode(pkt)
        if not fl or fl.proto != "TCP" or not fl.payload:
            continue
        k = (fl.ip_src, fl.ip_dst, fl.sport, fl.dport)
        buf = streams.setdefault(k, bytearray())
        exp = expected.get(k)
        if exp is None or fl.seq == exp:
            buf += fl.payload
            expected[k] = fl.seq + len(fl.payload)
        elif fl.seq > exp:
            streams.setdefault(k, bytearray())
        else:
            overlap = exp - fl.seq
            if overlap < len(fl.payload):
                buf += fl.payload[overlap:]
                expected[k] = fl.seq + len(fl.payload)
    return streams


SIGS = {
    b"\xff\xd8\xff": "jpg", b"\x89PNG": "png", b"%PDF": "pdf", b"PK\x03\x04": "zip",
    b"GIF8": "gif", b"MZ": "exe", b"\x1f\x8b": "gz", b"Rar!": "rar", b"7z\xbc\xaf": "7z",
    b"SQLite format 3": "sqlite", b"RIFF": "riff",
}


def extract_files(path, outdir, min_size=1024, max_packets=None):
    os.makedirs(outdir, exist_ok=True)
    found = []
    streams = tcp_streams(path, max_packets)
    for k, buf in streams.items():
        data = bytes(buf)
        for i in range(0, max(0, len(data) - 4)):
            for sig, ext in SIGS.items():
                if data[i:i + len(sig)] == sig:
                    if len(data) - i < min_size:
                        continue
                    out = os.path.join(outdir, f"{k[0]}_{k[2]}_{i}.{ext}")
                    with open(out, "wb") as f:
                        f.write(data[i:])
                    found.append(dict(path=out, stream=k, offset=i, sig=ext, size=len(data) - i))
                    break
    return found


def creds_in_plaintext(path, max_packets=None):
    hits = []
    kw = (b"password", b"passwd", b"pwd", b"user=", b"username", b"login", b"card",
          b"cvv", b"USER ", b"PASS ")
    for pkt in PcapReader(path, max_packets).packets():
        fl = decode(pkt)
        if not fl or not fl.payload:
            continue
        low = fl.payload.lower()
        if any(k.lower() in low for k in kw):
            hits.append(dict(ts=fl.pkt.ts, src=fl.ip_src, dst=fl.ip_dst,
                             sport=fl.sport, dport=fl.dport, proto=fl.proto,
                             payload=fl.payload[:800]))
    return hits


def wifi_from_pcap(path, max_packets=None):
    bssids = {}
    eapol = 0
    deauth = 0
    probes = set()
    for pkt in PcapReader(path, max_packets).packets():
        d = pkt.data
        off = 0
        if len(d) > 4 and d[0:2] == b"\x00\x00":
            off = struct.unpack_from("<H", d, 2)[0] if len(d) >= 4 else 0
        if len(d) < off + 24:
            continue
        fc = struct.unpack_from("<H", d, off)[0]
        ftype = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xF
        bssid = d[off + 16: off + 22].hex(":") if len(d) >= off + 22 else ""
        if ftype == 0 and subtype == 8:   # beacon
            ssid, ch = _ssid_from_beacon(d[off + 24:])
            rec = bssids.setdefault(bssid, dict(ssid=ssid, ch=ch, beacons=0, eapol=0))
            rec["beacons"] += 1
        elif ftype == 0 and subtype == 12:  # deauth
            deauth += 1
        elif ftype == 0 and subtype == 4:   # probe request
            ssid, _ = _ssid_from_beacon(d[off + 24:])
            if ssid:
                probes.add(ssid)
        elif ftype == 2 and len(d) > off + 24:
            # 检查 LLC SNAP -> EAPOL(0x888e)
            p = off + 24
            if len(d) > p + 8 and d[p + 6: p + 8] == b"\x88\x8e":
                eapol += 1
                if bssid in bssids:
                    bssids[bssid]["eapol"] += 1
    return dict(bssids=bssids, eapol_frames=eapol, deauth_frames=deauth,
                probe_ssids=sorted(probes),
                handshake_ready=eapol >= 4)


def _ssid_from_beacon(b):
    try:
        p = 12  # timestamp(8)+interval(2)+cap(2)
        while p + 2 <= len(b):
            eid = b[p]
            elen = b[p + 1]
            val = b[p + 2: p + 2 + elen]
            if eid == 0:
                return val.decode("utf8", "replace"), None
            if eid == 3 and elen >= 1:
                return None, val[0]
            p += 2 + elen
    except Exception:
        pass
    return None, None


def rogue_ap_hints(path, max_packets=None):
    w = wifi_from_pcap(path, max_packets)
    ssid_map = {}
    for bssid, rec in w["bssids"].items():
        ssid_map.setdefault(rec["ssid"], []).append(bssid)
    twins = {s: b for s, b in ssid_map.items() if s and len(b) > 1}
    return dict(eviltwin_candidates=twins, deauth_frames=w["deauth_frames"],
                probe_ssids=w["probe_ssids"], handshake_ready=w["handshake_ready"],
                total_ap=len(w["bssids"]))
