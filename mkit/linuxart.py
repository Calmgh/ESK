# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""自研 Linux 服务器取证痕迹解析 —— 纯标准库。

覆盖：
  * LVM2 元数据（/etc/lvm/backup/*、/etc/lvm/archive/*.vg）：VG/PV/LV/PE 大小、
    容量、分配百分比、df 记录里的使用百分比、激活命令
  * os-release / issue / 内核版本痕迹
  * /etc/passwd + /etc/shadow(算法识别) + /etc/group、sudoers
  * sshd 日志（/var/log/secure、auth.log、gz 与轮转）+ 自研 utmp/wtmp(384B) 解析
  * bash_history（#时间戳注释）、cron、systemd unit(ExecStart)
  * Docker config.v2.json、nginx/apache 配置与 access.log(combined/common)、
    攻击特征识别（SQL 注入 / 路径穿越 / 扫描器 UA）
  * MySQL 配置、数据目录、.sql dump、mdadm RAID、SUID 扫描、
    hosts/resolv.conf/nsswitch.conf、Radicale/Nextcloud .ics 日历

依赖：标准库（datetime/gzip/json/re/struct/zlib）。
全部方法在文件缺失时返回空值并把原因写入 self.notes，不抛异常。

utmp 结构说明（x86_64 glibc，记录 384 字节）：
    ut_type@0(2s) ut_pid@4(i) ut_line@8(32s) ut_id@40(4s) ut_user@44(32s)
    ut_host@76(256s) ut_exit@332(2h) ut_session@336(i) ut_tv@340(i sec, i usec)
    ut_addr_v6@348(4i)
题面常把 ut_addr_v6 记成 344（把 ut_tv 当 4 字节），实际 glibc 在 348；
本模块按 348 解析，同时把 344 处的原始 4 字节留在 addr_alt 字段备查。
"""
import bz2
import datetime
import gzip
import json
import lzma
import re
import struct
import zlib

UTMP_REC = 384

UT_TYPE_NAMES = {
    0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
    5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}

SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp/.X11-unix"}

SUID_SCAN_SKIP = {"/proc", "/sys", "/dev", "/run", "/boot", "/usr/share/doc",
                  "/usr/share/man", "/usr/share/locale"}

SIZE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


# --------------------------------------------------------------------------
# 通用工具
# --------------------------------------------------------------------------
def human_size(n):
    """字节数转人类可读。"""
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return str(n)
    neg = n < 0
    n = abs(n)
    for unit in SIZE_UNITS:
        if n < 1024.0 or unit == SIZE_UNITS[-1]:
            if unit == "B":
                s = "%d B" % int(n)
            else:
                s = "%.2f %s" % (n, unit)
            return ("-" + s) if neg else s
        n /= 1024.0
    return "%.2f PiB" % n


def decode_text(data):
    """尽力把字节解成文本（utf-8 → utf-16(BOM) → latin1）。"""
    if data is None:
        return None
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin1")


def gunzip(data):
    """gz 解压；文件被截断时尽量救回可解部分。"""
    if not data:
        return b""
    if data[:2] != b"\x1f\x8b":
        return data
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data)
        try:
            out += d.flush()
        except Exception:
            pass
        return out
    except Exception:
        return b""


def _decompress_any(data, path=""):
    """按后缀/魔数解 gz / bz2 / xz（截断时尽量返回可解部分）。"""
    if not data:
        return b""
    if data[:2] == b"\x1f\x8b" or path.endswith(".gz"):
        return gunzip(data)
    if data[:3] == b"BZh" or path.endswith(".bz2"):
        try:
            return bz2.decompress(data)
        except Exception:
            try:
                d = bz2.BZ2Decompressor()
                return d.decompress(data)
            except Exception:
                return data
    if data[:6] == b"\xfd7zXZ\x00" or path.endswith(".xz"):
        try:
            return lzma.decompress(data)
        except Exception:
            try:
                d = lzma.LZMADecompressor()
                return d.decompress(data)
            except Exception:
                return data
    return data


def _attr(ino, name, default=False):
    """兼容属性/方法两种 inode 实现。"""
    v = getattr(ino, name, default)
    if callable(v):
        try:
            return v()
        except Exception:
            return default
    return v if v is not None else default


def _is_dir(ino):
    return bool(ino is not None and _attr(ino, "is_dir"))


def _is_file(ino):
    if ino is None:
        return False
    if hasattr(ino, "is_file"):
        return bool(_attr(ino, "is_file"))
    return not _is_dir(ino)


def _is_link(ino):
    return bool(ino is not None and _attr(ino, "is_link"))


def _ino_size(ino):
    try:
        return int(getattr(ino, "size", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _ino_mtime(ino):
    for attr in ("mtime", "ctime"):
        v = getattr(ino, attr, None)
        if isinstance(v, datetime.datetime):
            return v
    return None


def _dt(ts):
    """unix 秒 → UTC datetime。"""
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return None
    if ts <= 0 or ts > 4102444800:      # 2100-01-01
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(dt, datetime.datetime) else None


def _dtkey(dt):
    """排序用：aware 统一折算成 UTC naive，naive 原样。"""
    if not isinstance(dt, datetime.datetime):
        return datetime.datetime.min
    if dt.tzinfo is not None:
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


def _days(v):
    """shadow 的日期字段是「自 1970-01-01 的天数」，不是秒。"""
    try:
        d = int(v)
    except (TypeError, ValueError):
        return None
    if d <= 0:
        return None
    return _dt(d * 86400)


def _cstr(raw):
    return decode_text(raw.split(b"\x00")[0]).strip()


# --------------------------------------------------------------------------
# utmp / wtmp
# --------------------------------------------------------------------------
def parse_utmp(data, rec_size=None):
    """解析 utmp/wtmp/btmp 二进制。返回记录 dict 列表。"""
    out = []
    if not data:
        return out
    total = len(data)
    if not rec_size:
        rec_size = UTMP_REC
        for cand in (384, 380, 392, 396):
            if total % cand == 0:
                rec_size = cand
                break
    for off in range(0, total - rec_size + 1, rec_size):
        rec = data[off:off + rec_size]
        if len(rec) < 348:
            break
        ut_type, pid = struct.unpack_from("<hi", rec, 0)
        if ut_type < 0 or ut_type > 9:
            # 不是合法记录（多为文件尾部残片）
            continue
        eterm, eexit = struct.unpack_from("<hh", rec, 332)
        session, sec, usec = struct.unpack_from("<iii", rec, 336)
        if usec < 0 or usec > 1000000:
            usec = 0
        addr = struct.unpack_from("<4I", rec, 348)
        ip = None
        if addr[0] and not (addr[1] or addr[2] or addr[3]):
            ip = "%d.%d.%d.%d" % (addr[0] & 0xFF, (addr[0] >> 8) & 0xFF,
                                  (addr[0] >> 16) & 0xFF, (addr[0] >> 24) & 0xFF)
        elif addr[3] and not (addr[0] or addr[1]) and addr[2] == 0xFFFF:
            ip = "%d.%d.%d.%d" % (addr[3] & 0xFF, (addr[3] >> 8) & 0xFF,
                                  (addr[3] >> 16) & 0xFF, (addr[3] >> 24) & 0xFF)
        out.append(dict(
            offset=off,
            type=ut_type,
            type_name=UT_TYPE_NAMES.get(ut_type, str(ut_type)),
            pid=pid,
            line=_cstr(rec[8:40]),
            id=_cstr(rec[40:44]),
            user=_cstr(rec[44:76]),
            host=_cstr(rec[76:332]),
            exit=dict(termination=eterm, exit=eexit),
            session=session,
            sec=sec,
            usec=usec,
            time=_dt(sec),
            ip=ip,
            addr_alt=rec[344:348].hex(),
        ))
    return out


# --------------------------------------------------------------------------
# LVM2 文本元数据
# --------------------------------------------------------------------------
def _strip_lvm_comment(line):
    """去掉行内 # 注释（引号内不算）。"""
    out = []
    q = False
    for ch in line:
        if ch == '"':
            q = not q
        if ch == "#" and not q:
            break
        out.append(ch)
    return "".join(out).rstrip()


def _lvm_value(text):
    text = text.strip()
    if not text:
        return ""
    if text[0] == '"':
        end = text.rfind('"')
        return text[1:end] if end > 0 else text[1:]
    if text[0] == "[":
        inner = text[1:text.rfind("]")] if "]" in text else text[1:]
        items = []
        for part in inner.split(","):
            part = part.strip()
            if not part:
                continue
            if part[0] == '"':
                items.append(part[1:part.rfind('"')] if part.rfind('"') > 0 else part[1:])
            else:
                try:
                    items.append(int(part))
                except ValueError:
                    items.append(part)
        return items
    try:
        return int(text, 0)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return text


def parse_lvm_metadata(text):
    """解析 vgcfgbackup / archive 文本。返回 {内容键..., '<VG名>': {...}}"""
    root = {}
    stack = [root]
    pending_key = None
    pending_buf = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = _strip_lvm_comment(raw).strip()
        if pending_key is not None:
            if line:
                pending_buf.append(line)
            joined = " ".join(pending_buf)
            if "]" in joined:
                stack[-1][pending_key] = _lvm_value(joined)
                pending_key, pending_buf = None, []
            continue
        if not line:
            continue
        if line.startswith("}"):
            if len(stack) > 1:
                stack.pop()
            continue
        if line.endswith("{"):
            name = line[:-1].strip().strip('"')
            child = {}
            stack[-1][name] = child
            stack.append(child)
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            key = k.strip()
            if v.strip().startswith("[") and "]" not in v:
                pending_key = key
                pending_buf = [v.strip()]
                continue
            stack[-1][key] = _lvm_value(v)
    return root


def _lvm_vg_names(meta):
    """从解析结果里挑出 VG 块（含 extent_size 或 physical_volumes）。"""
    names = []
    for k, v in meta.items():
        if isinstance(v, dict) and ("extent_size" in v or "physical_volumes" in v
                                    or "logical_volumes" in v):
            names.append(k)
    return names


class Lvm:
    """LVM2 元数据解析（backup + archive）。"""

    BACKUP_DIR = "/etc/lvm/backup"
    ARCHIVE_DIR = "/etc/lvm/archive"
    META_READ_LIMIT = 4 * 1024 * 1024

    def __init__(self, fs):
        self.fs = fs
        self.notes = []
        self.files = []          # [{path, kind, vg, seqno, creation_time}]
        self.history = {}        # vg -> [meta dict...]（按 seqno 升序）
        self.vgs = {}            # vg -> 最新 meta
        self._df_cache = None
        self._mount_cache = None
        self._load()

    # ---------- 底层 ----------
    def _names(self, path):
        ino = fs_lookup(self.fs, path)
        if ino is None or not _is_dir(ino):
            return []
        try:
            return [e.name for e in self.fs.listdir(ino)]
        except Exception as exc:
            self.notes.append("列目录失败 %s: %s" % (path, exc))
            return []

    def _text(self, path):
        data = fs_read(self.fs, path, self.META_READ_LIMIT)
        if data is None:
            return None
        if path.endswith(".gz") or data[:2] == b"\x1f\x8b":
            data = gunzip(data)
        return decode_text(data)

    # ---------- 装载 ----------
    def _load(self):
        found_any = False
        for d, kind in ((self.BACKUP_DIR, "backup"), (self.ARCHIVE_DIR, "archive")):
            names = self._names(d)
            if not names:
                continue
            found_any = True
            for nm in sorted(names):
                if kind == "archive" and not nm.endswith(".vg"):
                    continue
                path = d + "/" + nm
                txt = self._text(path)
                if not txt:
                    self.notes.append("无法读取 LVM 元数据 %s" % path)
                    continue
                self._add_meta(path, kind, txt)
        if not found_any:
            self.notes.append("未找到 %s 与 %s" % (self.BACKUP_DIR, self.ARCHIVE_DIR))
        for vg, items in self.history.items():
            items.sort(key=lambda m: (m.get("seqno") or 0, m.get("creation_time") or 0))
            self.vgs[vg] = items[-1]

    def _add_meta(self, path, kind, txt):
        try:
            meta = parse_lvm_metadata(txt)
        except Exception as exc:
            self.notes.append("LVM 元数据解析失败 %s: %s" % (path, exc))
            return
        names = _lvm_vg_names(meta)
        if not names:
            self.notes.append("LVM 元数据无 VG 块: %s" % path)
            return
        for vg in names:
            body = meta[vg]
            body["_path"] = path
            body["_kind"] = kind
            body["_file_meta"] = {k: meta[k] for k in
                                  ("contents", "version", "description", "creation_host",
                                   "creation_time") if k in meta}
            self.files.append(dict(path=path, kind=kind, vg=vg,
                                   seqno=body.get("seqno"),
                                   creation_time=meta.get("creation_time"),
                                   creation_host=meta.get("creation_host")))
            self.history.setdefault(vg, []).append(body)

    # ---------- 计算 ----------
    @staticmethod
    def _pe_size(vg):
        """extent_size 单位是 512B 扇区。"""
        try:
            return int(vg.get("extent_size") or 0) * 512
        except (TypeError, ValueError):
            return 0

    def _pvs(self, vg):
        out = []
        for name, pv in (vg.get("physical_volumes") or {}).items():
            if not isinstance(pv, dict):
                continue
            pe = int(pv.get("pe_count") or 0)
            out.append(dict(name=name, device=pv.get("device"), pe_count=pe,
                            pe_start=pv.get("pe_start"),
                            dev_size=int(pv.get("dev_size") or 0) * 512,
                            bytes=pe * self._pe_size(vg),
                            status=pv.get("status") or [], pv_id=pv.get("id")))
        return out

    def _lv_size(self, vg, lv):
        pe = self._pe_size(vg)
        total = 0
        for key in lv:
            if re.fullmatch(r"segment\d+", key or ""):
                seg = lv[key]
                if isinstance(seg, dict):
                    total += int(seg.get("extent_count") or 0)
        return total * pe, total

    def volume_groups(self):
        out = []
        for name, vg in self.vgs.items():
            pvs = self._pvs(vg)
            pe = self._pe_size(vg)
            total = sum(p["bytes"] for p in pvs)
            lvs = [k for k, v in (vg.get("logical_volumes") or {}).items()
                   if isinstance(v, dict)]
            meta = vg.get("_file_meta") or {}
            out.append(dict(
                name=name,
                vg_id=vg.get("id"),
                seqno=vg.get("seqno"),
                format=vg.get("format"),
                status=vg.get("status") or [],
                flags=vg.get("flags") or [],
                pe_size=pe,
                pe_size_human=human_size(pe),
                pe_total=sum(p["pe_count"] for p in pvs),
                pv_count=len(pvs),
                pvs=pvs,
                lv_count=len(lvs),
                lvs=lvs,
                total_bytes=total,
                total_human=human_size(total),
                max_lv=vg.get("max_lv"),
                max_pv=vg.get("max_pv"),
                metadata_copies=vg.get("metadata_copies"),
                creation_host=meta.get("creation_host"),
                creation_time=_dt(meta.get("creation_time")),
                source=vg.get("_path"),
                source_kind=vg.get("_kind"),
                archive_copies=[dict(path=f["path"], seqno=f["seqno"],
                                     creation_time=_dt(f["creation_time"]))
                                for f in self.files if f["vg"] == name],
            ))
        return out

    def logical_volumes(self):
        out = []
        mounts = self._mounts()
        df = self._df_records()
        for name, vg in self.vgs.items():
            pe = self._pe_size(vg)
            pvs = self._pvs(vg)
            vg_bytes = sum(p["bytes"] for p in pvs)
            for lvname, lv in (vg.get("logical_volumes") or {}).items():
                if not isinstance(lv, dict):
                    continue
                size, extents = self._lv_size(vg, lv)
                segs = []
                types = []
                thin_pool = None
                for key in sorted(lv, key=lambda k: (len(k), k)):
                    if re.fullmatch(r"segment\d+", key or "") and isinstance(lv[key], dict):
                        seg = lv[key]
                        segs.append(dict(name=key, start_extent=seg.get("start_extent"),
                                         extent_count=seg.get("extent_count"),
                                         type=seg.get("type"),
                                         thin_pool=seg.get("thin_pool") or seg.get("pool"),
                                         stripes=seg.get("stripes")))
                        if seg.get("type"):
                            types.append(seg.get("type"))
                        if thin_pool is None and seg.get("type") in ("thin", "thin-pool"):
                            thin_pool = seg.get("thin_pool") or seg.get("pool") or lvname
                dev_candidates = ["/dev/%s/%s" % (name, lvname),
                                  "/dev/mapper/%s-%s" % (name, lvname.replace("-", "--"))]
                mount = None
                for dev in dev_candidates:
                    if dev in mounts:
                        mount = mounts[dev]
                        break
                use_pct, df_line = self._df_lookup(df, name, lvname)
                out.append(dict(
                    name=lvname,
                    vg=name,
                    device=dev_candidates[0],
                    size=size,
                    size_human=human_size(size),
                    extents=extents,
                    seg_count=lv.get("segment_count"),
                    segments=segs,
                    types=types,
                    thin_pool=thin_pool,
                    status=lv.get("status") or [],
                    flags=lv.get("flags") or [],
                    creation_time=_dt(lv.get("creation_time")),
                    vg_total_bytes=vg_bytes,
                    alloc_percent=(round(size * 100.0 / vg_bytes, 2) if vg_bytes else None),
                    mountpoint=mount,
                    use_percent=use_pct,
                    df_line=df_line,
                    visible="VISIBLE" in (lv.get("status") or []),
                    lv_id=lv.get("id"),
                ))
        return out

    def activate_commands(self):
        """该场景应使用的激活命令（按 mdadm → LVM → 挂载顺序）。"""
        cmds = []
        if self.history:
            cmds.append("vgscan")
        else:
            self.notes.append("无 LVM 元数据，激活命令仅按通用流程给出")
            return ["vgscan", "vgchange -ay"]
        md = fs_read(self.fs, "/proc/mdstat", 65536)
        if md is None:
            md = fs_read(self.fs, "/etc/mdadm.conf", 65536)
        if md:
            cmds.append("mdadm --assemble --scan")
        cmds.append("vgchange -ay")
        for vg in sorted(self.vgs):
            cmds.append("vgchange -ay %s" % vg)
        for lv in self.logical_volumes():
            if "VISIBLE" in lv["status"]:
                continue
            cmds.append("lvchange -ay %s" % lv["device"])
        if any(True for vg in self.vgs.values()
               if "PARTIAL" in (vg.get("status") or [])):
            cmds.append("vgchange --activationmode partial -ay")
        for lv in self.logical_volumes():
            if lv["mountpoint"]:
                cmds.append("mount -o ro %s %s" % (lv["device"], lv["mountpoint"]))
        return cmds

    # ---------- df / mounts ----------
    DF_CANDIDATES = (
        "/root/df.txt", "/root/df.log", "/root/df", "/var/log/df.txt",
        "/tmp/df.txt", "/etc/df.txt", "/var/log/df.log",
    )

    def _mounts(self):
        if self._mount_cache is not None:
            return self._mount_cache
        self._mount_cache = {}
        for path in ("/etc/mtab", "/proc/mounts", "/proc/self/mounts"):
            data = fs_read(self.fs, path, 1 << 20)
            if not data:
                continue
            for line in decode_text(data).splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    self._mount_cache.setdefault(parts[0], parts[1])
            break
        return self._mount_cache

    def _df_records(self):
        if self._df_cache is not None:
            return self._df_cache
        self._df_cache = []
        paths = list(self.DF_CANDIDATES)
        for d in ("/root", "/var/log", "/tmp", "/home"):
            ino = fs_lookup(self.fs, d)
            if ino is None or not _is_dir(ino):
                continue
            try:
                for e in self.fs.listdir(ino):
                    nm = e.name or ""
                    if re.match(r"(?i)^(df|diskspace)[\w.\-]*$", nm) and nm not in (
                            "df", "df.txt", "df.log"):
                        paths.append(d + "/" + nm)
            except Exception:
                continue
        seen = set()
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            data = fs_read(self.fs, path, 1 << 20)
            if not data:
                continue
            recs = parse_df(decode_text(data))
            if recs:
                for r in recs:
                    r["source"] = path
                    self._df_cache.append(r)
        if not self._df_cache:
            self.notes.append("未找到 df 记录（%s），使用百分比只按 LVM 分配率计算"
                              % ", ".join(self.DF_CANDIDATES[:3]))
        return self._df_cache

    def _df_lookup(self, records, vg, lv):
        if not records:
            return None, None
        want = {"/dev/%s/%s" % (vg, lv),
                "/dev/mapper/%s-%s" % (vg, lv.replace("-", "--"))}
        for r in records:
            if _norm_dev(r.get("filesystem")) in {_norm_dev(w) for w in want}:
                return r.get("use_percent"), r.get("raw")
        return None, None


def _norm_dev(dev):
    if not dev:
        return ""
    d = dev.strip().rstrip("/")
    d = d.replace("/dev/mapper/", "/dev/")
    # vg0-pve--data → vg0/pve-data
    m = re.match(r"^/dev/([^/]+)-(.+)$", d)
    if m and not d.startswith("/dev/disk/"):
        return "/dev/%s/%s" % (m.group(1), m.group(2).replace("--", "#"))
    return d.replace("--", "#")


def parse_df(text):
    """解析 df / df -h 输出（含 df -P 与 1024-blocks 变体）。"""
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lower().startswith("filesystem"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        pct_idx = None
        for i, tok in enumerate(parts):
            if tok.endswith("%") and tok[:-1].isdigit():
                pct_idx = i
                break
        if pct_idx is None or pct_idx < 3:
            continue
        rows.append(dict(filesystem=parts[0], size=parts[pct_idx - 3],
                         used=parts[pct_idx - 2], avail=parts[pct_idx - 1],
                         use_percent=int(parts[pct_idx][:-1]),
                         mountpoint=parts[-1], raw=line.strip(),
                         available=len(parts) >= 6))
    return rows


# --------------------------------------------------------------------------
# fs 访问小工具（LinuxArtifacts / Lvm 共用）
# --------------------------------------------------------------------------
def fs_lookup(fs, path, max_links=16):
    """按路径组件解析，跟随符号链接（/bin、/lib、/etc/centos-release 等）。

    mkit.ext4.lookup 不跟随链接（遇到链接会当目录列而抛 ValueError），
    真实 CentOS/RHEL 上 /bin /sbin /lib /lib64 都是链接，必须在此解析。
    """
    try:
        parts = [p for p in str(path).replace("\\", "/").split("/")
                 if p not in ("", ".")]
    except Exception:
        return None
    try:
        cur = fs.lookup("/")
    except Exception:
        return None
    if cur is None:
        return None
    hops = 0
    while parts:
        name = parts.pop(0)
        if name == "..":
            cur = _fs_parent(fs, cur)
            if cur is None:
                return None
            continue
        ent = None
        try:
            for e in fs.listdir(cur):
                if e.name == name:
                    ent = e
                    break
        except Exception:
            return None
        if ent is None:
            return None
        child = _fs_inode(fs, getattr(ent, "inode", None))
        if child is None:
            return None
        if _is_link(child):
            hops += 1
            target = _readlink(fs, child)
            if not target or hops > max_links:
                return child
            if target.startswith("/"):
                try:
                    cur = fs.lookup("/")
                except Exception:
                    return None
            tparts = [p for p in target.split("/") if p not in ("", ".")]
            parts = tparts + parts
            continue
        cur = child
    return cur


def _fs_inode(fs, num):
    if num is None:
        return None
    try:
        return fs.inode(num)
    except Exception:
        return None


def _fs_parent(fs, ino):
    try:
        for e in fs.listdir(ino):
            if e.name == "..":
                return _fs_inode(fs, e.inode)
    except Exception:
        return None
    return None


def _readlink(fs, ino):
    """读符号链接目标（inline fast symlink 与 extent 存储都走 read_data）。"""
    try:
        size = min(_ino_size(ino) or 4096, 4096)
        data = fs.read_data(ino, size)
    except Exception:
        return None
    if not data:
        return None
    if isinstance(data, str):
        return data
    return decode_text(data).strip("\x00").strip()


def fs_read(fs, path, limit=1 << 20):
    ino = fs_lookup(fs, path)
    if ino is None or _is_dir(ino) or _is_link(ino):
        return None
    size = _ino_size(ino)
    if size:
        limit = min(limit, size) if limit else size
    try:
        data = fs.read_data(ino, limit)
    except TypeError:
        try:
            data = fs.read_data(ino)
        except Exception:
            return None
    except Exception:
        return None
    if data is None:
        return None
    return data[:limit] if limit else data


# --------------------------------------------------------------------------
# ICS 日历
# --------------------------------------------------------------------------
def _ics_unfold(text):
    return re.sub(r"\r?\n[ \t]", "", text)


def _ics_prop(line):
    """返回 (name, params dict, value)。"""
    if ":" not in line:
        return None, {}, ""
    head, value = line.split(":", 1)
    bits = head.split(";")
    name = bits[0].upper()
    params = {}
    for b in bits[1:]:
        if "=" in b:
            k, v = b.split("=", 1)
            params[k.upper()] = v.strip('"')
    return name, params, value


def _ics_dt(value, params):
    """ICS 日期/时间 → (datetime|None, all_day)"""
    value = value.strip()
    tz = params.get("TZID")
    try:
        if value.endswith("Z") and "T" in value:
            return datetime.datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(
                tzinfo=datetime.timezone.utc), False
        if "T" in value:
            return datetime.datetime.strptime(value[:15], "%Y%m%dT%H%M%S"), False
        return datetime.datetime.strptime(value[:8], "%Y%m%d"), True
    except ValueError:
        return None, ("T" not in value)


def parse_ics(text):
    """解析 .ics，返回 VEVENT 列表。"""
    events = []
    cur = None
    for line in _ics_unfold(text).replace("\r\n", "\n").split("\n"):
        line = line.rstrip("\r")
        if not line:
            continue
        if line.upper().startswith("BEGIN:VEVENT"):
            cur = dict(summary=None, dtstart=None, dtend=None, location=None, uid=None,
                       organizer=None, rrule=None, description=None, all_day=False,
                       tzid=None, created=None)
            continue
        if line.upper().startswith("END:VEVENT"):
            if cur is not None:
                events.append(cur)
            cur = None
            continue
        if cur is None:
            continue
        name, params, value = _ics_prop(line)
        if name == "SUMMARY":
            cur["summary"] = value
        elif name == "DTSTART":
            dt, all_day = _ics_dt(value, params)
            cur["dtstart"] = dt
            cur["all_day"] = all_day
            cur["tzid"] = params.get("TZID")
            cur["dtstart_raw"] = value
        elif name in ("DTEND", "DUE"):
            dt, _ = _ics_dt(value, params)
            cur["dtend"] = dt
            cur["dtend_raw"] = value
        elif name == "LOCATION":
            cur["location"] = value
        elif name == "UID":
            cur["uid"] = value
        elif name == "ORGANIZER":
            cur["organizer"] = value.replace("mailto:", "")
        elif name == "RRULE":
            cur["rrule"] = value
        elif name == "DESCRIPTION":
            cur["description"] = value[:400]
        elif name == "CREATED":
            cur["created"] = value
    return events


# --------------------------------------------------------------------------
# access.log
# --------------------------------------------------------------------------
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<ua>[^"]*)")?'
)

SCANNER_UA = (
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster", "gobuster",
    "wpscan", "nuclei", "acunetix", "nessus", "openvas", "netsparker",
    "appscan", "w3af", "jbrofuzz", "havij", "wpscan", "xray", "fscan",
    "whatweb", "arachni", "skipfish", "wapiti", "joomscan", "droopescan",
)

ATTACK_RULES = (
    ("sqli", re.compile(r"(union\s+(\/\*.*?\*\/)?\s*select|'\s*or\s*'?\d|"
                        r"or\s+1\s*=\s*1|information_schema|sleep\s*\(\s*\d|"
                        r"benchmark\s*\(|extractvalue\s*\(|updatexml\s*\(|"
                        r"concat\s*\(|--\+|%27|xp_cmdshell)", re.I)),
    ("traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|/etc/passwd|"
                             r"boot\.ini|win\.ini)", re.I)),
    ("webshell", re.compile(r"(<\?php|eval\s*\(|base64_decode|shell_exec|"
                            r"system\s*\(\s*\$|assert\s*\()", re.I)),
    ("cmdinj", re.compile(r"(;\s*(cat|id|whoami|wget|curl|nc|bash|sh)\b|\|\s*"
                          r"(id|whoami|nc)\b|`\s*(id|whoami)\s*`|\$\(|"
                          r"[?&](cmd|exec|command|shell|run|system)\s*=)", re.I)),
    ("lfi", re.compile(r"(php://|expect://|data:text/plain|\.\.%2f|%00)", re.I)),
    ("xss", re.compile(r"(<script|%3cscript|onerror\s*=|javascript:)", re.I)),
    ("log4j", re.compile(r"\$\{jndi:", re.I)),
)


def parse_access_log(text, limit=None):
    """解析 combined / common 格式，返回 dict 统计。"""
    stats = dict(total=0, parsed=0, unparsed=0, ips={}, uas={}, status={},
                 bytes=0, attacks={}, first=None, last=None, bad_lines=0,
                 requests_top={}, suspicious=[])
    lines = text.splitlines()
    if limit:
        lines = lines[:limit]
    for line in lines:
        if not line.strip():
            continue
        stats["total"] += 1
        m = ACCESS_RE.match(line)
        if not m:
            stats["unparsed"] += 1
            if stats["unparsed"] <= 3:
                stats["suspicious"].append(dict(kind="unparsed", raw=line[:200]))
            continue
        stats["parsed"] += 1
        ip = m.group("ip")
        ua = m.group("ua") or ""
        req = m.group("request")
        code = m.group("status")
        stats["ips"][ip] = stats["ips"].get(ip, 0) + 1
        stats["status"][code] = stats["status"].get(code, 0) + 1
        if ua:
            stats["uas"][ua] = stats["uas"].get(ua, 0) + 1
        try:
            stats["bytes"] += int(m.group("size"))
        except ValueError:
            pass
        dt = None
        try:
            dt = datetime.datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            pass
        if dt:
            if stats["first"] is None or dt < stats["first"]:
                stats["first"] = dt
            if stats["last"] is None or dt > stats["last"]:
                stats["last"] = dt
        target = req
        if " " in req:
            parts = req.split(" ")
            if len(parts) >= 2:
                stats["requests_top"][parts[1].split("?")[0][:120]] = \
                    stats["requests_top"].get(parts[1].split("?")[0][:120], 0) + 1
        low = req.lower()
        for kind, rx in ATTACK_RULES:
            if rx.search(low) or rx.search(_url_unescape(low)):
                stats["attacks"].setdefault(kind, []).append(dict(
                    ip=ip, time=_fmt(dt), request=req[:300], status=code,
                    ua=ua[:120], line=line[:300]))
        for scan in SCANNER_UA:
            if scan in ua.lower():
                stats["attacks"].setdefault("scanner_ua", []).append(dict(
                    scanner=scan, ip=ip, time=_fmt(dt), request=req[:200],
                    ua=ua[:160]))
                break
    return stats


def _url_unescape(s):
    s = s.replace("%20", " ").replace("%2f", "/").replace("%2F", "/")
    s = s.replace("%3c", "<").replace("%3e", ">").replace("%27", "'")
    s = s.replace("%3d", "=").replace("%3b", ";").replace("%00", "\x00")
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "%" and i + 2 < len(s):
            hexs = s[i + 1:i + 3]
            if all(c in "0123456789abcdefABCDEF" for c in hexs):
                try:
                    out.append(chr(int(hexs, 16)))
                    i += 3
                    continue
                except ValueError:
                    pass
        out.append(ch)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------
# 主体
# --------------------------------------------------------------------------
class LinuxArtifacts:
    MAX_READ = 128 * 1024 * 1024
    ACCESS_LINE_LIMIT = 400000
    SUID_LIMIT = 400000

    def __init__(self, fs):
        self.fs = fs
        self.notes = []
        self._dir_cache = {}
        self._users_cache = None
        self._log_year = None

    # ---------- fs 基础 ----------
    def _ino(self, path):
        return fs_lookup(self.fs, path)

    def _listdir(self, path):
        if path in self._dir_cache:
            return self._dir_cache[path]
        ino = self._ino(path)
        ents = []
        if ino is not None and _is_dir(ino):
            try:
                ents = list(self.fs.listdir(ino))
            except Exception as exc:
                self.notes.append("列目录失败 %s: %s" % (path, exc))
        self._dir_cache[path] = ents
        return ents

    def _names(self, path):
        return [e.name for e in self._listdir(path)
                if e.name not in (".", "..")]

    def _exists(self, path):
        return self._ino(path) is not None

    def _miss(self, path):
        self.notes.append("未找到 %s" % path)
        return None

    def _read(self, path, limit=None, allow_gz=True):
        ino = self._ino(path)
        if ino is None or _is_dir(ino):
            return None
        cap = self.MAX_READ if limit is None else min(limit, self.MAX_READ)
        size = _ino_size(ino)
        if size and size < cap:
            cap = size
        try:
            data = self.fs.read_data(ino, cap)
        except TypeError:
            try:
                data = self.fs.read_data(ino)
            except Exception as exc:
                self.notes.append("读取失败 %s: %s" % (path, exc))
                return None
        except Exception as exc:
            self.notes.append("读取失败 %s: %s" % (path, exc))
            return None
        if data is None:
            return None
        data = data[:cap] if cap else data
        if allow_gz:
            data = _decompress_any(data, path)
        return data

    def _text(self, path, limit=None, allow_gz=True):
        data = self._read(path, limit, allow_gz)
        if data is None:
            return None
        return decode_text(data)

    def _first_text(self, *paths, **kw):
        for path in paths:
            txt = self._text(path, kw.get("limit"), kw.get("allow_gz", True))
            if txt is not None:
                return path, txt
        self._miss(" / ".join(paths))
        return None, None

    # ---------- 日志 gz/轮转 ----------
    def _log_candidates(self, path):
        """主日志 + rsyslog/logrotate 的多种轮转命名。

        CentOS 用 secure-20210704 / messages-20230322，
        Debian 用 auth.log.1 / .2.gz，nginx 用 access.log-20240101 / .1.gz。
        """
        cands = [path, path + ".gz", path + ".1", path + ".1.gz", path + ".old"]
        base = path.rsplit("/", 1)[-1]
        parent = path.rsplit("/", 1)[0] or "/"
        rx = re.compile(re.escape(base) + r"([.\-_]\d{1,8})?(\.gz|\.xz|\.bz2)?$")
        for e in self._listdir(parent):
            nm = e.name or ""
            if nm in (".", ".."):
                continue
            if rx.match(nm):
                cand = parent + "/" + nm
                if cand not in cands:
                    cands.append(cand)
        return cands

    def _read_logs(self, path):
        """读取主日志 + 轮转段，返回 [(path, text)]。"""
        out = []
        seen = set()
        for cand in self._log_candidates(path):
            if cand in seen:
                continue
            seen.add(cand)
            txt = self._text(cand)
            if txt is not None:
                out.append((cand, txt))
        if not out:
            self.notes.append("未找到 %s（含 .gz/轮转）" % path)
        return out

    # ---------- 时间戳年份推断 ----------
    def _year_for(self, path, sample_text=""):
        ino = self._ino(path)
        mtime = _ino_mtime(ino)
        if mtime:
            return mtime.year
        return datetime.datetime.now().year

    def _parse_syslog_ts(self, tok, year):
        """'Jan  5 12:00:00' 或 ISO 时间戳。返回 (datetime, rest_of_line)。"""
        m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:[+-]\d\d:\d\d|Z)?)\s+(\S+)\s+(.*)$",
                     tok)
        if m:
            raw, host, msg = m.group(1), m.group(2), m.group(3)
            try:
                dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                dt = None
            return dt, host, msg
        m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+(.*)$", tok)
        if m:
            mon, day, hms, host, msg = m.groups()
            try:
                dt = datetime.datetime.strptime(
                    "%s %s %s %d" % (mon, day, hms, year), "%b %d %H:%M:%S %Y")
            except ValueError:
                return None, host, msg
            now = datetime.datetime.now()
            if dt > now + datetime.timedelta(days=1):
                dt = dt.replace(year=year - 1)
            return dt, host, msg
        return None, "", tok

    # ================================================================== os
    def os_release(self):
        info = dict(files={}, kernel_versions=[], hostname=None, uname_hints=[])
        for path in ("/etc/os-release", "/usr/lib/os-release", "/etc/issue",
                     "/etc/redhat-release", "/etc/centos-release", "/etc/debian_version",
                     "/etc/lsb-release", "/etc/alpine-release", "/etc/SuSE-release"):
            txt = self._text(path, 1 << 16)
            if txt is None:
                continue
            info["files"][path] = txt.strip()
            if path.endswith("os-release"):
                for line in txt.splitlines():
                    if "=" not in line or line.strip().startswith("#"):
                        continue
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip().strip('"')
            elif path == "/etc/issue":
                info["issue"] = txt.strip()
            elif path in ("/etc/redhat-release", "/etc/centos-release"):
                info.setdefault("pretty_name", txt.strip())
        if not info["files"]:
            self.notes.append("未找到 /etc/os-release 或发行版标识文件")
        host = self._text("/etc/hostname", 4096)
        if host is not None:
            info["hostname"] = host.strip()
        else:
            self.notes.append("未找到 /etc/hostname")
        mods = self._names("/lib/modules") + self._names("/usr/lib/modules")
        info["kernel_versions"] = sorted(set(m for m in mods if m))
        boot = self._names("/boot")
        info["boot_kernels"] = sorted(n for n in boot if n.startswith("vmlinuz"))
        for n in info["boot_kernels"]:
            info["uname_hints"].append("vmlinuz-%s" % n[len("vmlinuz-"):] if n.startswith("vmlinuz-") else n)
        for path in ("/proc/version", "/var/log/dmesg", "/var/log/boot.log"):
            txt = self._text(path, 8192)
            if not txt:
                continue
            for line in txt.replace("\x00", "").splitlines():
                line = line.strip()
                if len(line) >= 8 and line.isprintable():
                    info["uname_hints"].append("%s: %s" % (path, line[:200]))
                    break
        return info

    # ================================================================ users
    def _passwd(self):
        txt = self._text("/etc/passwd", 1 << 20)
        if txt is None:
            self.notes.append("未找到 /etc/passwd")
            return []
        users = []
        for line in txt.splitlines():
            if not line or line.startswith("#"):
                continue
            f = line.split(":")
            if len(f) < 7:
                continue
            users.append(dict(name=f[0], password=f[1], uid=int(f[2]) if f[2].isdigit() else None,
                              gid=int(f[3]) if f[3].isdigit() else None,
                              gecos=f[4], home=f[5], shell=f[6]))
        return users

    def _shadow(self):
        txt = self._text("/etc/shadow", 1 << 20)
        if txt is None:
            self.notes.append("未找到 /etc/shadow")
            return {}
        out = {}
        for line in txt.splitlines():
            if not line or line.startswith("#"):
                continue
            f = line.split(":")
            if len(f) < 2:
                continue
            h = f[1]
            rec = dict(hash=h, algo=_hash_algo(h), locked=h.startswith("!") or h in ("*", ""),
                       last_change=_days(f[2]),
                       min_days=f[3], max_days=f[4], warn_days=f[5],
                       expire=_days(f[7]) if len(f) > 7 else None,
                       has_hash=bool(h) and h not in ("*", "!!") and not h.startswith("!"))
            out[f[0]] = rec
        return out

    def _group(self):
        txt = self._text("/etc/group", 1 << 20)
        if txt is None:
            self.notes.append("未找到 /etc/group")
            return {}
        out = {}
        for line in txt.splitlines():
            if not line or line.startswith("#"):
                continue
            f = line.split(":")
            if len(f) < 4:
                continue
            out[f[0]] = dict(gid=int(f[2]) if f[2].isdigit() else None,
                             members=[m for m in f[3].split(",") if m])
        return out

    def users(self):
        users = self._passwd()
        if not users:
            return []
        shadow = self._shadow()
        groups = self._group()
        gid_name = {}
        for gname, g in groups.items():
            if g["gid"] is not None:
                gid_name.setdefault(g["gid"], gname)
        member_of = {}
        for gname, g in groups.items():
            for m in g["members"]:
                member_of.setdefault(m, []).append(gname)
        for u in users:
            primary = gid_name.get(u["gid"]) if u["gid"] is not None else None
            supp = sorted(set(member_of.get(u["name"], [])) |
                          ({primary} if primary else set()))
            u["primary_group"] = primary
            u["groups"] = supp
            sh = shadow.get(u["name"])
            if sh:
                u["shadow"] = dict(algo=sh["algo"], locked=sh["locked"],
                                   has_hash=sh["has_hash"], hash=sh["hash"],
                                   last_change=_fmt(sh["last_change"]),
                                   max_days=sh["max_days"], expire=_fmt(sh["expire"]))
            else:
                u["shadow"] = None
            u["is_root"] = (u["uid"] == 0)
            u["is_system"] = bool(u["uid"] is not None and u["uid"] < 1000 and u["uid"] != 0)
            u["is_admin"] = u["is_root"] or any(g in u["groups"] for g in
                                                ("wheel", "sudo", "admin", "adm"))
            u["privileged_shell"] = u["shell"].rsplit("/", 1)[-1] in (
                "bash", "sh", "zsh", "ksh", "csh", "dash")
        return users

    def sudoers(self):
        out = []
        paths = ["/etc/sudoers"]
        kids = self._names("/etc/sudoers.d")
        if not kids and self._ino("/etc/sudoers.d") is None:
            self.notes.append("未找到 /etc/sudoers.d")
        for nm in kids:
            paths.append("/etc/sudoers.d/" + nm)
        for path in paths:
            txt = self._text(path, 1 << 20)
            if txt is None:
                if path == "/etc/sudoers":
                    self.notes.append("未找到 /etc/sudoers")
                continue
            for line in txt.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.startswith("@include") or s.startswith("#include"):
                    out.append("%s: %s" % (path, s))
                    continue
                out.append("%s: %s" % (path, s))
        if not out:
            self.notes.append("sudoers 内容为空或不可读")
        return out

    # ================================================================= ssh
    SSH_PATTERNS = (
        ("accepted", re.compile(r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")),
        ("failed", re.compile(r"Failed\s+(\S+)\s+for\s+(invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")),
        ("invalid_user", re.compile(r"Invalid user\s+(\S+)\s+from\s+(\S+)")),
        ("checkpass", re.compile(r"pam_unix\(sshd:auth\):\s+authentication failure.*rhost=(\S+)")),
        ("preauth_disconnect", re.compile(r"Disconnected from (?:authenticating|invalid) user\s+(\S+)\s+(\S+)?")),
    )

    def ssh_logins(self):
        res = dict(success=0, failed=0, invalid_user=0, users={}, ips={},
                   events=[], sources=[], first=None, last=None, boots=[],
                   by_method={}, wtmp_sessions=0, btmp_failed=0)
        logs = []
        for base in ("/var/log/secure", "/var/log/auth.log", "/var/log/auth.log.1"):
            logs.extend(self._read_logs(base))
        seen = set()
        for path, txt in logs:
            if path in seen:
                continue
            seen.add(path)
            res["sources"].append(path)
            year = self._year_for(path)
            if self._log_year is None:
                self._log_year = year
            for line in txt.splitlines():
                low = line
                dt, host, msg = self._parse_syslog_ts(low, year)
                accepted = self.SSH_PATTERNS[0][1].search(msg)
                failed = self.SSH_PATTERNS[1][1].search(msg)
                invalid = self.SSH_PATTERNS[2][1].search(msg)
                if accepted:
                    method, user, ip = accepted.group(1), accepted.group(2), accepted.group(3)
                    port = accepted.group(4)
                    self._ssh_add(res, dt, user, ip, True, method, port, msg, path)
                    res["by_method"][method] = res["by_method"].get(method, 0) + 1
                elif failed:
                    method, invflag, user, ip = (failed.group(1), failed.group(2),
                                                 failed.group(3), failed.group(4))
                    port = failed.group(5)
                    self._ssh_add(res, dt, user, ip, False, method, port, msg, path)
                    if invflag:
                        res["invalid_user"] += 1
                elif invalid:
                    user, ip = invalid.group(1), invalid.group(2)
                    res["invalid_user"] += 1
                    self._ssh_add(res, dt, user, ip, False, "invalid", None, msg, path)
        # wtmp：成功登录补强
        for path in ("/var/log/wtmp", "/var/log/wtmp.1"):
            for cand in self._log_candidates(path):
                data = self._read(cand, allow_gz=True)
                if not data:
                    continue
                recs = parse_utmp(data)
                if not recs:
                    continue
                res["sources"].append(cand)
                for r in recs:
                    if r["type"] == 2:
                        res["boots"].append(dict(source=cand, time=_fmt(r["time"]),
                                                 user=r["user"] or None))
                    if r["type"] != 7:
                        continue
                    res["wtmp_sessions"] += 1
                    ip = r["ip"] or r["host"] or None
                    ev = dict(time=r["time"], user=r["user"], ip=ip, line=r["line"],
                              ok=True, method="wtmp", source=cand, tz="utc", raw=None)
                    res["success"] += 1
                    self._ssh_merge(res, ev)
        # btmp：失败爆破
        for cand in self._log_candidates("/var/log/btmp"):
            data = self._read(cand, allow_gz=True)
            if not data:
                continue
            recs = parse_utmp(data)
            if not recs:
                continue
            res["sources"].append(cand)
            for r in recs:
                if r["type"] not in (6, 7, 8):
                    continue
                ip = r["ip"] or r["host"] or None
                res["btmp_failed"] += 1
                res["failed"] += 1
                self._ssh_merge(res, dict(time=r["time"], user=r["user"], ip=ip,
                                          line=r["line"], ok=False, method="btmp",
                                          source=cand, tz="utc", raw=None))
        if res["sources"]:
            self.notes.append("ssh 时间基准：syslog(secure/auth.log) 为服务器本地时间且"
                              "无年份，按文件 mtime 推断；wtmp/btmp 为 UTC")
        if not res["sources"]:
            self.notes.append("未找到 ssh 登录相关日志（secure/auth.log/wtmp/btmp）")
        res["events"] = sorted([e for e in res["events"] if e["time"]],
                               key=lambda e: _dtkey(e["time"]))[:20000]
        for e in res["events"]:
            e["time"] = _fmt(e["time"])
        ts = [e["time"] for e in res["events"] if e["time"]]
        res["first"] = ts[0] if ts else None
        res["last"] = ts[-1] if ts else None
        return res

    def _ssh_add(self, res, dt, user, ip, ok, method, port, msg, source):
        if ok:
            res["success"] += 1
        else:
            res["failed"] += 1
        self._ssh_merge(res, dict(time=dt, user=user, ip=ip, ok=ok, method=method,
                                  port=port, source=source, tz="local",
                                  message=msg[:300]))

    def _ssh_merge(self, res, ev):
        res["events"].append(ev)
        u = res["users"].setdefault(ev["user"] or "-", dict(
            success=0, failed=0, ips=[], first=None, last=None))
        key = "success" if ev["ok"] else "failed"
        u[key] += 1
        if ev["ip"] and ev["ip"] not in u["ips"]:
            u["ips"].append(ev["ip"])
        if ev["time"]:
            t = _fmt(ev["time"])
            if u["first"] is None or t < u["first"]:
                u["first"] = t
            if u["last"] is None or t > u["last"]:
                u["last"] = t
        if ev["ip"]:
            i = res["ips"].setdefault(ev["ip"], dict(success=0, failed=0, users=[]))
            i[key] += 1
            if ev["user"] and ev["user"] not in i["users"]:
                i["users"].append(ev["user"])

    def last_users(self):
        out = []
        data_seen = False
        for cand in self._log_candidates("/var/log/wtmp"):
            data = self._read(cand, allow_gz=True)
            if not data:
                continue
            data_seen = True
            for r in parse_utmp(data):
                if r["type"] != 7:
                    continue
                rec = dict(r)
                rec["time"] = _fmt(r["time"])
                rec["source"] = cand
                out.append(rec)
        if not data_seen:
            self.notes.append("未找到 /var/log/wtmp（含 .gz/轮转），无法解析登录记录")
        out.sort(key=lambda r: (r["time"] or ""))
        return out

    # ==================================================== bash_history
    def bash_history(self):
        homes = [("/root", "root")]
        for u in self._passwd():
            if u["home"] and u["home"] not in ("/", "/nonexistent", "/bin"):
                homes.append((u["home"], u["name"]))
        seen_home = set()
        out = []
        for home, user in homes:
            home = home.rstrip("/") or "/"
            if home in seen_home:
                continue
            seen_home.add(home)
            for fname in (".bash_history", ".zsh_history", ".sh_history",
                          ".python_history", ".mysql_history"):
                path = home.rstrip("/") + "/" + fname
                txt = self._text(path, 8 << 20)
                if txt is None:
                    continue
                ts = None
                seq = 0
                for raw in txt.splitlines():
                    line = raw.rstrip("\n")
                    if not line.strip():
                        continue
                    m = re.match(r"^#(\d{9,11})$", line.strip())
                    if m:
                        ts = _dt(int(m.group(1)))
                        continue
                    if fname == ".zsh_history":
                        zm = re.match(r"^: (\d+):\d+;(.*)$", line)
                        if zm:
                            ts = _dt(int(zm.group(1)))
                            line = zm.group(2)
                    seq += 1
                    out.append(dict(user=user, file=path, seq=seq, cmd=line,
                                    time=_fmt(ts), ts=ts))
        if not out:
            self.notes.append("未找到任何 bash_history / .zsh_history")
        return out

    # ============================================================= cron
    CRON_DIRS = ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
                 "/etc/cron.monthly")

    def cron(self):
        out = []
        files = ["/etc/crontab", "/etc/anacrontab"]
        for d in ("/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"):
            for nm in self._names(d):
                files.append(d + "/" + nm)
        found = False
        for path in files:
            txt = self._text(path, 1 << 20)
            if txt is None:
                continue
            found = True
            for line in txt.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):     # 变量赋值
                    continue
                out.append("%s: %s" % (path, s))
        # run-parts 目录里的可执行脚本也算计划任务（只记文件，不解析脚本体）
        for d in self.CRON_DIRS:
            for nm in self._names(d):
                out.append("%s: %s/%s" % (d, d, nm))
        if not found:
            self.notes.append("未找到 crontab 相关文件")
        return out

    # ========================================================= services
    UNIT_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system",
                 "/lib/systemd/system", "/run/systemd/system")

    def _parse_ini(self, txt):
        sect = {}
        cur = None
        for line in txt.splitlines():
            s = line.strip()
            if not s or s.startswith("#") or s.startswith(";"):
                continue
            if s.startswith("[") and s.endswith("]"):
                cur = s[1:-1]
                sect.setdefault(cur, {})
                continue
            if "=" in s and cur:
                k, v = s.split("=", 1)
                sect[cur][k.strip()] = v.strip()
        return sect

    def _wanted_by(self):
        """扫描 *.wants 目录，得到 unit → 启用目标。"""
        out = {}
        for base in ("/etc/systemd/system",):
            for name in self._names(base):
                if not name.endswith(".wants"):
                    continue
                target = name[:-len(".wants")]
                d = base + "/" + name
                for e in self._listdir(d):
                    out.setdefault(e.name, []).append(target)
        return out

    def services(self):
        wanted = self._wanted_by()
        out = []
        seen = set()
        for d in self.UNIT_DIRS:
            for name in self._names(d):
                if not name.endswith((".service", ".timer", ".socket")):
                    continue
                if name in seen and d != "/etc/systemd/system":
                    continue
                path = d + "/" + name
                txt = self._text(path, 1 << 20)
                if txt is None:
                    continue
                seen.add(name)
                ini = self._parse_ini(txt)
                svc = ini.get("Service", {})
                unit = ini.get("Unit", {})
                inst = ini.get("Install", {})
                rec = dict(name=name, path=path,
                           description=unit.get("Description"),
                           exec_start=svc.get("ExecStart"),
                           exec_start_pre=svc.get("ExecStartPre"),
                           exec_start_post=svc.get("ExecStartPost"),
                           user=svc.get("User"),
                           group=svc.get("Group"),
                           working_directory=svc.get("WorkingDirectory"),
                           restart=svc.get("Restart"),
                           environment=svc.get("Environment"),
                           wanted_by=wanted.get(name, []),
                           install_wanted_by=inst.get("WantedBy"),
                           enabled=bool(wanted.get(name)))
                out.append(rec)
        if not out:
            self.notes.append("未找到任何 systemd unit（/etc|/usr/lib|/lib/systemd/system）")
        return out

    # =========================================================== docker
    def docker(self):
        res = dict(containers=[], count=0, images=[], image_repositories=None,
                   volumes=[], networks=[], notes=[])
        cdir = "/var/lib/docker/containers"
        names = self._names(cdir)
        if not names:
            self.notes.append("未找到 /var/lib/docker/containers（Docker 可能未使用或数据目录被迁移）")
        for cid in names:
            path = "%s/%s/config.v2.json" % (cdir, cid)
            raw = self._read(path, 8 << 20)
            if raw is None:
                continue
            try:
                cfg = json.loads(decode_text(raw))
            except Exception as exc:
                self.notes.append("Docker 配置解析失败 %s: %s" % (path, exc))
                continue
            cfgd = cfg.get("Config") or {}
            net = cfg.get("NetworkSettings") or {}
            ports = []
            for spec, binds in (net.get("Ports") or {}).items():
                if not binds:
                    ports.append(dict(container=spec, host=None))
                    continue
                for b in binds:
                    ports.append(dict(container=spec, host="%s:%s" % (
                        b.get("HostIp") or "0.0.0.0", b.get("HostPort") or "")))
            exposed = sorted((cfgd.get("ExposedPorts") or {}).keys())
            mounts = []
            for mnt, mv in (cfg.get("MountPoints") or {}).items():
                mounts.append(dict(dest=mnt, source=(mv or {}).get("Source"),
                                   driver=(mv or {}).get("Driver")))
            created = cfg.get("Created")
            res["containers"].append(dict(
                id=cid, name=(cfg.get("Name") or "").lstrip("/"),
                image=cfgd.get("Image"),
                image_id=cfgd.get("Image") if cfgd.get("Image") else cfg.get("Image"),
                created=created,
                created_time=_fmt(_json_time(created)),
                path=cfg.get("Path"), args=cfg.get("Args"),
                cmd=cfgd.get("Cmd"), entrypoint=cfgd.get("Entrypoint"),
                env=(cfgd.get("Env") or [])[:60],
                labels=cfgd.get("Labels") or {},
                ports=ports, exposed=exposed, mounts=mounts,
                running=((cfg.get("State") or {}).get("Running")),
                restart_count=(cfg.get("RestartCount")),
                hostname=cfgd.get("Hostname"),
                ip=net.get("IPAddress"),
                config_path=path,
            ))
        res["count"] = len(res["containers"])
        for base in ("/var/lib/docker/image/overlay2/repositories.json",
                     "/var/lib/docker/image/aufs/repositories.json"):
            raw = self._read(base, 8 << 20)
            if raw is None:
                continue
            try:
                repo = json.loads(decode_text(raw))
            except Exception:
                continue
            res["image_repositories"] = repo.get("Repositories") or {}
            for rname, tags in (res["image_repositories"] or {}).items():
                for tag, digest in (tags or {}).items():
                    res["images"].append(dict(repository=rname, tag=tag, id=digest,
                                              source=base))
            break
        if not res["images"]:
            self.notes.append("未找到 /var/lib/docker/image/*/repositories.json（镜像清单缺失）")
        for vname in self._names("/var/lib/docker/volumes"):
            if vname.startswith("."):
                continue
            res["volumes"].append(dict(name=vname,
                                       path="/var/lib/docker/volumes/" + vname))
        res["networks"] = [n for n in self._names("/var/lib/docker/network/files")]
        res["notes"] = list(self.notes)
        return res

    # ============================================================== web
    NGINX_CONF = ("/etc/nginx/nginx.conf", "/www/server/nginx/conf/nginx.conf",
                  "/usr/local/nginx/conf/nginx.conf")
    NGINX_DIRS = ("/etc/nginx/conf.d", "/etc/nginx/sites-enabled",
                  "/etc/nginx/sites-available", "/usr/local/nginx/conf/vhost",
                  "/www/server/nginx/conf/vhost", "/www/server/panel/vhost/nginx",
                  "/usr/local/nginx/conf/conf.d")
    APACHE_CONF = ("/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf",
                   "/etc/apache2/ports.conf", "/www/server/apache/conf/httpd.conf")
    APACHE_DIRS = ("/etc/httpd/conf.d", "/etc/apache2/sites-enabled",
                   "/etc/apache2/sites-available", "/etc/apache2/conf-enabled",
                   "/www/server/panel/vhost/apache")
    ACCESS_LOGS = ("/var/log/nginx/access.log", "/var/log/httpd/access_log",
                   "/var/log/apache2/access.log", "/usr/local/nginx/logs/access.log",
                   "/www/wwwlogs/access.log", "/www/wwwlogs/nginx_access.log")
    WWW_LOGS_DIR = "/www/wwwlogs"

    def _access_log_paths(self):
        paths = list(self.ACCESS_LOGS)
        # 宝塔面板：每个站点一个 /www/wwwlogs/<域名>.log
        extra = 0
        for nm in self._names(self.WWW_LOGS_DIR):
            if extra >= 30:
                break
            low = nm.lower()
            if not low.endswith(".log") or low.endswith("_error.log") or "error" in low:
                continue
            cand = self.WWW_LOGS_DIR + "/" + nm
            if cand not in paths:
                paths.append(cand)
                extra += 1
        return paths

    def web(self):
        res = dict(nginx=[], apache=[], configs=[], roots=[], access={},
                   attack_summary={}, log_files=[])
        for path in self.NGINX_CONF + self.APACHE_CONF:
            txt = self._text(path, 4 << 20)
            if txt is None:
                continue
            res["configs"].append(path)
            for srv in _parse_servers(txt):
                srv["file"] = path
                (res["nginx"] if "nginx" in path else res["apache"]).append(srv)
        for d in self.NGINX_DIRS + self.APACHE_DIRS:
            for nm in self._names(d):
                if not nm.endswith((".conf", ".vhost", ".vhosts")):
                    continue
                path = d + "/" + nm
                txt = self._text(path, 4 << 20)
                if txt is None:
                    continue
                res["configs"].append(path)
                for srv in _parse_servers(txt):
                    srv["file"] = path
                    (res["nginx"] if ("nginx" in path) else res["apache"]).append(srv)
        roots = []
        for srv in res["nginx"] + res["apache"]:
            r = srv.get("root") or srv.get("documentroot")
            if r and r not in roots:
                roots.append(r)
        res["roots"] = roots
        if not res["configs"]:
            self.notes.append("未找到 nginx/apache 配置文件")
        agg = dict(total=0, parsed=0, unparsed=0, ips={}, uas={}, status={},
                   attacks={}, first=None, last=None, bytes=0)
        for path in self._access_log_paths():
            logs = self._read_logs(path)
            if not logs and path not in self.ACCESS_LOGS:
                continue
            for cand, txt in logs:
                st = parse_access_log(txt, self.ACCESS_LINE_LIMIT)
                st["first"] = _fmt(st["first"])
                st["last"] = _fmt(st["last"])
                kept_attacks = {}
                for kind, items in st["attacks"].items():
                    kept_attacks[kind] = dict(count=len(items), samples=items[:5])
                st["attacks"] = kept_attacks
                res["access"][cand] = st
                res["log_files"].append(cand)
                agg["total"] += st["total"]
                agg["parsed"] += st["parsed"]
                agg["unparsed"] += st["unparsed"]
                agg["bytes"] += st["bytes"]
                if st["unparsed"]:
                    agg.setdefault("unparsed_samples", []).extend(
                        [dict(file=cand, line=s["raw"]) for s in st["suspicious"][:2]])
                for k, v in st["ips"].items():
                    agg["ips"][k] = agg["ips"].get(k, 0) + v
                for k, v in st["uas"].items():
                    agg["uas"][k] = agg["uas"].get(k, 0) + v
                for k, v in st["status"].items():
                    agg["status"][k] = agg["status"].get(k, 0) + v
                for kind, info in kept_attacks.items():
                    ent = agg["attacks"].setdefault(kind, dict(count=0, samples=[]))
                    ent["count"] += info["count"]
                    ent["samples"].extend(info["samples"][:2])
                for k in ("first", "last"):
                    if st[k] and (agg[k] is None or
                                  (st[k] < agg[k] if k == "first" else st[k] > agg[k])):
                        agg[k] = st[k]
        agg["top_ips"] = sorted(agg["ips"].items(), key=lambda kv: -kv[1])[:10]
        agg["top_uas"] = sorted(agg["uas"].items(), key=lambda kv: -kv[1])[:10]
        agg["unparsed_samples"] = (agg.get("unparsed_samples") or [])[:5]
        res["attack_summary"] = agg["attacks"]
        res["summary"] = agg
        if not res["log_files"]:
            self.notes.append("未找到 access.log（nginx/apache）")
        return res

    # ========================================================= databases
    def databases(self):
        out = []
        cfg_paths = ["/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf",
                     "/etc/mysql/mariadb.conf.d/50-server.cnf", "/etc/my.cnf.d/server.cnf",
                     "/usr/local/mysql/my.cnf", "/etc/mariadb/my.cnf"]
        for d in ("/etc/mysql/conf.d", "/etc/my.cnf.d"):
            for nm in self._names(d):
                if nm.endswith(".cnf"):
                    cfg_paths.append(d + "/" + nm)
        found_cfg = False
        for path in cfg_paths:
            txt = self._text(path, 1 << 20)
            if txt is None:
                continue
            found_cfg = True
            ini = self._parse_ini(txt)
            flat = {}
            for sect, kv in ini.items():
                for k, v in kv.items():
                    flat.setdefault(k.lower().replace("-", "_"), v)
            datadir = flat.get("datadir")
            rec = dict(config=path, datadir=datadir,
                       port=flat.get("port"), socket=flat.get("socket"),
                       bind_address=flat.get("bind_address"),
                       version=flat.get("version") or flat.get("version_comment"),
                       server_id=flat.get("server_id"),
                       skip_networking=flat.get("skip_networking"),
                       databases=[], dumps=[], user=None)
            if not datadir and not rec["port"]:
                continue        # [client]/[mysqldump] 之类的纯客户端片段
            if datadir:
                for nm in self._names(datadir):
                    full = datadir.rstrip("/") + "/" + nm
                    if nm in ("mysql", "performance_schema", "sys", "information_schema"):
                        rec["databases"].append(dict(name=nm, system=True, path=full))
                        continue
                    if nm.endswith((".ibd", ".frm", ".MYD", ".MYI", ".sql", ".opt",
                                    ".err", ".pid", ".index", ".log", ".cnf", ".pem")):
                        continue
                    if re.match(r"^(ib|mysql-bin|relay-bin|auto\.cnf|aria)", nm):
                        continue
                    ino = self._ino(full)
                    if ino is None or not _is_dir(ino):
                        continue
                    rec["databases"].append(dict(name=nm, system=False, path=full))
            out.append(rec)
        if not found_cfg:
            self.notes.append("未找到 MySQL/MariaDB 配置文件")
        dumps = []
        for root in ("/root", "/home", "/tmp", "/var/tmp", "/var/www", "/opt", "/srv",
                     "/var/lib/mysql", "/backup", "/www/wwwroot", "/www/backup",
                     "/www/backup/database", "/data"):
            for path, ino, depth in self._walk(root, max_depth=4):
                low = path.lower()
                if low.endswith((".sql", ".sql.gz", ".sql.bz2", ".sql.xz", ".sql.bak",
                                 ".sql.zip", ".dump")):
                    dumps.append(dict(path=path, size=_ino_size(ino),
                                      size_human=human_size(_ino_size(ino))))
        if dumps:
            if out:
                out[0]["dumps"] = dumps
            else:
                out.append(dict(config=None, databases=[], dumps=dumps))
        elif not out:
            self.notes.append("未找到数据库配置或 .sql dump")
        return out

    # ============================================================== raid
    def raid(self):
        res = dict(mdstat=None, arrays=[], mdadm_conf=None, mdadm_arrays=[],
                   fstab_raid=[], source=None)
        txt = self._text("/proc/mdstat", 1 << 20)
        if txt:
            res["source"] = "/proc/mdstat"
            res["mdstat"] = txt
            res["arrays"] = parse_mdstat(txt)
        conf = self._text("/etc/mdadm.conf", 1 << 20) or self._text("/etc/mdadm/mdadm.conf", 1 << 20)
        if conf:
            res["mdadm_conf"] = conf
            for line in conf.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.upper().startswith("ARRAY"):
                    res["mdadm_arrays"].append(s)
        fstab = self._text("/etc/fstab", 1 << 20)
        if fstab:
            for line in fstab.splitlines():
                s = line.strip()
                if s and not s.startswith("#") and ("/dev/md" in s or "raid" in s.lower()):
                    res["fstab_raid"].append(s)
        if not res["arrays"] and not res["mdadm_arrays"]:
            self.notes.append("未找到 /proc/mdstat 或 mdadm.conf 中的 RAID 阵列")
        return res

    # ============================================================== suid
    def suid_files(self, fs=None, max_depth=8, roots=None, limit=None):
        fs = fs or self.fs
        limit = limit or self.SUID_LIMIT
        out = []
        roots = roots or ["/"]
        visited = 0
        for root in roots:
            for path, ino, depth in self._walk(root, max_depth=max_depth, fs=fs):
                visited += 1
                if visited > limit:
                    self.notes.append("SUID 扫描达到上限 %d 个条目，已停止" % limit)
                    break
                mode = getattr(ino, "mode", None)
                if not isinstance(mode, int):
                    continue
                if (mode & 0o4000) and (mode & 0o111):
                    out.append("%s (mode=%s uid=%s)" % (
                        path, oct(mode & 0o7777), getattr(ino, "uid", "?")))
        if not out:
            self.notes.append("SUID 扫描未命中")
            if not self._names("/usr/bin") and not self._names("/bin"):
                self.notes.append("SUID 为 0 的可疑原因：/usr/bin 与 /bin 都列不出内容"
                                  "（见 integrity_check 的目录块自洽性结果）")
        return out

    def integrity_check(self, paths=None):
        """目录块自洽性校验：正常 ext4 目录首个 dirent '.' 必须指向自身 inode。

        真实案例（centos-new.E01）里 /dev /usr /run /srv 的目录块内容是别处
        locale 目录的残留，'.' 指向另一个 inode（偏移 +544 / +580）。这种镜像
        级异常会让 /usr 下的痕迹（SUID、systemd unit、nginx 配置）整段消失，
        必须显式报告，不能静默返回空结果。
        """
        paths = paths or ["/", "/etc", "/root", "/var", "/tmp", "/usr", "/usr/bin",
                          "/usr/sbin", "/usr/lib", "/usr/lib/systemd/system",
                          "/usr/share", "/dev", "/run", "/home", "/www", "/www/server",
                          "/opt", "/srv", "/boot", "/var/log"]
        res = dict(checked=0, ok=0, suspicious=[], missing=[], unsupported=False)
        if not hasattr(self.fs, "blockmap") or not hasattr(self.fs, "read_block"):
            res["unsupported"] = True
            self.notes.append("当前 fs 适配器无 blockmap/read_block，跳过目录自洽性校验")
            return res
        for p in paths:
            ino = self._ino(p)
            if ino is None:
                res["missing"].append(p)
                continue
            if not _is_dir(ino):
                continue
            res["checked"] += 1
            dot = None
            try:
                bm = self.fs.blockmap(ino)
                blk = bm[0][1] if bm else None
                data = self.fs.read_block(blk) if blk else b""
                if len(data) >= 8:
                    dot = struct.unpack_from("<I", data, 0)[0]
            except Exception:
                dot = None
            if dot is None or dot == ino.num:
                res["ok"] += 1
            else:
                res["suspicious"].append(dict(path=p, inode=ino.num, dot_inode=dot,
                                              delta=dot - ino.num))
        if res["suspicious"]:
            self.notes.append("目录块自洽性校验失败 %d 处：%s（镜像可能被改写或碎片错位，"
                              "相关目录下的痕迹会缺失）" % (
                                  len(res["suspicious"]),
                                  ", ".join(x["path"] for x in res["suspicious"])))
        return res

    def _walk(self, root, max_depth=8, fs=None):
        fs = fs or self.fs
        ino = fs_lookup(fs, root)
        if ino is None:
            return
        stack = [(root, ino, 0)]
        while stack:
            path, cur, depth = stack.pop()
            yield path, cur, depth
            if depth >= max_depth or not _is_dir(cur):
                continue
            try:
                ents = list(fs.listdir(cur))
            except Exception:
                continue
            for e in ents:
                if e.name in (".", ".."):
                    continue
                child = None
                try:
                    child = fs.inode(getattr(e, "inode", None))
                except Exception:
                    child = None
                if child is None:
                    continue
                cpath = (path.rstrip("/") + "/" + e.name)
                if cpath in SKIP_DIRS:
                    continue
                if cpath in SUID_SCAN_SKIP:
                    continue
                stack.append((cpath, child, depth + 1))

    # ================================================== name resolution
    def name_resolution_files(self):
        res = dict(files={}, hosts=[], nameservers=[], search=[], options=[],
                   nsswitch={}, missing=[])
        for path in ("/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf"):
            txt = self._text(path, 1 << 20)
            if txt is None:
                res["missing"].append(path)
                self.notes.append("未找到 %s" % path)
                continue
            res["files"][path] = txt
        hosts = res["files"].get("/etc/hosts", "")
        for line in hosts.splitlines():
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            parts = s.split()
            if len(parts) >= 2:
                res["hosts"].append(dict(ip=parts[0], names=parts[1:], raw=s))
        resolv = res["files"].get("/etc/resolv.conf", "")
        for line in resolv.splitlines():
            s = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not s:
                continue
            parts = s.split()
            if parts[0] == "nameserver" and len(parts) > 1:
                res["nameservers"].append(parts[1])
            elif parts[0] == "search" and len(parts) > 1:
                res["search"].append(parts[1:])
            elif parts[0] == "options" and len(parts) > 1:
                res["options"].append(parts[1:])
        nss = res["files"].get("/etc/nsswitch.conf", "")
        for line in nss.splitlines():
            s = line.split("#", 1)[0].strip()
            if not s or ":" not in s:
                continue
            k, v = s.split(":", 1)
            res["nsswitch"][k.strip()] = v.split()
        return res

    # ========================================================== calendar
    CAL_ROOTS = ("/var/lib/radicale/collections", "/var/www/nextcloud/data",
                 "/var/lib/nextcloud/data", "/data", "/home", "/var/www/html")

    def calendar(self):
        out = []
        seen_files = 0
        for root in self.CAL_ROOTS:
            if not self._exists(root):
                continue
            for path, ino, depth in self._walk(root, max_depth=8):
                if not path.lower().endswith((".ics", ".ifb")):
                    continue
                if _is_dir(ino):
                    continue
                txt = self._text(path, 16 << 20)
                if not txt:
                    continue
                seen_files += 1
                for ev in parse_ics(txt):
                    rec = dict(ev)
                    rec["file"] = path
                    rec["dtstart"] = _fmt(ev["dtstart"])
                    rec["dtend"] = _fmt(ev["dtend"]) if ev["dtend"] else None
                    out.append(rec)
        if not out:
            self.notes.append("未找到 .ics 日历文件（Radicale/Nextcloud 常见路径均已扫描）")
        return out


# --------------------------------------------------------------------------
# 配置解析辅助
# --------------------------------------------------------------------------
def _parse_servers(txt):
    """解析 nginx(server{}) 与 apache(<VirtualHost>) 配置块。"""
    txt = re.sub(r"#[^\n]*", "", txt)
    # apache 段标签 → 大括号
    txt = re.sub(r"<\s*([A-Za-z][\w:]*)([^>]*)>",
                 lambda m: " %s %s { " % (m.group(1), m.group(2).strip()), txt)
    txt = re.sub(r"</\s*[A-Za-z][\w:]*\s*>", " } ", txt)
    toks = txt.replace("{", " { ").replace("}", " } ").replace(";", " ; ").split()
    blocks = []
    stack = []
    cur = None
    pending = None
    i = 0
    n = len(toks)
    while i < n:
        t = toks[i]
        if t == "{":
            blk = dict(type=pending, directives=[], parent_type=stack[-1]["type"] if stack else None)
            stack.append(blk)
            cur = blk
            blocks.append(blk)
            pending = None
            i += 1
            continue
        if t == "}":
            if stack:
                stack.pop()
            cur = stack[-1] if stack else None
            i += 1
            continue
        if t == ";":
            i += 1
            continue
        vals = []
        j = i + 1
        while j < n and toks[j] not in (";", "{", "}"):
            vals.append(toks[j])
            j += 1
        if j < n and toks[j] == "{":
            pending = t
            i = j
            continue
        if cur is not None and vals:
            key = t.lower()
            cur.setdefault(key, " ".join(vals))
            cur["directives"].append("%s %s" % (key, " ".join(vals)))
        i = j
    res = []
    for s in blocks:
        stype = (s.get("type") or "").lower()
        if stype not in ("server", "virtualhost"):
            continue
        rec = dict(
            type=stype,
            server_name=s.get("server_name") or s.get("servername"),
            listen=s.get("listen"),
            root=s.get("root") or s.get("documentroot"),
            documentroot=s.get("documentroot") or s.get("root"),
            access_log=s.get("access_log") or s.get("customlog"),
            error_log=s.get("error_log") or s.get("errorlog"),
            ssl_certificate=s.get("ssl_certificate") or s.get("sslcertificatefile"),
            ssl_certificate_key=s.get("ssl_certificate_key") or s.get("sslcertificatekeyfile"),
            proxy_pass=s.get("proxy_pass"),
            index=s.get("index") or s.get("directoryindex"),
            server_alias=s.get("server_alias") or s.get("serveralias"),
            directives=s.get("directives", [])[:60],
        )
        res.append(rec)
    return res


def parse_mdstat(txt):
    """解析 /proc/mdstat。"""
    arrays = []
    cur = None
    for line in txt.splitlines():
        m = re.match(r"^(md\S+)\s*:\s*(.*)$", line)
        if m:
            cur = dict(name=m.group(1), state=m.group(2).strip(), level=None,
                       members=[], blocks=None, status=[], raw=[line])
            arrays.append(cur)
            lvl = re.search(r"raid\d+", m.group(2))
            if lvl:
                cur["level"] = lvl.group(0)
            for tok in m.group(2).split():
                mm = re.match(r"^(\w+)\[(\d+)\](\w*)$", tok)
                if mm:
                    cur["members"].append(dict(device=mm.group(1),
                                               slot=int(mm.group(2)),
                                               flag=mm.group(3) or None))
            continue
        if cur is None:
            continue
        cur["raw"].append(line)
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith("unused devices"):
            cur = None
            continue
        mm = re.match(r"^(\d+)\s+blocks\s*(.*)$", s)
        if mm:
            cur["blocks"] = int(mm.group(1))
            cur["status"] = mm.group(2).split()
            continue
        for tok in s.split():
            mm2 = re.match(r"^(\w+)\[(\d+)\](\w*)$", tok)
            if mm2:
                cur["members"].append(dict(device=mm2.group(1),
                                           slot=int(mm2.group(2)),
                                           flag=mm2.group(3) or None))
    for a in arrays:
        a["raw"] = "\n".join(a["raw"])
        a["degraded"] = ("degraded" in a["state"].lower() or
                         any(m["flag"] and "F" in m["flag"] for m in a["members"])
                         or "_" in " ".join(a["status"]))
    return arrays


def _hash_algo(h):
    if not h:
        return "empty"
    if h.startswith("!!"):
        return "locked(!!)"
    if h.startswith("!"):
        rest = h.lstrip("!")
        return "locked!" + (" (" + _hash_algo(rest) + ")" if rest else "")
    if h in ("*", "x"):
        return "locked/nologin"
    if h.startswith("$1$"):
        return "MD5($1$)"
    if h.startswith(("$2a$", "$2b$", "$2y$", "$2x$")):
        return "bcrypt($2*)"
    if h.startswith("$5$"):
        return "SHA-256($5$)"
    if h.startswith("$6$"):
        return "SHA-512($6$)"
    if h.startswith("$y$"):
        return "yescrypt($y$)"
    if h.startswith("$gy$"):
        return "gost-yescrypt($gy$)"
    if h.startswith("$7$"):
        return "scrypt($7$)"
    if h.startswith("$md5"):
        return "Sun-MD5($md5)"
    if h.startswith("$"):
        return "unknown(%s...)" % h[:2]
    if len(h) == 13:
        return "DES(13char)"
    return "unknown(len=%d)" % len(h)


def _json_time(value):
    """Docker Created 是 RFC3339 字符串或纳秒整数。"""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e17:
            v /= 1e9
        return _dt(v)
    if isinstance(value, str):
        s = value.replace("Z", "+00:00")
        m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?([+-]\d\d:\d\d)?$", s)
        if m:
            base = m.group(1) + (m.group(3) or "")
            try:
                return datetime.datetime.fromisoformat(base)
            except ValueError:
                return None
    return None
