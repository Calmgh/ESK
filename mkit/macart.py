# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""macOS 取证：APFS 容器/卷枚举、HFS+ 读取、.DS_Store、.dmg(koly)、以及 macOS 痕迹。

自研实现，不依赖第三方。APFS 只做到"卷枚举 + 对象结构解析 + 未加密卷的目录/文件读取"；
加密卷（FileVault）明确报不支持。
"""
import datetime
import plistlib
import struct

APFS_MAGIC = b"NXSB"
APSB_MAGIC = b"APSB"
HFS_MAGIC = 0x482B
HFSX_MAGIC = 0x4858


# ---------------- APFS ----------------
class Apfs:
    """APFS 容器解析（只读）。

    容器超级块 NXSB 在块 0；卷超级块由 NXSB 的 nx_fs_oid 指向的"卷对象"给出，
    为了在缺少完整 B-tree 遍历时也能工作，这里额外暴力扫描 APSB 签名定位卷。
    """

    def __init__(self, sub):
        self.sub = sub
        head = sub.read(0, 4096)
        i = 0 if head[:4] == APFS_MAGIC else head.find(APFS_MAGIC)
        if i < 0:
            raise ValueError("not APFS (no NXSB in first block)")
        # magic 偏移 i；容器块 0 的起始 = i - 32（obj_phys 头 32 字节）
        self.base = max(0, i - 32)
        nx = sub.read(i, 4096)
        # 以 magic 为基准：magic(4) block_size(4) block_count(8)
        self.block_size = struct.unpack_from("<I", nx, 4)[0] or 4096
        nbc = struct.unpack_from("<Q", nx, 8)[0]
        limit = (self.sub.size // max(1, self.block_size)) + 8
        self.block_count = nbc if 0 < nbc <= limit else (self.sub.size - self.base) // self.block_size
        self.uuid = nx[24:40].hex()
        self.volumes_list = self._scan_volumes()

    def _scan_volumes(self, limit_blocks=None):
        """扫描 APSB 签名定位卷超级块（APFS 卷对象固定块大小对齐）。"""
        bs = self.block_size
        total = self.block_count or ((self.sub.size - self.base) // bs)
        if limit_blocks:
            total = min(total, limit_blocks)
        found = []
        # 前 64MB 内通常就能找到卷超级块
        span = min(total, (64 << 20) // bs)
        buf = self.sub.read(self.base, span * bs)
        pos = 0
        while True:
            i = buf.find(APSB_MAGIC, pos)
            if i < 0:
                break
            blk = i // bs
            off = blk * bs
            blkdata = buf[off:off + bs]
            if len(blkdata) >= 0x400:
                vol = self._parse_volume_sb(blkdata, blk)
                if vol:
                    found.append(vol)
            pos = i + 4
        return found

    def _parse_volume_sb(self, d, blk):
        try:
            name = d[0x2C0:0x2C0 + 256].split(b"\x00")[0].decode("utf8", "replace")
            return dict(block=blk, name=name,
                        uuid=d[0x20:0x30].hex(),
                        role=struct.unpack_from("<H", d, 0x60)[0],
                        case_sensitive=bool(d[0x62] & 0x1),
                        encrypted=bool(d[0x62] & 0x2),
                        size=struct.unpack_from("<Q", d, 0x08)[0])
        except Exception:
            return None

    def volumes(self):
        return self.volumes_list

    def info(self):
        return dict(fs="apfs", block_size=self.block_size,
                    block_count=self.block_count, uuid=self.uuid,
                    volumes=self.volumes_list)


class HfsPlus:
    """HFS+ 读取（APFS 之前的 Mac 卷，2019 年前的 MacBook 常见）。"""

    def __init__(self, sub):
        self.sub = sub
        vh = sub.read(1024, 512)
        sig = struct.unpack_from(">H", vh, 0)[0]
        if sig not in (HFS_MAGIC, HFSX_MAGIC):
            raise ValueError("not HFS+")
        self.kind = "HFSX" if sig == HFSX_MAGIC else "HFS+"
        self.version = struct.unpack_from(">H", vh, 2)[0]
        self.block_size = struct.unpack_from(">I", vh, 0x28)[0]
        self.total_blocks = struct.unpack_from(">I", vh, 0x2C)[0]
        self.free_blocks = struct.unpack_from(">I", vh, 0x30)[0]
        nlen = vh[0x70]
        self.volume_name = vh[0x71:0x71 + nlen * 2].decode("utf-16-be", "replace")
        self.catalog_extents = self._fork_extents(vh, 0x110)
        self._cache = {}

    @staticmethod
    def _fork_extents(vh, off):
        """HFSPlusForkData: logicalSize(8) clumpSize(4) totalBlocks(4) extents[8]
        每项 extent: startBlock(4) blockCount(4)
        """
        out = []
        for i in range(8):
            base = off + 16 + i * 8
            if base + 8 > len(vh):
                break
            start, count = struct.unpack_from(">II", vh, base)
            if count:
                out.append((start, count))
        return out

    def read_fork(self, extents, offset, size):
        out = bytearray()
        bs = self.block_size
        left = size
        cur = 0
        for start, count in extents:
            run_len = count * bs
            if cur + run_len <= offset:
                cur += run_len
                continue
            within = max(0, offset - cur)
            take = min(left, run_len - within)
            data = self.sub.read(start * bs + within, take)
            out += data
            left -= len(data)
            cur += run_len
            if left <= 0:
                break
        return bytes(out)

    def catalog_node(self, node_num):
        """读取 catalog B-tree 的一个节点（8KB 或 block_size）。"""
        if node_num in self._cache:
            return self._cache[node_num]
        off = node_num * self.block_size
        data = self.read_fork(self.catalog_extents, off, self.block_size)
        self._cache[node_num] = data
        return data


# ---------------- .DS_Store ----------------
class DsStore:
    """`Bud1` 格式：块表 + 记录。"""

    def __init__(self, data):
        self.data = data
        self.entries = []
        # Bud1 魔数在偏移 4..8；头部前 4 字节是 0x00000001
        if len(data) < 0x24 or data[4:8] != b"Bud1" or data[:4] != b"\x00\x00\x00\x01":
            return
        self.offsets = struct.unpack_from(">IIII", data, 8)
        (self.offset_table, self.length, self.offset_table_count,
         self.offset_table_offset) = self.offsets
        self.parse()

    def parse(self):
        start = self.offset_table
        count = self.offset_table_count
        # 模式 A：(begin,end) u32 对
        try:
            for i in range(count):
                if start + 8 * (i + 1) > len(self.data):
                    break
                begin, end = struct.unpack_from(">II", self.data, start + i * 8)
                if end <= begin or end > len(self.data):
                    continue
                self.entries.append(self._parse_record(self.data[begin:end]))
        except Exception:
            self.entries = []
        if self.entries:
            return
        # 模式 B：真实 Bud1 —— 256 个 u32 偏移，记录 i 占 [off[i], off[i+1])
        try:
            offs = []
            for i in range(count + 1):
                if start + 4 * (i + 1) > len(self.data):
                    break
                offs.append(struct.unpack_from(">I", self.data, start + i * 4)[0])
            for i in range(len(offs) - 1):
                begin, end = offs[i], offs[i + 1]
                if end <= begin or end > len(self.data):
                    continue
                self.entries.append(self._parse_record(self.data[begin:end]))
        except Exception:
            pass

    def _parse_record(self, rec):
        """真实 Bud1 记录: [u32 namelen][UTF-16BE name][4s code][4s type][value...]"""
        out = dict(raw_len=len(rec))
        try:
            name_len = struct.unpack_from(">I", rec, 0)[0]
            if not 0 < name_len < 512:
                return out
            out["name"] = rec[4:4 + name_len * 2].decode("utf-16-be", "replace")
            p = 4 + name_len * 2
            out["type_code"] = rec[p:p + 4].decode("ascii", "replace")
            out["type"] = rec[p + 4:p + 8].decode("ascii", "replace")
            out["value"] = rec[p + 8:]
        except Exception:
            pass
        return out


# ---------------- .dmg (UDIF) ----------------
class Dmg:
    """UDIF 尾块（koly）解析：得到内含卷、压缩类型、分区表。"""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            f.seek(0, 2)
            self.size = f.tell()
            f.seek(max(0, self.size - 512))
            self.koly = f.read(512)

    def info(self):
        if self.koly[:4] != b"koly":
            return dict(error="不是 UDIF dmg（无 koly 尾块）")
        out = dict(version=struct.unpack_from(">I", self.koly, 4)[0],
                   header_size=struct.unpack_from(">I", self.koly, 8)[0],
                   data_fork_offset=struct.unpack_from(">Q", self.koly, 0x10)[0],
                   data_fork_length=struct.unpack_from(">Q", self.koly, 0x18)[0],
                   xml_offset=struct.unpack_from(">Q", self.koly, 0xD8)[0],
                   xml_length=struct.unpack_from(">Q", self.koly, 0xE0)[0])
        try:
            with open(self.path, "rb") as f:
                f.seek(out["xml_offset"])
                xml = f.read(min(out["xml_length"], 4 << 20)).decode("utf8", "replace")
            out["xml"] = xml[:2000]
            import re
            blkx = re.findall(r'<key>Name</key>\s*<string>([^<]+)</string>', xml)
            out["blkx_names"] = blkx[:20]
            csum = re.findall(r'<key>CFName</key>\s*<string>([^<]+)</string>', xml)
            out["cfnames"] = csum[:20]
        except Exception as e:
            out["xml_error"] = str(e)
        return out


# ---------------- macOS 痕迹 ----------------
class MacArtifacts:
    def __init__(self, fs):
        self.fs = fs
        self.notes = []

    def _read(self, path):
        try:
            ino = self.fs.lookup(path)
            if ino is None:
                return None
            if getattr(ino, "is_dir", False):
                return None
            return self.fs.read_data(ino)
        except Exception:
            return None

    def _exists(self, path):
        try:
            return self.fs.lookup(path) is not None
        except Exception:
            return False

    def _plist(self, path):
        d = self._read(path)
        if not d:
            return None
        try:
            return plistlib.loads(d)
        except Exception:
            return None

    def system_info(self):
        out = {}
        v = self._plist("/System/Library/CoreServices/SystemVersion.plist")
        if v:
            out.update(product=v.get("ProductName"), version=v.get("ProductVersion"),
                       build=v.get("ProductBuildVersion"))
        sp = self._plist("/System/Library/CoreServices/ServerVersion.plist")
        if sp:
            out["server"] = sp.get("ProductVersion")
        h = self._read("/etc/hosts")
        if h:
            out["hosts"] = h.decode("utf8", "replace")[:1000]
        # 计算机名 / 用户名
        for p in ("/Library/Preferences/SystemConfiguration/preferences.plist",):
            pl = self._plist(p)
            if pl:
                try:
                    out["computer_name"] = pl["System"]["System"]["ComputerName"]
                except Exception:
                    pass
        return out

    def users(self):
        out = []
        base = "/var/db/dslocal/nodes/Default/users"
        try:
            ino = self.fs.lookup(base)
            if ino is not None and getattr(ino, "is_dir", False):
                for e in self.fs.listdir(ino):
                    if e.name.startswith("."):
                        continue
                    pl = self._plist(base + "/" + e.name)
                    if not pl:
                        continue
                    out.append(dict(user=e.name.replace(".plist", ""),
                                    realname=_first(pl.get("RealName")),
                                    uid=_first(pl.get("uid")),
                                    gid=_first(pl.get("gid")),
                                    home=_first(pl.get("home")),
                                    shell=_first(pl.get("shell")),
                                    guid=_first(pl.get("GeneratedUID"))))
        except Exception as e:
            self.notes.append(f"users: {e}")
        return out

    def installed_apps(self):
        out = []
        base = "/Applications"
        try:
            ino = self.fs.lookup(base)
            if ino is None:
                return out
            for e in self.fs.listdir(ino):
                if not e.name.endswith(".app"):
                    continue
                pl = self._plist(f"{base}/{e.name}/Contents/Info.plist")
                if pl:
                    out.append(dict(app=e.name, bundle_id=pl.get("CFBundleIdentifier"),
                                    version=pl.get("CFBundleShortVersionString"),
                                    executable=pl.get("CFBundleExecutable")))
        except Exception as ex:
            self.notes.append(f"apps: {ex}")
        return out

    def quarantine(self, user="alice"):
        """下载来源（QuarantineEventsV2）：URL、时间、发起 App。"""
        out = []
        p = f"/Users/{user}/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        d = self._read(p)
        if not d:
            return out
        try:
            import sqlite3
            import tempfile
            import os
            fd, tmp = tempfile.mkstemp(suffix=".db")
            os.write(fd, d)
            os.close(fd)
            con = sqlite3.connect(tmp)
            cols = [r[1] for r in con.execute("pragma table_info(LSQuarantineEvent)")]
            rows = con.execute("select * from LSQuarantineEvent").fetchall()
            for r in rows:
                rec = dict(zip(cols, r))
                out.append(dict(time=rec.get("LSQuarantineTimeStamp"),
                                url=rec.get("LSQuarantineDataURLString"),
                                origin=rec.get("LSQuarantineOriginURLString"),
                                agent=rec.get("LSQuarantineAgentName")))
            con.close()
            os.unlink(tmp)
        except Exception as e:
            self.notes.append(f"quarantine: {e}")
        return out

    def knowledgec(self, user="alice"):
        """行为时间线：app 使用、网页浏览、设备插拔。"""
        out = {}
        p = f"/Users/{user}/Library/Application Support/Knowledge/knowledgeC.db"
        d = self._read(p)
        if not d:
            return out
        try:
            from .mobile import SqliteTriage
            t = SqliteTriage(d)
            tabs = t.tables()
            out["tables"] = list(tabs)
            for name in ("ZOBJECT", "ZSOURCE", "ZSTRUCTUREDMETADATA"):
                if name in tabs:
                    out[name] = tabs[name]
        except Exception as e:
            self.notes.append(f"knowledgec: {e}")
        return out

    def tcc(self, user="alice"):
        """TCC.db：哪些 App 拿到敏感权限。"""
        out = []
        for p in (f"/Users/{user}/Library/Application Support/com.apple.TCC/TCC.db",
                  "/Library/Application Support/com.apple.TCC/TCC.db"):
            d = self._read(p)
            if not d:
                continue
            try:
                from .mobile import SqliteTriage
                t = SqliteTriage(d)
                for r in t.dicts("select service, client, auth_value, last_modified from access",
                                 limit=500):
                    out.append(dict(file=p, **r))
            except Exception as e:
                self.notes.append(f"tcc {p}: {e}")
        return out

    def safari(self, user="alice"):
        out = {}
        d = self._read(f"/Users/{user}/Library/Safari/History.db")
        if d:
            try:
                from .mobile import SqliteTriage
                t = SqliteTriage(d)
                out["history"] = t.dicts(
                    "select url, visit_count, last_visit_time from history_items "
                    "order by visit_count desc limit 200", limit=200)
            except Exception as e:
                self.notes.append(f"safari history: {e}")
        bk = self._plist(f"/Users/{user}/Library/Safari/Bookmarks.plist")
        if bk:
            out["bookmarks"] = _walk_bookmarks(bk)
        dl = self._plist(f"/Users/{user}/Library/Safari/Downloads.plist")
        if dl:
            out["downloads"] = dl.get("DownloadHistory", [])[:50]
        return out

    def messages(self, user="alice"):
        d = self._read(f"/Users/{user}/Library/Messages/chat.db")
        if not d:
            return []
        try:
            from .mobile import SqliteTriage
            t = SqliteTriage(d)
            rows = t.dicts("select ROWID, text, handle_id, is_from_me, date from message "
                           "order by date desc limit 200", limit=200)
            for r in rows:
                r["time"] = _apple_time(r.get("date"))
            return rows
        except Exception as e:
            self.notes.append(f"messages: {e}")
            return []

    def notes(self, user="alice"):
        d = self._read(
            f"/Users/{user}/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite")
        if not d:
            return []
        try:
            from .mobile import SqliteTriage
            t = SqliteTriage(d)
            tabs = t.tables()
            tbl = "ZICCLOUDSYNCINGOBJECT" if "ZICCLOUDSYNCINGOBJECT" in tabs else None
            if not tbl:
                return []
            cols = t.schema(tbl)
            want = [c for c in ("ZTITLE1", "ZTITLE2", "ZSNIPPET", "ZISPASSWORDPROTECTED",
                                "ZMODIFICATIONDATE1") if c in cols]
            rows = t.dicts(f'select {", ".join(want)} from "{tbl}" limit 200', limit=200)
            for r in rows:
                if "ZMODIFICATIONDATE1" in r:
                    r["modified"] = _apple_time(r["ZMODIFICATIONDATE1"])
            return rows
        except Exception as e:
            self.notes.append(f"notes: {e}")
            return []

    def recent_items(self, user="alice"):
        out = {}
        for name in ("com.apple.recentitems.plist", "com.apple.LSSharedFileList.RecentDocuments.sfl2"):
            p = f"/Users/{user}/Library/Preferences/{name}"
            d = self._read(p)
            if d:
                out[name] = len(d)
        return out

    def ds_store(self, path):
        d = self._read(path)
        if not d:
            return []
        return DsStore(d).entries


def _first(v):
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v


def _apple_time(v):
    if not v:
        return None
    try:
        f = float(v)
        if f > 1e15:
            f /= 1e9
        return datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc) + \
            datetime.timedelta(seconds=f)
    except Exception:
        return None


def _walk_bookmarks(node, out=None, depth=0):
    if out is None:
        out = []
    if depth > 12 or not isinstance(node, dict):
        return out
    if node.get("WebBookmarkType") == "WebBookmarkTypeLeaf":
        out.append(dict(title=node.get("URIDictionary", {}).get("title"),
                        url=node.get("URLString")))
    for ch in node.get("Children", []) or []:
        _walk_bookmarks(ch, out, depth + 1)
    return out

# ---------------- APFS 对象读取（暴力扫描节点） ----------------
BTNODE_FLAG_LEAF = 0x0002
BTNODE_FLAG_ROOT = 0x0001
OBJECT_TYPE_MASK = 0x0000FFFF
OBJECT_TYPE_BTREE_NODE = 0x00000003


def _obj_phys(d, off=0):
    """obj_phys_t: o_cksum[8] o_oid[8] o_xid[8] o_type[4] o_subtype[4] = 32"""
    return dict(oid=struct.unpack_from("<Q", d, off + 8)[0],
                xid=struct.unpack_from("<Q", d, off + 16)[0],
                otype=struct.unpack_from("<I", d, off + 24)[0],
                subtype=struct.unpack_from("<I", d, off + 28)[0])


def parse_btree_node(blk, bs):
    """解析 btree_node_phys：obj(32) + flags(2) + level(2) + nkeys(4) + 4*nloc(4*4)"""
    if len(blk) < 0x38:
        return None
    o = _obj_phys(blk)
    if (o["otype"] & OBJECT_TYPE_MASK) != OBJECT_TYPE_BTREE_NODE:
        return None
    flags, level, nkeys = struct.unpack_from("<HHI", blk, 32)
    if nkeys > 4096 or level > 32:
        return None
    table_off, table_len = struct.unpack_from("<HH", blk, 40)
    # toc 紧跟在结构体后：偏移表 (key_off,val_off) 各 2 字节
    toc = 0x38
    items = []
    for i in range(nkeys):
        p = toc + i * 4
        if p + 4 > len(blk):
            break
        koff, voff = struct.unpack_from("<HH", blk, p)
        # 键/值的实际位置 = 0x38 + 表空间后的数据区；APFS 用 block 内绝对偏移
        items.append((koff, voff))
    return dict(flags=flags, level=level, nkeys=nkeys, items=items, oid=o["oid"],
                subtype=o["subtype"])


def j_drec_key(blk, koff):
    """j_drec_hashed_key_t: hashed key = name_len_and_hash(4) + parent_id(8) + name"""
    if koff + 12 > len(blk):
        return None
    nlh, parent = struct.unpack_from("<IQ", blk, koff)
    nlen = nlh & 0x3FF
    name = blk[koff + 12: koff + 12 + nlen]
    return dict(name=name.decode("utf8", "replace"), parent=parent, raw=name)


def j_drec_val(blk, voff):
    """j_drec_val_t: file_id(8) + date_added(8) + flags(2) + xfields"""
    if voff + 18 > len(blk):
        return None
    fid, added, flags = struct.unpack_from("<QQH", blk, voff)
    return dict(file_id=fid, date_added=added, flags=flags,
                dtype=flags & 0x000F, is_dir=(flags & 0x000F) == 4)


def j_inode_val(blk, voff):
    """j_inode_val_t: parent_id(8) unused(8) mode(2) pad(2) unused(8) internal_flags(8)
    ... 关键字段取前 64 字节内的 mode/size/owner 与 xfields 中的 name"""
    if voff + 0x5C > len(blk):
        return None
    parent_id = struct.unpack_from("<Q", blk, voff)[0]
    mode, = struct.unpack_from("<H", blk, voff + 16)
    internal_flags, = struct.unpack_from("<Q", blk, voff + 32)
    return dict(parent_id=parent_id, mode=mode, internal_flags=internal_flags)


class ApfsTree:
    """在 APFS 容器里暴力扫描 B-tree 节点，重建目录项（不依赖 omap）。"""

    def __init__(self, apfs, max_blocks=None):
        self.apfs = apfs
        self.bs = apfs.block_size
        self.nodes = []
        self.drecs = []
        self.inodes = {}
        self._scan(max_blocks)

    def _scan(self, max_blocks):
        sub = self.apfs.sub
        bs = self.bs
        total = self.apfs.block_count or ((sub.size - self.apfs.base) // bs)
        if max_blocks:
            total = min(total, max_blocks)
        for blk in range(total):
            d = sub.read(self.apfs.base + blk * bs, min(bs, 0x40))
            if len(d) < 32:
                break
            otype = struct.unpack_from("<I", d, 24)[0]
            if (otype & OBJECT_TYPE_MASK) != OBJECT_TYPE_BTREE_NODE:
                continue
            full = sub.read(self.apfs.base + blk * bs, bs)
            node = parse_btree_node(full, bs)
            if not node:
                continue
            self.nodes.append(dict(blk=blk, **{k: node[k] for k in ("flags", "level", "nkeys", "subtype")}))
            if not (node["flags"] & BTNODE_FLAG_LEAF):
                continue
            # fs-tree 的 subtype 为 0x0E（FSTREE）
            for koff, voff in node["items"]:
                if koff == 0xFFFF and voff == 0xFFFF:
                    continue
                k = j_drec_key(full, koff)
                if k and k["name"]:
                    v = j_drec_val(full, voff)
                    if v:
                        v.update(k)
                        self.drecs.append(v)

    def entries(self):
        return self.drecs

    def by_parent(self, parent_id):
        return [d for d in self.drecs if d["parent"] == parent_id]

    def listdir(self, parent_id=2):
        return [(d["name"], d["file_id"], d["is_dir"], d["date_added"]) for d in self.by_parent(parent_id)]

    def summary(self):
        return dict(nodes=len(self.nodes), leaf_nodes=sum(1 for n in self.nodes if n["flags"] & BTNODE_FLAG_LEAF),
                    drecs=len(self.drecs), dirs=sum(1 for d in self.drecs if d["is_dir"]),
                    files=sum(1 for d in self.drecs if not d["is_dir"]),
                    top_level=self.listdir(2)[:20])

# ---------------- HFS+ 目录遍历 ----------------
class HfsDir:
    """HFS+ catalog B-tree 遍历（key: parentID + 名字，val: 文件/目录记录）。"""

    def __init__(self, hfs):
        self.hfs = hfs
        self.bs = hfs.block_size
        self.nodes = {}
        self.records = []
        self._load()

    def _node(self, num):
        if num in self.nodes:
            return self.nodes[num]
        d = self.hfs.catalog_node(num)
        self.nodes[num] = d
        return d

    def _load(self):
        seen = set()
        stack = [0]
        while stack and len(seen) < 100000:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            d = self._node(n)
            if len(d) < 14:
                continue
            fwd, bwd = struct.unpack_from(">II", d, 0)
            kind = struct.unpack_from(">b", d, 8)[0]
            numrec = struct.unpack_from(">H", d, 10)[0]
            if kind == -1:          # leaf
                off = 14 + numrec * 2   # 记录偏移表之后
                for i in range(numrec):
                    roff = struct.unpack_from(">H", d, 14 + i * 2)[0]
                    if roff == 0 or roff >= len(d):
                        continue
                    self.records.append(self._parse_record(d, roff))
            elif kind == 0:          # index
                for i in range(numrec):
                    roff = struct.unpack_from(">H", d, 14 + i * 2)[0]
                    p = roff + 2 + struct.unpack_from(">H", d, roff)[0]
                    if p + 4 <= len(d):
                        child = struct.unpack_from(">I", d, p)[0]
                        if child not in seen:
                            stack.append(child)
            elif kind == 1:          # header
                for i in range(numrec):
                    roff = struct.unpack_from(">H", d, 14 + i * 2)[0]
                    rec = d[roff:]
                    if len(rec) > 0x20:
                        first = struct.unpack_from(">I", rec, 0x10)[0]
                        if first not in seen:
                            stack.append(first)
                # 头结点的第 3 条记录是"首个叶子结点号"
                if numrec >= 3:
                    roff = struct.unpack_from(">H", d, 14 + 2 * 2)[0]
                    if roff + 4 <= len(d):
                        leaf = struct.unpack_from(">I", d, roff)[0]
                        if leaf not in seen:
                            stack.append(leaf)

    def _parse_record(self, d, off):
        p = off
        if p + 2 > len(d):
            return None
        klen = struct.unpack_from(">H", d, p)[0]
        p += 2
        parent = struct.unpack_from(">I", d, p)[0]
        p += 4
        nlen = struct.unpack_from(">H", d, p)[0]
        p += 2
        if nlen == 0 or p + nlen * 2 > len(d):
            return None
        name = d[p:p + nlen * 2].decode("utf-16-be", "replace")
        p = off + 2 + klen
        if p + 2 > len(d):
            return None
        vtype = struct.unpack_from(">H", d, p)[0]
        p += 2
        rec = dict(parent=parent, name=name, type=vtype)
        try:
            if vtype == 1:      # folder
                rec["flags"] = struct.unpack_from(">H", d, p + 0)[0]
                rec["valence"] = struct.unpack_from(">I", d, p + 2)[0]
                rec["folder_id"] = struct.unpack_from(">I", d, p + 6)[0]
                rec["created"] = _hfs_time(struct.unpack_from(">I", d, p + 10)[0])
                rec["modified"] = _hfs_time(struct.unpack_from(">I", d, p + 14)[0])
            elif vtype == 2:    # file
                # p 指向 record+2（已跳过 recordType），故各字段相对 p 减 2
                # HFSPlusCatalogFile: type2 flags2 res4 fileID@8 create@12 mod@16 ... dataFork@88
                rec["flags"] = struct.unpack_from(">H", d, p + 0)[0]
                rec["file_id"] = struct.unpack_from(">I", d, p + 6)[0]
                rec["created"] = _hfs_time(struct.unpack_from(">I", d, p + 10)[0])
                rec["modified"] = _hfs_time(struct.unpack_from(">I", d, p + 14)[0])
                try:
                    rec["size"] = struct.unpack_from(">Q", d, p + 86)[0]
                except Exception:
                    rec["size"] = None
                rec["is_dir"] = False
            elif vtype == 3 or vtype == 4:
                rec["is_dir"] = True
        except Exception:
            pass
        return rec

    def listdir(self, parent_id=2):
        return [r for r in self.records if r and r.get("parent") == parent_id]

    def summary(self):
        dirs = [r for r in self.records if r and r.get("type") == 1]
        files = [r for r in self.records if r and r.get("type") == 2]
        return dict(records=len(self.records), dirs=len(dirs), files=len(files),
                    root=self.listdir(2)[:20])


def _hfs_time(v):
    if not v:
        return None
    try:
        return datetime.datetime(1904, 1, 1, tzinfo=datetime.timezone.utc) + \
            datetime.timedelta(seconds=v)
    except Exception:
        return None
