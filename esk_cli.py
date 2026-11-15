#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""esk_cli.py -- ESK 的命令行入口

把 mkit 的各模块包成 `<集合> <动词>` 形式的命令，结果以 JSON 或原始字节输出，
便于脚本与代理编排。也可用 `session` 子命令读 JSONL 逐行执行。

用法：
    python esk_cli.py images open  下载.E01
    python esk_cli.py --image 下载.E01 --offset 0x7500000 fs ls /
    python esk_cli.py --image 下载.E01 fs tree / --depth 2
    python esk_cli.py --image 下载.E01 fs cat /etc/passwd -o passwd.txt
    python esk_cli.py hash 下载.E01
    python esk_cli.py --image 下载.E01 search "password" --encodings ascii,utf16le
    python esk_cli.py --image 下载.E01 carve --kinds jpeg,png --out carved/
    python esk_cli.py --image 下载.E01 luks
    python esk_cli.py schema fs cat
    python esk_cli.py session --events          # 读 stdin 的 JSONL

设计说明：
    · 各文件系统模块的接口不统一（有按路径的、按 inode 的、按 entry 的），
      这里用 FsAdapter 抹平差异，对外只暴露 ls / tree / cat / find。
    · 所有命令都支持 --json，输出机器可读结构。
    · 只读；不实现写操作。
"""

import argparse
import json
import os
import sys
import traceback

__all__ = ["main", "FsAdapter", "open_image", "detect_fs"]

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

__version__ = "1.0.0"

# ------------------------------------------------------------
# 输出
# ------------------------------------------------------------
_QUIET = False


def out(obj, as_json=True):
    """统一输出：as_json 时打印 JSON，否则打印人类可读文本"""
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, default=str))
    else:
        if isinstance(obj, dict):
            for k, v in obj.items():
                print("%-22s %s" % (k, v))
        elif isinstance(obj, (list, tuple)):
            for x in obj:
                print(x)
        else:
            print(obj)


def err(msg, code=1):
    sys.stderr.write("error: %s\n" % msg)
    return code


# ------------------------------------------------------------
# 镜像打开
# ------------------------------------------------------------
def open_image(path):
    """按魔数识别容器并返回 (device, kind)

    支持：EWF(.E01) / 裸镜像 / VMDK / QCOW2 / VDI
    """
    from mkit.image import Image
    import mkit.vdisk as vdisk

    with open(path, "rb") as f:
        head = f.read(512)

    # 裸镜像 / EWF 交给 mkit.image
    if head[:4] == b"KDMV":
        import webvm3_dev                      # 在 ext/ 下
        return webvm3_dev.Dev1(path), "vmdk"
    if len(head) >= 4 and head[0:4] in (b"QFI\xfb",):
        return vdisk.Qcow2(open(path, "rb")), "qcow2"
    if len(head) >= 4 and head[0:4] == b"\x7f\x10\xda\xbe":
        return vdisk.Vdi(open(path, "rb")), "vdi"
    if head[:8] == b"vhdxfile":
        raise NotImplementedError("VHDX 需要 ext/ans_c02_vhdx.py，未接入 CLI")
    img = Image(path)
    return img, "raw-or-ewf"


def partitions(dev):
    """取分区表；没有分区表时返回整盘一个"分区"""
    import mkit.volume as volume
    try:
        parts = volume._gpt(dev, None)
    except Exception:
        parts = None
    if not parts:
        try:
            parts = volume.parse(dev)
        except Exception:
            parts = None
    if not parts:
        return [{"index": 0, "offset": 0, "size": getattr(dev, "size", 0),
                 "type": "whole", "type_id": None}]
    return parts


def detect_fs(dev, offset, size):
    """在给定偏移上猜文件系统，返回 (name, fs_obj 或 None, 错误说明)"""
    import mkit.volume as volume
    name = None
    try:
        name = volume.guess_filesystem(dev, offset, size)
    except Exception:
        name = None

    from mkit.image import SubImage
    try:
        sub = SubImage(dev, offset, size)
    except Exception as e:
        return (name or "unknown", None, "SubImage 失败: %s" % e)

    builders = [
        ("ntfs",      lambda: __import__("mkit.ntfs", fromlist=["NTFS"]).NTFS(sub)),
        ("ext4",      lambda: __import__("mkit.ext4", fromlist=["Ext4"]).Ext4(sub)),
        ("fat",       lambda: __import__("mkit.fat", fromlist=["Fat"]).Fat(sub)),
        ("exfat",     lambda: __import__("mkit.exfat", fromlist=["Exfat"]).Exfat(sub)),
        ("xfs",       lambda: __import__("mkit.xfs", fromlist=["Xfs"]).Xfs(sub)),
        ("squashfs",  lambda: __import__("mkit.squashfs", fromlist=["Squashfs"]).Squashfs(sub)),
        ("cramfs",    lambda: __import__("mkit.cramfs", fromlist=["Cramfs"]).Cramfs(sub)),
        ("romfs",     lambda: __import__("mkit.romfs", fromlist=["Romfs"]).Romfs(sub)),
        ("iso",       lambda: __import__("mkit.iso", fromlist=["Iso9660"]).Iso9660(sub)),
    ]
    # 先试猜出来的那个，再按顺序试其余
    order = ([name] if name in dict(builders) else []) + \
            [k for k, _ in builders if k != name]
    last = None
    for want in order:
        fn = dict(builders).get(want)
        if fn is None:
            continue
        try:
            fs = fn()
            return (want, fs, "")
        except Exception as e:
            last = "%s: %s" % (want, e)
            continue
    return (name or "unknown", None, last or "无匹配的文件系统")


# ------------------------------------------------------------
# 文件系统适配层
# ------------------------------------------------------------
class FsAdapter(object):
    """把各 FS 模块的异构接口抹平成 ls / tree / cat / find"""

    def __init__(self, name, fs):
        self.name = name
        self.fs = fs

    # ---- 取条目元信息（字段名各模块不同，这里做启发式提取）----
    @staticmethod
    def _meta(item):
        name = getattr(item, "name", None)
        size = getattr(item, "size", None)
        if size is None:
            size = getattr(item, "file_size", None)
        is_dir = getattr(item, "is_dir", None)
        if is_dir is None:
            t = getattr(item, "type_name", None) or ""
            is_dir = (t == "dir")
        deleted = bool(getattr(item, "deleted", False))
        return {"name": name, "size": size, "is_dir": bool(is_dir),
                "deleted": deleted}

    # ---- 列目录 ----
    def ls(self, path="/"):
        fs = self.fs
        if path in ("/", ""):
            entries = fs.listdir(None) if self._accepts_none(fs.listdir) else fs.listdir()
        else:
            # 有 read_path/lookup_path 的先解析成对象
            target = None
            for meth in ("lookup_path", "read_path"):
                if hasattr(fs, meth):
                    try:
                        target = getattr(fs, meth)(path)
                        break
                    except Exception:
                        target = None
            if target is None:
                target = self._resolve(path)
            entries = fs.listdir(target)
        out_list = []
        for e in entries:
            m = self._meta(e)
            if m["name"] in (".", ".."):
                continue
            m["path"] = (path.rstrip("/") + "/" + str(m["name"])).replace("//", "/")
            out_list.append(m)
        return out_list

    @staticmethod
    def _accepts_none(fn):
        try:
            import inspect
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            if not params:
                return False
            p = params[0]
            return p.default is None or p.default is not inspect._empty
        except Exception:
            return True

    def _resolve(self, path):
        """按路径逐级解析成 listdir 能接受的 entry 对象"""
        fs = self.fs
        cur = None
        for part in [p for p in path.split("/") if p]:
            entries = fs.listdir(cur)
            hit = None
            for e in entries:
                if getattr(e, "name", None) == part:
                    hit = e
                    break
            if hit is None:
                raise FileNotFoundError(path)
            cur = hit
        return cur

    # ---- 递归遍历（统一成 (path, meta) 二元组）----
    def tree(self, path="/", depth=3, limit=100000):
        fs = self.fs
        base = None
        if path not in ("/", ""):
            try:
                base = self._resolve(path)
            except Exception:
                base = None
        results = []
        for item in fs.walk(base):
            if len(results) >= limit:
                break
            if isinstance(item, tuple) and len(item) == 4:
                # squashfs: (name, typ, ref, ino)
                nm, typ = item[0], item[1]
                m = {"name": nm, "size": None,
                     "is_dir": typ in (1, 8), "deleted": False}
                p = nm
            elif isinstance(item, tuple) and len(item) >= 2:
                p = item[0]
                m = self._meta(item[1])
            else:
                continue
            # 深度过滤
            if p.count("/") > depth:
                continue
            m["path"] = p
            results.append(m)
        return results

    # ---- 读文件 ----
    def cat(self, path):
        fs = self.fs
        if hasattr(fs, "read_path"):
            try:
                return fs.read_path(path)
            except Exception:
                pass
        if hasattr(fs, "read_file") and self.name in ("ntfs",):
            return fs.read_file(path)
        target = self._resolve(path)
        return fs.read_file(target)

    # ---- 搜索 ----
    def find(self, pattern, limit=2000):
        fs = self.fs
        if hasattr(fs, "find"):
            try:
                hits = fs.find(pattern)
                res = []
                for h in hits[:limit]:
                    if isinstance(h, tuple) and len(h) >= 2:
                        m = self._meta(h[1])
                        m["path"] = h[0]
                        res.append(m)
                return res
            except Exception:
                pass
        # 退化：遍历后自己匹配
        low = pattern.lower()
        res = []
        for m in self.tree("/", depth=64, limit=200000):
            if low in str(m.get("path", "")).lower():
                res.append(m)
                if len(res) >= limit:
                    break
        return res


# ------------------------------------------------------------
# 命令实现
# ------------------------------------------------------------
def cmd_images_open(args, dev, kind):
    parts = partitions(dev)
    rows = []
    for i, p in enumerate(parts):
        off = p.get("offset", 0)
        size = p.get("size", 0)
        fs_name, fs_obj, why = (None, None, "")
        if size and size > 1024:
            fs_name, fs_obj, why = detect_fs(dev, off, size)
        rows.append({
            "index": p.get("index", i),
            "offset": off,
            "offset_hex": hex(off),
            "size": size,
            "size_gib": round(size / 2 ** 30, 3) if size else 0,
            "partition_type": p.get("type", p.get("type_id")),
            "filesystem": fs_name,
            "fs_error": why or None,
        })
    return {
        "image": args.image,
        "container": kind,
        "size": getattr(dev, "size", None),
        "partition_count": len(rows),
        "partitions": rows,
    }


def _need_fs(args, dev, kind):
    """按 --offset/--fs 定位文件系统并返回 FsAdapter"""
    if args.fs:
        parts = partitions(dev)
        off = args.offset if args.offset is not None else parts[0].get("offset", 0)
        size = args.size if args.size is not None else parts[0].get("size", getattr(dev, "size", 0))
        name, fs, why = detect_fs(dev, off, size)
        if fs is None:
            raise RuntimeError("在该偏移上打不开文件系统: %s" % why)
        return FsAdapter(name, fs)

    if args.offset is not None:
        size = args.size if args.size is not None else getattr(dev, "size", 0) - args.offset
        name, fs, why = detect_fs(dev, args.offset, size)
        if fs is None:
            raise RuntimeError("在偏移 %s 上打不开文件系统: %s" % (hex(args.offset), why))
        return FsAdapter(name, fs)

    # 没指定：在分区表里找第一个能挂上的
    for p in partitions(dev):
        off = p.get("offset", 0)
        size = p.get("size", 0)
        if not size or size < 1024:
            continue
        name, fs, why = detect_fs(dev, off, size)
        if fs is not None:
            return FsAdapter(name, fs)
    raise RuntimeError("没有找到可挂载的文件系统；请用 --offset 指定")


def cmd_fs_ls(args, dev, kind):
    ad = _need_fs(args, dev, kind)
    return {"fs": ad.name, "path": args.path, "entries": ad.ls(args.path)}


def cmd_fs_tree(args, dev, kind):
    ad = _need_fs(args, dev, kind)
    rows = ad.tree(args.path, depth=args.depth, limit=args.limit)
    return {"fs": ad.name, "path": args.path, "depth": args.depth,
            "count": len(rows), "entries": rows}


def cmd_fs_cat(args, dev, kind):
    ad = _need_fs(args, dev, kind)
    data = ad.cat(args.path)
    if data is None:
        raise FileNotFoundError(args.path)
    if args.output:
        with open(args.output, "wb") as f:
            f.write(data)
        return {"fs": ad.name, "path": args.path, "bytes": len(data),
                "written_to": args.output}
    if args.json:
        import base64
        return {"fs": ad.name, "path": args.path, "bytes": len(data),
                "base64": base64.b64encode(data).decode()}
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return None


def cmd_fs_find(args, dev, kind):
    ad = _need_fs(args, dev, kind)
    rows = ad.find(args.pattern, limit=args.limit)
    return {"fs": ad.name, "pattern": args.pattern,
            "count": len(rows), "matches": rows}


def cmd_hash(args, dev, kind):
    import mkit.hashcalc as H
    algos = tuple(a.strip() for a in args.algos.split(",") if a.strip())
    if dev is not None:
        res = H.stream_hash(dev.read, getattr(dev, "size", 0), algos)
        info = {"target": args.image, "algos": list(algos), "hashes": res}
        if args.verify_ewf:
            info["ewf_check"] = H.verify_ewf_hash(dev, algos)
        return info
    res = H.file_hash(args.target, algos)
    return {"target": args.target, "algos": list(algos), "hashes": res}


def cmd_search(args, dev, kind):
    import mkit.search as S
    encs = tuple(e.strip() for e in args.encodings.split(",") if e.strip())
    if dev is None:
        hits = S.scan_file(args.target, args.pattern, encs,
                           is_regex=args.regex, max_hits=args.max_hits)
    else:
        hits = S.scan(dev.read, getattr(dev, "size", 0), args.pattern, encs,
                      is_regex=args.regex, max_hits=args.max_hits)
    rows = [h.as_row() for h in hits]
    if args.csv:
        S.to_csv(hits, args.csv)
    return {"pattern": args.pattern, "encodings": list(encs),
            "count": len(rows), "hits": rows[:args.max_hits]}


def cmd_carve(args, dev, kind):
    import mkit.carve as C
    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()] or None
    if dev is None:
        def rd(off, n, _p=args.target):
            with open(_p, "rb") as f:
                f.seek(off)
                return f.read(n)
        size = os.path.getsize(args.target)
    else:
        rd = dev.read
        size = getattr(dev, "size", 0)
    items = C.carve(rd, size, kinds, args.out, max_per_kind=args.max_per_kind)
    return {
        "count": len(items),
        "out_dir": args.out,
        "items": [{"kind": i.kind, "offset": i.offset, "offset_hex": hex(i.offset),
                   "size": i.size, "truncated": i.truncated} for i in items],
    }


def cmd_luks(args, dev, kind):
    import mkit.luks as L
    parts = partitions(dev)
    rows = []
    for p in parts:
        off = p.get("offset", 0)
        size = p.get("size", 0)
        if not size or size < 4096:
            continue
        from mkit.image import SubImage
        try:
            sub = SubImage(dev, off, size)
        except Exception:
            continue
        v = L.detect(sub)
        if v:
            lk = L.Luks(sub)
            rows.append({"offset": off, "offset_hex": hex(off),
                         "volume": lk.info(), "slots": lk.slot_summary(),
                         "strength": lk.strength_note()})
    return {"count": len(rows), "luks": rows}


# ------------------------------------------------------------
# schema
# ------------------------------------------------------------
SCHEMA = {
    "images open": {"desc": "识别分区表并猜测每个分区的文件系统",
                    "args": {"--image": "镜像路径（必填）"}},
    "fs ls": {"desc": "列目录", "args": {"path": "目录路径，默认 /"}},
    "fs tree": {"desc": "递归遍历", "args": {"path": "起点", "--depth": "最大深度",
                                          "--limit": "最多条数"}},
    "fs cat": {"desc": "读文件到 stdout 或 -o 指定文件", "args": {"path": "文件路径",
                                                              "-o": "输出文件"}},
    "fs find": {"desc": "按名字子串搜索", "args": {"pattern": "子串", "--limit": "上限"}},
    "hash": {"desc": "文件或镜像哈希", "args": {"target": "文件路径", "--algos": "md5,sha1,sha256,sm3",
                                             "--verify-ewf": "核对 EWF 采集哈希"}},
    "search": {"desc": "多编码全局搜索", "args": {"pattern": "关键词", "--encodings": "ascii,utf8,utf16le,utf16be,gbk",
                                             "--regex": "按正则解释", "--csv": "导出 CSV"}},
    "carve": {"desc": "签名文件雕刻", "args": {"--kinds": "jpeg,png,sqlite...", "--out": "输出目录",
                                          "--max-per-kind": "每种上限"}},
    "luks": {"desc": "扫描 LUKS 卷头", "args": {}},
    "session": {"desc": "从 stdin 读 JSONL 命令", "args": {"--events": "同时输出事件"}},
}


def cmd_schema(args, dev, kind):
    if args.name:
        key = args.name.replace("  ", " ")
        hit = SCHEMA.get(key)
        if hit is None:
            for k in SCHEMA:
                if k.replace(" ", "") == key.replace(" ", ""):
                    hit = SCHEMA[k]
                    key = k
                    break
        if hit is None:
            return {"error": "未知命令: %s" % args.name, "available": list(SCHEMA)}
        return {"command": key, **hit}
    return {"commands": SCHEMA}


# ------------------------------------------------------------
# session（JSONL）
# ------------------------------------------------------------
def cmd_session(args, dev, kind):
    """从 stdin 逐行读 JSON 命令并执行，输出 JSONL

    每行格式：{"cmd": "fs", "action": "ls", "path": "/", "image": "...", "offset": null}
    """
    count = 0
    done = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        count += 1
        try:
            req = json.loads(line)
        except Exception as e:
            print(json.dumps({"ok": False, "error": "JSON 解析失败: %s" % e},
                             ensure_ascii=False))
            continue
        try:
            res = _dispatch_from_dict(req)
            done += 1
            print(json.dumps({"ok": True, "request": req, "result": res},
                             ensure_ascii=False, default=str))
        except Exception as e:
            print(json.dumps({"ok": False, "request": req,
                              "error": str(e),
                              "trace": traceback.format_exc().splitlines()[-3:]},
                             ensure_ascii=False))
            continue
    return {"lines": count, "ok": done, "failed": count - done}


def _dispatch_from_dict(req):
    """把一行 JSON 请求翻成一次命令调用"""
    cmd = (req.get("cmd") or "").strip()
    action = (req.get("action") or "").strip()
    image = req.get("image") or req.get("target")

    ns = argparse.Namespace(
        image=image, offset=req.get("offset"), size=req.get("size"),
        fs=req.get("fs"), path=req.get("path", "/"), depth=req.get("depth", 3),
        limit=req.get("limit", 1000), output=req.get("output"),
        json=True, target=image, algos=req.get("algos", "md5,sha256"),
        verify_ewf=req.get("verify_ewf", False),
        pattern=req.get("pattern", ""), encodings=req.get("encodings", "ascii"),
        regex=req.get("regex", False), max_hits=req.get("max_hits", 100),
        csv=req.get("csv"), kinds=req.get("kinds", ""),
        out=req.get("out"), max_per_kind=req.get("max_per_kind", 1000),
        name=req.get("name"),
    )

    dev = kind = None
    if image and cmd not in ("hash",):
        dev, kind = open_image(image)
    elif image and cmd == "hash":
        try:
            dev, kind = open_image(image)
        except Exception:
            dev, kind = None, None

    table = {
        ("images", "open"): cmd_images_open,
        ("fs", "ls"): cmd_fs_ls,
        ("fs", "tree"): cmd_fs_tree,
        ("fs", "cat"): cmd_fs_cat,
        ("fs", "find"): cmd_fs_find,
        ("hash", ""): cmd_hash,
        ("search", ""): cmd_search,
        ("carve", ""): cmd_carve,
        ("luks", ""): cmd_luks,
        ("schema", ""): cmd_schema,
    }
    fn = table.get((cmd, action)) or table.get((cmd, ""))
    if fn is None:
        raise ValueError("未知命令: %s %s" % (cmd, action))
    return fn(ns, dev, kind)


# ------------------------------------------------------------
# argparse
# ------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="esk_cli",
        description="ESK 电子数据取证工具包命令行",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="用 `esk_cli schema` 查看全部命令")
    p.add_argument("--version", action="version", version="esk_cli " + __version__)
    p.add_argument("--image", help="镜像路径")
    p.add_argument("--offset", type=lambda s: int(s, 0), help="分区/文件系统起始偏移")
    p.add_argument("--size", type=lambda s: int(s, 0), help="分区大小")
    p.add_argument("--fs", action="store_true", help="用第一个可挂载分区")
    p.add_argument("--json", action="store_true", help="机器可读输出")

    sp = p.add_subparsers(dest="cmd")

    # images
    si = sp.add_parser("images", help="镜像与分区")
    sia = si.add_subparsers(dest="action")
    sio = sia.add_parser("open", help="识别分区表并猜文件系统")
    sio.add_argument("path", nargs="?", help="镜像路径（也可用 --image）")

    # fs
    sf = sp.add_parser("fs", help="文件系统操作")
    sfa = sf.add_subparsers(dest="action")
    for name, help_text in (("ls", "列目录"), ("tree", "递归遍历"),
                            ("cat", "读文件"), ("find", "按名字搜索")):
        q = sfa.add_parser(name, help=help_text)
        if name == "find":
            q.add_argument("pattern")
            q.add_argument("--limit", type=int, default=2000)
        else:
            q.add_argument("path", nargs="?", default="/")
        if name == "tree":
            q.add_argument("--depth", type=int, default=3)
            q.add_argument("--limit", type=int, default=100000)
        if name == "cat":
            q.add_argument("-o", "--output")

    # hash
    sh = sp.add_parser("hash", help="哈希")
    sh.add_argument("target", nargs="?", help="文件路径（也可用 --image）")
    sh.add_argument("--algos", default="md5,sha1,sha256")
    sh.add_argument("--verify-ewf", action="store_true",
                    dest="verify_ewf", help="核对 EWF 采集哈希")

    # search
    ss = sp.add_parser("search", help="多编码全局搜索")
    ss.add_argument("pattern")
    ss.add_argument("target", nargs="?", help="文件路径（也可用 --image）")
    ss.add_argument("--encodings", default="ascii,utf8,utf16le,gbk")
    ss.add_argument("--regex", action="store_true")
    ss.add_argument("--csv")
    ss.add_argument("--max-hits", type=int, default=200, dest="max_hits")

    # carve
    sc = sp.add_parser("carve", help="签名文件雕刻")
    sc.add_argument("--kinds", default="")
    sc.add_argument("--out", default="carved")
    sc.add_argument("--max-per-kind", type=int, default=1000, dest="max_per_kind")
    sc.add_argument("target", nargs="?", help="文件路径（也可用 --image）")

    # luks
    sp.add_parser("luks", help="扫描 LUKS 卷头")

    # schema
    sq = sp.add_parser("schema", help="查看命令参数结构")
    sq.add_argument("name", nargs="?")

    # session
    se = sp.add_parser("session", help="从 stdin 读 JSONL 命令")
    se.add_argument("--events", action="store_true")

    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    p = build_parser()
    args = p.parse_args(argv)

    if not args.cmd:
        p.print_help()
        return 0

    # 位置参数里的路径也可以当镜像用
    if not args.image:
        cand = getattr(args, "path", None) or getattr(args, "target", None)
        if args.cmd == "images" and cand:
            args.image = cand

    if args.cmd == "session":
        return 0 if not cmd_session(args, None, None) else 0
    if args.cmd == "schema":
        out(cmd_schema(args, None, None), as_json=args.json or True)
        return 0

    dev = kind = None
    if args.cmd in ("images", "fs", "luks"):
        if not args.image:
            return err("需要 --image 或用位置参数给出镜像路径")
        try:
            dev, kind = open_image(args.image)
        except Exception as e:
            return err("打开镜像失败: %s" % e)
    elif args.cmd in ("hash", "search", "carve"):
        # 有 --image 就当设备；否则用位置参数当文件
        if args.image:
            try:
                dev, kind = open_image(args.image)
            except Exception as e:
                return err("打开镜像失败: %s" % e)
        else:
            tgt = getattr(args, "target", None)
            if not tgt:
                return err("需要 --image 或给出文件路径")
            if not os.path.exists(tgt):
                return err("文件不存在: %s" % tgt)
            args.target = tgt

    table = {
        ("images", "open"): cmd_images_open,
        ("fs", "ls"): cmd_fs_ls,
        ("fs", "tree"): cmd_fs_tree,
        ("fs", "cat"): cmd_fs_cat,
        ("fs", "find"): cmd_fs_find,
        ("hash", None): cmd_hash,
        ("search", None): cmd_search,
        ("carve", None): cmd_carve,
        ("luks", None): cmd_luks,
    }
    key = (args.cmd, args.action) if args.cmd in ("images", "fs") else (args.cmd, None)
    fn = table.get(key)
    if fn is None:
        return err("未知命令: %s %s" % (args.cmd, args.action or ""))

    try:
        res = fn(args, dev, kind)
    except NotImplementedError as e:
        return err("该功能未实现: %s" % e, 3)
    except Exception as e:
        if args.json:
            out({"ok": False, "error": str(e),
                 "trace": traceback.format_exc().splitlines()[-4:]})
            return 1
        return err(str(e))

    if res is not None:
        out(res, as_json=args.json or True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
