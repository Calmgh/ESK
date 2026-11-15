#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_cm02s5.py -- 用全叶子索引解析路径，导出完整文件树 + 关键文件读取

用法:
  python ans_cm02s5.py tree  [子串]        # 打印匹配子串的路径
  python ans_cm02s5.py cat <path>         # 打印文件内容（文本）
  python ans_cm02s5.py xattr <path>       # 打印 xattr
"""
import io
import pickle
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
import ans_cm02s_base as B  # noqa: E402

TREE = r"E:\ALL\AAAI\Works\RE\meiya\out\cm02s_tree.pkl"
_d = None


def load():
    global _d
    if _d is None:
        with open(TREE, "rb") as f:
            _d = pickle.load(f)
    return _d


def paths():
    """{inode_id: full path}，用 inode.parent 递归上溯"""
    d = load()
    dirs, inodes = d["dirs"], d["inodes"]
    # dirs: key=父目录id（DREC key 的 obj_id 字段）
    child2name = {}
    for pid, ents in dirs.items():
        for name, cid, dtype, added in ents:
            child2name.setdefault(cid, []).append((name, pid, dtype))
    # 只保留 parent 与 DREC 记录一致的边
    out = {}
    root = 2
    out[root] = "/"
    stack = [root]
    while stack:
        cur = stack.pop()
        cp = out[cur]
        for name, cid, dtype, added in dirs.get(cur, []):
            p = (cp.rstrip("/") + "/" + name)
            if cid in out:
                continue
            out[cid] = p
            if dtype == 4:
                stack.append(cid)
    return out


def find_path(p):
    want = p.rstrip("/")
    for ino, path in paths().items():
        if path == want:
            return ino
    return None


def read_file(ino, cap=64 << 20, clamp=True):
    d = load()
    inodes, ext = d["inodes"], d["ext"]
    i = inodes.get(ino, {})
    pid = i.get("private_id", ino)
    ex = ext.get(pid) or ext.get(ino) or []
    if not ex:
        return b""
    buf = bytearray()
    last = 0
    v = B.fs()
    for laddr, ln, paddr in ex:
        if laddr > last:
            buf.extend(b"\x00" * (laddr - last))
        if len(buf) >= cap:
            break
        n = min(ln, cap - len(buf))
        buf.extend(v.c.sub.read(v.c.bs * paddr, n))
        last = laddr + ln
    sz = i.get("size") or 0
    if clamp and sz and len(buf) > sz:
        buf = buf[:sz]
    return bytes(buf)


def xattrs_of(ino):
    d = load()
    out = {}
    for (oid, nm), (fl, data) in d["xattr"].items():
        if oid == ino:
            out[nm] = (fl, data)
    return out


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "tree"
    if cmd == "tree":
        sub = sys.argv[2] if len(sys.argv) > 2 else ""
        m = paths()
        for ino, p in sorted(m.items(), key=lambda kv: kv[1]):
            if sub.lower() in p.lower():
                print("%-9d %s" % (ino, p))
    elif cmd == "cat":
        ino = find_path(sys.argv[2])
        if ino is None:
            print("NOT FOUND", sys.argv[2])
        else:
            b = read_file(ino)
            print("-- %s id=%d size=%d" % (sys.argv[2], ino, len(b)))
            sys.stdout.buffer.write(b[:200000])
    elif cmd == "stat":
        ino = find_path(sys.argv[2])
        d = load()
        print(sys.argv[2], "id=", ino, d["inodes"].get(ino))
    elif cmd == "xattr":
        ino = find_path(sys.argv[2])
        print("-- xattr", sys.argv[2], "id=", ino)
        for k, (fl, data) in sorted(xattrs_of(ino).items()):
            print("  %-45s fl=%#x len=%d %r" % (k, fl, len(data), data[:160]))
