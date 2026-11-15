#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""apfs_fs.py -- CM-02 APFS 文件系统层：按路径 listdir / read_file / xattr。

已实测确认的 B-tree 约定
  btn_flags@0x20 u16, btn_level@0x22 u16, btn_nkeys@0x24 u32,
  btn_table_space@0x28 (u16 off, u16 len)
  键区起点 keybase = 0x38 + off + len
  TOC @0x38：
     fixed-KV (flag&4): 4 字节 (u16 koff, u16 voff)
     非 fixed        : 8 字节 kvloc (u16 koff, u16 klen, u16 voff, u16 vlen)
     键 = blk[keybase+koff : +klen]
     值 = blk[valend-voff : +vlen]，valend = bs-40（root，块尾有 btree_info）否则 bs
"""
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
from apfs_map import Container, u16, u32, u64  # noqa: E402

BS_ = 4096
ROOT_DIR = 2
T_INODE = 3
T_XATTR = 4
T_FILE_EXTENT = 8
T_DREC = 9

FLAG_FIXED = 0x0004
FLAG_LEAF = 0x0002
FLAG_ROOT = 0x0001


class FSNode(object):
    __slots__ = ("paddr", "blk", "flags", "level", "nkeys", "recs")

    def __repr__(self):
        return "<FSNode %d lvl=%d n=%d>" % (self.paddr, self.level, self.nkeys)


def jkey(raw):
    """返回 (obj_id, type)"""
    v = struct.unpack_from("<Q", raw, 0)[0]
    return (v & 0x0FFFFFFFFFFFFFFF, v >> 60)


class VolFS(object):
    """一个 APFS 卷的文件系统视图"""

    def __init__(self, c, oid):
        self.c = c
        self.bs = c.bs
        self.oid = oid
        self.sb = c.volumes[oid]
        self.root_oid = self.sb["root_tree"]
        self.root_paddr = c.oidmap.get(self.root_oid)
        if self.root_paddr is None:
            raise RuntimeError("root tree oid %d not in oidmap" % self.root_oid)
        self._nodes = {}

    # ---------- 节点 ----------
    def node(self, paddr):
        n = self._nodes.get(paddr)
        if n is not None:
            return n
        blk = self.c.blk(paddr)
        bs = self.bs
        flags = u16(blk, 0x20)
        level = u16(blk, 0x22)
        nkeys = u32(blk, 0x24)
        tsoff = u16(blk, 0x28)
        tslen = u16(blk, 0x2A)
        if nkeys > 8000 or level > 10 or tslen < nkeys * 4 or tslen > bs // 2:
            raise RuntimeError("bad node %d: flags=%#x lvl=%d n=%d tslen=%d" %
                               (paddr, flags, level, nkeys, tslen))
        keybase = 0x38 + tsoff + tslen
        valend = bs - 40 if (flags & FLAG_ROOT) else bs
        n = FSNode()
        n.paddr = paddr
        n.blk = blk
        n.flags = flags
        n.level = level
        n.nkeys = nkeys
        fixed = bool(flags & FLAG_FIXED)
        recs = []
        step = 4 if fixed else 8
        for i in range(nkeys):
            p = 0x38 + tsoff + i * step
            if fixed:
                koff, voff = struct.unpack_from("<HH", blk, p)
                klen = None
                vlen = None
            else:
                koff, klen, voff, vlen = struct.unpack_from("<HHHH", blk, p)
            kp = keybase + koff
            vp = valend - voff
            if fixed:
                recs.append((kp, vp, None, None))
            else:
                recs.append((kp, vp, klen, vlen))
        n.recs = recs
        self._nodes[paddr] = n
        return n

    def key_bytes(self, n, i):
        kp, vp, klen, vlen = n.recs[i]
        if klen is None:      # fixed-KV：键长由类型推出
            kv = u64(n.blk, kp)
            t = kv >> 60
            klen = 8
            if t == T_DREC:
                nlh = u32(n.blk, kp + 8)
                klen = 12 + (nlh & 0x3FF) + 1
            elif t == T_FILE_EXTENT:
                klen = 16
        return n.blk[kp:kp + klen]

    def val_bytes(self, n, i):
        kp, vp, klen, vlen = n.recs[i]
        if vlen is None:
            vlen = self.bs - vp if vp < self.bs else 0
            # fixed-KV 值为定长：用 btree_info 的 bt_val_size
            vlen = self.val_size(n)
        return n.blk[vp:vp + vlen]

    def val_size(self, n):
        # root 节点可从尾部 btree_info 拿 bt_val_size
        if n.flags & FLAG_ROOT:
            return u32(n.blk, self.bs - 40 + 12)
        return 0

    # ---------- 查找 ----------
    def _child(self, n, i):
        v = self.val_bytes(n, i)
        child = u64(v, 0)
        return self.c.oidmap.get(child, child)

    def scan_obj(self, obj_ids):
        """全树叶遍历（DFS），收集 obj_id 属于 obj_ids 的 (key,val,obj_id)。

        B-tree 节点无兄弟指针，直接按子指针深度优先走完所有叶子。
        """
        want = set(obj_ids)
        out = []
        stack = [self.root_paddr]
        leaves = 0
        while stack:
            paddr = stack.pop()
            n = self.node(paddr)
            if n.level > 0:
                kids = [self._child(n, i) for i in range(n.nkeys)]
                for k in reversed(kids):
                    stack.append(k)
                continue
            leaves += 1
            for i in range(n.nkeys):
                oid, _t = jkey(self.key_bytes(n, i))
                if oid in want:
                    out.append((self.key_bytes(n, i), self.val_bytes(n, i), oid))
        self._leaves = leaves
        return out

    def find(self, obj_id, want_type=None):
        """返回叶子节点里 obj_id（可选 type）的所有 (key,val)"""
        out = []
        paddr = self.root_paddr
        depth = 0
        path = []
        while depth < 12:
            n = self.node(paddr)
            if n.nkeys == 0:
                return out
            if n.level == 0:
                for i in range(n.nkeys):
                    oid, t = jkey(self.key_bytes(n, i))
                    if want_type is not None:
                        if oid == obj_id and t == want_type:
                            out.append((self.key_bytes(n, i), self.val_bytes(n, i)))
                    elif oid == obj_id:
                        out.append((self.key_bytes(n, i), self.val_bytes(n, i)))
                return out
            sel = 0
            for i in range(n.nkeys):
                oid, t = jkey(self.key_bytes(n, i))
                if oid <= obj_id:
                    sel = i
                else:
                    break
            v = self.val_bytes(n, sel)
            child = u64(v, 0)
            paddr = self.c.oidmap.get(child, child)
            depth += 1
        return out

    # ---------- 目录 ----------
    def listdir(self, dir_id):
        ents = []
        for k, v in self.find(dir_id, T_DREC):
            nlh = u32(k, 8)
            nlen = nlh & 0x3FF
            name = k[12:12 + nlen].split(b"\x00")[0].decode("utf-8", "replace")
            file_id, added, flags = struct.unpack_from("<QQH", v, 0)
            ents.append(dict(name=name, id=file_id, added=added,
                             dtype=flags & 0xF, raw_flags=flags))
        return ents

    def inode(self, ino):
        r = self.find(ino, T_INODE)
        if not r:
            return None
        v = r[0][1]
        d = dict(
            parent=u64(v, 0), private_id=u64(v, 8),
            create=u64(v, 0x10), mod=u64(v, 0x18), change=u64(v, 0x20),
            access=u64(v, 0x28), internal_flags=u64(v, 0x30),
            nchildren=u32(v, 0x38), bsd_flags=u32(v, 0x44),
            owner=u32(v, 0x48), group=u32(v, 0x4C), mode=u16(v, 0x50),
            size=u64(v, 0x54))
        return d

    def lookup(self, dir_id, name):
        for k, v in self.find(dir_id, T_DREC):
            nlh = u32(k, 8)
            nlen = nlh & 0x3FF
            nm = k[12:12 + nlen].split(b"\x00")[0].decode("utf-8", "replace")
            if nm == name:
                return u64(v, 0)
        return None

    def path(self, p):
        cur = ROOT_DIR
        parts = [x for x in p.replace("\\", "/").split("/") if x and x != "."]
        for seg in parts:
            nxt = self.lookup(cur, seg)
            if nxt is None:
                raise KeyError("not found: %s (in %s)" % (seg, p))
            cur = nxt
        return cur

    # ---------- xattr ----------
    def xattrs(self, ino):
        out = {}
        for k, v in self.find(ino, T_XATTR):
            nl = u16(k, 8)
            name = k[10:10 + nl].decode("utf-8", "replace")
            flags = u16(v, 0)
            xlen = u16(v, 2)
            data = v[4:4 + xlen]
            out[name] = dict(flags=flags, size=xlen, data=data)
        return out

    # ---------- 文件数据 ----------
    def extents(self, private_id):
        r = self.find(private_id, T_FILE_EXTENT)
        out = []
        for k, v in r:
            laddr = u64(k, 8)
            lnk = u64(v, 0)
            paddr = u64(v, 8)
            ln = lnk & 0x00FFFFFFFFFFFFFF
            out.append((laddr, ln, paddr))
        out.sort()
        return out

    def read_file(self, ino, limit=None):
        i = self.inode(ino)
        pid = i["private_id"] if i else ino
        buf = b""
        for laddr, ln, paddr in self.extents(pid):
            if limit and len(buf) >= limit:
                break
            n = ln
            if limit:
                n = min(n, limit - len(buf))
            buf += self.c.sub.read(self.c.bs * paddr, n)
        return buf
