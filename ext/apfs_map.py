#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""apfs_map.py -- CM-02 APFS 容器：卷超级块 + 对象目录（o_oid -> paddr）。

要点（实测确认）：
  * apfs_omap_phys 无魔数，用 obj_phys.o_type==0x0b 判定
  * btree_node_phys: btn_flags@0x20 u16, btn_level@0x22 u16, btn_nkeys@0x24 u32,
    btn_table_space@0x28 (off,len) —— 键区起点 = 0x38 + off + len，
    TOC 项 = (u16 koff, u16 voff)，键位置 = 键区起点 + koff
  * 每个 APFS 对象 obj_phys.o_oid@0x08 —— 用它在窗口内建 oid->paddr 目录，
    彻底绕开 omap B-tree 的值定位歧义
"""
import struct
import sys

sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
from mkit.image import Image, SubImage  # noqa: E402

PATH = r"D:\meiya\src\CM-02\CM-02\CM-02.E01"
PART_OFF = 0xC805000

u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
u64 = lambda b, o: struct.unpack_from("<Q", b, o)[0]

OBJ_BTREE = 0x02
OBJ_BTREE_NODE = 0x03
OBJ_OMAP = 0x0B
OBJ_FS = 0x0D


class Container(object):
    def __init__(self, path=PATH, off=PART_OFF):
        self.img = Image(path)
        self.sub = SubImage(self.img, off, self.img.size - off)
        nx = self.sub.read(0, 4096)
        if nx[0x20:0x24] != b"NXSB":
            raise RuntimeError("no NXSB")
        self.bs = u32(nx, 0x24)
        self.block_count = u64(nx, 0x28)
        self.nx_uuid = nx[0x48:0x58].hex()
        self.omap_oid = u64(nx, 0xA0)
        self.maxfs = u32(nx, 0xB4)
        self.fs_oids = [v for v in (u64(nx, 0xB8 + 8 * i) for i in range(self.maxfs)) if v]
        self.oidmap = {}       # oid -> paddr
        self.volumes = {}      # oid -> dict
        self.cache = {}

    def blk(self, paddr):
        d = self.cache.get(paddr)
        if d is None:
            d = self.sub.read(paddr * self.bs, self.bs)
            self.cache[paddr] = d
        return d

    # ---------- 窗口扫描 ----------
    def scan(self, start_blk, end_blk, chunk_blocks=2048, verbose=True):
        bs = self.bs
        for b0 in range(start_blk, end_blk, chunk_blocks):
            b1 = min(end_blk, b0 + chunk_blocks)
            buf = self.sub.read(b0 * bs, (b1 - b0) * bs)
            if not buf:
                break
            for i in range(b1 - b0):
                d = buf[i * bs:(i + 1) * bs]
                if len(d) < 0x60:
                    break
                oid = u64(d, 0x08)
                otype = u32(d, 0x18)
                if not oid or not otype:
                    continue
                paddr = b0 + i
                base = otype & 0xFFFF
                if d[0x20:0x24] == b"APSB":
                    xid = u64(d, 0x10)
                    prev = self.volumes.get(oid)
                    if prev is None or xid >= prev["xid"]:
                        self.volumes[oid] = dict(
                            paddr=paddr, xid=xid, index=u32(d, 0x2C),
                            root_tree=u64(d, 0x88), extentref=u64(d, 0x90),
                            omap_oid=u64(d, 0xC0),
                            name=d[0x2D0:0x2D0 + 256].split(b"\x00")[0].decode("utf-8", "replace"),
                            uuid=d[0xF0:0x100].hex(),
                            role=u16(d, 0x60) if len(d) > 0x62 else 0)
                # 记录 oid -> paddr（APFS 同 oid 多副本时保留 oid==paddr 或最后一次）
                self.oidmap[oid] = paddr
            if verbose:
                sys.stderr.write("  scan %d..%d  objs=%d vols=%d\r" % (b0, b1, len(self.oidmap), len(self.volumes)))

    def close(self):
        self.img.close()


def main():
    lo, hi = 800000, 1400000
    if len(sys.argv) > 2:
        lo, hi = int(sys.argv[1]), int(sys.argv[2])
    c = Container()
    print("bs=%d blocks=%d fs_oids=%s" % (c.bs, c.block_count, c.fs_oids))
    c.scan(lo, hi)
    print("\n扫描完成: 对象 %d 个, 卷 %d 个" % (len(c.oidmap), len(c.volumes)))
    for oid, v in sorted(c.volumes.items(), key=lambda kv: kv[1]["index"]):
        rt = v["root_tree"]
        print("oid=%-8d paddr=%-8d idx=%-2d xid=%-7d %-22r root=%-8d omap=%-8d -> %s" % (
            oid, v["paddr"], v["index"], v["xid"], v["name"], rt, v["omap_oid"],
            c.oidmap.get(rt, "MISSING")))
    miss = [v["root_tree"] for v in c.volumes.values() if v["root_tree"] not in c.oidmap]
    print("missing roots:", miss)
    c.close()


if __name__ == "__main__":
    main()
