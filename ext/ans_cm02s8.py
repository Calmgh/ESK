#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""ans_cm02s8.py -- 智能读取（extent 不全→按连续块读 + 按文件格式边界截断）+ 批量取证"""
import io
import os
import plistlib
import re
import sqlite3
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, r"E:\ALL\AAAI\Works\RE\meiya")
import ans_cm02s5 as T  # noqa: E402
import ans_cm02s_base as B  # noqa: E402

D = T.load()
V = B.fs()
OUTD = r"E:\ALL\AAAI\Works\RE\meiya\out\cm02s_pull"
os.makedirs(OUTD, exist_ok=True)


def raw_read(ino, cap=32 << 20):
    """从第一个 extent 起连续读（本镜像小文件物理连续），最多 cap"""
    inodes = D["inodes"]
    ext = D["ext"]
    i = inodes.get(ino, {})
    pix = i.get("private_id", ino)
    ex = ext.get(pix) or ext.get(ino) or []
    if not ex:
        return b""
    paddr = ex[0][2]
    nb = (cap + V.c.bs - 1) // V.c.bs
    return V.c.sub.read(V.c.bs * paddr, nb * V.c.bs)


def cut_xml(b):
    i = b.find(b"</plist>")
    if i < 0:
        return None
    return b[:i + 8]


def trim_bplist(b):
    """bplist00：用 trailer 反推长度"""
    if not b.startswith(b"bplist00"):
        return None
    for end in range(min(len(b), 4 << 20), 40, -1):
        t = b[end - 32:end]
        off_size, ref_size = t[6], t[7]
        if off_size not in (1, 2, 3, 4, 8) or ref_size not in (1, 2, 3, 4, 8):
            continue
        num, top, tab = struct.unpack(">QQQ", t[8:32])
        if not (0 < num < 200000 and top < num and 8 < tab < end - 32):
            continue
        try:
            return plistlib.loads(b[:end])
        except Exception:
            continue
    return None


def pload(path, cap=32 << 20, save=True):
    ino = T.find_path(path)
    if ino is None:
        print("  !! 无此路径 %s" % path)
        return None
    b = raw_read(ino, cap)
    obj = None
    if b.startswith(b"bplist00"):
        obj = trim_bplist(b)
    elif b[:1] in (b"<", b"\n"):
        x = cut_xml(b)
        if x:
            try:
                obj = plistlib.loads(x)
            except Exception as e:
                print("  !! xml parse %s: %r" % (path, e))
            if save:
                with open(os.path.join(OUTD, path.strip("/").replace("/", "_")), "wb") as f:
                    f.write(x)
    return obj


def pprint(o, n=12000):
    s = io.StringIO()
    import pprint as pp
    pp.pprint(o, stream=s, width=170)
    print(s.getvalue()[:n])


def main():
    print("########## Q1 计算机名 / Q3 MAC / 主机名")
    pref = pload("/Library/Preferences/SystemConfiguration/preferences.plist")
    if pref:
        print("  System.System =", (pref.get("System") or {}).get("System"))
        print("  Network.HostNames =", (pref.get("Network") or {}).get("HostNames"))
        for sid, svc in ((pref.get("Network") or {}).get("Service") or {}).items():
            f = svc.get("Interface") or {}
            print("   %s name=%r dev=%r mac=%r" % (sid, svc.get("UserDefinedName"),
                                                   f.get("DeviceName"), f.get("Hardware Address")))

    print("\n########## 系统偏好里的主机名相关")
    for p in ("/Library/Preferences/com.apple.smb.server.plist",
              "/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist",
              "/Library/Preferences/com.apple.RemoteManagement.plist",
              "/Library/Preferences/com.apple.sharingd.plist"):
        o = pload(p)
        if o:
            print(" --", p)
            pprint(o, 2000)

    print("\n########## Q4 Wi-Fi")
    kn = pload("/Library/Preferences/com.apple.wifi.known-networks.plist")
    if kn:
        pprint(kn, 6000)

    print("\n########## Q2 版本：搜索带 SystemVersion 的路径")
    for ino, p in sorted(T.paths().items(), key=lambda kv: kv[1]):
        if "SystemVersion" in p or p.endswith("/System/Library/CoreServices"):
            print("   ", p)


if __name__ == "__main__":
    main()
