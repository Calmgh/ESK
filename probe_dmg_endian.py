"""probe_dmg_endian.py —— 用真实 DMG 判定 koly / mish 的端序

判据（自行可验，不靠断言）：
  · koly.version       正常应为 4
  · koly.headerSize    正常应为 512
  · koly.sectorCount   应等于或略大于 dataForkLength/512
  · dataForkOffset + dataForkLength 必须 <= 文件大小
  · mish.numberOfBlockChunks 应是个合理的小数字（几十到几百）
  · 每条 chunk 的 sectorCount 累加应约等于 mish.sectorCount
"""
import io
import os
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

SAMPLES = [
    r"E:\ALL\AAAI\Works\RE\meiya\_corpus\apfs\hfsplus_zlib.dmg",
    r"E:\ALL\AAAI\Works\RE\meiya\_corpus\apfs\apfs_encrypted.dmg",
    r"D:\ALL\Normal\Download\CC-Switch-v3.18.0-macOS.dmg",
]

KOLY_LEN = 512


def read_at(f, off, n):
    f.seek(off)
    return f.read(n)


def probe(path):
    fsize = os.path.getsize(path)
    with open(path, "rb") as f:
        k = read_at(f, fsize - KOLY_LEN, KOLY_LEN)

        print("=" * 76)
        print(os.path.basename(path), " %.2f MB" % (fsize / 2 ** 20))
        print("  末尾 512 字节前 4 字节: %r" % k[0:4])
        if k[0:4] != b"koly":
            print("  不是 koly 结尾，跳过")
            return

        for name, e in (("大端 BE", ">"), ("小端 LE", "<")):
            ver = struct.unpack_from(e + "I", k, 0x004)[0]
            hsz = struct.unpack_from(e + "I", k, 0x008)[0]
            dfo = struct.unpack_from(e + "Q", k, 0x018)[0]
            dfl = struct.unpack_from(e + "Q", k, 0x020)[0]
            segn = struct.unpack_from(e + "I", k, 0x038)[0]
            segc = struct.unpack_from(e + "I", k, 0x03C)[0]
            xo = struct.unpack_from(e + "Q", k, 0x0D8)[0]
            xl = struct.unpack_from(e + "Q", k, 0x0E0)[0]
            sc = struct.unpack_from(e + "Q", k, 0x1EC)[0]

            ok_ver = (ver == 4)
            ok_hsz = (hsz == KOLY_LEN)
            ok_fork = (dfo + dfl <= fsize) and dfl > 0
            ok_xml = (xo + xl <= fsize) and xl > 0
            score = sum([ok_ver, ok_hsz, ok_fork, ok_xml])

            print("  [%s] version=%-12d headerSize=%-12d %s"
                  % (name, ver, hsz,
                     "version✓" if ok_ver else "version✗"))
            print("        dataFork: off=%-12d len=%-12d %s"
                  % (dfo, dfl, "✓" if ok_fork else "✗"))
            print("        xml:      off=%-12d len=%-12d %s"
                  % (xo, xl, "✓" if ok_xml else "✗"))
            print("        sectorCount=%-12d seg=%d/%d   [得分 %d/4]"
                  % (sc, segn, segc, score))

            if score == 4:
                # 用这个端序验证 mish
                verify_mish(f, fsize, xo, xl, e, name)

        print()


def verify_mish(f, fsize, xml_off, xml_len, e, label):
    """从 plist 里取 blkx 的 Data，解 base64 看 mish"""
    import base64
    import plistlib
    raw = read_at(f, xml_off, min(xml_len, 8 << 20))
    try:
        pl = plistlib.loads(raw)
    except Exception as ex:
        print("        plist 解析失败: %s" % ex)
        return
    rf = (pl or {}).get("resource-fork") or {}
    blkx = rf.get("blkx") or []
    if isinstance(blkx, dict):
        blkx = [blkx]
    print("        plist blkx 项数 = %d" % len(blkx))
    if not blkx:
        return

    for idx, item in enumerate(blkx[:3]):
        data = item.get("Data")
        name = item.get("Name") or item.get("CFName") or "?"
        if isinstance(data, str):
            try:
                data = base64.b64decode(data)
            except Exception:
                continue
        if not isinstance(data, (bytes, bytearray)):
            continue

        # 统计这张 Data 里出现几次 mish
        nmish = data.count(b"mish")
        print("        [%d] %-34r Data=%d B  内含 'mish' × %d" % (idx, str(name)[:34], len(data), nmish))

        pos = 0
        shown = 0
        while shown < 2:
            p = data.find(b"mish", pos)
            if p < 0:
                break
            if p + 0xD0 > len(data):
                break
            ver = struct.unpack_from(e + "I", data, p + 0x004)[0]
            fsn = struct.unpack_from(e + "Q", data, p + 0x008)[0]
            scn = struct.unpack_from(e + "Q", data, p + 0x010)[0]
            nck = struct.unpack_from(e + "I", data, p + 0xC8)[0]
            print("            @0x%X version=%d firstSector=%-8d sectorCount=%-8d chunks=%d"
                  % (p, ver, fsn, scn, nck))
            # 抽第一条 chunk 校验
            if nck and p + 0xCC + 40 <= len(data):
                et = struct.unpack_from(e + "I", data, p + 0xCC)[0]
                sn = struct.unpack_from(e + "Q", data, p + 0xCC + 0x08)[0]
                sc = struct.unpack_from(e + "Q", data, p + 0xCC + 0x10)[0]
                print("            chunk[0] type=0x%08X sector=%d count=%d" % (et, sn, sc))
            shown += 1
            pos = p + 4


for s in SAMPLES:
    if os.path.exists(s):
        try:
            probe(s)
        except Exception as ex:
            print("  探测失败 %s: %s" % (s, ex))
    else:
        print("  缺样本:", s)
