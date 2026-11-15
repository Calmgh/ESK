#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""自检：确认环境与所有模块可用

用法：
    python 00_selftest.py
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "ext"))

REQUIRED = [
    ("mkit.image", "EWF/原始镜像加载"),
    ("mkit.ntfs", "NTFS"),
    ("mkit.ext4", "ext4"),
    ("mkit.regf", "注册表"),
    ("mkit.volume", "分区表"),
    ("mkit.chain", "证据链"),
    ("mkit.aes", "AES"),
]

OPTIONAL = [
    ("mkit.stego", "隐写（需 Pillow + pyzbar）"),
    ("mkit.wallet", "钱包（需 pycryptodome）"),
    ("mkit.winart", "Windows 痕迹（需 dissect.eventlog）"),
    ("mkit.revkit", "逆向（需 capstone）"),
    ("mkit.mobile", "移动端综合"),
    ("mkit.mail", "邮件"),
    ("mkit.heif", "HEIC 解码"),
    ("mkit.linuxart", "Linux 痕迹"),
    ("mkit.iosart", "iOS 痕迹"),
    ("mkit.macart", "macOS 痕迹"),
    ("mkit.appdata", "应用数据"),
    ("mkit.netart", "网络痕迹"),
    ("mkit.sysconf", "系统配置"),
    ("mkit.winacct", "Windows 账户"),
    ("mkit.online", "在线服务"),
    ("apfs_fs", "APFS 文件系统树（自建）"),
    ("apfs_map", "APFS omap（自建）"),
    ("ans_c02vm2", "VMDK 设备层（自建）"),
    ("webvm3_dev", "单文件 VMDK（自建）"),
    ("ans_c02h_lvm", "LVM2（自建）"),
    ("com03_lib", "NAS/RAID 工具（自建）"),
    ("ans_lib", "通用库（自建）"),
]

# 这些是「导入即执行」的脚本，不能 import，只检查文件存在
SCRIPT_ONLY = [
    "q13_judge", "ans_78b_png", "ans_78b_zlib", "ans_78b_probe",
    "ans_78b_recover", "ans_78b_strip", "ans_78b_strings",
]


def check(mod):
    try:
        __import__(mod)
        return True, ""
    except Exception as e:
        return False, str(e)[:70]


def main():
    print("=" * 74)
    print("ESK 自检")
    print("Python %s" % sys.version.split()[0])
    print("=" * 74)

    fail = 0

    print("\n【必需】")
    for m, desc in REQUIRED:
        good, err = check(m)
        print("  %s %-18s %s%s" % ("OK  " if good else "FAIL", m, desc,
                                   "" if good else "  <- " + err))
        if not good:
            fail += 1

    print("\n【可选】")
    for m, desc in OPTIONAL:
        good, err = check(m)
        print("  %s %-18s %s%s" % ("OK  " if good else "  - ", m, desc,
                                   "" if good else "  (缺依赖: " + err + ")"))

    print("\n【脚本类扩展】（导入即执行，仅检查存在）")
    ext_dir = os.path.join(ROOT, "ext")
    for nm in SCRIPT_ONLY:
        fp = os.path.join(ext_dir, nm + ".py")
        good = os.path.exists(fp)
        print("  %s %-18s" % ("OK  " if good else "  - ", nm))

    print()
    print("=" * 74)
    if fail:
        print("必需模块缺失 %d 项，请执行：pip install -r requirements.txt" % fail)
        return 1
    print("环境就绪。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
