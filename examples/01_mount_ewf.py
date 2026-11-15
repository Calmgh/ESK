#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""示例 1：装载 EWF / 原始镜像，列出分区

用法：
    python 01_mount_ewf.py <镜像路径>

说明：
    · EWF（.E01/.e01）需要 libewf-python
    · 原始镜像（.dd/.raw/.img）直接读
    · 自动识别 MBR / GPT
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))          # 让 mkit 可导入

from mkit.image import Image, SubImage                # noqa: E402
import mkit.volume as volume                          # noqa: E402

GUID = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "MS Reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Basic data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows RE",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "APFS",
    "48465300-0000-11AA-AA11-00306543ECAC": "HFS+",
}


def describe(img, label=""):
    print("=" * 74)
    print("%s  大小 %.2f GiB" % (label or "镜像", img.size / 2 ** 30))
    head = img.read(0, 512)
    print("  MBR 签名: %s" % ("55AA ✓" if head[510:512] == b"\x55\xaa" else "无"))

    parts = None
    # GPT：注意 volume.parse() 有 bug（它检查 head[450:454]，而 GPT 签名在 512）
    try:
        parts = volume._gpt(img, None)
    except Exception:
        parts = None

    if not parts:
        try:
            parts = volume.parse(img)
        except Exception:
            parts = None

    if not parts:
        print("  未识别到分区表（可能是裸文件系统，直接按卷挂载）")
        return

    print("  分区 %d 个：" % len(parts))
    for i, p in enumerate(parts):
        t = str(p.get("type", "")).upper()
        name = GUID.get(t, p.get("type_desc") or t[:36])
        print("    [%d] 起始 %-14s 大小 %-12s 类型 %s" % (
            i, hex(p.get("offset", 0)),
            "%.3f GiB" % (p.get("size", 0) / 2 ** 30) if p.get("size", 0) > 2 ** 30
            else "%.1f MB" % (p.get("size", 0) / 2 ** 20),
            name))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    if not os.path.exists(path):
        print("文件不存在:", path)
        return 1
    img = Image(path)
    describe(img, os.path.basename(path))
    img.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
