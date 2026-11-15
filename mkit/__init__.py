# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""mkit 包：自研电子数据取证解析工具集。"""

__all__ = [
    # 镜像与容器
    "image", "ewf", "ewf_external", "volume", "vdisk",
    # 文件系统
    "ntfs", "ext4", "fat", "exfat", "iso", "macart",
    # 加密与凭据
    "aes", "luks", "wallet", "iosbackup_crypto",
    # 分析工具
    "hashcalc", "search", "carve", "stego", "chain", "zipview",
    # 平台痕迹
    "winart", "winacct", "appdata", "sysconf", "netart",
    "linuxart", "iosart", "mobile", "mail", "heif", "online",
    # 其他
    "regf", "revkit", "revkit_help",
]

__author__ = "Calmgh06"
__version__ = "1.2.0"
__watermark__ = "ESK by Calmgh06"


def banner():
    """打印工具包标识"""
    print("ESK %s  ·  Electronic Software Kit  ·  Calmgh06" % __version__)
    return __watermark__
