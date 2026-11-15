# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""mkit 包：自研电子数据取证解析工具集。"""
__all__ = ["ewf", "image", "volume"]

__author__ = "Calmgh06"
__version__ = "1.0.0"
__watermark__ = "ESK by Calmgh06"


def banner():
    """打印工具包标识"""
    print("ESK 1.0.0  ·  Electronic Software Kit  ·  Calmgh06")
    return __watermark__
