# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""mkit 包：自研电子数据取证解析工具集。"""
__all__ = ["ewf", "image", "volume"]

__author__ = "Calmgh06"
__version__ = "1.0.0"
__watermark__ = "dev by Calmgh06"


def banner():
    """打印工具包标识"""
    print("mkit_toolkit 1.0.0  ·  dev by Calmgh06")
    return __watermark__
