# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""mkit 包：自研电子数据取证解析工具集。"""

__version__ = "1.5.0"
__author__ = "Calmgh06"
__watermark__ = "ESK by Calmgh06"

__all__ = [
    "image", "ewf", "ewf_external", "volume",
    "parttable", "vdisk", "dmg", "ad1",
    "aes", "bitlocker", "luks", "wallet",
    "iosbackup_crypto", "ntfs", "ext4", "fat",
    "exfat", "xfs", "hfs", "squashfs",
    "cramfs", "romfs", "iso", "btrfs",
    "udf", "macart", "hashcalc", "search",
    "carve", "sqlite_forensic", "timeline", "stego",
    "chain", "zipview", "winart", "winacct",
    "appdata", "sysconf", "netart", "linuxart",
    "iosart", "mobile", "mail", "heif",
    "online", "regf", "revkit", "revkit_help",
]

# 模块用途速查
MODULE_DOC = {
    "image": "EWF/裸镜像加载 + SubImage 分区切片",
    "ewf": "EWF 解析",
    "ewf_external": "外部 libewf 调用",
    "volume": "MBR / GPT 分区表",
    "parttable": "APM / BSD label / Amiga RDB",
    "vdisk": "QCOW2 v2/v3 与 VirtualBox VDI",
    "dmg": "Apple DMG（UDIF）",
    "ad1": "AccessData AD1 逻辑镜像",
    "aes": "AES",
    "bitlocker": "BitLocker 恢复密码解锁与卷解密",
    "luks": "LUKS1/LUKS2 头解析（不解锁）",
    "wallet": "钱包 / 助记词",
    "iosbackup_crypto": "iOS 备份解密",
    "ntfs": "NTFS",
    "ext4": "ext2/3/4",
    "fat": "FAT12/16/32",
    "exfat": "exFAT",
    "xfs": "XFS v4/v5（extent 格式；b-tree 格式 inode 未支持）",
    "hfs": "HFS / HFS+ / HFSX",
    "squashfs": "SquashFS v4（gzip / xz）",
    "cramfs": "CramFS v2",
    "romfs": "Linux ROMFS",
    "iso": "ISO 9660（含 Joliet / Rock Ridge）",
    "btrfs": "Btrfs（超级块/chunk 树/目录遍历/读文件/zlib）",
    "udf": "UDF 1.02-2.01（VRS/AVDP/PVD/FSD/FE/FID，long_ad 与 embedded）",
    "macart": "macOS 痕迹（APFS 见 ext/apfs_fs.py）",
    "hashcalc": "MD5 / SHA-1 / SHA-256 / SM3 与 EWF 采集哈希核对",
    "search": "多编码全局搜索",
    "carve": "签名文件雕刻",
    "sqlite_forensic": "SQLite WAL 回放 / 删除记录 / 已删表检测",
    "timeline": "跨平台时间线聚合与导出",
    "stego": "隐写检测",
    "chain": "证据链完整性",
    "zipview": "压缩包只读浏览",
    "winart": "Windows 痕迹",
    "winacct": "Windows 账户",
    "appdata": "Windows 应用数据",
    "sysconf": "系统配置",
    "netart": "网络痕迹",
    "linuxart": "Linux 痕迹",
    "iosart": "iOS 痕迹",
    "mobile": "移动端综合",
    "mail": "邮件",
    "heif": "HEIF/HEIC 解码",
    "online": "在线服务痕迹",
    "regf": "注册表 hive",
    "revkit": "逆向套件",
    "revkit_help": "逆向辅助",
}


def banner():
    """打印工具包标识"""
    print("ESK %s  ·  Electronic Software Kit  ·  Calmgh06" % __version__)
    return __watermark__


def modules():
    """列出全部模块名"""
    return list(__all__)