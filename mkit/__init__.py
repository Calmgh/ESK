# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""mkit 包：自研电子数据取证解析工具集。"""

__version__ = "1.7.6"
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
    "archive", "bincue", "raid", "raidmeta",
    "ubi",
    "classicfs",
    "containers",
    "f2fs",
    "flashfs",
    "refs",
    "retrofs",
    "erofs",
    "gfs2",
    "zfs",
    "casebook",
    "filevault2",
    "nilfs2",
    "preview",
    "veracrypt",
    "vss",
    "bcachefs",
    "efs",
    "ocfs2",
    "gguf",
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
    "archive": "归档与逻辑包：TAR/GZ/BZ2/XZ（重复成员取证）、7z、Docker/OCI 层、BCP、小米 bak",
    "bincue": "光盘镜像：CUE/BIN 多轨、8 种扇区模式、CCD/MDS 头部、SUB Q 通道",
    "raid": "RAID 重组：0/1/4/5(left,right)/6/10，GF(2^8)，RAID6 缺两盘 P+Q 联立重建",
    "raidmeta": "RAID 元数据：Intel IMSM/VROC MPB 与 SNIA DDF",
    "ubi": "UBI 卷层（EC/VID 头、PEB 扫描、卷重组）+ UBIFS（顺序 LEB 扫描读文件）",
    "classicfs": "Minix FS V1/V2/V3 · JFS · ReiserFS 3.5/3.6（只读，含 S+ 树/xtree/dtree）",
    "containers": "冷门镜像/固件容器：uImage / CHK / TRX / PHD / Sercomm / SafeLoader / Buffalo",
    "f2fs": "F2FS（Android 主力闪存文件系统：超级块/checkpoint/NAT/SIT/inode/目录）",
    "flashfs": "JFFS2 · YAFFS1 · YAFFS2（裸 NAND 闪存文件系统，日志式多版本重建）",
    "refs": "ReFS（Windows 弹性文件系统：超级块/容器表/对象表/目录）",
    "retrofs": "Amiga OFS/FFS · BeFS · QNX4/QNX6（老式与车机/IoT 文件系统）",
    "erofs": "EROFS（Android 只读分区：FLAT_PLAIN/INLINE/COMPRESSED + 自实现 LZ4）",
    "gfs2": "GFS2（集群文件系统：超级块/资源组/dinode/stuffed 与 EXHASH 目录/元树）",
    "zfs": "ZFS（uberblock/blkptr/fletcher4/ZAP/目录；SA 未解，文件精确长度与 mtime 取不到）",
    "casebook": "取证案件管理（Case / 哈希链 AuditLog / sqlite 索引 / 清单复核 / **卷快照 snapshot+diff+restore+verify**）",
    "filevault2": "FileVault 2 / CoreStorage（AES-KW + XTS + 口令→KEK→VMK 密钥链）",
    "nilfs2": "NILFS2（日志结构：超级块 / 段摘要与超级根 / checkpoint / B-tree 目录）",
    "preview": "原类型预览 + PE / ELF / Mach-O 结构视图（文件头按需解析，不执行）",
    "veracrypt": "VeraCrypt / TrueCrypt 卷头解析与口令解锁（AES-XTS，PBKDF2 多 PRF）",
    "vss": "Windows VSS 卷影副本（catalog / 块描述符 / 满·范围·零三种块）",
    "bcachefs": "bcachefs（超级块/字段链/成员/journal；**btree 未实现，目录与文件读取不可用**）",
    "efs": "Windows EFS（$EFS 属性/凭据/密钥信息；FEK 为 RSA 加密，解不出明文）",
    "ocfs2": "OCFS2（超级块/链列表/extent 与 extent 块树/线性与索引目录）",
    "gguf": "GGUF 模型文件结构（元数据 KV / tensor_info / alignment；不做反量化，K-quant 类型不猜字节数）",
}


def banner():
    """打印工具包标识"""
    print("ESK %s  ·  Electronic Software Kit  ·  Calmgh06" % __version__)
    return __watermark__


def modules():
    """列出全部模块名"""
    return list(__all__)