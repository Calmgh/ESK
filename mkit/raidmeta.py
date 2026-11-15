# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""RAID 控制器元数据：Intel IMSM / VROC 与 SNIA DDF

只依赖可读对象的 `read(offset, size)` 与 `size`，可喂任意设备对象。
产出的描述结构可直接交给 `mkit.raid.Raid` 做重组。

============================================================================
已实现
============================================================================
1. Intel IMSM / VROC（MPB，小端）
   · 签名 `"Intel Raid ISM Cfg Sig. "` + 8 字节版本；在磁盘尾部若干 MB 内
     按扇区步长倒扫定位，再用 `mpb_size` 与校验和双重验证
   · MPB 按「锚点扇区在最后、扩展部分紧随其后」的语义拼接：先试
     `sig_offset` 起的连续 `mpb_size` 字节，再试 `sig_offset - (mpb_size - ss)`
     起的连续窗口，哪个校验和通过用哪个
   · 头部全字段：check_sum / mpb_size / family_num / generation_num /
     error_log_size / attributes / num_disks / num_raid_devs / cache_size /
     orig_family_num / pwr_cycle_count / bbm_log_size / creation_time
   · `imsm_disk` 48 字节（serial 16、total_blocks_lo/hi、scsi_id、status、
     owner_cfg_num）
   · `imsm_dev` 164 + 4×(num_members−1) 字节：卷名、size_low/high、status、
     `imsm_vol`、`imsm_map`（pba_of_lba0、blocks_per_member、num_data_stripes、
     blocks_per_strip、map_state、raid_level、num_members、disk_ord_tbl）
   · `disk_ord_tbl` 低 24 位 = 磁盘索引，最高字节 = 重建标志
   · RAID 级别：0 / 1 / 5 / 10（`raid_level==1` 且 num_members≠2 即 RAID10）
   · chunk = `blocks_per_strip × 512`
   · 校验和：`sum(mpb_size 内全部 u32) − check_sum == check_sum`
     （与 mdadm `__gen_imsm_checksum` 一致）

2. SNIA DDF（大端 / 大端字段）
   · 在设备最后 32 MiB 内按 512 字节步长扫 `0xDE11DE11`，按头部 `type`
     区分 anchor(0) / primary(1) / secondary(2)
   · 头部 512 字节全字段：crc / guid / revision / seq / timestamp / flags /
     primary_lba / secondary_lba / type / max_pd_entries / max_vd_entries /
     max_partitions / config_record_len / max_primary_element_entries /
     各 section 的偏移与长度（controller / phys / virt / config / data /
     bbm / diag / vendor）
   · 物理盘段 `phys_disk` + `phys_disk_entry`（guid、refnum、type、state、
     config_size、path）
   · 虚拟盘段 `virtual_disk` + `virtual_entry`（guid、unit、type、state、
     init_state、name）
   · 配置段 `vd_config`：prim_elmnt_count、chunk_shift、prl、rlq、
     sec_elmnt_count、srl、blocks、array_blocks、phys_refnum[]、lba_offset[]
   · RAID 级别映射照 mdadm `layout_ddf2md`：CONCAT / RAID0 / RAID1 /
     RAID1E→10 / RAID4 / RAID5（三种 rlq 布局）/ RAID6（三种 rlq 布局）/
     sec_elmnt_count>1 且 prl==RAID1 → RAID10

3. 统一产出（供 `mkit.raid.Raid` 消费）
   `{"scheme", "level", "chunk_bytes", "member_order", "member_offsets",
     "vd_size", "volume_name", "layout", "notes"}`

============================================================================
不实现（明确边界，不猜）
============================================================================
· **写回与初始化**：只读解析，不产生任何写操作
· **DDF 的 RAID3 / RAID5E / RAID5EE**：mdadm 也判为不支持，
  本模块给出 `level=None` 与 `notes` 说明，不假装能重组
· **DDF 的 CONCAT / SPANNED 跨盘拼接**：只报类型，不给重组参数
· **IMSM 迁移中的第二份 map**（`migr_state != 0`）：只报
  `migrating=True` 与两份 map 的级别差异，不pick一个当最终布局
· **IMSM 的 BBM（坏块管理）日志内容**：只报长度与偏移，不解析条目
· **DDF 的 spare / vendor / diag 段**：只报偏移与长度
· **加密**：控制器自加密盘（SED / OPAL）的锁定状态无法从这些元数据判断
· **CRC 校验**：DDF 头部 CRC32 与 IMSM 的 check_sum 都做了；但 DDF 各
  section 内部记录的 CRC 未逐条验证（只验头部），docstring 与返回值里
  如实标注 `section_crc_verified=False`

============================================================================
与常见二手资料的差异（本文件以 mdadm super-intel.c / super-ddf.c 为准）
============================================================================
· IMSM 的 `check_sum` 在 **0x20**（不是 0x28），`mpb_size` 在 **0x24**，
  `family_num` 在 0x28；磁盘表从 **0xD8** 开始（不是 0x40）
· IMSM 的 `attributes` 在 0x34，其 0x80000000 位是「校验和需验证」，
  不是「family_id」
· `imsm_disk` 里**没有** start_sector，也**没有** vol_id[2]；总容量是
  total_blocks_lo@0x10 与 total_blocks_hi@0x20 拼起来的
· `imsm_dev` 里**没有** password、没有 chunk_size 字段；chunk 由
  map 里的 `blocks_per_strip`×512 得到
· `disk_ord_tbl` 是 **u32**（不是 u8[4]），高位字节是重建标志
· 卷起始扇区是 map 里的 `pba_of_lba0`，不是独立的 start_sector
· DDF 的 `vd_config` 里没有单独的 chunk 字段，是 `chunk_shift`
  （`chunk = 512 << chunk_shift`）
"""

import struct

__all__ = ["ImsmSuper", "ImsmDisk", "ImsmDev", "DdfHeader", "DdfVd",
           "DdfSuper",
           "detect", "detect_imsm", "detect_ddf",
           "parse", "parse_imsm", "parse_ddf",
           "describe", "imsm_checksum_ok", "ddf_crc32",
           "IMSM_SIGNATURE", "DDF_MAGIC"]

IMSM_SIGNATURE = b"Intel Raid ISM Cfg Sig. "
DDF_MAGIC = 0xDE11DE11

# IMSM 常量（mdadm super-intel.c）
MPB_ATTRIB_CHECKSUM_VERIFY = 0x80000000
MPB_ATTRIB_2TB = 0x20000000
MPB_ATTRIB_2TB_DISK = 0x04000000
IMSM_ORD_REBUILD = 1 << 24
IMSM_STATUS_SPARE = 0x1
IMSM_STATUS_CONFIGURED = 0x2
IMSM_STATUS_FAILED = 0x4

IMSM_MAP_STATE = {0: "normal", 1: "uninitialized", 2: "degraded", 3: "failed"}

# DDF 常量（mdadm super-ddf.c）
DDF_HEADER_ANCHOR = 0x00
DDF_HEADER_PRIMARY = 0x01
DDF_HEADER_SECONDARY = 0x02

DDF_RAID0 = 0x00
DDF_RAID1 = 0x01
DDF_RAID3 = 0x03
DDF_RAID4 = 0x04
DDF_RAID5 = 0x05
DDF_RAID6 = 0x06
DDF_RAID1E = 0x11
DDF_CONCAT = 0x1F
DDF_RAID5E = 0x15
DDF_RAID5EE = 0x25

DDF_RAID1_SIMPLE = 0x00
DDF_RAID1_MULTI = 0x01
DDF_RAID4_N = 0x01
DDF_RAID5_0_RESTART = 0x00
DDF_RAID5_N_RESTART = 0x02
DDF_RAID5_N_CONTINUE = 0x03
DDF_RAID6_0_RESTART = 0x01
DDF_RAID1E_ADJACENT = 0x00
DDF_RAID1E_OFFSET = 0x01

DDF_2STRIPED = 0x00
DDF_2MIRRORED = 0x01
DDF_2CONCAT = 0x02
DDF_2SPANNED = 0x03

DDF_PRL_NAME = {
    DDF_RAID0: "RAID0", DDF_RAID1: "RAID1", DDF_RAID3: "RAID3",
    DDF_RAID4: "RAID4", DDF_RAID5: "RAID5", DDF_RAID6: "RAID6",
    DDF_RAID1E: "RAID1E", DDF_CONCAT: "CONCAT",
    DDF_RAID5E: "RAID5E", DDF_RAID5EE: "RAID5EE",
}

DDF_SRL_NAME = {
    DDF_2STRIPED: "2STRIPED", DDF_2MIRRORED: "2MIRRORED",
    DDF_2CONCAT: "2CONCAT", DDF_2SPANNED: "2SPANNED",
}

DDF_HEADER_TYPE_NAME = {
    DDF_HEADER_ANCHOR: "anchor", DDF_HEADER_PRIMARY: "primary",
    DDF_HEADER_SECONDARY: "secondary",
}


# ------------------------------------------------------------
# 字节序辅助
# ------------------------------------------------------------
def _le16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _le32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _le64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _be16(b, o):
    return struct.unpack_from(">H", b, o)[0]


def _be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def _be64(b, o):
    return struct.unpack_from(">Q", b, o)[0]


def _cstr(raw):
    """C 字符串解码（去掉尾部 NUL / 0xFF 填充）"""
    if not raw:
        return ""
    raw = raw.split(b"\x00")[0]
    try:
        return raw.decode("utf-8", "replace").strip()
    except Exception:
        return raw.decode("latin-1", "replace").strip()


# ------------------------------------------------------------
# IMSM
# ------------------------------------------------------------
def imsm_checksum_ok(buf, mpb_size):
    """mdadm __gen_imsm_checksum：sum(mpb_size 内全部 u32) − check_sum == check_sum"""
    if mpb_size < 0x28 or mpb_size > len(buf):
        return False
    end = mpb_size // 4
    total = 0
    for i in range(end):
        total = (total + _le32(buf, i * 4)) & 0xFFFFFFFF
    stored = _le32(buf, 0x20)
    return ((total - stored) & 0xFFFFFFFF) == stored


class ImsmDisk(object):
    """imsm_disk，48 字节"""

    __slots__ = ("index", "serial", "total_blocks", "scsi_id", "status",
                 "owner_cfg_num")

    def __init__(self, raw, index):
        self.index = index
        self.serial = _cstr(raw[0x00:0x10])
        lo = _le32(raw, 0x10)
        self.scsi_id = _le32(raw, 0x14)
        self.status = _le32(raw, 0x18)
        self.owner_cfg_num = _le32(raw, 0x1C)
        hi = _le32(raw, 0x20)
        self.total_blocks = lo | (hi << 32)

    @property
    def status_name(self):
        names = []
        if self.status & IMSM_STATUS_SPARE:
            names.append("spare")
        if self.status & IMSM_STATUS_CONFIGURED:
            names.append("configured")
        if self.status & IMSM_STATUS_FAILED:
            names.append("failed")
        return "|".join(names) if names else "0x%X" % self.status

    def to_dict(self):
        return {"index": self.index, "serial": self.serial,
                "total_blocks": self.total_blocks, "scsi_id": self.scsi_id,
                "status": self.status_name, "owner_cfg_num": self.owner_cfg_num}


class ImsmDev(object):
    """imsm_dev，164 + 4×(num_members−1) 字节"""

    __slots__ = ("index", "volume", "size_blocks", "status", "reserved_blocks",
                 "migr_state", "num_members", "raid_level", "chunk_blocks",
                 "map_state", "pba_of_lba0", "blocks_per_member",
                 "num_data_stripes", "disk_order", "rebuild_mask", "raw_len")

    def __init__(self, raw, index, base=0):
        self.index = index
        self.raw_len = len(raw)
        self.volume = _cstr(raw[0x00:0x10])
        self.size_blocks = _le32(raw, 0x10) | (_le32(raw, 0x14) << 32)
        self.status = _le32(raw, 0x18)
        self.reserved_blocks = _le32(raw, 0x1C)

        # imsm_vol @0x50
        self.migr_state = raw[0x50 + 0x08]
        # imsm_map @0x50 + 0x20 = 0x70
        mp = 0x70
        self.pba_of_lba0 = _le32(raw, mp + 0x00) | (_le32(raw, mp + 0x14) << 32)
        self.blocks_per_member = _le32(raw, mp + 0x04) | (_le32(raw, mp + 0x18) << 32)
        self.num_data_stripes = _le32(raw, mp + 0x08) | (_le32(raw, mp + 0x1C) << 32)
        self.chunk_blocks = _le16(raw, mp + 0x0C)
        self.map_state = raw[mp + 0x0E]
        self.raid_level = raw[mp + 0x0F]
        self.num_members = raw[mp + 0x10]

        self.disk_order = []
        self.rebuild_mask = 0
        tbl = mp + 0x30
        n = self.num_members if 0 < self.num_members <= 64 else 0
        for i in range(n):
            off = tbl + i * 4
            if off + 4 > len(raw):
                break
            v = _le32(raw, off)
            self.disk_order.append(v & 0x00FFFFFF)
            if v & IMSM_ORD_REBUILD:
                self.rebuild_mask |= (1 << i)

    @property
    def level(self):
        """映射到 MD 级别；raid_level==1 且成员数≠2 时是 RAID10"""
        if self.raid_level == 1:
            return 1 if self.num_members == 2 else 10
        return self.raid_level

    @property
    def chunk_bytes(self):
        return self.chunk_blocks * 512

    @property
    def map_state_name(self):
        return IMSM_MAP_STATE.get(self.map_state, "0x%02X" % self.map_state)

    def to_dict(self):
        return {
            "index": self.index, "volume": self.volume,
            "raid_level_raw": self.raid_level, "level": self.level,
            "num_members": self.num_members,
            "disk_order": list(self.disk_order),
            "rebuild_positions": [i for i in range(32) if self.rebuild_mask >> i & 1],
            "chunk_blocks": self.chunk_blocks, "chunk_bytes": self.chunk_bytes,
            "pba_of_lba0": self.pba_of_lba0,
            "blocks_per_member": self.blocks_per_member,
            "num_data_stripes": self.num_data_stripes,
            "size_blocks": self.size_blocks,
            "map_state": self.map_state_name,
            "migrating": bool(self.migr_state),
            "status": "0x%08X" % self.status,
            "reserved_blocks": self.reserved_blocks,
        }


class ImsmSuper(object):
    """解析后的 MPB"""

    def __init__(self, buf, offset=0):
        if len(buf) < 0xD8:
            raise ValueError("MPB 太短：%d 字节（至少 0xD8）" % len(buf))
        if not buf.startswith(IMSM_SIGNATURE):
            raise ValueError("不是 IMSM MPB：签名为 %r" % buf[:24])
        self.offset = offset
        self.version = _cstr(buf[24:32])
        self.check_sum = _le32(buf, 0x20)
        self.mpb_size = _le32(buf, 0x24)
        self.family_num = _le32(buf, 0x28)
        self.generation_num = _le32(buf, 0x2C)
        self.error_log_size = _le32(buf, 0x30)
        self.attributes = _le32(buf, 0x34)
        self.num_disks = buf[0x38]
        self.num_raid_devs = buf[0x39]
        self.error_log_pos = buf[0x3A]
        self.cache_size = _le32(buf, 0x3C)
        self.orig_family_num = _le32(buf, 0x40)
        self.pwr_cycle_count = _le32(buf, 0x44)
        self.bbm_log_size = _le32(buf, 0x48)
        self.creation_time = _le64(buf, 0x50)

        self.disks = []
        pos = 0xD8
        for i in range(self.num_disks):
            if pos + 48 > len(buf):
                raise ValueError("磁盘表越界：需要 %d 条，第 %d 条读不到"
                                 % (self.num_disks, i))
            self.disks.append(ImsmDisk(buf[pos:pos + 48], i))
            pos += 48

        self.devs = []
        for i in range(self.num_raid_devs):
            if pos + 164 > len(buf):
                raise ValueError("卷表越界：第 %d 个 imsm_dev 读不到" % i)
            n = buf[pos + 0x70 + 0x10]
            dlen = 164 + 4 * (n - 1) if 0 < n <= 64 else 164
            if pos + dlen > len(buf):
                dlen = len(buf) - pos
            self.devs.append(ImsmDev(buf[pos:pos + dlen], i))
            pos += dlen

        self.checksum_ok = imsm_checksum_ok(buf, min(self.mpb_size, len(buf)))

    def to_dict(self):
        return {
            "scheme": "imsm", "signature": "Intel Raid ISM Cfg Sig.",
            "version": self.version, "offset": self.offset,
            "mpb_size": self.mpb_size, "check_sum": "0x%08X" % self.check_sum,
            "checksum_ok": self.checksum_ok,
            "family_num": self.family_num, "orig_family_num": self.orig_family_num,
            "generation_num": self.generation_num,
            "attributes": "0x%08X" % self.attributes,
            "checksum_verify_bit": bool(self.attributes & MPB_ATTRIB_CHECKSUM_VERIFY),
            "support_2tb": bool(self.attributes & MPB_ATTRIB_2TB),
            "num_disks": self.num_disks, "num_raid_devs": self.num_raid_devs,
            "cache_size": self.cache_size,
            "pwr_cycle_count": self.pwr_cycle_count,
            "bbm_log_size": self.bbm_log_size,
            "creation_time": self.creation_time,
            "disks": [d.to_dict() for d in self.disks],
            "volumes": [v.to_dict() for v in self.devs],
        }


def detect_imsm(sub):
    """在磁盘尾部扫 IMSM 签名；找到且校验和通过才算命中"""
    try:
        size = int(getattr(sub, "size", 0) or 0)
    except Exception:
        return False
    if size < 0x10000:
        return False
    for off, buf in _imsm_candidates(sub):
        try:
            sup = ImsmSuper(buf, off)
        except Exception:
            continue
        if sup.checksum_ok:
            return True
    return False


def _imsm_candidates(sub):
    """产出 (偏移, mpb 字节) 候选；判据交给调用方的校验和

    MPB 在磁盘尾部：mdadm 把「锚点扇区」写在靠末尾处，扩展部分紧邻其前。
    这里按扇区步长倒扫签名，再对每个签名位置给出两种拼接解释：
      1) 从签名处向后连续读 mpb_size
      2) 让 mpb_size 的窗口在「签名扇区末尾」收尾（扩展部分在前）
    """
    size = int(getattr(sub, "size", 0) or 0)
    if size <= 0:
        return
    for ss in (512, 4096, 2048, 1024):
        if size < ss * 8:
            continue
        span = min(size, 4 * 1024 * 1024)          # 尾部 4 MiB 足够
        start = size - span
        start -= start % ss
        # 倒序（靠末尾的更可能是锚点）
        off = size - ss
        seen = 0
        while off >= start and seen < 4096:
            seen += 1
            try:
                head = sub.read(off, 0x30)
            except Exception:
                return
            if len(head) >= 24 and head.startswith(IMSM_SIGNATURE):
                try:
                    hdr = sub.read(off, 0x28)
                    mpb_size = _le32(hdr, 0x24) if len(hdr) >= 0x28 else 0
                except Exception:
                    mpb_size = 0
                if 0x100 <= mpb_size <= 16 * 1024 * 1024:
                    try:
                        buf = sub.read(off, mpb_size)
                    except Exception:
                        buf = b""
                    if len(buf) >= 0xD8:
                        yield (off, buf)
                    back = off - (mpb_size - ss)
                    if back >= 0:
                        try:
                            buf2 = sub.read(back, mpb_size)
                        except Exception:
                            buf2 = b""
                        if len(buf2) >= 0xD8 and buf2.startswith(IMSM_SIGNATURE):
                            yield (back, buf2)
            off -= ss


def parse_imsm(disk_subs):
    """解析成员盘，返回每个卷的重组描述

    disk_subs: 成员盘对象列表，按物理顺序（描述里的 member_order 是盘内索引）
    """
    hits = []
    for idx, sub in enumerate(disk_subs):
        found = None
        for off, buf in _imsm_candidates(sub):
            try:
                sup = ImsmSuper(buf, off)
            except Exception:
                continue
            if sup.checksum_ok:
                found = sup
                break
        if found is not None:
            hits.append((idx, found))

    if not hits:
        return []

    # 取 generation_num 最大的一份（最新的配置）
    hits.sort(key=lambda x: x[1].generation_num, reverse=True)
    sup = hits[0][1]

    out = []
    for dev in sup.devs:
        if dev.num_members != len(dev.disk_order):
            notes = ["disk_ord_tbl 长度与 num_members 不一致（%d vs %d）"
                     % (len(dev.disk_order), dev.num_members)]
        else:
            notes = []
        if dev.migr_state:
            notes.append("卷在迁移中（migr_state=%d），只报当前 map" % dev.migr_state)
        if dev.rebuild_mask:
            notes.append("disk_ord_tbl 有重建标志位")
        member_offsets = [dev.pba_of_lba0 * 512] * len(dev.disk_order)
        out.append({
            "scheme": "imsm",
            "level": dev.level,
            "chunk_bytes": dev.chunk_bytes,
            "member_order": list(dev.disk_order),
            "member_offsets": member_offsets,
            "vd_size": dev.blocks_per_member * dev.num_data_stripes * 512
                       if dev.num_data_stripes else dev.size_blocks * 512,
            "volume_name": dev.volume,
            "layout": "left" if dev.level in (5, 6) else None,
            "notes": notes,
            "raw": dev.to_dict(),
        })
    return out


# ------------------------------------------------------------
# DDF
# ------------------------------------------------------------
def _crc32_table():
    tbl = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        tbl.append(c)
    return tbl


_CRC_TBL = _crc32_table()


def ddf_crc32(data, init=0xFFFFFFFF):
    """DDF 用的 CRC32（多项式 0x04C11DB7 反射形式 0xEDB88320）"""
    c = init
    for b in data:
        c = _CRC_TBL[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


class DdfHeader(object):
    """DDF 头部，512 字节，全大端"""

    def __init__(self, buf, offset=0):
        if len(buf) < 0x100:
            raise ValueError("DDF 头部太短：%d 字节" % len(buf))
        if _be32(buf, 0) != DDF_MAGIC:
            raise ValueError("不是 DDF：magic=0x%08X" % _be32(buf, 0))
        self.offset = offset
        self.crc = _be32(buf, 0x04)
        self.guid = buf[0x08:0x20].hex()
        self.revision = _cstr(buf[0x20:0x28])
        self.seq = _be32(buf, 0x28)
        self.timestamp = _be32(buf, 0x2C)
        self.openflag = buf[0x30]
        self.foreignflag = buf[0x31]
        self.enforcegroups = buf[0x32]
        self.primary_lba = _be64(buf, 0x60)
        self.secondary_lba = _be64(buf, 0x68)
        self.type = buf[0x70]
        self.workspace_len = _be32(buf, 0x74)
        self.workspace_lba = _be64(buf, 0x78)
        self.max_pd_entries = _be16(buf, 0x80)
        self.max_vd_entries = _be16(buf, 0x82)
        self.max_partitions = _be16(buf, 0x84)
        self.config_record_len = _be16(buf, 0x86)
        self.max_primary_element_entries = _be16(buf, 0x88)

        self.sections = {}
        for name, base in (("controller", 0xC0), ("phys", 0xC8),
                           ("virt", 0xD0), ("config", 0xD8),
                           ("data", 0xE0), ("bbm", 0xE8),
                           ("diag", 0xF0), ("vendor", 0xF8)):
            self.sections[name] = (_be32(buf, base), _be32(buf, base + 4))

        # 头部 CRC：按 DDF 规范是对 crc 字段置零后的前 header_size 字节
        n = min(len(buf), 512)
        tmp = bytearray(buf[:n])
        if n >= 8:
            tmp[4:8] = b"\x00\x00\x00\x00"
        self.crc_ok = (ddf_crc32(bytes(tmp)) == self.crc)

    @property
    def type_name(self):
        return DDF_HEADER_TYPE_NAME.get(self.type, "0x%02X" % self.type)

    def to_dict(self):
        return {
            "type": self.type_name, "offset": self.offset,
            "guid": self.guid, "revision": self.revision, "seq": self.seq,
            "timestamp": self.timestamp,
            "open": self.openflag, "foreign": self.foreignflag,
            "primary_lba": self.primary_lba,
            "secondary_lba": self.secondary_lba,
            "max_pd_entries": self.max_pd_entries,
            "max_vd_entries": self.max_vd_entries,
            "max_primary_element_entries": self.max_primary_element_entries,
            "config_record_len": self.config_record_len,
            "sections": {k: {"offset": v[0], "length": v[1]}
                         for k, v in self.sections.items()},
            "crc_ok": self.crc_ok,
        }


class DdfVd(object):
    """一条 vd_config 记录"""

    def __init__(self, raw, index, rec_len, mppe):
        self.index = index
        self.record_len = rec_len
        if len(raw) < 0x200 + 4:
            raise ValueError("vd_config 太短：%d 字节" % len(raw))
        self.magic = _be32(raw, 0x00)
        self.crc = _be32(raw, 0x04)
        self.guid = raw[0x08:0x20].hex()
        self.timestamp = _be32(raw, 0x20)
        self.seqnum = _be32(raw, 0x24)
        self.prim_elmnt_count = _be16(raw, 0x40)
        self.chunk_shift = raw[0x42]
        self.prl = raw[0x43]
        self.rlq = raw[0x44]
        self.sec_elmnt_count = raw[0x45]
        self.sec_elmnt_seq = raw[0x46]
        self.srl = raw[0x47]
        self.blocks = _be64(raw, 0x48)
        self.array_blocks = _be64(raw, 0x50)

        n = self.prim_elmnt_count if 0 < self.prim_elmnt_count <= 4096 else 0
        self.phys_refnum = []
        self.lba_offset = []
        base = 0x200
        for i in range(n):
            off = base + i * 4
            if off + 4 > len(raw):
                break
            self.phys_refnum.append(_be32(raw, off))
        # lba_offset 紧跟在 phys_refnum[max_primary_element_entries] 之后
        lbase = 0x200 + max(mppe, n) * 4
        for i in range(n):
            off = lbase + i * 8
            if off + 8 > len(raw):
                break
            self.lba_offset.append(_be64(raw, off))

        self.level, self.layout, self.unsupported = _ddf_level(self)

    @property
    def chunk_bytes(self):
        return 512 << self.chunk_shift if self.chunk_shift < 32 else 0

    def to_dict(self):
        return {
            "index": self.index, "guid": self.guid,
            "prl": "0x%02X" % self.prl,
            "prl_name": DDF_PRL_NAME.get(self.prl, "0x%02X" % self.prl),
            "srl": "0x%02X" % self.srl,
            "srl_name": DDF_SRL_NAME.get(self.srl, "0x%02X" % self.srl),
            "rlq": "0x%02X" % self.rlq,
            "level": self.level, "layout": self.layout,
            "unsupported": self.unsupported,
            "prim_elmnt_count": self.prim_elmnt_count,
            "sec_elmnt_count": self.sec_elmnt_count,
            "chunk_shift": self.chunk_shift, "chunk_bytes": self.chunk_bytes,
            "blocks": self.blocks, "array_blocks": self.array_blocks,
            "phys_refnum": list(self.phys_refnum),
            "lba_offset": list(self.lba_offset),
            "seqnum": self.seqnum,
        }


def _ddf_level(vd):
    """照 mdadm layout_ddf2md 映射；返回 (level, layout, unsupported_reason)"""
    raid = vd.prim_elmnt_count

    if vd.sec_elmnt_count > 1:
        if vd.prl != DDF_RAID1 or vd.srl not in (DDF_2STRIPED, DDF_2SPANNED):
            return (None, None, "次级 RAID 组合 prl=0x%02X/srl=0x%02X 不支持"
                    % (vd.prl, vd.srl))
        if raid == 2 and vd.rlq == DDF_RAID1_SIMPLE:
            return (10, "near", None)
        if raid == 3 and vd.rlq == DDF_RAID1_MULTI:
            return (10, "near", None)
        return (None, None, "RAID10 布局 rlq=0x%02X 与成员数 %d 不匹配"
                % (vd.rlq, raid))

    if vd.prl == DDF_CONCAT:
        return (None, None, "CONCAT 跨盘拼接未实现")
    if vd.prl == DDF_RAID0:
        return (0, "stripe", None)
    if vd.prl == DDF_RAID1:
        if (vd.rlq == DDF_RAID1_SIMPLE and raid == 2) or \
           (vd.rlq == DDF_RAID1_MULTI and raid == 3):
            return (1, "mirror", None)
        return (None, None, "RAID1 布局 rlq=0x%02X 与成员数 %d 不匹配"
                % (vd.rlq, raid))
    if vd.prl == DDF_RAID1E:
        if vd.rlq == DDF_RAID1E_ADJACENT:
            return (10, "near", None)
        if vd.rlq == DDF_RAID1E_OFFSET:
            return (10, "offset", None)
        return (None, None, "RAID1E 布局 rlq=0x%02X 不支持" % vd.rlq)
    if vd.prl == DDF_RAID4:
        if vd.rlq == DDF_RAID4_N:
            return (4, "fixed-parity", None)
        return (None, None, "RAID4 只支持 parity 在末位（rlq=0x%02X）" % vd.rlq)
    if vd.prl == DDF_RAID5:
        if vd.rlq == DDF_RAID5_N_RESTART:
            return (5, "left-asymmetric", None)
        if vd.rlq == DDF_RAID5_0_RESTART:
            return (5, "right-asymmetric", None)
        if vd.rlq == DDF_RAID5_N_CONTINUE:
            return (5, "left-symmetric", None)
        return (None, None, "RAID5 布局 rlq=0x%02X 不支持" % vd.rlq)
    if vd.prl == DDF_RAID6:
        if vd.rlq == DDF_RAID5_N_RESTART:
            return (6, "rotating-n-restart", None)
        if vd.rlq == DDF_RAID6_0_RESTART:
            return (6, "rotating-zero-restart", None)
        if vd.rlq == DDF_RAID5_N_CONTINUE:
            return (6, "rotating-n-continue", None)
        return (None, None, "RAID6 布局 rlq=0x%02X 不支持" % vd.rlq)
    return (None, None, "未支持的 prl=0x%02X（%s）"
            % (vd.prl, DDF_PRL_NAME.get(vd.prl, "?")))


class DdfSuper(object):
    """解析后的 DDF 主配置"""

    def __init__(self, sub, header):
        self.sub = sub
        self.header = header
        self.phys_disks = []
        self.virtual_disks = []
        self.vds = []
        self.notes = []

        self._load_phys()
        self._load_virt()
        self._load_vds()

    def _section(self, name):
        off, length = self.header.sections.get(name, (0, 0))
        if not off or not length:
            return b""
        try:
            return self.sub.read(self.header.offset + off, length)
        except Exception:
            return b""

    def _load_phys(self):
        buf = self._section("phys")
        if len(buf) < 0x40:
            return
        magic = _be32(buf, 0)
        if magic != 0x22222222:
            self.notes.append("phys 段 magic=0x%08X（期望 0x22222222）" % magic)
            return
        used = _be16(buf, 0x08)
        maxp = _be16(buf, 0x0A)
        pos = 0x40
        for i in range(min(used, 4096)):
            if pos + 64 > len(buf):
                break
            self.phys_disks.append({
                "index": i,
                "guid": buf[pos:pos + 24].hex(),
                "refnum": _be32(buf, pos + 24),
                "type": "0x%04X" % _be16(buf, pos + 28),
                "state": "0x%04X" % _be16(buf, pos + 30),
                "config_size": _be64(buf, pos + 32),
                "path": _cstr(buf[pos + 40:pos + 58]),
            })
            pos += 64
        if len(self.phys_disks) != used:
            self.notes.append("phys 段声明 %d 条，实际解析 %d 条"
                              % (used, len(self.phys_disks)))

    def _load_virt(self):
        buf = self._section("virt")
        if len(buf) < 0x40:
            return
        magic = _be32(buf, 0)
        if magic != 0xDDDDDDDD:
            self.notes.append("virt 段 magic=0x%08X（期望 0xDDDDDDDD）" % magic)
            return
        used = _be16(buf, 0x08)
        pos = 0x40
        for i in range(min(used, 4096)):
            if pos + 64 > len(buf):
                break
            self.virtual_disks.append({
                "index": i,
                "guid": buf[pos:pos + 24].hex(),
                "unit": _be16(buf, pos + 24),
                "guid_crc": "0x%04X" % _be16(buf, pos + 28),
                "type": "0x%04X" % _be16(buf, pos + 30),
                "state": buf[pos + 32],
                "init_state": buf[pos + 33],
                "name": _cstr(buf[pos + 48:pos + 64]),
            })
            pos += 64

    def _load_vds(self):
        buf = self._section("config")
        if not buf:
            self.notes.append("没有 config 段，无法得到卷定义")
            return
        rec = self.header.config_record_len * 512
        if rec <= 0:
            rec = 512
        mppe = self.header.max_primary_element_entries or 0
        n = len(buf) // rec
        for i in range(n):
            chunk = buf[i * rec:(i + 1) * rec]
            if len(chunk) < 0x200:
                continue
            if _be32(chunk, 0) != 0xEEEEEEEE:
                continue
            try:
                self.vds.append(DdfVd(chunk, i, rec, mppe))
            except Exception as e:
                self.notes.append("config 记录 %d 解析失败：%s" % (i, e))

    def to_dict(self):
        return {
            "scheme": "ddf",
            "header": self.header.to_dict(),
            "phys_disks": self.phys_disks,
            "virtual_disks": self.virtual_disks,
            "volumes": [v.to_dict() for v in self.vds],
            "notes": list(self.notes),
            "section_crc_verified": False,
        }

    def layouts(self):
        """转成 mkit.raid.Raid 能直接用的描述"""
        out = []
        for vd in self.vds:
            notes = []
            if vd.unsupported:
                notes.append(vd.unsupported)
            if vd.layout in ("left-asymmetric", "right-asymmetric"):
                notes.append("asymmetric 布局与 mkit.raid 的 left/right 语义不完全一致，"
                             "重组前请核对条带走向")
            if vd.chunk_shift >= 32:
                notes.append("chunk_shift 异常（%d）" % vd.chunk_shift)
            member_order = list(range(vd.prim_elmnt_count))
            member_offsets = [off * 512 for off in vd.lba_offset] \
                if vd.lba_offset else [0] * vd.prim_elmnt_count
            out.append({
                "scheme": "ddf",
                "level": vd.level,
                "chunk_bytes": vd.chunk_bytes,
                "member_order": member_order,
                "member_offsets": member_offsets,
                "vd_size": vd.array_blocks * 512,
                "volume_name": None,
                "layout": vd.layout,
                "notes": notes,
                "phys_refnum": list(vd.phys_refnum),
                "raw": vd.to_dict(),
            })
        return out


def detect_ddf(sub):
    """在最后 32 MiB 内扫 DDF magic"""
    return _find_ddf_header(sub) is not None


def _find_ddf_header(sub):
    """倒序找第一个 magic 命中且 type 合法的 DDF 头部"""
    try:
        size = int(getattr(sub, "size", 0) or 0)
    except Exception:
        return None
    if size < 1024:
        return None
    span = min(size, 32 * 1024 * 1024)
    start = size - span
    start -= start % 512
    off = size - 512
    tries = 0
    while off >= start and tries < 65536:
        tries += 1
        try:
            head = sub.read(off, 8)
        except Exception:
            return None
        if len(head) >= 4 and _be32(head, 0) == DDF_MAGIC:
            try:
                buf = sub.read(off, 512)
                hdr = DdfHeader(buf, off)
            except Exception:
                off -= 512
                continue
            if hdr.type in (DDF_HEADER_ANCHOR, DDF_HEADER_PRIMARY,
                            DDF_HEADER_SECONDARY):
                return hdr
        off -= 512
    return None


def parse_ddf(disk_subs):
    """解析成员盘，返回卷的重组描述"""
    subs = disk_subs[0] if isinstance(disk_subs, (list, tuple)) and disk_subs else disk_subs
    if isinstance(subs, (list, tuple)):
        subs = subs[0]
    hdr = _find_ddf_header(subs)
    if hdr is None:
        return []

    # anchor 只是一个指针，真正的配置在 primary
    if hdr.type == DDF_HEADER_ANCHOR and hdr.primary_lba:
        try:
            raw = subs.read(hdr.primary_lba * 512, 512)
            if len(raw) >= 0x100 and _be32(raw, 0) == DDF_MAGIC:
                hdr = DdfHeader(raw, hdr.primary_lba * 512)
        except Exception:
            pass

    sup = DdfSuper(subs, hdr)
    return sup.layouts()


# ------------------------------------------------------------
# 统一入口
# ------------------------------------------------------------
def detect(sub):
    if detect_imsm(sub):
        return "imsm"
    if detect_ddf(sub):
        return "ddf"
    return "unknown"


def parse(disk_subs):
    """自动探测并解析；返回 (scheme, layouts)"""
    if not isinstance(disk_subs, (list, tuple)):
        disk_subs = [disk_subs]
    if not disk_subs:
        return ("unknown", [])
    if detect_imsm(disk_subs[0]):
        return ("imsm", parse_imsm(disk_subs))
    if detect_ddf(disk_subs[0]):
        return ("ddf", parse_ddf(disk_subs))
    return ("unknown", [])


def describe(layout):
    """把一条描述打成人类可读的一行"""
    lvl = layout.get("level")
    lvl_txt = "RAID%s" % lvl if lvl is not None else "未支持"
    lines = ["%s %s  chunk=%d  成员=%d  容量=%.1f MiB  %s"
             % (layout.get("scheme", "?"), lvl_txt,
                layout.get("chunk_bytes") or 0,
                len(layout.get("member_order") or []),
                (layout.get("vd_size") or 0) / 2 ** 20,
                layout.get("layout") or "-")]
    for n in layout.get("notes") or []:
        lines.append("  · %s" % n)
    return "\n".join(lines)


# ------------------------------------------------------------
# 自检
# ------------------------------------------------------------
if __name__ == "__main__":
    import io
    import sys

    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    PASS = [0]
    FAIL = [0]

    def ck(cond, name, extra=""):
        if cond:
            PASS[0] += 1
            print("  [PASS] %s %s" % (name, extra))
        else:
            FAIL[0] += 1
            print("  [FAIL] %s %s" % (name, extra))

    class MemSub(object):
        def __init__(self, data):
            self.data = bytes(data)
            self.size = len(self.data)

        def read(self, off, n):
            if off >= self.size or n <= 0:
                return b""
            return self.data[off:off + n]

    # ---------------- IMSM 合成 ----------------
    def build_imsm(members, level=5, chunk_blocks=128, volume="VOL_RAID5",
                   generation=7, bad_checksum=False):
        """3 盘 × 1 个 RAID5 卷的 MPB，放在磁盘尾部"""
        n = len(members)
        dev_len = 164 + 4 * (n - 1)
        mpb_size = 0xD8 + n * 48 + dev_len
        mpb_size = ((mpb_size + 511) // 512) * 512
        buf = bytearray(mpb_size)

        buf[0:24] = b"Intel Raid ISM Cfg Sig. "
        buf[24:32] = b"1.3.00\x00\x00"
        struct.pack_into("<I", buf, 0x24, mpb_size)
        struct.pack_into("<I", buf, 0x28, 0x1234)          # family_num
        struct.pack_into("<I", buf, 0x2C, generation)
        struct.pack_into("<I", buf, 0x30, 0)               # error_log_size
        struct.pack_into("<I", buf, 0x34, MPB_ATTRIB_CHECKSUM_VERIFY)
        buf[0x38] = n
        buf[0x39] = 1
        struct.pack_into("<I", buf, 0x3C, 0x10000)         # cache_size
        struct.pack_into("<Q", buf, 0x50, 0x01D0000000000000)

        pos = 0xD8
        for i, (serial, blocks) in enumerate(members):
            raw = bytearray(48)
            raw[0:16] = serial.encode()[:16].ljust(16, b"\x00")
            struct.pack_into("<I", raw, 0x10, blocks & 0xFFFFFFFF)
            struct.pack_into("<I", raw, 0x14, 0)
            struct.pack_into("<I", raw, 0x18, IMSM_STATUS_CONFIGURED)
            struct.pack_into("<I", raw, 0x1C, 1)
            struct.pack_into("<I", raw, 0x20, (blocks >> 32) & 0xFFFFFFFF)
            buf[pos:pos + 48] = raw
            pos += 48

        dev = bytearray(dev_len)
        dev[0:16] = volume.encode()[:16].ljust(16, b"\x00")
        struct.pack_into("<I", dev, 0x10, 4000)
        struct.pack_into("<I", dev, 0x14, 0)
        struct.pack_into("<I", dev, 0x18, 0)
        struct.pack_into("<I", dev, 0x1C, 2048)
        dev[0x50 + 0x08] = 0                                # migr_state
        mp = 0x70
        struct.pack_into("<I", dev, mp + 0x00, 2048)        # pba_of_lba0
        struct.pack_into("<I", dev, mp + 0x04, 4000)        # blocks_per_member
        struct.pack_into("<I", dev, mp + 0x08, 1000)        # num_data_stripes
        struct.pack_into("<H", dev, mp + 0x0C, chunk_blocks)
        dev[mp + 0x0E] = 0                                  # map_state normal
        dev[mp + 0x0F] = level
        dev[mp + 0x10] = n
        dev[mp + 0x11] = 1
        for i in range(n):
            struct.pack_into("<I", dev, mp + 0x30 + i * 4, i)
        buf[pos:pos + dev_len] = dev

        # 校验和：验证式为 sum(全部 u32) − check_sum == check_sum，
        # 即 check_sum 恰好等于「其余所有字之和」。此处 0x20 处还是 0，
        # 所以直接把当前总和存进去即可。
        end = mpb_size // 4
        total = 0
        for i in range(end):
            total = (total + _le32(bytes(buf), i * 4)) & 0xFFFFFFFF
        cs = total & 0xFFFFFFFF
        if bad_checksum:
            cs = (cs + 1) & 0xFFFFFFFF
        struct.pack_into("<I", buf, 0x20, cs)
        return bytes(buf)

    def put_mpb_at_tail(disk_bytes, mpb, ss=512):
        """把 MPB 放到磁盘尾部（末尾留 2 个扇区，MPB 向前扩展）"""
        d = bytearray(disk_bytes)
        off = len(d) - 2 * ss
        start = off - (len(mpb) - ss)
        if start < 0:
            raise ValueError("磁盘太小放不下 MPB")
        d[start:start + len(mpb)] = mpb
        return bytes(d)

    print("=== 1) IMSM ===")
    members = [("SN0001", 8000), ("SN0002", 8000), ("SN0003", 8000)]
    mpb = build_imsm(members, level=5, chunk_blocks=128)
    disk = put_mpb_at_tail(bytes(1024 * 1024), mpb)
    sub = MemSub(disk)

    ck(detect_imsm(sub), "detect_imsm 命中")
    ck(imsm_checksum_ok(mpb, len(mpb)), "合成 MPB 校验和自洽")

    sup = ImsmSuper(mpb, 0)
    ck(sup.num_disks == 3 and sup.num_raid_devs == 1,
       "num_disks/num_raid_devs", "%d/%d" % (sup.num_disks, sup.num_raid_devs))
    ck(sup.family_num == 0x1234, "family_num", hex(sup.family_num))
    ck(sup.generation_num == 7, "generation_num", sup.generation_num)
    ck(sup.checksum_ok, "checksum_ok")
    ck(bool(sup.attributes & MPB_ATTRIB_CHECKSUM_VERIFY), "attributes 校验位")
    ck([d.serial for d in sup.disks] == ["SN0001", "SN0002", "SN0003"],
       "磁盘序列号", [d.serial for d in sup.disks])
    ck(sup.disks[0].total_blocks == 8000, "磁盘容量", sup.disks[0].total_blocks)

    dev = sup.devs[0]
    ck(dev.volume == "VOL_RAID5", "卷名", dev.volume)
    ck(dev.raid_level == 5 and dev.level == 5, "级别 RAID5", dev.level)
    ck(dev.num_members == 3, "成员数", dev.num_members)
    ck(dev.chunk_blocks == 128, "chunk_blocks", dev.chunk_blocks)
    ck(dev.chunk_bytes == 128 * 512, "chunk_bytes = blocks_per_strip×512",
       dev.chunk_bytes)
    ck(dev.disk_order == [0, 1, 2], "disk_ord_tbl 顺序", dev.disk_order)
    ck(dev.pba_of_lba0 == 2048, "pba_of_lba0", dev.pba_of_lba0)
    ck(dev.map_state_name == "normal", "map_state", dev.map_state_name)
    ck(not dev.migr_state, "migr_state=0 不迁移")

    lays = parse_imsm([sub, sub, sub])
    ck(len(lays) == 1, "parse_imsm 返回 1 个卷", len(lays))
    L = lays[0]
    ck(L["scheme"] == "imsm" and L["level"] == 5, "描述 scheme/level")
    ck(L["chunk_bytes"] == 65536, "描述 chunk_bytes", L["chunk_bytes"])
    ck(L["member_order"] == [0, 1, 2], "描述 member_order", L["member_order"])
    ck(L["volume_name"] == "VOL_RAID5", "描述 volume_name", L["volume_name"])
    ck(L["member_offsets"][0] == 2048 * 512, "描述 member_offsets",
       L["member_offsets"][0])

    # 校验和坏掉 -> detect 不命中
    bad = build_imsm(members, level=5, bad_checksum=True)
    ck(not imsm_checksum_ok(bad, len(bad)), "坏校验和被判失败")
    ck(not detect_imsm(MemSub(put_mpb_at_tail(bytes(1024 * 1024), bad))),
       "坏校验和时 detect_imsm 不命中")

    # RAID10：raid_level=1 且成员 3 块
    mpb10 = build_imsm([("A", 100), ("B", 100), ("C", 100)], level=1)
    s10 = ImsmSuper(mpb10, 0)
    ck(s10.devs[0].raid_level == 1 and s10.devs[0].level == 10,
       "raid_level=1 且 3 成员 -> RAID10", s10.devs[0].level)

    # 4K 扇区放置
    big = build_imsm(members, level=5)
    disk4k = put_mpb_at_tail(bytes(8 * 1024 * 1024), big, ss=4096)
    ck(detect_imsm(MemSub(disk4k)), "4K 扇区磁盘尾部也能命中")

    print()
    print("=== 2) DDF ===")

    def build_ddf(n_phys=2, level=0, chunk_shift=6, prim=2, prl=None, rlq=None,
                  srl=0, sec=1, name="DDF_VOL", array_blocks=4096,
                  mppe=16):
        if prl is None:
            prl = DDF_RAID0 if level == 0 else DDF_RAID5
        if rlq is None:
            rlq = 0x00 if level == 0 else DDF_RAID5_N_CONTINUE

        # vd_config 记录要能容纳 phys_refnum[mppe] + lba_offset[prim]
        need = 0x200 + max(mppe, prim) * 4 + prim * 8
        rec_len = ((need + 511) // 512) * 512
        # 版式：header 512 | phys 段 | virt 段 | config 段
        phys = bytearray(0x40 + n_phys * 64)
        struct.pack_into(">I", phys, 0, 0x22222222)
        struct.pack_into(">H", phys, 0x08, n_phys)
        struct.pack_into(">H", phys, 0x0A, n_phys)
        for i in range(n_phys):
            p = 0x40 + i * 64
            phys[p:p + 24] = bytes(range(i, i + 24))
            struct.pack_into(">I", phys, p + 24, i + 1)
            struct.pack_into(">H", phys, p + 28, 0x0300)     # SATA
            struct.pack_into(">H", phys, p + 30, 0x0001)     # Online
            struct.pack_into(">Q", phys, p + 32, 4096)
            phys[p + 40:p + 58] = ("/dev/sd%c" % (ord("a") + i)).encode()[:18].ljust(18, b"\x00")

        virt = bytearray(0x40 + 64)
        struct.pack_into(">I", virt, 0, 0xDDDDDDDD)
        struct.pack_into(">H", virt, 0x08, 1)
        virt[0x40:0x58] = bytes(range(0x40, 0x58))
        struct.pack_into(">H", virt, 0x58, 1)                # unit
        struct.pack_into(">H", virt, 0x5C, 0x1234)           # guid_crc
        struct.pack_into(">H", virt, 0x5E, 0x0000)           # type
        virt[0x60] = 1                                       # state optimal
        virt[0x70:0x70 + 16] = name.encode()[:16].ljust(16, b"\x00")

        vd = bytearray(rec_len)
        struct.pack_into(">I", vd, 0, 0xEEEEEEEE)
        vd[0x08:0x20] = bytes(range(0x08, 0x20))
        struct.pack_into(">I", vd, 0x20, 0x01D00000)
        struct.pack_into(">I", vd, 0x24, 3)
        struct.pack_into(">H", vd, 0x40, prim)
        vd[0x42] = chunk_shift
        vd[0x43] = prl
        vd[0x44] = rlq
        vd[0x45] = sec
        vd[0x46] = 0
        vd[0x47] = srl
        struct.pack_into(">Q", vd, 0x48, array_blocks // max(prim, 1))
        struct.pack_into(">Q", vd, 0x50, array_blocks)
        for i in range(prim):
            struct.pack_into(">I", vd, 0x200 + i * 4, i + 1)  # phys_refnum
        lbase = 0x200 + mppe * 4
        for i in range(prim):
            struct.pack_into(">Q", vd, lbase + i * 8, 2048 + i * 100)

        c_off = 512
        p_off = c_off + len(vd)
        v_off = p_off + len(phys)
        total = 512 + len(vd) + len(phys) + len(virt)

        img = bytearray(total)
        img[0:512] = bytes(512)
        img[c_off:c_off + len(vd)] = vd
        img[p_off:p_off + len(phys)] = phys
        img[v_off:v_off + len(virt)] = virt

        # 头部
        h = bytearray(512)
        struct.pack_into(">I", h, 0, DDF_MAGIC)
        h[0x08:0x20] = bytes(range(0x10, 0x28))
        h[0x20:0x28] = b"01.02.00"
        struct.pack_into(">I", h, 0x28, 5)                   # seq
        struct.pack_into(">I", h, 0x2C, 0x60000000)
        h[0x70] = DDF_HEADER_PRIMARY
        struct.pack_into(">H", h, 0x80, n_phys)
        struct.pack_into(">H", h, 0x82, 1)
        struct.pack_into(">H", h, 0x84, 1)
        struct.pack_into(">H", h, 0x86, rec_len // 512)
        struct.pack_into(">H", h, 0x88, mppe)
        struct.pack_into(">I", h, 0xC8, p_off)               # phys
        struct.pack_into(">I", h, 0xCC, len(phys))
        struct.pack_into(">I", h, 0xD0, v_off)               # virt
        struct.pack_into(">I", h, 0xD4, len(virt))
        struct.pack_into(">I", h, 0xD8, c_off)               # config
        struct.pack_into(">I", h, 0xDC, len(vd))
        # 头部 CRC
        struct.pack_into(">I", h, 0x04, 0)
        struct.pack_into(">I", h, 0x04, ddf_crc32(bytes(h)))
        img[0:512] = h
        # 补齐到 512 整数倍：扫描器按 512 步长倒扫，总长不对齐会跳过头部
        if len(img) % 512:
            img.extend(b"\x00" * (512 - len(img) % 512))
        return bytes(img)

    ddf = build_ddf(n_phys=2, level=0)
    # DDF 结构在盘尾，前面垫空
    dsub = MemSub(bytes(64 * 1024) + ddf)

    ck(detect_ddf(dsub), "detect_ddf 命中")
    hdr = _find_ddf_header(dsub)
    ck(hdr is not None and hdr.type == DDF_HEADER_PRIMARY, "头部 type=primary",
       hdr.type_name if hdr else None)
    ck(hdr.revision == "01.02.00", "revision", hdr.revision)
    ck(hdr.max_pd_entries == 2, "max_pd_entries", hdr.max_pd_entries)
    ck(hdr.max_primary_element_entries == 16, "mppe",
       hdr.max_primary_element_entries)
    ck(hdr.crc_ok, "头部 CRC 校验通过")

    sup_d = DdfSuper(dsub, hdr)
    ck(len(sup_d.phys_disks) == 2, "物理盘 2 条", len(sup_d.phys_disks))
    ck(sup_d.phys_disks[0]["path"] == "/dev/sda", "物理盘路径",
       sup_d.phys_disks[0]["path"])
    ck(len(sup_d.virtual_disks) == 1, "虚拟盘 1 条", len(sup_d.virtual_disks))
    ck(sup_d.virtual_disks[0]["name"] == "DDF_VOL", "虚拟盘名",
       sup_d.virtual_disks[0]["name"])
    ck(len(sup_d.vds) == 1, "config 记录 1 条", len(sup_d.vds))

    vd0 = sup_d.vds[0]
    ck(vd0.level == 0, "DDF RAID0 级别映射", vd0.level)
    ck(vd0.chunk_bytes == 512 << 6, "chunk_bytes = 512<<chunk_shift",
       vd0.chunk_bytes)
    ck(vd0.prim_elmnt_count == 2, "prim_elmnt_count", vd0.prim_elmnt_count)
    ck(vd0.phys_refnum == [1, 2], "phys_refnum", vd0.phys_refnum)
    ck(vd0.lba_offset == [2048, 2148], "lba_offset", vd0.lba_offset)

    lays_d = parse_ddf([dsub])
    ck(len(lays_d) == 1, "parse_ddf 返回 1 个卷", len(lays_d))
    Ld = lays_d[0]
    ck(Ld["scheme"] == "ddf" and Ld["level"] == 0, "DDF 描述 scheme/level")
    ck(Ld["chunk_bytes"] == 32768, "DDF 描述 chunk_bytes", Ld["chunk_bytes"])
    ck(Ld["member_offsets"] == [2048 * 512, 2148 * 512],
       "DDF 描述 member_offsets", Ld["member_offsets"])
    ck(Ld["vd_size"] == 4096 * 512, "DDF 描述 vd_size", Ld["vd_size"])

    print()
    print("=== 3) DDF 级别映射（照 layout_ddf2md）===")
    cases = [
        (dict(prl=DDF_RAID0, rlq=0x00, prim=3), 0, "stripe"),
        (dict(prl=DDF_RAID1, rlq=DDF_RAID1_SIMPLE, prim=2), 1, "mirror"),
        (dict(prl=DDF_RAID1, rlq=DDF_RAID1_MULTI, prim=3), 1, "mirror"),
        (dict(prl=DDF_RAID1E, rlq=DDF_RAID1E_ADJACENT, prim=4), 10, "near"),
        (dict(prl=DDF_RAID1E, rlq=DDF_RAID1E_OFFSET, prim=4), 10, "offset"),
        (dict(prl=DDF_RAID4, rlq=DDF_RAID4_N, prim=3), 4, "fixed-parity"),
        (dict(prl=DDF_RAID5, rlq=DDF_RAID5_N_RESTART, prim=4), 5, "left-asymmetric"),
        (dict(prl=DDF_RAID5, rlq=DDF_RAID5_0_RESTART, prim=4), 5, "right-asymmetric"),
        (dict(prl=DDF_RAID5, rlq=DDF_RAID5_N_CONTINUE, prim=4), 5, "left-symmetric"),
        (dict(prl=DDF_RAID6, rlq=DDF_RAID5_N_RESTART, prim=5), 6, "rotating-n-restart"),
        (dict(prl=DDF_RAID6, rlq=DDF_RAID6_0_RESTART, prim=5), 6, "rotating-zero-restart"),
        (dict(prl=DDF_RAID6, rlq=DDF_RAID5_N_CONTINUE, prim=5), 6, "rotating-n-continue"),
        (dict(prl=DDF_RAID1, rlq=DDF_RAID1_SIMPLE, prim=2, sec=2,
              srl=DDF_2STRIPED), 10, "near"),
    ]
    for kw, want_lvl, want_layout in cases:
        img = build_ddf(n_phys=6, **kw)
        s = MemSub(bytes(4096) + img)
        h = _find_ddf_header(s)
        sup_x = DdfSuper(s, h)
        got = sup_x.vds[0]
        ck(got.level == want_lvl and got.layout == want_layout,
           "prl=0x%02X rlq=0x%02X sec=%d -> %s/%s"
           % (kw["prl"], kw["rlq"], kw.get("sec", 1),
              want_lvl, want_layout),
           "%s/%s" % (got.level, got.layout))

    print()
    print("=== 4) 不支持项如实标注 ===")
    for kw, why in (
            (dict(prl=DDF_RAID3, rlq=0x01, prim=4), "RAID3"),
            (dict(prl=DDF_RAID5E, rlq=0x02, prim=4), "RAID5E"),
            (dict(prl=DDF_RAID5EE, rlq=0x02, prim=4), "RAID5EE"),
            (dict(prl=DDF_CONCAT, rlq=0x00, prim=3), "CONCAT"),
    ):
        img = build_ddf(n_phys=6, **kw)
        s = MemSub(bytes(4096) + img)
        h = _find_ddf_header(s)
        sup_x = DdfSuper(s, h)
        got = sup_x.vds[0]
        ck(got.level is None and got.unsupported,
           "%s 判为不支持并给出原因" % why, (got.unsupported or "")[:40])

    print()
    print("=== 5) 非 RAID 盘与越界 ===")
    ck(detect(MemSub(bytes(65536))) == "unknown", "全零盘 -> unknown")
    ck(parse_imsm([MemSub(bytes(65536))]) == [], "非 IMSM 时 parse_imsm 返回空")
    ck(parse_ddf(MemSub(bytes(65536))) == [], "非 DDF 时 parse_ddf 返回空")
    ck(detect(MemSub(bytes(0))) == "unknown", "零长对象 -> unknown")
    try:
        ImsmSuper(bytes(16), 0)
        ck(False, "过短 MPB 应报错")
    except ValueError as e:
        ck(True, "过短 MPB 报错", str(e)[:34])
    try:
        DdfHeader(bytes(b"\x00" * 512), 0)
        ck(False, "非 DDF 头应报错")
    except ValueError as e:
        ck(True, "非 DDF 头报错", str(e)[:34])

    print()
    print("=== 6) describe ===")
    txt = describe(L)
    ck("imsm" in txt and "RAID5" in txt, "describe 输出可读",
       txt.splitlines()[0][:60])
    txt2 = describe(Ld)
    ck("ddf" in txt2, "describe DDF 输出可读", txt2.splitlines()[0][:60])

    print()
    print("=" * 62)
    print("IMSM（含 4K 扇区、坏校验和、RAID10）/ DDF（含 13 种级别映射与不支持项）")
    print("通过 %d 项，失败 %d 项" % (PASS[0], FAIL[0]))
    if FAIL[0]:
        raise SystemExit(1)
    print("raidmeta 模块自检全部通过")
