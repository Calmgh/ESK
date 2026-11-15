# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""revkit.py —— 二进制分析与逆向辅助（自研 PE 解析 + capstone 反汇编）。

纯标准库 + capstone；不依赖 pefile / IDA / x64dbg 图形界面。
命令行即可完成 "字符串定位 -> 交叉引用 -> 校验点识别 -> 字节补丁"
这一整套 2024 美亚杯个人赛 73~79 题类型的静态分析。

对外接口
--------------------------------------------------------------------------
PE(data)                        自研 PE 头 / 节表 / 导入 / 导出 / 资源 / .NET 解析
strings(data, ...)              ASCII + UTF-16LE 字符串提取（可按节过滤）
interesting_strings(pe)         按取证关键词库过滤
disasm(data_or_pe, ...)         capstone 反汇编
find_calls(pe, target_import)   找 call [IAT]（调用某导入函数的地址）
find_branches_near_string(...)  字符串 -> 引用它的 lea/push -> 邻近 CMP/TEST/Jcc
patch_bytes(data, patches)      打补丁（带原字节校验，返回新字节串）
patch_je_to_jmp(pe, addr)       JE/JZ -> JMP
patch_jne_to_nop(pe, addr)      JNE/JNZ -> 90 90
suggest_login_bypass(pe)        登录校验绕过综合建议（可读结论 + 字节偏移）
find_memory_offset_hint(pe)     找 [reg+0xB0B0C] 形式的全局标志位访问
DotnetInfo(pe)                  .NET 元数据：程序集 / 类型 / 方法名 / 用户字符串

命令行
--------------------------------------------------------------------------
    python -m mkit.revkit info     <file.exe>
    python -m mkit.revkit strings  <file.exe> [--all] [--min 6]
    python -m mkit.revkit imports  <file.exe>
    python -m mkit.revkit disasm   <file.exe> [--va 0x140001000] [--count 60]
    python -m mkit.revkit bypass   <file.exe>
    python -m mkit.revkit memhint  <file.exe> [--key 1]
    python -m mkit.revkit strings  <file.exe> --find "Login"

约定
--------------------------------------------------------------------------
* 所有 "addr" 均为 VA（image_base + RVA）；"offset" / "file_off" 为文件偏移。
* 反汇编采用线性扫描（与 x64dbg 的"转到表达式再反汇编"一致），
  不做递归/控制流跟随；对加壳或数据混排的节可能解出错位指令，
  这是线性扫描的固有特性，故 find_* 系列全部输出候选而非唯一结论。
"""

from __future__ import annotations

import datetime
import os
import re
import struct
import sys

try:                                            # capstone 为唯一第三方依赖
    import capstone
    from capstone import x86 as cs_x86
except ImportError:                             # 允许"只解析 PE"的场景
    capstone = None
    cs_x86 = None

try:                                            # 支持包内引用与脚本直跑两种方式
    from . import revkit_help as _help
except ImportError:                             # pragma: no cover
    import revkit_help as _help


__all__ = [
    "PE", "PEError", "strings", "interesting_strings", "disasm", "find_calls",
    "find_branches_near_string", "patch_bytes", "patch_je_to_jmp",
    "patch_jne_to_nop", "suggest_login_bypass", "find_memory_offset_hint",
    "DotnetInfo", "md5_hex", "save_patched",
]


# =========================================================================== #
# 0. 基础常量与安全读取
# =========================================================================== #
PE32_MAGIC = 0x10B
PE32P_MAGIC = 0x20B

MACHINE = {
    0x0000: "UNKNOWN", 0x014C: "i386", 0x0162: "R3000", 0x0166: "R4000",
    0x0168: "R10000", 0x0169: "WCEMIPSV2", 0x0184: "ALPHA", 0x01A2: "SH3",
    0x01A3: "SH3DSP", 0x01A4: "SH3E", 0x01A6: "SH4", 0x01A8: "SH5",
    0x01C0: "ARM", 0x01C2: "THUMB", 0x01C4: "ARMNT", 0x01D3: "AM33",
    0x01F0: "POWERPC", 0x01F1: "POWERPCFP", 0x0200: "IA64",
    0x0266: "MIPS16", 0x0284: "ALPHA64", 0x0366: "MIPSFPU",
    0x0466: "MIPSFPU16", 0x0520: "TRICORE", 0x0EBC: "EBC", 0x8664: "AMD64",
    0x9041: "M32R", 0xAA64: "ARM64", 0xC0EE: "CEE",
}

SUBSYSTEM = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
    5: "OS2_CUI", 7: "POSIX_CUI", 8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

# 节区特性
SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040
SCN_CNT_UNINITIALIZED_DATA = 0x00000080
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

# DLL 特性
DLLCHAR = {
    0x0020: "HIGH_ENTROPY_VA", 0x0040: "DYNAMIC_BASE",
    0x0080: "FORCE_INTEGRITY", 0x0100: "NX_COMPAT", 0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH", 0x0800: "NO_BIND", 0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER", 0x4000: "GUARD_CF", 0x8000: "TERMINAL_SERVER_AWARE",
}

# 数据目录索引
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_SECURITY = 0, 1, 2, 3, 4
DIR_BASERELOC, DIR_DEBUG, DIR_COPYRIGHT = 5, 6, 7
DIR_TLS, DIR_LOADCONFIG, DIR_BOUNDIMPORT, DIR_IAT = 9, 10, 11, 12
DIR_DELAYIMPORT, DIR_CLR = 13, 14


class PEError(Exception):
    """PE 结构非法/越界。"""


def _u8(b, o):
    return b[o] if 0 <= o < len(b) else 0


def _u16(b, o):
    if o < 0 or o + 2 > len(b):
        return 0
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    if o < 0 or o + 4 > len(b):
        return 0
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    if o < 0 or o + 8 > len(b):
        return 0
    return struct.unpack_from("<Q", b, o)[0]


def _i32(b, o):
    if o < 0 or o + 4 > len(b):
        return 0
    return struct.unpack_from("<i", b, o)[0]


def md5_hex(data):
    import hashlib
    return hashlib.md5(data).hexdigest()


def _cstr(b, off, limit=512):
    """从 off 读以 NUL 结尾的 ASCIIZ 字符串。"""
    if off is None or off < 0 or off >= len(b):
        return ""
    end = b.find(b"\x00", off, min(len(b), off + limit))
    if end < 0:
        end = min(len(b), off + limit)
    return b[off:end].decode("latin-1", "replace")


def _wstr(b, off, limit=512):
    """从 off 读以 \\x00\\x00 结尾的 UTF-16LE 字符串。"""
    if off is None or off < 0 or off >= len(b):
        return ""
    out = []
    i = off
    stop = min(len(b), off + limit * 2)
    while i + 1 < stop:
        c = b[i] | (b[i + 1] << 8)
        if c == 0:
            break
        out.append(chr(c))
        i += 2
    return "".join(out)


# =========================================================================== #
# 1. 自研 PE 解析
# =========================================================================== #
class PE:
    """自研 PE 解析器（不依赖 pefile）。

    pe = PE(open("a.exe", "rb").read())
    pe.machine / pe.is64 / pe.image_base / pe.entry_point["va"]
    pe.sections[0]["name"] / pe.imports / pe.exports / pe.resources

    所有解析失败都退化为空值而非抛异常（对截断/加壳样本更友好），
    只有 "连 MZ / PE 签名都不对" 才抛 PEError。
    """

    def __init__(self, data: bytes):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise PEError("PE() 需要 bytes")
        self.data = bytes(data)
        self.path = None
        self.size = len(self.data)
        self.sections = []
        self.directories = []
        self.imports = {}          # {dll: [func, ...]}
        self.import_details = []   # [{dll, func, ordinal, iat_va, hint}]
        self.iat_map = {}          # {iat_va: (dll, func)}  供 find_calls 用
        self.exports = []
        self.resources = []
        self._parse()

    # ---------------------------- 解析主流程 ---------------------------- #
    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PEError("不是 MZ 可执行文件")
        self.dos_magic = d[:2].decode("latin-1")
        e_lfanew = _u32(d, 0x3C)
        if e_lfanew <= 0 or e_lfanew + 24 > len(d):
            raise PEError("e_lfanew 越界: 0x%X" % e_lfanew)
        if d[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("缺少 PE\\0\\0 签名 @ 0x%X" % e_lfanew)
        self.e_lfanew = e_lfanew
        coff = e_lfanew + 4
        self.machine_raw = _u16(d, coff)
        self.machine = MACHINE.get(self.machine_raw, "0x%04X" % self.machine_raw)
        self.num_sections = _u16(d, coff + 2)
        self.timestamp = _u32(d, coff + 4)
        self.ptr_symbol = _u32(d, coff + 8)
        self.num_symbols = _u32(d, coff + 12)
        self.size_opt_header = _u16(d, coff + 16)
        self.characteristics = _u16(d, coff + 18)

        opt = coff + 20
        self.opt_offset = opt
        self.magic = _u16(d, opt)
        if self.magic not in (PE32_MAGIC, PE32P_MAGIC):
            raise PEError("未知 OptionalHeader magic: 0x%04X" % self.magic)
        self.is64 = self.magic == PE32P_MAGIC
        self.is_pe32plus = self.is64

        self.linker = "%d.%d" % (_u8(d, opt + 2), _u8(d, opt + 3))
        self.size_code = _u32(d, opt + 4)
        self.size_init_data = _u32(d, opt + 8)
        self.size_uninit_data = _u32(d, opt + 12)
        self.entry_rva = _u32(d, opt + 16)
        self.base_of_code = _u32(d, opt + 20)
        if self.is64:
            self.image_base = _u64(d, opt + 24)
            self.base_of_data = 0
        else:
            self.base_of_data = _u32(d, opt + 24)
            self.image_base = _u32(d, opt + 28)
        self.section_alignment = _u32(d, opt + 32)
        self.file_alignment = _u32(d, opt + 36)
        self.os_version = "%d.%d" % (_u16(d, opt + 40), _u16(d, opt + 42))
        self.image_version = "%d.%d" % (_u16(d, opt + 44), _u16(d, opt + 46))
        self.subsystem_version = "%d.%d" % (_u16(d, opt + 48), _u16(d, opt + 50))
        self.size_image = _u32(d, opt + 56)
        self.size_headers = _u32(d, opt + 60)
        self.checksum = _u32(d, opt + 64)
        self.subsystem_raw = _u16(d, opt + 68)
        self.subsystem = SUBSYSTEM.get(self.subsystem_raw, str(self.subsystem_raw))
        self.dll_chars = _u16(d, opt + 70)

        if self.is64:
            self.stack_reserve = _u64(d, opt + 72)
            self.stack_commit = _u64(d, opt + 80)
            self.heap_reserve = _u64(d, opt + 88)
            self.heap_commit = _u64(d, opt + 96)
            self.loader_flags = _u32(d, opt + 104)
            self.num_rva = _u32(d, opt + 108)
            ddir = opt + 112
        else:
            self.stack_reserve = _u32(d, opt + 72)
            self.stack_commit = _u32(d, opt + 76)
            self.heap_reserve = _u32(d, opt + 80)
            self.heap_commit = _u32(d, opt + 84)
            self.loader_flags = _u32(d, opt + 88)
            self.num_rva = _u32(d, opt + 92)
            ddir = opt + 96
        self.data_dir_offset = ddir

        n = min(self.num_rva, 16)
        for i in range(n):
            self.directories.append({
                "index": i,
                "rva": _u32(d, ddir + i * 8),
                "size": _u32(d, ddir + i * 8 + 4),
            })
        while len(self.directories) < 16:            # 便于 self.dir(i) 无脑索引
            self.directories.append({"index": len(self.directories),
                                     "rva": 0, "size": 0})

        sh = opt + self.size_opt_header
        for i in range(min(self.num_sections, 96)):
            base = sh + i * 40
            if base + 40 > len(d):
                break
            name = d[base:base + 8].split(b"\x00", 1)[0].decode("latin-1", "replace")
            vsize = _u32(d, base + 8)
            va = _u32(d, base + 12)
            raw_size = _u32(d, base + 16)
            raw_off = _u32(d, base + 20)
            self.sections.append({
                "index": i,
                "name": name,
                "va": va,
                "vsize": vsize,
                "raw_off": raw_off,
                "raw_size": raw_size,
                "chars": _u32(d, base + 36),
                "characteristics": _u32(d, base + 36),
                "executable": bool(_u32(d, base + 36) & SCN_MEM_EXECUTE),
                "writable": bool(_u32(d, base + 36) & SCN_MEM_WRITE),
            })

        # 入口点（VA + 文件偏移）
        self.entry_va = self.image_base + self.entry_rva
        self.entry_off = self.rva_to_off(self.entry_rva)
        self.entry_point = {
            "rva": self.entry_rva,
            "va": self.entry_va,
            "file_off": self.entry_off,
        }

        self.overlay_offset = self._calc_overlay()
        self._parse_imports()
        self._parse_exports()
        self._parse_resources()
        clr = self.dir(DIR_CLR)
        self.clr_rva = clr["rva"]
        self.is_dotnet = bool(self.dir(DIR_CLR)["rva"])

    # ------------------------------ 地址换算 ---------------------------- #
    def rva_to_off(self, rva):
        """RVA -> 文件偏移；不在任何节内则返回 None。"""
        if rva is None or rva < 0:
            return None
        if rva < self.size_headers:
            return rva if rva < len(self.data) else None
        for s in self.sections:
            span = max(s["vsize"], s["raw_size"])
            if s["va"] <= rva < s["va"] + span:
                off = rva - s["va"] + s["raw_off"]
                return off if 0 <= off < len(self.data) else None
        return None

    def off_to_rva(self, off):
        """文件偏移 -> RVA；落在头部则原样返回 None 之外的值。"""
        if off is None or off < 0:
            return None
        if off < self.size_headers:
            return off
        for s in self.sections:
            if s["raw_off"] <= off < s["raw_off"] + s["raw_size"]:
                return off - s["raw_off"] + s["va"]
        return None

    def va_to_off(self, va):
        return self.rva_to_off(va - self.image_base if va >= self.image_base else va)

    def off_to_va(self, off):
        rva = self.off_to_rva(off)
        return None if rva is None else self.image_base + rva

    def dir(self, index):
        """取数据目录项 {index, rva, size}。"""
        if 0 <= index < len(self.directories):
            return self.directories[index]
        return {"index": index, "rva": 0, "size": 0}

    def section_of(self, rva):
        for s in self.sections:
            span = max(s["vsize"], s["raw_size"])
            if s["va"] <= rva < s["va"] + span:
                return s
        return None

    def section_data(self, sec):
        """取某节的原始字节。"""
        off, size = sec["raw_off"], sec["raw_size"]
        return self.data[off:off + size]

    def exec_sections(self):
        return [s for s in self.sections if s["executable"]]

    def _calc_overlay(self):
        end = self.size_headers
        for s in self.sections:
            e = s["raw_off"] + s["raw_size"]
            if e > end:
                end = e
        return end if end < len(self.data) else None

    # ------------------------------- 导入 ------------------------------- #
    def _parse_imports(self):
        d = self.data
        dd = self.dir(DIR_IMPORT)
        if not dd["rva"]:
            return
        off = self.rva_to_off(dd["rva"])
        if off is None:
            return
        ptr = 8 if self.is64 else 4
        ord_flag = (1 << 63) if self.is64 else (1 << 31)
        for i in range(4096):
            base = off + i * 20
            if base + 20 > len(d):
                break
            oft = _u32(d, base)
            name_rva = _u32(d, base + 12)
            ft = _u32(d, base + 16)
            if not (oft or name_rva or ft):
                break
            dll = _cstr(d, self.rva_to_off(name_rva))
            if not dll:
                continue
            dll = dll.strip()
            self.imports.setdefault(dll, [])
            thunk_rva = oft or ft
            toff = self.rva_to_off(thunk_rva)
            if toff is None:
                continue
            for j in range(65536):
                tb = toff + j * ptr
                if tb + ptr > len(d):
                    break
                val = _u64(d, tb) if self.is64 else _u32(d, tb)
                if val == 0:
                    break
                if val & ord_flag:
                    func = "Ordinal_%d" % (val & 0xFFFF)
                    ordinal = val & 0xFFFF
                    hint = ""
                else:
                    hoff = self.rva_to_off(val & 0x7FFFFFFF)
                    ordinal = None
                    if hoff is None or hoff + 2 > len(d):
                        func, hint = "", ""
                    else:
                        hint = _u16(d, hoff)
                        func = _cstr(d, hoff + 2)
                self.imports[dll].append(func)
                iat_va = self.image_base + ft + j * ptr if ft else None
                rec = {"dll": dll, "func": func, "ordinal": ordinal,
                       "iat_va": iat_va, "iat_slot": j, "hint": hint}
                self.import_details.append(rec)
                if iat_va:
                    self.iat_map[iat_va] = (dll, func)

    # ------------------------------- 导出 ------------------------------- #
    def _parse_exports(self):
        d = self.data
        dd = self.dir(DIR_EXPORT)
        if not dd["rva"]:
            return
        off = self.rva_to_off(dd["rva"])
        if off is None or off + 40 > len(d):
            return
        self.export_dll_name = _cstr(d, self.rva_to_off(_u32(d, off + 12)))
        base = _u32(d, off + 16)
        n_funcs = _u32(d, off + 20)
        n_names = _u32(d, off + 24)
        a_funcs = self.rva_to_off(_u32(d, off + 28))
        a_names = self.rva_to_off(_u32(d, off + 32))
        a_ords = self.rva_to_off(_u32(d, off + 36))
        if a_funcs is None:
            return
        for i in range(min(n_names, 65536)):
            if a_names is None or a_ords is None:
                break
            noff = self.rva_to_off(_u32(d, a_names + i * 4))
            idx = _u16(d, a_ords + i * 2) if a_ords else 0
            if idx >= n_funcs:
                continue
            frva = _u32(d, a_funcs + idx * 4)
            fwd = None
            if dd["rva"] <= frva < dd["rva"] + dd["size"]:
                fwd = _cstr(d, self.rva_to_off(frva))
            self.exports.append({
                "name": _cstr(d, noff),
                "ordinal": base + idx,
                "rva": frva,
                "va": self.image_base + frva,
                "forwarder": fwd,
            })

    # ------------------------------- 资源 ------------------------------- #
    def _parse_resources(self):
        d = self.data
        dd = self.dir(DIR_RESOURCE)
        if not dd["rva"]:
            return
        root_off = self.rva_to_off(dd["rva"])
        if root_off is None:
            return
        out = []

        def walk(off, level, path):
            if level > 3 or off is None or off + 16 > len(d) or len(out) > 4096:
                return
            n_named = _u16(d, off + 12)
            n_id = _u16(d, off + 14)
            total = n_named + n_id
            for i in range(min(total, 512)):
                e = off + 16 + i * 8
                if e + 8 > len(d):
                    return
                name_field = _u32(d, e)
                data_field = _u32(d, e + 4)
                if name_field & 0x80000000:              # 名字是 UTF-16 串
                    so = root_off + (name_field & 0x7FFFFFFF)
                    s_len = _u16(d, so)
                    label = _wstr(d, so + 2, min(s_len, 256))
                else:
                    label = "#%d" % name_field
                if data_field & 0x80000000:              # 子目录
                    walk(root_off + (data_field & 0x7FFFFFFF), level + 1,
                         path + [label])
                else:
                    de = root_off + data_field
                    if de + 16 > len(d):
                        continue
                    drva = _u32(d, de)
                    dsize = _u32(d, de + 4)
                    out.append({
                        "type": path[0] if path else "#0",
                        "name": path[1] if len(path) > 1 else "#0",
                        "lang": path[2] if len(path) > 2 else label,
                        "path": "/".join(path + [label]) if path else label,
                        "rva": drva,
                        "va": self.image_base + drva,
                        "offset": self.rva_to_off(drva),
                        "size": dsize,
                        "codepage": _u32(d, de + 8),
                        "reserved": _u32(d, de + 12),
                    })

        walk(root_off, 0, [])
        self.resources = out

    # ------------------------------- 展示 ------------------------------- #
    def dll_char_names(self):
        return [n for bit, n in sorted(DLLCHAR.items()) if self.dll_chars & bit]

    def timestamp_dt(self):
        """PE 时间戳转 UTC datetime（不是本地时间，做题时注意 +8 时区换算）。"""
        try:
            return datetime.datetime.fromtimestamp(self.timestamp,
                                                   datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    def summary(self):
        """返回一行行可打印的解析摘要（list[str]）。"""
        dt = self.timestamp_dt()
        lines = [
            "文件大小    : %d (0x%X)" % (self.size, self.size),
            "MD5         : %s" % md5_hex(self.data),
            "机器类型    : %s (0x%04X)  位数=%s" % (
                self.machine, self.machine_raw, "64 (PE32+)" if self.is64 else "32 (PE32)"),
            "语言/连接器 : %s" % self.linker,
            "时间戳      : 0x%08X  %s" % (
                self.timestamp, dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "n/a"),
            "ImageBase   : 0x%X" % self.image_base,
            "入口点      : RVA=0x%X VA=0x%X 文件偏移=0x%X" % (
                self.entry_rva, self.entry_va,
                self.entry_off if self.entry_off is not None else 0xFFFFFFFF),
            "子系统      : %s (0x%X)" % (self.subsystem, self.subsystem_raw),
            "DLL特性     : 0x%04X %s" % (self.dll_chars, ",".join(self.dll_char_names())),
            ".NET        : %s" % ("是 (CLR 头 @RVA 0x%X)" % self.clr_rva if self.is_dotnet else "否"),
            "节数量      : %d" % len(self.sections),
        ]
        for s in self.sections:
            lines.append(
                "  节 %-8s VA=0x%08X VSize=0x%06X RawOff=0x%06X RawSize=0x%06X Chars=0x%08X%s%s"
                % (s["name"] or "<noname>", s["va"], s["vsize"], s["raw_off"],
                   s["raw_size"], s["chars"],
                   " E" if s["executable"] else "", " W" if s["writable"] else ""))
        lines.append("导入 DLL 数 : %d  函数总数: %d" % (
            len(self.imports), len(self.import_details)))
        for dll, funcs in list(self.imports.items())[:40]:
            lines.append("   %-28s %d 个" % (dll, len(funcs)))
        if len(self.imports) > 40:
            lines.append("   ...(省略 %d 个 DLL)" % (len(self.imports) - 40))
        lines.append("导出函数数  : %d" % len(self.exports))
        lines.append("资源条目数  : %d" % len(self.resources))
        if self.overlay_offset is not None:
            lines.append("覆盖数据    : 文件偏移 0x%X 起 %d 字节" % (
                self.overlay_offset, self.size - self.overlay_offset))
        return lines


# =========================================================================== #
# 2. 字符串提取
# =========================================================================== #
_ASCII_RX = re.compile(rb"[\x20-\x7e]{%d,}")
_UTF16_RX = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")


def strings(data, min_len=4, encoding="both", unicode=True,
            pe=None, section=None, limit=None):
    """提取 ASCII / UTF-16LE 字符串。

    data     : bytes，或直接传 PE（自动取 pe.data）
    min_len  : 最短长度
    encoding : "ascii" | "utf16" | "both"
    unicode  : False 时即使 encoding="both" 也不扫 UTF-16
    pe       : 传入 PE 对象则在结果里附带 va
    section  : 只扫某节（节名 ".text" / 索引 0 / 节 dict 均可）
    limit    : 最多返回条数（None = 全部）

    返回 [{value, offset, va(可选), encoding, section(可选)}]，按 offset 升序。
    """
    if isinstance(data, PE):
        pe = data
        data = pe.data
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("strings() 需要 bytes 或 PE")
    data = bytes(data)

    want_ascii = encoding in ("ascii", "both", "a")
    want_utf16 = encoding in ("utf16", "utf-16", "unicode", "both") and bool(unicode)

    lo, hi, sec_name = 0, len(data), None
    if section is not None:
        if pe is None:
            raise ValueError("按节过滤需要传 pe=PE(...)")
        sec = _pick_section(pe, section)
        if sec is None:
            return []
        lo = sec["raw_off"]
        hi = min(len(data), sec["raw_off"] + sec["raw_size"])
        sec_name = sec["name"]

    out = []
    if want_ascii:
        rx = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, int(min_len)))
        for m in rx.finditer(data, lo, hi):
            off = m.start()
            out.append({
                "value": m.group().decode("latin-1"),
                "offset": off,
                "encoding": "ascii",
                "va": pe.off_to_va(off) if pe is not None else None,
                "section": sec_name,
            })
    if want_utf16:
        rx = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % max(1, int(min_len)))
        for m in rx.finditer(data, lo, hi):
            off = m.start()
            raw = m.group()
            out.append({
                "value": raw.decode("utf-16-le", "replace"),
                "offset": off,
                "encoding": "utf-16le",
                "va": pe.off_to_va(off) if pe is not None else None,
                "section": sec_name,
            })
    out.sort(key=lambda x: (x["offset"], x["encoding"]))
    if limit is not None:
        out = out[:int(limit)]
    return out


def _pick_section(pe, section):
    if isinstance(section, dict):
        return section
    if isinstance(section, int):
        return pe.sections[section] if 0 <= section < len(pe.sections) else None
    name = str(section)
    for s in pe.sections:
        if s["name"].lower() == name.lower():
            return s
    for s in pe.sections:                       # 允许 ".text" 匹配 "text"
        if s["name"].lower().lstrip(".") == name.lower().lstrip("."):
            return s
    return None


def interesting_strings(pe, patterns=None, min_len=4, max_results=None,
                        sections=None, ignore_case=True):
    """按关键词库过滤出与"登录/授权/加解密"相关的字符串。

    patterns  : None = 用 revkit_help.DEFAULT_PATTERNS；也可给 list[str] 或编译好的正则
    sections  : 只在这些节里找（None = 全部）
    返回 [{value, offset, va, encoding, category, hit}]，按"相关度"排序。
    """
    if patterns is None:
        rx = _help.build_regex(_help.DEFAULT_PATTERNS, ignore_case)
        pat_list = list(_help.DEFAULT_PATTERNS)
    elif hasattr(patterns, "search"):
        rx = patterns
        pat_list = [p.pattern if hasattr(p, "pattern") else "" for p in [patterns]]
    else:
        pat_list = [p for p in patterns]
        rx = _help.build_regex(pat_list, ignore_case)
    if rx is None:
        return []

    candidates = []
    if sections is None:
        candidates = strings(pe.data, min_len=min_len, pe=pe)
    else:
        for sec in sections:
            candidates.extend(strings(pe.data, min_len=min_len, pe=pe, section=sec))

    seen = set()
    out = []
    for s in candidates:
        key = (s["offset"], s["encoding"])
        if key in seen:
            continue
        seen.add(key)
        val = s["value"]
        m = rx.search(val.encode("latin-1", "replace"))
        if not m:
            # 中文关键词走 UTF-8/UTF-16 路径再试一次
            if not any(ord(ch) > 0x7F for ch in val):
                continue
            if not _pattern_hits_unicode(val, pat_list):
                continue
            hit = _first_hit_unicode(val, pat_list)
        else:
            hit = m.group().decode("latin-1", "replace")
        out.append({
            "value": val,
            "offset": s["offset"],
            "va": s.get("va"),
            "encoding": s["encoding"],
            "section": s.get("section"),
            "hit": hit,
            "category": _help.category_of(hit),
            "result": _help.classify_result(val),
        })
    out.sort(key=lambda x: (_help.category_of(x["hit"]) == "other",
                            x["encoding"] != "ascii", x["offset"]))
    return out[:max_results] if max_results else out


def _pattern_hits_unicode(val, pats):
    low = val.lower()
    return any(p.lower() in low for p in pats if p)


def _first_hit_unicode(val, pats):
    low = val.lower()
    for p in pats:
        if p.lower() in low:
            return p
    return ""


# =========================================================================== #
# 3. 反汇编（capstone）
# =========================================================================== #
_ARCH = {
    "x64": (lambda: capstone.CS_ARCH_X86, lambda: capstone.CS_MODE_64),
    "x86": (lambda: capstone.CS_ARCH_X86, lambda: capstone.CS_MODE_32),
    "amd64": (lambda: capstone.CS_ARCH_X86, lambda: capstone.CS_MODE_64),
    "i386": (lambda: capstone.CS_ARCH_X86, lambda: capstone.CS_MODE_32),
    "arm64": (lambda: capstone.CS_ARCH_ARM64, lambda: capstone.CS_MODE_ARM),
    "aarch64": (lambda: capstone.CS_ARCH_ARM64, lambda: capstone.CS_MODE_ARM),
    "arm": (lambda: capstone.CS_ARCH_ARM, lambda: capstone.CS_MODE_ARM),
}


def _make_md(arch="x64"):
    if capstone is None:
        raise RuntimeError("未安装 capstone：pip install capstone")
    key = str(arch).lower()
    if key not in _ARCH:
        raise ValueError("不支持的 arch: %s（可用 %s）" % (arch, "/".join(sorted(_ARCH))))
    a, m = _ARCH[key]
    md = capstone.Cs(a(), m())
    md.detail = True
    return md


def _insn_dict(insn, va=None):
    return {
        "addr": insn.address,
        "bytes": bytes(insn.bytes).hex(),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "va": insn.address if va is None else va,
        "size": insn.size,
        "text": "%s %s" % (insn.mnemonic, insn.op_str),
    }


def disasm(data_or_pe, offset=None, rva=None, count=80, arch="x64",
           va=None, base_va=0, detail=False, stop_at_ret=False):
    """capstone 反汇编。

    data_or_pe : bytes 或 PE
    offset     : 起始文件偏移（PE 模式）
    rva        : 起始 RVA（PE 模式，优先于 offset）
    count      : 最多解多少条
    va         : 直接指定起始 VA（PE 模式下可不给，默认入口点）
    base_va    : 裸字节模式下的基址（默认 0）
    detail     : True 时附带操作数解析（供 find_memory_offset_hint 用）
    stop_at_ret: 遇到 ret / 无条件 jmp 即停（默认不停，保持线性扫描）

    返回 [{addr, bytes, mnemonic, op_str, va, size, text}]
    """
    md = _make_md(arch)
    if isinstance(data_or_pe, PE):
        pe = data_or_pe
        data = pe.data
        if va is not None:
            start_rva = va - pe.image_base
        elif rva is not None:
            start_rva = rva
        elif offset is not None:
            start_rva = pe.off_to_rva(offset)
            if start_rva is None:
                return []
        else:
            start_rva = pe.entry_rva
        start_off = pe.rva_to_off(start_rva)
        if start_off is None:
            return []
        start_addr = pe.image_base + start_rva
        chunk = data[start_off:start_off + max(16, count * 16)]
    else:
        data = bytes(data_or_pe)
        if offset is None:
            offset = 0
        start_off = int(offset)
        start_addr = va if va is not None else int(base_va)
        chunk = data[start_off:start_off + max(16, count * 16)]

    out = []
    for insn in md.disasm(chunk, start_addr):
        d = _insn_dict(insn)
        if detail:
            d["insn"] = insn
            d["operands"] = _operand_info(insn)
        out.append(d)
        if len(out) >= count:
            break
        if stop_at_ret and insn.mnemonic in ("ret", "retn", "jmp"):
            break
    return out


def _operand_info(insn):
    """把 capstone 操作数转成可序列化的 dict 列表。"""
    info = []
    if cs_x86 is None:
        return info
    for op in getattr(insn, "operands", []):
        if op.type == cs_x86.X86_OP_REG:
            info.append({"type": "reg", "reg": insn.reg_name(op.reg)})
        elif op.type == cs_x86.X86_OP_IMM:
            info.append({"type": "imm", "imm": op.imm,
                         "imm_hex": "0x%X" % (op.imm & ((1 << 64) - 1))})
        elif op.type == cs_x86.X86_OP_MEM:
            m = op.mem
            info.append({
                "type": "mem",
                "segment": insn.reg_name(m.segment) if m.segment else None,
                "base": insn.reg_name(m.base) if m.base else None,
                "index": insn.reg_name(m.index) if m.index else None,
                "scale": m.scale,
                "disp": m.disp,
                "disp_hex": "0x%X" % (m.disp & ((1 << 64) - 1)),
                "size": op.size,
            })
        else:
            info.append({"type": "other", "raw_type": op.type})
    return info


def _iter_insns(pe, sections=None, max_bytes=8 << 20, arch=None):
    """线性扫描节区，逐条产出 (insn, section)。"""
    md = _make_md(arch or ("x64" if pe.is64 else "x86"))
    secs = sections if sections is not None else pe.exec_sections()
    if not isinstance(secs, list):
        secs = [secs]
    budget = max_bytes
    for sec in secs:
        blob = pe.section_data(sec)
        if not blob:
            continue
        if len(blob) > budget:
            blob = blob[:budget]
        budget -= len(blob)
        base = pe.image_base + sec["va"]
        for insn in md.disasm(blob, base):
            yield insn, sec
        if budget <= 0:
            return


# =========================================================================== #
# 4. 交叉引用：call [IAT]
# =========================================================================== #
def find_calls(pe, target_import, sections=None):
    """找调用某导入函数的位置（call qword ptr [IAT]）。

    target_import : "VirtualAlloc" / "kernel32.dll!VirtualAlloc" / 大小写不敏感子串
    返回 [{addr, va, file_off, insn, target_va, dll, func, bytes}]
    """
    if not isinstance(pe, PE):
        raise TypeError("find_calls 需要 PE")
    want = str(target_import).lower()
    dll_filter, func_filter = None, want
    if "!" in want:
        dll_filter, func_filter = want.split("!", 1)

    out = []
    for insn, sec in _iter_insns(pe, sections):
        if insn.mnemonic not in ("call", "jmp"):
            continue
        ops = getattr(insn, "operands", [])
        if not ops:
            continue
        op = ops[0]
        if op.type != cs_x86.X86_OP_MEM:
            continue
        target = _mem_target_va(insn, op)
        if target is None:
            continue
        slot = None
        for cand in (target, target & 0xFFFFFFFF):
            if cand in pe.iat_map:
                slot = cand
                break
        if slot is None:
            continue
        dll, func = pe.iat_map[slot]
        if func_filter and func_filter not in func.lower():
            continue
        if dll_filter and dll_filter not in dll.lower():
            continue
        out.append({
            "addr": insn.address,
            "va": insn.address,
            "file_off": pe.va_to_off(insn.address),
            "insn": "%s %s" % (insn.mnemonic, insn.op_str),
            "target_va": slot,
            "dll": dll,
            "func": func,
            "bytes": bytes(insn.bytes).hex(),
        })
    return out


def _mem_target_va(insn, op):
    """把 call/jmp 的内存操作数换算成"被读取的那个地址"。"""
    m = op.mem
    base_name = insn.reg_name(m.base) if m.base else None
    if base_name in ("rip", "eip"):
        return insn.address + insn.size + m.disp
    if m.base == 0 and m.index == 0:
        return m.disp & ((1 << 64) - 1)
    return None


# =========================================================================== #
# 5. 字符串 -> 引用 -> 分支
# =========================================================================== #
_CMP_MNEM = {"cmp", "test", "bt"}
_JCC_MNEM = set(_help.JCC)


def _lower_data(pe):
    """整文件小写副本（缓存），交叉引用检索用。"""
    low = getattr(pe, "_lower_cache", None)
    if low is None:
        low = pe.data.lower()
        pe._lower_cache = low
    return low


def _find_string_occurrences(pe, needle, ignore_case=True):
    """在文件里找 needle 的 ASCII / UTF-16LE 出现，返回 [{offset, va, text, encoding}]。"""
    d = pe.data
    variants = []
    enc = "latin-1" if all(ord(c) < 256 for c in str(needle)) else "utf-8"
    try:
        raw = str(needle).encode(enc)
    except UnicodeEncodeError:
        raw = str(needle).encode("utf-8")
    if raw:
        variants.append((raw, "ascii"))
        variants.append(("".join(c + "\x00" for c in raw.decode("latin-1"))
                         .encode("latin-1"), "utf-16le"))
    hits = []
    seen = set()
    hay = _lower_data(pe) if ignore_case else d
    for pat, kind in variants:
        if not pat:
            continue
        ndl = pat.lower() if ignore_case else pat
        start = 0
        while True:
            idx = hay.find(ndl, start)
            if idx < 0:
                break
            start = idx + 1
            # 回退到字符串起点
            if kind == "ascii":
                s = idx
                while s > 0 and 0x20 <= d[s - 1] <= 0x7e:
                    s -= 1
                e = idx + len(pat)
                while e < len(d) and 0x20 <= d[e] <= 0x7e:
                    e += 1
                text = d[s:e].decode("latin-1", "replace")
            else:
                s = idx
                while s >= 2 and d[s - 2] != 0 and 0x20 <= d[s - 2] <= 0x7e:
                    s -= 2
                e = idx + len(pat)
                while e + 1 < len(d) and d[e + 1] == 0 and 0x20 <= d[e] <= 0x7e:
                    e += 2
                text = d[s:e].decode("utf-16-le", "replace")
            if (s, kind) in seen:
                continue
            seen.add((s, kind))
            hits.append({
                "offset": s,
                "va": pe.off_to_va(s),
                "text": text,
                "encoding": kind,
                "section": (pe.section_of(pe.off_to_rva(s)) or {}).get("name"),
            })
    hits.sort(key=lambda x: x["offset"])
    return hits


def build_ref_index(pe, sections=None, force=False):
    """一次扫描所有可执行节，建 {目标VA: [引用它的指令]} 索引（缓存在 PE 上）。

    索引的是 lea/mov/push/call/cmp 里出现的地址常量，包括 rip 相对寻址。
    没有索引时，每查一条字符串都要重扫整节；cmd.exe 那种 200KB 的 .text
    上跑 40 条字符串会慢到十几秒，建立索引后是一次扫描。
    """
    if sections is None and not force:
        idx = getattr(pe, "_ref_index", None)
        if idx is not None:
            return idx
    index = {}

    def add(target, rec):
        if target is None:
            return
        index.setdefault(target, []).append(rec)

    for insn, sec in _iter_insns(pe, sections):
        if insn.mnemonic not in _help.REF_MNEMONICS:
            continue
        base_rec = {
            "addr": insn.address,
            "va": insn.address,
            "file_off": pe.va_to_off(insn.address),
            "insn": "%s %s" % (insn.mnemonic, insn.op_str),
            "size": insn.size,
            "section": sec["name"],
        }
        for op in getattr(insn, "operands", []):
            if op.type == cs_x86.X86_OP_MEM:
                m = op.mem
                base_name = insn.reg_name(m.base) if m.base else None
                if base_name in ("rip", "eip"):
                    add(insn.address + insn.size + m.disp, dict(base_rec))
                elif m.base == 0 and m.index == 0:
                    if pe.is64:
                        add(m.disp & ((1 << 64) - 1), dict(base_rec))
                    else:
                        add(m.disp & 0xFFFFFFFF, dict(base_rec))
            elif op.type == cs_x86.X86_OP_IMM:
                v = op.imm & ((1 << 64) - 1)
                add(v, dict(base_rec))
                if not pe.is64 and (v & 0xFFFFFFFF) != v:
                    add(v & 0xFFFFFFFF, dict(base_rec))
    if sections is None:
        pe._ref_index = index
    return index


def _refs_to_va(pe, target_va, sections=None, index=None):
    """找引用 target_va 的指令（lea/mov/push/call 的 rip 相对或绝对形式）。"""
    if target_va is None:
        return []
    if index is None:
        index = build_ref_index(pe, sections)
    return list(index.get(target_va, []))


def find_branches_near_string(pe, needle, window=0x200, ignore_case=True,
                              sections=None):
    """字符串 -> 引用它的 lea/push -> 邻近的 CMP/TEST/Jcc。

    needle : 字符串片段（如 "Login" / "password"）
    window : 引用点之后扫描的字节数（另向前回看 window//4，兼容 cmp 在引用之前）

    返回 dict：
      {string, string_off, string_va, encoding,
       refs:[{addr, insn, ...}],
       branches:[{addr, insn, target, cond, side, file_off}],
       candidates: <branches 长度>,
       ok: bool}
    """
    if not isinstance(pe, PE):
        raise TypeError("find_branches_near_string 需要 PE")
    index = build_ref_index(pe, sections)
    occ = _find_string_occurrences(pe, needle, ignore_case)
    best = None
    for o in occ:
        refs = _refs_to_va(pe, o["va"], sections, index)
        branches = []
        for r in refs:
            branches.extend(_branches_around(pe, r["addr"], window, sections))
        payload = {
            "string": o["text"],
            "string_off": o["offset"],
            "string_va": o["va"],
            "encoding": o["encoding"],
            "section": o["section"],
            "refs": refs,
            "branches": _dedup_branches(branches),
            "ok": bool(refs and branches),
        }
        payload["candidates"] = len(payload["branches"])
        if best is None or payload["candidates"] > best["candidates"]:
            best = payload
    if best is None:
        return {"string": str(needle), "string_off": None, "string_va": None,
                "encoding": None, "refs": [], "branches": [], "candidates": 0,
                "ok": False, "occurrences": 0}
    best["occurrences"] = len(occ)
    return best


def _branches_around(pe, ref_addr, window, sections=None):
    """从 ref_addr - window//4 起反汇编 (window + window//4) 字节，挑出 CMP/TEST/Jcc。"""
    back = window // 4
    start = ref_addr - back
    off = pe.va_to_off(start)
    if off is None:
        off = pe.va_to_off(ref_addr)
        start = ref_addr
        if off is None:
            return []
    total = window + back
    blob = pe.data[off:off + total]
    md = _make_md("x64" if pe.is64 else "x86")
    out = []
    seq = 0
    for insn in md.disasm(blob, start):
        mn = insn.mnemonic.lower()
        rec = {
            "addr": insn.address,
            "va": insn.address,
            "file_off": pe.va_to_off(insn.address),
            "insn": "%s %s" % (insn.mnemonic, insn.op_str),
            "bytes": bytes(insn.bytes).hex(),
            "size": insn.size,
            "seq": seq,
            "side": "before" if insn.address < ref_addr else "after",
            "kind": None,
        }
        seq += 1
        if mn in _CMP_MNEM:
            rec["kind"] = "cmp"
            out.append(rec)
        elif mn in _JCC_MNEM:
            rec["kind"] = "jcc"
            rec["cond"] = mn
            # capstone 给 rel8/rel32 跳转的 imm 已经是"绝对目标地址"，
            # 不能再做 addr+size+imm，否则范围检查会永远失败。
            if insn.operands:
                rec["target"] = insn.operands[0].imm & ((1 << 64) - 1)
            else:
                rec["target"] = None
            sem, act, note = _help.bypass_hint(mn)
            rec["semantic"] = sem
            rec["patch_action"] = act
            rec["patch_note"] = note
            out.append(rec)
        # 函数边界：ret / int3 / 无条件 jmp / 无效指令，之后不再解码。
        # 否则会顺着 ret 滑进字符串常量区，解出一堆假指令（线性扫描的典型误报）。
        # 只在引用点之后生效：向前回看那一段必须走到引用点为止。
        if insn.address >= ref_addr:
            if mn in ("ret", "retn", "retf", "int3", "ud2", "hlt", "jmp"):
                break
            if insn.address >= ref_addr + window:
                break
    # 给每条 jcc 配一个最近的前置比较指令，并记录两者相隔几条指令
    for i, rec in enumerate(out):
        if rec["kind"] != "jcc":
            continue
        for back_rec in reversed(out[:i]):
            if back_rec["kind"] == "cmp":
                rec["guard"] = back_rec["insn"]
                rec["guard_addr"] = back_rec["addr"]
                rec["guard_seq"] = back_rec["seq"]
                rec["guard_dist"] = rec["seq"] - back_rec["seq"]
                break
    return out


def _dedup_branches(branches):
    seen = set()
    out = []
    for b in branches:
        key = b["addr"]
        if key in seen:
            continue
        seen.add(key)
        out.append(b)
    out.sort(key=lambda x: x["addr"])
    return out


# =========================================================================== #
# 6. 打补丁
# =========================================================================== #
def patch_bytes(data, patches, pe=None):
    """按 [{offset|va, bytes:"9090", expect?}] 打补丁，返回新字节串。

    每条的 "old"（原字节）会回填到 patches 元素里，同时整个报告存到
    patch_bytes.last_report，便于做题时"改前/改后"对照。

    patches 元素：
      offset : 文件偏移（优先）
      va     : 虚拟地址（需同时传 pe，或 patches 内自带 image_base）
      bytes  : 十六进制串 "9090" / bytes / list[int]
      expect : 可选，期望的原字节（hex 串），不符则抛 ValueError（防错位）
    """
    if isinstance(data, PE):
        pe = pe or data
        data = data.data
    buf = bytearray(data)
    report = []
    for p in patches:
        off = p.get("offset")
        if off is None:
            va = p.get("va")
            if va is None:
                raise ValueError("patch 条目必须给 offset 或 va: %r" % (p,))
            if pe is None:
                raise ValueError("用 va 打补丁需要传 pe=PE(...)")
            off = pe.va_to_off(int(va))
            if off is None:
                raise ValueError("VA 0x%X 不在任何节内" % int(va))
        off = int(off)
        raw = p.get("bytes", p.get("new", ""))
        if isinstance(raw, str):
            new = bytes.fromhex(raw.replace(" ", "").replace("0x", ""))
        elif isinstance(raw, (bytes, bytearray)):
            new = bytes(raw)
        else:
            new = bytes(int(x) for x in raw)
        if off < 0 or off + len(new) > len(buf):
            raise ValueError("补丁越界: offset=0x%X len=%d size=%d"
                             % (off, len(new), len(buf)))
        old = bytes(buf[off:off + len(new)])
        expect = p.get("expect")
        if expect:
            exp = bytes.fromhex(expect.replace(" ", "")) if isinstance(expect, str) else bytes(expect)
            if exp != old:
                raise ValueError("原字节校验失败 @0x%X：期望 %s 实际 %s"
                                 % (off, exp.hex(), old.hex()))
        buf[off:off + len(new)] = new
        rec = {
            "offset": off,
            "va": (pe.off_to_va(off) if pe is not None else None),
            "old": old.hex(),
            "new": new.hex(),
            "note": p.get("note", ""),
        }
        p["old"] = rec["old"]
        p["_resolved_offset"] = off
        report.append(rec)
    patch_bytes.last_report = report
    return bytes(buf)


patch_bytes.last_report = []


def save_patched(src_path, patches, dst_path=None, pe=None):
    """读文件 -> patch_bytes -> 写新文件；返回 (dst_path, report)。"""
    with open(src_path, "rb") as f:
        data = f.read()
    if pe is None:
        try:
            pe = PE(data)
        except PEError:
            pe = None
    out = patch_bytes(data, patches, pe=pe)
    if dst_path is None:
        root, ext = os.path.splitext(src_path)
        dst_path = root + ".patched" + (ext or ".bin")
    with open(dst_path, "wb") as f:
        f.write(out)
    return dst_path, patch_bytes.last_report


def _insn_at(pe, addr, arch=None):
    """在 addr 处解一条指令（addr 为 VA）。"""
    off = pe.va_to_off(addr)
    if off is None:
        raise ValueError("地址 0x%X 无法映射到文件偏移" % addr)
    md = _make_md(arch or ("x64" if pe.is64 else "x86"))
    blob = pe.data[off:off + 16]
    for insn in md.disasm(blob, addr):
        return insn
    return None


def patch_je_to_jmp(pe, addr):
    """把 addr 处的 JE/JZ 改成 JMP（无条件跳转）。

    支持 74 cb (短跳, 2 字节) -> EB cb，以及 0F 84 cd (近跳, 6 字节) -> E9 cd。
    返回 {offset, addr, old, new, bytes, mnemonic}，可直接喂给 patch_bytes。
    """
    insn = _insn_at(pe, addr)
    if insn is None:
        raise ValueError("0x%X 处无法反汇编" % addr)
    mn = insn.mnemonic.lower()
    if mn not in ("je", "jz", "jne", "jnz"):
        raise ValueError("0x%X 是 %s，不是条件跳转" % (addr, insn.mnemonic))
    raw = bytes(insn.bytes)
    off = pe.va_to_off(addr)
    if raw[:1] == b"\x74":                       # je rel8
        new = b"\xEB" + raw[1:2]
    elif raw[:1] == b"\x75":                     # jne rel8
        new = b"\xEB" + raw[1:2]
    elif raw[:2] == b"\x0f\x84":                 # je rel32
        new = b"\xE9" + raw[2:6]
    elif raw[:2] == b"\x0f\x85":                 # jne rel32
        new = b"\xE9" + raw[2:6]
    else:
        raise ValueError("未识别的条件跳转编码: %s" % raw.hex())
    return {
        "offset": off,
        "addr": addr,
        "va": addr,
        "mnemonic": insn.mnemonic,
        "old": raw.hex(),
        "new": new.hex(),
        "bytes": new.hex(),
        "note": "%s %s -> jmp（无条件跳转）" % (insn.mnemonic, insn.op_str),
    }


def patch_jne_to_nop(pe, addr, length=2):
    """把 addr 处的 JNE/JNZ 整条 NOP 掉（默认 2 字节短跳）。

    2 字节短跳 -> 90 90；6 字节近跳 -> 90 x6。length 可强制指定。
    返回 {offset, addr, old, new, bytes, mnemonic}。
    """
    insn = _insn_at(pe, addr)
    if insn is None:
        raise ValueError("0x%X 处无法反汇编" % addr)
    mn = insn.mnemonic.lower()
    if mn not in ("jne", "jnz", "je", "jz") and not mn.startswith("j"):
        raise ValueError("0x%X 是 %s，不是条件跳转" % (addr, insn.mnemonic))
    off = pe.va_to_off(addr)
    old = bytes(pe.data[off:off + insn.size])
    n = int(length) if length else insn.size
    n = min(n, insn.size)
    new = b"\x90" * n
    return {
        "offset": off,
        "addr": addr,
        "va": addr,
        "mnemonic": insn.mnemonic,
        "old": old.hex(),
        "new": new.hex(),
        "bytes": new.hex(),
        "note": "%s %s -> %s" % (insn.mnemonic, insn.op_str, " ".join(["90"] * n)),
    }


# =========================================================================== #
# 7. 登录校验绕过综合建议
# =========================================================================== #
def suggest_login_bypass(pe, patterns=None, window=0x200, max_strings=40,
                         max_guard_dist=6, max_per_string=3):
    """综合推理：找登录相关字符串 -> 找引用 -> 找 CMP/TEST + 条件跳转 -> 给字节级建议。

    max_guard_dist : 校验点与条件跳转之间最多隔几条指令（超过视为噪声）
    max_per_string : 同一条字符串最多保留几条候选（防止通用词刷屏）

    返回 list[dict]，每条形如：
      {
        "string": "Login Successful;", "string_off": 0x1234, "string_va": 0x140012034,
        "result": "success",                      # success / failure / unknown
        "ref_addr": 0x140001000, "ref_insn": "lea rax, [rip + 0xf9]",
        "guard": "cmp eax, 1", "guard_addr": 0x140001013,
        "branch_addr": 0x140001016, "branch": "jne 0x14000101f",
        "branch_target": 0x14000101f,
        "file_offset": 0x216,                     # 要改的文件偏移
        "patch": "90 90", "patch_hex": "9090", "action": "nop",
        "conclusion": "人话结论",
        "patch_item": {"offset":0x216, "bytes":"9090", "expect":"7540"},
      }
    patch_item 可直接喂给 patch_bytes(data, [x["patch_item"] for x in ret])。
    """
    if not isinstance(pe, PE):
        raise TypeError("suggest_login_bypass 需要 PE")
    inter = interesting_strings(pe, patterns=patterns, max_results=max_strings)
    if not inter:
        inter = interesting_strings(pe, patterns=list(_help.PATTERN_GROUPS["login"]),
                                    max_results=max_strings)

    results = []
    seen_branch = set()
    img_lo, img_hi = pe.image_base, pe.image_base + pe.size_image
    for s in inter:
        needle = s["value"][:24] if len(s["value"]) > 24 else s["value"]
        if not needle.strip():
            continue
        info = find_branches_near_string(pe, needle, window=window)
        if not info["refs"] or not info["branches"]:
            continue
        for br in info["branches"]:
            if br["kind"] != "jcc":
                continue
            key = br["addr"]
            if key in seen_branch:
                continue
            # 校验点必须紧邻跳转（默认 <= max_guard_dist 条指令），
            # 否则只是"同一函数里恰好有条条件跳转"，属于噪声。
            gd = br.get("guard_dist")
            if gd is None or gd > max_guard_dist:
                continue
            # 跳转目标必须落在映像内，否则是误码解出来的假指令
            tgt = br.get("target")
            if tgt is not None and not (img_lo <= tgt < img_hi):
                continue
            seen_branch.add(key)
            guard = br.get("guard")
            _sem, action, note = _help.bypass_hint(br["cond"])
            off = br["file_off"]
            if off is None:
                continue
            if action == "jmp":
                new_bytes = _to_jmp_bytes(bytes.fromhex(br["bytes"]))
                action_txt = "把 %s 改成 JMP（无条件跳转）" % br["cond"].upper()
            else:
                new_bytes = b"\x90" * br["size"]
                action_txt = "把 %s 整条 NOP 掉（%d 字节）" % (br["cond"].upper(),
                                                            br["size"])
            conclusion = _build_conclusion(s, info, br, guard, action_txt,
                                           new_bytes.hex())
            results.append({
                "string": info["string"],
                "string_off": info["string_off"],
                "string_va": info["string_va"],
                "result": s["result"],
                "ref_addr": info["refs"][0]["addr"] if info["refs"] else None,
                "ref_insn": info["refs"][0]["insn"] if info["refs"] else None,
                "guard": guard,
                "guard_addr": br.get("guard_addr"),
                "branch_addr": br["addr"],
                "branch": br["insn"],
                "branch_target": br.get("target"),
                "file_offset": off,
                "patch": " ".join("%02X" % b for b in new_bytes),
                "patch_hex": new_bytes.hex(),
                "action": action,
                "note": note,
                "conclusion": conclusion,
                "score": _score_candidate(s["result"], guard, br["insn"]),
                "patch_item": {
                    "offset": off,
                    "bytes": new_bytes.hex(),
                    "expect": br["bytes"],
                    "note": conclusion,
                },
            })

    results.sort(key=lambda r: (-r["score"], r["result"] != "success",
                                r["file_offset"]))
    # 同一条字符串只留前几条，避免一个通用词（如 cmd.exe 里的 "ERRORLEVEL"）刷屏
    kept = {}
    final = []
    for r in results:
        key = (r["string_off"], r["string"])
        if kept.get(key, 0) >= max_per_string:
            continue
        kept[key] = kept.get(key, 0) + 1
        final.append(r)
    return final


def _score_candidate(result, guard, branch):
    """给候选校验点打分，用于排序（分高 = 更像真正的登录校验）。"""
    score = 0
    if result == "success":
        score += 3                               # 成功文案旁的分支最可能是绕过点
    elif result == "failure":
        score += 1
    g = guard or ""
    # cmp/test 带立即数（cmp eax, 1 / test al, 1）比 reg,reg 更像硬编码校验
    if re.search(r",\s*(?:0x[0-9a-f]+|\d+)\s*$", g, re.I):
        score += 2
    mn = (branch or "").split(" ")[0].lower()
    if mn in ("jne", "jnz"):
        score += 1                               # JNE 后接成功块是经典写法
    elif mn in ("je", "jz"):
        score += 1
    return score


def _to_jmp_bytes(raw):
    """把 JE/JZ 的原始编码转成等价 JMP。"""
    if raw[:1] == b"\x74":
        return b"\xEB" + raw[1:2]
    if raw[:1] == b"\x75":
        return b"\xEB" + raw[1:2]
    if raw[:2] == b"\x0f\x84":
        return b"\xE9" + raw[2:6]
    if raw[:2] == b"\x0f\x85":
        return b"\xE9" + raw[2:6]
    return b"\x90" * len(raw)


def _build_conclusion(s, info, br, guard, action_txt, new_hex=None):
    """把人话结论拼出来：哪条字符串、哪个引用、哪个校验、改哪个字节。"""
    kind = s["result"]
    ref0 = info["refs"][0] if info["refs"] else {"addr": 0, "insn": "?"}
    if kind == "success":
        flow = ("程序把 \"%s\" 当作登录成功文案，引用点 0x%X（`%s`）前后出现校验 %s；"
                "跳转 0x%X `%s` 决定是否走向失败分支。%s，即可无条件走成功路径。"
                % (info["string"], ref0["addr"], ref0["insn"],
                   guard or "（未见紧邻 CMP）", br["addr"], br["insn"], action_txt))
    elif kind == "failure":
        flow = ("字符串 \"%s\" 是失败提示，其引用点 0x%X 位于失败分支；"
                "校验点 %s 之后的 `%s`（0x%X）决定走向。%s，可让流程不进入失败分支。"
                % (info["string"], ref0["addr"], guard or "n/a",
                   br["insn"], br["addr"], action_txt))
    else:
        flow = ("字符串 \"%s\"（引用点 0x%X `%s`）邻近校验 %s，跳转 `%s` @ 0x%X。%s。"
                % (info["string"], ref0["addr"], ref0["insn"],
                   guard or "n/a", br["insn"], br["addr"], action_txt))
    tail = " 文件偏移 0x%X 处原字节 %s" % (br["file_off"], br["bytes"].upper())
    if new_hex:
        tail += " 改为 %s。" % " ".join(new_hex[i:i + 2].upper()
                                       for i in range(0, len(new_hex), 2))
    return flow + tail


# =========================================================================== #
# 8. 全局偏移提示：[reg + 0xB0B0C]
# =========================================================================== #
def find_memory_offset_hint(pe, key_byte=1, min_disp=0x100, sections=None,
                            include_negative=True):
    """找 [reg + 大位移] 形式的访问（对应 78/79 题的 0xB0B0C 这类标志位）。

    key_byte : 关心与立即数 key_byte 比较/写入的指令（默认 1）
    min_disp : 只保留位移 >= min_disp 的候选（过滤结构体小字段）
    返回 [{va, addr, file_off, insn, mnemonic, base, index, disp, disp_hex,
           size, kind, strong, hint}]
    """
    if not isinstance(pe, PE):
        raise TypeError("find_memory_offset_hint 需要 PE")
    out = []
    for insn, sec in _iter_insns(pe, sections):
        ops = getattr(insn, "operands", [])
        if not ops:
            continue
        mn = insn.mnemonic.lower()
        for i, op in enumerate(ops):
            if op.type != cs_x86.X86_OP_MEM:
                continue
            m = op.mem
            disp = m.disp
            if disp == 0:
                continue
            if not any(insn.reg_name(m.base or 0) == r for r in (
                    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")):
                continue
            ad = abs(disp)
            if ad < min_disp or (disp < 0 and not include_negative):
                continue
            # 是否与 key_byte 立即数成对出现
            imm_key = None
            if mn in ("cmp", "mov", "test", "or", "and", "add"):
                for other in ops:
                    if other.type == cs_x86.X86_OP_IMM:
                        imm_key = other.imm
            strong = bool(mn in ("cmp", "test") and imm_key == key_byte
                          and op.size == 1)
            if mn in ("mov", "or") and imm_key == key_byte and i == 0:
                strong = True
            hint = "%s/%s + 0x%X" % (
                insn.reg_name(m.base) if m.base else "", mn.upper(), ad)
            out.append({
                "va": insn.address,
                "addr": insn.address,
                "file_off": pe.va_to_off(insn.address),
                "insn": "%s %s" % (insn.mnemonic, insn.op_str),
                "bytes": bytes(insn.bytes).hex(),
                "mnemonic": insn.mnemonic,
                "base": insn.reg_name(m.base) if m.base else None,
                "index": insn.reg_name(m.index) if m.index else None,
                "disp": disp,
                "disp_hex": "0x%X" % ad,
                "size": op.size,
                "imm": imm_key,
                "kind": "read" if i != 0 else "write",
                "strong": strong,
                "section": sec["name"],
                "hint": hint,
            })
    # 同一偏移聚合成"候选全局变量"
    grouped = {}
    for r in out:
        grouped.setdefault(r["disp_hex"], []).append(r)
    ordered = []
    for disp_hex, items in grouped.items():
        strong = any(i["strong"] for i in items)
        ordered.append((0 if strong else 1, -len(items), disp_hex, items))
    ordered.sort()
    flat = []
    for _, _, _, items in ordered:
        flat.extend(items)
    return flat


# =========================================================================== #
# 9. .NET 元数据
# =========================================================================== #
# ECMA-335 表结构：0x00..0x2C
_T = {
    0x00: "Module", 0x01: "TypeRef", 0x02: "TypeDef", 0x03: "FieldPtr",
    0x04: "Field", 0x05: "MethodPtr", 0x06: "MethodDef", 0x07: "ParamPtr",
    0x08: "Param", 0x09: "InterfaceImpl", 0x0A: "MemberRef",
    0x0B: "Constant", 0x0C: "CustomAttribute", 0x0D: "FieldMarshal",
    0x0E: "DeclSecurity", 0x0F: "ClassLayout", 0x10: "FieldLayout",
    0x11: "StandAloneSig", 0x12: "EventMap", 0x13: "EventPtr",
    0x14: "Event", 0x15: "PropertyMap", 0x16: "PropertyPtr",
    0x17: "Property", 0x18: "MethodSemantics", 0x19: "MethodImpl",
    0x1A: "ModuleRef", 0x1B: "TypeSpec", 0x1C: "ImplMap", 0x1D: "FieldRVA",
    0x1E: "EncLog", 0x1F: "EncMap", 0x20: "Assembly",
    0x21: "AssemblyProcessor", 0x22: "AssemblyOS", 0x23: "AssemblyRef",
    0x24: "AssemblyRefProcessor", 0x25: "AssemblyRefOS", 0x26: "File",
    0x27: "ExportedType", 0x28: "ManifestResource", 0x29: "NestedClass",
    0x2A: "GenericParam", 0x2B: "MethodSpec", 0x2C: "GenericParamConstraint",
}

# 每张表列定义：("u8"/"u16"/"u32"/"str"/"guid"/"blob"/"table:Name"/"coded:Name")
_SCHEMA = {
    0x00: [("u16",), ("str",), ("guid",), ("guid",), ("guid",)],
    0x01: [("coded:ResolutionScope",), ("str",), ("str",)],
    0x02: [("u32",), ("str",), ("str",), ("coded:TypeDefOrRef",),
           ("table:Field",), ("table:MethodDef",)],
    0x03: [("table:Field",)],
    0x04: [("u16",), ("str",), ("blob",)],
    0x05: [("table:MethodDef",)],
    0x06: [("u32",), ("u16",), ("u16",), ("str",), ("blob",), ("table:Param",)],
    0x07: [("table:Param",)],
    0x08: [("u16",), ("u16",), ("str",)],
    0x09: [("table:TypeDef",), ("coded:TypeDefOrRef",)],
    0x0A: [("coded:MemberRefParent",), ("str",), ("blob",)],
    0x0B: [("u8",), ("u8",), ("coded:HasConstant",), ("blob",)],
    0x0C: [("coded:HasCustomAttribute",), ("coded:CustomAttributeType",), ("blob",)],
    0x0D: [("coded:HasFieldMarshal",), ("blob",)],
    0x0E: [("u16",), ("coded:HasDeclSecurity",), ("blob",)],
    0x0F: [("u16",), ("u32",), ("table:TypeDef",)],
    0x10: [("u32",), ("table:Field",)],
    0x11: [("blob",)],
    0x12: [("table:TypeDef",), ("table:Event",)],
    0x13: [("table:Event",)],
    0x14: [("u16",), ("str",), ("coded:TypeDefOrRef",)],
    0x15: [("table:TypeDef",), ("table:Property",)],
    0x16: [("table:Property",)],
    0x17: [("u16",), ("str",), ("blob",)],
    0x18: [("u16",), ("table:MethodDef",), ("coded:HasSemantics",)],
    0x19: [("table:TypeDef",), ("coded:MethodDefOrRef",), ("coded:MethodDefOrRef",)],
    0x1A: [("str",)],
    0x1B: [("blob",)],
    0x1C: [("u16",), ("coded:MemberForwarded",), ("str",), ("table:ModuleRef",)],
    0x1D: [("u32",), ("table:Field",)],
    0x1E: [("u32",), ("u32",)],
    0x1F: [("u32",)],
    0x20: [("u32",), ("u16",), ("u16",), ("u16",), ("u16",), ("u32",),
           ("blob",), ("str",), ("str",)],
    0x21: [("u32",)],
    0x22: [("u32",), ("u32",), ("u32",)],
    0x23: [("u16",), ("u16",), ("u16",), ("u16",), ("u32",), ("blob",),
           ("str",), ("str",), ("blob",)],
    0x24: [("u32",), ("table:AssemblyRef",)],
    0x25: [("u32",), ("u32",), ("u32",), ("table:AssemblyRef",)],
    0x26: [("u32",), ("str",), ("blob",)],
    0x27: [("u32",), ("u32",), ("str",), ("str",), ("coded:Implementation",)],
    0x28: [("u32",), ("u32",), ("str",), ("coded:Implementation",)],
    0x29: [("table:TypeDef",), ("table:TypeDef",)],
    0x2A: [("u16",), ("u16",), ("coded:TypeOrMethodDef",), ("str",)],
    0x2B: [("coded:MethodDefOrRef",), ("blob",)],
    0x2C: [("table:GenericParam",), ("coded:TypeDefOrRef",)],
}

_CODED = {
    "TypeDefOrRef": (["TypeDef", "TypeRef", "TypeSpec"], 2),
    "HasConstant": (["Field", "Param", "Property"], 2),
    "HasCustomAttribute": (["MethodDef", "Field", "TypeRef", "TypeDef", "Param",
                            "InterfaceImpl", "MemberRef", "Module",
                            "DeclSecurity", "Property", "Event", "StandAloneSig",
                            "ModuleRef", "TypeSpec", "Assembly", "AssemblyRef",
                            "File", "ExportedType", "ManifestResource",
                            "GenericParam", "GenericParamConstraint",
                            "MethodSpec"], 5),
    "HasFieldMarshal": (["Field", "Param"], 1),
    "HasDeclSecurity": (["TypeDef", "MethodDef", "Assembly"], 2),
    "MemberRefParent": (["TypeDef", "TypeRef", "ModuleRef", "MethodDef",
                         "TypeSpec"], 3),
    "HasSemantics": (["Event", "Property"], 1),
    "MethodDefOrRef": (["MethodDef", "MemberRef"], 1),
    "MemberForwarded": (["Field", "MethodDef"], 1),
    "Implementation": (["File", "AssemblyRef", "ExportedType"], 2),
    "CustomAttributeType": (["<none>", "<none>", "MethodDef", "MemberRef",
                             "<none>"], 3),
    "ResolutionScope": (["Module", "ModuleRef", "AssemblyRef", "TypeRef"], 2),
    "TypeOrMethodDef": (["TypeDef", "MethodDef"], 1),
}
_TNAME2IDX = {v: k for k, v in _T.items()}


def _read_compressed(b, o):
    """ECMA-335 压缩整数；返回 (值, 新偏移)。"""
    if o >= len(b):
        return 0, o
    b0 = b[o]
    if b0 & 0x80 == 0:
        return b0, o + 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3F) << 8) | b[o + 1], o + 2
    if b0 & 0xE0 == 0xC0:
        v = ((b0 & 0x1F) << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]
        return v, o + 4
    return b0, o + 1


class DotnetInfo:
    """解析 .NET / CLR 元数据（BSJB）。

    dn = DotnetInfo(pe)
    dn.assembly      {"name":..., "version":...}
    dn.types         [{"namespace":..., "name":..., "methods":[str], "fields":[str]}]
    dn.methods       ["Type::Method", ...]
    dn.user_strings  ["登录成功", ...]      # #US 堆，.NET 里的中文文案都在这
    dn.streams       ["#~", "#Strings", "#US", ...]
    """

    def __init__(self, pe):
        if isinstance(pe, (bytes, bytearray)):
            pe = PE(pe)
        self.pe = pe
        self.ok = False
        self.error = ""
        self.streams = []
        self.heap_offsets = {}
        self.type_names = {}
        self.types = []
        self.methods = []
        self.user_strings = []
        self.assembly = {}
        self.tables = {}
        self._parse()

    # ------------------------------------------------ #
    def _parse(self):
        pe = self.pe
        if not pe.is_dotnet:
            self.error = "无 CLR 数据目录（不是 .NET 程序集）"
            return
        off = pe.rva_to_off(pe.clr_rva)
        if off is None or off + 0x48 > len(pe.data):
            self.error = "CLR 头越界"
            return
        d = pe.data
        self.runtime_version = "%d.%d" % (_u16(d, off + 4), _u16(d, off + 6))
        meta_rva = _u32(d, off + 8)
        meta_size = _u32(d, off + 12)
        self.flags = _u32(d, off + 16)
        self.entry_token = _u32(d, off + 20)
        moff = pe.rva_to_off(meta_rva)
        if moff is None:
            self.error = "元数据 RVA 无法映射"
            return
        if _u32(d, moff) != 0x424A5342:
            self.error = "缺少 BSJB 签名"
            return
        ver_len = _u32(d, moff + 12)
        self.meta_version = d[moff + 16:moff + 16 + max(0, ver_len)].split(b"\x00\r\x00")[0] \
            .decode("latin-1", "replace").split("\x00")[0]
        p = moff + 16 + ver_len
        p += 2                                       # flags
        n_streams = _u16(d, p)
        p += 2
        for _ in range(n_streams):
            s_off = _u32(d, p)
            s_size = _u32(d, p + 4)
            name = _cstr(d, p + 8, 32)
            self.streams.append(name)
            self.heap_offsets[name] = (moff + s_off, s_size)
            p += 8 + ((len(name) + 1 + 3) // 4) * 4
        self.ok = True

        self._parse_strings_heap()
        self._parse_us_heap()
        self._parse_tables()

    # ------------------------------------------------ #
    def _parse_strings_heap(self):
        loc = self.heap_offsets.get("#Strings")
        if not loc:
            return
        off, size = loc
        blob = self.pe.data[off:off + size]
        self.strings_heap = []
        i = 0
        while i < len(blob):
            j = blob.find(b"\x00", i)
            if j < 0:
                j = len(blob)
            s = blob[i:j]
            if s:
                self.strings_heap.append(s.decode("utf-8", "replace"))
            i = j + 1

    def _parse_us_heap(self):
        loc = self.heap_offsets.get("#US")
        if not loc:
            return
        off, size = loc
        blob = self.pe.data[off:off + size]
        i = 1                                        # 第 0 字节保留
        while i < len(blob):
            n, i2 = _read_compressed(blob, i)
            if n <= 0 or i2 + n > len(blob):
                break
            raw = blob[i2:i2 + n]
            i = i2 + n
            if raw.endswith(b"\x00"):
                raw = raw[:-1]
            try:
                txt = raw.decode("utf-16-le", "replace")
            except Exception:
                continue
            if txt and not txt.isprintable():
                txt = "".join(c for c in txt if c.isprintable())
            if txt:
                self.user_strings.append(txt)

    # ------------------------------------------------ #
    def _row_size(self, tid, rows, str_big, guid_big):
        total = 0
        for col in _SCHEMA.get(tid, []):
            kind = col[0]
            if kind == "u8":
                total += 1
            elif kind == "u16":
                total += 2
            elif kind == "u32":
                total += 4
            elif kind == "str":
                total += 4 if str_big else 2
            elif kind == "guid":
                total += 4 if guid_big else 2
            elif kind == "blob":
                total += 4 if self.blob_big else 2
            elif kind.startswith("table:"):
                name = kind.split(":", 1)[1]
                total += 4 if rows.get(_TNAME2IDX.get(name, 0xFFFF), 0) >= 65536 else 2
            elif kind.startswith("coded:"):
                cname = kind.split(":", 1)[1]
                targets, bits = _CODED[cname]
                mx = 0
                for t in targets:
                    mx = max(mx, rows.get(_TNAME2IDX.get(t, 0xFFFF), 0))
                total += 4 if mx >= (1 << (16 - bits)) else 2
        return total

    def _parse_tables(self):
        loc = self.heap_offsets.get("#~") or self.heap_offsets.get("#-")
        if not loc:
            return
        off, size = loc
        d = self.pe.data
        blob = d[off:off + size]
        if len(blob) < 24:
            return
        heap_sizes = blob[6]
        str_big = bool(heap_sizes & 0x01)
        guid_big = bool(heap_sizes & 0x02)
        self.blob_big = bool(heap_sizes & 0x04)
        valid = _u64(blob, 8)
        p = 24
        rows = {}
        for tid in range(64):
            if valid >> tid & 1:
                rows[tid] = _u32(blob, p)
                p += 4
        self.tables = rows
        p += (4 - (p % 4)) % 4
        offsets = {}
        for tid in sorted(rows):
            offsets[tid] = p
            p += self._row_size(tid, rows, str_big, guid_big) * rows[tid]
        self._table_offsets = offsets
        self._rows = rows
        self._blob = blob
        self._str_big = str_big
        self._guid_big = guid_big

        # TypeDef 名表
        type_rows = self._rows_of(0x02)
        for r in type_rows:
            self.type_names[self._row_index(0x02, r) + 1] = (
                r["Namespace"], r["Name"])
        # Assembly
        for r in self._rows_of(0x20)[:1]:
            self.assembly = {
                "name": r["Name"],
                "version": "%d.%d.%d.%d" % (r["Major"], r["Minor"], r["Build"],
                                            r["Rev"]),
                "culture": r.get("Culture", ""),
            }
        # TypeDef -> methods / fields
        td = self._rows_of(0x02)
        meth = self._rows_of(0x06)
        fld = self._rows_of(0x04)
        mc = self._rows.get(0x06, 0)
        fc = self._rows.get(0x04, 0)
        for i, r in enumerate(td):
            start = r.get("MethodList", 1)
            end = td[i + 1]["MethodList"] if i + 1 < len(td) else mc + 1
            names = []
            for mi in range(max(1, start), min(end, mc + 1)):
                if mi - 1 < len(meth):
                    nm = meth[mi - 1]["Name"]
                    names.append(nm)
                    self.methods.append("%s::%s" % (r["Name"], nm))
            fstart = r.get("FieldList", 1)
            fend = td[i + 1]["FieldList"] if i + 1 < len(td) else fc + 1
            fnames = [fld[fi - 1]["Name"] for fi in range(max(1, fstart),
                                                          min(fend, fc + 1))
                      if fi - 1 < len(fld)]
            self.types.append({
                "namespace": r["Namespace"], "name": r["Name"],
                "flags": "0x%X" % r["Flags"],
                "methods": names, "fields": fnames,
            })
        # AssemblyRef
        self.refs = [{"name": r["Name"],
                      "version": "%d.%d.%d.%d" % (r["Major"], r["Minor"],
                                                  r["Build"], r["Rev"])}
                     for r in self._rows_of(0x23)]

    # ------------------------------------------------ #
    def _row_index(self, tid, row):
        return row.get("_idx", 0)

    def _heap_str(self, idx):
        loc = self.heap_offsets.get("#Strings")
        if not loc:
            return ""
        base, size = loc
        return _cstr(self.pe.data, base + idx, 512)

    def _heap_blob(self, idx):
        loc = self.heap_offsets.get("#Blob")
        if not loc:
            return b""
        base, size = loc
        n, o = _read_compressed(self.pe.data, base + idx)
        return self.pe.data[o:o + n]

    def _heap_guid(self, idx):
        return "{%d}" % idx

    def _rows_of(self, tid):
        """解析某张表的全部行，返回 [dict]。"""
        if not self.ok or tid not in getattr(self, "_table_offsets", {}):
            return []
        blob = self._blob
        p = self._table_offsets[tid]
        row_size = self._row_size(tid, self._rows, self._str_big, self._guid_big)
        n = self._rows.get(tid, 0)
        schema = _SCHEMA.get(tid, [])
        out = []
        for i in range(n):
            base = p + i * row_size
            if base + row_size > len(blob):
                break
            cur = base
            rec = {"_idx": i}
            for ci, col in enumerate(schema):
                kind = col[0]
                key = _colname(tid, ci, cur - base)
                if kind == "u8":
                    rec[key] = blob[cur]
                    cur += 1
                elif kind == "u16":
                    rec[key] = _u16(blob, cur)
                    cur += 2
                elif kind == "u32":
                    rec[key] = _u32(blob, cur)
                    cur += 4
                elif kind == "str":
                    if self._str_big:
                        v = _u32(blob, cur)
                        cur += 4
                    else:
                        v = _u16(blob, cur)
                        cur += 2
                    rec[key] = self._heap_str(v)
                elif kind == "guid":
                    cur += 4 if self._guid_big else 2
                elif kind == "blob":
                    cur += 4 if self.blob_big else 2
                elif kind.startswith("table:"):
                    name = kind.split(":", 1)[1]
                    big = self._rows.get(_TNAME2IDX.get(name, 0xFFFF), 0) >= 65536
                    rec[key] = _u32(blob, cur) if big else _u16(blob, cur)
                    cur += 4 if big else 2
                elif kind.startswith("coded:"):
                    cname = kind.split(":", 1)[1]
                    targets, bits = _CODED[cname]
                    mx = max(self._rows.get(_TNAME2IDX.get(t, 0xFFFF), 0)
                             for t in targets)
                    big = mx >= (1 << (16 - bits))
                    rec[key] = _u32(blob, cur) if big else _u16(blob, cur)
                    cur += 4 if big else 2
            out.append(rec)
        return out

    # ------------------------------------------------ #
    def summary(self):
        lines = []
        if not self.ok:
            lines.append(".NET        : 否（%s）" % (self.error or "解析失败"))
            return lines
        lines.append(".NET 元数据 : BSJB ok, runtime %s, streams=%s"
                     % (getattr(self, "runtime_version", "?"),
                        ",".join(self.streams)))
        if self.assembly:
            lines.append("程序集      : %s v%s" % (self.assembly.get("name", "?"),
                                                  self.assembly.get("version", "?")))
        lines.append("类型 %d 个 / 方法 %d 个 / 用户字符串 %d 条"
                     % (len(self.types), len(self.methods), len(self.user_strings)))
        for t in self.types[:40]:
            lines.append("  %s%s  (%d methods, %d fields)"
                         % (t["namespace"] + "." if t["namespace"] else "",
                            t["name"], len(t["methods"]), len(t["fields"])))
            if t["methods"]:
                lines.append("      methods: " + ", ".join(t["methods"][:24]))
        if self.user_strings:
            lines.append("  #US 字符串: " + " | ".join(
                [s for s in self.user_strings if len(s) > 1][:40]))
        return lines


def _colname(tid, ci, offset):
    """给列起可读名字（部分表用真实列名，其余用 tid_列号）。"""
    known = {
        (0x02, 0): "Flags", (0x02, 1): "Name", (0x02, 2): "Namespace",
        (0x02, 3): "Extends", (0x02, 4): "FieldList", (0x02, 5): "MethodList",
        (0x06, 0): "RVA", (0x06, 1): "ImplFlags", (0x06, 2): "Flags",
        (0x06, 3): "Name", (0x06, 4): "Signature", (0x06, 5): "ParamList",
        (0x04, 0): "Flags", (0x04, 1): "Name", (0x04, 2): "Signature",
        (0x20, 0): "HashAlgId", (0x20, 1): "Major", (0x20, 2): "Minor",
        (0x20, 3): "Build", (0x20, 4): "Rev", (0x20, 5): "Flags",
        (0x20, 6): "PublicKey", (0x20, 7): "Name", (0x20, 8): "Culture",
        (0x23, 0): "Major", (0x23, 1): "Minor", (0x23, 2): "Build",
        (0x23, 3): "Rev", (0x23, 4): "Flags", (0x23, 5): "PublicKeyOrToken",
        (0x23, 6): "Name", (0x23, 7): "Culture", (0x23, 8): "HashValue",
        (0x08, 0): "Flags", (0x08, 1): "Sequence", (0x08, 2): "Name",
        (0x01, 0): "ResolutionScope", (0x01, 1): "Name", (0x01, 2): "Namespace",
    }
    return known.get((tid, ci), "col_%d_%d" % (tid, offset))


# =========================================================================== #
# 10. 命令行
# =========================================================================== #
def _load(path):
    with open(path, "rb") as f:
        data = f.read()
    return PE(data)


def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="revkit", description="自研 PE 分析 / 逆向辅助")
    ap.add_argument("cmd", choices=["info", "strings", "imports", "disasm",
                                    "bypass", "memhint", "dotnet"])
    ap.add_argument("path")
    ap.add_argument("--key", type=lambda s: int(s, 0), default=1)
    ap.add_argument("--count", type=int, default=60)
    ap.add_argument("--min", type=int, default=4)
    ap.add_argument("--va", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--all", action="store_true", help="strings: 不过滤关键词")
    ap.add_argument("--find", default=None, help="strings: 只找含该子串的行")
    args = ap.parse_args(argv)

    pe = _load(args.path)
    if args.cmd == "info":
        print("\n".join(pe.summary()))
        if pe.is_dotnet:
            print("\n".join(DotnetInfo(pe).summary()))
    elif args.cmd == "imports":
        for dll, funcs in pe.imports.items():
            print("%-30s %d" % (dll, len(funcs)))
            for fn in funcs[:200]:
                print("    %s" % fn)
    elif args.cmd == "strings":
        if args.find:
            hits = _find_string_occurrences(pe, args.find)
            for h in hits:
                print("0x%08X  off=0x%X  [%s]  %s" % (
                    h["va"] or 0, h["offset"], h["encoding"], h["text"]))
        else:
            rows = (strings(pe.data, min_len=args.min, pe=pe) if args.all
                    else interesting_strings(pe, min_len=args.min))
            for r in rows[:400]:
                print("0x%08X  off=0x%06X  %-9s %s%s" % (
                    r.get("va") or 0, r["offset"], r.get("encoding", ""),
                    r["value"], "  <- " + r["category"] if r.get("category") else ""))
    elif args.cmd == "disasm":
        for ins in disasm(pe, va=args.va, count=args.count):
            print("%016X  %-24s %s %s" % (ins["addr"], ins["bytes"],
                                          ins["mnemonic"], ins["op_str"]))
    elif args.cmd == "bypass":
        rows = suggest_login_bypass(pe)
        if not rows:
            print("未找到 CMP+条件跳转 组合（可能已加壳或字符串被加密）")
        for r in rows:
            print("[%s] %s" % (r["result"], r["conclusion"]))
            print("     补丁: offset=0x%X  %s -> %s" % (
                r["file_offset"], r["patch_item"]["expect"].upper(), r["patch"]))
    elif args.cmd == "memhint":
        rows = find_memory_offset_hint(pe, key_byte=args.key)
        for r in rows[:80]:
            print("%s  %016X  %-10s %-6s disp=%s %s" % (
                "STRONG" if r["strong"] else "      ", r["va"],
                r["section"], r["kind"], r["disp_hex"], r["insn"]))
        print("共 %d 条候选" % len(rows))
    elif args.cmd == "dotnet":
        print("\n".join(DotnetInfo(pe).summary()))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
