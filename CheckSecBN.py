"""
CheckSecBN
==========

A static, Narly/checksec-style exploit-mitigation reporter for Binary Ninja.

The classic WinDbg extension "narly" (https://code.google.com/archive/p/narly/)
inspected a *live* process's loaded modules and reported SafeSEH / GS / DEP /
ASLR status. This plugin reports the same class of information, but statically,
straight from the PE headers Binary Ninja has already parsed. No debugger
session required.

Adds a right-click / Tools menu command:
    Checksec > Show Mitigation Report

Reports:
    - ASLR (Dynamic Base) / High Entropy VA
    - DEP / NX
    - SafeSEH (32-bit only; N/A on 64-bit, which is table-based & always safe)
    - GS / stack cookie (heuristic, via load-config SecurityCookie)
    - Control Flow Guard (CFG)
    - Force Integrity
    - AppContainer / No SEH
    - Authenticode signature presence (blob presence only, not validated)
"""

import os
import struct

import binaryninja as bn
from binaryninja import BinaryView, PluginCommand


IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

DLLCHAR_HIGH_ENTROPY_VA = 0x0020
DLLCHAR_DYNAMIC_BASE = 0x0040
DLLCHAR_FORCE_INTEGRITY = 0x0080
DLLCHAR_NX_COMPAT = 0x0100
DLLCHAR_NO_ISOLATION = 0x0200
DLLCHAR_NO_SEH = 0x0400
DLLCHAR_NO_BIND = 0x0800
DLLCHAR_APPCONTAINER = 0x1000
DLLCHAR_WDM_DRIVER = 0x2000
DLLCHAR_GUARD_CF = 0x4000
DLLCHAR_TERMINAL_SERVER_AWARE = 0x8000

GUARD_CF_INSTRUMENTED = 0x00000100
GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400

MACHINE_I386 = 0x14C
MACHINE_AMD64 = 0x8664
MACHINE_ARM64 = 0xAA64


class PEParseError(Exception):
    pass


class PEMitigations:
    """Parses the subset of a PE file's headers relevant to exploit-mitigation reporting.

    All reads are done via file offsets against the raw (unmapped) view of the
    binary, so this works regardless of how Binary Ninja chose to map segments.
    """

    def __init__(self, raw):
        self.raw = raw
        self._parse()

    # -- low level reads (file-offset based) --

    def _read(self, offset, size):
        data = self.raw.read(offset, size)
        if data is None or len(data) < size:
            raise PEParseError(f"couldn't read {size} bytes at file offset {offset:#x}")
        return data

    def u16(self, offset):
        return struct.unpack("<H", self._read(offset, 2))[0]

    def u32(self, offset):
        return struct.unpack("<I", self._read(offset, 4))[0]

    def u64(self, offset):
        return struct.unpack("<Q", self._read(offset, 8))[0]

    # -- header parsing --

    def _parse(self):
        if self._read(0, 2) != b"MZ":
            raise PEParseError("not an MZ/PE file (no MZ signature)")

        e_lfanew = self.u32(0x3C)
        if self._read(e_lfanew, 4) != b"PE\x00\x00":
            raise PEParseError("no PE signature found")

        coff = e_lfanew + 4
        self.machine = self.u16(coff + 0)
        self.num_sections = self.u16(coff + 2)
        self.size_of_optional_header = self.u16(coff + 16)
        self.characteristics = self.u16(coff + 18)

        opt = coff + 20
        magic = self.u16(opt + 0)
        if magic == 0x10B:
            self.is_pe32_plus = False
        elif magic == 0x20B:
            self.is_pe32_plus = True
        else:
            raise PEParseError(f"unrecognized optional header magic {magic:#x}")

        # DllCharacteristics sits at the same offset in both PE32 and PE32+
        self.dll_characteristics = self.u16(opt + 0x46)

        if self.is_pe32_plus:
            num_rva_off = opt + 0x6C
            data_dir_off = opt + 0x70
        else:
            num_rva_off = opt + 0x5C
            data_dir_off = opt + 0x60

        self.num_rva_and_sizes = self.u32(num_rva_off)
        self.data_dir_offset = data_dir_off

        # Section table -- needed to resolve data-directory RVAs to file offsets.
        self.sections = []
        sec_off = opt + self.size_of_optional_header
        for i in range(self.num_sections):
            base = sec_off + i * 40
            name = self._read(base, 8).rstrip(b"\x00").decode("latin1", "replace")
            virtual_size = self.u32(base + 8)
            virtual_address = self.u32(base + 12)
            size_of_raw_data = self.u32(base + 16)
            pointer_to_raw_data = self.u32(base + 20)
            self.sections.append(
                dict(
                    name=name,
                    virtual_size=virtual_size,
                    virtual_address=virtual_address,
                    size_of_raw_data=size_of_raw_data,
                    pointer_to_raw_data=pointer_to_raw_data,
                )
            )

        self._parse_load_config()
        self._parse_security_directory()

    def _data_directory(self, index):
        if index >= self.num_rva_and_sizes:
            return (0, 0)
        off = self.data_dir_offset + index * 8
        return self.u32(off), self.u32(off + 4)

    def rva_to_offset(self, rva):
        for sec in self.sections:
            span = max(sec["virtual_size"], sec["size_of_raw_data"])
            if sec["virtual_address"] <= rva < sec["virtual_address"] + span:
                return sec["pointer_to_raw_data"] + (rva - sec["virtual_address"])
        # Not inside any section, assume it's within the headers (identity mapped).
        return rva

    def _parse_load_config(self):
        self.load_config = None
        rva, size = self._data_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        if not rva or not size:
            return
        try:
            off = self.rva_to_offset(rva)
            struct_size = self.u32(off)

            def field(field_off_32, field_off_64, width):
                foff = off + (field_off_64 if self.is_pe32_plus else field_off_32)
                if foff + width > off + struct_size:
                    return None
                return self.u64(foff) if width == 8 else self.u32(foff)

            security_cookie = field(0x3C, 0x58, 8 if self.is_pe32_plus else 4)
            seh_count = field(0x44, 0x68, 8 if self.is_pe32_plus else 4)
            guard_flags = field(0x58, 0x90, 4)

            self.load_config = dict(
                size=struct_size,
                security_cookie=security_cookie,
                seh_handler_count=seh_count,
                guard_flags=guard_flags,
            )
        except PEParseError:
            self.load_config = None

    def _parse_security_directory(self):
        # NOTE: unlike every other data directory, IMAGE_DIRECTORY_ENTRY_SECURITY's
        # "VirtualAddress" field is actually a raw file offset, not an RVA.
        off, size = self._data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
        self.is_signed = bool(off and size)

    # -- derived mitigation flags --

    @property
    def machine_name(self):
        return {
            MACHINE_I386: "x86",
            MACHINE_AMD64: "x64",
            MACHINE_ARM64: "ARM64",
        }.get(self.machine, f"0x{self.machine:04x}")

    @property
    def aslr(self):
        return bool(self.dll_characteristics & DLLCHAR_DYNAMIC_BASE)

    @property
    def high_entropy_va(self):
        if not self.is_pe32_plus:
            return None  # not applicable to 32-bit images
        return bool(self.dll_characteristics & DLLCHAR_HIGH_ENTROPY_VA)

    @property
    def dep(self):
        return bool(self.dll_characteristics & DLLCHAR_NX_COMPAT)

    @property
    def force_integrity(self):
        return bool(self.dll_characteristics & DLLCHAR_FORCE_INTEGRITY)

    @property
    def no_seh(self):
        return bool(self.dll_characteristics & DLLCHAR_NO_SEH)

    @property
    def appcontainer(self):
        return bool(self.dll_characteristics & DLLCHAR_APPCONTAINER)

    @property
    def cfg(self):
        if self.dll_characteristics & DLLCHAR_GUARD_CF:
            return True
        if self.load_config and self.load_config["guard_flags"]:
            return bool(self.load_config["guard_flags"] & GUARD_CF_INSTRUMENTED)
        return False

    @property
    def safeseh(self):
        if self.machine != MACHINE_I386:
            return None  # SafeSEH is a 32-bit-only concept; 64-bit SEH is table-based & always safe
        if self.no_seh:
            return True  # opted out of SEH entirely, which is at least as safe
        if not self.load_config:
            return False
        return bool(self.load_config["seh_handler_count"])

    @property
    def gs(self):
        # Heuristic (the same one classic checksec-style tools use): the compiler
        # only populates SecurityCookie in the load config when /GS was enabled.
        # Not 100% reliable, see printed caveat in the report.
        if not self.load_config or self.load_config["security_cookie"] is None:
            return False
        return self.load_config["security_cookie"] != 0

    @property
    def signed(self):
        return self.is_signed


def _tri(val):
    if val is None:
        return "N/A"
    return "Present" if val else "MISSING"


def build_report(bv: "BinaryView", mit: PEMitigations) -> str:
    filename = bv.file.filename if bv.file else "(unknown)"
    rows = [
        ("ASLR (Dynamic Base)", _tri(mit.aslr)),
        ("High Entropy VA", _tri(mit.high_entropy_va)),
        ("DEP / NX", _tri(mit.dep)),
        ("SafeSEH", _tri(mit.safeseh)),
        ("GS (stack cookie, heuristic)", _tri(mit.gs)),
        ("Control Flow Guard (CFG)", _tri(mit.cfg)),
        ("Force Integrity", _tri(mit.force_integrity)),
        ("AppContainer", _tri(mit.appcontainer)),
        ("No SEH", _tri(mit.no_seh)),
        ("Authenticode signature present", _tri(mit.signed)),
    ]

    lines = [
        f"# Mitigation Report: `{filename}`",
        "",
        f"**Architecture:** {mit.machine_name}  ",
        f"**Image type:** {'PE32+' if mit.is_pe32_plus else 'PE32'}",
        "",
        "| Mitigation | Status |",
        "|---|---|",
    ]
    for name, status in rows:
        marker = "\u2705" if status == "Present" else ("\u26a0\ufe0f" if status == "MISSING" else "\u2796")
        lines.append(f"| {name} | {marker} {status} |")

    lines += [
        "",
        "*GS detection is a heuristic based on a non-zero SecurityCookie in the load "
        "config directory and is not 100% reliable. Everything else is read directly "
        "from the PE header / load config directory. Signature presence is not the "
        "same as signature validity.*",
    ]
    return "\n".join(lines)


def show_checksec_report(bv: "BinaryView"):
    if bv.view_type != "PE":
        bn.log_error(
            "Checksec: this doesn't look like a PE file (view type is '%s')" % bv.view_type
        )
        return

    raw = bv.file.raw if bv.file and bv.file.raw else bv
    try:
        mit = PEMitigations(raw)
    except PEParseError as e:
        bn.log_error(f"Checksec: failed to parse PE headers: {e}")
        return

    report = build_report(bv, mit)

    # Always log a plain-text copy too, so this also works headlessly / in the console.
    bn.log_info(report)

    filename = bv.file.filename if bv.file else "(unknown)"
    project_name = os.path.basename(filename)
    tab_title = f"{project_name} CheckSec Report"

    try:
        bn.show_markdown_report(tab_title, report, report)
    except Exception:
        pass  # not running in a UI context; the log above already has the report


PluginCommand.register(
    "Generate CheckSec Report",
    "Report PE exploit mitigations (ASLR, DEP, SafeSEH, GS, CFG, signing). A static, "
    "Narly/checksec-style report for the loaded binary.",
    show_checksec_report,
)
