"""Mach-O parser (iOS app binaries and frameworks).

Extracts: header flags (PIE, stack execution), imported/defined symbols,
linked libraries, encryption info, minimum OS, embedded entitlements from the
code signature, and readable strings from __cstring / ObjC / Swift sections.
"""
from __future__ import annotations

import plistlib
import re
import struct
from dataclasses import dataclass, field

MH_MAGIC_64, MH_MAGIC = 0xFEEDFACF, 0xFEEDFACE
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
CPU_ARM64, CPU_X86_64, CPU_ARM = 0x0100000C, 0x01000007, 12

MH_PIE = 0x200000
MH_ALLOW_STACK_EXECUTION = 0x20000

LC_SEGMENT, LC_SYMTAB, LC_LOAD_DYLIB, LC_SEGMENT_64 = 0x1, 0x2, 0xC, 0x19
LC_CODE_SIGNATURE, LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x1D, 0x21, 0x2C
LC_VERSION_MIN_IPHONEOS, LC_BUILD_VERSION = 0x25, 0x32
LC_LOAD_WEAK_DYLIB, LC_RPATH, LC_REEXPORT_DYLIB = 0x80000018, 0x8000001C, 0x8000001F

STRING_SECTIONS = {"__cstring", "__objc_methname", "__objc_classname", "__swift5_reflstr",
                   "__objc_methtype", "__const", "__ustring"}


class MachOError(ValueError):
    pass


@dataclass
class MachO:
    arch: str = ""
    filetype: int = 0
    flags: int = 0
    pie: bool = False
    stack_exec: bool = False
    encrypted: bool | None = None
    min_os: str = ""
    imports: set = field(default_factory=set)
    exports_count: int = 0
    local_symbols: int = 0
    libraries: list = field(default_factory=list)
    rpaths: list = field(default_factory=list)
    entitlements: dict = field(default_factory=dict)
    strings: list = field(default_factory=list)
    has_code_signature: bool = False
    slices: list = field(default_factory=list)

    @property
    def stack_canary(self) -> bool:
        return bool(self.imports & {"___stack_chk_fail", "___stack_chk_guard"})

    @property
    def arc(self) -> bool:
        return bool(self.imports & {"_objc_release", "_objc_autoreleaseReturnValue",
                                    "_objc_storeStrong", "_swift_release"})

    @property
    def uses_objc(self) -> bool:
        return any(s.startswith("_objc_") for s in self.imports)


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _ver(v: int) -> str:
    return f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"


def pick_slice(data: bytes) -> tuple[int, int, list[str]]:
    """Return (offset, size, archs) for the best slice of a (possibly fat) binary."""
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return 0, len(data), []
    n = struct.unpack_from(">I", data, 4)[0]
    if n > 32:
        raise MachOError("not a fat binary (java class?)")
    entries, archs = [], []
    for i in range(n):
        if magic == FAT_MAGIC:
            cpu, _sub, off, size, _al = struct.unpack_from(">iiIII", data, 8 + i * 20)
        else:
            cpu, _sub, off, size, _al, _r = struct.unpack_from(">iiQQII", data, 8 + i * 32)
        entries.append((cpu, off, size))
        archs.append({CPU_ARM64: "arm64", CPU_X86_64: "x86_64", CPU_ARM: "armv7"}.get(cpu, hex(cpu)))
    for pref in (CPU_ARM64, CPU_ARM, CPU_X86_64):
        for cpu, off, size in entries:
            if cpu == pref:
                return off, size, archs
    cpu, off, size = entries[0]
    return off, size, archs


def is_macho(head: bytes) -> bool:
    if len(head) < 8:
        return False
    le = struct.unpack_from("<I", head, 0)[0]
    be = struct.unpack_from(">I", head, 0)[0]
    if le in (MH_MAGIC_64, MH_MAGIC):
        return True
    # 0xCAFEBABE is also Java class magic; fat headers have a small arch count
    return be in (FAT_MAGIC, FAT_MAGIC_64) and 0 < struct.unpack_from(">I", head, 4)[0] < 20


def parse(data: bytes, want_strings: bool = True) -> MachO:
    try:
        return _parse(data, want_strings)
    except (struct.error, IndexError, OverflowError, MemoryError) as e:
        raise MachOError(f"corrupt Mach-O: {e}") from None


def _parse(data: bytes, want_strings: bool = True) -> MachO:
    base, size, archs = pick_slice(data)
    d = data[base:base + size]
    magic = struct.unpack_from("<I", d, 0)[0]
    if magic not in (MH_MAGIC_64, MH_MAGIC):
        raise MachOError("not a Mach-O file")
    is64 = magic == MH_MAGIC_64
    cpu, _sub, ftype, ncmds, _sz, flags = struct.unpack_from("<iiIIII", d, 4)
    mo = MachO(arch={CPU_ARM64: "arm64", CPU_X86_64: "x86_64", CPU_ARM: "armv7"}.get(cpu, hex(cpu)),
               filetype=ftype, flags=flags, pie=bool(flags & MH_PIE),
               stack_exec=bool(flags & MH_ALLOW_STACK_EXECUTION), slices=archs)
    p = 32 if is64 else 28
    sections = []
    for _ in range(ncmds):
        if p + 8 > len(d):
            break
        cmd, cmdsize = struct.unpack_from("<II", d, p)
        if cmdsize < 8:
            break
        if cmd in (LC_SEGMENT_64, LC_SEGMENT):
            if cmd == LC_SEGMENT_64:
                nsects = struct.unpack_from("<I", d, p + 64)[0]
                sp, ssz = p + 72, 80
            else:
                nsects = struct.unpack_from("<I", d, p + 48)[0]
                sp, ssz = p + 56, 68
            for s in range(nsects):
                q = sp + s * ssz
                sect, seg = _cstr(d[q:q + 16]), _cstr(d[q + 16:q + 32])
                if cmd == LC_SEGMENT_64:
                    _addr, sz, off = struct.unpack_from("<QQI", d, q + 32)
                else:
                    _addr, sz, off = struct.unpack_from("<III", d, q + 32)
                sections.append((seg, sect, off, sz))
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", d, p + 8)
            esz = 16 if is64 else 12
            strtab = d[stroff:stroff + strsize]
            for i in range(min(nsyms, 2_000_000)):
                q = symoff + i * esz
                if q + esz > len(d):
                    break
                strx, ntype = struct.unpack_from("<IB", d, q)
                if ntype & 0xE0:  # stab / debug entries
                    mo.local_symbols += 1
                    continue
                name = _cstr(strtab[strx:strx + 256]) if strx < len(strtab) else ""
                if ntype & 0x0E == 0 and ntype & 0x01:
                    mo.imports.add(name)
                elif ntype & 0x01:
                    mo.exports_count += 1
                else:
                    mo.local_symbols += 1
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            noff = struct.unpack_from("<I", d, p + 8)[0]
            mo.libraries.append(_cstr(d[p + noff:p + cmdsize]))
        elif cmd == LC_RPATH:
            noff = struct.unpack_from("<I", d, p + 8)[0]
            mo.rpaths.append(_cstr(d[p + noff:p + cmdsize]))
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            _off, _size, cryptid = struct.unpack_from("<III", d, p + 8)
            mo.encrypted = cryptid != 0
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            mo.min_os = _ver(struct.unpack_from("<I", d, p + 8)[0])
        elif cmd == LC_BUILD_VERSION:
            _platform, minos = struct.unpack_from("<II", d, p + 8)
            mo.min_os = mo.min_os or _ver(minos)
        elif cmd == LC_CODE_SIGNATURE:
            off, size = struct.unpack_from("<II", d, p + 8)
            mo.has_code_signature = True
            mo.entitlements = _entitlements(d[off:off + size])
        p += cmdsize

    if want_strings:
        seen = set()
        for seg, sect, off, sz in sections:
            if sect not in STRING_SECTIONS or not off or off + sz > len(d) or sz > 40_000_000:
                continue
            blob = d[off:off + sz]
            if sect == "__ustring":
                txt = blob.decode("utf-16-le", "ignore")
                found = re.findall(r"[\x20-\x7e]{6,}", txt)
            else:
                found = [m.decode("utf-8", "ignore") for m in re.findall(rb"[\x20-\x7e]{4,}", blob)]
            for s in found:
                if s not in seen:
                    seen.add(s)
                    mo.strings.append(s)
    return mo


def _entitlements(blob: bytes) -> dict:
    if len(blob) < 12 or struct.unpack_from(">I", blob, 0)[0] != 0xFADE0CC0:
        return {}
    count = struct.unpack_from(">I", blob, 8)[0]
    for i in range(min(count, 64)):
        _typ, off = struct.unpack_from(">II", blob, 12 + i * 8)
        if off + 8 > len(blob):
            continue
        magic, length = struct.unpack_from(">II", blob, off)
        if magic == 0xFADE7171:  # XML entitlements
            try:
                return plistlib.loads(blob[off + 8:off + length])
            except Exception:
                return {}
    return {}
