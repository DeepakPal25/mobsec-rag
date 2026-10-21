"""ELF parser for Android native libraries (lib/<abi>/*.so)."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

PT_GNU_STACK, PT_GNU_RELRO, PT_DYNAMIC = 0x6474E551, 0x6474E552, 2
DT_NULL, DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_FLAGS, DT_FLAGS_1, DT_TEXTREL = 0, 1, 15, 29, 30, 0x6FFFFFFB, 22
DF_BIND_NOW, DF_TEXTREL, DF_1_NOW = 0x8, 0x4, 0x1
SHT_DYNSYM, SHT_SYMTAB = 11, 2

DANGEROUS_FUNCS = {"strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
                   "system", "popen", "execl", "execve", "memcpy", "strncpy", "rand", "srand"}


class ELFError(ValueError):
    pass


@dataclass
class ELF:
    bits: int = 0
    machine: int = 0
    nx: bool = True
    relro: str = "none"       # none | partial | full
    textrel: bool = False
    stripped: bool = True
    imports: set = field(default_factory=set)
    exports: set = field(default_factory=set)
    needed: list = field(default_factory=list)
    rpath: str = ""

    @property
    def stack_canary(self) -> bool:
        return "__stack_chk_fail" in self.imports or "__stack_chk_guard" in self.imports

    @property
    def fortify(self) -> bool:
        return any(s.endswith("_chk") and s != "__stack_chk_fail" for s in self.imports)

    @property
    def dangerous(self) -> list:
        return sorted(self.imports & DANGEROUS_FUNCS)


def parse(data: bytes) -> ELF:
    try:
        return _parse(data)
    except (struct.error, IndexError, OverflowError, MemoryError) as e:
        raise ELFError(f"corrupt ELF: {e}") from None


def _parse(data: bytes) -> ELF:
    if data[:4] != b"\x7fELF":
        raise ELFError("not ELF")
    cls, enc = data[4], data[5]
    e = "<" if enc == 1 else ">"
    is64 = cls == 2
    out = ELF(bits=64 if is64 else 32)
    if is64:
        (_t, mach, _v, _entry, phoff, shoff, _f, _eh, phentsize, phnum, shentsize, shnum, _shstrndx) = \
            struct.unpack_from(e + "HHIQQQIHHHHHH", data, 16)
    else:
        (_t, mach, _v, _entry, phoff, shoff, _f, _eh, phentsize, phnum, shentsize, shnum, _shstrndx) = \
            struct.unpack_from(e + "HHIIIIIHHHHHH", data, 16)
    out.machine = mach
    has_stack_hdr, dyn = False, None
    for i in range(phnum):
        q = phoff + i * phentsize
        if is64:
            ptype, pflags, poff, _va, _pa, pfsz = struct.unpack_from(e + "IIQQQQ", data, q)
        else:
            ptype, poff, _va, _pa, pfsz, _msz, pflags = struct.unpack_from(e + "IIIIIII", data, q)
        if ptype == PT_GNU_STACK:
            has_stack_hdr = True
            out.nx = not (pflags & 1)
        elif ptype == PT_GNU_RELRO:
            out.relro = "partial"
        elif ptype == PT_DYNAMIC:
            dyn = (poff, pfsz)
    if not has_stack_hdr:
        out.nx = False

    # section headers: symbol tables
    sects = []
    for i in range(shnum):
        q = shoff + i * shentsize
        if q + shentsize > len(data):
            break
        if is64:
            _n, st, _fl, _a, off, size, link, _i, _al, esz = struct.unpack_from(e + "IIQQQQIIQQ", data, q)
        else:
            _n, st, _fl, _a, off, size, link, _i, _al, esz = struct.unpack_from(e + "IIIIIIIIII", data, q)
        sects.append((st, off, size, link, esz))
    dynstr = b""
    for st, off, size, link, esz in sects:
        if st == SHT_SYMTAB:
            out.stripped = False
        if st != SHT_DYNSYM or not esz or link >= len(sects):
            continue
        _, soff, ssize, _, _ = sects[link]
        dynstr = data[soff:soff + ssize]
        for k in range(size // esz):
            q = off + k * esz
            if is64:
                name, info, _o, shndx = struct.unpack_from(e + "IBBH", data, q)
            else:
                name, _val, _sz, info, _o, shndx = struct.unpack_from(e + "IIIBBH", data, q)
            nm = dynstr[name:dynstr.find(b"\x00", name)].decode("ascii", "ignore")
            if not nm:
                continue
            (out.imports if shndx == 0 else out.exports).add(nm)

    if dyn:
        off, size = dyn
        step = 16 if is64 else 8
        fmt = e + ("qQ" if is64 else "iI")
        for k in range(size // step):
            tag, val = struct.unpack_from(fmt, data, off + k * step)
            if tag == DT_NULL:
                break
            if tag == DT_FLAGS and val & DF_BIND_NOW or tag == DT_FLAGS_1 and val & DF_1_NOW:
                if out.relro == "partial":
                    out.relro = "full"
            if tag == DT_TEXTREL or (tag == DT_FLAGS and val & DF_TEXTREL):
                out.textrel = True
            if tag in (DT_NEEDED, DT_RPATH, DT_RUNPATH) and dynstr:
                s = dynstr[val:dynstr.find(b"\x00", val)].decode("ascii", "ignore")
                if tag == DT_NEEDED:
                    out.needed.append(s)
                else:
                    out.rpath = s
    return out
