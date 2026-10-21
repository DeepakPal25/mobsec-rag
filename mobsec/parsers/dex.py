"""Dalvik Executable (DEX) parser.

Extracts strings, type/method/field references and class definitions, and walks
method bytecode to record, for every method, which APIs it invokes and which
string constants it loads. That lets rules report *where* (class->method) an
insecure API is used instead of only "somewhere in the app".
"""
from __future__ import annotations

import struct
from array import array
from collections import defaultdict
from dataclasses import dataclass, field


class DexError(ValueError):
    pass


def _uleb(data: bytes, p: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = data[p]; p += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, p
        shift += 7


def _mutf8(b: bytes) -> str:
    # good enough for MUTF-8: fix the 0xC0 0x80 NUL encoding, then decode leniently
    return b.replace(b"\xc0\x80", b"\x00").decode("utf-8", "replace")


# code-unit length of each opcode (Dalvik formats); payloads are handled separately
_SIZE = [1] * 256
for op, n in {
    0x02: 2, 0x03: 3, 0x05: 2, 0x06: 3, 0x08: 2, 0x09: 3, 0x13: 2, 0x14: 3, 0x15: 2,
    0x16: 2, 0x17: 3, 0x18: 5, 0x19: 2, 0x1a: 2, 0x1b: 3, 0x1c: 2, 0x1f: 2, 0x20: 2,
    0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x29: 2, 0x2a: 3, 0x2b: 3, 0x2c: 3,
    0xfa: 4, 0xfb: 4, 0xfc: 3, 0xfd: 3, 0xfe: 2, 0xff: 2,
}.items():
    _SIZE[op] = n
for rng, n in (((0x2d, 0x3e), 2), ((0x44, 0x6e), 2), ((0x6e, 0x73), 3), ((0x74, 0x79), 3),
               ((0x90, 0xb0), 2), ((0xd0, 0xe3), 2)):
    for op in range(*rng):
        _SIZE[op] = n

INVOKE_OPS = set(range(0x6e, 0x73)) | set(range(0x74, 0x79))
FIELD_OPS = set(range(0x52, 0x6e))

# calls whose constant (literal) arguments we record, e.g. setJavaScriptEnabled(true)
LITERAL_ARG_METHODS = {
    "setJavaScriptEnabled", "setAllowFileAccess", "setAllowFileAccessFromFileURLs",
    "setAllowUniversalAccessFromFileURLs", "setWebContentsDebuggingEnabled", "setAllowContentAccess",
    "getSharedPreferences", "openFileOutput", "openOrCreateDatabase", "setFlags", "addFlags",
    "getActivity", "getService", "getBroadcast", "getActivities", "setMixedContentMode",
}


@dataclass
class Method:
    idx: int
    cls: str          # Lcom/example/Foo;
    name: str
    proto: str        # (Ljava/lang/String;)V
    code_units: int = 0
    insns: tuple = ()  # first few code units, for tiny-method checks
    calls: set = field(default_factory=set)    # method_idx invoked
    strings: set = field(default_factory=set)  # string_idx loaded
    fields: set = field(default_factory=set)   # field_idx accessed
    literal_calls: list = field(default_factory=list)  # (callee_idx, (arg literals or None, ...))
    has_array_data: bool = False                        # fill-array-data payload (static byte[])

    @property
    def sig(self) -> str:
        return f"{self.cls}->{self.name}{self.proto}"


@dataclass
class ClassDef:
    name: str
    superclass: str
    interfaces: list
    access: int
    methods: list  # method idxs defined in this class
    source_file: str = ""


class Dex:
    def __init__(self, data: bytes, name: str = "classes.dex"):
        if data[:4] != b"dex\n":
            raise DexError("bad magic")
        self.data, self.name = data, name
        h = struct.unpack_from("<20I", data, 0x38)
        (self.n_str, str_off, self.n_type, type_off, self.n_proto, proto_off,
         self.n_field, field_off, self.n_meth, meth_off, self.n_cls, cls_off) = h[:12]
        str_offs = struct.unpack_from(f"<{self.n_str}I", data, str_off)
        self.strings = []
        for so in str_offs:
            _, p = _uleb(data, so)
            e = data.index(b"\x00", p)
            self.strings.append(_mutf8(data[p:e]))
        self.types = [self.strings[i] for i in struct.unpack_from(f"<{self.n_type}I", data, type_off)]
        self.protos = []
        for i in range(self.n_proto):
            _shorty, ret, params_off = struct.unpack_from("<III", data, proto_off + i * 12)
            self.protos.append("(" + "".join(self._type_list(params_off)) + ")" + self.types[ret])
        self.field_refs = []
        for i in range(self.n_field):
            c, t, nm = struct.unpack_from("<HHI", data, field_off + i * 8)
            self.field_refs.append((self.types[c], self.strings[nm], self.types[t]))
        self.methods: list[Method] = []
        for i in range(self.n_meth):
            c, pr, nm = struct.unpack_from("<HHI", data, meth_off + i * 8)
            self.methods.append(Method(i, self.types[c], self.strings[nm], self.protos[pr]))
        self._lit_idx = {m.idx for m in self.methods if m.name in LITERAL_ARG_METHODS}
        self.classes: list[ClassDef] = []
        for i in range(self.n_cls):
            (cidx, acc, sup, ifaces, _src, _ann, cdata, _sv) = struct.unpack_from("<8I", data, cls_off + i * 32)
            cd = ClassDef(self.types[cidx], self.types[sup] if sup != 0xFFFFFFFF else "",
                          self._type_list(ifaces), acc, [],
                          self.strings[_src] if _src < len(self.strings) else "")
            if cdata:
                self._class_data(cdata, cd)
            self.classes.append(cd)

    def _type_list(self, off: int) -> list[str]:
        if not off:
            return []
        n = struct.unpack_from("<I", self.data, off)[0]
        return [self.types[t] for t in struct.unpack_from(f"<{n}H", self.data, off + 4)]

    def _class_data(self, off: int, cd: ClassDef):
        d = self.data
        sf, p = _uleb(d, off); inf, p = _uleb(d, p); dm, p = _uleb(d, p); vm, p = _uleb(d, p)
        for _ in range(sf + inf):
            _, p = _uleb(d, p); _, p = _uleb(d, p)
        for count in (dm, vm):
            idx = 0
            for _ in range(count):
                diff, p = _uleb(d, p); _acc, p = _uleb(d, p); code_off, p = _uleb(d, p)
                idx += diff
                cd.methods.append(idx)
                if code_off and idx < len(self.methods):
                    self._walk_code(code_off, self.methods[idx])

    def _walk_code(self, off: int, m: Method):
        d = self.data
        n_units = struct.unpack_from("<I", d, off + 12)[0]
        start = off + 16
        if start + n_units * 2 > len(d):
            return
        ins = array("H")
        ins.frombytes(d[start:start + n_units * 2])
        if struct.pack("=H", 1) != b"\x01\x00":
            ins.byteswap()
        m.code_units = n_units
        m.insns = tuple(ins[:6])
        i = 0
        calls, strs, flds = m.calls, m.strings, m.fields
        consts: dict[int, int] = {}
        lit_names = self._lit_idx
        while i < n_units:
            u = ins[i]
            op = u & 0xFF
            if op == 0x00 and u in (0x0100, 0x0200, 0x0300):  # payload pseudo-instructions
                if i + 1 >= n_units:
                    break
                if u == 0x0100:
                    i += 4 + ins[i + 1] * 2
                elif u == 0x0200:
                    i += 2 + ins[i + 1] * 4
                else:
                    m.has_array_data = True
                    width = ins[i + 1]
                    size = ins[i + 2] | (ins[i + 3] << 16) if i + 3 < n_units else 0
                    i += 4 + (size * width + 1) // 2
                continue
            if op == 0x12:  # const/4 vA, #+B
                lit = u >> 12
                consts[(u >> 8) & 0xF] = lit - 16 if lit > 7 else lit
            elif op == 0x13 and i + 1 < n_units:  # const/16
                v = ins[i + 1]
                consts[u >> 8] = v - 0x10000 if v > 0x7FFF else v
            elif op == 0x14 and i + 2 < n_units:  # const
                consts[u >> 8] = ins[i + 1] | (ins[i + 2] << 16)
            elif op == 0x15 and i + 1 < n_units:  # const/high16
                consts[u >> 8] = ins[i + 1] << 16
            if i + 1 < n_units:
                if op in INVOKE_OPS or op in (0xfa, 0xfb):
                    calls.add(ins[i + 1])
                    if op < 0x73 and ins[i + 1] in lit_names and i + 2 < n_units:
                        cnt, g, w = u >> 12, (u >> 8) & 0xF, ins[i + 2]
                        regs = [w & 0xF, (w >> 4) & 0xF, (w >> 8) & 0xF, (w >> 12) & 0xF, g][:cnt]
                        m.literal_calls.append((ins[i + 1], tuple(consts.get(r) for r in regs)))
                elif op == 0x1a:
                    strs.add(ins[i + 1])
                elif op == 0x1b and i + 2 < n_units:
                    strs.add(ins[i + 1] | (ins[i + 2] << 16))
                elif op in FIELD_OPS:
                    flds.add(ins[i + 1])
            i += _SIZE[op]


class DexIndex:
    """Merged view over all classes*.dex files of an APK."""

    def __init__(self, dexes: list[Dex]):
        self.dexes = dexes
        self.strings: set[str] = set()
        self.classes: dict[str, tuple[Dex, ClassDef]] = {}
        # API signature "Lpkg/Cls;->name" -> list of caller Methods (defined in this app)
        self.callers: dict[str, list] = defaultdict(list)
        self.string_users: dict[str, list] = defaultdict(list)
        self.field_users: dict[str, list] = defaultdict(list)
        self.literal_calls: dict[str, list] = defaultdict(list)
        self.defined: list[tuple[Dex, Method]] = []
        for dx in dexes:
            self.strings.update(dx.strings)
            for cd in dx.classes:
                self.classes[cd.name] = (dx, cd)
                for mi in cd.methods:
                    if mi >= len(dx.methods):
                        continue
                    m = dx.methods[mi]
                    self.defined.append((dx, m))
                    for c in m.calls:
                        if c < len(dx.methods):
                            t = dx.methods[c]
                            self.callers[f"{t.cls}->{t.name}"].append((dx, m, t.proto))
                    for s in m.strings:
                        if s < len(dx.strings):
                            self.string_users[dx.strings[s]].append((dx, m))
                    for callee, lits in m.literal_calls:
                        t = dx.methods[callee]
                        self.literal_calls[f"{t.cls}->{t.name}"].append((dx, m, lits))
                    for f in m.fields:
                        if f < len(dx.field_refs):
                            c, n, _ = dx.field_refs[f]
                            self.field_users[f"{c}->{n}"].append((dx, m))

    def calls_to(self, api: str, proto_prefix: str | None = None):
        """Callers of `Lpkg/Cls;->method`, optionally filtered by proto prefix."""
        out = self.callers.get(api, [])
        if proto_prefix is not None:
            out = [x for x in out if x[2].startswith(proto_prefix)]
        return [(dx, m) for dx, m, _ in out]

    def method_strings(self, dx: Dex, m: Method) -> list[str]:
        return [dx.strings[s] for s in m.strings if s < len(dx.strings)]

    def method_calls(self, dx: Dex, m: Method) -> list[str]:
        out = []
        for c in m.calls:
            if c < len(dx.methods):
                t = dx.methods[c]
                out.append(f"{t.cls}->{t.name}")
        return out

    def implementors(self, iface: str):
        return [(dx, cd) for dx, cd in self.classes.values() if iface in cd.interfaces]

    def subclasses(self, sup: str):
        return [(dx, cd) for dx, cd in self.classes.values() if cd.superclass == sup]

    def class_methods(self, dx: Dex, cd: ClassDef):
        return [dx.methods[i] for i in cd.methods if i < len(dx.methods)]


def pretty(m: Method) -> str:
    """Lcom/a/B; + foo -> com.a.B.foo()"""
    return m.cls[1:-1].replace("/", ".") + "." + m.name + "()"
