"""Builders for synthetic test artifacts (binary AXML manifest, Mach-O, APK, IPA)."""
from __future__ import annotations

import io
import plistlib
import struct
import zipfile

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AXMLWriter:
    """Tiny binary-XML encoder: enough to build AndroidManifest.xml for tests."""

    def __init__(self):
        self.strings: list[str] = []
        self.chunks: list[bytes] = []

    def s(self, v: str) -> int:
        if v not in self.strings:
            self.strings.append(v)
        return self.strings.index(v)

    def start(self, tag: str, attrs: dict):
        # attrs: {"android:name": value} ; bools as Python bool
        recs = []
        for k, v in attrs.items():
            ns = self.s(ANDROID_NS) if k.startswith("android:") else 0xFFFFFFFF
            name = self.s(k.split(":", 1)[-1])
            if isinstance(v, bool):
                recs.append(struct.pack("<IIIHBBI", ns, name, 0xFFFFFFFF, 8, 0, 0x12, 0xFFFFFFFF if v else 0))
            elif isinstance(v, int):
                recs.append(struct.pack("<IIIHBBI", ns, name, 0xFFFFFFFF, 8, 0, 0x10, v))
            else:
                sv = self.s(v)
                recs.append(struct.pack("<IIIHBBI", ns, name, sv, 8, 0, 0x03, sv))
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, self.s(tag), 20, 20, len(recs), 0, 0, 0)
        body = struct.pack("<II", 1, 0xFFFFFFFF) + ext + b"".join(recs)
        self.chunks.append(struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body)

    def end(self, tag: str):
        body = struct.pack("<IIII", 1, 0xFFFFFFFF, 0xFFFFFFFF, self.s(tag))
        self.chunks.append(struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body)

    def build(self) -> bytes:
        self.s(ANDROID_NS)
        self.s("android")
        data = b""
        offs = []
        for st in self.strings:
            offs.append(len(data))
            enc = st.encode("utf-16-le")
            data += struct.pack("<H", len(st)) + enc + b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
        hdr = 28
        pool = struct.pack("<IIIII", len(self.strings), 0, 0, hdr + 4 * len(offs), 0)
        pool += struct.pack(f"<{len(offs)}I", *offs) + data
        pool = struct.pack("<HHI", 0x0001, hdr, 8 + len(pool)) + pool
        ns = struct.pack("<IIII", 1, 0xFFFFFFFF, self.s("android"), self.s(ANDROID_NS))
        start_ns = struct.pack("<HHI", 0x0100, 16, 8 + len(ns)) + ns
        body = pool + start_ns + b"".join(self.chunks)
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def vulnerable_manifest() -> bytes:
    w = AXMLWriter()
    w.start("manifest", {"package": "com.example.bank", "android:versionName": "1.0"})
    w.start("uses-sdk", {"android:minSdkVersion": 16, "android:targetSdkVersion": 26}); w.end("uses-sdk")
    w.start("uses-permission", {"android:name": "android.permission.READ_SMS"}); w.end("uses-permission")
    w.start("application", {"android:debuggable": True, "android:allowBackup": True})
    w.start("activity", {"android:name": ".MainActivity"})
    w.start("intent-filter", {})
    w.start("action", {"android:name": "android.intent.action.MAIN"}); w.end("action")
    w.start("category", {"android:name": "android.intent.category.LAUNCHER"}); w.end("category")
    w.end("intent-filter"); w.end("activity")
    w.start("activity", {"android:name": ".TransferActivity", "android:exported": True}); w.end("activity")
    w.start("provider", {"android:name": ".NotesProvider", "android:authorities": "com.example.bank.notes",
                         "android:exported": True}); w.end("provider")
    w.start("service", {"android:name": ".SafeService", "android:exported": False}); w.end("service")
    w.end("application"); w.end("manifest")
    return w.build()


def make_apk(manifest: bytes, extra: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return buf.getvalue()


def make_macho(imports: list[str], pie=True, strings: list[str] = (), entitlements: dict | None = None) -> bytes:
    """Minimal arm64 MH_EXECUTE with a __cstring section, LC_SYMTAB and an optional code signature."""
    cstr = b"".join(s.encode() + b"\x00" for s in strings) or b"\x00"
    strtab = b"\x00" + b"".join(n.encode() + b"\x00" for n in imports)
    ent_blob = b""
    if entitlements is not None:
        xml = plistlib.dumps(entitlements)
        blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
        ent_blob = struct.pack(">III", 0xFADE0CC0, 12 + 8 + len(blob), 1) + struct.pack(">II", 5, 20) + blob
    ncmds = 3 if ent_blob else 2
    seg_size = 72 + 80
    sym_size = 24
    cs_size = 16 if ent_blob else 0
    hdr_size = 32 + seg_size + sym_size + cs_size
    cstr_off = hdr_size
    sym_off = cstr_off + len(cstr)
    nlist = b""
    pos = 1
    for n in imports:
        nlist += struct.pack("<IBBHQ", pos, 0x01, 0, 0, 0)
        pos += len(n) + 1
    str_off = sym_off + len(nlist)
    cs_off = str_off + len(strtab)
    flags = 0x200000 if pie else 0
    out = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, ncmds, seg_size + sym_size + cs_size, flags, 0)
    seg = struct.pack("<II16sQQQQiiII", 0x19, seg_size, b"__TEXT", 0, 0, 0, 0, 5, 5, 1, 0)
    sect = struct.pack("<16s16sQQIIIIIIII", b"__cstring", b"__TEXT", 0, len(cstr), cstr_off, 0, 0, 0, 2, 0, 0, 0)
    out += seg + sect
    out += struct.pack("<IIIIII", 0x2, sym_size, sym_off, len(imports), str_off, len(strtab))
    if ent_blob:
        out += struct.pack("<IIII", 0x1D, 16, cs_off, len(ent_blob))
    return out + cstr + nlist + strtab + ent_blob


def make_ipa(info: dict, binary: bytes, extra: dict | None = None) -> bytes:
    buf = io.BytesIO()
    app = "Payload/Demo.app/"
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(app + "Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        z.writestr(app + info.get("CFBundleExecutable", "Demo"), binary)
        for k, v in (extra or {}).items():
            z.writestr(app + k, v)
    return buf.getvalue()
