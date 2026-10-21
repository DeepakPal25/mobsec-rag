"""Android binary XML (AXML) parser.

Decodes AndroidManifest.xml and compiled res/xml/*.xml files into
xml.etree.ElementTree elements. Attributes in the android namespace are keyed
as "android:<name>". Attribute names stripped by obfuscators are recovered
from the resource-id map.
"""
from __future__ import annotations

import struct
import xml.etree.ElementTree as ET

RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# android.R.attr ids for attributes we care about (used when names are stripped)
ATTR_IDS = {
    0x01010003: "name", 0x01010006: "permission", 0x01010007: "readPermission",
    0x01010008: "writePermission", 0x01010009: "protectionLevel", 0x0101000b: "sharedUserId",
    0x0101000e: "enabled", 0x0101000f: "debuggable", 0x01010010: "exported",
    0x01010012: "taskAffinity", 0x01010018: "authorities", 0x0101001b: "grantUriPermissions",
    0x0101001d: "launchMode", 0x01010024: "value", 0x01010027: "scheme", 0x01010028: "host",
    0x0101002a: "path", 0x0101002b: "pathPrefix", 0x0101002c: "pathPattern",
    0x0101020c: "minSdkVersion", 0x01010270: "targetSdkVersion", 0x01010271: "maxSdkVersion",
    0x01010272: "testOnly", 0x01010280: "allowBackup", 0x0101021b: "versionCode",
    0x0101021c: "versionName", 0x010104ec: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig",
    0x01010473: "fullBackupContent", 0x010104ea: "autoVerify", 0x01010011: "allowTaskReparenting",
    0x0101000c: "persistent", 0x01010001: "label", 0x0101061a: "requestLegacyExternalStorage",
    0x01010021: "multiprocess", 0x01010020: "process", 0x0101001e: "clearTaskOnLaunch",
}

TYPE_NULL, TYPE_REFERENCE, TYPE_ATTRIBUTE, TYPE_STRING = 0x00, 0x01, 0x02, 0x03
TYPE_FLOAT, TYPE_INT_DEC, TYPE_INT_HEX, TYPE_INT_BOOLEAN = 0x04, 0x10, 0x11, 0x12


class AXMLError(ValueError):
    pass


def parse_string_pool(data: bytes, off: int) -> list[str]:
    """Parse a ResStringPool chunk starting at `off` (shared with resources.arsc)."""
    ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
    if ctype != RES_STRING_POOL:
        raise AXMLError("not a string pool")
    count, _styles, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", data, off + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", data, off + hsize) if count else ()
    base = off + strings_start
    out = []
    for o in offsets:
        p = base + o
        try:
            if utf8:
                n = data[p]; p += 1
                if n & 0x80:
                    p += 1
                n = data[p]; p += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | data[p]; p += 1
                out.append(data[p:p + n].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", data, p)[0]; p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]; p += 2
                out.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


def _value(dtype: int, data: int, raw: int, strings: list[str]) -> str:
    if raw != 0xFFFFFFFF and raw < len(strings):
        return strings[raw]
    if dtype == TYPE_STRING:
        return strings[data] if data < len(strings) else ""
    if dtype == TYPE_INT_BOOLEAN:
        return "true" if data else "false"
    if dtype == TYPE_INT_DEC:
        return str(struct.unpack("<i", struct.pack("<I", data))[0])
    if dtype == TYPE_INT_HEX:
        return hex(data)
    if dtype == TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if dtype == TYPE_ATTRIBUTE:
        return f"?0x{data:08x}"
    if dtype == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", data))[0])
    if dtype == TYPE_NULL:
        return ""
    return str(data)


def parse(data: bytes) -> ET.Element:
    try:
        return _parse(data)
    except (struct.error, IndexError, OverflowError, MemoryError) as e:
        raise AXMLError(f"corrupt binary XML: {e}") from None


def _parse(data: bytes) -> ET.Element:
    if len(data) < 8:
        raise AXMLError("file too small")
    ctype, hsize, _size = struct.unpack_from("<HHI", data, 0)
    if ctype != RES_XML:
        raise AXMLError("not binary XML")
    strings: list[str] = []
    res_ids: list[int] = []
    ns_prefix: dict[str, str] = {}
    root = None
    stack: list[ET.Element] = []
    off = hsize
    n = len(data)
    while off + 8 <= n:
        ctype, chsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8 or off + csize > n:
            break
        if ctype == RES_STRING_POOL:
            strings = parse_string_pool(data, off)
        elif ctype == RES_XML_RESOURCE_MAP:
            cnt = (csize - chsize) // 4
            res_ids = list(struct.unpack_from(f"<{cnt}I", data, off + chsize))
        elif ctype == RES_XML_START_NS:
            prefix, uri = struct.unpack_from("<II", data, off + chsize)
            if uri < len(strings) and prefix < len(strings):
                ns_prefix[strings[uri]] = strings[prefix]
        elif ctype == RES_XML_START_ELEMENT:
            ext = off + chsize
            _ns, name, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, ext)
            tag = strings[name] if name < len(strings) else "?"
            el = ET.Element(tag)
            for i in range(attr_count):
                a = ext + attr_start + i * attr_size
                ans, aname, raw, _vs, _r0, dtype, vdata = struct.unpack_from("<IIIHBBI", data, a)
                key = strings[aname] if aname < len(strings) else ""
                if (not key or not key.isprintable()) and aname < len(res_ids):
                    key = ATTR_IDS.get(res_ids[aname], f"attr_{res_ids[aname]:08x}")
                elif aname < len(res_ids) and res_ids[aname] in ATTR_IDS:
                    key = ATTR_IDS[res_ids[aname]]  # trust the id over a renamed string
                ns_uri = strings[ans] if ans != 0xFFFFFFFF and ans < len(strings) else ""
                if ns_uri == ANDROID_NS or (aname < len(res_ids) and res_ids[aname] >> 24 == 0x01):
                    key = "android:" + key
                elif ns_uri:
                    key = ns_prefix.get(ns_uri, "ns") + ":" + key
                el.set(key, _value(dtype, vdata, raw, strings))
            if stack:
                stack[-1].append(el)
            else:
                root = el
            stack.append(el)
        elif ctype == RES_XML_END_ELEMENT:
            if stack:
                stack.pop()
        off += csize
    if root is None:
        raise AXMLError("no root element")
    return root


def to_string(el: ET.Element) -> str:
    ET.indent(el)
    return ET.tostring(el, encoding="unicode")
