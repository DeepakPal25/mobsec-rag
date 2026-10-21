import struct

import pytest

from mobsec.parsers import axml, macho, elf
from helpers import vulnerable_manifest, make_macho


def test_axml_roundtrip():
    root = axml.parse(vulnerable_manifest())
    assert root.tag == "manifest"
    assert root.get("package") == "com.example.bank"
    app = root.find("application")
    assert app.get("android:debuggable") == "true"
    names = [a.get("android:name") for a in app.findall("activity")]
    assert names == [".MainActivity", ".TransferActivity"]
    assert root.find("uses-sdk").get("android:minSdkVersion") == "16"


def test_axml_rejects_garbage():
    with pytest.raises(axml.AXMLError):
        axml.parse(b"<?xml version='1.0'?><manifest/>")


def test_macho_imports_flags_entitlements():
    data = make_macho(["_CC_MD5", "___stack_chk_guard", "_objc_release", "_NSLog"], pie=False,
                      strings=["http://api.example.org/v1", "hello world"], entitlements={"get-task-allow": True})
    mo = macho.parse(data)
    assert mo.arch == "arm64"
    assert not mo.pie
    assert mo.stack_canary and mo.arc
    assert "_CC_MD5" in mo.imports
    assert mo.entitlements == {"get-task-allow": True}
    assert "http://api.example.org/v1" in mo.strings


def test_macho_is_macho_vs_java_class():
    assert macho.is_macho(make_macho([])[:8])
    java_class = b"\xca\xfe\xba\xbe\x00\x00\x00\x34"  # Java class magic + version 52
    assert not macho.is_macho(java_class)


def test_elf_minimal():
    # 64-bit little-endian ELF header with no program/section headers -> NX unknown => False
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    hdr += struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    e = elf.parse(hdr)
    assert e.bits == 64 and e.nx is False and e.relro == "none"
