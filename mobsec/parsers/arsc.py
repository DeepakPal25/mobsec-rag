"""resources.arsc: extract the global string pool (string resource values).

Full resource-table resolution is not needed for security checks: hardcoded
secrets in strings.xml end up in the global pool, which is what we scan.
"""
from __future__ import annotations

import struct

from .axml import parse_string_pool

RES_TABLE = 0x0002


def strings(data: bytes) -> list[str]:
    if len(data) < 12:
        return []
    ctype, hsize, _size = struct.unpack_from("<HHI", data, 0)
    if ctype != RES_TABLE:
        return []
    try:
        return parse_string_pool(data, hsize)
    except Exception:
        return []
