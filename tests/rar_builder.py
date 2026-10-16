"""Minimal writer for RAR 2.9 (RAR 4.x) test archives with STORED members.

Creating RAR archives needs WinRAR, which is not free software, so the tests
write the format themselves. Stored (method 0x30) members are a legal RAR
archive that every reader (rarfile, 7-Zip, unrar, unar, bsdtar) accepts, and
they let a test choose any member name, content, host OS and mode bits.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Iterable, Tuple

MARKER = b"Rar!\x1a\x07\x00"
_HOST_WIN, _HOST_UNIX = 2, 3
_LONG_BLOCK, _UNICODE = 0x8000, 0x0200


def _block(head_type: int, flags: int, body: bytes) -> bytes:
    size = 7 + len(body)
    after_crc = struct.pack("<BHH", head_type, flags, size) + body
    return struct.pack("<H", zlib.crc32(after_crc) & 0xFFFF) + after_crc


def _file(name: str, data: bytes, mode: int) -> bytes:
    raw = name.encode("utf-8")
    flags = _LONG_BLOCK
    try:
        raw.decode("ascii")
    except UnicodeDecodeError:
        # RAR's "unicode" names: a byte form, NUL, then RAR's packed UTF-16
        # (accepted by rarfile, 7-Zip and unar).
        flags |= _UNICODE
        raw = name.encode("utf-8") + b"\x00" + _rar_unicode(name)
    host = _HOST_UNIX if mode else _HOST_WIN
    attr = mode if mode else 0x20                     # FILE_ATTRIBUTE_ARCHIVE
    body = struct.pack("<IIBIIBBHI", len(data), len(data), host, zlib.crc32(data),
                       0x5A210000, 20, 0x30, len(raw), attr) + raw
    return _block(0x74, flags, body) + data


def _rar_unicode(name: str) -> bytes:
    """RAR's compressed UTF-16 name encoding, using only the 'two bytes' opcode."""
    out = bytearray([0])                               # high byte (unused by opcode 2)
    units = name.encode("utf-16-le")
    pairs = [units[i:i + 2] for i in range(0, len(units), 2)]
    for start in range(0, len(pairs), 4):
        group = pairs[start:start + 4]
        flag = 0
        for j in range(len(group)):
            flag |= 2 << (6 - 2 * j)                   # opcode 2: low byte, high byte
        out.append(flag)
        for pair in group:
            out += pair
    return bytes(out)


def build_rar(path: Path, members: Iterable[Tuple[str, bytes]] = (),
              unix_modes: dict = None) -> Path:
    """`members` are (name, data); `unix_modes` maps a name to its st_mode (e.g.
    0o120777 makes the entry a symbolic link whose data is the link target)."""
    unix_modes = unix_modes or {}
    out = bytearray(MARKER)
    out += _block(0x73, 0, b"\x00" * 6)                # main archive header
    for name, data in members:
        out += _file(name, data, unix_modes.get(name, 0))
    out += _block(0x7B, 0x4000, b"")                   # end of archive
    path = Path(path)
    path.write_bytes(bytes(out))
    return path
