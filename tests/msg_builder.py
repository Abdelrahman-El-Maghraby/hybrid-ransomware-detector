"""Builder for Outlook .msg test files.

The compound-file writer itself lives in detectors/cfb_writer.py (MailGuard
uses it too). Only the MAPI property streams MailAnalyzer reads are emitted.
"""

from __future__ import annotations

import struct
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Tuple, Union

from detectors.cfb_writer import Tree, write_cfb  # noqa: F401  (re-exported)


@dataclass
class Ole:
    """An OLE object attachment (PR_ATTACH_METHOD = ATTACH_OLE): `tree` is the
    object's storage. `method=False` leaves PR_ATTACH_METHOD out, as some
    exporters do, so the reader has to tell objects from messages by content."""
    tree: Tree
    method: bool = True


def attach_properties(method: int) -> bytes:
    """An attachment's __properties_version1.0 stream holding PR_ATTACH_METHOD."""
    return b"\x00" * 8 + struct.pack("<IIQ", 0x37050003, 6, method)


def ole10native(label: str, data: bytes, src_path: str = "", temp_path: str = "") -> bytes:
    """The Packager "\x01Ole10Native" stream: a file wrapped as an OLE object."""
    src_path = src_path or "C:\\Users\\x\\" + label
    temp_path = temp_path or "C:\\Users\\x\\AppData\\Local\\Temp\\" + label
    body = (struct.pack("<H", 2) + label.encode("latin-1") + b"\x00"
            + src_path.encode("latin-1") + b"\x00" + struct.pack("<HH", 0, 3)
            + struct.pack("<I", len(temp_path) + 1) + temp_path.encode("latin-1") + b"\x00"
            + struct.pack("<I", len(data)) + data)
    return struct.pack("<I", len(body)) + body


def compobj(user_type: str, prog_id: str) -> bytes:
    """A "\x01CompObj" stream naming the object's ProgID."""
    def ansi(text: str) -> bytes:
        raw = text.encode("latin-1") + b"\x00"
        return struct.pack("<I", len(raw)) + raw
    return (struct.pack("<HHI16s", 1, 0xFFFE, 0x0A03, b"\x00" * 16)[:28].ljust(28, b"\x00")
            + ansi(user_type) + struct.pack("<I", 0) + ansi(prog_id))


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def msg_tree(subject: str = "", sender_name: str = "", sender_email: str = "",
             transport_headers: str = "", body: str = "", html: Optional[str] = None,
             attachments: Tuple[Tuple[str, Union[bytes, Tree]], ...] = ()) -> Tree:
    """The MAPI property streams of one message. An attachment whose data is a
    dict (another msg_tree) is an embedded Outlook item (PR_ATTACH_DATA_OBJ)."""
    root: Tree = {}
    if subject:
        root["__substg1.0_0037001F"] = _utf16(subject)
    if sender_name:
        root["__substg1.0_0C1A001F"] = _utf16(sender_name)
    if sender_email:
        root["__substg1.0_0C1F001F"] = _utf16(sender_email)
    if transport_headers:
        root["__substg1.0_007D001F"] = _utf16(transport_headers)
    if body:
        root["__substg1.0_1000001F"] = _utf16(body)
    if html is not None:
        root["__substg1.0_10130102"] = html.encode("utf-8")
    for i, (name, data) in enumerate(attachments):
        storage: Tree = {"__substg1.0_3001001F": _utf16(name)}       # PR_DISPLAY_NAME
        if isinstance(data, Ole):
            storage["__substg1.0_3701000D"] = data.tree              # OLE object
            if data.method:
                storage["__properties_version1.0"] = attach_properties(6)
        elif isinstance(data, dict):
            storage["__substg1.0_3701000D"] = data                   # embedded message
            storage["__properties_version1.0"] = attach_properties(5)
        else:
            storage["__substg1.0_3707001F"] = _utf16(name)
            storage["__substg1.0_37010102"] = data
        root[f"__attach_version1.0_#{i:08X}"] = storage
    return root


def build_msg(path: Path, attachments: Tuple[Tuple[str, Union[bytes, Tree]], ...] = (),
              **props) -> Path:
    path.write_bytes(write_cfb(msg_tree(attachments=attachments, **props)))
    return path
