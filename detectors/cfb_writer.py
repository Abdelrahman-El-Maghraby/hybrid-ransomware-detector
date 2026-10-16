"""Minimal MS-CFB (OLE compound file) writer.

Python has no library that *writes* compound files. MailGuard needs one to turn
an OLE object stored inside an Outlook item (an embedded Word or Excel file is a
storage, not a byte stream) back into a standalone .doc / .xls that the macro
and YARA layers can read; the test suite uses it to build .msg files.

The layout is the simplest legal one:

* 512-byte sectors; streams under 4096 bytes live in 64-byte mini sectors
  inside the root entry's mini stream (as the spec requires), larger ones in
  regular sectors;
* directory siblings chained through the right-sibling pointer (a valid,
  if unbalanced, red-black tree with every node black);
* the FAT is addressed from the header only, which caps a file at about 7 MB.
  Larger trees raise ValueError.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Tuple, Union

SECTOR = 512
MINI = 64
CUTOFF = 4096
FREESECT, ENDOFCHAIN, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF
MAX_TREE_BYTES = 6 * 1024 * 1024        # comfortably under the header-only FAT limit

Tree = Dict[str, Union[bytes, "Tree"]]


def write_cfb(tree: Tree) -> bytes:
    """Serialise {name: bytes | {nested storage}} as an MS-CFB v3 compound file."""
    entries: List[dict] = []                   # directory entries in id order
    streams: List[Tuple[int, bytes]] = []      # (entry id, data)

    def add(name: str, kind: int) -> int:
        entries.append({"name": name, "type": kind, "left": NOSTREAM, "right": NOSTREAM,
                        "child": NOSTREAM, "start": ENDOFCHAIN, "size": 0})
        return len(entries) - 1

    def add_children(parent: int, node: Tree) -> None:
        prev = None
        # CFB orders siblings by (length, upper-case name); keep that order.
        for name in sorted(node, key=lambda n: (len(n), n.upper())):
            value = node[name]
            eid = add(name, 1 if isinstance(value, dict) else 2)
            if prev is None:
                entries[parent]["child"] = eid
            else:
                entries[prev]["right"] = eid
            prev = eid
            if isinstance(value, dict):
                add_children(eid, value)
            else:
                streams.append((eid, value))

    add("Root Entry", 5)
    add_children(0, tree)

    # Lay out: big streams, mini stream, mini FAT, directory, FAT.
    fat: List[int] = []
    body = bytearray()
    minifat: List[int] = []
    ministream = bytearray()

    def place(data: bytes) -> int:
        n = max(1, -(-len(data) // SECTOR))
        start = len(fat)
        for i in range(n):
            fat.append(start + i + 1 if i < n - 1 else ENDOFCHAIN)
        body.extend(data.ljust(n * SECTOR, b"\x00"))
        return start

    for eid, data in streams:
        if not data:
            continue
        entries[eid]["size"] = len(data)
        if len(data) >= CUTOFF:
            entries[eid]["start"] = place(data)
            continue
        n = -(-len(data) // MINI)
        start = len(minifat)
        for i in range(n):
            minifat.append(start + i + 1 if i < n - 1 else ENDOFCHAIN)
        ministream.extend(data.ljust(n * MINI, b"\x00"))
        entries[eid]["start"] = start

    minifat_start, n_minifat = ENDOFCHAIN, 0
    if ministream:
        entries[0]["start"] = place(bytes(ministream))
        entries[0]["size"] = len(ministream)
        mf = minifat + [FREESECT] * (-len(minifat) % (SECTOR // 4))
        minifat_start = place(struct.pack(f"<{len(mf)}I", *mf))
        n_minifat = len(mf) * 4 // SECTOR

    directory = bytearray()
    for e in entries:
        name = e["name"].encode("utf-16-le")[:62]
        directory += struct.pack(
            "<64sHBBIII16sIQQIQ",
            name.ljust(64, b"\x00"), len(name) + 2, e["type"], 1,
            e["left"], e["right"], e["child"], b"\x00" * 16, 0, 0, 0,
            e["start"], e["size"])
    dir_start = place(bytes(directory))

    # FAT sectors describe themselves too: grow until it fits.
    n_fat = 1
    while (len(fat) + n_fat) > n_fat * (SECTOR // 4):
        n_fat += 1
    fat_start = len(fat)
    fat.extend([FATSECT] * n_fat)
    fat.extend([FREESECT] * (n_fat * (SECTOR // 4) - len(fat)))
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    if n_fat > 109:
        raise ValueError("compound file too large for a header-only DIFAT (~7 MB)")

    difat = [fat_start + i for i in range(n_fat)] + [FREESECT] * (109 - n_fat)
    header = struct.pack(
        "<8s16sHHHHH6sIIIIIIIII",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"\x00" * 16, 0x3E, 3, 0xFFFE, 9, 6,
        b"\x00" * 6, 0, n_fat, dir_start, 0, CUTOFF,
        minifat_start, n_minifat, ENDOFCHAIN, 0)
    header += struct.pack("<109I", *difat)
    assert len(header) == SECTOR
    return bytes(header) + bytes(body) + fat_bytes
