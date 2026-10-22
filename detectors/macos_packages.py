"""
Readers for macOS installer packages (.pkg) and disk images (.dmg).

WHY
---
On macOS, malware is shipped the way software is: as a disk image the user
opens and drags an app out of (Atomic/AMOS, Cuckoo and Poseidon stealers), or
as an installer package whose `preinstall` / `postinstall` scripts run as root
while the progress bar moves. Without these readers a .dmg or .pkg is one
opaque blob to the scanner.

PKG (pure Python, no external tool)
  A flat package is a XAR archive: a 28-byte header, a zlib-compressed XML
  table of contents, then a heap of (optionally compressed) files. Each
  component package inside holds `Scripts` (a gzip'd cpio archive with the
  install scripts) and `Payload` (a gzip'd or pbzx/xz cpio archive with the
  files that get installed). Both are unpacked, so install scripts and the
  binaries they drop are scanned like any archive member.

DMG (through 7-Zip)
  A UDIF disk image wraps a partition table and an HFS+ or APFS file system.
  Writing those parsers would be large; 7-Zip already reads all of them, so
  when a `7z` executable is present the image is listed (declared sizes are
  checked against the limits first), extracted, and each file-system image
  inside is opened one level further. Without 7-Zip the image is reported as
  not unpacked. Encrypted images ("encrcdsa") are reported as encrypted.

Every reader here works on bounded input: sizes are checked before data is
decompressed, and decompression stops at the caller's byte budget.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import struct
import subprocess
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Tuple

from core.tools import trusted_which

try:
    import defusedxml.ElementTree as _DET  # type: ignore
    DEFUSEDXML_AVAILABLE = True
except ImportError:                                      # pragma: no cover
    _DET = None
    DEFUSEDXML_AVAILABLE = False

XAR_MAGIC = b"xar!"
CPIO_ODC = b"070707"
CPIO_NEWC = (b"070701", b"070702")
PBZX_MAGIC = b"pbzx"
KOLY_MAGIC = b"koly"
DMG_ENCRYPTED_MAGICS = (b"encrcdsa", b"cdsaencr")
MAX_TOC = 16 * 1024 * 1024                  # compressed table-of-contents limit
FS_IMAGE_SUFFIXES = (".hfs", ".hfsx", ".apfs", ".img", ".fat", ".iso", ".ntfs", ".exfat")


class BudgetExceeded(Exception):
    """Decompressed data would pass the caller's byte budget."""


class TooManyEntries(BudgetExceeded):
    """More entries than the caller's member limit."""


class FormatError(Exception):
    """The bytes are not a well-formed package / image of the expected kind."""


# --------------------------------------------------------------- decompression
def bounded_decompress(data: bytes, encoding: str, budget: int) -> bytes:
    """Decompress one XAR heap entry (or a whole stream) without passing `budget`."""
    enc = (encoding or "").lower()
    if not enc or "octet-stream" in enc:
        if len(data) > budget:
            raise BudgetExceeded()
        return data
    if "gzip" in enc or "zlib" in enc:
        d = zlib.decompressobj(zlib.MAX_WBITS | 32)      # zlib or gzip header
        out = d.decompress(data, budget + 1)
    elif "bzip2" in enc:
        d = bz2.BZ2Decompressor()
        out = d.decompress(data, budget + 1)
    elif "lzma" in enc or "xz" in enc:
        d = lzma.LZMADecompressor()
        out = d.decompress(data, budget + 1)
    else:
        raise FormatError(f"unknown encoding {encoding!r}")
    if len(out) > budget:
        raise BudgetExceeded()
    return out


def stream_decompress(data: bytes, budget: int) -> bytes:
    """A Scripts/Payload stream: gzip, pbzx (xz chunks), bzip2, xz, or plain cpio."""
    if data.startswith(PBZX_MAGIC):
        return pbzx_decompress(data, budget)
    if data[:2] == b"\x1f\x8b":
        return bounded_decompress(data, "application/x-gzip", budget)
    if data[:3] == b"BZh":
        return bounded_decompress(data, "application/x-bzip2", budget)
    if data[:6] == b"\xfd7zXZ\x00":
        return bounded_decompress(data, "application/x-xz", budget)
    if len(data) > budget:
        raise BudgetExceeded()
    return data


def pbzx_decompress(data: bytes, budget: int) -> bytes:
    """Apple's pbzx: 'pbzx', u64 flags, then chunks of (u64 flags, u64 length, data)."""
    if not data.startswith(PBZX_MAGIC) or len(data) < 12:
        raise FormatError("not a pbzx stream")
    pos, out = 12, bytearray()
    while pos + 16 <= len(data):
        _flags, length = struct.unpack(">QQ", data[pos:pos + 16])
        pos += 16
        chunk = data[pos:pos + length]
        if len(chunk) != length:
            raise FormatError("truncated pbzx chunk")
        pos += length
        part = (bounded_decompress(chunk, "xz", budget - len(out))
                if chunk.startswith(b"\xfd7zXZ\x00") else chunk)
        out += part
        if len(out) > budget:
            raise BudgetExceeded()
    return bytes(out)


# ------------------------------------------------------------------------ cpio
@dataclass
class CpioEntry:
    name: str
    mode: int
    data: bytes

    @property
    def is_file(self) -> bool:
        return (self.mode & 0o170000) == 0o100000

    @property
    def is_link(self) -> bool:
        return (self.mode & 0o170000) == 0o120000

    @property
    def is_executable(self) -> bool:
        return self.is_file and bool(self.mode & 0o111)


def read_cpio(data: bytes, max_entries: int = 10_000) -> Iterator[CpioEntry]:
    """Entries of an odc ('070707', what pkgbuild writes) or newc cpio archive."""
    pos, n = 0, 0
    while pos + 6 <= len(data):
        magic = data[pos:pos + 6]
        if magic == CPIO_ODC:
            if pos + 76 > len(data):
                raise FormatError("truncated cpio header")
            h = data[pos:pos + 76]
            mode = int(h[18:24], 8)
            namesize = int(h[59:65], 8)
            filesize = int(h[65:76], 8)
            name_start = pos + 76
            data_start = name_start + namesize
            nxt = data_start + filesize
        elif magic in CPIO_NEWC:
            if pos + 110 > len(data):
                raise FormatError("truncated cpio header")
            h = data[pos:pos + 110]
            mode = int(h[14:22], 16)
            filesize = int(h[54:62], 16)
            namesize = int(h[94:102], 16)
            name_start = pos + 110
            data_start = (name_start + namesize + 3) & ~3
            nxt = (data_start + filesize + 3) & ~3
        else:
            raise FormatError("not a cpio archive")
        name = data[name_start:name_start + namesize].rstrip(b"\x00").decode("utf-8", "replace")
        if name == "TRAILER!!!":
            return
        if data_start + filesize > len(data):
            raise FormatError("truncated cpio member")
        n += 1
        if n > max_entries:
            raise TooManyEntries()
        yield CpioEntry(name[2:] if name.startswith("./") else name, mode,
                        data[data_start:data_start + filesize])
        pos = nxt


# ------------------------------------------------------------------------- XAR
@dataclass
class XarEntry:
    name: str                 # path inside the package, '/'-separated
    kind: str                 # file | directory | symlink | ...
    offset: int               # into the heap
    length: int               # stored (compressed) bytes
    size: int                 # extracted bytes
    encoding: str


def read_xar(path: Path) -> Tuple[List[XarEntry], int]:
    """Parse a XAR table of contents: (entries, absolute heap offset)."""
    if _DET is None:
        raise FormatError("defusedxml is needed to read the package's table of contents")
    with open(path, "rb") as fh:
        head = fh.read(28)
        if len(head) < 28 or head[:4] != XAR_MAGIC:
            raise FormatError("not a XAR archive")
        header_size, _version, toc_len, toc_size = struct.unpack(">HHQQ", head[4:24])
        if toc_len > MAX_TOC or toc_size > 8 * MAX_TOC:
            raise FormatError("table of contents too large")
        fh.seek(header_size)
        toc = bounded_decompress(fh.read(toc_len), "zlib", 8 * MAX_TOC)
    root = _DET.fromstring(toc)
    toc_el = root.find("toc")
    if toc_el is None:
        raise FormatError("no <toc>")
    entries: List[XarEntry] = []

    def walk(el, prefix: str) -> None:
        for f in el.findall("file"):
            name = (f.findtext("name") or "").strip()
            full = f"{prefix}{name}"
            kind = (f.findtext("type") or "file").strip()
            data = f.find("data")
            if data is not None:
                enc = data.find("encoding")
                entries.append(XarEntry(
                    full, kind,
                    int(data.findtext("offset") or 0), int(data.findtext("length") or 0),
                    int(data.findtext("size") or 0),
                    enc.get("style", "") if enc is not None else ""))
            else:
                entries.append(XarEntry(full, kind, 0, 0, 0, ""))
            walk(f, full + "/")

    walk(toc_el, "")
    return entries, header_size + toc_len


def xar_read_entry(path: Path, heap: int, entry: XarEntry, budget: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(heap + entry.offset)
        stored = fh.read(entry.length)
    if len(stored) != entry.length:
        raise FormatError("truncated package data")
    return bounded_decompress(stored, entry.encoding, budget)


def is_xar(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == XAR_MAGIC
    except OSError:
        return False


# ------------------------------------------------------------------------- DMG
def dmg_kind(path: Path) -> Optional[str]:
    """'udif' (koly trailer), 'encrypted', or None."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(8)
            if head in DMG_ENCRYPTED_MAGICS:
                return "encrypted"
            if size >= 512:
                fh.seek(size - 512)
                tail = fh.read(512)
                if tail[:4] == KOLY_MAGIC:
                    return "udif"
                if tail[-8:] in DMG_ENCRYPTED_MAGICS:
                    return "encrypted"
    except OSError:
        return None
    return None


def sevenzip_tool() -> Optional[str]:
    """A 7-Zip command-line program, if one is installed."""
    for name in ("7zz", "7z", "7za"):
        found = trusted_which(name)
        if found:
            return found
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            candidate = Path(base) / "7-Zip" / "7z.exe"
            if candidate.is_file():
                return str(candidate)
    return None


@dataclass
class ListedItem:
    path: str
    size: int
    is_dir: bool
    is_link: bool


def sevenzip_list(tool: str, archive: Path, timeout: int = 60,
                  runner: Callable = subprocess.run) -> List[ListedItem]:
    """`7z l -slt` parsed into items (raises FormatError if 7-Zip cannot open it)."""
    proc = runner([tool, "l", "-slt", "-ba", "-y", "-p", str(archive)],
                  capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise FormatError("7-Zip could not open the image")
    items: List[ListedItem] = []
    block: dict = {}
    for raw in proc.stdout.decode("utf-8", "replace").splitlines() + [""]:
        line = raw.strip()
        if not line:
            if "Path" in block:
                attrs = block.get("Attributes", "")
                items.append(ListedItem(
                    block["Path"], int(block.get("Size") or 0),
                    block.get("Folder") == "+" or attrs.startswith("D"),
                    bool(block.get("Symbolic Link")) or " -l" in attrs or attrs[:1] == "l"))
            block = {}
            continue
        key, sep, value = line.partition(" = ")
        if sep:
            block[key] = value
    return items


def sevenzip_extract(tool: str, archive: Path, out_dir: Path, timeout: int = 120,
                     runner: Callable = subprocess.run) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = runner([tool, "x", "-y", "-p", f"-o{out_dir}", str(archive)],
                  capture_output=True, timeout=timeout)
    if proc.returncode not in (0, 1):             # 1 = warnings (e.g. a skipped link)
        raise FormatError("7-Zip failed to extract the image")


def gzip_bytes(data: bytes) -> bytes:              # used by the package builder in tests
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()
