"""Builders for synthetic test samples. Nothing here is malware: every sample
only *looks like* an attack technique at the byte level (a relationship
pointing at a dead URL, a header that says MZ, random bytes, ...)."""

from __future__ import annotations

import io
import os
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Dict, Optional

import docx
from docx.shared import Pt, RGBColor


def make_docx(path: Path, paragraphs=("Quarterly report", "All figures are final."),
              hidden: Optional[str] = None, white: Optional[str] = None,
              tiny: Optional[str] = None) -> Path:
    d = docx.Document()
    for p in paragraphs:
        d.add_paragraph(p)
    if hidden:
        d.add_paragraph().add_run(hidden).font.hidden = True
    if white:
        d.add_paragraph().add_run(white).font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    if tiny:
        d.add_paragraph().add_run(tiny).font.size = Pt(1)
    d.save(str(path))
    return path


def rewrite_zip(src: Path, dst: Path, replace: Dict[str, bytes]) -> Path:
    """Copy an OOXML/ZIP file, replacing or adding the given members."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename in replace:
                continue
            zout.writestr(item, zin.read(item.filename))
        for name, data in replace.items():
            zout.writestr(name, data)
    return dst


def rels_xml(*relationships: str) -> bytes:
    body = "".join(relationships)
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{body}</Relationships>").encode()


def rel(rid: str, rtype: str, target: str, external: bool = True) -> str:
    mode = ' TargetMode="External"' if external else ""
    return (f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/'
            f'2006/relationships/{rtype}" Target="{target}"{mode}/>')


def make_pdf(text: str = "Hello", invisible: Optional[str] = None) -> bytes:
    """Minimal single-page PDF; `invisible` text is drawn with render mode 3."""
    ops = [f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"]
    if invisible:
        ops.append(f"BT /F1 12 Tf 3 Tr 72 700 Td ({invisible}) Tj ET")
    content = "\n".join(ops).encode("latin-1")
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content
            + b"\nendstream"]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
              .encode())
    return out.getvalue()


# ---------------------------------------------------------------- ZipCrypto
class _ZipCryptoKeys:
    """Traditional PKWARE stream cipher (what `zip -P` produces). Implemented
    here so the encrypted-archive tests run on every OS without extra tools."""

    def __init__(self, password: bytes):
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for c in password:
            self.update(c)

    @staticmethod
    def _crc(crc: int, b: int) -> int:
        return zlib.crc32(bytes([b]), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF

    def update(self, c: int) -> None:
        self.k[0] = self._crc(self.k[0], c)
        self.k[1] = (self.k[1] + (self.k[0] & 0xFF)) & 0xFFFFFFFF
        self.k[1] = (self.k[1] * 134775813 + 1) & 0xFFFFFFFF
        self.k[2] = self._crc(self.k[2], (self.k[1] >> 24) & 0xFF)

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for p in data:
            t = (self.k[2] | 2) & 0xFFFF
            out.append(p ^ (((t * (t ^ 1)) >> 8) & 0xFF))
            self.update(p)
        return bytes(out)


def make_zipcrypto_zip(path: Path, name: str, data: bytes, password: str) -> Path:
    """Single STORED member encrypted with ZipCrypto."""
    crc = zlib.crc32(data) & 0xFFFFFFFF
    header = bytearray(os.urandom(11)) + bytes([(crc >> 24) & 0xFF])
    payload = _ZipCryptoKeys(password.encode()).encrypt(bytes(header) + data)
    fname = name.encode()
    dos_time, dos_date = 0, (2026 - 1980) << 9 | 1 << 5 | 1
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x1, 0, dos_time, dos_date, crc,
                        len(payload), len(data), len(fname), 0) + fname
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x1, 0, dos_time, dos_date,
                          crc, len(payload), len(data), len(fname), 0, 0, 0, 0, 0, 0) + fname
    cd_offset = len(local) + len(payload)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), cd_offset, 0)
    path.write_bytes(local + payload + central + eocd)
    return path
