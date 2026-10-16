"""
File-integrity heuristics: format/magic validation, disguised executables, and
encrypted-content detection (ransomware impact).

WHY THIS EXISTS
---------------
The other layers ask "is this document a *weapon*?" (macros, YARA, reputation).
This layer asks two questions they cannot answer:

1. **Is it really what its extension claims?**  A Windows executable or shortcut
   (`MZ`, `ELF`, Mach-O, `.lnk`, `#!` script) saved as `invoice.pdf` is a classic
   lure - the extension is chosen for the victim, the content for the attacker.

2. **Has it already been encrypted?**  Ransomware rewrites documents in place
   (sometimes only the first few KB - "intermittent encryption", used by LockBit
   3.0 and BlackCat for speed). An encrypted file loses its format signature
   (`%PDF-`, `PK\\x03\\x04`, `D0 CF 11 E0`, ...) and its bytes become
   statistically indistinguishable from random noise. Finding that is evidence of
   *impact* (MITRE ATT&CK T1486), not of a malicious payload - but it means
   ransomware already ran on this machine.

WHY NOT "HIGH ENTROPY = BAD"?
-----------------------------
Because .docx/.xlsx (ZIP-compressed) and most PDFs (Flate streams) are *already*
high-entropy. A naive entropy threshold flags almost every Office file. This
module only looks at randomness when the format signature is **missing**, and it
uses two statistics together:

* Shannon entropy, compared with the value expected for truly random data *of
  the same length* (short samples can never reach 8.0 bits/byte), and
* a chi-square test against a uniform byte distribution. Ciphertext stays
  uniform (chi-square ~255 at any size); many compressed streams are measurably
  less uniform, which removes a class of false positives.

Honest limit: a raw, headerless compressed stream of high-entropy input can be
as uniform as ciphertext. Legitimate compressed formats carry a signature
(ZIP, gzip, PNG, ...), which is why the randomness test only runs once the
expected signature is already missing. Thresholds were calibrated on random
vs. compressed samples; see `tests/test_file_integrity.py`.
"""

from __future__ import annotations

import math
import os
import re
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union

PathLike = Union[str, Path]

HEAD_BYTES = 64 * 1024            # sample used for format + randomness checks
HEADER_BLOCK = 4 * 1024           # first block (catches intermittent encryption)
CHI_SQUARE_MAX_RANDOM = 400.0     # random data: mean 255, max ~350 in calibration
MIN_RANDOMNESS_SAMPLE = 1024      # below this, statistics are too noisy to judge

# Document extensions -> acceptable primary formats.
_OOXML = (".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
          ".xlsb", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm")
_OLE = (".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot", ".pps", ".msg")
EXPECTED_FORMATS: Dict[str, Sequence[str]] = {".pdf": ("pdf",), ".rtf": ("rtf",),
                                              ".zip": ("zip",), ".7z": ("7z",), ".rar": ("rar",)}
EXPECTED_FORMATS.update({e: ("zip",) for e in _OOXML})
EXPECTED_FORMATS.update({e: ("ole",) for e in _OLE})

# Other formats Office happily opens under these extensions - not suspicious on
# their own (e.g. many web apps export an HTML table as "statement.xls").
BENIGN_ALTERNATES: Dict[str, Sequence[str]] = {
    ".doc": ("rtf", "html", "mht", "xml", "text"),
    ".dot": ("rtf", "html", "mht", "xml", "text"),
    ".xls": ("html", "mht", "xml", "text"),
    ".xlt": ("html", "mht", "xml", "text"),
}
# A password-protected .docx/.xlsx is stored as an OLE "EncryptedPackage".
BENIGN_ALTERNATES.update({e: ("ole",) for e in _OOXML})

DOCUMENT_EXTENSIONS = frozenset(EXPECTED_FORMATS) - {".zip", ".7z", ".rar"}
EXECUTABLE_FORMATS = {"pe": "Windows PE executable", "elf": "Linux ELF executable",
                      "macho": "macOS Mach-O executable", "lnk": "Windows shortcut (.lnk)",
                      "script": "shebang script"}

# Ransomware impact indicators used while walking folders.
RANSOM_EXTENSIONS = frozenset({
    ".locked", ".encrypted", ".crypt", ".crypted", ".crypto", ".cry", ".enc",
    ".lockbit", ".ryuk", ".conti", ".blackcat", ".akira", ".royal", ".basta",
    ".hive", ".clop", ".cl0p", ".phobos", ".dharma", ".wallet", ".wncry", ".wnry",
    ".wcry", ".locky", ".zepto", ".cerber", ".djvu", ".makop", ".medusa",
    ".rhysida", ".8base", ".lockfile", ".deadbolt", ".babuk", ".avos", ".nefilim",
})
_DHARMA_STYLE = re.compile(r"\.id[-_][a-z0-9]{6,}\.\[[^\]]+@[^\]]+\]", re.I)
RANSOM_NOTE_RE = re.compile(
    r"(?i)^(?:_readme\.txt"
    r"|!+[^\\/]*read[_\-\s]?me[^\\/]*!+\.txt"
    r"|[^\\/]*(?:decrypt|ransom|unlock[_\-\s]?files"
    r"|(?:restore|recover)[_\-\s]?(?:my|your|all)?[_\-\s]?(?:files|data)"
    r"|how[_\-\s]?to[_\-\s]?(?:restore|recover|unlock|get[_\-\s]?back)"
    r"|files[_\-\s]?(?:are|were|have[_\-\s]?been)[_\-\s]?encrypted)"
    r"[^\\/]*\.(?:txt|html?|hta|rtf|url))$")


# ------------------------------------------------------------------ math
def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    n = len(data)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def chi_square_uniform(data: bytes) -> float:
    """Chi-square statistic of the byte histogram vs. a uniform distribution."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    expected = n / 256.0
    return sum((counts.get(i, 0) - expected) ** 2 for i in range(256)) / expected


def random_entropy_threshold(n: int) -> float:
    """Lowest entropy we still accept as 'random' for an n-byte sample.

    Random data of finite length has expected entropy ~ 8 - 255/(2 n ln 2);
    its spread shrinks roughly as 17/n. We accept anything within five of
    those 'standard deviations' of the expectation (plus a small bias term).
    """
    expected = 8.0 - 255.0 / (2.0 * n * math.log(2))
    return expected - 0.012 - 5.0 * 17.0 / n


def looks_random(block: bytes) -> bool:
    """True if `block` is statistically indistinguishable from random bytes."""
    n = len(block)
    if n < MIN_RANDOMNESS_SAMPLE:
        return False
    return (shannon_entropy(block) >= random_entropy_threshold(n)
            and chi_square_uniform(block) <= CHI_SQUARE_MAX_RANDOM)


def looks_encrypted(head: bytes) -> bool:
    """Whole sample random, or its first 4 KiB random (intermittent encryption)."""
    return looks_random(head) or looks_random(head[:HEADER_BLOCK])


# --------------------------------------------------------------- formats
# Legitimate encrypted containers: their bytes are random by design, but each
# starts with a recognisable header. Headers can be forged, so detect_format()
# deliberately does NOT use these: a document whose signature is gone stays
# "unknown" (and can be flagged as encrypted) even if it starts with one. The
# ML layer uses them only when the file's extension agrees (VAULT_EXTENSIONS).
KDBX_MAGIC = (b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5",   # KeePass 2.x (.kdbx)
              b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5")   # KeePass 1.x (.kdb)
AGE_MAGIC = b"age-encryption.org/v1\n"


def is_openpgp_message(head: bytes) -> bool:
    """A binary OpenPGP message: first packet is a public-key (tag 1) or
    symmetric-key (tag 3) encrypted session key with a valid version byte.
    Validating the structure (not just one byte) keeps a fake 1-byte prefix
    from hiding ransomware output."""
    if len(head) < 4 or not head[0] & 0x80:
        return False
    b0 = head[0]
    if b0 & 0x40:                                   # new packet format
        tag, l1 = b0 & 0x3F, head[1]
        lenlen = 1 if l1 < 192 else 2 if l1 < 224 else 5 if l1 == 255 else 1
    else:                                           # old packet format
        tag = (b0 >> 2) & 0x0F
        lenlen = {0: 1, 1: 2, 2: 4, 3: 0}[b0 & 0x03]
    if 1 + lenlen >= len(head):
        return False
    version = head[1 + lenlen]
    return (tag == 1 and version in (3, 6)) or (tag == 3 and version in (4, 5, 6))


VAULT_EXTENSIONS = {"kdbx": frozenset({".kdbx", ".kdb"}),
                    "pgp": frozenset({".gpg", ".pgp"}),
                    "age": frozenset({".age"})}


def encrypted_container_format(head: bytes) -> str:
    """'kdbx' | 'pgp' | 'age' for a known encrypted container, else ''."""
    if head.startswith(KDBX_MAGIC):
        return "kdbx"
    if head.startswith(AGE_MAGIC):
        return "age"
    if is_openpgp_message(head):
        return "pgp"
    return ""


def trusted_vault(head: bytes, extension: str) -> str:
    """The vault kind when BOTH the header and the extension say so, else ''."""
    kind = encrypted_container_format(head)
    return kind if kind and extension.lower() in VAULT_EXTENSIONS[kind] else ""


def detect_format(head: bytes) -> str:
    """Identify a file's real format from its first bytes."""
    if not head:
        return "empty"
    h = head
    stripped = h.lstrip(b"\xef\xbb\xbf\xff\xfe\xfe\xff \t\r\n")
    low = stripped[:512].lower()
    if h.startswith(b"MZ") and _has_pe_header(h):
        return "pe"
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                 b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if h.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if re.match(rb"#![ \t]*/[\w./-]+", h):
        return "script"
    if h.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if b"%PDF-" in h[:1024]:
        return "pdf"
    if stripped.startswith(b"{\\rt"):
        return "rtf"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"BZh"):
        return "bzip2"
    if h.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if h.startswith(b"MSCF"):
        return "cab"
    if h.startswith(b"\x89PNG"):
        return "png"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if h.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(h) >= 2 and h[0] == 0x78 and h[1] in (0x01, 0x5E, 0x9C, 0xDA) and _inflates(h):
        return "zlib"
    if low.startswith(b"mime-version:") or b"content-type: multipart/related" in low:
        return "mht"
    if low.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<meta")):
        return "html"
    if low.startswith(b"<?xml"):
        return "xml"
    sample = h[:4096]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    if printable / max(1, len(sample)) > 0.95:
        return "text"
    return "unknown"


def _has_pe_header(h: bytes) -> bool:
    """MZ stub whose e_lfanew points at a real 'PE\\0\\0' signature."""
    if len(h) < 0x40:
        return False
    offset = int.from_bytes(h[0x3C:0x40], "little")
    return 0x40 <= offset <= len(h) - 4 and h[offset:offset + 4] == b"PE\x00\x00"


def _inflates(h: bytes) -> bool:
    """A real zlib stream decompresses; random bytes with a lucky header don't."""
    try:
        zlib.decompressobj().decompress(h[:4096])
        return True
    except zlib.error:
        return False


def ransom_indicator(file_name: str) -> Optional[str]:
    """Classify a file *name* seen during a folder walk (no content read)."""
    name = os.path.basename(file_name)
    if RANSOM_NOTE_RE.search(name):
        return "ransom_note"
    suffix = os.path.splitext(name)[1].lower()
    if suffix in RANSOM_EXTENSIONS or _DHARMA_STYLE.search(name):
        return "ransom_extension"
    return None


# ----------------------------------------------------------------- result
@dataclass
class IntegrityResult:
    available: bool = True
    extension: str = ""
    detected_format: str = ""
    expected_formats: List[str] = field(default_factory=list)
    magic_ok: Optional[bool] = None       # None = extension not checked
    disguised_executable: Optional[str] = None
    encrypted_likely: bool = False
    format_mismatch: bool = False
    header_entropy: float = 0.0     # first 4 KiB
    sample_entropy: float = 0.0     # first 64 KiB
    sample_chi_square: float = 0.0  # first 64 KiB
    notes: List[str] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> Dict:
        return {
            "available": self.available,
            "extension": self.extension,
            "detected_format": self.detected_format,
            "expected_formats": self.expected_formats,
            "magic_ok": self.magic_ok,
            "disguised_executable": self.disguised_executable,
            "encrypted_likely": self.encrypted_likely,
            "format_mismatch": self.format_mismatch,
            "header_entropy": round(self.header_entropy, 4),
            "sample_entropy": round(self.sample_entropy, 4),
            "sample_chi_square": round(self.sample_chi_square, 1),
            "notes": self.notes,
            "detail": self.detail,
        }


class FileIntegrityAnalyzer:
    """Runs the format / disguise / encryption checks on one file."""

    def analyze_file(self, file_path: PathLike, extension: Optional[str] = None) -> IntegrityResult:
        path = Path(file_path)
        ext = (extension or path.suffix).lower()
        res = IntegrityResult(extension=ext)
        try:
            size = path.stat().st_size
            with path.open("rb") as fh:
                head = fh.read(HEAD_BYTES)
        except OSError as e:
            res.available = False
            res.detail = f"Integrity check skipped: {e}"
            return res

        res.detected_format = detect_format(head)
        res.header_entropy = shannon_entropy(head[:HEADER_BLOCK])
        res.sample_entropy = shannon_entropy(head)
        res.sample_chi_square = chi_square_uniform(head)
        expected = list(EXPECTED_FORMATS.get(ext, ()))
        res.expected_formats = expected

        if size == 0:
            res.notes.append("Empty file.")
            res.detail = "Empty file - nothing to check."
            return res

        fmt = res.detected_format
        if fmt in EXECUTABLE_FORMATS and ext in DOCUMENT_EXTENSIONS:
            res.disguised_executable = fmt
            res.magic_ok = False
            res.detail = (f"{EXECUTABLE_FORMATS[fmt]} disguised with a '{ext}' "
                          f"document extension.")
            return res

        if not expected:
            res.detail = f"Detected format: {fmt} (extension '{ext}' not validated)."
            return res

        if fmt in expected:
            res.magic_ok = True
            if fmt == "zip" and ext in _OOXML and not self._is_ooxml(path):
                res.format_mismatch = True
                res.notes.append("ZIP archive without [Content_Types].xml - not a real "
                                 "Office document despite its extension.")
            res.detail = res.notes[-1] if res.notes else f"Format signature OK ({fmt})."
            return res

        res.magic_ok = False
        if fmt in BENIGN_ALTERNATES.get(ext, ()):
            if fmt == "ole" and ext in _OOXML:
                res.notes.append("OLE container under an OOXML extension - usually a "
                                 "password-protected Office file (EncryptedPackage).")
            else:
                res.notes.append(f"{fmt.upper()} content under '{ext}' - Office opens this "
                                 f"format natively (common for web exports).")
            res.detail = res.notes[-1]
            return res

        # Only an *unrecognisable* blob can be ciphertext; a gzip/PNG/... file under
        # a document extension is a mismatch, not encryption.
        if fmt == "unknown" and looks_encrypted(head):
            res.encrypted_likely = True
            partial = not looks_random(head) and looks_random(head[:HEADER_BLOCK])
            res.detail = ("Format signature missing and the first 4 KiB is random-looking "
                          "(partial/intermittent encryption)." if partial else
                          "Format signature missing and the content is statistically "
                          "random - consistent with ransomware encryption.")
            return res

        res.format_mismatch = True
        res.detail = (f"Content does not match its '{ext}' extension "
                      f"(expected {'/'.join(expected)}, found {fmt}).")
        return res

    @staticmethod
    def _is_ooxml(path: Path) -> bool:
        try:
            with zipfile.ZipFile(path) as zf:
                return "[Content_Types].xml" in zf.namelist()
        except Exception:
            return False
