"""
File types that carry other files: OneNote notebooks, compiled HTML help (CHM),
Windows Installer packages (MSI), password-protected Office documents, and Excel
add-ins (XLL).

WHY THIS EXISTS
---------------
When Office macros were blocked by default, delivery moved to formats that still
run something on a double-click: a OneNote page with an embedded .hta / .bat
behind a "Double-click to view" button; a .chm whose help page starts a command;
an .msi with a script custom action; an .xll that Excel loads as code; and a
password-protected .docx whose content no gateway can read.

WHAT IS DONE (nothing is executed)
----------------------------------
* OneNote (.one): embedded files (FileDataStoreObject blocks) are carved out and
  scanned through the whole pipeline. Script-like text gets a script extension
  so the script layer reads it.
* CHM: unpacked with 7-Zip; the pages and scripts inside are scanned. The HTML
  Help "ShortCut" ActiveX command object is flagged.
* MSI: streams holding programs, cabinets or scripts are carved out and scanned;
  a VBScript / JScript custom action is flagged (rare in legitimate packages).
* Encrypted Office (OOXML in an EncryptedPackage, or legacy RC4 / XOR): opened
  with msoffcrypto-tool when a candidate password works - the password written
  in the e-mail it came with, Excel's default "VelvetSweatshop", the delivery
  list and the file name - and the decrypted document is scanned.
* XLL: a Windows DLL that exports Excel's xlAutoOpen entry point.

Every step is bounded (bytes read, members, member size) and every member lives
in a sandbox folder that is deleted when the scan of the container ends.
"""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Union

from .file_integrity import detect_format

logger = logging.getLogger("RansomwareScanner.embedded")

PathLike = Union[str, Path]

try:
    import olefile  # type: ignore
except ImportError:  # pragma: no cover
    olefile = None
try:
    import msoffcrypto  # type: ignore
    MSOFFCRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    msoffcrypto = None
    MSOFFCRYPTO_AVAILABLE = False

MAX_READ = 64 * 1024 * 1024
MAX_MEMBERS = 25
MAX_MEMBER_BYTES = 30 * 1024 * 1024

ONENOTE_MAGIC = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")
_ONENOTE_FILEDATA = bytes.fromhex("E716E3BD65261145A4C48D4D0B7A9EAC")
CHM_MAGIC = b"ITSF"
OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
_MSI_CLSID = "000C1084-0000-0000-C000-000000000046"
_HHCTRL_CLSID = "adb880a6-d8ff-11cf-9377-00aa003b7a11"
DEFAULT_OFFICE_PASSWORDS = ("VelvetSweatshop", "infected", "password", "1234", "123456")

_EXT_BY_FORMAT = {"pe": ".exe", "elf": ".elf", "macho": ".macho", "lnk": ".lnk", "zip": ".zip",
                  "7z": ".7z", "rar": ".rar", "cab": ".cab", "ole": ".doc", "pdf": ".pdf",
                  "rtf": ".rtf", "gzip": ".gz", "script": ".sh"}
RISKY_EXTENSIONS = frozenset({".exe", ".dll", ".scr", ".lnk", ".hta", ".vbs", ".vbe", ".js",
                              ".jse", ".wsf", ".ps1", ".bat", ".cmd", ".elf", ".macho", ".sh"})

_SCRIPT_GUESS = (
    (".hta", re.compile(rb"<hta:application", re.I)),
    (".wsf", re.compile(rb"<job\b[^>]*>|<script\s+language\s*=\s*[\"']?(?:vbscript|jscript)", re.I)),
    (".ps1", re.compile(rb"\$[a-z_]\w*\s*=|invoke-|new-object\s|-encodedcommand|\[convert\]::", re.I)),
    (".vbs", re.compile(rb"createobject\s*\(|wscript\.|\bdim\s+\w+|\bsub\s+\w+\s*\(", re.I)),
    (".bat", re.compile(rb"^\s*@?echo\s+off|^\s*(?:set|start|call|goto)\s", re.I | re.M)),
    (".js", re.compile(rb"activexobject|\bvar\s+\w+\s*=|function\s*\w*\s*\(", re.I)),
)


@dataclass
class EmbeddedMember:
    name: str
    size: int
    kind: str                         # format / script type
    path: Optional[str] = None        # sandbox copy while the context is open

    def as_dict(self) -> Dict:
        return {"name": self.name, "size": self.size, "kind": self.kind}


@dataclass
class EmbeddedResult:
    kind: str = ""                    # onenote | chm | msi | office-encrypted | xll
    members: List[EmbeddedMember] = field(default_factory=list)
    risky_members: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    chm_shortcut: bool = False
    msi_script_actions: List[str] = field(default_factory=list)
    xll_addin: bool = False
    encrypted: bool = False
    decrypted_with: Optional[str] = None
    password_from_message: bool = False
    skipped: List[str] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> Dict:
        return {"kind": self.kind, "members": [m.as_dict() for m in self.members],
                "risky_members": self.risky_members, "findings": self.findings,
                "chm_shortcut": self.chm_shortcut,
                "msi_script_actions": self.msi_script_actions, "xll_addin": self.xll_addin,
                "encrypted": self.encrypted, "decrypted": self.decrypted_with is not None,
                "password_from_message": self.password_from_message,
                "skipped": self.skipped, "detail": self.detail}


def _guess_text_extension(data: bytes) -> str:
    head = data[:65536]
    if head.count(b"\x00") > len(head) // 20:
        return ".bin"
    for ext, rx in _SCRIPT_GUESS:
        if rx.search(head):
            return ext
    return ".txt"


def member_extension(data: bytes) -> str:
    fmt = detect_format(data[:65536])
    if fmt in _EXT_BY_FORMAT:
        return _EXT_BY_FORMAT[fmt]
    if data[:4] == b"MSCF":
        return ".cab"
    return _guess_text_extension(data)


def sniff(path: PathLike) -> str:
    """The embedded-content kind of a file ('' if it is none of them)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return ""
    if head.startswith(ONENOTE_MAGIC):
        return "onenote"
    if head.startswith(CHM_MAGIC):
        return "chm"
    if head.startswith(OLE_MAGIC) and olefile is not None:
        try:
            with olefile.OleFileIO(str(path)) as ole:
                if (ole.root.clsid or "").upper() == _MSI_CLSID:
                    return "msi"
                if ole.exists("EncryptedPackage") and ole.exists("EncryptionInfo"):
                    return "office-encrypted"
        except Exception:
            return ""
        if MSOFFCRYPTO_AVAILABLE and Path(path).suffix.lower() in (".doc", ".xls", ".ppt"):
            try:
                with open(path, "rb") as fh:
                    if msoffcrypto.OfficeFile(fh).is_encrypted():
                        return "office-encrypted"
            except Exception:
                return ""
        return ""
    if head[:2] == b"MZ":
        try:
            with open(path, "rb") as fh:
                data = fh.read(8 * 1024 * 1024)
        except OSError:
            return ""
        if b"xlAutoOpen" in data and detect_format(data[:4096]) == "pe":
            return "xll"
    return ""


class EmbeddedContentAnalyzer:
    def __init__(self, password_source: Optional[Callable[[], Sequence[str]]] = None,
                 sevenzip: Optional[Callable[[], Optional[str]]] = None):
        # password_source: extra candidates, e.g. the ones written in the e-mail being scanned
        self.password_source = password_source or (lambda: ())
        if sevenzip is None:
            from .macos_packages import sevenzip_tool
            sevenzip = sevenzip_tool
        self.sevenzip = sevenzip

    def applies(self, path: PathLike) -> bool:
        return bool(sniff(path))

    def analyze(self, path: PathLike) -> EmbeddedResult:
        with self.open(path, extract=False) as res:
            return res

    @contextlib.contextmanager
    def open(self, path: PathLike, extract: bool = True) -> Iterator[EmbeddedResult]:
        p = Path(path)
        res = EmbeddedResult(kind=sniff(p))
        sandbox = Path(tempfile.mkdtemp(prefix="hrd_emb_"))
        try:
            try:
                handler = {"onenote": self._onenote, "chm": self._chm, "msi": self._msi,
                           "office-encrypted": self._office, "xll": self._xll}.get(res.kind)
                if handler:
                    handler(p, res, sandbox, extract)
            except Exception as e:                    # hostile file: a finding, not a crash
                logger.debug("Embedded-content parsing failed for %s: %s", p, e)
                res.skipped.append(f"could not be parsed completely ({type(e).__name__})")
            res.detail = self._summary(res)
            yield res
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

    # ------------------------------------------------------------- helpers
    def _add(self, res: EmbeddedResult, sandbox: Path, extract: bool, name: str,
             data: bytes, kind: Optional[str] = None) -> None:
        if len(res.members) >= MAX_MEMBERS:
            res.skipped.append(f"{name}: member limit reached")
            return
        if len(data) > MAX_MEMBER_BYTES:
            res.skipped.append(f"{name}: larger than {MAX_MEMBER_BYTES // (1024 * 1024)} MB")
            return
        safe = re.sub(r"[^\w.\-]", "_", Path(name).name)[:80] or "member"
        member = EmbeddedMember(safe, len(data), kind or Path(safe).suffix.lstrip(".") or "data")
        if extract:
            target = sandbox / f"m{len(res.members)}" / safe
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            member.path = str(target)
        res.members.append(member)
        if Path(safe).suffix.lower() in RISKY_EXTENSIONS:
            res.risky_members.append(safe)

    # ------------------------------------------------------------- OneNote
    def _onenote(self, path: Path, res: EmbeddedResult, sandbox: Path, extract: bool) -> None:
        with open(path, "rb") as fh:
            data = fh.read(MAX_READ)
        pos = 0
        while True:
            pos = data.find(_ONENOTE_FILEDATA, pos)
            if pos < 0:
                break
            header = data[pos + 16: pos + 36]
            if len(header) < 20:
                break
            length = struct.unpack_from("<Q", header, 0)[0]
            start, end = pos + 36, pos + 36 + length
            if length == 0 or end > len(data):
                res.skipped.append("embedded file with an impossible length")
                pos += 16
                continue
            blob = data[start:end]
            ext = member_extension(blob)
            self._add(res, sandbox, extract, f"embedded{len(res.members) + 1}{ext}", blob,
                      ext.lstrip("."))
            pos = end

    # ------------------------------------------------------------- CHM
    def _chm(self, path: Path, res: EmbeddedResult, sandbox: Path, extract: bool) -> None:
        """Pages and files of a compiled help file, read one at a time with
        `7z e -so` (7-Zip never writes a file; see container_extractor)."""
        from .macos_packages import sevenzip_list, sevenzip_read
        tool = self.sevenzip()
        if not tool:
            res.skipped.append("7-Zip is needed to unpack CHM files")
            return
        work = sandbox / "chm"
        work.mkdir()
        for item in sorted(sevenzip_list(tool, path), key=lambda i: i.path):
            name = PurePosixPath(item.path.replace("\\", "/")).name
            if item.is_dir or item.is_link or not name or name.startswith(("#", "$")):
                continue                                 # internal index streams
            if item.size > MAX_MEMBER_BYTES:
                res.skipped.append(f"{name}: too large")
                continue
            data = sevenzip_read(tool, path, item.path, work, MAX_MEMBER_BYTES)
            if data is None:
                res.skipped.append(f"{name}: could not be read")
                continue
            low = data.lower()
            if _HHCTRL_CLSID.encode() in low and (b'"shortcut"' in low or b"'shortcut'" in low
                                                  or b"value=shortcut" in low):
                res.chm_shortcut = True
            if PurePosixPath(name).suffix.lower() in (
                    ".htm", ".html", ".js", ".vbs", ".hta", ".exe", ".dll", ".bat", ".cmd",
                    ".ps1", ".lnk") or detect_format(data[:4096]):
                self._add(res, sandbox, extract, name, data)
        if res.chm_shortcut:
            res.findings.append("help page runs a command through the HTML Help ShortCut object")

    # ------------------------------------------------------------- MSI
    def _msi(self, path: Path, res: EmbeddedResult, sandbox: Path, extract: bool) -> None:
        with olefile.OleFileIO(str(path)) as ole:
            for entry in ole.listdir(streams=True, storages=False):
                if len(res.members) >= MAX_MEMBERS:
                    break
                try:
                    size = ole.get_size(entry)
                    if size < 16 or size > MAX_MEMBER_BYTES:
                        continue
                    data = ole.openstream(entry).read()
                except Exception:
                    continue
                fmt = detect_format(data[:4096])
                if fmt in ("pe", "lnk") or data[:4] == b"MSCF":
                    self._add(res, sandbox, extract, f"stream{len(res.members) + 1}"
                              f"{member_extension(data)}", data)
                    continue
                ext = _guess_text_extension(data)
                if ext in (".vbs", ".js", ".ps1", ".bat", ".wsf", ".hta"):
                    res.msi_script_actions.append(ext.lstrip("."))
                    self._add(res, sandbox, extract, f"customaction{len(res.members) + 1}{ext}", data)
        if res.msi_script_actions:
            res.findings.append("script custom action(s): " + ", ".join(sorted(set(res.msi_script_actions))))

    # ------------------------------------------------------------- encrypted Office
    def _office(self, path: Path, res: EmbeddedResult, sandbox: Path, extract: bool) -> None:
        res.encrypted = True
        if not MSOFFCRYPTO_AVAILABLE:
            res.skipped.append("password-protected document; install msoffcrypto-tool to try "
                               "known passwords")
            return
        from_message = [p for p in self.password_source() if p]
        candidates = list(dict.fromkeys([*from_message, *DEFAULT_OFFICE_PASSWORDS,
                                         path.stem, path.stem.lower()]))
        for pwd in candidates:
            try:
                with open(path, "rb") as fh:
                    office = msoffcrypto.OfficeFile(fh)
                    office.load_key(password=pwd)
                    out = sandbox / "decrypted.bin"
                    with open(out, "wb") as dst:
                        office.decrypt(dst)
            except Exception:
                continue
            data = out.read_bytes()
            out.unlink(missing_ok=True)
            if not data:
                continue
            res.decrypted_with = pwd
            res.password_from_message = pwd in from_message
            self._add(res, sandbox, extract, path.name, data)
            res.findings.append("password-protected document opened"
                                + (" with the password from the message" if res.password_from_message
                                   else ""))
            return
        res.skipped.append("password-protected document; password unknown")

    # ------------------------------------------------------------- XLL
    @staticmethod
    def _xll(path: Path, res: EmbeddedResult, sandbox: Path, extract: bool) -> None:
        res.xll_addin = True
        res.findings.append("Excel add-in DLL (exports xlAutoOpen): Excel runs it when it is opened")

    @staticmethod
    def _summary(res: EmbeddedResult) -> str:
        names = {"onenote": "OneNote notebook", "chm": "compiled HTML help", "msi": "Windows Installer package",
                 "office-encrypted": "password-protected Office document", "xll": "Excel add-in (XLL)"}
        bits = [names.get(res.kind, "file")]
        if res.members:
            bits.append(f"{len(res.members)} embedded file(s)")
        if res.risky_members:
            bits.append("runnable: " + ", ".join(res.risky_members[:5]))
        bits.extend(res.findings)
        bits.extend(res.skipped[:3])
        return "; ".join(bits) + "."
