"""
Safe ZIP archive inspection: unpack into a throw-away sandbox, defend against
archive attacks, and hand every member to the full scan pipeline.

WHY THIS EXISTS
---------------
Malicious documents are usually *delivered* in archives - an invoice.zip
attached to an email - partly because many gateways don't look inside, and
partly because a password-protected ZIP (password in the email body) defeats
scanning entirely. The v3 scanner skipped .zip files, so a macro dropper inside
one was invisible to every layer.

This module extracts ZIP archives (including nested ones) into a temporary
directory and reports archive-level red flags:

* **Zip bombs** - absurd compression ratios, too many entries, too much
  decompressed data, or excessive nesting. Limits are checked against the
  declared sizes *and* enforced while streaming (declared sizes can lie).
* **Zip slip** - members whose names escape the extraction directory
  (`../../.bashrc`, absolute paths, drive letters) or are symlinks. Such members
  are never written; their presence is itself evidence of an attack.
* **Executables and lure names** - scripts/executables/shortcuts inside the
  archive (by extension *and* by magic bytes), double extensions like
  `invoice.pdf.exe`, and the right-to-left-override trick (`invoice\\u202Efdp.exe`
  displays as `invoiceexe.pdf`).
* **Encryption** - encrypted members are tried against a short list of
  passwords commonly used for malware delivery ("infected", the archive's own
  name, ...). If none works the archive is reported as unreadable, because an
  archive the scanner cannot open is a classic evasion technique.

Only the Python standard library is used (no external unrar/7z binaries are
spawned). Formats other than ZIP are out of scope for now.
"""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import stat
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Iterator, List, Optional, Union

logger = logging.getLogger("RansomwareScanner.archive")

PathLike = Union[str, Path]

DEFAULT_PASSWORDS = ("infected", "malware", "virus", "password", "123456", "1234", "123")
EXECUTABLE_EXTENSIONS = frozenset({
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".msix", ".appx", ".dll",
    ".cpl", ".jar", ".iso", ".img", ".vhd", ".vhdx", ".one", ".url", ".scf", ".reg",
    ".chm", ".xll", ".sys", ".sh", ".app", ".command",
})
LURE_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".rtf",
    ".txt", ".jpg", ".jpeg", ".png", ".gif", ".csv", ".zip", ".mp3", ".mp4", ".html",
})
_EXEC_MAGIC = ((b"MZ", "pe"), (b"\x7fELF", "elf"), (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk"),
               (b"\xcf\xfa\xed\xfe", "macho"), (b"\xce\xfa\xed\xfe", "macho"))
RTLO = "\u202e"   # right-to-left override (escaped on purpose: never put it in source)
_STREAM_CHUNK = 64 * 1024


@dataclass
class ArchiveMember:
    name: str                       # display path, e.g. "invoice.zip!/docs/a.docm"
    size: int = 0
    compressed_size: int = 0
    encrypted: bool = False
    extracted: bool = False
    executable: bool = False
    skipped_reason: str = ""
    path: Optional[str] = None      # sandbox path while the context is open

    def as_dict(self) -> Dict:
        return {"name": self.name, "size": self.size,
                "compressed_size": self.compressed_size, "encrypted": self.encrypted,
                "extracted": self.extracted, "executable": self.executable,
                "skipped_reason": self.skipped_reason}


@dataclass
class ContainerResult:
    available: bool = True
    is_container: bool = False
    container_type: str = ""
    members: List[ArchiveMember] = field(default_factory=list)
    total_uncompressed: int = 0
    max_depth_reached: int = 0
    zip_bomb: bool = False
    zip_bomb_reason: str = ""
    zip_slip: bool = False
    zip_slip_reason: str = ""
    unreadable_members: int = 0
    password_used: Optional[str] = None
    executable_members: List[str] = field(default_factory=list)
    double_extension_members: List[str] = field(default_factory=list)
    rtlo_members: List[str] = field(default_factory=list)
    detail: str = ""

    @property
    def encrypted_unreadable(self) -> bool:
        return self.unreadable_members > 0 and any(m.encrypted and not m.extracted
                                                   for m in self.members)

    def as_dict(self) -> Dict:
        return {
            "available": self.available,
            "is_container": self.is_container,
            "container_type": self.container_type,
            "member_count": len(self.members),
            "members": [m.as_dict() for m in self.members[:200]],
            "total_uncompressed": self.total_uncompressed,
            "max_depth_reached": self.max_depth_reached,
            "zip_bomb": self.zip_bomb,
            "zip_bomb_reason": self.zip_bomb_reason,
            "zip_slip": self.zip_slip,
            "zip_slip_reason": self.zip_slip_reason,
            "unreadable_members": self.unreadable_members,
            "encrypted_unreadable": self.encrypted_unreadable,
            "password_used": self.password_used,
            "executable_members": self.executable_members[:50],
            "double_extension_members": self.double_extension_members[:50],
            "rtlo_members": self.rtlo_members[:50],
            "detail": self.detail,
        }


def visible_name(name: str) -> str:
    """Render a member name safely for reports (control chars + RTLO shown)."""
    out = name.replace(RTLO, "[RTLO]")
    return re.sub(r"[\x00-\x1f\x7f]", "?", out)


def _unsafe_member_path(name: str) -> Optional[str]:
    """Return a reason if extracting `name` could escape the sandbox."""
    if not name or "\x00" in name:
        return "empty or NUL-containing member name"
    for flavour in (PurePosixPath(name), PureWindowsPath(name)):
        if flavour.is_absolute() or flavour.drive or str(flavour).startswith(("/", "\\")):
            return f"absolute path '{visible_name(name)}'"
        if ".." in flavour.parts:
            return f"directory traversal in '{visible_name(name)}'"
    return None


class ContainerExtractor:
    """Recursive, bounded ZIP extraction into a temporary sandbox."""

    SUPPORTED_EXTENSIONS = frozenset({".zip"})

    def __init__(self, max_depth: int = 3, max_total_bytes: int = 100 * 1024 * 1024,
                 max_members: int = 500, max_ratio: float = 100.0,
                 passwords=DEFAULT_PASSWORDS):
        self.max_depth = int(max_depth)
        self.max_total_bytes = int(max_total_bytes)
        self.max_members = int(max_members)
        self.max_ratio = float(max_ratio)
        self.passwords = tuple(passwords)

    def is_container(self, file_path: PathLike) -> bool:
        path = Path(file_path)
        if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return False
        try:
            return zipfile.is_zipfile(path)
        except OSError:
            return False

    @contextlib.contextmanager
    def open(self, file_path: PathLike) -> Iterator[ContainerResult]:
        """Extract into a sandbox that exists only inside the `with` block."""
        path = Path(file_path)
        result = ContainerResult(is_container=True, container_type="zip")
        sandbox = Path(tempfile.mkdtemp(prefix="hrd_unpack_"))
        try:
            self._walk(path, path.name, sandbox, 1, result)
            result.detail = self._summary(result)
            yield result
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

    # ------------------------------------------------------------- internals
    def _walk(self, archive: Path, display: str, sandbox: Path, depth: int,
              res: ContainerResult) -> None:
        if res.zip_bomb:
            return
        if depth > self.max_depth:
            res.zip_bomb = True
            res.zip_bomb_reason = f"Archives nested deeper than {self.max_depth} levels."
            return
        res.max_depth_reached = max(res.max_depth_reached, depth)
        try:
            zf = zipfile.ZipFile(archive)
        except (zipfile.BadZipFile, OSError) as e:
            res.unreadable_members += 1
            logger.debug("Unreadable archive %s: %s", display, e)
            return
        with zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if len(res.members) + len(infos) > self.max_members:
                res.zip_bomb = True
                res.zip_bomb_reason = (f"{len(res.members) + len(infos)} entries exceed the "
                                       f"{self.max_members}-member limit.")
                return
            declared = sum(i.file_size for i in infos)
            if res.total_uncompressed + declared > self.max_total_bytes:
                res.zip_bomb = True
                res.zip_bomb_reason = (f"Declared uncompressed size {declared:,} bytes exceeds "
                                       f"the {self.max_total_bytes:,}-byte limit.")
                return
            for info in infos:
                if res.zip_bomb:
                    return
                self._handle_member(zf, info, archive, display, sandbox, depth, res)

    def _handle_member(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, archive: Path,
                       display: str, sandbox: Path, depth: int, res: ContainerResult) -> None:
        shown = f"{display}!/{visible_name(info.filename)}"
        reason = _unsafe_member_path(info.filename)
        mode = (info.external_attr >> 16) & 0xFFFF
        if reason is None and stat.S_ISLNK(mode):
            reason = f"symbolic link entry '{visible_name(info.filename)}'"
        if reason:
            res.zip_slip = True
            res.zip_slip_reason = res.zip_slip_reason or f"Blocked {reason}."
            res.members.append(ArchiveMember(shown, info.file_size, info.compress_size,
                                             skipped_reason="unsafe path (zip slip)"))
            return
        if (info.file_size > 1024 * 1024 and info.compress_size > 0
                and info.file_size / info.compress_size > self.max_ratio):
            res.zip_bomb = True
            res.zip_bomb_reason = (f"'{visible_name(info.filename)}' expands "
                                   f"{info.file_size / info.compress_size:,.0f}x "
                                   f"(limit {self.max_ratio:.0f}x).")
            return

        member = ArchiveMember(shown, info.file_size, info.compress_size,
                               encrypted=bool(info.flag_bits & 0x1))
        base = PurePosixPath(info.filename.replace("\\", "/")).name or "member"
        self._classify_name(base, shown, member, res)

        target_dir = sandbox / f"m{len(res.members):04d}"
        target_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w.\- ]", "_", base.replace(RTLO, ""))[-120:] or "member"
        target = target_dir / safe
        candidates: List[Optional[str]] = [None]
        if member.encrypted:
            stem = Path(archive.name).stem
            candidates = list(dict.fromkeys([*self.passwords, stem, stem.lower()]))
        for pwd in candidates:
            outcome = self._extract_one(zf, info, target, pwd, res)
            if outcome == "ok":
                member.extracted = True
                member.path = str(target)
                if pwd:
                    res.password_used = pwd
                break
            if outcome == "bomb":
                res.members.append(member)
                return
            if outcome == "unsupported":
                member.skipped_reason = "unsupported compression or encryption method"
                break
        if not member.extracted:
            res.unreadable_members += 1
            member.skipped_reason = member.skipped_reason or (
                "encrypted - password unknown" if member.encrypted else "could not extract")
        else:
            with open(target, "rb") as fh:
                head = fh.read(8)
            kind = next((k for magic, k in _EXEC_MAGIC if head.startswith(magic)), None)
            if kind and not member.executable:
                member.executable = True
                res.executable_members.append(shown)
        res.members.append(member)

        if member.extracted and target.suffix.lower() in self.SUPPORTED_EXTENSIONS \
                and zipfile.is_zipfile(target):
            self._walk(target, shown, sandbox, depth + 1, res)

    def _extract_one(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path,
                     pwd: Optional[str], res: ContainerResult) -> str:
        written = 0
        budget = self.max_total_bytes - res.total_uncompressed
        try:
            with zf.open(info, pwd=pwd.encode() if pwd else None) as src, \
                    open(target, "wb") as dst:
                while True:
                    chunk = src.read(_STREAM_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > budget:
                        dst.close()
                        target.unlink(missing_ok=True)
                        res.zip_bomb = True
                        res.zip_bomb_reason = (f"Actual decompressed data exceeded the "
                                               f"{self.max_total_bytes:,}-byte limit.")
                        return "bomb"
                    dst.write(chunk)
        except NotImplementedError:
            target.unlink(missing_ok=True)
            return "unsupported"
        except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError):
            target.unlink(missing_ok=True)       # wrong password / corrupt member
            return "failed"
        res.total_uncompressed += written
        return "ok"

    @staticmethod
    def _classify_name(base: str, shown: str, member: ArchiveMember,
                       res: ContainerResult) -> None:
        clean = base.replace(RTLO, "")
        suffixes = [s.strip().lower() for s in PurePosixPath(clean).suffixes]
        if RTLO in base:
            res.rtlo_members.append(shown)
        if suffixes and suffixes[-1] in EXECUTABLE_EXTENSIONS:
            member.executable = True
            res.executable_members.append(shown)
            if len(suffixes) >= 2 and suffixes[-2] in LURE_EXTENSIONS:
                res.double_extension_members.append(shown)

    @staticmethod
    def _summary(res: ContainerResult) -> str:
        bits = [f"{len(res.members)} member(s), {res.total_uncompressed:,} bytes extracted"]
        if res.zip_bomb:
            bits.append(f"ZIP BOMB: {res.zip_bomb_reason}")
        if res.zip_slip:
            bits.append(f"ZIP SLIP: {res.zip_slip_reason}")
        if res.executable_members:
            bits.append(f"{len(res.executable_members)} executable/script member(s)")
        if res.double_extension_members:
            bits.append("double-extension lure name(s)")
        if res.rtlo_members:
            bits.append("right-to-left-override filename spoofing")
        if res.encrypted_unreadable:
            bits.append("encrypted member(s) could not be opened")
        elif res.password_used:
            bits.append(f"opened with password '{res.password_used}'")
        return "; ".join(bits) + "."
