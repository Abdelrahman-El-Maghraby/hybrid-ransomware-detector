"""
Safe archive inspection (ZIP, 7z, RAR, ISO): unpack into a throw-away sandbox,
defend against archive attacks, and hand every member to the full scan
pipeline.

WHY THIS EXISTS
---------------
Malicious documents are usually *delivered* in archives - an invoice.zip
attached to an email - partly because many gateways don't look inside, and
partly because a password-protected archive (password in the email body)
defeats scanning entirely. ISO images are used the same way: files inside an
ISO did not inherit the Windows "downloaded from the internet" mark, so Office
macros and SmartScreen warnings were bypassed.

All formats go through the same checks:

* **Bombs** - absurd compression ratios, too many entries, too much
  decompressed data, or excessive nesting. Limits are checked against the
  declared sizes before anything is written; ZIP and ISO members are also
  limited while streaming (declared sizes can lie), 7z members are checked
  right after extraction.
* **Path escapes ("zip slip")** - members whose names escape the extraction
  directory (`../../.bashrc`, absolute paths, drive letters) or are symlinks.
  Such members are never written; their presence is itself evidence of an attack.
* **Executables and lure names** - scripts/executables/shortcuts inside the
  archive (by extension *and* by magic bytes), double extensions like
  `invoice.pdf.exe`, and the right-to-left-override trick (`invoice\\u202Efdp.exe`
  displays as `invoiceexe.pdf`).
* **Encryption** - encrypted members (ZipCrypto, WinZip AES, 7z AES, RAR, including
  7z and RAR archives whose file names are encrypted) are tried against a short list of
  passwords commonly used for malware delivery ("infected", the archive's own
  name, ...). If none works the archive is reported as unreadable, because an
  archive the scanner cannot open is a classic evasion technique.

FORMATS AND LIBRARIES (all optional, pure Python or prebuilt wheels)
--------------------------------------------------------------------
  .zip            standard library; AES members need `pyzipper`
  .7z             `py7zr`
  .iso / .img     `pycdlib` (ISO 9660 images, with Joliet / Rock Ridge names)
  .rar            `rarfile` + one decompressor already on the machine: 7-Zip,
                  unrar, unar or bsdtar (RAR's compression is proprietary, so
                  no pure-Python decoder exists)
A recognised archive whose library is missing is reported as unreadable, with
the package to install.

RAR is the only format that runs an external program. It is only ever asked to
decompress ONE member to stdout (`7z e -so`, `unrar p`), never to write files,
so its own path handling (the source of past unrar traversal bugs) is never
used: every byte comes back through the same bounded writer and the sandbox
naming as the other formats. Member names, sizes, encryption and symlinks are
read by `rarfile` in Python, so the name checks work even with no tool installed.
"""

from __future__ import annotations

import contextlib
import logging
import os
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

try:  # WinZip AES (compression type 99); also reads ZipCrypto and plain ZIPs
    import pyzipper as _pyzipper  # type: ignore
    AES_ZIP_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    _pyzipper = None
    AES_ZIP_AVAILABLE = False

try:
    import py7zr as _py7zr  # type: ignore
    SEVENZIP_AVAILABLE = True
except ImportError:  # pragma: no cover
    _py7zr = None
    SEVENZIP_AVAILABLE = False

try:
    import pycdlib as _pycdlib  # type: ignore
    ISO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _pycdlib = None
    ISO_AVAILABLE = False

try:
    import rarfile as _rarfile  # type: ignore
    RAR_AVAILABLE = True
except ImportError:  # pragma: no cover
    _rarfile = None
    RAR_AVAILABLE = False

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
RTLO = "‮"   # right-to-left override (escaped on purpose: never put it in source)
_STREAM_CHUNK = 64 * 1024
_SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
_RAR_MAGICS = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")      # RAR 1.5-4.x, RAR 5
_ISO_DESCRIPTOR_OFFSETS = (0x8001, 0x8801, 0x9001)
_FORMAT_EXTENSIONS = {"zip": {".zip"}, "7z": {".7z"}, "iso": {".iso", ".img"},
                      "rar": {".rar"}}
_MISSING_LIBRARY = {"7z": "py7zr", "iso": "pycdlib", "rar": "rarfile",
                    "rar-tool": "7-Zip, unrar or unar (a RAR decompressor)"}
# Where the RAR decompressors live on Windows when they are not on PATH.
_WINDOWS_RAR_TOOLS = (("SEVENZIP_TOOL", r"7-Zip\7z.exe"), ("UNRAR_TOOL", r"WinRAR\UnRAR.exe"))
_rar_tool_state: Optional[bool] = None


def rar_tool_available() -> bool:
    """True if rarfile can find a program to decompress RAR members (cached)."""
    global _rar_tool_state
    if not RAR_AVAILABLE:
        return False
    if _rar_tool_state is None:
        if os.name == "nt":
            for setting, rel in _WINDOWS_RAR_TOOLS:
                if shutil.which(getattr(_rarfile, setting)):
                    continue
                for base in filter(None, (os.environ.get("ProgramFiles"),
                                          os.environ.get("ProgramFiles(x86)"))):
                    candidate = os.path.join(base, rel)
                    if os.path.isfile(candidate):
                        setattr(_rarfile, setting, candidate)
                        break
        try:
            _rarfile.tool_setup(force=True)
            _rar_tool_state = True
        except Exception:
            _rar_tool_state = False
    return _rar_tool_state

_BAD_ZIP_ERRORS = (zipfile.BadZipFile,) + (
    (_pyzipper.BadZipFile,) if AES_ZIP_AVAILABLE and _pyzipper.BadZipFile is not zipfile.BadZipFile
    else ())


class _BudgetExceeded(Exception):
    """Raised by a bounded writer when a member outgrows the decompression budget."""


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
    nested: bool = False            # a container itself (its members are listed too)

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
    missing_support: List[str] = field(default_factory=list)   # libraries to install

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


def detect_container(file_path: PathLike) -> Optional[str]:
    """'zip' | '7z' | 'rar' | 'iso' when the extension AND the content agree, else None."""
    path = Path(file_path)
    ext = path.suffix.lower()
    try:
        if ext in _FORMAT_EXTENSIONS["zip"]:
            return "zip" if zipfile.is_zipfile(path) else None
        if ext in _FORMAT_EXTENSIONS["7z"]:
            with open(path, "rb") as fh:
                return "7z" if fh.read(6) == _SEVENZIP_MAGIC else None
        if ext in _FORMAT_EXTENSIONS["rar"]:
            with open(path, "rb") as fh:
                head = fh.read(8)
            return "rar" if head.startswith(_RAR_MAGICS) else None
        if ext in _FORMAT_EXTENSIONS["iso"]:
            with open(path, "rb") as fh:
                for off in _ISO_DESCRIPTOR_OFFSETS:
                    fh.seek(off)
                    if fh.read(5) == b"CD001":
                        return "iso"
    except OSError:
        return None
    return None


def _open_zip(path: Path):
    return _pyzipper.AESZipFile(path) if AES_ZIP_AVAILABLE else zipfile.ZipFile(path)


class _BoundedWriter:
    """File-like sink that refuses to grow past `budget` bytes."""

    def __init__(self, fh, budget: int):
        self.fh, self.budget, self.written = fh, budget, 0

    def write(self, data) -> int:
        self.written += len(data)
        if self.written > self.budget:
            raise _BudgetExceeded()
        return self.fh.write(data)


class ContainerExtractor:
    """Recursive, bounded archive extraction into a temporary sandbox."""

    SUPPORTED_EXTENSIONS = frozenset(set().union(*_FORMAT_EXTENSIONS.values()))

    def __init__(self, max_depth: int = 3, max_total_bytes: int = 100 * 1024 * 1024,
                 max_members: int = 500, max_ratio: float = 100.0,
                 passwords=DEFAULT_PASSWORDS):
        self.max_depth = int(max_depth)
        self.max_total_bytes = int(max_total_bytes)
        self.max_members = int(max_members)
        self.max_ratio = float(max_ratio)
        self.passwords = tuple(passwords)

    def is_container(self, file_path: PathLike) -> bool:
        return detect_container(file_path) is not None

    @contextlib.contextmanager
    def open(self, file_path: PathLike) -> Iterator[ContainerResult]:
        """Extract into a sandbox that exists only inside the `with` block."""
        path = Path(file_path)
        result = ContainerResult(is_container=True,
                                 container_type=detect_container(path) or "zip")
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
        fmt = detect_container(archive) or "zip"
        if fmt == "7z":
            self._walk_7z(archive, display, sandbox, depth, res)
        elif fmt == "rar":
            self._walk_rar(archive, display, sandbox, depth, res)
        elif fmt == "iso":
            self._walk_iso(archive, display, sandbox, depth, res)
        else:
            self._walk_zip(archive, display, sandbox, depth, res)

    def _candidates(self, archive: Path) -> List[Optional[str]]:
        stem = Path(archive.name).stem
        return list(dict.fromkeys([*self.passwords, stem, stem.lower()]))

    def _missing(self, fmt: str, res: ContainerResult, count: int = 1) -> None:
        res.unreadable_members += count
        lib = _MISSING_LIBRARY[fmt]
        if lib not in res.missing_support:
            res.missing_support.append(lib)
            how = f"install {lib}" if fmt == "rar-tool" else f"pip install {lib}"
            logger.warning("Cannot look inside this %s archive: %s "
                           "(its contents were NOT scanned).", fmt.split("-")[0], how)

    # ---------- shared member handling
    def _admit(self, name: str, size: int, csize: int, is_link: bool, shown: str,
               res: ContainerResult) -> bool:
        """Path/symlink and ratio checks shared by every format. False = do not extract."""
        reason = _unsafe_member_path(name)
        if reason is None and is_link:
            reason = f"symbolic link entry '{visible_name(name)}'"
        if reason:
            res.zip_slip = True
            res.zip_slip_reason = res.zip_slip_reason or f"Blocked {reason}."
            res.members.append(ArchiveMember(shown, size, csize,
                                             skipped_reason="unsafe path (zip slip)"))
            return False
        if size > 1024 * 1024 and csize > 0 and size / csize > self.max_ratio:
            res.zip_bomb = True
            res.zip_bomb_reason = (f"'{visible_name(name)}' expands "
                                   f"{size / csize:,.0f}x (limit {self.max_ratio:.0f}x).")
            return False
        return True

    def _limits_ok(self, count: int, declared: int, res: ContainerResult) -> bool:
        if len(res.members) + count > self.max_members:
            res.zip_bomb = True
            res.zip_bomb_reason = (f"{len(res.members) + count} entries exceed the "
                                   f"{self.max_members}-member limit.")
            return False
        if res.total_uncompressed + declared > self.max_total_bytes:
            res.zip_bomb = True
            res.zip_bomb_reason = (f"Declared uncompressed size {declared:,} bytes exceeds "
                                   f"the {self.max_total_bytes:,}-byte limit.")
            return False
        return True

    @staticmethod
    def _target(name: str, sandbox: Path, res: ContainerResult) -> Path:
        base = PurePosixPath(name.replace("\\", "/")).name or "member"
        target_dir = sandbox / f"m{len(res.members):04d}"
        target_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w.\- ]", "_", base.replace(RTLO, ""))[-120:] or "member"
        return target_dir / safe

    def _new_member(self, name: str, size: int, csize: int, encrypted: bool, shown: str,
                    res: ContainerResult) -> ArchiveMember:
        member = ArchiveMember(shown, size, csize, encrypted=encrypted)
        base = PurePosixPath(name.replace("\\", "/")).name or "member"
        self._classify_name(base, shown, member, res)
        return member

    def _finish(self, member: ArchiveMember, target: Path, sandbox: Path, depth: int,
                res: ContainerResult) -> None:
        """Count unreadable members, check magic bytes, record, recurse into containers."""
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
                res.executable_members.append(member.name)
        res.members.append(member)
        if member.extracted and detect_container(target):
            member.nested = True
            self._walk(target, member.name, sandbox, depth + 1, res)

    def _stream_into(self, target: Path, read_chunks, res: ContainerResult) -> str:
        """Write chunks to `target` within the budget: 'ok' | 'bomb' | 'failed'."""
        written = 0
        budget = self.max_total_bytes - res.total_uncompressed
        with open(target, "wb") as dst:
            for chunk in read_chunks:
                written += len(chunk)
                if written > budget:
                    dst.close()
                    target.unlink(missing_ok=True)
                    res.zip_bomb = True
                    res.zip_bomb_reason = (f"Actual decompressed data exceeded the "
                                           f"{self.max_total_bytes:,}-byte limit.")
                    return "bomb"
                dst.write(chunk)
        res.total_uncompressed += written
        return "ok"

    # ---------- ZIP (stdlib; AES through pyzipper)
    def _walk_zip(self, archive: Path, display: str, sandbox: Path, depth: int,
                  res: ContainerResult) -> None:
        try:
            zf = _open_zip(archive)
        except (*_BAD_ZIP_ERRORS, OSError) as e:
            res.unreadable_members += 1
            logger.debug("Unreadable archive %s: %s", display, e)
            return
        with zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if not self._limits_ok(len(infos), sum(i.file_size for i in infos), res):
                return
            for info in infos:
                if res.zip_bomb:
                    return
                self._zip_member(zf, info, archive, display, sandbox, depth, res)

    def _zip_member(self, zf, info, archive: Path, display: str, sandbox: Path, depth: int,
                    res: ContainerResult) -> None:
        shown = f"{display}!/{visible_name(info.filename)}"
        mode = (info.external_attr >> 16) & 0xFFFF
        if not self._admit(info.filename, info.file_size, info.compress_size,
                           stat.S_ISLNK(mode), shown, res):
            return
        member = self._new_member(info.filename, info.file_size, info.compress_size,
                                  bool(info.flag_bits & 0x1), shown, res)
        target = self._target(info.filename, sandbox, res)
        candidates: List[Optional[str]] = [None]
        if member.encrypted:
            candidates = self._candidates(archive)
        for pwd in candidates:
            outcome = self._extract_zip_member(zf, info, target, pwd, res)
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
                member.skipped_reason = ("unsupported compression or encryption method"
                                         + ("" if AES_ZIP_AVAILABLE else
                                            " (AES needs: pip install pyzipper)"))
                break
        self._finish(member, target, sandbox, depth, res)

    def _extract_zip_member(self, zf, info, target: Path, pwd: Optional[str],
                            res: ContainerResult) -> str:
        try:
            with zf.open(info, pwd=pwd.encode() if pwd else None) as src:
                return self._stream_into(target, iter(lambda: src.read(_STREAM_CHUNK), b""),
                                         res)
        except NotImplementedError:
            target.unlink(missing_ok=True)
            return "unsupported"
        except (RuntimeError, *_BAD_ZIP_ERRORS, zlib.error, EOFError, OSError, ValueError):
            target.unlink(missing_ok=True)       # wrong password / corrupt member
            return "failed"
        except Exception:                        # pyzipper raises its own error types
            target.unlink(missing_ok=True)
            return "failed"

    # ---------- 7z (py7zr)
    def _walk_7z(self, archive: Path, display: str, sandbox: Path, depth: int,
                 res: ContainerResult) -> None:
        if not SEVENZIP_AVAILABLE:
            self._missing("7z", res)
            return
        listing_pwd: Optional[str] = None
        try:
            with _py7zr.SevenZipFile(archive) as z:
                infos, needs_pwd = z.list(), z.needs_password()
        except _py7zr.exceptions.PasswordRequired:
            # The file NAMES are encrypted too: nothing is listed until a password opens it.
            infos, needs_pwd = None, True
            for pwd in self._candidates(archive):
                try:
                    with _py7zr.SevenZipFile(archive, password=pwd) as z:
                        infos = z.list()
                    listing_pwd = pwd
                    break
                except Exception:
                    continue
            if infos is None:
                res.unreadable_members += 1
                res.members.append(ArchiveMember(f"{display}!/(encrypted file names)",
                                                 encrypted=True,
                                                 skipped_reason="encrypted - password unknown"))
                return
        except Exception as e:
            res.unreadable_members += 1
            logger.debug("Unreadable 7z %s: %s", display, e)
            return

        files = [i for i in infos if not i.is_directory]
        if not self._limits_ok(len(files), sum(i.uncompressed or 0 for i in files), res):
            return
        admitted = []
        for info in files:
            shown = f"{display}!/{visible_name(info.filename)}"
            size, csize = int(info.uncompressed or 0), int(info.compressed or 0)
            if self._admit(info.filename, size, csize, bool(getattr(info, "is_symlink", False)),
                           shown, res):
                admitted.append((info, self._new_member(info.filename, size, csize,
                                                        needs_pwd, shown, res)))
            if res.zip_bomb:
                return
        if not admitted:
            return

        raw = Path(tempfile.mkdtemp(prefix="raw7z_", dir=sandbox))
        candidates = ([listing_pwd] if listing_pwd else
                      self._candidates(archive) if needs_pwd else [None])
        used, extracted = None, False
        for pwd in candidates:
            shutil.rmtree(raw, ignore_errors=True)
            raw.mkdir()
            try:
                with _py7zr.SevenZipFile(archive, password=pwd) as z:
                    z.extract(path=raw, targets=[i.filename for i, _ in admitted])
                used, extracted = pwd, True
                break
            except Exception:
                continue
        for info, member in admitted:
            target = self._target(info.filename, sandbox, res)
            src = (raw / info.filename).resolve()
            if extracted and raw.resolve() in src.parents and src.is_file() \
                    and not src.is_symlink():
                size = src.stat().st_size
                if res.total_uncompressed + size > self.max_total_bytes:
                    res.zip_bomb = True
                    res.zip_bomb_reason = (f"Actual decompressed data exceeded the "
                                           f"{self.max_total_bytes:,}-byte limit.")
                    res.members.append(member)
                    break
                os.replace(src, target)
                res.total_uncompressed += size
                member.extracted, member.path = True, str(target)
                if used:
                    res.password_used = used
            self._finish(member, target, sandbox, depth, res)
            if res.zip_bomb:
                break
        shutil.rmtree(raw, ignore_errors=True)

    # ---------- RAR (rarfile + an external decompressor)
    def _walk_rar(self, archive: Path, display: str, sandbox: Path, depth: int,
                  res: ContainerResult) -> None:
        if not RAR_AVAILABLE:
            self._missing("rar", res)
            return
        try:
            rf = _rarfile.RarFile(str(archive), errors="strict")
            listing_pwd: Optional[str] = None
            if rf.needs_password() and not rf.infolist():
                # RAR5 "encrypt file names": nothing is listed until a password opens it.
                for pwd in self._candidates(archive):
                    try:
                        rf = _rarfile.RarFile(str(archive), errors="strict")
                        rf.setpassword(pwd)
                        rf.infolist()
                        listing_pwd = pwd
                        break
                    except Exception:
                        continue
                if listing_pwd is None:
                    res.unreadable_members += 1
                    res.members.append(ArchiveMember(f"{display}!/(encrypted file names)",
                                                     encrypted=True,
                                                     skipped_reason="encrypted - password unknown"))
                    return
            infos = [i for i in rf.infolist() if not i.is_dir()]
        except Exception as e:                   # corrupt, or a later volume of a set
            res.unreadable_members += 1
            logger.debug("Unreadable RAR %s: %s", display, e)
            return
        with contextlib.closing(rf):
            if not self._limits_ok(len(infos), sum(int(i.file_size or 0) for i in infos), res):
                return
            for info in infos:
                if res.zip_bomb:
                    return
                self._rar_member(rf, info, archive, display, sandbox, depth, listing_pwd, res)

    def _rar_member(self, rf, info, archive: Path, display: str, sandbox: Path, depth: int,
                    listing_pwd: Optional[str], res: ContainerResult) -> None:
        name = info.filename
        shown = f"{display}!/{visible_name(name)}"
        size, csize = int(info.file_size or 0), int(info.compress_size or 0)
        if not self._admit(name, size, csize, info.is_symlink(), shown, res):
            return
        member = self._new_member(name, size, csize, bool(info.needs_password()), shown, res)
        target = self._target(name, sandbox, res)
        rar_tool_available()                     # also locates 7-Zip / WinRAR on Windows
        candidates: List[Optional[str]] = [None]
        if member.encrypted:
            candidates = [listing_pwd] if listing_pwd else self._candidates(archive)
        for pwd in candidates:
            try:
                with rf.open(info, pwd=pwd) as src:
                    outcome = self._stream_into(
                        target, iter(lambda: src.read(_STREAM_CHUNK), b""), res)
            except _rarfile.RarCannotExec:
                # No decompressor installed. Stored members don't need one, so this
                # is per member; the name checks above were still applied.
                target.unlink(missing_ok=True)
                member.skipped_reason = "needs a RAR decompressor (7-Zip, unrar or unar)"
                self._missing("rar-tool", res, count=0)
                break
            except Exception as e:               # wrong password, CRC error, tool failure
                target.unlink(missing_ok=True)
                logger.debug("RAR member %s failed: %s", shown, e)
                continue
            if outcome == "bomb":
                res.members.append(member)
                return
            member.extracted, member.path = True, str(target)
            if pwd:
                res.password_used = pwd
            break
        self._finish(member, target, sandbox, depth, res)

    # ---------- ISO 9660 (pycdlib)
    def _walk_iso(self, archive: Path, display: str, sandbox: Path, depth: int,
                  res: ContainerResult) -> None:
        if not ISO_AVAILABLE:
            self._missing("iso", res)
            return
        iso = _pycdlib.PyCdlib()
        try:
            iso.open(str(archive))
        except Exception as e:
            res.unreadable_members += 1
            logger.debug("Unreadable ISO %s: %s", display, e)
            return
        try:
            # Prefer the names Windows/Linux show: Rock Ridge, then Joliet, then 8.3.
            key = ("rr_path" if iso.has_rock_ridge() else
                   "joliet_path" if iso.has_joliet() else "iso_path")
            entries = []
            for dirname, _dirs, files in iso.walk(**{key: "/"}):
                for fn in files:
                    p = dirname.rstrip("/") + "/" + fn
                    entries.append((p, iso.get_record(**{key: p})))
            if not self._limits_ok(len(entries),
                                   sum(r.get_data_length() for _, r in entries), res):
                return
            for p, rec in entries:
                if res.zip_bomb:
                    return
                name = p.lstrip("/")
                if key == "iso_path":
                    name = re.sub(r";\d+$", "", name)
                size = rec.get_data_length()
                is_link = bool(key == "rr_path" and getattr(rec, "rock_ridge", None)
                               and rec.rock_ridge.is_symlink())
                shown = f"{display}!/{visible_name(name)}"
                if not self._admit(name, size, size, is_link, shown, res):
                    continue
                member = self._new_member(name, size, size, False, shown, res)
                target = self._target(name, sandbox, res)
                budget = self.max_total_bytes - res.total_uncompressed
                try:
                    with open(target, "wb") as fh:
                        sink = _BoundedWriter(fh, budget)
                        iso.get_file_from_iso_fp(sink, **{key: p})
                    res.total_uncompressed += sink.written
                    member.extracted, member.path = True, str(target)
                except _BudgetExceeded:
                    target.unlink(missing_ok=True)
                    res.zip_bomb = True
                    res.zip_bomb_reason = (f"Actual decompressed data exceeded the "
                                           f"{self.max_total_bytes:,}-byte limit.")
                    res.members.append(member)
                    return
                except Exception as e:
                    target.unlink(missing_ok=True)
                    logger.debug("ISO member %s failed: %s", shown, e)
                self._finish(member, target, sandbox, depth, res)
        finally:
            with contextlib.suppress(Exception):
                iso.close()

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
        for lib in res.missing_support:
            how = f"install {lib}" if lib == _MISSING_LIBRARY["rar-tool"] else f"pip install {lib}"
            bits.append(f"could not be opened: {how}")
        return "; ".join(bits) + "."
