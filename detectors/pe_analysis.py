"""
Static triage of Windows PE files (.exe, .dll, .sys, .scr, .cpl ...).

Until 4.6 a Windows program was only looked at by YARA, the ML layer and
VirusTotal. This module reads the PE structure itself, without running it and
without third-party libraries (pefile is not needed):

* **Sections** - Shannon entropy per section, packer section names (UPX,
  VMProtect, Themida, ASPack ...), and sections that are both writable and
  executable (an unpacking stub or self-modifying code).
* **Imports** - the import table is parsed (names, not just DLL counts) and
  checked for three combinations:
    - process injection: memory allocated in another process, written, and
      a thread started there. One of the three alone is common in normal
      programs (debuggers, games, browsers); all three together is the
      classic injection chain (T1055).
    - a ransomware profile: an encryption API together with directory walking
      and file writing, in an unsigned program.
    - imports resolved at run time only (LoadLibrary + GetProcAddress and next
      to nothing else), which hides what the program really calls.
* **Recovery inhibition (T1490)** - command lines that delete shadow copies or
  backups and turn off Windows recovery (`vssadmin delete shadows /all`,
  `wbadmin delete catalog -quiet`, `bcdedit ... recoveryenabled no` ...), in
  ASCII or UTF-16 strings. The patterns need the arguments an attacker types,
  so the help text inside vssadmin.exe / wbadmin.exe themselves does not match.
* **Overlay** - data appended after the last section, not counting an
  Authenticode certificate. An overlay that is itself a program (a binder or
  dropper) is flagged; so is a large, near-random overlay in an unsigned file
  that is not a known installer or archive format.
* **Authenticode** - whether a signature directory is present. The signature
  is NOT verified (that needs the Windows trust store); the report says so.
  Presence only switches off the two weakest checks above.

Everything is bounded (bytes read, sections, DLLs, imported names, string
text) and a malformed header is a finding, never an exception.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from .entropy import shannon_entropy

PathLike = Union[str, Path]

_MAX_READ = 64 * 1024 * 1024            # bytes examined at most
_MAX_STRING_BYTES = 16 * 1024 * 1024    # bytes searched for command lines
_MAX_SECTIONS = 96                      # the Windows loader's own limit
_MAX_DLLS = 256
_MAX_IMPORTS = 4096
_ENTROPY_SAMPLE = 4 * 1024 * 1024       # per-section bytes used for entropy

PACKED_ENTROPY = 7.2                    # bits per byte, executable section
_MIN_PACKED_SECTION = 4 * 1024
OVERLAY_MIN_SIZE = 64 * 1024
OVERLAY_ENTROPY = 7.9

SCN_CNT_CODE = 0x00000020
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_WRITE = 0x80000000

DIR_IMPORT = 1
DIR_SECURITY = 4

# Section name -> packer / protector.
PACKER_SECTIONS: Dict[str, str] = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", ".winlice": "WinLicense",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".petite": "Petite", ".packed": "generic packer",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    "pec2": "PECompact", ".pelock": "PELock", ".yp": "Y0da", ".perplex": "Perplex",
}

# Import groups (lower-case function names).
_INJECT_ALLOC = frozenset({"virtualallocex", "virtualalloc2", "ntallocatevirtualmemory",
                           "zwallocatevirtualmemory", "ntmapviewofsection",
                           "zwmapviewofsection"})
_INJECT_WRITE = frozenset({"writeprocessmemory", "ntwritevirtualmemory",
                           "zwwritevirtualmemory"})
_INJECT_EXEC = frozenset({"createremotethread", "createremotethreadex", "ntcreatethreadex",
                          "zwcreatethreadex", "rtlcreateuserthread", "queueuserapc",
                          "ntqueueapcthread", "setthreadcontext", "ntsetcontextthread",
                          "wow64setthreadcontext"})
_CRYPT_ENCRYPT = frozenset({"cryptencrypt", "bcryptencrypt", "ncryptencrypt"})
_FILE_WALK = frozenset({"findfirstfilew", "findfirstfilea", "findfirstfileexw",
                        "findfirstfileexa", "findnextfilew", "findnextfilea"})
_FILE_WRITE = frozenset({"writefile", "movefilew", "movefilea", "movefileexw", "movefileexa",
                         "replacefilew", "setfileinformationbyhandle"})
_RUNTIME_RESOLVE = frozenset({"getprocaddress", "loadlibrarya", "loadlibraryw",
                              "loadlibraryexa", "loadlibraryexw", "ldrloaddll",
                              "ldrgetprocedureaddress"})

# Recovery inhibition (T1490), matched on lower-cased strings.
_RECOVERY = [re.compile(p) for p in (
    r"vssadmin(?:\.exe)?\"?\s+delete\s+shadows",
    r"delete\s+shadows\s+/all",
    r"shadowcopy\s+delete",
    r"win32_shadowcopy[^\n]{0,80}\.delete\(",
    r"wbadmin(?:\.exe)?\"?\s+delete\s+(?:catalog|systemstatebackup|backup)\s+-quiet",
    r"bcdedit(?:\.exe)?\"?[^\n]{0,60}recoveryenabled\s+(?:no|false|off)",
    r"bcdedit(?:\.exe)?\"?[^\n]{0,60}bootstatuspolicy\s+ignoreallfailures",
    r"resize\s+shadowstorage\s+/for=[a-z]:\S*\s+/on=[a-z]:\S*\s+/maxsize=",
)]
# Cheap pre-check (substring search on the lower-cased bytes, ASCII and UTF-16):
# most programs contain none of these words, and then no strings are extracted.
_ANCHOR_WORDS = (b"vssadmin", b"shadow", b"wbadmin", b"bcdedit")
_ANCHORS = _ANCHOR_WORDS + tuple(w.decode().encode("utf-16-le") for w in _ANCHOR_WORDS)
_PRINTABLE = re.compile(rb"[\x20-\x7e]*")
_ASCII = re.compile(rb"[\x20-\x7e\t]{8,}")
_WIDE = re.compile(rb"(?:[\x20-\x7e\t]\x00){8,}")

# Overlays that are compressed by design.
_INSTALLER_MARKERS = (b"NullsoftInst", b"Inno Setup", b"zlb\x1a", b"7z\xbc\xaf\x27\x1c",
                      b"Rar!\x1a\x07", b"PK\x03\x04", b"MSCF", b"\x1f\x8b", b"WiseMain",
                      b"InstallShield", b"\xfd7zXZ")
# Installer engines whose stub names itself somewhere in the program.
_INSTALLER_NAMES = (b"NullsoftInst", b"Nullsoft Install System", b"Inno Setup",
                    b"InstallShield", b"WiseMain", b"7-Zip SFX", b"WinRAR SFX",
                    b"Setup Factory", b"Advanced Installer")


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int
    characteristics: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE))

    @property
    def writable_executable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_EXECUTE
                    and self.characteristics & SCN_MEM_WRITE)

    def as_dict(self) -> Dict:
        flags = ("R" + ("W" if self.characteristics & SCN_MEM_WRITE else "")
                 + ("X" if self.characteristics & SCN_MEM_EXECUTE else ""))
        return {"name": self.name, "raw_size": self.raw_size, "entropy": round(self.entropy, 2),
                "flags": flags}


@dataclass
class PeResult:
    is_pe: bool = False
    bits: int = 0
    kind: str = ""                      # "executable" | "DLL" | "driver"
    machine: str = ""
    malformed: List[str] = field(default_factory=list)
    sections: List[Section] = field(default_factory=list)
    packer: str = ""
    packed: bool = False
    wx_sections: List[str] = field(default_factory=list)
    high_entropy_sections: List[str] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)   # dll -> names
    injection: List[str] = field(default_factory=list)
    ransomware_apis: List[str] = field(default_factory=list)
    runtime_imports_only: bool = False
    recovery_inhibition: List[str] = field(default_factory=list)
    overlay_size: int = 0
    overlay_entropy: float = 0.0
    overlay_executable: bool = False
    overlay_encrypted: bool = False
    signature_present: bool = False
    truncated: bool = False             # only the first max_read bytes were examined
    detail: str = ""

    @property
    def import_count(self) -> int:
        return sum(len(v) for v in self.imports.values())

    def as_dict(self) -> Dict:
        return {
            "is_pe": self.is_pe, "bits": self.bits, "kind": self.kind, "machine": self.machine,
            "malformed": self.malformed,
            "sections": [s.as_dict() for s in self.sections],
            "packed": self.packed, "packer": self.packer,
            "wx_sections": self.wx_sections, "high_entropy_sections": self.high_entropy_sections,
            "import_dlls": len(self.imports), "import_count": self.import_count,
            "injection_apis": self.injection, "ransomware_apis": self.ransomware_apis,
            "runtime_imports_only": self.runtime_imports_only,
            "recovery_inhibition": self.recovery_inhibition,
            "overlay_size": self.overlay_size, "overlay_entropy": round(self.overlay_entropy, 2),
            "overlay_executable": self.overlay_executable,
            "overlay_encrypted": self.overlay_encrypted,
            "signature_present": self.signature_present,
            "signature_verified": False, "truncated": self.truncated,
            "detail": self.detail,
        }


_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0x1C4: "ARMv7",
             0xAA64: "ARM64", 0x200: "IA-64"}
_IMAGE_FILE_DLL = 0x2000
_SUBSYSTEM_NATIVE = 1


def pe_header_offset(data: bytes) -> Optional[int]:
    """Offset of the 'PE\\0\\0' signature, or None when this is not a PE file."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    off = struct.unpack_from("<I", data, 0x3C)[0]
    if off < 0x40 or off + 24 > len(data) or data[off:off + 4] != b"PE\x00\x00":
        return None
    return off


def is_pe(path: PathLike) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    if pe_header_offset(head) is not None:
        return True
    if head[:2] != b"MZ" or len(head) < 0x40:
        return False
    # e_lfanew past the first page (rare but legal): read the signature itself.
    off = struct.unpack_from("<I", head, 0x3C)[0]
    if off > 16 * 1024 * 1024:
        return False
    try:
        with open(path, "rb") as fh:
            fh.seek(off)
            return fh.read(4) == b"PE\x00\x00"
    except OSError:
        return False


class PeAnalyzer:
    def __init__(self, max_read: int = _MAX_READ):
        self.max_read = max_read

    def analyze_file(self, path: PathLike, data: Optional[bytes] = None) -> PeResult:
        try:
            size = Path(path).stat().st_size
            if data is None:
                with open(path, "rb") as fh:
                    data = fh.read(self.max_read)
        except OSError as e:
            return PeResult(detail=f"Could not read file: {e}")
        return self.analyze_bytes(data[: self.max_read], size)

    def analyze_bytes(self, data: bytes, file_size: Optional[int] = None) -> PeResult:
        """`file_size` is the real size when `data` is only the first part of
        the file: sections beyond what was read are then not "malformed", and
        the overlay is not judged."""
        res = PeResult(truncated=bool(file_size and file_size > len(data)))
        pe = pe_header_offset(data)
        if pe is None:
            res.detail = "Not a PE file."
            return res
        res.is_pe = True
        try:
            table, count, dirs = self._headers(data, pe, res)
            if table is not None:
                self._sections(data, table, count, res)
                self._imports(data, dirs, res)
                self._overlay(data, dirs, res)
        except struct.error:
            res.malformed.append("truncated header")
        self._strings(data, res)
        self._verdicts(res)
        res.detail = _summary(res)
        return res

    # ------------------------------------------------------------------ headers
    @staticmethod
    def _headers(data: bytes, pe: int,
                 res: PeResult) -> Tuple[Optional[int], int, List[Tuple[int, int]]]:
        machine, n_sections = struct.unpack_from("<HH", data, pe + 4)
        opt_size, characteristics = struct.unpack_from("<HH", data, pe + 20)
        res.machine = _MACHINES.get(machine, f"machine 0x{machine:x}")
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            res.malformed.append(f"unknown optional-header magic 0x{magic:x}")
            return None, 0, []
        plus = magic == 0x20B
        res.bits = 64 if plus else 32
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        res.kind = ("driver" if subsystem == _SUBSYSTEM_NATIVE
                    else "DLL" if characteristics & _IMAGE_FILE_DLL else "executable")
        n_dirs_at = opt + (108 if plus else 92)
        dirs_at = n_dirs_at + 4
        n_dirs = 0
        if opt_size >= (dirs_at - opt):
            n_dirs = min(struct.unpack_from("<I", data, n_dirs_at)[0], 16,
                         (opt_size - (dirs_at - opt)) // 8)
        dirs = [struct.unpack_from("<II", data, dirs_at + 8 * i) for i in range(max(n_dirs, 0))]
        if n_sections == 0 or n_sections > _MAX_SECTIONS:
            res.malformed.append(f"{n_sections} sections")
        return opt + opt_size, n_sections, dirs

    # ----------------------------------------------------------------- sections
    @staticmethod
    def _sections(data: bytes, table: int, count: int, res: PeResult) -> None:
        for i in range(min(count, _MAX_SECTIONS)):
            off = table + i * 40
            if off + 40 > len(data):
                if not res.truncated:
                    res.malformed.append("section table runs past the end of the file")
                break
            name = data[off:off + 8].split(b"\x00", 1)[0].decode("latin-1")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            sec = Section(name, vaddr, vsize, raw_ptr, raw_size, chars)
            if raw_size and raw_ptr >= len(data) and not res.truncated:
                res.malformed.append(f"section {name!r} starts past the end of the file")
            elif raw_size:
                sec.entropy = shannon_entropy(
                    data[raw_ptr:raw_ptr + min(raw_size, _ENTROPY_SAMPLE)])
            res.sections.append(sec)

    # ------------------------------------------------------------------ imports
    def _imports(self, data: bytes, dirs: Sequence[Tuple[int, int]], res: PeResult) -> None:
        if len(dirs) <= DIR_IMPORT or not dirs[DIR_IMPORT][0]:
            return
        desc = _rva_to_offset(res.sections, dirs[DIR_IMPORT][0])
        if desc is None:
            res.malformed.append("import table outside every section")
            return
        width, flag = (8, 1 << 63) if res.bits == 64 else (4, 1 << 31)
        fmt = "<Q" if width == 8 else "<I"
        total = 0
        for _ in range(_MAX_DLLS):
            if desc + 20 > len(data):
                break
            oft, _ts, _fw, name_rva, ft = struct.unpack_from("<IIIII", data, desc)
            if not (oft or name_rva or ft):
                break
            desc += 20
            dll = _cstring(data, _rva_to_offset(res.sections, name_rva)).lower() or "?"
            names = res.imports.setdefault(dll, [])
            thunk = _rva_to_offset(res.sections, oft or ft)
            while thunk is not None and thunk + width <= len(data) and total < _MAX_IMPORTS:
                value = struct.unpack_from(fmt, data, thunk)[0]
                if not value:
                    break
                thunk += width
                total += 1
                if value & flag:
                    names.append(f"#{value & 0xFFFF}")
                    continue
                hint = _rva_to_offset(res.sections, value & 0x7FFFFFFF)
                names.append(_cstring(data, None if hint is None else hint + 2))

    # ------------------------------------------------------------------ overlay
    @staticmethod
    def _overlay(data: bytes, dirs: Sequence[Tuple[int, int]], res: PeResult) -> None:
        sig_off, sig_size = dirs[DIR_SECURITY] if len(dirs) > DIR_SECURITY else (0, 0)
        res.signature_present = bool(sig_off and sig_size and sig_off + 8 <= len(data))
        end = max((s.raw_pointer + s.raw_size for s in res.sections if s.raw_size), default=0)
        if not end or end >= len(data) or res.truncated:
            return
        overlay = data[end:]
        if res.signature_present and sig_off >= end:      # the certificate is not overlay
            cut = sig_off - end
            overlay = overlay[:cut] + overlay[cut + sig_size:]
        res.overlay_size = len(overlay)
        if not overlay:
            return
        res.overlay_entropy = shannon_entropy(overlay[:_ENTROPY_SAMPLE])
        res.overlay_executable = (pe_header_offset(overlay[:4096]) is not None
                                  or _embedded_pe(overlay))
        head = overlay[:4096]
        known = (any(m in head for m in _INSTALLER_MARKERS)
                 or any(m in data[:end] for m in _INSTALLER_NAMES))
        res.overlay_encrypted = (res.overlay_size >= OVERLAY_MIN_SIZE
                                 and res.overlay_entropy >= OVERLAY_ENTROPY and not known)

    # ------------------------------------------------------------------ strings
    @staticmethod
    def _strings(data: bytes, res: PeResult) -> None:
        blob = data[:_MAX_STRING_BYTES]
        low = blob.lower()
        if not any(a in low for a in _ANCHORS):
            return
        parts = [m.group().decode("ascii", "replace") for m in _ASCII.finditer(blob)]
        parts += [m.group().decode("utf-16-le", "replace") for m in _WIDE.finditer(blob)]
        text = "\n".join(parts).lower()
        for pat in _RECOVERY:
            m = pat.search(text)
            if m:
                res.recovery_inhibition.append(m.group()[:80])

    # ----------------------------------------------------------------- verdicts
    @staticmethod
    def _verdicts(res: PeResult) -> None:
        for s in res.sections:
            low = s.name.lower()
            if low in PACKER_SECTIONS and not res.packer:
                res.packer = PACKER_SECTIONS[low]
            if s.writable_executable:
                res.wx_sections.append(s.name)
            if (s.executable and s.raw_size >= _MIN_PACKED_SECTION
                    and s.entropy >= PACKED_ENTROPY):
                res.high_entropy_sections.append(s.name)
        if not res.packer and res.high_entropy_sections:
            res.packer = "unknown (near-random code section)"
        res.packed = bool(res.packer)

        shown = {n.lower(): n for v in res.imports.values() for n in v}   # original case
        names: Set[str] = set(shown)
        alloc, write, run = (sorted(names & g) for g in (_INJECT_ALLOC, _INJECT_WRITE,
                                                          _INJECT_EXEC))
        if alloc and write and run:
            res.injection = [shown[alloc[0]], shown[write[0]], shown[run[0]]]
        crypt, walk, writes = (sorted(names & g) for g in (_CRYPT_ENCRYPT, _FILE_WALK,
                                                            _FILE_WRITE))
        if crypt and walk and writes and not res.signature_present:
            res.ransomware_apis = [shown[crypt[0]], shown[walk[0]], shown[writes[0]]]
        resolvers = names & _RUNTIME_RESOLVE
        res.runtime_imports_only = (bool(res.imports) and "getprocaddress" in resolvers
                                    and len(resolvers) >= 2 and res.import_count <= 6)
        if res.signature_present:
            res.overlay_encrypted = False


def _rva_to_offset(sections: Sequence[Section], rva: int) -> Optional[int]:
    if not rva:
        return None
    for s in sections:
        span = max(s.virtual_size, s.raw_size)
        if s.virtual_address <= rva < s.virtual_address + span:
            off = rva - s.virtual_address + s.raw_pointer
            return off if off < s.raw_pointer + max(s.raw_size, 1) else None
    first = min((s.raw_pointer for s in sections if s.raw_size), default=0)
    return rva if first and rva < first else None      # inside the headers


def _cstring(data: bytes, off: Optional[int], limit: int = 256) -> str:
    if off is None or off < 0 or off >= len(data):
        return ""
    raw = data[off:off + limit].split(b"\x00", 1)[0]
    return raw.decode("ascii") if _PRINTABLE.fullmatch(raw) else ""


def _embedded_pe(overlay: bytes, window: int = 1024 * 1024, limit: int = 64) -> bool:
    """A complete PE header somewhere in the first megabyte of the overlay."""
    pos, seen = 0, 0
    chunk = overlay[:window]
    while seen < limit:
        pos = chunk.find(b"MZ", pos)
        if pos < 0:
            return False
        seen += 1
        if pe_header_offset(chunk[pos:pos + 4096]) is not None:
            return True
        pos += 2
    return False


def _summary(res: PeResult) -> str:
    if not res.is_pe:
        return res.detail
    bits = [f"{res.bits}-bit {res.machine} {res.kind}".strip() if res.bits
            else "PE file"]
    bits.append(f"{len(res.sections)} section(s), {res.import_count} import(s) "
                f"from {len(res.imports)} DLL(s)")
    if res.packed:
        bits.append(f"packed ({res.packer})")
    if res.wx_sections:
        bits.append("writable+executable: " + ", ".join(res.wx_sections[:3]))
    if res.injection:
        bits.append("injection imports: " + " + ".join(res.injection))
    if res.ransomware_apis:
        bits.append("encrypt/walk/write imports: " + " + ".join(res.ransomware_apis))
    if res.runtime_imports_only:
        bits.append("imports resolved at run time")
    if res.recovery_inhibition:
        bits.append("deletes backups: " + res.recovery_inhibition[0])
    if res.overlay_executable:
        bits.append(f"a program is appended after the sections ({res.overlay_size} bytes)")
    elif res.overlay_encrypted:
        bits.append(f"near-random overlay of {res.overlay_size} bytes")
    if res.malformed:
        bits.append("malformed: " + "; ".join(res.malformed[:2]))
    bits.append("Authenticode signature present (not verified)" if res.signature_present
                else "unsigned")
    return "; ".join(bits) + "."
