"""
Static triage of Linux ELF executables and shared objects.

Before 4.4.0-beta.2 the engine only noticed an ELF file when it was disguised as a
document or sat inside an archive. This module looks at the ELF itself, without
running it:

* **Header** - 32/64-bit, endianness, type (executable, shared object, relocatable,
  core), machine, program and section header counts, statically or dynamically
  linked (a PT_INTERP program header means dynamic).
* **Packing** - the UPX marker, or near-random content (entropy) with few or no
  sections, which is how packed and encrypted payloads look.
* **Section headers removed** - a runnable ELF with no section table at all
  (`sstrip`); ordinary toolchains keep it, so this is an evasion hint.
* **Behaviour strings** - printable strings that only make sense in hostile code:
  ransom notes, cryptominer pool URLs, reverse shells, download-and-run one-liners,
  log/firewall tampering and persistence paths. Categories that also occur in
  legitimate system binaries (persistence, defence evasion) need two distinct
  markers before they count.

Everything is bounded (a size cap on what is read) and a malformed header is a
finding, not an exception.
"""

from __future__ import annotations

import math
import re
from collections import Counter
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

PathLike = Union[str, Path]

ELF_MAGIC = b"\x7fELF"
_MAX_READ = 64 * 1024 * 1024          # bytes examined for strings and entropy
_PACKED_ENTROPY = 7.3                  # bits per byte
_MIN_PACKED_SIZE = 16 * 1024

_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
_MACHINES = {3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM", 42: "SuperH",
             43: "SPARC v9", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
_PT_INTERP = 3

# Behaviour markers, matched on the lower-cased printable strings of the file.
# (category, minimum distinct markers, patterns)
_MARKERS = [
    ("ransom_note", 1, [
        r"your (?:important )?(?:files|data|documents)[^\n]{0,60}(?:encrypted|locked)",
        r"(?:files|data) (?:have been|has been|were) encrypted",
        r"(?:pay|send)[^\n]{0,40}(?:bitcoin|btc|monero|xmr)",
        r"decrypt(?:ion)? (?:key|tool)[^\n]{0,60}(?:bitcoin|btc|monero|\.onion|pay)",
    ]),
    ("miner", 1, [
        r"stratum\+(?:tcp|ssl|tls)://",
        r"\bxmrig\b",
        r"--donate-level",
        r"\bcryptonight\b",
    ]),
    ("reverse_shell", 1, [
        r"/dev/tcp/\d",
        r"\bbash -i\b[^\n]{0,20}>&",
        r"\b(?:nc|ncat|netcat) [^\n]{0,30}-e /bin/(?:ba)?sh",
        r"socat [^\n]{0,40}exec:",
    ]),
    ("download_exec", 1, [
        r"\b(?:wget|curl)\b[^\n]{0,80}https?://[^\n]{0,160}\|\s*(?:ba)?sh\b",
        r"chmod\s+(?:\+x|[0-7]?7[0-7]{2})\s+/(?:tmp|dev/shm|var/tmp)/",
    ]),
    ("evasion", 2, [
        r"iptables -f\b",
        r"setenforce 0",
        r"history -c",
        r"rm -rf /var/log",
        r"ufw disable",
        r"/proc/sys/kernel/nmi_watchdog",
        r"unset histfile",
    ]),
    ("persistence", 2, [
        r"/etc/ld\.so\.preload",
        r"/etc/rc\.local",
        r"/etc/cron\.d/",
        r"crontab -[lr]?\s*(?:\||-)",
        r"/etc/init\.d/",
        r"\.config/autostart",
    ]),
]
_COMPILED = [(cat, need, [re.compile(p) for p in pats]) for cat, need, pats in _MARKERS]
_STRINGS = re.compile(rb"[\x20-\x7e\t]{6,}")


@dataclass
class ElfResult:
    is_elf: bool = False
    bits: int = 0
    endian: str = ""
    elf_type: str = ""
    machine: str = ""
    linking: str = ""                   # "static" | "dynamic" | ""
    program_headers: int = 0
    sections: int = 0
    entropy: float = 0.0
    packed: bool = False
    packer: str = ""
    no_section_table: bool = False
    malformed: bool = False
    categories: Dict[str, List[str]] = field(default_factory=dict)
    detail: str = ""

    def as_dict(self) -> Dict:
        return {
            "is_elf": self.is_elf, "bits": self.bits, "endian": self.endian,
            "type": self.elf_type, "machine": self.machine, "linking": self.linking,
            "program_headers": self.program_headers, "sections": self.sections,
            "entropy": round(self.entropy, 2), "packed": self.packed, "packer": self.packer,
            "no_section_table": self.no_section_table, "malformed": self.malformed,
            "behaviour": self.categories, "detail": self.detail,
        }


def is_elf(path: PathLike) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == ELF_MAGIC
    except OSError:
        return False


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


class ElfAnalyzer:
    def __init__(self, max_read: int = _MAX_READ):
        self.max_read = max_read

    def analyze_file(self, path: PathLike, data: Optional[bytes] = None) -> ElfResult:
        res = ElfResult()
        if data is not None:
            data = data[: self.max_read]
        else:
            try:
                with open(path, "rb") as fh:
                    data = fh.read(self.max_read)
            except OSError as e:
                res.detail = f"Could not read file: {e}"
                return res
        if not data.startswith(ELF_MAGIC):
            res.detail = "Not an ELF file."
            return res
        res.is_elf = True
        self._header(data, res)
        res.entropy = _entropy(data[:2 * 1024 * 1024])
        if b"UPX!" in data[:64 * 1024] or b"UPX!" in data[-4096:]:
            res.packed, res.packer = True, "UPX"
        elif (len(data) >= _MIN_PACKED_SIZE and res.entropy >= _PACKED_ENTROPY
              and res.sections <= 3):
            res.packed, res.packer = True, "unknown (near-random content, few sections)"
        self._behaviour(data, res)
        res.detail = self._summary(res)
        return res

    # ------------------------------------------------------------------ header
    @staticmethod
    def _header(data: bytes, res: ElfResult) -> None:
        if len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
            res.malformed = True
            return
        res.bits = 32 if data[4] == 1 else 64
        res.endian = "little" if data[5] == 1 else "big"
        e = "<" if data[5] == 1 else ">"
        try:
            e_type, e_machine = struct.unpack_from(e + "HH", data, 16)
            if res.bits == 64:
                if len(data) < 64:
                    raise struct.error("short header")
                e_phoff = struct.unpack_from(e + "Q", data, 32)[0]
                e_phentsize, e_phnum, _shentsize, e_shnum = struct.unpack_from(e + "HHHH", data, 54)
            else:
                e_phoff = struct.unpack_from(e + "I", data, 28)[0]
                e_phentsize, e_phnum, _shentsize, e_shnum = struct.unpack_from(e + "HHHH", data, 42)
        except struct.error:
            res.malformed = True
            return
        res.elf_type = _TYPES.get(e_type, f"0x{e_type:x}")
        res.machine = _MACHINES.get(e_machine, f"machine {e_machine}")
        res.program_headers, res.sections = e_phnum, e_shnum
        res.no_section_table = e_type in (2, 3) and e_shnum == 0
        if e_type in (2, 3) and e_phnum and e_phentsize >= 4:
            interp = False
            for i in range(min(e_phnum, 256)):
                off = e_phoff + i * e_phentsize
                if off + 4 > len(data):
                    break
                if struct.unpack_from(e + "I", data, off)[0] == _PT_INTERP:
                    interp = True
                    break
            res.linking = "dynamic" if interp else "static"

    # --------------------------------------------------------------- behaviour
    @staticmethod
    def _behaviour(data: bytes, res: ElfResult) -> None:
        text = "\n".join(m.group().decode("ascii", "replace").lower()
                         for m in _STRINGS.finditer(data))
        for cat, need, patterns in _COMPILED:
            hits = []
            for pat in patterns:
                m = pat.search(text)
                if m:
                    hits.append(m.group()[:80])
            if len(hits) >= need:
                res.categories[cat] = hits

    @staticmethod
    def _summary(res: ElfResult) -> str:
        if res.malformed:
            return "ELF header is malformed or truncated."
        bits = [f"{res.bits}-bit {res.machine} {res.elf_type}"]
        if res.linking:
            bits.append(f"{res.linking}ally linked")
        if res.packed:
            bits.append(f"packed ({res.packer})")
        if res.no_section_table:
            bits.append("section table removed")
        if res.categories:
            bits.append("behaviour: " + ", ".join(sorted(res.categories)))
        return "; ".join(bits) + "."
