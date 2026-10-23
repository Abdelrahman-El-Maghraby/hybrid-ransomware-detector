"""detectors/pe_analysis.py: static triage of Windows programs. Every sample is
built from scratch by tests.helpers.make_pe - the code sections are NOPs and
nothing here can run."""

import os
import random
import struct

import pytest

import RansomwareScanner as RS
from detectors.pe_analysis import PeAnalyzer, _cstring, _embedded_pe, _rva_to_offset, is_pe, pe_header_offset
from detectors.scoring import ScoringMatrix
from engine.layers import PeLayer
from tests.helpers import SCN_CODE_RX, SCN_RWX, make_pe
from tests.test_scanner_integration import _config

A = PeAnalyzer()
K32 = "KERNEL32.dll"
NOP = b"\x90" * 0x400


def analyze(data, **kw):
    return A.analyze_bytes(data, **kw)


# ----------------------------------------------------------------- headers
@pytest.mark.parametrize("bits, kind, label", [
    (32, "exe", "32-bit x86 executable"), (64, "exe", "64-bit x86-64 executable"),
    (64, "dll", "64-bit x86-64 DLL"), (64, "driver", "64-bit x86-64 driver"),
])
def test_header_fields(bits, kind, label):
    r = analyze(make_pe(bits=bits, kind=kind, imports={K32: ["ExitProcess"]}))
    assert r.is_pe and r.detail.startswith(label)
    assert r.imports == {"kernel32.dll": ["ExitProcess"]}
    assert not r.malformed and r.detail.endswith("unsigned.")


def test_clean_program_has_no_findings():
    r = analyze(make_pe(imports={K32: ["CreateFileW", "WriteFile", "ExitProcess"],
                                 "USER32.dll": ["MessageBoxW"]}))
    d = r.as_dict()
    assert not any(d[k] for k in ("packed", "wx_sections", "injection_apis", "ransomware_apis",
                                  "runtime_imports_only", "recovery_inhibition",
                                  "overlay_executable", "overlay_encrypted", "malformed"))
    assert ScoringMatrix().score({"pe": _signals(r)}).risk_score == 0


def test_not_a_pe():
    for data in (b"", b"MZ", b"MZ" + bytes(100), b"\x7fELF" + bytes(200), os.urandom(4096)):
        r = analyze(data)
        assert not r.is_pe and r.detail == "Not a PE file."
    assert pe_header_offset(b"MZ" + bytes(0x3A) + (0x10).to_bytes(4, "little") + bytes(64)) is None


def test_is_pe_reads_the_file(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(make_pe())
    assert is_pe(p)
    far = bytearray(0x3000)                      # e_lfanew beyond the first 4 KB
    far[0:2] = b"MZ"
    struct.pack_into("<I", far, 0x3C, 0x2000)
    far[0x2000:0x2004] = b"PE\x00\x00"
    (tmp_path / "far.exe").write_bytes(bytes(far))
    assert is_pe(tmp_path / "far.exe")
    (tmp_path / "doc.pdf").write_bytes(b"%PDF-1.7")
    assert not is_pe(tmp_path / "doc.pdf") and not is_pe(tmp_path / "missing.exe")
    huge = bytearray(far)
    struct.pack_into("<I", huge, 0x3C, 0x7FFFFFFF)
    (tmp_path / "huge.exe").write_bytes(bytes(huge))
    assert not is_pe(tmp_path / "huge.exe")


# ----------------------------------------------------------------- sections
def test_packer_section_names():
    r = analyze(make_pe(sections=(("UPX0", bytes(0x200), SCN_RWX), ("UPX1", NOP, SCN_RWX)),
                        imports={K32: ["LoadLibraryA", "GetProcAddress"]}))
    assert r.packed and r.packer == "UPX" and r.wx_sections == ["UPX0", "UPX1"]
    s = ScoringMatrix().score({"pe": _signals(r)})
    # Packed: writable code and hidden imports are the packer's doing, scored once.
    assert [c.indicator for c in s.contributions] == ["pe_packed"] and s.risk_score == 20


def test_near_random_code_section_is_packed():
    rnd = random.Random(1).randbytes(16 * 1024)
    r = analyze(make_pe(sections=((".text", rnd, SCN_CODE_RX),)))
    assert r.packed and r.packer.startswith("unknown") and r.high_entropy_sections == [".text"]
    assert r.sections[0].entropy > 7.9


def test_small_random_section_is_not_packing():
    r = analyze(make_pe(sections=((".text", random.Random(2).randbytes(1024), SCN_CODE_RX),)))
    assert not r.packed


def test_writable_code_in_unpacked_program():
    r = analyze(make_pe(sections=((".text", NOP, SCN_CODE_RX), (".evil", NOP, SCN_RWX))))
    assert r.wx_sections == [".evil"] and not r.packed
    s = ScoringMatrix().score({"pe": _signals(r)})
    assert [c.indicator for c in s.contributions] == ["pe_writable_code"]
    assert r.as_dict()["sections"][1]["flags"] == "RWX"


# ------------------------------------------------------------------ imports
INJECT = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]


def test_injection_needs_the_whole_chain():
    r = analyze(make_pe(imports={K32: INJECT + ["ExitProcess"]}))
    assert r.injection == ["virtualallocex", "writeprocessmemory", "createremotethread"]
    for missing in INJECT:
        partial = [f for f in INJECT if f != missing]
        assert not analyze(make_pe(imports={K32: partial})).injection
    nt = analyze(make_pe(imports={"ntdll.dll": ["NtAllocateVirtualMemory",
                                                "NtWriteVirtualMemory", "NtQueueApcThread"]}))
    assert nt.injection


RANSOM = {"ADVAPI32.dll": ["CryptEncrypt"],
          K32: ["FindFirstFileW", "FindNextFileW", "MoveFileExW"]}


def test_ransomware_imports_only_when_unsigned():
    r = analyze(make_pe(imports=RANSOM))
    assert r.ransomware_apis == ["cryptencrypt", "findfirstfilew", "movefileexw"]
    signed = analyze(make_pe(imports=RANSOM, cert=b"\x00" * 8 + b"cert" * 64))
    assert signed.signature_present and not signed.ransomware_apis
    no_walk = analyze(make_pe(imports={"bcrypt.dll": ["BCryptEncrypt"], K32: ["WriteFile"]}))
    assert not no_walk.ransomware_apis


def test_runtime_import_resolution():
    r = analyze(make_pe(imports={K32: ["LoadLibraryA", "GetProcAddress", "ExitProcess"]}))
    assert r.runtime_imports_only
    s = ScoringMatrix().score({"pe": _signals(r)})
    assert [c.indicator for c in s.contributions] == ["pe_runtime_imports"]
    many = analyze(make_pe(imports={K32: ["LoadLibraryA", "GetProcAddress"] + [
        f"Func{i}" for i in range(10)]}))
    assert not many.runtime_imports_only


def test_ordinal_imports_and_bad_name_pointers():
    data = bytearray(make_pe(imports={"WS2_32.dll": ["socket"]}))
    r = analyze(bytes(data))
    idata = r.sections[-1]
    thunk_off = _rva_to_offset(r.sections, idata.virtual_address + 40)   # first ILT entry
    struct.pack_into("<I", data, thunk_off, 0x80000017)                   # by ordinal 23
    assert analyze(bytes(data)).imports == {"ws2_32.dll": ["#23"]}
    struct.pack_into("<I", data, thunk_off, 0x7FFF0000)                   # nowhere
    assert analyze(bytes(data)).imports == {"ws2_32.dll": [""]}


def test_import_table_outside_the_sections():
    data = bytearray(make_pe(imports={K32: ["ExitProcess"]}))
    struct.pack_into("<I", data, 0x98 + 96 + 8, 0x00900000)
    r = analyze(bytes(data))
    assert "import table outside every section" in r.malformed and not r.imports


def test_endless_thunk_array_is_bounded():
    data = bytearray(make_pe(imports={K32: ["ExitProcess"]}))
    r = analyze(bytes(data))
    idata = r.sections[-1]
    start = idata.raw_pointer + 40
    # Point the lookup table at a run of non-zero values to the end of the section.
    for off in range(start, idata.raw_pointer + idata.raw_size - 4, 4):
        struct.pack_into("<I", data, off, idata.virtual_address + 2)
    assert analyze(bytes(data)).import_count <= 4096


# --------------------------------------------------------- recovery (T1490)
@pytest.mark.parametrize("line", [
    "cmd.exe /c vssadmin.exe delete shadows /all /quiet",
    "vssadmin Delete Shadows /All /Quiet",
    "wmic shadowcopy delete",
    "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }",
    "wbadmin delete catalog -quiet",
    "bcdedit /set {default} recoveryenabled No",
    "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
    "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
])
@pytest.mark.parametrize("encoding", ["ascii", "utf-16-le"])
def test_recovery_inhibition(line, encoding):
    r = analyze(make_pe(strings=b"\x00\x00" + line.encode(encoding) + b"\x00\x00"))
    assert r.recovery_inhibition, line
    s = ScoringMatrix().score({"pe": _signals(r)})
    assert s.verdict == "High" and s.contributions[0].indicator == "pe_recovery_inhibition"


@pytest.mark.parametrize("text", [
    # The help text of the Windows tools themselves.
    "Delete Shadows        - Delete volume shadow copies",
    "Delete Shadows /Type=ClientAccessible /For=ForVolumeSpec [/Oldest | /All] [/Quiet]",
    "Resize ShadowStorage /For=ForVolumeSpec /On=OnVolumeSpec /MaxSize=MaxSizeSpec",
    "wbadmin delete catalog [-quiet]",
    "bcdedit /set {default} recoveryenabled Yes",
    "Creates a shadow copy with Win32_ShadowCopy.Create()",
])
def test_help_text_and_benign_mentions_do_not_match(text):
    for enc in ("ascii", "utf-16-le"):
        assert not analyze(make_pe(strings=text.encode(enc) + b"\x00\x00")).recovery_inhibition


# ------------------------------------------------------------------ overlay
def test_appended_program_is_flagged():
    r = analyze(make_pe(overlay=make_pe()))
    assert r.overlay_executable and r.overlay_size > 0
    later = analyze(make_pe(overlay=b"\x00" * 300 + make_pe()))
    assert later.overlay_executable
    s = ScoringMatrix().score({"pe": _signals(r)})
    assert [c.indicator for c in s.contributions] == ["pe_overlay_executable"]


def test_near_random_overlay():
    blob = random.Random(3).randbytes(128 * 1024)
    assert analyze(make_pe(overlay=blob)).overlay_encrypted
    assert not analyze(make_pe(overlay=blob[:4096])).overlay_encrypted          # small
    assert not analyze(make_pe(overlay=b"7z\xbc\xaf\x27\x1c" + blob)).overlay_encrypted
    nsis = make_pe(overlay=blob, strings=b"Nullsoft Install System v3.10\x00")
    assert not analyze(nsis).overlay_encrypted
    signed = analyze(make_pe(overlay=blob, cert=b"\x00" * 8 + b"c" * 1000))
    assert signed.signature_present and not signed.overlay_encrypted


def test_certificate_is_not_overlay():
    cert = b"\x00\x02\x02\x00" + os.urandom(4000)
    r = analyze(make_pe(cert=cert))
    assert r.signature_present and r.overlay_size == 0 and not r.overlay_encrypted
    assert "signature present (not verified)" in r.detail
    assert r.as_dict()["signature_verified"] is False
    assert not analyze(make_pe(cert=cert, overlay=b"")).overlay_executable


def test_embedded_pe_search_is_bounded():
    assert not _embedded_pe(b"MZ" * 1000)
    assert _embedded_pe(b"junk" + make_pe())


# ---------------------------------------------------------------- malformed
def test_malformed_headers_are_findings():
    data = bytearray(make_pe())
    struct.pack_into("<H", data, 0x98, 0x777)                  # optional-header magic
    r = analyze(bytes(data))
    assert r.malformed == ["unknown optional-header magic 0x777"]
    assert ScoringMatrix().score({"pe": _signals(r)}).risk_score == 10

    data = bytearray(make_pe())
    struct.pack_into("<I", data, 0x80 + 24 + 224 + 20, 0x7FFFFF00)   # section pointer
    assert any("past the end" in m for m in analyze(bytes(data)).malformed)

    data = bytearray(make_pe())
    struct.pack_into("<H", data, 0x86, 0)                          # no sections
    assert "0 sections" in analyze(bytes(data)).malformed

    cut = make_pe()[:0x80 + 24 + 224 + 20]                        # table cut short
    assert any("section table" in m for m in analyze(cut).malformed)
    assert analyze(make_pe()[:0xA0]).malformed == ["truncated header"]


def test_partly_read_file_is_not_malformed():
    full = make_pe(sections=((".text", NOP, SCN_CODE_RX), (".data", bytes(0x2000), 0xC0000040)))
    head = full[:0x600]
    assert analyze(head).malformed
    r = analyze(head, file_size=len(full))
    assert r.truncated and not r.malformed and r.overlay_size == 0


def test_helpers():
    assert _cstring(b"abc\x00def", 0) == "abc" and _cstring(b"a\x01b\x00", 0) == ""
    assert _cstring(b"abc", None) == "" and _cstring(b"abc", 10) == ""
    assert _rva_to_offset([], 0) is None


# --------------------------------------------------------------------- fuzz
def test_fuzzed_programs_never_raise():
    rng = random.Random(46)
    seeds = [make_pe(imports=RANSOM, strings=b"vssadmin delete shadows /all\x00"),
             make_pe(bits=64, kind="dll", imports={K32: INJECT}, overlay=make_pe(),
                     cert=b"\x00" * 64)]
    for i in range(600):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 40)):
            pos = rng.randrange(0, min(len(data), 0x800 if i % 2 else len(data)))
            data[pos] = rng.randrange(256)
        if i % 7 == 0:
            data = data[:rng.randrange(0x40, len(data))]
        r = analyze(bytes(data))
        r.as_dict()
        ScoringMatrix().score({"pe": _signals(r)})


def test_random_bytes_behind_a_valid_signature_never_raise():
    rng = random.Random(7)
    for _ in range(300):
        body = bytearray(rng.randbytes(rng.randrange(0x100, 0x1200)))
        body[0:2] = b"MZ"
        struct.pack_into("<I", body, 0x3C, 0x80)
        body[0x80:0x84] = b"PE\x00\x00"
        analyze(bytes(body)).as_dict()


# -------------------------------------------------------------- integration
def _signals(r):
    return {"packed": r.packed, "packer": r.packer, "wx_sections": r.wx_sections,
            "injection": r.injection, "ransomware_apis": r.ransomware_apis,
            "runtime_imports_only": r.runtime_imports_only,
            "recovery_inhibition": r.recovery_inhibition,
            "overlay_executable": r.overlay_executable,
            "overlay_encrypted": r.overlay_encrypted, "overlay_size": r.overlay_size,
            "malformed": r.malformed, "signature_present": r.signature_present}


def test_layer_signals_match_the_scorer_contract(tmp_path):
    scanner = RS.RansomwareScanner(_config(tmp_path))
    p = tmp_path / "scan" / "tool.exe"
    p.write_bytes(make_pe(imports=RANSOM))
    from engine.layers import ScanContext
    ctx = ScanContext.start(scanner, str(p), 0, str(p), "x")
    PeLayer().run(scanner, ctx)
    from detectors.signals import PeSignal
    assert ctx.signals.pe == PeSignal(**_signals(A.analyze_bytes(p.read_bytes())))
    assert ctx.scan_results["pe_analysis"]["ransomware_apis"]


def test_scanner_reports_a_backup_deleting_program(tmp_path):
    scanner = RS.RansomwareScanner(_config(tmp_path))
    p = tmp_path / "scan" / "update.exe"
    p.write_bytes(make_pe(imports=RANSOM,
                          strings="vssadmin delete shadows /all /quiet".encode("utf-16-le")))
    r = scanner.scan_file(str(p))
    assert r["verdict"] == "Critical" and r["risk_score"] >= 75
    names = {c["indicator"] for c in r["score_breakdown"]["contributions"]}
    assert {"pe_recovery_inhibition", "pe_ransomware_imports"} <= names
    report = scanner._format_file_finding(r)
    assert "[PE]" in report and "deletes backups" in report


def test_scanner_leaves_an_ordinary_program_clean(tmp_path):
    scanner = RS.RansomwareScanner(_config(tmp_path))
    p = tmp_path / "scan" / "hello.exe"
    p.write_bytes(make_pe(imports={K32: ["GetStdHandle", "WriteConsoleW", "ExitProcess"]}))
    r = scanner.scan_file(str(p))
    assert r["verdict"] == "Clean", r["score_breakdown"]
    assert r["scan_results"]["pe_analysis"]["is_pe"]


def test_programs_are_scanned_in_folder_scans():
    for ext in (".exe", ".dll", ".scr", ".sys"):
        assert ext in RS.SUPPORTED_EXTENSIONS


def test_ml_does_not_count_packing_twice():
    ml = {"suspicious": True, "probability": 0.9, "model": "rules"}
    both = ScoringMatrix().score({"pe": {"packed": True, "packer": "UPX"}, "ml": ml})
    assert [c.indicator for c in both.contributions] == ["pe_packed"]
    alone = ScoringMatrix().score({"ml": ml})
    assert [c.indicator for c in alone.contributions] == ["ml_classifier"]
