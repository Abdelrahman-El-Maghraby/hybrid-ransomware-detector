"""I-2 (owner-approved 2026-11-12): an archive gets the full pipeline for at
most `archive_scan_members` (25) members. They were taken in archive order, so a
script, program or nested container listed after the 25th was extracted and its
name checked, but its content never reached YARA, the script layer or the PE
layer. Risky members now take the places first (the `_priority_name` order the
extractor already uses past 500 entries, plus members recognised as programs by
their first bytes); everything else keeps archive order. The limit is unchanged
and the members left out are still reported, and the scan is partial. Inputs are inert."""

import zipfile

import pytest

import RansomwareScanner as RS
from tests.test_scanner_integration import _config

FILLER = [(f"notes/{i:02d}.txt", f"meeting note {i}\n".encode()) for i in range(30)]
SHADOW = b"vssadmin delete shadows /all /quiet\n"        # inert text; a critical YARA rule
PE = b"MZ" + b"\x00" * 200


@pytest.fixture
def scanner(tmp_path):
    (tmp_path / "scan").mkdir()
    return RS.RansomwareScanner(_config(tmp_path, isolate_scans=False, qr_scan_enabled=False))


def _zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members:
            z.writestr(name, data)
    return path


def _scanned(r):
    box = r["scan_results"]["archive"]
    return [m["name"].split("!/", 1)[1] for m in box["member_results"]], box


def test_a_risky_member_after_the_25th_is_scanned(scanner, tmp_path):
    arc = _zip(tmp_path / "scan" / "notes.zip", FILLER + [("z_cleanup.ps1", SHADOW)])
    r = scanner.scan_file(str(arc))
    names, box = _scanned(r)
    assert names[0] == "z_cleanup.ps1"                    # 31st in the archive, scanned first
    assert box["deep_scanned"] == 25 and box["not_scanned_budget"] == 6
    assert r["verdict"] == "Critical"                     # the script's content was read
    assert r["scan_status"] == "partial"                  # the six left out are reported
    assert any(g["layer"] == "archive" and "6 member(s) over the scan budget" in g["reason"]
               for g in r["incomplete_reasons"])


def test_a_program_by_its_first_bytes_is_scanned_first(scanner, tmp_path):
    arc = _zip(tmp_path / "scan" / "photos.zip", FILLER[:27] + [("report.pdf", PE)] + FILLER[27:])
    names, box = _scanned(scanner.scan_file(str(arc)))
    assert names[0] == "report.pdf" and box["deep_scanned"] == 25


def test_risky_members_keep_their_archive_order(scanner, tmp_path):
    risky = [("b.js", b"var a = 1;\n"), ("a.zip", b""), ("c.ps1", b"Write-Output 1\n")]
    with zipfile.ZipFile(tmp_path / "inner.zip", "w") as z:
        z.writestr("readme.txt", "inner")
    risky[1] = ("a.zip", (tmp_path / "inner.zip").read_bytes())
    arc = _zip(tmp_path / "scan" / "mixed.zip", FILLER[:26] + risky[:1] + FILLER[26:]
               + risky[1:])
    names, box = _scanned(scanner.scan_file(str(arc)))
    # a nested archive is expanded by the extractor, not scanned as an item; its
    # harmless readme keeps its place in archive order
    assert names[:3] == ["b.js", "c.ps1", "notes/00.txt"]
    assert box["deep_scanned"] == 25 and box["not_scanned_budget"] == 8


def test_ordinary_archives_keep_archive_order(scanner, tmp_path):
    arc = _zip(tmp_path / "scan" / "plain.zip", FILLER)
    names, box = _scanned(scanner.scan_file(str(arc)))
    assert names == [n for n, _ in FILLER[:25]]
    assert box["not_scanned_budget"] == 5


def test_small_archives_are_unchanged(scanner, tmp_path):
    members = [("a.txt", b"one\n"), ("z.ps1", b"Write-Output 1\n"), ("m.txt", b"two\n")]
    arc = _zip(tmp_path / "scan" / "small.zip", members)
    names, box = _scanned(scanner.scan_file(str(arc)))
    assert names == ["a.txt", "z.ps1", "m.txt"]           # under the limit: archive order
    assert box["not_scanned_budget"] == 0
