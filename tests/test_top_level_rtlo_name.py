"""M30 (owner-approved 2026-11-12): a right-to-left override in the scanned
file's own name was not a finding. "invoice<RTLO>fdp.exe" is shown as
"invoiceexe.pdf"; under that name an inert MZ stub scored Clean 0, while the
same name inside a ZIP scored Critical 95. The top-level name now gets the
archive member's weight. All files are inert stubs."""

import zipfile

import pytest

import RansomwareScanner as RS
from detectors.container_extractor import RTLO
from tests.test_scanner_integration import _config

NAME = "invoice" + RTLO + "fdp.exe"
STUB = b"MZ" + bytes(300)


@pytest.fixture
def scanner(tmp_path):
    return RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))


def _indicators(result):
    return [c["indicator"] for c in result["score_breakdown"]["contributions"]]


def test_a_top_level_rtlo_name_is_a_finding(scanner, tmp_path):
    p = tmp_path / "scan" / NAME
    p.write_bytes(STUB)
    r = scanner.scan_file(str(p))
    assert "file_rtlo_spoof" in _indicators(r)
    assert r["risk_score"] >= 60 and r["verdict"] != "Clean"
    assert r["scan_results"]["file_integrity"]["rtlo_name"] == "invoice[RTLO]fdp.exe"
    text = scanner.generate_report([r])
    assert "invoice[RTLO]fdp.exe" in text


def test_a_plain_name_is_unchanged(scanner, tmp_path):
    p = tmp_path / "scan" / "invoice.pdf.txt"
    p.write_bytes(b"Quarterly figures attached.\n")
    r = scanner.scan_file(str(p))
    assert "file_rtlo_spoof" not in _indicators(r)
    assert "rtlo_name" not in r["scan_results"]["file_integrity"]


def test_an_archive_member_is_scored_once_by_its_container(scanner, tmp_path):
    p = tmp_path / "scan" / "a.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr(NAME, STUB)
    r = scanner.scan_file(str(p))
    found = _indicators(r)
    assert "archive_rtlo_spoof" in found and "file_rtlo_spoof" not in found
    assert not any(i.endswith(":file_rtlo_spoof") for i in found)
    assert (r["verdict"], r["risk_score"]) == ("Critical", 95)        # as before M30
