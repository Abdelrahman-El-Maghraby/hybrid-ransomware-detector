"""M29, script part (owner-approved 2026-11-12): the critical rule
Ransomware_Shadow_Copy_Deletion fired on any file naming the WMI/CIM shadow-copy
class or "vssadmin resize shadowstorage", so a two-line script that only lists
restore points scored Critical 90. The WMI/CIM strings now need a deletion verb
and the resize needs its /maxsize= argument. Every deletion form still matches.
The web-page case (prose quoting "vssadmin delete shadows") is deliberately
unchanged. Inputs are inert text; nothing here runs."""

from pathlib import Path

import pytest

import RansomwareScanner as RS
from detectors.yara_engine import YARA_AVAILABLE, YaraEngine
from tests.test_scanner_integration import _config

pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
RULES = Path(__file__).resolve().parent.parent / "rules"
RULE = "Ransomware_Shadow_Copy_Deletion"

LISTING = "# list existing restore points for the backup report\n" \
          "Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate\n"

NOT_DELETION = [
    LISTING,
    "Get-CimInstance Win32_ShadowCopy | Format-Table ID, VolumeName\n",
    "Get-WmiObject Win32_Shadowcopy | Measure-Object\n",
    "vssadmin resize shadowstorage /?\n",
    "vssadmin list shadowstorage\n",
]
DELETION = [
    'Shell "cmd /c vssadmin delete shadows /all /quiet"',
    "vssadmin.exe delete shadows /all /quiet",
    "wmic shadowcopy delete /nointeractive",
    "Get-WmiObject Win32_Shadowcopy | % { $_.Delete() }",
    "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete( ) }",
    "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject",
    "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance",
    "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
    "VSSADMIN Resize ShadowStorage /For=C: /On=C: /MaxSize=1%",
    "wbadmin delete catalog -quiet",
    "wbadmin delete systemstatebackup -keepversions:0",
]


@pytest.fixture(scope="module")
def engine():
    return YaraEngine(rules_dir=str(RULES))


def _rules(engine, tmp_path, data: bytes):
    p = tmp_path / "sample.bin"
    p.write_bytes(data)
    return {m.rule for m in engine.scan_file(str(p)).matches}


@pytest.mark.parametrize("encoding", ["ascii", "utf-16le"])
@pytest.mark.parametrize("text", NOT_DELETION)
def test_listing_and_sizing_scripts_do_not_match(engine, tmp_path, text, encoding):
    assert RULE not in _rules(engine, tmp_path, text.encode(encoding))


@pytest.mark.parametrize("encoding", ["ascii", "utf-16le"])
@pytest.mark.parametrize("text", DELETION)
def test_every_deletion_form_still_matches(engine, tmp_path, text, encoding):
    assert RULE in _rules(engine, tmp_path, text.encode(encoding))


def test_the_web_page_case_is_unchanged(engine, tmp_path):
    page = (b"<html><body><p>Attackers often run <code>vssadmin delete shadows /all "
            b"/quiet</code> before encrypting.</p></body></html>")
    assert RULE in _rules(engine, tmp_path, page)


def test_the_listing_script_is_no_longer_critical(tmp_path):
    scanner = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False,
                                           qr_scan_enabled=False))
    scan = tmp_path / "scan"
    scan.mkdir(exist_ok=True)
    listing = scan / "list_shadows.ps1"
    listing.write_text(LISTING)
    r = scanner.scan_file(str(listing))
    assert r["verdict"] not in ("High", "Critical"), (r["verdict"], r["risk_score"])
    deleting = scan / "delete_shadows.ps1"
    deleting.write_text("Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }\n")
    assert scanner.scan_file(str(deleting))["verdict"] == "Critical"
