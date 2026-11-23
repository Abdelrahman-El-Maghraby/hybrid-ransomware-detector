"""M29 (web-page and text case) and M32: harmless pages and notices that quote
or describe ransomware techniques stay below High; ransom notes and droppers
keep their verdicts. The examples are in tests/fp_examples.py (inert,
synthetic). Measured before the rule change (docs/HANDOFF.md, group 42): the
seven harmless files scored High or Critical except the listing script."""

import pytest

import RansomwareScanner as RS
from detectors.yara_engine import YARA_AVAILABLE
from tests.fp_examples import HARMFUL, HARMLESS
from tests.test_scanner_integration import _config

pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
HIGH = ("High", "Critical")


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fp")
    s = RS.RansomwareScanner(_config(tmp, isolate_scans=False, qr_scan_enabled=False))

    def run(name, data):
        p = tmp / "scan" / name
        p.write_bytes(data)
        return s.scan_file(str(p))
    yield run
    if s.cache is not None:
        s.cache.close()


def _rules(r):
    return {m["rule"] for m in r["scan_results"].get("yara", {}).get("matches", [])}


@pytest.mark.parametrize("name,data", HARMLESS, ids=[n for n, _ in HARMLESS])
def test_harmless_descriptions_stay_below_high(scan, name, data):
    r = scan(name, data)
    assert r["verdict"] not in HIGH, (r["verdict"], _rules(r))
    assert "Ransomware_Shadow_Copy_Deletion" not in _rules(r)
    assert "Crypto_Ransom_Extortion_Combo" not in _rules(r)


@pytest.mark.parametrize("name,data", HARMFUL, ids=[n for n, _ in HARMFUL])
def test_notes_and_droppers_keep_their_verdict(scan, name, data):
    r = scan(name, data)
    assert r["verdict"] in HIGH, (r["verdict"], _rules(r))
    expected = ("Ransomware_Shadow_Copy_Deletion" if name.endswith((".bat", ".hta", ".ps1"))
                or name == "dropper.html" else "Crypto_Ransom_Extortion_Combo")
    assert expected in _rules(r)


def test_the_page_rule_still_needs_its_command(scan):
    page = b'<html><script>new ActiveXObject("WScript.Shell").Run("notepad")</script></html>'
    assert "Ransomware_Shadow_Copy_Deletion" not in _rules(scan("tool.html", page))


def test_a_quoted_command_in_a_document_type_is_unchanged(scan):
    # outside the prose types (here a batch file named as such) one command is enough
    r = scan("notes.cmd", b"vssadmin delete shadows /all /quiet\r\n")
    assert "Ransomware_Shadow_Copy_Deletion" in _rules(r)
