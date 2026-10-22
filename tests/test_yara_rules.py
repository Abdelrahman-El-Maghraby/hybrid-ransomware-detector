from pathlib import Path

import pytest

from detectors.yara_engine import YARA_AVAILABLE, YaraEngine
from tests.helpers import make_docx, make_pdf

pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
RULES = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def engine():
    e = YaraEngine(rules_dir=str(RULES))
    assert e.scan_file(__file__).rules_loaded == 5
    return e


@pytest.mark.parametrize("payload,rule", [
    (b'Shell "cmd /c vssadmin delete shadows /all /quiet"', "Ransomware_Shadow_Copy_Deletion"),
    ("Get-WmiObject Win32_Shadowcopy | % { $_.Delete() }".encode("utf-16le"),
     "Ransomware_Shadow_Copy_Deletion"),
    (b"wbadmin delete catalog -quiet", "Ransomware_Shadow_Copy_Deletion"),
    (b"bcdedit /set {default} recoveryenabled No", "Ransomware_Boot_Recovery_Tampering"),
    (b"YOUR FILES HAVE BEEN ENCRYPTED. Buy the decryption key with bitcoin.",
     "Ransom_Note_Language"),
])
def test_rules_fire_on_their_technique(engine, tmp_path, payload, rule):
    p = tmp_path / "sample.bin"
    p.write_bytes(payload)
    assert rule in {m.rule for m in engine.scan_file(str(p)).matches}


def test_benign_documents_do_not_match(engine, tmp_path):
    doc = make_docx(tmp_path / "policy.docx",
                    paragraphs=["Backup policy", "Shadow copies are kept for 30 days.",
                                "Recovery is tested every quarter."])
    pdf = tmp_path / "letter.pdf"
    pdf.write_bytes(make_pdf("Please pay the attached invoice within 30 days."))
    for path in (doc, pdf):
        assert engine.scan_file(str(path)).matched is False
