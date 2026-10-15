import csv
import io
import os
from pathlib import Path

import docx
import PyPDF2
import pytest

from core.canary import CANARY_TEMPLATES, CanaryManager


@pytest.fixture
def setup(tmp_path):
    d1, d2 = tmp_path / "Downloads", tmp_path / "Documents"
    d1.mkdir()
    d2.mkdir()
    mgr = CanaryManager(tmp_path / "data" / "canaries.json")
    created = mgr.deploy([d1, d2, tmp_path / "does-not-exist"])
    return mgr, d1, d2, created


def _canary(d: Path, ext: str) -> Path:
    return next(d / name for name, _ in CANARY_TEMPLATES if name.endswith(ext))


def test_deploy_creates_valid_realistic_documents(setup):
    mgr, d1, d2, created = setup
    assert len(created) == 2 * len(CANARY_TEMPLATES)
    assert len(mgr.entries()) == len(created)
    text = "\n".join(p.text for p in docx.Document(str(_canary(d1, ".docx"))).paragraphs)
    assert "Finance Records" in text
    pdf = PyPDF2.PdfReader(str(_canary(d1, ".pdf")))
    assert "Signed Contracts" in pdf.pages[0].extract_text()
    rows = list(csv.reader(io.StringIO(_canary(d2, ".csv").read_text())))
    assert rows[0][0] == "asset_tag" and len(rows) > 10
    # every canary is unique (random token), so hashes differ between folders
    assert _canary(d1, ".docx").read_bytes() != _canary(d2, ".docx").read_bytes()


def test_intact_canaries_do_not_trigger(setup):
    mgr, *_ = setup
    report = mgr.verify()
    assert not report.triggered and report.intact == report.deployed == 6


def test_redeploy_is_idempotent_and_never_overwrites(setup, tmp_path):
    mgr, d1, d2, _ = setup
    assert mgr.deploy([d1, d2]) == []
    d3 = tmp_path / "Desktop"
    d3.mkdir()
    user_file = d3 / CANARY_TEMPLATES[0][0]
    user_file.write_text("the user's own file")
    created = mgr.deploy([d3])
    assert user_file.read_text() == "the user's own file"
    assert len(created) == len(CANARY_TEMPLATES) - 1


def test_detects_deletion(setup):
    mgr, d1, *_ = setup
    _canary(d1, ".pdf").unlink()
    report = mgr.verify()
    assert report.triggered and [f.status for f in report.findings] == ["deleted"]


def test_detects_modification(setup):
    mgr, d1, *_ = setup
    with open(_canary(d1, ".csv"), "a") as fh:
        fh.write("AT-NEW-0001,Laptop,dept-1,Floor 1,2026-01-01\n")
    assert [f.status for f in mgr.verify().findings] == ["modified"]


def test_detects_in_place_encryption(setup):
    mgr, d1, *_ = setup
    target = _canary(d1, ".docx")
    target.write_bytes(os.urandom(target.stat().st_size))
    assert [f.status for f in mgr.verify().findings] == ["encrypted"]


def test_detects_partial_header_encryption(setup):
    mgr, d1, *_ = setup
    target = _canary(d1, ".pdf")
    data = bytearray(target.read_bytes())
    data[:4096] = os.urandom(4096)[:len(data[:4096])]
    target.write_bytes(bytes(data))
    assert [f.status for f in mgr.verify().findings] == ["encrypted"]


def test_detects_rename_with_ransomware_extension(setup):
    mgr, d1, *_ = setup
    src = _canary(d1, ".docx")
    src.rename(src.with_name(src.name + ".lockbit"))
    finding = mgr.verify().findings[0]
    assert finding.status == "renamed" and ".lockbit" in finding.evidence


def test_detects_ransom_note_next_to_canaries(setup):
    mgr, d1, *_ = setup
    (d1 / "HOW_TO_DECRYPT_FILES.txt").write_text("pay us")
    statuses = [f.status for f in mgr.verify().findings]
    assert statuses == ["ransom_note"]


def test_remove_cleans_up(setup):
    mgr, d1, d2, _ = setup
    assert mgr.remove() == 6
    assert mgr.entries() == []
    assert not any(p.name.startswith("!000_") for p in list(d1.iterdir()) + list(d2.iterdir()))
    assert not mgr.verify().triggered


def test_paths_are_normalised(setup):
    mgr, d1, *_ = setup
    norm = mgr.paths()
    assert os.path.normcase(os.path.abspath(str(_canary(d1, ".pdf")))) in norm
