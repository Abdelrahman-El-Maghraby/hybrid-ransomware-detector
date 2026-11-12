"""M24 (owner-approved 2026-11-12): Windows removes trailing dots and spaces when
it creates a file, so a member or attachment named "invoice.pdf.exe." is saved
as "invoice.pdf.exe". The scanner classified the name with the dot and lost the
executable and double-extension findings and the script layer. Names are now
classified as Windows saves them; reports keep the name as it was received.
What a given Windows mail client or archive tool does needs a Windows machine."""

import zipfile
from pathlib import Path

import pytest

import RansomwareScanner as RS
from detectors.container_extractor import ContainerExtractor, windows_name
from detectors.script_analysis import ScriptAnalyzer, is_script
from tests.test_container_extractor import _zip
from tests.test_mail_analyzer import analyze, make_eml
from tests.test_scanner_integration import _config

TRAILING = ["invoice.pdf.exe.", "invoice.pdf.exe ", "invoice.pdf.exe. .", "invoice.pdf.js.",
            "invoice.pdf.js. ."]
SCRIPT = b"var greeting = 'hello';\n"


@pytest.mark.parametrize("name,saved", [
    ("a.exe.", "a.exe"), ("a.exe ", "a.exe"), ("a.js. .", "a.js"), ("a.exe", "a.exe"),
    (".", ""), (". .", ""), ("a .b", "a .b"), ("a..exe", "a..exe")])
def test_windows_name(name, saved):
    assert windows_name(name) == saved


@pytest.mark.parametrize("name", TRAILING)
def test_archive_members_are_classified_as_windows_saves_them(tmp_path, name):
    shown = f"lure.zip!/{name}"
    with ContainerExtractor().open(_zip(tmp_path / "lure.zip", [(name, SCRIPT)])) as res:
        assert res.executable_members == [shown]          # the name as received
        assert res.double_extension_members == [shown]
        [member] = res.members
        assert member.name == shown
        assert Path(member.path).name == windows_name(name)
        if ".js" in name:
            assert is_script(member.path)                 # the script layer applies


def test_cleaned_names_never_overwrite_each_other(tmp_path):
    """"a.exe" and "a.exe." are one name once cleaned; each keeps its own file."""
    members = [("a.exe", b"MZ first"), ("a.exe.", b"MZ second"), ("a.exe ", b"MZ third")]
    with ContainerExtractor().open(_zip(tmp_path / "same.zip", members)) as res:
        paths = [m.path for m in res.members]
        assert len(set(paths)) == 3
        assert [Path(p).read_bytes() for p in paths] == [d for _, d in members]
        assert [m.name for m in res.members] == ["same.zip!/a.exe", "same.zip!/a.exe.",
                                                 "same.zip!/a.exe "]


@pytest.mark.parametrize("name", TRAILING)
def test_mail_attachments_are_classified_as_windows_saves_them(tmp_path, name):
    p = make_eml(tmp_path / "m.eml", attachments=[(name, SCRIPT, "application", "octet-stream")])
    res = analyze(p)
    received = name.rstrip()                    # the e-mail parser drops trailing spaces itself
    assert res.executable_attachments == [received]
    assert res.double_extension_attachments == [received]


def test_cleaned_attachment_names_never_overwrite_each_other(tmp_path):
    p = make_eml(tmp_path / "m.eml", attachments=[
        ("a.exe", b"MZ first", "application", "octet-stream"),
        ("a.exe.", b"MZ second", "application", "octet-stream")])
    from detectors.mail_analyzer import MailAnalyzer
    with MailAnalyzer().open(p) as res:
        assert [Path(a.path).read_bytes() for a in res.attachments] == [b"MZ first",
                                                                         b"MZ second"]
        assert [a.filename for a in res.attachments] == ["a.exe", "a.exe."]


def test_the_script_layer_takes_trailing_dot_names(tmp_path):
    assert is_script("a.js.") and is_script("b.ps1 ") and is_script("c.vbs. .")
    assert not is_script("d.txt.") and not is_script(".")
    p = tmp_path / "drop.js."
    p.write_bytes(SCRIPT)
    r = ScriptAnalyzer().analyze_file(p)
    assert r.is_script and r.language


def test_api_upload_keeps_the_windows_extension():
    from api.server import upload_extension
    assert upload_extension("invoice.pdf.js.") == ".js"
    assert upload_extension("invoice.pdf.exe. .") == ".exe"
    assert upload_extension("report.pdf") == ".pdf"
    assert upload_extension("noext.") == "" and upload_extension("x.$$$") == ""


def test_a_scan_scores_the_trailing_dot_member_like_the_plain_one(tmp_path):
    scanner = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False,
                                           qr_scan_enabled=False))
    scan = tmp_path / "scan"
    scan.mkdir(exist_ok=True)
    plain = _zip(scan / "plain.zip", [("invoice.pdf.exe", b"MZ" + b"\0" * 100)])
    dotted = _zip(scan / "dotted.zip", [("invoice.pdf.exe.", b"MZ" + b"\0" * 100)])
    a, b = scanner.scan_file(str(plain)), scanner.scan_file(str(dotted))
    assert (b["verdict"], b["risk_score"]) == (a["verdict"], a["risk_score"])
    assert a["verdict"] != "Clean"
    assert "dotted.zip!/invoice.pdf.exe." in str(b["scan_results"])   # name as received


def test_zip_names_are_stored_as_given(tmp_path):
    """The test archives really hold the trailing dot (zipfile keeps it)."""
    arc = _zip(tmp_path / "x.zip", [("a.exe.", b"x")])
    with zipfile.ZipFile(arc) as z:
        assert z.namelist() == ["a.exe."]
