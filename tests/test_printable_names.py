"""L-E9 and I-T3: file names never forge or reorder lines of text output, and
no tracked text file carries a raw bidirectional control character.

L-E9: a POSIX file name may hold a line break or a right-to-left override. In
the text log and the text report the rest of the name started a new line that
read like a real entry (a forged "Verdict: Clean" or "scan_completed"), and an
override reversed the shown name. The JSON outputs are unchanged.

I-T3: raw bidi characters in sources show reordered text in reviews and diffs.
Tests use escapes; this test keeps it that way for every tracked text file.
Every special character below is built with chr() for the same reason."""

import logging
import subprocess
import sys
from pathlib import Path

import pytest

import RansomwareScanner as RS
from detectors import qr_scanner
from engine.logs import TextFormatter, printable
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

RTLO, RLI, LRM, NEL, LS = chr(0x202E), chr(0x2067), chr(0x200E), chr(0x85), chr(0x2028)
BIDI = [0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)]
FORGED = "\n- File:     /home/u/ok.pdf\n  Verdict:  Clean"


def test_printable_shows_line_breaks_and_bidi_controls():
    assert printable("a\nb\r\tc") == "a?b??c"
    assert printable("invoice" + RTLO + "fdp.exe") == "invoice[RTLO]fdp.exe"
    assert printable(RLI + "x" + LRM + NEL + LS) == "[U+2067]x[U+200E]?[U+2028]"
    plain = "فاتورة_报告_é ok.pdf"                     # ordinary text is unchanged
    assert printable(plain) == plain


def _record(msg, *args, exc_info=None):
    return logging.LogRecord("RansomwareScanner", logging.INFO, __file__, 1, msg, args, exc_info)


def test_a_file_name_cannot_forge_a_text_log_line():
    fmt = TextFormatter("%(levelname)s - %(message)s")
    line = fmt.format(_record("Scanning file: %s", "a.pdf\nINFO - scan_completed Clean"))
    assert "\n" not in line and line.startswith("INFO - Scanning file: a.pdf?")
    try:
        raise ValueError("boom")
    except ValueError:
        with_trace = fmt.format(_record("failed: %s", "x" + RTLO, exc_info=sys.exc_info()))
    first, *rest = with_trace.split("\n")
    assert first == "INFO - failed: x[RTLO]" and rest[0].startswith("Traceback")


@pytest.fixture
def results(tmp_path, monkeypatch):
    monkeypatch.setattr(qr_scanner, "QR_AVAILABLE", False)    # partial: listed by name
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    pdf = tmp_path / "scan" / "a.pdf"
    pdf.write_bytes(make_pdf("hello"))
    partial = s.scan_file(str(pdf))
    flagged = dict(partial, is_malicious=True, verdict="High", risk_score=72)
    name = "evil" + RTLO + "fdp.exe" + FORGED
    for r in (partial, flagged):
        r["file_path"] = str(tmp_path / name)
    return s, [partial, flagged]


def test_a_file_name_cannot_forge_a_text_report_entry(results):
    s, rs = results
    text = s.generate_report(rs)
    assert RTLO not in text
    files = [line for line in text.splitlines() if line.startswith("- File:")]
    assert len(files) == 2 and all("evil[RTLO]fdp.exe?- File:" in f for f in files)
    assert "  Verdict:  Clean" not in text.splitlines()
    report = Path(s.report_dir)
    assert next(report.glob("*.json")).read_text(encoding="utf-8").count("\\u202e") == 2


def _tracked_text_files(root):
    names = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True,
                           check=True).stdout.decode("utf-8").split("\0")
    for name in filter(None, names):
        try:
            yield name, (root / name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):         # binary fixtures, missing files
            continue


def test_no_tracked_text_file_holds_a_raw_bidi_character():
    root = Path(__file__).resolve().parents[1]
    if not (root / ".git").exists():
        pytest.skip("not a git checkout")
    bad = [f"{name}:{i}: U+{ord(c):04X}"
           for name, text in _tracked_text_files(root)
           for i, line in enumerate(text.splitlines(), 1)
           for c in line if ord(c) in BIDI]
    assert not bad, "use an escape such as \\u202e instead: " + ", ".join(bad[:20])
