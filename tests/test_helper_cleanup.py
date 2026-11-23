"""L-E5: helper programs a scan starts do not outlive their worker, and OCR is
bounded. On POSIX each isolated worker leads its own process group; when the
parent stops it (time-out, death, memory limit, invalid reply), that group is
killed, and only that group: other programs, including ones the parent itself
started, are left alone. The helpers here are inert sleeping Python processes;
Tesseract and poppler are replaced by stand-ins (neither is installed here, and
the real programs are not verified by these tests)."""

import os
import subprocess
import sys
import time

import pytest

import RansomwareScanner as RS
from engine import text as text_mod
from engine import workers as W
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

posix = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX")


def _gone(pid, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def _scan(tmp_path, name, limit=3):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = tmp_path / "scan" / name
    p.write_bytes(b"inert")
    s = RS.RansomwareScanner(_config(tmp_path, _scanner_factory="tests.worker_fakes:make",
                                     scan_timeout_seconds=limit))
    got = []
    W.scan_isolated(s, [str(p)], 1, limit, 0, lambda i, path, r: got.append(r))
    with open(str(p) + ".helper") as fh:
        return got[0], int(fh.read())


@posix
@pytest.mark.parametrize("name,why", [("helperhang.txt", "timed out"),
                                      ("helperexit.txt", "died")])
def test_a_stopped_or_dead_worker_takes_its_helpers_with_it(tmp_path, name, why):
    bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)            # another program
    sibling = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        result, helper = _scan(tmp_path, name)
        assert result["scan_status"] == "failed" and why in result["scan_results"]["scan_failed"]["reason"]
        assert _gone(helper), "the scan's helper outlived its worker"
        assert bystander.poll() is None and sibling.poll() is None    # untouched
    finally:
        for p in (bystander, sibling):
            p.kill()
            p.wait(5)


@posix
def test_a_worker_leads_its_own_group(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, scan_timeout_seconds=5))
    w = W.start_worker(s, 0)
    try:
        assert W.wait_ready(w, 60)
        assert w.pgid == w.proc.pid and os.getpgid(w.proc.pid) != os.getpgid(0)
    finally:
        w.kill()


# ------------------------------------------------------------------- OCR
class _Image:
    pass


@pytest.fixture
def ocr(monkeypatch):
    """Stand-ins with the libraries' contract: run a helper, kill it at the
    timeout and raise (pytesseract: RuntimeError "Tesseract process timeout")."""
    seen = {"pages": [], "render": []}

    def render(path, last_page=None, timeout=None):
        seen["render"].append(timeout)
        return [_Image(), _Image(), _Image()]

    def read(image, timeout=0):
        seen["pages"].append(timeout)
        try:
            subprocess.run([sys.executable, "-c", "import time; time.sleep(30)"],
                           timeout=timeout or None)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Tesseract process timeout") from None
        return "text"
    monkeypatch.setattr(text_mod, "OCR_AVAILABLE", True)
    monkeypatch.setattr(text_mod, "convert_from_path", render, raising=False)
    monkeypatch.setattr(text_mod, "pytesseract", type("T", (), {"image_to_string":
                                                               staticmethod(read)}))
    return seen


@pytest.fixture
def scanner(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    yield s
    if s.cache is not None:
        s.cache.close()


def test_ocr_is_bounded_and_its_time_out_is_reported(scanner, tmp_path, ocr, monkeypatch):
    monkeypatch.setattr(type(scanner), "OCR_TOTAL_SECONDS", 2.0)
    pdf = tmp_path / "scan.pdf"
    pdf.write_bytes(make_pdf(""))
    errors = []
    started = time.monotonic()
    scanner._extract_text_with_ocr_from_pdf(str(pdf), errors)
    assert time.monotonic() - started < 3.5
    assert ocr["render"] and ocr["render"][0] <= 2 and ocr["pages"][0] <= 2
    assert errors and ("OCR failed (RuntimeError: Tesseract process timeout)" in errors[0]
                       or errors[0].startswith("OCR stopped at its time limit"))


def test_in_a_worker_ocr_gets_only_the_time_left(scanner, tmp_path, ocr):
    scanner.config["scan_timeout_seconds"] = 20
    scanner.scan_deadline = time.monotonic() + 4.5           # 4.5 - 2 s margin = 2.5 s
    pdf = tmp_path / "scan.pdf"
    pdf.write_bytes(make_pdf(""))
    errors = []
    scanner._extract_text_with_ocr_from_pdf(str(pdf), errors)
    assert ocr["render"][0] <= 3 and all(t <= 3 for t in ocr["pages"]) and errors


def test_no_ocr_without_time(scanner, tmp_path, ocr):
    scanner.config["scan_timeout_seconds"] = 20
    scanner.scan_deadline = time.monotonic() + 2.5          # 0.5 s usable
    errors = []
    pdf = tmp_path / "scan.pdf"
    pdf.write_bytes(make_pdf(""))
    assert scanner._extract_text_with_ocr_from_pdf(str(pdf), errors) == ""
    assert ocr["render"] == [] and errors == ["OCR not run: no time left in the scan limit"]


def test_an_ocr_time_out_makes_the_pdf_scan_partial(scanner, tmp_path, ocr, monkeypatch):
    monkeypatch.setattr(type(scanner), "OCR_TOTAL_SECONDS", 1.5)
    pdf = tmp_path / "scan" / "scan.pdf"
    pdf.parent.mkdir(exist_ok=True)
    pdf.write_bytes(make_pdf(""))
    errors = []
    scanner._extract_text_from_file(str(pdf), allow_ocr=True, errors=errors)
    assert errors and "OCR" in errors[0]
