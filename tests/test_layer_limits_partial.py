"""L-D5 (owner-approved 2026-11-12): emulation failures and the QR layer's limits
and errors left the scan `complete`. A script that box-js could not finish, or a
QR code past a page, image, size or pixel limit, is now named as not checked
and the scan is partial. Findings are unchanged; all inputs are benign."""

import io
import subprocess
import zipfile

import pytest

import detectors.emulation as em
import detectors.qr_scanner as qr
import RansomwareScanner as RS
from detectors.emulation import ScriptEmulator
from detectors.qr_scanner import QRScanner
from tests.test_scanner_integration import _config

PIL = pytest.importorskip("PIL.Image")


@pytest.fixture
def scanner(tmp_path):
    return RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))


def _png(size=(64, 64)) -> bytes:
    buf = io.BytesIO()
    PIL.new("RGB", size, "white").save(buf, "PNG")
    return buf.getvalue()


# ------------------------------------------------------------------ emulation
def _emulator(tool="/usr/bin/true"):
    emu = ScriptEmulator(tool="")
    emu.tool = tool                              # a program that writes no results
    return emu


def test_emulation_failures_carry_a_status(tmp_path, monkeypatch):
    script = tmp_path / "a.js"
    script.write_text("var x = 1;")
    assert _emulator().emulate(str(script)).as_dict()["status"] == "error"   # no results
    big = tmp_path / "big.js"
    big.write_bytes(b"/" * (em.MAX_SCRIPT_BYTES + 1))
    r = _emulator().emulate(str(big))
    assert (r.status, r.detail) == ("error", "script too large to emulate")

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("box-js", 1)
    monkeypatch.setattr(em.subprocess, "run", slow)
    assert _emulator().emulate(str(script)).status == "timeout"


def test_a_script_box_js_could_not_finish_makes_the_scan_partial(scanner, tmp_path):
    script = tmp_path / "scan" / "a.js"
    script.write_text("var greeting = 'hello';\n")
    scanner.emulator = _emulator()
    r = scanner.scan_file(str(script))
    assert r["scan_status"] == "partial"
    assert any(g["layer"] == "emulation" and "no results" in g["reason"]
               for g in r["incomplete_reasons"])
    assert r["verdict"] == "Clean"                        # findings unchanged


# ------------------------------------------------------------------------ QR
needs_decoder = pytest.mark.skipif(not qr.QR_AVAILABLE, reason="no QR decoder installed")


@needs_decoder
def test_an_image_over_the_size_limit_is_named(tmp_path):
    p = tmp_path / "big.png"
    p.write_bytes(_png())
    res = QRScanner(max_image_bytes=50).analyze_file(p)
    assert res.images_checked == 0 and "over the" in res.not_checked
    assert res.as_dict()["not_checked"] == res.not_checked


@needs_decoder
def test_images_over_the_image_limit_and_the_pixel_limit_are_named(tmp_path):
    p = tmp_path / "many.docx"
    with zipfile.ZipFile(p, "w") as z:
        for i in range(3):
            z.writestr(f"word/media/image{i}.png", _png())
    res = QRScanner(max_images=1).analyze_file(p)
    assert res.images_checked == 1 and "2 image(s) over the 1-image limit" in res.not_checked
    res = QRScanner(max_pixels=100).analyze_file(p)
    assert "over 100 pixels" in res.not_checked


@needs_decoder
def test_pages_over_the_page_limit_are_named(tmp_path):
    p = tmp_path / "eleven.pdf"
    pages = [PIL.new("RGB", (64, 64), "white") for _ in range(11)]
    pages[0].save(p, "PDF", save_all=True, append_images=pages[1:])
    res = QRScanner().analyze_file(p)
    assert "pages 11-11 not checked (limit 10)" in res.not_checked


@needs_decoder
def test_a_pdf_the_layer_cannot_open_is_an_error(tmp_path):
    p = tmp_path / "broken.pdf"
    p.write_bytes(b"%PDF-1.4\nthis is not a PDF body")
    res = QRScanner().analyze_file(p)
    assert res.error and res.as_dict()["error"] == res.error
    program = tmp_path / "invoice.pdf"                   # A2: not a PDF at all
    program.write_bytes(b"MZ" + b"\x00" * 200)
    assert not QRScanner().analyze_file(program).error


@needs_decoder
def test_a_qr_limit_makes_the_scan_partial_and_a_normal_image_does_not(scanner, tmp_path):
    p = tmp_path / "scan" / "flyer.png"
    p.write_bytes(_png())
    assert scanner.scan_file(str(p))["scan_status"] == "complete"
    scanner.qr_scanner = QRScanner(max_image_bytes=50)
    r = scanner.scan_file(str(p))
    assert r["scan_status"] == "partial"
    assert any(g["layer"] == "qr" for g in r["incomplete_reasons"])
    assert r["scan_results"]["qr_codes"]["not_checked"]
