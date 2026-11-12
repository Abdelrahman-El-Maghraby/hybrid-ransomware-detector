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


# ------------------------------------------------------- L-D8: hidden content
# Owner-approved 2026-11-12: the hidden-content check stopped after 200,000 cells
# and 50 PDF pages without saying so. The limits stay (lowered here to keep the
# files small) and what they leave out is named; the scan is then partial.
import detectors.prompt_guard as pg  # noqa: E402
from detectors.prompt_guard import PromptGuard  # noqa: E402
from tests.helpers import make_pdf  # noqa: E402
from tests.test_office_hidden import INJECTION, make_xlsx  # noqa: E402


def _workbook(path, n):
    return make_xlsx(path, [
        {"name": "Data", "cells": {f"A{i}": (f"row {i}", 0) for i in range(1, n + 1)}},
        {"name": "Secret", "state": "hidden", "cells": {"A1": (INJECTION, 0)}}])


def test_cells_over_the_limit_are_named(tmp_path, monkeypatch):
    monkeypatch.setattr(pg, "_MAX_CELLS", 5)
    over = PromptGuard().inspect_hidden_content(_workbook(tmp_path / "big.xlsx", 8))
    assert "cells after the first 5" in over.not_checked
    assert not over.found                                 # the hidden sheet was not reached
    exact = PromptGuard().inspect_hidden_content(_workbook(tmp_path / "ok.xlsx", 2))
    assert exact.not_checked == "" and exact.found        # within the limit: as before


def test_pdf_pages_over_the_limit_are_named(tmp_path, monkeypatch):
    monkeypatch.setattr(pg, "_MAX_PDF_PAGES", 2)
    p = tmp_path / "long.pdf"
    from pypdf import PdfReader, PdfWriter
    page = PdfReader(io.BytesIO(make_pdf("Quarterly figures"))).pages[0]
    w = PdfWriter()
    for _ in range(3):
        w.add_page(page)
    with open(p, "wb") as fh:
        w.write(fh)
    res = PromptGuard().inspect_hidden_content(p)
    assert "pages 3-3 not checked for invisible text (limit 2)" in res.not_checked
    one = tmp_path / "one.pdf"
    one.write_bytes(make_pdf("Quarterly figures"))
    assert PromptGuard().inspect_hidden_content(one).not_checked == ""


def test_a_hidden_content_limit_makes_the_scan_partial(scanner, tmp_path, monkeypatch):
    monkeypatch.setattr(pg, "_MAX_CELLS", 5)
    r = scanner.scan_file(str(_workbook(tmp_path / "scan" / "big.xlsx", 8)))
    assert r["scan_status"] == "partial"
    assert any(g["layer"] == "prompt-guard" and "cells after the first 5" in g["reason"]
               for g in r["incomplete_reasons"])


# ----------------------------------------------- L-L1: unusable LLM replies
# Owner-approved 2026-11-12: an empty, prose or non-object reply returned "no
# opinion" without an error, so the LLM layer read as complete. Content can make
# a model abandon the JSON format; the scan is now partial, the verdict as before.
import detectors.llm_backends as lb  # noqa: E402


@pytest.mark.parametrize("reply", ["", "I will not answer.", "[1, 2]", '"just a string"'])
def test_unusable_llm_replies_are_errors(reply):
    r = lb._parse_analysis(reply)
    assert r["analyzed"] is False and r["is_malicious"] is False and r["error"]


def test_a_usable_reply_is_not_an_error():
    r = lb._parse_analysis('{"is_suspicious": false, "confidence_score": 0.1}')
    assert r["analyzed"] and "error" not in r


def test_a_prose_reply_makes_the_scan_partial(scanner, tmp_path):
    class Prose(lb.LLMBackend):
        name, model, is_local = "fake", "m", True

        @property
        def available(self):
            return True

        def analyze(self, content):
            return lb._parse_analysis("I will not answer.")
    scanner.llm_backend = Prose()
    p = tmp_path / "scan" / "memo.txt"
    p.write_text("Team lunch is on Thursday at noon.\n")
    r = scanner.scan_file(str(p))
    assert r["scan_results"]["chatgpt_analysis"]["error"]
    assert r["scan_status"] == "partial" and r["verdict"] == "Clean"
    assert any(g["layer"] == "llm" for g in r["incomplete_reasons"])
