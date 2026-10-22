"""Fixes from the 4.4.0-beta.3 benign-corpus benchmark (see CHANGELOG)."""

import json
import time

import pytest

from detectors import YARA_AVAILABLE
from detectors.fuzzy_hash import FuzzyHasher
from detectors.yara_engine import YaraEngine, file_extension
from engine.text import extract_suspicious_strings
from tests.test_file_integrity import _pe_bytes


def test_strings_pass_is_linear_on_one_long_line(tmp_path):
    p = tmp_path / "bundle.min.js"
    p.write_bytes(b"var a=1;function f(x){return x+1}" * 30_000 + b"\n")   # ~1 MB, one line
    start = time.perf_counter()
    out = extract_suspicious_strings(str(p))
    assert time.perf_counter() - start < 2.0          # was minutes (quadratic)
    assert out.startswith("var a=1;")


@pytest.mark.parametrize("name, ext", [("a/b/setup.EXE", "exe"), ("x.tar.gz", "gz"),
                                       ("noext", ""), (".bashrc", ""), ("C:\\\\t\\\\d.pdf", "pdf")])
def test_file_extension(name, ext):
    assert file_extension(name) == ext


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_program_named_as_program_is_not_masquerading(tmp_path):
    engine = YaraEngine("rules")
    pe = _pe_bytes(4096)
    exe, pdf = tmp_path / "tool.exe", tmp_path / "invoice.pdf"
    exe.write_bytes(pe)
    pdf.write_bytes(pe)
    assert "Embedded_Executable_In_Document" not in {m.rule for m in engine.scan_file(str(exe)).matches}
    assert "Embedded_Executable_In_Document" in {m.rule for m in engine.scan_file(str(pdf)).matches}


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_macro_words_in_a_manual_page_do_not_match(tmp_path):
    engine = YaraEngine("rules")
    text = "Sub AutoOpen() Shell \"cmd.exe\" URLDownloadToFile http://x.example/a"
    page, vba = tmp_path / "manual.html", tmp_path / "module.bas"
    page.write_text(f"<html><body><pre>{text}</pre></body></html>")
    vba.write_text(text)
    assert not engine.scan_file(str(page)).matches
    assert {"Office_Macro_AutoExec_Execution", "Office_Macro_Payload_Download"} <= {
        m.rule for m in engine.scan_file(str(vba)).matches}


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_bitcoin_rule_needs_currency_and_ransom_context(tmp_path):
    engine = YaraEngine("rules")
    addr = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    note, noise = tmp_path / "note.txt", tmp_path / "noise.txt"
    note.write_text(f"Pay 0.1 BTC to wallet {addr} to decrypt your files.")
    noise.write_text(f"qZ+btc/x9{addr}Lpay3send")         # base64-like chance hits
    rule = "Bitcoin_Address_With_Payment_Context"
    assert rule in {m.rule for m in engine.scan_file(str(note)).matches}
    assert rule not in {m.rule for m in engine.scan_file(str(noise)).matches}


def test_ssdeep_only_when_a_signature_needs_it(tmp_path):
    db = tmp_path / "db.json"
    db.write_text(json.dumps({"signatures": [{"family": "Example.Placeholder", "ssdeep": "3:a:b"}]}))
    assert not FuzzyHasher(str(db)).needs_ssdeep
    db.write_text(json.dumps({"signatures": [{"family": "Real", "ssdeep": "3:a:b"}]}))
    assert FuzzyHasher(str(db)).needs_ssdeep
    data = bytes(range(256)) * 64
    assert FuzzyHasher.hash_bytes(data, with_ssdeep=False)["ssdeep"] is None


def test_profile_layers_tool(tmp_path, capsys):
    from tools.profile_layers import main
    (tmp_path / "a.txt").write_text("hello world " * 50)
    (tmp_path / "b.exe").write_bytes(_pe_bytes(2048))
    out = tmp_path / "p.json"
    assert main([str(tmp_path), "--out", str(out), "--top", "1"]) == 0
    res = json.loads(out.read_text())
    assert res["files"] == 2 and "yara" in res["layers"]
    assert "files/s" in capsys.readouterr().out
