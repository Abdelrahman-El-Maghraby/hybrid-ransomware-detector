"""4.7: scan_status / incomplete_reasons say how far the evidence goes, separately
from the score; a clean score on an incomplete scan never reads as plain "Clean"."""

import io
import json
import zipfile

import pytest

import RansomwareScanner as RS
from api import SCHEMA_VERSION, load_schema
from core.outputs import alert_payload
from engine import completeness as C
from engine.capabilities import DISABLED, DOWN, UP
from engine.validation import ConfigError, check_config, validate_config
from tests.helpers import make_docx, make_pdf, make_zipcrypto_zip
from tests.test_scanner_integration import _config

# ZipCrypto checks a password against one header byte, so a wrong delivery password
# passes about 1 time in 256; on a 1-byte member the CRC then matches too and the
# member really is opened (CI saw it once). A longer member makes a false open need a 32-bit
# CRC match as well.
SECRET_TEXT = b"quarterly figures, do not forward: 4471-2209-8813-5530-0001-xx"


def _disguised_pe() -> bytes:
    h = bytearray(4096)
    h[0:2] = b"MZ"
    h[0x3C:0x40] = (0x80).to_bytes(4, "little")
    h[0x80:0x84] = b"PE\x00\x00"
    return bytes(h)


def _all_up(scanner, **overrides):
    """Layer states as on a complete installation, whatever this machine has."""
    states = {name: {"state": UP, "detail": "", "missing": []} for name in scanner.capability_states}
    for name in ("llm", "virustotal", "sandbox", "emulation"):
        states[name] = {"state": DISABLED, "detail": "off", "missing": []}
    states.update(overrides)
    scanner.capability_states = states
    return scanner


@pytest.fixture
def scanner(tmp_path):
    return _all_up(RS.RansomwareScanner(_config(tmp_path, cache_enabled=False)))


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_complete_scan(scanner, tmp_path):
    r = scanner.scan_file(_write(tmp_path, "letter.pdf", make_pdf("Quarterly report")))
    assert r["scan_status"] == "complete" and r["incomplete_reasons"] == []
    assert r["verdict_label"] == r["verdict"] == "Clean"


def test_precedence_is_documented_and_total():
    assert C.PRECEDENCE == ("complete", "unsupported", "partial", "locked", "failed")
    assert C.worst(["partial", "locked", "unsupported"]) == "locked"
    assert C.worst(["failed", "locked"]) == "failed"
    assert C.worst([]) == "complete"


def test_layer_error_makes_the_scan_partial(scanner, tmp_path, monkeypatch):
    def boom(*a, **k):
        raise ValueError("bad header")
    monkeypatch.setattr(scanner.pe_analyzer, "analyze_file", boom)
    r = scanner.scan_file(_write(tmp_path, "tool.exe", _disguised_pe()))
    assert r["scan_status"] == "partial"
    assert {"layer": "pe", "reason": "layer error: ValueError: bad header",
            "member_path": r["file_path"], "status": "partial"} in r["incomplete_reasons"]


def test_unavailable_layer_counts_only_where_it_applies(scanner, tmp_path):
    down = {"state": DOWN, "detail": "needs oletools", "missing": ["oletools"]}
    _all_up(scanner, macro=down)
    pdf = scanner.scan_file(_write(tmp_path, "a.pdf", make_pdf("hello")))
    assert pdf["scan_status"] == "complete"              # macros cannot live in a PDF
    doc = make_docx(tmp_path / "a.docm")
    r = scanner.scan_file(str(doc))
    assert r["scan_status"] == "partial"
    assert r["incomplete_reasons"][0]["reason"] == "layer unavailable (needs oletools)"
    assert r["verdict_label"] == f"{r['verdict']} (partial scan)"


def test_disabled_optional_layers_do_not_make_a_scan_partial(scanner, tmp_path):
    assert scanner.capability_states["llm"]["state"] == DISABLED
    r = scanner.scan_file(_write(tmp_path, "b.pdf", make_pdf("hello")))
    assert r["scan_status"] == "complete"


def test_intended_skips_are_not_gaps(tmp_path):
    p = tmp_path / "scan" / "vendor.pdf"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(make_pdf("vendor"))
    import hashlib
    allow = tmp_path / "allow.txt"
    allow.write_text(hashlib.sha256(p.read_bytes()).hexdigest() + "  # vendor\n")
    s = _all_up(RS.RansomwareScanner(_config(tmp_path, allowlist_path=str(allow))))
    r = s.scan_file(str(p))
    assert r["scan_results"]["skipped_layers"]["layers"] and r["scan_status"] == "complete"


def test_external_layer_failure_is_partial(scanner, tmp_path, monkeypatch):
    scanner.config["virustotal_api_key"] = "k" * 64
    monkeypatch.setattr(scanner, "scan_file_with_virustotal",
                        lambda path, hashes: scanner._vt_empty(error="API Error: 500"))
    r = scanner.scan_file(_write(tmp_path, "c.pdf", make_pdf("hello")))
    assert r["scan_status"] == "partial"
    assert r["incomplete_reasons"][0]["reason"] == "virustotal failed: API Error: 500"


def test_size_skip_of_a_required_layer_is_partial(scanner, tmp_path):
    scanner.fuzzy_max_bytes = 10
    r = scanner.scan_file(_write(tmp_path, "d.pdf", make_pdf("hello")))
    assert r["scan_status"] == "partial"
    assert r["incomplete_reasons"][0]["layer"] == "fuzzy"


def test_encrypted_member_locks_the_archive_without_lowering_the_score(scanner, tmp_path):
    secret = make_zipcrypto_zip(tmp_path / "secret.zip", "plan.txt", SECRET_TEXT, "Zq8!long-pw")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("invoice.pdf", _disguised_pe())
        z.writestr("secret.zip", secret.read_bytes())
    both = scanner.scan_file(_write(tmp_path, "parcel.zip", buf.getvalue()))
    buf2 = io.BytesIO()
    with zipfile.ZipFile(buf2, "w") as z:
        z.writestr("invoice.pdf", _disguised_pe())
    only_bad = scanner.scan_file(_write(tmp_path, "parcel2.zip", buf2.getvalue()))

    assert both["scan_status"] == "locked"
    locked = [r for r in both["incomplete_reasons"] if r["status"] == "locked"]
    assert locked and locked[0]["member_path"].endswith("secret.zip!/plan.txt")
    assert only_bad["scan_status"] == "complete"
    # status, score and verdict are independent: the malicious member keeps its score
    assert both["risk_score"] == only_bad["risk_score"] and both["verdict"] == only_bad["verdict"]
    assert both["verdict"] in ("High", "Critical")
    # the nested ZIP is walked by the outer archive itself: its locked member is
    # named by its full path, and the scanned member summaries carry their status
    members = both["scan_results"]["archive"]["member_results"]
    assert [m["scan_status"] for m in members if m["name"].endswith("invoice.pdf")] == ["complete"]


def test_password_protected_pdf_is_locked(scanner, tmp_path):
    from pypdf import PdfReader, PdfWriter
    src = PdfReader(io.BytesIO(make_pdf("Pay the invoice")))

    def encrypted(user_password):
        w = PdfWriter()
        for page in src.pages:
            w.add_page(page)
        w.encrypt(user_password=user_password, owner_password="owner-secret", algorithm="AES-128")
        out = io.BytesIO()
        w.write(out)
        return out.getvalue()
    r = scanner.scan_file(_write(tmp_path, "locked.pdf", encrypted("open-sesame")))
    assert r["scan_status"] == "locked" and r["verdict_label"].endswith("(locked scan)")
    owner_only = scanner.scan_file(_write(tmp_path, "owner.pdf", encrypted("")))
    assert owner_only["scan_status"] == "complete"     # every reader opens it


def test_unsupported_format(scanner, tmp_path):
    macho = b"\xcf\xfa\xed\xfe" + bytes(4092)
    r = scanner.scan_file(_write(tmp_path, "tool", macho))
    assert r["scan_status"] == "unsupported"
    assert "macho" in r["incomplete_reasons"][0]["reason"]


def test_member_budget_makes_the_archive_partial(scanner, tmp_path):
    scanner.archive_scan_members = 1
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "one")
        z.writestr("b.txt", "two")
    r = scanner.scan_file(_write(tmp_path, "two.zip", buf.getvalue()))
    assert r["scan_status"] == "partial"
    assert any("over the scan budget" in x["reason"] for x in r["incomplete_reasons"])


def test_failed_worker_result(tmp_path):
    from engine.workers import failure_result
    s = RS.RansomwareScanner(_config(tmp_path))
    r = failure_result(s, _write(tmp_path, "hang.pdf", b"%PDF-1.4"), "timed out after 300 s")
    assert r["scan_status"] == "failed" and r["verdict_label"] == f"{r['verdict']} (failed scan)"
    assert r["incomplete_reasons"] == [{"member_path": r["file_path"], "layer": "worker",
                                        "reason": "timed out after 300 s", "status": "failed"}]


def test_reasons_are_capped():
    class Ctx:
        display, path, depth = "x", "x", 0
        scan_results: dict = {}
        member_reasons = [C.reason("partial", f"x!/{i}", "archive", "r") for i in range(250)]

        def data(self):
            return b""

    class Scanner:
        capability_states: dict = {}
        max_nesting = 2
    status, reasons = C.assess(Scanner(), Ctx())
    assert status == "partial" and len(reasons) == C.MAX_REASONS
    assert reasons[-1]["reason"] == "151 more reason(s) not listed"


# ------------------------------------------------------------- how it is shown
def test_clean_but_incomplete_never_reads_as_plain_clean(scanner, tmp_path):
    from aegis_gui.formatting import first_gap, verdict_text
    _all_up(scanner, macro={"state": DOWN, "detail": "needs oletools", "missing": ["oletools"]})
    r = scanner.scan_file(str(make_docx(tmp_path / "b.docm")))
    assert r["verdict"] == "Clean" and r["verdict_label"] == "Clean (partial scan)"
    assert verdict_text(r) == "Clean (partial scan)" and first_gap(r).startswith("not fully")
    report = scanner.generate_report([r])
    assert "NOT FULLY INSPECTED (1)" in report and "Clean (partial scan)" in report
    assert "No suspicious files detected in what was inspected; 1 scan(s)" in report
    assert "Scan completeness:      1 partial" in report
    assert alert_payload(r)["scan_status"] == "partial"


def test_complete_report_is_unchanged(scanner, tmp_path):
    r = scanner.scan_file(_write(tmp_path, "e.pdf", make_pdf("hello")))
    report = scanner.generate_report([r])
    assert "\nNo suspicious files detected.\n" in report and "NOT FULLY" not in report
    assert "Scan completeness:      1 complete" in report


def test_flagged_file_lists_its_gaps(scanner, tmp_path, monkeypatch):
    def boom(*a, **k):
        raise ValueError("bad header")
    monkeypatch.setattr(scanner.yara_engine, "scan_file", boom)
    r = scanner.scan_file(_write(tmp_path, "invoice.pdf", _disguised_pe()))
    report = scanner.generate_report([r])
    assert f"Verdict:  {r['verdict']} (partial scan)" in report
    assert "[yara] layer error: ValueError: bad header" in report


def test_result_matches_schema_1_2(scanner, tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    r = scanner.scan_file(_write(tmp_path, "f.pdf", make_pdf("hello")))
    assert SCHEMA_VERSION == "1.3" and r["schema_version"] == "1.3"
    jsonschema.validate(json.loads(json.dumps(r)), load_schema())
    r["scan_status"] = "sort-of"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(r, load_schema())


# ------------------------------------------------------- production profile
def test_production_profile_refuses_a_disabled_required_layer(tmp_path):
    cfg = _config(tmp_path, profile="production", qr_scan_enabled=False, ml_enabled=False,
                  emulation_enabled=True)
    errors, _ = validate_config(cfg)
    assert any("QR_SCAN_ENABLED=0" in e for e in errors)
    assert any("ML_ENABLED=0" in e for e in errors)
    assert any("EMULATION_ENABLED" in e for e in errors)
    with pytest.raises(ConfigError):
        check_config(cfg, env_problems=())
    # the same settings are allowed outside the production profile
    assert not [e for e in validate_config(dict(cfg, profile="standard"))[0]
                if "production profile" in e]


def test_production_profile_needs_the_rules_folder(tmp_path):
    cfg = _config(tmp_path, profile="production", yara_rules_dir=str(tmp_path / "missing"))
    assert any("YARA_RULES_DIR" in e for e in validate_config(cfg)[0])
    cfg = _config(tmp_path, profile="prod")
    assert any("AEGIS_PROFILE" in e for e in validate_config(cfg)[0])


def test_member_gaps_propagate_with_the_precedence(scanner, tmp_path):
    _all_up(scanner, macro={"state": DOWN, "detail": "needs oletools", "missing": ["oletools"]})
    doc = make_docx(tmp_path / "plan.docm").read_bytes()
    secret = make_zipcrypto_zip(tmp_path / "s.zip", "x.txt", SECRET_TEXT, "Zq8!long-pw").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("plan.docm", doc)
    partial_only = scanner.scan_file(_write(tmp_path, "p.zip", buf.getvalue()))
    assert partial_only["scan_status"] == "partial"
    assert partial_only["incomplete_reasons"][0]["member_path"].endswith("!/plan.docm")
    with zipfile.ZipFile(buf, "a") as z:
        z.writestr("s.zip", secret)
    both = scanner.scan_file(_write(tmp_path, "q.zip", buf.getvalue()))
    assert both["scan_status"] == "locked"                    # locked outranks partial
    assert {r["status"] for r in both["incomplete_reasons"]} == {"partial", "locked"}


def test_gui_lists_every_gap_and_the_provenance(scanner, tmp_path):
    """A9-1: the analyst sees what was not inspected and what produced the result."""
    from aegis_gui.formatting import gap_rows, provenance_rows
    _all_up(scanner, macro={"state": DOWN, "detail": "needs oletools", "missing": ["oletools"]})
    scanner.provenance = dict(scanner.provenance, layers_down=[{"layer": "macro",
                                                                "reason": "needs oletools"}])
    r = scanner.scan_file(str(make_docx(tmp_path / "b.docm")))
    rows = gap_rows(r)
    assert rows and rows[0][0] == "macro" and "oletools" in rows[0][1]
    labels = dict(provenance_rows(r))
    assert {"Rules", "Registry", "Profile", "Services"} <= set(labels)
    assert labels["Profile"] == "standard" and f"schema {SCHEMA_VERSION}" in labels["Registry"]
    assert "macro: needs oletools" in labels.get("Down here", "")
    many = dict(r, incomplete_reasons=[{"layer": "x", "reason": str(i)} for i in range(25)])
    assert len(gap_rows(many)) == 21 and "5 more" in gap_rows(many)[-1][1]
    assert gap_rows(dict(r, scan_status="complete")) == [] and provenance_rows({}) == []


def test_diagnostics_rank_required_layers_first():
    """A9-4: a required layer that is down is a problem; an optional or switched-off
    one is a note; configuration warnings sit in between. The copied report holds
    no path or key."""
    from aegis_gui.formatting import diagnostic_rows, diagnostics_text
    states = {"qr": {"state": DOWN, "detail": "needs zbar", "missing": ["zbar"]},
              "emulation": {"state": DISABLED, "detail": "EMULATION_ENABLED=0", "missing": []},
              "yara": {"state": UP, "detail": "5 rule files", "missing": []},
              "archive": {"state": UP, "missing": [],
                          "detail": "RAR through bsdtar: encrypted RAR members are not opened "
                                    "(install unar, unrar or 7-Zip)"},
              "sandbox": {"state": DOWN, "detail": "needs intel service", "missing": ["intel service"]}}
    rows = diagnostic_rows(states, ["ISOLATE_SCANS is off"])
    assert rows[0] == ("problem", "qr: needs zbar")
    assert rows[1] == ("warning", "ISOLATE_SCANS is off")
    assert ("note", "sandbox: needs intel service") in rows
    assert ("note", "emulation: off (EMULATION_ENABLED=0)") in rows
    assert not any("yara" in t for _, t in rows)
    assert any(lvl == "note" and t.startswith("archive: RAR through bsdtar") for lvl, t in rows)
    text = diagnostics_text(rows, "4.7.0", "Windows 11")
    assert text.splitlines()[0] == "Aegis Sentinel 4.7.0 on Windows 11"
    assert "[problem] qr: needs zbar" in text
    assert diagnostics_text([], "4.7.0", "macOS").endswith("every layer is up")


def test_containers_that_could_not_be_opened_are_never_complete(scanner, tmp_path):
    """A4: a damaged archive, an archive that would not open, and a mail over the
    analysis limit all came back 'Clean, complete' with nothing inspected."""
    import io
    import shutil
    import zipfile

    from tests.test_file_integrity import _pe_bytes
    from tests.test_mail_analyzer import make_eml
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("payload.exe", _pe_bytes(4096))
    truncated = _write(tmp_path, "invoice.zip", buf.getvalue()[: len(buf.getvalue()) // 2])
    r = scanner.scan_file(str(truncated))
    assert r["scan_status"] == "partial" and r["verdict_label"].endswith("(partial scan)")
    assert any("zip content was not opened" in g["reason"] for g in r["incomplete_reasons"])

    broken_7z = _write(tmp_path, "bundle.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 100)
    r = scanner.scan_file(str(broken_7z))
    assert r["scan_status"] == "partial"
    assert any("could not be opened" in g["reason"] for g in r["incomplete_reasons"])

    mail = tmp_path / "statement.eml"
    make_eml(mail, subject="Invoice", sender="a@example.com",
             attachments=[("pay.exe", _pe_bytes(2048), "application", "octet-stream")])
    scanner.mail_analyzer.max_message_bytes = 100
    r = scanner.scan_file(str(mail))
    assert r["scan_status"] == "partial"
    assert any(g["reason"].startswith("message not analysed: Message is")
               for g in r["incomplete_reasons"])

    doc = make_docx(tmp_path / "letter.docx")                 # a ZIP the document layers read
    shutil.copy(doc, tmp_path / "letter.bin")
    for path in (doc, tmp_path / "letter.bin"):
        assert scanner.scan_file(str(path))["scan_status"] == "complete"
    good = io.BytesIO()
    with zipfile.ZipFile(good, "w") as z:
        z.writestr("notes.txt", "quarterly figures")
    assert scanner.scan_file(str(_write(tmp_path, "ok.zip", good.getvalue())))["scan_status"] == "complete"


def test_documents_that_could_not_be_parsed_are_never_complete(scanner, tmp_path, monkeypatch):
    """A2: a damaged PDF / Office file gave '' text (parser failed) and read
    'Clean, complete'; YARA, macro and relationship failures sat in a free-text
    detail. Each is now a partial gap - and a program merely named .pdf is not."""
    pdf = make_pdf("Quarterly figures " * 40)
    for name, data in (("cut.pdf", pdf[: len(pdf) // 2]),
                       ("noise.pdf", b"%PDF-1.7\n" + b"\x00\xff" * 500)):
        r = scanner.scan_file(str(_write(tmp_path, name, data)))
        assert r["scan_status"] == "partial", name
        assert any(g["reason"].startswith("document text not read: PDF could not be parsed")
                   for g in r["incomplete_reasons"])
    raw = make_docx(tmp_path / "full.docx").read_bytes()
    r = scanner.scan_file(str(_write(tmp_path, "cut.docx", raw[: len(raw) // 2])))
    assert any("Office document could not be parsed" in g["reason"] for g in r["incomplete_reasons"])

    r = scanner.scan_file(str(_write(tmp_path, "broken.doc", bytes.fromhex("D0CF11E0A1B11AE1")
                                     + b"\0" * 600)))
    assert r["scan_results"]["macro_analysis"]["error"]
    assert any(g["layer"] == "macro" and "could not analyse" in g["reason"]
               for g in r["incomplete_reasons"])

    class TimingOut:
        def match(self, *a, **k):
            raise RuntimeError("internal error: 30")   # what yara-python raises on a timeout
    if scanner.yara_engine._rules is not None:
        monkeypatch.setattr(scanner.yara_engine, "_rules", TimingOut())
        r = scanner.scan_file(str(_write(tmp_path, "big.txt", b"plain text " * 100)))
        assert r["scan_results"]["yara"]["error"].startswith("RuntimeError")
        assert any(g["layer"] == "yara" for g in r["incomplete_reasons"])
        monkeypatch.undo()

    for name, data in (("invoice.pdf", _disguised_pe()), ("ok.pdf", pdf),
                       ("ok.docx", raw)):
        assert scanner.scan_file(str(_write(tmp_path, name, data)))["scan_status"] == "complete", name
