"""H4 and M13 (PROJECT_REVIEW section 28, owner-approved): evidence that was not
inspected makes a scan partial instead of reading as "nothing found".

H4  An Office relationship part over 2 MiB was skipped silently (a remote
    template could hide behind ~2 KB of compressed padding) and an RTF was read
    only to 8 MiB; both reported complete. The limits stay; the skipped part is
    named in scan_results.relationships.not_checked and the scan is partial.
M13 (a) An OOXML coordinate that is not a plain integer ("1in", allowed by
    strict OOXML) made the hidden-content check raise and lose every finding;
    it now only skips that one position check.
    (b) Any other error in the hidden-content check kept nothing and recorded
    nothing; findings so far are now kept, scan_results.prompt_guard.error is
    set, and the scan is partial (for content that really is a document).

The result schema is unchanged: both keys sit inside the free-form per-layer
scan_results, and partial is an existing scan_status value. Score and verdict do
not depend on completeness."""

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import RansomwareScanner as RS
from aegis_gui.formatting import first_gap, gap_rows, verdict_text
from core.outputs import alert_payload
from detectors import prompt_guard as PG
from detectors.prompt_guard import DEFUSEDXML_AVAILABLE, PromptGuard
from detectors.relationship_scanner import RelationshipScanner
from tests.helpers import make_docx, rel, rels_xml, rewrite_zip
from tests.test_office_hidden import INJECTION, make_pptx
from tests.test_scanner_integration import _config

pytestmark = pytest.mark.skipif(not DEFUSEDXML_AVAILABLE, reason="defusedxml not installed")

REMOTE = rel("rId1", "attachedTemplate", "http://203.0.113.9/t.dotm")
PAD = b" " * (2 * 1024 * 1024 + 4096)              # whitespace after the root: valid XML
RTF_LIMIT = 8 * 1024 * 1024
GUARD = PromptGuard()


def _scanner(tmp_path, **over):
    # QR off: without a QR decoder (zbar) every Office scan is already partial
    # for that reason, which would hide what these tests check.
    return RS.RansomwareScanner(_config(tmp_path, isolate_scans=False, qr_scan_enabled=False,
                                        **over))


def _in_scan(tmp_path, name):
    folder = tmp_path / "scan"
    folder.mkdir(exist_ok=True)
    return folder / name


def _oversized_rels_docx(tmp_path, name="padded.docx", template_in_small_part=False):
    base = make_docx(tmp_path / f"base-{name}")
    replace = {"word/_rels/settings.xml.rels": rels_xml(REMOTE) + PAD}
    if template_in_small_part:
        replace["word/_rels/footnotes.xml.rels"] = rels_xml(
            rel("rId9", "attachedTemplate", "http://198.51.100.4/x.dotm"))
    return rewrite_zip(base, _in_scan(tmp_path, name), replace)


def _gaps(result, layer):
    return [g for g in result["incomplete_reasons"] if g["layer"] == layer]


# ------------------------------------------------------------------ H4: relationships
def test_an_oversized_relationship_part_is_named_not_silently_skipped(tmp_path):
    p = _oversized_rels_docx(tmp_path, template_in_small_part=True)
    with zipfile.ZipFile(p) as z:
        info = z.getinfo("word/_rels/settings.xml.rels")
        assert info.file_size > 2 * 1024 * 1024 and info.compress_size < 64 * 1024
    res = RelationshipScanner().scan_file(p)
    assert res.checked and res.kinds == ["remote_template"]   # the small part is still read
    assert res.not_checked == ("1 relationship part(s) over 2 MiB not checked: "
                               "word/_rels/settings.xml.rels")
    assert res.as_dict()["not_checked"] == res.not_checked


def test_normal_office_files_and_rtf_have_no_not_checked_key(tmp_path):
    clean = RelationshipScanner().scan_file(make_docx(tmp_path / "ok.docx")).as_dict()
    assert "not_checked" not in clean and clean["checked"]
    rtf = tmp_path / "ok.rtf"
    rtf.write_bytes(b"{\\rtf1 " + b"x" * (RTF_LIMIT - 64) + b"}")      # just under the limit
    assert "not_checked" not in RelationshipScanner().scan_file(rtf).as_dict()


def test_rtf_beyond_8_mib_is_reported_and_earlier_findings_kept(tmp_path):
    rtf = tmp_path / "big.rtf"
    rtf.write_bytes(b"{\\rtf1{\\*\\template http://203.0.113.9/t.dot}" + b"x" * RTF_LIMIT + b"}")
    res = RelationshipScanner().scan_file(rtf)
    assert res.kinds == ["rtf_remote_template"]
    assert res.not_checked == "RTF content after the first 8 MiB not checked"


def test_scan_of_an_oversized_part_is_partial_with_the_same_score(tmp_path):
    s = _scanner(tmp_path)
    padded = s.scan_file(str(_oversized_rels_docx(tmp_path)))
    small = s.scan_file(str(rewrite_zip(make_docx(tmp_path / "b2.docx"), tmp_path / "scan" / "small.docx",
                                        {"word/_rels/settings.xml.rels": rels_xml()})))
    assert small["scan_status"] == "complete" and not _gaps(small, "relationships")
    assert padded["scan_status"] == "partial"
    [gap] = _gaps(padded, "relationships")
    assert gap["status"] == "partial" and "over 2 MiB not checked" in gap["reason"]
    assert padded["verdict_label"] == f"{padded['verdict']} (partial scan)"
    # completeness never moves the score or the verdict
    assert (padded["risk_score"], padded["verdict"]) == (small["risk_score"], small["verdict"])


def test_an_rtf_over_the_limit_scans_partial(tmp_path):
    s = _scanner(tmp_path)
    p = tmp_path / "scan" / "long.rtf"
    p.write_bytes(b"{\\rtf1 " + b"x" * (RTF_LIMIT + 16) + b"}")
    r = s.scan_file(str(p))
    assert r["scan_status"] == "partial"
    assert [g["reason"] for g in _gaps(r, "relationships")] == [
        "RTF content after the first 8 MiB not checked"]


def test_partial_status_survives_the_isolated_worker(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, _scanner_factory="tests.worker_fakes:make",
                                     scan_timeout_seconds=60, scan_workers=1, qr_scan_enabled=False,
                                     data_dir=str(tmp_path / "data")))
    r = s.scan_one(str(_oversized_rels_docx(tmp_path)))
    assert r["provenance"]["isolation"] == "worker"
    assert r["scan_status"] == "partial" and _gaps(r, "relationships")


# ------------------------------------------------------------------ M13 (a)
def test_a_non_integer_coordinate_no_longer_hides_the_findings(tmp_path):
    p = make_pptx(tmp_path / "d.pptx", [{"shapes": [
        {"text": "Agenda", "x": "1in"},
        {"text": INJECTION, "hidden": True}]}])
    res = GUARD.inspect_hidden_content(p)
    assert res.reasons == ["hidden_shape"] and INJECTION in res.snippets and not res.error


def test_only_the_position_check_of_that_shape_is_skipped(tmp_path):
    p = make_pptx(tmp_path / "d.pptx", [{"shapes": [
        {"text": "off by inches", "x": "20in"},          # unknown: not judged
        {"text": INJECTION, "x": 9_500_000}]}])          # plain EMU: still judged
    res = GUARD.inspect_hidden_content(p)
    assert res.reasons == ["text_outside_slide"] and res.snippets == [INJECTION]
    deck = make_pptx(tmp_path / "s.pptx", [{"shapes": [{"text": INJECTION, "x": 9_500_000}]}],
                     size=("10in", "7.5in"))
    assert not GUARD.inspect_hidden_content(deck).found   # unknown slide size: no off-slide test


def test_a_scan_with_inch_coordinates_is_complete_and_scored(tmp_path):
    s = _scanner(tmp_path)
    p = make_pptx(tmp_path / "scan" / "deck.pptx", [{"shapes": [
        {"text": "Agenda", "x": "1in"}, {"text": INJECTION, "hidden": True}]}])
    r = s.scan_file(str(p))
    guard = r["scan_results"]["prompt_guard"]
    assert guard["hidden_text_found"] and guard["injection_status"] == "confirmed"
    assert "error" not in guard and not _gaps(r, "prompt-guard")


# ------------------------------------------------------------------ M13 (b)
def _docx_with_broken_footer(tmp_path, name="broken.docx"):
    base = make_docx(tmp_path / f"base-{name}")
    with zipfile.ZipFile(base) as z:
        body = z.read("word/document.xml").decode("utf-8")
    hidden = (f'<w:r><w:rPr><w:vanish/></w:rPr><w:t>{INJECTION}</w:t></w:r>')
    body = body.replace("</w:body>", f"<w:p>{hidden}</w:p></w:body>", 1)
    return rewrite_zip(base, _in_scan(tmp_path, name), {
        "word/document.xml": body.encode("utf-8"),
        "word/footer1.xml": b"<w:ftr xmlns:w='http://schemas.openxmlformats.org/"
                            b"wordprocessingml/2006/main'><w:p>unclosed"})


def test_an_error_keeps_what_was_found_and_says_so(tmp_path):
    res = GUARD.inspect_hidden_content(_docx_with_broken_footer(tmp_path))
    assert res.found and res.reasons == ["hidden_attribute"] and INJECTION in res.snippets
    assert res.error.startswith("ParseError")
    out = GUARD.analyze("", "", res).as_dict()
    assert out["error"] == res.error and out["injection_status"] == "confirmed"


def test_findings_on_earlier_slides_survive_a_later_error(tmp_path, monkeypatch):
    p = make_pptx(tmp_path / "d.pptx", [
        {"shapes": [{"text": INJECTION, "hidden": True}]},
        {"shapes": [{"text": "second slide"}]}])
    real, calls = PromptGuard._pptx_shape, []

    def flaky(self, shape, *a, **kw):
        calls.append(1)
        if len(calls) > 1:
            raise ValueError("unexpected shape")
        return real(self, shape, *a, **kw)
    monkeypatch.setattr(PromptGuard, "_pptx_shape", flaky)
    res = GUARD.inspect_hidden_content(p)
    assert res.reasons == ["hidden_shape"] and res.error == "ValueError: unexpected shape"


def test_clean_documents_carry_no_error_key(tmp_path):
    out = GUARD.analyze("text", "", GUARD.inspect_hidden_content(make_docx(tmp_path / "a.docx")))
    assert "error" not in out.as_dict()


def test_scan_with_a_broken_part_is_partial_and_still_scored(tmp_path):
    s = _scanner(tmp_path)
    r = s.scan_file(str(_docx_with_broken_footer(tmp_path)))
    guard = r["scan_results"]["prompt_guard"]
    assert guard["hidden_text_found"] and guard["error"].startswith("ParseError")
    assert r["scan_status"] == "partial"
    assert any(g["reason"].startswith("hidden-content check incomplete: ParseError")
               for g in _gaps(r, "prompt-guard"))
    # the findings made before the error still count (before the fix: none)
    indicators = {c["indicator"] for c in r["score_breakdown"]["contributions"]}
    assert {"prompt_injection", "hidden_content"} <= indicators


def test_an_error_on_a_program_named_like_a_document_is_not_a_gap(tmp_path, monkeypatch):
    """As for text extraction: a program merely named .pdf fails the PDF reader,
    but it is analysed as what it is, so the scan stays complete."""
    s = _scanner(tmp_path)
    p = tmp_path / "scan" / "invoice.pdf"
    p.write_bytes(b"#!/bin/sh\necho hello\n")
    r = s.scan_file(str(p))
    assert not _gaps(r, "prompt-guard")


# ------------------------------------------------------------------ where partial shows
@pytest.fixture
def partial_result(tmp_path):
    s = _scanner(tmp_path)
    return s, s.scan_file(str(_oversized_rels_docx(tmp_path)))


def test_partial_in_the_text_and_json_reports(partial_result):
    s, r = partial_result
    assert not r["is_malicious"]
    text = s.generate_report([r])
    assert "NOT FULLY INSPECTED (1)" in text
    assert f"Verdict:  {r['verdict']} (partial scan)" in text
    assert "[relationships] 1 relationship part(s) over 2 MiB not checked" in text
    saved = json.loads(next(Path(s.report_dir).glob("ransomware_scan_*.json")).read_text(
        encoding="utf-8"))
    assert saved[0]["scan_status"] == "partial"
    assert saved[0]["scan_results"]["relationships"]["not_checked"]


def test_partial_in_the_cli_output(tmp_path, partial_result, capsys):
    s, r = partial_result
    RS._scan_or_schedule(SimpleNamespace(scan_file=r["file_path"], scan_now=False,
                                         background=False), s)
    out = capsys.readouterr().out
    assert "NOT FULLY INSPECTED (1)" in out and "(partial scan)" in out
    assert "over 2 MiB not checked" in out


def test_partial_in_the_gui_labels(partial_result):
    _, r = partial_result
    assert verdict_text(r) == f"{r['verdict']} (partial scan)"
    assert first_gap(r).startswith("not fully inspected: 1 relationship part(s) over 2 MiB")
    assert ("relationships", r["incomplete_reasons"][0]["reason"], "") in gap_rows(r)


def test_partial_in_alerts_and_json_lines(partial_result, tmp_path):
    _, r = partial_result
    assert alert_payload(r)["scan_status"] == "partial"
    from core.outputs import write_jsonl
    write_jsonl([r], tmp_path / "out.jsonl")
    line = json.loads((tmp_path / "out.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert line["scan_status"] == "partial"


def test_results_still_match_the_published_schema(partial_result, tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    _, r = partial_result
    schema = json.loads((Path(PG.__file__).resolve().parent.parent / "api"
                         / "scan_result.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(json.loads(json.dumps(r)), schema)
    broken = _scanner(tmp_path).scan_file(str(_docx_with_broken_footer(tmp_path, "b2.docx")))
    jsonschema.validate(json.loads(json.dumps(broken)), schema)


# ------------------------------------------------------------------ H4-b: oversized XML parts
# An XML part over the hidden-content size limit (20 MiB) was only listed as
# oversized_xml_part(...) in hidden_reasons while the scan read "complete", so
# hidden text could sit in a padded part. It is now named in
# scan_results.prompt_guard.not_checked and the scan is partial.
XML_LIMIT = 20 * 1024 * 1024
FOOTER = ("<w:ftr xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>"
          "<w:p><w:r><w:t>Page footer</w:t></w:r></w:p></w:ftr>")


def _docx_with_oversized_footer(tmp_path, name="bigfooter.docx", hidden=False):
    base = make_docx(tmp_path / f"base-{name}")
    replace = {"word/footer1.xml": FOOTER.encode("utf-8") + b" " * (XML_LIMIT + 4096)}
    if hidden:
        with zipfile.ZipFile(base) as z:
            body = z.read("word/document.xml").decode("utf-8")
        run = f"<w:r><w:rPr><w:vanish/></w:rPr><w:t>{INJECTION}</w:t></w:r>"
        replace["word/document.xml"] = body.replace(
            "</w:body>", f"<w:p>{run}</w:p></w:body>", 1).encode("utf-8")
    return rewrite_zip(base, _in_scan(tmp_path, name), replace)


def test_an_oversized_document_part_is_named_and_findings_kept(tmp_path):
    p = _docx_with_oversized_footer(tmp_path, hidden=True)
    with zipfile.ZipFile(p) as z:
        assert z.getinfo("word/footer1.xml").compress_size < 256 * 1024     # tiny on disk
    res = GUARD.inspect_hidden_content(p)
    assert res.found and INJECTION in res.snippets
    assert res.reasons == ["hidden_attribute", "oversized_xml_part(word/footer1.xml)"]
    assert res.not_checked == ("1 XML part(s) over 20 MiB not checked for hidden content: "
                               "word/footer1.xml")
    assert GUARD.analyze("", "", res).as_dict()["not_checked"] == res.not_checked


def test_oversized_slides_and_workbooks_are_named(tmp_path, monkeypatch):
    monkeypatch.setattr(PG, "_MAX_XML_BYTES", 4096)             # small parts, same code path
    deck = make_pptx(tmp_path / "d.pptx", [
        {"shapes": [{"text": INJECTION, "hidden": True}]},
        {"shapes": [{"text": "x" * 5000}]}])
    res = GUARD.inspect_hidden_content(deck)
    assert res.reasons[0] == "hidden_shape" and "ppt/slides/slide2.xml" in res.not_checked
    from tests.test_office_hidden import make_xlsx
    book = make_xlsx(tmp_path / "b.xlsx", [{"name": "S" + "x" * 30, "cells": {"A1": ("hi", 0)}}
                                           for _ in range(150)])        # workbook.xml > 4 KiB
    res = GUARD.inspect_hidden_content(book)
    assert not res.found and "xl/workbook.xml" in res.not_checked   # nothing could be checked


def test_documents_within_the_limit_carry_no_not_checked_key(tmp_path):
    out = GUARD.analyze("", "", GUARD.inspect_hidden_content(make_docx(tmp_path / "a.docx")))
    assert "not_checked" not in out.as_dict()


def test_scan_with_an_oversized_part_is_partial_with_the_same_score(tmp_path):
    s = _scanner(tmp_path)
    padded = s.scan_file(str(_docx_with_oversized_footer(tmp_path, hidden=True)))
    small = s.scan_file(str(rewrite_zip(
        _docx_with_oversized_footer(tmp_path, "tmp.docx", hidden=True),
        _in_scan(tmp_path, "smallfooter.docx"), {"word/footer1.xml": FOOTER.encode("utf-8")})))
    assert small["scan_status"] == "complete" and not _gaps(small, "prompt-guard")
    assert padded["scan_status"] == "partial"
    [gap] = _gaps(padded, "prompt-guard")
    assert gap["status"] == "partial" and gap["reason"].startswith("1 XML part(s) over 20 MiB")
    assert padded["scan_results"]["prompt_guard"]["not_checked"] == gap["reason"]
    assert padded["scan_results"]["prompt_guard"]["hidden_text_found"]
    assert (padded["risk_score"], padded["verdict"]) == (small["risk_score"], small["verdict"])


@pytest.fixture
def oversized_clean(tmp_path):
    s = _scanner(tmp_path)
    return s, s.scan_file(str(_docx_with_oversized_footer(tmp_path)))


def test_oversized_part_in_the_reports(oversized_clean):
    s, r = oversized_clean
    assert not r["is_malicious"] and r["scan_status"] == "partial"
    text = s.generate_report([r])
    assert "NOT FULLY INSPECTED (1)" in text
    assert f"Verdict:  {r['verdict']} (partial scan)" in text
    assert "[prompt-guard] 1 XML part(s) over 20 MiB not checked for hidden content" in text
    saved = json.loads(next(Path(s.report_dir).glob("ransomware_scan_*.json")).read_text(
        encoding="utf-8"))
    assert saved[0]["scan_status"] == "partial"
    assert saved[0]["scan_results"]["prompt_guard"]["not_checked"]
    assert saved[0]["verdict_label"].endswith("(partial scan)")


def test_a_flagged_file_shows_the_gap_under_its_finding(tmp_path):
    s = _scanner(tmp_path)
    r = s.scan_file(str(_docx_with_oversized_footer(tmp_path, hidden=True)))
    assert r["is_malicious"]
    text = s.generate_report([r])
    assert "  Scan:     partial - 1 gap(s) in the evidence" in text
    assert "[prompt-guard] 1 XML part(s) over 20 MiB not checked" in text


def test_oversized_part_in_the_cli_output(oversized_clean, capsys):
    s, r = oversized_clean
    RS._scan_or_schedule(SimpleNamespace(scan_file=r["file_path"], scan_now=False,
                                         background=False), s)
    out = capsys.readouterr().out
    assert "NOT FULLY INSPECTED (1)" in out and "(partial scan)" in out
    assert "not checked for hidden content: word/footer1.xml" in out


def test_oversized_part_in_the_gui_labels(oversized_clean):
    _, r = oversized_clean
    assert verdict_text(r) == f"{r['verdict']} (partial scan)"
    assert first_gap(r) == ("not fully inspected: 1 XML part(s) over 20 MiB not checked for "
                            "hidden content: word/footer1.xml")
    assert gap_rows(r) == [("prompt-guard", r["incomplete_reasons"][0]["reason"], "")]


def test_oversized_part_result_matches_the_schema(oversized_clean):
    jsonschema = pytest.importorskip("jsonschema")
    _, r = oversized_clean
    schema = json.loads((Path(PG.__file__).resolve().parent.parent / "api"
                         / "scan_result.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(json.loads(json.dumps(r)), schema)
    assert alert_payload(r)["scan_status"] == "partial"
