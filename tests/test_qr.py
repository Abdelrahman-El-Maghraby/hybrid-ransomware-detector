"""4.4.0-beta.2: QR codes (quishing) in images, PDFs, Office documents and e-mail
attachments. QR images are generated here with the `qrcode` package; the links
point at documentation addresses (RFC 5737 / example domains)."""

import io
import zipfile

import pytest

import detectors.qr_scanner as qr
from detectors.qr_scanner import QRScanner, assess_url
from detectors.scoring import ScoringMatrix
from tests.test_mail_analyzer import make_eml
from tests.test_scanner_integration import _indicators, scanner  # noqa: F401  (fixture)

qrcode = pytest.importorskip("qrcode")
needs_decoder = pytest.mark.skipif(not qr.QR_AVAILABLE,
                                   reason="no QR decoder (pyzbar or opencv) installed")

SUSPICIOUS = "http://203.0.113.5/login"
ORDINARY = "https://www.example.com/menu"


def qr_png(payload: str) -> bytes:
    buf = io.BytesIO()
    qrcode.make(payload).get_image().convert("RGB").save(buf, "PNG")
    return buf.getvalue()


def qr_pdf(path, payload: str):
    from PIL import Image
    Image.open(io.BytesIO(qr_png(payload))).save(path, "PDF")
    return path


def qr_docx(path, payload: str):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/media/image1.png", qr_png(payload))
    return path


# ------------------------------------------------------------------ URL judgement
@pytest.mark.parametrize("url,suspicious", [
    (ORDINARY, False),
    ("https://example.org/login", False),                  # one weak reason is not enough
    ("http://198.51.100.9/pay", True),                     # bare IP
    ("https://bit.ly/3xYz", True),                         # shortener
    ("https://xn--pple-43d.com/", True),                   # punycode
    ("https://bank.example@evil.example/", True),          # user-info trick
    ("http://login.secure-update.xyz/verify", True),       # several weak reasons together
    ("javascript:alert(1)", True),
])
def test_url_assessment(url, suspicious):
    is_url, reasons = assess_url(url)
    assert is_url and bool(reasons) == suspicious


def test_non_url_payloads_are_not_links():
    for payload in ("WIFI:S:Office;T:WPA;P:x;;", "BEGIN:VCARD\nFN:A\nEND:VCARD", "hello"):
        assert assess_url(payload) == (False, [])
    assert assess_url("www.example.com/path")[0]


# ------------------------------------------------------------------ extraction
@needs_decoder
def test_codes_are_found_in_images_pdfs_and_office_files(tmp_path):
    s = QRScanner()
    png = tmp_path / "flyer.png"
    png.write_bytes(qr_png(SUSPICIOUS))
    for path in (png, qr_pdf(tmp_path / "flyer.pdf", SUSPICIOUS),
                 qr_docx(tmp_path / "flyer.docx", SUSPICIOUS)):
        res = s.analyze_file(path)
        assert res.images_checked == 1, path
        assert res.urls == [SUSPICIOUS] and res.suspicious, path


@needs_decoder
def test_limits_and_files_without_images(tmp_path):
    s = QRScanner(max_images=1)
    p = tmp_path / "many.docx"
    with zipfile.ZipFile(p, "w") as z:
        for i in range(3):
            z.writestr(f"word/media/image{i}.png", qr_png(f"https://example.com/{i}"))
    assert s.analyze_file(p).images_checked == 1
    plain = tmp_path / "plain.docx"
    with zipfile.ZipFile(plain, "w") as z:
        z.writestr("word/document.xml", "<w:document/>")
    assert s.analyze_file(plain).images_checked == 0
    junk = tmp_path / "broken.png"
    junk.write_bytes(b"\x89PNG not really")
    assert s.analyze_file(junk).codes == []


def test_without_a_decoder_the_layer_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(qr, "QR_AVAILABLE", False)
    png = tmp_path / "a.png"
    png.write_bytes(qr_png(ORDINARY))
    res = QRScanner().analyze_file(png)
    assert not res.available and res.codes == [] and "pyzbar" in res.detail


@pytest.mark.skipif(qr._pyzbar is None, reason="pyzbar not installed")
def test_opencv_fallback_decodes_too(tmp_path, monkeypatch):
    cv2 = pytest.importorskip("cv2")
    monkeypatch.setattr(qr, "_pyzbar", None)
    monkeypatch.setattr(qr, "_cv2", cv2)
    png = tmp_path / "a.png"
    png.write_bytes(qr_png(ORDINARY))
    assert QRScanner().analyze_file(png).urls == [ORDINARY]


# ------------------------------------------------------------------ scoring / scanner
def test_scoring():
    m = ScoringMatrix()
    sus = m.score({"qr": {"urls": ["hxxp://203.0.113[.]5/login"],
                          "suspicious": [{"url": "hxxp://203.0.113[.]5/login",
                                          "reasons": ["bare IP address instead of a domain"]}]}})
    assert [c.indicator for c in sus.contributions] == ["qr_code_suspicious_url"]
    assert sus.verdict == "Medium"
    plain = m.score({"qr": {"urls": ["https://www.example[.]com/menu"], "suspicious": []}})
    assert [c.indicator for c in plain.contributions] == ["qr_code_url"]
    assert plain.verdict == "Low"


@needs_decoder
def test_scanner_flags_a_quishing_attachment(scanner, tmp_path):
    p = tmp_path / "scan" / "parking.eml"
    p.parent.mkdir(exist_ok=True)
    make_eml(p, subject="Parking permit renewal",
             attachments=[("permit.png", qr_png(SUSPICIOUS), "image", "png")])
    r = scanner.scan_file(str(p))
    assert any(i.endswith("qr_code_suspicious_url") for i in _indicators(r))
    assert r["verdict"] in ("Medium", "High", "Critical")
    assert "http://203.0.113.5" not in scanner.generate_report([r])   # links are defanged


@needs_decoder
def test_report_shows_the_decoded_link_defanged(scanner, tmp_path):
    p = tmp_path / "scan" / "poster.png"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(qr_png(SUSPICIOUS))
    r = scanner.scan_file(str(p))
    assert r["scan_results"]["qr_codes"]["codes"][0]["payload"] == SUSPICIOUS
    report = scanner.generate_report([r])
    assert "[QR]        hxxp://203.0.113[.]5/login" in report
    assert "http://203.0.113.5" not in report


@needs_decoder
def test_documents_without_images_get_no_qr_entry(scanner, tmp_path):
    from tests.helpers import make_pdf
    p = tmp_path / "scan" / "letter.pdf"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(make_pdf("hello"))
    assert "qr_codes" not in scanner.scan_file(str(p))["scan_results"]
