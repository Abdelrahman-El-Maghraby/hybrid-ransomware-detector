"""Pictures: a payload appended after the image data, an executable renamed to
.jpg, and SVG images that carry active content.

Every image is drawn with Pillow at test time; the appended "payloads" are a
ZIP built in memory and the inert PE header stub used across the suite.
"""

import io
import zipfile

import pytest

PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

import RansomwareScanner as RS  # noqa: E402
from detectors.file_integrity import (  # noqa: E402
    FileIntegrityAnalyzer,
    appended_payload_format,
    detect_format,
    image_end,
)
from detectors.web_content import WebContentAnalyzer  # noqa: E402
from tests.test_file_integrity import _pe_bytes  # noqa: E402
from tests.test_scanner_integration import _config  # noqa: E402

A = FileIntegrityAnalyzer()
W = WebContentAnalyzer()

FORMATS = {           # extension -> (Pillow format, detect_format name, save options)
    ".png": ("PNG", "png", {}),
    ".jpg": ("JPEG", "jpeg", {"quality": 85}),
    ".gif": ("GIF", "gif", {}),
    ".bmp": ("BMP", "bmp", {}),
    ".webp": ("WEBP", "webp", {"quality": 80}),
}


def _image(ext: str, size=(64, 48), **extra) -> bytes:
    pil_fmt, _, opts = FORMATS[ext]
    img = Image.new("RGB", size)
    for x in range(size[0]):                         # a gradient: real entropy-coded data
        for y in range(size[1]):
            img.putpixel((x, y), ((x * 4) % 256, (y * 5) % 256, (x * y) % 256))
    buf = io.BytesIO()
    img.save(buf, pil_fmt, **{**opts, **extra})
    return buf.getvalue()


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
    return buf.getvalue()


@pytest.fixture
def scanner(tmp_path):
    return RS.RansomwareScanner(_config(tmp_path))


# ------------------------------------------------------------ image_end
@pytest.mark.parametrize("ext", sorted(FORMATS))
def test_image_end_is_the_exact_length_of_a_clean_image(ext):
    data = _image(ext)
    fmt = FORMATS[ext][1]
    assert detect_format(data) == fmt
    assert image_end(data, fmt) == len(data)


def test_progressive_and_large_jpeg_are_parsed():
    for kw in ({"progressive": True}, {"optimize": True}):
        data = _image(".jpg", size=(640, 480), **kw)
        assert image_end(data, "jpeg") == len(data)


@pytest.mark.parametrize("ext", sorted(FORMATS))
def test_truncated_or_garbled_image_does_not_raise(ext):
    data = _image(ext)
    fmt = FORMATS[ext][1]
    for broken in (data[: len(data) // 2], data[:12] + b"\xff" * 40, data[:8]):
        end = image_end(broken, fmt)
        assert end is None or 0 < end <= len(broken)


# --------------------------------------------------- appended payloads
@pytest.mark.parametrize("ext", sorted(FORMATS))
@pytest.mark.parametrize("payload,expected", [("zip", "zip"), ("pe", "pe")])
def test_payload_appended_after_image_is_flagged(tmp_path, ext, payload, expected):
    blob = _zip_bytes() if payload == "zip" else _pe_bytes()
    p = tmp_path / f"photo{ext}"
    p.write_bytes(_image(ext) + blob)
    res = A.analyze_file(p)
    assert res.appended_payload == expected
    assert res.appended_bytes == len(blob)
    assert not res.disguised_executable           # the file really is an image


def test_payload_after_a_short_gap_is_still_found(tmp_path):
    p = tmp_path / "photo.png"
    p.write_bytes(_image(".png") + b"\x00" * 300 + _pe_bytes())
    assert A.analyze_file(p).appended_payload == "pe"


def test_metadata_after_image_is_noted_but_not_a_payload(tmp_path):
    p = tmp_path / "camera.jpg"
    p.write_bytes(_image(".jpg") + b"Exif-like trailer written by an editor\n" * 20)
    res = A.analyze_file(p)
    assert res.appended_bytes > 0
    assert res.appended_payload is None


def test_zero_padding_after_image_is_ignored(tmp_path):
    p = tmp_path / "padded.png"
    p.write_bytes(_image(".png") + b"\x00" * 4096)
    res = A.analyze_file(p)
    assert res.appended_bytes == 0 and res.appended_payload is None


@pytest.mark.parametrize("ext", sorted(FORMATS))
def test_clean_images_have_no_findings(tmp_path, ext):
    p = tmp_path / f"clean{ext}"
    p.write_bytes(_image(ext))
    res = A.analyze_file(p)
    assert not (res.appended_bytes or res.appended_payload or res.disguised_executable
                or res.format_mismatch)


def test_appended_payload_format_ignores_random_text():
    assert appended_payload_format(b"just some trailing words, nothing more " * 50) is None


# ------------------------------------------------ executable named .jpg
@pytest.mark.parametrize("ext", sorted(FORMATS))
def test_executable_renamed_to_an_image_is_disguised(tmp_path, ext):
    p = tmp_path / f"holiday{ext}"
    p.write_bytes(_pe_bytes())
    assert A.analyze_file(p).disguised_executable


# ------------------------------------------------- through the scanner
def test_image_with_appended_payload_scores_high(scanner, tmp_path):
    p = tmp_path / "scan" / "photo.png"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(_image(".png") + _pe_bytes())
    r = scanner.scan_file(str(p))
    indicators = {c["indicator"] for c in r["score_breakdown"]["contributions"]}
    assert "image_appended_payload" in indicators
    assert r["verdict"] in ("High", "Critical")


def test_clean_image_is_clean_and_skips_the_llm(scanner, tmp_path):
    p = tmp_path / "scan" / "clean.jpg"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(_image(".jpg"))
    r = scanner.scan_file(str(p))
    assert r["verdict"] == "Clean"
    assert "Image" in r["scan_results"]["chatgpt_analysis"]["details"]


# ----------------------------------------------------------------- SVG
CLEAN_SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
             b'<rect width="10" height="10" fill="#0a0"/><text x="1" y="8">ok</text></svg>')


@pytest.mark.parametrize("snippet,label", [
    (b'<svg xmlns="http://www.w3.org/2000/svg" onload="go()"></svg>',
     "event handler attribute"),
    (b'<svg xmlns="http://www.w3.org/2000/svg"><script>var a = 1;</script></svg>',
     "script element"),
    (b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="9" height="9">'
     b'<div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject></svg>',
     "foreignObject (embedded HTML)"),
    (b'<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:void(0)">x</a></svg>',
     "javascript: link"),
])
def test_active_svg_content_is_detected(tmp_path, snippet, label):
    p = tmp_path / "logo.svg"
    p.write_bytes(snippet)
    assert W.is_web(p)
    assert label in W.analyze(p).svg_active


def test_plain_svg_has_no_active_content(tmp_path):
    p = tmp_path / "logo.svg"
    p.write_bytes(CLEAN_SVG)
    assert W.analyze(p).svg_active == []


def test_active_svg_scores_through_the_scanner(scanner, tmp_path):
    p = tmp_path / "scan" / "badge.svg"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(b'<svg xmlns="http://www.w3.org/2000/svg"><script>var a = 1;</script></svg>')
    r = scanner.scan_file(str(p))
    indicators = {c["indicator"] for c in r["score_breakdown"]["contributions"]}
    assert "svg_active_content" in indicators
    assert r["verdict"] != "Clean"


def test_plain_svg_is_clean_through_the_scanner(scanner, tmp_path):
    p = tmp_path / "scan" / "logo.svg"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(CLEAN_SVG)
    assert scanner.scan_file(str(p))["verdict"] == "Clean"
