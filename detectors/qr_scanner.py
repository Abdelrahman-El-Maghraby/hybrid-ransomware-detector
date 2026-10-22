"""
QR codes in images, PDFs and Office documents ("quishing").

Phishing mail increasingly hides its link in a QR code: the text filters never see
a URL, and the victim opens it on a phone, outside the company's protection. This
module finds the images in a file, decodes any QR codes in them, and judges the
links they carry.

Where images come from
  * an image file itself (.png, .jpg, .gif, .bmp, .webp), including images that
    arrive as e-mail attachments or archive members;
  * the media folder of an Office Open XML document (word/media, xl/media, ppt/media);
  * the image objects on the first pages of a PDF.

Decoders (optional, the first one found is used)
  * pyzbar - `pip install pyzbar`. On Windows the wheel includes the zbar library;
    on Linux install `libzbar0`, on macOS `brew install zbar`.
  * OpenCV - `pip install opencv-python-headless` (its built-in QR detector).
With neither installed the layer reports that QR codes were not checked; nothing
else in the scan changes.

Every step is bounded: number of images, bytes per image, and pixels per image
(decompression bombs are refused before decoding).
"""

from __future__ import annotations

import io
import ipaddress
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, List, Tuple, Union
from urllib.parse import urlsplit

logger = logging.getLogger("RansomwareScanner")

PathLike = Union[str, Path]

try:
    from PIL import Image  # type: ignore
    PIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    Image = None
    PIL_AVAILABLE = False

_pyzbar = None
_cv2 = None
try:
    from pyzbar import pyzbar as _pyzbar  # type: ignore
    from pyzbar.pyzbar import ZBarSymbol as _ZBarSymbol  # type: ignore
except Exception:  # ImportError, or the zbar shared library is missing
    _pyzbar = None
if _pyzbar is None:
    try:
        import cv2 as _cv2  # type: ignore
    except Exception:
        _cv2 = None

QR_BACKEND = "pyzbar" if _pyzbar is not None else ("opencv" if _cv2 is not None else "")
QR_AVAILABLE = PIL_AVAILABLE and bool(QR_BACKEND)
QR_INSTALL_HINT = "pip install pyzbar (plus the zbar library) or opencv-python-headless"

IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"})
OOXML_EXTENSIONS = frozenset({".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx",
                              ".xltm", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"})
_OOXML_MEDIA = ("word/media/", "xl/media/", "ppt/media/")

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly",
    "s.id", "rb.gy", "shorturl.at", "tiny.cc", "buff.ly", "t.ly", "qrco.de", "qr.codes",
    "bl.ink", "short.io", "lnkd.in", "v.gd",
})
RISKY_TLDS = frozenset({"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml",
                        "cf", "ga", "work", "rest", "cam", "icu", "sbs"})
LURE_WORDS = ("login", "signin", "sign-in", "verify", "account", "password", "secure",
              "update", "wallet", "invoice", "payment", "mfa", "2fa", "auth")


@dataclass
class QRCode:
    payload: str
    source: str                       # which image it came from
    is_url: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {"payload": self.payload[:300], "source": self.source, "is_url": self.is_url,
                "suspicious_reasons": self.suspicious_reasons}


@dataclass
class QRResult:
    available: bool = QR_AVAILABLE
    backend: str = QR_BACKEND
    images_checked: int = 0
    codes: List[QRCode] = field(default_factory=list)
    detail: str = ""

    @property
    def urls(self) -> List[str]:
        return [c.payload for c in self.codes if c.is_url]

    @property
    def suspicious(self) -> List[QRCode]:
        return [c for c in self.codes if c.suspicious_reasons]

    def as_dict(self) -> Dict:
        return {"available": self.available, "backend": self.backend or "none",
                "images_checked": self.images_checked,
                "codes": [c.as_dict() for c in self.codes], "detail": self.detail}


def assess_url(url: str) -> Tuple[bool, List[str]]:
    """(is_url, reasons) for a decoded payload. Reasons are empty for an ordinary link.

    Strong reasons make a link suspicious on their own (an IP address or user name in
    the host, punycode, a script/data scheme, a URL shortener). Weak ones (plain
    http, a lure word in the address, a throw-away TLD, a deep subdomain chain) count
    only when two of them occur together.
    """
    text = url.strip()
    low = text.lower()
    if low.startswith(("javascript:", "data:", "vbscript:")):
        return True, [f"{low.split(':', 1)[0]}: scheme"]
    if not low.startswith(("http://", "https://")):
        if low.startswith("www.") and " " not in low:
            text, low = "http://" + text, "http://" + low
        else:
            return False, []
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower()
    except ValueError:
        return True, ["malformed URL"]
    if not host:
        return True, ["URL without a host"]
    strong: List[str] = []
    weak: List[str] = []
    if "@" in (parts.netloc or ""):
        strong.append("user name in the address (the real host comes after '@')")
    try:
        ipaddress.ip_address(host.strip("[]"))
        strong.append("bare IP address instead of a domain")
    except ValueError:
        pass
    if "xn--" in host:
        strong.append("punycode host (look-alike characters)")
    if host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS):
        strong.append(f"URL shortener ({host}) hides the destination")
    if parts.scheme == "http":
        weak.append("not HTTPS")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        weak.append(f"throw-away top-level domain .{tld}")
    if host.count(".") >= 4:
        weak.append("long subdomain chain")
    path = (parts.path or "") + "?" + (parts.query or "")
    words = sorted({w for w in LURE_WORDS if w in host or w in path.lower()})
    if words:
        weak.append("lure words in the address: " + ", ".join(words[:3]))
    return True, strong + (weak if len(weak) >= 2 else [])


class QRScanner:
    def __init__(self, max_images: int = 20, max_image_bytes: int = 8 * 1024 * 1024,
                 max_pixels: int = 25_000_000, max_pdf_pages: int = 10):
        self.max_images = max_images
        self.max_image_bytes = max_image_bytes
        self.max_pixels = max_pixels
        self.max_pdf_pages = max_pdf_pages

    @staticmethod
    def applies(path: PathLike) -> bool:
        ext = Path(path).suffix.lower()
        return ext in IMAGE_EXTENSIONS or ext in OOXML_EXTENSIONS or ext == ".pdf"

    def analyze_file(self, path: PathLike) -> QRResult:
        res = QRResult(available=QR_AVAILABLE, backend=QR_BACKEND)
        if not QR_AVAILABLE:
            res.detail = f"QR codes not checked: no decoder installed ({QR_INSTALL_HINT})."
            return res
        try:
            images = self._collect(Path(path))
        except Exception as e:                       # hostile container: not checked
            logger.debug("QR image collection failed for %s: %s", path, e)
            images = []
        seen = set()
        for source, data in images:
            res.images_checked += 1
            for payload in self._decode(data):
                if payload in seen:
                    continue
                seen.add(payload)
                is_url, reasons = assess_url(payload)
                res.codes.append(QRCode(payload, source, is_url, reasons))
        if res.codes:
            n_sus = len(res.suspicious)
            res.detail = (f"{len(res.codes)} QR code(s) in {res.images_checked} image(s); "
                          f"{len(res.urls)} link(s), {n_sus} suspicious.")
        else:
            res.detail = f"No QR codes in {res.images_checked} image(s)."
        return res

    # ------------------------------------------------------------- collection
    def _collect(self, path: Path) -> List[Tuple[str, bytes]]:
        ext = path.suffix.lower()
        if ext in IMAGE_EXTENSIONS:
            if path.stat().st_size <= self.max_image_bytes:
                return [(path.name, path.read_bytes())]
            return []
        if ext in OOXML_EXTENSIONS:
            return self._ooxml_images(path)
        if ext == ".pdf":
            return self._pdf_images(path)
        return []

    def _ooxml_images(self, path: Path) -> List[Tuple[str, bytes]]:
        out: List[Tuple[str, bytes]] = []
        if not zipfile.is_zipfile(path):
            return out
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if len(out) >= self.max_images:
                    break
                name = info.filename
                if (name.startswith(_OOXML_MEDIA)
                        and PurePosixPath(name).suffix.lower() in IMAGE_EXTENSIONS
                        and 0 < info.file_size <= self.max_image_bytes):
                    out.append((name, z.read(info)))
        return out

    def _pdf_images(self, path: Path) -> List[Tuple[str, bytes]]:
        out: List[Tuple[str, bytes]] = []
        try:
            from pypdf import PdfReader  # type: ignore
        except ImportError:
            try:
                from PyPDF2 import PdfReader  # type: ignore
            except ImportError:
                return out
        reader = PdfReader(str(path), strict=False)
        for pno, page in enumerate(reader.pages[: self.max_pdf_pages], 1):
            try:
                images = list(page.images)
            except Exception as e:
                logger.debug("PDF page %d images unreadable: %s", pno, e)
                continue
            for img in images:
                if len(out) >= self.max_images:
                    return out
                data = getattr(img, "data", b"") or b""
                if 0 < len(data) <= self.max_image_bytes:
                    out.append((f"page {pno}: {getattr(img, 'name', 'image')}", data))
        return out

    # ---------------------------------------------------------------- decoding
    def _decode(self, data: bytes) -> List[str]:
        try:
            img = Image.open(io.BytesIO(data))
            w, h = img.size
            if w * h > self.max_pixels or w < 21 or h < 21:   # bomb, or too small for a QR
                return []
            img = img.convert("L")
        except Exception:
            return []
        out: List[str] = []
        try:
            if _pyzbar is not None:
                for sym in _pyzbar.decode(img, symbols=[_ZBarSymbol.QRCODE]):
                    out.append(sym.data.decode("utf-8", "replace"))
            elif _cv2 is not None:
                import numpy as np  # OpenCV always ships with numpy
                ok, texts, _pts, _ = _cv2.QRCodeDetector().detectAndDecodeMulti(np.array(img))
                if ok:
                    out.extend(t for t in texts if t)
        except Exception as e:
            logger.debug("QR decode failed: %s", e)
        return out
