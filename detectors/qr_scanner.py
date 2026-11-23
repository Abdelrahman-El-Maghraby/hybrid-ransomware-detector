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
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

logger = logging.getLogger("RansomwareScanner")

PathLike = Union[str, Path]

try:
    from PIL import Image  # type: ignore
    PIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    Image = None  # type: ignore[assignment]
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
    # L-D5: images or pages over a limit that were not decoded, and an error that
    # stopped the image collection; either makes the scan partial
    not_checked: str = ""
    error: str = ""

    @property
    def urls(self) -> List[str]:
        return [c.payload for c in self.codes if c.is_url]

    @property
    def suspicious(self) -> List[QRCode]:
        return [c for c in self.codes if c.suspicious_reasons]

    def as_dict(self) -> Dict:
        return {"available": self.available, "backend": self.backend or "none",
                "images_checked": self.images_checked,
                "codes": [c.as_dict() for c in self.codes], "detail": self.detail,
                **({"not_checked": self.not_checked} if self.not_checked else {}),
                **({"error": self.error} if self.error else {})}


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
        notes: List[str] = []
        try:
            images = self._collect(Path(path), notes)
        except Exception as e:                       # hostile container: not checked
            logger.debug("QR image collection failed for %s: %s", path, e)
            res.error = f"images could not be read ({type(e).__name__})"
            images = []
        seen = set()
        too_big = 0
        for source, data in images:
            res.images_checked += 1
            payloads = self._decode(data)
            if payloads is None:
                too_big += 1
                continue
            for payload in payloads:
                if payload in seen:
                    continue
                seen.add(payload)
                is_url, reasons = assess_url(payload)
                res.codes.append(QRCode(payload, source, is_url, reasons))
        if too_big:
            notes.append(f"{too_big} image(s) over {self.max_pixels} pixels not decoded")
        res.not_checked = "; ".join(notes)[:500]
        if res.codes:
            n_sus = len(res.suspicious)
            res.detail = (f"{len(res.codes)} QR code(s) in {res.images_checked} image(s); "
                          f"{len(res.urls)} link(s), {n_sus} suspicious.")
        else:
            res.detail = f"No QR codes in {res.images_checked} image(s)."
        return res

    # ------------------------------------------------------------- collection
    def _collect(self, path: Path, notes: List[str]) -> List[Tuple[str, bytes]]:
        """The images to decode; what a limit leaves out is added to `notes` (L-D5)."""
        ext = path.suffix.lower()
        if ext in IMAGE_EXTENSIONS:
            if path.stat().st_size <= self.max_image_bytes:
                return [(path.name, path.read_bytes())]
            notes.append(self._over_size(1))
            return []
        if ext in OOXML_EXTENSIONS:
            return self._ooxml_images(path, notes)
        if ext == ".pdf":
            return self._pdf_images(path, notes)
        return []

    def _over_size(self, n: int) -> str:
        mib = 1024 * 1024
        limit = (f"{self.max_image_bytes // mib} MiB" if self.max_image_bytes % mib == 0
                 else f"{self.max_image_bytes}-byte")
        return f"{n} image(s) over the {limit} limit not decoded"

    def _ooxml_images(self, path: Path, notes: List[str]) -> List[Tuple[str, bytes]]:
        out: List[Tuple[str, bytes]] = []
        if not zipfile.is_zipfile(path):
            return out
        big = over = 0
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                name = info.filename
                if not (name.startswith(_OOXML_MEDIA)
                        and PurePosixPath(name).suffix.lower() in IMAGE_EXTENSIONS
                        and info.file_size > 0):
                    continue
                if info.file_size > self.max_image_bytes:
                    big += 1
                elif len(out) >= self.max_images:
                    over += 1
                else:
                    out.append((name, z.read(info)))
        if big:
            notes.append(self._over_size(big))
        if over:
            notes.append(f"{over} image(s) over the {self.max_images}-image limit not decoded")
        return out

    def _pdf_images(self, path: Path, notes: List[str]) -> List[Tuple[str, bytes]]:
        out: List[Tuple[str, bytes]] = []
        try:
            from pypdf import PdfReader  # type: ignore
        except ImportError:
            try:
                from PyPDF2 import PdfReader  # type: ignore
            except ImportError:
                return out
        with open(path, "rb") as fh:            # A2: a program merely named .pdf is not
            if b"%PDF" not in fh.read(1024):     # a PDF the layer failed to read
                return out
        reader = PdfReader(str(path), strict=False)
        total = len(reader.pages)
        if total > self.max_pdf_pages:
            notes.append(f"pages {self.max_pdf_pages + 1}-{total} not checked "
                         f"(limit {self.max_pdf_pages})")
        big, unreadable = 0, []
        for pno, page in enumerate(reader.pages[: self.max_pdf_pages], 1):
            try:
                images = list(page.images)
            except Exception as e:
                logger.debug("PDF page %d images unreadable: %s", pno, e)
                unreadable.append(str(pno))
                continue
            for img in images:
                if len(out) >= self.max_images:
                    notes.append(f"image limit ({self.max_images}) reached on page {pno}: "
                                 "later images not decoded")
                    break
                data = getattr(img, "data", b"") or b""
                if len(data) > self.max_image_bytes:
                    big += 1
                elif data:
                    out.append((f"page {pno}: {getattr(img, 'name', 'image')}", data))
            else:
                continue
            break
        if big:
            notes.append(self._over_size(big))
        if unreadable:
            notes.append(f"images of page(s) {', '.join(unreadable[:5])} unreadable")
        return out

    # ---------------------------------------------------------------- decoding
    def _decode(self, data: bytes) -> Optional[List[str]]:
        """Decoded payloads; None for an image over the pixel limit (L-D5: named)."""
        try:
            opened = Image.open(io.BytesIO(data))
            w, h = opened.size
            if w * h > self.max_pixels:              # a decompression bomb: not decoded
                return None
            if w < 21 or h < 21:                     # too small to hold a QR code
                return []
            img = opened.convert("L")
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
