"""Text and printable-string extraction used by the prompt-guard and LLM layers."""

import logging
import os
import re
from typing import List

import docx

try:  # pypdf is the maintained successor; PyPDF2 3.0.x has a known parser hang (CVE-2023-36464)
    from pypdf import PdfReader
except ImportError:  # pragma: no cover
    from PyPDF2 import PdfReader  # type: ignore[no-redef]
import pytesseract
from pdf2image import convert_from_path

from detectors import DEFUSEDXML_AVAILABLE
from detectors.web_content import WEB_EXTENSIONS, visible_text

logger = logging.getLogger("RansomwareScanner")

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{5,}")


_NON_PRINTABLE = re.compile(rb"[^\x20-\x7e]")


def _trailing_run_start(data: bytes) -> int:
    """Index where the trailing printable run of `data` starts. Searched from the
    end: the obvious `[\x20-\x7e]*$` regex is quadratic on long lines (a 120 KB
    minified script took 40 s)."""
    m = _NON_PRINTABLE.search(data[::-1])
    return len(data) - m.start() if m else 0


def extract_suspicious_strings(file_path: str, min_len: int = 5, chunk_size: int = 1024 * 1024,
                               max_bytes: int = 32 * 1024 * 1024,
                               max_chars: int = 200_000) -> str:
    """Extract human-readable ASCII strings from a file using memory-efficient chunked reads.

    Bounded on both input (max_bytes read) and output (max_chars returned), and
    regex-based so a large file no longer costs a Python-level loop per byte.
    """
    pattern = _PRINTABLE_RUN if min_len == 5 else re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    strings: List[str] = []
    total_chars = 0
    carry = b""
    read = 0
    try:
        with open(file_path, "rb") as f:
            while read < max_bytes and total_chars < max_chars:
                chunk = f.read(min(chunk_size, max_bytes - read))
                if not chunk:
                    break
                read += len(chunk)
                data = carry + chunk
                # Keep a trailing printable run for the next chunk so strings
                # that straddle a chunk boundary are not split.
                cut = _trailing_run_start(data)
                if len(data) - cut > 65536:     # one giant run (plain text): flush it
                    cut = len(data)
                carry, data = data[cut:], data[:cut]
                for m in pattern.finditer(data):
                    s = m.group().decode("ascii")
                    strings.append(s)
                    total_chars += len(s) + 1
                    if total_chars >= max_chars:
                        break
            if carry and len(carry) >= min_len and total_chars < max_chars:
                strings.append(carry.decode("ascii"))
    except Exception as e:
        logger.error("Error extracting strings from %s: %s", file_path, str(e))
    return "\n".join(strings)[:max_chars]


class TextExtractionMixin:
    """Visible-text extraction (PDF, Word, OOXML parts, OCR fallback)."""

    def _extract_text_from_file(self, file_path: str, allow_ocr: bool = True) -> str:
        """Extract readable text from a PDF or Office document ('' if none)."""
        file_ext = os.path.splitext(file_path)[1].lower()

        try:
            if file_ext in WEB_EXTENSIONS:
                with open(file_path, "rb") as fh:
                    return visible_text(fh.read(2 * 1024 * 1024))
            if file_ext == ".pdf":
                text = self._extract_text_from_pdf(file_path)
                if not text.strip() and allow_ocr:
                    logger.info("No text found in PDF. Using OCR fallback for %s", file_path)
                    text = self._extract_text_with_ocr_from_pdf(file_path)
                return text
            elif file_ext == ".docx":
                return self._extract_text_from_word(file_path) or \
                    self._extract_text_from_ooxml(file_path)
            elif file_ext in (".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                return self._extract_text_from_ooxml(file_path)
            else:
                return ""     # legacy binary formats: the strings pass covers them
        except Exception as e:
            logger.error("Error extracting text from %s: %s", file_path, str(e))
            return ""

    PDF_MAX_PAGES = 50
    PDF_MAX_CHARS = 200_000

    def _extract_text_from_pdf(self, file_path: str) -> str:
        """Extract text from a PDF file.

        Bounded like the OOXML path: the LLM reads the first 3,000 characters and
        the injection patterns the first 200,000, so long manuals stop early
        (page-by-page text extraction was half of all scan time)."""
        chunks: List[str] = []
        total = 0
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PdfReader(file, strict=False)
                for page in pdf_reader.pages[:self.PDF_MAX_PAGES]:
                    chunk = page.extract_text() or ""
                    chunks.append(chunk)
                    total += len(chunk) + 1
                    if total >= self.PDF_MAX_CHARS:
                        break
            return "\n".join(chunks)[:self.PDF_MAX_CHARS]
        except Exception as e:
            logger.warning("Could not extract PDF text from %s: %s", file_path, e)
            return ""

    def _extract_text_with_ocr_from_pdf(self, file_path: str) -> str:
        """Extract text from a PDF file using OCR if it is image-based."""
        try:
            images = convert_from_path(file_path, last_page=20)
            text = ""
            for img in images:
                text += pytesseract.image_to_string(img)
            return text
        except Exception as e:
            logger.error("OCR failed for PDF %s: %s", file_path, str(e))
            return ""

    def _extract_text_from_word(self, file_path: str) -> str:
        """Extract text from a Word document."""
        try:
            doc = docx.Document(file_path)
            return "\n".join([paragraph.text for paragraph in doc.paragraphs])
        except Exception as e:
            logger.debug("python-docx could not read %s: %s", file_path, e)
            return ""

    @staticmethod
    def _extract_text_from_ooxml(file_path: str, max_chars: int = 200_000) -> str:
        """Text from any OOXML file (Word/Excel/PowerPoint, incl. macro-enabled),
        read straight from the XML parts with defusedxml."""
        if not DEFUSEDXML_AVAILABLE:
            return ""
        import zipfile

        import defusedxml.ElementTree as DET
        part_re = re.compile(r"(word/(document|header\d*|footer\d*)\.xml"
                             r"|xl/sharedStrings\.xml|ppt/slides/slide\d+\.xml)$")
        chunks: List[str] = []
        total = 0
        try:
            with zipfile.ZipFile(file_path) as zf:
                for info in zf.infolist():
                    if not part_re.match(info.filename) or info.file_size > 20 * 1024 * 1024:
                        continue
                    root = DET.fromstring(zf.read(info))
                    for el in root.iter():
                        tag = str(el.tag)
                        if (tag.endswith("}t") or tag == "t") and el.text:
                            chunks.append(el.text)
                            total += len(el.text) + 1
                            if total > max_chars:
                                return " ".join(chunks)[:max_chars]
        except Exception as e:
            logger.debug("OOXML text extraction failed for %s: %s", file_path, e)
        return " ".join(chunks)

