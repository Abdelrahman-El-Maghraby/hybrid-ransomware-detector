"""Text and printable-string extraction used by the prompt-guard and LLM layers."""

import logging
import os
import re
from typing import List, Optional, Tuple

import docx

try:  # pypdf is the maintained successor; PyPDF2 3.0.x has a known parser hang (CVE-2023-36464)
    from pypdf import PdfReader
except ImportError:  # pragma: no cover
    from PyPDF2 import PdfReader  # type: ignore[no-redef]
try:  # OCR is optional (the "ocr" extra plus the tesseract and poppler programs)
    import pytesseract
    from pdf2image import convert_from_path
    OCR_AVAILABLE = True
except ImportError:
    pytesseract = convert_from_path = None  # type: ignore[assignment]
    OCR_AVAILABLE = False

from detectors import DEFUSEDXML_AVAILABLE
from detectors.web_content import MAX_READ as WEB_MAX_READ
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


STRINGS_MAX_BYTES = 32 * 1024 * 1024     # bytes of a file the strings pass reads
STRINGS_MAX_CHARS = 200_000              # characters of strings it returns
STRINGS_LOOKAHEAD_BYTES = 32 * 1024 * 1024   # TX-2b: unread bytes searched for one more string


def extract_suspicious_strings(file_path: str, min_len: int = 5, chunk_size: int = 1024 * 1024,
                               max_bytes: Optional[int] = None,
                               max_chars: Optional[int] = None,
                               omitted: Optional[List[str]] = None,
                               lookahead_bytes: Optional[int] = None) -> str:
    """Extract human-readable ASCII strings from a file using memory-efficient chunked reads.

    Bounded on both input (max_bytes read, STRINGS_MAX_BYTES by default) and output
    (max_chars returned, STRINGS_MAX_CHARS), and regex-based so a large file no
    longer costs a Python-level loop per byte.

    TX-2: `omitted` receives what a limit left unchecked: strings past max_chars,
    or a string in the bytes after max_bytes (looked for, not extracted). Reaching
    a limit exactly, or only white space or no printable run after it, is not an
    omission. The text returned is the same as before.

    TX-2b: that search reads at most `lookahead_bytes` (STRINGS_LOOKAHEAD_BYTES)
    after max_bytes, so the pass never reads more than max_bytes + lookahead_bytes
    (64 MiB by default). Bytes left after that, with no string found before them,
    are reported as not inspected (nothing is claimed about their content).
    Strings that cannot reach the returned text are not kept in memory.
    """
    max_bytes = STRINGS_MAX_BYTES if max_bytes is None else max_bytes
    max_chars = STRINGS_MAX_CHARS if max_chars is None else max_chars
    lookahead = STRINGS_LOOKAHEAD_BYTES if lookahead_bytes is None else lookahead_bytes
    pattern = _PRINTABLE_RUN if min_len == 5 else re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    strings: List[str] = []
    total_chars = 0
    kept: Optional[int] = None      # joined length the earlier stop rule returned
    length = -1                     # of the "\n"-joined strings so far
    over = False
    carry = b""
    last = b""                      # the final bytes read (a run cut at max_bytes)
    keep = max(min_len - 1, 0)
    read = 0

    def add(s: str) -> None:
        nonlocal total_chars, kept, length, over
        if kept is None:            # TX-2b: past it, a string only decides `over`
            strings.append(s)
            total_chars += len(s) + 1
            if total_chars >= max_chars:
                kept = total_chars - 1
        length, over = _past_limit(length, s, max_chars)

    try:
        with open(file_path, "rb") as f:
            while read < max_bytes and not over:
                chunk = f.read(min(chunk_size, max_bytes - read))
                if not chunk:
                    break
                read += len(chunk)
                joined = last + chunk[max(0, len(chunk) - keep):] if keep else b""   # not all of it
                last = joined[max(0, len(joined) - keep):]
                data = carry + chunk
                # Keep a trailing printable run for the next chunk so strings
                # that straddle a chunk boundary are not split.
                cut = _trailing_run_start(data)
                if len(data) - cut > 65536:     # one giant run (plain text): flush it
                    cut = len(data)
                carry, data = data[cut:], data[:cut]
                for m in pattern.finditer(data):
                    add(m.group().decode("ascii"))
                    if over:
                        break
            if carry and len(carry) >= min_len and not over:
                add(carry.decode("ascii"))
            if omitted is not None:
                if over:
                    omitted.append(f"strings after the first {max_chars:,} characters "
                                   "not checked")
                elif read >= max_bytes:
                    rest = _run_after(f, last, keep, pattern, chunk_size, lookahead)
                    if rest == _FOUND:
                        omitted.append(f"strings after the first {_size(max_bytes)} of the "
                                       "file not checked")
                    elif rest == _UNINSPECTED:
                        omitted.append(f"file bytes after the first {_size(max_bytes + lookahead)}"
                                       " not inspected for strings")
    except Exception as e:
        logger.error("Error extracting strings from %s: %s", file_path, str(e))
    return "\n".join(strings)[:max_chars if kept is None else min(max_chars, kept)]


_FOUND, _NONE, _UNINSPECTED = "found", "none", "uninspected"


def _run_after(fh, last: bytes, keep: int, pattern: "re.Pattern[bytes]",
               chunk_size: int, budget: int) -> str:
    """TX-2: whether the unread rest of `fh` holds a printable run with text other
    than white space (_FOUND) or not (_NONE). `last`, the final bytes read (at most
    `keep`, one fewer than a run), joins a run cut at the limit; its own bytes were
    read, so only the unread part of a run counts. Stops at the first such run.
    TX-2b: reads at most `budget` bytes; with bytes still left after them and no
    run found, the answer is _UNINSPECTED."""
    prev, start = last, len(last)
    left = budget
    while True:
        if left <= 0:
            # bytes left? from the size, so nothing past the budget is read
            return _UNINSPECTED if os.fstat(fh.fileno()).st_size > fh.tell() else _NONE
        chunk = fh.read(min(chunk_size, left))
        if not chunk:
            return _NONE
        left -= len(chunk)
        data = prev + chunk
        for m in pattern.finditer(data):
            if data[max(m.start(), start):m.end()].strip():
                return _FOUND
        at = max(0, len(data) - keep)
        prev, start = data[at:], max(0, start - at)    # read bytes stay excluded


def _size(n: int) -> str:
    return f"{n // (1024 * 1024)} MiB" if n % (1024 * 1024) == 0 else f"{n:,} bytes"


class TextExtractionMixin:
    """Visible-text extraction (PDF, Word, OOXML parts, OCR fallback).

    TX-1: each limit below reports, in `omitted`, text it actually left unread
    (engine/completeness.py makes that a partial scan). Reaching a limit exactly,
    with only white space after it, is not an omission. The text returned is
    the same as before (a PDF may gain one trailing page separator)."""

    TEXT_MAX_BYTES = 2 * 1024 * 1024      # web pages and SVG: bytes read for the text layers
    TEXT_CHECK_BYTES = WEB_MAX_READ       # read to here only to tell a cut from markup

    def _extract_text_from_file(self, file_path: str, allow_ocr: bool = True,
                                errors: Optional[List[str]] = None,
                                omitted: Optional[List[str]] = None) -> str:
        """Extract readable text from a PDF or Office document ('' if none).

        '' also comes back when the document could not be parsed; pass `errors` to
        tell the two apart - it receives why, when no text could be read because a
        parser failed (engine/completeness.py turns that into a partial scan).
        `omitted` receives what a limit left unread, whether or not text was read."""
        failures: List[str] = []
        cut: List[str] = []
        text = self._dispatch_text(file_path, allow_ocr, failures, cut)
        if errors is not None and failures and not text.strip():
            errors.extend(failures)
        if omitted is not None:
            omitted.extend(cut)
        return text

    def _dispatch_text(self, file_path: str, allow_ocr: bool, errors: List[str],
                       omitted: Optional[List[str]] = None) -> str:
        file_ext = os.path.splitext(file_path)[1].lower()
        cut: List[str] = omitted if omitted is not None else []

        try:
            if file_ext in WEB_EXTENSIONS:
                limit = self.TEXT_MAX_BYTES
                with open(file_path, "rb") as fh:
                    raw = fh.read(limit + 1)
                    if len(raw) > limit:      # read on, to the web layer's limit, to compare
                        raw += fh.read(max(0, self.TEXT_CHECK_BYTES - len(raw)) + 1)
                text = visible_text(raw[:limit])
                if len(raw) > limit and _page_text_cut(text, raw, self.TEXT_CHECK_BYTES):
                    cut.append(f"page text after the first {_size(limit)} not read")
                return text
            if file_ext == ".pdf":
                text = self._extract_text_from_pdf(file_path, errors, cut)
                if not text.strip() and allow_ocr:
                    logger.info("No text found in PDF. Using OCR fallback for %s", file_path)
                    text = self._extract_text_with_ocr_from_pdf(file_path, errors, cut)
                return text
            elif file_ext == ".docx":
                return self._extract_text_from_word(file_path, cut) or \
                    self._extract_text_from_ooxml(file_path, errors=errors, omitted=cut)
            elif file_ext in (".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                return self._extract_text_from_ooxml(file_path, errors=errors, omitted=cut)
            else:
                return ""     # legacy binary formats: the strings pass covers them
        except Exception as e:
            logger.error("Error extracting text from %s: %s", file_path, str(e))
            errors.append(f"text extraction failed ({type(e).__name__})")
            return ""

    PDF_MAX_PAGES = 50
    PDF_MAX_CHARS = 200_000

    def _extract_text_from_pdf(self, file_path: str, errors: Optional[List[str]] = None,
                               omitted: Optional[List[str]] = None) -> str:
        """Extract text from a PDF file.

        Bounded like the OOXML path: the LLM reads the first 3,000 characters and
        the injection patterns the first 200,000, so long manuals stop early
        (page-by-page text extraction was half of all scan time). TX-1: pages
        are read until the text is longer than the limit, so text cut off and
        pages left over are told apart from text that ends exactly at it."""
        chunks: List[str] = []
        length = -1                     # of the "\n"-joined text so far
        over = False
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PdfReader(file, strict=False)
                pages = pdf_reader.pages
                for page in pages[:self.PDF_MAX_PAGES]:
                    chunk = page.extract_text() or ""
                    chunks.append(chunk)
                    length, over = _past_limit(length, chunk, self.PDF_MAX_CHARS)
                    if over:
                        break
                if omitted is not None:
                    if over:
                        omitted.append(f"PDF text after the first {self.PDF_MAX_CHARS:,} "
                                       f"characters not read ({len(chunks)} page(s) read)")
                    elif len(pages) > self.PDF_MAX_PAGES:
                        omitted.append(f"PDF pages after the first {self.PDF_MAX_PAGES} not "
                                       f"read ({len(pages)} pages)")
            return "\n".join(chunks)[:self.PDF_MAX_CHARS]
        except Exception as e:
            logger.warning("Could not extract PDF text from %s: %s", file_path, e)
            if errors is not None:
                errors.append(f"PDF could not be parsed ({type(e).__name__}: {str(e)[:80]})")
            return ""

    OCR_TOTAL_SECONDS = 180.0      # L-E5: rendering plus every page of one PDF
    OCR_MIN_CALL_SECONDS = 1.0

    def _ocr_end(self) -> float:
        """When this PDF's OCR must end: OCR_TOTAL_SECONDS from now, and in an
        isolated worker no later than the scan limit less the M26 margin."""
        import time
        now = time.monotonic()
        end = now + self.OCR_TOTAL_SECONDS
        time_left = getattr(self, "time_left", None)
        left = time_left() if callable(time_left) else None
        if left is not None:
            limit = float((getattr(self, "config", None) or {}).get("scan_timeout_seconds", 300)
                          or 300)
            end = min(end, now + left - max(1.0, 0.1 * limit))
        return end

    OCR_MAX_PAGES = 20

    def _extract_text_with_ocr_from_pdf(self, file_path: str,
                                        errors: Optional[List[str]] = None,
                                        omitted: Optional[List[str]] = None) -> str:
        """Extract text from a PDF file using OCR if it is image-based. L-E5: the
        poppler and tesseract helpers get only the OCR time left (each library
        kills its helper at its timeout); a time-out or a failure is recorded in
        `errors`, which makes the scan partial, and the pages read are kept.
        TX-1: pages after OCR_MAX_PAGES, and pages a time limit left unread after
        others were read, are named in `omitted`."""
        import time
        if not OCR_AVAILABLE:
            return ""
        failures = errors if errors is not None else []
        cut = omitted if omitted is not None else []
        end = self._ocr_end()
        text = ""
        try:
            if end - time.monotonic() < self.OCR_MIN_CALL_SECONDS:
                failures.append("OCR not run: no time left in the scan limit")
                return ""
            images = convert_from_path(file_path, last_page=self.OCR_MAX_PAGES,
                                       timeout=max(1, int(end - time.monotonic())))
            for done, img in enumerate(images):
                left = end - time.monotonic()
                if left < self.OCR_MIN_CALL_SECONDS:
                    note = f"OCR stopped at its time limit: {done} of {len(images)} page(s) read"
                    failures.append(note)
                    if text.strip():      # with no text at all, `errors` reports it
                        cut.append(note)
                    break
                text += pytesseract.image_to_string(img, timeout=max(1, int(left)))
            if len(images) >= self.OCR_MAX_PAGES:
                pages = _pdf_page_count(file_path)
                if pages > self.OCR_MAX_PAGES:
                    cut.append(f"OCR pages after the first {self.OCR_MAX_PAGES} not read "
                               f"({pages} pages)")
            return text
        except Exception as e:
            logger.error("OCR failed for PDF %s: %s", file_path, str(e))
            failures.append(f"OCR failed ({type(e).__name__}: {str(e)[:80]})")
            return text

    OOXML_PART_MAX = 20 * 1024 * 1024     # as _extract_text_from_ooxml
    OOXML_MAX_CHARS = 200_000

    def _extract_text_from_word(self, file_path: str, omitted: Optional[List[str]] = None) -> str:
        """Extract text from a Word document. L-E4: within the same limits as the
        other Office formats: python-docx reads the whole main part, so a part
        declared over OOXML_PART_MAX is left to the bounded reader (which skips
        it), and the text is cut at OOXML_MAX_CHARS. zipfile reads no more than
        a part's declared size."""
        try:
            import zipfile
            with zipfile.ZipFile(file_path) as zf:
                if zf.getinfo("word/document.xml").file_size > self.OOXML_PART_MAX:
                    return ""
            doc = docx.Document(file_path)
            text = "\n".join([paragraph.text for paragraph in doc.paragraphs])
            if text[self.OOXML_MAX_CHARS:].strip() and omitted is not None:
                omitted.append(f"document text after the first {self.OOXML_MAX_CHARS:,} "
                               "characters not read")
            return text[:self.OOXML_MAX_CHARS]
        except Exception as e:
            logger.debug("python-docx could not read %s: %s", file_path, e)
            return ""

    @staticmethod
    def _extract_text_from_ooxml(file_path: str, max_chars: int = 200_000,
                                 errors: Optional[List[str]] = None,
                                 omitted: Optional[List[str]] = None) -> str:
        """Text from any OOXML file (Word/Excel/PowerPoint, incl. macro-enabled),
        read straight from the XML parts with defusedxml. Parts over 20 MiB are
        skipped here and named by the hidden-content check (prompt_guard)."""
        if not DEFUSEDXML_AVAILABLE:
            return ""
        import zipfile

        import defusedxml.ElementTree as DET
        part_re = re.compile(r"(word/(document|header\d*|footer\d*)\.xml"
                             r"|xl/sharedStrings\.xml|ppt/slides/slide\d+\.xml)$")
        chunks: List[str] = []
        length = -1                     # of the " "-joined text so far
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
                            length, over = _past_limit(length, el.text, max_chars)
                            if over:
                                if omitted is not None:
                                    omitted.append(f"document text after the first "
                                                   f"{max_chars:,} characters not read")
                                return " ".join(chunks)[:max_chars]
        except Exception as e:
            logger.debug("OOXML text extraction failed for %s: %s", file_path, e)
            if errors is not None:
                errors.append(f"Office document could not be parsed ({type(e).__name__})")
        return " ".join(chunks)[:max_chars]      # anything after the limit is white space


def _past_limit(length: int, chunk: str, limit: int) -> Tuple[int, bool]:
    """TX-1: the joined length after one more chunk (one separator before it),
    and whether text other than white space now lies past `limit`. Text that
    ends exactly at the limit, or only white space after it, is not cut off."""
    start = length + 1
    return start + len(chunk), bool(chunk[max(0, limit - start):].strip())


def _pdf_page_count(file_path: str) -> int:
    """Pages in a PDF (0 when it cannot be read)."""
    try:
        with open(file_path, "rb") as fh:
            return len(PdfReader(fh, strict=False).pages)
    except Exception:
        return 0


def _page_text_cut(text: str, raw: bytes, bound: int) -> bool:
    """TX-R1: whether the page read past the limit (`raw`, up to `bound` + 1 bytes)
    has visible text that `text`, from the bytes within the limit, lacks. Closing
    markup, a script or white space after the limit is not an omission (an
    unclosed tag left at the cut stays in `text` as a fragment, so the longer
    page's text is then its prefix). Past `bound` the rest is not compared: cut."""
    if len(raw) > bound:
        return True
    return not text.startswith(visible_text(raw))
