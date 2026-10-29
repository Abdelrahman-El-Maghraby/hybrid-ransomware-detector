"""
How much of a file was actually inspected: `scan_status` and `incomplete_reasons`.

    complete     every applicable, enabled layer ran
    unsupported  the format has no type-specific analysis here: only the generic
                 layers (hashes, YARA, integrity, ML, strings) looked at it
    partial      an applicable, enabled layer errored or was unavailable, or part of
                 the content was not unpacked (limits, a missing decompressor)
    locked       encrypted or password-protected content was not opened
    failed       the scan worker timed out, crashed or ran out of memory, or no
                 isolated worker could start, so the file was not scanned at all

A container takes the most severe status among itself and its members, in this
order (docs/RELEASE_SCOPE.md, criterion C1):

    failed > locked > partial > unsupported > complete

- failed first: nothing is known about the file, and a scanner that dies on a
  file may be under attack itself.
- locked next: the content is there but unread, and a password-protected
  payload is a deliberate delivery technique.
- partial: the content was read, but some evidence is missing.
- unsupported: everything this build can do ran; the format has no deeper analysis.

Intended skips do NOT make a scan partial: a slow layer skipped because the score
is already 100, or because the file is allowlisted; a layer that does not apply
to the file's type; an optional layer switched off by configuration (recorded in
provenance instead). The status never changes the score, the verdict or the
response action; it says how far the evidence goes.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from .capabilities import DOWN, layer_states

if TYPE_CHECKING:  # pragma: no cover
    from .layers import ScanContext
    from .scanner import RansomwareScanner

COMPLETE, UNSUPPORTED, PARTIAL, LOCKED, FAILED = (
    "complete", "unsupported", "partial", "locked", "failed")
PRECEDENCE = (COMPLETE, UNSUPPORTED, PARTIAL, LOCKED, FAILED)       # least -> most severe
RANK = {status: i for i, status in enumerate(PRECEDENCE)}
MAX_REASONS = 100

# Real formats (file_integrity.detect_format) with no type-specific analysis here.
# content the integrity layer recognises as an archive: it must have been opened
ARCHIVE_FORMATS = frozenset({"zip", "7z", "rar"})
UNSUPPORTED_FORMATS = frozenset({"unknown", "macho", "gzip", "bzip2", "xz", "zstd", "zlib",
                                 "cab", "lnk"})
_OOXML = frozenset({".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
                    ".xlam", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".ppam"})
# result key of each external / opt-in layer, for failures reported as data
_EXTERNAL_RESULTS = (("llm", "chatgpt_analysis"), ("virustotal", "virustotal"),
                     ("sandbox", "sandbox"), ("emulation", "emulation"))
_CONTAINER_RESULTS = ("archive", "mail", "web", "embedded")
# core layers that report "could not analyse" as data (an `error` field)
_ANALYSIS_RESULTS = (("yara", "yara"), ("macro", "macro_analysis"),
                     ("relationships", "relationships"))

Reason = Dict[str, str]


def reason(status: str, member: str, layer: str, text: str) -> Reason:
    return {"member_path": member, "layer": layer, "reason": text, "status": status}


def worst(statuses) -> str:
    return max(statuses, key=RANK.__getitem__, default=COMPLETE)


# ------------------------------------------------- does a down layer apply here?
def _ext(ctx: ScanContext) -> str:
    return Path(ctx.path).suffix.lower()


def _office_xml(scanner: RansomwareScanner, ctx: ScanContext) -> bool:
    return _ext(ctx) in _OOXML


APPLIES: Dict[str, Callable[[Any, Any], bool]] = {
    "fuzzy": lambda s, c: True,
    "yara": lambda s, c: True,
    "macro": lambda s, c: _ext(c) in s.macro_analyzer.SUPPORTED_EXTS,
    "prompt-guard": _office_xml,
    "relationships": _office_xml,
    "mail": lambda s, c: c.is_mail and _ext(c) == ".msg",
    "qr": lambda s, c: (s.qr_scanner is not None and not (c.is_archive or c.is_mail)
                        and s.qr_scanner.applies(c.path)),
    "embedded": lambda s, c: bool(c.embedded_kind) or _ext(c) in (".doc", ".xls", ".ppt"),
    "emulation": lambda s, c: s.emulator is not None and s.emulator.applies(c.path),
    # "archive" is judged from its own result (it knows which format needed what)
}


def _states(scanner: RansomwareScanner) -> Dict[str, Dict[str, Any]]:
    """Layer states, computed once when the scanner was built (they change only
    with a restart)."""
    states = getattr(scanner, "capability_states", None)
    return states if states is not None else layer_states(scanner)


# ------------------------------------------------------------- the sources
def _layer_gaps(scanner: RansomwareScanner, ctx: ScanContext, out: List[Reason]) -> None:
    sr = ctx.scan_results
    for layer, error in (sr.get("layer_errors") or {}).items():
        out.append(reason(PARTIAL, ctx.display, layer, f"layer error: {error}"))
    for layer, why in (sr.get("layer_skips") or {}).items():
        out.append(reason(PARTIAL, ctx.display, layer, f"layer skipped: {why}"))
    for name, st in _states(scanner).items():
        test = APPLIES.get(name)
        if st["state"] == DOWN and test is not None and test(scanner, ctx):
            out.append(reason(PARTIAL, ctx.display, name, f"layer unavailable ({st['detail']})"))
    for layer, key in _ANALYSIS_RESULTS:
        entry = sr.get(key)
        if isinstance(entry, dict) and entry.get("error"):
            out.append(reason(PARTIAL, ctx.display, layer, f"{layer} could not analyse the file: "
                                                          f"{entry['error']}"))
    for layer, key in _EXTERNAL_RESULTS:
        entry = sr.get(key)
        if not isinstance(entry, dict):
            continue
        if entry.get("error"):
            out.append(reason(PARTIAL, ctx.display, layer, f"{layer} failed: {entry['error']}"))
        elif entry.get("status") in ("error", "timeout"):
            out.append(reason(PARTIAL, ctx.display, layer,
                              f"{layer} {entry['status']}: {entry.get('detail', '')}".rstrip(": ")))


def _archive_gaps(sr: Dict, ctx: ScanContext, out: List[Reason]) -> None:
    arc = sr.get("archive")
    if not isinstance(arc, dict):
        return
    for lib in arc.get("missing_support") or []:
        out.append(reason(PARTIAL, ctx.display, "archive", f"needs {lib}"))
    for m in arc.get("members") or []:
        if m.get("extracted"):
            continue
        name = str(m.get("name") or ctx.display)
        if m.get("encrypted"):
            out.append(reason(LOCKED, name, "archive", "encrypted member not opened "
                              "(password unknown)"))
        elif m.get("skipped_reason"):
            out.append(reason(PARTIAL, name, "archive", f"not unpacked: {m['skipped_reason']}"))
    if arc.get("skipped_members"):
        out.append(reason(PARTIAL, ctx.display, "archive",
                          f"{arc['skipped_members']} member(s) over the member limit: names "
                          "checked, content not unpacked"))
    if arc.get("zip_bomb"):
        out.append(reason(PARTIAL, ctx.display, "archive",
                          "unpacking stopped at the size limits (zip bomb)"))
    # Members that were not extracted are listed above; anything else counted as
    # unreadable is an archive (or nested archive) that could not be opened at all.
    listed = sum(1 for m in arc.get("members") or [] if not m.get("extracted"))
    unopened = int(arc.get("unreadable_members") or 0) - listed
    if unopened > 0:
        out.append(reason(PARTIAL, ctx.display, "archive",
                          f"{unopened} archive(s) could not be opened (damaged, truncated, "
                          "or a later volume of a set): content not inspected"))


def _embedded_gaps(sr: Dict, ctx: ScanContext, out: List[Reason]) -> None:
    emb = sr.get("embedded")
    if not isinstance(emb, dict):
        return
    locked = bool(emb.get("encrypted") and not emb.get("decrypted"))
    if locked:
        out.append(reason(LOCKED, ctx.display, "embedded",
                          "password-protected document not decrypted"))
    for text in emb.get("skipped") or []:
        if locked and str(text).startswith("password-protected"):
            continue
        out.append(reason(PARTIAL, ctx.display, "embedded", f"not unpacked: {text}"))


def _budget_gaps(scanner: RansomwareScanner, sr: Dict, ctx: ScanContext,
                 out: List[Reason]) -> None:
    for key in _CONTAINER_RESULTS:
        box = sr.get(key)
        if not isinstance(box, dict):
            continue
        if box.get("not_scanned_budget"):
            out.append(reason(PARTIAL, ctx.display, key,
                              f"{box['not_scanned_budget']} member(s) over the scan budget: "
                              "listed, not scanned"))
        if (ctx.depth >= scanner.max_nesting and not box.get("deep_scanned")
                and (box.get("member_count") or box.get("attachment_count") or box.get("members"))):
            out.append(reason(PARTIAL, ctx.display, key,
                              f"nesting limit ({scanner.max_nesting}) reached: members listed, "
                              "not scanned"))
    fmt = str((sr.get("file_integrity") or {}).get("detected_format") or "")
    if (sr.get("text_extraction") or {}).get("error") and fmt in ("pdf", "zip"):
        # only when the content really is a PDF / OOXML: a program named .pdf fails
        # the PDF parser, but it is analysed as what it is
        out.append(reason(PARTIAL, ctx.display, "prompt-guard",
                          f"document text not read: {sr['text_extraction']['error']}"))
    if (sr.get("mail") or {}).get("error"):
        out.append(reason(PARTIAL, ctx.display, "mail",
                          f"message not analysed: {sr['mail']['error']}"))
    if (sr.get("mail") or {}).get("attachments_skipped"):
        out.append(reason(PARTIAL, ctx.display, "mail",
                          f"{sr['mail']['attachments_skipped']} attachment(s) not unpacked"))


def pdf_locked(path: str, data: Optional[bytes]) -> bool:
    """True for a PDF that needs a user password to read (an owner-only password,
    which every reader opens, does not count)."""
    head = data if data is not None else _head(path)
    if not head or b"%PDF-" not in head[:1024] or b"/Encrypt" not in head:
        return False
    try:
        from pypdf import PdfReader
        reader = PdfReader(path)
        return bool(reader.is_encrypted) and not reader.decrypt("")
    except Exception:          # unreadable or unsupported encryption: not opened either way
        return True


def _head(path: str, limit: int = 64 * 1024 * 1024) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def _office_package(ctx: ScanContext) -> bool:
    """An OOXML document is a ZIP the document layers read, not an archive to open."""
    if _ext(ctx) in _OOXML:
        return True
    try:
        import zipfile
        with zipfile.ZipFile(ctx.path) as z:
            return "[Content_Types].xml" in z.namelist()
    except Exception:          # damaged: not shown to be a document
        return False


def _format_gaps(ctx: ScanContext, out: List[Reason]) -> None:
    sr = ctx.scan_results
    fmt = str((sr.get("file_integrity") or {}).get("detected_format") or "")
    if fmt == "pdf" and pdf_locked(ctx.path, ctx.data()):
        out.append(reason(LOCKED, ctx.display, "prompt-guard",
                          "password-protected PDF: its text was not read"))
    opened = any(isinstance(sr.get(k), dict) for k in _CONTAINER_RESULTS)
    if fmt in ARCHIVE_FORMATS and not opened and not _office_package(ctx):
        out.append(reason(PARTIAL, ctx.display, "archive",
                          f"{fmt} content was not opened (damaged, truncated, or not a "
                          "supported container): members not inspected"))
    if fmt in UNSUPPORTED_FORMATS and not opened:
        out.append(reason(UNSUPPORTED, ctx.display, "integrity",
                          f"no type-specific analysis for {fmt} content; only the generic "
                          "layers ran"))


# ------------------------------------------------------------------ public
def assess(scanner: RansomwareScanner, ctx: ScanContext) -> Tuple[str, List[Reason]]:
    """(scan_status, incomplete_reasons) for one scanned file, members included."""
    out: List[Reason] = []
    _layer_gaps(scanner, ctx, out)
    _archive_gaps(ctx.scan_results, ctx, out)
    _embedded_gaps(ctx.scan_results, ctx, out)
    _budget_gaps(scanner, ctx.scan_results, ctx, out)
    _format_gaps(ctx, out)
    out.extend(ctx.member_reasons)
    status = worst(r["status"] for r in out)
    if len(out) > MAX_REASONS:
        extra = len(out) - MAX_REASONS + 1
        out = out[:MAX_REASONS - 1] + [reason(PARTIAL if status == COMPLETE else status,
                                              ctx.display, "report",
                                              f"{extra} more reason(s) not listed")]
    return status, out


def failed(path: str, why: str, layer: str = "worker") -> Tuple[str, List[Reason]]:
    """Status for a file whose worker timed out, crashed or hit the memory limit
    (layer "worker"), or that no isolated worker could take (layer "isolation")."""
    return FAILED, [reason(FAILED, path, layer, why)]


def verdict_label(result: Dict) -> str:
    """The verdict as people should read it: a scan that is not complete never
    reads as plain "Clean" (or plain anything)."""
    verdict = str(result.get("verdict") or "Clean")
    status = str(result.get("scan_status") or COMPLETE)
    return verdict if status == COMPLETE else f"{verdict} ({status} scan)"
