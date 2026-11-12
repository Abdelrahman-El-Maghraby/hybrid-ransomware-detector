"""
Web content attachments: HTML smuggling, active SVG and phishing pages.

WHY THIS EXISTS
---------------
Attaching an executable to an e-mail no longer works: gateways strip it. So
attackers attach a web page instead. **HTML smuggling** (MITRE ATT&CK
T1027.006) hides the payload inside the page as a base64 string; when the
victim opens the file, JavaScript decodes it, wraps it in a `Blob` and makes
the browser "download" it locally (`URL.createObjectURL` + an `<a download>`
click, or `msSaveOrOpenBlob`). The mail gateway only ever saw text. Qakbot,
IcedID, Nobelium and many ransomware affiliates delivered ZIP/ISO payloads this
way. **SVG** images can carry the same JavaScript, or simply redirect to a
credential-phishing site, and look like a harmless picture attachment.

WHAT IS CHECKED (statically - nothing is executed or fetched)
-------------------------------------------------------------
* Embedded payloads: base64 strings and `data:` URIs are decoded and their real
  format identified by magic bytes. Executables, scripts, shortcuts, archives,
  disc images and OLE documents are written to a sandbox and scanned through the
  full pipeline like any attachment. Inline images and fonts are ignored.
* The smuggling construct: Blob creation + a download trigger (object URL with
  a `download` attribute or click, `msSaveOrOpenBlob`), alone or together with
  `atob()`. Construct + payload = confirmed smuggling.
* Active SVG: `<script>`, `on*=` event handlers, `<foreignObject>`,
  `javascript:` links, embedded frames.
* Redirects to an external URL (meta refresh, `location` assignment).
* Credential forms: a password field whose data goes to an external URL, or
  exfiltration endpoints phishing kits favour (Telegram bot API, Discord
  webhooks).
* JavaScript obfuscation markers (eval, unescape, long fromCharCode/hex runs).

Limits: payloads built from XOR/char-code arithmetic are not reconstructed
(the obfuscation markers still count), and scripts are not run.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import logging
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, Union

from .file_integrity import detect_format
from .mail_analyzer import _strip_script_style, _strip_tags  # H2: the same patterns, linear

logger = logging.getLogger("RansomwareScanner.web")

PathLike = Union[str, Path]

HTML_EXTENSIONS = frozenset({".html", ".htm", ".shtml", ".xhtml", ".hta"})
SVG_EXTENSIONS = frozenset({".svg"})
WEB_EXTENSIONS = HTML_EXTENSIONS | SVG_EXTENSIONS

MAX_READ = 20 * 1024 * 1024          # bytes of the page that are analysed
MIN_PAYLOAD_B64 = 256                # shorter base64 strings are not payload candidates
MAX_PAYLOADS = 5
MAX_PAYLOAD_BYTES = 60 * 1024 * 1024

# Decoded formats that make an embedded blob a payload, and the file extension
# the sandbox copy gets so the rest of the pipeline treats it correctly.
PAYLOAD_EXTENSIONS = {"pe": ".exe", "elf": ".elf", "macho": ".macho", "lnk": ".lnk",
                      "script": ".sh", "zip": ".zip", "7z": ".7z", "rar": ".rar",
                      "cab": ".cab", "ole": ".doc", "iso": ".iso", "gzip": ".gz"}
EXECUTABLE_PAYLOADS = frozenset({"pe", "elf", "macho", "lnk", "script"})

_DATA_URI = re.compile(rb"data:([a-z0-9.+/-]*)((?:;[a-z0-9=._-]+)*);base64,([a-z0-9+/=\s\\]+)", re.I)
_B64_LITERAL = re.compile(rb"""["'`]([A-Za-z0-9+/\s\\]{%d,}={0,2})["'`]""" % MIN_PAYLOAD_B64)
# H-04+: was ["']\s*\+\s*(?:\r?\n\s*)?["']; \s already takes the line break,
# and the extra group made a long run of white space quadratic.
_JS_CONCAT = re.compile(rb"""["']\s*\+\s*["']""")

# H-04+ (owner-approved 2026-11-12). The tag checks below used single patterns
# such as <a\b[^>]*\bdownload\b. Many tag starts before one '>' (or none) made
# each start scan to that '>': quadratic, and cubic for the meta refresh and the
# data: download link (2 MB pages are read). A match cannot cross a '>', and a
# later start before the same '>' sees a suffix of the first one's text, so it
# can only match where the first one does. The helpers check the first start
# per tag only and give the same results. tests/test_web_content_linear.py
# keeps the old patterns as the reference.
_SMUGGLE_BLOB = re.compile(r"new\s+blob\s*\(|\bblob\s*\(\s*\[", re.I)
_SMUGGLE_URL = re.compile(r"createobjecturl\s*\(", re.I)
_SMUGGLE_SAVE = re.compile(r"mssaveoropenblob|mssaveblob", re.I)
_SMUGGLE_DOWNLOAD = re.compile(r"\.download\s*=|setattribute\s*\(\s*['\"]download['\"]", re.I)
_SMUGGLE_CLICK = re.compile(r"\.click\s*\(\s*\)|dispatchevent\s*\(", re.I)
_ATOB = re.compile(r"\batob\s*\(", re.I)

_A_OPEN = re.compile(r"<a\b", re.I)
_ELEMENT_OPEN = re.compile(r"<[a-z]", re.I)
_INPUT_OPEN = re.compile(r"<input", re.I)
_FORM_OPEN = re.compile(r"<form", re.I)
_META_OPEN = re.compile(r"<meta", re.I)
_DOWNLOAD_WORD = re.compile(r"\bdownload\b", re.I)
_DATA_HREF = re.compile(r"href\s*=\s*(?:['\"]\s*)?data:", re.I)       # \s*['"]?\s* before
_EVENT_HANDLER = re.compile(r"\son[a-z]{3,}\s*=", re.I)
_PASSWORD_TYPE = re.compile(r"type\s*=\s*['\"]?password", re.I)
_ACTION_WORD = re.compile(r"action", re.I)
_ACTION_URL = re.compile(r"action\s*=\s*['\"]?(https?://[^\s'\">]+)", re.I)
_REFRESH = re.compile(r"http-equiv\s*=\s*['\"]?refresh", re.I)
_URL_WORD = re.compile(r"url", re.I)
_REFRESH_URL = re.compile(r"url\s*=\s*(?:['\"]\s*)?(https?://[^\s'\">]+)", re.I)

_SVG_SCRIPT = re.compile(r"<script\b", re.I)
_SVG_FOREIGN = re.compile(r"<foreignobject\b", re.I)
_SVG_JS_LINK = re.compile(r"javascript\s*:", re.I)
_SVG_FRAME = re.compile(r"<(?:iframe|embed|object)\b", re.I)
_REDIRECTS = (          # the meta refresh is _meta_refresh_urls
    re.compile(r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*['\"](https?://[^'\"]+)", re.I),
    re.compile(r"location\.(?:replace|assign)\s*\(\s*['\"](https?://[^'\"]+)", re.I),
)
_EXFIL = re.compile(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|"
                    r"hooks\.slack\.com/services|formsubmit\.co|ngrok(?:-free)?\.(?:io|app)", re.I)
_OBFUSCATION = (
    ("eval()", re.compile(r"\beval\s*\(", re.I)),
    ("unescape()", re.compile(r"\bunescape\s*\(", re.I)),
    ("long String.fromCharCode", re.compile(r"fromcharcode\s*\((?:\s*\d+\s*,){40,}", re.I)),
    ("long hex/unicode escape run", re.compile(r"(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){200,}", re.I)),
    ("document.write of decoded data", re.compile(r"document\.write\s*\(\s*(?:unescape|atob|decodeuri)", re.I)),
)


def _tags(text: str, opener: re.Pattern[str], skip: int = 0) -> Iterator[Tuple[int, int]]:
    """(start, end) of the text after the first `opener` before each '>' (or
    the end); `skip` = 1 for a pattern that needs [^>]+ after the opener."""
    done = -1
    for m in opener.finditer(text):
        if m.start() < done:
            continue
        end = text.find(">", m.end())
        done = end = len(text) if end < 0 else end
        yield m.end() + skip, end


def _in_tags(text: str, opener: re.Pattern[str], inner: re.Pattern[str], skip: int = 0) -> bool:
    """opener[^>]*inner (skip=0) or opener[^>]+inner (skip=1), for an inner
    pattern that cannot match a '>'."""
    return any(inner.search(text, s, e) for s, e in _tags(text, opener, skip))


def _download_anchor(text: str) -> bool:
    r"""<a\b[^>]*\bdownload\b"""
    return _in_tags(text, _A_OPEN, _DOWNLOAD_WORD)


def _data_download_anchor(text: str) -> bool:
    r"""<a\b[^>]*(?:\bdownload\b[^>]*HREF|HREF[^>]*\bdownload\b), HREF being
    href\s*=\s*['"]?\s*data: . The two parts cannot overlap, so one tag that
    has both has them in one of the two orders."""
    return any(_DOWNLOAD_WORD.search(text, s, e) and _DATA_HREF.search(text, s, e)
               for s, e in _tags(text, _A_OPEN))


def _event_handler(text: str) -> bool:
    r"""<[a-z][^>]*\son[a-z]{3,}\s*="""
    return _in_tags(text, _ELEMENT_OPEN, _EVENT_HANDLER)


def _password_field(text: str) -> bool:
    r"""<input[^>]+type\s*=\s*['"]?password"""
    return _in_tags(text, _INPUT_OPEN, _PASSWORD_TYPE, skip=1)


def _last_match(text: str, word: re.Pattern[str], full: re.Pattern[str],
                s: int, e: int) -> Optional[re.Match[str]]:
    """The match of `full` that starts at the last `word` in s..e where it
    matches: what a greedy [^>]+ before it picks. A failed try stops within
    the white space after its own word."""
    for start in reversed([m.start() for m in word.finditer(text, s, e)]):
        m = full.match(text, start)
        if m:
            return m
    return None


def _form_action(text: str) -> Optional[str]:
    r"""findall(<form[^>]+action\s*=\s*['"]?(https?://[^\s'">]+))[0]"""
    for s, e in _tags(text, _FORM_OPEN, skip=1):
        m = _last_match(text, _ACTION_WORD, _ACTION_URL, s, e)
        if m:
            return m.group(1)
    return None


def _meta_refresh_urls(text: str) -> List[str]:
    r"""group(1) of each finditer match of
    <meta[^>]+http-equiv\s*=\s*['"]?refresh[^>]*url\s*=\s*['"]?\s*(https?://[^\s'">]+)
    The greedy parts pick the tag's last url= with a refresh before it; at
    most one match per tag, as the next one would need a later url=."""
    urls = []
    for s, e in _tags(text, _META_OPEN, skip=1):
        url = _last_match(text, _URL_WORD, _REFRESH_URL, s, e)
        refresh = _REFRESH.search(text, s, e) if url else None
        if url and refresh and refresh.end() <= url.start():
            urls.append(url.group(1))
    return urls


_SVG_ACTIVE = (
    ("script element", _SVG_SCRIPT.search),
    ("event handler attribute", _event_handler),
    ("foreignObject (embedded HTML)", _SVG_FOREIGN.search),
    ("javascript: link", _SVG_JS_LINK.search),
    ("embedded frame/object", _SVG_FRAME.search),
)


@dataclass
class WebPayload:
    name: str                       # display name inside the page, e.g. "payload1.iso"
    format: str
    size: int
    source: str                     # "data URI" | "base64 string"
    path: Optional[str] = None      # sandbox path while the context is open

    def as_dict(self) -> Dict:
        return {"name": self.name, "format": self.format, "size": self.size,
                "source": self.source}


@dataclass
class WebResult:
    available: bool = True
    kind: str = ""                  # "html" | "svg"
    smuggling: bool = False         # construct + payload (or data-URI download of a payload)
    smuggling_construct: bool = False
    smuggling_reasons: List[str] = field(default_factory=list)
    payloads: List[WebPayload] = field(default_factory=list)
    svg_active: List[str] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)
    credential_form: bool = False
    credential_reasons: List[str] = field(default_factory=list)
    obfuscation: List[str] = field(default_factory=list)
    truncated: bool = False
    detail: str = ""

    @property
    def executable_payloads(self) -> List[str]:
        return [p.name for p in self.payloads if p.format in EXECUTABLE_PAYLOADS]

    def as_dict(self) -> Dict:
        return {
            "available": self.available,
            "kind": self.kind,
            "smuggling": self.smuggling,
            "smuggling_construct": self.smuggling_construct,
            "smuggling_reasons": self.smuggling_reasons,
            "payloads": [p.as_dict() for p in self.payloads],
            "svg_active": self.svg_active,
            "redirects": self.redirects[:10],
            "credential_form": self.credential_form,
            "credential_reasons": self.credential_reasons,
            "obfuscation": self.obfuscation,
            "truncated": self.truncated,
            "detail": self.detail,
        }


def payload_format(data: bytes) -> Optional[str]:
    """The format of decoded bytes if it is one a page has no business carrying."""
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    fmt = detect_format(data[:65536])
    return fmt if fmt in PAYLOAD_EXTENSIONS else None


def _b64decode(blob: bytes) -> Optional[bytes]:
    clean = re.sub(rb"\\[nrt]", b"", blob)          # JS escape sequences in the string
    clean = re.sub(rb"[\s\\]", b"", clean)
    if len(clean) < MIN_PAYLOAD_B64:
        return None
    clean += b"=" * (-len(clean) % 4)
    try:
        return base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError):
        return None


def visible_text(raw: bytes) -> str:
    """Readable text of a page (scripts and styles removed) for the text layers."""
    text = _strip_script_style(raw.decode("utf-8", errors="replace"))
    return re.sub(r"\s+", " ", _strip_tags(text, " ")).strip()


class WebContentAnalyzer:
    """Static analysis of HTML / SVG files; payloads are extracted to a sandbox."""

    def is_web(self, file_path: PathLike) -> bool:
        return Path(file_path).suffix.lower() in WEB_EXTENSIONS

    def analyze(self, file_path: PathLike) -> WebResult:
        """Findings only (no sandbox)."""
        with self.open(file_path, extract=False) as res:
            return res

    @contextlib.contextmanager
    def open(self, file_path: PathLike, extract: bool = True) -> Iterator[WebResult]:
        path = Path(file_path)
        res = WebResult(kind="svg" if path.suffix.lower() in SVG_EXTENSIONS else "html")
        sandbox = Path(tempfile.mkdtemp(prefix="hrd_web_")) if extract else None
        try:
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(MAX_READ + 1)
            except OSError as e:
                res.available = False
                res.detail = f"Web content check skipped: {e}"
                yield res
                return
            if len(raw) > MAX_READ:
                raw, res.truncated = raw[:MAX_READ], True
            self._inspect(raw, res, sandbox)
            res.detail = self._summary(res)
            yield res
        finally:
            if sandbox is not None:
                shutil.rmtree(sandbox, ignore_errors=True)

    # ------------------------------------------------------------ internals
    def _inspect(self, raw: bytes, res: WebResult, sandbox: Optional[Path]) -> None:
        text = raw.decode("utf-8", errors="replace")
        self._payloads(raw, res, sandbox)

        blob = bool(_SMUGGLE_BLOB.search(text))
        save = bool(_SMUGGLE_SAVE.search(text))
        trigger = bool(_SMUGGLE_URL.search(text)) and bool(
            _SMUGGLE_DOWNLOAD.search(text) or _download_anchor(text)
            or _SMUGGLE_CLICK.search(text))
        if blob and (trigger or save):
            res.smuggling_construct = True
            res.smuggling_reasons.append("builds a Blob and makes the browser save it"
                                         + (" (msSaveOrOpenBlob)" if save else
                                            " (object URL + download/click)"))
            if _ATOB.search(text):
                res.smuggling_reasons.append("decodes base64 in the page (atob)")
        if res.payloads and _data_download_anchor(text):
            res.smuggling_construct = True
            res.smuggling_reasons.append("download link whose target is an embedded data: URI")
        res.smuggling = res.smuggling_construct and bool(res.payloads)

        if res.kind == "svg":
            res.svg_active = [label for label, found in _SVG_ACTIVE if found(text)]

        found_urls = _meta_refresh_urls(text) + [
            m.group(1) for rx in _REDIRECTS for m in rx.finditer(text)]
        for url in found_urls:
            if url not in res.redirects:
                res.redirects.append(url)

        if _password_field(text):
            action = _form_action(text)
            if action:
                res.credential_reasons.append("password field submitted to " + action)
            if re.search(r"fetch\s*\(|xmlhttprequest|\$\.(?:ajax|post)\s*\(|sendbeacon", text, re.I):
                res.credential_reasons.append("password field read by script that sends data out")
        exfil = _EXFIL.search(text)
        if exfil:
            res.credential_reasons.append("exfiltration endpoint " + exfil.group(0))
        res.credential_form = bool(res.credential_reasons)

        res.obfuscation = [label for label, rx in _OBFUSCATION if rx.search(text)]

    def _payloads(self, raw: bytes, res: WebResult, sandbox: Optional[Path]) -> None:
        seen = set()
        candidates = [(m.group(3), "data URI") for m in _DATA_URI.finditer(raw)]
        joined = _JS_CONCAT.sub(b"", raw)            # "AAAA" + "BBBB" -> "AAAABBBB"
        candidates += [(m.group(1), "base64 string") for m in _B64_LITERAL.finditer(joined)]
        for blob, source in sorted(candidates, key=lambda c: -len(c[0])):
            if len(res.payloads) >= MAX_PAYLOADS:
                break
            data = _b64decode(blob)
            if not data or len(data) > MAX_PAYLOAD_BYTES:
                continue
            digest = hash(data)
            if digest in seen:
                continue
            seen.add(digest)
            fmt = payload_format(data)
            if fmt is None:
                continue                              # an inline image, font, text...
            payload = WebPayload(name=f"payload{len(res.payloads) + 1}{PAYLOAD_EXTENSIONS[fmt]}",
                                 format=fmt, size=len(data), source=source)
            if sandbox is not None:
                target = sandbox / f"p{len(res.payloads)}" / payload.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                payload.path = str(target)
            res.payloads.append(payload)

    @staticmethod
    def _summary(res: WebResult) -> str:
        bits = [f"{res.kind.upper()} page"]
        if res.smuggling:
            bits.append("HTML SMUGGLING: " + "; ".join(res.smuggling_reasons))
        elif res.smuggling_construct:
            bits.append("Blob download construct (no embedded payload found)")
        if res.payloads:
            bits.append("embedded payload(s): " + ", ".join(
                f"{p.name} ({p.format}, {p.size:,} bytes)" for p in res.payloads))
        if res.svg_active:
            bits.append("active SVG content: " + ", ".join(res.svg_active))
        if res.credential_form:
            bits.append("credential capture: " + "; ".join(res.credential_reasons))
        if res.redirects:
            bits.append(f"{len(res.redirects)} redirect(s) to an external URL")
        if res.obfuscation:
            bits.append("obfuscation: " + ", ".join(res.obfuscation))
        if len(bits) == 1:
            bits.append("no active or embedded content of concern")
        return "; ".join(bits) + "."
