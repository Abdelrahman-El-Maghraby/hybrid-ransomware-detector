"""
MailGuard - static analysis of saved e-mails (.eml and Outlook .msg).

WHY THIS EXISTS
---------------
Most ransomware still arrives by e-mail: a lure message with a macro document,
a script, or a password-protected ZIP attached. Before v4.1 the scanner only saw
the attachment *after* someone saved it to disk; a saved .eml/.msg (exported
from a mail client, pulled from a phishing mailbox, or attached to a ticket)
was opaque. MailGuard opens the message, judges the envelope, and hands every
attachment to the normal scan pipeline.

WHAT IT CHECKS
--------------
* Sender authentication - SPF, DKIM and DMARC results as recorded by the
  *receiving* mail server in ``Authentication-Results`` / ``Received-SPF``.
  Only the **topmost** instance of each header is trusted: those are prepended
  by the last hop (your server). Copies further down the header block were
  written by whoever sent the message and can be forged at will, so they are
  ignored (and their presence is reported). MailGuard does not re-run DNS
  checks itself - a saved message can be years old and DNS has moved on.
* Sender spoofing - a display name that carries a *different* address or
  domain ("PayPal Service <x@evil.tld>" is fine, "billing@paypal.com
  <x@evil.tld>" is not), and a Reply-To that sends answers to another domain
  (classic business-e-mail-compromise set-up).
* Deceptive links - HTML anchors whose visible text shows one domain while
  the href goes to another.
* Attachments - executable/script types, double extensions
  (``invoice.pdf.exe``), right-to-left-override names, and attached e-mails
  (``message/rfc822``) which are saved as .eml so they are scanned too.
* Lure subjects - payment/urgency/credential phrasing. This is a *weak*,
  semantic signal and is scored as such.

FORMATS
-------
* ``.eml`` (RFC 5322 / MIME) - standard library ``email`` package.
* ``.msg`` (Outlook, MS-OXMSG compound file) - read stream-by-stream with
  ``olefile`` (already installed with oletools). The transport-header stream
  is parsed exactly like an .eml header block, so the authentication checks
  work for .msg too when Outlook kept the headers (received mail does; drafts
  and sent items have none).

Attachments are written to a private temporary directory that exists only
inside the ``with MailAnalyzer().open(path)`` block, one sub-directory per
attachment, with sanitised names. Nothing is ever executed.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import email
import email.policy
import hashlib
import html
import logging
import quopri
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses, parseaddr
from pathlib import Path, PurePosixPath
from typing import Dict, Iterator, List, Optional, Tuple, Union

from .container_extractor import EXECUTABLE_EXTENSIONS, LURE_EXTENSIONS, RTLO, visible_name

logger = logging.getLogger("RansomwareScanner.mail")

try:  # olefile ships with oletools (already a scanner dependency)
    import olefile as _olefile  # type: ignore
    MSG_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    _olefile = None
    MSG_AVAILABLE = False

PathLike = Union[str, Path]

# Macro-enabled Office formats are delivery vehicles in their own right.
_RISKY_ATTACHMENT_EXTENSIONS = EXECUTABLE_EXTENSIONS | frozenset({
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".sldm",
})
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_AUTH_PASS = frozenset({"pass"})
_AUTH_FAIL = frozenset({"fail", "softfail", "permerror"})

_LURE_SUBJECT_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = tuple(
    (label, re.compile(rx, re.I)) for label, rx in (
        ("invoice/payment", r"\b(invoice|payment|remittance|wire transfer|overdue|past due)\b"),
        ("urgency", r"\b(urgent|immediate(ly)?|final (notice|warning)|action required)\b"),
        ("account threat", r"\baccount\b.{0,30}\b(suspend|lock|terminat|disabl|clos)\w*"),
        ("credential lure", r"\b(verify|confirm|update|reset)\b.{0,30}\b(account|password|"
                            r"credentials?|payment details|login)\b"),
        ("password expiry", r"\bpassword\b.{0,20}\bexpir\w*"),
        ("delivery lure", r"\b(parcel|package|shipment|delivery)\b.{0,30}\b(failed|held|pending)\b"),
        ("document share", r"\b(shared|sent) (a|the) (document|file)s? with you\b"),
    ))
_DOMAIN_IN_TEXT = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.I)
_ANCHOR = re.compile(r"<a\b[^>]*\bhref\s*=\s*([\"'])(.*?)\1[^>]*>(.*?)</a\s*>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")

# MS-OXPROPS property tags used from .msg files (stream names are
# __substg1.0_<TAG><TYPE>, TYPE 001F = UTF-16 string, 001E = 8-bit string,
# 0102 = binary).
_P_SUBJECT = "0037"
_P_SENDER_NAME = "0C1A"
_P_SENDER_EMAIL = "0C1F"
_P_SENDER_SMTP = "5D01"
_P_TRANSPORT_HEADERS = "007D"
_P_BODY = "1000"
_P_BODY_HTML = "1013"
_P_ATTACH_DATA = "3701"
_P_ATTACH_LONG_NAME = "3707"
_P_ATTACH_NAME = "3704"
_P_ATTACH_MIME = "370E"
_P_DISPLAY_NAME = "3001"
_EMBEDDED_MSG = "__substg1.0_3701000D"   # PR_ATTACH_DATA_OBJ: an Outlook item inside
_MAX_EMBEDDED_DEPTH = 3


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class AttachmentInfo:
    filename: str                   # sanitised display name
    content_type: str = ""
    size: int = 0
    sha256: str = ""
    executable: bool = False
    double_extension: bool = False
    rtlo: bool = False
    path: Optional[str] = None      # sandbox path while the context is open

    def as_dict(self) -> Dict:
        return {"filename": self.filename, "content_type": self.content_type,
                "size": self.size, "sha256": self.sha256, "executable": self.executable,
                "double_extension": self.double_extension, "rtlo": self.rtlo}


@dataclass
class AuthResult:
    spf: Optional[str] = None       # pass | fail | softfail | neutral | none | ... | None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    authserv_id: str = ""           # who wrote the trusted Authentication-Results
    ignored_headers: int = 0        # lower (sender-controlled) copies that were ignored

    @property
    def present(self) -> bool:
        return any(v is not None for v in (self.spf, self.dkim, self.dmarc))

    @property
    def failures(self) -> List[str]:
        return [n for n, v in (("SPF", self.spf), ("DKIM", self.dkim), ("DMARC", self.dmarc))
                if v in _AUTH_FAIL]

    @property
    def all_pass(self) -> bool:
        vals = [v for v in (self.spf, self.dkim, self.dmarc) if v is not None]
        return bool(vals) and all(v in _AUTH_PASS for v in vals)

    def as_dict(self) -> Dict:
        return {"spf": self.spf, "dkim": self.dkim, "dmarc": self.dmarc,
                "authserv_id": self.authserv_id, "ignored_headers": self.ignored_headers,
                "failures": self.failures}


@dataclass
class MailResult:
    available: bool = True
    is_mail: bool = False
    format: str = ""                # eml | msg
    subject: str = ""
    from_header: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""
    auth: AuthResult = field(default_factory=AuthResult)
    display_name_spoof: bool = False
    display_name_spoof_reason: str = ""
    reply_to_mismatch: bool = False
    lure_subject: List[str] = field(default_factory=list)
    deceptive_links: List[str] = field(default_factory=list)
    link_count: int = 0
    attachments: List[AttachmentInfo] = field(default_factory=list)
    attachments_skipped: int = 0
    body_text: str = ""             # plain text (HTML stripped) for prompt-guard / LLM
    error: str = ""
    detail: str = ""

    @property
    def executable_attachments(self) -> List[str]:
        return [a.filename for a in self.attachments if a.executable]

    @property
    def double_extension_attachments(self) -> List[str]:
        return [a.filename for a in self.attachments if a.double_extension]

    @property
    def rtlo_attachments(self) -> List[str]:
        return [a.filename for a in self.attachments if a.rtlo]

    def as_dict(self) -> Dict:
        return {
            "available": self.available, "is_mail": self.is_mail, "format": self.format,
            "subject": self.subject, "from": self.from_header,
            "from_address": self.from_address, "from_domain": self.from_domain,
            "reply_to_domain": self.reply_to_domain,
            "return_path_domain": self.return_path_domain,
            "auth": self.auth.as_dict(),
            "display_name_spoof": self.display_name_spoof,
            "display_name_spoof_reason": self.display_name_spoof_reason,
            "reply_to_mismatch": self.reply_to_mismatch,
            "lure_subject": self.lure_subject,
            "deceptive_links": self.deceptive_links[:10],
            "link_count": self.link_count,
            "attachment_count": len(self.attachments),
            "attachments": [a.as_dict() for a in self.attachments[:100]],
            "attachments_skipped": self.attachments_skipped,
            "executable_attachments": self.executable_attachments,
            "double_extension_attachments": self.double_extension_attachments,
            "rtlo_attachments": self.rtlo_attachments,
            "error": self.error, "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class MailAnalyzer:
    """Parse a saved e-mail and extract attachments into a temporary sandbox."""

    SUPPORTED_EXTENSIONS = frozenset({".eml", ".msg"})

    def __init__(self, max_attachments: int = 50,
                 max_total_bytes: int = 100 * 1024 * 1024,
                 max_message_bytes: int = 60 * 1024 * 1024):
        self.max_attachments = int(max_attachments)
        self.max_total_bytes = int(max_total_bytes)
        self.max_message_bytes = int(max_message_bytes)

    def is_mail(self, file_path: PathLike) -> bool:
        return Path(file_path).suffix.lower() in self.SUPPORTED_EXTENSIONS

    @contextlib.contextmanager
    def open(self, file_path: PathLike) -> Iterator[MailResult]:
        """Analyse the message; attachments exist on disk only inside the block."""
        path = Path(file_path)
        res = MailResult(is_mail=True)
        sandbox = Path(tempfile.mkdtemp(prefix="hrd_mail_"))
        try:
            try:
                self._analyze(path, sandbox, res)
            except Exception as exc:  # noqa: BLE001 - a hostile file must not crash a scan
                logger.debug("MailGuard failed on %s", path, exc_info=True)
                res.error = res.error or f"{type(exc).__name__}: {exc}"
            res.detail = _summary(res)
            yield res
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

    def analyze(self, file_path: PathLike) -> MailResult:
        """Header/body analysis only (attachments are inspected, then discarded)."""
        with self.open(file_path) as res:
            for a in res.attachments:
                a.path = None
            return res

    # ------------------------------------------------------------ dispatch
    def _analyze(self, path: Path, sandbox: Path, res: MailResult) -> None:
        size = path.stat().st_size
        if size > self.max_message_bytes:
            res.error = (f"Message is {size:,} bytes, above the "
                         f"{self.max_message_bytes:,}-byte analysis limit.")
            return
        with open(path, "rb") as fh:
            head = fh.read(8)
        if head.startswith(_OLE_MAGIC) or path.suffix.lower() == ".msg":
            res.format = "msg"
            if not head.startswith(_OLE_MAGIC):
                # Outlook can "save as .msg" in plain-text RFC 822 form too.
                res.format = "eml"
                self._parse_eml(path.read_bytes(), sandbox, res)
                return
            if not MSG_AVAILABLE:
                res.available = False
                res.error = "olefile is not installed (pip install oletools)."
                return
            self._parse_msg(path, sandbox, res)
        else:
            res.format = "eml"
            self._parse_eml(path.read_bytes(), sandbox, res)

    # ----------------------------------------------------------------- EML
    def _parse_eml(self, raw: bytes, sandbox: Path, res: MailResult) -> None:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
        self._judge_headers(msg, res)
        plain, html_parts = [], []
        for part in _leaf_parts(msg):
            ctype = part.get_content_type()
            disposition = (part.get_content_disposition() or "").lower()
            filename = _decode_words(part.get_filename() or "")
            if ctype == "message/rfc822":
                # Attached e-mail: saved as .eml so the scan pipeline recurses
                # into it (and its own attachments) with its own verdict.
                data = _rfc822_bytes(part)
                if data:
                    name = filename or "attached-message.eml"
                    if not name.lower().endswith(".eml"):
                        name += ".eml"
                    self._add_attachment(data, name, ctype, sandbox, res)
            elif disposition == "attachment" or filename or not ctype.startswith("text/"):
                payload = part.get_payload(decode=True)
                if payload is not None:
                    self._add_attachment(payload, filename, ctype, sandbox, res)
            elif ctype == "text/html":
                html_parts.append(_decode_text(part))
            else:
                plain.append(_decode_text(part))
        self._judge_body("\n".join(plain), "\n".join(html_parts), res)

    # ----------------------------------------------------------------- MSG
    def _parse_msg(self, path: Path, sandbox: Path, res: MailResult) -> None:
        with _olefile.OleFileIO(str(path)) as ole:
            def prop(tag: str, storage: str = "") -> Optional[str]:
                return _msg_string(ole, tag, storage)

            headers_text = prop(_P_TRANSPORT_HEADERS) or ""
            if headers_text.strip():
                hdr_msg = email.message_from_string(headers_text.strip() + "\n\n",
                                                    policy=email.policy.compat32)
            else:
                hdr_msg = Message()
            # Fill gaps from MAPI properties (drafts / sent items have no headers).
            if not hdr_msg.get("Subject") and prop(_P_SUBJECT):
                hdr_msg["Subject"] = prop(_P_SUBJECT)
            if not hdr_msg.get("From"):
                addr = prop(_P_SENDER_SMTP) or prop(_P_SENDER_EMAIL) or ""
                if addr and "@" not in addr:
                    addr = ""                   # Exchange DN, not an SMTP address
                name = prop(_P_SENDER_NAME) or ""
                if addr or name:
                    hdr_msg["From"] = f'"{name}" <{addr}>' if addr else name
            self._judge_headers(hdr_msg, res)

            html_body = ""
            raw_html = _msg_binary(ole, _P_BODY_HTML)
            if raw_html:
                html_body = raw_html.decode("utf-8", errors="replace")
            self._judge_body(prop(_P_BODY) or "", html_body, res)

            for storage in _attachment_storages(ole, ""):
                data = _msg_binary(ole, _P_ATTACH_DATA, storage)
                name = (prop(_P_ATTACH_LONG_NAME, storage) or prop(_P_ATTACH_NAME, storage)
                        or "attachment.bin")
                mime = prop(_P_ATTACH_MIME, storage) or ""
                if data is None:
                    embedded = f"{storage}/{_EMBEDDED_MSG}"
                    if ole.exists(embedded):
                        # An Outlook item attached to an Outlook item: rebuilt as
                        # .eml so it is scanned like any attached e-mail.
                        eml = _embedded_msg_to_eml(ole, embedded, 1)
                        title = (prop(_P_DISPLAY_NAME, storage)
                                 or _msg_string(ole, _P_SUBJECT, embedded) or "attached-message")
                        self._add_attachment(eml, _eml_name(title), "message/rfc822", sandbox, res)
                    else:
                        res.attachments_skipped += 1      # OLE object: noted, not unpacked
                    continue
                self._add_attachment(data, name, mime, sandbox, res)

    # -------------------------------------------------------------- checks
    def _judge_headers(self, msg: Message, res: MailResult) -> None:
        res.subject = _decode_words(msg.get("Subject", "") or "")
        res.from_header = _decode_words(msg.get("From", "") or "")
        name, addr = parseaddr(res.from_header)
        res.from_address = addr.lower() if "@" in addr else ""
        res.from_domain = _domain_of(addr)

        reply = getaddresses([_decode_words(v) for v in (msg.get_all("Reply-To") or [])])
        reply_domains = {_domain_of(a) for _, a in reply if _domain_of(a)}
        if reply_domains:
            res.reply_to_domain = sorted(reply_domains)[0]
            if res.from_domain and not any(_same_org(d, res.from_domain) for d in reply_domains):
                res.reply_to_mismatch = True
        res.return_path_domain = _domain_of(parseaddr(msg.get("Return-Path", "") or "")[1])

        reason = _display_name_spoof(name, res.from_domain)
        if reason:
            res.display_name_spoof, res.display_name_spoof_reason = True, reason

        res.lure_subject = [label for label, rx in _LURE_SUBJECT_PATTERNS
                            if rx.search(res.subject)]
        _parse_auth(msg, res.auth)

    def _judge_body(self, plain: str, html_body: str, res: MailResult) -> None:
        text_from_html = ""
        if html_body:
            for _q, href, inner in _ANCHOR.findall(html_body):
                res.link_count += 1
                shown = html.unescape(_TAG.sub("", inner)).strip()
                target = _domain_of_url(html.unescape(href))
                m = _DOMAIN_IN_TEXT.search(shown)
                if target and m and not _same_org(m.group(1).lower(), target):
                    if len(res.deceptive_links) < 20:
                        res.deceptive_links.append(f"text shows {m.group(1).lower()} "
                                                   f"-> link goes to {target}")
            stripped = re.sub(r"(?is)<(script|style)\b.*?</\1\s*>", " ", html_body)
            text_from_html = html.unescape(_TAG.sub(" ", stripped))
        body = plain.strip() or text_from_html
        res.body_text = re.sub(r"[ \t\r\f\v]+", " ", body).strip()[:200_000]

    def _add_attachment(self, data: bytes, name: str, ctype: str, sandbox: Path,
                        res: MailResult) -> None:
        used = sum(a.size for a in res.attachments)
        if len(res.attachments) >= self.max_attachments or used + len(data) > self.max_total_bytes:
            res.attachments_skipped += 1
            return
        base = PurePosixPath(name.replace("\\", "/")).name or "attachment.bin"
        clean = base.replace(RTLO, "")
        suffixes = [s.strip().lower() for s in PurePosixPath(clean).suffixes]
        info = AttachmentInfo(
            filename=visible_name(base), content_type=ctype, size=len(data),
            sha256=hashlib.sha256(data).hexdigest(), rtlo=RTLO in base)
        if suffixes and suffixes[-1] in _RISKY_ATTACHMENT_EXTENSIONS:
            info.executable = True
            info.double_extension = len(suffixes) >= 2 and suffixes[-2] in LURE_EXTENSIONS
        target_dir = sandbox / f"a{len(res.attachments):04d}"
        target_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w.\- ]", "_", clean)[-120:].lstrip(".") or "attachment.bin"
        target = target_dir / safe
        target.write_bytes(data)
        info.path = str(target)
        res.attachments.append(info)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _leaf_parts(msg: Message) -> Iterator[Message]:
    """Like Message.walk() but treats an attached message/rfc822 as one leaf."""
    if msg.get_content_type() == "message/rfc822":
        yield msg
    elif msg.is_multipart():
        for sub in msg.get_payload() or []:
            yield from _leaf_parts(sub)
    else:
        yield msg


def _rfc822_bytes(part: Message) -> bytes:
    """Raw bytes of an attached message, undoing a (non-standard but common)
    base64 / quoted-printable transfer encoding on the message/rfc822 part."""
    inner = part.get_payload()
    if isinstance(inner, list) and inner:
        raw = inner[0].as_bytes()
    elif isinstance(inner, (str, bytes)):
        raw = inner.encode("latin-1", "replace") if isinstance(inner, str) else inner
    else:
        return b""
    cte = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
    try:
        if cte == "base64":
            return base64.b64decode(b"".join(raw.split()), validate=False)
        if cte == "quoted-printable":
            return quopri.decodestring(raw)
    except (binascii.Error, ValueError):
        pass
    return raw


def _decode_words(value: str) -> str:
    """Decode RFC 2047 encoded-words ("=?utf-8?b?...?=") into text."""
    if not value:
        return ""
    try:
        from email.header import decode_header, make_header
        return str(make_header(decode_header(value))).strip()
    except Exception:  # noqa: BLE001 - malformed encodings are common in spam
        return str(value).strip()


def _decode_text(part: Message) -> str:
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _domain_of(address: str) -> str:
    address = (address or "").strip().strip("<>").lower()
    return address.rsplit("@", 1)[1].strip(".") if "@" in address else ""


def _domain_of_url(url: str) -> str:
    m = re.match(r"\s*[a-z][a-z0-9+.-]*://(?:[^@/\s]*@)?([^/:?#\s]+)", url, re.I)
    return m.group(1).lower().strip(".") if m else ""


def _registrable(domain: str) -> str:
    """Rough organisational domain: last two labels (three for co.uk-style)."""
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {
            "co", "com", "net", "org", "gov", "edu", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _same_org(a: str, b: str) -> bool:
    return bool(a and b) and _registrable(a) == _registrable(b)


def _display_name_spoof(display: str, from_domain: str) -> str:
    """Return a reason when the display name names another address or domain."""
    display = (display or "").strip().strip('"')
    if not display or not from_domain:
        return ""
    if "@" in display:
        shown = _domain_of(display.split()[-1] if " " in display else display)
        if shown and not _same_org(shown, from_domain):
            return f"display name shows an address at {shown} but the mail is from {from_domain}"
        return ""
    m = _DOMAIN_IN_TEXT.search(display)
    if m and "." in m.group(1) and not _same_org(m.group(1).lower(), from_domain):
        return f"display name shows {m.group(1).lower()} but the mail is from {from_domain}"
    return ""


def _parse_auth(msg: Message, auth: AuthResult) -> None:
    """Trust only the topmost Authentication-Results / Received-SPF headers."""
    results = msg.get_all("Authentication-Results") or []
    if results:
        top = " ".join(str(results[0]).split()).lower()
        auth.ignored_headers += len(results) - 1
        auth.authserv_id = top.split(";", 1)[0].strip()[:120]
        for method in ("spf", "dkim", "dmarc"):
            found = re.findall(rf"(?:^|[;\s]){method}\s*=\s*([a-z]+)", top)
            if not found:
                continue
            # Several DKIM signatures are normal; one valid signature is enough.
            value = "pass" if method == "dkim" and "pass" in found else found[0]
            setattr(auth, method, value)
    received_spf = msg.get_all("Received-SPF") or []
    if received_spf:
        auth.ignored_headers += len(received_spf) - 1
        if auth.spf is None:
            m = re.match(r"\s*([a-z]+)", str(received_spf[0]), re.I)
            if m:
                auth.spf = m.group(1).lower()


def _msg_stream(ole, tag: str, types: Tuple[str, ...], storage: str) -> Optional[bytes]:
    """`storage` is a '/'-separated storage path ('' = the message root)."""
    for t in types:
        parts = (storage.split("/") if storage else []) + [f"__substg1.0_{tag}{t}"]
        if ole.exists("/".join(parts)):
            return ole.openstream(parts).read()
    return None


def _msg_string(ole, tag: str, storage: str = "") -> Optional[str]:
    raw = _msg_stream(ole, tag, ("001F",), storage)
    if raw is not None:
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    raw = _msg_stream(ole, tag, ("001E",), storage)
    if raw is not None:
        return raw.decode("cp1252", errors="replace").rstrip("\x00")
    return None


def _msg_binary(ole, tag: str, storage: str = "") -> Optional[bytes]:
    return _msg_stream(ole, tag, ("0102",), storage)


def _attachment_storages(ole, base: str) -> List[str]:
    """Attachment storages directly under `base`, as '/'-joined paths."""
    prefix = base.split("/") if base else []
    found = set()
    for entry in ole.listdir(streams=True, storages=False):
        if (len(entry) > len(prefix) + 1 and entry[:len(prefix)] == prefix
                and entry[len(prefix)].lower().startswith("__attach_version1.0_")):
            found.add("/".join(entry[:len(prefix) + 1]))
    return sorted(found)


def _eml_name(title: str) -> str:
    title = re.sub(r"[\\/:*?\"<>|\x00-\x1f]", "_", title).strip() or "attached-message"
    return title[:100] + ("" if title.lower().endswith(".eml") else ".eml")


def _embedded_msg_to_eml(ole, base: str, depth: int) -> bytes:
    """Rebuild an embedded Outlook item as RFC 822 bytes (headers, bodies,
    attachments; deeper embedded items recursively, up to a fixed depth)."""
    from email.mime.application import MIMEApplication
    from email.mime.message import MIMEMessage
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    def prop(tag: str, storage: str = base) -> Optional[str]:
        return _msg_string(ole, tag, storage)

    out = MIMEMultipart("mixed")
    headers_text = prop(_P_TRANSPORT_HEADERS) or ""
    if headers_text.strip():
        parsed = email.message_from_string(headers_text.strip() + "\n\n",
                                           policy=email.policy.compat32)
        for key, value in parsed.items():
            if key.lower() not in ("content-type", "mime-version", "content-transfer-encoding"):
                out[key] = value
    if not out.get("Subject") and prop(_P_SUBJECT):
        out["Subject"] = prop(_P_SUBJECT)
    if not out.get("From"):
        addr = prop(_P_SENDER_SMTP) or prop(_P_SENDER_EMAIL) or ""
        name = prop(_P_SENDER_NAME) or ""
        if addr and "@" in addr:
            out["From"] = f'"{name}" <{addr}>' if name else addr
        elif name:
            out["From"] = name
    body = MIMEMultipart("alternative")
    body.attach(MIMEText(prop(_P_BODY) or "", "plain", "utf-8"))
    raw_html = _msg_binary(ole, _P_BODY_HTML, base)
    if raw_html:
        body.attach(MIMEText(raw_html.decode("utf-8", errors="replace"), "html", "utf-8"))
    out.attach(body)
    for storage in _attachment_storages(ole, base):
        data = _msg_binary(ole, _P_ATTACH_DATA, storage)
        nested = f"{storage}/{_EMBEDDED_MSG}"
        if data is None and depth < _MAX_EMBEDDED_DEPTH and ole.exists(nested):
            inner = email.message_from_bytes(_embedded_msg_to_eml(ole, nested, depth + 1),
                                             policy=email.policy.compat32)
            part = MIMEMessage(inner)
            title = prop(_P_DISPLAY_NAME, storage) or inner.get("Subject") or "attached-message"
            part.add_header("Content-Disposition", "attachment", filename=_eml_name(title))
            out.attach(part)
            continue
        if data is None:
            continue
        name = (prop(_P_ATTACH_LONG_NAME, storage) or prop(_P_ATTACH_NAME, storage)
                or "attachment.bin")
        part = MIMEApplication(data, Name=name)
        part.add_header("Content-Disposition", "attachment", filename=name)
        out.attach(part)
    return out.as_bytes()


def _summary(res: MailResult) -> str:
    if res.error and not res.from_header and not res.attachments:
        return f"Could not analyse message: {res.error}"
    bits = [f"{res.format.upper() or 'mail'} from {res.from_address or 'unknown sender'}"]
    if res.auth.present:
        bits.append("auth " + ", ".join(f"{n}={v}" for n, v in
                                        (("SPF", res.auth.spf), ("DKIM", res.auth.dkim),
                                         ("DMARC", res.auth.dmarc)) if v))
    else:
        bits.append("no authentication results recorded")
    if res.display_name_spoof:
        bits.append("DISPLAY-NAME SPOOF: " + res.display_name_spoof_reason)
    if res.reply_to_mismatch:
        bits.append(f"replies go to {res.reply_to_domain}")
    if res.deceptive_links:
        bits.append(f"{len(res.deceptive_links)} deceptive link(s)")
    bits.append(f"{len(res.attachments)} attachment(s)")
    if res.executable_attachments:
        bits.append("risky attachment(s): " + ", ".join(res.executable_attachments[:3]))
    if res.attachments_skipped:
        bits.append(f"{res.attachments_skipped} attachment(s) not unpacked")
    return "; ".join(bits) + "."
