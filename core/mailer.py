"""
E-mail alerts (F4): a fixed, metadata-only message over SMTP with TLS.

The message is built from a fixed template and a fixed set of fields
(EMAIL_FIELDS): alert id, kind, verdict, risk band, SHA-256, file name, time,
scan id and reason codes. Nothing else is accepted - no free text, no
recipients, no attachments and never file content. Every text value is cleaned
of control and format characters (CR/LF, RTLO) and truncated, so a hostile file
name cannot inject headers or reshape the message.

Transport: implicit TLS (SMTP_SECURITY=tls, port 465 by default) or STARTTLS
that must succeed (SMTP_SECURITY=starttls, usually 587); certificates and host
names are verified (ssl.create_default_context). There is no plaintext option.
The only destination is the configured SMTP_HOST:SMTP_PORT; recipients and the
sender come from the configuration, never from an alert. SMTP_PASSWORD comes
from the secret store and is never logged.

Where it runs: the desktop sends directly. In Docker the analysis service has no
network, so it hands the fields to the intel service (POST /v1/alert/email,
api/intel.py), which holds the SMTP settings and sends with this same code.
"""

from __future__ import annotations

import re
import smtplib
import ssl
import threading
import time
import unicodedata
from collections import deque
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Callable, Deque, Dict, List, Mapping, Optional

VERDICTS = ("Clean", "Low", "Medium", "High", "Critical")
KINDS = ("verdict", "canary")
_ALERT_ID = re.compile(r"^[0-9a-f]{32}$")
_SCAN_ID = re.compile(r"^([0-9a-f]{16})?$")
_SHA256 = re.compile(r"^([0-9a-f]{64})?$")
_BAND = re.compile(r"^\d{1,3}-\d{1,3}$")
_CODE = re.compile(r"^[a-z0-9_]{1,64}$")
_ADDRESS = re.compile(r"^[^@\s<>,;:\"()\[\]\\]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$|^\[?[0-9A-Fa-f:.]{2,45}\]?$")
MAX_NAME = 120
MAX_CODES = 8

# name -> (type, check); exactly these keys, no others (api/intel.py uses it too)
EMAIL_FIELDS: Dict[str, Any] = {
    "alert_id": (str, _ALERT_ID.match),
    "kind": (str, lambda v: v in KINDS),
    "verdict": (str, lambda v: v in VERDICTS),
    "risk_band": (str, _BAND.match),
    "sha256": (str, _SHA256.match),
    "file_name": (str, lambda v: len(v) <= MAX_NAME and v == clean_text(v, MAX_NAME)),
    "time": (str, lambda v: 0 < len(v) <= 40 and v == clean_text(v, 40)),
    "scan_id": (str, _SCAN_ID.match),
    "reason_codes": (list, lambda v: len(v) <= MAX_CODES
                     and all(isinstance(c, str) and _CODE.match(c) for c in v)),
}


class MailError(RuntimeError):
    """An e-mail could not be sent (the message never contains the password)."""


class RateLimited(MailError):
    """The hourly or daily cap is reached; the alert stays queued."""


def clean_text(value: Any, limit: int) -> str:
    """Printable text only: control and format characters (CR, LF, RTLO ...)
    removed, whitespace collapsed, truncated."""
    text = "".join(" " if ch.isspace() else ch for ch in str(value)
                   if ch.isspace()
                   or unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    return " ".join(text.split())[:limit]


def validate_fields(payload: Any) -> Dict[str, Any]:
    """The payload if it is exactly EMAIL_FIELDS with valid values, else ValueError."""
    if not isinstance(payload, dict) or set(payload) != set(EMAIL_FIELDS):
        raise ValueError(f"expected exactly {sorted(EMAIL_FIELDS)}")
    for key, (kind, ok) in EMAIL_FIELDS.items():
        value = payload[key]
        if isinstance(value, bool) or not isinstance(value, kind) or not ok(value):
            raise ValueError(f"{key} is not valid")
    return payload


def valid_address(value: str) -> bool:
    return bool(_ADDRESS.match(value or "")) and len(value) <= 254


def valid_host(value: str) -> bool:
    return bool(_HOST.match(value or "")) and ".." not in value


def recipients(config: Mapping[str, Any]) -> List[str]:
    raw = config.get("alert_email_to") or ""
    items = raw if isinstance(raw, (list, tuple)) else str(raw).split(",")
    return [str(a).strip() for a in items if str(a).strip()]


def email_configured(config: Mapping[str, Any]) -> bool:
    """SMTP settings for sending directly (the desktop, or the intel service)."""
    return bool(config.get("smtp_host") and recipients(config) and config.get("alert_email_from"))


SUBJECTS = {"verdict": "Aegis Sentinel alert: {verdict} - {file_name}",
            "canary": "Aegis Sentinel alert: ransomware tripwire triggered"}
BODY = """Aegis Sentinel raised an alert.

Kind:         {kind}
Verdict:      {verdict}
Risk band:    {risk_band}
File name:    {file_name}
SHA-256:      {sha256}
Time:         {time}
Scan id:      {scan_id}
Reasons:      {reasons}
Alert id:     {alert_id}

Details are in the scanner's report on the host that raised the alert. This
message carries metadata only: no file content is attached or included.
"""


def build_message(fields: Mapping[str, Any], sender: str, to: List[str]) -> EmailMessage:
    f = validate_fields(dict(fields))
    values = dict(f, reasons=", ".join(f["reason_codes"]) or "-",
                  file_name=f["file_name"] or "-", sha256=f["sha256"] or "-",
                  scan_id=f["scan_id"] or "-")
    msg = EmailMessage()
    msg["Subject"] = clean_text(SUBJECTS[f["kind"]].format(**values), 200)
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="aegis-sentinel.invalid")
    msg["X-Aegis-Alert-Id"] = f["alert_id"]
    msg.set_content(BODY.format(**values))
    return msg


class SmtpMailer:
    """Sends EMAIL_FIELDS alerts to the configured recipients, at most
    `per_hour` and `per_day` messages (RateLimited beyond that)."""

    def __init__(self, config: Mapping[str, Any], smtp: Optional[Callable[..., Any]] = None,
                 smtp_ssl: Optional[Callable[..., Any]] = None,
                 clock: Callable[[], float] = time.time):
        self.host = str(config.get("smtp_host") or "")
        self.security = str(config.get("smtp_security") or "tls").lower()
        self.port = int(config.get("smtp_port") or (465 if self.security == "tls" else 587))
        self.user = str(config.get("smtp_user") or "")
        self._password = str(config.get("smtp_password") or "")
        self.sender = str(config.get("alert_email_from") or "")
        self.to = recipients(config)
        self.per_hour = int(config.get("alert_email_per_hour") or 20)
        self.per_day = int(config.get("alert_email_per_day") or 100)
        self.timeout = float(config.get("http_timeout") or 30)
        self._smtp = smtp or smtplib.SMTP
        self._smtp_ssl = smtp_ssl or smtplib.SMTP_SSL
        self._clock = clock
        self._sent: Deque[float] = deque()
        self._lock = threading.Lock()
        if self.security not in ("tls", "starttls"):
            raise MailError("SMTP_SECURITY must be tls or starttls (no plaintext)")
        if not valid_host(self.host):
            raise MailError("SMTP_HOST is not a host name or address")
        if not (valid_address(self.sender) and self.to and all(map(valid_address, self.to))):
            raise MailError("ALERT_EMAIL_FROM / ALERT_EMAIL_TO are not valid addresses")

    @property
    def destination(self) -> str:
        return f"smtp://{self.host}:{self.port} ({self.security})"

    def _take(self) -> None:
        now = self._clock()
        with self._lock:
            while self._sent and now - self._sent[0] > 86_400:
                self._sent.popleft()
            last_hour = sum(1 for t in self._sent if now - t <= 3_600)
            if last_hour >= self.per_hour or len(self._sent) >= self.per_day:
                raise RateLimited(f"e-mail cap reached ({self.per_hour}/hour, {self.per_day}/day)")
            self._sent.append(now)

    def send(self, fields: Mapping[str, Any]) -> None:
        msg = build_message(fields, self.sender, self.to)
        self._take()
        context = ssl.create_default_context()          # CERT_REQUIRED + host name check
        try:
            if self.security == "tls":
                server = self._smtp_ssl(self.host, self.port, timeout=self.timeout,
                                        context=context)
            else:
                server = self._smtp(self.host, self.port, timeout=self.timeout)
            with server:
                if self.security == "starttls":
                    server.ehlo()
                    if not server.has_extn("starttls"):
                        raise MailError("the SMTP server does not offer STARTTLS; "
                                        "nothing was sent in plaintext")
                    server.starttls(context=context)
                    server.ehlo()
                if self.user:
                    server.login(self.user, self._password)
                server.send_message(msg, from_addr=self.sender, to_addrs=self.to)
        except MailError:
            raise
        except (smtplib.SMTPException, ssl.SSLError, OSError) as e:
            raise MailError(f"{type(e).__name__} from {self.destination}") from None
