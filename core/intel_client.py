"""
The analysis service's side of the intel service (api/intel.py).

In a Docker deployment the analysis service has no network: it opens hostile
files, so a parser compromise there must not reach the internet. VirusTotal, the
LLM and the sandbox are reached through the intel service instead, over a Unix
domain socket (AEGIS_INTEL_SOCKET) with a shared token (AEGIS_INTEL_TOKEN). The
classes here have the same interface as the in-process ones, so the pipeline does
not change: IntelLLMBackend is an LLMBackend, IntelSandbox has CapeClient's
analyze(), and the VirusTotal layer calls IntelClient.vt_lookup / vt_upload.

Kubernetes (docs/KUBERNETES.md, decision record K8S-1, option E): intel runs in
its own Pod and the analysis Pod reaches it over TLS on one port instead, with
AEGIS_INTEL_URL (https://SERVICE-CLUSTER-IP:PORT, an IP literal: analysis has no
DNS), AEGIS_INTEL_CA_FILE (a private CA; the system store is not used) and
AEGIS_INTEL_SERVER_NAME (the name the certificate must carry, checked although
the connection goes to an address). TLS 1.2 or later, the certificate and name
verified, no plaintext or unverified fallback, no redirects (http.client follows
none; any status but 200 is an error), proxy variables ignored, no retries. The
token goes only to that address. The Unix socket stays the Docker transport.

On both transports a reply is read with a size limit (MAX_REPLY_BYTES, 1 MiB) and
in the identity encoding only; an oversized, compressed, cut-short or (for a 200)
non-JSON reply is an IntelError, never an empty success.

Without either (desktop, CLI) nothing here is used.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlsplit

from detectors.llm_backends import LLMBackend, _empty_analysis

from .sandbox import (
    MIN_REQUEST_SECONDS,
    SUBMISSION_STATES,
    Progress,
    SandboxResult,
    _late,
    _no_progress,
    _request_timeout,
    _wait_end,
)

logger = logging.getLogger("RansomwareScanner")

RETRY_CAPABILITIES_SECONDS = 30.0
# Largest reply accepted from intel, on both transports. Every reply is a small
# JSON object: capabilities, a VirusTotal summary, a normalised LLM analysis (at
# most 20 elements; its free-text explanation is bounded only by the model's
# output, about 0.5 MB for a 128k-token context), a sandbox summary (30
# signatures of at most 200-character descriptions, 20 hosts) or an e-mail
# receipt; together a few kilobytes in practice. 1 MiB leaves a wide margin and
# bounds what a faulty or compromised intel can make analysis hold in memory.
MAX_REPLY_BYTES = 1024 * 1024


class IntelError(RuntimeError):
    """The intel service could not be reached or refused the request.
    `status`: its HTTP status, or None when no answer came. `delivered`: False
    when the connection never opened (nothing reached the service), else None."""

    def __init__(self, message: str, status: Optional[int] = None,
                 delivered: Optional[bool] = None):
        super().__init__(message)
        self.status, self.delivered = status, delivered


class NotConnected(OSError):
    """The Unix socket connection to the intel service did not open."""


class BadReply(Exception):
    """Intel answered, but not with something this client reads: larger than
    MAX_REPLY_BYTES (declared or actual), or in a content encoding other than
    identity (the client asks for identity; decoding would need its own bound)."""

    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


def read_reply(resp: http.client.HTTPResponse, limit: int = MAX_REPLY_BYTES) -> bytes:
    """The reply body, read at most limit + 1 bytes: a declared Content-Length over
    the limit is refused before reading, and a body without one (or chunked, or
    longer than declared) is cut at limit + 1 and refused. A body shorter than its
    Content-Length is refused too; a chunked body cut short raises
    http.client.IncompleteRead."""
    encoding = (resp.getheader("Content-Encoding") or "identity").strip().lower()
    if encoding not in ("", "identity"):
        raise BadReply(f"intel reply in an unsupported encoding ({encoding[:40]})", resp.status)
    declared = resp.getheader("Content-Length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError:
            size = -1
        if size > limit:
            raise BadReply(f"intel reply of {size} bytes is over the {limit}-byte limit",
                           resp.status)
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise BadReply(f"intel reply is over the {limit}-byte limit", resp.status)
    if declared is not None and 0 <= size != len(data):
        # read(amt) returns what came before the connection closed: a cut reply
        # must not parse as a shorter, valid one
        raise BadReply(f"intel reply is shorter than its declared {size} bytes", resp.status)
    return data


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        family = getattr(socket, "AF_UNIX", None)
        if family is None:                  # Windows builds without Unix sockets
            raise OSError("Unix domain sockets are not available on this platform")
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


def unix_request(path: str, method: str, url: str, body: Optional[bytes] = None,
                 headers: Optional[Dict[str, str]] = None,
                 timeout: float = 30) -> Tuple[int, bytes]:
    """One HTTP request over a Unix domain socket: (status, body)."""
    conn = _UnixConnection(path, timeout)
    try:
        try:
            conn.connect()
        except OSError as e:
            raise NotConnected(f"{type(e).__name__}: {e}") from e
        conn.request(method, url, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, read_reply(resp)
    finally:
        conn.close()


_SERVER_NAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)"
                          r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


@dataclass(frozen=True)
class TlsEndpoint:
    """Where intel listens in Kubernetes, and how its certificate is checked."""
    host: str                # an IP literal (the intel Service's ClusterIP)
    port: int
    ca_file: str
    server_name: str

    @classmethod
    def parse(cls, url: str, ca_file: str, server_name: str) -> TlsEndpoint:
        """ValueError unless url is https://IP:PORT (nothing else) and the CA file
        and a DNS server name are given."""
        parts = urlsplit(str(url or "").strip())
        if parts.scheme != "https":
            raise ValueError("AEGIS_INTEL_URL must be an https:// URL (no plaintext)")
        if parts.username or parts.password or parts.query or parts.fragment \
                or parts.path not in ("", "/"):
            raise ValueError("AEGIS_INTEL_URL must be https://IP:PORT with nothing else")
        host = parts.hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("AEGIS_INTEL_URL needs an IP address (the intel Service's "
                             "ClusterIP): analysis does no DNS look-ups") from None
        try:
            port = parts.port
        except ValueError:
            port = None
        if not port:
            raise ValueError("AEGIS_INTEL_URL needs an explicit port")
        if not ca_file:
            raise ValueError("AEGIS_INTEL_URL needs AEGIS_INTEL_CA_FILE (the CA that signed "
                             "intel's certificate)")
        name = str(server_name or "").strip().lower().rstrip(".")
        if not _SERVER_NAME.match(name) or _is_ip(name):
            raise ValueError("AEGIS_INTEL_URL needs AEGIS_INTEL_SERVER_NAME, the DNS name in "
                             "intel's certificate")
        return cls(host, port, str(ca_file), name)

    def context(self) -> ssl.SSLContext:
        """Read for every connection, so a renewed CA bundle applies at once."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)          # verifies by default
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=self.ca_file)          # this CA only
        return ctx


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


class _TlsConnection(http.client.HTTPConnection):
    """HTTP over TLS to an address, with the certificate checked against a name."""

    def __init__(self, endpoint: TlsEndpoint, timeout: float):
        super().__init__(endpoint.server_name, endpoint.port, timeout=timeout)
        self.endpoint = endpoint

    def connect(self) -> None:
        sock = socket.create_connection((self.endpoint.host, self.endpoint.port),
                                        timeout=self.timeout)
        try:
            self.sock = self.endpoint.context().wrap_socket(
                sock, server_hostname=self.endpoint.server_name)
        except BaseException:
            sock.close()
            raise


def tls_request(endpoint: TlsEndpoint, method: str, url: str, body: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None,
                timeout: float = 30) -> Tuple[int, bytes]:
    """One HTTPS request to intel: (status, body). Nothing is sent before the
    certificate and its name are verified."""
    conn = _TlsConnection(endpoint, timeout)
    try:
        try:
            conn.connect()
        except OSError as e:                # refused, time-out, or TLS verification
            raise NotConnected(f"{type(e).__name__}: {e}") from e
        conn.request(method, url, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, read_reply(resp)
    finally:
        conn.close()


class IntelClient:
    def __init__(self, socket_path: str, token: str, timeout: float = 60,
                 clock: Callable[[], float] = time.monotonic,
                 tls: Optional[TlsEndpoint] = None):
        if bool(socket_path) == bool(tls):
            raise ValueError("an intel client needs exactly one transport")
        self.socket_path, self.token, self.timeout = socket_path, token, timeout
        self.tls = tls
        self._clock = clock
        self._caps: Optional[Dict] = None
        self._caps_failed_at: Optional[float] = None
        self._lock = threading.Lock()

    def call(self, method: str, url: str, payload: Optional[Dict] = None,
             data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None,
             timeout: Optional[float] = None) -> Dict:
        send = {"Authorization": f"Bearer {self.token}", **(headers or {})}
        body = data
        if payload is not None:
            body = json.dumps(payload).encode()
            send["Content-Type"] = "application/json"
        elif data is not None:
            send["Content-Type"] = "application/octet-stream"
        try:
            if self.tls is not None:
                status, raw = tls_request(self.tls, method, url, body, send,
                                          timeout or self.timeout)
            else:
                status, raw = unix_request(self.socket_path, method, url, body, send,
                                           timeout or self.timeout)
        except NotConnected as e:
            raise IntelError(f"intel service unreachable ({type(e.__cause__).__name__})",
                             delivered=False) from None
        except OSError as e:
            raise IntelError(f"intel service unreachable ({type(e).__name__})") from None
        except BadReply as e:
            # it answered: the request may have been acted on (a sandbox submission
            # stays "possible"); never an empty success
            raise IntelError(f"intel {url}: {e}", status=e.status) from None
        except http.client.HTTPException as e:   # malformed or cut-short reply
            raise IntelError(f"intel {url}: unreadable reply ({type(e).__name__})") from None
        try:
            answer = json.loads(raw.decode() or "{}")
        except ValueError:
            if status == 200:          # a success must be readable, never read as {}
                raise IntelError(f"intel {url}: the reply is not JSON", status=status) from None
            answer = {}
        if status != 200:
            detail = answer.get("detail") if isinstance(answer, dict) else ""
            raise IntelError(f"intel {url}: HTTP {status}" + (f" ({detail})" if detail else ""),
                             status=status)
        if not isinstance(answer, dict):
            raise IntelError(f"intel {url}: not a JSON object", status=status)
        return answer

    def capabilities(self) -> Dict:
        """The services the intel side has configured. A failure is retried after
        RETRY_CAPABILITIES_SECONDS; until then every service reads as unreachable."""
        with self._lock:
            if self._caps is not None:
                return self._caps
            if (self._caps_failed_at is not None
                    and self._clock() - self._caps_failed_at < RETRY_CAPABILITIES_SECONDS):
                return {"unreachable": True}
            try:
                self._caps = self.call("GET", "/v1/capabilities", timeout=10)
                return self._caps
            except IntelError as e:
                logger.warning("Intel service: %s", e)
                self._caps_failed_at = self._clock()
                return {"unreachable": True}

    def service(self, name: str) -> Dict:
        caps = self.capabilities()
        if caps.get("unreachable"):
            return {"enabled": False, "unreachable": True}
        entry = caps.get(name)
        if not isinstance(entry, dict) or not isinstance(entry.get("enabled"), bool):
            # not stated by intel: off for the caller, but not a statement that it is
            # disabled (RV-15: queued e-mail is kept for that case)
            return {"enabled": False, "unknown": True}
        return dict(entry)

    # ------------------------------------------------------------ operations
    def vt_lookup(self, sha256: str, timeout: Optional[float] = None) -> Dict:
        """`timeout`: I-6, an isolated worker's time left (default: the client's)."""
        return self.call("POST", "/v1/virustotal/lookup", {"sha256": sha256},
                         timeout=None if timeout is None else max(0.01, timeout))

    def alert_email(self, fields: Dict) -> None:
        """Hand an e-mail alert (core/mailer.EMAIL_FIELDS, metadata only) to the
        intel service, which holds the SMTP settings; raises IntelError so the
        outbox retries it."""
        self.call("POST", "/v1/alert/email", dict(fields), timeout=60)

    def vt_upload(self, path: str, timeout: Optional[float] = None) -> Dict:
        """`timeout`: I-6, the time an isolated worker has left (default 600 s)."""
        with open(path, "rb") as fh:
            data = fh.read()
        return self.call("POST", "/v1/virustotal/upload", data=data,
                         timeout=600 if timeout is None else max(1.0, min(600.0, timeout)))


class IntelLLMBackend(LLMBackend):
    """The LLM the intel service has configured; its name and model are the remote
    ones, so cached answers keep their keys (engine/external.py)."""

    def __init__(self, client: IntelClient):
        self.client = client

    @property
    def name(self) -> str:  # type: ignore[override]
        info = self.client.service("llm")
        return str(info.get("name") or "none") if info.get("enabled") else "none"

    @property
    def model(self) -> str:
        return str(self.client.service("llm").get("model") or "")

    @property
    def is_local(self) -> bool:  # type: ignore[override]
        return bool(self.client.service("llm").get("is_local"))

    @property
    def available(self) -> bool:
        return bool(self.client.service("llm").get("enabled"))

    def analyze(self, combined_content: str, timeout: Optional[float] = None) -> Dict:
        if self.client.service("llm").get("unreachable"):
            return _empty_analysis("Intel service unreachable; semantic layer skipped.", error=True)
        if not self.available:
            return _empty_analysis("No LLM configured on the intel service; semantic layer "
                                   "skipped.")
        try:
            return self.client.call("POST", "/v1/llm/analyze", {"content": combined_content},
                                    timeout=180 if timeout is None else max(0.01, min(180, timeout)))
        except IntelError as e:
            logger.error("LLM analysis through the intel service failed: %s", e)
            return _empty_analysis("LLM analysis through the intel service failed.", error=True)


class IntelSandbox:
    """CapeClient's analyze() through the intel service: submit, then poll."""

    def __init__(self, client: IntelClient, wait_seconds: int = 600, poll_seconds: int = 15,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        info = client.service("sandbox")
        self.client = client
        self.url = f"intel:{info.get('server', '')}"      # part of the cache key
        self.options = str(info.get("options") or "")
        self.wait_seconds, self.poll_seconds = wait_seconds, poll_seconds
        self.sleep, self.clock = sleep, clock

    def analyze(self, path: str, deadline: Optional[float] = None,
                progress: Optional[Progress] = None) -> SandboxResult:
        """M26: `deadline` (on self.clock) bounds the wait cooperatively as in
        CapeClient: each call's timeout is the time left, no call starts with less
        than MIN_REQUEST_SECONDS left, and a transient failure of a status check
        counts as pending. What the intel service does after this side stops
        waiting (its own CAPE requests) is not bounded here."""
        note = progress or _no_progress
        res = SandboxResult(enabled=True)
        try:
            ext = os.path.splitext(path)[1].lower()
            with open(path, "rb") as fh:
                data = fh.read()
            headers = {"X-Aegis-Extension": ext} if 1 < len(ext) <= 9 and ext[1:].isalnum() else {}
            if deadline is not None and deadline - self.clock() < MIN_REQUEST_SECONDS:
                res.status, res.detail = "timeout", "not submitted: no time left for a request"
                return res
            res.submission = "possible"            # from here on the file may leave
            note("possible")
            try:
                submitted = self.client.call("POST", "/v1/sandbox/submit", data=data,
                                             headers=headers,
                                             timeout=_request_timeout(120, deadline, self.clock))
            except IntelError as e:
                if e.delivered is False or (e.status is not None and 400 <= e.status < 500):
                    res.submission = "not_attempted"   # intel never had it, or refused it
                    note("not_attempted")
                raise
            first = _result(submitted)
            note(first.submission, first.task_id if first.submission == "confirmed" else None)
            if submitted.get("status") == "cached" or not submitted.get("submitted"):
                return first                         # intel's cached report, or refused
            task_id = int(submitted["task_id"])
            end = _wait_end(self.clock() + self.wait_seconds, deadline)
            unreadable = ""
            while True:
                if deadline is None:
                    polled: Optional[Dict] = self.client.call(
                        "POST", "/v1/sandbox/poll", {"task_id": task_id}, timeout=None)
                else:
                    polled = self._poll_bounded(task_id, deadline)
                if polled is not None and polled.get("status") != "pending":
                    return _result(polled, default="confirmed")
                if polled is not None and polled.get("detail"):
                    unreadable = str(polled["detail"])[:300]     # M34: say why it waited
                if self.clock() >= end:
                    res.submitted, res.task_id, res.status = True, task_id, "timeout"
                    res.submission = "confirmed"
                    res.detail = unreadable or _late(self.wait_seconds, deadline, task_id)
                    return res
                self.sleep(min(self.poll_seconds, max(0.0, end - self.clock())))
        except (IntelError, OSError, KeyError, ValueError) as e:
            logger.warning("Sandbox through the intel service failed: %s", e)
            res.status, res.detail = "error", f"sandbox via intel failed ({e})"
            if res.submission == "possible":
                res.detail += "; the intel service may still have submitted the file"
            return res

    def _poll_bounded(self, task_id: int, deadline: float) -> Optional[Dict]:
        """One status check within the deadline; None (pending) when there is no
        time for it or it failed in a way a later check may not (no answer, a
        time-out, HTTP 429 or 5xx)."""
        if deadline - self.clock() < MIN_REQUEST_SECONDS:
            return None
        try:
            return self.client.call("POST", "/v1/sandbox/poll", {"task_id": task_id},
                                    timeout=_request_timeout(self.client.timeout, deadline,
                                                             self.clock))
        except IntelError as e:
            if e.status is None or e.status == 429 or e.status >= 500:
                return None
            raise


def _result(d: Dict[str, Any], default: str = "") -> SandboxResult:
    fields = ("enabled", "submitted", "task_id", "status", "malscore", "signatures",
              "ransomware", "network_hosts", "detail")
    res = SandboxResult(**{k: d[k] for k in fields if k in d})
    res.submission = _submission(d, default)
    return res


def _submission(d: Dict[str, Any], default: str = "") -> str:
    """The submission state an intel answer gives, or (an older intel service)
    the one its other fields imply; an unclear failure is `possible`."""
    if d.get("status") == "cached":              # a report intel already had: nothing sent
        return "not_attempted"
    state = d.get("submission")
    if state in SUBMISSION_STATES:
        return str(state)
    if d.get("submitted"):
        return "confirmed"
    if default:
        return default
    if str(d.get("detail") or "").startswith("submission refused"):
        return "refused"
    return "possible"


def intel_configured(config: Any) -> bool:
    """True when the external services are the intel service's (Docker socket or
    Kubernetes TLS), so the analysis side holds none of their settings."""
    return bool(config.get("intel_socket") or config.get("intel_url"))


def client_from_config(config: Dict) -> Optional[IntelClient]:
    """An IntelClient for AEGIS_INTEL_SOCKET (Docker) or AEGIS_INTEL_URL (Kubernetes),
    else None (in-process lookups). The configuration check refuses an invalid URL
    or both at once before this runs; here an invalid URL gives no client."""
    path = str(config.get("intel_socket") or "")
    url = str(config.get("intel_url") or "")
    if not path and not url:
        return None
    from engine.secret_store import from_environment
    token = str(config.get("intel_token") or from_environment("AEGIS_INTEL_TOKEN") or "")
    if path:
        return IntelClient(path, token)
    try:
        endpoint = TlsEndpoint.parse(url, str(config.get("intel_ca_file") or ""),
                                     str(config.get("intel_server_name") or ""))
    except ValueError as e:
        logger.error("Intel service not used: %s", e)
        return None
    return IntelClient("", token, tls=endpoint)
