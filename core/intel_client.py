"""
The analysis service's side of the intel service (api/intel.py).

In a Docker deployment the analysis service has no network: it opens hostile
files, so a parser compromise there must not reach the internet. VirusTotal, the
LLM and the sandbox are reached through the intel service instead, over a Unix
domain socket (AEGIS_INTEL_SOCKET) with a shared token (AEGIS_INTEL_TOKEN). The
classes here have the same interface as the in-process ones, so the pipeline does
not change: IntelLLMBackend is an LLMBackend, IntelSandbox has CapeClient's
analyze(), and the VirusTotal layer calls IntelClient.vt_lookup / vt_upload.

Without AEGIS_INTEL_SOCKET (desktop, CLI) nothing here is used.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import socket
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

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
        return resp.status, resp.read()
    finally:
        conn.close()


class IntelClient:
    def __init__(self, socket_path: str, token: str, timeout: float = 60,
                 clock: Callable[[], float] = time.monotonic):
        self.socket_path, self.token, self.timeout = socket_path, token, timeout
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
            status, raw = unix_request(self.socket_path, method, url, body, send,
                                       timeout or self.timeout)
        except NotConnected as e:
            raise IntelError(f"intel service unreachable ({type(e.__cause__).__name__})",
                             delivered=False) from None
        except OSError as e:
            raise IntelError(f"intel service unreachable ({type(e).__name__})") from None
        try:
            answer = json.loads(raw.decode() or "{}")
        except ValueError:
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


def client_from_config(config: Dict) -> Optional[IntelClient]:
    """An IntelClient when AEGIS_INTEL_SOCKET is set, else None (in-process lookups)."""
    path = str(config.get("intel_socket") or "")
    if not path:
        return None
    from engine.secret_store import from_environment
    token = str(config.get("intel_token") or from_environment("AEGIS_INTEL_TOKEN") or "")
    return IntelClient(path, token)
