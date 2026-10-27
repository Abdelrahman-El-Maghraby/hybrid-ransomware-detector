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

from .sandbox import SandboxResult

logger = logging.getLogger("RansomwareScanner")

RETRY_CAPABILITIES_SECONDS = 30.0


class IntelError(RuntimeError):
    """The intel service could not be reached or refused the request."""


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # type: ignore[attr-defined]
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
        except OSError as e:
            raise IntelError(f"intel service unreachable ({type(e).__name__})") from None
        try:
            answer = json.loads(raw.decode() or "{}")
        except ValueError:
            answer = {}
        if status != 200:
            detail = answer.get("detail") if isinstance(answer, dict) else ""
            raise IntelError(f"intel {url}: HTTP {status}" + (f" ({detail})" if detail else ""))
        if not isinstance(answer, dict):
            raise IntelError(f"intel {url}: not a JSON object")
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
        return dict(caps.get(name) or {"enabled": False})

    # ------------------------------------------------------------ operations
    def vt_lookup(self, sha256: str) -> Dict:
        return self.call("POST", "/v1/virustotal/lookup", {"sha256": sha256})

    def vt_upload(self, path: str) -> Dict:
        with open(path, "rb") as fh:
            data = fh.read()
        return self.call("POST", "/v1/virustotal/upload", data=data, timeout=600)


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

    def analyze(self, combined_content: str) -> Dict:
        if self.client.service("llm").get("unreachable"):
            return _empty_analysis("Intel service unreachable; semantic layer skipped.", error=True)
        if not self.available:
            return _empty_analysis("No LLM configured on the intel service; semantic layer "
                                   "skipped.")
        try:
            return self.client.call("POST", "/v1/llm/analyze", {"content": combined_content},
                                    timeout=180)
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

    def analyze(self, path: str) -> SandboxResult:
        res = SandboxResult(enabled=True)
        try:
            ext = os.path.splitext(path)[1].lower()
            with open(path, "rb") as fh:
                data = fh.read()
            headers = {"X-Aegis-Extension": ext} if 1 < len(ext) <= 9 and ext[1:].isalnum() else {}
            submitted = self.client.call("POST", "/v1/sandbox/submit", data=data,
                                         headers=headers, timeout=120)
            if not submitted.get("submitted"):
                return _result(submitted)
            task_id = int(submitted["task_id"])
            deadline = self.clock() + self.wait_seconds
            while True:
                polled = self.client.call("POST", "/v1/sandbox/poll", {"task_id": task_id})
                if polled.get("status") != "pending":
                    return _result(polled)
                if self.clock() >= deadline:
                    res.submitted, res.task_id, res.status = True, task_id, "timeout"
                    res.detail = (f"no report within {self.wait_seconds}s (task {task_id}; "
                                  "look it up in CAPE later)")
                    return res
                self.sleep(self.poll_seconds)
        except (IntelError, OSError, KeyError, ValueError) as e:
            logger.warning("Sandbox through the intel service failed: %s", e)
            res.status, res.detail = "error", f"sandbox via intel failed ({e})"
            return res


def _result(d: Dict[str, Any]) -> SandboxResult:
    fields = ("enabled", "submitted", "task_id", "status", "malscore", "signatures",
              "ransomware", "network_hosts", "detail")
    return SandboxResult(**{k: d[k] for k in fields if k in d})


def client_from_config(config: Dict) -> Optional[IntelClient]:
    """An IntelClient when AEGIS_INTEL_SOCKET is set, else None (in-process lookups)."""
    path = str(config.get("intel_socket") or "")
    if not path:
        return None
    from engine.secret_store import from_environment
    token = str(config.get("intel_token") or from_environment("AEGIS_INTEL_TOKEN") or "")
    return IntelClient(path, token)
