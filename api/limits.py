"""
Abuse protection for the REST API, as plain ASGI middleware (no extra package).

* BodyLimit - rejects an upload larger than the limit BEFORE it is parsed: a
  Content-Length over the limit gets 413 at once, and a chunked body is
  counted as it streams and cut off at the limit. (FastAPI's UploadFile spools
  the whole multipart body to a temporary file before the endpoint runs, so a
  check inside the endpoint alone lets a client fill the disk.)
* RateLimit - a token bucket per client (IP address + a fingerprint of the
  bearer token): RATE requests per minute with BURST in hand; over that, 429
  with Retry-After. /health is exempt. Behind a reverse proxy set
  AEGIS_API_TRUST_PROXY=1 so the first X-Forwarded-For address is the client.
* ScanSlots - at most N scans at once (they are CPU- and memory-heavy); a
  request beyond that gets 503 with Retry-After instead of queueing forever.

Every rejection is counted in engine.metrics (requests_rejected).
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from engine.metrics import METRICS

Scope = Dict[str, Any]
Message = Dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


async def _reply(send: Send, status: int, detail: str,
                 headers: Optional[Dict[str, str]] = None) -> None:
    body = json.dumps({"detail": detail}).encode()
    hdrs = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    hdrs += [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    await send({"type": "http.response.start", "status": status, "headers": hdrs})
    await send({"type": "http.response.body", "body": body})


def _header(scope: Scope, name: bytes) -> str:
    for k, v in scope.get("headers") or []:
        if k.lower() == name:
            return v.decode("latin-1")
    return ""


class BodyLimit:
    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        length = _header(scope, b"content-length")
        if length.isdigit() and int(length) > self.max_bytes:
            METRICS.reject("too_large")
            await _reply(send, 413, f"request body larger than {self.max_bytes} bytes")
            return
        seen = 0
        too_large = False
        started = False

        async def limited_receive() -> Message:
            nonlocal seen, too_large
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    too_large = True
                    return {"type": "http.disconnect"}      # stop reading the body
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if too_large:
                if not started:                             # replace the app's answer
                    started = True
                    METRICS.reject("too_large")
                    await _reply(send, 413, f"request body larger than {self.max_bytes} bytes")
                return
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not too_large:
                raise
            if not started:
                started = True
                METRICS.reject("too_large")
                await _reply(send, 413, f"request body larger than {self.max_bytes} bytes")


class TokenBuckets:
    """Thread-safe token buckets keyed by client; the least recently seen are
    forgotten beyond `max_clients` so the table cannot grow without bound."""

    def __init__(self, per_minute: float, burst: int, clock=time.monotonic,
                 max_clients: int = 10_000):
        self.rate = per_minute / 60.0
        self.burst = max(1, burst)
        self.clock = clock
        self.max_clients = max_clients
        self._buckets: OrderedDict[str, Tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str) -> float:
        """0 when allowed, else the seconds until the next request is allowed."""
        if self.rate <= 0:
            return 0.0
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.pop(key, (float(self.burst), now))
            tokens = min(float(self.burst), tokens + (now - last) * self.rate)
            wait = 0.0
            if tokens >= 1:
                tokens -= 1
            else:
                wait = (1 - tokens) / self.rate
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self.max_clients:
                self._buckets.popitem(last=False)
            return wait


def client_key(scope: Scope, trust_proxy: bool) -> str:
    ip = (scope.get("client") or ("unknown", 0))[0]
    if trust_proxy:
        forwarded = _header(scope, b"x-forwarded-for").split(",")[0].strip()
        ip = forwarded or ip
    auth = _header(scope, b"authorization")
    token = hashlib.sha256(auth.encode()).hexdigest()[:12] if auth else "anonymous"
    return f"{ip}|{token}"


class RateLimit:
    EXEMPT = ("/health",)

    def __init__(self, app: ASGIApp, buckets: TokenBuckets, trust_proxy: bool = False):
        self.app, self.buckets, self.trust_proxy = app, buckets, trust_proxy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") not in self.EXEMPT:
            wait = self.buckets.take(client_key(scope, self.trust_proxy))
            if wait > 0:
                METRICS.reject("rate_limited")
                await _reply(send, 429, "too many requests",
                             {"retry-after": str(max(1, int(wait + 0.999)))})
                return
        await self.app(scope, receive, send)


class ScanSlots:
    """At most `limit` concurrent scans (non-blocking)."""

    def __init__(self, limit: int):
        self.limit = max(1, limit)
        self._sem = threading.BoundedSemaphore(self.limit)

    def try_acquire(self) -> bool:
        if self._sem.acquire(blocking=False):
            return True
        METRICS.reject("busy")
        return False

    def release(self) -> None:
        self._sem.release()
