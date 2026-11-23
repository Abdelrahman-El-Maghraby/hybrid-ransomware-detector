"""
Abuse protection for the REST API, as plain ASGI middleware (no extra package).

* BodyLimit - rejects an upload larger than the limit BEFORE it is parsed: a
  Content-Length over the limit gets 413 at once, and a chunked body is
  counted as it streams and cut off at the limit. (FastAPI's UploadFile spools
  the whole multipart body to a temporary file before the endpoint runs, so a
  check inside the endpoint alone lets a client fill the disk.)
* RateLimit - a token bucket per client IP address, applied BEFORE authentication:
  IP_RATE requests per minute with IP_BURST in hand; over that, 429 with
  Retry-After. /health is exempt. Behind a reverse proxy set
  AEGIS_API_TRUST_PROXY=1 so the address that proxy saw (the LAST
  X-Forwarded-For entry) is the client; see client_ip.
* AuthGuard - failed bearer tokens are counted per IP address: THRESHOLD failures
  within WINDOW seconds lock that address out for LOCKOUT seconds (429 with
  Retry-After), checked before the token is compared. Rotating wrong tokens does
  not help: the count is per address, not per token.
* After a token matches, the per-client quota (IP + token: RATE per minute with
  BURST in hand) applies as before.
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
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple

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


def _header(scope: Mapping[str, Any], name: bytes) -> str:
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


def client_ip(scope: Mapping[str, Any], trust_proxy: bool) -> str:
    """The peer address, or behind the one trusted reverse proxy the address that
    proxy saw: the LAST X-Forwarded-For entry. Earlier entries come from the client
    (a proxy that appends keeps them), so trusting the first one would let every
    request pick a fresh address and escape the rate limit and the lockout."""
    ip = (scope.get("client") or ("unknown", 0))[0]
    if trust_proxy:
        forwarded = _header(scope, b"x-forwarded-for").split(",")[-1].strip()
        ip = forwarded or ip
    return str(ip)


def client_key(scope: Mapping[str, Any], trust_proxy: bool) -> str:
    """IP address + a fingerprint of the bearer token: the authenticated quota."""
    auth = _header(scope, b"authorization")
    token = hashlib.sha256(auth.encode()).hexdigest()[:12] if auth else "anonymous"
    return f"{client_ip(scope, trust_proxy)}|{token}"


class AuthGuard:
    """Locks an IP address out after repeated failed bearer tokens.

    `failure(ip)` records one failed compare; `threshold` failures within `window`
    seconds lock the address for `lockout` seconds. `locked_for(ip)` answers the
    seconds left (0 = not locked) and is checked BEFORE the token is compared. The
    table forgets the least recently seen addresses beyond `max_clients`."""

    def __init__(self, threshold: int = 5, window: float = 300, lockout: float = 900,
                 clock=time.monotonic, max_clients: int = 10_000):
        self.threshold = max(1, int(threshold))
        self.window, self.lockout = float(window), float(lockout)
        self.clock, self.max_clients = clock, max_clients
        # ip -> (failure times within the window, locked until)
        self._state: OrderedDict[str, Tuple[Tuple[float, ...], float]] = OrderedDict()
        self._lock = threading.Lock()

    def locked_for(self, ip: str) -> float:
        now = self.clock()
        with self._lock:
            _, until = self._state.get(ip, ((), 0.0))
            return max(0.0, until - now)

    def failure(self, ip: str) -> float:
        """Record a failed token; the lockout in seconds if this one triggered it."""
        now = self.clock()
        with self._lock:
            times, until = self._state.pop(ip, ((), 0.0))
            times = tuple(t for t in times if now - t < self.window) + (now,)
            locked = 0.0
            if len(times) >= self.threshold:
                until, times, locked = now + self.lockout, (), self.lockout
            self._state[ip] = (times, until)
            while len(self._state) > self.max_clients:
                self._state.popitem(last=False)
            return locked

    def success(self, ip: str) -> None:
        with self._lock:
            times, until = self._state.get(ip, ((), 0.0))
            if times and until <= self.clock():
                del self._state[ip]


class RateLimit:
    """The general per-IP limit, before authentication (the token plays no part)."""
    EXEMPT = ("/health",)

    def __init__(self, app: ASGIApp, buckets: TokenBuckets, trust_proxy: bool = False):
        self.app, self.buckets, self.trust_proxy = app, buckets, trust_proxy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") not in self.EXEMPT:
            wait = self.buckets.take(client_ip(scope, self.trust_proxy))
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
