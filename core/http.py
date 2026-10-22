"""
Shared HTTP plumbing for the external layers (VirusTotal, LLM backends).

Two problems this fixes in the earlier versions:

1. **No timeouts.** A bare `requests.get(url)` waits forever if the server
   stalls, which froze a scheduled scan (and the GUI's worker thread) for good.
   Callers now always pass a timeout; `DEFAULT_TIMEOUT` is the fallback.
2. **Rate limits.** VirusTotal's free API allows 4 requests per minute and
   answers HTTP 429 beyond that. The session below retries idempotent requests
   (GET/HEAD) on 429/5xx with exponential backoff and honours `Retry-After`,
   and `RateLimiter` spaces requests out *before* they hit the quota.
   POSTs (uploads, LLM calls) are deliberately not auto-retried.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Iterable, Optional

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 ships with requests
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None  # type: ignore[assignment,misc]

DEFAULT_TIMEOUT = 30
RETRY_STATUSES = (429, 500, 502, 503, 504)


def build_session(total_retries: int = 3, backoff_factor: float = 2.0,
                  statuses: Iterable[int] = RETRY_STATUSES,
                  user_agent: str = "hybrid-ransomware-detector/4.0") -> requests.Session:
    """A `requests.Session` that retries GET/HEAD on 429/5xx with backoff."""
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    if Retry is not None and total_retries > 0:
        kwargs: Dict[str, Any] = dict(total=total_retries, connect=total_retries, read=total_retries,
                      status=total_retries, backoff_factor=backoff_factor,
                      status_forcelist=tuple(statuses),
                      respect_retry_after_header=True, raise_on_status=False)
        try:
            retry = Retry(allowed_methods=frozenset({"GET", "HEAD"}), **kwargs)
        except TypeError:  # pragma: no cover - urllib3 < 1.26
            retry = Retry(method_whitelist=frozenset({"GET", "HEAD"}), **kwargs)  # type: ignore[call-arg]
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
    return session


class RateLimiter:
    """Minimal thread-safe limiter: at most `per_minute` calls per 60 seconds.

    `per_minute <= 0` disables limiting (e.g. for a premium VirusTotal key).
    """

    def __init__(self, per_minute: float, clock=time.monotonic, sleep=time.sleep):
        self.interval = 60.0 / per_minute if per_minute and per_minute > 0 else 0.0
        self._clock = clock
        self._sleep = sleep
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Block until the next call is allowed; returns the seconds waited."""
        if self.interval <= 0:
            return 0.0
        with self._lock:
            now = self._clock()
            delay = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self.interval
        if delay > 0:
            self._sleep(delay)
        return delay


def safe_json(response: Optional[requests.Response]) -> dict:
    """Parse a JSON body without raising (returns {} on any problem)."""
    if response is None:
        return {}
    try:
        data = response.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
