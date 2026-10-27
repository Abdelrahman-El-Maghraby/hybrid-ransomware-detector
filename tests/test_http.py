"""core/http.py: the retrying session, the rate limiter and safe_json."""

import threading

import pytest
import requests

from core import http


def test_session_retries_only_idempotent_requests():
    s = http.build_session(total_retries=2, backoff_factor=0.5, user_agent="t/1")
    retry = s.get_adapter("https://example.org").max_retries
    assert s.headers["User-Agent"] == "t/1"
    assert retry.total == 2 and retry.backoff_factor == 0.5
    assert set(retry.allowed_methods) == {"GET", "HEAD"}
    assert 429 in retry.status_forcelist and retry.respect_retry_after_header
    assert s.get_adapter("http://example.org").max_retries is retry


def test_session_without_retries():
    s = http.build_session(total_retries=0)
    assert s.get_adapter("https://example.org").max_retries.total == 0   # requests' default


class Clock:
    def __init__(self):
        self.now, self.slept = 100.0, []

    def __call__(self):
        return self.now

    def sleep(self, d):
        self.slept.append(d)
        self.now += d


def test_rate_limiter_spaces_calls():
    c = Clock()
    rl = http.RateLimiter(4, clock=c, sleep=c.sleep)
    assert rl.interval == 15.0
    assert rl.wait() == 0.0
    assert rl.wait() == 15.0 and c.slept == [15.0]
    c.now += 60                                  # idle for a minute: no wait
    assert rl.wait() == 0.0


@pytest.mark.parametrize("per_minute", [0, -1, None])
def test_rate_limiter_disabled(per_minute):
    rl = http.RateLimiter(per_minute)
    assert rl.interval == 0.0 and rl.wait() == 0.0


def test_rate_limiter_is_thread_safe():
    c = Clock()
    lock = threading.Lock()

    def sleep(d):
        with lock:
            c.slept.append(d)
    rl = http.RateLimiter(60, clock=c, sleep=sleep)
    threads = [threading.Thread(target=rl.wait) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(c.slept) == [float(i) for i in range(1, 8)]   # each waits one slot more


class Resp:
    def __init__(self, value=None, exc=None):
        self.value, self.exc = value, exc

    def json(self):
        if self.exc:
            raise self.exc
        return self.value


def test_safe_json():
    assert http.safe_json(None) == {}
    assert http.safe_json(Resp({"a": 1})) == {"a": 1}
    assert http.safe_json(Resp([1, 2])) == {}
    assert http.safe_json(Resp(exc=ValueError("not json"))) == {}
    assert http.safe_json(Resp(exc=requests.exceptions.JSONDecodeError("x", "y", 0))) == {}
