"""Operations: runtime metrics, structured scan events, and the API's abuse
limits (body size, rate, concurrency)."""

import asyncio
import logging

import pytest

from api.limits import BodyLimit, ScanSlots, TokenBuckets, client_key
from engine.metrics import METRICS, Metrics
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

TOKEN = "t" * 32


def auth():
    return {"Authorization": f"Bearer {TOKEN}"}


# ------------------------------------------------------------------ metrics
class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def test_metrics_counts_results_failures_and_rejections():
    c = Clock()
    m = Metrics(clock=c)
    m.record_result({"verdict": "High", "file_size": 10, "scan_duration_ms": 40,
                     "scan_results": {"layer_errors": {"yara": "boom"}}})
    m.record_result({"verdict": "Medium", "file_size": 5,
                     "scan_results": {"scan_failed": {"reason": "timed out after 300s"}}}, 0.5)
    m.record_results([{"verdict": "Clean", "scan_results": {"scan_failed": {
        "reason": "the worker process died (exit code 3)"}}},
        {"verdict": "Clean", "scan_results": {"scan_failed": {"reason": "MemoryError: x"}}}])
    m.reject("rate_limited")
    c.t += 10
    s = m.snapshot()
    assert s["files_scanned"] == 4 and s["bytes_scanned"] == 15
    assert s["files_per_second"] == 0.4 and s["average_scan_ms"] == 135.0
    assert s["verdicts"] == {"Clean": 2, "Low": 0, "Medium": 1, "High": 1, "Critical": 0}
    assert s["layer_errors"] == {"yara": 1}
    assert s["scan_failures"] == {"timeout": 1, "worker_crash": 1, "memory": 1}
    assert s["requests_rejected"] == {"rate_limited": 1}
    text = m.prometheus()
    assert 'aegis_verdicts_total{verdict="High"} 1' in text
    assert 'aegis_scan_failures_total{kind="timeout"} 1' in text
    assert "aegis_files_scanned_total 4" in text and text.endswith("\n")
    m.reset()
    assert m.snapshot()["files_scanned"] == 0 and m.snapshot()["average_scan_ms"] == 0.0


def test_batch_summary():
    s = Metrics().batch_summary([{"verdict": "Clean"}, {"verdict": "High"}], 4.0)
    assert s == {"files": 2, "seconds": 4.0, "files_per_sec": 0.5,
                 "verdicts": {"Clean": 1, "Low": 0, "Medium": 0, "High": 1, "Critical": 0}}
    assert Metrics().batch_summary([], 0)["files_per_sec"] == 0.0


def test_folder_scan_records_metrics_and_logs_events(tmp_path, caplog):
    import RansomwareScanner as RS
    scanner = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    for i in range(3):
        (tmp_path / "scan" / f"d{i}.pdf").write_bytes(make_pdf(f"doc {i}"))
    METRICS.reset()
    with caplog.at_level(logging.INFO, logger="RansomwareScanner"):
        results = scanner.scan_all_directories()
    assert len(results) == 3 and all(r["scan_duration_ms"] >= 0 for r in results)
    assert METRICS.snapshot()["files_scanned"] == 3
    events = {getattr(r, "event", None) for r in caplog.records}
    assert {"scan_started", "scan_completed", "scan_batch"} <= events
    done = next(r for r in caplog.records if getattr(r, "event", "") == "scan_completed")
    assert len(done.sha256) == 64 and done.verdict == "Clean"
    batch = next(r for r in caplog.records if getattr(r, "event", "") == "scan_batch")
    assert batch.files == 3 and "Clean 3" in batch.getMessage()


# ------------------------------------------------------------------ limits (unit)
def test_token_buckets():
    c = Clock()
    b = TokenBuckets(per_minute=60, burst=2, clock=c, max_clients=2)
    assert b.take("a") == 0 and b.take("a") == 0
    assert b.take("a") == pytest.approx(1.0)
    c.t += 1
    assert b.take("a") == 0
    b.take("b"), b.take("c")                      # "a" is forgotten (table bound)
    assert len(b._buckets) == 2 and "a" not in b._buckets
    assert TokenBuckets(0, 1).take("x") == 0      # 0 = no limit


def test_client_key_and_proxy():
    scope = {"client": ("10.0.0.5", 1234),
             "headers": [(b"authorization", b"Bearer abc"), (b"x-forwarded-for", b"1.2.3.4, 10.0.0.1")]}
    assert client_key(scope, False).startswith("10.0.0.5|")
    assert client_key(scope, True).startswith("1.2.3.4|")
    assert client_key({"headers": []}, False) == "unknown|anonymous"
    other = dict(scope, headers=[(b"authorization", b"Bearer xyz")])
    assert client_key(other, False) != client_key(scope, False)


def test_scan_slots():
    s = ScanSlots(1)
    assert s.try_acquire() and not s.try_acquire()
    s.release()
    assert s.try_acquire()


def _run(app, scope, chunks):
    sent = []
    queue = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
             for i, c in enumerate(chunks)]

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(m):
        sent.append(m)
    asyncio.run(app(scope, receive, send))
    return sent


def test_body_limit_streaming_and_declared():
    async def reader(scope, receive, send):        # an app that reads the whole body
        while True:
            m = await receive()
            if m["type"] != "http.request" or not m.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    app = BodyLimit(reader, max_bytes=10)
    post = {"type": "http", "method": "POST", "headers": []}
    assert _run(app, post, [b"12345", b"12345"])[0]["status"] == 200
    assert _run(app, post, [b"123456", b"123456"])[0]["status"] == 413      # chunked
    declared = dict(post, headers=[(b"content-length", b"99")])
    assert _run(app, declared, [b""])[0]["status"] == 413                  # before reading
    get = {"type": "http", "method": "GET", "headers": []}
    assert _run(app, get, [b"x" * 50])[0]["status"] == 200

    async def crashes(scope, receive, send):
        await receive()
        await receive()
        raise RuntimeError("parser gave up")
    assert _run(BodyLimit(crashes, 3), post, [b"1234", b"5"])[0]["status"] == 413
    with pytest.raises(RuntimeError):
        _run(BodyLimit(crashes, 100), post, [b"1", b"2"])


# ------------------------------------------------------------------ API
@pytest.fixture
def api(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")               # the [api] extra is optional
    from fastapi.testclient import TestClient

    from api.server import create_app
    monkeypatch.setenv("AEGIS_API_RATE_PER_MINUTE", "60")
    monkeypatch.setenv("AEGIS_API_BURST", "3")
    return TestClient(create_app(_config(tmp_path), token=TOKEN, isolate=False))


def test_rate_limit_answers_429_with_retry_after(api):
    METRICS.reset()
    codes = [api.get("/version", headers=auth()).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429
    r = api.get("/version", headers=auth())
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert all(api.get("/health").status_code == 200 for _ in range(10))   # exempt
    assert METRICS.snapshot()["requests_rejected"]["rate_limited"] >= 2


def test_metrics_endpoint(api):
    METRICS.reset()
    r = api.post("/scan", headers=auth(), files={"file": ("a.pdf", make_pdf("hello"))})
    assert r.status_code == 200 and r.json()["scan_duration_ms"] >= 0
    m = api.get("/metrics", headers=auth()).json()
    assert m["files_scanned"] == 1 and m["verdicts"]["Clean"] == 1
    p = api.get("/metrics?format=prometheus", headers=auth())
    assert p.headers["content-type"].startswith("text/plain")
    assert "aegis_files_scanned_total 1" in p.text
    assert api.get("/metrics").status_code == 401


def test_declared_oversize_upload_is_refused_before_parsing(api):
    r = api.post("/scan", headers={**auth(), "content-length": str(500 * 1024 * 1024)},
                 content=b"x")
    assert r.status_code == 413


def test_busy_scanner_answers_503(api, monkeypatch):
    from api import limits
    monkeypatch.setattr(limits.ScanSlots, "try_acquire", lambda self: False)
    r = api.post("/scan", headers=auth(), files={"file": ("a.pdf", make_pdf("x"))})
    assert r.status_code == 503 and r.headers["retry-after"] == "5"


def test_bad_api_setting_fails_fast(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import importlib

    import api.server as srv
    monkeypatch.setenv("AEGIS_API_MAX_CONCURRENT_SCANS", "many")
    with pytest.raises(RuntimeError, match="AEGIS_API_MAX_CONCURRENT_SCANS"):
        srv.create_app(_config(tmp_path), token=TOKEN, isolate=False)
    importlib.reload(srv)
