"""Isolated, parallel folder scans: a file that hangs, kills or exhausts its worker
is reported (scan_failed) and the scan carries on."""

import sys
import threading

import pytest

import RansomwareScanner as RS
from engine.workers import default_workers
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config


def _setup(tmp_path, names, **over):
    opts = dict(_scanner_factory="tests.worker_fakes:make", scan_timeout_seconds=8, scan_workers=2)
    opts.update(over)
    cfg = _config(tmp_path, **opts)
    for n in names:
        (tmp_path / "scan" / n).write_bytes(make_pdf(f"text of {n}"))
    return RS.RansomwareScanner(cfg)


def test_parallel_scan_matches_in_process_results(tmp_path):
    names = [f"doc{i}.pdf" for i in range(5)]
    iso = _setup(tmp_path, names)
    a = iso.scan_all_directories()
    seq = RS.RansomwareScanner(dict(iso.config, isolate_scans=False))
    b = seq.scan_all_directories()
    key = lambda rs: [(r["file_name"], r["verdict"], r["risk_score"], r["sha256_hash"]) for r in rs]
    assert key(a) == key(b) and len(a) == 5


def test_hang_and_crash_become_findings_and_the_scan_continues(tmp_path):
    s = _setup(tmp_path, ["hang.pdf", "exit.pdf", "ok1.pdf", "ok2.pdf"])
    seen = []
    res = {r["file_name"]: r for r in s.scan_all_directories(
        progress_callback=lambda i, t, p, r: seen.append(i))}
    assert sorted(seen) == [1, 2, 3, 4]
    for bad, why in (("hang.pdf", "timed out"), ("exit.pdf", "died")):
        r = res[bad]
        assert r["verdict"] == "Medium" and why in r["scan_results"]["scan_failed"]["reason"]
        assert r["score_breakdown"]["contributions"][0]["indicator"] == "scan_failed"
        assert len(r["sha256_hash"]) == 64
    assert res["ok1.pdf"]["verdict"] == "Clean" and res["ok2.pdf"]["verdict"] == "Clean"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is enforced on Linux")
def test_memory_limit_stops_runaway_allocation(tmp_path):
    s = _setup(tmp_path, ["hog.pdf", "ok.pdf"], worker_memory_mb=1024)
    res = {r["file_name"]: r for r in s.scan_all_directories()}
    assert "MemoryError" in res["hog.pdf"]["scan_results"]["scan_failed"]["reason"]
    assert res["ok.pdf"]["verdict"] == "Clean"


def test_cancel_stops_handing_out_files(tmp_path):
    s = _setup(tmp_path, [f"d{i}.pdf" for i in range(6)], scan_workers=1)
    stop = threading.Event()
    out = s.scan_all_directories(progress_callback=lambda i, t, p, r: stop.set(), cancel_event=stop)
    assert 1 <= len(out) < 6


def test_worker_count():
    assert default_workers({"scan_workers": 3}) == 3
    assert default_workers({"scan_workers": 3, "virustotal_api_key": "k",
                            "virustotal_requests_per_minute": 4}) == 1
    assert 1 <= default_workers({}) <= 4


def test_workers_that_cannot_start_fall_back_to_in_process(tmp_path):
    s = _setup(tmp_path, ["a.pdf", "b.pdf", "c.pdf"],
               _scanner_factory="tests.worker_fakes:does_not_exist")
    res = s.scan_all_directories()
    assert sorted(r["file_name"] for r in res) == ["a.pdf", "b.pdf", "c.pdf"]
    assert all(r["verdict"] == "Clean" for r in res)
