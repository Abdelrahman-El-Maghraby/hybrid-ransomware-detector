"""4.8 background reliability (PR-07, PR-09, PR-10): a scheduled job that raises
does not end the background service, a file whose in-process scan raises is
reported as failed instead of being dropped, and the docs match the code."""

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
import schedule

import RansomwareScanner as RS
from engine.metrics import METRICS
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

ROOT = Path(__file__).resolve().parent.parent


class FakeScanner:
    """run_scan fails like deliver() on a full disk; the canary check works."""

    def __init__(self):
        self.canary_checks = 0
        self.scans = 0
        self.canaries = SimpleNamespace(entries=list)

    def run_scan(self):
        self.scans += 1
        raise OSError(28, "No space left on device")

    def check_canaries(self):
        self.canary_checks += 1

    def scan_mailbox_safely(self):
        pass


class FakeWatcher:
    def __init__(self):
        self.refreshed = 0

    def start(self):
        return False

    def refresh(self):
        self.refreshed += 1
        raise RuntimeError("watcher refresh broke")


@pytest.fixture
def jobs():
    schedule.clear()
    yield
    schedule.clear()


CONFIG = {"scan_interval_hours": 24, "canary_check_minutes": 5, "imap_check_minutes": 0}


def test_a_failing_job_is_logged_counted_and_the_others_still_run(jobs, caplog):
    scanner, watcher = FakeScanner(), FakeWatcher()
    RS._schedule_background_jobs(scanner, watcher, CONFIG)
    before = dict(METRICS.snapshot()["scheduled_job_failures"])
    with caplog.at_level(logging.ERROR, logger="RansomwareScanner"):
        schedule.run_all()                    # unguarded, the first raise stopped everything
        schedule.run_all()
    assert scanner.scans == 2 and scanner.canary_checks == 2 and watcher.refreshed == 2
    after = METRICS.snapshot()["scheduled_job_failures"]
    assert after["scan"] == before.get("scan", 0) + 2
    assert after["canary_refresh"] == before.get("canary_refresh", 0) + 2
    events = [r for r in caplog.records if getattr(r, "event", "") == "scheduled_job_failed"]
    assert {r.job for r in events} == {"scan", "canary_refresh"}
    assert "No space left on device" in caplog.text
    assert len(schedule.get_jobs()) == 6     # nothing cancelled (+ outbox, cloud upload, cleanup)


def test_the_loop_keeps_running_and_the_next_canary_check_runs(jobs, monkeypatch):
    scanner, watcher = FakeScanner(), FakeWatcher()
    RS._schedule_background_jobs(scanner, watcher, CONFIG)
    passes = []

    def run_pending():                                    # every job is due on each pass
        passes.append(1)
        if len(passes) == 1:
            raise RuntimeError("scheduler hiccup")
        schedule.run_all()
    monkeypatch.setattr(schedule, "run_pending", run_pending)
    sleeps = []
    RS._run_background_loop(sleep=sleeps.append, keep_going=lambda: len(passes) < 4)
    assert len(passes) == 4 and sleeps == [30] * 4
    assert scanner.canary_checks == 3 and scanner.scans == 3


def test_guarded_returns_the_job_result_when_it_works():
    assert RS._guarded("x", lambda: 42)() == 42
    assert RS._guarded("x", lambda: 1 / 0)() is None


def test_scan_failures_metric_in_prometheus():
    METRICS.job_failed("scan")
    assert 'aegis_scheduled_job_failures_total{job="scan"}' in METRICS.prometheus()


# ------------------------------------------------------------- PR-09
def test_a_file_that_vanishes_mid_scan_is_reported_as_failed(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    for n in ("a.pdf", "gone.pdf", "c.pdf"):
        (tmp_path / "scan" / n).write_bytes(make_pdf(n))
    targets = s._collect_target_files(str(tmp_path / "scan"), s._new_impact([]))
    assert len(targets) == 3
    (tmp_path / "scan" / "gone.pdf").unlink()             # after the walk, before the scan
    results = {r["file_name"]: r for r in s._scan_targets(targets)}
    assert sorted(results) == ["a.pdf", "c.pdf", "gone.pdf"]
    gone = results["gone.pdf"]
    assert gone["scan_status"] == "failed" and gone["file_size"] == 0
    assert "FileNotFoundError" in gone["scan_results"]["scan_failed"]["reason"]
    assert results["a.pdf"]["verdict"] == "Clean"


def test_a_raising_scan_gets_a_failed_result_with_its_reason(tmp_path, monkeypatch):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    for n in ("a.pdf", "bad.pdf"):
        (tmp_path / "scan" / n).write_bytes(make_pdf(n))
    real = s.scan_file

    def scan_file(path, *a, **k):
        if path.endswith("bad.pdf"):
            raise ValueError("parser bug")
        return real(path, *a, **k)
    monkeypatch.setattr(s, "scan_file", scan_file)
    seen = []
    results = s.scan_all_directories(progress_callback=lambda i, t, p, r: seen.append(i))
    assert sorted(seen) == [1, 2] and len(results) == 2
    bad = next(r for r in results if r["file_name"] == "bad.pdf")
    assert bad["scan_results"]["scan_failed"]["reason"] == "ValueError: parser bug"
    assert len(bad["sha256_hash"]) == 64


# ------------------------------------------------------------- PR-10
def _flat(text):
    return " ".join((text or "").split())


def test_docstrings_match_the_code():
    import api.limits
    assert "first X-Forwarded-For address is the client" not in _flat(api.limits.__doc__)
    assert "the LAST X-Forwarded-For entry" in _flat(api.limits.__doc__)
    assert "the LAST X-Forwarded-For entry" in _flat(api.limits.client_ip.__doc__)
    pytest.importorskip("fastapi")
    import api.server
    doc = _flat(api.server.__doc__)
    assert "each client (IP + token) gets" not in doc
    assert "every request is first limited per IP address" in doc
    assert "before the token is checked" in doc


def test_public_docs_name_no_local_download_paths():
    hits = [p.name for p in (ROOT / "docs").glob("*.md")
            if p.name != "PROJECT_REVIEW.md" and "~/Downloads" in p.read_text(encoding="utf-8")]
    assert hits == []
