"""I-4: in the background service a long scheduled scan no longer holds back the
short jobs (alert-outbox retries, canary checks, cloud uploads). Scans and
mailbox checks stay on the main loop, so they still never overlap. Inert fakes
only: no file is scanned and no network is used."""

import datetime
import threading
import time
from types import SimpleNamespace

import pytest
import schedule

import RansomwareScanner as RS

CONFIG = {"scan_interval_hours": 24, "canary_check_minutes": 5, "imap_check_minutes": 1,
          "imap_host": "imap.invalid", "imap_folder": "INBOX"}


class SlowScanner:
    """run_scan blocks until released; it records overlapping scans."""

    def __init__(self):
        self.canaries = SimpleNamespace(entries=list)
        self.release = threading.Event()
        self.scanning = threading.Event()
        self.canary_checked = threading.Event()
        self.active = 0
        self.most_at_once = 0
        self._guard = threading.Lock()

    def _heavy(self):
        with self._guard:
            self.active += 1
            self.most_at_once = max(self.most_at_once, self.active)
        self.scanning.set()
        self.release.wait(5)
        with self._guard:
            self.active -= 1

    def run_scan(self):
        self._heavy()

    def scan_mailbox_safely(self):
        self._heavy()

    def check_canaries(self):
        self.canary_checked.set()


class Watcher:
    def start(self):
        return False

    def refresh(self):
        pass


@pytest.fixture
def service(monkeypatch):
    schedule.clear()
    RS.SERVICE_JOBS.clear()
    RS.CANARY_JOBS.clear()
    outbox, outbox_release = threading.Event(), threading.Event()
    outbox_release.set()

    def flush(cfg):
        outbox.set()
        outbox_release.wait(5)
    monkeypatch.setattr("core.outbox.flush_pending", flush)
    monkeypatch.setattr("core.cloud.run_uploads", lambda *a, **k: None)
    scanner = SlowScanner()
    RS._schedule_background_jobs(scanner, Watcher(), CONFIG)
    due = datetime.datetime.now() - datetime.timedelta(seconds=1)
    for job in schedule.jobs + RS.SERVICE_JOBS.jobs + RS.CANARY_JOBS.jobs:
        job.next_run = due                       # every job is due now
    stop = threading.Event()
    main = threading.Thread(target=RS._run_background_loop, daemon=True, kwargs={
        "sleep": lambda _s: time.sleep(0.01), "keep_going": lambda: not stop.is_set()})
    jobs = RS._ServiceJobThread(tick=0.01)
    canary = RS._ServiceJobThread(RS.CANARY_JOBS, tick=0.01)
    yield SimpleNamespace(scanner=scanner, outbox=outbox, outbox_release=outbox_release,
                          main=main, jobs=jobs, canary=canary)
    scanner.release.set()
    outbox_release.set()
    stop.set()
    jobs.stop(2)
    canary.stop(2)
    if main.is_alive():
        main.join(5)
    schedule.clear()
    RS.SERVICE_JOBS.clear()
    RS.CANARY_JOBS.clear()


def test_only_scans_and_mailbox_checks_stay_on_the_main_loop(service):
    main = sorted(j.job_func.__name__ for j in schedule.jobs)
    short = sorted(j.job_func.__name__ for j in RS.SERVICE_JOBS.jobs)
    canary = sorted(j.job_func.__name__ for j in RS.CANARY_JOBS.jobs)
    assert main == ["guarded_mailbox", "guarded_scan"]
    assert short == ["guarded_alert_outbox", "guarded_cloud_cleanup", "guarded_cloud_upload"]
    assert canary == ["guarded_canary_check", "guarded_canary_refresh"]


def test_alert_retries_and_canary_checks_run_during_a_long_scan(service):
    service.main.start()
    service.jobs.start()
    service.canary.start()
    assert service.scanner.scanning.wait(2)
    # before I-4 both waited for the scan (the scan here would hold them 5 s)
    assert service.outbox.wait(2)
    assert service.scanner.canary_checked.wait(2)
    assert service.scanner.active == 1           # the scan is still running


def test_a_slow_outbox_flush_does_not_hold_back_the_canary_check(service):
    """RV-C1: the outbox has network timeouts but no total budget; on the shared
    short-job thread a hung flush delayed the scheduled canary check."""
    later = datetime.datetime.now() + datetime.timedelta(days=1)
    for job in RS.SERVICE_JOBS.jobs + RS.CANARY_JOBS.jobs:
        job.next_run = later
    outbox = next(j for j in RS.SERVICE_JOBS.jobs if j.job_func.__name__ == "guarded_alert_outbox")
    outbox.next_run = datetime.datetime.now() - datetime.timedelta(seconds=1)
    service.outbox_release.clear()               # the flush hangs until released
    service.jobs.start()
    service.canary.start()
    assert service.outbox.wait(2)
    for job in RS.SERVICE_JOBS.jobs + RS.CANARY_JOBS.jobs:  # the next canary check falls due
        if job.job_func.__name__ == "guarded_canary_check":
            job.next_run = datetime.datetime.now() - datetime.timedelta(seconds=1)
    assert service.scanner.canary_checked.wait(2)
    service.outbox_release.set()


def test_scans_and_mailbox_checks_never_overlap(service):
    service.main.start()
    assert service.scanner.scanning.wait(2)
    time.sleep(0.2)                               # the mailbox check is due as well
    assert service.scanner.most_at_once == 1
    service.scanner.release.set()


def test_the_short_job_thread_stops_promptly():
    jobs = RS._ServiceJobThread(jobs=schedule.Scheduler(), tick=30)
    jobs.start()
    started = time.monotonic()
    assert jobs.stop(timeout=5) is True
    assert time.monotonic() - started < 2         # it does not sleep out its 30 s tick
