"""v4.2: canary tripwires are verified within about a second of being touched,
instead of waiting for the next interval check."""

import threading
import time
from pathlib import Path

import pytest

from core.canary import CanaryManager
from core.canary_watch import WATCHDOG_AVAILABLE, CanaryWatcher

needs_watchdog = pytest.mark.skipif(not WATCHDOG_AVAILABLE, reason="watchdog not installed")


def deployed(tmp_path):
    folder = tmp_path / "Documents"
    folder.mkdir()
    mgr = CanaryManager(tmp_path / "canaries.json")
    mgr.deploy([folder])
    return mgr, folder


class Recorder:
    def __init__(self, mgr=None):
        self.mgr, self.reports, self.event = mgr, [], threading.Event()

    def __call__(self):
        self.reports.append(self.mgr.verify() if self.mgr else None)
        self.event.set()

    def wait(self, timeout=10):
        assert self.event.wait(timeout), "no verification after the file event"
        self.event.clear()


def test_relevance_rules(tmp_path):
    mgr, folder = deployed(tmp_path)
    w = CanaryWatcher(mgr, lambda: None)
    w._canaries = set(mgr.paths())
    canary = next(iter(mgr.paths()))
    assert w.is_relevant(canary)
    assert w.is_relevant(canary + ".lockbit")                 # renamed with a new extension
    assert w.is_relevant(str(folder / "HOW_TO_DECRYPT.txt"))  # ransom note next to it
    assert not w.is_relevant(str(folder / "holiday.jpg"))     # ordinary file activity


def test_bursts_are_coalesced_and_errors_do_not_escape(tmp_path):
    mgr, _ = deployed(tmp_path)
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("alarm failed")

    w = CanaryWatcher(mgr, boom, debounce=0.2)
    for _ in range(50):
        w.poke()
    time.sleep(0.6)
    assert calls == [1] and w.fired == 1
    w.poke()
    time.sleep(0.6)
    assert w.fired == 2


@needs_watchdog
def test_modifying_a_canary_triggers_a_verification(tmp_path):
    mgr, _ = deployed(tmp_path)
    rec = Recorder(mgr)
    w = CanaryWatcher(mgr, rec, debounce=0.3)
    assert w.start() and w.running
    try:
        canary = Path(next(iter(mgr.paths())))
        canary.write_bytes(b"\x8f" * 4096)                  # "encrypted" in place
        rec.wait()
        assert rec.reports[-1].triggered
    finally:
        w.stop()
    assert not w.running


@needs_watchdog
def test_rename_and_ransom_note_trigger(tmp_path):
    mgr, folder = deployed(tmp_path)
    rec = Recorder(mgr)
    w = CanaryWatcher(mgr, rec, debounce=0.3)
    w.start()
    try:
        canary = Path(next(iter(mgr.paths())))
        canary.rename(str(canary) + ".locked")
        rec.wait()
        assert rec.reports[-1].triggered
        (folder / "README_RESTORE_FILES.txt").write_text("pay up")
        rec.wait()
    finally:
        w.stop()


@needs_watchdog
def test_verification_itself_does_not_loop(tmp_path):
    """verify() reads every canary; read events must not start another verification."""
    mgr, folder = deployed(tmp_path)
    rec = Recorder(mgr)
    w = CanaryWatcher(mgr, rec, debounce=0.2)
    w.start()
    try:
        (folder / "HOW_TO_DECRYPT.txt").write_text("x")
        rec.wait()
        time.sleep(1.5)                                     # give a loop time to show up
        assert w.fired == 1
        (folder / "notes.txt").write_text("ordinary edit")  # unrelated activity is ignored
        time.sleep(1.0)
        assert w.fired == 1
    finally:
        w.stop()


@needs_watchdog
def test_nothing_deployed_means_nothing_watched(tmp_path):
    w = CanaryWatcher(CanaryManager(tmp_path / "none.json"), lambda: None)
    assert w.start() is False and not w.running


@needs_watchdog
def test_refresh_follows_new_deployments(tmp_path):
    mgr = CanaryManager(tmp_path / "canaries.json")
    w = CanaryWatcher(mgr, lambda: None)
    assert not w.start()
    (tmp_path / "Desk").mkdir()
    mgr.deploy([tmp_path / "Desk"])
    assert w.refresh() and w.running
    w.stop()
