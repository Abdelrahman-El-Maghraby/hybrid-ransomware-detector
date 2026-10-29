"""4.8 folder monitoring (F1, D-B) and quarantine integration (F3); I-1, I-2, I-3.
Files are scanned once after they settle, only in isolated workers, never from
the app's own folders or through links, and monitoring pauses instead of
parsing in-process when workers cannot start."""

import os
import time

import pytest

import RansomwareScanner as RS
from core import folder_watch as FW
from core.outbox import verdict_alert
from core.outputs import alert_payload
from core.quarantine import QuarantineError
from engine.validation import ConfigError, check_config, validate_config
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

GOOD = "tests.worker_fakes:make"
BROKEN = "tests.worker_fakes:does_not_exist"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _scanner(tmp_path, factory=GOOD, **over):
    opts = dict(_scanner_factory=factory, scan_timeout_seconds=4, scan_workers=1,
                data_dir=str(tmp_path / "data"), outbox_dir=str(tmp_path / "outbox"))
    opts.update(over)
    return RS.RansomwareScanner(_config(tmp_path, **opts))


def _watch(tmp_path):
    w = tmp_path / "watch"
    w.mkdir(exist_ok=True)
    return w


def _monitor(tmp_path, scanner, clock=None, **kw):
    return FW.FolderMonitor(scanner, [str(_watch(tmp_path))], clock=clock or Clock(), **kw)


def _pdf(path, text="hello"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(make_pdf(text))
    return path


# ------------------------------------------------------------------ what is watched
def test_own_folders_links_and_other_files_are_never_scanned(tmp_path):
    w = _watch(tmp_path)
    s = _scanner(tmp_path, report_directory=str(w / "reports"),
                 quarantine_dir=str(w / "vault"), jsonl_path=str(w / "out.jsonl"))
    m = _monitor(tmp_path, s)
    ok = _pdf(w / "sub" / "invoice.pdf")
    assert m.wanted(str(ok)) == FW._real(str(ok))
    for own in (_pdf(w / "reports" / "x.pdf"), _pdf(w / "vault" / "y.pdf"),
                _pdf(w / "aegis_worker_123_x" / "m.pdf"), _pdf(w / "~$lock.pdf")):
        assert m.wanted(str(own)) is None, own
    (w / "notes.xyz").write_text("x")
    assert m.wanted(str(w / "notes.xyz")) is None                   # not a scanned extension
    outside = _pdf(tmp_path / "elsewhere" / "secret.pdf")
    if hasattr(os, "symlink"):
        try:
            os.symlink(outside, w / "link.pdf")
            os.symlink(outside.parent, w / "linkdir", target_is_directory=True)
        except OSError:
            pytest.skip("cannot create symlinks here")
        assert m.wanted(str(w / "link.pdf")) is None                # never followed
        assert m.wanted(str(w / "linkdir" / "secret.pdf")) is None  # resolves outside the root
    canary = s.deploy_canaries([str(w)])
    if canary:
        assert m.wanted(canary[0]["path"]) is None


def test_a_file_is_scanned_once_after_it_settles(tmp_path):
    clock = Clock()
    s = _scanner(tmp_path)
    m = _monitor(tmp_path, s, clock, settle=2)
    scanned = []
    m.scan_batch = lambda paths: scanned.append(list(paths)) or [{"file_path": p} for p in paths]
    f = _pdf(_watch(tmp_path) / "a.pdf", "one")
    m.note(str(f))
    clock.now += 1
    assert m.scan_due() == [] and scanned == []                     # still settling
    with open(f, "ab") as fh:                                       # still being written
        fh.write(b"%more")
    m.note(str(f))
    clock.now += 1.5
    assert m.scan_due() == []
    clock.now += 2
    m.scan_due()
    assert scanned == [[FW._real(str(f))]]
    for _ in range(3):                                              # repeated events, no change
        m.note(str(f))
    clock.now += 3
    m.scan_due()
    assert len(scanned) == 1
    os.utime(f, None)                                               # touched, same content
    st = os.stat(f)
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    m.note(str(f))
    clock.now += 3
    m.scan_due()
    assert len(scanned) == 1 and m.status()["duplicates"] >= 1
    f.write_bytes(make_pdf("changed"))                              # new content: rescanned
    m.note(str(f))
    clock.now += 3
    m.scan_due()
    assert len(scanned) == 2


def test_a_file_that_vanishes_before_it_settles_is_dropped(tmp_path):
    clock = Clock()
    m = _monitor(tmp_path, _scanner(tmp_path), clock)
    m.scan_batch = lambda paths: pytest.fail("nothing should be scanned")
    f = _pdf(_watch(tmp_path) / "gone.pdf")
    m.note(str(f))
    f.unlink()
    clock.now += 5
    assert m.scan_due() == [] and m.status()["pending"] == 0


def test_the_queue_is_bounded(tmp_path):
    m = _monitor(tmp_path, _scanner(tmp_path), max_queue=2)
    for i in range(5):
        m.note(str(_pdf(_watch(tmp_path) / f"f{i}.pdf")))
    assert m.status()["pending"] == 2 and m.status()["dropped"] == 3


def test_monitoring_pauses_and_never_parses_in_process_when_workers_cannot_start(tmp_path, monkeypatch):
    clock = Clock()
    s = _scanner(tmp_path, BROKEN)
    monkeypatch.setattr(s, "scan_file", lambda *a, **k: pytest.fail("parsed in-process"))
    m = _monitor(tmp_path, s, clock, retry_minutes=1)
    f = _pdf(_watch(tmp_path) / "a.pdf")
    m.note(str(f))
    clock.now += 5
    results = m.scan_due()
    assert results and results[0]["provenance"]["isolation"] == "unavailable"
    assert "could not start" in m.status()["paused"]
    clock.now += 5
    assert m.due() == []                                            # paused: nothing handed out
    s.config["_scanner_factory"] = GOOD
    clock.now += 61                                                 # the retry
    again = m.scan_due()
    assert again and again[0]["provenance"]["isolation"] == "worker" and not m.status()["paused"]


# ------------------------------------------------------------------ I-1 / I-2 (real events)
def _wait(cond, seconds=60):
    end = time.monotonic() + seconds
    while not cond() and time.monotonic() < end:
        time.sleep(0.2)
    return cond()


@pytest.mark.skipif(not FW.WATCHDOG_AVAILABLE, reason="watchdog not installed")
def test_i1_create_modify_rename_each_scanned_once_into_the_report(tmp_path):
    w = _watch(tmp_path)
    s = _scanner(tmp_path, report_directory=str(w / "reports"),
                 jsonl_path=str(tmp_path / "out.jsonl"))
    seen = []
    m = FW.FolderMonitor(s, [str(w)], settle=0.6, on_results=seen.extend)
    assert m.start()
    try:
        time.sleep(0.5)
        a = _pdf(w / "a.pdf", "first")
        assert _wait(lambda: any(r["file_name"] == "a.pdf" for r in seen))
        a.write_bytes(make_pdf("second version"))                   # modified
        assert _wait(lambda: sum(r["file_name"] == "a.pdf" for r in seen) == 2)
        b = w / "staged.tmp"
        b.write_bytes(make_pdf("third"))
        os.replace(b, w / "renamed.pdf")                            # renamed into a .pdf
        assert _wait(lambda: any(r["file_name"] == "renamed.pdf" for r in seen))
        time.sleep(2.5)                                             # nothing more arrives
    finally:
        m.stop()
    names = [r["file_name"] for r in seen]
    assert names.count("a.pdf") == 2 and names.count("renamed.pdf") == 1
    assert all(r["provenance"]["isolation"] == "worker" for r in seen)
    reports = list((w / "reports").glob("ransomware_scan_*.json"))
    assert reports                                                  # in the report, not rescanned
    assert not any(str(w / "reports") in r["file_path"] for r in seen)
    assert (tmp_path / "out.jsonl").read_text().count("\n") == len(seen)


@pytest.mark.skipif(not FW.WATCHDOG_AVAILABLE, reason="watchdog not installed")
def test_i2_a_hanging_file_fails_after_the_timeout_and_the_watcher_stays_responsive(tmp_path):
    w = _watch(tmp_path)
    s = _scanner(tmp_path, scan_timeout_seconds=3)
    seen = []
    m = FW.FolderMonitor(s, [str(w)], settle=0.5, on_results=seen.extend)
    assert m.start()
    try:
        time.sleep(0.5)
        _pdf(w / "hang.pdf")
        assert _wait(lambda: m.status()["pending"] == 0 and m.status()["queued"] >= 1, 20)
        time.sleep(1.0)                                             # the hang is now in a worker
        _pdf(w / "ok.pdf")                                          # recorded during the hang
        assert _wait(lambda: m.status()["queued"] >= 2, 10)
        assert _wait(lambda: {r["file_name"] for r in seen} >= {"hang.pdf", "ok.pdf"}, 90)
    finally:
        m.stop()
    by = {r["file_name"]: r for r in seen}
    assert "timed out after 3s" in by["hang.pdf"]["scan_results"]["scan_failed"]["reason"]
    assert by["ok.pdf"]["verdict"] == "Clean"


# ------------------------------------------------------------------ I-3 / F3: quarantine
def test_i3_a_monitored_file_is_quarantined_and_restored_without_overwrite(tmp_path):
    pytest.importorskip("cryptography")
    clock = Clock()
    s = _scanner(tmp_path, auto_quarantine="medium", scan_timeout_seconds=3,
                 quarantine_dir=str(tmp_path / "vault"), keystore_dir=str(tmp_path / "keys"))
    m = _monitor(tmp_path, s, clock)
    f = _pdf(_watch(tmp_path) / "hang.pdf")                         # scan_failed: Medium
    original = f.read_bytes()
    m.note(str(f))
    clock.now += 5
    [r] = m.scan_due()
    q = r["quarantine"]
    assert r["verdict"] == "Medium" and q["original_removed"] and not f.exists()
    assert s.quarantine_vault.verify(q["id"])
    alert = verdict_alert(r)
    assert "quarantined" in alert["email"]["reason_codes"]
    assert alert["webhook"]["quarantine"] == {"id": q["id"], "original_removed": True}
    f.write_bytes(b"a new file with the same name")                 # restore never overwrites
    restored = s.quarantine_vault.restore(q["id"])
    assert restored != f and restored.read_bytes() == original
    assert f.read_bytes() == b"a new file with the same name"


def test_a_file_swapped_in_after_the_scan_is_not_quarantined(tmp_path):
    pytest.importorskip("cryptography")
    s = _scanner(tmp_path, quarantine_dir=str(tmp_path / "vault"),
                 keystore_dir=str(tmp_path / "keys"))
    f = _pdf(_watch(tmp_path) / "x.pdf", "scanned")
    result = {"file_path": str(f), "verdict": "High", "risk_score": 80,
              "sha256_hash": s.calculate_hashes(str(f))["sha256"]}
    f.write_bytes(make_pdf("swapped in by a rename"))               # the race (TMA-5)
    with pytest.raises(QuarantineError, match="changed after it was scanned"):
        s.quarantine_file(str(f), reason="test", result=result)
    assert f.exists() and s.quarantine_vault.list() == []
    s.config["auto_quarantine"] = "high"
    s._maybe_auto_quarantine(result)
    assert "changed after it was scanned" in result["quarantine"]["error"]
    assert alert_payload(result)["quarantine"]["error"].startswith("The file changed")


# ------------------------------------------------------------------ settings
def test_monitoring_is_off_without_watch_dirs_and_desktop_only(tmp_path):
    s = _scanner(tmp_path)
    assert FW.monitor_from_config(s, {"watch_dirs": ""}) is None
    m = FW.monitor_from_config(s, {"watch_dirs": f"{_watch(tmp_path)};/no/such/dir"})
    assert m is not None and len(m.roots) == 1 and m.missing == ["/no/such/dir"]
    import engine.config as cfg_mod
    for change in ({"intel_socket": "/x.sock", "intel_token": "t" * 40},
                   {"profile": "production", "llm_provider": "none"}):
        with pytest.raises(ConfigError, match="desktop feature"):
            check_config({**cfg_mod.CONFIG, "watch_dirs": str(tmp_path), **change}, env_problems=())
    _, warnings = validate_config({**cfg_mod.CONFIG, "watch_dirs": "/no/such/dir"})
    assert any("is not a folder" in w for w in warnings)
    with pytest.raises(ConfigError, match="WATCH_MAX_QUEUE=0"):
        check_config({**cfg_mod.CONFIG, "watch_max_queue": 0}, env_problems=())


def test_split_dirs():
    sep = ";"
    assert FW.split_dirs(f"/a{sep} /b ;") == ["/a", "/b"]
    assert FW.split_dirs(["~/x"]) == [os.path.expanduser("~/x")]
