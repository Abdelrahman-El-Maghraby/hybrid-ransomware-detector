"""H1: a FIFO, or a symlink to a device, in a scanned or watched folder must
never block the main process. Before the fix, a FIFO named like a document
was collected as a scan target; after its worker timed out, the parent opened
it to hash it and waited forever (and /dev/zero was read forever).

Every check that could block runs in a daemon thread with a deadline, so a
regression fails the test instead of hanging the suite."""

import hashlib
import os
import threading

import pytest

import RansomwareScanner as RS
from core import folder_watch as FW
from core.canary import CanaryManager
from engine.fsutil import is_regular_file, open_regular
from engine.workers import failure_result
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

pytestmark = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")

DEADLINE = 10.0
DEVICE = "/dev/zero"


def _within_deadline(fn):
    """Run fn() in a daemon thread; fail (instead of hanging) past the deadline."""
    box = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as e:          # re-raised in the test thread
            box["error"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(DEADLINE)
    assert not t.is_alive(), "blocked on a non-regular file"
    if "error" in box:
        raise box["error"]
    return box.get("value")


@pytest.fixture
def folder(tmp_path):
    scan = tmp_path / "scan"
    scan.mkdir(exist_ok=True)
    (scan / "real.pdf").write_bytes(make_pdf("real"))
    os.mkfifo(scan / "pipe.pdf")
    (scan / "link.pdf").symlink_to(scan / "real.pdf")
    if os.path.exists(DEVICE):
        (scan / "zero.pdf").symlink_to(DEVICE)
    return scan


def test_fsutil_only_opens_regular_files(folder):
    assert is_regular_file(str(folder / "real.pdf"))
    assert is_regular_file(str(folder / "link.pdf"))           # links to files still count
    assert not is_regular_file(str(folder / "pipe.pdf"))
    assert not is_regular_file(str(folder))
    assert not is_regular_file(str(folder / "missing.pdf"))
    assert _within_deadline(lambda: open_regular(str(folder / "pipe.pdf"))) is None
    if os.path.exists(DEVICE):
        assert not is_regular_file(str(folder / "zero.pdf"))
        assert _within_deadline(lambda: open_regular(str(folder / "zero.pdf"))) is None
    fh = open_regular(str(folder / "real.pdf"))
    assert fh is not None
    with fh:
        assert fh.read() == (folder / "real.pdf").read_bytes()
    with pytest.raises(OSError):
        open_regular(str(folder / "missing.pdf"))


def test_directory_walk_skips_fifos_and_devices(tmp_path, folder):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    targets = _within_deadline(lambda: s._collect_target_files(str(folder), s._new_impact([])))
    assert sorted(os.path.basename(t) for t in targets) == ["link.pdf", "real.pdf"]


def test_failure_result_does_not_open_a_fifo(tmp_path, folder):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    r = _within_deadline(lambda: failure_result(s, str(folder / "pipe.pdf"), "timed out"))
    assert r["md5_hash"] == "" and r["sha256_hash"] == ""
    assert r["scan_status"] == "failed"
    if os.path.exists(DEVICE):
        r = _within_deadline(lambda: failure_result(s, str(folder / "zero.pdf"), "timed out"))
        assert r["sha256_hash"] == ""


def test_hashes_of_regular_files_are_unchanged(tmp_path, folder):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    data = (folder / "real.pdf").read_bytes()
    assert s.calculate_hashes(str(folder / "real.pdf")) == {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()}


def test_a_directory_scan_with_a_fifo_completes(tmp_path, folder):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    results = _within_deadline(lambda: s.scan_directory(str(folder)))
    assert sorted(r["file_name"] for r in results) == ["link.pdf", "real.pdf"]


def test_folder_monitor_ignores_fifos(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    watch = tmp_path / "watch"
    watch.mkdir()
    os.mkfifo(watch / "pipe.pdf")
    m = FW.FolderMonitor(s, [str(watch)], clock=lambda: 0.0)
    _within_deadline(lambda: m.note(str(watch / "pipe.pdf")))
    assert m.status()["pending"] == 0 and m.counts["ignored"] == 1
    assert _within_deadline(lambda: m._new_content(str(watch / "pipe.pdf"))) is False


def test_a_canary_replaced_by_a_fifo_is_reported_not_hung(tmp_path):
    folder = tmp_path / "Documents"
    folder.mkdir()
    mgr = CanaryManager(tmp_path / "data" / "canaries.json")
    created = mgr.deploy([folder])
    victim = created[0]["path"]
    os.unlink(victim)
    os.mkfifo(victim)
    report = _within_deadline(mgr.verify)
    assert report.triggered
    assert [(f.path, f.status) for f in report.findings] == [(str(victim), "modified")]
    assert "not a regular file" in report.findings[0].evidence
