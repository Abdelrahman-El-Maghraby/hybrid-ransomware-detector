"""M6: what a scan worker logs while it scans a file reaches the parent's log
handlers (log file, GUI log, cloud event spool). Before the fix the worker
logger was at WARNING with no handler, so INFO events such as scan_completed
and external_share (THREAT_MODEL section 6) were dropped, and warnings such as
layer_error only reached the worker's stderr."""

import logging
import pickle

import RansomwareScanner as RS
from engine import workers as W
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

GOOD = "tests.worker_fakes:make"


def _isolated(tmp_path):
    return RS.RansomwareScanner(_config(
        tmp_path, _scanner_factory=GOOD, scan_timeout_seconds=60, scan_workers=1,
        data_dir=str(tmp_path / "data"), outbox_dir=str(tmp_path / "outbox")))


def test_scan_events_from_an_isolated_worker_reach_the_parent_log(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="RansomwareScanner")
    s = _isolated(tmp_path)
    path = tmp_path / "scan" / "invoice.pdf"
    path.write_bytes(make_pdf("hello"))
    result = s.scan_one(str(path))
    assert result["provenance"]["isolation"] == "worker"
    done = [r for r in caplog.records if getattr(r, "event", "") == "scan_completed"]
    assert len(done) == 1
    assert done[0].path.endswith("invoice.pdf") and done[0].verdict == result["verdict"]
    assert done[0].getMessage().startswith("Scan completed for")


def test_worker_start_up_lines_are_not_repeated_in_the_parent(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="RansomwareScanner")
    s = _isolated(tmp_path)
    caplog.clear()
    path = tmp_path / "scan" / "a.pdf"
    path.write_bytes(make_pdf("a"))
    s.scan_one(str(path))
    assert not [r for r in caplog.records if "Scanner initialized" in r.getMessage()]


def test_buffer_limits_records_and_keeps_them_picklable(caplog):
    # set_level also lifts a logging.disable() an earlier test may have left on
    caplog.set_level(logging.INFO, logger="RansomwareScanner.test_worker_logs")
    buf = W._WorkerLogBuffer(limit=3)
    log = logging.getLogger("RansomwareScanner.test_worker_logs")
    log.addHandler(buf)
    log.propagate = False
    log.setLevel(logging.INFO)
    try:
        log.info("shared %s", "x", extra={"event": "external_share", "shared": [{"a": "b"}],
                                          "obj": object()})
        for i in range(5):
            log.warning("w%d", i)
    finally:
        log.removeHandler(buf)
    records = buf.take()
    pickle.dumps(records)
    assert [r["msg"] for r in records[:3]] == ["shared x", "w0", "w1"]
    assert records[0]["shared"] == [{"a": "b"}] and records[0]["obj"].startswith("<object")
    assert "3 log record(s)" in records[-1]["msg"]
    assert buf.take() == []


def test_replayed_records_respect_the_parent_level(caplog):
    caplog.set_level(logging.WARNING, logger="RansomwareScanner")
    info = logging.makeLogRecord({"name": "RansomwareScanner", "levelno": logging.INFO,
                                  "levelname": "INFO", "msg": "quiet"}).__dict__
    warn = dict(info, levelno=logging.WARNING, levelname="WARNING", msg="loud")
    W.replay_worker_logs([info, warn, "not a record"])
    assert [r.getMessage() for r in caplog.records] == ["loud"]
