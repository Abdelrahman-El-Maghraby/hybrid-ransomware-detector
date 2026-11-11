"""M17: a JSON Lines or report write error must not drop the webhook and e-mail
alerts. Before the fix, deliver() wrote JSON Lines before queuing the alerts and
did not catch the error, and run_scan, --scan-file and the folder monitor wrote
the report before calling deliver(), so either failure meant no alert at all."""

import logging
from types import SimpleNamespace

import pytest

import RansomwareScanner as RS
from core import folder_watch as FW
from core.outputs import deliver
from tests.test_alerts import _result
from tests.test_scanner_integration import _config


def _alert_config(tmp_path, **over):
    return _config(tmp_path, webhook_url="https://siem.example/hook", webhook_min_verdict="High",
                   outbox_dir=str(tmp_path / "outbox"), **over)


def _pending(tmp_path):
    return list((tmp_path / "outbox" / "pending").glob("*.json"))


@pytest.fixture
def receiver_down(monkeypatch):
    def post(*a, **k):
        raise ConnectionError("receiver down")         # the alert stays in the outbox
    monkeypatch.setattr("requests.post", post)


def test_an_unwritable_jsonl_path_keeps_the_alerts(tmp_path, receiver_down, caplog):
    (tmp_path / "out.jsonl").mkdir()                   # JSONL_PATH is a directory
    cfg = _alert_config(tmp_path, jsonl_path=str(tmp_path / "out.jsonl"))
    with caplog.at_level(logging.ERROR, logger="RansomwareScanner"):
        deliver([_result("High")], cfg)
    assert len(_pending(tmp_path)) == 1
    assert any(getattr(r, "event", "") == "jsonl_error" for r in caplog.records)


def _broken_report(*a, **k):
    raise OSError("report folder is read-only")


def test_run_scan_delivers_when_the_report_fails(tmp_path, monkeypatch):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    delivered = []
    monkeypatch.setattr(s, "scan_all_directories", lambda: [_result("High")])
    monkeypatch.setattr(s, "generate_report", _broken_report)
    monkeypatch.setattr("core.outputs.deliver", lambda results, cfg: delivered.extend(results))
    with pytest.raises(OSError):                       # the report error is still reported
        s.run_scan()
    assert [r["verdict"] for r in delivered] == ["High"]


@pytest.mark.parametrize("not_scanned", [0, 1])
def test_cli_scan_file_delivers_and_keeps_its_exit_status_when_the_report_fails(
        tmp_path, monkeypatch, not_scanned):
    target = tmp_path / "a.pdf"
    target.write_bytes(b"%PDF-1.4")
    scanner = SimpleNamespace(scan_one=lambda p: _result("High"), generate_report=_broken_report,
                              last_not_scanned=not_scanned)
    delivered = []
    monkeypatch.setattr("core.outputs.deliver", lambda results, cfg: delivered.extend(results))
    args = SimpleNamespace(scan_file=str(target), scan_now=False, background=False)
    expected = SystemExit if not_scanned else OSError
    with pytest.raises(expected) as info:
        RS._scan_or_schedule(args, scanner)
    if not_scanned:
        assert info.value.code == RS.EXIT_ISOLATION_UNAVAILABLE
    assert len(delivered) == 1


def test_folder_monitor_delivers_when_the_report_fails(tmp_path, monkeypatch, caplog):
    watch = tmp_path / "watch"
    watch.mkdir()
    scanner = SimpleNamespace(config={}, last_not_scanned=0, generate_report=_broken_report,
                              _scan_targets=lambda paths: [_result("High")])
    delivered = []
    monkeypatch.setattr("core.outputs.deliver", lambda results, cfg: delivered.extend(results))
    with caplog.at_level(logging.ERROR, logger="RansomwareScanner"):
        FW.FolderMonitor(scanner, [str(watch)]).scan_batch([str(watch / "a.pdf")])
    assert len(delivered) == 1
    assert any("report failed" in r.getMessage() for r in caplog.records)
