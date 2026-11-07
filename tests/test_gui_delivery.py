"""H3: scans started from the GUI (manual or scheduled) reach the configured
outputs. Before the fix, ScanController wrote the report but never called
core.outputs.deliver(), so no JSON Lines record and no webhook or e-mail
alert left the app for a GUI scan, unlike the CLI, the background service and
folder monitoring."""

import json
import logging
import queue
from types import SimpleNamespace

import pytest

from aegis_gui.state import ScanController


def _result(name, verdict):
    return {"schema_version": "1.4", "file_path": f"/data/{name}", "file_name": name,
            "sha256_hash": "ab" * 32, "scan_time": "2026-11-08 12:00:00",
            "verdict": verdict, "risk_score": 85 if verdict == "Critical" else 0,
            "is_malicious": verdict != "Clean", "scan_status": "complete",
            "score_breakdown": {"contributions": []}}


def _scanner(tmp_path, results, report=lambda r, impact=None: "report"):
    return SimpleNamespace(
        config={"jsonl_path": str(tmp_path / "results.jsonl")},
        scan_directory=lambda target, cb, ev: list(results),
        scan_all_directories=lambda cb, ev: list(results),
        scan_one=lambda target: results[0],
        last_impact=None, last_not_scanned=0, generate_report=report)


def _run(scanner, mode="dir", target="/data"):
    bus: queue.Queue = queue.Queue()
    c = ScanController(bus)
    assert c.start(scanner, mode, target)
    c.thread.join(30)
    events = []
    while not bus.empty():
        events.append(bus.get_nowait())
    return events


def _jsonl(tmp_path):
    path = tmp_path / "results.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("mode", ["file", "dir", "all"])
def test_gui_scans_deliver_their_results(tmp_path, mode):
    results = [_result("a.docm", "Critical"), _result("b.pdf", "Clean")][:1 if mode == "file" else 2]
    events = _run(_scanner(tmp_path, results), mode)
    assert [e[0] for e in events if e[0] in ("scan_done", "scan_error")] == ["scan_done"]
    assert [r["file_name"] for r in _jsonl(tmp_path)] == [r["file_name"] for r in results]


def test_webhook_alerts_are_queued_for_a_gui_scan(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("core.outbox.queue_and_send", lambda alerts, cfg: calls.append(alerts))
    s = _scanner(tmp_path, [_result("a.docm", "Critical")])
    s.config["webhook_url"] = "https://siem.example/hook"
    _run(s)
    assert len(calls) == 1 and calls[0][0]["verdict"] == "Critical"


def test_results_are_delivered_even_when_the_report_cannot_be_written(tmp_path):
    def full_disk(results, impact=None):
        raise OSError(28, "No space left on device")
    events = _run(_scanner(tmp_path, [_result("a.docm", "Critical")], report=full_disk))
    assert [e[0] for e in events][-1] == "scan_error"
    assert len(_jsonl(tmp_path)) == 1


def test_a_delivery_failure_is_logged_not_a_scan_error(tmp_path, monkeypatch, caplog):
    # set_level also lifts a logging.disable() left on by an earlier test
    # (tools/evaluate.py's worker set-up runs in-process in test_evaluation_tools).
    caplog.set_level(logging.ERROR, logger="RansomwareScanner.GUI")

    def broken(results, config):
        raise RuntimeError("outbox folder is read-only")
    monkeypatch.setattr("core.outputs.deliver", broken)
    events = _run(_scanner(tmp_path, [_result("a.docm", "Critical")]))
    assert "scan_error" not in [e[0] for e in events]
    assert "Delivering scan results" in caplog.text
