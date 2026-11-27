"""No external services or malware: completed answers survive worker timeouts."""
import copy
from types import SimpleNamespace

import pytest

from engine import workers as W
from tests.test_slow_layer_deadline import _cfg, _scan, _script, _stage


@pytest.mark.parametrize("stall,completed,key", [
    ("llm", "virustotal", "virustotal"),
    ("virustotal", "llm", "chatgpt_analysis"),
])
@pytest.mark.parametrize("parallel", [True, False])
def test_completed_answer_then_stalled_service(tmp_path, stall, completed, key, parallel):
    # Sequential VT-first is tested by reversing just these two layers in a factory below.
    if not parallel and stall == "llm":
        factory = "tests.completed_fakes:make_vt_first"
    else:
        factory = "tests.completed_fakes:make"
    cfg = _cfg(tmp_path, 3, _stall=stall, virustotal_api_key="k" * 64,
               parallel_heavy_layers=parallel)
    cfg["_scanner_factory"] = factory
    got = _scan(cfg, [_script(tmp_path)], 3)
    assert len(got) == 1
    r = got[0][1]
    assert r["scan_status"] == "partial" and "scan_failed" not in r["scan_results"]
    assert r["scan_results"]["stopped_layers"] == [stall]
    assert r["scan_results"][key].get("status") != "timeout"
    indicators = {c["indicator"] for c in r["score_breakdown"]["contributions"]}
    assert any(completed in i for i in indicators)
    assert {s["service"] for s in r["provenance"]["shared"]} == {"llm", "virustotal"}
    assert r["scan_results"][W.STOPPABLE[stall]]["transmission"] == "possible"


@pytest.mark.parametrize("first", ["llm", "virustotal"])
def test_both_answers_before_stalled_sandbox_and_repeated_files(tmp_path, first):
    cfg = _cfg(tmp_path, 3, _stall="sandbox", virustotal_api_key="k" * 64,
               sandbox_submit="all", _delays={first: 0.01, "virustotal" if first == "llm" else "llm": 0.1})
    cfg["_scanner_factory"] = "tests.completed_fakes:make"
    files = [_script(tmp_path, f"f{i}.ps1") for i in range(2)]
    got = _scan(cfg, files, 3)
    assert [p for p, _ in got] == list(map(str, files))
    for path, r in got:
        assert r["file_path"] == path
        assert r["scan_results"]["stopped_layers"] == ["sandbox"]
        assert r["scan_results"]["virustotal"]["malicious_detections"] == 8
        assert r["scan_results"]["chatgpt_analysis"]["is_malicious"]
        assert r["risk_score"] >= 64


def test_completed_results_before_final_reply(tmp_path):
    cfg = _cfg(tmp_path, 3, _slow_finish=True, virustotal_api_key="k" * 64)
    cfg["_scanner_factory"] = "tests.completed_fakes:make"
    got = _scan(cfg, [_script(tmp_path)], 3)
    assert len(got) == 1
    r = got[0][1]
    assert "stopped_layers" not in r["scan_results"]
    assert r["scan_results"]["virustotal"]["malicious_detections"] == 8
    assert r["scan_results"]["chatgpt_analysis"]["is_malicious"]


def test_snapshot_protocol_rejects_unhashable_layers():
    r = _stage()
    r["scan_results"]["stopped_layers"] = [["llm"]]
    with pytest.raises(W.InvalidReply):
        W.check_reply(["provisional", r])


def test_watchdog_memory_failure_wins_over_deadline(monkeypatch):
    w = SimpleNamespace(retired=False, ready=True, path="file", started=0,
                        proc=SimpleNamespace(is_alive=lambda: True), provisional=_stage(),
                        evidence=None, settled=False)
    scan = object.__new__(W._IsolatedScan)
    scan.pool, scan.pending, scan.timeout, scan.memory_mb = [w], [], 1, 1
    monkeypatch.setattr(scan, "_receive", lambda w: ("", None))
    monkeypatch.setattr(scan, "_over_memory", lambda w: 2 * 1024 * 1024)
    failures = []
    monkeypatch.setattr(scan, "_finish", lambda *args: None)
    monkeypatch.setattr(scan, "_fail", lambda *args: failures.append(args))
    monkeypatch.setattr(scan, "_replace", lambda i: True)
    scan._step(0)
    assert len(failures) == 1 and "MemoryError" in failures[0][1]


def test_wrong_file_snapshot_is_failure(monkeypatch):
    w = SimpleNamespace(retired=False, ready=True, path="other", evidence=None)
    scan = object.__new__(W._IsolatedScan)
    scan.pool, scan.pending = [w], []
    monkeypatch.setattr(scan, "_receive", lambda w: ("provisional", _stage()))
    failures = []
    monkeypatch.setattr(scan, "_fail", lambda *args: failures.append(args))
    monkeypatch.setattr(scan, "_replace", lambda i: True)
    scan._step(0)
    assert len(failures) == 1 and "another file" in failures[0][1]


def test_progress_reset_and_completed_validation():
    completed = _stage()
    completed["scan_results"].pop("stopped_layers")
    W.check_reply(["completed", completed])
    with pytest.raises(W.InvalidReply):
        W.check_reply(["completed", _stage()])
    w = SimpleNamespace(path="x", parent=SimpleNamespace(send=lambda p: None))
    scan = object.__new__(W._IsolatedScan)
    scan.pending = ["next"]
    W._IsolatedScan._progress(w, "completed", copy.deepcopy(completed))
    scan._dispatch(w)
    assert w.provisional is None and w.external == {} and not w.settled


@pytest.mark.parametrize("parallel", [True, False])
def test_no_stopped_snapshot_outlives_the_slow_layers(tmp_path, parallel):
    """Once VirusTotal and the LLM have answered, the parent must not still hold a
    snapshot that stops one of them: a stall in the final assembly would then
    replace a real answer with a timeout. Before the fix the last message before
    `completed` was the provisional naming the last layer to finish."""
    import time

    from tests.completed_fakes import CompletedScanner
    cfg = _cfg(tmp_path, 30, virustotal_api_key="k" * 64, parallel_heavy_layers=parallel,
               _delays={"virustotal": 0.2})
    cfg.pop("_scanner_factory")
    s = CompletedScanner(dict(cfg, isolate_scans=False))
    msgs = []
    s.provisional_listener = lambda r, settled=False: msgs.append(
        ("provisional", tuple(r["scan_results"].get("stopped_layers") or ())))
    s.clear_provisional_listener = lambda: msgs.append(("clear", ()))
    s.completed_listener = lambda r: msgs.append(("completed", ()))
    s.sandbox_listener = s.external_listener = lambda *a: None
    s.scan_deadline = time.monotonic() + 30
    r = s.scan_file(str(_script(tmp_path)))
    assert r["scan_results"]["virustotal"]["malicious_detections"] == 8
    assert any(kind == "provisional" for kind, _ in msgs)      # the stage was published
    assert msgs[-1][0] == "completed" and msgs[-2][0] == "clear"
