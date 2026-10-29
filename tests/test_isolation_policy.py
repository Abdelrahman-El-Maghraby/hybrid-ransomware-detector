"""4.8 fail-closed isolation (PR-02, PR-03, PR-11; owner decisions D-E, D-E1):
single files are scanned in a worker, nothing is parsed in the main process when
workers cannot start, results record where they were parsed, and the API's
/scan and /ready say so."""

import json
import time
from types import SimpleNamespace

import pytest

import RansomwareScanner as RS
from api import load_schema
from engine import workers as W
from engine.metrics import METRICS, Metrics
from engine.validation import ConfigError, check_config, validate_config
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

GOOD = "tests.worker_fakes:make"
BROKEN = "tests.worker_fakes:does_not_exist"
TOKEN = "i" * 32


def _scanner(tmp_path, factory=GOOD, **over):
    opts = dict(_scanner_factory=factory, scan_timeout_seconds=4, scan_workers=2,
                data_dir=str(tmp_path / "data"))
    opts.update(over)
    return RS.RansomwareScanner(_config(tmp_path, **opts))


def _file(tmp_path, name, folder="scan"):
    p = tmp_path / folder / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(make_pdf(f"text of {name}"))
    return str(p)


def _never_in_process(monkeypatch, scanner):
    monkeypatch.setattr(scanner, "scan_file",
                        lambda *a, **k: pytest.fail("a file was parsed in the main process"))


# ------------------------------------------------------------- PR-03: single files
def test_a_one_file_folder_is_scanned_in_a_worker(tmp_path, monkeypatch):
    s = _scanner(tmp_path)
    _file(tmp_path, "hang.pdf", "one")
    _never_in_process(monkeypatch, s)
    started = time.monotonic()
    [r] = s.scan_directory(str(tmp_path / "one"))
    assert time.monotonic() - started < 60
    assert "timed out after 4s" in r["scan_results"]["scan_failed"]["reason"]
    assert r["provenance"]["isolation"] == "worker" and r["scan_status"] == "failed"


def test_scan_one_isolates_a_hanging_file_and_records_the_worker(tmp_path, monkeypatch):
    s = _scanner(tmp_path)
    hang, ok = _file(tmp_path, "hang.pdf"), _file(tmp_path, "ok.pdf")
    _never_in_process(monkeypatch, s)
    r = s.scan_one(hang)
    assert "timed out" in r["scan_results"]["scan_failed"]["reason"] and r["verdict"] == "Medium"
    assert r["provenance"]["isolation"] == "worker" and s.last_not_scanned == 0
    good = s.scan_one(ok)
    assert good["verdict"] == "Clean" and good["provenance"]["isolation"] == "worker"
    assert good["scan_status"] != "failed"           # partial where a layer is down (no zbar)


def test_cli_scan_file_goes_through_a_worker(tmp_path, monkeypatch, capsys):
    s = _scanner(tmp_path)
    hang = _file(tmp_path, "hang.pdf")
    _never_in_process(monkeypatch, s)
    delivered = []
    monkeypatch.setattr("core.outputs.deliver", lambda results, cfg: delivered.extend(results))
    args = SimpleNamespace(scan_file=hang, scan_now=False, background=False)
    RS._scan_or_schedule(args, s)
    out = capsys.readouterr()
    assert "timed out" in out.out and "Isolated scan workers" not in out.err
    assert delivered[0]["provenance"]["isolation"] == "worker"


def test_the_isolation_opt_out_scans_in_process_and_says_so(tmp_path):
    s = _scanner(tmp_path, isolate_scans=False)
    r = s.scan_one(_file(tmp_path, "ok.pdf"))
    assert r["provenance"]["isolation"] == "in_process" and r["verdict"] == "Clean"
    [d] = s.scan_directory(str(tmp_path / "scan"))
    assert d["provenance"]["isolation"] == "in_process"


# ------------------------------------------------------------- PR-02: fail closed
def test_scan_one_fails_closed(tmp_path, monkeypatch):
    s = _scanner(tmp_path, BROKEN)
    _never_in_process(monkeypatch, s)
    r = s.scan_one(_file(tmp_path, "a.pdf"))
    assert W.isolation_unavailable(r) and s.last_not_scanned == 1
    assert r["provenance"]["isolation"] == "unavailable" and r["verdict_label"] == "Clean (failed scan)"
    assert not r["is_malicious"] and r["risk_score"] == 0


def test_cli_reports_the_cause_and_exits_non_zero(tmp_path, monkeypatch, capsys):
    s = _scanner(tmp_path, BROKEN)
    _never_in_process(monkeypatch, s)
    monkeypatch.setattr("core.outputs.deliver", lambda results, cfg: None)
    args = SimpleNamespace(scan_file=_file(tmp_path, "a.pdf"), scan_now=False, background=False)
    with pytest.raises(SystemExit) as info:
        RS._scan_or_schedule(args, s)
    assert info.value.code == RS.EXIT_ISOLATION_UNAVAILABLE == 3
    err = capsys.readouterr().err
    assert "Isolated scan workers could not start: 1 file(s) were not scanned" in err
    assert "No file was scanned in the main process" in err


def test_cli_scan_now_reports_unscanned_files_and_exits_non_zero(tmp_path, monkeypatch, capsys):
    s = _scanner(tmp_path, BROKEN)
    _file(tmp_path, "a.pdf")
    _file(tmp_path, "b.pdf")
    _never_in_process(monkeypatch, s)
    monkeypatch.setattr("core.outputs.deliver", lambda results, cfg: None)
    monkeypatch.setattr("builtins.input", lambda *a: "")
    with pytest.raises(SystemExit) as info:
        RS._scan_or_schedule(SimpleNamespace(scan_file=None, scan_now=True, background=False), s)
    assert info.value.code == 3 and "2 file(s) were not scanned" in capsys.readouterr().err


def test_a_worker_that_never_becomes_ready_counts_as_a_failed_start(tmp_path, monkeypatch):
    monkeypatch.setattr(W._IsolatedScan, "START_SECONDS", 2.0)
    s = _scanner(tmp_path, "tests.worker_fakes:never_ready", scan_workers=1)
    _never_in_process(monkeypatch, s)
    started = time.monotonic()
    r = s.scan_one(_file(tmp_path, "a.pdf"))
    assert W.isolation_unavailable(r) and time.monotonic() - started < 90


def test_failed_starts_are_counted_and_make_worker_health_fail(tmp_path):
    before = METRICS.snapshot()["worker_starts"]["failed"]
    s = _scanner(tmp_path, BROKEN)
    s.scan_one(_file(tmp_path, "a.pdf"))
    snap = METRICS.snapshot()
    assert snap["worker_starts"]["failed"] - before >= W._IsolatedScan.MAX_FAILED_STARTS
    ok, detail = METRICS.worker_health()
    assert not ok and "isolated scan workers do not start" in detail
    _scanner(tmp_path).scan_one(_file(tmp_path, "b.pdf"))                 # a good start
    assert METRICS.worker_health()[0] is True


def test_batch_metrics_count_unscanned_files_by_code(tmp_path):
    s = _scanner(tmp_path, BROKEN)
    _file(tmp_path, "a.pdf")
    before = METRICS.snapshot()["scan_failures"].get(W.ISOLATION_UNAVAILABLE, 0)
    s.scan_all_directories()
    assert METRICS.snapshot()["scan_failures"][W.ISOLATION_UNAVAILABLE] == before + 1


def test_worker_health_and_prometheus_lines():
    m = Metrics()
    assert m.worker_health() == (True, "no worker started yet")
    m.worker_start(True, 1.13)
    assert m.worker_health() == (True, "isolated workers start (last start 1.1s)")
    m.worker_start(False, reason="exit code 1")
    m.worker_start(False, reason="exit code 1")
    ok, detail = m.worker_health()
    assert not ok and "2 failed start(s) in a row; last: exit code 1" in detail
    text = m.prometheus()
    assert 'aegis_worker_starts_total{outcome="failed"} 2' in text
    assert 'aegis_worker_starts_total{outcome="ok"} 1' in text
    assert "aegis_worker_start_failure_streak 2" in text
    m.worker_start(True, 1.0)
    assert m.worker_health()[0] and m.snapshot()["worker_start_failure_streak"] == 0


def test_busy_lets_files_in_a_worker_finish_but_hands_out_nothing_new():
    scan = object.__new__(W._IsolatedScan)
    scan.cancel_event, scan.broken, scan.pending = None, True, ["left.pdf"]
    scan.pool = [SimpleNamespace(path="busy.pdf"), SimpleNamespace(path=None)]
    assert scan._busy()                                   # busy.pdf still finishes
    scan.pool[0].path = None
    assert not scan._busy()                               # left.pdf is not dispatched
    scan.broken = False
    assert scan._busy()


@pytest.mark.parametrize("make", ["worker", "unavailable"])
def test_results_match_schema_1_4(tmp_path, make):
    jsonschema = pytest.importorskip("jsonschema")
    s = _scanner(tmp_path, GOOD if make == "worker" else BROKEN)
    r = s.scan_one(_file(tmp_path, "a.pdf"))
    assert r["schema_version"] == "1.4" and r["provenance"]["isolation"] == make
    jsonschema.validate(json.loads(json.dumps(r)), load_schema())
    r["provenance"]["isolation"] = "somewhere"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(r, load_schema())


# ------------------------------------------------------------- D-E1: the opt-out
def test_isolation_opt_out_is_refused_under_the_production_profile():
    import engine.config as cfg_mod
    with pytest.raises(ConfigError) as info:
        check_config({**cfg_mod.CONFIG, "profile": "production", "isolate_scans": False,
                      "llm_provider": "none"}, env_problems=())
    assert "ISOLATE_SCANS=0" in str(info.value) and "development opt-out" in str(info.value)
    errors, warnings = validate_config({**cfg_mod.CONFIG, "isolate_scans": False})
    assert not errors and any("development only" in w for w in warnings)


# ------------------------------------------------------------- GUI (worker thread)
def test_gui_single_file_scan_is_isolated_and_fails_closed(tmp_path, monkeypatch):
    pytest.importorskip("customtkinter")
    import queue

    from aegis_gui.state import ScanController
    for factory, expect_event in ((GOOD, False), (BROKEN, True)):
        s = _scanner(tmp_path, factory)
        _never_in_process(monkeypatch, s)
        bus: queue.Queue = queue.Queue()
        c = ScanController(bus)
        c.start(s, "file", _file(tmp_path, "a.pdf"))
        c.thread.join(120)
        events = []
        while not bus.empty():
            events.append(bus.get_nowait())
        done = [e for e in events if e[0] == "scan_done"]
        assert done and done[0][1][0]["provenance"]["isolation"] == (
            "unavailable" if expect_event else "worker")
        unavailable = [e for e in events if e[0] == "isolation_unavailable"]
        assert bool(unavailable) == expect_event
        if expect_event:
            assert unavailable[0][1:] == (1, "file", str(tmp_path / "scan" / "a.pdf"))


# ------------------------------------------------------------- API (PR-02, PR-11)
@pytest.fixture
def api(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from api.server import create_app
    monkeypatch.setenv("AEGIS_API_SPARE_WORKERS", "0")
    clients = []

    def build(factory=GOOD):
        cfg = _config(tmp_path, data_dir=str(tmp_path / "data"), _scanner_factory=factory,
                      scan_timeout_seconds=30)
        client = TestClient(create_app(cfg, token=TOKEN, isolate=True))
        clients.append(client)
        return client
    yield build
    for c in clients:
        c.app.state.service.close()


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_api_scan_answers_503_and_ready_turns_503_when_workers_cannot_start(api, monkeypatch):
    client = api(GOOD)
    assert client.get("/ready").status_code == 200
    service = client.app.state.service
    monkeypatch.setattr(service.scanner, "scan_file",
                        lambda *a, **k: pytest.fail("parsed in the API process"))
    service.scanner.config["_scanner_factory"] = BROKEN     # workers stop starting
    r = client.post("/scan", headers=AUTH, files={"file": ("a.pdf", make_pdf("hello"))})
    assert r.status_code == 503 and r.headers["retry-after"] == "30"
    assert "isolated scan workers could not start" in r.json()["detail"]
    ready = client.get("/ready", headers=AUTH)                # the very next probe
    assert ready.status_code == 503
    assert ready.json()["checks"]["workers"]["ok"] is False
    assert client.get("/metrics", headers=AUTH).json()["requests_rejected"][
        W.ISOLATION_UNAVAILABLE] >= 1
    service.scanner.config["_scanner_factory"] = GOOD        # recovered
    ok = client.post("/scan", headers=AUTH, files={"file": ("b.pdf", make_pdf("hello"))})
    assert ok.status_code == 200 and ok.json()["provenance"]["isolation"] == "worker"
    assert client.get("/ready").status_code == 200


def test_api_that_starts_without_workers_is_not_ready(api):
    client = api(BROKEN)
    r = client.get("/ready", headers=AUTH)
    assert r.status_code == 503
    detail = r.json()["checks"]["workers"]["detail"]
    assert "do not start" in detail or "warm-up scan" in detail


def test_spares_refill_to_their_target_after_failed_starts(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from api.server import _ScanService
    monkeypatch.setattr(_ScanService, "SPARE_RETRY_MAX_SECONDS", 0.5)
    cfg = _config(tmp_path, data_dir=str(tmp_path / "data"), _scanner_factory=BROKEN)
    service = _ScanService(cfg, isolate=True, spares=2)
    try:
        before = METRICS.snapshot()["worker_starts"]["failed"]
        _wait(lambda: METRICS.snapshot()["worker_starts"]["failed"] >= before + 2)
        assert service.spare_count() == 0 and not service.workers_check()[0]
        service.scanner.config["_scanner_factory"] = GOOD
        _wait(lambda: service.spare_count() == 2)
        assert service.workers_check()[0] is True
        spare = service._take_spare()
        assert spare.ready and spare.proc.is_alive()
        spare.kill()                                       # an idle spare that died ...
        service._spares.put(spare)
        other = service._take_spare()
        assert other is not spare and other.proc.is_alive()   # ... is never handed out
        service._spares.put(other)
        _wait(lambda: service.spare_count() == 2)          # and is replaced
    finally:
        service.close()


def _wait(cond, seconds=120):
    end = time.monotonic() + seconds
    while not cond() and time.monotonic() < end:
        time.sleep(0.1)
    assert cond()


def test_wait_ready_kills_a_worker_that_dies_before_ready(tmp_path):
    s = _scanner(tmp_path, BROKEN)
    w = W.start_worker(s, 0)
    assert W.wait_ready(w, 60) is False
    assert not w.proc.is_alive()
    w2 = W.start_worker(_scanner(tmp_path), 0)
    try:
        assert W.wait_ready(w2, 120) is True and w2.ready
    finally:
        w2.kill()
