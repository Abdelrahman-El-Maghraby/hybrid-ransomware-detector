"""4.7: readiness (GET /ready) is distinct from liveness (GET /health): ready only
when rules, registry, storage, workers and - in the production profile - every
required layer are in order."""

import pytest

import RansomwareScanner as RS
from detectors import YARA_AVAILABLE
from engine import readiness as R
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

TOKEN = "r" * 32
WORKERS_OK = (True, "in-process scans (isolation off)")


def _scanner(tmp_path, **overrides):
    return RS.RansomwareScanner(_config(tmp_path, data_dir=str(tmp_path / "data"), **overrides))


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_standard_profile_is_ready(tmp_path):
    report = R.readiness(_scanner(tmp_path), WORKERS_OK)
    assert report["ready"] and report["problems"] == [] and report["profile"] == "standard"
    assert set(report["checks"]) == {"rules", "registry", "storage", "workers", "layers"}
    assert report["checks"]["rules"]["detail"].endswith("rule files")
    assert report["layers"]["pe"] == {"state": "up", "detail": ""}


def test_production_profile_needs_every_required_layer(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path, profile="production")
    down = {"state": "down", "detail": "needs zbar", "missing": ["zbar"]}
    states = {**R.layer_states(scanner), "qr": down}
    monkeypatch.setattr(R, "layer_states", lambda s: states)
    report = R.readiness(scanner, WORKERS_OK)
    assert not report["ready"] and report["profile"] == "production"
    assert "layers: qr: down (needs zbar)" in report["problems"]
    assert report["layers"]["qr"] == {"state": "down", "detail": "needs zbar"}


def test_standard_profile_does_not_enforce_required_layers(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    states = {**R.layer_states(scanner), "qr": {"state": "down", "detail": "needs zbar",
                                                "missing": ["zbar"]}}
    monkeypatch.setattr(R, "layer_states", lambda s: states)
    assert R.readiness(scanner, WORKERS_OK)["checks"]["layers"]["ok"]


def test_rules_storage_registry_and_workers_each_block_readiness(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    empty = tmp_path / "no-rules"
    empty.mkdir()
    no_rules = _scanner(tmp_path, yara_rules_dir=str(empty))
    assert not R.readiness(no_rules, WORKERS_OK)["checks"]["rules"]["ok"]

    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    scanner.report_dir = str(blocker / "reports")      # under a file: cannot be created
    report = R.readiness(scanner, WORKERS_OK)
    assert not report["checks"]["storage"]["ok"] and str(blocker) in report["checks"]["storage"]["detail"]

    report = R.readiness(_scanner(tmp_path), (False, "warm-up scan failed: timeout"))
    assert "workers: warm-up scan failed: timeout" in report["problems"]

    broken = _scanner(tmp_path)
    monkeypatch.setattr(broken.scoring.registry, "caps", {"technical": 100.0})
    assert R.registry_check(broken)[0] is False
    assert "no cap for reputation" in R.registry_check(broken)[1]
    monkeypatch.setattr(broken.scoring, "registry", None)
    assert R.registry_check(broken) == (False, "no indicator registry loaded")


# ------------------------------------------------------------------ the API
@pytest.fixture
def make_api(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from api.server import create_app

    def build(isolate=False, **overrides):
        cfg = _config(tmp_path, data_dir=str(tmp_path / "data"), **overrides)
        return TestClient(create_app(cfg, token=TOKEN, isolate=isolate))
    return build


def test_ready_hides_details_without_the_token(make_api, monkeypatch):
    import api.server as srv
    api = make_api()
    monkeypatch.setattr(srv, "readiness", lambda s, w: {"ready": True, "checks": {}, "layers": {},
                                                        "problems": [], "profile": "standard"})
    anonymous = api.get("/ready")
    assert anonymous.status_code == 200 and anonymous.json() == {"ready": True}
    full = api.get("/ready", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert full["ready"] is True and "checks" in full
    assert api.get("/ready", headers={"Authorization": "Bearer wrong-token-value"}).json() == {
        "ready": True}


def test_not_ready_answers_503_while_health_stays_200(make_api, monkeypatch):
    import api.server as srv
    api = make_api()
    monkeypatch.setattr(srv, "readiness", lambda s, w: {
        "ready": False, "checks": {}, "layers": {}, "problems": ["rules: needs yara-python"],
        "profile": "production"})
    assert api.get("/ready").status_code == 503
    r = api.get("/ready", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 503 and r.json()["problems"] == ["rules: needs yara-python"]
    assert api.get("/health").json() == {"status": "ok"}


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_isolated_warm_up_proves_workers_start(make_api):
    api = make_api(isolate=True)
    report = api.get("/ready", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert report["checks"]["workers"] == {"ok": True, "detail": "isolated workers start"}
    r = api.post("/scan", headers={"Authorization": f"Bearer {TOKEN}"},
                 files={"file": ("a.pdf", make_pdf("hello"))})
    assert r.status_code == 200


def test_failed_warm_up_is_reported(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from api.server import _ScanService
    service = _ScanService(_config(tmp_path), isolate=True)
    monkeypatch.setattr(service, "scan", lambda path, display: {
        "scan_results": {"scan_failed": {"reason": "worker crashed"}}})
    assert service.warm_up() == (False, "warm-up scan failed: worker crashed")

    def boom(path, display):
        raise OSError("no fork")
    monkeypatch.setattr(service, "scan", boom)
    assert service.warm_up() == (False, "warm-up scan raised OSError")
    assert _ScanService(_config(tmp_path), isolate=False).warm_up()[0] is True
