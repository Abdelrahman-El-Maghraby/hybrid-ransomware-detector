"""Versioned result schema, JSON Lines / webhook outputs and the REST API."""

import hashlib
import hmac
import json

import pytest

from api import SCHEMA_VERSION, load_schema
from core.outputs import alert_payload, send_webhook, sign, write_jsonl
from tests.helpers import make_pdf
from tests.test_file_integrity import _pe_bytes
from tests.test_regression_corpus import build_corpus
from tests.test_scanner_integration import _config

jsonschema = pytest.importorskip("jsonschema")


@pytest.fixture(scope="module")
def corpus_results(tmp_path_factory):
    import RansomwareScanner as RS
    base = tmp_path_factory.mktemp("schema")
    corpus = build_corpus(base / "corpus")
    cfg = _config(base, cache_enabled=False, file_extensions=RS.SUPPORTED_EXTENSIONS + [".exe", ".txt"])
    return RS.RansomwareScanner(cfg).scan_directory(str(corpus))


def test_every_result_matches_the_schema(corpus_results):
    validator = jsonschema.Draft202012Validator(load_schema())
    for r in corpus_results:
        errors = sorted(validator.iter_errors(json.loads(json.dumps(r, default=str))), key=str)
        assert not errors, (r["file_name"], [e.message for e in errors[:3]])
        assert r["schema_version"] == SCHEMA_VERSION


def test_failure_results_match_the_schema(tmp_path):
    import RansomwareScanner as RS
    from engine.workers import failure_result
    p = tmp_path / "x.bin"
    p.write_bytes(b"x")
    r = failure_result(RS.RansomwareScanner(_config(tmp_path)), str(p), "timed out after 5s")
    jsonschema.validate(r, load_schema())


def test_jsonl_appends_one_line_per_result(tmp_path, corpus_results):
    out = tmp_path / "siem" / "aegis.jsonl"
    assert write_jsonl(corpus_results[:3], out) == 3
    write_jsonl(corpus_results[3:5], out)
    lines = out.read_text().splitlines()
    assert len(lines) == 5 and all(json.loads(line)["sha256_hash"] for line in lines)


class Recorder:
    def __init__(self, status=200):
        self.calls, self.status = [], status

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append((url, data, headers))
        return type("R", (), {"status_code": self.status})()


def test_webhook_sends_signed_alerts_above_the_threshold(corpus_results):
    rec = Recorder()
    sent = send_webhook(corpus_results, "https://hooks.example.invalid/x", "s3cret", "High", session=rec)
    high = [r for r in corpus_results if r["verdict"] in ("High", "Critical")]
    assert len(sent) == len(high) == len(rec.calls)
    url, body, headers = rec.calls[0]
    expect = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert headers["X-Aegis-Signature"] == expect == sign(body, "s3cret")
    payload = json.loads(body)
    assert set(payload) >= {"verdict", "sha256", "indicators", "top_reason"}
    assert "content" not in payload and "scan_results" not in payload       # metadata only
    assert send_webhook(corpus_results, "u", min_verdict="Critical", session=Recorder(500)) == []


def test_alert_payload_orders_indicators_by_points():
    r = {"verdict": "High", "score_breakdown": {"contributions": [
        {"indicator": "a", "points": 10, "detail": "small"},
        {"indicator": "b", "points": 60, "detail": "big"}]}}
    p = alert_payload(r)
    assert p["indicators"] == ["b", "a"] and p["top_reason"] == "big"


# ------------------------------------------------------------------ REST API
fastapi = pytest.importorskip("fastapi")
TOKEN = "t" * 32


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient

    from api.server import create_app
    return TestClient(create_app(_config(tmp_path), token=TOKEN, isolate=False))


def auth(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def test_token_is_required(client, tmp_path):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/version").status_code == 401
    assert client.get("/version", headers=auth("wrong" * 8)).status_code == 401
    assert client.post("/scan", files={"file": ("a.pdf", b"x")}).status_code == 401
    v = client.get("/version", headers=auth()).json()
    assert v["schema"] == SCHEMA_VERSION and v["registry"]


def test_server_refuses_to_start_without_a_strong_token(tmp_path):
    from api.server import create_app
    with pytest.raises(RuntimeError):
        create_app(_config(tmp_path), token="short")


def test_scan_endpoint(client):
    bad = client.post("/scan", headers=auth(), files={"file": ("invoice.pdf", _pe_bytes(4096))})
    assert bad.status_code == 200
    body = bad.json()
    assert body["verdict"] == "Critical" and body["file_name"] == "invoice.pdf"
    jsonschema.validate(body, client.get("/schema", headers=auth()).json())
    ok = client.post("/scan", headers=auth(), files={"file": ("letter.pdf", make_pdf("Hello"))})
    assert ok.json()["verdict"] == "Clean"


def test_hostile_file_names_are_not_used_as_paths(client):
    r = client.post("/scan", headers=auth(),
                    files={"file": ("../../etc/passwd;rm -rf .pdf", make_pdf("x"))})
    assert r.status_code == 200 and r.json()["file_name"] == "passwd;rm -rf .pdf"


def test_upload_size_limit(client, monkeypatch):
    import api.server as srv
    monkeypatch.setattr(srv, "MAX_UPLOAD_MB", 0.001)
    r = client.post("/scan", headers=auth(), files={"file": ("big.pdf", b"x" * 5000)})
    assert r.status_code == 413


def test_scan_endpoint_isolated_worker(tmp_path):
    from fastapi.testclient import TestClient

    from api.server import create_app
    c = TestClient(create_app(_config(tmp_path), token=TOKEN, isolate=True))
    r = c.post("/scan", headers=auth(), files={"file": ("invoice.pdf", _pe_bytes(4096))})
    assert r.json()["verdict"] == "Critical" and r.json()["file_name"] == "invoice.pdf"
