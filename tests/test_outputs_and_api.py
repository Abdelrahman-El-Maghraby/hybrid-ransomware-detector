"""Versioned result schema, JSON Lines / webhook outputs and the REST API."""

import hashlib
import hmac
import json

import pytest

from api import SCHEMA_VERSION, load_schema
from core.outputs import alert_payload, sign, write_jsonl
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
    """Through the path the product uses (the outbox's channels and post_alert);
    the older send_webhook was unused and is removed (I-x)."""
    from core.outbox import channels_for, verdict_alert
    from core.outputs import post_alert
    rec = Recorder()
    cfg = {"webhook_url": "https://hooks.example.invalid/x", "webhook_min_verdict": "High"}
    alerts = [verdict_alert(r) for r in corpus_results]
    for alert in alerts:
        if channels_for(alert, cfg, email_available=False) == ["webhook"]:
            post_alert(alert["webhook"], cfg["webhook_url"], "s3cret", session=rec)
    high = [r for r in corpus_results if r["verdict"] in ("High", "Critical")]
    assert high and len(rec.calls) == len(high)
    url, body, headers = rec.calls[0]
    expect = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert headers["X-Aegis-Signature"] == expect == sign(body, "s3cret")
    payload = json.loads(body)
    assert set(payload) >= {"verdict", "sha256", "indicators", "top_reason"}
    assert "content" not in payload and "scan_results" not in payload       # metadata only
    with pytest.raises(RuntimeError, match="HTTP 500"):
        post_alert(alerts[0]["webhook"], "https://hooks.example.invalid/x", session=Recorder(500))


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


def test_the_upload_name_reaches_the_name_checks(client):
    """M30 through the API: the upload was stored as `upload<ext>`, so a
    right-to-left override in the client's name scored Clean here and High from
    the CLI. Unusable names still fall back to `upload<ext>`."""
    r = client.post("/scan", headers=auth(),
                    files={"file": ("invoice\u202efdp.txt", b"hello world\n")}).json()
    assert r["file_name"] == "invoice\u202efdp.txt"
    assert "file_rtlo_spoof" in {c["indicator"] for c in r["score_breakdown"]["contributions"]}
    assert r["verdict"] != "Clean"


@pytest.mark.parametrize("name,ext,stored", [
    ("Report.PDF", ".pdf", "Report.pdf"),
    ("invoice\u202efdp.txt", ".txt", "invoice\u202efdp.txt"),
    ("README", "", "README"),
    ("NUL.pdf", ".pdf", "upload.pdf"),            # M20: a Windows device
    ("a:b.pdf", ".pdf", "upload.pdf"),            # an NTFS stream
    ("a\\b.pdf", ".pdf", "upload.pdf"),
    ("bad\x01.pdf", ".pdf", "upload.pdf"),
    ("invoice.pdf.js.", ".js", "upload.js"),       # M24: Windows would drop the dots
    ("x.$$$", "", "upload"),                       # an extension upload_extension refused
    ("\udcff.pdf", ".pdf", "upload.pdf"),          # not encodable
    ("\u00e9" * 150 + ".pdf", ".pdf", "upload.pdf"),  # over the byte limit
])
def test_stored_upload_names(name, ext, stored):
    from api.server import stored_name, upload_extension
    assert upload_extension(name) == ext
    assert stored_name(name, ext) == stored


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


def test_api_results_never_show_the_server_work_folder(client):
    """L-A1 (check 15): member names of an uploaded archive started with the
    server's temporary work folder; only file_path and file_name were replaced."""
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("inner/report.pdf", make_pdf("hello"))
        z.writestr("tool.exe", _pe_bytes(4096))
    r = client.post("/scan", headers=auth(), files={"file": ("bundle.zip", buf.getvalue())})
    assert r.status_code == 200
    text = r.text
    assert "aegis_api_" not in text and "upload.zip" not in text
    assert "bundle.zip!/tool.exe" in text


def test_upload_limits_set_in_the_env_file_are_honoured(monkeypatch):
    # AR-1: both limits were read at import, before main() loaded .env.
    pytest.importorskip("uvicorn")
    import uvicorn

    import api.server as server
    import engine.config as config
    for name in ("MAX_UPLOAD_MB", "UPLOAD_SECONDS"):
        monkeypatch.setattr(server, name, getattr(server, name))        # restored afterwards

    def load_env_file():                                  # what .env would contain
        monkeypatch.setenv("AEGIS_API_MAX_UPLOAD_MB", "7")
        monkeypatch.setenv("AEGIS_API_UPLOAD_SECONDS", "30")

    monkeypatch.setattr(config, "init_runtime", load_env_file)
    monkeypatch.setattr(server, "create_app", lambda: object())
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.delenv("AEGIS_API_SOCKET", raising=False)
    server.main()
    assert (server.MAX_UPLOAD_MB, server.UPLOAD_SECONDS) == (7.0, 30.0)
