"""4.8 optional cloud storage of reports and logs (F5; I-5; D-D1 to D-D3):
off by default, an allowlisted and redacted upload view, a 30-day local spool
with a size cap, create-only uploads with a verified checksum over verified
HTTPS, and no path, name, content or secret in any uploaded byte."""

import base64
import getpass
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import RansomwareScanner as RS
from core import cloud as C
from engine.validation import ConfigError, check_config
from tests.helpers import make_pdf
from tests.test_mail_analyzer import make_eml
from tests.test_scanner_integration import _config

SECRET = "CLOUD-SECRET-key-9d2e"
MARKERS = ("MARKERUSERq7", "MARKERDIRw3", "MARKERFILEe5", "MARKERMEMBERr1", "MARKERATTACHt9",
           "MARKERCONTENTy2")


class FakeS3:
    """Records every PUT; can be down."""

    def __init__(self, up=True, echo=True):
        self.up, self.echo, self.puts = up, echo, []

    def put_object(self, **kw):
        if not self.up:
            raise ConnectionError("endpoint unreachable")
        self.puts.append(kw)
        answer = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        if self.echo:
            answer["ChecksumSHA256"] = kw["ChecksumSHA256"]
        return answer


@pytest.fixture
def app(tmp_path, monkeypatch):
    """APP_DIR in the test folder; the pseudonym key without a keyring."""
    monkeypatch.setattr("engine.config.APP_DIR", tmp_path / "app")
    monkeypatch.setattr("engine.secret_store.keyring_backend", lambda: None)
    monkeypatch.setattr(C, "_EVENT_SPOOL", None)
    return tmp_path / "app"


def _cloud_config(tmp_path, **over):
    cfg = _config(tmp_path, cloud_upload=True, cloud_endpoint="https://s3.example.org",
                  cloud_bucket="aegis-reports", cloud_prefix="org/desk", cloud_region="eu-west-1",
                  cloud_access_key_id="AKIDEXAMPLE", cloud_secret_access_key=SECRET,
                  cloud_spool_dir=str(tmp_path / "spool"), isolate_scans=False,
                  outbox_dir=str(tmp_path / "outbox"))
    cfg.update(over)
    return cfg


def _uploader(cfg, s3, install="0" * 32):
    return C.S3Uploader(cfg, install, client=s3)


# ------------------------------------------------------------------ off by default
def test_off_by_default_nothing_is_queued(tmp_path, app):
    assert RS.CONFIG["cloud_upload"] is False
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False,
                                     cloud_spool_dir=str(tmp_path / "spool")))
    (tmp_path / "scan" / "a.pdf").write_bytes(make_pdf("hello"))
    s.generate_report(s.scan_all_directories())
    assert not (tmp_path / "spool").exists()
    assert C.run_uploads(s.config) == {"uploaded": 0, "retry": 0, "waiting": 0}


# ------------------------------------------------------------------ D-D3: the marker test
def _marked_tree(tmp_path):
    root = tmp_path / "scan" / MARKERS[0] / MARKERS[1]
    root.mkdir(parents=True)
    (root / f"{MARKERS[2]}.pdf").write_bytes(make_pdf(f"invoice {MARKERS[5]}"))
    with zipfile.ZipFile(root / f"{MARKERS[2]}-bundle.zip", "w") as z:
        z.writestr(f"{MARKERS[3]}/{MARKERS[3]}.js", f"var x = '{MARKERS[5]}';")
    make_eml(root / f"{MARKERS[2]}-mail.eml", subject=f"Re: {MARKERS[5]}",
             attachments=[(f"{MARKERS[4]}.pdf", make_pdf(MARKERS[5]), "application", "pdf")])
    return root


def test_no_path_name_user_host_or_content_leaves_in_any_uploaded_byte(tmp_path, app, caplog):
    root = _marked_tree(tmp_path)
    cfg = _cloud_config(tmp_path, scan_directories=[str(tmp_path / "scan")])
    s = RS.RansomwareScanner(cfg)
    C.install_event_spool(cfg)
    try:
        with caplog.at_level(logging.INFO, logger="RansomwareScanner"):
            results = s.scan_all_directories()
            s.generate_report(results)
        assert len(results) == 3 and any(MARKERS[0] in r["file_path"] for r in results)
        s3 = FakeS3()
        counts = C.run_uploads(cfg, uploader=_uploader(cfg, s3))
    finally:
        logging.getLogger("RansomwareScanner").removeHandler(C._EVENT_SPOOL)
    assert counts["uploaded"] == 2 and {p["Key"].split("/")[3] for p in s3.puts} == {"reports", "logs"}
    sent = b"".join(p["Body"] + p["Key"].encode() for p in s3.puts)
    forbidden = list(MARKERS) + [socket.gethostname(), getpass.getuser(), str(tmp_path),
                                 str(root), "invoice", SECRET]
    for marker in forbidden:
        assert marker.encode() not in sent, marker
    report = json.loads(next(p["Body"] for p in s3.puts if "/reports/" in p["Key"]))
    assert report["redacted"] is True and report["full_detail"] is False
    one = report["results"][0]
    assert set(one) <= set(C.RESULT_FIELDS) | {"file", "extension", "detected_type",
                                               "indicators", "rules", "incomplete", "provenance"}
    assert re.fullmatch(r"[0-9a-f]{16}", one["file"]) and one["extension"] in (".pdf", ".zip", ".eml")
    logs = json.loads(next(p["Body"] for p in s3.puts if "/logs/" in p["Key"]))
    assert logs["events"] and all(set(e) <= {"time", "level"} | set(C.EVENT_FIELDS)
                                  for e in logs["events"])
    assert any(MARKERS[2] in r.getMessage() for r in caplog.records)   # the local log has it


def test_pseudonyms_correlate_without_revealing_names(tmp_path, app):
    key = C.pseudonym_key({}, app)
    r = {"file_path": "/Users/x/Documents/secret plan.pdf", "file_name": "secret plan.pdf"}
    assert C.redact_result(r, key)["file"] == C.redact_result(dict(r), key)["file"]
    assert C.redact_result(r, b"other key")["file"] != C.redact_result(r, key)["file"]
    assert C.pseudonym_key({}, app) == key                         # kept for the installation
    if os.name != "nt":
        assert (app / "cloud_pseudonym.key").stat().st_mode & 0o777 == 0o600


def test_full_detail_is_an_explicit_recorded_and_warned_opt_in(tmp_path, app, caplog):
    cfg = _cloud_config(tmp_path, cloud_upload_full=True)
    with caplog.at_level(logging.WARNING, logger="RansomwareScanner"):
        handler = C.install_event_spool(cfg)
    logging.getLogger("RansomwareScanner").removeHandler(handler)
    assert any(getattr(r, "event", "") == "cloud_full_detail" for r in caplog.records)
    C.spool_report([{"file_path": f"/x/{MARKERS[2]}.pdf", "verdict": "Clean"}], cfg)
    s3 = FakeS3()
    C.run_uploads(cfg, uploader=_uploader(cfg, s3))
    doc = json.loads(next(p["Body"] for p in s3.puts if "/reports/" in p["Key"]))
    assert doc["full_detail"] is True and doc["redacted"] is False
    assert MARKERS[2] in doc["results"][0]["file_path"]
    assert any("CLOUD_UPLOAD_FULL" in w for w in check_config(cfg, env_problems=()))


# ------------------------------------------------------------------ I-5: spool and network
def test_with_the_network_down_the_spool_fills_and_drains_later(tmp_path, app):
    cfg = _cloud_config(tmp_path)
    for i in range(3):
        C.spool_report([{"file_path": f"/x/{i}.pdf", "verdict": "Clean"}], cfg)
    s3 = FakeS3(up=False)
    up = _uploader(cfg, s3)
    assert C.run_uploads(cfg, uploader=up)["retry"] == 3
    spool = C.spool_for(cfg)
    assert spool.status()["pending"] == 3 and "ConnectionError" in spool.status()["last_error"]
    s3.up = True
    state = json.loads((tmp_path / "spool" / "state.json").read_text())
    for info in state["items"].values():
        info["next"] = 0
    (tmp_path / "spool" / "state.json").write_text(json.dumps(state))
    assert C.run_uploads(cfg, uploader=up)["uploaded"] == 3
    assert spool.status()["pending"] == 0 and len(s3.puts) == 3


def test_object_keys_are_unique_create_only_and_checksummed(tmp_path, app):
    cfg = _cloud_config(tmp_path)
    s3 = FakeS3()
    up = _uploader(cfg, s3, install="ab" * 16)
    body = b'{"x": 1}'
    k1, k2 = up.put("report", body), up.put("report", body)
    assert k1 != k2
    pattern = (r"org/desk/" + "ab" * 16 + r"/reports/\d{4}/\d{2}/\d{2}/\d{8}T\d{6}Z-[0-9a-f]{32}-"
               + hashlib.sha256(body).hexdigest()[:12] + r"\.json")
    assert re.fullmatch(pattern, k1)
    put = s3.puts[0]
    assert put["IfNoneMatch"] == "*" and put["Bucket"] == "aegis-reports"
    assert put["ChecksumAlgorithm"] == "SHA256"
    assert put["ChecksumSHA256"] == base64.b64encode(hashlib.sha256(body).digest()).decode()
    plain = FakeS3()
    _uploader(dict(cfg, cloud_conditional_writes=False), plain).put("logs", body)
    assert "IfNoneMatch" not in plain.puts[0] and "/logs/" in plain.puts[0]["Key"]


def test_an_unconfirmed_upload_stays_in_the_spool(tmp_path, app):
    cfg = _cloud_config(tmp_path)

    class Liar(FakeS3):
        def put_object(self, **kw):
            answer = super().put_object(**kw)
            answer["ChecksumSHA256"] = base64.b64encode(b"\0" * 32).decode()
            return answer
    C.spool_report([{"file_path": "/x/a.pdf", "verdict": "Clean"}], cfg)
    assert C.run_uploads(cfg, uploader=_uploader(cfg, Liar()))["retry"] == 1
    assert C.spool_for(cfg).status()["pending"] == 1


def test_cleanup_deletes_expired_items_then_the_oldest_over_the_cap(tmp_path, app, caplog):
    now = [1_700_000_000.0]
    spool = C.Spool(str(tmp_path / "spool"), days=30, max_mb=0.001, clock=lambda: now[0])
    old = spool.add("report", b"x" * 100)
    now[0] += 31 * 86_400
    a = spool.add("report", b"a" * 600)
    now[0] += 60
    b = spool.add("logs", b"b" * 600)
    reports = tmp_path / "reports_kept"
    reports.mkdir()
    (reports / "ransomware_scan_x.json").write_text("{}")
    with caplog.at_level(logging.WARNING, logger="RansomwareScanner"):
        assert spool.cleanup() == 2
    assert not old.exists() and not a.exists() and b.exists()
    reasons = [r.getMessage() for r in caplog.records if getattr(r, "event", "") == "cloud_spool_expired"]
    assert any("31.0 days old" in m and "queued more than 30 days ago" in m for m in reasons)
    assert any("size cap" in m for m in reasons)
    assert spool.status()["expired_without_upload"] == 2
    assert (reports / "ransomware_scan_x.json").exists()          # local reports untouched


def test_turning_cloud_off_stops_queuing_and_uploading_but_keeps_the_spool(tmp_path, app):
    cfg = _cloud_config(tmp_path)
    C.spool_report([{"file_path": "/x/a.pdf", "verdict": "Clean"}], cfg)
    off = dict(cfg, cloud_upload=False)
    C.spool_report([{"file_path": "/x/b.pdf", "verdict": "Clean"}], off)
    s3 = FakeS3()
    assert C.run_uploads(off, uploader=_uploader(off, s3)) == {"uploaded": 0, "retry": 0,
                                                              "waiting": 0}
    assert s3.puts == [] and C.spool_for(cfg).status()["pending"] == 1


def test_only_reports_and_logs_are_ever_spooled(tmp_path, app):
    """Never inspected files, the vault, keys, the outbox or the cache (I-5)."""
    root = _marked_tree(tmp_path)
    cfg = _cloud_config(tmp_path, scan_directories=[str(tmp_path / "scan")],
                        auto_quarantine="medium")
    s = RS.RansomwareScanner(cfg)
    s.generate_report(s.scan_all_directories())
    names = [p.name for p in C.spool_for(cfg).items()]
    assert names and all(n.split("-", 1)[0] in C.KINDS for n in names)
    blobs = b"".join(p.read_bytes() for p in C.spool_for(cfg).items())
    for f in root.rglob("*"):
        if f.is_file():
            assert f.read_bytes()[:64] not in blobs
    assert MARKERS[5].encode() not in blobs


def test_the_secret_key_never_appears_in_logs_spool_or_errors(tmp_path, app, caplog):
    cfg = _cloud_config(tmp_path)
    C.spool_report([{"file_path": "/x/a.pdf", "verdict": "Clean"}], cfg)
    with caplog.at_level(logging.DEBUG):
        C.run_uploads(cfg, uploader=_uploader(cfg, FakeS3(up=False)))
    text = caplog.text + "".join(p.read_text() for p in (tmp_path / "spool").iterdir())
    assert SECRET not in text


# ------------------------------------------------------------------ settings
@pytest.mark.parametrize("change, message", [
    ({"cloud_endpoint": "http://s3.example.org"}, "https:// URL"),
    ({"cloud_bucket": "Bad_Bucket"}, "CLOUD_BUCKET"),
    ({"cloud_prefix": "../escape"}, "CLOUD_PREFIX"),
    ({"cloud_secret_access_key": ""}, "CLOUD_SECRET_ACCESS_KEY"),
    ({"cloud_ca_bundle": "/no/such/ca.pem"}, "CLOUD_CA_BUNDLE"),
    ({"intel_socket": "/run/aegis/intel/intel.sock", "intel_token": "t" * 40}, "desktop feature"),
    ({"profile": "production", "llm_provider": "none"}, "desktop feature"),
    ({"cloud_spool_days": 0}, "CLOUD_SPOOL_DAYS=0 is out of range"),
])
def test_cloud_settings_are_validated(tmp_path, change, message):
    with pytest.raises(ConfigError) as info:
        check_config(dict(_cloud_config(tmp_path), **change), env_problems=())
    assert message in str(info.value) and SECRET not in str(info.value)


def test_the_secret_key_comes_from_the_secret_store(tmp_path, monkeypatch):
    from engine import secret_store
    (tmp_path / "k").write_text(SECRET)
    monkeypatch.setenv("CLOUD_SECRET_ACCESS_KEY_FILE", str(tmp_path / "k"))
    cfg = {}
    assert secret_store.apply(cfg, backend=None)["CLOUD_SECRET_ACCESS_KEY"] == "environment"
    assert cfg["cloud_secret_access_key"] == SECRET


# ------------------------------------------------------------------ a real S3 PUT over HTTPS
def _tls_files(tmp_path):
    from tests.test_alerts import _self_signed
    return _self_signed(tmp_path)


class _S3Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"          # answers boto3's Expect: 100-continue
    seen: list = []
    echo_checksum = True

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        _S3Handler.seen.append((self.path, dict(self.headers), body))
        checksum = base64.b64encode(hashlib.sha256(body).digest()).decode()
        if (self.headers.get("x-amz-checksum-sha256") != checksum
                or self.headers.get("x-amz-sdk-checksum-algorithm") != "SHA256"):
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("ETag", '"' + hashlib.md5(body).hexdigest() + '"')  # nosec - S3 ETag
        if self.echo_checksum:
            self.send_header("x-amz-checksum-sha256", checksum)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _Server(HTTPServer):
    def server_bind(self):                 # no reverse DNS look-up (getfqdn can stall)
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", self.server_address[1]


@pytest.fixture
def https_s3(tmp_path):
    pytest.importorskip("boto3")
    cert, key = _tls_files(tmp_path)
    server = _Server(("127.0.0.1", 0), _S3Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    _S3Handler.seen = []
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"https://localhost:{server.server_address[1]}", cert
    server.shutdown()


@pytest.mark.parametrize("echo_checksum", [True, False])
def test_a_real_create_only_put_over_verified_https(
        tmp_path, app, https_s3, monkeypatch, echo_checksum):
    # The receiver validates the bytes even when it omits the response checksum.
    monkeypatch.setattr(_S3Handler, "echo_checksum", echo_checksum)
    endpoint, cert = https_s3
    cfg = _cloud_config(tmp_path, cloud_endpoint=endpoint, cloud_ca_bundle=str(cert))
    up = C.S3Uploader(cfg, "cd" * 16)
    key = up.put("report", b'{"results": []}')
    [(path, headers, body)] = _S3Handler.seen
    headers = {k.lower(): v for k, v in headers.items()}
    assert path == f"/aegis-reports/{key}" and body == b'{"results": []}'
    assert headers["if-none-match"] == "*"
    assert headers["x-amz-sdk-checksum-algorithm"] == "SHA256"
    assert headers["x-amz-checksum-sha256"] == base64.b64encode(hashlib.sha256(body).digest()).decode()
    assert "AKIDEXAMPLE" in headers["authorization"] and SECRET not in json.dumps(headers)


def test_an_endpoint_whose_certificate_does_not_verify_gets_nothing(tmp_path, app, https_s3):
    endpoint, _ = https_s3
    up = C.S3Uploader(_cloud_config(tmp_path, cloud_endpoint=endpoint), "cd" * 16)
    with pytest.raises(C.CloudError):
        up.put("report", b"{}")
    assert _S3Handler.seen == []
    with pytest.raises(C.CloudError, match="https"):
        C.S3Uploader(_cloud_config(tmp_path, cloud_endpoint="http://localhost:1"), "cd" * 16)


def test_no_response_checksum_drains_the_spool_after_server_validation(tmp_path, app):
    cfg = _cloud_config(tmp_path)

    class VerifyingS3(FakeS3):
        def put_object(self, **kw):
            assert kw["ChecksumAlgorithm"] == "SHA256"
            assert kw["ChecksumSHA256"] == base64.b64encode(
                hashlib.sha256(kw["Body"]).digest()).decode()
            return super().put_object(**kw)

    C.spool_report([{"verdict": "Clean"}], cfg)
    s3 = VerifyingS3(echo=False)
    assert C.run_uploads(cfg, uploader=_uploader(cfg, s3))["uploaded"] == 1
    assert C.spool_for(cfg).status()["pending"] == 0
