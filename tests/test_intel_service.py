"""4.7: the intel service (api/intel.py) is the only part of a Docker deployment
with network access. It offers fixed operations, connects only to destinations
from its own configuration, validates every input, needs the shared token and is
rate-limited. The analysis side reaches it over a Unix socket (core/intel_client.py).
Nothing here talks to a real service: sessions are fakes or refuse before sending."""

import os
import socket
import sys
import tempfile
import threading
import time

import pytest
import requests

from core.http import AllowlistSession, EgressDenied, build_session, origin
from engine.validation import validate_config

TOKEN = "i" * 40
SHA = "ab" * 32
VT_HIT = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1,
                                                          "undetected": 66}}}}


# ------------------------------------------------------------- the allowlist
def test_origin_normalises_and_refuses_tricks():
    assert origin("HTTPS://WWW.VirusTotal.com/api/v3/files") == "https://www.virustotal.com:443"
    assert origin("http://cape.lab:8000/apiv2/") == "http://cape.lab:8000"
    for bad in ("ftp://host/x", "https://allowed.example@evil.example/", "file:///etc/passwd",
                "//no-scheme", "https://"):
        with pytest.raises(ValueError):
            origin(bad)


class _Adapter(requests.adapters.BaseAdapter):
    """Answers every request locally; records what was sent."""

    def __init__(self, redirect_to=None):
        super().__init__()
        self.sent, self.redirect_to = [], redirect_to

    def send(self, request, **kwargs):
        self.sent.append(request.url)
        r = requests.Response()
        r.request, r.url = request, request.url
        if self.redirect_to and len(self.sent) == 1:
            r.status_code, r.headers["Location"] = 302, self.redirect_to
        else:
            r.status_code, r._content = 200, b"{}"
        return r

    def close(self):
        pass


def test_session_refuses_other_destinations_and_redirects():
    s = build_session(allowed_origins=["https://www.virustotal.com"])
    assert isinstance(s, AllowlistSession)
    adapter = _Adapter()
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    assert s.get("https://www.virustotal.com/api/v3/files/x").status_code == 200
    for url in ("https://evil.example/", "http://www.virustotal.com/",       # wrong scheme
                "https://www.virustotal.com:8443/", "http://169.254.169.254/latest/meta-data"):
        with pytest.raises(EgressDenied):
            s.get(url)
    assert adapter.sent == ["https://www.virustotal.com/api/v3/files/x"]

    bounce = _Adapter(redirect_to="https://evil.example/steal")
    s.mount("https://", bounce)
    with pytest.raises(EgressDenied):
        s.get("https://www.virustotal.com/api/v3/files/y")
    assert bounce.sent == ["https://www.virustotal.com/api/v3/files/y"]   # never followed
    assert isinstance(build_session(), requests.Session)                   # desktop: unchanged
    assert not isinstance(build_session(), AllowlistSession)


# ------------------------------------------------------------- the service
class FakeVT:
    """Stands in for the VirusTotal session; every URL must be VirusTotal's."""

    def __init__(self, status=200):
        self.status, self.seen = status, []

    def get(self, url, headers=None, timeout=None):
        assert origin(url) == "https://www.virustotal.com:443"
        self.seen.append(url)
        r = requests.Response()
        r.status_code = self.status
        r._content = b'{"data": {"attributes": {"last_analysis_stats": ' \
                     b'{"malicious": 3, "suspicious": 1, "undetected": 66}}}}'
        return r


class FakeCape:
    def __init__(self):
        self.headers, self.polls = {}, 0

    def post(self, url, files=None, data=None, timeout=None):
        r = requests.Response()
        r.status_code, r._content = 200, b'{"error": false, "data": {"task_ids": [7]}}'
        return r

    def get(self, url, timeout=None):
        r = requests.Response()
        r.status_code = 200
        if "/tasks/view/" in url:
            self.polls += 1
            r._content = (b'{"data": {"status": "reported"}}' if self.polls > 1
                          else b'{"data": {"status": "running"}}')
        else:
            r._content = b'{"malscore": 8.5, "signatures": [{"name": "ransomware_files", ' \
                         b'"severity": 3}]}'
        return r


def _intel_config(tmp_path, **extra):
    from tests.test_scanner_integration import _config
    cfg = _config(tmp_path, llm_provider="none", virustotal_api_key="vt-key-secret-value",
                  sandbox_url="http://cape.lab:8000", sandbox_token="cape-token-secret")
    cfg.update(extra)
    return cfg


@pytest.fixture
def intel(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from api.intel import IntelService, create_intel_app

    def build(**extra):
        for k in [k for k in extra if k.startswith("AEGIS_")]:
            monkeypatch.setenv(k, str(extra.pop(k)))
        service = IntelService(_intel_config(tmp_path, **extra))
        vt = FakeVT()
        for client in (service._vt, service._vt_upload):
            client.http = vt
        service.sandbox.session = FakeCape()
        api = TestClient(create_intel_app(token=TOKEN, service=service))
        return api, service, vt
    return build


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_token_is_required_and_strong(intel):
    api, _, _ = intel()
    assert api.get("/health").json() == {"status": "ok"}              # health check only
    assert api.get("/v1/capabilities").status_code == 401
    assert api.get("/v1/capabilities", headers={"Authorization": "Bearer " + "x" * 40}).status_code == 401
    assert api.post("/v1/virustotal/lookup", json={"sha256": SHA}).status_code == 401
    from api.intel import create_intel_app
    with pytest.raises(RuntimeError, match="at least 32"):
        create_intel_app(token="short-token", service=object())


def test_only_fixed_operations_exist(intel):
    api, _, _ = intel()
    for path in ("/v1/fetch", "/v1/proxy", "/fetch", "/v1/http", "/v1/virustotal/files",
                 "/docs", "/openapi.json", "/v1/llm/chat"):
        assert api.post(path, headers=AUTH, json={"url": "https://evil.example/"}).status_code == 404
        assert api.get(path, headers=AUTH).status_code == 404
    assert api.get("/v1/virustotal/lookup", headers=AUTH).status_code == 405


def test_inputs_are_validated(intel):
    api, _, vt = intel()
    for body in ({"sha256": "zz" * 32}, {"sha256": SHA[:-1]}, {"sha256": SHA, "url": "x"},
                 {"hash": SHA}, {"sha256": 5}, [SHA]):
        assert api.post("/v1/virustotal/lookup", headers=AUTH, json=body).status_code == 422, body
    for body in ({"content": ""}, {"content": "x" * 8001}, {"content": 3}):
        assert api.post("/v1/llm/analyze", headers=AUTH, json=body).status_code == 422
    for body in ({"task_id": 0}, {"task_id": "7"}, {"task_id": True}, {"task_id": 999}):
        assert api.post("/v1/sandbox/poll", headers=AUTH, json=body).status_code == 422
    r = api.post("/v1/sandbox/submit", headers={**AUTH, "X-Aegis-Extension": "../../x"},
                 content=b"inert")
    assert r.status_code == 422
    assert vt.seen == []


def test_hash_lookup_reaches_only_virustotal(intel):
    api, service, vt = intel()
    r = api.post("/v1/virustotal/lookup", headers=AUTH, json={"sha256": SHA.upper()})
    assert r.status_code == 200 and r.json()["malicious_detections"] == 3
    assert vt.seen == [f"https://www.virustotal.com/api/v3/files/{SHA}"]
    assert service.destinations == {"virustotal": ["https://www.virustotal.com:443"], "llm": [],
                                    "sandbox": ["http://cape.lab:8000"]}


def test_upload_needs_the_intel_side_switch(intel):
    api, _, vt = intel()                                       # VT_UPLOAD_UNKNOWN off
    r = api.post("/v1/virustotal/upload", headers=AUTH, content=b"inert test bytes")
    assert r.status_code == 403 and vt.seen == []


def test_llm_and_sandbox_operations(intel):
    api, _, _ = intel()
    assert api.post("/v1/llm/analyze", headers=AUTH, json={"content": "hello"}).status_code == 403
    sub = api.post("/v1/sandbox/submit", headers={**AUTH, "X-Aegis-Extension": ".docm"},
                   content=b"inert test bytes").json()
    assert sub["submitted"] and sub["task_id"] == 7
    assert api.post("/v1/sandbox/poll", headers=AUTH, json={"task_id": 7}).json()["status"] == "pending"
    done = api.post("/v1/sandbox/poll", headers=AUTH, json={"task_id": 7}).json()
    assert done["status"] == "reported" and done["malscore"] == 8.5
    # a finished task is forgotten: its report cannot be fetched again through intel
    assert api.post("/v1/sandbox/poll", headers=AUTH, json={"task_id": 7}).status_code == 422


def test_capabilities_carry_no_secret(intel):
    api, _, _ = intel()
    caps = api.get("/v1/capabilities", headers=AUTH)
    assert caps.status_code == 200
    text = caps.text
    for secret in ("vt-key-secret-value", "cape-token-secret", "cape.lab"):
        assert secret not in text
    body = caps.json()
    assert body["virustotal"] == {"enabled": True, "upload": False}
    assert body["sandbox"]["enabled"] and len(body["sandbox"]["server"]) == 12


def test_operations_are_rate_limited(intel):
    api, _, _ = intel(AEGIS_INTEL_RATE_PER_MINUTE=1, AEGIS_INTEL_BURST=2)
    codes = [api.post("/v1/virustotal/lookup", headers=AUTH, json={"sha256": SHA}).status_code
             for _ in range(3)]
    assert codes == [200, 200, 429]
    assert api.get("/v1/capabilities", headers=AUTH).status_code == 200   # its own bucket


def test_bodies_are_size_limited(intel):
    api, _, _ = intel(AEGIS_INTEL_MAX_UPLOAD_MB=0.001)
    r = api.post("/v1/sandbox/submit", headers=AUTH, content=b"x" * 5000)
    assert r.status_code == 413


def test_llm_session_is_allowlisted_too(tmp_path):
    pytest.importorskip("fastapi")
    from api.intel import IntelService, llm_destinations
    cfg = _intel_config(tmp_path, llm_provider="openai", chatgpt_api_key="sk-test",
                        chatgpt_api_url="https://api.openai.com/v1/chat/completions")
    assert llm_destinations(cfg) == ["https://api.openai.com:443"]
    assert llm_destinations(dict(cfg, llm_provider="none")) == []
    service = IntelService(cfg)
    with pytest.raises(EgressDenied):
        service.llm.http.get("https://www.virustotal.com/")
    with pytest.raises(EgressDenied):
        service.sandbox.session.get("https://api.openai.com/")
    assert "Authorization" not in service.llm.http.headers          # the CAPE token stays put


# ------------------------------------------------------------- analysis -> intel
pytestmark_unix = pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or sys.platform == "win32",
                                     reason="Unix domain sockets")


@pytest.fixture
def intel_socket(tmp_path):
    """A real intel service on a Unix socket, its VirusTotal session faked."""
    pytest.importorskip("fastapi")
    uvicorn = pytest.importorskip("uvicorn")
    from api.intel import IntelService, create_intel_app
    service = IntelService(_intel_config(tmp_path))
    vt = FakeVT()
    for client in (service._vt, service._vt_upload):
        client.http = vt
    folder = tempfile.mkdtemp(prefix="ai", dir="/tmp")            # short: sun_path limit
    path = os.path.join(folder, "intel.sock")
    server = uvicorn.Server(uvicorn.Config(create_intel_app(token=TOKEN, service=service),
                                           uds=path, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    yield path, vt
    server.should_exit = True
    thread.join(5)
    import shutil
    shutil.rmtree(folder, ignore_errors=True)


@pytestmark_unix
def test_scanner_uses_intel_over_the_socket(tmp_path, intel_socket):
    import RansomwareScanner as RS
    from core.intel_client import IntelLLMBackend
    from engine.capabilities import external_services
    from tests.test_scanner_integration import _config
    path, vt = intel_socket
    scanner = RS.RansomwareScanner(_config(tmp_path, intel_socket=path, intel_token=TOKEN,
                                           data_dir=str(tmp_path / "data")))
    assert isinstance(scanner.llm_backend, IntelLLMBackend)
    states = scanner.capability_states
    assert states["virustotal"] == {"state": "up", "detail": "hash look-up via intel", "missing": []}
    assert states["llm"]["state"] == "disabled"
    assert external_services(states)["sandbox"] == "submit=suspicious via intel"
    f = tmp_path / "f.txt"
    f.write_text("hello")
    vt_result = scanner.scan_file_with_virustotal(str(f))
    assert vt_result["malicious_detections"] == 3 and len(vt.seen) == 1
    assert scanner.scan_file_with_virustotal(str(f))["cached"] and len(vt.seen) == 1


@pytestmark_unix
def test_wrong_token_and_unreachable_intel_are_reported(tmp_path, intel_socket):
    from core.intel_client import IntelClient, IntelError
    path, _ = intel_socket
    with pytest.raises(IntelError, match="HTTP 401"):
        IntelClient(path, "w" * 40).vt_lookup(SHA)
    clock = {"t": 0.0}
    gone = IntelClient(os.path.join(os.path.dirname(path), "missing.sock"), TOKEN,
                       clock=lambda: clock["t"])
    assert gone.service("virustotal") == {"enabled": False, "unreachable": True}
    clock["t"] = 31.0                                    # retried after 30 s
    gone.socket_path = path
    assert gone.service("virustotal")["enabled"] is True


def test_unreachable_intel_makes_external_layers_down(tmp_path):
    import RansomwareScanner as RS
    from tests.test_scanner_integration import _config
    scanner = RS.RansomwareScanner(_config(tmp_path, intel_socket=str(tmp_path / "none.sock"),
                                           intel_token=TOKEN, data_dir=str(tmp_path / "data")))
    for name in ("virustotal", "llm", "sandbox"):
        assert scanner.capability_states[name]["state"] == "down", name
        assert scanner.capability_states[name]["missing"] == ["intel service"]
    f = tmp_path / "f.txt"
    f.write_text("hello")
    assert scanner.scan_file_with_virustotal(str(f))["error"] == "intel service unreachable"
    llm = scanner.analyze_with_llm(str(f), "some text", "", sha256=None)
    assert llm["analyzed"] is False and "unreachable" in llm["error"]


def test_validation_keeps_secrets_on_the_intel_side(monkeypatch):
    monkeypatch.delenv("AEGIS_INTEL_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_INTEL_TOKEN_FILE", raising=False)
    errors, _ = validate_config({"intel_socket": "/run/aegis/intel/intel.sock"}, ())
    assert any("AEGIS_INTEL_TOKEN" in e for e in errors)
    cfg = {"intel_socket": "/run/x.sock", "intel_token": TOKEN, "virustotal_api_key": "k"}
    errors, warnings = validate_config(cfg, ())
    assert not errors and any("VIRUSTOTAL_API_KEY" in w for w in warnings)
    errors, _ = validate_config(dict(cfg, profile="production", sandbox_token="t"), ())
    assert any("VIRUSTOTAL_API_KEY, SANDBOX_TOKEN" in e for e in errors)
    assert validate_config({"intel_socket": "", "virustotal_api_key": "k"}, ())[0] == []


@pytestmark_unix
def test_probe_reports_health(intel_socket):
    from api.probe import main
    path, _ = intel_socket
    assert main([path]) == 0
    assert main([path, "/v1/capabilities"]) == 1                     # needs the token
    assert main([path + ".missing"]) == 1
    assert main([]) == 2
