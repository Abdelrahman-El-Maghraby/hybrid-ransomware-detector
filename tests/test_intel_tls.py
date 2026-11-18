"""Kubernetes intel transport (option E, docs/KUBERNETES.md): HTTPS to an address
with the certificate checked against a configured name, a private CA only, no
redirects, proxies, plaintext or retries. A real TLS server on 127.0.0.1 with
throwaway test certificates; nothing leaves this machine. The Docker socket
transport is covered by tests/test_intel_service.py and stays the default."""

from __future__ import annotations

import datetime
import http.server
import json
import ssl
import threading
import time
from pathlib import Path

import pytest

from core.intel_client import IntelClient, IntelError, TlsEndpoint, client_from_config

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

NAME = "aegis-intel.aegis-sentinel.svc"
TOKEN = "i" * 40


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _cert(subject_key, issuer_key, issuer_name, cn, *, ca=False, names=(), days=(-1, 30)):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(issuer_name)
         .public_key(subject_key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now + datetime.timedelta(days=days[0]))
         .not_valid_after(now + datetime.timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
                            critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _pem(obj) -> bytes:
    if hasattr(obj, "private_bytes"):
        return obj.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    return obj.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca_key, other_key = _key(), _key()
    ca = _cert(ca_key, ca_key, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")]),
               "test CA", ca=True)
    other = _cert(other_key, other_key,
                  x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other CA")]),
                  "other CA", ca=True)
    out = {"ca": d / "ca.pem", "other_ca": d / "other-ca.pem"}
    out["ca"].write_bytes(_pem(ca))
    out["other_ca"].write_bytes(_pem(other))
    leaves = {"good": ((NAME,), (-1, 30)), "wrong_name": (("intel.example.invalid",), (-1, 30)),
              "expired": ((NAME,), (-30, -1))}
    for label, (names, days) in leaves.items():
        k = _key()
        c = _cert(k, ca_key, ca.subject, names[0], names=names, days=days)
        (d / f"{label}.key").write_bytes(_pem(k))
        (d / f"{label}.pem").write_bytes(_pem(c))
        out[label] = (d / f"{label}.pem", d / f"{label}.key")
    return out


class _Server:
    """HTTPS on 127.0.0.1 that records every request it gets."""

    def __init__(self, cert, key, routes):
        self.requests: list = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append((self.command, self.path,
                                       self.headers.get("Authorization"), len(body)))
                status, headers, payload, delay = routes.get(self.path, (404, {}, {}, 0))
                if delay:
                    time.sleep(delay)
                data = json.dumps(payload).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _answer

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


CAPS = {"email": {"enabled": True}, "virustotal": {"enabled": True}}
ROUTES = {
    "/v1/capabilities": (200, {}, CAPS, 0),
    "/v1/virustotal/lookup": (200, {}, {"found": False}, 0),
    "/v1/virustotal/upload": (500, {}, {"detail": "busy"}, 0),
    "/v1/llm/analyze": (200, {}, {}, 3),                       # stalls past the time-out
}


@pytest.fixture
def server(pki):
    made = []

    def make(leaf="good", routes=None):
        cert, key = pki[leaf]
        s = _Server(cert, key, routes or ROUTES)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()


def _client(pki, port, ca="ca", name=NAME, token=TOKEN, timeout=10):
    ep = TlsEndpoint.parse(f"https://127.0.0.1:{port}", str(pki[ca]), name)
    return IntelClient("", token, tls=ep, timeout=timeout)


# ------------------------------------------------------------------ it works
def test_a_verified_connection_carries_the_token(server, pki):
    s = server()
    assert _client(pki, s.port).call("GET", "/v1/capabilities") == CAPS
    assert s.requests == [("GET", "/v1/capabilities", f"Bearer {TOKEN}", 0)]


# ------------------------------------------------------------------ identity
@pytest.mark.parametrize("leaf,ca,name,why", [
    ("good", "other_ca", NAME, "a certificate from a CA that is not configured"),
    ("wrong_name", "ca", NAME, "a certificate for another name"),
    ("good", "ca", "other.aegis-sentinel.svc", "a configured name the certificate lacks"),
    ("expired", "ca", NAME, "an expired certificate"),
])
def test_an_unverified_server_gets_nothing(server, pki, leaf, ca, name, why):
    """The request, and so the token, is sent only after the certificate and its
    name are verified; a failure is 'unreachable', never a downgrade."""
    s = server(leaf)
    with pytest.raises(IntelError) as e:
        _client(pki, s.port, ca=ca, name=name).call("GET", "/v1/capabilities")
    assert e.value.delivered is False and "unreachable" in str(e.value), why
    assert s.requests == [], why


def test_the_system_trust_store_is_not_used(pki, monkeypatch):
    def refuse(self, *a, **k):
        raise AssertionError("the system trust store was loaded")
    for name in ("load_default_certs", "set_default_verify_paths"):
        monkeypatch.setattr(ssl.SSLContext, name, refuse)
    monkeypatch.setattr(ssl, "create_default_context", refuse)
    ctx = TlsEndpoint.parse("https://10.96.0.20:9443", str(pki["ca"]), NAME).context()
    assert len(ctx.get_ca_certs()) == 1
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_a_renewed_ca_file_applies_without_a_restart(server, pki, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(Path(pki["other_ca"]).read_bytes())
    s = server()
    client = IntelClient("", TOKEN, tls=TlsEndpoint.parse(f"https://127.0.0.1:{s.port}",
                                                          str(ca), NAME))
    with pytest.raises(IntelError):
        client.call("GET", "/v1/capabilities")
    ca.write_bytes(Path(pki["ca"]).read_bytes())                # rotated in place
    assert client.call("GET", "/v1/capabilities") == CAPS


# ------------------------------------------------------------------ what is accepted
@pytest.mark.parametrize("url,ca,name,why", [
    ("http://10.96.0.20:9443", "ca.pem", NAME, "https://"),
    ("https://aegis-intel.aegis-sentinel.svc:9443", "ca.pem", NAME, "IP address"),
    ("https://10.96.0.20", "ca.pem", NAME, "explicit port"),
    ("https://10.96.0.20:9443/v1", "ca.pem", NAME, "nothing else"),
    ("https://user:pw@10.96.0.20:9443", "ca.pem", NAME, "nothing else"),
    ("https://10.96.0.20:9443?x=1", "ca.pem", NAME, "nothing else"),
    ("https://10.96.0.20:9443", "", NAME, "AEGIS_INTEL_CA_FILE"),
    ("https://10.96.0.20:9443", "ca.pem", "", "AEGIS_INTEL_SERVER_NAME"),
    ("https://10.96.0.20:9443", "ca.pem", "10.96.0.20", "AEGIS_INTEL_SERVER_NAME"),
])
def test_only_https_to_an_ip_with_a_ca_and_a_name_is_accepted(url, ca, name, why):
    with pytest.raises(ValueError, match=why):
        TlsEndpoint.parse(url, ca, name)


# ------------------------------------------------------------------ no redirects, proxies
def test_a_redirect_is_an_error_and_is_not_followed(server, pki):
    target = server()
    s = server(routes={"/v1/capabilities": (
        302, {"Location": f"https://127.0.0.1:{target.port}/v1/capabilities"}, {}, 0)})
    with pytest.raises(IntelError) as e:
        _client(pki, s.port).call("GET", "/v1/capabilities")
    assert e.value.status == 302
    assert target.requests == []                    # the token went nowhere else


def test_proxy_settings_are_ignored(server, pki, monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")    # nothing listens there
    s = server()
    assert _client(pki, s.port).call("GET", "/v1/capabilities") == CAPS


# ------------------------------------------------------------------ failures, bounds
def test_a_wrong_token_is_a_refusal_not_an_outage(server, pki):
    s = server(routes={"/v1/capabilities": (401, {}, {"detail": "bad token"}, 0)})
    with pytest.raises(IntelError) as e:
        _client(pki, s.port, token="w" * 40).call("GET", "/v1/capabilities")
    assert e.value.status == 401 and "bad token" in str(e.value)


def test_a_stalled_server_hits_the_time_out(server, pki):
    s = server()
    started = time.monotonic()
    with pytest.raises(IntelError, match="unreachable"):
        _client(pki, s.port).call("POST", "/v1/llm/analyze", {"x": 1}, timeout=0.5)
    assert time.monotonic() - started < 2.5


def test_a_closed_port_is_unreachable(pki):
    import socket
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]                # bound, not listening
    with pytest.raises(IntelError) as e:
        _client(pki, port).call("GET", "/v1/capabilities")
    assert e.value.delivered is False


def test_an_upload_is_sent_once_even_when_it_fails(server, pki, tmp_path):
    s = server()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"inert bytes" * 100)
    with pytest.raises(IntelError) as e:
        _client(pki, s.port).vt_upload(str(sample))
    assert e.value.status == 500
    assert [r[:2] for r in s.requests] == [("POST", "/v1/virustotal/upload")]


def test_capabilities_and_services_work_over_tls(server, pki):
    s = server()
    client = _client(pki, s.port)
    assert client.service("email") == {"enabled": True}


# ------------------------------------------------------------------ configuration
def test_the_configuration_picks_one_transport(pki, monkeypatch):
    monkeypatch.setenv("AEGIS_INTEL_TOKEN", TOKEN)
    sock = client_from_config({"intel_socket": "/run/aegis/intel/intel.sock"})
    assert sock is not None and sock.socket_path and sock.tls is None       # Docker
    tls = client_from_config({"intel_url": "https://10.96.0.20:9443",
                              "intel_ca_file": str(pki["ca"]), "intel_server_name": NAME})
    assert tls is not None and tls.tls is not None and not tls.socket_path
    assert client_from_config({"intel_url": "http://10.96.0.20:9443",
                               "intel_ca_file": str(pki["ca"]),
                               "intel_server_name": NAME}) is None
    assert client_from_config({}) is None
    with pytest.raises(ValueError):
        IntelClient("/x.sock", TOKEN, tls=tls.tls)                  # never both


def test_the_configuration_check_refuses_a_bad_intel_url(pki, tmp_path, monkeypatch):
    from engine.validation import validate_config
    from tests.test_scanner_integration import _config
    monkeypatch.setenv("AEGIS_INTEL_TOKEN", TOKEN)
    base = _config(tmp_path)
    good = dict(base, intel_url="https://10.96.0.20:9443", intel_ca_file=str(pki["ca"]),
                intel_server_name=NAME)
    assert not [e for e in validate_config(good)[0] if "INTEL" in e]
    cases = [
        (dict(good, intel_socket="/x.sock"), "both set"),
        (dict(good, intel_url="http://10.96.0.20:9443"), "https://"),
        (dict(good, intel_ca_file=str(tmp_path / "missing.pem")), "cannot be read"),
        (dict(good, intel_server_name=""), "AEGIS_INTEL_SERVER_NAME"),
        (dict(good, virustotal_api_key="k" * 64, profile="production"), "belong to the intel"),
    ]
    for cfg, why in cases:
        assert any(why in e for e in validate_config(cfg)[0]), why
