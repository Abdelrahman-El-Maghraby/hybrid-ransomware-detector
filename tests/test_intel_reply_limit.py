"""Intel replies are read with a size limit (core/intel_client.MAX_REPLY_BYTES) on
both transports: honest, exactly-at-limit, oversized, length-less, chunked and
lying replies, and unsupported encodings. A raw server on loopback sends exact
bytes, so headers can lie; each test sends at most a few MiB and has a socket
time-out, so nothing can hang or grow without bound."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import sys
import tempfile
import threading

import pytest

from core import intel_client as IC
from core.intel_client import BadReply, IntelClient, IntelError, read_reply

TOKEN = "t" * 40
LIMIT = 1000                          # read_reply's limit in the unit tests


class _Raw:
    """Accepts connections, reads one request, sends `reply` (bytes) and then
    closes, or with `hold` keeps the connection open after sending."""

    def __init__(self, reply: bytes, family=socket.AF_INET, path: str = "", hold=False):
        self.reply, self.hold = reply, hold
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind(path or ("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(10)
        self.port = None if path else self.sock.getsockname()[1]
        self.conns: list = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            while True:
                conn, _ = self.sock.accept()
                self.conns.append(conn)
                conn.settimeout(10)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                head, _, body = data.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    name, _, value = line.partition(b":")
                    if name.strip().lower() == b"content-length":
                        length = int(value)
                while len(body) < length:
                    body += conn.recv(65536)
                try:
                    conn.sendall(self.reply)
                except OSError:
                    pass                      # the client stopped reading: expected
                if not self.hold:
                    conn.close()
        except OSError:
            return

    def close(self):
        for c in self.conns:
            c.close()
        self.sock.close()


def _response(body: bytes, *, length="auto", extra=b"", status=b"200 OK") -> bytes:
    head = b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n" + extra
    if length == "auto":
        head += b"Content-Length: %d\r\n" % len(body)
    elif length is not None:
        head += b"Content-Length: " + str(length).encode() + b"\r\n"
    return head + b"Connection: close\r\n\r\n" + body


def _chunked(body: bytes, size=300) -> bytes:
    parts = b"".join(b"%x\r\n" % len(body[i:i + size]) + body[i:i + size] + b"\r\n"
                     for i in range(0, len(body), size))
    return (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            + parts + b"0\r\n\r\n")


@pytest.fixture
def raw():
    made = []

    def make(reply, **kw):
        s = _Raw(reply, **kw)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()


def _read(server, limit=LIMIT):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    try:
        conn.request("GET", "/v1/capabilities")
        return read_reply(conn.getresponse(), limit)
    finally:
        conn.close()


# ------------------------------------------------------------ read_reply itself
@pytest.mark.parametrize("make_reply", [
    lambda b: _response(b),                      # honest Content-Length
    lambda b: _response(b, length=None),         # no length: read until close
    lambda b: _chunked(b),                       # chunked
], ids=["content-length", "no-length", "chunked"])
@pytest.mark.parametrize("size", [0, 10, LIMIT], ids=["empty", "small", "exactly-at-limit"])
def test_replies_up_to_the_limit_are_read_whole(raw, make_reply, size):
    body = b"x" * size
    assert _read(raw(make_reply(body))) == body


@pytest.mark.parametrize("make_reply", [
    lambda b: _response(b),
    lambda b: _response(b, length=None),
    lambda b: _chunked(b),
], ids=["content-length", "no-length", "chunked"])
def test_one_byte_over_the_limit_is_refused(raw, make_reply):
    with pytest.raises(BadReply, match="limit"):
        _read(raw(make_reply(b"x" * (LIMIT + 1))))


def test_a_huge_declared_length_is_refused_before_reading(raw):
    """10 GiB declared, a little sent, the connection held open: refused from the
    header at once, without waiting for (or buffering) a body."""
    server = raw(_response(b"{}", length=10 * 1024 ** 3), hold=True)
    with pytest.raises(BadReply, match="10737418240 bytes"):
        _read(server)


def test_a_body_longer_than_its_declared_length_is_not_read_past_it(raw):
    """Content-Length 2 with megabytes behind it: only the declared bytes are
    read (HTTP framing), nothing more is buffered."""
    assert _read(raw(_response(b"{}" + b"x" * (2 * 1024 * 1024), length=2))) == b"{}"


def test_an_unbounded_stream_without_length_stops_at_the_limit(raw):
    """No length and 3 MiB on the wire: the read stops after limit + 1 bytes."""
    with pytest.raises(BadReply):
        _read(raw(_response(b"y" * (3 * 1024 * 1024), length=None)))


def test_a_body_shorter_than_its_declared_length_is_an_error(raw):
    """Content-Length 500, two bytes, then the connection closes: read(amt)
    returns the two bytes without complaint, so the length is compared."""
    with pytest.raises(BadReply, match="shorter than its declared 500"):
        _read(raw(_response(b"{}", length=500)))


def test_a_chunked_body_cut_short_is_an_error(raw):
    cut = _chunked(b"x" * 600)[:-40]               # closes inside the chunks
    with pytest.raises(http.client.IncompleteRead):
        _read(raw(cut))


@pytest.mark.parametrize("encoding", [b"gzip", b"deflate", b"br"])
def test_a_compressed_reply_is_refused(raw, encoding):
    """The client asks for identity; a compressed body is not decoded (its
    decompressed size would be unbounded)."""
    server = raw(_response(b"\x1f\x8b" + b"\0" * 20, extra=b"Content-Encoding: " + encoding + b"\r\n"))
    with pytest.raises(BadReply, match="encoding"):
        _read(server)


def test_the_client_asks_for_identity_encoding(raw):
    seen = {}

    class Recording(_Raw):
        def _serve(self):
            conn, _ = self.sock.accept()
            seen["request"] = conn.recv(65536)
            conn.sendall(self.reply)
            conn.close()
    server = Recording(_response(b"{}"))
    try:
        _read(server)
    finally:
        server.close()
    assert b"accept-encoding: identity" in seen["request"].lower()


def test_the_default_limit_is_one_mebibyte_on_both_transports():
    import inspect
    assert IC.MAX_REPLY_BYTES == 1024 * 1024
    for fn in (IC.unix_request, IC.tls_request):
        assert "read_reply(resp)" in inspect.getsource(fn)
        assert "resp.read()" not in inspect.getsource(fn)


# ------------------------------------------------- through IntelClient (socket)
unix_only = pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or sys.platform == "win32",
                               reason="Unix domain sockets")


@pytest.fixture
def unix_raw():
    folder = tempfile.mkdtemp(prefix="ir", dir="/tmp")  # nosec B108 - private mkdtemp; short sun_path
    made = []

    def make(reply, **kw):
        path = os.path.join(folder, f"intel{len(made)}.sock")
        s = _Raw(reply, family=socket.AF_UNIX, path=path, **kw)
        made.append(s)
        return IntelClient(path, TOKEN, timeout=5)
    yield make
    for s in made:
        s.close()
    shutil.rmtree(folder, ignore_errors=True)


@unix_only
def test_a_normal_reply_is_unchanged(unix_raw):
    answer = {"is_malicious": False, "detection_ratio": 0, "total_engines": 70}
    assert unix_raw(_response(json.dumps(answer).encode())).vt_lookup("a" * 64) == answer


@unix_only
def test_a_reply_exactly_at_the_real_limit_is_accepted(unix_raw):
    pad = IC.MAX_REPLY_BYTES - len(b'{"p": ""}')
    body = b'{"p": "' + b"x" * pad + b'"}'
    assert len(body) == IC.MAX_REPLY_BYTES
    assert len(unix_raw(_response(body)).call("GET", "/v1/capabilities")["p"]) == pad


@unix_only
@pytest.mark.parametrize("framing", ["content-length", "no-length", "chunked"])
def test_an_oversized_reply_is_an_explicit_failure(unix_raw, framing):
    body = b'{"p": "' + b"x" * IC.MAX_REPLY_BYTES + b'"}'
    reply = {"content-length": _response(body), "no-length": _response(body, length=None),
             "chunked": _chunked(body, size=65536)}[framing]
    with pytest.raises(IntelError, match="limit") as e:
        unix_raw(reply).call("GET", "/v1/capabilities")
    assert e.value.status == 200                  # it answered; not "never delivered"


@unix_only
def test_a_lying_short_length_is_not_an_empty_success(unix_raw):
    """Content-Length 5 cuts a valid object to '{"is_': not JSON, so an error,
    where the client used to return {} as a successful answer."""
    client = unix_raw(_response(b'{"is_malicious": true}' + b" " * 100, length=5))
    with pytest.raises(IntelError, match="not JSON"):
        client.vt_lookup("a" * 64)


@unix_only
def test_a_lying_long_length_is_not_a_success(unix_raw):
    """'{}' with Content-Length 900: it would parse as an empty success."""
    with pytest.raises(IntelError, match="shorter than its declared 900"):
        unix_raw(_response(b"{}", length=900)).call("GET", "/v1/capabilities")


@unix_only
def test_a_chunked_reply_cut_short_is_an_unreadable_reply(unix_raw):
    with pytest.raises(IntelError, match="unreadable reply"):
        unix_raw(_chunked(b'{"a": "' + b"x" * 600 + b'"}')[:-40]).call("GET", "/x")


@unix_only
def test_an_error_status_with_an_oversized_body_keeps_its_status(unix_raw):
    big = b"z" * (IC.MAX_REPLY_BYTES + 10)
    with pytest.raises(IntelError) as e:
        unix_raw(_response(big, status=b"500 Internal Server Error")).call("GET", "/x")
    assert e.value.status == 500


@unix_only
def test_oversized_capabilities_read_as_unreachable_not_as_settings(unix_raw):
    body = b'{"llm": {"enabled": true, "pad": "' + b"x" * IC.MAX_REPLY_BYTES + b'"}}'
    client = unix_raw(_response(body))
    assert client.service("llm") == {"enabled": False, "unreachable": True}
    assert client._caps is None                    # nothing cached as valid


@unix_only
def test_oversized_llm_reply_is_a_failed_layer(unix_raw):
    caps = json.dumps({"llm": {"enabled": True, "name": "ollama", "model": "m"}}).encode()
    big = b'{"is_malicious": true, "details": "' + b"x" * IC.MAX_REPLY_BYTES + b'"}'

    class Two(_Raw):                               # capabilities, then the analysis
        replies = [_response(caps), _response(big)]

        def _serve(self):
            for reply in self.replies:
                conn, _ = self.sock.accept()
                conn.recv(65536)
                try:
                    conn.sendall(reply)
                except OSError:
                    pass
                conn.close()
    folder = tempfile.mkdtemp(prefix="ir", dir="/tmp")  # nosec B108 - private mkdtemp; short sun_path
    path = os.path.join(folder, "llm.sock")
    server = Two(b"", family=socket.AF_UNIX, path=path)
    try:
        out = IC.IntelLLMBackend(IntelClient(path, TOKEN, timeout=5)).analyze("text")
    finally:
        server.close()
        shutil.rmtree(folder, ignore_errors=True)
    assert out["analyzed"] is False and out.get("error")      # partial, not a verdict
    assert out["is_malicious"] is False


@unix_only
def test_oversized_sandbox_submit_reply_keeps_the_submission_possible(unix_raw, tmp_path):
    """Intel answered (it may have submitted the file): the result is an error
    with the submission still "possible", never "not_attempted" or a report."""
    sample = tmp_path / "inert.txt"
    sample.write_text("inert", encoding="utf-8")
    client = unix_raw(_response(b'{"submitted": true, "p": "' + b"x" * IC.MAX_REPLY_BYTES
                                + b'"}'))
    client._caps = {"sandbox": {"enabled": True, "server": "cape"}}
    res = IC.IntelSandbox(client).analyze(str(sample))
    assert res.status == "error" and res.submission == "possible"
    assert "limit" in res.detail and not res.signatures


@unix_only
def test_oversized_virustotal_reply_is_an_error_and_never_cached(unix_raw, tmp_path):
    import hashlib

    import RansomwareScanner as RS
    from tests.test_scanner_integration import _config
    scanner = RS.RansomwareScanner(_config(tmp_path, data_dir=str(tmp_path / "data")))
    assert scanner.cache is not None
    big = b'{"total_engines": 70, "malicious_detections": 5, "p": "' + b"x" * IC.MAX_REPLY_BYTES + b'"}'
    client = unix_raw(_response(big))
    client._caps = {"virustotal": {"enabled": True, "upload": False}}
    scanner.intel = client
    f = tmp_path / "f.bin"
    f.write_bytes(b"inert")
    result = scanner.scan_file_with_virustotal(str(f))
    assert "limit" in result["error"] and result["total_engines"] == 0
    assert result["is_malicious"] is False
    sha = hashlib.sha256(b"inert").hexdigest()
    assert scanner.cache.get(sha, scanner._vt_cache_layer()) is None
