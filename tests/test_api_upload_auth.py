"""M4: the API's /scan route reads its upload only after the token check. Before,
the `File(...)` parameter made FastAPI read and spool the whole multipart body
(up to AEGIS_API_MAX_UPLOAD_MB) before the route's token dependency ran. These
tests drive the ASGI app directly and count the body chunks it pulls and the
temporary spool files Starlette creates. Every upload is inert bytes."""

import asyncio

import pytest

from tests.test_scanner_integration import _config

TOKEN = "t" * 40
BOUNDARY = "X"


def _multipart(payload: bytes, name: str = "a.bin") -> bytes:
    return (f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="{name}"\r\n\r\n').encode() + payload + f"\r\n--{BOUNDARY}--\r\n".encode()


def _call(app, body: bytes, authorization: str = "", content_type: str = ""):
    """POST /scan through the ASGI interface; (status, chunks read, chunks sent)."""
    chunks = [body[i:i + 65536] for i in range(0, len(body), 65536)] or [b""]
    seen = {"read": 0, "status": None}

    async def receive():
        if seen["read"] < len(chunks):
            seen["read"] += 1
            return {"type": "http.request", "body": chunks[seen["read"] - 1],
                    "more_body": seen["read"] < len(chunks)}
        await asyncio.sleep(0)
        return {"type": "http.disconnect"}

    async def send(msg):
        if msg["type"] == "http.response.start" and seen["status"] is None:
            seen["status"] = msg["status"]
            seen["read_at_answer"] = seen["read"]

    headers = [(b"host", b"testserver"),
               (b"content-type", (content_type or f"multipart/form-data; boundary={BOUNDARY}")
                .encode()),
               (b"content-length", str(len(body)).encode())]
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": "POST", "path": "/scan", "raw_path": b"/scan", "query_string": b"",
             "root_path": "", "scheme": "http", "client": ("127.0.0.1", 50000),
             "server": ("testserver", 80), "headers": headers}
    asyncio.run(app(scope, receive, send))
    return seen["status"], seen["read_at_answer"], len(chunks)


@pytest.fixture
def app(tmp_path, monkeypatch):
    from api.server import create_app
    spooled = []
    import starlette.formparsers as fp
    real = fp.SpooledTemporaryFile

    def counting(*a, **k):
        spooled.append(1)
        return real(*a, **k)
    monkeypatch.setattr(fp, "SpooledTemporaryFile", counting)
    application = create_app(_config(tmp_path), token=TOKEN, isolate=False)
    application.state.spooled = spooled
    return application


BIG = _multipart(b"A" * (2 * 1024 * 1024))          # 33 chunks of 64 KiB


@pytest.mark.parametrize("authorization", ["", "Bearer wrong-token-value-000000000000"],
                         ids=["no-token", "wrong-token"])
def test_an_unauthorised_upload_is_refused_before_it_is_read(app, authorization):
    status, read, total = _call(app, BIG, authorization)
    assert status == 401
    assert read == 0 and total == 33                 # not one chunk of the body was pulled
    assert app.state.spooled == []                    # nothing was spooled to a temp file


def test_an_authorised_upload_is_read_and_scanned(app):
    status, read, total = _call(app, BIG, f"Bearer {TOKEN}")
    assert status == 200 and read == total            # the whole body, once authorised
    assert len(app.state.spooled) == 1                # the probe above sees spooling


def test_a_body_without_a_file_field_is_refused(app):
    status, _, _ = _call(app, b'{"file": "x"}', f"Bearer {TOKEN}", "application/json")
    assert status == 422


def test_scan_results_and_limits_are_unchanged(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import api.server as srv
    client = TestClient(srv.create_app(_config(tmp_path), token=TOKEN, isolate=False))
    auth = {"Authorization": f"Bearer {TOKEN}"}
    r = client.post("/scan", headers=auth, files={"file": ("../x/report.txt", b"hello")})
    assert r.status_code == 200 and r.json()["file_name"] == "report.txt"
    monkeypatch.setattr(srv, "MAX_UPLOAD_MB", 0.001)
    assert client.post("/scan", headers=auth,
                       files={"file": ("big.txt", b"x" * 5000)}).status_code == 413
    assert client.post("/scan", files={"file": ("a.txt", b"x")}).status_code == 401
