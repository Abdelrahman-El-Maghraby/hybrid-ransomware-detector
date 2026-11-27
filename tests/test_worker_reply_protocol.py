"""M18, owner-approved 2026-11-12: a worker's messages reach the parent as bounded
JSON bytes with a shape check, never as a pickle. A worker taken over by a parser
exploit cannot make the long-lived parent (the API process) run its code; a
malformed, oversized or unexpected message fails that file (scan_failed) and
stops the worker, and nothing in it is used. Valid messages work as before."""

import json
import multiprocessing as mp
import pickle
import threading

import pytest

from engine import workers as W
from tests.test_worker_limits import FakeConn
from tests.test_workers import _setup


class _Marker:
    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return (open, (self.path, "w"))


@pytest.fixture
def pipe():
    parent, child = mp.Pipe()
    yield parent, child
    parent.close()
    child.close()


def _write(child, raw):
    """Write from a thread: a message larger than the pipe buffer blocks until read."""
    t = threading.Thread(target=child.send_bytes, args=(raw,), daemon=True)
    t.start()
    return t


def _result(**over):
    r = {"file_path": "/x/a.pdf", "file_name": "a.pdf", "verdict": "Clean", "risk_score": 0,
         "scan_status": "complete", "scan_results": {}, "incomplete_reasons": [],
         "is_malicious": False, "provenance": {"isolation": "worker"}}
    r.update(over)
    return r


def test_a_pickle_from_a_worker_is_rejected_and_never_loaded(pipe, tmp_path):
    """Check 3 of the review, which ran code in the receiver before this fix."""
    parent, child = pipe
    marker = tmp_path / "pwned"
    child.send_bytes(pickle.dumps(("ok", _Marker(str(marker)))))
    kind, why = W._IsolatedScan._receive(None, type("W", (), {"parent": parent})())
    assert kind == "invalid" and "not JSON" in why
    assert not marker.exists()


def test_an_oversized_message_is_refused_before_it_is_read(pipe, monkeypatch):
    parent, child = pipe
    monkeypatch.setattr(W, "MAX_REPLY_BYTES", 1024)
    _write(child, json.dumps(["ok", _result(note="x" * 2000)]).encode())
    with pytest.raises(W.InvalidReply, match="over 1024 bytes"):
        W.read_reply(parent)


@pytest.mark.parametrize("raw,why", [
    (b"\xff\xfe", "not JSON"),
    (b"not json", "not JSON"),
    (b"[" * 100000 + b"]" * 100000, "not JSON"),                 # nesting past the stack
    (b'{"kind": "ok"}', "pair"),
    (b'["ok"]', "pair"),
    (b'["exec", "print(1)"]', "pair"),
    (b'["ready", {"a": 1}]', "ready message with a payload"),
    (b'["error", {"why": 1}]', "not text"),
    (b'["log", "x"]', "not a list"),
    (json.dumps(["log", [{}] * (W.LOG_RECORDS_PER_FILE + 2)]).encode(), "not a list"),
    (b'["log", [{"msg": "m", "getMessage": "x"}]]', "not a plain record"),
    (b'["log", [{"__class__": "x"}]]', "not a plain record"),
    (b'["log", ["text"]]', "not a plain record"),
    (b'["log", [{"msg": "%s", "args": ["x"]}]]', "not a plain record"),
    (b'["log", [{"msg": "m", "exc_info": [1, 2, 3]}]]', "not a plain record"),
    (b'["ok", []]', "not an object"),
    (json.dumps(["ok", {k: v for k, v in _result().items() if k != "verdict"}]).encode(),
     "without verdict"),
    (json.dumps(["ok", _result(verdict="Pwned")]).encode(), "unknown verdict"),
    (json.dumps(["ok", _result(scan_status="done")]).encode(), "unknown verdict or scan"),
    (json.dumps(["ok", _result(risk_score="95")]).encode(), "risk_score is a str"),
    (json.dumps(["ok", _result(risk_score=True)]).encode(), "risk_score is a bool"),
    (json.dumps(["ok", _result(scan_results=[])]).encode(), "scan_results is a list"),
    (json.dumps(["ok", _result(incomplete_reasons=["x"])]).encode(), "not objects"),
    # Shapes the parent's metrics read outside any guard; before the fix one such
    # reply raised in the parent and lost the results of the whole batch.
    (json.dumps(["ok", _result(scan_duration_ms="abc")]).encode(), "scan_duration_ms is a str"),
    (json.dumps(["ok", _result(scan_results={"scan_failed": "x"})]).encode(),
     "scan_results.scan_failed is not an object"),
    (json.dumps(["ok", _result(scan_results={"layer_errors": 5})]).encode(),
     "scan_results.layer_errors is not an object"),
    (b'["ok", ' + json.dumps(_result(risk_score=0)).replace('"risk_score": 0', '"risk_score": NaN').encode() + b']',
     "risk_score is not finite"),
    (json.dumps(["ok", _result(severity_score=float("inf"))]).encode(), "severity_score is not finite"),
], ids=lambda v: v.decode("latin-1")[:24] if isinstance(v, bytes) else None)
def test_malformed_and_unexpected_messages_are_refused(pipe, raw, why):
    parent, child = pipe
    writer = _write(child, raw)
    with pytest.raises(W.InvalidReply, match=why):
        W.read_reply(parent)
    writer.join(5)


def test_valid_messages_round_trip(pipe, tmp_path):
    parent, child = pipe
    name = "inv\udcffé.pdf"                      # a non-UTF-8 name read with surrogateescape
    result = _result(file_name=name, risk_score=42.5, verdict="Medium",
                     incomplete_reasons=[{"member_path": name, "reason": "r"}])
    records = [{"name": "RansomwareScanner", "msg": "done", "levelno": 20, "args": None}]
    for kind, payload in (("ready", None), ("log", records), ("ok", result),
                          ("error", "KeyError: 'x'")):
        assert W.send_reply(child, kind, payload)
        assert W.read_reply(parent) == (kind, payload)


def test_a_long_error_text_is_cut(pipe):
    parent, child = pipe
    threading.Thread(target=W.send_reply, args=(child, "error", "e" * 10000), daemon=True).start()
    assert W.read_reply(parent) == ("error", "e" * W.MAX_ERROR_CHARS)


def test_the_worker_sends_an_error_for_a_result_over_the_limit_and_drops_big_logs(monkeypatch):
    monkeypatch.setattr(W, "MAX_REPLY_BYTES", 1024)
    conn = FakeConn([])
    assert W.send_reply(conn, "log", [{"msg": "x" * 2000}]) is False
    assert conn.sent == []
    assert W.send_reply(conn, "ok", _result(note="x" * 2000))
    kind, text = conn.sent[0]
    assert kind == "error" and "too large to return" in text


def test_values_json_cannot_hold_are_sent_as_text(pipe):
    parent, child = pipe
    W.send_reply(child, "ok", _result(extra={"when": object, "tuple": (1, 2)}))
    _, got = W.read_reply(parent)
    assert got["extra"] == {"when": str(object), "tuple": [1, 2]}


def test_a_compromised_worker_fails_its_file_and_the_scan_continues(tmp_path):
    """Real isolated workers: one sends a crafted pickle, one a message over the
    size limit. Each file is reported as a failed scan, no code runs in the
    parent, and the other file is scanned normally."""
    s = _setup(tmp_path, ["evil.pdf", "huge.pdf", "ok.pdf"], scan_timeout_seconds=20)
    res = {r["file_name"]: r for r in s.scan_all_directories()}
    for bad, why in (("evil.pdf", "not JSON"), ("huge.pdf", "over")):
        r = res[bad]
        reason = r["scan_results"]["scan_failed"]["reason"]
        assert r["verdict"] == "Medium" and r["scan_status"] == "failed"
        assert "invalid reply" in reason and why in reason
    assert not (tmp_path / "scan" / "evil.pdf.pwned").exists()
    assert res["ok.pdf"]["verdict"] == "Clean" and res["ok.pdf"]["scan_status"] == "complete"


def test_an_invalid_first_message_is_a_failed_start(pipe):
    parent, child = pipe
    child.send_bytes(pickle.dumps(("ready", None)))
    proc = type("P", (), {"is_alive": lambda self: True, "exitcode": None})()
    killed = []
    w = type("W", (), {"parent": parent, "proc": proc, "created": 0.0, "ready": False,
                       "kill": lambda self: killed.append(True)})()
    assert W.wait_ready(w, 2) is False and killed == [True]
