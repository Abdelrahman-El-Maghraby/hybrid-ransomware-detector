"""M26 (owner-approved 2026-11-12, owner choices 2026-11-13): the sandbox wait
(CAPE and the intel service) ends 10 % of the scan limit (at least 1 s) before
the isolated worker would be stopped. A late report costs the sandbox layer
(status `timeout`, scan `partial`); the static findings and verdict are kept and
the verdict alert is sent, not a scan-failed notice. With less than one poll
interval left the file is not submitted. Only the sandbox is bounded;
VirusTotal and the LLM are unchanged. Every service here is a stand-in."""

import http.server
import json
import threading
import time
import zipfile

import pytest

import RansomwareScanner as RS
from core import outbox as OB
from core.intel_client import IntelSandbox
from core.outputs import deliver
from tests.helpers import make_pdf
from tests.test_incomplete_scan_alert import receiver  # noqa: F401  (fixture)
from tests.test_intel_service import CAPS, ScriptedIntel
from tests.test_sandbox import FakeCape, _scanner, client
from tests.test_scanner_integration import _config


def test_a_worker_knows_its_remaining_time(tmp_path):
    cfg = _config(tmp_path, _scanner_factory="tests.worker_fakes:make", scan_timeout_seconds=8)
    p = tmp_path / "scan" / "deadline.pdf"
    p.write_bytes(make_pdf("quarterly figures"))
    scanner = RS.RansomwareScanner(cfg)
    assert scanner.time_left() is None                      # in-process: no limit
    r = scanner.scan_one(str(p))
    assert r["scan_status"] != "failed"
    left = float((tmp_path / "scan" / "deadline.pdf.left").read_text())
    assert 4.0 < left <= 8.0                                 # measured inside the worker


# ------------------------------------------------------------- the clients
class TimedCape(FakeCape):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.timeouts = []

    def post(self, url, files=None, data=None, timeout=None):
        self.timeouts.append(timeout)
        return super().post(url, files, data, timeout)

    def get(self, url, timeout=None):
        self.timeouts.append(timeout)
        return super().get(url, timeout)


def test_cape_stops_at_the_deadline(tmp_path):
    f = tmp_path / "s.bin"
    f.write_bytes(b"inert")
    fake = TimedCape(statuses=("running",))
    cape = client(fake, wait=600)
    res = cape.analyze(str(f), deadline=100.0)
    assert res.status == "timeout" and res.task_id == 42
    assert "cut short by the scan time limit" in res.detail
    assert cape.clock() == 100.0                             # never past the deadline
    assert max(fake.timeouts) <= 100.0


def test_cape_without_a_deadline_is_unchanged(tmp_path):
    f = tmp_path / "s.bin"
    f.write_bytes(b"inert")
    fake = TimedCape(statuses=("running",))
    cape = client(fake, wait=60)
    res = cape.analyze(str(f))
    assert res.status == "timeout" and "cut short" not in res.detail
    assert cape.clock() == 60.0 and set(fake.timeouts) == {cape.timeout}


def test_the_intel_sandbox_stops_at_the_deadline(tmp_path):
    f = tmp_path / "s.docm"
    f.write_bytes(b"inert")
    clock = {"t": 0.0}
    slow = ScriptedIntel(CAPS, {"/v1/sandbox/submit": {"submitted": True, "task_id": 3},
                                "/v1/sandbox/poll": {"status": "pending"}})
    slow.timeout = 30                                       # as IntelClient has
    box = IntelSandbox(slow, wait_seconds=600, sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
                       clock=lambda: clock["t"])
    res = box.analyze(str(f), deadline=40.0)
    assert res.status == "timeout" and res.task_id == 3 and "cut short" in res.detail
    assert clock["t"] == 40.0


# --------------------------------------------------------------- the layer
def _script(tmp_path):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = tmp_path / "scan" / "tool.ps1"
    p.write_bytes(b"Start-Process notepad.exe\r\n")
    return p


def test_the_layer_waits_only_the_time_left(tmp_path, monkeypatch):
    s = _scanner(tmp_path, FakeCape(), submit="all")
    seen = {}

    def analyze(path, deadline=None):
        seen["deadline"] = deadline
        return client(FakeCape()).analyze(path)
    monkeypatch.setattr(s.sandbox, "analyze", analyze)
    s.config["scan_timeout_seconds"] = 300
    s.scan_deadline = time.monotonic() + 100                 # 100 s left of 300
    s.scan_file(str(_script(tmp_path)))
    assert 69 < seen["deadline"] - time.monotonic() <= 70   # 100 - 30 (10 % of 300)


def test_no_time_left_means_the_file_is_not_sent(tmp_path):
    fake = FakeCape()
    s = _scanner(tmp_path, fake, submit="all")
    s.config["scan_timeout_seconds"] = 300
    p = _script(tmp_path)
    s.scan_deadline = time.monotonic() + 40                  # 40 - 30 < one 15 s poll
    r = s.scan_file(str(p))
    assert fake.posts == []                                  # nothing left the machine
    box = r["scan_results"]["sandbox"]
    assert box["status"] == "timeout" and box["detail"].startswith(
        "not submitted: no time left in the scan limit")
    assert r["scan_status"] == "partial"
    assert any(g["layer"] == "sandbox" for g in r["incomplete_reasons"])


def test_outside_a_worker_the_layer_is_unchanged(tmp_path):
    fake = FakeCape()
    s = _scanner(tmp_path, fake, submit="all")
    r = s.scan_file(str(_script(tmp_path)))
    assert s.scan_deadline is None and r["scan_results"]["sandbox"]["status"] == "reported"


# ------------------------------------------------- check 8, in a real worker
class _Running(http.server.BaseHTTPRequestHandler):
    """A CAPE stand-in on loopback that accepts every task and never finishes it."""
    def _json(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.submitted += 1
        self._json({"error": False, "data": {"task_ids": [7]}})

    def do_GET(self):
        self._json({"data": {"status": "running"}})

    def log_message(self, *a):
        pass


@pytest.fixture
def slow_cape():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Running)
    server.submitted = 0
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def _lure(tmp_path):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = tmp_path / "scan" / "invoice.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("invoice.pdf.exe", b"MZ" + bytes(62))
        z.writestr("readme.txt", b"hi")
    return p


def test_a_slow_report_keeps_the_static_verdict(tmp_path, slow_cape, receiver):
    p = _lure(tmp_path)
    static = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False)).scan_file(str(p))
    cfg = _config(tmp_path, _scanner_factory="tests.worker_fakes:make_quick_poll",
                  scan_timeout_seconds=6, qr_scan_enabled=False,
                  sandbox_url=f"http://127.0.0.1:{slow_cape.server_port}")
    s = RS.RansomwareScanner(cfg)
    r = s.scan_one(str(p))
    assert slow_cape.submitted == 1                          # it did wait for the report
    assert r["scan_status"] == "partial"                     # not failed: the worker lived
    assert (r["verdict"], r["risk_score"]) == (static["verdict"], static["risk_score"])
    assert r["verdict"] == "Critical"
    box = r["scan_results"]["sandbox"]
    assert box["status"] == "timeout" and "cut short" in box["detail"]
    assert "scan_failed" not in r["scan_results"]
    assert OB.failed_alert(r) is None
    deliver([r], dict(cfg, webhook_url="https://siem.example.invalid/hook",
                      outbox_dir=str(tmp_path / "outbox"), jsonl_path=""))
    assert [m["kind"] for m in receiver] == ["verdict"]      # the detection, no failure notice
