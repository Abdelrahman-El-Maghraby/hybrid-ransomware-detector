"""M26, provisional results (owner-approved 2026-11-13).

Inside an isolated worker the sandbox runs after the other slow layers. Before
its network wait the worker sends the parent a checked provisional result (every
other layer's findings, the sandbox at `timeout`) and then the submission state
as it changes. Two things bound the wait:

- cooperatively, inside the worker: no automatic retries, each request's timeout
  is the time left, no request with less than one second left, Retry-After only
  if it fits, a report that cannot be read is not a finished one;
- strictly, by the parent: the worker is stopped at the existing scan limit, and
  the parent then uses the provisional result (only that case: an invalid
  message, a dead worker or the memory limit keep their failure result).

Every service here is a loopback stand-in or a fake object; every file is inert.
Nothing is sent outside this machine."""

import http.server
import json
import os
import select
import socket
import socketserver
import threading
import time
import zipfile

import pytest

import RansomwareScanner as RS
from core import outbox as OB
from core.intel_client import IntelClient, IntelError, IntelSandbox
from core.outputs import deliver
from core.sandbox import CapeClient, SandboxResult, nothing_sent
from engine import workers as W
from tests.test_incomplete_scan_alert import receiver  # noqa: F401  (fixture)
from tests.test_intel_service import CAPS, TOKEN, ScriptedIntel
from tests.test_sandbox import FakeCape, FakeResponse, client
from tests.test_scanner_integration import _config

TASK = 7


# ------------------------------------------------------------ stand-ins
class Stand:
    """A CAPE (or proxy) stand-in on loopback, raw sockets, one behaviour per
    `mode`. It records request lines and counts connections opened and closed;
    a hanging or dripping answer ends when the client goes away or at teardown."""

    def __init__(self, mode, tls=False):
        self.mode, self.tls = mode, tls
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.lines, self.times = [], []
        self.opened = self.closed = self.posts = 0
        self.redirects = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(2)

    def wait_closed(self, n, seconds=5.0):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            with self.lock:
                if self.closed >= n and self.opened == self.closed:
                    return True
            time.sleep(0.05)
        return False

    # ----------------------------------------------------------- serving
    def _accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with self.lock:
            self.opened += 1
        try:
            conn.settimeout(0.2)
            if self.tls:
                self._recv_some(conn)                    # the ClientHello
                conn.sendall(b"\x16\x03\x03\x40\x00")   # a record header, then a drip
                self._drip(conn, b"\x00")
                return
            while not self.stop.is_set():
                req = self._read_request(conn)
                if req is None or not self._answer(conn, *req):
                    return
        except OSError:
            return
        finally:
            conn.close()
            with self.lock:
                self.closed += 1

    def _recv_some(self, conn):
        end = time.monotonic() + 2
        while time.monotonic() < end and not self.stop.is_set():
            try:
                if conn.recv(65536):
                    return
            except socket.timeout:
                continue

    def _read_request(self, conn):
        data = b""
        while b"\r\n\r\n" not in data:
            if self.stop.is_set():
                return None
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return None
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        length = 0
        for h in lines[1:]:
            if h.lower().startswith("content-length:"):
                length = int(h.split(":", 1)[1])
        while len(body) < length and not self.stop.is_set():
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return None
            body += chunk
        with self.lock:
            self.lines.append(lines[0])
            self.times.append(time.monotonic())
        return lines[0], body

    def _send(self, conn, code, body=b"", headers=()):
        reason = {200: "OK", 302: "Found", 500: "Error", 503: "Unavailable"}.get(code, "X")
        head = [f"HTTP/1.1 {code} {reason}", f"Content-Length: {len(body)}",
                "Content-Type: application/json", *headers]
        conn.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + body)
        return True

    def _json(self, conn, obj, code=200, headers=()):
        return self._send(conn, code, json.dumps(obj).encode(), headers)

    def _drip(self, conn, first=b"HTTP/1.1 200 OK\r\nX-Drip: "):
        try:
            conn.sendall(first)
            while not self.stop.is_set():
                time.sleep(0.2)
                conn.sendall(b"a")
        except OSError:
            pass                                   # the client went away
        return False

    def _hang(self, conn):
        """No answer; ends when the client closes its side (or at teardown)."""
        while not self.stop.is_set():
            ready, _, _ = select.select([conn], [], [], 0.1)
            if ready:
                try:
                    if not conn.recv(1):
                        return False
                except OSError:
                    return False
        return False

    def _answer(self, conn, line, body):
        mode = self.mode
        if line.startswith("POST"):
            with self.lock:
                self.posts += 1
            if mode in ("drip_submit", "proxy"):
                return self._drip(conn)
            if mode == "hang_submit":
                return self._hang(conn)
            if mode == "refuse":
                return self._json(conn, {"error": True, "error_value": "file too big"}, 400)
            return self._json(conn, {"error": False, "data": {"task_ids": [TASK]}})
        report = "/tasks/get/report/" in line
        if mode == "drip_view":
            return self._drip(conn)
        if mode == "hang_view":
            return self._hang(conn)
        if mode == "redirect_view":
            time.sleep(0.5)
            with self.lock:
                self.redirects += 1
                n = self.redirects
            return self._send(conn, 302, headers=(f"Location: /apiv2/tasks/view/{TASK}/?n={n}",))
        if mode.startswith("503"):
            ra = mode.partition(":")[2]
            return self._send(conn, 503, headers=((f"Retry-After: {ra}",) if ra else ()))
        if mode == "report_ok":
            if not report:
                return self._json(conn, {"data": {"status": "reported"}})
            return self._json(conn, {"malscore": 8.5, "signatures": [
                {"name": "ransomware_files", "severity": 3, "categories": ["ransomware"]}]})
        if mode in ("report_hang", "report_500"):
            if not report:
                return self._json(conn, {"data": {"status": "reported"}})
            if mode == "report_hang":
                return self._hang(conn)
            return self._send(conn, 500)
        return self._json(conn, {"data": {"status": "running"}})


@pytest.fixture
def stand():
    made = []

    def make(mode, tls=False):
        s = Stand(mode, tls)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()


def _lure(tmp_path, name="invoice.zip"):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = tmp_path / "scan" / name
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("invoice.pdf.exe", b"MZ" + bytes(62))
        z.writestr("readme.txt", b"hi")
    return p


def _inert(tmp_path, name="s.bin"):
    p = tmp_path / name
    p.write_bytes(b"inert test bytes")
    return p


def _worker_cfg(tmp_path, url, limit, **extra):
    return _config(tmp_path, _scanner_factory="tests.worker_fakes:make_sandbox_probe",
                   scan_timeout_seconds=limit, qr_scan_enabled=False, sandbox_url=url,
                   sandbox_submit="all", **extra)


def _scan_in_workers(cfg, paths, limit):
    """Scan `paths` with one isolated worker; [(path, result)], one per file."""
    s = RS.RansomwareScanner(cfg)
    got = []
    W.scan_isolated(s, [str(p) for p in paths], 1, limit, 0,
                    lambda i, path, r: got.append((path, r)))
    return s, got


def _probes(path):
    with open(str(path) + ".probe") as fh:
        return [json.loads(line) for line in fh]


# ============================================== the worker stop (strict bound)
STOPPED = [
    # (stand mode, tls, extra config, expected submission)
    ("drip_submit", False, {}, "possible"),          # CAPE drips its answer to the upload
    ("drip_view", False, {}, "confirmed"),           # the status check drips
    ("redirect_view", False, {}, "confirmed"),       # 30 slow redirects
    ("running", False, {"_hang_dns": True}, "possible"),   # a name lookup that hangs
]


@pytest.mark.parametrize("mode,tls,extra,submission", STOPPED,
                         ids=["drip-upload", "drip-status", "redirects", "dns-hang"])
def test_a_stall_the_worker_cannot_bound_keeps_the_static_verdict(
        tmp_path, stand, receiver, mode, tls, extra, submission):
    cape = stand(mode, tls=tls)
    url = cape.url if not extra.get("_hang_dns") else f"http://cape.example.invalid:{cape.port}"
    p = _lure(tmp_path)
    static = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False)).scan_file(str(p))
    cfg = _worker_cfg(tmp_path, url, 4, **extra)
    started = time.monotonic()
    s, got = _scan_in_workers(cfg, [p], 4)
    elapsed = time.monotonic() - started
    assert len(got) == 1                                     # one final result, once
    r = got[0][1]
    assert elapsed < 4 + 6                                   # the limit, the stop, the shutdown
    assert r["scan_status"] == "partial" and "scan_failed" not in r["scan_results"]
    assert (r["verdict"], r["risk_score"]) == (static["verdict"], static["risk_score"])
    box = r["scan_results"]["sandbox"]
    assert box["status"] == "timeout" and "worker was stopped" in box["detail"]
    assert box["submission"] == submission
    assert box["submitted"] is (submission == "confirmed")
    assert box["task_id"] == (TASK if submission == "confirmed" else None)
    shared = [e for e in r["provenance"]["shared"] if e["service"] == "sandbox"]
    assert shared == [{"service": "sandbox", "sent": ["file"]}]
    assert box["transmission"] == ("possible" if submission == "possible" else "sent")
    if submission == "possible":
        assert "not confirmed" in box["detail"]
    assert any(g["layer"] == "sandbox" and "worker was stopped" in g["reason"]
               for g in r["incomplete_reasons"])
    assert OB.failed_alert(r) is None
    deliver([r], dict(cfg, webhook_url="https://siem.example.invalid/hook",
                      outbox_dir=str(tmp_path / "outbox"), jsonl_path=""))
    assert [m["kind"] for m in receiver] == ["verdict"]     # once; no failure notice
    if not extra.get("_hang_dns"):
        assert cape.wait_closed(1)                          # the stopped worker's sockets went
    key = "sandbox:" + __import__("hashlib").sha256(
        f"{s.sandbox.url}|{s.sandbox.options}".encode()).hexdigest()[:12]
    time.sleep(0.5)
    assert s.cache.get(r["sha256_hash"], key) is None       # no late report reached the cache


def test_a_proxy_that_stalls_is_stopped_too(tmp_path, stand, monkeypatch):
    proxy = stand("proxy")
    for name in ("NO_PROXY", "no_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTP_PROXY", proxy.url)               # read by the spawned worker
    p = _lure(tmp_path)
    cfg = _worker_cfg(tmp_path, "http://cape.example.invalid:8000", 4)
    _, got = _scan_in_workers(cfg, [p], 4)
    r = got[0][1]
    assert r["scan_status"] == "partial" and r["verdict"] == "Critical"
    assert r["scan_results"]["sandbox"]["submission"] == "possible"
    assert proxy.lines and proxy.lines[0].startswith(
        "POST http://cape.example.invalid:8000/apiv2/tasks/create/file/")


def test_after_a_stop_a_new_worker_scans_the_next_file(tmp_path, stand):
    cape = stand("drip_view")
    first, second = _lure(tmp_path, "a.zip"), _lure(tmp_path, "b.zip")
    cfg = _worker_cfg(tmp_path, cape.url, 4)
    _, got = _scan_in_workers(cfg, [first, second], 4)
    assert [os.path.basename(p) for p, _ in got] == ["a.zip", "b.zip"]
    assert all(r["scan_results"]["sandbox"]["submission"] == "confirmed" for _, r in got)
    # neither worker lived to write its probe: each was stopped in the sandbox
    # wait, and the second file was served by the worker started in its place
    assert not os.path.exists(str(first) + ".probe")
    assert not os.path.exists(str(second) + ".probe")
    assert cape.wait_closed(2)                                   # both stopped workers' sockets


# ============================================ the cooperative bound (worker lives)
def test_repeated_scans_leave_nothing_behind_in_the_worker(tmp_path, stand):
    cape = stand("hang_view")                       # a time-out the worker bounds itself
    files = [_lure(tmp_path, f"f{i}.zip") for i in range(4)]
    cfg = _worker_cfg(tmp_path, cape.url, 5)
    _, got = _scan_in_workers(cfg, files, 5)
    assert len(got) == 4
    for _, r in got:
        box = r["scan_results"]["sandbox"]
        assert r["scan_status"] == "partial" and box["status"] == "timeout"
        assert box["submission"] == "confirmed" and "worker was stopped" not in box["detail"]
    probes = [_probes(f)[0] for f in files]
    assert len({p["pid"] for p in probes}) == 1                  # one worker, never stopped
    assert probes[-1]["threads"] <= probes[1]["threads"]         # no thread left per scan
    assert probes[-1]["fds"] <= probes[1]["fds"]                 # no socket left per scan
    assert cape.wait_closed(4)                    # one kept-alive connection per scan, closed


def test_a_dripped_tls_handshake_ends_at_its_own_timeout(tmp_path, stand):
    """Observed with Python 3.14.2 on macOS: the handshake's timeout covered the
    whole dripped handshake, so the worker bounded it itself and lived."""
    cape = stand("running", tls=True)
    p = _lure(tmp_path)
    cfg = _worker_cfg(tmp_path, cape.url, 5)
    _, got = _scan_in_workers(cfg, [p], 5)
    r = got[0][1]
    box = r["scan_results"]["sandbox"]
    assert r["scan_status"] == "partial" and r["verdict"] == "Critical"
    assert box["status"] == "error" and "worker was stopped" not in box["detail"]
    assert box["submission"] == "possible" and box["transmission"] == "possible"
    assert len(_probes(p)) == 1                                  # the worker finished the file
    assert cape.wait_closed(1)


def test_slow_other_layers_leave_the_sandbox_no_time(tmp_path, stand):
    """The sandbox runs after the other slow layers in a worker: their time is
    taken from its wait, and too little left means the file is not sent. Limit
    10 s, margin 1 s, poll 3 s: after 6.3 s of VirusTotal at most 2.7 s is usable."""
    cape = stand("running")
    p = _lure(tmp_path)
    cfg = _worker_cfg(tmp_path, cape.url, 10, _slow_vt_seconds=6.3, _poll_seconds=3)
    _, got = _scan_in_workers(cfg, [p], 10)
    box = got[0][1]["scan_results"]["sandbox"]
    assert cape.posts == 0                                       # nothing left the machine
    assert box["status"] == "timeout" and box["submission"] == "not_attempted"
    assert box["detail"].startswith("not submitted: no time left in the scan limit")
    assert box["transmission"] == "none" and "sent" not in box
    assert not [e for e in got[0][1]["provenance"]["shared"] if e["service"] == "sandbox"]


# ===================================== failures keep their failure reporting
@pytest.mark.parametrize("flag,why", [("_crash_in_sandbox", "died"),
                                      ("_bad_provisional", "invalid reply")])
def test_a_dead_worker_or_a_bad_provisional_result_is_still_a_failure(tmp_path, stand, flag, why):
    cape = stand("running")
    p = _lure(tmp_path)
    cfg = _worker_cfg(tmp_path, cape.url, 4, **{flag: True})
    _, got = _scan_in_workers(cfg, [p], 4)
    r = got[0][1]
    assert r["scan_status"] == "failed" and why in r["scan_results"]["scan_failed"]["reason"]
    assert "sandbox" not in r["scan_results"]


# ============================================== in-process: order and messages
def _script(tmp_path):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = tmp_path / "scan" / "tool.ps1"
    p.write_bytes(b"Start-Process notepad.exe\r\n")
    return p


def _in_worker(s, left, limit=300):
    """Make an in-process scanner act as a worker's (listeners and a deadline)."""
    sent = {"provisional": [], "settled": [], "sandbox": []}
    s.provisional_listener = lambda result, settled=False: sent[
        "settled" if settled else "provisional"].append(result)
    s.sandbox_listener = lambda state, task_id=None: sent["sandbox"].append((state, task_id))
    s.config["scan_timeout_seconds"] = limit
    s.scan_deadline = time.monotonic() + left
    return sent


def _scanner(tmp_path, fake):
    s = RS.RansomwareScanner(_config(tmp_path, sandbox_url="http://cape.lab:8000",
                                     sandbox_submit="all"))
    s.sandbox = client(fake)
    return s


def _timed_layers(s, vt_seconds):
    marks = {}
    original_vt, original_box = s.scan_file_with_virustotal, s.sandbox.analyze

    def vt(*a, **k):
        time.sleep(vt_seconds)
        marks["vt_end"] = time.monotonic()
        return original_vt(*a, **k)

    def box(path, deadline=None, progress=None):
        marks["sandbox_start"] = time.monotonic()
        return (original_box(path, deadline=deadline, progress=progress) if progress
                else original_box(path, deadline=deadline))
    s.scan_file_with_virustotal, s.sandbox.analyze = vt, box
    return marks


def test_in_a_worker_the_sandbox_starts_after_the_other_slow_layers(tmp_path):
    s = _scanner(tmp_path, FakeCape())
    _in_worker(s, left=200)
    marks = _timed_layers(s, 0.4)
    s.scan_file(str(_script(tmp_path)))
    assert marks["sandbox_start"] >= marks["vt_end"]


def test_outside_a_worker_the_slow_layers_still_run_together(tmp_path):
    s = _scanner(tmp_path, FakeCape())
    marks = _timed_layers(s, 0.4)
    r = s.scan_file(str(_script(tmp_path)))
    assert marks["sandbox_start"] < marks["vt_end"]              # concurrent, as before
    box = r["scan_results"]["sandbox"]
    assert box["status"] == "reported" and box["submission"] == "confirmed"
    assert box["sent"] == ["file"] and box["transmission"] == "sent"


def test_the_time_the_other_layers_take_can_leave_too_little_for_a_submission(tmp_path):
    fake = FakeCape()
    s = _scanner(tmp_path, fake)
    _in_worker(s, left=19, limit=20)            # 19 s - 2 s margin = 17 s: enough at once
    _timed_layers(s, 2.5)                       # ... but under 15 s after VirusTotal
    r = s.scan_file(str(_script(tmp_path)))
    assert fake.posts == []
    assert r["scan_results"]["sandbox"]["detail"].startswith("not submitted: no time left")
    fake2 = FakeCape()
    s2 = _scanner(tmp_path, fake2)
    _in_worker(s2, left=19, limit=20)
    s2.scan_file(str(_script(tmp_path)))
    assert len(fake2.posts) == 1                                 # without the delay: sent


def test_the_provisional_result_is_built_without_side_effects(tmp_path, caplog):
    import logging
    caplog.set_level(logging.INFO, logger="RansomwareScanner")
    s = _scanner(tmp_path, FakeCape())
    sent = _in_worker(s, left=200)
    final = s.scan_file(str(_script(tmp_path)))
    assert len(sent["provisional"]) == 1
    prov = json.loads(json.dumps(sent["provisional"][0], default=str))
    kind, checked = W.check_reply(["provisional", prov])         # passes the parent's check
    box = checked["scan_results"]["sandbox"]
    assert (box["status"], box["submission"]) == ("timeout", "not_attempted")
    assert checked["scan_status"] == "partial"
    assert final["scan_results"]["sandbox"]["status"] == "reported"
    assert sent["sandbox"] == [("possible", None), ("confirmed", 42)]
    assert len(sent["settled"]) == 1                            # the outcome, once known
    settled = json.loads(json.dumps(sent["settled"][0], default=str))
    assert W.check_reply(["settled", settled])[1]["scan_results"]["sandbox"]["status"] == "reported"
    assert settled["verdict"] == final["verdict"]
    events = [getattr(r, "event", "") for r in caplog.records]
    assert events.count("scan_completed") == 1 and events.count("external_share") == 1


# ======================================================= the cooperative client
def _left(seconds):
    return time.monotonic() + seconds


def test_no_hidden_retries_within_the_deadline(tmp_path, stand):
    cape = stand("503")
    cc = CapeClient(cape.url, poll_seconds=0.3)
    started = time.monotonic()
    res = cc.analyze(str(_inert(tmp_path)), deadline=_left(2.0))
    assert time.monotonic() - started < 2.5
    assert res.status == "timeout" and res.submission == "confirmed" and res.task_id == TASK
    views = [t for line, t in zip(cape.lines, cape.times) if line.startswith("GET")]
    assert 2 <= len(views) <= 8                                  # one request per poll
    assert min(b - a for a, b in zip(views, views[1:])) >= 0.25  # no burst of retries


def test_a_retry_after_that_fits_is_honoured(tmp_path, stand):
    cape = stand("503:1")
    cc = CapeClient(cape.url, poll_seconds=0.2)
    cc.analyze(str(_inert(tmp_path)), deadline=_left(3.5))
    views = [t for line, t in zip(cape.lines, cape.times) if line.startswith("GET")]
    assert len(views) >= 2 and min(b - a for a, b in zip(views, views[1:])) >= 0.9


def test_a_retry_after_that_does_not_fit_ends_the_wait(tmp_path, stand):
    cape = stand("503:60")
    cc = CapeClient(cape.url, poll_seconds=0.2)
    started = time.monotonic()
    res = cc.analyze(str(_inert(tmp_path)), deadline=_left(3.0))
    assert time.monotonic() - started < 1.5
    assert res.status == "timeout" and "asked to wait 60s" in res.detail
    assert res.task_id == TASK


def test_a_report_that_hangs_after_reported_is_bounded(tmp_path, stand):
    cape = stand("report_hang")
    cc = CapeClient(cape.url, poll_seconds=0.2)
    started = time.monotonic()
    res = cc.analyze(str(_inert(tmp_path)), deadline=_left(2.0))
    assert time.monotonic() - started < 2.6
    assert res.status == "timeout" and res.submission == "confirmed" and res.task_id == TASK
    assert "report could not be read" in res.detail
    assert cape.wait_closed(1)                                    # the session was closed


def test_a_report_error_is_not_a_finished_report_within_the_deadline(tmp_path, stand):
    cape = stand("report_500")
    cc = CapeClient(cape.url, poll_seconds=0.2)
    res = cc.analyze(str(_inert(tmp_path)), deadline=_left(1.5))
    assert res.status == "timeout" and res.malscore == 0 and not res.signatures
    assert "report could not be read" in res.detail


def test_each_request_gets_the_time_left_when_it_starts(tmp_path):
    class Clocked(FakeCape):
        def __init__(self, clock):
            super().__init__(statuses=("reported",))
            self.clock, self.timeouts = clock, []

        def post(self, url, files=None, data=None, timeout=None):
            self.timeouts.append(timeout)
            self.clock["t"] += 5
            return super().post(url, files, data, timeout)

        def get(self, url, timeout=None, **kwargs):
            self.timeouts.append(timeout)
            self.clock["t"] += 5
            return super().get(url, timeout)
    clock = {"t": 0.0}
    fake = Clocked(clock)
    cc = CapeClient("http://cape.lab:8000", session=fake, timeout=100, clock=lambda: clock["t"],
                    sleep=lambda s: clock.__setitem__("t", clock["t"] + s))
    res = cc.analyze(str(_inert(tmp_path)), deadline=40.0)
    assert res.status == "reported"
    assert fake.timeouts == [40.0, 35.0, 30.0]          # submit, status, report


def test_no_request_starts_with_less_than_a_second_left(tmp_path):
    fake = FakeCape()
    cc = client(fake)                                     # fake clock at 0
    res = cc.analyze(str(_inert(tmp_path)), deadline=0.5)
    assert fake.posts == [] and fake.gets == []
    assert res.status == "timeout" and res.submission == "not_attempted"


def test_without_a_deadline_the_client_keeps_its_session_and_retries(tmp_path):
    cc = CapeClient("http://cape.lab:8000")
    adapter = cc.session.get_adapter("http://cape.lab:8000")
    assert adapter.max_retries.total == 3                 # the shared session, unchanged
    fake = FakeCape()
    res = client(fake).analyze(str(_inert(tmp_path)))
    assert res.status == "reported" and res.submission == "confirmed"


# ================================================= submission states, privacy
def test_a_connection_that_never_opens_sent_nothing(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                              # nothing listens there
    res = CapeClient(f"http://127.0.0.1:{port}").analyze(str(_inert(tmp_path)),
                                                         deadline=_left(3))
    assert res.status == "error" and res.submission == "not_attempted"
    assert res.as_dict()["transmission"] == "none"


def test_an_upload_without_an_answer_is_a_possible_transmission(tmp_path, stand):
    cape = stand("hang_submit")
    res = CapeClient(cape.url).analyze(str(_inert(tmp_path)), deadline=_left(1.5))
    assert res.submission == "possible" and not res.submitted and res.task_id is None
    assert res.as_dict()["transmission"] == "possible"


def test_a_refused_task_still_counts_as_sent(tmp_path):
    s = _scanner(tmp_path, FakeCape(refuse=True))
    r = s.scan_file(str(_script(tmp_path)))
    box = r["scan_results"]["sandbox"]
    assert box["submission"] == "refused" and box["submitted"] is False
    assert box["transmission"] == "sent" and box["sent"] == ["file"]
    assert {"service": "sandbox", "sent": ["file"]} in r["provenance"]["shared"]


def test_which_failures_certainly_sent_nothing():
    import requests
    from urllib3.exceptions import MaxRetryError, NewConnectionError, ProtocolError
    refused = requests.exceptions.ConnectionError(
        MaxRetryError(None, "/", reason=NewConnectionError(None, "refused")))
    aborted = requests.exceptions.ConnectionError(
        MaxRetryError(None, "/", reason=ProtocolError("aborted")))
    assert nothing_sent(refused) and nothing_sent(requests.exceptions.ConnectTimeout())
    assert not nothing_sent(aborted) and not nothing_sent(requests.exceptions.ReadTimeout())
    assert not nothing_sent(requests.exceptions.ProxyError(
        MaxRetryError(None, "/", reason=NewConnectionError(None, "proxy"))))


def test_a_cached_report_sent_nothing(tmp_path):
    fake = FakeCape()
    s = _scanner(tmp_path, fake)
    p = _script(tmp_path)
    s.scan_file(str(p))
    again = s.scan_file(str(p))["scan_results"]["sandbox"]
    assert again["status"] == "cached" and again["submission"] == "not_attempted"
    assert "sent" not in again and len(fake.posts) == 1


# ============================================================== the intel path
def test_intel_submission_states(tmp_path):
    f = _inert(tmp_path, "s.docm")
    cases = [
        (IntelError("down", delivered=False), "not_attempted"),
        (IntelError("HTTP 403", status=403), "not_attempted"),
        (IntelError("timed out"), "possible"),
        ({"submitted": False, "status": "error", "detail": "submission refused: 400"}, "refused"),
        ({"submitted": True, "task_id": 3, "status": "submitted"}, "confirmed"),
        ({"status": "cached", "submitted": True, "submission": "confirmed"}, "not_attempted"),
    ]
    for answer, state in cases:
        intel = ScriptedIntel(CAPS, {"/v1/sandbox/submit": answer,
                                     "/v1/sandbox/poll": {"status": "pending"}})
        clock = {"t": 0.0}
        res = IntelSandbox(intel, wait_seconds=30, clock=lambda: clock["t"],
                           sleep=lambda s: clock.__setitem__("t", clock["t"] + s)).analyze(str(f))
        assert res.submission == state, answer
    possible = IntelSandbox(ScriptedIntel(CAPS, {"/v1/sandbox/submit": IntelError("t")}))
    assert "may still have submitted" in possible.analyze(str(f)).detail


def test_intel_status_checks_retry_only_transient_failures(tmp_path):
    f = _inert(tmp_path, "s.docm")
    clock = {"t": 0.0}
    tick = {"clock": lambda: clock["t"], "sleep": lambda s: clock.__setitem__("t", clock["t"] + s)}
    flaky = ScriptedIntel(CAPS, {"/v1/sandbox/submit": {"submitted": True, "task_id": 3},
                                 "/v1/sandbox/poll": [IntelError("HTTP 503", status=503),
                                                      {"status": "reported", "submitted": True,
                                                       "task_id": 3, "malscore": 5.0}]})
    flaky.timeout = 30                                       # as IntelClient has
    res = IntelSandbox(flaky, poll_seconds=15, **tick).analyze(str(f), deadline=100.0)
    assert res.status == "reported" and res.submission == "confirmed"
    clock["t"] = 0.0
    wrong = ScriptedIntel(CAPS, {"/v1/sandbox/submit": {"submitted": True, "task_id": 3},
                                 "/v1/sandbox/poll": IntelError("HTTP 422", status=422)})
    wrong.timeout = 30
    assert IntelSandbox(wrong, **tick).analyze(str(f), deadline=100.0).status == "error"


# Windows Python has no socketserver.UnixStreamServer: define the stand-in only
# where Unix sockets exist, so the module still collects there.
unix_only = pytest.mark.skipif(not hasattr(socketserver, "UnixStreamServer"),
                               reason="needs Unix sockets")

if hasattr(socketserver, "UnixStreamServer"):
    class _UnixIntel(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True


@pytest.fixture
def unix_intel(tmp_path, monkeypatch):
    """An intel stand-in on a Unix socket whose path is relative to the test
    folder (a full temporary path can exceed the socket path limit)."""
    monkeypatch.chdir(tmp_path)
    stop = threading.Event()
    script = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            del body
            answer = script.get(self.path)
            if answer == "hang":
                stop.wait(10)
                return
            data = json.dumps(answer).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    server = _UnixIntel("i.sock", Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield script
    stop.set()
    server.shutdown()
    server.server_close()


def _intel_box():
    real = IntelClient("i.sock", TOKEN)
    real._caps = CAPS
    return IntelSandbox(real, poll_seconds=0.2)


@unix_only
def test_intel_over_a_socket_a_hanging_status_check_is_bounded(tmp_path, unix_intel):
    unix_intel.update({"/v1/sandbox/submit": {"submitted": True, "task_id": 5,
                                              "status": "submitted", "submission": "confirmed"},
                       "/v1/sandbox/poll": "hang"})
    started = time.monotonic()
    res = _intel_box().analyze(str(_inert(tmp_path, "s.docm")), deadline=_left(2.0))
    assert time.monotonic() - started < 2.6
    assert res.status == "timeout" and res.submission == "confirmed" and res.task_id == 5


@unix_only
def test_intel_over_a_socket_a_hanging_upload_is_possible_not_confirmed(tmp_path, unix_intel):
    unix_intel.update({"/v1/sandbox/submit": "hang"})
    started = time.monotonic()
    res = _intel_box().analyze(str(_inert(tmp_path, "s.docm")), deadline=_left(1.5))
    assert time.monotonic() - started < 2.1
    assert res.submission == "possible" and "may still have submitted" in res.detail


def test_intel_socket_that_does_not_exist_sent_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    real = IntelClient("missing.sock", TOKEN)
    real._caps = CAPS
    res = IntelSandbox(real).analyze(str(_inert(tmp_path, "s.docm")), deadline=_left(3))
    assert res.status == "error" and res.submission == "not_attempted"


# =================================================== the messages and the parent
def _provisional():
    box = SandboxResult(enabled=True, status="timeout", detail="stopped").as_dict()
    return {"file_path": "/x/a.zip", "verdict": "Critical", "risk_score": 95,
            "scan_status": "partial", "sha256_hash": "ab" * 32,
            "scan_results": {"sandbox": box, "stopped_layers": ["sandbox"]},
            "incomplete_reasons": [{"member_path": "/x/a.zip", "layer": "sandbox",
                                    "reason": "sandbox timeout: stopped", "status": "partial"}],
            "provenance": {"shared": [{"service": "virustotal", "sent": ["sha256"]}]}}


def test_provisional_and_progress_messages_are_checked():
    assert W.check_reply(["provisional", _provisional()])[0] == "provisional"
    bad = []
    for change in ({"scan_status": "complete"}, {"verdict": "Awful"}, {"risk_score": "95"},
                   {"scan_results": {}}, {"provenance": {"shared": "all"}}):
        bad.append({**_provisional(), **change})
    wrong_box = _provisional()
    wrong_box["scan_results"]["sandbox"]["status"] = "reported"
    sent_box = _provisional()
    sent_box["scan_results"]["sandbox"]["submission"] = "confirmed"
    for payload in bad + [wrong_box, sent_box, [], "x"]:
        with pytest.raises(W.InvalidReply):
            W.check_reply(["provisional", payload])
    assert W.check_reply(["sandbox", {"submission": "confirmed", "task_id": 7}])
    assert W.check_reply(["sandbox", {"submission": "possible", "task_id": None}])
    for payload in ({"submission": "sent", "task_id": None},
                    {"submission": "confirmed", "task_id": True},
                    {"submission": "confirmed", "task_id": -1},
                    {"submission": "possible", "task_id": 7},
                    {"submission": "possible", "task_id": None, "extra": 1},
                    {"submission": "confirmed"}, None):
        with pytest.raises(W.InvalidReply):
            W.check_reply(["sandbox", payload])


def test_a_provisional_result_over_the_size_limit_is_not_sent(monkeypatch):
    sent = []

    class Conn:
        def send_bytes(self, data):
            sent.append(data)
    monkeypatch.setattr(W, "MAX_REPLY_BYTES", 200)
    assert W.send_reply(Conn(), "provisional", _provisional()) is False and sent == []


@pytest.mark.parametrize("state,task,transmission,listed", [
    (None, None, "none", False),
    ("not_attempted", None, "none", False),
    ("possible", None, "possible", True),
    ("refused", None, "sent", True),
    ("confirmed", 9, "sent", True),
])
def test_the_stopped_result_completes_the_sandbox_entry(state, task, transmission, listed):
    prov = _provisional()
    progress = None if state is None else {"submission": state, "task_id": task}
    r = W.sandbox_stopped_result(prov, progress, 4, 4.2)
    box = r["scan_results"]["sandbox"]
    assert box["submission"] == (state or "not_attempted")
    assert box["transmission"] == transmission and box["task_id"] == task
    assert box["submitted"] is (state == "confirmed")
    assert ({"service": "sandbox", "sent": ["file"]} in r["provenance"]["shared"]) is listed
    assert r["incomplete_reasons"][0]["reason"] == f"sandbox timeout: {box['detail']}"
    assert (r["verdict"], r["risk_score"], r["scan_status"]) == ("Critical", 95, "partial")
    assert prov["scan_results"]["sandbox"]["detail"] == "stopped"     # the input is unchanged
    if task:
        assert f"task {task}" in box["detail"]


def test_fake_response_without_headers_is_accepted():
    from core.sandbox import retry_after
    assert retry_after(FakeResponse({})) is None


# ============================== M34 and the gap after the sandbox has answered
class ReportFails(FakeCape):
    """CAPE says the task is reported, but the report request fails or is not a
    JSON object."""

    def __init__(self, response):
        super().__init__(statuses=("reported",))
        self.response = response

    def get(self, url, timeout=None, **kwargs):
        self.gets.append(url)
        if "/tasks/view/" in url:
            return FakeResponse({"data": {"status": "reported"}})
        return self.response


class BadJson(FakeResponse):
    def json(self):
        raise ValueError("not JSON")

    def iter_content(self, chunk_size=1):
        yield b"<html>not JSON</html>"


@pytest.mark.parametrize("response", [FakeResponse({"error": "x"}, 500), FakeResponse([], 200),
                                      BadJson(None, 200), FakeResponse({}, 502)],
                         ids=["http-500", "a-list", "not-json", "http-502"])
def test_a_report_that_failed_is_not_a_finished_report(tmp_path, response):
    """M34, without a deadline (desktop and CLI outside a worker, and the intel
    service's own polling): the wait goes on and ends at timeout."""
    res = client(ReportFails(response), wait=60).analyze(str(_inert(tmp_path)))
    assert res.status == "timeout" and res.malscore == 0 and not res.signatures
    assert "report could not be read" in res.detail and res.task_id == 42


def test_an_empty_report_object_is_still_a_report(tmp_path):
    res = client(ReportFails(FakeResponse({}, 200)), wait=60).analyze(str(_inert(tmp_path)))
    assert res.status == "reported" and res.malscore == 0


def test_a_failed_report_is_not_cached(tmp_path):
    s = _scanner(tmp_path, ReportFails(FakeResponse({}, 500)))
    s.sandbox.wait_seconds = 60
    p = _script(tmp_path)
    box = s.scan_file(str(p))["scan_results"]["sandbox"]
    assert box["status"] == "timeout" and "report could not be read" in box["detail"]
    key = "sandbox:" + __import__("hashlib").sha256(
        f"{s.sandbox.url}|{s.sandbox.options}".encode()).hexdigest()[:12]
    assert s.cache.get(s.calculate_hashes(str(p))["sha256"], key) is None


def test_the_intel_wait_says_why_it_waited(tmp_path):
    why = "CAPE said task 3 finished, but its report could not be read (HTTP 500)"
    intel = ScriptedIntel(CAPS, {"/v1/sandbox/submit": {"submitted": True, "task_id": 3},
                                 "/v1/sandbox/poll": {"status": "pending", "detail": why}})
    clock = {"t": 0.0}
    res = IntelSandbox(intel, wait_seconds=30, clock=lambda: clock["t"],
                       sleep=lambda s: clock.__setitem__("t", clock["t"] + s)).analyze(
        str(_inert(tmp_path, "s.docm")))
    assert res.status == "timeout" and res.detail == why


def test_a_worker_stopped_after_the_sandbox_answered_keeps_that_answer(tmp_path, stand):
    cape = stand("report_ok")
    p = _script(tmp_path)
    static = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False)).scan_file(str(p))
    cfg = _worker_cfg(tmp_path, cape.url, 5, _slow_finish=True)
    _, got = _scan_in_workers(cfg, [p], 5)
    r = got[0][1]
    box = r["scan_results"]["sandbox"]
    assert box["status"] == "reported" and box["malscore"] == 8.5
    assert "did not answer" not in box["detail"] and "scan_failed" not in r["scan_results"]
    assert "sandbox_ransomware_behaviour" in {
        c["indicator"] for c in r["score_breakdown"]["contributions"]}
    assert r["risk_score"] > static["risk_score"]               # the sandbox's finding counts
    assert box["submission"] == "confirmed" and box["sent"] == ["file"]


def test_settled_results_are_checked():
    good = _provisional()
    good["scan_results"]["sandbox"].update(status="reported", submission="confirmed",
                                           transmission="sent")
    assert W.check_reply(["settled", good])[0] == "settled"
    for change in ({"status": "pending"}, {"submission": "sent"},
                   {"submission": "confirmed", "transmission": "none"}):
        bad = _provisional()
        bad["scan_results"]["sandbox"].update({"status": "reported", "submission": "confirmed",
                                               "transmission": "sent", **change})
        with pytest.raises(W.InvalidReply):
            W.check_reply(["settled", bad])


class _Streamed:
    """A streamed response: chunks as requests yields them after gzip decoding."""

    def __init__(self, chunks, headers=None):
        self.status_code, self.headers, self._chunks = 200, headers or {}, chunks
        self.read, self.closed = 0, False

    def iter_content(self, chunk_size=1):
        for chunk in self._chunks:
            self.read += len(chunk)
            yield chunk

    def close(self):
        self.closed = True


def test_a_report_over_the_size_limit_is_not_read():
    # PR-S2: the report was buffered and parsed whole, gzip-decoded, without a bound.
    from core.sandbox import ReportTooLarge, report_body
    declared = _Streamed([b"{}"], headers={"Content-Length": "2000"})
    with pytest.raises(ReportTooLarge, match="limit"):
        report_body(declared, limit=1000)
    assert declared.read == 0 and declared.closed
    endless = _Streamed(b"x" * 400 for _ in range(1000))      # 400 KB if read to the end
    with pytest.raises(ReportTooLarge):
        report_body(endless, limit=1000)
    assert endless.read <= 1200 and endless.closed


def test_a_report_within_the_limit_is_read_and_closed():
    from core.sandbox import report_body
    ok = _Streamed([b'{"malscore": ', b'2.5}'])
    assert report_body(ok, limit=1000) == {"malscore": 2.5} and ok.closed
