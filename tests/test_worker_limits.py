"""engine/workers.py internals: the per-OS memory limits (RLIMIT_AS, Windows Job
Object, macOS watchdog) and the worker loop, tested in-process with fakes where
the real call would limit the test run itself, and for real where it is safe."""

import ctypes
import os
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from engine import workers as W
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------- _limit_memory
def test_no_limit_and_platform_choice(monkeypatch):
    assert W._limit_memory(0) == ""
    assert W._limit_memory(512, platform="darwin") == "watchdog"
    monkeypatch.setattr(W, "_windows_job_limit", lambda mb: mb == 512)
    assert W._limit_memory(512, platform="win32") == "job"
    assert W._limit_memory(64, platform="win32") == ""


@pytest.mark.skipif(sys.platform == "win32", reason="the resource module is POSIX")
def test_rlimit_is_set_without_limiting_the_test_run(monkeypatch):
    import resource
    calls = []
    monkeypatch.setattr(resource, "setrlimit", lambda what, lim: calls.append((what, lim)))
    assert W._limit_memory(256, platform="linux") == "rlimit"
    assert calls == [(resource.RLIMIT_AS, (256 << 20, 256 << 20))]

    def refuse(*a):
        raise ValueError("not allowed")
    monkeypatch.setattr(resource, "setrlimit", refuse)
    assert W._limit_memory(256, platform="linux") == ""


# ------------------------------------------------------------ Windows Job Object
class FakeKernel32:
    def __init__(self, fail=""):
        self.fail, self.calls, self.limits = fail, [], None

    def CreateJobObjectW(self, attrs, name):
        self.calls.append("create")
        return None if self.fail == "create" else 0x44

    def SetInformationJobObject(self, job, cls, info, size):
        self.calls.append(("set", job, cls, size))
        self.limits = ctypes.cast(info, ctypes.POINTER(W.JobLimits)).contents
        return 0 if self.fail == "set" else 1

    def GetCurrentProcess(self):
        return -1

    def AssignProcessToJobObject(self, job, proc):
        self.calls.append(("assign", job, proc))
        return 0 if self.fail == "assign" else 1


def test_job_object_is_configured_and_kept(monkeypatch):
    monkeypatch.setattr(W, "_JOB_HANDLE", None)
    k = FakeKernel32()
    assert W._windows_job_limit(300, kernel32=k)
    flags = k.limits.BasicLimitInformation.LimitFlags
    assert flags & W.JOB_OBJECT_LIMIT_PROCESS_MEMORY and flags & W.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert k.limits.ProcessMemoryLimit == 300 << 20
    assert k.calls[1] == ("set", 0x44, 9, ctypes.sizeof(W.JobLimits))
    assert k.calls[2] == ("assign", 0x44, -1) and W._JOB_HANDLE == 0x44


@pytest.mark.parametrize("fail", ["create", "set", "assign"])
def test_job_object_failures_are_not_fatal(monkeypatch, fail):
    monkeypatch.setattr(W, "_JOB_HANDLE", None)
    assert not W._windows_job_limit(300, kernel32=FakeKernel32(fail))
    assert W._JOB_HANDLE is None


def test_job_object_off_windows():
    if sys.platform != "win32":
        assert not W._windows_job_limit(300)          # no WinDLL: refused, not raised
        with pytest.raises(OSError):
            W._kernel32()


@pytest.mark.skipif(sys.platform != "win32", reason="real Job Object")
def test_job_object_really_caps_memory():
    code = (f"import sys; sys.path.insert(0, {ROOT!r})\n"
            "from engine.workers import _windows_job_limit\n"
            "assert _windows_job_limit(400)\n"
            "try:\n    bytearray(2 * 1024 ** 3)\nexcept MemoryError:\n    print('capped')\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip() == "capped", out.stderr


# -------------------------------------------------------------- macOS watchdog
class FakeLibproc:
    def __init__(self, rss=None):
        def proc_pidinfo(pid, flavor, arg, buf, size):     # a plain function takes restype
            assert flavor == W.PROC_PIDTASKINFO and size == ctypes.sizeof(W._TaskInfo)
            if rss is None:
                return 0
            buf._obj.pti_resident_size = rss
            return size
        self.proc_pidinfo = proc_pidinfo


def test_macos_reader_with_a_fake_libproc():
    assert W.macos_rss_reader(FakeLibproc(123 << 20))(42) == 123 << 20
    assert W.macos_rss_reader(FakeLibproc(None))(42) is None
    assert W.macos_rss_reader(SimpleNamespace()) is None          # no proc_pidinfo
    assert ctypes.sizeof(W._TaskInfo) == 96                       # sys/proc_info.h


def test_macos_reader_counts_compressed_memory():
    """Resident size misses what macOS compressed; the physical footprint does not."""
    fake = FakeLibproc(100 << 20)

    def proc_pid_rusage(pid, flavor, buf):
        assert flavor == W.RUSAGE_INFO_V0
        buf._obj.ri_phys_footprint = 3 << 30                     # 3 GB, mostly compressed
        return 0
    fake.proc_pid_rusage = proc_pid_rusage
    assert W.macos_rss_reader(fake)(42) == 3 << 30
    fake.proc_pid_rusage = lambda pid, flavor, buf: -1           # call failed: resident size
    assert W.macos_rss_reader(fake)(42) == 100 << 20
    assert ctypes.sizeof(W._RusageInfoV0) == 96                  # sys/resource.h


@pytest.mark.skipif(sys.platform != "darwin", reason="real libproc")
def test_macos_reader_reads_this_process():
    read = W.macos_rss_reader()
    assert read is not None and read(os.getpid()) > 10 << 20


def test_watchdog_only_on_macos(monkeypatch):
    assert W.memory_watchdog(512, platform="linux") is None
    assert W.memory_watchdog(0, platform="darwin") is None
    monkeypatch.setattr(W, "macos_rss_reader", lambda: "reader")
    assert W.memory_watchdog(512, platform="darwin") == "reader"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc")
def test_linux_reader():
    assert W.linux_rss_reader(os.getpid()) > 1 << 20
    assert W.linux_rss_reader(2 ** 22 + 7) is None


def test_watchdog_stops_an_over_limit_worker(tmp_path, monkeypatch):
    """The parent-side kill path, on any OS: a reader reports the worker that
    holds slow.pdf as far over the limit; it is stopped and replaced."""
    import RansomwareScanner as RS

    def reader(pid):
        p = tmp_path / "scan" / "slow.pdf.pid"
        return 10 ** 12 if p.exists() and p.read_text() == str(pid) else 1
    monkeypatch.setattr(W, "memory_watchdog", lambda mb: reader)
    cfg = _config(tmp_path, _scanner_factory="tests.worker_fakes:make", scan_timeout_seconds=60,
                  scan_workers=1, worker_memory_mb=0)
    for n in ("slow.pdf", "ok.pdf"):
        (tmp_path / "scan" / n).write_bytes(make_pdf(n))
    t = time.monotonic()
    res = {r["file_name"]: r for r in RS.RansomwareScanner(cfg).scan_all_directories()}
    assert time.monotonic() - t < 50
    reason = res["slow.pdf"]["scan_results"]["scan_failed"]["reason"]
    assert reason.startswith("MemoryError: the worker used") and res["slow.pdf"]["verdict"] == "Medium"
    assert res["ok.pdf"]["verdict"] == "Clean"


def test_over_memory_is_throttled():
    scan = object.__new__(W._IsolatedScan)
    scan.rss, scan.memory_mb = (lambda pid: 5 << 30), 1024
    w = SimpleNamespace(path="x", proc=SimpleNamespace(pid=7), watched=0.0)
    assert scan._over_memory(w) == 5 << 30
    assert scan._over_memory(w) == 0                     # checked again only after 0.25 s
    w.path = None
    assert scan._over_memory(w) == 0
    scan.rss = None
    assert scan._over_memory(SimpleNamespace(path="x", proc=SimpleNamespace(pid=7),
                                             watched=0.0)) == 0


# ------------------------------------------------------------- the worker loop
class FakeConn:
    def __init__(self, incoming):
        self.incoming, self.sent = list(incoming), []

    def recv(self):
        if not self.incoming:
            raise EOFError
        return self.incoming.pop(0)

    def send(self, msg):
        self.sent.append(msg)


class ScriptedScanner:
    def __init__(self, cfg):
        self.cfg = cfg

    def scan_file(self, path):
        if path == "mem":
            raise MemoryError
        if path == "deep":
            raise RecursionError
        if path == "bad":
            raise KeyError("x")
        return {"file_path": path}


def make_scripted(cfg):
    return ScriptedScanner(cfg)


def test_worker_loop_reports_each_outcome():
    conn = FakeConn(["a.pdf", "mem", "deep", "bad", None])
    level = W.logging.getLogger("RansomwareScanner").level
    try:
        W._worker_main({"_scanner_factory": "tests.test_worker_limits:make_scripted"}, 0, conn)
    finally:
        W.logging.getLogger("RansomwareScanner").setLevel(level)
    kinds = [m[0] for m in conn.sent]
    assert kinds == ["ready", "ok", "error", "error", "error"]
    assert conn.sent[1][1] == {"file_path": "a.pdf"}
    assert "MemoryError" in conn.sent[2][1] and "RecursionError" in conn.sent[3][1]
    assert conn.sent[4][1] == "KeyError: 'x'"
    assert W._SCANNER.cfg["isolate_scans"] is False and W._SCANNER.cfg["scan_workers"] == 1


def test_worker_loop_ends_when_the_parent_goes_away():
    conn = FakeConn(["a.pdf"])                           # then EOFError
    W._worker_main({"_scanner_factory": "tests.test_worker_limits:make_scripted"}, 0, conn)
    assert [m[0] for m in conn.sent] == ["ready", "ok"]


def test_main_module_is_hidden_and_restored():
    main = sys.modules["__main__"]
    had_file = "__file__" in main.__dict__
    before = (main.__dict__.get("__file__"), main.__dict__.get("__spec__"))
    with W._main_not_reimported():
        assert "__file__" not in main.__dict__ and main.__dict__.get("__spec__") is None
    assert (main.__dict__.get("__file__"), main.__dict__.get("__spec__")) == before
    assert ("__file__" in main.__dict__) == had_file


# ------------------------------------------------- pool plumbing, without processes
class BrokenPipe:
    def poll(self, t):
        raise OSError("closed")

    def recv(self):
        raise EOFError

    def send(self, x):
        raise BrokenPipeError


def _bare_scan(scanner=None):
    scan = object.__new__(W._IsolatedScan)
    scan.scanner, scan.pending, scan.done, scan.total = scanner, [], 0, 0
    scan.results = []
    scan.on_result = lambda i, p, r: scan.results.append((p, r))
    scan.cancel_event = None
    return scan


def test_receive_and_dispatch_survive_a_broken_pipe():
    scan = _bare_scan()
    assert scan._receive(SimpleNamespace(parent=BrokenPipe())) == ("dead", None)

    class PollsThenFails(BrokenPipe):
        def poll(self, t):
            return True
    assert scan._receive(SimpleNamespace(parent=PollsThenFails())) == ("dead", None)
    scan.pending = ["f.pdf"]
    w = SimpleNamespace(parent=BrokenPipe(), path=None, started=0.0)
    scan._dispatch(w)                                    # no exception
    assert w.path == "f.pdf" and scan.pending == []


def test_shutdown_kills_a_worker_that_does_not_stop():
    killed = []

    class Proc:
        def join(self, t):
            pass

        def is_alive(self):
            return True
    w = SimpleNamespace(parent=BrokenPipe(), proc=Proc(), kill=lambda: killed.append(1),
                        remove_temp=lambda: None)
    scan = _bare_scan()
    scan.pool = [w]
    scan._shutdown()
    assert killed == [1]


def test_in_process_fallback_records_a_crash(tmp_path):
    import RansomwareScanner as RS
    scanner = RS.RansomwareScanner(_config(tmp_path))
    p = tmp_path / "scan" / "a.pdf"
    p.write_bytes(make_pdf("a"))

    def boom(path, *a, **k):
        raise RuntimeError("parser bug")
    scanner.scan_file = boom
    scan = _bare_scan(scanner)
    scan.pending = [str(p)]
    scan._scan_in_process()
    path, result = scan.results[0]
    assert result["scan_results"]["scan_failed"]["reason"] == "RuntimeError: parser bug"
    assert result["sha256_hash"]


def test_failure_result_without_hashes(tmp_path):
    import RansomwareScanner as RS
    scanner = RS.RansomwareScanner(_config(tmp_path))
    scanner.calculate_hashes = lambda p: (_ for _ in ()).throw(OSError("gone"))
    r = W.failure_result(scanner, str(tmp_path / "missing.pdf"), "the worker process died")
    assert r["file_size"] == 0 and r["sha256_hash"] == "" and r["verdict"] == "Medium"


def test_kill_tolerates_a_dead_process(tmp_path):
    class Dead:
        def kill(self):
            raise ProcessLookupError

        def join(self, t):
            pass
    w = object.__new__(W._Worker)
    w.proc, w.parent = Dead(), BrokenPipe()
    w.parent.close = lambda: (_ for _ in ()).throw(OSError())
    w.temp_dir = str(tmp_path / "worker")
    (tmp_path / "worker" / "member").mkdir(parents=True)
    w.kill()                                             # no exception
    assert not (tmp_path / "worker").exists()            # and its temp folder is gone


def test_cancel_before_start_returns_quickly(tmp_path):
    import RansomwareScanner as RS
    cfg = _config(tmp_path, scan_workers=1)
    for i in range(3):
        (tmp_path / "scan" / f"d{i}.pdf").write_bytes(make_pdf(str(i)))
    stop = threading.Event()
    stop.set()
    assert RS.RansomwareScanner(cfg).scan_all_directories(cancel_event=stop) == []


@pytest.mark.skipif(sys.platform == "darwin", reason="libproc exists on macOS")
def test_macos_reader_elsewhere_is_none():
    assert W.macos_rss_reader() is None
