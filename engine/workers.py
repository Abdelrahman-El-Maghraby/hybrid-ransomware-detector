"""
Isolated, parallel scanning of many files.

Every file a folder scan opens is untrusted, and parsing is done by libraries
(olefile, pypdf, py7zr, rarfile, oletools, ...) that were not written to resist
hostile input. In one process, a single crafted file that makes a parser hang,
recurse until the stack overflows, or allocate gigabytes stops the whole scan.

Here each file is scanned in a worker process that
  * has a wall-clock limit per file (the worker is killed and replaced when it
    is exceeded),
  * has a memory limit (WORKER_MEMORY_MB), so runaway allocation ends in a
    MemoryError or a dead worker instead of a frozen machine:
      - Linux: an address-space limit (RLIMIT_AS) set inside the worker;
      - Windows: the worker puts itself in a Job Object with a per-process
        committed-memory limit (JOB_OBJECT_LIMIT_PROCESS_MEMORY); the job is
        also set to kill the worker if the scanner itself exits;
      - macOS (which does not enforce RLIMIT_AS): the parent reads each busy
        worker's resident memory with proc_pidinfo() four times a second and
        kills a worker that goes over the limit,
  * is replaced if it dies for any reason.
A file that times out or kills its worker is reported with the `scan_failed`
indicator (Medium): ordinary documents do not do that.

Workers also make folder scans parallel. The VirusTotal free quota is enforced
per process, so with a VirusTotal key and pacing on, one worker is used.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import logging
import multiprocessing as mp
import os
import shutil
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("RansomwareScanner")

_SCANNER = None
_START_LOCK = threading.Lock()


def _limit_memory(megabytes: int, platform: str = sys.platform) -> str:
    """Apply the worker's memory limit; returns how ("rlimit", "job", "watchdog",
    or "" when there is no limit or the OS refused)."""
    if megabytes <= 0:
        return ""
    if platform == "win32":
        return "job" if _windows_job_limit(megabytes) else ""
    if platform == "darwin":
        return "watchdog"                    # RLIMIT_AS is accepted but not enforced
    try:
        import resource
        limit = megabytes * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        return "rlimit"
    except (ImportError, ValueError, OSError):
        return ""


# ------------------------------------------------------------- Windows: Job Object
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32)]


class JobLimits(ctypes.Structure):
    """JOBOBJECT_EXTENDED_LIMIT_INFORMATION."""
    _fields_ = [("BasicLimitInformation", _BasicLimits),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


_JOB_HANDLE: Any = None                     # kept open for the worker's lifetime


def _kernel32() -> Any:
    win_dll = getattr(ctypes, "WinDLL", None)      # Windows only
    if win_dll is None:
        raise OSError("not Windows")
    k32 = win_dll("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = ctypes.c_void_p
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    k32.SetInformationJobObject.restype = ctypes.c_int
    k32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                            ctypes.c_uint32]
    k32.AssignProcessToJobObject.restype = ctypes.c_int
    k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    return k32


def _windows_job_limit(megabytes: int, kernel32: Any = None) -> bool:
    """Put the current process in a Job Object that caps its committed memory.
    An allocation beyond the cap fails (Python raises MemoryError); a native
    crash ends the worker, which the parent reports as scan_failed either way."""
    global _JOB_HANDLE
    try:
        k32 = kernel32 or _kernel32()
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return False
        info = JobLimits()
        info.BasicLimitInformation.LimitFlags = (JOB_OBJECT_LIMIT_PROCESS_MEMORY
                                                 | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                                                 | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        info.ProcessMemoryLimit = megabytes * 1024 * 1024
        if not k32.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                                           ctypes.byref(info), ctypes.sizeof(info)):
            return False
        if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
            return False
        _JOB_HANDLE = job
        return True
    except (AttributeError, OSError):
        return False


# ---------------------------------------------------- macOS: resident-memory watchdog
PROC_PIDTASKINFO = 4


class _TaskInfo(ctypes.Structure):
    """struct proc_taskinfo from <sys/proc_info.h>."""
    _fields_ = ([(n, ctypes.c_uint64) for n in (
        "pti_virtual_size", "pti_resident_size", "pti_total_user", "pti_total_system",
        "pti_threads_user", "pti_threads_system")]
        + [(n, ctypes.c_int32) for n in (
            "pti_policy", "pti_faults", "pti_pageins", "pti_cow_faults", "pti_messages_sent",
            "pti_messages_received", "pti_syscalls_mach", "pti_syscalls_unix", "pti_csw",
            "pti_threadnum", "pti_numrunning", "pti_priority")])


RUSAGE_INFO_V0 = 0


class _RusageInfoV0(ctypes.Structure):
    """struct rusage_info_v0 from <sys/resource.h>."""
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [(n, ctypes.c_uint64) for n in (
        "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups",
        "ri_pageins", "ri_wired_size", "ri_resident_size", "ri_phys_footprint",
        "ri_proc_start_abstime", "ri_proc_exit_abstime")]


RssReader = Callable[[int], Optional[int]]


def macos_rss_reader(libproc: Any = None) -> Optional[RssReader]:
    """A function pid -> bytes of memory in use, or None when libproc is unavailable.

    The physical footprint (proc_pid_rusage; Activity Monitor's "Memory") counts
    memory the system compressed. Resident size does not: a worker filling memory
    with repetitive data stayed far under the limit while using gigabytes. The
    larger of the two is used; resident size alone where proc_pid_rusage is missing."""
    try:
        lib = libproc or ctypes.CDLL(ctypes.util.find_library("proc") or "libproc.dylib")
        fn = lib.proc_pidinfo
    except (OSError, AttributeError):
        return None
    fn.restype = ctypes.c_int
    fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    rusage = getattr(lib, "proc_pid_rusage", None)
    if rusage is not None:
        rusage.restype = ctypes.c_int
        rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]

    def read(pid: int) -> Optional[int]:
        info = _TaskInfo()
        size = ctypes.sizeof(info)
        if fn(pid, PROC_PIDTASKINFO, 0, ctypes.byref(info), size) != size:
            return None
        used = int(info.pti_resident_size)
        if rusage is not None:
            ri = _RusageInfoV0()
            if rusage(pid, RUSAGE_INFO_V0, ctypes.byref(ri)) == 0:
                used = max(used, int(ri.ri_phys_footprint))
        return used
    return read


def memory_watchdog(memory_mb: int, platform: str = sys.platform) -> Optional[RssReader]:
    """The reader the parent polls busy workers with: macOS only, because Linux
    and Windows enforce the limit inside the worker."""
    if memory_mb <= 0 or platform != "darwin":
        return None
    return macos_rss_reader()


def linux_rss_reader(pid: int) -> Optional[int]:
    """Resident bytes from /proc (used by the tests to exercise the watchdog)."""
    try:
        with open(f"/proc/{pid}/statm") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


def _worker_main(config: Dict, memory_mb: int, conn, temp_dir: str = "") -> None:
    """Worker loop: build one scanner, then scan paths sent over the pipe. Every
    temporary file goes under `temp_dir`, which the parent removes when this
    worker is killed (a killed worker never runs its own clean-up)."""
    global _SCANNER
    if temp_dir:
        tempfile.tempdir = temp_dir
        os.environ["TMPDIR"] = temp_dir          # helper programs (unar, 7z) too
    _limit_memory(memory_mb)
    logging.getLogger("RansomwareScanner").setLevel(logging.WARNING)
    cfg = dict(config, isolate_scans=False, scan_workers=1)
    factory = cfg.get("_scanner_factory")          # "module:callable"; used by the tests
    if factory:
        import importlib
        mod, _, attr = factory.partition(":")
        _SCANNER = getattr(importlib.import_module(mod), attr)(cfg)
    else:
        from engine.scanner import RansomwareScanner
        _SCANNER = RansomwareScanner(cfg)
    conn.send(("ready", None))
    while True:
        try:
            path = conn.recv()
        except EOFError:
            return
        if path is None:
            return
        try:
            conn.send(("ok", _SCANNER.scan_file(path)))
        except MemoryError:
            conn.send(("error", "MemoryError: the file needed more memory than the worker limit"))
        except RecursionError:
            conn.send(("error", "RecursionError: a parser recursed too deeply"))
        except Exception as e:              # the engine should not raise; record it if it does
            conn.send(("error", f"{type(e).__name__}: {e}"))


@contextlib.contextmanager
def _main_not_reimported():
    """Stop spawned workers from re-running the caller's main script.

    'spawn' normally re-imports __main__ in every child so that objects defined there
    can be unpickled. Workers need nothing from it (their target lives in this
    module), and re-running it is harmful: a script without an
    `if __name__ == "__main__":` guard would open its GUI or start its own scan in
    each worker. Hiding the main module's path for the moment of start() avoids it."""
    main = sys.modules.get("__main__")
    saved = {}
    if main is not None and not getattr(sys, "frozen", False):
        if "__file__" in main.__dict__:
            saved["__file__"] = main.__dict__.pop("__file__")
        if "__spec__" in main.__dict__:
            saved["__spec__"] = main.__dict__["__spec__"]
            main.__dict__["__spec__"] = None
    try:
        yield
    finally:
        if main is not None:
            main.__dict__.update(saved)


WORKER_TEMP_PREFIX = "aegis_worker_"
_SWEPT = False


def _pid_alive(pid: int) -> bool:
    """True when a process with this id exists (or might: when in doubt, alive)."""
    if os.name == "nt":                      # os.kill would terminate it on Windows
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.OpenProcess(0x1000, False, pid)    # QUERY_LIMITED_INFORMATION
            if not handle:
                return False
            code = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            kernel32.CloseHandle(handle)
            return code.value == 259                             # STILL_ACTIVE
        except (AttributeError, OSError):
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:                          # exists, owned by someone else
        return True
    return True


def sweep_stale_worker_dirs(folder: Optional[str] = None) -> int:
    """Remove worker temp folders whose scanner process no longer exists. A crash or
    kill of the scanner itself (not just a worker) leaves them behind, and nothing
    else would delete them outside a container's tmpfs. Returns how many went."""
    removed = 0
    root = folder or tempfile.gettempdir()
    try:
        names = os.listdir(root)
    except OSError:
        return 0
    for name in names:
        if not name.startswith(WORKER_TEMP_PREFIX):
            continue
        owner = name[len(WORKER_TEMP_PREFIX):].split("_", 1)[0]
        if not owner.isdigit() or int(owner) == os.getpid() or _pid_alive(int(owner)):
            continue
        shutil.rmtree(os.path.join(root, name), ignore_errors=True)
        removed += 1
    if removed:
        logger.info("Removed %d temporary folder(s) left by a scanner that stopped "
                    "abnormally.", removed)
    return removed


class _Worker:
    def __init__(self, ctx, config: Dict, memory_mb: int):
        global _SWEPT
        if not _SWEPT:                       # once per scanner process
            _SWEPT = True
            sweep_stale_worker_dirs()
        self.parent, child = ctx.Pipe()
        self.temp_dir = tempfile.mkdtemp(prefix=f"{WORKER_TEMP_PREFIX}{os.getpid()}_")
        self.proc = ctx.Process(target=_worker_main, args=(config, memory_mb, child, self.temp_dir),
                                daemon=True)
        with _START_LOCK, _main_not_reimported():
            self.proc.start()
        child.close()
        self.path: Optional[str] = None
        self.started = 0.0
        self.watched = 0.0
        self.ready = False

    def kill(self) -> None:
        try:
            self.proc.kill()
            self.proc.join(5)
        except Exception:
            pass
        try:
            self.parent.close()
        except Exception:
            pass
        self.remove_temp()

    def remove_temp(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)


def failure_result(scanner, path: str, reason: str) -> Dict:
    """A result for a file whose scan timed out or crashed the worker."""
    import os as _os
    from datetime import datetime

    from engine.config import ENGINE_VERSION
    try:
        hashes = scanner.calculate_hashes(path)
    except Exception:
        hashes = {}
    score = scanner.scoring.score({"scan_failed": reason})
    from api import SCHEMA_VERSION
    from engine.completeness import failed, verdict_label
    status, reasons = failed(path, reason)
    result = {
        "schema_version": SCHEMA_VERSION,
        "file_path": path, "file_name": _os.path.basename(path),
        "file_size": _os.path.getsize(path) if _os.path.exists(path) else 0,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "engine_version": ENGINE_VERSION,
        "md5_hash": hashes.get("md5", ""), "sha256_hash": hashes.get("sha256", ""),
        "scan_results": {"scan_failed": {"reason": reason}},
        "is_malicious": score.is_malicious, "severity_score": score.severity_score,
        "risk_score": score.risk_score, "verdict": score.verdict,
        "score_breakdown": score.as_dict(),
        "scan_status": status, "incomplete_reasons": reasons,
        "provenance": {**(getattr(scanner, "provenance", None) or {}), "layers_run": [],
                       "layers_unavailable": [], "layers_not_applicable": [],
                       "layers_failed": ["worker"],
                       "layers_skipped": []},
    }
    result["verdict_label"] = verdict_label(result)
    return result


def start_worker(scanner, memory_mb: int) -> _Worker:
    """A worker started now and handed to scan_isolated(spare=...) later, so a scan
    does not wait for a process to start and build its scanner (about 1.4 s)."""
    return _Worker(mp.get_context("spawn"), dict(scanner.config), memory_mb)


def scan_isolated(scanner, targets: List[str], workers: int, timeout: float, memory_mb: int,
                  on_result: Callable[[int, str, Dict], None],
                  cancel_event=None, spare: Optional[_Worker] = None) -> None:
    """Scan `targets` in worker processes; call on_result(index, path, result) as files
    finish (index is the 1-based count of finished files). `spare` (start_worker)
    joins the pool instead of one newly started worker."""
    _IsolatedScan(scanner, targets, workers, timeout, memory_mb, on_result,
                  cancel_event, spare).run()


class _IsolatedScan:
    """One folder scan over a pool of worker processes (see the module docstring)."""

    MAX_FAILED_STARTS = 3
    POLL_SECONDS = 0.05
    WATCH_SECONDS = 0.25                     # memory watchdog interval (macOS)

    def __init__(self, scanner, targets: List[str], workers: int, timeout: float,
                 memory_mb: int, on_result: Callable[[int, str, Dict], None], cancel_event,
                 spare: Optional[_Worker] = None):
        self.scanner = scanner
        self.total = len(targets)
        self.pending = list(targets)
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.on_result = on_result
        self.cancel_event = cancel_event
        self.ctx = mp.get_context("spawn")     # same behaviour on Linux, macOS and Windows
        self.config = dict(scanner.config)
        self.done = 0
        self.failed_starts = 0
        self.rss = memory_watchdog(memory_mb)
        size = max(1, min(workers, len(targets)))
        self.pool: List[_Worker] = ([spare] if spare is not None else [])
        self.pool += [_Worker(self.ctx, self.config, memory_mb)
                      for _ in range(size - len(self.pool))]

    # ---------------------------------------------------------------- flow
    def run(self) -> None:
        broken = False
        try:
            while (self.pending and not self.cancelled()) or any(w.path for w in self.pool):
                if not all(self._step(i) for i in range(len(self.pool))):
                    broken = True
                    break
        finally:
            self._shutdown()
        if broken and self.pending:
            self._scan_in_process()
        if self.cancelled():
            logger.info("Scan cancelled by user after %d/%d files.", self.done, self.total)

    def cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()

    def _step(self, i: int) -> bool:
        """Feed and poll worker i once. False when workers evidently cannot start."""
        w = self.pool[i]
        if w.ready and w.path is None and self.pending and not self.cancelled():
            self._dispatch(w)
        kind, payload = self._receive(w)
        if kind == "ready":
            w.ready = True
            return True
        if kind in ("ok", "error"):
            path, w.path = w.path, None
            if path is not None:
                if kind == "ok" and isinstance(payload, dict):
                    self._finish(path, payload)
                else:
                    self._fail(path, payload or "scan error")
            return True
        dead = kind == "dead" or not w.proc.is_alive()
        overdue = w.path is not None and time.monotonic() - w.started > self.timeout
        over_memory = not (dead or overdue) and self._over_memory(w)
        if not (dead or overdue or over_memory):
            return True
        if w.path is not None:
            path, w.path = w.path, None
            if over_memory:
                reason = (f"MemoryError: the worker used {over_memory // (1024 * 1024)} MB, "
                          f"over the {self.memory_mb} MB limit, and was stopped")
            elif overdue and not dead:
                reason = f"timed out after {int(self.timeout)}s"
            else:
                reason = f"the worker process died (exit code {w.proc.exitcode})"
            self._fail(path, reason)
        return self._replace(i)

    def _over_memory(self, w: _Worker) -> int:
        """Resident bytes when a busy worker is over the limit, else 0 (watchdog)."""
        if self.rss is None or w.path is None or w.proc.pid is None:
            return 0
        now = time.monotonic()
        if now - w.watched < self.WATCH_SECONDS:
            return 0
        w.watched = now
        used = self.rss(w.proc.pid) or 0
        return used if used > self.memory_mb * 1024 * 1024 else 0

    # ---------------------------------------------------------------- helpers
    def _dispatch(self, w: _Worker) -> None:
        w.path, w.started = self.pending.pop(0), time.monotonic()
        try:
            w.parent.send(w.path)
        except Exception:
            pass                              # noticed as a dead worker on the next poll

    def _receive(self, w: _Worker):
        try:
            has = w.parent.poll(self.POLL_SECONDS)
        except Exception:
            has = True                        # closed pipe: treat as a dead worker
        if not has:
            return "", None
        try:
            return w.parent.recv()
        except Exception:
            return "dead", None

    def _finish(self, path: str, result: Dict) -> None:
        self.done += 1
        self.on_result(self.done, path, result)

    def _fail(self, path: str, reason: str) -> None:
        logger.warning("Scan of %s failed: %s", path, reason)
        self._finish(path, failure_result(self.scanner, path, reason))

    def _replace(self, i: int) -> bool:
        w = self.pool[i]
        if not w.ready:
            self.failed_starts += 1
        w.kill()
        if self.failed_starts >= self.MAX_FAILED_STARTS:
            return False
        self.pool[i] = _Worker(self.ctx, self.config, self.memory_mb)
        return True

    def _shutdown(self) -> None:
        for w in self.pool:
            try:
                w.parent.send(None)
            except Exception:
                pass
            w.proc.join(2)
            if w.proc.is_alive():
                w.kill()
            w.remove_temp()

    def _scan_in_process(self) -> None:
        # Worker processes cannot start here (e.g. an embedded interpreter without an
        # importable __main__): finish without isolation instead of looping.
        logger.warning("Worker processes cannot start; scanning the remaining %d file(s) "
                       "in this process without isolation.", len(self.pending))
        while self.pending and not self.cancelled():
            path = self.pending.pop(0)
            try:
                self._finish(path, self.scanner.scan_file(path))
            except Exception as e:
                self._fail(path, f"{type(e).__name__}: {e}")


def default_workers(config: Dict) -> int:
    configured = int(config.get("scan_workers", 0) or 0)
    if config.get("virustotal_api_key") and float(config.get("virustotal_requests_per_minute", 4) or 0) > 0:
        return 1                            # the free VirusTotal quota is per process
    if configured > 0:
        return configured
    return max(1, min(4, (os.cpu_count() or 2)))
