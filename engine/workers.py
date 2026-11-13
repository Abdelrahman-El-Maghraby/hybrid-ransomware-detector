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

Isolation fails closed (D-E). When workers cannot start (MAX_FAILED_STARTS
starts end before the worker is ready), no further file is handed out, the
files already in a worker finish, and every file not scanned gets one result
with scan_status "failed" and the code `isolation_unavailable`. Nothing is ever
parsed in the calling process instead. Those files were not opened, so they are
not scored as "file broke the scanner". Each result records where it was parsed
in `provenance.isolation`: "worker", "in_process" (only with the ISOLATE_SCANS=0
development opt-out, refused under the production profile) or "unavailable".

Workers also make folder scans parallel. The VirusTotal free quota is enforced
per process, so with a VirusTotal key and pacing on, one worker is used.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import json
import logging
import math
import multiprocessing as mp
import multiprocessing.connection
import os
import shutil
import sys
import tempfile
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from engine.completeness import PRECEDENCE
from engine.metrics import METRICS, VERDICTS

logger = logging.getLogger("RansomwareScanner")

ISOLATION_UNAVAILABLE = "isolation_unavailable"
ISOLATION_TEXT = ("isolated scan workers could not start; the file was not scanned "
                  "(nothing is parsed in the main process)")


class IsolationUnavailable(RuntimeError):
    """Isolated scan workers could not start, so the file was not scanned."""


def isolation_unavailable(result: Dict) -> bool:
    """True for the result of a file that was not scanned because no isolated
    worker could start."""
    failed = (result.get("scan_results") or {}).get("scan_failed") or {}
    return isinstance(failed, dict) and failed.get("code") == ISOLATION_UNAVAILABLE

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


LOG_RECORDS_PER_FILE = 200
LOG_TAIL_RECORDS = 50           # L-E8: the last records are kept too (the outer file's)


# M18: what a worker sends its parent. A message is JSON bytes, read with a size
# limit and checked before any field is used; the parent never unpickles worker
# data, so a worker taken over by a parser exploit cannot run code in the
# long-lived parent (the API process holds every client's uploads). The parent
# still pickles the paths it sends: the worker trusts its parent, not the reverse.
MAX_REPLY_BYTES = 16 * 1024 * 1024      # one message; a 500-member archive's result is ~50 KB
MAX_ERROR_CHARS = 2000
REPLY_KINDS = ("ready", "log", "ok", "error", "container", "member")
# H6 (b): while the outer file is still being scanned, the worker reports its
# container's own findings once the container is opened ("container") and each
# direct member whose scan finished ("member"), so a time-out or a dead worker
# does not lose them. Nothing else of the unfinished file is sent.
MEMBER_CONTAINERS = ("archive", "mail", "web", "embedded")
MAX_KEPT_MEMBERS = 10                   # highest-risk members kept per file
# Record keys that would replace a LogRecord method (getMessage, ...) when replayed.
_LOG_KEYS_REFUSED = frozenset(k for k in dir(logging.LogRecord)
                              if callable(getattr(logging.LogRecord, k)))
# Result fields the parent and its outputs read, with the types they must have.
_NUMBER = (int, float)
_RESULT_FIELDS: Dict[str, Tuple[Any, bool]] = {   # name: (types, required)
    "file_path": (str, True), "verdict": (str, True), "risk_score": (_NUMBER, True),
    "scan_status": (str, True), "scan_results": (dict, True),
    "file_name": (str, False), "file_size": (int, False), "scan_time": (str, False),
    "md5_hash": (str, False), "sha256_hash": (str, False), "is_malicious": (bool, False),
    "severity_score": (_NUMBER, False), "score_breakdown": (dict, False),
    "incomplete_reasons": (list, False), "provenance": (dict, False),
    "verdict_label": (str, False), "engine_version": (str, False),
}


class InvalidReply(ValueError):
    """A worker message that is too large, not JSON, or not of the expected shape."""


def send_reply(conn, kind: str, payload: Any) -> bool:
    """Worker side (M18): send one message as JSON bytes. Values JSON cannot hold
    are sent as text, as the JSON Lines output writes them. A result over the
    limit becomes an error; log records over it are dropped. False when nothing
    was sent."""
    data = json.dumps([kind, payload], default=str).encode("utf-8")
    if len(data) > MAX_REPLY_BYTES:
        if kind != "ok":
            return False
        data = json.dumps(["error", f"the scan result was too large to return "
                                    f"({len(data)} bytes, limit {MAX_REPLY_BYTES})"]).encode()
    conn.send_bytes(data)
    return True


def read_reply(conn) -> Tuple[str, Any]:
    """Parent side (M18): read one worker message: at most MAX_REPLY_BYTES, JSON,
    then checked by check_reply. Raises InvalidReply for a bad message, and the
    connection's own errors (EOFError, OSError) for a closed pipe."""
    try:
        data = conn.recv_bytes(MAX_REPLY_BYTES)
    except OSError as e:
        if "bad message length" in str(e):   # over the limit; nothing was read into memory
            raise InvalidReply(f"a message over {MAX_REPLY_BYTES} bytes") from None
        raise
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise InvalidReply(f"not JSON ({type(e).__name__})") from None
    return check_reply(msg)


def check_reply(msg: Any) -> Tuple[str, Any]:
    """The shape a worker message must have before the parent uses any field."""
    if not (isinstance(msg, list) and len(msg) == 2 and msg[0] in REPLY_KINDS):
        raise InvalidReply("not a [kind, payload] pair of a known kind")
    kind, payload = msg
    if kind == "ready":
        if payload is not None:
            raise InvalidReply("a ready message with a payload")
    elif kind == "error":
        if not isinstance(payload, str):
            raise InvalidReply("an error message that is not text")
        payload = payload[:MAX_ERROR_CHARS]
    elif kind == "log":
        if not (isinstance(payload, list) and len(payload) <= LOG_RECORDS_PER_FILE + 1):
            raise InvalidReply("log records that are not a list within the limit")
        for rec in payload:
            if not isinstance(rec, dict) or any(
                    k in _LOG_KEYS_REFUSED or k.startswith("__") for k in rec) or (
                    rec.get("args") is not None or rec.get("exc_info")):
                raise InvalidReply("a log record that is not a plain record")
    elif kind == "container":
        if not (isinstance(payload, dict) and set(payload) == {"container", "signal"}
                and payload["container"] in MEMBER_CONTAINERS
                and isinstance(payload["signal"], dict)
                and payload["signal"].get("worst") is None):
            raise InvalidReply("a container report that is not {container, signal}")
        try:
            _signal_class(payload["container"])(**payload["signal"])
        except (TypeError, ValueError):
            raise InvalidReply("a container signal with unknown fields") from None
    elif kind == "member":
        if not (isinstance(payload, dict) and set(payload) == {"container", "result"}
                and payload["container"] in MEMBER_CONTAINERS):
            raise InvalidReply("a member report that is not {container, result}")
        _check_result(payload["result"])
        _check_contributions(payload["result"])
    else:
        _check_result(payload)
    return kind, payload


def _check_contributions(result: Dict[str, Any]) -> None:
    """A member's contributions are scored again in the parent (H6 b)."""
    contribs = (result.get("score_breakdown") or {}).get("contributions", [])
    if not isinstance(contribs, list) or len(contribs) > 200:
        raise InvalidReply("member contributions that are not a list within the limit")
    for c in contribs:
        if not (isinstance(c, dict) and isinstance(c.get("indicator"), str)
                and isinstance(c.get("category", "technical"), str)
                and isinstance(c.get("detail", ""), str)
                and isinstance(c.get("points", 0), (int, float))
                and not isinstance(c.get("points", 0), bool)
                and math.isfinite(c.get("points", 0))):
            raise InvalidReply("a member contribution that is not plain")
    if not math.isfinite(result["risk_score"]):
        raise InvalidReply("a member risk score that is not finite")


def _signal_class(container: str):
    from detectors.signals import ArchiveSignal, EmbeddedSignal, MailSignal, WebSignal
    return {"archive": ArchiveSignal, "mail": MailSignal, "web": WebSignal,
            "embedded": EmbeddedSignal}[container]


def container_evidence(container: str, signal: Any) -> Optional[Dict[str, Any]]:
    """Worker side (H6 b): the container's own signal as its layer computed it from
    the opened container, before any member is scanned (no worst member yet)."""
    import dataclasses
    if container not in MEMBER_CONTAINERS or not isinstance(signal, _signal_class(container)):
        return None
    data = dataclasses.asdict(signal)
    data.pop("worst", None)
    return {"container": container, "signal": data}


def member_evidence(container: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Worker side (H6 b): the part of a finished member's result the parent keeps,
    as the worker scored it; nothing is added."""
    keep = ("file_path", "file_name", "verdict", "risk_score", "scan_status",
            "md5_hash", "sha256_hash")
    out = {k: result[k] for k in keep if k in result}
    out["scan_results"] = {}
    password = ((result.get("scan_results") or {}).get("archive") or {}).get("password_used")
    if password:
        out["scan_results"]["archive"] = {"password_used": password}
    out["score_breakdown"] = {"contributions": [
        {k: c.get(k) for k in ("indicator", "category", "points", "detail") if k in c}
        for c in (result.get("score_breakdown") or {}).get("contributions") or []]}
    return {"container": container, "result": out}


def _check_result(result: Any) -> None:
    if not isinstance(result, dict):
        raise InvalidReply("a result that is not an object")
    for name, (types, required) in _RESULT_FIELDS.items():
        if name not in result:
            if required:
                raise InvalidReply(f"a result without {name}")
            continue
        value = result[name]
        if not isinstance(value, types) or (types is not bool and isinstance(value, bool)):
            raise InvalidReply(f"a result whose {name} is a {type(value).__name__}")
    if result["verdict"] not in VERDICTS or result["scan_status"] not in PRECEDENCE:
        raise InvalidReply("a result with an unknown verdict or scan status")
    if not all(isinstance(r, dict) for r in result.get("incomplete_reasons") or []):
        raise InvalidReply("incomplete reasons that are not objects")


def _plain(value: Any, depth: int = 0) -> bool:
    if isinstance(value, (str, int, float, bool, type(None))):
        return True
    if depth < 4 and isinstance(value, (list, tuple)):
        return all(_plain(v, depth + 1) for v in value)
    if depth < 4 and isinstance(value, dict):
        return all(isinstance(k, str) and _plain(v, depth + 1) for k, v in value.items())
    return False


class _WorkerLogBuffer(logging.Handler):
    """Collects the records a worker logs while it scans one file. They are sent
    to the parent with the result and re-emitted there through its handlers
    (log file, GUI log, cloud event spool), so events such as scan_completed,
    external_share and layer_error are not lost in the worker process."""

    def __init__(self, limit: int = LOG_RECORDS_PER_FILE, tail: int = LOG_TAIL_RECORDS):
        super().__init__()
        self.limit, self.dropped = limit, 0
        self.tail_size = max(0, min(tail, limit - 1))
        self.records: List[Dict[str, Any]] = []
        # L-E8: the first records and the last ones; the outer file's own
        # scan_completed and external_share come after its members' records.
        self.tail: Deque[Dict[str, Any]] = deque()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            data = dict(record.__dict__)
            data["msg"], data["args"] = record.getMessage(), None
            if record.exc_info and not record.exc_text:
                data["exc_text"] = logging.Formatter().formatException(record.exc_info)
            data["exc_info"] = None
            plain = {k: v if _plain(v) else repr(v) for k, v in data.items()}
        except Exception:
            self.dropped += 1
            return
        if len(self.records) < self.limit - self.tail_size:
            self.records.append(plain)
            return
        self.tail.append(plain)
        if len(self.tail) > self.tail_size:
            self.tail.popleft()
            self.dropped += 1

    def take(self) -> List[Dict[str, Any]]:
        out, self.records = self.records, []
        tail, self.tail = list(self.tail), deque()
        if self.dropped:
            out.append(logging.makeLogRecord({
                "name": "RansomwareScanner", "levelno": logging.WARNING,
                "levelname": "WARNING", "args": None,
                "msg": f"{self.dropped} log record(s) from a scan worker were dropped "
                       f"(limit {self.limit} per file)."}).__dict__)
            self.dropped = 0
        return out + tail


def replay_worker_logs(records: Any) -> None:
    """Re-emit a worker's records in this process, under its logger levels."""
    if not isinstance(records, list):
        return
    for data in records:
        try:
            record = logging.makeLogRecord(data)
            target = logging.getLogger(record.name)
            if target.isEnabledFor(record.levelno):
                target.handle(record)
        except Exception:
            continue


def _worker_main(config: Dict, memory_mb: int, conn, temp_dir: str = "",
                 log_level: int = logging.WARNING) -> None:
    """Worker loop: build one scanner, then scan paths sent over the pipe. Every
    temporary file goes under `temp_dir`, which the parent removes when this
    worker is killed (a killed worker never runs its own clean-up). Records
    logged while a file is scanned go to the parent as a ("log", [...]) message
    before the result; building the scanner stays quiet (WARNING, stderr) as
    each worker would otherwise repeat the start-up lines."""
    global _SCANNER
    if temp_dir:
        tempfile.tempdir = temp_dir
        os.environ["TMPDIR"] = temp_dir          # helper programs (unar, 7z) too
    _limit_memory(memory_mb)
    logging.getLogger("RansomwareScanner").setLevel(logging.WARNING)
    cfg = dict(config, isolate_scans=False, scan_workers=1, _isolation="worker")
    factory = cfg.get("_scanner_factory")          # "module:callable"; used by the tests
    if factory:
        import importlib
        mod, _, attr = factory.partition(":")
        _SCANNER = getattr(importlib.import_module(mod), attr)(cfg)
    else:
        from engine.scanner import RansomwareScanner
        _SCANNER = RansomwareScanner(cfg)
    buffer = _WorkerLogBuffer()
    scan_logger = logging.getLogger("RansomwareScanner")
    propagate = scan_logger.propagate
    scan_logger.addHandler(buffer)
    scan_logger.propagate = False
    scan_logger.setLevel(log_level)
    def report_member(event: str, container: str, data: Any) -> None:
        try:
            if event == "container":
                report = container_evidence(container, data)
                if report is not None:
                    send_reply(conn, "container", report)
            else:
                send_reply(conn, "member", member_evidence(container, data))
        except Exception:
            pass                             # never stop a scan over a progress report
    _SCANNER.member_listener = report_member   # read by engine/containers.py
    try:
        send_reply(conn, "ready", None)
        _serve(_SCANNER, conn, buffer)
    finally:                                 # matters only when run in-process (tests)
        scan_logger.removeHandler(buffer)
        scan_logger.propagate = propagate


def _serve(scanner: Any, conn, buffer: _WorkerLogBuffer) -> None:
    while True:
        try:
            path = conn.recv()
        except EOFError:
            return
        if path is None:
            return
        # M26: the parent stops waiting scan_timeout_seconds after it sent the path
        # (every caller passes that setting); this clock starts just after it.
        limit = float((getattr(scanner, "config", None) or {}).get("scan_timeout_seconds") or 0)
        scanner.scan_deadline = time.monotonic() + limit if limit > 0 else None
        try:
            reply: Tuple[str, Any] = ("ok", scanner.scan_file(path))
        except MemoryError:
            reply = ("error", "MemoryError: the file needed more memory than the worker limit")
        except RecursionError:
            reply = ("error", "RecursionError: a parser recursed too deeply")
        except Exception as e:              # the engine should not raise; record it if it does
            reply = ("error", f"{type(e).__name__}: {e}")
        records = buffer.take()
        if records:
            try:
                send_reply(conn, "log", records)
            except Exception:
                pass                         # never lose the result over its log lines
        try:
            send_reply(conn, *reply)
        except (TypeError, ValueError) as e:     # not encodable (a circular value)
            send_reply(conn, "error", f"the scan result could not be returned: "
                                      f"{type(e).__name__}: {e}")


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
        level = logging.getLogger("RansomwareScanner").getEffectiveLevel()
        self.proc = ctx.Process(target=_worker_main,
                                args=(config, memory_mb, child, self.temp_dir, level),
                                daemon=True)
        with _START_LOCK, _main_not_reimported():
            self.proc.start()
        child.close()
        self.created = time.monotonic()
        self.path: Optional[str] = None
        self.started = 0.0
        self.watched = 0.0
        self.ready = False
        self.retired = False                 # killed and not replaced (workers cannot start)
        self.evidence = Evidence()           # H6 (b): members finished for self.path

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


def failure_result(scanner, path: str, reason: str, code: str = "",
                   isolation: str = "worker", evidence: Optional[Evidence] = None) -> Dict:
    """A result for a file whose scan timed out or crashed the worker, or (code
    ISOLATION_UNAVAILABLE, isolation "unavailable") that was never scanned because
    no isolated worker could start. That file was not opened, so it gets no
    `scan_failed` indicator: it is not evidence against the file."""
    import os as _os
    from datetime import datetime

    from engine.config import ENGINE_VERSION
    try:
        hashes = scanner.calculate_hashes(path)
    except Exception:
        hashes = {}
    unscanned = code == ISOLATION_UNAVAILABLE
    score = scanner.scoring.score({} if unscanned else {"scan_failed": reason})
    from api import SCHEMA_VERSION
    from engine.completeness import failed, verdict_label
    from engine.containers import member_summary
    kept = None if unscanned or evidence is None else evidence.score(scanner, path)
    why = reason
    if kept is not None and evidence is not None:   # H6 (b): findings made before the failure
        if kept.risk_score > score.risk_score:
            score = kept                      # the higher of the two (owner, 2026-11-12)
        why = (f"{reason}; the findings made before the failure are kept (partial "
               f"evidence: the container's own findings and {evidence.seen} member(s) "
               f"scanned)")
    status, reasons = failed(path, why, "isolation" if unscanned else "worker")
    failure: Dict[str, str] = {"reason": reason}
    if code:
        failure["code"] = code
    result = {
        "schema_version": SCHEMA_VERSION,
        "file_path": path, "file_name": _os.path.basename(path),
        "file_size": _os.path.getsize(path) if _os.path.exists(path) else 0,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "engine_version": ENGINE_VERSION,
        "md5_hash": hashes.get("md5", ""), "sha256_hash": hashes.get("sha256", ""),
        "scan_results": {"scan_failed": failure, **({"partial_evidence": {
            "members_scanned": evidence.seen,
            "containers": sorted(evidence.containers),
            "indicators": [c.indicator for c in kept.contributions][:20],
            "members": [dict(member_summary(r), container=c)
                        for c, r in evidence.findings()]}}
            if kept is not None and evidence is not None else {})},
        "is_malicious": score.is_malicious, "severity_score": score.severity_score,
        "risk_score": score.risk_score, "verdict": score.verdict,
        "score_breakdown": score.as_dict(),
        "scan_status": status, "incomplete_reasons": reasons,
        "provenance": {**(getattr(scanner, "provenance", None) or {}), "layers_run": [],
                       "layers_unavailable": [], "layers_not_applicable": [],
                       "layers_failed": ["isolation" if unscanned else "worker"],
                       "layers_skipped": [], "isolation": isolation},
    }
    result["verdict_label"] = verdict_label(result)
    return result


class Evidence:
    """H6 (b): what a worker reported for the file it is scanning before it
    finished: the container's own signal and its direct members that finished
    (how many, and the highest-risk ones, at most MAX_KEPT_MEMBERS)."""

    def __init__(self) -> None:
        self.seen = 0
        self.containers: Dict[str, Dict[str, Any]] = {}
        self.kept: List[Tuple[str, Dict[str, Any]]] = []

    def add_container(self, report: Dict[str, Any]) -> None:
        self.containers[report["container"]] = report["signal"]

    def add(self, report: Dict[str, Any]) -> None:
        self.seen += 1
        self.kept.append((report["container"], report["result"]))
        self.kept.sort(key=lambda e: -float(e[1]["risk_score"]))
        del self.kept[MAX_KEPT_MEMBERS:]

    def findings(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Members with findings, highest risk first."""
        return [e for e in self.kept if float(e[1]["risk_score"]) > 0]

    def score(self, scanner, path: str):
        """The score the container layer would give from this evidence alone: each
        container's own signal with its worst finished member (WorstMember), as
        engine/containers.py builds it. None when that finds nothing (or fails)."""
        from detectors.signals import Signals, WorstMember
        kinds = set(self.containers) | {c for c, _ in self.kept}
        if not kinds:
            return None
        signals: Dict[str, Any] = {}
        try:
            for kind in kinds:
                worst = next((r for c, r in self.findings() if c == kind), None)
                member = None if worst is None else WorstMember(
                    name=str(worst.get("file_name") or os.path.basename(path)),
                    contributions=list((worst.get("score_breakdown") or {})
                                       .get("contributions") or []))
                signals[kind] = _signal_class(kind)(**self.containers.get(kind, {}),
                                                    worst=member)
            result = scanner.scoring.score(Signals(**signals))
        except Exception as e:               # a forged signal must not break the failure path
            logger.warning("Partial evidence of %s could not be scored: %s", path, e)
            return None
        return result if result.risk_score > 0 else None


def start_worker(scanner, memory_mb: int) -> _Worker:
    """A worker started now and handed to scan_isolated(spare=...) later, so a scan
    does not wait for a process to start and build its scanner (about 1.4 s)."""
    return _Worker(mp.get_context("spawn"), dict(scanner.config), memory_mb)


def wait_ready(w: _Worker, timeout: float) -> bool:
    """Wait until a started worker reports ready (counted in METRICS either way).
    False, with the worker killed, when it ends or stays silent instead."""
    deadline = time.monotonic() + timeout
    why = f"not ready after {timeout:g}s"
    while True:
        remaining = deadline - time.monotonic()
        try:
            if w.parent.poll(max(0.0, min(remaining, 0.5))):
                kind, _ = read_reply(w.parent)
                if kind == "ready":
                    w.ready = True
                    METRICS.worker_start(True, time.monotonic() - w.created)
                    return True
                why = f"unexpected first message {kind!r}"
                break
        except InvalidReply as e:
            why = f"invalid first message: {e}"
            break
        except Exception:
            why = f"the worker process ended (exit code {w.proc.exitcode})"
            break
        if not w.proc.is_alive() and not w.parent.poll(0):
            why = f"the worker process ended (exit code {w.proc.exitcode})"
            break
        if remaining <= 0:
            break
    METRICS.worker_start(False, reason=why)
    w.kill()
    return False


def scan_isolated(scanner, targets: List[str], workers: int, timeout: float, memory_mb: int,
                  on_result: Callable[[int, str, Dict], None],
                  cancel_event=None, spare: Optional[_Worker] = None) -> int:
    """Scan `targets` in worker processes; call on_result(index, path, result) as files
    finish (index is the 1-based count of finished files). `spare` (start_worker)
    joins the pool instead of one newly started worker. Returns how many files were
    not scanned because workers could not start (each still got a result)."""
    scan = _IsolatedScan(scanner, targets, workers, timeout, memory_mb, on_result,
                         cancel_event, spare)
    scan.run()
    return scan.not_scanned


class _IsolatedScan:
    """One folder scan over a pool of worker processes (see the module docstring)."""

    MAX_FAILED_STARTS = 3
    START_SECONDS = 120.0                    # a worker silent this long after start has failed
    POLL_SECONDS = 0.05                      # longest wait for a message before limits are checked
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
        self.broken = False                    # workers cannot start: hand out nothing more
        self.not_scanned = 0
        self.rss = memory_watchdog(memory_mb)
        size = max(1, min(workers, len(targets)))
        self.pool: List[_Worker] = ([spare] if spare is not None else [])
        while len(self.pool) < size and not self.broken:
            w = self._start()
            if w is not None:
                self.pool.append(w)

    # ---------------------------------------------------------------- flow
    def run(self) -> None:
        try:
            while self._busy():
                self._wait()
                for i in range(len(self.pool)):
                    self._step(i)
        finally:
            self._shutdown()
        if self.pending and not self.cancelled():
            self._not_scanned()
        if self.cancelled():
            logger.info("Scan cancelled by user after %d/%d files.", self.done, self.total)

    def _wait(self) -> None:
        """Sleep until any worker has a message (a result, "ready", or the EOF of
        a dead worker), at most POLL_SECONDS, so time and memory limits are still
        checked on that tick (PR-17). Before 4.8 each worker was polled in turn
        for up to 50 ms, so dispatch slowed down as workers were added."""
        if self._dispatchable():
            return                             # an idle worker gets work at once
        pipes = [w.parent for w in self.pool if not w.retired]
        try:
            if pipes:
                multiprocessing.connection.wait(pipes, timeout=self.POLL_SECONDS)
                return
        except (OSError, ValueError):         # a pipe closed meanwhile: _step sees it
            pass
        time.sleep(self.POLL_SECONDS)

    def _dispatchable(self) -> bool:
        return (bool(self.pending) and not self.cancelled() and not self.broken
                and any(w.ready and w.path is None and not w.retired for w in self.pool))

    def _busy(self) -> bool:
        if any(w.path for w in self.pool):     # files in a worker always finish
            return True
        return bool(self.pending) and not self.cancelled() and not self.broken

    def cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()

    def _step(self, i: int) -> bool:
        """Feed and poll worker i once. False when it is retired."""
        w = self.pool[i]
        if w.retired:
            return False
        if (w.ready and w.path is None and self.pending and not self.cancelled()
                and not self.broken):
            self._dispatch(w)
        kind, payload = self._receive(w)
        if kind == "log":
            replay_worker_logs(payload)
            return True
        if kind == "ready":
            w.ready = True
            METRICS.worker_start(True, time.monotonic() - w.created)
            return True
        if kind in ("container", "member"):
            if w.path is not None:
                (w.evidence.add_container if kind == "container" else w.evidence.add)(payload)
            return True
        if kind in ("ok", "error"):
            path, w.path = w.path, None
            if path is not None:
                if kind == "ok" and isinstance(payload, dict):
                    self._finish(path, payload)
                else:
                    self._fail(path, payload or "scan error", w.evidence)
            return True
        invalid = kind == "invalid"
        dead = (invalid or kind == "dead" or not w.proc.is_alive()
                or (not w.ready and time.monotonic() - w.created > self.START_SECONDS))
        overdue = w.path is not None and time.monotonic() - w.started > self.timeout
        over_memory = not (dead or overdue) and self._over_memory(w)
        if not (dead or overdue or over_memory):
            return True
        if w.path is not None:
            path, w.path = w.path, None
            if invalid:
                reason = (f"the worker sent an invalid reply ({payload}) and was stopped; "
                          f"nothing in it was used")
            elif over_memory:
                reason = (f"MemoryError: the worker used {over_memory // (1024 * 1024)} MB, "
                          f"over the {self.memory_mb} MB limit, and was stopped")
            elif overdue and not dead:
                reason = f"timed out after {int(self.timeout)}s"
            else:
                reason = f"the worker process died (exit code {w.proc.exitcode})"
            self._fail(path, reason, w.evidence)
        return self._replace(i)

    def _over_memory(self, w: _Worker) -> int:
        """Resident bytes when a busy worker is over the limit, else 0 (watchdog)."""
        if self.rss is None or self.memory_mb <= 0 or w.path is None or w.proc.pid is None:
            return 0                             # 0 MB = no limit
        now = time.monotonic()
        if now - w.watched < self.WATCH_SECONDS:
            return 0
        w.watched = now
        used = self.rss(w.proc.pid) or 0
        return used if used > self.memory_mb * 1024 * 1024 else 0

    # ---------------------------------------------------------------- helpers
    def _dispatch(self, w: _Worker) -> None:
        w.path, w.started = self.pending.pop(0), time.monotonic()
        w.evidence = Evidence()
        try:
            w.parent.send(w.path)
        except Exception:
            pass                              # noticed as a dead worker on the next poll

    def _receive(self, w: _Worker):
        try:
            has = w.parent.poll(0)              # _wait() already slept until a message
        except Exception:
            has = True                        # closed pipe: treat as a dead worker
        if not has:
            return "", None
        try:
            return read_reply(w.parent)
        except InvalidReply as e:
            return "invalid", str(e)
        except Exception:
            return "dead", None

    def _finish(self, path: str, result: Dict) -> None:
        self.done += 1
        self.on_result(self.done, path, result)

    def _fail(self, path: str, reason: str, evidence: Optional[Evidence] = None) -> None:
        logger.warning("Scan of %s failed: %s", path, reason)
        self._finish(path, failure_result(self.scanner, path, reason, evidence=evidence))

    def _start(self) -> Optional[_Worker]:
        try:
            return _Worker(self.ctx, self.config, self.memory_mb)
        except Exception as e:                # the process could not even be created
            self._start_failed(f"{type(e).__name__}: {e}")
            return None

    def _start_failed(self, why: str) -> None:
        self.failed_starts += 1
        METRICS.worker_start(False, reason=why)
        logger.warning("A scan worker did not start: %s", why)
        if self.failed_starts >= self.MAX_FAILED_STARTS:
            self.broken = True

    def _replace(self, i: int) -> bool:
        """Kill worker i and start another. False (worker retired) once workers
        evidently cannot start."""
        w = self.pool[i]
        if not w.ready:
            self._start_failed(f"the worker process ended before it was ready "
                               f"(exit code {w.proc.exitcode})")
        w.kill()
        w.retired = True
        while not self.broken:
            new = self._start()
            if new is not None:
                self.pool[i] = new
                return True
        return False

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

    def _not_scanned(self) -> None:
        """Fail closed: one isolation_unavailable result for every file left (e.g.
        an embedded interpreter without an importable __main__, a process limit, a
        broken image). Nothing is parsed in this process."""
        paths, self.pending = self.pending, []
        logger.error("Isolated scan workers could not start (%d failed start(s)): %d "
                     "file(s) were not scanned. Nothing is scanned in the main process.",
                     self.failed_starts, len(paths),
                     extra={"event": ISOLATION_UNAVAILABLE, "files": len(paths)})
        for path in paths:
            self.not_scanned += 1
            self._finish(path, failure_result(self.scanner, path, ISOLATION_TEXT,
                                              ISOLATION_UNAVAILABLE, "unavailable"))


def default_workers(config: Dict) -> int:
    configured = int(config.get("scan_workers", 0) or 0)
    if config.get("virustotal_api_key") and float(config.get("virustotal_requests_per_minute", 4) or 0) > 0:
        return 1                            # the free VirusTotal quota is per process
    if configured > 0:
        return configured
    return max(1, min(4, (os.cpu_count() or 2)))
