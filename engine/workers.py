"""
Isolated, parallel scanning of many files.

Every file a folder scan opens is untrusted, and parsing is done by libraries
(olefile, pypdf, py7zr, rarfile, oletools, ...) that were not written to resist
hostile input. In one process, a single crafted file that makes a parser hang,
recurse until the stack overflows, or allocate gigabytes stops the whole scan.

Here each file is scanned in a worker process that
  * has a wall-clock limit per file (the worker is killed and replaced when it
    is exceeded),
  * has an address-space limit on Linux (RLIMIT_AS), so runaway allocation ends
    in a MemoryError or a dead worker instead of a frozen machine,
  * is replaced if it dies for any reason.
A file that times out or kills its worker is reported with the `scan_failed`
indicator (Medium): ordinary documents do not do that.

Workers also make folder scans parallel. The VirusTotal free quota is enforced
per process, so with a VirusTotal key and pacing on, one worker is used.
"""

from __future__ import annotations

import contextlib
import logging
import multiprocessing as mp
import os
import sys
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("RansomwareScanner")

_SCANNER = None
_START_LOCK = threading.Lock()


def _limit_memory(megabytes: int) -> None:
    if megabytes <= 0:
        return
    try:
        import resource
        limit = megabytes * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except Exception:                       # not available (Windows) or not enforced (macOS)
        pass


def _worker_main(config: Dict, memory_mb: int, conn) -> None:
    """Worker loop: build one scanner, then scan paths sent over the pipe."""
    global _SCANNER
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


class _Worker:
    def __init__(self, ctx, config: Dict, memory_mb: int):
        self.parent, child = ctx.Pipe()
        self.proc = ctx.Process(target=_worker_main, args=(config, memory_mb, child), daemon=True)
        with _START_LOCK, _main_not_reimported():
            self.proc.start()
        child.close()
        self.path: Optional[str] = None
        self.started = 0.0
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
    return {
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
    }


def scan_isolated(scanner, targets: List[str], workers: int, timeout: float, memory_mb: int,
                  on_result: Callable[[int, str, Dict], None],
                  cancel_event=None) -> None:
    """Scan `targets` in worker processes; call on_result(index, path, result) as files
    finish (index is the 1-based count of finished files)."""
    _IsolatedScan(scanner, targets, workers, timeout, memory_mb, on_result,
                  cancel_event).run()


class _IsolatedScan:
    """One folder scan over a pool of worker processes (see the module docstring)."""

    MAX_FAILED_STARTS = 3
    POLL_SECONDS = 0.05

    def __init__(self, scanner, targets: List[str], workers: int, timeout: float,
                 memory_mb: int, on_result: Callable[[int, str, Dict], None], cancel_event):
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
        self.pool: List[_Worker] = [_Worker(self.ctx, self.config, memory_mb)
                                    for _ in range(max(1, min(workers, len(targets))))]

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
        if not (dead or overdue):
            return True
        if w.path is not None:
            path, w.path = w.path, None
            self._fail(path, f"timed out after {int(self.timeout)}s" if overdue and not dead
                       else f"the worker process died (exit code {w.proc.exitcode})")
        return self._replace(i)

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
