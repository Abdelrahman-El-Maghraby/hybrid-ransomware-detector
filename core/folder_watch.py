"""
Folder monitoring (F1): scan files as they arrive in watched folders.

Desktop only (owner decision D-B): the desktop app and its background service on
Windows, macOS and Linux. The Docker edition and the REST API have no watcher.

    WATCH_DIRS=~/Downloads;~/Desktop      (";" on Windows, ";" or ":" elsewhere)

How a file gets scanned (threat model TMA-5: files an attacker can drop are
parsed with no user action):

  * Events (created, modified, moved, closed-after-write) only RECORD a path;
    nothing is opened from the event thread. Repeated events for one path
    collapse into one entry, so an event flood costs memory per file, not per
    event, and the queue is bounded (WATCH_MAX_QUEUE): beyond it new paths are
    dropped, logged and counted.
  * A file is scanned once, after its size and modification time have not
    changed for WATCH_SETTLE_SECONDS. Duplicates are skipped by path, size,
    modification time and SHA-256 (a touch that changes nothing is not
    rescanned).
  * Only regular files with a configured extension, whose real path is inside a
    watched folder: links are never followed out of a watched root.
  * The app's own output is never scanned - app data (logs included),
    reports, quarantine, keys, the alert outbox, the cloud spool, the JSON
    Lines file, the cache database and the scan workers' temporary folders -
    and neither are canary files, so the monitor cannot loop on its own output.
  * Scans run only in isolated workers (engine/workers.py), on the monitor's
    own thread, so events are still recorded while a file is being parsed. If
    workers cannot start, monitoring PAUSES with a visible error (status(),
    the log) and retries after WATCH_RETRY_MINUTES; it never parses a file in
    this process (D-E).
  * Results go through the normal path: the report, the outputs and alerts
    (core/outputs.deliver), and automatic quarantine under the existing
    AUTO_QUARANTINE setting (F3). Quarantine refuses a file whose SHA-256 no
    longer matches the scanned one, so a file swapped in after the scan (a
    rename race) is never vaulted in its place.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

logger = logging.getLogger("RansomwareScanner.monitor")

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore[assignment,misc]
    WATCHDOG_AVAILABLE = False

_EVENTS = frozenset({"created", "modified", "moved", "closed"})
TEMP_PREFIXES = ("aegis_worker_", "aegis_api_", "aegis_warmup_", "aegis_intel_", "hrd_")
SEEN_LIMIT = 10_000


def split_dirs(raw: Any) -> List[str]:
    """WATCH_DIRS: a list, or one string separated by ';' (and ':' outside Windows)."""
    import re
    if isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    else:
        items = re.split(r";" if os.name == "nt" else r"[;:]", str(raw or ""))
    return [os.path.expanduser(x.strip()) for x in items if x.strip()]


def _real(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:                   # different drives on Windows
        return False


def own_folders(config: Mapping[str, Any]) -> List[str]:
    """Folders the scanner itself writes: never scanned by the monitor."""
    from engine.config import APP_DIR
    folders = [str(APP_DIR)]
    for key in ("report_directory", "quarantine_dir", "keystore_dir", "outbox_dir",
                "cloud_spool_dir", "data_dir"):
        if config.get(key):
            folders.append(str(config[key]))
    return [_real(f) for f in folders]


def own_files(config: Mapping[str, Any]) -> List[str]:
    """Single files the scanner writes outside its folders: JSON Lines, the cache."""
    files = []
    if config.get("jsonl_path"):
        files.append(str(config["jsonl_path"]))
    cache = str(config.get("cache_db_path") or "")
    if cache:
        files += [cache + suffix for suffix in ("", "-wal", "-shm", "-journal")]
    return [_real(f) for f in files]


@dataclass
class _Pending:
    size: int
    mtime_ns: int
    changed: float                       # last time size/mtime changed (monotonic)


class _Handler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(self, monitor: FolderMonitor):
        super().__init__()
        self.monitor = monitor

    def on_any_event(self, event):
        if event.event_type not in _EVENTS or event.is_directory:
            return
        if event.event_type == "closed" and "nowrite" in type(event).__name__.lower():
            return                       # a reader closing a file changes nothing
        path = getattr(event, "dest_path", "") or event.src_path
        self.monitor.note(path)


class FolderMonitor:
    """Watches folders and scans what settles. `scan_batch(paths)` returns the
    results of an isolated scan (default: the scanner's own path, with the
    report, outputs and automatic quarantine)."""

    def __init__(self, scanner: Any, roots: Iterable[str], settle: float = 2.0,
                 max_queue: int = 1000, retry_minutes: float = 5.0,
                 on_results: Optional[Callable[[List[Dict]], None]] = None,
                 clock: Callable[[], float] = time.monotonic):
        self.scanner = scanner
        self.config = scanner.config
        self.roots = [_real(r) for r in roots if os.path.isdir(r)]
        self.missing = [r for r in roots if not os.path.isdir(r)]
        self.settle = float(settle)
        self.max_queue = int(max_queue)
        self.retry_seconds = float(retry_minutes) * 60
        self.on_results = on_results
        self._clock = clock
        self.exclude = own_folders(self.config)
        self.exts = tuple(e.lower() for e in (self.config.get("file_extensions") or ()))
        self.exclude_files = set(own_files(self.config))
        self._pending: Dict[str, _Pending] = {}
        self._seen: OrderedDict[str, Tuple[int, int, str]] = OrderedDict()   # path -> size, mtime, sha
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._observer: Any = None
        self.paused_reason = ""
        self._paused_at = 0.0
        self.counts = {"queued": 0, "scanned": 0, "dropped": 0, "duplicates": 0, "ignored": 0}
        self.last_results: List[Dict] = []

    # ------------------------------------------------------------- control
    @property
    def available(self) -> bool:
        return WATCHDOG_AVAILABLE

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        """Start watching; False when watchdog is missing or no folder exists."""
        if not WATCHDOG_AVAILABLE:
            logger.error("Folder monitoring needs the 'watchdog' package (pip install watchdog).",
                         extra={"event": "monitor_unavailable"})
            return False
        for missing in self.missing:
            logger.warning("WATCH_DIRS: %s is not a folder; not watched.", missing)
        if not self.roots:
            return False
        observer = Observer()
        handler = _Handler(self)
        for root in self.roots:
            observer.schedule(handler, root, recursive=True)
        observer.daemon = True
        observer.start()
        self._observer = observer
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="aegis-folder-monitor", daemon=True)
        self._thread.start()
        logger.info("Monitoring %d folder(s) for new and changed files.", len(self.roots),
                    extra={"event": "monitor_started", "files": len(self.roots)})
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def resume(self) -> None:
        """Retry now after a pause (the GUI's retry action)."""
        with self._lock:
            self.paused_reason, self._paused_at = "", 0.0

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {"running": self.running, "folders": list(self.roots),
                    "pending": len(self._pending), "paused": self.paused_reason,
                    **self.counts}

    # ------------------------------------------------------------- events
    def wanted(self, path: str) -> Optional[str]:
        """The real path when `path` should be scanned, else None."""
        try:
            if os.path.islink(path):
                return None                      # never follow a link
            real = _real(path)
        except OSError:
            return None
        if not any(_inside(real, root) for root in self.roots):
            return None                          # resolved outside every watched root
        if any(_inside(real, own) for own in self.exclude) or real in self.exclude_files:
            return None                          # the scanner's own output
        name = os.path.basename(real)
        parts = real.split(os.sep)
        if name.startswith("~$") or any(p.startswith(TEMP_PREFIXES) for p in parts):
            return None
        if self.exts and not name.lower().endswith(self.exts):
            return None
        try:
            if real in self.scanner.canaries.paths():
                return None
        except Exception:
            pass
        return real

    def note(self, path: str) -> None:
        """Record a path from an event (cheap; nothing is opened)."""
        real = self.wanted(path)
        if real is None:
            with self._lock:
                self.counts["ignored"] += 1
            return
        try:
            st = os.stat(real)
        except OSError:
            return
        now = self._clock()
        with self._lock:
            entry = self._pending.get(real)
            if entry is None:
                if len(self._pending) >= self.max_queue:
                    self.counts["dropped"] += 1
                    if self.counts["dropped"] in (1, 10, 100) or self.counts["dropped"] % 1000 == 0:
                        logger.warning("Folder monitor queue full (%d): %d file event(s) dropped.",
                                       self.max_queue, self.counts["dropped"],
                                       extra={"event": "monitor_queue_full"})
                    return
                self._pending[real] = _Pending(st.st_size, st.st_mtime_ns, now)
                self.counts["queued"] += 1
            elif (entry.size, entry.mtime_ns) != (st.st_size, st.st_mtime_ns):
                entry.size, entry.mtime_ns, entry.changed = st.st_size, st.st_mtime_ns, now

    # ------------------------------------------------------------- scanning
    def due(self) -> List[str]:
        """Paths that have settled; re-checks size and mtime first."""
        now = self._clock()
        ready: List[str] = []
        with self._lock:
            if self.paused_reason:
                if now - self._paused_at < self.retry_seconds:
                    return []
                logger.info("Folder monitor: retrying isolated scans after a pause.")
                self.paused_reason = ""
            for real, entry in list(self._pending.items()):
                if now - entry.changed < self.settle:
                    continue
                try:
                    st = os.stat(real)
                except OSError:
                    del self._pending[real]              # gone (deleted or renamed away)
                    continue
                if (st.st_size, st.st_mtime_ns) != (entry.size, entry.mtime_ns):
                    entry.size, entry.mtime_ns, entry.changed = st.st_size, st.st_mtime_ns, now
                    continue
                del self._pending[real]
                seen = self._seen.get(real)
                if seen and seen[:2] == (st.st_size, st.st_mtime_ns):
                    self.counts["duplicates"] += 1
                    continue
                ready.append(real)
        return [p for p in ready if self._new_content(p)]

    def _new_content(self, real: str) -> bool:
        """False when the file's SHA-256 equals the last scanned one for this path."""
        try:
            st = os.stat(real)
            h = hashlib.sha256()
            with open(real, "rb") as fh:            # hashing reads bytes; it parses nothing
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
        except OSError:
            return False
        sha = h.hexdigest()
        with self._lock:
            seen = self._seen.get(real)
            self._seen[real] = (st.st_size, st.st_mtime_ns, sha)
            self._seen.move_to_end(real)
            while len(self._seen) > SEEN_LIMIT:
                self._seen.popitem(last=False)
            if seen and seen[2] == sha:
                self.counts["duplicates"] += 1
                return False
        return True

    def scan_due(self) -> List[Dict]:
        """One pass: scan what settled. Returns the results."""
        paths = self.due()
        if not paths:
            return []
        results = self.scan_batch(paths)
        unscanned = int(getattr(self.scanner, "last_not_scanned", 0) or 0)
        if unscanned:
            with self._lock:
                self.paused_reason = ("isolated scan workers could not start; no file was "
                                      "scanned in the main process")
                self._paused_at = self._clock()
                for p in paths:                    # retried after the pause
                    self._seen.pop(p, None)
                    try:
                        st = os.stat(p)
                        self._pending[p] = _Pending(st.st_size, st.st_mtime_ns, 0.0)
                    except OSError:
                        pass
            logger.error("Folder monitoring paused: %s. %d file(s) will be retried in %.0f "
                         "minute(s).", self.paused_reason, unscanned, self.retry_seconds / 60,
                         extra={"event": "monitor_paused", "files": unscanned})
            return results
        with self._lock:
            self.counts["scanned"] += len(results)
        self.last_results = results
        if self.on_results is not None:
            try:
                self.on_results(results)
            except Exception as e:
                logger.error("Folder monitor: result callback failed: %s", e)
        return results

    def scan_batch(self, paths: List[str]) -> List[Dict]:
        """Isolated scan with the normal outputs: report, JSON Lines, alerts and
        automatic quarantine (inside _scan_targets)."""
        results = self.scanner._scan_targets(paths)
        if not results or int(getattr(self.scanner, "last_not_scanned", 0) or 0):
            return results
        try:
            self.scanner.generate_report(results)
            from core.outputs import deliver
            deliver(results, self.config)
        except Exception as e:
            logger.error("Folder monitor: outputs failed: %s", e,
                         extra={"event": "monitor_output_error"})
        return results

    def _loop(self) -> None:
        while not self._stop.wait(0.5):
            try:
                self.scan_due()
            except Exception as e:                # the monitor must keep running
                logger.error("Folder monitor pass failed: %s: %s", type(e).__name__, e,
                             extra={"event": "monitor_error"})


def monitor_from_config(scanner: Any, config: Mapping[str, Any],
                        on_results: Optional[Callable[[List[Dict]], None]] = None
                        ) -> Optional[FolderMonitor]:
    roots = split_dirs(config.get("watch_dirs"))
    if not roots:
        return None
    return FolderMonitor(scanner, roots, float(config.get("watch_settle_seconds") or 2),
                         int(config.get("watch_max_queue") or 1000),
                         float(config.get("watch_retry_minutes") or 5), on_results)
