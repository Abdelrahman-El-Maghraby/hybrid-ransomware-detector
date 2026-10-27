"""
Real-time canary watching: verify the tripwires the moment something touches
them, instead of waiting for the next interval check.

Ransomware encrypts thousands of files a minute, so a 5-minute interval can
mean a lot of damage before the alarm. With `watchdog` installed, the folders
that hold canaries are watched for file-system events and a verification runs
within about a second of a canary being changed, deleted, renamed (e.g.
`report.docx` -> `report.docx.lockbit`) or of a ransom note appearing next to
it. The interval check keeps running as a safety net.

Only events that CHANGE something count: opening or reading a canary (which
`CanaryManager.verify()` itself does) produces "opened" / "closed without
writing" events on Linux, and reacting to those would loop forever. Bursts of
events are coalesced into one verification (`debounce` seconds).

Without `watchdog` the watcher reports itself unavailable and the scanner
falls back to interval checks only.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Callable, List, Optional, Set

from detectors.file_integrity import RANSOM_NOTE_RE

from .canary import CanaryManager, _norm

logger = logging.getLogger("RansomwareScanner.canary")

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore[assignment,misc]
    WATCHDOG_AVAILABLE = False

# Event types that mean something changed (watchdog's names).
_CHANGE_EVENTS = frozenset({"created", "deleted", "modified", "moved", "closed"})


class _Handler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(self, watcher: CanaryWatcher):
        super().__init__()
        self.watcher = watcher

    def on_any_event(self, event):
        if event.event_type not in _CHANGE_EVENTS or event.is_directory:
            return
        for path in (event.src_path, getattr(event, "dest_path", "") or ""):
            if path and self.watcher.is_relevant(path):
                self.watcher.poke(path)
                return


class CanaryWatcher:
    """Calls `on_change()` (in a background thread, debounced) when a canary or
    its folder shows signs of ransomware activity."""

    def __init__(self, manager: CanaryManager, on_change: Callable[[], object],
                 debounce: float = 1.0):
        self.manager = manager
        self.on_change = on_change
        self.debounce = float(debounce)
        self._observer: Optional[Any] = None
        self._watched: Set[str] = set()
        self._canaries: Set[str] = set()
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()
        self._touched: Set[str] = set()      # paths seen changing since the last check
        self.fired = 0                       # verifications started (for status / tests)

    @property
    def available(self) -> bool:
        return WATCHDOG_AVAILABLE

    @property
    def running(self) -> bool:
        return self._observer is not None

    # ---------------------------------------------------------------- control
    def start(self) -> bool:
        """Watch the folders of every deployed canary. False if nothing to watch."""
        if not WATCHDOG_AVAILABLE:
            return False
        self._canaries = set(self.manager.paths())
        dirs = {os.path.dirname(p) for p in self._canaries if os.path.isdir(os.path.dirname(p))}
        if not dirs:
            self.stop()
            return False
        if dirs == self._watched and self.running:
            return True
        self.stop()
        observer = Observer()
        handler = _Handler(self)
        for d in sorted(dirs):
            observer.schedule(handler, d, recursive=False)
        observer.daemon = True
        observer.start()
        self._observer, self._watched = observer, dirs
        logger.info("Canary tripwires watched in real time in %d folder(s).", len(dirs))
        return True

    def refresh(self) -> bool:
        """Pick up canaries deployed or removed since start() (cheap if unchanged)."""
        return self.start()

    def stop(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
        self._observer, self._watched = None, set()

    # ----------------------------------------------------------------- events
    def is_relevant(self, path: str) -> bool:
        p = _norm(path)
        if p in self._canaries:
            return True
        # A canary renamed with an appended extension (x.docx -> x.docx.lockbit).
        if any(p.startswith(c + ".") for c in self._canaries):
            return True
        return bool(RANSOM_NOTE_RE.search(os.path.basename(path)))

    def poke(self, path: str = "") -> None:
        """Schedule one verification `debounce` seconds from the first event."""
        with self._lock:
            if path and len(self._touched) < 1000:
                self._touched.add(path)
            if self._timer is not None:
                return
            self._timer = threading.Timer(self.debounce, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def take_touched(self) -> List[str]:
        """The changed paths seen since the last call (for containment: they
        point at the folders where the encrypting process is working)."""
        with self._lock:
            out, self._touched = sorted(self._touched), set()
        return out

    def _fire(self) -> None:
        with self._lock:
            self._timer = None
        self.fired += 1
        try:
            self.on_change()
        except Exception:                    # an alarm path must never crash the watcher
            logger.exception("Canary verification after a file event failed")
