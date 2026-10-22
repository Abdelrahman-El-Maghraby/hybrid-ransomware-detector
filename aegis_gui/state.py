"""Settings persistence, the log bridge and the scan worker thread."""

import json
import logging
import queue
import threading

from aegis_gui.common import RS, SETTINGS_FILE

# --- Settings persistence -----------------------------------------------------

class SettingsStore:
    """Small JSON-backed store for GUI preferences (API keys stay in .env)."""

    DEFAULTS = {
        "scan_directories": None,      # seeded from RS.CONFIG on first run
        "file_extensions": None,
        "scan_interval_hours": None,
        "schedule_enabled": True,
    }

    def __init__(self):
        self.data = {}
        try:
            if SETTINGS_FILE.exists():
                self.data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logging.getLogger("RansomwareScanner.GUI").error(
                f"Could not read GUI settings: {e}")
        for key, default in self.DEFAULTS.items():
            self.data.setdefault(key, default)
        if not self.data["scan_directories"]:
            self.data["scan_directories"] = list(RS.CONFIG["scan_directories"])
        if not self.data["file_extensions"]:
            self.data["file_extensions"] = list(RS.CONFIG["file_extensions"])
        if not self.data["scan_interval_hours"]:
            self.data["scan_interval_hours"] = int(RS.CONFIG["scan_interval_hours"])

    def save(self) -> None:
        try:
            tmp = SETTINGS_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            tmp.replace(SETTINGS_FILE)
        except Exception as e:
            logging.getLogger("RansomwareScanner.GUI").error(
                f"Could not save GUI settings: {e}")

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value
        self.save()


# --- Logging bridge -----------------------------------------------------------

class QueueLogHandler(logging.Handler):
    """Forwards scanner log records to the UI thread through a queue."""

    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue
        self.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s  %(message)s",
                                            "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.log_queue.put_nowait(self.format(record))
        except Exception:
            pass


# --- Scan controller (worker thread) -------------------------------------------

class ScanController:
    """Owns the scan worker thread; reports back through the app event bus."""

    def __init__(self, bus: queue.Queue):
        self.bus = bus
        self.thread = None
        self.cancel_event = None
        self.running = False

    def start(self, scanner: "RS.RansomwareScanner", mode: str, target: str = None) -> bool:
        if self.running:
            return False
        self.running = True
        self.cancel_event = threading.Event()
        self.thread = threading.Thread(target=self._work, daemon=True,
                                       args=(scanner, mode, target))
        self.thread.start()
        return True

    def stop(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()

    def _work(self, scanner, mode, target):
        bus = self.bus
        try:
            def callback(done, total, path, res):
                bus.put(("progress", done, total, path, res))
            if mode == "file":
                bus.put(("progress", 0, 1, target, None))
                results = [scanner.scan_file(target)]
                bus.put(("progress", 1, 1, target, results[0]))
            elif mode == "dir":
                results = scanner.scan_directory(target, callback, self.cancel_event)
            else:
                results = scanner.scan_all_directories(callback, self.cancel_event)

            cancelled = self.cancel_event.is_set()
            report_text = None
            if results and not cancelled:
                impact = scanner.last_impact if mode != "file" else None
                report_text = scanner.generate_report(results, impact=impact)
            bus.put(("scan_done", results, report_text, cancelled))
        except Exception as e:
            logging.getLogger("RansomwareScanner.GUI").exception("Scan failed")
            bus.put(("scan_error", str(e)))
        finally:
            self.running = False
