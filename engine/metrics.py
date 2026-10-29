"""
Runtime counters for operations: how many files were scanned, how fast, with
which verdicts, and which layers failed or timed out.

One process-wide, thread-safe `METRICS` object. Results are recorded where
they reach the parent process (folder scans, the API, --scan-file), so scans
run in isolated workers are counted once. Layer errors and worker time-outs /
crashes are read from the result itself (`layer_errors`, `scan_failed`), which
works across processes. Worker starts are counted where the parent sees a worker
become ready or die before that; `worker_health()` is the live readiness check
of isolated scanning (GET /ready).

Exposed by the REST API (GET /metrics, JSON or Prometheus text) and logged as
a summary after every folder scan.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Dict, Iterable, Optional, Tuple

VERDICTS = ("Clean", "Low", "Medium", "High", "Critical")


class Metrics:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.started = self._clock()
            self.files = 0
            self.bytes = 0
            self.busy_seconds = 0.0
            self.verdicts: Counter = Counter({v: 0 for v in VERDICTS})
            self.layer_errors: Counter = Counter()
            self.failures: Counter = Counter()        # timeout | worker_crash | error
            self.rejected: Counter = Counter()        # API: rate_limited | too_large | busy
            self.worker_starts: Counter = Counter({"ok": 0, "failed": 0})
            self.worker_start_seconds = 0.0           # the last successful start
            self.start_failure_streak = 0             # failed starts since the last success
            self.start_failure_reason = ""

    # ---------------------------------------------------------------- recording
    def record_result(self, result: Dict, seconds: Optional[float] = None) -> None:
        sr = result.get("scan_results") or {}
        failed = str((sr.get("scan_failed") or {}).get("reason", ""))
        with self._lock:
            self.files += 1
            self.bytes += int(result.get("file_size") or 0)
            if seconds is None:
                seconds = float(result.get("scan_duration_ms") or 0) / 1000.0
            self.busy_seconds += max(0.0, seconds)
            self.verdicts[str(result.get("verdict", "Clean"))] += 1
            for layer in (sr.get("layer_errors") or {}):
                self.layer_errors[str(layer)] += 1
            if failed:
                code = str((sr.get("scan_failed") or {}).get("code", ""))
                kind = (code if code else
                        "timeout" if "timed out" in failed else
                        "worker_crash" if "died" in failed else
                        "memory" if "MemoryError" in failed else "error")
                self.failures[kind] += 1

    def record_results(self, results: Iterable[Dict]) -> None:
        for r in results:
            self.record_result(r)

    def reject(self, reason: str) -> None:
        with self._lock:
            self.rejected[reason] += 1

    def worker_start(self, ok: bool, seconds: float = 0.0, reason: str = "") -> None:
        """An isolated scan worker became ready (ok) or ended before that."""
        with self._lock:
            self.worker_starts["ok" if ok else "failed"] += 1
            if ok:
                self.worker_start_seconds = max(0.0, seconds)
                self.start_failure_streak = 0
                self.start_failure_reason = ""
            else:
                self.start_failure_streak += 1
                self.start_failure_reason = reason

    def worker_health(self) -> Tuple[bool, str]:
        """(ok, detail): isolated workers are failing when the most recent start
        failed and none has succeeded since (PR-11: readiness from live data)."""
        with self._lock:
            if self.start_failure_streak:
                why = f"; last: {self.start_failure_reason}" if self.start_failure_reason else ""
                return False, (f"isolated scan workers do not start "
                               f"({self.start_failure_streak} failed start(s) in a row{why})")
            if self.worker_starts["ok"]:
                return True, (f"isolated workers start "
                              f"(last start {self.worker_start_seconds:.1f}s)")
            return True, "no worker started yet"

    def worker_starts_ok(self) -> int:
        with self._lock:
            return self.worker_starts["ok"]

    # ---------------------------------------------------------------- reading
    def snapshot(self) -> Dict:
        with self._lock:
            uptime = max(1e-9, self._clock() - self.started)
            return {
                "uptime_seconds": round(uptime, 1),
                "files_scanned": self.files,
                "bytes_scanned": self.bytes,
                "files_per_second": round(self.files / uptime, 3),
                "average_scan_ms": round(1000 * self.busy_seconds / self.files, 1)
                if self.files else 0.0,
                "verdicts": dict(self.verdicts),
                "layer_errors": dict(self.layer_errors),
                "scan_failures": dict(self.failures),
                "requests_rejected": dict(self.rejected),
                "worker_starts": dict(self.worker_starts),
                "worker_start_failure_streak": self.start_failure_streak,
            }

    def prometheus(self) -> str:
        """The snapshot in the Prometheus text exposition format."""
        s = self.snapshot()
        out = [
            "# HELP aegis_uptime_seconds Seconds since the counters started.",
            "# TYPE aegis_uptime_seconds gauge",
            f"aegis_uptime_seconds {s['uptime_seconds']}",
            "# HELP aegis_files_scanned_total Files scanned.",
            "# TYPE aegis_files_scanned_total counter",
            f"aegis_files_scanned_total {s['files_scanned']}",
            "# TYPE aegis_bytes_scanned_total counter",
            f"aegis_bytes_scanned_total {s['bytes_scanned']}",
            "# HELP aegis_verdicts_total Results by verdict band.",
            "# TYPE aegis_verdicts_total counter",
        ]
        out += [f'aegis_verdicts_total{{verdict="{v}"}} {n}' for v, n in s["verdicts"].items()]
        out += ["# HELP aegis_layer_errors_total Layers that raised on a file.",
                "# TYPE aegis_layer_errors_total counter"]
        out += [f'aegis_layer_errors_total{{layer="{k}"}} {n}'
                for k, n in sorted(s["layer_errors"].items())]
        out += ["# HELP aegis_scan_failures_total Files whose scan timed out or crashed.",
                "# TYPE aegis_scan_failures_total counter"]
        out += [f'aegis_scan_failures_total{{kind="{k}"}} {n}'
                for k, n in sorted(s["scan_failures"].items())]
        out += ["# TYPE aegis_requests_rejected_total counter"]
        out += [f'aegis_requests_rejected_total{{reason="{k}"}} {n}'
                for k, n in sorted(s["requests_rejected"].items())]
        out += ["# HELP aegis_worker_starts_total Isolated scan workers that became ready "
                "(ok) or ended before that (failed).",
                "# TYPE aegis_worker_starts_total counter"]
        out += [f'aegis_worker_starts_total{{outcome="{k}"}} {n}'
                for k, n in sorted(s["worker_starts"].items())]
        out += ["# HELP aegis_worker_start_failure_streak Failed worker starts since the "
                "last successful one.",
                "# TYPE aegis_worker_start_failure_streak gauge",
                f"aegis_worker_start_failure_streak {s['worker_start_failure_streak']}"]
        return "\n".join(out) + "\n"

    def batch_summary(self, results: Iterable[Dict], seconds: float) -> Dict:
        """Figures for one folder scan (not the process totals)."""
        rs = list(results)
        verdicts = Counter(str(r.get("verdict", "Clean")) for r in rs)
        return {"files": len(rs), "seconds": round(seconds, 2),
                "files_per_sec": round(len(rs) / seconds, 2) if seconds > 0 else 0.0,
                "verdicts": {v: verdicts.get(v, 0) for v in VERDICTS}}


METRICS = Metrics()
