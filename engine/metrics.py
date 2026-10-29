"""
Runtime counters for operations: how many files were scanned, how fast, with
which verdicts, and which layers failed or timed out.

One process-wide, thread-safe `METRICS` object. Results are recorded where
they reach the parent process (folder scans, the API, --scan-file), so scans
run in isolated workers are counted once. Layer errors and worker time-outs /
crashes are read from the result itself (`layer_errors`, `scan_failed`), which
works across processes.

Exposed by the REST API (GET /metrics, JSON or Prometheus text) and logged as
a summary after every folder scan.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Dict, Iterable, Optional

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
            self.job_failures: Counter = Counter()    # background jobs that raised (by name)
            self.layer_errors: Counter = Counter()
            self.failures: Counter = Counter()        # timeout | worker_crash | error
            self.rejected: Counter = Counter()        # API: rate_limited | too_large | busy

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
                kind = ("timeout" if "timed out" in failed else
                        "worker_crash" if "died" in failed else
                        "memory" if "MemoryError" in failed else "error")
                self.failures[kind] += 1

    def record_results(self, results: Iterable[Dict]) -> None:
        for r in results:
            self.record_result(r)

    def job_failed(self, name: str) -> None:
        """A scheduled background job raised (it is logged and runs again next time)."""
        with self._lock:
            self.job_failures[name] += 1

    def reject(self, reason: str) -> None:
        with self._lock:
            self.rejected[reason] += 1

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
                "scheduled_job_failures": dict(self.job_failures),
                "layer_errors": dict(self.layer_errors),
                "scan_failures": dict(self.failures),
                "requests_rejected": dict(self.rejected),
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
        out += ["# HELP aegis_scheduled_job_failures_total Background jobs that raised.",
                "# TYPE aegis_scheduled_job_failures_total counter"]
        out += [f'aegis_scheduled_job_failures_total{{job="{k}"}} {n}'
                for k, n in sorted(s["scheduled_job_failures"].items())]
        out += ["# HELP aegis_scan_failures_total Files whose scan timed out or crashed.",
                "# TYPE aegis_scan_failures_total counter"]
        out += [f'aegis_scan_failures_total{{kind="{k}"}} {n}'
                for k, n in sorted(s["scan_failures"].items())]
        out += ["# TYPE aegis_requests_rejected_total counter"]
        out += [f'aegis_requests_rejected_total{{reason="{k}"}} {n}'
                for k, n in sorted(s["requests_rejected"].items())]
        return "\n".join(out) + "\n"

    def batch_summary(self, results: Iterable[Dict], seconds: float) -> Dict:
        """Figures for one folder scan (not the process totals)."""
        rs = list(results)
        verdicts = Counter(str(r.get("verdict", "Clean")) for r in rs)
        return {"files": len(rs), "seconds": round(seconds, 2),
                "files_per_sec": round(len(rs) / seconds, 2) if seconds > 0 else 0.0,
                "verdicts": {v: verdicts.get(v, 0) for v in VERDICTS}}


METRICS = Metrics()
