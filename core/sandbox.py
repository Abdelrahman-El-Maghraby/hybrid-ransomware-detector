"""
Client for a self-hosted CAPEv2 sandbox (https://github.com/kevoreilly/CAPEv2).

Static analysis cannot see what a file does when it runs: a payload downloaded
later, a second-stage password, code that only unpacks in memory. A sandbox runs
the file in an isolated virtual machine and records its behaviour. This module
does not run anything itself: it hands the file to a CAPE server *you* operate
(on your own network, typically next to the analysis VM), waits for the report,
and turns CAPE's behaviour signatures into evidence for the scoring matrix.

Off by default. Nothing is sent anywhere unless SANDBOX_URL is set, and only to
that URL. Results are cached by SHA-256 like the other external layers.

CAPE REST API (apiv2) used:
    POST {url}/apiv2/tasks/create/file/      multipart "file" (+ options)
    GET  {url}/apiv2/tasks/view/{id}/        -> data.status
    GET  {url}/apiv2/tasks/get/report/{id}/  -> JSON report (signatures, malscore)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .http import DEFAULT_TIMEOUT, build_session, safe_json

logger = logging.getLogger("RansomwareScanner.sandbox")

# CAPE signature names / categories that mean ransomware behaviour specifically.
RANSOM_HINTS = ("ransom", "deletes_shadow", "shadowcopy", "bcdedit", "wbadmin",
                "encrypt", "mass_file_modification", "modifies_files_extension",
                "cryptopp", "recovery")


@dataclass
class SandboxResult:
    enabled: bool = False
    submitted: bool = False
    task_id: Optional[int] = None
    status: str = ""                      # reported | timeout | error | skipped | cached
    malscore: float = 0.0                 # CAPE's own 0-10 score
    signatures: List[Dict] = field(default_factory=list)   # name, description, severity
    ransomware: List[str] = field(default_factory=list)    # signatures that match RANSOM_HINTS
    network_hosts: List[str] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> Dict:
        return {"enabled": self.enabled, "submitted": self.submitted, "task_id": self.task_id,
                "status": self.status, "malscore": self.malscore,
                "signatures": self.signatures[:30], "ransomware": self.ransomware,
                "network_hosts": self.network_hosts[:20], "detail": self.detail}


def summarise_report(report: Dict, res: SandboxResult) -> None:
    """Fill `res` from a CAPE JSON report."""
    res.malscore = float(report.get("malscore") or 0)
    sigs = []
    for s in report.get("signatures") or []:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name", ""))
        cats = [str(c) for c in (s.get("categories") or [])]
        sev = int(s.get("severity") or 1)
        sigs.append({"name": name, "description": str(s.get("description", ""))[:200],
                     "severity": max(1, min(3, sev)), "categories": cats[:5]})
        text = (name + " " + " ".join(cats)).lower()
        if any(h in text for h in RANSOM_HINTS):
            res.ransomware.append(name)
    res.signatures = sorted(sigs, key=lambda s: -s["severity"])
    net = report.get("network") or {}
    hosts = [h.get("ip") if isinstance(h, dict) else str(h) for h in (net.get("hosts") or [])]
    hosts += [d.get("domain") for d in (net.get("domains") or []) if isinstance(d, dict)]
    res.network_hosts = [h for h in hosts if h][:20]


class CapeClient:
    def __init__(self, url: str, token: str = "", timeout: int = DEFAULT_TIMEOUT,
                 wait_seconds: int = 600, poll_seconds: int = 15, options: str = "",
                 session=None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds
        self.options = options
        self.session = session or build_session(user_agent="aegis-sentinel/4.4")
        if token:
            self.session.headers["Authorization"] = f"Token {token}"
        self.sleep, self.clock = sleep, clock

    def analyze(self, path: str) -> SandboxResult:
        res = SandboxResult(enabled=True)
        try:
            with open(path, "rb") as fh:
                data = {"options": self.options} if self.options else {}
                r = self.session.post(f"{self.url}/apiv2/tasks/create/file/",
                                      files={"file": (Path(path).name, fh)}, data=data,
                                      timeout=self.timeout)
            body = safe_json(r)
            ids = ((body.get("data") or {}).get("task_ids") or []) if not body.get("error") else []
            if not ids:
                res.status, res.detail = "error", f"submission refused: {body.get('error_value') or r.status_code}"
                return res
            res.submitted, res.task_id = True, int(ids[0])
            deadline = self.clock() + self.wait_seconds
            while True:
                view = safe_json(self.session.get(f"{self.url}/apiv2/tasks/view/{res.task_id}/",
                                                  timeout=self.timeout))
                status = str(((view.get("data") or {}).get("status")) or "")
                if status == "reported":
                    break
                if status in ("failed_analysis", "failed_processing", "failed_reporting"):
                    res.status, res.detail = "error", f"sandbox task {status}"
                    return res
                if self.clock() >= deadline:
                    res.status = "timeout"
                    res.detail = (f"no report within {self.wait_seconds}s (task {res.task_id}; "
                                  "look it up in CAPE later)")
                    return res
                self.sleep(self.poll_seconds)
            report = safe_json(self.session.get(
                f"{self.url}/apiv2/tasks/get/report/{res.task_id}/", timeout=self.timeout))
            summarise_report(report, res)
            res.status = "reported"
            res.detail = (f"CAPE task {res.task_id}: malscore {res.malscore:.1f}/10, "
                          f"{len(res.signatures)} behaviour signature(s)"
                          + (f"; ransomware behaviour: {', '.join(res.ransomware[:3])}"
                             if res.ransomware else ""))
            return res
        except Exception as e:                       # network trouble never breaks a scan
            logger.warning("Sandbox submission failed: %s", e)
            res.status, res.detail = "error", f"sandbox unreachable ({type(e).__name__})"
            return res
