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

from .http import DEFAULT_TIMEOUT, EgressDenied, build_session, safe_json

logger = logging.getLogger("RansomwareScanner.sandbox")

# M26: what is known about handing the file to the sandbox. `submitted` keeps its
# meaning (CAPE confirmed with a task id); these say more, for privacy reporting:
#   not_attempted  nothing was sent (no time, no upload started, or the
#                  connection to the sandbox never opened)
#   possible       an upload was started, but it is not known whether its bytes
#                  went out or whether CAPE accepted them
#   refused        CAPE answered without a task id: the request reached it
#   confirmed      CAPE answered with a task id
SUBMISSION_STATES = ("not_attempted", "possible", "refused", "confirmed")
# whether the file left the machine, per state: none | possible | sent
TRANSMISSION = {"not_attempted": "none", "possible": "possible", "refused": "sent",
                "confirmed": "sent"}
MIN_REQUEST_SECONDS = 1.0     # M26: with less time left, a request is not started
Progress = Callable[..., None]


def _no_progress(state: str, task_id: Optional[int] = None) -> None:
    pass


def _wait_end(end: float, deadline: Optional[float]) -> float:
    return end if deadline is None else min(end, deadline)


def _request_timeout(normal: float, deadline: Optional[float],
                     clock: Callable[[], float]) -> float:
    """A request's timeout: `normal`, or with a deadline the time left (at most
    `normal`). Callers with a deadline do not start a request when less than
    MIN_REQUEST_SECONDS is left, so no request is started after the deadline."""
    return normal if deadline is None else min(normal, max(0.01, deadline - clock()))


def _late(wait_seconds: float, deadline: Optional[float], task_id) -> str:
    cut = " (cut short by the scan time limit)" if deadline is not None else ""
    return (f"no report within {wait_seconds}s{cut} (task {task_id}; "
            "look it up in CAPE later)")


def nothing_sent(e: BaseException) -> bool:
    """True when a failed upload certainly sent nothing: the connection to the
    sandbox never opened (name not resolved, refused, connect time-out) or the
    allowlist refused the destination. Anything else may have sent bytes."""
    import requests
    from urllib3.exceptions import ConnectTimeoutError
    if isinstance(e, (EgressDenied, requests.exceptions.ConnectTimeout)):
        return True
    if isinstance(e, requests.exceptions.ConnectionError) and \
            not isinstance(e, requests.exceptions.ProxyError):
        reason = getattr(e.args[0], "reason", None) if e.args else None
        return isinstance(reason, ConnectTimeoutError)   # NewConnectionError, NameResolutionError
    return False


def retry_after(response) -> Optional[float]:
    """Seconds a 429/503 answer asks the client to wait (Retry-After in seconds)."""
    value = str((getattr(response, "headers", None) or {}).get("Retry-After") or "").strip()
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if 0 <= seconds < 10 ** 7 else None


# CAPE signature names / categories that mean ransomware behaviour specifically.
RANSOM_HINTS = ("ransom", "deletes_shadow", "shadowcopy", "bcdedit", "wbadmin",
                "encrypt", "mass_file_modification", "modifies_files_extension",
                "cryptopp", "recovery")


@dataclass
class SandboxResult:
    enabled: bool = False
    submitted: bool = False
    task_id: Optional[int] = None
    status: str = ""                      # submitted | pending | reported | timeout | error | cached
    malscore: float = 0.0                 # CAPE's own 0-10 score
    signatures: List[Dict] = field(default_factory=list)   # name, description, severity
    ransomware: List[str] = field(default_factory=list)    # signatures that match RANSOM_HINTS
    network_hosts: List[str] = field(default_factory=list)
    detail: str = ""
    submission: str = "not_attempted"     # SUBMISSION_STATES (M26)

    def as_dict(self) -> Dict:
        return {"enabled": self.enabled, "submitted": self.submitted, "task_id": self.task_id,
                "status": self.status, "malscore": self.malscore,
                "signatures": self.signatures[:30], "ransomware": self.ransomware,
                "network_hosts": self.network_hosts[:20], "detail": self.detail,
                "submission": self.submission,
                "transmission": TRANSMISSION.get(self.submission, "possible")}


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
        self.token = token
        self._own_session = session is None      # a given session is used as it is
        self.session = session or build_session()
        if token:
            self.session.headers["Authorization"] = f"Token {token}"
        self.sleep, self.clock = sleep, clock

    def analyze(self, path: str, deadline: Optional[float] = None,
                progress: Optional[Progress] = None) -> SandboxResult:
        """Submit, wait for the report (up to wait_seconds), summarise it.

        M26: with a `deadline` (on self.clock; set only inside an isolated worker)
        the wait is cooperative and bounded: no automatic retries, each request's
        timeout is the time left when it starts, no request starts with less than
        MIN_REQUEST_SECONDS left, a transient failure counts as "still pending", a
        Retry-After is honoured only if it fits, and a report that cannot be read
        is not taken as a finished one. This does not bound everything (a name
        lookup, a slowly dripped answer, redirects or a proxy can outlast it);
        the worker's own time limit stops those. `progress(state, task_id)` hears
        the submission state as it changes."""
        note = progress or _no_progress
        if deadline is not None:
            return self._analyze_bounded(path, deadline, note)
        res = self.submit(path, progress=note)
        if not res.submitted:
            return res
        end = self.clock() + self.wait_seconds
        unreadable = ""
        while True:
            polled = self.poll(int(res.task_id or 0))
            if polled.status != "pending":
                return polled
            unreadable = polled.detail or unreadable
            if self.clock() >= end:
                res.status = "timeout"
                res.detail = unreadable or _late(self.wait_seconds, None, res.task_id)
                return res
            self.sleep(min(self.poll_seconds, max(0.0, end - self.clock())))

    def submit(self, path: str, name: str = "", timeout: Optional[float] = None,
               session=None, progress: Optional[Progress] = None) -> SandboxResult:
        """Hand the file to CAPE: status "submitted" with a task id, or "error"."""
        res = SandboxResult(enabled=True)
        note = progress or _no_progress
        try:
            with open(path, "rb") as fh:
                data = {"options": self.options} if self.options else {}
                res.submission = "possible"          # from here on bytes may leave
                note("possible")
                r = (session or self.session).post(
                    f"{self.url}/apiv2/tasks/create/file/",
                    files={"file": (name or Path(path).name, fh)}, data=data,
                    timeout=timeout or self.timeout)
            body = safe_json(r)
            ids = ((body.get("data") or {}).get("task_ids") or []) if not body.get("error") else []
            if not ids:                              # an answer: the request reached CAPE
                res.submission = "refused"
                note("refused")
                res.status, res.detail = "error", f"submission refused: {body.get('error_value') or r.status_code}"
                return res
            res.submitted, res.task_id, res.status = True, int(ids[0]), "submitted"
            res.submission = "confirmed"
            note("confirmed", res.task_id)
            return res
        except Exception as e:                       # network trouble never breaks a scan
            if res.submission == "possible" and nothing_sent(e):
                res.submission = "not_attempted"
                note("not_attempted")
            return self._unreachable(res, e)

    def poll(self, task_id: int, timeout: Optional[float] = None) -> SandboxResult:
        """One status check: "pending", "reported" (with the summary) or "error"."""
        res = SandboxResult(enabled=True, submitted=True, task_id=task_id, status="pending",
                            submission="confirmed")
        timeout = timeout or self.timeout
        try:
            view = safe_json(self.session.get(f"{self.url}/apiv2/tasks/view/{task_id}/",
                                              timeout=timeout))
            status = str(((view.get("data") or {}).get("status")) or "")
            if status in ("failed_analysis", "failed_processing", "failed_reporting"):
                res.status, res.detail = "error", f"sandbox task {status}"
                return res
            if status != "reported":
                return res
            r = self.session.get(f"{self.url}/apiv2/tasks/get/report/{task_id}/",
                                 timeout=timeout)
            report = report_body(r)
            if report is None:                       # M34: not a finished report; wait on
                res.detail = _unreadable(task_id, r)
                return res
            return _reported(res, report, task_id)
        except Exception as e:
            return self._unreachable(res, e)

    # ------------------------------------------------- M26: the bounded wait
    def _bounded_session(self):
        """A session of this call only, without automatic retries (a retry and
        its back-off would not see the deadline); closed when the call ends, so
        nothing of it outlives the scan. A session given to the client (tests,
        the intel service's allowlist session) is used as it is."""
        if not self._own_session:
            return self.session, False
        session = build_session(total_retries=0)
        if self.token:
            session.headers["Authorization"] = f"Token {self.token}"
        return session, True

    def _left(self, deadline: float) -> float:
        return deadline - self.clock()

    def _analyze_bounded(self, path: str, deadline: float, note: Progress) -> SandboxResult:
        session, owned = self._bounded_session()
        try:
            if self._left(deadline) < MIN_REQUEST_SECONDS:
                return SandboxResult(enabled=True, status="timeout",
                                     detail="not submitted: no time left for a request")
            res = self.submit(path, timeout=min(self.timeout, self._left(deadline)),
                              session=session, progress=note)
            if not res.submitted:
                return res
            end = _wait_end(self.clock() + self.wait_seconds, deadline)
            unreadable = False
            while True:
                polled, pause, bad_report = self._poll_bounded(int(res.task_id or 0), deadline,
                                                               session)
                unreadable = unreadable or bad_report
                if polled is not None:
                    return polled
                now = self.clock()
                wait = max(self.poll_seconds, pause or 0.0)
                if now >= end or (pause is not None and pause > end - now):
                    res.status = "timeout"
                    if pause is not None and pause > end - now:
                        res.detail = (f"the sandbox asked to wait {pause:g}s; no time left in "
                                      f"the scan limit (task {res.task_id}; look it up in CAPE "
                                      f"later)")
                    elif unreadable:
                        res.detail = (f"CAPE said task {res.task_id} finished, but its report "
                                      f"could not be read before the scan time limit")
                    else:
                        res.detail = _late(self.wait_seconds, deadline, res.task_id)
                    return res
                self.sleep(min(wait, max(0.0, end - now)))
        finally:
            if owned:
                session.close()

    def _poll_bounded(self, task_id: int, deadline: float, session):
        """One status check within the deadline: (final result or None while
        pending, the Retry-After asked for, whether a finished task's report could
        not be read). Transient failures count as pending."""
        pending = (None, None, False)
        if self._left(deadline) < MIN_REQUEST_SECONDS:
            return pending
        try:
            r = session.get(f"{self.url}/apiv2/tasks/view/{task_id}/",
                            timeout=min(self.timeout, self._left(deadline)))
        except Exception as e:
            logger.info("Sandbox status check failed (will try again): %s", type(e).__name__)
            return pending
        code = int(getattr(r, "status_code", 200) or 200)
        if code == 429 or code >= 500:
            return None, retry_after(r), False
        status = str(((safe_json(r).get("data") or {}).get("status")) or "")
        if status in ("failed_analysis", "failed_processing", "failed_reporting"):
            return SandboxResult(enabled=True, submitted=True, task_id=task_id, status="error",
                                 submission="confirmed", detail=f"sandbox task {status}"), None, False
        if status != "reported" or self._left(deadline) < MIN_REQUEST_SECONDS:
            return pending
        try:
            r = session.get(f"{self.url}/apiv2/tasks/get/report/{task_id}/",
                            timeout=min(self.timeout, self._left(deadline)))
            code = int(getattr(r, "status_code", 200) or 200)
            if not 200 <= code < 300:
                return None, retry_after(r), True
            if self._left(deadline) <= 0:            # arrived too late: not decoded
                return pending
            report = report_body(r)
        except Exception as e:
            logger.info("Sandbox report could not be read (will try again): %s", type(e).__name__)
            return None, None, True
        if report is None:
            return None, None, True
        res = SandboxResult(enabled=True, submitted=True, task_id=task_id, status="pending",
                            submission="confirmed")
        return _reported(res, report, task_id), None, False

    @staticmethod
    def _unreachable(res: SandboxResult, e: Exception) -> SandboxResult:
        logger.warning("Sandbox request failed: %s", e)
        res.status, res.detail = "error", f"sandbox unreachable ({type(e).__name__})"
        return res


def report_body(response) -> Optional[Dict]:
    """M34: a CAPE report only when the request succeeded (2xx) and its body is
    a JSON object; an empty object is a valid report. Anything else (an error
    page, a proxy's answer, a truncated body) is not a finished report."""
    code = int(getattr(response, "status_code", 200) or 200)
    if not 200 <= code < 300:
        return None
    try:
        body = response.json()
    except Exception:
        return None
    return body if isinstance(body, dict) else None


def _unreadable(task_id: int, response) -> str:
    code = getattr(response, "status_code", "?")
    return (f"CAPE said task {task_id} finished, but its report could not be read "
            f"(HTTP {code}); look it up in CAPE later")


def _reported(res: SandboxResult, report: Dict, task_id: int) -> SandboxResult:
    summarise_report(report, res)
    res.status = "reported"
    res.detail = (f"CAPE task {task_id}: malscore {res.malscore:.1f}/10, "
                  f"{len(res.signatures)} behaviour signature(s)"
                  + (f"; ransomware behaviour: {', '.join(res.ransomware[:3])}"
                     if res.ransomware else ""))
    return res
