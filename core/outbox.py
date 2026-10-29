"""
The alert outbox (PR-08): alerts survive a receiver outage.

Each alert is saved as one JSON file of metadata in OUTBOX_DIR (the app-data
folder on the desktop, the analysis-state volume in Docker) before anything is
sent, then delivered on every configured channel - the webhook, e-mail - and
retried with exponential backoff until it is delivered or older than
OUTBOX_MAX_AGE_HOURS. An alert's id is derived from what it reports, so the same
alert queued twice is delivered once (a `sent/` marker remembers it for the
maximum age). Files are written atomically and readable by the owner only.

Only metadata is stored: the webhook payload (core/outputs.alert_payload) and
the e-mail fields (core/mailer.EMAIL_FIELDS). Never file content, never a
secret: senders get their URL, key or password from the configuration.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

from .mailer import RateLimited, clean_text

logger = logging.getLogger("RansomwareScanner")

CHANNELS = ("webhook", "email")
RANK = {"Clean": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
FIRST_RETRY_SECONDS = 30.0
MAX_RETRY_SECONDS = 3_600.0
Sender = Callable[[Dict[str, Any]], None]


# ------------------------------------------------------------------ alerts
def _alert_id(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:32]


def risk_band(score: Any) -> str:
    try:
        value = max(0, min(100, int(float(score))))
    except (TypeError, ValueError):
        value = 0
    low = min(80, (value // 20) * 20)
    return f"{low}-{low + 20 if low < 80 else 100}"


def verdict_alert(result: Mapping[str, Any]) -> Dict[str, Any]:
    """The outbox entry for one scan result: the webhook payload as before (plus
    alert_id and kind) and the e-mail fields."""
    from .outputs import alert_payload
    sha = str(result.get("sha256_hash") or "")
    scan_time = str(result.get("scan_time") or "")
    path = str(result.get("file_path") or "")
    alert_id = _alert_id("verdict", sha, scan_time, path)
    contribs = sorted((result.get("score_breakdown") or {}).get("contributions") or [],
                      key=lambda c: -float(c.get("points", 0) or 0))
    codes = [str(c.get("indicator")) for c in contribs if c.get("indicator")][:8]
    if (result.get("quarantine") or {}).get("id"):         # F3: the alert says it was vaulted
        codes = codes[:7] + ["quarantined"]
    name = clean_text(result.get("file_name") or os.path.basename(path), 120)
    email = {"alert_id": alert_id, "kind": "verdict",
             "verdict": str(result.get("verdict") or "Clean"),
             "risk_band": risk_band(result.get("risk_score")),
             "sha256": sha if len(sha) == 64 else "",
             "file_name": name, "time": clean_text(scan_time, 40) or "-",
             "scan_id": _alert_id("scan", scan_time, sha)[:16],
             "reason_codes": [c for c in codes if c.replace("_", "").isalnum()
                              and c == c.lower()]}
    webhook = dict(alert_payload(dict(result)), alert_id=alert_id, kind="verdict")
    return {"id": alert_id, "kind": "verdict", "verdict": email["verdict"],
            "webhook": webhook, "email": email}


def canary_alert(report: Any) -> Dict[str, Any]:
    """The outbox entry for a canary trip: what tripped, never file content."""
    findings = list(getattr(report, "findings", []) or [])
    statuses = sorted({str(f.status) for f in findings})
    checked = str(getattr(report, "checked_at", "") or time.strftime("%Y-%m-%d %H:%M:%S"))
    signature = tuple(sorted((str(f.path), str(f.status)) for f in findings))
    alert_id = _alert_id("canary", checked, signature)
    first = os.path.basename(str(findings[0].path)) if findings else ""
    codes = [f"canary_{s}" for s in statuses if s.replace("_", "").isalnum()][:8]
    email = {"alert_id": alert_id, "kind": "canary", "verdict": "Critical",
             "risk_band": "80-100", "sha256": "", "file_name": clean_text(first, 120),
             "time": clean_text(checked, 40) or "-", "scan_id": "",
             "reason_codes": [c.lower() for c in codes]}
    webhook = {"source": "aegis-sentinel", "alert_id": alert_id, "kind": "canary",
               "verdict": "Critical", "checked_at": checked,
               "summary": clean_text(report.summary(), 500) if hasattr(report, "summary") else "",
               "findings": [{"path": str(f.path), "status": str(f.status)} for f in findings[:50]]}
    return {"id": alert_id, "kind": "canary", "verdict": "Critical",
            "webhook": webhook, "email": email}


# ------------------------------------------------------------------ the outbox
class Outbox:
    """Pending alerts on disk; `flush` delivers what is due."""

    def __init__(self, folder: str, max_age_hours: float = 24,
                 clock: Callable[[], float] = time.time):
        self.root = Path(folder)
        self.pending = self.root / "pending"
        self.sent = self.root / "sent"
        self.max_age = float(max_age_hours) * 3600
        self._clock = clock
        self._lock = threading.Lock()

    def _ensure(self) -> None:
        for d in (self.root, self.pending, self.sent):
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

    def _write(self, path: Path, entry: Dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".alert.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(entry, fh, ensure_ascii=False, indent=1)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def enqueue(self, alert: Dict[str, Any], channels: Iterable[str]) -> bool:
        """Save the alert for `channels`; False when it is already queued or was
        delivered within the maximum age (duplicate), or there is no channel."""
        wanted = [c for c in channels if c in CHANNELS and alert.get(c)]
        if not wanted:
            return False
        with self._lock:
            self._ensure()
            target = self.pending / f"{alert['id']}.json"
            if target.exists() or (self.sent / alert["id"]).exists():
                return False
            entry = {"id": alert["id"], "kind": alert["kind"], "created": self._clock(),
                     "channels": {c: {"attempts": 0, "next": 0.0, "error": ""} for c in wanted},
                     **{c: alert[c] for c in wanted}}
            self._write(target, entry)
        logger.info("Alert %s (%s) queued for %s.", alert["id"], alert["kind"], ", ".join(wanted),
                    extra={"event": "alert_queued", "alert_id": alert["id"]})
        return True

    def flush(self, senders: Mapping[str, Optional[Sender]]) -> Dict[str, int]:
        """Try every due channel of every pending alert once. Returns counts:
        sent, retry (failed, will be retried), expired, waiting."""
        counts = {"sent": 0, "retry": 0, "expired": 0, "waiting": 0}
        with self._lock:
            if not self.pending.is_dir():
                return counts
            self._prune_sent()
            for path in sorted(self.pending.glob("*.json")):
                self._flush_one(path, senders, counts)
        return counts

    def _flush_one(self, path: Path, senders: Mapping[str, Optional[Sender]],
                   counts: Dict[str, int]) -> None:
        now = self._clock()
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            logger.error("Unreadable alert file %s (%s): removed.", path.name, type(e).__name__)
            path.unlink(missing_ok=True)
            return
        if now - float(entry.get("created", now)) > self.max_age:
            logger.error("Alert %s was not delivered within %.0f h (%s): dropped.",
                         entry.get("id"), self.max_age / 3600,
                         "; ".join(f"{c}: {s.get('error') or 'not tried'}"
                                   for c, s in entry["channels"].items()),
                         extra={"event": "alert_expired", "alert_id": entry.get("id")})
            from engine.metrics import METRICS
            for channel in entry["channels"]:
                METRICS.alert(channel, "expired")
            path.unlink(missing_ok=True)
            counts["expired"] += 1
            return
        for channel, state in list(entry["channels"].items()):
            send = senders.get(channel)
            if send is None or state["next"] > now:
                counts["waiting"] += 1
                continue
            try:
                send(entry[channel])
            except Exception as e:
                state["attempts"] += 1
                pause = (FIRST_RETRY_SECONDS if isinstance(e, RateLimited) else
                         min(MAX_RETRY_SECONDS, FIRST_RETRY_SECONDS * 2 ** (state["attempts"] - 1)))
                state["next"] = now + pause
                state["error"] = clean_text(f"{type(e).__name__}: {e}", 200)
                logger.warning("Alert %s: %s delivery failed (%s); retry in %.0fs.",
                               entry["id"], channel, state["error"], pause,
                               extra={"event": "alert_retry", "alert_id": entry["id"],
                                      "channel": channel})
                from engine.metrics import METRICS
                METRICS.alert(channel, "failed")
                counts["retry"] += 1
                continue
            del entry["channels"][channel]
            from engine.metrics import METRICS
            METRICS.alert(channel, "sent")
            counts["sent"] += 1
            logger.info("Alert %s delivered by %s.", entry["id"], channel,
                        extra={"event": "alert_sent", "alert_id": entry["id"], "channel": channel})
        if entry["channels"]:
            self._write(path, entry)
        else:
            (self.sent / entry["id"]).touch()
            path.unlink(missing_ok=True)

    def _prune_sent(self) -> None:
        now = self._clock()
        for marker in self.sent.iterdir():
            try:
                if now - marker.stat().st_mtime > self.max_age:
                    marker.unlink()
            except OSError:
                continue

    def status(self) -> Dict[str, Any]:
        """Pending alerts per channel and the last error (for the GUI and logs)."""
        out: Dict[str, Any] = {"pending": 0, "channels": {}}
        if not self.pending.is_dir():
            return out
        for path in self.pending.glob("*.json"):
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            out["pending"] += 1
            for channel, state in entry.get("channels", {}).items():
                c = out["channels"].setdefault(channel, {"pending": 0, "last_error": ""})
                c["pending"] += 1
                c["last_error"] = state.get("error") or c["last_error"]
        return out


# ------------------------------------------------------------------ wiring
def channels_for(alert: Mapping[str, Any], config: Mapping[str, Any],
                 email_available: bool) -> List[str]:
    """Which channels this alert goes to under `config`: a canary trip on every
    configured channel; a verdict at or above each channel's minimum."""
    rank = RANK.get(str(alert.get("verdict")), 0)
    canary = alert.get("kind") == "canary"
    out = []
    if config.get("webhook_url") and (
            canary or rank >= RANK.get(str(config.get("webhook_min_verdict") or "High"), 3)):
        out.append("webhook")
    if email_available and (
            canary or rank >= RANK.get(str(config.get("alert_email_min_verdict") or "High"), 3)):
        out.append("email")
    return out


def outbox_for(config: Mapping[str, Any]) -> Outbox:
    from engine.config import APP_DIR
    return Outbox(str(config.get("outbox_dir") or APP_DIR / "outbox"),
                  float(config.get("outbox_max_age_hours") or 24))


_MAILERS: Dict[tuple, Any] = {}


def senders_for(config: Mapping[str, Any]) -> Dict[str, Optional[Sender]]:
    """The delivery functions under `config`: the signed webhook, and e-mail
    either directly (desktop) or through the intel service (Docker)."""
    from .outputs import post_alert
    out: Dict[str, Optional[Sender]] = {"webhook": None, "email": None}
    if config.get("webhook_url"):
        url, secret = str(config["webhook_url"]), str(config.get("webhook_secret") or "")
        out["webhook"] = lambda payload: post_alert(payload, url, secret)
    if config.get("intel_socket"):
        from .intel_client import client_from_config
        client = client_from_config(dict(config))
        if client is not None and client.service("email").get("enabled"):
            out["email"] = client.alert_email
    else:
        from .mailer import SmtpMailer, email_configured
        if email_configured(config):
            key = tuple(str(config.get(k) or "") for k in (
                "smtp_host", "smtp_port", "smtp_security", "smtp_user", "alert_email_from",
                "alert_email_to", "alert_email_per_hour", "alert_email_per_day"))
            mailer = _MAILERS.get(key)
            if mailer is None:              # one per destination, so the caps hold across calls
                mailer = _MAILERS[key] = SmtpMailer(config)
            out["email"] = mailer.send
    return out


def queue_and_send(alerts: Iterable[Dict[str, Any]], config: Mapping[str, Any]) -> Dict[str, int]:
    """Queue each alert for its channels, then deliver what is due. Never raises:
    a delivery problem leaves the alert queued for the next flush."""
    try:
        senders = senders_for(config)
        box = outbox_for(config)
        for alert in alerts:
            wanted = channels_for(alert, config, senders["email"] is not None)
            box.enqueue(alert, wanted)
        return box.flush(senders)
    except Exception as e:
        logger.error("Alert outbox: %s: %s", type(e).__name__, e,
                     extra={"event": "alert_outbox_error"})
        return {"sent": 0, "retry": 0, "expired": 0, "waiting": 0}


def flush_pending(config: Mapping[str, Any]) -> Dict[str, int]:
    """Retry what is due (the background service calls this every minute)."""
    return queue_and_send((), config)
