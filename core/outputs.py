"""Machine-readable outputs for SIEM / SOC pipelines.

* JSON Lines: one result per line (schema api/scan_result.schema.json), appended,
  so a log shipper (Filebeat, Fluent Bit, Splunk UF ...) can tail the file.
* Webhook: a compact alert per file at or above a verdict, POSTed as JSON. With a
  shared secret the body is signed (header X-Aegis-Signature: sha256=<hex HMAC>),
  so the receiver can reject forged alerts. Only metadata is sent - never file
  content.
* Alerts (webhook, e-mail, canary trips) go through the persistent outbox
  (core/outbox.py): a receiver that is down gets the alert later, once.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

logger = logging.getLogger("RansomwareScanner")

RANK = {"Clean": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def write_jsonl(results: Iterable[Dict], path: Union[str, Path]) -> int:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(p, "a", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
            n += 1
    return n


def alert_payload(r: Dict) -> Dict:
    contribs = sorted((r.get("score_breakdown") or {}).get("contributions") or [],
                      key=lambda c: -float(c.get("points", 0) or 0))
    return {
        "schema_version": r.get("schema_version"), "source": "aegis-sentinel",
        "engine_version": r.get("engine_version"), "scan_time": r.get("scan_time"),
        "file_path": r.get("file_path"), "sha256": r.get("sha256_hash"),
        "verdict": r.get("verdict"), "risk_score": r.get("risk_score"),
        "scan_status": r.get("scan_status", "complete"),
        "indicators": [c.get("indicator") for c in contribs[:8]],
        "top_reason": contribs[0].get("detail", "") if contribs else "",
        **_quarantine(r),
    }


def _quarantine(r: Dict) -> Dict:
    """The automatic quarantine taken on this file, when there was one (F3)."""
    q = r.get("quarantine") or {}
    if q.get("id"):
        return {"quarantine": {"id": q["id"], "original_removed": bool(q.get("original_removed"))}}
    if q.get("error"):
        return {"quarantine": {"error": str(q["error"])[:200]}}
    return {}


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _failure(e: BaseException, url: str) -> str:
    """L-A7: the error type and the host only. A webhook URL path can be the
    credential (chat services), and request errors repeat it."""
    from urllib.parse import urlsplit
    return f"{type(e).__name__} from {urlsplit(url).hostname or 'the webhook'}"


def post_alert(payload: Dict, url: str, secret: str = "", session=None,
               timeout: float = 10) -> None:
    """POST one alert payload, signed when there is a secret; raises when it was
    not accepted (2xx), so the outbox retries it."""
    import requests
    http = session or requests
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if payload.get("alert_id"):          # the same on every retry: receivers de-duplicate
        headers["Idempotency-Key"] = str(payload["alert_id"])
    if secret:
        headers["X-Aegis-Signature"] = sign(body, secret)
    try:
        resp = http.post(url, data=body, headers=headers, timeout=timeout)
    except Exception as e:
        raise RuntimeError(_failure(e, url)) from None
    status = getattr(resp, "status_code", 0)
    if not 200 <= status < 300:
        raise RuntimeError(f"webhook answered HTTP {status}")


def deliver(results: List[Dict], config: Dict, jsonl_path: Optional[str] = None) -> None:
    """Send results to every configured output: the JSON Lines file, and an alert
    per qualifying result through the outbox (webhook, e-mail).

    M17: a JSON Lines file that cannot be written (a directory, a full disk, a
    read-only mount) is logged and does not stop the alerts."""
    path = jsonl_path or config.get("jsonl_path")
    if path:
        try:
            write_jsonl(results, path)
        except Exception as e:
            logger.error("JSON Lines output %s could not be written: %s", path, e,
                         extra={"event": "jsonl_error"})
    from .mailer import email_configured
    from .outbox import queue_and_send, results_alerts
    if config.get("webhook_url") or email_configured(config) or config.get("intel_socket"):
        queue_and_send(results_alerts(results), config)
