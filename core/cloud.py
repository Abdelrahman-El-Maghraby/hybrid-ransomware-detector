"""
Optional cloud storage for reports and logs (F5; owner decisions D-D, D-D1-D-D3).

Off by default and desktop only (the Docker edition keeps its own log shipping).
With CLOUD_UPLOAD=true the scanner uploads, to one S3-compatible bucket:

  * reports: an UPLOAD VIEW of each scan's results, built from an explicit
    allowlist of fields - not the local report with fields removed, so a new
    result field is never uploaded until someone adds it here;
  * logs: structured events (event type, level, time, codes, counts, verdict,
    hash) captured from the logger, never the log files or message text.

What the upload view does NOT contain (D-D3): paths, folder names and file
names (scan targets, archive members, attachments, embedded objects), user and
host names, and free text (log messages, indicator details, extracted strings,
URLs, e-mail addresses, subjects). A file is identified by a keyed pseudonym,
HMAC-SHA-256(key, its path) truncated to 16 hex digits; the key is a
per-installation secret (the secret store's CLOUD_PSEUDONYM_KEY) that is never
uploaded, so the same file correlates across uploads without its name. What
remains is listed in docs/DATA_POLICY.md. CLOUD_UPLOAD_FULL=true uploads the
full results instead (still no file content): it is recorded in every upload
and logged as a warning.

Never uploaded, in any mode: inspected files, quarantine vault contents, keys,
the alert outbox, the result cache.

Transport and storage (D-D1):
  * HTTPS PUT to CLOUD_ENDPOINT only, with certificate verification
    (CLOUD_CA_BUNDLE for a private CA); the SHA-256 checksum is sent (the
    server rejects a mismatch) and checked in the answer;
  * object keys are unique:
    <prefix>/<install-id>/<reports|logs>/<yyyy>/<mm>/<dd>/<UTC time>-<128-bit random>-<sha256 prefix>.json
    and, where the endpoint supports it, written create-only (If-None-Match: *);
  * the credential only needs to create objects under this installation's
    prefix: the client never lists, reads or deletes remote objects;
  * remote retention (90 days recommended) is the bucket's lifecycle rule,
    set by the operator; the product cannot check or enforce it. Unique keys
    stop the app from overwriting its own objects by accident; they do not
    stop someone holding the credential, and uploads are not tamper-evident -
    an uploaded report is only as trustworthy as the host that produced it.

The local spool (CLOUD_SPOOL_DIR): owner-only copies waiting for upload.
Removed at once after a confirmed upload; retried with backoff while the
network is down; at start and daily, items queued more than CLOUD_SPOOL_DAYS
(30) ago are deleted, then the oldest beyond CLOUD_SPOOL_MAX_MB (1024). Each
deletion is logged (name, age, reason) and counted. The local reports and logs
themselves are never touched. Turning cloud off stops queuing and uploading;
what is spooled stays until it expires; nothing is deleted remotely.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

logger = logging.getLogger("RansomwareScanner")

KINDS = ("report", "logs")
FIRST_RETRY_SECONDS = 60.0
MAX_RETRY_SECONDS = 3_600.0
_EXT = re.compile(r"^\.[a-z0-9]{1,8}$")
_CODE = re.compile(r"^[A-Za-z0-9_.:+-]{1,80}$")

# ------------------------------------------------------------------ the upload view
RESULT_FIELDS = ("sha256_hash", "md5_hash", "file_size", "verdict", "risk_score",
                 "severity_score", "is_malicious", "scan_status", "scan_time", "schema_version",
                 "engine_version", "scan_duration_ms")
PROVENANCE_FIELDS = ("engine_version", "schema_version", "registry_version", "profile", "isolation")
LAYER_LISTS = ("layers_run", "layers_failed", "layers_unavailable", "layers_not_applicable")
# structured log events: these fields only (engine/logs.py EVENT_FIELDS minus free text,
# paths and client addresses)
EVENT_FIELDS = ("event", "verdict", "risk_score", "duration_ms", "layer", "files",
                "files_per_sec", "scan_status", "sha256", "job", "channel")


def pseudonym(key: bytes, value: Any) -> str:
    return hmac.new(key, str(value or "").encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _code(value: Any) -> Optional[str]:
    text = str(value or "")
    return text if _CODE.match(text) else None


def redact_result(r: Mapping[str, Any], key: bytes) -> Dict[str, Any]:
    """The allowlisted, redacted view of one result (D-D3)."""
    out: Dict[str, Any] = {k: r[k] for k in RESULT_FIELDS if k in r}
    out["file"] = pseudonym(key, r.get("file_path") or r.get("file_name"))
    ext = os.path.splitext(str(r.get("file_name") or r.get("file_path") or ""))[1].lower()
    out["extension"] = ext if _EXT.match(ext) else ""
    sr = r.get("scan_results") or {}
    out["detected_type"] = _code((sr.get("file_integrity") or {}).get("detected_format")) or ""
    out["indicators"] = [
        {"indicator": _code(c.get("indicator")), "category": _code(c.get("category")),
         "points": c.get("points")}
        for c in (r.get("score_breakdown") or {}).get("contributions") or []
        if _code(c.get("indicator"))]
    rules = [_code(m.get("rule")) for m in ((sr.get("yara") or {}).get("matches") or [])]
    out["rules"] = sorted({x for x in rules if x})
    out["incomplete"] = [{"status": _code(g.get("status")), "layer": _code(g.get("layer"))}
                         for g in r.get("incomplete_reasons") or []]
    pv = r.get("provenance") or {}
    prov: Dict[str, Any] = {k: pv[k] for k in PROVENANCE_FIELDS if k in pv}
    rules_info = pv.get("rules") or {}
    prov["rules"] = {k: rules_info.get(k) for k in ("source", "version", "sha256")
                     if k in rules_info}
    for name in LAYER_LISTS:
        prov[name] = [x for x in (pv.get(name) or []) if _code(x)]
    prov["layers_skipped"] = [s["layer"] for s in pv.get("layers_skipped") or []
                              if isinstance(s, dict) and _code(s.get("layer"))]
    out["provenance"] = prov
    return out


def redact_event(record: logging.LogRecord) -> Optional[Dict[str, Any]]:
    """A structured log event, or None for a record without an event type."""
    event = getattr(record, "event", None)
    if not event or not _code(event):
        return None
    out: Dict[str, Any] = {"time": datetime.fromtimestamp(record.created, timezone.utc)
                           .isoformat(timespec="seconds"),
                           "level": record.levelname}
    for name in EVENT_FIELDS:
        value = getattr(record, name, None)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            out[name] = value
        elif isinstance(value, str) and _code(value):
            out[name] = value
    return out


def document(kind: str, items: List[Dict[str, Any]], install_id: str, full: bool) -> bytes:
    from engine.config import ENGINE_VERSION
    doc = {"format": 1, "kind": kind, "installation": install_id,
           "os": platform.system().lower(), "app_version": ENGINE_VERSION,
           "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "redacted": not full, "full_detail": full,
           ("results" if kind == "report" else "events"): items}
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")


# ------------------------------------------------------------------ identity
def installation_id(app_dir: Path) -> str:
    """A random identifier of this installation (not a secret), made once."""
    path = app_dir / "installation_id"
    try:
        value = path.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9a-f]{32}", value):
            return value
    except OSError:
        pass
    value = secrets.token_hex(16)
    app_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    return value


def pseudonym_key(config: Mapping[str, Any], app_dir: Path) -> bytes:
    """The per-installation pseudonym key: from the secret store (environment or
    OS keyring), created there on first use; without a keyring, an owner-only
    file next to the app data (logged). Never uploaded."""
    given = str(config.get("cloud_pseudonym_key") or "")
    if given:
        return given.encode("utf-8")
    from engine import secret_store
    stored = secret_store.load("CLOUD_PSEUDONYM_KEY")
    if stored:
        return stored.encode("utf-8")
    fallback = app_dir / "cloud_pseudonym.key"
    try:
        value = fallback.read_text(encoding="utf-8").strip()
        if value:
            return value.encode("utf-8")
    except OSError:
        pass
    value = secrets.token_hex(32)
    try:
        secret_store.store("CLOUD_PSEUDONYM_KEY", value)
        return value.encode("utf-8")
    except secret_store.SecretStoreError:
        logger.warning("No OS keyring: the cloud pseudonym key is kept in an owner-only "
                       "file in the app folder.")
    app_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(fallback), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value + "\n")
    return value.encode("utf-8")


# ------------------------------------------------------------------ the spool
class Spool:
    """Documents waiting for upload; retry state and counters in state.json."""

    def __init__(self, folder: str, days: float = 30, max_mb: float = 1024,
                 clock: Callable[[], float] = time.time):
        self.root = Path(folder)
        self.max_age = float(days) * 86_400
        self.max_bytes = int(float(max_mb) * 1024 * 1024)
        self._clock = clock
        self._lock = threading.Lock()

    def _ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _state(self) -> Dict[str, Any]:
        try:
            state = json.loads((self.root / "state.json").read_text(encoding="utf-8"))
            if isinstance(state, dict):
                state.setdefault("items", {})
                state.setdefault("expired_without_upload", 0)
                return state
        except (OSError, ValueError):
            pass
        return {"items": {}, "expired_without_upload": 0, "last_error": ""}

    def _save(self, state: Dict[str, Any]) -> None:
        self._write(self.root / "state.json", json.dumps(state, indent=1).encode("utf-8"))

    def _write(self, path: Path, data: bytes) -> None:
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".spool.", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def items(self) -> List[Path]:
        if not self.root.is_dir():
            return []
        return sorted(p for p in self.root.glob("*.json") if p.name != "state.json")

    def add(self, kind: str, data: bytes) -> Path:
        with self._lock:
            self._ensure()
            now = self._clock()
            stamp = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%dT%H%M%S")
            path = self.root / f"{kind}-{stamp}-{secrets.token_hex(8)}.json"
            self._write(path, data)
            state = self._state()
            state["items"][path.name] = {"queued": now, "attempts": 0, "next": 0.0}
            self._save(state)
            return path

    def cleanup(self) -> int:
        """Delete what expired (age) and the oldest beyond the size cap."""
        removed = 0
        with self._lock:
            if not self.root.is_dir():
                return 0
            state, now = self._state(), self._clock()
            entries = []
            for p in self.items():
                queued = float(state["items"].get(p.name, {}).get("queued", p.stat().st_mtime))
                entries.append((queued, p))
            entries.sort()
            keep = []
            for queued, p in entries:
                if now - queued > self.max_age:
                    removed += self._drop(p, state, now - queued,
                                          f"queued more than {self.max_age / 86_400:.0f} days ago")
                else:
                    keep.append((queued, p))
            total = sum(p.stat().st_size for _, p in keep)
            for queued, p in keep:
                if total <= self.max_bytes:
                    break
                total -= p.stat().st_size
                removed += self._drop(p, state, now - queued, "spool over its size cap")
            for name in [n for n in state["items"] if not (self.root / n).exists()]:
                del state["items"][name]
            self._save(state)
        return removed

    def _drop(self, path: Path, state: Dict[str, Any], age: float, why: str) -> int:
        logger.warning("Cloud spool: deleted %s (%.1f days old) without upload: %s.",
                       path.name, age / 86_400, why,
                       extra={"event": "cloud_spool_expired"})
        from engine.metrics import METRICS
        METRICS.cloud("expired")
        path.unlink(missing_ok=True)
        state["items"].pop(path.name, None)
        state["expired_without_upload"] = int(state.get("expired_without_upload", 0)) + 1
        return 1

    def upload_due(self, put: Callable[[str, bytes], str]) -> Dict[str, int]:
        """Upload every due item once; delete it after a confirmed upload."""
        counts = {"uploaded": 0, "retry": 0, "waiting": 0}
        from engine.metrics import METRICS
        with self._lock:
            state, now = self._state(), self._clock()
            for p in self.items():
                info = state["items"].setdefault(p.name, {"queued": now, "attempts": 0,
                                                          "next": 0.0})
                if info["next"] > now:
                    counts["waiting"] += 1
                    continue
                kind = p.name.split("-", 1)[0]
                try:
                    put(kind, p.read_bytes())
                except Exception as e:
                    info["attempts"] += 1
                    info["next"] = now + min(MAX_RETRY_SECONDS,
                                             FIRST_RETRY_SECONDS * 2 ** (info["attempts"] - 1))
                    state["last_error"] = f"{type(e).__name__}: {str(e)[:160]}"
                    METRICS.cloud("failed")
                    counts["retry"] += 1
                    continue
                p.unlink(missing_ok=True)
                state["items"].pop(p.name, None)
                METRICS.cloud("uploaded")
                counts["uploaded"] += 1
            if self.root.is_dir():
                self._save(state)
        if counts["retry"]:
            logger.warning("Cloud upload: %d item(s) not uploaded (%s); retried later.",
                           counts["retry"], state.get("last_error", ""),
                           extra={"event": "cloud_upload_retry"})
        return counts

    def status(self) -> Dict[str, Any]:
        state = self._state()
        files = self.items()
        return {"pending": len(files), "bytes": sum(p.stat().st_size for p in files),
                "expired_without_upload": int(state.get("expired_without_upload", 0)),
                "last_error": state.get("last_error", "")}


# ------------------------------------------------------------------ the uploader
class CloudError(RuntimeError):
    """An upload was not confirmed (never contains the secret key)."""


class S3Uploader:
    """Create-only PUTs of JSON documents to one bucket (boto3, the [cloud] extra)."""

    def __init__(self, config: Mapping[str, Any], install_id: str, client: Any = None,
                 clock: Callable[[], float] = time.time):
        self.bucket = str(config.get("cloud_bucket") or "")
        self.prefix = str(config.get("cloud_prefix") or "aegis").strip("/")
        self.install_id = install_id
        self.conditional = bool(config.get("cloud_conditional_writes", True))
        self._clock = clock
        self.client = client if client is not None else self._client(config)

    @staticmethod
    def _client(config: Mapping[str, Any]) -> Any:
        endpoint = str(config.get("cloud_endpoint") or "")
        if not endpoint.lower().startswith("https://"):
            raise CloudError("CLOUD_ENDPOINT must be an https:// URL")
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise CloudError("cloud uploads need the [cloud] extra: pip install boto3") from None
        return boto3.client(
            "s3", endpoint_url=endpoint, region_name=str(config.get("cloud_region") or "us-east-1"),
            aws_access_key_id=str(config.get("cloud_access_key_id") or ""),
            aws_secret_access_key=str(config.get("cloud_secret_access_key") or ""),
            verify=str(config.get("cloud_ca_bundle") or "") or True,
            config=Config(signature_version="s3v4", connect_timeout=10, read_timeout=30,
                          retries={"max_attempts": 2, "mode": "standard"},
                          s3={"addressing_style": "path"}))

    def object_key(self, kind: str, body: bytes) -> str:
        now = datetime.fromtimestamp(self._clock(), timezone.utc)
        digest = hashlib.sha256(body).hexdigest()
        folder = "reports" if kind == "report" else "logs"
        return (f"{self.prefix}/{self.install_id}/{folder}/{now:%Y/%m/%d}/"
                f"{now:%Y%m%dT%H%M%SZ}-{secrets.token_hex(16)}-{digest[:12]}.json")

    def put(self, kind: str, body: bytes) -> str:
        key = self.object_key(kind, body)
        checksum = base64.b64encode(hashlib.sha256(body).digest()).decode()
        args: Dict[str, Any] = {"Bucket": self.bucket, "Key": key, "Body": body,
                                "ContentType": "application/json", "ChecksumAlgorithm": "SHA256",
                                "ChecksumSHA256": checksum}
        if self.conditional:
            args["IfNoneMatch"] = "*"                 # create-only where supported
        try:
            answer = self.client.put_object(**args)
        except Exception as e:
            raise CloudError(f"upload of {kind} failed ({type(e).__name__})") from None
        status = (answer.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        if status != 200:
            raise CloudError(f"upload of {kind} answered HTTP {status}")
        echoed = answer.get("ChecksumSHA256")
        if echoed and echoed != checksum:
            raise CloudError(f"upload of {kind}: the stored checksum does not match")
        logger.info("Cloud upload: %s stored.", kind, extra={"event": "cloud_uploaded"})
        return key


# ------------------------------------------------------------------ wiring
def enabled(config: Mapping[str, Any]) -> bool:
    return bool(config.get("cloud_upload"))


def _app_dir() -> Path:
    from engine.config import APP_DIR
    return Path(APP_DIR)


def spool_for(config: Mapping[str, Any]) -> Spool:
    return Spool(str(config.get("cloud_spool_dir") or _app_dir() / "cloud_spool"),
                 float(config.get("cloud_spool_days") or 30),
                 float(config.get("cloud_spool_max_mb") or 1024))


def spool_report(results: List[Dict[str, Any]], config: Mapping[str, Any]) -> None:
    """Queue the upload view of one scan's results. Never raises."""
    if not (enabled(config) and results):
        return
    try:
        full = bool(config.get("cloud_upload_full"))
        app = _app_dir()
        key = pseudonym_key(config, app)
        items = ([dict(r) for r in results] if full else [redact_result(r, key) for r in results])
        spool_for(config).add("report", document("report", items, installation_id(app), full))
    except Exception as e:
        logger.error("Cloud spool: the report was not queued (%s).", type(e).__name__,
                     extra={"event": "cloud_spool_error"})


class EventSpool(logging.Handler):
    """Collects structured log events (redact_event) for upload as one logs
    document at a time; the message text is never kept."""

    def __init__(self, config: Mapping[str, Any], limit: int = 500):
        super().__init__(level=logging.INFO)
        self.config, self.limit = config, limit
        self.events: List[Dict[str, Any]] = []
        self._events_lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith("botocore") or record.name.startswith("urllib3"):
            return
        event = redact_event(record)
        if event is None:
            return
        with self._events_lock:
            self.events.append(event)
            full = len(self.events) >= self.limit
        if full:
            self.flush_to_spool()

    def flush_to_spool(self) -> None:
        with self._events_lock:
            events, self.events = self.events, []
        if not events or not enabled(self.config):
            return
        try:
            full = bool(self.config.get("cloud_upload_full"))
            spool_for(self.config).add("logs", document("logs", events,
                                                        installation_id(_app_dir()), full))
        except Exception:
            pass                                       # never log from inside a handler


_EVENT_SPOOL: Optional[EventSpool] = None


def install_event_spool(config: Mapping[str, Any]) -> Optional[EventSpool]:
    """Attach the event collector to the scanner's logger when cloud is on."""
    global _EVENT_SPOOL
    if not enabled(config) or _EVENT_SPOOL is not None:
        return _EVENT_SPOOL
    _EVENT_SPOOL = EventSpool(config)
    logging.getLogger("RansomwareScanner").addHandler(_EVENT_SPOOL)
    if config.get("cloud_upload_full"):
        logger.warning("CLOUD_UPLOAD_FULL is on: uploads carry the full results, including "
                       "paths and file names (recorded in every upload).",
                       extra={"event": "cloud_full_detail"})
    return _EVENT_SPOOL


_UPLOADER: Dict[str, S3Uploader] = {}


def run_uploads(config: Mapping[str, Any], cleanup: bool = False,
                uploader: Optional[S3Uploader] = None) -> Dict[str, int]:
    """The scheduled job: flush captured events, optionally clean the spool,
    upload what is due. Off: nothing is queued or uploaded (the spool stays)."""
    spool = spool_for(config)
    if cleanup:
        spool.cleanup()
    if not enabled(config):
        return {"uploaded": 0, "retry": 0, "waiting": 0}
    if _EVENT_SPOOL is not None:
        _EVENT_SPOOL.flush_to_spool()
    if uploader is None:
        install = installation_id(_app_dir())
        uploader = _UPLOADER.get(install)
        if uploader is None:
            uploader = _UPLOADER[install] = S3Uploader(config, install)
    return spool.upload_due(uploader.put)
