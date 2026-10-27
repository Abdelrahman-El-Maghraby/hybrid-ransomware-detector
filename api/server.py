"""
Optional REST API: scan a file over HTTP (for a mail gateway, a SOAR playbook, a
ticketing system, or a web front-end).

    pip install -e ".[api]"
    AEGIS_API_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))") aegis-api
    curl -H "Authorization: Bearer $AEGIS_API_TOKEN" -F file=@invoice.docx http://127.0.0.1:8765/scan

Endpoints
    GET  /health        liveness (no token)
    GET  /version       engine, registry and schema versions
    GET  /schema        the JSON schema of a result
    GET  /metrics       counters (files, files/s, verdicts, layer errors, rejections);
                        ?format=prometheus for the Prometheus text format
    POST /scan          multipart "file" -> one result (api/scan_result.schema.json)

Security
  * A bearer token is required for everything except /health; the server refuses
    to start without one. Tokens are compared in constant time.
  * Binds to 127.0.0.1 by default; put it behind a TLS reverse proxy to expose it.
  * Abuse limits (api/limits.py): uploads over AEGIS_API_MAX_UPLOAD_MB are
    refused before they are parsed (413); each client (IP + token) gets
    AEGIS_API_RATE_PER_MINUTE requests with AEGIS_API_BURST in hand (429);
    at most AEGIS_API_MAX_CONCURRENT_SCANS scans run at once (503). Behind a
    reverse proxy set AEGIS_API_TRUST_PROXY=1. TLS: see docs/DEPLOYMENT.md.
  * Uploads are size-limited, written to a private temporary folder with a
    generated name (the client's file name is only used for its extension and
    for display), scanned, and deleted.
  * Each scan runs in an isolated worker process with a time and memory limit
    (engine/workers.py), so a hostile upload cannot hang or crash the service.
  * The file is never executed; nothing is sent to third parties unless the
    operator configured VirusTotal / an LLM / a sandbox.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse

from api import SCHEMA_VERSION, load_schema
from api.limits import BodyLimit, RateLimit, ScanSlots, TokenBuckets
from engine.metrics import METRICS
from engine.readiness import readiness


def _env_number(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        raise RuntimeError(f"{name} must be a number") from None


MAX_UPLOAD_MB = _env_number("AEGIS_API_MAX_UPLOAD_MB", 50)
MULTIPART_OVERHEAD = 64 * 1024              # form boundaries and headers around the file
_SAFE_EXT = re.compile(r"^\.[A-Za-z0-9]{1,8}$")
logger = logging.getLogger("RansomwareScanner")


class _ScanService:
    """Owns the scanner and runs each upload isolated (or in-process for tests)."""

    def __init__(self, config: Dict, isolate: bool = True):
        from engine.scanner import RansomwareScanner
        self.config = dict(config)
        self.scanner = RansomwareScanner(self.config)
        self.isolate = isolate
        self._lock = threading.Lock()

    def scan(self, path: str, display: str) -> Dict:
        if not self.isolate:
            result = self.scanner.scan_file(path)
        else:
            from engine.workers import scan_isolated
            box: Dict = {}
            scan_isolated(self.scanner, [path], 1,
                          float(self.config.get("scan_timeout_seconds", 300)),
                          int(self.config.get("worker_memory_mb", 2048)),
                          lambda i, p, r: box.setdefault("r", r))
            result = box["r"]
        result["file_path"] = display
        result["file_name"] = display
        return result

    def warm_up(self) -> Tuple[bool, str]:
        """Prove isolated workers start and finish a scan: one small text file, once,
        at start-up (a readiness probe must not spawn a process each time)."""
        if not self.isolate:
            return True, "in-process scans (isolation off)"
        work = Path(tempfile.mkdtemp(prefix="aegis_warmup_"))
        try:
            sample = work / "warmup.txt"
            sample.write_text("Aegis Sentinel readiness check\n", encoding="utf-8")
            result = self.scan(str(sample), "warmup.txt")
        except Exception as e:  # the worker machinery itself is broken
            return False, f"warm-up scan raised {type(e).__name__}"
        finally:
            shutil.rmtree(work, ignore_errors=True)
        failed = (result.get("scan_results") or {}).get("scan_failed")
        if failed:
            return False, f"warm-up scan failed: {failed.get('reason', 'unknown')}"
        return True, "isolated workers start"


def create_app(config: Optional[Dict] = None, token: Optional[str] = None,
               isolate: bool = True) -> FastAPI:
    from engine.config import CONFIG, ENGINE_VERSION
    from engine.validation import check_config
    check_config(config or CONFIG, env_problems=None if config is None else ())
    token = token if token is not None else os.getenv("AEGIS_API_TOKEN", "")
    if not token or len(token) < 16:
        raise RuntimeError("Set AEGIS_API_TOKEN to a random value of at least 16 characters.")
    service = _ScanService(config or CONFIG, isolate=isolate)
    workers = service.warm_up()
    start = readiness(service.scanner, workers)
    if start["ready"]:
        logger.info("Ready (%s profile).", start["profile"], extra={"event": "ready"})
    else:
        logger.warning("Not ready (%s profile): %s", start["profile"], "; ".join(start["problems"]),
                       extra={"event": "not_ready", "problems": start["problems"]})
    app = FastAPI(title="Aegis Sentinel API", version=ENGINE_VERSION,
                  docs_url=None, redoc_url=None, openapi_url=None)
    limit = int(MAX_UPLOAD_MB * 1024 * 1024)
    slots = ScanSlots(int(_env_number("AEGIS_API_MAX_CONCURRENT_SCANS", 2)))
    app.add_middleware(BodyLimit, max_bytes=limit + MULTIPART_OVERHEAD)
    app.add_middleware(RateLimit, buckets=TokenBuckets(
        _env_number("AEGIS_API_RATE_PER_MINUTE", 60), int(_env_number("AEGIS_API_BURST", 10))),
        trust_proxy=os.getenv("AEGIS_API_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes"))

    def token_ok(authorization: str) -> bool:
        scheme, _, given = authorization.partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(given.encode(), token.encode())

    def require_token(authorization: str = Header(default="")) -> None:
        if not token_ok(authorization):
            raise HTTPException(status_code=401, detail="missing or wrong bearer token",
                                headers={"WWW-Authenticate": "Bearer"})

    @app.get("/health")
    def health() -> Dict:
        """The process is alive (not: it can scan correctly - that is /ready)."""
        return {"status": "ok"}

    @app.get("/ready")
    def ready(authorization: str = Header(default="")) -> JSONResponse:
        """200 when a scan would be correct and complete, else 503. Without the token
        only the yes/no is shown; the checks and layer states need it."""
        report = readiness(service.scanner, workers)
        body = report if token_ok(authorization) else {"ready": report["ready"]}
        return JSONResponse(body, status_code=200 if report["ready"] else 503)

    @app.get("/version", dependencies=[Depends(require_token)])
    def version() -> Dict:
        pv = service.scanner.provenance
        return {"engine": ENGINE_VERSION, "schema": SCHEMA_VERSION,
                "registry": service.scanner.scoring.registry.version,
                "rules": pv["rules"], "profile": pv["profile"],
                "external_services": pv["external_services"]}

    @app.get("/schema", dependencies=[Depends(require_token)])
    def schema() -> Dict:
        return load_schema()

    @app.get("/metrics", dependencies=[Depends(require_token)])
    def metrics(format: str = "json"):
        if format == "prometheus":
            return PlainTextResponse(METRICS.prometheus(),
                                     media_type="text/plain; version=0.0.4")
        return METRICS.snapshot()

    @app.post("/scan", dependencies=[Depends(require_token)])
    def scan(file: UploadFile = File(...)) -> Dict:
        if not slots.try_acquire():
            raise HTTPException(status_code=503, detail="scanner busy, retry shortly",
                                headers={"Retry-After": "5"})
        name = Path(file.filename or "upload").name[:200] or "upload"
        ext = Path(name).suffix if _SAFE_EXT.match(Path(name).suffix or "") else ""
        work = Path(tempfile.mkdtemp(prefix="aegis_api_"))
        try:
            target = work / f"upload{ext.lower()}"
            file_limit = int(MAX_UPLOAD_MB * 1024 * 1024)   # checked again on the file itself
            written = 0
            with open(target, "wb") as out:
                while True:
                    chunk = file.file.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > file_limit:
                        METRICS.reject("too_large")
                        raise HTTPException(status_code=413,
                                            detail=f"file larger than {MAX_UPLOAD_MB:g} MB")
                    out.write(chunk)
            result = service.scan(str(target), name)
            METRICS.record_result(result)
            return result
        finally:
            slots.release()
            shutil.rmtree(work, ignore_errors=True)

    return app


def main() -> None:
    import uvicorn

    from engine.config import init_runtime
    from engine.validation import ConfigError
    init_runtime()
    try:
        app = create_app()           # fails fast on a bad token or configuration
    except (ConfigError, RuntimeError) as e:
        raise SystemExit(f"aegis-api: {e}") from e
    host = os.getenv("AEGIS_API_HOST", "127.0.0.1")
    port = int(os.getenv("AEGIS_API_PORT", "8765"))
    uvicorn.run(app, host=host, port=port, workers=1)


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
