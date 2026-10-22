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
    POST /scan          multipart "file" -> one result (api/scan_result.schema.json)

Security
  * A bearer token is required for everything except /health; the server refuses
    to start without one. Tokens are compared in constant time.
  * Binds to 127.0.0.1 by default; put it behind a TLS reverse proxy to expose it.
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
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Dict, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile

from api import SCHEMA_VERSION, load_schema

MAX_UPLOAD_MB = float(os.getenv("AEGIS_API_MAX_UPLOAD_MB", "50"))
_SAFE_EXT = re.compile(r"^\.[A-Za-z0-9]{1,8}$")


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


def create_app(config: Optional[Dict] = None, token: Optional[str] = None,
               isolate: bool = True) -> FastAPI:
    from engine.config import CONFIG, ENGINE_VERSION
    token = token if token is not None else os.getenv("AEGIS_API_TOKEN", "")
    if not token or len(token) < 16:
        raise RuntimeError("Set AEGIS_API_TOKEN to a random value of at least 16 characters.")
    service = _ScanService(config or CONFIG, isolate=isolate)
    app = FastAPI(title="Aegis Sentinel API", version=ENGINE_VERSION,
                  docs_url=None, redoc_url=None, openapi_url=None)

    def require_token(authorization: str = Header(default="")) -> None:
        scheme, _, given = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(given.encode(), token.encode()):
            raise HTTPException(status_code=401, detail="missing or wrong bearer token",
                                headers={"WWW-Authenticate": "Bearer"})

    @app.get("/health")
    def health() -> Dict:
        return {"status": "ok"}

    @app.get("/version", dependencies=[Depends(require_token)])
    def version() -> Dict:
        return {"engine": ENGINE_VERSION, "schema": SCHEMA_VERSION,
                "registry": service.scanner.scoring.registry.version}

    @app.get("/schema", dependencies=[Depends(require_token)])
    def schema() -> Dict:
        return load_schema()

    @app.post("/scan", dependencies=[Depends(require_token)])
    def scan(file: UploadFile = File(...)) -> Dict:
        name = Path(file.filename or "upload").name[:200] or "upload"
        ext = Path(name).suffix if _SAFE_EXT.match(Path(name).suffix or "") else ""
        work = Path(tempfile.mkdtemp(prefix="aegis_api_"))
        try:
            target = work / f"upload{ext.lower()}"
            limit = int(MAX_UPLOAD_MB * 1024 * 1024)
            written = 0
            with open(target, "wb") as out:
                while True:
                    chunk = file.file.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limit:
                        raise HTTPException(status_code=413,
                                            detail=f"file larger than {MAX_UPLOAD_MB:g} MB")
                    out.write(chunk)
            return service.scan(str(target), name)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    return app


def main() -> None:
    import uvicorn
    host = os.getenv("AEGIS_API_HOST", "127.0.0.1")
    port = int(os.getenv("AEGIS_API_PORT", "8765"))
    uvicorn.run(create_app(), host=host, port=port, workers=1)


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
