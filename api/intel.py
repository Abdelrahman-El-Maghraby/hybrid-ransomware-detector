"""
Intel service: in a Docker deployment, the only part that talks to the outside
world (VirusTotal, an LLM, a CAPE sandbox). The analysis service, which opens the
hostile files, runs with no network at all (`network_mode: none`) and asks this
service over a Unix domain socket on a shared volume (docs/DEPLOYMENT.md).

It is not a proxy. It offers a fixed set of operations and never takes a URL:

    GET  /health                 liveness, no token (the container health check)
    GET  /v1/capabilities        which services are configured (no secrets)
    POST /v1/virustotal/lookup   {"sha256": "<64 hex digits>"}
    POST /v1/virustotal/upload   body = the file; only with VT_UPLOAD_UNKNOWN=true
    POST /v1/llm/analyze         {"content": "<at most MAX_LLM_CHARS characters>"}
    POST /v1/sandbox/submit      body = the file; X-Aegis-Extension: .docx (optional)
    POST /v1/sandbox/poll        {"task_id": <a task this service submitted>}
    POST /v1/alert/email         exactly the fields of core/mailer.EMAIL_FIELDS
                                 (metadata only); sent with this service's SMTP
                                 settings to its configured recipients

Every destination comes from this service's own configuration, and each service
gets its own session that refuses any other origin, redirects included
(core/http.py AllowlistSession): VirusTotal's API host, the configured LLM URL,
the configured SANDBOX_URL. Secrets (API keys, the sandbox token) live only here.
E-mail alerts go only to the configured SMTP_HOST:SMTP_PORT over TLS with
certificate verification (core/mailer.py); the SMTP password, the sender and
the recipients live only here, and the message is built from a fixed template.
The operation has its own hourly and daily caps (ALERT_EMAIL_PER_HOUR /
ALERT_EMAIL_PER_DAY) and ignores an alert id it has already sent.

Every request needs `Authorization: Bearer <AEGIS_INTEL_TOKEN>` (at least 32
characters, compared in constant time); the socket directory is open only to the
analysis service's group. Each operation has its own rate limit
(AEGIS_INTEL_RATE_PER_MINUTE, AEGIS_INTEL_BURST) and bodies are size-limited
(AEGIS_INTEL_MAX_UPLOAD_MB). Inputs are checked exactly: unknown fields, wrong
types, a hash that is not 64 hex digits or a task id this service did not create
are refused with 422.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import shutil
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from api.limits import BodyLimit, TokenBuckets
from core.http import RateLimiter, build_session, origin
from engine.external import ExternalLookupsMixin

logger = logging.getLogger("RansomwareScanner")

MAX_LLM_CHARS = 8000                       # the analysis side sends about 5,100
MAX_TASKS = 10_000                         # remembered sandbox task ids
VIRUSTOTAL_ORIGIN = "https://www.virustotal.com"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_EXT = re.compile(r"^\.[A-Za-z0-9]{1,8}$")
OPERATIONS = ("capabilities", "vt_lookup", "vt_upload", "llm_analyze", "sandbox_submit",
              "sandbox_poll", "alert_email")
MAX_SENT_IDS = 10_000                      # remembered e-mail alert ids (de-duplication)


def _env_number(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        raise RuntimeError(f"{name} must be a number") from None


def _origins(*urls: str) -> List[str]:
    out = []
    for url in urls:
        try:
            out.append(origin(url))
        except ValueError:
            logger.warning("Intel: %r is not an http(s) URL; not allowed as a destination", url)
    return out


def llm_destinations(config: Dict) -> List[str]:
    provider = str(config.get("llm_provider") or "auto").lower()
    urls = []
    if provider in ("auto", "ollama"):
        urls.append(str(config.get("ollama_host") or "http://localhost:11434"))
    if provider in ("auto", "openai") and config.get("chatgpt_api_key"):
        urls.append(str(config.get("chatgpt_api_url")
                        or "https://api.openai.com/v1/chat/completions"))
    return _origins(*urls)


class _VirusTotal(ExternalLookupsMixin):
    """The engine's VirusTotal code (engine/external.py) with an allowlisted
    session and the intel service's cache."""

    def __init__(self, config: Dict, session: Any, upload: bool, cache: Any = None):
        self.config = dict(config, virustotal_upload_unknown=upload)
        self.cache = cache                     # the intel service's own (see IntelService)
        self.intel = None
        self.http = session
        self.http_timeout = int(config.get("http_timeout", 30))
        self.vt_limiter = RateLimiter(float(config.get("virustotal_requests_per_minute", 4)))


class IntelService:
    """The operations, without HTTP (create_intel_app adds that)."""

    def __init__(self, config: Dict):
        from core.cache import ResultCache
        from core.sandbox import CapeClient
        from detectors.llm_backends import build_llm_backend
        self.config = config
        # The only cache of external answers in a Docker deployment. Entries are
        # written from the real service's reply, keyed by what this service derives
        # itself: the requested hash, the hash of the bytes received, the hash of
        # the text given. Nothing a caller sends is stored as an answer.
        self.cache = (ResultCache(config["cache_db_path"],
                                  float(config.get("cache_ttl_hours", 24)) * 3600)
                      if config.get("cache_enabled", True) and config.get("cache_db_path")
                      else None)
        self.upload_allowed = bool(config.get("virustotal_upload_unknown"))
        self.vt_enabled = bool(config.get("virustotal_api_key"))
        self.destinations: Dict[str, List[str]] = {"virustotal": [], "llm": [], "sandbox": []}
        self._vt = self._vt_upload = None
        if self.vt_enabled:
            self.destinations["virustotal"] = [origin(VIRUSTOTAL_ORIGIN)]
            session = build_session(allowed_origins=self.destinations["virustotal"])
            self._vt = _VirusTotal(config, session, upload=False, cache=self.cache)
            self._vt_upload = _VirusTotal(config, session, upload=True, cache=self.cache)
        self.destinations["llm"] = llm_destinations(config)
        self.llm = build_llm_backend(config, session=build_session(
            total_retries=0, allowed_origins=self.destinations["llm"]))
        self.sandbox = None
        url = str(config.get("sandbox_url") or "")
        if url:
            self.destinations["sandbox"] = _origins(url)
            self.sandbox = CapeClient(url, token=str(config.get("sandbox_token") or ""),
                                      session=build_session(user_agent="aegis-sentinel/4.7",
                                                            allowed_origins=self.destinations["sandbox"]))
        self._tasks: OrderedDict[int, str] = OrderedDict()     # task id -> sample sha256
        self._tasks_lock = threading.Lock()
        from core.mailer import SmtpMailer, email_configured
        self.mailer = SmtpMailer(config) if email_configured(config) else None
        self.destinations["email"] = [self.mailer.destination] if self.mailer else []
        self._sent_alerts: OrderedDict[str, bool] = OrderedDict()
        self._sent_lock = threading.Lock()

    def capabilities(self, max_upload: int) -> Dict:
        sandbox = self.sandbox
        return {
            "virustotal": {"enabled": self.vt_enabled, "upload": self.vt_enabled and self.upload_allowed},
            "llm": {"enabled": bool(getattr(self.llm, "available", False)),
                    "name": self.llm.name, "model": str(getattr(self.llm, "model", "") or ""),
                    "is_local": bool(self.llm.is_local)},
            "sandbox": {"enabled": sandbox is not None,
                        "server": self._sandbox_layer().split(":", 1)[1] if sandbox else "",
                        "options": sandbox.options if sandbox else ""},
            "email": {"enabled": self.mailer is not None},
            "limits": {"max_upload_bytes": max_upload, "max_llm_chars": MAX_LLM_CHARS},
        }

    # ------------------------------------------------------------ VirusTotal
    def vt_lookup(self, sha256: str) -> Dict:
        if self._vt is None:
            raise HTTPException(status_code=403, detail="VirusTotal is not configured")
        return self._vt.scan_file_with_virustotal("", {"sha256": sha256, "md5": ""})

    def vt_upload(self, path: str) -> Dict:
        if self._vt_upload is None or not self.upload_allowed:
            raise HTTPException(status_code=403, detail="uploads are switched off "
                                                        "(VT_UPLOAD_UNKNOWN=false)")
        hashes = _hashes(path)                 # of the bytes received, not a claimed hash
        return self._vt_upload.scan_file_with_virustotal(path, hashes)

    # ------------------------------------------------------------ LLM
    def _llm_layer(self) -> str:
        from detectors.llm_backends import PROMPT_VERSION
        return f"llm:{self.llm.name}:{getattr(self.llm, 'model', '')}:prompt-{PROMPT_VERSION}"

    def llm_analyze(self, content: str) -> Dict:
        if not getattr(self.llm, "available", False):
            raise HTTPException(status_code=403, detail="no LLM is configured")
        key = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if self.cache is not None:
            cached = self.cache.get(key, self._llm_layer())
            if cached is not None:
                return dict(cached, cached=True)
        result = self.llm.analyze(content)
        if self.cache is not None and result.get("analyzed"):
            self.cache.put(key, self._llm_layer(), result)
        return result

    # ------------------------------------------------------------ sandbox
    def sandbox_submit(self, path: str, name: str) -> Dict:
        if self.sandbox is None:
            raise HTTPException(status_code=403, detail="no sandbox is configured")
        sha = _hashes(path)["sha256"]
        if self.cache is not None:
            cached = self.cache.get(sha, self._sandbox_layer())
            if cached is not None:
                return dict(cached, status="cached")
        res = self.sandbox.submit(path, name=name)
        if res.submitted and res.task_id:
            with self._tasks_lock:
                self._tasks[int(res.task_id)] = sha
                while len(self._tasks) > MAX_TASKS:
                    self._tasks.popitem(last=False)
        return res.as_dict()

    def sandbox_poll(self, task_id: int) -> Dict:
        if self.sandbox is None:
            raise HTTPException(status_code=403, detail="no sandbox is configured")
        with self._tasks_lock:
            sha = self._tasks.get(task_id)
        if sha is None:
            raise HTTPException(status_code=422, detail="not a task this service submitted")
        res = self.sandbox.poll(task_id)
        if res.status != "pending":
            with self._tasks_lock:
                self._tasks.pop(task_id, None)
        if res.status == "reported" and self.cache is not None:
            self.cache.put(sha, self._sandbox_layer(), res.as_dict())
        return res.as_dict()

    # ------------------------------------------------------------ e-mail alerts
    def alert_email(self, fields: Dict) -> Dict:
        """Send one validated alert (fields checked by _email_fields); an id
        already sent is acknowledged without a second message."""
        from core.mailer import MailError, RateLimited
        if self.mailer is None:
            raise HTTPException(status_code=403, detail="e-mail alerts are not configured")
        alert_id = fields["alert_id"]
        with self._sent_lock:
            if alert_id in self._sent_alerts:
                return {"sent": False, "duplicate": True}
        try:
            self.mailer.send(fields)
        except RateLimited as e:
            raise HTTPException(status_code=429, detail=str(e), headers={"Retry-After": "300"}) from e
        except MailError as e:
            logger.warning("Intel: e-mail alert %s not sent: %s", alert_id, e,
                           extra={"event": "intel_email_failed"})
            raise HTTPException(status_code=502, detail="the SMTP server did not take the message") from e
        with self._sent_lock:
            self._sent_alerts[alert_id] = True
            while len(self._sent_alerts) > MAX_SENT_IDS:
                self._sent_alerts.popitem(last=False)
        logger.info("Intel: e-mail alert %s sent (%s, %s).", alert_id, fields["kind"],
                    fields["verdict"], extra={"event": "intel_email_sent"})
        return {"sent": True, "duplicate": False}

    def _sandbox_layer(self) -> str:
        """Cache key part: a report belongs to the CAPE server and options that made it."""
        box = self.sandbox
        if box is None:
            return "sandbox:"
        return "sandbox:" + hashlib.sha256(f"{box.url}|{box.options}".encode()).hexdigest()[:12]


def _hashes(path: str) -> Dict[str, str]:
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)  # md5: VirusTotal's id
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha.update(chunk)
            md5.update(chunk)
    return {"sha256": sha.hexdigest(), "md5": md5.hexdigest()}


def _fields(payload: Any, expected: Dict[str, type]) -> Dict:
    """Exactly the expected keys, each of the expected type (bool is not an int)."""
    if not isinstance(payload, dict) or set(payload) != set(expected):
        raise HTTPException(status_code=422, detail=f"expected exactly {sorted(expected)}")
    for key, kind in expected.items():
        value = payload[key]
        if isinstance(value, bool) or not isinstance(value, kind):
            raise HTTPException(status_code=422, detail=f"{key} must be {kind.__name__}")
    return payload


def _sha256(payload: Any) -> str:
    sha = _fields(payload, {"sha256": str})["sha256"].lower()
    if not _SHA256.match(sha):
        raise HTTPException(status_code=422, detail="sha256 must be 64 hex digits")
    return sha


def _content(payload: Any) -> str:
    content = _fields(payload, {"content": str})["content"]
    if not content.strip() or len(content) > MAX_LLM_CHARS:
        raise HTTPException(status_code=422, detail=f"content must be 1-{MAX_LLM_CHARS} characters")
    return content


def _task_id(payload: Any) -> int:
    task_id = _fields(payload, {"task_id": int})["task_id"]
    if task_id <= 0:
        raise HTTPException(status_code=422, detail="task_id must be positive")
    return task_id


def _email_fields(payload: Any) -> Dict:
    from core.mailer import validate_fields
    try:
        return validate_fields(payload)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from None


def _extension(value: str) -> str:
    if value and not _SAFE_EXT.match(value):
        raise HTTPException(status_code=422, detail="X-Aegis-Extension must look like .docx")
    return value.lower()


def create_intel_app(config: Optional[Dict] = None, token: Optional[str] = None,
                     service: Optional[IntelService] = None) -> FastAPI:
    from engine.config import CONFIG, ENGINE_VERSION
    token = token if token is not None else intel_token()
    if not token or len(token) < 32:
        raise RuntimeError("Set AEGIS_INTEL_TOKEN (or AEGIS_INTEL_TOKEN_FILE) to a random "
                           "value of at least 32 characters.")
    service = service or IntelService(config or CONFIG)
    max_upload = int(_env_number("AEGIS_INTEL_MAX_UPLOAD_MB", 100) * 1024 * 1024)
    buckets = TokenBuckets(_env_number("AEGIS_INTEL_RATE_PER_MINUTE", 120),
                           int(_env_number("AEGIS_INTEL_BURST", 20)))
    app = FastAPI(title="Aegis Sentinel intel", version=ENGINE_VERSION,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(BodyLimit, max_bytes=max_upload)
    logger.info("Intel service: destinations %s",
                {k: v for k, v in service.destinations.items() if v} or "none",
                extra={"event": "intel_ready"})

    def guard(operation: str) -> Callable[..., None]:
        def check(authorization: str = Header(default="")) -> None:
            scheme, _, given = authorization.partition(" ")
            if not (scheme.lower() == "bearer"
                    and hmac.compare_digest(given.encode(), token.encode())):
                logger.warning("Intel: refused a request with a missing or wrong token",
                               extra={"event": "intel_auth_failed"})
                raise HTTPException(status_code=401, detail="missing or wrong token")
            wait = buckets.take(operation)
            if wait > 0:
                raise HTTPException(status_code=429, detail="too many requests",
                                    headers={"Retry-After": str(max(1, int(wait + 0.999)))})
        return check

    async def with_sample(request: Request, ext: str, work: Callable[[str], Dict]) -> Dict:
        body = await request.body()
        if not body:
            raise HTTPException(status_code=422, detail="empty body")
        folder = Path(tempfile.mkdtemp(prefix="aegis_intel_"))
        try:
            sample = folder / f"sample{ext}"
            sample.write_bytes(body)
            return await run_in_threadpool(work, str(sample))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    @app.get("/health")
    def health() -> Dict:
        return {"status": "ok"}

    @app.get("/v1/capabilities", dependencies=[Depends(guard("capabilities"))])
    def capabilities() -> Dict:
        return service.capabilities(max_upload)

    @app.post("/v1/virustotal/lookup", dependencies=[Depends(guard("vt_lookup"))])
    def vt_lookup(payload: Any = Body(...)) -> Dict:
        return service.vt_lookup(_sha256(payload))

    @app.post("/v1/virustotal/upload", dependencies=[Depends(guard("vt_upload"))])
    async def vt_upload(request: Request) -> Dict:
        if not service.upload_allowed:              # before reading the body
            raise HTTPException(status_code=403, detail="uploads are switched off "
                                                        "(VT_UPLOAD_UNKNOWN=false)")
        return await with_sample(request, "", service.vt_upload)

    @app.post("/v1/llm/analyze", dependencies=[Depends(guard("llm_analyze"))])
    def llm_analyze(payload: Any = Body(...)) -> Dict:
        return service.llm_analyze(_content(payload))

    @app.post("/v1/sandbox/submit", dependencies=[Depends(guard("sandbox_submit"))])
    async def sandbox_submit(request: Request,
                             x_aegis_extension: str = Header(default="")) -> Dict:
        if service.sandbox is None:
            raise HTTPException(status_code=403, detail="no sandbox is configured")
        ext = _extension(x_aegis_extension)
        return await with_sample(request, ext,
                                 lambda path: service.sandbox_submit(path, f"sample{ext}"))

    @app.post("/v1/sandbox/poll", dependencies=[Depends(guard("sandbox_poll"))])
    def sandbox_poll(payload: Any = Body(...)) -> Dict:
        return service.sandbox_poll(_task_id(payload))

    @app.post("/v1/alert/email", dependencies=[Depends(guard("alert_email"))])
    def alert_email(payload: Any = Body(...)) -> Dict:
        if service.mailer is None:                  # before looking at the fields
            raise HTTPException(status_code=403, detail="e-mail alerts are not configured")
        return service.alert_email(_email_fields(payload))

    return app


def intel_token() -> str:
    from engine.secret_store import from_environment
    return from_environment("AEGIS_INTEL_TOKEN") or ""


def main() -> None:
    import uvicorn

    from engine.config import init_runtime
    init_runtime()
    socket_path = os.getenv("AEGIS_INTEL_SOCKET", "")
    if not socket_path:
        raise SystemExit("aegis-intel: set AEGIS_INTEL_SOCKET to the Unix socket path to "
                         "listen on (a volume shared with the analysis service)")
    from engine.config import CONFIG
    from engine.validation import ConfigError, check_config
    try:
        # its own settings, checked like the analysis service's (AEGIS_INTEL_SOCKET is
        # where this service listens, not a client setting here)
        check_config(dict(CONFIG, intel_socket=""))
        app = create_intel_app()
    except (ConfigError, RuntimeError) as e:
        raise SystemExit(f"aegis-intel: {e}") from e
    uvicorn.run(app, uds=socket_path, workers=1)


if __name__ == "__main__":
    main()
