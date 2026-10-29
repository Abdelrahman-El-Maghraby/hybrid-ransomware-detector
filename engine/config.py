"""
Engine configuration: version, per-user paths, the .env file and the default
CONFIG dict.

Importing this module has no side effects: it creates no folder, configures
no logging and does not change os.environ (the .env file is only read). The
entry points (RansomwareScanner.py, gui.py, api/server.py) call init_runtime()
once, which does those three things, and validate the configuration with
engine.validation.check_config() so a bad value stops the program with a
clear message instead of surfacing later as a silent default.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import dotenv_values, load_dotenv

ENGINE_VERSION = "4.7.0"

# Resolve per-user paths dynamically so they adapt to the host OS (Windows/macOS/Linux)
USER_HOME = Path.home()
APP_DIR = USER_HOME / "RansomwareScanner"
DATA_DIR = APP_DIR / "data"
REPORT_DIR = APP_DIR / "scan_reports"
LOG_FILE = APP_DIR / "ransomware_scanner.log"
QUARANTINE_DIR = APP_DIR / "quarantine"
KEYSTORE_DIR = APP_DIR / "keystore"

# Repo-relative assets that ship with the scanner (YARA rules, sample signatures).
# In a PyInstaller build they are unpacked to sys._MEIPASS instead.
FROZEN = bool(getattr(sys, "frozen", False))
SCRIPT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
BUNDLED_RULES_DIR = SCRIPT_DIR / "rules"
BUNDLED_FUZZY_SIGS = SCRIPT_DIR / "fuzzy_signatures.sample.json"

logger = logging.getLogger("RansomwareScanner")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# API keys and settings may come from a local .env file (NEVER commit real keys).
# From source it sits next to this script; a packaged build keeps it in the
# per-user app folder, because the bundle directory is temporary or read-only.
ENV_FILE = (APP_DIR / ".env") if FROZEN else (SCRIPT_DIR / ".env")


def _read_dotenv(path: Path) -> Dict[str, str]:
    try:
        return {k: v for k, v in dotenv_values(path).items() if v is not None}
    except OSError:                       # unreadable .env: the environment still applies
        return {}


_DOTENV = _read_dotenv(ENV_FILE)
# Imported here, before init_runtime() copies .env into os.environ: it remembers which
# secrets the process environment really set (environment > OS keyring > .env).
from engine import secret_store  # noqa: E402

# Values that could not be parsed (reported by engine.validation, not ignored).
ENV_PROBLEMS: List[str] = []


def _raw(name: str) -> Optional[str]:
    """The environment wins over .env (as load_dotenv without override)."""
    return os.environ.get(name, _DOTENV.get(name))


def _getenv(name: str, default: str = "") -> str:
    value = _raw(name)
    return default if value is None else value


_RUNTIME_READY = False


def init_runtime(console: bool = True, level: int = logging.INFO) -> None:
    """For entry points, once: create the per-user folders, make .env values
    visible to os.getenv (some settings are read outside CONFIG), and send
    logs to the log file (and stdout). Calling it again does nothing."""
    global _RUNTIME_READY
    if _RUNTIME_READY:
        return
    APP_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    from engine.logs import configure_logging
    configure_logging(LOG_FILE, console=console, level=level)
    if ENV_FILE.is_file():                  # first run after 4.6: secrets out of .env
        secret_store.migrate_env_file(ENV_FILE, _DOTENV)
    load_dotenv(ENV_FILE)
    sources = secret_store.apply(CONFIG)
    logging.getLogger("RansomwareScanner").info(
        "Secrets -> %s", "  ".join(f"{name}:{src}" for name, src in sources.items()),
        extra={"event": "secrets", "sources": sources})
    _RUNTIME_READY = True


_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


def _env_bool(name: str, default: bool = False) -> bool:
    value = _raw(name)
    if value is None or not value.strip():
        return default
    v = value.strip().lower()
    if v not in _TRUE + _FALSE:
        ENV_PROBLEMS.append(f"{name}={value!r} is not a yes/no value (use true or false)")
        return default
    return v in _TRUE


def _env_float(name: str, default: float) -> float:
    value = _raw(name)
    if value is None or not str(value).strip():
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        ENV_PROBLEMS.append(f"{name}={value!r} is not a number")
        return default


# Every file type the engine understands. The GUI lets you pick a subset.
SUPPORTED_EXTENSIONS = [".pdf", ".docx", ".doc", ".docm", ".dotm", ".xlsx", ".xlsm",
                        ".xls", ".pptx", ".pptm", ".ppt", ".rtf", ".zip", ".7z", ".rar", ".iso", ".img", ".pkg", ".mpkg", ".dmg",
                        ".eml", ".msg", ".html", ".htm", ".svg",
                        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".bat", ".cmd",
                        ".one", ".chm", ".msi", ".xll",
                        ".exe", ".dll", ".scr", ".cpl", ".sys",
                        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"]
# Pictures are supported but not scanned in folder scans by default: a Downloads
# folder can hold thousands, and each one would cost a VirusTotal lookup. Images
# inside archives and e-mails are always checked; tick them in the GUI to add them.
IMAGE_SCAN_EXTENSIONS = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"]
DEFAULT_EXTENSIONS = [e for e in SUPPORTED_EXTENSIONS if e not in IMAGE_SCAN_EXTENSIONS]

# Configuration - paths derive from the user's home directory and adapt to the OS
CONFIG = {
    # "production" = the supported on-prem edition (docs/RELEASE_SCOPE.md): every
    # required layer must be available and enabled, emulation is refused.
    "profile": _getenv("AEGIS_PROFILE", "standard").strip().lower(),
    "scan_directories": [
        str(USER_HOME / "Downloads"),
        # Add more folders to scan as needed
    ],
    "file_extensions": list(DEFAULT_EXTENSIONS),
    "kaggle_database_path": str(DATA_DIR / "data_file.csv"),

    # --- LLM semantic layer -------------------------------------------------
    # llm_provider: "auto" (prefer a reachable LOCAL Ollama for OPSEC, else fall
    # back to OpenAI if a key is set), "ollama", "openai", or "none".
    "llm_provider": _getenv("LLM_PROVIDER", "auto"),
    "ollama_host": _getenv("OLLAMA_HOST", "http://localhost:11434"),
    "ollama_model": _getenv("OLLAMA_MODEL", "llama3.1"),
    "chatgpt_api_key": _getenv("OPENAI_API_KEY", ""),
    "chatgpt_api_url": "https://api.openai.com/v1/chat/completions",
    "openai_model": _getenv("OPENAI_MODEL", "gpt-4"),

    # --- Fuzzy / similarity hashing ----------------------------------------
    # Falls back to the bundled sample if no per-user DB exists.
    # Optional self-hosted CAPEv2 sandbox (dynamic analysis). Empty URL = off.
    "sandbox_url": _getenv("SANDBOX_URL", ""),
    "sandbox_token": _getenv("SANDBOX_TOKEN", ""),
    "sandbox_wait_seconds": int(_env_float("SANDBOX_WAIT_SECONDS", 600)),
    # "suspicious": only files the static layers already rate Medium or worse; "all": every top-level file
    "sandbox_submit": _getenv("SANDBOX_SUBMIT", "suspicious"),
    # Docker deployment: the analysis service has no network and reaches VirusTotal,
    # the LLM and the sandbox through the intel service on this Unix socket
    # (api/intel.py; the token is AEGIS_INTEL_TOKEN or AEGIS_INTEL_TOKEN_FILE).
    "intel_socket": _getenv("AEGIS_INTEL_SOCKET", ""),
    # Optional JavaScript emulation with box-js. Runs the attacker's script in a
    # Node sandbox: enable inside an analysis VM / container only.
    "emulation_enabled": _env_bool("EMULATION_ENABLED", False),
    "emulation_tool": _getenv("EMULATION_TOOL", "box-js"),
    "emulation_timeout": int(_env_float("EMULATION_TIMEOUT", 20)),
    # Reviewed weight changes (e.g. from tools/calibrate_weights.py); empty = registry as shipped
    "weights_override": _getenv("WEIGHTS_OVERRIDE", ""),
    # Folder scans: each file in a worker process with a time and memory limit
    "isolate_scans": _env_bool("ISOLATE_SCANS", True),
    "scan_workers": int(_env_float("SCAN_WORKERS", 0)),          # 0 = automatic (up to 4)
    "scan_timeout_seconds": int(_env_float("SCAN_TIMEOUT_SECONDS", 300)),
    "worker_memory_mb": int(_env_float("WORKER_MEMORY_MB", 2048)),  # 0 = no limit
    # Machine-readable outputs (SIEM / SOC): JSON Lines file and alert webhook
    "jsonl_path": _getenv("JSONL_PATH", ""),
    "webhook_url": _getenv("WEBHOOK_URL", ""),
    "webhook_secret": _getenv("WEBHOOK_SECRET", ""),
    "webhook_min_verdict": _getenv("WEBHOOK_MIN_VERDICT", "High"),
    # E-mail alerts (core/mailer.py): metadata only, SMTP with TLS; the password
    # comes from the secret store (SMTP_PASSWORD). In Docker these belong to the
    # intel service, which sends for the analysis service.
    "smtp_host": _getenv("SMTP_HOST", ""),
    "smtp_port": int(_env_float("SMTP_PORT", 465)),
    "smtp_security": _getenv("SMTP_SECURITY", "tls").lower(),
    "smtp_user": _getenv("SMTP_USER", ""),
    "smtp_password": _getenv("SMTP_PASSWORD", ""),
    "alert_email_from": _getenv("ALERT_EMAIL_FROM", ""),
    "alert_email_to": _getenv("ALERT_EMAIL_TO", ""),
    "alert_email_min_verdict": _getenv("ALERT_EMAIL_MIN_VERDICT", "High"),
    "alert_email_per_hour": int(_env_float("ALERT_EMAIL_PER_HOUR", 20)),
    "alert_email_per_day": int(_env_float("ALERT_EMAIL_PER_DAY", 100)),
    # The alert outbox (core/outbox.py): pending alerts, retried until delivered
    "outbox_dir": _getenv("OUTBOX_DIR", str(APP_DIR / "outbox")),
    "outbox_max_age_hours": _env_float("OUTBOX_MAX_AGE_HOURS", 24),
    # Optional cloud storage of reports and logs (core/cloud.py): off by default,
    # desktop only, a redacted upload view to one S3-compatible bucket over HTTPS.
    "cloud_upload": _env_bool("CLOUD_UPLOAD", False),
    "cloud_endpoint": _getenv("CLOUD_ENDPOINT", ""),
    "cloud_region": _getenv("CLOUD_REGION", "us-east-1"),
    "cloud_bucket": _getenv("CLOUD_BUCKET", ""),
    "cloud_prefix": _getenv("CLOUD_PREFIX", "aegis"),
    "cloud_access_key_id": _getenv("CLOUD_ACCESS_KEY_ID", ""),
    "cloud_secret_access_key": _getenv("CLOUD_SECRET_ACCESS_KEY", ""),
    "cloud_pseudonym_key": _getenv("CLOUD_PSEUDONYM_KEY", ""),
    "cloud_ca_bundle": _getenv("CLOUD_CA_BUNDLE", ""),
    "cloud_conditional_writes": _env_bool("CLOUD_CONDITIONAL_WRITES", True),
    "cloud_upload_full": _env_bool("CLOUD_UPLOAD_FULL", False),
    "cloud_spool_dir": _getenv("CLOUD_SPOOL_DIR", str(APP_DIR / "cloud_spool")),
    "cloud_spool_days": _env_float("CLOUD_SPOOL_DAYS", 30),
    "cloud_spool_max_mb": _env_float("CLOUD_SPOOL_MAX_MB", 1024),
    # Signed rule packs: base64 Ed25519 public keys allowed to sign them (comma-separated)
    "rulepack_public_keys": [k for k in _getenv("RULEPACK_PUBLIC_KEYS", "").split(",") if k.strip()],
    "data_dir": str(DATA_DIR),
    # Known-good files: one SHA-256 per line, optional "# note" after it
    "allowlist_path": _getenv("ALLOWLIST_PATH", str(DATA_DIR / "allowlist.txt")),
    "fuzzy_signature_db": _getenv("FUZZY_SIGNATURE_DB", str(DATA_DIR / "fuzzy_signatures.json")),
    "fuzzy_max_bytes": 20 * 1024 * 1024,   # don't fuzzy-hash files larger than this

    # --- YARA ---------------------------------------------------------------
    "yara_rules_dir": _getenv("YARA_RULES_DIR", str(BUNDLED_RULES_DIR)),

    # --- VirusTotal ---------------------------------------------------------
    "virustotal_api_key": _getenv("VIRUSTOTAL_API_KEY", ""),
    "virustotal_api_url": "https://www.virustotal.com/api/v3/files",
    # Privacy: by default only the file's SHA-256 is looked up. Uploading an
    # unknown file shares its full content with VirusTotal (and, through it,
    # with VT Enterprise subscribers) - opt in explicitly if you accept that.
    "virustotal_upload_unknown": _env_bool("VT_UPLOAD_UNKNOWN", False),
    # Free public API: 4 requests/minute. Set 0 to disable client-side pacing.
    "virustotal_requests_per_minute": _env_float("VT_REQUESTS_PER_MINUTE", 4),
    "http_timeout": int(_env_float("HTTP_TIMEOUT", 30)),

    # --- Result cache (VirusTotal + LLM answers, keyed by SHA-256) ---------
    "cache_enabled": _env_bool("CACHE_ENABLED", True),
    "cache_db_path": _getenv("CACHE_DB_PATH", str(DATA_DIR / "scan_cache.sqlite3")),
    "cache_ttl_hours": _env_float("CACHE_TTL_HOURS", 24),

    # --- Archives -----------------------------------------------------------
    "archive_max_depth": 3,
    "archive_max_total_mb": 100,
    "archive_max_members": 500,
    "archive_scan_members": 25,       # members that get the full pipeline
    # Containers inside containers (mail -> zip -> document) are followed this
    # many levels deep; deeper ones are still inspected but not unpacked.
    "max_nesting": 2,

    # --- E-mail (MailGuard) -------------------------------------------------
    "mail_max_attachments": 50,
    "mail_scan_attachments": 25,      # attachments that get the full pipeline

    # --- ML classifier ------------------------------------------------------
    # Without a trained model the transparent rule engine is used. Train one
    # with --train-ml BENIGN_DIR MALICIOUS_DIR (needs requirements-ml.txt).
    "ml_enabled": _env_bool("ML_ENABLED", True),
    "ml_model_path": _getenv("ML_MODEL_PATH", str(DATA_DIR / "ml_model.joblib")),

    # --- Pipeline staging (4.4.0-beta.2) ------------------------------------
    # The slow layers (ML, LLM, VirusTotal) run last. They are skipped when the
    # earlier layers already put the file at 100/100, where nothing can change the
    # verdict, and otherwise run at the same time instead of one after another.
    "skip_heavy_when_saturated": _env_bool("SKIP_HEAVY_WHEN_SATURATED", True),
    "parallel_heavy_layers": _env_bool("PARALLEL_HEAVY_LAYERS", True),
    "qr_scan_enabled": _env_bool("QR_SCAN_ENABLED", True),

    # --- Quarantine ---------------------------------------------------------
    "quarantine_dir": str(QUARANTINE_DIR),
    "keystore_dir": str(KEYSTORE_DIR),
    # "" (off, default) | "critical" | "high": quarantine files at/above this
    # verdict automatically after they are scanned.
    "auto_quarantine": _getenv("AUTO_QUARANTINE", "").strip().lower(),

    # --- Mailbox (IMAP) scanning -------------------------------------------
    # Read-only, TLS only. Use an app password. Empty host = off.
    "imap_host": _getenv("IMAP_HOST", ""),
    "imap_port": int(_env_float("IMAP_PORT", 993)),
    "imap_starttls": _env_bool("IMAP_STARTTLS", False),
    "imap_user": _getenv("IMAP_USER", ""),
    "imap_password": _getenv("IMAP_PASSWORD", ""),
    "imap_folder": _getenv("IMAP_FOLDER", "INBOX"),
    "imap_since_days": int(_env_float("IMAP_SINCE_DAYS", 7)),
    "imap_max_messages": int(_env_float("IMAP_MAX_MESSAGES", 200)),
    "imap_max_mb": _env_float("IMAP_MAX_MB", 25),
    "imap_state_path": str(DATA_DIR / "imap_state.json"),
    "imap_check_minutes": int(_env_float("IMAP_CHECK_MINUTES", 0)),   # background mode; 0 = off

    # --- Canary tripwires ---------------------------------------------------
    "canary_registry": str(DATA_DIR / "canaries.json"),
    "canary_check_minutes": int(_env_float("CANARY_CHECK_MINUTES", 5)),
    # On a NEW trigger: "" (alert only, default) or any of "network_off,script"
    "canary_response": _getenv("CANARY_RESPONSE", ""),
    "canary_response_script": _getenv("CANARY_RESPONSE_SCRIPT", ""),
    "canary_contain_mode": _getenv("CANARY_CONTAIN_MODE", "suspend"),   # or "terminate"
    "canary_contain_exclude": _getenv("CANARY_CONTAIN_EXCLUDE", ""),    # extra process names
    "canary_lock_dirs": _getenv("CANARY_LOCK_DIRS", ""),                # default: canary folders
    "containment_state_file": str(DATA_DIR / "containment_state.json"),

    "report_directory": str(REPORT_DIR),
    "scan_interval_hours": 6,  # Scan every 6 hours
}

VERDICT_RANK = {"Clean": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
