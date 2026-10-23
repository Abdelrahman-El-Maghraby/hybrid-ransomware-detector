"""
Engine configuration: version, per-user paths, logging, .env loading and the
default CONFIG dict. Importing this module has the same side effects the
monolithic RansomwareScanner.py always had (creates ~/RansomwareScanner,
configures logging, loads .env), so behaviour is unchanged.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ENGINE_VERSION = "4.5.0"

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

# Create application directories if they don't exist
APP_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("RansomwareScanner")

# Load API keys from a local .env file (NEVER commit real keys to source control).
# From source it sits next to this script; a packaged build keeps it in the
# per-user app folder, because the bundle directory is temporary or read-only.
ENV_FILE = (APP_DIR / ".env") if FROZEN else (SCRIPT_DIR / ".env")
load_dotenv(ENV_FILE)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
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
    "scan_directories": [
        str(USER_HOME / "Downloads"),
        # Add more folders to scan as needed
    ],
    "file_extensions": list(DEFAULT_EXTENSIONS),
    "kaggle_database_path": str(DATA_DIR / "data_file.csv"),

    # --- LLM semantic layer -------------------------------------------------
    # llm_provider: "auto" (prefer a reachable LOCAL Ollama for OPSEC, else fall
    # back to OpenAI if a key is set), "ollama", "openai", or "none".
    "llm_provider": os.getenv("LLM_PROVIDER", "auto"),
    "ollama_host": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
    "ollama_model": os.getenv("OLLAMA_MODEL", "llama3.1"),
    "chatgpt_api_key": os.getenv("OPENAI_API_KEY", ""),
    "chatgpt_api_url": "https://api.openai.com/v1/chat/completions",
    "openai_model": os.getenv("OPENAI_MODEL", "gpt-4"),

    # --- Fuzzy / similarity hashing ----------------------------------------
    # Falls back to the bundled sample if no per-user DB exists.
    # Optional self-hosted CAPEv2 sandbox (dynamic analysis). Empty URL = off.
    "sandbox_url": os.getenv("SANDBOX_URL", ""),
    "sandbox_token": os.getenv("SANDBOX_TOKEN", ""),
    "sandbox_wait_seconds": int(_env_float("SANDBOX_WAIT_SECONDS", 600)),
    # "suspicious": only files the static layers already rate Medium or worse; "all": every top-level file
    "sandbox_submit": os.getenv("SANDBOX_SUBMIT", "suspicious"),
    # Optional JavaScript emulation with box-js. Runs the attacker's script in a
    # Node sandbox: enable inside an analysis VM / container only.
    "emulation_enabled": _env_bool("EMULATION_ENABLED", False),
    "emulation_tool": os.getenv("EMULATION_TOOL", "box-js"),
    "emulation_timeout": int(_env_float("EMULATION_TIMEOUT", 20)),
    # Reviewed weight changes (e.g. from tools/calibrate_weights.py); empty = registry as shipped
    "weights_override": os.getenv("WEIGHTS_OVERRIDE", ""),
    # Folder scans: each file in a worker process with a time and memory limit
    "isolate_scans": _env_bool("ISOLATE_SCANS", True),
    "scan_workers": int(_env_float("SCAN_WORKERS", 0)),          # 0 = automatic (up to 4)
    "scan_timeout_seconds": int(_env_float("SCAN_TIMEOUT_SECONDS", 300)),
    "worker_memory_mb": int(_env_float("WORKER_MEMORY_MB", 2048)),  # 0 = no limit
    # Machine-readable outputs (SIEM / SOC): JSON Lines file and alert webhook
    "jsonl_path": os.getenv("JSONL_PATH", ""),
    "webhook_url": os.getenv("WEBHOOK_URL", ""),
    "webhook_secret": os.getenv("WEBHOOK_SECRET", ""),
    "webhook_min_verdict": os.getenv("WEBHOOK_MIN_VERDICT", "High"),
    # Signed rule packs: base64 Ed25519 public keys allowed to sign them (comma-separated)
    "rulepack_public_keys": [k for k in os.getenv("RULEPACK_PUBLIC_KEYS", "").split(",") if k.strip()],
    "data_dir": str(DATA_DIR),
    # Known-good files: one SHA-256 per line, optional "# note" after it
    "allowlist_path": os.getenv("ALLOWLIST_PATH", str(DATA_DIR / "allowlist.txt")),
    "fuzzy_signature_db": os.getenv("FUZZY_SIGNATURE_DB", str(DATA_DIR / "fuzzy_signatures.json")),
    "fuzzy_max_bytes": 20 * 1024 * 1024,   # don't fuzzy-hash files larger than this

    # --- YARA ---------------------------------------------------------------
    "yara_rules_dir": os.getenv("YARA_RULES_DIR", str(BUNDLED_RULES_DIR)),

    # --- VirusTotal ---------------------------------------------------------
    "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
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
    "cache_db_path": str(DATA_DIR / "scan_cache.sqlite3"),
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
    "ml_model_path": os.getenv("ML_MODEL_PATH", str(DATA_DIR / "ml_model.joblib")),

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
    "auto_quarantine": os.getenv("AUTO_QUARANTINE", "").strip().lower(),

    # --- Mailbox (IMAP) scanning -------------------------------------------
    # Read-only, TLS only. Use an app password. Empty host = off.
    "imap_host": os.getenv("IMAP_HOST", ""),
    "imap_port": int(_env_float("IMAP_PORT", 993)),
    "imap_starttls": _env_bool("IMAP_STARTTLS", False),
    "imap_user": os.getenv("IMAP_USER", ""),
    "imap_password": os.getenv("IMAP_PASSWORD", ""),
    "imap_folder": os.getenv("IMAP_FOLDER", "INBOX"),
    "imap_since_days": int(_env_float("IMAP_SINCE_DAYS", 7)),
    "imap_max_messages": int(_env_float("IMAP_MAX_MESSAGES", 200)),
    "imap_max_mb": _env_float("IMAP_MAX_MB", 25),
    "imap_state_path": str(DATA_DIR / "imap_state.json"),
    "imap_check_minutes": int(_env_float("IMAP_CHECK_MINUTES", 0)),   # background mode; 0 = off

    # --- Canary tripwires ---------------------------------------------------
    "canary_registry": str(DATA_DIR / "canaries.json"),
    "canary_check_minutes": int(_env_float("CANARY_CHECK_MINUTES", 5)),
    # On a NEW trigger: "" (alert only, default) or any of "network_off,script"
    "canary_response": os.getenv("CANARY_RESPONSE", ""),
    "canary_response_script": os.getenv("CANARY_RESPONSE_SCRIPT", ""),
    "canary_contain_mode": os.getenv("CANARY_CONTAIN_MODE", "suspend"),   # or "terminate"
    "canary_contain_exclude": os.getenv("CANARY_CONTAIN_EXCLUDE", ""),    # extra process names
    "canary_lock_dirs": os.getenv("CANARY_LOCK_DIRS", ""),                # default: canary folders
    "containment_state_file": str(DATA_DIR / "containment_state.json"),

    "report_directory": str(REPORT_DIR),
    "scan_interval_hours": 6,  # Scan every 6 hours
}

VERDICT_RANK = {"Clean": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
