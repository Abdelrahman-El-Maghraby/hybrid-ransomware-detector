#!/usr/bin/env python3
"""
Hybrid Ransomware Detection System - cross-platform scanner for documents.

This script scans documents (PDF, Word, Excel, PowerPoint, RTF) and ZIP
archives for ransomware / malicious behaviour by fusing independent detection
layers through a transparent weighted scoring matrix:

  1. Cryptographic hashes (MD5 + SHA-256) checked against a local malware dataset
  2. Fuzzy / similarity hashing (TLSH + ssdeep) to catch polymorphic *families*
  3. Static VBA/XLM macro analysis (olevba), incl. VBA-stomping detection
  4. YARA pattern matching against a rules directory (structural IOCs)
  5. File-integrity heuristics: disguised executables, format mismatches, and
     encrypted-content detection (evidence that ransomware already ran)
  6. Hidden-content + prompt-injection detection (protects the LLM layer)
  7. Office external relationships: remote template injection, Follina-style
     OLE links, exploit URI schemes, NTLM-leaking UNC paths
  8. Safe ZIP inspection: zip bombs, zip slip, executables and lure names;
     every member goes through the full pipeline
  9. VirusTotal multi-engine reputation (hash lookup; uploads are opt-in)
 10. LLM semantic analysis - LOCAL model (Ollama) by default for OPSEC, with
     nonce-spotlighted prompts; optional cloud (OpenAI) fallback

Host-side protection (core/): ransomware canary tripwires, an AES-256-GCM
encrypted quarantine vault, and a result cache so scheduled re-scans don't
re-query VirusTotal/LLM for unchanged files.

Every optional layer degrades gracefully when its dependency or API key is
missing, so the core local checks always run. This tool is for DEFENSIVE and
educational use - analysing suspect documents, never executing or creating
malware. No macro or payload is ever run.
"""

import os
import re
import sys
import time
import json
import hashlib
import logging
from dotenv import load_dotenv
import schedule
import argparse
import platform
import subprocess
import shutil
try:
    import winreg  # Windows registry module (Windows only)
except ImportError:
    winreg = None  # Non-Windows: autostart features are disabled gracefully
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pdf2image import convert_from_path
import pytesseract
# For handling Word and PDF files
import docx
import PyPDF2

# Modular detection engines (each degrades gracefully if its dependency is
# missing). Importing the package never raises on absent third-party libs.
from detectors import (
    FuzzyHasher, FUZZY_AVAILABLE,
    MacroAnalyzer, OLEVBA_AVAILABLE,
    YaraEngine, YARA_AVAILABLE,
    build_llm_backend,
    ScoringMatrix,
    FileIntegrityAnalyzer,
    PromptGuard, DEFUSEDXML_AVAILABLE,
    RelationshipScanner,
    ContainerExtractor,
    MailAnalyzer, MSG_AVAILABLE,
    MLClassifier, SKLEARN_AVAILABLE,
    ransom_indicator,
)
from detectors.relationship_scanner import defang
from core import (
    ResultCache, CanaryManager, build_session, RateLimiter,
    QUARANTINE_AVAILABLE, QuarantineError, QuarantineVault,
)
from core.canary import desktop_notify

ENGINE_VERSION = "4.1.0"

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
SCRIPT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
BUNDLED_RULES_DIR = SCRIPT_DIR / "rules"
BUNDLED_FUZZY_SIGS = SCRIPT_DIR / "fuzzy_signatures.sample.json"

# Create application directories if they don't exist
APP_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# For handling CSV database
import csv  # noqa: E402

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
                        ".xls", ".pptx", ".pptm", ".ppt", ".rtf", ".zip", ".eml", ".msg"]

# Configuration - paths derive from the user's home directory and adapt to the OS
CONFIG = {
    "scan_directories": [
        str(USER_HOME / "Downloads"),
        # Add more folders to scan as needed
    ],
    "file_extensions": list(SUPPORTED_EXTENSIONS),
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

    # --- Quarantine ---------------------------------------------------------
    "quarantine_dir": str(QUARANTINE_DIR),
    "keystore_dir": str(KEYSTORE_DIR),
    # "" (off, default) | "critical" | "high": quarantine files at/above this
    # verdict automatically after they are scanned.
    "auto_quarantine": os.getenv("AUTO_QUARANTINE", "").strip().lower(),

    # --- Canary tripwires ---------------------------------------------------
    "canary_registry": str(DATA_DIR / "canaries.json"),
    "canary_check_minutes": int(_env_float("CANARY_CHECK_MINUTES", 5)),

    "report_directory": str(REPORT_DIR),
    "scan_interval_hours": 6,  # Scan every 6 hours
}

VERDICT_RANK = {"Clean": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{5,}")


def extract_suspicious_strings(file_path: str, min_len: int = 5, chunk_size: int = 1024 * 1024,
                               max_bytes: int = 32 * 1024 * 1024,
                               max_chars: int = 200_000) -> str:
    """Extract human-readable ASCII strings from a file using memory-efficient chunked reads.

    Bounded on both input (max_bytes read) and output (max_chars returned), and
    regex-based so a large file no longer costs a Python-level loop per byte.
    """
    pattern = _PRINTABLE_RUN if min_len == 5 else re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    strings: List[str] = []
    total_chars = 0
    carry = b""
    read = 0
    try:
        with open(file_path, "rb") as f:
            while read < max_bytes and total_chars < max_chars:
                chunk = f.read(min(chunk_size, max_bytes - read))
                if not chunk:
                    break
                read += len(chunk)
                data = carry + chunk
                # Keep a trailing printable run for the next chunk so strings
                # that straddle a chunk boundary are not split.
                tail = re.search(rb"[\x20-\x7e]*$", data)
                cut = tail.start() if tail else len(data)
                if len(data) - cut > 65536:     # one giant run (plain text): flush it
                    cut = len(data)
                carry, data = data[cut:], data[:cut]
                for m in pattern.finditer(data):
                    s = m.group().decode("ascii")
                    strings.append(s)
                    total_chars += len(s) + 1
                    if total_chars >= max_chars:
                        break
            if carry and len(carry) >= min_len and total_chars < max_chars:
                strings.append(carry.decode("ascii"))
    except Exception as e:
        logger.error(f"Error extracting strings from {file_path}: {str(e)}")
    return "\n".join(strings)[:max_chars]


class RansomwareScanner:
    """Main scanner class: multi-layer analysis of documents and ZIP archives."""

    def __init__(self, config: Dict):
        """Initialize the scanner with configuration settings."""
        self.config = config
        self.scan_dirs = config["scan_directories"]  # Already expanded
        self.file_extensions = config["file_extensions"]
        self.kaggle_db_path = config["kaggle_database_path"]
        self.report_dir = config["report_directory"]

        # Ensure reports directory exists
        os.makedirs(self.report_dir, exist_ok=True)

        # Load Kaggle database
        self.hash_database = self._load_kaggle_database()

        # --- Initialise the modular detection engines -----------------------
        # Fuzzy hashing: prefer a per-user signature DB, else the bundled sample.
        fuzzy_db = config.get("fuzzy_signature_db")
        if not (fuzzy_db and os.path.exists(fuzzy_db)) and BUNDLED_FUZZY_SIGS.exists():
            fuzzy_db = str(BUNDLED_FUZZY_SIGS)
        self.fuzzy_hasher = FuzzyHasher(signature_db_path=fuzzy_db)
        self.fuzzy_max_bytes = int(config.get("fuzzy_max_bytes", 20 * 1024 * 1024))

        # Static macro analysis (olevba).
        self.macro_analyzer = MacroAnalyzer()

        # YARA engine over the configured rules directory.
        self.yara_engine = YaraEngine(rules_dir=config.get("yara_rules_dir"))

        # LLM backend (local Ollama by default; cloud OpenAI optional).
        self.llm_backend = build_llm_backend(config)

        # v4 layers.
        self.integrity = FileIntegrityAnalyzer()
        self.prompt_guard = PromptGuard()
        self.relationship_scanner = RelationshipScanner()
        self.container_extractor = ContainerExtractor(
            max_depth=int(config.get("archive_max_depth", 3)),
            max_total_bytes=int(float(config.get("archive_max_total_mb", 100)) * 1024 * 1024),
            max_members=int(config.get("archive_max_members", 500)),
        )
        self.archive_scan_members = int(config.get("archive_scan_members", 25))
        self.max_nesting = int(config.get("max_nesting", 2))

        # v4.1 layers.
        self.mail_analyzer = MailAnalyzer(
            max_attachments=int(config.get("mail_max_attachments", 50)),
            max_total_bytes=int(float(config.get("archive_max_total_mb", 100)) * 1024 * 1024),
        )
        self.mail_scan_attachments = int(config.get("mail_scan_attachments", 25))
        self.ml: Optional[MLClassifier] = (
            MLClassifier(config.get("ml_model_path")) if config.get("ml_enabled", True) else None)

        # Weighted scoring matrix that fuses every layer's signals.
        self.scoring = ScoringMatrix()

        # External calls: shared session (timeouts + retry/backoff), VT pacing,
        # and a SHA-256-keyed cache so re-scans don't burn the API quota.
        self.http = build_session()
        self.http_timeout = int(config.get("http_timeout", 30))
        self.vt_limiter = RateLimiter(float(config.get("virustotal_requests_per_minute", 4)))
        self.cache: Optional[ResultCache] = None
        if config.get("cache_enabled", True) and config.get("cache_db_path"):
            self.cache = ResultCache(config["cache_db_path"],
                                     float(config.get("cache_ttl_hours", 24)) * 3600)

        # Host-side protection.
        self.canaries = CanaryManager(config.get("canary_registry",
                                                 str(DATA_DIR / "canaries.json")))
        self._vault: Optional[QuarantineVault] = None
        self._last_canary_signature: Optional[tuple] = None
        self.last_impact: Optional[Dict] = None

        logger.info(f"Scanner initialized (engine v{ENGINE_VERSION}). "
                    f"Monitoring directories: {self.scan_dirs}")
        logger.info(
            "Detection layers -> fuzzy:%s  macro:%s  yara:%s(%d rule files)  "
            "integrity:on  prompt-guard:%s  relationships:%s  archives:on  "
            "mail:%s  ml:%s  llm:%s%s  virustotal:%s  cache:%s",
            "on" if FUZZY_AVAILABLE else "off (install python-tlsh/ppdeep)",
            "on" if OLEVBA_AVAILABLE else "off (install oletools)",
            "on" if YARA_AVAILABLE else "off (install yara-python)",
            getattr(self.yara_engine, "_rules_count", 0),
            "on" if DEFUSEDXML_AVAILABLE else "partial (install defusedxml)",
            "on" if DEFUSEDXML_AVAILABLE else "rtf-only (install defusedxml)",
            "on" if MSG_AVAILABLE else "eml-only (install oletools)",
            ("off" if self.ml is None else
             f"model ({self.ml.model_name})" if self.ml.has_model else "rules"),
            self.llm_backend.name,
            " [LOCAL]" if getattr(self.llm_backend, "is_local", False) else
            (" [CLOUD]" if self.llm_backend.name == "openai" else ""),
            "on" if config.get("virustotal_api_key") else "off (no API key)",
            "on" if (self.cache and self.cache.enabled) else "off",
        )

    # ------------------------------------------------------------------ setup
    @property
    def quarantine_vault(self) -> QuarantineVault:
        """The encrypted quarantine vault (created on first use)."""
        if self._vault is None:
            if not QUARANTINE_AVAILABLE:
                raise QuarantineError("Quarantine needs the 'cryptography' package: "
                                      "pip install cryptography")
            self._vault = QuarantineVault(self.config.get("quarantine_dir", str(QUARANTINE_DIR)),
                                          self.config.get("keystore_dir", str(KEYSTORE_DIR)))
        return self._vault

    def _load_kaggle_database(self) -> set:
        """Load malicious MD5 hashes into a memory-efficient set (streaming CSV, no pandas)."""
        malicious_hashes = set()
        try:
            if not os.path.exists(self.kaggle_db_path):
                logger.warning(f"Malware database not found at {self.kaggle_db_path}. "
                               f"Expected columns: FileName, md5Hash, Benign.")
                return malicious_hashes

            logger.info(f"Loading malware database from {self.kaggle_db_path}")
            with open(self.kaggle_db_path, mode="r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # A row is malicious when the 'Benign' flag is false/0/no
                    benign_value = str(row.get("Benign", "")).strip().lower()
                    is_malicious = benign_value in ["0", "false", "no", "n"]
                    if is_malicious:
                        md5 = row.get("md5Hash")
                        if md5:
                            malicious_hashes.add(md5.strip().lower())

            logger.info(f"Loaded {len(malicious_hashes)} malicious hashes into memory.")
            return malicious_hashes
        except Exception as e:
            logger.error(f"Error loading malware database: {str(e)}")
            return set()

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5 and SHA-256 using memory-efficient chunked reads.

        MD5 is kept for the local dataset lookup; SHA-256 is the modern
        identifier used for VirusTotal, the result cache, and as the canonical
        file hash.
        """
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(64 * 1024), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            return {"md5": md5_hash.hexdigest(), "sha256": sha256_hash.hexdigest()}
        except Exception as e:
            logger.error(f"Error calculating hashes for {file_path}: {str(e)}")
            return {"md5": "", "sha256": ""}

    def check_hash_in_database(self, file_hash: str) -> Tuple[bool, Dict]:
        """Check whether an MD5 hash is present in the local malicious-hash set."""
        if file_hash and file_hash.lower() in self.hash_database:
            return True, {"reason": "Identified as malicious in local hash database"}
        return False, {}

    # -------------------------------------------------------------------- LLM
    def _llm_cache_layer(self) -> str:
        backend = self.llm_backend
        return f"llm:{getattr(backend, 'name', 'none')}:{getattr(backend, 'model', '')}"

    def analyze_with_llm(self, file_path: str, file_content: Optional[str] = None,
                         embedded_strings: Optional[str] = None,
                         sha256: Optional[str] = None) -> Dict:
        """Send document content + embedded strings to the configured LLM backend.

        The backend is chosen once at init (local Ollama by default for OPSEC,
        cloud OpenAI optional). Prompt-injection hardening lives in the backend:
        analyst instructions in the system role, untrusted file content in the
        user role wrapped in per-request nonce delimiters, temperature 0,
        JSON-only output. Answers are cached by SHA-256 when one is given.
        """
        try:
            if not getattr(self.llm_backend, "available", True):
                return self.llm_backend.analyze("")       # uniform "skipped" result

            cache_layer = self._llm_cache_layer()
            if sha256 and self.cache is not None:
                cached = self.cache.get(sha256, cache_layer)
                if cached is not None:
                    cached["cached"] = True
                    return cached

            # Extract visible content (and strings: code/keywords/shell hints)
            if file_content is None:
                file_content = self._extract_text_from_file(file_path)
            if embedded_strings is None:
                embedded_strings = extract_suspicious_strings(file_path)

            # Skip empty results before spending an LLM call
            if not file_content.strip() and not embedded_strings.strip():
                logger.warning(f"No content or strings extracted from {file_path}. Skipping LLM analysis.")
                return {
                    "is_malicious": False,
                    "confidence": 0,
                    "details": "No content or strings to analyze.",
                    "suspicious_elements": []
                }

            # Combine both (truncated to keep the prompt bounded)
            combined = (
                "Visible Document Content:\n"
                f"{file_content[:3000]}\n\n"
                "Extracted Embedded Strings:\n"
                f"{embedded_strings[:2000]}"
            )

            result = self.llm_backend.analyze(combined)
            if sha256 and self.cache is not None and result.get("analyzed"):
                self.cache.put(sha256, cache_layer, result)
            return result
        except Exception as e:
            logger.error(f"Error in LLM analysis for {file_path}: {str(e)}")
            return {
                "is_malicious": False,
                "confidence": 0,
                "details": "LLM analysis failed.",
                "suspicious_elements": []
            }

    # Backward-compatible alias: older callers / docs reference analyze_with_chatgpt.
    def analyze_with_chatgpt(self, file_path: str) -> Dict:
        return self.analyze_with_llm(file_path)

    # ------------------------------------------------------- text extraction
    def _extract_text_from_file(self, file_path: str, allow_ocr: bool = True) -> str:
        """Extract readable text from a PDF or Office document ('' if none)."""
        file_ext = os.path.splitext(file_path)[1].lower()

        try:
            if file_ext == ".pdf":
                text = self._extract_text_from_pdf(file_path)
                if not text.strip() and allow_ocr:
                    logger.info(f"No text found in PDF. Using OCR fallback for {file_path}")
                    text = self._extract_text_with_ocr_from_pdf(file_path)
                return text
            elif file_ext == ".docx":
                return self._extract_text_from_word(file_path) or \
                    self._extract_text_from_ooxml(file_path)
            elif file_ext in (".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                return self._extract_text_from_ooxml(file_path)
            else:
                return ""     # legacy binary formats: the strings pass covers them
        except Exception as e:
            logger.error(f"Error extracting text from {file_path}: {str(e)}")
            return ""

    def _extract_text_from_pdf(self, file_path: str) -> str:
        """Extract text from a PDF file."""
        text = ""
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file, strict=False)
                for page in pdf_reader.pages[:200]:
                    text += (page.extract_text() or "") + "\n"
            return text
        except Exception as e:
            logger.warning(f"Could not extract PDF text from {file_path}: {e}")
            return ""

    def _extract_text_with_ocr_from_pdf(self, file_path: str) -> str:
        """Extract text from a PDF file using OCR if it is image-based."""
        try:
            images = convert_from_path(file_path, last_page=20)
            text = ""
            for img in images:
                text += pytesseract.image_to_string(img)
            return text
        except Exception as e:
            logger.error(f"OCR failed for PDF {file_path}: {str(e)}")
            return ""

    def _extract_text_from_word(self, file_path: str) -> str:
        """Extract text from a Word document."""
        try:
            doc = docx.Document(file_path)
            return "\n".join([paragraph.text for paragraph in doc.paragraphs])
        except Exception as e:
            logger.debug(f"python-docx could not read {file_path}: {e}")
            return ""

    @staticmethod
    def _extract_text_from_ooxml(file_path: str, max_chars: int = 200_000) -> str:
        """Text from any OOXML file (Word/Excel/PowerPoint, incl. macro-enabled),
        read straight from the XML parts with defusedxml."""
        if not DEFUSEDXML_AVAILABLE:
            return ""
        import zipfile
        import defusedxml.ElementTree as DET
        part_re = re.compile(r"(word/(document|header\d*|footer\d*)\.xml"
                             r"|xl/sharedStrings\.xml|ppt/slides/slide\d+\.xml)$")
        chunks: List[str] = []
        total = 0
        try:
            with zipfile.ZipFile(file_path) as zf:
                for info in zf.infolist():
                    if not part_re.match(info.filename) or info.file_size > 20 * 1024 * 1024:
                        continue
                    root = DET.fromstring(zf.read(info))
                    for el in root.iter():
                        tag = str(el.tag)
                        if (tag.endswith("}t") or tag == "t") and el.text:
                            chunks.append(el.text)
                            total += len(el.text) + 1
                            if total > max_chars:
                                return " ".join(chunks)[:max_chars]
        except Exception as e:
            logger.debug(f"OOXML text extraction failed for {file_path}: {e}")
        return " ".join(chunks)

    # -------------------------------------------------------------- VirusTotal
    def _vt_empty(self, **extra) -> Dict:
        result = {"is_malicious": False, "detection_ratio": 0, "malicious_detections": 0,
                  "suspicious_detections": 0, "total_engines": 0, "permalink": ""}
        result.update(extra)
        return result

    def scan_file_with_virustotal(self, file_path: str, hashes: Optional[Dict] = None) -> Dict:
        """Look the file up on VirusTotal by SHA-256 (upload only if opted in).

        Results are cached per SHA-256 (24 h for verdicts, 6 h for "unknown"),
        requests are paced to the API quota, and every call has a timeout.
        """
        if not self.config.get("virustotal_api_key"):
            return self._vt_empty(details="VirusTotal API key not configured; "
                                          "reputation layer skipped.")
        try:
            # VirusTotal identifies files primarily by SHA-256
            hashes = hashes or self.calculate_hashes(file_path)
            file_hash = hashes["sha256"] or hashes["md5"]

            if self.cache is not None:
                cached = self.cache.get(file_hash, "virustotal")
                if cached is not None:
                    cached["cached"] = True
                    return cached

            headers = {"x-apikey": self.config["virustotal_api_key"]}
            check_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            self.vt_limiter.wait()
            response = self.http.get(check_url, headers=headers, timeout=self.http_timeout)

            if response.status_code == 404:
                if not self.config.get("virustotal_upload_unknown"):
                    result = self._vt_empty(
                        not_found=True,
                        details="Hash unknown to VirusTotal. Upload is disabled for privacy "
                                "(set VT_UPLOAD_UNKNOWN=true to submit unknown files).")
                    if self.cache is not None:
                        self.cache.put(file_hash, "virustotal", result, ttl_seconds=6 * 3600)
                    return result
                response = self._vt_upload_and_wait(file_path, headers, check_url) or response

            # Process VirusTotal results
            if response.status_code == 200:
                attributes = response.json().get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                # Calculate detection ratio
                total_engines = sum(v for v in stats.values() if isinstance(v, int))
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                detection_ratio = (malicious + suspicious) / total_engines if total_engines > 0 else 0

                result = {
                    "is_malicious": (malicious + suspicious) > 0,
                    "detection_ratio": detection_ratio,
                    "malicious_detections": malicious,
                    "suspicious_detections": suspicious,
                    "total_engines": total_engines,
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}/detection"
                }
                if self.cache is not None and total_engines:
                    self.cache.put(file_hash, "virustotal", result)
                return result
            if response.status_code == 404:
                return self._vt_empty(not_found=True,
                                      details="Hash unknown to VirusTotal; upload did not complete.")
            logger.error(f"VirusTotal API error: {response.status_code} - {response.text[:200]}")
            return self._vt_empty(error=f"API Error: {response.status_code}")

        except Exception as e:
            logger.error(f"Error in VirusTotal scan for {file_path}: {str(e)}")
            return self._vt_empty(error=str(e))

    def _vt_upload_and_wait(self, file_path: str, headers: Dict, check_url: str):
        """Opt-in upload of an unknown file; returns the final file report response."""
        logger.info(f"File {file_path} not found in VirusTotal. Uploading (VT_UPLOAD_UNKNOWN=true)...")
        # VirusTotal: files < 32 MB use the standard /files endpoint;
        # larger files require a dedicated one-time upload URL.
        file_size = os.path.getsize(file_path)
        upload_url = "https://www.virustotal.com/api/v3/files"
        if file_size >= 32 * 1024 * 1024:
            logger.info("File >= 32 MB; requesting a dedicated upload URL...")
            self.vt_limiter.wait()
            r = self.http.get("https://www.virustotal.com/api/v3/files/upload_url",
                              headers=headers, timeout=self.http_timeout)
            if r.status_code != 200:
                logger.error(f"Error getting VirusTotal upload URL: {r.status_code}")
                return None
            upload_url = r.json().get("data", "")
        self.vt_limiter.wait()
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            upload = self.http.post(upload_url, headers=headers, files=files,
                                    timeout=max(120, self.http_timeout))
        if upload.status_code != 200:
            logger.error(f"Error uploading file to VirusTotal: {upload.status_code}")
            return None
        analysis_id = upload.json().get("data", {}).get("id", "")
        logger.info(f"File uploaded to VirusTotal. Analysis ID: {analysis_id}. Waiting for results...")
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _attempt in range(10):
            time.sleep(15)  # Wait between status checks
            self.vt_limiter.wait()
            status_resp = self.http.get(analysis_url, headers=headers, timeout=self.http_timeout)
            if status_resp.status_code == 200 and status_resp.json().get("data", {}) \
                    .get("attributes", {}).get("status") == "completed":
                self.vt_limiter.wait()
                return self.http.get(check_url, headers=headers, timeout=self.http_timeout)
        return None

    # ------------------------------------------------------------- scanning
    def scan_file(self, file_path: str, _depth: int = 0,
                  _display_name: Optional[str] = None) -> Dict:
        """Scan a single file for ransomware indicators using all available layers.

        `_depth` / `_display_name` are used internally when scanning the
        members of an archive (e.g. "invoice.zip!/payload.docm").
        """
        display = _display_name or file_path
        logger.info(f"Scanning file: {display}")

        file_size = os.path.getsize(file_path)
        # Initialize result structure
        result = {
            "file_path": display,
            "file_name": os.path.basename(display.replace("!/", "/")),
            "file_size": file_size,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "engine_version": ENGINE_VERSION,
            "is_malicious": False,
            "scan_results": {}
        }

        # 1. Cryptographic hashes (chunked / memory-efficient)
        hashes = self.calculate_hashes(file_path)
        file_hash = hashes["md5"]
        result["md5_hash"] = hashes["md5"]
        result["sha256_hash"] = hashes["sha256"]

        # 2. Fuzzy / similarity hashing (polymorphic family detection)
        if file_size <= self.fuzzy_max_bytes:
            fuzzy = self.fuzzy_hasher.analyze_file(file_path)
        else:
            from detectors.fuzzy_hash import FuzzyResult
            fuzzy = FuzzyResult(available=FUZZY_AVAILABLE,
                                detail=f"Skipped: file exceeds fuzzy_max_bytes "
                                       f"({self.fuzzy_max_bytes} bytes).")
        result["scan_results"]["fuzzy_hash"] = fuzzy.as_dict()

        # 3. Local cryptographic-hash database lookup (exact known-bad)
        is_known_malicious, malware_info = self.check_hash_in_database(file_hash)
        result["scan_results"]["local_database"] = {
            "is_malicious": is_known_malicious,
            "details": malware_info if is_known_malicious else "Not found in local database"
        }

        # 4. Static VBA/XLM macro analysis (Office dropper mechanism)
        macro = self.macro_analyzer.analyze_file(file_path)
        result["scan_results"]["macro_analysis"] = macro.as_dict()

        # 5. YARA pattern matching (structural IOCs)
        yara_res = self.yara_engine.scan_file(file_path)
        result["scan_results"]["yara"] = yara_res.as_dict()

        # 6. File integrity: disguised executables / encrypted content
        integrity = self.integrity.analyze_file(file_path)
        result["scan_results"]["file_integrity"] = integrity.as_dict()

        # 7. Hidden content + prompt-injection attempts (text extracted once
        #    and shared with the LLM layer)
        is_archive = self.container_extractor.is_container(file_path)
        is_mail = self.mail_analyzer.is_mail(file_path)
        llm_on = getattr(self.llm_backend, "available", True)

        # 6b. E-mail: judge the envelope, unpack + scan every attachment. The
        #     message body becomes the text the prompt-guard / LLM layers read.
        mail_signals: Dict = {}
        mail_body = ""
        if is_mail:
            mail_signals, mail_body = self._scan_mail(file_path, display, _depth, result)

        if is_archive:
            text = ""
        elif is_mail:
            text = mail_body
        else:
            text = self._extract_text_from_file(file_path, allow_ocr=llm_on)
        strings = "" if is_archive else extract_suspicious_strings(file_path)
        hidden = self.prompt_guard.inspect_hidden_content(file_path)
        guard = self.prompt_guard.analyze(text, strings, hidden)
        result["scan_results"]["prompt_guard"] = guard.as_dict()

        # 8. Office external relationships (remote template / Follina / UNC)
        rels = self.relationship_scanner.scan_file(file_path)
        result["scan_results"]["relationships"] = rels.as_dict()

        # 9. Archives: unpack safely and run every member through this pipeline
        archive_signals: Dict = {}
        if is_archive:
            archive_signals = self._scan_archive(file_path, display, _depth, result)

        # 9b. Static ML classifier over the byte structure (containers are
        #     judged through their members instead)
        ml_signals: Dict = {}
        if self.ml is not None and not (is_archive or is_mail):
            ml_res = self.ml.classify(file_path)
            result["scan_results"]["ml_classifier"] = ml_res.as_dict()
            ml_signals = {"suspicious": ml_res.suspicious, "probability": ml_res.probability,
                          "model": ml_res.model, "indicators": ml_res.indicators}

        # 10. LLM semantic analysis (local-first for OPSEC; cached by SHA-256)
        if is_archive:
            llm_result = {"is_malicious": False, "confidence": 0, "suspicious_elements": [],
                          "details": "Archive: members are analysed individually; "
                                     "LLM layer skipped for the container."}
        else:
            llm_result = self.analyze_with_llm(file_path, text, strings,
                                               sha256=hashes["sha256"])
        result["scan_results"]["chatgpt_analysis"] = llm_result  # legacy key name kept

        # 11. VirusTotal multi-engine reputation (hash lookup; cached)
        virustotal_result = self.scan_file_with_virustotal(file_path, hashes)
        result["scan_results"]["virustotal"] = virustotal_result

        # 12. Fuse every signal through the weighted scoring matrix
        signals = {
            "local_db_hit": is_known_malicious,
            "fuzzy": {
                "matched": fuzzy.matched,
                "best_confidence": fuzzy.best_confidence,
                "families": sorted({m.family for m in fuzzy.matches}),
            },
            "macro": {
                "has_macros": macro.has_macros,
                "autoexec": macro.autoexec,
                "critical": macro.critical,
                "suspicious": macro.suspicious,
                "vba_stomping": macro.vba_stomping,
                "xlm_macros": macro.xlm_macros,
            },
            "yara": {
                "matched": yara_res.matched,
                "top_severity": yara_res.top_severity or "medium",
                "rules": sorted({m.rule for m in yara_res.matches}),
            },
            "virustotal": {
                "malicious": virustotal_result.get("malicious_detections", 0),
                "suspicious": virustotal_result.get("suspicious_detections", 0),
                "total": virustotal_result.get("total_engines", 0),
                "ratio": virustotal_result.get("detection_ratio", 0),
            },
            "llm": {
                "is_suspicious": llm_result.get("is_malicious", False),
                "confidence": llm_result.get("confidence", 0),
                "elements": llm_result.get("suspicious_elements", []),
            },
            "integrity": {
                "disguised_executable": integrity.disguised_executable,
                "encrypted_likely": integrity.encrypted_likely,
                "format_mismatch": integrity.format_mismatch,
                "detail": integrity.detail,
            },
            "prompt_guard": {
                "injection_status": guard.injection_status,
                "indicators": guard.injection_indicators,
                "hidden_text_found": guard.hidden_text_found,
                "hidden_reasons": guard.hidden_reasons,
            },
            "relationships": {
                "kinds": rels.kinds,
                "targets": [defang(f.target) for f in rels.findings[:3]],
            },
            "archive": archive_signals,
            "mail": mail_signals,
            "ml": ml_signals,
        }
        score = self.scoring.score(signals)

        result["is_malicious"] = score.is_malicious
        result["severity_score"] = score.severity_score   # legacy 0-10 (DB hit => 10.0)
        result["risk_score"] = score.risk_score            # 0-100
        result["verdict"] = score.verdict                  # Clean|Low|Medium|High|Critical
        result["score_breakdown"] = score.as_dict()        # full evidence trail

        logger.info(
            "Scan completed for %s. Verdict: %s (risk %d/100, severity %.1f/10).",
            display, result["verdict"], result["risk_score"], result["severity_score"],
        )
        return result

    def _scan_archive(self, file_path: str, display: str, depth: int, result: Dict) -> Dict:
        """Unpack an archive into a sandbox, scan its members, return signals."""
        member_results: List[Dict] = []
        with self.container_extractor.open(file_path) as arc:
            skipped_for_budget = 0
            if depth < self.max_nesting:
                for member in arc.members:
                    if not member.extracted or not member.path:
                        continue
                    if member.path.lower().endswith(".zip"):
                        continue       # nested archives are already expanded
                    if len(member_results) >= self.archive_scan_members:
                        skipped_for_budget += 1
                        continue
                    try:
                        member_results.append(self.scan_file(
                            member.path, _depth=depth + 1,
                            _display_name=member.name.replace(
                                os.path.basename(file_path) + "!", display + "!", 1)))
                    except Exception as e:
                        logger.error(f"Error scanning archive member {member.name}: {e}")
            arc_dict = arc.as_dict()

        arc_dict["deep_scanned"] = len(member_results)
        arc_dict["not_scanned_budget"] = skipped_for_budget
        summaries = [self._member_summary(r) for r in member_results]
        # Archive-level findings about a member (lure names, executables) are
        # attached to that member so it is never shown as plainly "Clean".
        flag_sources = (("double_extension", "double_extension_members"),
                        ("rtlo_spoof", "rtlo_members"), ("executable", "executable_members"))
        for summary in summaries:
            inner = str(summary.get("name", "")).split("!/", 1)[-1]
            summary["archive_flags"] = [
                flag for flag, key in flag_sources
                if any(str(n).split("!/", 1)[-1] == inner for n in arc_dict.get(key, []))]
        arc_dict["member_results"] = summaries
        result["scan_results"]["archive"] = arc_dict

        worst = max(member_results, key=lambda r: r.get("risk_score", 0), default=None)
        signals = {
            "zip_slip": arc_dict["zip_slip"],
            "zip_bomb": arc_dict["zip_bomb"],
            "encrypted_unreadable": arc_dict["encrypted_unreadable"],
            "executable_members": arc_dict["executable_members"],
            "double_extension_members": arc_dict["double_extension_members"],
            "rtlo_members": arc_dict["rtlo_members"],
            "reasons": {"zip_slip": arc_dict["zip_slip_reason"],
                        "zip_bomb": arc_dict["zip_bomb_reason"]},
        }
        if worst and worst.get("risk_score", 0) > 0:
            signals["worst_member"] = {
                "name": worst.get("file_name", "member"),
                "contributions": worst.get("score_breakdown", {}).get("contributions", []),
            }
        return signals

    def _scan_mail(self, file_path: str, display: str, depth: int,
                   result: Dict) -> Tuple[Dict, str]:
        """Analyse an e-mail, scan its attachments, return (signals, body text)."""
        attachment_results: List[Dict] = []
        skipped_for_budget = 0
        with self.mail_analyzer.open(file_path) as mail:
            if depth < self.max_nesting:
                for att in mail.attachments:
                    if not att.path:
                        continue
                    if len(attachment_results) >= self.mail_scan_attachments:
                        skipped_for_budget += 1
                        continue
                    try:
                        attachment_results.append(self.scan_file(
                            att.path, _depth=depth + 1,
                            _display_name=f"{display}!/{att.filename}"))
                    except Exception as e:
                        logger.error(f"Error scanning attachment {att.filename}: {e}")
            mail_dict = mail.as_dict()
            body = mail.body_text

        mail_dict["deep_scanned"] = len(attachment_results)
        mail_dict["not_scanned_budget"] = skipped_for_budget
        mail_dict["attachment_results"] = [self._member_summary(r) for r in attachment_results]
        result["scan_results"]["mail"] = mail_dict

        signals = {
            "from_domain": mail_dict["from_domain"],
            "reply_to_domain": mail_dict["reply_to_domain"],
            "auth_failures": mail_dict["auth"]["failures"],
            "display_name_spoof": mail_dict["display_name_spoof"],
            "display_name_spoof_reason": mail_dict["display_name_spoof_reason"],
            "reply_to_mismatch": mail_dict["reply_to_mismatch"],
            "deceptive_links": mail_dict["deceptive_links"],
            "executable_attachments": mail_dict["executable_attachments"],
            "double_extension_attachments": mail_dict["double_extension_attachments"],
            "rtlo_attachments": mail_dict["rtlo_attachments"],
            "lure_subject": mail_dict["lure_subject"],
        }
        worst = max(attachment_results, key=lambda r: r.get("risk_score", 0), default=None)
        if worst and worst.get("risk_score", 0) > 0:
            signals["worst_attachment"] = {
                "name": worst.get("file_name", "attachment"),
                "contributions": worst.get("score_breakdown", {}).get("contributions", []),
            }
        return signals, body

    @staticmethod
    def _member_summary(r: Dict) -> Dict:
        contributions = r.get("score_breakdown", {}).get("contributions", []) or []
        return {
            "name": r.get("file_path"),
            "verdict": r.get("verdict", "Clean"),
            "risk_score": r.get("risk_score", 0),
            "md5_hash": r.get("md5_hash", ""),
            "sha256_hash": r.get("sha256_hash", ""),
            "indicators": [c.get("indicator") for c in contributions][:8],
        }

    # ------------------------------------------------------- directory walks
    @staticmethod
    def _new_impact(directories: List[str]) -> Dict:
        return {"directories": list(directories), "ransom_note_count": 0, "ransom_notes": [],
                "ransom_extension_count": 0, "ransom_extension_files": []}

    def _collect_target_files(self, directory: str, impact: Optional[Dict] = None) -> List[str]:
        """Walk a directory tree and return every file matching the configured extensions.

        While walking, every file *name* is also checked for ransomware impact
        indicators (ransom notes, ransomware extensions) - no content is read.
        Canary files and Office lock files (~$*) are never returned as targets.
        """
        targets = []
        exts = tuple(ext.lower() for ext in self.file_extensions)
        canary_paths = self.canaries.paths()
        try:
            for root, _, files in os.walk(directory):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    if impact is not None:
                        kind = ransom_indicator(filename)
                        if kind:
                            key = "ransom_note" if kind == "ransom_note" else "ransom_extension"
                            impact[f"{key}_count"] += 1
                            bucket = impact["ransom_notes" if key == "ransom_note"
                                            else "ransom_extension_files"]
                            if len(bucket) < 50:
                                bucket.append(full_path)
                    if filename.startswith("~$") or not filename.lower().endswith(exts):
                        continue
                    if os.path.normcase(os.path.abspath(full_path)) in canary_paths:
                        continue
                    targets.append(full_path)
        except Exception as e:
            logger.error(f"Error walking directory {directory}: {str(e)}")
        return targets

    def _scan_targets(self, targets: List[str], progress_callback=None,
                      cancel_event=None) -> List[Dict]:
        """Scan a list of files, optionally reporting progress and honouring cancellation.

        progress_callback: optional callable(done, total, file_path, result) invoked
            after each file completes. Used by the GUI; CLI callers pass nothing.
        cancel_event: optional threading.Event-like object. When set, the scan stops
            cleanly after the file currently being scanned (a file mid-scan is never
            left half-analysed).
        """
        results = []
        total = len(targets)
        for index, file_path in enumerate(targets, start=1):
            if cancel_event is not None and cancel_event.is_set():
                logger.info(f"Scan cancelled by user after {len(results)}/{total} files.")
                break
            try:
                result = self.scan_file(file_path)
                self._maybe_auto_quarantine(result)
                results.append(result)
            except Exception as e:
                logger.error(f"Error scanning file {file_path}: {str(e)}")
                continue
            if progress_callback is not None:
                try:
                    progress_callback(index, total, file_path, result)
                except Exception as e:
                    logger.error(f"Progress callback error: {str(e)}")
        return results

    def scan_directory(self, directory: str, progress_callback=None,
                       cancel_event=None) -> List[Dict]:
        """Scan all supported files in a directory for ransomware indicators."""
        impact = self._new_impact([directory])
        targets = self._collect_target_files(directory, impact)
        self.last_impact = impact
        return self._scan_targets(targets, progress_callback, cancel_event)

    def scan_all_directories(self, progress_callback=None,
                             cancel_event=None) -> List[Dict]:
        """Scan all configured directories for ransomware indicators."""
        targets = []
        impact = self._new_impact(list(self.scan_dirs))

        for directory in self.scan_dirs:
            if os.path.exists(directory):
                logger.info(f"Scanning directory: {directory}")
                targets.extend(self._collect_target_files(directory, impact))
            else:
                logger.warning(f"Directory does not exist: {directory}")

        self.last_impact = impact
        return self._scan_targets(targets, progress_callback, cancel_event)

    # ------------------------------------------------------------ quarantine
    def quarantine_file(self, file_path: str, reason: str = "",
                        result: Optional[Dict] = None) -> Dict:
        """Move a file into the encrypted quarantine vault (verify-before-delete)."""
        extra = {}
        if result:
            extra = {k: result.get(k) for k in ("verdict", "risk_score", "sha256_hash")}
        return self.quarantine_vault.quarantine(file_path, reason=reason, extra=extra)

    def _maybe_auto_quarantine(self, result: Dict) -> None:
        threshold = VERDICT_RANK.get(str(self.config.get("auto_quarantine") or "").capitalize())
        if not threshold or VERDICT_RANK.get(result.get("verdict", "Clean"), 0) < threshold:
            return
        try:
            meta = self.quarantine_file(
                result["file_path"],
                reason=f"auto-quarantine: {result.get('verdict')} "
                       f"(risk {result.get('risk_score')}/100)",
                result=result)
            result["quarantine"] = {"id": meta["id"], "vault_file": meta["vault_file"],
                                    "original_removed": meta["original_removed"]}
        except Exception as e:
            logger.error(f"Auto-quarantine failed for {result.get('file_path')}: {e}")
            result["quarantine"] = {"error": str(e)}

    # --------------------------------------------------------------- canaries
    def deploy_canaries(self, directories: Optional[List[str]] = None) -> List[Dict]:
        return self.canaries.deploy(directories or self.scan_dirs)

    def remove_canaries(self) -> int:
        return self.canaries.remove()

    def check_canaries(self, notify: bool = True):
        """Verify every canary. On a NEW trigger: write an alert file next to the
        reports and raise a desktop notification (repeat findings stay quiet)."""
        report = self.canaries.verify()
        if not report.triggered:
            self._last_canary_signature = None
            return report
        signature = tuple(sorted((f.path, f.status) for f in report.findings))
        if signature != self._last_canary_signature:
            self._last_canary_signature = signature
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            alert = Path(self.report_dir) / f"canary_alert_{stamp}.txt"
            lines = ["RANSOMWARE CANARY TRIPWIRE", "=" * 26,
                     f"Time:    {report.checked_at}", f"Summary: {report.summary()}", ""]
            lines += [f"[{f.status}] {f.path}\n    {f.evidence}" for f in report.findings]
            lines += ["", "Recommended: disconnect this machine from the network, do not "
                          "reboot, and investigate running processes."]
            try:
                alert.write_text("\n".join(lines) + "\n", encoding="utf-8")
            except OSError as e:
                logger.error(f"Could not write canary alert file: {e}")
            if notify:
                desktop_notify("Ransomware tripwire triggered", report.summary())
        return report

    # ---------------------------------------------------------------- reports
    def generate_report(self, results: List[Dict], impact: Optional[Dict] = None,
                        canary_report=None) -> str:
        """Generate a comprehensive report based on scan results.

        The report reflects the multi-layer engine: files are grouped by
        verdict band (Critical -> High -> Medium -> Low), and each flagged file
        lists the concrete evidence from every layer plus the weighted score
        breakdown that explains *why* it scored what it did. Optional sections
        summarise ransomware-impact indicators seen while walking folders and
        the state of the canary tripwires.

        Backward compatibility: the JSON report is still the full list of result
        dicts, and the legacy fields (md5_hash, severity_score) are still shown.
        """
        if not results:
            return "No files scanned."

        # Create a timestamp for the report file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.report_dir, f"ransomware_scan_{timestamp}.json")

        # Write detailed JSON report (full evidence trail, unchanged shape)
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=4)

        total_files = len(results)
        flagged = [r for r in results if r.get("is_malicious")]
        malicious_files = len(flagged)

        # Group flagged files by verdict band, most severe first.
        band_order = ["Critical", "High", "Medium", "Low"]
        grouped: Dict[str, List[Dict]] = {b: [] for b in band_order}
        for r in flagged:
            verdict = r.get("verdict", "Low")
            grouped.setdefault(verdict, []).append(r)

        # Highest verdict reached across the whole scan (for the summary line).
        worst = "Clean"
        for b in band_order:
            if grouped.get(b):
                worst = b
                break

        report_text = f"""
Ransomware Scan Report
======================
Timestamp:              {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Engine version:         {ENGINE_VERSION}
Total files scanned:    {total_files}
Files flagged:          {malicious_files}
Highest verdict:        {worst}
Detection layers used:  {self._active_layers_label()}
LLM posture:            {self._llm_posture_label()}
"""
        if canary_report is not None:
            report_text += f"Canary tripwires:       {canary_report.summary()}\n"

        report_text += self._impact_section(results, impact)
        if canary_report is not None and canary_report.triggered:
            report_text += f"\n{'!' * 60}\nCANARY TRIPWIRE TRIGGERED\n{'!' * 60}\n"
            for f in canary_report.findings:
                report_text += f"  [{f.status}] {f.path}\n      {f.evidence}\n"

        if malicious_files == 0:
            report_text += "\nNo suspicious files detected.\n"
        else:
            # Quick band breakdown line, e.g. "Critical: 1 | High: 2 | Medium: 0"
            breakdown = " | ".join(
                f"{b}: {len(grouped.get(b, []))}" for b in band_order
            )
            report_text += f"\nVerdict breakdown:  {breakdown}\n"

            for band in band_order:
                bucket = grouped.get(band, [])
                if not bucket:
                    continue
                report_text += f"\n{'=' * 60}\n{band.upper()} ({len(bucket)})\n{'=' * 60}\n"
                # Sort within a band by risk score, highest first.
                for result in sorted(
                    bucket, key=lambda r: r.get("risk_score", 0), reverse=True
                ):
                    report_text += self._format_file_finding(result)

        report_text += f"\nDetailed JSON report saved to: {report_file}\n"

        # Also save the text report
        text_report_file = os.path.join(self.report_dir, f"ransomware_scan_{timestamp}.txt")
        with open(text_report_file, 'w') as f:
            f.write(report_text)

        return report_text

    @staticmethod
    def _impact_section(results: List[Dict], impact: Optional[Dict]) -> str:
        """Folder-level ransomware-impact summary (empty string if nothing seen)."""
        encrypted = [r.get("file_path") for r in results
                     if r.get("scan_results", {}).get("file_integrity", {}).get("encrypted_likely")]
        notes = (impact or {}).get("ransom_notes", [])
        note_count = (impact or {}).get("ransom_note_count", 0)
        ext_files = (impact or {}).get("ransom_extension_files", [])
        ext_count = (impact or {}).get("ransom_extension_count", 0)
        if not (encrypted or note_count or ext_count):
            return ""
        strong = note_count >= 1 or ext_count >= 3 or len(encrypted) >= 2
        out = f"\n{'#' * 60}\n"
        out += ("POSSIBLE ACTIVE RANSOMWARE IMPACT - investigate this machine now\n"
                if strong else "Ransomware impact indicators (weak signal)\n")
        out += f"{'#' * 60}\n"
        if encrypted:
            out += f"  Files whose content looks encrypted: {len(encrypted)}\n"
            out += "".join(f"    - {p}\n" for p in encrypted[:10])
        if note_count:
            out += f"  Ransom-note-like files: {note_count}\n"
            out += "".join(f"    - {p}\n" for p in notes[:10])
        if ext_count:
            out += f"  Files with known ransomware extensions: {ext_count}\n"
            out += "".join(f"    - {p}\n" for p in ext_files[:10])
        return out

    def _format_file_finding(self, result: Dict) -> str:
        """Render one flagged file's evidence block for the text report."""
        sr = result.get("scan_results", {})
        lines = [
            f"\n- File:     {result.get('file_path')}",
            f"  Verdict:  {result.get('verdict', 'n/a')} "
            f"(risk {result.get('risk_score', 0)}/100, "
            f"severity {result.get('severity_score', 0)}/10)",
            f"  MD5:      {result.get('md5_hash', 'n/a')}",
        ]

        # Local hash DB (exact known-bad)
        local_db = sr.get("local_database", {})
        if local_db.get("is_malicious"):
            lines.append("  [Local DB]  Exact hash match against known-bad database.")

        # Fuzzy / structural similarity
        fuzzy = sr.get("fuzzy_hash", {})
        if fuzzy.get("matched"):
            fams = sorted({m.get("family", "") for m in fuzzy.get("matches", [])
                           if m.get("family")}) or ["known family"]
            conf = fuzzy.get("best_confidence", 0) or 0
            lines.append(
                f"  [Fuzzy]     Structural similarity to {', '.join(fams)} "
                f"(confidence {conf:.2f})."
            )

        # Macro analysis (Office dropper mechanism)
        macro = sr.get("macro_analysis", {})
        if macro.get("has_macros"):
            autoexec = macro.get("autoexec", []) or []
            critical = macro.get("critical", []) or []
            suspicious = macro.get("suspicious", []) or []
            if autoexec:
                lines.append(f"  [Macro]     Auto-run trigger(s): {', '.join(autoexec)}.")
            if critical:
                lines.append(
                    f"  [Macro]     Execution/download primitive(s): "
                    f"{', '.join(critical)}."
                )
            elif suspicious:
                lines.append(
                    f"  [Macro]     Suspicious call(s): "
                    f"{', '.join(suspicious[:6])}."
                )
            if autoexec and critical:
                lines.append(
                    "  [Macro]     -> Auto-exec + exec primitive = classic "
                    "dropper pattern."
                )
            if macro.get("vba_stomping"):
                lines.append("  [Macro]     VBA STOMPING: compiled P-code differs from the "
                             "visible source.")
            if macro.get("xlm_macros"):
                lines.append("  [Macro]     Excel 4.0 (XLM) macro sheet(s): "
                             f"{', '.join((macro.get('xlm_evidence') or [])[:3])}.")

        # YARA structural IOCs
        yara_res = sr.get("yara", {})
        if yara_res.get("matched"):
            rule_names = sorted({m.get("rule", "") for m in yara_res.get("matches", [])
                                 if m.get("rule")})
            rules = ", ".join(rule_names) if rule_names else "(unnamed)"
            lines.append(
                f"  [YARA]      Rule(s) matched [{rules}] "
                f"(top severity '{yara_res.get('top_severity', 'medium')}')."
            )

        # File integrity (disguise / encryption)
        integ = sr.get("file_integrity", {})
        if integ.get("disguised_executable") or integ.get("encrypted_likely") \
                or integ.get("format_mismatch"):
            lines.append(f"  [Integrity] {integ.get('detail', '')}")

        # Hidden content / prompt injection
        guard = sr.get("prompt_guard", {})
        if guard.get("hidden_text_found"):
            lines.append(f"  [Hidden]    Concealed content: "
                         f"{', '.join(guard.get('hidden_reasons', []) or [])}.")
        if guard.get("injection_status") in ("confirmed", "suspicious"):
            lines.append(f"  [Injection] {guard['injection_status']} prompt-injection attempt: "
                         f"{', '.join(guard.get('injection_indicators', []) or [])}.")

        # Office external relationships
        rels = sr.get("relationships", {})
        for f in (rels.get("findings") or [])[:3]:
            lines.append(f"  [External]  {f.get('kind')} -> {defang(str(f.get('target', '')))}")

        # Archive contents
        arc = sr.get("archive", {})
        if arc:
            lines.append(f"  [Archive]   {arc.get('detail', '')}")
            shown = set()
            for label, key in (("double extension", "double_extension_members"),
                               ("RTLO spoof", "rtlo_members"),
                               ("executable", "executable_members")):
                for name in [n for n in (arc.get(key) or []) if n not in shown][:3]:
                    shown.add(name)
                    lines.append(f"              ! {label}: {name}")
            for m in arc.get("member_results", []) or []:
                if m.get("verdict", "Clean") != "Clean":
                    lines.append(f"              - {m.get('name')}: {m.get('verdict')} "
                                 f"(risk {m.get('risk_score', 0)}/100)")

        # E-mail envelope + attachments
        mail = sr.get("mail", {})
        if mail:
            lines.append(f"  [Mail]      {mail.get('detail', '')}")
            if mail.get("subject"):
                lines.append(f"              Subject: {mail['subject'][:120]}")
            for link in (mail.get("deceptive_links") or [])[:3]:
                lines.append(f"              ! deceptive link: {defang(link)}")
            for a in mail.get("attachment_results", []) or []:
                if a.get("verdict", "Clean") != "Clean":
                    lines.append(f"              - {a.get('name')}: {a.get('verdict')} "
                                 f"(risk {a.get('risk_score', 0)}/100)")

        # ML classifier
        ml = sr.get("ml_classifier", {})
        if ml.get("label") == "suspicious":
            lines.append(f"  [ML]        {ml.get('model')} p={ml.get('probability', 0):.2f}: "
                         f"{'; '.join((ml.get('indicators') or [])[:3])}")

        # VirusTotal reputation
        vt = sr.get("virustotal", {})
        if vt.get("is_malicious"):
            lines.append(
                f"  [VT]        {vt.get('malicious_detections', 0)} malicious / "
                f"{vt.get('total_engines', 0)} engines."
            )
            if vt.get("permalink"):
                lines.append(f"              {vt.get('permalink')}")

        # LLM semantic opinion (capped low by the scoring matrix)
        llm = sr.get("chatgpt_analysis", {})
        if llm.get("is_malicious"):
            lines.append(
                f"  [Semantic]  LLM flagged the text "
                f"(confidence {llm.get('confidence', 0):.2f})."
            )
            elems = llm.get("suspicious_elements", []) or []
            if elems:
                lines.append(f"              Elements: {', '.join(map(str, elems))}.")

        quarantine = result.get("quarantine") or {}
        if quarantine.get("id"):
            lines.append(f"  [Quarantine] Moved to the encrypted vault (id {quarantine['id']}).")
        elif quarantine.get("error"):
            lines.append(f"  [Quarantine] FAILED: {quarantine['error']}")

        # Weighted score breakdown (the "why")
        breakdown = result.get("score_breakdown", {})
        contribs = breakdown.get("contributions", []) or []
        if contribs:
            lines.append("  Score breakdown:")
            for c in contribs:
                lines.append(
                    f"    + {c.get('points', 0):>5.1f}  "
                    f"[{c.get('category', '?')}] {c.get('indicator', '?')}"
                )
            totals = breakdown.get("category_totals", {})
            if totals:
                totals_str = ", ".join(
                    f"{k}={v}" for k, v in totals.items() if v
                )
                if totals_str:
                    lines.append(f"    = category totals: {totals_str}")

        lines.append("")
        return "\n".join(lines)

    def _active_layers_label(self) -> str:
        """Human-readable list of which optional detection layers are active."""
        layers = ["hashes", "local-db"]
        if FUZZY_AVAILABLE:
            layers.append("fuzzy")
        if OLEVBA_AVAILABLE:
            layers.append("macro")
        if YARA_AVAILABLE:
            layers.append("yara")
        layers += ["integrity", "prompt-guard", "relationships", "archives", "mail"]
        if getattr(self, "ml", None) is not None:
            layers.append("ml")
        layers.append("llm")
        layers.append("virustotal")
        return ", ".join(layers)

    def _llm_posture_label(self) -> str:
        """Describe whether the active LLM backend keeps data local or sends it out."""
        backend = getattr(self, "llm_backend", None)
        if backend is None:
            return "none"
        name = backend.__class__.__name__
        if "Ollama" in name:
            return f"LOCAL ({getattr(backend, 'model', 'ollama')})"
        if "OpenAI" in name:
            return "CLOUD (OpenAI - documents leave the machine)"
        return "disabled"

    def run_scan(self) -> str:
        """Run a complete scan (canary check + all directories) and generate a report."""
        logger.info("Starting scheduled ransomware scan...")
        canary_report = self.check_canaries() if self.canaries.entries() else None
        results = self.scan_all_directories()
        report = self.generate_report(results, impact=self.last_impact,
                                      canary_report=canary_report)
        logger.info("Scan complete.")
        return report

# ---------------------------------------------------------------------------
# Cross-platform autostart  (run the scanner automatically at login/startup)
# ---------------------------------------------------------------------------

AUTOSTART_LABEL = "com.abdelrahman.ransomwarescanner"   # macOS launchd label
AUTOSTART_NAME = "RansomwareScanner"                     # Windows registry value
SYSTEMD_UNIT = "ransomware-scanner.service"             # Linux systemd unit
CRON_MARKER = "# RansomwareScanner autostart"           # Linux/macOS cron marker


def _resolve_python_and_script() -> Tuple[str, str]:
    """Return (program, script) used to relaunch the scanner.

    From source that is the interpreter plus this file. In a PyInstaller build
    the executable *is* the program, so the script part is empty.
    """
    if FROZEN:
        return sys.executable, ""
    python_exe = sys.executable or "python3"
    script_path = str(Path(__file__).resolve())
    return python_exe, script_path


def _q(script_path: str) -> str:
    """' "script"' when running from source, '' for a frozen executable."""
    return f' "{script_path}"' if script_path else ""


def setup_windows_autostart() -> bool:
    """Register the scanner to run at login via the Windows registry (HKCU\\...\\Run)."""
    if winreg is None or os.name != "nt":
        print("ℹ️  Windows autostart is only available on Windows.")
        return False
    try:
        python_exe, script_path = _resolve_python_and_script()
        pythonw = python_exe.replace("python.exe", "pythonw.exe")  # no console window
        command = f'"{pythonw}"{_q(script_path)} --background'
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, AUTOSTART_NAME, 0, winreg.REG_SZ, command)
        logger.info("Added scanner to Windows startup registry.")
        print("✅ Configured to run at Windows login.")
        return True
    except Exception as e:
        logger.error(f"Windows autostart failed: {e}")
        print(f"❌ Windows autostart failed: {e}")
        return False


def setup_macos_autostart() -> bool:
    """Install a launchd LaunchAgent so the scanner runs at login on macOS."""
    try:
        python_exe, script_path = _resolve_python_and_script()
        agents_dir = Path.home() / "Library" / "LaunchAgents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        plist_path = agents_dir / f"{AUTOSTART_LABEL}.plist"
        script_line = f"\n        <string>{script_path}</string>" if script_path else ""
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{AUTOSTART_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_exe}</string>{script_line}
        <string>--background</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>{LOG_FILE}</string>
</dict>
</plist>
"""
        plist_path.write_text(plist)
        # Reload the agent (unload first in case it already exists)
        subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True, text=True)
        result = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, text=True)
        if result.returncode != 0 and result.stderr.strip():
            logger.warning(f"launchctl load reported: {result.stderr.strip()}")
        logger.info(f"Installed launchd agent at {plist_path}")
        print(f"✅ Configured to run at macOS login (launchd agent: {plist_path}).")
        return True
    except Exception as e:
        logger.error(f"macOS autostart failed: {e}")
        print(f"❌ macOS autostart failed: {e}")
        return False


def _setup_systemd_autostart(python_exe: str, script_path: str) -> bool:
    """Install a systemd *user* service (preferred on modern Linux)."""
    if not shutil.which("systemctl"):
        return False
    try:
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / SYSTEMD_UNIT
        unit = f"""[Unit]
Description=Hybrid Ransomware Detection System (background scanner)
After=network-online.target

[Service]
Type=simple
ExecStart="{python_exe}"{_q(script_path)} --background
Restart=on-failure

[Install]
WantedBy=default.target
"""
        unit_path.write_text(unit)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True)
        result = subprocess.run(
            ["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT],
            capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning(f"systemctl enable reported: {result.stderr.strip()}")
        logger.info(f"Installed systemd user unit at {unit_path}")
        print(f"✅ Configured to run at Linux login (systemd user unit: {unit_path}).")
        print("   Tip: run 'loginctl enable-linger $USER' to keep it running without an active session.")
        return True
    except Exception as e:
        logger.error(f"systemd autostart failed: {e}")
        return False


def _setup_cron_autostart(python_exe: str, script_path: str) -> bool:
    """Fallback: add a @reboot crontab entry (Linux/macOS without systemd)."""
    if not shutil.which("crontab"):
        return False
    try:
        cron_line = f'@reboot "{python_exe}"{_q(script_path)} --background  {CRON_MARKER}'
        existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        current = existing.stdout if existing.returncode == 0 else ""
        if CRON_MARKER in current:
            print("ℹ️  Cron autostart entry already present.")
            return True
        sep = "\n" if current and not current.endswith("\n") else ""
        new_crontab = current + sep + cron_line + "\n"
        proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)
        if proc.returncode != 0:
            logger.error(f"crontab update failed: {proc.stderr.strip()}")
            return False
        logger.info("Added @reboot crontab entry.")
        print("✅ Configured to run at startup via cron (@reboot).")
        return True
    except Exception as e:
        logger.error(f"cron autostart failed: {e}")
        return False


def setup_linux_autostart() -> bool:
    """Configure Linux autostart: systemd user service, falling back to cron."""
    python_exe, script_path = _resolve_python_and_script()
    if _setup_systemd_autostart(python_exe, script_path):
        return True
    print("ℹ️  systemd user service unavailable; falling back to cron.")
    if _setup_cron_autostart(python_exe, script_path):
        return True
    print("❌ Could not configure Linux autostart (neither systemd nor cron available).")
    return False


def setup_autostart() -> bool:
    """Dispatch to the correct autostart implementation for the current OS."""
    system = platform.system()
    if system == "Windows":
        return setup_windows_autostart()
    if system == "Darwin":
        return setup_macos_autostart()
    if system == "Linux":
        return setup_linux_autostart()
    print(f"ℹ️  Autostart is not supported on this platform: {system}")
    return False


def remove_autostart() -> bool:
    """Remove any autostart entry this scanner created on the current OS."""
    system = platform.system()
    try:
        if system == "Windows":
            if winreg is None:
                return False
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
                try:
                    winreg.DeleteValue(key, AUTOSTART_NAME)
                except FileNotFoundError:
                    pass
            print("✅ Removed Windows autostart entry (if it existed).")
            return True

        if system == "Darwin":
            plist_path = Path.home() / "Library" / "LaunchAgents" / f"{AUTOSTART_LABEL}.plist"
            if plist_path.exists():
                subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True, text=True)
                plist_path.unlink()
                print(f"✅ Removed macOS launchd agent: {plist_path}")
            else:
                print("ℹ️  No macOS launchd agent found.")
            return True

        if system == "Linux":
            removed = False
            unit_path = Path.home() / ".config" / "systemd" / "user" / SYSTEMD_UNIT
            if unit_path.exists() and shutil.which("systemctl"):
                subprocess.run(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT],
                               capture_output=True, text=True)
                unit_path.unlink()
                subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True)
                removed = True
            if shutil.which("crontab"):
                existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                if existing.returncode == 0 and CRON_MARKER in existing.stdout:
                    filtered = "\n".join(l for l in existing.stdout.splitlines() if CRON_MARKER not in l)
                    filtered = (filtered + "\n") if filtered.strip() else ""
                    subprocess.run(["crontab", "-"], input=filtered, text=True, capture_output=True)
                    removed = True
            print("✅ Removed Linux autostart entry." if removed else "ℹ️  No Linux autostart entry found.")
            return True
    except Exception as e:
        logger.error(f"Failed to remove autostart: {e}")
        print(f"❌ Failed to remove autostart: {e}")
        return False
    print(f"ℹ️  Autostart removal is not supported on this platform: {system}")
    return False


def create_desktop_shortcut() -> bool:
    """Create a desktop shortcut/launcher (Windows .lnk or Linux .desktop)."""
    system = platform.system()
    python_exe, script_path = _resolve_python_and_script()

    if system == "Windows":
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            desktop = shell.SpecialFolders("Desktop")
            shortcut_path = os.path.join(desktop, "Ransomware Scanner.lnk")
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.TargetPath = python_exe
            shortcut.Arguments = f'{_q(script_path).strip()} --scan-now'.strip()
            shortcut.WorkingDirectory = os.path.dirname(script_path or python_exe)
            shortcut.IconLocation = python_exe + ",0"
            shortcut.Description = "Run Ransomware Scanner"
            shortcut.Save()
            print(f"✅ Created desktop shortcut: {shortcut_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to create shortcut: {e}")
            print("Note: install pywin32 for shortcut support:  pip install pywin32")
            return False

    if system == "Linux":
        try:
            desktop_dir = Path.home() / "Desktop"
            desktop_dir.mkdir(parents=True, exist_ok=True)
            launcher = desktop_dir / "ransomware-scanner.desktop"
            launcher.write_text(
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=Ransomware Scanner\n"
                f'Exec="{python_exe}"{_q(script_path)} --scan-now\n'
                "Terminal=true\n"
                "Categories=Utility;Security;\n"
            )
            launcher.chmod(0o755)
            print(f"✅ Created desktop launcher: {launcher}")
            return True
        except Exception as e:
            print(f"❌ Failed to create launcher: {e}")
            return False

    print("ℹ️  Desktop shortcuts are supported on Windows and Linux only.")
    return False


def import_hash_database(source_path: str, destination_path: str = None) -> Dict:
    """Copy a malware-hash CSV into the app data directory and validate its format.

    Shared by the CLI (--import-database) and the GUI so both use one code path.
    Returns a dict:
        ok               True when the copy succeeded and all required columns exist
        error_kind       None | "missing_source" | "exception"
        message          human-readable status
        destination      final path of the database
        entries          number of data rows found
        missing_columns  required columns absent from the header
    """
    destination_path = destination_path or CONFIG["kaggle_database_path"]
    outcome = {"ok": False, "error_kind": None, "message": "",
               "destination": destination_path, "entries": 0, "missing_columns": []}

    if not os.path.exists(source_path):
        outcome["error_kind"] = "missing_source"
        outcome["message"] = f"Cannot find database file at {source_path}"
        return outcome

    try:
        shutil.copy2(source_path, destination_path)

        with open(destination_path, mode="r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            outcome["entries"] = sum(1 for _ in reader)

        required_columns = ['FileName', 'md5Hash', 'Benign']
        outcome["missing_columns"] = [col for col in required_columns if col not in header]
        outcome["ok"] = not outcome["missing_columns"]
        outcome["message"] = (
            f"Database format validated. Found {outcome['entries']} entries."
            if outcome["ok"]
            else f"Missing required columns: {', '.join(outcome['missing_columns'])}"
        )
        logger.info(f"Hash database imported from {source_path} -> {destination_path} "
                    f"({outcome['entries']} entries)")
        return outcome
    except Exception as e:
        outcome["error_kind"] = "exception"
        outcome["message"] = str(e)
        logger.error(f"Error importing database: {e}")
        return outcome


def _print_fuzzy_hash(path: str) -> None:
    """Print a file's fuzzy digests so the user can add them to a signature DB.

    This is the intended workflow for growing `fuzzy_signatures.json`: run this
    against a confirmed-malicious sample, then paste the TLSH (and/or ssdeep)
    value into a signature entry with the family name. Matching is then done by
    structural similarity, so polymorphic variants of that family are caught
    without an exact hash.
    """
    if not os.path.exists(path):
        print(f"Error: file not found: {path}")
        return
    if not FUZZY_AVAILABLE:
        print("Fuzzy hashing libraries are not installed.")
        print("Install them with:  pip install python-tlsh ppdeep")
        return

    hasher = FuzzyHasher()
    digests = hasher.hash_file(path)
    print(f"File:   {path}")
    print(f"Size:   {os.path.getsize(path)} bytes")
    print(f"TLSH:   {digests.get('tlsh') or '(unavailable - input too small/uniform)'}")
    print(f"ssdeep: {digests.get('ssdeep') or '(unavailable)'}")
    print()
    print("Add to your fuzzy_signatures.json like:")
    print(json.dumps({
        "family": "Example.Family.Name",
        "tlsh": digests.get("tlsh") or "",
        "ssdeep": digests.get("ssdeep") or "",
        "note": "describe the sample / source here"
    }, indent=2))


def _print_quarantine_list(scanner: "RansomwareScanner") -> None:
    items = scanner.quarantine_vault.list()
    if not items:
        print("The quarantine vault is empty.")
        return
    print(f"{len(items)} item(s) in {scanner.config.get('quarantine_dir')}:")
    for item in items:
        extra = item.get("extra") or {}
        verdict = f"  [{extra.get('verdict')}]" if extra.get("verdict") else ""
        print(f"  {item.get('id')}  {item.get('quarantined_at', '?')}  "
              f"{item.get('original_path', '?')}{verdict}")
        if item.get("reason"):
            print(f"      reason: {item['reason']}")


def _train_ml_cli(benign_dir: str, malicious_dir: str, out_path: str) -> int:
    """--train-ml: fit the RandomForest on two folders and report honest metrics."""
    from detectors.ml_classifier import collect_files
    for d in (benign_dir, malicious_dir):
        if not Path(d).is_dir():
            print(f"❌ Not a directory: {d}")
            return 2
    if not SKLEARN_AVAILABLE:
        print("❌ Training needs scikit-learn and joblib:  pip install -r requirements-ml.txt")
        return 2
    benign, malicious = collect_files(benign_dir), collect_files(malicious_dir)
    print(f"Extracting features: {len(benign)} benign, {len(malicious)} malicious file(s)...")
    clf = MLClassifier()
    try:
        metrics = clf.train(benign, malicious)
    except ValueError as e:
        print(f"❌ {e}")
        return 2
    clf.save(out_path)
    c = metrics["confusion"]
    print(f"✅ Model saved to {out_path}")
    print(f"   Held-out set ({metrics['holdout_size']} files): "
          f"accuracy {metrics['accuracy']:.1%}, precision {metrics['precision']:.1%}, "
          f"recall {metrics['recall']:.1%}, false-positive rate "
          f"{metrics['false_positive_rate']:.1%}  (tn={c['tn']} fp={c['fp']} "
          f"fn={c['fn']} tp={c['tp']})")
    top = sorted(clf.model_info["feature_importances"].items(),
                 key=lambda kv: kv[1], reverse=True)[:5]
    print("   Most informative features: " + ", ".join(f"{k} ({v:.2f})" for k, v in top))
    print("   Note: metrics are only as representative as the folders you trained on.")
    return 0


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Cross-platform ransomware & malicious-document scanner "
                    "(PDF, Office, RTF, ZIP)")
    parser.add_argument("--version", action="version",
                        version=f"hybrid-ransomware-detector {ENGINE_VERSION}")
    parser.add_argument("--scan-now", action="store_true",
                        help="Run a scan immediately")
    parser.add_argument("--background", action="store_true",
                        help="Run in the background with scheduled scans and canary checks")
    parser.add_argument("--setup-autostart", action="store_true",
                        help="Run automatically at login/startup (Windows, macOS, or Linux)")
    parser.add_argument("--remove-autostart", action="store_true",
                        help="Remove the autostart entry created on this machine")
    parser.add_argument("--create-shortcut", action="store_true",
                        help="Create a desktop shortcut/launcher (Windows/Linux)")
    parser.add_argument("--import-database",
                        help="Import a malware-hash CSV database from the given path")
    parser.add_argument("--gui", action="store_true",
                        help="Launch the graphical interface")
    parser.add_argument("--scan-file", metavar="PATH",
                        help="Scan a single file and print its full verdict, then exit")
    parser.add_argument("--fuzzy-hash", metavar="PATH",
                        help="Print a file's TLSH and ssdeep digests (use these to "
                             "populate your fuzzy signature DB), then exit")
    parser.add_argument("--llm-provider", choices=["auto", "ollama", "openai", "none"],
                        help="Override the LLM backend for this run. 'auto' (default) "
                             "prefers a reachable local Ollama for OPSEC and only falls "
                             "back to OpenAI if a key is set; 'none' disables the layer.")
    # --- v4: protection features ------------------------------------------
    parser.add_argument("--deploy-canaries", nargs="*", metavar="DIR",
                        help="Plant ransomware canary files in DIR(s) "
                             "(default: the configured scan directories)")
    parser.add_argument("--verify-canaries", action="store_true",
                        help="Check every canary file now (exit code 2 if tripped)")
    parser.add_argument("--remove-canaries", action="store_true",
                        help="Delete all canary files this tool planted")
    parser.add_argument("--quarantine", metavar="PATH",
                        help="Move a file into the encrypted quarantine vault")
    parser.add_argument("--list-quarantine", action="store_true",
                        help="List the items in the quarantine vault")
    parser.add_argument("--restore", metavar="ID",
                        help="Restore a quarantined item (full id or unique prefix)")
    parser.add_argument("--restore-to", metavar="PATH",
                        help="Destination for --restore (default: original location)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Don't use or update the VirusTotal/LLM result cache this run")
    parser.add_argument("--clear-cache", action="store_true",
                        help="Delete all cached VirusTotal/LLM results, then exit")
    parser.add_argument("--train-ml", nargs=2, metavar=("BENIGN_DIR", "MALICIOUS_DIR"),
                        help="Train the ML classifier on two labelled folders and save it "
                             "to ML_MODEL_PATH (needs requirements-ml.txt)")
    parser.add_argument("--ml-model-out", metavar="PATH",
                        help="Where --train-ml saves the model (default: ML_MODEL_PATH)")

    args = parser.parse_args()

    # An explicit --llm-provider overrides config/env for this process.
    if args.llm_provider:
        CONFIG["llm_provider"] = args.llm_provider
    if args.no_cache:
        CONFIG["cache_enabled"] = False

    if args.train_ml:
        sys.exit(_train_ml_cli(args.train_ml[0], args.train_ml[1],
                               args.ml_model_out or CONFIG["ml_model_path"]))

    # --fuzzy-hash is a standalone utility: it needs no DB, no API keys, no banner.
    if args.fuzzy_hash:
        _print_fuzzy_hash(args.fuzzy_hash)
        return

    if args.gui:
        try:
            import gui
        except ImportError as e:
            print("The GUI needs the 'customtkinter' package. Install it with:")
            print("    pip install customtkinter")
            print(f"Details: {e}")
            return
        gui.main()
        return

    utility_mode = (args.background or args.setup_autostart or args.remove_autostart
                    or args.create_shortcut or args.import_database
                    or args.deploy_canaries is not None or args.verify_canaries
                    or args.remove_canaries or args.quarantine or args.list_quarantine
                    or args.restore or args.clear_cache)

    # Display a welcome banner for interactive use
    if not utility_mode:
        print("=" * 56)
        print("  HYBRID RANSOMWARE DETECTION SYSTEM  v" + ENGINE_VERSION)
        print("  Multi-layer document & archive scanner")
        print("=" * 56)
        print(f"Platform:          {platform.system()} ({platform.machine()})")
        print(f"App directory:     {APP_DIR}")
        print(f"Log file:          {LOG_FILE}")
        print(f"Report directory:  {CONFIG['report_directory']}")
        print(f"Database path:     {CONFIG['kaggle_database_path']}")
        print("-" * 56)
        print("Detection layers:")
        print("  Cryptographic hashes ....... enabled")
        print("  Local hash database ........ enabled")
        print(f"  Fuzzy hashing (TLSH/ssdeep)  {'enabled' if FUZZY_AVAILABLE else 'unavailable (pip install python-tlsh ppdeep)'}")
        print(f"  VBA/XLM macro analysis ..... {'enabled' if OLEVBA_AVAILABLE else 'unavailable (pip install oletools)'}")
        print(f"  YARA structural rules ...... {'enabled' if YARA_AVAILABLE else 'unavailable (pip install yara-python)'}")
        print("  File integrity heuristics .. enabled")
        print(f"  Hidden content / injection . {'enabled' if DEFUSEDXML_AVAILABLE else 'PDF only (pip install defusedxml)'}")
        print(f"  Office external links ...... {'enabled' if DEFUSEDXML_AVAILABLE else 'RTF only (pip install defusedxml)'}")
        print("  ZIP archive inspection ..... enabled")
        print(f"  E-mail (.eml/.msg) ......... {'enabled' if MSG_AVAILABLE else '.eml only (pip install oletools)'}")
        _ml_model = Path(CONFIG.get("ml_model_path", ""))
        print("  ML classifier .............. " + (
            "disabled (ML_ENABLED=0)" if not CONFIG.get("ml_enabled", True) else
            f"trained model ({_ml_model.name})" if _ml_model.is_file() and SKLEARN_AVAILABLE
            else "rule engine (no trained model)"))
        print(f"  LLM semantic analysis ...... provider='{CONFIG.get('llm_provider', 'auto')}'")
        print(f"  VirusTotal reputation ...... {'key set' if CONFIG.get('virustotal_api_key') else 'no key (layer skipped)'}")
        print("=" * 56)

    if args.setup_autostart:
        setup_autostart()
        return

    if args.remove_autostart:
        remove_autostart()
        return

    if args.create_shortcut:
        create_desktop_shortcut()
        return

    if args.import_database:
        outcome = import_hash_database(args.import_database)
        if outcome["error_kind"] == "missing_source":
            print(f"Error: Cannot find database file at {args.import_database}")
            return
        if outcome["error_kind"] == "exception":
            print(f"❌ Error importing database: {outcome['message']}")
            return
        print(f"✅ Successfully imported database from {args.import_database}")
        print(f"   Database saved to {outcome['destination']}")
        if outcome["missing_columns"]:
            print(f"⚠️  Missing required columns: {', '.join(outcome['missing_columns'])}")
            print("   The scanner may not work properly without these columns.")
        else:
            print(f"✅ Database format validated. Found {outcome['entries']} entries.")
        return

    # Warn if API keys are not configured (set them in a local .env file)
    if not utility_mode and (not CONFIG["chatgpt_api_key"] or not CONFIG["virustotal_api_key"]):
        print("⚠️  One or more API keys are missing. Copy .env.example to .env and add your keys.")
        print("    The local layers still work; the VirusTotal and cloud-LLM layers need keys.\n")

    scanner = RansomwareScanner(CONFIG)

    # --- protection utilities -------------------------------------------------
    if args.clear_cache:
        removed = scanner.cache.clear() if scanner.cache is not None else 0
        print(f"✅ Cleared {removed} cached result(s).")
        return

    if args.deploy_canaries is not None:
        targets = args.deploy_canaries or scanner.scan_dirs
        created = scanner.deploy_canaries(targets)
        for entry in created:
            print(f"✅ Canary planted: {entry['path']}")
        total = len(scanner.canaries.entries())
        print(f"{len(created)} new canary file(s); {total} registered in total.")
        print("The background mode (--background) checks them every "
              f"{CONFIG['canary_check_minutes']} minute(s).")
        return

    if args.verify_canaries:
        report = scanner.check_canaries(notify=False)
        print(report.summary())
        for f in report.findings:
            print(f"  [{f.status}] {f.path}\n      {f.evidence}")
        sys.exit(2 if report.triggered else 0)

    if args.remove_canaries:
        print(f"✅ Removed {scanner.remove_canaries()} canary file(s).")
        return

    if args.quarantine or args.list_quarantine or args.restore:
        try:
            if args.quarantine:
                meta = scanner.quarantine_file(args.quarantine, reason="manual (CLI)")
                print(f"✅ Quarantined {meta['original_path']}")
                print(f"   vault id: {meta['id']}   (restore with --restore {meta['id']})")
                if not meta["original_removed"]:
                    print("⚠️  The original could not be deleted (file in use?). Delete it manually.")
            if args.restore:
                dest = scanner.quarantine_vault.restore(args.restore, destination=args.restore_to)
                print(f"✅ Restored to {dest}")
            if args.list_quarantine:
                _print_quarantine_list(scanner)
        except QuarantineError as e:
            print(f"❌ {e}")
            sys.exit(1)
        return

    # --scan-file: analyse exactly one file, print its verdict, and exit.
    if args.scan_file:
        if not os.path.exists(args.scan_file):
            print(f"Error: file not found: {args.scan_file}")
            return
        result = scanner.scan_file(args.scan_file)
        print(scanner.generate_report([result]))
        return

    if args.scan_now:
        print("Starting scan. This may take some time depending on the number of files...")
        report = scanner.run_scan()
        print("\n" + "=" * 56)
        print(report)
        print("=" * 56)
        print(f"\nDetailed reports saved to: {CONFIG['report_directory']}")
        if not args.background:
            input("\nPress Enter to exit...")

    if args.background or not args.scan_now:
        if not os.path.exists(CONFIG['kaggle_database_path']):
            print(f"⚠️  Malware-hash database not found at {CONFIG['kaggle_database_path']}")
            print("   Import one with the --import-database option, e.g.:")
            print(f"   python {Path(__file__).name} --import-database /path/to/your/dataset.csv")
            if not args.background:
                input("\nPress Enter to continue anyway...")

        logger.info(f"Scheduling scans every {CONFIG['scan_interval_hours']} hours.")
        schedule.every(CONFIG['scan_interval_hours']).hours.do(scanner.run_scan)
        # Always scheduled: with no canaries deployed the check is a no-op, and
        # canaries deployed later (from the GUI or CLI) are picked up live.
        minutes = max(1, int(CONFIG.get("canary_check_minutes", 5)))
        if scanner.canaries.entries():
            logger.info(f"Canary tripwires armed: checking every {minutes} minute(s).")
        schedule.every(minutes).minutes.do(scanner.check_canaries)

        if not args.scan_now:
            scanner.run_scan()

        try:
            while True:
                schedule.run_pending()
                time.sleep(30)
        except KeyboardInterrupt:
            logger.info("Scanner stopped by user.")


if __name__ == "__main__":
    main()
