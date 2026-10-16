"""
The scanner: wires the detection engines together and runs the pipeline.

`RansomwareScanner.scan_file` runs the ordered layers in engine/layers.py over
one file and scores the result; containers (ZIP, e-mail) send their members
back through `scan_file` (engine/containers.py). Directory walks, quarantine
and canary handling live here; LLM/VirusTotal lookups, text extraction and
report writing come from the mixins in engine/external.py, engine/text.py and
engine/report.py.
"""

import csv
import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core import (
    CanaryManager, QUARANTINE_AVAILABLE, QuarantineError, QuarantineVault,
    RateLimiter, ResultCache, build_session,
)
from core.canary import desktop_notify
from detectors import (
    DEFUSEDXML_AVAILABLE, FUZZY_AVAILABLE, MSG_AVAILABLE, OLEVBA_AVAILABLE, YARA_AVAILABLE,
    ContainerExtractor, FileIntegrityAnalyzer, FuzzyHasher, MacroAnalyzer, MailAnalyzer,
    MLClassifier, PromptGuard, RelationshipScanner, ScoringMatrix, YaraEngine,
    build_llm_backend, ransom_indicator,
)

from .config import (
    BUNDLED_FUZZY_SIGS, DATA_DIR, ENGINE_VERSION, KEYSTORE_DIR, QUARANTINE_DIR, VERDICT_RANK,
)
from .external import ExternalLookupsMixin
from .layers import Layer, ScanContext, default_pipeline
from .report import ReportMixin
from .text import TextExtractionMixin

logger = logging.getLogger("RansomwareScanner")


class RansomwareScanner(ReportMixin, ExternalLookupsMixin, TextExtractionMixin):
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

        # Weighted scoring matrix that fuses every layer's signals, and the
        # ordered list of layers that produce them (engine/layers.py).
        self.scoring = ScoringMatrix()
        self.pipeline: List[Layer] = default_pipeline()

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

    # ------------------------------------------------------------- scanning
    def scan_file(self, file_path: str, _depth: int = 0,
                  _display_name: Optional[str] = None) -> Dict:
        """Scan a single file through every layer of the pipeline and score it.

        `_depth` / `_display_name` are used internally when scanning the
        members of a container (e.g. "invoice.zip!/payload.docm").
        """
        display = _display_name or file_path
        logger.info(f"Scanning file: {display}")
        ctx = ScanContext.start(self, file_path, _depth, display, ENGINE_VERSION)
        for layer in self.pipeline:
            layer.run(self, ctx)

        # Fuse every signal through the weighted scoring matrix
        score = self.scoring.score(ctx.signals)
        result = ctx.result
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

    # ------------------------------------------------------------------ run
    def run_scan(self) -> str:
        """Run a complete scan (canary check + all directories) and generate a report."""
        logger.info("Starting scheduled ransomware scan...")
        canary_report = self.check_canaries() if self.canaries.entries() else None
        results = self.scan_all_directories()
        report = self.generate_report(results, impact=self.last_impact,
                                      canary_report=canary_report)
        logger.info("Scan complete.")
        return report

