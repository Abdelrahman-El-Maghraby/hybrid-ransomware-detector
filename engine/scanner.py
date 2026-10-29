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
import glob
import hashlib
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from core import (
    CanaryManager,
    QuarantineVault,
    RateLimiter,
    ResultCache,
    build_session,
)
from core.allowlist import load_allowlist
from detectors import (
    ContainerExtractor,
    FileIntegrityAnalyzer,
    FuzzyHasher,
    MacroAnalyzer,
    MailAnalyzer,
    MLClassifier,
    PromptGuard,
    RelationshipScanner,
    ScoringMatrix,
    YaraEngine,
    build_llm_backend,
    ransom_indicator,
)
from detectors.elf_analysis import ElfAnalyzer
from detectors.embedded_content import EmbeddedContentAnalyzer
from detectors.pe_analysis import PeAnalyzer
from detectors.qr_scanner import QRScanner
from detectors.script_analysis import ScriptAnalyzer
from detectors.web_content import WebContentAnalyzer

from .capabilities import external_services, layer_states, summary_line
from .config import (
    BUNDLED_FUZZY_SIGS,
    BUNDLED_RULES_DIR,
    DATA_DIR,
    ENGINE_VERSION,
)
from .external import ExternalLookupsMixin
from .layers import Layer, default_pipeline
from .metrics import METRICS
from .protection import ProtectionMixin
from .provenance import scanner_provenance
from .report import ReportMixin
from .staging import StagedPipelineMixin
from .text import TextExtractionMixin

logger = logging.getLogger("RansomwareScanner")


class RansomwareScanner(StagedPipelineMixin, ProtectionMixin, ReportMixin, ExternalLookupsMixin,
                        TextExtractionMixin):
    """The facade every entry point uses: builds the detection engines, walks
    folders and runs scans. Running the pipeline (engine/staging.py), host
    protection (engine/protection.py), reports, external lookups and text
    extraction come from mixins."""

    def __init__(self, config: Dict):
        """Build every detection engine from the configuration."""
        self.config = config
        self.scan_dirs = config["scan_directories"]  # Already expanded
        self.file_extensions = config["file_extensions"]
        self.kaggle_db_path = config["kaggle_database_path"]
        self.report_dir = config["report_directory"]
        os.makedirs(self.report_dir, exist_ok=True)
        self.hash_database = self._load_kaggle_database()

        self._init_signatures(config)
        from core.intel_client import client_from_config
        self.intel = client_from_config(config)      # external services via api/intel.py
        self._init_static_layers(config)
        self._init_optional_layers(config)
        from detectors.registry import load_overrides
        self.scoring = ScoringMatrix(load_overrides(config.get("weights_override")) or None)
        self.pipeline: List[Layer] = default_pipeline()
        self._heavy_pool: Optional[ThreadPoolExecutor] = None
        self._init_external(config)

        # Host-side protection (engine/protection.py).
        self.canaries = CanaryManager(config.get("canary_registry",
                                                 str(DATA_DIR / "canaries.json")))
        self._vault: Optional[QuarantineVault] = None
        self._last_canary_signature: Optional[tuple] = None
        self.last_impact: Optional[Dict] = None
        self._log_layers()
        self._content_lock = threading.Lock()
        self._content_fp = self._content_fingerprint()

    # ------------------------------------------------------------------ setup
    def _init_signatures(self, config: Dict) -> None:
        """Fuzzy signatures and YARA rules: a per-user DB or folder, else an
        installed signed rule pack (core/rulepack.py), else the bundled ones."""
        from core.rulepack import FUZZY_NAME, active_pack
        self.rulepack = active_pack(config.get("data_dir") or DATA_DIR,
                                    config.get("rulepack_public_keys") or [])
        fuzzy_db = config.get("fuzzy_signature_db")
        if (not (fuzzy_db and os.path.exists(fuzzy_db)) and self.rulepack
                and self.rulepack.get("has_fuzzy")):
            fuzzy_db = os.path.join(self.rulepack["path"], FUZZY_NAME)
        if not (fuzzy_db and os.path.exists(fuzzy_db)) and BUNDLED_FUZZY_SIGS.exists():
            fuzzy_db = str(BUNDLED_FUZZY_SIGS)
        self.fuzzy_hasher = FuzzyHasher(signature_db_path=fuzzy_db)
        self.fuzzy_max_bytes = int(config.get("fuzzy_max_bytes", 20 * 1024 * 1024))
        rules_dir = config.get("yara_rules_dir")
        if self.rulepack and (not rules_dir
                              or os.path.abspath(rules_dir) == os.path.abspath(BUNDLED_RULES_DIR)):
            rules_dir = os.path.join(self.rulepack["path"], "rules")
            logger.info("YARA rules from signed rule pack %s.", self.rulepack["version"])
        self.yara_engine = YaraEngine(rules_dir=rules_dir)

    def _content_fingerprint(self) -> Tuple:
        """(path, mtime, size) of everything detection content is loaded from: the
        active rule pack, the YARA rule files, the fuzzy signatures, the allowlist."""
        data_dir = str(self.config.get("data_dir") or DATA_DIR)
        paths = [os.path.join(data_dir, "rulepacks", "active.json")]
        for folder in sorted({str(self.config.get("yara_rules_dir") or ""),
                              str(getattr(self.yara_engine, "rules_dir", "") or "")}):
            if folder and os.path.isdir(folder):
                paths += sorted(glob.glob(os.path.join(folder, "*.yar"))
                                + glob.glob(os.path.join(folder, "*.yara")))
        paths += [str(getattr(self.fuzzy_hasher, "signature_db_path", "") or ""),
                  str(self.config.get("allowlist_path") or "")]
        out: List[Tuple[str, Optional[int], Optional[int]]] = []
        for p in paths:
            try:
                st = os.stat(p)
                out.append((p, st.st_mtime_ns, st.st_size))
            except OSError:
                out.append((p, None, None))
        return tuple(out)

    def refresh_detection_content(self) -> bool:
        """Reload rules, fuzzy signatures and the allowlist when they changed on disk
        (a rule-pack update, an edited rule, --allow from another process), so a
        long-running scanner never scores with content that was replaced. A few
        stat() calls per top-level scan; True when something was reloaded."""
        fingerprint = self._content_fingerprint()
        if fingerprint == self._content_fp:
            return False
        with self._content_lock:
            if self._content_fingerprint() == self._content_fp:
                return False
            self._init_signatures(self.config)
            self.allowlist = load_allowlist(self.config.get("allowlist_path"))
            self._log_layers()                       # new layer states and provenance
            self._content_fp = self._content_fingerprint()
        logger.info("Detection content changed on disk: reloaded (rules %s, sha256 %s).",
                    self.provenance["rules"]["version"] or self.provenance["rules"]["source"],
                    self.provenance["rules"]["sha256"][:16],
                    extra={"event": "content_reloaded"})
        return True

    def _init_static_layers(self, config: Dict) -> None:
        total_bytes = int(float(config.get("archive_max_total_mb", 100)) * 1024 * 1024)
        self.macro_analyzer = MacroAnalyzer()
        if self.intel is not None:
            from core.intel_client import IntelLLMBackend
            self.llm_backend: Any = IntelLLMBackend(self.intel)
        else:
            self.llm_backend = build_llm_backend(config)
        self.integrity = FileIntegrityAnalyzer()
        self.prompt_guard = PromptGuard()
        self.relationship_scanner = RelationshipScanner()
        self.container_extractor = ContainerExtractor(
            max_depth=int(config.get("archive_max_depth", 3)), max_total_bytes=total_bytes,
            max_members=int(config.get("archive_max_members", 500)))
        self.archive_scan_members = int(config.get("archive_scan_members", 25))
        self.max_nesting = int(config.get("max_nesting", 2))
        self.mail_analyzer = MailAnalyzer(
            max_attachments=int(config.get("mail_max_attachments", 50)),
            max_total_bytes=total_bytes)
        self.mail_scan_attachments = int(config.get("mail_scan_attachments", 25))
        self.web_analyzer = WebContentAnalyzer()
        self.allowlist = load_allowlist(config.get("allowlist_path"))
        self.embedded_analyzer = EmbeddedContentAnalyzer(
            password_source=self.container_extractor.current_extra_passwords)
        self.elf_analyzer = ElfAnalyzer()
        self.pe_analyzer = PeAnalyzer()
        self.script_analyzer = ScriptAnalyzer()
        self.qr_scanner: Optional[QRScanner] = (
            QRScanner() if config.get("qr_scan_enabled", True) else None)
        self.ml: Optional[MLClassifier] = (
            MLClassifier(config.get("ml_model_path")) if config.get("ml_enabled", True) else None)

    def _init_optional_layers(self, config: Dict) -> None:
        """Emulation and the sandbox: off unless configured (they run attacker code)."""
        self.emulator = None
        if config.get("emulation_enabled"):
            from detectors.emulation import ScriptEmulator
            self.emulator = ScriptEmulator(config.get("emulation_tool", "box-js"),
                                           int(config.get("emulation_timeout", 20)))
            logger.info("Emulation layer: %s.", f"ON ({self.emulator.tool})"
                        if self.emulator.available else "enabled but box-js was not found")
        self.sandbox: Any = None
        if self.intel is not None:
            if self.intel.service("sandbox").get("enabled"):
                from core.intel_client import IntelSandbox
                self.sandbox = IntelSandbox(self.intel,
                                            wait_seconds=int(config.get("sandbox_wait_seconds", 600)))
        elif config.get("sandbox_url"):
            from core.sandbox import CapeClient
            self.sandbox = CapeClient(config["sandbox_url"], token=config.get("sandbox_token", ""),
                                      wait_seconds=int(config.get("sandbox_wait_seconds", 600)))
            logger.info("Sandbox layer: ON (CAPEv2 at %s, submit=%s).", config["sandbox_url"],
                        config.get("sandbox_submit", "suspicious"))

    def _init_external(self, config: Dict) -> None:
        """Shared HTTP session (timeouts + retry/backoff), VirusTotal pacing, and
        a SHA-256-keyed cache so re-scans don't burn the API quota."""
        self.http = build_session()
        self.http_timeout = int(config.get("http_timeout", 30))
        self.vt_limiter = RateLimiter(float(config.get("virustotal_requests_per_minute", 4)))
        self.cache: Optional[ResultCache] = None
        # With the intel service the answers are cached there, written only from the
        # real reply: a cache here would be writable by the scan workers, which open
        # hostile files, so one exploited parser could plant clean answers.
        if (self.intel is None and config.get("cache_enabled", True)
                and config.get("cache_db_path")):
            self.cache = ResultCache(config["cache_db_path"],
                                     float(config.get("cache_ttl_hours", 24)) * 3600)

    def _log_layers(self) -> None:
        logger.info("Scanner initialized (engine v%s). Monitoring directories: %s",
                    ENGINE_VERSION, self.scan_dirs)
        states = layer_states(self)
        self.capability_states = states      # read by engine/completeness.py per scan
        self.provenance = scanner_provenance(self, states)
        logger.info("Detection layers -> %s  cache:%s", summary_line(states),
                    "intel" if self.intel is not None
                    else "on" if (self.cache and self.cache.enabled) else "off",
                    extra={"event": "layers", "layers": {n: s["state"] for n, s in states.items()}})
        logger.info("External services -> %s",
                    "  ".join(f"{n}:{v}" for n, v in external_services(states).items()))

    # ------------------------------------------------------------------ setup

    def _load_kaggle_database(self) -> set:
        """Load malicious MD5 hashes into a memory-efficient set (streaming CSV, no pandas)."""
        malicious_hashes: set = set()
        try:
            if not os.path.exists(self.kaggle_db_path):
                logger.warning("Malware database not found at %s. Expected columns: FileName, md5Hash, Benign.", self.kaggle_db_path)
                return malicious_hashes

            logger.info("Loading malware database from %s", self.kaggle_db_path)
            with open(self.kaggle_db_path, encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # A row is malicious when the 'Benign' flag is false/0/no
                    benign_value = str(row.get("Benign", "")).strip().lower()
                    is_malicious = benign_value in ["0", "false", "no", "n"]
                    if is_malicious:
                        md5 = row.get("md5Hash")
                        if md5:
                            malicious_hashes.add(md5.strip().lower())

            logger.info("Loaded %s malicious hashes into memory.", len(malicious_hashes))
            return malicious_hashes
        except Exception as e:
            logger.error("Error loading malware database: %s", str(e))
            return set()

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5 and SHA-256 using memory-efficient chunked reads.

        MD5 is kept for the local dataset lookup; SHA-256 is the modern
        identifier used for VirusTotal, the result cache, and as the canonical
        file hash.
        """
        md5_hash = hashlib.md5(usedforsecurity=False)
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(64 * 1024), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            return {"md5": md5_hash.hexdigest(), "sha256": sha256_hash.hexdigest()}
        except Exception as e:
            logger.error("Error calculating hashes for %s: %s", file_path, str(e))
            return {"md5": "", "sha256": ""}

    def check_hash_in_database(self, file_hash: str) -> Tuple[bool, Dict]:
        """Check whether an MD5 hash is present in the local malicious-hash set."""
        if file_hash and file_hash.lower() in self.hash_database:
            return True, {"reason": "Identified as malicious in local hash database"}
        return False, {}

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
            logger.error("Error walking directory %s: %s", directory, str(e))
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
        started = time.perf_counter()
        results: List[Dict] = []
        total = len(targets)

        def collect(index, file_path, result):
            try:
                self._maybe_auto_quarantine(result)
            except Exception as e:
                logger.error("Auto-quarantine failed for %s: %s", file_path, e)
            results.append(result)
            METRICS.record_result(result)
            if progress_callback is not None:
                try:
                    progress_callback(index, total, file_path, result)
                except Exception as e:
                    logger.error("Progress callback error: %s", e)

        if self.config.get("isolate_scans", True) and total > 1:
            from engine.workers import default_workers, scan_isolated
            scan_isolated(self, targets, default_workers(self.config),
                          float(self.config.get("scan_timeout_seconds", 300)),
                          int(self.config.get("worker_memory_mb", 2048)), collect, cancel_event)
            order = {p: i for i, p in enumerate(targets)}
            results.sort(key=lambda r: order.get(str(r.get("file_path")), 0))
        else:
            self._scan_in_order(targets, collect, cancel_event)
        if total:
            summary = METRICS.batch_summary(results, time.perf_counter() - started)
            logger.info("Scanned %d file(s) in %.1fs (%.2f files/s): %s", summary["files"],
                        summary["seconds"], summary["files_per_sec"],
                        ", ".join(f"{v} {n}" for v, n in summary["verdicts"].items() if n),
                        extra={"event": "scan_batch", "files": summary["files"],
                               "files_per_sec": summary["files_per_sec"],
                               "duration_ms": int(summary["seconds"] * 1000)})
        return results

    def _scan_in_order(self, targets: List[str], collect, cancel_event) -> None:
        """Scan in this process, one file after the other. A file whose scan raises
        (for example, it was deleted after the folder walk) gets a failed result,
        as in an isolated scan, instead of being left out of the report (PR-09)."""
        done = 0
        for file_path in targets:
            if cancel_event is not None and cancel_event.is_set():
                logger.info("Scan cancelled by user after %s/%s files.", done, len(targets))
                break
            try:
                result = self.scan_file(file_path)
            except Exception as e:
                logger.error("Error scanning file %s: %s", file_path, e)
                from engine.workers import failure_result
                result = failure_result(self, file_path, f"{type(e).__name__}: {e}")
            done += 1
            collect(done, file_path, result)

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
                logger.info("Scanning directory: %s", directory)
                targets.extend(self._collect_target_files(directory, impact))
            else:
                logger.warning("Directory does not exist: %s", directory)

        self.last_impact = impact
        return self._scan_targets(targets, progress_callback, cancel_event)

    # ------------------------------------------------------------------ run
    def scan_mailbox(self):
        """Scan new messages in the configured IMAP folder (read-only). Returns
        (report text, core.mailbox.MailboxRun); raises core.mailbox.MailboxError."""
        from core.mailbox import ImapSettings, MailboxScanner
        from core.outputs import deliver
        run = MailboxScanner(self, ImapSettings.from_config(self.config)).run()
        deliver(run.results, self.config)
        report = self.generate_report(run.results) if run.results else (
            f"No new messages in {self.config.get('imap_folder', 'INBOX')}.")
        return report, run

    def scan_mailbox_safely(self) -> None:
        """For the scheduler: never let a mailbox problem stop the background loop."""
        try:
            _, run = self.scan_mailbox()
            logger.info("Mailbox check: %d new message(s) scanned.", len(run.results))
        except Exception as e:
            logger.error("Mailbox check failed: %s", e)

    def run_scan(self) -> str:
        """Run a complete scan (canary check + all directories) and generate a report."""
        logger.info("Starting scheduled ransomware scan...")
        canary_report = self.check_canaries() if self.canaries.entries() else None
        results = self.scan_all_directories()
        report = self.generate_report(results, impact=self.last_impact,
                                      canary_report=canary_report)
        from core.outputs import deliver
        deliver(results, self.config)
        logger.info("Scan complete.")
        return report

