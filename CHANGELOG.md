# Changelog

All notable changes to **AEGIS SENTINEL** (formerly Hybrid Ransomware & Malware Detector) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.2.0] - 2026-10-15

### Added
- **Host-Level Active Response (`core/host_response.py`):** Process tree termination (`terminate_process_tree`), process suspension/resumption (`suspend_process`, `resume_process`), pre-quarantine file-lock release (`terminate_processes_locking_file`) with a non-bypassable OS critical-process safelist, and host firewall network isolation/rollback (`isolate_host_network`, `restore_host_network`).
- **Persistent SQLite WAL Telemetry Spooler (`core/telemetry_spooler.py`):** Durable disk queue (`aegis_telemetry_spool.sqlite3`) for SIEM and Cloud Sync alerts with deterministic `UUIDv5` `idempotency_key` deduplication, exponential retry backoff, dead-lettering, and 14-day retention pruning.
- **Supply Chain Security & URL Privacy Filter (`core/supply_chain.py`):** Standards-compliant **CycloneDX v1.5 JSON SBOM** generator (`--generate-sbom`), Ed25519 `TrustKeyRing` key rotation and revocation (`--rotate-signing-key`), and `URLPrivacyFilter` preventing internal domain/RFC1918 IP and query-token leakage to external reputation APIs.
- **AI Team Dataset Exporter & Ablation Suite (`core/ai_dataset_exporter.py`):** Standardized 16-feature CSV and JSONL dataset exporter (`--export-ai-dataset`) and 3-way A/B ablation benchmark (`--ablation-benchmark`) comparing Rules-Only vs. Rules+ML vs. Full Hybrid AI.
- **Engineering Capability Matrix (`docs/CAPABILITY_MATRIX.md`):** OS-by-OS capability table, privilege requirements, known user-space boundaries, and MITRE CAR analytic specifications.

### Changed
- Unified all internal logger namespaces under `AegisSentinel.*`.
- Surfaced unreadable password-protected archives (`encrypted_unreadable`) directly in `ScoringMatrix` contributions.

---

## [5.1.0] - 2026-10-15

### Added
- **Live Process Memory Forensics (`detectors/memory_scanner.py`):** 64 KB chunked inspection of private/unbacked `RWX` memory regions on Linux (`/proc/<pid>/maps` + `mem`) and Windows (`VirtualQueryEx` + `ReadProcessMemory`) for reflective PE/ELF headers, shellcode prologues, and AMSI bypass patches (`--scan-memory`).
- **Sigma & YARA-L Temporal Correlation Engine (`core/sigma_engine.py`):** Single-event Sigma rule evaluator and sliding-window YARA-L multi-event correlation engine (`--sigma-status`).
- **Deception & Canary Honeypot Tripwires (`core/canary_manager.py`):** Cryptographically watermarked (`HMAC-SHA256`) decoy files (`!00_*`) deployed in monitored directories to detect ransomware encryption waves immediately (`--deploy-canaries`, `--verify-canaries`, `--remove-canaries`).

---

## [5.0.0] - 2026-10-15

### Added
- **Multi-Format Malware Analyzer (`detectors/multi_format_analyzer.py`):** Native parsers and 12-feature vector extraction for Windows `PE` (`.exe`, `.dll`, `.sys`, `.scr`), `.msi`, Linux `ELF`, macOS `Mach-O`, Windows `.lnk` shortcuts, scripts (`.ps1`, `.js`, `.vbs`, `.bat`), and web files (`.html`, `.hta`, `.svg`).
- **Dynamic Malware Sandbox (`detectors/dynamic_sandbox.py`):** Unprivileged Linux `bwrap` container execution (`isolated_container`) and deterministic multi-stage Base64/behavioral emulation (`safe_emulation`).
- **Threat Intelligence Platform (`core/threat_intel.py`):** SQLite WAL IOC store supporting `sha256`, `md5`, `domain`, `ip`, and `url` observables with source attribution, TTL expiration, and **OASIS STIX 2.1 Bundle** ingestion (`--import-ioc-feed`, `--prune-iocs`).
- **Endpoint Host Telemetry (`core/host_telemetry.py`):** Sensitive file mtime monitoring, authentication failure log inspection, `/etc/ld.so.preload` rootkit checks, and outbound C2 connection profiling (`--host-telemetry`).
- **Advanced Incident Response (`core/incident_response.py`):** SHA-256 Evidence Locker, automated response playbooks, temporary path snoozing (`--ir-snooze`), Human-in-the-Loop (HITL) approval queue (`--ir-list-hitl`, `--ir-approve-hitl`), and an HMAC-SHA256 chained audit ledger (`--ir-verify-audit`).
- **Central Management Console (`core/central_console.py`):** Fleet agent enrollment, PBKDF2-HMAC-SHA256 RBAC (`admin` vs. `analyst`), policy publishing, signed rule distribution, and cross-fleet event search.
- **Calibrated ML Classifier, Local LLM Threat Analyst & 6-Pillar AI Correlator (`detectors/ml_classifier.py`, `detectors/llm_analyst.py`, `detectors/ai_correlator.py`):** Platt-calibrated ensemble classification, structured analyst briefings, and supporting vs. opposing evidence correlation.

---

## [4.1.0] - 2026-10-15

### Added
- **Coverage-Guided Fuzzing & Regression Suite (`tests/fuzz_harnesses.py`, `tests/test_fuzz_regressions.py`):** Atheris & structure-aware mutational fuzzers across archive, email, XML, and PDF parsers (`--fuzz`, `--run-regressions`).
- **Ed25519 Self-Integrity & Signed Rule Updater (`core/integrity.py`, `core/rule_updater.py`):** Startup code/rule manifest verification, anti-rollback monotonic sequence enforcement, and Last-Known-Good (LKG) rule rollback.
- **Behavioral Monitor, MITRE ATT&CK Mapper, Eval Lab & Incident Correlator (`detectors/behavioral_monitor.py`, `core/mitre_mapper.py`, `core/eval_lab.py`, `core/incident_correlator.py`).**

---

## [4.0.0] - 2026-10-15

### Added
- **Aegis MailGuard (`detectors/mail_analyzer.py`):** `.eml` and `.msg` parser with SPF/DKIM/DMARC honesty model (`verified`, `reported`, `unavailable`), lookalike domain detection, and multi-service URL reputation checks.
- **AES-256-GCM Chunked Quarantine Vault (`core/quarantine.py`), Watchdog Service (`core/watchdog_service.py`), Sandboxed Container Unpacker (`detectors/container_extractor.py`), Office RTI Scanner (`detectors/relationship_scanner.py`), PromptGuard (`detectors/prompt_guard.py`), TCP Syslog SIEM Handler (`core/siem_handler.py`), and PyInstaller Packaging (`build.py`, `scanner.spec`).**

---

## [3.0.0] - 2026-04-01

### Added
- Pluggable detection package (`detectors/`) with Fuzzy Hashing (`TLSH` + `ssdeep`), static `olevba` Macro Analyzer, namespaced YARA Engine, Local-First Ollama LLM backend, and Category-Capped Scoring Matrix (0–100 risk score).