# AEGIS SENTINEL v5.2.0 — Multi-Layer Endpoint Triage, MailGuard, Threat Intel & Hybrid AI Detection Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Engine: v5.2.0](https://img.shields.io/badge/Engine-v5.2.0--aegis--sentinel-critical.svg)](config.py)
[![SBOM: CycloneDX 1.5](https://img.shields.io/badge/SBOM-CycloneDX%201.5-informational.svg)](core/supply_chain.py)

**AEGIS SENTINEL** is a cross-platform user-space endpoint detection, multi-format malware analysis, email security (**Aegis MailGuard**), deception tripwire, and local-first AI correlation platform. It combines deterministic cryptographic, structural, behavioral, and memory-level inspection with a calibrated machine learning classifier and a local Ollama LLM threat analyst—governed by strict mathematical category caps so that neither AI nor semantic heuristics can unilaterally quarantine a file or override hard technical detections.

---

## High-Level Architecture & Pipeline

```text
                         +---------------------------------------------------+
                         |            AEGIS SENTINEL v5.2.0 CORE             |
                         |   Ed25519 Self-Integrity Guard & TrustKeyRing     |
                         +-------------------------+-------------------------+
                                                   |
                   +-------------------------------+-------------------------------+
                   |                               |                               |
                   v                               v                               v
       +-----------------------+       +-----------------------+       +-----------------------+
       |   Real-Time Watchdog  |       |  Deception Canaries   |       |  Scheduled / CLI /    |
       |  (2.0s Settle Wait)   |       | (!00_* HMAC Decoys)   |       |   CustomTkinter GUI   |
       +-----------+-----------+       +-----------+-----------+       +-----------+-----------+
                   |                               |                               |
                   +-------------------------------+-------------------------------+
                                                   |
                                                   v
                         +---------------------------------------------------+
                         |        SQLite WAL Dual-Table Scan Cache           |
                         |  (file_stat_cache -> verdict_cache, 7-Day TTL)    |
                         +-------------------------+-------------------------+
                                                   | (Cache Miss)
                                                   v
   +-----------------------------------------------------------------------------------------------+
   |                         STAGE 1: UNTRUSTED PARSING & DECONSTRUCTION                           |
   |                                                                                               |
   |  * 64 KB Chunked MD5/SHA-256 + 5 MB Capped ASCII/UTF-16LE String Generator                    |
   |  * Sandboxed Recursive Container Unpacker (.zip/.7z/.rar/.iso) with Zip-Bomb & Zip-Slip Guard |
   |  * Office Relationship Scanner (_rels/*.rels via defusedxml -> RTI / Follina ms-msdt:)        |
   |  * Aegis MailGuard (.eml/.msg -> SPF/DKIM/DMARC Honesty Model, Lookalikes, URL Egress Filter) |
   +-----------------------------------------------+-----------------------------------------------+
                                                   |
                                                   v
   +-----------------------------------------------------------------------------------------------+
   |                     STAGE 2: MULTI-LAYER STATIC, DYNAMIC & HOST SENSORS                       |
   |                                                                                               |
   |  +---------------------+  +----------------------+  +------------------+  +----------------+  |
   |  | Local Hash DB &     |  | VBA / XLM Macros &   |  | Multi-Format     |  | Namespaced     |  |
   |  | Fuzzy (TLSH/ssdeep) |  | P-Code VBA Stomping  |  | PE/ELF/MachO/LNK |  | YARA Engine    |  |
   |  +---------------------+  +----------------------+  +------------------+  +----------------+  |
   |  +---------------------+  +----------------------+  +------------------+  +----------------+  |
   |  | Behavioral Monitor  |  | Dynamic Sandbox      |  | Live Memory      |  | Sigma Log &    |  |
   |  | (Lineage & Entropy) |  | (bwrap / Emulation)  |  | Forensics (RWX)  |  | YARA-L Windows |  |
   |  +---------------------+  +----------------------+  +------------------+  +----------------+  |
   |  +---------------------+  +----------------------+  +------------------+  +----------------+  |
   |  | Threat Intel (TIP)  |  | VirusTotal / GSB /   |  | PromptGuard &    |  | Calibrated ML  |  |
   |  | (STIX 2.1 / IOC DB) |  | IPQS / AbuseIPDB     |  | Nonce Spotlight  |  | & Local Ollama |  |
   |  +---------------------+  +----------------------+  +------------------+  +----------------+  |
   +-----------------------------------------------+-----------------------------------------------+
                                                   |
                                                   v
   +-----------------------------------------------------------------------------------------------+
   |                  STAGE 3: SCORING MATRIX, 6-PILLAR AI CORRELATOR & MITRE                      |
   |                                                                                               |
   |  * Category Caps: Technical <= 100 | Reputation <= 80 | Semantic <= 24 | ML Standalone <= 35  |
   |  * Guardrail: Semantic-only / uncorroborated AI signals clamped at <= 49 (Medium)             |
   |  * Supporting vs. Mitigating Evidence Enumeration + MITRE ATT&CK v15 / CAR Mapping            |
   +-----------------------------------------------+-----------------------------------------------+
                                                   |
                                                   v
   +-----------------------------------------------------------------------------------------------+
   |                STAGE 4: ACTIVE CONTAINMENT, IR PLAYBOOKS & DURABLE TELEMETRY                  |
   |                                                                                               |
   |  * Pre-Quarantine Process Lock Termination (OS Safelist Enforced)                             |
   |  * Atomic Move + 64 KB Chunked AES-256-GCM Quarantine Vault (AAD Bound) + Self-Test           |
   |  * Evidence Locker, HITL Approval Queue, HMAC-SHA256 Chained Audit Ledger                     |
   |  * Persistent SQLite WAL Telemetry Spooler -> TCP Syslog SIEM (CEF/JSON), SMTP & Cloud Sync   |
   +-----------------------------------------------------------------------------------------------+
```

---

## Key Capabilities Breakdown

### 1. Memory-Safe I/O, Resilience & Caching (`core/resilience.py`, `core/cache.py`)
* **64 KB Streaming I/O:** Cryptographic hashing (`MD5`, `SHA-256`) and fuzzy hashing (`TLSH`, `ssdeep`) stream files in 64 KB chunks so multi-gigabyte ISOs and archives never spike RAM.
* **5 MB Capped String Generator:** Extracts ASCII and UTF-16LE strings lazily with a hard 5 MB ceiling.
* **Exponential Backoff with Full Jitter:** `ResilientHttpClient` handles HTTP `429` (`Retry-After`) and `5xx` errors across VirusTotal, Google Safe Browsing, IPQualityScore, AbuseIPDB, OpenAI, and Cloud Sync endpoints.
* **Dual-Table SQLite WAL Cache:** Maps `(file_path, mtime_ns, file_size)` to `(md5, sha256)` and `(sha256, ENGINE_VERSION)` to full scan verdicts with a 7-day TTL.

### 2. Multi-Format & Untrusted Container Analysis (`detectors/`)
* **Multi-Format Binary, Script & Web Parser (`multi_format_analyzer.py`):**
  * **Windows (`PE` / `MSI`):** Inspects `.exe`, `.dll`, `.sys`, `.scr` headers, per-section Shannon entropy, `RWX` permissions, packer sections (`.upx`, `.vmp`, `.themida`), high-risk injection APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`), and `.msi` `CustomAction` streams.
  * **Linux (`ELF`) & macOS (`Mach-O`):** Detects `PT_LOAD` `RWX` segments, `LD_PRELOAD` hooks, `ptrace` references, `DYLD_INSERT_LIBRARIES`, and `task_for_pid`.
  * **Shortcuts (`LNK`), Scripts & Web:** Parses MS-SHLLINK `.lnk` arguments, PowerShell/JS/VBS/BAT obfuscation and AMSI bypasses, and HTML Smuggling (`Blob` + `URL.createObjectURL`) or SVG `<script>` payloads.
* **Sandboxed Recursive Container Unpacker (`container_extractor.py`):** Extracts `.zip`, `.7z`, `.rar`, and `.iso` up to 3 levels deep inside an isolated temporary directory while enforcing a 200 MB cumulative byte cap, a 50-file ceiling, `os.path.commonpath` Zip-Slip traversal prevention, symlink refusal, and dictionary password recovery.
* **Office RTI & Macro Stomping Defense (`relationship_scanner.py`, `macro_analysis.py`):** Uses `defusedxml` to parse `_rels/*.rels` for external template injection (`T1221`) and `ms-msdt:` Follina exploits, detects Excel 4.0 (XLM) macros, and flags **VBA Stomping** (`T1564.007`) by comparing raw `_VBA_PROJECT` P-Code identifiers against decompressed VBA source.

### 3. Aegis MailGuard (`detectors/mail_analyzer.py`)
* **Strict Authentication Honesty Model:** Evaluates `SPF`, `DKIM`, and `DMARC` and labels every mechanism as:
  * `verified`: Cryptographically verified by AEGIS SENTINEL (`dkimpy` signature verification / live DNS policy lookup).
  * `reported`: Parsed from an `Authentication-Results` or `Received-SPF` header emitted by an explicitly trusted `authserv-id` (`trusted_authserv`). Headers from untrusted servers are ignored for trust and flagged as `mail_untrusted_auth_header`.
  * `unavailable`: Live verification disabled or DNS unreachable (logged under `inconclusive_notes` without arbitrary point penalties).
* **Phishing & URL Egress Privacy:** Detects `From` / `Return-Path` / `Reply-To` spoofing, Punycode/homoglyph and Levenshtein lookalike domains, HTML credential-harvesting forms, and anchor href mismatches. All extracted URLs pass through `URLPrivacyFilter` (blocking internal domains/RFC1918 IPs and redacting secret query tokens) before querying external reputation APIs.

### 4. Behavioral, Dynamic Sandbox, Memory Forensics, Sigma & Deception (`core/`, `detectors/`)
* **Deception Canary Tripwires (`canary_manager.py`):** Deploys HMAC-watermarked decoy files (`!00_passwords_vault.docx`, `!00_prod_cluster_id_rsa.pem`) that sort first alphabetically; any modification, encryption, or deletion triggers an immediate `Critical (100/100)` alert.
* **Behavioral Process & Burst Monitor (`behavioral_monitor.py`):** Detects document readers spawning command interpreters (`winword.exe -> powershell.exe`), shadow-copy deletion (`vssadmin delete shadows`), and high-entropy (`>= 7.35` bits/byte) file-modification bursts.
* **Dynamic Sandbox (`dynamic_sandbox.py`):** Explicitly distinguishes between `"isolated_container"` execution (Linux `bwrap` unshared namespaces with `--unshare-all` and no network) and `"safe_emulation"` (multi-stage Base64 deobfuscation and behavioral IOC extraction).
* **Live Process Memory Forensics (`memory_scanner.py`):** Scans live process memory on Linux (`/proc/<pid>/maps` + `mem`) and Windows (`VirtualQueryEx` + `ReadProcessMemory`) in 64 KB chunks for unbacked `RWX` pages, reflective PE/ELF headers, and AMSI bypass patches, explicitly reporting `"inspected"` vs. `"permission_denied"`.
* **Sigma & YARA-L Engine (`sigma_engine.py`):** Evaluates single-event Sigma rules and sliding-window YARA-L temporal correlation rules.

### 5. Calibrated ML, Local LLM Threat Analyst & 6-Pillar AI Correlator (`detectors/`)
* **PromptGuard (`prompt_guard.py`):** Extracts hidden `.docx` (`w:vanish`, 1pt font, white-on-white) and HTML (`display:none`, `opacity:0`) text, detects prompt-injection attempts, and wraps untrusted content in randomized `<UNTRUSTED_DATA_{NONCE}>` delimiters using a 40%/30%/30% Head/Middle/Tail sampler.
* **Calibrated ML Classifier (`ml_classifier.py`):** Evaluates a standardized 16-feature file vector and an 8-feature MailGuard phishing vector using Platt-scaled probability calibration.
* **6-Pillar AI Correlator (`ai_correlator.py`):** Fuses Static, Behavioral/Sandbox, MailGuard, Threat Intelligence (STIX 2.1 TIP + VT), ML Classifier, and Local LLM signals, outputting explicit `supporting_evidence` and `opposing_evidence` lists.

---

## Unified Weighted Scoring Matrix

```text
+-------------------------------------------------------------------------+
|Indicator                                      Category     Max Weight   |
+-------------------------------------------------------------------------+
|Local Malicious Hash DB Match                  technical    100.0        |
|Canary Honeypot Tripwire Tampered/Deleted      technical    100.0        |
|Zip-Bomb / Zip-Slip Archive Breach             technical    100.0        |
|VBA Stomping (P-Code vs. Source Mismatch)      technical     90.0        |
|Live Memory Reflective PE/ELF or Shellcode     technical     90.0        |
|YARA Rule Match (critical/high/medium/low)     technical  90/65/40/18    |
|Sigma / YARA-L Temporal Correlation Match      technical     90.0        |
|Behavioral Shadow Copy Deletion                technical     85.0        |
|Fuzzy Hash Match (TLSH / ssdeep * confidence)  technical     72.0        |
|Remote Template Injection (RTI / Follina)      technical     70.0        |
|Excel 4.0 (XLM) Macro Detection                technical     55.0        |
|Confirmed LLM Prompt Injection                 technical     50.0        |
|MailGuard DMARC Fail (verified=100%/rep=80%)   technical     45.0        |
|MailGuard Lookalike Domain                     technical     45.0        |
|Macro Critical Execution Primitive             technical     40.0 (+8)   |
|Calibrated ML Classifier (Standalone Cap)      technical     35.0        |
|Unreadable Password-Protected Archive          technical  25.0 - 35.0    |
|Concealed / Hidden Document or HTML Text       technical     25.0        |
+-------------------------------------------------------------------------+
|VirusTotal Multi-Engine Detections             reputation    80.0 (fl 35)|
|Threat Intelligence Platform (TIP) IOC Hit     reputation    95.0 (cap80)|
|MailGuard Malicious URL (VT/GSB/IPQS/AbuseIP)  reputation    65.0        |
+-------------------------------------------------------------------------+
|Local LLM Semantic Lure Analysis               semantic      24.0        |
|MailGuard Phishing Urgency Keywords            semantic      20.0        |
+-------------------------------------------------------------------------+
|Category Caps: Technical = 100.0 | Reputation = 80.0 | Semantic = 24.0   |
|Guardrail: If Technical == 0 and Reputation == 0 -> Max Score = 49 (Med) |
+-------------------------------------------------------------------------+
```

**Verdict Bands:**
* **0:** `Clean`
* **1 – 24:** `Low`
* **25 – 49:** `Medium`
* **50 – 79:** `High`
* **80 – 100:** `Critical`

---

## Installation

### 1. System Prerequisites (Optional but Recommended)
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y tesseract-ocr poppler-utils libfuzzy-dev unrar bubblewrap strace

# macOS (Homebrew)
brew install tesseract poppler ssdeep

# Windows (winget / Chocolatey)
choco install tesseract poppler unrar
```

### 2. Python Environment Setup
```bash
git clone [https://github.com/your-org/aegis-sentinel.git](https://github.com/your-org/aegis-sentinel.git)
cd aegis-sentinel
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Local LLM Setup (Optional — Privacy-Preserving Default)
```bash
ollama pull llama3.1
ollama serve
```

---

## CLI Usage Reference

### Core Scanning & Daemon Mode
```bash
# Scan a single file (any format: PDF, Office, PE, ELF, Mach-O, LNK, Script, Archive, .eml, .msg)
python RansomwareScanner.py --scan-file /path/to/suspicious.docm

# Run an immediate directory scan across configured paths with 4 worker threads
python RansomwareScanner.py --scan-now --workers 4 --enable-quarantine

# Run real-time Watchdog monitoring daemon + scheduled background scans
python RansomwareScanner.py --daemon --enable-quarantine --siem-host 10.0.0.50:514

# Launch the CustomTkinter graphical XDR console
python RansomwareScanner.py --gui
```

### Quarantine, Host Response & Incident Management
```bash
# Run the AES-256-GCM chunked quarantine tamper & restore self-test
python RansomwareScanner.py --quarantine-self-test

# List, restore, or purge quarantined artifacts
python RansomwareScanner.py --list-quarantine
python RansomwareScanner.py --restore <QUARANTINE_ID>
python RansomwareScanner.py --purge-quarantine <QUARANTINE_ID>

# Correlated incidents, timelines, and Local LLM incident narratives
python RansomwareScanner.py --list-incidents
python RansomwareScanner.py --incident-timeline <INCIDENT_ID>
python RansomwareScanner.py --explain-incident <INCIDENT_ID>

# Verify the HMAC-SHA256 chained IR audit ledger & manage HITL approvals
python RansomwareScanner.py --ir-verify-audit
python RansomwareScanner.py --ir-list-hitl
python RansomwareScanner.py --ir-approve-hitl <REQUEST_ID>

# Host-level containment (process tree termination & firewall network isolation)
python RansomwareScanner.py --kill-pid <PID>
sudo python RansomwareScanner.py --isolate-host 10.0.0.10
sudo python RansomwareScanner.py --restore-network
```

### Deception Canaries, Memory Forensics, TIP & Supply Chain
```bash
# Deploy, audit, or remove cryptographic ransomware canary honeypots
python RansomwareScanner.py --deploy-canaries
python RansomwareScanner.py --verify-canaries
python RansomwareScanner.py --remove-canaries

# Scan live process memory for RWX pages & reflective PE/ELF injection
sudo python RansomwareScanner.py --scan-memory

# Import STIX 2.1 / JSON / CSV threat intelligence feeds & prune expired IOCs
python RansomwareScanner.py --import-ioc-feed feeds/stix_ransomware_iocs.json
python RansomwareScanner.py --prune-iocs

# Verify Ed25519 self-integrity, sign/update YARA rules, and generate CycloneDX 1.5 SBOM
python RansomwareScanner.py --verify-integrity
python RansomwareScanner.py --sign-rules rules/ signed_rules_v2.json --rule-seq 2
python RansomwareScanner.py --update-rules signed_rules_v2.json
python RansomwareScanner.py --generate-sbom
```

### AI / ML Team Workflow & Evaluation Benchmarks
```bash
# Export 16-feature CSV & JSONL training datasets from a labeled corpus (benign/ and malicious/)
python RansomwareScanner.py --export-ai-dataset /path/to/corpus data/ai_features.csv

# Run the 3-way A/B ablation benchmark (Rules-Only vs. Rules+ML vs. Full Hybrid AI)
python RansomwareScanner.py --ablation-benchmark

# Run the Automated Malware Evaluation Lab & parser fuzzing regression suite
python RansomwareScanner.py --eval-lab --eval-save-baseline
python RansomwareScanner.py --fuzz 250
python RansomwareScanner.py --run-regressions
```

---

## Standalone Executable Packaging (PyInstaller)

Build a single-file executable (`dist/aegis-sentinel` or `dist/aegis-sentinel.exe`) that bundles `rules/`, `fuzzy_signatures.sample.json`, and `CustomTkinter` assets:

```bash
python build.py --run-smoke-test
```

---

## Repository Structure

```text
aegis-sentinel/
├── config.py                        # Central configuration, limits & PyInstaller _MEIPASS resolver
├── scanner.py                       # Core AegisSentinelScanner orchestrator
├── RansomwareScanner.py             # CLI entrypoint & backward-compatible shim
├── gui.py                           # Threaded CustomTkinter desktop console
├── build.py                         # PyInstaller build & smoke-verification script
├── scanner.spec                     # PyInstaller single-file spec
├── core/
│   ├── resilience.py                # 64KB I/O, 5MB string generator, Backoff+Jitter HTTP client
│   ├── cache.py                     # Dual-table SQLite WAL cache (7-day TTL + ENGINE_VERSION)
│   ├── quarantine.py                # 64KB chunked AES-256-GCM vault with AAD binding
│   ├── watchdog_service.py          # Real-time directory monitor with settle-wait debounce
│   ├── siem_handler.py              # Non-blocking TCP Syslog forwarder (CEF & JSON)
│   ├── notifier.py                  # Rate-limited SMTP/STARTTLS Critical alert dispatcher
│   ├── cloud_sync.py                # AES-256-GCM encrypted report uploader
│   ├── integrity.py                 # Ed25519 self-integrity guard & permission verifier
│   ├── rule_updater.py              # Signed YARA rule bundle installer & LKG rollback
│   ├── mitre_mapper.py              # MITRE ATT&CK v15+ mapper & gap catalog
│   ├── incident_correlator.py       # Cross-layer incident correlator & microsecond timeline
│   ├── eval_lab.py                  # Precision/Recall/F1/FPR & memory evaluation lab
│   ├── threat_intel.py              # SQLite TIP with STIX 2.1 ingestion & TTL pruning
│   ├── host_telemetry.py            # Process, sensitive file, auth & network snapshot collector
│   ├── incident_response.py         # Evidence locker, playbooks, HITL queue & HMAC audit chain
│   ├── central_console.py           # Multi-agent registry, RBAC & policy/rule distribution
│   ├── sigma_engine.py              # Sigma log rules & YARA-L sliding-window correlation
│   ├── canary_manager.py            # Cryptographic ransomware canary honeypot tripwires
│   ├── host_response.py             # Process tree termination & OS firewall network isolation
│   ├── telemetry_spooler.py         # Durable SQLite WAL disk spooler with idempotency keys
│   ├── supply_chain.py              # CycloneDX v1.5 SBOM, TrustKeyRing & URLPrivacyFilter
│   └── ai_dataset_exporter.py       # 16-feature CSV/JSONL exporter & 3-way ablation benchmark
├── detectors/
│   ├── fuzzy_hash.py                # 64KB-chunked TLSH + ssdeep similarity engine
│   ├── macro_analysis.py            # Static VBA/XLM triage + P-Code VBA Stomping detector
│   ├── yara_engine.py               # Namespaced YARA compiler & scanner
│   ├── prompt_guard.py              # Concealed text extractor & nonce spotlighting guard
│   ├── llm_backends.py              # Local Ollama & OpenAI semantic analyzers
│   ├── container_extractor.py       # Sandboxed recursive archive unpacker
│   ├── relationship_scanner.py      # defusedxml Office _rels/*.rels RTI & Follina scanner
│   ├── mail_analyzer.py             # Aegis MailGuard (.eml/.msg, SPF/DKIM/DMARC honesty model)
│   ├── behavioral_monitor.py        # Process lineage, shadow-copy & entropy burst detector
│   ├── multi_format_analyzer.py     # PE, MSI, ELF, Mach-O, LNK, Script & Web parser
│   ├── dynamic_sandbox.py           # Isolated bwrap container runner & safe behavioral emulator
│   ├── memory_scanner.py            # Live process RWX & reflective injection scanner
│   ├── ml_classifier.py             # Platt-calibrated Random Forest / Ensemble classifier
│   ├── llm_analyst.py               # Local LLM threat briefing & incident narrative generator
│   ├── ai_correlator.py             # 6-pillar consensus engine (supporting vs. opposing evidence)
│   └── scoring.py                   # Unified category-capped scoring matrix
├── rules/
│   ├── ransomware_generic.yar       # Generic ransomware note & shadow-copy YARA rules
│   └── office_dropper.yar           # Office macro + PowerShell cradle YARA rules
├── tests/
│   ├── fuzz_harnesses.py            # Atheris & structure-aware mutational fuzzing harnesses
│   └── test_fuzz_regressions.py     # Deterministic parser fuzzing regression suite
├── docs/
│   ├── DETECTION_v5.md              # Deep-dive v5.2.0 detection & cryptographic specification
│   └── CAPABILITY_MATRIX.md         # OS capability matrix, MITRE CAR specs & AI handoff guide
└── test_smoke.py                    # End-to-end automated smoke test suite