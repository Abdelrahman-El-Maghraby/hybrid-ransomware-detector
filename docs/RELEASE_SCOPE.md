# Release scope: Aegis Sentinel On-Prem (first paid edition)

Status: **draft for the owner's review** (Phase 0 of the v4.7 work, 2026-10-27).
Items marked **Decision** are product choices only the owner can make; the text
states the proposal so the work can start, and changes if the owner decides otherwise.

## 1. What is sold

File and e-mail-attachment triage for a company IT / security team, with an
explained verdict for every file: a 0-100 risk score in which every point is a named
contribution. The customer pays a subscription for signed rule-pack updates and support.

- **Delivery:** one Docker deployment per customer, on the customer's own Linux host.
  Not a SaaS, not multi-tenant: one customer, one configuration, one data folder.
- **The production profile** is the configuration this edition ships and supports. It
  fixes which layers must be available and enabled (section 3) and which external
  services are off by default. Other configurations stay possible, but they are not the
  supported product.

## 2. Surfaces in the edition

| Surface | In the edition | Notes |
|---|---|---|
| REST API (`aegis-api`) | **Yes, primary** | Behind the customer's TLS reverse proxy. `/scan`, `/health`, `/ready` (Phase 1), `/version`, `/schema`, `/metrics`. |
| CLI inside the container | Yes | Folder and single-file triage, `--scan-imap` (read-only mailbox scanning), rule-pack install, quarantine management. |
| JSON Lines and signed webhooks | Yes | SIEM / SOAR integration; metadata only, never file content. |
| Encrypted quarantine vault | Yes | Restore needs authorisation and is audit-logged (A8). Quarantining is a separate action decision, not the verdict. |
| Desktop GUI (`aegis_gui/`) | **Decision D2** | Proposal: supported as an analyst workstation app on Windows and macOS. It is not part of the Docker deployment, and it ships as unsigned binaries until certificates exist. |
| Host protection (canaries, `stop_writers`, `lock_folders`, `network_off`, Controlled Folder Access) | **Decision D3** | Proposal: not part of the Docker edition. A container cannot watch or contain processes on the customer's endpoints, and it must not hold kill / network rights (Phase 2). The features stay in the desktop build, outside the paid support scope. |

## 3. Layers in the production profile

**Required** means available **and** enabled. If one is missing or disabled,
`check_config()` fails at start-up and `/ready` reports not ready (Phase 1, item 3).
The container image must therefore carry the system tools those layers need.

| Layer (pipeline name) | Production profile | Needs in the image | Why |
|---|---|---|---|
| `hashes`, `allowlist`, `local-db` | Required | — | Identity and known-bad / known-good look-ups. The hash dataset and allowlist are customer data; empty is valid. |
| `fuzzy` | Required | `python-tlsh` (or the built-in port), `ppdeep`, `numpy` | Family similarity. The signature DB ships empty; content arrives in rule packs. |
| `macro` | Required | `oletools` | Office droppers are the core use case. |
| `yara` | Required | `yara-python` | Structural rules; the subscription content. |
| `integrity` | Required | — | Disguised executables and encrypted content. |
| `elf`, `pe` | Required | — (standard library) | Executables in attachments and archives. |
| `script` | Required | — | JS / VBS / HTA / PS1 / BAT droppers. |
| `mail` (container) | Required | `olefile`, `defusedxml` | `.eml` / `.msg` triage. |
| `prompt-guard`, `relationships` | Required | `defusedxml`, `pypdf`, `python-docx` | Hidden content, injection, remote templates, Follina, UNC links. |
| `archive` (container) | Required | `pyzipper`, `py7zr`, `pycdlib`, `rarfile` + a RAR decompressor (`7zip` or `unar`) | Archives are the main delivery wrapper. Without a decompressor RAR members are only listed, which would make every RAR scan partial. |
| `web`, `embedded` (containers) | Required | `msoffcrypto-tool` | HTML smuggling, OneNote / CHM / MSI / XLL, password-protected Office. |
| `qr` | Required | `pyzbar` + `libzbar0` | Quishing in images, PDFs and Office files. |
| `ml` | Required, **rule-engine mode** | `numpy` (`scikit-learn` only to load a model) | No model ships (A3: an unvalidated model is not shipped). The transparent rule engine runs instead. |
| `llm` | Optional, **off** by default | Local Ollama, or a cloud key; OCR (`tesseract`, `poppler`) only with it | Sends document text to a model. Enabling it is explicit, logged at start-up and recorded in each result's provenance. |
| `virustotal` | Optional, **off** by default (**Decision D4**) | API key | Even a hash look-up tells a third party what the customer is scanning. Upload stays a second, separate opt-in. |
| `sandbox` | Optional, **off** by default | The customer's own CAPEv2 server | Submits files to another system. |
| `emulation` | **Not supported** in the production profile | box-js / Node | It executes attacker JavaScript; it is an analysis-VM feature. If enabled, the configuration is reported as outside the production profile. |

An optional layer that is disabled by configuration is recorded in provenance. It does
**not** make a scan `partial` (Phase 1, item 3).

## 4. Supported platforms

| Platform | Support | Evidence today |
|---|---|---|
| Docker Engine on Linux x86_64 (image based on Python 3.12) | **Supported** (the product) | No Dockerfile yet (Phase 2). |
| Docker Engine on Linux arm64 | **Decision D5**; proposed "supported once the image is built and tested in CI" | Dependencies ship arm64 wheels (README); not tested yet. |
| Docker Desktop on macOS / Windows | Evaluation only, not production | macOS cannot enforce RLIMIT_AS, so worker memory falls back to a 0.25 s watchdog (THREAT_MODEL §1). |
| Source install, Python 3.9 and 3.12 (Linux, macOS, Windows) | Tested in CI | `tests` workflow, 6 jobs green on `93b19f2`. **Decision D6:** Python 3.9 reached end of life in October 2025. |
| Python 3.13 | The lock file is resolved for it | `requirements.lock` header. |
| Python 3.14 | Not supported yet | `requirements.lock` does not install (`backports-zstd==1.8.0` requires < 3.14); see RELEASE_READINESS baseline B3. |
| Desktop binaries (Windows, macOS, Linux) | Only if D2 = yes | Built and smoke-tested by `release.yml`; unsigned. Signing and notarisation need certificates the owner buys. Signing does not remove every OS warning (for example SmartScreen reputation). |

## 5. Explicitly out of scope

- SaaS, hosted service, multi-tenancy, per-tenant isolation.
- Replacing antivirus or EDR: no on-access scanning, no kernel hooks, no prevention before a write.
- High availability or clustering: one instance per customer. Scaling is "more CPU and workers on that host".
- Executing samples in the production profile (emulation; sandbox detonation only on the customer's own CAPE server).
- A shipped ML model, and any published detection rate, until real-sample evaluation in the VM is done.
- Microsoft Graph (Exchange Online without IMAP) mailbox scanning.
- Authenticode **validation** against a trust store in this release. Presence and validity are reported separately (A3); validity is shown as "not verified" unless it was verified.
- Changing scoring weights or YARA / indicator thresholds in v4.7. They need real-sample measurement.
- Windows container images.

## 6. Release acceptance criteria

Every criterion needs evidence in `docs/RELEASE_READINESS.md` (a test, a CI run, a
build log or a documented walk-through) before the release candidate is cut.
Numbers that need measurement are marked **set after measurement**: they are not
invented here.

### Security

| ID | Criterion |
|---|---|
| S1 | Every gate green on the integrated tree: ruff, mypy, bandit (medium/high = fail), pip-audit on the shipped dependencies, coverage ≥ 85 %, the 13-file regression corpus, the registry test, the full suite on Python 3.9 and 3.12. |
| S2 | No secret in logs, reports, results, error messages or the image. Secrets come from the OS keyring (desktop) or environment / Docker secrets (service). |
| S3 | API: a per-IP limit applies before authentication; failed tokens lock out the source IP. Rotating invalid tokens does not reset the limit. Authenticated quotas are kept. Regression tests cover each rule. |
| S4 | The analysis service has no route to the internet, and can reach only the intel service. Intel calls only allowlisted destinations, through fixed operations. Each property has a test. |
| S5 | The analysis container runs non-root, read-only root FS, tmpfs for extraction, capabilities dropped, `no-new-privileges`, default seccomp, CPU / memory / pids limits. |
| S6 | Rule packs: signature, manifest hashes, downgrade and replay are refused. A rollback after a defective update is possible only through a signed rollback, not by accepting older content. Key rotation and compromise recovery are documented. |
| S7 | Quarantine restore and containment resume / unlock need authorisation and are audit-logged. |
| S8 | External sharing (VirusTotal, LLM, sandbox) is off by default. Enabling it is logged at start-up and recorded in every result's provenance. |
| S9 | Supply chain: the SBOM lists what ships in each artifact; third-party GitHub Actions are pinned by commit SHA; every workflow has least-privilege `permissions:`; no required check uses `continue-on-error`. |
| S10 | THREAT_MODEL.md covers parser compromise, malicious archives and rule-pack updates for the shipped design. |

### Result correctness

| ID | Criterion |
|---|---|
| C1 | Every result has `scan_status` (complete, partial, locked, unsupported, failed) and `incomplete_reasons`. The container precedence is documented and tested. |
| C2 | A clean score on a scan that is not `complete` never displays as plain "Clean" in the CLI, GUI, reports or API. |
| C3 | Score, verdict, `scan_status` and the response action are independent. A malicious member keeps its full score when another member is locked. |
| C4 | Provenance in every result and report: engine, rules version / hash, registry, schema, layers run / skipped / disabled with the reason, external services enabled. No secrets. |
| C5 | A rules or configuration change never serves a stale cached verdict (the cache key includes what changes the answer). |
| C6 | The result schema stays backward compatible: additive changes only, minor version bumped, CHANGELOG entry. |
| C7 | Regression corpus verdicts, scores and indicators unchanged (no weight or threshold change in v4.7). |
| M1 | Detection rate and false-positive rate per file type and family: **set after measurement** (owner runs `tools/evaluate.py` in the VM). This criterion stays open until then. |
| M2 | Throughput and p50 / p95 latency per file type on the reference host: **set after measurement**. |

### Install, operate, upgrade, recover

| ID | Criterion |
|---|---|
| O1 | A customer installs from the documented steps (image + compose file + config) with no other help. Documented in a walk-through, done once on a clean host. |
| O2 | Start-up validation stops a wrong configuration with one line per problem. A production configuration with a required layer missing or disabled does not start, and `/ready` says why. |
| O3 | `/health` (process alive) and `/ready` (able to scan correctly) are distinct, and `/ready` lists each layer as up, down or disabled. |
| O4 | Start-up logs enabled and disabled layers and external services. Logs are JSON and metrics are scrapeable. |
| O5 | The release build fails when a required dependency of its flavour (cli, gui, api) is missing. The packaged artifact's capabilities are checked, not only the build machine's. |
| O6 | Graceful shutdown; bounded admission of work; temporary files removed after cancel, worker crash and restart. |
| U1 | Documented upgrade from v4.6.0 to v4.7.0 that keeps configuration, quarantine and keys, and a documented rollback to the previous image. |
| U2 | A rule-pack update can be applied and rolled back (signed) without a new release. |
| R1 | Backup and restore of configuration and the quarantine key, tested end to end. |
| R2 | Runbooks for layer failure, worker failure, disk pressure, outdated rules and a failed update. |
| R3 | Support doc: how a customer reports a false positive and what to send. |
| R4 | Data policy: what can leave the host and when, and the retention of reports and samples. |
| L1 | Third-party dependency and service terms listed for legal review (no legal conclusions drawn here). |

## 7. Work areas

Used by Phase 3 (one branch per area). Copied from the owner's overview doc, with
the files that doc leaves unassigned placed in an area.

| Area | Owns (files) | Tests | Boundary it must keep |
|---|---|---|---|
| A1 Detection content | `rules/`, `detectors/indicators.yaml`, fuzzy signature DB, `tools/build_fuzzy_db.py`, `tools/rulepack.py`, `core/rulepack.py`, `core/allowlist.py` | `test_yara_rules`, `test_registry`, `test_rulepack`, `test_allowlist`, regression corpus | Every rule has a `severity`; every indicator is registered; no weight or threshold change without measurement |
| A2 Documents | `detectors/file_integrity.py`, `macro_analysis.py`, `prompt_guard.py`, `relationship_scanner.py`, `engine/text.py` | `test_file_integrity`, `test_office_hidden`, `test_relationship_scanner`, `test_prompt_guard`, fuzz | Writes `IntegritySignal`, `MacroSignal`, `PromptGuardSignal`, `RelationshipSignal` |
| A3 Executables | `detectors/pe_analysis.py`, `elf_analysis.py`, `ml_classifier.py`, `entropy.py` | `test_pe_analysis`, `test_elf`, `test_ml_classifier` | `PeSignal`, `ElfSignal`, `MlSignal`; packing scored once |
| A4 Containers and delivery | `detectors/container_extractor.py`, `mail_analyzer.py`, `web_content.py`, `embedded_content.py`, `script_analysis.py`, `qr_scanner.py`, `macos_packages.py`, `cfb_writer.py`, `engine/containers.py` | `test_container_extractor`, `test_mail_analyzer`, `test_web_smuggling`, `test_scripts`, `test_qr`, `test_rar`, `test_archive_formats` | `ContainerHandler` hooks; limits on depth, members and bytes |
| A5 Dynamic and intelligence | `detectors/emulation.py`, `llm_backends.py`, `core/sandbox.py`, `core/http.py`, `core/cache.py`, `engine/external.py` | `test_emulation`, `test_sandbox`, `test_http`, `test_cache`, `test_prompt_guard` | Opt-in, scored in its own category, never required |
| A6 Scoring and evaluation | `detectors/scoring.py`, `signals.py`, `registry.py`, `tools/evaluate.py`, `tools/calibrate_weights.py`, `tools/profile_layers.py` | `test_signals`, `test_registry`, `test_calibrate_tool`, regression corpus | Caps and the semantic-only clamp; registry version bumped on change; the score is never called a probability |
| A7 Engine core | `engine/staging.py`, `layers.py`, `scanner.py`, `workers.py`, `config.py`, `validation.py`, `core/tools.py` | `test_pipeline`, `test_staged_pipeline`, `test_workers`, `test_worker_limits`, `test_config_runtime`, `test_tools_path` | Layer guard, isolation, no import side effects |
| A8 Host protection | `core/canary.py`, `canary_watch.py`, `response.py`, `containment.py`, `quarantine.py`, `engine/protection.py` | `test_containment`, `test_response`, `test_canary*`, `test_quarantine`, `test_key_backup` | Never stop system or own processes; every action reversible or logged |
| A9 Interfaces | `RansomwareScanner.py`, `gui.py`, `aegis_gui/`, `api/`, `engine/report.py`, `core/outputs.py`, `core/mailbox.py` | `test_outputs_and_api`, `test_ops_metrics`, `test_mailbox`, `test_report_sections`, GUI smoke | Result schema (`api/scan_result.schema.json`) stays compatible |
| A10 Operations and release | `engine/logs.py`, `engine/metrics.py`, `.github/workflows/`, `build.py`, `scanner.spec`, `requirements*`, `pyproject.toml`, Docker files, `docs/` | Full suite on 3 OSes, quality job, build smoke test | All gates green; CHANGELOG and README updated per release |

## 8. Open decisions for the owner

| ID | Question | Proposal |
|---|---|---|
| D1 | Is this scope (sections 1-5) the first paid edition? | As written. |
| D2 | Does the desktop GUI ship as a supported part of the paid edition? | Yes, as an analyst workstation app on Windows and macOS. |
| D3 | Are canaries and containment part of the paid edition? | No: desktop build only, outside paid support. |
| D4 | Is the VirusTotal hash look-up off by default in the production profile (not only upload)? | Off; one setting turns on look-up, a second turns on upload. |
| D5 | Is Linux arm64 a supported image? | Yes, once it is built and tested in CI. |
| D6 | Python 3.9 is end of life. Keep it in the test matrix for v4.7? | Keep it for v4.7, as the hard rules require; drop it in the next release. |
