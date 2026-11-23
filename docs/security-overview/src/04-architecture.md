# Architecture and repository map

## The main objects and who owns what

**`RansomwareScanner`** (`engine/scanner.py`) is the facade every entry point uses. It
builds the detection engines from the configuration, walks folders, runs scans and keeps
the per-scanner state (allowlist, hash database, provenance, layer states). Its behaviour
comes from five mixins, inherited in this order:

| Mixin | File | Responsibility |
|---|---|---|
| `StagedPipelineMixin` | `engine/staging.py` | `scan_file()`: runs the pipeline over one file, groups heavy layers, merges their results, `_assemble()` scores and assesses |
| `ProtectionMixin` | `engine/protection.py` | quarantine, automatic quarantine after batch scans, canary deployment and checks, the canary alert and containment call |
| `ReportMixin` | `engine/report.py` | text and JSON reports; spools the cloud upload view |
| `ExternalLookupsMixin` | `engine/external.py` | the LLM call (prompt building, caching) and VirusTotal (lookup, optional upload, pacing, caching) |
| `TextExtractionMixin` | `engine/text.py` | visible text from PDF, Office and web pages, OCR fallback, printable strings |

The scanner **owns** (creates and keeps): `pipeline`, the {{fact:layer_instances}} `Layer`
objects from `default_pipeline()`; `scoring`, a `ScoringMatrix`; sixteen detection engines,
one attribute each (`fuzzy_hasher`, `macro_analyzer`, `yara_engine`, `integrity`,
`elf_analyzer`, `pe_analyzer`, `script_analyzer`, `mail_analyzer`, `prompt_guard`,
`relationship_scanner`, `qr_scanner`, `container_extractor`, `web_analyzer`,
`embedded_analyzer`, `ml`, `emulator`; `qr_scanner`, `ml` and `emulator` are `None` when
switched off);
`llm_backend` (`NullBackend`, `OllamaBackend`, `OpenAIBackend` or `IntelLLMBackend`);
`sandbox` (`CapeClient`, `IntelSandbox` or `None`); `intel` (an `IntelClient` or `None`);
`canaries` (`CanaryManager`); the quarantine vault (created on first use); and `cache` (a
`ResultCache`, only when there is no intel service: a cache the scan workers could write
would let one exploited parser plant clean answers).

**The pipeline.** `engine/layers.py` defines `Layer` (a `name`, a `heavy` flag and
`run(scanner, ctx)`) and its {{fact:layer_classes}} subclasses. `ContainerLayer` is
instantiated four times, once per `ContainerHandler` (`MailHandler`, `ArchiveHandler`,
`WebHandler`, `EmbeddedHandler`), which is why {{fact:layer_classes}} classes give
{{fact:layer_instances}} layers. **A layer never calls another layer.** It reaches its
engine through the scanner (`YaraLayer` calls `scanner.yara_engine`) and writes into the
shared context. The order is data: `ORDER_RULES`, `FAST_BEFORE_HEAVY` and `SANDBOX_LAST`
state which layer reads what an earlier one produced, and `pipeline_order_problems()`
(tested in `tests/test_pipeline.py`) fails when the order breaks them.

**`ScanContext`** carries one file through the pipeline: the path of the bytes and the
display name (`invoice.eml!/docs.zip!/pay.js`), the depth, type flags (`is_archive`,
`is_mail`, `is_web`, `embedded_kind`), a shared in-memory copy of the file up to
{{fact:shared_read_mib}} MiB, the hashes, the extracted text and strings, the `Signals`, the
result dictionary with its `scan_results`, and three lists of bookkeeping: `layer_log`
(what ran), `member_reasons` (completeness gaps of members) and `member_shared` (what
members sent outside).

**`Signals`** (`detectors/signals.py`) is the scorer's view: {{fact:typed_signals}} typed
dataclasses, one per layer that produces evidence (from `FuzzySignal` to
`EmulationSignal`), three flags (`allowlisted`, `local_db_hit`, `scan_failed`) and an
`extra` map for third-party layers. Container signals carry `.worst`, the worst member's
contributions.

**Scoring.** `ScoringMatrix.score(signals)` runs {{fact:scorers}} scorer functions
(`SCORERS` in `detectors/scoring.py`), each turning one signal into `Contribution`
objects (indicator, category, points, detail), then caps and adds the categories. Weights,
caps and labels come from `detectors/indicators.yaml` (registry {{fact:registry_version}});
`weights_override` can load reviewed proposals. Chapter 7 covers the rules.

**Isolation.** `scan_isolated()` creates an `_IsolatedScan`, which owns a pool of
`_Worker` objects, each wrapping a spawned process that builds its own
`RansomwareScanner`. Each `_Worker` owns an `Evidence` record (container and member
findings reported before the file finished) and, on macOS, a `Descendants` tracker
(`engine/helper_processes.py`) that finds and stops helper programs the worker started
(7-Zip, Tesseract, box-js). Workers talk to the parent over a pipe in size-limited JSON.

**Results.** `engine/completeness.py` assesses `scan_status`; `engine/provenance.py`
records what ran and what was shared; `engine/report.py` writes reports;
`api/scan_result.schema.json` is the result contract (schema {{fact:schema_version}}).

**Delivery.** `core/outputs.py` (JSON Lines, webhook payload and HMAC signature),
`core/outbox.py` (the persistent alert outbox), `core/mailer.py` (metadata-only e-mail),
`core/cloud.py` (redacted S3 upload view and spool).

**Protection.** `core/quarantine.py` (`QuarantineVault`), `core/canary.py`
(`CanaryManager`), `core/canary_watch.py` (event-driven checks), `core/response.py` and
`core/containment.py` (actions after a trip).

**Services.** `api/server.py` (the REST API: `_ScanService`, `_Alerts`, `ScanSlots`,
middleware from `api/limits.py`), `api/intel.py` (the intel service: the only component
that holds external-service credentials in Docker and Kubernetes), `core/intel_client.py`
(the client side: one transport, either a Unix socket or HTTPS to a fixed address with a
private CA), `api/probe.py` (health probe over the socket). TLS for clients is terminated
by Caddy (`deploy/Caddyfile`, and an intel-side Caddyfile in
`deploy/kubernetes/components/intel/`), which forwards to the Unix sockets.



## Repository map: where each responsibility lives

| Responsibility | Start here | Then |
|---|---|---|
| Entry points | `RansomwareScanner.py` (CLI, background loop), `gui.py` + `aegis_gui/app.py` | `aegis_gui/integration.py` (`ScanController`) |
| Configuration and validation | `engine/config.py` (`CONFIG`, defaults, paths) | `engine/validation.py` (`check_config`, profiles), `engine/secret_store.py` (keyring) |
| One file through the pipeline | `engine/staging.py` (`scan_file`, `_run_heavy`, `_assemble`) | `engine/layers.py` (`ScanContext`, every `Layer`, `default_pipeline`) |
| Containers and recursion | `engine/containers.py` (`scan_container`, handlers) | `detectors/container_extractor.py`, `mail_analyzer.py`, `web_content.py`, `embedded_content.py`, `macos_packages.py` |
| Static detectors | `detectors/*.py`, one module per layer | `rules/*.yar` (25 YARA rules), `detectors/indicators.yaml` |
| Scoring | `detectors/scoring.py` | `detectors/signals.py`, `detectors/registry.py`, `tools/calibrate_weights.py` |
| Completeness and provenance | `engine/completeness.py` | `engine/provenance.py`, `engine/capabilities.py` (layer states) |
| Isolation and limits | `engine/workers.py` | `engine/helper_processes.py`, `engine/fsutil.py` |
| External services | `engine/external.py`, `detectors/llm_backends.py`, `core/sandbox.py` | `core/intel_client.py`, `api/intel.py`, `core/http.py`, `core/cache.py` |
| Alerts and outputs | `core/outputs.py`, `core/outbox.py` | `core/mailer.py`, `core/cloud.py` |
| Host protection | `engine/protection.py` | `core/quarantine.py`, `core/canary.py`, `core/canary_watch.py`, `core/response.py`, `core/containment.py` |
| REST API | `api/server.py` | `api/limits.py`, `api/probe.py`, `api/scan_result.schema.json` |
| Deployment | `Dockerfile`, `docker-compose.yml`, `deploy/` | `deploy/kubernetes/` (base, `components/intel`, overlays, `check_manifests.py`, `isolation_gate.py`, `verify-cluster.sh`) |
| Content updates | `core/rulepack.py` (signed rule packs) | `tools/rulepack.py` |
| Evaluation tooling | `tools/evaluate.py`, `tools/splits.py` | `docs/DATASET_PLAN.md` |
| Tests | `tests/` (141 files, 2,190 collected tests at this baseline) | `tests/worker_fakes.py`, `tests/fp_examples.py`, `test_smoke.py` |

Graphify (a static code graph) was used only to navigate; a fresh code-only build of
`e012d3f` named the same hubs. Every relationship above was read in the source.

@diagram 1-class-diagram.svg | Diagram 1 - class diagram: the scanner, its mixins, the pipeline, scoring, isolation and the engines. Hollow triangles are inheritance, filled diamonds composition. | landscape
