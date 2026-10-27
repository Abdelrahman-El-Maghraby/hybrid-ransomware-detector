# Architecture overview

A short, defensible tour of how Aegis Sentinel is built and why. Each section
ends with the files to read.

## 1. One file, one context, many independent layers

`RansomwareScanner.scan_file(path)` creates a `ScanContext` (the path, the result
that ends up in the report, and the typed `Signals` only the scoring reads) and runs
the layers of `default_pipeline()` in order. Layers never call each other; they
read what earlier layers left in the context. That keeps each one testable on its
own and makes the order a single, visible list.

```
hashes → allowlist → fuzzy → local-db → macro → yara → integrity → elf → pe → script
→ mail⟲ → prompt-guard → relationships → qr → archive⟲ → web⟲ → embedded⟲
→ [emulation · ml · llm · virustotal · sandbox]   (slow: skipped at 100, else concurrent)
```

⟲ = container: members are unpacked into a temporary folder and scanned through
the whole pipeline again; the container inherits its worst member's evidence.

The facade (`engine/scanner.py`) builds the engines and walks folders; running the
pipeline lives in `engine/staging.py`, quarantine and canaries in
`engine/protection.py`.

*Read:* `engine/scanner.py`, `engine/staging.py`, `engine/layers.py`, `engine/containers.py`.

## 2. Evidence → score: a registry, categories and caps

Every layer fills its typed **signal** (`detectors/signals.py`, one dataclass per
layer; mypy checks the layers that write them and the scorers that read them).
`ScoringMatrix.score()` runs the per-layer scorer functions in `SCORERS` and turns
signals into **contributions** (indicator, category, points, human-readable detail). Points come
from `detectors/indicators.yaml`. Categories are capped (technical 100, reputation
80, semantic 24, statistical 20, dynamic 100), summed, clamped to 100 and mapped to
verdict bands. Two rules make the score hard to game:

- semantic / statistical evidence alone never exceeds Medium (49);
- the LLM category is capped below the Medium ceiling, so a fooled model cannot
  outweigh one structural finding.

Why hand-set weights? There was no labelled data at the start. They are written
down in one place, tested by the regression corpus, and `tools/calibrate_weights.py`
proposes data-driven values (cross-validated) for review.

*Read:* `detectors/indicators.yaml`, `detectors/registry.py`, `detectors/signals.py`,
`detectors/scoring.py`.

## 3. Hostile input is the normal case

- **Bounded everything:** depth, member count, bytes, compression ratio, pixels,
  pages, decoding depth.
- **Guards:** each layer runs in a try-block (`layer_errors`); folder and API scans
  run each file in a worker process with a time and memory limit (`scan_failed`):
  RLIMIT_AS on Linux, a Job Object on Windows, a resident-memory watchdog in the
  parent on macOS.
- **Fail fast on configuration:** importing `engine/config.py` has no side
  effects; entry points call `init_runtime()` and `engine/validation.py` rejects
  out-of-range numbers, unknown choices and conflicting settings at start-up.
- **Fuzzing:** every parser, in CI and with atheris for long runs.

*Read:* `engine/workers.py`, `tests/test_fuzz_parsers.py`, `docs/THREAT_MODEL.md`.

**Saying how far the evidence goes.** A score says what was found; `scan_status` says
how much was looked at: `complete`, `partial`, `locked`, `unsupported` or `failed`,
with one `incomplete_reasons` entry per gap. Containers take their most severe
member status (failed > locked > partial > unsupported > complete). The status
never changes the score, so a locked member cannot hide a malicious one, and a
clean score on an incomplete scan is shown as "Clean (partial scan)", never as
plain "Clean".

*Read:* `engine/completeness.py`, `engine/capabilities.py`.

## 4. Static first, dynamic optional

Everything above is static: no file is executed or rendered, links are never
followed. Behaviour that only shows at run time is the main blind spot. Two opt-in
layers cover part of it, both scored in a separate *dynamic* category: `emulation`
runs JavaScript in box-js against fake WScript objects (URLs, file writes, commands),
and `sandbox` hands suspicious files to the user's own CAPEv2 server. Both execute
attacker code, so both are off by default and meant for an analysis VM.

*Read:* `detectors/emulation.py`, `core/sandbox.py`.

## 5. Privacy by default

Local layers need no network. VirusTotal is hash-only unless uploads are enabled;
the LLM prefers a local Ollama model; the sandbox is self-hosted; webhooks carry
metadata only.

## 6. Interfaces

CLI (`RansomwareScanner.py`), desktop app (`aegis_gui/`), background scheduler with
canary tripwires and containment (`core/response.py`, `core/containment.py`: stop
the writing process, lock folders, cut the network), IMAP mailbox scanning
(`core/mailbox.py`, read-only), JSON Lines and signed webhooks for SIEM/SOAR, and an
optional REST API with abuse limits (`api/limits.py`). All results follow
`api/scan_result.schema.json` (`schema_version`). Operations: structured JSON logs
(`engine/logs.py`) and counters (`engine/metrics.py`, `GET /metrics`); see
`docs/DEPLOYMENT.md`.

## 7. Keeping it trustworthy over time

Quality gates on every pull request (lint including cyclomatic complexity under 20
and lazy log arguments, types, coverage floor, dependency audit, regression corpus); signed rule packs for content updates; tagged releases built in
CI with checksums, an SBOM and Sigstore signatures.

## 8. Design patterns, and why each one is here

| Pattern | Where | What it buys |
|---|---|---|
| **Pipeline** of independent stages | `engine/layers.py` (`Layer`, `default_pipeline()`) | Each layer is testable alone; order is one visible list; a new layer is one class. |
| **Template Method** | `engine/containers.py` (`ContainerHandler`: `applies` / `open` / `items` / `decorate` / `signals`) | Archives, e-mails, web pages and embedded files share one recursion, budget and "worst member" logic; a new container type only fills in the hooks. |
| **Strategy** | `detectors/llm_backends.py` (`LLMBackend` → Ollama / OpenAI / Null); `core/response.py` (`ResponseAction` → stop writers / lock folders / network off / script) | The provider or action is chosen at run time; "no LLM" is a real object, not `if` checks everywhere. |
| **Registry / data-driven configuration** | `detectors/indicators.yaml` + `detectors/registry.py`; `SCORERS` in `detectors/scoring.py`; `FINDING_SECTIONS` in `engine/report.py`; `FORMAT_RULES` in `detectors/file_integrity.py`; `SECTIONS` in the GUI result window | Weights, scorers, report sections and format rules are data: tuning, overriding or adding one does not touch the code around them. |
| **Typed contract (DTOs)** | `detectors/signals.py` | Layers and scorers agree on field names and types statically; a renamed field fails type checking instead of silently scoring nothing. |
| **Facade** | `RansomwareScanner` (`engine/scanner.py`) | CLI, GUI, REST API and tools use one object; the layers behind it can change. |
| **Bulkhead** (process isolation) | `engine/workers.py` (`_IsolatedScan`) | One hostile file can crash or hang only its worker; the scan continues and reports `scan_failed`. |
| **Rate limiter / token bucket** | `api/limits.py` (`TokenBuckets`, `ScanSlots`), `core/http.py` (`RateLimiter`) | Clients and quotas cannot overload the service; rejections are explicit (429 / 503 with `Retry-After`). |
| **Null Object** | `NullBackend`, empty `FuzzyResult` / `YaraResult` when a library is missing | Optional dependencies switch a layer off without special cases in the callers. |
| **Mixins for cohesion** | `StagedPipelineMixin`, `ProtectionMixin`, `ReportMixin`, `ExternalLookupsMixin`, `TextExtractionMixin` | Reporting, network look-ups and text extraction live in their own files instead of one large class. |

Security-relevant conventions: helper programs are resolved with
`core.tools.trusted_which` (never the current directory), ML model files are
refused when another user could have changed them, MD5 is marked
`usedforsecurity=False` (it identifies files; SHA-256 is the security hash), and
the source contains no raw bidirectional control characters.

## Questions this design answers

| Question | Short answer |
|---|---|
| Why not one ML model? | No labelled data for most file types; explainability matters to an analyst; ML is one capped layer. |
| Why can't the LLM decide? | It reads attacker-controlled text. It is spotlighted, capped, and cannot clear technical findings. |
| How do you avoid false positives on compressed files? | Randomness is only tested after the format signature is already missing. |
| What if a parser hangs? | Worker timeout → `scan_failed` (Medium), the scan continues. |
| How are weights justified? | Registry + regression corpus now; calibration from labelled data next. |
| What does it not catch? | Run-time-only behaviour without the sandbox; detection rate on real samples is not yet measured. |
