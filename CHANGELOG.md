# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## [4.0.0] — 2026-10-15

v4 moves the project from "is this document a weapon?" to "is this document a
weapon, is it lying about what it is, and is ransomware already running?". Four
new detection layers join the scoring matrix, two host-side protections are
added, and the external layers get safer defaults. The v3 smoke test, the GUI,
the JSON report shape and every v3 result key keep working unchanged.

Design notes: [`docs/DETECTION_v4.md`](docs/DETECTION_v4.md).

### Added

- **File-integrity layer** (`detectors/file_integrity.py`). Magic-byte format
  detection vs. the extension; executables disguised as documents (validated
  PE header, ELF, Mach-O, `.lnk`, shebang scripts); **encrypted-content
  detection** (format signature missing + statistically random bytes, using
  size-adjusted Shannon entropy and a chi-square uniformity test, including a
  first-4-KiB check for intermittent encryption). Formats Office opens natively
  under another extension (HTML-as-.xls, RTF-as-.doc, password-protected OOXML)
  are noted, not scored.
- **Hidden-content & prompt-injection layer** (`detectors/prompt_guard.py`).
  Hidden runs, micro fonts and white text in Word files; invisible text (render
  mode 3) in PDFs; injection phrasing aimed at AI analysis, classified as
  *confirmed* (inside concealed content) or *suspicious* (visible text only).
- **Office external-relationship layer** (`detectors/relationship_scanner.py`).
  Remote template injection (T1221), external and Follina-style OLE links
  (CVE-2022-30190), exploit URI schemes (`ms-msdt:`, `search-ms:`, `mhtml:` …),
  NTLM-leaking UNC paths (T1187), RTF remote templates and auto-updating OLE
  links. Reads relationship parts only; never contacts the URLs.
- **Archive layer** (`detectors/container_extractor.py`). Sandboxed, bounded ZIP
  extraction (nested and ZipCrypto-protected archives) with zip-bomb, zip-slip,
  symlink, executable, double-extension and RTLO checks; up to 25 members per
  archive go through the full pipeline and the archive is scored like its
  worst member. `.zip` is now a default scan type.
- **Macro analysis:** VBA-stomping detection (olevba + pcodedmp) and Excel 4.0
  (XLM) macro sheets in BIFF and OOXML workbooks.
- **YARA:** `rules/recovery_inhibition.yar` - shadow-copy deletion and boot
  recovery tampering (T1490). Ten rules ship in total.
- **Canary tripwires** (`core/canary.py`): decoy documents whose deletion,
  modification, encryption or renaming fires an alert file, a CRITICAL log
  entry and a desktop notification (macOS/Linux). Checked every 5 minutes by
  `--background` and by the GUI. CLI: `--deploy-canaries`, `--verify-canaries`
  (exit code 2 when tripped), `--remove-canaries`.
- **Encrypted quarantine vault** (`core/quarantine.py`): chunked AES-256-GCM
  with per-file HKDF keys, authenticated header/chunks/end-of-file frame,
  verify-before-delete, non-clobbering restore. CLI: `--quarantine`,
  `--list-quarantine`, `--restore [--restore-to]`. Optional
  `AUTO_QUARANTINE=high|critical`.
- **Ransomware-impact section** in reports: encrypted-looking files plus ransom
  notes and ransomware extensions seen while walking folders.
- **Result cache** (`core/cache.py`): VirusTotal and LLM answers cached by
  SHA-256 in SQLite (WAL); `--no-cache`, `--clear-cache`.
- **More file types:** `.docm`, `.dotm`, `.xlsx`, `.xlsm`, `.xls`, `.pptx`,
  `.pptm`, `.ppt`, `.rtf`, `.zip`, with OOXML text extraction for the LLM.
- **GUI:** Protection page (canaries, vault with restore/delete, automatic
  quarantine, cache), a third row of dashboard cards, detail sections for every
  new layer including per-member archive results, a *Quarantine file* button,
  canary alerts while the window is open, the VirusTotal-upload switch, and all
  file types on the Scan page.
- **Test suite** (`tests/`, pytest): 145 tests plus an opt-in GUI test, all on
  synthetic samples, passing on Python 3.9, 3.11, 3.12 and 3.13.
- `--version` flag; `engine_version` in every result.

### Changed

- **VirusTotal is hash-lookup only by default.** v3 uploaded every unknown file,
  which shares private documents with VirusTotal and its Enterprise
  subscribers. Uploading is now opt-in (`VT_UPLOAD_UNKNOWN=true` or the GUI
  switch).
- **LLM prompts are spotlighted:** document content is wrapped in per-request
  random delimiters, look-alike tags are neutralised, and model replies are
  validated more strictly (confidence clamped to 0-1, non-object JSON rejected).
- Default scan types now include the Office, RTF and ZIP formats above.
  Existing GUI users keep their saved selection; tick the new types on the Scan
  page.
- OCR runs only when an LLM backend is active (it only feeds the LLM).
- Text extraction failures return empty text instead of sending the error
  message to the LLM as "document content".
- String extraction is regex-based and bounded (it used to loop over every
  byte in Python).
- Office lock files (`~$*.docx`) and canary files are skipped during scans.
- Expected-but-harmless conditions (non-PDF content under `.pdf`, non-Office
  content under an Office extension) are logged as warnings, not errors.
- `Embedded_Executable_In_Document` YARA rule description now matches what it
  detects (a PE masquerading as a document).

### Fixed

- **External calls had no timeout.** A stalled VirusTotal request could hang a
  scheduled scan (or the GUI worker thread) indefinitely. Every call now has a
  timeout, GETs retry with backoff on 429/5xx, and requests are paced to the
  API quota.

## [3.0.0] — 2026-06-14

The detection engine grows from **three layers to seven**, all fused through a
new **transparent weighted scoring matrix**. The CLI, the GUI, the reports, and
the existing smoke test all keep working unchanged — every new layer is
additive and degrades gracefully when its dependency is absent.

A deeper write-up of each layer and the scoring design lives in
[`docs/DETECTION_v3.md`](docs/DETECTION_v3.md).

### Added

- **Fuzzy / structural hashing** (`detectors/fuzzy_hash.py`). TLSH + ssdeep
  (via the pure-Python `ppdeep`) digests, matched against a JSON signature
  database of *confirmed* malicious samples. Catches polymorphic variants whose
  exact SHA-256 has never been seen. New CLI helper `--fuzzy-hash <file>` prints
  a sample's digests for populating the database; a documented placeholder DB
  ships as `fuzzy_signatures.sample.json`.
- **VBA / XLM macro analysis** (`detectors/macro_analysis.py`). Static `olevba`
  triage of embedded Office macros — **never executed** — bucketed into auto-run
  triggers, execution/download primitives, other suspicious calls, and IOCs.
- **YARA rules engine** (`detectors/yara_engine.py`, `rules/`). Compiles every
  `.yar`/`.yara` file in a rules directory and scans each file, reading a
  `severity` meta from each rule. Ships eight original triage rules across
  `ransomware_generic.yar` and `office_dropper.yar`. Records only matched string
  identifiers, never raw matched bytes.
- **Local-first LLM backend** (`detectors/llm_backends.py`). Pluggable semantic
  layer: a local **Ollama** model is preferred for OPSEC so documents never
  leave the machine, with a cloud (OpenAI) fallback only when no local model is
  reachable *and* a key is set. Cloud egress is logged. Selectable via
  `LLM_PROVIDER` (`auto` | `ollama` | `openai` | `none`) or the new
  `--llm-provider` flag.
- **Weighted scoring matrix** (`detectors/scoring.py`). Replaces the hardcoded
  severity equation. Every signal contributes through an explicit rule with a
  category (technical / reputation / semantic), a weight, and a human-readable
  detail. Produces a granular **risk score (0–100)** with verdict bands
  (Clean / Low / Medium / High / Critical) alongside the legacy 0–10 score.
- **`--scan-file <path>`** CLI flag — scan a single file and print its full
  multi-layer verdict.
- **GUI surfaces every layer.** The dashboard gains status cards for fuzzy
  hashing (signature count), macro analysis, and YARA (rule-file count); the LLM
  card shows its LOCAL vs CLOUD posture. Result rows now show a 0–100 risk bar
  and the verdict band with a compact all-layer summary, and the detail window
  adds fuzzy/macro/YARA sections plus the **weighted score breakdown** explaining
  each verdict. The GUI degrades gracefully for legacy reports that predate these
  fields.
- New configuration: `LLM_PROVIDER`, `OLLAMA_HOST`, `OLLAMA_MODEL`,
  `OPENAI_MODEL`, `FUZZY_SIGNATURE_DB`, `YARA_RULES_DIR` (all env-overridable);
  documented in `.env.example`.
- Smoke-test coverage for the scoring matrix (incl. the technical-over-semantic
  guarantee and the semantic-only clamp) and graceful degradation of the new
  engines.

### Changed

- **Scoring is no longer hardcoded.** The previous
  `severity = 10·db + 5·llm + 5·vt` gave a semantic guess the same weight as
  multi-engine reputation and could not express that a real exec primitive
  matters more than a suspicious sentence. The matrix now guarantees that
  technical evidence outweighs semantic evidence, and that a semantic-only hit
  can never exceed the **Medium** band.
- **Reports are richer.** `generate_report()` now groups flagged files by
  verdict band (most severe first) and lists concrete per-layer evidence plus
  the weighted score breakdown that explains each verdict. The machine-readable
  JSON keeps its previous shape.
- **Startup banner** now shows which detection layers are active and the current
  LLM posture (LOCAL vs CLOUD).
- `analyze_with_chatgpt()` is now a thin alias over the provider-agnostic
  `analyze_with_llm()` (kept for backward compatibility).
- `requirements.txt` documents the new optional dependencies and the Ollama
  setup; all wheels remain x86_64 + ARM64 with no compiler required.

### Fixed

- **Macro analyser false positives on non-Office files.** `olevba`'s parser
  would treat an arbitrary file (a plain `.txt`, or even a `.pdf`) as candidate
  VBA source and report phantom macros. Macro analysis is now gated to real
  Office document extensions, so PDFs and text files no longer show spurious
  "macros present" findings. (The weighted score was already robust to this —
  empty primitive lists contributed nothing — so verdicts are unchanged.)

### Security / privacy

- **OPSEC by default:** potentially sensitive documents are analysed by a local
  model unless you explicitly opt into the cloud.
- Macros are parsed statically and **never executed**.
- YARA output and the scoring breakdown expose rule/indicator names only — never
  raw matched content (privacy + copyright hygiene).
- The prompt-injection hardening of the LLM layer (system/user role separation,
  `temperature = 0`) is preserved across both the local and cloud backends.

### Backward compatibility

- Every result key the GUI reads (`scan_results`, `local_database`,
  `chatgpt_analysis`, `is_malicious`, `md5_hash`, `sha256_hash`,
  `severity_score`, …) is still produced; new keys (`risk_score`, `verdict`,
  `score_breakdown`, and the `fuzzy_hash` / `macro_analysis` / `yara` subkeys)
  are additive.
- A pure local-DB hit still scores exactly `severity_score == 10.0`; a clean
  file `0.0`. The legacy `scan_directory(dir)` / `scan_all_directories()`
  signatures, the progress-callback contract, cancellation, and the JSON+TXT
  report output are unchanged.

## [2.0.0] — earlier

- Cross-platform **desktop GUI** (`gui.py`, CustomTkinter) using the scanner as
  a library, with live progress, per-layer breakdown, report browser, dataset
  import, log stream, and settings.
- **Cross-platform autostart at login** (Windows registry, macOS launchd, Linux
  systemd user service with cron fallback) and optional desktop shortcuts.
- Memory-efficient chunked hashing, streamed-CSV hash database, OCR fallback for
  scanned PDFs, graceful degradation, and prompt-injection hardening of the LLM
  layer. Hardcoded credentials removed in favour of a git-ignored `.env`.

## [1.0.0] — graduation project

- Initial three-layer scanner (local MD5 hash database, VirusTotal reputation,
  OpenAI semantic analysis) for PDF and Word documents, with a single 0–10
  severity score and JSON/TXT reports. B.Sc. graduation project (Grade: B+).
