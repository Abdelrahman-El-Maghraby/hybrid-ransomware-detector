# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## [4.4.0-beta.2] — 2026-10-21 (pre-release)

### Added

- **QR codes (quishing):** QR codes in images, PDF pages, Office documents and
  e-mail attachments are decoded and their links judged (bare IP, punycode,
  user-info trick, URL shortener, script scheme; weaker hints such as plain
  HTTP, throw-away TLDs and lure words only count in pairs). Links are defanged
  in reports. Needs an optional decoder: `pyzbar` (plus the zbar library) or
  OpenCV; without one the layer says QR codes were not checked.
- **Linux ELF triage:** header (bits, machine, type, static/dynamic), UPX or
  near-random packing, a removed section table, and behaviour strings (ransom
  note, cryptominer, reverse shell, download-and-run, log/firewall tampering,
  persistence). Checked against 2,388 system binaries with no findings.
- **Script attachments (JS / JSE / VBS / VBE / WSF / HTA / PS1 / BAT / CMD):**
  download, execute, recovery tampering (T1490), ransom-note wording, Defender /
  AMSI tampering and persistence markers; Script Encoder output; obfuscation
  (Chr/fromCharCode chains, eval/Execute, backticks, -join [char]). PowerShell
  `-EncodedCommand` and `FromBase64String` payloads are decoded one level. A
  download plus an execute (a dropper) scores High; either alone stays Low.
  Run over 16,475 scripts on the build machine: 15 High, all of them the same
  browser-installer scripts that really do download and run an installer.
- **Archive passwords from the message:** "Password: 4471" (and the same in
  German, French, Spanish, Portuguese, Italian, Dutch, Polish, Turkish, Arabic
  and Russian) in a mail's subject or body is tried first on its encrypted ZIP /
  7z / RAR attachments. An archive opened this way adds
  `mail_archive_password_in_body` (30, technical): the classic gateway-evasion
  trick of Emotet / Qakbot campaigns.
- **Encoded scripts are decoded:** Windows Script Encoder blocks (`.vbe`,
  `.jse`, encoded blocks in `.hta` / `.wsf`) are decoded and the real source is
  analysed (decoding tables from Didier Stevens' public-domain decode-vbe.py).
- **YARA: 11 new original rules** (21 in total, five files): shortcuts that
  start a script host, HTML Applications, Script Encoder output, OneNote
  notebooks with embedded scripts, LOLBin downloads, Defender tampering, bulk
  stopping of database/backup services, Safe Mode boot, event-log clearing,
  encryptor binaries and Tor ransom notes. Run over 258,666 benign files on the
  build machine: no matches.
- `tools/build_fuzzy_db.py`: build the fuzzy-signature database inside the
  analysis VM from a folder of confirmed samples (family = sub-folder or a
  labels CSV). Near-duplicates are kept once, and with `--benign` every
  signature that matches a known-good file is dropped. The output holds digests
  only.
- `tools/mbox_to_eml.py`: split mbox mailboxes (e.g. public phishing corpora)
  into one `.eml` per message, skipping duplicates.
- 98 new tests (ELF, QR, scripts, HTML smuggling, mail archive passwords,
  Script Encoder, fuzzy-DB tool, mbox tool, staged pipeline, RAR codec); 505 in total. HTML-smuggling detection now has automated tests.

### Changed

- **Generic YARA rules tightened.** The same benign run showed the original
  rules firing on documentation, dictionaries and binaries (1,128 matches,
  outside the PE rule). Ransom-note/extortion rules now need wording addressed
  to the victim plus ransom vocabulary, the Bitcoin rule needs the currency
  named, the PowerShell cradle needs an encoded blob or download + execute, and
  the macro rules only apply to Office binaries, VBA source or small files.
  Matches on the benign set: 1,128 -> under 180, mostly security tools that
  quote these strings (oletools, pygments) and Chromium translation files.
  Regression corpus unchanged.
- **Staged pipeline:** the slow layers (ML, LLM, VirusTotal) run last. When the
  local layers already give the maximum score they are skipped (the verdict
  cannot change) and the report lists them under `[Skipped]`; otherwise they
  run concurrently. Scores are identical to beta.1 on the regression corpus; a
  benchmark with simulated 0.4 s LLM/VirusTotal latency went from 16.6 s to
  6.4 s. Switches: `SKIP_HEAVY_WHEN_SATURATED`, `PARALLEL_HEAVY_LAYERS`.
- **RAR:** when the only extractor is a 7-Zip build without the RAR codec
  (common with `p7zip` on Linux), members are reported as "no RAR codec"
  instead of as encrypted.
- **GUI:** shown as **Aegis Sentinel**; calmer palette, one engine-status panel
  instead of separate cards, and a "Main reasons" column in the results table.
  The repository and package names are unchanged.

### Known limitations

- Scripts are judged statically: a legitimate installer script that downloads
  and runs an installer looks like a dropper.

## [4.4.0-beta.1] — 2026-10-18 (pre-release)

### Added

- **Web content (HTML / SVG):** HTML smuggling (MITRE ATT&CK T1027.006): the
  Blob + object-URL / download construct, with base64 strings and `data:`
  URIs decoded and any executable, archive, disc image or Office payload
  scanned through the full pipeline. Active SVG content, credential forms
  posting to external hosts, external redirects and obfuscation markers.
- **Images:** payloads appended after the image data (PNG, JPEG, GIF, BMP,
  WEBP) and executables renamed to image extensions. Images are supported
  but excluded from folder scans by default.
- **macOS installers:** `.pkg` (XAR + gzip/pbzx cpio, pure Python) and `.dmg`
  (UDIF, through 7-Zip). Installer contents are scanned individually and not
  scored for merely containing programs; oversized content is reported as
  not unpacked instead of as a bomb.
- 62 tests for images, SVG and installers (407 in total).

### Changed

- The random-bytes calibration test tolerates one miss in 200 samples: the
  threshold rejects about 1 in 100,000 random 1 KiB blocks (measured on
  300,000), which made the strict assertion fail about once in 500 runs.

### Known limitations

- HTML-smuggling detection has no automated tests yet (verified manually).
- `.dmg` needs a 7-Zip executable; without it the image is reported as not
  unpacked.

## [4.3.1] — 2026-10-17

### Fixed

- **False "disguised executable" on encrypted documents.** The shebang rule
  accepted `#!/` followed by a single path character, so ciphertext that
  happened to start with `#!/s…` was classified as a script and, behind a
  document extension, scored 90 points. A script now needs a complete
  interpreter line (absolute path, printable arguments, line end within 256
  bytes). On random data the misclassification rate fell from about 1 in 900
  to 0 in 20,000. This was also the cause of an occasional test failure.

### Changed

- The integrity layer validates `.7z` and `.rar` signatures, so a 7z/RAR file
  that ransomware has encrypted in place is reported as encrypted content
  instead of "extension not validated". Archive extensions are never treated as
  a document disguise.
- GUI labels say "archives" / `arc` instead of "zip", since the layer covers
  ZIP, 7z, RAR and ISO.
- README screenshots retaken on v4.3.

## [4.3.0] — 2026-10-16

The two items left open by 4.2.

### Added

- **RAR archives** (RAR 4 / RAR 5, encrypted members and encrypted file names)
  through the optional `rarfile` plus any installed decompressor (7-Zip, unrar,
  unar, bsdtar; 7-Zip and WinRAR are located in Program Files on Windows). The
  decompressor only streams one member to stdout; names, symlinks, sizes and
  limits are handled in Python as for every other format. Headers are parsed
  strictly, so a corrupted header makes the archive unreadable instead of
  looking empty.
- **OLE objects in `.msg` files** (`PR_ATTACH_METHOD = ATTACH_OLE`): packaged
  files (`\x01Ole10Native`) are extracted under the name that actually runs,
  not the icon label; embedded OOXML (`Package`) and PDF (`CONTENTS`) objects
  get their extension from the ProgID or magic bytes; legacy Word/Excel/
  PowerPoint storages are repacked as standalone compound files. Also inside
  forwarded Outlook items.
- `detectors/cfb_writer.py`: the compound-file writer, moved out of the test
  helpers because MailGuard now uses it.

### Changed

- Embedded Outlook items and OLE objects share a storage name; they are now
  told apart by `PR_ATTACH_METHOD`, or by content when it is missing.
- `.rar` is scanned by default.

### Verified

- Golden corpus byte-identical to 4.1.0 / 4.2.0 apart from the version.
- 336 tests (21 new): 335 passed + 1 opt-in GUI test on 3.12; 331 + 5 skipped
  on 3.9 / 3.11 / 3.13. The Linux binary unpacks an encrypted, compressed RAR 5
  with 7-Zip and flags a packaged executable in a `.msg`.

## [4.2.0] — 2026-10-16

Seven items from the 4.1 limitations list, plus the engine refactor below.
Design notes: [`docs/DETECTION_v4.md`](docs/DETECTION_v4.md#v42-additions).

### Added

- **AES-encrypted ZIP, 7z and ISO/IMG archives** (optional `pyzipper`, `py7zr`,
  `pycdlib`), with the same bomb / slip / member limits and delivery-password
  list as ZIP, and nesting across formats. 7z archives with encrypted file names
  are tried against the password list and never reported as empty.
- **Excel and PowerPoint hidden content:** hidden and very hidden sheets, hidden
  rows and columns with text, white and ≤ 2 pt text, hidden shapes and slides,
  text placed off the slide.
- **Outlook items attached to Outlook items** are rebuilt as `.eml` and scanned
  with their own headers and attachments (3 levels).
- **`--export-key` / `--import-key` / `--replace-key`:** passphrase-protected
  backup of the quarantine key (scrypt + AES-256-GCM) with a fingerprint, and
  no silent replacement of a different key.
- **Real-time canary watching** (optional `watchdog`) in `--background` and the
  GUI; verification about a second after a canary is touched.

### Changed

- The ML layer treats KeePass, GPG and age files with a matching extension as a
  known format instead of suspicious random data. The encrypted-content check is
  unchanged on purpose (a forged header must not hide ransomware output).
- Container members are recursed into by type, not by `.zip` suffix.
- `.7z`, `.iso` and `.img` are scanned by default.

### Verified

- The 13-file golden corpus gives byte-identical results to 4.1.0.
- 315 tests (71 new); see the test count per Python version in the PR.

## [4.2.0] — engine refactor (same release)

### Changed

- **Engine refactor, no behaviour change.** The 2,128-line `RansomwareScanner.py`
  is split into an `engine/` package: configuration, the scanner, the scan
  pipeline, containers, LLM/VirusTotal lookups, text extraction and reports.
  `RansomwareScanner.py` stays the CLI entry point and keeps exporting every
  name the GUI and older callers use.
- **The scan is now an explicit pipeline.** `scan_file` went from 286 lines to
  about 20: it runs an ordered list of small layer classes
  (`engine/layers.py`), each recording its result and its scoring signals.
  A new layer is one class plus one line in `default_pipeline()`.
- **One loop for every container.** ZIP and e-mail scanning shared most of
  their code in two copies; both now use `scan_container()` with a small
  handler for what differs (`engine/containers.py`). New container types
  (7z, ISO, nested Outlook items) need only a handler.
- `build.py` reads the version from `engine/config.py` and fails loudly if
  it cannot, instead of silently packaging `0.0.0`.

### Verified

- A fixed corpus of 13 files (documents, a disguised executable, an encrypted
  workbook, a ZIP with zip-slip and double-extension members, `.eml` with a
  nested ZIP, `.msg`) produces byte-identical JSON results and report text
  before and after the refactor.
- All 210 existing tests pass unchanged; 34 new tests cover the pipeline order,
  adding a layer, adding a container type, and the entry point's exports.
  244 passed on Python 3.12; 240 on 3.9, 3.11 and 3.13, where the 4
  scikit-learn tests skip. The Linux binary builds and passes its smoke test.

## [4.1.0] — 2026-10-15

Three additions that were in the v5 plan but never actually built: e-mail
analysis, a static ML layer, and standalone executables. Each is complete,
tested, and wired into the scan pipeline, the scoring matrix, the report and
the GUI. Results from 4.0 keep every key they had.

Design notes: [`docs/DETECTION_v4.md`](docs/DETECTION_v4.md#v41-additions).

### Added

- **MailGuard** (`detectors/mail_analyzer.py`) for `.eml` and Outlook `.msg`.
  - SPF / DKIM / DMARC from the *topmost* `Authentication-Results` /
    `Received-SPF` only (lower copies are sender-controlled and are ignored and
    counted); one passing DKIM signature is enough.
  - Display-name spoofing, Reply-To diversion to another organisation,
    deceptive HTML links (text domain ≠ href domain), lure subjects.
  - Attachments: executables, scripts and macro-enabled Office files, double
    extensions, RTLO names, attached e-mails (saved as `.eml` and scanned
    recursively, including base64-wrapped `message/rfc822` parts). Each
    attachment is extracted to a per-scan sandbox with a sanitised name and
    goes through the full pipeline; the mail is scored like its worst
    attachment. Limits: 50 attachments, 100 MB, 60 MB per message.
  - `.msg` is read stream-by-stream with `olefile` (already installed with
    oletools): subject, sender (SMTP address preferred over Exchange DN),
    transport headers (so the authentication checks work for `.msg` too),
    plain and HTML body, attachments. Plain-text RFC 822 files saved with a
    `.msg` extension are detected and parsed as `.eml`.
  - The message body is handed to the prompt-injection and LLM layers.
  - `.eml` and `.msg` are now default scan types.
- **Static ML classifier** (`detectors/ml_classifier.py`).
  - 15 explainable features (entropy profile, high-entropy window share, PE
    section count/entropy, imported DLLs, packer section names, W+X sections,
    size, null/printable ratios, known-compressed-format flag, extension risk),
    computed from the first 8 MiB with the standard library only.
  - `--train-ml BENIGN_DIR MALICIOUS_DIR` fits a RandomForest and prints
    held-out accuracy, precision, recall, false-positive rate and the confusion
    matrix; the model (joblib) records its feature list and is refused if it
    doesn't match. No model ships with the project.
  - Without a model, a transparent rule engine runs.
  - New **statistical** scoring category, capped at 20 and treated like the
    semantic category (alone it can't exceed Medium). When the file-integrity
    layer has already proved encryption, the ML opinion isn't counted twice.
  - `ML_ENABLED` / `ML_MODEL_PATH` settings; `requirements-ml.txt`.
- **Standalone executables**: `build.py` + `scanner.spec` (PyInstaller).
  - `hrd-scanner` (CLI) and `hrd-scanner-gui` (no console; `.app` on macOS)
    from one shared runtime; folder build by default, `--onefile` optional,
    `--no-ml` drops scikit-learn. UPX off.
  - The build is smoke-tested by running the produced CLI on a clean PDF and a
    disguised executable; the archive gets a `SHA256SUMS` entry.
  - Verified on Linux x86_64: e-mail, `.msg`, YARA rules and a trained model
    all work inside the binary, and the GUI binary starts.
- GUI: MailGuard and ML sections in the result window, `mail` / `spoof!` /
  `ml` tags in the results table, the heuristics card lists the new layers.
- Report: `[Mail]` and `[ML]` lines per flagged file.
- Tests: 65 new (MailGuard incl. real `.msg` compound files generated by
  `tests/msg_builder.py`, ML features/PE parsing/training/persistence,
  end-to-end mail and ML scans, scoring rules, `--train-ml` CLI, launchd
  plist for source vs packaged builds, GUI), passing on Python 3.9–3.13.

### Changed

- Containers are followed up to `max_nesting` (2) levels: mail → ZIP →
  document, ZIP → mail → attachment. Archives were previously unpacked at the
  top level only.
- Running as a packaged build: bundled assets are read from the bundle,
  settings (`.env`) live in `~/RansomwareScanner/`, and autostart / shortcuts
  launch the executable instead of `python script.py`.
- The Settings page shows the full path of the `.env` file it writes.

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
