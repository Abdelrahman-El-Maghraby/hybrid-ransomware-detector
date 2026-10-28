# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Per-layer capabilities** (`engine/capabilities.py`): every pipeline layer reports `up`, `down` (with what it needs) or `disabled` (with the setting), from the engines the scanner really built. The start-up log lists every layer this way, plus the external services (`llm`, `virustotal`, `sandbox`) and whether each is on. This also fixes the v4.6.0 binaries' start-up log, which did not show the PE layer (`pe:on`).
- **`GET /ready`**, distinct from `/health` (process alive): 200 only when the YARA rules compiled, the indicator registry loaded with every category cap, the report / data / temporary folders accept a file, isolated workers start (a warm-up scan at start-up), and, in the production profile, every required layer is up. Otherwise 503. With the bearer token it lists each check and every layer's state; without it, only `{"ready": ...}`. The API logs ready / not ready at start-up.
- **`AEGIS_PROFILE`** (`standard` or `production`, validated at start-up).
- **Scan completeness** (`engine/completeness.py`, result schema **1.2**, additive): every result has
  - `scan_status`: `complete`, `partial` (an applicable, enabled layer errored, was unavailable or was skipped, or content was not unpacked), `locked` (encrypted content not opened: archive members, password-protected Office files and, newly detected, PDFs that need a user password), `unsupported` (a format with no type-specific analysis), or `failed` (worker timeout, crash or memory limit);
  - `incomplete_reasons`: one `{member_path, layer, reason, status}` per gap;
  - `verdict_label`, e.g. `Clean (partial scan)`.

  A container takes its most severe member status: failed > locked > partial > unsupported > complete. Intended skips (score already 100, allowlisted file, a layer that does not apply to the file type, an optional layer switched off) do not make a scan partial. The status never changes the score, the verdict or the response action: a malicious member keeps its full score next to a locked one.
- **Provenance** in every result (`provenance`, schema 1.2) and in the text report's header (`engine/provenance.py`):
  - engine, schema and registry versions (with `+override`);
  - the YARA rules (bundled / rule pack / custom folder, version, SHA-256 over the compiled files) and the fuzzy-signature database (source, SHA-256);
  - the profile and the external services (`llm`, `virustotal`, `sandbox`: off, or how each is used);
  - the layers disabled or down for this installation, with the reason;
  - for each file, the layers that ran, were unavailable, did not apply, failed or were skipped (with the reason).

  It never contains a key, token, password or service URL. `GET /version` also returns the rules, the profile and the external services.
- A clean score on an incomplete scan never shows as plain "Clean": text reports have a "Scan completeness" line and a "NOT FULLY INSPECTED" section, flagged files list their gaps, the GUI shows the label in the results table and the detail window, and webhooks / JSON Lines carry `scan_status`.
- **Production profile configuration** (`AEGIS_PROFILE=production`): switching off a required layer (`QR_SCAN_ENABLED=0`, `ML_ENABLED=0`), a missing `YARA_RULES_DIR` or `EMULATION_ENABLED=1` stops the program at start-up.
- **GUI:** the result view lists every gap of an incomplete scan (layer, reason, member) and the provenance (rules version and hash, registry, schema, profile, external services, layers that did not run). Settings has a **Diagnostics** section: required layers that are down, configuration warnings, switched-off layers, with Re-check and a copyable report. On first launch the app reports, once, any required layer that cannot run on this computer.
- **Desktop alerts on Windows** (toast notifications through the built-in WinRT API); before, a canary tripwire raised no notification there.
- **What left the machine, per file** (`provenance.shared`, result schema **1.3**, additive): one entry per external service a scan really contacted. VirusTotal records `sha256`, plus `file` when it uploaded; the LLM records `text` and whether it was `local` or `cloud`; the sandbox records `file`. Archive and mail members are included with their path, and an answer from a cache records nothing. The text report has a "Sent outside" line, the GUI shows it per file, and each share is logged (`external_share`, no content).
- **Delay-loaded imports** are read by the PE layer (data directory 13, RVA form): an injection chain bound on first use no longer escapes the import checks, even in a program with no ordinary import table. Results list `delay_loaded_dlls`.
- **Evaluation you can trust** (`tools/evaluate.py`, `tools/calibrate_weights.py`, `tools/splits.py`):
  - files are hashed first; duplicates count once, and files labelled both malicious and benign are left out;
  - a fixed, family-grouped calibration / test split (`--split`), and cross-validation folds grouped by family, so a family is never on both sides;
  - a worst-case detection rate that counts errors and timeouts as misses;
  - a scan-completeness table, and `split` and `scan_status` columns in `results.csv`.
- `--capabilities [cli|gui|api]` prints the layer states as JSON. With a build flavour, it exits 1 when a layer that flavour requires is not up.
- **Docker deployment** (`Dockerfile`, `docker-compose.yml`, `deploy/`): three services from a pinned image.
  - `analysis` runs `aegis-api` with `network_mode: none` (no interface but loopback) and listens on a Unix socket; it holds no external-service secret, and the detection content is mounted read-only.
  - `intel` (`aegis-intel`, `api/intel.py`) is the only service with egress. It offers fixed operations only: VirusTotal hash look-up, upload when `VT_UPLOAD_UNKNOWN` is on, LLM analysis, and sandbox submit and poll of its own tasks. Inputs are validated exactly, the shared `AEGIS_INTEL_TOKEN` is required, each operation is rate-limited, and each external service has a session that refuses every origin outside the configuration, redirects included.
  - `proxy` (Caddy) terminates TLS with the operator's certificate.
  - Every service runs non-root with a read-only root file system, all capabilities dropped, no-new-privileges, Docker's default seccomp profile, memory / CPU / process limits and a size-limited `noexec` tmpfs. Secrets are Docker secrets.
  - `deploy/check-deployment.sh` (run in CI by `docker.yml`) proves the isolation from inside the running containers and scans a file through TLS.
- `AEGIS_INTEL_SOCKET` / `AEGIS_INTEL_TOKEN`: the scanner reaches VirusTotal, the LLM and the sandbox through the intel service; capability states show `... via intel`, or `down` when it is unreachable.
- **Faster API uploads with the same isolation:** `AEGIS_API_SPARE_WORKERS` (default one per scan slot) workers are started ahead and each scans exactly one upload. Small-file latency with uploads 2 s apart: p50 1,399 ms to 257 ms (measured on macOS).
- `AEGIS_API_SOCKET` (serve on a Unix socket), `AEGIS_API_TOKEN_FILE`, `CACHE_DB_PATH`, and `python -m api.probe SOCKET [PATH]` (container health check).

### Fixed / security

- **API authentication throttling.** The rate-limit buckets were keyed on IP address + token, so a client rotating wrong tokens got a fresh bucket for every guess. Now:
  - a per-IP limit applies before authentication (`AEGIS_API_IP_RATE_PER_MINUTE`, `AEGIS_API_IP_BURST`);
  - an address that is locked out is refused before the token is compared;
  - each failed constant-time compare is recorded against the address, and `AEGIS_API_AUTH_FAILURES` failures within `AEGIS_API_AUTH_WINDOW_SECONDS` lock it out for `AEGIS_API_AUTH_LOCKOUT_SECONDS` (429 with Retry-After);
  - a valid token keeps its per-client quota.

  `GET /ready` shows its details only to a valid token, through the same policy, so it cannot be used to guess tokens. Lockouts are logged (`auth_lockout`) and counted in `/metrics` (`auth_failed`, `auth_locked`).

- **Secrets out of `.env`** (`engine/secret_store.py`). The desktop app used to write API keys in plain text into `.env`; it now saves them to the OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service), reads each one back to verify it, and writes nothing to disk when no keyring is available.
  - Precedence: the process environment, or `NAME_FILE` (Docker secrets), then the keyring, then `.env`.
  - First-run migration: secrets in `.env` are written to the keyring and read back. Only when every value matches are their lines removed (atomic rewrite, permissions kept); on any failure `.env` is left untouched and a warning names the secret, never its value.
  - The start-up log shows each secret's source. New dependency: `keyring` (pure Python; added to the lock with its dependencies).

- **Stale answers after a content or configuration change.** Verdicts were never cached, but cached evidence and loaded content could be stale:
  - LLM answers are now keyed by the prompt version and the engine version as well as the back-end and model;
  - VirusTotal answers are keyed by the upload setting, so turning `VT_UPLOAD_UNKNOWN` on is no longer ignored for 6 hours;
  - sandbox reports are keyed by the CAPE server and options;
  - a running scanner reloads the YARA rules, the active rule pack, the fuzzy signatures and the allowlist when they change on disk, before the next top-level scan.

- **Cache poisoning from a scan worker.** In the Docker deployment the scan workers, which open hostile files, read and wrote the result cache. One exploited parser could plant a clean VirusTotal, LLM or sandbox answer for another file. With `AEGIS_INTEL_SOCKET` the analysis side now keeps no cache of external answers. The intel service caches them in its own volume, and only from the real service's reply, keyed by what it derives itself: the requested hash, the hash of the bytes it received, the hash of the text it was given. Without intel (desktop, CLI) the local cache is unchanged.
- **The macOS memory watchdog missed compressed memory.** It read resident size, so a worker filling memory with repetitive data used gigabytes without being stopped. It now reads the physical footprint, which includes compressed memory. The memory-limit test allocated an untouched buffer that macOS never made resident, so it tested nothing there (B5); it now writes the memory it allocates.
- **Temp folders of a crashed scanner stayed behind** (outside Docker): worker folders carry the scanner's process id, and the next scanner removes those of processes that no longer exist.
- **`--resume-pid` acted on any process** and resume / unlock left no log entry. The tripwire now records which processes it suspended, with their program names. `--resume-pid PID|all` resumes only those, refuses a reused pid, and audit-logs each resume and unlock with the OS user.
- **No implicit cloud LLM in the production profile.** `LLM_PROVIDER=auto` falls back to OpenAI whenever the local Ollama is unreachable, so a passing outage could send documents to the cloud. The production profile now requires `none`, `ollama` or `openai`, and the server image defaults to `none`. The intel service now validates its own settings at start.
- **Documents a parser could not read were reported as complete scans.** A damaged PDF or Office file gave empty text that looked like "no text". YARA errors (including its timeout), macro-analysis errors and relationship-scan errors appeared only in a free-text detail. Each now makes the scan `partial` with the parser's error, and these layers' results carry an `error` field. A program merely named `.pdf` is analysed as what it is and stays complete.
- **Containers that could not be opened were reported as complete scans.** A damaged or truncated ZIP, an archive the extractor could not open, and a mail over the analysis size limit (or one that failed to parse) all came back "Clean, complete" with nothing inside inspected. Each is now `partial` with its reason. Scores and verdicts are unchanged.
- **Encrypted RAR with only bsdtar** (as on a stock Mac) said "needs a RAR decompressor" although one was installed. It now says bsdtar cannot decrypt and names 7-Zip, unrar or unar; the archive layer's state and the GUI diagnostics show the same note (B1).
- **Rule packs: no replay of older content, signed rollback, compromise recovery.** `--allow-downgrade` installed any older signed pack, including one whose rules are known to be bypassed. Older packs, or the same pack again, are now always refused. A rollback is a signed pack with a newer version that carries `rollback_of` (`tools/rulepack.py rollback`). Each install records its signing key. Removing a compromised key from `RULEPACK_PUBLIC_KEYS` stops the scanner from using what that key signed, and a pack signed by a new key installs even if the attacker published a huge version (`docs/RULE_PACKS.md`).
- **X-Forwarded-For spoofing behind an appending proxy.** With `AEGIS_API_TRUST_PROXY=1` the first entry was used, which a proxy that appends (nginx `$proxy_add_x_forwarded_for`) takes from the client. Each request could claim a new address and escape the per-address rate limit and the token lockout. The last entry, which the trusted proxy added, is used now.
- **A killed worker's unpacked files stayed in the temp folder.** A worker stopped for the timeout or the memory limit cannot clean up, so repeated hostile files could fill a size-limited `/tmp`. Each worker now has its own temporary folder, which the parent removes.
- **Scanning loaded the containment code.** Validation imported `core.response` on every start. It is now imported only when `CANARY_RESPONSE` is set. The production profile refuses `CANARY_RESPONSE` (containment is desktop-only), and the server image does not contain it.
- **The engine did not start without the optional OCR packages** (`pytesseract`, `pdf2image` were imported unconditionally). OCR is now skipped when they are missing.
- The readiness storage check required the data folder to be writable, which ruled out read-only detection content. It now checks where scans write: reports, the cache, and temporary files.

- The start-up "Detection layers" line did not list `pe:on` (cosmetic; the layer ran; PR #21).

### Release and CI

- Releases include the server images (`aegis-sentinel-server-<version>-linux-amd64.tar.gz`, for `docker load` on an offline host), built and proven by the deployment check first.
- An SBOM per artifact, from the environment it was built in (the image also lists its Debian packages), instead of one SBOM of the lock file; every file is checksummed and Sigstore-signed.
- Every GitHub Action is pinned to a commit SHA, and Dependabot proposes updates. A tag can be moved; a SHA cannot. This matters most in the release job, which can publish and sign.
- mypy in CI runs against every optional package (`requirements.lock`); the 10 errors that only a full install showed are fixed.
- `docs/RELEASING.md`: tagging, what a release contains, verifying signatures, offline install, and the Authenticode / notarisation steps once certificates exist.

### Changed

- The sandbox client has `submit()` and `poll()` steps (`analyze()` uses them), and the LLM back-ends accept an injected HTTP session.
- LLM back-ends mark real failures (API error, unreachable server) with an `error` field, so they count as a partial scan rather than as "nothing to analyse".
- A file over `fuzzy_max_bytes` is recorded in `layer_skips` (the fuzzy layer did not run on it).
- **Builds fail on a missing required dependency** (`build.py`): every package a production-profile layer needs, and the GUI toolkit, must be installed (preflight). The smoke test runs `--capabilities cli` on the packaged program and fails the build, and so the release job, when a required layer is not up in the artifact. A folder build must contain customtkinter. Host tools a desktop binary cannot bundle (a RAR decompressor, the zbar library) are reported, not required; the Docker image must carry them.

## [4.6.0] — 2026-10-26

### Added

- **Windows PE layer** (`detectors/pe_analysis.py`, standard library only):
  - per-section entropy, packer section names and writable+executable sections;
  - the import table parsed by name, with three combinations checked: the process-injection chain, encryption + directory walking + file writing in unsigned programs, and imports resolved only at run time;
  - shadow-copy and backup deletion command lines (T1490) in ASCII and UTF-16. The tools' own help text does not match;
  - the overlay without the Authenticode certificate (a program appended to a program, near-random data that is no known installer);
  - malformed headers;
  - whether a signature directory is present (not verified).

  Nine technical indicators (registry `2026.10.23-1`), a `[PE]` report line and a GUI section. Folder scans now include `.exe`, `.dll`, `.scr`, `.cpl` and `.sys`.
- **Canary containment** (`core/containment.py`, new `CANARY_RESPONSE` actions):
  - `stop_writers` suspends (or, with `CANARY_CONTAIN_MODE=terminate`, kills) the processes that have files open for writing in the canary folders, together with their child processes. Linux uses `/proc` fd + fdinfo, macOS `lsof`, Windows the Restart Manager.
  - Never touched: this tool and its ancestors, system, indexing and antivirus processes, Restart Manager "critical" processes, and other users' processes.
  - `lock_folders` removes write access: `chmod a-w` with the original modes saved on POSIX, a deny ACE for Everyone via icacls on Windows.
  - `controlled_folder_access` turns on Defender's Controlled Folder Access.
  - Actions always run containment first.
  - `--resume-pid` and `--unlock-folders` undo the containment.
  - The real-time watcher passes the paths it saw change.
- **Memory limits on Windows and macOS** for scan workers: a Job Object with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` on Windows, and a parent-side resident-memory watchdog (libproc `proc_pidinfo`) on macOS.
- **Start-up configuration validation** (`engine/validation.py`): ranges, allowed values, URLs, canary actions, IMAP and LLM prerequisites, conflicting settings. Unparseable numbers and booleans in the environment are errors instead of silent defaults. The CLI exits with code 2, the GUI shows a dialog, the API refuses to start.
- **Structured logs** (`LOG_FORMAT=json`, `LOG_LEVEL`) with the events `scan_started`, `scan_completed` (sha256, verdict, risk score, duration), `layer_error` and `scan_batch` (files/s).
- **Runtime metrics** (`engine/metrics.py`): files, bytes, files/s, average scan time, verdict counts, errors per layer, time-outs and crashes, rejected API requests. Exposed as `GET /metrics` (JSON, or `?format=prometheus`). Results carry `scan_duration_ms` (schema 1.1, additive).
- **REST API abuse limits** (`api/limits.py`):
  - upload size enforced before the multipart body is parsed (413);
  - per-client token buckets: 429 with Retry-After;
  - a cap on concurrent scans: 503;
  - `AEGIS_API_TRUST_PROXY` for X-Forwarded-For behind a reverse proxy.
- `docs/DEPLOYMENT.md`: nginx and Caddy TLS configurations, systemd hardening, log shipping and Prometheus scraping.

### Changed

- **Typed signals** (`detectors/signals.py`): one dataclass per layer replaces the untyped signals dict. Layer `run()` methods are annotated, so mypy checks writers and readers. The dict shape is still accepted, and a misspelt field raises.
- **Per-layer scorers**: `ScoringMatrix.score()` is a loop over `SCORERS` plus `_aggregate()`. Indicators, points and details are unchanged.
- **`engine/config.py` has no import-time side effects**: no folders created, no logging configured, `os.environ` not modified (the `.env` file is only read). Entry points call `init_runtime()`.
- **Facade slimmed**: running the pipeline moved to `engine/staging.py`, quarantine and canaries to `engine/protection.py`, and the constructor is split into named setup steps.
- **Complexity**: every function is under cyclomatic complexity 20, enforced by ruff (`C90`, max 19).
  - `detect_format` is a rule table and `image_end` a dispatch of per-format parsers. Both give identical results to 4.5 on 3,713 files and 120,000 random inputs.
  - The GUI result window has one method per section, and `layers_summary` one token function per layer (identical output on 20,000 random results).
  - The macro analyzer is split into steps.
- **Lazy logging**: the 34 f-string log calls pass `%s` arguments, enforced by ruff (`G`).
- **Faster entropy**: byte counts use numpy above 64 KB (15x faster); the ML layer gained about a third.
- A packed program is scored once: the PE layer's packing finding replaces the ML opinion on the same sections (`setup.exe` in the regression corpus: same score, now a technical indicator).

### Fixed / security

- `brotli` locked to 1.2.1 (PYSEC-2026-4322 / GHSA-9v8h-qqgm-4m35).
- `.coverage` is no longer tracked.

### Quality

- 858 tests (+5 opt-in or platform-specific); coverage 91 %. `engine/workers.py` went from 77 % to 96 % and `core/http.py` from 78 % to 100 %.
- Real-process tests: a writer is suspended while a reader is left alone (Linux and macOS); on Windows the holder is found by the Restart Manager and terminated, and the Job Object really caps memory.
- Benign corpus (3,312 files + 401 Windows binaries from PyPI / npm wheels): no new High or Critical. pywin32's `win32process.pyd` is Low, because it really wraps the injection APIs.

## [4.5.0] — 2026-10-22

Includes everything listed under 4.4.1 below (that version was not published
separately).

### Added

- **IMAP mailbox scanning** (`--scan-imap`, `IMAP_*`, `core/mailbox.py`): messages
  are read with their transport headers, so authentication and spoofing checks
  work on mail that saved copies would have stripped. Read-only (EXAMINE +
  BODY.PEEK[]), TLS only with certificate verification, isolated workers, last
  UID per folder (reset on UIDVALIDITY change), per-run and per-message limits,
  scheduled with `--background` and `IMAP_CHECK_MINUTES`. Results carry a
  `mailbox` field and an `imap://user@host/folder;UID=n` path.
- **Canary response actions** (`CANARY_RESPONSE`, `core/response.py`):
  `network_off` (PowerShell Disable-NetAdapter / nmcli / networksetup) and
  `script` (your script, absolute path, owner-only writable, alert JSON on
  stdin). Off by default, time-limited, results written into the alert file.
- **Optional JavaScript emulation** with box-js (`EMULATION_ENABLED`,
  `detectors/emulation.py`): URLs fetched, files written and commands run by
  `.js` / `.jse` files, including URLs built at run time. New dynamic indicators
  `emulated_dropper` (65) and `emulated_network` (25). Off by default because it
  executes the script in a Node sandbox; documented for analysis VMs.


### Added (limits from the README, now closed)

- **Equation Editor 3.0 objects** (CVE-2017-11882 / CVE-2018-0802, still common in
  RTF droppers): YARA rules for RTF (class name in clear or hex-encoded, or the
  CLSID; High) and legacy OLE Office files (Medium: old documents with real
  equations also match).
- **Hidden and "very hidden" sheets in legacy `.xls`** workbooks, read from the
  BIFF8 BOUNDSHEET records (the usual home of Excel 4.0 macro droppers).
- **More encrypted containers recognised** so they are not called "random":
  LUKS volumes and `openssl enc` output, when the extension agrees.

Benign benchmark unchanged: 27 High/Critical and 25 Low on 3,312 files.

### Security

- Helper programs (7-Zip, unrar, unar, bsdtar, notify-send, osascript) are found
  with `core.tools.trusted_which`: absolute PATH entries only, never the current
  directory, and the absolute path is what runs. A planted `7z.exe` in the folder
  being scanned can no longer be started (Windows looks in the current directory
  first, and `shutil.which` did too before Python 3.12).
- ML model files (joblib, i.e. pickle: loading runs code) are refused on POSIX
  when another user owns them or group/others can write them; trained models are
  saved with mode 600.
- The right-to-left-override constant is written as an escape, not as the raw
  character (bandit B613, "trojan source").
- MD5 is created with `usedforsecurity=False` (works on FIPS-mode Python; MD5
  only identifies files, SHA-256 is the security hash).
- bandit runs in CI; medium and high findings fail the build (there are none).

### Changed

- Text report: one small renderer per layer in `FINDING_SECTIONS` instead of one
  200-line method (identical output, checked against the old one).
- CLI `main()` split into parser, overrides, stand-alone commands, banner, setup,
  protection and scan steps (identical behaviour).
- `docs/ARCHITECTURE.md` lists the design patterns used and why.
- Type checking covers every detector (43 files, was 22); the mail, macOS package,
  ML and hidden-content modules were fixed where mypy found unchecked `None` /
  wrong-type paths.

## [4.4.0] — 2026-10-22

Stable release. Everything from 4.4.0-beta.1 and 4.4.0-beta.2 (below), plus the
benchmark fixes in this section. Known limit: the detection rate on real malware
samples has not been measured yet (`tools/evaluate.py`); the numbers below are
about false alarms and speed on benign files.

Measured on 3,312 benign files from a Linux workstation (system binaries, Python /
Node / Go packages, PDFs, HTML, scripts, Windows launchers found in Python
packages) plus 105 documents made with LibreOffice and 100 synthetic e-mails /
archives. The project's own test fixtures were excluded.

| | before | after |
|---|---|---|
| High / Critical on benign files | 160 (4.8%) | 27 (0.8%) |
| Low on benign files | 97 | 25 |
| In-process scan time | 589 s | 91 s (6.5x) |
| Folder scan, 662 files, 2 cores (workers) | 57.5 s | 16.4 s (3.5x) |

The 27 left: 25 browser-installer PowerShell scripts that really download and
silently run an installer, and 2 Go test archives that really contain a symlink
entry (zip slip). Detection on real malware is still unmeasured
(`tools/evaluate.py` in the analysis VM).

### Fixed

- **A 120 KB minified script took 40 s to scan** (and a 300 KB one 140 s): the
  printable-strings pass used a regular expression that is quadratic on long
  lines. Now linear. An attacker could have used this to stall scans until the
  worker timeout.
- **Every Windows program was rated High** by the YARA rule meant for "a program
  disguised as a document". YARA rules now get the file's extension (`file_ext`)
  and that rule skips files named as programs (.exe, .dll, .sys, ...). Programs
  delivered by mail or in archives are still judged by those layers.
- **Archives with more than 500 entries were called decompression bombs** (Go's
  timezone database, an icon set). Now the first 500 are unpacked (programs,
  scripts and nested archives first), the names of the rest are still checked for
  executables and double extensions, and the archive gets the Low indicator
  `archive_partially_scanned`. Bombs are still detected by ratio, size and depth.
- **VBA keywords in HTML manuals** matched the Office macro rules; small web pages
  and text files are no longer treated as macro source.
- **Bitcoin rule on e-mails**: "btc", "pay" and "send" also occur by chance in an
  attachment's base64 next to address-shaped runs; a bare "BTC" now needs a
  ransom word (wallet / decrypt).
- **PDFs looked "random throughout" to the ML fallback** (18% of benign PDFs):
  a PDF whose object structure is intact counts as a compressed format; one that
  keeps only its header (partial encryption) still does not.

### Changed

- ssdeep (pure-Python, ~3 MB/s) is only computed when a loaded fuzzy signature has
  an ssdeep digest; TLSH is always computed.
- PDF text for the injection check and the LLM stops after 50 pages / 200,000
  characters (the LLM reads the first 3,000).
- One shared entropy function (`detectors/entropy.py`) instead of three copies,
  with a table for the per-window counts; the ML printable ratio is computed in C.
- The worker-pool loop is a small class instead of one 100-line function.
- E-mail attachments that the message-level checks flagged (double extension,
  RTLO, program) carry `mail_flags`, like archive members carry `archive_flags`,
  so the desktop app never shows `pay.pdf.exe` as a plainly clean attachment.

### Added

- `tools/profile_layers.py`: time per pipeline layer and the slowest files.

## [4.4.0-beta.2] — 2026-10-21 (pre-release)

### Added

- **QR codes (quishing):** QR codes in images, PDF pages, Office documents and
  e-mail attachments are decoded and their links judged (bare IP, punycode,
  user-info trick, URL shortener, script scheme; weaker hints such as plain
  HTTP, throw-away TLDs and lure words only count in pairs). Links are defanged
  in reports. Needs an optional decoder: `pyzbar` (plus the zbar library) or
  OpenCV; without one the layer says QR codes were not checked.
- **TLSH on Windows:** python-tlsh has no Windows wheels, so Windows installs
  and the Windows release binary fell back to ssdeep alone. A built-in port
  (`detectors/tlsh_py.py`, Apache-2.0, from Trend Micro's TLSH) is used when
  the C library is missing. Its digests and distances are identical (checked
  against python-tlsh on random and real files, plus golden values tested on
  every OS); with numpy it hashes about 8 MB/s.
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
- **Layered script obfuscation:** up to five nested layers are unwound
  (base64 / `-enc`, Chr() / fromCharCode / [char] codes, hex and % escapes,
  split strings, reversal, junk replacement); nesting itself counts as
  obfuscation. 16,464 real scripts: no new High results.
- **OneNote, CHM, MSI, XLL and password-protected Office:** embedded files are
  carved out of OneNote notebooks, CHM help is unpacked (7-Zip), MSI programs and
  script custom actions are extracted, password-protected Office documents are
  opened with msoffcrypto-tool (password from the e-mail, Excel's default, the
  delivery list) - and the content goes through the whole pipeline. XLL add-ins
  are flagged.
- **Allowlist** of known-good SHA-256 hashes (`--allow FILE --note "..."`):
  such files are still scanned and reported, but not scored; a hash in the
  malware database still wins.
- **Optional sandbox (CAPEv2):** with `SANDBOX_URL` set, top-level files the
  static layers rate Medium or worse (or every file, `SANDBOX_SUBMIT=all`) are
  sent to *your* CAPE server; its behaviour signatures enter a new **dynamic**
  scoring category (ransomware behaviour 80; other signatures 25 / 12 / 4 by
  severity, up to 70). Off by default; results cached by SHA-256.
- `tools/calibrate_weights.py`: scans labelled folders (engine only), fits a
  logistic regression on the indicators that fired and proposes points per
  indicator, with detection / false-alarm rates for current vs proposed weights
  (cross-validated). Never applied automatically.
- `tools/build_fuzzy_db.py`: build the fuzzy-signature database inside the
  analysis VM from a folder of confirmed samples (family = sub-folder or a
  labels CSV). Near-duplicates are kept once, and with `--benign` every
  signature that matches a known-good file is dropped. The output holds digests
  only.
- `tools/mbox_to_eml.py`: split mbox mailboxes (e.g. public phishing corpora)
  into one `.eml` per message, skipping duplicates.
- 141 new tests (ELF, QR, scripts and layered encodings, HTML smuggling, mail
  archive passwords, Script Encoder, OneNote / CHM / MSI / XLL / encrypted
  Office, allowlist, sandbox, calibration and fuzzy-DB tools, mbox tool, staged
  pipeline, RAR codec, registry, workers, fuzzing, schema, API, rule packs);
  647 in total (+1 opt-in GUI test). HTML-smuggling detection now has automated tests.

### Engineering

- **Continuous integration:** GitHub Actions runs the test suite and the v3
  smoke test on Windows, macOS and Linux with Python 3.9 and 3.12 for every
  push and pull request (from 4.3.1's CI work, merged into this release).
- **Indicator registry** (`detectors/indicators.yaml`): weights, caps, categories
  and labels in one versioned file; reviewed overrides via `WEIGHTS_OVERRIDE`;
  the calibration tool writes override files.
- **Isolated, parallel folder scans** (`engine/workers.py`): per-file time and
  memory limits; hangs and crashes become `scan_failed` findings; workers never
  re-run the caller's main script. Every layer runs in a guard (`layer_errors`).
  Files are read once and shared by the layers.
- **GUI split** into the `aegis_gui` package (one module per page).
- **Packaging and gates:** `pyproject.toml` with extras, pinned
  `requirements.lock`, quality workflow (ruff, mypy, 85 % coverage floor,
  pip-audit, regression corpus as a test). PyPDF2 replaced by `pypdf`
  (CVE-2023-36464, a parser hang reported by pip-audit).
- **Fuzzing** of every parser (Hypothesis in the suite, atheris harness).
- **Integration:** versioned result schema, JSON Lines (`--jsonl`), HMAC-signed
  webhook, optional REST API (`aegis-api`).
- **Signed rule packs** (`tools/rulepack.py`, `--update-rules`).
- **Release workflow:** three-OS builds, SHA-256 sums, CycloneDX SBOM, Sigstore
  signatures.
- **Threat model** of the scanner itself (`docs/THREAT_MODEL.md`) and an
  architecture overview (`docs/ARCHITECTURE.md`).

### Fixed

- A mutated ZIP (unsupported "version needed" field) made pyzipper raise out of
  the archive layer and ended the scan of that file (found by fuzzing).

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
