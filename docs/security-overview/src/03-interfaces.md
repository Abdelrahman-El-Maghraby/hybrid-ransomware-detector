# Interfaces and operating modes

Every interface ends in the same engine call chain: `scan_isolated()`
(`engine/workers.py`), a worker process, the detection pipeline, `ScoringMatrix`, and back
to the calling process. What differs is how files arrive and what happens to the result
afterwards. Diagram 2 (use cases) and diagram 4 (system flowchart) in Appendix C show the
same material graphically.

## The interfaces

**Desktop GUI** (`gui.py`, `aegis_gui/`, Tk). Pages for the dashboard, scans, the hash
database, logs, folder monitoring, outputs, protection (canaries and quarantine), reports
and settings. `ScanController` runs scans on a background thread: a single file through
`scan_one()`, folders through `scan_directory()` or `scan_all_directories()`. The GUI can
stop a running batch (the file in progress always finishes). It checks canaries on a timer,
can run the folder monitor, and uploads queued cloud reports on a timer. [[impl]];
[[local]] only as headless widget tests; [[pending]] on a real display.

**Command line** (`RansomwareScanner.py`). `--scan-file PATH` scans one file;
`--scan-now` runs `run_scan()`: a canary check (when canaries exist), all configured
folders, a report and delivery. Other commands manage canaries (`--deploy-canaries`,
`--verify-canaries`, `--remove-canaries`), containment (`--resume-pid`,
`--unlock-folders`), the quarantine (`--quarantine`, `--list-quarantine`, `--restore`,
`--restore-to`, `--export-key`, `--import-key`, `--replace-key`), rule packs
(`--update-rules`), the allowlist (`--allow`, `--note`), the cache, the IMAP scan
(`--scan-imap`) and the capability report (`--capabilities`). Exit codes: 0 success; 1 an
input error (missing file, database not imported) or a failed command; 2 a tripped canary
(and two other uses the owner chose to keep); 3 isolated workers could not start, so
nothing was scanned.

**Scheduled background operation** (`--background`). A `schedule`-based loop
(`RansomwareScanner.py`): a full `run_scan()` every {{fact:scan_interval_hours}} hours,
and, on a separate scheduler thread so that a long scan does not delay them, canary checks
every {{fact:canary_check_minutes}} minutes, alert-outbox retries every minute, cloud
uploads every 5 minutes with a daily clean-up, and IMAP checks every `IMAP_CHECK_MINUTES`
when set (off by default). It also starts the folder monitor when `WATCH_DIRS` is set.
`--setup-autostart` registers it at login.

**Folder monitoring** (`core/folder_watch.py`, desktop only). With `watchdog`, file events
in `WATCH_DIRS` only *record* a path; nothing is opened on the event thread. A file is
scanned once its size and modification time have been stable for
`WATCH_SETTLE_SECONDS` (2 s); duplicates are skipped by path, size, time and SHA-256. The
queue is bounded (`WATCH_MAX_QUEUE`, 1000); beyond it new paths are dropped, logged and
counted. Links are never followed out of a watched folder, and the application's own
output (reports, quarantine, outbox, worker temp folders, canaries) is never scanned.
Files that could not be scanned are retried after `WATCH_RETRY_MINUTES`.

**IMAP mailbox scanning** (`core/mailbox.py`, desktop and CLI). TLS only (implicit or
STARTTLS, certificates verified); the folder is opened read-only (`EXAMINE`, `BODY.PEEK[]`),
so nothing is marked read, moved or deleted. Each new message (tracked by UID and
`UIDVALIDITY`) is written to a private temporary folder as `.eml`, scanned in an isolated
worker like any file, and deleted. Bounded by `IMAP_MAX_MESSAGES` (200 per run) and `IMAP_MAX_MB` (25 MB per message).

**REST API** (`api/server.py`, FastAPI under uvicorn, one process). Bearer-token
authentication compared in constant time (`hmac.compare_digest`), a per-IP lockout after
repeated bad tokens, per-IP and per-client rate limits, a request-body limit enforced
before authentication, a bounded number of concurrent scans, and a fresh isolated worker
per upload. Endpoints:

| Endpoint | Authentication | Purpose |
|---|---|---|
| `GET /health` | none | liveness (`{"status": "ok"}`) |
| `GET /ready` | optional | readiness: required layers available, isolated workers can start; full detail only with a valid token |
| `GET /version`, `GET /schema` | token | engine, schema and registry versions, profile, external services; the result JSON schema |
| `GET /metrics` | token | counters as JSON or Prometheus text |
| `POST /scan` | token | multipart upload of one file; returns the result JSON |

`POST /scan` admission and failure answers: a scan slot is taken before the body is read
(`AEGIS_API_MAX_CONCURRENT_SCANS`, 2 in the shipped deployments), else **503** with
`Retry-After: 5`; an over-limit declared body gets **413** before authentication; an upload
that is still arriving after `AEGIS_API_UPLOAD_SECONDS` (600 s) gets **408** and releases its
slot (RV-S4); no isolated worker available gets **503** with `Retry-After: 30`; bad tokens get
**401**, and too many get **429**. The stored upload is renamed to a generated name in a fresh
temporary folder, and the response reports the client's file name instead of the server path.

**Docker Compose, Kubernetes base, Kubernetes with option E.** These run the REST API; they
are deployments, not separate interfaces. Chapter 11 describes them. In Docker and in
Kubernetes with option E, external services and e-mail alerts go through a separate
**intel** service; in the Kubernetes base there are none.

## Profiles

`AEGIS_PROFILE=production` (set in the Docker and Kubernetes deployments) makes
`check_config()` refuse to start when a required layer is switched off (QR, ML), when the
YARA rules directory is missing, when emulation is enabled, when `LLM_PROVIDER=auto` could
silently fall back to a cloud LLM, when containment (`CANARY_RESPONSE`) is configured, or
when isolation is disabled (`ISOLATE_SCANS=0`). The default `standard` profile only warns.
Whether each required layer is actually *available* is reported by `GET /ready` and
`--capabilities`.



Outputs and actions differ by interface (the table at the end of this chapter). The
differences are intentional (`docs/architecture/README.md`, section 4):

- A **single-file scan is an inspection**, so it never quarantines automatically; batch
  scans (folders, monitor, IMAP) do, through `collect()` in `_scan_targets()`, when the
  verdict reaches `AUTO_QUARANTINE`.
- The **API never holds the user's file** after answering and never quarantines; in Docker
  its analysis container has no network, so it writes no JSON Lines, sends no webhook and
  uploads nothing; e-mail alerts are sent by the intel container instead.
- A **cancelled GUI batch** writes no report file, but alerts and JSON Lines for the files
  already scanned are still delivered.
- The **monitor** delivers outputs for the files it scanned and retries only the files that
  were not scanned (a fix in this branch; the whole batch used to be held back).

@landscape

## Outputs and actions by interface

| Output or action | GUI | CLI `--scan-file` | CLI `--scan-now` | Background service | Folder monitor | IMAP | REST API |
|---|---|---|---|---|---|---|---|
| Result shown or returned | dashboard and detail pages | console report | console report | — | GUI / log | console report | JSON response |
| Report files (JSON + text) | yes (not for a cancelled batch) | yes | yes | yes | yes | yes | no |
| Structured log, provenance in each result | yes | yes | yes | yes | yes | yes | yes |
| JSON Lines (`JSONL_PATH`) | yes | yes | yes | yes | yes | yes | no |
| Webhook (`WEBHOOK_URL`, HMAC-signed) | yes | yes | yes | yes | yes | yes | no (cleared on purpose) |
| E-mail alert | yes, direct SMTP | yes | yes | yes | yes | yes | yes: via intel (Docker, option E) or direct SMTP |
| Cloud upload (S3, redacted view) | spooled with each report; uploaded by the GUI timer | spooled; uploaded later by GUI or service | spooled | uploaded every 5 min | spooled | spooled | no |
| Automatic quarantine (`AUTO_QUARANTINE`) | folder scans only | no | yes | yes | yes | yes (the temporary `.eml` copy, not the mailbox message) | no |
| Canary check | on a timer | no | before the scan | on a timer, and on events with `watchdog` | — | — | no |
| Containment on a trip (`CANARY_RESPONSE`) | yes, if configured | — | yes, if configured | yes, if configured | — | — | no (refused by the production profile) |

@endlandscape
