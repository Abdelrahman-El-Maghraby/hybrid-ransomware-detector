# Data policy: what leaves the host, what is kept

Applies to v4.8. "The host" is the machine (or, in Docker, the deployment) that
runs the scanner. Settings are the ones in `.env.example` / `docs/OPERATIONS.md`.

## What can leave the host

Nothing leaves unless an external service is configured. There is no telemetry,
no update check and no call home. With every external setting at its default,
the only network traffic is the API answering its own clients.

| Service | Off by default? | What is sent, when | Where to |
|---|---|---|---|
| VirusTotal hash look-up | Yes (needs `VIRUSTOTAL_API_KEY`) | the SHA-256 of each scanned file, archive and mail members included | VirusTotal (Google); in Docker only from the intel service |
| VirusTotal upload | Yes (needs the key **and** `VT_UPLOAD_UNKNOWN=true`) | the whole file, only when its hash is unknown to VirusTotal | VirusTotal; what VirusTotal does with uploaded files is governed by its terms (`docs/THIRD_PARTY.md`) |
| LLM analysis | Yes (`LLM_PROVIDER=none` in the server image; the production profile refuses `auto`) | up to about 5,000 characters per file: visible text and printable strings | `ollama`: the Ollama host you configure (local or on your network); `openai`: OpenAI's API (cloud) |
| Sandbox | Yes (needs `SANDBOX_URL`) | the whole file; top-level files only, and with `SANDBOX_SUBMIT=suspicious` (default) only files the static layers rate Medium or worse | your own CAPEv2 server |
| Webhook | Yes (needs `WEBHOOK_URL`) | metadata only: verdict, score, SHA-256, indicators, the file path, and since 4.8 canary trips (the canary paths and what changed) and the automatic quarantine taken (vault id) - never content; optional HMAC signature | the receiver you configure |
| E-mail alerts (4.8) | Yes (needs `SMTP_HOST`, `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`) | metadata only, in a fixed template: alert id, kind (verdict or canary), verdict, risk band, SHA-256, the file **name** (not the path; cleaned and truncated), time, scan id, reason codes (indicator names, `quarantined`). No content, no attachment. Over TLS with certificate verification | your SMTP server and the configured recipients (and therefore your mail provider). In Docker only the intel service sends |
| Cloud storage of reports and logs (4.8, desktop) | Yes (`CLOUD_UPLOAD=false`) | a redacted upload view, see below | the S3-compatible bucket you configure, over HTTPS |
| IMAP (desktop / CLI) | Yes (needs `IMAP_HOST`) | read-only login to your mailbox over TLS | your mail server |

**How you can see it.**
* The start-up log line `External services -> llm:... virustotal:... sandbox:...`.
* Every result's `provenance.external_services` (how each is configured) and
  `provenance.shared`: what this scan actually sent, per service (`sha256`, `file`,
  `text`; `local` or `cloud` for the LLM), members included. An answer served from
  a cache sent nothing and records nothing.
* The text report's "Sent outside" line, and the `external_share` log event per
  file (service and kind of data, never the content).

In the Docker deployment the analysis service, which opens the files, has no
network at all; only the intel service can reach the services above, only those
configured, and only through fixed operations. Cloud storage is not available in
Docker; the server keeps its own log shipping.

### Cloud storage: what is uploaded and what is not

Uploads are built from an explicit allowlist (`core/cloud.py`), not from the local
files with parts removed, so a new result field is never uploaded until it is added
there on purpose.

**Never uploaded, in any mode:** scanned files or any part of their content, the
quarantine vault and its key, the alert outbox, the result cache, the log files
themselves.

**Removed from what is uploaded (by default):** full paths, folder names and file
names - of scanned files, archive members, attachments and embedded objects - user
and host names, and free text: log message text, indicator detail strings,
extracted strings, URLs, e-mail addresses and subjects. A file is identified by a
keyed pseudonym (HMAC-SHA-256 of its path with a per-installation key kept in the OS
keyring and never uploaded), so the same file can be followed across uploads
without its name.

**The metadata that remains:**
- file facts: SHA-256 and MD5, size, detected type and extension;
- scan outcome: verdict, risk and severity scores, indicator and YARA rule ids with
  their category and points, layer states, `scan_status` and the status and layer of
  each gap;
- provenance: engine, schema, registry and rule-pack versions, profile, isolation;
- identifiers: timestamps, an installation id (random, made once), OS family, app
  version;
- logs: structured events only - event type, level, time, verdict, risk score,
  durations, counts, layer, `scan_status`, SHA-256.

Anyone who already has a file can match it to an uploaded hash.

**Full detail** (`CLOUD_UPLOAD_FULL=true`, off by default) uploads the full results
instead - with paths and file names, still never file content. It is recorded in
every upload (`full_detail: true`), logged as a warning at start and flagged by the
configuration check and the GUI.

**Remote retention** is set on the bucket by its operator, not by the product: the
recommended lifecycle rule deletes objects after 90 days (`docs/OPERATIONS.md`). The
product never lists, reads or deletes remote objects, so it cannot check or enforce
that rule. To delete uploaded data, delete the objects under
`<prefix>/<installation id>/` in the bucket. Uploads are not tamper-evident: an
uploaded report is only as trustworthy as the host that produced it
(`docs/THREAT_MODEL.md`, TMA-7).

## What is kept, and for how long

| Data | Kept where | For how long |
|---|---|---|
| Files uploaded to `POST /scan` | a private temporary folder (tmpfs in Docker) | deleted when the scan ends; a worker killed mid-scan has its folder removed by the parent |
| Scan results of `/scan` | returned to the client; not stored by the service | - (only counters in `/metrics`) |
| Logs | the log file (`analysis-state` volume) and Docker's container logs | rotated: `LOG_MAX_MB` x (1 + `LOG_BACKUPS`), default 120 MB; Docker logs 5 x 10 MB per service. Log lines include file names, SHA-256 hashes, verdicts and client IP addresses (for lockouts) - never file content, keys or tokens |
| Cache of external answers | `intel-state` volume (Docker) or the data folder (desktop) | `CACHE_TTL_HOURS` (24 h; 6 h for "unknown to VirusTotal"); expired answers are never used and are deleted when the cache opens. Verdicts are never cached |
| Reports | `scan_reports/` (CLI and desktop folder scans only) | until you delete them |
| Quarantined files (desktop) | the encrypted vault (AES-256-GCM) | until restored or deleted by the user |
| Alert outbox (4.8) | `OUTBOX_DIR` (app folder; `analysis-state` in Docker), one owner-only file of alert metadata per alert | until delivered, at most `OUTBOX_MAX_AGE_HOURS` (24 h); an expired alert is dropped and logged. A `sent/` marker (the alert id only) is kept for the same time to stop duplicates |
| Cloud spool (4.8, desktop, only with cloud on) | `CLOUD_SPOOL_DIR` (app folder), owner-only copies of the upload view | removed at once after a confirmed upload; otherwise at most `CLOUD_SPOOL_DAYS` (30) and `CLOUD_SPOOL_MAX_MB` (1024, oldest first); each deletion is logged. Turning cloud off keeps what is spooled until it expires; nothing is deleted remotely |
| Installation id and pseudonym key (4.8, only with cloud on) | `installation_id` in the app folder; the key in the OS keyring (an owner-only file where there is none) | for the life of the installation; deleting them makes later uploads unlinkable to earlier ones |
| Samples | not kept by the product | the evaluation tools (`tools/evaluate.py`) run on samples you hold, in your own analysis VM |

Secrets (API tokens, service keys, the IMAP and SMTP passwords, the cloud secret key) are kept in the OS keyring
on a desktop and in Docker secrets on a server - never in logs, reports, results
or error messages.

## Choices for the customer

* Keep all external services off: detection then runs entirely on the host.
* Prefer `LLM_PROVIDER=ollama` with a model you host over the cloud LLM.
* Enable VirusTotal uploads only if your policy allows sending files to a third
  party; the hash look-up alone sends no content.
* E-mail alerts put file names and hashes in your mail system; use the webhook to a
  SIEM instead if that is not acceptable.
* Keep cloud storage off unless reports must leave the host; if it is on, keep
  full detail off, set the bucket's 90-day lifecycle rule, versioning or object lock,
  and a credential that can only create objects under this installation's prefix.
