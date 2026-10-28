# Data policy: what leaves the host, what is kept

Applies to v4.7. "The host" is the machine (or, in Docker, the deployment) that
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
| Webhook | Yes (needs `WEBHOOK_URL`) | metadata only: verdict, score, SHA-256, indicators - never content; optional HMAC signature | the receiver you configure |
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
configured, and only through fixed operations.

## What is kept, and for how long

| Data | Kept where | For how long |
|---|---|---|
| Files uploaded to `POST /scan` | a private temporary folder (tmpfs in Docker) | deleted when the scan ends; a worker killed mid-scan has its folder removed by the parent |
| Scan results of `/scan` | returned to the client; not stored by the service | - (only counters in `/metrics`) |
| Logs | the log file (`analysis-state` volume) and Docker's container logs | rotated: `LOG_MAX_MB` x (1 + `LOG_BACKUPS`), default 120 MB; Docker logs 5 x 10 MB per service. Log lines include file names, SHA-256 hashes, verdicts and client IP addresses (for lockouts) - never file content, keys or tokens |
| Cache of external answers | `intel-state` volume (Docker) or the data folder (desktop) | `CACHE_TTL_HOURS` (24 h; 6 h for "unknown to VirusTotal"); expired answers are never used and are deleted when the cache opens. Verdicts are never cached |
| Reports | `scan_reports/` (CLI and desktop folder scans only) | until you delete them |
| Quarantined files (desktop) | the encrypted vault (AES-256-GCM) | until restored or deleted by the user |
| Samples | not kept by the product | the evaluation tools (`tools/evaluate.py`) run on samples you hold, in your own analysis VM |

Secrets (API tokens, service keys, the IMAP password) are kept in the OS keyring
on a desktop and in Docker secrets on a server - never in logs, reports, results
or error messages.

## Choices for the customer

* Keep all external services off: detection then runs entirely on the host.
* Prefer `LLM_PROVIDER=ollama` with a model you host over the cloud LLM.
* Enable VirusTotal uploads only if your policy allows sending files to a third
  party; the hash look-up alone sends no content.
