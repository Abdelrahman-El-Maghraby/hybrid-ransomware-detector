# Runbooks

For the Docker deployment (`docs/OPERATIONS.md`). Each runbook: how you notice,
how to confirm, what to do. Commands assume the folder with `docker-compose.yml`
and `TOKEN=$(cat deploy/secrets/api_token)`; `API=https://<host>:8443`.

Signals used throughout:

* `GET /ready` (with the token): `ready`, one check per area (`rules`, `registry`,
  `storage`, `workers`, `layers`), every layer `up` / `down` / `disabled` with the
  reason, and `problems`.
* Results: `scan_status` (`complete`, `partial`, `locked`, `unsupported`, `failed`)
  and `incomplete_reasons` - what was not inspected, and why.
* Metrics (`GET /metrics?format=prometheus`): `aegis_files_scanned_total`,
  `aegis_scan_failures_total`, `aegis_layer_errors_total`,
  `aegis_requests_rejected_total{reason=...}`, `aegis_verdicts_total`.
* Log events (with `LOG_FORMAT=json`, field `event`): `not_ready`, `layer_error`,
  `scan_completed`, `content_reloaded`, `rulepack_untrusted`, `auth_lockout`,
  `intel_auth_failed`, `external_share`.

## 1. A detection layer is down

**Notice.** `/ready` answers 503 with `layers: <name>: down (needs ...)` (production
profile), results turn `partial` with `layer unavailable (needs ...)`, or the start-up
log line `Detection layers -> ... <name>:down(needs ...)`.

**Confirm.** `curl -s -H "Authorization: Bearer $TOKEN" $API/ready | python3 -m json.tool`
and `docker compose run --rm --entrypoint python content RansomwareScanner.py --capabilities api`.

**Act.**
* `needs <package>` or a host tool (zbar, a RAR decompressor) inside the image: the image
  is broken or was built differently - reload or rebuild the release image; do not
  install into a running container (its root file system is read-only by design).
* `rules: ...` (no YARA rules / they do not compile): see runbook 4.
* External layers (`virustotal`, `llm`, `sandbox`) `down (needs intel service)`: intel is
  not running or not healthy - `docker compose ps intel`, `docker compose logs intel`;
  a bad intel setting stops it at start with one line per problem.
* `down` is never silent: every affected result says `partial` and names the layer, so
  re-scan those files (`scan_status != complete`) once the layer is back.

## 2. Scans fail (worker timeout, crash, memory)

**Notice.** `aegis_scan_failures_total` rises; results have `scan_status: failed`,
verdict at least Medium (`scan_failed` indicator), and the reason `timed out after Ns`,
`the worker process died (exit code N)` or `MemoryError: the worker used N MB`.
`/ready` shows `workers: warm-up scan failed: ...` when workers cannot start at all.

**Confirm.** Is it one file or every file? One file is the design working: a file that
hangs or exhausts a parser is reported, not allowed to stop the service. Every file
means the worker machinery is broken.

**Act.**
* One file: treat it as suspicious (the verdict already does); send the hash for analysis
  (`docs/SUPPORT.md`). If it is a legitimate large file, raise `SCAN_TIMEOUT_SECONDS` or
  `WORKER_MEMORY_MB` and keep `AEGIS_ANALYSIS_MEMORY` above
  `(AEGIS_API_MAX_CONCURRENT_SCANS + AEGIS_API_SPARE_WORKERS) x WORKER_MEMORY_MB`
  plus about 1 GB.
* Every file: `docker compose logs analysis` for the start-up error; check that the
  container is not at its memory limit (`docker stats`) or `pids_limit`; restart with
  `docker compose restart analysis`.

## 3. Disk or memory pressure

**Notice.** `/ready` answers `storage: <folder>: No space left on device`; scans fail or
turn partial with extraction errors; `docker stats` shows analysis near its limit.

**Where space goes.**
* `/tmp` in analysis is a tmpfs of `AEGIS_TMP_SIZE` (default 2 GB) counted against the
  container's memory. Unpacked members live there only during a scan; a killed worker's
  folder is removed by the parent, and a restart empties the tmpfs.
* The `analysis-state` volume: reports and the log file. The log rotates at
  `LOG_MAX_MB` (20) keeping `LOG_BACKUPS` (5) old files; reports are only written by CLI
  folder scans, not by `/scan`.
* The `intel-state` volume: the cache of external answers (expires after
  `CACHE_TTL_HOURS`, default 24 h).
* Docker's own container logs: capped by compose (`max-size: 10m`, `max-file: 5`).

**Act.** Free host disk (`docker system df`, old images: `docker image prune`); delete
old reports in the `analysis-state` volume; lower `AEGIS_API_MAX_CONCURRENT_SCANS` or
raise `AEGIS_ANALYSIS_MEMORY` when the tmpfs and workers together exceed the memory
limit. Never set `read_only: false` or remove the tmpfs size to "make room".

## 4. Detection content is outdated or wrong

**Notice.** Results show an old `provenance.rules.version` (and rules SHA-256); `/ready`
`rules: no YARA rules`; a vendor advisory names a newer pack; or a new pack produces
obvious false alarms.

**Confirm.** `curl -s -H "Authorization: Bearer $TOKEN" $API/version` (rules source,
version, SHA-256).

**Act.**
* Install the newer signed pack:
  `docker compose run --rm -v "$PWD/packs:/import:ro" content --update-rules /import/<pack>.tar.gz`
  (the `.sig` next to it). The running service reloads it before the next scan
  (`content_reloaded` in the log); `/version` shows the new version.
* A defective pack: ask the publisher for a signed rollback (a newer version with the
  previous rules) and install it the same way. Older packs are refused by design
  (`docs/RULE_PACKS.md`).
* `rulepack_untrusted` in the log: the active pack's signing key was removed from
  `RULEPACK_PUBLIC_KEYS`; the bundled rules are in use until a pack signed by a trusted
  key is installed.

## 5. An update failed

**Rule pack rejected** (`Rule pack rejected: <reason>`): nothing was changed; the
previous pack stays active. `signature does not match any trusted key` - wrong pack or
missing key in `RULEPACK_PUBLIC_KEYS`; `not newer than installed` - it is old (a
rollback must be a newer signed pack); `rules do not compile` - report it to the
publisher.

**Image upgrade failed** (the new version does not become healthy, or `/ready` stays
503):

1. `docker compose logs analysis intel proxy` - a configuration error is one line per
   problem; fix `.env` and `docker compose up -d --wait` again.
2. Otherwise roll back: set `AEGIS_VERSION` to the previous version in `.env`,
   `docker compose up -d --wait`.
3. If volumes were changed by the new version and the old one misbehaves:
   `deploy/restore.sh <backup taken before the upgrade>`.
4. Keep the failing version's logs for support (`docs/SUPPORT.md`).
