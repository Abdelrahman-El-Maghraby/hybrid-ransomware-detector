# Threat model: attacking the scanner itself

Aegis Sentinel exists to read files that attackers wrote. That makes the scanner a
target: an attacker who cannot get a file past it can try to break it, blind it,
or turn it against the machine it protects. This document lists those attacks,
what the code does about each, and what is left.

## Assets

| Asset | Why it matters |
|---|---|
| The verdict | A false "Clean" lets the payload through; a flood of false alarms gets the tool switched off. |
| The host running the scan | The scanner runs with the user's rights and opens hostile files. |
| Quarantined files and the vault key | Restoring the wrong file, or losing the key, loses data. |
| The user's documents | Sent to a cloud LLM or VirusTotal, they leave the organisation. |
| Detection content | Rules, signatures, weights and the allowlist decide what is flagged. |
| Alerts | Forged or suppressed alerts mislead the SOC. |
| Uploaded reports and logs (optional) | They leave the host and sit in a bucket the operator controls. |

## Trust boundaries

1. **Scanned files** (fully hostile): every byte, every name, every nested file.
2. **External services** (semi-trusted): VirusTotal, the LLM, the CAPE sandbox, the webhook receiver, the SMTP server, the S3-compatible bucket.
3. **Detection content** (trusted only when signed or written locally): rule packs, the allowlist, weight overrides.
4. **Local user and configuration** (trusted): `.env`, the OS keyring, the GUI, CLI arguments.
5. **API clients** (authenticated, otherwise untrusted): anyone who can reach the REST port.
6. **The analysis service** (assume compromised): in the Docker deployment it opens
   the hostile files, so a parser exploit is planned for. It has no network and
   no external-service secret; the intel service treats its requests as untrusted
   input (section 10).

## Threats and mitigations

### 1. Crash or hang the scanner (denial of service)
*A crafted PDF loops forever in the parser; a ZIP declares a format version the
library cannot handle; an archive nests 50 levels deep.*

- Every scan runs each file in a **worker process** with a wall-clock limit and a
  memory limit - folder scans, API uploads and, since 4.8, single files (`--scan-file`,
  the GUI's single file, a one-file folder) and monitored files. A hung or dead
  worker is replaced and the file is reported as `scan_failed` (Medium)
  (`engine/workers.py`).
- **Isolation fails closed (4.8).** When workers cannot start (three failed starts,
  or a worker silent for 120 s at start-up), nothing is parsed in the scanning
  process: every file left gets a `failed` result with the code
  `isolation_unavailable`, the CLI exits with code 3, the GUI shows an error with a
  retry, folder monitoring pauses, and the API answers 503 while `/ready` turns 503
  from live worker-start counters. Each result records where it was parsed
  (`provenance.isolation`: `worker`, `in_process` or `unavailable`). Turning
  isolation off (`ISOLATE_SCANS=0`) is a development-only opt-out, recorded in every
  result and refused at start-up under the production profile.
- **Every pipeline layer runs in a guard**: a parser that raises costs only that
  layer's evidence and is recorded in `layer_errors` (`engine/scanner.py`).
- Hard limits on archive depth, members, total and per-member size, compression
  ratio, image pixels, PDF pages, script size and decoding depth.
- **Fuzzing** of every parser (`tests/test_fuzz_parsers.py`, `fuzz/`). Found and
  fixed: a pyzipper `NotImplementedError` that ended a file's scan; a known infinite
  loop in PyPDF2 3.0.x (CVE-2023-36464), removed by moving to `pypdf`.
- **Timing on a benign corpus** (`tools/profile_layers.py`). Found and fixed: a
  quadratic regular expression in the strings pass (a 300 KB single-line script
  took 140 s).
- `pip-audit` in CI against the pinned lock file.

Memory is capped on every OS: RLIMIT_AS on Linux, a Job Object
(JOB_OBJECT_LIMIT_PROCESS_MEMORY) on Windows, and on macOS, where RLIMIT_AS is not
enforced, the parent reads each busy worker's resident size four times a second
and stops it over the limit.

*Residual:* on macOS a burst of allocation between two watchdog reads can go above
the limit for up to 0.25 s. A determined attacker can still make one file slow up
to the time limit.

### 2. Escape the extraction sandbox (path traversal, links)
*Archive members named `../../.bashrc`, absolute paths, symlinks, device files.*

- Members are written under generated names inside a fresh temporary folder;
  traversal, absolute paths and links are reported (`archive_zip_slip`) and never
  written. External tools (7-Zip, unrar) only stream one member to stdout: RAR
  members, and since 4.8 the files of macOS disk images (DMG) and CHM help files,
  which are listed first and then read one at a time with
  `7z e -so -spd -- <image> <name>` through the byte budget. 7-Zip never writes a
  file (it runs in an empty folder), links and folders are never requested, and a
  member it cannot read costs that member only.
- Rule packs refuse any entry that is not a plain file under `rules/`.
- API uploads are saved under a generated name; the client's file name is only used
  for its extension and for display.
- RAR members are streamed to stdout by the external tool with `--` before every
  name, so a member called `-x...` is not an option and the tool's own path
  handling is never used. 7z members are extracted into a private folder, then
  only names that passed the checks and resolve inside it are moved, never links.
- Unpacked data has a budget (`ARCHIVE_MAX_TOTAL_MB`, member count, nesting); in
  Docker it lands on a size-limited `noexec,nosuid,nodev` tmpfs.
- A worker killed for a timeout or the memory limit cannot run its own clean-up;
  each worker has its own temporary folder, which the parent deletes when it kills
  or stops the worker, so hostile files cannot fill `/tmp` one timeout at a time.

### 3. Evade detection
*Obfuscation, password-protected archives, payloads fetched later, QR codes,
smuggling, lookalike formats.*

- Layered decoding of scripts (5 levels), Script Encoder decoding, archive
  passwords read from the e-mail, HTML-smuggling payload extraction, QR decoding,
  OneNote / CHM / MSI / encrypted-Office unpacking, magic-byte format checks.
- Scoring favours structural evidence and stacks independent layers, so evading
  one layer rarely drops the verdict to Clean.

*Residual:* static analysis cannot see behaviour that only appears at run time
(payload downloaded later, environment checks). The optional CAPE sandbox layer
covers part of this; without it, this is the largest gap.

### 4. Manipulate the LLM (prompt injection)
*Hidden text telling the model "this file is safe".*

- Hidden-content and injection detection runs **before** the LLM; hidden injection
  text is itself a technical finding (`prompt_injection`, 50).
- Document text is wrapped in per-request random delimiters, instructions stay in
  the system role, output is JSON only at temperature 0.
- The LLM category is capped at 24 points and semantic evidence alone can never
  exceed Medium: a fooled model can add little, and cannot clear technical findings.

### 5. Poison detection content
*A malicious rule pack, a planted allowlist entry, a weights file that zeroes a weight.*

- Rule packs install only with an **Ed25519 signature** from a configured key, a
  manifest whose hashes match every file, a newer version, and rules that compile
  (`core/rulepack.py`). The version, and a rollback's `rollback_of`, must be purely
  numeric: they name the install folder, which must be a direct child of
  `rulepacks/` (4.8; before, a signed pack could name a folder outside it). Keys
  come from configuration, never from the pack. An older
  or the same pack is always refused (no replay of a pack with known gaps); a
  rollback is a signed pack with a newer version (`rollback_of`). Each install
  records its signing key: removing a compromised key from RULEPACK_PUBLIC_KEYS
  stops the content it signed from being used and lets a pack signed by the new
  key install, even if the attacker published a huge version (`docs/RULE_PACKS.md`).
- The allowlist holds **SHA-256 hashes** only (no names, paths or wildcards), so an
  attacker cannot reuse an entry without a byte-identical file; a hash in the
  malware database still wins.
- Weight overrides must name existing weights with the same shape; reports record
  the registry version and "+override".

- **Rule-pack updates in Docker:** the content volume (rule packs, allowlist, hash
  and fuzzy databases) is mounted read-only in the analysis service and written
  only by the one-off `content` tool, which has no network. A compromised parser
  cannot add its own hash to the allowlist or swap the rules. The running service
  reloads changed content before the next scan and every result records the pack
  version and rules hash (`provenance`), so an unexpected change is visible.
- Pickled ML models (joblib) run code when loaded: on POSIX only a model owned by
  the user or root and not group/world-writable is loaded; the server image has no
  scikit-learn, so it loads none.

*Residual:* on a desktop, anyone who can write to the user's data folder can edit
the allowlist or point the config elsewhere - protect that folder like the rest of
the account.

### 5b. Turn the scanner's own features against the host
- **Emulation** (box-js) executes the attacker's JavaScript in a Node sandbox;
  sandboxes of this kind (vm2) have had escapes. It is off by default, documented
  for analysis VMs only, found by trusted path, run on a copy in a private
  temporary folder with a stripped environment and a time limit, inheriting the
  worker's memory limit; its result files are parsed as untrusted JSON.
- **Canary response scripts** run with the user's rights when an attack is under
  way: only an absolute path, owned by the user, not writable by group/others.
- **Process containment** (`stop_writers`) could be aimed at a legitimate program
  by touching a canary while that program has a file open in the same folder.
  It suspends rather than kills by default (undo: `--resume-pid`), only processes
  with files open *for writing* there (Linux, macOS), never this tool or its
  ancestors, system, indexing or antivirus processes, or other users' processes.
  On Windows the Restart Manager cannot tell reads from writes, so the protected
  list matters more; add sync clients to `CANARY_CONTAIN_EXCLUDE` if needed.
- **Folder lock** (`lock_folders`) is reversible: original POSIX modes are saved
  and restored by `--unlock-folders`; on Windows a single deny ACE for Everyone is
  added and removed with icacls. A process running as the same user can undo it,
  so it slows ransomware down rather than stopping a determined one.
- **Helper programs** (7-Zip, unrar, nmcli, ...) are resolved outside the current
  directory, so a planted `7z.exe` in a scanned folder is never started.
- **Secrets** (API keys, the sandbox token, the webhook secret, the IMAP app password)
  come from the environment or a `NAME_FILE` secret on a server, and from the OS keyring
  on a desktop; the scanner never writes one to a file. A secret left in `.env` is moved
  to the keyring on the next start, and `.env` is only rewritten after the keyring
  returned every value unchanged. Values are never logged or put in error messages.
- **IMAP credentials**: an app password (environment or keyring), never logged, never in
  reports or the state file; TLS with certificate verification only, read-only
  mailbox access.

### 6. Leak data to third parties
- VirusTotal is queried **by hash**; uploads are opt-in. The LLM prefers a local
  Ollama model; cloud use is logged. The sandbox is the user's own server.
- Webhooks and e-mail alerts send metadata only (verdict, hash, indicators), never
  content; webhooks can be HMAC-signed (section 12).
- Optional cloud storage uploads a redacted view of reports and logs, never files
  (section 13).
- Every result records what its scan sent outside (`provenance.shared`: hash, file
  or text, local or cloud), members included, and each share is logged
  (`external_share`), so a data-protection review can see exactly what left. The
  production profile refuses `LLM_PROVIDER=auto`, which would fall back to the
  cloud whenever the local model is unreachable.

### 7. Abuse the API
- Bearer token required (constant-time compare); the server refuses to start with
  a short token; binds to 127.0.0.1 unless configured; documentation endpoints are
  off.
- Uploads over the limit are refused before they are parsed (declared length,
  then a streaming count), so a client cannot fill the disk through the
  multipart spool; scans are isolated.
- A per-IP token bucket applies before authentication. Failed bearer tokens are
  counted per IP address (not per token, so rotating guesses does not help): after
  `AEGIS_API_AUTH_FAILURES` failures within the window, the address is refused
  before the compare until the lockout ends (429 with Retry-After). `/ready` shows
  details only for a valid token and goes through the same policy. A valid token
  has its own per-client quota; at most N concurrent scans, then 503. Rejections
  are counted in `/metrics`.

*Residual:* no TLS of its own - put it behind a reverse proxy (`docs/DEPLOYMENT.md`).
With `AEGIS_API_TRUST_PROXY=1` the client address is the last X-Forwarded-For entry
(the one the proxy added; earlier ones are the client's and are ignored), so the API
must only be reachable through that proxy. In Docker it listens only on a socket
that only the proxy can open.

### 8. Tamper with quarantine
- AES-256-GCM per file with authenticated header, chunks and end marker
  (bit flips, reordering, truncation detected); originals deleted only after a
  verified decrypt; restore never overwrites; key backup is passphrase-encrypted.
- Quarantine takes the SHA-256 of the scanned file and refuses a file whose content
  changed since the scan (4.8): a file renamed into its place is never vaulted
  instead of the one that was judged.

### 9. Supply chain
- Hash-pinned lock files (4.8): every package the image and the release builds
  install is pinned to a version and to the SHA-256 of its files, and installed with
  `--require-hashes`, so a substituted file stops the build. `pip-audit` in CI on
  every lock. Release builds come from CI with SHA-256 sums, a CycloneDX SBOM and
  keyless Sigstore signatures, and only for a commit whose tests, quality and docker
  workflows passed (the release `gate` job).

*Residual:* binaries are not Authenticode-signed / notarised (needs paid certificates).

### 10. Compromise a parser (code execution in the analysis service)
*A crafted file exploits a bug in pypdf, olefile, py7zr, libyara or libzbar and runs
code inside a scan worker.*

The worker pool stops a parser from hanging or exhausting the service; it is not a
security boundary. In the Docker deployment the boundary is the container:

- **No network.** `network_mode: none`: no interface but loopback, no route, no DNS.
  The code cannot download a second stage, exfiltrate scanned documents, reach the
  LAN or the cloud metadata address, or attack the proxy.
- **Nothing to steal.** The VirusTotal, OpenAI and sandbox secrets live only in the
  intel service; the production profile refuses them on the analysis side.
- **Intel is not a proxy.** The worker can call intel (it needs the intel token for
  the external layers), but only the fixed operations, with exact input checks, a
  rate limit per operation, and destinations taken from intel's own configuration.
  It cannot name a URL; redirects to other origins are refused.
- **Little to change.** Non-root, read-only root file system, read-only detection
  content, `noexec` tmpfs, all capabilities dropped, no-new-privileges, Docker's
  default seccomp profile, memory / CPU / process limits.
- **Nothing to act with.** The containment code (suspend or kill processes, lock
  folders, disable the network) is not in the server image.

*Residual:*
- The compromised worker can **forge the result of the file that exploited it**
  (each API upload gets a fresh worker, so not other uploads' results). It cannot
  plant answers for other files: the analysis side keeps no cache of external
  answers, and the intel service's cache, in a volume analysis does not mount, is
  written only from the real service's reply under a key intel derives itself
  (the requested hash, the hash of the bytes it received, the hash of the text it
  was given). Verdicts are never cached anywhere.
- With the intel token it can spend the configured quotas: hash look-ups, LLM calls
  and - only when the operator switched them on - VirusTotal uploads and sandbox
  submissions, each limited per minute. Data it sends this way goes only to the
  operator's own destinations.
- A kernel or container-runtime escape is outside what the application can stop;
  keep the host kernel and Docker patched.
- **TMA-1 (accepted residual risk).** The compromised worker can write the
  `analysis-state` volume: the local log file and reports, and the alert outbox
  (4.8). So it can delete or edit local log lines and reports, and suppress or
  forge queued e-mail alerts before they reach intel. Docker's own container log is
  out of its reach, and so is everything intel holds. Uploaded reports and logs are
  therefore not described as tamper-evident (section 13). On a desktop the workers
  run as the same user, so the same holds there.

### 11. Folder monitoring (desktop)
*An attacker drops a file into a watched folder - a download, a share, an e-mail
client's attachment folder - so it is parsed with no user action. Or floods the
folder with events, plants a link out of it, swaps a file between scan and
quarantine, or makes the monitor scan its own output in a loop.*

Mitigated (TMA-5, `core/folder_watch.py`):
- Monitored files are parsed only in isolated workers, like every scan (section 1);
  when workers cannot start, monitoring pauses with a visible error and retries
  later - it never parses in the main process.
- Events only record a path; repeated events collapse into one entry, and the queue
  is bounded (`WATCH_MAX_QUEUE`; overflow dropped, logged and counted). A file is
  scanned once, after it stops changing; duplicates are skipped by path, size,
  modification time and SHA-256.
- Links are never followed, and a file whose real path is outside every watched
  folder is ignored.
- The app's own output is never scanned (app data with the logs, reports,
  quarantine, keys, outbox, cloud spool, JSON Lines file, cache database, worker
  temporary folders), nor are canaries, so there is no loop.
- Quarantine refuses a file whose SHA-256 differs from the scanned one (section 8).
- Desktop only: the Docker edition and the REST API have no watcher.

*Accepted residual risk:* a watched folder that receives files continuously keeps
the workers busy (up to `SCAN_TIMEOUT_SECONDS` per file) and drops events beyond the
queue; dropped files are not scanned until they change again.

### 12. E-mail alerts
*A new egress; an SMTP credential to steal; header injection through a hostile
file name; alert contents disclosed to the mail provider; alert floods.*

Mitigated (TMA-6, `core/mailer.py`, `core/outbox.py`, `api/intel.py`):
- A fixed set of metadata fields in a fixed template: alert id, kind, verdict, risk
  band, SHA-256, file name, time, scan id, reason codes. No free text, no
  recipients from the alert, no attachments, no content. File names are cleaned of
  control and format characters (CR/LF, RTLO) and truncated, so they cannot inject
  headers.
- SMTP over implicit TLS or STARTTLS that must succeed, with certificate and host
  name verification; no plaintext option. Only the configured host and port;
  recipients and sender come from the configuration.
- The password comes from the secret store and is never logged or put in an error.
  In Docker, only intel holds the SMTP settings; analysis hands it the fields
  through one operation (`POST /v1/alert/email`) that accepts exactly those fields
  and needs the intel token; the production profile refuses SMTP settings on the
  analysis side.
- Hourly and daily caps; an alert id already sent is ignored.

*Accepted residual risk:* the alert metadata (file name, hash, verdict) reaches the
mail provider and the recipients' mailboxes. A compromised parser in Docker can use
the operation to send forged alerts to the configured recipients, within the caps
(TMA-1).

### 13. Optional cloud storage of reports and logs
*Data leaves the host; the upload credential leaks; remote retention is out of the
product's control; the local spool is tampered with.*

Mitigated (TMA-7, `core/cloud.py`; owner decisions D-D1 to D-D3):
- Off by default; desktop only.
- What is uploaded is an allowlisted view built field by field: no paths, folder or
  file names, user or host names, and no free text; a file is a keyed pseudonym
  (HMAC-SHA-256 with a per-installation key in the secret store, never uploaded).
  Logs are uploaded as structured events, never the log files. Never uploaded:
  inspected files, the vault, keys, the outbox, the cache. Full detail is an
  explicit opt-in, recorded in every upload and warned.
- HTTPS with certificate verification to the configured endpoint only; the SHA-256
  checksum is sent and checked; object keys are unique and written create-only where
  the endpoint supports it. The client never lists, reads or deletes remote objects,
  so the credential can be limited to creating objects under the installation's
  prefix (`docs/OPERATIONS.md`).
- The local spool is owner-only, removed after a confirmed upload, and expires after
  30 days or beyond 1 GiB, each deletion logged and counted.

*Accepted residual risks:*
- What remains (hashes, sizes, types, verdicts, indicator and rule ids,
  provenance, timestamps, installation id) leaves the host; anyone who already has a
  file can match it to an uploaded hash.
- Remote retention is the bucket's lifecycle rule, set by the operator; the product
  cannot check or enforce it.
- Unique keys stop the app from overwriting its own objects by accident; they do not
  stop someone holding the credential from uploading forged objects, or, on an
  endpoint without conditional writes, overwriting a key. Only bucket versioning or
  object lock can prevent or reveal that.
- An uploaded report or log is only as trustworthy as the host that produced it
  (TMA-1): uploads are not tamper-evident.

## Changes in 4.8: TMA-1 to TMA-7

Owner decision D-G (`docs/PROJECT_REVIEW.md` section 24.9). Each entry is either a
mitigated defect, with the commit that fixed it and its test, or an accepted
residual risk.

| ID | Subject | Status | Commit | Test |
|---|---|---|---|---|
| TMA-1 | A compromised worker can write `analysis-state` (local log, reports, alert outbox) | accepted residual risk (section 10) | - | - |
| TMA-2 | A signed rule pack's version used as a path could delete or replace directories | mitigated defect (PR-01): numeric version, folder confined to `rulepacks/`; a compromised key again changes content only | `40b690f` | `tests/test_rulepack.py` (traversal, absolute, separator and drive versions; planted link) |
| TMA-3 | DMG unpacking relied on the host 7-Zip's path and link handling | mitigated defect (PR-04): members streamed through `7z e -so` | `600d8bc` | `tests/test_dmg_streaming.py` (crafted link image, traversal names, budget, pipe only) |
| TMA-4 | Isolation could silently fall back to the main process | mitigated defect (PR-02, PR-03): fail closed, single files isolated, `provenance.isolation`; opt-out development only | `9d1062d` | `tests/test_isolation_policy.py`, `tests/test_workers.py` |
| TMA-5 | Folder monitoring: dropped files parsed without user action, floods, link escapes, rename races, loops | mitigated as listed in section 11; flood and drop limits accepted | `ecaca34` | `tests/test_folder_monitor.py` (I-1, I-2, I-3) |
| TMA-6 | E-mail alerts: new egress, credential, header injection, disclosure, floods | mitigated as listed in section 12; disclosure to the mail provider and forged alerts from a compromised parser accepted | `af8deda` | `tests/test_alerts.py`, `deploy/isolation_check.py` |
| TMA-7 | Cloud storage: data leaving, credential scope, remote retention, spool tampering | mitigated as listed in section 13; remaining metadata, operator-owned retention and non-tamper-evident uploads accepted | `0209d7b` | `tests/test_cloud.py` (marker-name test) |

## Summary of residual risk

| Risk | Level | Next step |
|---|---|---|
| Run-time-only behaviour | High | Use the CAPE sandbox layer for suspicious files |
| Detection rate on real samples unknown | High | `tools/evaluate.py` on labelled data |
| Canary containment misses a fast encryptor (no file open at check time) | Medium | Folder lock + network off; Controlled Folder Access on Windows; an EDR |
| macOS memory watchdog reacts within 0.25 s, not instantly | Low | Run the API on Linux or in a VM |
| Local tampering with config / allowlist | Medium | OS file permissions; signed config (future) |
| Unsigned binaries | Medium | Code-signing certificates |
| Slow-file DoS up to the timeout | Low | Lower SCAN_TIMEOUT_SECONDS where latency matters |
| Parser exploit forges the result of the file that exploited it | Low | Fresh worker per API upload; cached external answers live only in intel |
| Parser exploit spends the intel quotas | Low | Per-operation rate limits; uploads and sandbox stay off unless needed |
| Container or kernel escape | Medium | Patched host kernel and Docker; a dedicated VM per deployment |
| A compromised parser edits local logs, reports or queued alerts (TMA-1) | Low | Ship logs off the host; treat uploads as host-attested only |
| Monitored folder flooded: events dropped, files not scanned until they change (TMA-5) | Low | Watch specific folders; raise `WATCH_MAX_QUEUE` |
| Alert metadata at the mail provider; forged alerts from a compromised parser (TMA-6) | Low | Choose the SMTP provider deliberately; caps; a separate mailbox |
| Uploaded metadata, operator-owned retention, uploads not tamper-evident (TMA-7) | Low | Keep cloud off unless needed; bucket lifecycle 90 days, versioning or object lock; least-privilege credential |
