# Protection and delivery

Everything in this chapter except e-mail alerts is a **desktop and CLI feature**: the
Docker and Kubernetes server editions do not quarantine, deploy canaries or contain
processes (a container cannot watch or stop processes on users' endpoints, and must not
hold kill or network rights).

## Quarantine vault

`QuarantineVault` (`core/quarantine.py`) moves a file out of reach in a form that cannot be
opened, executed or re-detected, while keeping it recoverable.

- **Encryption.** AES-256-GCM in 64 KiB chunks (streaming, so large files never need to fit
  in memory). A random 32-byte master key lives in `keystore_dir/quarantine.key` (mode
  0600). Each item gets its own key, derived with HKDF-SHA256 from the master key and a
  random 16-byte salt, and a random 8-byte nonce prefix.
- **Authentication of everything.** An encrypted metadata header (original path, SHA-256,
  size, mode, reason), every chunk with its sequence number bound in the associated data (no
  reordering or dropping), and an explicit end frame (truncation is detected). A plaintext
  sidecar `<id>.json` exists only for fast listing; restore trusts only the authenticated
  header.
- **Verify before delete.** After writing, the vault file is decrypted again and its SHA-256
  compared with the original **before** the original is removed. No user file is deleted
  unless a verified encrypted copy exists.
- **Restore.** Authenticates first, decrypts into a temporary file next to the destination,
  checks the SHA-256 against the header, then renames atomically. An existing file at the
  destination is never overwritten unless asked; the restored copy gets a `.restored-<id>`
  suffix instead. The GUI asks for confirmation; every quarantine and restore is logged with
  the operating-system account that performed it. There is no separate role: anyone who can
  act as that account can restore.
- **Key backup.** `--export-key` writes the master key encrypted with a passphrase (at least
  10 characters; scrypt then AES-GCM); `--import-key` and `--replace-key` restore it. Without
  the key the vault cannot be decrypted.
- **Limit (stated in the code).** The vault neutralises files; it is not a secrecy boundary
  against someone who already controls the user account, because the key is on the same
  disk.

Automatic quarantine happens only in batch scans (`collect()` in `_scan_targets()`) when
`AUTO_QUARANTINE` is set and the verdict reaches it. The result then records the vault id,
and the alert carries the reason code `quarantined`.

## Canaries

`CanaryManager` (`core/canary.py`) plants decoy documents in protected folders, named to sort
first (`!000_Finance_Records_Backup.docx`, `!000_Signed_Contracts_Archive.pdf`,
`!000_Asset_Inventory.csv`), because ransomware tends to walk folders in name order. Their
path, size and SHA-256 are recorded; `verify()` reports a canary deleted, rewritten, renamed
or replaced with high-entropy data, and ransom-note names appearing beside it (MITRE ATT&CK
T1486).

**Timing.** Checks run every {{fact:canary_check_minutes}} minutes in the background service
and the GUI, before `--scan-now`, and, with `watchdog` installed, within about a second of a
change event (`core/canary_watch.py`; read-only events are ignored and bursts coalesced). By
construction a canary trips **after** encryption has started: it limits damage and does not
prevent the first encrypted files. The registry is itself a file ransomware can destroy; a
second copy and the last good list in memory turn a lost registry into an alert of its own
(M25).

## Containment (optional, desktop only)

`CANARY_RESPONSE` (empty by default; refused by the production profile) selects actions that
run when a canary trips, fastest first (`core/response.py`, `core/containment.py`):

| Action | What it does | Platform mechanism | Limits |
|---|---|---|---|
| `stop_writers` | suspend (or, with `CANARY_CONTAIN_MODE=terminate`, kill) processes with files open for writing in the canary folders, and their children | Linux `/proc/<pid>/fd` + `fdinfo`; macOS `lsof`; Windows Restart Manager (cannot tell reads from writes) | an encryptor that opens, writes and closes quickly may hold no handle at check time; system, indexing and antivirus processes and the scanner's own ancestors are never touched; reversible with `--resume-pid` |
| `lock_folders` | remove write access to `CANARY_LOCK_DIRS` (default: the canary folders) | permissions / ACLs | undo with `--unlock-folders` |
| `controlled_folder_access` | turn on Microsoft Defender Controlled Folder Access for those folders | Windows, administrator rights | Windows only |
| `network_off` | disable network adapters | administrator or root | stops spread and exfiltration, also legitimate traffic |
| `script` | run `CANARY_RESPONSE_SCRIPT` with the alert as JSON on stdin | absolute path, permission-checked | operator-defined |

Status: [[impl]]; [[local]] with stand-ins only (no real process was suspended in tests);
[[pending]] on Linux and Windows. This is rapid damage mitigation, not EDR-style prevention.

## Alert delivery: the outbox

`core/outbox.py` makes alerts survive receiver outages.

- **What is queued.** For each result: a verdict alert, queued for a channel only if the
  verdict reaches that channel's minimum ({{fact:webhook_min_verdict}} by default); a
  `scan_failed` notice for a time-out, crash or memory failure (not for files never opened);
  an `incomplete_scan` notice when CHM content was left unread. Canary trips go to every
  configured channel. Notices are marked `detection: false`; they never change the result.
- **Persistence.** Each alert is written atomically as one owner-only JSON file of metadata
  (never file content or secrets) **before** any send, then delivered on each channel and
  retried with exponential backoff (30 s up to 1 h) until delivered or older than
  `OUTBOX_MAX_AGE_HOURS` ({{fact:outbox_max_age_hours}} h). The background service flushes
  every minute; the API flushes every 60 s.
- **Stable identifiers.** The alert id is a SHA-256 of what it reports (kind, file SHA-256,
  scan time, path), so the same alert queued twice is one alert; webhooks carry it as
  `Idempotency-Key` so receivers can de-duplicate.
- **Duplicates.** Each delivery is remembered in the process and recorded at once as
  `sent/<id>.<channel>` for the maximum age (RV-14), so a failed rewrite of the entry does
  not cause resends. Delivery is **at least once**, not exactly once: a crash between a
  successful send and the marker write can repeat an alert, and a marker older than the
  maximum age no longer suppresses a re-queued alert.
- **Disabled versus failing.** E-mail is treated as *disabled* only when the intel service
  answers, authenticated, that it has no SMTP settings: nothing new is queued and queued
  e-mail parts are removed with an error instead of waiting for expiry (RV-15). When intel is
  unreachable or its answer is unknown, e-mail stays queued and is retried.
- **Not yet done** (deferred, `FINDINGS_REGISTER` section 4): permanent-error classification
  (intel 403/422 and webhook 4xx are retried for the full 24 h), outbox size caps, and
  `fsync` before rename (RV-S5, not reproduced).

## Outputs for SIEM and SOAR

JSON Lines (`JSONL_PATH`, one result per line in the published schema) and HMAC-signed
webhooks are metadata only and exist on the desktop and CLI only. Structured logs
(`LOG_FORMAT=json` on servers) record every scan, layer error, external share and alert.
