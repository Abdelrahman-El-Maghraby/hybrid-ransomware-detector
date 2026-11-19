# Completeness, failure and resource limits

## The five statuses

`assess()` in `engine/completeness.py` gives each file one `scan_status` and up to
{{fact:max_reasons}} `incomplete_reasons`, each `{member_path, layer, reason, status}`.

| Status | Meaning |
|---|---|
| `complete` | every applicable, enabled layer ran |
| `unsupported` | the content has no type-specific analysis (gzip, bzip2, xz, zstd, zlib, cab, LNK, Mach-O, unknown); only the generic layers looked at it |
| `partial` | an applicable, enabled layer failed or was unavailable, an external service errored or timed out, or part of the content was not unpacked (limits, a missing decompressor, a truncated page, members over a budget or the nesting limit) |
| `locked` | encrypted or password-protected content was not opened |
| `failed` | the worker timed out, crashed, ran out of memory or sent an invalid reply, or no isolated worker could start: the file was not (fully) scanned |

Precedence, most severe first: **{{fact:status_precedence}}**. A container takes the most
severe status of itself and its members, because a member's gap is a gap in the
container's evidence. `failed` ranks first because nothing reliable is known and a scanner
that dies on a file may be under attack; `locked` next because a password-protected
payload is a deliberate delivery technique.

**Intended skips are not gaps**: a heavy layer skipped at 100 points or for an allowlisted
file, a layer that does not apply to the type, and an optional layer switched off by
configuration (recorded in provenance instead). The status **never** changes the score,
the verdict or an automatic action; `verdict_label` only appends it, so a Clean file whose
scan was partial reads "Clean (partial scan)".

## Where the reasons come from

| Source (`assess` helper) | Typical reason | Status |
|---|---|---|
| Layer gaps (`_layer_gaps`) | "layer error: ...", "layer skipped: file larger than fuzzy_max_bytes", "layer unavailable (needs pyzbar)", "yara could not analyse the file", "virustotal timeout" | partial |
| Archive gaps (`_archive_gaps`) | "needs py7zr", "encrypted member not opened", "N member(s) over the member limit", "unpacking stopped at the size limits", "N archive(s) could not be opened" | partial or locked |
| Embedded gaps | "password-protected document not decrypted", "not unpacked: ..." | locked or partial |
| Web gaps (RV-S1, RV-13) | "page longer than the analysis limit", payloads over the count or size limit listed in `skipped` | partial |
| Budget gaps | "N member(s) over the scan budget", "nesting limit (2) reached: members listed, not scanned", mail attachments skipped or the message not analysed | partial |
| Format gaps | "password-protected PDF", ZIP/7z/RAR content not opened, "no type-specific analysis for gzip content" | locked, partial, unsupported |
| Members | each member's own reasons, with its `member_path` | as the member |
| Worker failure (`failed()`) | "timed out after 300s", "MemoryError ...", "the worker process died", "invalid reply ..." | failed |

## Resource limits: configured defaults versus hard limits

| Limit | Value | Configurable? | Enforced by |
|---|---|---|---|
| Wall-clock per file | {{fact:scan_timeout_seconds}} s | `SCAN_TIMEOUT_SECONDS` (1 to 86,400) | the parent kills the worker |
| Memory per worker | {{fact:worker_memory_mb}} MB | `WORKER_MEMORY_MB` (0 = none) | Linux `RLIMIT_AS`; Windows Job Object; macOS parent watchdog every 0.25 s |
| Workers | auto, up to 4 (1 with VirusTotal pacing) | `SCAN_WORKERS` | `default_workers()` |
| Worker start | {{fact:worker_start_seconds}} s; {{fact:max_failed_starts}} failed starts | fixed | `_IsolatedScan` |
| Worker message size | {{fact:worker_reply_mib}} MiB | fixed | `read_reply()` |
| Worker log records per file | 200 (+50 kept from the end) | fixed | `_WorkerLogBuffer` |
| Container recursion, archive and mail limits | chapter 2 | partly (`archive_*`, `max_nesting`, `mail_*`) | extractor and `scan_container` |
| API concurrent scans | 2 in Docker and Kubernetes | `AEGIS_API_MAX_CONCURRENT_SCANS` | `ScanSlots` (503) |
| API upload size | 50 MiB in Docker and Kubernetes (+64 KiB form overhead) | `AEGIS_API_MAX_UPLOAD_MB` | `BodyLimit` (413), the proxy's 51 MiB cap |
| API upload deadline | 600 s | `AEGIS_API_UPLOAD_SECONDS` | `asyncio.wait_for` (408) |
| Intel reply size | {{fact:intel_reply_mib}} MiB, identity encoding only | fixed | `core/intel_client.read_reply` |
| Intel request size | 100 MiB | `AEGIS_INTEL_MAX_UPLOAD_MB` | intel `BodyLimit`; the intel proxy's 101 MiB cap |
| Result reasons listed | {{fact:max_reasons}} | fixed | `assess()` |

## How failures are told apart

The parent's `_step()` (`engine/workers.py`) checks every worker on each 50 ms tick, after
handling any message, so a worker that floods messages is still stopped on time (RV-4).

| Situation | Detected by | Result |
|---|---|---|
| Valid `ok` reply for the file sent | `_final_reply` | the worker's own result |
| `ok` naming another file (RV-S2) | `_final_reply`, `_step` | `failure_result`, worker replaced; the path drives quarantine, so a forged path must never be acted on |
| `error` reply (MemoryError, RecursionError, an engine exception) | `_final_reply` | `failure_result` (`scan_failed`); the worker is kept |
| Invalid message (too large, not JSON, wrong shape, a log record that would overwrite a method) | `read_reply`, `check_reply` | `failure_result`; "nothing in it was used"; worker replaced |
| Time limit, last snapshot `settled` or `completed` | `_step` | that snapshot is the result (no more waiting was needed) |
| Time limit, last snapshot `provisional` (a VirusTotal, LLM or sandbox wait) | `_step`, `stopped_result()` | the other layers' findings stand; the waiting layers are named in `stopped_layers` with what may have been sent; `partial` |
| Time limit, no snapshot | `_step` | `failure_result`: "timed out after N s" |
| Worker died | dead pipe or process | `failure_result`: "the worker process died (exit code N)" |
| Memory over the limit (macOS watchdog) | `_over_memory` | `failure_result`: "MemoryError: the worker used N MB ..." |
| Workers cannot start | {{fact:max_failed_starts}} failed starts | **fail closed**: every remaining file gets `isolation_unavailable`, `failed`, no score; nothing is parsed in the parent. CLI exit 3, API 503, the GUI offers a retry |

`failure_result()` scores `scan_failed` ({{fact:w_scan_failed}} points, Medium), because
ordinary documents do not hang or crash parsers, **unless** the file was never opened
(`isolation_unavailable`). Evidence the worker reported before failing (the container's own
findings and up to 10 of the highest-risk finished members) is kept under
`partial_evidence`, and the result takes the higher of the two scores. A failed or
timed-out scan also produces a `scan_failed` notice to the alert channels
(`detection: false`), separate from any verdict alert.

## Cleanup and platform limits

After a kill, the parent removes the worker's temporary folder (a killed worker never runs
its own clean-up), and a sweep at start-up removes folders left by workers whose process no
longer exists. Helper programs are stopped with the worker: on Linux and other POSIX
systems by signalling the worker's process group; on macOS by tracking observed
descendants by kernel identity, including those that start a new session. **Known limit
(L-E5):** a helper that detaches *before* the first discovery pass can survive its worker
(confirmed by a bounded probe); Linux session escapes and the Windows path need platform
work. Worker processes share the user and permissions of the scanner: they are a
reliability boundary, not a security one.

## Partial results from slow external services

Before a heavy layer waits on a service, a worker sends a `provisional` result that holds
every other layer's findings with that layer at `timeout`, and (`external`) what is about to
be sent. If the parent must stop the worker during the wait, it uses that result instead of
failing the file; the waiting layer is listed in `stopped_layers`, the scan is `partial`,
and provenance says what *may* have left the host. The sandbox submission state
(`not_attempted`, `possible`, `refused`, `confirmed`) is tracked the same way. The
guarantee is the worker's time limit; the cooperative deadlines inside the clients are best
effort (a slow name lookup or a proxy can outlast them), and requests the intel service
already started can continue after a worker stops waiting.
