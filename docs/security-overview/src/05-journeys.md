# End-to-end file journeys

Two journeys, traced through the code at the baseline. The file names are illustrative and
inert; no real sample is involved. Diagram 7 shows the process boundaries of the first,
diagram 9 the containment tree of the second, and diagram 3 (Appendix C) the same flow as an
activity diagram with every failure branch.

## Journey 1: one document, scanned from the command line

The analyst runs `RansomwareScanner.py --scan-file report.docm`.

| # | Step | Owner (code) | What crosses a boundary |
|---|---|---|---|
| 1 | **Intake and configuration.** `CONFIG` is built from defaults, the environment and `.env`; secrets come from the OS keyring (`engine/secret_store.py`); `check_config()` validates values and the profile. A `RansomwareScanner` is built: hash database, YARA rules (or the active signed rule pack), fuzzy signatures, allowlist, layer states. | CLI process | — |
| 2 | **Admission and limits.** `scan_one()` calls `scan_isolated()` with one worker, the {{fact:scan_timeout_seconds}} s limit and {{fact:worker_memory_mb}} MB. (The API adds a scan slot, a body limit and an upload deadline before this point.) | `engine/scanner.py` | — |
| 3 | **Worker start-up.** A process is started with the `spawn` method on every OS, in its own temporary folder (`aegis_worker_<pid>_...`). It joins its own process group, applies the memory limit (Linux `RLIMIT_AS`, Windows Job Object; macOS relies on the parent's watchdog), builds its own scanner with isolation switched off inside, and sends `ready`. No `ready` within {{fact:worker_start_seconds}} s counts as a failed start; after {{fact:max_failed_starts}} failed starts the scan fails closed. | `_IsolatedScan`, `_Worker`, `_worker_main` | parent → worker: the full configuration (on the desktop, API keys included) as process arguments; worker → parent: `ready` |
| 4 | **Dispatch.** The parent sends the path on the pipe and starts the clock. The worker sets its own deadline from the same limit. | `_dispatch`, `_serve` | parent → worker: the path |
| 5 | **Context creation.** `scan_file()` reloads detection content if it changed on disk, then `ScanContext.start()` records size, type flags and the display name. | `engine/staging.py`, `engine/layers.py` | — |
| 6 | **Layer execution.** The fast layers run in order: hashes, allowlist, fuzzy, local-db, macro, YARA, integrity, ELF, PE, script, mail, prompt-guard, relationships, QR, archive, web, embedded. Layers that do not apply return without an entry. A layer that raises is recorded in `layer_errors` and the scan continues; `MemoryError` is re-raised so the worker reports it. | `_run_layer` | — |
| 7 | **Recursion.** None here: an Office Open XML file is a ZIP the document layers read, not an archive to open. | — | — |
| 8 | **Optional external analysis.** If an LLM is configured, `llm` sends up to 3,000 characters of visible text and 2,000 of strings, wrapped as untrusted data; if VirusTotal is configured, `virustotal` sends the SHA-256. Before each wait the worker tells the parent what is about to leave (`external`) and the result to keep if it is stopped (`provisional`). | `engine/external.py` | worker → service: hash or text; worker → parent: `external`, `provisional` |
| 9 | **Evidence aggregation.** The heavy layers (emulation, ML, LLM, VirusTotal) run concurrently on copies of the context and are merged back in pipeline order; they are skipped if the file is allowlisted or already scores 100. | `_run_heavy`, `_run_together`, `_merge_layer` | — |
| 10 | **Scoring and completeness.** `_assemble()` scores the signals, sets the verdict, `scan_status`, `incomplete_reasons`, `verdict_label` and provenance. | `_assemble` | — |
| 11 | **Reply validation.** The worker sends `completed` (a snapshot), `log` (at most 200 records) and `ok` (the result). The parent reads each message with a {{fact:worker_reply_mib}} MiB limit, parses JSON (never pickle), checks the shape and types with `check_reply()`, and refuses a result whose `file_path` is not the file it sent. | `read_reply`, `check_reply`, `_final_reply` | worker → parent: JSON only |
| 12 | **Report, alerts, clean-up.** `scan_one()` returns the result. The CLI prints and writes the report (JSON and text, and spools the cloud view if enabled) and calls `deliver()`: JSON Lines if configured, and an alert through the outbox if the verdict reaches the channel's minimum ({{fact:webhook_min_verdict}} by default). A single-file scan never quarantines automatically. The parent sends `None`, the worker exits, its temporary folder is deleted. | `engine/report.py`, `core/outputs.py`, `core/outbox.py` | parent → receivers: alert metadata only |

Illustrative arithmetic: if only the macro layer fired, with an auto-run trigger
(`Document_Open`) and one execution primitive (`Shell`), the contributions would be
`macro_autoexec` {{fact:w_macro_autoexec}} + `macro_exec_primitive` {{fact:w_macro_critical}} +
`macro_dropper_synergy` {{fact:w_macro_synergy}} = 82 points, Critical. Real files usually fire
several layers at once (YARA's Office-dropper rules, for example).



## Journey 2: an e-mail carrying an archive carrying a document and a script

The background service polls a mailbox. A new message, `invoice.eml`, says "Password:
4471" in its body and carries `docs.zip`, an encrypted archive with `report.docm` and
`pay.js` inside.

| # | Step | Owner (code) | What crosses a boundary |
|---|---|---|---|
| 1 | **Intake.** `MailboxScanner` fetches the message read-only over TLS, writes it to a private temporary folder as `.eml`, and passes it to `_scan_targets()`. | `core/mailbox.py` | IMAP server → host: the raw message |
| 2 | **Admission.** As journey 1, through a pool of up to 4 workers (1 when VirusTotal pacing is on, because the free quota is per process). | `default_workers()` | — |
| 3 | **Depth 0, the message.** `ContainerLayer(MailHandler)` runs before prompt-guard. It reads the topmost `Authentication-Results` for SPF/DKIM/DMARC, checks display-name spoofing, reply-to diversion, deceptive links and attachment names, extracts the body (which becomes `ctx.text` for prompt-guard and the LLM) and collects "Password:" candidates. As soon as the container is open the worker sends `container` with the message's own signal. | `engine/containers.py`, `detectors/mail_analyzer.py` | worker → parent: `container` |
| 4 | **Depth 1, the archive.** The attachment is scanned with `scan_file(..., depth 1)`. `ArchiveHandler` opens it with the message's password offered first (`extra_passwords`), then a short list of common ones and the file stem. Unsafe names (path traversal, links, device names) are refused and flagged; nested archives are expanded by the extractor; the size, entry and ratio limits apply; risky members take the scan budget first. | `ContainerExtractor` | — (members are written only inside the worker's temp folder) |
| 5 | **Depth 2, the members.** `report.docm` and `pay.js` each go through the full pipeline at depth 2. Containers found *inside* them would only be listed, because depth 2 equals `max_nesting`. | `scan_container` | — |
| 6 | **Back up one level.** Each member's result becomes a summary in the archive's result; the highest-scoring member's contributions become the archive's `worst` and are re-scored as `archive_member:...`; members' incomplete reasons and what they shared are carried up. When a direct member of the top-level file finishes, the worker sends `member`. | `scan_container`, `_worst` | worker → parent: `member` |
| 7 | **Back up to the message.** The message scores its own indicators plus its worst attachment's contributions, prefixed `mail_attachment:` (so `mail_attachment:archive_member:macro_autoexec`). The password found in the body opening an attached archive is itself an indicator (`mail_archive_password_in_body`, gateway evasion). | `detectors/scoring.py` | — |
| 8 | **Optional external analysis.** VirusTotal is asked about every scanned file's hash, members included; the LLM is asked about the message body and the document text; images and archives are skipped. The sandbox, if configured, receives only the top-level file and only if the static score is at least 25 (`SANDBOX_SUBMIT=suspicious`). | `engine/external.py`, `SandboxLayer` | hashes, text, possibly the `.eml` file |
| 9 | **Completeness.** If the archive could not be decrypted, its members are `locked` and so is the message. A member over a budget, a missing decompressor, or a container at the nesting limit makes it `partial`. | `assess` | — |
| 10 | **Result and delivery.** As journey 1. Because this is a batch scan, `collect()` quarantines the **temporary `.eml` copy** when the verdict reaches `AUTO_QUARANTINE`; the message on the server is never changed. The temporary folder is deleted afterwards. | `collect()`, `QuarantineVault` | alert metadata to receivers |

If the worker stops during this journey (time limit, crash, memory limit), the parent
keeps what it already received: the message's own findings (`container`) and every
finished attachment (`member`). The file's result then carries those findings under
`partial_evidence` and takes the higher of `scan_failed` ({{fact:w_scan_failed}} points)
and the kept evidence (chapter 8).

@diagram 7-one-file-sequence.svg | Diagram 7 - one file across processes. Dashed arrows are checked JSON messages from the worker or answers from a service. | landscape

@diagram 9-nested-containers.svg | Diagram 9 - nested containers: what goes down and what comes back up. Illustrative names. | landscape
