# Findings register (production-hardening branch)

One current status list for every finding of the production review. It replaces
the status columns of older tables (PROJECT_REVIEW 28.1, 31.10, 32.6, 33.6 and the
handoff's earlier "still open" lists), which are kept as history and may say
"open" for items fixed later. Details, reproductions and evidence stay where they
were recorded: [PROJECT_REVIEW](PROJECT_REVIEW.md) (sections 28 to 34) and
[HANDOFF](HANDOFF.md) (groups 1 to 48 and the 2026-11-14 reliability follow-up).
Current code baseline: `b6966f8` (review of thirteen items, 2026-11-17; see
[the task brief](tasks/review-items-2026-11-17.md) and the
[verification matrix](VERIFICATION_MATRIX.md)). Earlier baselines: `72aa761`
([local validation](tasks/reliability-local-validation.md)), `88b2db1`.

**Categories:** *defect* (confirmed by a reproduction or an unambiguous code
path), *suspicion* (not confirmed), *gap* (a check that needs another platform or
service), *improvement* (optional). **Fixed** means a code or document change with
a regression test that failed before it and passes after it, on this Mac only.

## 1. Fixed in this branch

| ID | Plain description | Fix (commit) |
|---|---|---|
| H1 | FIFOs and device files in a scanned folder hung the scanner | `eb62c0b` |
| H2 | Mail HTML patterns backtracked: a 20 KB body could hold a worker | `eb62c0b` |
| H3 | GUI scans never sent webhook, e-mail or JSON Lines alerts | `3be37a2` |
| H4, H4-b, M13 | Large or unreadable Office parts were skipped silently; the scan read complete | `b1ce30f`, `33fd895` |
| H5, M22, I-5 | A ~165-byte script (and seven other inputs) held a worker until its limit; a guard test now times every detector pattern | `c09f904` |
| H6 (a), (b) | A timed-out or crashed scan became "Medium (failed scan)" with no notice and lost its findings | `592e920`, `8978c68` |
| H-04+ | Web-page checks were cubic or quadratic in the page size | `804b96b` |
| M1, M2, M6, M11 | E-mail alerts lost while intel was down; duplicate alerts; worker logs lost; cloud log feeding on itself | `3be37a2` |
| M3, M5, M7, M8, M14, M16 | Containment state, placeholder VirusTotal key, `--scan-now` without a terminal, IMAP skipping on start failure, backup image version, release version check | `3e2eed2` (M16's check runs only on a tag: see 5) |
| M4 | The API read and spooled an upload before checking the token | `23c0565` |
| M9, M10, M12 | Non-ASCII report names, same-second report overwrite, `..` member names stopping later members | `eb62c0b` |
| M15 | A wheel install shipped no YARA rules, and YARA was silently off | `8bcbe10` |
| M17 | A failed JSON Lines or report write dropped the alerts | `e334704` |
| M18 | Workers replied with pickle: a compromised worker could run code in the parent | `34c5e76` |
| M19 | A second `href` hid a deceptive link | `c074243` |
| M20, L-E9, I-T3 | Windows device names in the extraction folder; control and bidirectional characters in logs, reports, GUI | `f623adb` |
| M21, L-B7 | `pypdf` with seven advisories; a test that depended on the QR decoder | `17a499d` |
| M23 | A fake certificate entry hid a program appended to a program | `eccdde4` |
| M24 | Trailing dots or spaces in names removed the executable and double-extension findings | `72d6fcb` |
| M25 | A lost canary registry silenced the tripwire (alert only; no containment) | `cabf3db` |
| M26 | The sandbox wait outlasted the scan limit and cost the file its findings | `4665b0c` (start-up check), `bd9514e`, `f6c0bab`, `9ae8e64` |
| M27 | Docker never passed rule-pack keys; a pack was used with no key configured | `4665b0c`, `c0b33e3` |
| M28 | The GUI's scan folders and types were ignored by the service it installs | `8e240a7` |
| M29 | The shadow-copy rule fired on listing scripts and on prose quoting the command | `b34181b` (scripts), `724484d` (pages and text) |
| M30 | A right-to-left override in a top-level name was not a finding | `2282119` |
| M31 | One broken `.rels` part dropped every relationship finding | `c825986` |
| M32 | A short ransomware advisory scored High 73 | `724484d` |
| M33 | `charset=idna` or `undefined` ended the whole mail analysis | `27b2dd9` |
| M34 | A failed or invalid CAPE report was taken and cached as an empty finished report | `9ae8e64` |
| L-A1 to L-A8 | API work folder in results; `backup.sh` umask; non-atomic key and records; version parsing; containment record order; spool races; webhook error leaks; e-mail cap counting | `75c1819`, `a23cc2c`, `85acb6e`, `c26f018` |
| L-B1, L-B3, L-B4, L-B5 | README install command; smoke test used the real home; `.dockerignore` gaps; stale docs | `3e2eed2`, `9449038`, `4c9bc37` |
| L-C1 to L-C11 | Hash-database import, exit code 1, report layer list, evaluation tools, autostart plist, LLM posture, IMAP truncation, tool details | `4e8d280`, `85acb6e`, `374dd29`, `7e5f4a6`, `70ce04c`, `04f396e` |
| L-D1 | A XAR entry's declared range was used unchecked (could request a large read) | `e68d50a` |
| L-D2 to L-D8 | Truncated streams read complete; emulation and QR limits; script read before size check; unbounded skip lists; YARA namespaces; CHM read limit; silent cell and page limits | `dda5936`, `a8b1e03`, `4c9bc37`, `ad69e65`, `50d715d`, `37ee441`, `3fd0164` |
| L-E1, L-E2, L-E3, L-E7, L-E8, L-E10, L-E11, L-E12 | Layer errors overwritten; NaN settings; multi-line secrets; shared not-scanned count; worker log tail; metrics lock; empty env secret; ransom-note name regex | `67fbbfa`, `9a1bd35`, `85acb6e`, `742a1cc`, `fbc65dd`, `9b0af65` |
| L-E4 | `.docx` text bypassed the Office size limits | `e68d50a` |
| L-G1, L-L1, L-GUI | LLM answers shown as skipped; unusable LLM replies read complete; GUI version label | `fbc65dd`, `7b40b9e`, `3e2eed2` |
| L-T1, I-T1, I-T2, S-T1 | Test isolation (exported keys, logging level, unclosed caches, sleeps) | `9449038`, `cf82df4`, `0fb39b2` |
| I-1 (part) | Eight macro-capable Office types offered to folder scans | `d95e5e5` |
| I-2 (archives) | Risky archive members take the 25-member budget first | `e3f1cd3` |
| I-3 | Daily dependency audit; manual lock-refresh tool | `4c68756`, `42852d3` |
| I-6 | The sandbox wait (M26), the VirusTotal upload wait, the VirusTotal lookup and the LLM request respect the worker's limit: cooperatively (time left per call), and if a call stalls past the limit the worker is stopped and the result it sent before the call is kept (`scan_results.stopped_layers`; possible transmissions labelled); completed VirusTotal/LLM answers are kept by coordinated snapshots when another layer stalls | `bd9514e`, `f6c0bab`, `873fc0a`, `489ace5`, `2004d79` |
| L-E5 | OCR ran without a timeout; on macOS and Linux a stopped worker's helper programs kept running; on macOS, observed helpers that started a new session escaped the group kill | `9572a10`, `2004d79` (macOS only; see residuals) |
| L-E6 | On Windows, "access denied" made a live process count as dead (stale-folder sweep) | `5984d05` (stand-in kernel32 only; Windows unverified) |
| S-Y2, S-Y3 | Defender folder exclusion and administrative shortcut false positives | `88b2db1`; retained |
| S-Y4 (service coverage) | `88b2db1` had dropped service-only `net stop` / `sc stop` detection; restored with the known tradeoff in section 2 | `72aa761` |
| I-B1, I-B2, I-B4, I-B5 | User agent; hash-pinned SBOM tool; profiling tool; member indicators in alerts | `742a1cc`, `70ce04c`, `fbc65dd` |
| I-x | Cache purge while running; IMAP fetch label; intel auth before JSON; unused `send_webhook`; evaluation errors counted as Clean | `9a1bd35`, `9892704`, `70ce04c` |
| ML version (suspicion, now confirmed) | A model saved by another scikit-learn version was used silently | `15b6760` |
| Release pip upgrade | An unhashed `pip install --upgrade pip` in the release job | `109df77` |
| I-4 | A scheduled scan held back the alert-outbox retry, canary checks and cloud uploads of the background service (shown by a bounded probe); they now run on their own thread, scans stay on the main loop | `f8af202` |
| M35 | A partly unscanned folder-monitor batch dropped the report, JSON Lines and alerts of the files that were scanned and queued them again; an auto-quarantined file then never alerted | `6e1190c` |
| I-T4 | A developer's own `.env` (scan settings written by the GUI) failed a shared-settings test | `43cd1d4` |
| Eval summary | The evaluation summary did not show rates on complete scans, family-label coverage or dominant families | `0acd78b` |
| Layer order | Ordering dependencies between layers were implicit; now declared and checked (no layer moved) | `8686cd2` |
| D43 | Protection and support wording: extraction "sandbox", worker isolation, monitoring after a write, the dated 0.7% figure, `--scan-imap` in Docker, the GUI "Protection on" label | `b6966f8` |
| D44 | Architecture: deployment and trust-boundary diagram; `scan_directory()` in the flowchart; Graphify page marked as a `72aa761` snapshot | `fde684c` |

**Documentation only:** D1 to D9, D11 to D13, D15 to D25, D27 to D42, L-B2 (server
lock and secrets), L-B6 (platform claims), D26 (`db01796`: Python 3.9 stays
supported). D10 and D14 (release-state text) are left as they are on purpose.

## 2. Confirmed and unresolved

| ID | Description | Why it stays open | Next action |
|---|---|---|---|
| 27.5 / B4 | Long fuzz campaigns ended in out-of-memory failures | Restricted: replay only in the isolated VM | VM investigation, separately authorized |

### Documented ambiguities (left unchanged on purpose)

| ID | What matches | Why it is not changed |
|---|---|---|
| S-Y1 | `Event_Log_Clearing` scores a lab log reset (`Clear-EventLog -LogName Application`) Medium 40, the same as a script clearing every log | The command is the technique; it scores Medium (below the alert floor), and the log name alone does not separate maintenance from anti-forensics |
| S-Y4 (encryptor strings) | `Ransomware_Encryptor_Target_Extensions` matches a program-shaped string set (user-data extensions, crypto and file-walk APIs, "readme", "decrypt") that a backup tool could also hold | The rule's inputs are identical for both; the harmless example was constructed here, not found |
| S-Y4 (services, tradeoff) | Service-only `net stop` / `sc stop` coverage restored, High 65 on the two added inert fixtures; backup pre-freeze also returns High 65 | Identical observable service inhibition cannot establish intent; the false positive remains explicit, without an administrator whitelist |

All three were re-scored at `b6966f8` with unchanged results. Concrete policy
options with their coverage and false-positive tradeoffs (P1 to P3) are in the
[task brief](tasks/review-items-2026-11-17.md#2-detection-policy-proposals-s-y1-s-y4-for-approval-not-implemented);
none is implemented.

### Residuals of fixed items

- **L-E5:** macOS now tracks observed descendants by native lifetime identity
  and signals with kernel generation checks, including new sessions. Unobserved
  detached/reparented descendants, discovery overflow, unsupported APIs and
  teardown races remain limits. A bounded probe on 2026-11-17 confirmed the
  first: a helper whose parent exits before the first discovery pass survives. Linux session escapes and Windows need platform
  work; real Tesseract/poppler remain unverified. See the local-validation brief.
- **I-6, M26:** the cooperative bounds are best effort (a name lookup, a dripped
  answer, redirects or a proxy can outlast them); the guarantee is the worker's scan
  limit. Completed VirusTotal/LLM answers are now retained by coordinated snapshots
  (focused regressions and the final safe suite at `72aa761` passed on macOS). The intel
  service's own requests can continue after a worker stops waiting.

## 3. Suspicions, not confirmed

| ID | Description | Status |
|---|---|---|
| S-01 | A crafted DMG could make 7-Zip write outside the extraction folder | Risk reduced by an existing change: members are streamed with `7z e -so` (`600d8bc`); those tests skip here (no 7-Zip) |
| S-03 | Concurrent canary checks race on the last signature | Still not reproduced. Because I-4 runs the scheduled check on its own thread (and the real-time watcher already ran one), the compare-and-set now runs under a lock (`f8af202`); the two-thread test still passes |
| S-04 | `requirements.lock` does not install on Python 3.9 | A recorded CI exception: the 3.9 job installs the latest releases instead (`tests.yml`) |
| H-03, OOM-H | Nested containers keep each level in memory; XAR TOC and pypdf memory hypotheses | Not measured: memory measurements are excluded on this Mac (VM only). L-D1's range check (`e68d50a`) removes one of the XAR paths |

## 4. Deferred improvements (not started on purpose)

The other twelve I-1 file types; I-2 ordering for mail attachments; automatic lock updates
(Dependabot, or a workflow that opens a PR); replacing `httpx` for the Starlette
test-client warning (a dependency change); shipping the placeholder fuzzy-signature
sample in a wheel (it matches nothing).

## 5. Verification that needs another platform or service

The current matrix, by platform and service, is [VERIFICATION_MATRIX](VERIFICATION_MATRIX.md).

- **CI:** no workflow has run on any commit after `3e5a3f2`; the daily audit (I-3)
  and the release job (M16, I-B2, the pip change) run only on GitHub.
- **Windows:** M2, M9, M20, M24 (what mail clients and archive tools save), M30
  names, L-A5 order, L-E6 (only a stand-in kernel32 was used), the Job Object path for
  L-E5, worker pipes (M18), toasts, containment, autostart.
- **Linux:** the worker process groups (L-E5) and the rest of the suite (no CI run).
- **Docker:** `deploy/check-deployment.sh`, M26 through intel (and intel's own CAPE
  requests, which continue after a worker stops waiting), M27, I-B3, the L-B4
  image, backup scripts on real volumes, D22/D23.
- **Real services and programs:** a real CAPE server (M26, M34), VirusTotal and a real
  LLM (I-6, L-L1), Tesseract and poppler (L-E5), SMTP, webhook receivers, S3; the GUI
  on a display (M28, L-C6, L-G1, L-E9, M30).
- **Hardware:** Linux and Windows ARM64, macOS Intel (no runner).
- **Corpora:** a benign corpus for M29, M32 and S-Y1 to S-Y4 (only synthetic
  examples were used: `tests/fp_examples.py`, `tests/sy_examples.py`); real-sample
  evaluation in the VM (detection rate unmeasured).

## 6. Owner decisions

- The M26 "not enough time to submit" threshold: less than one 15 s poll left after
  the margin. **Unchanged; local virtual-clock measurements support retaining it pending real latency evidence and an owner policy decision.**
- The documented ambiguities in section 2 (S-Y1, the encryptor strings, the S-Y4
  service tradeoff): accept, choose one of the proposals P1 to P3, or decide with
  a benign admin-script and backup-tool corpus.
- Whether to authorise the bounded 27.5 / B4 VM investigation (task brief section 3).
- How CI should run on this branch (a pull request would also start the restricted
  Atheris campaigns; a push plus manual dispatch would not).
- Exit code 2's three meanings and the IMAP fetch retry: kept as they are.
- When to drop Python 3.9 (kept for now).
