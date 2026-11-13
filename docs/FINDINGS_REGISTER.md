# Findings register (production-hardening branch)

One current status list for every finding of the production review. It replaces
the status columns of older tables (PROJECT_REVIEW 28.1, 31.10, 32.6, 33.6 and the
handoff's earlier "still open" lists), which are kept as history and may say
"open" for items fixed later. Details, reproductions and evidence stay where they
were recorded: [PROJECT_REVIEW](PROJECT_REVIEW.md) (sections 28 to 34) and
[HANDOFF](HANDOFF.md) (groups 1 to 44). Status as of HEAD `db01796`, 2026-11-13.

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
| I-6 (part) | The sandbox wait (M26) and the VirusTotal upload wait end with the worker's limit | `bd9514e`, `f6c0bab`, `873fc0a` |
| I-B1, I-B2, I-B4, I-B5 | User agent; hash-pinned SBOM tool; profiling tool; member indicators in alerts | `742a1cc`, `70ce04c`, `fbc65dd` |
| I-x | Cache purge while running; IMAP fetch label; intel auth before JSON; unused `send_webhook`; evaluation errors counted as Clean | `9a1bd35`, `9892704`, `70ce04c` |
| ML version (suspicion, now confirmed) | A model saved by another scikit-learn version was used silently | `15b6760` |
| Release pip upgrade | An unhashed `pip install --upgrade pip` in the release job | `109df77` |

**Documentation only:** D1 to D9, D11 to D13, D15 to D25, D27 to D42, L-B2 (server
lock and secrets), L-B6 (platform claims), D26 (`db01796`: Python 3.9 stays
supported). D10 and D14 (release-state text) are left as they are on purpose.

## 2. Confirmed and unresolved

| ID | Description | Why it stays open | Next action |
|---|---|---|---|
| I-6 (rest) | The VirusTotal hash lookup (with its retries) and the LLM request are bounded only by their own timeouts; a stall past the scan limit still fails the file and loses its static findings | A reliable bound needs the M26 provisional mechanism extended to the slow-layer stage, with per-service transmission progress (hash, file, text): a worker-protocol extension, not a focused fix | Owner decides whether to extend it |
| L-E5 | OCR (`pdf2image`, `pytesseract`) runs with no timeout; on macOS and Linux a killed worker's helper processes are not killed with it | Tesseract is not installed here, and killing helpers needs process-group handling in the worker lifecycle | On a host with Tesseract: add timeouts and a process-group kill, with a stand-in OCR process |
| L-E6 | Windows `_pid_alive` reads "access denied" as "dead" (stale-folder sweep) | Windows only; low impact (temp folders are per user) | Fix and test on Windows |
| S-Y2 | `PowerShell_Defender_Tampering`: a build-agent setup script adding a Defender folder exclusion scores Critical 100 | Attackers run the same command (T1562.001); intent is not in the text | Owner decision with a benign admin-script corpus |
| S-Y1 | `Event_Log_Clearing`: a log-reset script scores Medium 40 (below the alert floor) | Same command as the technique; low impact | As S-Y2 |
| 27.5 / B4 | Long fuzz campaigns ended in out-of-memory failures | Restricted: replay only in the isolated VM | VM investigation, separately authorized |

## 3. Suspicions, not confirmed

| ID | Description | Status |
|---|---|---|
| S-01 | A crafted DMG could make 7-Zip write outside the extraction folder | Risk reduced by an existing change: members are streamed with `7z e -so` (`600d8bc`); those tests skip here (no 7-Zip) |
| S-03 | Concurrent canary checks race on the last signature | Not reproduced: the two-thread test (`af8deda`, `tests/test_alerts.py`) shows one alert; it relies on the GIL, no lock was added |
| S-04 | `requirements.lock` does not install on Python 3.9 | A recorded CI exception: the 3.9 job installs the latest releases instead (`tests.yml`) |
| S-Y3 | `LNK_Shortcut_Runs_Script_Host` may match ordinary admin shortcuts | Not checked: needs a shell-link file and a corpus |
| S-Y4 | `Stops_Services` and `Encryptor_Target_Extensions` may match backup agents | Not reproduced on one synthetic backup-window script (Clean) |
| H-03, OOM-H | Nested containers keep each level in memory; XAR TOC and pypdf memory hypotheses | Not measured: memory measurements are excluded on this Mac (VM only) |

## 4. Deferred improvements (not started on purpose)

The other twelve I-1 file types; I-2 ordering for mail attachments; I-4 (scheduled
background scans on a worker thread; needs S-03 settled); automatic lock updates
(Dependabot, or a workflow that opens a PR); replacing `httpx` for the Starlette
test-client warning (a dependency change); shipping the placeholder fuzzy-signature
sample in a wheel (it matches nothing).

## 5. Verification that needs another platform or service

- **CI:** no workflow has run on any commit after `3e5a3f2`; the daily audit (I-3)
  and the release job (M16, I-B2, the pip change) run only on GitHub.
- **Windows:** M2, M9, M20, M24 (what mail clients and archive tools save), M30
  names, L-A5 order, L-E6, worker pipes (M18), toasts, containment, autostart.
- **Docker:** `deploy/check-deployment.sh`, M26 through intel (and intel's own CAPE
  requests, which continue after a worker stops waiting), M27, I-B3, the L-B4
  image, backup scripts on real volumes, D22/D23.
- **Real services:** a real CAPE server (M26, M34), SMTP, webhook receivers, S3,
  VirusTotal, a real LLM (L-L1); the GUI on a display (M28, L-C6, L-G1, L-E9, M30).
- **Hardware:** Linux and Windows ARM64, macOS Intel (no runner).
- **Corpora:** a benign corpus for M29, M32 and S-Y1 to S-Y4 (only synthetic
  examples were used); real-sample evaluation in the VM (detection rate unmeasured).

## 6. Owner decisions

- The M26 "not enough time to submit" threshold: less than one 15 s poll left after
  the margin. Implemented as a working default; **not yet confirmed by the owner**.
- Whether to extend the provisional-result mechanism to VirusTotal and the LLM (I-6).
- S-Y1 and S-Y2 rule conditions (needs a benign admin-script corpus).
- How CI should run on this branch (a pull request would also start the restricted
  Atheris campaigns; a push plus manual dispatch would not).
- Exit code 2's three meanings and the IMAP fetch retry: recommended to keep.
- When to drop Python 3.9 (kept for now).
