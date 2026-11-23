# Review of thirteen items (2026-11-17)

Sanitised technical brief. The owner asked for thirteen review items from an
earlier discussion of the code, findings and diagrams to be validated against the
current branch, with focused repairs where a defect is confirmed. Constraints:
no change to detection weights, thresholds, inspection coverage, result schema or
intentional interface behaviour without separate approval; no malware, real
samples, OOM reproduction, fuzz campaigns or artifact replay on the host; local
commits only (no push, merge, tag or release).

Baseline at the start: `74b6aef` (code unchanged since `72aa761`). The Graphify
graph (built from `72aa761`) matched the code at the start and was used for
navigation only; every relationship used here was checked in the source.

## 1. Disposition per item

| # | Item | Disposition | Result |
|---|---|---|---|
| 1 | Detection effectiveness (M1/X1) | Verification gap; tooling improvement | No rates measured. The evaluation summary now reports rates on complete scans only, family-label coverage and dominant families (`0acd78b`). A reproducible procedure is in DATASET_PLAN Part 3. No defect was found in deduplication or the family-grouped split. |
| 2 | S-Y1 / S-Y4 ambiguities | Known limitation, unchanged | All three still apply at HEAD (scores in section 2). Proposals for approval in section 2; no rule changed. |
| 3 | 27.5 / B4 OOM | Unresolved; blocked on the VM | Harness and product memory paths compared by reading; bounded VM plan in section 3. Nothing replayed or reproduced. |
| 4 | L-E5 helper cleanup | Known limitation; macOS verified, Linux/Windows pending | Existing tests pass here. A bounded inert probe confirmed the documented limit (a helper whose parent exits before discovery survives); no repair is possible without a broad kill, which is out of bounds. Section 4. |
| 5 | Verification gaps | Verification gap | Matrix in [VERIFICATION_MATRIX](../VERIFICATION_MATRIX.md); local checks run, platform and service checks pending. |
| 6 | I-4 scheduler blocking | **Confirmed defect, fixed** | A bounded probe showed the outbox retry waiting for a running scan. Short jobs now run on their own scheduler thread; scans stay on the main loop (no overlap, unchanged Ctrl+C). S-03 lock added (`f8af202`). |
| 7 | RansomwareScanner responsibilities | Optional improvement; not changed | Six cohesive files (about 2,100 lines); callers outside `engine/` use two private members (`_scan_targets` twice, `_load_kaggle_database` once); layers read about 36 scanner attributes, the intended registry role. The confirmed output defect (item 9) was in a caller. No extraction is justified now. |
| 8 | Implicit pipeline ordering | Improvement, done | Real dependencies declared as data with a checker and tests; no layer moved (`8686cd2`). |
| 9 | Output behaviour by entry point | **One confirmed defect, fixed**; the rest intentional | A partly unscanned monitor batch dropped the outputs of the files that were scanned (an auto-quarantined file then never alerted) (`6e1190c`). Behaviour table in architecture/README section 4 (M35). |
| 10 | Support boundaries | Documentation gap, fixed | Support table in VERIFICATION_MATRIX section 1 (D43, `b6966f8`); RELEASE_SCOPE no longer lists `--scan-imap` for the Docker CLI (no network there). |
| 11 | Protection claims | Two wording issues, fixed | README: extraction "sandbox" is a temporary folder; worker isolation is not a security sandbox; monitoring scans after a write; the 0.7% false-alarm figure dated to 4.6.0. GUI "Protection on" now reads "Scheduled scans on" (it shows that setting only). Canary wording was already accurate. |
| 12 | Deployment / trust-boundary view | Added | Diagram 5 with editable source, built with the other four (`fde684c`). |
| 13 | Diagram accuracy and quality | Two corrections; snapshot labelled | `scan_directory()` added to the flowchart and README table; the Graphify page now states its `72aa761` snapshot. All five diagrams rebuilt and inspected in headless-Chrome screenshots. |

## 2. Detection-policy proposals (S-Y1, S-Y4): for approval, not implemented

Scores of the inert fixtures (`tests/sy_examples.py`) at HEAD, in-process, QR
off: `rotate_logs.ps1` Medium 40 (`Event_Log_Clearing`); `backup_prefreeze.bat`
High 65 (`Ransomware_Stops_Services_And_Processes`); `backup_agent.exe` High 65
(`Ransomware_Encryptor_Target_Extensions`). The harmful counterparts score the
same (Medium 40, High 65, High 65). Each rule's inputs are identical in both
cases, so no wording or exemption separates them; only additional evidence can.

**P1 (S-Y1, log clearing).** Split `Event_Log_Clearing` by scope: clearing all
logs (the `wevtutil el` loop) or the Security log keeps Medium; clearing only the
Application log drops to Low.
- Coverage: an attacker who clears only the Application log scores Low instead
  of Medium. Neither result alerts at the default floor today (Medium is below it),
  so alert coverage is unchanged; the change shows in reports and in the evaluation.
- False positives: the lab-reset example drops to Low.
- Validation: the S-Y fixtures, the regression corpus, and a benign corpus of
  maintenance scripts in the VM; record the per-rule hit counts before and after.

**P2 (S-Y4, service stopping).** Keep High for service-only stopping, but add a
corroboration step: when the same script also *restarts* at least half of the
services it stopped (`net start`, `sc start`, `Start-Service`) and has no
recovery-inhibition indicator (shadow-copy deletion, `wbadmin delete`,
`bcdedit ... recoveryenabled no`, Office or mail `taskkill`), score Medium.
- Coverage: a dropper that adds matching start commands is downgraded. Adding
  them is cheap, so this trades evasion resistance for fewer false positives.
  Scripts that restart services only after encryption would also be downgraded.
- False positives: pre-freeze/post-thaw pairs in one file drop below the alert
  floor; a pre-freeze script without its thaw step stays High.
- Validation: the S-Y fixtures plus new inert pairs; a benign corpus of backup
  vendor scripts; the regression corpus unchanged.

**P3 (S-Y4, encryptor strings).** Keep the rule but require one
ransom-specific note string (`.onion`, "your files", "bitcoin", "recovery
key" plus a payment word) for High; the generic set ("readme", "decrypt") alone
scores Medium.
- Coverage: encryptors that keep their note in an encrypted or external resource
  drop from High to Medium; the PE layer's own encryption-and-walk import signal
  is unaffected.
- False positives: backup and archive tools with "readme" and "decrypt" strings
  drop to Medium.
- Validation: the fixtures, the regression corpus and the benign Windows-binary
  set in the VM; per-family detection before and after on the real-sample set.

**Alternative for all three:** keep the rules and accept the documented false
positives until the benign corpus exists (the current state). Every option above
is a detection-content change and needs a signed rule pack and an owner decision.

## 3. 27.5 / B4: memory evidence and a bounded VM plan

**Evidence (unchanged):** three campaign OOM exits (exit 71, libFuzzer
`-rss_limit_mb=4096`, peak RSS 4,261 to 4,628 MB), with no allocation trace and no
per-target attribution. Nothing was replayed here.

**Harness and product differ (read from `fuzz/fuzz_b4.py`, `fuzz/fuzz_parsers.py`,
`.github/workflows/fuzz.yml`, `engine/workers.py`):**

| | Fuzz harness | Product |
|---|---|---|
| Process | one long-lived process runs every target, with Atheris instrumentation of all imported modules | one worker process per file in flight, reused for the next file |
| Analyzer objects | created once and reused for every input | created per worker (one scanner per worker) |
| Memory limit | libFuzzer's whole-process RSS at 4,096 MB (interpreter, instrumentation, in-memory corpus, YARA rules included) | `WORKER_MEMORY_MB` (2,048) per worker: RLIMIT_AS on Linux, Job Object on Windows, RSS watchdog on macOS; over it the file fails, the parent is unaffected |
| Input size | up to 1 MiB (`-max_len=1048576`) | up to the configured file and member limits |

So an OOM in the harness is one of: (H1) one input needs a large allocation
(product-relevant: in the product that file would fail its scan at the worker
limit); (H2) memory accumulates across inputs in reused objects, a library cache
or allocator fragmentation (relevant to both, because workers are reused);
(H3) harness overhead (instrumentation, corpus) near the 4 GB line. None of these
is confirmed. The XAR and pypdf ideas (OOM-H) remain hypotheses.

**Bounded plan (needs separate VM and artifact authorisation):**

0. Prepare: an isolated, snapshotted analysis VM with no shared folders, no
   network and no credentials; the three artifacts fetched by digest into the VM
   only; the harness commit of each run checked out.
1. Classify without parsing: read the first byte of each artifact and map it to
   its target with that commit's `TARGETS` list (`data[0] % len(TARGETS)`;
   `0xFF` is the cpio target in `fuzz_parsers.py`). Record target and size.
2. Single input (H1): run one artifact once through its own target in a fresh
   process under an OS limit of 512 MiB, one CPU and a 10 s wall limit, with
   `tracemalloc` on; record exit status, peak RSS (`getrusage`) and the top ten
   allocation sites (file and line only). Stop at the first limit hit.
3. Accumulation (H2), only if step 2 stays small: run the same target over the
   committed seed corpus in one process for a fixed number of iterations under
   the same limit, sampling RSS every 1,000 inputs. A steady rise points to
   retained state; a flat line points away from H2.
4. Product path: scan the artifact through `scan_isolated()` with
   `WORKER_MEMORY_MB=512`; expected result `scan_failed` with a memory reason and
   a healthy parent. Any other outcome is a product finding.
5. Keep only metadata (digests, targets, exit codes, RSS, allocation sites). Do
   not raise limits, run a campaign or change instrumentation without a new
   decision. A small-bound negative result does not rule out the 4 GB failure.

## 4. L-E5: what is verified where

- **Verified on this Mac (macOS 27.2.1, arm64):** `tests/test_escaped_helpers.py`
  and `tests/test_containment.py`: 36 passed, 1 skipped. A bounded probe with
  inert `sleep` helpers, cleaned by recorded PID: a helper started in a new
  session by an intermediate that exits before the first discovery pass
  **survives** `Descendants.stop()`; the same helper is stopped when the
  intermediate is still alive at discovery. This confirms the documented limit;
  without ownership evidence for the orphan there is no safe way to stop it.
- **Mocked only:** the Windows Job Object path and `kernel32` liveness (L-E6).
- **Unverified:** Linux process-group cleanup and session escapes; Windows
  helpers; real Tesseract and poppler.

## 5. Commits of this review

`f8af202` (I-4, S-03), `6e1190c` (M35, monitor outputs), `0acd78b` (evaluation
summary and procedure), `8686cd2` (layer order), `43cd1d4` (I-T4, test
isolation), `b6966f8` (D43, wording and the GUI label), `fde684c` (D44,
diagrams), then the documentation checkpoint with this brief.
