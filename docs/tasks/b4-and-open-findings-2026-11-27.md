# B4 investigation and open findings (2026-11-27, second pass)

Sanitised technical brief. Branch `review/remaining-issues-2026-11-27` (PR #49,
open), continued locally on top of its head `6c42dc8`. **Nothing in this pass is
pushed**: publication, PR updates, merge, tag, release and workflow dispatch wait
for the owner. Restricted fuzz/OOM validation stays in the isolated VM.

## 1. B4 / 27.5: what the historical evidence says

Source: the text logs of the four `parser-fuzz` runs (read with `gh run view
--log-failed`; no artifact or corpus was downloaded). Only two runs reached the
campaign step; the two later runs (`b55c60e`, `3e5a3f2`) skipped it (no change).

| Run / job | Commit | Group | End | Executions | RSS before | Peak |
|---|---|---|---|---|---|---|
| 40969502006 / 123782397665 | `b2e8aea` | b4 | OOM, exit 71 | 13,639 | 289 MB, flat for 20 s | 4,314 MB |
| 40969502006 / 123782398098 | `b2e8aea` | parsers | uncaught exception in `read_cpio` (fixed `673acdc`) | 104 | 236 MB | 236 MB |
| 40974246237 / 123798293969 | `673acdc` | b4 | OOM, exit 71 | 2,500 | 246 MB, then 3,045 MB at #1,959 | 4,261 MB |
| 40974246237 / 123798293941 | `673acdc` | parsers | OOM, exit 71 | 36,433 | 236 to 245 MB, flat for 85 s | 4,627 MB |

Corrections to earlier records:

- These were **not long campaigns**: each OOM came 30 to 85 seconds after fuzzing
  started (job time about 3 minutes), not near the end of the 1-hour budget.
- The earlier statement "B4 has never been reproduced anywhere" is wrong as
  worded. The OOM was **observed three times in CI**; it has **never been
  replayed** and its root cause is **not confirmed**.
- Inputs were at most 36,623 bytes (`lim:`), the size of the largest seed (the
  python-docx DOCX), well under `-max_len`.

What the logs support:

- **H1 (one input needs a large allocation): supported.** Before each OOM the
  RSS line is flat, then one input runs 11 to 17 seconds with no other progress
  line while RSS passes 4 GB. The b4 run at `673acdc` shows a first jump to
  3,045 MB (not returned to the OS) before the second input crossed the limit.
- **H2 (accumulation across inputs): not supported** by the flat RSS lines.
- **H3 (harness overhead near the limit): not supported**: baseline 227 to 289 MB.
- The logs do not name the target of the failing input (the harness prints a
  target only on its first completion, and all targets completed in the first
  second). The artifact's first byte names it (plan step 1, VM only).

## 2. B4: defects found and repaired (local commits)

Both are single-input amplifications reachable from both harnesses and from the
product. Neither is confirmed as the cause of the three OOMs.

### 2a. OLE stream read past its file (`2a6f76c`), rank 1

- **Defect (confirmed by code and a bounded probe):** olefile 0.47 reads
  `size / sector_size` sectors along a stream's FAT chain. A declared size larger
  than the FAT is only logged (`DEFECT_INCORRECT`), and a looping chain re-reads
  the same sector, then joins and slices (about 2.3 times the declared size at
  peak). The size field allows 4 GiB. olevba 0.60.2 `detect_vba_macros()` reads
  every stream of every OLE file, orphans included, and also OLE parts inside
  OOXML; the `.msg` reader reads its property streams.
- **Probe (inert, 4 MiB):** a 6,656-byte `.doc` whose stream claims 4 MiB with a
  self-looping FAT entry: olefile read 4,194,304 bytes, peak 9.3 MiB;
  `MacroAnalyzer` peak 9.1 MiB. After the fix: 6,656 bytes read, peak 0.4 MiB,
  same result (`error=''`, no macros).
- **Why it fits the evidence best:** reachable from the b4 targets `macro-doc`
  and `macro-xls` (OLE seed) and the parsers target `f.msg`; needs only integer
  mutations of a directory entry and a FAT entry (libFuzzer ChangeBinInt, CMP
  dictionary entries of 8-byte integers appear in the logs); the Python sector
  loop grows memory over seconds, as observed.
- **Repair:** `detectors/ole_limits.py`, installed from `detectors/__init__.py`,
  caps every declared stream read at the file size through olefile's single
  stream-open path. A stream stores each sector once, so real content never
  exceeds the file: every byte the file holds is still read, and a valid chain
  with an inflated size still returns its real content (tested). An earlier
  draft refused such streams; it was replaced because refusing would let an
  attacker hide a stream by inflating its size.
- **Tests:** `tests/test_ole_limits.py` (4): the two amplification tests fail
  without the cap; the two content tests pass either way.

### 2b. PDF decoded streams held for every page (`63658a3`), rank 2

- **Defect (confirmed):** pypdf 6.21 caches each decoded stream on its object for
  the reader's lifetime. The hidden-text check (`_pdf_invisible_pages`) and the QR
  image walk read page by page, so all pages' decoded content stayed in memory.
  pypdf caps one stream at 75 MB, not the sum.
- **Probe:** peak grew 2 MiB per 2 MiB page (7.5, 13.5, 21.6 MiB for 1, 4, 8
  pages); after the fix 7.5, 9.5, 9.6 MiB. Two Flate layers cost 264 bytes per
  75 MB page, so 50 such pages fit in about 19 KB (about 3.75 GB retained).
  Nested filters decode in pypdf (checked at 1 MiB). Text extraction did not grow.
- **Why it is rank 2:** the PDF seed is one uncompressed page; reaching 27+ pages
  of nested Flate in under 10 seconds of mutation is unlikely.
- **Repair:** `release_decoded_streams(reader)` after each page (both callers).
- **Tests:** peak no longer grows with the page count (failed before: +6.0 MiB
  and +3.1 MiB); a stream shared by pages is still read on each page.

### Unexamined or open B4 hypotheses (no code change)

YARA match objects on repetitive input; ZIP central-directory entries duplicated
onto one member (olevba reads each OLE member fully); olefile sector sizes other
than 512/4096 (logged, not refused) with `read(sector_size)`. None was
measured. Examined in the follow-up (section 8): the olefile directory read is
already bounded (olefile cuts the FAT to the file), and a repeated DIFAT chain
(B4-O2) grows too slowly to match B4.

**Status: candidate root-cause repairs implemented (2a most likely); original
B4 OOM validation pending in the VM.** B4 stays open in the register.

## 3. B4 VM validation procedure (owner-run; not executed here)

**Prerequisites.** Isolated, snapshotted Linux VM (Ubuntu 24.04, x86_64, Python
3.12, like the workflow), no shared folders, no network after setup, no
credentials. Two checkouts: baseline `673acdc` (the last campaign commit) and
the repaired revision (the branch tip recorded in docs/HANDOFF.md once
pushed; it contains `2a6f76c`, `29f2206` and `63658a3`). Install as `.github/workflows/fuzz.yml` does: `apt-get install
7zip unar libzbar0`; `pip install --require-hashes -r requirements.lock`; `pip
install pytest hypothesis`; `pip install --require-hashes -r
fuzz/requirements-linux.txt`. The three OOM artifacts
(`oom-07598bbb…`, `oom-50152c60…`, `oom-fb07a247…`) only if their 14-day
retention left them. Checked by metadata on 2026-11-27: neither run has an
artifact available any more (`total_count=0`); other copies are not ruled out.
Step-by-step guide with bounds, stop conditions, expected results and closing
wordings: [b4-vm-validation-guide.md](b4-vm-validation-guide.md). It adds a
B4-only revision (`673acdc` plus `63658a3`, `2a6f76c`, `29f2206`) so that B4 is
separated from the other changes and dependency updates.

Every step runs under `prlimit --as=$((512*1024*1024)) --cpu=60 timeout 120`
(step 6: 4096 MB, like the workflow) and stops at the first limit hit. Record
exit status, `/usr/bin/time -v` max RSS, and only metadata.

1. **Classify (no parsing):** `python3 -c "import sys; d=open(sys.argv[1],'rb').read(1); print(d[0])" ART`;
   map with the commit's `TARGETS` (`data[0] % len(TARGETS)`, `0xFF` = cpio in
   `fuzz_parsers.py`). Record target, size, SHA-256.
2. **Single replay, baseline:** `python fuzz/fuzz_<group>.py -runs=1 -rss_limit_mb=512 ART`
   at `673acdc`. Expected if H1: OOM at 512 MB.
3. **Single replay, repaired:** the same command at the repaired revision.
   Pass: exits 0 (or a documented exception) with max RSS under 512 MB.
4. **Product path:** `WORKER_MEMORY_MB=512` and scan the artifact with
   `scan_isolated()` (CLI: `ISOLATE_SCANS=true WORKER_MEMORY_MB=512 python RansomwareScanner.py --scan-file ART`
   from a scratch folder). Baseline expected `scan_failed` with a memory reason
   and a healthy parent; repaired expected a normal result. Anything else is a
   product finding.
5. **Synthetic checks (when no artifact is left):** run
   `python -m pytest -q tests/test_ole_limits.py tests/test_prompt_guard.py tests/test_qr.py`
   on both revisions (baseline: copy the three test files in; they fail there),
   then the same probes at 512 MiB declared size under the 512 MiB limit:
   baseline should hit the limit, repaired should not. Optionally measure
   B4-O2 (section 8) with 4096-byte sectors under the same limit to confirm it
   is time-bound, not memory-bound.
6. **Campaign comparison:** the workflow's exact command (`-max_total_time=3600
   -timeout=90 -rss_limit_mb=4096 -max_len=1048576 -seed=20261030`) for both
   groups on both revisions, sampling RSS every 60 s. Pass: the repaired revision
   completes both hours without an OOM; any OOM gets steps 1 to 4 again.

**Sufficient to close B4:** each historical OOM attributed to a target and a
cause (steps 1 to 3), the product contains or no longer reaches it (step 4), and
step 6 passes for both groups on the repaired revision. Without the artifacts
the historical cause stays unconfirmed: the guide (section 8) lists the closing
wordings, which separate validated candidate repairs from a confirmed historical
cause. Campaigns are supporting evidence and never close B4 on their own.

## 4. Other repairs in this pass (local commits)

| ID | Defect | Commit | Tests |
|---|---|---|---|
| PR-S2 | CAPE report buffered (gzip-decoded) and parsed without a bound, in the worker or intel | `5a9e3a5`: streamed, decoded bytes counted, `MAX_REPORT_BYTES` 128 MiB, declared `Content-Length` over it refused unread, response closed on every path; over-limit = unreadable report (M34) | 2 new; fail before |
| PR-Q1 | Restore checked the name, decrypted, then `os.replace()`d whatever appeared there; also replaced a dangling link or an earlier `.restored-<id>` copy | `7221c64`: target reserved with `O_CREAT|O_EXCL`; fallback name; both taken = error, nothing overwritten | 3 new; fail before |
| PR-F1 | `stop()` forgot a loop still scanning; `start()` cleared the shared event, so the old loop resumed beside the new one | `11144b8`: one stop event per run; `stop()` logs a scan still finishing | 1 new; fails before |

## 5. PR-M1 (no code change: policy)

| OS | Mechanism | What is measured | Helpers |
|---|---|---|---|
| Linux | `RLIMIT_AS` set in the worker | address space of the worker | each helper inherits its own copy (N helpers: N times the limit) |
| Windows | Job Object, `ProcessMemoryLimit` | committed memory per process | helpers join the job (kill on close) but each has its own per-process limit; `JobMemoryLimit` (aggregate) is not set |
| macOS | parent watchdog, `proc_pid_rusage` every 0.25 s | physical footprint of the worker pid only | not counted; a fast allocation can pass the limit between samples |

Existing tests prove a single worker is stopped (CI, all three OSes); they do not
cover helpers, reparented helpers (L-E5 residual) or the aggregate. Options for
the owner: (A) Windows `JOB_OBJECT_LIMIT_JOB_MEMORY` (small, aggregate, Windows
only); (B) macOS: sum the footprints of descendants already tracked by
`engine/helper_processes.py` (counts only observed descendants); (C) Linux
cgroup v2 `memory.max` per worker (needs delegation; an operational contract);
(D) keep per-process limits and document. Recommendation: A and B together, C
for container deployments (Docker/Kubernetes already set memory limits on the
analysis container). Needs a VM measurement with an inert helper stand-in.

## 6. Read-only review results (two reviewers, 2026-11-27)

Fixed: AR-1 (`64425f7`), RV-O1 and RV-O2 (`1e22a3f`), RV-L1 (`672730e`), each
with a test that fails before. Open, in the findings register: AR-2, AR-3,
RV-L2, RV-V1, RV-I1, RV-C1; suspicions SU-1 to SU-4 and RV-S6. Areas reviewed
with nothing confirmed: API auth and upload cleanup, configuration precedence and
secret logging, Docker hardening, GUI/CLI/API exit codes, cache TTLs and keys,
intel reply limits, completeness roll-up of layer errors.

## 7. Dependency and release follow-up (read-only)

| PR | State | Change | Notes |
|---|---|---|---|
| #23 | open, mergeable, base `abfe429` | actions/checkout 4.4.0 to 7.0.1 | major; checks ran on an old base |
| #24 | open, mergeable, base `fc91366` | actions/download-artifact 4.3.0 to 8.0.2 | major; `release.yml` uses `merge-multiple: true` into `dist`: confirm unchanged behaviour |
| #25 | open, mergeable, base `abfe429` | actions/setup-python 5.6.0 to 7.1.0 | major; only failure was the PR-R1 timing flake (fixed) |
| #26 | open, mergeable, base `fc91366` | softprops/action-gh-release 2.6.2 to 3.0.3 | major; release-only, cannot be exercised without a tag |
| #27 | open, mergeable, base `fc91366` | sigstore/gh-action-sigstore-python 3.0.0 to 3.5.0 | minor; release-only |
| #46 | draft, open | CPIO fix and validation | head `3e5a3f2` is contained in main: superseded |

Safe local validation is not possible for workflow actions. Recommended: rebase
each on main (Dependabot `@dependabot rebase`, owner action) so `tests`,
`quality` and `docker` run on the current base; the release-only actions
(#24, #26, #27) need either an `-rc` tag run or acceptance on release notes.

## 8. Follow-up pass (owner request, 2026-11-27)

### Open findings

| ID | Result | Commit |
|---|---|---|
| AR-2 | Fixed: 0 for the lockout window or duration is refused at start, as nan already was (L-E2). An operator with 0 set must change it (CHANGELOG) | `0305f29` |
| AR-3 | Fixed: extension and stored name come from the whole client name; the `upload<ext>` fallback keeps a right-to-left override, so M30 sees it. Long names also keep their extension now | `0305f29` |
| RV-L2 | Confirmed and fixed: the scan context carries `text_complete` (heavy layers run on a copy without `scan_results`); an LLM answer is cached only on fully read text | `78fb35a` |
| RV-V1 | Confirmed and fixed as CO-1: no engine results = layer error, not cached | `5962225` |
| RV-C1 | Confirmed and fixed: canary jobs on `CANARY_JOBS` with their own thread; the test fails with the shared layout | `46c788a` |
| RV-I1 | Not a defect as described: no analysis-side cache with intel; each API upload runs in a newly spawned worker. Residual: one scan per spare worker started before an intel restart | none |

### B4 repairs, reviewed

- **OLE (`29f2206`).** Two errors in `2a6f76c` found by reading olefile 0.47 and
  probing: (1) cutting a stream that claims at least the 4,096-byte cutoff to a
  smaller file's size moved its read from the FAT to the MiniFAT (other bytes;
  probe: 512 B from the FAT before, 64 B from the MiniFAT after); (2) treating
  0x7FFFFFFF, olefile's unknown size, as declared read one repeated sector more
  and logged a defect olefile did not. Both fixed; the wrapper is installed only
  over the 0.47 `_open(start, size, force_FAT)` signature and a test requires it.
  Differential (in one process, original vs bounded `_open`): 300/300 valid
  generated files identical (bytes and `parsing_issues`); 1,482/1,500 mutated
  files identical; the other 18 read past the file in the original (8 amplified,
  10 longer), and the bound returns a prefix that holds every distinct sector.
- **Why a private method.** `_open` is olefile's single stream-open path: the
  public `openstream` does not cover the MiniStream load (`root.size`), and
  olevba builds its own `OleFileIO`, so a subclass cannot be passed in.
  Refusing such files before olevba would hide their macros. The tests run
  against the pinned olefile 0.47; they cannot vouch for later versions.
- **Malformed input reporting.** olefile's `parsing_issues` are identical where
  the bytes are; Aegis does not surface olefile parsing issues in reports,
  before or after (unchanged).
- **B4-O2 (new observation, not patched).** A DIFAT chain that repeats one
  sector makes `loadfat` grow the FAT before olefile cuts it: memory linear
  (about 124 KB per repeat), time quadratic (160 repeats: 4.05 s, 19.9 MiB). Far
  too slow to match B4's 4 GB in 11 to 17 s; bounded by the scan time limit.
- **PDF (`63658a3`, kept).** `decoded_self` set to None makes pypdf decode again
  on the next `get_data()`; each check opens its own reader. Object streams are
  released too, so pypdf decodes one again when it next resolves an object in
  it: at most 50 times per file, each within pypdf's 75 MB cap (a hostile file
  could already force 50 such decodes through its content streams). Keeping them
  would let object streams accumulate as pages did. Benign PDFs with object
  streams (1 to 231 pages): 2.3 to 99 ms, no measurable change, peak equal or
  lower. If pypdf renames these attributes the release becomes a no-op; the
  tracemalloc tests would fail on the pinned version only.
- **CAPE (`8852880`).** Over the limit was read as "not finished yet": the scan
  polled to its limit, fetched the report each time and ended as a timeout with
  no reason. It is now a sandbox error naming the limit (partial); only
  "reported" results are cached (`api/intel.py`).

## 9. Progress

- Local commits after `6c42dc8` (none pushed): `63658a3`, `2a6f76c`, `5a9e3a5`,
  `7221c64`, `11144b8`, `64425f7`, `1e22a3f`, `672730e`, documentation
  (`1c7a1f7`, `442a346`), then the follow-up (section 8): `0305f29`, `78fb35a`,
  `5962225`, `46c788a`, `29f2206`, `8852880`, and its documentation.
- Last verified remote commit: `6c42dc8` (PR #49 head, 11 checks green).
- Next: owner review; on approval push the branch, update PR #49, watch CI on
  all platforms; then the VM procedure (section 3) and the PR-M1 decision.
