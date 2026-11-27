# Post-4.8.0 review and repair (2026-11-27)

Sanitised technical brief. Branch `review/remaining-issues-2026-11-27`, cut from
main at `da7d6c9` (the 4.8.0 release commit).

## Scope (owner-authorised)

Evidence-based review of remaining problems after 4.8.0, repair of confirmed
defects with regression tests, focused improvements, documentation drift.
Not authorised here: detection weights, thresholds, rule semantics or inspection
coverage (S-Y1/S-Y4 stay owner decisions); fuzz campaigns or OOM replays (27.5 /
B4, VM only); real samples; live external services; cluster deployment; merge,
tag or release.

## State established

| Item | Evidence |
|---|---|
| Released | v4.8.0 (stable, Latest) and v4.8.0-rc1 (pre-release), both tags on `da7d6c9`; 20 assets with `SHA256SUMS` and Sigstore bundles; release run 45630024216 green |
| main CI at `da7d6c9` | tests 45620268446, quality 45620268479, docker 45620268850: success; daily dependency-audit green |
| PRs #39, #47, #48 | merged (#39 still flagged draft, but merged) |
| PR #46 (draft, open) | its head is contained in main; superseded, owner may close it |
| Dependabot #23 to #27 | open; checks ran on old bases (`abfe429`, `fc91366`); #25's only failure was a timing flake (below) |
| Local only | `local/combined-preview`: merge commits of branches already in main, no unique changes |

## Findings in this pass

| ID | Class | Status |
|---|---|---|
| PR-R1 | `test_the_upload_wait_ends_before_the_scan_limit` asserted 1.6 s wall clock for a 1.5 s budget; failed once on macOS CI (1.63 s, PR #25). Verification flake, not a product defect | fixed `0c47a31`: asserts the wait ends before the scan limit; the poll count still shows the margin |
| PR-D1 | FINDINGS_REGISTER, VERIFICATION_MATRIX, PROJECT_MAP and RELEASING still said no CI ran after `3e5a3f2` | fixed `0c47a31` |
| PR-W1 | Worker reply with mistyped `scan_failed` / `layer_errors` / `scan_duration_ms` crashed the parent's metrics and lost the batch | fixed `fd29e39` |
| PR-W2 | Stale provisional snapshot after the last parallel slow layer answered | fixed `d92403c` |
| PR-A1 | API stored uploads as `upload<ext>`: M30 name check never ran through the API | fixed `39dc503` |
| PR-C1 | Canaries in a linked folder were scanned; redeploy warned about its own files | fixed `208e14d` |
| PR-S1 | One CAPE status-check error ended the wait; intel forgot the task | fixed `5904898` |
| PR-M1 | Memory limit is per worker process; helpers not counted on macOS, each helper has its own limit elsewhere | open: documented in THREAT_MODEL; owner decision and VM measurement |
| PR-S2, PR-Q1, PR-F1 | CAPE report size unbounded; restore check-then-replace race; monitor stop forgets a running thread | suspected, not reproduced |

Every fix has a regression test that failed on the code before it. Local
evidence: VERIFICATION_MATRIX section 18.

## 27.5 / B4 and the runaway-allocation test (status 2026-11-27)

Neither was changed in this pass, and neither is marked resolved.

- **27.5 / B4** (campaign OOMs): no code was investigated or changed beyond
  reading the harness/product comparison (review-items brief, section 3). The
  Atheris campaigns stay manual-dispatch only; no artifact was fetched or
  replayed. `tests/test_fuzz_parsers.py` is a separate, bounded Hypothesis suite
  (40 derandomised examples per parser, synthetic inputs): it is not run on this
  host because its seeds are shared with the campaigns, and it passed in every CI
  job at `da7d6c9`. That says nothing about the campaign OOMs.
- **`test_memory_limit_stops_runaway_allocation`**: not run here (a deliberate
  allocation past 1 GB on an 8 GB host); passed in CI at `da7d6c9` on Ubuntu,
  Windows and macOS, Python 3.9 and 3.12. That verifies the worker-process limit
  on each OS (RLIMIT_AS, Job Object, watchdog) with a stand-in allocation; it does
  not cover helper processes (PR-M1) or real parser inputs.

### Isolated-VM validation still required (separate authorisation)

1. The bounded plan of review-items brief section 3, steps 0 to 5 (classify the
   three artifacts by target without parsing; single input under 512 MiB with
   tracemalloc; accumulation over the seed corpus; the product path through
   `scan_isolated()` with `WORKER_MEMORY_MB=512`, expected `scan_failed` with a
   memory reason and a healthy parent; keep metadata only).
2. PR-M1: on macOS and Linux VMs, an inert helper stand-in that allocates past the
   worker limit, started from a worker; record whether the scan fails, the peak
   memory of worker plus helpers, and that the parent stays healthy.
3. The long Hypothesis run (`FUZZ_RANDOM=1 FUZZ_EXAMPLES=5000`) in the VM.

B4 can be closed only when that plan attributes each OOM to H1, H2 or H3 and its step 4
shows the product contains it (or a fix is made and the same replay passes).
