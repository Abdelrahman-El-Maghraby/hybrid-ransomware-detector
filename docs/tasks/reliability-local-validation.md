# Authorized reliability follow-up

Scope: completed external findings (I-6/M26), escaped helpers (L-E5), named
S-Y1/S-Y4 tradeoffs, retained sandbox submission policy, bounded guard checks,
local/platform verification and a local Graphify navigation map. No remote
publication, dependency changes, real samples, fuzz campaigns or artifact replay.

## Implementation and focused evidence

- Snapshots are assembled by the heavy-layer coordinator as futures complete,
  merging completed contexts in pipeline order. Mutable layer bookkeeping is
  private to each thread. Sequential mode publishes before each applicable
  external wait and clears stale snapshots before unrelated work. Completed
  scans publish a checked final checkpoint before log/final delivery.
- The parent checks snapshot file identity, retains the existing 16 MiB JSON
  limit/type validation, resets state on dispatch, and delivers once. Crashes,
  invalid replies and memory failures remain failures. A watchdog memory breach
  takes precedence over a simultaneous deadline. Transmission reports remain
  possible until completion supplies evidence; no cancellation of remote tasks
  is claimed. No new request threads, executors or connections were introduced.
- On supported macOS, bounded descendant discovery uses native process identities
  and ancestry, and audit-token signals bind delivery to the kernel PID version.
  Group enumeration is only a candidate list, checked by parent unique identity
  or original parent generation. This handles a helper exec after its worker
  exits and reparenting changes its current parent. At most 128 helpers are kept;
  discovery runs at most every 250 ms and on teardown. Missing facilities fail
  closed for descendant discovery; existing POSIX group/Windows Job paths remain.
- L-E5 is **not universal containment**: a session-detached descendant that
  reparents before observation, a changing exec generation at signal delivery,
  unavailable native APIs, discovery overflow and teardown-time new descendants
  can escape. Linux session escape and Windows Job behavior require platform
  validation/design; no privileges, global process sweep or name-based kill.

Native API definitions were checked against the installed SDK and Apple's
[libproc implementation](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c),
[identity structures](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h)
and [kernel signal checks](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c).

Before/after evidence uses a clean temporary export of `d8aec95`, with only the
new test fixtures copied in. External regression baseline: 9 failures, 2 passes
(51.33 s); new protocol/reset assertions necessarily fail on the old protocol.
Initial implementation: 28 passes, 2 sequential-mode failures; sequential mode
was corrected. Expanded focused selection: **123 passed, 216.25 s**. This
selection includes completed external results, stalled layers, repeated files,
protocol validation, final-delivery timeout, existing sandbox socket stand-ins,
helper cleanup and a bystander. Later macOS teardown refinement is verified
separately and will be included in the final safe run.

A loopback-denied run gave 90 passes, 19 failures and 2 errors; those socket
failures were environment restrictions, then rerun with local socket access.
The fast-exit helper refinement initially failed one existing regression; the
final implementation uses original parent generation for the exec/reparent race.
All test helpers are inert and bounded or explicitly cleaned by verified identity.

Focused commands (temporary HOME/TMPDIR, clean environment, bytecode disabled):

```sh
.venv/bin/python -m pytest -p no:cacheprovider -q --tb=short \
 tests/test_completed_external.py tests/test_slow_layer_deadline.py \
 tests/test_staged_pipeline.py tests/test_worker_reply_protocol.py \
 tests/test_sandbox_provisional.py tests/test_escaped_helpers.py tests/test_helper_cleanup.py
.venv/bin/python -m pytest -p no:cacheprovider -q \
 tests/test_admin_command_rules.py tests/test_yara_rules.py \
 tests/test_yara_rule_coverage.py tests/test_regression_corpus.py \
 tests/test_shadow_copy_rule_scripts.py tests/test_false_positive_fixes.py
.venv/bin/python -m pytest -p no:cacheprovider -q \
 tests/test_sandbox_budget_experiment.py tests/test_resource_bounds.py
```

Detection selection: **121 passed, 4.33 s**. Budget/resource guards: **9 passed,
1.37 s**. One attempted detection command named two nonexistent test files;
collection ran no tests; the corrected explicit selection above passed.

## Detection tradeoff (synthetic only)

No approved independent real-file corpus was available. These are generated
administration examples and inert technique fixtures, not malware effectiveness.

| Example | At 88b2db1 | After this pass | Interpretation |
|---|---|---|---|
| Service-only `net stop` (five server/backup targets) | Clean 0 | High 65 | Coverage restored |
| Service-only `sc stop` (same targets) | Clean 0 | High 65 | Coverage restored |
| Backup pre-freeze script | Clean 0 | High 65 | Known false positive restored with coverage |
| Lab Application log reset (S-Y1) | Medium 40 | Medium 40 | Intent unresolved; unchanged |
| Inert backup encryptor strings (S-Y4) | High 65 | High 65 | Intent unresolved; unchanged |
| Two Defender administration examples | Medium 40 each | Medium 40 each | S-Y2 fix retained |
| Two administrative shortcuts | Clean 0 each | Clean 0 each | S-Y3 fix retained |
| Original 11 technique fixtures | 2 Medium, 5 High, 4 Critical | Same scores/matches | Preserved |

At High or above, this expanded synthetic set changes from 1/7 to 2/7 harmless
examples flagged, and from 9/13 to 11/13 technique examples flagged. The two
remaining below High are log-clearing fixtures intentionally rated Medium; they
still match their rule. Both added service-only fixtures were missed at the
baseline. These fractions describe only this constructed set, not population
rates. M29/M32 and rule coverage/regression tests pass. No weights or global
thresholds changed. S-Y1 and encryptor ambiguity cannot be responsibly resolved
from identical strings; a separately approved labeled corpus is the next step.

## Sandbox budget experiment (policy unchanged)

`python -m tests.sandbox_budget_experiment` runs 144 deterministic fake-HTTP,
virtual-clock cases. Usable budgets: 5, 14.9, 15, 30 seconds; submission delays:
0.2, 4, 12 seconds; report-ready delay after submission: 0, 5, 20 seconds;
report-fetch delay: 0.2 or 4 seconds; status call: 0.1 seconds. Poll stays 15 s.
Each combination runs with the actual gate and a hypothetical gate bypass.
All calls honor their timeout. These are simulated elapsed seconds, not real
service performance measurements or wall-clock latency benchmarks.

| Usable budget | Current gate: reports / 18 | Hypothetical bypass: reports / 18 | Bypass accepted, then no report |
|---|---|---|---|
| 5 s | 0 (all refused before submission) | 2 | 10 (plus 6 submission timeouts, transmission possible) |
| 14.9 s | 0 (all refused before submission) | 5 | 13 |
| 15 s | 5 | 5 | 13 |
| 30 s | 11 | 11 | 7 |

Recommendation: retain 15 s pending measured CAPE submission/queue/report
latencies and an explicit owner decision about uploads without timely results.
The gate avoids futile uploads but misses some fast reports; 15 s is neither a
guarantee of a report nor a demonstrated optimum. No threshold or setting added.

## Restricted memory findings

27.5/B4 remains **failed/unresolved**, with three recorded campaign OOM exits
and no allocation attribution. The direct fuzz harness does not run application
workers; parser, native library and harness/corpus memory are not distinguished
by those logs. Range checks and small stand-ins do not resolve that root cause.
The existing eight resource-bound tests use small XAR/DOCX inputs, reduced caps
and read spies; watchdog, OS-limit and MemoryError routing tests use stand-ins.
No artifact was acquired/replayed, no campaign restarted, no memory spike
attempted, no VM started and no malware accessed.

Pending procedure, requiring separate explicit VM/artifact authorization:
use an already provisioned isolated disposable analysis VM with no shared host
folders, no internet and no service credentials; preserve a snapshot; identify
an approved artifact by digest without extracting on the host; run one artifact
in one disposable subprocess with OS-enforced 512 MiB memory, one CPU and 10 s
wall limit, recording target, process RSS and exit status. Stop after the first
limit/failure and retain safe metadata only. Do not raise limits or run a campaign
without another decision. A negative result at the smaller bound is inconclusive
about the historical 4096 MB failure; instrumentation/limit changes need approval.

## Final validation and platform status

Pending final safe selection, smoke, quality, GUI, packaging and Graphify evidence.
Prepared procedures and local stand-ins do not constitute platform/provider passes.
