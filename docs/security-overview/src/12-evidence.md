# Evidence, limitations and next steps

## What the tests establish

At `e012d3f`, `pytest --collect-only` finds 2,190 tests in 141 files under `tests/`, plus
`test_smoke.py`. Grouped by what they exercise:

| Area | Tests | What a pass establishes | What it does not |
|---|---|---|---|
| Detectors and parsers | 742 | each detector's findings on synthetic, inert inputs (crafted headers, macros, archives, messages, pages) and its behaviour on damaged input | detection of real-world samples |
| Isolation, worker protocol, limits, partial evidence | 282 | time limits, fail-closed start, reply validation, kept evidence, provisional and stopped results, helper clean-up (largely with stand-in workers and virtual clocks) | Linux process groups and Windows Job Objects on real systems |
| Pipeline, scoring, status, provenance | 259 | layer order rules, scoring arithmetic, completeness rules, a small regression corpus of inert files, documented false-positive fixes | calibration of weights |
| Deployment, packaging, CI | 199 | Kubernetes manifests render and satisfy `check_manifests.py` (139 tests, including weakened copies that must fail); Docker settings; workflow files | anything on a running cluster or container |
| Configuration, secrets, rule packs | 160 | defaults, validation bounds, profiles, keyring handling, signed rule-pack verification | — |
| API, intel service and transports | 155 | token handling, lockout, body limits, upload deadline, intel operations, TLS client against a local TLS server, the 1 MiB reply cap | real VirusTotal, LLM, CAPE or SMTP |
| Alerts, outbox and outputs | 151 | queuing, retry, de-duplication, disabled versus failing channels, signed webhooks, cloud redaction (against local stand-ins) | real receivers and S3 providers |
| Protection, monitoring, mailbox | 122 | quarantine crypto round trips, key backup, canary logic, containment decisions (stand-ins), the monitor's queueing | suspending a real process; a real IMAP server |
| Linear-time pattern guards | 61 | every detector pattern finishes quickly on adversarial strings (ReDoS regression guard) | — |
| Tools, GUI integration, fuzz seeds | 59 | evaluation and calibration tools; headless GUI wiring; fuzz seed corpora | GUI on a display; fuzz campaigns |

## Latest verified revision and results

| Check | Where | Result |
|---|---|---|
| Safe test selection at `2672376` | macOS 27.2.1 arm64, Python 3.14.2, temporary HOME and TMPDIR, no outside network | **2,246 passed, 0 failed, 0 errors, 8 skipped, 4 deselected**, 589 s |
| Skips (platform) | same | Windows Restart Manager, real Job Object, `/proc`, a libproc-absent case, a system ELF binary, box-js, OpenCV, the opt-in GUI test |
| Deselected and excluded | same | the runaway-memory test (a deliberate allocation spike), three intel tests that hard-code `/tmp`, and `tests/test_fuzz_parsers.py` (its seeds feed restricted fuzz campaigns) |
| Ruff, mypy, bandit gate | at `2672376` | clean |
| Diagram build (layout checks) | this review, `e012d3f` | 11 diagrams, no label overflow, overlap or connector through a node |
| CI (Linux x64, Windows x64, macOS arm64; quality; Docker) | GitHub | passed on `3e5a3f2` only; **no workflow has run on the 175 commits since** |

## Platform and service gaps

All of the following are [[pending]] at this baseline: CI on any newer commit; Linux and
Windows runs of the current code; Linux arm64, Windows arm64, macOS Intel; Docker
(`check-deployment.sh`, isolation on real containers, backup and restore on real volumes);
any Kubernetes cluster (`verify-cluster.sh`, NetworkPolicy enforcement, `fsGroup` on real
storage, probes and shutdown timing, option E); real VirusTotal, LLM, CAPE, SMTP, webhook,
S3 and IMAP endpoints; Tesseract and poppler; the GUI on a display; desktop binaries and the
release workflow. The review host (8 GiB RAM, Docker installed but not running) was judged
too small for the representative cluster run.

## Real-sample evaluation

No detection rate, false-positive rate or calibration exists (M1/X1). Real samples are never
handled on the development host; evaluation is planned in an isolated VM under a separate
authorisation (`docs/DATASET_PLAN.md`: collection, splits, `tools/evaluate.py`). Until then,
treat every weight as an expert prior.

## Known false positives and documented ambiguities

Left unchanged on purpose, pending an owner policy decision or a benign corpus:

- **S-Y1**: a lab log reset (`Clear-EventLog -LogName Application`) scores Medium 40, the same
  as an anti-forensic script clearing every log; the command is the technique.
- **S-Y4 (encryptor strings)**: `Ransomware_Encryptor_Target_Extensions` matches a string set
  a backup tool could also hold.
- **S-Y4 (services)**: service-stop coverage (`net stop`, `sc stop`) scores High 65, which a
  backup pre-freeze script also triggers.

Proposals P1 to P3 with their trade-offs are in `docs/tasks/review-items-2026-11-17.md`.

## Open items by register ID

From `docs/FINDINGS_REGISTER.md` (the authoritative list; not reproduced in full):

| ID | State | Summary |
|---|---|---|
| 27.5 / B4 | confirmed, unresolved, restricted | long fuzz campaigns ended in out-of-memory failures; investigation only in the VM |
| L-E5 (residual) | known limit | a helper program that detaches before discovery can outlive its worker |
| I-6, M26 (residual) | known limit | client-side deadlines are best effort; intel requests may continue after a worker stops waiting |
| S-01 | suspicion, risk reduced | a crafted DMG and 7-Zip writing outside the extraction folder (members are now streamed) |
| S-03 | not reproduced | concurrent canary checks racing (now under a lock) |
| H-03, OOM-H | not measured | memory growth with nested containers; XAR and pypdf hypotheses |
| RV-S5 | not reproduced | outbox writes without `fsync` |
| Deferred | not started | outbox caps and permanent-error classes, the remaining I-1 file types, mail attachment ordering, automatic lock updates |
| Owner decisions | open | test-cluster choice and approval for `verify-cluster.sh`; publishing the branch and running CI; two historical commits with a trailer AGENTS.md disallows; S-Y policies; the B4 VM investigation; Python 3.9 support |

## Practical next steps for an incoming engineer

1. Read `AGENTS.md`, `docs/AI_WORKFLOW.md` and the end of `docs/HANDOFF.md`; the branch is local
   and approval-gated (no push, merge or deployment without the owner).
2. Read the code in the order of Appendix B; run `--capabilities` and the safe test selection
   in a temporary HOME to see the layer states on your machine.
3. Before claiming any platform behaviour, get CI running on this branch (the owner decides
   how) and read the per-job results.
4. For the server edition, run `deploy/check-deployment.sh` with Docker; for Kubernetes, run
   `verify-cluster.sh` on a disposable, labelled test cluster with an enforcing network plugin.
5. Do not change weights, thresholds, inspection coverage or the result schema without an
   explicit owner decision; record proposals instead.
