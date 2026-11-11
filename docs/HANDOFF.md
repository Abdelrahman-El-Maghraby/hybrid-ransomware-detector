# Current task handoff

- Status: production-engineering review and staged fixes; not ready for merge and
  not production ready. Latest step: Claude's whole-repository review (findings
  and plan only, 2026-11-10 to 2026-11-11), PROJECT_REVIEW section 31.
- Active agent: Claude (2026-11-11). The owner confirmed the previous Codex
  session was stopped; no concurrent changes were seen during the reviews or the
  validation (HEAD and `git status` were compared before and after each group
  of checks). One editing agent.
- Branch: `review/production-hardening`, **local only**, cut from `3e5a3f2`
  (head of `validation/v4.8-remaining`, draft PR
  [#46](https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector/pull/46)).
  Owner instruction: commit locally; do not push, merge, tag, release or deploy
  without an explicit owner request.
- Brief: owner request for a production review; register and stage record in
  [PROJECT_REVIEW](PROJECT_REVIEW.md) section 28. Earlier context: sections 24,
  26, 27 and the [owner checklist](tasks/v4.8-owner-validation.md).
- PR #46 at start: local, origin and PR head all `3e5a3f2`; no differences.
  CI on `3e5a3f2`: tests 6/6, quality 4/4, Docker passed; Atheris skipped
  (docs-only). PR #39 and Dependabot PRs untouched.

## Authorisation boundary (unchanged, plus this task)

- Stages 1-3 of the section 28 plan: verified fixes with focused regression
  tests and full checks after each stage.
- Owner decision required before: H4 and M13 (they would change `scan_status`
  for affected files), M4 (API pre-auth body handling), H-04 (web-content
  regexes) and the low items. Explain affected cases and compatibility first.
- From section 27: no artifact replay, no memory-spike reproduction, no fuzz
  campaign restart, no memory-limit change, B4 stays failed/unresolved.
- No detection-weight, threshold, inspection-coverage or result-schema change.
  No malware, real samples, secrets or private data.

## Progress

- Stage 0 (audit): done; register in PROJECT_REVIEW 28.1.
- Stage 1 (H1, H2, M9, M10, M12): committed locally as `eb62c0b`; see 28.2.
  Full suite 1,256 passed / 13 skipped; ruff, mypy, bandit clean.
- Stage 2 (H3, M1, M2, M6, M11): committed locally as `3be37a2`; see 28.3.
  Full suite 1,270 passed / 13 skipped / 1 failed (new test hit I-T1; fixed
  and re-run in suite order).
- Stage 3 (M3, M5, M7, M8, M14, M15 docs, M16, GUI label, docs): committed
  locally as `3e2eed2`; see 28.4. Full suite 1,290 passed / 13 skipped.
- Stage 4 (owner-approved H4, M13 (a)+(b)): committed locally as `b1ce30f`;
  see 28.5. Full suite on that commit 1,309 passed / 13 skipped.
- Stage 5 (owner-approved H4-b): committed locally as the next commit after
  `b1ce30f`; see 28.6.
- Codex takeover (2026-11-09): the two interrupted Arena runs remain as
  untracked `.arena/` data; neither produced a completed review. No application
  files were changed during the takeover. A focused local check of the five
  production-hardening commits ran 157 tests across partial evidence, alerts,
  operations, worker logs, special files, mail, reports, GUI delivery and cloud:
  157 passed. Ruff passed on the application packages and CLI. One test emitted
  a Starlette TestClient deprecation warning; there were no test failures.
- Deferred by the owner (not started): M4, H-04, the low items, I-T1 and the
  M15 packaging change.

## Unresolved items carried forward

- Section 27.5 long-fuzz OOM failures (runs 40969502006, 40974246237): unresolved,
  restricted; do not execute the artifacts.
- Owner checks: Windows/macOS GUI, desktop monitoring, real SMTP/S3 providers.
- Production M1/X1, M2, O1, U1, X2, legal review, conditional D5, real-sample
  evaluation: pending and out of scope.

## Claude review session (2026-11-10): findings report only

- Scope: the five hardening commits (`eb62c0b`..`33fd895`) with callers and tests,
  worker IPC, output delivery, the LLM path, MCP (none in the repository) and CI
  runner coverage. Only `docs/PROJECT_REVIEW.md` (new section 29) and this file
  were edited. No application code, test, CI, dependency or configuration change.
- Safe test selection, run once at HEAD `c056e6f` (macOS 27.0.1 arm64,
  Python 3.14.2): `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p
  no:cacheprovider -q -rs -W default tests --ignore=tests/test_fuzz_parsers.py
  --deselect tests/test_workers.py::test_memory_limit_stops_runaway_allocation`
  gave 1,299 passed, 13 skipped, 1 deselected, 0 failed, 126 warnings, 272 s.
  Excluded: the Hypothesis fuzz file (it also writes `.hypothesis/` into the
  tree), the runaway-memory test (memory spike), `test_smoke.py` (real HOME).
  Not a full-suite pass. No repository artifacts (ignored/untracked status
  unchanged). ruff, mypy and bandit were not run (no code change).
- New findings (section 29): M17 (alerts lost when JSON Lines or the report
  cannot be written), M18 (pickle worker IPC: a compromised worker can run code
  in the API parent), M19 (a second `href` hides a deceptive link; needs
  approval), M20 (suspected, Windows device names as member names), L-E8, L-L1
  (needs approval), L-G1, L-A4, L-B6, I-T2. Hostile-input checks: in-memory
  synthetic strings only, each under a timeout.
- Platform table in 29.10: latest CI is on base `3e5a3f2` (tests 40977056829:
  ubuntu-24.04 x64, windows-2025 x64, macos-26-arm64), not on HEAD. Linux ARM64,
  Windows ARM64 and macOS Intel are unverified. The hardening commits have never
  run in CI.
- Reviewed in depth: see 29.15 for the parts not reviewed (other detectors,
  intel service beyond the LLM call, rule packs, quarantine, most GUI pages,
  build and Docker files, tools, fuzz harnesses). Not a complete project review.

## Claude validation session (2026-11-10): evidence only

- Scope: validate the section 29 review at `bfc58ff` and record evidence. Only
  `docs/PROJECT_REVIEW.md` (new section 30) and this file were edited. No
  application code, test, CI, configuration, dependency or lock-file change; no
  finding fixed; nothing pushed; `.arena/` untouched.
- Isolation for every local check (30.2): a clean environment, `HOME` and
  `TMPDIR` in a temporary folder outside the repository, a kernel sandbox that
  refuses writes outside that folder and all external network, and a wall-time
  and memory watchdog. Repository files, the real home folder and `/tmp` were
  unchanged afterwards. Host: macOS 27.2.1 arm64, Python 3.14.2. The installed
  packages differ from `requirements.lock` in six places (`pypdf` 6.21.3 instead
  of 6.21.2).
- Checks run and results (commands in 30.4 to 30.8):
  - pytest main selection (1,308 of 1,330 items) with a QR decoder present:
    1,300 passed, **1 failed**, 8 skipped, 4 deselected, 273 s.
  - The same selection without a QR decoder, as on the Linux and macOS CI jobs:
    1,296 passed, 0 failed, 13 skipped, 4 deselected, 269 s.
  - `test_smoke.py`: passed. `tests/test_fuzz_parsers.py::test_cpio`: passed.
  - ruff: clean on the 197 tracked Python files (plain `ruff check .` shows 447
    items, all inside the untracked `.arena/` folder). mypy: clean, 68 files.
    bandit CI gate: clean; 68 low results in shipped code, none material; the
    tests are reported separately in 30.5.
  - pip-audit (an extra): `requirements.lock` and `requirements-server.lock`
    **fail** with 7 advisories in `pypdf 6.21.2`; `requirements-build.lock` is
    clean.
  - Atheris harnesses: both import and every entry point returns on 69 and 62
    synthetic inputs of at most 1 KiB. Wiring only; no campaign was run.
  - A wheel builds from a clean export (M15 reproduced). The tag check of the
    release gate behaves correctly for four stand-in tags.
- Not run here, with the reason (30.3): 17 tests of `tests/test_fuzz_parsers.py`
  (their seeds feed the failed Atheris campaigns), the runaway-memory test (a
  deliberate spike above 1 GB), 3 intel socket tests (the fixture hardcodes
  `/tmp`), the GUI smoke test (needs a display), the coverage gate, the Docker
  check (no daemon), the desktop build, the release workflow, the Atheris
  campaigns and real-sample evaluation.
- New items (30.9):
  - **M21** (Medium, provisional): the pinned `pypdf 6.21.2` has seven published
    advisories (memory exhaustion, long run time and endless loops on crafted
    PDFs). The CI `dependency-audit` job passed on 2026-10-30 and fails today on
    the same lock files. Fix: `pypdf` 6.21.4 or later in both locks.
  - **L-B7** (Low, blocks CI): the M9 regression test
    `test_reports_with_non_ascii_names_are_utf8` in `tests/test_report_files.py`
    passes only without a QR decoder. It is expected to fail in the CI coverage
    job and on both Windows jobs.
- Finding validation (30.8). Reproduced from section 29: M17, M18, M19, L-E8,
  L-L1, L-G1, L-A4, L-B6, I-T2. Reproduced from section 28: M4, M15, H-04+,
  L-E2, L-C1, L-C2, L-C3, L-A1, L-D2, L-B3, L-B4, I-T1. L-E8 needs containers of
  mixed kinds (for example a ZIP of e-mails with attachments); a 100-member
  archive does not trigger it. M20 stays SUSPECTED (Windows only). 27.5 and B4
  are unchanged: the `pypdf` advisories are a lead for them, not a cause.
- Platform evidence (30.7): no workflow run exists for any commit after
  `3e5a3f2`. Every CI result is historical (tests 40977056829, quality
  40977056790, docker 40977056845, parser-fuzz 40977056762 with Atheris
  skipped). Linux ARM64, Windows ARM64 and macOS Intel have no runner.
- CI on HEAD needs the owner. A push alone starts no workflow. A pull request
  from this branch would also start the two one-hour Atheris campaigns, which
  27.5 forbids. The alternative is a push followed by a manual dispatch of
  `tests.yml`, `quality.yml` and `docker.yml` on this branch.

## Claude whole-repository review (2026-11-10 to 2026-11-11): findings and plan only

- Scope: a review of the repository at `eb1d96f` (last implementation commit
  `33fd895`) and an improvement plan. Only `docs/PROJECT_REVIEW.md` (new section
  31) and this file were edited. No application code, test, CI, dependency,
  lock-file, configuration or detection change; no finding fixed; nothing
  pushed, merged, tagged, released or deployed; `.arena/` untouched; no Arena
  run and no subagent.
- Baseline: section 30 (pytest, ruff, mypy, bandit and pip-audit at `bfc58ff`).
  `git diff 33fd895..eb1d96f` is documentation only, so no suite or tool was
  run again. This is not a full-suite pass and not a complete review.
- Completed coverage (31.2, read in full): the scan pipeline and the isolation
  workers; the archive, mail, script, web, embedded-content, PE, ELF, macro,
  integrity, YARA, fuzzy, QR, emulation and ML detectors; scoring and the
  indicator registry; `engine/external.py` and `engine/text.py`; the intel
  service and its clients; the REST API and its limits; containment, response,
  canaries and quarantine; rule packs and the allowlist; cloud upload, folder
  monitoring, outputs and the mailer; configuration, validation, capabilities
  and provenance; the CLI; packaging and deployment files; the fuzz harnesses;
  every workflow; and thirteen documents (README, threat model, deployment,
  operations, rule packs, releasing, release scope, architecture, readiness,
  handoff, workflow and the two instruction files).
- Remaining gaps (31.12, not read in this session): `engine/report.py`,
  `readiness.py`, `metrics.py`, `logs.py`, `fsutil.py`; `core/cache.py`,
  `core/mailbox.py`; `detectors/signals.py`, `tlsh_py.py`, `cfb_writer.py`,
  `llm_backends.py`; `api/probe.py` and the result schema; `scanner.spec`;
  `deploy/isolation_check.py`; `tools/` except `rulepack.py`; most GUI pages
  (the GUI was never run on a display); the rule content; the tests one by one;
  and `DATA_POLICY`, `SUPPORT`, `THIRD_PARTY`, `DATASET_PLAN`, `DETECTION_v3`,
  `DETECTION_v4`, `docs/tasks/*`. Read in part: `prompt_guard.py`,
  `relationship_scanner.py`, `secret_store.py`, `outbox.py`, `build.py`,
  `aegis_gui/app.py`, `RUNBOOKS`, `.env.example`, `CHANGELOG`.
- Checks run (31.4, twenty). All used `.venv/bin/python -B`, a clean
  environment, `HOME` and `TMPDIR` in a scratch folder outside the repository,
  synthetic inputs and a hard time limit per timing; none reached a product
  limit:
  1. timing of the two script patterns and of `ScriptAnalyzer.analyze_bytes`;
  2. an isolated `scan_one()` of a ZIP with and without a 109-byte script, 6 s
     limit;
  3. timing of seven more paths (mail, embedded content, script, charset);
  4. `PeAnalyzer` on `make_pe(overlay=...)` and `make_pe(cert=...)`;
  5. member and attachment names with a trailing dot;
  6. a OneNote marker file and the size of its result;
  7. a canary registry overwritten and deleted;
  8. an isolated scan against a stand-in sandbox on loopback, 8 s limit;
  9. `lock_folders` with a state path that cannot be written;
  10. a stand-in emulator's three failure results and `scan_status`;
  11. two rule files with the same stem;
  12. the layers' extension sets against `SUPPORTED_EXTENSIONS`;
  13. a signed pack with different key lists; the compose file parsed;
  14. two cloud spool objects on one folder;
  15. the error text of a failed webhook delivery;
  16. the number of compiled YARA rules;
  17. the outputs of an API scan through `TestClient` (this one made a DNS
      lookup for a reserved example name; nothing connected);
  18. setting names in the documents against the code;
  19. the e-mail cap with a stand-in SMTP server that refuses connections;
  20. the macOS autostart file with a stand-in for `launchctl`.
  Plus a read-only `git ls-remote --heads origin`. `git status` showed only the
  two documentation files and `.arena/` afterwards.
- New findings (31.3). High: **H5** (two script-layer regular expressions: a
  script of about 165 bytes holds a worker until the time limit), **H6** (a
  time-out or a dead worker replaces every finding of the file and its members
  with `Medium (failed scan)`, below the default alert floor; needs approval).
  Medium: **M22** (seven more quadratic paths), **M23** (a certificate-table
  entry hides a program appended to a program; needs approval), **M24** (a
  trailing dot in a name removes the executable and double-extension findings;
  needs approval; the Windows delivery step is suspected only), **M25** (a lost
  canary registry silences the tripwire; needs approval), **M26** (the default
  sandbox wait is longer than the scan limit), **M27** (the Docker services
  never receive `RULEPACK_PUBLIC_KEYS`, and removing the only key leaves its
  pack in use). Low and informational: L-A5, L-A6, L-A7, L-A8, L-C5, L-D4,
  L-D5 (needs approval), L-D6, L-D7, I-B1, I-B2. M20 gains a third place
  (attachment names). Two leads for 27.5 from reading only (31.6); 27.5 and B4
  stay unresolved and restricted.
- Documentation (31.7): 37 corrections, D1 to D37, none applied. Among them:
  25 YARA rules, not 23; the suite runs on pull requests and pushes to `main`,
  not on every push; `ARCHIVE_MAX_TOTAL_MB` is not a setting; the rule-pack
  commands for Docker; the memory and stop-grace defaults against the rules the
  documents give; JSON Lines, webhooks and quarantine in the Docker edition;
  Python 3.9 against owner decision D6; release examples still for 4.7.0.
- Platform (31.8): `eb1d96f` is not on the remote, so no workflow run exists
  for it. Linux x64 and Windows x64: historical runs on `3e5a3f2` only. macOS
  Apple Silicon: the local runs of section 30 and the checks of 31.4, on
  Python 3.14.2 and not the lock. Linux ARM64, Windows ARM64 and macOS Intel:
  unverified, no runner.

## Exact next action

Owner decisions first:

1. Fix M21 (lock update) and L-B7 (test only) before anything else? Both make CI
   fail whatever else is on the branch (unchanged from section 30).
2. H6: alerts for failed scans, partial evidence kept, or both?
3. M23, M24, M25, the M26 wait cap, the M27 empty-key rule and L-D5 change
   inspection behaviour, `scan_status` or a response action: approve, defer or
   reject each. Unchanged from before: M19 and L-L1 (29.14), the direction for
   M18, and the section 28 deferred items (M4, H-04, low items, I-T1, M15
   packaging).
4. Documentation questions D22, D23 and D26 (31.11): outputs and quarantine in
   the Docker edition; Python 3.9 in 4.8.
5. How to get CI on HEAD without restarting the Atheris campaigns (a push plus
   a manual dispatch of `tests.yml`, `quality.yml` and `docker.yml`, 30.7).

Then a separate fix session, each item with its regression test and the full
gates afterwards (pytest, ruff, mypy, bandit, pip-audit), in this order (31.10):

1. M21 and L-B7.
2. H5.
3. H6 (a), if approved.
4. M22, before any fuzz campaign is restarted.
5. The compose part of M27 and the start-up check of M26.
6. M17 and M18 (section 29), then H6 (b) if approved.
7. The approved items of decision 3.
8. The low items: L-D4, L-D6, L-D7, L-A5, L-A6, L-A7, L-A8, L-C5, I-B1, I-B2,
   with M20, L-E8, L-G1, L-A4 and I-T2 from section 29.
9. The documentation corrections D1 to D37, with L-B6.
10. CI on the branch, then the Windows, Docker and VM items of 30.11.

Commit state: section 31 and this handoff are meant to go into one local
documentation commit on top of `eb1d96f`; its ID is reported in chat and is
visible in `git log` (a commit cannot record its own ID). Until that commit
exists, both files are uncommitted changes. Pushed: nothing on this branch,
ever. The untracked `.arena/` folder is unrelated and preserved.
Still unverified: everything listed in 30.11 and 31.12, the release gate job
(tag only), the deploy scripts against real Docker, the Windows behaviour of the
outbox lock (`msvcrt.locking`) and of the UTF-8 report fix, the delivery step of
M24, the Docker part of M27, and every Windows, ARM64 and Intel statement in
29.10, 30.7 and 31.8.
