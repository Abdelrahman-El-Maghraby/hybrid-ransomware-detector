# Current task handoff

- Status: **optional Kubernetes deployment implemented and statically validated;
  paused for owner decisions** (2026-11-18). Runtime validation on a cluster is
  pending. Not ready for merge and not production ready. Latest: section
  "Optional Kubernetes deployment (2026-11-18)" at the end; the thirteen-item
  review (2026-11-17) before it is complete.
  Start here: [PROJECT_MAP](PROJECT_MAP.md) (what the project is, what changed, how
  to resume), [FINDINGS_REGISTER](FINDINGS_REGISTER.md) (the current status of
  every finding) and [architecture/README](architecture/README.md) (how the scanner
  is built: six diagrams, also stated in text). Current checks per platform:
  [VERIFICATION_MATRIX](VERIFICATION_MATRIX.md). The sections below are the
  history of the work, in order; older "still open" lists in them are superseded by
  the register.
- Active agent: Claude Code (2026-11-17), the only editor. Earlier (2026-11-14): Codex reached its usage limit at the
  Graphify step and is stopped. Historical context: The owner confirmed the previous Codex
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
- Deferred by the owner (not started): M4 and the M15 packaging change.
  H-04+ and I-T1 were approved and done in group 34.

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

## Claude review of the remaining components (2026-11-11): findings only

- Scope: the components 31.12 listed as unread or partly read, from commit
  `6cde91e`. Only `docs/PROJECT_REVIEW.md` (new section 32) and this file were
  edited. No code, test, CI, dependency or detection change; nothing pushed;
  `.arena/` untouched; no Arena run, no subagent, no suite rerun (baseline:
  section 30).
- Reviewed (32.1): `engine/report.py`, `readiness.py`, `metrics.py`, `logs.py`,
  `fsutil.py`; `core/cache.py`, `core/mailbox.py`; `detectors/tlsh_py.py`,
  `cfb_writer.py`, `signals.py` (helpers); `api/probe.py` and the result schema;
  `scanner.spec`, `build.py`; `deploy/isolation_check.py`; every tool in
  `tools/`; the GUI state, actions and the database, logs, monitoring, outputs,
  protection, reports and scan pages; the rule names, severities and
  conditions; `DATA_POLICY`, `SUPPORT`, and in part `THIRD_PARTY` and
  `DATASET_PLAN`. `llm_backends.py` was not repeated (29.7).
- Still not reviewed in detail (32.8): GUI layout files (`pages/dashboard.py`,
  `widgets.py`, `common.py`, the start of `app.py`); the hidden-content and
  relationship inspectors and the bodies of `secret_store.py` and the first 119
  lines of `outbox.py` beyond their 28/29 diffs; the YARA string lists; the
  dated design notes (`DETECTION_v3/v4`) and task briefs; the tests one by one.
- Check run: check 21 only (a two-line admin `.ps1` and an `.html` page that
  quotes the command, scanned in-process under a scratch `HOME`). Everything
  else in section 32 is from reading the code at the lines given.
- New findings (32.2): **M28** (the GUI's scan folders and file types are not
  used by the background service it installs at login; no setting exists),
  **M29** (the `critical` shadow-copy YARA rule scores a benign listing script
  and a page quoting the command `Critical` 90; needs approval), and low or
  informational L-E9, L-E10, L-C6, L-C7 (needs approval), L-C8, L-C9, L-C10,
  L-C11, I-B3, I-B4. Additions to L-E7, L-C1, I-1 and L-A7 (32.4). Five more
  documentation corrections, D38 to D42 (32.5).

## Claude review of the components section 32 left (2026-11-11): findings only

- Scope: the components 32.8 listed, from commit `7e449cb`. Only
  `docs/PROJECT_REVIEW.md` (new section 33) and this file were edited.
  - No code, test, CI, dependency or detection change, and nothing pushed.
  - `.arena/` untouched. No Arena run, no subagent, no suite rerun; the
    baseline is section 30.
- Coverage (33.5):
  - Reviewed in full: the GUI layout and start-up, the `prompt_guard`
    inspectors, `relationship_scanner.py`, the body of `secret_store.py`, the
    first 119 lines of `outbox.py`, and all 25 YARA rules with their strings.
  - Reviewed as dated notes or briefs: `DETECTION_v3`/`v4`, `docs/tasks/*`.
  - Tests: every one of the 95 files under `tests/` and `test_smoke.py` was
    checked for structure and assertions (941 tests); only some parts were read
    line by line. This item is partly reviewed.
  - Not opened: the binary RAR fixtures.
  - So this is not a complete line-by-line audit.
- Checks run (all synthetic, in-process, under a scratch `HOME`):
  - check 22: a top-level file name with U+202E
  - check 23: a docx with one malformed relationship part
  - check 24: a short ransomware advisory page
- New findings (33.1 to 33.4):
  - **M30.** A right-to-left override in a top-level name is not a finding:
    Clean 0, while the same name inside a ZIP is Critical 95. Needs approval.
  - **M31.** One malformed `.rels` part drops the earlier relationship findings,
    so a remote-template docx turns from High 70 into Clean, partial. Needs
    approval.
  - **M32.** A short ransomware advisory scores High 73 from the ransom-note
    rules. Needs approval.
  - Low or informational: L-D8 (needs approval), L-E11, I-B5, L-T1, I-T3.
  - Suspicions S-Y1 to S-Y4 (YARA admin-command rules) and S-T1 (sleep-based
    tests).
  - Additions to L-E9, L-C6 and L-B3.
- `PROJECT_REVIEW.md` carried a raw U+202E from the batch A checkpoint. It
  was replaced with a placeholder in `632ef11`. Scan added lines for bidirectional
  characters before every commit.

## Implementation of the SAFE items (Claude, 2026-11-11)

- Owner request: fix the confirmed SAFE items of 33.6 in small groups, each with
  its cause verified, a focused regression test, the smallest complete fix and
  the relevant checks. Local only: no push, PR, merge, tag, release, deploy or
  version change. No real malware, heavy fuzzing or memory-spike tests. OWNER
  items stay untouched until the owner decides.
- Test environment for every run below: `.venv` (Python 3.14.2, macOS arm64),
  `HOME` and `TMPDIR` in a scratch folder outside the repository, `env -i` with
  `PATH=/usr/bin:/bin` (so Homebrew tools such as 7-Zip are not found). "Safe
  selection" means the section 30 command: `tests` minus
  `tests/test_fuzz_parsers.py`, the runaway-memory test and the three intel
  socket tests that hardcode `/tmp`.

### Group 1: M21 and L-B7 (CI blockers)

- **L-B7.** Cause confirmed: the text report lists only flagged or not-complete
  files, and the PDF in the M9 test is partial only because the QR layer says
  "needs zbar". With the decoder simulated as present (`QR_AVAILABLE = True`)
  the scan is complete and Clean, so the name is missing from the report. Fix
  (test only): the shared fixture in `tests/test_report_files.py` pins
  `qr_scanner.QR_AVAILABLE = False`, as `tests/test_qr.py` already does.
  Before the fix, with the decoder forced present: 1 failed, 1 passed. After:
  2 passed in both states.
- **M21.** `pypdf` 6.21.2 to **6.21.4** in `requirements.lock` and
  `requirements-server.lock` (the newest 6.x; `uv` would otherwise have picked
  7.0.1, a major version, which was not taken). Regenerated with the documented
  `uv pip compile` commands plus `--upgrade-package pypdf` and a temporary
  `pypdf==6.21.4` constraint. Only the `pypdf` entry changed in each lock; the
  headers are kept; both hashes equal PyPI's published SHA-256. `.venv` updated
  from 6.21.3 to 6.21.4 with `--require-hashes` from the lock entry.
- Checks: `pip-audit --require-hashes --disable-pip -r <lock>` reports no known
  vulnerabilities for all three locks (it failed with 7 advisories before).
  Safe selection: 1,281 passed, 28 skipped, 4 deselected, 0 failed, 264 s
  (the H5 edit of group 2 was made while this run was in progress, so it
  counts as evidence for group 1 only). ruff (tracked files), mypy (68 files)
  and the bandit CI gate: clean.
- Not verified: CI (nothing pushed); the advisories' crafted PDFs were not
  replayed (excluded on this host).

### Group 2: H5, M22 and I-5 (the time-out class)

- Rule kept throughout: every new form gives the same matches as the old
  pattern. The old patterns stay in the tests as the reference and are compared
  on 30,000 random inputs each, with a minimum number of real matches so the
  comparison cannot pass empty.
- **H5** (`detectors/script_analysis.py`): `_CHR_RUN`, `_PSCHAR_RUN` and
  `_PSCHAR_ONE` give each white-space run one owner. The review's proposed
  `_\s*\r?\n\s*` still split blank lines two ways; `_[^\S\n]*\n\s*` matches
  the same strings and splits at the first newline.
- **M22**, all seven paths of check 3:
  - `_PASSWORD_RX`: `(?:\s*[:=...])?\s*` in place of `\s*[:=...]?\s*`. The
    subject is not capped; the pattern is linear without it.
  - `From:` display name: `_first_domain()` (the H2 helper) in place of
    `_DOMAIN_IN_TEXT.search`.
  - Mail body charset: `punycode` is read as UTF-8. Every other charset is
    unchanged (see M33 below for the ones that still fail).
  - Embedded-block type guess (`detectors/embedded_content.py`): the `.bat`
    pattern is line-local; `.wsf` and `.js` use two small helpers with the
    same yes/no answer. Only a boolean was ever used.
  - Script Encoder blocks: a start marker is paired with the first end marker
    after it; the search stops when no end is left.
  - `_REVERSE_JS` and `_REPLACE_DOT`: a memoised string-literal scanner
    (`_Literals`, `_literal_matches`). A literal opening at an escaped quote
    inside a longer one continues exactly as the longer one, so each run is
    scanned once. Plain characters are skipped by a C-level pattern: 1 MB of
    ordinary JavaScript takes 0.10 s (old regex 0.08 s).
- **I-5** (`tests/test_regex_guard.py`): every module-level compiled pattern
  in `detectors/` (114) runs `finditer` on ~20 KB hostile inputs in a child
  process. The inputs are runs of one character, tokens from the pattern's own
  text, and the H5 shape. Limits: 0.5 s per call, 240 s in all; 3.7 s here.
  The slowest call that is checked is about 0.006 s. Shown to catch the old
  `_PSCHAR_RUN`, `_CHR_RUN`, `_PASSWORD_RX`, `.bat` guess and `_REVERSE_JS`
  when they are put back. It does not catch the old Script Encoder pattern
  (0.25 s at 20 KB); that one has its own test. Inline `re.*` calls are not
  covered. Skipped by name, with the reason in the file:
  - helpers that run only anchored at positions their caller bounds:
    `_JS_FUNCTION_TAIL`, `_DOMAIN_CHAIN`, `_DOMAIN_IN_TEXT`, `_TAG`, and the
    three `_literal_matches` suffix patterns;
  - three web-content patterns that are quadratic on `<a` runs: H-04+,
    deferred by the owner (`_DATA_DOWNLOAD_ANCHOR`, `_SMUGGLE_DOWNLOAD`,
    `_SVG_ACTIVE[1][1]`);
  - `file_integrity.RANSOM_NOTE_RE`: L-E12 below.
- Tests: `tests/test_script_patterns_linear.py`,
  `tests/test_mail_embedded_linear.py`, `tests/test_regex_guard.py`. Every
  timing test was run against the unfixed detectors in a temporary worktree:
  each group was still running at a 30 s cap (exit 124). After the fix they
  take 0.1 to 1.5 s each.
- Gates at commit time: ruff (tracked files), mypy (68 files), bandit CI
  gate and `test_smoke.py` clean; the three new test files pass. The full safe
  selection is run in a clean worktree at this commit afterwards (edits for
  the next group were being made in the main tree); its result is in the next
  checkpoint.
- Review (Ponytail Review of the diff): one finding, the speed of the
  pure-Python literal scanner on ordinary scripts. Fixed with the C-level skip.
- New items found during this group (not fixed, recorded here for the owner):
  - **M33** (Medium, needs approval, same rule as M31): a mail part that
    declares `charset=idna` or `charset=undefined` makes `bytes.decode` raise
    `UnicodeError` even with `errors="replace"`. The whole mail analysis then
    ends in an error: a planted `Password: ...` and everything after it are
    not found. Reproduced in-process with a three-line `.eml`. Proposed fix:
    read these two (and any codec that raises) as UTF-8, as for `punycode`.
  - **L-E12** (Low): `RANSOM_NOTE_RE` is quadratic on a long name (80 KB of
    `decrypt`: 2.2 s). It sees only file names; a ZIP member name can be
    64 KB, about 1.5 s per member. A detection pattern, so not changed here.

### Group 3: M17 (M18 waits for the owner)

- **M18 not started.** 33.6 marks it SAFE, but 33.7 lists "M18's direction"
  as an owner decision. 29.11 gives three directions: JSON bytes with a shape
  check, a restricted unpickler, or a corrected THREAT_MODEL residual.
- **M17.** Cause confirmed by tests that fail before the fix (5 failed):
  - `deliver()` wrote JSON Lines before it queued the alerts, and did not
    catch the error.
  - `run_scan`, `--scan-file` and the folder monitor wrote the report
    before they called `deliver()`.
- Fix:
  - `deliver()` logs a JSON Lines failure (`event=jsonl_error`) and still
    queues the alerts.
  - `run_scan` and `--scan-file` call `deliver()` in a `finally`. The report
    error still propagates, and `--scan-file` still exits 3 when isolation
    is unavailable.
  - The folder monitor writes the report and delivers in separate `try`
    blocks.
  - IMAP already delivered before the report; the GUI was fixed by H3.
  - `--scan-now` is unchanged: a report error still ends it, after the
    alerts.
- Test: `tests/test_output_failures.py` (5 tests; the JSON Lines case uses
  the real outbox with the receiver down). 5 failed before the fix, 5 pass
  after. 136 tests across the delivery, alert, folder-monitor, isolation,
  operations and partial-evidence files pass. ruff, mypy and bandit clean.
  The full safe selection is in "Group 4" below.

### Full-suite evidence for groups 2 and 3

- Group 2 (`c09f904`), safe selection in a clean worktree at that commit:
  1,321 passed, 28 skipped, 4 deselected, 0 failed, 290 s.
- Two earlier runs saw files change mid-run and count only as smoke checks:
  1,320 and 1,321 passed, 0 failed.
- Group 3 (`e334704`) is covered by the group 4 run below. The group 4 commit
  contains it.

### Group 4: M20, L-E9 and I-T3 (file names)

- **M20.** `not_a_device()` in `detectors/container_extractor.py` puts "_"
  before a sandbox file name that is a Windows device name. That means CON,
  PRN, AUX, NUL, COM0-9 and LPT0-9 (also with superscript 1-3), in any case,
  followed by an extension, a space or nothing.
  - Applied where archive members, embedded blocks and mail attachments are
    written to the sandbox.
  - Only the file name on disk changes; the names shown in results are
    unchanged.
  - Test: `tests/test_device_names.py` (17 tests). The device behaviour
    itself is still PLATFORM (Windows) and was not run.
- **L-E9.** `engine/logs.py` gains `printable()` and `TextFormatter`.
  - `printable()` shows control characters as "?", U+202E as "[RTLO]", and
    the other bidi and line-separator characters as "[U+XXXX]".
  - `TextFormatter` is used by the text log and the GUI log view: one record
    is one line, and a traceback stays on its own lines.
  - The text report shows every path through `printable()`: file lines,
    gaps, allowlist, canary paths and impact lists. So does the GUI result
    table.
  - JSON logs, the JSON report and `visible_name` are unchanged.
  - Test: `tests/test_printable_names.py`. The GUI table change was not run
    on a display; the module imports.
  - The M9 test (`tests/test_report_files.py`) pinned the raw override in
    the text report (listed in 33.4). It now checks the shown form in text
    and the exact name in JSON.
- **I-T3.** The six raw bidi characters in `tests/test_alerts.py`,
  `tests/test_mail_analyzer.py`, `tests/test_rar.py` and
  `tests/test_report_files.py` are now `\u` escapes. A test fails when any
  tracked text file holds one.
- Full evidence for groups 3 and 4: the safe selection in a clean worktree at
  the group 4 commit `f623adb` gave 1,348 passed, 28 skipped, 4 deselected,
  0 failed, 284 s; `test_smoke.py` passed there too.
- New tests fail on the code before the fix (worktree at `e334704`, with a
  pass-through `printable`): 4 of 4. After the fix: 155 tests across the
  touched files pass. ruff, mypy and bandit clean.

### Group 5: M33 (owner-approved, 2026-11-11)

- The owner approved the proposed fix: a mail part that declares
  `charset=idna` or `charset=undefined` is read as UTF-8.
- Cause confirmed: of all codecs in the standard library, only `idna` and
  `undefined` raise `UnicodeError` from `bytes.decode(..., errors="replace")`
  (checked by decoding test bytes with every codec). `_decode_text` caught
  only `LookupError`, so the error ended the whole analysis.
- Fix: `_decode_text` in `detectors/mail_analyzer.py` also catches
  `UnicodeError` and decodes as UTF-8. Every other charset takes the same path
  as before. Encoded-word headers (`=?idna?Q?..?=`) already did not raise,
  checked in-process.
- Test: `tests/test_mail_charset.py` (13 tests). The body, the planted
  password and an empty `error` with `idna`, `undefined` and `IDNA`; the UTF-8
  fallback; six valid charsets (utf-8, latin-1, cp1252, shift_jis, utf-16,
  koi8-r) give the same text as a direct decode; unknown and `punycode` still
  read as UTF-8. Before the fix: 5 failed, 8 passed. After: 13 passed; with the
  other mail test files, 73 passed. ruff and mypy clean.

### Group 6: L-C6 (rank 7)

- Cause confirmed: `_llm_posture_label` (`engine/report.py`) and
  `_llm_card_state` (`aegis_gui/pages/dashboard.py`) tested the class name for
  "Ollama" or "OpenAI". With `AEGIS_INTEL_SOCKET` the backend is
  `IntelLLMBackend`, so both said disabled even when intel sends text to a
  cloud LLM.
- Fix: both now use the backend's `available`, `is_local` and `model` (or
  `name`). One visible text change: a direct OpenAI backend now reads
  `CLOUD (<model> - documents leave the machine)` instead of
  `CLOUD (OpenAI - ...)`, the same form as the LOCAL line. Nothing pinned the
  old text.
- The 33.1 addition: the VirusTotal card said "Connected" whenever a key was
  set, with no request made; it now says "Key set".
- Test: `tests/test_llm_posture.py` (15 tests). The report line and the card
  for an intel stand-in (cloud, local, disabled, unreachable), direct Ollama,
  direct OpenAI, the null backend and no backend. The card tests import the
  GUI module and skip without Tkinter; the report tests do not. Before the
  fix: 6 failed (4 intel cases, plus the changed OpenAI text), 9 passed.
  After: 15 passed. ruff and mypy clean; the dashboard module imports. The
  cards were not shown on a display.
- Not changed (observation): with intel, the VirusTotal key lives in the
  intel service, so the card still says "Key missing" there. Showing intel's
  VirusTotal state would need a capability call from the GUI thread.

### Group 7: M28 (rank 7) and D38

- Cause confirmed: in a new process with `SCAN_DIRECTORIES=/x/Documents
  FILE_EXTENSIONS=.pdf SCAN_INTERVAL_HOURS=3`, the old `engine/config.py`
  built the home Downloads folder, 43 default types and 6 hours. Nothing read these
  names, and the GUI kept its choices only in `gui_settings.json`, so the
  background service the GUI installs at login scanned other folders.
- Fix:
  - `engine/config.py` reads `SCAN_DIRECTORIES` (";", also ":" outside
    Windows, `~` expanded, as for `WATCH_DIRS`), `FILE_EXTENSIONS` (commas,
    lower-cased) and `SCAN_INTERVAL_HOURS`. Unset gives the old defaults;
    set but empty gives an empty list.
  - `engine/validation.py` names `SCAN_INTERVAL_HOURS` in its range error and
    `FILE_EXTENSIONS` in the format error. It warns for a scan folder that
    does not exist, except with the intel socket (Docker has no folder
    scans).
  - GUI: `aegis_gui/integration.save_scan_settings` writes the three values
    to `.env` through the existing validated `apply_settings`. The Scan page
    (folders, types) and the Settings page (interval) call it on each
    change.
  - When the GUI starts, a value set in the environment or `.env` wins over
    `gui_settings.json`. A GUI choice that `.env` lacks (an install from
    before the fix) is written to `.env` once.
  - A folder name containing a list separator is refused with an error,
    since it could not be read back.
- Docs (D38): README configuration table and "Scan directories..."
  paragraph, and `.env.example`.
- Limits, documented or recorded here:
  - A running background service reads `.env` at start only.
  - A value set in the process environment wins over `.env`, so a GUI change
    is overridden there at the next start.
- Test: `tests/test_scan_settings_shared.py` (8 tests):
  - a fresh process reads the three settings;
  - empty means no folders, and a bad interval is reported;
  - list parsing;
  - validation messages, including the missing-folder warning and its Docker
    exception;
  - the values the GUI writes to a real `.env` (python-dotenv `set_key`) give
    the same CONFIG in a fresh process;
  - the separator refusal;
  - the store's precedence and the one-time save flag.
  On the old code the module fails at import (the helpers do not exist), and
  the in-process probe above shows the behaviour. After: 8 passed; with the
  GUI integration, config, scanner, cloud, folder monitor, secret store and
  L-C6 tests, 136 passed; the docs test files 29 passed. A UNC path and a
  quote survive the `.env` round trip (checked in-process). ruff, mypy and the
  bandit gate are clean. The GUI was not run on a display; its modules import.

### Full-suite evidence for groups 5 to 7

- Safe selection in a clean worktree at `8e240a7` (M28), with
  `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` so the QR decoder loads
  (section 30 run A; the earlier groups ran without it, hence 23 skips here
  against 28): 1,388 passed, 23 skipped, 4 deselected, **1 failed**, 276 s.
  `test_smoke.py` passed.
- The failure was `test_public_docs_name_no_local_download_paths`: the group
  7 handoff entry quoted the default Downloads path literally, which that
  test forbids in `docs/*.md`. Reworded in the next docs commit; the test
  then passed on its own. No code changed after the run.

### Full-suite rerun at `2803b56` (owner request, 2026-11-11)

- Safe selection in a clean worktree, with the QR decoder (as for groups 5
  to 7): **1,389 passed, 0 failed, 23 skipped, 4 deselected**, 276 s.
  `test_smoke.py` passed. Nothing needed fixing.

### Group 8: L-T1 and L-B3 (rank 9, test isolation)

- **L-T1.** Cause confirmed by the new test: a child pytest session started
  with `VIRUSTOTAL_API_KEY=dummy-vt` saw it in CONFIG ("AssertionError:
  virustotal_api_key"). `tests/conftest.py` used `setdefault` for two names
  and left the rest alone.
  - Fix: it now removes every secret's `NAME_FILE` form. It sets every secret
    of `engine/secret_store.SECRETS`, the two service tokens and the service
    endpoints (`OLLAMA_HOST`, `SANDBOX_URL`, `WEBHOOK_URL`, `SMTP_HOST`,
    `IMAP_HOST`, `CLOUD_ENDPOINT`, the two sockets) to empty, which also
    hides a repository `.env`. `LLM_PROVIDER` is now assigned `none`.
  - Test: `tests/test_env_isolation.py` (3 tests): the child session with
    eight exported settings and two `_FILE` forms sees none of them; the
    conftest list covers `SECRET_NAMES`. Before: 1 failed. After: 3 passed;
    with the secret store, API, intel, config, capabilities, containment,
    alerts, readiness and deployment tests, 197 passed, 1 skipped.
- **L-B3.** `test_smoke.py` runs outside pytest; before the fix its app
  folder was under the real home (checked in-process: True). It now imports
  `tests/conftest.py` first, which only sets the environment, and asserts
  that `APP_DIR` is outside the real home. Run with the real `HOME`: "ALL
  SMOKE TESTS PASSED".

### Group 9: I-T2 and S-T1 (rank 9)

- **I-T2.** Cause: `core/cache.py:54` is the only SQLite connection, and test
  scanners never close their result cache. `tests/test_scanner_integration.py`
  with `-W default::ResourceWarning` gave "18 passed, 15 warnings" (all
  "unclosed database"). Fix: an autouse fixture in `tests/conftest.py` closes
  every `ResultCache` a test opened at teardown; caches of module or session
  fixtures are opened before it and left alone. After: "18 passed", no
  warning. The full-run count is in the next evidence entry.
- **S-T1.** Most sleeps in the three files check that nothing more happens (a
  quiet period), which a poll cannot replace and which does not fail on a slow
  runner; they stay. The two sleeps that gated a positive assertion now poll
  with a deadline (`tests/helpers.wait_for`):
  - `test_bursts_are_coalesced_and_errors_do_not_escape` (canary debounce);
  - `test_lockout_expires` (the lockout check does not extend the lock,
    `api/limits.py`).
  Three consecutive runs of both files: 19 passed each.
  `test_mail_html_linear.py`'s 15 s bound is a time limit, not a gate: kept.

### Group 10: the 33.4 missing rule tests (rank 9)

- 33.4 listed 14 public YARA rules that no test named; a fresh check found the
  same 14. `tests/test_yara_rule_coverage.py` (29 tests): for each rule, an
  inert synthetic input with every part of its condition matches, and a near
  miss without one part does not. A further test fails when a rule in
  `rules/` is named by no test. Reserved `.invalid` domains only; no sample
  or executable content. 29 passed (yara-python present, nothing skipped).
- The rules are unchanged. The other missing tests in 33.4 are left for the
  owner, because they would pin or change owner items:
  - benign documents for M29, M32 and S-Y1 to S-Y3;
  - M30 (top-level right-to-left override names);
  - M31 (a good relationship part plus a bad one);
  - L-D8 (the silent cell and page limits).
- I-T1 stays deferred by the owner (section 28).

### Group 11: rank 6, SAFE parts (M26 start-up check, M27 compose part)

- **M26.** `engine/validation._sandbox_wait`: with a sandbox URL and isolated
  scans, `SANDBOX_WAIT_SECONDS` not below `SCAN_TIMEOUT_SECONDS` is a warning,
  and an error in the production profile. The compose file passes both
  settings to `intel`, which holds the sandbox, with the same defaults (600,
  300). So intel's own start-up check compares the real pair: with a sandbox
  configured and the defaults, it warns.
  - Not changed (owner): the wait cap and the per-layer deadline (I-6).
- **M27 compose part.** `RULEPACK_PUBLIC_KEYS: ${RULEPACK_PUBLIC_KEYS:-}` for
  `analysis` and `content`. `test_secrets_come_from_files_not_the_environment`
  treated every name with "KEY" as a secret; it now skips this one name (public
  keys, no `_FILE` form in config).
  - Not changed (owner): the empty-key rule.
- Docs: `docs/DEPLOYMENT.md` names `SANDBOX_WAIT_SECONDS` and its limit, and
  `RULEPACK_PUBLIC_KEYS` for Docker. The rule-pack example and the compose
  comment use a `.tar.gz` with its `.sig` (D27; the signature is
  `<pack>.sig`, `core/rulepack.py:168`).
- Test: `tests/test_deploy_settings.py` (8 tests): the warning, the
  production error, three cases without a report, intel's settings in
  compose, and the keys for both services. Before the fix: 5 failed (the
  three no-report cases passed). After: 8 passed; with deployment, config,
  sandbox, intel, readiness, capabilities and rule-pack tests, 161 passed.
  `docker compose config -q` is clean (no daemon needed). ruff, mypy and
  bandit are clean.
- **Not done, needs a Docker host (PLATFORM).** Docker is installed here but
  its daemon is not running, so `deploy/check-deployment.sh` cannot run, and
  an unrun change could break the CI Docker job:
  - M27's signed-pack install in `deploy/check-deployment.sh`;
  - I-B3's stand-in LLM and sandbox URLs for `deploy/isolation_check.py`;
  - running the compose changes in containers.

### Full-suite evidence for groups 8 to 11

- Safe selection in a clean worktree at `4665b0c`, with the QR decoder and
  `-W default::ResourceWarning`: **1,429 passed, 0 failed, 23 skipped, 4
  deselected**, 278 s. `test_smoke.py` passed.
- I-T2: **0** "unclosed database" warnings; 33.4 recorded 199 per safe run.
- 15 warnings remain:
  - one Starlette deprecation;
  - 14 other resources, not SQLite: unclosed text files under pytest
    collection, three loopback SSL sockets, and files in
    `tools/mbox_to_eml.py:61`, `tests/test_mbox_tool.py:15` and
    `tests/test_evaluation_tools.py:110`.
  These are new test-hygiene notes, not fixed here.

### Group 12: L-E11, I-B5 and L-G1 (rank 10)

- **L-E11.** `engine/secret_store.apply`: a secret set in the process
  environment, even empty, now wins over the keyring with source
  `environment`. So `VIRUSTOTAL_API_KEY=` switches VirusTotal off for a run,
  as the Settings page says. A value `load_dotenv` copied from `.env` is still
  not "the environment" (`PROCESS_ENV`).
  - Test `test_an_empty_environment_variable_overrides_a_stored_key`: before
    the fix 1 failed, after it passes.
  - `test_environment_and_docker_secrets_win` relied on `WEBHOOK_SECRET` and
    `IMAP_PASSWORD` being unset, which group 8's conftest no longer gives (it
    exports them empty). It now removes them itself.
- **I-B5.** `core/outbox.verdict_alert` sends a container indicator by its
  base name (`archive_member:external_relationship` gives
  `external_relationship`), without duplicates; the character filter is
  unchanged. Test in `tests/test_alerts.py`: before 1 failed, after 56 passed
  with the M17 tests.
- **L-G1.** `aegis_gui/formatting.llm_skipped` returns False for an answer
  the model gave (`analyzed` True, or flagged). The text markers still apply
  to results without `analyzed`. Test: `tests/test_llm_skipped.py` (4 tests):
  before 1 failed, after 4 passed; with the GUI delivery and integration
  tests, 20 passed. Not shown on a display.
- Related runs: secret store, config, env isolation, GUI integration, intel,
  API, alerts, cloud and mailbox tests, 177 passed. ruff and mypy clean.

### Group 13: L-E10, I-B1 and I-B2 (rank 10)

- **L-E10.** `engine/metrics.prometheus` now reads the alert counter under the
  lock, as `snapshot()` does; the JSON snapshot is unchanged. Test in
  `tests/test_ops_metrics.py`: a stand-in counter raises "dictionary changed
  size during iteration" when it is read outside the lock. Before 1 failed,
  after it passes.
- **I-B1.** `core/http.USER_AGENT = "aegis-sentinel/<ENGINE_VERSION>"` is the
  default of `build_session`. The intel sandbox session and `CapeClient` no
  longer pass their own (4.7, 4.4); the default had been
  `hybrid-ransomware-detector/4.0`. Test in `tests/test_http.py`: before 1
  failed, after it passes.
- **I-B2.** New `requirements-sbom.txt` and `requirements-sbom.lock`
  (`cyclonedx-bom==7.5.0` and 32 dependencies, universal, Python 3.12+, every
  file hashed; same `uv pip compile` flags as the build lock). Both release
  SBOM steps install it with `--require-hashes`, and `quality.yml` audits it
  with the other locks.
  - Checked: it installs in a fresh venv with `--require-hashes`
    (`cyclonedx-py` 7.5.0), and pip-audit reports "No known
    vulnerabilities".
  - Test: `test_every_release_install_is_hash_pinned` (before the workflow
    edit 1 failed); the lock tests now cover the file.
  - **For the owner:** `python -m pip install --upgrade pip` (release build
    job) is the one remaining unhashed install. The test names it as the only
    exception; removing it would change the build environment.
- Runs: locks, CI workflows, metrics, HTTP, sandbox and intel tests, 62
  passed. ruff, mypy and bandit clean.

### Group 14: L-D4 and L-D6 (rank 10); L-D7 held for the owner

- **L-D4.** Cause confirmed on the old code: a 720 KB OneNote file of 20,000
  FileDataStoreObject GUIDs with impossible lengths gave 20,000 `skipped`
  entries.
  - Fix: `EmbeddedResult.skip()` keeps the first `MAX_SKIPPED` (50) and counts
    the rest; `as_dict()` adds one line "... N more not listed". The field
    stays a list of strings, and a non-empty list still makes the scan
    partial. All nine `skipped.append` calls use it.
  - Test: `tests/test_embedded_bounds.py` (bounded flood, short list
    unchanged).
- **L-D6.** `detectors/yara_engine.py` compiles each rule file under its file
  name (`a.yar`, `a.yara`), as `core/rulepack.py` does; the namespace appears
  in no result. Test: two rule files with one stem both match. The bundled
  set still compiles 5 files.
- Before the fix the three new tests failed; after it, 3 passed. With the
  embedded, mail, YARA, rule-pack, device-name and integration tests, 155
  passed. ruff and mypy clean.
- **L-D7 not changed: an owner decision.** `_chm` reads every page with
  `7z e -so`, because the HTML Help ShortCut check (`chm_shortcut`) looks at
  all of them, including pages past the 25-member limit. The plan's fix (stop
  reading at the member limit) would leave a shortcut page after the first 25
  members unchecked. That is an inspection-coverage change, which the
  repository rules reserve for the owner. Options:
  - (a) the plan's cap, with a `skipped` note so the scan reads partial;
  - (b) a higher read cap only for the shortcut check;
  - (c) keep reading every page.

### Group 15: L-A5, L-A6, L-A7 and L-A8 (rank 10)

- **L-A8.** `core/mailer.SmtpMailer.send` reserves a slot under the caps, then
  gives it back when the attempt fails, so only sent messages count and two
  threads cannot overshoot. Test: 25 failing sends with a cap of 20 an hour,
  then a working server sends.
- **L-A7.** `core/outputs._failure`: webhook errors (`post_alert`, which the
  outbox stores and the GUI shows, and the older `send_webhook` log line) name
  only the error type and the host. The README settings row says a chat
  service's webhook URL is itself a credential. Test: a `requests` error
  repeating a credential path does not leak it into the error or the log.
- **L-A5.** `core/containment.lock_folders` saves the record before every
  change: before anything, before each folder's `icacls`, and with each
  folder's original modes before its `chmod`.
  - If the record cannot be saved, nothing (more) is changed and a problem is
    returned.
  - A walk cut at `MAX_LOCK_ENTRIES` is reported ("the rest stay writable").
  - `_save_state` returns whether it saved.
  - Tests (check 9): an unwritable record path changes nothing; a crash after
    two `chmod` calls is undone by `unlock_folders`; the cap is reported.
- **L-A6.** `core/outbox._FlushLock` takes a lock name. `core/cloud.Spool`
  uses two per folder, shared by every thread and process:
  - "state", around each read-modify-write of `state.json` (in `add`,
    `cleanup` and `upload_due`);
  - "upload", one uploader at a time; another one returns at once.
  Uploads run outside the state lock. Tests (check 14): two Spool objects in
  two threads upload six items exactly once. While another process holds the
  upload lock, nothing is sent and the item stays queued.
- Before the fixes the new tests failed: L-A8 1, L-A7 1, L-A5 3, L-A6 2 (the
  thread test showed duplicate uploads). After: cloud, alerts, locks,
  background reliability, containment and response tests, 95 + 36 passed (1
  skip); the L-A6 tests passed in three repeat runs. ruff, mypy and bandit
  clean.

### Group 16: L-C5, L-E8 and L-A4 (rank 10), and a group 12 test repair

- **L-C5.** `setup_macos_autostart` writes the launchd agent with
  `plistlib.dumps` (paths with "&" or "<" are escaped). It returns False and
  prints the `launchctl load` error when the load fails; it used to report
  success. Test: `tests/test_autostart_macos.py` with a stand-in
  `subprocess.run` (no real launchctl): the plist parses with the exact
  arguments, and a failing load gives False. Before 2 failed, after 2 passed.
- **L-E8.** `engine/workers._WorkerLogBuffer` keeps the first records and the
  last `LOG_TAIL_RECORDS` (50) of its 200, with the "dropped" note between
  them. So the outer file's own `scan_completed` and `external_share`, which
  come after its members' records, reach the parent.
  - Test: 302 records give 201, ending with the outer file's two events.
  - The existing limit test now builds its 3-record buffer with `tail=0`
    (the old head-only form).
  - Before the fix 1 failed. After: worker log, worker and worker-limit
    tests, 39 passed, 3 skipped.
- **L-A4.** `deploy/backup.sh` and `deploy/restore.sh` read
  `AEGIS_VERSION=x`, `"x"` or `'x'`, with an optional `# comment`. Another
  form that sets the name (`export ...`, `AEGIS_VERSION = ...`) stops the
  script with a message, instead of the 4.8.0 default being used silently.
  Compose's own reading of those forms was not verified, so the scripts do
  not guess it.
  - Test: `tests/test_deploy_env_version.py` (14 cases) runs copies of the
    real scripts with a stand-in `docker` that records the image it is asked
    for. Before 6 failed, after 14 passed; `bash -n` clean.
- **Group 12 repair.** I did not run `tests/test_operations_fixes.py` with
  group 12 (L-E11), and three of its tests failed. They expected a keyring or
  unset source while conftest exports `VIRUSTOTAL_API_KEY=""`; old conftest
  did too, and the tests passed only because of the L-E11 bug. A fixture now
  removes the variable for those three tests: 30 passed with the L-A4 tests.

### Full-suite evidence for groups 12 to 16

- Safe selection in a clean worktree at `85acb6e`, with the QR decoder and
  `-W default::ResourceWarning`: **1,466 passed, 0 failed, 23 skipped, 4
  deselected**, 284 s. `test_smoke.py` passed. 0 "unclosed database"
  warnings.
- 16 warnings: one Starlette deprecation and 15 resource warnings (14 as in
  the groups 8 to 11 run, plus the child's stdout pipe in the new L-A6
  process test). That pipe is now closed (the test passes with no warning);
  test-only change after the run.

### Rank 11: status check (2026-11-11)

Each rank 11 item was checked against the code before work started; none had
been fixed since section 30.
- Done in groups 17 to 21 below: L-E1, L-E2, L-E3, L-C1, L-C2 (in part),
  L-C3, L-A1, L-A3, L-D3, L-B4, and the I-x items listed in group 21. L-D2
  is held for the owner (group 20).
- Not done here, as the register records:
  - L-D1 and L-E4 are excluded on this host with the known memory failures
    (30.6) and need the VM;
  - L-E5 and L-E6 stay suspected: Tesseract is not installed here, and L-E6
    is Windows only.

### Group 17: L-E1, L-E2 and L-E3 (rank 11)

- **L-E1.** `engine/staging._run_heavy` adds each parallel heavy layer's
  `layer_errors` to the result instead of letting `dict.update` replace the
  entry, which lost the other layers' errors. Test: two failing heavy layers
  are both recorded. Before 1 failed; after, the pipeline, scan-status and
  partial-evidence tests pass (93).
- **L-E2.** Three changes:
  - `engine/config._env_float` reports `nan` and `inf` and keeps the default;
    the import no longer crashes with `SCAN_TIMEOUT_SECONDS=nan`.
  - A new `_env_int`, used by the 16 whole-number settings, reports a
    positive value below 1 instead of reading it as 0, which means no limit
    for `WORKER_MEMORY_MB`, off for `IMAP_CHECK_MINUTES` and automatic for
    `SCAN_WORKERS`. Other values truncate as before.
  - `validate_config` rejects non-finite numbers set in code.
  - Test: `tests/test_config_numbers.py` (6 tests, fresh processes). Before
    5 failed; after 6 passed, with the config tests 58.
- **L-E3.** `engine/secret_store._remove_lines` also removes the continuation
  lines of a quoted multi-line value up to its closing quote (a double quote
  may be escaped). Test: single and double quotes; only the other settings
  stay in `.env`. Before 2 failed; after, with the other secret tests, 32
  passed.

### Group 18: L-C1, L-C2 and L-C3 (rank 11)

- **L-C1.** `import_hash_database` reads and checks the new file's header
  before anything is written. A file without `FileName`, `md5Hash` and
  `Benign` is refused and the working database is kept; a valid one replaces
  it atomically (temporary copy, `os.replace`). The CLI no longer prints
  "Successfully imported" for a refused file. The GUI already showed the
  message, and the database now really is unchanged.
- **L-C2.** `--scan-file` with a missing path, and a failed or refused
  `--import-database`, exit with the new `EXIT_INPUT_ERROR` (1); README
  updated.
  - **For the owner:** exit code 2 still has three meanings (configuration
    error, tripped canary for `--verify-canaries`, argparse usage error). They
    are documented and scripts may rely on them, so they were not renumbered.
- Tests for L-C1 and L-C2: `tests/test_cli_inputs.py` (3 tests, the CLI run
  in a subprocess with a scratch HOME). Before 2 failed; after 3 passed.
- **L-C3.** The report's "Detection layers used" lists `llm` only when the
  backend is available, and `virustotal` only with a key here, or when the
  intel service reports VirusTotal enabled. Test in
  `tests/test_llm_posture.py`: before 1 failed, after it passes.
- Runs: LLM posture, report files, scanner and v4.1 integration, intel
  tests: 74 passed; CLI, output-failure and pipeline tests: 42 passed;
  `test_smoke.py` passed.

### Group 19: L-A1 and L-A3 (rank 11)

- **L-A1.** `api/server._without_work_path` replaces, in every string of an
  API result, the temporary path of the upload by the client's file name.
  Its folder is removed, and `upload<ext>!/` member prefixes become
  `<name>!/`. Before, only `file_path` and `file_name` were replaced, so
  member names and findings started with the server's work folder.
  - Test (check 15): a ZIP upload through `TestClient` shows `bundle.zip!/...`
    and neither `aegis_api_` nor `upload.zip`. Before 1 failed; after, the
    API, auth, metrics, cache and alert tests pass (96).
- **L-A3.** New `write_atomic` (first in `core/fsutil.py`, moved to `engine/fsutil.py`
  with the docs group so there is one `fsutil` module): a temporary file in the same
  folder, flushed and fsynced, then `os.replace`, or `os.link` with
  `create_only`, which never replaces an existing file. Used for:
  - the containment record (`_save_state`);
  - the quarantine master key at creation (a concurrent creator still wins);
  - the key backup and import (`os.replace` from the old key to the new: no
    empty key slot);
  - the quarantine item records.
  - Not done: the folder itself is not fsynced, so a power loss just after
    the rename may still lose the new name on some file systems; the old
    file stays intact.
  - Test: `tests/test_atomic_writes.py` (4 tests). The commit step is made to
    fail, and the previous record or "no key" state is intact, with no
    temporary file left. With the old write paths all 4 fail; with the fix,
    4 pass, and with the quarantine and key-backup tests 27 passed;
    containment, response and folder-monitor tests pass. ruff and mypy
    clean.

### Group 20: L-D3 and L-B4 (rank 11); L-D2 held for the owner

- **L-D3.** `ScriptEmulator.emulate` checks the file size before reading the
  file (and again after, in case it grew). Test: a sparse file just over
  `MAX_SCRIPT_BYTES` is refused without `read_bytes`. Before 1 failed, after
  the emulation tests pass (5 passed, 1 skipped as before).
- **L-B4.** `.dockerignore` also excludes:
  - tool caches and `.arena`;
  - editor folders;
  - the local data and secret patterns of `.gitignore`: `*.key`, `secrets.*`,
    `*.csv`, `*.quar`, `*.joblib`, `keystore`, `quarantine`, `scan_reports`,
    `data`, `datasets`.
  No tracked file matches them (`git ls-files`: none under those roots, none
  with those extensions). Before, `COPY . .` in a local build could copy a
  key, hash CSVs or vault items into the image.
  - Test `test_local_data_secrets_and_tool_caches_stay_out_of_the_image`:
    before 1 failed; after, deployment and privilege-separation tests pass
    (21). The image itself was not built (no Docker daemon).
- **L-D2 not changed: an owner decision.**
  - A cut zlib, bzip2 or xz stream (`bounded_decompress` ignores the
    decompressor's `eof`), and a CPIO archive without `TRAILER!!!`, read as
    complete.
  - The fix that keeps the members read so far and counts the stream as
    unreadable changes those files' `scan_status` from `complete` to
    `partial`. 33.6 classes that as an owner decision (as for H4 and M13).
  - A plain `FormatError` would be worse: the caller collects members in a
    list comprehension, so every member already read would be lost.
  - Proposed when approved: a `Truncated` error carrying the partial output;
    `_pkg_stream` keeps the members it has and adds one unreadable member.

### Group 21: L-E7 and two I-x items (rank 11)

- **L-E7.** `RansomwareScanner.last_not_scanned` is a property backed by a
  `threading.local`. The GUI scan thread, the folder monitor and the CLI each
  set and read it in the thread that ran the scan, so concurrent scans no
  longer see each other's count. No caller changed, and the scanner is never
  pickled (the workers use `config`, `scan_file`, `scoring` and
  `calculate_hashes` only).
  - Test: two threads set 0 and 3 and each reads its own. Before 1 failed;
    after, the scanner, folder-monitor, output-failure, isolation,
    GUI-delivery and background tests pass.
- **I-x: IMAP fetch failures.** `MailboxRun.fetch_failed` lists UIDs whose
  body the server did not return; they were counted in `skipped_too_large`.
  The CLI prints a separate warning.
  - Test: a stand-in server that answers NO for one body. Before 1 failed;
    after, 8 mailbox tests pass.
  - **For the owner:** a failed fetch is still marked seen (not retried), as
    before. Retrying it would rescan every later message on each run while
    the failure lasts (duplicate alerts).
- **I-x: intel JSON parsed before auth.** The four JSON routes
  (`/v1/virustotal/lookup`, `/v1/llm/analyze`, `/v1/sandbox/poll`,
  `/v1/alert/email`) took `Body(...)`, which FastAPI parses before the token
  dependency. They now read the body in the route (`_json_body`) and run the
  service call in the thread pool, as FastAPI did for the old sync routes.
  - Test: without a token or with a wrong one, a broken body gets 401 (it
    was 422); with the token, 422, or 403 for e-mail when no mailer is
    configured. Before 4 failed; after, intel, alert and mailbox tests pass
    (85).
  - The three real-socket intel tests stay deselected here (they hardcode
    `/tmp`).
- I-x items not done:
  - the cache purge runs at start-up only (expired answers are never
    served; disk growth only);
  - `send_webhook` is unused in production but kept, since tests use it;
  - the scikit-learn pickle version check is only suspected;
  - "evaluate counts errors as Clean" is in rank 12 (L-C9).

### Group 22: rank 12, the evaluation and build tools

Status check first: none of L-C4, L-C8, L-C9, L-C10, L-C11, I-B4 or the I-x
"evaluate counts errors as Clean" had been fixed. All are done here. These
tools run in the analysis VM, not in the product; no sample was used, only
synthetic inert files.

- **L-C4.** `tools/evaluate.py` (pool worker) and `tools/calibrate_weights.py`
  set `sandbox_url` to empty: evaluation samples never go to a sandbox.
  - Test: with `SANDBOX_URL` configured, both scanners have no sandbox. The
    test restores the environment and `logging.disable`, because
    `_init_worker` sets both (I-T1, still deferred).
- **L-C9.**
  - `calibrate_weights.scan_folders` scans through `scan_one`, the product's
    isolated worker with its time and memory limits, and records a failed
    scan as an error row.
  - `evaluate._init_worker` applies the product's `WORKER_MEMORY_MB` with
    `engine.workers._limit_memory`; the time limit stays the pool's
    `--timeout`. On macOS that sets nothing, because the product's watchdog
    needs a parent; Linux was not run here.
  - Test: a stand-in `scan_one` that fails one file gives one error row, and
    `scan_file` is never called.
- **I-x.** The evaluation's verdict distribution no longer counts errored or
  timed-out files as Clean; an "Error" row lists them.
- **L-C8.** `tools/mbox_to_eml.py` names the second mailbox with one stem
  `<stem>-2_00001.eml` and so on: two `inbox.mbox` give twice the files.
- **L-C10.** `calibrate_weights.score_rows` scores like the engine.
  `ScoringMatrix._aggregate` applies the per-category caps, the semantic-only
  clamp at 49 and the maximum, with each indicator's category from the
  registry. `calibrate()` dedupes with `tools/splits.dedupe` and reports
  `duplicates` and `conflicts`.
  - Tests: a semantic-only row scores at most 24, and semantic plus 40
    technical points gives 64. Duplicates count once and a conflicting hash
    is left out.
- **L-C11.** `build_fuzzy_db.build()` keeps benign file paths out of the
  database, which may leave the VM. They go only to an optional
  `local_report`; the CLI writes them to `<out>.benign-matches.local.json`.
- **I-B4.** `tools/profile_layers.py` times only the outermost layer calls
  (members of a container run their layers inside it), and removes its
  `hrd-profile-` folder and closes the cache.
  - Test: with a clock for the tool only, the per-layer total is at most the
    wall time; it was 286 against 223. The folder is gone.
- Before the fixes the new or changed tests failed: L-C4, L-C9 and the I-x
  item, 3; L-C8 1; L-C11 1; I-B4 1; L-C10 2. After: tool tests (evaluation,
  calibration, fuzzy DB, mbox, profile, benchmark fixes, tools path) 41
  passed. ruff, mypy and bandit clean.

### Group 23: rank 14 documentation, README part

Status check first, against the code:
- **Already done:** D27 and D38 (with M27 and M28); D42 is now true, because
  L-C11 keeps benign paths out of the fuzzy database.
- **Owner items, unchanged:** D20 (M18), D22, D23 and D26 (33.7), D32 (the
  L-B2 lock choice) and D11 (M23).
- **Release state, unchanged:** D14 (badge, tag, image archive) and D10 (the
  history and "delivered" list); both are true only after a release, and the
  version is not touched.

README changes:
- **D1:** "23 public rules" (yara-python compiles 25: 23 public and the 2
  private helpers in `office_dropper.yar`).
- **D2:** CI runs on pull requests, pushes to `main` and manual dispatch.
- **D3 and L-B6:** the badge and two sentences now name the tested targets
  (Linux x64, Windows x64, macOS arm64), and `python-tlsh` is source-only.
- **D4:** all eight secret names.
- **D5:** notifications on Windows too.
- **D6:** `AUTO_QUARANTINE` accepts `medium` and `off`.
- **D7:** every scan runs in a worker.
- **D8:** the project tree lists the modules added since 4.6, `deploy/`,
  Docker and the documents.
- **D9:** the docker and parser-fuzz workflows.
- **D12:** one total decompressed-size budget, not a per-member limit.
- **D13:** `requirements.txt` is unpinned; the audited set is the lock.
- **D31:** the sandbox wait must stay below `SCAN_TIMEOUT_SECONDS`.

`write_atomic` moved from `core/fsutil.py` (group 19) to `engine/fsutil.py`, so
there is one `fsutil` module; its users and test were updated (56 passed).

### Group 24: rank 14 documentation, the other documents

Each statement was checked against the code before it was written.
- **THREAT_MODEL.**
  - D12: one total budget.
  - D15: the layer guard is in `engine/staging.py`.
  - D16: the 100 MB budget is fixed, not a setting.
  - D17: a timed-out file reads Medium without its other findings, below the
    default alert floor (H6); the slow-file risk is re-rated Medium.
  - D18: all secrets named.
  - D19: removing a key works only while another key stays configured (M27).
- **RULE_PACKS (D19).** The same limit, and where Docker reads the keys.
- **ARCHITECTURE.** D7: every scan runs in a worker. D21: the interfaces added
  since 4.6 (folder monitoring, outbox and e-mail, cloud, the intel service).
- **RELEASE_SCOPE.**
  - D24: the Dockerfile exists, and the `docker` workflow builds and checks it.
  - D25: the lock is for Python 3.12 and later; 3.14 installs (local runs used
    3.14.2); neither 3.13 nor 3.14 runs in CI.
- **DEPLOYMENT, RUNBOOKS, OPERATIONS.**
  - D28: the memory rule is concurrent scans x `WORKER_MEMORY_MB` plus about
    200 MB per idle spare, plus the main process. Only workers holding an
    upload are busy, and uploads are capped by `ScanSlots`.
  - D29: a stop keeps scans that end within 120 s; raise `AEGIS_STOP_GRACE`
    for longer ones.
  - D30: the bundled proxy stops bodies at 52 MB (`deploy/Caddyfile`).
  - D33: copy the `deploy/` folder too.
  - D34: install the current signed pack; installed packs cannot be copied.
  - D35: going back from 4.8 to 4.7 was not tested, and what it needs:
    4.7.0's compose has no `smtp_password` secret (checked with `git show`).
  - No default was changed.
- **RELEASING.**
  - D36: `X.Y.Z` in the examples. The release workflow compares the tag with
    `pyproject.toml` and `ENGINE_VERSION` only (`release.yml:57-68`), so the
    changelog heading is kept in step by hand.
  - D37: the readiness matrix is the 4.7 one; the 4.8 state is here and in
    the review.
- **DATA_POLICY (D39), SUPPORT (D40), DATASET_PLAN (D41).**
  - D39: the webhook URL can be a credential.
  - D40: the result fields that can hold document content (`prompt_guard`'s
    `hidden_text_snippets` exists, `detectors/prompt_guard.py:127`).
  - D41: the extension list matches `SUPPORTED_EXTENSIONS` exactly (checked
    by script); `evaluate.py` also takes LNK, ELF, PE and embedded-content
    files by content.
- Unchanged: D10 and D14 (release state), D11, D20, D22, D23, D26, D32 (owner).
- Docs-reading tests (background reliability, closed limits, operations,
  printable names, deployment, CI workflows, locks): 59 passed.

### L-D7: options for the owner (prepared 2026-11-11, not changed)

Today `_chm` starts one `7z e -so` per page or file in the help file. It reads
every one (to look for the HTML Help ShortCut object) and keeps at most 25
(`MAX_MEMBERS`) as members. Measured here: starting `7zz` costs about 4.2 ms
(30 starts of `7zz i`, macOS arm64). Each page read also reopens the CHM index,
so the real cost per page is higher and grows with the file. 7-Zip is not in
the server image, so this is a desktop and analysis-VM question.

| Option | Detection coverage | Resources | `scan_status` |
|---|---|---|---|
| (a) Stop reading at the member limit (the review's fix) | A ShortCut page that sorts after the 25th kept member is no longer seen, so `chm_shortcut` and its points can be lost | Bounded by the number of pages up to the 25th member, often under 100 processes | `partial` with a `skipped` note when pages were left unread, so the loss is visible |
| (b) A separate, higher read cap for the ShortCut check (for example 500 pages) | Unchanged for help files up to the cap; beyond it, as (a) | At most cap processes: 500 x (4 ms + index read), a few seconds | `partial` only beyond the cap |
| (c) Keep reading every page (today) | Full | Unbounded by count; a file with thousands of tiny pages starts thousands of processes until `SCAN_TIMEOUT_SECONDS` (300) stops the worker | A timeout gives `failed`, which replaces the findings (H6) |

Notes:
- (b) keeps today's coverage for ordinary help files and bounds the cost.
  The cap is a coverage decision, which is why it is the owner's.
- A fourth design, one 7-Zip run that extracts all pages into the sandbox,
  would change the "7-Zip never writes a file" rule (`container_extractor`)
  and is not proposed.
- Whichever option is chosen, the test is a stand-in page list of 100
  members, counting the reads; and, for (a) or (b), a ShortCut page past the
  cap gives `partial`.

### Full-suite evidence for groups 17 to 24

- Safe selection in a clean worktree at `0ca988a`, with the QR decoder and
  `-W default::ResourceWarning`: **1,500 passed, 0 failed, 23 skipped, 4
  deselected**, 300 s. `test_smoke.py` passed. 0 "unclosed database".
- 17 warnings. The two new ones came from the L-C8 test reaching a known leak:
  `tools/mbox_to_eml.py` never closed its mailbox (listed in groups 8 to 11).
  Fixed after the run; the mbox tests then pass with no warning. The rest are
  as before: Starlette, test sockets and files.

### Final safe run at `04f396e` (owner request, 2026-11-11)

- Clean worktree, `env -i PATH=/usr/bin:/bin`, scratch `HOME` and `TMPDIR`,
  `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`. Command: `.venv/bin/python -m pytest
  -p no:cacheprovider -q -rfE --tb=short -W default::ResourceWarning -o
  faulthandler_timeout=300 --ignore=tests/test_fuzz_parsers.py`, deselecting the
  runaway-memory test and the three intel socket tests.
- Result: **1,500 passed, 0 failed, 23 skipped, 4 deselected, 13 warnings**,
  301 s. 0 "unclosed database". `test_smoke.py`: "ALL SMOKE TESTS PASSED".

### L-D7 option (b): proposal, not implemented (waits for the owner)

- **Cap.** A new `MAX_CHM_READS = 1000`: the most pages and files `_chm` reads
  with `7z e -so`. Internal streams (`#...`, `$...`), folders and links are
  not counted, as today. Pages over `MAX_MEMBER_BYTES` stay skipped as today,
  and the 25-member limit is unchanged.
- **Why 1,000.**
  - The phishing CHM files this check is for are small, a handful of pages,
    and most product help files have tens to a few hundred.
  - 1,000 keeps today's coverage for all of them, at a cost that is a small
    part of the 300 s scan limit.
  - Large reference CHMs (programming-language manuals) can have several
    thousand pages; they would read partial.
  - 500 would halve the cost but reach that point sooner; this was chosen
    from typical sizes, not measured on a corpus.
- **Resource cost (measured here).**
  - Starting `7zz` takes 4.2 ms. Reading one page with `7z e -so` from a
    synthetic 600-page ZIP took 3.9 to 4.0 ms (50 and 200 reads, macOS arm64).
  - So 1,000 pages is about 4 s of 7-Zip time, plus a CHM index that may cost
    more than a ZIP's.
  - Today a hostile file with 75,000 tiny pages would take about 300 s and
    end as a timeout (H6). With the cap the worst case stays near 4 s.
  - 7-Zip is not in the server image: desktop and analysis VM only.
- **What can be missed beyond the cap.**
  - The HTML Help ShortCut object (`chm_shortcut_command`, 60 technical
    points) on a page after the 1,000th. Alone it makes a file High (50 to
    79), so such a file would read Clean, but partial.
  - Pages are read in sorted path order, so an attacker who adds 1,000 filler
    pages in front can push the ShortCut page past the cap. That costs them
    the partial flag and a 1,000-page file.
  - A script or program page that would have been one of the first 25
    members but sorts after the cap.
- **When `scan_status` becomes partial.** Only when pages are left unread:
  `res.skip("N of M help pages not read (read limit 1000)")`. The existing
  embedded-content rule (`engine/completeness.py`: every `skipped` entry is a
  partial reason) makes the file partial with the reason "not unpacked: N of M
  help pages not read (read limit 1000)". A CHM with at most 1,000 pages is
  unchanged.
- **Regression tests (stand-in `sevenzip_list` and `sevenzip_read`, as in
  `test_chm_pages_are_scanned_and_shortcut_object_flagged`):**
  1. 1,200 pages: `sevenzip_read` is called exactly 1,000 times, and
     `skipped` holds "200 of 1200 help pages not read (read limit 1000)".
  2. A ShortCut page at position 1,000: found, nothing skipped, `complete`.
  3. A ShortCut page at position 1,001: not found, skipped note present;
     through the scanner, `scan_status` is `partial` with that reason.
  4. 30 pages: all read, nothing skipped, `complete`; the existing CHM test
     unchanged.
  5. 2,000 internal streams (`#SYSTEM`, `$FIftiMain`) plus 10 pages: 10
     reads, no skip.
  6. 40 script pages within the cap: 25 members as today, the rest
     "member limit reached".
- Optional later: read the CHM's default topic (named in `#SYSTEM`) first,
  since a ShortCut that runs on opening is usually there. Not part of this
  proposal.

### Group 25: L-D7 option (b), owner-approved 2026-11-11

- `detectors/embedded_content.py`: `MAX_CHM_READS = 1000`.
  - `_chm` collects the pages and files it would read: not internal
    `#`/`$` streams, folders or links, as before.
  - It reads at most 1,000 of them in sorted path order.
  - When more exist, it adds "N of M help pages not read (read limit 1000)"
    before any other note, so it is always among the 50 listed entries.
  - Nothing else changed: weights, thresholds, member limit, size limit and
    result fields. The roughly 4 s cost for 1,000 pages is an estimate from a
    synthetic ZIP, not a measured CHM runtime.
- Found while testing, not changed: every `.htm` page is a member, so a help
  file with more than 25 pages already reads partial through the member limit
  ("member limit reached"). A test pins this.
- Tests: `tests/test_chm_read_cap.py` (10).
  - The cap value; 1,200 pages give 1,000 reads and the note.
  - ShortCut on page 1,000: found, no read note.
  - ShortCut on page 1,001: not found, note.
  - 20 pages: complete. Internal streams do not count. Member limit
    unchanged. More than 25 pages read partial (existing).
  - Through the scanner: beyond the cap, Clean and partial with the reason;
    at page 1,000, the indicator; 20 pages: complete and High.
  - The alert pin below.
  - Before the change the four cap tests failed, and the other five passed
    on the old code.
- Output check, in-process with stand-in 7-Zip calls and a scratch home: a
  ShortCut page on page 1,001 of 1,001.

  | Output | What it shows |
  |---|---|
  | Result | `Clean`, risk 0, `scan_status: partial`, first reason "not unpacked: 1 of 1001 help pages not read (read limit 1000)" |
  | Text report (what `--scan-file` prints) | "Scan completeness: 1 partial", "No suspicious files detected in what was inspected; 1 scan(s) were not complete", "Verdict: Clean (partial scan)", the gap line |
  | JSON report, JSON Lines | `partial` and the same reason |
  | Webhook payload | `scan_status: partial` |
  | GUI helpers (`verdict_text`, `first_gap`, `gap_rows`, used by the result table and the detail window) | "Clean (partial scan)", the read-limit gap first |
  | Alerts | none queued: alerts follow the verdict only; the e-mail fields have no `scan_status` |

  The CLI exit code stays 0 for a partial scan (3 only when isolation is
  unavailable). The GUI was not shown on a display.
- **Owner decision needed (not changed): alerting on a partial scan.** Such a
  file sends no webhook or e-mail at any verdict below the floor (default
  High), as for every partial result today. Options:
  - (i) keep it;
  - (ii) an alert for partial results of selected kinds, such as "help pages
    not read", at a configured floor;
  - (iii) let a partial result's verdict be raised.
  (ii) changes alert semantics and (iii) changes result semantics; both are
  the owner's.
- README: the CHM paragraph names the 1,000-page limit and the partial
  report.
- Full safe run at `50d715d` (clean worktree, the same command as at
  `04f396e`): **1,510 passed, 0 failed, 23 skipped, 4 deselected, 13
  warnings**, 297 s; 0 "unclosed database"; `test_smoke.py` passed.
  Focused: CHM cap, embedded, scan status, partial evidence, report files,
  alerts and LLM-skip tests, 138 passed before the alert pin; the CHM file
  then had 10 passed. ruff, mypy and bandit clean.

### Group 26: L-D7 option (ii), the incomplete-scan notice (owner-approved 2026-11-11)

The owner chose (ii), then corrected the scope: CHM content left unread by
either the 1,000-page read limit or the 25-member limit. Fully inspected CHM
files and malware alerts stay as they were.
- **Notice.** `core/outbox.incomplete_alert(result)` builds a notice of kind
  `incomplete_scan` when the result's gaps hold
  `embedded_content.CHM_READ_LIMIT_MARK` or `CHM_MEMBER_LIMIT_MARK`. That
  includes a CHM inside an archive or e-mail; otherwise it returns None.
  - The id is `_alert_id("incomplete_scan", sha256, scan_time, path)`: the
    same result gives the same id, and `Outbox.enqueue` skips an id already
    pending or sent, so the notice is never sent twice.
  - `channels_for` sends it, like a canary trip, to every configured channel
    whatever the verdict floor.
  - Delivery, retries, expiry and the e-mail caps (`SmtpMailer`) are the
    existing ones.
  - `results_alerts()` is used by `core/outputs.deliver` (CLI, folder scans,
    folder monitor, GUI) and by the API's alert queue.
- **Unchanged:** the result (a test compares it before and after delivery),
  its score, verdict, `scan_status` and fields; the CLI exit code; the
  verdict alert and its payload.
- **E-mail.** The kind `incomplete_scan` is added to `core/mailer.KINDS`; the
  field set is unchanged. Subject: "Aegis Sentinel notice: incomplete scan
  (not a detection) - <file>". It opens with "...This is not a malware
  detection...". The reason codes are `chm_pages_not_read` and/or
  `chm_members_not_scanned`. Messages of the other kinds are byte-identical.
- **Webhook.** A separate message: `kind: incomplete_scan`, `detection: false`,
  verdict, score, `scan_status`, and up to 10 gaps (path and reason).
- **The only change to result content.** A CHM page over the member limit is
  now noted "<page>: member limit reached (help file)" instead of
  "<page>: member limit reached", so the notice can tell CHM files apart from
  OneNote, MSI and XLL files, which keep the old text. Same field, same
  status, same score.
- **Compatibility.**
  - Result schema: unchanged.
  - Webhook receivers get a third value of `kind`. The canary message
    already has a different shape, so a receiver that handles canary
    messages handles this one; one that assumes every message has
    `indicators` and `top_reason` was already broken by canary messages.
    There is no documented webhook schema; DATA_POLICY now names the notice.
  - Docker: the intel service validates the e-mail `kind`. Analysis and intel
    run the same image; a mixed-version pair (an older intel) would answer
    422, so the e-mail stays queued and expires after `OUTBOX_MAX_AGE_HOURS`.
  - Outbox files and metrics are kind-neutral. No code in the repository
    branches on alert kinds besides the outbox and the mailer (searched).
- **Tests:** `tests/test_incomplete_scan_alert.py` (10).
  - Read limit: one notice, the result unchanged, no second notice for the
    same result.
  - Member limit only (30 pages): a notice with `chm_members_not_scanned`.
  - Fully read (20 pages): nothing.
  - Other partial scans (an archive limit, a OneNote member limit): none.
  - A Clean result's alert is unchanged; a High CHM sends only its verdict
    alert when fully read, and both when it also has a gap.
  - The e-mail wording, and existing e-mails unchanged.
  - The hourly cap applies.
  - Every configured channel whatever the floor.
  - `tests/test_chm_read_cap.py`'s alert pin now expects the one notice.
  - Before the change 5 failed and 2 passed (today's behaviour). After: with
    the CHM, alerts, embedded, output-failure, GUI-delivery and intel tests,
    122 passed.
- **Reports, checked in-process with stand-in 7-Zip calls:**
  - 1,001 pages: text "Verdict: Clean (partial scan)", "51 gap(s)", the
    read-limit line first, then "member limit reached (help file)"; JSON
    `partial` with the same first reason; notice with both codes.
  - 30 pages: Clean, partial, 5 member-limit gaps; notice
    `chm_members_not_scanned`.
  - 20 pages: Clean, complete, no notice.
- Docs: README CHM paragraph; DATA_POLICY webhook row.
- Full safe run at `37ee441` (clean worktree, the same command as at
  `04f396e`): **1,520 passed, 0 failed, 23 skipped, 4 deselected, 13
  warnings**, 299 s; 0 "unclosed database"; `test_smoke.py` passed. ruff,
  mypy and bandit clean.

### Group 27: the last SAFE I-x items (2026-11-11)

A reconciliation of every finding against the code and tests found two
confirmed SAFE sub-items of the I-x row still open. Both are done here.
- **Cache purge.** `core/cache.ResultCache.put` also deletes expired rows, at
  most once an hour (`PURGE_EVERY_SECONDS`). Before, only opening the cache
  did, so the background service and the API kept expired rows on disk until
  a restart (they were never served). Test
  `test_expired_answers_are_purged_while_the_process_runs`, with a fake clock:
  before 1 failed; after, with the cache and scanner tests, 29 passed.
- **Unused `send_webhook`.** Removed from `core/outputs.py`; the product uses
  the outbox and `post_alert`.
  - Its test now goes through `verdict_alert`, `channels_for` and
    `post_alert`, keeping the signature, threshold and "metadata only"
    checks.
  - The L-A7 test keeps its `post_alert` part.
  - 80 passed with the alert, output-failure and notice tests.
- Not done: the scikit-learn version check on model pickles. The review
  records it as a suspicion (S), not a confirmed finding.
- **Optional improvements I-3 and I-4** (31.9, "not defects"; 24.2: done only
  if approved separately) are listed for the owner, not done.

### Reconciliation of every finding (2026-11-11, at `9892704`)

Full safe run at `9892704` (clean worktree, the same command as at
`04f396e`): **1,521 passed, 0 failed, 23 skipped, 4 deselected, 13 warnings**,
300 s; 0 "unclosed database"; `test_smoke.py` passed. Skipped and deselected
tests are not counted as passed.

| State | Findings |
|---|---|
| Fixed, with a regression test passing locally | Sections 28 to 30: H1 to H4, H4-b, M1 to M3, M5 to M14, M15 docs, L-GUI, L-B1, L-B5, the L-B2 secrets. Groups 1 to 27: M21, L-B7, H5, M22, I-5, M17, M20, L-E9, I-T3, M33, L-C6, M28 (D38), L-T1, L-B3, I-T2, S-T1, the 33.4 rule tests, M26 start-up check, M27 compose part, L-E11, I-B5, L-G1, L-E10, I-B1, I-B2, L-D4, L-D6, L-A4 to L-A8, L-C5, L-E8, L-E1 to L-E3, L-E7, L-C1, L-C2 (exit 1), L-C3, L-C4, L-C8 to L-C11, L-A1, L-A3, L-D3, L-B4, I-B4, the I-x items (IMAP label, intel auth, evaluate errors, cache purge, `send_webhook`), L-D7 (read limit and notice), H6 (a) (group 28, `592e920`), M18 (group 29, `34c5e76`), H6 (b) (group 30, `8978c68`, `eb04d82`), M31, M23, L-E12, L-D2, L-D5, L-D8, L-C7 (group 32), M19, L-L1, L-A2, the release pip upgrade (group 33), H-04+, M30, M25 (alert only), the M27 empty-key rule, I-1 (eight macro types), I-3 (daily audit; Dependabot not added), I-T1 (group 34), M24, M29 (script part), the lock-refresh tool (I-3 option A) (group 35), I-2 (archive member order), the M26 wait cap (sandbox only) (group 36) |
| Fixed, docs only | D1 to D9, D12, D13, D15 to D19, D11 (group 32), D20 (group 31), D21, D24, D25, D27 to D31, D33 to D42, L-B6 (claims narrowed to the tested targets), the L-B2 lock choice (D32), D22, D23 (group 34) |
| SAFE, still open | none that can be done here |
| Owner decision | M29 web-page case (prose quoting the command), M32, S-Y1 to S-Y4, the rest of I-6 (VirusTotal upload wait and LLM; the sandbox part is done), M4, M15 packaging, D26, the Starlette `httpx` deprecation (dependency), I-2 for mail attachments (not asked), I-4, the other twelve I-1 types, Dependabot for the locks (I-3; replaced by the manual `tools/refresh_locks.py`, option B, a workflow that opens a PR, not taken), exit code 2 (keep), IMAP fetch retry (keep) |
| Real-environment check needed | CI (nothing since `3e5a3f2`; the new daily audit, I-3); Docker (deployment check, M27 signed pack and the empty-key fallback, D22/D23, the M26 cap on the intel sandbox path, I-B3, the L-B4 image, M26 on intel, L-A4 scripts); Windows (M2, M9, M20, M24 delivery by real mail clients and archive tools, L-E6, toasts, containment, autostart, the L-A5 icacls order); the VM (L-D1, L-E4, OOM-H, 27.5, real samples, L-C9 on Linux); a display (M28, L-C6, L-G1, L-E9, M30 in the table); a running service and GUI (M25 copy and memory); a Linux server (L-B2); the release workflow on a tag (M16, I-B2); Linux and Windows ARM64, macOS Intel; a benign corpus (M29 script part and web-page case, M32, S-Y); Tesseract (L-E5) |
| Suspected, not confirmed | S-01, S-03, the scikit-learn version check, L-E5, L-E6 |
| Restricted | OOM-H (VM only) |

### Group 28: H6 option (a), the scan-failed notice (owner-approved 2026-11-12)

- Owner decision: H6 (a) only. H6 (b) (keep the partial evidence) and every
  other owner item are unchanged.
- **Behaviour.** A result whose `scan_results.scan_failed` is set (time-out,
  a dead worker, the memory limit, or a scan error in the worker or the
  in-process path) also queues a notice of kind `scan_failed` on every
  configured channel, whatever the verdict floor, as canary and
  incomplete-scan notices do. A file never scanned because no worker could
  start (`code: isolation_unavailable`) gets none; it is reported by exit code
  3, the GUI error and the API 503 as before. The review's option (a) text
  ("failed scans other than isolation_unavailable") sets this scope; the
  memory limit and scan errors are included because they build the same
  `failure_result`.
- **Unchanged:** the verdict (Medium), risk score, `scan_status: failed`, the
  result schema, the CLI exit code, and the verdict alert. Under a Medium
  floor the verdict alert is still sent, with the notice beside it (pinned).
- **Code.** `core/outbox.py`: `_notice()` is the shared builder for both
  notices (the incomplete-scan output is byte-for-byte the same);
  `failed_alert()` names the failure (`scan_timed_out`, `worker_died`,
  `worker_memory_limit`, `scan_error`, read from the failure text as
  `engine/metrics.py` does); `results_alerts()` adds it; `channels_for()`
  routes it. `core/mailer.py`: kind `scan_failed`, subject "Aegis Sentinel
  notice: scan failed (not a detection) - {file_name}", and an intro saying it
  is an incomplete scan, not a malware detection.
- **Dedup, retry, caps.** The id is `_alert_id("scan_failed", sha256,
  scan_time, path)`, so the outbox skips the same result twice; retries,
  expiry and the e-mail hourly and daily caps are the existing ones.
- **Compatibility.** As for `incomplete_scan` (group 26): the result schema is
  unchanged; webhook receivers see a third non-verdict `kind` with
  `detection: false`; the intel service validates e-mail kinds with the same
  code, and both services run the same image. An older intel would answer 422
  and the e-mail would stay queued until it expires.
- **Docs.** README (isolation), DATA_POLICY (webhook row), RUNBOOKS section
  2, THREAT_MODEL (worker bullet and the slow-file row).
- **Tests:** `tests/test_failed_scan_alert.py` (13). All 13 failed before the
  change. They cover a real time-out and a real worker exit in isolated
  workers (one notice each, none for the file that scanned, none on a second
  delivery), each failure code, `isolation_unavailable`, a successful scan,
  malware alerts unchanged, the Medium floor, routing, the e-mail text and
  intel validation, the e-mail cap and the API e-mail queue. No memory-spike
  test was run (the memory code is checked on a built result).
- **Checks.** Related suites (alerts, notices, outputs, workers, scan status,
  metrics, isolation, intel, mailbox, mail, cache): 231 passed, 1 deselected
  (the runaway-memory test). ruff, mypy (68 files) and bandit (`-ll`, the CI
  scope) clean. pip-audit not run: no dependency changed.
- **Full safe run at `592e920`** (clean worktree, the command of the
  `04f396e` run): **1,534 passed, 0 failed, 23 skipped, 4 deselected, 13
  warnings**, 313 s; 0 "unclosed database"; `test_smoke.py`: "ALL SMOKE TESTS
  PASSED". Skipped and deselected tests are not counted as passed.
- Not verified here: delivery to a real webhook receiver or SMTP server, the
  notice through the Docker intel service, and Windows worker deaths.

### Group 29: M18, checked JSON replies from workers (owner-approved 2026-11-12)

- Owner decision: M18 only. H6 (b) and the other owner items are unchanged.
- **Protocol before.** Worker to parent: `("ready", None)`, `("log", [records])`
  before each result, then `("ok", result)` or `("error", text)`, all through
  `Connection.send`, so the parent unpickled them (`wait_ready` and
  `_IsolatedScan._receive`). Time-outs, the memory limit and worker death are
  noticed by the parent (no message); a closed pipe reads as a dead worker.
- **Protocol now** (`engine/workers.py`):
  - `send_reply()` (worker): JSON bytes through `send_bytes`. Values JSON
    cannot hold are sent as text (`default=str`, as the JSON Lines output);
    a result over the limit is sent as an error, log records over it are
    dropped (a file never loses its result over its log lines).
  - `read_reply()` (parent): `recv_bytes(MAX_REPLY_BYTES)` (16 MiB; a longer
    message is refused before its body is read), UTF-8, `json.loads`, then
    `check_reply()`. Nothing is unpickled.
  - `check_reply()`: a `[kind, payload]` pair of a known kind; `ready` with no
    payload; `error` as text, cut to 2,000 characters; `log` a list of at most
    201 plain records (no key that names a LogRecord method or starts with
    `__`, no `args` or `exc_info`); `ok` an object with `file_path`, `verdict`
    (one of the five), `risk_score` (a number, not a bool), `scan_status` (one
    of the five) and `scan_results`, and the right types for the other fields
    the parent and the outputs read.
  - An invalid message fails that file as `scan_failed` with "the worker sent
    an invalid reply (...) and was stopped; nothing in it was used", and the
    worker is replaced, as for a dead worker. Before the first `ready` it is a
    failed start. Metrics count it as `error`; the H6 (a) notice names it
    `scan_error`.
  - Unchanged: the parent still pickles the paths it sends (the worker trusts
    its parent); results, errors, log replay, time-outs, the memory limit,
    worker death and the result schema. A 500-member archive's result is about
    50 KB and round-trips through JSON unchanged (probe).
- **Review check 3** (the pickle that runs code in the receiver), before and
  after: `('ok', None) | code ran in the receiver: True`, then `('invalid',
  'not JSON (UnicodeDecodeError)') | code ran in the receiver: False`.
- **Tests.** `tests/test_worker_reply_protocol.py` (31): a pickle with
  `__reduce__` is refused and never loaded; an oversized message is refused
  before reading; 23 malformed or unexpected shapes; valid `ready`, `log`, `ok`
  and `error` round-trip (with a non-UTF-8 file name); long errors are cut; the
  worker's own size handling; non-JSON values; an invalid first message is a
  failed start; and real isolated workers (`tests/worker_fakes.py`: `evil*`
  writes a crafted pickle, `huge*` a message over the limit) fail only their
  own file, run no code in the parent, and the scan continues.
  `tests/test_worker_limits.py`: the stand-in pipe takes JSON bytes now (the
  assertions are unchanged).
- **Docs.** THREAT_MODEL section 10 (residual), DEPLOYMENT (why no network),
  RUNBOOKS section 2 (the new failure text). The pool is still described as
  not a full security boundary: worker and parent run as the same user.
- **Checks.** Worker, isolation, log, partial-evidence, folder-monitor, scan
  status, outputs, failed-scan, metrics, regression-corpus and scanner
  suites: 223 passed, 3 skipped, 1 deselected (runaway memory); after the log
  record check was tightened, the worker suites again: 90 passed, 3 skipped,
  1 deselected. ruff, mypy (68 files) and bandit (`-ll`) clean. pip-audit not
  run: no dependency changed.
- **Full safe run at `34c5e76`** (clean worktree, the command of the
  `04f396e` run): **1,565 passed, 0 failed, 23 skipped, 4 deselected, 13
  warnings**, 314 s; 0 "unclosed database"; `test_smoke.py`: "ALL SMOKE TESTS
  PASSED". Skipped and deselected tests are not counted as passed. (A first
  launch did not run: the shell did not split the command variable; it was
  rerun with the command written out.)
- Not verified here: Windows pipes (`PipeConnection`, the same
  `recv_bytes` limit by the standard library's code), Linux and the Docker
  API service under load.

### Group 30: H6 option (b), findings kept when a scan fails (owner-approved 2026-11-12)

- Owner decisions (2026-11-12): H6 (b); score rule "the higher of the two";
  evidence in a new `scan_results.partial_evidence` key; automatic quarantine
  may act on the result; scope "members + container listing" (asked after the
  probe below showed members alone miss the review's own example).
- **What reached the parent before a failure (after M18): nothing.** Per file
  the worker sent `log` then `ok`/`error`, both after `scan_file` returned; a
  time-out or death lost every finding and the buffered log lines.
- **Protocol now** (`engine/workers.py`, `engine/containers.py`,
  `engine/scanner.py`):
  - For the outer file only (depth 0), `scan_container` calls
    `scanner.member_listener`, which a worker sets:
    - `("container", kind, signal)` once the container is opened: the signal
      the container layer builds from the opened container (`handler.signals`),
      without a worst member;
    - `("member", kind, result)` for each direct member whose scan finished.
  - The worker sends them as `container` and `member` messages. A member is
    sent trimmed to what the parent uses (paths, verdict, score, status,
    hashes, contributions, the archive password flag).
  - `check_reply` validates them as M18 does: a known container kind, signal
    fields the signal class accepts and no `worst`; a member passes the result
    check, plus contributions (a list of at most 200 plain items with finite
    numeric points) and a finite risk score. An invalid one fails the file as
    any invalid reply.
  - The parent keeps per file an `Evidence`: the container signals, the count
    of finished members and the ten highest-risk ones.
- **On a failure** (time-out, death, memory limit, a worker `error`):
  `failure_result(..., evidence=)` scores the evidence with the existing
  scorer (each container's signal with its worst finished member as
  `WorstMember`, as `scan_container` does) and keeps the higher of that and
  the failed-scan Medium. `scan_status` stays `failed`;
  `scan_results.scan_failed` (reason, code) is unchanged, so metrics and the
  H6 (a) notice are unchanged. The incomplete reason adds "; the findings made
  before the failure are kept (partial evidence: the container's own findings
  and N member(s) scanned)". `scan_results.partial_evidence` = `members_scanned`,
  `containers`, `indicators` (up to 20) and `members` (summaries with findings,
  with their container). No evidence, or evidence that scores 0, or a signal
  that breaks the scorer (logged): the result is exactly as before.
  `isolation_unavailable` ignores evidence.
- **Not kept:** findings of the outer file's other layers (its own YARA, PE,
  script analysis), and anything of a member that did not finish. Nothing is
  reconstructed.
- **Probes (real isolated workers, the stand-in scanner):**
  - the review's check 2 shape (`invoice.pdf.exe`, `readme.txt`, a hanging
    member) gives "Critical (failed scan)", 95, `archive_double_extension`
    and `archive_executable` (was Medium 25);
  - a malicious `.ps1` member, then a dead worker, gives Critical 100 with
    `archive_member:script_behaviour`;
  - clean members, then a hang, stays Medium 25 with no `partial_evidence`.
  - In-process: a mail (`.eml` with a `.ps1` attachment) and an HTML smuggling
    page report their container signals, and the evidence score equals the
    full scan's (Critical 100 and Low 15).
- **Alerts:** at the default High floor a retained Critical sends the verdict
  alert and the scan-failed notice; a failed scan without evidence sends the
  notice only (tested). Automatic quarantine acts on the verdict as for any
  result (rule unchanged; owner approved).
- **Tests:** `tests/test_failed_scan_evidence.py` (23). 21 failed before the
  change; the two that passed are the no-evidence checks, which must behave
  as before. They cover:
  - a time-out and a worker death in real isolated workers;
  - no evidence (the result is identical to the old failure result);
  - a completed container scan unchanged against an in-process scan;
  - alerts at the default floor, and text and JSON reports;
  - only the outer file's container and direct members are reported;
  - 5 malformed container reports and 8 malformed member reports;
  - a signal that breaks the scorer, the ten-member bound, and
    `isolation_unavailable`.
- **Docs.** README (isolation), THREAT_MODEL (worker bullet and the slow-file
  row), RUNBOOKS section 2, ARCHITECTURE (the hang row).
- **Checks.** Related suites (evidence, protocol, failed-scan notice,
  workers, limits, logs, isolation, partial evidence, folder monitor, scan
  status, outputs, alerts, metrics, regression corpus, scanner, archive
  formats, background reliability): 329 passed, 3 skipped, 1 deselected.
  ruff, mypy (68 files) and bandit (`-ll`) clean. pip-audit not run: no
  dependency changed.
- **Full safe run at `8978c68`:** 1,588 passed, 0 failed, 23 skipped, 4
  deselected, 13 warnings, but 1 "unclosed database": the new module-scoped
  fixture did not close its scanner's cache. Fixed in `eb04d82` (test only).
- **Full safe run at `eb04d82`** (clean worktree, the command of the
  `04f396e` run): **1,588 passed, 0 failed, 23 skipped, 4 deselected, 13
  warnings**, 340 s; 0 "unclosed database"; `test_smoke.py`: "ALL SMOKE TESTS
  PASSED". Skipped and deselected tests are not counted as passed.
- Not verified here: Windows and Linux workers, the API under load (one
  message per direct member; up to 500 per archive by default), real
  samples, and automatic quarantine of a failed-scan file on a real host.

### Group 31: test warnings and D20 (2026-11-12)

- **SAFE re-check.** The 2026-11-11 reconciliation still holds: no confirmed
  SAFE code finding is open. D20 (THREAT_MODEL: a compromised worker forges
  only its own file's result) is now true and stated, with the M18 bullet
  added in group 29; D11 still waits on M23.
- **The 13 warnings at `eb04d82`:** 12 came from our tests, 1 from a third
  party.
  - Fixed in `b11590c` (tests only):
    - `test_cloud.py` `https_s3`: the TLS stand-in server was shut down but
      its listening socket was never closed (3 warnings);
    - `test_containment.py` and `test_alerts.py`: the stdout pipes of the
      helper processes were left open (3);
    - `test_archive_formats.py`, `test_embedded_content.py`,
      `test_evaluation_tools.py`: `open(...).read()` without a close (6).
  - Third party, left as is: `StarletteDeprecationWarning` from
    `fastapi/testclient.py` ("Using `httpx` with `starlette.testclient` is
    deprecated; install `httpx2` instead"). It comes from FastAPI's test
    client import; changing it is a dependency change (owner).
  - No warning came from product code.
- **Full safe run at `b11590c`** (clean worktree, the command of the
  `04f396e` run): **1,588 passed, 0 failed, 23 skipped, 4 deselected, 1
  warning** (the Starlette one), 327 s; 0 "unclosed database";
  `test_smoke.py`: "ALL SMOKE TESTS PASSED". ruff clean.

### Group 32: M31, M23, L-E12 and the partial-status items (owner-approved 2026-11-12)

Each item: current behaviour confirmed by a test that failed first, the
smallest fix, focused tests on benign synthetic files, ruff and mypy.

- **M31** (`c825986`, `detectors/relationship_scanner.py`). Each `.rels`
  part is parsed on its own; a part that cannot be parsed is named in the
  result's `error` (partial) and `detail`, and the other parts' findings are
  kept, as M13 (b). Check 23: High 70 complete; with the broken part High 70
  partial (was Clean 0 partial). Tests: 2 (both failed before);
  relationship, partial-evidence and scan-status tests 66 passed.
- **M23 and D11** (`eccdde4`, `detectors/pe_analysis.py`). The security
  directory counts as a signature only when it sits after the sections, ends
  the file and starts with a plausible WIN_CERTIFICATE header (length,
  revision 1.0 or 2.0, type 1 to 4, DER sequence byte); its bytes are searched
  for a program either way. Check 4: `make_pe(cert=make_pe())` keeps
  `pe_overlay_executable` (Medium 25, was Clean 0); a well-formed stub keeps
  the signed result (Clean, no overlay, unsigned-imports check off). Three
  existing tests used a zeroed fake header for "signed"; they use a
  well-formed stub now. README states what presence changes (D11). Tests: 7
  new (6 failed before); PE and regression-corpus tests 75 passed.
- **L-E12** (`9b0af65`, `detectors/file_integrity.py`). `RANSOM_NOTE_RE` is
  checked from the old pattern's parts in linear time, keeping
  `.search(name)` for its callers. The old pattern is the reference in
  `tests/test_ransom_note_name_linear.py`: 41 known names and 40,000 random
  names built from its words match the same (including Unicode case folding,
  Kelvin sign and long s, and `$` before a final newline); 80 KB names run
  under 0.2 s (was 2.2 s). The regex guard's L-E12 exemption is removed, so
  the new parts are guarded. Detection unchanged.
- **L-D2** (`dda5936`, `detectors/macos_packages.py`,
  `detectors/container_extractor.py`). `bounded_decompress` checks the
  decompressor's `eof` and raises `Truncated` (a `FormatError`) carrying the
  partial output; a pbzx stream keeps the chunks before a cut one;
  `read_cpio` raises `FormatError` at the end when there is no `TRAILER!!!`,
  after yielding the entries before it. A package entry or Scripts/Payload
  stream cut short keeps the files read (scanned as usual) and adds a
  `<name> (cut short)` member, so the scan is partial ("not unpacked: cut
  short: N file(s) read before the cut"). Before, a cut payload lost every
  file already read, and a payload without a trailer read complete. A file
  past the cut loses its findings (as it must). Tests: 9 (all failed
  before); macOS package, archive and scan-status tests 116 passed.
- **L-D5** (`a8b1e03`). Emulation results carry `status` `timeout` or
  `error` (no results, over 2 MB), which the completeness check already reads
  as partial. The QR layer names what its limits leave out in
  `qr_codes.not_checked` (image over the byte or pixel limit, images over the
  image limit, PDF pages over the page limit, unreadable page images) and an
  `error` when a real PDF's images cannot be read; `qr_codes` is recorded
  then even with no image decoded and joins `_ANALYSIS_RESULTS`. A program
  merely named `.pdf` stays complete (A2: the QR layer skips content without
  a `%PDF` header; first found by two scan-status tests failing). Tests: 7
  (all failed before).
- **L-D8** (`3fd0164`, `detectors/prompt_guard.py`). A cell left unread past
  200,000 and PDF pages over 50 are named in `prompt_guard.not_checked`
  (with oversized XML parts), which already makes the scan partial. Limits
  unchanged. Tests: 3 (all failed before, with lowered limits); hidden
  content tests 94 passed.
- **L-C7** (`7e5f4a6`, `core/mailbox.py`). A message cut at `IMAP_MAX_MB`
  (no `RFC822.SIZE` answer) is scanned as before, but its result is partial
  with a `mailbox` reason, `mailbox.truncated` is set and the verdict label
  shows the partial scan; findings in the part read are kept. The whole
  message is still read into memory before the cut (imaplib); not changed.
  Test: 1 (failed before); mailbox and scan-status tests 34 passed.
- **No change** to scores, weights, thresholds or verdict rules: M23 and M31
  recover findings that were dropped, as approved; the other items change
  `scan_status` only.
- **Full safe run at `7e5f4a6`** (clean worktree, the command of the
  `04f396e` run, plus `-rs` for skip reasons): **1,620 passed, 0 failed, 23
  skipped, 4 deselected, 1 warning**, 326 s; 0 "unclosed database";
  `test_smoke.py`: "ALL SMOKE TESTS PASSED". Skipped and deselected tests are
  not counted as passed.
  - Skipped (23):
    - 7-Zip not installed: 12 (DMG streaming 8, macOS packages 4);
    - no RAR tool that decrypts: 3;
    - GUI opt-in (no display): 1;
    - Windows only (Restart Manager, real Job Object): 2;
    - Linux only (`/proc`): 1;
    - libproc check: 1;
    - no system ELF binary: 1;
    - box-js not installed: 1;
    - OpenCV not installed: 1.
  - Deselected (4): the runaway-memory test and the three intel socket
    tests.
  - Warning (1): the Starlette `httpx` deprecation (third party).
- Not verified here: real Office, PE, package and mailbox samples; 7-Zip,
  box-js and OpenCV paths (skipped); Windows and Linux.

### Group 33: M19, L-L1, L-A2 and the release pip upgrade (owner-approved 2026-11-12)

- **M19** (`c074243`, `detectors/mail_analyzer.py`). With several `href`
  attributes in one `<a>` tag, `_anchors` used the last one that formed a
  complete link (the original greedy pattern); HTML keeps the first, so a
  harmless second `href` hid a deceptive first one. It now takes the first
  that forms a complete link (the pattern with a lazy `[^>]*?`), still linear
  (the H2 hostile-input tests pass). The equivalence tests use that reference.
  The general token soup was not sensitive to the change (it passed before
  too); a new random test built from link parts (most tags with several
  hrefs) and the review's example fail before and pass after (14 passed).
- **L-L1** (`7b40b9e`, `detectors/llm_backends.py`). An empty reply, prose or
  JSON that is not an object now carries `error`, which the completeness
  check reports as a partial LLM gap; the verdict is unchanged (no opinion),
  errors are not cached (only `analyzed` results are), and the intel service
  passes the field through. Tests: 6 (5 failed before); prompt-guard,
  coverage, scan-status, intel and GUI integration tests 111 passed.
- **L-A2** (`a23cc2c`, `deploy/backup.sh`). `umask 077` at the top. Test with
  a stand-in `docker` under `umask 022`: the backup and volumes folders 700,
  `BACKUP_INFO` and `config.tar.gz` 600 (were 755, 755, 644, and the config
  archive readable until its chmod). The volume archives written inside the
  container land in the 0700 volumes folder. ShellCheck is not installed
  here (not run); `bash -n` passes. Deploy tests 31 passed.
- **Release pip upgrade** (`109df77`, `.github/workflows/release.yml`). The
  unhashed `python -m pip install --upgrade pip` is removed from the build
  job; setup-python's pip installs the locks with `--require-hashes`. The I-B2
  test allows no exception now (it failed before the edit). `quality.yml` and
  `tests.yml` still upgrade pip (not part of the approval).
- ruff, mypy (68 files) and bandit (`-ll`) clean.
- **Full safe run at `109df77`** (clean worktree, the documented command with
  `-rs`): **1,629 passed, 0 failed, 23 skipped, 4 deselected, 1 warning**,
  327 s; 0 "unclosed database"; `test_smoke.py`: "ALL SMOKE TESTS PASSED".
  The 23 skips are those of group 32 (7-Zip 12, RAR 3, Windows 2, Linux 1,
  libproc 1, ELF 1, box-js 1, OpenCV 1, GUI 1); the warning is Starlette's
  `httpx` deprecation (third party). Skipped and deselected tests are not
  counted as passed.
- **Needs a real platform:** the release job on a tag (the build with
  setup-python's pip; CI has not run since `3e5a3f2`); `backup.sh` against a
  Docker deployment (real volumes, the container's archives); the LLM layer
  with a real model that answers in prose; real phishing mail with duplicate
  `href` attributes.

### Group 34: rows 1, 2, 4, 7, 9, 11, 13, 15 and 17 of the decision table (owner-approved 2026-11-12)

The owner approved nine rows of the ranked owner-decision table; every other
owner and deferred item is unchanged (M24, M29, M32, S-Y1 to S-Y4, the M26
wait cap / I-6, I-2, I-4, M4, M15 packaging, `httpx2`, D26, exit code 2, the
IMAP fetch retry).

- **H-04+** (`804b96b`, `detectors/web_content.py`). Measured first: the
  data: download link and the meta refresh were cubic (2,000 to 4,000
  characters: 8 times slower), the `<a … download`, `<x … on…=`, `<input`,
  `<form` checks and `visible_text` quadratic, and `_JS_CONCAT` quadratic in
  the white space after `+` (8,000 newlines 0.45 s). A match cannot cross a
  `>`, and a later tag start before the same `>` sees a suffix of the first
  one's text, so the helpers check the first start per tag (`_tags`), and the
  greedy `[^>]+` choices (last `action=`, last `url=` with a refresh before
  it) are found from the right. `visible_text` reuses the H2 mail helpers
  (same patterns). `_JS_CONCAT` drops `(?:\r?\n\s*)?`, which `\s*` already
  covers. The old patterns are the reference in
  `tests/test_web_content_linear.py`: known pages, 30,000 random pages from
  tag parts (each check matches hundreds to thousands of times) and 20,000
  random `_JS_CONCAT` inputs give identical results; two wrong variants (form
  takes the first action, meta without the refresh check) are caught. 200 KB
  of each crafted shape runs in under 2 s; `visible_text` on 128 KB of `<`
  went from 7 s to 0.002 s (2 MiB: 0.04 s). The regex guard no longer skips
  the three web-content patterns. Related tests 83 passed.
- **M30** (`2282119`). The integrity layer records a right-to-left override
  in a top-level file's own name (`file_integrity.rtlo_name`, shown with
  `[RTLO]`); new indicator `file_rtlo_spoof`, weight `W_FILE_RTLO` 60 (the
  archive member's). Members stay scored once, by their container. Check 22:
  the stub that scored Clean 0 is High 60; the ZIP is Critical 95 as before.
  `tests/test_top_level_rtlo_name.py` (1 of 3 fails before); registry,
  calibration, regression corpus, signals and integration 122 passed.
- **M25** (`cabf3db`, alert only). `CanaryManager` keeps a second copy of the
  registry in the reports folder (`.canary_registry_copy.json`) and the last
  good list in memory. A registry that is missing or unreadable while either
  still lists canaries gives a `registry` finding, and the known canaries are
  still checked. That finding writes the alert file, notifies and queues the
  outbox alert (`canary_registry`), but `respond()` is not called for it; a
  real trip beside it still responds. **First installation vs tampering:** a
  new installation has no registry, no copy and nothing in memory, so it
  still reads "No canaries deployed"; `remove()` empties both copies, so a
  removal is not a loss. Limit: if both copies are gone before a process
  starts, the loss looks like a new installation (README). A registry that is
  not a `{"canaries": [...]}` object now counts as unreadable.
  `tests/test_canary_registry_loss.py` (8; all fail before); canary,
  containment, alert, background and GUI suites 136 passed, 2 skipped.
- **M27 empty-key rule** (`c0b33e3`). With `RULEPACK_PUBLIC_KEYS` empty, a
  pack that records its signer is not used: `rulepack_no_key` warning, the
  bundled rules instead, `provenance.rules` no longer names the pack. Nothing
  is deleted; setting the key again puts it back. Packs from before 4.7 (no
  signer) stay in use. **Deployment impact** (docs/RULE_PACKS.md "No key
  configured", RUNBOOKS, THREAT_MODEL): an installation that used a pack but
  has no key configured (a Docker `.env` without the variable, a desktop
  whose key was set only in an old shell) scans with the bundled rules until
  the key is set. Four existing tests read the active pack without a key and
  one scanner test had no key: they now pass the key (that is the change).
  Check 13 is a test; rule-pack, deployment and provenance tests 84 passed.
- **I-1** (`d95e5e5`). Added to `SUPPORTED_EXTENSIONS` (so to the default
  folder-scan, monitor and GUI list), exactly these eight macro-capable
  types: **`.dot`, `.xlsb`, `.xltm`, `.xlam`, `.xlm`, `.potm`, `.ppam`,
  `.ppsm`**. All are in the macro layer's set. A `FILE_EXTENSIONS` the user
  set (or saved from the GUI) is kept as it is (README). The other twelve
  types of check 12 are not added. Test fails before; settings, corpus,
  pipeline, evaluation, GUI, monitor, PE and archive suites 169 passed.
- **I-3** (`4c68756`). `.github/workflows/dependency-audit.yml`: the same
  pip-audit over the four locks daily (05:17 UTC) and on demand; on a failed
  scheduled run a second job (`issues: write` only there) opens an issue or
  comments on the open one. A test keeps the audit step identical to
  `quality.yml`. **Not done: Dependabot for the locks.** They are hash-pinned
  `uv pip compile` outputs named `*.lock`; Dependabot's pip support reads
  requirements `.txt`/`.in`/`pyproject.toml` and its uv support `uv.lock`,
  so it would not regenerate them (a pyproject entry would propose range
  bumps that leave the locks stale). actionlint is not installed here.
- **L-B2 lock choice** (`30e09c4`). DEPLOYMENT.md's non-Docker install uses
  `requirements-server.lock` with `--require-hashes` on Python 3.12 (it had
  the desktop lock, with the GUI toolkit, and no hash check); the server lock
  holds every base and `[api]` dependency (checked). A test keeps the command.
- **I-T1** (`cf82df4`, tests only). An autouse fixture in
  `tests/test_evaluation_tools.py` restores `logging.disable`. The leak was
  still there but hidden by order: only the file's last test reset it. With
  that test deselected, the review's probe failed ("left at level 50") before
  and passes after.
- **D22, D23** (`dbd4e76`, docs). RELEASE_SCOPE: JSON Lines and signed
  webhooks and the quarantine vault are "No (desktop and CLI only)" for the
  Docker edition, a row for the e-mail alerts it does send, and "quarantine
  management" removed from the container CLI row; ARCHITECTURE and
  `.env.example` say the same. The product is unchanged.
- ruff (tracked files), mypy (68 files) and bandit (`-ll`) clean. No bidi
  characters in any staged diff.
- **Full safe run at `dbd4e76`** (clean worktree, the documented command):
  **1,650 passed, 0 failed, 23 skipped, 4 deselected, 1 warning**, 324 s;
  `test_smoke.py`: "ALL SMOKE TESTS PASSED". Skips as before (7-Zip 12, RAR 3,
  Windows 2, Linux 1, libproc 1, ELF 1, box-js 1, OpenCV 1, GUI 1); the
  warning is Starlette's `httpx` deprecation (third party). Skipped and
  deselected tests are not counted as passed.
- **Needs a real platform:** M25 with a running background service and the
  GUI (the copy and memory across restarts, real notifications); M27 in
  Docker (the `.env` key reaching `analysis` and `content`, a signed pack
  installed and dropped); I-3 on GitHub (the schedule, `gh` with the
  workflow token, the issue); L-B2 on a clean Linux server with Python 3.12;
  I-1 and M30 on Windows (names with U+202E, GUI checkboxes); M30's name in
  the GUI table on a display; H-04+ against real phishing and smuggling
  pages; D22/D23 against a running Docker edition.

### Group 35: M24, M29 (script part) and the lock-refresh tool (owner-approved 2026-11-12)

Start: HEAD `cc9161f`, tree clean apart from `.arena/`; none of the three
existed. Each test failed before its fix and passes after.

- **M24** (`72d6fcb`). New `windows_name()` in `container_extractor` (drops
  trailing dots and spaces, as the Windows file API does), used for member
  classification, the extracted file's name and the over-the-limit priority
  order; mail attachments, `is_script` and the script language, and the API
  upload extension (`upload_extension()`) use the same rule. Reports keep the
  name as received. Each member and attachment keeps its own numbered folder,
  so `a.exe`, `a.exe.` and `a.exe ` never overwrite each other (tested with
  three members and two attachments). The `.venv` runs Python 3.14, where
  `Path("a.js.").suffix` is `"."` (older: `""`); stripping first covers both.
  Python's e-mail parser already drops trailing spaces from attachment names,
  so only the dot reaches the mail code. Test: `tests/test_trailing_dot_names.py`
  (24; before the fix 13 failed). A scan of a ZIP holding `invoice.pdf.exe.`
  now scores as one holding `invoice.pdf.exe`.
- **M29, script part** (`b34181b`). `Ransomware_Shadow_Copy_Deletion`: the
  `Get-WmiObject`/`Get-CimInstance` `Win32_ShadowCopy` strings now count only
  with `.Delete(`, `Remove-WmiObject` or `Remove-CimInstance`, and `vssadmin
  resize shadowstorage` only with `maxsize=` on the same line (within 200
  characters). `vssadmin delete shadows`, `wmic shadowcopy delete` and both
  `wbadmin` strings are unchanged; the web-page case (prose quoting `vssadmin
  delete shadows`) still matches, as approved; no other rule changed. Test:
  `tests/test_shadow_copy_rule_scripts.py` (34; ASCII and UTF-16; before the
  fix 9 failed): the check 21 listing script is no longer High or Critical, a
  deleting script stays Critical. README rule list notes it. An installed
  signed rule pack keeps the old rule until a new pack is signed. Not measured
  on a benign corpus.
- **Lock refresh, option A** (`42852d3`). `tools/refresh_locks.py` (Python,
  so the test can read its command table): runs each lock header's `uv pip
  compile` command in dependency order into an output folder (a new temporary
  one by default; the repository is refused), keeps the headers, rewrites
  uv's scratch constraint path in the `# via` notes back to
  `requirements.lock`, audits each with `pip-audit --require-hashes
  --disable-pip`, prints changed pins. No install, commit or PR. Test:
  `tests/test_refresh_locks.py` (9): commands equal the four headers, a run
  with stand-ins writes only the output folder, forbidden commands absent.
  Real run without upgrades (network to PyPI and the advisory service): exit
  0, all four locks regenerated **byte-identical** to the tracked ones, "No
  known vulnerabilities found" for each; tracked lock checksums unchanged. A
  first run printed uv's output and showed path-only differences in the
  server and build `# via` notes; both fixed before the commit. README notes
  the tool. Option B (a workflow that opens a PR) was not taken.
- ruff (tracked files), mypy (68 files), bandit (CI scope, `-ll`) clean. No
  bidi characters in any staged diff.
- **Full safe run at `42852d3`** (clean worktree, the documented command with
  the four deselects): **1,717 passed, 0 failed, 23 skipped, 4 deselected,
  1 warning**, 318 s; `test_smoke.py`: "ALL SMOKE TESTS PASSED". Skips as
  before (7-Zip 12, RAR 3, Windows 2, Linux 1, libproc 1, ELF 1, box-js 1,
  OpenCV 1, GUI 1); the warning is Starlette's `httpx` deprecation (third
  party). A first launch was stopped: its deselect list was built by a grep
  that matched nothing; it was rerun with the four names written out.
- **Needs a real platform:** M24 on Windows (what mail clients and archive
  tools save for a trailing dot or space); M29 on a benign corpus and against
  real droppers; the lock tool on a machine other than this Mac (only this
  run, uv 0.13.7, pip-audit 2.10.1).

### Group 36: I-2 and the M26 wait cap (owner-approved 2026-11-12, choices 2026-11-13)

Start: HEAD `7a1d0b3`, tree clean apart from `.arena/`; neither existed. The
reporting of members left out by the budget already existed (`_budget_gaps`:
"N member(s) over the scan budget: listed, not scanned", scan `partial`).

- **I-2** (`e3f1cd3`). `scan_container` lists the members, and only when there
  are more than the budget asks the handler for its order
  (`ContainerHandler.first`, default unchanged). `ArchiveHandler.first` puts
  members named as programs, scripts or containers, with RTLO, or recognised
  as programs by their first bytes (`member.executable`) ahead, by the
  extractor's `_priority_name`; the sort is stable. Under the budget, and for
  mail, web and embedded containers, the order is unchanged. The limit (25)
  is unchanged. A nested archive is expanded by the extractor and never an
  item itself, so its harmless members keep their archive position (pinned).
  Test: `tests/test_archive_member_priority.py` (5; before the fix 3 failed):
  a `.ps1` at position 31 is scanned and the archive is Critical, partial,
  "6 member(s) over the scan budget"; a renamed PE at 28 goes first; archive
  order inside the risky group; plain and small archives unchanged. README
  notes the order. Related suites: 375 passed, 5 skipped.
- **M26 wait cap** (`bd9514e`). Owner choices (asked before the change):
  sandbox only (VirusTotal upload wait and LLM unchanged), margin 10 % of the
  scan limit with at least 1 s, and no submission when no time is left. Made
  here, stated to the owner: "no time left" = less than one poll interval
  (15 s) after the margin.
  - `engine/workers._serve` records `scan_deadline` = receipt +
    `scan_timeout_seconds` (every caller passes that setting; the parent's
    clock starts a few ms earlier, inside the margin); `time_left()` on the
    scanner. Outside a worker it is None and nothing changes.
  - `engine/layers._sandbox_deadline` gives the layer an absolute deadline;
    `CapeClient.analyze` and `IntelSandbox.analyze` take an optional
    `deadline` that ends the wait and also bounds request timeouts (at least
    1 s) and the pause between polls. A cut wait says "(cut short by the scan
    time limit)". Without a deadline both behave as before (tested).
  - The start-up check (group 11) keeps its warning / production error; only
    its text changed (the wait is cut short, slower reports are never used).
    README and DEPLOYMENT updated.
  - Test: `tests/test_external_deadline.py` (8; before the fix 7 failed, the
    unchanged-client case passed). Check 8 as a test: a real isolated worker,
    6 s limit, a loopback CAPE stand-in that never finishes, the stand-in
    scanner polling every 0.5 s: before, `failed`, "timed out after 6s";
    after, `partial`, Critical with the static score, sandbox `timeout` "cut
    short", no `scan_failed`, and one webhook alert of kind `verdict`.
    No-time-left: nothing posted, `timeout` "not submitted ...", `partial`.
  - Related suites: 303 passed, 8 skipped; with config validation 213 passed.
- ruff (tracked files), mypy (68 files), bandit (CI scope, `-ll`) clean. No
  bidi characters in any staged diff.
- **Full safe run at `bd9514e`** (clean worktree, the documented command with
  the four deselects written out): **1,730 passed, 0 failed, 23 skipped,
  4 deselected, 1 warning**, 325 s; `test_smoke.py`: "ALL SMOKE TESTS
  PASSED". Skips as before (7-Zip 12, RAR 3, Windows 2, Linux 1, libproc 1,
  ELF 1, box-js 1, OpenCV 1, GUI 1); the warning is Starlette's `httpx`
  deprecation (third party).
- **Needs a real platform:** M26 against a real CAPE server (submission and
  report times, the 15 s poll) and in Docker (the `analysis` worker polling
  `intel`; `intel`'s own wait); I-2 score shifts on real large archives.

### Checkpoint after group 36 (2026-11-13, owner restart)

- State: branch `review/production-hardening`, local only, never pushed. M26
  code is in `bd9514e`; HEAD (`f732247` before this note) differs from it only
  in this file. `git stash list` is empty: the stash used to show the M26
  tests failing without the fix (7 of 8) was popped and every change was
  restored. Tree clean apart from the untracked `.arena/` (preserved).
- M26 evidence, all on the current code (`bd9514e` and later); the earlier
  1,717-pass run at `42852d3` predates M26 and does not validate it:
  - `tests/test_external_deadline.py` rerun at the checkpoint: 8 passed
    (`test_a_worker_knows_its_remaining_time`,
    `test_cape_stops_at_the_deadline`,
    `test_cape_without_a_deadline_is_unchanged`,
    `test_the_intel_sandbox_stops_at_the_deadline`,
    `test_the_layer_waits_only_the_time_left`,
    `test_no_time_left_means_the_file_is_not_sent`,
    `test_outside_a_worker_the_layer_is_unchanged`,
    `test_a_slow_report_keeps_the_static_verdict`).
  - Related suites before the commit: 303 passed, 8 skipped; with the
    config-validation tests 213 passed.
  - Full safe run at `bd9514e`: 1,730 passed, 0 failed, 23 skipped,
    4 deselected, 1 warning (Starlette `httpx`); smoke passed.
- Owner policy choices, as recorded in the owner's answers of 2026-11-13:
  sandbox only; margin 10 % of the scan limit, at least 1 s; **"Don't
  submit"** when the time left is insufficient. Recorded and implemented.
- **Pending owner confirmation (made by Claude, not chosen by the owner):**
  "insufficient" means less than one poll interval (15 s) left after the
  margin. Changing it is one comparison in `engine/layers._sandbox_deadline`.
- Not tested: a real CAPE server; the Docker path (`analysis` worker polling
  `intel`, and `intel`'s own wait); that `IntelSandbox`'s request timeouts
  are capped (only its clock is tested; `CapeClient`'s timeouts are); the
  real 15 s poll inside a worker (the worker test uses a 0.5 s stand-in poll);
  VirusTotal and LLM waits (out of scope, the rest of I-6).
- Exact next step: the owner confirms or changes the "less than one poll
  interval" threshold; then, on a Docker host, run `deploy/check-deployment.sh`
  and a scan against a stand-in or real CAPE through `intel`. No other item is
  in progress.

### Group 37: M26 provisional result (owner-approved 2026-11-13)

Start: HEAD `8060a5d`, tree clean apart from `.arena/`. Planning first (read
only, four rounds with the owner); the approved approach and its limits are
recorded here and in PROJECT_REVIEW 34.1.

- **Problem confirmed** (reading, then a test on the old code): the group 36 cap
  was enforced only between requests. Retries with back-off, `Retry-After`,
  one timeout for two requests, a request started after the deadline (1 s
  floor), a dripped answer, a slow name lookup, redirects and proxies could
  outlast the scan limit; the worker was then stopped and the file's findings
  lost. On `8060a5d` a CAPE stand-in whose status check never answers made all
  four files of a scan fail with "timed out after 5s".
- **Rejected:** a socket watcher. Registering the socket returned by urllib3's
  `_new_conn()` misses the name lookup and connect loop
  (`urllib3/util/connection.py:60-76`); `ssl.SSLSocket._create` detaches the raw
  socket before the handshake; proxies and redirects open further connections.
- **Repair** (`f6c0bab`):
  - `engine/staging.py`: `_assemble()` (score, completeness, provenance; no
    logging) is shared by `scan_file` and `provisional_result()`. In a worker
    with a sandbox (`_sandbox_last`), the sandbox runs after the other slow
    layers; elsewhere they still run together.
  - `engine/layers.py`: before the sandbox's network wait in a worker, the layer
    sends the provisional result (sandbox `timeout`, `submission:
    not_attempted`), then the submission state as it changes.
  - `engine/workers.py`: new message kinds `provisional` and `sandbox`, checked
    under the M18 limits (16 MiB, shapes, states, task id an int). The parent
    keeps the latest per file and uses them **only** when the file is overdue
    and the worker is otherwise alive (`sandbox_stopped_result`); an invalid
    message, a dead worker or the memory limit still fail the file as before.
    The result is passed to `on_result` once; building and sending the
    provisional result logs and delivers nothing (tested).
  - `core/sandbox.py`, `core/intel_client.py`, with a deadline only: a per-call
    session without retries (closed in `finally`), each request's timeout is
    the time left, no request with less than 1 s left, transient failures
    (no answer, 429, 5xx) count as pending, `Retry-After` only if it fits, a
    report that is not a JSON object or answers with an error is not a finished
    report (the M34 equivalent outside this path is recorded, not repaired:
    PROJECT_REVIEW 34.2).
  - Submission states (all scans): `not_attempted` (nothing sent: no time, no
    upload, or the connection never opened), `possible` (an upload started;
    arrival unknown), `refused` (CAPE answered without a task), `confirmed`
    (task id, kept). `transmission` is `none`, `possible` or `sent`.
    `provenance.shared` lists the file for `possible`, `refused` and
    `confirmed`; the uncertainty is labelled in `scan_results.sandbox`
    (`submission`, `transmission`, detail), not in `provenance.shared` (no
    schema change). **Change outside deadline scans:** a refused upload is now
    listed as sent (it was left out), and every sandbox result carries the two
    new keys.
  - README (`SANDBOX_WAIT_SECONDS` row), DEPLOYMENT (intel), THREAT_MODEL
    (worker messages); the start-up warning lost a stray "a".
- **Unchanged:** the 10 % margin (at least 1 s); the 15 s submission threshold
  (**still pending owner confirmation**); VirusTotal, the LLM, rules, the
  intel API, the result schema version.
- **What is bounded how:**
  - Cooperatively, inside the worker (best effort): the waits above. Observed
    on this Mac (Python 3.14.2): a dripped TLS handshake ended at its own
    timeout and the worker lived.
  - Strictly, by stopping the worker at the existing scan limit (plus the stop
    and replacement time): a slow name lookup, dripped answers, 30 slow
    redirects and a stalled proxy, each tested; the static verdict is kept.
  - Not bounded by either: nothing in the sandbox path after the provisional
    result is sent. Before it, VirusTotal and the LLM (out of scope) can still
    reach the limit, and then the file fails as before.
- **Timing impact:** the sandbox now starts after VirusTotal, the LLM, ML and
  emulation in a worker, so their time comes out of its wait; tested in process
  (14.5 s left after a 2.5 s VirusTotal delay: not sent) and in a worker (limit
  10 s, VirusTotal 6.3 s: not sent, `not_attempted`, nothing posted).
- **Tests:** `tests/test_sandbox_provisional.py` (41), stand-ins only (a raw
  loopback HTTP stand-in that answers, hangs, drips, redirects, acts as a proxy
  or a TLS endpoint; a Unix-socket intel stand-in; a probe scanner in
  `tests/worker_fakes.py`). On the old code, in a worktree at `8060a5d` with an
  import made tolerant in that copy only: 40 failed, 1 passed (a worker that
  dies in the sandbox wait, which must stay a failure). After: 41 passed
  (104 s). Covered: drip on upload and status, redirects, name lookup, proxy,
  TLS drip, worker replacement, repeated scans in one worker (same pid, thread
  and descriptor counts not growing, stand-in sees every connection closed),
  no late cache entry, invalid provisional and dead worker still failures, no
  hidden retries, `Retry-After` that fits and that does not, a report that
  hangs or errors, per-request timeouts, no request under 1 s, submission
  states and privacy listing, intel states and transient retries, intel over a
  real Unix socket, the message checks and the size limit.
- **Checks:** related suites (alerts, background, deploy, external deadline,
  failed-scan notice and evidence, folder monitor, intel, isolation, metrics,
  outputs and API, partial evidence, provenance, regression corpus, sandbox,
  scan status, scanner integration, sharing, worker limits, logs, protocol,
  workers, and the new file): 427 passed, 3 skipped, 4 deselected. ruff
  (tracked files), mypy (68 files), bandit (CI scope, `-ll`) clean. No bidi
  characters in the diff.
- **Full safe run at `f6c0bab`** (clean worktree, the documented command with
  the four deselects written out, `-rs`): **1,771 passed, 0 failed, 23
  skipped, 4 deselected, 1 warning**, 446 s (the new file adds about 104 s);
  0 "unclosed database"; `test_smoke.py`: "ALL SMOKE TESTS PASSED". Skips as
  before (7-Zip 12, RAR 3, Windows 2, Linux 1, libproc 1, ELF 1, box-js 1,
  OpenCV 1, GUI 1); the warning is Starlette's `httpx` deprecation (third
  party). The 1,730-pass run at `bd9514e` predates this repair and does not
  validate it.
- **Docs checks and a slip.** After the documentation edits, the tests that read
  the README and the docs passed (91 passed, 3 skipped). That file list came
  from a grep that also matched `tests/test_fuzz_parsers.py`, which the safe
  selection excludes; its in-process Hypothesis tests ran for about 12 s, with
  no failure. No Atheris campaign or memory test ran. The 12 example files it
  added to the existing, untracked local `.hypothesis/` folder were removed (300
  files remain, as before).
- **Not verified:** a real CAPE server; the Docker path (analysis worker,
  intel's own CAPE requests, which continue after the worker stops waiting);
  Linux and Windows (the worker stop, socket behaviour, `/dev/fd` counts);
  a dripped answer after a completed TLS handshake (needs a certificate);
  the cost of replacing a stopped worker under load. A worker stopped after
  its sandbox wait had already ended (only the final scoring left, inside the
  margin) would also get the provisional result, whose sandbox entry then
  says it did not answer; not observed, not tested.

### Groups 38 to 44: the final hardening pass (owner request, 2026-11-13)

Start: HEAD `170faf9`, tree clean apart from `.arena/`. Claude Code was the only
editing agent. Each group: the defect confirmed by a test that fails on the code
before it (run in a temporary worktree at the previous commit with only the new
test copied in), the smallest fix, focused suites, ruff and mypy, a local commit.
Test lists were built from explicit names and checked for excluded files before
running (a zsh variable is not split into words: `${=L}` was used).

- **Group 38, M34 and the M26 finalization gap** (`9ae8e64`). A CAPE report request
  that fails, or a body that is not a JSON object, is no longer a finished
  (empty, cached) report, on both the deadline and the plain path; an empty JSON
  object still is. Once the sandbox has answered, the worker sends a checked
  `settled` result; a worker stopped before its final reply keeps that outcome
  instead of "did not answer". Before: 7 of 9 new tests failed (the two that passed
  are the valid-empty-report and an initially non-discriminating test, rewritten to
  stall after the scan: then it failed before, `timeout`, and passes after,
  `reported`). Related suites: 211 passed, 4 deselected.
- **Group 39, M4** (`23c0565`). `/scan` parses its upload inside the route, after the
  token check and a free scan slot. ASGI-level test: without a valid token 0 of 33
  body chunks are read and nothing is spooled (before: 33 of 33); with it, all 33
  and one spool file. Missing file field 422, not a form 400; limits, lockout and
  results unchanged. API suites: 42 passed.
- **Group 40, M15** (`8bcbe10`). An explicit package list plus `aegis_sentinel_rules`
  mapped to `rules/`; `engine/config.py` uses `rules/` beside the code first, else
  the installed package; a missing rules folder is a warning. Check (script in the
  session scratchpad, not in the repository): `git archive` of the commit, `pip
  wheel --no-deps --no-build-isolation --no-index`, the wheel unpacked into a new
  `venv --without-pip`, dependencies reached through one `.pth` path to `.venv`
  site-packages (no `.pth` processing, so the old editable install there is not
  active), run with `python -I` outside the tree. Before (`23c0565`): no rules
  folder, 0 rules compiled, no YARA match on a probe script, provenance "bundled"
  with 0 files. After: 5 rule files compiled, `Ransomware_Shadow_Copy_Deletion`
  matched, provenance "bundled", 5 files. The wheel differs from the old one only
  by the five rule files. The placeholder `fuzzy_signatures.sample.json` is not
  shipped (it matches nothing). Tests: `tests/test_packaging.py`.
- **Group 41, I-6 VirusTotal part** (`873fc0a`). In a worker, the opt-in upload wait
  ends with the scan limit less the M26 margin; no upload when not one 15 s check
  fits (the hash only was sent); both read `status: timeout` (scan partial); the
  intel upload call's timeout is capped. Outside a worker unchanged. **Boundary
  recorded, not repaired:** the hash lookup (with urllib3 retries) and the LLM
  request are bounded only by their own timeouts; a stall past the limit still
  fails the file. A reliable bound needs the provisional result extended to the
  slow-layer stage with per-service transmission progress (register section 2).
  The old wait was a literal `time.sleep(15)` x 10, so no before-run was made.
- **Group 42, M29 prose and M32** (`724484d`). Documented examples:
  `tests/fp_examples.py` (7 harmless, 7 harmful, all inert). Before: the article,
  detection note and hardening page Critical 90; the advisory High 73; a helpdesk
  and a payroll notice High 65; the harmful seven High or Critical. After: every
  harmless example below High (the advisory Medium 40 from `Ransom_Note_Language`),
  every harmful one unchanged. Shadow-copy rule: in `.html`, `.htm`, `.xhtml`,
  `.txt`, `.md` the commands need an execution API. Extortion rule: also a wallet,
  `.onion`, a victim/personal ID or a send-the-payment instruction; `pay` as a word.
  Synthetic only; signed packs keep the old rules until re-signed. S-Y1 to S-Y4
  investigated, not changed: S-Y1 Medium 40, S-Y2 Critical 100 on a build-agent
  Defender exclusion (same command as the technique), S-Y4 not reproduced, S-Y3
  not checked (needs a shell-link file).
- **Group 43, scikit-learn version** (`15b6760`). Reproduced: a model pickled as
  0.24.2 loaded under 1.9.1 and was used. Now refused (rule engine, logged reason).
- **Group 44, L-D1 and L-E4** (`e68d50a`), and D26 (`db01796`, docs). XAR entry
  numbers must be whole and non-negative, and a range outside the file is refused
  before any read (a spy shows no read); `.docx` text through python-docx only for
  a main part declared at most 20 MiB, cut at 200,000 characters. Before: 7 of 8
  failed (the normal-document case passed, as it must). Small files only; no large
  allocation.
- **Investigated, not changed:** S-03 (not reproduced; the existing test `af8deda`),
  S-01 (risk reduced by `600d8bc`), L-E5 (confirmed by reading; Tesseract absent),
  L-E6 (confirmed by reading; Windows only).

### Groups 45 to 48: the remaining repairs (owner request, 2026-11-13)

Start: HEAD `a10700b`, tree clean apart from `.arena/`. Same method as groups 38
to 44 (each new test run on the previous commit in a temporary worktree first).

- **Group 45, I-6 VirusTotal lookup and LLM** (`489ace5`). The provisional result
  is extended to the slow-layer stage: before VirusTotal and the LLM run in a
  worker, a provisional result names them in `scan_results.stopped_layers` (at
  timeout), and an `external` message reports what each call is about to send
  (hash, file, text, destination); sends from the layers' threads share a lock;
  both kinds are checked like every worker message. On a stop at the scan limit
  the parent keeps that result: static verdict kept, the stalled layer timeout,
  possible transmission labelled in the entry and listed in `provenance.shared`.
  Cooperatively (worker only): the time left per call, the quota pause counted, no
  call under 1 s, the lookup without retries when the session is a real one.
  Before: 11 of 13 failed (stalls ended as "timed out after 4s"); the crash and
  outside-a-worker cases passed both times. Related suites 313 passed.
- **Group 46, L-E5** (`9572a10`). OCR budget (180 s, capped by the worker's time
  left), each poppler and tesseract call given the time left, a time-out recorded
  (scan partial). POSIX workers lead their own process group, noted when ready and
  killed when the parent stops the worker. Before: 7 of 7 failed; that run left two
  inert helpers orphaned (the defect), stopped by PID after checking command line
  and parent 1. Tested with inert Python helpers and OCR stand-ins; a bystander in
  another group and a child of the test process survive.
- **Group 47, L-E6** (`5984d05`). `_pid_alive_windows`: only
  `ERROR_INVALID_PARAMETER` means dead; tested with a stand-in kernel32 (Windows
  not run).
- **Group 48, S-Y1 to S-Y4** (`88b2db1`). `tests/sy_examples.py`: 7 harmless and 11
  harmful inert examples, shortcuts as real shell links. Before: Defender build
  scripts Critical 100, admin shortcuts and a backup pre-freeze High 65, the log
  reset Medium 40, a backup-tool string set High 65. Changed: S-Y2 (broad or
  user-writable exclusion paths, or a download), S-Y3 (`/c` with another script
  host), S-Y4 services (a process kill or an Office/security target). After: the
  five harmless cases Medium 40 (the script layer still notes the exclusion) or
  Clean; all harmful unchanged. Left as documented ambiguities: S-Y1 and the
  encryptor strings. Before: 6 of 20 new tests failed.

### Checkpoint at `db01796` (superseded by the final checkpoint below)

- **State.** Branch `review/production-hardening`, local only, **never pushed**; no
  PR, merge, tag, release, deployment or version change (4.8.0 throughout). Last
  implementation commit and last tested commit: `db01796` (the documents committed
  after it change no code). `git stash list` empty; the only untracked path is the
  unrelated `.arena/`, preserved. The local `.hypothesis/` folder (untracked,
  ignored) is unchanged.
- **Final safe run at `db01796`** (clean worktree, `env -i PATH=/usr/bin:/bin`,
  scratch `HOME` and `TMPDIR`, `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`):
  `.venv/bin/python -m pytest -p no:cacheprovider -q -rfE -rs --tb=short -W
  default::ResourceWarning -o faulthandler_timeout=300 --ignore=tests/test_fuzz_parsers.py
  --deselect tests/test_workers.py::test_memory_limit_stops_runaway_allocation
  --deselect tests/test_intel_service.py::test_scanner_uses_intel_over_the_socket
  --deselect tests/test_intel_service.py::test_wrong_token_and_unreachable_intel_are_reported
  --deselect tests/test_intel_service.py::test_probe_reports_health tests`.
  The selection was collected first: 1,845 of 1,849 items, none from the fuzz file
  or the memory test. Result: **1,823 passed, 0 failed, 23 skipped, 4 deselected,
  1 warning**, 447 s; 0 "unclosed database". Skips: 7-Zip 12, RAR decryption 3,
  Windows 2, Linux `/proc` 1, libproc 1, ELF binary 1, box-js 1, OpenCV 1, GUI 1.
  Warning: Starlette's `httpx` deprecation (third party). `test_smoke.py`: "ALL
  SMOKE TESTS PASSED".
- **Other checks at `db01796`:** ruff on the tracked Python files (not `.arena/`):
  clean. mypy: 68 files, no issues. bandit (CI scope, `-ll`): clean. The JSON schema
  and the regression corpus are covered by the suite (`test_scan_endpoint`,
  `test_regression_corpus.py`). Packaging: the group 40 wheel check on a clean
  export of `db01796` found and compiled the 5 bundled rule files. The committed
  diff `170faf9..db01796`: no secret patterns, no bidirectional characters, no
  local paths.
- **Not run:** pip-audit (no dependency changed in this pass), the coverage gate,
  CI, Docker, Windows, real services, the GUI on a display, the excluded tests.
- **Mistake in an earlier session, recorded in group 37:** one excluded file ran by
  accident; this pass checked every file list before running it.
- **Evidence limits:** macOS on Apple Silicon, Python 3.14.2, synthetic inputs and
  local stand-ins only. The 1,771-pass run at `f6c0bab` and the 1,730-pass run at
  `bd9514e` validate only their own code.
- **Paused.** No agent should continue without a new owner request.


### Final checkpoint (2026-11-13): paused for owner review

- **State.** Branch `review/production-hardening`, local only, **never pushed**; no
  PR, merge, tag, release, deployment or version change (4.8.0). Last code commit
  and last tested commit: `88b2db1`; the documentation commit after it changes no
  code. No stash, no extra worktree; the only untracked path is the unrelated
  `.arena/`, preserved; the local `.hypothesis/` folder is unchanged (300 files).
- **Final safe run at `88b2db1`**, clean worktree, the same command and environment
  as the `db01796` checkpoint below (the four deselects written out, the fuzz file
  ignored). The selection was collected first: 1,892 of 1,896 items, none from the
  fuzz file, the memory test or the three intel socket tests. Result: **1,870
  passed, 0 failed, 23 skipped, 4 deselected, 1 warning**, 489 s; 0 "unclosed
  database". Skips: 7-Zip 12, RAR decryption 3, Windows 2, Linux `/proc` 1, libproc
  1, ELF binary 1, box-js 1, OpenCV 1, GUI 1. Warning: Starlette's `httpx`
  deprecation (third party). `test_smoke.py`: "ALL SMOKE TESTS PASSED". No test
  helper process was left running afterwards.
- **Other checks at `88b2db1`:** ruff (tracked Python files, not `.arena/`) clean;
  mypy 68 files, no issues; bandit (CI scope, `-ll`) clean; the worker protocol and
  JSON schema checks, the regression corpus and the rule tests are in the suite;
  the wheel check (group 40 method) on a clean export: 5 rule files compiled, the
  probe matched, provenance "bundled". The diff `a10700b..88b2db1`: no secret
  patterns, no bidirectional characters, no local paths.
- **Not run:** pip-audit (no dependency changed), the coverage gate, CI, Docker,
  Windows, Linux, real CAPE, VirusTotal, an LLM, Tesseract or poppler, the GUI on a
  display, the excluded tests. The 1,823-pass run at `db01796` validates only that
  code.
- **Evidence limits:** macOS on Apple Silicon, Python 3.14.2, synthetic inputs and
  local stand-ins only. Detection on real malware is not measured.
- **Paused.** No agent should continue without a new owner request.


## Exact next action

None: the work is paused for owner review, and no agent should continue without a
new owner request. The owner decisions in
[FINDINGS_REGISTER](FINDINGS_REGISTER.md) section 6 come first (the pending M26
15 s submission threshold among them). The list that stood here before this
checkpoint is kept below as history; the register supersedes it.

### Superseded: the next-action list before the final pass


The review stage is closed; the next stage is implementation in the order of
PROJECT_REVIEW 33.6, which replaces 31.10 and 32.6. Owner decisions are listed
in 33.7 and must be obtained before the OWNER items:
- Done: H6 and M18 (groups 28 to 30); M23, M31, L-D5, L-C7, L-D8 (group 32);
  M19, L-L1 (group 33); H-04+, M30, M25, the M27 empty-key rule, I-1 (eight
  types), I-3 (without Dependabot), L-B2, I-T1, D22, D23 (group 34); M24,
  M29 (script part), the lock-refresh tool (group 35); I-2, the M26 wait cap
  (sandbox only) (group 36); the M26 provisional result (group 37)
- Still open, unchanged: the M26 15 s submission threshold (owner
  confirmation), M34 (recorded only), M24 on Windows (delivery), the M29 web-page case,
  M32 and S-Y1 to S-Y4 (benign corpus), the rest of I-6 (VirusTotal and LLM waits), I-2 for
  mail attachments (not asked), I-4 (after
  S-03), M4, M15 packaging, D26, `httpx2`; exit code 2 and the IMAP fetch
  retry were recommended to stay as they are

SAFE items, in order (done items are marked):
1. M21 and L-B7 (CI): done, group 1 (local commit after `05aae35`).
2. H5, M22 and I-5 (the time-out class): done, group 2 (the local commit
   after group 1).
   New: M33 (owner-approved, done in group 5) and L-E12 (see group 2).
3. M17: done, group 3. M18: waits for the owner's choice of direction.
4. the SAFE file-name items (M20, L-E9, I-T3): done, group 4.
5. Rank 7: M28 (with D38) and L-C6 done, groups 7 and 6. M33 (owner-approved)
   done, group 5.
6. Rank 9: L-T1, L-B3, I-T2, S-T1 and the 33.4 rule tests done (groups 8
   to 10). I-T1 stays deferred. The other 33.4 missing tests wait on owner
   items (M29, M32, S-Y1 to S-Y3, M30, M31, L-D8).
7. Rank 6 SAFE parts done (group 11): the M26 start-up check and the M27
   compose part. They still need a Docker host for the M27 signed-pack
   install in `deploy/check-deployment.sh`, I-B3, and a container run.
8. Rank 10 done (groups 12 to 16), except L-D7, which is held for the owner
   (inspection coverage, see group 14).
   New for the owner: the unhashed `pip install --upgrade pip` in the release
   build job (group 13).
9. Ranks 11, 12 and 14 done (groups 17 to 24), except the items below.
   - Owner decisions, unchanged: M18, L-E12, L-D2 (group 20) and the 33.7
     list. L-D7 is done: the read limit in group 25, the notice in group 26.
   - New questions from this work:
     - the unhashed `pip install --upgrade pip` in the release job (group 13);
     - exit code 2's three meanings (group 18);
     - retrying failed IMAP fetches (group 21).
   - Platform or VM only: L-D1, L-E4, L-E5, L-E6; the M27 signed-pack install
     and I-B3 in the deployment check (Docker host).
   - Not done: the scikit-learn version check (suspected only). The I-x cache
     purge and the unused `send_webhook` are done (group 27).
   - Docs left as they are: D10 and D14 (release state); D11, D20, D22, D23,
     D26 and D32 (owner).
10. What remains SAFE is ranks 13 and 15. They are owner or platform work by
    their class (deferred items; evidence on Windows, Docker, ARM64, a display,
    the release workflow, the VM). Nothing SAFE is left to do on this Mac.

Each item needs its regression test and the full gates afterwards (pytest,
ruff, mypy, bandit, pip-audit). Tests that pin current behaviour and must
change with their fix are listed in 33.4.

Commit state:
- Review documents, local commits: section 31 `6cde91e`, section 32
  `7e449cb`, section 33 `3ee787c`, `18635cc`, `c2de93e`, `632ef11`,
  `05aae35` (last review commit).
- Implementation commits are local and listed by `git log 05aae35..HEAD`; a
  commit cannot record its own ID. Anything shown by `git status` other than
  `.arena/` is uncommitted work in progress of the current group.
- Pushed: nothing on this branch, ever.
- The untracked `.arena/` folder is unrelated and preserved.

Still unverified (33.7 lists the platform checks):
- CI on this branch
- the Windows items: M2, M9, M20, M24, L-E6, toasts, containment, autostart
- Docker: M27 (signed pack and the empty-key fallback), I-B3, the deploy
  scripts, D22/D23 against the running edition
- GitHub: the daily dependency audit and its issue (I-3)
- Windows: M24 (what mail clients and archive tools save for a trailing dot)
- a benign corpus: the M29 rule change (only fixed test inputs were checked)
- a real CAPE server and Docker: the M26 cap (stand-ins only here)
- a running background service and GUI: the M25 registry copy and memory
- Linux ARM64, Windows ARM64 and macOS Intel
- the GUI on a display
- the VM items: 27.5, L-D1, L-E4, OOM-H, real-sample evaluation
- the release gate job (runs on a tag only)
- the benign corpus for M29, M32 and S-Y1 to S-Y4


## Codex reliability checkpoint (2026-11-14, supersedes earlier stop state)

Owner authorized the remaining I-6/M26, L-E5 and named S-Y detection repairs,
bounded policy/guard experiments, final local verification and Graphify mapping.
Codex is the sole editor. Read-only supporting agents stopped after reaching their
usage limit; none edits or continues. Technical brief and evidence:
[tasks/reliability-local-validation.md](tasks/reliability-local-validation.md).

Completed working implementation: coordinated completed-layer snapshots, strict
file identity/reset/JSON checks, memory-failure precedence, and bounded macOS
native-identity descendant cleanup. Focused reliability selection: 123 passed;
a later teardown refinement and final safe suite still need final validation.
Detection/budget batch is in the working tree and separately reviewed/tested.
Last full safe implementation remains `88b2db1` until the new full run completes.

Next: finish the local checkpoints, inspect/execute the safe selection with all
four historical deselections and fuzz-file exclusion, smoke/quality/packaging/GUI,
then Graphify static mapping outside the tree and final owner-review checkpoint.
No remote actions authorized; nothing pushed. Preserve `.arena/` and `.hypothesis/`.


### Detection and budget checkpoint

Reliability implementation checkpoint: `2004d79`. macOS helper refinement:
13 passed in 20.90 s; escaped-helper baseline test failed on `d8aec95` as
expected (12.79 s, teardown cleaned its inert children). Additional generation
unit tests are included in final validation. Ruff and mypy passed (69 files).

S-Y4 service-only coverage restored with the exact known maintenance false
positive documented; S-Y1/encryptor remain unresolved ambiguities. 121 detection
checks passed. The 144-case virtual-clock sandbox experiment leaves the 15 s
threshold unchanged; 9 experiment/resource-bound tests passed. Full final safe
validation is next; no remote action occurred.


## Final reliability checkpoint (2026-11-14, Claude Code)

Claude Code took over from Codex at the Graphify step (Codex reached its usage
limit and is stopped). One editing agent. No code changed in this step.

- **Branch:** `review/production-hardening`, local only. Last implementation
  commit: `72aa761`. This documentation commit follows it. Nothing is pushed: no
  PR, tag, release, deployment or version change.
- **Validation at `72aa761` (macOS, Apple Silicon, Python 3.14.2):**
  - Safe suite: 1,891 passed, 0 failed, 23 skipped, 4 deselected, 1 warning
    (third party), 577.55 s; coverage 92%.
  - `test_smoke.py` passed. GUI tests: 2 passed. Wheel check passed.
  - Ruff and mypy are clean (69 files); both were rerun at this checkpoint.
  - Details: [local validation](tasks/reliability-local-validation.md).
- **Graphify map:** static, code-only and local (no LLM, no network service, no
  installs). It was built from a `git archive` of tracked files and stored
  outside the repository. It is not committed. The architecture notes and five
  diagrams (flowchart, sequence, use case, class, activity) went to the owner
  locally.
- **Status by category** (the register is authoritative):
  - Fixed and verified locally: I-6 completed-finding retention, the macOS L-E5
    escaped helpers, restored S-Y4 service coverage, and every item in register
    section 1.
  - Awaiting platform validation: L-E5 on Linux and Windows, L-E6, Tesseract and
    poppler, real CAPE, VirusTotal and LLM, Docker, CI, and the GUI on a display
    (register section 5).
  - Unresolved with blockers: 27.5/B4 out-of-memory failures. These need a
    separately authorized VM run.
  - Unconfirmed suspicions: S-01, S-03, S-04, H-03/OOM-H.
  - Owner decisions: the M26 15 s threshold (retained), S-Y1 and the S-Y4
    tradeoffs, CI on this branch, exit code 2 and the IMAP retry, and Python 3.9.
  - Deferred: register section 4.
- **Uncommitted:** none from this task. The untracked `.arena/` folder is
  unrelated and is preserved.

## Architecture diagrams in the repository (2026-11-16, Claude Code)

Owner request: draw the finished architecture as four UML diagrams, review them
against the code, and keep them in the repository so a new session finds them.
Documentation only: no application code, test, CI, dependency or detection change.

- **Where:** `docs/architecture/`. `README.md` states the diagrams in text;
  `ARCHITECTURE_UML_DIAGRAMS.html` shows all four on one self-contained page;
  `uml-diagram-sources/` holds one definition (`d1` to `d4`) and one SVG per
  diagram, the drawing toolkit (`umlkit.py`) and `build_diagrams.py`.
- **Baseline:** the code at `72aa761` (`f825915` adds documentation only).
- **Graphify:** the stored code-only graph was rebuilt from a `git archive` of
  `f825915` with the network blocked and compared: the same 6,366 nodes, 15,577
  edges and 335 communities. On 2026-11-17 the owner asked for the interactive
  page in the project so it can be shared: it is now
  `docs/architecture/graphify-code-graph.html` (552 KB, all 253 Python files at
  `72aa761`, loads `vis-network` from unpkg). The raw `graph.json` and cache
  (about 18 MB) stay outside the repository.
- **Review of 2026-11-17 (before the owner shares the diagrams):** every claim in
  the four diagrams and the README was re-read against the code (class members
  per class, layer order, worker replies, time-out outcomes, defaults, intake
  routes and destinations). Two errors were found and fixed: "19 typed signals,
  one per layer" (the hash, allowlist and local-db layers have none) and the
  diagrams page saying the graph is not in the folder. In the Graphify page, 65
  of 335 community names paired a symbol with a file it is not in (for example
  `tests/test_elf · ElfAnalyzer`); each is now named after its main symbol's own
  file (`detectors/elf_analysis · ElfAnalyzer`). Nodes and links are unchanged
  (335 nodes, 1,811 aggregated links, checked by comparing the data).
- **Checked against the code:** inheritance and hubs from the graph; the pipeline
  order, the 12 worker reply kinds, the listener callbacks, the time-out outcomes
  of `_IsolatedScan._step`, every entry point and every output by reading
  `engine/`, `core/`, `api/`, `aegis_gui/` and `RansomwareScanner.py`. A second
  pass corrected three statements (the CLI reaches folder scans through
  `run_scan()`; an `error` reply keeps its worker; monitor results also reach the
  GUI) and added the caller classes and the layer-to-scanner dependency.
- **Checks run (macOS, Apple Silicon, Python 3.14.2):** `build_diagrams.py` (0
  layout problems); every label measured in headless Chrome (none wider than its
  box, none under 12 px) and all four diagrams looked at in screenshots of the
  page; `ruff check` on the tracked files and the new ones; the focused tests
  named in the commit message. Application tests were not rerun (no code change).
- **Not verified:** rendering in browsers other than Chrome; the page at widths
  under 1280 px beyond its horizontal scroll.
- **Pointers added:** `AGENTS.md`, `docs/PROJECT_MAP.md`, `docs/ARCHITECTURE.md`
  and the top of this file link to `docs/architecture/README.md`.

## Review of thirteen items (2026-11-17, Claude Code)

Owner request: validate thirteen items from an earlier discussion of the code,
findings and diagrams against the branch, repair confirmed defects with focused
tests, and prepare proposals, a VM plan and a verification matrix for the rest.
Sanitised brief, dispositions and proposals:
[tasks/review-items-2026-11-17.md](tasks/review-items-2026-11-17.md).

- **Branch:** `review/production-hardening`, local only; nothing pushed, no PR,
  tag, release or deployment. Start: `74b6aef`. Last implementation commit:
  `b6966f8`; diagrams `fde684c`; this documentation checkpoint follows.
- **Commits:** `f8af202` I-4 scheduler and S-03 lock; `6e1190c` M35 monitor
  outputs; `0acd78b` evaluation summary and procedure; `8686cd2` layer-order
  check; `43cd1d4` I-T4 test isolation; `b6966f8` D43 wording and GUI label;
  `fde684c` D44 deployment diagram and corrections.
- **Not changed (approval needed):** S-Y1/S-Y4 rules (proposals P1 to P3), the
  27.5/B4 VM investigation, any extraction from `RansomwareScanner` (assessed as
  not justified now).
- **Checks run here** (macOS 27.2.1 arm64, Python 3.14.2): see
  [VERIFICATION_MATRIX](VERIFICATION_MATRIX.md) section 3. Final safe suite at
  `fde684c`: 1,919 passed, 0 failed, 8 skipped, 4 deselected, 547 s;
  `test_smoke.py` passed; GUI tests 3 passed (headless). A first full run at `0acd78b` (zbar not reachable through
  SIP-protected `env`/`time`) gave 1,898 passed, 4 failed: three needed zbar and
  passed with it; one was I-T4, fixed in `43cd1d4`. Ruff, mypy (69 files) and the
  bandit gate are clean. 18 documentation-pinning test files: 262 passed, 1
  skipped. Diagrams: build check clean, 881 labels measured in headless Chrome,
  none wider than its box.
- **Environment note:** on this Mac zbar is in `/opt/homebrew/lib`; tests that
  need it pass only with `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`, and that
  variable is stripped by SIP-protected launchers (`/usr/bin/env`, `/usr/bin/time`).
- **Not run:** Docker (daemon not running), CI, Linux, Windows, real services,
  the GUI on a display, desktop packaging, real samples, fuzz campaigns, OOM work.
- **Uncommitted:** none from this task. `.arena/` is unrelated and preserved.

## Exact next action (superseded 2026-11-18)

Paused for owner review; see the Kubernetes section below for the current next
action.

## Optional Kubernetes deployment (2026-11-18)

- **Goal and brief:** an optional, single-instance Kubernetes deployment reusing
  the existing images; Docker Compose and the desktop/CLI unchanged. Brief and
  boundaries: [tasks/kubernetes-deployment-2026-11-18.md](tasks/kubernetes-deployment-2026-11-18.md).
  Guide: [KUBERNETES](KUBERNETES.md).
- **Agent:** Claude Code, the only editor. Branch `review/production-hardening`,
  local only, started at `b93f287`. Nothing pushed, merged, published or deployed;
  no cluster contacted, no kubectl context read or changed (only offline
  `kubectl kustomize`).
- **Decision:** one Pod (analysis + TLS proxy over the Unix socket in an
  emptyDir), default-deny NetworkPolicy with ingress TCP 8443 only and no egress,
  restricted Pod Security, isolation-gate init container and readiness probe,
  ReadWriteOncePod claims, content written only by a Job while analysis is scaled
  to zero. **No intel on Kubernetes:** external services and e-mail alerts are
  unavailable there until owner decision K8S-1 (proposal in the guide).
- **Commits:** `a139fa3` manifests, checker, gate, operator scripts, tests;
  `00c0639` guide and `/tmp` clearing at container start (an emptyDir outlives a
  container restart); `7ae85eb` diagram 6 and THREAT_MODEL section 14; `817d3b9`
  `prepare-state` (the runtime would create the nested content mount point in a
  new state claim as root 0755, so uid 10001 could not write its log; Docker seeds
  its volume from the image); then the commit with the fresh/existing-volume tests
  and these documents (last implementation commit before it: `817d3b9`).
- **No application code changed.** No detection, threshold, coverage or schema
  change.
- **Checks:** [VERIFICATION_MATRIX](VERIFICATION_MATRIX.md) section 4. Safe suite
  at `7ae85eb`: 1,960 passed, 0 failed (15 extra 7-Zip/RAR skips from a short
  PATH). Final revision `062262a`: 1,980 passed, 0 failed, 8 skipped, 4
  deselected; ruff, mypy, bandit clean; 61 Kubernetes tests pass.
- **Pending, not verified anywhere:** everything at run time on a cluster
  (admission, server-side schema, NetworkPolicy enforcement, `fsGroup` on real
  storage and Linux ownership of the folders `prepare-state` creates, probes,
  shutdown within 330 s, resources, `content-update.sh`, `verify-cluster.sh`);
  the image's `sh` and `find` (Docker not running).
- **Uncommitted:** none from this task. `.arena/` is unrelated and preserved.

## Repository audit (2026-11-18, Claude Code)

- Brief and findings RA-1 to RA-10: [tasks/repository-audit-2026-11-18.md](tasks/repository-audit-2026-11-18.md);
  register section 1 (RA-1 to RA-4) and section 4 (the optional items).
- Commits (local only): `f20de01` (Kubernetes tests portable to Windows: a
  Windows temp path compiled as Python source, `os.geteuid`, bash scripts
  without a Windows skip), `5d01232` (documents), then this record.
- No file removed or moved; no application code, detection, schema or isolation
  change. Coverage: tool checks across all code; full re-inspection of
  `deploy/kubernetes/`; the rest targeted (see the brief's coverage table).
- Checks at `5d01232`: safe suite 1,980 passed, 0 failed, 8 skipped, 4
  deselected (553 s); ruff, mypy, bandit clean (VERIFICATION_MATRIX section 4).
  Windows and CI not run. Kubernetes runtime validation still pending.
- Uncommitted: none. `.arena/` unrelated and preserved.

## Exact next action (current)

Owner decisions: K8S-1 (intel transport on Kubernetes) and whether to approve a
dedicated test cluster for `deploy/kubernetes/verify-cluster.sh --restart-test`
and a `content-update.sh` run with a test-signed pack; then the earlier decisions
in [FINDINGS_REGISTER](FINDINGS_REGISTER.md) section 6. No step runs without
approval.
