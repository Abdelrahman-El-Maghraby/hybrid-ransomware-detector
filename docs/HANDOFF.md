# Current task handoff

- Status: production-engineering review and staged fixes; not ready for merge and
  not production ready. The review stage ended with PROJECT_REVIEW section 33
  and its ranked repair plan (33.6). Current stage: implementation of the SAFE
  items of 33.6, in small groups (see "Implementation of the SAFE items" below).
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

## Exact next action

The review stage is closed; the next stage is implementation in the order of
PROJECT_REVIEW 33.6, which replaces 31.10 and 32.6. Owner decisions are listed
in 33.7 and must be obtained before the OWNER items:
- H6 (a)/(b) and M18's direction
- M23, M24, M25, M30, M31
- L-D5, L-C7, L-D8
- the M26 wait cap and the M27 empty-key rule
- M29, M32 and S-Y1 to S-Y4
- M19 and L-L1
- the section 28 deferred items
- D22, D23 and D26
- I-1, I-2 and I-6

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
- Docker: M27, I-B3 and the deploy scripts
- Linux ARM64, Windows ARM64 and macOS Intel
- the GUI on a display
- the VM items: 27.5, L-D1, L-E4, OOM-H, real-sample evaluation
- the release gate job (runs on a tag only)
- the benign corpus for M29, M32 and S-Y1 to S-Y4
