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
  The full safe selection follows in the next checkpoint.

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
- New tests fail on the code before the fix (worktree at `e334704`, with a
  pass-through `printable`): 4 of 4. After the fix: 155 tests across the
  touched files pass. ruff, mypy and bandit clean.

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
   New for the owner: M33 (needs approval) and L-E12 (see group 2).
3. M17: done, group 3. M18: waits for the owner's choice of direction.
4. the SAFE file-name items (M20, L-E9, I-T3): done, group 4.
5. Next SAFE work in 33.6 order: rank 7 (M28, L-C6), rank 9 (tests), rank 10
   onward. Rank 6 has SAFE parts (the M27 compose change and start-up check).

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
