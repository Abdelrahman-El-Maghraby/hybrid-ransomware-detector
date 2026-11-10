# Current task handoff

- Status: production-engineering review and staged fixes; not ready for merge.
  Latest step: Claude's evidence-driven review of the hardening branch
  (findings report only, 2026-11-10), PROJECT_REVIEW section 29.
- Active agent: Claude (2026-11-10). The owner confirmed the previous Codex
  session was stopped; no concurrent changes were seen during the review.
  One editing agent.
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

## Exact next action

A separate fix session for the SAFE findings of section 29 (M17, M18, M20,
L-E8, L-G1, L-A4, L-B6, I-T2), each with the regression test listed in 29.11
and the full gates (pytest, ruff, mypy, bandit) afterwards. M19 and L-L1 wait
for an owner decision (29.14), as do the section 28 deferred items (M4, H-04,
low items, I-T1, M15 packaging). Nothing on this branch has been pushed; the
owner decides whether and where to push (CI on HEAD needs a push). Still
unverified: the release-gate step (tag only), the deploy scripts against real
Docker, Windows behaviour of the outbox lock (`msvcrt.locking`) and of the UTF-8
report fix, and every Windows/ARM64/Intel statement in 29.10.
