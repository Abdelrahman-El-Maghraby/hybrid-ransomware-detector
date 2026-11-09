# Current task handoff

- Status: production-engineering review and staged fixes; not ready for merge.
- Active agent: Codex; Claude's Arena session was stopped on 2026-11-09 at
  the owner's request. One editing agent.
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

## Exact next action

Continue the focused review of the five local production-hardening commits;
check any findings against the code and existing tests before changing files.
The deferred items remain gated by owner decisions. Nothing on this branch has
been pushed; the owner decides whether and where to push. Unverified here: the
release-gate step (runs only on a tag), the deploy
scripts against real Docker, Windows behaviour of the outbox lock
(`msvcrt.locking`) and of the UTF-8 report fix beyond the simulated cp1252 test.
