# Current task handoff

- Status: production-engineering review and staged fixes; not ready for merge.
- Active agent: Claude; Codex stopped (owner confirmed 2026-11-08). One editing agent.
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
  locally as the next commit after `3be37a2`; see 28.4.
- Waiting for the owner: H4 and M13 (would change `scan_status` to partial for
  the affected files; the M13 coordinate fix also restores lost findings), M4,
  H-04, the low items (including L-A2 `umask`), I-T1 and the packaging part of
  M15. Nothing of these has been started.

## Unresolved items carried forward

- Section 27.5 long-fuzz OOM failures (runs 40969502006, 40974246237): unresolved,
  restricted; do not execute the artifacts.
- Owner checks: Windows/macOS GUI, desktop monitoring, real SMTP/S3 providers.
- Production M1/X1, M2, O1, U1, X2, legal review, conditional D5, real-sample
  evaluation: pending and out of scope.

## Exact next action

Wait for the owner's decision on H4/M13 and the other items above. Nothing on
this branch has been pushed; the owner decides whether and where to push.
Unverified here: the release-gate step (runs only on a tag), the deploy scripts
against real Docker, Windows behaviour of the outbox lock (`msvcrt.locking`)
and of the UTF-8 report fix beyond the simulated cp1252 test.
