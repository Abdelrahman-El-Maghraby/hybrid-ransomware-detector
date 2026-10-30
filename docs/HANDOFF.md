# Current task handoff

- Status: active Stage 3 validation, unresolved resource-limit failures.
- Active agent: Codex; Claude stopped. One editing agent.
- Branch: `validation/v4.8-remaining`; base: `integration/v4.8`;
  draft PR [#46](https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector/pull/46).
  Not ready for merge. Never merge, force-push, tag or release.
- Brief: [tasks/project-review.md](tasks/project-review.md),
  [PROJECT_REVIEW](PROJECT_REVIEW.md) sections 24, 26, 27;
  [owner checklist](tasks/v4.8-owner-validation.md).
- Verified remote checkpoint: `b55c60e3c809f6a123257a0f504e27c2fd3b259e`,
  equal to local HEAD at start of restricted follow-up, with a clean tree.
- Last application fix: `673acdc`; initial fuzz tooling: `b2e8aea`.
- Integration baseline: `03089d5`, verified owner merge of #45, identical tree
  to `cd51cee`. PR #39 reverified open/draft at this tip; keep draft.
- Current uncommitted task files: HANDOFF, PROJECT_REVIEW and owner checklist,
  recording completed CI failures and the new investigation restrictions.
  No unrelated local changes. No OOM artifact downloaded or executed.

## Current authorisation boundary

Owner permits defensive static resource-handling review, documentation and small
benign regression checks. Do not execute the failing artifact, reproduce the
memory spike, raise the memory limit, disable checks or mark B4 passed. Do not
restart the same fuzz campaigns under this restriction, locally or in CI.
No secrets/private data or malware on the Mac. No detection-weight, threshold,
inspection-coverage or result-schema changes. No new resource fix without
supporting evidence and a small benign regression case.

## Completed and preserved

- Steps 1-12, checksum #44, and final evidence #45 are merged. Section 26 records
  I-1 to I-7, full-suite/CI evidence and the 29-run benchmark. Do not restart them
  without a relevant change or unresolved failure.
- #40 already records B4/B5/entropy/ML bounds review and 5,000-example Hypothesis
  run. Reconciled the PR evidence; did not restart that review.
- CPIO: Atheris found an uncaught ValueError in malformed numeric header fields.
  Scanner package handler already contains the error. Fix `673acdc` validates
  unsigned odc/newc fields and raises FormatError. All 36 regression cases failed
  before; 87 related package/streaming/fuzz tests passed afterward (4.78 s).
  ruff, mypy (67 files), repository bandit gate and diff check passed.
- Resource follow-up: inspected harness/workflow, parser allocation/cleanup
  boundaries, shared-buffer limits and worker policy. Fuzzing runs directly in
  the Atheris process, without application scan workers. Aggregate RSS cannot be
  attributed to a specific parser or harness component from current logs.
  No speculative resource fix or limit change made.
- Seven explicitly selected benign worker-limit tests passed, no skips, 4.77 s.
  Exact command and limits of mocked evidence are in report 27.5. No large
  allocations, no artifact replay, no new fuzz run in this follow-up.
- Owner checklist committed in `b55c60e`: GUI/monitoring, SMTP/S3 and production
  prerequisites. Scratch GUI visual attempt was inconclusive; no owner GUI pass.
  Existing hardcoded GUI version label "4.4 beta" recorded, not changed.

## Actual long-fuzz failures (all unresolved as long-run validation)

- Run 40969502006 / parser job 123782398098: exit 77 after 104 inputs, CPIO
  ValueError; regression fix above. Artifact crash-019c81091380d838741ab1e991c0e0226a79ed2e.
- Same run / B4 job 123782397665: exit 71, 13,639 inputs, peak RSS 4314 MB;
  oom-07598bbb032f9faaaeef08f618a35502df0699e3.
- Corrected-code run 40974246237 / B4 job 123798293969: exit 71, 2,500 inputs,
  peak RSS 4261 MB; oom-50152c60b007e96f0a4afdbe5ab0051325ceaadf.
- Same corrected run / parser job 123798293941: exit 71, 36,433 inputs,
  peak RSS 4628 MB; oom-fb07a247962bea213437824a4f5f5d8bc270a725.
- Threshold was 4096 MB in every run. None completed one hour. Artifacts remain
  under GitHub's 14-day retention. Do not execute them. No allocation traceback
  or per-target memory attribution exists in the inspected logs.

## Ordinary CI and remaining work

On `b55c60e`: tests 40974592287 has all six matrix jobs passed; quality 40974592282 all four passed; Docker 40974592263 passed.
Fuzz change gate 40974592278 passed; Atheris skipped for docs-only update.
The skip is not a fuzz pass and does not supersede the failure evidence.

1. Save/push this documentation checkpoint and verify the remote SHA.
2. Inspect final ordinary CI statuses; document actual outcomes, including skips.
3. Continue only non-reproducing static investigation or small benign tests with
   concrete hypotheses. Attribution needs additional non-executing evidence or
   a separately approved investigation plan; do not infer a culprit from RSS.
4. Keep #46/#39 draft. Owner must perform Windows/macOS GUI, real Windows/Linux
   desktop monitoring and real SMTP/S3 provider checks per the checklist.
5. Production M1/X1, M2, O1, U1, X2, legal review, conditional D5 and final-release
   deployment remain separate. No real-sample evaluation is authorised here.

Exact next action after this checkpoint: inspect ordinary CI and retain the
resource failures as unresolved. Do not start another long fuzz campaign.

Last verified push: `b55c60e` matched live origin. This documentation update is
not yet pushed; verify the new remote tip after the checkpoint push succeeds.
Keep this active handoff while the draft PR is incomplete; reset to integration's
idle content only as the final commit when the task is actually ready for owner
merge under AI_WORKFLOW.
