# Current task handoff

- Status: active, awaiting owner review. **Local only**: nothing in this
  checkpoint is pushed; publication was not authorised in this session.
- Task: B4 investigation and repair, PR-M1, PR-S2, PR-Q1, PR-F1 and a review of
  the remaining areas. Brief: [tasks/b4-and-open-findings-2026-11-27.md](tasks/b4-and-open-findings-2026-11-27.md).
- Active agent: Claude (the previous agent is stopped).
- Branch: `review/remaining-issues-2026-11-27`, base `main`, PR #49 (open).
- Last verified remote commit: `6c42dc8` (PR #49 head; 11/11 checks green).
- Last implementation commit: `672730e`. Unpushed commits after `6c42dc8`:
  `63658a3`, `2a6f76c`, `5a9e3a5`, `7221c64`, `11144b8`, `64425f7`, `1e22a3f`,
  `672730e`, plus this documentation commit.
- Approval boundary: no push, PR update, merge, tag, release or workflow
  dispatch without the owner. Atheris campaigns, artifact replay and memory
  tests stay in the isolated VM (procedure: brief section 3).

## Checks

- Safe suite at `11144b8`: 2,332 passed, 0 failed, 8 skipped, 1 deselected
  and at `1c7a1f7` (all code of this pass): 2,337 passed, 0 failed, 8 skipped,
  1 deselected (VERIFICATION_MATRIX section 19).
- ruff (without `.arena/`), mypy, bandit: clean at `672730e`.
- Not run: fuzz suite and runaway-allocation test (by rule), Windows/Linux (CI
  after upload), real external services, a cluster.

## Pending owner decisions

1. Upload: push the branch and update PR #49 (then watch CI on all platforms).
2. B4: run the VM procedure (brief section 3). B4 stays open until then.
3. PR-M1: options A to D (brief section 5); recommendation A + B.
4. AR-2 (lockout with 0), AR-3 (long names and RTLO), RV-V1 policy; S-Y1/S-Y4
   unchanged; Dependabot #23 to #27 rebase; close the superseded draft #46.

## Next step

Owner review of the local commits. On "push": push this branch, update PR #49's
description, watch CI, report links. Do not reset this file to idle until PR #49
is ready to merge.

Technical task state only; update this file on the task branch, never on main.
