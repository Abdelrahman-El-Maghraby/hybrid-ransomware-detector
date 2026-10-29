# Current task handoff

- Status: **active** (WIP checkpoint; not for merge in this form).
- Task: Stage 3 of the project review: implementation for release 4.8.0.
- Brief: [PROJECT_REVIEW.md](PROJECT_REVIEW.md) section 24 (steps 1-12 in 24.3,
  refined by the owner answers in 24.1 and 24.9) and the startup prompt at the
  end of [tasks/project-review.md](tasks/project-review.md).
- Stage and approval boundary: Stage 3 authorised by the owner on 2026-10-29
  for steps 1-12: code, tests, docs, commits, pushes, creating
  `integration/v4.8` and opening step PRs. **No PR merges by the agent and
  nothing into `main`.** Optional (O) items need separate approval.
- Active agent: Claude. Previous agent: none active.
- Workflow: B1 (24.9 D-F). Step branches start from `integration/v4.8` when
  their prerequisites are merged, or stack on one unmerged parent. A step with
  two unmerged parents waits. This file holds the active checkpoint on the step
  branch being worked on; each step PR's last commit restores it to the
  `integration/v4.8` content before the PR is marked ready.

## Baseline

- PR #30 merged into `main` (merge commit `bd46fff`, 2026-10-29). The report
  is read from `main`.
- Implementation baseline: `origin/main` = `bd46fff`. Since the reviewed
  commit `af5e6d2` only `docs/` changed, so the report's file:line references
  hold.
- `integration/v4.8` created from `bd46fff` and pushed (it did not exist).

## Step PRs

| Step | Branch | PR | State |
|---|---|---|---|
| 1 | `fix/rulepack-confinement` | #31 | CI green; handoff restored; to be marked ready once CI on the restore commit is green |
| 2 | `fix/isolation-fail-closed` | to be opened (draft) | implemented, local checks pass; holds this checkpoint |
| 4 | `fix/background-reliability` | not pushed yet | implemented and committed locally (`1e0801a`); full suite still to run |
| 5 | `fix/dmg-streaming` | not pushed yet | in progress (branch from `integration/v4.8`) |

The draft `integration/v4.8` → `main` PR is opened once the integration branch
differs from `main` (GitHub refuses a PR with no commits).

## Completed

- Step 1 (PR-01, PR-14), last implementation commit `40b690f`: numeric version
  check in verify, build, rollback and CLI; install folders confined to
  `rulepacks/` (also refuses a planted link); atomic `active.json`; logged
  `rulepack_unreadable`.
- Step 2 (PR-02, PR-03, PR-11, D-E, D-E1), last implementation commit
  `9d1062d`: fail closed (no in-process fallback; `isolation_unavailable`
  results, not scored as `scan_failed`); CLI exit 3, GUI dialog with retry,
  API 503; single files isolated (`scan_one`); worker-start metrics and live
  `/ready`; spares wait for ready and refill with backoff; 120 s start
  deadline; `provenance.isolation`, schema 1.4; `ISOLATE_SCANS=0` an error
  under the production profile.
- Step 2 inspection (24.5): `engine/validation.py`, `provenance.py`,
  `metrics.py`, `readiness.py`, `capabilities.py` (relevant parts) read;
  scoring: `scan_failed` (W=25, Medium) is applied by `failure_result`; for
  files never opened the indicator is not applied (otherwise automatic
  quarantine at "medium" would quarantine unscanned files). No weight or
  threshold changed.
- Step 4 (PR-07, PR-09, PR-10), commit `1e0801a`: guarded scheduled jobs with
  a failure counter; a failed result instead of a dropped file; docstrings and
  the doc path corrected. Trial merge with step 2: clean.
- S-01 verification (step 5), benign generated archives only: with 7-Zip
  26.05 on macOS, `7z x` did not write outside its output folder (`..` and
  absolute names were rewritten). A link entry plus a file "through" it made
  7-Zip refuse, so the whole image was reported unreadable and none of its
  members was inspected. Other 7-Zip versions were not tested.

## Checks run (macOS, Python 3.14.2, `.venv`)

- Step 1: `pytest -q` 1049 passed, 8 skipped; ruff, mypy, bandit `-ll` clean;
  `pip-audit -r requirements.lock --no-deps --disable-pip` clean. PR #31 CI:
  all 13 checks green on `602ddfb`.
- Step 2: `pytest -q` 1036 passed, 8 skipped (the step 1 tests are not on this
  branch); `tests/test_isolation_policy.py` 20 tests; ruff, mypy, bandit
  clean.
- Step 4: `tests/test_background_reliability.py` 8 passed; ruff, mypy, bandit
  clean. Full suite not yet run.

## Limitations

- No Python 3.9 / 3.12, Windows or Linux desktop on this Mac: CI only.
- Docker is not available on this Mac: `deploy/check-deployment.sh` runs in CI.
- The GUI dialog for the fail-closed case is exercised through the controller
  event only; the window itself is covered by the GUI smoke test in CI (step
  10 extends it).

## Uncommitted work

- Step 5 worktree (scratchpad, branch `fix/dmg-streaming`): work in progress.

## Remaining steps (24.3)

1. Mark #31 ready when CI on `19506d9` is green.
2. Open the step 2 PR (draft); restore this file before marking it ready.
3. Run step 4's full suite, push it and open its PR.
4. Finish step 5 (stream DMG members with `7z e -so -spd`, S-01 tests).
5. Step 6 from `integration/v4.8`; step 3 stacked on step 2; step 7 stacked
   on step 4; step 9 stacked on step 7. Steps 8, 10, 11 and 12 wait for their
   parents to be merged.

## Next action

Push `fix/isolation-fail-closed` and open its draft PR.

## Last verified push

- `fix/rulepack-confinement` at `19506d9`: pushed and verified.
