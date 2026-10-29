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
| 1 | `fix/rulepack-confinement` | to be opened | implemented, local checks pass |

The draft `integration/v4.8` → `main` PR is opened once the integration branch
differs from `main` (GitHub refuses a PR with no commits).

## Completed

- Step 1 (PR-01, PR-14), last implementation commit `40b690f`: numeric version
  check in verify, build, rollback and CLI; install folders confined to
  `rulepacks/` (also refuses a planted link); atomic `active.json`; logged
  `rulepack_unreadable`. `docs/RULE_PACKS.md` states the version rule.

## Checks run (macOS, Python 3.14.2, `.venv`)

- Step 1: `pytest -q` 1049 passed, 8 skipped; `tests/test_rulepack.py` 51
  passed (31 of the new tests fail against the unfixed module); ruff clean;
  mypy clean; bandit `-ll` clean; `pip-audit -r requirements.lock --no-deps
  --disable-pip` no known vulnerabilities (the lock does not resolve on 3.14,
  so resolution was skipped; CI runs it on 3.12).

## Limitations

- No Python 3.9 / 3.12, Windows or Linux desktop on this Mac: CI only.
- Docker is not available on this Mac: `deploy/check-deployment.sh` runs in CI.

## Uncommitted work

- None.

## Remaining steps (24.3)

1. Open the step 1 PR (base `integration/v4.8`).
2. Step 2 `fix/isolation-fail-closed` from `integration/v4.8` (inspection:
   `engine/validation.py`, `provenance.py`, `metrics.py`, `capabilities.py`,
   scoring correctness).
3. Step 3 stacked on step 2; steps 4, 5, 6 from `integration/v4.8`; step 7
   stacked on step 4; step 9 stacked on step 7. Steps 8, 10, 11 and 12 wait for
   their parents to be merged.

## Next action

Push `fix/rulepack-confinement` and open its PR.

## Last verified push

- `integration/v4.8` at `bd46fff`: pushed and verified.
