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
- Workflow: B1 (24.9 D-F). This file holds the active checkpoint on the step
  branch being worked on (now `feat/cloud-reports`, step 9); each step
  PR's last commit restores it to the `integration/v4.8` content before the PR
  is marked ready.

## Baseline

- PR #30 merged into `main` (`bd46fff`). Implementation baseline `origin/main`
  = `bd46fff`; only `docs/` changed since the reviewed `af5e6d2`.
- `integration/v4.8` created from `bd46fff` (did not exist) and pushed. No
  step PR is merged into it yet, so the draft `integration/v4.8` -> `main` PR
  cannot be opened (no commits between them).

## Step PRs (all bases per B1)

| Step | Branch | PR | Base | State |
|---|---|---|---|---|
| 1 | `fix/rulepack-confinement` | #31 | `integration/v4.8` | ready, CI green |
| 2 | `fix/isolation-fail-closed` | #32 | `integration/v4.8` | ready, CI green |
| 3 | `perf/worker-dispatch` | #36 | `fix/isolation-fail-closed` (#32) | ready, CI green; retarget after #32 merges |
| 4 | `fix/background-reliability` | #33 | `integration/v4.8` | ready, CI green |
| 5 | `fix/dmg-streaming` | #35 | `integration/v4.8` | ready, CI green |
| 6 | `ci/matrix-coverage` | #34 | `integration/v4.8` | ready, CI green |
| 7 | `feat/alert-outbox-email` | #37 | `fix/background-reliability` (#33) | ready, CI green on `c8721b3`; retarget after #33 merges |
| 8 | `feat/folder-monitoring` | - | - | waits: needs 2, 3, 4, 7 merged |
| 9 | `feat/cloud-reports` | #38 (draft) | `feat/alert-outbox-email` (#37) | CI green; holds this checkpoint: restore this file, then mark ready |
| 10 | `feat/gui-integration` | - | - | waits: needs 2, 7, 8, 9 |
| 11 | `build/hash-pinned-lock` | - | - | waits: needs 6 and 9 merged |
| 12 | `docs/v4.8` | - | - | waits: needs 7-11 |

Trial merges (`git merge-tree`) of every pair of step branches above: clean.

## Completed (last implementation commit per step)

- 1 `40b690f` PR-01, PR-14. 2 `9d1062d` + `e8ee3d2` PR-02, PR-03, PR-11,
  D-E, D-E1 (schema 1.4). 3 `aaf6415` PR-17. 4 `1e0801a` PR-07, PR-09,
  PR-10. 5 `600d8bc` S-01, PR-04 (and CHM). 6 `056ab85` PR-05, PR-06, S-04,
  PR-13. 7 `af8deda` PR-08, F4, S-03. 9 `0209d7b` F5 (D-D, D-D1-D-D3).
- S-01: not reproduced with 7-Zip 26.05 (benign generated images); a link
  entry made `7z x` refuse the whole image (nothing inspected). Fixed by
  streaming.
- S-03: not reproduced on CPython with the GIL (0 of 3,000 trials); no lock
  (plan: lock if confirmed); regression test kept.
- S-04: confirmed by CI: the lock does not install on Python 3.9 on any OS;
  recorded as an exception (3.9 jobs test the latest releases).
- PR-17 benchmark (this Mac, regenerated benign set): 644 files, 4 workers
  146-154 -> 336-344 files/s; 1 worker unchanged (~200). On 161 files 4
  workers stay below 1 worker (start-up dominates ~1 s of work).

## Checks run (macOS, Python 3.14.2, `.venv`)

- Each step's full suite on its own branch: 1 1049, 2 1036, 3 1040 (2+3),
  4 1024, 5 1031, 7 1070 (4+7), 9 1092 (4+7+9) passed; 8 skipped each. ruff, mypy, bandit
  clean on every branch. pip-audit (lock, no resolution) clean (step 1).
- CI: #31-#37 all checks green (run IDs in each PR); #37's deployment job ran
  the new intel e-mail checks.
- Local combined preview (all step branches merged in a throwaway local
  branch `local/combined-preview`, not pushed): every merge clean; pytest
  1167 passed, 8 skipped; ruff, mypy, bandit clean. #38 coverage job: 1096
  passed, 5 skipped, 92 %.

## Limitations

- No Python 3.9 / 3.12, Windows or Linux desktop here: CI only. No Docker
  here: `deploy/check-deployment.sh` (extended in step 7) runs in CI.
- E-mail tested with fakes and a local TLS server with an untrusted
  certificate (refused); a real provider check is for the owner.

## Uncommitted work

- None in the main checkout. Scratch worktrees under the session scratchpad
  hold only committed branches.

## Remaining steps

1. Owner: review and merge #31-#35 into `integration/v4.8` (B1), then #36
   and #37 after their parents, then step 9.
2. Agent, after merges: retarget #36 (after #32), #37 (after #33), step 9
   (after #37) to `integration/v4.8`, merging the integration branch into
   them if needed; open the draft `integration/v4.8` -> `main` PR.
3. Before step 8: the 24.5 review pass of the B4/B5 parsers and ML layer,
   and a full read of `core/quarantine.py`, `core/containment.py`,
   `core/response.py` (F3). Then step 8 (needs 2, 3, 4, 7 merged), step 10
   (needs 8, 9), step 11 (needs 6, 9), step 12 (needs 7-11), then I-1 to
   I-7 and the release report.

## Next action

Wait for the owner's merges; then step 2 of the list above.

## Last verified push

- `feat/alert-outbox-email` at `c8721b3` and `feat/cloud-reports` at
  `e52a217` (merge of step 7 to resolve the handoff conflict, keeping this
  checkpoint): pushed and verified. Nothing uncommitted.
