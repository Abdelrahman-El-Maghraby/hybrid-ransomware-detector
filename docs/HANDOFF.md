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
  branch being worked on (now `feat/gui-integration`, step 10); each step
  PR's last commit restores it to the `integration/v4.8` content before the PR
  is marked ready.

## Baseline

- PR #30 merged into `main` (`bd46fff`). Implementation baseline `origin/main`
  = `bd46fff`; only `docs/` changed since the reviewed `af5e6d2`.
- `integration/v4.8`: #31-#38, #40, #41 merged (tip `fc5d2f8`, merge commits). Draft
  `integration/v4.8` -> `main`: #39.

## Step PRs (all bases per B1)

| Step | Branch | PR | Base | State |
|---|---|---|---|---|
| 1-7 | (see the report) | #31-#37 | `integration/v4.8` | merged |
| 8 | `feat/folder-monitoring` | #40 | `integration/v4.8` | merged |
| 9 | `feat/cloud-reports` | #38 | `integration/v4.8` | merged |
| 10 | `feat/gui-integration` | draft | `integration/v4.8` | implemented (`9fcefdc`); this checkpoint |
| 11 | `build/hash-pinned-lock` | #41 | `integration/v4.8` | merged |
| 12 | `docs/v4.8` | - | - | waits: needs 10 merged |

Step 8's conflicts with step 9 were resolved on its branch (both sides kept);
combined suite 1178 passed, 8 skipped.

## Completed (last implementation commit per step)

- 1 `40b690f` PR-01, PR-14. 2 `9d1062d` + `e8ee3d2` PR-02, PR-03, PR-11,
  D-E, D-E1 (schema 1.4). 3 `aaf6415` PR-17. 4 `1e0801a` PR-07, PR-09,
  PR-10. 5 `600d8bc` S-01, PR-04 (and CHM). 6 `056ab85` PR-05, PR-06, S-04,
  PR-13. 7 `af8deda` PR-08, F4, S-03. 9 `0209d7b` F5 (D-D, D-D1-D-D3).
  8 `ecaca34` F1, F3. 11 `d64add6` PR-12 (hashed locks; no pin changed;
  a tampered hash fails pip download, checked by hand; pip-audit clean on all
  three locks without resolution). 10 `9fcefdc` F2 (monitoring page, alerts &
  cloud page with test sends and delivery status, key backup; GUI smoke test
  extended; full suite with GUI tests 1197 passed, 7 skipped).
- Pre-step-8 review (24.5): B4/B5/ML bounds and error handling reviewed
  (reads capped, loops progress, IndexError caught, YARA 60 s timeout, ML
  falls back without a model): no new High or Medium. Quarantine read fully;
  containment/response outlines read (canary only). Hypothesis long run
  (FUZZ_EXAMPLES=5000): 18 passed. atheris not run (no libFuzzer clang here;
  Linux CI or VM still required).
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
  4 1024, 5 1031, 7 1070 (4+7), 9 1092 (4+7+9), 8 1156 (1-8) passed;
  8 skipped each. ruff, mypy, bandit
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

1. Owner: review the step 10 PR.
2. Step 12 (`docs/v4.8`): DATA_POLICY, OPERATIONS, RUNBOOKS, README,
   CHANGELOG, TMA-1 to TMA-7 (D-G), after step 10 merges.
3. Then I-1 to I-7 on the integration branch, the section 15 benchmark, the
   release report; restore this file; #39 out of draft for the owner.

## Next action

Push `feat/gui-integration` and open its draft PR; restore this file and mark
it ready when CI is green.

## Last verified push

- `build/hash-pinned-lock` merged as #41. Nothing uncommitted.
