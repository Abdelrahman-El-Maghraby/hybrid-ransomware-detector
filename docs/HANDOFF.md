# Current task handoff

- Status: active, awaiting owner review of PR #49. Pushed and verified in CI;
  not merged.
- Task: B4 investigation and repair, PR-M1, PR-S2, PR-Q1, PR-F1, a review of
  the remaining areas, then a follow-up on AR-2, AR-3, RV-L2, RV-V1, RV-I1,
  RV-C1 and a review of the B4 repairs. Brief: [tasks/b4-and-open-findings-2026-11-27.md](tasks/b4-and-open-findings-2026-11-27.md) (follow-up: section 8).
- Active agent: Claude (the previous agent is stopped).
- Branch: `review/remaining-issues-2026-11-27`, base `main` (`da7d6c9`, v4.8.0),
  PR #49 (open, mergeable).
- Last verified commit: `162caf9`, the PR #49 head, pushed on owner approval
  (local and remote SHAs matched). The last implementation commit is `648a80b`;
  `c17c4a8`, `64db93f`, `398cb94` and `162caf9` are documentation. Pushed after `6c42dc8`:
  `63658a3`, `2a6f76c`, `5a9e3a5`, `7221c64`, `11144b8`, `64425f7`, `1e22a3f`,
  `672730e`, `0305f29`, `78fb35a`, `5962225`, `46c788a`, `29f2206`, `8852880`,
  `648a80b`, plus documentation.
- Approval boundary: no merge, tag, release, branch deletion or workflow
  dispatch without the owner. Atheris campaigns, artifact replay and memory
  tests stay in the isolated VM (procedure:
  [tasks/b4-vm-validation-guide.md](tasks/b4-vm-validation-guide.md)).
- B4 VM validation guide: published in English (`398cb94`, `162caf9`); not yet
  executed. Its B4-only revision is not runtime-tested.

## Checks

- CI at `162caf9`: 11/11 passed (tests on ubuntu-latest 3.12, ubuntu-24.04 3.9,
  macOS 3.12 and 3.9, Windows 3.12 and 3.9; lint-and-types, coverage,
  dependency-audit, regression-corpus; deployment). Runs
  [46057763815](https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector/actions/runs/46057763815) (tests),
  [46057763841](https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector/actions/runs/46057763841) (quality),
  [46057763824](https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector/actions/runs/46057763824) (docker).
  Earlier: `c17c4a8` and `64db93f` also 11/11.
- Local safe suite at `071d780`: 2,350 passed, 0 failed, 8 skipped, 1 deselected;
  after `648a80b` the 23 API/docs test files: 543 passed (VERIFICATION_MATRIX
  section 20). ruff, mypy, bandit clean.
- Not run: fuzz suite and runaway-allocation test (by rule; the fuzz workflow
  was not dispatched), real external services, a cluster.

## Pending

1. B4 / 27.5: pending isolated-VM validation (owner-run, using the guide).
   Candidate repairs B4-O1 and B4-P1 are in; the historical OOM is not
   confirmed fixed and its root cause is unconfirmed.
2. PR-M1: pending an owner decision between options A to D (brief section 5);
   recommendation A + B.
3. AR-2 refuses 0 at start (0 was never a documented setting); an operator
   with 0 set must remove the line or set a positive value (CHANGELOG).
4. S-Y1/S-Y4 unchanged; Dependabot #23 to #27 rebase; close the superseded
   draft #46.

## Next step

Owner review of PR #49 and the merge decision. Do not reset this file to idle
until PR #49 is merged or closed.

Technical task state only; update this file on the task branch, never on main.
