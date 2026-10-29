# Current task handoff

- Status: active. Stage 3, release 4.8.0; Claude stopped, Codex active.
- Brief: tasks/project-review.md and PROJECT_REVIEW sections 24-25.
- Branch: `fix/cloud-put-checksum`, based on step 12 `docs/v4.8` at `b770763`.
- Base for the requested separate PR: `integration/v4.8`; owner merged #43 at 3a35a6f; fetched and verified. The diff now contains
  only the checksum fix, its tests/docs and this handoff.
- Step 12 PR #43: merged by the owner at 3a35a6f. Final head b770763
  has all 11 checks green: tests 40868054269, quality 40868054104, Docker
  40868054126. The owner has been notified.
  Tests 1197 passed / 7 skipped; ruff, mypy, bandit and three lock audits passed.
  Previous head `ed3736c` had green tests, quality and Docker CI.
- Owner explicitly authorised this follow-up: explicit SHA256 on every cloud
  PUT, client-computed digest, retain response checksum validation, test omitted
  response checksum, update DATA_POLICY and OPERATIONS.
- Implementation: prepared in core/cloud.py, tests/test_cloud.py and the two docs.
  Local cloud tests: 24 passed in 5.32 seconds, including HTTPS requests with
  and without a returned checksum. Ruff, mypy and bandit passed. Diff reviewed.
  Full suite: `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib RUN_GUI_TESTS=1
  .venv/bin/python -m pytest -q -rs`: 1199 passed, 7 skipped, one Starlette
  deprecation warning in 272.21 seconds (macOS, Python 3.14.2). CI pending.
  Implementation commit `4d113a6` pushed, local and origin tips verified equal.
  Skips: Windows Restart Manager and Job Object; Linux ELF system binary and
  /proc; non-macOS fallback; missing box-js and optional OpenCV cv2.
  No skip rules changed. The original step-12 suite had these same seven skips.
- No unrelated local changes. No secrets, samples or detection changes.
- Remaining: validate and commit/push small checkpoints; open checksum PR into integration/v4.8, restore integration handoff as final
  commit and mark ready only after CI passes. Owner merges; never auto-merge.
- Then: final I-1 to I-7, regenerated section 15 benign benchmark and release
  report on final integrated code, through a separate PR into integration/v4.8.
  #39 stays draft. Production prerequisites and manual/atheris checks remain
  as PROJECT_REVIEW section 25 records.
- Exact next action: open the checksum PR into integration/v4.8.
  Scratch benchmark generator prepared from repository builders, seed 20261029:
  163 benign files / 24,681,977 bytes. No benchmark measurements run yet;
  regenerate as a new baseline after final code is integrated.
- Last verified push: fix/cloud-put-checksum at aec6d39, local and origin
  tips equal. This documentation checkpoint is not yet pushed.
