# Current task handoff

- Status: active. Stage 3, release 4.8.0; Claude stopped, Codex active.
- Brief: tasks/project-review.md and PROJECT_REVIEW sections 24-25.
- Branch: `fix/cloud-put-checksum`, based on step 12 `docs/v4.8` at `b770763`.
- Base for the requested separate PR: `integration/v4.8`; wait for owner merge
  of #43 before opening it so the diff is only the checksum fix.
- Step 12 PR #43: implementation and local checks complete, final CI pending.
  Tests 1197 passed / 7 skipped; ruff, mypy, bandit and three lock audits passed.
  Previous head `ed3736c` had green tests, quality and Docker CI.
- Owner explicitly authorised this follow-up: explicit SHA256 on every cloud
  PUT, client-computed digest, retain response checksum validation, test omitted
  response checksum, update DATA_POLICY and OPERATIONS.
- Implementation: prepared in core/cloud.py, tests/test_cloud.py and the two docs.
  Local cloud tests: 24 passed in 5.32 seconds, including HTTPS requests with
  and without a returned checksum. Ruff, mypy and bandit passed. Diff reviewed.
  Full suite and CI pending; checksum checkpoint not yet pushed.
- No unrelated local changes. No secrets, samples or detection changes.
- Remaining: validate and commit/push small checkpoints; wait for #43 merge,
  open checksum PR into integration/v4.8, restore integration handoff as final
  commit and mark ready only after CI passes. Owner merges; never auto-merge.
- Then: final I-1 to I-7, regenerated section 15 benign benchmark and release
  report on final integrated code, through a separate PR into integration/v4.8.
  #39 stays draft. Production prerequisites and manual/atheris checks remain
  as PROJECT_REVIEW section 25 records.
- Exact next action: run cloud tests and quality checks, inspect #43 final CI.
- Last verified push: docs/v4.8 at b770763, local and origin tips equal.
