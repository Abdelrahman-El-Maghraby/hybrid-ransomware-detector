# Current task handoff

- Status: active Stage 3 remaining validation; owner authorised continuation.
- Active agent: Codex. Claude is stopped; one editing agent.
- Brief: [tasks/project-review.md](tasks/project-review.md); requirements and
  decisions in [PROJECT_REVIEW.md](PROJECT_REVIEW.md) sections 24 and 26.
- Branch: `validation/v4.8-remaining`; base: `integration/v4.8`; PR not yet open.
- Baseline: `03089d5e16467d19edf2f718220cb5bab13af8ee`, verified owner merge of
  PR #45. Its tree equals final validation head `cd51cee`; application baseline
  remains `087b460`. No implementation changes in this task yet.
- PR #39 verified open and draft at `03089d5`. Keep draft until required
  acceptance evidence is complete. Owner merges every PR; no tags or releases.
- Working tree was clean at takeover. No unrelated changes to preserve.

## Completed evidence (do not repeat without cause)

- Steps 1-12, checksum PR #44 and final evidence PR #45 are merged.
- Section 26 records I-1 to I-7: 190 focused tests plus 23 key/vault tests,
  all passed; same application tree full suite 1199 passed / 7 explained skips.
- Integration CI and 29 benchmark measurements are recorded in section 26.
- Fetched origin, verified PRs #45/#39 and commit identity. No application
  tests rerun in this takeover.
- Docker CLI exists locally but its daemon socket does not exist; no local
  Docker deployment is available. Local Python is 3.14; Atheris is not
  installed. The existing fuzz harness omits several B4 layers, so simply
  running it cannot close the stated B4 requirement.

## Remaining approved work, in order

1. Arrange bounded long Atheris runs on Linux CI with benign generated seeds,
   covering the existing harness and missing B4 entry points. Inspect actual
   results; retain any failures as unresolved until investigated. No malware.
2. Determine feasible macOS GUI evidence; owner manual Windows/macOS acceptance
   and real Windows/Linux desktop monitoring remain separate requirements.
3. Write concrete owner instructions for desktop checks and real SMTP/S3
   providers, and distinguish production prerequisites M1/X1, M2, O1, U1,
   X2, legal review and conditional D5 from development completion.
4. Record new evidence and limits, run checks appropriate to changed files,
   and submit a task PR into integration only. Restore handoff to integration's
   idle content as the final commit before marking that task PR ready.

Exact next action: inspect the fuzz harness/dependency/toolchain options and
prepare the Linux fuzz validation with explicit target coverage. Do not rerun
successful integration tests or benchmarks solely for this documentation merge.

No provider credentials, signing identity, reference workload or other desktops
are available in this task. Real-sample evaluation is not authorised here and
requires a separate explicit request and an isolated environment.

Last verified push: previous validation branch `cd51cee` is merged via #45.
This initial checkpoint has not yet been pushed; verify its remote tip after push.
