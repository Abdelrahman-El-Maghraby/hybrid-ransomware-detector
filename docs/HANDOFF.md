# Current task handoff

- Status: active Stage 3 remaining validation; owner authorised continuation.
- Active agent: Codex. Claude is stopped; one editing agent.
- Brief: [tasks/project-review.md](tasks/project-review.md); requirements and
  decisions in [PROJECT_REVIEW.md](PROJECT_REVIEW.md) sections 24 and 26.
- Branch: `validation/v4.8-remaining`; base: `integration/v4.8`; draft PR #46.
- Baseline: `03089d5e16467d19edf2f718220cb5bab13af8ee`, verified owner merge of
  PR #45. Its tree equals final validation head `cd51cee`; application baseline
  remains `087b460`. CPIO numeric-field fix is now pending commit (see below).
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

Prepared fuzz harness extension, B4 harness, benign seed generator and two
one-hour Linux CI jobs. No application files or shipped locks changed.
Local ruff and diff checks passed. Seed-driver replay passed all 53 parser and 48 B4 seeds; every entry point
returned. It used a no-op instrumentation shim and is not Atheris evidence.
Expected malformed-input parser error results were observed.

## New evidence and failure under investigation

- Fuzz tooling pushed as `b2e8aea`; PR #46 is draft into integration/v4.8.
- Initial Atheris run 40969502006: parser job 123782398098 failed after 104
  inputs, uncaught ValueError in read_cpio's octal file-size conversion.
  Generated benign crash SHA-1: 019c81091380d838741ab1e991c0e0226a79ed2e.
  B4 job 123782397665 is still running; do not label it passed.
- The scanner's _pkg_stream already catches the error and marks the stream
  unreadable. The direct parser violates its FormatError contract. Fix adds
  unsigned numeric-field validation for odc/newc, preserving valid parsing.
- All 36 new regression cases failed before the fix (1.96 s). Afterward:
  tests/test_macos_packages.py tests/test_dmg_streaming.py
  tests/test_fuzz_parsers.py: 87 passed / no skips (4.78 s), with zbar path set.
  ruff passed; mypy passed 67 files; bandit passed at the repository gate.
- Fuzz workflow now detects parser/dependency/tooling changes between PR updates
  so a documentation-only checkpoint does not repeat an hour-long campaign.
  A skipped campaign is not fresh passing evidence. Inspect recorded code SHA.
- Integration 03089d5 checks verified green: tests 40932281409, quality
  40932281540, Docker 40932281388 (also deployment 40932271434).
- Scratch macOS GUI launched with isolated config and no credentials. Dashboard
  visible, but native control did not reliably navigate; no manual GUI pass.
  GUI displays an existing stale "4.4 beta" label (aegis_gui/common.py), noted
  for follow-up, not silently fixed. Scratch process is no longer running.
- Owner checklist drafted in docs/tasks/v4.8-owner-validation.md (uncommitted).

Exact next action: push the CPIO fix, inspect its new Linux Atheris run and CI,
then finish/checkpoint owner instructions and report evidence. Do not rerun
successful integration tests or benchmarks solely for this documentation merge.

No provider credentials, signing identity, reference workload or other desktops
are available in this task. Real-sample evaluation is not authorised here and
requires a separate explicit request and an isolated environment.

Last verified push: `b2e8aea` on validation/v4.8-remaining matched origin.
CPIO fix, workflow adjustment, checklist and this handoff are not yet pushed.
