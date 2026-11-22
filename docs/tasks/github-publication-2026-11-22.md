# Development-branch publication review (2026-11-22)

## Scope and current gate

Review local and GitHub state before publishing `review/production-hardening`.
The owner authorized a branch push, then requested an independent read-only
review before publication. **Push is pending that review.** No merge, PR,
workflow dispatch, tag, release, installation or deployment is part of this step.
Codex is the only editor; the independent reviewer must not mutate the checkout
or run another test suite concurrently.

## Verified repository state

- Starting HEAD: `cdfd82c`; last application change: `38c817b`.
- Fetch from `origin` succeeded. Current HEAD contains all of `origin/main`
  (`bd46fff`), `origin/integration/v4.8` (`03089d5`) and
  `origin/validation/v4.8-remaining` (`3e5a3f2`): no divergent commits in those
  comparisons. It is respectively 249, 185 and 180 commits ahead.
- 180 commits reachable from HEAD are absent from fetched origin branches.
  The publication branch does not yet exist on origin.
- Tracked files were clean at entry; untracked `.arena/` is preserved and excluded.
  `.env.example` is tracked; `.env`, `.venv/` and `.arena/` are not part of this
  branch's tracked snapshot. Other local branches are not automatically published.
- Git object connectivity check passed. Dangling objects are local historical
  objects, not a connectivity failure; no cleanup or history rewrite was performed.
- Commit identity matches AGENTS.md. Two historical commits (`a11b37c`,
  `74b6aef`) have prohibited AI attribution trailers. They remain explicitly
  recorded exceptions; rewriting their descendants and cited hashes is not
  authorized by this publication review. New commits omit such trailers.

## GitHub and workflow boundary

- The repository is public. PR #39 remains draft, integration to main;
  PR #46 remains draft, validation to integration. Neither is changed.
- Latest observed tests, quality and Docker runs are on `3e5a3f2`; they do not
  validate these 180 local commits. The successful parser-fuzz run at that
  revision skipped its campaigns; the earlier B4 memory failures remain unresolved.
- Current workflow definitions do not match pushes to
  `review/production-hardening`. Tests/quality match pushes to main; Docker
  matches main, integration, fix and area branches; release matches version tags;
  dependency audit is scheduled/manual; fuzz is PR/manual.
- Opening a PR for these code changes would match the restricted fuzz workflow.
  Do not open one as a side effect of saving the branch remotely. No workflow
  dispatch is authorized here.

## Publication-content review

A separate read-only review examined 876 previously unpushed blobs (43.4 MB)
and messages of all 180 commits. Bounded known-token, private-key, private-path
and private-material heuristics found no concrete publication blocker. Generic
credential candidates were synthetic test sentinels or prose. No suspicious
secret/archive/executable filenames or blobs above 10 MiB were found.

All three historical overview PDFs (62, 62 and 63 pages) were text-scanned;
no attachments or private-material matches were found. This is not an exhaustive
secret-detection guarantee or a full security review.

## Local verification

- Ruff on all tracked Python files: passed.
- Mypy: passed, 69 source files; existing untyped-body informational notes remain.
- Bandit medium/high gate including `deploy/`: passed.
- `python -m pip check`: no broken requirements found.
- Safe suite at application baseline `38c817b`, checkout `cdfd82c`: **2,295
  passed, 8 skipped, 4 deselected, 0 failures**, 610.86 s, macOS arm64, Python
  3.14.2. Same command/selection as verification matrix section 11, a clean
  subprocess environment, temporary HOME/TMPDIR, tool PATH and zbar library path.
  One existing Starlette deprecation warning; no ResourceWarning. A loopback
  test-server exception header appeared without a traceback; pytest reported
  no test failure. See verification matrix section 16 for limitations.
- Overview `facts.py` output exactly matches committed `src/facts.json`.
- `git diff --check 3e5a3f2..HEAD` found one trailing blank line in the overview
  layer source; removed in this review. The overview README now labels its
  baseline and counts as a snapshot and points to current verification records.
  No application behavior or PDF content changed.

## Remaining steps

1. Review independent findings about packaging, fresh-clone reproducibility,
   cross-platform assumptions and potentially missing local-branch work.
2. Resolve concrete publication blockers, if any, without merging unrelated work.
3. Push only the named development branch after the review gate is satisfied;
   verify local and remote SHA equality and observe any resulting workflow runs.
4. Keep merge/release readiness separate: B4, cross-platform CI, Docker,
   Kubernetes and real-service/corpus validation remain as tracked in the
   findings register and verification matrix.
