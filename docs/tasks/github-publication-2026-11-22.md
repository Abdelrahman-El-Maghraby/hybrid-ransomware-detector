# Development-branch publication review (2026-11-22)

## Scope and publication outcome

Review local and GitHub state before publishing `review/production-hardening`.
The owner authorized a branch push, then requested an independent read-only
review before publication. The review was assessed and the owner requested
continuation. **The named development branch was successfully published.** No merge, PR,
workflow dispatch, tag, release, installation or deployment is part of this step.
Codex is the only editor; the independent reviewer must not mutate the checkout
or run another test suite concurrently.

## Verified starting repository state

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

## Independent review assessed

The independent read-only review inspected `cdfd82c` while the publication
records were being prepared; `de5ce1d` subsequently committed those records.
Application code did not change. It found no concrete publication blocker.

- Runtime assets and package declarations had no identified missing required
  file. Build/install behavior and cross-platform execution remain unverified.
- `local/combined-preview` contains seven old merge commits absent from this
  branch; their merged branch tips are already ancestors of HEAD. No separate
  feature branch was identified as missing intended work; nothing was merged
  automatically. Dependency-update branches remain separate.
- Rechecked the README finding: runtime locks omit httpx and jsonschema while
  CI installs both. Corrected the alternative test setup to include them and
  the tools used by the listed coverage/type/lint/security commands. The normal
  dev route now explicitly installs bandit too. These are documentation edits,
  not a dependency installation or lock refresh.
- Linked the safe local test selection from README; corrected stale current
  status in PROJECT_MAP and the verification-matrix header.
- The PDF remains a dated `0a6be7f` snapshot, explicitly labelled by its README.
  Its historical local-only wording describes the baseline, not current remote
  status. No PDF rebuild was needed for these publication records.
- `.arena/` remains untracked and untouched; only explicit documentation paths
  are staged. No local exclude/settings change was made.
- Workflow precautions and the historical attribution exceptions remain as
  recorded above. Publication does not authorize a PR, merge or release.

The prior independent safe run remains applicable to the unchanged application
code. Documentation diffs, relative link targets and the test-tool instructions
were checked; no suite rerun, install or build was performed for these edits.

## Verified publication

The explicit, non-forced push named only
`HEAD:refs/heads/review/production-hardening`, with tag-following and mirror
behavior disabled. It created the branch and set its upstream.

`git ls-remote --heads origin` confirmed local HEAD and the published branch
both at `c78a386c422c9069da34880390eb946a2bdbc4e2`. The main (`bd46fff`),
integration (`03089d5`) and validation (`3e5a3f2`) branch tips remained unchanged.
The GitHub workflow-run list for `review/production-hardening` was empty.
This result record follows that verified checkpoint; its own commit is pushed
and checked separately. No tags, PRs, merges or releases were created.

The branch is a complete tracked project snapshot, not a partial source upload.
Ignored/untracked local files and unrelated branches are not part of that
snapshot. GitHub's default branch remains main; select the development branch
for the newly published work.

## Remaining validation before merge or release

Cross-platform CI, Docker, Kubernetes, real-service/corpus validation and B4
remain as tracked in the findings register and verification matrix. The owner
must decide the permitted CI plan and merge sequence. Publishing does not
supersede any of those limits or authorize the restricted fuzz campaigns.
