# Current task handoff

- Status: **active** (Codex). Claude has stopped.
- Task: Stage 3 of the project review: implementation for release 4.8.0.
- Brief:
  - the owner's Stage 3 authorisation and start-up prompt:
    [tasks/project-review.md](tasks/project-review.md), last section;
  - the plan: [PROJECT_REVIEW.md](PROJECT_REVIEW.md) section 24 (steps 1-12
    in 24.3; release requirement / production prerequisite / optional split in
    24.2; branch workflow 24.4 as replaced by 24.9 D-F; inspection 24.5;
    threat-model items 24.6; owner answers 24.1 and 24.9). Acceptance
    criteria: section 10 (per finding), section 13 (per block), section 20
    (I-1 to I-7), section 21 (release closure checklist).
- Stage and approval boundary: Stage 3 is authorised for steps 1-12: code,
  tests, docs, commits, pushes, step branches and PRs. **No PR merges by the
  agent and nothing into `main`; no force-push, no auto-merge.** Optional (O)
  items need separate owner approval. The owner merges every PR.
- Active agent: Codex. Previous agent (Claude): stopped.

## Owner decisions (all final, 2026-10-29)

- **D-A** Release 4.8.0 = steps 1-12. Keep release requirements (R),
  production prerequisites (P) and optional improvements (O) separate (24.2);
  no O item without separate approval.
- **D-B** Folder monitoring is desktop only (desktop app and its background
  service on Windows, macOS, Linux). No watcher in Docker or the REST API.
- **D-C** Docker e-mail goes through one narrowly scoped intel operation with a
  fixed metadata schema; intel holds SMTP settings, credentials, recipients;
  TLS with verification; SMTP destination check; rate limit and daily cap;
  analysis keeps no network. The desktop sends directly over TLS.
- **D-D** Optional S3-compatible upload of logs and reports only, off by
  default. **D-D2** desktop only. Local spool: 30 days and a size cap, separate
  from cloud retention.
- **D-D1** 90-day cloud retention through the bucket lifecycle configuration
  (operator-configured, documented). Least-privilege credentials (create
  objects under this installation's prefix only; no list/read/delete/config).
  Unique keys, create-only conditional writes where supported, checksum
  verified. Never claim write-only access prevents overwriting or tampering;
  document versioning / object lock as operator controls; uploads are not
  tamper-evident.
- **D-D3** Uploads are an allowlisted, redacted view (paths, folder and file
  names, user and host names redacted with keyed per-installation pseudonyms;
  no free text; logs as structured events). DATA_POLICY lists the metadata
  that remains. Full detail is an explicit, recorded, warned opt-in. A
  marker-name test proves no path or name leaks.
- **D-E** Fail closed by default on desktop and API when isolated workers
  cannot start; never scan in the main process. **D-E1** `ISOLATE_SCANS=0` is a
  development-only opt-out, recorded in every result (`provenance.isolation`)
  and rejected at start-up under the production profile.
- **D-F** Workflow B1: step PRs into `integration/v4.8`, owner merges; stack
  on a single unmerged parent; wait on two. The active checkpoint lives in this
  file on the step branch being worked on; before a step PR is marked ready,
  its last commit restores this file to the `integration/v4.8` content.
  `integration/v4.8` -> `main` is the draft PR #39.
- **D-G** Threat-model items TMA-1 to TMA-7 approved for step 12, written after
  steps 1-11 against the final implementation, separating mitigated defects
  (with commit and test) from accepted residual risks.
- **D-H** PR #30 (the review) is merged into `main` (`bd46fff`).
- **D-I** Approved contract and dependency changes: schema 1.4 (additive
  `provenance.isolation`), the intel e-mail operation, the optional `[cloud]`
  extra (boto3), CI workflow changes, the hash-pinned locks. Nothing beyond
  the plan.

## Baseline and branches

- `main` = `bd46fff` (PR #30 merged). Since the reviewed commit `af5e6d2` only
  `docs/` changed before Stage 3.
- `integration/v4.8` = `c4906ac` (steps 1-11 merged, merge commits).
- Draft PR **#39** `integration/v4.8` -> `main`: not for merge until step 12,
  the final checks and the release report are done.
- Step 12 work in progress: branch **`docs/v4.8`** (from `c4906ac`), draft PR
  **#43** into `integration/v4.8`. This file is its active checkpoint; the last
  implementation commit is `9a24a13` (WIP docs).

## Step PRs

| Step | IDs | PR | State | Merge commit |
|---|---|---|---|---|
| 1 `fix/rulepack-confinement` | PR-01, PR-14 | #31 | merged | `9c6df73` |
| 2 `fix/isolation-fail-closed` | PR-02, PR-03, PR-11, D-E, D-E1 | #32 | merged | `9c4b0fd` |
| 3 `perf/worker-dispatch` | PR-17 | #36 | merged | `cad2a83` |
| 4 `fix/background-reliability` | PR-07, PR-09, PR-10 | #33 | merged | `bb8a556` |
| 5 `fix/dmg-streaming` | S-01, PR-04 (+ CHM) | #35 | merged | `dc037b5` |
| 6 `ci/matrix-coverage` | PR-05, PR-06, S-04, PR-13 | #34 | merged | `79c48c2` |
| 7 `feat/alert-outbox-email` | PR-08, S-03, F4 | #37 | merged | `046a972` |
| 8 `feat/folder-monitoring` | F1, F3 | #40 | merged | `44c8341` |
| 9 `feat/cloud-reports` | F5 | #38 | merged | `fa8da7c` |
| 10 `feat/gui-integration` | F2 | #42 | merged | `c4906ac` |
| 11 `build/hash-pinned-lock` | PR-12 | #41 | merged | `fc5d2f8` |
| 12 `docs/v4.8` | B16, TMA-1 to TMA-7 | #43 (draft) | **in progress** (this branch) | - |

Each step PR's description records its acceptance tests, the checks run and
the CI run IDs.

## Results worth knowing (details in the PRs)

- S-01: not reproduced with 7-Zip 26.05 (benign generated images); a link
  entry made `7z x` refuse the whole image (nothing inspected). Fixed by
  streaming members (`7z e -so -spd`). Other 7-Zip versions not tested.
- S-03: not reproduced on CPython with the GIL (0 of 3,000 trials); no lock
  (plan: lock if confirmed); regression test kept.
- S-04: confirmed by CI: the lock does not install on Python 3.9 on any OS;
  recorded exception (3.9 jobs test the latest releases). 3.12 installs the
  hashed lock completely on Linux, macOS, Windows.
- PR-17 (this Mac, regenerated benign set, not the section 15 files): 644
  files, 4 workers 146-154 -> 336-344 files/s; 161 files, 4 workers still
  below 1 worker (start-up dominates). M2 stays open.
- Scoring: files not scanned because workers could not start get
  `scan_status: failed` with code `isolation_unavailable` but **no**
  `scan_failed` indicator (would make them Medium and auto-quarantine them).
  No weight or threshold changed anywhere.
- Pre-step-8 review (24.5): B4/B5/ML bounds reviewed, no new High/Medium;
  Hypothesis long run (5,000 examples) passed; **atheris not run** (no
  libFuzzer clang on the Mac; Linux CI or the VM still required).
- Behaviour changes to document in step 12: CLI exit code 3 when isolation is
  unavailable; `/scan` 503 and live `/ready`; quarantine refuses a file changed
  since its scan; rule-pack versions must be numeric; Docker needs a
  `deploy/secrets/smtp_password` file (empty = e-mail off) when upgrading;
  schema 1.4.

## Checks run

- Every step: full suite locally (macOS, Python 3.14.2) and green CI on its
  final head (tests 3.9/3.12 on Linux, macOS, Windows; quality; docker). Last
  full local run (step 10, with GUI tests): 1197 passed, 7 skipped; ruff, mypy,
  bandit clean. pip-audit on all three locks: no known vulnerabilities.
- Not run anywhere yet: I-1 to I-7 as one pass on `integration/v4.8`; the
  section 15 benchmark re-run on the final code; atheris long runs; a real SMTP
  provider and a real S3 bucket (owner's accounts); manual GUI checks on
  Windows and macOS; monitoring on real Windows/Linux desktops (CI covers it
  headless).

## Uncommitted work

- None. The step 12 WIP is committed and pushed on `docs/v4.8` (`9a24a13`).
- On the owner's Mac only (not shared, disposable): a few scratch git
  worktrees of already-pushed branches and an unpushed local branch
  `local/combined-preview` (a test merge). They hold nothing that is not on
  GitHub; remove with `git worktree prune` / `git branch -D`.

## Step 12 status (`docs/v4.8`)

Done in the WIP commit `9a24a13`:
- `docs/THREAT_MODEL.md`: sections 1, 2, 5, 8, 9 updated to the 4.8 design;
  TMA-1 in section 10; new sections 11 (monitoring, TMA-5), 12 (e-mail,
  TMA-6), 13 (cloud, TMA-7); the "Changes in 4.8: TMA-1 to TMA-7" table with
  commits and tests; residual-risk rows. Re-check every commit SHA in that
  table against `git log` before review.
- `docs/DATA_POLICY.md`: v4.8; e-mail alerts and cloud rows; the cloud upload
  view (never uploaded / removed / remaining metadata / full detail / remote
  retention and deletion); outbox, spool, installation id and pseudonym key in
  "what is kept"; customer choices.

Still to do in step 12:
1. `docs/OPERATIONS.md`: install creates `deploy/secrets/smtp_password` (empty
   = off); SMTP settings go to intel in `.env`; upgrade 4.7.x -> 4.8.0 note
   (the new secret file, schema 1.4, `ISOLATE_SCANS=0` refused in production,
   `/scan` 503); desktop: folder monitoring, e-mail, cloud storage with an
   **example bucket lifecycle rule (90 days)**, an **example least-privilege
   policy** (`s3:PutObject` on `<prefix>/<installation id>/*` only), and
   versioning / object lock as operator controls; key backup in the GUI.
   Update the 4.7.0 version examples.
2. `docs/RUNBOOKS.md`: new runbooks: isolated workers cannot start (fail
   closed: `/ready` 503, `/scan` 503, CLI exit 3, GUI dialog, monitoring
   paused); alerts not delivered (`alert_retry`, `alert_expired`,
   `aegis_alerts_total`, GUI delivery status, SMTP certificate / credential /
   caps); cloud spool growing or expiring (`cloud_upload_retry`,
   `cloud_spool_expired`); monitoring queue full or paused.
3. `README.md`: features and the settings table (WATCH_*, SMTP_* /
   ALERT_EMAIL_*, OUTBOX_*, CLOUD_*), the CLI exit code 3, the new GUI pages.
4. `CHANGELOG.md`: a `[4.8.0]` section (Added / Changed / Security / Upgrade
   notes) covering steps 1-11 and the behaviour changes above.
5. Version 4.8.0 consistently: `ENGINE_VERSION` (`engine/config.py`),
   `pyproject.toml`, the image tag defaults in `docker-compose.yml` (check the
   tests that assert versions) - or record why it waits for the release.
6. `docs/PROJECT_REVIEW.md`: append a new section (do not edit the historical
   sections) recording each ID's fix against its PR, commit and test.
   `docs/RELEASE_READINESS.md`: change only for tracked items actually closed.
7. Run the full gates, restore this file to the `integration/v4.8` content as
   the PR's last commit, mark the draft PR ready when CI is green.

## After step 12 (Stage 3 finish)

1. Run I-1 to I-7 on `integration/v4.8` (section 20) and record the evidence.
2. Re-run the section 15 benchmark on the final code (method in section 15;
   the earlier scripts were scratch files, so regenerate the benign set from
   the test builders, seed 20261029) and label it a new baseline.
3. Report development completion and production readiness separately, with
   the open tracked prerequisites: M1/X1, M2, O1, U1, X2, the legal review of
   `docs/THIRD_PARTY.md`, D5 if arm64 is claimed; the deployment check on the
   release commit; atheris long runs; owner manual checks.
4. Reset this file to idle as the last commit before the owner merges #39;
   take #39 out of draft for the owner. Do not merge it.

## Local environment notes (this Mac)

- `.venv` with Python 3.14.2 (3.9 / 3.12 only in CI). `uv` and `boto3` are
  installed in it. Set `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` so the
  QR layer finds zbar. GUI tests run locally with `RUN_GUI_TESTS=1`. Docker is
  not available here; the deployment check runs in CI.
- pip-audit needs `--no-deps --disable-pip` locally (the locks target 3.12).

## Next action

Continue step 12 with item 1 (`docs/OPERATIONS.md`).

Takeover reconciliation: fetched and fast-forward checked; clean working tree,
local and remote task tip `4a5faa5`; integration remains `c4906ac`, main
`bd46fff`. PRs #39 and #43 remain open drafts with the expected bases.
PR #39 has an outdated progress description; branch history is authoritative.
No newer implementation or local changes found. Commit identity verified.
Documentation-only checkpoint: application checks not run; diff reviewed.

## Last verified push

- `docs/v4.8`: this checkpoint commit (the branch tip), pushed; the WIP docs
  commit `9a24a13` before it.
