# Task brief: project review and development closure plan

Sanitised technical brief for the review task. It keeps the technical
requirements and approval gates of the owner's request and omits private
context. See [AI_WORKFLOW.md](../AI_WORKFLOW.md) for the shared handoff rules.

## Stages and approval gates

| Stage | Content | Gate to start |
|---|---|---|
| 1 | Initial reading, baseline, block overview, architecture diagram, clean code and design review, threat-to-mitigation mapping, platform/Python coverage observations. Report marked as incomplete draft. No benchmarks, no PR. | Task start |
| 2 | Refactoring proposals, performance benchmarks, gap analysis, roadmap, closure plan, final report, validation, PR, handoff idle reset. | Owner's explicit "continue" after Stage 1 |
| 3 | Implementation of the approved development closure plan. | Owner's separate explicit approval of the implementation plan presented at the end of Stage 2 |

- Stop after Stage 1 and wait for the owner's explicit "continue".
- Stage 2 completion, or the "continue" for Stage 2, does not authorise Stage 3.
- Owner-facing progress updates and summaries are in English.

## Review-stage rules (Stages 1 and 2)

- Branch: `review/project-review`, from updated `main`.
- Only these files may change: `docs/PROJECT_REVIEW.md`,
  `docs/tasks/project-review.md`, `docs/HANDOFF.md`.
- Do not change application code, tests, dependencies, configuration, or other
  documentation. Do not modify `docs/RELEASE_READINESS.md` or
  `docs/THREAT_MODEL.md`. If `docs/PROJECT_REVIEW.md` exists, update it.
- Commit and push WIP checkpoints after each meaningful section. Keep
  `docs/HANDOFF.md` current (stage, completed sections, remaining work, exact
  next step, tests actually run). Follow the handoff lifecycle in
  `docs/AI_WORKFLOW.md`, including the idle reset prepared as the final commit
  before the owner merges.
- Open the PR only at the end of Stage 2, against the normal target branch.
  Never merge it.
- Preserve unrelated working-tree changes. Do not run formatters or auto-fixes
  that modify other files. Do not install or upgrade dependencies or regenerate
  lockfiles.
- Keep temporary scripts, fixtures and raw benchmark results outside the commit.
- If any step is unavailable, record the exact limitation and continue the
  remaining feasible work. Never invent results or claim unrun checks passed.

## Review goal

A comprehensive, evidence-based architecture, code quality, performance and
readiness review of the project at its current active-development stage, plus
the incremental work needed to reach A+ quality and production readiness.

Read `AGENTS.md`, `CLAUDE.md`, `README.md`, `CHANGELOG.md` and everything in
`docs/` first.

Classify every item as one of: confirmed defect in implemented behaviour;
design or implementation weakness; planned or unfinished functionality;
production-deployment requirement. Unfinished functionality is not a defect
merely because it is incomplete; explain current impact and when to address
it. If documentation does not establish whether something is planned, mark it
uncertain. Rank confirmed defects by current impact; rank production
requirements by deployment risk; label the two rankings distinctly.

Record the reviewed branch and commit SHA at the start of the report. All
file:line references must match that commit. State whether any uncommitted
changes were excluded and identify the benchmarked code state.

## Project-specific scope

### Existing release-readiness tracking
- Read `docs/RELEASE_READINESS.md` before creating findings.
- Do not re-report tracked items (including real-sample evaluation, legal
  review, clean-Linux walk-through, 4.6.0 upgrade test, code signing). Reference
  their actual IDs; never invent IDs or duplicate them.
- Add only new evidence, evidence-backed status changes, or distinct issues.
- If an expected tracking item or ID cannot be found, say so.

### Detection accuracy (out of scope)
- No estimate of accuracy, detection rate or false positives, and no inference
  from synthetic fixtures or tests. Missing accuracy evaluation is not a finding.
- Review scoring code for implementation correctness, consistency and
  explainability only. Never propose weight or threshold changes.
- Performance benchmarking is in scope; keep throughput, latency, memory and
  inspection completion separate from accuracy.

### Threat-model-driven security review
- Use `docs/THREAT_MODEL.md` assumptions, trust boundaries and threats. Main
  attacker: a hostile file submitted for inspection.
- Prioritise parsers, archive extraction, worker isolation, the analysis/intel
  boundary, the API and rule-pack updates.
- For each area, map stated mitigations to: threat/mitigation reference;
  implementation (file:line); automated tests (file:line); whether those tests
  ran in this review and their results; implementation or testing gaps.
- Distinguish documented, implemented, test-covered and review-exercised
  mitigations.
- Report material threats missing from the threat model as proposed additions
  with evidence; do not silently expand attacker capabilities.

### Platforms and Python versions
- Product targets Windows, macOS and Linux. Verify actual CI Python versions
  and the local runtime; document discrepancies.
- Identify platform-specific code paths exercised by CI, explicitly skipped, or
  without demonstrated coverage (check test selection, conditions, mocks,
  skips; an OS CI job alone is not proof).
- Distinguish verified compatibility defects from coverage gaps. A local-only
  failure on an unsupported runtime is a local observation unless shown to
  affect a supported runtime.
- Local benchmarks are from the owner's Mac; never present them as Linux server
  or Windows results.

### Inspection depth
- If budget is limited, fully inspect security-critical blocks and sample the
  rest. Record fully inspected, sampled (with rationale) and unreviewed areas.
  "Fully inspected" means all files in the declared scope were read, not proof
  of absence of defects. Limit sampled-block conclusions to inspected evidence.

## Feature completeness and final feature roadmap

Assess against the implementation: real-time monitoring of selected folders
that submits new or modified files to the existing scan engine; the GUI
dashboard and its integration with monitoring, results, alerts, quarantine and
reports; the quarantine and restore workflow; outbound email alerting;
optional cloud storage for logs and reports.

For each: status (implemented/partial/planned/absent/uncertain) with evidence;
reuse existing functionality; missing behaviour, dependencies, platform limits
and acceptance criteria; incremental steps in the roadmap. These are requested
product capabilities, not automatically defects or production prerequisites.

Distinguish canary monitoring from folder monitoring and auto-scan; email
inspection from outbound alerting; existing quarantine from missing usability
or integration work; monitoring/auto-scan from guaranteed ransomware
prevention. Cloud storage must be optional and limited to logs and reports by
default; cover privacy, credential handling, retention and recovery after
network failure. Never assume permission to upload inspected files.

ML training, replacement, tuning and accuracy evaluation belong to a separate
contributor; review ML integration boundaries only where relevant.

## Development completion and block closure plan

- Derive the target-release baseline from docs and implementation, including
  the requested capabilities. Separate target-release work, production
  prerequisites and optional future improvements; explain overlaps. Record
  ambiguous scope as a proposed assumption plus the decision needed.
- For every block: expected behaviour and interfaces; what is implemented
  (evidence, verification limits); fixes and integration work needed; related
  finding or readiness IDs; dependencies; small dependency-ordered tasks with
  components, effort and compatibility risks; observable acceptance criteria
  and checks (including failure paths and platform behaviour); evidence needed
  before completion (inspected code vs existing tests vs tests run in review vs
  future validation); deferrable improvements with reasons; one final status:
  ready within reviewed scope / requires specified work / blocked by named
  dependency or decision / insufficient evidence (primary status plus others).
- A block is never ready merely because code exists or coverage is high.
- A dependency-ordered implementation sequence for all target-release work,
  with shared changes owned once, plus cross-block integration verification
  (monitoring to scan to GUI, quarantine and restore, alert delivery, optional
  cloud delivery); do not assume every flow exists.
- A project-level release closure checklist: block items, capability
  completion, cross-block interfaces/errors/cancellation/cleanup/recovery,
  platform and runtime checks with honest coverage, documentation and
  operational handover, outstanding ML dependencies, tracked prerequisites and
  external decisions.
- State separately whether evidence supports development completion and
  production readiness; name remaining items. The review itself does not
  complete development.
- Stage 1 records preliminary closure requirements and marks the rest pending;
  Stage 2 finalises.

## Report sections (docs/PROJECT_REVIEW.md)

1. **Block overview**: blocks from the actual structure (engine core, detection
   layer groups, containers, host protection, intel/external services, API,
   GUI, CLI, Docker, release/CI, tests, documentation, plus any others). Per
   block: purpose, files and entry points, connections, dependencies and data
   flows, evidenced quality, status, inspection depth. One Mermaid diagram with
   blocks, connections, external systems and trust boundaries.
2. **Clean code and design review** per block: naming, size, complexity,
   duplication, dead code (check registrations, dynamic dispatch, plugins,
   public interfaces, entry points; otherwise "suspected"), coupling/cohesion,
   separation of concerns, error handling, type hints, testability. Existing
   patterns with file:line, where they fit, misuse, and where a pattern would
   genuinely simplify. Size, mixins or global state are not defects by
   themselves; show practical impact. No speculative abstractions.
3. **Refactoring and optimisation**: small incremental steps only (never a
   big-bang rewrite), each with problem and evidence, benefit, steps,
   dependencies, effort, risk, verification tests, acceptance criteria, timing.
   Performance: inspect `tools/profile_layers.py` and scan entry points first;
   measure with it and a timed scan of a mixed safe file set: throughput
   (files/s, bytes/s), p50/p95 per file type with sample counts, peak memory
   (state whether workers included), worker start-up, steady state vs start-up,
   per-layer costs and hotspots. Fully document hardware, OS, runtime and
   dependency versions, commands, settings, enabled layers, workers, timeouts,
   external-service behaviour, dataset composition and sizes, type
   identification, cache conditions, warm-up, repetitions, metric definitions,
   failures and variability. Never execute scanned files, use private files,
   send content to external services, or download/generate malware. Do not
   tune settings, disable layers or compare runs with different coverage.
   Optimisation proposals separate measured results from hypotheses and are
   not implemented in review stages.
4. **Gap analysis to A+**: explicit criteria first, applied consistently; both
   current-stage quality and pre-production work; per block and project-wide.
   Severity scale (critical/high/medium/low) and effort scale defined with
   assumptions. Each new gap: unique ID, blocks, confirmed/suspected, category,
   severity, evidence, impact, fix, effort, dependencies, timing, acceptance
   criteria. Absence claims name the locations and mechanisms checked. Never
   claim "100% secure" or equate coverage with correctness. Do not inflate
   severity; state when a gap becomes consequential.
5. **Report structure**: executive summary; branch and SHA; scope, methodology
   and limitations; development context; criteria and scales; inspection
   inventory; blocks and diagram; per-block review; patterns; refactoring;
   benchmark methodology and results; hotspots; threat-to-mitigation mapping;
   platform/Python observations; confirmed gaps; suspected findings with
   verification steps; release-readiness references and new evidence; overall
   assessment; prioritised roadmap; block closure checklists; implementation
   sequence; release closure checklist. Per block: working well, improve now,
   before production, can wait, not established. End with up to 10
   highest-value actions (IDs, change, rationale, severity, effort,
   dependencies, risk, timing, acceptance criteria).
6. **Validation before PR**: verify file:line references, readiness IDs and
   benchmark tables; check Markdown and Mermaid syntax with available tools;
   confirm only the three files changed; run relevant existing checks and
   record outcomes. PR title and body cover scope, development stage,
   benchmark environment, threat-model basis, inspection depth, limitations and
   validation results.

## Stage 3 rules (only after explicit plan approval)

- Review-stage restrictions are lifted only as needed for the approved plan;
  repository instructions, privacy and malware-safety rules still apply.
- At the end of Stage 2, present the PR link, proposed implementation scope,
  block order, material risks and unresolved decisions, and ask for approval.
  Approval covers routine code changes, tests, commits, pushes and
  implementation PRs; never merge without explicit authorisation.
- Inspect repository instructions, working tree, report, readiness tracking and
  plan before editing; establish the implementation baseline; do not assume the
  review PR is merged.
- Use dedicated implementation branches separate from the review PR. Keep the
  handoff resumable with active block, IDs, work done, validation, dependencies
  and next step. Record fixes against implementation commits without rewriting
  historical review evidence.
- Implement approved target-release items, including folder monitoring, GUI
  integration, quarantine and restore, outbound email alerts and optional cloud
  logs/report storage, by extending existing code. ML work, weights, thresholds
  and accuracy remain out of scope; record cross-boundary dependencies.
- Per block: follow dependency order, small coherent changes, meaningful tests,
  relevant checks, honest validation records, focused PRs (not auto-merged).
  Never disable protections to obtain passing results.
- Afterwards verify the end-to-end flows, keep cloud uploads optional and
  limited to logs/reports, re-measure performance where relevant, update
  user-facing docs without secrets, and report development completion and
  production readiness separately.

## Plan revision after Stage 2 (owner request, 2026-10-29)

Authorises planning and documentation updates only. It does not approve Stage 3,
application code changes or merging any PR. The three-file scope still applies.

- Record the owner's answers:
  - D-A: 4.8.0 covering steps 1-12, with release requirements kept apart from
    optional improvements;
  - D-B: folder monitoring desktop only;
  - D-C: one narrowly scoped e-mail operation through intel for Docker;
  - D-D: optional S3-compatible storage for logs and reports only, off by
    default. The 30-day local spool retention is separate from cloud
    retention. Explain the cleanup and propose a cloud retention policy;
  - D-E: fail closed by default on the desktop and the API, with a clear error.
- Clarify:
  - how dependent branches build on each other and are tested together while
    their PRs stay unmerged, without assuming merges or an integration branch
    unless proposed explicitly;
  - the areas not reviewed, and the inspection and validation required before
    the release is declared complete;
  - what TMA-1 to TMA-4 propose, and which the new features require;
  - the actual results of the PR #30 checks.
- Save the revised plan and the open decisions in the review documents. Keep the
  "Last Dance" reference, and keep the historical findings and measurements
  identifiable.
- Result: report section 24.

## Second plan revision (owner answers, 2026-10-29)

Authorises documentation and planning updates only. Stage 3 is to be authorised
separately in a fresh session. The answers to D-D1 to D-D3, D-E1, D-F (B1), D-G
and D-I are recorded in report section 24.9. PR #30's actual status is recorded in
section 24.10; it must not be merged by Claude.

## Stage 3 startup prompt (for a fresh session, after the owner authorises Stage 3)

```text
Repository: https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector
Local checkout: ~/Projects/hybrid-ransomware-detector. Verify the working
directory is this repository (git remote, top-level files) before anything else.

I authorise Stage 3 (implementation) of the project review for release 4.8.0:
steps 1-12 of docs/PROJECT_REVIEW.md section 24.3, as refined by sections 24.1
and 24.9. This authorises routine code, test and documentation changes,
commits, pushes, creating integration/v4.8, and opening implementation PRs. It
does not authorise merging any PR or merging into main.

Decisions (all final):
- D-A: 4.8.0, steps 1-12. Keep release requirements (R), production
  prerequisites (P) and optional improvements (O) separate (24.2). Do not do
  O items unless I approve them separately.
- D-B: folder monitoring is desktop only (Windows, macOS, Linux desktop app and
  its background service). No watcher in Docker or the REST API.
- D-C: Docker e-mail goes through one narrowly scoped intel operation with a
  fixed metadata schema; intel holds SMTP settings, credentials and recipients;
  TLS with verification; SMTP destination check; rate limit and daily cap;
  analysis keeps no network. The desktop sends directly over TLS.
- D-D: optional S3-compatible upload of logs and reports only, off by default,
  desktop only (D-D2). Local spool: 30 days and a size cap, separate from cloud
  retention, cleanup as in 24.3 step 9.
- D-D1: 90-day cloud retention through the bucket lifecycle configuration
  (operator-configured and documented). Least-privilege credentials: create
  objects under this installation's prefix only, no list/read/delete/config.
  Unique object keys, create-only conditional writes where supported, checksum
  verified. Never claim that write-only access prevents overwriting or
  tampering; document bucket versioning / object lock as operator controls and
  that uploads are not tamper-evident.
- D-D3: uploads are an allowlisted, redacted view. File paths, folder names and
  file names (targets, archive members, attachments, embedded objects), user
  and host names are redacted by default (keyed per-installation pseudonyms;
  replacing the home folder with ~ is not enough). No free text by default; logs
  as structured allowlisted events. Document in DATA_POLICY the metadata that
  remains. Full-detail upload is an explicit opt-in, recorded and warned. A
  marker-name test proves no path or name leaks.
- D-E: fail closed by default on desktop and API when isolated workers cannot
  start, with a clear error; never silently scan in the main process.
- D-E1: disabling isolation (ISOLATE_SCANS=0) stays a development-only opt-out,
  recorded in every result (provenance.isolation), and is rejected at start-up
  under the production profile.
- D-F: Option B1. Create integration/v4.8 from updated main. Never commit to
  it directly; every change reaches it through a step PR that I review and
  merge. Follow the B1 workflow in 24.9: branch from the integration tip when
  the prerequisites are merged; stack on a single unmerged parent (PR base =
  parent branch, retarget to integration/v4.8 after I merge the parent);
  wait when a step has two unmerged parents. Open integration/v4.8 -> main early
  as a draft for combined CI. You merge no PR and never merge into main.
- D-G: threat-model updates TMA-1 to TMA-7 approved for step 12, written after
  steps 1-11, matching the final implementation, and separating mitigated
  defects (with commit and test) from accepted residual risks.
- D-I: schema 1.4 (additive provenance.isolation) and the scoped contract and
  dependency changes the plan needs are approved: the intel e-mail operation,
  an optional [cloud] extra and its client dependency, CI workflow changes, the
  hash-pinned lock. Nothing beyond the plan.

Start-up checks (before editing):
1. Read AGENTS.md, CLAUDE.md, docs/AI_WORKFLOW.md and docs/HANDOFF.md.
2. Check PR #30 (gh pr view 30): record whether it is merged. If merged, read the
   report from main. If not, read docs/PROJECT_REVIEW.md and
   docs/tasks/project-review.md from origin/review/project-review with git show,
   and record that in the handoff; do not assume it is merged and do not merge it.
3. Read the report sections 10, 13, 14, 15, 20, 21 and 24, and
   docs/RELEASE_READINESS.md for tracked IDs.
4. Check the working tree and preserve unrelated changes. Fetch origin; record
   the implementation baseline (origin/main SHA) and whether it moved past
   af5e6d2; if it did, re-check the cited file:line references of the step
   being started.
5. Create integration/v4.8 from updated main, push it, then start step 1.

Rules:
- Order and dependencies: 24.3 "Builds on". One focused branch and PR per step,
  using the branch names in 24.3, base per the B1 workflow. Each PR states its
  parent, IDs, acceptance criteria, checks run with results and skips, and the
  limitations. Mark it ready only when its CI is green.
- Before each step, do the inspection 24.5 assigns to it, and record it.
- Commit identity and attribution exactly as AGENTS.md says. No force-push, no
  auto-merge, no commits to main.
- No secrets, .env files, tokens or private data in commits, logs, PRs or the
  handoff; the repository is public.
- This Mac is the host: never download, extract or run malware samples; use
  generated benign fixtures only (including the S-01 DMG test).
- Do not change detection weights, thresholds or inspection coverage. ML
  training/model work and accuracy evaluation are out of scope; record any
  cross-boundary dependency.
- Change docs/THREAT_MODEL.md only in step 12. Change docs/RELEASE_READINESS.md
  only to record evidence for items actually closed.
- Tests for every acceptance criterion (sections 10, 20 I-1 to I-7, 24.3, 24.9),
  including failure paths. Run pytest, ruff, mypy, bandit and pip-audit locally
  and rely on CI for Python 3.9/3.12, Windows, Linux and Docker. Never weaken a
  protection to make a test pass. Record what actually ran; do not invent results.
- Handoff: keep the active checkpoint in docs/HANDOFF.md on the step branch
  being worked on (fields per AI_WORKFLOW.md, list every step PR and its state);
  before marking a step PR ready, restore docs/HANDOFF.md exactly to its
  content on integration/v4.8. Save and push small checkpoints.
- Record fixes against implementation commits; do not rewrite the historical
  review evidence in docs/PROJECT_REVIEW.md.
- If something is unavailable (for example Windows or Linux desktops), record
  the exact limitation and continue with the feasible work.
- Progress updates and summaries in English.

Finish: run I-1 to I-7 and the section 15 benchmark where relevant (re-measure
after step 3), update user-facing docs, and report development completion and
production readiness separately, listing the remaining tracked prerequisites
(M1/X1, M2, O1, U1, X2, legal review of docs/THIRD_PARTY.md, D5 if arm64 is
claimed). Stop when the final integration/v4.8 -> main PR is ready for my
review; do not merge it.
```
