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
