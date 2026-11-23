# Current task handoff

- Status: idle.
- Active task: none.
- Active agent: none.
- Pending steps: none.
- Pending owner approval for an active task: none.

Start a new authorised task on its task branch, then replace this idle state
with its sanitised technical checkpoint. Follow [AI_WORKFLOW.md](AI_WORKFLOW.md)
for the required checkpoint fields, public repository privacy rules, takeover
procedure and reset to idle when the task PR is merged.

Technical task state only: no business plans, pricing, customer names, personal
data, VM details, API keys or private chat content. Update this file on the task
branch only; never directly on main.

## Last completed task (reference only, not active)

`review/production-hardening` was merged into main after cross-platform CI
passed ([VERIFICATION_MATRIX](VERIFICATION_MATRIX.md) section 17). Its full
checkpoint history is in this file's Git history (last at `bc9bea5`) and in the
task briefs under [tasks/](tasks/).

- Start here: [PROJECT_MAP](PROJECT_MAP.md), [FINDINGS_REGISTER](FINDINGS_REGISTER.md)
  (status of every finding) and [architecture/README](architecture/README.md).
- Still open, unchanged by the merge: 27.5 / B4 (restricted; `parser-fuzz` runs
  only on manual dispatch with owner approval), Kubernetes runtime validation on a
  cluster, real-sample and real-service validation, and the readiness items in
  [RELEASE_READINESS](RELEASE_READINESS.md). No tag, release or deployment was made.
- Dependabot PRs #23 to #27 were left open for a separate decision.
