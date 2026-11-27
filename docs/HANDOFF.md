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

Post-4.8.0 review and repair (`review/remaining-issues-2026-11-27`, PR #49):
PR-W1, PR-W2, PR-A1, PR-C1, PR-S1, PR-R1 and PR-D1 fixed; PR-M1 recorded open.
Evidence: [VERIFICATION_MATRIX](VERIFICATION_MATRIX.md) section 18 and the
[brief](tasks/post-release-review-2026-11-27.md). Its checkpoint history is in
this file's Git history (last at `e44c729`).

- Start here: [PROJECT_MAP](PROJECT_MAP.md), [FINDINGS_REGISTER](FINDINGS_REGISTER.md)
  (status of every finding) and [architecture/README](architecture/README.md).
- Still open: 27.5 / B4 and PR-M1 (isolated-VM validation, separately
  authorised; steps in the brief), S-Y1/S-Y4 policy, Kubernetes on a cluster,
  real-sample and real-service validation, the suspicions PR-S2, PR-Q1, PR-F1,
  Dependabot PRs #23 to #27 and the superseded draft PR #46 (owner decisions).
- Released: 4.8.0 at `da7d6c9`. This task made no tag or release.
