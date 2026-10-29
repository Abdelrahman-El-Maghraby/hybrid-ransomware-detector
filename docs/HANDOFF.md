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

## Last Dance — Final implementation follow-up

Reference only, not an active task. The project review (PR #30, report
[PROJECT_REVIEW.md](PROJECT_REVIEW.md), reviewed commit `af5e6d2`) is complete.
Implementation needs the owner's explicit approval and is a new task on its own
branches. Details live only in the report; follow the references.

- **Confirmed issues to fix** (report section 10; priority order in section 22):
  - PR-01 (High);
  - PR-02, PR-03, PR-04, PR-05, PR-07, PR-17 (Medium);
  - PR-06, PR-08, PR-09, PR-10, PR-11, PR-12, PR-13, PR-14, PR-16 (Low);
  - PR-15 (observation);
  - still to verify: S-01, S-03, S-04; H-03 unmeasured.
- **Requested feature completion** (report section 9; tasks in section 13 B9 / B11
  / B12; order in section 20 rows 10-14): F1 folder monitoring, F2 GUI
  integration, F3 quarantine integration, F4 outbound e-mail alerts, F5 optional
  cloud storage for logs and reports.
- **Owner decisions:** D-A to D-E were answered on 2026-10-29 (report section 24.1):
  4.8.0, monitoring desktop only, e-mail through one intel operation, optional
  S3-compatible logs and reports, and fail closed everywhere. D-D1 to D-D3,
  D-E1, D-F (B1), D-G and D-I were answered the same day (report section 24.9).
  Still open: D-H, merging PR #30; its status is in report section 24.10.
- **Revised Stage 3 plan** (proposed, **not approved**): report section 24.
  - steps 1-12 and the release requirement / optional split: 24.2-24.3;
  - branch and combined-testing workflow: 24.4;
  - unreviewed areas and the validation still required: 24.5;
  - TMA-1 to TMA-7: 24.6;
  - PR #30 checks: 24.7 and 24.10;
  - owner answers and the B1 workflow: 24.9;
  - the Stage 3 startup prompt: `docs/tasks/project-review.md`, last section.
- **Remaining closure items:**
  - block checklists, report section 13;
  - project release closure checklist, report section 21 (block closure,
    capabilities, integration checks I-1 to I-7, platforms and runtimes,
    documentation, ML dependency);
  - tracked prerequisites M1 / X1, M2, O1, U1, X2, D5, and the legal review of
    `docs/THIRD_PARTY.md`.
- **Threat-model proposals for the owner:** TMA-1 to TMA-4 (report section 7),
  and TMA-5 to TMA-7 for the new features (report section 24.6).
