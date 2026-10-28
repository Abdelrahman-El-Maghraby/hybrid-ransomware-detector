# Current task handoff

## Checkpoint

- Updated: 2026-10-28 (Africa/Cairo).
- Recorded by: Codex.
- Status: handoff setup prepared; owner merge pending.
- Setup branch: docs/claude-codex-handoff.
- Base branch: main.
- Code baseline: 8221fe74fce2d42c51fa45c4bfd36af1fdebbbfc.
- Active implementation task: none established by this setup.
- Task PR: locate the setup PR by its branch; no implementation PR selected.
- Remote checkpoint: verify from the branch history; do not infer from this file.

## Owner request and scope

Prepare GitHub-backed continuity so Codex can continue Claude's work when
Claude's weekly allowance runs out, and vice versa.

This checkpoint adds shared instructions and a handoff process only. It does
not start the previously discussed project review, change scanner behaviour,
or authorise a later review stage. The owner's current task and approval
boundaries must be captured before starting that task.

## Completed in this checkpoint

- Prepared AGENTS.md and CLAUDE.md to point both agents to the same rules.
- Prepared docs/AI_WORKFLOW.md with checkpoint, push, takeover and recovery steps.
- Initialised this handoff with the verified main code baseline.

## Decisions and constraints

- One agent works on a task branch at a time; the owner initiates each switch.
- Keep small pushed checkpoints throughout work.
- Preserve uncommitted changes and reconcile stale handoffs against actual files.
- The owner merges main and explicitly authorises releases.
- Read docs/RELEASE_READINESS.md for existing release work; this setup does not
  reassess or close those items.

## Validation evidence

- Confirmed that the three new instruction/handoff paths did not exist on main.
- Read the existing local-only CLAUDE.md without modifying it.
- Checked the proposed Markdown links and documentation-only file scope.
- Application tests: not run for this documentation-only setup.
- CI: not evaluated at the time this checkpoint was written.
- Verify the final PR diff and remote branch tip before reporting delivery.

## Remaining work and exact next step

1. Owner reviews and merges the setup PR.
2. Bring the setup into the intended task branch, preserving any current work
   and backing up an excluded local CLAUDE.md if Git reports a collision.
3. Capture the current authorised task brief and stage in a tracked task document.
4. Replace this setup state with the real task state before implementation.
5. Continue that task with either agent; use the continuation prompt in
   docs/AI_WORKFLOW.md when switching.

## Fields to maintain for each real task

- Goal and task-brief path:
- Current stage and owner approval boundary:
- Active agent / previous agent stopped:
- Task branch, base branch and PR URL:
- Last implementation commit / reviewed code baseline:
- Completed work (with file paths):
- Decisions and rationale:
- Tests actually run (commands, runtime, results and skips):
- Known failures, blockers and unverified assumptions:
- Uncommitted task files / unrelated changes to preserve:
- Local-only artifacts needed for continuation:
- Ordered remaining steps:
- Exact next action:
- Last push result (verify independently; never predict success):
