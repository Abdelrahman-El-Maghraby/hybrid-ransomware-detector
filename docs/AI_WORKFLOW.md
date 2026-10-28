# Claude and Codex handoff

## Purpose

The owner can switch between Claude and Codex when either usage allowance runs
out. GitHub stores the shared task files and progress; it does not transfer chat
history or start the other assistant automatically.

## Activation

Merge the setup PR, then bring these files into the working branch before relying
on this process. For a new task, start a branch from updated main. For an existing
task, preserve its branch and changes, and bring in the setup commit with a normal
merge or cherry-pick after checking the working tree. Do not reset the task onto
main.

For the existing local checkout, after the setup PR is merged, preserve any
unfinished work and use a clean main branch tracking origin/main. Confirm that
CLAUDE.md is the old untracked local file and that ~/CLAUDE.local-backup.md does
not already exist; preserve an existing backup under a different name first.
Then run these exact local steps from the repository root on this Mac:

```sh
mv CLAUDE.md ~/CLAUDE.local-backup.md
sed -i '' '/^CLAUDE\.md$/d' .git/info/exclude
git pull
```

The middle command removes the exact CLAUDE.md line from .git/info/exclude.
If main has diverged or the pull fails, inspect the state and reconcile it;
never force a reset. Reconcile still-relevant backup instructions privately.
Never force-add the backup, local-only instructions or private notes to publish
them. These activation steps are instructions for after merge, not permission
to replace an active task branch or execute them before merge.

## Public repository privacy

This repository is public. Task briefs and docs/HANDOFF.md must contain only
technical task state: no business plans, pricing, customer names, personal data,
VM details, API keys or private chat content. Summarise the authorised technical
requirements without copying the owner's private messages. Apply the same rule
to tracked artifacts, commit messages and PR descriptions.

If continuation requires private context, keep it outside the public repository
and record only that owner input is required. Do not include private context,
private links or sensitive paths in the handoff. Review every checkpoint for
these exclusions before staging and pushing.

## Starting or taking over

1. The owner stops the previous agent and tells the next one to continue. The
   previous agent must remain stopped until the next handoff.
2. Read AGENTS.md, CLAUDE.md and docs/HANDOFF.md. Inspect Git status, the actual
   branch, recent commits, remote tip and any open task PR. Fetch remote updates.
3. Preserve unrelated changes. On the same machine, inspect any uncommitted task
   work left by the previous agent before switching branches or pulling.
   Across machines, local-only work is unavailable until deliberately transferred.
4. Resume the recorded task branch. When clean, update it with a fast-forward-only
   pull. If it has diverged, inspect and reconcile deliberately; do not force-push
   or reset away either side.
5. Check the stated baseline against the files. Keep valid completed work and
   rerun checks only when changes, failures or uncertainty justify it.
6. Record the new active agent and continue the first unfinished authorised step.
   If the saved state is awaiting owner input, honour that boundary.

The active-agent field is a human-readable convention, not a technical lock.
Do not run both agents against one working tree or task branch simultaneously.

## Checkpoints during work

After each meaningful unit, and before a long operation:

- Save the work and update docs/HANDOFF.md with the goal, scope, decisions,
  completed work, next steps, branch, code baseline and test evidence.
- Keep a sanitised technical task brief in a tracked task document when it is
  needed to resume. Include the current stage and any required owner approval,
  subject to the public repository privacy rules above. Never copy a private
  conversation or depend on private links or local-only files for shared context.
- Review the diff and stage explicit paths. Never use a blind git add . or include
  secrets, malware, environment files, raw private logs or unrelated work.
- Commit a coherent unit with a conventional commit message and push the task
  branch. An incomplete checkpoint is allowed if labelled WIP, with failures and
  missing checks explicit; it must not be merged or described as ready.
- Keep an existing task PR, or open one when useful. Do not create a new PR for
  every checkpoint. Use a draft for incomplete work.

Record the last implementation commit, rather than trying to put a handoff
commit's own SHA inside itself. The remote branch history establishes whether a
checkpoint arrived. Do not describe a new checkpoint as pushed before the push
succeeds; after pushing, verify the local and remote branch tips agree and report
that outcome in chat.

If push or authentication fails, retain the local commit and report the failure.
Local commits and uncommitted work are not available from GitHub. Git-ignored
notes may help on the same machine but are not the shared handoff.

## Handoff lifecycle

Update docs/HANDOFF.md on the task branch only, never directly on main. During
the task, it records the current technical checkpoint under the privacy rules
above. A paused task retains its checkpoint on that branch.

An active checkpoint must include the technical goal and sanitised brief path;
stage and approval boundary; active agent and whether the previous agent stopped;
task branch, base branch and PR; last implementation commit and code baseline;
completed changes and decisions; checks actually run with results and skips;
failures and uncertainties; uncommitted task files and unrelated changes to
preserve (without sensitive paths); ordered remaining steps; the exact next
action; and the last verified push result.

When the task's PR is merged, docs/HANDOFF.md must be reset to an idle state:
no active task, no active agent, no pending steps or approval request. Prepare
this reset as the final commit on the task branch immediately before the owner
merges, so main receives the idle state with the completed task. Preserve useful
technical evidence in the task's documentation and PR history, not as an active
handoff. If the PR is merged before the reset is included, submit the reset on a
follow-up maintenance branch and PR; do not write directly to main. There is no
automatic merge hook in this setup.

## When a limit interrupts the session

A final checkpoint is best effort, not guaranteed. The incoming agent first
checks for work newer than the last handoff, including unfinished local files.
It must reconcile that work before continuing. Periodic pushes limit the amount
of context that can be lost; they do not guarantee zero loss.

This setup does not monitor Claude's quota or automatically launch Codex. The
owner initiates the switch by sending the continuation prompt below.

## Validation

For application changes, use the existing repository gates as appropriate:

- python -m pytest -q
- ruff check .
- mypy
- bandit -q -r engine detectors core api aegis_gui tools RansomwareScanner.py -ll

Use coverage and regression checks when relevant; follow the actual configuration
and CI workflows rather than assuming an old test count or coverage percentage.
Record runtime, platform, skipped checks and failures. Cross-platform CI results
must be inspected before claiming them.

For documentation-only checkpoints, check the diff, Markdown links and consistency
with repository instructions. State that application tests were not run for that
checkpoint. Do not change dependencies just to complete a handoff.

## Owner prompts

Start or resume with either agent:

> Continue the current task using AGENTS.md, CLAUDE.md, docs/AI_WORKFLOW.md and
> docs/HANDOFF.md. The previous agent is stopped. Inspect the actual branch,
> remote tip and local changes, reconcile anything newer than the handoff, then
> continue the first unfinished authorised step. Preserve stage approval gates.
> Keep saving and pushing small checkpoints. Do not restart completed work.

Ask the current agent to hand over:

> Prepare a handoff now: save the task brief and current progress, update
> docs/HANDOFF.md, commit only the task files and push the branch. Tell me the
> branch, checkpoint SHA, PR URL, push result, remaining work and exact next step.
> Then stop so the other agent can continue.
