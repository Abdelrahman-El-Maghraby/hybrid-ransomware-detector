# Aegis Sentinel — agent instructions

Read [docs/AI_WORKFLOW.md](docs/AI_WORKFLOW.md) and
[docs/HANDOFF.md](docs/HANDOFF.md) before starting or resuming work.
They define the shared Claude/Codex handoff process and the latest saved task state.

- Follow the owner's current request and explicit stage boundaries. A handoff does
  not authorise a new task, a wider scope, or a previously gated next stage.
- Only one agent edits a task branch at a time. Resume the recorded branch;
  inspect its actual files and history before relying on the handoff.
- Use small checkpoints throughout the work. Update the handoff, commit only
  reviewed task files, and push to the task branch after each meaningful step.
  Never wait until a usage limit is exhausted to save progress.
- Use branches and pull requests. The owner merges into main and authorises tags
  and releases. Never force-push or discard unrelated local changes.
- Keep code, repository docs and commits in English. Reply in English in chat
  unless the owner asks otherwise.
- Commit as Abdelrahman El-Maghraby <abdelrahmanfekrymaghrby@gmail.com>; verify
  git config user.name/user.email before the first commit. Omit AI attribution
  trailers and generated-by lines from commits and PR descriptions.
- Never print or commit secrets, .env files, tokens or private conversation exports.
- This repository is public. Task briefs and docs/HANDOFF.md must contain only
  technical task state: no business plans, pricing, customer names, personal
  data, VM details, API keys or private chat content. Write a sanitised technical
  brief instead of copying private messages. If essential private context cannot
  be shared, record only that owner input is required.
- This Mac is the host: never download, extract or run malware samples here.
  Malware samples stay in password-protected 7z archives inside the VM; never
  unzip them on this Mac.
  Real-sample evaluation and training require a separate explicit request and
  the isolated VM. Only safe metadata and digests belong in Git.
- Do not change detection weights, indicator thresholds or inspection coverage
  without an explicit request. Preserve result-schema compatibility.
- Read the relevant README, architecture and threat-model sections before code
  changes. Check docs/RELEASE_READINESS.md before adding readiness findings;
  reference existing item IDs instead of duplicating tracked work.
- Validate changes with the relevant existing checks and record actual commands,
  outcomes and limitations. Never label unrun checks as passing.
