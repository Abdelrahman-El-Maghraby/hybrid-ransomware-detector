# About this document

## Purpose and reading order

This overview explains Aegis Sentinel from end to end for a security engineer who has
not seen the repository: what it does, how a file travels through it, how each
detection layer works, how a verdict and a completeness status are produced, which
data leaves the host, how the system is deployed and separated, and what evidence
supports each of those statements. Appendices: glossary (A), code-reading guide (B),
diagrams and their review (C), build instructions (D).

Code names (classes, functions, configuration keys) are given in `monospace` so they
can be searched for. Paths are relative to the repository root. Numbers that the code
defines (defaults, limits, weights, counts) are not typed by hand: the build reads them
from the code (`docs/security-overview/facts.py`) and refuses to build when the code
and this text disagree.

## Baseline

| Item | Value |
|---|---|
| Document date | 22 November 2026 (first edition 19 November; updated for TX-1, TX-2, TX-2b, TX-R1 and TX-R2) |
| Branch | `review/production-hardening` (local only; not pushed, not merged) |
| Last application-code commit | `0a6be7f` (strings lookahead bounded, TX-2b; before it `2672376`, text and strings limits reported as partial) |
| Documentation and manifests reviewed at | `e012d3f` (code then at `d45715a`; `deploy/kubernetes/` last changed in `a1c752e`); the text, completeness and layer chapters re-checked against `0a6be7f` |
| Engine, result schema, indicator registry | {{fact:engine_version}}, {{fact:schema_version}}, {{fact:registry_version}} |
| Last CI run on any commit | `3e5a3f2`, an older base of this branch; no workflow has run on the 177 commits since |
| Current local verification | at `0a6be7f` on macOS 27.2.1 arm64, Python 3.14.2: 2,273 passed, 0 failed, 0 errors, 8 skipped, 4 deselected, 606 s (safe selection, see chapter 12) |
| Earlier local runs (historical) | first edition, `d45715a`: 2,161 passed; `2672376`: 2,246 passed (each 0 failed, 8 skipped, 4 deselected) |

@note warn | **What this document does not claim.** No detection rate or false-positive rate has been measured on real samples. No external service (VirusTotal, an LLM provider, CAPE, SMTP, S3, IMAP) has been exercised for real at this baseline. Docker, Kubernetes, Windows and Linux behaviour of the current commits have not been run. A clean result means no indicator fired, not that a file is safe.

## How claims are labelled

Every capability in this document is in one of these states. They are not
interchangeable, and the chapters keep them apart.

| Label | Meaning | Example |
|---|---|---|
| [[impl]] | The behaviour exists in the code at the baseline. Nothing more is claimed. | The Windows Job Object memory limit |
| [[local]] | The repository's own tests exercise it and passed on the one macOS host, at the baseline, often with stand-ins (fake services, a recording `kubectl`, a virtual clock, inert files) | Worker reply validation |
| [[ci]] | GitHub Actions ran it (Linux, Windows, macOS runners) | Only on `3e5a3f2`; nothing newer |
| [[pending]] | Needs a platform, a real service or a cluster that was not available | NetworkPolicy enforcement, real VirusTotal |
| [[optional]] | Present but switched off unless an operator configures it | Sandbox, emulation, LLM, VirusTotal |
| [[proposed]] | Not built; a design or a recommendation only | Anything a later chapter calls "proposed" |
