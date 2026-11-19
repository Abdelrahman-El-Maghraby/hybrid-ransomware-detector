# Task brief: repository audit and cleanup (2026-11-18)

Sanitised technical brief. Branch `review/production-hardening` (local only),
started at `4b046b8`. Request: audit the whole repository for incorrect,
redundant, obsolete, misplaced or inconsistent files and code; make justified,
low-risk repairs; keep detection behaviour, security, public interfaces and
unrelated work unchanged. No push, deploy, cluster, install, malware, fuzzing
or OOM work.

## 1. Coverage (honest)

367 tracked files at `4b046b8`. Untracked `.arena/` (earlier review runs) and
ignored caches, `.venv/`, `.env`, `build/`, `dist/` were excluded from content
review; `.env` was not opened.

| Area | Files | State |
|---|---|---|
| `engine/`, `detectors/`, `core/`, `api/`, `aegis_gui/`, CLI, `gui.py` | 92 | Checked with tools: ruff, mypy (engine, core, detectors, api), bandit, the safe suite, a never-referenced-definition scan, a duplicate-helper scan, an env-variable cross-check against `.env.example`. Targeted reading only: alert enabling in `api/server.py` (`_Alerts`) and `core/outbox.py` without intel, `/version`, `gui.py` re-exports, `aegis_gui/formatting.py`. **Not re-reviewed line by line**; earlier reviews are in PROJECT_REVIEW 28 to 34 and the register |
| `deploy/kubernetes/` (13 files) | 13 | Inspected in full again, with fresh eyes, against `docker-compose.yml`, `Dockerfile`, `.dockerignore`, `api/server.py`, `core/outbox.py`; rendered and checked offline; tests run |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `deploy/*` (Docker) | 8 | Inspected (paths, users, volumes, backup/restore volume names) |
| `pyproject.toml`, `scanner.spec`, `build.py`, `requirements*` | 11 | Inspected for packaged data files and dependency drift (pyproject vs `requirements.txt`); locks inventoried only |
| `.github/` | 7 | `tests.yml`, `quality.yml`, `docker.yml` inspected; `release.yml`, `fuzz.yml`, `dependency-audit.yml`, `dependabot.yml` inventoried only |
| `tools/`, `fuzz/` | 13 | Every tool's `--help` run; consumers of `tools/splits.py` and the test helpers checked |
| `tests/` | 154 | All 139 `test_*.py` modules collect (2,009 tests; `test_gui_smoke.py` is opt-in); helper modules' consumers checked; `test_kubernetes.py` inspected |
| `rules/` | 5 | Counted (23 public, 2 private rules) against the README; not re-reviewed |
| Markdown (34 files) | 34 | Every relative link and heading anchor checked by script; backticked repo paths checked; version strings compared. Read: AGENTS, AI_WORKFLOW, HANDOFF (status and outline), PROJECT_MAP, ARCHITECTURE (parts), RELEASE_SCOPE (sections 1, 4, 5), FINDINGS_REGISTER (outline), VERIFICATION_MATRIX. PROJECT_REVIEW, CHANGELOG body and older task briefs: inventoried only (history) |
| Diagram sources and outputs, Graphify page, screenshots | 27 | Sources and references checked; generated HTML/SVG not opened |

## 2. Findings

| ID | Class | Files | Evidence | Action |
|---|---|---|---|---|
| RA-1 | Confirmed defect (CI) | `tests/test_kubernetes.py` | On Windows, the two prepare-state tests pasted `str(tmp_path)` (`C:\Users\...`) into Python source: `SyntaxError: truncated \UXXXXXXXX escape` (reproduced here with a Windows-style path); `os.geteuid` does not exist on Windows; the bash-script tests had no Windows skip, unlike `tests/test_operations_fixes.py`. They run wherever `kubectl` is installed, which includes GitHub's hosted runners | Fixed: forward-slash paths (`as_posix()`), the permission assertion only on POSIX, `needs_bash` skip on Windows. Verified on macOS only; CI has not run |
| RA-2 | Documentation inconsistency | `docs/ARCHITECTURE.md`, `docs/PROJECT_MAP.md` | "five diagrams" after diagram 6 was added; the Kubernetes deployment missing from the interfaces and operations overviews | Fixed |
| RA-3 | Documentation inconsistency | `README.md`, `docs/PROJECT_MAP.md` | "about 1,300 tests" and "about 1,850 tests" (2,009 collected); "108 commits" (128); pointers to the handoff's superseded "Final checkpoint" | Fixed: approximate counts, pointer to VERIFICATION_MATRIX |
| RA-4 | Documentation inconsistency | `docs/RELEASE_SCOPE.md` | The platform table did not mention the Kubernetes manifests, so their support status was unstated | Fixed: a row stating "not in the accepted scope; unverified; owner decision" |
| RA-5 | Optional improvement | `docs/screenshot-dashboard.png`, `screenshot-detail2.png`, `screenshot-scan.png` (1.9 MB) | Referenced by no document (`screenshot-detail2.png` never was; the other two were replaced by the v4 screenshots); not packaged | Kept: removal would not shrink the clone (history keeps them) and they are historical assets. Owner may remove |
| RA-6 | Optional improvement | `aegis_gui/formatting.py` `severity_color`, `severity_bar` | No caller anywhere; re-exported by `gui.py`'s `import *`, whose comment says it keeps names "other code and the tests import" | Kept: part of the `gui` module's import surface |
| RA-7 | Intentional duplication | `api/server.py`, `api/intel.py` `_env_number` | Identical 5-line helpers in two separately deployed services (`engine/logs.py` has different semantics) | Kept: a shared module would couple the intel service's imports to the API's |
| RA-8 | Intentional duplication | `deploy/isolation_check.py`, `deploy/kubernetes/base/isolation_gate.py` | Both check container posture (`/proc/self/status`) | Kept: different mechanisms (no interface vs. probes that must fail), different delivery (stdin vs. ConfigMap) and stdlib-only constraints |
| RA-9 | Optional improvement | `CHANGELOG.md` | `[Unreleased]` has no entry for this branch's changes (hardening groups or Kubernetes) | Left for the release: the branch's changelog should be written once, before merge |
| RA-10 | Optional improvement | `.github/workflows/quality.yml` | bandit does not scan `deploy/` (ruff's `S` rules do) | Not changed (CI scope change); bandit on `deploy/kubernetes` is clean locally |

No exact duplicate files, backup copies, stale backticked paths or broken
relative links were found. `.env.example` and the code read the same variables
(three documented elsewhere: `CLOUD_PSEUDONYM_KEY`, `CLOUD_SPOOL_DIR`,
`HRD_KEY_PASSPHRASE`). Packaging ships every runtime data file the code loads.
Kubernetes: the analysis Pod's settings match the Compose analysis service except
the documented differences; without intel and SMTP settings the API's alert outbox
stays disabled (`_Alerts.enabled` is false), so nothing queues without a receiver.

## 3. Files removed or moved

None.

## 4. Checks

Recorded in `docs/VERIFICATION_MATRIX.md` section 4 and the handoff.

## 5. Second pass (2026-11-18)

Same branch, local commits only; started at `4fecfbf`, last implementation
commit `8f61050`. Request: verify the first pass's conclusions, review the
highest-risk application paths it did not read, extend the security gate to
`deploy/`, review the Kubernetes isolation critically, turn K8S-1 into a
decision record, prepare runtime (cluster) and Windows verification, write the
CHANGELOG entry. No push, cluster, install, malware, fuzzing or OOM work; no
detection-weight, threshold, coverage or schema change. Findings RV-1 to RV-15
and RV-S1 to RV-S5 are in the [register](../FINDINGS_REGISTER.md).

### 5.1 The first pass's conclusions, checked

| Claim | Finding |
|---|---|
| RA-1 made the Kubernetes tests portable to Windows | **Incomplete.** The path and skip changes in `f20de01` are correct, and the bash skips cover only bash-specific tests. Two Windows failures remained: `test_the_deployment_docs_link_the_kubernetes_guide` read `README.md` with the locale encoding (its first bytes, an emoji, include 0x8F, which cp1252 cannot decode), and `posture_checks()` calls `os.getuid` in an existing test. Fixed as RV-1 without skipping the portable logic. A scan of every test for encoding-less reads of non-cp1252 repository files found no other case |
| Platform skips cover only platform-specific behaviour | Holds after RV-1: the bash and POSIX-permission checks are skipped or guarded; the YAML, checker, gate and text checks run everywhere |
| "bandit on `deploy/kubernetes` is clean locally" | True at `-ll`; the CI gate still excluded `deploy/` (now RV-3) |
| The documents state the Kubernetes limits | Mostly. One overclaim: the requirements table implied the gate always catches a missing policy; it does so through cluster DNS and the API server, not the internet probes. The contract and its limits are now one section of [KUBERNETES](../KUBERNETES.md#isolation-contract-and-its-limits) |
| Test revision vs document revisions | The safe-suite run "at `5d01232`" includes the code of `f20de01`; `5d01232` and `4fecfbf` changed documents only. The Windows fix was never run on Windows |

### 5.2 What this pass read (source level) and what it did not

| Path | Read | Not read |
|---|---|---|
| API admission, auth, limits, temp files | `api/server.py`, `api/limits.py`, `api/probe.py` in full; `engine/secret_store.py`, `engine/config.py`; Starlette's form parser and uvicorn's socket binding | intel endpoints in depth |
| Workers | `engine/workers.py`: reply protocol, `_IsolatedScan`, `_Worker`, failure and stopped results | `engine/helper_processes.py` internals |
| Containers and completeness | `engine/containers.py`, `engine/completeness.py` in full; the extractor's admission and limit checks; `detectors/web_content.py` payloads | the per-format walks (7z, RAR, ISO, pkg, DMG) |
| Scoring and results for failed or partial scans | `engine/staging.py` assembly, `engine/scanner.py` targets, report completeness lines | weights and rules (out of scope) |
| Alerts and outbox | `core/outbox.py` in full; `core/mailer.py` sending; `core/intel_client.py` alert calls; `_Alerts`; `core/outputs.py` delivery | `core/response.py`, `core/cloud.py`, GUI alert state |
| Configuration and secrets across deployments | API and intel settings, token files, Compose and Kubernetes environments | desktop keyring paths |
| State and restart | API start-up, stale `api.sock` (asyncio replaces a socket file; a regular file fails safely), emptyDir and claim lifetimes | Windows service restart |
| Kubernetes | manifests, gate, checker, both scripts, Caddyfile; rendered into another namespace | anything on a cluster |

Three narrow read-only reviews (API and configuration; workers and extraction;
alerts) ran in parallel; every defect they reported was re-read in the code and
reproduced by a regression test that fails before its fix, except RV-13 to
RV-15, which are recorded, not fixed. This is not an exhaustive security audit.

### 5.3 Clean-up decisions

Rechecked consumers: the three screenshots (RA-5) are referenced by no tracked
file; `severity_color` and `severity_bar` (RA-6) are called nowhere but are
re-exported by `gui.py`'s `import *`. Both are kept: removing tracked files only
shrinks the current checkout (Git history keeps them), and removing a
re-exported name needs an owner decision about the `gui` import surface. The two
`_env_number` helpers (RA-7) are identical again after RV-7 and stay separate
(the API and intel are deployed separately). No file was removed or moved.

## 6. Third pass (2026-11-19)

Same branch, local commits only, started at `1cf68c2`; last implementation
commit `e3e001b`. Authorized: repairs for RV-13, RV-14, RV-15 and unintended
network activity in local verification; triage of RV-S1 to RV-S5; option E only
if already approved. No push, deployment, cluster, malware, fuzzing or OOM work;
no weight, threshold or inspection-coverage change.

**Option E was not approved** (no record says so, and this request makes it
conditional), so it was not implemented. Its transport contract is now resolved
in the [decision record](../KUBERNETES.md#decision-record-k8s-1-how-analysis-reaches-intel-option-e-approved-and-implemented).
No K8S-1 implementation work existed in the tree; nothing was overwritten.

| Item | Outcome | Evidence |
|---|---|---|
| RV-13 | Fixed, additive `web.skipped`; schema version kept (scan_results are free-form) | tests at, above and over the size limit, through a ZIP, report, alert payload, GUI label, schema validation |
| RV-14 | Fixed; at-least-once window documented in OPERATIONS | failure before sending; send then failed record; restart; the double-failure window; stable ids |
| RV-15 | Fixed | disabled, unavailable, unstated, disabled after queueing (other channel kept), re-enabled |
| Network in local verification | Fixed (RV-16) and a suite-wide guard added, which found RV-17 | 21 refusal and offline tests; the guarded safe suite |
| RV-S1 | Confirmed, fixed | inert page, lowered read limit |
| RV-S2 | Confirmed, fixed (more serious than suspected: auto-quarantine acted on the path) | inert stand-in worker and decoy file |
| RV-S3 | Code path confirmed, no realistic trigger; fixed | injected exception |
| RV-S4 | Confirmed on loopback, fixed with an upload deadline | loopback probe: 503 for over 20 s before; with a 3 s deadline the next upload gets 200 |
| RV-S5 | Not reproduced; consequence checked (visible ERROR, alert lost) | empty entry stand-in |

Limits of this pass: the network guard covers the test process, not worker
processes started by tests; Caddy, Docker, Windows, Linux and any cluster were
not run.
