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
