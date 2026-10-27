# Release readiness: v4.7 (first paid edition)

The acceptance criteria live in [`RELEASE_SCOPE.md`](RELEASE_SCOPE.md) section 6.
This file tracks every task against them.

**Status values:** `done` (evidence given) · `failed` · `external dependency`
(needs an OS, credential, certificate or service that is not available here, recorded
once) · `deferred` (moved out of v4.7, with the reason) · `open` (not started yet).

## Baseline (Phase 0, 2026-10-27)

Tree: `main` at `93b19f2` (v4.6.0 + PR #21), branched as `integration/v4.7`.

| Gate | Where | Result |
|---|---|---|
| Full suite, Python 3.9 and 3.12 on Linux, macOS, Windows | CI `tests` workflow on `93b19f2` | 6 / 6 jobs green |
| Coverage, lint + types, dependency audit, regression corpus | CI `quality` workflow on `93b19f2` | 4 / 4 jobs green |
| Full suite with coverage | Local, macOS arm64, Python 3.14.2, full `.[dev]` install | 843 passed, **3 failed**, 17 skipped; coverage **90.17 %** (floor 85 %) |
| Regression corpus + registry test | Local | 19 passed |
| ruff | Local | clean |
| mypy | Local, full install | **10 errors in 5 files** (B2) |
| bandit, CI gate (`-r engine detectors core api aegis_gui tools RansomwareScanner.py -ll`) | Local | 0 issues |
| bandit, whole tree (`-r . -c pyproject.toml -x ./.venv`) | Local | 0 medium/high in shipped code; 5 medium/high in tests and `test_smoke.py`; 1,497 low (1,372 are `assert` in tests) |
| pip-audit, pinned lock (`--no-deps`) | Local | no known vulnerabilities |
| pip-audit, installed environment | Local | no known vulnerabilities |

### Failures that exist before any v4.7 change

These are recorded so they are not confused with regressions.

| ID | What | Cause | Affects |
|---|---|---|---|
| B1 | `tests/test_rar.py`: `test_encrypted_rar5_opened_with_delivery_password`, `test_encrypted_file_names_opened_with_delivery_password`, `test_unknown_password_is_reported` fail | No RAR decompressor on the machine (7-Zip, unrar or unar). These tests fail instead of skipping, unlike the other tool-dependent tests. CI installs `unar` on macOS, `7zip`/`unar` in the coverage job. | Local runs without a decompressor. Proposed fix (A4): skip when no decompressor is found. |
| B2 | mypy: 10 errors in `detectors/container_extractor.py` (5), `core/canary_watch.py` (2), `detectors/tlsh_py.py`, `detectors/entropy.py`, `detectors/ml_classifier.py` | The optional-import fallback (`except ImportError: _np = None`) and the pycdlib types only type-check when the optional packages are installed. CI's mypy job installs core dependencies only (`pip install -e .`), so CI never sees them. | The gate passes in CI but fails on a full developer install. Proposed fix (A10): run mypy in CI with the extras installed and fix the 10 errors. |
| B3 | `requirements.lock` does not install on Python 3.14 | `backports-zstd==1.8.0` is pinned without an environment marker and requires Python < 3.14. | Only 3.14; CI and the release use 3.12. The Docker image will use 3.12. |
| B5 | `tests/test_workers.py::test_memory_limit_stops_runaway_allocation` fails on this Mac (also on `main` at `93b19f2`; it passed in the first baseline run) | On an 8 GB macOS host, `bytearray(8 GiB)` is zero-filled on demand, so resident memory never passes the 1 GiB limit and the watchdog has nothing to stop. The test depends on the host's memory behaviour. | Local macOS only. Proposed fix (A7): a hog that touches its pages. Deselected in local Phase 1 runs; CI runs it. |
| B4 | The bandit command in the working rules scanned `.venv` | `pyproject.toml` has no `[tool.bandit]` section, so `-c pyproject.toml` excludes nothing. | Local only; fixed in the working rules with `-x ./.venv`. |

Note on CI for branches: the `tests` and `quality` workflows run on pushes to `main`,
on pull requests and on `workflow_dispatch`. Integration and area branches are tested
with `gh workflow run <workflow> --ref <branch>`.

## Task matrix

### Phase 0: baseline, scope and acceptance criteria

| ID | Task | Criteria | Status | Evidence |
|---|---|---|---|---|
| P0.1 | Create `integration/v4.7` from `main` | — | done | Branch created at `93b19f2` |
| P0.2 | Run the suite and gates; record existing failures | S1 | done | Baseline above; B1-B4 |
| P0.3 | `docs/RELEASE_SCOPE.md`: edition, required / optional layers, platforms, out of scope | — | done | Accepted by the owner 2026-10-27, D1-D6 as proposed |
| P0.4 | Acceptance criteria (security, correctness, install / operate / upgrade / recover) | — | done | RELEASE_SCOPE.md §6, accepted 2026-10-27 |
| P0.5 | This readiness matrix | — | done | This file |

### Phase 1: release-blocking fixes (`fix/release-integrity`)

| ID | Task | Criteria | Status | Evidence |
|---|---|---|---|---|
| P1.1 | Build integrity: required dependency set per flavour (cli, gui, api); a missing one fails `build.py` and the release job; check the packaged artifact; log layers at start-up | O4, O5 | done | `bfe0a72`. Finding confirmed: `release.yml` installed each pin with `|| echo ::warning::` and `build.py` required 4 modules. Now preflight fails on a missing required package; the smoke test runs `--capabilities cli` on the packaged program. Local PyInstaller build (macOS arm64, 2026-10-27) passed; the packaged binary fails `--capabilities api` as expected (no fastapi, no zbar). `tests/test_capabilities.py` (14). |
| P1.2 | `GET /ready`, distinct from `/health`, with per-layer up / down / disabled | O2, O3 | done | `ac7c05a`. `engine/readiness.py`, `GET /ready` (503 when not ready, details only with a valid token). `tests/test_readiness.py` (9). |
| P1.3 | `scan_status`, `incomplete_reasons`, container precedence, required-layer enforcement in `check_config()`, no plain "Clean" on an incomplete scan | C1, C2, C3, O2 | done | `1a14d0e`. `engine/completeness.py`, schema 1.2. Precedence failed > locked > partial > unsupported > complete (justified in the module). Locked PDFs newly detected. Production profile refuses disabled required layers. `tests/test_scan_status.py` (21); regression corpus unchanged. |
| P1.4 | Provenance in every result and report | C4, S8 | done | `2bb0c54`. `engine/provenance.py`; report header and `/version`. Secret-leak test over results and reports. `tests/test_provenance.py` (9). |
| P1.5 | API auth throttling: per-IP limit before auth, lock-out on failed tokens, per-token quota kept | S3 | done | `8733662`, `448d21f`. Finding confirmed: `api/limits.py` `client_key()` keyed buckets on IP + token. Per-IP pre-auth limit, `AuthGuard` lockout checked before the compare, per-token quota after it; `/ready` no longer a token oracle. `tests/test_api_auth.py` (10). |
| P1.6 | Secrets to the OS keyring; verified migration from `.env` | S2 | done | `bab56e2`. Finding confirmed: `aegis_gui/pages/settings.py` wrote keys with `set_key()`. `engine/secret_store.py`: environment / `NAME_FILE` > keyring > `.env`; migration verified by read-back, `.env` untouched on any failure. `keyring` added to the lock (additions only, pip-audit clean). `tests/test_secret_store.py` (13). |
| P1.7 | Cache keys include model, prompt version and rules version | C5 | done | `8f66c4a`. Verdicts were never cached. Fixed: LLM key lacked prompt / engine version; VT "not found" answer survived enabling upload for 6 h; sandbox key ignored the server; a running scanner kept replaced rules until restart. `tests/test_cache_keys.py` (3). |

### Phase 2: privilege separation (`fix/privilege-separation`)

| ID | Task | Criteria | Status | Evidence |
|---|---|---|---|---|
| P2.1 | Scanning works with no containment rights; containment / response separated | S5 | open | |
| P2.2 | `analysis` and `intel` services; one connection design chosen and documented | S4 | open | |
| P2.3 | Intel: fixed operations, allowlisted destinations, input validation, service authentication, rate limit | S4 | open | |
| P2.4 | Tests: analysis has no internet route, reaches only intel; intel refuses other operations and destinations | S4 | open | |
| P2.5 | Audit temp files, extraction, `core/tools.py`, subprocesses, model loading, races, cleanup | S1, O6 | open | |
| P2.6 | Docker hardening, Dockerfile, `docker-compose.yml`, DEPLOYMENT.md notes | S5, O1 | open | |
| P2.7 | THREAT_MODEL.md: parser compromise, malicious archives, rule-pack updates | S10 | open | |

### Phase 3: area audits

| ID | Area | Includes | Status | Evidence |
|---|---|---|---|---|
| P3.A10 | Operations and release | Release fails on missing required deps; `pe:on` in the next release notes; signing / notarisation steps documented; SBOM per artifact; Actions pinned by SHA; least-privilege `permissions:`; no `continue-on-error` on required checks; B2 | open | |
| P3.A9 | Interfaces | GUI shows `scan_status`, `incomplete_reasons`, provenance; quarantine undo; Windows toast alerts; first-run setup with validation and diagnostics | open | |
| P3.A7 | Engine core | Graceful shutdown, bounded admission, temp cleanup after cancel / crash / restart; typed config where a fix needs it | open | |
| P3.A8 | Host protection | Authorised, audit-logged restore / resume / unlock; key backup and recovery end to end; `stop_writers` dry-run; GUI coverage of containment commands | open | |
| P3.A5 | Dynamic and intel | External sharing off by default, logged, in provenance | open | |
| P3.A4 | Containers | Audit; B1 | open | |
| P3.A2 | Documents | Audit | open | |
| P3.A3 | Executables | Delay-load imports; Authenticode presence vs validity; no unvalidated model shipped | open | |
| P3.A1 | Detection content | Rule-pack downgrade / replay protection verified; signed rollback; key rotation and compromise recovery documented. Code quality, tests and tooling only | open | |
| P3.A6 | Scoring and evaluation | `tools/evaluate.py`: separated splits, hash dedupe, no family leakage, counts per type / family, `summary.md` with detection / FP rate and misses. No weight changes | open | |

### Phase 4: release candidate (local only)

| ID | Task | Criteria | Status | Evidence |
|---|---|---|---|---|
| P4.1 | Install, configure, start, stop, upgrade, rollback, uninstall docs (Docker) | O1, U1 | open | |
| P4.2 | Backup / restore of config and quarantine key | R1 | open | |
| P4.3 | Runbooks: layer failure, worker failure, disk pressure, outdated rules, failed update | R2 | open | |
| P4.4 | Data policy | R4 | open | |
| P4.5 | Support doc (false positives) | R3 | open | |
| P4.6 | Third-party dependency and service terms for legal review | L1 | open | |
| P4.7 | Final readiness check against the acceptance criteria; prioritised remaining blockers | all | open | |
| P4.8 | v4.7.0-rc1 locally: version, CHANGELOG, full validation, local build and smoke test. No merge to main, no tag, no release | S1, O5 | open | |

### External dependencies

| ID | Needs | Blocks | Status |
|---|---|---|---|
| X1 | Real-sample evaluation in the isolated VM (owner) | M1, M2 | external dependency |
| X2 | Code-signing certificate (Windows) and Apple Developer ID for notarisation (owner purchase) | Signed desktop binaries (D2) | external dependency |
| X3 | Python 3.9 / 3.12 and Windows runs | S1 on each branch | Covered by CI (`workflow_dispatch`); not available locally |
