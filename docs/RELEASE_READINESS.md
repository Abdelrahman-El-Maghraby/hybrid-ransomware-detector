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
| B1 | **Fixed in A4 (7277af8).** `tests/test_rar.py`: `test_encrypted_rar5_opened_with_delivery_password`, `test_encrypted_file_names_opened_with_delivery_password`, `test_unknown_password_is_reported` fail | No RAR decompressor on the machine (7-Zip, unrar or unar). These tests fail instead of skipping, unlike the other tool-dependent tests. CI installs `unar` on macOS, `7zip`/`unar` in the coverage job. | Local runs without a decompressor. Proposed fix (A4): skip when no decompressor is found. |
| B2 | **Fixed in A10 (485eda7).** mypy: 10 errors in `detectors/container_extractor.py` (5), `core/canary_watch.py` (2), `detectors/tlsh_py.py`, `detectors/entropy.py`, `detectors/ml_classifier.py` | The optional-import fallback (`except ImportError: _np = None`) and the pycdlib types only type-check when the optional packages are installed. CI's mypy job installs core dependencies only (`pip install -e .`), so CI never sees them. | The gate passes in CI but fails on a full developer install. Proposed fix (A10): run mypy in CI with the extras installed and fix the 10 errors. |
| B3 | `requirements.lock` does not install on Python 3.14 | `backports-zstd==1.8.0` is pinned without an environment marker and requires Python < 3.14. | Only 3.14; CI and the release use 3.12. The Docker image will use 3.12. |
| B5 | **Fixed in A7 (ffaf4a5).** `tests/test_workers.py::test_memory_limit_stops_runaway_allocation` fails on this Mac (also on `main` at `93b19f2`; it passed in the first baseline run) | On an 8 GB macOS host, `bytearray(8 GiB)` is zero-filled on demand, so resident memory never passes the 1 GiB limit and the watchdog has nothing to stop. The test depends on the host's memory behaviour. | Local macOS only. Proposed fix (A7): a hog that touches its pages. Deselected in local Phase 1 runs; CI runs it. |
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

**Phase 1 gates on the merged tree** (`integration/v4.7` at `d557550`, 2026-10-28):
CI `tests` run 40591609694, 6 / 6 jobs green (Linux, macOS, Windows; Python 3.9 and 3.12);
CI `quality` run 40591613442, 4 / 4 green (lint + types, coverage, dependency audit,
regression corpus). Locally (macOS, Python 3.14): ruff clean, mypy at the 10 baseline
errors (B2), bandit 0 medium/high in shipped code, pip-audit clean, 928 passed with only
B5 failing, coverage 90.96 %, `test_smoke.py` passed. Two CI-only test faults were fixed
on the way: a POSIX-mode assertion on Windows, and a 1-byte ZipCrypto member that a wrong
delivery password could open (about 1 in 1,400 tries).

### Phase 2: privilege separation (`fix/privilege-separation`)

| ID | Task | Criteria | Status | Evidence |
|---|---|---|---|---|
| P2.1 | Scanning works with no containment rights; containment / response separated | S5 | done | fe6f793: validation imported `core.response` on every start (verified: the API process held it); now only with `CANARY_RESPONSE`; production profile refuses it; the image leaves both modules out (c7a4ac7, build-time `test ! -e`). `tests/test_privilege_separation.py`: scan + API with both modules unimportable; import-graph check. |
| P2.2 | `analysis` and `intel` services; one connection design chosen and documented | S4 | done | daf94d8, e496a6a, c7a4ac7. Design (b): analysis `network_mode: none`, Unix sockets on shared volumes; reasons in DEPLOYMENT.md section 0 and the build commit. |
| P2.3 | Intel: fixed operations, allowlisted destinations, input validation, service authentication, rate limit | S4 | done | daf94d8 (`api/intel.py`, `core/http.py` AllowlistSession incl. redirects; per-service sessions so the CAPE token stays on its host). `tests/test_intel_service.py` (19). |
| P2.4 | Tests: analysis has no internet route, reaches only intel; intel refuses other operations and destinations | S4 | done | `deploy/isolation_check.py` inside the running containers (Docker Desktop 29.9.2 locally: all checks PASS; CI `docker.yml` on ubuntu); unit tests for operations, inputs, token, rate limit, egress allowlist; `tests/test_deployment.py` keeps the compose hardening. |
| P2.5 | Audit temp files, extraction, `core/tools.py`, subprocesses, model loading, races, cleanup | S1, O6 | done | Findings fixed: killed workers leaked unpacked files (a9bcf5d, verified by a leftover `hrd_unpack_*`); XFF spoofing behind an appending proxy (12acafc); engine could not import without OCR (bdb9b6f). Checked, no change: RAR via `--` + stdout, 7z resolve-inside + no links, ZIP/ISO slip checks, generated upload names, trusted_which, joblib owner/mode check (no scikit-learn in the image). Residual: cache writable by workers (backlog). |
| P2.6 | Docker hardening, Dockerfile, `docker-compose.yml`, DEPLOYMENT.md notes | S5, O1 | done | c7a4ac7, 31c4c15, 88dc6d8: non-root, read-only root, noexec tmpfs, cap_drop ALL, no-new-privileges, default seccomp, CPU/memory/pids limits, Docker secrets, read-only content, TLS (Caddy), trusted proxy; images pinned by digest, packages from the lock (verified identical). `/ready` 200 in the production profile inside the image; one scan through TLS. |
| P2.7 | THREAT_MODEL.md: parser compromise, malicious archives, rule-pack updates | S10 | done | 88dc6d8: trust boundary 6, section 10, sections 2 and 5 extended, residual-risk rows. |

Phase 2 CI evidence (branch `fix/privilege-separation`): tests run 40599677907 6/6 green
(Linux, macOS, Windows on Python 3.9 and 3.12; the first run 40598939507 failed on Windows,
which has no `AF_UNIX` - fixed in the client, not by skipping the test); docker run
40599666228 green (build, isolation checks inside the containers, one scan through TLS);
quality on the final tip below. Locally (macOS, Python 3.14): ruff clean, mypy at the 10
baseline errors, bandit 0 medium/high in shipped code, 970 passed with only B5 deselected,
coverage 91 %, `deploy/check-deployment.sh` passed on Docker Desktop 29.9.2.

Phase 2 backlog (not blocking; owners in brackets):
- ~~Workers can write the result cache, so a parser exploit could plant a clean VirusTotal or LLM answer for a hash.~~ Fixed first in Phase 3 (owner: high priority), branch `area/a5-cache-integrity`: the cache lives only in intel.
- Workers hold the intel token (they run the external layers). Bounded by intel's fixed operations and rate limits [A5].
- ~~The API starts a new worker process per upload~~: measured and fixed in A7 (spare workers, still one fresh worker per file).
- No scikit-learn in the server image, so a trained ML model is not used there (the rule engine is) [A3 / product decision if a model ships].

### Phase 3: area audits

| ID | Area | Includes | Status | Evidence |
|---|---|---|---|---|
| P3.A10 | Operations and release | Release fails on missing required deps; `pe:on` in the next release notes; signing / notarisation steps documented; SBOM per artifact; Actions pinned by SHA; least-privilege `permissions:`; no `continue-on-error` on required checks; B2 | done | Branch `area/a10-operations-release`. A10-1 actions pinned by SHA + Dependabot + test (ba9b045); A10-2 server images in the release after the deployment check (3c7e4d1); A10-3 SBOM per artifact (Windows SBOM verified: PyInstaller in, python-tlsh out; image: 63 Python packages + 207 Debian packages); A10-4 / B2 mypy 0 errors, CI against the lock (485eda7); A10-5 `pe:on` in CHANGELOG; A10-6 `docs/RELEASING.md`. Already met: deps gate (P1.1), `permissions:` least-privilege, no `continue-on-error`. CI: tests 40604811112 6/6, quality 40604815855 4/4, docker 40604801195, release dry-run 40604819740 (3 builds + image green, publish skipped: no tag). Backlog A10-7: no vulnerability scan of the image's Debian packages (needs a scanner action). |
| P3.A9 | Interfaces | GUI shows `scan_status`, `incomplete_reasons`, provenance; quarantine undo; Windows toast alerts; first-run setup with validation and diagnostics | done | Branch `area/a9-interfaces`. A9-1 result view: gaps + provenance (95efa43); A9-2 Windows toasts, injection-safe (fd5ce15; unit-tested with a fake runner - a real toast on a Windows desktop not verified here, no Windows host); A9-4 Diagnostics panel + first-run check (ee552a5). Backlog: A9-3 quarantine undo from the result view (low: restore exists in Protection > vault); A9-5 API isolation costs a worker start per upload: p50 1,437 ms vs 4 ms in-process, p95 1,488 ms (small PDF, macOS, 10 runs) - about 1.4 files/s with 2 concurrent scans; fix = keep a pre-started spare worker per slot (still one fresh worker per file), measure again (A7). |
| P3.A7 | Engine core | Graceful shutdown, bounded admission, temp cleanup after cancel / crash / restart; typed config where a fix needs it | done | Branch `area/a7-engine-core`. A7-4 / B5: macOS watchdog read resident size and missed compressed memory - a worker could use gigabytes unstopped (reproduced); now physical footprint (ffaf4a5), test writes the memory it allocates and passes on this Mac. A7-1: temp folders of a crashed scanner swept by process id (8877b94). A7-2: spare workers, one file each - p50 1,399 -> 257 ms with uploads 2 s apart, back to back p50 1,357 -> 256 ms / p95 1,380 -> 1,228 ms; idle spare ~193 MB on macOS (c1bb781). A7-3: `stop_grace_period` 120 s (uvicorn finishes requests in progress on SIGTERM; not measured with a slow scan). Already in place: bounded admission (scan slots -> 503, upload limits), temp cleanup after a worker kill (Phase 2). Typed config: no fix needed it. |
| P3.A8 | Host protection | Authorised, audit-logged restore / resume / unlock; key backup and recovery end to end; `stop_writers` dry-run; GUI coverage of containment commands | done | Branch `area/a8-host-protection` (desktop only, decision D3). A8-1 resume only recorded pids, reused-pid check, audit log for resume and unlock (7ecf5e2). Verified, no change: quarantine and restore are audit-logged (`QUARANTINED` / `RESTORED`); key backup and recovery end to end (`tests/test_key_backup.py`: quarantined on one machine, restored on another; wrong passphrase and tampering refused; a different key never replaced silently). Backlog (low, outside paid support): A8-2 `stop_writers` dry-run; A8-3 resume / unlock buttons in the GUI (CLI exists). |
| P3.A5 | Dynamic and intel | External sharing off by default, logged, in provenance | done | Branches `area/a5-cache-integrity` (cache only in intel, first in Phase 3) and `area/a5-dynamic-intel`. A5-3 per-file `provenance.shared` (schema 1.3), report line, GUI row, `external_share` log event, members included; a cached answer records nothing (e842b1d). A5-1 production refuses `LLM_PROVIDER=auto`; image defaults to `none` (1a53acb). A5-2 intel validates its own settings at start (1a53acb). Verified, no change: VirusTotal off without a key, upload a separate switch off by default (D4); sandbox only with SANDBOX_URL; intel destinations allowlisted (Phase 2). |
| P3.A4 | Containers | Audit; B1 | done | Branch `area/a4-containers`. A4-1 (high): containers that could not be opened read 'Clean, complete' - damaged/truncated ZIP, unopenable archive (counted in unreadable_members, never read), mail over the size limit or unparseable; each reproduced, now partial with a reason (see commit). A4-2 / B1: bsdtar-only encrypted RAR named correctly, archive state note, tests skip with the reason (7277af8). Measured with tools/profile_layers.py on a synthetic container set: about 19 files/s in-process, slowest a 25-document ZIP at 0.33 s - no hotspot to fix; a 412:1 ZIP scored High through the zip-bomb rule as designed. Extraction safety was audited in Phase 2 (P2.5). |
| P3.A2 | Documents | Audit | done | Branch `area/a2-documents`. A2-1 (high): parser failures read as 'nothing found' - damaged PDF / Office text extraction, YARA error and timeout, macro and relationship errors; reproduced on a truncated PDF, a PDF of noise, a truncated .docx and a broken OLE .doc; now partial with the error, a program named .pdf stays complete. No perf hotspot in documents on the synthetic set (prompt-guard 0.19 s of 0.52 s for 10 files). |
| P3.A3 | Executables | Delay-load imports; Authenticode presence vs validity; no unvalidated model shipped | done | Branch `area/a3-executables`. A3-1 delay-load imports read and counted as imports, also without an ordinary import table (feat(pe) commit). Verified, no change: results report `signature_present` and `signature_verified: false`, detail 'present (not verified)'; no model file in the repo (0 tracked) and none in the server image (no scikit-learn); malformed PE / ELF headers are reported and scored as findings, not hidden. |
| P3.A1 | Detection content | Rule-pack downgrade / replay protection verified; signed rollback; key rotation and compromise recovery documented. Code quality, tests and tooling only | done | Branch `area/a1-detection-content`; no rule content changed. A1-1 (S6 conflict): `--allow-downgrade` accepted any older signed pack (replay of known-bypassed rules); now refused, rollback = signed newer pack with `rollback_of` (`tools/rulepack.py rollback`). A1-2: signer recorded per install; a pack signed by a removed key is not used and does not block recovery from a key compromise (a huge version). `docs/RULE_PACKS.md`: publishing, signed rollback, key rotation, compromise recovery. Tests: monotonic incl. replay of the same pack, signed rollback end to end, distrusted key, legacy active.json. |
| P3.A6 | Scoring and evaluation | `tools/evaluate.py`: separated splits, hash dedupe, no family leakage, counts per type / family, `summary.md` with detection / FP rate and misses. No weight changes | done | Branch `area/a6-scoring-evaluation`. A6-1 hash dedupe and contradictory labels; A6-2 family-grouped split shared by both tools (`tools/splits.py`); A6-3 calibration CV folds grouped by family (was shuffled: family leakage); A6-4 worst-case rate with errors as misses, scan-completeness table. Already present: per type / family / folder tables, misses and false alarms with reasons, three thresholds. No weight or threshold changed. Tested on synthetic files only; real-sample runs remain X1 (owner, VM). |

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
