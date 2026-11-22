# Support boundaries and verification matrix

Where each capability stands, and what has actually been checked on the current
code. Revision: code `b6966f8` on `review/production-hardening` (local, not
pushed); written 2026-11-17. The release-scope decisions are in
[RELEASE_SCOPE](RELEASE_SCOPE.md); finding status in
[FINDINGS_REGISTER](FINDINGS_REGISTER.md). A check listed here as passed ran on
this revision unless the row says otherwise. Older results are history, not
evidence for this revision.

## 1. Support boundaries

| Class | Capabilities | What it means |
|---|---|---|
| **Core** | Static detection layers of the production profile (RELEASE_SCOPE section 3), isolated scan workers with time and memory limits, scoring and verdicts, scan status and provenance, the result schema, CLI scans, the REST API in Docker | Part of every scan; covered by the test suite on macOS here; CI last ran on `3e5a3f2` |
| **Desktop and CLI features** (outside the Docker edition; D2 and D3 open) | GUI, folder monitoring, IMAP mailbox scanning, canaries and containment, quarantine vault, webhooks, JSON Lines, S3 uploads, the background service | Implemented and unit-tested; the GUI on a real display, Windows behaviour and real providers are not verified (section 2) |
| **Optional, off by default** | VirusTotal, an LLM (Ollama or OpenAI), a CAPE sandbox, e-mail alerts, OCR (Tesseract, poppler) | Need the operator's own service or key; checked here only with local stand-ins |
| **Analysis-VM only** | JavaScript emulation (box-js); real-sample evaluation; fuzz campaigns | Execute or parse hostile content by design; never on a workstation or the host |
| **Not shipped** | A trained ML model (the rule engine runs instead) | No validated model exists (A3) |

Guarantees that are **not** given: no detection or false-positive rate is
established (M1/X1); canaries and folder monitoring act after a write and cannot
prevent the first encrypted file; worker processes are a reliability boundary,
not a security sandbox (the Docker containers and the separate CAPE environment
are the security boundaries); helper programs that detach before discovery can
outlive their worker (L-E5).

## 2. Verification matrix

Status: **passed here** (this Mac, this revision), **stand-in** (local fakes or
mocks only), **pending** (needs a platform, service or authorisation that was not
available), **history** (an earlier revision only).

### Worker behaviour, cleanup, IPC and containment

| Check | macOS 27.2.1 arm64 (this Mac) | Linux | Windows |
|---|---|---|---|
| Worker IPC: JSON replies, size and type checks, invalid replies | passed here (full suite) | history: CI `3e5a3f2` predates M18 | history: CI `3e5a3f2` predates M18 |
| Time limit, partial and failed results, fail-closed start | passed here | history (CI `3e5a3f2`) | history (CI `3e5a3f2`) |
| Memory limit | RSS watchdog: passed here with stand-ins; the runaway-allocation test is deselected (memory spike) | RLIMIT_AS: pending | Job Object: stand-in only |
| Helper cleanup (L-E5) | passed here: escaped-helper tests; probe confirms the reparent-before-discovery limit | process groups: pending | Job Object: pending |
| Liveness of a stale worker folder (L-E6) | n/a | n/a | stand-in kernel32 only |
| Canary containment (`stop_writers`, `lock_folders`, `network_off`) | unit tests with stand-ins; no real process suspended | pending | Restart Manager and Controlled Folder Access: pending |
| Background scheduler (I-4): short jobs beside a long scan | passed here (inert fakes) | pending | pending |

### Docker isolation, deployment, backup and restore

| Check | Status |
|---|---|
| `deploy/check-deployment.sh` (build, isolation, health, signed rule pack, M27) | pending: the Docker daemon is not running on this Mac; CI's `docker` job last ran on `3e5a3f2` |
| `analysis` has no network; intel reaches only allowlisted destinations | pending (compose file read; not run) |
| Backup and restore scripts on real volumes | pending |
| Upgrade from 4.7 and rollback of a rule pack | pending |

### Kubernetes (optional; `deploy/kubernetes/`, [KUBERNETES](KUBERNETES.md))

| Check | Status |
|---|---|
| Base and example overlay render (`kubectl kustomize`, client 1.36.1, Kustomize 5.8.1, offline) | passed here |
| `check_manifests.py` invariants; the checker rejects weakened copies; the gate's classification; scripts refuse to run without context and namespace | passed here (`tests/test_kubernetes.py`, 61 tests) |
| Schema validation against a server, admission (`restricted`) | pending: no cluster; no offline schema validator installed |
| NetworkPolicy enforcement, isolation gate in a Pod, `fsGroup` on real storage, probes, shutdown, `content-update.sh`, `verify-cluster.sh` | pending: needs an approved test cluster; procedure in [KUBERNETES](KUBERNETES.md#verify) (disposable labelled namespaces, positive controls, drift and restart tests) |
| `verify-cluster.sh` refusals (shared namespaces, unlabelled namespace for changing checks, Kubernetes before 1.29) and that only read-only calls happen then | passed here with a recording kubectl stand-in (no cluster) |
| Image provides `sh` and `find` for the analysis start command | pending: Docker not running here |
| Intel on Kubernetes (option E, `components/intel`) | implemented; transport tested against a real TLS server on 127.0.0.1 and the manifests checked statically (section 7); **pending on a cluster**: NetworkPolicy on ClusterIP traffic, the TLS proxy in the intel Pod, certificate rotation, `verify-cluster.sh`'s intel checks |

### Real integrations

| Service | Status |
|---|---|
| CAPE sandbox (M26, M34) | stand-in only (fake HTTP, virtual clock) |
| VirusTotal (I-6) | stand-in only |
| LLM: Ollama or OpenAI (I-6, L-L1) | stand-in only |
| SMTP provider | local TLS stand-in only |
| Webhook receiver | local stand-in only |
| S3-compatible storage | stand-in only |
| IMAP server | stand-in only |
| Tesseract, poppler (OCR) | pending: not installed here |
| 7-Zip, unar | installed here (`7zz`, `unar`); archive tests ran without tool skips |

### GUI on a real display

| Check | Status |
|---|---|
| GUI smoke tests (`RUN_GUI_TESTS=1`) | passed here (3); headless widgets, not a check on a display |
| Pages, dialogs, label fit (M28, L-C6, L-G1, L-E9, M30, the new sidebar label) | pending: needs a person at a display on Windows and macOS |

### Packaging, installation, upgrade and rollback

| Check | Status |
|---|---|
| Wheel contents (M15) | history: passed at `72aa761`; packaging files unchanged since |
| Desktop binaries (PyInstaller) | pending: the release workflow runs on a tag only |
| Release gate (M16), SBOM, hash-pinned tools | pending: GitHub only |
| Python 3.9 and 3.12 | pending: CI only; this Mac runs 3.14.2 |
| Linux and Windows ARM64, macOS Intel | pending: no runner |

### Detection effectiveness

| Check | Status |
|---|---|
| Detection and false-positive rates (M1/X1) | pending: VM and a separate authorisation; procedure in [DATASET_PLAN](DATASET_PLAN.md#part-3-reproducible-evaluation-procedure) |
| S-Y1 / S-Y4 ambiguities against a benign corpus | pending: the same corpus |
| 27.5 / B4 out-of-memory failures | pending: VM plan in [the task brief](tasks/review-items-2026-11-17.md#3-275--b4-memory-evidence-and-a-bounded-vm-plan) |

## 3. Checks run on this revision

At `fde684c` (code identical to `b6966f8`), macOS 27.2.1 on Apple Silicon,
Python 3.14.2, temporary HOME and TMPDIR, bytecode disabled,
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` so the QR layer has zbar:

| Check | Result |
|---|---|
| Safe suite (`tests`, without `tests/test_fuzz_parsers.py`; four historical deselections: the runaway-memory test and three intel tests that hardcode `/tmp`) | **1,919 passed, 0 failed, 8 skipped, 4 deselected**, 1 third-party warning, 547 s. Skips: Restart Manager, real Job Object, `/proc`, a libproc-absent case, a system ELF binary, box-js, OpenCV, and the opt-in GUI test |
| `test_smoke.py` | ALL SMOKE TESTS PASSED |
| GUI tests (`RUN_GUI_TESTS=1 tests/test_gui_smoke.py`) | 3 passed, 12.8 s (headless widgets; not a check on a display) |
| Ruff (tracked Python files and the new diagram source) | clean |
| Mypy | no issues in 69 source files |
| Bandit gate (`-r engine detectors core api aegis_gui tools RansomwareScanner.py -ll`) | clean |
| Diagrams (`build_diagrams.py`, label check in headless Chrome) | no layout problems; 881 labels, none wider than its box |

Not run: pip-audit (no dependency changed), the coverage gate as CI runs it,
the wheel build (no packaging file changed), Docker, CI and everything marked
pending above.

## 4. Checks run for the Kubernetes deployment (2026-11-18)

At `7ae85eb` (manifests before `prepare-state`), macOS 27.2.1 on Apple Silicon,
Python 3.14.2, temporary HOME and TMPDIR, `PATH=/usr/local/bin:/usr/bin:/bin`
(kubectl found; Homebrew's `7zz` and `unar` not on the path),
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`:

| Check | Result |
|---|---|
| Safe suite (same selection and deselections as section 3) | **1,960 passed, 0 failed, 23 skipped, 4 deselected**, 1 warning, 551 s. The 15 skips beyond section 3 are 7-Zip and RAR tests, because that PATH left out `/opt/homebrew/bin`; no Kubernetes test was skipped |
| Ruff (tracked Python files) | clean (the untracked `.arena/` scratch folder has findings; not part of the repository) |
| Mypy | no issues in 69 source files |
| Bandit gate | clean; `bandit -ll -r deploy/kubernetes` clean |

At `062262a` (the final revision of this task: `prepare-state`, the fresh- and
existing-volume tests, these documents), same machine and settings,
`PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`:

| Check | Result |
|---|---|
| Safe suite (same selection and deselections as section 3) | **1,980 passed, 0 failed, 8 skipped, 4 deselected**, 1 warning, 546 s; the same 8 skips as section 3 |
| `tests/test_kubernetes.py` (in the suite) | 61 passed: render, invariants, 28 weakened manifests rejected, `prepare-state` on a fresh volume, an existing volume (nothing re-moded or re-owned, idempotent) and an unwritable one (clear failure), no permission changes, the gate, the scripts |
| Ruff (tracked Python files), mypy (69 files), bandit gate, `bandit -ll -r deploy/kubernetes` | clean |
| `bash -n` on the operator scripts | clean |
| Base render + `check_manifests.py --allow-placeholders`; example overlay | passes; the overlay is refused on its 8 placeholders, as intended |
| Diagram build | no layout problems; rebuilding changes no file; diagrams 1 to 5 unchanged |

Not run: anything against a cluster, image builds, `verify-cluster.sh`,
`content-update.sh`.

At `5d01232` (repository audit: Windows-portable Kubernetes tests and document
corrections; [brief](tasks/repository-audit-2026-11-18.md)), same machine and
settings as `062262a`:

| Check | Result |
|---|---|
| Safe suite (same selection and deselections as section 3) | **1,980 passed, 0 failed, 8 skipped, 4 deselected**, 1 warning, 553 s; the same 8 skips |
| Ruff (tracked Python files), mypy (69 files), bandit gate | clean |
| Markdown relative links (script) | none broken |
| The Windows fix itself | not run on Windows (no CI run); the old form's `SyntaxError` was reproduced here with a Windows-style path |


## 5. Second review pass (2026-11-18)

At `8f61050` (last implementation commit; the documents after it change no
code), macOS 27.2.1 on Apple Silicon, Python 3.14.2, scratch HOME and TMPDIR,
`env -i PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`, bytecode disabled,
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`:

| Check | Result |
|---|---|
| Safe suite (same selection and deselections as section 3) | **2,014 passed, 0 failed, 8 skipped, 4 deselected**, 1 third-party warning, 550 s; the same 8 skips as section 3 (34 tests more than at `5d01232`) |
| Ruff (tracked Python files; the untracked `.arena/` is excluded), mypy (69 files) | clean |
| Bandit gate as CI now runs it (`... RansomwareScanner.py deploy -ll`) | clean, no warnings; three `nosec B108` lines, each one literal `/tmp` that is compared or whose mount options are read |
| `tests/test_kubernetes.py` with `-X warn_default_encoding -W error::EncodingWarning` | 72 passed |
| Each fix's regression test against the code before the fix | failed before, passes after (RV-1 gate test with `os.getuid` removed; RV-2, RV-4 to RV-10, the CI bandit test) |
| `bash -n` on every deploy script; base render + `check_manifests.py`; base rendered into another namespace | clean; passes; passes. The example overlay is refused on its placeholders, as intended |
| Markdown links and anchors (script) | no new break; the six README emoji anchors this checker always flags remain |

Not run: Windows, Linux, CI, Docker, any cluster, Caddy, `test_smoke.py`, the
coverage gate as CI runs it.

### Windows verification (pending; the procedure)

Nothing in this pass ran on Windows. Checking RA-1 and RV-1 on macOS with a
Windows-style path or with `os.getuid` removed is a simulation, not a Windows
pass.

1. CI, without the restricted fuzz campaigns: after the owner pushes the branch,
   start the workflows manually (a pull request would also start `parser-fuzz`,
   because the branch changes `core/` and `engine/`):
   `gh workflow run tests.yml --ref review/production-hardening` and
   `gh workflow run quality.yml --ref review/production-hardening`.
2. Expected evidence in the `windows-latest` jobs (Python 3.9 and 3.12), whose
   log lists failures and skips (`-rfs`):
   - no `FAILED` or `ERROR` line;
   - `tests/test_kubernetes.py`: skipped only `test_scripts_*` and
     `test_verify_*` that need bash (reason "bash scripts"), and, if the runner
     has no `kubectl`, the render and `prepare-state` tests (reason "kubectl not
     installed"); `test_the_deployment_docs_link_the_kubernetes_guide`,
     `test_the_gate_flags_external_settings` and
     `test_the_gate_content_write_check_fails_and_leaves_nothing` must not be
     skipped;
   - the new worker, outbox and API tests pass (`test_a_worker_that_keeps_sending_messages_is_still_stopped_at_the_limit`,
     `test_a_worker_that_fails_to_start_leaves_no_temp_folder`, the four outbox
     tests in `tests/test_alerts.py`, the settings tests in `tests/test_api_auth.py`).
3. On a local Windows machine instead: `py -3.12 -m pytest -q -rfs
   tests/test_kubernetes.py tests/test_workers.py tests/test_alerts.py
   tests/test_api_auth.py tests/test_ci_workflows.py tests/test_deployment.py`
   with the requirements installed; record the Python version and `kubectl
   version --client`.

## 6. Third pass (2026-11-19)

At `e3e001b` (last implementation commit), same machine and settings as section 5,
run from a separate worktree of that commit:

| Check | Result |
|---|---|
| Safe suite (same selection and deselections), now with the conftest guard that fails any test reaching beyond this machine | **2,058 passed, 0 failed, 0 errors, 8 skipped, 4 deselected**, 1 third-party warning, 573 s; the same 8 platform skips; no outside network attempt recorded |
| The guard's first full run (at `9f37e26`) | 2,040 passed, **1 error**: the provenance test's real VirusTotal look-up (RV-17), fixed in `27b6872` |
| Ruff, mypy (69 files), bandit gate with `deploy/`, `bash -n`, base render + checker | clean |
| `test_smoke.py` (outside pytest, so not under the guard; it blanks every key and service setting itself) | ALL SMOKE TESTS PASSED |
| Each fix's tests against the code before it | failed before, pass after (RV-13: 4, RV-14: 5, RV-15: 4, RV-16: 21, RV-S1, RV-S2, RV-S3, RV-S4) |
| Loopback runtime probe of RV-S4 (uvicorn on 127.0.0.1, one slot) | before: 503 while a stalled upload held the slot (over 20 s); after, with a 3 s deadline: 200 |

Evidence classes: the outbox, intel and gate checks are unit tests with
stand-ins; RV-S2 and the worker fixes ran real worker processes with inert
stand-in scanners; RV-S4 ran the real API on loopback. Nothing ran on a cluster,
on Windows or Linux, or through Caddy or Docker.

## 7. Option E: intel on Kubernetes (2026-11-19)

At `706ea8a` (implementation), same machine and settings as section 5, from a
separate worktree of that commit. **Implementation results only: nothing ran on a
cluster, in Docker, on Windows or Linux, or through Caddy.**

| Check | Kind | Result |
|---|---|---|
| Safe suite under the network guard | local | **2,112 passed, 0 failed, 0 errors, 8 skipped, 4 deselected**, 581 s; the same 8 platform skips; no outside network attempt |
| `tests/test_intel_tls.py` (25): verified connection, wrong CA, wrong name, expired certificate, system store never loaded, CA rotation, URL rules, redirect not followed, proxies ignored, 401, time-out, closed port, upload sent once, transport selection, configuration check | real TLS server on 127.0.0.1, throwaway certificates | passed |
| The same tests against weakened clients (verification off, name check off or against the address, system store added) | mutation | each made tests fail (3, 7, 1) |
| `tests/test_kubernetes.py` (127): the intel overlay passes only once filled; 21 weakened intel deployments rejected; secret placement; proxy-to-socket wiring; base and Docker unchanged; gate settings and positive control | static, offline render | passed |
| Renders: base; base + `components/intel`; `overlays/example-intel` | `kubectl kustomize` (offline) | base and base + intel pass (placeholders allowed); the example is refused only on its placeholders |
| Ruff, mypy (69 files), bandit gate with `deploy/`, `bash -n` | static | clean |

Pending: everything at run time on a cluster (`verify-cluster.sh` with
`--control-namespace`, which now also checks analysis-to-intel with and without
the token, intel-to-analysis blocked, intel unreachable from another
namespace); the intel proxy's Caddy configuration in a container; the plugin's
treatment of ClusterIP traffic under the egress rule.

## 8. Review of option E (2026-11-19)

At `ef3a5c4` (the review's fixes on top of `706ea8a`), same machine and settings
as section 5. **Local results only: nothing ran on a cluster, in Docker, on
Windows or Linux, through Caddy, or in CI.** Findings K8S-R1 to K8S-R5 in the
[register](FINDINGS_REGISTER.md); brief
[tasks/kubernetes-option-e-review-2026-11-19.md](tasks/kubernetes-option-e-review-2026-11-19.md).

| Check | Kind | Result |
|---|---|---|
| Safe suite under the network guard (command as in section 5, from a separate worktree of `ef3a5c4`) | local | **2,122 passed, 0 failed, 0 errors, 8 skipped, 4 deselected**, 587 s (2,112 plus the 10 new tests); the same 8 platform skips and the one Starlette deprecation warning; no outside network attempt |
| `tests/test_kubernetes.py` (137, was 127): two split default routes refused, a narrow intel rule accepted, the digest arguments, the image check run against canned container statuses (match, older image, proxy digest), the order of positive controls and the gated intel Pod deletion | static, offline render | passed; before the checker fix the two split-route tests failed (the gap reproduced) |
| `verify-cluster.sh` end to end against a fake `kubectl` and `curl` (scratch only, not committed): the full run with `--control-namespace --drift-test --restart-test` and intel; a wrong `--image-digest`; no control namespace | dry run, no cluster | 62 passes and exit 0; the wrong image stops after the first Pod (exit 1); without a control namespace exit 3 (`INCONCLUSIVE` intel-to-analysis). Deletes: only its own objects, plus the two Pods of the restart test; both markers removed on exit. It shows the script's flow, not any cluster behaviour |
| The script's in-Pod intel snippet, run locally against a closed loopback port | local | `unreachable` for the token, wrong-token and wrong-name modes (it parses and uses the client API) |
| `tests/test_kubernetes.py` and `tests/test_intel_tls.py` on a copy with every text file converted to CRLF (what a Windows checkout gets without `.gitattributes`) | local emulation, not Windows | everything passed except the bash-script tests, which `tests.yml` skips on Windows |
| Python 3.9 grammar of every Python file changed since `c3dc658` (`ast.parse(feature_version=(3, 9))`) | static | passed; no 3.9 interpreter here, so not run on 3.9 |
| Renders: base, `overlays/example`, `overlays/example-intel`; the intel overlay moved to another namespace without the certificate name | `kubectl kustomize` (offline) | all three pass with placeholders allowed; the moved overlay is refused ("AEGIS_INTEL_SERVER_NAME must be aegis-intel.aegis-verify.svc") |
| Diagram 6 rebuilt; `build_diagrams.py --check` measured in headless Chrome | local | layout check passed; 974 labels, 0 wider than their box |
| Ruff, mypy (69 files), bandit gate with `deploy/`, `bash -n` on every deploy script, workflow YAML parses, `tests/test_ci_workflows.py` | static | clean / passed |

Unchanged by the review and still pending: everything on a cluster
(`verify-cluster.sh` as in [KUBERNETES](KUBERNETES.md#runtime-procedure-operator-run-disposable-namespaces-inert-files-only),
with the expected results listed there), the intel proxy's Caddyfile in a
container, Docker (the socket transport is unchanged in code; `docker.yml` has
not run on this branch), Windows, Linux and CI.

## 9. Intel reply limit and restart-test scope (2026-11-19)

At `d45715a`, same machine and settings as section 5. **Local results only:
nothing ran on a cluster, in Docker, on Windows or Linux, on Python 3.9, or in
CI.** Findings K8S-R4 and K8S-R6; brief section 9.

| Check | Kind | Result |
|---|---|---|
| Safe suite at `7f95021` (before the last fix) | local | 2,160 passed, 0 failed, 0 errors, 8 skipped, 4 deselected, 604 s; but **5 new ResourceWarnings**: a refused reply's socket was closed only by garbage collection. Fixed in `d45715a` |
| Safe suite under the network guard (command as in section 5, from a separate worktree of `d45715a`) | local | **2,161 passed, 0 failed, 0 errors, 8 skipped, 4 deselected**, 645 s; the same 8 platform skips and only the known Starlette deprecation warning (no ResourceWarning); no outside network attempt |
| `tests/test_intel_reply_limit.py` (36): a raw loopback server sends exact bytes. Empty, small and exactly-at-limit replies with Content-Length, without it and chunked; one byte over in all three framings; a 10 GiB declared length refused at once with the connection held open; a body longer than declared read only to its length; 3 MiB without a length stopped at the limit; shorter than declared; a chunked body cut short; gzip, deflate and br refused; `Accept-Encoding: identity` sent. Through `IntelClient` on a Unix socket: a normal reply unchanged, exactly 1 MiB accepted, 1 MiB + JSON over refused in three framings with status 200, lying lengths not read as `{}`, a 500 keeps its status, capabilities not cached, the LLM layer fails, a sandbox submission stays `possible`, a VirusTotal error is not cached; a refused reply's connection closed while the exception still exists | local, bounded (at most a few MiB, 10 s socket time-outs) | 36 passed (the Unix-socket ones are skipped on Windows); the closing test fails at `7f95021` |
| `tests/test_intel_tls.py`: an oversized reply over TLS | real TLS on loopback | passed |
| Weakened clients: `resp.read()` again; no shorter-than-declared check; a non-JSON 200 read as `{}`; any encoding accepted | mutation | 10, 2, 1 and 3 tests failed respectively; the reviewed file restored byte for byte |
| `tests/test_kubernetes.py` (139): restart test refused without the label on the Deployment; the ownership check precedes each Pod deletion | static and a recording `kubectl` stub | passed |
| `verify-cluster.sh` dry runs against a fake `kubectl` (scratch only) | dry run, no cluster | full run exit 0 (62 passes); a Pod owned by another Deployment: refused (exit 2) before its deletion, only the script's own control objects deleted; an unlabelled intel Deployment: refused in the preflight, nothing changed |
| Ruff, mypy, bandit with `deploy/`, `bash -n`, Python 3.9 grammar of the changed files | static | clean |
| This Mac's resources, Docker and cluster tools | read-only | brief section 9: 8 GiB RAM; Docker installed, not running; no kind |

## 10. Repair pass (2026-11-20)

| Check | Result |
|---|---|
| Safe suite at `5562225` (same selection and deselections as section 3) | **2,169 passed, 0 failed, 8 skipped, 4 deselected** (2,096 in the full run plus `tests/test_kubernetes.py` rerun with kubectl on PATH: 139 passed; details in the [brief](tasks/repair-pass-2026-11-20.md)) |
| ruff, mypy (69 files), bandit gate | clean |
| Platforms | macOS arm64 only; FI-2's device/inode check and FI-1's identity (ctime) are unverified on Windows |

## 11. TX-1 visible-text limits (2026-11-20)

Revision `b432f07`; macOS 27.2.1 arm64, Python 3.14.2. Environment: scratch
`HOME` and `TMPDIR`, `PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin`
(kubectl and 7-Zip found), `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`, the
suite's network guard active (`tests/conftest.py`). Command: `.venv/bin/python -m pytest -p no:cacheprovider -q -rfE -rs --tb=short -W default::ResourceWarning -o faulthandler_timeout=300 --ignore=tests/test_fuzz_parsers.py --deselect tests/test_workers.py::test_memory_limit_stops_runaway_allocation --deselect tests/test_intel_service.py::test_scanner_uses_intel_over_the_socket --deselect tests/test_intel_service.py::test_wrong_token_and_unreachable_intel_are_reported --deselect tests/test_intel_service.py::test_probe_reports_health tests`.

| Check | Result |
|---|---|
| Safe suite, **one run** at `b432f07` | **2,203 passed, 0 failed, 8 skipped, 4 deselected**, 1 third-party warning (Starlette `httpx` deprecation), 598 s; 0 ResourceWarnings; no outside network attempt. Kubernetes render tests ran (none skipped); the 8 skips are the usual platform ones (GUI opt-in, Restart Manager, system ELF, box-js, OpenCV, Job Object, `/proc`, libproc) |
| `tests/test_text_limits.py` at `b432f07` | 34 passed |
| The same file against `0ec91e0` (temporary worktree) | 30 failed, 4 passed (the 4 expect `complete` at or under the limits) |
| Focused neighbours (scan status, mail, embedded msg, charset, HTML mail, OCR helper cleanup, prompt guard, privilege separation, web smuggling, mailbox) with the new file | 181 passed |
| ruff (tracked Python files), mypy (69 files), bandit gate | clean |
| Platforms | macOS arm64 only; no Linux, Windows or CI run; OCR helpers were stand-ins (real Tesseract/poppler not run) |

## 12. TX-1 completion: strings pass (TX-2) and web boundary (TX-R1) (2026-11-22)

Working tree on `6cf7d9a` with the TX-2 / TX-R1 change (committed as
`2672376`; four comments changed after the run started, no code); macOS 27.2.1 arm64, Python 3.14.2.
Environment and command as section 11 (`env -i`, scratch `HOME` and `TMPDIR`,
the same `PATH`, `DYLD_FALLBACK_LIBRARY_PATH`, ignore and four deselections).

| Check | Result |
|---|---|
| Safe suite, **one run** | **2,246 passed, 0 failed, 8 skipped, 4 deselected** (2,203 of section 11 plus the 43 new tests), 589 s; 1 Starlette deprecation warning; 0 ResourceWarnings; no Kubernetes test skipped; the 8 skips are the usual platform ones |
| `tests/test_strings_limits.py` + `tests/test_text_limits.py` with neighbours (`test_strings`, `test_benchmark_fixes`, `test_pipeline`) | 132 passed |
| The two files against `6cf7d9a` (temporary worktree) | 35 failed, 42 passed (26 of 28 strings tests; 9 web-page cases) |
| Old `tests/test_text_limits.py` rechecked | 34 passed at `6cf7d9a`; 30 failed, 4 passed at `0ec91e0` (as recorded in section 11) |
| Strings output equivalence (scratch script) | identical to the previous function on 24,000 random comparisons; omission flag equal to a ground truth on 44,000 cases |
| One test through a real scan worker (`test_nested_reasons_survive_an_isolated_worker`) | passed: same `scan_status` and reasons as in process |
| ruff (tracked Python files and the new test), mypy (69 files), bandit gate | clean |
| Platforms | macOS arm64 only; no Linux, Windows or CI run; no real OCR |
