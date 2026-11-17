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
