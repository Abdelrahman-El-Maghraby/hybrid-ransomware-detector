# Project map and state of the production-hardening work

A short guide for coming back to this project. It links to the detailed records
instead of repeating them: [README](../README.md) (features and settings),
[ARCHITECTURE](ARCHITECTURE.md) and its [eleven diagrams](architecture/README.md),
[THREAT_MODEL](THREAT_MODEL.md),
[FINDINGS_REGISTER](FINDINGS_REGISTER.md) (every finding's current status),
[PROJECT_REVIEW](PROJECT_REVIEW.md) (the review, sections 28 to 34) and
[HANDOFF](HANDOFF.md) (each repair group, with its commands and results).

## 1. What the project is

Aegis Sentinel (package `hybrid-ransomware-detector`, version 4.8.0) inspects files
without running them: documents, archives, scripts, programs, web pages and
e-mails. Twenty detection layers feed one weighted scoring matrix that gives a
0-100 risk score, a verdict and the reasons. Every result says whether the scan was
complete. Around the scanner: canary tripwires with containment, an encrypted
quarantine vault, alert delivery (webhook, e-mail, JSON Lines) and optional
external opinions (VirusTotal, an LLM, a self-hosted CAPE sandbox).

| Part | Where | Role |
|---|---|---|
| Scan engine | `engine/` | the pipeline (`staging.py`, `layers.py`), isolated worker processes with time and memory limits (`workers.py`), completeness and provenance, configuration and validation, reports, external lookups |
| Detectors | `detectors/` | one module per layer (archives, mail, web, PE, ELF, scripts, macros, hidden content, YARA, QR, ML, ...), the scoring matrix and `indicators.yaml` (weights) |
| Protection and delivery | `core/` | canaries, containment, quarantine, the alert outbox, mailer, cloud upload, IMAP, CAPE and intel clients, rule packs |
| Services | `api/` | the REST API (`server.py`) and, for Docker, the intel service (`intel.py`), the only part that reaches VirusTotal, the LLM or CAPE |
| Desktop | `aegis_gui/`, `gui.py` | the Tk GUI; `RansomwareScanner.py` is the CLI |
| Content | `rules/` | five YARA rule files (25 rules); installed from a wheel as `aegis_sentinel_rules` |
| Operations | `deploy/`, `Dockerfile`, `docker-compose.yml`, `tools/` | Docker edition, backup and restore, deployment check, the optional Kubernetes deployment (`deploy/kubernetes/`, [guide](KUBERNETES.md)), evaluation and build tools |
| Tests | `tests/`, `test_smoke.py` | about 2,000 tests; see section 6 for what runs here |

## 2. What the hardening branch changed

Branch `review/production-hardening`, cut from `3e5a3f2`, contains the accumulated
hardening work. Current publication status and verification are recorded in
[HANDOFF](HANDOFF.md) and the
[publication review](tasks/github-publication-2026-11-22.md). Publishing this
development branch is separate from merging or releasing it. By purpose
(IDs and commits in the register):

- **Security:** checked JSON from workers instead of pickle (M18); the API reads an
  upload only after the token check (M4); intel checks its token before parsing
  (I-x); no work-folder paths or webhook credentials in output (L-A1, L-A7); private
  backups, atomic key writes, a fixed `.dockerignore`; hash-pinned release installs
  and a daily dependency audit (I-B2, I-3); rule packs need a configured key (M27).
- **Detection correctness:** findings no longer dropped by one bad part, a fake
  certificate, trailing dots, right-to-left names or device names (M31, M23, M24,
  M30, M20); first `href` (M19); scans marked partial when a limit or a cut stream
  leaves content unread (H4, M13, L-D2, L-D5, L-D8, L-C7, L-E4); risky archive
  members first (I-2); false positives fixed for listing scripts, quoted commands,
  advisories and single admin commands (M29, M32, S-Y2, S-Y3, S-Y4), with two
  ambiguities left documented (S-Y1, the encryptor strings).
- **Scan reliability:** hangs and slow patterns removed (H1, H2, H5, M22, H-04+,
  L-E12) with a guard test (I-5); failed scans notify and keep earlier findings
  (H6); the sandbox, VirusTotal and LLM waits respect the scan limit, and a worker
  stopped during any of them keeps its static result (M26, M34, I-6); bounded OCR,
  and a stopped worker's helper programs are stopped with it (L-E5); bounded
  package and Word parsing (L-D1, L-E4); Windows liveness (L-E6).
- **Alerts:** GUI scans deliver (H3); alerts survive intel outages, output errors and
  concurrency (M1, M2, M17, L-A8); notices for incomplete and failed scans (L-D7,
  H6); a lost canary registry still alarms (M25).
- **GUI and settings:** one scan-folder setting for GUI and service (M28); honest
  dashboard cards (L-C6, L-G1); safe display of names (L-E9).
- **Packaging and deployment:** a wheel ships and finds its YARA rules (M15);
  deployment scripts, version checks, the server lock (M14, M16, L-A4, L-B2); a model
  from another scikit-learn version is refused.
- **Tests and documentation:** isolation and resource-warning fixes, rule coverage
  tests, and 40-odd documentation corrections (D1 to D42, D26).

## 3. What is fixed, and the evidence

Each fix has a regression test that failed on the code before it and passes after
it (the handoff records each before/after run). The latest full local runs are in
[VERIFICATION_MATRIX](VERIFICATION_MATRIX.md): the documented safe selection with
its commands, revision, skips and deselections. That is evidence for **macOS on Apple Silicon, Python 3.14.2,
synthetic inputs and local stand-in services only**.

## 4. What remains

All in the [register](FINDINGS_REGISTER.md):
- **Confirmed and unresolved** (section 2): only the restricted 27.5 out-of-memory
  failures (VM only). Documented ambiguities (S-Y1, the encryptor strings, the S-Y4
  service tradeoff) and residuals of fixed items are listed there too.
- **Unconfirmed suspicions** (section 3): S-01, S-03, S-04, H-03, OOM-H.
- **External or platform validation** (section 5): CI, Windows, Linux, Docker, real
  CAPE, VirusTotal, LLM, Tesseract and other services, the GUI on a display, ARM64
  and Intel, corpora.
- **Deferred improvements** (section 4) and **owner decisions** (section 6),
  including the retained 15 s sandbox submission threshold (confirmation pending).

## 5. Limitations to keep in mind

- **Effectiveness on real malware is not measured.** Only a false-alarm rate on a
  benign corpus exists (README); the YARA rules are triage heuristics; no ML model
  ships. The false-positive fixes here were checked on synthetic examples only.
- Static analysis by default: run-time behaviour needs the optional sandbox or
  emulation, which belong in an analysis VM.
- Worker isolation limits time and memory, but workers run as the same user as the
  parent: it is not a full security boundary.
- The sandbox, VirusTotal and LLM waits are bounded cooperatively; the guarantee is
  the worker's scan limit, after which the static findings are kept.
- **Not production ready:** CI has not run on this branch, and the platform checks in
  register section 5 are open.

## 6. How to resume

1. Read `AGENTS.md`, `docs/AI_WORKFLOW.md`, this file and the status at the top of
   the handoff. Check `git status`, the branch and HEAD against it. `.arena/` is
   unrelated local data: leave it alone.
2. Do not redo completed work: the register says what is fixed and by which commit.
3. Test locally with the handoff's documented safe-selection command. Never run
   `tests/test_fuzz_parsers.py`, the runaway-memory test or the three intel socket
   tests that hardcode `/tmp`. Check any file list built by matching names before
   running it.
4. The work is **paused for owner review**. Start again only on a new request; the
   owner decisions in register section 6 come first.
