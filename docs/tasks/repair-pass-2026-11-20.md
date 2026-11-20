# Repair pass (2026-11-20)

Owner request: repair confirmed defects and actionable gaps on
`review/production-hardening`, with regression tests and local verification.
Local commits only; nothing pushed, merged, deployed or run on a cluster. No
detection weight, threshold, inspection coverage, limit or schema change.

## Repair queue

Each fixed item has a regression test that failed on the code before its fix
(run here) and passes after it.

| ID | Area | Class | Outcome |
|---|---|---|---|
| FI-1 | Failed scan, auto-quarantine | Confirmed defect | Fixed and verified (`db65a35`) |
| FI-2 | Quarantine deletes a replaced file | Confirmed defect | Fixed and verified (`db65a35`); a narrow window before the unlink remains |
| FI-3 | Canary removal deletes a changed file | Confirmed defect | Fixed and verified (`5562225`) |
| CO-1 | Failed VirusTotal upload read as complete | Confirmed defect | Fixed and verified (`024fffa`) |
| AL-1 | Intel sends an alert twice while the first send runs | Confirmed defect | Fixed and verified (`0056177`) |
| AL-2 | In-process delivery record grows without bound | Confirmed defect (code path) | Fixed and verified (`8a504b5`) |
| TX-1 | Visible-text caps (2 MiB text, 200,000 characters of PDF text and mail body) give no completeness reason | Verification gap | Owner-approved; fixed and verified (`b432f07`); section below |
| API-1 | Upload admission slot on disconnect or cancellation | Suspicion | Not reproduced: the middleware is plain ASGI, the slot is released in `finally`, Starlette closes spooled parts on any exception including cancellation |
| API-2 | Missing or dishonest `Content-Length` | Suspicion | Already handled: `BodyLimit` counts streamed bytes; the file is counted again when written |
| RP-1 | Rule-pack install removing paths outside its folder | Suspicion | Not reproduced: staging and final folders must resolve inside `rulepacks/` |
| PK-1 | Wheel missing rules or data | Suspicion | Already fixed (M15); package data lists the YAML, schema and rule files |

## Details

- **FI-1.** `failure_result` (engine/workers.py) hashed the file after the worker
  failed. A file renamed into place during the scan got its own hash, so the
  TMA-5 guard in `quarantine()` passed and auto-quarantine removed it. The parent
  now stores `file_identity()` at dispatch; a changed file gets no hash and the
  scan-failed reason says so. `_maybe_auto_quarantine` refuses a result without
  `sha256_hash`. Tests: `tests/test_workers.py` (the `swapexit` stand-in renames
  another file into place and exits; an unchanged file keeps its hash).
- **FI-2.** `quarantine()` now records `fstat` of the file it reads and deletes
  the path only while `lstat` shows the same device and inode. Test:
  `tests/test_quarantine.py` swaps the file during verification.
- **FI-3.** `CanaryManager.remove()` deletes only files whose SHA-256 matches the
  deployed canary and that are not links. Test: `tests/test_canary.py`.
- **CO-1.** `engine/external.py`: the upload-without-report case now sets `error`,
  so completeness adds a VirusTotal reason and the intel client does not cache it.
  Scores are unchanged (the VirusTotal signal reads only the detection counts).
  Tests: `tests/test_vt_deadline.py` (refused upload; unfinished analysis).
- **AL-1.** `api/intel.py`: an alert id whose send is running is answered 409
  with `Retry-After`; the outbox treats it as a retryable failure and later gets
  `duplicate`. The id is marked sent in the same lock that ends its in-flight
  mark. Test: `tests/test_alerts.py`.
- **AL-2.** `core/outbox.py`: `_DELIVERED` stores the delivery time and is pruned
  with the `sent/` markers after `OUTBOX_MAX_AGE_HOURS`. Test: `tests/test_alerts.py`.

## TX-1: visible-text limits (owner-approved 2026-11-20)

Approved scope: when an existing limit actually leaves visible text unread,
report the analysis as partial with a reason. Limits, inspection coverage,
weights, scores, verdicts and schema compatibility unchanged.

Paths traced (the text feeds the prompt-injection phrasing check, the LLM and,
for mail, the archive-password search; `PromptGuardLayer` in `engine/layers.py`):

| Limit | Where | Omission means | Reason recorded |
|---|---|---|---|
| Web page / SVG, 2 MiB read (`TEXT_MAX_BYTES`) | `engine/text.py` `_dispatch_text` | bytes after the first 2 MiB exist (one more byte is read to tell) | `text_extraction.not_checked` |
| PDF, 200,000 characters | `_extract_text_from_pdf` | non-blank text past the limit | same |
| PDF, 50 pages | same | more than 50 pages (unread pages may be blank) | same |
| Word (python-docx) and OOXML, 200,000 characters | `_extract_text_from_word`, `_extract_text_from_ooxml` | non-blank text past the limit | same |
| OCR, 20 pages | `_extract_text_with_ocr_from_pdf` | the PDF has more than 20 pages | same |
| OCR time limit | same | stopped after some pages had text (before, this note was dropped once any text was read; with no text it stays a `text_extraction.error`) | same |
| E-mail body, 200,000 characters (`MAX_BODY_CHARS`) | `detectors/mail_analyzer.py` `_judge_body` | non-blank text past the limit | `mail.body_not_checked` |

- `engine/completeness.py` turns either key into a `partial` reason (layer
  `prompt-guard` or `mail`). Container members already pass their reasons up
  (`member_reasons`), so a zip, e-mail or nested member reaches the top level
  with its member path; no container change was needed.
- Already covered, not changed: OOXML parts over 20 MiB (named by the
  hidden-content check, `prompt_guard.not_checked`), messages over the mail size
  limit (`mail.error`), web pages over 20 MiB (`web.truncated`).
- Not reported on purpose: the LLM's 3,000-character excerpt (a summary; the
  phrasing check reads the full extracted text). Not in scope: the printable
  strings pass (`extract_suspicious_strings`, 32 MiB / 200,000 characters) is not
  visible text; recorded in FINDINGS_REGISTER section 4.
- Text inspected: unchanged. The PDF and OOXML loops now stop once non-blank
  text lies past the limit instead of on reaching it, so a text that ends exactly
  at the limit is told apart; the returned text is the same (a PDF may gain one
  trailing page separator) and is still cut at 200,000 characters.
- Result schema: two optional keys under `scan_results` (an open object);
  `schema_version` unchanged.
- Tests: `tests/test_text_limits.py`, 34 tests, real limit values (PDF page text
  from a stand-in reader, OCR helpers replaced, all inputs synthetic under
  `tmp_path`). Below, at and over each limit; white space after a limit; an
  injection phrase before the cut still found with the same score, verdict and
  indicators as when the whole page is read; zip with an e-mail whose body and
  attached page are over the limits (both named at the top), and a zip of
  members exactly at the limits (complete). The final file run against the
  previous code (`0ec91e0`, a temporary worktree): **30 failed, 4 passed**. 25
  failed on the new `omitted` argument or mail field, 5 result-level tests
  because no text reason was recorded (the over-limit page, 51-page PDF, Word
  document and e-mail read `complete`); the 4 that passed expect `complete` at
  or under the limits.

TX-1 verification (macOS 27.2.1 arm64, Python 3.14.2; one run at `b432f07`,
scratch `HOME`/`TMPDIR`, kubectl and 7-Zip on `PATH`, network guard active, the
fuzz file ignored and the same four deselections): **2,203 passed, 0 failed,
8 skipped, 4 deselected**, 598 s, one Starlette deprecation warning, no
ResourceWarning. This is a single suite run (no combined rerun needed: no
Kubernetes test skipped). ruff, mypy (69 files), bandit: clean. Details:
[VERIFICATION_MATRIX](../VERIFICATION_MATRIX.md) section 11.

## Not changed and why

- Kubernetes and Docker: no new local defect found in this pass; cluster and
  Docker runtime verification remain pending (FINDINGS_REGISTER section 5).
- Multi-tenancy: the API has one bearer token, one scanner configuration, one
  outbox and one cache; it is a single-tenant service. RELEASE_SCOPE already
  states "not a SaaS, not multi-tenant"; no document claims tenant isolation.

## Verification (this Mac only: macOS arm64, Python 3.14)

- Safe suite at `5562225` (scratch `HOME` and `TMPDIR`, the documented
  `--ignore` of the fuzz file and the four deselections, under the suite's
  network guard): 2,096 passed, 0 failed, 81 skipped, 4 deselected, 578 s. 73 of
  the skips were `tests/test_kubernetes.py` render tests, because that run's
  `PATH` left out `/usr/local/bin` (kubectl); rerun alone with it: 139 passed.
  Together: **2,169 passed, 0 failed, 8 skipped** (the usual platform skips),
  4 deselected; one known Starlette deprecation warning, no ResourceWarning.
- ruff (tracked Python files), mypy (69 files), bandit gate: clean.
- Evidence types: FI-1 used real worker processes; FI-2, FI-3, CO-1 (fake HTTP
  session), AL-1 (FastAPI test client, stand-in SMTP) and AL-2 ran in process.
  No real VirusTotal, SMTP, Docker, Kubernetes, Linux or Windows run.
