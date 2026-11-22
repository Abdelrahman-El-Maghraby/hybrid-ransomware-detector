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
| Web page / SVG, 2 MiB read (`TEXT_MAX_BYTES`) | `engine/text.py` `_dispatch_text` | bytes after the first 2 MiB exist (one more byte is read to tell); **superseded by TX-R1 below**: visible text after the limit | `text_extraction.not_checked` |
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

## TX-1 completion: review, strings pass (TX-2), web boundary (TX-R1), 2026-11-22

Owner request: independently review `b432f07` and `6cf7d9a`; report the
printable-strings limits (32 MiB read, 200,000 characters returned) the same
way, keeping both limits and avoiding false partials at exact boundaries; check
that the reasons survive nested containers. No change to weights, thresholds,
coverage, verdict logic or schema compatibility.

Review of `b432f07` and `6cf7d9a`:

- PDF (characters and pages), Word/OOXML, OCR (pages, time limit) and e-mail
  body limits: boundary logic correct; `.eml` and `.msg` share `_judge_body`.
  The PDF and OCR page limits report unread pages without knowing whether they
  hold text (reading them is what the limit avoids); kept.
- **TX-R1 (defect):** the web page/SVG limit reported any byte after 2 MiB, so a
  page whose visible text ends at the limit, followed by a newline or closing
  tags, read `partial`. The brief above described that as the design ("one more
  byte is read to tell") while the commit message and README said white space
  after a limit is not an omission. The tests encoded it (`_html(TEXT_MAX + 1)`
  has only `>` after the limit). Fixed: the page is read on to the web layer's
  own 20 MiB limit, only to compare; it is cut when the longer page's visible
  text is not a prefix of the text from the first 2 MiB (an unclosed tag at the
  cut stays in that text as a fragment, so closing markup, comments and scripts
  after the limit do not count; a character split at the limit does). Past
  20 MiB the rest is not compared and the cut is reported.
- Reported results rechecked: the old test file passes 34 of 34 at `6cf7d9a`
  and fails 30, passes 4 at `0ec91e0` (temporary worktrees), as recorded.
- Nested containers: reasons travel up through `member_reasons` with their
  member paths; confirmed for zip in zip, e-mail, attachment (below), including
  through a real scan worker whose result returns as JSON.

TX-2, the strings pass (`engine/text.py` `extract_suspicious_strings`, called by
`PromptGuardLayer` for every file that is not an archive, e-mail included):

| Limit | Omission means | Reason recorded |
|---|---|---|
| 200,000 characters returned (`STRINGS_MAX_CHARS`) | a string with text other than white space lies past the limit in the joined output; reading goes on only until that is known | `text_extraction.strings_not_checked`: "strings after the first 200,000 characters not checked" |
| 32 MiB read (`STRINGS_MAX_BYTES`) | the unread bytes hold a printable run (five or more characters) with text other than white space, including the unread rest of a run cut at the limit; looked for, stopping at the first, never extracted | same: "strings after the first 32 MiB of the file not checked" |

- `engine/completeness.py` makes the key a `partial` reason, layer
  `prompt-guard`. The strings returned are the same as before: the earlier stop
  rule still fixes the output length; checked against the previous function on
  24,000 random inputs (chunk sizes 1 to 64, both limits, run lengths 3 and 5),
  and the omission flag against a ground truth on 44,000 cases (scratch scripts,
  not committed).
- Cost: the output check reads at most one more string. The input check reads
  the unread rest of the file only until the first printable run: immediate for
  ordinary files; a large file of non-printable bytes after 32 MiB (zero padding,
  a disk image) is read once more to its end, as the hashes already do.
  **Superseded by TX-2b below:** the search is now bounded to 32 MiB.
- **Effect:** any file with more than 200,000 characters of printable strings
  now reads `partial`. On this Mac, `/usr/bin/ssh` (1.75 MB), `/usr/lib/dyld`,
  `vim`, two system fonts, three large Python extension modules and the 3.5 MB
  overview PDF reached the limit; `/bin/ls` (0.25 MB), `/bin/zsh` (2.05 MB) and
  small PDFs did not. Scores and verdicts do not change.
- Tests: `tests/test_strings_limits.py` (28) and `tests/test_text_limits.py`
  (49: 15 new, 4 changed). Real limit values for the function (32 MiB files
  under `tmp_path`); below, at and over each limit; white space, short runs and
  runs cut at the limit; every chunk size; the same score and verdict with the
  limit raised; zip, zip, e-mail and attachment (strings, body and member
  reasons at the top with member paths; small members add nothing); the same
  archive through a real scan worker gives the same reasons as in process. On
  `6cf7d9a` (temporary worktree): **35 failed, 42 passed** (26 of 28 strings
  tests; 9 web-page cases); the tests that pass there expect no reason or a
  real cut.

TX-2 verification (macOS 27.2.1 arm64, Python 3.14.2; one run of the code
committed as `2672376`, same environment and selection as for TX-1): **2,246
passed, 0 failed, 8 skipped, 4 deselected**, 589 s, one Starlette deprecation
warning, no ResourceWarning; no existing test changed outcome. ruff, mypy
(69 files), bandit: clean. Details:
[VERIFICATION_MATRIX](../VERIFICATION_MATRIX.md) section 12.

## Cost review and bounded lookahead (TX-R2, TX-2b), 2026-11-22

Owner request: review the resource cost of the two lookaheads; then (approved)
A, stop keeping strings that cannot reach the output, and C, bound the strings
lookahead to 32 MiB (64 MiB inspected in all) and report bytes left after it as
not inspected. B, a faster search, only if equivalent; not done, see below.

Limits by entry point (code read): API uploads 50 MB by default; folder, CLI
and monitor scans have **no file-size limit**; archives 100 MiB in all, e-mail
60 MiB, embedded files 30 MiB; every file in an isolated worker killed at 300 s
with 2 GB of memory (`ISOLATE_SCANS=0`, refused by the production profile, has
neither). Cancelling stops new files and shuts the pool down. The hashes and
YARA already read every byte.

| Path | Before TX-2 | `2672376` (measured) | Now (measured) |
|---|---|---|---|
| Strings, output full then white-space strings | stopped at the output | heap grew with the tail: 11.0 / 31.4 / 61.0 MiB for 1 / 3 / 6 MiB | 3.3 / 4.3 / 4.3 MiB |
| Strings, bytes read on sparse zero files of 64 / 96 / 160 MiB | 32 MiB | 64 / 96 / 160 MiB (0.60 / 0.91 / 1.50 s) | 64 / 64 / 64 MiB (about 0.6 s); 96 and 160 MiB give "not inspected" |
| Web/SVG text, 2 MiB of text then markup to 20 MiB | 0.02 s, 10 MiB peak | 0.39 s, 113 MiB peak | unchanged (fixed 20 MiB bound; the web layer itself took 3.7 s, 40 MiB on the same page) |

Extrapolated, not measured: the worst lookahead (32 MiB of white-space
strings) costs about 1.1 s at the 35 ms per MiB measured on a 4 MiB tail; the
post-output read within the 32 MiB limit about 2 s; heap stays near the
measured 4 MiB. Measurements: tracemalloc peaks (Python allocations, not RSS)
and reads counted through a wrapped `open`, on this Mac, scratch scripts.

- A (TX-R2): after the output length is fixed, a string only decides whether
  something was left out; it is no longer stored.
- C (TX-2b): `STRINGS_LOOKAHEAD_BYTES` = 32 MiB. The search stops at the first
  string with text other than white space (reason "strings after the first
  32 MiB of the file not checked"), at the end of the file (no reason), or at the
  bound: then the file size says whether bytes are left ("file bytes after the
  first 64 MiB not inspected for strings"; nothing is read past the bound and
  nothing is claimed about those bytes). A run cut by the bound counts only if
  its part inside the bound is a string on its own.
- B not done: the bound makes the search cost fixed (about 1 s at most).
- A slicing slip in a follow-up optimisation (keeping the last bytes of a chunk
  shorter than four bytes) was caught by the equivalence script before any
  commit; `test_a_run_cut_at_the_limit_with_tiny_chunks` now fails on it.
- Equivalence (scratch scripts): output identical to the pre-TX function on
  24,000 and 30,000 random cases; reasons equal to a ground truth that models the
  bound on 30,000; within the inspected range (22,825 of them) the same reasons
  as `2672376`.
- Tests added to `tests/test_strings_limits.py` (now 55): bytes read counted
  (inside, exactly at, one byte past the bound; a run ending at and cut by the
  bound; white space then more bytes; chunk sizes 1 to 1,024); sparse files at
  the real 64 MiB (exact, one byte more, a string inside, a string only beyond);
  the memory regression (3 and 6 MiB tails: no growth, under 8 MiB); the new
  reason through zip, zip, e-mail and attachment; the real limits through a
  spawned scan worker (a stored zip with a 64 MiB + 1 byte member).

TX-2b verification: (macOS 27.2.1 arm64, Python 3.14.2; one run of `0a6be7f`,
same environment and selection as for TX-1): **2,273 passed, 0 failed, 8 skipped,
4 deselected**, 606 s, one Starlette deprecation warning, no ResourceWarning.
ruff, mypy (69 files), bandit: clean. Details:
[VERIFICATION_MATRIX](../VERIFICATION_MATRIX.md) section 13.

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
