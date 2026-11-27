# B4 validation guide for the isolated VM

Step-by-step version of section 3 of the
[brief](b4-and-open-findings-2026-11-27.md#3-b4-vm-validation-procedure-owner-run-not-executed-here).
Run it only inside an isolated, snapshotted VM. Nothing here was executed on the
development Mac; the commands were checked for syntax only. No input that causes
an out-of-memory (OOM) failure leaves the VM: only numbers, hashes and logs
without input content.

## 1. Two separate questions

| Question | What answers it | What it cannot show |
|---|---|---|
| **A. Candidate-repair validation:** do B4-O1 and B4-P1 remove the amplification they target? | Steps 6.1, 6.3, 6.4 on the baseline, the B4-only revision and the PR head | That these defects caused the 2026-10-29 OOMs |
| **B. Historical root-cause confirmation:** did these defects cause the 2026-10-29 OOMs? | Replay of a historical input, or of an input reproduced by the baseline campaign, on the baseline and on the B4-only revision (step 6.6) | Anything, if no such input is available |

Fuzz campaigns (step 6.5) are supporting evidence for both, not proof on their
own: a clean hour is one sample of the input space.

## 2. What was repaired

| ID | Defect | Repair | Commits |
|---|---|---|---|
| B4-O1 | olefile reads a stream for its declared size (up to 4 GiB) along its FAT chain; a looping chain re-reads one sector. A 6.6 KB file made it read 4 MiB (9.3 MiB peak); the pattern scales to about 2.3 times the declared size | Every declared read is capped at the file size (`detectors/ole_limits.py`); olefile's FAT/MiniFAT choice and unknown size are kept | `2a6f76c`, `29f2206` |
| B4-P1 | pypdf keeps every decoded stream for the reader's lifetime, so the hidden-text and QR walks held all pages | Released after each page (`release_decoded_streams`) | `63658a3` |

## 3. What remains unconfirmed

- The cause of the three CI OOMs (2026-10-29). The logs show one input growing
  past 4 GB in 11 to 17 s (H1). B4-O1 is the most likely candidate, B4-P1 a
  weaker one; neither is linked to those failures yet.
- Unmeasured hypotheses: YARA matches on repetitive input, ZIP entries
  duplicated onto one member, unusual sector sizes.
- B4-O2 (a DIFAT chain repeating one sector) was measured only with 512-byte
  sectors: time-bound, slow memory growth.

## 4. Original failure artifacts

Checked on 2026-11-27 through the GitHub API, metadata only (`gh api
repos/<owner>/<repo>/actions/runs/<id>/artifacts`):

| Run | Commit | Result |
|---|---|---|
| `40969502006` | `b2e8aea` | `total_count=0` |
| `40974246237` | `673acdc` | `total_count=0` |

No artifacts are currently available from these runs (the workflow kept them
for 14 days). This does not prove that no other copy exists, for example one
downloaded at the time. If a copy of `oom-07598bbb…`, `oom-50152c60…` or
`oom-fb07a247…` turns up, copy it into the VM only and use step 6.6.

**Without them:** question A can be answered fully; question B stays
unconfirmed unless the baseline campaign (step 6.6) reproduces an OOM whose
input can be attributed. The historical cause remains unconfirmed until then,
not unknowable.

## 5. Revisions and differences

| Name | Revision | Dependency lock |
|---|---|---|
| `base` | `673acdc` (the last campaign that ran out of memory) | as at `673acdc` (pypdf 6.21.2) |
| `b4only` | `673acdc` plus `63658a3`, `2a6f76c`, `29f2206` (they apply cleanly; checked with `git cherry-pick --no-commit`) | same as `base` |
| `head` | `64db93f` (PR #49 head, 11/11 checks green; code at `648a80b`) | current (pypdf 6.21.4, other updates) |

`head` differs from `base` by more than B4: other fixes and dependency updates.
**Attribute a difference to B4 only when `base` and `b4only` differ**; a
difference seen only between `base` and `head` may come from anything else.
The harness files (`fuzz/fuzz_b4.py`, `fuzz/fuzz_parsers.py`,
`fuzz/seed_corpus.py`) are identical in all three.

## 6. Procedure

### Prerequisites

- Ubuntu 24.04 x86_64, Python 3.12 (as the workflow), at least 12 GB of RAM
  (so the fuzzer's 4 GiB limit and the 10 GiB address-space backstop below act
  before the kernel's OOM killer), at least 20 GB free disk, snapshot taken.
- No shared folders, no credentials or tokens. Network only for setup; disconnect
  it afterwards.

### Bounds, logging and stop conditions (all steps)

- Every heavy command runs under `prlimit` (address space and CPU) and
  `timeout`, wrapped in `/usr/bin/time -v`. Record `Maximum resident set size`,
  `Exit status` and the elapsed time.
- Never raise a bound to make a step pass. A bound that is hit is a result.
- **Stop** and record before continuing when:
  1. `b4only` or `head` hits a memory or time bound, or a fuzzer writes `oom-*`,
     `crash-*` or `timeout-*`: keep the input in the VM, go to step 6.6;
  2. a control input (step 6.2) fails on any revision: calibration error, fix
     it identically for all revisions first;
  3. the kernel OOM killer ran (`sudo dmesg | grep -i "out of memory"`) or free
     disk falls under 2 GB (`df -h /tmp`): restore the snapshot; add VM memory
     or disk, not looser bounds.

### Setup (network on)

```sh
sudo apt-get update && sudo apt-get install -y 7zip unar libzbar0 git python3.12 python3.12-venv time
git clone https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector.git ~/aegis
cd ~/aegis && git fetch origin review/remaining-issues-2026-11-27
git worktree add ~/b4-base 673acdc
git worktree add ~/b4-b4only 673acdc
(cd ~/b4-b4only && git -c user.name=vm -c user.email=vm@localhost cherry-pick 63658a3 2a6f76c 29f2206)
git worktree add ~/b4-head 64db93f
for d in ~/b4-base ~/b4-b4only ~/b4-head; do
  python3.12 -m venv "$d/.venv"
  timeout 1800 "$d/.venv/bin/python" -m pip install --require-hashes -r "$d/requirements.lock"
  timeout 600 "$d/.venv/bin/python" -m pip install pytest hypothesis
  timeout 600 "$d/.venv/bin/python" -m pip install --require-hashes -r "$d/fuzz/requirements-linux.txt"
done
for d in ~/b4-base ~/b4-b4only ~/b4-head; do (cd "$d" && git rev-parse HEAD && .venv/bin/python -m pip freeze | sha256sum); done
mkdir -p ~/b4-evidence /tmp/b4-inputs
```

Disconnect the network and take a snapshot.

### 6.1 Repair tests on `b4only` and `head`

```sh
for R in ~/b4-b4only ~/b4-head; do
  cd $R && prlimit --as=$((4*1024*1024*1024)) --cpu=900 -- timeout 1200 /usr/bin/time -v .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_ole_limits.py tests/test_prompt_guard.py tests/test_qr.py 2>&1 | tee ~/b4-evidence/6.1-$(basename $R).log
done
```

Expected: all passed (one skip without `cv2` is normal). A failure stops the
procedure; on `b4only` it may reveal a dependency on code outside the three
commits, which is itself a finding.

### 6.2 Fixture generation (from `head`; bounded)

```sh
cd ~/b4-head
prlimit --as=$((2*1024*1024*1024)) --cpu=120 -- timeout 300 .venv/bin/python -c "import sys; sys.path.insert(0,'.'); from tests.test_ole_limits import _with_declared_size as w; open('/tmp/b4-inputs/ole-loop-512m.doc','wb').write(w(512*1024*1024, loop=True)); open('/tmp/b4-inputs/ole-loop-1m.doc','wb').write(w(1024*1024, loop=True))"
prlimit --as=$((3*1024*1024*1024)) --cpu=600 -- timeout 900 .venv/bin/python -c "import sys; sys.path.insert(0,'.'); from tests.helpers import make_pdf_pages as m; open('/tmp/b4-inputs/pdf-12x64m.pdf','wb').write(m([b' '*(64*1024*1024)+b'%d'%i for i in range(12)])); open('/tmp/b4-inputs/pdf-2x1m.pdf','wb').write(m([b' '*(1024*1024)+b'%d'%i for i in range(2)]))"
ls -l /tmp/b4-inputs && sha256sum /tmp/b4-inputs/* | tee ~/b4-evidence/6.2-inputs.sha256
```

The OLE files are a few KB; the PDF generator holds about 0.8 GB while
compressing. `ole-loop-1m.doc` and `pdf-2x1m.pdf` are the controls.

### 6.3 Probes on all three revisions

```sh
for R in ~/b4-base ~/b4-b4only ~/b4-head; do
  cd $R && N=$(basename $R)
  for f in ole-loop-1m.doc ole-loop-512m.doc; do
    prlimit --as=$((2*1024*1024*1024)) --cpu=120 -- timeout 180 /usr/bin/time -v .venv/bin/python -c "import sys; from detectors.macro_analysis import MacroAnalyzer; r=MacroAnalyzer().analyze_file(sys.argv[1]); print('error=', repr(r.error), 'macros=', r.has_macros)" /tmp/b4-inputs/$f 2>&1 | tee ~/b4-evidence/6.3-$N-$f.log
  done
  for f in pdf-2x1m.pdf pdf-12x64m.pdf; do
    prlimit --as=$((2*1024*1024*1024)) --cpu=120 -- timeout 180 /usr/bin/time -v .venv/bin/python -c "import sys; from pathlib import Path; from detectors.prompt_guard import PromptGuard; r=PromptGuard().inspect_hidden_content(Path(sys.argv[1])); print('reasons=', r.reasons)" /tmp/b4-inputs/$f 2>&1 | tee ~/b4-evidence/6.3-$N-$f.log
  done
done
grep -H "Maximum resident\|Exit status" ~/b4-evidence/6.3-*.log
```

| Input | `base` | `b4only` and `head` |
|---|---|---|
| `ole-loop-1m.doc` (control) | exit 0, small peak | exit 0, small peak |
| `ole-loop-512m.doc` | peak about 1.2 GB, or `MemoryError` at the 2 GiB bound | exit 0, peak near the control (under 150 MB) |
| `pdf-2x1m.pdf` (control) | exit 0 | exit 0 |
| `pdf-12x64m.pdf` | peak grows with the pages (above about 768 MB) | about one page above the control (under 250 MB) |

Question A is answered for a defect when `base` shows its amplification and
`b4only` does not.

### 6.4 Product path (isolated worker with a memory limit)

Calibrate first: if a control fails at 512, use 1024 for every revision and
record it.

```sh
for R in ~/b4-base ~/b4-b4only ~/b4-head; do
  N=$(basename $R) && mkdir -p /tmp/b4-scan-$N && cd /tmp/b4-scan-$N
  for f in ole-loop-1m.doc ole-loop-512m.doc pdf-2x1m.pdf pdf-12x64m.pdf; do
    ISOLATE_SCANS=true WORKER_MEMORY_MB=512 LLM_PROVIDER=none prlimit --as=$((4*1024*1024*1024)) --cpu=600 -- timeout 600 /usr/bin/time -v $R/.venv/bin/python $R/RansomwareScanner.py --scan-file /tmp/b4-inputs/$f 2>&1 | tee ~/b4-evidence/6.4-$N-$f.log
  done
done
```

Expected: on `base`, the large inputs end in `scan_failed` with a memory reason
and a healthy parent; on `b4only` and `head`, a normal verdict. Anything else
(a crashed parent, or "Clean" without `scan_failed` on `base`) is a product
finding.

### 6.5 One-hour campaigns (supporting evidence)

The workflow's command, one group at a time (`b4`, then `parsers`), on `b4only`
and on `head`: four hours in total. Check free disk first (`df -h /tmp`, at
least 5 GB).

```sh
G=b4; R=~/b4-head   # repeat for G=parsers and for R=~/b4-b4only
N=$(basename $R) && W=/tmp/aegis-$G-$N && mkdir -p $W/artifacts && cd $R
LLM_PROVIDER=none prlimit --as=$((2*1024*1024*1024)) --cpu=300 -- timeout 600 .venv/bin/python fuzz/seed_corpus.py $G $W/corpus
(LLM_PROVIDER=none prlimit --as=$((10*1024*1024*1024)) --cpu=4200 -- timeout 4000 /usr/bin/time -v .venv/bin/python fuzz/fuzz_$G.py -max_total_time=3600 -timeout=90 -rss_limit_mb=4096 -max_len=1048576 -seed=20261030 -print_final_stats=1 -artifact_prefix=$W/artifacts/ $W/corpus > $W/run.log 2>&1; echo "exit=$?" >> $W/run.log) &
P=$!
while kill -0 $P 2>/dev/null; do echo "$(date +%T) rss_kb=$(ps -eo rss=,args= | grep "[f]uzz/fuzz_$G.py" | sort -n | tail -1 | awk '{print $1}') free_disk=$(df --output=avail -BM /tmp | tail -1)" >> $W/rss.log; sleep 60; done
tail -25 $W/run.log; ls -l $W/artifacts; cp $W/run.log ~/b4-evidence/6.5-$G-$N-run.log; cp $W/rss.log ~/b4-evidence/6.5-$G-$N-rss.log
```

A clean run: `exit=0`, `Done ... in 3600 second(s)`, `stat::peak_rss_mb` well
below 4096, no `oom-*`, `crash-*` or `timeout-*` in `artifacts/`. Any artifact
stops the procedure (step 6.6). A clean run supports, but does not prove, that
B4 no longer occurs.

### 6.6 Baseline reproduction and attribution (question B)

Optional, and the only route to question B without historical inputs: run step
6.5 with `R=~/b4-base`. An OOM is expected there and allowed inside the VM. With
Atheris and native code, the same seed may not reproduce the same input.

Classify any `oom-*` (or a recovered historical input) without parsing it:

```sh
prlimit --as=$((512*1024*1024)) -- timeout 30 python3 -c "import sys,hashlib; d=open(sys.argv[1],'rb').read(); print('size=',len(d),'sha256=',hashlib.sha256(d).hexdigest(),'first_byte=',d[0])" ARTIFACT
```

Target = `first_byte % len(TARGETS)`:

- `b4` (12 targets): 0 integrity-docx, 1 integrity-pdf, 2 macro-docx,
  3 macro-doc, 4 macro-xls, 5 hidden-docx, 6 hidden-pdf, 7 relationships-docx,
  8 relationships-rtf, 9 yara, 10 fuzzy, 11 tlsh-python.
- `parsers` (13 targets; `0xFF` = cpio): 0 f.zip, 1 f.docx hidden,
  2 f.docx relationships, 3 f.pdf hidden, 4 f.eml, 5 f.msg, 6 f.html, 7 f.js,
  8 ELF, 9 f.one, 10 f.bin integrity, 11 f.dmg, 12 f.pkg.

Replay once on every revision (512 MB RSS limit; set `G` to the input's group):

```sh
for R in ~/b4-base ~/b4-b4only ~/b4-head; do
  cd $R && LLM_PROVIDER=none prlimit --as=$((6*1024*1024*1024)) --cpu=300 -- timeout 300 /usr/bin/time -v .venv/bin/python fuzz/fuzz_$G.py -runs=1 -rss_limit_mb=512 ARTIFACT 2>&1 | tee ~/b4-evidence/6.6-replay-$(basename $R).log
done
```

| `base` | `b4only` | `head` | Conclusion |
|---|---|---|---|
| OOM | exit 0 | exit 0 | The B4 repairs remove this OOM (same dependencies). For a historical input: root cause confirmed. For a reproduced input: confirmed for that input, which shares the historical symptom but not necessarily its cause |
| OOM | OOM | exit 0 | Removed by other changes or by dependency updates, not by B4 |
| OOM | OOM | OOM | A third cause; B4 stays open; run step 6.4 with this input |
| exit 0 | any | any | Not reproduced at 512 MB; record the peak and stop attribution |

### 6.7 Optional: B4-O2 with 4096-byte sectors

No ready input. If wanted, ask for a small bounded generator, to be run under
the same bounds as step 6.3.

## 7. Evidence to record (numbers only)

- Per revision: `git rev-parse HEAD`, the `pip freeze` hash, `python --version`,
  `uname -a`, VM memory and disk.
- Per command: the command, exit status, `Maximum resident set size`, duration.
- Per campaign: the last 25 lines of `run.log` (including
  `stat::number_of_executed_units` and `stat::peak_rss_mb`), `rss.log`, the
  `artifacts/` listing.
- Per input: size, SHA-256, first byte and target. The file stays in the VM.

## 8. Closing B4

Closing is an owner decision recorded in `docs/FINDINGS_REGISTER.md` with one
of these wordings:

| Evidence | Register wording |
|---|---|
| Question A answered (6.1, 6.3, 6.4) and a historical input attributed in 6.6 | "Root cause confirmed on a historical input; repairs validated" |
| Question A answered, a reproduced input attributed in 6.6, clean campaigns (6.5) | "Candidate repairs validated; a reproduced OOM is removed by them; historical inputs not available; historical cause not confirmed" |
| Question A answered, nothing attributed, clean campaigns (6.5) | "Candidate repairs validated; no OOM in two one-hour campaigns; historical cause not confirmed" |
| Any OOM on `b4only` or `head`, a failed control, or unclear 6.3 results | Stays open |

Campaigns alone never close B4. Send the contents of `~/b4-evidence/` (logs and
numbers only) so the register and `docs/VERIFICATION_MATRIX.md` can be updated.
