# Fuzzing the parsers

The scanner reads hostile files by design, so every parser is fuzzed.

**In the test suite** (`tests/test_fuzz_parsers.py`, Hypothesis): each parser gets
random bytes and mutated valid samples and must return a result quickly. Longer run:

    FUZZ_RANDOM=1 FUZZ_EXAMPLES=5000 python -m pytest tests/test_fuzz_parsers.py

**Coverage-guided** (`fuzz/fuzz_parsers.py`, atheris / libFuzzer), for hours:

    pip install atheris
    mkdir -p fuzz/corpus && python fuzz/fuzz_parsers.py -max_total_time=3600 fuzz/corpus/

Findings so far (4.4.0-beta.2): a mutated ZIP made `pyzipper` raise
`NotImplementedError`, which ended the whole scan of that file. Fixed in two
places: archive walking now records "could not be parsed completely", and every
pipeline layer runs inside a guard so one failing parser costs only that layer's
evidence (`layer_errors` in the result). A known parser hang in PyPDF2 3.0.x
(CVE-2023-36464) was removed by moving to `pypdf`.

## Stage 3 long validation

`parser-fuzz` runs two independent one-hour Linux / Python 3.12 campaigns when
parser/application dependencies, this directory or its workflow change in a PR,
or on manual dispatch. A documentation-only follow-up checkpoint skips new
campaigns and retains the explicitly recorded earlier run; it is not a new fuzz
pass. The
validation-only Atheris wheel is hash-pinned in `requirements-linux.txt`; shipped
application locks are unchanged. See [Atheris](https://github.com/google/atheris)
for instrumentation and native-extension limitations.

- `fuzz_parsers.py`: the existing document/mail/web/script/ELF/OneNote/ZIP paths,
  CPIO, plus generated DMG and PKG inputs exercising archive extraction.
- `fuzz_b4.py`: document/PDF integrity, Office macro parsing, hidden content,
  DOCX/RTF relationships, bundled YARA rules, fuzzy hashing and Python TLSH.
  Dependencies and compiled rules are required, so an absent layer fails startup.
- `seed_corpus.py`: generates benign fixtures from repository builders. No
  sample download, document execution or provider call. A benign OLE message
  exercises macro-container rejection; this is not valid VBA/P-code coverage.

Example in a disposable Linux validation environment with the application lock,
pytest, hypothesis and `requirements-linux.txt` installed:

```sh
python fuzz/seed_corpus.py parsers /tmp/aegis-fuzz-parsers
python fuzz/fuzz_parsers.py -max_total_time=3600 -timeout=90 -rss_limit_mb=4096 -max_len=1048576 -seed=20261030 -print_final_stats=1 /tmp/aegis-fuzz-parsers
python fuzz/seed_corpus.py b4 /tmp/aegis-fuzz-b4
python fuzz/fuzz_b4.py -max_total_time=3600 -timeout=90 -rss_limit_mb=4096 -max_len=1048576 -seed=20261030 -print_final_stats=1 /tmp/aegis-fuzz-b4
```

Use fresh corpora for this harness version: selector indexes changed when the
archive targets were added. CI retains logs, evolved corpora and failure inputs
for 14 days. `TARGET completed` confirms each selected entry point returned;
periodic counters show distribution, not branch coverage. A timeout, resource
limit or exception fails the job and must be investigated; do not call it a pass.
The 90-second per-input / 4 GiB process / 1 MiB input limits bound this validation,
not the product's worker settings. Native libraries and 7-Zip are exercised but
not sanitizer-instrumented; CHM has no generated valid seed, and no claim of
complete parser or native-code coverage follows from a successful campaign.
