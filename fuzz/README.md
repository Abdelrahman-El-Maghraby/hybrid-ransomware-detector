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
