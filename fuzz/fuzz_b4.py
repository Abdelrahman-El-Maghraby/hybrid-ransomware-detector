#!/usr/bin/env python3
"""Coverage-guided B4 entry points; generated inputs are only statically parsed."""

import logging
import os
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from detectors import fuzzy_hash, macro_analysis, tlsh_py
    from detectors.file_integrity import FileIntegrityAnalyzer
    from detectors.prompt_guard import PromptGuard
    from detectors.relationship_scanner import RelationshipScanner
    from detectors.yara_engine import YaraEngine

# Malformed-input warnings are expected; uncaught exceptions still fail fuzzing.
logging.disable(logging.CRITICAL)

WORK = Path(tempfile.mkdtemp(prefix="aegis_b4_fuzz_"))
YARA = YaraEngine(str(Path(__file__).resolve().parents[1] / "rules"))
assert macro_analysis.OLEVBA_AVAILABLE, "oletools must be installed"
assert fuzzy_hash._tlsh is not None and fuzzy_hash._ppdeep is not None
assert YARA._rules is not None, "bundled YARA rules must compile"


def _tlsh(path):
    data = Path(path).read_bytes()
    digest = tlsh_py.hash(data)
    if digest != "TNULL":
        assert tlsh_py.diff(digest, digest) == 0
    # Invalid digest strings have a documented ValueError contract.
    try:
        tlsh_py.diff(data[:72].decode("latin-1"), digest)
    except ValueError:
        pass


# Keep this order in sync with seed_corpus.py. Filename extensions exercise the
# actual format gates; an arbitrary .bin would bypass the Office parsers.
TARGETS = [
    ("integrity-docx", "f.docx", FileIntegrityAnalyzer().analyze_file),
    ("integrity-pdf", "f.pdf", FileIntegrityAnalyzer().analyze_file),
    ("macro-docx", "f.docx", macro_analysis.MacroAnalyzer().analyze_file),
    ("macro-doc", "f.doc", macro_analysis.MacroAnalyzer().analyze_file),
    ("macro-xls", "f.xls", macro_analysis.MacroAnalyzer().analyze_file),
    ("hidden-docx", "f.docx", PromptGuard().inspect_hidden_content),
    ("hidden-pdf", "f.pdf", PromptGuard().inspect_hidden_content),
    ("relationships-docx", "f.docx", RelationshipScanner().scan_file),
    ("relationships-rtf", "f.rtf", RelationshipScanner().scan_file),
    ("yara", "f.bin", YARA.scan_file),
    ("fuzzy", "f.bin", fuzzy_hash.FuzzyHasher().analyze_file),
    ("tlsh-python", "f.bin", _tlsh),
]
COUNTS = [0] * len(TARGETS)


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    if len(data) < 2:
        return
    index = data[0] % len(TARGETS)
    label, name, fn = TARGETS[index]
    path = WORK / name
    path.write_bytes(data[1:])
    fn(str(path))
    COUNTS[index] += 1
    if COUNTS[index] == 1:
        print(f"TARGET completed: {label}", flush=True)
    if sum(COUNTS) % 10000 == 0:
        print(f"TARGET counts: {COUNTS}", flush=True)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
