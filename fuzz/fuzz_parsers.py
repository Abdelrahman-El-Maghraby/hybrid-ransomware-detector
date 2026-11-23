#!/usr/bin/env python3
"""Coverage-guided fuzzing of the file parsers with atheris (libFuzzer).

    pip install atheris
    python fuzz/fuzz_parsers.py -max_total_time=3600 fuzz/corpus/

The first input byte picks the parser, the rest is the file content. A crash is
any exception that escapes a parser (other than its documented errors) - the
input that caused it is written to crash-<hash> for a regression test.
Run it only on a machine you do not mind keeping busy; nothing is executed or
sent anywhere.
"""

import logging
import os
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from detectors.container_extractor import ContainerExtractor
    from detectors.elf_analysis import ElfAnalyzer
    from detectors.embedded_content import EmbeddedContentAnalyzer
    from detectors.file_integrity import FileIntegrityAnalyzer
    from detectors.macos_packages import BudgetExceeded, FormatError, read_cpio
    from detectors.mail_analyzer import MailAnalyzer
    from detectors.prompt_guard import PromptGuard
    from detectors.relationship_scanner import RelationshipScanner
    from detectors.script_analysis import ScriptAnalyzer
    from detectors.web_content import WebContentAnalyzer

# Malformed-input warnings are expected; uncaught exceptions still fail fuzzing.
logging.disable(logging.CRITICAL)

WORK = tempfile.mkdtemp(prefix="aegis_fuzz_")


def _archive(path):
    with ContainerExtractor().open(path) as res:
        return res


TARGETS = [
    ("f.zip", _archive),
    ("f.docx", PromptGuard().inspect_hidden_content),
    ("f.docx", RelationshipScanner().scan_file),
    ("f.pdf", PromptGuard().inspect_hidden_content),
    ("f.eml", MailAnalyzer().analyze),
    ("f.msg", MailAnalyzer().analyze),
    ("f.html", WebContentAnalyzer().analyze),
    ("f.js", ScriptAnalyzer().analyze_file),
    ("f", ElfAnalyzer().analyze_file),
    ("f.one", EmbeddedContentAnalyzer(sevenzip=lambda: None).analyze),
    ("f.bin", FileIntegrityAnalyzer().analyze_file),
    ("f.dmg", _archive),
    ("f.pkg", _archive),
]


COUNTS = [0] * (len(TARGETS) + 1)


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    if len(data) < 2:
        return
    if data[0] == 0xFF:
        try:
            list(read_cpio(data[1:], max_entries=100))
        except (FormatError, BudgetExceeded):
            pass
        COUNTS[-1] += 1
        if COUNTS[-1] == 1:
            print("TARGET completed: cpio", flush=True)
        return
    index = data[0] % len(TARGETS)
    name, fn = TARGETS[index]
    path = os.path.join(WORK, name)
    with open(path, "wb") as fh:
        fh.write(data[1:])
    fn(path)
    COUNTS[index] += 1
    if COUNTS[index] == 1:
        print(f"TARGET completed: {index} {name}", flush=True)
    if sum(COUNTS) % 10000 == 0:
        print(f"TARGET counts: {COUNTS}", flush=True)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
