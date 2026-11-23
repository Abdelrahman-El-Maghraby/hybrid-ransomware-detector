"""L-E12 (owner-approved 2026-11-12): the ransom-note file-name check was a
regular expression that took quadratic time on a long name (80 KB of
"decrypt": 2.2 s; a ZIP member name can be 64 KB). It is now checked in linear
time and must match exactly the names the old pattern matched, so detection does
not change. The old pattern is kept here as the reference."""

import random
import re
import time

from detectors.file_integrity import RANSOM_NOTE_RE

OLD = re.compile(
    r"(?i)^(?:_readme\.txt"
    r"|!+[^\\/]*read[_\-\s]?me[^\\/]*!+\.txt"
    r"|[^\\/]*(?:decrypt|ransom|unlock[_\-\s]?files"
    r"|(?:restore|recover)[_\-\s]?(?:my|your|all)?[_\-\s]?(?:files|data)"
    r"|how[_\-\s]?to[_\-\s]?(?:restore|recover|unlock|get[_\-\s]?back)"
    r"|files[_\-\s]?(?:are|were|have[_\-\s]?been)[_\-\s]?encrypted)"
    r"[^\\/]*\.(?:txt|html?|hta|rtf|url))$")

KNOWN = [
    "_readme.txt", "_README.TXT", "!!!READ_ME!!!.txt", "!readme!.txt", "!!read me now!.TXT",
    "HOW_TO_DECRYPT.txt", "decrypt-files.html", "RANSOM_NOTE.hta", "restore_my_files.rtf",
    "recover-your-data.htm", "how to get back files.url", "FILES_ARE_ENCRYPTED.txt",
    "files have been encrypted.html", "unlock files.txt", "how-to-recover.txt",
    "readme.txt", "notes.txt", "decrypt.exe", "a/decrypt.txt", "a\\ransom.txt",
    "!readme.txt", "readme!.txt", "!.txt", "decrypt.txt\n", "_readme.txt\n", "decrypt.txt\n\n",
    "Known_ransom.txt", "ſome-decrypt.txt", "decrypt.tKt", "x.TXT", "decrypt.",
    "decrypt", ".txt", "DECRYPT.TxT", "foo.decrypt.txt", "decrypt.txt.exe", "my.decrypt.html",
    "!!!readme.txt!!!.txt", "!\nreadme\n!.txt", "_readme.txt.txt", "ransom\\.txt",
]
PIECES = ["decrypt", "ransom", "unlock", "files", "file", "restore", "recover", "my", "your",
          "all", "data", "how", "to", "get", "back", "are", "were", "have", "been", "encrypted",
          "read", "me", "readme", "_readme", "!", "!!", ".", ".txt", ".htm", ".html", ".hta",
          ".rtf", ".url", ".exe", "_", "-", " ", "\n", "\t", "/", "\\", "a", "X",
          "K", "ſ", "İ", "DECRYPT", "Files", ".TXT"]


def test_known_names_match_as_before():
    for name in KNOWN:
        assert bool(RANSOM_NOTE_RE.search(name)) == bool(OLD.search(name)), repr(name)


def test_random_names_match_as_before():
    rng = random.Random(12)
    for _ in range(40000):
        name = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 9)))
        assert bool(RANSOM_NOTE_RE.search(name)) == bool(OLD.search(name)), repr(name)


def test_long_names_are_linear():
    for name in ("decrypt" * 12000, "!" + "readme" * 12000 + "!.tx",
                 "ransom " * 12000 + "x", "how to " * 12000 + ".txt"):
        start = time.perf_counter()
        RANSOM_NOTE_RE.search(name)
        assert time.perf_counter() - start < 0.2, name[:20]
