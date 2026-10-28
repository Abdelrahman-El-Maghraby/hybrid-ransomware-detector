"""Shared by tools/evaluate.py and tools/calibrate_weights.py: one hash per file,
and one deterministic split of labelled files into a calibration part and a test
part, grouped by malware family.

Why grouped: samples of one family share code. With one family on both sides,
weights fitted on the calibration part look better on the test part than they
will on a family nobody has seen. Every file of a family therefore lands in the
same part; a file without a family label is its own group (its SHA-256).

Why deterministic: the same file is always in the same part, on every machine
and every run, so weights fitted on "calibration" are never evaluated on files
they were fitted on.
"""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SPLITS = ("all", "calibration", "test")
TEST_SHARE = 0.3
SEED = "aegis-eval-1"


def sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    """The file's SHA-256 (the bytes are read, never executed)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def load_families(path: Optional[str]) -> Dict[str, str]:
    """sha256 -> family from a labels CSV (sha256 first, family third: the
    MalwareBazaar export); {} without a file."""
    fam: Dict[str, str] = {}
    if path and Path(path).expanduser().exists():
        with open(Path(path).expanduser(), newline="") as f:
            for row in csv.reader(f):
                if len(row) >= 3 and len(row[0]) == 64:
                    fam[row[0].lower()] = row[2]
    return fam


def group_of(sha256: str, family: str = "") -> str:
    family = (family or "").strip().lower()
    return f"family:{family}" if family else f"sha256:{sha256.lower()}"


def split_of(group: str, test_share: float = TEST_SHARE, seed: str = SEED) -> str:
    """'test' or 'calibration' for a group, the same everywhere."""
    bucket = int(hashlib.sha256(f"{seed}|{group}".encode()).hexdigest()[:8], 16) / 0x100000000
    return "test" if bucket < test_share else "calibration"


def dedupe(rows: Iterable[Dict], key: str = "sha256",
           label: str = "label") -> Tuple[List[Dict], int, List[str]]:
    """(unique rows, duplicates dropped, hashes labelled both benign and malicious).
    A file present twice would count twice in every rate; one labelled both ways
    says nothing about either and is left out entirely. Rows without a hash (they
    could not be read) are kept as they are."""
    first: Dict[str, Dict] = {}
    labels: Dict[str, set] = {}
    keep: List[Dict] = []
    duplicates = 0
    for r in rows:
        h = str(r.get(key) or "").lower()
        if not h:
            keep.append(r)
            continue
        if r.get(label) in labels.setdefault(h, set()):
            duplicates += 1                     # the same file again, same label
            continue
        labels[h].add(r.get(label))
        first.setdefault(h, r)
    conflicts = sorted(h for h, ls in labels.items() if len(ls) > 1)
    keep += [r for h, r in first.items() if h not in conflicts]
    return keep, duplicates, conflicts


def group_folds(groups: List[str], folds: int, seed: str = SEED) -> List[int]:
    """A fold number per row such that one group never spans two folds."""
    return [int(hashlib.sha256(f"{seed}|fold|{g}".encode()).hexdigest()[:8], 16) % folds
            for g in groups]


def select(rows: Iterable[Dict], split: str, families: Optional[Dict[str, str]] = None,
           test_share: float = TEST_SHARE) -> List[Dict]:
    """The rows of one split ('all' keeps every row). Each row needs 'sha256';
    the family comes from `families` (sha256 -> family) for malicious rows."""
    families = families or {}
    out = []
    for r in rows:
        sha = str(r.get("sha256") or "").lower()
        fam = families.get(sha, "") if r.get("label") == "malicious" else ""
        r["split"] = split_of(group_of(sha, fam), test_share) if sha else "calibration"
        if split == "all" or r["split"] == split:
            out.append(r)
    return out
