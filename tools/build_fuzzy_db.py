#!/usr/bin/env python3
"""Build a fuzzy-signature database (TLSH + ssdeep) from confirmed samples.

Run this INSIDE the isolated analysis VM, where the samples are. It only reads
bytes and computes digests; nothing is executed, unpacked or uploaded. The
output JSON holds digests, SHA-256 and family labels only, so it is the one
thing that may leave the VM and be used by the scanner on other machines.

    python tools/build_fuzzy_db.py SAMPLES_DIR --out fuzzy_signatures.json \
           [--labels labels.csv] [--benign BENIGN_DIR] [--merge existing.json]

Family labels: by default the first sub-folder under SAMPLES_DIR
(SAMPLES_DIR/LockBit/x.exe -> "LockBit"). With --labels, a CSV with columns
sha256,family overrides that.

Quality gates:
  * near-duplicates of the same family (TLSH distance < --dedup, default 30)
    are kept once, so the database stays small;
  * with --benign, any signature that matches a benign file under the
    scanner's own thresholds is dropped and reported - such a signature would
    raise false alarms in the field.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detectors.fuzzy_hash import FuzzyHasher, _ppdeep, _tlsh  # noqa: E402

MAX_BYTES = 50 * 1024 * 1024
MIN_BYTES = 512                 # smaller files give digests that match too much
SKIP_NAMES = {".DS_Store", "Thumbs.db", "labels.csv"}


SSDEEP_DEDUP = 90      # ssdeep similarity (0-100) treated as "the same sample"


def _files(root: Path) -> Iterable[Path]:
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and p.name not in SKIP_NAMES:
            yield p


def _labels(path: Optional[Path]) -> Dict[str, str]:
    if not path:
        return {}
    with open(path, newline="", encoding="utf-8") as fh:
        return {r["sha256"].strip().lower(): r["family"].strip()
                for r in csv.DictReader(fh) if r.get("sha256") and r.get("family")}


def _digest(path: Path) -> Optional[Dict]:
    try:
        if not MIN_BYTES <= path.stat().st_size <= MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    d = FuzzyHasher.hash_bytes(data)
    if not d["tlsh"] and not d["ssdeep"]:
        return None                      # too small / too uniform to fingerprint
    d["sha256"] = hashlib.sha256(data).hexdigest()
    return d


def _near_duplicate(d: Dict, family: str, signatures: List[Dict], dedup: int) -> bool:
    """Same family and (TLSH distance < dedup, or - without TLSH, e.g. on Windows
    where python-tlsh has no wheels - ssdeep similarity >= SSDEEP_DEDUP)."""
    for s in signatures:
        if s.get("family") != family:
            continue
        if _tlsh is not None and d["tlsh"] and s.get("tlsh"):
            if _tlsh.diff(d["tlsh"], s["tlsh"]) < dedup:
                return True
        elif _ppdeep is not None and d["ssdeep"] and s.get("ssdeep"):
            if _ppdeep.compare(d["ssdeep"], s["ssdeep"]) >= SSDEEP_DEDUP:
                return True
    return False


def build(samples: Path, labels: Optional[Path] = None, benign: Optional[Path] = None,
          merge: Optional[Path] = None, dedup: int = 30) -> Dict:
    fam_by_hash = _labels(labels)
    signatures: List[Dict] = []
    if merge and merge.exists():
        signatures = [s for s in json.loads(merge.read_text()).get("signatures", [])
                      if s.get("family") != "Example.Placeholder"]
    seen_sha = {s.get("sha256") for s in signatures}
    stats = {"files": 0, "added": 0, "duplicates": 0, "near_duplicates": 0,
             "unhashable": 0, "dropped_benign_match": 0}

    for path in _files(samples):
        stats["files"] += 1
        d = _digest(path)
        if d is None:
            stats["unhashable"] += 1
            continue
        if d["sha256"] in seen_sha:
            stats["duplicates"] += 1
            continue
        rel = path.relative_to(samples)
        family = fam_by_hash.get(d["sha256"]) or (rel.parts[0] if len(rel.parts) > 1 else "unknown")
        if _near_duplicate(d, family, signatures, dedup):
            stats["near_duplicates"] += 1
            continue
        signatures.append({"family": family, "tlsh": d["tlsh"], "ssdeep": d["ssdeep"],
                           "sha256": d["sha256"], "note": f"built from {rel.suffix or 'file'}"})
        seen_sha.add(d["sha256"])
        stats["added"] += 1

    dropped: List[Dict] = []
    if benign:
        checker = FuzzyHasher()
        for path in _files(benign):
            d = _digest(path)
            if d is None:
                continue
            checker.signatures = signatures
            hits = {m.family for m in checker.match(d["tlsh"], d["ssdeep"])}
            if not hits:
                continue
            keep = []
            for s in signatures:
                checker.signatures = [s]
                if checker.match(d["tlsh"], d["ssdeep"]):
                    dropped.append({"family": s["family"], "sha256": s["sha256"],
                                    "benign_file": str(path.relative_to(benign))})
                else:
                    keep.append(s)
            signatures = keep
        stats["dropped_benign_match"] = len(dropped)

    return {"version": 1,
            "_comment": "Fuzzy-hash signatures of confirmed malicious samples, built with "
                        "tools/build_fuzzy_db.py. Digests only - no sample content.",
            "signatures": signatures, "stats": stats, "dropped": dropped}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("samples", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--labels", type=Path)
    ap.add_argument("--benign", type=Path, help="folder of known-good files (false-alarm check)")
    ap.add_argument("--merge", type=Path, help="existing database to extend")
    ap.add_argument("--dedup", type=int, default=30, help="TLSH distance treated as the same sample")
    a = ap.parse_args(argv)
    if not a.samples.is_dir():
        print(f"not a folder: {a.samples}", file=sys.stderr)
        return 2
    db = build(a.samples, a.labels, a.benign, a.merge, a.dedup)
    a.out.write_text(json.dumps(db, indent=2))
    s = db["stats"]
    print(f"{len(db['signatures'])} signature(s) in {a.out}: {s['added']} new from {s['files']} "
          f"file(s); {s['duplicates']} duplicate(s), {s['near_duplicates']} near-duplicate(s), "
          f"{s['unhashable']} too small, {s['dropped_benign_match']} dropped for matching a "
          f"benign file.")
    return 0 if db["signatures"] else 1


if __name__ == "__main__":
    sys.exit(main())
