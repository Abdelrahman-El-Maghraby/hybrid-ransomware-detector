"""tools/build_fuzzy_db.py: digests from a labelled sample folder. The "samples"
are random bytes; variants of a family differ in a few places."""

import json
import random

import pytest

from detectors import FUZZY_AVAILABLE
from detectors.fuzzy_hash import FuzzyHasher, _ppdeep, _tlsh
from tools import build_fuzzy_db
from tools.build_fuzzy_db import build, main

pytestmark = pytest.mark.skipif(not FUZZY_AVAILABLE, reason="python-tlsh / ppdeep not installed")
# The corpus below spreads 20 edits over each variant: TLSH still groups them,
# ssdeep (block hashes) does not. (Without python-tlsh the built-in port is used.)
needs_tlsh = pytest.mark.skipif(_tlsh is None, reason="no TLSH implementation")


def family(seed, n, size=40_000):
    rng = random.Random(seed)
    base = bytearray(rng.getrandbits(8) for _ in range(size))
    out = []
    for i in range(n):
        v = bytearray(base)
        for _ in range(20):                       # a few small edits per variant
            v[rng.randrange(size)] = rng.getrandbits(8)
        out.append(bytes(v))
    return out


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "samples"
    for name, seed in (("FamA", 1), ("FamB", 2)):
        d = root / name
        d.mkdir(parents=True)
        for i, data in enumerate(family(seed, 3)):
            (d / f"s{i}.bin").write_bytes(data)
    (root / "FamA" / "copy.bin").write_bytes((root / "FamA" / "s0.bin").read_bytes())
    (root / "FamA" / "tiny.bin").write_bytes(b"abc")
    return root


@needs_tlsh
def test_families_dedup_and_stats(corpus):
    db = build(corpus)
    fams = sorted(s["family"] for s in db["signatures"])
    assert fams == ["FamA", "FamB"]                       # variants collapse to one each
    st = db["stats"]
    assert st["files"] == 8 and st["duplicates"] == 1 and st["unhashable"] == 1
    assert st["near_duplicates"] == 4
    assert all(len(s["sha256"]) == 64 for s in db["signatures"])


@needs_tlsh
def test_signatures_match_new_variants_through_the_scanner_hasher(corpus, tmp_path):
    out = tmp_path / "db.json"
    assert main([str(corpus), "--out", str(out)]) == 0
    hasher = FuzzyHasher(signature_db_path=str(out))
    unseen = family(1, 5)[4]                              # a variant not in the folder
    d = FuzzyHasher.hash_bytes(unseen)
    assert {m.family for m in hasher.match(d["tlsh"], d["ssdeep"])} == {"FamA"}


@needs_tlsh
def test_signature_matching_a_benign_file_is_dropped(corpus, tmp_path):
    benign = tmp_path / "benign"
    benign.mkdir()
    (benign / "tool.bin").write_bytes(family(2, 4)[3])   # "benign" lookalike of FamB
    db = build(corpus, benign=benign)
    assert [s["family"] for s in db["signatures"]] == ["FamA"]
    assert db["dropped"][0]["family"] == "FamB"


@needs_tlsh
def test_labels_csv_overrides_folder_names_and_merge_extends(corpus, tmp_path):
    first = build(corpus)
    sha = next(s["sha256"] for s in first["signatures"] if s["family"] == "FamB")
    labels = tmp_path / "labels.csv"
    labels.write_text(f"sha256,family\n{sha},Conti\n")
    relabelled = build(corpus, labels=labels)
    assert "Conti" in {s["family"] for s in relabelled["signatures"]}

    prev = tmp_path / "prev.json"
    prev.write_text(json.dumps(first))
    merged = build(corpus, merge=prev)
    assert len(merged["signatures"]) == 2 and merged["stats"]["duplicates"] >= 2


@pytest.mark.skipif(_ppdeep is None, reason="ppdeep not installed")
def test_without_tlsh_near_duplicates_collapse_by_ssdeep(tmp_path, monkeypatch):
    monkeypatch.setattr(build_fuzzy_db, "_tlsh", None)
    monkeypatch.setattr(FuzzyHasher, "hash_bytes", staticmethod(
        lambda data, _orig=FuzzyHasher.hash_bytes: {**_orig(data), "tlsh": None}))
    rng = random.Random(7)
    base = bytearray(rng.getrandbits(8) for _ in range(40_000))
    d = tmp_path / "samples" / "FamC"
    d.mkdir(parents=True)
    for i in range(3):                       # one flipped byte each: ssdeep ~99
        v = bytearray(base)
        v[rng.randrange(len(v))] ^= 0xFF
        (d / f"v{i}.bin").write_bytes(bytes(v))
    (d / "other.bin").write_bytes(bytes(rng.getrandbits(8) for _ in range(40_000)))
    db = build(tmp_path / "samples")
    assert db["stats"]["near_duplicates"] == 2
    assert [s["family"] for s in db["signatures"]] == ["FamC", "FamC"]
    assert all(s["tlsh"] is None and s["ssdeep"] for s in db["signatures"])
