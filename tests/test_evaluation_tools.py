"""A6: the evaluation tooling measures honestly - one file counts once, a file
labelled both ways is left out, a malware family never sits on both sides of the
calibration / test split or of a cross-validation fold, and incomplete scans and
errors are visible. Synthetic files only (nothing here is malware)."""

import csv
import shutil

import pytest

from tests.helpers import make_pe
from tools import splits as S


def test_split_is_deterministic_and_keeps_families_together():
    rows = [{"sha256": f"{i:064x}", "label": "malicious"} for i in range(400)]
    families = {r["sha256"]: f"fam{i % 20}" for i, r in enumerate(rows)}
    first = {r["sha256"]: r["split"] for r in S.select([dict(r) for r in rows], "all", families)}
    again = {r["sha256"]: r["split"] for r in S.select([dict(r) for r in rows], "all", families)}
    assert first == again
    by_family = {}
    for sha, part in first.items():
        by_family.setdefault(families[sha], set()).add(part)
    assert all(len(parts) == 1 for parts in by_family.values())       # never split
    test = S.select([dict(r) for r in rows], "test", families)
    calib = S.select([dict(r) for r in rows], "calibration", families)
    assert len(test) + len(calib) == 400 and not {r["sha256"] for r in test} & {r["sha256"] for r in calib}


def test_unlabelled_files_are_their_own_group_and_the_share_is_about_right():
    groups = [S.group_of(f"{i:064x}") for i in range(3000)]
    share = sum(S.split_of(g) == "test" for g in groups) / len(groups)
    assert 0.26 < share < 0.34
    assert S.group_of("AB" * 32, "LockBit ") == "family:lockbit"
    assert S.group_of("ab" * 32) == "sha256:" + "ab" * 32


def test_dedupe_counts_once_and_drops_contradictory_labels():
    rows = [{"sha256": "a" * 64, "label": "malicious", "path": "1"},
            {"sha256": "A" * 64, "label": "malicious", "path": "copy"},
            {"sha256": "b" * 64, "label": "malicious"}, {"sha256": "b" * 64, "label": "benign"},
            {"sha256": "", "label": "benign", "path": "unreadable"}]
    keep, duplicates, conflicts = S.dedupe(rows)
    assert duplicates == 1 and conflicts == ["b" * 64]
    assert sorted(r.get("path", "") for r in keep) == ["1", "unreadable"]


def test_folds_never_split_a_group():
    groups = ["family:a"] * 5 + ["family:b"] * 7 + [f"sha256:{i}" for i in range(30)]
    folds = S.group_folds(groups, 5)
    assert len({f for g, f in zip(groups, folds) if g == "family:a"}) == 1
    assert len({f for g, f in zip(groups, folds) if g == "family:b"}) == 1


def test_calibration_cross_validation_is_grouped_by_family(monkeypatch):
    from tools import calibrate_weights as C
    rows = [{"label": "malicious", "sha256": f"{i:064x}", "indicators": {"pe_injection": 40.0}}
            for i in range(30)]
    rows += [{"label": "benign", "sha256": f"{i + 100:064x}", "indicators": {}} for i in range(30)]
    families = {r["sha256"]: ("famA" if i < 15 else "famB") for i, r in enumerate(rows[:30])}
    seen = []
    real = C.score_rows

    def spy(test_rows, weights):
        seen.append({families.get(r["sha256"]) for r in test_rows} - {None})
        return real(test_rows, weights)
    monkeypatch.setattr(C, "score_rows", spy)
    res = C.calibrate(rows, min_support=5, families=families)
    assert res["proposed_cross_validated"] is not None
    folds = seen[1:-1]                     # first: current weights; last: proposed, in sample
    for fam in ("famA", "famB"):
        assert sum(fam in s for s in folds) == 1                    # one fold per family


@pytest.fixture
def folders(tmp_path):
    mal, ben = tmp_path / "malicious", tmp_path / "benign"
    mal.mkdir()
    ben.mkdir()
    pe = make_pe(imports={"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory",
                                           "CreateRemoteThread", "ExitProcess"]})
    (mal / "a.exe").write_bytes(pe)
    (mal / "a-copy.exe").write_bytes(pe)                           # duplicate
    (mal / "both.html").write_text("<p>the same file in both folders</p>")
    shutil.copy(mal / "both.html", ben / "both.html")             # contradictory label
    for i in range(3):
        (ben / f"note{i}.html").write_text(f"<p>quarterly figures {i}</p>")
    return mal, ben


def test_evaluate_end_to_end_reports_dedupe_split_and_completeness(tmp_path, folders):
    from tools import evaluate as E
    mal, ben = folders
    out = tmp_path / "out"
    assert E.main(["--malicious", str(mal), "--benign", str(ben), "--out", str(out),
                   "--jobs", "1", "--timeout", "120"]) == 0
    summary = (out / "summary.md").read_text()
    assert "Duplicates (same SHA-256) counted once: 1" in summary
    assert "labelled both malicious and benign, left out: 1" in summary
    assert "## Scan completeness" in summary and "Split: **all**" in summary
    rows = list(csv.DictReader(open(out / "results.csv", encoding="utf-8")))
    assert len(rows) == 4 and {r["label"] for r in rows} == {"malicious", "benign"}
    assert all(r["split"] in ("calibration", "test") and r["scan_status"] for r in rows)

    only_test = tmp_path / "out-test"
    E.main(["--malicious", str(mal), "--benign", str(ben), "--out", str(only_test),
            "--jobs", "1", "--timeout", "120", "--split", "test"])
    if (only_test / "results.csv").exists():
        test_rows = list(csv.DictReader(open(only_test / "results.csv", encoding="utf-8")))
        assert all(r["split"] == "test" for r in test_rows)
