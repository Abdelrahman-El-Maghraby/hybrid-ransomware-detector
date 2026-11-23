"""L-C1 and L-C2 (checks 13 and the --scan-file probe).

L-C1: --import-database copied the file over the working database before
checking its header, then printed "Successfully imported" and exited 0 for a
file without the required columns. Now nothing is replaced unless the header
is valid, and a failed import exits 1.

L-C2: --scan-file with a missing file printed an error and exited 0. It now
exits 1. Exit code 2 keeps its documented meanings (configuration error,
tripped canary, usage error); exit 3 is unchanged."""

import os
import subprocess
import sys
from pathlib import Path

import RansomwareScanner as RS

ROOT = Path(__file__).resolve().parents[1]
GOOD = "FileName,md5Hash,Benign\nevil.docx,0123456789abcdef0123456789abcdef,0\n"


def test_a_bad_header_never_replaces_the_working_database(tmp_path):
    db = tmp_path / "data_file.csv"
    db.write_text(GOOD)
    bad = tmp_path / "bad.csv"
    bad.write_text("name,hash\nx,y\n")
    out = RS.import_hash_database(str(bad), str(db))
    assert out["ok"] is False and out["missing_columns"] == ["FileName", "md5Hash", "Benign"]
    assert db.read_text() == GOOD                                 # untouched


def test_a_valid_database_is_imported(tmp_path):
    src, db = tmp_path / "new.csv", tmp_path / "data_file.csv"
    src.write_text(GOOD)
    out = RS.import_hash_database(str(src), str(db))
    assert out["ok"] and out["entries"] == 1 and db.read_text() == GOOD
    assert not list(tmp_path.glob("*.tmp"))


def _cli(tmp_path, *args):
    # The CLI prints UTF-8 symbols; decode them as UTF-8 here too (Windows would
    # otherwise use its ANSI code page and lose the output).
    env = {**os.environ, "HOME": str(tmp_path / "home"), "USERPROFILE": str(tmp_path / "home"),
           "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, str(ROOT / "RansomwareScanner.py"), *args],
                          cwd=tmp_path, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=120)


def test_cli_failed_import_and_missing_scan_file_exit_1(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("name,hash\nx,y\n")
    run = _cli(tmp_path, "--import-database", str(bad))
    assert run.returncode == 1 and "Successfully" not in run.stdout, run.stdout[-500:]
    run = _cli(tmp_path, "--import-database", str(tmp_path / "missing.csv"))
    assert run.returncode == 1
    run = _cli(tmp_path, "--scan-file", str(tmp_path / "does-not-exist.pdf"))
    assert run.returncode == 1 and "file not found" in run.stdout
