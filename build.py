#!/usr/bin/env python3
"""
build.py — Automated PyInstaller single-binary packaging & smoke verification.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def build_executable(run_smoke: bool = False) -> int:
    root = Path(__file__).resolve().parent
    spec_file = root / "scanner.spec"
    cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(spec_file)]
    print(f"[+] Building AEGIS SENTINEL executable: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=str(root))
    if res.returncode != 0:
        return res.returncode

    if run_smoke:
        print("[+] Running post-build smoke test suite...")
        smoke = subprocess.run([sys.executable, str(root / "test_smoke.py")], cwd=str(root))
        return smoke.returncode
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-smoke-test", action="store_true")
    args = parser.parse_args()
    sys.exit(build_executable(run_smoke=args.run_smoke_test))