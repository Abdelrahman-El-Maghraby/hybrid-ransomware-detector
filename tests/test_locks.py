"""4.8 hash-pinned dependencies (PR-12): every package the image and the release
builds install is pinned to a version and to the SHA-256 of its files, and those
installs run in pip's --require-hashes mode, so a substituted file stops the build."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
LOCKS = ("requirements.lock", "requirements-server.lock", "requirements-build.lock")
_PIN = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;\\]+)")


def _entries(name):
    """{package: (version, number of hashes)} of a lock file."""
    out, current = {}, None
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        m = _PIN.match(line)
        if m:
            current = m.group(1).lower()
            out[current] = [m.group(2), 0]
        elif current and line.strip().startswith("--hash=sha256:"):
            assert re.fullmatch(r"--hash=sha256:[0-9a-f]{64}( \\)?", line.strip()), line
            out[current][1] += 1
        elif line.strip() and not line.lstrip().startswith("#"):
            assert line.startswith(("    ", "\t")) or _PIN.match(line), f"{name}: {line!r}"
    return out


@pytest.mark.parametrize("name", LOCKS)
def test_every_pin_has_hashes_and_no_local_path(name):
    entries = _entries(name)
    assert entries and all(n >= 1 for _, n in entries.values()), \
        [k for k, (_, n) in entries.items() if n == 0]
    text = (ROOT / name).read_text(encoding="utf-8")
    assert not re.search(r"/Users/|/home/|/private/|[A-Z]:\\\\", text)
    assert "pip install --require-hashes -r " + name in text            # how to use it


def test_the_locks_agree_and_the_image_gets_only_server_packages():
    main, server, build = (_entries(n) for n in LOCKS)
    for lock in (server, build):
        shared = set(lock) & set(main)
        assert {k: lock[k][0] for k in shared} == {k: main[k][0] for k in shared}
    for desktop_only in ("boto3", "customtkinter", "scikit-learn", "joblib", "watchdog"):
        assert desktop_only in main and desktop_only not in server
    assert "pyinstaller" in build and "fastapi" in server and "yara-python" in server


def test_the_image_and_the_release_builds_install_in_hash_mode():
    docker = (ROOT / "Dockerfile").read_text()
    assert "pip install --no-cache-dir --require-hashes -r requirements-server.lock" in docker
    assert "-c requirements.lock" not in docker                       # constraints skip hashes
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    steps = {s.get("name", ""): s.get("run", "") for s in release["jobs"]["build"]["steps"]}
    install = steps["Install pinned dependencies + PyInstaller (hash-checked)"]
    assert "--require-hashes -r requirements.lock" in install
    assert "--require-hashes -r requirements-build.lock" in install
    assert "while read" not in install                                 # no per-package loop


def test_quality_jobs_keep_hash_mode_and_audit_every_lock():
    text = (ROOT / ".github/workflows/quality.yml").read_text()
    assert not re.search(r"install (--require-hashes )?-r requirements\.lock \S", text)
    for line in re.findall(r".*-r requirements\.lock.*", text):
        if "pip install" in line:
            assert "--require-hashes" in line, line
    assert "requirements-server.lock requirements-build.lock" in text
