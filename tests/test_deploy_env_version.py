"""L-A4 (check 9): deploy/backup.sh and deploy/restore.sh read AEGIS_VERSION
from .env with a parser for `AEGIS_VERSION=x` and `"x"` only.
`AEGIS_VERSION=4.7.0 # pinned` gave "4.7.0 # pinned", and `export ...` or
`AEGIS_VERSION = ...` gave nothing, so the 4.8.0 default was used whatever
compose reads. Now a trailing comment is accepted, and any other form stops
the script with a clear message. A stand-in `docker` records the image it is
asked for; nothing else runs."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("bash") is None or os.name == "nt",
                                reason="bash scripts")


def _run(tmp_path, script, env_text):
    (tmp_path / "deploy").mkdir(exist_ok=True)
    shutil.copy(ROOT / "deploy" / script, tmp_path / "deploy" / script)
    if env_text is not None:
        (tmp_path / ".env").write_text(env_text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "docker"
    fake.write_text('#!/bin/sh\necho "$@" >> "$(dirname "$0")/calls"\nexit 1\n')
    fake.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "AEGIS_VERSION"}
    env["PATH"] = f"{bin_dir}{os.pathsep}/usr/bin:/bin"
    run = subprocess.run(["bash", str(tmp_path / "deploy" / script), str(tmp_path / "b")],
                         cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    calls = (bin_dir / "calls").read_text() if (bin_dir / "calls").exists() else ""
    return run, calls


@pytest.mark.parametrize("script", ["backup.sh", "restore.sh"])
@pytest.mark.parametrize("env_text, image", [
    ("AEGIS_VERSION=4.7.0 # pinned\n", "aegis-sentinel:4.7.0"),
    ('AEGIS_VERSION="4.7.1"\n', "aegis-sentinel:4.7.1"),
    ("AEGIS_VERSION='4.7.2'   \n", "aegis-sentinel:4.7.2"),
    ("LOG_FORMAT=json\n", "aegis-sentinel:4.8.0"),
    (None, "aegis-sentinel:4.8.0"),
])
def test_the_version_compose_reads_is_the_one_checked(tmp_path, script, env_text, image):
    (tmp_path / "b").mkdir()
    run, calls = _run(tmp_path, script, env_text)
    assert run.returncode == 1 and f"image inspect {image}" in calls, (run.stderr, calls)


@pytest.mark.parametrize("script", ["backup.sh", "restore.sh"])
@pytest.mark.parametrize("env_text", ["export AEGIS_VERSION=4.7.0\n", "AEGIS_VERSION = 4.7.0\n"])
def test_a_form_the_script_cannot_read_stops_it(tmp_path, script, env_text):
    (tmp_path / "b").mkdir()
    run, calls = _run(tmp_path, script, env_text)
    assert run.returncode != 0 and "AEGIS_VERSION" in run.stderr and calls == ""


def test_backup_files_and_folders_are_private(tmp_path):
    """L-A2 (owner-approved 2026-11-12): backup.sh had no `umask 077`, so the
    backup folders and BACKUP_INFO were world-readable and config.tar.gz (the
    keys) was readable until its chmod. A stand-in docker: the image exists and
    no volume is found, so only the config archive and BACKUP_INFO are written."""
    (tmp_path / "deploy" / "secrets").mkdir(parents=True)
    (tmp_path / "deploy" / "secrets" / "api_key").write_text("not-a-real-key")
    shutil.copy(ROOT / "deploy" / "backup.sh", tmp_path / "deploy" / "backup.sh")
    (tmp_path / ".env").write_text("LOG_FORMAT=json\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "docker"
    fake.write_text("#!/bin/sh\nexit 0\n")                 # inspect: found; volume ls: none
    fake.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "AEGIS_VERSION"}
    env["PATH"] = f"{bin_dir}{os.pathsep}/usr/bin:/bin"
    dest = tmp_path / "b"
    run = subprocess.run(["bash", "-c", f"umask 022; exec bash deploy/backup.sh {dest}"],
                         cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    mode = {p: (dest / p).stat().st_mode & 0o777 for p in
            ("", "volumes", "BACKUP_INFO", "config.tar.gz")}
    assert mode == {"": 0o700, "volumes": 0o700, "BACKUP_INFO": 0o600,
                    "config.tar.gz": 0o600}, {k: oct(v) for k, v in mode.items()}
