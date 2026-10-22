"""core.tools.trusted_which: helper programs are never taken from the current
directory or from relative PATH entries (a planted 7z.exe in Downloads)."""

import os
import stat

from core.tools import trusted_which


def _exe(path):
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_skips_current_directory_and_relative_entries(tmp_path, monkeypatch):
    planted, good = tmp_path / "downloads", tmp_path / "bin"
    planted.mkdir()
    good.mkdir()
    _exe(planted / "fake7z")
    _exe(good / "fake7z")
    monkeypatch.chdir(planted)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", str(planted), str(good)]))
    assert trusted_which("fake7z") == str(good / "fake7z")


def test_not_found_and_explicit_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert trusted_which("does-not-exist-xyz") is None
    tool = _exe(tmp_path / "tool")
    assert trusted_which(str(tool)) == str(tool)
    assert trusted_which(os.path.join(".", "tool")) is None     # relative path refused
