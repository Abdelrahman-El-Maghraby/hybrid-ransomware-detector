"""M28: the scan folders, file types and interval chosen in the GUI reach the
background service the GUI installs at login. Before the fix the GUI kept them
in gui_settings.json only, and `RansomwareScanner.py --background` scanned
~/Downloads with the default types: there was no setting it could read.

Now SCAN_DIRECTORIES, FILE_EXTENSIONS and SCAN_INTERVAL_HOURS are read by
engine/config.py, validated, and written by the GUI to the .env file."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from dotenv import dotenv_values, set_key

from engine.config import split_dir_list, split_extension_list
from engine.validation import validate_config
from tests.test_scanner_integration import _config

ROOT = Path(__file__).resolve().parents[1]
KEYS = ("scan_directories", "file_extensions", "scan_interval_hours")


def _fresh_config(env):
    """CONFIG as a new process (the background service) builds it."""
    code = ("import json, engine.config as c; "
            f"print(json.dumps({{k: c.CONFIG[k] for k in {KEYS!r}}})); "
            "print(json.dumps(c.ENV_PROBLEMS))")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
                         check=True, env={**os.environ, **env}).stdout.splitlines()
    return json.loads(out[0]), json.loads(out[1])


def test_the_settings_are_read_from_the_environment(tmp_path):
    a, b = tmp_path / "Documents", tmp_path / "Desktop"
    cfg, problems = _fresh_config({"SCAN_DIRECTORIES": f"{a};{b}",
                                   "FILE_EXTENSIONS": " .PDF, .docx ,", "SCAN_INTERVAL_HOURS": "3"})
    assert cfg == {"scan_directories": [str(a), str(b)], "file_extensions": [".pdf", ".docx"],
                   "scan_interval_hours": 3}
    assert problems == []


def test_set_but_empty_means_no_folders_and_a_bad_interval_is_reported():
    cfg, problems = _fresh_config({"SCAN_DIRECTORIES": "", "SCAN_INTERVAL_HOURS": "often"})
    assert cfg["scan_directories"] == [] and cfg["scan_interval_hours"] == 6
    assert any("SCAN_INTERVAL_HOURS" in p for p in problems)


def test_list_parsing():
    assert split_dir_list(" ~/a ; ;/b ") == [os.path.expanduser("~/a"), "/b"]
    assert split_extension_list(".PDF,,.Js ") == [".pdf", ".js"]


def test_validation_names_the_settings(tmp_path):
    missing = str(tmp_path / "gone")
    errors, warnings = validate_config(_config(tmp_path, scan_directories=[missing],
                                               scan_interval_hours=0, file_extensions=["pdf"]))
    assert any(e.startswith("SCAN_INTERVAL_HOURS=0") for e in errors)
    assert any("FILE_EXTENSIONS" in e for e in errors)
    assert f"SCAN_DIRECTORIES: {missing} is not a folder (skipped by scans)" in warnings
    _, docker = validate_config(_config(tmp_path, scan_directories=[missing],
                                        intel_socket="/run/aegis/intel.sock"))
    assert not any("SCAN_DIRECTORIES" in w for w in docker)


# ------------------------------------------------------------------ the GUI side
@pytest.fixture
def GI():
    pytest.importorskip("customtkinter")
    from aegis_gui import integration
    return integration


def test_the_gui_choice_reaches_a_freshly_built_config(tmp_path, GI):
    env = tmp_path / ".env"
    docs = tmp_path / "Documents"
    docs.mkdir()
    cfg = _config(tmp_path)
    choice = {"scan_directories": [str(docs)], "file_extensions": [".pdf", ".eml"],
              "scan_interval_hours": 12}
    assert GI.save_scan_settings(cfg, choice, env, set_key=set_key) == []
    assert {k: cfg[k] for k in KEYS} == choice
    fresh, _ = _fresh_config({k: v for k, v in dotenv_values(env).items() if v is not None})
    assert fresh == choice


@pytest.mark.skipif(os.name == "nt", reason="':' is a drive separator on Windows")
def test_a_folder_name_with_a_list_separator_is_not_saved(tmp_path, GI):
    written = {}
    cfg = _config(tmp_path)
    errors = GI.save_scan_settings(
        cfg, {"scan_directories": [str(tmp_path / "a:b")], "file_extensions": [".pdf"],
              "scan_interval_hours": 6}, tmp_path / ".env",
        set_key=lambda path, name, value: written.__setitem__(name, value))
    assert errors and "list separator" in errors[0] and written == {}


@pytest.fixture
def store(tmp_path, monkeypatch):
    pytest.importorskip("customtkinter")
    from aegis_gui import state
    file = tmp_path / "gui_settings.json"
    monkeypatch.setattr(state, "SETTINGS_FILE", file)
    for name in ("SCAN_DIRECTORIES", "FILE_EXTENSIONS", "SCAN_INTERVAL_HOURS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setitem(state.RS.CONFIG, "scan_directories", ["/shared"])
    monkeypatch.setitem(state.RS.CONFIG, "file_extensions", [".pdf"])
    monkeypatch.setitem(state.RS.CONFIG, "scan_interval_hours", 6)

    def make(saved):
        file.write_text(json.dumps(saved), encoding="utf-8")
        return state.SettingsStore()
    return make


GUI_ONLY = {"scan_directories": ["/gui"], "file_extensions": [".eml"], "scan_interval_hours": 2}


def test_a_shared_setting_wins_over_the_gui_copy(store, monkeypatch):
    monkeypatch.setenv("SCAN_DIRECTORIES", "/shared")
    monkeypatch.setenv("FILE_EXTENSIONS", ".pdf")
    monkeypatch.setenv("SCAN_INTERVAL_HOURS", "6")
    s = store(GUI_ONLY)
    assert [s[k] for k in KEYS] == [["/shared"], [".pdf"], 6]
    assert s.unsaved_scan_settings is False


def test_an_older_gui_choice_is_kept_and_marked_for_saving(store):
    s = store(GUI_ONLY)
    assert [s[k] for k in KEYS] == [["/gui"], [".eml"], 2]
    assert s.unsaved_scan_settings is True
    assert store({}).unsaved_scan_settings is False          # first run: the defaults
