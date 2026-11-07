"""Stage 3 of the production review (PROJECT_REVIEW section 28): operations.

M3  --unlock-folders kept the containment state of suspended processes.
M5  the .env.example VirusTotal placeholder switched VirusTotal on.
M7  --scan-now without a terminal reached its documented exit code 3.
M8  IMAP did not advance past messages that were never scanned.
M14 the backup/restore scripts used the 4.7.0 image on a 4.8 host.
M16 the package, engine, compose and script versions agree; the release gate
    checks the tag.
GUI label: the window shows the engine version."""

import logging
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import RansomwareScanner as RS
from core import containment as C
from engine import secret_store as SS
from engine.config import ENGINE_VERSION

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ M3
def test_unlocking_folders_keeps_the_record_of_suspended_processes(tmp_path, monkeypatch):
    state = tmp_path / "containment.json"
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.txt").write_text("x")
    monkeypatch.setattr(C, "process_table", lambda system="": {9: (1, "evil")})
    C.record_suspended(state, [9], "Linux")
    locked, problems = C.lock_folders([str(docs)], state, system="Linux")
    assert locked and not problems
    restored, problems = C.unlock_folders(state, system="Linux")
    assert restored >= 2 and not problems
    kept = C._load_state(state)
    assert kept == {"suspended": {"9": "evil"}}         # the lock entries are gone
    resumed = []
    monkeypatch.setattr(C, "resume", lambda pid, system="": resumed.append(pid) or "")
    done, problems = C.resume_recorded(state, [9], who="analyst")
    assert done == [9] and resumed == [9] and not problems


def test_unlocking_without_other_state_still_removes_the_file(tmp_path):
    state = tmp_path / "containment.json"
    docs = tmp_path / "docs"
    docs.mkdir()
    C.lock_folders([str(docs)], state, system="Linux")
    C.unlock_folders(state, system="Linux")
    assert not state.exists()


# ------------------------------------------------------------------ M5
PLACEHOLDER = "your-virustotal-api-key-here"


class MemoryKeyring:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def set_password(self, service, name, value):
        self.values[name] = value

    def get_password(self, service, name):
        return self.values.get(name)


def test_the_example_file_switches_no_external_service_on():
    values = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m:
            values[m.group(1)] = m.group(2).strip()
    for name in SS.SECRET_NAMES:
        assert not values.get(name), f"{name} has a value in .env.example"


def test_the_template_placeholder_is_ignored_and_never_migrated(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="RansomwareScanner")
    config = {"virustotal_api_key": PLACEHOLDER}
    sources = SS.apply(config, backend=MemoryKeyring())
    assert config["virustotal_api_key"] == "" and sources["VIRUSTOTAL_API_KEY"] == "unset"
    assert "placeholder" in caplog.text and PLACEHOLDER not in caplog.text
    env = tmp_path / ".env"
    env.write_text(f"VIRUSTOTAL_API_KEY={PLACEHOLDER}\nLLM_PROVIDER=none\n", encoding="utf-8")
    kr = MemoryKeyring()
    moved = SS.migrate_env_file(env, {"VIRUSTOTAL_API_KEY": PLACEHOLDER}, backend=kr)
    assert moved.moved == [] and kr.values == {}


def test_a_placeholder_already_in_the_keyring_is_ignored():
    config = {"virustotal_api_key": ""}
    sources = SS.apply(config, backend=MemoryKeyring({"VIRUSTOTAL_API_KEY": PLACEHOLDER}))
    assert config["virustotal_api_key"] == "" and sources["VIRUSTOTAL_API_KEY"] == "unset"


def test_real_looking_keys_are_kept():
    key = "0123456789abcdef" * 4
    config = {"virustotal_api_key": ""}
    sources = SS.apply(config, backend=MemoryKeyring({"VIRUSTOTAL_API_KEY": key}))
    assert config["virustotal_api_key"] == key and sources["VIRUSTOTAL_API_KEY"] == "keyring"


# ------------------------------------------------------------------ M7
class _Unscanned:
    last_not_scanned = 2

    def run_scan(self):
        return "report"


def test_scan_now_without_a_terminal_exits_3_instead_of_crashing(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", open(__file__, encoding="utf-8"))   # not a TTY
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt="": asked.append(prompt) or "")
    try:
        with pytest.raises(SystemExit) as info:
            RS._scan_or_schedule(SimpleNamespace(scan_file=None, scan_now=True,
                                                 background=False), _Unscanned())
    finally:
        sys.stdin.close()
    assert info.value.code == RS.EXIT_ISOLATION_UNAVAILABLE == 3
    assert asked == []


def test_scan_now_with_closed_input_exits_3(monkeypatch):
    class Tty:
        def isatty(self):
            return True
    monkeypatch.setattr(sys, "stdin", Tty())

    def eof(prompt=""):
        raise EOFError
    monkeypatch.setattr("builtins.input", eof)
    with pytest.raises(SystemExit) as info:
        RS._scan_or_schedule(SimpleNamespace(scan_file=None, scan_now=True, background=False),
                             _Unscanned())
    assert info.value.code == 3


def test_scan_now_in_a_terminal_still_waits_for_enter(monkeypatch):
    class Tty:
        def isatty(self):
            return True
    monkeypatch.setattr(sys, "stdin", Tty())
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt="": asked.append(prompt) or "")

    class Scanned(_Unscanned):
        last_not_scanned = 0
    RS._scan_or_schedule(SimpleNamespace(scan_file=None, scan_now=True, background=False),
                         Scanned())
    assert asked == ["\nPress Enter to exit..."]


# ------------------------------------------------------------------ M14 / M16
def _script_default(name):
    text = (ROOT / "deploy" / name).read_text(encoding="utf-8")
    return re.search(r'image="aegis-sentinel:\$\{AEGIS_VERSION:-([^}]+)\}"', text).group(1)


def test_versions_agree_everywhere():
    pyproject = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(
        encoding="utf-8"), re.M).group(1)
    compose = set(re.findall(r"\$\{AEGIS_VERSION:-([^}]+)\}",
                             (ROOT / "docker-compose.yml").read_text(encoding="utf-8")))
    assert pyproject == ENGINE_VERSION
    assert compose == {ENGINE_VERSION}
    assert _script_default("backup.sh") == _script_default("restore.sh") == ENGINE_VERSION


def test_gui_shows_the_engine_version():
    from aegis_gui.common import APP_VERSION
    assert APP_VERSION == ENGINE_VERSION


@pytest.mark.parametrize("name", ["backup.sh", "restore.sh"])
def test_deploy_scripts_read_the_version_from_env_and_check_the_image_first(name):
    text = (ROOT / "deploy" / name).read_text(encoding="utf-8")
    assert "AEGIS_VERSION=" in text and ".env" in text
    check = text.index('docker image inspect "$image"')
    assert check < text.index("docker run")
    if name == "restore.sh":
        assert check < text.index("docker compose down")


@pytest.mark.skipif(sys.platform == "win32", reason="bash scripts")
@pytest.mark.parametrize("name", ["backup.sh", "restore.sh"])
def test_deploy_scripts_are_valid_bash(name):
    assert subprocess.run(["bash", "-n", str(ROOT / "deploy" / name)]).returncode == 0


def test_the_release_gate_checks_the_tag_against_the_versions():
    gate = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"))["jobs"]["gate"]
    steps = gate["steps"]
    check = next(s for s in steps if "versions" in s.get("name", "").lower())
    assert "GITHUB_REF_NAME" in check["run"] and "pyproject.toml" in check["run"]
    assert "engine/config.py" in check["run"]
    assert any("actions/checkout@" in s.get("uses", "") for s in steps)
