"""L-C5 (check 20): the launchd agent was built by pasting paths into XML, so a
home or install path with "&" or "<" gave a file that does not parse, and
"Configured to run at macOS login" was printed although `launchctl load`
failed. No real launchctl runs here: subprocess.run is a stand-in."""

import plistlib
import sys
from types import SimpleNamespace

import pytest

import RansomwareScanner as RS

# launchd agents exist only on macOS, and the fixture's "<x>.py" is not a valid
# Windows file name.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="launchd agent paths")


@pytest.fixture
def agent(tmp_path, monkeypatch):
    home = tmp_path / "R&D <team>"
    monkeypatch.setattr(RS.Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(RS, "_resolve_python_and_script",
                        lambda: (str(home / "py & co/python3"), str(home / "app/<x>.py")))
    calls = []

    def run(load_rc):
        def fake(cmd, **kw):
            calls.append(cmd)
            rc = load_rc if cmd[1] == "load" else 0
            return SimpleNamespace(returncode=rc, stdout="", stderr="load failed" if rc else "")
        monkeypatch.setattr(RS.subprocess, "run", fake)
    return home, run, calls


def _plist(home):
    return home / "Library" / "LaunchAgents" / f"{RS.AUTOSTART_LABEL}.plist"


def test_paths_with_xml_characters_give_a_valid_agent(agent):
    home, run, _ = agent
    run(0)
    assert RS.setup_macos_autostart() is True
    data = plistlib.loads(_plist(home).read_bytes())
    assert data["ProgramArguments"] == [str(home / "py & co/python3"),
                                        str(home / "app/<x>.py"), "--background"]
    assert data["Label"] == RS.AUTOSTART_LABEL and data["RunAtLoad"] is True


def test_a_failing_launchctl_is_reported(agent, capsys):
    home, run, calls = agent
    run(1)
    assert RS.setup_macos_autostart() is False
    assert "Configured to run" not in capsys.readouterr().out
    assert calls[-1][:2] == ["launchctl", "load"]
