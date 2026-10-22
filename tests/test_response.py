"""core/response.py: actions on a canary trip. No command really runs here: a
recording runner stands in for subprocess.run."""

import json
import os
import stat
import subprocess

import pytest

from core import response
from core.response import NetworkOffAction, configured_actions, respond

ALERT = {"summary": "1 canary changed", "findings": [{"path": "/x", "status": "modified"}]}


class Recorder:
    def __init__(self, rc=0, stdout=""):
        self.calls, self.rc, self.stdout = [], rc, stdout

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw.get("input")))
        return subprocess.CompletedProcess(argv, self.rc, self.stdout, "denied" if self.rc else "")


def test_off_by_default_and_unknown_names_ignored():
    assert configured_actions({}) == []
    assert configured_actions({"canary_response": "network_off, reboot ,script"}) == [
        "network_off", "script"]
    assert respond({}, ALERT, runner=Recorder()) == []


@pytest.mark.parametrize("system, tool, expect", [
    ("Linux", "nmcli", ["networking", "off"]),
    ("Windows", "powershell", ["Get-NetAdapter | Disable-NetAdapter -Confirm:$false"]),
])
def test_network_off_uses_the_os_tool(monkeypatch, system, tool, expect):
    monkeypatch.setattr(response, "trusted_which", lambda n: f"/usr/bin/{n}" if n == tool else None)
    rec = Recorder()
    [res] = respond({"canary_response": "network_off"}, ALERT, runner=rec, system=system)
    assert res.ok and rec.calls[0][0][0] == f"/usr/bin/{tool}"
    assert rec.calls[0][0][-len(expect):] == expect


def test_network_off_on_macos_disables_every_service(monkeypatch):
    monkeypatch.setattr(response, "trusted_which", lambda n: "/usr/sbin/networksetup")
    rec = Recorder(stdout="An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Ethernet\n")
    cmds = NetworkOffAction({}, runner=rec, system="Darwin").commands()
    assert [c[-2] for c in cmds] == ["Wi-Fi", "Ethernet"]


def test_failures_are_reported_not_raised(monkeypatch):
    monkeypatch.setattr(response, "trusted_which", lambda n: None)
    [res] = respond({"canary_response": "network_off"}, ALERT, runner=Recorder(), system="Linux")
    assert not res.ok and "no supported network tool" in res.detail
    monkeypatch.setattr(response, "trusted_which", lambda n: "/usr/bin/nmcli")
    [res] = respond({"canary_response": "network_off"}, ALERT, runner=Recorder(rc=1), system="Linux")
    assert not res.ok and "admin rights" in res.detail

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("nmcli", 60)
    [res] = respond({"canary_response": "network_off"}, ALERT, runner=boom, system="Linux")
    assert not res.ok and "TimeoutExpired" in res.detail


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission checks")
def test_script_gets_the_alert_and_must_be_safe(tmp_path):
    script = tmp_path / "isolate.sh"
    script.write_text("#!/bin/sh\ncat > /dev/null\n")
    script.chmod(0o700)
    cfg = {"canary_response": "script", "canary_response_script": str(script)}
    rec = Recorder()
    [res] = respond(cfg, ALERT, runner=rec)
    assert res.ok and json.loads(rec.calls[0][1]) == ALERT

    script.chmod(0o777)                                   # anyone could change it
    [res] = respond(cfg, ALERT, runner=Recorder())
    assert not res.ok and "writable by group/others" in res.detail
    script.chmod(0o600)
    [res] = respond(cfg, ALERT, runner=Recorder())
    assert not res.ok and "not executable" in res.detail
    for bad, why in (("", "not set"), ("isolate.sh", "absolute"), (str(tmp_path / "no"), "does not exist")):
        [res] = respond({"canary_response": "script", "canary_response_script": bad}, ALERT,
                        runner=Recorder())
        assert why in res.detail
    assert stat.S_IMODE(script.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="runs a shell script")
def test_script_really_runs(tmp_path):
    out = tmp_path / "got.json"
    script = tmp_path / "r.sh"
    script.write_text(f"#!/bin/sh\ncat > '{out}'\n")
    script.chmod(0o700)
    [res] = respond({"canary_response": "script", "canary_response_script": str(script)}, ALERT)
    assert res.ok and json.loads(out.read_text()) == ALERT
