"""
What to do when a canary tripwire fires, beyond writing an alert.

Canaries only detect: by the time one changes, encryption is running. Stopping
the encrypting process needs operating-system hooks (an EDR's job), but cutting
the machine off the network stops the spread to shares and other machines and
stops exfiltration - the step every incident-response playbook starts with.

Configured with CANARY_RESPONSE (comma-separated, off when empty):
  network_off  disable the network adapters (needs admin / root rights)
  script       run CANARY_RESPONSE_SCRIPT with the alert as JSON on stdin

Each action is a small strategy class; new ones register in ACTIONS. Programs
are found with core.tools.trusted_which and the response script must be an
absolute path that only its owner can change (it runs with your rights at the
worst possible moment). Every action is time-limited and never raises.

On Windows, also turn on Controlled Folder Access (Windows Security >
Ransomware protection): unlike this tool, it blocks unknown programs from
writing to protected folders.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from core.tools import trusted_which

logger = logging.getLogger("RansomwareScanner.response")

Runner = Callable[..., subprocess.CompletedProcess]
TIMEOUT = 60


@dataclass
class ActionResult:
    action: str
    ok: bool
    detail: str

    def line(self) -> str:
        return f"[{'done' if self.ok else 'FAILED'}] {self.action}: {self.detail}"


class ResponseAction:
    name = ""

    def __init__(self, config: Dict, runner: Runner = subprocess.run, system: str = ""):
        self.config = config
        self.runner = runner
        self.system = system or platform.system()

    def run(self, alert: Dict) -> ActionResult:          # pragma: no cover - interface
        raise NotImplementedError

    def _exec(self, argv: Sequence[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess:
        return self.runner(list(argv), input=stdin, capture_output=True, text=True,
                           timeout=TIMEOUT, check=False)


class NetworkOffAction(ResponseAction):
    """Disable network adapters with the operating system's own tool."""
    name = "network_off"

    def commands(self) -> List[List[str]]:
        if self.system == "Windows":
            ps = trusted_which("powershell") or trusted_which("powershell.exe")
            return [[ps, "-NoProfile", "-NonInteractive", "-Command",
                     "Get-NetAdapter | Disable-NetAdapter -Confirm:$false"]] if ps else []
        if self.system == "Linux":
            nmcli = trusted_which("nmcli")
            return [[nmcli, "networking", "off"]] if nmcli else []
        if self.system == "Darwin":
            tool = trusted_which("networksetup")
            if not tool:
                return []
            listing = self._exec([tool, "-listallnetworkservices"]).stdout or ""
            services = [s.lstrip("*").strip() for s in listing.splitlines()[1:] if s.strip()]
            return [[tool, "-setnetworkserviceenabled", s, "off"] for s in services]
        return []

    def run(self, alert: Dict) -> ActionResult:
        cmds = self.commands()
        if not cmds:
            return ActionResult(self.name, False, f"no supported network tool on {self.system}")
        failed = []
        for argv in cmds:
            done = self._exec(argv)
            if done.returncode != 0:
                failed.append(f"{' '.join(argv[-2:])}: {(done.stderr or '').strip()[:120]}")
        if failed:
            return ActionResult(self.name, False, "; ".join(failed) + " (admin rights needed?)")
        return ActionResult(self.name, True, f"{len(cmds)} command(s) succeeded")


class ScriptAction(ResponseAction):
    """Run the user's own response script with the alert as JSON on stdin."""
    name = "script"

    def run(self, alert: Dict) -> ActionResult:
        script = str(self.config.get("canary_response_script") or "")
        problem = _script_problem(script)
        if problem:
            return ActionResult(self.name, False, problem)
        done = self._exec([script], stdin=json.dumps(alert))
        if done.returncode != 0:
            return ActionResult(self.name, False,
                                f"exit code {done.returncode}: {(done.stderr or '').strip()[:200]}")
        return ActionResult(self.name, True, f"{Path(script).name} finished")


ACTIONS: Dict[str, type] = {cls.name: cls for cls in (NetworkOffAction, ScriptAction)}


def _script_problem(script: str) -> str:
    if not script:
        return "CANARY_RESPONSE_SCRIPT is not set"
    path = Path(script)
    if not path.is_absolute():
        return "CANARY_RESPONSE_SCRIPT must be an absolute path"
    if not path.is_file():
        return f"{script} does not exist"
    if os.name == "posix":
        st = path.stat()
        if st.st_mode & 0o022:
            return f"{script} is writable by group/others (chmod go-w)"
        if hasattr(os, "getuid") and st.st_uid not in (os.getuid(), 0):
            return f"{script} is owned by another user"
        if not os.access(script, os.X_OK):
            return f"{script} is not executable (chmod u+x)"
    return ""


def configured_actions(config: Dict) -> List[str]:
    raw = config.get("canary_response") or ""
    names = [n.strip().lower() for n in str(raw).split(",") if n.strip()]
    unknown = [n for n in names if n not in ACTIONS]
    if unknown:
        logger.warning("Unknown CANARY_RESPONSE action(s) ignored: %s", ", ".join(unknown))
    return [n for n in names if n in ACTIONS]


def respond(config: Dict, alert: Dict, runner: Runner = subprocess.run,
            system: str = "") -> List[ActionResult]:
    """Run every configured action; never raises."""
    results: List[ActionResult] = []
    for name in configured_actions(config):
        try:
            result = ACTIONS[name](config, runner=runner, system=system).run(alert)
        except Exception as e:                   # time-out, missing tool, OS error
            result = ActionResult(name, False, f"{type(e).__name__}: {e}")
        (logger.warning if result.ok else logger.error)("Canary response %s", result.line())
        results.append(result)
    return results
