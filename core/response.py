"""
What to do when a canary tripwire fires, beyond writing an alert.

Canaries only detect: by the time one changes, encryption is running. Stopping
the encrypting process needs operating-system hooks (an EDR's job), but cutting
the machine off the network stops the spread to shares and other machines and
stops exfiltration - the step every incident-response playbook starts with.

Configured with CANARY_RESPONSE (comma-separated, off when empty). Whatever
the order there, actions run fastest-containment first:
  stop_writers   suspend (CANARY_CONTAIN_MODE=terminate: kill) the processes
                 that have files open for writing in the canary folders, with
                 their child processes (core/containment.py)
  lock_folders   remove write access to CANARY_LOCK_DIRS (default: the canary
                 folders); undo with --unlock-folders
  controlled_folder_access
                 Windows: turn on Defender's Controlled Folder Access and add
                 the lock folders to it (needs admin rights)
  network_off    disable the network adapters (needs admin / root rights)
  script         run CANARY_RESPONSE_SCRIPT with the alert as JSON on stdin

This is a rapid-containment and damage-mitigation tripwire, not prevention:
by the time a canary changes, encryption is already running.

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
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Type

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
    priority = 50                                        # lower runs first

    def __init__(self, config: Dict, runner: Runner = subprocess.run, system: str = ""):
        self.config = config
        self.runner = runner
        self.system = system or platform.system()

    def run(self, alert: Dict) -> ActionResult:          # pragma: no cover - interface
        raise NotImplementedError

    def _exec(self, argv: Sequence[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess:
        return self.runner(list(argv), input=stdin, capture_output=True, text=True,
                           timeout=TIMEOUT, check=False)


def canary_dirs(alert: Dict) -> List[str]:
    """Folders where a canary changed or a file event was seen."""
    paths = [f.get("path", "") for f in alert.get("findings") or []]
    paths += list(alert.get("touched") or [])
    return sorted({os.path.dirname(os.path.abspath(p)) for p in paths if p})


class StopWritersAction(ResponseAction):
    """Suspend or kill the processes writing in the canary folders."""
    name = "stop_writers"
    priority = 10

    def run(self, alert: Dict) -> ActionResult:
        from core.containment import contain
        terminate = str(self.config.get("canary_contain_mode") or "suspend").lower() == "terminate"
        extra = str(self.config.get("canary_contain_exclude") or "").split(",")
        touched = [p for p in alert.get("touched") or []]
        touched += [f.get("path", "") for f in alert.get("findings") or []]
        res = contain(canary_dirs(alert), touched, terminate=terminate, extra_protected=extra,
                      system=self.system, runner=self.runner)
        alert.setdefault("contained_pids", []).extend(res.pids)
        state_file = self.config.get("containment_state_file")
        if res.pids and not terminate and state_file:
            from core.containment import record_suspended
            record_suspended(Path(state_file), res.pids, self.system)
        verb = "killed" if terminate else "suspended"
        detail = res.summary(verb)
        if res.pids and not terminate:
            detail += (" (investigate, then kill them or undo with "
                       "--resume-pid " + ",".join(map(str, res.pids)) + " or --resume-pid all)")
        return ActionResult(self.name, res.ok, detail)


class LockFoldersAction(ResponseAction):
    """Remove write access to the protected folders."""
    name = "lock_folders"
    priority = 20

    def folders(self, alert: Dict) -> List[str]:
        raw = str(self.config.get("canary_lock_dirs") or "")
        # ";" everywhere; ":" too on POSIX (it is part of a Windows drive path).
        seps = r";" if self.system == "Windows" else r"[;:]"
        dirs = [d.strip() for d in re.split(seps, raw) if d.strip()]
        return dirs or canary_dirs(alert)

    def run(self, alert: Dict) -> ActionResult:
        from core.containment import lock_folders
        state = Path(self.config.get("containment_state_file") or "containment_state.json")
        locked, problems = lock_folders(self.folders(alert), state, system=self.system,
                                        runner=self.runner)
        detail = (f"write access removed from {len(locked)} folder(s): " + ", ".join(locked)
                  if locked else "no folder locked")
        if problems:
            detail += "; problems: " + "; ".join(problems[:3])
        return ActionResult(self.name, bool(locked) and not problems,
                            detail + (" (undo with --unlock-folders)" if locked else ""))


class ControlledFolderAccessAction(ResponseAction):
    """Windows: turn on Defender's Controlled Folder Access for the lock folders."""
    name = "controlled_folder_access"
    priority = 25

    def run(self, alert: Dict) -> ActionResult:
        if self.system != "Windows":
            return ActionResult(self.name, False, "Controlled Folder Access exists only on Windows")
        ps = trusted_which("powershell") or trusted_which("powershell.exe")
        if not ps:
            return ActionResult(self.name, False, "powershell not found")
        folders = LockFoldersAction(self.config, self.runner, self.system).folders(alert)
        script = "Set-MpPreference -EnableControlledFolderAccess Enabled"
        for d in folders:
            quoted = d.replace("'", "''")
            script += f"; Add-MpPreference -ControlledFolderAccessProtectedFolders '{quoted}'"
        done = self._exec([ps, "-NoProfile", "-NonInteractive", "-Command", script])
        if done.returncode != 0:
            return ActionResult(self.name, False, (done.stderr or "").strip()[:200]
                                + " (admin rights needed?)")
        return ActionResult(self.name, True, f"enabled, {len(folders)} folder(s) protected")


class NetworkOffAction(ResponseAction):
    """Disable network adapters with the operating system's own tool."""
    name = "network_off"
    priority = 30

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
    priority = 40

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


ACTIONS: Dict[str, Type[ResponseAction]] = {cls.name: cls for cls in (
    StopWritersAction, LockFoldersAction, ControlledFolderAccessAction, NetworkOffAction,
    ScriptAction)}


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
    known = list(dict.fromkeys(n for n in names if n in ACTIONS))
    return sorted(known, key=lambda n: ACTIONS[n].priority)


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
