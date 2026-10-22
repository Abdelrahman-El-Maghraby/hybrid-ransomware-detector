"""
Optional JavaScript emulation with box-js (https://github.com/CapacitorSet/box-js).

Static decoding unwinds the usual obfuscation, but a script that builds its
download URL at run time (string arithmetic, date checks, eval chains) only
shows it when it runs. box-js runs the script in Node with fake WScript /
ActiveX objects and records what it *tried* to do: URLs it fetched, files it
wrote, commands it ran. Nothing is downloaded (no --download) and the fake
objects never touch the real system.

OFF by default (EMULATION_ENABLED=1 to turn on), because it still executes the
attacker's JavaScript inside a Node sandbox (vm2), and such sandboxes have had
escapes. Turn it on inside an analysis VM or container, not on a workstation.
Defences here: the tool is found by trusted path, runs on a copy in a private
temporary folder with a minimal environment and a wall-clock limit, inherits the
scan worker's memory limit (Linux), and its output files are parsed as
untrusted data.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from core.tools import trusted_which

from .script_analysis import decode_script_encoder

logger = logging.getLogger("RansomwareScanner.emulation")

EMULATED_EXTENSIONS = (".js", ".jse")
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 5 * 1024 * 1024
_EXEC_WRITE_SUFFIXES = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
                        ".msi", ".lnk")


@dataclass
class EmulationResult:
    ran: bool = False
    urls: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    written_files: List[str] = field(default_factory=list)
    detail: str = ""

    @property
    def downloads_and_runs(self) -> bool:
        wrote_program = any(f.lower().endswith(_EXEC_WRITE_SUFFIXES) for f in self.written_files)
        return bool(self.urls) and bool(self.commands or wrote_program)

    def as_dict(self) -> Dict:
        d = asdict(self)
        d["downloads_and_runs"] = self.downloads_and_runs
        return d


class ScriptEmulator:
    def __init__(self, tool: str = "box-js", timeout: int = 20):
        self.tool = trusted_which(tool) if tool else None
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.tool)

    def applies(self, path: str) -> bool:
        return Path(path).suffix.lower() in EMULATED_EXTENSIONS

    def emulate(self, path: str, data: Optional[bytes] = None) -> EmulationResult:
        if not self.tool:
            return EmulationResult(detail="box-js not found (npm install -g box-js)")
        raw = data if data is not None else Path(path).read_bytes()
        if len(raw) > MAX_SCRIPT_BYTES:
            return EmulationResult(detail="script too large to emulate")
        source = raw
        if Path(path).suffix.lower() == ".jse":
            source = decode_script_encoder(raw.decode("latin-1")).encode("latin-1", "replace")
        work = Path(tempfile.mkdtemp(prefix="hrd_emu_"))
        try:
            sample = work / "sample.js"
            sample.write_bytes(source)
            out = work / "out"
            out.mkdir()
            env = {"PATH": os.environ.get("PATH", ""), "HOME": str(work), "TMPDIR": str(work),
                   "NODE_OPTIONS": ""}
            if os.name == "nt":
                env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
            try:
                subprocess.run([self.tool, str(sample), f"--output-dir={out}",
                                f"--timeout={self.timeout}", "--no-kill", "--loglevel=error"],
                               cwd=work, env=env, capture_output=True,
                               timeout=self.timeout + 30, check=False)
            except subprocess.TimeoutExpired:
                return EmulationResult(detail="emulation timed out")
            return _read_results(out)
        finally:
            shutil.rmtree(work, ignore_errors=True)


def _load(path: Path):
    try:
        if path.is_file() and path.stat().st_size <= MAX_RESULT_BYTES:
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        pass
    return None


def _read_results(out: Path) -> EmulationResult:
    folders = [p for p in out.iterdir() if p.is_dir() and p.name.endswith(".results")]
    if not folders:
        return EmulationResult(detail="box-js produced no results")
    res_dir = folders[0]
    res = EmulationResult(ran=True)
    urls = _load(res_dir / "urls.json")
    if isinstance(urls, list):
        res.urls = [str(u)[:500] for u in urls if isinstance(u, str)][:20]
    iocs = _load(res_dir / "IOC.json")
    for ioc in iocs if isinstance(iocs, list) else []:
        if not isinstance(ioc, dict) or not isinstance(ioc.get("value"), dict):
            continue
        kind, value = ioc.get("type"), ioc["value"]
        if kind == "Run" and value.get("command"):
            res.commands.append(str(value["command"])[:300])
        elif kind == "FileWrite" and value.get("file"):
            res.written_files.append(str(value["file"])[:300])
        elif kind == "UrlFetch" and value.get("url"):
            url = str(value["url"])[:500]
            if url not in res.urls:
                res.urls.append(url)
    res.commands, res.written_files = res.commands[:20], res.written_files[:20]
    bits = []
    if res.urls:
        bits.append(f"{len(res.urls)} URL(s) contacted")
    if res.written_files:
        bits.append(f"{len(res.written_files)} file(s) written")
    if res.commands:
        bits.append(f"{len(res.commands)} command(s) run")
    res.detail = ("Emulation: " + ", ".join(bits) + ".") if bits else "Emulation: no network, file or process activity."
    return res
