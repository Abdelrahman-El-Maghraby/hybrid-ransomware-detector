"""Refresh the four hash-pinned lock files into a scratch folder (I-3, option A).

Dependabot cannot regenerate these `uv pip compile --generate-hashes` outputs,
so this is the manual step to run when the daily dependency audit opens an
issue, or monthly. It runs the command written in each lock's header, in
dependency order (the server and build locks are constrained by the refreshed
requirements.lock), keeps each header, audits every result with pip-audit and
prints which pins changed.

It writes only to the output folder. It never touches the tracked locks, never
installs a package (pip-audit runs with --disable-pip on the hashed files) and
never commits or opens a pull request. Review the result, then copy the files
you want over the tracked locks and run the tests yourself.

    python tools/refresh_locks.py --upgrade-package pypdf     # one package
    python tools/refresh_locks.py --upgrade                    # everything
    python tools/refresh_locks.py                              # re-resolve, keep pins

Needs `uv` and `pip-audit` on PATH (or next to this Python) and network access
to PyPI and the advisory database.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
COMMON = ["--python-version", "3.12", "--universal", "--generate-hashes", "--no-header",
          "--prerelease=disallow"]
SERVER_EXTRAS = ["fuzzy", "macro", "yara", "archives", "office", "qr", "api"]

# (lock, compile inputs, constrained by requirements.lock), in dependency order.
LOCKS = [
    ("requirements.lock", ["pyproject.toml", "--extra", "all", "--extra", "cloud"], False),
    ("requirements-server.lock",
     ["pyproject.toml"] + [a for e in SERVER_EXTRAS for a in ("--extra", e)], True),
    ("requirements-build.lock", ["requirements-build.txt"], True),
    ("requirements-sbom.lock", ["requirements-sbom.txt"], False),
]
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)", re.M)


def compile_args(lock: str, inputs: List[str], constrained: bool, out: Path) -> List[str]:
    """The header's `uv pip compile` arguments, writing into `out`."""
    args = ["pip", "compile", *inputs, *COMMON]
    if constrained:
        args += ["-c", str(out / "requirements.lock")]
    return args + ["-o", str(out / lock)]


def header(text: str) -> str:
    """The comment lines before the first pin."""
    lines = []
    for line in text.splitlines(keepends=True):
        if not line.startswith("#"):
            break
        lines.append(line)
    return "".join(lines)


def pins(text: str) -> Dict[str, str]:
    return {m.group(1).lower(): m.group(2) for m in _PIN.finditer(text)}


def changes(old: str, new: str) -> List[str]:
    a, b = pins(old), pins(new)
    out = [f"  {n}: {a[n]} -> {b[n]}" for n in sorted(a.keys() & b.keys()) if a[n] != b[n]]
    out += [f"  {n}: added {b[n]}" for n in sorted(b.keys() - a.keys())]
    out += [f"  {n}: removed {a[n]}" for n in sorted(a.keys() - b.keys())]
    return out


def _tool(name: str) -> Optional[str]:
    beside = Path(sys.executable).parent / name
    return str(beside) if beside.is_file() else shutil.which(name)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, help="output folder (default: a new temporary one)")
    ap.add_argument("--upgrade-package", action="append", default=[], metavar="NAME",
                    help="upgrade this package (repeatable)")
    ap.add_argument("--upgrade", action="store_true", help="upgrade every package")
    ap.add_argument("--no-audit", action="store_true", help="skip pip-audit")
    args = ap.parse_args(argv)

    out = (args.out or Path(tempfile.mkdtemp(prefix="aegis-locks-"))).resolve()
    if out == ROOT or out in ROOT.parents:
        ap.error("--out must not be the repository (the tracked locks stay unchanged)")
    out.mkdir(parents=True, exist_ok=True)
    uv = _tool("uv")
    audit = None if args.no_audit else _tool("pip-audit")
    if not uv or (not args.no_audit and not audit):
        print("needs uv" + ("" if args.no_audit else " and pip-audit") + " on PATH",
              file=sys.stderr)
        return 2
    upgrade = ["--upgrade"] if args.upgrade else \
        [a for p in args.upgrade_package for a in ("--upgrade-package", p)]

    failed = False
    for lock, inputs, constrained in LOCKS:
        old = (ROOT / lock).read_text(encoding="utf-8")
        (out / lock).write_text(old, encoding="utf-8")       # uv keeps these pins
        cmd = [uv, *compile_args(lock, inputs, constrained, out), *upgrade]
        print(f"== {lock}", flush=True)
        if subprocess.run(cmd, cwd=ROOT,  # nosec B603
                          stdout=subprocess.DEVNULL).returncode:   # the lock is in the file
            print(f"   uv failed for {lock}", file=sys.stderr)
            failed = True
            continue
        body = (out / lock).read_text(encoding="utf-8")
        new = header(old) + body[len(header(body)):]
        # uv names the constraint by the path it was given; the tracked locks say
        # "requirements.lock", so a copied file differs only where pins do.
        new = new.replace(f"-c {out / 'requirements.lock'}", "-c requirements.lock")
        (out / lock).write_text(new, encoding="utf-8")
        print("\n".join(changes(old, new)) or "  no pin changed", flush=True)
        if audit and subprocess.run(  # nosec B603
                [audit, "--require-hashes", "--disable-pip", "--progress-spinner", "off",
                 "-r", str(out / lock)]).returncode:
            print(f"   pip-audit reports a problem in {lock}", file=sys.stderr)
            failed = True
    print(f"\nRefreshed locks in {out}. The tracked locks are unchanged; review, copy the "
          "files you want, and run the tests.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
