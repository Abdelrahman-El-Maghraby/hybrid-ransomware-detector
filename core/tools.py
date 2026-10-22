"""Find helper programs (7-Zip, unrar, notify-send, ...) without trusting the
current directory.

A scanner is often started from the folder it scans. On Windows, a plain
program name ("7z") is looked up in the current directory before PATH, and
`shutil.which` does too, even with an explicit path - so a `7z.exe` planted in a
Downloads folder would run with the user's rights. Here only absolute PATH
entries are searched, the current directory is skipped, and the absolute path
is what the caller runs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def trusted_which(name: str) -> Optional[str]:
    """Absolute path of `name` from absolute PATH entries other than the current
    directory, or None. A name that already contains a directory is returned
    as-is when it is an absolute path to an existing file."""
    if os.path.dirname(name):
        return name if os.path.isabs(name) and os.path.isfile(name) else None
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        cwd = None
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue                            # "" and "." mean the current directory
        try:
            if cwd is not None and Path(entry).resolve() == cwd:
                continue
        except OSError:
            continue
        found = _in_dir(entry, name)
        if found:
            return found
    return None


def _in_dir(directory: str, name: str) -> Optional[str]:
    """`name` as an executable file directly in `directory`. Done by hand because
    shutil.which on Windows also searches the current directory first, even when
    given an explicit path."""
    if os.name == "nt" and not os.path.splitext(name)[1]:
        exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
    else:
        exts = [""]
    for ext in exts:
        candidate = os.path.join(directory, name + ext)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None
