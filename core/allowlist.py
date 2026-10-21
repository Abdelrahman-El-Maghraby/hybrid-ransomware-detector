"""Known-good files, by SHA-256.

A plain text file the user maintains: one SHA-256 per line, optionally followed by
a note after '#'. Blank lines and lines starting with '#' are ignored, as is
anything that is not a 64-character hex digest (reported once in the log).

    # vendor installer scripts that download and run their own setup
    3f1c...e9a2  # Playwright browser installer (checked 2026-10)

An allowlisted file is still scanned and its findings are kept in the report,
but it is not scored - unless the same hash is in the malware database.
Hashes, not names or paths: an attacker cannot reuse an allowlist entry
without producing a byte-identical file.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Optional, Union

logger = logging.getLogger("RansomwareScanner")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def load_allowlist(path: Optional[Union[str, Path]]) -> Dict[str, str]:
    """{sha256: note} from the allowlist file ({} if there is none)."""
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    entries: Dict[str, str] = {}
    bad = 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, note = line.partition("#")
        digest = digest.strip().lower()
        if _SHA256.match(digest):
            entries[digest] = note.strip()
        else:
            bad += 1
    if bad:
        logger.warning("Allowlist %s: %d line(s) are not SHA-256 digests and were ignored.", p, bad)
    if entries:
        logger.info("Allowlist: %d known-good file hash(es) loaded from %s.", len(entries), p)
    return entries
