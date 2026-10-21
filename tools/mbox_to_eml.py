#!/usr/bin/env python3
"""Split mbox mailboxes into one .eml file per message.

Mail corpora are often published as mbox files (one file holding thousands of
messages). The scanner and tools/evaluate.py work per file, so this writes each
message to its own .eml. Duplicate messages (same bytes) are written once.

    python tools/mbox_to_eml.py OUT_DIR mailbox1.mbox [mailbox2 ...] [--limit N]

Nothing in a message is opened or decoded beyond splitting the mailbox.
"""

from __future__ import annotations

import argparse
import hashlib
import mailbox
import re
import sys
from pathlib import Path
from typing import Iterable, Tuple


def split(mboxes: Iterable[Path], out_dir: Path, limit: int = 0) -> Tuple[int, int, int]:
    """Write each message as OUT_DIR/<mailbox>_<n>.eml. Returns (written, duplicates, errors)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    seen = set()
    written = dups = errors = 0
    for mb_path in mboxes:
        stem = re.sub(r"[^\w.-]", "_", mb_path.stem)[:40] or "mbox"
        try:
            box = mailbox.mbox(str(mb_path), create=False)
        except Exception as e:
            print(f"skip {mb_path}: {e}", file=sys.stderr)
            errors += 1
            continue
        for i, key in enumerate(box.iterkeys(), 1):
            if limit and written >= limit:
                return written, dups, errors
            try:
                raw = box.get_bytes(key)
            except Exception:
                errors += 1
                continue
            digest = hashlib.sha256(raw).hexdigest()
            if digest in seen:
                dups += 1
                continue
            seen.add(digest)
            (out_dir / f"{stem}_{i:05d}.eml").write_bytes(raw)
            written += 1
    return written, dups, errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("mboxes", type=Path, nargs="+")
    ap.add_argument("--limit", type=int, default=0, help="stop after N messages (0 = all)")
    a = ap.parse_args(argv)
    written, dups, errors = split(a.mboxes, a.out_dir, a.limit)
    print(f"{written} message(s) written to {a.out_dir}; {dups} duplicate(s) skipped; "
          f"{errors} error(s).")
    return 0 if written else 1


if __name__ == "__main__":
    sys.exit(main())
