"""Small file-system helpers shared by the core modules."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Union


def write_atomic(path: Union[str, Path], data: bytes, mode: int = 0o600,
                 create_only: bool = False) -> None:
    """Write `data` to `path` so that a crash or a full disk never leaves a
    truncated file (L-A3): a temporary file in the same folder is written and
    flushed to disk, then moved into place. With `create_only`, an existing
    `path` is never replaced (FileExistsError), even by a concurrent writer."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if create_only:
            os.link(tmp, path)            # atomic, and fails when `path` exists
        else:
            os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)                # gone after os.replace; the spare link after os.link
        except FileNotFoundError:
            pass
