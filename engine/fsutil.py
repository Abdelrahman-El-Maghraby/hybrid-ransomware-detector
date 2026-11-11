"""Small file-system helpers shared by the scanner, the folder monitor and the
canary checks.

A FIFO, socket or device node can sit in a scanned folder under any name
(``invoice.pdf``), and a symlink can point at ``/dev/zero``. Opening a FIFO for
reading blocks until a writer appears, and reading a device can never reach
end-of-file. Code that runs in the main process (hashing a file whose isolated
scan failed, the folder monitor's duplicate check, canary checks) must
therefore only ever read regular files.
"""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import BinaryIO, Optional, Union

# O_NONBLOCK makes open() on a FIFO return at once instead of waiting for a
# writer; it has no effect on regular files. Windows has neither flag.
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def is_regular_file(path: str) -> bool:
    """True when `path` (following symlinks) is a regular file. Never opens it."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def open_regular(path: str) -> Optional[BinaryIO]:
    """Open `path` for binary reading only when it is a regular file.

    Returns None for a FIFO, socket, device or directory without blocking.
    The type is checked on the opened descriptor, so a file swapped for a FIFO
    after an earlier stat() is still refused. Raises OSError when the path
    cannot be opened at all.
    """
    fd = os.open(path, _OPEN_FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
        return os.fdopen(fd, "rb")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


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
