"""Stand-in scanners for tests/test_workers.py (imported inside worker processes)."""

import gc
import multiprocessing.connection
import os
import pickle
import tempfile
import time

from engine.scanner import RansomwareScanner


class MisbehavingScanner(RansomwareScanner):
    """Behaves badly on purpose, chosen by the file name: hangs, exits, or asks for
    far more memory than the worker limit. Every other file is scanned normally."""

    def scan_file(self, file_path, _depth=0, _display_name=None):
        name = os.path.basename(file_path)
        if name.startswith("hang"):
            time.sleep(600)
        if name.startswith("exit"):
            os._exit(3)
        if name.startswith("hog"):              # runaway allocation that is really used:
            hoard = []                           # untouched pages (one huge bytearray) are not
            for _ in range(256):                 # resident on macOS, so the watchdog saw nothing
                hoard.append(b"\x01" * (64 * 1024 * 1024))
        if name.startswith("litter"):            # unpacks, then hangs past the timeout
            sandbox = tempfile.mkdtemp(prefix="hrd_unpack_")
            with open(os.path.join(sandbox, "member.bin"), "wb") as fh:
                fh.write(b"x" * 4096)
            with open(file_path + ".tmpdir", "w") as fh:
                fh.write(sandbox)
            time.sleep(600)
        if name.startswith(("evil", "huge")):       # M18: a worker taken over by a parser
            _write_to_parent(file_path, name)
        if name.startswith("slow"):              # tells the test which worker has it
            with open(file_path + ".pid", "w") as fh:
                fh.write(str(os.getpid()))
            time.sleep(30)
        return super().scan_file(file_path, _depth, _display_name)


class _Marker:
    """Unpickling this creates a file: proof that the receiver ran its code."""

    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return (open, (self.path, "w"))


def _write_to_parent(file_path, name):
    """Write raw bytes to the parent the way a compromised worker could: a pickle
    whose loading creates `<file>.pwned`, or a message over the size limit."""
    from engine.workers import MAX_REPLY_BYTES
    conns = [o for o in gc.get_objects()
             if isinstance(o, multiprocessing.connection.Connection) and not o.closed]
    if name.startswith("evil"):
        data = pickle.dumps(("ok", _Marker(file_path + ".pwned")))
    else:
        data = b"[" * (MAX_REPLY_BYTES + 1)
    for c in conns:
        c.send_bytes(data)
    time.sleep(30)


def make(config):
    return MisbehavingScanner(config)


def never_ready(config):
    """A worker whose scanner build never finishes (a start-up hang)."""
    time.sleep(600)
