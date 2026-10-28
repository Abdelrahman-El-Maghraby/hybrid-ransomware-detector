"""Stand-in scanners for tests/test_workers.py (imported inside worker processes)."""

import os
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
        if name.startswith("slow"):              # tells the test which worker has it
            with open(file_path + ".pid", "w") as fh:
                fh.write(str(os.getpid()))
            time.sleep(30)
        return super().scan_file(file_path, _depth, _display_name)


def make(config):
    return MisbehavingScanner(config)
