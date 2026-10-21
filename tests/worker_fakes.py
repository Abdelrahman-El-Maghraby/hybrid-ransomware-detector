"""Stand-in scanners for tests/test_workers.py (imported inside worker processes)."""

import os
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
        if name.startswith("hog"):
            bytearray(8 * 1024 * 1024 * 1024)
        return super().scan_file(file_path, _depth, _display_name)


def make(config):
    return MisbehavingScanner(config)
