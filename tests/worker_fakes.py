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
        if name.startswith("deadline"):          # M26: what the worker knows of its limit
            with open(file_path + ".left", "w") as fh:
                fh.write(repr(self.time_left()))
        if name.startswith("helper"):            # L-E5: an inert helper program of the scan
            import subprocess
            import sys
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
            with open(file_path + ".helper", "w") as fh:
                fh.write(str(child.pid))
            if name.startswith("helperexit"):
                os._exit(3)
            time.sleep(600)
        if name.startswith("chatty"):            # a looping worker that keeps sending
            end = time.monotonic() + 30          # valid progress messages, then claims
            while time.monotonic() < end:        # a complete result long after the limit
                self.clear_provisional_listener()
                time.sleep(0.01)
        if name.startswith("relabel"):
            # RV-S2: a compromised worker names another file (an inert decoy) as the
            # one it scanned, with that file's hash
            import hashlib
            decoy = file_path + ".decoy"
            result = super().scan_file(file_path, _depth, _display_name)
            with open(decoy, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            result.update(file_path=decoy, file_name=os.path.basename(decoy),
                          sha256_hash=digest, verdict="Critical", risk_score=100)
            return result
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


def make_quick_poll(config):
    """M26: a real scanner whose sandbox polls every 0.5 s (CAPE's 15 s would not
    fit in a test-sized scan limit)."""
    scanner = RansomwareScanner(config)
    scanner.sandbox.poll_seconds = 0.5
    return scanner


class SandboxProbeScanner(RansomwareScanner):
    """M26 (provisional results): a real scanner whose sandbox polls every 0.3 s.
    After each top-level scan it appends what its worker holds to
    `<file>.probe` (pid, threads, open descriptors). Config keys, all test-only:
    `_slow_vt_seconds` delays the VirusTotal layer of a top-level `.zip` (it runs
    before the sandbox),
    `_hang_dns` makes every name lookup in this worker hang, `_crash_in_sandbox`
    ends the worker inside the sandbox wait, `_bad_provisional` sends a
    provisional result that fails the parent's check, `_poll_seconds` sets the
    sandbox poll interval (0.3 s by default), `_hang_vt`, `_hang_llm` and
    `_crash_in_vt` make VirusTotal or the LLM stall past any timeout (or end the
    worker), `_slow_llm` makes the LLM honour the timeout it is given, `_slow_finish` stalls after the
    scan has finished, before the worker replies."""

    def __init__(self, config):
        super().__init__(config)
        if self.sandbox is not None:
            self.sandbox.poll_seconds = float(config.get("_poll_seconds") or 0.3)
        if config.get("_hang_dns"):
            import socket

            def hang(*a, **k):
                time.sleep(600)
            socket.getaddrinfo = hang
        if config.get("_crash_in_sandbox") and self.sandbox is not None:
            def crash(path, deadline=None, progress=None):
                os._exit(3)
            self.sandbox.analyze = crash
        if config.get("_hang_vt") or config.get("_crash_in_vt"):
            crash = bool(config.get("_crash_in_vt"))

            class StalledVT:                       # ignores its timeout: a dripped answer
                def get(self, url, headers=None, timeout=None):
                    if crash:
                        os._exit(3)
                    time.sleep(600)

                def post(self, *a, **k):
                    time.sleep(600)
            self.http = StalledVT()
        if config.get("_hang_llm") or config.get("_slow_llm"):
            honour = bool(config.get("_slow_llm"))
            from detectors.llm_backends import LLMBackend, _empty_analysis

            class StalledLLM(LLMBackend):
                name, model, is_local = "stand-in", "m", False

                def analyze(self, combined_content, timeout=None):
                    if honour and timeout is not None:   # a server that times out properly
                        time.sleep(timeout)
                        return _empty_analysis("stand-in LLM timed out", error=True)
                    time.sleep(600)
            self.llm_backend = StalledLLM()
        slow = float(config.get("_slow_vt_seconds") or 0)
        if slow:
            original = self.scan_file_with_virustotal

            def slow_vt(path, *a, **k):          # the top-level archive only, not its members
                if str(path).endswith(".zip"):
                    time.sleep(slow)
                return original(path, *a, **k)
            self.scan_file_with_virustotal = slow_vt

    def provisional_result(self, ctx, stopped):
        result = super().provisional_result(ctx, stopped)
        if self.config.get("_bad_provisional") and "sandbox" in result["scan_results"]:
            result["scan_results"]["sandbox"]["status"] = "reported"
            hang = getattr(self.sandbox, "analyze", None)
            if hang is not None:
                self.sandbox.analyze = lambda *a, **k: time.sleep(600)
        return result

    def scan_file(self, file_path, _depth=0, _display_name=None):
        result = super().scan_file(file_path, _depth, _display_name)
        if _depth == 0 and self.config.get("_slow_finish"):
            time.sleep(600)                      # finished, but the reply never leaves
        if _depth == 0:
            import json
            import threading
            fds = len(os.listdir("/dev/fd")) if os.path.isdir("/dev/fd") else -1
            with open(file_path + ".probe", "a") as fh:
                fh.write(json.dumps({"pid": os.getpid(), "threads": threading.active_count(),
                                     "fds": fds}) + "\n")
        return result


def make_sandbox_probe(config):
    return SandboxProbeScanner(config)
