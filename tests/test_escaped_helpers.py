"""Inert, bounded descendants; no process-name matching or global sweep."""
import ctypes
import signal
import subprocess
import sys
import time

import pytest

from engine.helper_processes import MAX_HELPERS, Descendants, MacProcesses
from tests.test_helper_cleanup import _gone
from tests.test_scanner_integration import _config
from tests.test_slow_layer_deadline import _scan, _script


class Tree:
    def __init__(self):
        self.data = {10: (100, 1, 1, 1), 20: (200, 100, 10, 2), 30: (300, 200, 20, 3)}
        self.signals = []

    def read(self, pid):
        return self.data.get(pid)

    def children(self, pid):
        return [p for p, info in self.data.items() if info[2] == pid]

    def signal(self, pid, unique, sig):
        if self.read(pid) and self.read(pid)[0] == unique:
            self.signals.append(pid)


def test_ownership_survives_reparenting_but_not_pid_reuse():
    tree = Tree()
    track = Descendants(10, tree)
    track.collect(force=True)
    assert track.known == {20: 200, 30: 300}
    tree.data[20] = (201, 1, 1, 20)  # PID reused by a bystander
    tree.data[30] = (300, 200, 1, 30)  # discovered child reparented
    tree.data[40] = (400, 201, 20, 40)  # replacement's child: not ours
    track.stop(signal.SIGKILL)
    assert tree.signals == [30] and not track.known


def test_ancestry_and_discovery_are_bounded():
    tree = Tree()
    tree.data.update({p: (p * 100, 100, 10, p) for p in range(100, 500)})
    tree.data[50] = (500, 999, 10, 50)  # PPID alone is insufficient
    track = Descendants(10, tree)
    track.collect(force=True)
    assert len(track.known) == MAX_HELPERS and 50 not in track.known


def test_missing_identity_never_discovers_or_signals():
    tree = Tree()
    tree.data.pop(10)
    track = Descendants(10, tree)
    track.stop(signal.SIGKILL)
    assert not track.known and not tree.signals


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS audit-token API")
def test_generation_checked_signals_leave_a_bystander_alive():
    backend = MacProcesses()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(15)"])
    try:
        info = backend.read(child.pid)
        assert info is not None
        assert not backend.signal(child.pid, info[0] + 1, signal.SIGKILL)
        assert child.poll() is None
        token = (ctypes.c_uint32 * 8)()
        token[5], token[7] = child.pid, info[3] + 1
        assert backend.lib.proc_signal_with_audittoken(ctypes.byref(token), signal.SIGKILL) != 0
        assert child.poll() is None
        assert backend.signal(child.pid, info[0], signal.SIGKILL)
        child.wait(5)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(5)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS descendant discovery")
def test_session_escaped_helper_and_descendant_are_stopped(tmp_path):
    cfg = _config(tmp_path, _scanner_factory="tests.completed_fakes:make_escaped",
                  scan_timeout_seconds=3)
    path = _script(tmp_path)
    backend = MacProcesses()
    # Bystander is our direct child; it is outside the scanner worker's ancestry.
    bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                 start_new_session=True)
    identities = []
    try:
        got = _scan(cfg, [path], 3)
        assert len(got) == 1 and got[0][1]["scan_status"] == "failed"
        for line in (path.parent / "owned-pids").read_text().splitlines():
            pid, unique = map(int, line.split())
            identities.append((pid, unique))
        assert len(identities) == 2
        assert all(_gone(pid) for pid, _ in identities)
        assert bystander.poll() is None
    finally:
        for pid, unique in identities:
            backend.signal(pid, unique, signal.SIGKILL)
        bystander.kill()
        bystander.wait(5)


class EscapedScanner:
    def __init__(self, config):
        self.config = config

    def scan_file(self, path):
        from pathlib import Path
        target = str(Path(path).parent / "owned-pids")
        script = '''import subprocess, sys, time
from engine.helper_processes import MacProcesses
m = MacProcesses()
p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'], start_new_session=True)
with open(sys.argv[1], 'a') as f:
    f.write(f'{p.pid} {m.read(p.pid)[0]}\\n')
time.sleep(20)
'''
        child = subprocess.Popen([sys.executable, "-c", script, target], start_new_session=True)
        info = MacProcesses().read(child.pid)
        with open(target, "a") as output:
            output.write(f"{child.pid} {info[0]}\n")
        time.sleep(20)


def test_group_candidates_need_unique_parent_ownership():
    tree = Tree()
    tree.group = lambda pid: [20, 30, 40]
    tree.data.pop(10)
    tree.data[20] = (200, 100, 1, 2)
    tree.data[30] = (300, 200, 1, 3)
    tree.data[40] = (400, 999, 1, 4)
    track = Descendants(10, tree)
    track.root = 100  # retained while the worker was alive
    track.stop(signal.SIGKILL)
    assert tree.signals == [30, 20]


def test_child_exec_after_reparent_uses_original_parent_generation():
    tree = Tree()
    track = Descendants(10, tree)
    tree.data.pop(10)
    tree.data[20] = (200, 1, 1, 22, 1)  # current parent changed; original generation kept
    tree.data[30] = (300, 1, 1, 33, 999)  # unrelated, same candidate group
    tree.group = lambda pid: [20, 30]
    track.stop(signal.SIGKILL)
    assert tree.signals == [20]
