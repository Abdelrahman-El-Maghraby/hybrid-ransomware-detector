"""core/containment.py and the containment response actions. The real tests
start a harmless child process that keeps a file open in a temporary "canary"
folder, and check that exactly that process is found and stopped."""

import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core import containment as C
from core import response
from core.containment import Holder, contain, descendants, protection_reason
from core.response import (
    ControlledFolderAccessAction,
    LockFoldersAction,
    StopWritersAction,
    canary_dirs,
    configured_actions,
    respond,
)

ROOT = Path(__file__).resolve().parent.parent
POSIX = os.name == "posix"


class Recorder:
    def __init__(self, rc=0, stdout=""):
        self.calls, self.rc, self.stdout = [], rc, stdout

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, self.rc, self.stdout, "denied" if self.rc else "")


# ------------------------------------------------------------- process tree
TABLE = {1: (0, "init"), 50: (1, "bash"), 60: (50, "python"),        # 60 = this tool
         100: (1, "evil"), 101: (100, "evil-child"), 102: (101, "grandchild"), 200: (1, "other")}


def test_tree_helpers():
    assert descendants(100, TABLE) == [100, 101, 102]          # parents first
    assert descendants(999, TABLE) == [999]
    assert C.ancestors(60, TABLE) == {60, 50, 1}
    loop = {5: (6, "a"), 6: (5, "b")}
    assert C.ancestors(5, loop) == {5, 6}


def test_protection_rules():
    keep = {60, 50, 1}
    assert protection_reason(Holder(50, "bash"), keep).startswith("this scanner")
    assert protection_reason(Holder(4, "System"), set()) == "system process"
    assert "antivirus" in protection_reason(Holder(900, "MsMpEng.exe"), set())
    assert "antivirus" in protection_reason(Holder(900, "x", exe="/opt/x/SearchIndexer.exe"), set())
    assert protection_reason(Holder(900, "Finder"), set())
    assert protection_reason(Holder(900, "mysync"), set(), extra_names=["MySync"])
    assert protection_reason(Holder(900, "x", critical=True), set()) == "critical to Windows"
    assert protection_reason(Holder(900, "x", uid=1001), set(), uid=1000) == "belongs to another user"
    assert protection_reason(Holder(900, "x", exe="/usr/sbin/cupsd", uid=0), set(),
                             uid=0) == "system binary"
    assert protection_reason(Holder(900, "x", exe="/tmp/x", uid=0), set(), uid=0) == ""
    assert protection_reason(Holder(900, "evil.exe", uid=1000), set(), uid=1000) == ""


# ------------------------------------------------------------- finding holders
def _fake_proc(tmp_path, pid, name, targets, flags="0100002", uid_dir=None):
    base = tmp_path / "proc" / str(pid)
    (base / "fd").mkdir(parents=True)
    (base / "fdinfo").mkdir()
    (base / "comm").write_text(name + "\n")
    (base / "stat").write_text(f"{pid} ({name} x) S 1 {pid} {pid} 0")
    for i, t in enumerate(targets):
        os.symlink(t, base / "fd" / str(i))
        (base / "fdinfo" / str(i)).write_text(f"pos:\t0\nflags:\t{flags}\nmnt_id:\t1\n")
    return base


@pytest.mark.skipif(not POSIX, reason="symlinks")
def test_linux_proc_parsing(tmp_path):
    canary = tmp_path / "Documents"
    canary.mkdir()
    _fake_proc(tmp_path, 300, "writer", [str(canary / "a.docx"), "/etc/hosts", "pipe:[1]"])
    _fake_proc(tmp_path, 301, "reader", [str(canary / "b.docx")], flags="0100000")
    _fake_proc(tmp_path, 302, "elsewhere", [str(tmp_path / "Documents2" / "c")])
    (tmp_path / "proc" / "self").mkdir()
    holders = C._linux_holders([str(canary)], proc=str(tmp_path / "proc"))
    assert [(h.pid, h.name, h.files) for h in holders] == [(300, "writer", [str(canary / "a.docx")])]
    table = C._linux_table(str(tmp_path / "proc"))
    assert table[300] == (1, "writer x")


def test_lsof_output_parsing():
    text = "\n".join(["p77", "cevil", "f3", "aw", "n/home/u/Docs/a.docx", "f4", "ar",
                      "n/home/u/Docs/b.docx", "p78", "cmds", "f5", "ar", "n/home/u/Docs/c",
                      "p79", "cother", "f1", "au", "n/home/u/Elsewhere/d", "junk"])
    holders = C._parse_lsof(text, [os.path.normcase("/home/u/Docs")])
    assert [(h.pid, h.name, h.files) for h in holders] == [(77, "evil", ["/home/u/Docs/a.docx"])]


@pytest.mark.skipif(not POSIX, reason="lsof is a macOS / Linux tool")
def test_lsof_command(monkeypatch):
    monkeypatch.setattr(C, "trusted_which", lambda n: "/usr/sbin/lsof")
    rec = Recorder(stdout="p9\ncx\nf1\nau\nn/d/f\n")
    holders = C.find_holders(["/d"], system="Darwin", runner=rec)
    assert rec.calls[0][:5] == ["/usr/sbin/lsof", "-nP", "-w", "-F", "pcan"]
    assert "+d" in rec.calls[0] and [h.pid for h in holders] == [9]


def test_ps_table():
    rec = Recorder(stdout="  1     0 /sbin/launchd\n 42     1 /Applications/X.app/Contents/MacOS/X\n"
                          "bad line\n")
    assert C._ps_table(rec) == {1: (0, "launchd"), 42: (1, "X")}


def test_find_holders_never_raises(monkeypatch):
    assert C.find_holders([]) == []

    def boom(*a):
        raise RuntimeError("x")
    monkeypatch.setattr(C, "_linux_holders", boom)
    assert C.find_holders(["/x"], system="Linux") == []
    monkeypatch.setattr(C, "_linux_table", boom)
    assert C.process_table("Linux") == {}


def test_candidate_files_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "MAX_FILES_PER_DIR", 3)
    for i in range(6):
        (tmp_path / f"f{i}").write_text("x")
    (tmp_path / "sub").mkdir()
    files = C._candidate_files([str(tmp_path), str(tmp_path / "missing")], [str(tmp_path / "f5")])
    assert len(files) <= 4 and str(tmp_path / "f5") in files


# ------------------------------------------------------------- contain()
def test_contain_stops_the_tree_and_spares_protected(monkeypatch):
    monkeypatch.setattr(C, "find_holders", lambda *a: [Holder(100, "evil"), Holder(200, "MsMpEng.exe"),
                                                       Holder(60, "python"), Holder(300, "gone")])
    monkeypatch.setattr(C, "process_table", lambda s: {**TABLE, 300: (1, "gone")})
    monkeypatch.setattr(C.os, "getpid", lambda: 60)
    sent = []

    def fake_signal(pids, terminate, system):
        sent.append((list(pids), terminate))
        return [f"pid {p}: denied" for p in pids] if pids == [300] else []
    monkeypatch.setattr(C, "signal_processes", fake_signal)
    res = contain(["/docs"], terminate=False, system="Linux")
    assert sent == [([100, 101, 102], False), ([300], False)]
    assert res.stopped == ["evil (pid 100) + 2 child process(es)"] and res.pids == [100, 101, 102]
    assert any("MsMpEng" in s for s in res.skipped) and any("python" in s for s in res.skipped)
    assert res.failed == ["gone (pid 300): pid 300: denied"] and not res.ok
    assert "suspended evil" in res.summary("suspended")
    assert C.ContainmentResult().summary("x").startswith("no process")


@pytest.mark.skipif(not POSIX, reason="POSIX signals")
def test_signal_processes(monkeypatch):
    calls = []

    def kill(pid, sig):
        calls.append((pid, sig))
        if pid == 2:
            raise ProcessLookupError
        if pid == 3:
            raise PermissionError("not permitted")
    monkeypatch.setattr(C.os, "kill", kill)
    assert C.signal_processes([1, 2, 3], terminate=False, system="Linux") == ["pid 3: not permitted"]
    assert calls[0] == (1, C.signal.SIGSTOP)
    C.signal_processes([1], terminate=True, system="Linux")
    assert calls[-1] == (1, C.signal.SIGKILL)
    assert C.resume(1, system="Linux") == "" and calls[-1] == (1, C.signal.SIGCONT)
    assert "not permitted" in C.resume(3, system="Linux")


def test_windows_helpers_off_windows():
    if sys.platform != "win32":
        assert C.signal_processes([12345], terminate=False, system="Windows")[0].startswith("pid 12345")
        assert C.resume(12345, system="Windows")
        assert C.process_table("Windows") == {}
        assert C.find_holders(["C:/x"], system="Windows") == []


# ------------------------------------------------------------- real processes
HOLD = ("import sys, time\nf = open(sys.argv[1], sys.argv[2])\nprint('ready', flush=True)\n"
        "time.sleep(120)\n")


def _child(path, mode="w"):
    p = subprocess.Popen([sys.executable, "-c", HOLD, str(path), mode], stdout=subprocess.PIPE,
                         text=True)
    assert p.stdout.readline().strip() == "ready"
    return p


def _state(pid):
    if sys.platform.startswith("linux"):
        raw = Path(f"/proc/{pid}/stat").read_text()
        return raw[raw.rfind(")") + 2]
    return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                          text=True).stdout.strip()[:1]


@pytest.mark.skipif(not (sys.platform.startswith("linux") or sys.platform == "darwin"),
                    reason="/proc or lsof")
def test_real_writer_is_suspended_and_reader_left_alone(tmp_path):
    docs = tmp_path / "Documents"
    docs.mkdir()
    (docs / "read.txt").write_text("x")
    writer, reader = _child(docs / "x.docx", "w"), _child(docs / "read.txt", "r")
    try:
        res = contain([str(docs)], system="")
        assert writer.pid in res.pids and reader.pid not in res.pids, res
        deadline = time.time() + 5
        while _state(writer.pid) != "T" and time.time() < deadline:
            time.sleep(0.1)
        assert _state(writer.pid) == "T"
        assert _state(reader.pid) != "T"
        assert C.resume(writer.pid) == ""
    finally:
        for p in (writer, reader):
            p.kill()
            p.wait()


@pytest.mark.skipif(sys.platform != "win32", reason="Restart Manager")
def test_real_windows_holder_is_found_and_terminated(tmp_path):
    docs = tmp_path / "Documents"
    docs.mkdir()
    writer = _child(docs / "x.docx", "w")
    try:
        assert writer.pid in [h.pid for h in C.find_holders([str(docs)])]
        res = contain([str(docs)])
        assert writer.pid in res.pids, res
        assert C.resume(writer.pid) == ""
        res = contain([str(docs)], terminate=True)
        writer.wait(timeout=20)
    finally:
        writer.kill()


# ------------------------------------------------------------- folder lock
@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_lock_and_unlock_posix(tmp_path):
    docs = tmp_path / "Docs"
    (docs / "sub").mkdir(parents=True)
    f = docs / "sub" / "a.txt"
    f.write_text("x")
    f.chmod(0o640)
    state = tmp_path / "state.json"
    locked, problems = C.lock_folders([str(docs), str(tmp_path / "nope")], state, system="Linux")
    assert locked == [str(docs)] and "not a folder" in problems[0]
    assert stat.S_IMODE(f.stat().st_mode) == 0o440
    assert not stat.S_IMODE(docs.stat().st_mode) & 0o222
    if os.geteuid() != 0:                                  # root ignores permission bits
        with pytest.raises(PermissionError):
            f.write_text("encrypted")
    C.lock_folders([str(docs)], state, system="Linux")     # twice: originals are kept
    restored, problems = C.unlock_folders(state, system="Linux")
    assert not problems and restored >= 3 and not state.exists()
    assert stat.S_IMODE(f.stat().st_mode) == 0o640
    f.write_text("fine again")


def test_lock_and_unlock_windows_commands(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "trusted_which", lambda n: "C:/Windows/System32/icacls.exe")
    rec = Recorder()
    state = tmp_path / "state.json"
    locked, problems = C.lock_folders([str(tmp_path)], state, system="Windows", runner=rec)
    assert locked and not problems
    assert rec.calls[0][2:4] == ["/deny", "*S-1-1-0:(OI)(CI)(W,D,DC)"]
    restored, problems = C.unlock_folders(state, system="Windows", runner=rec)
    assert restored == 1 and rec.calls[-1][2:4] == ["/remove:d", "*S-1-1-0"]

    failing = Recorder(rc=5)
    locked, problems = C.lock_folders([str(tmp_path)], state, system="Windows", runner=failing)
    assert not locked and problems
    monkeypatch.setattr(C, "trusted_which", lambda n: None)
    locked, problems = C.lock_folders([str(tmp_path)], state, system="Windows", runner=rec)
    assert "icacls not found" in problems[0]


def test_state_file_problems(tmp_path):
    assert C._load_state(tmp_path / "missing.json") == {}
    (tmp_path / "bad.json").write_text("[1]")
    assert C._load_state(tmp_path / "bad.json") == {}
    C._save_state(tmp_path / "f" / "s.json", {"a": 1})
    assert C._load_state(tmp_path / "f" / "s.json") == {"a": 1}
    blocker = tmp_path / "file"
    blocker.write_text("x")
    C._save_state(blocker / "s.json", {})                  # logged, not raised


# ------------------------------------------------------------- response actions
ALERT = {"summary": "1 canary changed", "touched": ["/home/u/Docs/x.docx.lock"],
         "findings": [{"path": "/home/u/Docs/!000_a.docx", "status": "modified"}]}


def test_actions_run_containment_first():
    names = configured_actions({"canary_response": "script, network_off, lock_folders, "
                                                   "stop_writers, stop_writers"})
    assert names == ["stop_writers", "lock_folders", "network_off", "script"]


def test_canary_dirs():
    assert canary_dirs(ALERT) == [os.path.abspath("/home/u/Docs")]
    assert canary_dirs({}) == []


def test_stop_writers_action(monkeypatch):
    seen = {}

    def fake(dirs, files, terminate, extra_protected, system, runner):
        seen.update(dirs=dirs, files=files, terminate=terminate, extra=extra_protected)
        r = C.ContainmentResult(stopped=["evil (pid 9)"], pids=[9])
        return r
    monkeypatch.setattr(C, "contain", fake)
    alert = dict(ALERT)
    res = StopWritersAction({"canary_contain_exclude": "SyncApp"}, system="Linux").run(alert)
    assert res.ok and "suspended evil (pid 9)" in res.detail and "--resume-pid 9" in res.detail
    assert seen["terminate"] is False and seen["extra"] == ["SyncApp"]
    assert "/home/u/Docs/x.docx.lock" in seen["files"] and alert["contained_pids"] == [9]
    res = StopWritersAction({"canary_contain_mode": "terminate"}, system="Linux").run(dict(ALERT))
    assert "killed" in res.detail and "--resume-pid" not in res.detail


def test_lock_folders_action(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(C, "lock_folders", lambda dirs, state, system, runner: (
        calls.append((dirs, state)) or (list(dirs), [])))
    cfg = {"canary_lock_dirs": f"{tmp_path};{tmp_path / 'b'}",
           "containment_state_file": str(tmp_path / "s.json")}
    res = LockFoldersAction(cfg).run(ALERT)
    assert res.ok and calls[0][0] == [str(tmp_path), str(tmp_path / "b")]
    assert "--unlock-folders" in res.detail
    res = LockFoldersAction({}).run(ALERT)                   # default: the canary folders
    assert calls[1][0] == canary_dirs(ALERT)
    monkeypatch.setattr(C, "lock_folders", lambda *a, **k: ([], ["x: denied"]))
    res = LockFoldersAction({}).run(ALERT)
    assert not res.ok and "denied" in res.detail


def test_controlled_folder_access_action(monkeypatch):
    assert not ControlledFolderAccessAction({}, system="Linux").run(ALERT).ok
    monkeypatch.setattr(response, "trusted_which", lambda n: None)
    assert "powershell" in ControlledFolderAccessAction({}, system="Windows").run(ALERT).detail
    monkeypatch.setattr(response, "trusted_which", lambda n: "C:/ps.exe")
    rec = Recorder()
    cfg = {"canary_lock_dirs": "C:/Users/u/Doc's"}
    res = ControlledFolderAccessAction(cfg, runner=rec, system="Windows").run(ALERT)
    assert res.ok and "EnableControlledFolderAccess Enabled" in rec.calls[0][-1]
    assert "'C:/Users/u/Doc''s'" in rec.calls[0][-1]
    res = ControlledFolderAccessAction(cfg, runner=Recorder(rc=1), system="Windows").run(ALERT)
    assert not res.ok and "admin" in res.detail


def test_respond_runs_the_new_actions(monkeypatch):
    monkeypatch.setattr(C, "contain", lambda *a, **k: C.ContainmentResult())
    [res] = respond({"canary_response": "stop_writers"}, dict(ALERT), system="Linux")
    assert res.ok and "no process" in res.detail


# ------------------------------------------------------------- CLI
def test_cli_resume_and_unlock(tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path),
               PYTHONIOENCODING="utf-8")
    run = dict(capture_output=True, encoding="utf-8", errors="replace", timeout=120,
               cwd=tmp_path, env=env)
    out = subprocess.run([sys.executable, str(ROOT / "RansomwareScanner.py"), "--unlock-folders"],
                         **run)
    assert out.returncode == 0 and "restored on 0" in out.stdout, out.stderr[-1500:]
    out = subprocess.run([sys.executable, str(ROOT / "RansomwareScanner.py"), "--resume-pid",
                          "999999"], **run)
    assert out.returncode == 1 and "pid 999999" in out.stdout


# ------------------------------------------------------------- watcher and scanner
def test_watcher_remembers_touched_paths():
    from core.canary_watch import CanaryWatcher

    class Mgr:
        def paths(self):
            return []
    w = CanaryWatcher(Mgr(), lambda: None, debounce=60)
    w.poke("/d/a.docx")
    w.poke("/d/b.docx.lock")
    w.poke()
    assert w.take_touched() == ["/d/a.docx", "/d/b.docx.lock"] and w.take_touched() == []
    w.stop()


def test_scanner_passes_touched_paths_to_the_response(tmp_path, monkeypatch):
    import RansomwareScanner as RS
    from tests.test_scanner_integration import _config
    seen = {}
    monkeypatch.setattr(response, "respond", lambda cfg, alert, **k: (
        seen.update(alert) or [response.ActionResult("stop_writers", True, "suspended evil")]))
    scanner = RS.RansomwareScanner(_config(tmp_path))
    entry = scanner.deploy_canaries([str(tmp_path / "scan")])[0]
    Path(entry["path"]).write_bytes(b"encrypted")
    report = scanner.check_canaries(notify=False, touched=[entry["path"] + ".lock"])
    assert report.triggered and seen["touched"] == [entry["path"] + ".lock"]
    alert = next(Path(scanner.report_dir).glob("canary_alert_*.txt")).read_text()
    assert "rapid containment" in alert and "[done] stop_writers: suspended evil" in alert
