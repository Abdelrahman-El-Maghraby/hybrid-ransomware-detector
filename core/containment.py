"""
Best-effort user-space containment when a canary tripwire fires.

This is damage mitigation, not prevention. An EDR stops an encrypting process
before or while it writes, from inside the kernel. This tool only learns about
encryption after a canary changed, so what it can do is shorten the damage:

* **Find the writer.** Processes that have files open in the folders where a
  canary changed are found with the operating system's own interfaces:
    - Linux:   /proc/<pid>/fd and fdinfo - only handles open for writing count;
    - macOS:   lsof (-F output) - only handles opened 'w' or 'u' count;
    - Windows: the Restart Manager API (RmGetList), the documented way to ask
               "which processes have these files open"; it cannot tell reads
               from writes, so the protected-process list matters more there.
  Ransomware that opens, encrypts and closes each file quickly may have no
  handle open at the moment of the check; then nothing is found and the other
  actions (folder lock, network off) still apply.
* **Stop it.** The process and every process it started are suspended
  (SIGSTOP / NtSuspendProcess) - reversible, so a false alarm costs a
  `--resume-pid` - or, with CANARY_CONTAIN_MODE=terminate, killed.
* **Never stop the system or this tool.** Skipped: this process and its
  ancestors (the GUI, the terminal), process IDs 0/1/4, a list of system,
  indexing and antivirus processes that open files on their own (search
  indexers, Defender, Spotlight ...), Restart Manager "critical" processes,
  and on POSIX processes of other users (and system binaries when running as
  root).

* **Lock the folders.** Write access to the configured folders is removed:
  `chmod a-w` on POSIX (original modes are saved and restored by
  `--unlock-folders`), and on Windows an inheritable deny-write ACE for
  Everyone with icacls (`/remove:d` undoes it).

Every function here is bounded and returns results instead of raising.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import signal
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from core.tools import trusted_which

logger = logging.getLogger("RansomwareScanner.containment")

Runner = Callable[..., subprocess.CompletedProcess]
TIMEOUT = 30
MAX_FILES_PER_DIR = 1000          # Restart Manager registration (Windows)
MAX_LOCK_ENTRIES = 50_000         # files + folders whose permissions are changed

# Processes that open other programs' files by design. Lower-case names.
PROTECTED_NAMES = frozenset({
    # Windows core
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "sihost.exe", "fontdrvhost.exe", "taskhostw.exe", "runtimebroker.exe",
    # Windows indexing / antivirus
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe", "msmpeng.exe",
    "nissrv.exe", "mssense.exe", "securityhealthservice.exe", "mpdefendercoreservice.exe",
    # macOS
    "kernel_task", "launchd", "mds", "mds_stores", "mdworker", "mdworker_shared", "fseventsd",
    "finder", "quicklookuiservice", "com.apple.quicklook.thumbnailsagent", "revisiond",
    "backupd", "xprotect", "xprotectservice",
    # Linux
    "init", "systemd", "kthreadd", "tracker-miner-fs", "tracker-miner-fs-3", "baloo_file",
    "clamd", "freshclam",
})
_SYSTEM_PREFIXES = ("/usr/sbin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/", "/System/")


@dataclass
class Holder:
    pid: int
    name: str
    exe: str = ""
    files: List[str] = field(default_factory=list)
    uid: Optional[int] = None
    critical: bool = False

    def label(self) -> str:
        return f"{self.name or '?'} (pid {self.pid})"


@dataclass
class ContainmentResult:
    stopped: List[str] = field(default_factory=list)       # "name (pid n) + k child(ren)"
    skipped: List[str] = field(default_factory=list)       # "name (pid n): reason"
    failed: List[str] = field(default_factory=list)
    pids: List[int] = field(default_factory=list)          # every process acted on

    @property
    def ok(self) -> bool:
        return not self.failed

    def summary(self, verb: str) -> str:
        if not (self.stopped or self.skipped or self.failed):
            return "no process had files open in the canary folders"
        parts = []
        if self.stopped:
            parts.append(f"{verb} " + "; ".join(self.stopped))
        if self.skipped:
            parts.append("left alone " + "; ".join(self.skipped[:4]))
        if self.failed:
            parts.append("could not stop " + "; ".join(self.failed[:4]))
        return " | ".join(parts)


# ------------------------------------------------------------------ process table
def process_table(system: str = "") -> Dict[int, Tuple[int, str]]:
    """pid -> (parent pid, name) for every visible process."""
    system = system or platform.system()
    try:
        if system == "Linux":
            return _linux_table()
        if system == "Windows":
            return _windows_table()
        return _ps_table()
    except Exception as e:                  # a containment helper never raises
        logger.warning("Could not list processes: %s", e)
        return {}


def _linux_table(proc: str = "/proc") -> Dict[int, Tuple[int, str]]:
    table = {}
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        try:
            with open(f"{proc}/{entry}/stat", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            continue
        name = raw[raw.find("(") + 1:raw.rfind(")")]
        rest = raw[raw.rfind(")") + 2:].split()
        if len(rest) >= 2:
            table[int(entry)] = (int(rest[1]), name)
    return table


def _ps_table(runner: Runner = subprocess.run) -> Dict[int, Tuple[int, str]]:
    ps = trusted_which("ps") or "/bin/ps"
    out = runner([ps, "-A", "-o", "pid=,ppid=,comm="], capture_output=True, text=True,
                 timeout=TIMEOUT, check=False).stdout or ""
    table = {}
    for line in out.splitlines():
        bits = line.split(None, 2)
        if len(bits) == 3 and bits[0].isdigit() and bits[1].isdigit():
            table[int(bits[0])] = (int(bits[1]), os.path.basename(bits[2].strip()))
    return table


def ancestors(pid: int, table: Dict[int, Tuple[int, str]]) -> Set[int]:
    seen: Set[int] = set()
    while pid and pid not in seen:
        seen.add(pid)
        pid = table.get(pid, (0, ""))[0]
    return seen


def descendants(pid: int, table: Dict[int, Tuple[int, str]]) -> List[int]:
    """`pid` and every process below it, parents first (a stopped parent cannot
    start new children while the rest of the tree is being stopped)."""
    children: Dict[int, List[int]] = {}
    for p, (pp, _name) in table.items():
        children.setdefault(pp, []).append(p)
    order, seen = [pid], {pid}
    for p in order:                         # breadth first; `order` grows as we go
        for c in sorted(children.get(p, [])):
            if c not in seen:
                seen.add(c)
                order.append(c)
    return order


# ------------------------------------------------------------------ who holds files
def find_holders(dirs: Sequence[str], files: Sequence[str] = (), system: str = "",
                 runner: Runner = subprocess.run) -> List[Holder]:
    """Processes with files open in `dirs` (Linux/macOS: open for writing)."""
    system = system or platform.system()
    roots = [os.path.normcase(os.path.abspath(d)) for d in dirs if d]
    if not roots:
        return []
    try:
        if system == "Linux":
            return _linux_holders(roots)
        if system == "Windows":
            return _restart_manager_holders(_candidate_files(roots, files))
        return _lsof_holders(roots, runner)
    except Exception as e:
        logger.warning("Could not look up processes holding canary files: %s", e)
        return []


def _under(path: str, roots: Sequence[str]) -> bool:
    p = os.path.normcase(path)
    return any(p == r or p.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def _linux_holders(roots: Sequence[str], proc: str = "/proc") -> List[Holder]:
    out = []
    me = os.getpid()
    for entry in os.listdir(proc):
        if not entry.isdigit() or int(entry) == me:
            continue
        base = f"{proc}/{entry}"
        files = []
        try:
            fds = os.listdir(f"{base}/fd")
        except OSError:                      # another user's process, or gone
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{base}/fd/{fd}")
            except OSError:
                continue
            if not target.startswith("/") or not _under(target, roots):
                continue
            if _linux_fd_writable(f"{base}/fdinfo/{fd}"):
                files.append(target)
        if files:
            out.append(Holder(int(entry), _read(f"{base}/comm").strip(),
                              _readlink(f"{base}/exe"), sorted(set(files)),
                              _owner(base)))
    return out


def _linux_fd_writable(fdinfo: str) -> bool:
    for line in _read(fdinfo).splitlines():
        if line.startswith("flags:"):
            return int(line.split()[1], 8) & 3 in (1, 2)          # O_WRONLY / O_RDWR
    return False


def _lsof_holders(roots: Sequence[str], runner: Runner) -> List[Holder]:
    lsof = trusted_which("lsof") or next(
        (p for p in ("/usr/sbin/lsof", "/usr/bin/lsof") if os.path.isfile(p)), None)
    if not lsof:
        logger.warning("lsof not found: cannot tell which process holds the canary files")
        return []
    argv = [lsof, "-nP", "-w", "-F", "pcan"]
    for r in roots:
        argv += ["+d", r]
    done = runner(argv, capture_output=True, text=True, timeout=TIMEOUT, check=False)
    return _parse_lsof(done.stdout or "", roots)


def _parse_lsof(text: str, roots: Sequence[str]) -> List[Holder]:
    holders: Dict[int, Holder] = {}
    cur: Optional[Holder] = None
    mode = ""
    for line in text.splitlines():
        tag, value = line[:1], line[1:]
        if tag == "p" and value.isdigit():
            cur = holders.setdefault(int(value), Holder(int(value), ""))
        elif cur is None:
            continue
        elif tag == "c":
            cur.name = value
        elif tag == "f":
            mode = ""
        elif tag == "a":
            mode = value
        elif tag == "n" and mode in ("w", "u") and _under(value, roots):
            cur.files.append(value)
    me = os.getpid()
    return [h for h in holders.values() if h.files and h.pid != me]


def _candidate_files(roots: Sequence[str], files: Sequence[str]) -> List[str]:
    out = [f for f in files if f and os.path.isfile(f)]
    for r in roots:
        try:
            with os.scandir(r) as it:
                for i, e in enumerate(it):
                    if i >= MAX_FILES_PER_DIR:
                        break
                    if e.is_file(follow_symlinks=False):
                        out.append(e.path)
        except OSError:
            continue
    return sorted(set(out))


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _readlink(path: str) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def _owner(path: str) -> Optional[int]:
    try:
        return os.stat(path).st_uid
    except OSError:
        return None


# ------------------------------------------------------------------ what is protected
def protection_reason(h: Holder, keep: Set[int], extra_names: Iterable[str] = (),
                      uid: Optional[int] = None) -> str:
    """Why this process must not be stopped ("" when it may be)."""
    names = PROTECTED_NAMES | {n.strip().lower() for n in extra_names if n.strip()}
    if h.pid in keep:
        return "this scanner or the program that started it"
    if h.pid in (0, 1, 4):
        return "system process"
    if h.critical:
        return "critical to Windows"
    if (h.name or "").lower() in names or os.path.basename(h.exe or "").lower() in names:
        return "protected system / indexing / antivirus process"
    if uid is None:
        uid = os.getuid() if hasattr(os, "getuid") else None
    if uid is not None and h.uid is not None:
        if uid != 0 and h.uid != uid:
            return "belongs to another user"
        if uid == 0 and h.uid == 0 and (h.exe or "").startswith(_SYSTEM_PREFIXES):
            return "system binary"
    return ""


# ------------------------------------------------------------------ suspend / kill
def signal_processes(pids: Sequence[int], terminate: bool, system: str = "") -> List[str]:
    """Suspend (or kill) each pid; returns a failure note per pid that could not be."""
    system = system or platform.system()
    failures = []
    for pid in pids:
        try:
            if system == "Windows":
                _windows_stop(pid, terminate)
            else:
                os.kill(pid, signal.SIGKILL if terminate else signal.SIGSTOP)
        except ProcessLookupError:
            continue                          # already gone
        except (OSError, AttributeError) as e:
            failures.append(f"pid {pid}: {e}")
    return failures


def resume(pid: int, system: str = "") -> str:
    """Undo a suspension (POSIX SIGCONT / NtResumeProcess). Returns "" or an error."""
    system = system or platform.system()
    try:
        if system == "Windows":
            _windows_call(pid, "NtResumeProcess")
        else:
            os.kill(pid, signal.SIGCONT)
        return ""
    except (OSError, AttributeError) as e:
        return str(e)


def contain(dirs: Sequence[str], files: Sequence[str] = (), terminate: bool = False,
            extra_protected: Iterable[str] = (), system: str = "",
            runner: Runner = subprocess.run) -> ContainmentResult:
    """Find the processes writing in `dirs` and stop each with its process tree."""
    system = system or platform.system()
    res = ContainmentResult()
    holders = find_holders(dirs, files, system, runner)
    if not holders:
        return res
    table = process_table(system)
    keep = ancestors(os.getpid(), table)
    for h in holders:
        if h.pid in table:
            h.name = h.name or table[h.pid][1]
            h.exe = h.exe or table[h.pid][1]
        why = protection_reason(h, keep, extra_protected)
        if why:
            res.skipped.append(f"{h.label()}: {why}")
            continue
        tree = [p for p in descendants(h.pid, table) if p not in keep] or [h.pid]
        failed = signal_processes(tree, terminate, system)
        if failed and len(failed) == len(tree):
            res.failed.append(f"{h.label()}: {failed[0]}")
            continue
        res.pids += [p for p in tree if p not in res.pids]
        extra = len(tree) - 1
        res.stopped.append(h.label() + (f" + {extra} child process(es)" if extra else ""))
    return res


# ------------------------------------------------------------------ folder lock
def lock_folders(dirs: Sequence[str], state_file: Path, system: str = "",
                 runner: Runner = subprocess.run) -> Tuple[List[str], List[str]]:
    """Remove write access to `dirs`. Returns (locked folders, problems)."""
    system = system or platform.system()
    locked, problems = [], []
    state = _load_state(state_file)
    for d in dirs:
        if not d or not os.path.isdir(d):
            problems.append(f"{d}: not a folder")
            continue
        d = os.path.abspath(d)
        try:
            if system == "Windows":
                icacls = trusted_which("icacls") or trusted_which("icacls.exe")
                if not icacls:
                    raise OSError("icacls not found")
                done = runner([icacls, d, "/deny", "*S-1-1-0:(OI)(CI)(W,D,DC)", "/C", "/Q"],
                              capture_output=True, text=True, timeout=TIMEOUT, check=False)
                if done.returncode != 0:
                    raise OSError((done.stderr or done.stdout or "").strip()[:200])
                state.setdefault("windows_denied", [])
                if d not in state["windows_denied"]:
                    state["windows_denied"].append(d)
            else:
                modes = state.setdefault("posix_modes", {})
                _posix_lock(d, modes)
            locked.append(d)
        except OSError as e:
            problems.append(f"{d}: {e}")
    _save_state(state_file, state)
    return locked, problems


def _posix_lock(root: str, modes: Dict[str, int]) -> None:
    count = 0
    entries: List[str] = []
    for top, _subdirs, names in os.walk(root):
        for n in names:
            entries.append(os.path.join(top, n))
        entries.append(top)
        count += len(names) + 1
        if count >= MAX_LOCK_ENTRIES:
            break
    for path in entries:                     # files first, folders last (os.walk order)
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                continue
            mode = stat.S_IMODE(st.st_mode)
            modes.setdefault(path, mode)
            os.chmod(path, mode & ~0o222)
        except OSError:
            continue


def unlock_folders(state_file: Path, system: str = "",
                   runner: Runner = subprocess.run) -> Tuple[int, List[str]]:
    """Undo lock_folders(). Returns (entries restored, problems)."""
    system = system or platform.system()
    state = _load_state(state_file)
    restored, problems = 0, []
    modes: Dict[str, int] = state.get("posix_modes", {})
    for path in sorted(modes, key=len):      # folders before their contents
        try:
            os.chmod(path, int(modes[path]))
            restored += 1
        except OSError as e:
            problems.append(f"{path}: {e}")
    icacls = ((trusted_which("icacls") or trusted_which("icacls.exe"))
              if system == "Windows" else None)
    for d in state.get("windows_denied", []):
        if not icacls:
            problems.append(f"{d}: icacls not found")
            continue
        done = runner([icacls, d, "/remove:d", "*S-1-1-0", "/C", "/Q"], capture_output=True,
                      text=True, timeout=TIMEOUT, check=False)
        if done.returncode == 0:
            restored += 1
        else:
            problems.append(f"{d}: {(done.stderr or '').strip()[:200]}")
    if not problems:
        try:
            state_file.unlink()
        except OSError:
            pass
    return restored, problems


def _load_state(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(path: Path, state: Dict[str, Any]) -> None:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(state, indent=1), encoding="utf-8")
    except OSError as e:
        logger.error("Could not save the folder-lock state (%s): %s", path, e)


# ------------------------------------------------------------------ Windows APIs
PROCESS_TERMINATE = 0x0001
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
RM_CRITICAL = 1000
ERROR_MORE_DATA = 234


def _last_error() -> int:
    return int(getattr(ctypes, "get_last_error", lambda: 0)())


def _win(name: str) -> Any:
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("Windows only")
    return win_dll(name, use_last_error=True)


class _ProcessEntry(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                ("th32ProcessID", ctypes.c_uint32), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_int32),
                ("dwFlags", ctypes.c_uint32), ("szExeFile", ctypes.c_wchar * 260)]


def _windows_table() -> Dict[int, Tuple[int, str]]:
    k32 = _win("kernel32")
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.Process32FirstW.argtypes = k32.Process32NextW.argtypes = [ctypes.c_void_p,
                                                                   ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return {}
    table = {}
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            table[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), entry.szExeFile)
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return table


def _windows_call(pid: int, fn: str) -> None:
    k32, ntdll = _win("kernel32"), _win("ntdll")
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    access = PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
    handle = k32.OpenProcess(access, False, pid)
    if not handle:
        raise OSError(f"OpenProcess failed (error {_last_error()})")
    try:
        if fn == "TerminateProcess":
            k32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            if not k32.TerminateProcess(handle, 1):
                raise OSError(f"TerminateProcess failed (error {_last_error()})")
        else:
            call = getattr(ntdll, fn)
            call.argtypes = [ctypes.c_void_p]
            status = call(handle)
            if status:
                raise OSError(f"{fn} returned NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
    finally:
        k32.CloseHandle(handle)


def _windows_stop(pid: int, terminate: bool) -> None:
    _windows_call(pid, "TerminateProcess" if terminate else "NtSuspendProcess")


class _RmUniqueProcess(ctypes.Structure):
    _fields_ = [("dwProcessId", ctypes.c_uint32), ("ProcessStartTime", ctypes.c_uint64)]


class _RmProcessInfo(ctypes.Structure):
    _fields_ = [("Process", _RmUniqueProcess), ("strAppName", ctypes.c_wchar * 256),
                ("strServiceShortName", ctypes.c_wchar * 64), ("ApplicationType", ctypes.c_int),
                ("AppStatus", ctypes.c_uint32), ("TSSessionId", ctypes.c_uint32),
                ("bRestartable", ctypes.c_int)]


def _restart_manager_holders(files: Sequence[str]) -> List[Holder]:
    if not files:
        return []
    rm = _win("rstrtmgr")
    session = ctypes.c_uint32()
    key = ctypes.create_unicode_buffer(33)
    if rm.RmStartSession(ctypes.byref(session), 0, key) != 0:
        raise OSError("RmStartSession failed")
    try:
        arr = (ctypes.c_wchar_p * len(files))(*files)
        if rm.RmRegisterResources(session, len(files), arr, 0, None, 0, None) != 0:
            raise OSError("RmRegisterResources failed")
        needed, count, reasons = ctypes.c_uint32(0), ctypes.c_uint32(0), ctypes.c_uint32(0)
        status = rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), None,
                              ctypes.byref(reasons))
        if status not in (0, ERROR_MORE_DATA) or not needed.value:
            return []
        info = (_RmProcessInfo * needed.value)()
        count.value = needed.value
        if rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), info,
                        ctypes.byref(reasons)) != 0:
            return []
        me = os.getpid()
        out = []
        for i in range(count.value):
            p = info[i]
            pid = int(p.Process.dwProcessId)
            if pid != me:
                out.append(Holder(pid, p.strAppName, critical=p.ApplicationType == RM_CRITICAL))
        return out
    finally:
        rm.RmEndSession(session)
