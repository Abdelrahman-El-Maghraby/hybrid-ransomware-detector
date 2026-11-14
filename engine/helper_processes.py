"""Bounded discovery of worker descendants on macOS, including new sessions.

Only verified ancestry is retained. Signals use the kernel's audit-token PID
version check, never an executable name or a check-then-kill PID fallback.
This is best effort: descendants reparented before discovery can be missed.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

MAX_HELPERS = 128


class _BsdInfo(ctypes.Structure):
    _fields_ = ([(n, ctypes.c_uint32) for n in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid",
        "svuid", "svgid", "reserved")]
        + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
        + [(n, ctypes.c_uint32) for n in ("nfiles", "pgid", "jobc", "tdev", "tpgid")]
        + [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
           ("start_usec", ctypes.c_uint64)])


class _UniqueInfo(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16), ("unique", ctypes.c_uint64),
                ("parent_unique", ctypes.c_uint64), ("version", ctypes.c_int32),
                ("parent_version", ctypes.c_int32), ("reserved", ctypes.c_uint64 * 2)]


class _Identity(ctypes.Structure):
    _fields_ = [("bsd", _BsdInfo), ("identity", _UniqueInfo)]


class MacProcesses:
    """libproc ABI: PROC_PIDT_BSDINFOWITHUNIQID (18), audit-token signals.

    Definitions: Apple's xnu/bsd/sys/proc_info_private.h and libproc.h.
    Missing symbols, denied reads and short structures fail closed.
    """
    def __init__(self, lib: Any = None):
        self.lib = lib or ctypes.CDLL(ctypes.util.find_library("proc") or "libproc.dylib")
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                         ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listchildpids.restype = ctypes.c_int
        self.lib.proc_listpgrppids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listpgrppids.restype = ctypes.c_int
        self.lib.proc_signal_with_audittoken.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_signal_with_audittoken.restype = ctypes.c_int

    def read(self, pid: int) -> Optional[Tuple[int, int, int, int, int]]:
        data = _Identity()
        size = ctypes.sizeof(data)
        if self.lib.proc_pidinfo(pid, 18, 0, ctypes.byref(data), size) != size:
            return None
        if data.bsd.pid != pid or not data.identity.unique:
            return None
        return (int(data.identity.unique), int(data.identity.parent_unique),
                int(data.bsd.ppid), int(data.identity.version), int(data.identity.parent_version))

    def children(self, pid: int) -> List[int]:
        buf = (ctypes.c_int * MAX_HELPERS)()
        count = self.lib.proc_listchildpids(pid, buf, ctypes.sizeof(buf))
        return [int(p) for p in buf[:max(0, min(count, MAX_HELPERS))] if p > 0]

    def group(self, pgid: int) -> List[int]:
        buf = (ctypes.c_int * MAX_HELPERS)()
        count = self.lib.proc_listpgrppids(pgid, buf, ctypes.sizeof(buf))
        return [int(p) for p in buf[:max(0, min(count, MAX_HELPERS))] if p > 0]

    def signal(self, pid: int, unique: int, sig: int) -> bool:
        current = self.read(pid)
        if current is None or current[0] != unique:
            return False
        token = (ctypes.c_uint32 * 8)()
        token[5], token[7] = pid, current[3]
        # Kernel holds the target reference and validates its PID version before
        # signalling. A concurrent exit/reuse/exec cannot signal a replacement.
        return self.lib.proc_signal_with_audittoken(ctypes.byref(token), sig) == 0


class Descendants:
    def __init__(self, pid: int, backend: Any):
        self.backend, self.pid = backend, pid
        root = backend.read(pid)
        self.root = root[0] if root else None
        self.root_version = root[3] if root else None
        self.known: Dict[int, int] = {}
        self.last = 0.0

    def collect(self, force: bool = False) -> None:
        now = time.monotonic()
        if self.root is None or (not force and now - self.last < 0.25):
            return
        self.last = now
        pending = [(self.pid, self.root), *list(self.known.items())]
        visited: Set[int] = set()
        while pending and len(visited) < MAX_HELPERS + 1:
            pid, unique = pending.pop(0)
            if pid in visited:
                continue
            visited.add(pid)
            current = self.backend.read(pid)
            if current is None or current[0] != unique:
                self.known.pop(pid, None)
                continue
            for child in self.backend.children(pid):
                if child == self.pid or child in self.known or len(self.known) >= MAX_HELPERS:
                    continue
                info = self.backend.read(child)
                if info is not None and info[1] == unique and info[2] == pid:
                    self.known[child] = info[0]
                    pending.append((child, info[0]))

    def ready(self) -> None:
        current = self.backend.read(self.pid)
        if current is not None and current[0] == self.root:
            self.root_version = current[3]

    def _collect_group(self) -> None:
        # A worker may exit between polls. Its original group is a bounded
        # candidate list only: require a retained parent unique ID, not the PGID
        # or current PPID alone. Never signal the group by its recyclable number.
        group: Callable[[int], List[int]] = getattr(self.backend, "group", lambda pid: [])
        candidates = [(pid, self.backend.read(pid)) for pid in group(self.pid)]
        owned = {self.root, *self.known.values()}
        for _ in range(MAX_HELPERS):
            added = False
            for pid, info in candidates:
                if (pid != self.pid and pid not in self.known and info is not None
                        and (info[1] in owned or (len(info) > 4 and info[4] == self.root_version))
                        and len(self.known) < MAX_HELPERS):
                    self.known[pid] = info[0]
                    owned.add(info[0])
                    added = True
            if not added:
                break

    def stop(self, sig: int) -> None:
        self.collect(force=True)
        if self.root is not None:
            self._collect_group()
        for pid, unique in reversed(list(self.known.items())):
            self.backend.signal(pid, unique, sig)
        self.known.clear()


def track_descendants(pid: Optional[int]) -> Optional[Descendants]:
    if sys.platform != "darwin" or pid is None:
        return None
    try:
        tracker = Descendants(pid, MacProcesses())
        return tracker if tracker.root is not None else None
    except (OSError, AttributeError):
        return None
