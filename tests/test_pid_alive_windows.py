"""L-E6: on Windows, OpenProcess fails both for a process that does not exist
and for one that exists but belongs to another user (access denied). Only the
first may count as dead; otherwise the stale-folder sweep could delete a live
scanner's work folder. Tested with a stand-in kernel32 on any platform: this
shows the decision logic only, not Windows behaviour (unverified here)."""

import ctypes

import pytest

from engine import workers as W


class Kernel32:
    def __init__(self, handle=0, exit_code=259, query_ok=True):
        self.handle, self.exit_code, self.query_ok = handle, exit_code, query_ok
        self.closed = []

    def OpenProcess(self, access, inherit, pid):
        return self.handle

    def GetExitCodeProcess(self, handle, ref):
        ctypes.cast(ref, ctypes.POINTER(ctypes.c_ulong)).contents.value = self.exit_code
        return 1 if self.query_ok else 0

    def CloseHandle(self, handle):
        self.closed.append(handle)


@pytest.mark.parametrize("error,alive", [(W.ERROR_ACCESS_DENIED, True),
                                         (W.ERROR_INVALID_PARAMETER, False),
                                         (1234, True)],
                         ids=["access-denied", "no-such-process", "unclear"])
def test_a_failed_open_is_dead_only_for_no_such_process(error, alive):
    assert W._pid_alive_windows(4242, Kernel32(handle=0), lambda: error) is alive


@pytest.mark.parametrize("code,ok,alive", [(259, True, True), (0, True, False),
                                           (0, False, True)],
                         ids=["still-active", "exited", "query-failed"])
def test_an_open_process_is_judged_by_its_exit_code(code, ok, alive):
    k = Kernel32(handle=77, exit_code=code, query_ok=ok)
    assert W._pid_alive_windows(4242, k, lambda: 0) is alive
    assert k.closed == [77]                               # the handle is always closed


def test_the_sweep_keeps_a_folder_whose_owner_it_may_not_open(tmp_path, monkeypatch):
    kept = tmp_path / f"{W.WORKER_TEMP_PREFIX}4242_abc"
    kept.mkdir()
    monkeypatch.setattr(W, "_pid_alive",
                        lambda pid: W._pid_alive_windows(pid, Kernel32(), lambda: 5))
    assert W.sweep_stale_worker_dirs(str(tmp_path)) == 0 and kept.is_dir()
    monkeypatch.setattr(W, "_pid_alive",
                        lambda pid: W._pid_alive_windows(pid, Kernel32(), lambda: 87))
    assert W.sweep_stale_worker_dirs(str(tmp_path)) == 1 and not kept.exists()
