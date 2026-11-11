"""L-A3: the containment record, the quarantine key and the quarantine item
records were written in place (`write_text`, or create then write), so a crash
or a full disk mid-write left a truncated file: a key file the vault then
refuses as corrupt, an empty key slot after `--replace-key`, or a record that
does not parse. They are now written to a temporary file, flushed to disk and
moved into place. Each test makes that last step fail and checks that what was
there before is intact."""

import json
from pathlib import Path

import pytest

from core import containment as C
from core import fsutil
from core.quarantine import QUARANTINE_AVAILABLE, QuarantineVault


class Crash(Exception):
    pass


@pytest.fixture
def crash_on_commit(monkeypatch):
    def fail(*a, **k):
        raise Crash("disk full")
    monkeypatch.setattr(fsutil.os, "replace", fail)
    monkeypatch.setattr(fsutil.os, "link", fail)


def _no_temp_files(folder: Path):
    return not [p for p in folder.rglob("*") if p.name.endswith(".tmp")]


def test_a_failed_save_keeps_the_previous_containment_record(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    assert C._save_state(state, {"posix_modes": {"/a": 420}})
    monkeypatch.setattr(fsutil.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("full")))
    assert C._save_state(state, {"posix_modes": {}}) is False
    assert json.loads(state.read_text()) == {"posix_modes": {"/a": 420}}
    assert _no_temp_files(tmp_path)


@pytest.mark.skipif(not QUARANTINE_AVAILABLE, reason="cryptography not installed")
def test_a_crash_while_creating_the_key_leaves_no_truncated_key(tmp_path, crash_on_commit):
    keys = tmp_path / "keys"
    keys.mkdir()                                     # as the vault does before this call
    with pytest.raises(Crash):
        QuarantineVault(tmp_path / "vault", keys)._load_or_create_master_key()
    assert not (keys / "quarantine.key").exists() and _no_temp_files(tmp_path)


@pytest.mark.skipif(not QUARANTINE_AVAILABLE, reason="cryptography not installed")
def test_a_crash_while_vaulting_keeps_the_item_record_readable(tmp_path, monkeypatch):
    vault = QuarantineVault(tmp_path / "vault", tmp_path / "keys")
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"inert test payload " * 50)
    meta = vault.quarantine(str(sample), reason="first", delete_original=False)
    record = vault._sidecar_path(meta["id"])
    before = record.read_text()
    monkeypatch.setattr(fsutil.os, "replace", lambda *a: (_ for _ in ()).throw(Crash("full")))
    with pytest.raises(Crash):
        vault.quarantine(str(sample), reason="second", delete_original=False)
    assert record.read_text() == before
    assert all(isinstance(i, dict) for i in vault.list()) and _no_temp_files(tmp_path)


def test_write_atomic_never_overwrites_in_create_mode(tmp_path):
    target = tmp_path / "k"
    fsutil.write_atomic(target, b"one", create_only=True)
    with pytest.raises(FileExistsError):
        fsutil.write_atomic(target, b"two", create_only=True)
    assert target.read_bytes() == b"one" and _no_temp_files(tmp_path)
