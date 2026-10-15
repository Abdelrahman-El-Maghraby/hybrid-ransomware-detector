import os
import stat
import struct
from pathlib import Path

import pytest

from core.quarantine import MAGIC, QUARANTINE_AVAILABLE, QuarantineError, QuarantineVault

pytestmark = pytest.mark.skipif(not QUARANTINE_AVAILABLE, reason="cryptography not installed")


@pytest.fixture
def vault(tmp_path):
    return QuarantineVault(tmp_path / "vault", tmp_path / "keys", chunk_size=4096)


def _sample(tmp_path, name="invoice.docm", size=50_000):
    p = tmp_path / "downloads" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    data = b"MALICIOUS-MARKER" + os.urandom(size)
    p.write_bytes(data)
    return p, data


def test_roundtrip_removes_original_and_restores_identically(vault, tmp_path):
    src, data = _sample(tmp_path)
    os.chmod(src, 0o640)
    meta = vault.quarantine(src, reason="YARA critical")
    assert not src.exists() and meta["original_removed"] is True
    assert [i["id"] for i in vault.list()] == [meta["id"]]
    assert vault.verify(meta["id"])
    restored = vault.restore(meta["id"])
    assert restored == src and restored.read_bytes() == data
    if os.name != "nt":
        assert stat.S_IMODE(restored.stat().st_mode) == 0o640
    assert vault.list() == []                    # released from the vault


def test_vault_contains_no_plaintext(vault, tmp_path):
    src, _ = _sample(tmp_path)
    meta = vault.quarantine(src)
    raw = Path(meta["vault_file"]).read_bytes()
    assert raw.startswith(MAGIC)
    assert b"MALICIOUS-MARKER" not in raw and b"invoice.docm" not in raw


def test_authenticated_metadata(vault, tmp_path):
    src, data = _sample(tmp_path)
    meta = vault.quarantine(src, reason="test", extra={"verdict": "Critical"})
    inner = vault.read_metadata(meta["id"])
    assert inner["original_name"] == "invoice.docm"
    assert inner["size"] == len(data)
    assert inner["extra"] == {"verdict": "Critical"}


@pytest.mark.parametrize("mutation", ["flip", "truncate", "swap_chunks", "drop_eof"])
def test_tampering_is_detected_and_nothing_is_written(vault, tmp_path, mutation):
    src, _ = _sample(tmp_path, size=30_000)       # ~8 chunks of 4 KiB
    meta = vault.quarantine(src)
    vf = Path(meta["vault_file"])
    raw = bytearray(vf.read_bytes())
    if mutation == "flip":
        raw[len(raw) // 2] ^= 0x01
    elif mutation == "truncate":
        raw = raw[:-40]
    elif mutation == "drop_eof":
        raw = raw[:-(4 + 4 + 16)]
    else:                                         # swap the first two frames
        header_len = len(MAGIC) + 16 + 8 + 8
        meta_len = struct.unpack(">I", raw[len(MAGIC) + 24 + 4:len(MAGIC) + 24 + 8])[0]
        off = header_len + meta_len
        l1 = struct.unpack(">I", raw[off:off + 4])[0]
        f1 = raw[off:off + 4 + l1]
        l2 = struct.unpack(">I", raw[off + 4 + l1:off + 8 + l1])[0]
        f2 = raw[off + 4 + l1:off + 8 + l1 + l2]
        raw = raw[:off] + f2 + f1 + raw[off + len(f1) + len(f2):]
    vf.write_bytes(bytes(raw))
    assert vault.verify(meta["id"]) is False
    with pytest.raises(QuarantineError):
        vault.restore(meta["id"], destination=tmp_path / "out.bin")
    assert not (tmp_path / "out.bin").exists()
    assert not any(p.name.startswith(".restore-") for p in tmp_path.iterdir())


def test_wrong_key_cannot_decrypt(tmp_path):
    v1 = QuarantineVault(tmp_path / "vault", tmp_path / "keys1")
    src, _ = _sample(tmp_path)
    meta = v1.quarantine(src)
    v2 = QuarantineVault(tmp_path / "vault", tmp_path / "keys2")
    assert v2.verify(meta["id"]) is False
    with pytest.raises(QuarantineError):
        v2.restore(meta["id"])


def test_corrupt_key_file_is_never_overwritten(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "quarantine.key").write_bytes(b"short")
    vault = QuarantineVault(tmp_path / "vault", keys)
    src, _ = _sample(tmp_path)
    with pytest.raises(QuarantineError):
        vault.quarantine(src)
    assert src.exists()                                  # nothing was deleted
    assert (keys / "quarantine.key").read_bytes() == b"short"


def test_opening_and_listing_writes_nothing(tmp_path):
    vault = QuarantineVault(tmp_path / "vault", tmp_path / "keys")
    assert vault.list() == []
    assert not (tmp_path / "keys").exists() and not (tmp_path / "vault").exists()


def test_restore_does_not_clobber_existing_file(vault, tmp_path):
    src, data = _sample(tmp_path)
    meta = vault.quarantine(src)
    src.write_bytes(b"new file the user created meanwhile")
    restored = vault.restore(meta["id"])
    assert restored.name == f"invoice.docm.restored-{meta['id']}"
    assert restored.read_bytes() == data
    assert src.read_bytes() == b"new file the user created meanwhile"


def test_id_prefix_resolution(vault, tmp_path):
    src, _ = _sample(tmp_path)
    meta = vault.quarantine(src)
    assert vault.resolve_id(meta["id"][:4]) == meta["id"]
    with pytest.raises(QuarantineError):
        vault.resolve_id("zzzz")


def test_keep_original_option(vault, tmp_path):
    src, data = _sample(tmp_path)
    meta = vault.quarantine(src, delete_original=False)
    assert src.read_bytes() == data and meta["original_removed"] is False


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_refuses_symlinks(vault, tmp_path):
    src, _ = _sample(tmp_path)
    link = tmp_path / "link.docm"
    link.symlink_to(src)
    with pytest.raises(QuarantineError):
        vault.quarantine(link)
    assert src.exists()


def test_empty_file_roundtrip(vault, tmp_path):
    p = tmp_path / "empty.pdf"
    p.write_bytes(b"")
    meta = vault.quarantine(p)
    assert vault.restore(meta["id"]).read_bytes() == b""


def test_self_test():
    assert QuarantineVault.self_test() is True
