"""v4.2: the quarantine key can be backed up with a passphrase and installed on
another machine, without ever silently replacing a different key."""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from core.quarantine import (KEY_FILE_NAME, QUARANTINE_AVAILABLE, QuarantineError,
                             QuarantineVault)

pytestmark = pytest.mark.skipif(not QUARANTINE_AVAILABLE, reason="cryptography not installed")
ROOT = Path(__file__).resolve().parent.parent
PHRASE = "correct horse battery staple"


def machine(tmp_path, name):
    return QuarantineVault(tmp_path / name / "vault", tmp_path / name / "keys")


def test_item_quarantined_on_one_machine_restores_on_another(tmp_path):
    a = machine(tmp_path, "a")
    sample = tmp_path / "invoice.docm"
    sample.write_bytes(b"MALICIOUS" + os.urandom(5000))
    original = sample.read_bytes()
    meta = a.quarantine(sample)
    backup = a.export_key(tmp_path / "key.hrdkey", PHRASE)

    b = machine(tmp_path, "b")
    assert b.import_key(backup, PHRASE) == "installed"
    assert b.key_fingerprint() == a.key_fingerprint()
    # Move the encrypted item to the new machine's vault and restore it there.
    (tmp_path / "b" / "vault").mkdir(parents=True, exist_ok=True)
    for f in (tmp_path / "a" / "vault").iterdir():
        f.rename(tmp_path / "b" / "vault" / f.name)
    out = b.restore(meta["id"], destination=tmp_path / "restored.docm")
    assert out.read_bytes() == original


def test_backup_contains_no_plaintext_key(tmp_path):
    a = machine(tmp_path, "a")
    backup = a.export_key(tmp_path / "k", PHRASE)
    key = (tmp_path / "a" / "keys" / KEY_FILE_NAME).read_bytes()
    assert key not in backup.read_bytes()
    assert a.key_fingerprint() not in key.hex()


def test_wrong_passphrase_and_tampering_are_rejected(tmp_path):
    a = machine(tmp_path, "a")
    backup = a.export_key(tmp_path / "k", PHRASE)
    with pytest.raises(QuarantineError, match="Wrong passphrase"):
        QuarantineVault.read_key_backup(backup, "not the passphrase")
    raw = bytearray(backup.read_bytes())
    for offset in (12, 30, len(raw) - 1):        # salt, scrypt params, tag
        bad = bytearray(raw)
        bad[offset] ^= 0x01
        p = tmp_path / f"bad{offset}"
        p.write_bytes(bytes(bad))
        with pytest.raises(QuarantineError):
            QuarantineVault.read_key_backup(p, PHRASE)
    junk = tmp_path / "junk"
    junk.write_bytes(b"hello")
    with pytest.raises(QuarantineError, match="Not a quarantine key backup"):
        QuarantineVault.read_key_backup(junk, PHRASE)


def test_export_rules(tmp_path):
    a = machine(tmp_path, "a")
    with pytest.raises(QuarantineError, match="at least"):
        a.export_key(tmp_path / "k", "short")
    a.export_key(tmp_path / "k", PHRASE)
    with pytest.raises(QuarantineError, match="already exists"):
        a.export_key(tmp_path / "k", PHRASE)
    if os.name != "nt":
        assert (tmp_path / "k").stat().st_mode & 0o777 == 0o600


def test_a_different_key_is_never_replaced_silently(tmp_path):
    a, b = machine(tmp_path, "a"), machine(tmp_path, "b")
    b.key_fingerprint()                                # b creates its own key
    b_key = (tmp_path / "b" / "keys" / KEY_FILE_NAME).read_bytes()
    backup = a.export_key(tmp_path / "k", PHRASE)
    with pytest.raises(QuarantineError, match="different quarantine key"):
        b.import_key(backup, PHRASE)
    assert (tmp_path / "b" / "keys" / KEY_FILE_NAME).read_bytes() == b_key
    assert b.import_key(backup, PHRASE, replace=True) == "replaced"
    olds = list((tmp_path / "b" / "keys").glob(f"{KEY_FILE_NAME}.bak-*"))
    assert len(olds) == 1 and olds[0].read_bytes() == b_key
    assert b.key_fingerprint() == a.key_fingerprint()
    assert b.import_key(backup, PHRASE) == "already-present"


def test_cli_export_then_import(tmp_path):
    env = dict(os.environ, LLM_PROVIDER="none", HRD_KEY_PASSPHRASE=PHRASE)
    run = lambda home, *a: subprocess.run(
        [sys.executable, str(ROOT / "RansomwareScanner.py"), *a], capture_output=True,
        text=True, timeout=120, env=dict(env, HOME=str(home), USERPROFILE=str(home)))
    out = run(tmp_path / "h1", "--export-key", str(tmp_path / "k.hrdkey"))
    assert out.returncode == 0 and "fingerprint" in out.stdout, out.stdout + out.stderr
    fp = re.search(r"fingerprint ([0-9a-f]{16}) - keep", out.stdout).group(1)
    out = run(tmp_path / "h2", "--import-key", str(tmp_path / "k.hrdkey"))
    assert out.returncode == 0 and f"installed (fingerprint {fp})" in out.stdout
    bad = subprocess.run([sys.executable, str(ROOT / "RansomwareScanner.py"), "--import-key",
                          str(tmp_path / "k.hrdkey")], capture_output=True, text=True,
                         timeout=120, env=dict(env, HOME=str(tmp_path / "h4"),
                                               HRD_KEY_PASSPHRASE="wrong passphrase!!"))
    assert bad.returncode == 1 and "Wrong passphrase" in bad.stdout
