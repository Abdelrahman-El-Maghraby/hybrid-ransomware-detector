"""Legitimate encrypted files (KeePass, GPG, age) are random by design; they
must not be reported as ransomware output, while a forged header must not hide
real ransomware output: the ML layer trusts a header only when the extension
agrees, and the file-integrity layer never trusts it for a document."""

import os

import pytest

import RansomwareScanner as RS
from detectors.file_integrity import (detect_format, encrypted_container_format,
                                       is_openpgp_message, trusted_vault)
from detectors.ml_classifier import MLClassifier, extract_features
from tests.test_scanner_integration import _config, _indicators

KDBX4 = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00"
KDB1 = b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5"
PGP_PKESK_OLD = b"\x85\x01\x0c\x03" + b"\x11" * 8          # old format, tag 1, v3
PGP_PKESK_NEW = b"\xc1\xc0\x4c\x03"                         # new format, tag 1, v3
PGP_SKESK_NEW = b"\xc3\x0d\x04\x09\x03"                     # new format, tag 3, v4
AGE = b"age-encryption.org/v1\n-> X25519 abc\nxyz\n--- def\n"


def _random_file(path, header=b"", size=200_000):
    path.write_bytes(header + os.urandom(size))
    return path


@pytest.mark.parametrize("header,kind", [
    (KDBX4, "kdbx"), (KDB1, "kdbx"), (PGP_PKESK_OLD, "pgp"), (PGP_PKESK_NEW, "pgp"),
    (PGP_SKESK_NEW, "pgp"), (AGE, "age"),
])
def test_known_encrypted_headers(header, kind):
    head = header + os.urandom(64)
    assert encrypted_container_format(head) == kind
    # The integrity layer never takes a header's word for it.
    assert detect_format(head) == "unknown"


@pytest.mark.parametrize("fake", [
    b"\x85\x01\x0c\x09",       # PKESK tag, impossible version 9
    b"\x8c\x0d\x01",           # SKESK tag, impossible version 1
    b"\xc1",                   # truncated
    b"\x99\x01\x0c\x04",       # public-key packet (tag 6), not an encrypted message
])
def test_one_byte_lookalikes_are_not_trusted(fake):
    assert not is_openpgp_message(fake + b"\x00" * 3)


@pytest.mark.parametrize("name,header", [
    ("Passwords.kdbx", KDBX4), ("backup.tar.gpg", PGP_PKESK_OLD),
    ("notes.txt.age", AGE), ("secret.asc.gpg", PGP_SKESK_NEW),
])
def test_ml_rule_engine_leaves_vaults_alone(tmp_path, name, header):
    p = _random_file(tmp_path / name, header)
    f = extract_features(p)
    assert f["known_compressed_format"] == 1 and f["entropy_full"] > 7.9
    r = MLClassifier().classify(p)
    assert r.label == "benign" and r.indicators == []


def test_random_bytes_with_a_fake_header_are_still_flagged(tmp_path):
    p = _random_file(tmp_path / "invoice.docx.locked", b"\x85\x01\x0c\x09")
    assert MLClassifier().classify(p).label == "suspicious"


@pytest.mark.parametrize("name,header", [
    ("invoice.docx.locked", KDBX4),       # real KeePass header, ransomware extension
    ("report.pdf.enc", PGP_PKESK_OLD),
    ("Passwords.dat", KDBX4),
])
def test_header_without_matching_extension_is_not_trusted(tmp_path, name, header):
    p = _random_file(tmp_path / name, header)
    assert trusted_vault(p.read_bytes()[:64], p.suffix) == ""
    assert MLClassifier().classify(p).label == "suspicious"


def test_scanner_reports_a_vault_as_clean(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, file_extensions=[".kdbx"]))
    p = _random_file(tmp_path / "scan" / "Passwords.kdbx", KDBX4)
    r = s.scan_file(str(p))
    assert r["verdict"] == "Clean", r["score_breakdown"]


def test_forged_header_on_an_encrypted_document_does_not_lower_the_score(tmp_path):
    # Ransomware that keeps "budget.xlsx" and writes a KeePass/GPG header first
    # must still be reported as encrypted content, not as a mere mismatch.
    s = RS.RansomwareScanner(_config(tmp_path))
    for i, header in enumerate((KDBX4, PGP_PKESK_OLD, AGE)):
        p = _random_file(tmp_path / "scan" / f"budget{i}.xlsx", header)
        r = s.scan_file(str(p))
        assert "encrypted_content" in _indicators(r) and r["verdict"] in ("High", "Critical")
