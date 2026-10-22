import os
import random
import zipfile
import zlib

import pytest

from detectors.file_integrity import (
    FileIntegrityAnalyzer,
    detect_format,
    looks_encrypted,
    looks_random,
    random_entropy_threshold,
    ransom_indicator,
    shannon_entropy,
)
from tests.helpers import make_docx, make_pdf

A = FileIntegrityAnalyzer()


def _compressible_text(n_words=60000, seed=7):
    rnd = random.Random(seed)
    words = ["invoice", "payment", "the", "report", "quarter", "total", "amount", "customer"]
    return " ".join(rnd.choice(words) + str(rnd.randint(0, 999)) for _ in range(n_words)).encode()


# ---------------------------------------------------------------- calibration
@pytest.mark.parametrize("n", [1024, 4096, 65536])
def test_random_bytes_always_look_random(n):
    # 200 independent samples. The thresholds are a statistical test: measured
    # over 300,000 random 1 KiB blocks they reject about 1 in 100,000, so one
    # miss in 200 is tolerated to keep the suite deterministic in practice.
    assert sum(not looks_random(os.urandom(n)) for _ in range(200)) <= 1


def test_chi_square_separates_structured_compression():
    # Repetitive content compresses into a stream that is high-entropy yet
    # measurably non-uniform: chi-square rejects it.
    words = (b"invoice payment total amount customer quarter report " * 4000)
    data = zlib.compress(words + _compressible_text(4000), 9)
    data = (data * (65536 // len(data) + 1))[:65536] if len(data) < 65536 else data[:65536]
    assert not looks_random(data)


def test_high_entropy_office_files_are_not_flagged(tmp_path):
    # A .docx full of compressed/random media has ~8 bits/byte of entropy, but
    # its ZIP signature is intact, so it must never be called "encrypted".
    p = tmp_path / "photos.docx"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_STORED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/media/image1.png", os.urandom(300_000))
    r = A.analyze_file(p)
    assert r.sample_entropy > 7.9 and r.magic_ok and not r.encrypted_likely


def test_headerless_compressed_data_is_a_known_limit():
    # Honest limitation: a raw deflate stream of high-entropy input can be as
    # uniform as ciphertext. That is why randomness is only consulted when a
    # document's format signature is already missing.
    data = zlib.compress(_compressible_text(), 9)[2:]
    assert shannon_entropy(data[:65536]) > 7.99


def test_gzip_renamed_to_pdf_is_a_mismatch_not_encryption(tmp_path):
    import gzip
    p = tmp_path / "statement.pdf"
    p.write_bytes(gzip.compress(_compressible_text()))
    r = A.analyze_file(p)
    assert r.detected_format == "gzip" and r.format_mismatch and not r.encrypted_likely


def test_plain_text_and_short_samples_are_not_random():
    assert not looks_random(b"hello world " * 1000)
    assert not looks_random(os.urandom(512))             # too short to judge
    assert random_entropy_threshold(4096) < 7.955 < 8.0


# -------------------------------------------------------------------- formats
def _pe_bytes(size=512):
    h = bytearray(size)
    h[0:2] = b"MZ"
    h[0x3C:0x40] = (0x80).to_bytes(4, "little")
    h[0x80:0x84] = b"PE\x00\x00"
    return bytes(h)


@pytest.mark.parametrize("head,fmt", [
    (b"%PDF-1.7\n", "pdf"), (b"PK\x03\x04rest", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"{\\rtf1\\ansi", "rtf"),
    (_pe_bytes(), "pe"), (b"\x7fELF\x02", "elf"), (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"#!/bin/sh\n", "script"),
    (b"<!DOCTYPE html><html>", "html"), (b"\xef\xbb\xbf<html>", "html"),
    (b"MIME-Version: 1.0\r\n", "mht"), (b"plain words only\n", "text"),
    (b"\x1f\x8b\x08", "gzip"), (b"", "empty"),
])
def test_detect_format(head, fmt):
    assert detect_format(head) == fmt


# ------------------------------------------------------------------ analyzer
def test_real_documents_pass(tmp_path):
    d = make_docx(tmp_path / "report.docx")
    p = tmp_path / "letter.pdf"
    p.write_bytes(make_pdf("Dear customer"))
    for path in (d, p):
        r = A.analyze_file(path)
        assert r.magic_ok is True
        assert not (r.encrypted_likely or r.disguised_executable or r.format_mismatch)


def test_random_header_never_looks_like_an_executable():
    # 'MZ' / '#!' / zlib headers occur by chance in ciphertext; they must not
    # turn an encrypted file into a "disguised executable".
    # Seeded, and many samples: a single os.urandom() draw made this test fail
    # about once in 900 runs, because the old shebang rule accepted "#!/s".
    rnd = random.Random(20261017)
    for _ in range(3000):
        noise = bytes(rnd.getrandbits(8) for _ in range(120))
        assert detect_format(b"MZ" + noise) == "unknown"
        assert detect_format(b"#!" + noise) == "unknown"
        assert detect_format(b"\x78\x9c" + noise) == "unknown"


@pytest.mark.parametrize("head", [
    b"#!/sG\x91\xa2\xa9\xcc7*\xd8",                 # the sample that failed in CI-like runs
    b"#!/usr/bin/env python3",                      # no line end: not proven to be a script
    b"#!/bin/sh \x00\x91 -c\n",                    # binary bytes in the "arguments"
    b"#!" + b"/a" * 200 + b"\n",                     # line longer than any real interpreter line
])
def test_shebang_needs_a_real_interpreter_line(head):
    assert detect_format(head) != "script"


@pytest.mark.parametrize("head", [
    b"#!/bin/sh\n", b"#!/usr/bin/env python3\nprint(1)\n", b"#! /bin/bash -e\r\n",
    b"#!/usr/bin/perl -w\nuse strict;\n", b"#!/opt/node-20/bin/node\n",
])
def test_real_shebangs_are_still_scripts(head):
    assert detect_format(head) == "script"


@pytest.mark.parametrize("name,head,kind", [
    ("invoice.pdf", _pe_bytes(), "pe"),
    ("scan.docx", b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 100, "lnk"),
    ("cv.doc", b"\x7fELF\x02\x01\x01" + b"\x00" * 100, "elf"),
])
def test_disguised_executables(tmp_path, name, head, kind):
    p = tmp_path / name
    p.write_bytes(head)
    r = A.analyze_file(p)
    assert r.disguised_executable == kind and r.magic_ok is False


def test_fully_encrypted_document(tmp_path):
    p = tmp_path / "budget.xlsx"
    p.write_bytes(os.urandom(200_000))
    r = A.analyze_file(p)
    assert r.encrypted_likely and "random" in r.detail


def test_intermittent_encryption_only_first_block(tmp_path):
    body = make_pdf("x" * 50) + _compressible_text(20000)
    p = tmp_path / "contract.pdf"
    p.write_bytes(os.urandom(4096) + body[4096:])
    r = A.analyze_file(p)
    assert r.encrypted_likely and "intermittent" in r.detail


def test_html_export_named_xls_is_benign(tmp_path):
    p = tmp_path / "CardStatement.xls"
    p.write_bytes(b"<html><body><table><tr><td>1</td></tr></table></body></html>")
    r = A.analyze_file(p)
    assert r.magic_ok is False and r.notes
    assert not (r.encrypted_likely or r.format_mismatch or r.disguised_executable)


def test_password_protected_ooxml_is_noted_not_flagged(tmp_path):
    p = tmp_path / "salary.docx"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + os.urandom(5000))
    r = A.analyze_file(p)
    assert not r.encrypted_likely and not r.format_mismatch
    assert "password-protected" in r.detail


def test_plain_zip_renamed_to_docx_is_a_mismatch(tmp_path):
    p = tmp_path / "offer.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("payload.txt", "hello")
    assert A.analyze_file(p).format_mismatch


def test_text_renamed_to_pdf_is_a_mismatch(tmp_path):
    p = tmp_path / "notes.pdf"
    p.write_text("just some text " * 200)
    r = A.analyze_file(p)
    assert r.format_mismatch and not r.encrypted_likely


def test_unknown_extension_is_not_validated(tmp_path):
    p = tmp_path / "data.bin"
    p.write_bytes(os.urandom(5000))
    r = A.analyze_file(p)
    assert r.magic_ok is None and not r.encrypted_likely


def test_looks_encrypted_on_head_or_first_block():
    assert looks_encrypted(os.urandom(65536))
    assert looks_encrypted(os.urandom(4096) + b"A" * 60000)
    assert not looks_encrypted(b"A" * 65536)


# ------------------------------------------------------- ransom indicators
@pytest.mark.parametrize("name,expected", [
    ("HOW_TO_DECRYPT.txt", "ransom_note"), ("_readme.txt", "ransom_note"),
    ("!!!READ_ME!!!.txt", "ransom_note"), ("RESTORE_MY_FILES.html", "ransom_note"),
    ("YOUR_FILES_ARE_ENCRYPTED.hta", "ransom_note"),
    ("report.docx.lockbit", "ransom_extension"), ("photo.jpg.locked", "ransom_extension"),
    ("a.pdf.id-1A2B3C4D.[help@evil.example].dharma", "ransom_extension"),
    ("README.txt", None), ("notes.txt", None), ("decryption_theory.pdf", None),
    ("invoice.pdf", None),
])
def test_ransom_indicator(name, expected):
    assert ransom_indicator(name) == expected
