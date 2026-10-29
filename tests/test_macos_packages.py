"""macOS installer packages (.pkg) and disk images (.dmg).

Packages are read in pure Python; disk images need a 7-Zip executable, and
those tests skip without one. All samples are built by tests/macos_builder.py.
"""

import logging
import lzma
import struct

import pytest

import RansomwareScanner as RS
from detectors import container_extractor as ce
from detectors import macos_packages as mp
from detectors.container_extractor import ContainerExtractor, detect_container
from tests.helpers import make_pdf
from tests.macos_builder import (
    build_dmg,
    build_encrypted_dmg,
    build_pkg,
    cpio_odc,
)
from tests.test_file_integrity import _pe_bytes
from tests.test_scanner_integration import _config

X = ContainerExtractor()
SCRIPT = ("./postinstall", b"#!/bin/sh\necho installed\n", 0o100755)
APP_FILE = ("./Applications/Demo.app/Contents/Info.plist", b"<plist/>", 0o100644)
needs_7zip = pytest.mark.skipif(mp.sevenzip_tool() is None, reason="7-Zip not installed")


@pytest.fixture
def scanner(tmp_path):
    logging.disable(logging.CRITICAL)
    yield RS.RansomwareScanner(_config(tmp_path))
    logging.disable(logging.NOTSET)


def _indicators(result):
    return {c["indicator"] for c in result["score_breakdown"]["contributions"]}


# ------------------------------------------------------------------ format
def test_pkg_and_dmg_are_recognised_by_content(tmp_path):
    assert detect_container(build_pkg(tmp_path / "a.pkg", scripts=[SCRIPT])) == "pkg"
    assert detect_container(build_dmg(tmp_path / "a.dmg", files=[("a.txt", b"x")])) == "dmg"
    (tmp_path / "fake.pkg").write_bytes(b"not a package")
    (tmp_path / "fake.dmg").write_bytes(b"\x00" * 2048)
    assert detect_container(tmp_path / "fake.pkg") is None
    assert detect_container(tmp_path / "fake.dmg") is None


def test_cpio_odc_and_newc_round_trip():
    entries = list(mp.read_cpio(cpio_odc([SCRIPT, APP_FILE])))
    assert [e.name for e in entries] == ["postinstall", APP_FILE[0][2:]]
    assert entries[0].is_executable and not entries[1].is_executable

    def newc(name, data, mode):
        raw = name.encode() + b"\x00"
        head = b"070701" + b"".join(b"%08X" % v for v in
                                    (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw), 0))
        blob = head + raw
        blob += b"\x00" * (-len(blob) % 4) + data
        return blob + b"\x00" * (-len(blob) % 4)

    data = newc("a/b.txt", b"hello", 0o100644) + newc("TRAILER!!!", b"", 0)
    (e,) = list(mp.read_cpio(data))
    assert (e.name, e.data) == ("a/b.txt", b"hello")


def test_pbzx_payload_is_decompressed():
    inner = cpio_odc([APP_FILE])
    chunk = lzma.compress(inner, format=lzma.FORMAT_XZ)
    stream = b"pbzx" + struct.pack(">Q", 1 << 24) + struct.pack(">QQ", 0, len(chunk)) + chunk
    assert mp.stream_decompress(stream, 10_000) == inner


def test_decompression_stops_at_the_budget():
    big = mp.gzip_bytes(b"\x00" * 1_000_000)
    with pytest.raises(mp.BudgetExceeded):
        mp.stream_decompress(big, 10_000)


# --------------------------------------------------------------------- PKG
def test_pkg_scripts_and_payload_are_unpacked(tmp_path):
    p = build_pkg(tmp_path / "app.pkg", scripts=[SCRIPT], payload=[APP_FILE])
    with X.open(p) as res:
        names = [m.name for m in res.members]
        assert "app.pkg!/app.pkg/Scripts/postinstall" in names
        assert "app.pkg!/app.pkg/Payload/Applications/Demo.app/Contents/Info.plist" in names
        # Install scripts are expected in an installer: listed, not scored as such.
        assert res.installer_executables == ["app.pkg!/app.pkg/Scripts/postinstall"]
        assert res.executable_members == []
        assert not (res.zip_bomb or res.zip_slip)


def test_benign_pkg_is_clean(scanner, tmp_path):
    p = build_pkg(tmp_path / "scan" / "app.pkg", scripts=[SCRIPT], payload=[APP_FILE])
    assert scanner.scan_file(str(p))["verdict"] == "Clean"


def test_disguised_executable_in_pkg_payload_is_caught(scanner, tmp_path):
    p = build_pkg(tmp_path / "scan" / "update.pkg",
                  payload=[("./tmp/report.pdf", _pe_bytes(4096), 0o100644)])
    r = scanner.scan_file(str(p))
    assert "archive_member:disguised_executable" in _indicators(r)
    assert r["verdict"] in ("High", "Critical")


def test_path_traversal_in_pkg_payload_is_blocked(tmp_path):
    p = build_pkg(tmp_path / "evil.pkg",
                  payload=[("../../../etc/evil", b"x", 0o100644), APP_FILE])
    with X.open(p) as res:
        assert res.zip_slip
        assert not any("etc/evil" in (m.path or "") for m in res.members)


def test_oversized_payload_is_not_unpacked_and_not_a_bomb(tmp_path):
    p = build_pkg(tmp_path / "big.pkg", payload=[("./big.bin", b"\x00" * 300_000, 0o100644)])
    small = ContainerExtractor(max_total_bytes=50_000)
    with small.open(p) as res:
        assert not res.zip_bomb
        assert any("not unpacked" in m.skipped_reason for m in res.members)


def test_package_with_more_files_than_the_limit_is_not_a_bomb(tmp_path):
    # A real .app payload easily holds thousands of files.
    many = [(f"./f{i}.txt", b"x", 0o100644) for i in range(30)]
    p = build_pkg(tmp_path / "many.pkg", payload=many)
    with ContainerExtractor(max_members=10).open(p) as res:
        assert not res.zip_bomb
        assert any("member limit" in m.skipped_reason for m in res.members)


def test_corrupt_pkg_does_not_raise(tmp_path):
    p = tmp_path / "broken.pkg"
    p.write_bytes(b"xar!" + struct.pack(">HHQQI", 28, 1, 40, 400, 0) + b"\x01" * 40)
    with X.open(p) as res:
        assert res.unreadable_members >= 1


def test_pkg_attachment_counts_as_executable_in_a_zip(tmp_path):
    import zipfile
    inner = build_pkg(tmp_path / "Setup.pkg", scripts=[SCRIPT])
    z = tmp_path / "files.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(inner, "Setup.pkg")
    with X.open(z) as res:
        assert "files.zip!/Setup.pkg" in res.executable_members      # outside an installer


# --------------------------------------------------------------------- DMG
@needs_7zip
def test_dmg_files_are_extracted(tmp_path):
    p = build_dmg(tmp_path / "app.dmg", files=[("readme.txt", b"hello"),
                                               ("letter.pdf", make_pdf("Hello"))])
    with X.open(p) as res:
        names = sorted(m.name for m in res.members)
        assert names == ["app.dmg!/letter.pdf", "app.dmg!/readme.txt"]
        assert all(m.extracted for m in res.members)


@needs_7zip
def test_benign_dmg_is_clean(scanner, tmp_path):
    p = build_dmg(tmp_path / "scan" / "app.dmg", files=[("letter.pdf", make_pdf("Hello"))])
    assert scanner.scan_file(str(p))["verdict"] == "Clean"


@needs_7zip
def test_lure_in_dmg_is_caught(scanner, tmp_path):
    p = build_dmg(tmp_path / "scan" / "invoice.dmg",
                  files=[("Invoice.pdf.exe", _pe_bytes(4096))])
    r = scanner.scan_file(str(p))
    assert "archive_double_extension" in _indicators(r)
    assert r["verdict"] in ("High", "Critical")


@needs_7zip
def test_large_dmg_is_not_unpacked_and_not_a_bomb(tmp_path):
    p = build_dmg(tmp_path / "big.dmg", files=[("big.bin", b"\x00" * 200_000)])
    with ContainerExtractor(max_total_bytes=50_000).open(p) as res:
        assert not res.zip_bomb
        assert any("not unpacked" in m.skipped_reason for m in res.members)


def test_encrypted_dmg_is_reported(scanner, tmp_path):
    p = build_encrypted_dmg(tmp_path / "scan" / "secret.dmg")
    assert detect_container(p) == "dmg"
    r = scanner.scan_file(str(p))
    assert "archive_encrypted" in _indicators(r)


def test_dmg_without_7zip_says_what_to_install(monkeypatch, tmp_path):
    monkeypatch.setattr(ce, "sevenzip_tool", lambda: None)
    p = build_dmg(tmp_path / "app.dmg", files=[("a.txt", b"x")])
    with X.open(p) as res:
        assert res.members == []
        assert "7-Zip" in " ".join(res.missing_support)
        assert "install 7-Zip" in X._summary(res)


@pytest.mark.parametrize("magic,start,end,base", [
    (b"070707", 18, 24, 8), (b"070707", 59, 65, 8),
    (b"070707", 65, 76, 8), (b"070701", 14, 22, 16),
    (b"070701", 54, 62, 16), (b"070701", 94, 102, 16),
    (b"070702", 14, 22, 16), (b"070702", 54, 62, 16),
    (b"070702", 94, 102, 16),
])
@pytest.mark.parametrize("bad", [b"\x00", b"Z", b"-", b"+"])
def test_cpio_invalid_numeric_fields_are_format_errors(magic, start, end, base, bad):
    """Atheris found a NUL in an odc size; all used fields are unsigned digits."""
    header_size = 76 if base == 8 else 110
    data = bytearray(magic + b"0" * (header_size - 6))
    data[start:end] = bad + b"0" * (end - start - 1)
    with pytest.raises(mp.FormatError, match="numeric"):
        list(mp.read_cpio(bytes(data)))
