import io
import os
import stat
import zipfile
from pathlib import Path

import pytest

from detectors.container_extractor import ContainerExtractor
from tests.helpers import make_docx, make_zipcrypto_zip

X = ContainerExtractor()


def _zip(path: Path, members) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            if isinstance(name, zipfile.ZipInfo):
                z.writestr(name, data)
            else:
                z.writestr(name, data)
    return path


def test_extracts_members_into_a_sandbox_that_is_removed(tmp_path):
    doc = make_docx(tmp_path / "invoice.docx")
    arc = _zip(tmp_path / "mail.zip", [("invoice.docx", doc.read_bytes()), ("note.txt", "hi")])
    assert X.is_container(arc)
    with X.open(arc) as res:
        paths = [Path(m.path) for m in res.members if m.extracted]
        assert {m.name for m in res.members} == {"mail.zip!/invoice.docx", "mail.zip!/note.txt"}
        assert all(p.exists() for p in paths)
        assert not (res.zip_bomb or res.zip_slip or res.executable_members)
    assert not any(p.exists() for p in paths)


def test_nested_archives_are_followed_with_chained_names(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("payload.docm", b"PK fake")
    arc = _zip(tmp_path / "outer.zip", [("inner.zip", inner.getvalue())])
    with X.open(arc) as res:
        names = [m.name for m in res.members]
        assert "outer.zip!/inner.zip!/payload.docm" in names
        assert res.max_depth_reached == 2


@pytest.mark.parametrize("evil", ["../../.bashrc", "/etc/cron.d/x", "C:\\Windows\\x.dll",
                                  "..\\..\\startup\\x.bat", "a/../../b.txt"])
def test_zip_slip_members_are_blocked(tmp_path, evil):
    arc = _zip(tmp_path / "slip.zip", [("ok.txt", "fine"), (evil, "pwned")])
    with X.open(arc) as res:
        assert res.zip_slip
        bad = [m for m in res.members if m.skipped_reason.startswith("unsafe")]
        assert len(bad) == 1 and not bad[0].extracted
    assert not (tmp_path.parent / ".bashrc").exists()


def test_symlink_member_is_blocked(tmp_path):
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    arc = _zip(tmp_path / "ln.zip", [(info, "/etc/passwd")])
    with X.open(arc) as res:
        assert res.zip_slip and "symbolic link" in res.zip_slip_reason


def test_compression_ratio_bomb(tmp_path):
    arc = _zip(tmp_path / "bomb.zip", [("zeros.bin", b"\x00" * (5 * 1024 * 1024))])
    with X.open(arc) as res:
        assert res.zip_bomb and "expands" in res.zip_bomb_reason


def test_member_count_and_size_limits(tmp_path):
    # Many entries are not a bomb: the first ones are unpacked (programs first),
    # the names of the rest are still checked.
    entries = [(f"f{i}.txt", "x") for i in range(20)] + [("late.pdf.exe", "MZ")]
    many = _zip(tmp_path / "many.zip", entries)
    with ContainerExtractor(max_members=10).open(many) as res:
        assert not res.zip_bomb
        assert len(res.members) == 10 and res.skipped_members == 11
        assert any(m.name.endswith("late.pdf.exe") and m.extracted for m in res.members)
    names_only = _zip(tmp_path / "names.zip",
                      [(f"f{i}.txt", "x") for i in range(10)] + [("a.exe", "x"), ("b.pdf.scr", "x")])
    with ContainerExtractor(max_members=1).open(names_only) as res:
        assert res.skipped_members == 11
        assert any(n.endswith("b.pdf.scr") for n in res.double_extension_members)
        assert len(res.executable_members) == 2
    big = _zip(tmp_path / "big.zip", [("r.bin", os.urandom(300_000))])
    with ContainerExtractor(max_total_bytes=100_000).open(big) as res:
        assert res.zip_bomb


def test_nesting_depth_limit(tmp_path):
    data = b"leaf"
    for level in range(5):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("n.zip" if level else "leaf.txt", data)
        data = buf.getvalue()
    arc = tmp_path / "deep.zip"
    arc.write_bytes(data)
    with ContainerExtractor(max_depth=3).open(arc) as res:
        assert res.zip_bomb and "nested" in res.zip_bomb_reason


def test_lure_names_and_executables(tmp_path):
    arc = _zip(tmp_path / "lure.zip", [
        ("invoice.pdf.exe", b"MZ\x90\x00"),
        ("Invoice\u202efdp.scr", b"MZ\x90\x00"),
        ("readme.txt", b"MZ\x90\x00 really an exe"),
        ("photo.jpg", b"\xff\xd8\xff"),
    ])
    with X.open(arc) as res:
        assert res.double_extension_members == ["lure.zip!/invoice.pdf.exe"]
        assert res.rtlo_members == ["lure.zip!/Invoice[RTLO]fdp.scr"]
        assert set(res.executable_members) == {"lure.zip!/invoice.pdf.exe",
                                               "lure.zip!/Invoice[RTLO]fdp.scr",
                                               "lure.zip!/readme.txt"}


def test_password_protected_archive_opened_with_common_password(tmp_path):
    arc = make_zipcrypto_zip(tmp_path / "invoice.zip", "invoice.docm", b"secret doc", "infected")
    with X.open(arc) as res:
        m = res.members[0]
        assert m.encrypted and m.extracted and res.password_used == "infected"
        assert Path(m.path).read_bytes() == b"secret doc"
        assert not res.encrypted_unreadable


def test_password_equal_to_archive_name(tmp_path):
    arc = make_zipcrypto_zip(tmp_path / "Q3-report.zip", "a.docx", b"data", "q3-report")
    with X.open(arc) as res:
        assert res.members[0].extracted and res.password_used == "q3-report"


def test_unknown_password_is_reported_unreadable(tmp_path):
    arc = make_zipcrypto_zip(tmp_path / "x.zip", "a.docm", b"data" * 100, "Tr0ub4dor&3")
    with X.open(arc) as res:
        assert res.encrypted_unreadable and not res.members[0].extracted
        assert "password unknown" in res.members[0].skipped_reason


def test_not_a_container(tmp_path):
    doc = make_docx(tmp_path / "x.docx")          # a ZIP, but not an archive to unpack
    assert not X.is_container(doc)
    fake = tmp_path / "fake.zip"
    fake.write_bytes(b"not a zip")
    assert not X.is_container(fake)
