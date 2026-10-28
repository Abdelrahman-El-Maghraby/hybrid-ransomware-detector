"""v4.3: RAR archives (RAR 4 and RAR 5) go through the same checks as the
other formats. Stored RAR 4 samples are built by tests/rar_builder.py; the
encrypted RAR 5 samples are rarfile's own fixtures (tests/data/rar/README.md)."""

import shutil
import zipfile
from pathlib import Path

import pytest

import detectors.container_extractor as ce
import RansomwareScanner as RS
from detectors.container_extractor import ContainerExtractor, detect_container
from tests.rar_builder import build_rar
from tests.test_file_integrity import _pe_bytes
from tests.test_scanner_integration import _config, _indicators

pytestmark = pytest.mark.skipif(not ce.RAR_AVAILABLE, reason="rarfile not installed")
needs_tool = pytest.mark.skipif(not ce.rar_tool_available(),
                                reason="no RAR decompressor (7-Zip / unrar / unar)")
# bsdtar (on every Mac) reads plain RAR but takes no password (B1)
needs_decrypting_tool = pytest.mark.skipif(not ce.rar_decrypts(),
                                           reason="no RAR tool that decrypts (7-Zip / unrar / unar)")
FIXTURES = Path(__file__).parent / "data" / "rar"


def names(res):
    return [m.name.split("!/", 1)[-1] for m in res.members]


def fixture(tmp_path, name):
    return Path(shutil.copy(FIXTURES / name, tmp_path / name))


@pytest.fixture
def no_rar_tool(monkeypatch):
    import rarfile
    for setting in ("UNRAR_TOOL", "UNAR_TOOL", "BSDTAR_TOOL", "SEVENZIP_TOOL", "SEVENZIP2_TOOL"):
        monkeypatch.setattr(rarfile, setting, "/nonexistent/" + setting.lower())
    monkeypatch.setattr(rarfile, "CURRENT_SETUP", None)
    monkeypatch.setattr(ce, "_rar_tool_state", None)
    monkeypatch.setattr(ce, "_rar_codec_state", None)
    # On Windows the extractor also looks for 7-Zip / WinRAR in Program Files.
    monkeypatch.setattr(ce, "_WINDOWS_RAR_TOOLS", ())
    yield
    ce._rar_tool_state = None
    ce._rar_codec_state = None


def test_detection_needs_extension_and_magic(tmp_path):
    rar = build_rar(tmp_path / "a.rar", [("x.txt", b"x")])
    renamed = tmp_path / "a.zip"
    renamed.write_bytes(rar.read_bytes())
    fake = tmp_path / "b.rar"
    fake.write_bytes(b"PK\x03\x04 not a rar")
    assert detect_container(rar) == "rar"
    assert detect_container(fixture(tmp_path, "rar5-psw.rar")) == "rar"
    assert detect_container(renamed) is None and detect_container(fake) is None


def test_members_are_extracted_and_lures_flagged(tmp_path):
    p = build_rar(tmp_path / "invoice.rar", [("docs/readme.txt", b"hello" * 50),
                                              ("invoice.pdf.exe", _pe_bytes(1024)),
                                              ("photo‮gpj.scr", b"x")])
    with ContainerExtractor().open(p) as res:
        assert res.container_type == "rar"
        assert names(res) == ["docs/readme.txt", "invoice.pdf.exe", "photo[RTLO]gpj.scr"]
        assert all(m.extracted for m in res.members)
        assert res.double_extension_members == ["invoice.rar!/invoice.pdf.exe"]
        assert res.rtlo_members == ["invoice.rar!/photo[RTLO]gpj.scr"]
        exe = res.members[1]
        assert Path(exe.path).read_bytes()[:2] == b"MZ"
        assert Path(exe.path).parent.parent == Path(res.members[0].path).parent.parent


def test_slip_and_symlink_members_are_never_written(tmp_path):
    p = build_rar(tmp_path / "x.rar", [("../../evil.sh", b"rm -rf ~"), ("link", b"/etc/passwd"),
                                        ("ok.txt", b"fine")], unix_modes={"link": 0o120777})
    with ContainerExtractor().open(p) as res:
        assert res.zip_slip
        skipped = {n for n, m in zip(names(res), res.members) if not m.extracted}
        assert skipped == {"../../evil.sh", "link"}
        written = [m for m in res.members if m.path]
        assert [Path(m.path).read_bytes() for m in written] == [b"fine"]


def test_limits_apply(tmp_path):
    p = build_rar(tmp_path / "many.rar", [(f"f{i}.txt", b"x") for i in range(30)])
    with ContainerExtractor(max_members=10).open(p) as res:
        assert not res.zip_bomb                  # many entries: partial scan, not a bomb
        assert len(res.members) == 10 and res.skipped_members == 20
    big = build_rar(tmp_path / "big.rar", [("a.bin", b"\0" * 5000), ("b.bin", b"\0" * 5000)])
    with ContainerExtractor(max_total_bytes=6000).open(big) as res:
        assert res.zip_bomb


def test_nesting_across_formats(tmp_path):
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("payload.js", "WScript.Shell")
    p = build_rar(tmp_path / "outer.rar", [("inner.zip", inner.read_bytes())])
    with ContainerExtractor().open(p) as res:
        assert names(res) == ["inner.zip", "inner.zip!/payload.js"]
        assert res.executable_members == ["outer.rar!/inner.zip!/payload.js"]


@needs_decrypting_tool
def test_encrypted_rar5_opened_with_delivery_password(tmp_path):
    with ContainerExtractor().open(fixture(tmp_path, "rar5-psw.rar")) as res:
        assert res.password_used == "password" and not res.encrypted_unreadable
        assert names(res) == ["stest1.txt", "stest2.txt"]
        assert all(m.extracted and m.encrypted for m in res.members)
        assert all(Path(m.path).stat().st_size == 2048 for m in res.members)


@needs_decrypting_tool
def test_encrypted_file_names_opened_with_delivery_password(tmp_path):
    with ContainerExtractor().open(fixture(tmp_path, "rar5-hpsw.rar")) as res:
        assert res.password_used == "password"
        assert names(res) == ["stest1.txt", "stest2.txt"]
        assert all(m.extracted for m in res.members)


@needs_decrypting_tool
def test_unknown_password_is_reported(tmp_path):
    ex = ContainerExtractor(passwords=("infected",))
    with ex.open(fixture(tmp_path, "rar5-psw.rar")) as res:
        assert res.encrypted_unreadable and res.unreadable_members == 2
        assert {m.skipped_reason for m in res.members} == {"encrypted - password unknown"}
    with ex.open(fixture(tmp_path, "rar5-hpsw.rar")) as res:
        assert res.encrypted_unreadable and names(res) == ["(encrypted file names)"]


def test_corrupt_archives_are_unreadable_not_empty(tmp_path):
    p = build_rar(tmp_path / "x.rar", [("a.txt", b"a" * 100)])
    raw = p.read_bytes()
    header = bytearray(raw)
    header[30] ^= 0xFF          # a broken file header must not make the archive look empty
    p.write_bytes(bytes(header))
    with ContainerExtractor().open(p) as res:
        assert res.unreadable_members == 1 and res.members == []
    data = bytearray(raw)
    data[-20] ^= 0xFF           # a broken member fails its CRC instead of being scanned
    p.write_bytes(bytes(data))
    with ContainerExtractor().open(p) as res:
        assert res.unreadable_members == 1 and res.members[0].skipped_reason == "could not extract"


def test_without_a_decompressor_names_are_still_checked(tmp_path, no_rar_tool):
    assert not ce.rar_tool_available()
    with ContainerExtractor().open(fixture(tmp_path, "rar5-psw.rar")) as res:
        assert not any(m.extracted for m in res.members)
        assert res.members[0].skipped_reason == "needs a RAR decompressor (7-Zip, unrar or unar)"
        assert "could not be opened: install 7-Zip" in res.detail
    # Stored members need no decompressor at all.
    p = build_rar(tmp_path / "s.rar", [("a.pdf.exe", b"MZ" + b"\0" * 64)])
    with ContainerExtractor().open(p) as res:
        assert res.members[0].extracted and res.double_extension_members


def test_without_rarfile_says_what_to_install(tmp_path, monkeypatch):
    monkeypatch.setattr(ce, "RAR_AVAILABLE", False)
    with ContainerExtractor().open(build_rar(tmp_path / "x.rar", [("a", b"a")])) as res:
        assert "pip install rarfile" in res.detail and res.unreadable_members == 1


def test_scanner_scores_a_rar_like_its_worst_member(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path))
    p = build_rar(tmp_path / "parcel.rar", [("invoice.pdf.exe", _pe_bytes(2048)),
                                             ("readme.txt", b"hello")])
    r = s.scan_file(str(p))
    assert r["scan_results"]["archive"]["container_type"] == "rar"
    assert "archive_double_extension" in _indicators(r)
    assert r["verdict"] in ("High", "Critical")


def test_integrity_validates_rar_and_7z_signatures(tmp_path):
    from detectors.file_integrity import FileIntegrityAnalyzer
    good = FileIntegrityAnalyzer().analyze_file(build_rar(tmp_path / "a.rar", [("x.txt", b"x")]))
    assert good.magic_ok and "not validated" not in good.detail
    encrypted = tmp_path / "b.rar"            # an archive ransomware has encrypted in place
    encrypted.write_bytes(__import__("os").urandom(64 * 1024))
    res = FileIntegrityAnalyzer().analyze_file(encrypted)
    assert res.encrypted_likely and not res.disguised_executable
    exe = tmp_path / "c.7z"                   # an archive extension is not a "document" disguise
    exe.write_bytes(_pe_bytes(2048))
    assert not FileIntegrityAnalyzer().analyze_file(exe).disguised_executable


# ---- 4.4.0-beta.2: a 7-Zip without the RAR codec is named, not called "encrypted"
SEVENZIP_INFO_WITH_RAR = """Formats:
 0  ...F....  Rar5  rar r00
Codecs:
 0  ED  40301 Rar1
 0  ED  40305 Rar5
 0  ED  40108 Deflate
Hashers:
 4  1 CRC32
"""
SEVENZIP_INFO_WITHOUT_RAR = """Formats:
 0  ...F....  Rar   rar r00
 0  ...F....  Rar5  rar r00
Codecs:
 0  ED  30101 LZMA
 0  ED  40108 Deflate
Hashers:
 4  1 CRC32
"""


def test_sevenzip_codec_list_is_read_from_the_codecs_section():
    assert not ce.sevenzip_lacks_rar_codec(SEVENZIP_INFO_WITH_RAR)
    # the format table mentions "Rar5" too, but only the codec list counts
    assert ce.sevenzip_lacks_rar_codec(SEVENZIP_INFO_WITHOUT_RAR)
    assert not ce.sevenzip_lacks_rar_codec("")          # unknown output: no claim


def test_codec_less_7zip_is_reported_instead_of_a_password(tmp_path, monkeypatch):
    import rarfile
    p = build_rar(tmp_path / "a.rar", [("note.txt", b"hello")])

    def fail(*_a, **_k):
        raise rarfile.RarExecError("7z: Unsupported Method")
    monkeypatch.setattr(rarfile.RarFile, "open", fail)
    monkeypatch.setattr(ce, "_rar_codec_state", ce.RAR_NO_CODEC)
    with ContainerExtractor().open(p) as res:
        member = res.members[0]
        assert not member.extracted
        assert "no RAR codec" in member.skipped_reason
        assert "password" not in member.skipped_reason
        assert any("RAR codec" in m for m in res.missing_support)


def test_bsdtar_is_named_when_it_cannot_decrypt(tmp_path, monkeypatch):
    """B1: with only bsdtar, an encrypted RAR is reported as needing a tool that
    decrypts - not as 'no decompressor' or a wrong password - and the archive
    layer says so in its state."""
    monkeypatch.setattr(ce, "rar_tool_available", lambda: True)
    monkeypatch.setattr(ce, "rar_decrypts", lambda: False)

    def cannot(*a, **k):
        raise ce._rarfile.RarCannotExec("bsdtar does not support passwords")
    monkeypatch.setattr(ce._rarfile.RarFile, "open", cannot)
    with ContainerExtractor().open(fixture(tmp_path, "rar5-psw.rar")) as res:
        reasons = {m.skipped_reason for m in res.members if m.encrypted}
    assert reasons == {ce.BSDTAR_NO_PASSWORDS}
    from engine import capabilities as C
    state = C._archive(None)
    assert state["state"] == "up" and "bsdtar" in state["detail"]
