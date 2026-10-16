"""v4.2 archive formats: WinZip-AES ZIPs, 7z (incl. encrypted names) and ISO
images, through the extractor and through the full scanner."""

import io
import zipfile

import pytest

import RansomwareScanner as RS
import detectors.container_extractor as ce
from detectors.container_extractor import ContainerExtractor, detect_container
from tests.helpers import make_pdf
from tests.test_file_integrity import _pe_bytes
from tests.test_scanner_integration import _config, _indicators

pyzipper = pytest.importorskip("pyzipper") if ce.AES_ZIP_AVAILABLE else None
needs_aes = pytest.mark.skipif(not ce.AES_ZIP_AVAILABLE, reason="pyzipper not installed")
needs_7z = pytest.mark.skipif(not ce.SEVENZIP_AVAILABLE, reason="py7zr not installed")
needs_iso = pytest.mark.skipif(not ce.ISO_AVAILABLE, reason="pycdlib not installed")


def aes_zip(path, members, password="infected"):
    with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password.encode())
        for name, data in members.items():
            z.writestr(name, data)
    return path


def seven_zip(path, members, password=None, header_encryption=False):
    import py7zr
    with py7zr.SevenZipFile(path, "w", password=password,
                            header_encryption=header_encryption) as z:
        for name, data in members.items():
            z.writestr(data, name)
    return path


def iso_image(path, members, rock_ridge=True):
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(joliet=3, rock_ridge="1.09" if rock_ridge else None)
    made = set()
    for i, (name, data) in enumerate(members.items()):
        parts = name.split("/")
        for d in range(1, len(parts)):
            sub = "/".join(parts[:d])
            if sub not in made:
                iso.add_directory("/" + "/".join(f"D{d}{j}" for j in range(d)),
                                  joliet_path="/" + sub,
                                  **({"rr_name": parts[d - 1]} if rock_ridge else {}))
                made.add(sub)
        iso_dir = "/".join(f"D{d}{j}" for d in range(1, len(parts)) for j in [d - 1])
        iso_name = ("/" + iso_dir + "/" if iso_dir else "/") + f"F{i}.BIN;1"
        iso.add_fp(io.BytesIO(data), len(data), iso_name, joliet_path="/" + name,
                   **({"rr_name": parts[-1]} if rock_ridge else {}))
    iso.write(str(path))
    iso.close()
    return path


def names(res):
    return [m.name.split("!/", 1)[-1] for m in res.members]


# ----------------------------------------------------------------- detection
def test_detect_container_needs_extension_and_content(tmp_path):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.txt", "x")
    fake = tmp_path / "b.7z"
    fake.write_bytes(b"not an archive")
    renamed = tmp_path / "c.iso"
    renamed.write_bytes(z.read_bytes())
    assert detect_container(z) == "zip"
    assert detect_container(fake) is None and detect_container(renamed) is None


# ----------------------------------------------------------------------- AES
@needs_aes
def test_aes_zip_opened_with_delivery_password(tmp_path):
    p = aes_zip(tmp_path / "invoice.zip", {"invoice.docm": b"PK fake docm", "a.pdf.exe": b"MZ"})
    with ContainerExtractor().open(p) as res:
        assert res.password_used == "infected" and not res.encrypted_unreadable
        assert all(m.extracted for m in res.members)
        assert res.double_extension_members == ["invoice.zip!/a.pdf.exe"]


@needs_aes
def test_aes_zip_unknown_password_is_reported(tmp_path):
    p = aes_zip(tmp_path / "x.zip", {"payload.js": b"WScript"}, password="Tr0ub4dor&3")
    with ContainerExtractor().open(p) as res:
        assert res.encrypted_unreadable and res.unreadable_members == 1
        assert res.members[0].skipped_reason == "encrypted - password unknown"


def test_aes_zip_without_pyzipper_says_what_to_install(tmp_path, monkeypatch):
    if not ce.AES_ZIP_AVAILABLE:
        pytest.skip("needs pyzipper to build the sample")
    p = aes_zip(tmp_path / "x.zip", {"a.txt": b"hello"})
    monkeypatch.setattr(ce, "AES_ZIP_AVAILABLE", False)
    with ContainerExtractor().open(p) as res:
        assert "pip install pyzipper" in res.members[0].skipped_reason


# ------------------------------------------------------------------------ 7z
@needs_7z
def test_7z_members_are_extracted_and_classified(tmp_path):
    p = seven_zip(tmp_path / "docs.7z", {"docs/readme.txt": b"hello" * 100,
                                          "invoice.pdf.exe": _pe_bytes(1024)})
    with ContainerExtractor().open(p) as res:
        assert res.container_type == "7z"
        assert sorted(names(res)) == ["docs/readme.txt", "invoice.pdf.exe"]
        assert all(m.extracted for m in res.members)
        assert res.double_extension_members == ["docs.7z!/invoice.pdf.exe"]
        exe = next(m for m in res.members if m.name.endswith(".exe"))
        assert open(exe.path, "rb").read(2) == b"MZ"


@needs_7z
@pytest.mark.parametrize("header_encryption", [False, True])
def test_7z_password_from_delivery_list(tmp_path, header_encryption):
    p = seven_zip(tmp_path / "parcel.7z", {"a.docm": b"secret" * 20}, password="infected",
                  header_encryption=header_encryption)
    with ContainerExtractor().open(p) as res:
        assert res.password_used == "infected"
        assert names(res) == ["a.docm"] and res.members[0].extracted


@needs_7z
def test_7z_with_encrypted_names_and_unknown_password(tmp_path):
    p = seven_zip(tmp_path / "x.7z", {"a.docm": b"x"}, password="n0t-in-list",
                  header_encryption=True)
    with ContainerExtractor().open(p) as res:
        assert res.encrypted_unreadable
        assert names(res) == ["(encrypted file names)"]


@needs_7z
def test_7z_declared_size_bomb_is_refused(tmp_path):
    p = seven_zip(tmp_path / "big.7z", {"zeros.bin": b"\0" * 2_000_000})
    with ContainerExtractor(max_total_bytes=1_000_000).open(p) as res:
        assert res.zip_bomb and "Declared" in res.zip_bomb_reason
        assert res.total_uncompressed == 0


@needs_7z
def test_7z_inside_zip_is_expanded(tmp_path):
    inner = seven_zip(tmp_path / "inner.7z", {"payload.js": b"WScript.Shell"}).read_bytes()
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("inner.7z", inner)
    with ContainerExtractor().open(outer) as res:
        assert res.max_depth_reached == 2
        assert "outer.zip!/inner.7z!/payload.js" in res.executable_members


def test_missing_7z_library_is_reported(tmp_path, monkeypatch):
    p = tmp_path / "x.7z"
    p.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 64)
    monkeypatch.setattr(ce, "SEVENZIP_AVAILABLE", False)
    with ContainerExtractor().open(p) as res:
        assert res.unreadable_members == 1 and "pip install py7zr" in res.detail


# ----------------------------------------------------------------------- ISO
@needs_iso
@pytest.mark.parametrize("rock_ridge", [True, False])
def test_iso_members_use_readable_names(tmp_path, rock_ridge):
    p = iso_image(tmp_path / "Invoice.iso", {"invoice.pdf.lnk": b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 64,
                                             "docs/readme.txt": b"read me"},
                  rock_ridge=rock_ridge)
    with ContainerExtractor().open(p) as res:
        assert res.container_type == "iso"
        assert sorted(names(res)) == ["docs/readme.txt", "invoice.pdf.lnk"]
        assert "Invoice.iso!/invoice.pdf.lnk" in res.double_extension_members
        assert all(m.extracted for m in res.members)


@needs_iso
def test_iso_declared_size_limit(tmp_path):
    p = iso_image(tmp_path / "big.iso", {"a.bin": b"A" * 300_000, "b.bin": b"B" * 300_000})
    with ContainerExtractor(max_total_bytes=400_000).open(p) as res:
        assert res.zip_bomb and "Declared" in res.zip_bomb_reason


@needs_iso
def test_iso_limit_is_also_enforced_while_copying(tmp_path, monkeypatch):
    # Declared sizes can lie; skip the up-front check to exercise the copy-time one.
    p = iso_image(tmp_path / "big.iso", {"a.bin": b"A" * 300_000, "b.bin": b"B" * 300_000})
    monkeypatch.setattr(ContainerExtractor, "_limits_ok", lambda self, n, d, r: True)
    with ContainerExtractor(max_total_bytes=400_000).open(p) as res:
        assert res.zip_bomb and "Actual decompressed data" in res.zip_bomb_reason
        assert res.total_uncompressed <= 400_000
        assert sum(m.extracted for m in res.members) == 1


@needs_iso
def test_img_extension_only_when_it_is_really_iso(tmp_path):
    real = iso_image(tmp_path / "disk.img", {"a.txt": b"x"})
    fat = tmp_path / "fat.img"
    fat.write_bytes(b"\xeb\x3c\x90MSDOS5.0" + b"\0" * 40000)
    assert detect_container(real) == "iso" and detect_container(fat) is None


# ---------------------------------------------------------- through scan_file
@pytest.fixture
def scanner(tmp_path):
    return RS.RansomwareScanner(_config(tmp_path))


@needs_7z
def test_scanner_scores_a_7z_like_its_worst_member(scanner, tmp_path):
    p = seven_zip(tmp_path / "scan" / "parcel.7z", {"note.pdf": make_pdf("hello"),
                                                    "invoice.pdf": _pe_bytes(4096)},
                  password="infected")
    r = scanner.scan_file(str(p))
    assert "archive_member:disguised_executable" in _indicators(r)
    assert r["verdict"] in ("High", "Critical")
    arc = r["scan_results"]["archive"]
    assert arc["container_type"] == "7z" and arc["password_used"] == "infected"
    assert {m["name"].split("!/")[-1] for m in arc["member_results"]} == {"note.pdf",
                                                                       "invoice.pdf"}


@needs_iso
def test_scanner_flags_an_iso_delivering_a_shortcut(scanner, tmp_path):
    lnk = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 64
    p = iso_image(tmp_path / "scan" / "Invoice.iso", {"Invoice.pdf.lnk": lnk})
    r = scanner.scan_file(str(p))
    ind = _indicators(r)
    assert "archive_double_extension" in ind and "archive_executable" in ind
    assert r["verdict"] in ("High", "Critical")


@needs_aes
def test_scanner_reads_inside_an_aes_zip(scanner, tmp_path):
    p = aes_zip(tmp_path / "scan" / "bank.zip", {"statement.pdf": _pe_bytes(4096)})
    r = scanner.scan_file(str(p))
    assert "archive_member:disguised_executable" in _indicators(r)
    assert "archive_encrypted" not in _indicators(r)


def test_new_formats_are_default_scan_types():
    for ext in (".7z", ".iso", ".img"):
        assert ext in RS.SUPPORTED_EXTENSIONS
