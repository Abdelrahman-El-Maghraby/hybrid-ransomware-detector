"""4.4.0-beta.2: an encrypted archive whose password is written in the e-mail.

Gateways cannot open the archive; the victim types the password from the message.
The scanner now reads candidate passwords from the subject and body and tries
them first. Archives hold an inert MZ/PE header and a text file."""

import pytest

import detectors.container_extractor as ce
from detectors.container_extractor import ContainerExtractor
from detectors.mail_analyzer import archive_passwords
from detectors.scoring import ScoringMatrix
from tests.test_file_integrity import _pe_bytes
from tests.test_mail_analyzer import make_eml
from tests.test_scanner_integration import _indicators, scanner  # noqa: F401  (fixture)

needs_aes = pytest.mark.skipif(not ce.AES_ZIP_AVAILABLE, reason="pyzipper not installed")
needs_7z = pytest.mark.skipif(not ce.SEVENZIP_AVAILABLE, reason="py7zr not installed")

SECRET = "Qx77-Inv"        # not in the built-in delivery list


@pytest.mark.parametrize("text,expected", [
    ("Please find the invoice attached. Password: 4471.", "4471"),
    ("PW = Inv2024!", "Inv2024!"),
    ('The archive password is "Qx-77a".', "Qx-77a"),
    ("كلمة المرور: 9182", "9182"),
    ("Passwort: abc123", "abc123"),
    ("Mot de passe : zx9", "zx9"),
    ("Code: 5521", "5521"),
])
def test_password_candidates_are_read_from_text(text, expected):
    assert expected in archive_passwords(text)


def test_ordinary_text_gives_no_candidates_and_the_list_is_capped():
    assert archive_passwords("Attached is the file for you. Thanks!") == []
    many = " ".join(f"password: p{i}x{i}" for i in range(20))
    assert len(archive_passwords(many)) == 5


@needs_aes
def test_extractor_uses_extra_passwords_only_inside_the_block(tmp_path):
    from tests.test_archive_formats import aes_zip
    z = aes_zip(tmp_path / "invoice.zip", {"invoice.txt": b"hello " * 50}, password=SECRET)
    ex = ContainerExtractor()
    with ex.open(z) as res:
        assert res.password_used is None and res.members[0].skipped_reason
    with ex.extra_passwords([SECRET]):
        with ex.open(z) as res:
            assert res.password_used == SECRET and not res.members[0].skipped_reason
    with ex.open(z) as res:                                   # gone again afterwards
        assert res.password_used is None


def _mail_with_archive(tmp_path, data, name="invoice.zip", body=f"Password: {SECRET}"):
    p = tmp_path / "scan" / "invoice.eml"
    p.parent.mkdir(exist_ok=True)
    make_eml(p, subject="Overdue invoice", body=f"Hello,\nthe invoice is attached.\n{body}\n",
             attachments=[(name, data, "application", "zip")])
    return p


@needs_aes
def test_scanner_opens_the_archive_with_the_password_from_the_body(scanner, tmp_path):
    from tests.test_archive_formats import aes_zip
    z = aes_zip(tmp_path / "a.zip", {"Invoice.pdf.exe": _pe_bytes(4096)}, password=SECRET)
    r = scanner.scan_file(str(_mail_with_archive(tmp_path, z.read_bytes())))
    ind = _indicators(r)
    assert "mail_archive_password_in_body" in ind
    assert any(i.startswith("mail_attachment:") and "double_extension" in i for i in ind)
    assert r["verdict"] == "Critical"
    assert r["scan_results"]["mail"]["archive_passwords"] == [SECRET]


@needs_aes
def test_without_the_password_in_the_body_the_archive_stays_closed(scanner, tmp_path):
    from tests.test_archive_formats import aes_zip
    z = aes_zip(tmp_path / "a.zip", {"Invoice.pdf.exe": _pe_bytes(4096)}, password=SECRET)
    r = scanner.scan_file(str(_mail_with_archive(tmp_path, z.read_bytes(), body="Regards")))
    assert "mail_archive_password_in_body" not in _indicators(r)
    arc = r["scan_results"]["mail"]["attachment_results"][0]
    assert arc.get("archive_password") is None


@needs_7z
def test_works_for_7z_with_encrypted_names(scanner, tmp_path):
    from tests.test_archive_formats import seven_zip
    z = seven_zip(tmp_path / "a.7z", {"run.js": b"var x = 1;"}, password=SECRET,
                  header_encryption=True)
    r = scanner.scan_file(str(_mail_with_archive(tmp_path, z.read_bytes(), name="docs.7z")))
    assert "mail_archive_password_in_body" in _indicators(r)


def test_scoring_rule():
    s = ScoringMatrix().score({"mail": {"archive_password_in_body": ["m.eml!/invoice.zip"]}})
    assert [c.indicator for c in s.contributions] == ["mail_archive_password_in_body"]
    assert s.risk_score == 30 and s.verdict == "Medium"
