"""v4.3: OLE objects attached to Outlook items are unpacked and scanned instead
of only being counted."""

import email
import email.policy
from pathlib import Path

import pytest

import RansomwareScanner as RS
from detectors.mail_analyzer import MSG_AVAILABLE, MailAnalyzer, parse_ole10native
from tests.helpers import make_pdf
from tests.msg_builder import Ole, build_msg, compobj, msg_tree, ole10native
from tests.test_file_integrity import _pe_bytes
from tests.test_scanner_integration import _config, _indicators

pytestmark = pytest.mark.skipif(not MSG_AVAILABLE, reason="olefile not installed")

PACKAGE = {"\x01Ole10Native": ole10native("invoice.pdf", _pe_bytes(2048),
                                           temp_path="C:\\Temp\\invoice.pdf.exe"),
           "\x01CompObj": compobj("OLE Package", "Package")}


def mail_with(tmp_path, *attachments):
    return build_msg(tmp_path / "m.msg", subject="Invoice", sender_name="A",
                     sender_email="a@x.example", body="see attached",
                     attachments=attachments)


def attachments(path):
    with MailAnalyzer().open(path) as res:
        return res.attachments_skipped, [(a.filename, a.executable, a.double_extension,
                                          Path(a.path).read_bytes()) for a in res.attachments]


@pytest.mark.parametrize("method", [True, False])
def test_packager_object_unpacked_under_its_real_name(tmp_path, method):
    skipped, found = attachments(mail_with(tmp_path, ("invoice.pdf", Ole(PACKAGE, method))))
    assert skipped == 0
    (name, executable, double, data), = found
    # The icon says invoice.pdf; what runs on double-click is invoice.pdf.exe.
    assert (name, executable, double) == ("invoice.pdf.exe", True, True)
    assert data == _pe_bytes(2048)


def test_embedded_ooxml_and_pdf_objects(tmp_path):
    docm = {"Package": b"PK\x03\x04 fake docm",
            "\x01CompObj": compobj("Microsoft Word Document", "Word.DocumentMacroEnabled.12")}
    pdf = {"CONTENTS": make_pdf("embedded"), "\x01CompObj": compobj("Acrobat", "AcroExch.Document.DC")}
    skipped, found = attachments(mail_with(tmp_path, ("Report", Ole(docm)), ("Scan", Ole(pdf))))
    assert skipped == 0
    assert [f[0] for f in found] == ["Report.docm", "Scan.pdf"]
    assert found[0][3] == b"PK\x03\x04 fake docm" and found[1][3].startswith(b"%PDF-")


def test_legacy_document_storage_is_repacked_as_a_compound_file(tmp_path):
    import olefile
    word = {"WordDocument": b"\xec\xa5" + b"w" * 5000, "1Table": b"t" * 300,
            "Macros": {"VBA": {"ThisDocument": b"Attribute VB_Name" * 10, "dir": b"d" * 40},
                       "PROJECT": b"ID=\"{...}\""},
            "\x01CompObj": compobj("Microsoft Word 97-2003 Document", "Word.Document.8")}
    skipped, found = attachments(mail_with(tmp_path, ("Contract.doc", Ole(word))))
    (name, _, _, data), = found
    assert name == "Contract.doc" and skipped == 0
    copy = tmp_path / "copy.doc"
    copy.write_bytes(data)
    with olefile.OleFileIO(str(copy)) as ole:
        assert ole.openstream("WordDocument").read() == word["WordDocument"]
        assert ole.openstream("Macros/VBA/ThisDocument").read() == word["Macros"]["VBA"]["ThisDocument"]


def test_unrecognised_object_is_counted_not_dropped(tmp_path):
    equation = {"\x01CompObj": compobj("Equation", "Equation.3"), "Equation Native": b"\x1c" * 40}
    skipped, found = attachments(mail_with(tmp_path, ("eq", Ole(equation))))
    assert (skipped, found) == (1, [])


def test_embedded_message_with_method_is_still_a_message(tmp_path):
    inner = msg_tree(subject="Inner", body="hi", attachments=(("a.txt", b"a"),))
    skipped, found = attachments(mail_with(tmp_path, ("Inner", inner)))
    assert [f[0] for f in found] == ["Inner.eml"] and skipped == 0


def test_object_inside_a_forwarded_item(tmp_path):
    inner = msg_tree(subject="Your invoice", body="open it",
                     attachments=(("invoice.pdf", Ole(PACKAGE)),))
    p = mail_with(tmp_path, ("Your invoice", inner))
    with MailAnalyzer().open(p) as res:
        rebuilt = Path(res.attachments[0].path).read_bytes()
    msg = email.message_from_bytes(rebuilt, policy=email.policy.compat32)
    files = [part.get_filename() for part in msg.walk() if part.get_filename()]
    assert files == ["invoice.pdf.exe"]


def test_ole10native_parser(tmp_path):
    raw = ole10native("doc.pdf", b"x" * 10, src_path="D:\\src\\doc.pdf.js",
                      temp_path="C:\\Temp\\doc.pdf.js")
    assert parse_ole10native(raw) == ("doc.pdf", "doc.pdf.js", b"x" * 10)
    assert parse_ole10native(raw[:-3]) is None                       # truncated data
    assert parse_ole10native(b"\x00" * 7) is None
    oleobj = pytest.importorskip("oletools.oleobj")
    native = oleobj.OleNativeStream(raw)
    assert (native.filename, native.data) == ("doc.pdf", b"x" * 10)


def test_scanner_flags_the_packaged_executable(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path))
    r = s.scan_file(str(mail_with(tmp_path, ("invoice.pdf", Ole(PACKAGE)))))
    ind = _indicators(r)
    assert "mail_double_extension" in ind and "mail_attachment:disguised_executable" not in ind
    assert r["verdict"] in ("High", "Critical")
    assert r["scan_results"]["mail"]["attachments_skipped"] == 0
