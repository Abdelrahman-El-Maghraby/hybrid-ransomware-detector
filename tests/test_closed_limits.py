"""4.4.1: limits from the README that are now closed - Equation Editor objects,
hidden sheets in legacy .xls workbooks, more recognised encrypted containers."""

import struct

import pytest

from detectors import YARA_AVAILABLE
from detectors.cfb_writer import write_cfb
from detectors.file_integrity import encrypted_container_format, trusted_vault
from detectors.prompt_guard import PromptGuard, _xls_sheet_states
from detectors.yara_engine import YaraEngine

EQ_CLSID = bytes.fromhex("02ce020000000000c000000000000046")


def _rules(path):
    return {m.rule for m in YaraEngine("rules").scan_file(str(path)).matches}


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_equation_editor_object_in_rtf(tmp_path):
    named = tmp_path / "invoice.rtf"
    named.write_text("{\\rtf1{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata 0105}}}")
    hexed = tmp_path / "order.rtf"                  # class name only inside the hex blob
    hexed.write_text("{\\rt{\\object{\\*\\objdata 01050000020000000b000000"
                     + "4571756174696f6e2e33" + "00}}}")
    plain = tmp_path / "letter.rtf"
    plain.write_text("{\\rtf1 The equation 3 is in chapter 3.}")
    assert "Equation_Editor_Object_In_RTF" in _rules(named)
    assert "Equation_Editor_Object_In_RTF" in _rules(hexed)
    assert not _rules(plain)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_equation_editor_object_in_ole_document(tmp_path):
    doc = tmp_path / "old.doc"
    doc.write_bytes(write_cfb({"WordDocument": b"\0" * 600,
                               "ObjectPool": {"_1": {"\x01CompObj": b"\0" * 12 + EQ_CLSID
                                                     + b"Microsoft Equation 3.0\0"}}}))
    assert "Equation_Editor_Object_In_Office_Binary" in _rules(doc)


def _biff_record(rtype, body):
    return struct.pack("<HH", rtype, len(body)) + body


def _boundsheet(name, state):
    raw = name.encode("latin-1")
    return _biff_record(0x0085, struct.pack("<IBBBB", 0, state, 0, len(raw), 0) + raw)


def _xls(path, sheets):
    stream = (_biff_record(0x0809, b"\0" * 16)
              + b"".join(_boundsheet(n, s) for n, s in sheets)
              + _biff_record(0x000A, b""))
    path.write_bytes(write_cfb({"Workbook": stream + b"\0" * 4096}))
    return path


def test_hidden_and_very_hidden_sheets_in_xls(tmp_path):
    book = _xls(tmp_path / "budget.xls", [("Sheet1", 0), ("Data", 1), ("Macro1", 2)])
    assert _xls_sheet_states(book) == [("Sheet1", 0), ("Data", 1), ("Macro1", 2)]
    res = PromptGuard().inspect_hidden_content(book)
    assert res.found and res.reasons == ["hidden_sheet", "very_hidden_sheet"]
    assert "[Macro1]" in res.snippets


def test_visible_xls_and_non_ole_file_are_clean(tmp_path):
    assert not PromptGuard().inspect_hidden_content(_xls(tmp_path / "ok.xls", [("A", 0)])).found
    junk = tmp_path / "fake.xls"
    junk.write_bytes(b"not an ole file at all")
    assert _xls_sheet_states(junk) == []


@pytest.mark.parametrize("head, ext, kind", [
    (b"LUKS\xba\xbe\x00\x02" + b"\0" * 56, ".luks", "luks"),
    (b"Salted__" + b"\x11" * 56, ".enc", "openssl"),
])
def test_more_encrypted_containers_are_recognised(head, ext, kind):
    assert encrypted_container_format(head) == kind
    assert trusted_vault(head, ext) == kind
    assert trusted_vault(head, ".docx") == ""          # the extension has to agree
