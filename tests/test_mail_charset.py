"""M33: a mail part that declares charset=idna or charset=undefined made
bytes.decode raise UnicodeError even with errors="replace", so the whole mail
analysis stopped: the body, the archive password written in it and every later
part went unread. Those parts are now read as UTF-8, like an unknown charset.
Every other charset decodes exactly as before."""

from email.message import Message

import pytest

from detectors.mail_analyzer import MailAnalyzer, _decode_text

RAW = (b"From: billing@vendor.example\r\nTo: user@corp.example\r\nSubject: Statement\r\n"
       b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=%s\r\n\r\n"
       b"Your statement is attached. Password: Zx9-Qr41\r\n")


def _part(charset, payload):
    part = Message()
    part["Content-Type"] = f"text/plain; charset={charset}"
    part.set_payload(payload)
    return part


@pytest.mark.parametrize("charset", [b"idna", b"undefined", b"IDNA"])
def test_a_charset_that_rejects_replace_does_not_stop_the_analysis(tmp_path, charset):
    eml = tmp_path / "m.eml"
    eml.write_bytes(RAW % charset)
    res = MailAnalyzer().analyze(eml)
    assert res.error == ""
    assert "Your statement is attached" in res.body_text
    assert res.archive_passwords == ["Zx9-Qr41"]


@pytest.mark.parametrize("charset", ["idna", "undefined"])
def test_the_fallback_reads_utf8(charset):
    assert _decode_text(_part(charset, "caf\xc3\xa9 \xff")) == "caf\xe9 �"


@pytest.mark.parametrize("charset, payload", [
    ("utf-8", b"caf\xc3\xa9 \xff"), ("latin-1", b"caf\xe9"), ("cp1252", b"\x80 \x81"),
    ("shift_jis", b"\x82\xa0\xff"), ("utf-16", b"\xff\xfea\x00\x00"), ("koi8-r", b"\xc1\xc2"),
])
def test_valid_charsets_decode_as_before(charset, payload):
    part = _part(charset, payload.decode("latin-1"))
    assert _decode_text(part) == payload.decode(charset, errors="replace")


@pytest.mark.parametrize("charset", ["no-such-charset", "punycode"])
def test_unknown_and_punycode_charsets_still_read_utf8(charset):
    assert _decode_text(_part(charset, "caf\xc3\xa9")) == "caf\xe9"
