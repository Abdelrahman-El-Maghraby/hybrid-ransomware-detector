"""M20: archive members, embedded blocks and mail attachments are never written
to the sandbox under a Windows device name. On Windows, writing "m0001/NUL.exe"
opens the NUL device instead of a file, so the member would never be examined
and the scan would still read complete. The sanitised name keeps its extension
behind a "_" prefix; the name shown in results is unchanged.

The device behaviour itself needs a Windows runner (PLATFORM); this test checks
the names on every platform."""

import os

import pytest

from detectors import embedded_content as ec
from detectors.container_extractor import ContainerExtractor, not_a_device
from detectors.embedded_content import EmbeddedContentAnalyzer
from detectors.mail_analyzer import MailAnalyzer
from tests.test_container_extractor import _zip
from tests.test_mail_analyzer import make_eml

DEVICES = ["NUL.exe", "con.txt", "AUX", "COM1.pdf", "lpt9", "nul .txt", "Prn.tar.gz",
           "COM\u00b9.js"]
ORDINARY = ["nullsoft.exe", "console.txt", "com10.txt", "CONTRACT.pdf", "prn_", "aux-1", "_NUL"]


@pytest.mark.parametrize("name", DEVICES)
def test_device_names_get_a_prefix(name):
    assert not_a_device(name) == "_" + name


@pytest.mark.parametrize("name", ORDINARY)
def test_other_names_are_unchanged(name):
    assert not_a_device(name) == name


def test_archive_member_named_like_a_device_is_written_as_a_file(tmp_path):
    arc = _zip(tmp_path / "a.zip", [("NUL.exe", b"MZ" + b"\0" * 100), ("aux.txt", b"text")])
    with ContainerExtractor().open(arc) as res:
        assert [os.path.basename(m.path) for m in res.members] == ["_NUL.exe", "_aux.txt"]
        assert all(m.extracted for m in res.members)
        assert res.executable_members == ["a.zip!/NUL.exe"]       # shown name unchanged


def test_embedded_block_named_like_a_device_is_written_as_a_file(tmp_path):
    res = ec.EmbeddedResult()
    EmbeddedContentAnalyzer()._add(res, tmp_path, True, "con.exe", b"MZ payload")
    [member] = res.members
    assert member.name == "con.exe" and os.path.basename(member.path) == "_con.exe"


def test_mail_attachment_named_like_a_device_is_written_as_a_file(tmp_path):
    eml = make_eml(tmp_path / "m.eml",
                   attachments=[("AUX.pdf.exe", b"MZ" + b"\0" * 64, "application", "octet-stream")])
    with MailAnalyzer().open(eml) as res:
        [att] = res.attachments
        assert os.path.basename(att.path) == "_AUX.pdf.exe"
        assert att.filename == "AUX.pdf.exe" and att.executable and att.double_extension
