"""L-D1 (XAR table of contents) and L-E4 (Word text): sizes and offsets that a
file declares are checked before they are used. Small synthetic files only:
the out-of-range lengths here exceed the file by 10 MB, never more, so even a
regression could not ask for a large allocation."""

import struct
import zlib

import pytest

import RansomwareScanner as RS
from detectors import macos_packages as mp
from tests.helpers import make_docx
from tests.test_scanner_integration import _config


def _xar(path, files):
    """A XAR archive whose table of contents lists `files` as (name, offset,
    length) strings, over a 16-byte heap."""
    toc = ('<?xml version="1.0" encoding="UTF-8"?><xar><toc>' + "".join(
        f"<file><name>{n}</name><type>file</type><data><offset>{o}</offset>"
        f"<length>{n_}</length><size>{n_}</size><encoding style=\"application/octet-stream\"/>"
        f"</data></file>" for n, o, n_ in files) + "</toc></xar>").encode()
    ztoc = zlib.compress(toc)
    path.write_bytes(b"xar!" + struct.pack(">HHQQI", 28, 1, len(ztoc), len(toc), 0) + ztoc
                     + b"0123456789abcdef")
    return path


@pytest.fixture
def reads(monkeypatch):
    sizes = []
    real = open

    def spy(*a, **k):
        fh = real(*a, **k)
        orig = fh.read

        def read(n=-1):
            sizes.append(n)
            return orig(n)
        fh.read = read
        return fh
    monkeypatch.setattr(mp, "open", spy, raising=False)
    return sizes


def test_an_entry_outside_the_file_is_refused_before_it_is_read(tmp_path, reads):
    if mp._DET is None:
        pytest.skip("defusedxml not installed")
    size = 10 * 1024 * 1024
    p = _xar(tmp_path / "a.pkg", [("ok.txt", "0", "4"), ("far.bin", "8", str(size))])
    entries, heap = mp.read_xar(p)
    ok, far = entries
    assert mp.xar_read_entry(p, heap, ok, 1 << 20) == b"0123"
    reads.clear()
    with pytest.raises(mp.FormatError, match="outside the file"):
        mp.xar_read_entry(p, heap, far, 1 << 30)
    assert reads == []                                    # nothing was read for it


@pytest.mark.parametrize("bad", ["abc", "-5", "1e9", " "])
def test_a_table_of_contents_number_that_is_not_a_size_is_a_format_error(tmp_path, bad):
    if mp._DET is None:
        pytest.skip("defusedxml not installed")
    p = _xar(tmp_path / "b.pkg", [("x.txt", bad, "4")])
    if bad.strip() == "":
        entries, _ = mp.read_xar(p)                       # empty reads as 0, as before
        assert entries[0].offset == 0
        return
    with pytest.raises(mp.FormatError, match="not a size or offset"):
        mp.read_xar(p)


@pytest.fixture
def scanner(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    yield s
    if s.cache is not None:
        s.cache.close()


def test_word_text_is_capped(scanner, tmp_path, monkeypatch):
    doc = make_docx(tmp_path / "long.docx", paragraphs=["x" * 50, "y" * 50])
    monkeypatch.setattr(type(scanner), "OOXML_MAX_CHARS", 30)
    assert len(scanner._extract_text_from_word(str(doc))) == 30


def test_an_oversized_word_part_is_not_given_to_python_docx(scanner, tmp_path, monkeypatch):
    import docx
    doc = make_docx(tmp_path / "big.docx", paragraphs=["hello world"])
    monkeypatch.setattr(type(scanner), "OOXML_PART_MAX", 10)

    def never(*a, **k):
        raise AssertionError("python-docx read an oversized part")
    monkeypatch.setattr(docx, "Document", never)
    assert scanner._extract_text_from_word(str(doc)) == ""


def test_a_normal_word_document_reads_as_before(scanner, tmp_path):
    doc = make_docx(tmp_path / "letter.docx", paragraphs=["Dear team,", "the report is attached."])
    assert scanner._extract_text_from_word(str(doc)) == "Dear team,\nthe report is attached."
