"""B4: an OLE stream is never read past the size of its file (detectors/ole_limits)."""

import struct

import pytest

olefile = pytest.importorskip("olefile")

import detectors  # noqa: E402,F401  (installs the bound)
from detectors.cfb_writer import write_cfb  # noqa: E402
from detectors.macro_analysis import OLEVBA_AVAILABLE, MacroAnalyzer  # noqa: E402

CONTENT = bytes(range(256)) * 20                   # 5,120 bytes: a regular-FAT stream


def _with_declared_size(size: int, loop: bool, name: str = "Data") -> bytes:
    """A one-stream compound file whose stream claims `size` bytes; with `loop`
    its FAT chain points its first sector back at itself."""
    data = bytearray(write_cfb({name: CONTENT}))
    sector = 1 << struct.unpack_from("<H", data, 30)[0]
    dir_start = struct.unpack_from("<I", data, 48)[0]
    fat_start = struct.unpack_from("<I", data, 76)[0]
    with olefile.OleFileIO(bytes(data)) as ole:
        sid = ole._find([name])
        start = ole.direntries[sid].isectStart
    struct.pack_into("<I", data, 512 + dir_start * sector + sid * 128 + 120, size)
    if loop:
        struct.pack_into("<I", data, 512 + fat_start * sector + 4 * start, start)
    return bytes(data)


def test_a_looping_stream_is_read_only_up_to_the_file_size():
    # Before: olefile followed the loop for the full declared 4 MiB (2.3x that at peak).
    data = _with_declared_size(4 * 1024 * 1024, loop=True)
    with olefile.OleFileIO(data) as ole:
        assert len(ole.openstream("Data").read()) <= len(data)


def test_an_inflated_size_keeps_the_real_content():
    data = _with_declared_size(4 * 1024 * 1024, loop=False)
    with olefile.OleFileIO(data) as ole:
        assert ole.openstream("Data").read() == CONTENT


def test_ordinary_streams_are_unchanged():
    with olefile.OleFileIO(write_cfb({"Data": CONTENT, "Small": b"x" * 100})) as ole:
        assert ole.openstream("Data").read() == CONTENT
        assert ole.openstream("Small").read() == b"x" * 100


@pytest.mark.skipif(not OLEVBA_AVAILABLE, reason="oletools not installed")
def test_macro_analysis_reads_a_looping_stream_within_the_file_size(tmp_path, monkeypatch):
    sizes = []
    original = olefile.OleFileIO._open

    def spy(self, start, size=None, *args, **kwargs):
        stream = original(self, start, size, *args, **kwargs)
        sizes.append(stream.size)
        return stream

    monkeypatch.setattr(olefile.OleFileIO, "_open", spy)
    path = tmp_path / "f.doc"
    path.write_bytes(_with_declared_size(4 * 1024 * 1024, loop=True))
    result = MacroAnalyzer().analyze_file(str(path))
    assert result.error == "" and not result.has_macros
    assert sizes and max(sizes) <= path.stat().st_size
