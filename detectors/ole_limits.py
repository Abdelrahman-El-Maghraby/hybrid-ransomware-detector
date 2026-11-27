"""Never read an OLE stream past the size of the file that holds it (B4).

olefile reads a stream by following its FAT chain for size / sector_size
sectors. When the declared size is larger than the FAT it only logs a defect,
and a chain that loops back re-reads the same sector, so a 7 KB file whose
stream claims 4 GiB made olefile allocate about 2.3 times that (olevba reads
every stream of every OLE file it sees; the .msg reader reads its property
streams). A stream stores each of its sectors once inside the file, so its real
content never exceeds the file size: capping the read there keeps every byte
the file holds, and a valid chain still stops at its end marker as before.
"""

from __future__ import annotations

import inspect

try:
    import olefile
except ImportError:  # pragma: no cover - optional dependency
    olefile = None


def _bounded_open(original):
    def _open(self, start, size=None, force_FAT=False):
        if size is None:
            return original(self, start, force_FAT=force_FAT)
        filesize = getattr(self, "_filesize", None)
        # UNKNOWN_SIZE (0x7FFFFFFF, also when a file declares it) makes olefile read
        # len(fat) sectors, and olefile already cuts the FAT to the file: left as is
        if filesize is not None and filesize < size != olefile.olefile.UNKNOWN_SIZE:
            # the declared size picked the table: a stream at or over the cutoff is
            # in the FAT even when the file is smaller than the cutoff
            force_FAT = force_FAT or size >= self.minisectorcutoff
            size = filesize
        return original(self, start, size, force_FAT)
    _open.aegis_bounded = True                  # type: ignore[attr-defined]
    _open.aegis_original = original             # type: ignore[attr-defined]
    return _open


def _expected_signature(method) -> bool:
    """The wrapper copies olefile 0.47's _open(start, size, force_FAT); another
    signature is left alone (and the tests that require the bound fail)."""
    try:
        return list(inspect.signature(method).parameters) == ["self", "start", "size", "force_FAT"]
    except (TypeError, ValueError):
        return False


if (olefile is not None and not getattr(olefile.OleFileIO._open, "aegis_bounded", False)
        and _expected_signature(olefile.OleFileIO._open)):
    olefile.OleFileIO._open = _bounded_open(olefile.OleFileIO._open)
