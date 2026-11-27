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

try:
    import olefile
except ImportError:  # pragma: no cover - optional dependency
    olefile = None


def _bounded_open(original):
    def _open(self, start, size=None, *args, **kwargs):
        if size is None:
            return original(self, start, *args, **kwargs)
        filesize = getattr(self, "_filesize", None)
        # An explicit size is declared by the file (0x7FFFFFFF included: olefile
        # would then read the whole FAT); only olefile's own directory read omits it.
        if filesize is not None and size > filesize:
            size = filesize
        return original(self, start, size, *args, **kwargs)
    _open.aegis_bounded = True                  # type: ignore[attr-defined]
    return _open


if olefile is not None and not getattr(olefile.OleFileIO._open, "aegis_bounded", False):
    olefile.OleFileIO._open = _bounded_open(olefile.OleFileIO._open)
