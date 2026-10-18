"""Build macOS installer packages (.pkg) and disk images (.dmg) at test time.

Neither format can be produced on Linux/Windows without Apple's tools, so the
tests write them directly:

* a flat package is a XAR archive (header, zlib table of contents, heap) whose
  component holds `Scripts` and `Payload` as gzip'd "odc" cpio archives, the
  layout `pkgbuild` produces;
* a disk image is UDIF: the partition data, an XML property list with one
  `blkx` table describing it as raw sectors, and the 512-byte `koly` trailer.
  The partition inside is an ISO 9660 file system (built with pycdlib), which
  7-Zip opens the same way it opens HFS+ or APFS.
"""

from __future__ import annotations

import base64
import io
import struct
import zlib
from pathlib import Path
from typing import Iterable, Optional, Tuple

from detectors.macos_packages import gzip_bytes

Member = Tuple[str, bytes, int]          # name, data, mode


def cpio_odc(members: Iterable[Member]) -> bytes:
    out = bytearray()
    ino = 1
    for name, data, mode in list(members) + [("TRAILER!!!", b"", 0)]:
        raw = name.encode() + b"\x00"
        out += (b"070707" + b"%06o" % 0 + b"%06o" % ino + b"%06o" % mode + b"%06o" % 0
                + b"%06o" % 0 + b"%06o" % 1 + b"%06o" % 0 + b"%011o" % 0
                + b"%06o" % len(raw) + b"%011o" % len(data)) + raw + data
        ino += 1
    return bytes(out)


def build_pkg(path: Path, scripts: Iterable[Member] = (), payload: Iterable[Member] = (),
              component: str = "app.pkg", extra: Iterable[Tuple[str, bytes]] = (),
              payload_bytes: Optional[bytes] = None) -> Path:
    """A product archive: Distribution + one component with Scripts and Payload."""
    heap = bytearray()
    entries = []

    def add(name: str, data: bytes, compress: bool = True) -> None:
        stored = zlib.compress(data) if compress else data
        entries.append((name, len(heap), len(stored), len(data),
                        "application/x-gzip" if compress else "application/octet-stream"))
        heap.extend(stored)

    add("Distribution", b'<?xml version="1.0"?><installer-gui-script minSpecVersion="1"/>')
    for name, data in extra:
        add(name, data)
    scripts = list(scripts)
    if scripts:
        add(f"{component}/Scripts", gzip_bytes(cpio_odc(scripts)), compress=False)
    payload = list(payload)
    if payload or payload_bytes is not None:
        add(f"{component}/Payload",
            payload_bytes if payload_bytes is not None else gzip_bytes(cpio_odc(payload)),
            compress=False)
    add(f"{component}/PackageInfo", b'<pkg-info identifier="com.example.app" version="1"/>')

    def file_xml(name, off, length, size, enc, fid):
        return (f'<file id="{fid}"><name>{name}</name><type>file</type><data>'
                f'<offset>{off}</offset><length>{length}</length><size>{size}</size>'
                f'<encoding style="{enc}"/></data></file>')

    top, comp = [], []
    for fid, (name, off, length, size, enc) in enumerate(entries, start=2):
        if "/" in name:
            comp.append(file_xml(name.split("/", 1)[1], off, length, size, enc, fid))
        else:
            top.append(file_xml(name, off, length, size, enc, fid))
    toc = ('<?xml version="1.0" encoding="UTF-8"?><xar><toc>' + "".join(top)
           + f'<file id="1"><name>{component}</name><type>directory</type>'
           + "".join(comp) + "</file></toc></xar>").encode()
    ztoc = zlib.compress(toc)
    header = b"xar!" + struct.pack(">HHQQI", 28, 1, len(ztoc), len(toc), 0)
    path.write_bytes(header + ztoc + bytes(heap))
    return path


def iso_image(files: Iterable[Tuple[str, bytes]]) -> bytes:
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(joliet=3, rock_ridge="1.09")
    for i, (name, data) in enumerate(files):
        iso.add_fp(io.BytesIO(data), len(data), f"/F{i}.;1",
                   joliet_path=f"/{name}", rr_name=name)
    buf = io.BytesIO()
    iso.write_fp(buf)
    iso.close()
    return buf.getvalue()


def build_dmg(path: Path, files: Iterable[Tuple[str, bytes]] = (),
              partition: Optional[bytes] = None) -> Path:
    """UDIF image whose single partition is `partition` (default: an ISO of `files`)."""
    data = partition if partition is not None else iso_image(files)
    data += b"\x00" * (-len(data) % 512)
    sectors = len(data) // 512
    chunks = struct.pack(">IIQQQQ", 1, 0, 0, sectors, 0, len(data))          # raw
    chunks += struct.pack(">IIQQQQ", 0xFFFFFFFF, 0, sectors, 0, len(data), 0)  # end
    mish = (b"mish" + struct.pack(">IQQQII", 1, 0, sectors, 0, 0, 0) + b"\x00" * 24
            + struct.pack(">II", 0, 0) + b"\x00" * 128 + struct.pack(">I", 2) + chunks)
    plist = (b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC '
             b'"-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
             b'<plist version="1.0"><dict><key>resource-fork</key><dict><key>blkx</key><array>'
             b'<dict><key>Attributes</key><string>0x0050</string><key>CFName</key>'
             b'<string>disk image (Apple_HFS : 0)</string><key>Data</key><data>'
             + base64.b64encode(mish) + b'</data><key>ID</key><string>0</string>'
             b'<key>Name</key><string>disk image (Apple_HFS : 0)</string></dict>'
             b'</array></dict></dict></plist>\n')
    koly = bytearray(512)
    struct.pack_into(">4sIII", koly, 0, b"koly", 4, 512, 1)
    struct.pack_into(">QQQ", koly, 16, 0, 0, len(data))          # running/data fork offset, len
    struct.pack_into(">II", koly, 56, 1, 1)                      # segment 1 of 1
    struct.pack_into(">QQ", koly, 216, len(data), len(plist))   # XML offset, length
    struct.pack_into(">IQ", koly, 488, 1, sectors)               # variant, sector count
    path.write_bytes(data + plist + bytes(koly))
    return path


def build_encrypted_dmg(path: Path) -> Path:
    path.write_bytes(b"encrcdsa" + b"\x00" * 4096)
    return path
