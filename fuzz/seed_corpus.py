#!/usr/bin/env python3
"""Generate benign seed bytes in a scratch directory, never download samples."""

import argparse
import io
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.macos_builder import build_dmg, build_pkg, cpio_odc
from tests.test_fuzz_parsers import SEEDS


def generate(group, destination):
    destination.mkdir(parents=True, exist_ok=True)
    seeds = dict(SEEDS)
    seeds["bin"] = bytes(range(256)) * 8
    # Benign OLE container, for structural macro parsing (no VBA payload).
    seeds["ole"] = seeds["msg"]
    with tempfile.TemporaryDirectory(prefix="aegis_fuzz_seeds_") as tmp:
        root = Path(tmp)
        tar = io.BytesIO()
        with tarfile.open(fileobj=tar, mode="w") as archive:
            info = tarfile.TarInfo("readme.txt")
            info.size = 5
            archive.addfile(info, io.BytesIO(b"hello"))
        seeds["dmg"] = build_dmg(root / "safe.dmg", partition=tar.getvalue()).read_bytes()
        seeds["pkg"] = build_pkg(root / "safe.pkg", payload=[
            ("./readme.txt", b"hello", 0o100644)]).read_bytes()
    kinds = (["zip", "docx", "docx", "pdf", "eml", "msg", "html", "js",
              "elf", "one", "bin", "dmg", "pkg"] if group == "parsers" else
             ["docx", "pdf", "docx", "ole", "ole", "docx", "pdf", "docx",
              "rtf", "bin", "bin", "bin"])
    for index, kind in enumerate(kinds):
        data = seeds[kind]
        for variant, content in [("valid", data), ("truncated", data[:32]),
                                 ("empty", b"\x00"), ("tail", data + b"\xff" * 16)]:
            (destination / f"{index:02d}-{kind}-{variant}").write_bytes(bytes([index]) + content)
    if group == "parsers":
        (destination / "255-cpio").write_bytes(
            b"\xff" + cpio_odc([("readme.txt", b"hello", 0o100644)]))
    print(f"Generated {len(list(destination.iterdir()))} seeds for {group}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=["parsers", "b4"])
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    generate(args.group, args.destination)
