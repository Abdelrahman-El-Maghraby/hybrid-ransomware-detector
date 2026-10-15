#!/usr/bin/env python3
"""
detectors/container_extractor.py — Sandboxed recursive archive unpacker (.zip, .7z,
.rar, .iso) with Zip-Bomb, Zip-Slip, symlink refusal, and password recovery.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from config import ARCHIVE_BASE_PASSWORDS, IO_CHUNK_SIZE, ZIP_BOMB_MAX_DEPTH, ZIP_BOMB_MAX_FILES, ZIP_BOMB_MAX_TOTAL_BYTES

logger = logging.getLogger("AegisSentinel.containers")

try:
    import py7zr  # type: ignore
    PY7ZR_AVAILABLE = True
except ImportError:  # pragma: no cover
    py7zr = None
    PY7ZR_AVAILABLE = False

try:
    import rarfile  # type: ignore
    RARFILE_AVAILABLE = True
except ImportError:  # pragma: no cover
    rarfile = None
    RARFILE_AVAILABLE = False

try:
    import pycdlib  # type: ignore
    PYCDLIB_AVAILABLE = True
except ImportError:  # pragma: no cover
    pycdlib = None
    PYCDLIB_AVAILABLE = False


@dataclass
class ContainerExtractionResult:
    is_container: bool = True
    container_type: str = ""
    extracted_files: List[str] = field(default_factory=list)
    total_extracted_bytes: int = 0
    max_depth_reached: int = 0
    zip_bomb_detected: bool = False
    zip_bomb_reason: str = ""
    zip_slip_detected: bool = False
    zip_slip_reason: str = ""
    password_protected: bool = False
    cracked_password: Optional[str] = None
    encrypted_unreadable: bool = False
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "is_container": self.is_container,
            "container_type": self.container_type,
            "extracted_files_count": len(self.extracted_files),
            "total_extracted_bytes": self.total_extracted_bytes,
            "max_depth_reached": self.max_depth_reached,
            "zip_bomb_detected": self.zip_bomb_detected,
            "zip_bomb_reason": self.zip_bomb_reason,
            "zip_slip_detected": self.zip_slip_detected,
            "zip_slip_reason": self.zip_slip_reason,
            "password_protected": self.password_protected,
            "cracked_password": self.cracked_password,
            "encrypted_unreadable": self.encrypted_unreadable,
            "detail": self.detail,
        }


class ContainerExtractor:
    SUPPORTED_EXTENSIONS = {".zip", ".7z", ".rar", ".iso"}

    def __init__(
        self,
        max_depth: int = ZIP_BOMB_MAX_DEPTH,
        max_total_bytes: int = ZIP_BOMB_MAX_TOTAL_BYTES,
        max_files: int = ZIP_BOMB_MAX_FILES,
        base_passwords: Optional[List[str]] = None,
    ) -> None:
        self.max_depth = int(max_depth)
        self.max_total_bytes = int(max_total_bytes)
        self.max_files = int(max_files)
        self.base_passwords = list(base_passwords or ARCHIVE_BASE_PASSWORDS)

    def is_supported_container(self, file_path: str | Path) -> bool:
        return Path(file_path).suffix.lower() in self.SUPPORTED_EXTENSIONS

    @staticmethod
    def _validate_member_dest(sandbox_root: Path, member_name: str) -> tuple[bool, Path, str]:
        cleaned = member_name.replace("\\", "/")
        if os.path.isabs(cleaned) or cleaned.startswith("/") or ":" in cleaned.split("/")[0]:
            return False, sandbox_root, f"Absolute or drive-qualified archive path blocked: {member_name}"
        parts = Path(cleaned).parts
        if ".." in parts:
            return False, sandbox_root, f"Directory traversal ('..') blocked in archive member: {member_name}"
        target = (sandbox_root / cleaned).resolve()
        if os.path.commonpath([str(sandbox_root.resolve()), str(target)]) != str(sandbox_root.resolve()):
            return False, sandbox_root, f"Zip-Slip escape outside sandbox blocked: {member_name}"
        return True, target, ""

    def _candidate_passwords(self, archive_path: Path) -> List[Optional[str]]:
        stem = archive_path.stem
        pwds: List[Optional[str]] = [None]
        for p in [*self.base_passwords, stem, stem.lower(), stem.upper()]:
            if p and p not in pwds:
                pwds.append(p)
        return pwds

    def _extract_zip(self, archive_path: Path, dest_dir: Path, state: ContainerExtractionResult) -> List[Path]:
        written: List[Path] = []
        with zipfile.ZipFile(archive_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > self.max_files:
                state.zip_bomb_detected = True
                state.zip_bomb_reason = f"Archive member count ({len(infos)}) exceeds max_files ({self.max_files})."
                return written

            for info in infos:
                if info.is_dir():
                    continue
                # Reject UNIX symlinks (0o120000)
                if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                    state.zip_slip_detected = True
                    state.zip_slip_reason = f"Symbolic link entry rejected: {info.filename}"
                    return written

                ok, target_path, reason = self._validate_member_dest(dest_dir, info.filename)
                if not ok:
                    state.zip_slip_detected = True
                    state.zip_slip_reason = reason
                    return written

                if info.file_size > self.max_total_bytes or (state.total_extracted_bytes + info.file_size) > self.max_total_bytes:
                    state.zip_bomb_detected = True
                    state.zip_bomb_reason = f"Declared uncompressed size exceeds {self.max_total_bytes} bytes."
                    return written

                if info.flag_bits & 0x1:
                    state.password_protected = True

                target_path.parent.mkdir(parents=True, exist_ok=True)
                extracted_ok = False
                for cand in self._candidate_passwords(archive_path):
                    pwd_bytes = cand.encode("utf-8") if cand else None
                    try:
                        with zf.open(info, "r", pwd=pwd_bytes) as src, open(target_path, "wb") as dst:
                            while True:
                                chunk = src.read(IO_CHUNK_SIZE)
                                if not chunk:
                                    break
                                state.total_extracted_bytes += len(chunk)
                                if state.total_extracted_bytes > self.max_total_bytes:
                                    state.zip_bomb_detected = True
                                    state.zip_bomb_reason = f"Streamed uncompressed bytes exceeded {self.max_total_bytes}."
                                    dst.close()
                                    target_path.unlink(missing_ok=True)
                                    return written
                                dst.write(chunk)
                        if cand:
                            state.cracked_password = cand
                        extracted_ok = True
                        break
                    except RuntimeError:
                        target_path.unlink(missing_ok=True)
                        continue
                    except Exception:
                        target_path.unlink(missing_ok=True)
                        break

                if extracted_ok and target_path.exists():
                    written.append(target_path)
                    if len(state.extracted_files) + len(written) > self.max_files:
                        state.zip_bomb_detected = True
                        state.zip_bomb_reason = f"Total extracted files exceeded {self.max_files}."
                        return written
                elif state.password_protected:
                    state.encrypted_unreadable = True
        return written

    def _unpack_recursive(self, current_archive: Path, sandbox_root: Path, depth: int, state: ContainerExtractionResult) -> None:
        if depth > self.max_depth:
            state.zip_bomb_detected = True
            state.zip_bomb_reason = f"Archive nesting depth ({depth}) exceeds max_depth ({self.max_depth})."
            return
        state.max_depth_reached = max(state.max_depth_reached, depth)
        ext = current_archive.suffix.lower()
        step_dir = sandbox_root / f"d{depth}_{current_archive.stem}"
        step_dir.mkdir(parents=True, exist_ok=True)

        new_files: List[Path] = []
        try:
            if ext == ".zip":
                new_files = self._extract_zip(current_archive, step_dir, state)
        except Exception as exc:
            state.detail = f"Container extraction error: {exc}"
            return

        if state.zip_bomb_detected or state.zip_slip_detected:
            return

        for child in new_files:
            if self.is_supported_container(child):
                self._unpack_recursive(child, sandbox_root, depth + 1, state)
                if state.zip_bomb_detected or state.zip_slip_detected:
                    return
            else:
                state.extracted_files.append(str(child))

    @contextlib.contextmanager
    def extract_sandbox(self, file_path: str | Path) -> Iterator[ContainerExtractionResult]:
        path = Path(file_path).resolve()
        res = ContainerExtractionResult(is_container=True, container_type=path.suffix.lower().lstrip("."))
        with tempfile.TemporaryDirectory(prefix="aegis_unpack_") as tmp:
            sandbox_root = Path(tmp).resolve()
            self._unpack_recursive(path, sandbox_root, 1, res)
            res.detail = (
                res.zip_bomb_reason or res.zip_slip_reason
                or f"Extracted {len(res.extracted_files)} file(s) ({res.total_extracted_bytes} bytes)."
            )
            yield res