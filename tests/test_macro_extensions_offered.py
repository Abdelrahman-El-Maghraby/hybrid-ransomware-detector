"""I-1 (owner-approved 2026-11-12): eight macro-capable Office types that the
macro layer reads were never offered to folder scans, the folder monitor or
the GUI. They are now in the default list. Files are benign."""

import RansomwareScanner as RS
from detectors.macro_analysis import MacroAnalyzer
from engine.config import DEFAULT_EXTENSIONS, SUPPORTED_EXTENSIONS
from tests.test_scanner_integration import _config

ADDED = [".dot", ".xlsb", ".xltm", ".xlam", ".xlm", ".potm", ".ppam", ".ppsm"]


def test_the_eight_macro_types_are_offered_by_default():
    for ext in ADDED:
        assert ext in SUPPORTED_EXTENSIONS and ext in DEFAULT_EXTENSIONS, ext
        assert ext in MacroAnalyzer.SUPPORTED_EXTS, ext
    assert len(SUPPORTED_EXTENSIONS) == len(set(SUPPORTED_EXTENSIONS))


def test_a_folder_scan_reaches_them(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, file_extensions=list(DEFAULT_EXTENSIONS)))
    for ext in ADDED:
        (tmp_path / "scan" / f"budget{ext}").write_bytes(b"plain text, no macros\n")
    found = {r["file_name"] for r in s.scan_all_directories()}
    assert found == {f"budget{ext}" for ext in ADDED}
