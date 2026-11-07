"""M9 / M10: report files.

M9: the reports were opened without an encoding, so on Windows (cp1252) a
file name outside that code page raised UnicodeEncodeError, the scan's report
was lost and deliver(), which runs after generate_report, never sent alerts.
M10: report names had one-second resolution, so a second report finished in
the same second replaced the first."""

import builtins
import json
from datetime import datetime
from pathlib import Path

import pytest

import engine.report as report_module
import RansomwareScanner as RS
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config

NAME = "فاتورة_报告_‮exe.pdf"          # Arabic, CJK and a right-to-left override


@pytest.fixture
def scanned(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    path = tmp_path / "scan" / NAME
    path.write_bytes(make_pdf("hello"))
    return s, [s.scan_file(str(path))]


@pytest.fixture
def windows_default_encoding(monkeypatch):
    """open() without encoding= behaves as on a cp1252 Windows machine."""
    real_open = builtins.open

    def cp1252_open(file, mode="r", *args, encoding=None, **kw):
        if "b" not in mode and encoding is None:
            encoding = "cp1252"
        return real_open(file, mode, *args, encoding=encoding, **kw)

    monkeypatch.setattr(report_module, "open", cp1252_open, raising=False)


class FrozenClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 11, 8, 12, 0, 0)


def test_reports_with_non_ascii_names_are_utf8(scanned, windows_default_encoding):
    s, results = scanned
    text = s.generate_report(results)
    assert NAME in text
    folder = Path(s.report_dir)
    assert len(list(folder.iterdir())) == 2
    txt = next(folder.glob("ransomware_scan_*.txt")).read_text(encoding="utf-8")
    assert NAME in txt
    data = json.loads(next(folder.glob("ransomware_scan_*.json")).read_text(encoding="utf-8"))
    assert data[0]["file_name"] == NAME


def test_reports_in_the_same_second_do_not_overwrite(scanned, monkeypatch):
    s, results = scanned
    monkeypatch.setattr(report_module, "datetime", FrozenClock)
    first = s.generate_report(results)
    second = s.generate_report(results + results)
    third = s.generate_report(results)
    names = sorted(p.name for p in Path(s.report_dir).iterdir())
    assert names == ["ransomware_scan_20261108_120000.json",
                     "ransomware_scan_20261108_120000.txt",
                     "ransomware_scan_20261108_120000_2.json",
                     "ransomware_scan_20261108_120000_2.txt",
                     "ransomware_scan_20261108_120000_3.json",
                     "ransomware_scan_20261108_120000_3.txt"]
    assert "ransomware_scan_20261108_120000.json" in first
    assert "ransomware_scan_20261108_120000_2.json" in second
    assert "ransomware_scan_20261108_120000_3.json" in third
    second_json = json.loads((Path(s.report_dir) / names[2]).read_text(encoding="utf-8"))
    assert len(second_json) == 2
