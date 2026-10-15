"""Headless GUI smoke test (opt-in): builds the real window, runs a scan through
the worker thread, opens every page and a detail window, and exercises the
quarantine + canary flows. Run with an X display (e.g. under xvfb-run):

    RUN_GUI_TESTS=1 xvfb-run -a python -m pytest tests/test_gui_smoke.py
"""

import os
import time
from pathlib import Path

import pytest

if os.environ.get("RUN_GUI_TESTS") != "1":
    pytest.skip("GUI tests are opt-in (RUN_GUI_TESTS=1 with a display)",
                allow_module_level=True)

import gui  # noqa: E402
import RansomwareScanner as RS  # noqa: E402
from tests.helpers import make_docx  # noqa: E402
from tests.test_file_integrity import _pe_bytes  # noqa: E402


def _pump(app, seconds=0.3):
    end = time.time() + seconds
    while time.time() < end:
        app.update()
        time.sleep(0.02)


@pytest.fixture
def app(tmp_path, monkeypatch):
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    make_docx(downloads / "notes.docx")
    (downloads / "invoice.pdf").write_bytes(_pe_bytes(2048))
    monkeypatch.setitem(RS.CONFIG, "scan_directories", [str(downloads)])
    monkeypatch.setitem(RS.CONFIG, "report_directory", str(tmp_path / "reports"))
    monkeypatch.setitem(RS.CONFIG, "quarantine_dir", str(tmp_path / "vault"))
    monkeypatch.setitem(RS.CONFIG, "keystore_dir", str(tmp_path / "keys"))
    monkeypatch.setitem(RS.CONFIG, "canary_registry", str(tmp_path / "canaries.json"))
    monkeypatch.setattr(gui, "SETTINGS_FILE", tmp_path / "gui_settings.json")
    monkeypatch.setattr(gui.messagebox, "showinfo", lambda *a, **k: None)
    monkeypatch.setattr(gui.messagebox, "showwarning", lambda *a, **k: None)
    a = gui.App()
    yield a
    a.destroy()


def test_full_gui_flow(app, tmp_path):
    for key, _ in app.NAV:
        app.show_page(key)
        _pump(app, 0.1)

    app.start_scan(mode="all")
    deadline = time.time() + 60
    while app.controller.running and time.time() < deadline:
        _pump(app, 0.1)
    _pump(app, 0.3)
    dash = app.pages["dashboard"]
    rows = {r["file_name"]: r for r in dash.row_results.values()}
    assert rows["invoice.pdf"]["verdict"] == "Critical"
    assert "exe!" in gui.layers_summary(rows["invoice.pdf"])

    win = gui.DetailWindow(app, rows["invoice.pdf"])
    _pump(app, 0.3)
    win._quarantine(confirm=False)
    assert not (tmp_path / "Downloads" / "invoice.pdf").exists()
    win.destroy()

    app.show_page("protection")
    _pump(app, 0.2)
    page = app.pages["protection"]
    items = app.scanner.quarantine_vault.list()
    assert len(items) == 1
    page._restore(items[0]["id"], confirm=False)
    assert (tmp_path / "Downloads" / "invoice.pdf").exists()

    page._deploy()
    deadline = time.time() + 10
    while app.last_canary_report is None and time.time() < deadline:
        _pump(app, 0.1)
    assert app.last_canary_report is not None and not app.last_canary_report.triggered
    victim = next(Path(tmp_path / "Downloads").glob("!000_*.csv"))
    victim.unlink()
    app.check_canaries_now()
    deadline = time.time() + 10
    while not app.last_canary_report.triggered and time.time() < deadline:
        _pump(app, 0.1)
    assert app.last_canary_report.triggered
    assert dash.card_canary.status_label.cget("text") == "TRIGGERED"
