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

import gui
import RansomwareScanner as RS
from tests.helpers import make_docx
from tests.test_file_integrity import _pe_bytes
from tests.test_mail_analyzer import make_eml


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
    make_eml(downloads / "statement.eml", subject="Invoice overdue",
             sender='"billing@bank.example" <x@evil.example>',
             attachments=[("pay.pdf.exe", _pe_bytes(1024), "application", "octet-stream")])
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

    mail = rows["statement.eml"]
    assert mail["verdict"] in ("High", "Critical")
    summary = gui.layers_summary(mail)
    assert "mail1!1" in summary and "spoof!" in summary
    mail_win = gui.DetailWindow(app, mail)            # renders the MailGuard section
    _pump(app, 0.3)
    mail_win.destroy()

    partial = dict(rows["invoice.pdf"], scan_status="partial",
                   incomplete_reasons=[{"layer": "archive", "reason": "member not unpacked",
                                        "member_path": "x.zip!/a.doc", "status": "partial"}])
    gui.DetailWindow(app, partial).destroy()          # completeness + provenance sections
    win = gui.DetailWindow(app, rows["invoice.pdf"])
    _pump(app, 0.3)
    original = tmp_path / "Downloads" / "invoice.pdf"
    content = original.read_bytes()
    win._quarantine(confirm=False)
    assert not original.exists()
    assert win.undo_button.winfo_manager() == "pack"           # Undo offered

    # Undo from the result view puts the file back, byte for byte
    assert win._undo_quarantine(confirm=False) == original
    assert original.read_bytes() == content and app.scanner.quarantine_vault.list() == []
    assert win.quarantine_button.cget("text") == "Quarantine file"
    assert win.undo_button.winfo_manager() == ""                # hidden again

    # a new file took the name meanwhile: nothing is overwritten
    win._quarantine(confirm=False)
    original.write_bytes(b"a new, different file")
    restored = win._undo_quarantine(confirm=False)
    assert restored.name.startswith("invoice.pdf.restored-") and restored.read_bytes() == content
    assert original.read_bytes() == b"a new, different file"
    restored.unlink()
    original.write_bytes(content)
    win._quarantine(confirm=False)                              # for the vault checks below
    assert not original.exists()
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


def test_first_run_check_shows_diagnostics_once(app, monkeypatch):
    """A9-4: a required layer that cannot run is reported on first launch, once."""
    shown = []
    monkeypatch.setattr(gui.messagebox, "showwarning", lambda *a, **k: shown.append(a))
    page = app.pages["settings"]
    monkeypatch.setattr(page, "diagnostics", lambda: [("problem", "qr: needs zbar"),
                                                      ("note", "emulation: off")])
    app.settings.data["diagnostics_seen"] = False
    app._first_run_check()
    assert len(shown) == 1 and "qr: needs zbar" in shown[0][1]
    assert app.current_page == "settings" and app.settings.data["diagnostics_seen"] is True
    assert "qr: needs zbar" in page.diag_label.cget("text")
    app._first_run_check()
    assert len(shown) == 1                                  # never again
    page._copy_diagnostics()
    assert app.clipboard_get().startswith("Aegis Sentinel ")


def test_monitoring_alerts_cloud_and_key_backup(app, tmp_path, monkeypatch):
    """4.8 (F2): watch a folder and see its result on the dashboard; save e-mail
    settings (password to the keyring only) and send a test e-mail; see the
    delivery status; export and re-import the quarantine key."""
    import aegis_gui.pages.outputs as outputs_mod
    import core.mailer
    from tests.helpers import make_pdf
    env = tmp_path / ".env"
    monkeypatch.setattr(outputs_mod, "ENV_FILE", env)
    monkeypatch.setattr(RS, "CONFIG", dict(RS.CONFIG))   # saved settings must not leak out
    ring = {}
    monkeypatch.setattr("engine.secret_store.store", lambda n, v: ring.__setitem__(n, v))
    sent = []
    monkeypatch.setattr(core.mailer.SmtpMailer, "send", lambda self, f: sent.append(f))
    cfg = app.scanner.config
    for key, name in (("outbox_dir", "outbox"), ("cloud_spool_dir", "spool")):
        monkeypatch.setitem(cfg, key, str(tmp_path / name))

    # -- monitoring -----------------------------------------------------------------
    watched = tmp_path / "watched"
    watched.mkdir()
    app.show_page("monitoring")
    page = app.pages["monitoring"]
    monkeypatch.setattr(page, "ask_folder", lambda: str(watched))
    page._add()
    assert app.settings["watch_dirs"] == [str(watched)]
    page._toggle()
    assert app.monitor is not None and app.monitor.running
    time.sleep(0.5)
    (watched / "dropped.pdf").write_bytes(make_pdf("hello"))
    dash = app.pages["dashboard"]
    deadline = time.time() + 90
    while time.time() < deadline and not any(
            r["file_name"] == "dropped.pdf" for r in dash.row_results.values()):
        _pump(app, 0.2)
    found = [r for r in dash.row_results.values() if r["file_name"] == "dropped.pdf"]
    assert found and found[0]["provenance"]["isolation"] == "worker"
    page.refresh_status()
    assert "Scanned: 1" in page.status_label.cget("text")
    page._toggle()
    assert app.monitor is None and app.settings["monitor_enabled"] is False

    # -- e-mail settings and the test send --------------------------------------------
    app.show_page("outputs")
    out = app.pages["outputs"]
    for name, value in (("SMTP_HOST", "smtp.example.org"), ("ALERT_EMAIL_FROM", "a@example.org"),
                        ("ALERT_EMAIL_TO", "soc@example.org")):
        out.entries[name].delete(0, "end")
        out.entries[name].insert(0, value)
    out.secret_entries["SMTP_PASSWORD"].insert(0, "pw-in-the-keyring-only")
    out._save_email()
    assert out.email_label.cget("text").startswith("Saved")
    assert ring == {"SMTP_PASSWORD": "pw-in-the-keyring-only"}
    assert "pw-in-the-keyring-only" not in env.read_text() and "SMTP_HOST" in env.read_text()
    out._test_email()
    deadline = time.time() + 10
    while time.time() < deadline and not out.email_label.cget("text").startswith("Test"):
        _pump(app, 0.1)
    assert out.email_label.cget("text").startswith("Test e-mail sent") and len(sent) == 1
    out.entries["CLOUD_ENDPOINT"].insert(0, "http://not-https.example.org")
    out.cloud_var.set(True)
    out._save_cloud()
    assert out.cloud_label.cget("text").startswith("Not saved") and not cfg["cloud_upload"]
    out.refresh_status()
    assert out.status_label.cget("text").startswith("Alerts waiting: 0")

    # -- quarantine key backup --------------------------------------------------------
    app.show_page("protection")
    prot = app.pages["protection"]
    backup = tmp_path / "key.aegiskey"
    monkeypatch.setattr(prot, "ask_save_path", lambda: str(backup))
    monkeypatch.setattr(prot, "ask_open_path", lambda: str(backup))
    monkeypatch.setattr(prot, "ask_secret", lambda title, prompt: "a long passphrase")
    prot._export_key()
    assert backup.exists() and prot.key_label.cget("text").startswith("Key backup written")
    prot._import_key()
    assert prot.key_label.cget("text").startswith("This key is already installed")
