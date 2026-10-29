"""4.8 GUI integration (F2) without a display: saving alert, cloud and monitoring
settings (validated first; secrets only in the keyring), the test e-mail and
test upload, the delivery status, and the quarantine key backup (F3)."""

import pytest

pytest.importorskip("customtkinter")

from aegis_gui import integration as GI
from core.mailer import MailError
from tests.test_scanner_integration import _config

SECRET = "GUI-SMTP-secret-31f"


class Keyring:
    def __init__(self):
        self.saved = {}

    def __call__(self, name, value):
        self.saved[name] = value


def _env_writer():
    written = {}
    return written, lambda path, name, value: written.__setitem__(name, value)


def test_valid_settings_are_saved_secrets_only_to_the_keyring(tmp_path, caplog):
    cfg = _config(tmp_path)
    ring = Keyring()
    written, set_key = _env_writer()
    errors, _ = GI.apply_settings(cfg, {"SMTP_HOST": "smtp.example.org", "SMTP_PORT": "587",
                                        "SMTP_SECURITY": "starttls",
                                        "ALERT_EMAIL_FROM": "aegis@example.org",
                                        "ALERT_EMAIL_TO": "soc@example.org"},
                                  {"SMTP_PASSWORD": SECRET}, tmp_path / ".env", store=ring,
                                  set_key=set_key)
    assert errors == []
    assert cfg["smtp_port"] == 587 and cfg["smtp_password"] == SECRET
    assert ring.saved == {"SMTP_PASSWORD": SECRET}
    assert "SMTP_PASSWORD" not in written and SECRET not in str(written)
    assert written["SMTP_HOST"] == "smtp.example.org"
    assert SECRET not in caplog.text


@pytest.mark.parametrize("updates, message", [
    ({"SMTP_HOST": "smtp.example.org"}, "ALERT_EMAIL_FROM"),
    ({"SMTP_SECURITY": "none"}, "SMTP_SECURITY"),
    ({"CLOUD_UPLOAD": "true", "CLOUD_ENDPOINT": "http://s3.example.org"}, "https://"),
    ({"SMTP_PORT": "five"}, "not a number"),
])
def test_invalid_settings_change_nothing(tmp_path, updates, message):
    cfg = _config(tmp_path)
    before = dict(cfg)
    ring = Keyring()
    written, set_key = _env_writer()
    errors, _ = GI.apply_settings(cfg, updates, {"SMTP_PASSWORD": SECRET}, tmp_path / ".env",
                                  store=ring, set_key=set_key)
    assert errors and any(message in e for e in errors)
    assert cfg == before and ring.saved == {} and written == {}
    assert not any(SECRET in e for e in errors)


def test_empty_secret_fields_keep_the_stored_value(tmp_path):
    cfg = _config(tmp_path, webhook_secret="kept")
    ring = Keyring()
    errors, _ = GI.apply_settings(cfg, {"WEBHOOK_URL": "https://siem.example.org/hook"},
                                  {"WEBHOOK_SECRET": ""}, None, store=ring)
    assert errors == [] and ring.saved == {} and cfg["webhook_secret"] == "kept"


def test_the_test_e_mail(tmp_path):
    cfg = _config(tmp_path)
    assert GI.send_test_email(cfg).startswith("E-mail is not configured")
    sent = []
    fake = type("M", (), {"send": lambda self, f: sent.append(f)})()
    assert GI.send_test_email(cfg, mailer=fake).startswith("Test e-mail sent")
    from core.mailer import validate_fields
    validate_fields(sent[0])
    assert sent[0]["reason_codes"] == ["test_message"]

    class Broken:
        def send(self, f):
            raise MailError("SSLCertVerificationError from smtp://x:465 (tls)")
    assert "SSLCertVerificationError" in GI.send_test_email(cfg, mailer=Broken())


def test_the_test_upload(tmp_path, monkeypatch):
    monkeypatch.setattr("engine.config.APP_DIR", tmp_path / "app")
    puts = []

    class Up:
        def put(self, kind, body):
            puts.append((kind, body))
            return "aegis/x/logs/k.json"
    assert GI.send_test_upload(_config(tmp_path), uploader=Up()) == \
        "Test upload stored as aegis/x/logs/k.json."
    assert puts[0][0] == "logs" and b"cloud_test" in puts[0][1]
    msg = GI.send_test_upload(_config(tmp_path, cloud_endpoint="http://insecure"))
    assert msg.startswith("The test upload failed") and "https" in msg


def test_delivery_status_lines(tmp_path):
    from core import cloud
    from core.outbox import outbox_for, verdict_alert
    cfg = _config(tmp_path, outbox_dir=str(tmp_path / "outbox"),
                  cloud_spool_dir=str(tmp_path / "spool"))
    box = outbox_for(cfg)
    box.enqueue(verdict_alert({"sha256_hash": "a" * 64, "scan_time": "t", "file_path": "/x",
                               "verdict": "High"}), ["webhook"])
    box.flush({"webhook": lambda p: (_ for _ in ()).throw(ConnectionError("down"))})
    cloud.spool_for(cfg).add("report", b"{}")
    lines = GI.status_lines(GI.delivery_status(cfg))
    assert lines[0] == "Alerts waiting: 1"
    assert "webhook: 1 pending - last error: ConnectionError: down" in lines[1]
    assert lines[2].startswith("Cloud spool: 1 item(s)") and "0 expired without upload" in lines[2]


def test_key_backup_export_and_import(tmp_path):
    pytest.importorskip("cryptography")
    from core.quarantine import QuarantineVault
    vault = QuarantineVault(tmp_path / "vault", tmp_path / "keys")
    vault.key_fingerprint()                                         # creates the key
    backup = str(tmp_path / "k.aegiskey")
    assert GI.export_key_backup(vault, backup, "long passphrase", "other phrase") \
        .startswith("The two passphrases differ")
    assert GI.export_key_backup(vault, backup, "short", "short").startswith("Not exported")
    assert GI.export_key_backup(vault, backup, "long passphrase", "long passphrase") \
        .startswith("Key backup written")
    assert GI.import_key_backup(vault, backup, "long passphrase").startswith("This key is already")
    assert GI.import_key_backup(vault, backup, "wrong passphrase!").startswith("Not imported")
    other = QuarantineVault(tmp_path / "vault2", tmp_path / "keys2")
    other.key_fingerprint()
    refused = GI.import_key_backup(other, backup, "long passphrase")
    assert "different quarantine key is already installed" in refused
    assert GI.import_key_backup(other, backup, "long passphrase", replace=True).startswith(
        "Key replaced")
    assert other.key_fingerprint() == vault.key_fingerprint()
