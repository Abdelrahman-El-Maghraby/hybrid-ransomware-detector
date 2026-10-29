"""The GUI's side of monitoring, alerts and cloud storage (F2), without Tk:
validated settings, test sends and delivery status. The pages call these and
show the result, so the logic is tested without a display.

Settings are saved like the rest of the app: plain values in the .env file next
to the program, secrets in the OS keyring (engine/secret_store.py; never a
file). Every change is checked with engine.validation first; nothing is saved
when the result would not start.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, MutableMapping, Optional, Tuple

logger = logging.getLogger("RansomwareScanner.GUI")

# environment variable -> (CONFIG key, kind); kind: str | int | float | bool
FIELDS: Dict[str, Tuple[str, str]] = {
    "SMTP_HOST": ("smtp_host", "str"), "SMTP_PORT": ("smtp_port", "int"),
    "SMTP_SECURITY": ("smtp_security", "str"), "SMTP_USER": ("smtp_user", "str"),
    "ALERT_EMAIL_FROM": ("alert_email_from", "str"), "ALERT_EMAIL_TO": ("alert_email_to", "str"),
    "ALERT_EMAIL_MIN_VERDICT": ("alert_email_min_verdict", "str"),
    "WEBHOOK_URL": ("webhook_url", "str"), "WEBHOOK_MIN_VERDICT": ("webhook_min_verdict", "str"),
    "WATCH_DIRS": ("watch_dirs", "str"),
    "CLOUD_UPLOAD": ("cloud_upload", "bool"), "CLOUD_ENDPOINT": ("cloud_endpoint", "str"),
    "CLOUD_REGION": ("cloud_region", "str"), "CLOUD_BUCKET": ("cloud_bucket", "str"),
    "CLOUD_PREFIX": ("cloud_prefix", "str"), "CLOUD_ACCESS_KEY_ID": ("cloud_access_key_id", "str"),
    "CLOUD_CA_BUNDLE": ("cloud_ca_bundle", "str"),
    "CLOUD_UPLOAD_FULL": ("cloud_upload_full", "bool"),
}
SECRETS: Dict[str, str] = {"SMTP_PASSWORD": "smtp_password", "WEBHOOK_SECRET": "webhook_secret",
                           "CLOUD_SECRET_ACCESS_KEY": "cloud_secret_access_key"}


def _convert(kind: str, value: str) -> Any:
    value = (value or "").strip()
    if kind == "int":
        return int(float(value)) if value else 0
    if kind == "float":
        return float(value) if value else 0.0
    if kind == "bool":
        return value.lower() in ("1", "true", "yes", "on")
    return value


def apply_settings(config: MutableMapping[str, Any], updates: Dict[str, str],
                   secrets: Optional[Dict[str, str]] = None, env_file: Optional[Path] = None,
                   store: Optional[Callable[[str, str], None]] = None,
                   set_key: Optional[Callable[[str, str, str], Any]] = None
                   ) -> Tuple[List[str], List[str]]:
    """Validate, then save: (errors, warnings). With errors nothing is saved or
    changed. Empty secret fields keep the stored value. Secrets are never
    written to the .env file and never appear in a message."""
    from engine.validation import validate_config
    secrets = {k: v for k, v in (secrets or {}).items() if k in SECRETS and v}
    try:
        values = {FIELDS[name][0]: _convert(FIELDS[name][1], v)
                  for name, v in updates.items() if name in FIELDS}
    except ValueError:
        return ["a number field holds something that is not a number"], []
    candidate = dict(config, **values, **{SECRETS[k]: v for k, v in secrets.items()})
    errors, warnings = validate_config(candidate)
    if errors:
        return errors, warnings
    if store is None:
        from engine.secret_store import store as store
    for name, value in secrets.items():
        store(name, value)                          # raises SecretStoreError; nothing logged
    if env_file is not None:
        if set_key is None:
            from dotenv import set_key
        env_file.touch(exist_ok=True)
        for name, value in updates.items():
            if name in FIELDS:
                set_key(str(env_file), name, str(value).strip())
    config.update(candidate)
    logger.info("Settings saved from the GUI: %s", ", ".join(sorted(list(updates) + list(secrets))),
                extra={"event": "settings_saved"})
    return [], warnings


def test_alert() -> Dict[str, Any]:
    """The e-mail fields of a test message (no file was scanned)."""
    from core.outbox import _alert_id
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    return {"alert_id": _alert_id("test", stamp, time.time()), "kind": "verdict",
            "verdict": "Clean", "risk_band": "0-20", "sha256": "",
            "file_name": "test message from the Aegis Sentinel settings", "time": stamp,
            "scan_id": "", "reason_codes": ["test_message"]}


def send_test_email(config: MutableMapping[str, Any], mailer: Any = None) -> str:
    """Send one test message now (not through the outbox); a sentence for the GUI."""
    from core.mailer import MailError, SmtpMailer, email_configured
    if mailer is None and not email_configured(config):
        return "E-mail is not configured: set the SMTP host, the sender and the recipients."
    try:
        (mailer or SmtpMailer(config)).send(test_alert())
    except MailError as e:
        return f"The test e-mail was not sent: {e}"
    return "Test e-mail sent. Check the recipients' inboxes."


def send_test_upload(config: MutableMapping[str, Any], uploader: Any = None) -> str:
    """Upload one small test document now; a sentence for the GUI."""
    from core import cloud
    try:
        install = cloud.installation_id(cloud._app_dir())
        up = uploader or cloud.S3Uploader(config, install)
        body = cloud.document("logs", [{"time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                        "level": "INFO", "event": "cloud_test"}],
                              install, bool(config.get("cloud_upload_full")))
        key = up.put("logs", body)
    except cloud.CloudError as e:
        return f"The test upload failed: {e}"
    return f"Test upload stored as {key}."


def delivery_status(config: MutableMapping[str, Any]) -> Dict[str, Any]:
    """Pending alerts per channel and the cloud spool, for the status panel."""
    from core import cloud
    from core.outbox import outbox_for
    return {"alerts": outbox_for(config).status(), "cloud": cloud.spool_for(config).status()}


def status_lines(status: Dict[str, Any]) -> List[str]:
    alerts, spool = status["alerts"], status["cloud"]
    lines = [f"Alerts waiting: {alerts['pending']}"]
    for channel, c in sorted(alerts.get("channels", {}).items()):
        lines.append(f"  {channel}: {c['pending']} pending"
                     + (f" - last error: {c['last_error']}" if c.get("last_error") else ""))
    lines.append(f"Cloud spool: {spool['pending']} item(s), {spool['bytes'] / 1024:.0f} KB; "
                 f"{spool['expired_without_upload']} expired without upload")
    if spool.get("last_error"):
        lines.append(f"  last upload error: {spool['last_error']}")
    return lines


# ------------------------------------------------------------------ quarantine key backup
def export_key_backup(vault: Any, destination: str, passphrase: str, again: str) -> str:
    """Write a passphrase-protected copy of the vault key (F3); a sentence."""
    from core.quarantine import QuarantineError
    if passphrase != again:
        return "The two passphrases differ; nothing was written."
    try:
        path = vault.export_key(destination, passphrase)
    except QuarantineError as e:
        return f"Not exported: {e}"
    logger.info("Quarantine key backup exported (fingerprint %s).", vault.key_fingerprint(),
                extra={"event": "key_exported"})
    return f"Key backup written to {path} (fingerprint {vault.key_fingerprint()})."


def import_key_backup(vault: Any, source: str, passphrase: str, replace: bool = False) -> str:
    """Install a vault key from a backup; never replaces a different key silently."""
    from core.quarantine import QuarantineError
    try:
        status = vault.import_key(source, passphrase, replace=replace)
    except QuarantineError as e:
        return f"Not imported: {e}"
    return {"installed": "Key installed.", "already-present": "This key is already installed.",
            "replaced": "Key replaced; the previous key was kept as a .bak file next to it."
            }.get(status, status) + f" Fingerprint {vault.key_fingerprint()}."
