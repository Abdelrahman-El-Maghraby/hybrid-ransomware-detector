"""Alerts & cloud page (F2 for F4, F5 and the outbox): e-mail and webhook alerts
with a test send, optional cloud storage with a test upload, and what is still
waiting to be delivered."""

import threading

from aegis_gui.common import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_SOFT,
    AMBER_SOFT,
    BG,
    BORDER_2,
    ENV_FILE,
    MUTED,
    ON_ACCENT,
    PANEL_2,
    RED,
    RED_SOFT,
    TEXT,
    ctk,
)
from aegis_gui.pages.base import BasePage
from aegis_gui.widgets import Section

VERDICTS = ["Low", "Medium", "High", "Critical"]
EMAIL_FIELDS = [("SMTP_HOST", "SMTP server", ""), ("SMTP_PORT", "Port", ""),
                ("SMTP_USER", "User name", ""), ("ALERT_EMAIL_FROM", "From", ""),
                ("ALERT_EMAIL_TO", "To (comma-separated)", "")]
CLOUD_FIELDS = [("CLOUD_ENDPOINT", "Endpoint (https://)", ""), ("CLOUD_REGION", "Region", ""),
                ("CLOUD_BUCKET", "Bucket", ""), ("CLOUD_PREFIX", "Prefix", ""),
                ("CLOUD_ACCESS_KEY_ID", "Access key id", ""),
                ("CLOUD_CA_BUNDLE", "CA bundle (optional)", "")]


class OutputsPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        from aegis_gui.integration import FIELDS
        self._fields = FIELDS
        self.entries = {}
        self.secret_entries = {}
        cfg = app.scanner.config
        outer = ctk.CTkScrollableFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True)
        ctk.CTkLabel(outer, text="Alerts & cloud", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")

        # -- e-mail -------------------------------------------------------------------
        sec = Section(outer, "E-mail alerts", app)
        sec.pack(fill="x", pady=(14, 0))
        self._note(sec, "Metadata only - verdict, hash, file name and reason codes, never file "
                        "content - over TLS with certificate verification. The password is "
                        "kept in the OS keyring.")
        for name, label, _ in EMAIL_FIELDS:
            self._entry(sec, name, label, cfg)
        self._choice(sec, "SMTP_SECURITY", "Encryption", ["tls", "starttls"],
                     str(cfg.get("smtp_security") or "tls"))
        self._choice(sec, "ALERT_EMAIL_MIN_VERDICT", "Alert from", VERDICTS,
                     str(cfg.get("alert_email_min_verdict") or "High"))
        self._secret(sec, "SMTP_PASSWORD", "Password", cfg.get("smtp_password"))
        self.email_label = self._buttons(sec, [("Save", self._save_email),
                                               ("Send test e-mail", self._test_email)])

        # -- webhook ------------------------------------------------------------------
        sec = Section(outer, "Webhook alerts", app)
        sec.pack(fill="x", pady=(14, 0))
        self._entry(sec, "WEBHOOK_URL", "URL", cfg)
        self._choice(sec, "WEBHOOK_MIN_VERDICT", "Alert from", VERDICTS,
                     str(cfg.get("webhook_min_verdict") or "High"))
        self._secret(sec, "WEBHOOK_SECRET", "Signing secret", cfg.get("webhook_secret"))
        self.webhook_label = self._buttons(sec, [("Save", self._save_webhook)])

        # -- cloud --------------------------------------------------------------------
        sec = Section(outer, "Cloud storage of reports and logs (optional)", app)
        sec.pack(fill="x", pady=(14, 0))
        self._note(sec, "Off by default. Uploads a redacted view - no paths, file names, user "
                        "or host names, no free text - to one S3-compatible bucket over HTTPS. "
                        "Retention is the bucket's lifecycle rule (90 days recommended); uploads "
                        "are not tamper-evident. See docs/DATA_POLICY.md.")
        self.cloud_var = ctk.BooleanVar(value=bool(cfg.get("cloud_upload")))
        ctk.CTkSwitch(sec.body, text="Upload reports and logs", variable=self.cloud_var,
                      font=app.font_ui, text_color=TEXT, progress_color=ACCENT,
                      button_color=TEXT, fg_color=BORDER_2).pack(anchor="w", padx=14, pady=4)
        for name, label, _ in CLOUD_FIELDS:
            self._entry(sec, name, label, cfg)
        self._secret(sec, "CLOUD_SECRET_ACCESS_KEY", "Secret access key",
                     cfg.get("cloud_secret_access_key"))
        self.full_var = ctk.BooleanVar(value=bool(cfg.get("cloud_upload_full")))
        ctk.CTkSwitch(sec.body, text="Full detail: also upload paths and file names "
                                     "(recorded in every upload)",
                      variable=self.full_var, font=app.font_ui, text_color=TEXT,
                      progress_color=RED, button_color=TEXT,
                      fg_color=BORDER_2).pack(anchor="w", padx=14, pady=4)
        self.cloud_label = self._buttons(sec, [("Save", self._save_cloud),
                                               ("Test upload", self._test_upload)])

        # -- status -------------------------------------------------------------------
        sec = Section(outer, "Delivery status", app)
        sec.pack(fill="x", pady=(14, 24))
        self.status_label = ctk.CTkLabel(sec.body, text="", font=app.font_mono_small,
                                         text_color=MUTED, anchor="w", justify="left")
        self.status_label.pack(fill="x", padx=14, pady=12)

    # -- building blocks ---------------------------------------------------------------
    def _note(self, sec, text):
        ctk.CTkLabel(sec.body, text=text, font=self.app.font_small, text_color=MUTED,
                     anchor="w", wraplength=720, justify="left").pack(fill="x", padx=14,
                                                                     pady=(12, 6))

    def _row(self, sec, label):
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(row, text=label, width=190, anchor="w", font=self.app.font_ui,
                     text_color=TEXT).pack(side="left")
        return row

    def _entry(self, sec, name, label, cfg):
        entry = ctk.CTkEntry(self._row(sec, label), width=360, fg_color=BG,
                             border_color=BORDER_2, text_color=TEXT)
        value = cfg.get(self._fields[name][0])
        if value not in (None, ""):
            entry.insert(0, str(value))
        entry.pack(side="left")
        self.entries[name] = entry

    def _choice(self, sec, name, label, values, current):
        var = ctk.StringVar(value=current if current in values else values[0])
        ctk.CTkSegmentedButton(self._row(sec, label), values=values, variable=var,
                               selected_color=ACCENT, selected_hover_color=ACCENT_HOVER,
                               font=self.app.font_small).pack(side="left")
        self.entries[name] = var

    def _secret(self, sec, name, label, current):
        row = self._row(sec, label)
        entry = ctk.CTkEntry(row, show="•", width=360, fg_color=BG, border_color=BORDER_2,
                             text_color=TEXT, placeholder_text="unchanged" if current else "")
        entry.pack(side="left")
        ctk.CTkLabel(row, text="stored" if current else "not set", font=self.app.font_small,
                     text_color=MUTED).pack(side="left", padx=8)
        self.secret_entries[name] = entry

    def _buttons(self, sec, buttons):
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(8, 2))
        for i, (text, command) in enumerate(buttons):
            ctk.CTkButton(row, text=text, width=140, height=30, command=command,
                          font=self.app.font_bold if i == 0 else self.app.font_small,
                          fg_color=ACCENT if i == 0 else "transparent",
                          hover_color=ACCENT_HOVER if i == 0 else PANEL_2,
                          text_color=ON_ACCENT if i == 0 else TEXT,
                          border_width=0 if i == 0 else 1,
                          border_color=BORDER_2).pack(side="left", padx=(0, 10))
        label = ctk.CTkLabel(sec.body, text="", font=self.app.font_small, text_color=MUTED,
                             anchor="w", wraplength=720, justify="left")
        label.pack(fill="x", padx=14, pady=(0, 12))
        return label

    # -- saving --------------------------------------------------------------------------
    def _values(self, names):
        return {n: self.entries[n].get() for n in names}

    def _apply(self, label, names, secret_names, extra=None):
        from aegis_gui.integration import apply_settings
        from engine.secret_store import SecretStoreError
        updates = dict(self._values(names), **(extra or {}))
        secrets = {n: self.secret_entries[n].get().strip() for n in secret_names}
        try:
            errors, warnings = apply_settings(self.app.scanner.config, updates, secrets,
                                              ENV_FILE)
        except SecretStoreError as e:
            label.configure(text=f"Not saved: {e}. Nothing was written to disk.",
                            text_color=RED_SOFT)
            return False
        if errors:
            label.configure(text="Not saved: " + "; ".join(errors), text_color=RED_SOFT)
            return False
        for n in secret_names:
            self.secret_entries[n].delete(0, "end")
        label.configure(text="Saved." + (" " + "; ".join(warnings) if warnings else ""),
                        text_color=AMBER_SOFT if warnings else ACCENT_SOFT)
        self.app.config_changed()
        return True

    def _save_email(self):
        names = [n for n, _, _ in EMAIL_FIELDS] + ["SMTP_SECURITY", "ALERT_EMAIL_MIN_VERDICT"]
        self._apply(self.email_label, names, ["SMTP_PASSWORD"])

    def _save_webhook(self):
        self._apply(self.webhook_label, ["WEBHOOK_URL", "WEBHOOK_MIN_VERDICT"], ["WEBHOOK_SECRET"])

    def _save_cloud(self):
        extra = {"CLOUD_UPLOAD": "true" if self.cloud_var.get() else "false",
                 "CLOUD_UPLOAD_FULL": "true" if self.full_var.get() else "false"}
        self._apply(self.cloud_label, [n for n, _, _ in CLOUD_FIELDS], ["CLOUD_SECRET_ACCESS_KEY"],
                    extra)

    # -- tests (off the UI thread; the answer arrives on the bus) --------------------------
    def _run(self, label, work):
        label.configure(text="Working…", text_color=MUTED)

        def go():
            try:
                message = work(self.app.scanner.config)
            except Exception as e:                       # never crash the window
                message = f"Failed: {type(e).__name__}"
            self.app.bus.put(("output_test", label, message))
        threading.Thread(target=go, daemon=True).start()

    def _test_email(self):
        from aegis_gui.integration import send_test_email
        self._run(self.email_label, send_test_email)

    def _test_upload(self):
        from aegis_gui.integration import send_test_upload
        self._run(self.cloud_label, send_test_upload)

    def show_test_result(self, label, message):
        ok = message.startswith(("Test e-mail sent", "Test upload stored"))
        label.configure(text=message, text_color=ACCENT_SOFT if ok else RED_SOFT)

    # -- status --------------------------------------------------------------------------
    def on_show(self):
        self.refresh_status()

    def refresh_status(self):
        from aegis_gui.integration import delivery_status, status_lines
        try:
            lines = status_lines(delivery_status(self.app.scanner.config))
        except Exception as e:
            lines = [f"Status unavailable: {type(e).__name__}"]
        self.status_label.configure(text="\n".join(lines))
