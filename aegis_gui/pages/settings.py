"""Settings page: schedule, autostart, uploads, API keys."""

import logging
import platform
import threading

from aegis_gui.common import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_SOFT,
    AMBER_SOFT,
    BG,
    BLUE,
    BORDER_2,
    ENV_FILE,
    MUTED,
    ON_ACCENT,
    PANEL_2,
    RED,
    RED_SOFT,
    RS,
    TEXT,
    Path,
    ctk,
    set_key,
)
from aegis_gui.formatting import mask_key, open_path
from aegis_gui.pages.base import BasePage
from aegis_gui.widgets import Section


class SettingsPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        outer = ctk.CTkScrollableFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True)
        ctk.CTkLabel(outer, text="Settings", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")

        # -- schedule ------------------------------------------------------------
        sec = Section(outer, "Scheduled scans", app)
        sec.pack(fill="x", pady=(14, 0))
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(12, 4))
        self.schedule_var = ctk.BooleanVar(value=app.settings["schedule_enabled"])
        ctk.CTkSwitch(row, text="Run a full scan automatically while this window is open",
                      variable=self.schedule_var, font=app.font_ui, text_color=TEXT,
                      progress_color=ACCENT, button_color=TEXT, fg_color=BORDER_2,
                      command=self._schedule_toggled).pack(side="left")
        irow = ctk.CTkFrame(sec.body, fg_color="transparent")
        irow.pack(fill="x", padx=14, pady=(4, 12))
        ctk.CTkLabel(irow, text="Every", font=app.font_ui,
                     text_color=MUTED).pack(side="left")
        self.interval_label = ctk.CTkLabel(irow, text="", width=70, font=app.font_bold,
                                           text_color=ACCENT_SOFT)
        self.interval_slider = ctk.CTkSlider(irow, from_=1, to=24, number_of_steps=23,
                                             width=260, progress_color=ACCENT,
                                             button_color=ACCENT_SOFT,
                                             button_hover_color=TEXT, fg_color=BORDER_2,
                                             command=self._interval_changed)
        self.interval_slider.set(app.settings["scan_interval_hours"])
        self.interval_slider.pack(side="left", padx=10)
        self.interval_label.pack(side="left")
        self._interval_changed(app.settings["scan_interval_hours"])

        # -- autostart -------------------------------------------------------------
        sec = Section(outer, "Start at login", app)
        sec.pack(fill="x", pady=(14, 0))
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(12, 2))
        self.autostart_var = ctk.BooleanVar(value=detect_autostart())
        self.autostart_switch = ctk.CTkSwitch(
            row, text="Run the background scanner automatically at login",
            variable=self.autostart_var, font=app.font_ui, text_color=TEXT,
            progress_color=ACCENT, button_color=TEXT, fg_color=BORDER_2,
            command=self._autostart_toggled)
        self.autostart_switch.pack(side="left")
        self.autostart_note = ctk.CTkLabel(
            sec.body, text="Uses the same mechanism as the CLI "
                           "(--setup-autostart): registry on Windows, launchd on macOS, "
                           "systemd user service on Linux. It runs the command-line "
                           "scanner in background mode — independent of this window.",
            font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
            justify="left")
        self.autostart_note.pack(fill="x", padx=14, pady=(0, 12))

        # -- API keys ----------------------------------------------------------------
        sec = Section(outer, "API keys", app)
        sec.pack(fill="x", pady=(14, 0))
        ctk.CTkLabel(sec.body,
                     text="Keys are stored in the OS keyring (macOS Keychain, Windows "
                          "Credential Manager, Linux Secret Service), never in a file. An "
                          "environment variable with the same name takes precedence. Leave "
                          "a field empty to keep the current value.",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 6))
        self.key_rows = {}
        for env_name, config_key, label in [
                ("OPENAI_API_KEY", "chatgpt_api_key", "OpenAI (LLM layer)"),
                ("VIRUSTOTAL_API_KEY", "virustotal_api_key", "VirusTotal")]:
            row = ctk.CTkFrame(sec.body, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=4)
            ctk.CTkLabel(row, text=label, width=160, anchor="w", font=app.font_ui,
                         text_color=TEXT).pack(side="left")
            entry = ctk.CTkEntry(row, show="•", width=280, fg_color=BG,
                                 border_color=BORDER_2, text_color=TEXT,
                                 placeholder_text="paste new key…")
            entry.pack(side="left", padx=(0, 10))
            status = ctk.CTkLabel(row, text=mask_key(app.scanner.config.get(config_key)),
                                  font=app.font_mono_small, text_color=MUTED, anchor="w")
            status.pack(side="left")
            self.key_rows[env_name] = (entry, status, config_key)
        ctk.CTkButton(sec.body, text="Save keys", height=32, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, text_color=ON_ACCENT, font=app.font_bold,
                      command=self._save_keys).pack(anchor="w", padx=14, pady=(6, 4))
        self.vt_upload_var = ctk.BooleanVar(
            value=bool(app.scanner.config.get("virustotal_upload_unknown")))
        ctk.CTkSwitch(sec.body, text="Upload files VirusTotal has never seen (shares their "
                                     "full content with VirusTotal)",
                      variable=self.vt_upload_var, font=app.font_ui, text_color=TEXT,
                      progress_color=RED, button_color=TEXT, fg_color=BORDER_2,
                      command=self._vt_upload_toggled).pack(anchor="w", padx=14, pady=(8, 2))
        self.keys_label = ctk.CTkLabel(sec.body, text="", font=app.font_small,
                                       text_color=MUTED, anchor="w")
        self.keys_label.pack(fill="x", padx=14, pady=(0, 12))

        # -- locations -------------------------------------------------------------------
        sec = Section(outer, "Locations", app)
        sec.pack(fill="x", pady=(14, 24))
        for label, target in [("Application folder", RS.APP_DIR),
                              ("Reports", RS.REPORT_DIR),
                              ("Log file", RS.LOG_FILE)]:
            row = ctk.CTkFrame(sec.body, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=4)
            ctk.CTkLabel(row, text=label, width=160, anchor="w", font=app.font_ui,
                         text_color=TEXT).pack(side="left")
            ctk.CTkLabel(row, text=str(target), font=app.font_mono_small,
                         text_color=MUTED, anchor="w").pack(side="left", fill="x",
                                                            expand=True)
            ctk.CTkButton(row, text="Open", width=60, height=26, font=app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=BLUE,
                          command=lambda t=target: open_path(t)).pack(side="right")
        ctk.CTkLabel(sec.body, text="", font=app.font_small).pack(pady=2)

    # -- callbacks ------------------------------------------------------------------

    def _schedule_toggled(self):
        self.app.settings["schedule_enabled"] = bool(self.schedule_var.get())
        self.app.reset_schedule()

    def _interval_changed(self, value):
        hours = int(round(float(value)))
        self.interval_label.configure(text=f"{hours} h")
        if hours != self.app.settings["scan_interval_hours"]:
            self.app.settings["scan_interval_hours"] = hours
            self.app.scanner.config["scan_interval_hours"] = hours
            self.app.reset_schedule()

    def _autostart_toggled(self):
        desired = bool(self.autostart_var.get())
        self.autostart_switch.configure(state="disabled")
        self.autostart_note.configure(text="Applying…", text_color=AMBER_SOFT)
        threading.Thread(target=self._apply_autostart, args=(desired,),
                         daemon=True).start()

    def _apply_autostart(self, desired):
        try:
            ok = RS.setup_autostart() if desired else RS.remove_autostart()
        except Exception:
            logging.getLogger("RansomwareScanner.GUI").exception("Autostart change failed")
            ok = False
        self.app.bus.put(("autostart_done", desired, ok))

    def autostart_finished(self, desired, ok):
        self.autostart_switch.configure(state="normal")
        if ok:
            self.autostart_note.configure(
                text=("Enabled — the background scanner will start at login."
                      if desired else "Disabled — the autostart entry was removed."),
                text_color=ACCENT_SOFT)
        else:
            self.autostart_var.set(detect_autostart())
            self.autostart_note.configure(
                text="Could not change the autostart entry — see Logs for details.",
                text_color=RED_SOFT)

    def _vt_upload_toggled(self):
        enabled = bool(self.vt_upload_var.get())
        try:
            ENV_FILE.touch(exist_ok=True)
            set_key(str(ENV_FILE), "VT_UPLOAD_UNKNOWN", "true" if enabled else "false")
        except Exception as e:
            self.keys_label.configure(text=f"Could not save setting: {e}", text_color=RED_SOFT)
        RS.CONFIG["virustotal_upload_unknown"] = enabled
        self.app.scanner.config["virustotal_upload_unknown"] = enabled
        self.keys_label.configure(
            text=("VirusTotal uploads ON — unknown files will be shared with VirusTotal."
                  if enabled else "VirusTotal uploads OFF — hash lookups only (private)."),
            text_color=AMBER_SOFT if enabled else ACCENT_SOFT)

    def _save_keys(self):
        from engine.secret_store import SecretStoreError, store
        changed = []
        try:
            for env_name, (entry, status, config_key) in self.key_rows.items():
                value = entry.get().strip()
                if not value:
                    continue
                store(env_name, value)           # written, read back and compared
                RS.CONFIG[config_key] = value
                self.app.scanner.config[config_key] = value
                status.configure(text=mask_key(value))
                entry.delete(0, "end")
                changed.append(env_name)
        except SecretStoreError as e:            # the message never holds the key
            self.keys_label.configure(
                text=f"Could not save to the OS keyring: {e}. Nothing was written to disk; "
                     "set the key as an environment variable instead.",
                text_color=RED_SOFT)
            return
        if changed:
            self.keys_label.configure(text=f"Saved to the OS keyring: "
                                           f"{', '.join(changed)}",
                                      text_color=ACCENT_SOFT)
            logging.getLogger("RansomwareScanner.GUI").info(
                "API keys updated via GUI: %s", ', '.join(changed))
            self.app.pages["dashboard"].refresh_cards()
        else:
            self.keys_label.configure(text="Nothing to save — both fields were empty.",
                                      text_color=MUTED)


def detect_autostart() -> bool:
    """Best-effort check of whether the CLI autostart entry currently exists."""
    system = platform.system()
    try:
        if system == "Windows" and RS.winreg is not None:
            with RS.winreg.OpenKey(RS.winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                RS.winreg.QueryValueEx(key, RS.AUTOSTART_NAME)
            return True
        if system == "Darwin":
            return (Path.home() / "Library" / "LaunchAgents" /
                    f"{RS.AUTOSTART_LABEL}.plist").exists()
        return (Path.home() / ".config" / "systemd" / "user" / RS.SYSTEMD_UNIT).exists()
    except Exception:
        return False
