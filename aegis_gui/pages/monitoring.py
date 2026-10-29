"""Monitoring page (F2 for F1): watched folders, start/stop, live status, and the
pause when isolated workers cannot start (with a retry)."""

from aegis_gui.common import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_SOFT,
    AMBER_SOFT,
    BG,
    BORDER_2,
    MUTED,
    ON_ACCENT,
    PANEL_2,
    RED_SOFT,
    TEXT,
    ctk,
    filedialog,
)
from aegis_gui.pages.base import BasePage
from aegis_gui.widgets import Section


class MonitoringPage(BasePage):
    # a dialog attribute, so the GUI smoke test can answer it
    ask_folder = staticmethod(lambda: filedialog.askdirectory(title="Watch a folder"))

    def __init__(self, app):
        super().__init__(app)
        outer = ctk.CTkScrollableFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True)
        ctk.CTkLabel(outer, text="Folder monitoring", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")

        sec = Section(outer, "Watched folders", app)
        sec.pack(fill="x", pady=(14, 0))
        ctk.CTkLabel(sec.body,
                     text="New and changed files in these folders are scanned once they stop "
                          "changing, in isolated workers, with the automatic quarantine setting "
                          "of the Protection page. The app's own folders are never scanned, and "
                          "links are not followed out of a watched folder.",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 6))
        self.folder_rows = ctk.CTkFrame(sec.body, fg_color="transparent")
        self.folder_rows.pack(fill="x", padx=10, pady=(0, 6))
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 12))
        ctk.CTkButton(row, text="Add folder…", width=120, height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self._add).pack(side="left")
        self.toggle_button = ctk.CTkButton(row, text="Start monitoring", width=150, height=30,
                                           fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                           text_color=ON_ACCENT, font=app.font_bold,
                                           command=self._toggle)
        self.toggle_button.pack(side="left", padx=10)
        self.retry_button = ctk.CTkButton(row, text="Retry now", width=100, height=30,
                                          font=app.font_small, fg_color="transparent",
                                          hover_color=PANEL_2, border_width=1,
                                          border_color=BORDER_2, text_color=AMBER_SOFT,
                                          command=self._retry)

        sec = Section(outer, "Status", app)
        sec.pack(fill="x", pady=(14, 24))
        self.status_label = ctk.CTkLabel(sec.body, text="", font=app.font_mono_small,
                                         text_color=MUTED, anchor="w", justify="left")
        self.status_label.pack(fill="x", padx=14, pady=12)

    def on_show(self):
        self._refresh_folders()
        self.refresh_status()

    # -- views -----------------------------------------------------------------------
    def _refresh_folders(self):
        for child in self.folder_rows.winfo_children():
            child.destroy()
        folders = self.app.settings["watch_dirs"]
        if not folders:
            ctk.CTkLabel(self.folder_rows, text="No folder is watched.", font=self.app.font_small,
                         text_color=MUTED, anchor="w").pack(fill="x", padx=4, pady=2)
        for folder in folders:
            row = ctk.CTkFrame(self.folder_rows, fg_color=BG, corner_radius=8)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=folder, font=self.app.font_mono_small, text_color=TEXT,
                         anchor="w").pack(side="left", fill="x", expand=True, padx=10, pady=6)
            ctk.CTkButton(row, text="Remove", width=80, height=26, font=self.app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=MUTED,
                          command=lambda f=folder: self._remove(f)).pack(side="right", padx=8)

    def refresh_status(self):
        monitor = self.app.monitor
        running = monitor is not None and monitor.running
        self.toggle_button.configure(text="Stop monitoring" if running else "Start monitoring")
        if not running:
            self.retry_button.pack_forget()
            self.status_label.configure(text="Not monitoring.", text_color=MUTED)
            return
        st = monitor.status()
        lines = [f"Watching {len(st['folders'])} folder(s)",
                 f"Waiting to settle: {st['pending']}   Scanned: {st['scanned']}   "
                 f"Skipped (unchanged): {st['duplicates']}   Dropped (queue full): {st['dropped']}"]
        if st["paused"]:
            lines.insert(0, f"PAUSED: {st['paused']}. Files are retried automatically.")
            self.retry_button.pack(side="left")
        else:
            self.retry_button.pack_forget()
        self.status_label.configure(text="\n".join(lines),
                                    text_color=RED_SOFT if st["paused"] else ACCENT_SOFT)

    # -- actions ---------------------------------------------------------------------
    def _save(self, folders):
        self.app.settings["watch_dirs"] = folders
        if self.app.monitor is not None and self.app.monitor.running:
            self.app.start_monitor()                 # restart with the new folders
        self._refresh_folders()
        self.refresh_status()

    def _add(self):
        folder = self.ask_folder()
        if folder and folder not in self.app.settings["watch_dirs"]:
            self._save(list(self.app.settings["watch_dirs"]) + [folder])

    def _remove(self, folder):
        self._save([f for f in self.app.settings["watch_dirs"] if f != folder])

    def _toggle(self):
        if self.app.monitor is not None and self.app.monitor.running:
            self.app.stop_monitor()
        else:
            message = self.app.start_monitor()
            if message:
                self.status_label.configure(text=message, text_color=AMBER_SOFT)
                return
        self.refresh_status()

    def _retry(self):
        if self.app.monitor is not None:
            self.app.monitor.resume()
        self.refresh_status()
