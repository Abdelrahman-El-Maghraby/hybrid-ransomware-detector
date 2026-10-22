"""Scan page: monitored folders, file types, run / stop."""

import os

from aegis_gui.common import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_SOFT,
    AMBER_SOFT,
    BORDER_2,
    MUTED,
    ON_ACCENT,
    PANEL_2,
    RED,
    RED_SOFT,
    RS,
    TEXT,
    ctk,
    filedialog,
)
from aegis_gui.pages.base import BasePage
from aegis_gui.widgets import Section


class ScanPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        ctk.CTkLabel(self, text="Scan", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(self, text="Choose what to scan. Results appear on the Dashboard.",
                     font=app.font_small, text_color=MUTED, anchor="w").pack(fill="x")

        sec = Section(self, "Monitored directories", app)
        sec.pack(fill="x", pady=(14, 0))
        self.dir_list = ctk.CTkFrame(sec.body, fg_color="transparent")
        self.dir_list.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkButton(sec.body, text="+  Add directory…", height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=ACCENT_SOFT,
                      command=self._add_directory).pack(anchor="w", padx=14, pady=(0, 12))

        sec = Section(self, "File types", app)
        sec.pack(fill="x", pady=(14, 0))
        ext_row = ctk.CTkFrame(sec.body, fg_color="transparent")
        ext_row.pack(fill="x", padx=14, pady=12)
        self.ext_vars = {}
        for i, ext in enumerate(RS.SUPPORTED_EXTENSIONS):
            var = ctk.BooleanVar(value=ext in app.settings["file_extensions"])
            self.ext_vars[ext] = var
            ctk.CTkCheckBox(ext_row, text=ext, variable=var, font=app.font_ui, width=90,
                            text_color=TEXT, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                            border_color=BORDER_2, checkmark_color=ON_ACCENT,
                            command=self._extensions_changed
                            ).grid(row=i // 7, column=i % 7, sticky="w", pady=3)

        sec = Section(self, "Run", app)
        sec.pack(fill="x", pady=(14, 0))
        run_row = ctk.CTkFrame(sec.body, fg_color="transparent")
        run_row.pack(fill="x", padx=14, pady=(12, 6))
        self.scan_button = ctk.CTkButton(run_row, text="Scan all directories", height=34,
                                         fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                         text_color=ON_ACCENT, font=app.font_bold,
                                         command=app.start_full_scan)
        self.scan_button.pack(side="left")
        ctk.CTkButton(run_row, text="Scan a single file…", height=34, font=app.font_ui,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self._scan_single_file).pack(side="left", padx=10)
        self.stop_button = ctk.CTkButton(run_row, text="Stop", width=86, height=34,
                                         fg_color="transparent", hover_color=PANEL_2,
                                         border_width=1, border_color=RED,
                                         text_color=RED_SOFT, font=app.font_bold,
                                         state="disabled", command=app.stop_scan)
        self.stop_button.pack(side="left")
        ctk.CTkLabel(sec.body,
                     text="VirusTotal is queried by hash only (uploads are opt-in in Settings) and "
                          "paced to the free API quota, so large first scans take a while; "
                          "unchanged files are answered from the cache afterwards. "
                          "“Stop” takes effect after the file currently being scanned.",
                     font=app.font_small, text_color=MUTED, anchor="w", justify="left",
                     wraplength=720).pack(fill="x", padx=14, pady=(0, 12))

        self.refresh_directories()

    def _extensions_changed(self):
        selected = [ext for ext, var in self.ext_vars.items() if var.get()]
        if not selected:
            self.ext_vars[".pdf"].set(True)
            selected = [".pdf"]
        self.app.settings["file_extensions"] = selected
        self.app.scanner.file_extensions = selected

    def refresh_directories(self):
        for child in self.dir_list.winfo_children():
            child.destroy()
        directories = self.app.settings["scan_directories"]
        if not directories:
            ctk.CTkLabel(self.dir_list, text="No directories configured yet.",
                         font=self.app.font_small, text_color=AMBER_SOFT,
                         anchor="w").pack(fill="x", padx=4, pady=4)
        for directory in directories:
            row = ctk.CTkFrame(self.dir_list, fg_color="transparent")
            row.pack(fill="x", pady=2)
            exists = os.path.isdir(directory)
            ctk.CTkLabel(row, text=directory, font=self.app.font_mono_small,
                         text_color=TEXT if exists else AMBER_SOFT,
                         anchor="w").pack(side="left", fill="x", expand=True, padx=(4, 8))
            if not exists:
                ctk.CTkLabel(row, text="missing", font=self.app.font_small,
                             text_color=AMBER_SOFT).pack(side="left", padx=(0, 8))
            ctk.CTkButton(row, text="Remove", width=70, height=26, font=self.app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=MUTED,
                          command=lambda d=directory: self._remove_directory(d)
                          ).pack(side="right")

    def _add_directory(self):
        chosen = filedialog.askdirectory(title="Choose a directory to monitor")
        if chosen:
            directories = list(self.app.settings["scan_directories"])
            if chosen not in directories:
                directories.append(chosen)
                self.app.settings["scan_directories"] = directories
                self.app.scanner.scan_dirs = directories
            self.refresh_directories()

    def _remove_directory(self, directory):
        directories = [d for d in self.app.settings["scan_directories"] if d != directory]
        self.app.settings["scan_directories"] = directories
        self.app.scanner.scan_dirs = directories
        self.refresh_directories()

    def _scan_single_file(self):
        chosen = filedialog.askopenfilename(
            title="Choose a document to scan",
            filetypes=[("Documents & archives",
                        " ".join("*" + e for e in RS.SUPPORTED_EXTENSIONS)),
                       ("All files", "*.*")])
        if chosen:
            self.app.start_scan(mode="file", target=chosen)

    def set_running(self, running: bool):
        self.scan_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
