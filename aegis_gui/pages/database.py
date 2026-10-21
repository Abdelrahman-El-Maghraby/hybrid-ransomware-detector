"""Database page: the malware-hash dataset."""

import os

from aegis_gui.common import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_SOFT,
    AMBER_SOFT,
    MUTED,
    ON_ACCENT,
    RED_SOFT,
    RS,
    TEXT,
    ctk,
    filedialog,
)
from aegis_gui.pages.base import BasePage
from aegis_gui.widgets import Section


class DatabasePage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        ctk.CTkLabel(self, text="Database", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(self, text="Local malware-hash dataset used by detection layer 1.",
                     font=app.font_small, text_color=MUTED, anchor="w").pack(fill="x")

        sec = Section(self, "Status", app)
        sec.pack(fill="x", pady=(14, 0))
        self.path_label = ctk.CTkLabel(sec.body, text="", font=app.font_mono_small,
                                       text_color=MUTED, anchor="w", wraplength=720,
                                       justify="left")
        self.path_label.pack(fill="x", padx=14, pady=(12, 2))
        self.status_label = ctk.CTkLabel(sec.body, text="", font=app.font_ui,
                                         text_color=TEXT, anchor="w")
        self.status_label.pack(fill="x", padx=14, pady=(0, 12))

        sec = Section(self, "Import", app)
        sec.pack(fill="x", pady=(14, 0))
        ctk.CTkLabel(sec.body,
                     text="Import a CSV with at least the columns FileName, md5Hash and "
                          "Benign (Benign = 0 marks a malicious entry). Public datasets "
                          "are available on Kaggle.",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 6))
        ctk.CTkButton(sec.body, text="Import dataset (.csv)…", height=34,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ON_ACCENT,
                      font=app.font_bold, command=self._import).pack(anchor="w",
                                                                     padx=14, pady=(0, 8))
        self.import_label = ctk.CTkLabel(sec.body, text="", font=app.font_small,
                                         text_color=MUTED, anchor="w", wraplength=720,
                                         justify="left")
        self.import_label.pack(fill="x", padx=14, pady=(0, 12))

    def on_show(self):
        scanner = self.app.scanner
        self.path_label.configure(text=scanner.kaggle_db_path)
        count = len(scanner.hash_database)
        if count:
            self.status_label.configure(
                text=f"Loaded — {count:,} malicious hashes in memory.",
                text_color=ACCENT_SOFT)
        elif os.path.exists(scanner.kaggle_db_path):
            self.status_label.configure(
                text="File present but no malicious rows were loaded — check the Benign column.",
                text_color=AMBER_SOFT)
        else:
            self.status_label.configure(
                text="Not imported — layer 1 is inactive until a dataset is imported.",
                text_color=AMBER_SOFT)

    def _import(self):
        chosen = filedialog.askopenfilename(title="Choose a malware-hash CSV",
                                            filetypes=[("CSV files", "*.csv"),
                                                       ("All files", "*.*")])
        if not chosen:
            return
        outcome = RS.import_hash_database(chosen)
        if outcome["ok"]:
            self.app.scanner.hash_database = self.app.scanner._load_kaggle_database()
            self.import_label.configure(
                text=f"Imported {outcome['entries']:,} entries — "
                     f"{len(self.app.scanner.hash_database):,} malicious hashes loaded.",
                text_color=ACCENT_SOFT)
        else:
            self.import_label.configure(text=f"Import failed: {outcome['message']}",
                                        text_color=RED_SOFT)
        self.on_show()
        self.app.pages["dashboard"].refresh_cards()
