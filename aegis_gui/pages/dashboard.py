"""Dashboard: engine status, scan progress and latest results."""

import os

from aegis_gui.common import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_SOFT,
    BLUE,
    BORDER,
    BORDER_2,
    MUTED,
    ON_ACCENT,
    PANEL,
    PANEL_2,
    RED,
    RED_SOFT,
    RS,
    TEXT,
    ctk,
    ttk,
)
from aegis_gui.detail import DetailWindow
from aegis_gui.formatting import (
    VERDICT_COLORS,
    first_gap,
    open_path,
    result_risk,
    result_verdict,
    top_reasons,
    verdict_text,
)
from aegis_gui.pages.base import BasePage
from aegis_gui.widgets import StatCard


class DashboardPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        self.row_results = {}

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x")
        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(left, text="Dashboard", font=app.font_h1,
                     text_color=TEXT, anchor="w").pack(fill="x")
        self.meta_label = ctk.CTkLabel(left, text="", font=app.font_small,
                                       text_color=MUTED, anchor="w")
        self.meta_label.pack(fill="x")

        self.stop_button = ctk.CTkButton(header, text="Stop", width=86, height=34,
                                         fg_color="transparent", hover_color=PANEL_2,
                                         border_width=1, border_color=RED,
                                         text_color=RED_SOFT, font=app.font_bold,
                                         command=app.stop_scan)
        self.scan_button = ctk.CTkButton(header, text="Scan now", width=112, height=34,
                                         fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                         text_color=ON_ACCENT, font=app.font_bold,
                                         command=app.start_full_scan)
        self.scan_button.pack(side="right")

        cards = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8,
                             border_width=1, border_color=BORDER)
        cards.app = app
        cards.pack(fill="x", pady=(14, 0))
        cards.grid_columnconfigure((0, 1, 2), weight=1, uniform="cards")
        # Row 0 — technical layers (exact + structural)
        self.card_db = StatCard(cards, "Hash database")
        self.card_db.grid(row=0, column=0, sticky="nsew", pady=(4, 0))
        self.card_fuzzy = StatCard(cards, "Fuzzy hashing")
        self.card_fuzzy.grid(row=0, column=1, sticky="nsew", pady=(4, 0))
        self.card_macro = StatCard(cards, "Macro analysis")
        self.card_macro.grid(row=0, column=2, sticky="nsew", pady=(4, 0))
        # Row 1 — structural / reputation / semantic
        self.card_yara = StatCard(cards, "YARA rules")
        self.card_yara.grid(row=1, column=0, sticky="nsew")
        self.card_vt = StatCard(cards, "VirusTotal")
        self.card_vt.grid(row=1, column=1, sticky="nsew")
        self.card_ai = StatCard(cards, "LLM analysis")
        self.card_ai.grid(row=1, column=2, sticky="nsew")
        # Row 2 — v4 heuristics + host protection
        self.card_heur = StatCard(cards, "Heuristic layers")
        self.card_heur.grid(row=2, column=0, sticky="nsew", pady=(0, 4))
        self.card_canary = StatCard(cards, "Canary tripwires")
        self.card_canary.grid(row=2, column=1, sticky="nsew", pady=(0, 4))
        self.card_vault = StatCard(cards, "Quarantine vault")
        self.card_vault.grid(row=2, column=2, sticky="nsew", pady=(0, 4))

        prog = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=10,
                            border_width=1, border_color=BORDER)
        prog.pack(fill="x", pady=(12, 0))
        prow = ctk.CTkFrame(prog, fg_color="transparent")
        prow.pack(fill="x", padx=14, pady=(10, 4))
        self.progress_file = ctk.CTkLabel(prow, text="No scan running", anchor="w",
                                          font=app.font_mono_small, text_color=MUTED)
        self.progress_file.pack(side="left", fill="x", expand=True)
        self.progress_count = ctk.CTkLabel(prow, text="", anchor="e",
                                           font=app.font_small, text_color=MUTED)
        self.progress_count.pack(side="right")
        self.progress_bar = ctk.CTkProgressBar(prog, height=7, corner_radius=4,
                                               fg_color=BORDER, progress_color=ACCENT_SOFT)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=14, pady=(0, 12))

        table_frame = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=10,
                                   border_width=1, border_color=BORDER)
        table_frame.pack(fill="both", expand=True, pady=(12, 0))
        trow = ctk.CTkFrame(table_frame, fg_color="transparent")
        trow.pack(fill="x", padx=14, pady=(10, 6))
        self.results_title = ctk.CTkLabel(trow, text="Latest results", font=app.font_bold,
                                          text_color=TEXT, anchor="w")
        self.results_title.pack(side="left")
        ctk.CTkButton(trow, text="Open reports folder", height=28, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=BLUE,
                      command=lambda: open_path(app.scanner.report_dir)
                      ).pack(side="right")

        tree_holder = ctk.CTkFrame(table_frame, fg_color="transparent")
        tree_holder.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.tree = ttk.Treeview(tree_holder, columns=("file", "verdict", "risk", "why"),
                                 show="headings", style="RD.Treeview", selectmode="browse")
        for col, label, width, stretch in [("file", "File", 220, False),
                                           ("verdict", "Verdict", 90, False),
                                           ("risk", "Risk", 70, False),
                                           ("why", "Main reasons", 420, True)]:
            self.tree.heading(col, text=label, anchor="w")
            self.tree.column(col, width=width, stretch=stretch, anchor="w")
        scrollbar = ctk.CTkScrollbar(tree_holder, command=self.tree.yview,
                                     fg_color="transparent", button_color=BORDER_2,
                                     button_hover_color=MUTED)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        for verdict, color in VERDICT_COLORS.items():
            self.tree.tag_configure(verdict, foreground=color if verdict != "Clean" else TEXT)
        self.tree.bind("<Double-1>", self._open_detail)

        self.empty_label = ctk.CTkLabel(table_frame,
                                        text="No scans yet — press “Scan now” to run your first scan.",
                                        font=app.font_small, text_color=MUTED)

    # -- table helpers ---------------------------------------------------------

    def clear_results(self, title="Scan in progress…"):
        self.row_results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results_title.configure(text=title)
        self.empty_label.place_forget()

    def add_result(self, result: dict):
        verdict = result_verdict(result)
        risk = result_risk(result)
        iid = self.tree.insert("", "end", values=(
            result.get("file_name", "?"),
            verdict_text(result),
            f"{risk}",
            top_reasons(result) if verdict != "Clean" else first_gap(result),
        ), tags=(verdict if verdict in VERDICT_COLORS else "Clean",))
        self.row_results[iid] = result
        self.tree.see(iid)

    def load_results(self, results, title):
        self.clear_results(title)
        for result in sorted(results, key=lambda r: -result_risk(r)):
            self.add_result(result)
        if not results:
            self.empty_label.place(relx=0.5, rely=0.55, anchor="center")

    def _open_detail(self, _event):
        selection = self.tree.selection()
        if selection and selection[0] in self.row_results:
            DetailWindow(self.app, self.row_results[selection[0]])

    # -- refresh ----------------------------------------------------------------

    def on_show(self):
        self.refresh_cards()
        self.refresh_meta()

    def refresh_meta(self):
        app = self.app
        last = app.last_scan_text()
        nxt = app.next_scan_text()
        self.meta_label.configure(text=f"Last scan {last}  ·  {nxt}")

    def refresh_cards(self):
        app = self.app
        scanner = app.scanner
        count = len(scanner.hash_database)
        db_exists = os.path.exists(scanner.kaggle_db_path)
        if count:
            self.card_db.update_card(f"{count:,}", "Loaded", True)
        elif db_exists:
            self.card_db.update_card("0", "No malicious rows", False)
        else:
            self.card_db.update_card("—", "Not imported", False)

        # Fuzzy hashing — available libs + loaded signature count.
        if RS.FUZZY_AVAILABLE:
            sigs = len(getattr(scanner.fuzzy_hasher, "signatures", []) or [])
            self.card_fuzzy.update_card(
                f"{sigs} sig" + ("s" if sigs != 1 else ""),
                "TLSH + ssdeep" if sigs else "No signatures", bool(sigs))
        else:
            self.card_fuzzy.update_card("—", "Libs missing", False)

        # Macro analysis — availability of olevba.
        if RS.OLEVBA_AVAILABLE:
            self.card_macro.update_card("olevba", "Ready", True)
        else:
            self.card_macro.update_card("—", "Libs missing", False)

        # YARA — availability + number of compiled rule files.
        if RS.YARA_AVAILABLE:
            n_rules = getattr(scanner.yara_engine, "_rules_count", 0)
            self.card_yara.update_card(
                f"{n_rules} file" + ("s" if n_rules != 1 else ""),
                "Compiled" if n_rules else "No rules", bool(n_rules))
        else:
            self.card_yara.update_card("—", "Libs missing", False)

        vt_key = scanner.config.get("virustotal_api_key")
        self.card_vt.update_card("API v3", "Connected" if vt_key else "Key missing",
                                 bool(vt_key))

        # LLM — reflect the active backend posture (local vs cloud vs off).
        value, status, ok = self._llm_card_state(scanner)
        self.card_ai.update_card(value, status, ok)

        # Heuristics: integrity, hidden content, external links, archives,
        # e-mail and the ML classifier.
        names = ["integrity"]
        if RS.DEFUSEDXML_AVAILABLE:
            names += ["hidden", "links"]
        names += ["archives", "mail"]
        ml = getattr(scanner, "ml", None)
        if ml is not None:
            names.append("ML model" if ml.has_model else "ML rules")
        ok = RS.DEFUSEDXML_AVAILABLE
        self.card_heur.update_card(f"{len(names)} active",
                                   " · ".join(names) if ok else "install defusedxml", ok)

        # Canaries: deployed count + last verification.
        deployed = len(scanner.canaries.entries())
        report = getattr(app, "last_canary_report", None)
        if not deployed:
            self.card_canary.update_card("—", "Not deployed", False)
        elif report is not None and report.triggered:
            self.card_canary.update_card(f"{deployed} files", "TRIGGERED", False, alert=True)
        else:
            self.card_canary.update_card(f"{deployed} files",
                                         "Armed" if report is not None else "Armed · not checked",
                                         True)

        # Quarantine vault.
        try:
            items = len(scanner.quarantine_vault.list())
            self.card_vault.update_card(f"{items} item" + ("s" if items != 1 else ""),
                                        "AES-256-GCM", True)
        except Exception:
            self.card_vault.update_card("—", "install cryptography", False)

    @staticmethod
    def _llm_card_state(scanner):
        """Map the active LLM backend to (value, status, ok) for its card."""
        backend = getattr(scanner, "llm_backend", None)
        name = backend.__class__.__name__ if backend else ""
        if "Ollama" in name:
            return (getattr(backend, "model", "ollama"), "Local · OPSEC", True)
        if "OpenAI" in name:
            return (scanner.config.get("openai_model", "openai"), "Cloud", True)
        return ("—", "Disabled", False)
