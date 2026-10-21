"""Protection page: canaries, automatic quarantine, vault."""

import os

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
    RS,
    TEXT,
    ctk,
    messagebox,
    set_key,
)
from aegis_gui.pages.base import BasePage
from aegis_gui.widgets import Section

AUTO_QUARANTINE_CHOICES = {"Off": "", "High and above": "high", "Critical only": "critical"}


class ProtectionPage(BasePage):
    """Canary tripwires, the encrypted quarantine vault, and the result cache."""

    def __init__(self, app):
        super().__init__(app)
        outer = ctk.CTkScrollableFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True)
        ctk.CTkLabel(outer, text="Protection", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(outer, text="Tripwires that catch ransomware in the act, and an "
                                 "encrypted vault for anything you quarantine.",
                     font=app.font_small, text_color=MUTED, anchor="w").pack(fill="x")

        # -- canaries -------------------------------------------------------------
        sec = Section(outer, "Canary tripwires", app)
        sec.pack(fill="x", pady=(14, 0))
        minutes = int(app.scanner.config.get("canary_check_minutes", 5))
        ctk.CTkLabel(sec.body,
                     text="Decoy documents (named !000_…) planted in your monitored folders. "
                          "Nobody should ever open or change them: if one is deleted, "
                          "rewritten, renamed or encrypted, ransomware is most likely running "
                          "right now. "
                          + ("They are watched in real time, and also checked every "
                             f"{minutes} minute(s), " if RS.WATCHDOG_AVAILABLE else
                             f"They are checked every {minutes} minute(s) (install "
                             "'watchdog' for real-time watching) ")
                          + "while this window is open, and by the background scanner "
                            "(--background).",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 4))
        self.canary_status = ctk.CTkLabel(sec.body, text="", font=app.font_bold, anchor="w",
                                          wraplength=720, justify="left")
        self.canary_status.pack(fill="x", padx=14, pady=(2, 6))
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 6))
        ctk.CTkButton(row, text="Deploy to monitored folders", height=32, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, text_color=ON_ACCENT, font=app.font_bold,
                      command=self._deploy).pack(side="left")
        ctk.CTkButton(row, text="Verify now", height=32, font=app.font_ui,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=app.check_canaries_now).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Remove canaries", height=32, font=app.font_ui,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=MUTED,
                      command=self._remove).pack(side="left")
        self.canary_list = ctk.CTkTextbox(sec.body, height=96, fg_color=BG, text_color=MUTED,
                                          font=app.font_mono_small, wrap="none",
                                          border_width=0)
        self.canary_list.pack(fill="x", padx=14, pady=(4, 12))

        # -- quarantine -------------------------------------------------------------
        sec = Section(outer, "Quarantine vault", app)
        sec.pack(fill="x", pady=(14, 0))
        ctk.CTkLabel(sec.body,
                     text="Quarantined files are encrypted with AES-256-GCM (per-file keys, "
                          "authenticated chunks) and removed from their folder only after the "
                          "encrypted copy has been verified. Restore puts the original back.",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 6))
        auto_row = ctk.CTkFrame(sec.body, fg_color="transparent")
        auto_row.pack(fill="x", padx=14, pady=(0, 8))
        ctk.CTkLabel(auto_row, text="Quarantine automatically after a scan:",
                     font=app.font_ui, text_color=TEXT).pack(side="left")
        current = str(app.scanner.config.get("auto_quarantine") or "")
        label = next((k for k, v in AUTO_QUARANTINE_CHOICES.items() if v == current), "Off")
        self.auto_var = ctk.StringVar(value=label)
        ctk.CTkSegmentedButton(auto_row, values=list(AUTO_QUARANTINE_CHOICES),
                               variable=self.auto_var, command=self._auto_changed,
                               selected_color=ACCENT, selected_hover_color=ACCENT_HOVER,
                               font=app.font_small).pack(side="left", padx=10)
        self.vault_rows = ctk.CTkFrame(sec.body, fg_color="transparent")
        self.vault_rows.pack(fill="x", padx=10, pady=(2, 12))

        # -- cache ------------------------------------------------------------------
        sec = Section(outer, "Result cache", app)
        sec.pack(fill="x", pady=(14, 24))
        crow = ctk.CTkFrame(sec.body, fg_color="transparent")
        crow.pack(fill="x", padx=14, pady=12)
        self.cache_label = ctk.CTkLabel(crow, text="", font=app.font_small, text_color=MUTED,
                                        anchor="w", justify="left", wraplength=560)
        self.cache_label.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(crow, text="Clear cache", width=110, height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self._clear_cache).pack(side="right")

    # -- refresh -------------------------------------------------------------------
    def on_show(self):
        self._refresh_canaries()
        self._refresh_vault()
        self._refresh_cache()

    def _refresh_canaries(self):
        entries = self.app.scanner.canaries.entries()
        report = self.app.last_canary_report
        if not entries:
            text, color = "No canaries deployed yet.", AMBER_SOFT
        elif report is not None and report.triggered:
            text, color = report.summary(), RED
        elif report is not None:
            text = f"{len(entries)} canaries armed — last check {report.checked_at}: all intact."
            color = ACCENT_SOFT
        else:
            text, color = f"{len(entries)} canaries armed — first check pending.", ACCENT_SOFT
        self.canary_status.configure(text=text, text_color=color)
        lines = [e["path"] for e in entries] or ["—"]
        if report is not None and report.triggered:
            lines += [""] + [f"[{f.status}] {f.path}" for f in report.findings]
        self.canary_list.configure(state="normal")
        self.canary_list.delete("1.0", "end")
        self.canary_list.insert("1.0", "\n".join(lines))
        self.canary_list.configure(state="disabled")

    def _refresh_vault(self):
        for child in self.vault_rows.winfo_children():
            child.destroy()
        try:
            items = self.app.scanner.quarantine_vault.list()
        except Exception as e:
            ctk.CTkLabel(self.vault_rows, text=f"Unavailable: {e}", font=self.app.font_small,
                         text_color=AMBER_SOFT, anchor="w").pack(fill="x", padx=4)
            return
        if not items:
            ctk.CTkLabel(self.vault_rows, text="The vault is empty.", font=self.app.font_small,
                         text_color=MUTED, anchor="w").pack(fill="x", padx=4, pady=2)
            return
        for item in items[:100]:
            row = ctk.CTkFrame(self.vault_rows, fg_color=BG, corner_radius=8)
            row.pack(fill="x", pady=3)
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=10, pady=6)
            extra = item.get("extra") or {}
            verdict = f"  ·  {extra['verdict']}" if extra.get("verdict") else ""
            ctk.CTkLabel(info, text=f"{item.get('id')}  ·  {item.get('quarantined_at', '?')}"
                                    f"{verdict}",
                         font=self.app.font_mono_small, text_color=TEXT,
                         anchor="w").pack(fill="x")
            ctk.CTkLabel(info, text=f"{item.get('original_path', '?')}\n{item.get('reason', '')}",
                         font=self.app.font_small, text_color=MUTED, anchor="w",
                         justify="left", wraplength=540).pack(fill="x")
            ctk.CTkButton(row, text="Delete", width=70, height=28, font=self.app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=MUTED,
                          command=lambda i=item["id"]: self._delete(i)).pack(side="right",
                                                                            padx=(4, 10))
            ctk.CTkButton(row, text="Restore", width=80, height=28, font=self.app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=BLUE,
                          command=lambda i=item["id"]: self._restore(i)).pack(side="right")

    def _refresh_cache(self):
        cache = self.app.scanner.cache
        if cache is None or not cache.enabled:
            self.cache_label.configure(text="Cache disabled.")
            return
        st = cache.stats()
        self.cache_label.configure(
            text=f"{st['entries']} cached VirusTotal/LLM answer(s) "
                 f"({st['expired']} expired) · {st['hits']} hit(s) this session\n{st['path']}")

    # -- actions ---------------------------------------------------------------------
    def _deploy(self):
        dirs = [d for d in self.app.settings["scan_directories"] if os.path.isdir(d)]
        if not dirs:
            messagebox.showinfo("No folders", "Add a monitored directory on the Scan page first.")
            return
        created = self.app.scanner.deploy_canaries(dirs)
        self.app.gui_log.info(f"Deployed {len(created)} canary file(s) from GUI.")
        messagebox.showinfo("Canaries deployed",
                            f"{len(created)} new canary file(s) planted in {len(dirs)} folder(s).")
        self.app.check_canaries_now()

    def _remove(self):
        if not messagebox.askyesno("Remove canaries", "Delete every canary file this tool planted?"):
            return
        removed = self.app.scanner.remove_canaries()
        self.app.last_canary_report = None
        self.app.gui_log.info(f"Removed {removed} canary file(s) from GUI.")
        self.app.refresh_protection_views()
        self.on_show()

    def _restore(self, item_id: str, confirm: bool = True):
        if confirm and not messagebox.askyesno(
                "Restore file", "Decrypt this item and put it back where it was?\n\n"
                                "Only do this if you are sure it is a false positive."):
            return
        try:
            dest = self.app.scanner.quarantine_vault.restore(item_id)
        except Exception as e:
            messagebox.showerror("Restore failed", str(e))
            return
        self.app.gui_log.warning(f"Restored vault item {item_id} -> {dest}")
        if confirm:
            messagebox.showinfo("Restored", f"Restored to:\n{dest}")
        self.app.refresh_protection_views()
        self.on_show()

    def _delete(self, item_id: str, confirm: bool = True):
        if confirm and not messagebox.askyesno("Delete permanently",
                                               "Permanently delete this quarantined item?"):
            return
        try:
            self.app.scanner.quarantine_vault.delete(item_id)
        except Exception as e:
            messagebox.showerror("Delete failed", str(e))
            return
        self.app.refresh_protection_views()
        self.on_show()

    def _auto_changed(self, label: str):
        value = AUTO_QUARANTINE_CHOICES.get(label, "")
        try:
            ENV_FILE.touch(exist_ok=True)
            set_key(str(ENV_FILE), "AUTO_QUARANTINE", value)
        except Exception as e:
            self.app.gui_log.error(f"Could not save AUTO_QUARANTINE: {e}")
        RS.CONFIG["auto_quarantine"] = value
        self.app.scanner.config["auto_quarantine"] = value
        self.app.gui_log.info(f"Automatic quarantine set to: {label}")

    def _clear_cache(self):
        if self.app.scanner.cache is not None:
            removed = self.app.scanner.cache.clear()
            self.app.gui_log.info(f"Cleared {removed} cached result(s).")
        self._refresh_cache()
