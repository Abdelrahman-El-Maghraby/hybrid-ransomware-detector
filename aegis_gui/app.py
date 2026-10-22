"""The main window: sidebar, pages, status bar, timers."""

import json
import logging
import platform
import queue
import threading

from aegis_gui.common import (
    ACCENT_DIM,
    ACCENT_SOFT,
    APP_VERSION,
    BG,
    MUTED,
    PANEL,
    PANEL_2,
    RED_SOFT,
    RS,
    SELECT,
    TEXT,
    Path,
    ctk,
    datetime,
    messagebox,
    timedelta,
    tkfont,
    ttk,
)
from aegis_gui.formatting import humanize_delta, mono_family
from aegis_gui.pages.dashboard import DashboardPage
from aegis_gui.pages.database import DatabasePage
from aegis_gui.pages.logs import LogsPage
from aegis_gui.pages.protection import ProtectionPage
from aegis_gui.pages.reports import ReportsPage
from aegis_gui.pages.scan import ScanPage
from aegis_gui.pages.settings import SettingsPage
from aegis_gui.state import QueueLogHandler, ScanController, SettingsStore

# --- Application ---------------------------------------------------------------------

class App(ctk.CTk):
    NAV = [("dashboard", "Dashboard"), ("scan", "Scan"), ("protection", "Protection"),
           ("reports", "Reports"), ("database", "Database"), ("logs", "Logs"),
           ("settings", "Settings")]

    def __init__(self):
        ctk.set_appearance_mode("dark")
        super().__init__(fg_color=BG)
        self.title("Aegis Sentinel")
        self.geometry("1180x760")
        self.minsize(1024, 660)

        # fonts (must be created after the root window exists)
        default_family = tkfont.nametofont("TkDefaultFont").actual("family")
        self.font_ui = ctk.CTkFont(size=13)
        self.font_bold = ctk.CTkFont(size=13, weight="bold")
        self.font_small = ctk.CTkFont(size=11)
        self.font_h1 = ctk.CTkFont(size=20, weight="bold")
        self.font_h2 = ctk.CTkFont(size=16, weight="bold")
        self.font_card = ctk.CTkFont(size=17, weight="bold")
        self.font_mono = ctk.CTkFont(family=mono_family(), size=13)
        self.font_mono_small = ctk.CTkFont(family=mono_family(), size=11)

        # ttk style for the results table
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("RD.Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=TEXT, bordercolor=PANEL, borderwidth=0,
                        lightcolor=PANEL, darkcolor=PANEL, relief="flat",
                        rowheight=34, font=(mono_family(), 11))
        style.configure("RD.Treeview.Heading", background=PANEL, foreground=MUTED,
                        bordercolor=PANEL, borderwidth=0, relief="flat",
                        font=(default_family, 10))
        style.map("RD.Treeview", background=[("selected", SELECT)],
                  foreground=[("selected", TEXT)])
        style.map("RD.Treeview.Heading", background=[("active", PANEL)])

        # state
        self.settings = SettingsStore()
        self.scanner = RS.RansomwareScanner(self._build_config())
        self.bus = queue.Queue()
        self.log_queue = queue.Queue()
        self.controller = ScanController(self.bus)
        self.next_scan_at = None
        self.last_scan_at = None
        self._scan_seen_progress = False
        self.last_canary_report = None
        self._canary_check_running = False
        self._alerted_signature = None
        # Real-time tripwire watching (watchdog thread -> bus -> UI thread).
        self.canary_watcher = RS.CanaryWatcher(self.scanner.canaries,
                                               lambda: self.bus.put(("canary_event",)))

        log_handler = QueueLogHandler(self.log_queue)
        logging.getLogger("RansomwareScanner").addHandler(log_handler)
        self.gui_log = logging.getLogger("RansomwareScanner.GUI")

        # layout: sidebar | content, status bar at the bottom
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        self.content = ctk.CTkFrame(self, fg_color=BG)
        self.content.grid(row=0, column=1, sticky="nsew", padx=18, pady=(16, 8))

        self._build_status_bar()

        self.pages = {
            "dashboard": DashboardPage(self),
            "scan": ScanPage(self),
            "protection": ProtectionPage(self),
            "reports": ReportsPage(self),
            "database": DatabasePage(self),
            "logs": LogsPage(self),
            "settings": SettingsPage(self),
        }
        self.current_page = None
        self.show_page("dashboard")

        self._bootstrap_last_report()
        self.reset_schedule()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(120, self._poll)
        self.after(1000, self._tick)
        self.after(4000, self._canary_tick)
        self.gui_log.info(f"GUI started (v{APP_VERSION}) on {platform.system()}")

    # -- construction helpers ---------------------------------------------------------

    def _build_config(self) -> dict:
        config = dict(RS.CONFIG)
        config["scan_directories"] = list(self.settings["scan_directories"])
        config["file_extensions"] = list(self.settings["file_extensions"])
        config["scan_interval_hours"] = int(self.settings["scan_interval_hours"])
        return config

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, fg_color=BG, width=212, corner_radius=0,
                               border_width=0)
        sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=16, pady=(18, 14))
        ctk.CTkLabel(brand, text="Aegis Sentinel", font=self.font_h2,
                     text_color=TEXT, anchor="w").pack(fill="x")
        ctk.CTkLabel(brand, text=f"hybrid ransomware detector · v{APP_VERSION}",
                     font=self.font_small, text_color=MUTED, anchor="w").pack(fill="x")

        self.nav_buttons = {}
        for key, label in self.NAV:
            button = ctk.CTkButton(sidebar, text=label, anchor="w", height=36,
                                   corner_radius=8, fg_color="transparent",
                                   hover_color=PANEL_2, text_color=MUTED,
                                   font=self.font_ui,
                                   command=lambda k=key: self.show_page(k))
            button.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = button

        self.protection_label = ctk.CTkLabel(sidebar, text="", font=self.font_small,
                                             anchor="w")
        self.protection_label.pack(side="bottom", fill="x", padx=20, pady=14)

    def _build_status_bar(self):
        bar = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, height=30,
                           border_width=0)
        bar.grid(row=1, column=1, sticky="sew", padx=0, pady=0)
        bar.grid_propagate(False)
        self.status_label = ctk.CTkLabel(bar, text="Ready.", font=self.font_mono_small,
                                         text_color=MUTED, anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True, padx=14)

    def _bootstrap_last_report(self):
        """Populate the dashboard from the most recent JSON report, if any."""
        try:
            report_dir = Path(self.scanner.report_dir)
            reports = sorted(report_dir.glob("ransomware_scan_*.json"),
                             key=lambda p: p.stat().st_mtime, reverse=True)
            if not reports:
                self.pages["dashboard"].load_results([], "Latest results")
                return
            latest = reports[0]
            self.last_scan_at = datetime.fromtimestamp(latest.stat().st_mtime)
            results = json.loads(latest.read_text(encoding="utf-8"))
            self.pages["dashboard"].load_results(results, f"Latest results — {latest.name}")
        except Exception:
            self.gui_log.exception("Could not load the latest report")
            self.pages["dashboard"].load_results([], "Latest results")

    # -- navigation ----------------------------------------------------------------------

    def show_page(self, key: str):
        if self.current_page is not None:
            self.pages[self.current_page].pack_forget()
        self.current_page = key
        page = self.pages[key]
        page.pack(fill="both", expand=True)
        page.on_show()
        for nav_key, button in self.nav_buttons.items():
            active = nav_key == key
            button.configure(fg_color=ACCENT_DIM if active else "transparent",
                             text_color=ACCENT_SOFT if active else MUTED,
                             font=self.font_bold if active else self.font_ui)

    # -- scanning ------------------------------------------------------------------------

    def start_full_scan(self):
        self.start_scan(mode="all")

    def start_scan(self, mode="all", target=None):
        if self.controller.running:
            return
        if mode == "all" and not self.settings["scan_directories"]:
            messagebox.showinfo("No directories",
                                "Add at least one directory on the Scan page first.")
            return
        dashboard = self.pages["dashboard"]
        dashboard.clear_results("Scan in progress…")
        self._scan_seen_progress = False
        dashboard.progress_bar.configure(mode="indeterminate")
        dashboard.progress_bar.start()
        dashboard.progress_file.configure(text="Collecting files…", text_color=MUTED)
        dashboard.progress_count.configure(text="")
        self._set_running_ui(True)
        started = self.controller.start(self.scanner, mode, target)
        if started:
            self.gui_log.info(f"Scan started from GUI (mode={mode})")
            if self.current_page != "dashboard":
                self.show_page("dashboard")

    def stop_scan(self):
        if self.controller.running:
            self.controller.stop()
            self.status_label.configure(text="Stopping after the current file…")

    def _set_running_ui(self, running: bool):
        dashboard = self.pages["dashboard"]
        if running:
            dashboard.scan_button.pack_forget()
            dashboard.stop_button.pack(side="right")
        else:
            dashboard.stop_button.pack_forget()
            dashboard.scan_button.pack(side="right")
        self.pages["scan"].set_running(running)

    # -- event bus / polling ------------------------------------------------------------------

    def _poll(self):
        try:
            while True:
                event = self.bus.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.status_label.configure(text=line[:180])
                if self.current_page == "logs":
                    self.pages["logs"].append(line)
        except queue.Empty:
            pass
        self.after(120, self._poll)

    def _handle_event(self, event):
        kind = event[0]
        dashboard = self.pages["dashboard"]
        if kind == "progress":
            _, done, total, path, result = event
            if not self._scan_seen_progress:
                self._scan_seen_progress = True
                dashboard.progress_bar.stop()
                dashboard.progress_bar.configure(mode="determinate")
            dashboard.progress_file.configure(text=f"Scanning {path}", text_color=TEXT)
            dashboard.progress_count.configure(text=f"{done} / {total} files")
            dashboard.progress_bar.set(done / total if total else 0)
            if result is not None:
                dashboard.add_result(result)
        elif kind == "scan_done":
            _, results, report_text, cancelled = event
            dashboard.progress_bar.stop()
            dashboard.progress_bar.configure(mode="determinate")
            dashboard.progress_bar.set(1 if results and not cancelled else 0)
            self._set_running_ui(False)
            self.last_scan_at = datetime.now()
            self.reset_schedule()
            malicious = sum(1 for r in results if r.get("is_malicious"))
            if cancelled:
                summary = f"Scan stopped — {len(results)} file(s) scanned, {malicious} malicious."
                dashboard.results_title.configure(text="Latest results (partial — scan stopped)")
            elif not results:
                summary = "Scan finished — no matching files were found."
                dashboard.results_title.configure(text="Latest results")
                dashboard.load_results([], "Latest results")
            else:
                summary = (f"Scan complete — {len(results)} file(s), {malicious} malicious. "
                           f"Report saved to {Path(self.scanner.report_dir).name}/")
                dashboard.results_title.configure(text="Latest results")
            dashboard.progress_file.configure(text=summary,
                                              text_color=RED_SOFT if malicious else ACCENT_SOFT)
            dashboard.progress_count.configure(text="")
            dashboard.refresh_meta()
        elif kind == "scan_error":
            self._set_running_ui(False)
            dashboard.progress_bar.stop()
            dashboard.progress_bar.configure(mode="determinate")
            dashboard.progress_bar.set(0)
            dashboard.progress_file.configure(text=f"Scan failed: {event[1]}",
                                              text_color=RED_SOFT)
        elif kind == "autostart_done":
            self.pages["settings"].autostart_finished(event[1], event[2])
        elif kind == "canary_report":
            self._canary_check_running = False
            self._on_canary_report(event[1])
        elif kind == "canary_event":
            self.check_canaries_now()

    # -- canary tripwires ---------------------------------------------------------------------

    def check_canaries_now(self):
        """Verify canaries in a worker thread; the result arrives on the bus."""
        self.canary_watcher.refresh()          # follows canaries deployed / removed
        if self._canary_check_running or not self.scanner.canaries.entries():
            self.refresh_protection_views()
            return
        self._canary_check_running = True

        def work():
            try:
                report = self.scanner.check_canaries(notify=True)
            except Exception:
                self.gui_log.exception("Canary check failed")
                report = None
            self.bus.put(("canary_report", report))

        threading.Thread(target=work, daemon=True).start()

    def _canary_tick(self):
        self.check_canaries_now()
        minutes = max(1, int(self.scanner.config.get("canary_check_minutes", 5)))
        self.after(minutes * 60 * 1000, self._canary_tick)

    def _on_canary_report(self, report):
        if report is None:
            return
        self.last_canary_report = report
        self.refresh_protection_views()
        if report.triggered:
            signature = tuple(sorted((f.path, f.status) for f in report.findings))
            self.status_label.configure(text=f"CANARY: {report.summary()}")
            if signature != self._alerted_signature:
                self._alerted_signature = signature
                details = "\n".join(f"[{f.status}] {f.path}" for f in report.findings[:8])
                messagebox.showwarning(
                    "Ransomware tripwire triggered",
                    f"{report.summary()}\n\n{details}\n\nDisconnect from the network and "
                    "investigate running processes before rebooting.")
        else:
            self._alerted_signature = None

    def refresh_protection_views(self):
        try:
            self.pages["dashboard"].refresh_cards()
            if self.current_page == "protection":
                self.pages["protection"].on_show()
        except Exception:
            self.gui_log.exception("Could not refresh protection views")

    # -- schedule -----------------------------------------------------------------------------

    def reset_schedule(self):
        if self.settings["schedule_enabled"]:
            hours = int(self.settings["scan_interval_hours"])
            self.next_scan_at = datetime.now() + timedelta(hours=hours)
        else:
            self.next_scan_at = None
        self._refresh_protection()
        self.pages["dashboard"].refresh_meta()

    def _tick(self):
        if (self.next_scan_at is not None and datetime.now() >= self.next_scan_at
                and not self.controller.running):
            self.gui_log.info("Scheduled scan triggered.")
            self.start_scan(mode="all")
        if self.current_page == "dashboard":
            self.pages["dashboard"].refresh_meta()
        self.after(1000, self._tick)

    def _refresh_protection(self):
        enabled = self.settings["schedule_enabled"]
        self.protection_label.configure(
            text=("●  Protection on" if enabled else "○  Protection off"),
            text_color=ACCENT_SOFT if enabled else MUTED)

    def last_scan_text(self) -> str:
        return self.last_scan_at.strftime("%H:%M") if self.last_scan_at else "never"

    def next_scan_text(self) -> str:
        if self.controller.running:
            return "scan running now"
        if self.next_scan_at is None:
            return "scheduled scans off"
        delta = (self.next_scan_at - datetime.now()).total_seconds()
        return (f"next scheduled in {humanize_delta(delta)} "
                f"({self.next_scan_at.strftime('%H:%M')})")

    # -- shutdown ---------------------------------------------------------------------------------

    def _on_close(self):
        if self.controller.running:
            if not messagebox.askyesno("Scan in progress",
                                       "A scan is still running. Stop it and exit?"):
                return
            self.controller.stop()
        self.gui_log.info("GUI closed.")
        self.destroy()

    def destroy(self):
        watcher = getattr(self, "canary_watcher", None)
        if watcher is not None:
            watcher.stop()
        super().destroy()


def main():
    app = App()
    app.mainloop()
