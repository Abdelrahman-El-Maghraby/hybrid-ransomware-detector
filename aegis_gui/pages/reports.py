"""Reports page: past reports and canary alerts."""

import json

from aegis_gui.common import (
    BLUE,
    BORDER,
    BORDER_2,
    MUTED,
    PANEL,
    PANEL_2,
    TEXT,
    Path,
    ctk,
    datetime,
)
from aegis_gui.formatting import layers_summary, open_path
from aegis_gui.pages.base import BasePage


class ReportsPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x")
        ctk.CTkLabel(header, text="Reports", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(side="left")
        ctk.CTkButton(header, text="Open reports folder", height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=BLUE,
                      command=lambda: open_path(app.scanner.report_dir)
                      ).pack(side="right")
        ctk.CTkButton(header, text="Refresh", height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self.on_show).pack(side="right", padx=8)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, pady=(12, 0))
        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self.list_frame = ctk.CTkScrollableFrame(body, fg_color=PANEL, corner_radius=10,
                                                 border_width=1, border_color=BORDER,
                                                 width=250)
        self.list_frame.grid(row=0, column=0, sticky="nsw", padx=(0, 10))

        viewer_frame = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=10,
                                    border_width=1, border_color=BORDER)
        viewer_frame.grid(row=0, column=1, sticky="nsew")
        self.viewer = ctk.CTkTextbox(viewer_frame, fg_color=PANEL, text_color=TEXT,
                                     font=app.font_mono_small, wrap="word",
                                     border_width=0)
        self.viewer.pack(fill="both", expand=True, padx=8, pady=8)
        self._set_viewer("Select a report on the left to preview it here.")

    def _set_viewer(self, text):
        self.viewer.configure(state="normal")
        self.viewer.delete("1.0", "end")
        self.viewer.insert("1.0", text)
        self.viewer.configure(state="disabled")

    def on_show(self):
        for child in self.list_frame.winfo_children():
            child.destroy()
        report_dir = Path(self.app.scanner.report_dir)
        files = sorted([*report_dir.glob("ransomware_scan_*"), *report_dir.glob("canary_alert_*")],
                       key=lambda p: p.stat().st_mtime, reverse=True) if report_dir.exists() else []
        if not files:
            ctk.CTkLabel(self.list_frame, text="No reports yet.\nRun a scan first.",
                         font=self.app.font_small, text_color=MUTED,
                         justify="left").pack(anchor="w", padx=8, pady=8)
            self._set_viewer("Reports will appear here after your first scan.")
            return
        for path in files[:120]:
            stamp = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            kind = "ALERT" if path.name.startswith("canary_alert_") else path.suffix.lstrip(".").upper()
            text = f"{stamp}   ·  {kind}"
            ctk.CTkButton(self.list_frame, text=text, anchor="w", height=30,
                          font=self.app.font_mono_small, fg_color="transparent",
                          hover_color=PANEL_2, text_color=TEXT,
                          command=lambda p=path: self._preview(p)).pack(fill="x", pady=1)

    def _preview(self, path: Path):
        try:
            if path.suffix == ".json":
                results = json.loads(path.read_text(encoding="utf-8"))
                malicious = [r for r in results if r.get("is_malicious")]
                lines = [f"{path.name}",
                         f"Files scanned : {len(results)}",
                         f"Malicious     : {len(malicious)}", ""]
                for r in sorted(results, key=lambda r: -float(r.get("severity_score", 0) or 0)):
                    lines.append(f"[{float(r.get('severity_score', 0) or 0):4.1f}/10] "
                                 f"{r.get('file_name','?')}  ({layers_summary(r)})")
                lines += ["", "—" * 60, "", json.dumps(results, indent=2)[:60000]]
                self._set_viewer("\n".join(lines))
            else:
                self._set_viewer(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            self._set_viewer(f"Could not read {path.name}:\n{e}")
