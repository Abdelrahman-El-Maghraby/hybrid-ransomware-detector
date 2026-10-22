"""Logs page: the live log stream."""

from aegis_gui.common import BLUE, BORDER, BORDER_2, PANEL, PANEL_2, RS, TEXT, Path, ctk
from aegis_gui.formatting import open_path
from aegis_gui.pages.base import BasePage


class LogsPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x")
        ctk.CTkLabel(header, text="Logs", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(side="left")
        ctk.CTkButton(header, text="Open log file", height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=BLUE,
                      command=lambda: open_path(RS.LOG_FILE)).pack(side="right")
        ctk.CTkButton(header, text="Reload", height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self.on_show).pack(side="right", padx=8)

        box_frame = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=10,
                                 border_width=1, border_color=BORDER)
        box_frame.pack(fill="both", expand=True, pady=(12, 0))
        self.box = ctk.CTkTextbox(box_frame, fg_color=PANEL, text_color=TEXT,
                                  font=app.font_mono_small, wrap="none", border_width=0)
        self.box.pack(fill="both", expand=True, padx=8, pady=8)
        self.box.configure(state="disabled")

    def on_show(self):
        try:
            lines = Path(RS.LOG_FILE).read_text(encoding="utf-8",
                                                errors="replace").splitlines()[-400:]
            text = "\n".join(lines) if lines else "Log file is empty."
        except Exception:
            text = "Log file not found yet."
        self.box.configure(state="normal")
        self.box.delete("1.0", "end")
        self.box.insert("1.0", text)
        self.box.see("end")
        self.box.configure(state="disabled")

    def append(self, line: str):
        self.box.configure(state="normal")
        self.box.insert("end", "\n" + line)
        self.box.see("end")
        self.box.configure(state="disabled")
