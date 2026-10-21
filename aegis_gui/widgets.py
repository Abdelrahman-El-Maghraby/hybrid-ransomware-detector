"""Small reusable widgets."""

from aegis_gui.common import AMBER_SOFT, BORDER, MUTED, OK, PANEL, RED, TEXT, ctk

# --- Reusable widgets -----------------------------------------------------------

class StatCard(ctk.CTkFrame):
    """Dashboard layer card: title, value, status dot + status text."""

    def __init__(self, master, title: str, **kwargs):
        # A cell of the shared "Engine" panel rather than a card of its own.
        super().__init__(master, fg_color="transparent", corner_radius=0, **kwargs)
        self.title_label = ctk.CTkLabel(self, text=title, text_color=MUTED,
                                        font=master.app.font_small, anchor="w")
        self.title_label.pack(fill="x", padx=16, pady=(10, 0))
        self.value_label = ctk.CTkLabel(self, text="—", text_color=TEXT,
                                        font=master.app.font_bold, anchor="w")
        self.value_label.pack(fill="x", padx=16, pady=(0, 0))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 10))
        self.dot = ctk.CTkLabel(row, text="●", width=14, anchor="w",
                                text_color=MUTED, font=master.app.font_small)
        self.dot.pack(side="left")
        self.status_label = ctk.CTkLabel(row, text="", text_color=MUTED,
                                         font=master.app.font_small, anchor="w")
        self.status_label.pack(side="left")

    def update_card(self, value: str, status: str, ok: bool, alert: bool = False):
        self.value_label.configure(text=value)
        color = RED if alert else (OK if ok else AMBER_SOFT)
        self.status_label.configure(text=status, text_color=color if not ok else MUTED)
        self.dot.configure(text_color=color)


class Section(ctk.CTkFrame):
    """Settings-style section: heading + bordered panel body."""

    def __init__(self, master, title: str, app):
        super().__init__(master, fg_color="transparent")
        ctk.CTkLabel(self, text=title, text_color=TEXT, font=app.font_bold,
                     anchor="w").pack(fill="x", pady=(0, 6))
        self.body = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=10,
                                 border_width=1, border_color=BORDER)
        self.body.pack(fill="x")
