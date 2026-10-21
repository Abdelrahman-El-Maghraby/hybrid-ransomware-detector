"""Base class of the pages."""

from aegis_gui.common import ctk


class BasePage(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color="transparent")
        self.app = app

    def on_show(self):
        pass
