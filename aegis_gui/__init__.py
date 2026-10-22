"""Aegis Sentinel desktop app (CustomTkinter), split by responsibility:

    common      imports, dependency guards, paths, colour theme
    formatting  pure result -> text / colour helpers (testable without a display)
    state       settings store, log bridge, scan worker thread
    widgets     small reusable widgets
    detail      per-file result window
    pages/      one module per page
    app         the main window
"""

from .app import App, main  # noqa: F401
