"""Imports, dependency guards, version, paths and the colour theme.

Other modules of the package import the names they use from here (the GUI
toolkit, the scanner module, paths and theme colours), so the dependency
guards run once and the theme has one definition.
"""
# ruff: noqa: F401   (re-exported names)

import platform
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

from detectors.registry import REGISTRY

# --- Dependency guards (friendly errors instead of tracebacks) --------------

try:
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover
    print("Tkinter is not available. On Debian/Ubuntu install it with:")
    print("    sudo apt-get install python3-tk")
    sys.exit(1)

try:
    import customtkinter as ctk
except ImportError:  # pragma: no cover
    print("The GUI needs the 'customtkinter' package. Install it with:")
    print("    pip install customtkinter")
    sys.exit(1)

try:
    import RansomwareScanner as RS
except ImportError:  # pragma: no cover
    print("Could not import RansomwareScanner.py — run gui.py from the project folder.")
    sys.exit(1)

from dotenv import set_key

APP_VERSION = "4.4 beta"
SETTINGS_FILE = RS.APP_DIR / "gui_settings.json"
ENV_FILE = RS.ENV_FILE        # next to the script, or ~/RansomwareScanner in a build

# --- Theme --------------------------------------------------------------------
# Graphite neutrals with a slight blue cast and one cobalt accent for actions.
# Red / orange / amber / green are reserved for verdicts and status, so colour
# always means something.

BG = "#0F1216"
PANEL = "#151A20"
PANEL_2 = "#1B2129"
BORDER = "#232A33"
BORDER_2 = "#2F3843"
TEXT = "#E3E7ED"
MUTED = "#8A94A3"
ACCENT = "#3E6FD8"
ACCENT_HOVER = "#335DB8"
ACCENT_SOFT = "#93B1EE"
ACCENT_DIM = "#18233A"
ON_ACCENT = "#FFFFFF"
OK = "#5FB98E"
RED = "#E5484D"
RED_HOVER = "#C73E42"
RED_SOFT = "#F2A3A5"
ORANGE = "#EE9454"
AMBER_SOFT = "#E9BE6C"
BLUE = "#93B1EE"
SELECT = "#1F2A3A"

SEV_HIGH, SEV_MED = 7.0, 3.5
