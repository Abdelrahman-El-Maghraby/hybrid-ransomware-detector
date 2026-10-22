#!/usr/bin/env python3
"""
Aegis Sentinel (hybrid ransomware detector) — graphical interface.

A desktop front-end for RansomwareScanner.py. The scanner module is used as a
library; nothing in the CLI behaviour changes. All scanning runs in a worker
thread and communicates with the UI through queues (Tkinter is not
thread-safe, so widgets are only ever touched from the main thread).

Launch with:
    python gui.py
or:
    python RansomwareScanner.py --gui
"""


# The app lives in the aegis_gui package; this module keeps the old entry point
# and the names other code and the tests import from `gui`.
from aegis_gui.app import App, main
from aegis_gui.common import *
from aegis_gui.detail import *
from aegis_gui.formatting import *
from aegis_gui.pages import *
from aegis_gui.state import *
from aegis_gui.widgets import *

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()   # isolated scan workers in frozen builds
    main()
