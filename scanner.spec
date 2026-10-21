# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build recipe for the Hybrid Ransomware Detection System.

Use build.py instead of calling this directly - it sets the options below,
runs PyInstaller, smoke-tests the result and packages it. Direct use:

    pyinstaller scanner.spec --noconfirm --clean

Produces two programs from one shared runtime:

    hrd-scanner       console CLI   (RansomwareScanner.py: --scan-now, --scan-file ...)
    hrd-scanner-gui   desktop app   (gui.py; no console window on Windows/macOS)

Options (environment variables, set by build.py):

    HRD_ONEFILE=1   one self-extracting file per program instead of a folder.
                    Starts slower and unpacks to a temp dir on every launch,
                    which some antivirus products treat as suspicious; the
                    folder build is the default for that reason.
    HRD_WITH_ML=0   leave scikit-learn/numpy out (~100 MB smaller). The ML
                    layer then runs its rule engine; trained models can't load.

UPX is deliberately OFF: UPX-packed executables are a classic malware trait
(this scanner's own ML layer flags UPX sections) and trip AV heuristics.

PyInstaller cannot cross-compile: build on Windows for .exe, on macOS for the
.app, on Linux for an ELF binary (CI matrix: see build.py --help).
"""

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

ROOT = Path(SPECPATH).resolve()          # noqa: F821 - injected by PyInstaller
ONEFILE = os.environ.get("HRD_ONEFILE", "0") == "1"
WITH_ML = os.environ.get("HRD_WITH_ML", "1") == "1"
IS_MAC = sys.platform == "darwin"
APP_NAME = "HybridRansomwareDetector"

datas = [
    (str(ROOT / "rules"), "rules"),                                  # YARA rules
    (str(ROOT / "detectors" / "indicators.yaml"), "detectors"),      # weights + labels
    (str(ROOT / "fuzzy_signatures.sample.json"), "."),
    (str(ROOT / ".env.example"), "."),
    (str(ROOT / "LICENSE"), "."),
]
for package in ("customtkinter", "docx"):                            # themes / templates
    try:
        datas += collect_data_files(package)
    except Exception:                                                # not installed: skip
        pass

hiddenimports = [
    # Optional layers are imported inside try/except; name them so the
    # dependency scan doesn't miss them when they are installed.
    "tlsh", "ppdeep", "yara", "oletools.olevba", "olefile", "defusedxml",
    "cryptography.hazmat.primitives.ciphers.aead",
    "PyPDF2", "docx", "pytesseract", "pdf2image", "PIL",
    # v4.2
    "pyzipper", "py7zr", "pycdlib", "watchdog.observers", "watchdog.events",
    "rarfile",                                                  # v4.3
    "cryptography.hazmat.primitives.kdf.scrypt",
]
excludes = ["pytest", "tests", "IPython", "matplotlib", "pandas", "notebook", "jupyter"]
if WITH_ML:
    hiddenimports += ["sklearn.ensemble._forest", "sklearn.tree._utils", "joblib"]
else:
    excludes += ["sklearn", "scipy", "joblib", "numpy"]


def analysis(script):
    return Analysis(                                                 # noqa: F821
        [str(ROOT / script)],
        pathex=[str(ROOT)],
        datas=datas,
        hiddenimports=hiddenimports,
        excludes=excludes,
        noarchive=False,
    )


cli_a = analysis("RansomwareScanner.py")
gui_a = analysis("gui.py")


def exe(a, name, console):
    pyz = PYZ(a.pure)                                                # noqa: F821
    common = dict(name=name, debug=False, strip=False, upx=False, console=console,
                  disable_windowed_traceback=False, argv_emulation=False,
                  target_arch=None, codesign_identity=None, entitlements_file=None)
    if ONEFILE:
        return EXE(pyz, a.scripts, a.binaries, a.datas, [],          # noqa: F821
                   runtime_tmpdir=None, **common)
    return EXE(pyz, a.scripts, [], exclude_binaries=True, **common)  # noqa: F821


cli_exe = exe(cli_a, "hrd-scanner", console=True)
gui_exe = exe(gui_a, "hrd-scanner-gui", console=False)

if not ONEFILE:
    # GUI first: a macOS .app launches the first executable in the bundle.
    coll = COLLECT(                                                  # noqa: F821
        gui_exe, gui_a.binaries, gui_a.datas,
        cli_exe, cli_a.binaries, cli_a.datas,
        strip=False, upx=False, name=APP_NAME,
    )
    if IS_MAC:
        app = BUNDLE(                                                # noqa: F821
            coll,
            name="Hybrid Ransomware Detector.app",
            bundle_identifier="com.abdelrahman.ransomwarescanner",
            info_plist={"NSHighResolutionCapable": True,
                        "CFBundleShortVersionString": os.environ.get("HRD_VERSION", "0")},
        )
elif IS_MAC:
    app = BUNDLE(                                                    # noqa: F821
        gui_exe,
        name="Hybrid Ransomware Detector.app",
        bundle_identifier="com.abdelrahman.ransomwarescanner",
        info_plist={"NSHighResolutionCapable": True,
                    "CFBundleShortVersionString": os.environ.get("HRD_VERSION", "0")},
    )
