# -*- mode: python ; coding: utf-8 -*-
"""
scanner.spec — PyInstaller single-file specification for AEGIS SENTINEL v5.2.0.
"""

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

project_root = Path(SPECPATH).resolve()

datas = [
    (str(project_root / "rules"), "rules"),
    (str(project_root / "fuzzy_signatures.sample.json"), "."),
]
try:
    datas += collect_data_files("customtkinter")
except Exception:
    pass

hiddenimports = [
    "core",
    "detectors",
    *collect_submodules("core"),
    *collect_submodules("detectors"),
]

a = Analysis(
    [str(project_root / "RansomwareScanner.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="aegis-sentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
)