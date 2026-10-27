#!/usr/bin/env python3
"""
Build standalone executables of the Hybrid Ransomware Detection System.

    pip install -r requirements.txt -r requirements-build.txt
    python build.py                 # folder build: dist/HybridRansomwareDetector/
    python build.py --onefile       # one file per program
    python build.py --no-ml         # leave scikit-learn out (~100 MB smaller)
    python build.py --smoke-only    # re-test an existing build, don't rebuild

What it does:
  1. checks the interpreter and that PyInstaller + the core packages import;
  2. runs PyInstaller with scanner.spec (UPX off, see the spec for why);
  3. SMOKE-TESTS the produced CLI in a throw-away HOME: --version, then a real
     --scan-file of a clean PDF and of an executable disguised as a PDF, and
     fails the build if the verdicts are wrong - a binary that starts but
     can't find its YARA rules would otherwise ship silently. Then
     `--capabilities cli` must report every layer the production profile
     requires as up in the PACKAGED program (docs/RELEASE_SCOPE.md), and a
     folder build must contain the GUI toolkit;
  4. packages the result as dist/hrd-scanner-<version>-<os>-<arch>.zip
     (.tar.gz on Linux/macOS) and writes a SHA256SUMS file next to it.

PyInstaller does not cross-compile. Build each target on its own OS, e.g. a
GitHub Actions matrix over windows-latest, macos-latest and ubuntu-latest that
runs `python build.py` and uploads dist/*.zip / dist/*.tar.gz.

Release binaries are unsigned. On Windows, SmartScreen will warn until the exe
is code-signed; on macOS, Gatekeeper requires `xattr -dr com.apple.quarantine`
or signing + notarisation. Signing is out of scope for this script.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = ROOT / "scanner.spec"
DIST = ROOT / "dist"
WORK = ROOT / "build"
APP_NAME = "HybridRansomwareDetector"
CLI_NAME = "hrd-scanner"
GUI_NAME = "hrd-scanner-gui"
# Import names the binaries must bundle: the engine core plus every package a layer
# required by the production profile needs (docs/RELEASE_SCOPE.md section 3), and the
# GUI toolkit (both programs ship in one build). A missing one fails the build.
REQUIRED = ("requests", "dotenv", "pypdf", "docx", "yaml", "PIL", "defusedxml", "cryptography",
            "olefile", "oletools", "yara", "ppdeep", "pyzipper", "py7zr", "pycdlib", "rarfile",
            "msoffcrypto", "pyzbar", "customtkinter")
# Optional: bundled when installed, their features are off otherwise.
OPTIONAL = ("tlsh",              # the built-in port gives identical digests
            "pytesseract", "pdf2image",   # OCR, only used with an LLM
            "watchdog")          # real-time canary watching (desktop)


def engine_version() -> str:
    """Read ENGINE_VERSION without importing the scanner (import has side effects)."""
    m = re.search(r'^ENGINE_VERSION\s*=\s*"([^"]+)"',
                  (ROOT / "engine" / "config.py").read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit("Could not read ENGINE_VERSION from engine/config.py")
    return m.group(1)


def platform_tag() -> str:
    system = {"Darwin": "macos", "Windows": "windows"}.get(platform.system(),
                                                           platform.system().lower())
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    return f"{system}-{machine}"


def exe_name(name: str) -> str:
    return name + (".exe" if os.name == "nt" else "")


def preflight(with_ml: bool) -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit("PyInstaller is not installed:  pip install -r requirements-build.txt")
    missing = [m for m in REQUIRED if importlib.util.find_spec(m) is None]
    if missing:
        sys.exit(f"Missing required packages: {', '.join(missing)}  "
                 "(pip install -r requirements.txt)")
    absent = [m for m in OPTIONAL if importlib.util.find_spec(m) is None]
    if with_ml and importlib.util.find_spec("sklearn") is None:
        absent.append("scikit-learn (ML model loading)")
    if absent:
        print("! Optional, not installed, so not bundled: " + ", ".join(absent))


def run_pyinstaller(onefile: bool, with_ml: bool, version: str) -> None:
    env = dict(os.environ, HRD_ONEFILE="1" if onefile else "0",
               HRD_WITH_ML="1" if with_ml else "0", HRD_VERSION=version)
    cmd = [sys.executable, "-m", "PyInstaller", str(SPEC), "--noconfirm", "--clean",
           "--distpath", str(DIST), "--workpath", str(WORK)]
    print("$ " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, env=env, check=True)


def built_cli(onefile: bool) -> Path:
    return (DIST / exe_name(CLI_NAME)) if onefile else (DIST / APP_NAME / exe_name(CLI_NAME))


def _disguised_pe() -> bytes:
    h = bytearray(4096)
    h[0:2] = b"MZ"
    h[0x3C:0x40] = (0x80).to_bytes(4, "little")
    h[0x80:0x84] = b"PE\x00\x00"
    return bytes(h)


def _clean_pdf() -> bytes:
    body = b"BT /F1 12 Tf 72 720 Td (Quarterly report) Tj ET"
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
            b"<< /Length %d >>\nstream\n" % len(body) + body + b"\nendstream"]
    out, offsets = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


def smoke_test(cli: Path, version: str) -> None:
    if not cli.is_file():
        sys.exit(f"Smoke test: {cli} was not produced.")
    with tempfile.TemporaryDirectory(prefix="hrd_smoke_") as tmp:
        home = Path(tmp)
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), LLM_PROVIDER="none",
                   VIRUSTOTAL_API_KEY="", PYTHONIOENCODING="utf-8")

        def run(*args, timeout=180):
            return subprocess.run([str(cli), *args], capture_output=True, text=True,
                                  env=env, cwd=home, timeout=timeout,
                                  encoding="utf-8", errors="replace")

        out = run("--version")
        if out.returncode != 0 or version not in (out.stdout + out.stderr):
            sys.exit(f"Smoke test: --version failed\n{out.stdout}\n{out.stderr}")
        print(f"  ok  --version -> {(out.stdout or out.stderr).strip()}")

        samples = {"clean.pdf": (_clean_pdf(), ("Clean",)),
                   "invoice.pdf": (_disguised_pe(), ("High", "Critical"))}
        for name, (data, expected) in samples.items():
            p = home / name
            p.write_bytes(data)
            out = run("--scan-file", str(p))
            verdict = re.search(r"Highest verdict:\s+(\w+)", out.stdout)
            got = verdict.group(1) if verdict else None
            if out.returncode != 0 or got not in expected:
                sys.exit(f"Smoke test: {name} -> {got!r}, expected {expected}\n"
                         f"{out.stdout[-3000:]}\n{out.stderr[-3000:]}")
            print(f"  ok  --scan-file {name} -> {got}")

        check_capabilities(run("--capabilities", "cli"))


def capabilities_report(stdout: str) -> dict:
    """The JSON object `--capabilities` prints (log lines may come before it)."""
    start = stdout.find("\n{\n") + 1 if not stdout.startswith("{") else 0
    try:
        report, _ = json.JSONDecoder().raw_decode(stdout[start:])
    except ValueError:
        return {}
    return report if isinstance(report, dict) else {}


def check_capabilities(out: subprocess.CompletedProcess[str]) -> None:
    """Fail the build when the packaged program lacks a required layer."""
    report = capabilities_report(out.stdout)
    if not report.get("layers"):
        sys.exit(f"Smoke test: --capabilities printed no report\n{out.stdout[-3000:]}\n"
                 f"{out.stderr[-3000:]}")
    for name, st in report["layers"].items():
        note = f" ({st['detail']})" if st.get("detail") else ""
        print(f"  {'ok' if st['state'] != 'down' else '!'}  layer {name}: {st['state']}{note}")
    problems = report.get("flavour_problems", [])
    if out.returncode != 0 or problems:
        sys.exit("Smoke test: the packaged program lacks required layers:\n  "
                 + "\n  ".join(problems or [f"--capabilities exited {out.returncode}"]))


def check_gui_bundle(onefile: bool) -> None:
    """The GUI program is only as good as the toolkit bundled next to it."""
    if onefile:
        print("  -   onefile build: GUI bundle not inspected (the release uses the folder build)")
        return
    if not any((DIST / APP_NAME).rglob("customtkinter")):
        sys.exit("Smoke test: customtkinter is not in the bundle; hrd-scanner-gui cannot start.")
    print("  ok  GUI toolkit (customtkinter) bundled")


def package(onefile: bool, version: str) -> Path:
    base = f"{CLI_NAME}-{version}-{platform_tag()}"
    if onefile:
        items = [DIST / exe_name(CLI_NAME), DIST / exe_name(GUI_NAME)]
        app = DIST / "Hybrid Ransomware Detector.app"
        if app.exists():
            items.append(app)
    else:
        items = [DIST / APP_NAME]
        app = DIST / "Hybrid Ransomware Detector.app"
        if app.exists():
            items.append(app)
    items = [i for i in items if i.exists()]

    if os.name == "nt":
        archive = DIST / f"{base}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            for item in items:
                for f in ([item] if item.is_file() else sorted(item.rglob("*"))):
                    if f.is_file():
                        z.write(f, Path(base) / f.relative_to(DIST))
    else:
        archive = DIST / f"{base}.tar.gz"          # tar keeps exec bits and symlinks
        with tarfile.open(archive, "w:gz") as t:
            for item in items:
                t.add(item, arcname=str(Path(base) / item.name))

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sums = DIST / "SHA256SUMS"
    lines = [ln for ln in (sums.read_text().splitlines() if sums.exists() else [])
             if not ln.endswith(archive.name)]
    sums.write_text("\n".join(lines + [f"{digest}  {archive.name}"]) + "\n")
    return archive


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("--onefile", action="store_true", help="one file per program")
    ap.add_argument("--no-ml", action="store_true", help="leave scikit-learn/numpy out")
    ap.add_argument("--smoke-only", action="store_true", help="test an existing build")
    ap.add_argument("--no-package", action="store_true", help="skip the archive step")
    ap.add_argument("--clean", action="store_true", help="delete build/ and dist/ first")
    args = ap.parse_args(argv)

    version = engine_version()
    print(f"Hybrid Ransomware Detector {version}  ->  {platform_tag()}  "
          f"({'onefile' if args.onefile else 'folder'}, ML {'off' if args.no_ml else 'on'})")
    if not args.smoke_only:
        preflight(with_ml=not args.no_ml)
        if args.clean:
            shutil.rmtree(DIST, ignore_errors=True)
            shutil.rmtree(WORK, ignore_errors=True)
        run_pyinstaller(args.onefile, not args.no_ml, version)

    print("Smoke test:")
    smoke_test(built_cli(args.onefile), version)
    check_gui_bundle(args.onefile)

    if not args.no_package and not args.smoke_only:
        archive = package(args.onefile, version)
        print(f"Package: {archive}  ({archive.stat().st_size / 1e6:.1f} MB)")
        print(f"Checksums: {DIST / 'SHA256SUMS'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
