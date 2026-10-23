#!/usr/bin/env python3
"""
Hybrid Ransomware Detection System - command-line entry point.

Scans documents (PDF, Word, Excel, PowerPoint, RTF), ZIP archives and e-mails
(.eml / .msg) for ransomware / malicious behaviour by fusing independent
detection layers through a transparent weighted scoring matrix.

Where things live:
  engine/config.py      version, per-user paths, logging, .env, CONFIG
  engine/scanner.py     RansomwareScanner: runs the pipeline, walks folders,
                        quarantine and canaries
  engine/layers.py      the ordered detection layers (the scan pipeline)
  engine/containers.py  ZIP / e-mail handling: members re-scanned recursively
  engine/external.py    LLM and VirusTotal lookups (cached)
  engine/text.py        text and string extraction
  engine/report.py      text + JSON reports
  detectors/            the individual detection engines
  core/                 quarantine vault, canaries, cache, HTTP helpers
  this file             autostart, shortcuts, hash-DB import and the CLI

Importing this module keeps every name the GUI and older integrations used
(RansomwareScanner, CONFIG, ENGINE_VERSION, the *_AVAILABLE flags, ...).

This tool is for DEFENSIVE and educational use - analysing suspect documents,
never executing or creating malware. No macro or payload is ever run.
"""

import argparse
import csv
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Tuple

import schedule

try:
    import winreg  # Windows registry module (Windows only)
except ImportError:
    winreg = None  # Non-Windows: autostart features are disabled gracefully

# Engine: configuration first (creates the app folders, logging, .env), then
# the scanner. Every name below is re-exported for the GUI and older callers.
from core import WATCHDOG_AVAILABLE, CanaryWatcher, QuarantineError
from detectors import (
    DEFUSEDXML_AVAILABLE,
    FUZZY_AVAILABLE,
    MSG_AVAILABLE,
    OLEVBA_AVAILABLE,
    SKLEARN_AVAILABLE,
    YARA_AVAILABLE,
    FuzzyHasher,
    MLClassifier,
)
from detectors.relationship_scanner import defang  # noqa: F401
from engine.config import (  # noqa: F401
    APP_DIR,
    BUNDLED_FUZZY_SIGS,
    BUNDLED_RULES_DIR,
    CONFIG,
    DATA_DIR,
    ENGINE_VERSION,
    ENV_FILE,
    FROZEN,
    KEYSTORE_DIR,
    LOG_FILE,
    QUARANTINE_DIR,
    REPORT_DIR,
    SCRIPT_DIR,
    SUPPORTED_EXTENSIONS,
    USER_HOME,
    VERDICT_RANK,
    _env_bool,
    _env_float,
    logger,
)
from engine.scanner import RansomwareScanner
from engine.text import extract_suspicious_strings  # noqa: F401

# ---------------------------------------------------------------------------
# Cross-platform autostart  (run the scanner automatically at login/startup)
# ---------------------------------------------------------------------------

AUTOSTART_LABEL = "com.abdelrahman.ransomwarescanner"   # macOS launchd label
AUTOSTART_NAME = "RansomwareScanner"                     # Windows registry value
SYSTEMD_UNIT = "ransomware-scanner.service"             # Linux systemd unit
CRON_MARKER = "# RansomwareScanner autostart"           # Linux/macOS cron marker


def _resolve_python_and_script() -> Tuple[str, str]:
    """Return (program, script) used to relaunch the scanner.

    From source that is the interpreter plus this file. In a PyInstaller build
    the executable *is* the program, so the script part is empty.
    """
    if FROZEN:
        return sys.executable, ""
    python_exe = sys.executable or "python3"
    script_path = str(Path(__file__).resolve())
    return python_exe, script_path


def _q(script_path: str) -> str:
    """' "script"' when running from source, '' for a frozen executable."""
    return f' "{script_path}"' if script_path else ""


def setup_windows_autostart() -> bool:
    """Register the scanner to run at login via the Windows registry (HKCU\\...\\Run)."""
    if winreg is None or os.name != "nt":
        print("ℹ️  Windows autostart is only available on Windows.")
        return False
    try:
        python_exe, script_path = _resolve_python_and_script()
        pythonw = python_exe.replace("python.exe", "pythonw.exe")  # no console window
        command = f'"{pythonw}"{_q(script_path)} --background'
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, AUTOSTART_NAME, 0, winreg.REG_SZ, command)
        logger.info("Added scanner to Windows startup registry.")
        print("✅ Configured to run at Windows login.")
        return True
    except Exception as e:
        logger.error(f"Windows autostart failed: {e}")
        print(f"❌ Windows autostart failed: {e}")
        return False


def setup_macos_autostart() -> bool:
    """Install a launchd LaunchAgent so the scanner runs at login on macOS."""
    try:
        python_exe, script_path = _resolve_python_and_script()
        agents_dir = Path.home() / "Library" / "LaunchAgents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        plist_path = agents_dir / f"{AUTOSTART_LABEL}.plist"
        script_line = f"\n        <string>{script_path}</string>" if script_path else ""
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{AUTOSTART_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_exe}</string>{script_line}
        <string>--background</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>{LOG_FILE}</string>
</dict>
</plist>
"""
        plist_path.write_text(plist)
        # Reload the agent (unload first in case it already exists)
        subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True, text=True)
        result = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, text=True)
        if result.returncode != 0 and result.stderr.strip():
            logger.warning(f"launchctl load reported: {result.stderr.strip()}")
        logger.info(f"Installed launchd agent at {plist_path}")
        print(f"✅ Configured to run at macOS login (launchd agent: {plist_path}).")
        return True
    except Exception as e:
        logger.error(f"macOS autostart failed: {e}")
        print(f"❌ macOS autostart failed: {e}")
        return False


def _setup_systemd_autostart(python_exe: str, script_path: str) -> bool:
    """Install a systemd *user* service (preferred on modern Linux)."""
    if not shutil.which("systemctl"):
        return False
    try:
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / SYSTEMD_UNIT
        unit = f"""[Unit]
Description=Hybrid Ransomware Detection System (background scanner)
After=network-online.target

[Service]
Type=simple
ExecStart="{python_exe}"{_q(script_path)} --background
Restart=on-failure

[Install]
WantedBy=default.target
"""
        unit_path.write_text(unit)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True)
        result = subprocess.run(
            ["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT],
            capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning(f"systemctl enable reported: {result.stderr.strip()}")
        logger.info(f"Installed systemd user unit at {unit_path}")
        print(f"✅ Configured to run at Linux login (systemd user unit: {unit_path}).")
        print("   Tip: run 'loginctl enable-linger $USER' to keep it running without an active session.")
        return True
    except Exception as e:
        logger.error(f"systemd autostart failed: {e}")
        return False


def _setup_cron_autostart(python_exe: str, script_path: str) -> bool:
    """Fallback: add a @reboot crontab entry (Linux/macOS without systemd)."""
    if not shutil.which("crontab"):
        return False
    try:
        cron_line = f'@reboot "{python_exe}"{_q(script_path)} --background  {CRON_MARKER}'
        existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        current = existing.stdout if existing.returncode == 0 else ""
        if CRON_MARKER in current:
            print("ℹ️  Cron autostart entry already present.")
            return True
        sep = "\n" if current and not current.endswith("\n") else ""
        new_crontab = current + sep + cron_line + "\n"
        proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)
        if proc.returncode != 0:
            logger.error(f"crontab update failed: {proc.stderr.strip()}")
            return False
        logger.info("Added @reboot crontab entry.")
        print("✅ Configured to run at startup via cron (@reboot).")
        return True
    except Exception as e:
        logger.error(f"cron autostart failed: {e}")
        return False


def setup_linux_autostart() -> bool:
    """Configure Linux autostart: systemd user service, falling back to cron."""
    python_exe, script_path = _resolve_python_and_script()
    if _setup_systemd_autostart(python_exe, script_path):
        return True
    print("ℹ️  systemd user service unavailable; falling back to cron.")
    if _setup_cron_autostart(python_exe, script_path):
        return True
    print("❌ Could not configure Linux autostart (neither systemd nor cron available).")
    return False


def setup_autostart() -> bool:
    """Dispatch to the correct autostart implementation for the current OS."""
    system = platform.system()
    if system == "Windows":
        return setup_windows_autostart()
    if system == "Darwin":
        return setup_macos_autostart()
    if system == "Linux":
        return setup_linux_autostart()
    print(f"ℹ️  Autostart is not supported on this platform: {system}")
    return False


def remove_autostart() -> bool:
    """Remove any autostart entry this scanner created on the current OS."""
    system = platform.system()
    try:
        if system == "Windows":
            if winreg is None:
                return False
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
                try:
                    winreg.DeleteValue(key, AUTOSTART_NAME)
                except FileNotFoundError:
                    pass
            print("✅ Removed Windows autostart entry (if it existed).")
            return True

        if system == "Darwin":
            plist_path = Path.home() / "Library" / "LaunchAgents" / f"{AUTOSTART_LABEL}.plist"
            if plist_path.exists():
                subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True, text=True)
                plist_path.unlink()
                print(f"✅ Removed macOS launchd agent: {plist_path}")
            else:
                print("ℹ️  No macOS launchd agent found.")
            return True

        if system == "Linux":
            removed = False
            unit_path = Path.home() / ".config" / "systemd" / "user" / SYSTEMD_UNIT
            if unit_path.exists() and shutil.which("systemctl"):
                subprocess.run(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT],
                               capture_output=True, text=True)
                unit_path.unlink()
                subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True)
                removed = True
            if shutil.which("crontab"):
                existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                if existing.returncode == 0 and CRON_MARKER in existing.stdout:
                    filtered = "\n".join(line for line in existing.stdout.splitlines()
                                         if CRON_MARKER not in line)
                    filtered = (filtered + "\n") if filtered.strip() else ""
                    subprocess.run(["crontab", "-"], input=filtered, text=True, capture_output=True)
                    removed = True
            print("✅ Removed Linux autostart entry." if removed else "ℹ️  No Linux autostart entry found.")
            return True
    except Exception as e:
        logger.error(f"Failed to remove autostart: {e}")
        print(f"❌ Failed to remove autostart: {e}")
        return False
    print(f"ℹ️  Autostart removal is not supported on this platform: {system}")
    return False


def create_desktop_shortcut() -> bool:
    """Create a desktop shortcut/launcher (Windows .lnk or Linux .desktop)."""
    system = platform.system()
    python_exe, script_path = _resolve_python_and_script()

    if system == "Windows":
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            desktop = shell.SpecialFolders("Desktop")
            shortcut_path = os.path.join(desktop, "Ransomware Scanner.lnk")
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.TargetPath = python_exe
            shortcut.Arguments = f'{_q(script_path).strip()} --scan-now'.strip()
            shortcut.WorkingDirectory = os.path.dirname(script_path or python_exe)
            shortcut.IconLocation = python_exe + ",0"
            shortcut.Description = "Run Ransomware Scanner"
            shortcut.Save()
            print(f"✅ Created desktop shortcut: {shortcut_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to create shortcut: {e}")
            print("Note: install pywin32 for shortcut support:  pip install pywin32")
            return False

    if system == "Linux":
        try:
            desktop_dir = Path.home() / "Desktop"
            desktop_dir.mkdir(parents=True, exist_ok=True)
            launcher = desktop_dir / "ransomware-scanner.desktop"
            launcher.write_text(
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=Ransomware Scanner\n"
                f'Exec="{python_exe}"{_q(script_path)} --scan-now\n'
                "Terminal=true\n"
                "Categories=Utility;Security;\n"
            )
            launcher.chmod(0o755)
            print(f"✅ Created desktop launcher: {launcher}")
            return True
        except Exception as e:
            print(f"❌ Failed to create launcher: {e}")
            return False

    print("ℹ️  Desktop shortcuts are supported on Windows and Linux only.")
    return False


def import_hash_database(source_path: str, destination_path: str = None) -> Dict:
    """Copy a malware-hash CSV into the app data directory and validate its format.

    Shared by the CLI (--import-database) and the GUI so both use one code path.
    Returns a dict:
        ok               True when the copy succeeded and all required columns exist
        error_kind       None | "missing_source" | "exception"
        message          human-readable status
        destination      final path of the database
        entries          number of data rows found
        missing_columns  required columns absent from the header
    """
    destination_path = destination_path or CONFIG["kaggle_database_path"]
    outcome = {"ok": False, "error_kind": None, "message": "",
               "destination": destination_path, "entries": 0, "missing_columns": []}

    if not os.path.exists(source_path):
        outcome["error_kind"] = "missing_source"
        outcome["message"] = f"Cannot find database file at {source_path}"
        return outcome

    try:
        shutil.copy2(source_path, destination_path)

        with open(destination_path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            outcome["entries"] = sum(1 for _ in reader)

        required_columns = ['FileName', 'md5Hash', 'Benign']
        outcome["missing_columns"] = [col for col in required_columns if col not in header]
        outcome["ok"] = not outcome["missing_columns"]
        outcome["message"] = (
            f"Database format validated. Found {outcome['entries']} entries."
            if outcome["ok"]
            else f"Missing required columns: {', '.join(outcome['missing_columns'])}"
        )
        logger.info(f"Hash database imported from {source_path} -> {destination_path} "
                    f"({outcome['entries']} entries)")
        return outcome
    except Exception as e:
        outcome["error_kind"] = "exception"
        outcome["message"] = str(e)
        logger.error(f"Error importing database: {e}")
        return outcome


def _allow_file(path: str, note: str, allowlist_path: str) -> None:
    """Append a file's SHA-256 (and a note) to the allowlist."""
    import hashlib

    from core.allowlist import load_allowlist
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}")
        return
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    digest = h.hexdigest()
    if digest in load_allowlist(allowlist_path):
        print(f"Already on the allowlist: {digest}")
        return
    os.makedirs(os.path.dirname(allowlist_path) or ".", exist_ok=True)
    clean_note = " ".join((note or os.path.basename(path)).split())
    with open(allowlist_path, "a", encoding="utf-8") as fh:
        fh.write(f"{digest}  # {clean_note}\n")
    print(f"Added to {allowlist_path}: {digest}  # {clean_note}")


def _print_fuzzy_hash(path: str) -> None:
    """Print a file's fuzzy digests so the user can add them to a signature DB.

    This is the intended workflow for growing `fuzzy_signatures.json`: run this
    against a confirmed-malicious sample, then paste the TLSH (and/or ssdeep)
    value into a signature entry with the family name. Matching is then done by
    structural similarity, so polymorphic variants of that family are caught
    without an exact hash.
    """
    if not os.path.exists(path):
        print(f"Error: file not found: {path}")
        return
    if not FUZZY_AVAILABLE:
        print("Fuzzy hashing libraries are not installed.")
        print("Install them with:  pip install python-tlsh ppdeep")
        return

    hasher = FuzzyHasher()
    digests = hasher.hash_file(path)
    print(f"File:   {path}")
    print(f"Size:   {os.path.getsize(path)} bytes")
    print(f"TLSH:   {digests.get('tlsh') or '(unavailable - input too small/uniform)'}")
    print(f"ssdeep: {digests.get('ssdeep') or '(unavailable)'}")
    print()
    print("Add to your fuzzy_signatures.json like:")
    print(json.dumps({
        "family": "Example.Family.Name",
        "tlsh": digests.get("tlsh") or "",
        "ssdeep": digests.get("ssdeep") or "",
        "note": "describe the sample / source here"
    }, indent=2))


def _print_quarantine_list(scanner: "RansomwareScanner") -> None:
    items = scanner.quarantine_vault.list()
    if not items:
        print("The quarantine vault is empty.")
        return
    print(f"{len(items)} item(s) in {scanner.config.get('quarantine_dir')}:")
    for item in items:
        extra = item.get("extra") or {}
        verdict = f"  [{extra.get('verdict')}]" if extra.get("verdict") else ""
        print(f"  {item.get('id')}  {item.get('quarantined_at', '?')}  "
              f"{item.get('original_path', '?')}{verdict}")
        if item.get("reason"):
            print(f"      reason: {item['reason']}")


def _ask_passphrase(confirm: bool) -> str:
    """Passphrase for key backups: HRD_KEY_PASSPHRASE, or asked without echo."""
    env = os.getenv("HRD_KEY_PASSPHRASE")
    if env:
        return env
    import getpass
    phrase = getpass.getpass("Key backup passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != phrase:
        raise QuarantineError("The passphrases did not match.")
    return phrase


def _train_ml_cli(benign_dir: str, malicious_dir: str, out_path: str) -> int:
    """--train-ml: fit the RandomForest on two folders and report honest metrics."""
    from detectors.ml_classifier import collect_files
    for d in (benign_dir, malicious_dir):
        if not Path(d).is_dir():
            print(f"❌ Not a directory: {d}")
            return 2
    if not SKLEARN_AVAILABLE:
        print("❌ Training needs scikit-learn and joblib:  pip install -r requirements-ml.txt")
        return 2
    benign, malicious = collect_files(benign_dir), collect_files(malicious_dir)
    print(f"Extracting features: {len(benign)} benign, {len(malicious)} malicious file(s)...")
    clf = MLClassifier()
    try:
        metrics = clf.train(benign, malicious)
    except ValueError as e:
        print(f"❌ {e}")
        return 2
    clf.save(out_path)
    c = metrics["confusion"]
    print(f"✅ Model saved to {out_path}")
    print(f"   Held-out set ({metrics['holdout_size']} files): "
          f"accuracy {metrics['accuracy']:.1%}, precision {metrics['precision']:.1%}, "
          f"recall {metrics['recall']:.1%}, false-positive rate "
          f"{metrics['false_positive_rate']:.1%}  (tn={c['tn']} fp={c['fp']} "
          f"fn={c['fn']} tp={c['tp']})")
    top = sorted(clf.model_info["feature_importances"].items(),
                 key=lambda kv: kv[1], reverse=True)[:5]
    print("   Most informative features: " + ", ".join(f"{k} ({v:.2f})" for k, v in top))
    print("   Note: metrics are only as representative as the folders you trained on.")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cross-platform ransomware & malicious-document scanner "
                    "(PDF, Office, RTF, ZIP)")
    parser.add_argument("--version", action="version",
                        version=f"hybrid-ransomware-detector {ENGINE_VERSION}")
    parser.add_argument("--scan-now", action="store_true",
                        help="Run a scan immediately")
    parser.add_argument("--background", action="store_true",
                        help="Run in the background with scheduled scans and canary checks")
    parser.add_argument("--setup-autostart", action="store_true",
                        help="Run automatically at login/startup (Windows, macOS, or Linux)")
    parser.add_argument("--remove-autostart", action="store_true",
                        help="Remove the autostart entry created on this machine")
    parser.add_argument("--create-shortcut", action="store_true",
                        help="Create a desktop shortcut/launcher (Windows/Linux)")
    parser.add_argument("--import-database",
                        help="Import a malware-hash CSV database from the given path")
    parser.add_argument("--gui", action="store_true",
                        help="Launch the graphical interface")
    parser.add_argument("--scan-file", metavar="PATH",
                        help="Scan a single file and print its full verdict, then exit")
    parser.add_argument("--fuzzy-hash", metavar="PATH",
                        help="Print a file's TLSH and ssdeep digests (use these to "
                             "populate your fuzzy signature DB), then exit")
    parser.add_argument("--update-rules", metavar="PACK",
                        help="Install a signed rule pack (PACK + PACK.sig), verified against "
                             "RULEPACK_PUBLIC_KEYS, then exit")
    parser.add_argument("--allow-downgrade", action="store_true",
                        help="With --update-rules: accept a pack that is not newer (roll back)")
    parser.add_argument("--jsonl", metavar="FILE",
                        help="Also append each result as one JSON line to FILE (for SIEM ingestion)")
    parser.add_argument("--allow", metavar="PATH",
                        help="Add a known-good file's SHA-256 to the allowlist (it is still "
                             "scanned and reported, but not scored), then exit")
    parser.add_argument("--note", metavar="TEXT", default="",
                        help="Note stored with --allow (who checked it and why)")
    parser.add_argument("--llm-provider", choices=["auto", "ollama", "openai", "none"],
                        help="Override the LLM backend for this run. 'auto' (default) "
                             "prefers a reachable local Ollama for OPSEC and only falls "
                             "back to OpenAI if a key is set; 'none' disables the layer.")
    # --- v4: protection features ------------------------------------------
    parser.add_argument("--deploy-canaries", nargs="*", metavar="DIR",
                        help="Plant canary files in DIR(s): a rapid-containment and "
                             "damage-mitigation tripwire, not kernel-level prevention "
                             "(default: the configured scan directories)")
    parser.add_argument("--verify-canaries", action="store_true",
                        help="Check every canary file now (exit code 2 if tripped)")
    parser.add_argument("--remove-canaries", action="store_true",
                        help="Delete all canary files this tool planted")
    parser.add_argument("--resume-pid", metavar="PID[,PID...]",
                        help="Resume processes the stop_writers response suspended "
                             "(after you checked they are not ransomware)")
    parser.add_argument("--unlock-folders", action="store_true",
                        help="Give back the write access the lock_folders response removed")
    parser.add_argument("--quarantine", metavar="PATH",
                        help="Move a file into the encrypted quarantine vault")
    parser.add_argument("--list-quarantine", action="store_true",
                        help="List the items in the quarantine vault")
    parser.add_argument("--restore", metavar="ID",
                        help="Restore a quarantined item (full id or unique prefix)")
    parser.add_argument("--restore-to", metavar="PATH",
                        help="Destination for --restore (default: original location)")
    parser.add_argument("--export-key", metavar="PATH",
                        help="Back up the quarantine key to PATH, encrypted with a passphrase "
                             "(asked for, or HRD_KEY_PASSPHRASE)")
    parser.add_argument("--import-key", metavar="PATH",
                        help="Install a quarantine key backup (e.g. on a new machine)")
    parser.add_argument("--replace-key", action="store_true",
                        help="With --import-key: replace a DIFFERENT existing key "
                             "(the old one is kept as quarantine.key.bak-<time>)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Don't use or update the VirusTotal/LLM result cache this run")
    parser.add_argument("--clear-cache", action="store_true",
                        help="Delete all cached VirusTotal/LLM results, then exit")
    parser.add_argument("--train-ml", nargs=2, metavar=("BENIGN_DIR", "MALICIOUS_DIR"),
                        help="Train the ML classifier on two labelled folders and save it "
                             "to ML_MODEL_PATH (needs requirements-ml.txt)")
    parser.add_argument("--ml-model-out", metavar="PATH",
                        help="Where --train-ml saves the model (default: ML_MODEL_PATH)")
    parser.add_argument("--scan-imap", action="store_true",
                        help="Scan new messages in the IMAP mailbox (IMAP_HOST, IMAP_USER, "
                             "IMAP_PASSWORD; read-only, TLS only), then exit")
    return parser


def _apply_overrides(args) -> None:
    """Options that change CONFIG for this run only."""
    if args.jsonl:
        CONFIG["jsonl_path"] = args.jsonl

    # An explicit --llm-provider overrides config/env for this process.
    if args.llm_provider:
        CONFIG["llm_provider"] = args.llm_provider
    if args.no_cache:
        CONFIG["cache_enabled"] = False


def _standalone_command(args) -> bool:
    """Commands that need no scanner or banner. True when one ran."""
    if args.train_ml:
        sys.exit(_train_ml_cli(args.train_ml[0], args.train_ml[1],
                               args.ml_model_out or CONFIG["ml_model_path"]))

    if args.allow:
        _allow_file(args.allow, args.note, CONFIG["allowlist_path"])
        return True

    if args.update_rules:
        from core.rulepack import RulePackError, install_pack
        try:
            info = install_pack(args.update_rules, CONFIG["data_dir"], CONFIG["rulepack_public_keys"],
                                ENGINE_VERSION, allow_downgrade=args.allow_downgrade)
        except (RulePackError, OSError, ValueError) as e:
            print(f"❌ Rule pack rejected: {e}")
            sys.exit(1)
        print(f"✅ Rule pack {info['version']} installed ({info['files']} file(s)); "
              "used from the next scan.")
        return True

    # --fuzzy-hash is a standalone utility: it needs no DB, no API keys, no banner.
    if args.fuzzy_hash:
        _print_fuzzy_hash(args.fuzzy_hash)
        return True

    if args.gui:
        try:
            import gui
        except ImportError as e:
            print("The GUI needs the 'customtkinter' package. Install it with:")
            print("    pip install customtkinter")
            print(f"Details: {e}")
            return True
        gui.main()
        return True
    return False


def _is_utility_mode(args) -> bool:
    """A one-off maintenance command (no banner, no API-key warning)."""
    return bool(args.background or args.setup_autostart or args.remove_autostart
                    or args.create_shortcut or args.import_database
                    or args.deploy_canaries is not None or args.verify_canaries
                    or args.remove_canaries or args.quarantine or args.list_quarantine
                    or args.restore or args.clear_cache or args.export_key
                    or args.import_key or args.resume_pid or args.unlock_folders)


def _print_banner() -> None:
    print("=" * 56)
    print("  HYBRID RANSOMWARE DETECTION SYSTEM  v" + ENGINE_VERSION)
    print("  Multi-layer document & archive scanner")
    print("=" * 56)
    print(f"Platform:          {platform.system()} ({platform.machine()})")
    print(f"App directory:     {APP_DIR}")
    print(f"Log file:          {LOG_FILE}")
    print(f"Report directory:  {CONFIG['report_directory']}")
    print(f"Database path:     {CONFIG['kaggle_database_path']}")
    print("-" * 56)
    print("Detection layers:")
    print("  Cryptographic hashes ....... enabled")
    print("  Local hash database ........ enabled")
    print(f"  Fuzzy hashing (TLSH/ssdeep)  {'enabled' if FUZZY_AVAILABLE else 'unavailable (pip install python-tlsh ppdeep)'}")
    print(f"  VBA/XLM macro analysis ..... {'enabled' if OLEVBA_AVAILABLE else 'unavailable (pip install oletools)'}")
    print(f"  YARA structural rules ...... {'enabled' if YARA_AVAILABLE else 'unavailable (pip install yara-python)'}")
    print("  File integrity heuristics .. enabled")
    print(f"  Hidden content / injection . {'enabled' if DEFUSEDXML_AVAILABLE else 'PDF only (pip install defusedxml)'}")
    print(f"  Office external links ...... {'enabled' if DEFUSEDXML_AVAILABLE else 'RTF only (pip install defusedxml)'}")
    print("  ZIP archive inspection ..... enabled")
    print(f"  E-mail (.eml/.msg) ......... {'enabled' if MSG_AVAILABLE else '.eml only (pip install oletools)'}")
    _ml_model = Path(CONFIG.get("ml_model_path", ""))
    print("  ML classifier .............. " + (
        "disabled (ML_ENABLED=0)" if not CONFIG.get("ml_enabled", True) else
        f"trained model ({_ml_model.name})" if _ml_model.is_file() and SKLEARN_AVAILABLE
        else "rule engine (no trained model)"))
    print(f"  LLM semantic analysis ...... provider='{CONFIG.get('llm_provider', 'auto')}'")
    print(f"  VirusTotal reputation ...... {'key set' if CONFIG.get('virustotal_api_key') else 'no key (layer skipped)'}")
    print("=" * 56)


def _setup_command(args) -> bool:
    """Autostart, shortcut and database import. True when one ran."""
    if args.setup_autostart:
        setup_autostart()
        return True

    if args.remove_autostart:
        remove_autostart()
        return True

    if args.create_shortcut:
        create_desktop_shortcut()
        return True

    if args.import_database:
        outcome = import_hash_database(args.import_database)
        if outcome["error_kind"] == "missing_source":
            print(f"Error: Cannot find database file at {args.import_database}")
            return True
        if outcome["error_kind"] == "exception":
            print(f"❌ Error importing database: {outcome['message']}")
            return True
        print(f"✅ Successfully imported database from {args.import_database}")
        print(f"   Database saved to {outcome['destination']}")
        if outcome["missing_columns"]:
            print(f"⚠️  Missing required columns: {', '.join(outcome['missing_columns'])}")
            print("   The scanner may not work properly without these columns.")
        else:
            print(f"✅ Database format validated. Found {outcome['entries']} entries.")
        return True
    return False


def _release_containment(args) -> None:
    """--resume-pid / --unlock-folders: undo the canary containment actions."""
    from core.containment import resume, unlock_folders
    failed = False
    for raw in (args.resume_pid or "").split(","):
        if raw.strip():
            pid = int(raw)
            error = resume(pid)
            failed |= bool(error)
            print(f"❌ pid {pid}: {error}" if error else f"✅ Resumed pid {pid}.")
    if args.unlock_folders:
        restored, problems = unlock_folders(Path(CONFIG["containment_state_file"]))
        print(f"✅ Write access restored on {restored} file(s) / folder(s).")
        for p in problems:
            failed = True
            print(f"❌ {p}")
    if failed:
        sys.exit(1)


def _protection_command(args, scanner) -> bool:
    """Cache, canaries, key backup and quarantine. True when one ran."""
    # --- protection utilities -------------------------------------------------
    if args.clear_cache:
        removed = scanner.cache.clear() if scanner.cache is not None else 0
        print(f"✅ Cleared {removed} cached result(s).")
        return True

    if args.deploy_canaries is not None:
        targets = args.deploy_canaries or scanner.scan_dirs
        created = scanner.deploy_canaries(targets)
        for entry in created:
            print(f"✅ Canary planted: {entry['path']}")
        total = len(scanner.canaries.entries())
        print(f"{len(created)} new canary file(s); {total} registered in total.")
        print("The background mode (--background) checks them every "
              f"{CONFIG['canary_check_minutes']} minute(s).")
        return True

    if args.verify_canaries:
        report = scanner.check_canaries(notify=False)
        print(report.summary())
        for f in report.findings:
            print(f"  [{f.status}] {f.path}\n      {f.evidence}")
        sys.exit(2 if report.triggered else 0)

    if args.remove_canaries:
        print(f"✅ Removed {scanner.remove_canaries()} canary file(s).")
        return True

    if args.resume_pid or args.unlock_folders:
        _release_containment(args)
        return True

    if args.export_key or args.import_key:
        try:
            vault = scanner.quarantine_vault
            if args.export_key:
                phrase = _ask_passphrase(confirm=True)
                dest = vault.export_key(args.export_key, phrase)
                print(f"✅ Quarantine key backed up to {dest}")
                print(f"   fingerprint {vault.key_fingerprint()} - keep the file and the "
                      "passphrase in separate places.")
            if args.import_key:
                status = vault.import_key(args.import_key, _ask_passphrase(confirm=False),
                                          replace=args.replace_key)
                print(f"✅ Quarantine key {status.replace('-', ' ')} "
                      f"(fingerprint {vault.key_fingerprint()}).")
        except (QuarantineError, OSError) as e:
            print(f"❌ {e}")
            sys.exit(1)
        return True

    if args.quarantine or args.list_quarantine or args.restore:
        try:
            if args.quarantine:
                meta = scanner.quarantine_file(args.quarantine, reason="manual (CLI)")
                print(f"✅ Quarantined {meta['original_path']}")
                print(f"   vault id: {meta['id']}   (restore with --restore {meta['id']})")
                if not meta["original_removed"]:
                    print("⚠️  The original could not be deleted (file in use?). Delete it manually.")
            if args.restore:
                dest = scanner.quarantine_vault.restore(args.restore, destination=args.restore_to)
                print(f"✅ Restored to {dest}")
            if args.list_quarantine:
                _print_quarantine_list(scanner)
        except QuarantineError as e:
            print(f"❌ {e}")
            sys.exit(1)
        return True
    return False


def _mailbox_command(args, scanner) -> bool:
    """--scan-imap: one pass over the mailbox. True when it ran."""
    if not args.scan_imap:
        return False
    from core.mailbox import MailboxError
    try:
        report, run = scanner.scan_mailbox()
    except MailboxError as e:
        print(f"❌ {e}")
        sys.exit(1)
    print(report)
    if run.skipped_too_large:
        print(f"⚠️  {len(run.skipped_too_large)} message(s) over IMAP_MAX_MB were not scanned "
              f"(UIDs {', '.join(map(str, run.skipped_too_large[:10]))}).")
    if run.more_waiting:
        print("⚠️  More new messages are waiting; run --scan-imap again.")
    return True


def _scan_or_schedule(args, scanner) -> None:
    """--scan-file, --scan-now and the scheduled background loop."""
    # --scan-file: analyse exactly one file, print its verdict, and exit.
    if args.scan_file:
        if not os.path.exists(args.scan_file):
            print(f"Error: file not found: {args.scan_file}")
            return
        result = scanner.scan_file(args.scan_file)
        print(scanner.generate_report([result]))
        from core.outputs import deliver
        deliver([result], CONFIG)
        return

    if args.scan_now:
        print("Starting scan. This may take some time depending on the number of files...")
        report = scanner.run_scan()
        print("\n" + "=" * 56)
        print(report)
        print("=" * 56)
        print(f"\nDetailed reports saved to: {CONFIG['report_directory']}")
        if not args.background:
            input("\nPress Enter to exit...")

    if args.background or not args.scan_now:
        if not os.path.exists(CONFIG['kaggle_database_path']):
            print(f"⚠️  Malware-hash database not found at {CONFIG['kaggle_database_path']}")
            print("   Import one with the --import-database option, e.g.:")
            print(f"   python {Path(__file__).name} --import-database /path/to/your/dataset.csv")
            if not args.background:
                input("\nPress Enter to continue anyway...")

        logger.info(f"Scheduling scans every {CONFIG['scan_interval_hours']} hours.")
        schedule.every(CONFIG['scan_interval_hours']).hours.do(scanner.run_scan)
        # Always scheduled: with no canaries deployed the check is a no-op, and
        # canaries deployed later (from the GUI or CLI) are picked up live.
        minutes = max(1, int(CONFIG.get("canary_check_minutes", 5)))
        watcher = CanaryWatcher(
            scanner.canaries, lambda: scanner.check_canaries(touched=watcher.take_touched()))
        if scanner.canaries.entries():
            realtime = watcher.start()
            logger.info("Canary tripwires armed: %s, plus a check every %d minute(s).",
                        "watched in real time" if realtime else
                        ("no real-time watching (pip install watchdog)"
                         if not WATCHDOG_AVAILABLE else "real-time watching unavailable"),
                        minutes)
        schedule.every(minutes).minutes.do(scanner.check_canaries)
        # Canaries deployed or removed later (GUI or CLI) are picked up here.
        schedule.every(minutes).minutes.do(watcher.refresh)
        imap_minutes = int(CONFIG.get("imap_check_minutes", 0) or 0)
        if imap_minutes > 0 and CONFIG.get("imap_host"):
            logger.info("Mailbox %s checked every %d minute(s).", CONFIG["imap_folder"], imap_minutes)
            schedule.every(imap_minutes).minutes.do(scanner.scan_mailbox_safely)

        if not args.scan_now:
            scanner.run_scan()

        try:
            while True:
                schedule.run_pending()
                time.sleep(30)
        except KeyboardInterrupt:
            logger.info("Scanner stopped by user.")
        finally:
            watcher.stop()


def main():
    """Main entry point for the script."""
    # Output redirected to a file on Windows uses the ANSI code page (cp1252),
    # which cannot encode characters such as "→": replace them rather than crash.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = _build_parser().parse_args()
    _apply_overrides(args)
    if _standalone_command(args):
        return
    utility_mode = _is_utility_mode(args)
    if not utility_mode:
        _print_banner()
    if _setup_command(args):
        return
    # Warn if API keys are not configured (set them in a local .env file)
    if not utility_mode and (not CONFIG["chatgpt_api_key"] or not CONFIG["virustotal_api_key"]):
        print("⚠️  One or more API keys are missing. Copy .env.example to .env and add your keys.")
        print("    The local layers still work; the VirusTotal and cloud-LLM layers need keys.\n")
    scanner = RansomwareScanner(CONFIG)
    if _protection_command(args, scanner) or _mailbox_command(args, scanner):
        return
    _scan_or_schedule(args, scanner)


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()   # isolated scan workers in frozen builds
    main()
