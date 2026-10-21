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

import json
import logging
import os
import platform
import queue
import re
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

# --- Dependency guards (friendly errors instead of tracebacks) --------------

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    import tkinter.font as tkfont
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


def mono_family() -> str:
    return {"Windows": "Consolas", "Darwin": "Menlo"}.get(platform.system(),
                                                          "DejaVu Sans Mono")


def open_path(path) -> None:
    """Open a file or folder with the OS default application."""
    path = str(path)
    try:
        if platform.system() == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as e:
        messagebox.showerror("Open failed", f"Could not open:\n{path}\n\n{e}")


def mask_key(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return "not configured"
    if len(value) <= 10:
        return "configured"
    return f"{value[:3]}…{value[-4:]}"


def severity_color(score: float, malicious: bool) -> str:
    if malicious or score >= SEV_HIGH:
        return RED_SOFT
    if score >= SEV_MED:
        return AMBER_SOFT
    return OK


def severity_bar(score: float) -> str:
    filled = max(0, min(10, int(score + 0.5)))
    return "█" * filled + "─" * (10 - filled) + f"  {score:.1f}"


# Verdict bands mirror detectors/scoring.py. Colours map band -> palette.
VERDICT_COLORS = {
    "Critical": RED,
    "High": ORANGE,
    "Medium": AMBER_SOFT,
    "Low": ACCENT_SOFT,
    "Clean": MUTED,
}


def verdict_color(verdict: str) -> str:
    return VERDICT_COLORS.get(verdict, ACCENT_SOFT)


def result_verdict(result: dict) -> str:
    """The engine's verdict band, with a fallback for legacy (pre-v3) results."""
    v = result.get("verdict")
    if v:
        return v
    if not result.get("is_malicious"):
        return "Clean"
    sev = float(result.get("severity_score", 0) or 0)   # legacy 0-10
    if sev >= 8:
        return "Critical"
    if sev >= 5:
        return "High"
    if sev >= 2.5:
        return "Medium"
    return "Low"


def result_risk(result: dict) -> int:
    """The 0-100 risk score, derived from the legacy severity for old results."""
    if "risk_score" in result and result.get("risk_score") is not None:
        return int(result.get("risk_score") or 0)
    return int(round(float(result.get("severity_score", 0) or 0) * 10))


def risk_bar(risk: int) -> str:
    filled = max(0, min(10, int(round(risk / 10.0))))
    return "█" * filled + "─" * (10 - filled) + f"  {risk}/100"


# Plain-language names for the scoring indicators (detectors/scoring.py).
_REASON_LABELS = {
    "local_db_hit": "known malicious hash", "yara_match": "YARA rule match",
    "fuzzy_family_match": "similar to a known family", "macro_autoexec": "auto-run macro",
    "macro_critical": "macro runs or downloads code", "macro_suspicious": "suspicious macro",
    "macro_dropper_synergy": "macro dropper", "vba_stomping": "VBA stomping",
    "xlm_macros": "Excel 4.0 macros", "disguised_executable": "program disguised as a document",
    "encrypted_content": "content looks encrypted", "format_mismatch": "wrong file format",
    "prompt_injection": "hidden instructions to AI", "prompt_injection_phrasing": "AI-steering text",
    "hidden_content": "hidden text", "external_relationship": "loads content from the internet",
    "archive_zip_slip": "path traversal in archive", "archive_zip_bomb": "decompression bomb",
    "archive_double_extension": "double extension", "archive_rtlo_spoof": "spoofed file name",
    "archive_executable": "program inside archive", "archive_encrypted": "locked archive",
    "mail_dmarc_fail": "sender fails DMARC", "mail_auth_fail": "sender fails SPF/DKIM",
    "mail_display_name_spoof": "spoofed sender name", "mail_reply_to_mismatch": "replies diverted",
    "mail_deceptive_link": "deceptive link", "mail_risky_attachment": "risky attachment",
    "mail_double_extension": "double extension", "mail_rtlo_spoof": "spoofed file name",
    "mail_lure_subject": "pressure in subject", "html_smuggling": "HTML smuggling",
    "web_embedded_payload": "file hidden in page", "web_download_construct": "page builds a download",
    "svg_active_content": "active SVG", "web_credential_capture": "password form",
    "web_redirect": "redirects away", "js_obfuscation": "obfuscated script",
    "image_appended_payload": "payload after image", "elf_behaviour": "hostile Linux program",
    "elf_packed": "packed Linux program", "elf_no_section_table": "stripped Linux program",
    "qr_code_suspicious_url": "QR code to a risky link", "qr_code_url": "QR code with a link",
    "ml_classifier": "ML model", "virustotal": "VirusTotal engines", "llm_semantic": "LLM opinion",
    "script_behaviour": "script downloads / runs code", "script_encoded": "encoded script",
    "script_obfuscation": "obfuscated script",
}


def top_reasons(result: dict, limit: int = 2) -> str:
    """The strongest reasons behind a verdict, in words, e.g.
    'program disguised as a document · YARA rule match'."""
    contribs = (result.get("score_breakdown") or {}).get("contributions") or []
    out: List[str] = []
    for c in sorted(contribs, key=lambda c: -float(c.get("points", 0) or 0)):
        name = str(c.get("indicator", ""))
        where = ""
        if ":" in name:
            prefix, name = name.split(":", 1)
            where = " (attachment)" if prefix.startswith("mail") else " (inside)"
        label = _REASON_LABELS.get(name, name.replace("_", " ")) + where
        if label not in out:
            out.append(label)
        if len(out) >= limit:
            break
    return "  ·  ".join(out) if out else "nothing found"


# Markers the LLM layer emits when it did not actually analyse the document
# (no backend, no key, or nothing to read). Used to render a "skipped" state.
_LLM_SKIP_MARKERS = ("not configured", "layer skipped", "no llm backend",
                     "not installed", "no content or strings")


def llm_skipped(ai: dict) -> bool:
    detail = str(ai.get("details", "")).lower()
    return any(marker in detail for marker in _LLM_SKIP_MARKERS)


def layers_summary(result: dict) -> str:
    """Compact per-layer breakdown, e.g. 'DB– fuzzy– macro✓ yara✓ VT14/72 AI0.80'.

    Only the layers that actually ran contribute a token; unavailable/skipped
    layers are omitted so the line stays readable across the seven layers."""
    sr = result.get("scan_results", {})
    parts = []

    local = sr.get("local_database", {})
    parts.append("DB✓" if local.get("is_malicious") else "DB–")

    fuzzy = sr.get("fuzzy_hash", {})
    if fuzzy.get("available"):
        parts.append("fuzzy✓" if fuzzy.get("matched") else "fuzzy–")

    macro = sr.get("macro_analysis", {})
    if macro.get("available") and macro.get("has_macros"):
        # Surface the most serious macro finding compactly.
        if macro.get("critical"):
            parts.append("macro!")          # exec/download primitive present
        elif macro.get("autoexec"):
            parts.append("macro⚡")          # auto-run trigger present
        else:
            parts.append("macro✓")
    elif macro.get("available"):
        parts.append("macro–")

    yara = sr.get("yara", {})
    if yara.get("available"):
        n = len(yara.get("matches", []) or [])
        parts.append(f"yara✓{n}" if yara.get("matched") else "yara–")

    # v4 layers: only shown when they found something, to keep the row short.
    integ = sr.get("file_integrity", {})
    if integ.get("disguised_executable"):
        parts.append("exe!")             # executable behind a document extension
    elif integ.get("encrypted_likely"):
        parts.append("enc!")             # content looks encrypted (impact)
    elif integ.get("format_mismatch"):
        parts.append("fmt?")

    guard = sr.get("prompt_guard", {})
    if guard.get("injection_status") == "confirmed":
        parts.append("inj!")
    elif guard.get("injection_status") == "suspicious":
        parts.append("inj?")
    elif guard.get("hidden_text_found"):
        parts.append("hidden")

    if sr.get("relationships", {}).get("suspicious"):
        parts.append("ext!")             # remote template / OLE / UNC link

    arc = sr.get("archive", {})
    if arc:
        bad = sum(1 for m in arc.get("member_results", []) or []
                  if m.get("verdict", "Clean") != "Clean" or m.get("archive_flags"))
        parts.append(f"arc{arc.get('member_count', 0)}" + (f"!{bad}" if bad else ""))

    mail = sr.get("mail", {})
    if mail:
        bad = sum(1 for m in mail.get("attachment_results", []) or []
                  if m.get("verdict", "Clean") != "Clean")
        parts.append(f"mail{mail.get('attachment_count', 0)}" + (f"!{bad}" if bad else ""))
        if (mail.get("auth") or {}).get("failures") or mail.get("display_name_spoof"):
            parts.append("spoof!")       # authentication failure / display-name spoof

    web = sr.get("web", {})
    if web:
        if web.get("smuggling"):
            parts.append("smuggle!")     # HTML smuggling with an embedded payload
        elif web.get("svg_active") or web.get("credential_form") or web.get("payloads"):
            parts.append("web!")
        else:
            parts.append("web")

    if (sr.get("file_integrity") or {}).get("appended_payload"):
        parts.append("img+payload!")

    if sr.get("ml_classifier", {}).get("label") == "suspicious":
        parts.append(f"ml {float(sr['ml_classifier'].get('probability', 0)):.2f}")

    vt = sr.get("virustotal", {})
    if "not configured" in str(vt.get("details", "")):
        parts.append("VT off")
    elif vt.get("error"):
        parts.append("VT err")
    elif vt.get("not_found"):
        parts.append("VT new")
    elif vt.get("total_engines"):
        hits = vt.get("malicious_detections", 0) + vt.get("suspicious_detections", 0)
        parts.append(f"VT {hits}/{vt.get('total_engines', 0)}")

    ai = sr.get("chatgpt_analysis", {})
    if not llm_skipped(ai):
        parts.append(f"AI {float(ai.get('confidence', 0) or 0):.2f}")

    return "  ".join(parts)


def humanize_delta(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, m = seconds // 3600, (seconds % 3600) // 60
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m"
    return "<1m"


# --- Settings persistence -----------------------------------------------------

class SettingsStore:
    """Small JSON-backed store for GUI preferences (API keys stay in .env)."""

    DEFAULTS = {
        "scan_directories": None,      # seeded from RS.CONFIG on first run
        "file_extensions": None,
        "scan_interval_hours": None,
        "schedule_enabled": True,
    }

    def __init__(self):
        self.data = {}
        try:
            if SETTINGS_FILE.exists():
                self.data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logging.getLogger("RansomwareScanner.GUI").error(
                f"Could not read GUI settings: {e}")
        for key, default in self.DEFAULTS.items():
            self.data.setdefault(key, default)
        if not self.data["scan_directories"]:
            self.data["scan_directories"] = list(RS.CONFIG["scan_directories"])
        if not self.data["file_extensions"]:
            self.data["file_extensions"] = list(RS.CONFIG["file_extensions"])
        if not self.data["scan_interval_hours"]:
            self.data["scan_interval_hours"] = int(RS.CONFIG["scan_interval_hours"])

    def save(self) -> None:
        try:
            tmp = SETTINGS_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            tmp.replace(SETTINGS_FILE)
        except Exception as e:
            logging.getLogger("RansomwareScanner.GUI").error(
                f"Could not save GUI settings: {e}")

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value
        self.save()


# --- Logging bridge -----------------------------------------------------------

class QueueLogHandler(logging.Handler):
    """Forwards scanner log records to the UI thread through a queue."""

    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue
        self.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s  %(message)s",
                                            "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.log_queue.put_nowait(self.format(record))
        except Exception:
            pass


# --- Scan controller (worker thread) -------------------------------------------

class ScanController:
    """Owns the scan worker thread; reports back through the app event bus."""

    def __init__(self, bus: queue.Queue):
        self.bus = bus
        self.thread = None
        self.cancel_event = None
        self.running = False

    def start(self, scanner: "RS.RansomwareScanner", mode: str, target: str = None) -> bool:
        if self.running:
            return False
        self.running = True
        self.cancel_event = threading.Event()
        self.thread = threading.Thread(target=self._work, daemon=True,
                                       args=(scanner, mode, target))
        self.thread.start()
        return True

    def stop(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()

    def _work(self, scanner, mode, target):
        bus = self.bus
        try:
            callback = lambda done, total, path, res: bus.put(
                ("progress", done, total, path, res))
            if mode == "file":
                bus.put(("progress", 0, 1, target, None))
                results = [scanner.scan_file(target)]
                bus.put(("progress", 1, 1, target, results[0]))
            elif mode == "dir":
                results = scanner.scan_directory(target, callback, self.cancel_event)
            else:
                results = scanner.scan_all_directories(callback, self.cancel_event)

            cancelled = self.cancel_event.is_set()
            report_text = None
            if results and not cancelled:
                impact = scanner.last_impact if mode != "file" else None
                report_text = scanner.generate_report(results, impact=impact)
            bus.put(("scan_done", results, report_text, cancelled))
        except Exception as e:
            logging.getLogger("RansomwareScanner.GUI").exception("Scan failed")
            bus.put(("scan_error", str(e)))
        finally:
            self.running = False


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


# --- Result detail window --------------------------------------------------------

class DetailWindow(ctk.CTkToplevel):
    def __init__(self, app, result: dict):
        super().__init__(app, fg_color=BG)
        self.app = app
        self.result = result
        self.title(result.get("file_name", "Scan result"))
        self.geometry("640x560")
        self.minsize(560, 480)
        self.after(80, lambda: (self.lift(), self.focus_force()))

        outer = ctk.CTkScrollableFrame(self, fg_color=BG)
        outer.pack(fill="both", expand=True, padx=16, pady=16)
        self.scroll_area = outer

        verdict = result_verdict(result)
        risk = result_risk(result)
        vcolor = verdict_color(verdict)

        head = ctk.CTkFrame(outer, fg_color=PANEL, corner_radius=10,
                            border_width=1, border_color=BORDER)
        head.pack(fill="x")
        ctk.CTkLabel(head, text=result.get("file_name", "?"), font=app.font_h2,
                     text_color=TEXT, anchor="w").pack(fill="x", padx=14, pady=(12, 0))
        ctk.CTkLabel(head, text=result.get("file_path", ""), font=app.font_mono_small,
                     text_color=MUTED, anchor="w", wraplength=560,
                     justify="left").pack(fill="x", padx=14)
        vrow = ctk.CTkFrame(head, fg_color="transparent")
        vrow.pack(fill="x", padx=14, pady=(8, 12))
        ctk.CTkLabel(vrow, text=risk_bar(risk), font=app.font_mono,
                     text_color=vcolor).pack(side="left")
        ctk.CTkLabel(vrow, text=f"   {verdict}", font=app.font_bold,
                     text_color=vcolor).pack(side="left")

        def info_section(title):
            sec = Section(outer, title, app)
            sec.pack(fill="x", pady=(12, 0))
            return sec.body

        body = info_section("File")
        size_kb = (result.get("file_size", 0) or 0) / 1024
        for label, value in [("Scanned", result.get("scan_time", "—")),
                             ("Size", f"{size_kb:,.1f} KB"),
                             ("MD5", result.get("md5_hash", "—")),
                             ("SHA-256", result.get("sha256_hash", "—"))]:
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            ctk.CTkLabel(row, text=label, width=70, anchor="w",
                         text_color=MUTED, font=app.font_small).pack(side="left")
            ctk.CTkLabel(row, text=value, anchor="w", text_color=TEXT,
                         font=app.font_mono_small, wraplength=440,
                         justify="left").pack(side="left", fill="x", expand=True)

        sr = result.get("scan_results", {})

        local = sr.get("local_database", {})
        body = info_section("Layer 1 — local hash database")
        flagged = local.get("is_malicious")
        ctk.CTkLabel(body, text="Match found in local malware database" if flagged
                     else "Not found in local database",
                     text_color=RED_SOFT if flagged else ACCENT_SOFT,
                     font=app.font_ui, anchor="w").pack(fill="x", padx=14, pady=10)

        # --- Layer 2: fuzzy / structural hashing -----------------------------
        fuzzy = sr.get("fuzzy_hash", {})
        body = info_section("Layer 2 — fuzzy / structural hashing")
        if not fuzzy.get("available", False):
            ctk.CTkLabel(body, text="Skipped — fuzzy-hash libraries not installed "
                                    "(python-tlsh / ppdeep).",
                         text_color=AMBER_SOFT, font=app.font_ui,
                         anchor="w").pack(fill="x", padx=14, pady=10)
        else:
            matched = fuzzy.get("matched")
            if matched:
                fams = sorted({m.get("family", "") for m in fuzzy.get("matches", [])
                               if m.get("family")})
                conf = float(fuzzy.get("best_confidence", 0) or 0)
                msg = (f"Structural match to {', '.join(fams) or 'a known family'} "
                       f"(confidence {conf:.2f})")
            else:
                msg = fuzzy.get("detail") or "No structural match in the signature database."
            ctk.CTkLabel(body, text=msg,
                         text_color=RED_SOFT if matched else ACCENT_SOFT,
                         font=app.font_ui, anchor="w", wraplength=540,
                         justify="left").pack(fill="x", padx=14, pady=(10, 2))
            digest_bits = []
            if fuzzy.get("tlsh"):
                digest_bits.append(f"TLSH    {fuzzy['tlsh']}")
            if fuzzy.get("ssdeep"):
                digest_bits.append(f"ssdeep  {fuzzy['ssdeep']}")
            if digest_bits:
                ctk.CTkLabel(body, text="\n".join(digest_bits), text_color=MUTED,
                             font=app.font_mono_small, anchor="w", wraplength=540,
                             justify="left").pack(fill="x", padx=14, pady=(0, 10))
            else:
                ctk.CTkLabel(body, text="").pack(pady=2)

        # --- Layer 3: VBA macro analysis -------------------------------------
        macro = sr.get("macro_analysis", {})
        body = info_section("Layer 3 — VBA macro analysis")
        if not macro.get("available", False):
            ctk.CTkLabel(body, text="Skipped — oletools not installed.",
                         text_color=AMBER_SOFT, font=app.font_ui,
                         anchor="w").pack(fill="x", padx=14, pady=10)
        elif not macro.get("has_macros"):
            ctk.CTkLabel(body, text=macro.get("detail") or "No VBA macros found.",
                         text_color=ACCENT_SOFT, font=app.font_ui,
                         anchor="w").pack(fill="x", padx=14, pady=10)
        else:
            autoexec = macro.get("autoexec") or []
            critical = macro.get("critical") or []
            suspicious = macro.get("suspicious") or []
            iocs = macro.get("iocs") or []
            dropper = bool(autoexec and critical)
            headline = ("Auto-executing macro with an exec/download primitive "
                        "(classic dropper pattern)" if dropper else "Macros present")
            ctk.CTkLabel(body, text=headline,
                         text_color=RED_SOFT if (critical or dropper) else AMBER_SOFT,
                         font=app.font_ui, anchor="w", wraplength=540,
                         justify="left").pack(fill="x", padx=14, pady=(10, 2))
            for label, items in [("Auto-run", autoexec), ("Critical", critical),
                                 ("Suspicious", suspicious[:8]), ("IOCs", iocs[:6])]:
                if items:
                    ctk.CTkLabel(body, text=f"{label}: " + ", ".join(map(str, items)),
                                 text_color=MUTED, font=app.font_small, anchor="w",
                                 wraplength=540, justify="left").pack(fill="x", padx=14)
            if macro.get("vba_stomping"):
                ctk.CTkLabel(body, text="VBA stomping: the compiled P-code differs from the "
                                        "visible source (deliberate evasion).",
                             text_color=RED_SOFT, font=app.font_small, anchor="w",
                             wraplength=540, justify="left").pack(fill="x", padx=14)
            if macro.get("xlm_macros"):
                ctk.CTkLabel(body, text="Excel 4.0 (XLM) macro sheet(s): "
                                        + ", ".join(macro.get("xlm_evidence") or []),
                             text_color=RED_SOFT, font=app.font_small, anchor="w",
                             wraplength=540, justify="left").pack(fill="x", padx=14)
            ctk.CTkLabel(body, text="").pack(pady=2)

        # --- Layer 4: YARA rules ---------------------------------------------
        yara = sr.get("yara", {})
        body = info_section("Layer 4 — YARA rules")
        if not yara.get("available", False):
            ctk.CTkLabel(body, text="Skipped — yara-python not installed.",
                         text_color=AMBER_SOFT, font=app.font_ui,
                         anchor="w").pack(fill="x", padx=14, pady=10)
        elif not yara.get("matched"):
            ctk.CTkLabel(body, text=yara.get("detail") or "No YARA rules matched.",
                         text_color=ACCENT_SOFT, font=app.font_ui,
                         anchor="w").pack(fill="x", padx=14, pady=10)
        else:
            top = yara.get("top_severity", "medium")
            matches = yara.get("matches", []) or []
            ctk.CTkLabel(body, text=f"{len(matches)} rule(s) matched · top severity: {top}",
                         text_color=RED_SOFT, font=app.font_ui,
                         anchor="w").pack(fill="x", padx=14, pady=(10, 2))
            for m in matches:
                desc = m.get("description", "")
                line = f"•  {m.get('rule', '?')}  [{m.get('severity', 'medium')}]"
                if desc:
                    line += f" — {desc}"
                ctk.CTkLabel(body, text=line, text_color=MUTED, font=app.font_small,
                             anchor="w", wraplength=540,
                             justify="left").pack(fill="x", padx=14)
            ctk.CTkLabel(body, text="").pack(pady=2)

        def line(body, text, color=MUTED, font=None, pad=(0, 0)):
            ctk.CTkLabel(body, text=text, text_color=color, font=font or app.font_small,
                         anchor="w", wraplength=540, justify="left").pack(fill="x", padx=14,
                                                                          pady=pad)

        # --- Layer 5: file integrity -----------------------------------------
        integ = sr.get("file_integrity")
        if integ is not None:
            body = info_section("Layer 5 — file integrity (disguise / encryption)")
            flagged = (integ.get("disguised_executable") or integ.get("encrypted_likely")
                       or integ.get("format_mismatch"))
            line(body, integ.get("detail") or "—", RED_SOFT if flagged else ACCENT_SOFT,
                 app.font_ui, (10, 2))
            line(body, f"Detected format: {integ.get('detected_format', '?')}   ·   "
                       f"entropy {float(integ.get('sample_entropy', 0) or 0):.3f} bits/byte   ·   "
                       f"chi² {float(integ.get('sample_chi_square', 0) or 0):.0f}")
            for note in integ.get("notes", []) or []:
                line(body, note, AMBER_SOFT)
            line(body, "", pad=(0, 4))

        # --- Layer 6: hidden content / prompt injection ----------------------
        guard = sr.get("prompt_guard")
        if guard is not None:
            body = info_section("Layer 6 — hidden content & prompt injection")
            status = guard.get("injection_status", "none")
            hit = status != "none" or guard.get("hidden_text_found")
            line(body, guard.get("detail") or "—",
                 RED_SOFT if status == "confirmed" else (AMBER_SOFT if hit else ACCENT_SOFT),
                 app.font_ui, (10, 2))
            for snippet in (guard.get("hidden_text_snippets") or [])[:4]:
                line(body, f"hidden: “{snippet[:160]}”")
            line(body, "", pad=(0, 4))

        # --- Layer 7: Office external relationships --------------------------
        rels = sr.get("relationships")
        if rels is not None:
            body = info_section("Layer 7 — Office external links (template / OLE / UNC)")
            line(body, rels.get("detail") or "—",
                 RED_SOFT if rels.get("suspicious") else ACCENT_SOFT, app.font_ui, (10, 2))
            for f in (rels.get("findings") or [])[:6]:
                line(body, f"•  {f.get('kind')}  →  {RS.defang(str(f.get('target', '')))}")
            line(body, "", pad=(0, 4))

        # --- Layer 8: archive contents ----------------------------------------
        arc = sr.get("archive")
        if arc:
            body = info_section("Layer 8 — archive contents")
            bad = (arc.get("zip_bomb") or arc.get("zip_slip") or arc.get("executable_members")
                   or arc.get("encrypted_unreadable"))
            line(body, arc.get("detail") or "—", RED_SOFT if bad else ACCENT_SOFT,
                 app.font_ui, (10, 4))
            for m in (arc.get("member_results") or [])[:30]:
                v = m.get("verdict", "Clean")
                name = str(m.get("name", "?")).split("!/", 1)[-1]
                flags = m.get("archive_flags") or []
                tag = f"   ← {', '.join(f.replace('_', ' ') for f in flags)}" if flags else ""
                color = RED_SOFT if flags and v == "Clean" else verdict_color(v)
                line(body, f"{v:<8}  {m.get('risk_score', 0):>3}/100   {name}{tag}",
                     color, app.font_mono_small)
            if arc.get("not_scanned_budget"):
                line(body, f"+{arc['not_scanned_budget']} more member(s) listed but not "
                           f"deep-scanned (per-archive budget).", AMBER_SOFT)
            line(body, "", pad=(0, 4))
        elif integ is not None:          # v4 result for a non-archive file
            body = info_section("Layer 8 — archive contents")
            line(body, "Not an archive.", ACCENT_SOFT, app.font_ui, (10, 10))

        # --- v4.1: e-mail (MailGuard) -----------------------------------------
        mail = sr.get("mail")
        if mail:
            body = info_section("E-mail — sender, links & attachments (MailGuard)")
            auth = mail.get("auth") or {}
            bad = (auth.get("failures") or mail.get("display_name_spoof")
                   or mail.get("reply_to_mismatch") or mail.get("deceptive_links")
                   or mail.get("executable_attachments"))
            line(body, mail.get("detail") or "—", RED_SOFT if bad else ACCENT_SOFT,
                 app.font_ui, (10, 4))
            if mail.get("subject"):
                line(body, f"Subject:  {mail['subject'][:140]}")
            if auth.get("ignored_headers"):
                line(body, f"{auth['ignored_headers']} lower authentication header(s) ignored "
                           "(written by the sender, not your mail server).", AMBER_SOFT)
            for link in (mail.get("deceptive_links") or [])[:4]:
                line(body, f"•  {RS.defang(link)}", RED_SOFT)
            for a in (mail.get("attachment_results") or [])[:30]:
                v = a.get("verdict", "Clean")
                name = str(a.get("name", "?")).split("!/", 1)[-1]
                line(body, f"{v:<8}  {a.get('risk_score', 0):>3}/100   {name}",
                     verdict_color(v), app.font_mono_small)
            if mail.get("attachments_skipped") or mail.get("not_scanned_budget"):
                line(body, f"{mail.get('attachments_skipped', 0) + mail.get('not_scanned_budget', 0)}"
                           " attachment(s) not deep-scanned (limits / embedded objects).", AMBER_SOFT)
            line(body, "", pad=(0, 4))

        # --- v4.4: web page (HTML smuggling, active SVG, phishing form) -------
        web = sr.get("web")
        if web:
            body = info_section("Web page — HTML smuggling, active SVG, phishing")
            bad = (web.get("smuggling") or web.get("payloads") or web.get("svg_active")
                   or web.get("credential_form"))
            detail = re.sub(r"https?://[^\s;,'\")]+", lambda m: RS.defang(m.group(0)),
                            web.get("detail") or "—")
            line(body, detail, RED_SOFT if bad else ACCENT_SOFT, app.font_ui, (10, 4))
            for url in (web.get("redirects") or [])[:4]:
                line(body, f"•  redirects to {RS.defang(url)}", AMBER_SOFT)
            for m in (web.get("payload_results") or [])[:5]:
                v = m.get("verdict", "Clean")
                name = str(m.get("name", "?")).split("!/", 1)[-1]
                line(body, f"{v:<8}  {m.get('risk_score', 0):>3}/100   {name}",
                     verdict_color(v), app.font_mono_small)
            line(body, "", pad=(0, 4))

        # --- v4.1: ML classifier --------------------------------------------
        ml = sr.get("ml_classifier")
        if ml:
            body = info_section("ML classifier — byte & PE structure (statistical)")
            susp = ml.get("label") == "suspicious"
            line(body, f"{ml.get('label', '?').capitalize()}  ·  p(suspicious) = "
                       f"{float(ml.get('probability', 0)):.2f}  ·  "
                       f"{'trained model ' + str(ml.get('model')) if ml.get('model') != 'rules' else 'rule engine (no trained model)'}",
                 RED_SOFT if susp else ACCENT_SOFT, app.font_ui, (10, 4))
            for why in (ml.get("indicators") or [])[:4]:
                line(body, f"•  {why}")
            line(body, "", pad=(0, 4))

        # --- Layer 9: VirusTotal ---------------------------------------------
        vt = sr.get("virustotal", {})
        body = info_section("Layer 9 — VirusTotal reputation")
        if "not configured" in str(vt.get("details", "")):
            ctk.CTkLabel(body, text="Skipped — API key not configured (add it in Settings).",
                         text_color=AMBER_SOFT, font=app.font_ui,
                         anchor="w").pack(fill="x", padx=14, pady=10)
        elif vt.get("not_found"):
            ctk.CTkLabel(body, text=vt.get("details") or "Unknown to VirusTotal.",
                         text_color=MUTED, font=app.font_ui, anchor="w", wraplength=540,
                         justify="left").pack(fill="x", padx=14, pady=10)
        else:
            hits = vt.get("malicious_detections", 0) + vt.get("suspicious_detections", 0)
            total = vt.get("total_engines", 0)
            ratio = float(vt.get("detection_ratio", 0) or 0)
            ctk.CTkLabel(body, text=f"{hits} of {total} engines flagged this file "
                                    f"(detection ratio {ratio:.2f})",
                         text_color=RED_SOFT if hits else ACCENT_SOFT,
                         font=app.font_ui, anchor="w").pack(fill="x", padx=14, pady=(10, 4))
            if vt.get("error"):
                ctk.CTkLabel(body, text=f"Error: {vt['error']}", text_color=AMBER_SOFT,
                             font=app.font_small, anchor="w",
                             wraplength=540, justify="left").pack(fill="x", padx=14)
            if vt.get("permalink"):
                ctk.CTkButton(body, text="Open VirusTotal report", height=30,
                              fg_color="transparent", hover_color=PANEL_2,
                              border_width=1, border_color=BORDER_2, text_color=BLUE,
                              font=app.font_small,
                              command=lambda: webbrowser.open(vt["permalink"])
                              ).pack(anchor="w", padx=14, pady=(2, 10))
            else:
                ctk.CTkLabel(body, text="").pack(pady=2)

        # --- Layer 6: LLM semantic analysis ----------------------------------
        ai = sr.get("chatgpt_analysis", {})
        body = info_section("Layer 10 — LLM semantic analysis")
        if llm_skipped(ai):
            ctk.CTkLabel(body, text="Skipped — no LLM backend available "
                                    "(start a local Ollama or set an OpenAI key).",
                         text_color=AMBER_SOFT, font=app.font_ui,
                         anchor="w").pack(fill="x", padx=14, pady=10)
        else:
            conf = float(ai.get("confidence", 0) or 0)
            ctk.CTkLabel(body, text=f"Confidence: {conf:.2f} — "
                                    f"{'flagged as suspicious' if ai.get('is_malicious') else 'no ransomware indicators'}",
                         text_color=RED_SOFT if ai.get("is_malicious") else ACCENT_SOFT,
                         font=app.font_ui, anchor="w").pack(fill="x", padx=14, pady=(10, 2))
            elements = ai.get("suspicious_elements") or []
            if elements:
                ctk.CTkLabel(body, text="Suspicious elements: " + ", ".join(map(str, elements)),
                             text_color=AMBER_SOFT, font=app.font_small, anchor="w",
                             wraplength=540, justify="left").pack(fill="x", padx=14)
            details = str(ai.get("details", "")).strip()
            if details:
                ctk.CTkLabel(body, text=details, text_color=MUTED, font=app.font_small,
                             anchor="w", wraplength=540,
                             justify="left").pack(fill="x", padx=14, pady=(2, 10))
            else:
                ctk.CTkLabel(body, text="").pack(pady=2)

        # --- Why this verdict: weighted score breakdown ----------------------
        breakdown = result.get("score_breakdown", {})
        contribs = breakdown.get("contributions", []) or []
        if contribs:
            body = info_section("Score breakdown — why this verdict")
            for c in contribs:
                rowf = ctk.CTkFrame(body, fg_color="transparent")
                rowf.pack(fill="x", padx=14, pady=2)
                ctk.CTkLabel(rowf, text=f"+{float(c.get('points', 0)):>5.1f}", width=52,
                             anchor="w", text_color=TEXT,
                             font=app.font_mono_small).pack(side="left")
                ctk.CTkLabel(rowf, text=f"[{c.get('category', '?')}] {c.get('indicator', '?')}",
                             anchor="w", text_color=TEXT, font=app.font_small,
                             wraplength=440, justify="left").pack(side="left",
                                                                  fill="x", expand=True)
            totals = breakdown.get("category_totals", {})
            tnz = ", ".join(f"{k} {v:g}" for k, v in totals.items() if v)
            ctk.CTkLabel(body, text=f"Category totals: {tnz}" if tnz else "",
                         text_color=MUTED, font=app.font_small,
                         anchor="w").pack(fill="x", padx=14, pady=(4, 10))

        actions = ctk.CTkFrame(outer, fg_color="transparent")
        actions.pack(fill="x", pady=(14, 0))
        ctk.CTkButton(actions, text="Show in folder", height=32, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=lambda: open_path(Path(result.get("file_path", ".")).parent)
                      ).pack(side="left")
        ctk.CTkButton(actions, text="Copy SHA-256", height=32, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self._copy_sha).pack(side="left", padx=8)
        path = str(result.get("file_path", ""))
        if "!/" not in path and os.path.isfile(path):
            self.quarantine_button = ctk.CTkButton(
                actions, text="Quarantine file", height=32, font=app.font_small,
                fg_color="transparent", hover_color=PANEL_2, border_width=1,
                border_color=RED, text_color=RED_SOFT, command=self._quarantine)
            self.quarantine_button.pack(side="right")

    def _copy_sha(self):
        self.clipboard_clear()
        self.clipboard_append(self.result.get("sha256_hash", ""))

    def _quarantine(self, confirm: bool = True):
        path = str(self.result.get("file_path", ""))
        if confirm and not messagebox.askyesno(
                "Quarantine file",
                f"Move this file into the encrypted quarantine vault?\n\n{path}\n\n"
                "It is encrypted with AES-256-GCM and removed from its folder. "
                "You can restore it from the Protection page.", parent=self):
            return
        verdict = result_verdict(self.result)
        try:
            meta = self.app.scanner.quarantine_file(
                path, reason=f"manual (GUI): {verdict}, risk {result_risk(self.result)}/100",
                result=self.result)
        except Exception as e:
            messagebox.showerror("Quarantine failed", str(e), parent=self)
            return
        self.result["quarantine"] = {"id": meta["id"], "vault_file": meta["vault_file"],
                                     "original_removed": meta["original_removed"]}
        self.quarantine_button.configure(state="disabled", text=f"Quarantined · {meta['id']}")
        self.app.gui_log.warning(f"Quarantined from GUI: {path} -> vault id {meta['id']}")
        self.app.refresh_protection_views()
        if confirm:
            messagebox.showinfo("Quarantined", f"Moved to the vault (id {meta['id']}).",
                                parent=self)


# --- Pages ------------------------------------------------------------------------

class BasePage(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color="transparent")
        self.app = app

    def on_show(self):
        pass


class DashboardPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        self.row_results = {}

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x")
        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(left, text="Dashboard", font=app.font_h1,
                     text_color=TEXT, anchor="w").pack(fill="x")
        self.meta_label = ctk.CTkLabel(left, text="", font=app.font_small,
                                       text_color=MUTED, anchor="w")
        self.meta_label.pack(fill="x")

        self.stop_button = ctk.CTkButton(header, text="Stop", width=86, height=34,
                                         fg_color="transparent", hover_color=PANEL_2,
                                         border_width=1, border_color=RED,
                                         text_color=RED_SOFT, font=app.font_bold,
                                         command=app.stop_scan)
        self.scan_button = ctk.CTkButton(header, text="Scan now", width=112, height=34,
                                         fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                         text_color=ON_ACCENT, font=app.font_bold,
                                         command=app.start_full_scan)
        self.scan_button.pack(side="right")

        cards = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8,
                             border_width=1, border_color=BORDER)
        cards.app = app
        cards.pack(fill="x", pady=(14, 0))
        cards.grid_columnconfigure((0, 1, 2), weight=1, uniform="cards")
        # Row 0 — technical layers (exact + structural)
        self.card_db = StatCard(cards, "Hash database")
        self.card_db.grid(row=0, column=0, sticky="nsew", pady=(4, 0))
        self.card_fuzzy = StatCard(cards, "Fuzzy hashing")
        self.card_fuzzy.grid(row=0, column=1, sticky="nsew", pady=(4, 0))
        self.card_macro = StatCard(cards, "Macro analysis")
        self.card_macro.grid(row=0, column=2, sticky="nsew", pady=(4, 0))
        # Row 1 — structural / reputation / semantic
        self.card_yara = StatCard(cards, "YARA rules")
        self.card_yara.grid(row=1, column=0, sticky="nsew")
        self.card_vt = StatCard(cards, "VirusTotal")
        self.card_vt.grid(row=1, column=1, sticky="nsew")
        self.card_ai = StatCard(cards, "LLM analysis")
        self.card_ai.grid(row=1, column=2, sticky="nsew")
        # Row 2 — v4 heuristics + host protection
        self.card_heur = StatCard(cards, "Heuristic layers")
        self.card_heur.grid(row=2, column=0, sticky="nsew", pady=(0, 4))
        self.card_canary = StatCard(cards, "Canary tripwires")
        self.card_canary.grid(row=2, column=1, sticky="nsew", pady=(0, 4))
        self.card_vault = StatCard(cards, "Quarantine vault")
        self.card_vault.grid(row=2, column=2, sticky="nsew", pady=(0, 4))

        prog = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=10,
                            border_width=1, border_color=BORDER)
        prog.pack(fill="x", pady=(12, 0))
        prow = ctk.CTkFrame(prog, fg_color="transparent")
        prow.pack(fill="x", padx=14, pady=(10, 4))
        self.progress_file = ctk.CTkLabel(prow, text="No scan running", anchor="w",
                                          font=app.font_mono_small, text_color=MUTED)
        self.progress_file.pack(side="left", fill="x", expand=True)
        self.progress_count = ctk.CTkLabel(prow, text="", anchor="e",
                                           font=app.font_small, text_color=MUTED)
        self.progress_count.pack(side="right")
        self.progress_bar = ctk.CTkProgressBar(prog, height=7, corner_radius=4,
                                               fg_color=BORDER, progress_color=ACCENT_SOFT)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=14, pady=(0, 12))

        table_frame = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=10,
                                   border_width=1, border_color=BORDER)
        table_frame.pack(fill="both", expand=True, pady=(12, 0))
        trow = ctk.CTkFrame(table_frame, fg_color="transparent")
        trow.pack(fill="x", padx=14, pady=(10, 6))
        self.results_title = ctk.CTkLabel(trow, text="Latest results", font=app.font_bold,
                                          text_color=TEXT, anchor="w")
        self.results_title.pack(side="left")
        ctk.CTkButton(trow, text="Open reports folder", height=28, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=BLUE,
                      command=lambda: open_path(app.scanner.report_dir)
                      ).pack(side="right")

        tree_holder = ctk.CTkFrame(table_frame, fg_color="transparent")
        tree_holder.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.tree = ttk.Treeview(tree_holder, columns=("file", "verdict", "risk", "why"),
                                 show="headings", style="RD.Treeview", selectmode="browse")
        for col, label, width, stretch in [("file", "File", 220, False),
                                           ("verdict", "Verdict", 90, False),
                                           ("risk", "Risk", 70, False),
                                           ("why", "Main reasons", 420, True)]:
            self.tree.heading(col, text=label, anchor="w")
            self.tree.column(col, width=width, stretch=stretch, anchor="w")
        scrollbar = ctk.CTkScrollbar(tree_holder, command=self.tree.yview,
                                     fg_color="transparent", button_color=BORDER_2,
                                     button_hover_color=MUTED)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        for verdict, color in VERDICT_COLORS.items():
            self.tree.tag_configure(verdict, foreground=color if verdict != "Clean" else TEXT)
        self.tree.bind("<Double-1>", self._open_detail)

        self.empty_label = ctk.CTkLabel(table_frame,
                                        text="No scans yet — press “Scan now” to run your first scan.",
                                        font=app.font_small, text_color=MUTED)

    # -- table helpers ---------------------------------------------------------

    def clear_results(self, title="Scan in progress…"):
        self.row_results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results_title.configure(text=title)
        self.empty_label.place_forget()

    def add_result(self, result: dict):
        verdict = result_verdict(result)
        risk = result_risk(result)
        iid = self.tree.insert("", "end", values=(
            result.get("file_name", "?"),
            verdict,
            f"{risk}",
            top_reasons(result) if verdict != "Clean" else "",
        ), tags=(verdict if verdict in VERDICT_COLORS else "Clean",))
        self.row_results[iid] = result
        self.tree.see(iid)

    def load_results(self, results, title):
        self.clear_results(title)
        for result in sorted(results, key=lambda r: -result_risk(r)):
            self.add_result(result)
        if not results:
            self.empty_label.place(relx=0.5, rely=0.55, anchor="center")

    def _open_detail(self, _event):
        selection = self.tree.selection()
        if selection and selection[0] in self.row_results:
            DetailWindow(self.app, self.row_results[selection[0]])

    # -- refresh ----------------------------------------------------------------

    def on_show(self):
        self.refresh_cards()
        self.refresh_meta()

    def refresh_meta(self):
        app = self.app
        last = app.last_scan_text()
        nxt = app.next_scan_text()
        self.meta_label.configure(text=f"Last scan {last}  ·  {nxt}")

    def refresh_cards(self):
        app = self.app
        scanner = app.scanner
        count = len(scanner.hash_database)
        db_exists = os.path.exists(scanner.kaggle_db_path)
        if count:
            self.card_db.update_card(f"{count:,}", "Loaded", True)
        elif db_exists:
            self.card_db.update_card("0", "No malicious rows", False)
        else:
            self.card_db.update_card("—", "Not imported", False)

        # Fuzzy hashing — available libs + loaded signature count.
        if RS.FUZZY_AVAILABLE:
            sigs = len(getattr(scanner.fuzzy_hasher, "signatures", []) or [])
            self.card_fuzzy.update_card(
                f"{sigs} sig" + ("s" if sigs != 1 else ""),
                "TLSH + ssdeep" if sigs else "No signatures", bool(sigs))
        else:
            self.card_fuzzy.update_card("—", "Libs missing", False)

        # Macro analysis — availability of olevba.
        if RS.OLEVBA_AVAILABLE:
            self.card_macro.update_card("olevba", "Ready", True)
        else:
            self.card_macro.update_card("—", "Libs missing", False)

        # YARA — availability + number of compiled rule files.
        if RS.YARA_AVAILABLE:
            n_rules = getattr(scanner.yara_engine, "_rules_count", 0)
            self.card_yara.update_card(
                f"{n_rules} file" + ("s" if n_rules != 1 else ""),
                "Compiled" if n_rules else "No rules", bool(n_rules))
        else:
            self.card_yara.update_card("—", "Libs missing", False)

        vt_key = scanner.config.get("virustotal_api_key")
        self.card_vt.update_card("API v3", "Connected" if vt_key else "Key missing",
                                 bool(vt_key))

        # LLM — reflect the active backend posture (local vs cloud vs off).
        value, status, ok = self._llm_card_state(scanner)
        self.card_ai.update_card(value, status, ok)

        # Heuristics: integrity, hidden content, external links, archives,
        # e-mail and the ML classifier.
        names = ["integrity"]
        if RS.DEFUSEDXML_AVAILABLE:
            names += ["hidden", "links"]
        names += ["archives", "mail"]
        ml = getattr(scanner, "ml", None)
        if ml is not None:
            names.append("ML model" if ml.has_model else "ML rules")
        ok = RS.DEFUSEDXML_AVAILABLE
        self.card_heur.update_card(f"{len(names)} active",
                                   " · ".join(names) if ok else "install defusedxml", ok)

        # Canaries: deployed count + last verification.
        deployed = len(scanner.canaries.entries())
        report = getattr(app, "last_canary_report", None)
        if not deployed:
            self.card_canary.update_card("—", "Not deployed", False)
        elif report is not None and report.triggered:
            self.card_canary.update_card(f"{deployed} files", "TRIGGERED", False, alert=True)
        else:
            self.card_canary.update_card(f"{deployed} files",
                                         "Armed" if report is not None else "Armed · not checked",
                                         True)

        # Quarantine vault.
        try:
            items = len(scanner.quarantine_vault.list())
            self.card_vault.update_card(f"{items} item" + ("s" if items != 1 else ""),
                                        "AES-256-GCM", True)
        except Exception:
            self.card_vault.update_card("—", "install cryptography", False)

    @staticmethod
    def _llm_card_state(scanner):
        """Map the active LLM backend to (value, status, ok) for its card."""
        backend = getattr(scanner, "llm_backend", None)
        name = backend.__class__.__name__ if backend else ""
        if "Ollama" in name:
            return (getattr(backend, "model", "ollama"), "Local · OPSEC", True)
        if "OpenAI" in name:
            return (scanner.config.get("openai_model", "openai"), "Cloud", True)
        return ("—", "Disabled", False)


class ScanPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        ctk.CTkLabel(self, text="Scan", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(self, text="Choose what to scan. Results appear on the Dashboard.",
                     font=app.font_small, text_color=MUTED, anchor="w").pack(fill="x")

        sec = Section(self, "Monitored directories", app)
        sec.pack(fill="x", pady=(14, 0))
        self.dir_list = ctk.CTkFrame(sec.body, fg_color="transparent")
        self.dir_list.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkButton(sec.body, text="+  Add directory…", height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=ACCENT_SOFT,
                      command=self._add_directory).pack(anchor="w", padx=14, pady=(0, 12))

        sec = Section(self, "File types", app)
        sec.pack(fill="x", pady=(14, 0))
        ext_row = ctk.CTkFrame(sec.body, fg_color="transparent")
        ext_row.pack(fill="x", padx=14, pady=12)
        self.ext_vars = {}
        for i, ext in enumerate(RS.SUPPORTED_EXTENSIONS):
            var = ctk.BooleanVar(value=ext in app.settings["file_extensions"])
            self.ext_vars[ext] = var
            ctk.CTkCheckBox(ext_row, text=ext, variable=var, font=app.font_ui, width=90,
                            text_color=TEXT, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                            border_color=BORDER_2, checkmark_color=ON_ACCENT,
                            command=self._extensions_changed
                            ).grid(row=i // 7, column=i % 7, sticky="w", pady=3)

        sec = Section(self, "Run", app)
        sec.pack(fill="x", pady=(14, 0))
        run_row = ctk.CTkFrame(sec.body, fg_color="transparent")
        run_row.pack(fill="x", padx=14, pady=(12, 6))
        self.scan_button = ctk.CTkButton(run_row, text="Scan all directories", height=34,
                                         fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                         text_color=ON_ACCENT, font=app.font_bold,
                                         command=app.start_full_scan)
        self.scan_button.pack(side="left")
        ctk.CTkButton(run_row, text="Scan a single file…", height=34, font=app.font_ui,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self._scan_single_file).pack(side="left", padx=10)
        self.stop_button = ctk.CTkButton(run_row, text="Stop", width=86, height=34,
                                         fg_color="transparent", hover_color=PANEL_2,
                                         border_width=1, border_color=RED,
                                         text_color=RED_SOFT, font=app.font_bold,
                                         state="disabled", command=app.stop_scan)
        self.stop_button.pack(side="left")
        ctk.CTkLabel(sec.body,
                     text="VirusTotal is queried by hash only (uploads are opt-in in Settings) and "
                          "paced to the free API quota, so large first scans take a while; "
                          "unchanged files are answered from the cache afterwards. "
                          "“Stop” takes effect after the file currently being scanned.",
                     font=app.font_small, text_color=MUTED, anchor="w", justify="left",
                     wraplength=720).pack(fill="x", padx=14, pady=(0, 12))

        self.refresh_directories()

    def _extensions_changed(self):
        selected = [ext for ext, var in self.ext_vars.items() if var.get()]
        if not selected:
            self.ext_vars[".pdf"].set(True)
            selected = [".pdf"]
        self.app.settings["file_extensions"] = selected
        self.app.scanner.file_extensions = selected

    def refresh_directories(self):
        for child in self.dir_list.winfo_children():
            child.destroy()
        directories = self.app.settings["scan_directories"]
        if not directories:
            ctk.CTkLabel(self.dir_list, text="No directories configured yet.",
                         font=self.app.font_small, text_color=AMBER_SOFT,
                         anchor="w").pack(fill="x", padx=4, pady=4)
        for directory in directories:
            row = ctk.CTkFrame(self.dir_list, fg_color="transparent")
            row.pack(fill="x", pady=2)
            exists = os.path.isdir(directory)
            ctk.CTkLabel(row, text=directory, font=self.app.font_mono_small,
                         text_color=TEXT if exists else AMBER_SOFT,
                         anchor="w").pack(side="left", fill="x", expand=True, padx=(4, 8))
            if not exists:
                ctk.CTkLabel(row, text="missing", font=self.app.font_small,
                             text_color=AMBER_SOFT).pack(side="left", padx=(0, 8))
            ctk.CTkButton(row, text="Remove", width=70, height=26, font=self.app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=MUTED,
                          command=lambda d=directory: self._remove_directory(d)
                          ).pack(side="right")

    def _add_directory(self):
        chosen = filedialog.askdirectory(title="Choose a directory to monitor")
        if chosen:
            directories = list(self.app.settings["scan_directories"])
            if chosen not in directories:
                directories.append(chosen)
                self.app.settings["scan_directories"] = directories
                self.app.scanner.scan_dirs = directories
            self.refresh_directories()

    def _remove_directory(self, directory):
        directories = [d for d in self.app.settings["scan_directories"] if d != directory]
        self.app.settings["scan_directories"] = directories
        self.app.scanner.scan_dirs = directories
        self.refresh_directories()

    def _scan_single_file(self):
        chosen = filedialog.askopenfilename(
            title="Choose a document to scan",
            filetypes=[("Documents & archives",
                        " ".join("*" + e for e in RS.SUPPORTED_EXTENSIONS)),
                       ("All files", "*.*")])
        if chosen:
            self.app.start_scan(mode="file", target=chosen)

    def set_running(self, running: bool):
        self.scan_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")


AUTO_QUARANTINE_CHOICES = {"Off": "", "High and above": "high", "Critical only": "critical"}


class ProtectionPage(BasePage):
    """Canary tripwires, the encrypted quarantine vault, and the result cache."""

    def __init__(self, app):
        super().__init__(app)
        outer = ctk.CTkScrollableFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True)
        ctk.CTkLabel(outer, text="Protection", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(outer, text="Tripwires that catch ransomware in the act, and an "
                                 "encrypted vault for anything you quarantine.",
                     font=app.font_small, text_color=MUTED, anchor="w").pack(fill="x")

        # -- canaries -------------------------------------------------------------
        sec = Section(outer, "Canary tripwires", app)
        sec.pack(fill="x", pady=(14, 0))
        minutes = int(app.scanner.config.get("canary_check_minutes", 5))
        ctk.CTkLabel(sec.body,
                     text="Decoy documents (named !000_…) planted in your monitored folders. "
                          "Nobody should ever open or change them: if one is deleted, "
                          "rewritten, renamed or encrypted, ransomware is most likely running "
                          "right now. "
                          + ("They are watched in real time, and also checked every "
                             f"{minutes} minute(s), " if RS.WATCHDOG_AVAILABLE else
                             f"They are checked every {minutes} minute(s) (install "
                             "'watchdog' for real-time watching) ")
                          + "while this window is open, and by the background scanner "
                            "(--background).",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 4))
        self.canary_status = ctk.CTkLabel(sec.body, text="", font=app.font_bold, anchor="w",
                                          wraplength=720, justify="left")
        self.canary_status.pack(fill="x", padx=14, pady=(2, 6))
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 6))
        ctk.CTkButton(row, text="Deploy to monitored folders", height=32, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, text_color=ON_ACCENT, font=app.font_bold,
                      command=self._deploy).pack(side="left")
        ctk.CTkButton(row, text="Verify now", height=32, font=app.font_ui,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=app.check_canaries_now).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Remove canaries", height=32, font=app.font_ui,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=MUTED,
                      command=self._remove).pack(side="left")
        self.canary_list = ctk.CTkTextbox(sec.body, height=96, fg_color=BG, text_color=MUTED,
                                          font=app.font_mono_small, wrap="none",
                                          border_width=0)
        self.canary_list.pack(fill="x", padx=14, pady=(4, 12))

        # -- quarantine -------------------------------------------------------------
        sec = Section(outer, "Quarantine vault", app)
        sec.pack(fill="x", pady=(14, 0))
        ctk.CTkLabel(sec.body,
                     text="Quarantined files are encrypted with AES-256-GCM (per-file keys, "
                          "authenticated chunks) and removed from their folder only after the "
                          "encrypted copy has been verified. Restore puts the original back.",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 6))
        auto_row = ctk.CTkFrame(sec.body, fg_color="transparent")
        auto_row.pack(fill="x", padx=14, pady=(0, 8))
        ctk.CTkLabel(auto_row, text="Quarantine automatically after a scan:",
                     font=app.font_ui, text_color=TEXT).pack(side="left")
        current = str(app.scanner.config.get("auto_quarantine") or "")
        label = next((k for k, v in AUTO_QUARANTINE_CHOICES.items() if v == current), "Off")
        self.auto_var = ctk.StringVar(value=label)
        ctk.CTkSegmentedButton(auto_row, values=list(AUTO_QUARANTINE_CHOICES),
                               variable=self.auto_var, command=self._auto_changed,
                               selected_color=ACCENT, selected_hover_color=ACCENT_HOVER,
                               font=app.font_small).pack(side="left", padx=10)
        self.vault_rows = ctk.CTkFrame(sec.body, fg_color="transparent")
        self.vault_rows.pack(fill="x", padx=10, pady=(2, 12))

        # -- cache ------------------------------------------------------------------
        sec = Section(outer, "Result cache", app)
        sec.pack(fill="x", pady=(14, 24))
        crow = ctk.CTkFrame(sec.body, fg_color="transparent")
        crow.pack(fill="x", padx=14, pady=12)
        self.cache_label = ctk.CTkLabel(crow, text="", font=app.font_small, text_color=MUTED,
                                        anchor="w", justify="left", wraplength=560)
        self.cache_label.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(crow, text="Clear cache", width=110, height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self._clear_cache).pack(side="right")

    # -- refresh -------------------------------------------------------------------
    def on_show(self):
        self._refresh_canaries()
        self._refresh_vault()
        self._refresh_cache()

    def _refresh_canaries(self):
        entries = self.app.scanner.canaries.entries()
        report = self.app.last_canary_report
        if not entries:
            text, color = "No canaries deployed yet.", AMBER_SOFT
        elif report is not None and report.triggered:
            text, color = report.summary(), RED
        elif report is not None:
            text = f"{len(entries)} canaries armed — last check {report.checked_at}: all intact."
            color = ACCENT_SOFT
        else:
            text, color = f"{len(entries)} canaries armed — first check pending.", ACCENT_SOFT
        self.canary_status.configure(text=text, text_color=color)
        lines = [e["path"] for e in entries] or ["—"]
        if report is not None and report.triggered:
            lines += [""] + [f"[{f.status}] {f.path}" for f in report.findings]
        self.canary_list.configure(state="normal")
        self.canary_list.delete("1.0", "end")
        self.canary_list.insert("1.0", "\n".join(lines))
        self.canary_list.configure(state="disabled")

    def _refresh_vault(self):
        for child in self.vault_rows.winfo_children():
            child.destroy()
        try:
            items = self.app.scanner.quarantine_vault.list()
        except Exception as e:
            ctk.CTkLabel(self.vault_rows, text=f"Unavailable: {e}", font=self.app.font_small,
                         text_color=AMBER_SOFT, anchor="w").pack(fill="x", padx=4)
            return
        if not items:
            ctk.CTkLabel(self.vault_rows, text="The vault is empty.", font=self.app.font_small,
                         text_color=MUTED, anchor="w").pack(fill="x", padx=4, pady=2)
            return
        for item in items[:100]:
            row = ctk.CTkFrame(self.vault_rows, fg_color=BG, corner_radius=8)
            row.pack(fill="x", pady=3)
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=10, pady=6)
            extra = item.get("extra") or {}
            verdict = f"  ·  {extra['verdict']}" if extra.get("verdict") else ""
            ctk.CTkLabel(info, text=f"{item.get('id')}  ·  {item.get('quarantined_at', '?')}"
                                    f"{verdict}",
                         font=self.app.font_mono_small, text_color=TEXT,
                         anchor="w").pack(fill="x")
            ctk.CTkLabel(info, text=f"{item.get('original_path', '?')}\n{item.get('reason', '')}",
                         font=self.app.font_small, text_color=MUTED, anchor="w",
                         justify="left", wraplength=540).pack(fill="x")
            ctk.CTkButton(row, text="Delete", width=70, height=28, font=self.app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=MUTED,
                          command=lambda i=item["id"]: self._delete(i)).pack(side="right",
                                                                            padx=(4, 10))
            ctk.CTkButton(row, text="Restore", width=80, height=28, font=self.app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=BLUE,
                          command=lambda i=item["id"]: self._restore(i)).pack(side="right")

    def _refresh_cache(self):
        cache = self.app.scanner.cache
        if cache is None or not cache.enabled:
            self.cache_label.configure(text="Cache disabled.")
            return
        st = cache.stats()
        self.cache_label.configure(
            text=f"{st['entries']} cached VirusTotal/LLM answer(s) "
                 f"({st['expired']} expired) · {st['hits']} hit(s) this session\n{st['path']}")

    # -- actions ---------------------------------------------------------------------
    def _deploy(self):
        dirs = [d for d in self.app.settings["scan_directories"] if os.path.isdir(d)]
        if not dirs:
            messagebox.showinfo("No folders", "Add a monitored directory on the Scan page first.")
            return
        created = self.app.scanner.deploy_canaries(dirs)
        self.app.gui_log.info(f"Deployed {len(created)} canary file(s) from GUI.")
        messagebox.showinfo("Canaries deployed",
                            f"{len(created)} new canary file(s) planted in {len(dirs)} folder(s).")
        self.app.check_canaries_now()

    def _remove(self):
        if not messagebox.askyesno("Remove canaries", "Delete every canary file this tool planted?"):
            return
        removed = self.app.scanner.remove_canaries()
        self.app.last_canary_report = None
        self.app.gui_log.info(f"Removed {removed} canary file(s) from GUI.")
        self.app.refresh_protection_views()
        self.on_show()

    def _restore(self, item_id: str, confirm: bool = True):
        if confirm and not messagebox.askyesno(
                "Restore file", "Decrypt this item and put it back where it was?\n\n"
                                "Only do this if you are sure it is a false positive."):
            return
        try:
            dest = self.app.scanner.quarantine_vault.restore(item_id)
        except Exception as e:
            messagebox.showerror("Restore failed", str(e))
            return
        self.app.gui_log.warning(f"Restored vault item {item_id} -> {dest}")
        if confirm:
            messagebox.showinfo("Restored", f"Restored to:\n{dest}")
        self.app.refresh_protection_views()
        self.on_show()

    def _delete(self, item_id: str, confirm: bool = True):
        if confirm and not messagebox.askyesno("Delete permanently",
                                               "Permanently delete this quarantined item?"):
            return
        try:
            self.app.scanner.quarantine_vault.delete(item_id)
        except Exception as e:
            messagebox.showerror("Delete failed", str(e))
            return
        self.app.refresh_protection_views()
        self.on_show()

    def _auto_changed(self, label: str):
        value = AUTO_QUARANTINE_CHOICES.get(label, "")
        try:
            ENV_FILE.touch(exist_ok=True)
            set_key(str(ENV_FILE), "AUTO_QUARANTINE", value)
        except Exception as e:
            self.app.gui_log.error(f"Could not save AUTO_QUARANTINE: {e}")
        RS.CONFIG["auto_quarantine"] = value
        self.app.scanner.config["auto_quarantine"] = value
        self.app.gui_log.info(f"Automatic quarantine set to: {label}")

    def _clear_cache(self):
        if self.app.scanner.cache is not None:
            removed = self.app.scanner.cache.clear()
            self.app.gui_log.info(f"Cleared {removed} cached result(s).")
        self._refresh_cache()


class ReportsPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x")
        ctk.CTkLabel(header, text="Reports", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(side="left")
        ctk.CTkButton(header, text="Open reports folder", height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=BLUE,
                      command=lambda: open_path(app.scanner.report_dir)
                      ).pack(side="right")
        ctk.CTkButton(header, text="Refresh", height=30, font=app.font_small,
                      fg_color="transparent", hover_color=PANEL_2, border_width=1,
                      border_color=BORDER_2, text_color=TEXT,
                      command=self.on_show).pack(side="right", padx=8)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, pady=(12, 0))
        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self.list_frame = ctk.CTkScrollableFrame(body, fg_color=PANEL, corner_radius=10,
                                                 border_width=1, border_color=BORDER,
                                                 width=250)
        self.list_frame.grid(row=0, column=0, sticky="nsw", padx=(0, 10))

        viewer_frame = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=10,
                                    border_width=1, border_color=BORDER)
        viewer_frame.grid(row=0, column=1, sticky="nsew")
        self.viewer = ctk.CTkTextbox(viewer_frame, fg_color=PANEL, text_color=TEXT,
                                     font=app.font_mono_small, wrap="word",
                                     border_width=0)
        self.viewer.pack(fill="both", expand=True, padx=8, pady=8)
        self._set_viewer("Select a report on the left to preview it here.")

    def _set_viewer(self, text):
        self.viewer.configure(state="normal")
        self.viewer.delete("1.0", "end")
        self.viewer.insert("1.0", text)
        self.viewer.configure(state="disabled")

    def on_show(self):
        for child in self.list_frame.winfo_children():
            child.destroy()
        report_dir = Path(self.app.scanner.report_dir)
        files = sorted([*report_dir.glob("ransomware_scan_*"), *report_dir.glob("canary_alert_*")],
                       key=lambda p: p.stat().st_mtime, reverse=True) if report_dir.exists() else []
        if not files:
            ctk.CTkLabel(self.list_frame, text="No reports yet.\nRun a scan first.",
                         font=self.app.font_small, text_color=MUTED,
                         justify="left").pack(anchor="w", padx=8, pady=8)
            self._set_viewer("Reports will appear here after your first scan.")
            return
        for path in files[:120]:
            stamp = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            kind = "ALERT" if path.name.startswith("canary_alert_") else path.suffix.lstrip(".").upper()
            text = f"{stamp}   ·  {kind}"
            ctk.CTkButton(self.list_frame, text=text, anchor="w", height=30,
                          font=self.app.font_mono_small, fg_color="transparent",
                          hover_color=PANEL_2, text_color=TEXT,
                          command=lambda p=path: self._preview(p)).pack(fill="x", pady=1)

    def _preview(self, path: Path):
        try:
            if path.suffix == ".json":
                results = json.loads(path.read_text(encoding="utf-8"))
                malicious = [r for r in results if r.get("is_malicious")]
                lines = [f"{path.name}",
                         f"Files scanned : {len(results)}",
                         f"Malicious     : {len(malicious)}", ""]
                for r in sorted(results, key=lambda r: -float(r.get("severity_score", 0) or 0)):
                    lines.append(f"[{float(r.get('severity_score', 0) or 0):4.1f}/10] "
                                 f"{r.get('file_name','?')}  ({layers_summary(r)})")
                lines += ["", "—" * 60, "", json.dumps(results, indent=2)[:60000]]
                self._set_viewer("\n".join(lines))
            else:
                self._set_viewer(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            self._set_viewer(f"Could not read {path.name}:\n{e}")


class DatabasePage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        ctk.CTkLabel(self, text="Database", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(self, text="Local malware-hash dataset used by detection layer 1.",
                     font=app.font_small, text_color=MUTED, anchor="w").pack(fill="x")

        sec = Section(self, "Status", app)
        sec.pack(fill="x", pady=(14, 0))
        self.path_label = ctk.CTkLabel(sec.body, text="", font=app.font_mono_small,
                                       text_color=MUTED, anchor="w", wraplength=720,
                                       justify="left")
        self.path_label.pack(fill="x", padx=14, pady=(12, 2))
        self.status_label = ctk.CTkLabel(sec.body, text="", font=app.font_ui,
                                         text_color=TEXT, anchor="w")
        self.status_label.pack(fill="x", padx=14, pady=(0, 12))

        sec = Section(self, "Import", app)
        sec.pack(fill="x", pady=(14, 0))
        ctk.CTkLabel(sec.body,
                     text="Import a CSV with at least the columns FileName, md5Hash and "
                          "Benign (Benign = 0 marks a malicious entry). Public datasets "
                          "are available on Kaggle.",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 6))
        ctk.CTkButton(sec.body, text="Import dataset (.csv)…", height=34,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ON_ACCENT,
                      font=app.font_bold, command=self._import).pack(anchor="w",
                                                                     padx=14, pady=(0, 8))
        self.import_label = ctk.CTkLabel(sec.body, text="", font=app.font_small,
                                         text_color=MUTED, anchor="w", wraplength=720,
                                         justify="left")
        self.import_label.pack(fill="x", padx=14, pady=(0, 12))

    def on_show(self):
        scanner = self.app.scanner
        self.path_label.configure(text=scanner.kaggle_db_path)
        count = len(scanner.hash_database)
        if count:
            self.status_label.configure(
                text=f"Loaded — {count:,} malicious hashes in memory.",
                text_color=ACCENT_SOFT)
        elif os.path.exists(scanner.kaggle_db_path):
            self.status_label.configure(
                text="File present but no malicious rows were loaded — check the Benign column.",
                text_color=AMBER_SOFT)
        else:
            self.status_label.configure(
                text="Not imported — layer 1 is inactive until a dataset is imported.",
                text_color=AMBER_SOFT)

    def _import(self):
        chosen = filedialog.askopenfilename(title="Choose a malware-hash CSV",
                                            filetypes=[("CSV files", "*.csv"),
                                                       ("All files", "*.*")])
        if not chosen:
            return
        outcome = RS.import_hash_database(chosen)
        if outcome["ok"]:
            self.app.scanner.hash_database = self.app.scanner._load_kaggle_database()
            self.import_label.configure(
                text=f"Imported {outcome['entries']:,} entries — "
                     f"{len(self.app.scanner.hash_database):,} malicious hashes loaded.",
                text_color=ACCENT_SOFT)
        else:
            self.import_label.configure(text=f"Import failed: {outcome['message']}",
                                        text_color=RED_SOFT)
        self.on_show()
        self.app.pages["dashboard"].refresh_cards()


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


class SettingsPage(BasePage):
    def __init__(self, app):
        super().__init__(app)
        outer = ctk.CTkScrollableFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True)
        ctk.CTkLabel(outer, text="Settings", font=app.font_h1, text_color=TEXT,
                     anchor="w").pack(fill="x")

        # -- schedule ------------------------------------------------------------
        sec = Section(outer, "Scheduled scans", app)
        sec.pack(fill="x", pady=(14, 0))
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(12, 4))
        self.schedule_var = ctk.BooleanVar(value=app.settings["schedule_enabled"])
        ctk.CTkSwitch(row, text="Run a full scan automatically while this window is open",
                      variable=self.schedule_var, font=app.font_ui, text_color=TEXT,
                      progress_color=ACCENT, button_color=TEXT, fg_color=BORDER_2,
                      command=self._schedule_toggled).pack(side="left")
        irow = ctk.CTkFrame(sec.body, fg_color="transparent")
        irow.pack(fill="x", padx=14, pady=(4, 12))
        ctk.CTkLabel(irow, text="Every", font=app.font_ui,
                     text_color=MUTED).pack(side="left")
        self.interval_label = ctk.CTkLabel(irow, text="", width=70, font=app.font_bold,
                                           text_color=ACCENT_SOFT)
        self.interval_slider = ctk.CTkSlider(irow, from_=1, to=24, number_of_steps=23,
                                             width=260, progress_color=ACCENT,
                                             button_color=ACCENT_SOFT,
                                             button_hover_color=TEXT, fg_color=BORDER_2,
                                             command=self._interval_changed)
        self.interval_slider.set(app.settings["scan_interval_hours"])
        self.interval_slider.pack(side="left", padx=10)
        self.interval_label.pack(side="left")
        self._interval_changed(app.settings["scan_interval_hours"])

        # -- autostart -------------------------------------------------------------
        sec = Section(outer, "Start at login", app)
        sec.pack(fill="x", pady=(14, 0))
        row = ctk.CTkFrame(sec.body, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(12, 2))
        self.autostart_var = ctk.BooleanVar(value=detect_autostart())
        self.autostart_switch = ctk.CTkSwitch(
            row, text="Run the background scanner automatically at login",
            variable=self.autostart_var, font=app.font_ui, text_color=TEXT,
            progress_color=ACCENT, button_color=TEXT, fg_color=BORDER_2,
            command=self._autostart_toggled)
        self.autostart_switch.pack(side="left")
        self.autostart_note = ctk.CTkLabel(
            sec.body, text="Uses the same mechanism as the CLI "
                           "(--setup-autostart): registry on Windows, launchd on macOS, "
                           "systemd user service on Linux. It runs the command-line "
                           "scanner in background mode — independent of this window.",
            font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
            justify="left")
        self.autostart_note.pack(fill="x", padx=14, pady=(0, 12))

        # -- API keys ----------------------------------------------------------------
        sec = Section(outer, "API keys", app)
        sec.pack(fill="x", pady=(14, 0))
        ctk.CTkLabel(sec.body,
                     text=f"Keys are stored only in {ENV_FILE} "
                          "(git-ignored, never committed). Leave a field empty to keep "
                          "the current value.",
                     font=app.font_small, text_color=MUTED, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=14, pady=(12, 6))
        self.key_rows = {}
        for env_name, config_key, label in [
                ("OPENAI_API_KEY", "chatgpt_api_key", "OpenAI (LLM layer)"),
                ("VIRUSTOTAL_API_KEY", "virustotal_api_key", "VirusTotal")]:
            row = ctk.CTkFrame(sec.body, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=4)
            ctk.CTkLabel(row, text=label, width=160, anchor="w", font=app.font_ui,
                         text_color=TEXT).pack(side="left")
            entry = ctk.CTkEntry(row, show="•", width=280, fg_color=BG,
                                 border_color=BORDER_2, text_color=TEXT,
                                 placeholder_text="paste new key…")
            entry.pack(side="left", padx=(0, 10))
            status = ctk.CTkLabel(row, text=mask_key(app.scanner.config.get(config_key)),
                                  font=app.font_mono_small, text_color=MUTED, anchor="w")
            status.pack(side="left")
            self.key_rows[env_name] = (entry, status, config_key)
        ctk.CTkButton(sec.body, text="Save keys", height=32, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, text_color=ON_ACCENT, font=app.font_bold,
                      command=self._save_keys).pack(anchor="w", padx=14, pady=(6, 4))
        self.vt_upload_var = ctk.BooleanVar(
            value=bool(app.scanner.config.get("virustotal_upload_unknown")))
        ctk.CTkSwitch(sec.body, text="Upload files VirusTotal has never seen (shares their "
                                     "full content with VirusTotal)",
                      variable=self.vt_upload_var, font=app.font_ui, text_color=TEXT,
                      progress_color=RED, button_color=TEXT, fg_color=BORDER_2,
                      command=self._vt_upload_toggled).pack(anchor="w", padx=14, pady=(8, 2))
        self.keys_label = ctk.CTkLabel(sec.body, text="", font=app.font_small,
                                       text_color=MUTED, anchor="w")
        self.keys_label.pack(fill="x", padx=14, pady=(0, 12))

        # -- locations -------------------------------------------------------------------
        sec = Section(outer, "Locations", app)
        sec.pack(fill="x", pady=(14, 24))
        for label, target in [("Application folder", RS.APP_DIR),
                              ("Reports", RS.REPORT_DIR),
                              ("Log file", RS.LOG_FILE)]:
            row = ctk.CTkFrame(sec.body, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=4)
            ctk.CTkLabel(row, text=label, width=160, anchor="w", font=app.font_ui,
                         text_color=TEXT).pack(side="left")
            ctk.CTkLabel(row, text=str(target), font=app.font_mono_small,
                         text_color=MUTED, anchor="w").pack(side="left", fill="x",
                                                            expand=True)
            ctk.CTkButton(row, text="Open", width=60, height=26, font=app.font_small,
                          fg_color="transparent", hover_color=PANEL_2, border_width=1,
                          border_color=BORDER_2, text_color=BLUE,
                          command=lambda t=target: open_path(t)).pack(side="right")
        ctk.CTkLabel(sec.body, text="", font=app.font_small).pack(pady=2)

    # -- callbacks ------------------------------------------------------------------

    def _schedule_toggled(self):
        self.app.settings["schedule_enabled"] = bool(self.schedule_var.get())
        self.app.reset_schedule()

    def _interval_changed(self, value):
        hours = int(round(float(value)))
        self.interval_label.configure(text=f"{hours} h")
        if hours != self.app.settings["scan_interval_hours"]:
            self.app.settings["scan_interval_hours"] = hours
            self.app.scanner.config["scan_interval_hours"] = hours
            self.app.reset_schedule()

    def _autostart_toggled(self):
        desired = bool(self.autostart_var.get())
        self.autostart_switch.configure(state="disabled")
        self.autostart_note.configure(text="Applying…", text_color=AMBER_SOFT)
        threading.Thread(target=self._apply_autostart, args=(desired,),
                         daemon=True).start()

    def _apply_autostart(self, desired):
        try:
            ok = RS.setup_autostart() if desired else RS.remove_autostart()
        except Exception:
            logging.getLogger("RansomwareScanner.GUI").exception("Autostart change failed")
            ok = False
        self.app.bus.put(("autostart_done", desired, ok))

    def autostart_finished(self, desired, ok):
        self.autostart_switch.configure(state="normal")
        if ok:
            self.autostart_note.configure(
                text=("Enabled — the background scanner will start at login."
                      if desired else "Disabled — the autostart entry was removed."),
                text_color=ACCENT_SOFT)
        else:
            self.autostart_var.set(detect_autostart())
            self.autostart_note.configure(
                text="Could not change the autostart entry — see Logs for details.",
                text_color=RED_SOFT)

    def _vt_upload_toggled(self):
        enabled = bool(self.vt_upload_var.get())
        try:
            ENV_FILE.touch(exist_ok=True)
            set_key(str(ENV_FILE), "VT_UPLOAD_UNKNOWN", "true" if enabled else "false")
        except Exception as e:
            self.keys_label.configure(text=f"Could not save setting: {e}", text_color=RED_SOFT)
        RS.CONFIG["virustotal_upload_unknown"] = enabled
        self.app.scanner.config["virustotal_upload_unknown"] = enabled
        self.keys_label.configure(
            text=("VirusTotal uploads ON — unknown files will be shared with VirusTotal."
                  if enabled else "VirusTotal uploads OFF — hash lookups only (private)."),
            text_color=AMBER_SOFT if enabled else ACCENT_SOFT)

    def _save_keys(self):
        changed = []
        try:
            for env_name, (entry, status, config_key) in self.key_rows.items():
                value = entry.get().strip()
                if not value:
                    continue
                ENV_FILE.touch(exist_ok=True)
                set_key(str(ENV_FILE), env_name, value)
                os.environ[env_name] = value
                RS.CONFIG[config_key] = value
                self.app.scanner.config[config_key] = value
                status.configure(text=mask_key(value))
                entry.delete(0, "end")
                changed.append(env_name)
        except Exception as e:
            self.keys_label.configure(text=f"Could not save keys: {e}",
                                      text_color=RED_SOFT)
            return
        if changed:
            self.keys_label.configure(text=f"Saved to {ENV_FILE.name}: "
                                           f"{', '.join(changed)}",
                                      text_color=ACCENT_SOFT)
            logging.getLogger("RansomwareScanner.GUI").info(
                f"API keys updated via GUI: {', '.join(changed)}")
            self.app.pages["dashboard"].refresh_cards()
        else:
            self.keys_label.configure(text="Nothing to save — both fields were empty.",
                                      text_color=MUTED)


def detect_autostart() -> bool:
    """Best-effort check of whether the CLI autostart entry currently exists."""
    system = platform.system()
    try:
        if system == "Windows" and RS.winreg is not None:
            with RS.winreg.OpenKey(RS.winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                RS.winreg.QueryValueEx(key, RS.AUTOSTART_NAME)
            return True
        if system == "Darwin":
            return (Path.home() / "Library" / "LaunchAgents" /
                    f"{RS.AUTOSTART_LABEL}.plist").exists()
        return (Path.home() / ".config" / "systemd" / "user" / RS.SYSTEMD_UNIT).exists()
    except Exception:
        return False


# --- Application ---------------------------------------------------------------------

class App(ctk.CTk):
    NAV = [("dashboard", "Dashboard"), ("scan", "Scan"), ("protection", "Protection"),
           ("reports", "Reports"), ("database", "Database"), ("logs", "Logs"),
           ("settings", "Settings")]

    def __init__(self):
        ctk.set_appearance_mode("dark")
        super().__init__(fg_color=BG)
        self.title("Aegis Sentinel")
        self.geometry("1180x760")
        self.minsize(1024, 660)

        # fonts (must be created after the root window exists)
        default_family = tkfont.nametofont("TkDefaultFont").actual("family")
        self.font_ui = ctk.CTkFont(size=13)
        self.font_bold = ctk.CTkFont(size=13, weight="bold")
        self.font_small = ctk.CTkFont(size=11)
        self.font_h1 = ctk.CTkFont(size=20, weight="bold")
        self.font_h2 = ctk.CTkFont(size=16, weight="bold")
        self.font_card = ctk.CTkFont(size=17, weight="bold")
        self.font_mono = ctk.CTkFont(family=mono_family(), size=13)
        self.font_mono_small = ctk.CTkFont(family=mono_family(), size=11)

        # ttk style for the results table
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("RD.Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=TEXT, bordercolor=PANEL, borderwidth=0,
                        lightcolor=PANEL, darkcolor=PANEL, relief="flat",
                        rowheight=34, font=(mono_family(), 11))
        style.configure("RD.Treeview.Heading", background=PANEL, foreground=MUTED,
                        bordercolor=PANEL, borderwidth=0, relief="flat",
                        font=(default_family, 10))
        style.map("RD.Treeview", background=[("selected", SELECT)],
                  foreground=[("selected", TEXT)])
        style.map("RD.Treeview.Heading", background=[("active", PANEL)])

        # state
        self.settings = SettingsStore()
        self.scanner = RS.RansomwareScanner(self._build_config())
        self.bus = queue.Queue()
        self.log_queue = queue.Queue()
        self.controller = ScanController(self.bus)
        self.next_scan_at = None
        self.last_scan_at = None
        self._scan_seen_progress = False
        self.last_canary_report = None
        self._canary_check_running = False
        self._alerted_signature = None
        # Real-time tripwire watching (watchdog thread -> bus -> UI thread).
        self.canary_watcher = RS.CanaryWatcher(self.scanner.canaries,
                                               lambda: self.bus.put(("canary_event",)))

        log_handler = QueueLogHandler(self.log_queue)
        logging.getLogger("RansomwareScanner").addHandler(log_handler)
        self.gui_log = logging.getLogger("RansomwareScanner.GUI")

        # layout: sidebar | content, status bar at the bottom
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        self.content = ctk.CTkFrame(self, fg_color=BG)
        self.content.grid(row=0, column=1, sticky="nsew", padx=18, pady=(16, 8))

        self._build_status_bar()

        self.pages = {
            "dashboard": DashboardPage(self),
            "scan": ScanPage(self),
            "protection": ProtectionPage(self),
            "reports": ReportsPage(self),
            "database": DatabasePage(self),
            "logs": LogsPage(self),
            "settings": SettingsPage(self),
        }
        self.current_page = None
        self.show_page("dashboard")

        self._bootstrap_last_report()
        self.reset_schedule()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(120, self._poll)
        self.after(1000, self._tick)
        self.after(4000, self._canary_tick)
        self.gui_log.info(f"GUI started (v{APP_VERSION}) on {platform.system()}")

    # -- construction helpers ---------------------------------------------------------

    def _build_config(self) -> dict:
        config = dict(RS.CONFIG)
        config["scan_directories"] = list(self.settings["scan_directories"])
        config["file_extensions"] = list(self.settings["file_extensions"])
        config["scan_interval_hours"] = int(self.settings["scan_interval_hours"])
        return config

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, fg_color=BG, width=212, corner_radius=0,
                               border_width=0)
        sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=16, pady=(18, 14))
        ctk.CTkLabel(brand, text="Aegis Sentinel", font=self.font_h2,
                     text_color=TEXT, anchor="w").pack(fill="x")
        ctk.CTkLabel(brand, text=f"hybrid ransomware detector · v{APP_VERSION}",
                     font=self.font_small, text_color=MUTED, anchor="w").pack(fill="x")

        self.nav_buttons = {}
        for key, label in self.NAV:
            button = ctk.CTkButton(sidebar, text=label, anchor="w", height=36,
                                   corner_radius=8, fg_color="transparent",
                                   hover_color=PANEL_2, text_color=MUTED,
                                   font=self.font_ui,
                                   command=lambda k=key: self.show_page(k))
            button.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = button

        self.protection_label = ctk.CTkLabel(sidebar, text="", font=self.font_small,
                                             anchor="w")
        self.protection_label.pack(side="bottom", fill="x", padx=20, pady=14)

    def _build_status_bar(self):
        bar = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, height=30,
                           border_width=0)
        bar.grid(row=1, column=1, sticky="sew", padx=0, pady=0)
        bar.grid_propagate(False)
        self.status_label = ctk.CTkLabel(bar, text="Ready.", font=self.font_mono_small,
                                         text_color=MUTED, anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True, padx=14)

    def _bootstrap_last_report(self):
        """Populate the dashboard from the most recent JSON report, if any."""
        try:
            report_dir = Path(self.scanner.report_dir)
            reports = sorted(report_dir.glob("ransomware_scan_*.json"),
                             key=lambda p: p.stat().st_mtime, reverse=True)
            if not reports:
                self.pages["dashboard"].load_results([], "Latest results")
                return
            latest = reports[0]
            self.last_scan_at = datetime.fromtimestamp(latest.stat().st_mtime)
            results = json.loads(latest.read_text(encoding="utf-8"))
            self.pages["dashboard"].load_results(results, f"Latest results — {latest.name}")
        except Exception:
            self.gui_log.exception("Could not load the latest report")
            self.pages["dashboard"].load_results([], "Latest results")

    # -- navigation ----------------------------------------------------------------------

    def show_page(self, key: str):
        if self.current_page is not None:
            self.pages[self.current_page].pack_forget()
        self.current_page = key
        page = self.pages[key]
        page.pack(fill="both", expand=True)
        page.on_show()
        for nav_key, button in self.nav_buttons.items():
            active = nav_key == key
            button.configure(fg_color=ACCENT_DIM if active else "transparent",
                             text_color=ACCENT_SOFT if active else MUTED,
                             font=self.font_bold if active else self.font_ui)

    # -- scanning ------------------------------------------------------------------------

    def start_full_scan(self):
        self.start_scan(mode="all")

    def start_scan(self, mode="all", target=None):
        if self.controller.running:
            return
        if mode == "all" and not self.settings["scan_directories"]:
            messagebox.showinfo("No directories",
                                "Add at least one directory on the Scan page first.")
            return
        dashboard = self.pages["dashboard"]
        dashboard.clear_results("Scan in progress…")
        self._scan_seen_progress = False
        dashboard.progress_bar.configure(mode="indeterminate")
        dashboard.progress_bar.start()
        dashboard.progress_file.configure(text="Collecting files…", text_color=MUTED)
        dashboard.progress_count.configure(text="")
        self._set_running_ui(True)
        started = self.controller.start(self.scanner, mode, target)
        if started:
            self.gui_log.info(f"Scan started from GUI (mode={mode})")
            if self.current_page != "dashboard":
                self.show_page("dashboard")

    def stop_scan(self):
        if self.controller.running:
            self.controller.stop()
            self.status_label.configure(text="Stopping after the current file…")

    def _set_running_ui(self, running: bool):
        dashboard = self.pages["dashboard"]
        if running:
            dashboard.scan_button.pack_forget()
            dashboard.stop_button.pack(side="right")
        else:
            dashboard.stop_button.pack_forget()
            dashboard.scan_button.pack(side="right")
        self.pages["scan"].set_running(running)

    # -- event bus / polling ------------------------------------------------------------------

    def _poll(self):
        try:
            while True:
                event = self.bus.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.status_label.configure(text=line[:180])
                if self.current_page == "logs":
                    self.pages["logs"].append(line)
        except queue.Empty:
            pass
        self.after(120, self._poll)

    def _handle_event(self, event):
        kind = event[0]
        dashboard = self.pages["dashboard"]
        if kind == "progress":
            _, done, total, path, result = event
            if not self._scan_seen_progress:
                self._scan_seen_progress = True
                dashboard.progress_bar.stop()
                dashboard.progress_bar.configure(mode="determinate")
            dashboard.progress_file.configure(text=f"Scanning {path}", text_color=TEXT)
            dashboard.progress_count.configure(text=f"{done} / {total} files")
            dashboard.progress_bar.set(done / total if total else 0)
            if result is not None:
                dashboard.add_result(result)
        elif kind == "scan_done":
            _, results, report_text, cancelled = event
            dashboard.progress_bar.stop()
            dashboard.progress_bar.configure(mode="determinate")
            dashboard.progress_bar.set(1 if results and not cancelled else 0)
            self._set_running_ui(False)
            self.last_scan_at = datetime.now()
            self.reset_schedule()
            malicious = sum(1 for r in results if r.get("is_malicious"))
            if cancelled:
                summary = f"Scan stopped — {len(results)} file(s) scanned, {malicious} malicious."
                dashboard.results_title.configure(text="Latest results (partial — scan stopped)")
            elif not results:
                summary = "Scan finished — no matching files were found."
                dashboard.results_title.configure(text="Latest results")
                dashboard.load_results([], "Latest results")
            else:
                summary = (f"Scan complete — {len(results)} file(s), {malicious} malicious. "
                           f"Report saved to {Path(self.scanner.report_dir).name}/")
                dashboard.results_title.configure(text="Latest results")
            dashboard.progress_file.configure(text=summary,
                                              text_color=RED_SOFT if malicious else ACCENT_SOFT)
            dashboard.progress_count.configure(text="")
            dashboard.refresh_meta()
        elif kind == "scan_error":
            self._set_running_ui(False)
            dashboard.progress_bar.stop()
            dashboard.progress_bar.configure(mode="determinate")
            dashboard.progress_bar.set(0)
            dashboard.progress_file.configure(text=f"Scan failed: {event[1]}",
                                              text_color=RED_SOFT)
        elif kind == "autostart_done":
            self.pages["settings"].autostart_finished(event[1], event[2])
        elif kind == "canary_report":
            self._canary_check_running = False
            self._on_canary_report(event[1])
        elif kind == "canary_event":
            self.check_canaries_now()

    # -- canary tripwires ---------------------------------------------------------------------

    def check_canaries_now(self):
        """Verify canaries in a worker thread; the result arrives on the bus."""
        self.canary_watcher.refresh()          # follows canaries deployed / removed
        if self._canary_check_running or not self.scanner.canaries.entries():
            self.refresh_protection_views()
            return
        self._canary_check_running = True

        def work():
            try:
                report = self.scanner.check_canaries(notify=True)
            except Exception:
                self.gui_log.exception("Canary check failed")
                report = None
            self.bus.put(("canary_report", report))

        threading.Thread(target=work, daemon=True).start()

    def _canary_tick(self):
        self.check_canaries_now()
        minutes = max(1, int(self.scanner.config.get("canary_check_minutes", 5)))
        self.after(minutes * 60 * 1000, self._canary_tick)

    def _on_canary_report(self, report):
        if report is None:
            return
        self.last_canary_report = report
        self.refresh_protection_views()
        if report.triggered:
            signature = tuple(sorted((f.path, f.status) for f in report.findings))
            self.status_label.configure(text=f"CANARY: {report.summary()}")
            if signature != self._alerted_signature:
                self._alerted_signature = signature
                details = "\n".join(f"[{f.status}] {f.path}" for f in report.findings[:8])
                messagebox.showwarning(
                    "Ransomware tripwire triggered",
                    f"{report.summary()}\n\n{details}\n\nDisconnect from the network and "
                    "investigate running processes before rebooting.")
        else:
            self._alerted_signature = None

    def refresh_protection_views(self):
        try:
            self.pages["dashboard"].refresh_cards()
            if self.current_page == "protection":
                self.pages["protection"].on_show()
        except Exception:
            self.gui_log.exception("Could not refresh protection views")

    # -- schedule -----------------------------------------------------------------------------

    def reset_schedule(self):
        if self.settings["schedule_enabled"]:
            hours = int(self.settings["scan_interval_hours"])
            self.next_scan_at = datetime.now() + timedelta(hours=hours)
        else:
            self.next_scan_at = None
        self._refresh_protection()
        self.pages["dashboard"].refresh_meta()

    def _tick(self):
        if (self.next_scan_at is not None and datetime.now() >= self.next_scan_at
                and not self.controller.running):
            self.gui_log.info("Scheduled scan triggered.")
            self.start_scan(mode="all")
        if self.current_page == "dashboard":
            self.pages["dashboard"].refresh_meta()
        self.after(1000, self._tick)

    def _refresh_protection(self):
        enabled = self.settings["schedule_enabled"]
        self.protection_label.configure(
            text=("●  Protection on" if enabled else "○  Protection off"),
            text_color=ACCENT_SOFT if enabled else MUTED)

    def last_scan_text(self) -> str:
        return self.last_scan_at.strftime("%H:%M") if self.last_scan_at else "never"

    def next_scan_text(self) -> str:
        if self.controller.running:
            return "scan running now"
        if self.next_scan_at is None:
            return "scheduled scans off"
        delta = (self.next_scan_at - datetime.now()).total_seconds()
        return (f"next scheduled in {humanize_delta(delta)} "
                f"({self.next_scan_at.strftime('%H:%M')})")

    # -- shutdown ---------------------------------------------------------------------------------

    def _on_close(self):
        if self.controller.running:
            if not messagebox.askyesno("Scan in progress",
                                       "A scan is still running. Stop it and exit?"):
                return
            self.controller.stop()
        self.gui_log.info("GUI closed.")
        self.destroy()

    def destroy(self):
        watcher = getattr(self, "canary_watcher", None)
        if watcher is not None:
            watcher.stop()
        super().destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
