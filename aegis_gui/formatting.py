"""Pure helpers that turn scan results into text and colours (no widgets)."""

import os
import platform
import subprocess

from aegis_gui.common import (
    ACCENT_SOFT,
    AMBER_SOFT,
    MUTED,
    OK,
    ORANGE,
    RED,
    RED_SOFT,
    REGISTRY,
    SEV_HIGH,
    SEV_MED,
    List,
    messagebox,
)


def mono_family() -> str:
    return {"Windows": "Consolas", "Darwin": "Menlo"}.get(platform.system(),
                                                          "DejaVu Sans Mono")


def open_path(path) -> None:
    """Open a file or folder with the OS default application."""
    path = str(path)
    try:
        if platform.system() == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606 - opens a report/folder the user picked
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
# Short labels for indicators come from the registry (detectors/indicators.yaml).


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
        label = REGISTRY.label(name) + where
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
                  if m.get("verdict", "Clean") != "Clean" or m.get("mail_flags"))
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
