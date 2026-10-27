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


def _db_token(sr: dict) -> List[str]:
    return ["DB✓" if sr.get("local_database", {}).get("is_malicious") else "DB–"]


def _fuzzy_token(sr: dict) -> List[str]:
    fuzzy = sr.get("fuzzy_hash", {})
    if not fuzzy.get("available"):
        return []
    return ["fuzzy✓" if fuzzy.get("matched") else "fuzzy–"]


def _macro_token(sr: dict) -> List[str]:
    macro = sr.get("macro_analysis", {})
    if not macro.get("available"):
        return []
    if not macro.get("has_macros"):
        return ["macro–"]
    if macro.get("critical"):
        return ["macro!"]                   # exec/download primitive present
    return ["macro⚡" if macro.get("autoexec") else "macro✓"]   # ⚡ = auto-run trigger


def _yara_token(sr: dict) -> List[str]:
    yara = sr.get("yara", {})
    if not yara.get("available"):
        return []
    n = len(yara.get("matches", []) or [])
    return [f"yara✓{n}" if yara.get("matched") else "yara–"]


def _integrity_token(sr: dict) -> List[str]:
    integ = sr.get("file_integrity", {})
    for key, token in (("disguised_executable", "exe!"),   # program behind a document name
                       ("encrypted_likely", "enc!"),       # content looks encrypted (impact)
                       ("format_mismatch", "fmt?")):
        if integ.get(key):
            return [token]
    return []


def _guard_token(sr: dict) -> List[str]:
    guard = sr.get("prompt_guard", {})
    status = guard.get("injection_status")
    if status in ("confirmed", "suspicious"):
        return ["inj!" if status == "confirmed" else "inj?"]
    return ["hidden"] if guard.get("hidden_text_found") else []


def _external_token(sr: dict) -> List[str]:
    return ["ext!"] if sr.get("relationships", {}).get("suspicious") else []   # remote template


def _container_token(sr: dict, key: str, members: str, count: str, flags: str,
                     label: str) -> List[str]:
    box = sr.get(key, {})
    if not box:
        return []
    bad = sum(1 for m in box.get(members, []) or []
              if m.get("verdict", "Clean") != "Clean" or m.get(flags))
    return [f"{label}{box.get(count, 0)}" + (f"!{bad}" if bad else "")]


def _archive_token(sr: dict) -> List[str]:
    return _container_token(sr, "archive", "member_results", "member_count",
                            "archive_flags", "arc")


def _mail_tokens(sr: dict) -> List[str]:
    out = _container_token(sr, "mail", "attachment_results", "attachment_count",
                           "mail_flags", "mail")
    mail = sr.get("mail", {})
    if mail and ((mail.get("auth") or {}).get("failures") or mail.get("display_name_spoof")):
        out.append("spoof!")                # authentication failure / display-name spoof
    return out


def _web_token(sr: dict) -> List[str]:
    web = sr.get("web", {})
    if not web:
        return []
    if web.get("smuggling"):
        return ["smuggle!"]                 # HTML smuggling with an embedded payload
    risky = web.get("svg_active") or web.get("credential_form") or web.get("payloads")
    return ["web!" if risky else "web"]


def _payload_token(sr: dict) -> List[str]:
    return ["img+payload!"] if (sr.get("file_integrity") or {}).get("appended_payload") else []


def _ml_token(sr: dict) -> List[str]:
    ml = sr.get("ml_classifier", {})
    if ml.get("label") != "suspicious":
        return []
    return [f"ml {float(ml.get('probability', 0)):.2f}"]


def _vt_token(sr: dict) -> List[str]:
    vt = sr.get("virustotal", {})
    if "not configured" in str(vt.get("details", "")):
        return ["VT off"]
    if vt.get("error"):
        return ["VT err"]
    if vt.get("not_found"):
        return ["VT new"]
    if vt.get("total_engines"):
        hits = vt.get("malicious_detections", 0) + vt.get("suspicious_detections", 0)
        return [f"VT {hits}/{vt.get('total_engines', 0)}"]
    return []


def _ai_token(sr: dict) -> List[str]:
    ai = sr.get("chatgpt_analysis", {})
    return [] if llm_skipped(ai) else [f"AI {float(ai.get('confidence', 0) or 0):.2f}"]


# One function per layer, in display order. v4+ layers only show a token when
# they found something, to keep the row short.
LAYER_TOKENS = (_db_token, _fuzzy_token, _macro_token, _yara_token, _integrity_token,
                _guard_token, _external_token, _archive_token, _mail_tokens, _web_token,
                _payload_token, _ml_token, _vt_token, _ai_token)


def layers_summary(result: dict) -> str:
    """Compact per-layer breakdown, e.g. 'DB– fuzzy– macro✓ yara✓ VT14/72 AI0.80'.

    Only the layers that actually ran contribute a token; unavailable/skipped
    layers are omitted so the line stays readable."""
    sr = result.get("scan_results", {})
    return "  ".join(token for layer in LAYER_TOKENS for token in layer(sr))


def humanize_delta(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, m = seconds // 3600, (seconds % 3600) // 60
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m"
    return "<1m"
