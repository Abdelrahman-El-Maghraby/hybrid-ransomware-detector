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


def verdict_text(result: dict) -> str:
    """The verdict as shown: a scan that was not complete never reads as plain
    "Clean" (engine/completeness.py)."""
    status = result.get("scan_status") or "complete"
    verdict = result_verdict(result)
    return verdict if status == "complete" else f"{verdict} ({status} scan)"


def first_gap(result: dict) -> str:
    """The first reason a scan is not complete ('' when it is)."""
    reasons = result.get("incomplete_reasons") or []
    if (result.get("scan_status") or "complete") == "complete" or not reasons:
        return ""
    return f"not fully inspected: {reasons[0].get('reason', '')}"


def gap_rows(result: dict, limit: int = 20) -> list:
    """(layer, reason, where) for every gap of an incomplete scan, worst first as
    the engine recorded them; [] for a complete one. `where` is the member path
    inside a container, or ''."""
    reasons = result.get("incomplete_reasons") or []
    if (result.get("scan_status") or "complete") == "complete":
        return []
    top = result.get("file_path")
    rows = [(str(r.get("layer") or "?"), str(r.get("reason") or ""),
             "" if (r.get("member_path") or top) == top else str(r.get("member_path")))
            for r in reasons[:limit]]
    if len(reasons) > limit:
        rows.append(("", f"... {len(reasons) - limit} more in the JSON report", ""))
    return rows


def provenance_rows(result: dict) -> list:
    """(label, value) of what produced the result: rules, registry and schema,
    profile, external services, and the layers that did not run on this file."""
    pv = result.get("provenance") or {}
    if not pv:
        return []
    rules = pv.get("rules") or {}
    sha = str(rules.get("sha256") or "")
    rows = [("Rules", f"{rules.get('version') or rules.get('source', 'none')} "
                      f"({rules.get('files', 0)} file(s)" + (f", sha256 {sha[:16]}" if sha else "") + ")"),
            ("Registry", f"{pv.get('registry_version', '?')}  ·  schema {pv.get('schema_version', '?')}"),
            ("Profile", str(pv.get("profile", "standard"))),
            ("Services", ", ".join(f"{k} {v}" for k, v in (pv.get("external_services") or {}).items())
             or "n/a")]
    for key, label in (("layers_down", "Down here"), ("layers_unavailable", "Unavailable"),
                       ("layers_failed", "Failed"), ("layers_skipped", "Skipped")):
        items = [(i.get("layer"), i.get("reason")) if isinstance(i, dict) else (i, "")
                 for i in (pv.get(key) or [])]
        if items:
            rows.append((label, "; ".join(f"{n}: {why}" if why else str(n) for n, why in items)))
    return rows


def diagnostic_rows(states: dict, warnings=()) -> list:
    """(level, text) for the Diagnostics panel and the first-run check:
    'problem'  a layer the supported edition requires is down (scans are partial),
    'note'     an optional layer is down, or a layer is switched off by a setting,
    'warning'  a configuration warning from the start-up validation."""
    from engine.capabilities import DISABLED, DOWN, PRODUCTION_REQUIRED
    rows = []
    for name, st in states.items():
        if st.get("state") == DOWN:
            level = "problem" if name in PRODUCTION_REQUIRED else "note"
            rows.append((level, f"{name}: {st.get('detail') or 'unavailable'}"))
        elif st.get("state") == DISABLED:
            rows.append(("note", f"{name}: off ({st.get('detail') or 'switched off'})"))
    rows += [("warning", str(w)) for w in warnings]
    order = {"problem": 0, "warning": 1, "note": 2}
    return sorted(rows, key=lambda r: order[r[0]])


def diagnostics_text(rows: list, version: str, system: str) -> str:
    """The copyable report (no paths, keys or file names)."""
    lines = [f"Aegis Sentinel {version} on {system}"]
    lines += [f"[{level}] {text}" for level, text in rows] or ["every layer is up"]
    return "\n".join(lines)


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
