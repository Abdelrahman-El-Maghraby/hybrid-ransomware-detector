"""Text/JSON report generation for scan results."""

import json
import logging
import os
import re
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from detectors import FUZZY_AVAILABLE, OLEVBA_AVAILABLE, YARA_AVAILABLE
from detectors.qr_scanner import QR_AVAILABLE
from detectors.relationship_scanner import defang

from .completeness import COMPLETE, PRECEDENCE, verdict_label
from .config import ENGINE_VERSION

logger = logging.getLogger("RansomwareScanner")


class ReportMixin:
    """Builds the human-readable report and writes the JSON evidence trail."""

    report_dir: str          # provided by RansomwareScanner

    def generate_report(self, results: List[Dict], impact: Optional[Dict] = None,
                        canary_report=None) -> str:
        """Generate a comprehensive report based on scan results.

        The report reflects the multi-layer engine: files are grouped by
        verdict band (Critical -> High -> Medium -> Low), and each flagged file
        lists the concrete evidence from every layer plus the weighted score
        breakdown that explains *why* it scored what it did. Optional sections
        summarise ransomware-impact indicators seen while walking folders and
        the state of the canary tripwires.

        Backward compatibility: the JSON report is still the full list of result
        dicts, and the legacy fields (md5_hash, severity_score) are still shown.
        """
        if not results:
            return "No files scanned."

        # Create a timestamp for the report file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.report_dir, f"ransomware_scan_{timestamp}.json")

        # Write detailed JSON report (full evidence trail, unchanged shape)
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=4)

        total_files = len(results)
        flagged = [r for r in results if r.get("is_malicious")]
        malicious_files = len(flagged)

        # Group flagged files by verdict band, most severe first.
        band_order = ["Critical", "High", "Medium", "Low"]
        grouped: Dict[str, List[Dict]] = {b: [] for b in band_order}
        for r in flagged:
            verdict = r.get("verdict", "Low")
            grouped.setdefault(verdict, []).append(r)

        # Highest verdict reached across the whole scan (for the summary line).
        worst = "Clean"
        for b in band_order:
            if grouped.get(b):
                worst = b
                break

        report_text = f"""
Ransomware Scan Report
======================
Timestamp:              {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Engine version:         {ENGINE_VERSION}
Total files scanned:    {total_files}
Files flagged:          {malicious_files}
Highest verdict:        {worst}
Scan completeness:      {_completeness_label(results)}
Detection layers used:  {self._active_layers_label()}
LLM posture:            {self._llm_posture_label()}
"""
        report_text += _provenance_lines(results, getattr(self, "provenance", None) or {})
        if canary_report is not None:
            report_text += f"Canary tripwires:       {canary_report.summary()}\n"

        report_text += self._impact_section(results, impact)
        allowed = [r for r in results
                   if (r.get("scan_results", {}).get("allowlist") or {}).get("allowlisted")]
        if allowed:
            report_text += f"\n[Allowlist] {len(allowed)} known-good file(s) scanned but not scored:\n"
            for r in allowed[:20]:
                note = r["scan_results"]["allowlist"].get("note") or "no note"
                report_text += f"  - {r.get('file_path')} ({note})\n"
        if canary_report is not None and canary_report.triggered:
            report_text += f"\n{'!' * 60}\nCANARY TRIPWIRE TRIGGERED\n{'!' * 60}\n"
            for f in canary_report.findings:
                report_text += f"  [{f.status}] {f.path}\n      {f.evidence}\n"

        incomplete = [r for r in results if r.get("scan_status", COMPLETE) != COMPLETE]
        if malicious_files == 0:
            report_text += ("\nNo suspicious files detected.\n" if not incomplete else
                            f"\nNo suspicious files detected in what was inspected; {len(incomplete)} "
                            "scan(s) were not complete (listed below).\n")
        else:
            # Quick band breakdown line, e.g. "Critical: 1 | High: 2 | Medium: 0"
            breakdown = " | ".join(
                f"{b}: {len(grouped.get(b, []))}" for b in band_order
            )
            report_text += f"\nVerdict breakdown:  {breakdown}\n"

            for band in band_order:
                bucket = grouped.get(band, [])
                if not bucket:
                    continue
                report_text += f"\n{'=' * 60}\n{band.upper()} ({len(bucket)})\n{'=' * 60}\n"
                # Sort within a band by risk score, highest first.
                for result in sorted(
                    bucket, key=lambda r: r.get("risk_score", 0), reverse=True
                ):
                    report_text += self._format_file_finding(result)

        report_text += _incomplete_section([r for r in incomplete if not r.get("is_malicious")])
        report_text += f"\nDetailed JSON report saved to: {report_file}\n"

        # Also save the text report
        text_report_file = os.path.join(self.report_dir, f"ransomware_scan_{timestamp}.txt")
        with open(text_report_file, 'w') as f:
            f.write(report_text)

        return report_text

    @staticmethod
    def _impact_section(results: List[Dict], impact: Optional[Dict]) -> str:
        """Folder-level ransomware-impact summary (empty string if nothing seen)."""
        encrypted = [r.get("file_path") for r in results
                     if r.get("scan_results", {}).get("file_integrity", {}).get("encrypted_likely")]
        notes = (impact or {}).get("ransom_notes", [])
        note_count = (impact or {}).get("ransom_note_count", 0)
        ext_files = (impact or {}).get("ransom_extension_files", [])
        ext_count = (impact or {}).get("ransom_extension_count", 0)
        if not (encrypted or note_count or ext_count):
            return ""
        strong = note_count >= 1 or ext_count >= 3 or len(encrypted) >= 2
        out = f"\n{'#' * 60}\n"
        out += ("POSSIBLE ACTIVE RANSOMWARE IMPACT - investigate this machine now\n"
                if strong else "Ransomware impact indicators (weak signal)\n")
        out += f"{'#' * 60}\n"
        if encrypted:
            out += f"  Files whose content looks encrypted: {len(encrypted)}\n"
            out += "".join(f"    - {p}\n" for p in encrypted[:10])
        if note_count:
            out += f"  Ransom-note-like files: {note_count}\n"
            out += "".join(f"    - {p}\n" for p in notes[:10])
        if ext_count:
            out += f"  Files with known ransomware extensions: {ext_count}\n"
            out += "".join(f"    - {p}\n" for p in ext_files[:10])
        return out

    def _format_file_finding(self, result: Dict) -> str:
        """Render one flagged file's evidence block for the text report: a header,
        one block per layer that found something (FINDING_SECTIONS), then the
        quarantine note and the score breakdown."""
        sr = result.get("scan_results", {})
        lines = [
            f"\n- File:     {result.get('file_path')}",
            f"  Verdict:  {verdict_label(result) if result.get('verdict') else 'n/a'} "
            f"(risk {result.get('risk_score', 0)}/100, "
            f"severity {result.get('severity_score', 0)}/10)",
            f"  MD5:      {result.get('md5_hash', 'n/a')}",
        ]
        lines.extend(_gap_lines(result))
        for section in FINDING_SECTIONS:
            lines.extend(section(sr))
        lines.extend(_quarantine_lines(result.get("quarantine") or {}))
        lines.extend(_breakdown_lines(result.get("score_breakdown", {})))
        lines.append("")
        return "\n".join(lines)

    def _active_layers_label(self) -> str:
        """Human-readable list of which optional detection layers are active."""
        layers = ["hashes", "local-db"]
        if FUZZY_AVAILABLE:
            layers.append("fuzzy")
        if OLEVBA_AVAILABLE:
            layers.append("macro")
        if YARA_AVAILABLE:
            layers.append("yara")
        layers += ["integrity", "elf", "pe", "script", "prompt-guard", "relationships", "archives", "mail",
                   "web", "embedded"]
        qr = getattr(self, "qr_scanner", None)
        if qr is not None and QR_AVAILABLE:
            layers.append("qr")
        if getattr(self, "ml", None) is not None:
            layers.append("ml")
        layers.append("llm")
        layers.append("virustotal")
        emulator = getattr(self, "emulator", None)
        if emulator is not None and emulator.available:
            layers.append("emulation")
        if getattr(self, "sandbox", None) is not None:
            layers.append("sandbox")
        return ", ".join(layers)

    def _llm_posture_label(self) -> str:
        """Describe whether the active LLM backend keeps data local or sends it out."""
        backend = getattr(self, "llm_backend", None)
        if backend is None:
            return "none"
        name = backend.__class__.__name__
        if "Ollama" in name:
            return f"LOCAL ({getattr(backend, 'model', 'ollama')})"
        if "OpenAI" in name:
            return "CLOUD (OpenAI - documents leave the machine)"
        return "disabled"


# --------------------------------------------------------------------------
# Finding sections. Each takes a result's scan_results and returns report
# lines (none when the layer found nothing). A new layer adds one function
# and one entry in FINDING_SECTIONS; the order there is the order in reports.
# --------------------------------------------------------------------------
Lines = List[str]


def _provenance_lines(results: List[Dict], fallback: Dict) -> str:
    """What produced these results: rules, registry, schema, profile, external services."""
    pv = next((r["provenance"] for r in results if r.get("provenance")), fallback)
    if not pv:
        return ""
    rules = pv.get("rules") or {}
    services = ", ".join(f"{k} {v}" for k, v in (pv.get("external_services") or {}).items())
    sha = rules.get("sha256", "")
    return (f"Rules:                  {rules.get('version') or rules.get('source', 'none')} "
            f"({rules.get('files', 0)} file(s){', sha256 ' + sha[:16] if sha else ''})\n"
            f"Registry / schema:      {pv.get('registry_version', '?')} / {pv.get('schema_version', '?')}\n"
            f"Profile:                {pv.get('profile', 'standard')}\n"
            f"External services:      {services or 'n/a'}\n")


def _completeness_label(results: List[Dict]) -> str:
    """"12 complete, 1 partial, 1 locked" in severity order."""
    counts = {s: 0 for s in PRECEDENCE}
    for r in results:
        status = r.get("scan_status", COMPLETE)
        counts[status if status in counts else COMPLETE] += 1
    return ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), key=lambda kv: PRECEDENCE.index(kv[0]))
                     if n) or "n/a"


def _gap_lines(result: Dict, limit: int = 5) -> Lines:
    """Why a scan is not complete: one line per gap (member, layer, reason)."""
    reasons = result.get("incomplete_reasons") or []
    if result.get("scan_status", COMPLETE) == COMPLETE or not reasons:
        return []
    lines = [f"  Scan:     {result['scan_status']} - {len(reasons)} gap(s) in the evidence"]
    for r in reasons[:limit]:
        where = r.get("member_path") or result.get("file_path")
        lines.append(f"              - [{r.get('layer')}] {r.get('reason')}"
                     + (f"  ({where})" if where != result.get("file_path") else ""))
    if len(reasons) > limit:
        lines.append(f"              ... {len(reasons) - limit} more in the JSON report")
    return lines


def _incomplete_section(results: List[Dict]) -> str:
    """Files that scored Low/Clean but were not fully inspected: never silently 'clean'."""
    if not results:
        return ""
    out = f"\n{'=' * 60}\nNOT FULLY INSPECTED ({len(results)})\n{'=' * 60}\n"
    for r in sorted(results, key=lambda r: PRECEDENCE.index(r.get("scan_status", COMPLETE)),
                    reverse=True):
        out += f"\n- File:     {r.get('file_path')}\n  Verdict:  {verdict_label(r)}\n"
        out += "".join(f"{line}\n" for line in _gap_lines(r, limit=3))
    return out


def _members(results, indent: str = "              - ") -> Lines:
    """Non-clean members / attachments / payloads, one line each."""
    return [f"{indent}{m.get('name')}: {m.get('verdict')} (risk {m.get('risk_score', 0)}/100)"
            for m in results or [] if m.get("verdict", "Clean") != "Clean"]


def _local_db(sr: Dict) -> Lines:
    if sr.get("local_database", {}).get("is_malicious"):
        return ["  [Local DB]  Exact hash match against known-bad database."]
    return []


def _fuzzy(sr: Dict) -> Lines:
    fuzzy = sr.get("fuzzy_hash", {})
    if not fuzzy.get("matched"):
        return []
    fams = sorted({m.get("family", "") for m in fuzzy.get("matches", [])
                   if m.get("family")}) or ["known family"]
    conf = fuzzy.get("best_confidence", 0) or 0
    return [f"  [Fuzzy]     Structural similarity to {', '.join(fams)} (confidence {conf:.2f})."]


def _macro(sr: Dict) -> Lines:
    macro = sr.get("macro_analysis", {})
    if not macro.get("has_macros"):
        return []
    autoexec = macro.get("autoexec", []) or []
    critical = macro.get("critical", []) or []
    suspicious = macro.get("suspicious", []) or []
    out: Lines = []
    if autoexec:
        out.append(f"  [Macro]     Auto-run trigger(s): {', '.join(autoexec)}.")
    if critical:
        out.append(f"  [Macro]     Execution/download primitive(s): {', '.join(critical)}.")
    elif suspicious:
        out.append(f"  [Macro]     Suspicious call(s): {', '.join(suspicious[:6])}.")
    if autoexec and critical:
        out.append("  [Macro]     -> Auto-exec + exec primitive = classic dropper pattern.")
    if macro.get("vba_stomping"):
        out.append("  [Macro]     VBA STOMPING: compiled P-code differs from the visible source.")
    if macro.get("xlm_macros"):
        out.append("  [Macro]     Excel 4.0 (XLM) macro sheet(s): "
                   f"{', '.join((macro.get('xlm_evidence') or [])[:3])}.")
    return out


def _yara(sr: Dict) -> Lines:
    yara_res = sr.get("yara", {})
    if not yara_res.get("matched"):
        return []
    names = sorted({m.get("rule", "") for m in yara_res.get("matches", []) if m.get("rule")})
    return [f"  [YARA]      Rule(s) matched [{', '.join(names) if names else '(unnamed)'}] "
            f"(top severity '{yara_res.get('top_severity', 'medium')}')."]


def _integrity(sr: Dict) -> Lines:
    integ = sr.get("file_integrity", {})
    if (integ.get("disguised_executable") or integ.get("encrypted_likely")
            or integ.get("format_mismatch")):
        return [f"  [Integrity] {integ.get('detail', '')}"]
    return []


def _prompt_guard(sr: Dict) -> Lines:
    guard = sr.get("prompt_guard", {})
    out: Lines = []
    if guard.get("hidden_text_found"):
        out.append(f"  [Hidden]    Concealed content: "
                   f"{', '.join(guard.get('hidden_reasons', []) or [])}.")
    if guard.get("injection_status") in ("confirmed", "suspicious"):
        out.append(f"  [Injection] {guard['injection_status']} prompt-injection attempt: "
                   f"{', '.join(guard.get('injection_indicators', []) or [])}.")
    return out


def _elf(sr: Dict) -> Lines:
    elf = sr.get("elf_analysis", {})
    if elf.get("behaviour") or elf.get("packed") or elf.get("no_section_table"):
        return [f"  [ELF]       {elf.get('detail', '')}"]
    return []


def _pe(sr: Dict) -> Lines:
    pe = sr.get("pe_analysis", {})
    if any(pe.get(k) for k in ("packed", "wx_sections", "injection_apis", "ransomware_apis",
                               "runtime_imports_only", "recovery_inhibition",
                               "overlay_executable", "overlay_encrypted", "malformed")):
        return [f"  [PE]        {pe.get('detail', '')}"]
    return []


def _sandbox(sr: Dict) -> Lines:
    sb = sr.get("sandbox", {})
    if not sb:
        return []
    return ([f"  [Sandbox]   {sb.get('detail') or sb.get('status', '')}"]
            + [f"              - contacted {defang(str(h))}"
               for h in (sb.get("network_hosts") or [])[:3]])


def _allowlist(sr: Dict) -> Lines:
    allow = sr.get("allowlist", {})
    if allow.get("allowlisted"):
        return [f"  [Allowlist] known-good SHA-256 ({allow.get('note') or 'no note'}); "
                "findings below are not scored"]
    return []


def _script(sr: Dict) -> Lines:
    sc = sr.get("script_analysis", {})
    if not (sc.get("behaviour") or sc.get("encoded") or len(sc.get("obfuscation") or []) >= 2):
        return []
    return ([f"  [Script]    {sc.get('detail', '')}"]
            + [f"              - {defang(url)}" for url in (sc.get("urls") or [])[:3]])


def _embedded(sr: Dict) -> Lines:
    emb = sr.get("embedded", {})
    if not emb:
        return []
    return ([f"  [Embedded]  {emb.get('detail', '')}"]
            + [f"              - {m.get('name')}: {m.get('verdict')} "
               f"(risk {m.get('risk_score')}/100)"
               for m in (emb.get("member_results") or [])[:5] if m.get("risk_score", 0) > 0])


def _qr(sr: Dict) -> Lines:
    qr = sr.get("qr_codes", {})
    out = [f"  [QR]        {defang(c.get('payload', ''))} "
           f"({'; '.join(c.get('suspicious_reasons') or []) or 'ordinary link'})"
           for c in (qr.get("codes") or [])[:3] if c.get("is_url")]
    if qr and not qr.get("available"):
        out.append(f"  [QR]        {qr.get('detail', '')}")
    return out


def _relationships(sr: Dict) -> Lines:
    return [f"  [External]  {f.get('kind')} -> {defang(str(f.get('target', '')))}"
            for f in (sr.get("relationships", {}).get("findings") or [])[:3]]


def _archive(sr: Dict) -> Lines:
    arc = sr.get("archive", {})
    if not arc:
        return []
    out = [f"  [Archive]   {arc.get('detail', '')}"]
    shown: set = set()
    for label, key in (("double extension", "double_extension_members"),
                       ("RTLO spoof", "rtlo_members"), ("executable", "executable_members")):
        for name in [n for n in (arc.get(key) or []) if n not in shown][:3]:
            shown.add(name)
            out.append(f"              ! {label}: {name}")
    return out + _members(arc.get("member_results"))


def _mail(sr: Dict) -> Lines:
    mail = sr.get("mail", {})
    if not mail:
        return []
    out = [f"  [Mail]      {mail.get('detail', '')}"]
    if mail.get("subject"):
        out.append(f"              Subject: {mail['subject'][:120]}")
    out += [f"              ! deceptive link: {defang(link)}"
            for link in (mail.get("deceptive_links") or [])[:3]]
    return out + _members(mail.get("attachment_results"))


_URL = re.compile(r"https?://[^\s;,'\")]+")


def _web(sr: Dict) -> Lines:
    web = sr.get("web", {})
    if not web:
        return []
    detail = _URL.sub(lambda m: defang(m.group(0)), web.get("detail", ""))
    return ([f"  [Web]       {detail}"]
            + [f"              ! redirects to {defang(url)}" for url in (web.get("redirects") or [])[:3]]
            + _members(web.get("payload_results")))


def _ml(sr: Dict) -> Lines:
    ml = sr.get("ml_classifier", {})
    if ml.get("label") != "suspicious":
        return []
    return [f"  [ML]        {ml.get('model')} p={ml.get('probability', 0):.2f}: "
            f"{'; '.join((ml.get('indicators') or [])[:3])}"]


def _virustotal(sr: Dict) -> Lines:
    vt = sr.get("virustotal", {})
    if not vt.get("is_malicious"):
        return []
    out = [f"  [VT]        {vt.get('malicious_detections', 0)} malicious / "
           f"{vt.get('total_engines', 0)} engines."]
    if vt.get("permalink"):
        out.append(f"              {vt.get('permalink')}")
    return out


def _llm(sr: Dict) -> Lines:
    llm = sr.get("chatgpt_analysis", {})
    if not llm.get("is_malicious"):
        return []
    out = [f"  [Semantic]  LLM flagged the text (confidence {llm.get('confidence', 0):.2f})."]
    elems = llm.get("suspicious_elements", []) or []
    if elems:
        out.append(f"              Elements: {', '.join(map(str, elems))}.")
    return out


def _emulation(sr: Dict) -> Lines:
    emu = sr.get("emulation", {})
    if not emu.get("ran"):
        return []
    return ([f"  [Emulation] {emu.get('detail', '')}"]
            + [f"              - fetched {defang(u)}" for u in (emu.get("urls") or [])[:3]]
            + [f"              - ran {c}" for c in (emu.get("commands") or [])[:3]])


def _skipped(sr: Dict) -> Lines:
    skipped = sr.get("skipped_layers") or {}
    if skipped.get("layers"):
        return [f"  [Skipped]   {', '.join(skipped['layers'])}: score already 100/100."]
    return []


FINDING_SECTIONS: Tuple[Callable[[Dict], Lines], ...] = (
    _local_db, _fuzzy, _macro, _yara, _integrity, _prompt_guard, _elf, _pe, _sandbox,
    _allowlist, _script, _embedded, _qr, _relationships, _archive, _mail, _web, _ml,
    _virustotal, _llm, _emulation, _skipped,
)


def _quarantine_lines(quarantine: Dict) -> Lines:
    if quarantine.get("id"):
        return [f"  [Quarantine] Moved to the encrypted vault (id {quarantine['id']})."]
    if quarantine.get("error"):
        return [f"  [Quarantine] FAILED: {quarantine['error']}"]
    return []


def _breakdown_lines(breakdown: Dict) -> Lines:
    """The weighted score breakdown: the "why" behind the number."""
    contribs = breakdown.get("contributions", []) or []
    if not contribs:
        return []
    out = ["  Score breakdown:"]
    out += [f"    + {c.get('points', 0):>5.1f}  [{c.get('category', '?')}] {c.get('indicator', '?')}"
            for c in contribs]
    totals_str = ", ".join(f"{k}={v}" for k, v in (breakdown.get("category_totals") or {}).items() if v)
    if totals_str:
        out.append(f"    = category totals: {totals_str}")
    return out
