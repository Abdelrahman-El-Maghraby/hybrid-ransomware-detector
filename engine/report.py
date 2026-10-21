"""Text/JSON report generation for scan results."""

import json
import logging
import os
import re
from datetime import datetime
from typing import Dict, List, Optional

from detectors import FUZZY_AVAILABLE, OLEVBA_AVAILABLE, YARA_AVAILABLE
from detectors.qr_scanner import QR_AVAILABLE
from detectors.relationship_scanner import defang

from .config import ENGINE_VERSION

logger = logging.getLogger("RansomwareScanner")


class ReportMixin:
    """Builds the human-readable report and writes the JSON evidence trail."""

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
Detection layers used:  {self._active_layers_label()}
LLM posture:            {self._llm_posture_label()}
"""
        if canary_report is not None:
            report_text += f"Canary tripwires:       {canary_report.summary()}\n"

        report_text += self._impact_section(results, impact)
        if canary_report is not None and canary_report.triggered:
            report_text += f"\n{'!' * 60}\nCANARY TRIPWIRE TRIGGERED\n{'!' * 60}\n"
            for f in canary_report.findings:
                report_text += f"  [{f.status}] {f.path}\n      {f.evidence}\n"

        if malicious_files == 0:
            report_text += "\nNo suspicious files detected.\n"
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
        """Render one flagged file's evidence block for the text report."""
        sr = result.get("scan_results", {})
        lines = [
            f"\n- File:     {result.get('file_path')}",
            f"  Verdict:  {result.get('verdict', 'n/a')} "
            f"(risk {result.get('risk_score', 0)}/100, "
            f"severity {result.get('severity_score', 0)}/10)",
            f"  MD5:      {result.get('md5_hash', 'n/a')}",
        ]

        # Local hash DB (exact known-bad)
        local_db = sr.get("local_database", {})
        if local_db.get("is_malicious"):
            lines.append("  [Local DB]  Exact hash match against known-bad database.")

        # Fuzzy / structural similarity
        fuzzy = sr.get("fuzzy_hash", {})
        if fuzzy.get("matched"):
            fams = sorted({m.get("family", "") for m in fuzzy.get("matches", [])
                           if m.get("family")}) or ["known family"]
            conf = fuzzy.get("best_confidence", 0) or 0
            lines.append(
                f"  [Fuzzy]     Structural similarity to {', '.join(fams)} "
                f"(confidence {conf:.2f})."
            )

        # Macro analysis (Office dropper mechanism)
        macro = sr.get("macro_analysis", {})
        if macro.get("has_macros"):
            autoexec = macro.get("autoexec", []) or []
            critical = macro.get("critical", []) or []
            suspicious = macro.get("suspicious", []) or []
            if autoexec:
                lines.append(f"  [Macro]     Auto-run trigger(s): {', '.join(autoexec)}.")
            if critical:
                lines.append(
                    f"  [Macro]     Execution/download primitive(s): "
                    f"{', '.join(critical)}."
                )
            elif suspicious:
                lines.append(
                    f"  [Macro]     Suspicious call(s): "
                    f"{', '.join(suspicious[:6])}."
                )
            if autoexec and critical:
                lines.append(
                    "  [Macro]     -> Auto-exec + exec primitive = classic "
                    "dropper pattern."
                )
            if macro.get("vba_stomping"):
                lines.append("  [Macro]     VBA STOMPING: compiled P-code differs from the "
                             "visible source.")
            if macro.get("xlm_macros"):
                lines.append("  [Macro]     Excel 4.0 (XLM) macro sheet(s): "
                             f"{', '.join((macro.get('xlm_evidence') or [])[:3])}.")

        # YARA structural IOCs
        yara_res = sr.get("yara", {})
        if yara_res.get("matched"):
            rule_names = sorted({m.get("rule", "") for m in yara_res.get("matches", [])
                                 if m.get("rule")})
            rules = ", ".join(rule_names) if rule_names else "(unnamed)"
            lines.append(
                f"  [YARA]      Rule(s) matched [{rules}] "
                f"(top severity '{yara_res.get('top_severity', 'medium')}')."
            )

        # File integrity (disguise / encryption)
        integ = sr.get("file_integrity", {})
        if integ.get("disguised_executable") or integ.get("encrypted_likely") \
                or integ.get("format_mismatch"):
            lines.append(f"  [Integrity] {integ.get('detail', '')}")

        # Hidden content / prompt injection
        guard = sr.get("prompt_guard", {})
        if guard.get("hidden_text_found"):
            lines.append(f"  [Hidden]    Concealed content: "
                         f"{', '.join(guard.get('hidden_reasons', []) or [])}.")
        if guard.get("injection_status") in ("confirmed", "suspicious"):
            lines.append(f"  [Injection] {guard['injection_status']} prompt-injection attempt: "
                         f"{', '.join(guard.get('injection_indicators', []) or [])}.")

        # Linux ELF triage
        elf = sr.get("elf_analysis", {})
        if elf.get("behaviour") or elf.get("packed") or elf.get("no_section_table"):
            lines.append(f"  [ELF]       {elf.get('detail', '')}")

        # Script files (JS / VBS / HTA / PS1 / BAT)
        sc = sr.get("script_analysis", {})
        if sc.get("behaviour") or sc.get("encoded") or len(sc.get("obfuscation") or []) >= 2:
            lines.append(f"  [Script]    {sc.get('detail', '')}")
            for url in (sc.get("urls") or [])[:3]:
                lines.append(f"              - {defang(url)}")

        # OneNote / CHM / MSI / encrypted Office / XLL
        emb = sr.get("embedded", {})
        if emb:
            lines.append(f"  [Embedded]  {emb.get('detail', '')}")
            for m in (emb.get("member_results") or [])[:5]:
                if m.get("risk_score", 0) > 0:
                    lines.append(f"              - {m.get('name')}: {m.get('verdict')} "
                                 f"(risk {m.get('risk_score')}/100)")

        # QR codes (quishing)
        qr = sr.get("qr_codes", {})
        for c in (qr.get("codes") or [])[:3]:
            if c.get("is_url"):
                why = "; ".join(c.get("suspicious_reasons") or []) or "ordinary link"
                lines.append(f"  [QR]        {defang(c.get('payload', ''))} ({why})")
        if qr and not qr.get("available"):
            lines.append(f"  [QR]        {qr.get('detail', '')}")

        # Office external relationships
        rels = sr.get("relationships", {})
        for f in (rels.get("findings") or [])[:3]:
            lines.append(f"  [External]  {f.get('kind')} -> {defang(str(f.get('target', '')))}")

        # Archive contents
        arc = sr.get("archive", {})
        if arc:
            lines.append(f"  [Archive]   {arc.get('detail', '')}")
            shown = set()
            for label, key in (("double extension", "double_extension_members"),
                               ("RTLO spoof", "rtlo_members"),
                               ("executable", "executable_members")):
                for name in [n for n in (arc.get(key) or []) if n not in shown][:3]:
                    shown.add(name)
                    lines.append(f"              ! {label}: {name}")
            for m in arc.get("member_results", []) or []:
                if m.get("verdict", "Clean") != "Clean":
                    lines.append(f"              - {m.get('name')}: {m.get('verdict')} "
                                 f"(risk {m.get('risk_score', 0)}/100)")

        # E-mail envelope + attachments
        mail = sr.get("mail", {})
        if mail:
            lines.append(f"  [Mail]      {mail.get('detail', '')}")
            if mail.get("subject"):
                lines.append(f"              Subject: {mail['subject'][:120]}")
            for link in (mail.get("deceptive_links") or [])[:3]:
                lines.append(f"              ! deceptive link: {defang(link)}")
            for a in mail.get("attachment_results", []) or []:
                if a.get("verdict", "Clean") != "Clean":
                    lines.append(f"              - {a.get('name')}: {a.get('verdict')} "
                                 f"(risk {a.get('risk_score', 0)}/100)")

        # Web page (HTML smuggling, active SVG, phishing form)
        web = sr.get("web", {})
        if web:
            detail = re.sub(r"https?://[^\s;,'\")]+", lambda m: defang(m.group(0)),
                            web.get("detail", ""))
            lines.append(f"  [Web]       {detail}")
            for url in (web.get("redirects") or [])[:3]:
                lines.append(f"              ! redirects to {defang(url)}")
            for m in web.get("payload_results", []) or []:
                if m.get("verdict", "Clean") != "Clean":
                    lines.append(f"              - {m.get('name')}: {m.get('verdict')} "
                                 f"(risk {m.get('risk_score', 0)}/100)")

        # ML classifier
        ml = sr.get("ml_classifier", {})
        if ml.get("label") == "suspicious":
            lines.append(f"  [ML]        {ml.get('model')} p={ml.get('probability', 0):.2f}: "
                         f"{'; '.join((ml.get('indicators') or [])[:3])}")

        # VirusTotal reputation
        vt = sr.get("virustotal", {})
        if vt.get("is_malicious"):
            lines.append(
                f"  [VT]        {vt.get('malicious_detections', 0)} malicious / "
                f"{vt.get('total_engines', 0)} engines."
            )
            if vt.get("permalink"):
                lines.append(f"              {vt.get('permalink')}")

        # LLM semantic opinion (capped low by the scoring matrix)
        llm = sr.get("chatgpt_analysis", {})
        if llm.get("is_malicious"):
            lines.append(
                f"  [Semantic]  LLM flagged the text "
                f"(confidence {llm.get('confidence', 0):.2f})."
            )
            elems = llm.get("suspicious_elements", []) or []
            if elems:
                lines.append(f"              Elements: {', '.join(map(str, elems))}.")

        skipped = sr.get("skipped_layers") or {}
        if skipped.get("layers"):
            lines.append(f"  [Skipped]   {', '.join(skipped['layers'])}: score already 100/100.")

        quarantine = result.get("quarantine") or {}
        if quarantine.get("id"):
            lines.append(f"  [Quarantine] Moved to the encrypted vault (id {quarantine['id']}).")
        elif quarantine.get("error"):
            lines.append(f"  [Quarantine] FAILED: {quarantine['error']}")

        # Weighted score breakdown (the "why")
        breakdown = result.get("score_breakdown", {})
        contribs = breakdown.get("contributions", []) or []
        if contribs:
            lines.append("  Score breakdown:")
            for c in contribs:
                lines.append(
                    f"    + {c.get('points', 0):>5.1f}  "
                    f"[{c.get('category', '?')}] {c.get('indicator', '?')}"
                )
            totals = breakdown.get("category_totals", {})
            if totals:
                totals_str = ", ".join(
                    f"{k}={v}" for k, v in totals.items() if v
                )
                if totals_str:
                    lines.append(f"    = category totals: {totals_str}")

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
        layers += ["integrity", "elf", "script", "prompt-guard", "relationships", "archives", "mail", "web"]
        qr = getattr(self, "qr_scanner", None)
        if qr is not None and QR_AVAILABLE:
            layers.append("qr")
        if getattr(self, "ml", None) is not None:
            layers.append("ml")
        layers.append("llm")
        layers.append("virustotal")
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

