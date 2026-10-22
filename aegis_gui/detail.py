"""The per-file result window."""

import os
import re
import webbrowser

from aegis_gui.common import (
    ACCENT_SOFT,
    AMBER_SOFT,
    BG,
    BLUE,
    BORDER,
    BORDER_2,
    MUTED,
    PANEL,
    PANEL_2,
    RED,
    RED_SOFT,
    RS,
    TEXT,
    Path,
    ctk,
    messagebox,
)
from aegis_gui.formatting import (
    llm_skipped,
    open_path,
    result_risk,
    result_verdict,
    risk_bar,
    verdict_color,
)
from aegis_gui.widgets import Section

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
