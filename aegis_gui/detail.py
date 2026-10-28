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
    gap_rows,
    llm_skipped,
    open_path,
    provenance_rows,
    result_risk,
    result_verdict,
    risk_bar,
    verdict_color,
    verdict_text,
)
from aegis_gui.widgets import Section

# --- Result detail window --------------------------------------------------------

class DetailWindow(ctk.CTkToplevel):
    """One window per file: a header, then one section per detection layer
    (SECTIONS, in pipeline order), the score breakdown and the actions."""

    def __init__(self, app, result: dict):
        super().__init__(app, fg_color=BG)
        self.app = app
        self.result = result
        self.title(result.get("file_name", "Scan result"))
        self.geometry("640x560")
        self.minsize(560, 480)
        self.after(80, lambda: (self.lift(), self.focus_force()))

        self.scroll_area = ctk.CTkScrollableFrame(self, fg_color=BG)
        self.scroll_area.pack(fill="both", expand=True, padx=16, pady=16)
        self._header()
        sr = result.get("scan_results", {})
        for section in self.SECTIONS:
            section(self, sr)
        self._actions()

    # ------------------------------------------------------------- building blocks
    def _section(self, title):
        sec = Section(self.scroll_area, title, self.app)
        sec.pack(fill="x", pady=(12, 0))
        return sec.body

    def _line(self, body, text, color=MUTED, font=None, pad=(0, 0)):
        ctk.CTkLabel(body, text=text, text_color=color, font=font or self.app.font_small,
                     anchor="w", wraplength=540, justify="left").pack(fill="x", padx=14, pady=pad)

    def _status(self, body, text, color, pady=10):
        """The one-line state of a layer (skipped / clean / found)."""
        ctk.CTkLabel(body, text=text, text_color=color, font=self.app.font_ui, anchor="w",
                     wraplength=540, justify="left").pack(fill="x", padx=14, pady=pady)

    def _spacer(self, body):
        ctk.CTkLabel(body, text="").pack(pady=2)

    def _members(self, body, members, limit, flags_key=None):
        for m in (members or [])[:limit]:
            v = m.get("verdict", "Clean")
            status = m.get("scan_status") or "complete"
            shown = v if status == "complete" else f"{v} ({status})"
            name = str(m.get("name", "?")).split("!/", 1)[-1]
            flags = (m.get(flags_key) or []) if flags_key else []
            tag = f"   ← {', '.join(f.replace('_', ' ') for f in flags)}" if flags else ""
            color = RED_SOFT if flags and v == "Clean" else verdict_color(v)
            self._line(body, f"{shown:<8}  {m.get('risk_score', 0):>3}/100   {name}{tag}",
                       color, self.app.font_mono_small)

    # ----------------------------------------------------------------- header
    def _header(self):
        app, result = self.app, self.result
        verdict = result_verdict(result)
        vcolor = verdict_color(verdict)
        head = ctk.CTkFrame(self.scroll_area, fg_color=PANEL, corner_radius=10,
                            border_width=1, border_color=BORDER)
        head.pack(fill="x")
        ctk.CTkLabel(head, text=result.get("file_name", "?"), font=app.font_h2,
                     text_color=TEXT, anchor="w").pack(fill="x", padx=14, pady=(12, 0))
        ctk.CTkLabel(head, text=result.get("file_path", ""), font=app.font_mono_small,
                     text_color=MUTED, anchor="w", wraplength=560,
                     justify="left").pack(fill="x", padx=14)
        vrow = ctk.CTkFrame(head, fg_color="transparent")
        vrow.pack(fill="x", padx=14, pady=(8, 12))
        ctk.CTkLabel(vrow, text=risk_bar(result_risk(result)), font=app.font_mono,
                     text_color=vcolor).pack(side="left")
        ctk.CTkLabel(vrow, text=f"   {verdict_text(result)}", font=app.font_bold,
                     text_color=vcolor).pack(side="left")

    # --------------------------------------------------------------- sections
    def _file_info(self, sr):
        result, app = self.result, self.app
        body = self._section("File")
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

    def _local_db(self, sr):
        body = self._section("Layer 1 — local hash database")
        flagged = sr.get("local_database", {}).get("is_malicious")
        self._status(body, "Match found in local malware database" if flagged
                     else "Not found in local database", RED_SOFT if flagged else ACCENT_SOFT)

    def _fuzzy(self, sr):
        fuzzy = sr.get("fuzzy_hash", {})
        body = self._section("Layer 2 — fuzzy / structural hashing")
        if not fuzzy.get("available", False):
            self._status(body, "Skipped — fuzzy-hash libraries not installed "
                               "(python-tlsh / ppdeep).", AMBER_SOFT)
            return
        matched = fuzzy.get("matched")
        if matched:
            fams = sorted({m.get("family", "") for m in fuzzy.get("matches", [])
                           if m.get("family")})
            conf = float(fuzzy.get("best_confidence", 0) or 0)
            msg = (f"Structural match to {', '.join(fams) or 'a known family'} "
                   f"(confidence {conf:.2f})")
        else:
            msg = fuzzy.get("detail") or "No structural match in the signature database."
        self._status(body, msg, RED_SOFT if matched else ACCENT_SOFT, (10, 2))
        digests = [f"{label:<8}{fuzzy[key]}" for key, label in (("tlsh", "TLSH"),
                                                                ("ssdeep", "ssdeep"))
                   if fuzzy.get(key)]
        if digests:
            self._line(body, "\n".join(digests), MUTED, self.app.font_mono_small, (0, 10))
        else:
            self._spacer(body)

    def _macro(self, sr):
        macro = sr.get("macro_analysis", {})
        body = self._section("Layer 3 — VBA macro analysis")
        if not macro.get("available", False):
            self._status(body, "Skipped — oletools not installed.", AMBER_SOFT)
            return
        if not macro.get("has_macros"):
            self._status(body, macro.get("detail") or "No VBA macros found.", ACCENT_SOFT)
            return
        autoexec = macro.get("autoexec") or []
        critical = macro.get("critical") or []
        dropper = bool(autoexec and critical)
        self._status(body, "Auto-executing macro with an exec/download primitive "
                           "(classic dropper pattern)" if dropper else "Macros present",
                     RED_SOFT if (critical or dropper) else AMBER_SOFT, (10, 2))
        for label, items in [("Auto-run", autoexec), ("Critical", critical),
                             ("Suspicious", (macro.get("suspicious") or [])[:8]),
                             ("IOCs", (macro.get("iocs") or [])[:6])]:
            if items:
                self._line(body, f"{label}: " + ", ".join(map(str, items)))
        if macro.get("vba_stomping"):
            self._line(body, "VBA stomping: the compiled P-code differs from the "
                             "visible source (deliberate evasion).", RED_SOFT)
        if macro.get("xlm_macros"):
            self._line(body, "Excel 4.0 (XLM) macro sheet(s): "
                             + ", ".join(macro.get("xlm_evidence") or []), RED_SOFT)
        self._spacer(body)

    def _yara(self, sr):
        yara = sr.get("yara", {})
        body = self._section("Layer 4 — YARA rules")
        if not yara.get("available", False):
            self._status(body, "Skipped — yara-python not installed.", AMBER_SOFT)
            return
        if not yara.get("matched"):
            self._status(body, yara.get("detail") or "No YARA rules matched.", ACCENT_SOFT)
            return
        matches = yara.get("matches", []) or []
        self._status(body, f"{len(matches)} rule(s) matched · top severity: "
                           f"{yara.get('top_severity', 'medium')}", RED_SOFT, (10, 2))
        for m in matches:
            text = f"•  {m.get('rule', '?')}  [{m.get('severity', 'medium')}]"
            if m.get("description"):
                text += f" — {m['description']}"
            self._line(body, text)
        self._spacer(body)

    def _integrity(self, sr):
        integ = sr.get("file_integrity")
        if integ is None:
            return
        body = self._section("Layer 5 — file integrity (disguise / encryption)")
        flagged = (integ.get("disguised_executable") or integ.get("encrypted_likely")
                   or integ.get("format_mismatch"))
        self._line(body, integ.get("detail") or "—", RED_SOFT if flagged else ACCENT_SOFT,
                   self.app.font_ui, (10, 2))
        self._line(body, f"Detected format: {integ.get('detected_format', '?')}   ·   "
                         f"entropy {float(integ.get('sample_entropy', 0) or 0):.3f} bits/byte"
                         f"   ·   chi² {float(integ.get('sample_chi_square', 0) or 0):.0f}")
        for note in integ.get("notes", []) or []:
            self._line(body, note, AMBER_SOFT)
        self._line(body, "", pad=(0, 4))

    def _pe(self, sr):
        pe = sr.get("pe_analysis")
        if not pe or not pe.get("is_pe"):
            return
        body = self._section("Windows program — sections, imports, overlay")
        bad = any(pe.get(k) for k in ("packed", "injection_apis", "ransomware_apis",
                                      "recovery_inhibition", "overlay_executable",
                                      "malformed"))
        self._line(body, pe.get("detail") or "—", RED_SOFT if bad else ACCENT_SOFT,
                   self.app.font_ui, (10, 2))
        for s in (pe.get("sections") or [])[:12]:
            self._line(body, f"{s.get('name', '?'):<10} {s.get('flags', ''):<4} "
                             f"{s.get('raw_size', 0):>10,} bytes   entropy {s.get('entropy', 0):.2f}",
                       MUTED, self.app.font_mono_small)
        self._line(body, "", pad=(0, 4))

    def _guard(self, sr):
        guard = sr.get("prompt_guard")
        if guard is None:
            return
        body = self._section("Layer 6 — hidden content & prompt injection")
        status = guard.get("injection_status", "none")
        hit = status != "none" or guard.get("hidden_text_found")
        self._line(body, guard.get("detail") or "—",
                   RED_SOFT if status == "confirmed" else (AMBER_SOFT if hit else ACCENT_SOFT),
                   self.app.font_ui, (10, 2))
        for snippet in (guard.get("hidden_text_snippets") or [])[:4]:
            self._line(body, f"hidden: “{snippet[:160]}”")
        self._line(body, "", pad=(0, 4))

    def _relationships(self, sr):
        rels = sr.get("relationships")
        if rels is None:
            return
        body = self._section("Layer 7 — Office external links (template / OLE / UNC)")
        self._line(body, rels.get("detail") or "—",
                   RED_SOFT if rels.get("suspicious") else ACCENT_SOFT, self.app.font_ui, (10, 2))
        for f in (rels.get("findings") or [])[:6]:
            self._line(body, f"•  {f.get('kind')}  →  {RS.defang(str(f.get('target', '')))}")
        self._line(body, "", pad=(0, 4))

    def _archive(self, sr):
        arc = sr.get("archive")
        if not arc:
            if sr.get("file_integrity") is not None:      # v4 result for a non-archive file
                body = self._section("Layer 8 — archive contents")
                self._line(body, "Not an archive.", ACCENT_SOFT, self.app.font_ui, (10, 10))
            return
        body = self._section("Layer 8 — archive contents")
        bad = (arc.get("zip_bomb") or arc.get("zip_slip") or arc.get("executable_members")
               or arc.get("encrypted_unreadable"))
        self._line(body, arc.get("detail") or "—", RED_SOFT if bad else ACCENT_SOFT,
                   self.app.font_ui, (10, 4))
        self._members(body, arc.get("member_results"), 30, flags_key="archive_flags")
        if arc.get("not_scanned_budget"):
            self._line(body, f"+{arc['not_scanned_budget']} more member(s) listed but not "
                             f"deep-scanned (per-archive budget).", AMBER_SOFT)
        self._line(body, "", pad=(0, 4))

    def _mail(self, sr):
        mail = sr.get("mail")
        if not mail:
            return
        body = self._section("E-mail — sender, links & attachments (MailGuard)")
        auth = mail.get("auth") or {}
        bad = (auth.get("failures") or mail.get("display_name_spoof")
               or mail.get("reply_to_mismatch") or mail.get("deceptive_links")
               or mail.get("executable_attachments"))
        self._line(body, mail.get("detail") or "—", RED_SOFT if bad else ACCENT_SOFT,
                   self.app.font_ui, (10, 4))
        if mail.get("subject"):
            self._line(body, f"Subject:  {mail['subject'][:140]}")
        if auth.get("ignored_headers"):
            self._line(body, f"{auth['ignored_headers']} lower authentication header(s) "
                             "ignored (written by the sender, not your mail server).",
                       AMBER_SOFT)
        for link in (mail.get("deceptive_links") or [])[:4]:
            self._line(body, f"•  {RS.defang(link)}", RED_SOFT)
        self._members(body, mail.get("attachment_results"), 30)
        skipped = mail.get("attachments_skipped", 0) + mail.get("not_scanned_budget", 0)
        if skipped:
            self._line(body, f"{skipped} attachment(s) not deep-scanned (limits / embedded "
                             "objects).", AMBER_SOFT)
        self._line(body, "", pad=(0, 4))

    def _web(self, sr):
        web = sr.get("web")
        if not web:
            return
        body = self._section("Web page — HTML smuggling, active SVG, phishing")
        bad = (web.get("smuggling") or web.get("payloads") or web.get("svg_active")
               or web.get("credential_form"))
        detail = re.sub(r"https?://[^\s;,'\")]+", lambda m: RS.defang(m.group(0)),
                        web.get("detail") or "—")
        self._line(body, detail, RED_SOFT if bad else ACCENT_SOFT, self.app.font_ui, (10, 4))
        for url in (web.get("redirects") or [])[:4]:
            self._line(body, f"•  redirects to {RS.defang(url)}", AMBER_SOFT)
        self._members(body, web.get("payload_results"), 5)
        self._line(body, "", pad=(0, 4))

    def _ml(self, sr):
        ml = sr.get("ml_classifier")
        if not ml:
            return
        body = self._section("ML classifier — byte & PE structure (statistical)")
        model = ("rule engine (no trained model)" if ml.get("model") == "rules"
                 else f"trained model {ml.get('model')}")
        self._line(body, f"{ml.get('label', '?').capitalize()}  ·  p(suspicious) = "
                         f"{float(ml.get('probability', 0)):.2f}  ·  {model}",
                   RED_SOFT if ml.get("label") == "suspicious" else ACCENT_SOFT,
                   self.app.font_ui, (10, 4))
        for why in (ml.get("indicators") or [])[:4]:
            self._line(body, f"•  {why}")
        self._line(body, "", pad=(0, 4))

    def _virustotal(self, sr):
        vt = sr.get("virustotal", {})
        body = self._section("Layer 9 — VirusTotal reputation")
        if "not configured" in str(vt.get("details", "")):
            self._status(body, "Skipped — API key not configured (add it in Settings).",
                         AMBER_SOFT)
            return
        if vt.get("not_found"):
            self._status(body, vt.get("details") or "Unknown to VirusTotal.", MUTED)
            return
        hits = vt.get("malicious_detections", 0) + vt.get("suspicious_detections", 0)
        ratio = float(vt.get("detection_ratio", 0) or 0)
        self._status(body, f"{hits} of {vt.get('total_engines', 0)} engines flagged this file "
                           f"(detection ratio {ratio:.2f})",
                     RED_SOFT if hits else ACCENT_SOFT, (10, 4))
        if vt.get("error"):
            self._line(body, f"Error: {vt['error']}", AMBER_SOFT)
        if vt.get("permalink"):
            ctk.CTkButton(body, text="Open VirusTotal report", height=30,
                          fg_color="transparent", hover_color=PANEL_2,
                          border_width=1, border_color=BORDER_2, text_color=BLUE,
                          font=self.app.font_small,
                          command=lambda: webbrowser.open(vt["permalink"])
                          ).pack(anchor="w", padx=14, pady=(2, 10))
        else:
            self._spacer(body)

    def _llm(self, sr):
        ai = sr.get("chatgpt_analysis", {})
        body = self._section("Layer 10 — LLM semantic analysis")
        if llm_skipped(ai):
            self._status(body, "Skipped — no LLM backend available "
                               "(start a local Ollama or set an OpenAI key).", AMBER_SOFT)
            return
        flagged = ai.get("is_malicious")
        self._status(body, f"Confidence: {float(ai.get('confidence', 0) or 0):.2f} — "
                           f"{'flagged as suspicious' if flagged else 'no ransomware indicators'}",
                     RED_SOFT if flagged else ACCENT_SOFT, (10, 2))
        elements = ai.get("suspicious_elements") or []
        if elements:
            self._line(body, "Suspicious elements: " + ", ".join(map(str, elements)), AMBER_SOFT)
        details = str(ai.get("details", "")).strip()
        if details:
            self._line(body, details, pad=(2, 10))
        else:
            self._spacer(body)

    def _breakdown(self, sr):
        breakdown = self.result.get("score_breakdown", {})
        contribs = breakdown.get("contributions", []) or []
        if not contribs:
            return
        app = self.app
        body = self._section("Score breakdown — why this verdict")
        for c in contribs:
            rowf = ctk.CTkFrame(body, fg_color="transparent")
            rowf.pack(fill="x", padx=14, pady=2)
            ctk.CTkLabel(rowf, text=f"+{float(c.get('points', 0)):>5.1f}", width=52,
                         anchor="w", text_color=TEXT, font=app.font_mono_small).pack(side="left")
            ctk.CTkLabel(rowf, text=f"[{c.get('category', '?')}] {c.get('indicator', '?')}",
                         anchor="w", text_color=TEXT, font=app.font_small,
                         wraplength=440, justify="left").pack(side="left", fill="x", expand=True)
        totals = breakdown.get("category_totals", {})
        tnz = ", ".join(f"{k} {v:g}" for k, v in totals.items() if v)
        ctk.CTkLabel(body, text=f"Category totals: {tnz}" if tnz else "",
                     text_color=MUTED, font=app.font_small,
                     anchor="w").pack(fill="x", padx=14, pady=(4, 10))

    def _completeness(self, sr):
        """What was not inspected, and why (engine/completeness.py)."""
        rows = gap_rows(self.result)
        if not rows:
            return
        body = self._section(f"Not fully inspected — {self.result.get('scan_status')} scan")
        self._status(body, "The verdict covers only what was inspected:", AMBER_SOFT, pady=(10, 4))
        for layer, reason, where in rows:
            self._line(body, f"[{layer}] {reason}" + (f"   ({where})" if where else ""),
                       AMBER_SOFT, pad=(0, 2))
        self._spacer(body)

    def _provenance(self, sr):
        """Which rules, registry, profile and services produced this result."""
        rows = provenance_rows(self.result)
        if not rows:
            return
        body = self._section("Provenance")
        for label, value in rows:
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            ctk.CTkLabel(row, text=label, width=90, anchor="w",
                         text_color=MUTED, font=self.app.font_small).pack(side="left")
            ctk.CTkLabel(row, text=value, anchor="w", text_color=TEXT,
                         font=self.app.font_mono_small, wraplength=420,
                         justify="left").pack(side="left", fill="x", expand=True)

    SECTIONS = (_completeness, _file_info, _local_db, _fuzzy, _macro, _yara, _integrity, _pe, _guard,
                _relationships, _archive, _mail, _web, _ml, _virustotal, _llm, _breakdown,
                _provenance)

    # ---------------------------------------------------------------- actions
    def _actions(self):
        app, result = self.app, self.result
        actions = ctk.CTkFrame(self.scroll_area, fg_color="transparent")
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
        self.undo_button = None
        if "!/" not in path and os.path.isfile(path):
            self.quarantine_button = ctk.CTkButton(
                actions, text="Quarantine file", height=32, font=app.font_small,
                fg_color="transparent", hover_color=PANEL_2, border_width=1,
                border_color=RED, text_color=RED_SOFT, command=self._quarantine)
            self.quarantine_button.pack(side="right")
            # shown once the file is in the vault: puts it back where it was
            self.undo_button = ctk.CTkButton(
                actions, text="Undo", width=70, height=32, font=app.font_small,
                fg_color="transparent", hover_color=PANEL_2, border_width=1,
                border_color=BORDER_2, text_color=TEXT, command=self._undo_quarantine)

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
        if self.undo_button is not None:
            self.undo_button.pack(side="right", padx=(0, 8))
        self.app.gui_log.warning(f"Quarantined from GUI: {path} -> vault id {meta['id']}")
        self.app.refresh_protection_views()
        if confirm:
            messagebox.showinfo("Quarantined", f"Moved to the vault (id {meta['id']}). "
                                "Undo puts it back.", parent=self)

    def _undo_quarantine(self, confirm: bool = True):
        """Restore the file this window quarantined to where it was. The vault never
        overwrites: if a new file took its place, it comes back as
        <name>.restored-<id>. Every restore is in the audit log (RESTORED ...)."""
        item = (self.result.get("quarantine") or {}).get("id")
        if not item:
            return
        path = str(self.result.get("file_path", ""))
        if confirm and not messagebox.askyesno(
                "Undo quarantine",
                f"Put this file back where it was?\n\n{path}\n\nIt was flagged "
                f"{result_verdict(self.result)} ({result_risk(self.result)}/100). Only "
                "restore it if you are sure it is safe.", parent=self):
            return
        try:
            dest = self.app.scanner.quarantine_vault.restore(item)
        except Exception as e:
            messagebox.showerror("Undo failed", str(e), parent=self)
            return
        self.result.pop("quarantine", None)
        self.quarantine_button.configure(state="normal", text="Quarantine file")
        if self.undo_button is not None:
            self.undo_button.pack_forget()
        self.app.gui_log.warning(f"Quarantine undone from GUI: vault id {item} -> {dest}")
        self.app.refresh_protection_views()
        if confirm:
            moved = "" if str(dest) == path else f"\n\nA new file had taken its place, so it was restored as:\n{dest}"
            messagebox.showinfo("Restored", f"The file is back in its folder.{moved}", parent=self)
        return dest
