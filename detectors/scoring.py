"""
Weighted scoring matrix for the Hybrid Ransomware Detection System.

WHY THIS EXISTS
---------------
The original severity was a hardcoded equation:

    severity = 10*db_hit + 5*llm_confidence + 5*vt_ratio   (capped at 10)

That gives a *semantic* signal (the LLM's opinion of the text) the same weight
as multi-engine reputation, and offers no way to express that a structural
indicator - say a macro that calls `Shell` from `AutoOpen` - is far more
damning than a phishing-flavoured sentence. It is also opaque: the final number
explains nothing about *why* a file scored what it did.

This module replaces that with a transparent, weighted matrix. Every detection
signal contributes through an explicit rule with:
  * a CATEGORY  - technical | reputation | semantic | statistical,
  * a WEIGHT    - the points it contributes when fully triggered,
  * a DETAIL    - human-readable evidence for the report.

Design principles (these encode the requirement directly):

  1. TECHNICAL > SEMANTIC, mathematically.
     Technical indicators (local-DB hit, YARA, macro exec primitives, fuzzy
     family match) carry the heaviest weights. The SEMANTIC category (LLM text
     opinion) is capped low (SEMANTIC_CATEGORY_CAP) so a phishing lure can never
     by itself out-score a real structural indicator.

  2. SEMANTIC-ALONE CANNOT BE "HIGH".
     If *no* technical or reputation signal fired, the final band is clamped to
     at most MEDIUM, no matter how confident the LLM was about the prose.

  3. EXPLAINABILITY.
     score() returns a full per-indicator breakdown, so the report can show
     exactly which signals drove the verdict and by how much.

v4 adds technical indicators from the new layers (file integrity, hidden
content / prompt injection, Office external relationships, archive inspection,
VBA stomping and XLM macros). An archive is scored like its most dangerous
member: that member's contributions are carried over, prefixed with its name,
so the same caps and the semantic-only clamp still apply.

v4.1 adds MailGuard indicators (sender authentication, spoofing, deceptive
links, risky attachments; a mail is scored like its most dangerous attachment,
prefixed "mail_attachment:") and a fourth category, STATISTICAL, for the ML
byte-structure classifier. Like SEMANTIC it has a small cap and does not count
as a "hard" signal, so an ML opinion alone also stays at MEDIUM or below.

Two scores are produced:
  * risk_score   - 0-100, the modern, granular figure with verdict bands,
  * severity_score - the legacy 0-10 figure (risk_score/10, rounded) kept so
                     existing reports, the GUI, and tests keep working. A pure
                     local-DB hit still yields exactly 10.0; a clean file 0.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

# ---- Category weight ceilings ---------------------------------------------
# Each category's summed contribution is capped here, then categories are added
# and the total is clamped to MAX_RAW. Caps give diminishing returns when many
# weak signals of the same kind stack up.
TECHNICAL_CATEGORY_CAP = 100.0      # technical can drive the score on its own
REPUTATION_CATEGORY_CAP = 80.0
SEMANTIC_CATEGORY_CAP = 24.0        # deliberately < the MEDIUM band ceiling (49)
STATISTICAL_CATEGORY_CAP = 20.0     # ML byte-shape classifier: a weak, broad signal

MAX_RAW = 100.0

# ---- Verdict bands (on the 0-100 risk score) ------------------------------
BANDS = [
    (0, 0, "Clean"),
    (1, 24, "Low"),
    (25, 49, "Medium"),
    (50, 79, "High"),
    (80, 100, "Critical"),
]
# A semantic-only result is clamped to the top of this band.
SEMANTIC_ONLY_MAX = 49      # => "Medium"


@dataclass
class Contribution:
    """One signal's contribution to the score (the explainable unit)."""
    indicator: str
    category: str          # technical | reputation | semantic
    points: float
    detail: str

    def as_dict(self) -> Dict:
        return {
            "indicator": self.indicator,
            "category": self.category,
            "points": round(self.points, 2),
            "detail": self.detail,
        }


@dataclass
class ScoreResult:
    risk_score: int                 # 0-100
    severity_score: float           # legacy 0-10
    verdict: str                    # Clean | Low | Medium | High | Critical
    is_malicious: bool
    contributions: List[Contribution] = field(default_factory=list)
    category_totals: Dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> Dict:
        return {
            "risk_score": self.risk_score,
            "severity_score": self.severity_score,
            "verdict": self.verdict,
            "is_malicious": self.is_malicious,
            "category_totals": {k: round(v, 2) for k, v in self.category_totals.items()},
            "contributions": [c.as_dict() for c in self.contributions],
        }


def _prefixed(member: str, c: Dict, prefix: str = "archive_member") -> "Contribution":
    return Contribution(
        indicator=f"{prefix}:{c.get('indicator', '?')}",
        category=str(c.get("category", "technical")),
        points=float(c.get("points", 0) or 0),
        detail=f"[{member}] {c.get('detail', '')}".strip())


def _band(score: int) -> str:
    for low, high, label in BANDS:
        if low <= score <= high:
            return label
    return "Critical"


class ScoringMatrix:
    """Turns the per-layer signals dict into a transparent weighted score.

    `signals` shape (every key optional; missing layers simply contribute 0):
        {
          "local_db_hit": bool,
          "fuzzy":  {"matched": bool, "best_confidence": 0..1, "families": [..]},
          "macro":  {"has_macros": bool, "autoexec": [..], "critical": [..],
                     "suspicious": [..]},
          "yara":   {"matched": bool, "top_severity": "low|medium|high|critical",
                     "rules": [..]},
          "virustotal": {"malicious": int, "suspicious": int, "total": int,
                         "ratio": 0..1},
          "llm":    {"is_suspicious": bool, "confidence": 0..1, "elements": [..]},

          # v4 layers
          "integrity": {"disguised_executable": str|None, "encrypted_likely": bool,
                        "format_mismatch": bool, "detail": str},
          "prompt_guard": {"injection_status": "none|suspicious|confirmed",
                           "indicators": [..], "hidden_text_found": bool,
                           "hidden_reasons": [..]},
          "relationships": {"kinds": [..], "targets": [..]},
          "archive": {"zip_slip": bool, "zip_bomb": bool, "encrypted_unreadable": bool,
                      "executable_members": [..], "double_extension_members": [..],
                      "rtlo_members": [..], "reasons": {...},
                      "worst_member": {"name": str, "contributions": [..]}},
          # macro gains: "vba_stomping": bool, "xlm_macros": bool
        }
    """

    # ---- per-indicator weights (points when fully triggered) --------------
    W_LOCAL_DB = 100.0              # exact known-bad hash => maximum
    W_YARA = {"critical": 90.0, "high": 65.0, "medium": 40.0, "low": 18.0}
    W_YARA_EXTRA = 8.0              # each additional rule beyond the top one
    W_FUZZY = 72.0                  # scaled by structural similarity confidence
    W_MACRO_AUTOEXEC = 22.0        # an auto-run trigger exists
    W_MACRO_CRITICAL = 40.0        # first exec/download primitive (Shell, etc.)
    W_MACRO_CRITICAL_EXTRA = 8.0   # each additional critical primitive
    W_MACRO_SUSPICIOUS = 10.0      # non-critical suspicious call(s), flat
    W_MACRO_DROPPER_SYNERGY = 20.0 # autoexec AND critical => classic dropper
    W_VT_RATIO = 80.0              # scaled by detection ratio
    W_VT_FLOOR = 35.0              # a few engines flag even at a low ratio
    W_LLM = 24.0                   # scaled by confidence (semantic, capped low)

    # ---- v4 technical indicators -------------------------------------------
    W_VBA_STOMPING = 90.0          # P-code/source mismatch = deliberate evasion
    W_XLM_MACROS = 55.0            # Excel 4.0 macro sheets (rarely legitimate)
    W_DISGUISED_EXECUTABLE = 90.0  # PE/ELF/Mach-O/LNK/script behind a doc extension
    W_ENCRYPTED_CONTENT = 70.0     # signature gone + random bytes = ransomware impact
    W_FORMAT_MISMATCH = 15.0       # content doesn't match the extension
    W_INJECTION_CONFIRMED = 50.0   # prompt injection hidden in the document
    W_INJECTION_SUSPICIOUS = 15.0  # injection phrasing in visible text only
    W_HIDDEN_CONTENT = 15.0        # concealed text (hidden runs, invisible PDF text)
    W_RTI = {                      # Office external relationships
        "exploit_scheme": 90.0,          # ms-msdt:, search-ms:, mhtml: ...
        "follina_style_ole": 90.0,       # external OLE link ending in '!'
        "remote_template": 70.0,         # T1221 remote template injection
        "external_ole": 70.0,
        "unc_ntlm_leak": 70.0,           # T1187 forced NTLM authentication
        "rtf_remote_template": 70.0,
        "external_frame": 40.0,
        "external_subdocument": 40.0,
        "rtf_ole_autoupdate": 40.0,
    }
    W_RTI_EXTRA = 8.0              # each additional distinct relationship kind
    W_ARCHIVE_SLIP = 80.0          # path traversal / symlink entries
    W_ARCHIVE_BOMB = 60.0          # decompression bomb
    W_ARCHIVE_DOUBLE_EXT = 60.0    # invoice.pdf.exe
    W_ARCHIVE_RTLO = 60.0          # right-to-left-override filename spoof
    W_ARCHIVE_EXECUTABLE = 35.0    # executable/script/shortcut inside an archive
    W_ARCHIVE_ENCRYPTED = 20.0     # encrypted content the scanner could not open

    # ---- v4.1: MailGuard (.eml / .msg) ---------------------------------------
    W_MAIL_DMARC_FAIL = 35.0       # receiving server says the From domain is forged
    W_MAIL_AUTH_FAIL = 20.0        # SPF or DKIM failed (DMARC not failed / absent)
    W_MAIL_DISPLAY_SPOOF = 30.0    # "billing@bank.com" <x@evil.tld>
    W_MAIL_REPLY_TO = 15.0         # replies diverted to another organisation
    W_MAIL_DECEPTIVE_LINK = 25.0   # link text shows one domain, href goes to another
    W_MAIL_RISKY_ATTACHMENT = 45.0 # executable / script / macro-enabled attachment
    W_MAIL_DOUBLE_EXT = 60.0
    W_MAIL_RTLO = 60.0
    W_MAIL_LURE_SUBJECT = 8.0      # semantic: urgency/payment/credential phrasing
    W_MAIL_ARCHIVE_PASSWORD = 30.0 # encrypted archive + its password in the mail (gateway evasion)

    # ---- v4.4: web content + images ------------------------------------------------
    W_HTML_SMUGGLING = 70.0        # Blob download construct + embedded payload (T1027.006)
    W_WEB_PAYLOAD = 60.0           # executable / archive / disc image embedded in a page
    W_WEB_DOWNLOAD_CONSTRUCT = 15.0  # the construct alone (web apps use it for exports)
    W_SVG_ACTIVE = 40.0            # script / event handlers / foreignObject in an SVG
    W_WEB_CREDENTIAL = 35.0        # password captured and sent out (phishing page)
    W_WEB_REDIRECT = 20.0          # page forwards to an external URL
    W_JS_OBFUSCATION = 15.0        # two or more obfuscation markers
    W_IMAGE_APPENDED_PAYLOAD = 70.0  # executable / archive after the end of an image

    # ---- 4.4.0-beta.2: Linux ELF triage and QR codes ------------------------------
    W_ELF_BEHAVIOUR = {             # hostile-only strings in an ELF, by category
        "ransom_note": 60.0, "miner": 45.0, "reverse_shell": 45.0,
        "download_exec": 35.0, "evasion": 25.0, "persistence": 20.0,
    }
    W_ELF_BEHAVIOUR_EXTRA = 8.0     # each additional category
    W_ELF_PACKED = 20.0             # UPX or near-random content with few sections
    W_ELF_NO_SECTIONS = 10.0        # runnable ELF with its section table removed
    W_QR_SUSPICIOUS_URL = 35.0      # QR code leads to an IP / shortener / punycode / lure URL
    W_QR_URL = 8.0                  # semantic: a QR code carries a web link (quishing pattern)
    W_SCRIPT_BEHAVIOUR = {          # script attachments (JS / VBS / HTA / PS1 / BAT), by category
        "recovery": 70.0, "dropper": 65.0, "ransom_note": 60.0, "defence_evasion": 40.0,
        "persistence": 25.0, "download": 20.0, "execute": 20.0,
    }
    W_SCRIPT_BEHAVIOUR_EXTRA = 8.0  # each additional category
    W_SCRIPT_ENCODED = 30.0         # Script Encoder output (.vbe / .jse): hides the source
    W_SCRIPT_OBFUSCATION = 20.0     # two or more obfuscation markers

    # ---- v4.1: ML classifier (statistical) --------------------------------------
    W_ML = 20.0                    # scaled by P(suspicious)

    def score(self, signals: Dict) -> ScoreResult:
        contribs: List[Contribution] = []

        # ---------------- TECHNICAL ----------------
        if signals.get("local_db_hit"):
            contribs.append(Contribution(
                "local_db_hit", "technical", self.W_LOCAL_DB,
                "Exact hash present in local malicious-hash database."))

        yara = signals.get("yara") or {}
        if yara.get("matched"):
            top = str(yara.get("top_severity", "medium")).lower()
            base = self.W_YARA.get(top, self.W_YARA["medium"])
            rules = yara.get("rules", []) or []
            extra = max(0, len(rules) - 1) * self.W_YARA_EXTRA
            names = ", ".join(rules) if rules else "(unnamed)"
            contribs.append(Contribution(
                "yara_match", "technical", base + extra,
                f"YARA rule(s) matched [{names}], top severity '{top}'."))

        fuzzy = signals.get("fuzzy") or {}
        if fuzzy.get("matched"):
            conf = float(fuzzy.get("best_confidence", 0) or 0)
            fams = ", ".join(fuzzy.get("families", []) or []) or "known family"
            contribs.append(Contribution(
                "fuzzy_family_match", "technical", self.W_FUZZY * conf,
                f"Structural similarity to {fams} (confidence {conf:.2f})."))

        macro = signals.get("macro") or {}
        if macro.get("has_macros"):
            autoexec = macro.get("autoexec", []) or []
            critical = macro.get("critical", []) or []
            suspicious = macro.get("suspicious", []) or []

            if autoexec:
                contribs.append(Contribution(
                    "macro_autoexec", "technical", self.W_MACRO_AUTOEXEC,
                    f"Auto-run trigger(s): {', '.join(autoexec)}."))
            if critical:
                pts = self.W_MACRO_CRITICAL + max(0, len(critical) - 1) * self.W_MACRO_CRITICAL_EXTRA
                contribs.append(Contribution(
                    "macro_exec_primitive", "technical", pts,
                    f"Execution/download primitive(s): {', '.join(critical)}."))
            elif suspicious:
                contribs.append(Contribution(
                    "macro_suspicious", "technical", self.W_MACRO_SUSPICIOUS,
                    f"Suspicious macro call(s): {', '.join(suspicious[:6])}."))
            if autoexec and critical:
                contribs.append(Contribution(
                    "macro_dropper_synergy", "technical", self.W_MACRO_DROPPER_SYNERGY,
                    "Auto-executing macro combined with an exec/download "
                    "primitive (classic dropper pattern)."))
            if macro.get("vba_stomping"):
                contribs.append(Contribution(
                    "vba_stomping", "technical", self.W_VBA_STOMPING,
                    "VBA stomping: compiled P-code differs from the visible macro "
                    "source (deliberate evasion of source-based analysis)."))
            if macro.get("xlm_macros"):
                contribs.append(Contribution(
                    "xlm_macros", "technical", self.W_XLM_MACROS,
                    "Excel 4.0 (XLM) macro sheet present - a legacy macro language "
                    "abused by loaders such as Emotet and Qakbot."))

        contribs.extend(self._v4_technical(signals))
        contribs.extend(self._mail(signals))
        contribs.extend(self._web(signals))
        contribs.extend(self._elf_and_qr(signals))
        contribs.extend(self._script(signals))

        # ---------------- STATISTICAL ----------------
        ml = signals.get("ml") or {}
        # When the integrity layer already proved the content is encrypted,
        # the ML layer is looking at the same evidence: don't count it twice.
        same_evidence = bool((signals.get("integrity") or {}).get("encrypted_likely"))
        if ml.get("suspicious") and not same_evidence:
            prob = float(ml.get("probability", 0) or 0)
            why = "; ".join((ml.get("indicators") or [])[:3])
            contribs.append(Contribution(
                "ml_classifier", "statistical", self.W_ML * prob,
                f"Static ML classifier ({ml.get('model', 'rules')}) rates the byte "
                f"structure suspicious (p={prob:.2f})" + (f": {why}." if why else ".")))

        # ---------------- REPUTATION ----------------
        vt = signals.get("virustotal") or {}
        vt_ratio = float(vt.get("ratio", 0) or 0)
        vt_flagged = int(vt.get("malicious", 0) or 0) + int(vt.get("suspicious", 0) or 0)
        if vt_flagged > 0:
            pts = max(self.W_VT_FLOOR, self.W_VT_RATIO * vt_ratio)
            contribs.append(Contribution(
                "virustotal", "reputation", pts,
                f"VirusTotal: {vt_flagged}/{vt.get('total', 0)} engines flagged "
                f"(ratio {vt_ratio:.2f})."))

        # ---------------- SEMANTIC ----------------
        llm = signals.get("llm") or {}
        if llm.get("is_suspicious"):
            conf = float(llm.get("confidence", 0) or 0)
            elems = ", ".join(llm.get("elements", []) or [])
            detail = f"LLM flagged the text as a likely lure (confidence {conf:.2f})."
            if elems:
                detail += f" Elements: {elems}."
            contribs.append(Contribution(
                "llm_semantic", "semantic", self.W_LLM * conf, detail))

        # ---------------- AGGREGATE with per-category caps -----------------
        caps = {
            "technical": TECHNICAL_CATEGORY_CAP,
            "reputation": REPUTATION_CATEGORY_CAP,
            "semantic": SEMANTIC_CATEGORY_CAP,
            "statistical": STATISTICAL_CATEGORY_CAP,
        }
        raw_totals = {"technical": 0.0, "reputation": 0.0, "semantic": 0.0,
                      "statistical": 0.0}
        for c in contribs:
            raw_totals[c.category] = raw_totals.get(c.category, 0.0) + c.points
        category_totals = {cat: min(total, caps.get(cat, total))
                           for cat, total in raw_totals.items()}

        raw_score = min(MAX_RAW, sum(category_totals.values()))

        # Rule 2: a semantic/statistical-only result cannot exceed MEDIUM.
        has_hard_signal = (category_totals.get("technical", 0) > 0
                           or category_totals.get("reputation", 0) > 0)
        if not has_hard_signal:
            raw_score = min(raw_score, SEMANTIC_ONLY_MAX)

        risk_score = int(round(raw_score))
        severity_score = round(risk_score / 10.0, 1)   # legacy 0-10
        verdict = _band(risk_score)

        # A file is "malicious" if any layer fired. (Mirrors the original
        # OR-of-layers behaviour; the score then expresses *how* malicious.)
        is_malicious = bool(contribs) and risk_score > 0

        return ScoreResult(
            risk_score=risk_score,
            severity_score=severity_score,
            verdict=verdict,
            is_malicious=is_malicious,
            contributions=contribs,
            category_totals=category_totals,
        )

    # ------------------------------------------------------------------ v4
    def _v4_technical(self, signals: Dict) -> List[Contribution]:
        out: List[Contribution] = []

        integ = signals.get("integrity") or {}
        if integ.get("disguised_executable"):
            out.append(Contribution(
                "disguised_executable", "technical", self.W_DISGUISED_EXECUTABLE,
                integ.get("detail") or "Executable content behind a document extension."))
        elif integ.get("encrypted_likely"):
            out.append(Contribution(
                "encrypted_content", "technical", self.W_ENCRYPTED_CONTENT,
                (integ.get("detail") or "Content looks encrypted.")
                + " Possible ransomware impact (MITRE ATT&CK T1486)."))
        elif integ.get("format_mismatch"):
            out.append(Contribution(
                "format_mismatch", "technical", self.W_FORMAT_MISMATCH,
                integ.get("detail") or "Content does not match the file extension."))

        guard = signals.get("prompt_guard") or {}
        status = guard.get("injection_status", "none")
        indicators = ", ".join(guard.get("indicators", []) or [])
        if status == "confirmed":
            out.append(Contribution(
                "prompt_injection", "technical", self.W_INJECTION_CONFIRMED,
                f"Prompt-injection attempt aimed at AI analysis ({indicators})."))
        elif status == "suspicious":
            out.append(Contribution(
                "prompt_injection_phrasing", "technical", self.W_INJECTION_SUSPICIOUS,
                f"Visible text addresses an AI analyst ({indicators})."))
        if guard.get("hidden_text_found"):
            reasons = ", ".join(guard.get("hidden_reasons", []) or []) or "concealed text"
            out.append(Contribution(
                "hidden_content", "technical", self.W_HIDDEN_CONTENT,
                f"Concealed document content ({reasons})."))

        if integ.get("appended_payload"):
            out.append(Contribution(
                "image_appended_payload", "technical", self.W_IMAGE_APPENDED_PAYLOAD,
                f"{str(integ['appended_payload']).upper()} data appended after the end of an "
                f"image: a payload hidden in a picture."))

        rels = signals.get("relationships") or {}
        kinds = [k for k in (rels.get("kinds") or []) if k in self.W_RTI]
        if kinds:
            top = max(kinds, key=lambda k: self.W_RTI[k])
            pts = self.W_RTI[top] + max(0, len(kinds) - 1) * self.W_RTI_EXTRA
            targets = ", ".join((rels.get("targets") or [])[:3])
            out.append(Contribution(
                "external_relationship", "technical", pts,
                f"Office external relationship(s) [{', '.join(kinds)}]"
                + (f" -> {targets}" if targets else "") + "."))

        arc = signals.get("archive") or {}
        reasons = arc.get("reasons") or {}
        if arc.get("zip_slip"):
            out.append(Contribution("archive_zip_slip", "technical", self.W_ARCHIVE_SLIP,
                                    f"Archive path traversal / symlink entry. "
                                    f"{reasons.get('zip_slip', '')}".strip()))
        if arc.get("zip_bomb"):
            out.append(Contribution("archive_zip_bomb", "technical", self.W_ARCHIVE_BOMB,
                                    f"Decompression bomb. {reasons.get('zip_bomb', '')}".strip()))
        if arc.get("double_extension_members"):
            out.append(Contribution(
                "archive_double_extension", "technical", self.W_ARCHIVE_DOUBLE_EXT,
                "Executable disguised with a double extension: "
                + ", ".join(arc["double_extension_members"][:3]) + "."))
        if arc.get("rtlo_members"):
            out.append(Contribution(
                "archive_rtlo_spoof", "technical", self.W_ARCHIVE_RTLO,
                "Right-to-left-override character used to spoof a file name: "
                + ", ".join(arc["rtlo_members"][:3]) + "."))
        if arc.get("executable_members"):
            out.append(Contribution(
                "archive_executable", "technical", self.W_ARCHIVE_EXECUTABLE,
                "Executable/script/shortcut inside the archive: "
                + ", ".join(arc["executable_members"][:3]) + "."))
        if arc.get("encrypted_unreadable"):
            out.append(Contribution(
                "archive_encrypted", "technical", self.W_ARCHIVE_ENCRYPTED,
                "Encrypted archive content the scanner could not open "
                "(a common way to slip payloads past scanners)."))
        worst = arc.get("worst_member") or {}
        for c in worst.get("contributions", []) or []:
            out.append(_prefixed(worst.get("name", "member"), c))
        return out


    # ------------------------------------------------------------------ v4.1
    def _mail(self, signals: Dict) -> List[Contribution]:
        out: List[Contribution] = []
        mail = signals.get("mail") or {}
        if not mail:
            return out
        failures = mail.get("auth_failures") or []
        if "DMARC" in failures:
            out.append(Contribution(
                "mail_dmarc_fail", "technical", self.W_MAIL_DMARC_FAIL,
                f"Receiving server recorded DMARC failure for {mail.get('from_domain') or 'the sender'} "
                f"({', '.join(failures)} failed) - the From domain is likely forged."))
        elif failures:
            out.append(Contribution(
                "mail_auth_fail", "technical", self.W_MAIL_AUTH_FAIL,
                f"Sender authentication failed: {', '.join(failures)}."))
        if mail.get("display_name_spoof"):
            out.append(Contribution("mail_display_name_spoof", "technical",
                                    self.W_MAIL_DISPLAY_SPOOF,
                                    f"Sender spoofing: {mail.get('display_name_spoof_reason', '')}."))
        if mail.get("reply_to_mismatch"):
            out.append(Contribution(
                "mail_reply_to_mismatch", "technical", self.W_MAIL_REPLY_TO,
                f"Replies are diverted to {mail.get('reply_to_domain')} instead of "
                f"{mail.get('from_domain')} (business-e-mail-compromise pattern)."))
        links = mail.get("deceptive_links") or []
        if links:
            out.append(Contribution("mail_deceptive_link", "technical",
                                    self.W_MAIL_DECEPTIVE_LINK,
                                    "Deceptive link(s): " + "; ".join(links[:2]) + "."))
        if mail.get("double_extension_attachments"):
            out.append(Contribution(
                "mail_double_extension", "technical", self.W_MAIL_DOUBLE_EXT,
                "Attachment disguised with a double extension: "
                + ", ".join(mail["double_extension_attachments"][:3]) + "."))
        if mail.get("rtlo_attachments"):
            out.append(Contribution(
                "mail_rtlo_spoof", "technical", self.W_MAIL_RTLO,
                "Right-to-left-override character used to spoof an attachment name: "
                + ", ".join(mail["rtlo_attachments"][:3]) + "."))
        if mail.get("executable_attachments"):
            out.append(Contribution(
                "mail_risky_attachment", "technical", self.W_MAIL_RISKY_ATTACHMENT,
                "Executable / script / macro-enabled attachment: "
                + ", ".join(mail["executable_attachments"][:3]) + "."))
        if mail.get("lure_subject"):
            out.append(Contribution(
                "mail_lure_subject", "semantic", self.W_MAIL_LURE_SUBJECT,
                f"Subject uses lure phrasing ({', '.join(mail['lure_subject'])})."))
        if mail.get("archive_password_in_body"):
            out.append(Contribution(
                "mail_archive_password_in_body", "technical", self.W_MAIL_ARCHIVE_PASSWORD,
                "Encrypted archive whose password is written in the message (hides the "
                "content from mail gateways): "
                + ", ".join(n.rsplit("!/", 1)[-1] for n in mail["archive_password_in_body"][:3])
                + "."))
        worst = mail.get("worst_attachment") or {}
        for c in worst.get("contributions", []) or []:
            out.append(_prefixed(worst.get("name", "attachment"), c, "mail_attachment"))
        return out

    # ------------------------------------------------------------------ v4.4
    def _elf_and_qr(self, signals: Dict) -> List[Contribution]:
        out: List[Contribution] = []
        elf = signals.get("elf") or {}
        cats = [c for c in (elf.get("categories") or {}) if c in self.W_ELF_BEHAVIOUR]
        if cats:
            cats.sort(key=lambda c: -self.W_ELF_BEHAVIOUR[c])
            pts = (self.W_ELF_BEHAVIOUR[cats[0]]
                   + max(0, len(cats) - 1) * self.W_ELF_BEHAVIOUR_EXTRA)
            examples = "; ".join(f"{c}: {elf['categories'][c][0]}" for c in cats[:3])
            out.append(Contribution(
                "elf_behaviour", "technical", pts,
                f"Linux executable contains hostile-only strings ({examples})."))
        if elf.get("packed"):
            out.append(Contribution(
                "elf_packed", "technical", self.W_ELF_PACKED,
                f"Linux executable is packed ({elf.get('packer') or 'unknown packer'})."))
        if elf.get("no_section_table"):
            out.append(Contribution(
                "elf_no_section_table", "technical", self.W_ELF_NO_SECTIONS,
                "Linux executable has its section table removed (anti-analysis)."))
        qr = signals.get("qr") or {}
        if qr.get("suspicious"):
            first = qr["suspicious"][0]
            out.append(Contribution(
                "qr_code_suspicious_url", "technical", self.W_QR_SUSPICIOUS_URL,
                f"QR code leads to {first['url']} ({'; '.join(first['reasons'][:3])})."))
        elif qr.get("urls"):
            out.append(Contribution(
                "qr_code_url", "semantic", self.W_QR_URL,
                f"QR code carries a web link ({qr['urls'][0]}); "
                "links in QR codes bypass text filters."))
        return out

    def _script(self, signals: Dict) -> List[Contribution]:
        out: List[Contribution] = []
        sc = signals.get("script") or {}
        if not sc:
            return out
        cats = dict(sc.get("categories") or {})
        if "download" in cats and "execute" in cats:      # the combination is the dropper
            cats["dropper"] = cats.pop("download") + cats.pop("execute")
        names = sorted((c for c in cats if c in self.W_SCRIPT_BEHAVIOUR),
                       key=lambda c: -self.W_SCRIPT_BEHAVIOUR[c])
        if names:
            pts = (self.W_SCRIPT_BEHAVIOUR[names[0]]
                   + max(0, len(names) - 1) * self.W_SCRIPT_BEHAVIOUR_EXTRA)
            examples = "; ".join(f"{c}: {cats[c][0]}" for c in names[:3])
            out.append(Contribution(
                "script_behaviour", "technical", pts,
                f"{sc.get('language') or 'Script'} ({examples})."))
        if sc.get("encoded"):
            out.append(Contribution(
                "script_encoded", "technical", self.W_SCRIPT_ENCODED,
                "Script is encoded with the Windows Script Encoder (source hidden)."))
        obf = [o for o in (sc.get("obfuscation") or []) if not o.startswith("Script Encoder")]
        if len(obf) >= 2:
            out.append(Contribution(
                "script_obfuscation", "technical", self.W_SCRIPT_OBFUSCATION,
                "Obfuscated script: " + ", ".join(obf[:4]) + "."))
        return out

    def _web(self, signals: Dict) -> List[Contribution]:
        out: List[Contribution] = []
        web = signals.get("web") or {}
        if not web:
            return out
        if web.get("smuggling"):
            out.append(Contribution(
                "html_smuggling", "technical", self.W_HTML_SMUGGLING,
                "HTML smuggling (T1027.006): " + "; ".join(web.get("smuggling_reasons") or [])
                + "."))
        elif web.get("smuggling_construct"):
            out.append(Contribution(
                "web_download_construct", "technical", self.W_WEB_DOWNLOAD_CONSTRUCT,
                "Page builds a file in the browser and saves it (no embedded payload found)."))
        if web.get("payloads"):
            out.append(Contribution(
                "web_embedded_payload", "technical", self.W_WEB_PAYLOAD,
                "File embedded in the page: " + ", ".join(web["payloads"][:3]) + "."))
        if web.get("svg_active"):
            out.append(Contribution(
                "svg_active_content", "technical", self.W_SVG_ACTIVE,
                "SVG image carries active content: " + ", ".join(web["svg_active"]) + "."))
        if web.get("credential_form"):
            out.append(Contribution(
                "web_credential_capture", "technical", self.W_WEB_CREDENTIAL,
                "Credential capture: " + "; ".join(web.get("credential_reasons") or []) + "."))
        if web.get("redirects"):
            out.append(Contribution(
                "web_redirect", "technical", self.W_WEB_REDIRECT,
                f"Redirects to {len(web['redirects'])} external URL(s)."))
        if len(web.get("obfuscation") or []) >= 2:
            out.append(Contribution(
                "js_obfuscation", "technical", self.W_JS_OBFUSCATION,
                "Obfuscated script: " + ", ".join(web["obfuscation"]) + "."))
        worst = web.get("worst_payload") or {}
        for c in worst.get("contributions", []) or []:
            out.append(_prefixed(worst.get("name", "payload"), c, "web_payload"))
        return out
