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

v4.6 makes the signals typed (detectors/signals.py) and splits the scorer into
one function per layer, registered in SCORERS (the same pattern as the report's
FINDING_SECTIONS): a new layer adds a dataclass, a scorer and one entry.

Two scores are produced:
  * risk_score   - 0-100, the modern, granular figure with verdict bands,
  * severity_score - the legacy 0-10 figure (risk_score/10, rounded) kept so
                     existing reports, the GUI, and tests keep working. A pure
                     local-DB hit still yields exactly 10.0; a clean file 0.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Union

from .registry import REGISTRY
from .signals import Signals, WorstMember, as_signals

# ---- Category weight ceilings ---------------------------------------------
# Each category's summed contribution is capped here, then categories are added
# and the total is clamped to MAX_RAW. Caps give diminishing returns when many
# weak signals of the same kind stack up.
TECHNICAL_CATEGORY_CAP = REGISTRY.caps["technical"]      # technical can drive the score on its own
REPUTATION_CATEGORY_CAP = REGISTRY.caps["reputation"]
SEMANTIC_CATEGORY_CAP = REGISTRY.caps["semantic"]        # below the top of Medium (49)
STATISTICAL_CATEGORY_CAP = REGISTRY.caps["statistical"]  # ML byte-shape classifier: weak, broad
DYNAMIC_CATEGORY_CAP = REGISTRY.caps["dynamic"]          # behaviour observed in a sandbox

MAX_RAW = REGISTRY.max_raw

# ---- Verdict bands (on the 0-100 risk score) ------------------------------
BANDS = [
    (0, 0, "Clean"),
    (1, 24, "Low"),
    (25, 49, "Medium"),
    (50, 79, "High"),
    (80, 100, "Critical"),
]
# A semantic-only result is clamped to the top of this band.
SEMANTIC_ONLY_MAX = REGISTRY.semantic_only_max      # => "Medium"


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
    registry_version: str = ""

    def as_dict(self) -> Dict:
        return {
            "risk_score": self.risk_score,
            "severity_score": self.severity_score,
            "verdict": self.verdict,
            "is_malicious": self.is_malicious,
            "category_totals": {k: round(v, 2) for k, v in self.category_totals.items()},
            "registry_version": self.registry_version,
            "contributions": [c.as_dict() for c in self.contributions],
        }


def _prefixed(member: str, c: Dict, prefix: str = "archive_member") -> Contribution:
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
    """Turns a file's Signals (detectors/signals.py) into a transparent
    weighted score. Each layer's evidence is turned into Contributions by one
    scorer function in SCORERS; the categories are then capped and added."""

    # Weights live in detectors/indicators.yaml (one place for weights, categories
    # and labels); they are attached to this class as W_* attributes at import
    # time, and an instance can carry reviewed overrides (see __init__).

    if TYPE_CHECKING:                     # W_* weights are attached from the registry
        def __getattr__(self, name: str) -> Any: ...

    def __init__(self, weights_override: Optional[Dict] = None):
        self.registry = REGISTRY.with_overrides(weights_override) if weights_override else REGISTRY
        for name, value in (weights_override or {}).items():
            setattr(self, name, value)

    def score(self, signals: Union[Signals, Dict[str, Any]]) -> ScoreResult:
        s = as_signals(signals)
        contribs = [c for scorer in SCORERS for c in scorer(self, s)]
        return self._aggregate(contribs, s)

    def _aggregate(self, contribs: List[Contribution], s: Signals) -> ScoreResult:
        """Per-category caps, the semantic-only clamp, the allowlist, the bands."""
        caps = {
            "technical": TECHNICAL_CATEGORY_CAP,
            "reputation": REPUTATION_CATEGORY_CAP,
            "semantic": SEMANTIC_CATEGORY_CAP,
            "statistical": STATISTICAL_CATEGORY_CAP,
            "dynamic": DYNAMIC_CATEGORY_CAP,
        }
        raw_totals = {"technical": 0.0, "reputation": 0.0, "semantic": 0.0,
                      "statistical": 0.0}
        if any(c.category == "dynamic" for c in contribs):
            raw_totals["dynamic"] = 0.0
        for c in contribs:
            raw_totals[c.category] = raw_totals.get(c.category, 0.0) + c.points
        category_totals = {cat: min(total, caps.get(cat, total))
                           for cat, total in raw_totals.items()}

        raw_score = min(MAX_RAW, sum(category_totals.values()))

        # Rule 2: a semantic/statistical-only result cannot exceed MEDIUM.
        has_hard_signal = (category_totals.get("technical", 0) > 0
                           or category_totals.get("reputation", 0) > 0
                           or category_totals.get("dynamic", 0) > 0)
        if not has_hard_signal:
            raw_score = min(raw_score, SEMANTIC_ONLY_MAX)

        # Allowlist (a SHA-256 the user marked as known-good): the evidence is kept in
        # the report but not scored - unless the same hash is in the malware database.
        if s.allowlisted and not s.local_db_hit:
            raw_score = 0.0
            contribs = [Contribution(
                "allowlisted", "technical", 0.0,
                f"SHA-256 is on the allowlist ({s.allowlisted}); "
                + (f"{len(contribs)} finding(s) kept for reference, not scored."
                   if contribs else "no findings."))]
            category_totals = {k: 0.0 for k in category_totals}

        risk_score = int(round(raw_score))
        # A file is "malicious" if any layer fired. (Mirrors the original
        # OR-of-layers behaviour; the score then expresses *how* malicious.)
        return ScoreResult(
            risk_score=risk_score,
            severity_score=round(risk_score / 10.0, 1),      # legacy 0-10
            verdict=_band(risk_score),
            is_malicious=risk_score > 0 and any(c.points > 0 for c in contribs),
            contributions=contribs,
            category_totals=category_totals,
            registry_version=self.registry.version + (" +override" if self.registry is not REGISTRY else ""),
        )


Scorer = Callable[[ScoringMatrix, Signals], List[Contribution]]
C = Contribution


def _worst(worst: Optional[WorstMember], default: str, prefix: str) -> List[Contribution]:
    """A container is scored like its most dangerous member."""
    if worst is None:
        return []
    return [_prefixed(worst.name or default, c, prefix) for c in worst.contributions or []]


# --------------------------------------------------------------------- technical
def _local_db(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    if not s.local_db_hit:
        return []
    return [C("local_db_hit", "technical", m.W_LOCAL_DB,
              "Exact hash present in local malicious-hash database.")]


def _yara(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    y = s.yara
    if y is None or not y.matched:
        return []
    top = str(y.top_severity or "medium").lower()
    base = m.W_YARA.get(top, m.W_YARA["medium"])
    rules = y.rules or []
    extra = max(0, len(rules) - 1) * m.W_YARA_EXTRA
    names = ", ".join(rules) if rules else "(unnamed)"
    return [C("yara_match", "technical", base + extra,
              f"YARA rule(s) matched [{names}], top severity '{top}'.")]


def _fuzzy(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    f = s.fuzzy
    if f is None or not f.matched:
        return []
    conf = float(f.best_confidence or 0)
    fams = ", ".join(f.families or []) or "known family"
    return [C("fuzzy_family_match", "technical", m.W_FUZZY * conf,
              f"Structural similarity to {fams} (confidence {conf:.2f}).")]


def _macro(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    mac = s.macro
    if mac is None or not mac.has_macros:
        return []
    out: List[Contribution] = []
    autoexec, critical, suspicious = mac.autoexec or [], mac.critical or [], mac.suspicious or []
    if autoexec:
        out.append(C("macro_autoexec", "technical", m.W_MACRO_AUTOEXEC,
                     f"Auto-run trigger(s): {', '.join(autoexec)}."))
    if critical:
        pts = m.W_MACRO_CRITICAL + max(0, len(critical) - 1) * m.W_MACRO_CRITICAL_EXTRA
        out.append(C("macro_exec_primitive", "technical", pts,
                     f"Execution/download primitive(s): {', '.join(critical)}."))
    elif suspicious:
        out.append(C("macro_suspicious", "technical", m.W_MACRO_SUSPICIOUS,
                     f"Suspicious macro call(s): {', '.join(suspicious[:6])}."))
    if autoexec and critical:
        out.append(C("macro_dropper_synergy", "technical", m.W_MACRO_DROPPER_SYNERGY,
                     "Auto-executing macro combined with an exec/download "
                     "primitive (classic dropper pattern)."))
    if mac.vba_stomping:
        out.append(C("vba_stomping", "technical", m.W_VBA_STOMPING,
                     "VBA stomping: compiled P-code differs from the visible macro "
                     "source (deliberate evasion of source-based analysis)."))
    if mac.xlm_macros:
        out.append(C("xlm_macros", "technical", m.W_XLM_MACROS,
                     "Excel 4.0 (XLM) macro sheet present - a legacy macro language "
                     "abused by loaders such as Emotet and Qakbot."))
    return out


def _integrity(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    i = s.integrity
    if i is None:
        return []
    if i.disguised_executable:
        return [C("disguised_executable", "technical", m.W_DISGUISED_EXECUTABLE,
                  i.detail or "Executable content behind a document extension.")]
    if i.encrypted_likely:
        return [C("encrypted_content", "technical", m.W_ENCRYPTED_CONTENT,
                  (i.detail or "Content looks encrypted.")
                  + " Possible ransomware impact (MITRE ATT&CK T1486).")]
    if i.format_mismatch:
        return [C("format_mismatch", "technical", m.W_FORMAT_MISMATCH,
                  i.detail or "Content does not match the file extension.")]
    return []


def _prompt_guard(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    g = s.prompt_guard
    if g is None:
        return []
    out: List[Contribution] = []
    indicators = ", ".join(g.indicators or [])
    if g.injection_status == "confirmed":
        out.append(C("prompt_injection", "technical", m.W_INJECTION_CONFIRMED,
                     f"Prompt-injection attempt aimed at AI analysis ({indicators})."))
    elif g.injection_status == "suspicious":
        out.append(C("prompt_injection_phrasing", "technical", m.W_INJECTION_SUSPICIOUS,
                     f"Visible text addresses an AI analyst ({indicators})."))
    if g.hidden_text_found:
        reasons = ", ".join(g.hidden_reasons or []) or "concealed text"
        out.append(C("hidden_content", "technical", m.W_HIDDEN_CONTENT,
                     f"Concealed document content ({reasons})."))
    return out


def _appended_payload(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    i = s.integrity
    if i is None or not i.appended_payload:
        return []
    return [C("image_appended_payload", "technical", m.W_IMAGE_APPENDED_PAYLOAD,
              f"{str(i.appended_payload).upper()} data appended after the end of an "
              f"image: a payload hidden in a picture.")]


def _relationships(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    r = s.relationships
    kinds = [k for k in (r.kinds if r else []) or [] if k in m.W_RTI]
    if not r or not kinds:
        return []
    top = max(kinds, key=lambda k: m.W_RTI[k])
    pts = m.W_RTI[top] + max(0, len(kinds) - 1) * m.W_RTI_EXTRA
    targets = ", ".join((r.targets or [])[:3])
    return [C("external_relationship", "technical", pts,
              f"Office external relationship(s) [{', '.join(kinds)}]"
              + (f" -> {targets}" if targets else "") + ".")]


def _archive(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    a = s.archive
    if a is None:
        return []
    out: List[Contribution] = []
    reasons = a.reasons or {}
    if a.zip_slip:
        out.append(C("archive_zip_slip", "technical", m.W_ARCHIVE_SLIP,
                     f"Archive path traversal / symlink entry. "
                     f"{reasons.get('zip_slip', '')}".strip()))
    if a.zip_bomb:
        out.append(C("archive_zip_bomb", "technical", m.W_ARCHIVE_BOMB,
                     f"Decompression bomb. {reasons.get('zip_bomb', '')}".strip()))
    if a.double_extension_members:
        out.append(C("archive_double_extension", "technical", m.W_ARCHIVE_DOUBLE_EXT,
                     "Executable disguised with a double extension: "
                     + ", ".join(a.double_extension_members[:3]) + "."))
    if a.rtlo_members:
        out.append(C("archive_rtlo_spoof", "technical", m.W_ARCHIVE_RTLO,
                     "Right-to-left-override character used to spoof a file name: "
                     + ", ".join(a.rtlo_members[:3]) + "."))
    if a.executable_members:
        out.append(C("archive_executable", "technical", m.W_ARCHIVE_EXECUTABLE,
                     "Executable/script/shortcut inside the archive: "
                     + ", ".join(a.executable_members[:3]) + "."))
    if a.skipped_members:
        out.append(C("archive_partially_scanned", "technical", m.W_ARCHIVE_PARTIAL,
                     f"{a.skipped_members} archive member(s) past the member limit were not "
                     "unpacked (their names were checked)."))
    if a.encrypted_unreadable:
        out.append(C("archive_encrypted", "technical", m.W_ARCHIVE_ENCRYPTED,
                     "Encrypted archive content the scanner could not open "
                     "(a common way to slip payloads past scanners)."))
    return out + _worst(a.worst, "member", "archive_member")


def _mail(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    mail = s.mail
    if mail is None:
        return []
    out: List[Contribution] = []
    failures = mail.auth_failures or []
    if "DMARC" in failures:
        out.append(C("mail_dmarc_fail", "technical", m.W_MAIL_DMARC_FAIL,
                     f"Receiving server recorded DMARC failure for "
                     f"{mail.from_domain or 'the sender'} "
                     f"({', '.join(failures)} failed) - the From domain is likely forged."))
    elif failures:
        out.append(C("mail_auth_fail", "technical", m.W_MAIL_AUTH_FAIL,
                     f"Sender authentication failed: {', '.join(failures)}."))
    if mail.display_name_spoof:
        out.append(C("mail_display_name_spoof", "technical", m.W_MAIL_DISPLAY_SPOOF,
                     f"Sender spoofing: {mail.display_name_spoof_reason or ''}."))
    if mail.reply_to_mismatch:
        out.append(C("mail_reply_to_mismatch", "technical", m.W_MAIL_REPLY_TO,
                     f"Replies are diverted to {mail.reply_to_domain} instead of "
                     f"{mail.from_domain} (business-e-mail-compromise pattern)."))
    if mail.deceptive_links:
        out.append(C("mail_deceptive_link", "technical", m.W_MAIL_DECEPTIVE_LINK,
                     "Deceptive link(s): " + "; ".join(mail.deceptive_links[:2]) + "."))
    if mail.double_extension_attachments:
        out.append(C("mail_double_extension", "technical", m.W_MAIL_DOUBLE_EXT,
                     "Attachment disguised with a double extension: "
                     + ", ".join(mail.double_extension_attachments[:3]) + "."))
    if mail.rtlo_attachments:
        out.append(C("mail_rtlo_spoof", "technical", m.W_MAIL_RTLO,
                     "Right-to-left-override character used to spoof an attachment name: "
                     + ", ".join(mail.rtlo_attachments[:3]) + "."))
    if mail.executable_attachments:
        out.append(C("mail_risky_attachment", "technical", m.W_MAIL_RISKY_ATTACHMENT,
                     "Executable / script / macro-enabled attachment: "
                     + ", ".join(mail.executable_attachments[:3]) + "."))
    if mail.lure_subject:
        out.append(C("mail_lure_subject", "semantic", m.W_MAIL_LURE_SUBJECT,
                     f"Subject uses lure phrasing ({', '.join(mail.lure_subject)})."))
    if mail.archive_password_in_body:
        out.append(C("mail_archive_password_in_body", "technical", m.W_MAIL_ARCHIVE_PASSWORD,
                     "Encrypted archive whose password is written in the message (hides the "
                     "content from mail gateways): "
                     + ", ".join(n.rsplit("!/", 1)[-1] for n in mail.archive_password_in_body[:3])
                     + "."))
    return out + _worst(mail.worst, "attachment", "mail_attachment")


def _web(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    w = s.web
    if w is None:
        return []
    out: List[Contribution] = []
    if w.smuggling:
        out.append(C("html_smuggling", "technical", m.W_HTML_SMUGGLING,
                     "HTML smuggling (T1027.006): " + "; ".join(w.smuggling_reasons or [])
                     + "."))
    elif w.smuggling_construct:
        out.append(C("web_download_construct", "technical", m.W_WEB_DOWNLOAD_CONSTRUCT,
                     "Page builds a file in the browser and saves it (no embedded payload "
                     "found)."))
    if w.payloads:
        out.append(C("web_embedded_payload", "technical", m.W_WEB_PAYLOAD,
                     "File embedded in the page: " + ", ".join(w.payloads[:3]) + "."))
    if w.svg_active:
        out.append(C("svg_active_content", "technical", m.W_SVG_ACTIVE,
                     "SVG image carries active content: " + ", ".join(w.svg_active) + "."))
    if w.credential_form:
        out.append(C("web_credential_capture", "technical", m.W_WEB_CREDENTIAL,
                     "Credential capture: " + "; ".join(w.credential_reasons or []) + "."))
    if w.redirects:
        out.append(C("web_redirect", "technical", m.W_WEB_REDIRECT,
                     f"Redirects to {len(w.redirects)} external URL(s)."))
    if len(w.obfuscation or []) >= 2:
        out.append(C("js_obfuscation", "technical", m.W_JS_OBFUSCATION,
                     "Obfuscated script: " + ", ".join(w.obfuscation) + "."))
    return out + _worst(w.worst, "payload", "web_payload")


def _elf(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    elf = s.elf
    if elf is None:
        return []
    out: List[Contribution] = []
    cats = sorted((c for c in (elf.categories or {}) if c in m.W_ELF_BEHAVIOUR),
                  key=lambda c: -m.W_ELF_BEHAVIOUR[c])
    if cats:
        pts = m.W_ELF_BEHAVIOUR[cats[0]] + max(0, len(cats) - 1) * m.W_ELF_BEHAVIOUR_EXTRA
        examples = "; ".join(f"{c}: {elf.categories[c][0]}" for c in cats[:3])
        out.append(C("elf_behaviour", "technical", pts,
                     f"Linux executable contains hostile-only strings ({examples})."))
    if elf.packed:
        out.append(C("elf_packed", "technical", m.W_ELF_PACKED,
                     f"Linux executable is packed ({elf.packer or 'unknown packer'})."))
    if elf.no_section_table:
        out.append(C("elf_no_section_table", "technical", m.W_ELF_NO_SECTIONS,
                     "Linux executable has its section table removed (anti-analysis)."))
    return out


def _qr(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    qr = s.qr
    if qr is None:
        return []
    if qr.suspicious:
        first = qr.suspicious[0]
        return [C("qr_code_suspicious_url", "technical", m.W_QR_SUSPICIOUS_URL,
                  f"QR code leads to {first['url']} ({'; '.join(first['reasons'][:3])}).")]
    if qr.urls:
        return [C("qr_code_url", "semantic", m.W_QR_URL,
                  f"QR code carries a web link ({qr.urls[0]}); "
                  "links in QR codes bypass text filters.")]
    return []


def _pe(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    pe = s.pe
    if pe is None:
        return []
    out: List[Contribution] = []
    if pe.recovery_inhibition:
        out.append(C("pe_recovery_inhibition", "technical", m.W_PE_RECOVERY_INHIBITION,
                     "Windows program carries a command that deletes shadow copies or backups "
                     f"(T1490): {pe.recovery_inhibition[0]}."))
    if pe.injection:
        out.append(C("pe_injection_imports", "technical", m.W_PE_INJECTION,
                     "Imports the process-injection chain (T1055): "
                     + " + ".join(pe.injection) + "."))
    if pe.ransomware_apis:
        out.append(C("pe_ransomware_imports", "technical", m.W_PE_RANSOM_APIS,
                     "Unsigned program imports encryption, directory walking and file writing: "
                     + " + ".join(pe.ransomware_apis) + "."))
    if pe.packed:
        # Packers make writable code sections and hide imports by design:
        # that is the same evidence, so it is not added again.
        out.append(C("pe_packed", "technical", m.W_PE_PACKED,
                     f"Windows program is packed ({pe.packer or 'unknown packer'})."))
    else:
        if pe.wx_sections:
            out.append(C("pe_writable_code", "technical", m.W_PE_WX_SECTION,
                         "Writable and executable section(s): "
                         + ", ".join(pe.wx_sections[:3]) + " (self-modifying code)."))
        if pe.runtime_imports_only:
            out.append(C("pe_runtime_imports", "technical", m.W_PE_RUNTIME_IMPORTS,
                         "Imports almost nothing but LoadLibrary/GetProcAddress: "
                         "the real API calls are resolved at run time."))
    if pe.overlay_executable:
        out.append(C("pe_overlay_executable", "technical", m.W_PE_OVERLAY_EXECUTABLE,
                     f"Another program is appended after the sections ({pe.overlay_size} "
                     "bytes): a binder or dropper."))
    elif pe.overlay_encrypted:
        out.append(C("pe_overlay_encrypted", "technical", m.W_PE_OVERLAY_ENCRYPTED,
                     f"Unsigned program carries {pe.overlay_size} bytes of near-random "
                     "appended data that is no known installer format."))
    if pe.malformed:
        out.append(C("pe_malformed", "technical", m.W_PE_MALFORMED,
                     "Malformed Windows program: " + "; ".join(pe.malformed[:2]) + "."))
    return out


def _script(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    sc = s.script
    if sc is None:
        return []
    out: List[Contribution] = []
    cats = dict(sc.categories or {})
    if "download" in cats and "execute" in cats:      # the combination is the dropper
        cats["dropper"] = cats.pop("download") + cats.pop("execute")
    names = sorted((c for c in cats if c in m.W_SCRIPT_BEHAVIOUR),
                   key=lambda c: -m.W_SCRIPT_BEHAVIOUR[c])
    if names:
        pts = m.W_SCRIPT_BEHAVIOUR[names[0]] + max(0, len(names) - 1) * m.W_SCRIPT_BEHAVIOUR_EXTRA
        examples = "; ".join(f"{c}: {cats[c][0]}" for c in names[:3])
        out.append(C("script_behaviour", "technical", pts,
                     f"{sc.language or 'Script'} ({examples})."))
    if sc.encoded:
        out.append(C("script_encoded", "technical", m.W_SCRIPT_ENCODED,
                     "Script is encoded with the Windows Script Encoder (source hidden)."))
    obf = [o for o in (sc.obfuscation or []) if not o.startswith("Script Encoder")]
    if len(obf) >= 2:
        out.append(C("script_obfuscation", "technical", m.W_SCRIPT_OBFUSCATION,
                     "Obfuscated script: " + ", ".join(obf[:4]) + "."))
    return out


def _embedded(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    e = s.embedded
    if e is None:
        return []
    out: List[Contribution] = []
    if e.kind == "onenote" and e.risky_members:
        out.append(C("onenote_embedded_file", "technical", m.W_ONENOTE_RISKY,
                     "OneNote page carries a runnable file: "
                     + ", ".join(e.risky_members[:3]) + "."))
    if e.chm_shortcut:
        out.append(C("chm_shortcut_command", "technical", m.W_CHM_SHORTCUT,
                     "Help file page runs a command (HTML Help ShortCut object)."))
    if e.msi_script_actions:
        out.append(C("msi_script_custom_action", "technical", m.W_MSI_SCRIPT_ACTION,
                     "Installer runs a script custom action ("
                     + ", ".join(sorted(set(e.msi_script_actions))) + ")."))
    if e.xll_addin:
        out.append(C("xll_addin", "technical", m.W_XLL_ADDIN,
                     "Excel add-in DLL (xlAutoOpen): Excel runs its code when the file is "
                     "opened."))
    if e.encrypted_unopened:
        out.append(C("office_encrypted_unopened", "technical", m.W_OFFICE_ENCRYPTED,
                     "Password-protected document: its content could not be checked."))
    if e.password_from_message:
        out.append(C("mail_archive_password_in_body", "technical", m.W_MAIL_ARCHIVE_PASSWORD,
                     "Password-protected document opened with the password written in the "
                     "message."))
    return out + _worst(e.worst, "embedded file", "embedded_member")


def _scan_failed(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    if not s.scan_failed:
        return []
    return [C("scan_failed", "technical", m.W_SCAN_FAILED,
              f"Scanning this file failed ({s.scan_failed}). Ordinary documents do "
              "not hang or crash a parser; inspect it manually.")]


# ------------------------------------------------------------------- statistical
def _ml(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    ml = s.ml
    if ml is None or not ml.suspicious:
        return []
    # When the integrity layer already proved the content is encrypted, or the
    # PE layer already scored the packing, the ML layer is looking at the same
    # evidence: don't count it twice.
    if (s.integrity and s.integrity.encrypted_likely) or (s.pe and s.pe.packed):
        return []
    prob = float(ml.probability or 0)
    why = "; ".join((ml.indicators or [])[:3])
    return [C("ml_classifier", "statistical", m.W_ML * prob,
              f"Static ML classifier ({ml.model or 'rules'}) rates the byte "
              f"structure suspicious (p={prob:.2f})" + (f": {why}." if why else "."))]


# ----------------------------------------------------------------------- dynamic
def _emulation(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    emu = s.emulation
    if emu is None:
        return []
    if emu.downloads_and_runs:
        return [C("emulated_dropper", "dynamic", m.W_EMU_DROPPER,
                  "Emulated script fetched " + ", ".join(emu.urls or [])
                  + " and ran or dropped a program.")]
    if emu.url_count:
        return [C("emulated_network", "dynamic", m.W_EMU_NETWORK,
                  "Emulated script contacted " + ", ".join(emu.urls or []) + ".")]
    return []


def _sandbox(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    sb = s.sandbox
    if sb is None:
        return []
    out: List[Contribution] = []
    if sb.ransomware:
        out.append(C("sandbox_ransomware_behaviour", "dynamic", m.W_SANDBOX_RANSOMWARE,
                     "Sandbox observed ransomware behaviour: " + ", ".join(sb.ransomware[:3])
                     + "."))
    sigs = [x for x in (sb.signatures or []) if x.get("name") not in (sb.ransomware or [])]
    if sigs:
        pts = min(m.W_SANDBOX_SIGNATURES_MAX,
                  sum(m.W_SANDBOX_SIGNATURE.get(int(x.get("severity", 1)), 4.0) for x in sigs))
        out.append(C("sandbox_behaviour", "dynamic", pts,
                     f"Sandbox behaviour ({len(sigs)} signature(s)): "
                     + ", ".join(x.get("name", "?") for x in sigs[:4]) + "."))
    return out


# -------------------------------------------------------------------- reputation
def _virustotal(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    vt = s.virustotal
    if vt is None:
        return []
    ratio = float(vt.ratio or 0)
    flagged = int(vt.malicious or 0) + int(vt.suspicious or 0)
    if flagged <= 0:
        return []
    return [C("virustotal", "reputation", max(m.W_VT_FLOOR, m.W_VT_RATIO * ratio),
              f"VirusTotal: {flagged}/{vt.total} engines flagged (ratio {ratio:.2f}).")]


# ---------------------------------------------------------------------- semantic
def _llm(m: ScoringMatrix, s: Signals) -> List[Contribution]:
    llm = s.llm
    if llm is None or not llm.is_suspicious:
        return []
    conf = float(llm.confidence or 0)
    elems = ", ".join(llm.elements or [])
    detail = f"LLM flagged the text as a likely lure (confidence {conf:.2f})."
    if elems:
        detail += f" Elements: {elems}."
    return [C("llm_semantic", "semantic", m.W_LLM * conf, detail)]


# The order here is the order of contributions in reports and breakdowns.
SCORERS: Tuple[Scorer, ...] = (
    _local_db, _yara, _fuzzy, _macro,
    _integrity, _prompt_guard, _appended_payload, _relationships, _archive,
    _mail, _web, _elf, _qr, _pe, _script, _embedded, _scan_failed,
    _ml, _emulation, _sandbox, _virustotal, _llm,
)


# Attach the registry's weights as class attributes (W_LOCAL_DB, W_YARA, ...).
for _name, _value in REGISTRY.weights.items():
    setattr(ScoringMatrix, _name, _value)
