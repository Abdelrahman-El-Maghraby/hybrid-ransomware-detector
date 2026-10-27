"""
Typed scoring signals: the contract between the detection layers (which fill
them in) and the scoring matrix (which reads them).

Until 4.6 the signals were one untyped dict per file, so a renamed key in a
layer silently became "no evidence" in the scorer. Now each layer fills a
dataclass and mypy checks both sides: a misspelt field is a type error, not a
missed detection.

`Signals.from_dict()` still accepts the old dict shape (the tests, the
calibration tool and anyone scoring hand-made signals use it); unknown keys in
a known layer raise, so a wrong shape fails loudly there too. Signals from a
layer the scorer does not know (a third-party Layer) go to `Signals.extra`.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type, TypeVar


def _list() -> Any:
    return field(default_factory=list)


@dataclass
class WorstMember:
    """The most dangerous member of a container: its contributions are scored
    again, prefixed with its name."""
    name: str = ""
    contributions: List[Dict[str, Any]] = _list()


@dataclass
class FuzzySignal:
    matched: bool = False
    best_confidence: float = 0.0
    families: List[str] = _list()


@dataclass
class MacroSignal:
    has_macros: bool = False
    autoexec: List[str] = _list()
    critical: List[str] = _list()
    suspicious: List[str] = _list()
    vba_stomping: bool = False
    xlm_macros: bool = False


@dataclass
class YaraSignal:
    matched: bool = False
    top_severity: str = "medium"
    rules: List[str] = _list()


@dataclass
class IntegritySignal:
    disguised_executable: Optional[str] = None
    encrypted_likely: bool = False
    format_mismatch: bool = False
    appended_payload: Optional[str] = None
    detail: str = ""


@dataclass
class ElfSignal:
    categories: Dict[str, List[str]] = field(default_factory=dict)
    packed: bool = False
    packer: str = ""
    no_section_table: bool = False


@dataclass
class PeSignal:
    packed: bool = False
    packer: str = ""
    wx_sections: List[str] = _list()
    injection: List[str] = _list()
    ransomware_apis: List[str] = _list()
    runtime_imports_only: bool = False
    recovery_inhibition: List[str] = _list()
    overlay_executable: bool = False
    overlay_encrypted: bool = False
    overlay_size: int = 0
    malformed: List[str] = _list()
    signature_present: bool = False


@dataclass
class ScriptSignal:
    language: str = ""
    categories: Dict[str, List[str]] = field(default_factory=dict)
    encoded: bool = False
    obfuscation: List[str] = _list()


@dataclass
class PromptGuardSignal:
    injection_status: str = "none"          # none | suspicious | confirmed
    indicators: List[str] = _list()
    hidden_text_found: bool = False
    hidden_reasons: List[str] = _list()


@dataclass
class RelationshipSignal:
    kinds: List[str] = _list()
    targets: List[str] = _list()


@dataclass
class QrSignal:
    urls: List[str] = _list()
    suspicious: List[Dict[str, Any]] = _list()      # {"url": str, "reasons": [str]}


@dataclass
class ArchiveSignal:
    zip_slip: bool = False
    zip_bomb: bool = False
    encrypted_unreadable: bool = False
    skipped_members: int = 0
    executable_members: List[str] = _list()
    double_extension_members: List[str] = _list()
    rtlo_members: List[str] = _list()
    reasons: Dict[str, str] = field(default_factory=dict)
    worst: Optional[WorstMember] = None


@dataclass
class MailSignal:
    from_domain: Optional[str] = ""
    reply_to_domain: Optional[str] = ""
    auth_failures: List[str] = _list()
    display_name_spoof: bool = False
    display_name_spoof_reason: str = ""
    reply_to_mismatch: bool = False
    deceptive_links: List[str] = _list()
    executable_attachments: List[str] = _list()
    double_extension_attachments: List[str] = _list()
    rtlo_attachments: List[str] = _list()
    lure_subject: List[str] = _list()
    archive_password_in_body: List[str] = _list()
    worst: Optional[WorstMember] = None


@dataclass
class WebSignal:
    smuggling: bool = False
    smuggling_construct: bool = False
    smuggling_reasons: List[str] = _list()
    payloads: List[str] = _list()
    svg_active: List[str] = _list()
    credential_form: bool = False
    credential_reasons: List[str] = _list()
    redirects: List[str] = _list()
    obfuscation: List[str] = _list()
    worst: Optional[WorstMember] = None


@dataclass
class EmbeddedSignal:
    kind: str = ""
    risky_members: List[str] = _list()
    chm_shortcut: bool = False
    msi_script_actions: List[str] = _list()
    xll_addin: bool = False
    encrypted_unopened: bool = False
    password_from_message: bool = False
    worst: Optional[WorstMember] = None


@dataclass
class MlSignal:
    suspicious: bool = False
    probability: float = 0.0
    model: str = ""
    indicators: List[str] = _list()


@dataclass
class LlmSignal:
    is_suspicious: bool = False
    confidence: float = 0.0
    elements: List[str] = _list()


@dataclass
class VirusTotalSignal:
    malicious: int = 0
    suspicious: int = 0
    total: int = 0
    ratio: float = 0.0


@dataclass
class SandboxSignal:
    signatures: List[Dict[str, Any]] = _list()
    ransomware: List[str] = _list()
    malscore: float = 0.0


@dataclass
class EmulationSignal:
    urls: List[str] = _list()
    url_count: int = 0
    commands: int = 0
    downloads_and_runs: bool = False


# Legacy dict key for each container's worst member.
_WORST_KEYS = ("worst_member", "worst_attachment", "worst_payload")
S = TypeVar("S")


@dataclass
class Signals:
    """Everything the layers found about one file, as the scorer sees it."""
    local_db_hit: bool = False
    allowlisted: str = ""                 # the allowlist note, when the SHA-256 is listed
    scan_failed: str = ""                 # why scanning failed (time-out, crash)
    fuzzy: Optional[FuzzySignal] = None
    macro: Optional[MacroSignal] = None
    yara: Optional[YaraSignal] = None
    integrity: Optional[IntegritySignal] = None
    elf: Optional[ElfSignal] = None
    pe: Optional[PeSignal] = None
    script: Optional[ScriptSignal] = None
    prompt_guard: Optional[PromptGuardSignal] = None
    relationships: Optional[RelationshipSignal] = None
    qr: Optional[QrSignal] = None
    archive: Optional[ArchiveSignal] = None
    mail: Optional[MailSignal] = None
    web: Optional[WebSignal] = None
    embedded: Optional[EmbeddedSignal] = None
    ml: Optional[MlSignal] = None
    llm: Optional[LlmSignal] = None
    virustotal: Optional[VirusTotalSignal] = None
    sandbox: Optional[SandboxSignal] = None
    emulation: Optional[EmulationSignal] = None
    extra: Dict[str, Any] = field(default_factory=dict)   # signals of third-party layers

    # ------------------------------------------------------------ mutation
    def set(self, key: str, value: Any) -> None:
        """Store a layer's signal under its key (unknown keys go to `extra`)."""
        if key in _TYPES or key in _SCALARS:
            setattr(self, key, value)
        else:
            self.extra[key] = value

    # Mapping-style access, so a third-party Layer written for the old dict keeps
    # working: signals["x"] = ... / signals.get("x").
    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)

    def __getitem__(self, key: str) -> Any:
        if key in _TYPES or key in _SCALARS:
            return getattr(self, key)
        return self.extra[key]

    def get(self, key: str, default: Any = None) -> Any:
        try:
            value = self[key]
        except KeyError:
            return default
        return default if value is None else value

    def copy(self) -> Signals:
        return dataclasses.replace(self, extra=dict(self.extra))

    def changed_since(self, before: Signals) -> Dict[str, Any]:
        """Fields this object holds that differ (by identity) from `before`."""
        out = {f: getattr(self, f) for f in _ALL if getattr(self, f) is not getattr(before, f)}
        out.update({k: v for k, v in self.extra.items() if v is not before.extra.get(k)})
        return out

    # ------------------------------------------------------------ dict shape
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Signals:
        out = cls()
        for key, value in (data or {}).items():
            if key in _SCALARS:
                setattr(out, key, value)
            elif key in _TYPES:
                if value is None or isinstance(value, _TYPES[key]):
                    setattr(out, key, value)
                elif value:                             # {} means "layer ran, found nothing"
                    setattr(out, key, _build(_TYPES[key], value))
            else:
                out.extra[key] = value
        return out


def _build(kind: Type[S], value: Dict[str, Any]) -> S:
    data = dict(value)
    for legacy in _WORST_KEYS:
        if legacy in data:
            worst = data.pop(legacy)
            data["worst"] = (WorstMember(**worst) if isinstance(worst, dict) and worst
                             else None)
    return kind(**data)


_TYPES: Dict[str, type] = {
    "fuzzy": FuzzySignal, "macro": MacroSignal, "yara": YaraSignal,
    "integrity": IntegritySignal, "elf": ElfSignal, "pe": PeSignal, "script": ScriptSignal,
    "prompt_guard": PromptGuardSignal, "relationships": RelationshipSignal, "qr": QrSignal,
    "archive": ArchiveSignal, "mail": MailSignal, "web": WebSignal, "embedded": EmbeddedSignal,
    "ml": MlSignal, "llm": LlmSignal, "virustotal": VirusTotalSignal, "sandbox": SandboxSignal,
    "emulation": EmulationSignal,
}
_SCALARS = ("local_db_hit", "allowlisted", "scan_failed")
_ALL = _SCALARS + tuple(_TYPES)


def as_signals(value: Any) -> Signals:
    """Signals as-is, or built from the legacy dict shape."""
    return value if isinstance(value, Signals) else Signals.from_dict(value or {})
