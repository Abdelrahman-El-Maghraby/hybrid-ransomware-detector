"""
The scan pipeline: an ordered list of layers that each add one kind of
evidence to a ScanContext.

Every layer does two things:
  * records its full result under `ctx.result["scan_results"][<key>]` (what the
    report and the GUI show), and
  * adds its scoring signals to `ctx.signals` (what the weighted matrix reads).

`RansomwareScanner.scan_file` creates the context, runs `scanner.pipeline` in
order, then scores `ctx.signals`. The order matters for two reasons: later
layers use earlier results (the hash feeds the database, VirusTotal and the
LLM cache; the e-mail body feeds the prompt guard and the LLM), and the order
of keys in the JSON report follows it.

Adding a layer = writing a small class here and placing it in
`default_pipeline()`. Layers run one after another; a layer never raises for a
hostile file (each detector degrades to "not checked").
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List

from detectors import FUZZY_AVAILABLE
from detectors.relationship_scanner import defang

from .containers import ArchiveHandler, MailHandler, scan_container
from .text import extract_suspicious_strings

if TYPE_CHECKING:  # pragma: no cover
    from .containers import ContainerHandler
    from .scanner import RansomwareScanner


@dataclass
class ScanContext:
    """Everything one file's scan accumulates as it moves through the pipeline."""

    path: str                     # where the bytes are (a sandbox path for members)
    display: str                  # what the report calls it ("mail.eml!/invoice.pdf")
    depth: int                    # 0 for a top-level file, +1 per container level
    result: Dict
    is_archive: bool = False
    is_mail: bool = False
    hashes: Dict = field(default_factory=dict)
    text: str = ""                # visible text (or the e-mail body)
    strings: str = ""             # printable strings from the raw bytes
    signals: Dict = field(default_factory=lambda: {"archive": {}, "mail": {}, "ml": {}})

    @classmethod
    def start(cls, scanner: "RansomwareScanner", path: str, depth: int, display: str,
              engine_version: str) -> "ScanContext":
        result = {
            "file_path": display,
            "file_name": os.path.basename(display.replace("!/", "/")),
            "file_size": os.path.getsize(path),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "engine_version": engine_version,
            "is_malicious": False,
            "scan_results": {},
        }
        return cls(path=path, display=display, depth=depth, result=result,
                   is_archive=scanner.container_extractor.is_container(path),
                   is_mail=scanner.mail_analyzer.is_mail(path))

    @property
    def scan_results(self) -> Dict:
        return self.result["scan_results"]


class Layer:
    """One detection step. Subclasses set `name` and implement `run`."""

    name = ""

    def run(self, scanner: "RansomwareScanner", ctx: ScanContext) -> None:
        raise NotImplementedError


# --------------------------------------------------------------------- layers
class HashLayer(Layer):
    """MD5 + SHA-256 (chunked). Everything that is cached or looked up keys on these."""
    name = "hashes"

    def run(self, scanner, ctx):
        ctx.hashes = scanner.calculate_hashes(ctx.path)
        ctx.result["md5_hash"] = ctx.hashes["md5"]
        ctx.result["sha256_hash"] = ctx.hashes["sha256"]


class FuzzyHashLayer(Layer):
    """TLSH + ssdeep similarity to known families (skipped above fuzzy_max_bytes)."""
    name = "fuzzy"

    def run(self, scanner, ctx):
        if ctx.result["file_size"] <= scanner.fuzzy_max_bytes:
            fuzzy = scanner.fuzzy_hasher.analyze_file(ctx.path)
        else:
            from detectors.fuzzy_hash import FuzzyResult
            fuzzy = FuzzyResult(available=FUZZY_AVAILABLE,
                                detail=f"Skipped: file exceeds fuzzy_max_bytes "
                                       f"({scanner.fuzzy_max_bytes} bytes).")
        ctx.scan_results["fuzzy_hash"] = fuzzy.as_dict()
        ctx.signals["fuzzy"] = {
            "matched": fuzzy.matched,
            "best_confidence": fuzzy.best_confidence,
            "families": sorted({m.family for m in fuzzy.matches}),
        }


class LocalDatabaseLayer(Layer):
    """Exact known-bad MD5 from the local dataset."""
    name = "local-db"

    def run(self, scanner, ctx):
        hit, info = scanner.check_hash_in_database(ctx.hashes.get("md5", ""))
        ctx.scan_results["local_database"] = {
            "is_malicious": hit,
            "details": info if hit else "Not found in local database",
        }
        ctx.signals["local_db_hit"] = hit


class MacroLayer(Layer):
    """olevba triage of VBA/XLM macros, VBA stomping."""
    name = "macro"

    def run(self, scanner, ctx):
        macro = scanner.macro_analyzer.analyze_file(ctx.path)
        ctx.scan_results["macro_analysis"] = macro.as_dict()
        ctx.signals["macro"] = {
            "has_macros": macro.has_macros,
            "autoexec": macro.autoexec,
            "critical": macro.critical,
            "suspicious": macro.suspicious,
            "vba_stomping": macro.vba_stomping,
            "xlm_macros": macro.xlm_macros,
        }


class YaraLayer(Layer):
    name = "yara"

    def run(self, scanner, ctx):
        res = scanner.yara_engine.scan_file(ctx.path)
        ctx.scan_results["yara"] = res.as_dict()
        ctx.signals["yara"] = {
            "matched": res.matched,
            "top_severity": res.top_severity or "medium",
            "rules": sorted({m.rule for m in res.matches}),
        }


class IntegrityLayer(Layer):
    """Format vs extension, disguised executables, encrypted content."""
    name = "integrity"

    def run(self, scanner, ctx):
        res = scanner.integrity.analyze_file(ctx.path)
        ctx.scan_results["file_integrity"] = res.as_dict()
        ctx.signals["integrity"] = {
            "disguised_executable": res.disguised_executable,
            "encrypted_likely": res.encrypted_likely,
            "format_mismatch": res.format_mismatch,
            "detail": res.detail,
        }


class ContainerLayer(Layer):
    """Unpack a container and send every member through the whole pipeline."""

    def __init__(self, handler: "ContainerHandler"):
        self.handler = handler
        self.name = handler.result_key

    def run(self, scanner, ctx):
        if self.handler.applies(ctx):
            scan_container(scanner, self.handler, ctx)


class PromptGuardLayer(Layer):
    """Extracts visible text + strings once (shared with the LLM), then looks for
    hidden content and prompt-injection attempts."""
    name = "prompt-guard"

    def run(self, scanner, ctx):
        if ctx.is_archive:
            ctx.text = ""
        elif not ctx.is_mail:      # an e-mail's body was captured by its container
            llm_on = getattr(scanner.llm_backend, "available", True)
            ctx.text = scanner._extract_text_from_file(ctx.path, allow_ocr=llm_on)
        ctx.strings = "" if ctx.is_archive else extract_suspicious_strings(ctx.path)
        hidden = scanner.prompt_guard.inspect_hidden_content(ctx.path)
        guard = scanner.prompt_guard.analyze(ctx.text, ctx.strings, hidden)
        ctx.scan_results["prompt_guard"] = guard.as_dict()
        ctx.signals["prompt_guard"] = {
            "injection_status": guard.injection_status,
            "indicators": guard.injection_indicators,
            "hidden_text_found": guard.hidden_text_found,
            "hidden_reasons": guard.hidden_reasons,
        }


class RelationshipLayer(Layer):
    """Office external links: remote templates, Follina-style OLE, UNC paths."""
    name = "relationships"

    def run(self, scanner, ctx):
        rels = scanner.relationship_scanner.scan_file(ctx.path)
        ctx.scan_results["relationships"] = rels.as_dict()
        ctx.signals["relationships"] = {
            "kinds": rels.kinds,
            "targets": [defang(f.target) for f in rels.findings[:3]],
        }


class MLLayer(Layer):
    """Byte/PE-structure classifier; containers are judged through their members."""
    name = "ml"

    def run(self, scanner, ctx):
        if scanner.ml is None or ctx.is_archive or ctx.is_mail:
            return
        res = scanner.ml.classify(ctx.path)
        ctx.scan_results["ml_classifier"] = res.as_dict()
        ctx.signals["ml"] = {"suspicious": res.suspicious, "probability": res.probability,
                             "model": res.model, "indicators": res.indicators}


class LLMLayer(Layer):
    """Semantic opinion on the text (local-first; cached by SHA-256)."""
    name = "llm"

    def run(self, scanner, ctx):
        if ctx.is_archive:
            llm = {"is_malicious": False, "confidence": 0, "suspicious_elements": [],
                   "details": "Archive: members are analysed individually; "
                              "LLM layer skipped for the container."}
        else:
            llm = scanner.analyze_with_llm(ctx.path, ctx.text, ctx.strings,
                                           sha256=ctx.hashes.get("sha256"))
        ctx.scan_results["chatgpt_analysis"] = llm      # legacy key name kept
        ctx.signals["llm"] = {
            "is_suspicious": llm.get("is_malicious", False),
            "confidence": llm.get("confidence", 0),
            "elements": llm.get("suspicious_elements", []),
        }


class VirusTotalLayer(Layer):
    """Multi-engine reputation by hash (uploads are opt-in; cached)."""
    name = "virustotal"

    def run(self, scanner, ctx):
        vt = scanner.scan_file_with_virustotal(ctx.path, ctx.hashes)
        ctx.scan_results["virustotal"] = vt
        ctx.signals["virustotal"] = {
            "malicious": vt.get("malicious_detections", 0),
            "suspicious": vt.get("suspicious_detections", 0),
            "total": vt.get("total_engines", 0),
            "ratio": vt.get("detection_ratio", 0),
        }


def default_pipeline() -> List[Layer]:
    """The layers in the order they run."""
    return [
        HashLayer(),
        FuzzyHashLayer(),
        LocalDatabaseLayer(),
        MacroLayer(),
        YaraLayer(),
        IntegrityLayer(),
        ContainerLayer(MailHandler()),       # before the prompt guard: it reads the body
        PromptGuardLayer(),
        RelationshipLayer(),
        ContainerLayer(ArchiveHandler()),
        MLLayer(),
        LLMLayer(),
        VirusTotalLayer(),
    ]
