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
`default_pipeline()`. Fast layers run one after another; slow ones (`heavy =
True`: ML, LLM, VirusTotal) run as a group at the end, concurrently, and are
skipped when the fast layers already put the file at the maximum score. A layer
never raises for a hostile file (each detector degrades to "not checked").
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List, Optional

from api import SCHEMA_VERSION
from detectors import FUZZY_AVAILABLE
from detectors.elf_analysis import is_elf
from detectors.embedded_content import sniff as embedded_sniff
from detectors.file_integrity import IMAGE_EXTENSIONS
from detectors.relationship_scanner import defang
from detectors.script_analysis import is_script

from .containers import ArchiveHandler, EmbeddedHandler, MailHandler, WebHandler, scan_container
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
    is_web: bool = False
    embedded_kind: str = ""      # onenote | chm | msi | office-encrypted | xll
    _data: Optional[bytes] = None
    _data_loaded: bool = False

    SHARED_READ_MAX = 64 * 1024 * 1024

    def data(self) -> Optional[bytes]:
        """The whole file, read once and shared by the layers that need every byte
        (hashes, fuzzy hashes, YARA, ELF, scripts). None above SHARED_READ_MAX:
        those layers then stream from disk as before."""
        if not self._data_loaded:
            self._data_loaded = True
            try:
                if os.path.getsize(self.path) <= self.SHARED_READ_MAX:
                    with open(self.path, "rb") as fh:
                        self._data = fh.read(self.SHARED_READ_MAX + 1)
            except OSError:
                self._data = None
        return self._data
    hashes: Dict = field(default_factory=dict)
    text: str = ""                # visible text (or the e-mail body)
    strings: str = ""             # printable strings from the raw bytes
    signals: Dict = field(default_factory=lambda: {"archive": {}, "mail": {}, "ml": {}})

    @classmethod
    def start(cls, scanner: RansomwareScanner, path: str, depth: int, display: str,
              engine_version: str) -> ScanContext:
        result = {
            "schema_version": SCHEMA_VERSION,
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
                   is_mail=scanner.mail_analyzer.is_mail(path),
                   is_web=scanner.web_analyzer.is_web(path),
                   embedded_kind=embedded_sniff(path))

    @property
    def scan_results(self) -> Dict:
        return self.result["scan_results"]


class Layer:
    """One detection step. Subclasses set `name` and implement `run`.

    `heavy` layers are slow (a model, a network call). The scanner runs them after
    the fast ones, skips them when the fast layers already reached the maximum
    score, and runs a group of them concurrently (each on its own copy of the
    context, merged back in pipeline order).
    """

    name = ""
    heavy = False

    def run(self, scanner: RansomwareScanner, ctx: ScanContext) -> None:
        raise NotImplementedError


# --------------------------------------------------------------------- layers
class HashLayer(Layer):
    """MD5 + SHA-256 (chunked). Everything that is cached or looked up keys on these."""
    name = "hashes"

    def run(self, scanner, ctx):
        data = ctx.data()
        if data is not None:
            import hashlib
            ctx.hashes = {"md5": hashlib.md5(data).hexdigest(),
                          "sha256": hashlib.sha256(data).hexdigest()}
        else:
            ctx.hashes = scanner.calculate_hashes(ctx.path)
        ctx.result["md5_hash"] = ctx.hashes["md5"]
        ctx.result["sha256_hash"] = ctx.hashes["sha256"]


class AllowlistLayer(Layer):
    """Known-good SHA-256 hashes the user listed (e.g. a vendor installer script
    that looks like a dropper). Every other layer still runs and is reported."""
    name = "allowlist"

    def run(self, scanner, ctx):
        note = scanner.allowlist.get(ctx.hashes.get("sha256", ""))
        if note is not None:
            ctx.scan_results["allowlist"] = {"allowlisted": True, "note": note}
            ctx.signals["allowlisted"] = note or "no note"


class FuzzyHashLayer(Layer):
    """TLSH + ssdeep similarity to known families (skipped above fuzzy_max_bytes)."""
    name = "fuzzy"

    def run(self, scanner, ctx):
        if ctx.result["file_size"] <= scanner.fuzzy_max_bytes:
            data = ctx.data()
            hasher = scanner.fuzzy_hasher
            pre = (hasher.hash_bytes(data, with_ssdeep=hasher.needs_ssdeep)
                   if data is not None else None)
            fuzzy = scanner.fuzzy_hasher.analyze_file(ctx.path, precomputed=pre)
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
        res = scanner.yara_engine.scan_file(ctx.path, data=ctx.data())
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
            "appended_payload": res.appended_payload,
            "detail": res.detail,
        }


class ElfLayer(Layer):
    """Linux ELF triage: header, packing, removed section table, hostile strings.
    Only ELF files get an `elf_analysis` entry."""
    name = "elf"

    def run(self, scanner, ctx):
        if ctx.is_archive or ctx.is_mail or not is_elf(ctx.path):
            return
        res = scanner.elf_analyzer.analyze_file(ctx.path, data=ctx.data())
        ctx.scan_results["elf_analysis"] = res.as_dict()
        ctx.signals["elf"] = {"categories": res.categories, "packed": res.packed,
                              "packer": res.packer, "no_section_table": res.no_section_table}


class ScriptLayer(Layer):
    """Windows script files (JS / VBS / HTA / WSF / PS1 / BAT): download, execute,
    recovery tampering, defence evasion, persistence and obfuscation markers."""
    name = "script"

    def run(self, scanner, ctx):
        if ctx.is_archive or ctx.is_mail or not is_script(ctx.path):
            return
        res = scanner.script_analyzer.analyze_file(ctx.path, data=ctx.data())
        ctx.scan_results["script_analysis"] = res.as_dict()
        ctx.signals["script"] = {"language": res.language, "categories": res.categories,
                                 "encoded": res.encoded, "obfuscation": res.obfuscation}


class ContainerLayer(Layer):
    """Unpack a container and send every member through the whole pipeline."""

    def __init__(self, handler: ContainerHandler):
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


class QRLayer(Layer):
    """QR codes in images, PDFs and Office documents; the links they carry are judged.
    Only files that can hold images get a `qr_codes` entry."""
    name = "qr"

    def run(self, scanner, ctx):
        if (scanner.qr_scanner is None or ctx.is_archive or ctx.is_mail
                or not scanner.qr_scanner.applies(ctx.path)):
            return
        res = scanner.qr_scanner.analyze_file(ctx.path)
        if res.available and not res.images_checked:
            return                      # nothing that could hold a QR code
        ctx.scan_results["qr_codes"] = res.as_dict()
        ctx.signals["qr"] = {
            "urls": [defang(u) for u in res.urls],
            "suspicious": [{"url": defang(c.payload), "reasons": c.suspicious_reasons}
                           for c in res.suspicious],
        }


class MLLayer(Layer):
    """Byte/PE-structure classifier; containers are judged through their members."""
    name = "ml"
    heavy = True

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
    heavy = True

    def run(self, scanner, ctx):
        if ctx.is_archive:
            llm = {"is_malicious": False, "confidence": 0, "suspicious_elements": [],
                   "details": "Archive: members are analysed individually; "
                              "LLM layer skipped for the container."}
        elif os.path.splitext(ctx.path)[1].lower() in IMAGE_EXTENSIONS:
            llm = {"is_malicious": False, "confidence": 0, "suspicious_elements": [],
                   "details": "Image: no text to analyse; LLM layer skipped."}
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
    heavy = True

    def run(self, scanner, ctx):
        vt = scanner.scan_file_with_virustotal(ctx.path, ctx.hashes)
        ctx.scan_results["virustotal"] = vt
        ctx.signals["virustotal"] = {
            "malicious": vt.get("malicious_detections", 0),
            "suspicious": vt.get("suspicious_detections", 0),
            "total": vt.get("total_engines", 0),
            "ratio": vt.get("detection_ratio", 0),
        }


class SandboxLayer(Layer):
    """Optional dynamic analysis in a self-hosted CAPEv2 sandbox (off by default).
    Only top-level files are submitted, and with SANDBOX_SUBMIT=suspicious only those
    the static layers already rate Medium or worse."""
    name = "sandbox"
    heavy = True

    def run(self, scanner, ctx):
        client = getattr(scanner, "sandbox", None)
        if client is None or ctx.depth > 0:
            return
        if scanner.config.get("sandbox_submit", "suspicious") != "all" and \
                scanner.scoring.score(ctx.signals).risk_score < 25:
            return
        sha = ctx.hashes.get("sha256", "")
        cached = scanner.cache.get(sha, "sandbox") if (scanner.cache and sha) else None
        if cached:
            data = dict(cached, status="cached")
        else:
            data = client.analyze(ctx.path).as_dict()
            if scanner.cache and sha and data.get("status") == "reported":
                scanner.cache.put(sha, "sandbox", data)
        ctx.scan_results["sandbox"] = data
        if data.get("status") in ("reported", "cached"):
            ctx.signals["sandbox"] = {"signatures": data.get("signatures", []),
                                      "ransomware": data.get("ransomware", []),
                                      "malscore": data.get("malscore", 0)}


def default_pipeline() -> List[Layer]:
    """The layers in the order they run."""
    return [
        HashLayer(),
        AllowlistLayer(),
        FuzzyHashLayer(),
        LocalDatabaseLayer(),
        MacroLayer(),
        YaraLayer(),
        IntegrityLayer(),
        ElfLayer(),
        ScriptLayer(),
        ContainerLayer(MailHandler()),       # before the prompt guard: it reads the body
        PromptGuardLayer(),
        RelationshipLayer(),
        QRLayer(),
        ContainerLayer(ArchiveHandler()),
        ContainerLayer(WebHandler()),        # HTML smuggling: payloads hidden in a page
        ContainerLayer(EmbeddedHandler()),   # OneNote / CHM / MSI / encrypted Office / XLL
        MLLayer(),
        LLMLayer(),
        VirusTotalLayer(),
        SandboxLayer(),
    ]
