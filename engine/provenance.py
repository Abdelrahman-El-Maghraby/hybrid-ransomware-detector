"""
Provenance: what produced a result, so a verdict can be traced and reproduced.

Every result carries `provenance`:

    engine_version, schema_version, registry_version   what scored it
    rules       source (bundled / rule pack / custom folder), version, SHA-256 and
                file count of the YARA rules that were compiled
    fuzzy_signatures  source and SHA-256 of the signature database
    profile     standard | production
    external_services  llm / virustotal / sandbox: "off" or how they are used
    layers_disabled / layers_down   switched off by configuration / missing something
    layers_run, layers_unavailable, layers_not_applicable, layers_failed,
    layers_skipped   for this file

No secrets: keys, tokens, passwords and service URLs are never included.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .capabilities import DISABLED, DOWN, external_services
from .config import BUNDLED_FUZZY_SIGS, BUNDLED_RULES_DIR, ENGINE_VERSION

if TYPE_CHECKING:  # pragma: no cover
    from .layers import ScanContext
    from .scanner import RansomwareScanner

RAN, NOT_APPLICABLE, FAILED, SKIPPED = "ran", "not applicable", "error", "skipped"
# Layers that always do their work but may record it outside scan_results.
ALWAYS_RUN = ("hashes", "allowlist")
# scan_results key of each layer whose result has an `available` flag
RESULT_KEYS = {"fuzzy": "fuzzy_hash", "macro": "macro_analysis", "yara": "yara",
               "integrity": "file_integrity", "prompt-guard": "prompt_guard",
               "relationships": "relationships", "qr": "qr_codes", "archive": "archive",
               "mail": "mail", "web": "web", "ml": "ml_classifier"}


def _inside(child: Any, parent: Any) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(child), os.path.abspath(parent)]) == \
            os.path.abspath(parent)
    except ValueError:             # different drives on Windows
        return False


def _sha256_files(files: List[Path]) -> str:
    h = hashlib.sha256()
    for f in files:
        h.update(f.name.encode("utf-8") + b"\0")
        try:
            h.update(f.read_bytes())
        except OSError:
            h.update(b"<unreadable>")
        h.update(b"\0")
    return h.hexdigest()


def rules_info(scanner: RansomwareScanner) -> Dict[str, Any]:
    """The YARA rules the scanner compiled: where from, which version, their hash."""
    rules_dir = getattr(scanner.yara_engine, "rules_dir", None) or ""
    folder = Path(rules_dir) if rules_dir else None
    files = sorted([*folder.glob("*.yar"), *folder.glob("*.yara")]) if folder and folder.is_dir() else []
    pack = getattr(scanner, "rulepack", None) or {}
    if pack and folder and pack.get("path") and _inside(folder, pack["path"]):
        source, version = "rule pack", str(pack.get("version", ""))
    elif folder and os.path.abspath(folder) == os.path.abspath(BUNDLED_RULES_DIR):
        source, version = "bundled", f"bundled with {ENGINE_VERSION}"
    else:
        source, version = ("custom folder" if folder else "none"), ""
    return {"source": source, "version": version, "files": len(files),
            "compiled": int(getattr(scanner.yara_engine, "_rules_count", 0) or 0),
            "sha256": _sha256_files(files) if files else ""}


def fuzzy_info(scanner: RansomwareScanner) -> Dict[str, Any]:
    path = getattr(scanner.fuzzy_hasher, "signature_db_path", None) or ""
    p = Path(path) if path else None
    if not (p and p.is_file()):
        return {"source": "none", "sha256": ""}
    pack = getattr(scanner, "rulepack", None) or {}
    source = ("rule pack" if pack and pack.get("path") and _inside(p, pack["path"])
              else "bundled sample" if os.path.abspath(p) == os.path.abspath(BUNDLED_FUZZY_SIGS)
              else "local database")
    return {"source": source, "sha256": _sha256_files([p])}


def registry_version(scanner: RansomwareScanner) -> str:
    from detectors.registry import REGISTRY
    reg = scanner.scoring.registry
    return reg.version + (" +override" if reg is not REGISTRY else "")


def scanner_provenance(scanner: RansomwareScanner, states: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """The part that is the same for every file this scanner scans."""
    from api import SCHEMA_VERSION
    return {
        "engine_version": ENGINE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "registry_version": registry_version(scanner),
        "rules": rules_info(scanner),
        "fuzzy_signatures": fuzzy_info(scanner),
        "profile": str(scanner.config.get("profile") or "standard"),
        "external_services": external_services(states),
        "layers_disabled": [{"layer": n, "reason": s["detail"]} for n, s in states.items()
                            if s["state"] == DISABLED],
        "layers_down": [{"layer": n, "reason": s["detail"]} for n, s in states.items()
                        if s["state"] == DOWN],
    }


def file_provenance(scanner: RansomwareScanner, ctx: ScanContext,
                    static: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Provenance of one result: the scanner's part plus what ran on this file."""
    order = [layer.name for layer in scanner.pipeline]
    outcome = dict(ctx.layer_log)
    sr = ctx.scan_results
    heavy_reason = str((sr.get("skipped_layers") or {}).get("reason", ""))
    skipped = [{"layer": n, "reason": heavy_reason} for n in order if outcome.get(n) == SKIPPED]
    skipped += [{"layer": n, "reason": str(why)} for n, why in (sr.get("layer_skips") or {}).items()]
    base = static if static is not None else getattr(scanner, "provenance", None) or {}
    # a disabled layer is invoked but only writes a "skipped" placeholder: it is
    # listed under layers_disabled, not as run
    disabled = {d["layer"] for d in base.get("layers_disabled", [])}
    # ... and one whose result says its library is missing did not really run
    unavailable = [n for n in order if (sr.get(RESULT_KEYS.get(n, "")) or {}).get("available") is False]
    ran = [n for n in order if n not in disabled and n not in unavailable and (
        outcome.get(n) == RAN or (outcome.get(n) == NOT_APPLICABLE and n in ALWAYS_RUN))]
    return {**base,
            "layers_run": ran,
            "layers_unavailable": unavailable,
            "layers_not_applicable": [n for n in order if n not in disabled and n not in ran
                                      and outcome.get(n) == NOT_APPLICABLE],
            "layers_failed": [n for n in order if outcome.get(n) == FAILED],
            "layers_skipped": skipped}
