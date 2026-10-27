"""
Readiness: can this scanner produce a correct, complete result right now?

/health answers "is the process alive"; readiness answers "send it work". It is
ready only when:

    rules      the YARA rules compiled
    registry   the indicator registry loaded with every category cap and weights
    storage    the report, data and temporary folders accept a new file
    workers    isolated scan workers start (proved by a warm-up scan at start-up)
    layers     in the production profile, every required layer is up

Each check is (ok, detail); the layer states come from engine.capabilities.
"""

from __future__ import annotations

import os
import tempfile
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from .capabilities import layer_states, production_problems

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import RansomwareScanner

Check = Tuple[bool, str]
CATEGORIES = ("technical", "reputation", "semantic", "statistical", "dynamic")


def registry_check(scanner: RansomwareScanner) -> Check:
    registry = getattr(scanner.scoring, "registry", None)
    if registry is None or not registry.version:
        return False, "no indicator registry loaded"
    missing = [c for c in CATEGORIES if c not in registry.caps]
    if missing:
        return False, f"registry {registry.version} has no cap for {', '.join(missing)}"
    if not registry.weights:
        return False, f"registry {registry.version} has no weights"
    return True, f"registry {registry.version}"


def _writable(folder: str) -> Optional[str]:
    """None when a file can be created in `folder`, else why not."""
    try:
        os.makedirs(folder, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=folder, prefix=".aegis_ready_"):
            pass
    except OSError as e:
        return f"{folder}: {e.strerror or type(e).__name__}"
    return None


def storage_check(scanner: RansomwareScanner) -> Check:
    """Where a scan writes: reports, the result cache, temporary files. Not the
    data folder itself: a Docker deployment mounts the detection content there
    read-only, so that a compromised parser cannot change rules or the allowlist."""
    cache = str(scanner.config.get("cache_db_path") or "") if scanner.cache is not None else ""
    folders = [scanner.report_dir, os.path.dirname(cache) if cache else "",
               tempfile.gettempdir()]
    problems = [p for p in (_writable(f) for f in folders if f) if p]
    return (not problems), ("; ".join(problems) if problems else "writable")


def readiness(scanner: RansomwareScanner, workers: Check) -> Dict[str, Any]:
    """{"ready": bool, "checks": {name: {"ok", "detail"}}, "layers": {...}, "problems": [...]}."""
    states = layer_states(scanner)
    production = str(scanner.config.get("profile") or "standard").lower() == "production"
    yara = states.get("yara", {"state": "down", "detail": "not in the pipeline"})
    layer_problems = production_problems(states) if production else []
    checks: Dict[str, Check] = {
        "rules": (yara["state"] == "up", yara["detail"] or yara["state"]),
        "registry": registry_check(scanner),
        "storage": storage_check(scanner),
        "workers": workers,
        "layers": (not layer_problems,
                   "; ".join(layer_problems) if layer_problems else
                   ("every required layer is up" if production
                    else "standard profile: required layers not enforced")),
    }
    problems: List[str] = [f"{name}: {detail}" for name, (ok, detail) in checks.items() if not ok]
    return {"ready": not problems,
            "profile": "production" if production else "standard",
            "checks": {name: {"ok": ok, "detail": detail} for name, (ok, detail) in checks.items()},
            "layers": {name: {"state": st["state"], "detail": st["detail"]}
                       for name, st in states.items()},
            "problems": problems}
