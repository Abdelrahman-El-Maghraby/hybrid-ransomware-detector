#!/usr/bin/env python3
"""Read the numbers the technical overview quotes straight from the code.

    python docs/security-overview/facts.py            print the facts as JSON
    python docs/security-overview/facts.py --write    store them in src/facts.json

The overview's Markdown cites these values as {{fact:<name>}} placeholders.
build_overview.py recomputes them on every build and stops when the code no
longer agrees with src/facts.json, so a changed default, layer, weight or limit
cannot silently leave the document out of date. Rewrite the file with --write
only after the text around each changed value has been reviewed.

Run it from the repository's own virtual environment: it imports the engine
(no file is scanned, nothing is written outside src/facts.json, no network). It
runs with an empty environment and a temporary HOME so that no local .env,
secret store or user setting changes a default.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FACTS_FILE = HERE / "src" / "facts.json"


def _collect() -> dict:
    """Runs inside a clean child process (see compute())."""
    sys.path.insert(0, str(REPO))
    from api import SCHEMA_VERSION
    from core import intel_client
    from detectors import scoring
    from detectors.registry import REGISTRY
    from detectors.signals import Signals
    from engine import completeness, config, layers, text, workers
    from engine.workers import _IsolatedScan

    pipeline = layers.default_pipeline()
    cfg: Any = config.CONFIG
    signal_fields = [f.name for f in dataclasses.fields(Signals)
                     if f.name not in ("allowlisted", "local_db_hit", "scan_failed", "extra")]
    w = REGISTRY.weights
    mib = 1024 * 1024
    return {
        "engine_version": config.ENGINE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "registry_version": REGISTRY.version,
        "layer_instances": len(pipeline),
        "layer_classes": len({type(layer) for layer in pipeline}),
        "container_layers": sum(isinstance(layer, layers.ContainerLayer) for layer in pipeline),
        "heavy_layers": ", ".join(layer.name for layer in pipeline if layer.heavy),
        "pipeline_order": ", ".join(layer.name for layer in pipeline),
        "typed_signals": len(signal_fields),
        "scorers": len(scoring.SCORERS),
        "indicators": len(REGISTRY.indicators) if hasattr(REGISTRY, "indicators") else 0,
        "cap_technical": int(REGISTRY.caps["technical"]),
        "cap_reputation": int(REGISTRY.caps["reputation"]),
        "cap_semantic": int(REGISTRY.caps["semantic"]),
        "cap_statistical": int(REGISTRY.caps["statistical"]),
        "cap_dynamic": int(REGISTRY.caps["dynamic"]),
        "max_raw": int(REGISTRY.max_raw),
        "semantic_only_max": int(REGISTRY.semantic_only_max),
        "bands": "; ".join(f"{lo}-{hi} {name}" for lo, hi, name in scoring.BANDS),
        "w_local_db": int(w["W_LOCAL_DB"]),
        "w_yara_critical": int(w["W_YARA"]["critical"]),
        "w_yara_medium": int(w["W_YARA"]["medium"]),
        "w_macro_autoexec": int(w["W_MACRO_AUTOEXEC"]),
        "w_macro_critical": int(w["W_MACRO_CRITICAL"]),
        "w_macro_suspicious": int(w["W_MACRO_SUSPICIOUS"]),
        "w_macro_synergy": int(w["W_MACRO_DROPPER_SYNERGY"]),
        "w_llm": int(w["W_LLM"]),
        "w_ml": int(w["W_ML"]),
        "w_vt_ratio": int(w["W_VT_RATIO"]),
        "w_vt_floor": int(w["W_VT_FLOOR"]),
        "w_scan_failed": int(w["W_SCAN_FAILED"]),
        "w_fuzzy": int(w["W_FUZZY"]),
        "status_precedence": " > ".join(reversed(completeness.PRECEDENCE)),
        "max_reasons": completeness.MAX_REASONS,
        "scan_timeout_seconds": cfg["scan_timeout_seconds"],
        "worker_memory_mb": cfg["worker_memory_mb"],
        "isolate_scans": cfg["isolate_scans"],
        "max_failed_starts": _IsolatedScan.MAX_FAILED_STARTS,
        "worker_start_seconds": int(_IsolatedScan.START_SECONDS),
        "worker_reply_mib": workers.MAX_REPLY_BYTES // mib,
        "reply_kinds": ", ".join(workers.REPLY_KINDS),
        "intel_reply_mib": intel_client.MAX_REPLY_BYTES // mib,
        "shared_read_mib": layers.ScanContext.SHARED_READ_MAX // mib,
        "fuzzy_max_mib": cfg["fuzzy_max_bytes"] // mib,
        "text_page_mib": text.TextExtractionMixin.TEXT_MAX_BYTES // mib,
        "text_compare_mib": text.TextExtractionMixin.TEXT_CHECK_BYTES // mib,
        "text_max_chars": f"{text.TextExtractionMixin.PDF_MAX_CHARS:,}",
        "strings_read_mib": text.STRINGS_MAX_BYTES // mib,
        "strings_max_chars": f"{text.STRINGS_MAX_CHARS:,}",
        "strings_lookahead_mib": text.STRINGS_LOOKAHEAD_BYTES // mib,
        "strings_inspected_mib": (text.STRINGS_MAX_BYTES + text.STRINGS_LOOKAHEAD_BYTES) // mib,
        "archive_max_depth": cfg["archive_max_depth"],
        "archive_max_total_mb": cfg["archive_max_total_mb"],
        "archive_max_members": cfg["archive_max_members"],
        "archive_scan_members": cfg["archive_scan_members"],
        "max_nesting": cfg["max_nesting"],
        "mail_max_attachments": cfg["mail_max_attachments"],
        "mail_scan_attachments": cfg["mail_scan_attachments"],
        "sandbox_wait_seconds": cfg["sandbox_wait_seconds"],
        "sandbox_submit": cfg["sandbox_submit"],
        "http_timeout": cfg["http_timeout"],
        "vt_requests_per_minute": int(cfg["virustotal_requests_per_minute"]),
        "cache_ttl_hours": int(cfg["cache_ttl_hours"]),
        "outbox_max_age_hours": int(cfg["outbox_max_age_hours"]),
        "webhook_min_verdict": cfg["webhook_min_verdict"],
        "alert_email_min_verdict": cfg["alert_email_min_verdict"],
        "canary_check_minutes": cfg["canary_check_minutes"],
        "scan_interval_hours": cfg["scan_interval_hours"],
        "default_extensions": len(config.DEFAULT_EXTENSIONS),
        "supported_extensions": len(config.SUPPORTED_EXTENSIONS),
        "llm_provider": cfg["llm_provider"],
        "emulation_enabled": cfg["emulation_enabled"],
        "ml_enabled": cfg["ml_enabled"],
        "qr_scan_enabled": cfg["qr_scan_enabled"],
    }


def compute() -> dict:
    """The facts, read by a child process with no inherited settings."""
    with tempfile.TemporaryDirectory(prefix="aegis_facts_") as home:
        env = {"HOME": home, "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": home}
        out = subprocess.run([sys.executable, "-I", "-c",
                              f"import sys; sys.path.insert(0, {str(HERE)!r}); "
                              "import json, facts; print(json.dumps(facts._collect()))"],
                             cwd=home, env=env, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise SystemExit(f"facts.py: could not read the code:\n{out.stderr[-2000:]}")
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    facts = compute()
    if "--write" in sys.argv[1:]:
        FACTS_FILE.write_text(json.dumps(facts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {FACTS_FILE.relative_to(REPO)} ({len(facts)} facts)")
    else:
        print(json.dumps(facts, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
