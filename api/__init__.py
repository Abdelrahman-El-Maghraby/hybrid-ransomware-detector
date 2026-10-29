"""Integration surface: the versioned result schema and the optional REST API."""

import json
from pathlib import Path

SCHEMA_VERSION = "1.4"   # 1.1: optional scan_duration_ms; 1.2: scan_status, incomplete_reasons, verdict_label; 1.3: provenance.shared; 1.4: provenance.isolation
SCHEMA_PATH = Path(__file__).with_name("scan_result.schema.json")


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
