"""Integration surface: the versioned result schema and the optional REST API."""

import json
from pathlib import Path

SCHEMA_VERSION = "1.1"   # 1.1: optional scan_duration_ms
SCHEMA_PATH = Path(__file__).with_name("scan_result.schema.json")


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
