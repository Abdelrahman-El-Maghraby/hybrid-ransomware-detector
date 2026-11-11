"""Rank 6, SAFE parts.

M26: a sandbox report may take SANDBOX_WAIT_SECONDS (600 by default), longer
than the worker's SCAN_TIMEOUT_SECONDS (300), so the worker is stopped and a
Critical file reads "Medium (failed scan)". Start-up now says so: a warning, an
error in the production profile. The compose file passes both settings to the
intel service, which holds the sandbox, so its own check compares the real
values. (A per-layer deadline is the owner's I-6 / wait-cap decision.)

M27 (compose part): no Docker service received RULEPACK_PUBLIC_KEYS, so the
`content` tool refused every pack and the analysis service could never
distrust a signer. Both now receive it. (The empty-key rule is the owner's.)"""

from pathlib import Path

import pytest
import yaml

from engine.validation import validate_config
from tests.test_scanner_integration import _config

ROOT = Path(__file__).resolve().parent.parent
SERVICES = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
MESSAGE = "SANDBOX_WAIT_SECONDS"


def _sandbox(tmp_path, **over):
    base = dict(sandbox_url="https://sandbox.example.invalid", sandbox_wait_seconds=600,
                scan_timeout_seconds=300, isolate_scans=True)
    return _config(tmp_path, **{**base, **over})


def test_a_sandbox_wait_not_below_the_scan_limit_is_reported(tmp_path):
    errors, warnings = validate_config(_sandbox(tmp_path))
    assert any(MESSAGE in w and "SCAN_TIMEOUT_SECONDS" in w for w in warnings)
    assert not any(MESSAGE in e for e in errors)
    errors, _ = validate_config(_sandbox(tmp_path, sandbox_wait_seconds=300))
    assert not any(MESSAGE in e for e in errors)          # equal is still too long: a warning
    assert any(MESSAGE in w for w in validate_config(_sandbox(tmp_path,
                                                               sandbox_wait_seconds=300))[1])


def test_it_is_an_error_in_the_production_profile(tmp_path):
    errors, _ = validate_config(_sandbox(tmp_path, profile="production"))
    assert any(MESSAGE in e for e in errors)


@pytest.mark.parametrize("over", [{"sandbox_wait_seconds": 240}, {"sandbox_url": ""},
                                  {"isolate_scans": False}])
def test_no_report_when_the_wait_fits_or_does_not_apply(tmp_path, over):
    errors, warnings = validate_config(_sandbox(tmp_path, **over))
    assert not any(MESSAGE in m for m in errors + warnings)


def test_compose_gives_intel_both_settings():
    env = SERVICES["intel"]["environment"]
    assert "SANDBOX_WAIT_SECONDS" in env and "SCAN_TIMEOUT_SECONDS" in env
    assert env["SCAN_TIMEOUT_SECONDS"] == SERVICES["analysis"]["environment"]["SCAN_TIMEOUT_SECONDS"]


@pytest.mark.parametrize("name", ["analysis", "content"])
def test_compose_passes_the_rule_pack_keys(name):
    assert SERVICES[name]["environment"]["RULEPACK_PUBLIC_KEYS"] == "${RULEPACK_PUBLIC_KEYS:-}"
