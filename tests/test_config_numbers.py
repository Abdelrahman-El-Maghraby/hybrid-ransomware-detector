"""L-E2: NaN passed validation (`OUTBOX_MAX_AGE_HOURS=nan`), NaN or inf crashed
the import of engine.config for integer settings (`SCAN_TIMEOUT_SECONDS=nan`:
"cannot convert float NaN to integer"), and `WORKER_MEMORY_MB=0.9` became 0,
which means no memory limit, with no message. Each is now reported."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from engine.validation import validate_config
from tests.test_scanner_integration import _config

ROOT = Path(__file__).resolve().parents[1]


def _fresh(env):
    code = ("import json, engine.config as c; print(json.dumps(["
            "c.CONFIG['outbox_max_age_hours'], c.CONFIG['worker_memory_mb'], "
            "c.CONFIG['scan_timeout_seconds'], c.ENV_PROBLEMS]))")
    run = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
                         env={**os.environ, **env}, timeout=60)
    assert run.returncode == 0, run.stderr[-500:]
    return json.loads(run.stdout)


@pytest.mark.parametrize("env, name", [
    ({"OUTBOX_MAX_AGE_HOURS": "nan"}, "OUTBOX_MAX_AGE_HOURS"),
    ({"SCAN_TIMEOUT_SECONDS": "nan"}, "SCAN_TIMEOUT_SECONDS"),
    ({"SCAN_TIMEOUT_SECONDS": "inf"}, "SCAN_TIMEOUT_SECONDS"),
    ({"WORKER_MEMORY_MB": "0.9"}, "WORKER_MEMORY_MB"),
])
def test_a_value_that_would_misbehave_is_reported(env, name):
    age, memory, timeout, problems = _fresh(env)
    assert any(p.startswith(name) for p in problems), problems
    assert age == 24 and memory == 2048 and timeout == 300               # the defaults


def test_ordinary_values_are_read_as_before():
    age, memory, timeout, problems = _fresh({"OUTBOX_MAX_AGE_HOURS": "12.5",
                                            "WORKER_MEMORY_MB": "0", "SCAN_TIMEOUT_SECONDS": "90.7"})
    assert (age, memory, timeout, problems) == (12.5, 0, 90, [])


def test_validation_rejects_a_non_finite_number(tmp_path):
    errors, _ = validate_config(_config(tmp_path, outbox_max_age_hours=float("nan")))
    assert any("OUTBOX_MAX_AGE_HOURS" in e for e in errors)
