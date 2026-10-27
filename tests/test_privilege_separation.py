"""4.7: scanning needs no containment rights. The code that suspends or kills
processes and locks folders (core/containment.py, core/response.py) is never
imported by a scan or by the API, and the server image leaves it out entirely
(.dockerignore; tests/test_deployment.py), so a compromised parser in the analysis
service finds none."""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONTAINMENT = ("core.containment", "core.response")


def _run(code: str, tmp_path) -> dict:
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    out = subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=180)
    assert out.returncode == 0, out.stderr[-3000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


SCAN = """
    import json, sys
    {block}
    from tests.helpers import make_pdf
    from tests.test_scanner_integration import _config
    import pathlib
    tmp = pathlib.Path({tmp!r})
    from engine.scanner import RansomwareScanner
    scanner = RansomwareScanner(_config(tmp, data_dir=str(tmp / "data")))
    f = tmp / "scan" / "doc.pdf"
    f.write_bytes(make_pdf("quarterly figures"))
    result = scanner.scan_file(str(f))
    try:
        from api.server import create_app
        create_app(scanner.config, token="t" * 32, isolate=False)
        api = True
    except ImportError as e:
        api = "fastapi" not in str(e) and str(e)
    print(json.dumps({{"verdict": result["verdict"], "status": result["scan_status"], "api": api,
                      "loaded": [m for m in {mods!r} if sys.modules.get(m) is not None]}}))
"""


def test_scan_and_api_never_import_containment(tmp_path):
    got = _run(SCAN.format(block="", tmp=str(tmp_path), mods=CONTAINMENT), tmp_path)
    assert got["loaded"] == [] and got["verdict"] == "Clean"


def test_scanning_works_when_containment_is_absent(tmp_path):
    """As in the server image: importing either module fails."""
    block = f"for m in {CONTAINMENT!r}: sys.modules[m] = None"
    got = _run(SCAN.format(block=block, tmp=str(tmp_path), mods=CONTAINMENT), tmp_path)
    assert got["verdict"] == "Clean" and got["status"] in ("complete", "partial")
    assert got["api"] in (True, False)


def test_without_containment_a_canary_response_is_a_clear_error(tmp_path):
    code = f"""
        import json, sys
        for m in {CONTAINMENT!r}: sys.modules[m] = None
        from engine.validation import validate_config
        errors, _ = validate_config({{"canary_response": "stop_writers"}}, ())
        print(json.dumps({{"errors": errors}}))
    """
    errors = _run(code, tmp_path)["errors"]
    assert any("desktop builds only" in e for e in errors)


def test_production_profile_refuses_containment():
    from engine.validation import validate_config
    errors, _ = validate_config({"profile": "production", "canary_response": "network_off"}, ())
    assert any("CANARY_RESPONSE" in e and "production" in e for e in errors)


@pytest.mark.parametrize("module", CONTAINMENT)
def test_containment_is_only_reached_from_desktop_entry_points(module):
    """Who imports it: the CLI's release commands, the canary alert, validation (guarded)."""
    name = module.split(".")[-1]
    users = []
    for path in list(ROOT.glob("*.py")) + list(ROOT.glob("engine/*.py")) + list(ROOT.glob("api/*.py")) \
            + list(ROOT.glob("detectors/*.py")) + list(ROOT.glob("core/*.py")):
        text = path.read_text(encoding="utf-8")
        if f"core.{name} import" in text or f"from core import {name}" in text:
            users.append(path.relative_to(ROOT).as_posix())
    allowed = {"RansomwareScanner.py", "engine/protection.py", "engine/validation.py",
               "core/response.py"}
    assert set(users) <= allowed, users
