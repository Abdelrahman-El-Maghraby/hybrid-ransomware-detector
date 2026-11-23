"""L-T1: the test session ignores keys and service settings exported in the
developer's shell. Before the fix conftest used setdefault for LLM_PROVIDER and
VIRUSTOTAL_API_KEY and left every other secret (and its NAME_FILE form) and the
service URLs alone, so a test scanner could send hashes to VirusTotal or text to
an LLM on the developer's account."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTED = {"VIRUSTOTAL_API_KEY": "dummy-vt", "LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "dummy-openai", "SANDBOX_URL": "https://sandbox.example",
            "SANDBOX_TOKEN": "dummy-sandbox", "WEBHOOK_URL": "https://siem.example/hook",
            "SMTP_HOST": "smtp.example", "AEGIS_INTEL_SOCKET": "/nonexistent/intel.sock"}


def test_probe_sees_no_exported_service_settings():
    if os.environ.get("AEGIS_ENV_PROBE") != "1":
        return                                       # only meaningful in the child session
    from engine.config import CONFIG
    for key in ("virustotal_api_key", "chatgpt_api_key", "sandbox_url", "sandbox_token",
                "webhook_url", "smtp_host", "intel_socket"):
        assert not CONFIG[key], key
    assert CONFIG["llm_provider"] == "none"
    assert not any(n.endswith("_FILE") and n[:-5] in EXPORTED or n == "OPENAI_API_KEY_FILE"
                   for n in os.environ)


def test_a_session_started_with_keys_exported_sees_none(tmp_path):
    key_file = tmp_path / "key"
    key_file.write_text("dummy-from-file")
    env = {**os.environ, **EXPORTED, "OPENAI_API_KEY_FILE": str(key_file),
           "SMTP_PASSWORD_FILE": str(key_file), "AEGIS_ENV_PROBE": "1"}
    run = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q",
                          f"{Path(__file__).name}::test_probe_sees_no_exported_service_settings"],
                         cwd=ROOT / "tests", env=env, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout[-2000:]


def test_conftest_clears_every_stored_secret():
    from engine.secret_store import SECRET_NAMES
    from tests import conftest
    assert set(SECRET_NAMES) <= set(conftest._SECRET_NAMES)
