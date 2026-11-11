"""Shared pytest setup: make the repo importable and keep runtime files in a
temporary HOME so tests never touch the real ~/RansomwareScanner folder."""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# RansomwareScanner.py creates ~/RansomwareScanner at import time; point HOME
# somewhere disposable *before* any test imports it.
_TEST_HOME = tempfile.mkdtemp(prefix="hrd_test_home_")
os.environ["HOME"] = _TEST_HOME
os.environ["USERPROFILE"] = _TEST_HOME          # Windows equivalent
# L-T1: keys and service settings exported in the developer's shell never reach a
# test. Assigned, not setdefault; an empty value also hides the repository .env.
# Kept in step with engine/secret_store.SECRETS (not imported: that would load
# engine.config before HOME is set).
_SECRET_NAMES = ("OPENAI_API_KEY", "VIRUSTOTAL_API_KEY", "SANDBOX_TOKEN", "WEBHOOK_SECRET",
                 "IMAP_PASSWORD", "SMTP_PASSWORD", "CLOUD_SECRET_ACCESS_KEY",
                 "CLOUD_PSEUDONYM_KEY", "AEGIS_API_TOKEN", "AEGIS_INTEL_TOKEN")
_SERVICES = ("OLLAMA_HOST", "SANDBOX_URL", "WEBHOOK_URL", "SMTP_HOST", "IMAP_HOST",
             "CLOUD_ENDPOINT", "AEGIS_INTEL_SOCKET", "AEGIS_API_SOCKET")
for _name in _SECRET_NAMES:
    os.environ.pop(_name + "_FILE", None)
for _name in _SECRET_NAMES + _SERVICES:
    os.environ[_name] = ""
os.environ["LLM_PROVIDER"] = "none"               # never call a real LLM in tests
# Tests never read or write the developer's real OS keyring.
os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"


import pytest  # noqa: E402  (after the environment is set)


@pytest.fixture(autouse=True)
def _close_result_caches(monkeypatch):
    """I-T2: close every result cache (one SQLite connection) a test opened.
    Production builds one scanner per process; tests build hundreds and never
    closed them. Caches of module or session fixtures are opened before this
    fixture and are left to their owner."""
    from core.cache import ResultCache
    opened = []
    real_init = ResultCache.__init__

    def init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(ResultCache, "__init__", init)
    yield
    for cache in opened:
        cache.close()
