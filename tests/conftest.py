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
os.environ.setdefault("LLM_PROVIDER", "none")    # never call a real LLM in tests
os.environ.setdefault("VIRUSTOTAL_API_KEY", "")
