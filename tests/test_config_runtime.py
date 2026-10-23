"""engine/config.py has no import-time side effects; init_runtime() and
engine/validation.py do the start-up work for the entry points."""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from engine import config as cfg_mod
from engine import logs
from engine.validation import ConfigError, check_config, validate_config

ROOT = Path(__file__).resolve().parent.parent


def _run(code, home, **env):
    e = dict(os.environ, HOME=str(home), USERPROFILE=str(home), **env)
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=120, cwd=ROOT, env=e)


def test_importing_creates_nothing_and_configures_no_logging(tmp_path):
    # (Intel OpenMP, loaded by an optional library, sets KMP_* itself.)
    code = ("import logging, os\n"
            "env = lambda: {k: v for k, v in os.environ.items() if not k.startswith('KMP_')}\n"
            "before = env()\n"
            "import RansomwareScanner, engine.config as c\n"
            "print(c.APP_DIR.exists(), len(logging.getLogger().handlers), env() == before)")
    out = _run(code, tmp_path)
    assert out.stdout.split() == ["False", "0", "True"], out.stderr[-2000:]


def test_init_runtime_creates_folders_and_logs_once(tmp_path):
    code = ("import logging, engine.config as c\n"
            "c.init_runtime(console=False); c.init_runtime(console=False)\n"
            "logging.getLogger('RansomwareScanner').info('hello')\n"
            "print(c.DATA_DIR.is_dir(), len(logging.getLogger().handlers))")
    out = _run(code, tmp_path)
    assert out.stdout.split() == ["True", "1"], out.stderr[-2000:]
    log = (tmp_path / "RansomwareScanner" / "ransomware_scanner.log").read_text()
    assert "RansomwareScanner - INFO - hello" in log


def test_json_logs(tmp_path):
    code = ("import logging, engine.config as c\n"
            "c.init_runtime(console=False)\n"
            "logging.getLogger('RansomwareScanner').info('scanned %s', 'a.pdf', extra={"
            "'event': 'scan_completed', 'sha256': 'ab', 'verdict': 'Clean', 'duration_ms': 4})\n"
            "try:\n    1/0\nexcept ZeroDivisionError:\n"
            "    logging.getLogger('x').exception('boom')\n")
    out = _run(code, tmp_path, LOG_FORMAT="json", LOG_LEVEL="DEBUG")
    assert out.returncode == 0, out.stderr[-2000:]
    lines = (tmp_path / "RansomwareScanner" / "ransomware_scanner.log").read_text().splitlines()
    first, second = json.loads(lines[0]), json.loads(lines[-1])
    assert first["event"] == "scan_completed" and first["message"] == "scanned a.pdf"
    assert first["verdict"] == "Clean" and first["duration_ms"] == 4 and first["level"] == "INFO"
    assert first["timestamp"][:4].isdigit() and "path" not in first
    assert second["event"] == "log" and "ZeroDivisionError" in second["exception"]


def test_configure_logging_replaces_its_own_handlers(tmp_path):
    root = logging.getLogger()
    level = root.level
    try:
        logs.configure_logging(tmp_path / "a.log", console=False, fmt="text")
        logs.configure_logging(tmp_path / "a.log", console=True, fmt="json")
        mine = [h for h in root.handlers if getattr(h, logs._MARK, False)]
        assert len(mine) == 2 and isinstance(mine[0].formatter, logs.JsonFormatter)
    finally:
        for h in [h for h in root.handlers if getattr(h, logs._MARK, False)]:
            root.removeHandler(h)
            h.close()
        root.setLevel(level)


def test_dotenv_is_read_not_exported(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("AEGIS_TEST_ONLY=from-file\nEMPTY=\n")
    values = cfg_mod._read_dotenv(env)
    assert values["AEGIS_TEST_ONLY"] == "from-file" and "AEGIS_TEST_ONLY" not in os.environ
    assert cfg_mod._read_dotenv(tmp_path / "missing") == {}
    monkeypatch.setattr(cfg_mod, "_DOTENV", values)
    assert cfg_mod._getenv("AEGIS_TEST_ONLY") == "from-file"
    monkeypatch.setenv("AEGIS_TEST_ONLY", "from-env")
    assert cfg_mod._getenv("AEGIS_TEST_ONLY") == "from-env"          # the environment wins


def test_bad_numbers_and_booleans_are_reported(monkeypatch):
    monkeypatch.setattr(cfg_mod, "ENV_PROBLEMS", [])
    monkeypatch.setenv("AEGIS_N", "four")
    monkeypatch.setenv("AEGIS_B", "maybe")
    monkeypatch.setenv("AEGIS_OK", " 7 ")
    assert cfg_mod._env_float("AEGIS_N", 3) == 3 and cfg_mod._env_float("AEGIS_OK", 3) == 7
    assert cfg_mod._env_bool("AEGIS_B", True) is True
    monkeypatch.setenv("AEGIS_B", "Off")
    assert cfg_mod._env_bool("AEGIS_B", True) is False
    assert cfg_mod.ENV_PROBLEMS == ["AEGIS_N='four' is not a number",
                                    "AEGIS_B='maybe' is not a yes/no value (use true or false)"]


# ------------------------------------------------------------------ validation
def test_the_default_configuration_is_valid():
    errors, _ = validate_config(cfg_mod.CONFIG)
    assert errors == []


@pytest.mark.parametrize("change, message", [
    ({"scan_workers": -1}, "SCAN_WORKERS=-1 is out of range"),
    ({"imap_port": 70000}, "IMAP_PORT=70000 is out of range"),
    ({"scan_timeout_seconds": "60"}, "SCAN_TIMEOUT_SECONDS must be a number"),
    ({"http_timeout": True}, "HTTP_TIMEOUT must be a number"),
    ({"llm_provider": "chatgpt"}, "LLM_PROVIDER='chatgpt' is not one of"),
    ({"webhook_min_verdict": "severe"}, "WEBHOOK_MIN_VERDICT='severe'"),
    ({"canary_contain_mode": "pause"}, "CANARY_CONTAIN_MODE='pause'"),
    ({"ollama_host": "localhost:11434"}, "OLLAMA_HOST='localhost:11434' must start with http"),
    ({"canary_response": "network-off"}, "unknown action(s) network-off"),
    ({"canary_response": "script"}, "CANARY_RESPONSE_SCRIPT is not set"),
    ({"canary_response_script": "isolate.sh"}, "must be an absolute path"),
    ({"imap_check_minutes": 5, "imap_host": ""}, "IMAP_CHECK_MINUTES is set but IMAP_HOST"),
    ({"weights_override": "/no/such/file.yaml"}, "WEIGHTS_OVERRIDE=/no/such/file.yaml"),
    ({"file_extensions": ["pdf"]}, "file_extensions must be a list"),
    ({"scan_directories": "/home"}, "scan_directories must be a list"),
    ({"llm_provider": "openai", "chatgpt_api_key": ""}, "LLM_PROVIDER=openai needs"),
])
def test_invalid_values_are_errors(change, message):
    errors, _ = validate_config({**cfg_mod.CONFIG, **change})
    assert any(message in e for e in errors), errors
    with pytest.raises(ConfigError) as info:
        check_config({**cfg_mod.CONFIG, **change}, env_problems=())
    assert message in str(info.value)


@pytest.mark.parametrize("change, message", [
    ({"webhook_url": "http://siem.example.org/hook", "webhook_secret": "s"}, "plain http"),
    ({"webhook_url": "https://siem.example.org/hook", "webhook_secret": ""}, "WEBHOOK_SECRET"),
    ({"imap_host": "imap.example.org", "imap_password": ""}, "app password"),
    ({"yara_rules_dir": "/no/rules"}, "YARA layer will be off"),
    ({"canary_lock_dirs": "/no/such/dir"}, "not a folder"),
    ({"canary_contain_mode": "terminate", "canary_response": ""}, "stop_writers"),
    ({"virustotal_upload_unknown": True, "virustotal_api_key": ""}, "VT_UPLOAD_UNKNOWN"),
    ({"isolate_scans": False, "scan_workers": 4}, "ISOLATE_SCANS is off"),
])
def test_doubtful_values_are_warnings(change, message, caplog):
    with caplog.at_level(logging.WARNING, logger="RansomwareScanner"):
        warnings = check_config({**cfg_mod.CONFIG, **change}, env_problems=())
    assert any(message in w for w in warnings), warnings
    assert message in caplog.text


def test_local_http_webhook_is_fine():
    _, warnings = validate_config({**cfg_mod.CONFIG, "webhook_url": "http://127.0.0.1:9000/x",
                                   "webhook_secret": "s"})
    assert not any("plain http" in w for w in warnings)


def test_env_problems_are_errors():
    with pytest.raises(ConfigError) as info:
        check_config(cfg_mod.CONFIG, env_problems=["SCAN_WORKERS='four' is not a number"])
    assert "SCAN_WORKERS='four'" in str(info.value)


def test_cli_stops_on_a_bad_configuration(tmp_path):
    out = subprocess.run([sys.executable, str(ROOT / "RansomwareScanner.py"), "--verify-canaries"],
                         capture_output=True, text=True, timeout=120, cwd=tmp_path,
                         env=dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path),
                                  SCAN_WORKERS="four", CANARY_RESPONSE="reboot"))
    assert out.returncode == 2
    assert "SCAN_WORKERS='four' is not a number" in out.stdout
    assert "unknown action(s) reboot" in out.stdout
