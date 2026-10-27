"""4.7: secrets move from .env to the OS keyring (verified before .env changes),
the environment / Docker secrets win on a service, and no value is ever logged or
put in an error. Every test uses a fake keyring: the real one is never touched."""

import json
import logging
import os
import stat
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

from engine import secret_store as S

KEY = "sk-live-0123456789abcdefSECRET"


class FakeKeyring:
    def __init__(self):
        self.data = {}

    def set_password(self, service, name, value):
        self.data[(service, name)] = value

    def get_password(self, service, name):
        return self.data.get((service, name))


class LiarKeyring(FakeKeyring):
    """Accepts the write, returns something else (a broken or locked keyring)."""

    def get_password(self, service, name):
        return "not-what-was-stored"


class RefusingKeyring(FakeKeyring):
    def set_password(self, service, name, value):
        raise PermissionError(f"denied for {value}")      # even if a backend echoes it


ENV_TEXT = (f"# local settings\nOPENAI_API_KEY={KEY}\nVT_UPLOAD_UNKNOWN=false\n"
            "export VIRUSTOTAL_API_KEY=vt-secret-value-1234\nLLM_PROVIDER=none\n")


def _env_file(tmp_path, text=ENV_TEXT, mode=0o600):
    p = tmp_path / ".env"
    p.write_text(text)
    p.chmod(mode)
    return p


def _values(p):
    from dotenv import dotenv_values
    return dotenv_values(p)


def test_tests_never_see_a_real_keyring():
    assert S.keyring_backend() is None        # conftest selects keyring's null backend


def test_store_reads_back_and_compares():
    kr = FakeKeyring()
    S.store("OPENAI_API_KEY", KEY, kr)
    assert kr.get_password(S.SERVICE, "OPENAI_API_KEY") == KEY
    with pytest.raises(S.SecretStoreError, match="did not return") as e:
        S.store("OPENAI_API_KEY", KEY, LiarKeyring())
    assert KEY not in str(e.value)
    with pytest.raises(S.SecretStoreError, match="refused OPENAI_API_KEY") as e:
        S.store("OPENAI_API_KEY", KEY, RefusingKeyring())
    assert KEY not in str(e.value) and e.value.__cause__ is None
    with pytest.raises(S.SecretStoreError, match="no OS keyring"):
        S.store("OPENAI_API_KEY", KEY)


def test_migration_moves_verified_secrets_and_keeps_the_rest(tmp_path, caplog):
    p = _env_file(tmp_path)
    kr = FakeKeyring()
    with caplog.at_level(logging.INFO, logger="RansomwareScanner"):
        m = S.migrate_env_file(p, _values(p), kr)
    assert m.moved == ["OPENAI_API_KEY", "VIRUSTOTAL_API_KEY"] and m.kept == []
    assert kr.get_password(S.SERVICE, "VIRUSTOTAL_API_KEY") == "vt-secret-value-1234"
    text = p.read_text()
    assert "OPENAI_API_KEY" not in text and "VIRUSTOTAL_API_KEY" not in text
    assert "VT_UPLOAD_UNKNOWN=false" in text and "# local settings" in text
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".env.*.tmp"))
    assert KEY not in caplog.text and "Moved OPENAI_API_KEY, VIRUSTOTAL_API_KEY" in caplog.text


@pytest.mark.parametrize("keyring", [LiarKeyring(), RefusingKeyring(), None])
def test_any_failure_leaves_env_untouched(tmp_path, caplog, keyring):
    p = _env_file(tmp_path)
    before = p.read_bytes()
    with caplog.at_level(logging.WARNING, logger="RansomwareScanner"):
        m = S.migrate_env_file(p, _values(p), keyring)
    assert p.read_bytes() == before and m.moved == []
    assert m.kept == ["OPENAI_API_KEY", "VIRUSTOTAL_API_KEY"] and m.reason
    assert KEY not in caplog.text and "vt-secret-value-1234" not in caplog.text


def test_failed_rewrite_leaves_env_untouched(tmp_path, monkeypatch):
    p = _env_file(tmp_path)
    before = p.read_bytes()

    def broken_replace(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(S.os, "replace", broken_replace)
    m = S.migrate_env_file(p, _values(p), FakeKeyring())
    assert p.read_bytes() == before and m.moved == [] and "could not be rewritten" in m.reason
    assert not list(tmp_path.glob(".env.*.tmp"))


def test_nothing_to_migrate(tmp_path):
    p = _env_file(tmp_path, "LLM_PROVIDER=none\nOPENAI_API_KEY=\n")
    assert S.migrate_env_file(p, _values(p), FakeKeyring()) == S.Migration()


def test_environment_and_docker_secrets_win(tmp_path, monkeypatch):
    secret = tmp_path / "vt"
    secret.write_text("from-docker-secret\n")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY_FILE", str(secret))
    monkeypatch.setenv("OPENAI_API_KEY", "from-environment")
    monkeypatch.setattr(S, "PROCESS_ENV", S.PROCESS_ENV | {"OPENAI_API_KEY"})
    monkeypatch.delenv("SANDBOX_TOKEN", raising=False)
    kr = FakeKeyring()
    for name in ("OPENAI_API_KEY", "VIRUSTOTAL_API_KEY", "SANDBOX_TOKEN"):
        kr.set_password(S.SERVICE, name, f"from-keyring-{name}")
    cfg = {"webhook_secret": "from-dotenv"}
    sources = S.apply(cfg, kr)
    assert cfg["chatgpt_api_key"] == "from-environment" and sources["OPENAI_API_KEY"] == "environment"
    assert cfg["virustotal_api_key"] == "from-docker-secret"
    assert cfg["sandbox_token"] == "from-keyring-SANDBOX_TOKEN" and sources["SANDBOX_TOKEN"] == "keyring"
    assert sources["WEBHOOK_SECRET"] == ".env" and sources["IMAP_PASSWORD"] == "unset"
    assert all(v in ("environment", "keyring", ".env", "unset") for v in sources.values())


def test_value_copied_from_dotenv_into_environ_is_not_the_environment(monkeypatch):
    monkeypatch.setenv("IMAP_PASSWORD", "loaded-by-dotenv")
    monkeypatch.setattr(S, "PROCESS_ENV", S.PROCESS_ENV - {"IMAP_PASSWORD"})
    assert S.from_environment("IMAP_PASSWORD") is None
    kr = FakeKeyring()
    kr.set_password(S.SERVICE, "IMAP_PASSWORD", "from-keyring")
    cfg = {}
    S.apply(cfg, kr)
    assert cfg["imap_password"] == "from-keyring"


def test_unreadable_secret_file_is_reported_without_a_value(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("WEBHOOK_SECRET_FILE", str(tmp_path / "missing"))
    with caplog.at_level(logging.WARNING, logger="RansomwareScanner"):
        assert S.from_environment("WEBHOOK_SECRET") is None
    assert "WEBHOOK_SECRET_FILE" in caplog.text


def test_init_runtime_migrates_on_first_run(tmp_path):
    """The real entry point, in a child process with its own HOME and .env."""
    env_file = _env_file(tmp_path)
    store_file = tmp_path / "keyring.json"
    code = textwrap.dedent(f"""
        import json, pathlib
        import engine.config as c
        from engine import secret_store as s

        class Kr:
            def __init__(self): self.d = {{}}
            def set_password(self, svc, n, v): self.d[n] = v
            def get_password(self, svc, n): return self.d.get(n)
        kr = Kr()
        s.keyring_backend = lambda: kr
        c.ENV_FILE = pathlib.Path({str(env_file)!r})
        c._DOTENV = c._read_dotenv(c.ENV_FILE)
        c.CONFIG["chatgpt_api_key"] = c._DOTENV.get("OPENAI_API_KEY", "")
        c.init_runtime(console=False)
        pathlib.Path({str(store_file)!r}).write_text(json.dumps(
            {{"keyring": kr.d, "config": c.CONFIG["chatgpt_api_key"]}}))
    """)
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    env.pop("OPENAI_API_KEY", None)
    env.pop("VIRUSTOTAL_API_KEY", None)
    root = Path(__file__).resolve().parent.parent
    out = subprocess.run([sys.executable, "-c", code], cwd=root, env=env,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    got = json.loads(store_file.read_text())
    assert got["keyring"] == {"OPENAI_API_KEY": KEY, "VIRUSTOTAL_API_KEY": "vt-secret-value-1234"}
    assert got["config"] == KEY
    assert "OPENAI_API_KEY" not in env_file.read_text()
    log = (tmp_path / "RansomwareScanner" / "ransomware_scanner.log").read_text()
    assert KEY not in log and "Secrets -> OPENAI_API_KEY:keyring" in log


def test_gui_saves_keys_to_the_keyring_not_to_disk(tmp_path, monkeypatch):
    settings = pytest.importorskip("aegis_gui.pages.settings")
    kr = FakeKeyring()
    monkeypatch.setattr(S, "keyring_backend", lambda: kr)
    monkeypatch.setattr(settings, "ENV_FILE", tmp_path / ".env")

    class Widget:
        def __init__(self, text=""):
            self.text, self.kw = text, {}

        def get(self):
            return self.text

        def delete(self, *a):
            self.text = ""

        def configure(self, **kw):
            self.kw.update(kw)

    cfg = {}
    monkeypatch.setattr(settings.RS, "CONFIG", cfg)
    page = types.SimpleNamespace(
        key_rows={"OPENAI_API_KEY": (Widget(KEY), Widget(), "chatgpt_api_key"),
                  "VIRUSTOTAL_API_KEY": (Widget(""), Widget(), "virustotal_api_key")},
        keys_label=Widget(),
        app=types.SimpleNamespace(scanner=types.SimpleNamespace(config={}),
                                  pages={"dashboard": types.SimpleNamespace(refresh_cards=lambda: None)}))
    settings.SettingsPage._save_keys(page)
    assert kr.get_password(S.SERVICE, "OPENAI_API_KEY") == KEY and cfg["chatgpt_api_key"] == KEY
    assert not (tmp_path / ".env").exists()
    assert "OS keyring: OPENAI_API_KEY" in page.keys_label.kw["text"]

    monkeypatch.setattr(S, "keyring_backend", lambda: None)
    page.key_rows["OPENAI_API_KEY"][0].text = KEY
    settings.SettingsPage._save_keys(page)
    assert "Nothing was written to disk" in page.keys_label.kw["text"]
    assert KEY not in page.keys_label.kw["text"] and not (tmp_path / ".env").exists()
