"""
Secrets (API keys, tokens, passwords) live in the OS keyring on a desktop and in
the environment for a service - never in a file the scanner writes.

Where a secret comes from, first match wins:

    1. the process environment: NAME, or NAME_FILE naming a file that holds it
       (Docker / Kubernetes secrets mounted under /run/secrets/...)
    2. the OS keyring (macOS Keychain, Windows Credential Manager, Secret Service)
    3. a legacy .env file (read, and moved to the keyring on first run)

Migration (`migrate_env_file`): every secret found in .env is written to the
keyring and read back; only when every one of them reads back identical are their
lines removed from .env. On any failure .env is left untouched and a warning
names the secret (never its value). Values are never logged or put in errors.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Set

logger = logging.getLogger("RansomwareScanner")

SERVICE = "aegis-sentinel"
# (environment variable, CONFIG key)
SECRETS = (("OPENAI_API_KEY", "chatgpt_api_key"), ("VIRUSTOTAL_API_KEY", "virustotal_api_key"),
           ("SANDBOX_TOKEN", "sandbox_token"), ("WEBHOOK_SECRET", "webhook_secret"),
           ("IMAP_PASSWORD", "imap_password"), ("SMTP_PASSWORD", "smtp_password"),
           ("CLOUD_SECRET_ACCESS_KEY", "cloud_secret_access_key"),
           ("CLOUD_PSEUDONYM_KEY", "cloud_pseudonym_key"))
SECRET_NAMES = tuple(name for name, _ in SECRETS)

# Names set in the process environment before any .env file was loaded into it.
PROCESS_ENV: Set[str] = set(os.environ)


class SecretStoreError(RuntimeError):
    """A secret could not be stored; the message never contains the value."""


def keyring_backend() -> Optional[Any]:
    """The keyring module when a real OS keyring is usable, else None (servers,
    containers and CI have none; the fail / null backends do not count)."""
    try:
        import keyring
        from keyring.backends import fail
    except ImportError:
        return None
    try:
        backend = keyring.get_keyring()
    except Exception:          # a broken keyring configuration: treat as none
        return None
    if isinstance(backend, fail.Keyring) or "null" in type(backend).__module__.lower():
        return None
    return keyring


def from_environment(name: str, environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """NAME or NAME_FILE from the process environment (not from .env)."""
    env = os.environ if environ is None else environ
    path = env.get(f"{name}_FILE")
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError as e:
            logger.warning("%s_FILE=%s cannot be read (%s)", name, path, type(e).__name__)
            return None
    if environ is None and name not in PROCESS_ENV:
        return None            # put there by load_dotenv: that is the .env file
    return env.get(name)


def store(name: str, value: str, backend: Optional[Any] = None) -> None:
    """Write a secret to the keyring and read it back; raise if it does not match."""
    kr = backend or keyring_backend()
    if kr is None:
        raise SecretStoreError("no OS keyring is available on this system")
    try:
        kr.set_password(SERVICE, name, value)
        back = kr.get_password(SERVICE, name)
    except Exception as e:
        raise SecretStoreError(f"the keyring refused {name} ({type(e).__name__})") from None
    if back is None or not hmac.compare_digest(back.encode(), value.encode()):
        raise SecretStoreError(f"the keyring did not return the stored {name}")


def load(name: str, backend: Optional[Any] = None) -> Optional[str]:
    kr = backend or keyring_backend()
    if kr is None:
        return None
    try:
        return kr.get_password(SERVICE, name)
    except Exception:
        return None


def apply(config: MutableMapping[str, Any], backend: Optional[Any] = None) -> Dict[str, str]:
    """Fill the CONFIG secret keys by precedence; return each one's source
    ("environment", "keyring", ".env" or "unset"), never the value."""
    kr = backend or keyring_backend()
    sources: Dict[str, str] = {}
    for name, key in SECRETS:
        env = from_environment(name)
        if env:
            config[key], sources[name] = env, "environment"
            continue
        stored = load(name, kr) if kr is not None else None
        if stored:
            config[key], sources[name] = stored, "keyring"
        else:
            sources[name] = ".env" if config.get(key) else "unset"
    return sources


@dataclass
class Migration:
    moved: List[str] = field(default_factory=list)       # now only in the keyring
    kept: List[str] = field(default_factory=list)        # still in .env
    reason: str = ""                                     # why they were kept


_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def migrate_env_file(env_file: Path, values: Mapping[str, Optional[str]],
                     backend: Optional[Any] = None) -> Migration:
    """Move the secrets in `env_file` (parsed as `values`) to the keyring."""
    found = {n: v for n, v in values.items() if n in SECRET_NAMES and v}
    result = Migration()
    if not found:
        return result
    kr = backend or keyring_backend()
    if kr is None:
        result.kept, result.reason = sorted(found), "no OS keyring available"
        logger.warning("Secrets %s stay in %s: %s. Use environment variables or Docker "
                       "secrets on a server.", ", ".join(result.kept), env_file, result.reason)
        return result
    try:
        for name, value in found.items():
            store(name, value, kr)
    except SecretStoreError as e:
        result.kept, result.reason = sorted(found), str(e)
        logger.warning("Could not move secrets to the OS keyring (%s); %s left unchanged.",
                       e, env_file)
        return result
    try:
        _remove_lines(env_file, set(found))
    except OSError as e:
        result.kept, result.reason = sorted(found), f"{env_file} could not be rewritten"
        logger.warning("Secrets are in the OS keyring, but %s could not be rewritten (%s); "
                       "remove %s from it by hand.", env_file, type(e).__name__,
                       ", ".join(sorted(found)))
        return result
    result.moved = sorted(found)
    logger.info("Moved %s from %s to the OS keyring.", ", ".join(result.moved), env_file)
    return result


def _remove_lines(env_file: Path, names: Set[str]) -> None:
    """Rewrite .env without the lines that set `names`, atomically, same permissions."""
    text = env_file.read_text(encoding="utf-8")
    kept = [ln for ln in text.splitlines(keepends=True)
            if not ((m := _LINE.match(ln)) and m.group(1) in names)]
    mode = env_file.stat().st_mode & 0o777
    fd, tmp = tempfile.mkstemp(dir=str(env_file.parent), prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("".join(kept))
        os.chmod(tmp, mode)
        os.replace(tmp, env_file)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
