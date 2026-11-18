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
             "CLOUD_ENDPOINT", "AEGIS_INTEL_SOCKET", "AEGIS_API_SOCKET", "AEGIS_INTEL_URL",
             "AEGIS_INTEL_CA_FILE", "AEGIS_INTEL_SERVER_NAME")
for _name in _SECRET_NAMES:
    os.environ.pop(_name + "_FILE", None)
for _name in _SECRET_NAMES + _SERVICES:
    os.environ[_name] = ""
os.environ["LLM_PROVIDER"] = "none"               # never call a real LLM in tests
# Tests never read or write the developer's real OS keyring.
os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"


import ipaddress  # noqa: E402
import socket  # noqa: E402

import pytest  # noqa: E402  (after the environment is set)

# --------------------------------------------------------------- no outside network
# The safe suite must not contact anything beyond this machine. Every connect, UDP
# send or name lookup aimed elsewhere is refused (the code sees an unreachable
# network, so nothing leaves) and recorded, and the test that made it fails. A test
# that deliberately exercises a refused outside address marks itself
# `expects_blocked_network`. Worker processes started by a test are not covered.
_BLOCKED: list = []
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", ""}


def _local_host(host) -> bool:
    if not isinstance(host, str):
        return True                      # AF_UNIX path (bytes) or an abstract name
    host = host.split("%", 1)[0].strip("[]").lower()
    if host in _LOCAL_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _outside(sock, address) -> bool:
    if getattr(socket, "AF_UNIX", None) is not None and sock.family == socket.AF_UNIX:
        return False
    return isinstance(address, tuple) and not _local_host(address[0])


def _guard(name, real):
    def call(self, address, *rest):
        target = rest[-1] if name == "sendto" and rest else address
        if _outside(self, target):
            _BLOCKED.append(f"{name} {target!r}")
            raise OSError(101, f"test network guard: {target!r} is outside this machine")
        return real(self, address, *rest)
    return call


for _name in ("connect", "connect_ex", "sendto"):
    setattr(socket.socket, _name, _guard(_name, getattr(socket.socket, _name)))
_real_getaddrinfo = socket.getaddrinfo


def _guarded_getaddrinfo(host, *args, **kwargs):
    if host is not None and not _local_host(host.decode() if isinstance(host, bytes) else host):
        _BLOCKED.append(f"getaddrinfo {host!r}")
        raise socket.gaierror(socket.EAI_NONAME, f"test network guard: {host!r} not resolved")
    return _real_getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _guarded_getaddrinfo


def pytest_configure(config):
    config.addinivalue_line("markers", "expects_blocked_network: the test deliberately "
                            "reaches for an outside address; the guard still blocks it")


@pytest.fixture(autouse=True)
def _no_outside_network(request):
    start = len(_BLOCKED)
    yield
    attempts = _BLOCKED[start:]
    del _BLOCKED[start:]
    if attempts and request.node.get_closest_marker("expects_blocked_network") is None:
        pytest.fail("outside network attempted (blocked): " + "; ".join(attempts[:5]))


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
