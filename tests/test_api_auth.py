"""4.7: API authentication throttling. Before, buckets were keyed on IP + token, so
rotating wrong tokens gave a fresh bucket every time. Now: a per-IP limit before
authentication, a failed-attempt lockout per IP checked before the compare, and the
per-token quota only for valid tokens."""


import pytest

from api.limits import AuthGuard, client_ip
from engine.metrics import METRICS
from tests.helpers import wait_for
from tests.test_scanner_integration import _config

TOKEN = "a" * 32


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_guard_locks_after_threshold_within_window():
    c = Clock()
    g = AuthGuard(threshold=3, window=60, lockout=300, clock=c)
    assert g.failure("1.1.1.1") == 0 and g.failure("1.1.1.1") == 0
    assert g.locked_for("1.1.1.1") == 0
    assert g.failure("1.1.1.1") == 300                    # the third one locks
    assert g.locked_for("1.1.1.1") == 300 and g.locked_for("2.2.2.2") == 0
    c.t += 299
    assert g.locked_for("1.1.1.1") == 1
    c.t += 2
    assert g.locked_for("1.1.1.1") == 0


def test_guard_window_and_success():
    c = Clock()
    g = AuthGuard(threshold=3, window=60, lockout=300, clock=c)
    g.failure("ip")
    g.failure("ip")
    c.t += 61                                             # the old failures expire
    assert g.failure("ip") == 0 and g.locked_for("ip") == 0
    g.success("ip")                                       # a valid token clears the count
    g.failure("ip")
    g.failure("ip")
    assert g.locked_for("ip") == 0


def test_guard_table_is_bounded():
    g = AuthGuard(threshold=5, clock=Clock(), max_clients=3)
    for i in range(10):
        g.failure(f"10.0.0.{i}")
    assert len(g._state) == 3


def test_client_ip_and_proxy():
    scope = {"client": ("10.0.0.5", 1), "headers": [(b"x-forwarded-for", b"1.2.3.4, 10.0.0.1")]}
    assert client_ip(scope, False) == "10.0.0.5" and client_ip(scope, True) == "10.0.0.1"


def test_spoofed_forwarded_for_cannot_escape_the_lockout():
    """A proxy that appends (nginx $proxy_add_x_forwarded_for) keeps what the client
    sent; only the entry the proxy added counts."""
    def scope(spoofed):
        return {"client": ("172.18.0.2", 1),
                "headers": [(b"x-forwarded-for", f"{spoofed}, 198.51.100.7".encode())]}
    g = AuthGuard(threshold=3, clock=Clock())
    for i in range(3):
        g.failure(client_ip(scope(f"203.0.113.{i}"), True))
    assert g.locked_for(client_ip(scope("203.0.113.99"), True)) > 0
    assert client_ip({"client": None, "headers": [(b"x-forwarded-for", b" 198.51.100.7 ")]},
                     True) == "198.51.100.7"                      # Unix socket peer: no address


@pytest.fixture
def make_api(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from api.server import create_app

    def build(**env):
        defaults = {"AEGIS_API_IP_RATE_PER_MINUTE": "6000", "AEGIS_API_IP_BURST": "1000",
                    "AEGIS_API_RATE_PER_MINUTE": "6000", "AEGIS_API_BURST": "1000",
                    "AEGIS_API_AUTH_FAILURES": "3", "AEGIS_API_AUTH_WINDOW_SECONDS": "60",
                    "AEGIS_API_AUTH_LOCKOUT_SECONDS": "900", "AEGIS_API_TRUST_PROXY": "1"}
        for k, v in {**defaults, **env}.items():
            monkeypatch.setenv(k, v)
        return TestClient(create_app(_config(tmp_path), token=TOKEN, isolate=False))
    return build


def _get(api, path="/version", token=None, ip="203.0.113.7"):
    headers = {"X-Forwarded-For": ip}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return api.get(path, headers=headers)


def test_rotating_wrong_tokens_locks_the_address(make_api):
    METRICS.reset()
    api = make_api()
    codes = [_get(api, token=f"wrong-token-number-{i:04d}").status_code for i in range(3)]
    assert codes == [401, 401, 401]
    r = _get(api, token="yet-another-wrong-token-0000")
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 800
    # locked out before the compare: even the right token is refused from there ...
    assert _get(api, token=TOKEN).status_code == 429
    # ... while other addresses are unaffected
    assert _get(api, token=TOKEN, ip="198.51.100.2").status_code == 200
    rejected = METRICS.snapshot()["requests_rejected"]
    assert rejected["auth_failed"] == 3 and rejected["auth_locked"] == 2


def test_lockout_expires(make_api):
    api = make_api(AEGIS_API_AUTH_FAILURES="2", AEGIS_API_AUTH_LOCKOUT_SECONDS="1")
    _get(api, token="wrong-token-aaaaaaaaaaaa")
    _get(api, token="wrong-token-bbbbbbbbbbbb")
    assert _get(api, token=TOKEN).status_code == 429
    assert wait_for(lambda: _get(api, token=TOKEN).status_code == 200, step=0.2)  # S-T1


def test_missing_token_counts_as_a_failure(make_api):
    api = make_api()
    assert [_get(api).status_code for _ in range(4)] == [401, 401, 401, 429]


def test_per_ip_limit_applies_before_authentication(make_api):
    METRICS.reset()
    api = make_api(AEGIS_API_IP_RATE_PER_MINUTE="60", AEGIS_API_IP_BURST="3",
                   AEGIS_API_AUTH_FAILURES="1000")
    codes = [_get(api, token=f"rotating-wrong-token-{i:04d}").status_code for i in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    assert _get(api, token=TOKEN).status_code == 429      # the address is over its limit
    assert all(_get(api, "/health").status_code == 200 for _ in range(5))   # liveness is exempt
    assert METRICS.snapshot()["requests_rejected"]["rate_limited"] >= 3


def test_valid_token_keeps_its_quota(make_api):
    api = make_api(AEGIS_API_RATE_PER_MINUTE="60", AEGIS_API_BURST="2")
    codes = [_get(api, token=TOKEN).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert _get(api, token=TOKEN).json()["detail"] == "too many requests"


def test_ready_cannot_be_used_to_guess_tokens(make_api):
    api = make_api()
    for i in range(3):
        r = _get(api, "/ready", token=f"guess-token-number-{i:04d}")
        assert set(r.json()) == {"ready"}                   # no details for a wrong token
    assert _get(api, "/ready", token=TOKEN).status_code == 429
    assert set(_get(api, "/ready").json()) == {"ready"}     # anonymous probes still answer


def test_token_can_come_from_a_secret_file(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from api.server import create_app
    from tests.test_scanner_integration import _config
    secret = tmp_path / "api_token"
    secret.write_text("s" * 32 + "\n")
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    monkeypatch.setenv("AEGIS_API_TOKEN_FILE", str(secret))
    from fastapi.testclient import TestClient
    api = TestClient(create_app(_config(tmp_path), isolate=False))
    assert api.get("/version", headers={"Authorization": "Bearer " + "s" * 32}).status_code == 200
    monkeypatch.setenv("AEGIS_API_TOKEN_FILE", str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match="AEGIS_API_TOKEN"):
        create_app(_config(tmp_path), isolate=False)


@pytest.mark.parametrize("module", ["api.server", "api.intel"])
@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "-5"])
def test_abuse_limit_settings_refuse_nan_inf_and_negative(monkeypatch, module, value):
    """nan made the lockout window and every rate limit pass silently (min(burst,
    nan) is burst; nan comparisons are false) and -1 MB answered every upload 413."""
    pytest.importorskip("fastapi")
    import importlib
    mod = importlib.import_module(module)
    monkeypatch.setenv("AEGIS_TEST_NUMBER", value)
    with pytest.raises(RuntimeError, match="AEGIS_TEST_NUMBER"):
        mod._env_number("AEGIS_TEST_NUMBER", 5)
    monkeypatch.setenv("AEGIS_TEST_NUMBER", "0")
    assert mod._env_number("AEGIS_TEST_NUMBER", 5) == 0          # 0 = no limit, as documented
    with pytest.raises(RuntimeError, match="above 0"):
        mod._env_number("AEGIS_TEST_NUMBER", 5, positive=True)
    monkeypatch.delenv("AEGIS_TEST_NUMBER")
    assert mod._env_number("AEGIS_TEST_NUMBER", 5) == 5


def test_lockout_settings_are_checked_when_the_app_is_built(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from api.server import create_app
    from tests.test_scanner_integration import _config
    monkeypatch.setenv("AEGIS_API_AUTH_WINDOW_SECONDS", "nan")
    with pytest.raises(RuntimeError, match="AEGIS_API_AUTH_WINDOW_SECONDS"):
        create_app(_config(tmp_path), token="t" * 32, isolate=False)


@pytest.mark.parametrize("problem", ["missing", "empty"])
def test_an_unreadable_token_file_does_not_fall_back_to_another_token(tmp_path, monkeypatch,
                                                                      problem):
    """A configured secret file that is missing or empty must stop the start, not
    quietly accept an older AEGIS_API_TOKEN from the environment or .env."""
    pytest.importorskip("fastapi")
    from api.server import create_app
    from tests.test_scanner_integration import _config
    secret = tmp_path / "api_token"
    if problem == "empty":
        secret.write_text("\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_API_TOKEN", "o" * 32)
    monkeypatch.setenv("AEGIS_API_TOKEN_FILE", str(secret))
    with pytest.raises(RuntimeError, match="AEGIS_API_TOKEN_FILE"):
        create_app(_config(tmp_path), isolate=False)


def test_a_used_spare_is_replaced_even_when_the_scan_raises(tmp_path, monkeypatch):
    """RV-S3: the refill ran only after a normal return; an exception from
    scan_isolated left one spare fewer for good. No realistic trigger was found;
    the exception is injected."""
    pytest.importorskip("fastapi")
    import api.server as server
    import engine.workers as workers
    from tests.test_scanner_integration import _config
    svc = server._ScanService.__new__(server._ScanService)
    svc.isolate, svc.config, svc.scanner = True, _config(tmp_path), None
    spare = object()
    refills = []
    monkeypatch.setattr(svc, "_take_spare", lambda: spare, raising=False)
    monkeypatch.setattr(svc, "_refill", lambda: refills.append(1), raising=False)

    def boom(*a, **k):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(workers, "scan_isolated", boom)
    with pytest.raises(RuntimeError):
        svc.scan(str(tmp_path / "x"), "x")
    assert refills == [1]


def test_a_stalled_upload_gives_up_its_slot(monkeypatch):
    """RV-S4: the slot is taken before the body is read (M4); an authenticated client
    that stopped sending held it for good (reproduced on loopback). The body must now
    arrive within AEGIS_API_UPLOAD_SECONDS."""
    pytest.importorskip("fastapi")
    import asyncio

    from fastapi import HTTPException

    import api.server as server
    monkeypatch.setattr(server, "UPLOAD_SECONDS", 0.2)

    class Stalled:
        async def form(self, **kwargs):
            await asyncio.sleep(30)
    with pytest.raises(HTTPException) as e:
        asyncio.run(server._scan_upload(Stalled(), None, None))
    assert e.value.status_code == 408


@pytest.mark.parametrize("setting", ["AEGIS_API_AUTH_WINDOW_SECONDS", "AEGIS_API_AUTH_LOCKOUT_SECONDS"])
def test_a_zero_lockout_setting_is_refused(tmp_path, monkeypatch, setting):
    """AR-2: 0 let every wrong token through without a lockout, like nan (L-E2)."""
    pytest.importorskip("fastapi")
    from api.server import create_app
    from tests.test_scanner_integration import _config
    monkeypatch.setenv(setting, "0")
    with pytest.raises(RuntimeError, match=f"{setting}='0' must be a finite number above 0; "
                                            r"remove it to use the default \(\d+\)"):
        create_app(_config(tmp_path), token="t" * 32, isolate=False)


@pytest.mark.parametrize("window,lockout", [("", ""), ("300", "900"), ("0.5", "1"), ("86400", "604800")])
def test_positive_lockout_settings_still_start(tmp_path, monkeypatch, window, lockout):
    """AR-2: only 0 (and nan, inf, negatives, as before) is refused."""
    pytest.importorskip("fastapi")
    from api.server import create_app
    from tests.test_scanner_integration import _config
    monkeypatch.setenv("AEGIS_API_AUTH_WINDOW_SECONDS", window)
    monkeypatch.setenv("AEGIS_API_AUTH_LOCKOUT_SECONDS", lockout)
    assert create_app(_config(tmp_path), token="t" * 32, isolate=False) is not None


def test_a_zero_lockout_setting_stops_the_server_with_its_message(monkeypatch):
    """What an operator with 0 in .env sees: one line, no traceback, no listener."""
    pytest.importorskip("fastapi")
    import api.server as srv
    monkeypatch.setattr("engine.config.init_runtime", lambda *a, **k: None)
    monkeypatch.setenv("AEGIS_API_AUTH_LOCKOUT_SECONDS", "0")
    monkeypatch.setenv("AEGIS_API_TOKEN", "t" * 32)
    monkeypatch.setattr(srv, "create_app", lambda: srv._Auth("t" * 32, False))
    with pytest.raises(SystemExit) as stop:
        srv.main()
    assert str(stop.value) == ("aegis-api: AEGIS_API_AUTH_LOCKOUT_SECONDS='0' must be a finite "
                               "number above 0; remove it to use the default (900)")
