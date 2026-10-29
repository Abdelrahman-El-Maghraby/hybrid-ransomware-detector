"""4.8 alert delivery (PR-08, S-03, F4; I-4): the persistent outbox, canary trips
on the alert outputs, metadata-only e-mail over verified TLS (directly on the
desktop, through the intel service in Docker), and no secret anywhere."""

import json
import logging
import os
import socket
import ssl
import threading
import time
from types import SimpleNamespace

import pytest

import RansomwareScanner as RS
from core import outbox as OB
from core.canary import CanaryFinding, CanaryReport
from core.mailer import (
    EMAIL_FIELDS,
    MailError,
    RateLimited,
    SmtpMailer,
    build_message,
    clean_text,
    validate_fields,
)
from engine.metrics import METRICS
from engine.validation import ConfigError, check_config, validate_config
from tests.test_scanner_integration import _config

PASSWORD = "SMTP-SECRET-pw-7f3a9c"
MARKER = "MARKER-CONTENT-must-not-leave"


def _result(verdict="High", name="Invoice.pdf", score=72, sha="ab" * 32, when="2026-10-29 10:00:00"):
    return {"schema_version": "1.3", "engine_version": "4.8.0", "scan_time": when,
            "file_path": f"/home/u/Downloads/{name}", "file_name": name, "sha256_hash": sha,
            "verdict": verdict, "risk_score": score, "scan_status": "complete",
            "score_breakdown": {"contributions": [
                {"indicator": "macro_autoexec", "points": 40, "detail": MARKER},
                {"indicator": "yara_match", "points": 20, "detail": "x"}]}}


class Receiver:
    """A webhook or mail receiver that is down until switched on."""

    def __init__(self, up=False):
        self.up, self.got = up, []

    def __call__(self, payload):
        if not self.up:
            raise ConnectionError("receiver down")
        self.got.append(payload)


@pytest.fixture
def clock():
    now = [1_000_000.0]
    return now


def _box(tmp_path, clock, hours=24):
    return OB.Outbox(str(tmp_path / "outbox"), hours, clock=lambda: clock[0])


# ------------------------------------------------------------------ I-4: the outbox
def test_an_alert_queued_while_the_receiver_is_down_arrives_once_it_is_back(tmp_path, clock):
    box, hook, mail = _box(tmp_path, clock), Receiver(), Receiver()
    alert = OB.verdict_alert(_result())
    assert box.enqueue(alert, ["webhook", "email"])
    assert box.flush({"webhook": hook, "email": mail}) == {"sent": 0, "retry": 2, "expired": 0,
                                                          "waiting": 0}
    assert box.flush({"webhook": hook, "email": mail})["waiting"] == 2   # backoff: not yet
    hook.up = mail.up = True
    clock[0] += OB.FIRST_RETRY_SECONDS + 1
    assert box.flush({"webhook": hook, "email": mail})["sent"] == 2
    assert len(hook.got) == len(mail.got) == 1 and hook.got[0]["alert_id"] == alert["id"]
    assert not list(box.pending.glob("*.json"))
    assert not box.enqueue(alert, ["webhook", "email"])                   # no duplicate
    clock[0] += 10_000
    assert box.flush({"webhook": hook, "email": mail})["sent"] == 0
    assert len(hook.got) == 1


def test_backoff_grows_and_one_channel_does_not_hold_back_the_other(tmp_path, clock):
    box, hook, mail = _box(tmp_path, clock), Receiver(up=True), Receiver()
    box.enqueue(OB.verdict_alert(_result()), ["webhook", "email"])
    box.flush({"webhook": hook, "email": mail})
    assert len(hook.got) == 1                                 # delivered at once
    pauses = []
    for _ in range(4):
        entry = json.loads(next(box.pending.glob("*.json")).read_text())
        pauses.append(entry["channels"]["email"]["next"] - clock[0])
        clock[0] = entry["channels"]["email"]["next"] + 0.1
        box.flush({"webhook": hook, "email": mail})
    assert pauses == sorted(pauses) and pauses[1] == 2 * pauses[0]
    assert "webhook" not in json.loads(next(box.pending.glob("*.json")).read_text())["channels"]


def test_an_alert_too_old_is_dropped_logged_and_counted(tmp_path, clock, caplog):
    box = _box(tmp_path, clock, hours=1)
    box.enqueue(OB.verdict_alert(_result()), ["webhook"])
    box.flush({"webhook": Receiver()})
    before = METRICS.snapshot()["alerts"].get("webhook_expired", 0)
    clock[0] += 3_601
    with caplog.at_level(logging.ERROR, logger="RansomwareScanner"):
        assert box.flush({"webhook": Receiver(up=True)})["expired"] == 1
    assert any(getattr(r, "event", "") == "alert_expired" for r in caplog.records)
    assert "receiver down" in caplog.text
    assert METRICS.snapshot()["alerts"]["webhook_expired"] == before + 1
    assert not list(box.pending.glob("*.json"))


def test_outbox_files_hold_metadata_only_and_are_private(tmp_path, clock):
    box = _box(tmp_path, clock)
    box.enqueue(OB.verdict_alert(_result()), ["email"])
    [path] = box.pending.glob("*.json")
    entry = json.loads(path.read_text())
    assert set(entry) == {"id", "kind", "created", "channels", "email"}
    validate_fields(entry["email"])
    assert MARKER not in path.read_text() and "/home/u" not in path.read_text()
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        assert box.pending.stat().st_mode & 0o777 == 0o700


def test_status_reports_pending_alerts_and_the_last_error(tmp_path, clock):
    box = _box(tmp_path, clock)
    box.enqueue(OB.verdict_alert(_result()), ["webhook"])
    box.flush({"webhook": Receiver()})
    assert box.status() == {"pending": 1, "channels": {"webhook": {
        "pending": 1, "last_error": "ConnectionError: receiver down"}}}


def test_channels_follow_each_minimum_verdict_and_canaries_always_alert():
    cfg = {"webhook_url": "https://siem.example/hook", "webhook_min_verdict": "High",
           "alert_email_min_verdict": "Critical"}
    assert OB.channels_for(OB.verdict_alert(_result("Medium")), cfg, True) == []
    assert OB.channels_for(OB.verdict_alert(_result("High")), cfg, True) == ["webhook"]
    assert OB.channels_for(OB.verdict_alert(_result("Critical")), cfg, True) == ["webhook", "email"]
    report = CanaryReport(deployed=2, findings=[CanaryFinding("/c/a.docx", "modified", "x")],
                          checked_at="2026-10-29 10:00:00")
    assert OB.channels_for(OB.canary_alert(report), cfg, True) == ["webhook", "email"]
    assert OB.channels_for(OB.canary_alert(report), cfg, False) == ["webhook"]


def test_the_webhook_payload_keeps_its_fields_and_gains_the_alert_id():
    from core.outputs import alert_payload
    r = _result()
    alert = OB.verdict_alert(r)
    assert alert["webhook"] == dict(alert_payload(r), alert_id=alert["id"], kind="verdict")
    assert OB.verdict_alert(dict(r))["id"] == alert["id"]                # stable id
    assert OB.verdict_alert(_result(when="2026-10-29 11:00:00"))["id"] != alert["id"]


def test_deliver_sends_signed_webhooks_through_the_outbox(tmp_path, monkeypatch):
    import hashlib
    import hmac

    from core.outputs import deliver
    posts, up = [], [False]

    def post(url, data=None, headers=None, timeout=None):
        if not up[0]:
            raise ConnectionError("refused")
        posts.append((url, data, headers))
        return SimpleNamespace(status_code=204)
    monkeypatch.setattr("requests.post", post)
    cfg = _config(tmp_path, webhook_url="https://siem.example/hook", webhook_secret="s3cret",
                  webhook_min_verdict="High", outbox_dir=str(tmp_path / "outbox"),
                  jsonl_path=str(tmp_path / "out.jsonl"))
    deliver([_result("High"), _result("Low", name="b.pdf")], cfg)
    assert posts == [] and (tmp_path / "out.jsonl").read_text().count("\n") == 2
    up[0] = True
    for f in (tmp_path / "outbox" / "pending").glob("*.json"):     # due now
        entry = json.loads(f.read_text())
        entry["channels"]["webhook"]["next"] = 0
        f.write_text(json.dumps(entry))
    assert OB.flush_pending(cfg)["sent"] == 1
    url, body, headers = posts[0]
    assert url == "https://siem.example/hook" and json.loads(body)["verdict"] == "High"
    expected = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert headers["X-Aegis-Signature"] == expected
    deliver([_result("High")], cfg)                       # the same result again: no duplicate
    assert len(posts) == 1


# ------------------------------------------------------------------ canaries (PR-08, S-03)
def _tripped():
    return CanaryReport(deployed=3, intact=2, checked_at="2026-10-29 10:00:00",
                        findings=[CanaryFinding("/data/canary_q3.docx", "encrypted", "entropy")])


def test_a_canary_trip_reaches_the_webhook(tmp_path, monkeypatch):
    s = RS.RansomwareScanner(_config(tmp_path, webhook_url="https://siem.example/hook",
                                     outbox_dir=str(tmp_path / "outbox")))
    monkeypatch.setattr(s.canaries, "verify", _tripped)
    sent = []
    monkeypatch.setattr("core.outputs.post_alert", lambda payload, url, secret="": sent.append(payload))
    s.check_canaries(notify=False)
    assert [p["kind"] for p in sent] == ["canary"] and sent[0]["verdict"] == "Critical"
    assert sent[0]["findings"] == [{"path": "/data/canary_q3.docx", "status": "encrypted"}]
    s.check_canaries(notify=False)                        # the same trip: no second alert
    assert len(sent) == 1


def test_s03_concurrent_canary_checks_alert_once(tmp_path, monkeypatch):
    """S-03: two checks racing on the same new trip alert once. Not confirmed on
    CPython with the GIL (the comparison and the assignment of the signature run
    with no call in between, so no thread switch happens there; 0 duplicates in
    3,000 trials of 8 threads with a 1 microsecond switch interval), so no lock
    was added (plan: "a lock if confirmed"). This test keeps it that way."""
    s = RS.RansomwareScanner(_config(tmp_path))
    gate = threading.Barrier(2)

    def slow_verify():
        try:
            gate.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
        time.sleep(0.2)
        return _tripped()
    monkeypatch.setattr(s.canaries, "verify", slow_verify)
    alerts = []
    monkeypatch.setattr(s, "_canary_alert", lambda report, touched, notify: alerts.append(report))
    threads = [threading.Thread(target=s.check_canaries, kwargs={"notify": False}) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(alerts) == 1


# ------------------------------------------------------------------ e-mail
class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout=None, context=None, starttls=True, fail=None):
        self.host, self.port, self.context, self.calls = host, port, context, []
        self.offers_starttls, self.fail = starttls, fail
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return self.offers_starttls

    def starttls(self, context=None):
        self.calls.append("starttls")
        self.context = context

    def login(self, user, password):
        self.calls.append(("login", user))
        if self.fail == "auth":
            import smtplib
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials")

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.calls.append(("send", msg, from_addr, to_addrs))


def _mail_config(**over):
    cfg = {"smtp_host": "smtp.example.org", "smtp_security": "tls", "smtp_port": 465,
           "smtp_user": "alerts", "smtp_password": PASSWORD, "alert_email_from": "aegis@example.org",
           "alert_email_to": "soc@example.org, oncall@example.org"}
    cfg.update(over)
    return cfg


def _mailer(cfg, **fake):
    FakeSMTP.instances = []
    make = lambda *a, **k: FakeSMTP(*a, **{**k, **fake})
    return SmtpMailer(cfg, smtp=make, smtp_ssl=make)


def test_implicit_tls_sends_metadata_only_to_the_configured_recipients():
    m = _mailer(_mail_config())
    fields = OB.verdict_alert(_result())["email"]
    m.send(fields)
    [smtp] = FakeSMTP.instances
    assert (smtp.host, smtp.port) == ("smtp.example.org", 465)
    assert smtp.context.verify_mode == ssl.CERT_REQUIRED and smtp.context.check_hostname
    _, msg, sender, to = smtp.calls[-1]
    assert sender == "aegis@example.org" and to == ["soc@example.org", "oncall@example.org"]
    text = msg.as_string()
    assert "High" in text and fields["sha256"] in text and "macro_autoexec" in text
    assert MARKER not in text and "/home/u" not in text and PASSWORD not in text
    assert not msg.is_multipart() and msg["X-Aegis-Alert-Id"] == fields["alert_id"]


def test_starttls_is_required_and_never_falls_back_to_plaintext():
    m = _mailer(_mail_config(smtp_security="starttls", smtp_port=587))
    m.send(OB.verdict_alert(_result())["email"])
    calls = FakeSMTP.instances[0].calls
    assert calls.index("starttls") < calls.index(("login", "alerts"))
    assert FakeSMTP.instances[0].context.verify_mode == ssl.CERT_REQUIRED
    m = _mailer(_mail_config(smtp_security="starttls", smtp_port=587), starttls=False)
    with pytest.raises(MailError, match="does not offer STARTTLS"):
        m.send(OB.verdict_alert(_result(when="t2"))["email"])
    assert not any(isinstance(c, tuple) for c in FakeSMTP.instances[0].calls)   # no login/send
    with pytest.raises(MailError, match="no plaintext"):
        SmtpMailer(_mail_config(smtp_security="none"))


def test_a_hostile_file_name_cannot_inject_headers_or_reorder_text():
    name = "Invoice\r\nBcc: attacker@evil.example‮gpj.exe\x00" + "A" * 300
    fields = OB.verdict_alert(_result(name=name))["email"]
    assert "\n" not in fields["file_name"] and "‮" not in fields["file_name"]
    assert len(fields["file_name"]) <= 120
    msg = build_message(fields, "aegis@example.org", ["soc@example.org"])
    assert msg["Bcc"] is None and "\r\nBcc" not in msg["Subject"]
    assert clean_text("a\r\nb\tc‏d", 50) == "a b cd"


@pytest.mark.parametrize("change", [
    {"to": "attacker@evil.example"}, {"body": "free text"}, {"attachments": []},
    {"verdict": "Catastrophic"}, {"kind": "other"}, {"alert_id": "x"}, {"sha256": "zz"},
    {"file_name": "a\nb"}, {"reason_codes": ["Not A Code"]}, {"reason_codes": ["a"] * 9},
    {"risk_band": "high"}, {"scan_id": 5}, {"time": ""},
])
def test_only_the_fixed_fields_are_accepted(change):
    fields = dict(OB.verdict_alert(_result())["email"], **change)
    with pytest.raises(ValueError):
        validate_fields(fields)
    assert set(EMAIL_FIELDS) == {"alert_id", "kind", "verdict", "risk_band", "sha256",
                                 "file_name", "time", "scan_id", "reason_codes"}


def test_hourly_and_daily_caps():
    now = [0.0]
    m = SmtpMailer(_mail_config(alert_email_per_hour=2, alert_email_per_day=3),
                   smtp_ssl=lambda *a, **k: FakeSMTP(*a, **k), clock=lambda: now[0])
    sends = [OB.verdict_alert(_result(when=f"t{i}"))["email"] for i in range(5)]
    m.send(sends[0])
    m.send(sends[1])
    with pytest.raises(RateLimited):
        m.send(sends[2])
    now[0] += 3_601
    m.send(sends[2])
    with pytest.raises(RateLimited):                       # 3 in the last day
        m.send(sends[3])
    now[0] += 86_401
    m.send(sends[3])


def test_errors_never_carry_the_password(caplog, tmp_path, clock):
    m = _mailer(_mail_config(), fail="auth")
    box = _box(tmp_path, clock)
    box.enqueue(OB.verdict_alert(_result()), ["email"])
    with caplog.at_level(logging.DEBUG):
        box.flush({"email": m.send})
    text = caplog.text + "".join(p.read_text() for p in box.pending.glob("*.json"))
    assert "SMTPAuthenticationError" in text and PASSWORD not in text


def _self_signed(tmp_path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    return tmp_path / "c.pem", tmp_path / "k.pem"


def test_a_server_certificate_that_does_not_verify_is_refused(tmp_path):
    """A real TLS handshake against a local server with an untrusted certificate:
    nothing is sent (the verification is not just configured, it is enforced)."""
    cert, key = _self_signed(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    got = []

    def serve():
        conn, _ = listener.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.sendall(b"220 localhost ESMTP\r\n")
                got.append(tls.recv(100))
        except (ssl.SSLError, OSError):
            pass
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    m = SmtpMailer(_mail_config(smtp_host="localhost", smtp_port=port))
    with pytest.raises(MailError, match="SSL|Certificate|certificate"):
        m.send(OB.verdict_alert(_result())["email"])
    t.join(5)
    listener.close()
    assert got == []


# ------------------------------------------------------------------ the intel operation (Docker)
@pytest.fixture
def intel_mail(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from api.intel import IntelService, create_intel_app
    from tests.test_intel_service import TOKEN, _intel_config

    def build(configured=True, fail=None):
        extra = _mail_config() if configured else {}
        service = IntelService(_intel_config(tmp_path, **extra))
        sent = []
        if service.mailer is not None:
            def send(fields):
                if fail:
                    raise fail
                sent.append(fields)
            service.mailer.send = send
        api = TestClient(create_intel_app(token=TOKEN, service=service))
        return api, service, sent, {"Authorization": f"Bearer {TOKEN}"}
    return build


def test_intel_sends_validated_alerts_once(intel_mail):
    api, service, sent, auth = intel_mail()
    fields = OB.verdict_alert(_result())["email"]
    caps = api.get("/v1/capabilities", headers=auth).json()
    assert caps["email"] == {"enabled": True}
    assert "smtp.example.org" not in json.dumps(caps) and "soc@" not in json.dumps(caps)
    assert api.post("/v1/alert/email", json=fields).status_code == 401
    r = api.post("/v1/alert/email", headers=auth, json=fields)
    assert r.status_code == 200 and r.json() == {"sent": True, "duplicate": False}
    r = api.post("/v1/alert/email", headers=auth, json=fields)
    assert r.json() == {"sent": False, "duplicate": True} and len(sent) == 1
    for bad in (dict(fields, to="attacker@evil.example"), dict(fields, body="x"),
                {k: v for k, v in fields.items() if k != "verdict"}, [fields],
                dict(fields, file_name="a\r\nBcc: x")):
        assert api.post("/v1/alert/email", headers=auth, json=bad).status_code == 422
    assert len(sent) == 1
    assert service.destinations["email"] == ["smtp://smtp.example.org:465 (tls)"]


def test_intel_without_smtp_settings_refuses_and_reports_it_off(intel_mail):
    api, _, _, auth = intel_mail(configured=False)
    assert api.get("/v1/capabilities", headers=auth).json()["email"] == {"enabled": False}
    fields = OB.verdict_alert(_result())["email"]
    assert api.post("/v1/alert/email", headers=auth, json=fields).status_code == 403


def test_intel_reports_smtp_failures_and_caps_so_the_outbox_retries(intel_mail):
    api, _, _, auth = intel_mail(fail=MailError("SMTPServerDisconnected from smtp"))
    fields = OB.verdict_alert(_result())["email"]
    assert api.post("/v1/alert/email", headers=auth, json=fields).status_code == 502
    api, _, _, auth = intel_mail(fail=RateLimited("cap"))
    r = api.post("/v1/alert/email", headers=auth, json=fields)
    assert r.status_code == 429 and r.headers["retry-after"] == "300"


def test_the_analysis_side_hands_e_mail_to_intel(tmp_path, monkeypatch):
    sent = []
    fake = SimpleNamespace(service=lambda name: {"enabled": name == "email"},
                           alert_email=sent.append)
    monkeypatch.setattr("core.intel_client.client_from_config", lambda cfg: fake)
    cfg = _config(tmp_path, intel_socket="/run/aegis/intel/intel.sock",
                  outbox_dir=str(tmp_path / "outbox"), alert_email_min_verdict="High")
    senders = OB.senders_for(cfg)
    assert senders["email"] == fake.alert_email and senders["webhook"] is None
    OB.queue_and_send([OB.verdict_alert(_result("Critical"))], cfg)
    assert len(sent) == 1 and validate_fields(sent[0])


def test_the_api_queues_e_mail_alerts_without_webhooks(monkeypatch):
    pytest.importorskip("fastapi")
    from api.server import _Alerts
    calls = []
    monkeypatch.setattr("core.outbox.queue_and_send", lambda alerts, cfg: calls.append((alerts, cfg)))
    monkeypatch.setattr("threading.Thread.start", lambda self: self.run())
    monkeypatch.setattr("api.server._Alerts._retry", lambda self: None)
    alerts = _Alerts({"intel_socket": "/x.sock", "webhook_url": "https://siem.example/hook"})
    alerts.submit(_result("Critical"))
    [(queued, cfg)] = calls
    assert queued[0]["kind"] == "verdict" and cfg["webhook_url"] == ""
    off = _Alerts({"webhook_url": "https://siem.example/hook"})
    off.submit(_result("Critical"))
    assert len(calls) == 1


# ------------------------------------------------------------------ settings (B3)
@pytest.mark.parametrize("change, message", [
    ({"alert_email_to": "soc@example.org"}, "SMTP_HOST is not"),
    ({"smtp_host": "smtp.example.org"}, "ALERT_EMAIL_FROM is not"),
    ({"smtp_host": "https://smtp.example.org/x", "alert_email_from": "a@example.org",
      "alert_email_to": "b@example.org"}, "must be a host name"),
    ({"smtp_host": "smtp.example.org", "alert_email_from": "not-an-address",
      "alert_email_to": "b@example.org"}, "ALERT_EMAIL_FROM='not-an-address'"),
    ({"smtp_host": "smtp.example.org", "alert_email_from": "a@example.org",
      "alert_email_to": "b@example.org, nope"}, "not e-mail addresses"),
    ({"smtp_security": "none"}, "SMTP_SECURITY='none' is not one of: tls, starttls"),
    ({"smtp_port": 70_000}, "SMTP_PORT=70000 is out of range"),
    ({"alert_email_per_day": 0}, "ALERT_EMAIL_PER_DAY=0 is out of range"),
    ({"outbox_max_age_hours": 0}, "OUTBOX_MAX_AGE_HOURS=0 is out of range"),
    ({"alert_email_min_verdict": "Severe"}, "ALERT_EMAIL_MIN_VERDICT"),
])
def test_e_mail_settings_are_validated(change, message):
    import engine.config as cfg_mod
    with pytest.raises(ConfigError) as info:
        check_config({**cfg_mod.CONFIG, **change}, env_problems=())
    assert message in str(info.value)


def test_the_analysis_side_may_not_hold_smtp_settings_in_production():
    import engine.config as cfg_mod
    cfg = {**cfg_mod.CONFIG, "intel_socket": "/x.sock", "intel_token": "t" * 40,
           "smtp_host": "smtp.example.org", "alert_email_from": "a@example.org",
           "alert_email_to": "b@example.org", "smtp_password": PASSWORD}
    errors, warnings = validate_config(cfg)
    assert any("SMTP_HOST" in w and "intel service only" in w for w in warnings)
    errors, _ = validate_config(dict(cfg, profile="production", llm_provider="none"))
    assert any("SMTP_PASSWORD" in e for e in errors)
    assert not any(PASSWORD in e for e in errors + warnings)


def test_smtp_password_comes_from_the_secret_store(monkeypatch, tmp_path):
    from engine import secret_store
    secret = tmp_path / "smtp_password"
    secret.write_text(PASSWORD + "\n")
    monkeypatch.setenv("SMTP_PASSWORD_FILE", str(secret))
    config = {}
    sources = secret_store.apply(config, backend=None)
    assert config["smtp_password"] == PASSWORD and sources["SMTP_PASSWORD"] == "environment"
