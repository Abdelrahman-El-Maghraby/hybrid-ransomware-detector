"""H6 option (a), owner-approved 2026-11-12: when a file's scan fails (time-out,
a dead worker, the memory limit or a scan error), a distinct "scan failed" notice
(kind `scan_failed`, `detection: false`) goes to every configured alert channel,
whatever the verdict floor. It is an incomplete scan, not a detection: the
result's verdict, score, scan_status and fields are unchanged, malware alerts are
unchanged, the same result never notifies twice, and e-mail goes through the same
outbox and caps. A file never scanned because no worker could start
(isolation_unavailable) gets no notice: it is reported as an error instead."""

import copy

import pytest

import RansomwareScanner as RS
from core import outbox as OB
from core.mailer import RateLimited, SmtpMailer, build_message, validate_fields
from core.outputs import deliver
from engine.workers import ISOLATION_TEXT, ISOLATION_UNAVAILABLE, failure_result
from tests.test_alerts import FakeSMTP, _mail_config, _result
from tests.test_incomplete_scan_alert import receiver  # noqa: F401  (fixture)
from tests.test_scanner_integration import _config
from tests.test_workers import _setup


def _cfg(scanner, tmp_path, **over):
    return dict(scanner.config, webhook_url="https://siem.example.invalid/hook",
                outbox_dir=str(tmp_path / "outbox"), jsonl_path="", **over)


@pytest.fixture
def plain(tmp_path):
    return RS.RansomwareScanner(_config(tmp_path))


def _failed(scanner, tmp_path, reason, **kw):
    p = tmp_path / "scan" / "f.pdf"
    p.write_bytes(b"%PDF-1.4 stand-in")
    return failure_result(scanner, str(p), reason, **kw)


def test_a_timeout_and_a_dead_worker_each_send_one_notice(tmp_path, receiver):
    """Real isolated workers: one file hangs past the limit, one kills its worker."""
    s = _setup(tmp_path, ["hang.pdf", "exit.pdf", "ok.pdf"], scan_timeout_seconds=4)
    results = s.scan_all_directories()
    before = copy.deepcopy(results)
    by = {r["file_name"]: r for r in results}
    deliver(results, _cfg(s, tmp_path))
    assert results == before                             # the results are not changed
    assert by["hang.pdf"]["verdict"] == "Medium" and by["exit.pdf"]["scan_status"] == "failed"
    got = {m["file_path"].rsplit("/", 1)[-1]: m for m in receiver}
    assert sorted(got) == ["exit.pdf", "hang.pdf"]       # none for the file that scanned
    assert all(m["kind"] == "scan_failed" and m["detection"] is False for m in receiver)
    assert "timed out after 4s" in got["hang.pdf"]["gaps"][0]["reason"]
    assert "died" in got["exit.pdf"]["gaps"][0]["reason"]
    assert OB.failed_alert(by["hang.pdf"])["email"]["reason_codes"] == ["scan_timed_out"]
    assert OB.failed_alert(by["exit.pdf"])["email"]["reason_codes"] == ["worker_died"]
    deliver(results, _cfg(s, tmp_path))                  # the same results again
    assert len(receiver) == 2


@pytest.mark.parametrize("reason,code", [
    ("timed out after 300s", "scan_timed_out"),
    ("the worker process died (exit code -9)", "worker_died"),
    ("MemoryError: the worker used 2100 MB, over the 2048 MB limit, and was stopped",
     "worker_memory_limit"),
    ("ValueError: bad table", "scan_error")])
def test_each_failure_is_named(plain, tmp_path, reason, code):
    r = _failed(plain, tmp_path, reason)
    notice = OB.failed_alert(r)
    assert notice["email"]["reason_codes"] == [code]
    assert notice["webhook"]["scan_status"] == "failed"
    assert notice["webhook"]["verdict"] == r["verdict"] == "Medium"
    assert notice["webhook"]["risk_score"] == r["risk_score"]


def test_a_file_never_scanned_for_lack_of_workers_sends_no_notice(plain, tmp_path):
    r = _failed(plain, tmp_path, ISOLATION_TEXT, code=ISOLATION_UNAVAILABLE,
                isolation="unavailable")
    assert OB.failed_alert(r) is None
    assert [a["kind"] for a in OB.results_alerts([r])] == ["verdict"]


def test_a_successful_scan_sends_no_notice(plain, tmp_path, receiver):
    (tmp_path / "scan" / "ok.txt").write_text("plain text")
    r = plain.scan_file(str(tmp_path / "scan" / "ok.txt"))
    assert r["scan_status"] == "complete" and "scan_failed" not in r["scan_results"]
    assert OB.failed_alert(r) is None
    deliver([r], _cfg(plain, tmp_path))
    assert receiver == []


def test_malware_alerts_are_unchanged(plain, tmp_path, receiver):
    r = _result("High")
    assert OB.failed_alert(r) is None
    deliver([r], _cfg(plain, tmp_path))
    assert [m["kind"] for m in receiver] == ["verdict"]
    assert "detection" not in receiver[0]


def test_a_medium_floor_also_sends_the_existing_verdict_alert(plain, tmp_path, receiver):
    """The verdict alert for a failed scan is not changed: under a Medium floor it is
    sent as before, and the notice beside it."""
    r = _failed(plain, tmp_path, "timed out after 300s")
    deliver([r], _cfg(plain, tmp_path, webhook_min_verdict="Medium"))
    assert sorted(m["kind"] for m in receiver) == ["scan_failed", "verdict"]


def test_it_goes_to_every_configured_channel_whatever_the_verdict_floor():
    cfg = {"webhook_url": "https://siem.example.invalid/hook", "webhook_min_verdict": "Critical",
           "alert_email_min_verdict": "Critical"}
    notice = {"kind": "scan_failed", "verdict": "Medium"}
    assert OB.channels_for(notice, cfg, email_available=True) == ["webhook", "email"]
    assert OB.channels_for({"kind": "verdict", "verdict": "Medium"}, cfg, True) == []


def test_the_email_says_it_is_an_incomplete_scan_not_a_detection(plain, tmp_path):
    fields = OB.failed_alert(_failed(plain, tmp_path, "timed out after 300s"))["email"]
    assert validate_fields(fields)["kind"] == "scan_failed"     # what intel accepts too
    msg = build_message(fields, "aegis@example.org", ["soc@example.org"])
    assert msg["Subject"].startswith("Aegis Sentinel notice: scan failed (not a detection)")
    body = msg.get_content()
    assert "This is an incomplete scan, not a malware" in body
    assert "raised an alert" not in body and "scan_timed_out" in body


def test_the_notice_respects_the_email_caps(plain, tmp_path):
    m = SmtpMailer(_mail_config(alert_email_per_hour=1),
                   smtp_ssl=lambda *a, **k: FakeSMTP(*a, **k))
    m.send(OB.verdict_alert(_result("High"))["email"])
    with pytest.raises(RateLimited):                     # the hourly cap applies to it
        m.send(OB.failed_alert(_failed(plain, tmp_path, "timed out after 300s"))["email"])


def test_the_api_submits_the_notice_by_email(plain, tmp_path, monkeypatch):
    """The API's alert queue sends e-mail only; the notice is among what it queues."""
    from api.server import _Alerts
    sent = []
    monkeypatch.setattr("core.outbox.queue_and_send", lambda alerts, cfg: sent.extend(alerts))
    monkeypatch.setattr("threading.Thread",
                        lambda target, args=(), **k: type("T", (), {
                            "start": lambda self: target(*args)})())
    q = _Alerts.__new__(_Alerts)
    q.enabled, q.config = True, {"webhook_url": ""}
    q.submit(_failed(plain, tmp_path, "the worker process died (exit code 3)"))
    assert [a["kind"] for a in sent] == ["verdict", "scan_failed"]
