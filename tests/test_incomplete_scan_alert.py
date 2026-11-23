"""L-D7 option (ii), owner-approved 2026-11-11 (with the owner's correction: both
limits): when CHM content is left unread because of the 1,000-page read limit or
the 25-member limit, a distinct "incomplete scan" notification
(kind `incomplete_scan`) goes to the configured alert channels. It is not a
detection: the result's risk score, verdict, scan_status and fields are
unchanged, malware alerts are unchanged, the same result never notifies twice,
and e-mail goes through the same outbox and caps. The 7-Zip calls are stand-ins."""

import copy
import json

import pytest

from core import outbox as OB
from core.mailer import SmtpMailer, build_message, validate_fields
from core.outputs import deliver
from tests.test_alerts import FakeSMTP, _mail_config, _result
from tests.test_chm_read_cap import chm  # noqa: F401  (fixture)
from tests.test_scanner_integration import scanner  # noqa: F401  (fixture)


@pytest.fixture
def receiver(monkeypatch):
    got = []

    class Ok:
        status_code = 200

    def post(url, data=None, **k):
        got.append(json.loads(data))
        return Ok()
    monkeypatch.setattr("requests.post", post)
    return got


def _cfg(scanner, tmp_path):
    return dict(scanner.config, webhook_url="https://siem.example.invalid/hook",
                outbox_dir=str(tmp_path / "outbox"), jsonl_path="")


def _scan(scanner, chm, pages, shortcut_at=None):
    install, _ = chm
    scanner.embedded_analyzer.sevenzip = lambda: "7z"
    return scanner.scan_file(str(install(pages, shortcut_at=shortcut_at)))


def test_pages_over_the_read_limit_send_one_incomplete_scan_notice(scanner, chm, tmp_path,
                                                                   receiver):
    r = _scan(scanner, chm, 1001, shortcut_at=1001)
    before = copy.deepcopy(r)
    deliver([r], _cfg(scanner, tmp_path))
    assert r == before                                   # the result is not changed
    assert [m["kind"] for m in receiver] == ["incomplete_scan"]
    notice = receiver[0]
    assert notice["detection"] is False and notice["verdict"] == "Clean"
    assert notice["scan_status"] == "partial" and notice["risk_score"] == 0
    assert any("help pages not read (read limit 1000)" in g["reason"] for g in notice["gaps"])
    deliver([r], _cfg(scanner, tmp_path))                # the same result again
    assert len(receiver) == 1


def test_a_fully_read_help_file_sends_nothing(scanner, chm, tmp_path, receiver):
    r = _scan(scanner, chm, 20)
    assert r["verdict"] == "Clean" and r["scan_status"] == "complete"
    deliver([r], _cfg(scanner, tmp_path))
    assert receiver == []


@pytest.mark.parametrize("reason", ["not unpacked: member limit",
                                    "not unpacked: x.exe: member limit reached"])
def test_other_partial_scans_send_no_notice(reason):
    """An archive's limit, or the member limit of a OneNote, MSI or XLL file."""
    r = dict(_result("Clean", score=0), scan_status="partial",
             incomplete_reasons=[{"member_path": "a.one", "layer": "embedded",
                                  "reason": reason, "status": "partial"}])
    assert OB.incomplete_alert(r) is None


def test_pages_over_the_member_limit_send_the_notice_too(scanner, chm, tmp_path, receiver):
    r = _scan(scanner, chm, 30)                          # all read; 5 over the 25 members
    assert r["verdict"] == "Clean" and r["scan_status"] == "partial"
    deliver([r], _cfg(scanner, tmp_path))
    assert [m["kind"] for m in receiver] == ["incomplete_scan"]
    assert OB.incomplete_alert(r)["email"]["reason_codes"] == ["chm_members_not_scanned"]
    assert all("member limit reached (help file)" in g["reason"] for g in receiver[0]["gaps"])


def test_a_detection_and_a_gap_send_both_the_alert_and_the_notice(scanner, chm, tmp_path,
                                                                 receiver):
    r = _scan(scanner, chm, 30, shortcut_at=3)
    assert r["verdict"] == "High"
    deliver([r], _cfg(scanner, tmp_path))
    assert sorted(m["kind"] for m in receiver) == ["incomplete_scan", "verdict"]


def test_malware_alerts_are_unchanged(scanner, chm, tmp_path, receiver):
    r = _scan(scanner, chm, 20, shortcut_at=20)              # ShortCut read: High
    assert r["verdict"] == "High"
    deliver([r], _cfg(scanner, tmp_path))
    assert [m["kind"] for m in receiver] == ["verdict"]
    assert OB.verdict_alert(r)["webhook"]["kind"] == "verdict"
    assert "detection" not in receiver[0]


def test_the_email_says_it_is_not_a_detection_and_existing_emails_are_unchanged(scanner, chm):
    r = _scan(scanner, chm, 1001, shortcut_at=1001)
    fields = OB.incomplete_alert(r)["email"]
    assert validate_fields(fields)["kind"] == "incomplete_scan"   # what intel accepts too
    assert fields["reason_codes"] == ["chm_pages_not_read", "chm_members_not_scanned"]
    msg = build_message(fields, "aegis@example.org", ["soc@example.org"])
    assert msg["Subject"].startswith("Aegis Sentinel notice: incomplete scan (not a detection)")
    body = msg.get_content()
    assert "This is not a malware detection" in body and "raised an alert" not in body
    verdict = build_message(OB.verdict_alert(_result("High"))["email"],
                            "aegis@example.org", ["soc@example.org"])
    assert verdict.get_content().startswith("Aegis Sentinel raised an alert.")
    assert verdict["Subject"].startswith("Aegis Sentinel alert: High")


def test_the_notice_respects_the_email_caps(scanner, chm, tmp_path):
    r = _scan(scanner, chm, 1001, shortcut_at=1001)
    m = SmtpMailer(_mail_config(alert_email_per_hour=1),
                   smtp_ssl=lambda *a, **k: FakeSMTP(*a, **k))
    m.send(OB.verdict_alert(_result("High"))["email"])
    from core.mailer import RateLimited
    with pytest.raises(RateLimited):                     # the hourly cap applies to it
        m.send(OB.incomplete_alert(r)["email"])


def test_it_goes_to_every_configured_channel_whatever_the_verdict_floor():
    notice = {"kind": "incomplete_scan", "verdict": "Clean"}
    cfg = {"webhook_url": "https://siem.example.invalid/hook", "webhook_min_verdict": "Critical",
           "alert_email_min_verdict": "Critical"}
    assert OB.channels_for(notice, cfg, email_available=True) == ["webhook", "email"]
    assert OB.channels_for({"kind": "verdict", "verdict": "Clean"}, cfg, True) == []
