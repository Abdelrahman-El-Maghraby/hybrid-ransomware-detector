"""v4.2: Outlook items attached to Outlook items are unpacked (as .eml) and
scanned with their own headers and attachments."""

import email
import email.policy
from pathlib import Path

import pytest

import RansomwareScanner as RS
from detectors.mail_analyzer import MSG_AVAILABLE, MailAnalyzer
from tests.msg_builder import build_msg, msg_tree
from tests.test_file_integrity import _pe_bytes
from tests.test_scanner_integration import _config, _indicators

pytestmark = pytest.mark.skipif(not MSG_AVAILABLE, reason="olefile not installed")

INNER_HEADERS = ("Authentication-Results: mx.corp.example; spf=fail; dkim=none; dmarc=fail\r\n"
                 'From: "billing@bank.example" <x@evil.example>\r\n'
                 "Subject: Your invoice\r\n")


def forwarded(tmp_path, inner_attachments=(("invoice.pdf", _pe_bytes(2048)),), depth=1):
    item = msg_tree(subject="Your invoice", transport_headers=INNER_HEADERS,
                    body="Please open the attached invoice.", attachments=inner_attachments)
    for level in range(depth - 1):
        item = msg_tree(subject=f"Fwd level {level + 2}", sender_name="Relay",
                        sender_email="relay@corp.example", attachments=(("FW", item),))
    return build_msg(tmp_path / "fwd.msg", subject="FW: Your invoice", sender_name="Colleague",
                     sender_email="colleague@corp.example", body="Is this legit?",
                     attachments=(("Your invoice", item), ("notes.txt", b"plain note")))


def test_embedded_item_becomes_an_eml_attachment(tmp_path):
    with MailAnalyzer().open(forwarded(tmp_path)) as res:
        assert res.attachments_skipped == 0
        names = [a.filename for a in res.attachments]
        assert names == ["Your invoice.eml", "notes.txt"]
        rebuilt = Path(res.attachments[0].path).read_bytes()
        inner = MailAnalyzer().analyze(res.attachments[0].path)
    msg = email.message_from_bytes(rebuilt, policy=email.policy.compat32)
    assert msg["Subject"] == "Your invoice"
    # The inner item keeps its own verdicts: its headers were rebuilt faithfully.
    assert inner.auth.failures == ["SPF", "DMARC"] and inner.display_name_spoof
    assert [a.filename for a in inner.attachments] == ["invoice.pdf"]
    assert inner.body_text == "Please open the attached invoice."


def test_nested_items_are_followed_but_bounded(tmp_path):
    with MailAnalyzer().open(forwarded(tmp_path, depth=5)) as res:
        rebuilt = Path(res.attachments[0].path).read_bytes()
    msg = email.message_from_bytes(rebuilt, policy=email.policy.compat32)
    subjects = []
    while msg is not None:
        subjects.append(msg["Subject"])
        inner = [p for p in msg.walk() if p.get_content_type() == "message/rfc822"]
        msg = inner[0].get_payload()[0] if inner else None
    # 5 levels were nested; rebuilding stops after 3 instead of recursing forever.
    assert subjects == ["Fwd level 5", "Fwd level 4", "Fwd level 3"]


def test_scanner_scores_the_forward_like_its_worst_attachment(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path))
    p = forwarded(tmp_path)
    r = s.scan_file(str(p))
    mail = r["scan_results"]["mail"]
    results = {a["name"].split("!/")[-1]: a for a in mail["attachment_results"]}
    assert results["Your invoice.eml"]["verdict"] in ("High", "Critical")
    assert "mail_attachment:mail_attachment:disguised_executable" in _indicators(r)
    assert r["verdict"] in ("High", "Critical")
