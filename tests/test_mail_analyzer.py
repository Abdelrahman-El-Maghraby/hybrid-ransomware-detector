"""MailGuard: .eml and .msg parsing, sender authentication, spoofing,
deceptive links and attachment extraction."""

import hashlib
import os
from email.message import EmailMessage
from pathlib import Path

import pytest

from detectors.mail_analyzer import MSG_AVAILABLE, MailAnalyzer
from tests.msg_builder import build_msg

GOOD_AUTH = ("mx.corp.example; spf=pass smtp.mailfrom=vendor.example; "
             "dkim=pass header.d=vendor.example; dmarc=pass header.from=vendor.example")


def make_eml(path: Path, *, sender='"Vendor Billing" <billing@vendor.example>',
             subject="Monthly statement", body="Hello, your statement is attached.",
             html=None, auth=(GOOD_AUTH,), received_spf=None, reply_to=None,
             attachments=(), extra_headers=()) -> Path:
    msg = EmailMessage()
    for value in auth:                         # first = topmost (added by our server)
        msg["Authentication-Results"] = value
    if received_spf:
        msg["Received-SPF"] = received_spf
    msg["From"] = sender
    msg["To"] = "user@corp.example"
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    for k, v in extra_headers:
        msg[k] = v
    msg.set_content(body)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for name, data, maintype, subtype in attachments:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    path.write_bytes(msg.as_bytes())
    return path


def analyze(path, **kw):
    return MailAnalyzer(**kw).analyze(path)


# ------------------------------------------------------------------- basics
def test_clean_message_with_attachment(tmp_path):
    pdf = b"%PDF-1.4\n" + b"statement " * 200
    p = make_eml(tmp_path / "statement.eml",
                 attachments=[("statement.pdf", pdf, "application", "pdf")])
    analyzer = MailAnalyzer()
    with analyzer.open(p) as res:
        assert res.format == "eml" and res.error == ""
        assert res.from_address == "billing@vendor.example"
        assert res.from_domain == "vendor.example"
        assert res.auth.all_pass and res.auth.failures == []
        assert res.auth.authserv_id == "mx.corp.example"
        assert not (res.display_name_spoof or res.reply_to_mismatch or res.deceptive_links)
        assert res.lure_subject == []
        assert "statement is attached" in res.body_text
        [att] = res.attachments
        assert att.filename == "statement.pdf" and not att.executable
        assert att.sha256 == hashlib.sha256(pdf).hexdigest()
        saved = Path(att.path)
        assert saved.read_bytes() == pdf
        sandbox = saved.parent.parent
    assert not sandbox.exists()               # sandbox removed after the block


def test_analyze_does_not_leak_sandbox_paths(tmp_path):
    p = make_eml(tmp_path / "m.eml", attachments=[("a.txt", b"x", "text", "plain")])
    res = analyze(p)
    assert res.attachments and all(a.path is None for a in res.attachments)


def test_encoded_subject_is_decoded(tmp_path):
    p = make_eml(tmp_path / "m.eml", subject="فاتورة مستحقة - invoice overdue")
    res = analyze(p)
    assert res.subject == "فاتورة مستحقة - invoice overdue"
    assert "invoice/payment" in res.lure_subject


@pytest.mark.parametrize("subject,label", [
    ("URGENT: action required on your mailbox", "urgency"),
    ("Your account will be suspended today", "account threat"),
    ("Please verify your account password", "credential lure"),
    ("Your password expires in 2 days", "password expiry"),
    ("Parcel delivery failed - reschedule", "delivery lure"),
])
def test_lure_subjects(tmp_path, subject, label):
    assert label in analyze(make_eml(tmp_path / "m.eml", subject=subject)).lure_subject


# --------------------------------------------------------- authentication
def test_failed_authentication(tmp_path):
    p = make_eml(tmp_path / "m.eml", auth=(
        "mx.corp.example; spf=fail smtp.mailfrom=vendor.example; dkim=none; "
        "dmarc=fail header.from=vendor.example",))
    res = analyze(p)
    assert (res.auth.spf, res.auth.dkim, res.auth.dmarc) == ("fail", "none", "fail")
    assert res.auth.failures == ["SPF", "DMARC"]


def test_forged_lower_auth_header_is_ignored(tmp_path):
    # The attacker wrote "all pass" into their own message; our server's
    # (topmost) verdict says otherwise and must win.
    p = make_eml(tmp_path / "m.eml", auth=(
        "mx.corp.example; spf=softfail smtp.mailfrom=evil.example; dkim=none; dmarc=fail",
        GOOD_AUTH))
    res = analyze(p)
    assert res.auth.dmarc == "fail" and res.auth.spf == "softfail"
    assert res.auth.ignored_headers == 1


def test_one_valid_dkim_signature_is_enough(tmp_path):
    p = make_eml(tmp_path / "m.eml", auth=(
        "mx.corp.example; dkim=fail header.d=list.example; dkim=pass header.d=vendor.example; "
        "spf=pass; dmarc=pass",))
    assert analyze(p).auth.dkim == "pass"


def test_received_spf_fallback_and_missing_results(tmp_path):
    res = analyze(make_eml(tmp_path / "a.eml", auth=(),
                           received_spf="fail (domain does not designate 1.2.3.4)"))
    assert res.auth.spf == "fail" and res.auth.dmarc is None
    res = analyze(make_eml(tmp_path / "b.eml", auth=()))
    assert not res.auth.present and "no authentication results" in res.detail


# ----------------------------------------------------------------- spoofing
@pytest.mark.parametrize("sender,spoof", [
    ('"billing@paypal.com" <x@evil.example>', True),
    ('"PayPal (paypal.com)" <x@evil.example>', True),
    ('"PayPal Service" <x@evil.example>', False),             # brand name alone: not provable
    ('"alerts@paypal.com" <alerts@mail.paypal.com>', False),  # same organisation
    ('"News" <news@shop.co.uk>', False),
])
def test_display_name_spoof(tmp_path, sender, spoof):
    assert analyze(make_eml(tmp_path / "m.eml", sender=sender)).display_name_spoof is spoof


def test_reply_to_diversion(tmp_path):
    res = analyze(make_eml(tmp_path / "m.eml", reply_to="ceo.private@gmail-secure.example"))
    assert res.reply_to_mismatch and res.reply_to_domain == "gmail-secure.example"
    res = analyze(make_eml(tmp_path / "n.eml", reply_to="support@help.vendor.example"))
    assert not res.reply_to_mismatch


def test_deceptive_links(tmp_path):
    html = ('<p>Pay here: <a href="https://evil.example/pay">https://www.paypal.com/invoice</a></p>'
            '<p><a href="https://vendor.example/a">vendor.example/account</a></p>'
            '<p><a href="https://evil.example/x">Click here</a></p>')
    res = analyze(make_eml(tmp_path / "m.eml", html=html))
    assert res.link_count == 3
    assert res.deceptive_links == ["text shows www.paypal.com -> link goes to evil.example"]


# -------------------------------------------------------------- attachments
def test_risky_attachment_names(tmp_path):
    rtlo_name = "invoice‮fdp.exe"         # displays as "invoiceexe.pdf"
    p = make_eml(tmp_path / "m.eml", attachments=[
        ("invoice.pdf.exe", b"MZ" + b"\0" * 100, "application", "octet-stream"),
        (rtlo_name, b"MZ", "application", "octet-stream"),
        ("budget.xlsm", b"PK\x03\x04", "application", "vnd.ms-excel.sheet.macroEnabled.12"),
        ("photo.jpg", b"\xff\xd8\xff" + b"\0" * 50, "image", "jpeg"),
    ])
    res = analyze(p)
    assert res.double_extension_attachments == ["invoice.pdf.exe"]
    assert res.rtlo_attachments == ["invoice[RTLO]fdp.exe"]
    assert set(res.executable_attachments) == {"invoice.pdf.exe", "invoice[RTLO]fdp.exe",
                                               "budget.xlsm"}
    assert "photo.jpg" not in res.executable_attachments


def test_traversal_attachment_name_stays_in_sandbox(tmp_path):
    p = make_eml(tmp_path / "m.eml",
                 attachments=[("../../../.bashrc", b"echo pwned", "text", "plain")])
    with MailAnalyzer().open(p) as res:
        [att] = res.attachments
        saved = Path(att.path)
        sandbox = saved.parent.parent
        assert sandbox in saved.parents and saved.name == "bashrc"
    assert not (tmp_path / ".bashrc").exists()


def test_attached_message_is_extracted_once(tmp_path):
    inner = make_eml(tmp_path / "inner.eml",
                     attachments=[("payload.js", b"WScript.Shell", "text", "javascript")])
    outer = EmailMessage()
    outer["From"] = "a@vendor.example"
    outer["Subject"] = "Fwd: invoice"
    outer.set_content("see attached")
    outer.add_attachment(inner.read_bytes(), maintype="message", subtype="rfc822",
                         filename="original.eml")
    p = tmp_path / "outer.eml"
    p.write_bytes(outer.as_bytes())
    with MailAnalyzer().open(p) as res:
        assert [a.filename for a in res.attachments] == ["original.eml"]
        saved = Path(res.attachments[0].path).read_bytes()
        assert saved.startswith(b"Authentication-Results:")   # decoded, not base64
        # The inner message is a complete e-mail MailGuard can open again.
        inner_res = MailAnalyzer().analyze(res.attachments[0].path)
    assert inner_res.executable_attachments == ["payload.js"]


def test_attachment_limits(tmp_path):
    atts = [(f"f{i}.txt", b"data", "text", "plain") for i in range(5)]
    res = analyze(make_eml(tmp_path / "m.eml", attachments=atts), max_attachments=3)
    assert len(res.attachments) == 3 and res.attachments_skipped == 2
    big = [("big.bin", os.urandom(4096), "application", "octet-stream")] * 2
    res = analyze(make_eml(tmp_path / "n.eml", attachments=big), max_total_bytes=5000)
    assert len(res.attachments) == 1 and res.attachments_skipped == 1


def test_oversized_and_garbage_input_never_raise(tmp_path):
    p = make_eml(tmp_path / "m.eml", body="x" * 5000)
    res = analyze(p, max_message_bytes=1000)
    assert "analysis limit" in res.error and res.attachments == []
    g = tmp_path / "garbage.eml"
    g.write_bytes(os.urandom(3000))
    res = analyze(g)                           # parses as a header-less blob
    assert res.is_mail and res.attachments == [] or res.error


# ---------------------------------------------------------------------- MSG
needs_msg = pytest.mark.skipif(not MSG_AVAILABLE, reason="olefile not installed")
HEADERS = ("Received: from mail.evil.example by mx.corp.example\r\n"
           "Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=evil.example; "
           "dkim=none; dmarc=fail header.from=paypal.com\r\n"
           'From: "billing@paypal.com" <x@evil.example>\r\n'
           "Reply-To: refunds@evil-pay.example\r\n"
           "Subject: URGENT: invoice overdue\r\n")


@needs_msg
def test_msg_full_parse(tmp_path):
    big = os.urandom(9000)                   # > 4096 bytes: regular sectors
    p = build_msg(tmp_path / "lure.msg", subject="URGENT: invoice overdue",
                  sender_name="billing@paypal.com", sender_email="x@evil.example",
                  transport_headers=HEADERS, body="Please pay today.",
                  html='<a href="http://evil.example/x">https://paypal.com/login</a>',
                  attachments=(("invoice.pdf.exe", b"MZ" + b"\0" * 700), ("blob.bin", big)))
    with MailAnalyzer().open(p) as res:
        assert res.format == "msg" and res.error == ""
        assert res.subject == "URGENT: invoice overdue"
        assert res.from_address == "x@evil.example"
        assert res.auth.failures == ["SPF", "DMARC"]
        assert res.display_name_spoof and res.reply_to_mismatch
        assert res.deceptive_links and res.body_text == "Please pay today."
        assert res.double_extension_attachments == ["invoice.pdf.exe"]
        blob = next(a for a in res.attachments if a.filename == "blob.bin")
        assert Path(blob.path).read_bytes() == big


@needs_msg
def test_msg_without_transport_headers_uses_mapi_properties(tmp_path):
    p = build_msg(tmp_path / "draft.msg", subject="Quarterly numbers",
                  sender_name="Finance Team", sender_email="finance@corp.example",
                  body="Numbers attached.", attachments=(("q3.csv", b"a,b\n1,2\n"),))
    res = analyze(p)
    assert res.subject == "Quarterly numbers"
    assert res.from_address == "finance@corp.example"
    assert not res.auth.present and not res.display_name_spoof
    assert [a.filename for a in res.attachments] == ["q3.csv"]


@needs_msg
def test_msg_exchange_dn_sender_is_not_an_address(tmp_path):
    p = build_msg(tmp_path / "x.msg", subject="hi", sender_name="Bob",
                  sender_email="/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP/CN=RECIPIENTS/CN=BOB")
    res = analyze(p)
    assert res.from_address == "" and res.from_domain == ""


def test_plain_text_saved_as_msg_is_parsed_as_eml(tmp_path):
    src = make_eml(tmp_path / "m.eml", subject="Payment overdue")
    p = tmp_path / "saved.msg"
    p.write_bytes(src.read_bytes())
    res = analyze(p)
    assert res.format == "eml" and res.subject == "Payment overdue"


@needs_msg
def test_corrupt_msg_never_raises(tmp_path):
    p = tmp_path / "broken.msg"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + os.urandom(2000))
    res = analyze(p)
    assert res.error and res.attachments == []
