"""core/mailbox.py: IMAP scanning against an in-memory server. Checks that the
folder is opened read-only, bodies are fetched with PEEK, nothing is scanned
twice, large messages are skipped and results carry the mailbox location."""

import json

import pytest

import RansomwareScanner as RS
from core.mailbox import ImapSettings, MailboxError, MailboxScanner
from tests.test_file_integrity import _pe_bytes
from tests.test_mail_analyzer import make_eml
from tests.test_scanner_integration import _config


class FakeImap:
    """Just enough of imaplib.IMAP4 for MailboxScanner."""

    def __init__(self, messages, validity=7, password="app-pass"):
        self.messages = dict(messages)          # uid -> raw bytes
        self.validity = validity
        self.password = password
        self.calls = []
        self.logged_out = False

    def login(self, user, password):
        import imaplib
        if password != self.password:
            raise imaplib.IMAP4.error("AUTHENTICATIONFAILED")
        return "OK", [b"logged in"]

    def select(self, folder, readonly=False):
        self.calls.append(("select", folder, readonly))
        return "OK", [str(len(self.messages)).encode()]

    def response(self, code):
        return code, [str(self.validity).encode()]

    def uid(self, command, *args):
        self.calls.append(("uid", command) + args)
        if command == "SEARCH":
            criteria = args[1:]
            uids = sorted(self.messages)
            if criteria[0].startswith("UID "):
                lo = int(criteria[0].split()[1].split(":")[0])
                uids = [u for u in uids if u >= lo] or [max(self.messages)]   # like a real server
            return "OK", [" ".join(map(str, uids)).encode()]
        if command == "FETCH":
            uid, what = int(args[0]), args[1]
            raw = self.messages[uid]
            if what == "(RFC822.SIZE)":
                return "OK", [f"1 (UID {uid} RFC822.SIZE {len(raw)})".encode()]
            assert what == "(BODY.PEEK[])"
            return "OK", [(f"1 (UID {uid} BODY[] {{{len(raw)}}}".encode(), raw), b")"]
        raise AssertionError(command)

    def logout(self):
        self.logged_out = True


def _messages(tmp_path):
    clean, bad = tmp_path / "clean.eml", tmp_path / "bad.eml"
    make_eml(clean, subject="Lunch on Thursday")
    make_eml(bad, subject="URGENT invoice overdue", sender='"billing@bank.example" <x@evil.example>',
             attachments=[("Remittance.pdf", _pe_bytes(4096), "application", "pdf")])
    return {101: clean.read_bytes(), 102: bad.read_bytes()}


@pytest.fixture
def setup(tmp_path):
    cfg = _config(tmp_path, cache_enabled=False, isolate_scans=False)
    scanner = RS.RansomwareScanner(cfg)
    settings = ImapSettings(host="imap.example", user="me@example", password="app-pass",
                            state_path=str(tmp_path / "imap_state.json"))
    return scanner, settings, tmp_path


def test_scans_new_messages_read_only_and_labels_them(setup):
    scanner, settings, tmp_path = setup
    imap = FakeImap(_messages(tmp_path))
    run = MailboxScanner(scanner, settings, connect=lambda s: imap).run()

    assert ("select", '"INBOX"', True) in imap.calls                 # EXAMINE, never SELECT
    assert all(c[3] in ("(RFC822.SIZE)", "(BODY.PEEK[])") for c in imap.calls if c[1] == "FETCH")
    assert imap.logged_out and run.new_messages == 2
    by_uid = {r["mailbox"]["uid"]: r for r in run.results}
    assert by_uid[101]["verdict"] == "Clean"
    assert by_uid[102]["verdict"] in ("High", "Critical")
    assert by_uid[102]["file_path"] == "imap://me@example@imap.example/INBOX;UID=102"
    state = json.loads((tmp_path / "imap_state.json").read_text())
    assert state[settings.key] == {"uidvalidity": 7, "last_uid": 102}


def test_nothing_is_scanned_twice_until_uidvalidity_changes(setup):
    scanner, settings, tmp_path = setup
    msgs = _messages(tmp_path)
    MailboxScanner(scanner, settings, connect=lambda s: FakeImap(msgs)).run()
    again = MailboxScanner(scanner, settings, connect=lambda s: FakeImap(msgs)).run()
    assert again.results == [] and again.new_messages == 0
    msgs[103] = msgs[101]
    third = MailboxScanner(scanner, settings, connect=lambda s: FakeImap(msgs)).run()
    assert [r["mailbox"]["uid"] for r in third.results] == [103]
    reset = MailboxScanner(scanner, settings, connect=lambda s: FakeImap(msgs, validity=8)).run()
    assert len(reset.results) == 3                                   # new UID space: rescan


def test_limits_and_errors(setup):
    scanner, settings, tmp_path = setup
    msgs = _messages(tmp_path)
    settings.max_bytes = min(len(m) for m in msgs.values()) + 1      # only the small one fits
    settings.max_messages = 5
    run = MailboxScanner(scanner, settings, connect=lambda s: FakeImap(msgs)).run()
    assert len(run.results) == 1 and len(run.skipped_too_large) == 1

    settings.max_bytes, settings.max_messages = 25 * 1024 * 1024, 1
    settings.state_path = str(tmp_path / "other_state.json")
    capped = MailboxScanner(scanner, settings, connect=lambda s: FakeImap(msgs)).run()
    assert len(capped.results) == 1 and capped.more_waiting

    with pytest.raises(MailboxError, match="login failed"):
        MailboxScanner(scanner, settings,
                       connect=lambda s: FakeImap(msgs, password="other")).run()

    def refuse(_):
        raise OSError("connection refused")
    with pytest.raises(MailboxError, match="cannot connect"):
        MailboxScanner(scanner, settings, connect=refuse).run()


def test_settings_from_config_need_host_and_user(tmp_path):
    with pytest.raises(MailboxError):
        ImapSettings.from_config({"imap_host": "", "imap_user": ""})
    s = ImapSettings.from_config({"imap_host": "h", "imap_user": "u", "imap_password": "s3cret-app-pw",
                                  "imap_max_mb": 2, "imap_folder": "Junk"})
    assert s.max_bytes == 2 * 1024 * 1024 and s.folder == "Junk" and "s3cret" not in repr(s)
