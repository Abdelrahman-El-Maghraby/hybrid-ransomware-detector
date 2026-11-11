"""M22: the mail and embedded-content paths of PROJECT_REVIEW check 3 run in
linear time and give the same results as before.

Before the fix: a "Password" label, then a long white-space run, took 2.8 s at
16 KB; a dotted display name 7.5 s at 32 KB; the `.bat` type guess 6.2 s on a
16 KB block of newlines (every OneNote and MSI block is guessed); a
`charset=punycode` body grew quadratically."""

import random
import re
import time
from email.message import Message

import pytest

from detectors import embedded_content as E
from detectors import mail_analyzer as M

# The exact patterns used before the change: the reference.
OLD_PASSWORD_RX = re.compile(
    r"(?:^|[\s(\[])(?:" + M._PASSWORD_LABELS + r")(?:\s+(?:is|ist|est|es|é))?\s*[:=：\-–]?\s*"
    r"[\"'“«‘]?([^\s\"'”»’<>]{3,40})", re.I | re.M)
OLD_DOMAIN_IN_TEXT = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.I)
OLD_SCRIPT_GUESS = (
    (".hta", re.compile(rb"<hta:application", re.I)),
    (".wsf", re.compile(rb"<job\b[^>]*>|<script\s+language\s*=\s*[\"']?(?:vbscript|jscript)", re.I)),
    (".ps1", re.compile(rb"\$[a-z_]\w*\s*=|invoke-|new-object\s|-encodedcommand|\[convert\]::", re.I)),
    (".vbs", re.compile(rb"createobject\s*\(|wscript\.|\bdim\s+\w+|\bsub\s+\w+\s*\(", re.I)),
    (".bat", re.compile(rb"^\s*@?echo\s+off|^\s*(?:set|start|call|goto)\s", re.I | re.M)),
    (".js", re.compile(rb"activexobject|\bvar\s+\w+\s*=|function\s*\w*\s*\(", re.I)),
)

PW_TOKENS = ["pw", "PW", "Password", "passwort", "пароль", "code", " ", "  ", "\n", "\t", ":",
             "=", "：", "-", "–", " is ", " ist", "\"", "'", "«", "abc", "Inv2024!", "x", "(",
             "[", "<", ".", "4471", "é"]
DOMAIN_TOKENS = ["a", "b.", "x-y", ".", "-", "com", "co.uk", " ", "Bank", "1", "é", "@", "\"",
                 "paypal.com", "evil", ".org", "..", "a.b.c"]
GUESS_TOKENS = [b"<job", b"<JOB id=1", b">", b"<script language=", b"vbscript", b"'", b"\"",
                b"function", b"FUNCTION", b"func", b"tion", b"(", b" ", b"\n", b"\r", b"\t",
                b"foo", b"_", b"1", b"var ", b"=", b"echo off", b"@", b"set ", b"goto",
                b"$a =", b"invoke-", b"dim x", b"sub s(", b"wscript.", b"<hta:application",
                b"activexobject", b"\x00"]


def _old_passwords(*texts, limit=5):
    found = []
    for text in texts:
        for m in OLD_PASSWORD_RX.finditer(text or ""):
            token = m.group(1)
            for cand in (token, token.rstrip(".,;:!?)]")):
                if (3 <= len(cand) <= 32 and cand.lower() not in M._NOT_PASSWORDS
                        and cand not in found):
                    found.append(cand)
            if len(found) >= limit:
                return found[:limit]
    return found


def _old_display_spoof(display, from_domain):
    display = (display or "").strip().strip('"')
    if not display or not from_domain:
        return ""
    if "@" in display:
        return M._display_name_spoof(display, from_domain)       # unchanged branch
    m = OLD_DOMAIN_IN_TEXT.search(display)
    if m and "." in m.group(1) and not M._same_org(m.group(1).lower(), from_domain):
        return f"display name shows {m.group(1).lower()} but the mail is from {from_domain}"
    return ""


def _old_guess(data):
    head = data[:65536]
    if head.count(b"\x00") > len(head) // 20:
        return ".bin"
    for ext, rx in OLD_SCRIPT_GUESS:
        if rx.search(head):
            return ext
    return ".txt"


def test_password_pattern_matches_the_original():
    rng = random.Random(4831)
    found = 0
    for _ in range(30_000):
        text = "".join(rng.choice(PW_TOKENS) for _ in range(rng.randint(0, 20)))
        assert ([m.span(1) for m in M._PASSWORD_RX.finditer(text)]
                == [m.span(1) for m in OLD_PASSWORD_RX.finditer(text)]), repr(text)
        assert M.archive_passwords(text) == _old_passwords(text), repr(text)
        found += bool(_old_passwords(text))
    assert found > 1_000


def test_display_name_check_matches_the_original():
    rng = random.Random(4832)
    for _ in range(30_000):
        display = "".join(rng.choice(DOMAIN_TOKENS) for _ in range(rng.randint(0, 15)))
        assert M._display_name_spoof(display, "corp.example") == \
            _old_display_spoof(display, "corp.example"), repr(display)
    assert "evil.org" in M._display_name_spoof("Support evil.org", "corp.example")


def test_type_guess_matches_the_original():
    rng = random.Random(4833)
    seen = set()
    for _ in range(30_000):
        data = b"".join(rng.choice(GUESS_TOKENS) for _ in range(rng.randint(0, 20)))
        assert E._guess_text_extension(data) == _old_guess(data), repr(data)
        seen.add(_old_guess(data))
    assert seen == {".hta", ".wsf", ".ps1", ".vbs", ".bat", ".js", ".txt", ".bin"}


def test_punycode_body_is_read_as_utf8():
    part = Message()
    part["Content-Type"] = "text/plain; charset=punycode"
    part.set_payload(b"Password: Inv2024")
    assert M._decode_text(part) == "Password: Inv2024"
    part.replace_header("Content-Type", "text/plain; charset=windows-1256")
    part.set_payload("كلمة".encode("cp1256"))
    assert M._decode_text(part) == "كلمة"           # real charsets are unchanged


def _timed(fn, *args, limit=5.0):
    start = time.perf_counter()
    fn(*args)
    assert time.perf_counter() - start < limit


@pytest.mark.parametrize("gap", [" ", "\n"])
def test_hostile_password_label_is_linear(gap):
    _timed(M.archive_passwords, "pw" + gap * 200_000 + "ab", "pw" + gap * 200_000 + "ab")


def test_hostile_display_name_is_linear():
    _timed(M._display_name_spoof, "a." * 100_000 + "1", "corp.example")


def test_hostile_punycode_body_is_linear():
    part = Message()
    part["Content-Type"] = "text/plain; charset=punycode"
    part.set_payload(b"a" * 2_400_000)
    _timed(M._decode_text, part)


@pytest.mark.parametrize("block", [b"\n" * 65536, b"function" * 8192, b"<job" * 16384,
                                   b"Function " * 7000 + b"x", b"\r\n " * 20000])
def test_hostile_embedded_blocks_are_linear(block):
    _timed(E._guess_text_extension, block, limit=2.0)
