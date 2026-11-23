"""H2: e-mail HTML is analysed in linear time with the same results as the
original regular expressions.

Before the fix, the link, display-domain, script/style and tag patterns
backtracked polynomially on crafted bodies: 5.2 KB of unclosed
``<a href='x'>y`` took about 2 s, and roughly 20 KB reached the 300 s worker
timeout, so the e-mail got a failed result instead of a verdict."""

import random
import re
import time

import pytest

from detectors import mail_analyzer as M
from detectors.mail_analyzer import MailAnalyzer, MailResult

# The exact patterns the analyser used before the change: the reference. M19
# (owner-approved 2026-11-12): the link reference takes the FIRST href of a tag
# that forms a complete link (lazy `[^>]*?`), as HTML keeps the first of
# duplicate attributes; the original greedy pattern took the last.
OLD_ANCHOR = re.compile(r"<a\b[^>]*?\bhref\s*=\s*([\"'])(.*?)\1[^>]*>(.*?)</a\s*>", re.I | re.S)
OLD_DOMAIN = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.I)
OLD_SCRIPT = re.compile(r"(?is)<(script|style)\b.*?</\1\s*>")
OLD_TAG = re.compile(r"<[^>]+>")

TOKENS = ['<a', '<A ', ' href=', ' HREF = ', 'data-href=', '"', "'", '>', '</a>', '</A >', 'x',
          'example.com', 'evil.org', 'login.bank.co.uk', ' ', '<', '.', 'a', '-', '_', '\n',
          '<script>', '</script>', '<style>', '</STYLE >', 'é', 'ab.', '<b>', '</b>', '<ſcript>',
          '</ſcript>', '<SCRİPT>', '</scrİpt >', '</scrıpt>', '</styles>', 'İ', 'ſ', 'K']

REAL_HTML = """<html><head><style>p { color: red }</style>
<script type="text/javascript">var a = "<a href='x'>no</a>";</script></head>
<body><p>Dear customer,</p>
<a href="https://evil.example.net/login" class="btn">www.mybank.com</a>
<A HREF='https://mybank.com/help'>Help at <b>mybank.com</b></A>
<a data-x="1" href = "https://t.co/abc" title="a > b">Track parcel</a >
<a name="top">no href</a>
<a href="https://news.example.org/a?b=c&amp;d=e">news.example.org.</a>
<a href="mailto:x@example.com">Contact</a></body></html>"""


def _old_judge(body):
    links = [(h, t) for _, h, t in OLD_ANCHOR.findall(body)]
    domains = []
    for _h, inner in links:
        m = OLD_DOMAIN.search(inner)
        domains.append(m.group(1) if m else "")
    return links, domains, OLD_TAG.sub(" ", OLD_SCRIPT.sub(" ", body))


def _new_judge(body):
    links = list(M._anchors(body))
    domains = [M._first_domain(inner) for _h, inner in links]
    return links, domains, M._strip_tags(M._strip_script_style(body), " ")


def test_realistic_html_gives_the_same_links_and_text():
    assert _new_judge(REAL_HTML) == _old_judge(REAL_HTML)
    assert len(_new_judge(REAL_HTML)[0]) == 6


def test_random_token_soup_matches_the_original_patterns():
    rng = random.Random(4801)
    for _ in range(20_000):
        body = "".join(rng.choice(TOKENS) for _ in range(rng.randint(0, 30)))
        assert _new_judge(body) == _old_judge(body), repr(body)
        m = OLD_DOMAIN.search(body)
        assert M._first_domain(body) == (m.group(1) if m else ""), repr(body)


def test_deceptive_link_findings_are_unchanged():
    res = MailResult()
    MailAnalyzer()._judge_body("", REAL_HTML, res)
    assert res.link_count == 6
    assert res.deceptive_links == [
        "text shows www.mybank.com -> link goes to evil.example.net"]
    assert "Dear customer" in res.body_text and "var a" not in res.body_text


@pytest.mark.parametrize("unit", [
    "<a href='x'>y", "<script>", "<style>", "a.", "<", "<a",
    "<a href=\"x' href='y'>", "<a href=\"x\">a.a.a.", "<ſcript>",
])
def test_hostile_html_is_analysed_in_linear_time(unit):
    body = unit * (1_000_000 // len(unit))           # ~1 MB; the old code needed hours
    start = time.perf_counter()
    MailAnalyzer()._judge_body("", body, MailResult())
    assert time.perf_counter() - start < 15


def test_a_second_href_does_not_hide_a_deceptive_first_one():
    """M19, review check 4 of section 29: the deceptive-link finding disappeared
    when a harmless second href followed the first."""
    two = '<a href="https://login.evil.example/x" href="https://paypal.com/">paypal.com</a>'
    one = '<a href="https://login.evil.example/x">paypal.com</a>'
    for body in (two, one):
        res = MailResult()
        MailAnalyzer()._judge_body("", "<html><body>" + body + "</body></html>", res)
        assert res.deceptive_links == [
            "text shows paypal.com -> link goes to login.evil.example"], body
    harmless_first = '<a href="https://paypal.com/" href="https://login.evil.example/x">paypal.com</a>'
    res = MailResult()
    MailAnalyzer()._judge_body("", harmless_first, res)
    assert res.deceptive_links == []                       # the browser follows the first
    assert list(M._anchors(two)) == [("https://login.evil.example/x", "paypal.com")]


def test_tags_with_several_hrefs_match_the_first_href_reference():
    """M19: token soup made of link parts only, so most tags carry several href
    attributes (the general soup above rarely does)."""
    parts = ["<a", " href=", ' HREF = ', '"', "'", ">", "</a>", "x", "evil.org", "example.com",
             " ", "a"]
    rng = random.Random(1912)
    for _ in range(20_000):
        body = "".join(rng.choice(parts) for _ in range(rng.randint(4, 24)))
        assert _new_judge(body)[0] == _old_judge(body)[0], repr(body)
