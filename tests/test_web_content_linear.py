"""H-04+ (owner-approved 2026-11-12): the web-content checks used patterns that
took quadratic (two of them cubic) time on crafted pages, and pages up to 20 MB
are read (2 MiB for the text layers). The checks now run in linear time and
must give exactly the results the old patterns gave, so detection does not
change. The old patterns are kept here as the reference."""

import random
import re
import time

import detectors.web_content as W

OLD_TAG = re.compile(r"<[^>]+>")
OLD_SMUGGLE_DOWNLOAD = re.compile(r"\.download\s*=|setattribute\s*\(\s*['\"]download['\"]|"
                                  r"<a\b[^>]*\bdownload\b", re.I)
OLD_DATA_DOWNLOAD_ANCHOR = re.compile(
    r"<a\b[^>]*(?:\bdownload\b[^>]*href\s*=\s*['\"]?\s*data:|href\s*=\s*['\"]?\s*data:[^>]*\bdownload\b)",
    re.I)
OLD_EVENT_HANDLER = re.compile(r"<[a-z][^>]*\son[a-z]{3,}\s*=", re.I)
OLD_META_REFRESH = re.compile(
    r"<meta[^>]+http-equiv\s*=\s*['\"]?refresh[^>]*url\s*=\s*['\"]?\s*(https?://[^\s'\">]+)", re.I)
OLD_PASSWORD_FIELD = re.compile(r"<input[^>]+type\s*=\s*['\"]?password", re.I)
OLD_FORM_ACTION = re.compile(r"<form[^>]+action\s*=\s*['\"]?(https?://[^\s'\">]+)", re.I)
OLD_JS_CONCAT = re.compile(rb"""["']\s*\+\s*(?:\r?\n\s*)?["']""")


def old_visible_text(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r"(?is)<(script|style)\b.*?</\1\s*>", " ", text)
    return re.sub(r"\s+", " ", OLD_TAG.sub(" ", text)).strip()


def old_and_new(text):
    first = OLD_FORM_ACTION.findall(text)
    return [
        (bool(OLD_SMUGGLE_DOWNLOAD.search(text)),
         bool(W._SMUGGLE_DOWNLOAD.search(text) or W._download_anchor(text))),
        (bool(OLD_DATA_DOWNLOAD_ANCHOR.search(text)), W._data_download_anchor(text)),
        (bool(OLD_EVENT_HANDLER.search(text)), W._event_handler(text)),
        ([m.group(1) for m in OLD_META_REFRESH.finditer(text)], W._meta_refresh_urls(text)),
        (bool(OLD_PASSWORD_FIELD.search(text)), W._password_field(text)),
        (first[0] if first else None, W._form_action(text)),
        (old_visible_text(text.encode("utf-8", "surrogatepass")),
         W.visible_text(text.encode("utf-8", "surrogatepass"))),
    ]


KNOWN = [
    '<a download href="data:application/zip;base64,UEsDBA==">x</a>',
    "<a href='data:x' download>", "<A HREF = ' data:x' DOWNLOAD>", "<a href=data:x>download</a>",
    "<a downloads href=data:x>", "<a href=data:xdownload>", "<abbr download href=data:x>",
    "<a download><a href=data:x>", "<a<a download", "<a href=x download>",
    '<svg onload="go()">', "<svg x onclick =1>", "<svg on=1>", "<svg onab=1>", "< svg onload=1>",
    "<\u017fvg onload=1>", "<\u212a onload=1>", "<svg\nonload=1>",
    '<meta http-equiv="refresh" content="0; url=https://evil.example/a">',
    "<meta http-equiv=refresh url=http://a url=http://b>", "<meta url=http://a http-equiv=refresh>",
    "<meta http-equiv=refresh content='0;URL=\"https://x\"'><meta http-equiv=refresh url=https://y>",
    "<meta http-equiv=refresh url=http://a/url=https://b>", "<metahttp-equiv=refresh url=http://a>",
    "<meta>http-equiv=refresh url=http://a", "<meta  http-equiv=refresh url = ' http://z'",
    '<input type="password"><form action="https://a.example/p">', "<input type=password>",
    "<inputtype=password>", "<input>type=password", "<form action=http://a action=https://b>",
    "<form action=http://a/action=https://b>", "<form>action=http://a", "<form x><form action=http://c>",
    "<script>x<a download</script><style>y</STYLE >z<p>t</p>", "<<>>", "<>", "<", "a > b < c",
    "<script>unclosed <a href=data:x download", "\u0130<SCRIPT>\u0131</script>",
]
PIECES = ["<a", "<A", " ", "\n", "<a ", "download", "DOWNLOAD", "downloads", "href", "=", "'",
          '"', "data:", "x", ">", "<", "<svg", "on", "onload", "onab", "\u017f", "\u212a",
          "<meta", "http-equiv", "refresh", "url", "URL", "http://", "https://", "a", "/",
          "<input", "type", "password", "<form", "action", "<script", "</script", "<style",
          "</style", "\t", "-", "_", "x=",
          # whole parts, so every check matches often
          "<a download", " href=data:", " href = ' data:", "<a href=data:", "<meta http-equiv=refresh",
          " http-equiv='refresh'", " url=http://", " url = \" https://", "<input type=password",
          " type=password", "<form action=http://", " action='https://", " onclick=", "<svg"]


def test_known_pages_give_the_old_results():
    for text in KNOWN:
        for old, new in old_and_new(text):
            assert old == new, (repr(text), old, new)


def test_random_pages_give_the_old_results():
    rng = random.Random(404)
    for _ in range(30000):
        text = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 14)))
        for old, new in old_and_new(text):
            assert old == new, (repr(text), old, new)


def test_js_concatenation_is_the_same_pattern():
    rng = random.Random(7)
    pieces = [b"'", b'"', b"+", b" ", b"\n", b"\r", b"\r\n", b"\t", b"a", b"\x0b"]
    for _ in range(20000):
        raw = b"".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        assert OLD_JS_CONCAT.sub(b"", raw) == W._JS_CONCAT.sub(b"", raw), raw


def test_crafted_pages_are_linear():
    """Each of these took seconds to hours before (the anchor and meta-refresh
    shapes grow with the cube of the length)."""
    n = 200_000
    shapes = ["<a download", "<a href=data:", "<meta http-equiv=refresh", "<", "<a ", "<x on",
              "<input", "<form action=http://a", "<meta url=http://a", "<script"]
    for unit in shapes:
        text = unit * (n // len(unit))
        start = time.perf_counter()
        old_and_new_fast(text)
        assert time.perf_counter() - start < 2.0, unit
    raw = b"'+" + b"\n" * n + b"x"
    start = time.perf_counter()
    W._JS_CONCAT.sub(b"", raw)
    assert time.perf_counter() - start < 0.5


def old_and_new_fast(text):
    """Only the new helpers (the old patterns would not finish)."""
    W._download_anchor(text), W._data_download_anchor(text), W._event_handler(text)
    W._meta_refresh_urls(text), W._password_field(text), W._form_action(text)
    W.visible_text(text.encode())
