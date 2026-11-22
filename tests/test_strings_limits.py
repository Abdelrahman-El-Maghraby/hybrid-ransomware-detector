"""TX-1, printable strings: the strings pass (phrasing check and LLM) keeps its
32 MiB input and 200,000-character output limits, and now says when either one
left strings unchecked (scan_results.text_extraction.strings_not_checked, a
partial reason). Reaching a limit exactly, or only white space or no printable
run after it, is not an omission. The strings returned, scores and verdicts are
unchanged. The reasons also reach the top of nested containers.

All inputs are synthetic and inert, written under tmp_path.
"""

import base64
import io
import zipfile

import pytest

import RansomwareScanner as RS
from engine import text as text_mod
from engine.text import extract_suspicious_strings as strings
from tests.test_scanner_integration import _config

MIB = 1024 * 1024
BYTES_MAX = 32 * MIB
CHARS_MAX = 200_000


def _write(tmp_path, name, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _run(path, **kw):
    omitted = []
    return strings(path, omitted=omitted, **kw), omitted


def test_limits_are_unchanged():
    assert (text_mod.STRINGS_MAX_BYTES, text_mod.STRINGS_MAX_CHARS) == (BYTES_MAX, CHARS_MAX)


# ------------------------------------------------- output limit, 200,000 characters
@pytest.mark.parametrize("data, cut", [
    (b"a" * (CHARS_MAX - 1), False),
    (b"a" * CHARS_MAX, False),                             # exactly at the limit
    (b"a" * (CHARS_MAX + 1), True),
    (b"a" * 99_999 + b"\x00" + b"b" * 100_000, False),     # two strings, joined 200,000
    (b"a" * 99_999 + b"\x00" + b"b" * 100_000 + b"\x00", False),
    (b"a" * 99_999 + b"\x00" + b"b" * 100_000 + b"\x00cdefg", True),
    (b"a" * CHARS_MAX + b"\x00" + b" " * 40 + b"\x00", False),    # only spaces after
    (b"a" * CHARS_MAX + b"\x00\x01abc\x02", False),        # a run too short to count
], ids=["under", "exact", "over", "two-exact", "two-exact-nul", "two-then-more",
        "spaces-after", "short-run-after"])
def test_output_limit(tmp_path, data, cut):
    out, omitted = _run(_write(tmp_path, "s.bin", data))
    assert bool(omitted) is cut
    assert len(out) <= CHARS_MAX
    if cut:
        assert omitted == ["strings after the first 200,000 characters not checked"]


def test_output_is_the_same_text_as_before(tmp_path):
    # The earlier stop rule fixed what is returned; reading on to find an omission
    # must not add a separator or a white-space string to it.
    data = b"a" * (CHARS_MAX - 1) + b"\x00" + b" " * 10 + b"\x00" + b"zzzzz"
    out, omitted = _run(_write(tmp_path, "s.bin", data))
    assert out == "a" * (CHARS_MAX - 1) and omitted


# ------------------------------------------------------- input limit, 32 MiB
@pytest.mark.parametrize("head, tail, cut", [
    (b"\x00" * BYTES_MAX, b"", False),                     # exactly 32 MiB
    (b"\x00" * BYTES_MAX, b"\x00" * 64, False),            # no printable run after
    (b"\x00" * BYTES_MAX, b"\x00   \t   \x00", False),     # white space only
    (b"\x00" * BYTES_MAX, b"\x00ab\x00cd\x00", False),     # runs too short to count
    (b"\x00" * BYTES_MAX, b"\x00vssadmin delete shadows\x00", True),
    (b"\x00" * (BYTES_MAX - 3) + b"abc", b"de\x00", True),       # a run cut at the limit
    (b"\x00" * (BYTES_MAX - 5) + b"abcde", b"   \x00", False),   # its rest is spaces
], ids=["exact", "nul-tail", "space-tail", "short-runs", "string-after", "run-cut",
        "run-cut-spaces"])
def test_input_limit(tmp_path, head, tail, cut):
    out, omitted = _run(_write(tmp_path, "big.bin", head + tail))
    assert bool(omitted) is cut
    if cut:
        assert omitted == ["strings after the first 32 MiB of the file not checked"]
    if head.endswith(b"abc"):        # the read part of a cut run is too short to be a
        assert out == ""             # string (as before); its unread rest is the omission


@pytest.mark.parametrize("chunk", [1, 3, 7, 4096])
def test_input_limit_with_any_chunk_size(tmp_path, chunk):
    # small limits, many chunks: a run across the peek's own chunk boundaries
    # still counts, and the read part of a cut run does not
    path = _write(tmp_path, "c.bin", b"\x00" * 20 + b"xy" + b"   " + b"\x00")
    assert _run(path, max_bytes=20, chunk_size=chunk)[1]          # "xy   " unread
    assert not _run(path, max_bytes=22, chunk_size=chunk)[1]      # only spaces unread
    path = _write(tmp_path, "d.bin", b"\x00" * 18 + b"wxyz" + b"   \x00")
    assert not _run(path, max_bytes=22, chunk_size=chunk)[1]


def test_the_output_limit_is_named_first(tmp_path):
    data = b"a" * (CHARS_MAX + 10) + b"\x00" * 100 + b"tail string\x00"
    _, omitted = _run(_write(tmp_path, "o.bin", data), max_bytes=CHARS_MAX + 50)
    assert omitted == ["strings after the first 200,000 characters not checked"]


def test_omitted_is_optional(tmp_path):
    assert strings(_write(tmp_path, "x.bin", b"a" * (CHARS_MAX + 1))) == "a" * CHARS_MAX


# ---------------------------------------------------------------- scan results
@pytest.fixture
def scanner(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False, cache_enabled=False,
                                     max_nesting=4))
    yield s
    if s.cache is not None:
        s.cache.close()


def _strings_reasons(result):
    return [r for r in result["incomplete_reasons"]
            if r["layer"] == "prompt-guard" and r["reason"].startswith("strings after")]


def _binary(n_chars: int) -> bytes:
    """Inert data whose strings, joined, are exactly `n_chars` characters: one
    run of at least 60 then runs of 49, split by NULs (n_chars >= 60)."""
    m = max(0, (n_chars - 60) // 50)
    return b"y" * (n_chars - 50 * m) + (b"\x00" + b"x" * 49) * m


def test_a_file_over_the_strings_limit_is_partial(scanner, tmp_path, monkeypatch):
    path = _write(tmp_path, "data.bin", _binary(CHARS_MAX + 500))
    over = scanner.scan_file(path)
    assert over["scan_status"] == "partial"
    reasons = _strings_reasons(over)
    assert reasons and reasons[0]["member_path"] == over["file_path"]
    assert over["scan_results"]["text_extraction"]["strings_not_checked"].startswith(
        "strings after the first 200,000 characters")
    # Read with no limit: no reason, and the same score and verdict.
    monkeypatch.setattr(text_mod, "STRINGS_MAX_CHARS", 10 * CHARS_MAX)
    whole = scanner.scan_file(path)
    assert not _strings_reasons(whole) and whole["scan_status"] != "partial"
    assert (whole["risk_score"], whole["verdict"]) == (over["risk_score"], over["verdict"])


def test_a_file_at_the_strings_limit_is_complete(scanner, tmp_path):
    data = _binary(CHARS_MAX)
    assert len(strings(_write(tmp_path, "probe.bin", data))) == CHARS_MAX
    r = scanner.scan_file(_write(tmp_path, "edge.bin", data))
    assert not _strings_reasons(r) and r["scan_status"] != "partial"   # .bin: unsupported
    assert "text_extraction" not in r["scan_results"]


def test_input_limit_in_the_result(scanner, tmp_path, monkeypatch):
    monkeypatch.setattr(text_mod, "STRINGS_MAX_BYTES", 4096)
    r = scanner.scan_file(_write(tmp_path, "pad.bin", b"\x00" * 4096 + b"\x00later text\x00"))
    assert [x["reason"] for x in _strings_reasons(r)] == [
        "strings after the first 4,096 bytes of the file not checked"]
    r = scanner.scan_file(_write(tmp_path, "pad2.bin", b"\x00" * 4096 + b"\x00" * 50))
    assert not _strings_reasons(r)


def _eml(body: str, attachments=()) -> bytes:
    head = ("From: a@example.com\r\nTo: b@example.com\r\nSubject: notes\r\n"
            'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n'
            "--B\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n")
    parts = "".join(
        f'--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; '
        f'filename="{name}"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
        + base64.encodebytes(data).decode() for name, data in attachments)
    return (head + parts + "--B--\r\n").encode()


def _zip(members) -> bytes:
    buf = io.BytesIO()
    # stored, not deflated: the repetitive filler would trip the zip-bomb ratio guard
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


def test_strings_reasons_reach_the_top_through_nested_containers(scanner, tmp_path):
    """zip -> zip -> eml -> attachment: the attachment's strings reason, the
    message's own body reason and a member's reason all reach the top-level
    result with their member paths; members within the limits add nothing."""
    small = _binary(1000)
    eml = _eml("a" * (CHARS_MAX + 1), [("dump.bin", _binary(CHARS_MAX + 500)),
                                       ("ok.bin", small)])
    inner = _zip([("mail/m.eml", eml), ("inner-ok.bin", small)])
    outer = _zip([("level1/inner.zip", inner), ("big.bin", _binary(CHARS_MAX + 500)),
                  ("ok.bin", small)])
    r = scanner.scan_file(_write(tmp_path, "outer.zip", outer))
    assert r["scan_status"] == "partial"
    paths = {x["member_path"].split("!/", 1)[-1] for x in _strings_reasons(r)}
    assert "big.bin" in paths
    assert any(p.endswith("dump.bin") and "m.eml" in p for p in paths)
    assert not any(p.endswith("ok.bin") for p in paths)
    body = [x for x in r["incomplete_reasons"]
            if x["layer"] == "mail" and "message text after" in x["reason"]]
    assert body and body[0]["member_path"].endswith("mail/m.eml")


def test_nested_reasons_survive_an_isolated_worker(tmp_path):
    """The same reasons through a real scan worker (a separate process whose result
    comes back as JSON), as production scans run."""
    cfg = _config(tmp_path, cache_enabled=False, scan_workers=1, scan_timeout_seconds=120,
                  max_nesting=4, isolate_scans=True, file_extensions=[".zip"])
    small = _binary(1000)
    eml = _eml("a" * (CHARS_MAX + 1), [("dump.bin", _binary(CHARS_MAX + 500))])
    (tmp_path / "scan" / "box.zip").write_bytes(
        _zip([("inner.zip", _zip([("m.eml", eml), ("ok.bin", small)]))]))
    iso = RS.RansomwareScanner(cfg)
    (a,) = iso.scan_all_directories()
    seq = RS.RansomwareScanner(dict(cfg, isolate_scans=False))
    (b,) = seq.scan_all_directories()
    assert a["scan_status"] == b["scan_status"] == "partial"
    key = lambda res: sorted((x["member_path"].split("!/", 1)[-1], x["layer"], x["reason"])
                             for x in res["incomplete_reasons"])
    assert key(a) == key(b)
    assert any(p.endswith("dump.bin") for p, _, _ in key(a))
    assert any(p.endswith("m.eml") and layer == "mail" for p, layer, _ in key(a))
    for s in (iso, seq):
        if s.cache is not None:
            s.cache.close()
