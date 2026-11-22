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


@pytest.mark.parametrize("chunk", [1, 2, 3, 4, 5])
def test_a_run_cut_at_the_limit_with_tiny_chunks(tmp_path, chunk):
    # chunks shorter than a run: the read part of the cut run must still be the
    # bytes just before the limit (a slicing slip kept the wrong ones)
    cut = _write(tmp_path, "r.bin", b"\x00" * 17 + b"wxyz" + b"e\x00")   # "wxyz" read, "e" not
    assert _run(cut, max_bytes=21, chunk_size=chunk)[1]
    spaces = _write(tmp_path, "s.bin", b"\x00" * 15 + b"abcde" + b"   \x00")
    assert not _run(spaces, max_bytes=20, chunk_size=chunk)[1]         # only spaces unread
    mixed = _write(tmp_path, "m.bin", b"\x00" * 18 + b"ab" + b"   \x00")
    assert _run(mixed, max_bytes=20, chunk_size=chunk)[1] == []        # "ab" + spaces


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


# ------------------------------------------- TX-2b: bounded lookahead, no retention
LOOK = 32 * MIB


class _Counting:
    """A real file whose reads are counted (the bound is on bytes actually read)."""
    total = 0

    def __init__(self, path, mode):
        self.fh = open(path, mode)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.fh.close()

    def read(self, n=-1):
        data = self.fh.read(n)
        _Counting.total += len(data)
        return data

    def fileno(self):
        return self.fh.fileno()

    def tell(self):
        return self.fh.tell()


@pytest.fixture
def counted(monkeypatch):
    _Counting.total = 0
    monkeypatch.setattr(text_mod, "open", _Counting, raising=False)
    return _Counting


def test_lookahead_default_is_32_mib():
    assert text_mod.STRINGS_LOOKAHEAD_BYTES == LOOK


@pytest.mark.parametrize("rest, reason, read", [
    (b"\x00" * 40, None, 40),                            # ends inside the budget
    (b"\x00" * 64, None, 64),                            # ends exactly at the budget
    (b"\x00" * 65, "not inspected", 64),                 # one byte left: not inspected
    (b"\x00" * 59 + b"hello\x00", "not checked", 64),    # "hello" ends at the budget: found
    (b"\x00" * 60 + b"hello\x00", "not inspected", 64),  # cut by the budget: "hell" is short
    (b"\x00" * 58 + b"hello" + b"\x00" * 50, "not checked", 63),   # found: stops there
    (b"\x00" * 40 + b"     " + b"\x00" * 40, "not inspected", 64),  # spaces, then more bytes
    (b"\x00" * 10 + b"zz" * 3 + b"\x00" * 10, "not checked", 16),
], ids=["inside", "exact", "one-more", "run-ends-at-bound", "run-cut-by-bound",
        "found-inside", "spaces-then-more", "short-chunks"])
def test_lookahead_is_bounded(tmp_path, counted, rest, reason, read):
    """max_bytes 32, lookahead 64: never more than 96 bytes read in all."""
    head = b"\x00" * 32
    path = _write(tmp_path, "b.bin", head + rest)
    expected = strings(path, max_bytes=32)
    counted.total = 0
    out, omitted = _run(path, max_bytes=32, lookahead_bytes=64, chunk_size=7)
    assert out == expected                                 # extraction unchanged
    assert counted.total <= 32 + 64
    if reason is None:
        assert omitted == []
    else:
        assert len(omitted) == 1 and reason in omitted[0]
    if reason == "not inspected":
        assert omitted == ["file bytes after the first 96 bytes not inspected for strings"]
        assert counted.total == 32 + 64
    if reason == "not checked":
        assert counted.total < 32 + 64 or rest[:64].strip(b"\x00")


def test_run_ending_exactly_at_the_bound(tmp_path, counted):
    # "hello" occupies the last five bytes of the budget and the file ends there
    path = _write(tmp_path, "e.bin", b"\x00" * 32 + b"\x00" * 59 + b"hello")
    _, omitted = _run(path, max_bytes=32, lookahead_bytes=64)
    assert [o for o in omitted if "of the file not checked" in o]


@pytest.mark.parametrize("chunk", [1, 4, 5, 6, 1024])
def test_lookahead_bound_with_any_chunk_size(tmp_path, counted, chunk):
    path = _write(tmp_path, "c.bin", b"\x00" * 20 + b"\x00" * 1000)
    counted.total = 0
    _, omitted = _run(path, max_bytes=20, lookahead_bytes=100, chunk_size=chunk)
    assert omitted == ["file bytes after the first 120 bytes not inspected for strings"]
    assert counted.total == 120


def _sparse(tmp_path, name, size, at=None, data=b""):
    """A sparse file of `size` bytes (zeros take no disk space), with `data` at `at`."""
    p = tmp_path / name
    with open(p, "wb") as fh:
        fh.truncate(size)
        if at is not None:
            fh.seek(at)
            fh.write(data)
    return str(p)


@pytest.mark.parametrize("size, at, reason", [
    (BYTES_MAX + LOOK, None, None),                                  # exactly 64 MiB
    (BYTES_MAX + LOOK + 1, None, "file bytes after the first 64 MiB not inspected for strings"),
    (BYTES_MAX + LOOK + 1, BYTES_MAX + LOOK - 6,                     # a string inside it
     "strings after the first 32 MiB of the file not checked"),
    (BYTES_MAX + LOOK + 100, BYTES_MAX + LOOK + 10, "file bytes after the first 64 MiB "
     "not inspected for strings"),                                   # only beyond the bound
], ids=["exact-64", "64-plus-1", "string-inside", "string-beyond"])
def test_real_limits_on_sparse_files(tmp_path, counted, size, at, reason):
    path = _sparse(tmp_path, "s.bin", size, at, b"hello\x00" if at is not None else b"")
    _, omitted = _run(path)
    assert omitted == ([reason] if reason else [])
    assert counted.total <= BYTES_MAX + LOOK


def _space_runs(n_bytes: int) -> bytes:
    return b"     \x00" * (n_bytes // 6)


def test_strings_that_cannot_reach_the_output_are_not_kept(tmp_path):
    """Memory regression (review of 2672376): after the output was full, every
    white-space string read was stored, so the peak grew with the tail (about
    10 MiB per MiB of it); now it does not."""
    import tracemalloc
    small = _write(tmp_path, "small.bin", b"a" * CHARS_MAX + b"\x00" + _space_runs(3 * MIB))
    large = _write(tmp_path, "large.bin", b"a" * CHARS_MAX + b"\x00" + _space_runs(6 * MIB))
    peaks = []
    for path in (small, large):
        tracemalloc.start()
        out, omitted = _run(path)
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
        assert out == "a" * CHARS_MAX and omitted == []
    assert peaks[1] < peaks[0] + MIB              # three more MiB of tail: no growth
    assert peaks[1] < 8 * MIB


def test_not_inspected_reason_in_the_result_and_nested(scanner, tmp_path, monkeypatch):
    monkeypatch.setattr(text_mod, "STRINGS_MAX_BYTES", 4096)
    monkeypatch.setattr(text_mod, "STRINGS_LOOKAHEAD_BYTES", 4096)
    big = b"\x00" * 8192 + b"\x00tail text\x00"            # the string is past the bound
    eml = _eml("short body", [("pad.bin", big)])
    outer = _zip([("inner.zip", _zip([("m.eml", eml), ("ok.bin", _binary(1000))])),
                  ("pad.bin", big)])
    r = scanner.scan_file(_write(tmp_path, "nest.zip", outer))
    found = {(x["member_path"].split("!/", 1)[-1], x["reason"]) for x in r["incomplete_reasons"]
             if x["layer"] == "prompt-guard" and "not inspected for strings" in x["reason"]}
    text = "file bytes after the first 8 KiB not inspected for strings"
    assert r["scan_status"] == "partial"
    paths = {p for p, why in found}
    assert {why for _, why in found} == {text.replace("8 KiB", "8,192 bytes")}
    assert "pad.bin" in paths and any(p.endswith("m.eml!/pad.bin") for p in paths)


def test_real_limits_through_an_isolated_worker(tmp_path):
    """The bound and its reason in a real scan worker (spawned: real 32 + 32 MiB
    limits), inside a zip. About 64 MiB of zeros on disk while the test runs."""
    cfg = _config(tmp_path, cache_enabled=False, scan_workers=1, scan_timeout_seconds=120,
                  isolate_scans=True, file_extensions=[".zip"])
    member = tmp_path / "member.bin"
    _sparse(tmp_path, "member.bin", BYTES_MAX + LOOK + 1)
    zpath = tmp_path / "scan" / "big.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_STORED) as z:
        z.write(member, "big.bin")
    member.unlink()
    (a,) = RS.RansomwareScanner(cfg).scan_all_directories()
    reasons = [(x["member_path"].split("!/", 1)[-1], x["reason"]) for x in a["incomplete_reasons"]
               if x["layer"] == "prompt-guard"]
    assert ("big.bin", "file bytes after the first 64 MiB not inspected for strings") in reasons
    assert a["scan_status"] == "partial"
    zpath.unlink()


# --------------------------------- TX-2c: the lookahead skips chunks with no text
def _reference_run_after(fh, last, keep, pattern, chunk_size, budget):
    """The 0a6be7f search, kept as the reference: every run visited in Python."""
    import os
    prev, start, left = last, len(last), budget
    while True:
        if left <= 0:
            return "uninspected" if os.fstat(fh.fileno()).st_size > fh.tell() else "none"
        chunk = fh.read(min(chunk_size, left))
        if not chunk:
            return "none"
        left -= len(chunk)
        data = prev + chunk
        for m in pattern.finditer(data):
            if data[max(m.start(), start):m.end()].strip():
                return "found"
        at = max(0, len(data) - keep)
        prev, start = data[at:], max(0, start - at)


def test_lookahead_matches_the_reference_search(tmp_path):
    import random
    import re
    rng = random.Random(2026_11_22)
    path = tmp_path / "r.bin"
    for _ in range(3000):
        alpha = rng.choice([b" \x00", b"a \x00", b"a \x00\t\n\x7f", b"ab \x00\x00"])
        tail = bytes(rng.choices(alpha, k=rng.randint(0, 120)))
        last = bytes(rng.choices(b"ab \x00", k=rng.randint(0, 7)))
        min_len = rng.randint(1, 8)
        keep = max(min_len - 1, 0)
        last = last[len(last) - keep:] if keep else b""
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        cs, budget = rng.choice([1, 2, 3, 5, 64]), rng.choice([0, 3, rng.randint(0, 130)])
        path.write_bytes(tail)
        with open(path, "rb") as a, open(path, "rb") as b:
            assert text_mod._run_after(a, last, keep, pattern, cs, budget) == \
                _reference_run_after(b, last, keep, pattern, cs, budget), (tail, last, min_len)


class _NoVisit:
    """A pattern that fails the test if the per-run loop is reached."""
    def finditer(self, data):
        raise AssertionError("visited a chunk with no text in it")


@pytest.mark.parametrize("tail", [b"     \x00" * 50, b"\x00" * 300, b" " * 300,
                                  b"\t\n\r\x0b\x0c" * 40, b"\x7f\x1f\x00 " * 60])
def test_chunks_without_text_are_skipped(tmp_path, tail):
    path = _write(tmp_path, "w.bin", tail)
    with open(path, "rb") as fh:
        assert text_mod._run_after(fh, b"", 4, _NoVisit(), 64, 10_000) == "none"


def test_read_text_then_unread_spaces_is_skipped_too(tmp_path):
    # the text is in `last` (already read): the search starts after it
    path = _write(tmp_path, "s.bin", b"      \x00" + b"\x00" * 100)
    with open(path, "rb") as fh:
        assert text_mod._run_after(fh, b"abcd", 4, _NoVisit(), 3, 10_000) == "none"


@pytest.mark.parametrize("chunk", [1, 2, 3, 4, 7])
@pytest.mark.parametrize("min_len", [2, 5, 8])
def test_text_arriving_in_a_later_chunk_is_found(tmp_path, chunk, min_len):
    # a run of spaces, then its text a few chunks later: still one run, found
    spaces = b" " * (min_len + 6)
    path = _write(tmp_path, "t.bin", b"\x00" * 30 + spaces + b"x\x00")
    _, omitted = _run(path, min_len=min_len, max_bytes=30, chunk_size=chunk)
    assert omitted == ["strings after the first 30 bytes of the file not checked"]
    # with only spaces it is not
    path = _write(tmp_path, "u.bin", b"\x00" * 30 + spaces + b"\x00")
    assert _run(path, min_len=min_len, max_bytes=30, chunk_size=chunk)[1] == []
