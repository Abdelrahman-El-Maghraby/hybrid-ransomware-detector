from RansomwareScanner import extract_suspicious_strings


def test_strings_across_chunk_boundaries(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00" * 10 + b"powershell -enc AAAA" + b"\x00\x01" + b"vssadmin delete shadows")
    out = extract_suspicious_strings(str(p), chunk_size=16).splitlines()
    assert out == ["powershell -enc AAAA", "vssadmin delete shadows"]


def test_short_runs_are_ignored_and_output_is_bounded(tmp_path):
    p = tmp_path / "y.bin"
    p.write_bytes(b"abc\x00defg\x00" + b"A" * 300_000)
    out = extract_suspicious_strings(str(p), max_chars=1000)
    assert "abc" not in out and "defg" not in out
    assert len(out) <= 1000


def test_missing_file_returns_empty(tmp_path):
    assert extract_suspicious_strings(str(tmp_path / "nope")) == ""
