"""ML classifier: feature extraction, PE parsing, the rule engine, training,
and model persistence. Every sample is synthetic (random bytes, text, or a
structurally valid but non-functional PE)."""

import io
import math
import os
import random
import struct
import zipfile
from pathlib import Path

import pytest

from detectors.ml_classifier import (
    FEATURE_NAMES,
    SKLEARN_AVAILABLE,
    MLClassifier,
    collect_files,
    extract_features,
    pe_features,
    rule_score,
    shannon_entropy,
)

needs_sklearn = pytest.mark.skipif(not SKLEARN_AVAILABLE, reason="scikit-learn not installed")

SCN_CODE_EXEC_READ = 0x60000020
SCN_DATA_RW = 0xC0000040
SCN_WX = 0xE0000020


def make_pe(sections, imports=("KERNEL32.dll", "USER32.dll", "ADVAPI32.dll"), pe32_plus=False):
    """A minimal, valid-looking PE: MZ stub, COFF + optional header, section
    table and an import directory with one descriptor per DLL. It does not run."""
    file_align = 0x200
    opt_size = 240 if pe32_plus else 224
    headers_end = 0x80 + 24 + opt_size + 40 * len(sections)
    raw_ptr = -(-headers_end // file_align) * file_align
    table, blobs = b"", b""
    rva = 0x1000
    import_rva = 0
    for i, (name, data, chars) in enumerate(sections):
        if i == 0 and imports:                       # import table lives in section 0
            import_rva = rva
            idt = b"".join(struct.pack("<IIIII", 0, 0, 0, rva + 0x400 + j * 16, rva + 0x800)
                           for j, _ in enumerate(imports)) + b"\0" * 20
            data = idt + data[len(idt):]
        size = -(-len(data) // file_align) * file_align
        table += struct.pack("<8sIIIIIIHHI", name.encode()[:8], len(data), rva, size,
                             raw_ptr + len(blobs), 0, 0, 0, 0, chars)
        blobs += data.ljust(size, b"\0")
        rva += -(-len(data) // 0x1000) * 0x1000 or 0x1000
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x80)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664 if pe32_plus else 0x14C,
                                   len(sections), 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    opt[0:2] = struct.pack("<H", 0x20B if pe32_plus else 0x10B)
    dd = 112 if pe32_plus else 96
    opt[dd + 8:dd + 16] = struct.pack("<II", import_rva, 20 * (len(imports) + 1))
    head = bytes(dos) + coff + bytes(opt) + table
    return head.ljust(raw_ptr, b"\0") + blobs


def low_entropy_code(n=4096, seed=1):
    rng = random.Random(seed)
    ops = [b"\x55", b"\x8b\xec", b"\x83\xec\x10", b"\xe8\x00\x00\x00\x00", b"\xc3", b"\x90"]
    out = b""
    while len(out) < n:
        out += rng.choice(ops)
    return out[:n]


# ---------------------------------------------------------------- features
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"A" * 1000) == 0.0
    assert math.isclose(shannon_entropy(bytes(range(256)) * 4), 8.0)


def test_feature_vector_shape_and_names(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("meeting notes\n" * 400)
    f = extract_features(p)
    assert list(f) == FEATURE_NAMES and len(f) == 15
    assert f["printable_ratio"] == 1.0 and f["entropy_full"] < 4.5
    assert f["is_pe"] == 0 and f["known_compressed_format"] == 0 and f["ext_risk"] == 1


def test_random_content_features(tmp_path):
    p = tmp_path / "report.docx"
    p.write_bytes(os.urandom(256 * 1024))
    f = extract_features(p)
    assert f["entropy_full"] > 7.99
    assert f["high_entropy_window_ratio"] == 1.0
    assert f["ext_risk"] == 2 and f["known_compressed_format"] == 0


def test_compressed_formats_are_recognised(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("data.bin", os.urandom(200_000))
    p = tmp_path / "archive.zip"
    p.write_bytes(buf.getvalue())
    f = extract_features(p)
    assert f["known_compressed_format"] == 1 and f["entropy_full"] > 7.9
    score, _ = rule_score(f)
    assert score < 0.5                         # high entropy is expected for a ZIP


def test_size_is_real_even_beyond_the_sample_window(tmp_path):
    p = tmp_path / "big.bin"
    with open(p, "wb") as fh:
        fh.seek(9 * 1024 * 1024)
        fh.write(b"\0")
    f = extract_features(p)
    assert math.isclose(f["log2_size"], math.log2(9 * 1024 * 1024 + 2))


# --------------------------------------------------------------- PE parsing
@pytest.mark.parametrize("pe32_plus", [False, True])
def test_pe_features_clean_layout(pe32_plus):
    pe = make_pe([(".text", low_entropy_code(), SCN_CODE_EXEC_READ),
                  (".data", b"\x01\x00" * 1000, SCN_DATA_RW),
                  (".rsrc", b"icon" * 300, SCN_DATA_RW)], pe32_plus=pe32_plus)
    f = pe_features(pe)
    assert f["is_pe"] == 1 and f["pe_section_count"] == 3
    assert f["pe_import_dll_count"] == 3
    assert f["pe_suspicious_sections"] == 0 and f["pe_wx_sections"] == 0
    assert f["pe_max_section_entropy"] < 6.5


def test_packed_pe_indicators():
    pe = make_pe([("UPX0", b"\0" * 512, SCN_WX),
                  ("UPX1", os.urandom(16_384), SCN_WX)], imports=("KERNEL32.dll",))
    f = pe_features(pe)
    assert f["pe_suspicious_sections"] == 2 and f["pe_wx_sections"] == 2
    assert f["pe_import_dll_count"] == 1 and f["pe_max_section_entropy"] > 7.5
    score, reasons = rule_score({**extract_features_from_bytes(pe, ".exe")})
    assert score >= 0.5 and any("packer" in r for r in reasons)


def extract_features_from_bytes(data, ext, tmp=Path(os.environ.get("HOME", "/tmp"))):
    p = tmp / f"sample{ext}"
    p.write_bytes(data)
    try:
        return extract_features(p)
    finally:
        p.unlink()


@pytest.mark.parametrize("blob", [
    b"MZ", b"MZ" + b"\0" * 100, b"MZ" + b"\0" * 58 + struct.pack("<I", 0xFFFFFF),
    b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + b"\xff" * 30,
])
def test_corrupt_pe_never_raises(blob):
    f = pe_features(blob)
    assert set(f) >= {"is_pe", "pe_section_count"}


# ------------------------------------------------------------- rule engine
def test_rule_engine_verdicts(tmp_path):
    clf = MLClassifier()                         # no model -> rules
    assert not clf.has_model
    text = tmp_path / "minutes.docx"
    text.write_text("All figures are final. " * 500)
    encrypted = tmp_path / "budget.xlsx"
    encrypted.write_bytes(os.urandom(300_000))
    clean_pe = tmp_path / "tool.exe"
    clean_pe.write_bytes(make_pe([(".text", low_entropy_code(), SCN_CODE_EXEC_READ)]))

    r = clf.classify(text)
    assert r.label == "benign" and r.model == "rules" and r.indicators == []
    r = clf.classify(encrypted)
    assert r.label == "suspicious" and r.probability >= 0.45
    assert "statistically random" in r.indicators[0]
    assert clf.classify(clean_pe).label == "benign"


def test_missing_file_is_reported_not_raised(tmp_path):
    r = MLClassifier().classify(tmp_path / "nope.bin")
    assert r.available is False and r.error


# ------------------------------------------------------------------ training
def _corpus(root: Path, n=24):
    benign, malicious = root / "benign", root / "malicious"
    benign.mkdir()
    malicious.mkdir()
    rng = random.Random(7)
    words = "the quarterly report shows revenue growth across all regions".split()
    for i in range(n):
        if i % 3 == 0:
            (benign / f"b{i}.txt").write_text(" ".join(rng.choice(words) for _ in range(3000)))
        elif i % 3 == 1:
            (benign / f"b{i}.exe").write_bytes(
                make_pe([(".text", low_entropy_code(8192, seed=i), SCN_CODE_EXEC_READ),
                         (".data", bytes(rng.randrange(8) for _ in range(2048)), SCN_DATA_RW)]))
        else:
            (benign / f"b{i}.csv").write_text("\n".join(f"{j},{j * 3},{rng.random():.3f}"
                                                        for j in range(2000)))
        if i % 2 == 0:
            (malicious / f"m{i}.locked").write_bytes(os.urandom(rng.randrange(20_000, 120_000)))
        else:
            (malicious / f"m{i}.exe").write_bytes(
                make_pe([("UPX0", b"\0" * 512, SCN_WX), ("UPX1", os.urandom(30_000), SCN_WX)],
                        imports=("KERNEL32.dll",)))
    return benign, malicious


@needs_sklearn
def test_train_save_load_roundtrip(tmp_path):
    benign, malicious = _corpus(tmp_path)
    clf = MLClassifier()
    metrics = clf.train(collect_files(benign), collect_files(malicious))
    assert metrics["samples"] == {"benign": 24, "malicious": 24, "unreadable": 0}
    assert metrics["accuracy"] >= 0.9 and metrics["false_positive_rate"] <= 0.1
    assert set(clf.model_info["feature_importances"]) == set(FEATURE_NAMES)

    model = tmp_path / "models" / "m.joblib"
    clf.save(model)
    loaded = MLClassifier(model)
    assert loaded.has_model and loaded.model_name == "m.joblib" and not loaded.load_error

    sample = tmp_path / "new.locked"
    sample.write_bytes(os.urandom(50_000))
    r1, r2 = clf.classify(sample), loaded.classify(sample)
    assert r1.probability == r2.probability and r2.label == "suspicious"
    assert r2.model == "m.joblib" and any("weight" in i for i in r2.indicators)
    doc = tmp_path / "letter.txt"
    doc.write_text("Dear team, the quarterly report is attached. " * 200)
    assert loaded.classify(doc).label == "benign"


@needs_sklearn
def test_too_few_samples(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    with pytest.raises(ValueError, match="at least 5 samples"):
        MLClassifier().train([tmp_path / "a.txt"] * 3, [tmp_path / "a.txt"] * 3)


@needs_sklearn
def test_foreign_or_stale_model_falls_back_to_rules(tmp_path):
    import joblib
    bad = tmp_path / "foreign.joblib"
    joblib.dump({"anything": 1}, bad)
    clf = MLClassifier(bad)
    assert not clf.has_model and "not a hybrid" in clf.load_error
    stale = tmp_path / "stale.joblib"
    joblib.dump({"format": "hrd-ml-1", "feature_names": ["entropy_full"], "model": None}, stale)
    clf = MLClassifier(stale)
    assert not clf.has_model and "different feature set" in clf.load_error
    p = tmp_path / "f.txt"
    p.write_text("hello")
    assert clf.classify(p).model == "rules"


def test_missing_model_path_uses_rules(tmp_path):
    clf = MLClassifier(tmp_path / "does-not-exist.joblib")
    assert not clf.has_model and clf.load_error == ""


def test_pdf_with_compressed_streams_is_not_random_but_header_only_pdf_is(tmp_path):
    rng = random.Random(4)
    body = b"".join(b"%d 0 obj\n<< /Filter /FlateDecode >>\nstream\n" % i
                    + bytes(rng.getrandbits(8) for _ in range(30_000))
                    + b"\nendstream\nendobj\n" for i in range(1, 8))
    real = tmp_path / "report.pdf"
    real.write_bytes(b"%PDF-1.7\n" + body + b"trailer\n%%EOF\n")
    assert rule_score(extract_features(real))[0] < 0.5
    # an encryptor that keeps the first bytes: header survives, structure does not
    locked = tmp_path / "locked.pdf"
    locked.write_bytes(b"%PDF-1.7\n" + bytes(rng.getrandbits(8) for _ in range(200_000)))
    assert rule_score(extract_features(locked))[0] >= 0.5
