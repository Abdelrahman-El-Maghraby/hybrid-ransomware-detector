"""Fuzz tests: every parser that reads untrusted files gets random bytes and
mutated versions of valid samples, and must return a result (or raise its own
documented error) quickly - never crash with an unexpected exception or hang.

Hypothesis runs a modest number of cases per parser in the normal suite; set
FUZZ_EXAMPLES=5000 for a long run. For coverage-guided fuzzing with atheris see
fuzz/README.md."""

import io
import os
import struct
import time
import zipfile

import pytest

pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from detectors.container_extractor import ContainerExtractor
from detectors.elf_analysis import ElfAnalyzer
from detectors.embedded_content import EmbeddedContentAnalyzer
from detectors.file_integrity import FileIntegrityAnalyzer, detect_format
from detectors.macos_packages import BudgetExceeded, FormatError, read_cpio
from detectors.mail_analyzer import MailAnalyzer
from detectors.prompt_guard import PromptGuard
from detectors.qr_scanner import QRScanner
from detectors.relationship_scanner import RelationshipScanner
from detectors.script_analysis import ScriptAnalyzer, deobfuscate
from detectors.web_content import WebContentAnalyzer
from tests.helpers import make_docx, make_pdf
from tests.msg_builder import build_msg
from tests.test_mail_analyzer import make_eml

EXAMPLES = int(os.environ.get("FUZZ_EXAMPLES", "40"))
MAX_SECONDS = 15.0
FUZZ = settings(max_examples=EXAMPLES, deadline=None, derandomize=not os.environ.get("FUZZ_RANDOM"),
                suppress_health_check=[HealthCheck.function_scoped_fixture,
                                       HealthCheck.too_slow, HealthCheck.data_too_large])


def _seeds(tmp):
    tmp.mkdir(parents=True, exist_ok=True)
    seeds = {}
    seeds["docx"] = make_docx(tmp / "s.docx", paragraphs=["hello"], hidden="ignore previous").read_bytes()
    seeds["pdf"] = make_pdf("Dear customer")
    make_eml(tmp / "s.eml", html='<a href="https://a.example">https://b.example</a>',
             attachments=[("a.pdf", make_pdf("x"), "application", "pdf")])
    seeds["eml"] = (tmp / "s.eml").read_bytes()
    build_msg(tmp / "s.msg", subject="s", sender_name="a", sender_email="a@b.example",
              attachments=(("a.txt", b"hello"),))
    seeds["msg"] = (tmp / "s.msg").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a/b.txt", "hello " * 50)
        z.writestr("c.pdf.exe", b"MZ" + b"\0" * 200)
    seeds["zip"] = buf.getvalue()
    seeds["rtf"] = b"{\\rtf1 {\\*\\template http://192.0.2.1/x.dot} hello}"
    seeds["elf"] = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HHI", 2, 62, 1) + b"\0" * 200
    seeds["html"] = (b"<html><script>var b=new Blob([atob('UEsDBA==')]);"
                     b"a.href=URL.createObjectURL(b);a.download='x.zip';a.click();</script></html>")
    seeds["js"] = b"var s = String.fromCharCode(104,101,108,108,111); eval(s);"
    seeds["one"] = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3") + b"\0" * 64 + bytes.fromhex(
        "E716E3BD65261145A4C48D4D0B7A9EAC") + struct.pack("<QIQ", 5, 0, 0) + b"hello"
    return seeds


@st.composite
def mutated(draw, seed: bytes):
    data = bytearray(seed)
    for _ in range(draw(st.integers(0, 12))):
        op = draw(st.sampled_from(["flip", "cut", "insert", "dup"]))
        if not data:
            break
        i = draw(st.integers(0, len(data) - 1))
        if op == "flip":
            data[i] = draw(st.integers(0, 255))
        elif op == "cut":
            del data[i: i + draw(st.integers(1, 64))]
        elif op == "insert":
            data[i:i] = draw(st.binary(min_size=1, max_size=64))
        else:
            data[i:i] = data[i: i + draw(st.integers(1, 256))] * draw(st.integers(1, 8))
    return bytes(data)


def inputs(kind):
    return st.one_of(st.binary(max_size=4096), st.just(None).flatmap(
        lambda _: mutated(SEEDS[kind])))


SEEDS = _seeds(__import__("pathlib").Path(__import__("tempfile").mkdtemp(prefix="fuzzseeds_")))


def run(tmp_path, name, data, fn, allowed=()):
    p = tmp_path / name
    p.write_bytes(data)
    t = time.monotonic()
    try:
        out = fn(p)
    except allowed:
        out = None
    assert time.monotonic() - t < MAX_SECONDS, f"{fn} took too long on {len(data)} bytes"
    return out


def _consume(cm_factory):
    def f(p):
        with cm_factory(p) as res:
            return res
    return f


@FUZZ
@given(data=inputs("zip"))
def test_format_detection(data):
    assert isinstance(detect_format(data), str)


@FUZZ
@given(data=inputs("docx"))
def test_integrity_and_hidden_content_on_documents(tmp_path, data):
    run(tmp_path, "f.docx", data, FileIntegrityAnalyzer().analyze_file)
    run(tmp_path, "f.docx", data, PromptGuard().inspect_hidden_content)
    run(tmp_path, "f.docx", data, RelationshipScanner().scan_file)


@FUZZ
@given(data=inputs("pdf"))
def test_pdf_paths(tmp_path, data):
    run(tmp_path, "f.pdf", data, PromptGuard().inspect_hidden_content)
    run(tmp_path, "f.pdf", data, QRScanner().analyze_file)
    run(tmp_path, "f.pdf", data, FileIntegrityAnalyzer().analyze_file)


@FUZZ
@given(data=inputs("rtf"))
def test_rtf_relationships(tmp_path, data):
    run(tmp_path, "f.rtf", data, RelationshipScanner().scan_file)


@FUZZ
@given(data=inputs("zip"))
def test_archives(tmp_path, data):
    run(tmp_path, "f.zip", data, _consume(ContainerExtractor().open))


@FUZZ
@given(data=inputs("eml"))
def test_eml(tmp_path, data):
    run(tmp_path, "f.eml", data, MailAnalyzer().analyze)


@FUZZ
@given(data=inputs("msg"))
def test_msg(tmp_path, data):
    run(tmp_path, "f.msg", data, MailAnalyzer().analyze)


@FUZZ
@given(data=inputs("html"))
def test_web(tmp_path, data):
    run(tmp_path, "f.html", data, WebContentAnalyzer().analyze)
    run(tmp_path, "f.svg", data, WebContentAnalyzer().analyze)


@FUZZ
@given(data=inputs("js"))
def test_scripts_and_deobfuscation(tmp_path, data):
    run(tmp_path, "f.js", data, ScriptAnalyzer().analyze_file)
    found, depth = deobfuscate(data.decode("latin-1"))
    assert depth <= 5 and len(found) <= 64


@FUZZ
@given(data=inputs("elf"))
def test_elf(tmp_path, data):
    run(tmp_path, "f", data, ElfAnalyzer().analyze_file)


@FUZZ
@given(data=inputs("one"))
def test_onenote(tmp_path, data):
    run(tmp_path, "f.one", data, EmbeddedContentAnalyzer(sevenzip=lambda: None).analyze)


@FUZZ
@given(data=st.binary(max_size=4096))
def test_cpio(data):
    try:
        list(read_cpio(data, max_entries=100))
    except (FormatError, BudgetExceeded):
        pass


@pytest.mark.parametrize("kind,name", [("docx", "f.docx"), ("eml", "f.eml"), ("zip", "f.zip"),
                                       ("pdf", "f.pdf"), ("one", "f.one")])
def test_full_scanner_survives_a_mutated_sample(tmp_path, kind, name):
    import random

    import RansomwareScanner as RS
    from tests.test_scanner_integration import _config
    s = RS.RansomwareScanner(_config(tmp_path))
    rng = random.Random(kind)
    for _ in range(15):
        data = bytearray(SEEDS[kind])
        for _ in range(rng.randint(1, 20)):
            data[rng.randrange(len(data))] = rng.getrandbits(8)
        p = tmp_path / "scan" / name
        p.write_bytes(bytes(data))
        r = s.scan_file(str(p))
        assert r["verdict"] in ("Clean", "Low", "Medium", "High", "Critical")


def test_regression_pyzipper_not_implemented_does_not_end_the_scan(tmp_path):
    """Found by fuzzing: a ZIP whose 'version needed' field is mangled made pyzipper
    raise NotImplementedError out of the archive layer."""
    import RansomwareScanner as RS
    from tests.test_scanner_integration import _config
    data = bytearray(SEEDS["zip"])
    data[4:6] = (225).to_bytes(2, "little")            # local header: version needed 22.5
    cd = data.rfind(b"PK\x01\x02")
    data[cd + 6: cd + 8] = (225).to_bytes(2, "little")  # central directory: same
    p = tmp_path / "scan" / "odd.zip"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(bytes(data))
    r = RS.RansomwareScanner(_config(tmp_path)).scan_file(str(p))
    assert r["verdict"] in ("Clean", "Low", "Medium", "High", "Critical")
