"""4.7: per-layer capabilities (up / down / disabled), the production profile's
required layers, and the build flavour checks run on the packaged program."""

import argparse
import json
import subprocess

import pytest

import build
import RansomwareScanner as RS
from detectors import YARA_AVAILABLE, container_extractor
from engine import capabilities as cap
from tests.test_scanner_integration import _config


def _states(tmp_path, **overrides):
    return cap.layer_states(RS.RansomwareScanner(_config(tmp_path, **overrides)))


def test_every_pipeline_layer_has_a_state_in_pipeline_order(tmp_path):
    scanner = RS.RansomwareScanner(_config(tmp_path))
    states = cap.layer_states(scanner)
    assert list(states) == [layer.name for layer in scanner.pipeline]
    assert all(s["state"] in (cap.UP, cap.DOWN, cap.DISABLED) for s in states.values())
    for name in ("hashes", "integrity", "pe", "elf", "script", "web"):
        assert states[name] == {"state": cap.UP, "detail": "", "missing": []}
    assert set(cap.PRODUCTION_REQUIRED) <= set(states)


def test_disabled_by_configuration(tmp_path):
    states = _states(tmp_path, qr_scan_enabled=False, ml_enabled=False)
    assert states["qr"]["state"] == cap.DISABLED and "QR_SCAN_ENABLED" in states["qr"]["detail"]
    assert states["ml"]["state"] == cap.DISABLED
    for name in cap.EXTERNAL_LAYERS + cap.NOT_IN_PRODUCTION:
        assert states[name]["state"] == cap.DISABLED
    assert cap.external_services(states) == {"llm": "off", "virustotal": "off", "sandbox": "off"}


def test_yara_without_compiled_rules_is_down(tmp_path):
    empty = tmp_path / "no-rules"
    empty.mkdir()
    if not YARA_AVAILABLE:
        pytest.skip("yara-python not installed")
    assert _states(tmp_path, yara_rules_dir=str(empty))["yara"] == {
        "state": cap.DOWN, "detail": "needs compiled YARA rules", "missing": ["compiled YARA rules"]}


def test_missing_rar_decompressor_is_a_host_tool(tmp_path, monkeypatch):
    if not container_extractor.RAR_AVAILABLE:
        pytest.skip("rarfile not installed")
    monkeypatch.setattr(container_extractor, "rar_tool_available", lambda: False)
    states = _states(tmp_path)
    assert states["archive"]["state"] == cap.DOWN
    assert states["archive"]["missing"][-1] == "rar-decompressor"
    only_tools = {**states, "archive": {**states["archive"], "missing": ["rar-decompressor"]}}
    # desktop binaries cannot bundle the decompressor; the Docker image must carry it
    assert cap.required_problems(only_tools, ["archive"], host_tools_required=False) == []
    assert cap.required_problems(only_tools, ["archive"]) == [
        "archive: down (needs rar-decompressor)"]


def test_external_services_are_described_when_on(tmp_path):
    states = _states(tmp_path, virustotal_api_key="x" * 64, virustotal_upload_unknown=True)
    assert states["virustotal"] == {"state": cap.UP, "detail": "hash look-up + upload", "missing": []}
    assert cap.external_services(states)["virustotal"] == "hash look-up + upload"


def _fake(**states):
    base = {n: {"state": cap.UP, "detail": "", "missing": []} for n in cap.PRODUCTION_REQUIRED}
    base.update({n: {"state": cap.DISABLED, "detail": "off", "missing": []}
                 for n in cap.EXTERNAL_LAYERS + cap.NOT_IN_PRODUCTION})
    base.update(states)
    return base


def test_production_problems():
    assert cap.production_problems(_fake()) == []
    down = {"state": cap.DOWN, "detail": "needs zbar", "missing": ["zbar"]}
    assert cap.production_problems(_fake(qr=down)) == ["qr: down (needs zbar)"]
    off = {"state": cap.DISABLED, "detail": "ML_ENABLED=0", "missing": []}
    assert cap.production_problems(_fake(ml=off)) == ["ml: disabled (ML_ENABLED=0)"]
    emulation = {"state": cap.UP, "detail": "", "missing": []}
    assert cap.production_problems(_fake(emulation=emulation)) == [
        "emulation: enabled, but it is outside the production profile"]
    gone = _fake()
    del gone["pe"]
    assert cap.production_problems(gone) == ["pe: not in the pipeline"]


def test_flavour_problems(monkeypatch):
    down = {"state": cap.DOWN, "detail": "needs zbar", "missing": ["zbar"]}
    assert cap.flavour_problems(_fake(qr=down), "cli") == []
    assert cap.flavour_problems(_fake(qr=down), "api")[0] == "qr: down (needs zbar)"
    monkeypatch.setattr(cap, "_has_package", lambda name: name != "customtkinter")
    assert cap.flavour_problems(_fake(), "gui") == ["package customtkinter: not installed"]
    pkg = {"state": cap.DOWN, "detail": "needs oletools", "missing": ["oletools"]}
    assert cap.flavour_problems(_fake(macro=pkg), "cli") == ["macro: down (needs oletools)"]


def test_summary_line_names_the_reason_when_not_up():
    line = cap.summary_line({"pe": {"state": cap.UP, "detail": "x", "missing": []},
                             "qr": {"state": cap.DOWN, "detail": "needs zbar", "missing": ["zbar"]}})
    assert line == "pe:up  qr:down(needs zbar)"


def test_start_up_log_lists_every_layer(tmp_path, caplog):
    with caplog.at_level("INFO", logger="RansomwareScanner"):
        RS.RansomwareScanner(_config(tmp_path))
    text = caplog.text
    assert "Detection layers -> hashes:up" in text and " pe:up " in text
    assert "External services -> llm:off  virustotal:off  sandbox:off" in text


def test_cli_capabilities_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(RS, "CONFIG", _config(tmp_path))
    with pytest.raises(SystemExit) as stop:
        RS._capabilities_command(argparse.Namespace(capabilities=""))
    assert stop.value.code == 0
    report = build.capabilities_report(capsys.readouterr().out)
    assert report["engine_version"] == RS.ENGINE_VERSION and report["layers"]["pe"]["state"] == "up"
    assert "flavour" not in report

    monkeypatch.setattr(cap, "flavour_problems", lambda states, flavour: ["qr: down (needs zbar)"])
    with pytest.raises(SystemExit) as stop:
        RS._capabilities_command(argparse.Namespace(capabilities="api"))
    assert stop.value.code == 1
    report = build.capabilities_report(capsys.readouterr().out)
    assert report["flavour"] == "api" and report["flavour_problems"] == ["qr: down (needs zbar)"]
    assert RS._capabilities_command(argparse.Namespace(capabilities=None)) is False


# ------------------------------------------------------------------ build.py
def _run(stdout, code=0):
    return subprocess.CompletedProcess(["hrd-scanner"], code, stdout, "")


def test_build_reads_the_report_after_log_lines():
    out = "2026-10-27 INFO Scanner initialized\n" + json.dumps({"layers": {"pe": {}}}, indent=2)
    assert build.capabilities_report(out) == {"layers": {"pe": {}}}
    assert build.capabilities_report("no json here") == {}


def test_build_fails_when_the_packaged_program_lacks_a_layer(capsys):
    good = {"layers": {"pe": {"state": "up", "detail": ""}}, "flavour_problems": []}
    build.check_capabilities(_run(json.dumps(good, indent=2)))
    assert "ok  layer pe: up" in capsys.readouterr().out
    bad = {"layers": {"macro": {"state": "down", "detail": "needs oletools"}},
           "flavour_problems": ["macro: down (needs oletools)"]}
    with pytest.raises(SystemExit, match="macro: down"):
        build.check_capabilities(_run(json.dumps(bad, indent=2), code=1))
    with pytest.raises(SystemExit, match="printed no report"):
        build.check_capabilities(_run("Traceback ..."))


def test_build_preflight_requires_every_bundled_package(monkeypatch):
    real = build.importlib.util.find_spec
    monkeypatch.setattr(build.importlib.util, "find_spec",
                        lambda name, *a: None if name == "oletools" else real(name, *a))
    monkeypatch.setitem(__import__("sys").modules, "PyInstaller", object())
    with pytest.raises(SystemExit, match="Missing required packages: oletools"):
        build.preflight(with_ml=False)


def test_build_checks_the_gui_toolkit_in_a_folder_bundle(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(build, "DIST", tmp_path)
    (tmp_path / build.APP_NAME).mkdir()
    with pytest.raises(SystemExit, match="customtkinter is not in the bundle"):
        build.check_gui_bundle(onefile=False)
    (tmp_path / build.APP_NAME / "_internal" / "customtkinter").mkdir(parents=True)
    build.check_gui_bundle(onefile=False)
    build.check_gui_bundle(onefile=True)
    out = capsys.readouterr().out
    assert "GUI toolkit (customtkinter) bundled" in out and "not inspected" in out


def test_capabilities_prints_nothing_but_json(tmp_path):
    """stdout of --capabilities is one JSON object (no log lines before it)."""
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path), LLM_PROVIDER="none",
               PYTHONIOENCODING="utf-8")
    out = subprocess.run([sys.executable, str(root / "RansomwareScanner.py"), "--capabilities"],
                         cwd=tmp_path, env=env, capture_output=True, text=True, timeout=180)
    report = json.loads(out.stdout)
    assert out.stdout.lstrip().startswith("{") and "layers" in report
