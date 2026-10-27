"""4.7: every result and report records what produced it (engine, rules, registry,
schema, layers, external services) and never a secret."""

import json
import shutil

import pytest

import RansomwareScanner as RS
from api import SCHEMA_VERSION
from detectors.registry import REGISTRY
from engine import provenance as P
from engine.config import BUNDLED_RULES_DIR
from tests.helpers import make_pdf
from tests.test_scan_status import _disguised_pe
from tests.test_scanner_integration import _config

SECRETS = {"virustotal_api_key": "VTKEY-" + "a" * 58, "chatgpt_api_key": "sk-SECRET-OPENAI-KEY",
           "sandbox_token": "SANDBOX-TOKEN-123", "webhook_secret": "HOOK-SECRET-456",
           "imap_password": "IMAP-APP-PASSWORD"}


def _scan(tmp_path, name, data, **cfg):
    scanner = RS.RansomwareScanner(_config(tmp_path, cache_enabled=False, **cfg))
    p = tmp_path / name
    p.write_bytes(data)
    return scanner, scanner.scan_file(str(p))


def test_every_result_says_what_produced_it(tmp_path):
    _, r = _scan(tmp_path, "a.pdf", make_pdf("hello"))
    pv = r["provenance"]
    assert pv["engine_version"] == RS.ENGINE_VERSION and pv["schema_version"] == SCHEMA_VERSION
    assert pv["registry_version"] == REGISTRY.version == r["score_breakdown"]["registry_version"]
    assert pv["rules"]["source"] == "bundled" and len(pv["rules"]["sha256"]) == 64
    assert pv["rules"]["files"] >= 1 and pv["profile"] == "standard"
    assert pv["external_services"] == {"llm": "off", "virustotal": "off", "sandbox": "off"}
    disabled = {d["layer"]: d["reason"] for d in pv["layers_disabled"]}
    assert disabled["virustotal"] == "no VIRUSTOTAL_API_KEY" and "emulation" in disabled
    assert "pe" in pv["layers_not_applicable"] and "yara" in pv["layers_run"]
    assert "hashes" in pv["layers_run"] and "virustotal" not in pv["layers_run"]
    assert pv["layers_failed"] == [] and pv["layers_skipped"] == []


def test_per_file_layers(tmp_path, monkeypatch):
    scanner, pe = _scan(tmp_path, "tool.exe", _disguised_pe())
    assert "pe" in pe["provenance"]["layers_run"]

    def boom(*a, **k):
        raise ValueError("x")
    monkeypatch.setattr(scanner.macro_analyzer, "analyze_file", boom)
    p = tmp_path / "b.pdf"
    p.write_bytes(make_pdf("hi"))
    r = scanner.scan_file(str(p))
    assert r["provenance"]["layers_failed"] == ["macro"]
    scanner.fuzzy_max_bytes = 1
    r = scanner.scan_file(str(p))
    assert {"layer": "fuzzy", "reason": "file larger than fuzzy_max_bytes (1 bytes)"} in \
        r["provenance"]["layers_skipped"]


def test_intended_heavy_skip_is_recorded_with_its_reason(tmp_path):
    import hashlib
    data = make_pdf("vendor")
    allow = tmp_path / "allow.txt"
    allow.write_text(hashlib.sha256(data).hexdigest() + "  # vendor\n")
    _, r = _scan(tmp_path, "v.pdf", data, allowlist_path=str(allow))
    skipped = r["provenance"]["layers_skipped"]
    assert {s["layer"] for s in skipped} >= {"ml"}
    assert all("allowlist" in s["reason"] for s in skipped)


def test_rules_hash_follows_the_rules(tmp_path):
    custom = tmp_path / "rules"
    shutil.copytree(BUNDLED_RULES_DIR, custom)
    _, bundled = _scan(tmp_path, "c.pdf", make_pdf("x"))
    _, same = _scan(tmp_path, "c.pdf", make_pdf("x"), yara_rules_dir=str(custom))
    assert same["provenance"]["rules"]["source"] == "custom folder"
    assert same["provenance"]["rules"]["sha256"] == bundled["provenance"]["rules"]["sha256"]
    first = sorted(custom.glob("*.yar"))[0]
    first.write_text(first.read_text() + "\n// edited\n")
    _, edited = _scan(tmp_path, "c.pdf", make_pdf("x"), yara_rules_dir=str(custom))
    assert edited["provenance"]["rules"]["sha256"] != bundled["provenance"]["rules"]["sha256"]


def test_rule_pack_and_override_are_named(tmp_path):
    pack = tmp_path / "data" / "rulepacks" / "2026.11.01"
    (pack / "rules").mkdir(parents=True)
    shutil.copy(sorted(BUNDLED_RULES_DIR.glob("*.yar"))[0], pack / "rules")

    class Yara:
        rules_dir, _rules_count = str(pack / "rules"), 1

    class Fake:
        yara_engine, rulepack = Yara(), {"path": str(pack), "version": "2026.11.01"}
    info = P.rules_info(Fake())
    assert info["source"] == "rule pack" and info["version"] == "2026.11.01" and info["files"] == 1
    Fake.rulepack = {"path": str(pack) + "2", "version": "x"}   # a sibling, not a parent
    assert P.rules_info(Fake())["source"] == "custom folder"

    name = next(k for k, v in REGISTRY.weights.items() if isinstance(v, (int, float)))
    override = tmp_path / "w.yaml"
    override.write_text(f"weights:\n  {name}: {REGISTRY.weights[name]}\n")
    _, r = _scan(tmp_path, "d.pdf", make_pdf("x"), weights_override=str(override))
    assert r["provenance"]["registry_version"] == REGISTRY.version + " +override"


def test_external_services_are_named_but_secrets_never_leak(tmp_path, monkeypatch):
    scanner, r = _scan(tmp_path, "e.pdf", make_pdf("x"), **SECRETS)
    monkeypatch.setattr(scanner, "scan_file_with_virustotal",
                        lambda path, hashes: scanner._vt_empty(not_found=True))
    p = tmp_path / "e.pdf"
    r = scanner.scan_file(str(p))
    assert r["provenance"]["external_services"]["virustotal"] == "hash look-up"
    text = json.dumps(r) + scanner.generate_report([r])
    for secret in SECRETS.values():
        assert secret not in text


def test_failed_worker_result_keeps_the_scanner_provenance(tmp_path):
    from engine.workers import failure_result
    scanner = RS.RansomwareScanner(_config(tmp_path))
    p = tmp_path / "f.pdf"
    p.write_bytes(b"%PDF-1.4")
    pv = failure_result(scanner, str(p), "crashed")["provenance"]
    assert pv["layers_failed"] == ["worker"] and pv["rules"] == scanner.provenance["rules"]


def test_report_header_names_rules_registry_schema_and_services(tmp_path):
    scanner, r = _scan(tmp_path, "g.pdf", make_pdf("x"))
    report = scanner.generate_report([r])
    sha = r["provenance"]["rules"]["sha256"][:16]
    assert f"sha256 {sha}" in report and "Rules:                  bundled with" in report
    assert f"Registry / schema:      {REGISTRY.version} / {SCHEMA_VERSION}" in report
    assert "External services:      llm off, virustotal off, sandbox off" in report


def test_version_endpoint_reports_rules(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from api.server import create_app
    token = "v" * 32
    api = TestClient(create_app(_config(tmp_path), token=token, isolate=False))
    v = api.get("/version", headers={"Authorization": f"Bearer {token}"}).json()
    assert v["rules"]["source"] == "bundled" and v["profile"] == "standard"
    assert v["external_services"]["llm"] == "off"
