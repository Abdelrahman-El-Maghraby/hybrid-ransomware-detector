"""4.7: a rules or configuration change never serves a stale answer."""

import shutil

import RansomwareScanner as RS
from detectors import llm_backends
from engine.config import BUNDLED_RULES_DIR
from tests.helpers import make_pdf
from tests.test_scanner_integration import _config


def test_llm_key_names_model_prompt_and_engine(tmp_path, monkeypatch):
    s = RS.RansomwareScanner(_config(tmp_path))
    key = s._llm_cache_layer()
    assert f"prompt-{llm_backends.PROMPT_VERSION}" in key and f"engine-{RS.ENGINE_VERSION}" in key
    monkeypatch.setattr(llm_backends, "PROMPT_VERSION", "edited")
    assert s._llm_cache_layer() != key


def test_vt_upload_setting_has_its_own_entries(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path))
    off = s._vt_cache_layer()
    s.config["virustotal_upload_unknown"] = True
    assert s._vt_cache_layer() != off


def test_rule_change_on_disk_is_used_by_the_next_scan(tmp_path):
    rules = tmp_path / "rules"
    shutil.copytree(BUNDLED_RULES_DIR, rules)
    s = RS.RansomwareScanner(_config(tmp_path, yara_rules_dir=str(rules)))
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(make_pdf("AEGIS-TEST-MARKER-7731"))
    first = s.scan_file(str(pdf))
    (rules / "zz_marker.yar").write_text(
        'rule test_marker { meta: severity = "low" strings: $a = "AEGIS-TEST-MARKER-7731" '
        'condition: $a }\n')
    second = s.scan_file(str(pdf))
    assert first["provenance"]["rules"]["sha256"] != second["provenance"]["rules"]["sha256"]
    assert "test_marker" in second["scan_results"]["yara"].get("matches_rules", str(second["scan_results"]["yara"]))
    assert s.refresh_detection_content() is False          # nothing changed since
