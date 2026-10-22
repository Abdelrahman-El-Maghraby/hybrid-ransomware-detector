"""The indicator registry (detectors/indicators.yaml) is the single source of
weights, categories and labels."""

import re
from pathlib import Path

import pytest
import yaml

from detectors.registry import REGISTRY, load_overrides, load_registry
from detectors.scoring import ScoringMatrix

ROOT = Path(__file__).resolve().parent.parent
SCORING = (ROOT / "detectors" / "scoring.py").read_text()


def emitted():
    return set(re.findall(r'Contribution\(\s*"([a-z_]+)",\s*"(\w+)"', SCORING))


def test_every_emitted_indicator_is_registered_with_its_category():
    for name, category in emitted():
        assert name in REGISTRY.indicators, name
        assert REGISTRY.indicators[name]["category"] == category, name


def test_every_weight_used_in_code_exists_and_nothing_is_hardcoded():
    used = set(re.findall(r"self\.(W_[A-Z0-9_]+)", SCORING))
    assert used <= set(REGISTRY.weights)
    assert not re.search(r"^\s+W_[A-Z0-9_]+\s*=", SCORING, re.M)      # no literals left
    for entry in REGISTRY.indicators.values():
        if "weight" in entry:
            assert entry["weight"] in REGISTRY.weights


def test_labels_and_caps():
    assert REGISTRY.label("mail_attachment:archive_member:yara_match") == "YARA rule match"
    assert REGISTRY.label("not_registered_thing") == "not registered thing"
    assert REGISTRY.caps["semantic"] < 50 and REGISTRY.semantic_only_max == 49


def test_overrides_change_one_instance_only(tmp_path):
    ov = tmp_path / "w.yaml"
    ov.write_text("weights:\n  W_DISGUISED_EXECUTABLE: 50.0\n")
    m = ScoringMatrix(load_overrides(ov))
    s = m.score({"integrity": {"disguised_executable": "pe"}})
    assert s.risk_score == 50 and s.registry_version.endswith("+override")
    assert ScoringMatrix().score({"integrity": {"disguised_executable": "pe"}}).risk_score == 90
    with pytest.raises(KeyError):
        ScoringMatrix({"W_NOT_A_WEIGHT": 1.0})
    with pytest.raises(TypeError):
        ScoringMatrix({"W_YARA": 10.0})
    assert load_overrides(tmp_path / "missing.yaml") == {}


def test_registry_file_round_trips(tmp_path):
    data = yaml.safe_load((ROOT / "detectors" / "indicators.yaml").read_text())
    p = tmp_path / "copy.yaml"
    p.write_text(yaml.safe_dump(data))
    assert load_registry(p).weights == REGISTRY.weights
