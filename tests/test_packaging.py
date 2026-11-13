"""M15: a wheel (a non-editable install) must ship the bundled YARA rules and the
scanner must find them there. The source tree's rules/ is packaged as
`aegis_sentinel_rules`; engine/config.py finds rules/ next to the code first
(source tree, editable install, PyInstaller bundle, Docker image) and the
installed package otherwise. The full check - a wheel built from a clean export
and installed into a new environment outside the tree - is recorded in
docs/HANDOFF.md (group 40); these tests keep its parts from drifting."""

import logging
import sys
from pathlib import Path

import pytest

from engine import config

ROOT = Path(__file__).resolve().parent.parent

try:
    import tomllib
except ImportError:                                  # Python < 3.11
    tomllib = None


@pytest.fixture
def setuptools_config():
    if tomllib is None:
        pytest.skip("tomllib needs Python 3.11+")
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]


def test_the_package_list_matches_the_code_packages(setuptools_config):
    from setuptools import find_namespace_packages
    code = set(find_namespace_packages(
        where=str(ROOT), include=["engine*", "detectors*", "core*", "aegis_gui*", "api*", "tools*"]))
    listed = set(setuptools_config["packages"])
    assert listed - {"aegis_sentinel_rules"} == code       # nothing missing, nothing extra
    assert setuptools_config["package-dir"] == {"aegis_sentinel_rules": "rules"}


def test_every_bundled_rule_file_is_package_data(setuptools_config):
    import fnmatch
    globs = setuptools_config["package-data"]["aegis_sentinel_rules"]
    files = [p.name for p in (ROOT / "rules").iterdir() if p.is_file()]
    assert files and all(any(fnmatch.fnmatch(f, g) for g in globs) for f in files)


def test_an_installed_copy_is_found_when_rules_is_not_next_to_the_code(tmp_path, monkeypatch):
    code = tmp_path / "site-packages"
    installed = code / "aegis_sentinel_rules"
    installed.mkdir(parents=True)
    (installed / "a.yar").write_text("rule A { condition: false }")
    monkeypatch.setattr(config, "SCRIPT_DIR", code)        # no rules/ beside the code
    monkeypatch.syspath_prepend(str(code))
    sys.modules.pop("aegis_sentinel_rules", None)
    assert config._bundled_rules_dir() == installed
    monkeypatch.setattr(config, "SCRIPT_DIR", ROOT)        # the source tree wins
    assert config._bundled_rules_dir() == ROOT / "rules"


def test_with_neither_the_default_stays_beside_the_code(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCRIPT_DIR", tmp_path)
    monkeypatch.setattr(sys, "path", [p for p in sys.path if "aegis_sentinel_rules" not in p])
    sys.modules.pop("aegis_sentinel_rules", None)
    assert config._bundled_rules_dir() == tmp_path / "rules"


def test_a_missing_rules_folder_is_a_warning(tmp_path, caplog):
    from detectors import yara_engine
    if not yara_engine.YARA_AVAILABLE:
        pytest.skip("yara-python not installed")
    caplog.set_level(logging.INFO, logger="RansomwareScanner")
    yara_engine.YaraEngine(rules_dir=str(tmp_path / "none"))
    assert any(r.levelno == logging.WARNING and "has no rules" in r.getMessage()
               for r in caplog.records)


def test_the_source_tree_still_uses_its_own_rules():
    assert config.BUNDLED_RULES_DIR == ROOT / "rules"
