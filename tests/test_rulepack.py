"""Signed rule packs: build, sign, verify, install, refuse anything tampered."""

import io
import json
import tarfile
from pathlib import Path

import pytest

import RansomwareScanner as RS
from core.rulepack import (
    RulePackError,
    active_pack,
    build_pack,
    generate_keypair,
    install_pack,
    sign_pack,
    verify_pack,
)
from tests.test_scanner_integration import _config
from tools.rulepack import main as cli

ROOT = Path(__file__).resolve().parent.parent
RULE = """rule Pack_Test_Marker { meta: severity = "high"
  strings: $a = "AEGIS-PACK-TEST-MARKER" condition: $a }"""


@pytest.fixture
def keys(tmp_path):
    priv, pub = generate_keypair(tmp_path / "keys")
    return priv, pub


def make_pack(tmp_path, keys, version="2026.10.21", rule=RULE, fuzzy=None):
    rules = tmp_path / f"src-{version}"
    rules.mkdir(exist_ok=True)
    (rules / "pack.yar").write_text(rule)
    pack = build_pack(rules, version, tmp_path / f"pack-{version}.tar.gz", fuzzy)
    sign_pack(pack, keys[0])
    return pack


def test_round_trip_and_install(tmp_path, keys):
    pack = make_pack(tmp_path, keys)
    checked = verify_pack(pack, [keys[1]])
    assert checked["manifest"]["version"] == "2026.10.21" and "rules/pack.yar" in checked["files"]
    info = install_pack(pack, tmp_path / "data", [keys[1]], "4.4.0-beta.2")
    assert active_pack(tmp_path / "data")["version"] == info["version"]
    assert (Path(info["path"]) / "rules" / "pack.yar").is_file()


def test_scanner_uses_the_installed_pack(tmp_path, keys):
    install_pack(make_pack(tmp_path, keys), tmp_path / "data", [keys[1]], "4.4.0")
    cfg = _config(tmp_path, data_dir=str(tmp_path / "data"))
    s = RS.RansomwareScanner(cfg)
    p = tmp_path / "scan" / "notes.txt"
    p.write_text("hello AEGIS-PACK-TEST-MARKER")
    r = s.scan_file(str(p))
    assert [m["rule"] for m in r["scan_results"]["yara"]["matches"]] == ["Pack_Test_Marker"]


@pytest.mark.parametrize("damage", ["flip", "wrong_key", "no_sig", "no_keys"])
def test_tampered_or_unsigned_packs_are_refused(tmp_path, keys, damage):
    pack = make_pack(tmp_path, keys)
    pubs = [keys[1]]
    if damage == "flip":
        data = bytearray(pack.read_bytes())
        data[len(data) // 2] ^= 0xFF
        pack.write_bytes(bytes(data))
    elif damage == "wrong_key":
        pubs = [generate_keypair(tmp_path / "other")[1]]
    elif damage == "no_sig":
        Path(str(pack) + ".sig").unlink()
    else:
        pubs = []
    with pytest.raises(RulePackError):
        install_pack(pack, tmp_path / "data", pubs, "4.4.0")
    assert active_pack(tmp_path / "data") is None


def _signed_raw_pack(tmp_path, keys, entries, manifest_files=None):
    """A pack built by hand (to smuggle bad entries in), validly signed."""
    pack = tmp_path / "evil.tar.gz"
    files = {n: d for n, d in entries if n != "manifest.json"}
    import hashlib
    manifest = {"format": 1, "version": "9.9", "min_engine": "4.4.0",
                "files": manifest_files if manifest_files is not None else
                {n: hashlib.sha256(d).hexdigest() for n, d in files.items()}}
    with tarfile.open(pack, "w:gz") as tar:
        for name, data in [("manifest.json", json.dumps(manifest).encode())] + entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    sign_pack(pack, keys[0])
    return pack


@pytest.mark.parametrize("entries,manifest_files", [
    ([("../escape.yar", b"rule a {condition: true}")], None),
    ([("/abs.yar", b"rule a {condition: true}")], None),
    ([("rules/run.sh", b"echo hi")], None),
    ([("rules/a.yar", b"rule a {condition: true}")], {"rules/a.yar": "0" * 64}),
    ([("rules/a.yar", b"rule a {condition: true}")], {}),
])
def test_signed_but_malformed_packs_are_refused(tmp_path, keys, entries, manifest_files):
    pack = _signed_raw_pack(tmp_path, keys, entries, manifest_files)
    with pytest.raises(RulePackError):
        install_pack(pack, tmp_path / "data", [keys[1]], "4.4.0")


def test_versions_are_monotonic_unless_rolling_back(tmp_path, keys):
    install_pack(make_pack(tmp_path, keys, "2026.10.21"), tmp_path / "data", [keys[1]], "4.4.0")
    old = make_pack(tmp_path, keys, "2026.9.1")
    with pytest.raises(RulePackError, match="not newer"):
        install_pack(old, tmp_path / "data", [keys[1]], "4.4.0")
    assert install_pack(old, tmp_path / "data", [keys[1]], "4.4.0", allow_downgrade=True)["version"] == "2026.9.1"


def test_rules_that_do_not_compile_are_refused(tmp_path, keys):
    pytest.importorskip("yara")
    bad = make_pack(tmp_path, keys, "2026.11.1", rule="rule broken { condition: }")
    with pytest.raises(RulePackError, match="compile"):
        install_pack(bad, tmp_path / "data", [keys[1]], "4.4.0")


def test_engine_too_old(tmp_path, keys):
    rules = tmp_path / "r"
    rules.mkdir()
    (rules / "a.yar").write_text(RULE)
    pack = build_pack(rules, "1", tmp_path / "p.tar.gz", min_engine="9.0.0")
    sign_pack(pack, keys[0])
    with pytest.raises(RulePackError, match="needs engine"):
        install_pack(pack, tmp_path / "data", [keys[1]], "4.4.0-beta.2")


def test_cli(tmp_path, capsys):
    assert cli(["keygen", str(tmp_path / "k")]) == 0
    pub = (tmp_path / "k" / "rulepack_public.txt").read_text().strip()
    assert cli(["build", str(ROOT / "rules"), "--version", "1.0", "--out", str(tmp_path / "p.tar.gz")]) == 0
    assert cli(["sign", str(tmp_path / "p.tar.gz"), "--key", str(tmp_path / "k" / "rulepack_private.pem")]) == 0
    assert cli(["verify", str(tmp_path / "p.tar.gz"), "--pub", pub]) == 0
    assert "OK: version 1.0" in capsys.readouterr().out
