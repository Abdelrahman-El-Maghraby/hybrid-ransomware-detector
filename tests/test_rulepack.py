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
    rollback_pack,
    sign_pack,
    trusted_fingerprints,
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


def test_versions_are_monotonic_and_older_content_is_never_installed(tmp_path, keys):
    """S6: an older or the same pack is refused - also with the old downgrade flag -
    so a pack with known gaps cannot be replayed."""
    install_pack(make_pack(tmp_path, keys, "2026.10.21"), tmp_path / "data", [keys[1]], "4.4.0")
    old = make_pack(tmp_path, keys, "2026.9.1")
    with pytest.raises(RulePackError, match="not newer"):
        install_pack(old, tmp_path / "data", [keys[1]], "4.4.0")
    with pytest.raises(RulePackError, match="not newer"):              # the same one again
        install_pack(make_pack(tmp_path, keys, "2026.10.21"), tmp_path / "data", [keys[1]], "4.4.0")
    with pytest.raises(RulePackError, match="signed rollback"):
        install_pack(old, tmp_path / "data", [keys[1]], "4.4.0", allow_downgrade=True)
    assert active_pack(tmp_path / "data")["version"] == "2026.10.21"


def test_a_signed_rollback_restores_the_previous_rules(tmp_path, keys):
    """The publisher re-issues the good content under a newer version."""
    good = make_pack(tmp_path, keys, "2026.10.21", rule=RULE)
    install_pack(good, tmp_path / "data", [keys[1]], "4.4.0")
    bad_rule = RULE.replace("Pack_Test_Marker", "Pack_Broken_Marker")
    install_pack(make_pack(tmp_path, keys, "2026.10.22", rule=bad_rule), tmp_path / "data",
                 [keys[1]], "4.4.0")
    back = rollback_pack(good, [keys[1]], "2026.10.23", tmp_path / "rollback.tar.gz")
    sign_pack(back, keys[0])
    info = install_pack(back, tmp_path / "data", [keys[1]], "4.4.0")
    assert info["version"] == "2026.10.23" and info["rollback_of"] == "2026.10.21"
    rules = list((Path(info["path"]) / "rules").glob("*.yar"))
    assert rules and "Pack_Test_Marker" in rules[0].read_text()
    assert "Pack_Broken_Marker" not in rules[0].read_text()
    unsigned = rollback_pack(good, [keys[1]], "2026.10.24", tmp_path / "unsigned.tar.gz")
    with pytest.raises(RulePackError, match="signature file missing"):
        install_pack(unsigned, tmp_path / "data", [keys[1]], "4.4.0")


def test_a_distrusted_key_drops_its_pack_and_does_not_block_recovery(tmp_path, keys):
    """Key compromise: an attacker signs a huge version to block every later update.
    Removing that key from RULEPACK_PUBLIC_KEYS stops its pack from being used at
    once, and a pack signed by the new key installs."""
    data = tmp_path / "data"
    evil = make_pack(tmp_path, keys, "9999.1")
    install_pack(evil, data, [keys[1]], "4.4.0")
    new_priv, new_pub = generate_keypair(tmp_path / "newkeys")
    assert active_pack(data, [keys[1], new_pub])["version"] == "9999.1"
    assert active_pack(data, [new_pub]) is None                      # old key removed
    scanner = RS.RansomwareScanner(_config(tmp_path, data_dir=str(data),
                                           rulepack_public_keys=[new_pub]))
    assert scanner.rulepack is None and scanner.provenance["rules"]["source"] != "rule pack"
    fresh = make_pack(tmp_path, (new_priv, new_pub), "2026.11.1")
    info = install_pack(fresh, data, [new_pub], "4.4.0")
    assert info["version"] == "2026.11.1"
    assert info["signer"] == trusted_fingerprints([new_pub])[0]
    with pytest.raises(RulePackError, match="not newer"):           # monotonic again
        install_pack(make_pack(tmp_path, (new_priv, new_pub), "2026.10.1"), data, [new_pub], "4.4.0")


def test_packs_installed_before_the_signer_was_recorded_stay_in_use(tmp_path, keys):
    import json
    info = install_pack(make_pack(tmp_path, keys), tmp_path / "data", [keys[1]], "4.4.0")
    active = tmp_path / "data" / "rulepacks" / "active.json"
    legacy = {k: v for k, v in json.loads(active.read_text()).items() if k != "signer"}
    active.write_text(json.dumps(legacy))
    assert active_pack(tmp_path / "data", [generate_keypair(tmp_path / "k2")[1]])["version"] == info["version"]


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


# ------------------------------------------------------------------ PR-01, PR-14
def _signed_pack_with_manifest(tmp_path, keys, **fields):
    """A well-formed, validly signed pack whose manifest carries `fields`."""
    import hashlib
    rule = b"rule a {condition: true}"
    manifest = {"format": 1, "version": "1", "min_engine": "4.4.0",
                "files": {"rules/a.yar": hashlib.sha256(rule).hexdigest()}}
    manifest.update(fields)
    pack = tmp_path / "crafted.tar.gz"
    with tarfile.open(pack, "w:gz") as tar:
        for name, data in [("manifest.json", json.dumps(manifest).encode()), ("rules/a.yar", rule)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    sign_pack(pack, keys[0])
    return pack


def _tree(path):
    return sorted(str(p.relative_to(path)) for p in path.rglob("*"))


BAD_VERSIONS = ["../../victim", "1/../../victim", "..", "../victim", "/tmp/victim", "victim",
                "1/2", "1\\..\\..\\victim", "C:\\victim", "C:victim", "1.2-beta", "", " 1.2",
                "1.2.", ".1", "1.2.3.4.5.6.7", 1.5, None, ["1"]]


@pytest.mark.parametrize("version", BAD_VERSIONS)
def test_a_signed_pack_with_a_path_like_version_is_refused(tmp_path, keys, version):
    """PR-01: the version names the install folder; a trusted signature does not
    make a traversal, absolute or separator-containing version acceptable."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    data = tmp_path / "a" / "b" / "data"                 # so ../../victim would resolve to it
    data.mkdir(parents=True)
    before = _tree(tmp_path)
    pack = _signed_pack_with_manifest(tmp_path, keys, version=version)
    with pytest.raises(RulePackError, match="not numeric"):
        verify_pack(pack, [keys[1]])
    with pytest.raises(RulePackError, match="not numeric"):
        install_pack(pack, data, [keys[1]], "4.4.0")
    assert (victim / "keep.txt").read_text() == "keep"
    after = [p for p in _tree(tmp_path) if not p.startswith("crafted.tar.gz")]
    assert after == before
    assert active_pack(data) is None


@pytest.mark.parametrize("rollback_of", ["../../victim", "C:\\x", "", "1.2-rc"])
def test_a_signed_pack_with_a_path_like_rollback_of_is_refused(tmp_path, keys, rollback_of):
    pack = _signed_pack_with_manifest(tmp_path, keys, version="2026.11.1", rollback_of=rollback_of)
    with pytest.raises(RulePackError, match="rollback_of"):
        install_pack(pack, tmp_path / "data", [keys[1]], "4.4.0")
    assert active_pack(tmp_path / "data") is None


def test_build_rollback_and_cli_refuse_a_non_numeric_version(tmp_path, keys, capsys):
    rules = tmp_path / "r"
    rules.mkdir()
    (rules / "a.yar").write_text(RULE)
    with pytest.raises(RulePackError, match="not numeric"):
        build_pack(rules, "../../victim", tmp_path / "p.tar.gz")
    assert not (tmp_path / "p.tar.gz").exists()
    good = make_pack(tmp_path, keys, "2026.10.21")
    with pytest.raises(RulePackError, match="not numeric"):
        rollback_pack(good, [keys[1]], "2026.10.23/../x", tmp_path / "back.tar.gz")
    assert not (tmp_path / "back.tar.gz").exists()
    assert cli(["build", str(rules), "--version", "1/../x", "--out", str(tmp_path / "c.tar.gz")]) == 1
    assert "not numeric" in capsys.readouterr().err


def test_numeric_versions_of_one_to_six_parts_install(tmp_path, keys):
    data = tmp_path / "data"
    for v in ["1", "2.0", "2026.11.02", "2026.11.02.1", "2026.11.02.1.0.7"]:
        info = install_pack(make_pack(tmp_path, keys, v), data, [keys[1]], "4.4.0")
        assert Path(info["path"]) == data / "rulepacks" / v


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="no symlinks")
def test_a_link_planted_at_the_install_folder_is_refused(tmp_path, keys):
    """Belt and braces: even a numeric version is refused when its folder name is
    a link that leads out of rulepacks/; the link target is left alone."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    root = tmp_path / "data" / "rulepacks"
    root.mkdir(parents=True)
    try:
        (root / "2026.11.1").symlink_to(victim, target_is_directory=True)
    except OSError:
        pytest.skip("cannot create symlinks here")
    with pytest.raises(RulePackError, match="outside"):
        install_pack(make_pack(tmp_path, keys, "2026.11.1"), tmp_path / "data", [keys[1]], "4.4.0")
    assert _tree(victim) == ["keep.txt"]
    assert active_pack(tmp_path / "data") is None


def test_active_record_is_replaced_atomically(tmp_path, keys, monkeypatch):
    """PR-14: the record is written to a temporary file and moved into place."""
    import core.rulepack as rp
    data = tmp_path / "data"
    install_pack(make_pack(tmp_path, keys, "2026.10.21"), data, [keys[1]], "4.4.0")
    replaced = []
    real_replace = rp.os.replace
    monkeypatch.setattr(rp.os, "replace", lambda a, b: (replaced.append((Path(a), Path(b))),
                                                        real_replace(a, b)))
    install_pack(make_pack(tmp_path, keys, "2026.10.22"), data, [keys[1]], "4.4.0")
    root = data / "rulepacks"
    assert replaced == [(root / ".active.json.tmp", root / "active.json")]
    assert not (root / ".active.json.tmp").exists()
    assert active_pack(data)["version"] == "2026.10.22"


def test_an_interrupted_record_write_keeps_the_previous_pack(tmp_path, keys, monkeypatch):
    import core.rulepack as rp
    data = tmp_path / "data"
    install_pack(make_pack(tmp_path, keys, "2026.10.21"), data, [keys[1]], "4.4.0")

    def crash(a, b):
        raise OSError("disk full")
    monkeypatch.setattr(rp.os, "replace", crash)
    with pytest.raises(OSError):
        install_pack(make_pack(tmp_path, keys, "2026.10.22"), data, [keys[1]], "4.4.0")
    assert active_pack(data)["version"] == "2026.10.21"


@pytest.mark.parametrize("content", ["{not json", json.dumps({"version": "1"}), ""])
def test_an_unreadable_record_is_logged_not_silent(tmp_path, content, caplog):
    root = tmp_path / "data" / "rulepacks"
    root.mkdir(parents=True)
    (root / "active.json").write_text(content)
    with caplog.at_level("WARNING", logger="RansomwareScanner"):
        assert active_pack(tmp_path / "data") is None
    assert [r.event for r in caplog.records if hasattr(r, "event")] == ["rulepack_unreadable"]


def test_a_record_whose_rules_folder_vanished_is_logged(tmp_path, keys, caplog):
    import shutil
    info = install_pack(make_pack(tmp_path, keys), tmp_path / "data", [keys[1]], "4.4.0")
    shutil.rmtree(Path(info["path"]) / "rules")
    with caplog.at_level("WARNING", logger="RansomwareScanner"):
        assert active_pack(tmp_path / "data") is None
    assert any(getattr(r, "event", "") == "rulepack_unreadable" for r in caplog.records)


def test_no_record_means_no_pack_and_no_warning(tmp_path, caplog):
    with caplog.at_level("WARNING", logger="RansomwareScanner"):
        assert active_pack(tmp_path / "data") is None
    assert not caplog.records
