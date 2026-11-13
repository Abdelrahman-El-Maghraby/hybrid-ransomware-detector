"""S-Y1 to S-Y4: admin and build commands in the YARA rules. Examples are in
tests/sy_examples.py (inert; shortcuts are real shell-link structures).

Measured before the change (docs/HANDOFF.md, group 48): every harmless example
scored High or Critical except the S-Y1 log reset (Medium 40). After: harmless
Defender build scripts Medium 40 (the script layer still notes the exclusion:
they are not called safe), the admin shortcuts and the backup pre-freeze script
Clean; every harmful example keeps its verdict and rule. Two cases stay as
documented ambiguities: the S-Y1 log reset and the encryptor-shaped string set."""

import pytest

import RansomwareScanner as RS
from detectors.yara_engine import YARA_AVAILABLE
from tests.sy_examples import HARMFUL, HARMLESS
from tests.test_scanner_integration import _config

pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
HIGH = ("High", "Critical")
AMBIGUOUS = {"rotate_logs.ps1", "backup_agent.exe"}
RULE = {"S-Y1": "Event_Log_Clearing", "S-Y2": "PowerShell_Defender_Tampering",
        "S-Y3": "LNK_Shortcut_Runs_Script_Host"}


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sy")
    s = RS.RansomwareScanner(_config(tmp, isolate_scans=False, qr_scan_enabled=False))

    def run(name, data):
        p = tmp / "scan" / name
        p.write_bytes(data)
        return s.scan_file(str(p))
    yield run
    if s.cache is not None:
        s.cache.close()


def _rules(r):
    return {m["rule"] for m in r["scan_results"].get("yara", {}).get("matches", [])}


def _indicators(r):
    return {c["indicator"] for c in r["score_breakdown"]["contributions"]}


@pytest.mark.parametrize("sid,name,data", [h for h in HARMLESS if h[1] not in AMBIGUOUS],
                         ids=[h[1] for h in HARMLESS if h[1] not in AMBIGUOUS])
def test_one_admin_command_alone_is_not_an_attack(scan, sid, name, data):
    r = scan(name, data)
    assert r["verdict"] not in HIGH, (r["verdict"], _rules(r))


def test_a_defender_exclusion_is_still_noted(scan):
    sid, name, data = next(h for h in HARMLESS if h[1] == "build_agent_setup.ps1")
    r = scan(name, data)
    assert r["verdict"] == "Medium" and "script_behaviour" in _indicators(r)


@pytest.mark.parametrize("sid,name,data", HARMFUL, ids=[h[1] for h in HARMFUL])
def test_the_techniques_keep_their_rule_and_verdict(scan, sid, name, data):
    r = scan(name, data)
    rule = RULE.get(sid) or ("Ransomware_Encryptor_Target_Extensions" if name.endswith(".exe")
                             else "Ransomware_Stops_Services_And_Processes")
    assert rule in _rules(r)
    assert r["verdict"] in (("Medium",) if sid == "S-Y1" else HIGH)


@pytest.mark.parametrize("name", sorted(AMBIGUOUS))
def test_documented_ambiguities_are_unchanged(scan, name):
    """The same observable strings as the technique: left as they were, on purpose."""
    sid, _, data = next(h for h in HARMLESS if h[1] == name)
    assert RULE.get(sid, "Ransomware_Encryptor_Target_Extensions") in _rules(scan(name, data))


def test_the_shortcut_fixture_is_a_real_shell_link():
    from tests.sy_examples import LINK_CLSID, shell_link
    data = shell_link(r"..\cmd.exe", "/c dir")
    assert data[:4] == b"\x4c\x00\x00\x00" and data[4:20] == LINK_CLSID
    assert int.from_bytes(data[20:24], "little") & 0xA8 == 0xA8   # path, arguments, unicode
