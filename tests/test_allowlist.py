"""4.4.0-beta.2: SHA-256 allowlist for known-good files."""

import hashlib

import RansomwareScanner as RS
from core.allowlist import load_allowlist
from tests.test_scanner_integration import _config

INSTALLER = (b"$c = New-Object Net.WebClient\r\n"
             b"$c.DownloadFile('https://example.invalid/setup.msi', \"$env:TEMP\\setup.msi\")\r\n"
             b"Start-Process msiexec.exe -ArgumentList '/i', \"$env:TEMP\\setup.msi\"\r\n")


def test_file_format(tmp_path):
    p = tmp_path / "allow.txt"
    good = "a" * 64
    p.write_text(f"# comment\n\n{good.upper()}  # vendor script\nnot-a-hash\n{'b' * 64}\n")
    assert load_allowlist(p) == {good: "vendor script", "b" * 64: ""}
    assert load_allowlist(tmp_path / "missing.txt") == {} and load_allowlist(None) == {}


def _scanner(tmp_path, entries):
    cfg = _config(tmp_path)
    allow = tmp_path / "allow.txt"
    allow.write_text("".join(f"{h}  # {n}\n" for h, n in entries))
    cfg["allowlist_path"] = str(allow)
    return RS.RansomwareScanner(cfg)


def test_allowlisted_installer_is_clean_but_findings_are_kept(tmp_path):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = tmp_path / "scan" / "install.ps1"
    p.write_bytes(INSTALLER)
    digest = hashlib.sha256(INSTALLER).hexdigest()

    before = _scanner(tmp_path, []).scan_file(str(p))
    assert before["verdict"] == "High"

    s = _scanner(tmp_path, [(digest, "vendor installer")])
    r = s.scan_file(str(p))
    assert r["verdict"] == "Clean" and r["risk_score"] == 0 and not r["is_malicious"]
    assert r["scan_results"]["script_analysis"]["dropper"]              # evidence kept
    assert [c["indicator"] for c in r["score_breakdown"]["contributions"]] == ["allowlisted"]
    assert "llm" in r["scan_results"]["skipped_layers"]["layers"]
    assert "[Allowlist]" in s.generate_report([r])


def test_a_hash_in_the_malware_database_beats_the_allowlist(tmp_path):
    from detectors.scoring import ScoringMatrix
    s = ScoringMatrix().score({"allowlisted": "x", "local_db_hit": True})
    assert s.verdict == "Critical"


def test_allow_command_appends_once(tmp_path, capsys):
    f = tmp_path / "tool.ps1"
    f.write_bytes(INSTALLER)
    allow = tmp_path / "data" / "allow.txt"
    RS._allow_file(str(f), "checked by me", str(allow))
    RS._allow_file(str(f), "again", str(allow))
    lines = allow.read_text().splitlines()
    assert len(lines) == 1 and lines[0].endswith("# checked by me")
    assert "Already on the allowlist" in capsys.readouterr().out
