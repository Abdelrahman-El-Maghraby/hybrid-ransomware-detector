"""engine/report.py: one renderer per layer (FINDING_SECTIONS)."""

from engine.report import FINDING_SECTIONS, _breakdown_lines, _quarantine_lines

RICH = {
    "local_database": {"is_malicious": True},
    "fuzzy_hash": {"matched": True, "matches": [{"family": "F"}], "best_confidence": 0.9},
    "macro_analysis": {"has_macros": True, "autoexec": ["AutoOpen"], "critical": ["Shell"],
                       "vba_stomping": True, "xlm_macros": True, "xlm_evidence": ["EXEC"]},
    "yara": {"matched": True, "matches": [{"rule": "R"}], "top_severity": "high"},
    "file_integrity": {"format_mismatch": True, "detail": "fi"},
    "prompt_guard": {"hidden_text_found": True, "hidden_reasons": ["white"],
                     "injection_status": "confirmed", "injection_indicators": ["ignore"]},
    "elf_analysis": {"packed": True, "detail": "elf"},
    "sandbox": {"detail": "sb", "network_hosts": ["http://a.example"]},
    "allowlist": {"allowlisted": True, "note": "n"},
    "script_analysis": {"behaviour": ["x"], "detail": "sd", "urls": ["http://u.example"]},
    "embedded": {"detail": "ed", "member_results": [{"name": "a", "verdict": "High", "risk_score": 60}]},
    "qr_codes": {"available": False, "detail": "qd",
                 "codes": [{"is_url": True, "payload": "http://q.example", "suspicious_reasons": ["ip"]}]},
    "relationships": {"findings": [{"kind": "attachedTemplate", "target": "http://t.example"}]},
    "archive": {"detail": "ad", "executable_members": ["x.exe"],
                "member_results": [{"name": "x.exe", "verdict": "High", "risk_score": 60}]},
    "mail": {"detail": "md", "subject": "S", "deceptive_links": ["http://d.example"],
             "attachment_results": [{"name": "x", "verdict": "High", "risk_score": 65}]},
    "web": {"detail": "see http://w.example/x", "redirects": ["http://r.example"],
            "payload_results": [{"name": "p", "verdict": "High", "risk_score": 70}]},
    "ml_classifier": {"label": "suspicious", "model": "rules", "probability": 0.7, "indicators": ["i"]},
    "virustotal": {"is_malicious": True, "malicious_detections": 3, "total_engines": 70,
                   "permalink": "https://vt"},
    "chatgpt_analysis": {"is_malicious": True, "confidence": 0.8, "suspicious_elements": ["e"]},
    "emulation": {"ran": True, "detail": "Emulation: 1 URL(s) contacted.",
                  "urls": ["http://e.example/a.exe"], "commands": ["a.exe"]},
    "skipped_layers": {"layers": ["ml"]},
}
TAGS = ["[Local DB]", "[Fuzzy]", "[Macro]", "[YARA]", "[Integrity]", "[Hidden]", "[ELF]",
        "[Sandbox]", "[Allowlist]", "[Script]", "[Embedded]", "[QR]", "[External]", "[Archive]",
        "[Mail]", "[Web]", "[ML]", "[VT]", "[Semantic]", "[Emulation]", "[Skipped]"]


def test_every_section_is_silent_without_findings():
    assert all(section({}) == [] for section in FINDING_SECTIONS)
    assert _quarantine_lines({}) == [] and _breakdown_lines({}) == []


def test_sections_render_in_order_and_defang_links():
    lines = [line for section in FINDING_SECTIONS for line in section(RICH)]
    text = "\n".join(lines)
    positions = [text.index(tag) for tag in TAGS]
    assert positions == sorted(positions)
    assert "http://" not in text and "hxxp://" in text          # every link defanged
    assert "-> Auto-exec + exec primitive = classic dropper pattern." in text


def test_quarantine_and_breakdown():
    assert "id q1" in _quarantine_lines({"id": "q1"})[0]
    assert "FAILED: e" in _quarantine_lines({"error": "e"})[0]
    out = _breakdown_lines({"contributions": [{"points": 65, "category": "technical",
                                               "indicator": "yara_match"}],
                            "category_totals": {"technical": 65, "semantic": 0}})
    assert out == ["  Score breakdown:", "    +  65.0  [technical] yara_match",
                   "    = category totals: technical=65"]
