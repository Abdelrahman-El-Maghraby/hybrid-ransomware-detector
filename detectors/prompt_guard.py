#!/usr/bin/env python3
"""
detectors/prompt_guard.py — Concealed text extractor (.docx/HTML), prompt-injection
classifier, and nonce-delimited spotlighting guard.
"""

from __future__ import annotations

import logging
import re
import secrets
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import defusedxml.ElementTree as DET

logger = logging.getLogger("AegisSentinel.prompt_guard")

CONFIRMED_INJECTION_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I), "ignore_previous_instructions"),
    (re.compile(r"disregard\s+(?:all\s+)?(?:previous|system)\s+instructions", re.I), "disregard_system_instructions"),
    (re.compile(r"system\s*override\s*[:=-]?\s*mark\s+(?:this\s+)?(?:file|document)\s+(?:as\s+)?(?:clean|safe|benign)", re.I), "override_verdict_clean"),
    (re.compile(r"output\s+only\s+[\"']?\{?\s*[\"']?is_malicious[\"']?\s*:\s*false", re.I), "force_json_is_malicious_false"),
    (re.compile(r"</?UNTRUSTED_DATA_", re.I), "delimiter_escape_attempt"),
)

SUSPICIOUS_INJECTION_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.I), "developer_mode_jailbreak"),
    (re.compile(r"do\s+not\s+flag\s+this\s+(?:file|document|email)", re.I), "do_not_flag_directive"),
)


def wrap_untrusted_with_nonce(untrusted_text: str) -> Tuple[str, str]:
    nonce = secrets.token_hex(16).upper()
    sanitized = re.sub(r"(?i)</?UNTRUSTED_DATA_[A-F0-9]*>", "[NEUTRALIZED_TAG]", untrusted_text or "")
    open_tag = f"<UNTRUSTED_DATA_{nonce}>"
    close_tag = f"</UNTRUSTED_DATA_{nonce}>"
    return f"{open_tag}\n{sanitized}\n{close_tag}", nonce


@dataclass
class HiddenTextResult:
    hidden_text_found: bool = False
    hidden_reasons: List[str] = field(default_factory=list)
    hidden_text_snippets: List[str] = field(default_factory=list)


@dataclass
class PromptGuardResult:
    hidden_text_found: bool = False
    hidden_reasons: List[str] = field(default_factory=list)
    hidden_text_snippets: List[str] = field(default_factory=list)
    injection_status: str = "none"  # "none" | "suspicious" | "confirmed"
    injection_indicators: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "hidden_text_found": self.hidden_text_found,
            "hidden_reasons": self.hidden_reasons,
            "hidden_text_snippets": self.hidden_text_snippets[:10],
            "injection_status": self.injection_status,
            "injection_indicators": self.injection_indicators,
        }


class PromptGuard:
    W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

    def inspect_docx_hidden_text(self, file_path: str | Path) -> HiddenTextResult:
        path = Path(file_path)
        if path.suffix.lower() not in (".docx", ".docm", ".dotm") or not zipfile.is_zipfile(path):
            return HiddenTextResult()

        reasons: List[str] = []
        snippets: List[str] = []
        try:
            with zipfile.ZipFile(path, "r") as zf:
                if "word/document.xml" not in zf.namelist():
                    return HiddenTextResult()
                xml_bytes = zf.read("word/document.xml")
            root = DET.fromstring(xml_bytes)
            for run in root.iter(f"{self.W_NS}r"):
                rpr = run.find(f"{self.W_NS}rPr")
                if rpr is None:
                    continue
                run_reasons: List[str] = []
                if rpr.find(f"{self.W_NS}vanish") is not None or rpr.find(f"{self.W_NS}webHidden") is not None:
                    run_reasons.append("w:vanish/webHidden")
                sz = rpr.find(f"{self.W_NS}sz")
                if sz is not None:
                    val = sz.attrib.get(f"{self.W_NS}val") or sz.attrib.get("val")
                    if val and val.isdigit() and int(val) <= 4:
                        run_reasons.append(f"micro_font_half_pt={val}")
                col = rpr.find(f"{self.W_NS}color")
                if col is not None:
                    cval = (col.attrib.get(f"{self.W_NS}val") or col.attrib.get("val") or "").upper()
                    if len(cval) == 6 and all(c in "0123456789ABCDEF" for c in cval):
                        r, g, b = int(cval[0:2], 16), int(cval[2:4], 16), int(cval[4:6], 16)
                        if r >= 240 and g >= 240 and b >= 240:
                            run_reasons.append(f"white_text_color=#{cval}")

                if run_reasons:
                    txt = "".join((t.text or "") for t in run.iter(f"{self.W_NS}t")).strip()
                    if txt:
                        reasons.extend(run_reasons)
                        snippets.append(txt[:300])
        except Exception as exc:
            logger.debug("Hidden text XML inspection skipped on %s: %s", path, exc)

        return HiddenTextResult(
            hidden_text_found=bool(snippets),
            hidden_reasons=sorted(set(reasons)),
            hidden_text_snippets=snippets,
        )

    def inspect_html_hidden_text(self, html_text: str) -> HiddenTextResult:
        if not html_text:
            return HiddenTextResult()
        reasons: List[str] = []
        snippets: List[str] = []
        pattern = re.compile(
            r"<([a-zA-Z0-9]+)\b[^>]*style\s*=\s*['\"]([^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^'\"]*)['\"][^>]*>(.*?)</\1>",
            re.I | re.S,
        )
        for m in pattern.finditer(html_text):
            style_str = m.group(2).strip()
            inner = re.sub(r"<[^>]+>", " ", m.group(3)).strip()
            if inner:
                reasons.append(f"css_hidden({style_str[:40]})")
                snippets.append(inner[:300])
        return HiddenTextResult(bool(snippets), sorted(set(reasons)), snippets)

    def analyze_text_for_injection(
        self,
        visible_text: str,
        embedded_strings: str = "",
        hidden_result: Optional[HiddenTextResult] = None,
    ) -> PromptGuardResult:
        h_res = hidden_result or HiddenTextResult()
        corpus = "\n".join([visible_text or "", embedded_strings or "", "\n".join(h_res.hidden_text_snippets)])

        confirmed: List[str] = []
        suspicious: List[str] = []
        for rx, name in CONFIRMED_INJECTION_PATTERNS:
            if rx.search(corpus):
                confirmed.append(name)
        for rx, name in SUSPICIOUS_INJECTION_PATTERNS:
            if rx.search(corpus):
                suspicious.append(name)

        status = "none"
        if confirmed or (suspicious and h_res.hidden_text_found):
            status = "confirmed"
        elif suspicious:
            status = "suspicious"

        return PromptGuardResult(
            hidden_text_found=h_res.hidden_text_found,
            hidden_reasons=h_res.hidden_reasons,
            hidden_text_snippets=h_res.hidden_text_snippets,
            injection_status=status,
            injection_indicators=sorted(set(confirmed + suspicious)),
        )