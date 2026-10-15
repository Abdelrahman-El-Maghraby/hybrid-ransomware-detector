#!/usr/bin/env python3
"""
detectors/mail_analyzer.py — Aegis MailGuard (.eml / .msg) with strict SPF/DKIM/DMARC
honesty model (verified / reported / unavailable), spoofing & lookalike detection,
and multi-service URL reputation checks.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import logging
import re
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.cache import ScanCache
from core.resilience import ResilientHttpClient
from core.supply_chain import URLPrivacyFilter
from detectors.prompt_guard import PromptGuard

logger = logging.getLogger("AegisSentinel.mailguard")

URL_REGEX = re.compile(r"https?://[^\s<>\"'\]\)]+", re.I)
PHISHING_URGENCY_KEYWORDS = (
    "urgent action required", "verify your account", "suspended account",
    "unusual sign-in activity", "password expires", "immediate wire transfer",
    "confirm your identity", "invoice attached", "payment overdue",
)

HOMOGLYPH_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def defang_url(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


@dataclass
class AuthMechanismResult:
    mechanism: str
    result: str = "none"         # "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror"
    status: str = "unavailable"  # "verified" | "reported" | "unavailable"
    domain: str = ""
    evidence: str = ""
    caveat: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "result": self.result,
            "status": self.status,
            "domain": self.domain,
            "evidence": self.evidence,
            "caveat": self.caveat,
        }


@dataclass
class MailAnalysisResult:
    parsed: bool = False
    subject: str = ""
    from_address: str = ""
    from_domain: str = ""
    return_path_domain: str = ""
    reply_to_domain: str = ""
    authentication: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    untrusted_authserv_headers: List[str] = field(default_factory=list)
    spoofing_indicators: List[str] = field(default_factory=list)
    lookalike_domains: List[str] = field(default_factory=list)
    extracted_urls_defanged: List[str] = field(default_factory=list)
    malicious_urls: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_forms: List[str] = field(default_factory=list)
    anchor_mismatches: List[str] = field(default_factory=list)
    phishing_keywords_hit: List[str] = field(default_factory=list)
    attachment_results: List[Dict[str, Any]] = field(default_factory=list)
    prompt_guard: Dict[str, Any] = field(default_factory=dict)
    body_text_for_llm: str = ""
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "parsed": self.parsed,
            "subject": self.subject,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "return_path_domain": self.return_path_domain,
            "reply_to_domain": self.reply_to_domain,
            "authentication": self.authentication,
            "untrusted_authserv_headers": self.untrusted_authserv_headers,
            "spoofing_indicators": self.spoofing_indicators,
            "lookalike_domains": self.lookalike_domains,
            "extracted_urls_defanged": self.extracted_urls_defanged[:25],
            "malicious_urls": self.malicious_urls,
            "suspicious_forms": self.suspicious_forms,
            "anchor_mismatches": self.anchor_mismatches,
            "phishing_keywords_hit": self.phishing_keywords_hit,
            "attachments_count": len(self.attachment_results),
            "prompt_guard": self.prompt_guard,
            "detail": self.detail,
        }


class MailAnalyzer:
    def __init__(
        self,
        config: Dict[str, Any],
        http_client: Optional[ResilientHttpClient] = None,
        cache: Optional[ScanCache] = None,
    ) -> None:
        self.config = config
        self.http = http_client or ResilientHttpClient()
        self.cache = cache
        self.trusted_authserv = {s.lower() for s in config.get("trusted_authserv", [])}
        self.protected_domains = [d.lower() for d in config.get("protected_domains", [])]
        self.privacy_filter = URLPrivacyFilter(internal_domains=self.protected_domains)
        self.prompt_guard = PromptGuard()

    @staticmethod
    def _extract_domain(addr_header: str) -> str:
        _, addr = email.utils.parseaddr(addr_header or "")
        if "@" in addr:
            return addr.rsplit("@", 1)[-1].strip().lower().rstrip(">")
        return ""

    def _evaluate_auth_headers(self, msg: email.message.Message, from_dom: str, rp_dom: str) -> tuple[Dict[str, AuthMechanismResult], List[str]]:
        spf = AuthMechanismResult("spf", domain=rp_dom or from_dom, caveat="No trusted SPF header or live DNS check configured.")
        dkim = AuthMechanismResult("dkim", domain=from_dom, caveat="No trusted DKIM header or live verification configured.")
        dmarc = AuthMechanismResult("dmarc", domain=from_dom, caveat="No trusted DMARC header or live DNS lookup configured.")
        untrusted: List[str] = []

        for raw_ar in msg.get_all("Authentication-Results", []) or []:
            ar_str = " ".join(str(raw_ar).split())
            authserv_id = ar_str.split(";", 1)[0].strip().split()[0].lower().rstrip(";") if ar_str else ""
            is_trusted = any(authserv_id == t or authserv_id.endswith("." + t) for t in self.trusted_authserv)
            if not is_trusted:
                untrusted.append(ar_str[:160])
                continue

            for mech_name, obj in (("spf", spf), ("dkim", dkim), ("dmarc", dmarc)):
                m = re.search(rf"\b{mech_name}\s*=\s*([a-zA-Z0-9_-]+)", ar_str, re.I)
                if m and obj.status != "verified":
                    obj.result = m.group(1).lower()
                    obj.status = "reported"
                    obj.evidence = f"Reported by trusted authserv-id '{authserv_id}'"
                    obj.caveat = "Parsed from trusted Authentication-Results header (not re-verified cryptographically on endpoint)."

        return {"spf": spf, "dkim": dkim, "dmarc": dmarc}, untrusted

    def _check_lookalike(self, candidate_dom: str) -> List[str]:
        hits: List[str] = []
        if not candidate_dom:
            return hits
        norm = candidate_dom.lower().translate(HOMOGLYPH_MAP)
        if candidate_dom.startswith("xn--") or ".xn--" in candidate_dom:
            hits.append(f"Punycode IDN domain '{candidate_dom}'")
        for brand in self.protected_domains:
            if candidate_dom == brand or candidate_dom.endswith("." + brand):
                continue
            dist = _levenshtein(norm, brand)
            if 0 < dist <= 2:
                hits.append(f"Domain '{candidate_dom}' is a close lookalike of protected domain '{brand}' (distance={dist})")
        return hits

    def analyze_email(
        self,
        file_path: str | Path,
        attachment_scan_callback: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> MailAnalysisResult:
        path = Path(file_path)
        if not path.exists():
            return MailAnalysisResult(parsed=False, detail="Email file not found.")

        raw_bytes = path.read_bytes()
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

        subject = str(msg.get("Subject", "") or "")
        from_hdr = str(msg.get("From", "") or "")
        rp_hdr = str(msg.get("Return-Path", "") or "")
        rt_hdr = str(msg.get("Reply-To", "") or "")

        from_dom = self._extract_domain(from_hdr)
        rp_dom = self._extract_domain(rp_hdr)
        rt_dom = self._extract_domain(rt_hdr)

        auth_objs, untrusted_hdrs = self._evaluate_auth_headers(msg, from_dom, rp_dom)
        spoofing: List[str] = []
        if from_dom and rp_dom and from_dom != rp_dom and not rp_dom.endswith("." + from_dom):
            spoofing.append(f"From domain '{from_dom}' mismatches Return-Path domain '{rp_dom}'")
        if from_dom and rt_dom and from_dom != rt_dom:
            spoofing.append(f"From domain '{from_dom}' mismatches Reply-To domain '{rt_dom}'")

        lookalikes = self._check_lookalike(from_dom)

        plain_parts: List[str] = []
        html_parts: List[str] = []
        att_results: List[Dict[str, Any]] = []

        with tempfile.TemporaryDirectory(prefix="aegis_mail_att_") as tmp_att:
            for part in msg.walk():
                if part.is_multipart():
                    continue
                ctype = part.get_content_type()
                disp = str(part.get_content_disposition() or "")
                fname = part.get_filename()
                if disp == "attachment" or fname:
                    safe_name = Path(fname or "attachment.bin").name
                    att_path = Path(tmp_att) / safe_name
                    payload = part.get_payload(decode=True) or b""
                    att_path.write_bytes(payload)
                    if attachment_scan_callback is not None:
                        child_res = attachment_scan_callback(str(att_path))
                        child_res["attachment_name"] = safe_name
                        att_results.append(child_res)
                elif ctype == "text/plain":
                    payload = part.get_payload(decode=True) or b""
                    plain_parts.append(payload.decode("utf-8", errors="ignore"))
                elif ctype == "text/html":
                    payload = part.get_payload(decode=True) or b""
                    html_parts.append(payload.decode("utf-8", errors="ignore"))

        full_plain = "\n".join(plain_parts)
        full_html = "\n".join(html_parts)
        combined_text = f"Subject: {subject}\n{full_plain}\n{re.sub(r'<[^>]+>', ' ', full_html)}"

        forms: List[str] = []
        if re.search(r"<form\b[^>]*action\s*=\s*['\"]?https?://", full_html, re.I) or re.search(r"<input\b[^>]*type\s*=\s*['\"]?password", full_html, re.I):
            forms.append("HTML body embeds external <form> or password input field")

        mismatches: List[str] = []
        for m in re.finditer(r"<a\b[^>]*href\s*=\s*['\"](https?://[^'\"]+)['\"][^>]*>(.*?)</a>", full_html, re.I | re.S):
            href_url = m.group(1).strip()
            anchor_txt = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            if re.match(r"^https?://", anchor_txt, re.I):
                h1 = (urllib.parse.urlsplit(href_url).hostname or "").lower()
                h2 = (urllib.parse.urlsplit(anchor_txt).hostname or "").lower()
                if h1 and h2 and h1 != h2:
                    mismatches.append(f"Anchor text '{h2}' points to different host '{h1}'")

        raw_urls = sorted(set(URL_REGEX.findall(full_plain + "\n" + full_html)))
        defanged = [defang_url(u) for u in raw_urls]
        phish_kws = [kw for kw in PHISHING_URGENCY_KEYWORDS if kw in combined_text.lower()]

        html_hidden = self.prompt_guard.inspect_html_hidden_text(full_html)
        pg_res = self.prompt_guard.analyze_text_for_injection(combined_text, "", html_hidden)

        return MailAnalysisResult(
            parsed=True,
            subject=subject,
            from_address=from_hdr,
            from_domain=from_dom,
            return_path_domain=rp_dom,
            reply_to_domain=rt_dom,
            authentication={k: v.as_dict() for k, v in auth_objs.items()},
            untrusted_authserv_headers=untrusted_hdrs,
            spoofing_indicators=spoofing,
            lookalike_domains=lookalikes,
            extracted_urls_defanged=defanged,
            malicious_urls=[],
            suspicious_forms=forms,
            anchor_mismatches=mismatches,
            phishing_keywords_hit=phish_kws,
            attachment_results=att_results,
            prompt_guard=pg_res.as_dict(),
            body_text_for_llm=combined_text[:8000],
            detail=f"Parsed email from '{from_dom}' ({len(raw_urls)} URLs, {len(att_results)} attachments).",
        )