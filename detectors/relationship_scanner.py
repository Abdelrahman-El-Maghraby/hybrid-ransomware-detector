#!/usr/bin/env python3
"""
detectors/relationship_scanner.py — defusedxml Office _rels/*.rels Remote Template
Injection (RTI) and Follina (ms-msdt:) scanner.
"""

from __future__ import annotations

import base64
import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import defusedxml.ElementTree as DET

from core.cache import ScanCache
from core.resilience import ResilientHttpClient

logger = logging.getLogger("AegisSentinel.rti")

SUSPICIOUS_SCHEMES = ("http://", "https://", "ftp://", "file://", "\\\\", "mhtml:", "ms-msdt:", "search-ms:")
RTF_TEMPLATE_RE = re.compile(r"\{\\\*\\template\s+([^}]+)\}", re.I)


@dataclass
class RelationshipFinding:
    source_part: str
    rel_id: str
    rel_type: str
    target: str
    target_mode: str
    vt_malicious: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_part": self.source_part,
            "rel_id": self.rel_id,
            "rel_type": self.rel_type,
            "target": self.target,
            "target_mode": self.target_mode,
            "vt_malicious": self.vt_malicious,
        }


@dataclass
class RelationshipScanResult:
    rti_detected: bool = False
    vt_malicious_urls: int = 0
    findings: List[RelationshipFinding] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rti_detected": self.rti_detected,
            "vt_malicious_urls": self.vt_malicious_urls,
            "findings": [f.as_dict() for f in self.findings],
            "detail": self.detail,
        }


class RelationshipScanner:
    OFFICE_XML_EXTS = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".rtf"}

    def __init__(
        self,
        vt_api_key: str = "",
        vt_url_api: str = "https://www.virustotal.com/api/v3/urls",
        http_client: Optional[ResilientHttpClient] = None,
        cache: Optional[ScanCache] = None,
    ) -> None:
        self.vt_api_key = vt_api_key.strip()
        self.vt_url_api = vt_url_api.rstrip("/")
        self.http = http_client or ResilientHttpClient()
        self.cache = cache

    def _check_vt_url(self, url: str) -> int:
        if not self.vt_api_key or not url.lower().startswith(("http://", "https://")):
            return 0
        if self.cache is not None:
            cached = self.cache.get_url_intel(url, "vt_rti")
            if cached is not None:
                return int(cached.get("malicious", 0))
        try:
            url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
            resp = self.http.get(f"{self.vt_url_api}/{url_id}", headers={"x-apikey": self.vt_api_key})
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = int(stats.get("malicious", 0) or 0) + int(stats.get("suspicious", 0) or 0)
                if self.cache is not None:
                    self.cache.put_url_intel(url, "vt_rti", {"malicious": mal})
                return mal
        except Exception:
            pass
        return 0

    def scan_file(self, file_path: str | Path) -> RelationshipScanResult:
        path = Path(file_path)
        ext = path.suffix.lower()
        if ext not in self.OFFICE_XML_EXTS or not path.exists():
            return RelationshipScanResult(detail="Not an OOXML/RTF relationship target.")

        findings: List[RelationshipFinding] = []
        vt_hits = 0

        if ext == ".rtf":
            try:
                txt = path.read_bytes()[: 2 * 1024 * 1024].decode("latin-1", errors="ignore")
                for m in RTF_TEMPLATE_RE.finditer(txt):
                    target = m.group(1).strip()
                    if target.lower().startswith(SUSPICIOUS_SCHEMES):
                        mal = self._check_vt_url(target)
                        if mal > 0:
                            vt_hits += 1
                        findings.append(RelationshipFinding("rtf_body", "rtf_template", "template", target, "External", mal))
            except Exception:
                pass
        elif zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    for member in zf.namelist():
                        if not (member.endswith(".rels") or member.endswith(".xml.rels")):
                            continue
                        xml_bytes = zf.read(member)
                        root = DET.fromstring(xml_bytes)
                        for elem in root.iter():
                            if not elem.tag.endswith("Relationship"):
                                continue
                            t_mode = (elem.attrib.get("TargetMode") or "").strip()
                            target = (elem.attrib.get("Target") or "").strip()
                            r_type = (elem.attrib.get("Type") or "").strip()
                            r_id = (elem.attrib.get("Id") or "").strip()

                            is_risky_type = any(k in r_type.lower() for k in ("attachedtemplate", "oleobject", "frame", "subdocument", "hyperlink"))
                            is_exploit_uri = target.lower().startswith(("ms-msdt:", "mhtml:", "search-ms:", "\\\\"))
                            if is_exploit_uri or (t_mode.lower() == "external" and is_risky_type and target.lower().startswith(SUSPICIOUS_SCHEMES)):
                                if "hyperlink" in r_type.lower() and not is_exploit_uri:
                                    continue
                                mal = self._check_vt_url(target)
                                if mal > 0:
                                    vt_hits += 1
                                findings.append(RelationshipFinding(member, r_id, r_type.rsplit("/", 1)[-1], target, t_mode or "External", mal))
            except Exception as exc:
                logger.debug("OOXML relationship scan note on %s: %s", path, exc)

        rti = bool(findings)
        detail = (
            f"Detected {len(findings)} external template/OLE relationship(s): {findings[0].target}"
            if rti else "No external template/OLE relationships found."
        )
        return RelationshipScanResult(rti_detected=rti, vt_malicious_urls=vt_hits, findings=findings, detail=detail)