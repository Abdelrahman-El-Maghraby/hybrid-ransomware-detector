#!/usr/bin/env python3
"""
detectors/macro_analysis.py — Static VBA / Excel 4.0 (XLM) macro analyzer
and P-Code vs. source VBA Stomping detector.
"""

from __future__ import annotations

import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("AegisSentinel.macro")

try:
    from oletools.olevba import VBA_Parser  # type: ignore
    OLEVBA_AVAILABLE = True
except ImportError:  # pragma: no cover
    VBA_Parser = None
    OLEVBA_AVAILABLE = False

CRITICAL_PRIMITIVES = {
    "shell", "wscript.shell", "createobject", "getobject", "urldownloadtofile",
    "xmlhttp", "msxml2.xmlhttp", "winhttp.winhttprequest", "adodb.stream",
    "powershell", "cmd.exe", "rundll32", "regsvr32", "virtualalloc",
    "writeprocessmemory", "createremotethread", "callbyname",
}

XLM_INDICATORS = ("EXEC(", "CALL(", "FORMULA.FILL(", "REGISTER(", "HALT(", "AUTO_OPEN")


@dataclass
class MacroResult:
    available: bool = OLEVBA_AVAILABLE
    has_macros: bool = False
    autoexec: List[str] = field(default_factory=list)
    critical: List[str] = field(default_factory=list)
    suspicious: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    vba_stomping_detected: bool = False
    vba_stomping_evidence: str = ""
    xlm_macros_detected: bool = False
    xlm_evidence: List[str] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "has_macros": self.has_macros,
            "autoexec": self.autoexec,
            "critical": self.critical,
            "suspicious": self.suspicious,
            "iocs": self.iocs,
            "vba_stomping_detected": self.vba_stomping_detected,
            "vba_stomping_evidence": self.vba_stomping_evidence,
            "xlm_macros_detected": self.xlm_macros_detected,
            "xlm_evidence": self.xlm_evidence,
            "detail": self.detail,
        }


class MacroAnalyzer:
    OFFICE_EXTENSIONS = {
        ".doc", ".docx", ".docm", ".dotm", ".xls", ".xlsx", ".xlsm",
        ".xlsb", ".xlm", ".ppt", ".pptx", ".pptm", ".rtf",
    }

    @staticmethod
    def _detect_vba_stomping_and_xlm(file_path: Path, decompressed_source: str) -> tuple[bool, str, bool, List[str]]:
        raw_bytes = b""
        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as zf:
                    for name in zf.namelist():
                        low = name.lower()
                        if "vbaproject.bin" in low or "xl/macrosheets" in low or "xl/workbook.xml" in low:
                            raw_bytes += zf.read(name)[: 2 * 1024 * 1024]
            else:
                raw_bytes = file_path.read_bytes()[: 4 * 1024 * 1024]
        except Exception:
            return False, "", False, []

        raw_ascii = raw_bytes.decode("latin-1", errors="ignore")
        src_lower = decompressed_source.lower()

        # 1. Check P-Code identifiers in binary stream missing from decompressed source
        pcode_only: List[str] = []
        for tok in ("Shell", "CreateObject", "WScript.Shell", "VirtualAlloc", "URLDownloadToFile", "powershell"):
            if tok.lower() in raw_ascii.lower() and tok.lower() not in src_lower:
                pcode_only.append(tok)

        stomped = bool(pcode_only)
        stomp_ev = (
            f"P-Code stream contains {pcode_only} absent from decompressed VBA source."
            if stomped else ""
        )

        # 2. Check Excel 4.0 (XLM) macros
        xlm_hits = [ind for ind in XLM_INDICATORS if ind.lower() in raw_ascii.lower()]
        return stomped, stomp_ev, bool(xlm_hits), xlm_hits

    def analyze_file(self, file_path: str | Path) -> MacroResult:
        path = Path(file_path)
        if path.suffix.lower() not in self.OFFICE_EXTENSIONS or not path.exists():
            return MacroResult(available=OLEVBA_AVAILABLE, detail="Not an Office macro target.")

        decompressed_parts: List[str] = []
        autoexec: List[str] = []
        critical: List[str] = []
        suspicious: List[str] = []
        iocs: List[str] = []
        has_macros = False

        if OLEVBA_AVAILABLE and VBA_Parser is not None:
            vba_parser = None
            try:
                vba_parser = VBA_Parser(str(path))
                if vba_parser.detect_vba_macros():
                    has_macros = True
                    for (_fn, _stream, _vba_fn, vba_code) in vba_parser.extract_all_macros():
                        if vba_code:
                            decompressed_parts.append(str(vba_code))
                    for kw_type, keyword, description in vba_parser.analyze_macros():
                        kw_str = str(keyword or "").strip()
                        if not kw_str:
                            continue
                        if kw_type == "AutoExec":
                            autoexec.append(kw_str)
                        elif kw_type == "IOC":
                            iocs.append(kw_str)
                        elif kw_type == "Suspicious":
                            if kw_str.lower() in CRITICAL_PRIMITIVES or any(c in kw_str.lower() for c in CRITICAL_PRIMITIVES):
                                critical.append(kw_str)
                            else:
                                suspicious.append(kw_str)
            except Exception as exc:
                logger.debug("olevba parse note on %s: %s", path, exc)
            finally:
                if vba_parser is not None:
                    try:
                        vba_parser.close()
                    except Exception:
                        pass

        full_source = "\n".join(decompressed_parts)
        stomped, stomp_ev, xlm_det, xlm_ev = self._detect_vba_stomping_and_xlm(path, full_source)
        if stomped or xlm_det:
            has_macros = True

        return MacroResult(
            available=OLEVBA_AVAILABLE,
            has_macros=has_macros,
            autoexec=sorted(set(autoexec)),
            critical=sorted(set(critical)),
            suspicious=sorted(set(suspicious)),
            iocs=sorted(set(iocs)),
            vba_stomping_detected=stomped,
            vba_stomping_evidence=stomp_ev,
            xlm_macros_detected=xlm_det,
            xlm_evidence=xlm_ev,
            detail="Macros analyzed." if has_macros else "No macros detected.",
        )