#!/usr/bin/env python3
"""
detectors/yara_engine.py — Namespaced YARA rule compiler and identifier-only scanner.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AegisSentinel.yara")

try:
    import yara as _yara  # type: ignore
    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover
    _yara = None
    YARA_AVAILABLE = False

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    severity: str
    description: str
    matched_identifiers: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "severity": self.severity,
            "description": self.description,
            "matched_identifiers": self.matched_identifiers,
        }


@dataclass
class YaraResult:
    available: bool = YARA_AVAILABLE
    matched: bool = False
    top_severity: Optional[str] = None
    matches: List[YaraMatch] = field(default_factory=list)
    rules_loaded: int = 0
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "matched": self.matched,
            "top_severity": self.top_severity,
            "matches": [m.as_dict() for m in self.matches],
            "rules_loaded": self.rules_loaded,
            "detail": self.detail,
        }


class YaraEngine:
    def __init__(self, rules_dir: Optional[str | Path] = None) -> None:
        self.rules_dir = Path(rules_dir).resolve() if rules_dir else None
        self._compiled: Any = None
        self.rules_loaded: int = 0
        self._compile_rules()

    def _compile_rules(self) -> None:
        if not YARA_AVAILABLE or _yara is None or not self.rules_dir or not self.rules_dir.exists():
            return
        filepaths: Dict[str, str] = {}
        for p in sorted([*self.rules_dir.glob("*.yar"), *self.rules_dir.glob("*.yara")]):
            if p.is_file():
                filepaths[p.stem] = str(p)
        if not filepaths:
            return
        try:
            self._compiled = _yara.compile(filepaths=filepaths)
            self.rules_loaded = len(filepaths)
        except Exception as exc:
            logger.error("Failed compiling YARA rules: %s", exc)

    def scan_file(self, file_path: str | Path) -> YaraResult:
        if not YARA_AVAILABLE:
            return YaraResult(available=False, detail="yara-python not installed.")
        if self._compiled is None:
            return YaraResult(available=True, rules_loaded=0, detail="No YARA rules compiled.")
        try:
            raw_matches = self._compiled.match(str(file_path), timeout=20)
        except Exception as exc:
            return YaraResult(available=True, rules_loaded=self.rules_loaded, detail=f"YARA error: {exc}")

        matches: List[YaraMatch] = []
        top_sev: Optional[str] = None

        for m in raw_matches:
            meta = getattr(m, "meta", {}) or {}
            sev = str(meta.get("severity", "medium")).lower()
            desc = str(meta.get("description", ""))
            ids: List[str] = []
            for s in getattr(m, "strings", []) or []:
                ident = getattr(s, "identifier", None)
                if ident is None and isinstance(s, tuple) and len(s) >= 2:
                    ident = s[1]
                if ident:
                    ids.append(str(ident))
            matches.append(
                YaraMatch(
                    rule=str(m.rule),
                    namespace=str(getattr(m, "namespace", "default")),
                    severity=sev,
                    description=desc,
                    matched_identifiers=sorted(set(ids)),
                )
            )
            if top_sev is None or SEVERITY_RANK.get(sev, 2) > SEVERITY_RANK.get(top_sev, 2):
                top_sev = sev

        return YaraResult(
            available=True,
            matched=bool(matches),
            top_severity=top_sev,
            matches=matches,
            rules_loaded=self.rules_loaded,
            detail=f"Matched {len(matches)} YARA rule(s)." if matches else "No YARA matches.",
        )