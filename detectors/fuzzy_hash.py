#!/usr/bin/env python3
"""
detectors/fuzzy_hash.py — 64 KB chunked TLSH + ssdeep similarity hashing engine.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import IO_CHUNK_SIZE
from core.resilience import iter_file_chunks

logger = logging.getLogger("AegisSentinel.fuzzy")

try:
    import tlsh  # type: ignore
    TLSH_AVAILABLE = True
except ImportError:  # pragma: no cover
    tlsh = None
    TLSH_AVAILABLE = False

try:
    import ppdeep  # type: ignore
    SSDEEP_AVAILABLE = True
except ImportError:  # pragma: no cover
    ppdeep = None
    SSDEEP_AVAILABLE = False

FUZZY_AVAILABLE: bool = TLSH_AVAILABLE or SSDEEP_AVAILABLE


@dataclass
class FuzzyMatch:
    family: str
    algorithm: str
    score: float
    confidence: float
    reference_digest: str
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family,
            "algorithm": self.algorithm,
            "score": round(self.score, 2),
            "confidence": round(self.confidence, 3),
            "reference_digest": self.reference_digest,
            "note": self.note,
        }


@dataclass
class FuzzyResult:
    available: bool = FUZZY_AVAILABLE
    tlsh: Optional[str] = None
    ssdeep: Optional[str] = None
    matched: bool = False
    best_confidence: float = 0.0
    matches: List[FuzzyMatch] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "tlsh": self.tlsh,
            "ssdeep": self.ssdeep,
            "matched": self.matched,
            "best_confidence": round(self.best_confidence, 3),
            "matches": [m.as_dict() for m in self.matches],
            "detail": self.detail,
        }


class FuzzyHasher:
    TLSH_MAX_DISTANCE = 100
    SSDEEP_MIN_SIMILARITY = 50

    def __init__(
        self,
        signature_db_path: Optional[str | Path] = None,
        max_bytes: int = 20 * 1024 * 1024,
    ) -> None:
        self.max_bytes = int(max_bytes)
        self.signatures: List[Dict[str, Any]] = []
        if signature_db_path and os.path.exists(signature_db_path):
            self._load_signatures(Path(signature_db_path))

    def _load_signatures(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            items = raw.get("signatures", raw) if isinstance(raw, dict) else raw
            if isinstance(items, list):
                self.signatures = [s for s in items if isinstance(s, dict)]
        except Exception as exc:
            logger.warning("Could not load fuzzy signatures from %s: %s", path, exc)

    def hash_file(self, file_path: str | Path) -> Dict[str, Optional[str]]:
        tlsh_digest: Optional[str] = None
        ssdeep_digest: Optional[str] = None
        tlsh_hasher = tlsh.Tlsh() if TLSH_AVAILABLE and tlsh is not None else None
        buf = bytearray() if SSDEEP_AVAILABLE else None

        try:
            for chunk in iter_file_chunks(file_path, chunk_size=IO_CHUNK_SIZE, max_bytes=self.max_bytes):
                if tlsh_hasher is not None:
                    tlsh_hasher.update(chunk)
                if buf is not None:
                    buf.extend(chunk)

            if tlsh_hasher is not None:
                try:
                    tlsh_hasher.final()
                    val = tlsh_hasher.hexdigest()
                    if val and val != "TNULL":
                        tlsh_digest = val
                except Exception:
                    tlsh_digest = None

            if buf is not None and ppdeep is not None and len(buf) > 0:
                try:
                    ssdeep_digest = ppdeep.hash(bytes(buf))
                except Exception:
                    ssdeep_digest = None
        except OSError:
            pass

        return {"tlsh": tlsh_digest, "ssdeep": ssdeep_digest}

    def analyze_file(self, file_path: str | Path) -> FuzzyResult:
        if not FUZZY_AVAILABLE:
            return FuzzyResult(available=False, detail="python-tlsh / ppdeep not installed.")

        digests = self.hash_file(file_path)
        tlsh_val = digests.get("tlsh")
        ssdeep_val = digests.get("ssdeep")
        matches: List[FuzzyMatch] = []

        for sig in self.signatures:
            fam = str(sig.get("family", "Unknown.Family"))
            note = str(sig.get("note", ""))
            ref_tlsh = str(sig.get("tlsh", "")).strip()
            ref_ssdeep = str(sig.get("ssdeep", "")).strip()

            if tlsh_val and ref_tlsh and ref_tlsh != "TNULL" and TLSH_AVAILABLE and tlsh is not None:
                try:
                    dist = int(tlsh.diff(tlsh_val, ref_tlsh))
                    if dist <= self.TLSH_MAX_DISTANCE:
                        conf = max(0.1, 1.0 - (dist / 120.0))
                        matches.append(FuzzyMatch(fam, "tlsh", float(dist), conf, ref_tlsh, note))
                except Exception:
                    pass

            if ssdeep_val and ref_ssdeep and SSDEEP_AVAILABLE and ppdeep is not None:
                try:
                    sim = int(ppdeep.compare(ssdeep_val, ref_ssdeep))
                    if sim >= self.SSDEEP_MIN_SIMILARITY:
                        conf = min(1.0, sim / 100.0)
                        matches.append(FuzzyMatch(fam, "ssdeep", float(sim), conf, ref_ssdeep, note))
                except Exception:
                    pass

        best = max((m.confidence for m in matches), default=0.0)
        return FuzzyResult(
            available=True,
            tlsh=tlsh_val,
            ssdeep=ssdeep_val,
            matched=bool(matches),
            best_confidence=best,
            matches=matches,
            detail=f"Matched {len(matches)} family signature(s)." if matches else "No fuzzy family match.",
        )