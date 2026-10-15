#!/usr/bin/env python3
"""
detectors/behavioral_monitor.py — Behavioral process lineage, shadow-copy deletion,
and Shannon entropy file-modification burst detector.
"""

from __future__ import annotations

import collections
import logging
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from config import IO_CHUNK_SIZE
from core.resilience import extract_suspicious_strings, iter_file_chunks

logger = logging.getLogger("AegisSentinel.behavioral")

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    psutil = None
    PSUTIL_AVAILABLE = False

SHADOW_DELETE_PATTERNS = (
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "wbadmin delete catalog",
    "win32_shadowcopy",
)

DOC_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "foxitreader.exe"}
SHELL_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
RANSOM_EXTS = {".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".ryuk", ".lockbit", ".blackcat"}


def calculate_shannon_entropy(file_path: str | Path, max_bytes: int = 2 * 1024 * 1024) -> float:
    counts = [0] * 256
    total = 0
    try:
        for chunk in iter_file_chunks(file_path, chunk_size=IO_CHUNK_SIZE, max_bytes=max_bytes):
            total += len(chunk)
            for b in chunk:
                counts[b] += 1
    except OSError:
        return 0.0
    if total == 0:
        return 0.0
    return round(-sum((c / total) * math.log2(c / total) for c in counts if c > 0), 4)


@dataclass
class BehavioralFinding:
    behavior_type: str
    points: float
    process_name: str = ""
    command_line: str = ""
    evidence: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "behavior_type": self.behavior_type,
            "points": round(self.points, 2),
            "process_name": self.process_name,
            "command_line": self.command_line,
            "evidence": self.evidence,
        }


@dataclass
class BehavioralReport:
    triggered: bool = False
    shannon_entropy: float = 0.0
    findings: List[BehavioralFinding] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "triggered": self.triggered,
            "shannon_entropy": round(self.shannon_entropy, 4),
            "findings": [f.as_dict() for f in self.findings],
            "detail": self.detail,
        }


class BehavioralMonitor:
    def __init__(
        self,
        burst_window_seconds: float = 30.0,
        burst_threshold_count: int = 8,
        high_entropy_threshold: float = 7.35,
    ) -> None:
        self.burst_window_seconds = float(burst_window_seconds)
        self.burst_threshold_count = int(burst_threshold_count)
        self.high_entropy_threshold = float(high_entropy_threshold)
        self._recent_high_entropy_writes: Deque[Tuple[float, str]] = collections.deque(maxlen=256)

    def analyze_file_behavior(
        self,
        file_path: str | Path,
        synthetic_processes: Optional[List[Dict[str, str]]] = None,
    ) -> BehavioralReport:
        path = Path(file_path)
        entropy = calculate_shannon_entropy(path)
        findings: List[BehavioralFinding] = []
        now = time.monotonic()

        strings_lower = extract_suspicious_strings(path, max_output_chars=64_000).lower()
        for pat in SHADOW_DELETE_PATTERNS:
            if pat in strings_lower:
                findings.append(
                    BehavioralFinding(
                        behavior_type="shadow_copy_deletion",
                        points=85.0,
                        process_name=path.name,
                        command_line=pat,
                        evidence=f"Shadow copy / system recovery inhibition command detected: '{pat}'.",
                    )
                )
                break

        if entropy >= self.high_entropy_threshold or path.suffix.lower() in RANSOM_EXTS:
            self._recent_high_entropy_writes.append((now, str(path)))
            while self._recent_high_entropy_writes and (now - self._recent_high_entropy_writes[0][0]) > self.burst_window_seconds:
                self._recent_high_entropy_writes.popleft()
            if len(self._recent_high_entropy_writes) >= self.burst_threshold_count:
                findings.append(
                    BehavioralFinding(
                        behavior_type="mass_encryption_burst",
                        points=80.0,
                        evidence=f"{len(self._recent_high_entropy_writes)} high-entropy/ransom-extension files written within {self.burst_window_seconds:.0f}s.",
                    )
                )

        proc_list = synthetic_processes or []
        if not proc_list and PSUTIL_AVAILABLE and psutil is not None:
            try:
                for p in psutil.process_iter(["name", "cmdline", "ppid"]):
                    pname = (p.info.get("name") or "").lower()
                    if pname in SHELL_CHILDREN:
                        parent = psutil.Process(p.info["ppid"]).name().lower() if p.info.get("ppid") else ""
                        cmdline = " ".join(p.info.get("cmdline") or [])
                        proc_list.append({"parent": parent, "name": pname, "cmdline": cmdline})
            except Exception:
                pass

        for proc in proc_list:
            parent_n = str(proc.get("parent", "")).lower()
            child_n = str(proc.get("name", "")).lower()
            cmd = str(proc.get("cmdline", ""))
            if parent_n in DOC_PARENTS and child_n in SHELL_CHILDREN:
                findings.append(
                    BehavioralFinding(
                        behavior_type="office_or_pdf_spawning_shell",
                        points=65.0,
                        process_name=child_n,
                        command_line=cmd[:200],
                        evidence=f"Document reader '{parent_n}' spawned command interpreter '{child_n}'.",
                    )
                )

        detail = "; ".join(f.evidence for f in findings) if findings else f"Normal behavior (entropy={entropy:.2f})."
        return BehavioralReport(triggered=bool(findings), shannon_entropy=entropy, findings=findings, detail=detail)