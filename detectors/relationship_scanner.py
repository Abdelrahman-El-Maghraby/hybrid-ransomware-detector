"""
Office external-relationship scanner: remote template injection, Follina-style
OLE links, exploit URI schemes and NTLM-leaking UNC paths.

WHY THIS EXISTS
---------------
Some of the most effective malicious documents contain **no macro at all**.
Their payload lives on a server and is pulled in by a *relationship* - a tiny
XML entry inside the .docx/.xlsx/.pptx ZIP container that tells Office to fetch
something when the file opens:

* **Remote template injection** (MITRE ATT&CK T1221) - `settings.xml.rels`
  points `attachedTemplate` at `http://attacker/t.dotm`; Office downloads the
  macro-enabled template and runs it. The .docx itself looks clean to olevba.
* **Follina / CVE-2022-30190** - an external `oleObject` relationship to
  `http://attacker/x.html!` loads HTML that invokes the `ms-msdt:` handler and
  runs PowerShell with macros disabled.
* **Exploit URI schemes** - `ms-msdt:`, `search-ms:`, `ms-officecmd:`, `mhtml:`
  targets abuse Windows protocol handlers.
* **UNC paths** (`\\\\attacker\\share\\x`) - opening the document makes Windows
  authenticate to the attacker's SMB server and leak the user's NTLM hash
  (T1187 Forced Authentication).
* **RTF** documents do the same with `{\\*\\template http://...}` and
  auto-updating OLE links (`\\objupdate` / `\\objautlink`).

This module reads only the relationship parts (never executes anything, never
contacts the URLs), parses XML with `defusedxml`, and caps how much of each
part it reads so a hostile archive cannot exhaust memory.
"""

from __future__ import annotations

import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

logger = logging.getLogger("RansomwareScanner.relationships")

try:
    import defusedxml.ElementTree as _DET
    DEFUSEDXML_AVAILABLE = True
except Exception:  # pragma: no cover - absence is a valid runtime state
    _DET = None
    DEFUSEDXML_AVAILABLE = False

PathLike = Union[str, Path]

OOXML_EXTS = frozenset({".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx",
                        ".xltm", ".xlsb", ".pptx", ".pptm", ".potx", ".potm", ".ppsx",
                        ".ppsm"})
_MAX_RELS_BYTES = 2 * 1024 * 1024
_MAX_RTF_BYTES = 8 * 1024 * 1024

EXPLOIT_SCHEMES = ("ms-msdt:", "search-ms:", "search:", "ms-officecmd:", "mhtml:",
                   "ms-word:", "ms-excel:", "ms-powerpoint:", "ms-appinstaller:",
                   "ms-search:", "jar:")
REMOTE_SCHEMES = ("http://", "https://", "ftp://", "file://", "\\\\", "//")
RISKY_TYPES = {"attachedtemplate": "remote_template", "oleobject": "external_ole",
               "frame": "external_frame", "subdocument": "external_subdocument"}

_RTF_TEMPLATE = re.compile(rb"\{\\\*\\template\s+([^}]{1,2048})\}", re.I)
_RTF_OLE_AUTO = re.compile(rb"\\obj(?:update|autlink)\b", re.I)
_RTF_OBJDATA = re.compile(rb"\\objdata\b", re.I)


@dataclass
class RelationshipFinding:
    kind: str           # remote_template | external_ole | follina_style_ole |
                        # exploit_scheme | unc_ntlm_leak | external_frame |
                        # external_subdocument | rtf_remote_template | rtf_ole_autoupdate
    part: str
    target: str
    rel_type: str = ""

    def as_dict(self) -> Dict:
        return {"kind": self.kind, "part": self.part, "target": self.target,
                "rel_type": self.rel_type}


@dataclass
class RelationshipResult:
    available: bool = True
    checked: bool = False
    findings: List[RelationshipFinding] = field(default_factory=list)
    detail: str = ""
    error: str = ""             # the document could not be parsed: not "nothing found"

    @property
    def kinds(self) -> List[str]:
        return sorted({f.kind for f in self.findings})

    def as_dict(self) -> Dict:
        return {"available": self.available, "checked": self.checked,
                "suspicious": bool(self.findings), "kinds": self.kinds,
                "findings": [f.as_dict() for f in self.findings[:25]],
                "detail": self.detail, **({"error": self.error} if self.error else {})}


def defang(url: str) -> str:
    """Make a URL safe to paste into a report (hxxp://evil[.]com)."""
    out = re.sub(r"^http", "hxxp", url, flags=re.I)
    return re.sub(r"\.(?=[^./\\]+(?:[/\\:]|$))", "[.]", out, count=1)


class RelationshipScanner:
    def scan_file(self, file_path: PathLike) -> RelationshipResult:
        path = Path(file_path)
        ext = path.suffix.lower()
        try:
            if ext == ".rtf" or (ext in (".doc", ".dot") and self._is_rtf(path)):
                return self._scan_rtf(path)
            if ext in OOXML_EXTS:
                if not DEFUSEDXML_AVAILABLE:
                    return RelationshipResult(available=False,
                                              detail="Skipped: install 'defusedxml'.")
                return self._scan_ooxml(path)
        except Exception as e:
            logger.debug("Relationship scan failed for %s: %s", path, e)
            return RelationshipResult(checked=False, detail=f"Relationship scan error: {e}",
                                      error=f"{type(e).__name__}: {e}"[:200])
        return RelationshipResult(checked=False,
                                  detail="Not an OOXML/RTF document; relationships not checked.")

    # ---------------------------------------------------------------- OOXML
    def _scan_ooxml(self, path: Path) -> RelationshipResult:
        if not zipfile.is_zipfile(path):
            return RelationshipResult(checked=False, detail="Not a ZIP-based Office file.")
        findings: List[RelationshipFinding] = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if not info.filename.lower().endswith(".rels"):
                    continue
                if info.file_size > _MAX_RELS_BYTES:
                    logger.debug("Skipping oversized rels part %s", info.filename)
                    continue
                root = _DET.fromstring(zf.read(info))
                for rel in root.iter():
                    if not str(rel.tag).endswith("Relationship"):
                        continue
                    finding = self._classify(info.filename, rel.get("Type") or "",
                                             (rel.get("Target") or "").strip(),
                                             (rel.get("TargetMode") or "").strip())
                    if finding is not None:
                        findings.append(finding)
        return self._result(findings)

    @staticmethod
    def _classify(part: str, rel_type: str, target: str,
                  target_mode: str) -> Optional[RelationshipFinding]:
        short_type = rel_type.rsplit("/", 1)[-1]
        t_low = target.lower()
        # Protocol-handler abuse is dangerous in ANY relationship (even a
        # hyperlink), whatever its TargetMode.
        if t_low.startswith(EXPLOIT_SCHEMES):
            return RelationshipFinding("exploit_scheme", part, target, short_type)
        if target_mode.lower() != "external":
            return None
        # \\host\share, //host/share or file://host/share make Windows open an
        # SMB connection - and send the user's NTLM hash - to that host.
        is_unc = (t_low.startswith(("\\\\", "//"))
                  or (t_low.startswith("file://") and not t_low.startswith("file:///")))
        if is_unc:
            return RelationshipFinding("unc_ntlm_leak", part, target, short_type)
        kind = RISKY_TYPES.get(short_type.lower())
        if kind is None or not t_low.startswith(REMOTE_SCHEMES):
            return None   # ordinary hyperlinks / web images are not flagged
        if kind == "external_ole" and target.rstrip().endswith("!"):
            kind = "follina_style_ole"
        return RelationshipFinding(kind, part, target, short_type)

    # ------------------------------------------------------------------ RTF
    @staticmethod
    def _is_rtf(path: Path) -> bool:
        try:
            with path.open("rb") as fh:
                return fh.read(16).lstrip().startswith(b"{\\rt")
        except OSError:
            return False

    def _scan_rtf(self, path: Path) -> RelationshipResult:
        with path.open("rb") as fh:
            data = fh.read(_MAX_RTF_BYTES)
        findings: List[RelationshipFinding] = []
        for m in _RTF_TEMPLATE.finditer(data):
            target = m.group(1).decode("latin-1", errors="replace").strip()
            t_low = target.lower()
            remote = (t_low.startswith(("http://", "https://", "ftp://", "\\\\", "//"))
                      or (t_low.startswith("file://") and not t_low.startswith("file:///"))
                      or t_low.startswith(EXPLOIT_SCHEMES))
            if remote:   # a local template path (C:\...\Normal.dotm) is normal
                findings.append(RelationshipFinding("rtf_remote_template", "rtf", target,
                                                    "template"))
        if _RTF_OLE_AUTO.search(data) and _RTF_OBJDATA.search(data):
            findings.append(RelationshipFinding(
                "rtf_ole_autoupdate", "rtf", "(embedded OLE object set to auto-update)",
                "objupdate"))
        return self._result(findings)

    @staticmethod
    def _result(findings: List[RelationshipFinding]) -> RelationshipResult:
        if not findings:
            return RelationshipResult(checked=True,
                                      detail="No external template/OLE relationships found.")
        kinds = sorted({f.kind for f in findings})
        first = defang(findings[0].target)
        return RelationshipResult(
            checked=True, findings=findings,
            detail=f"{len(findings)} external relationship finding(s) [{', '.join(kinds)}], "
                   f"e.g. {first}")
