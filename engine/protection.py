"""
Host protection on the scanner: the encrypted quarantine vault, automatic
quarantine, and the canary tripwires with their containment response
(core/response.py). A mixin of engine.scanner.RansomwareScanner.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional

from core import QUARANTINE_AVAILABLE, QuarantineError, QuarantineVault
from core.canary import desktop_notify

from .config import KEYSTORE_DIR, QUARANTINE_DIR, VERDICT_RANK

if TYPE_CHECKING:  # pragma: no cover
    from core import CanaryManager

logger = logging.getLogger("RansomwareScanner")


class ProtectionMixin:
    config: Dict
    report_dir: str
    scan_dirs: List[str]
    canaries: CanaryManager
    _vault: Optional[QuarantineVault]
    _last_canary_signature: Optional[tuple]

    @property
    def quarantine_vault(self) -> QuarantineVault:
        """The encrypted quarantine vault (created on first use)."""
        if self._vault is None:
            if not QUARANTINE_AVAILABLE:
                raise QuarantineError("Quarantine needs the 'cryptography' package: "
                                      "pip install cryptography")
            self._vault = QuarantineVault(self.config.get("quarantine_dir", str(QUARANTINE_DIR)),
                                          self.config.get("keystore_dir", str(KEYSTORE_DIR)))
        return self._vault

    # ------------------------------------------------------------ quarantine
    def quarantine_file(self, file_path: str, reason: str = "",
                        result: Optional[Dict] = None) -> Dict:
        """Move a file into the encrypted quarantine vault (verify-before-delete)."""
        extra = {}
        if result:
            extra = {k: result.get(k) for k in ("verdict", "risk_score", "sha256_hash")}
        return self.quarantine_vault.quarantine(file_path, reason=reason, extra=extra)

    def _maybe_auto_quarantine(self, result: Dict) -> None:
        threshold = VERDICT_RANK.get(str(self.config.get("auto_quarantine") or "").capitalize())
        if not threshold or VERDICT_RANK.get(result.get("verdict", "Clean"), 0) < threshold:
            return
        try:
            meta = self.quarantine_file(
                result["file_path"],
                reason=f"auto-quarantine: {result.get('verdict')} "
                       f"(risk {result.get('risk_score')}/100)",
                result=result)
            result["quarantine"] = {"id": meta["id"], "vault_file": meta["vault_file"],
                                    "original_removed": meta["original_removed"]}
        except Exception as e:
            logger.error("Auto-quarantine failed for %s: %s", result.get('file_path'), e)
            result["quarantine"] = {"error": str(e)}

    # --------------------------------------------------------------- canaries
    def deploy_canaries(self, directories: Optional[List[str]] = None) -> List[Dict]:
        return self.canaries.deploy(directories or self.scan_dirs)

    def remove_canaries(self) -> int:
        return self.canaries.remove()

    def check_canaries(self, notify: bool = True, touched: Iterable[str] = ()):
        """Verify every canary. On a NEW trigger: run the configured containment
        actions (core/response.py), write an alert file next to the reports and
        raise a desktop notification (repeat findings stay quiet). `touched` are
        the paths the real-time watcher saw change."""
        report = self.canaries.verify()
        if not report.triggered:
            self._last_canary_signature = None
            return report
        signature = tuple(sorted((f.path, f.status) for f in report.findings))
        if signature != self._last_canary_signature:
            self._last_canary_signature = signature
            self._canary_alert(report, touched, notify)
        return report

    def _canary_alert(self, report: Any, touched: Iterable[str], notify: bool) -> None:
        """Run the containment actions, then write the alert file and notify."""
        from core.response import respond
        actions = respond(self.config, {"summary": report.summary(),
                                        "checked_at": report.checked_at,
                                        "touched": sorted(set(touched)),
                                        "findings": [{"path": f.path, "status": f.status,
                                                      "evidence": f.evidence}
                                                     for f in report.findings]})
        lines = ["RANSOMWARE CANARY TRIPWIRE - rapid containment & damage mitigation",
                 "=" * 68,
                 f"Time:    {report.checked_at}", f"Summary: {report.summary()}", ""]
        lines += [f"[{f.status}] {f.path}\n    {f.evidence}" for f in report.findings]
        if actions:
            lines += ["", "Automatic response:"] + [f"  {a.line()}" for a in actions]
        lines += ["", "This tripwire limits damage; it cannot undo encryption that already "
                      "happened.",
                  "Recommended: disconnect this machine from the network, do not reboot, "
                  "and investigate running processes."]
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        alert = Path(self.report_dir) / f"canary_alert_{stamp}.txt"
        try:
            alert.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as e:
            logger.error("Could not write canary alert file: %s", e)
        if notify:
            desktop_notify("Ransomware tripwire triggered", report.summary())
        # PR-08: the alert outputs (webhook, e-mail) hear about it too, with retry
        from core.outbox import canary_alert, queue_and_send
        queue_and_send([canary_alert(report)], self.config)
