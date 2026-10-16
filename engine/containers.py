"""
Containers: files that hold other files (ZIP archives, e-mails).

Every container is handled the same way: open it into a temporary sandbox,
send each member through the full scan pipeline (up to `max_nesting` levels
deep, at most `budget` members), record the container's own findings, and
carry the most dangerous member's evidence over to the container's score.

Only the parts that genuinely differ live in a `ContainerHandler`: how to
open the container, which members to scan and under what display name, and
which of its own findings become scoring signals. Supporting a new container
type (7z, ISO, an Outlook item inside an Outlook item) means writing one
handler, not another copy of the scanning loop.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Dict, Iterator, List, Tuple

if TYPE_CHECKING:  # pragma: no cover
    from .layers import ScanContext
    from .scanner import RansomwareScanner

logger = logging.getLogger("RansomwareScanner")


def member_summary(r: Dict) -> Dict:
    """The short form of a member's result kept inside its container's result."""
    contributions = r.get("score_breakdown", {}).get("contributions", []) or []
    return {
        "name": r.get("file_path"),
        "verdict": r.get("verdict", "Clean"),
        "risk_score": r.get("risk_score", 0),
        "md5_hash": r.get("md5_hash", ""),
        "sha256_hash": r.get("sha256_hash", ""),
        "indicators": [c.get("indicator") for c in contributions][:8],
    }


class ContainerHandler:
    """What is specific to one kind of container."""

    result_key = ""            # key under result["scan_results"]
    signal_key = ""            # key in the scoring signals
    members_key = ""           # where member summaries are stored in the result
    worst_key = ""             # signal key carrying the worst member's evidence
    worst_default_name = "member"
    error_label = "member"     # used in the log line when a member scan fails

    def applies(self, ctx: "ScanContext") -> bool:
        raise NotImplementedError

    def open(self, scanner: "RansomwareScanner", path: str):
        """Context manager yielding a view with `.as_dict()`; sandbox lives inside it."""
        raise NotImplementedError

    def budget(self, scanner: "RansomwareScanner") -> int:
        raise NotImplementedError

    def items(self, view, ctx: "ScanContext") -> Iterator[Tuple[str, str, str]]:
        """Yield (sandbox path, display name, log label) for each scannable member."""
        raise NotImplementedError

    def capture(self, view, ctx: "ScanContext") -> None:
        """Copy anything else the pipeline needs out of the view before it closes."""

    def decorate(self, view_dict: Dict, summaries: List[Dict]) -> None:
        """Attach container-level findings to member summaries."""

    def signals(self, view_dict: Dict) -> Dict:
        raise NotImplementedError


def scan_container(scanner: "RansomwareScanner", handler: ContainerHandler,
                   ctx: "ScanContext") -> None:
    """Unpack, scan every member through the pipeline, record result + signals."""
    member_results: List[Dict] = []
    skipped_for_budget = 0
    with handler.open(scanner, ctx.path) as view:
        if ctx.depth < scanner.max_nesting:
            budget = handler.budget(scanner)
            for member_path, display_name, label in handler.items(view, ctx):
                if len(member_results) >= budget:
                    skipped_for_budget += 1
                    continue
                try:
                    member_results.append(scanner.scan_file(
                        member_path, _depth=ctx.depth + 1, _display_name=display_name))
                except Exception as e:
                    logger.error(f"Error scanning {handler.error_label} {label}: {e}")
        view_dict = view.as_dict()
        handler.capture(view, ctx)

    view_dict["deep_scanned"] = len(member_results)
    view_dict["not_scanned_budget"] = skipped_for_budget
    summaries = [member_summary(r) for r in member_results]
    handler.decorate(view_dict, summaries)
    view_dict[handler.members_key] = summaries
    ctx.result["scan_results"][handler.result_key] = view_dict

    signals = handler.signals(view_dict)
    worst = max(member_results, key=lambda r: r.get("risk_score", 0), default=None)
    if worst and worst.get("risk_score", 0) > 0:
        signals[handler.worst_key] = {
            "name": worst.get("file_name", handler.worst_default_name),
            "contributions": worst.get("score_breakdown", {}).get("contributions", []),
        }
    ctx.signals[handler.signal_key] = signals


class ArchiveHandler(ContainerHandler):
    """ZIP archives (nested ZIPs are expanded by the extractor itself)."""

    result_key = signal_key = "archive"
    members_key = "member_results"
    worst_key = "worst_member"
    worst_default_name = "member"
    error_label = "archive member"
    FLAG_SOURCES = (("double_extension", "double_extension_members"),
                    ("rtlo_spoof", "rtlo_members"), ("executable", "executable_members"))

    def applies(self, ctx):
        return ctx.is_archive

    def open(self, scanner, path):
        return scanner.container_extractor.open(path)

    def budget(self, scanner):
        return scanner.archive_scan_members

    def items(self, view, ctx):
        prefix = os.path.basename(ctx.path) + "!"
        for member in view.members:
            if not member.extracted or not member.path:
                continue
            if member.path.lower().endswith(".zip"):
                continue       # nested archives are already expanded
            yield member.path, member.name.replace(prefix, ctx.display + "!", 1), member.name

    def decorate(self, view_dict, summaries):
        # Archive-level findings about a member (lure names, executables) are
        # attached to that member so it is never shown as plainly "Clean".
        for summary in summaries:
            inner = str(summary.get("name", "")).split("!/", 1)[-1]
            summary["archive_flags"] = [
                flag for flag, key in self.FLAG_SOURCES
                if any(str(n).split("!/", 1)[-1] == inner for n in view_dict.get(key, []))]

    def signals(self, d):
        return {
            "zip_slip": d["zip_slip"],
            "zip_bomb": d["zip_bomb"],
            "encrypted_unreadable": d["encrypted_unreadable"],
            "executable_members": d["executable_members"],
            "double_extension_members": d["double_extension_members"],
            "rtlo_members": d["rtlo_members"],
            "reasons": {"zip_slip": d["zip_slip_reason"], "zip_bomb": d["zip_bomb_reason"]},
        }


class MailHandler(ContainerHandler):
    """E-mails (.eml / .msg): attachments are the members; the body is kept as text."""

    result_key = signal_key = "mail"
    members_key = "attachment_results"
    worst_key = "worst_attachment"
    worst_default_name = "attachment"
    error_label = "attachment"

    def applies(self, ctx):
        return ctx.is_mail

    def open(self, scanner, path):
        return scanner.mail_analyzer.open(path)

    def budget(self, scanner):
        return scanner.mail_scan_attachments

    def items(self, view, ctx):
        for att in view.attachments:
            if not att.path:
                continue
            yield att.path, f"{ctx.display}!/{att.filename}", att.filename

    def capture(self, view, ctx):
        ctx.text = view.body_text   # the prompt-guard and LLM layers read the body

    def signals(self, d):
        return {
            "from_domain": d["from_domain"],
            "reply_to_domain": d["reply_to_domain"],
            "auth_failures": d["auth"]["failures"],
            "display_name_spoof": d["display_name_spoof"],
            "display_name_spoof_reason": d["display_name_spoof_reason"],
            "reply_to_mismatch": d["reply_to_mismatch"],
            "deceptive_links": d["deceptive_links"],
            "executable_attachments": d["executable_attachments"],
            "double_extension_attachments": d["double_extension_attachments"],
            "rtlo_attachments": d["rtlo_attachments"],
            "lure_subject": d["lure_subject"],
        }
