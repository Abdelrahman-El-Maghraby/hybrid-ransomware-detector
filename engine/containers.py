"""
Containers: files that hold other files (ZIP archives, e-mails).

Every container is handled the same way: open it into a temporary sandbox,
send each member through the full scan pipeline (up to `max_nesting` levels
deep, at most `budget` members), record the container's own findings, and
carry the most dangerous member's evidence over to the container's score.

Only the parts that genuinely differ live in a `ContainerHandler`: how to
open the container, which members to scan and under what display name, and
which of its own findings become scoring signals. Supporting a new container
type (7z, ISO, an Outlook item inside an Outlook item, a payload smuggled
inside a web page) means writing one
handler, not another copy of the scanning loop.
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Tuple

from detectors.signals import ArchiveSignal, EmbeddedSignal, MailSignal, WebSignal, WorstMember

from .completeness import PARTIAL
from .completeness import reason as incomplete_reason

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
        "archive_password": (r.get("scan_results", {}).get("archive") or {}).get("password_used"),
        "scan_status": r.get("scan_status", "complete"),
    }


class ContainerHandler:
    """What is specific to one kind of container."""

    result_key = ""            # key under result["scan_results"]
    signal_key = ""            # key in the scoring signals
    members_key = ""           # where member summaries are stored in the result
    worst_key = ""             # signal key carrying the worst member's evidence
    worst_default_name = "member"
    error_label = "member"     # used in the log line when a member scan fails

    def applies(self, ctx: ScanContext) -> bool:
        raise NotImplementedError

    def open(self, scanner: RansomwareScanner, path: str):
        """Context manager yielding a view with `.as_dict()`; sandbox lives inside it."""
        raise NotImplementedError

    def budget(self, scanner: RansomwareScanner) -> int:
        raise NotImplementedError

    def items(self, view, ctx: ScanContext) -> Iterator[Tuple[str, str, str]]:
        """Yield (sandbox path, display name, log label) for each scannable member."""
        raise NotImplementedError

    def member_context(self, scanner: RansomwareScanner, view):
        """Context in which the members are scanned (e.g. extra archive passwords)."""
        return contextlib.nullcontext()

    def capture(self, view, ctx: ScanContext) -> None:
        """Copy anything else the pipeline needs out of the view before it closes."""

    def decorate(self, view_dict: Dict, summaries: List[Dict]) -> None:
        """Attach container-level findings to member summaries."""

    def signals(self, view_dict: Dict) -> Any:
        """The container's own findings as its typed signal (detectors/signals.py;
        it must have a `worst` field), or a plain dict for a third-party
        container the scorer does not know."""
        raise NotImplementedError


def scan_container(scanner: RansomwareScanner, handler: ContainerHandler,
                   ctx: ScanContext) -> None:
    """Unpack, scan every member through the pipeline, record result + signals."""
    member_results: List[Dict] = []
    skipped_for_budget = 0
    with handler.open(scanner, ctx.path) as view:
        if ctx.depth < scanner.max_nesting:
            budget = handler.budget(scanner)
            with handler.member_context(scanner, view):
                for member_path, display_name, label in handler.items(view, ctx):
                    if len(member_results) >= budget:
                        skipped_for_budget += 1
                        continue
                    try:
                        member_results.append(scanner.scan_file(
                            member_path, _depth=ctx.depth + 1, _display_name=display_name))
                    except Exception as e:
                        logger.error("Error scanning %s %s: %s", handler.error_label, label, e)
                        ctx.member_reasons.append(incomplete_reason(
                            PARTIAL, display_name, handler.result_key,
                            f"member scan failed: {type(e).__name__}"))
                        continue
                    ctx.member_reasons.extend(member_results[-1].get("incomplete_reasons") or [])
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
        member = WorstMember(
            name=worst.get("file_name", handler.worst_default_name),
            contributions=worst.get("score_breakdown", {}).get("contributions", []))
        if isinstance(signals, dict):
            signals[handler.worst_key] = {"name": member.name,
                                          "contributions": member.contributions}
        else:
            signals.worst = member
    ctx.signals.set(handler.signal_key, signals)


class ArchiveHandler(ContainerHandler):
    """ZIP / 7z / RAR / ISO archives (nested archives are expanded by the extractor itself)."""

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
            if member.nested:
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

    def signals(self, d: Dict) -> ArchiveSignal:
        return ArchiveSignal(
            zip_slip=d["zip_slip"], zip_bomb=d["zip_bomb"],
            encrypted_unreadable=d["encrypted_unreadable"],
            skipped_members=d.get("skipped_members", 0),
            executable_members=d["executable_members"],
            double_extension_members=d["double_extension_members"],
            rtlo_members=d["rtlo_members"],
            reasons={"zip_slip": d["zip_slip_reason"], "zip_bomb": d["zip_bomb_reason"]})


class WebHandler(ContainerHandler):
    """HTML / SVG pages: payloads decoded from base64 strings and data: URIs are
    the members (HTML smuggling); the page's own findings are its signals."""

    result_key = signal_key = "web"
    members_key = "payload_results"
    worst_key = "worst_payload"
    worst_default_name = "payload"
    error_label = "embedded payload"

    def applies(self, ctx):
        return ctx.is_web

    def open(self, scanner, path):
        return scanner.web_analyzer.open(path)

    def budget(self, scanner):
        return 5

    def items(self, view, ctx):
        for payload in view.payloads:
            if payload.path:
                yield payload.path, f"{ctx.display}!/{payload.name}", payload.name

    def signals(self, d: Dict) -> WebSignal:
        return WebSignal(
            smuggling=d["smuggling"], smuggling_construct=d["smuggling_construct"],
            smuggling_reasons=d["smuggling_reasons"],
            payloads=[p["name"] + " (" + p["format"] + ")" for p in d["payloads"]],
            svg_active=d["svg_active"], credential_form=d["credential_form"],
            credential_reasons=d["credential_reasons"], redirects=d["redirects"],
            obfuscation=d["obfuscation"])


class EmbeddedHandler(ContainerHandler):
    """OneNote / CHM / MSI / encrypted Office / XLL: carved or decrypted content is
    the members; the container's own findings are its signals."""

    result_key = signal_key = "embedded"
    members_key = "member_results"
    worst_key = "worst_member"
    worst_default_name = "embedded file"
    error_label = "embedded file"

    def applies(self, ctx):
        return bool(ctx.embedded_kind) and not (ctx.is_archive or ctx.is_mail or ctx.is_web)

    def open(self, scanner, path):
        return scanner.embedded_analyzer.open(path)

    def budget(self, scanner):
        return 25

    def items(self, view, ctx):
        for m in view.members:
            if m.path:
                yield m.path, f"{ctx.display}!/{m.name}", m.name

    def signals(self, d: Dict) -> EmbeddedSignal:
        return EmbeddedSignal(
            kind=d["kind"], risky_members=d["risky_members"], chm_shortcut=d["chm_shortcut"],
            msi_script_actions=d["msi_script_actions"], xll_addin=d["xll_addin"],
            encrypted_unopened=bool(d["encrypted"] and not d["decrypted"]),
            password_from_message=d["password_from_message"])


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

    def member_context(self, scanner, view):
        # "Password: 4471" in the message opens the encrypted ZIP / 7z / RAR it carries
        return scanner.container_extractor.extra_passwords(view.archive_passwords)

    def capture(self, view, ctx):
        ctx.text = view.body_text   # the prompt-guard and LLM layers read the body

    FLAG_SOURCES = (("double_extension", "double_extension_attachments"),
                    ("rtlo_spoof", "rtlo_attachments"), ("executable", "executable_attachments"))

    def decorate(self, view_dict, summaries):
        written = set(view_dict.get("archive_passwords") or [])
        view_dict["archives_opened_with_mail_password"] = [
            s["name"] for s in summaries if s.get("archive_password") in written]
        # Like archive members: an attachment the message-level checks flagged
        # (pay.pdf.exe) is never shown as plainly "Clean".
        for summary in summaries:
            inner = str(summary.get("name", "")).split("!/", 1)[-1]
            summary["mail_flags"] = [flag for flag, key in self.FLAG_SOURCES
                                     if inner in (view_dict.get(key) or [])]

    def signals(self, d: Dict) -> MailSignal:
        return MailSignal(
            from_domain=d["from_domain"], reply_to_domain=d["reply_to_domain"],
            auth_failures=d["auth"]["failures"], display_name_spoof=d["display_name_spoof"],
            display_name_spoof_reason=d["display_name_spoof_reason"],
            reply_to_mismatch=d["reply_to_mismatch"], deceptive_links=d["deceptive_links"],
            executable_attachments=d["executable_attachments"],
            double_extension_attachments=d["double_extension_attachments"],
            rtlo_attachments=d["rtlo_attachments"], lure_subject=d["lure_subject"],
            archive_password_in_body=d.get("archives_opened_with_mail_password", []))
