"""Diagram 9 - nested containers: an e-mail carrying an archive carrying a document
and a script (illustrative names; no real sample).

Read from engine/containers.py (scan_container, MailHandler, ArchiveHandler,
member_summary), detectors/container_extractor.py (open, nested expansion,
passwords, limits), detectors/scoring.py (_worst, _prefixed), engine/completeness.py
(member reasons, precedence) and engine/workers.py (container and member messages).
"""

from __future__ import annotations

from typing import List

from umlkit import MUTED, Diagram

TITLE = "Nested containers: one e-mail, one archive, two members"

D0 = "#dbeafe"
D1 = "#e0e7ff"
D2 = "#f0fdf4"
UP = "#fef3c7"


def build(meta: dict) -> object:
    d = Diagram("d9", 1600, 830, TITLE,
                f"Illustrative inert example; behaviour read from engine/containers.py and "
                f"detectors/container_extractor.py at commit {meta['code_commit']}.",
                "Containment tree of an e-mail with an encrypted archive attachment holding a "
                "document and a script; what goes down (passwords, depth, budgets) and what comes "
                "back up (member summaries, worst-member evidence, incomplete reasons).")
    d.title_block()

    # depth bands
    for i, (band_y, h, label) in enumerate([(92, 210, "depth 0  (top-level file)"),
                                       (318, 240, "depth 1  (attachment)"),
                                       (574, 150, "depth 2  (archive members)")]):
        d.rect(24, band_y, 1000, h, ["#f8fafc", "#ffffff", "#f8fafc"][i], "#94a3b8", 1, 6, "back")
        d.text(40, band_y + 22, label, 13, True, fill=MUTED, layer="back")

    mail = d.titled(220, 130, 600, "invoice.eml   (MailHandler: ContainerLayer 'mail')",
                    ["Sender checks (SPF / DKIM / DMARC from the top Authentication-Results), "
                     "display-name spoof, reply-to, deceptive links, risky attachment names. "
                     "The body becomes ctx.text for prompt-guard and the LLM. "
                     "\"Password: 4471\" in the body is offered to the archive below."],
                    fill=D0, size=12.5, name="mail")
    arc = d.titled(220, 356, 600, "invoice.eml!/docs.zip   (ArchiveHandler: 'archive')",
                   ["Opened into a private temp folder by ContainerExtractor: password tried "
                    "from the message, then common ones; zip-slip and device names refused; "
                    "nested archives expanded by the extractor itself (archive_max_depth 3); "
                    "100 MB total, 500 entries, ratio 100x; risky members get the scan budget "
                    "(archive_scan_members 25) first."],
                   fill=D1, size=12.5, name="archive")
    doc = d.titled(60, 612, 440, "...docs.zip!/report.docm",
                   ["Full pipeline at depth 2: macro (olevba), YARA, integrity, prompt-guard, "
                    "relationships, QR, ML, LLM. Its own containers would only be listed: "
                    "depth 2 = max_nesting."], fill=D2, size=12.5, name="docm")
    js = d.titled(540, 612, 440, "...docs.zip!/pay.js",
                  ["Full pipeline at depth 2: script categories (download, execute, recovery...), "
                   "obfuscation, YARA. Emulation only if enabled (off by default; it runs the "
                   "script in box-js)."], fill=D2, size=12.5, name="js")
    d.edge([mail.b(0.5), arc.t(0.5)], "flow", "scan_file(attachment, depth 1)",
           (mail.cx + 120, (mail.bottom + arc.top) / 2), (mail, arc))
    d.edge([arc.b(0.3), (arc.side("bottom", 0.3)[0], 590), (doc.cx, 590), doc.t()], "flow",
           ends=(arc, doc))
    d.edge([arc.b(0.7), (arc.side("bottom", 0.7)[0], 590), (js.cx, 590), js.t()], "flow",
           ends=(arc, js))
    d.label(arc.cx, 590, "scan_file(member, depth 2)", 12)

    # what comes back up
    d.frame(1060, 92, 516, 632, "What comes back up, per level", fill="#fffbeb", stroke="#b45309")
    rows = [
        ("Member summary", "name, verdict, risk_score, hashes, first 8 indicators, scan_status; "
                           "archive flags (double extension, RTLO, executable) attached."),
        ("Worst-member evidence", "the member with the highest risk score: its contributions are "
                                  "copied into the container's signal (.worst) and re-scored with "
                                  "a prefix: archive_member:macro_autoexec, then "
                                  "mail_attachment:archive_member:..."),
        ("Completeness", "each member's incomplete_reasons join ctx.member_reasons; the container "
                         "takes the most severe status: failed > locked > partial > unsupported "
                         "> complete. An encrypted member never opened is 'locked'."),
        ("Provenance", "what members sent outside (provenance.shared) is listed with member_path."),
        ("In a worker", "for the top-level file only, the worker reports 'container' (its own "
                        "findings) and 'member' (each direct member done), so a time-out keeps "
                        "them as partial evidence."),
    ]
    y = 132.0
    for title, body in rows:
        b = d.titled(1078, y, 480, title, [body], fill=UP, size=12.5, align="start", name=title)
        y = b.bottom + 12

    d.note(60, 744, 960, [
        "Limits that stop the descent: max_nesting 2 (members of a depth-2 container are listed, "
        "not scanned); per-container scan budgets (archive 25, mail 25, web 5, embedded 25); "
        "mail_max_attachments 50 and the shared 100 MB byte budget. Every member left out becomes "
        "an incomplete reason, so the top-level result reads 'partial' (or 'locked'), never "
        "plain 'complete'."], size=12)
    return d


NOTES: List[str] = [
    "The names are illustrative; no real sample is involved.",
    "Archive members are scanned only from the archive's own view: nested archives were already "
    "expanded by the extractor, so ArchiveHandler.items() skips them (engine/containers.py).",
]
