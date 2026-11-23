"""Diagram 2 - UML use-case diagram: who uses the system, and for what?

Human actors and external systems stand outside the system boundary
"Aegis Sentinel"; the user-facing goals are inside it. The GUI, the CLI and the
REST API are interfaces, not actors: each use case names the interfaces that
offer it.

Edit the texts and coordinates below, then run `python3 build_diagrams.py`.
"""

from __future__ import annotations

from typing import List, Sequence

from umlkit import INK, MUTED, Box, Diagram

TITLE = "Use-case diagram: Who uses the system, and for what?"

USER, ADMIN, SHARED = "#eff6ff", "#f0fdf4", "#fffbeb"
RX, RY, PITCH, TOP = 138, 38, 92, 262
LEFT_X, MID_X, RIGHT_X = 450, 800, 1150


def system(d: Diagram, x: float, y: float, w: float, name: str, sub: str = "",
           h: float = 58) -> Box:
    """An external system, drawn as a box with the keyword <<system>>."""
    d.rect(x, y, w, h, "#ffffff", INK, 1.6, 4)
    rows = ["«system»", name] + ([sub] if sub else [])
    sizes = [12, 13.5] + ([12] if sub else [])
    bolds = [False, True] + ([False] if sub else [])
    fills = [MUTED, INK] + ([MUTED] if sub else [])
    d.text_block(x + w / 2, y + h / 2, rows, 13, bolds, None, fills, "node", w - 12, sizes)
    return d.track(Box(x, y, w, h, "rect", name))


def build(meta: dict) -> Diagram:
    d = Diagram("d2", 1600, 1190, TITLE,
                f"Actors and external systems outside the boundary, user goals inside. "
                f"Branch {meta['branch']}, commit {meta['commit']}.",
                "UML use-case diagram of Aegis Sentinel with three primary actors, seven "
                "external systems and nineteen use cases; GUI, CLI and REST API are shown as "
                "interfaces.")
    d.title_block()

    # ------------------------------------------------------- system boundary
    bx, by, bw, bh = 300, 178, 1000, 892
    d.rect(bx, by, bw, bh, "#ffffff", INK, 2.2, 6, "frame")
    d.text(bx + 18, by + 30, "Aegis Sentinel", 20, True, layer="frame")

    def uc(cx: float, row: float, lines: Sequence[str], tag: str, fill: str, rx: float = RX) -> Box:
        return d.usecase(cx, TOP + PITCH * row, rx, RY, list(lines), tag, fill)

    # ------------------------------------------------- use cases: desktop user
    l1 = uc(LEFT_X, 0, ["Scan a single file"], "GUI · CLI · REST API", USER)
    l2 = uc(LEFT_X, 1, ["Scan the configured folders"], "GUI · CLI", USER)
    l3 = uc(LEFT_X, 2, ["Monitor folders for new files"], "GUI · CLI", USER)
    l4 = uc(LEFT_X, 3, ["Stop a running scan"], "GUI", USER)
    l5 = uc(LEFT_X, 4, ["Review verdicts and reports"], "GUI · CLI", USER)
    l6 = uc(LEFT_X, 5, ["Quarantine a suspicious file"], "GUI · CLI · automatic after scans", USER)
    l7 = uc(LEFT_X, 6, ["Restore a quarantined file"], "GUI · CLI", USER)
    left = [l1, l2, l3, l4, l5, l6, l7]

    # ------------------------------------------------ use cases: administrator
    r1 = uc(RIGHT_X, 0, ["Scan new e-mail from a mailbox"], "CLI", ADMIN)
    r2 = uc(RIGHT_X, 1, ["Run scheduled background scans"], "GUI · CLI", ADMIN)
    r3 = uc(RIGHT_X, 2, ["Configure settings, keys and alerts"], "GUI · CLI", ADMIN)
    r4 = uc(RIGHT_X, 3, ["Update detection content"], "GUI · CLI", ADMIN)
    r5 = uc(RIGHT_X, 4, ["Back up the quarantine key"], "GUI · CLI", ADMIN)
    r6 = uc(RIGHT_X, 5, ["Set up start at login"], "GUI · CLI", ADMIN)
    r7 = uc(RIGHT_X, 6, ["Check health and readiness"], "GUI · CLI · REST API", ADMIN)
    r8 = uc(RIGHT_X, 7, ["Lift containment after an alarm"], "CLI", ADMIN)
    canary = uc(RIGHT_X, 8, ["Guard folders with canary files"], "GUI · CLI", ADMIN)
    right = [r1, r2, r3, r4, r5, r6, r7, r8, canary]

    # ------------------------------------------- shared behaviour (middle)
    m1 = d.usecase(MID_X, TOP, 134, RY, ["Consult external services"], "VirusTotal · LLM · sandbox",
                   SHARED)
    m2 = d.usecase(MID_X, TOP + 150, 134, RY, ["Analyse a file and", "score its verdict"], "",
                   SHARED)
    m3 = d.usecase(MID_X, TOP + PITCH * 8 - 8, 134, RY + 6, ["Send alerts and", "upload reports"],
                   "webhook · e-mail · cloud storage", SHARED)

    # ----------------------------------------------------------------- actors
    api = system(d, 44, l1.cy - 34, 206, "API client", "mail gateway, SOAR, web app", h=68)
    d.edge([api.r(), l1.side("left", 0.36)], "line", ends=(api, l1), name="API client - scan")
    user = d.actor(170, 502, ["Desktop user"], ["through the GUI", "or the CLI"], label="left")
    hand = (user.right + 4, user.cy)
    for box in left:
        d.edge([hand, box.l()], "line", ends=(user, box), name=f"user - {box.name}")
    admin = d.actor(1430, 594, ["Administrator"], ["installs, configures", "and operates it"],
                    label="right")
    hand = (admin.left - 4, admin.cy)
    for box in right:
        d.edge([hand, box.r()], "line", ends=(admin, box), name=f"admin - {box.name}")

    # ------------------------------------------------------- external systems
    vt = system(d, 565, 96, 150, "VirusTotal")
    llm = system(d, 725, 96, 150, "LLM service", "Ollama or OpenAI")
    cape = system(d, 885, 96, 150, "CAPE sandbox")
    imap = system(d, 1075, 96, 150, "IMAP mail server")
    for ext in (vt, llm, cape):
        d.edge([ext.b(), m1.toward(ext.b())], "line", ends=(ext, m1), name=f"{ext.name} - m1")
    d.edge([imap.b(), r1.t()], "line", ends=(imap, r1), name="imap - r1")
    smtp = system(d, 541, by + bh + 22, 166, "SMTP mail server")
    hook = system(d, 717, by + bh + 22, 166, "Webhook receiver", "SOC, SIEM or chat")
    s3 = system(d, 893, by + bh + 22, 166, "S3-compatible storage")
    for ext in (smtp, hook, s3):
        d.edge([ext.t(), m3.toward(ext.t())], "line", ends=(ext, m3), name=f"{ext.name} - m3")

    # ------------------------------------------------- include / extend arrows
    def relation(src: Box, dst: Box, word: str, lpos, extra: str = "") -> None:
        rows = [word] + ([extra] if extra else [])
        d.edge([src.toward(dst.center), dst.toward(src.center)], "msg", rows, lpos, (src, dst),
               name=f"{word} {src.name} -> {dst.name}")

    def mid(a: Box, b: Box, dx: float = 0, dy: float = -11):
        p, q = a.toward(b.center), b.toward(a.center)
        return ((p[0] + q[0]) / 2 + dx, (p[1] + q[1]) / 2 + dy)

    relation(l1, m2, "«include»", mid(l1, m2, -6, -12))
    relation(l2, m2, "«include»", mid(l2, m2, 0, -11))
    relation(l3, m2, "«include»", mid(l3, m2, 4, 13))
    relation(r1, m2, "«include»", mid(r1, m2, 8, -12))
    relation(r2, m2, "«include»", mid(r2, m2, 0, -11))
    relation(m1, m2, "«extend»", (MID_X + 78, (m1.bottom + m2.top) / 2), "[service configured]")
    relation(m3, m2, "«extend»", (MID_X, 660), "[alert level reached]")
    d.edge([m3.r(), (canary.left, m3.cy)], "msg", ends=(m3, canary),
           name="«extend» alerts -> canary")
    d.label((m3.right + canary.left) / 2, m3.cy - 13, "«extend»", 12)
    d.label((m3.right + canary.left) / 2, m3.cy + 14, "[tripped]", 12)

    # ----------------------------------------------------- interfaces (key)
    ix, iy = 318, 892
    d.rect(ix, iy, 336, 160, "#f8fafc", "#475569", 1.2, 6)
    d.text(ix + 12, iy + 22, "Interfaces: how the system is reached", 13, True)
    d.text(ix + 12, iy + 40, "They are not actors. Each use case lists its interfaces.", 12,
           fill=MUTED, maxw=312)
    rows = [("GUI", "desktop application (aegis_gui)"),
            ("CLI", "RansomwareScanner.py command line"),
            ("REST API", "api/server.py: POST /scan, GET /ready")]
    ty = iy + 56
    for code, what in rows:
        used = d.chip(ix + 12, ty, code, "#1e293b", "#ffffff", h=22)
        d.text(ix + 12 + used + 8, ty + 16, what, 12, maxw=336 - 32 - used)
        ty += 32

    # ----------------------------------------------------- relationships (key)
    kx, ky = 24, 884
    d.rect(kx, ky, 262, 186, "#f8fafc", "#94a3b8", 1, 6, "frame")
    d.text(kx + 12, ky + 22, "Key", 13, True)
    d.edge([(kx + 12, ky + 42), (kx + 52, ky + 42)], "line", check=False)
    d.text(kx + 62, ky + 46, "takes part in the use case", 12)
    d.edge([(kx + 12, ky + 68), (kx + 52, ky + 68)], "msg", check=False)
    d.text(kx + 62, ky + 66, "«include»: always part of", 12)
    d.text(kx + 62, ky + 81, "the use case it points to", 12)
    d.edge([(kx + 12, ky + 108), (kx + 52, ky + 108)], "msg", check=False)
    d.text(kx + 62, ky + 106, "«extend»: added to it when", 12)
    d.text(kx + 62, ky + 121, "the [condition] holds", 12)
    d.rect(kx + 14, ky + 138, 36, 22, "#ffffff", INK, 1.4, 3, "frame")
    d.text(kx + 62, ky + 147, "«system»: an external", 12)
    d.text(kx + 62, ky + 162, "system (non-human actor)", 12)
    return d


NOTES: List[str] = [
    "Roles, not accounts: the code has no user roles, so the desktop user and the administrator "
    "may be the same person. The split shows everyday goals against set-up and operation.",
    "Interfaces per use case were checked in aegis_gui/pages/*.py, the argparse options in "
    "RansomwareScanner.py and the routes in api/server.py. The GUI has no mailbox scan, no "
    "containment release and no rule-pack install.",
    "Automatic quarantine follows folder, monitor and mailbox scans when AUTO_QUARANTINE is set "
    "(engine/protection.py); it never follows a single-file scan or an API upload.",
    "\"Send alerts and upload reports\" covers the alert outbox (signed webhook, e-mail) and the "
    "optional cloud spool (S3-compatible storage). A canary trip also goes through the outbox.",
    "\"Update detection content\" groups the hash-database import (GUI and CLI) with the signed "
    "rule pack, the allowlist and ML training (CLI only).",
]
