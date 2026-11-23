"""Diagram 4 - Flowchart: how does the whole system fit together?

A file is followed from every supported intake channel, through the scan
engine, the isolated worker and its detection stages, to scoring and the
result destinations. Names are the ones used in the code.

Edit the texts and coordinates below, then run `python3 build_diagrams.py`.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from umlkit import INK, MUTED, Box, Diagram, text_width

TITLE = "Flowchart: How does the whole system fit together?"

# intake channel code -> (chip fill, chip text colour)
CHANNELS = {
    "GUI": ("#dbeafe", "#1e3a8a"),
    "CLI": ("#dcfce7", "#14532d"),
    "BG": ("#fef3c7", "#78350f"),
    "MON": ("#fae8ff", "#701a75"),
    "IMAP": ("#ffe4e6", "#881337"),
    "API": ("#e0e7ff", "#312e81"),
}

ENGINE = "#eff6ff"
STAGE = "#f0fdf4"
PARENT = "#f5f3ff"
OUT = "#f8fafc"
DECISION = "#fef9c3"


def chips(d: Diagram, x: float, y: float, codes: Sequence[str], gap: float = 5) -> float:
    """A row of channel chips starting at x; returns the x after the last one."""
    for code in codes:
        fill, color = CHANNELS[code]
        x += d.chip(x, y, code, fill, color, stroke=color) + gap
    return x


def stage(d: Diagram, x: float, y: float, w: float, h: float, title: str,
          items: Sequence[Tuple[str, str]]) -> Box:
    """A detection stage: a title and one line per layer (code name in bold)."""
    d.rect(x, y, w, h, STAGE, INK, 1.5, 8)
    d.text(x + w / 2, y + 22, title, 13.5, True, anchor="middle", maxw=w - 16)
    d.line((x + 10, y + 32), (x + w - 10, y + 32), "#64748b", 1)
    ty = y + 36
    for name, what in items:
        ty += 20
        d.ellipse(x + 15, ty - 4.5, 2.2, 2.2, INK, INK, 1)
        used = d.text(x + 24, ty, name, 12.5, True)
        d.text(x + 24 + used + 4, ty, what, 12.5, maxw=w - 34 - used - 4)
    return d.track(Box(x, y, w, h, "rect", title))


def destination(d: Diagram, x: float, y: float, w: float, h: float, title: str, body: str,
                codes: Sequence[str], extra: str = "") -> Box:
    """A result destination with the intake channels that reach it."""
    from umlkit import wrap
    d.rect(x, y, w, h, OUT, INK, 1.5, 8)
    d.text(x + 12, y + 22, title, 13.5, True, maxw=w - 24)
    ty = y + 26
    for row in wrap(body, w - 24, 12.5):
        ty += 16.5
        d.text(x + 12, ty, row, 12.5, fill=MUTED, maxw=w - 24)
    d.text(x + 12, y + h - 13, "from", 12, fill=MUTED)
    end = chips(d, x + 12 + text_width("from", 12) + 7, y + h - 27, codes)
    if extra:
        d.text(end + 3, y + h - 13, extra, 12, fill=MUTED, maxw=x + w - 10 - end - 3)
    return d.track(Box(x, y, w, h, "rect", title))


def build(meta: dict) -> Diagram:
    d = Diagram("d4", 1600, 1876, TITLE,
                f"Follow a file from any intake channel to its outputs. Branch {meta['branch']}, "
                f"commit {meta['commit']}.",
                "Flowchart of Aegis Sentinel: six intake channels, the scan engine, the isolated "
                "worker with its detection stages, scoring, and eight result destinations.")
    d.title_block()

    # ---------------------------------------------------------------- legend
    lx, ly = 884, 30
    d.rect(lx, ly - 16, 696, 54, "#f8fafc", "#94a3b8", 1, 6, "frame")
    d.edge([(lx + 14, ly), (lx + 58, ly)], "flow", check=False)
    d.text(lx + 66, ly + 4, "the file or its result moves on", 12)
    d.edge([(lx + 262, ly), (lx + 306, ly)], "msg", check=False)
    d.text(lx + 314, ly + 4, "call to an external service", 12)
    d.polygon([(lx + 492, ly), (lx + 504, ly - 8), (lx + 516, ly), (lx + 504, ly + 8)],
              DECISION, INK, 1.3, "frame")
    d.text(lx + 524, ly + 4, "decision", 12)
    end = chips(d, lx + 14, ly + 13, list(CHANNELS))
    d.text(end + 4, ly + 27, "intake channel codes, repeated on each destination that channel reaches",
           12)

    # ------------------------------------------------------- 1 intake channels
    d.frame(20, 86, 1560, 152, "1  Intake channels: every way a file reaches the scanner")
    intake_text = [
        ("GUI", "Desktop GUI", ["aegis_gui: ScanController", "a file, a folder or all folders"]),
        ("CLI", "Command line", ["RansomwareScanner.py", "--scan-file PATH, --scan-now"]),
        ("BG", "Background service", ["--background scheduler", "run_scan() every N hours"]),
        ("MON", "Folder monitoring", ["FolderMonitor (watchdog)",
                                      "new or changed files, once settled"]),
        ("IMAP", "IMAP mailbox", ["MailboxScanner (--scan-imap)", "new messages, read-only"]),
        ("API", "REST API", ["POST /scan: _ScanService", "token, rate and size limits"]),
    ]
    intake: dict = {}
    for i, (code, title, body) in enumerate(intake_text):
        x = 40 + i * 256
        fill, color = CHANNELS[code]
        intake[code] = d.titled(x, 128, 240, title, body, h=96, fill=fill, name=f"intake {code}")
        d.chip(x + 10, 118, code, "#ffffff", color, stroke=color)
    gui, cli, bg, mon, imap, api = (intake[c] for c in CHANNELS)

    # ----------------------------------------------------------- 2 scan engine
    d.frame(20, 256, 1560, 376, "2  Scan engine")
    dq = d.decision(288, 345, 216, 84, ["One file,", "or folders?"], DECISION, name="one file?")
    d.edge([gui.b(), (gui.cx, 278), (288, 278), dq.t()], "flow", ends=(gui, dq), name="GUI in")
    d.edge([cli.b(), (cli.cx, 278), (288, 278), dq.t()], "flow", ends=(cli, dq), name="CLI in")

    e1 = d.titled(40, 424, 220, "scan_one(file_path)", "one file; no automatic quarantine",
                  h=92, fill=ENGINE)
    e2 = d.titled(320, 424, 280, "scan_all_directories()",
                  "all scan folders (a folder the GUI names: scan_directory()); the CLI "
                  "and background service come in through run_scan(), which checks the "
                  "canaries first", h=92, fill=ENGINE)
    e3 = d.titled(650, 424, 300, "_collect_target_files(directory)",
                  "walks each folder; keeps the configured file types; skips canary files, "
                  "~$ lock files and non-regular files", h=92, fill=ENGINE)
    e4 = d.titled(1000, 424, 260, "_scan_targets(targets)",
                  "a batch of files; collects every result", h=92, fill=ENGINE)

    d.edge([dq.l(), (120, 345), (120, e1.top)], "flow", "[one file]", (150, 332), (dq, e1))
    d.edge([dq.r(), (450, 345), (450, e2.top)], "flow", "[folders]", (425, 332), (dq, e2))
    d.edge([bg.b(), (bg.cx, 392), (540, 392), (540, e2.top)], "flow", "run_scan()",
           (bg.cx, 312), (bg, e2))
    d.edge([e2.r(), e3.l()], "flow", ends=(e2, e3))
    d.edge([e3.r(), e4.l()], "flow", ends=(e3, e4))
    d.edge([mon.b(), (mon.cx, 392), (1060, 392), (1060, e4.top)], "flow", "scan_batch()",
           (mon.cx, 312), (mon, e4))
    d.edge([imap.b(), (imap.cx, e4.top)], "flow", "run()", (imap.cx, 312), (imap, e4))

    diso = d.decision(660, 580, 270, 80, ["ISOLATE_SCANS on?", "(the default)"], DECISION,
                      name="isolate?")
    d.edge([e1.b(), (e1.cx, 528), (660, 528), diso.t()], "flow", ends=(e1, diso), name="e1 out")
    d.edge([e4.b(), (e4.cx, 528), (660, 528), diso.t()], "flow", ends=(e4, diso), name="e4 out")
    inproc = d.node(180, 557, 280, ["scan_file() in the caller's process",
                                    "ISOLATE_SCANS=0: development only"],
                    h=46, fill="#fff7ed", size=12.5, name="in-process")
    d.edge([diso.l(), inproc.r()], "flow", "[no]", (492, 567), (diso, inproc))

    # ------------------------------------------------------------- 3 isolation
    d.frame(300, 648, 720, 132, "3  Isolation")
    iso = d.titled(316, 678, 688, "scan_isolated() runs _IsolatedScan (engine/workers.py)",
                   "A pool of spawned worker processes: up to 4 by default, 1 with a VirusTotal "
                   "key. One file per worker at a time, with a time limit (SCAN_TIMEOUT_SECONDS, "
                   "300 s) and a memory limit (WORKER_MEMORY_MB, 2048). The path goes out over a "
                   "pipe; every reply comes back as JSON and is checked before it is used.",
                   fill=PARENT, name="isolation")
    d.edge([diso.b(), (660, iso.top)], "flow", "[yes]", (690, 636), (diso, iso))
    d.edge([api.b(), (api.cx, 722), (iso.right, 722)], "flow",
           ["_ScanService.scan()", "one fresh worker per upload"], (api.cx, 440), (api, iso))

    # ------------------------------------------- 4 worker: detection pipeline
    d.frame(20, 820, 1380, 412)
    d.text(1388, 840, "4  Worker process: _worker_main() runs scan_file(path), the detection "
                      "pipeline", 13, True, anchor="end", layer="frame")
    top, height = 862, 190
    s1 = stage(d, 40, top, 240, height, "Identify the file", [
        ("hashes", "MD5 and SHA-256"), ("allowlist", "known-good SHA-256"),
        ("fuzzy", "TLSH / ssdeep likeness"), ("local-db", "known-bad MD5")])
    s2 = stage(d, 310, top, 240, height, "Inspect structure and code", [
        ("macro", "VBA / XLM macros"), ("yara", "rule matches"),
        ("integrity", "format vs extension"), ("elf", "Linux programs"),
        ("pe", "Windows programs"), ("script", "JS, VBS, PS1, BAT ...")])
    s3 = stage(d, 580, top, 290, height, "Open containers and documents", [
        ("mail", "e-mail and attachments"), ("prompt-guard", "hidden text, injection"),
        ("relationships", "Office external links"), ("qr", "QR codes and their links"),
        ("archive", "ZIP, 7z, RAR, ISO members"), ("web", "payloads hidden in HTML / SVG"),
        ("embedded", "OneNote, CHM, MSI ...")])
    dh = d.decision(985, top + height / 2, 190, 100, ["Allowlisted,", "or risk", "already 100?"],
                    DECISION, name="skip heavy?")
    s4 = stage(d, 1120, top, 265, height, "Heavy layers, run in parallel", [
        ("emulation", "box-js (opt-in)"), ("ml", "byte-structure classifier"),
        ("llm", "LLM opinion on the text"), ("virustotal", "reputation by hash"),
        ("sandbox", "CAPE (opt-in), runs last")])

    d.edge([iso.b(0.12), (iso.side("bottom", 0.12)[0], 800), (s1.cx, 800), s1.t()], "flow",
           ends=(iso, s1), name="into pipeline")
    d.edge([inproc.b(0.2), (inproc.side("bottom", 0.2)[0], 800)], "flow", ends=(inproc,),
           name="in-process path")
    d.label(128, 700, ["same pipeline,", "no worker"], 12, fill=MUTED)
    d.edge([s1.r(), s2.l()], "flow", ends=(s1, s2))
    d.edge([s2.r(), s3.l()], "flow", ends=(s2, s3))
    d.edge([s3.r(), dh.l()], "flow", ends=(s3, dh))
    d.edge([dh.r(), s4.l()], "flow", "[no]", (1100, top + height / 2 - 13), (dh, s4))
    d.edge([s3.b(0.5), (s3.cx, 1090), (s1.cx, 1090), s1.b()], "flow",
           "each member goes through the same pipeline at depth + 1 (limit: max_nesting = 2)",
           ((s3.cx + s1.cx) / 2, 1090), (s3, s1))

    s5 = d.titled(860, 1118, 525, "Score and assemble the result: _assemble()",
                  "ScoringMatrix.score(Signals) adds the weighted contributions, capped per "
                  "category, into a risk score 0-100 and the verdict Clean, Low, Medium, High or "
                  "Critical. assess() sets scan_status: complete, unsupported, partial, locked or "
                  "failed.", fill="#fef3c7", name="score")
    d.edge([dh.b(), (dh.cx, s5.top)], "flow", ["[yes] heavy", "layers skipped"],
           (dh.cx, 1078), (dh, s5))
    d.edge([s4.b(), (s4.cx, s5.top)], "flow", ends=(s4, s5))

    # external services reached by the heavy layers
    d.frame(1420, 820, 160, 412, "External services", "#ffffff", "#475569", dash="6 4")
    vt = d.node(1432, 868, 136, ["VirusTotal"], h=40, fill="#ffffff", bold=True, name="VirusTotal")
    llm = d.node(1432, 924, 136, ["LLM service", "Ollama or OpenAI"], h=52, fill="#ffffff",
                 bold=[True, False], sizes=[13, 12], name="LLM")
    cape = d.node(1432, 992, 136, ["CAPE sandbox"], h=40, fill="#ffffff", bold=True, name="CAPE")
    for ext in (vt, llm, cape):
        d.edge([(s4.right, ext.cy), ext.l()], "msg", ends=(s4, ext))
    ty = 1064
    for row in ("Reached directly, or", "through intel: a Unix", "socket (Docker) or TLS",
                "(Kubernetes, option E)."):
        d.text(1500, ty, row, 12, anchor="middle", fill=MUTED)
        ty += 16

    # ------------------------------------------------------ 5 parent process
    d.frame(20, 1254, 1560, 252, "5  Back in the parent process")
    dt = d.decision(600, 1370, 270, 120, ["'ok' reply before", "the time limit?"], DECISION,
                    name="ok in time?")
    d.edge([s5.b(0.5), (s5.cx, 1243), (600, 1243), dt.t()], "flow",
           "reply over the pipe: 'ok' and the result (JSON, checked before use)",
           (870, 1243), (s5, dt))
    pf = d.titled(40, 1306, 380, "Time-out or failure",
                  "Time limit: the latest snapshot is kept, or stopped_result() marks the stalled "
                  "layers (partial). No snapshot, a crash, an 'error' or invalid reply, or the "
                  "memory limit: failure_result() (scan_failed, status failed). A stopped worker "
                  "is replaced.", fill="#fee2e2", name="failed")
    d.edge([dt.l(), (pf.right, dt.cy)], "flow", "[no]", (443, 1357), (dt, pf))
    da = d.decision(990, 1370, 330, 124, ["AUTO_QUARANTINE set and", "verdict at or above it?",
                                          "(folder, monitor, IMAP scans)"], DECISION,
                    name="auto-quarantine?")
    d.edge([dt.r(), da.l()], "flow", "[yes]", (760, 1357), (dt, da))
    d.edge([pf.b(), (pf.cx, 1468), (796, 1468), (796, 1370)], "flow", ends=(pf,),
           name="failed result joins")
    pq = d.titled(1215, 1326, 345, "QuarantineVault.quarantine()",
                  "encrypts the file (AES-256-GCM), verifies its SHA-256, then removes the "
                  "original", fill=PARENT, name="quarantine")
    d.edge([da.r(), (pq.left, da.cy)], "flow", "[yes]", (1186, 1357), (da, pq))

    # ------------------------------------------------- 6 result destinations
    d.frame(20, 1524, 1560, 332, "6  Result destinations")
    row1, row2, bus, dw, dh_ = 1570, 1720, 1698, 360, 106
    cols = [40, 420, 800, 1180]
    o1 = destination(d, cols[0], row1, dw, dh_, "GUI dashboard and detail window",
                     "one row per file as it finishes, details on demand; folder-monitor "
                     "results too when monitoring runs in the GUI", ["GUI"])
    o2 = destination(d, cols[1], row1, dw, dh_, "Console report",
                     "the text report, printed by --scan-file, --scan-now and --scan-imap",
                     ["CLI"])
    o3 = destination(d, cols[2], row1, dw, dh_, "JSON response",
                     "the result as api/scan_result.schema.json; HTTP 503 when no worker can start",
                     ["API"])
    o7 = destination(d, cols[3], row1, dw, dh_, "Encrypted quarantine vault",
                     "<id>.quar files; restored with --restore or from the GUI",
                     ["GUI", "CLI", "BG", "MON", "IMAP"])
    o4 = destination(d, cols[0], row2, dw, dh_, "Report files",
                     "ransomware_scan_<time>.json and .txt in the report folder (generate_report)",
                     ["GUI", "CLI", "BG", "MON", "IMAP"])
    o5 = destination(d, cols[1], row2, dw, dh_, "JSON Lines file",
                     "one result per line at JSONL_PATH, for a SIEM or log shipper (deliver)",
                     ["GUI", "CLI", "BG", "MON", "IMAP"])
    o6 = destination(d, cols[2], row2, dw, dh_, "Alerts through the outbox",
                     "signed webhook and e-mail from the alert level up (default High), retried "
                     "for up to 24 h; the API sends e-mail only",
                     ["GUI", "CLI", "BG", "MON", "IMAP", "API"])
    o8 = destination(d, cols[3], row2, dw, dh_, "Cloud storage (optional)",
                     "redacted reports and logs to an S3-compatible bucket (CLOUD_UPLOAD)",
                     ["GUI", "CLI", "BG", "MON", "IMAP"])

    gap_x = 1170                                   # between the third and fourth columns
    d.edge([da.b(), (da.cx, 1486), (gap_x, 1486), (gap_x, bus)], "line", ["[no]"],
           (da.cx + 26, 1450), (da,), name="result to the caller")
    d.edge([pq.b(0.25), (pq.side("bottom", 0.25)[0], 1486), (gap_x, 1486)], "line",
           "result", (pq.side("bottom", 0.25)[0], 1452), (pq,), name="result after quarantine")
    d.edge([pq.b(0.77), (pq.side("bottom", 0.77)[0], o7.top)], "flow", "the file",
           (pq.side("bottom", 0.77)[0], 1452), (pq, o7))
    d.edge([(o1.cx, bus), (o8.cx, bus)], "line", name="bus", check=False)
    for box in (o1, o2, o3):
        d.edge([(box.cx, bus), box.b()], "flow", ends=(box,))
    for box in (o4, o5, o6, o8):
        d.edge([(box.cx, bus), box.t()], "flow", ends=(box,))
    d.label(1170, 1544, "results return to the caller", 12, fill=MUTED)
    return d


NOTES: List[str] = [
    "GUI and CLI both reach scan_one() for a single file. For the configured folders the GUI "
    "calls scan_all_directories() itself, and scan_directory() for one folder it names; the CLI's --scan-now and the background service call "
    "run_scan(), which checks the canaries first and then calls it (engine/scanner.py).",
    "FolderMonitor.scan_batch() and MailboxScanner.run() hand their files straight to "
    "_scan_targets(); the REST API calls scan_isolated() itself through _ScanService.scan() "
    "(core/folder_watch.py, core/mailbox.py, api/server.py).",
    "Isolation fails closed: when no worker can start, the file is not parsed in the parent. "
    "The CLI exits 3, the API answers 503, the GUI offers a retry (engine/workers.py).",
    "Automatic quarantine runs in the collect() callback of _scan_targets(), so it applies to "
    "folder, monitor and IMAP scans, not to scan_one() or the API.",
    "The API path sends e-mail alerts only: _Alerts clears webhook_url, and it writes no report "
    "files or JSON Lines (api/server.py).",
]
