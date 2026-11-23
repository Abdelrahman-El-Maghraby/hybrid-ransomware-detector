"""Diagram 7 - one file across processes (sequence diagram of an isolated scan).

Read from engine/workers.py (scan_isolated, _IsolatedScan, _worker_main, _serve,
read_reply, check_reply, _final_reply), engine/staging.py (scan_file,
_run_heavy, _assemble), engine/containers.py (scan_container) and
engine/scanner.py (_scan_targets, scan_one, collect).

Solid arrows are calls or the path sent on the pipe; dashed arrows are JSON
messages from the worker (each read with a size limit and checked before use)
or answers from a service. Boxes on a lifeline are work done there.
"""

from __future__ import annotations

from typing import List

from umlkit import Diagram

TITLE = "One file across processes: an isolated scan, step by step"

HEAD = "#1e293b"
PARENT = "#eff6ff"
WORKER = "#f0fdf4"
EXT = "#f1f5f9"
NOTE = "#fffbeb"
BAD = "#fee2e2"

LANES = [  # x, title, subtitle
    (160, "Entry point", "GUI, CLI, API, monitor, IMAP"),
    (480, "Parent: _IsolatedScan", "engine/workers.py"),
    (800, "Worker process", "_worker_main, _serve"),
    (1120, "Pipeline in the worker", "scan_file, layers, _assemble"),
    (1440, "Services (optional)", "VirusTotal, LLM, CAPE"),
]


def build(meta: dict) -> object:
    d = Diagram("d7", 1600, 1010, TITLE,
                f"Isolated scan (the default). Branch {meta['branch']}, code at commit "
                f"{meta['code_commit']}.",
                "Sequence diagram: the entry point hands a file to the parent coordinator, which "
                "starts a worker process, sends the path, receives checked JSON messages while "
                "the pipeline runs, and hands the result back.")
    d.title_block()
    x = {i: lx for i, (lx, _, _) in enumerate(LANES)}
    top, bottom = 104, 862
    for lx, title, sub in LANES:
        d.node(lx - 130, top, 260, [title, sub], h=52, fill=HEAD, stroke=HEAD, rx=4,
               bold=[True, False], sizes=[14, 12], fills=["#ffffff", "#e2e8f0"], name=title)
        d.edge([(lx, top + 52), (lx, bottom)], "dline", color="#94a3b8", sw=1.2, check=False)

    def call(a: int, b: int, y: float, label: str, kind: str = "flow") -> None:
        d.edge([(x[a], y), (x[b], y)], kind, label, ((x[a] + x[b]) / 2, y - 11),
               check=False, lsize=12)

    def step(lane: int, y: float, w: float, rows: List[str], fill: str, h: float = 34) -> None:
        d.node(x[lane] - w / 2, y - h / 2, w, rows, h=h, fill=fill, size=12, rx=4, pad=6,
               track=False)

    y = 190
    call(0, 1, y, "scan_isolated(targets, ...)")
    y += 44
    call(1, 2, y, "start a spawned Process")
    step(2, y + 40, 300, ["memory limit, own process group,", "own temp folder; build the scanner"],
         WORKER, 40)
    y += 92
    call(2, 1, y, "'ready'", "msg")
    y += 40
    call(1, 2, y, "file path (clock starts)")
    y += 40
    call(2, 3, y, "scan_file(path)")
    step(3, y + 42, 290, ["fast layers in order; containers send", "members back through scan_file"],
         WORKER, 40)
    y += 90
    call(2, 1, y, "'container', 'member'", "msg")
    call(3, 4, y, "hash or text (opt-in)")
    y += 40
    call(2, 1, y, "'external', 'provisional'", "msg")
    call(4, 3, y, "answer", "msg")
    y += 40
    step(3, y + 2, 290, ["heavy layers on context copies;", "sandbox last, alone, in a worker"],
         WORKER, 40)
    y += 50
    step(3, y + 2, 290, ["_assemble: score, scan_status,", "provenance"], WORKER, 40)
    y += 48
    call(2, 1, y, "'completed', 'log', 'ok'", "msg")
    y += 14
    step(1, y + 30, 300, ["read_reply: at most 16 MiB of JSON;", "check_reply: shape and types;",
                          "the result must name this file"], PARENT, 58)
    y += 82
    call(1, 0, y, "on_result: collect()")
    step(0, y + 46, 250, ["auto-quarantine (batch scans", "only), then report and deliver"],
         PARENT, 40)

    # the alternative: the wait ends without a valid 'ok'
    ay = y + 86
    d.rect(300, ay, 700, 112, "#ffffff", "#b91c1c", 1.4, 4, "frame", "6 4")
    d.rect(300, ay, 52, 22, BAD, "#b91c1c", 1.2, 2, "frame")
    d.text(326, ay + 15, "alt", 12, True, anchor="middle", layer="frame")
    d.text(364, ay + 16, "[time limit, dead worker, invalid reply, memory limit]", 12, True,
           layer="frame", maxw=620)
    for i, row in enumerate([
            "settled or completed snapshot: kept as the result",
            "provisional snapshot: stopped_result(), status partial, waiting layers named",
            "no snapshot or a failure: failure_result(), status failed (scan_failed, Medium)",
            "then: kill the worker and its helpers, delete its temp folder, start another"]):
        d.text(316, ay + 40 + i * 18, row, 12, layer="frame", maxw=670)

    # notes
    d.note(1060, ay - 4, 500, [
        "Parent to worker: the path, then None to stop.",
        "Worker to parent: one JSON message each; kinds ready, log, ok, error, container, "
        "member, provisional, settled, sandbox, external, completed, clear.",
        "Three failed starts: no file is parsed in the parent; each gets an "
        "isolation_unavailable result (scan_status failed).",
        "ISOLATE_SCANS=0 (development only): the parent calls scan_file itself."],
        size=12, track=False)
    return d


NOTES: List[str] = [
    "scan_one() (GUI and CLI single file) and the REST API use the same path with their own "
    "callback, so they never quarantine automatically; folder scans, the monitor and IMAP use "
    "collect(), which does (engine/scanner.py).",
    "The REST API takes a fresh spare worker per upload (api/server.py, _ScanService).",
    "Services are reached directly on the desktop, and only through the intel service in Docker "
    "and in Kubernetes with option E.",
]
