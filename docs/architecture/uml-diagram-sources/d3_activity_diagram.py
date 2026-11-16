"""Diagram 3 - Activity diagram: how does one file get a verdict?

One file is traced from submission to its final result, with swimlanes for
who performs each step: the entry point, the parent process, the isolated
worker process and the optional external services. Guards are in [brackets].
Time-out and failure paths end where the code ends them (engine/workers.py).

Edit the texts and coordinates below, then run `python3 build_diagrams.py`.
"""

from __future__ import annotations

from typing import List

from umlkit import INK, MUTED, Diagram

TITLE = "Activity diagram: How does one file get a verdict?"

LANES = [  # x, width, title, subtitle
    (20, 220, "Entry point", "GUI, CLI, REST API, monitor, IMAP"),
    (240, 640, "Parent process", "RansomwareScanner and _IsolatedScan (engine/workers.py)"),
    (880, 500, "Worker process", "_worker_main(): scan_file() runs the pipeline"),
    (1380, 200, "External services", "optional"),
]
ENTRY, PARENT, WORKER, EXTERNAL = "#eff6ff", "#f5f3ff", "#f0fdf4", "#ffffff"
DECISION, BAD, GOOD = "#fef9c3", "#fee2e2", "#dcfce7"


def build(meta: dict) -> Diagram:
    d = Diagram("d3", 1600, 2400, TITLE,
                f"One file, from submission to its final result, in an isolated scan (the default). "
                f"Branch {meta['branch']}, commit {meta['commit']}.",
                "UML activity diagram with four swimlanes: entry point, parent process, worker "
                "process and external services. It shows the pipeline, the messages on the pipe "
                "and where time-out and failure paths end.")
    d.title_block()

    # ------------------------------------------------------------ entry point
    start = d.initial(130, 170)
    a1 = d.titled(32, 198, 196, "Submit a file for scanning",
                  "from the GUI, the CLI, the REST API, a watched folder or a mailbox",
                  fill=ENTRY, name="submit")
    d.edge([start.b(), a1.t()], "flow", ends=(start, a1))

    # ----------------------------------------------------- parent: get a worker
    b1 = d.titled(500, a1.cy - 42, 360, "scan_one() or _scan_targets() calls scan_isolated()",
                  "Start a worker process (the REST API hands over one it started earlier) "
                  "and wait for its 'ready' message.",
                  h=84, fill=PARENT, name="scan_isolated")
    d.edge([a1.r(), (b1.left, a1.cy)], "flow", ends=(a1, b1))
    d1 = d.decision(680, b1.bottom + 78, 260, 88, ["Did a worker start", "and send 'ready'?"],
                    DECISION, name="worker ready?")
    d.edge([b1.b(), d1.t()], "flow", ends=(b1, d1))
    f0 = d.titled(256, d1.cy - 50, 250, "Fail closed: isolation unavailable",
                  "After 3 failed starts: failure_result() with the code "
                  "isolation_unavailable. Nothing is parsed in the parent.", h=100, fill=BAD,
                  name="isolation unavailable")
    d.edge([d1.l(), (f0.right, d1.cy)], "flow", "[no]",
           ((d1.left + f0.right) / 2, d1.cy - 13), (d1, f0))
    a2 = d.titled(32, f0.y, 196, "Report: not scanned",
                  "The CLI exits 3, the API answers 503, the GUI offers a retry.",
                  h=100, fill=BAD, name="not scanned")
    d.edge([f0.l(), (a2.right, f0.cy)], "flow", ends=(f0, a2))
    end0 = d.final(130, a2.bottom + 40)
    d.edge([a2.b(), end0.t()], "flow", ends=(a2, end0))
    d.label(130, end0.bottom + 16, "End: the file was not scanned", 12, True, check=False)

    b2 = d.titled(540, d1.bottom + 50, 300, "_dispatch(w)",
                  "Send the path over the pipe and start the clock: scan_timeout_seconds "
                  "(300 s).", h=84, fill=PARENT, name="dispatch")
    d.edge([d1.b(), b2.t(0.467)], "flow", "[yes]", (d1.cx + 26, d1.bottom + 22), (d1, b2))

    # ------------------------------------------------------ worker: the pipeline
    cx, cw = 930, 400
    mid = cx + cw / 2
    c1 = d.titled(cx, b2.y, cw, "_serve(): take the next path",
                  "Set scan_deadline = now + scan_timeout_seconds; scan_file() builds the "
                  "ScanContext.", h=84, fill=WORKER, name="serve")
    d.edge([b2.r(), c1.l()], "msg", "path", ((b2.right + c1.left) / 2, b2.cy - 12), (b2, c1))
    c2 = d.titled(cx, c1.bottom + 36, cw, "Fast layers, in pipeline order (_run_layer)",
                  ["hashes, allowlist, fuzzy, local-db, macro, yara, integrity, elf, pe, script, "
                   "mail, prompt-guard, relationships, qr, archive, web, embedded.",
                   "Container members go through the same pipeline at depth + 1. A layer that "
                   "raises is recorded in layer_errors and the scan goes on (partial)."],
                  fill=WORKER, name="fast layers")
    d.edge([c1.b(), c2.t()], "flow", ends=(c1, c2))
    d2 = d.decision(mid, c2.bottom + 84, 300, 92, ["Allowlisted, or risk", "already 100?"],
                    DECISION, name="skip heavy?")
    d.edge([c2.b(), d2.t()], "flow", ends=(c2, d2))

    fork = d.bar(903, d2.bottom + 34, 454, name="fork")
    d.edge([d2.b(), (mid, fork.top)], "flow", "[no]", (mid - 22, d2.bottom + 16), (d2, fork))
    par_y = fork.bottom + 22
    layers = [("emulation", ["box-js,", "if enabled"]), ("ml", ["byte-structure", "classifier"]),
              ("llm", ["ask the LLM", "(time-bounded)"]),
              ("virustotal", ["hash lookup", "(time-bounded)"])]
    pars = []
    for i, (name, rows) in enumerate(layers):
        box = d.node(903 + i * 116, par_y, 106, [name] + rows, h=80, fill=WORKER,
                     bold=[True, False, False], sizes=[12.5, 12, 12], pad=6, name=f"layer {name}")
        d.edge([(box.cx, fork.bottom), box.t()], "flow", ends=(fork, box))
        pars.append(box)
    join = d.bar(903, par_y + 80 + 30, 454, name="join")
    for box in pars:
        d.edge([box.b(), (box.cx, join.top)], "flow", ends=(box, join))
    d.label(1250, fork.top - 13, "heavy layers run in parallel (thread pool)", 12, fill=MUTED,
            check=False)

    d3 = d.decision(mid, join.bottom + 78, 340, 100, ["Sandbox configured, and", "risk >= 25 or",
                                                      "SANDBOX_SUBMIT = all?"], DECISION,
                    name="sandbox?")
    d.edge([(mid, join.bottom), d3.t()], "flow", ends=(join, d3))
    c6 = d.titled(cx, d3.bottom + 40, cw, "SandboxLayer.run(): last, on its own",
                  "With less than one 15 s poll left before the safety margin: sandbox = "
                  "timeout and nothing is submitted. Otherwise send 'provisional' (sandbox = "
                  "timeout), submit the file to CAPE and poll, then send 'settled'.",
                  fill=WORKER, name="sandbox layer")
    d.edge([d3.b(), c6.t()], "flow", "[yes]", (mid + 24, d3.bottom + 19), (d3, c6))
    m1 = d.decision(mid, c6.bottom + 40, 46, 32, [""], "#ffffff", name="merge 1")
    d.edge([c6.b(), m1.t()], "flow", ends=(c6, m1))
    bypass_x = 892
    d.edge([d2.l(), (bypass_x, d2.cy), (bypass_x, m1.cy), m1.l()], "flow",
           ["[yes] heavy", "layers skipped"], (936, d2.cy - 22), (d2, m1), name="skip heavy")
    d.edge([d3.l(), (bypass_x, d3.cy)], "flow", "[no]", (936, d3.cy - 13), (d3,),
           name="no sandbox")
    c7 = d.titled(cx, m1.bottom + 30, cw, "_assemble(ctx)",
                  "ScoringMatrix.score(ctx.signals) gives the risk score 0-100 and the verdict; "
                  "assess() gives scan_status; provenance is added.", fill="#fef3c7",
                  name="assemble")
    d.edge([m1.b(), c7.t()], "flow", ends=(m1, c7))
    c8 = d.titled(cx, c7.bottom + 34, cw, "Reply to the parent",
                  "'completed' snapshot, 'log' records, then 'ok' with the result. A MemoryError, "
                  "RecursionError or other exception in scan_file() is sent as 'error' instead.",
                  fill=WORKER, name="reply")
    d.edge([c7.b(), c8.t()], "flow", ends=(c7, c8))
    done = d.flow_final(mid, c8.bottom + 40)
    d.edge([c8.b(), done.t()], "flow", ends=(c8, done))
    d.label(mid + 150, done.cy, ["done in the worker:", "it waits for the next path"], 12,
            fill=MUTED, check=False)

    # --------------------------------------------- parent: watch the worker
    watch_x, watch_w = 620, 210
    watch_y, watch_b = c2.y, c8.bottom
    d.rect(watch_x, watch_y, watch_w, watch_b - watch_y, PARENT, INK, 1.5, 10)
    from umlkit import Box
    watch = d.track(Box(watch_x, watch_y, watch_w, watch_b - watch_y, "rect", "watch"))
    d.text(watch.cx, watch_y + 24, "Watch the worker", 13.5, True, anchor="middle")
    d.text(watch.cx, watch_y + 42, "_step(), every tick (50 ms at most)", 12, anchor="middle",
           fill=MUTED, maxw=watch_w - 12)
    d.edge([b2.b(0.5), (b2.cx, watch_y)], "flow", ends=(b2, watch))

    def arrives(y: float, rows: List[str], src) -> None:
        """A message from the worker: dashed arrow plus what the parent does with it."""
        d.edge([(cx if src is not join else join.left, y), (watch.right, y)], "msg",
               ends=(src, watch), name=rows[0])
        ty = y - (len(rows) - 1) * 8
        for row in rows:
            d.text(watch_x + 12, ty + 4, row, 12, maxw=watch_w - 20)
            ty += 16

    arrives(c2.cy, ["'container', 'member':", "evidence so far is kept"], c2)
    arrives(join.cy, ["'external': what may leave", "'provisional': latest snapshot"], join)
    arrives(c6.cy, ["'provisional', 'sandbox',", "'settled': snapshot, state"], c6)
    arrives(c8.cy, ["'completed', 'log', then", "'ok' or 'error'"], c8)
    note_y = (join.cy + c6.cy) / 2
    for i, row in enumerate(["Each tick also checks the", "time limit and, on macOS,",
                             "the worker's memory use."]):
        d.text(watch_x + 12, note_y - 12 + i * 16, row, 12, fill=MUTED, maxw=watch_w - 20)

    d.note(256, watch_y, 340, [
        "Messages on the pipe",
        "Parent to worker: the file path, then None to stop.",
        "Worker to parent: JSON, read with a size limit and checked by check_reply() before "
        "any field is used. Kinds: ready, log, ok, error, container, member, provisional, "
        "settled, sandbox, external, completed, clear.",
        "'provisional' is the result the file gets if the worker has to be stopped now. "
        "'settled' and 'completed' need no more waiting. 'clear' drops a stale snapshot."],
        bold_first=True)

    # ------------------------------------------------------ external services
    ex, ew = 1392, 176
    vt = d.node(ex, pars[3].y - 17, ew, ["VirusTotal API", "hash lookup; upload", "only if opted in"],
                fill=EXTERNAL, bold=[True, False, False], sizes=[13, 12, 12], name="VirusTotal")
    d.edge([(pars[3].right, vt.cy), vt.l()], "msg", ends=(pars[3], vt))
    llm = d.node(ex, pars[3].bottom + 14 - 31, ew, ["LLM service", "Ollama (local) or", "OpenAI (cloud)"],
                 fill=EXTERNAL, bold=[True, False, False], sizes=[13, 12, 12], name="LLM")
    lx = pars[2].side("bottom", 0.8)[0]
    d.edge([(lx, pars[2].bottom), (lx, llm.cy), llm.l()], "msg", ends=(pars[2], llm, pars[3]),
           name="llm call")
    cape = d.node(ex, c6.cy - 30, ew, ["CAPE sandbox", "runs the file and", "returns a report"],
                  fill=EXTERNAL, bold=[True, False, False], sizes=[13, 12, 12], name="CAPE")
    d.edge([(c6.right, cape.cy), cape.l()], "msg", ends=(c6, cape))
    d.note(1390, cape.bottom + 44, 180, [
        "Docker: the worker has no network. These calls go through the intel service "
        "(api/intel.py) over a Unix socket."])

    # -------------------------------------------- parent: how the wait ended
    d5 = d.decision(560, watch_b + 78, 260, 88, ["How did the", "wait end?"], DECISION,
                    name="wait ended")
    d.edge([watch.b(0.25), (watch.side("bottom", 0.25)[0], watch_b + 18), (560, watch_b + 18),
            d5.t()], "flow", ends=(watch, d5))
    bus = d5.bottom + 26
    row = bus + 112
    b4 = d.node(252, row, 148, ["_finish(path, result):", "the worker's own", "result is used"],
                h=112, fill=GOOD, size=12, pad=8, name="finish")
    b6 = d.node(412, row, 148, ["The snapshot is", "kept as the result:", "nothing was", "still pending"],
                h=112, fill=GOOD, size=12, pad=8, name="keep snapshot")
    b7 = d.node(572, row, 148, ["stopped_result():", "finished layers kept,", "stalled ones listed in",
                                "stopped_layers;", "scan_status partial"],
                h=112, fill="#ffedd5", size=12, pad=8, name="stopped_result")
    b5 = d.node(732, row, 140, ["failure_result():", "scan_failed (Medium,", "or the kept member",
                                "evidence if higher);", "scan_status failed"],
                h=112, fill=BAD, size=12, pad=8, name="failure_result")
    d.edge([d5.b(), (560, bus)], "line", ends=(d5,), name="to outcomes")
    d.edge([(b4.cx, bus), (b5.cx, bus)], "line", name="outcome bus", check=False)
    guards = [
        (b4, ["['ok' reply]"]),
        (b6, ["[time limit passed;", "snapshot settled", "or completed]"]),
        (b7, ["[time limit passed;", "snapshot still", "provisional]"]),
        (b5, ["['error' or invalid", "reply, dead worker,", "memory limit, or", "time limit with",
              "no snapshot]"]),
    ]
    for box, rows in guards:
        d.edge([(box.cx, bus), box.t()], "flow", rows, (box.cx, bus + 56), (box,),
               name=rows[0])

    m3 = d.decision(b7.cx, row + 112 + 38, 46, 32, [""], "#ffffff", name="merge 3")
    d.edge([b6.b(), (b6.cx, m3.cy), m3.l()], "flow", ends=(b6, m3))
    d.edge([b7.b(), m3.t()], "flow", ends=(b7, m3))
    d.edge([b5.b(), (b5.cx, m3.cy), m3.r()], "flow", ends=(b5, m3))
    fork2 = d.bar(566, m3.bottom + 22, 160, name="fork 2")
    d.edge([m3.b(), (m3.cx, fork2.top)], "flow", ends=(m3, fork2))
    k = d.node(396, fork2.bottom + 28, 284,
               "_replace(i): stop and replace the worker. Kill it and its helper programs, "
               "delete its temp folder, start a new worker. An 'error' reply keeps the worker.",
               fill=BAD, size=12, name="replace worker")
    d.edge([(596, fork2.bottom), (596, k.top)], "flow", ends=(fork2, k))
    gone = d.flow_final(538, k.bottom + 32)
    d.edge([k.b(), gone.t()], "flow", ends=(k, gone))
    d.label(446, gone.cy, ["the stopped worker's", "flow ends here"], 12, fill=MUTED, check=False)

    m2 = d.decision(480, gone.bottom + 40, 46, 32, [""], "#ffffff", name="merge 2")
    d.edge([b4.b(), (b4.cx, m2.cy), m2.l()], "flow", ends=(b4, m2))
    d.edge([(700, fork2.bottom), (700, m2.cy), m2.r()], "flow", "result", (700, k.cy),
           (fork2, m2))
    d7 = d.decision(480, m2.bottom + 86, 348, 116, ["In collect(): a batch scan with",
                                                    "AUTO_QUARANTINE set, and the",
                                                    "verdict at or above it?"], DECISION,
                    name="auto-quarantine?")
    d.edge([m2.b(), d7.t()], "flow", ends=(m2, d7))
    b8 = d.node(708, d7.cy - 52, 164, ["QuarantineVault", ".quarantine():", "encrypt (AES-256-GCM),",
                                       "verify the SHA-256,", "remove the original"],
                h=104, fill=PARENT, size=12, pad=6, bold=[True, True, False, False, False],
                name="quarantine")
    d.edge([d7.r(), (b8.left, d7.cy)], "flow", "[yes]", ((d7.right + b8.left) / 2, d7.cy - 13),
           (d7, b8))
    b9 = d.titled(262, d7.bottom + 46, 400, "collect(): keep the result",
                  "Append it, record metrics, call the progress callback; scan_isolated() "
                  "returns to the caller.", h=84, fill=PARENT, name="collect")
    d.edge([d7.b(), (d7.cx, b9.top)], "flow", "[no]", (d7.cx + 24, d7.bottom + 20), (d7, b9))
    d.edge([b8.b(), (b8.cx, b9.cy), b9.r()], "flow", ends=(b8, b9))

    a3 = d.titled(32, b9.cy - 55, 196, "Report the verdict",
                  "Write the report, deliver alerts and outputs, show or return the result.",
                  h=110, fill=ENTRY, name="report")
    d.edge([b9.l(), (a3.right, b9.cy)], "flow", ends=(b9, a3))
    end = d.final(130, a3.bottom + 40)
    d.edge([a3.b(), end.t()], "flow", ends=(a3, end))
    d.label(130, end.bottom + 16, "End: verdict and scan_status", 12, True, check=False)

    # --------------------------------------------------------------- the key
    kx, ky = 904, done.bottom + 56
    d.rect(kx, ky, 452, 196, "#ffffff", "#94a3b8", 1, 6, "frame")
    d.text(kx + 14, ky + 22, "Key", 13, True)
    d.ellipse(kx + 24, ky + 44, 7, 7, INK, INK, 1)
    d.text(kx + 44, ky + 48, "start of the activity", 12)
    d.ellipse(kx + 244, ky + 44, 9, 9, "#ffffff", INK, 1.6)
    d.ellipse(kx + 244, ky + 44, 5, 5, INK, INK, 1)
    d.text(kx + 262, ky + 48, "end of the activity", 12)
    d.ellipse(kx + 24, ky + 72, 9, 9, "#ffffff", INK, 1.6)
    d.line((kx + 18, ky + 66), (kx + 30, ky + 78), INK, 1.6)
    d.line((kx + 18, ky + 78), (kx + 30, ky + 66), INK, 1.6)
    d.text(kx + 44, ky + 76, "one flow ends, the rest goes on", 12)
    d.polygon([(kx + 232, ky + 72), (kx + 244, ky + 64), (kx + 256, ky + 72), (kx + 244, ky + 80)],
              DECISION, INK, 1.3)
    d.text(kx + 262, ky + 76, "decision, with [guards]", 12)
    d.rect(kx + 14, ky + 97, 44, 6, INK, INK, 1, 2)
    d.text(kx + 68, ky + 104, "fork or join: the flows between two bars run in parallel", 12)
    d.edge([(kx + 14, ky + 128), (kx + 58, ky + 128)], "flow", check=False)
    d.text(kx + 68, ky + 132, "control flow: what happens next", 12)
    d.edge([(kx + 14, ky + 154), (kx + 58, ky + 154)], "msg", check=False)
    d.text(kx + 68, ky + 158, "message on the pipe, or a call to an external service", 12)
    d.polygon([(kx + 25, ky + 180), (kx + 36, ky + 172), (kx + 47, ky + 180), (kx + 36, ky + 188)],
              "#ffffff", INK, 1.3)
    d.text(kx + 68, ky + 184, "merge: alternative flows come together", 12)

    # ----------------------------------------------------------- swimlanes
    bottom = end.bottom + 44
    d.h = bottom + 20
    head_y, head_h = 84, 50
    for i, (x, w, title, sub) in enumerate(LANES):
        d.rect(x, head_y, w, bottom - head_y, "#ffffff" if i % 2 else "#f8fafc", "#475569", 1.4,
               0, "back")
        d.rect(x, head_y, w, head_h, "#1e293b", "#1e293b", 1.4, 0, "back")
        d.text(x + w / 2, head_y + 21, title, 14.5, True, anchor="middle", fill="#ffffff",
               layer="frame", maxw=w - 12)
        d.text(x + w / 2, head_y + 39, sub, 12, anchor="middle", fill="#e2e8f0", layer="frame",
               maxw=w - 12)
    return d


NOTES: List[str] = [
    "The worker runs the fast layers one after another, then emulation, ml, llm and virustotal "
    "together on up to four threads (_run_together, engine/staging.py). In a worker with a "
    "sandbox configured, the sandbox layer runs last, on its own.",
    "A provisional snapshot is sent only while every layer still running is VirusTotal or the "
    "LLM (_publish_pending); a stalled parser, classifier or emulator is treated as a failure, "
    "not as an external time-out.",
    "At the time limit the parent keeps a settled or completed snapshot as it is, turns a "
    "provisional one into a partial result with stopped_result(), and falls back to "
    "failure_result() when it holds none (_IsolatedScan._step).",
    "failure_result() scores the scan_failed indicator (25 points, Medium). Member evidence "
    "reported before the failure is kept when it scores higher.",
    "In the code the result is handed to on_result() first and the stopped worker is replaced "
    "straight after; the fork shows that both happen.",
    "Automatic quarantine belongs to collect(), the on_result callback of _scan_targets(). "
    "scan_one() and the REST API pass their own callback, so they never quarantine.",
    "An allowlisted file skips the heavy layers unless its MD5 is also in the local malware "
    "database. A sandbox report found in the result cache is used without submitting the file.",
    "Not drawn: cancelling a batch (the GUI's Stop) hands out no further files, and a file "
    "already in a worker still finishes; with ISOLATE_SCANS=0 (development only) scan_file() "
    "runs in the caller's process and none of the pipe messages exist.",
]
