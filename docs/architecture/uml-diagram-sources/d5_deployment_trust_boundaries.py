"""Diagram 5 - Deployment and trust boundaries: where does each part run, and
what separates it from the others?

Two execution modes are drawn separately: the desktop app / CLI on one computer,
and the Docker deployment (docker-compose.yml). External services, including a
separately isolated CAPE sandbox, are shared on the right. Every connection is
taken from the code or the compose file named in the notes.

A dashed frame is process separation inside one operating-system user or
container user: it limits time and memory and keeps a crash away, but it is not
a security boundary. A thick frame is a container: an OS-enforced boundary.

Edit the texts and coordinates below, then run `python3 build_diagrams.py`.
"""

from __future__ import annotations

from typing import List

from umlkit import INK, MUTED, Box, Diagram

TITLE = "Deployment: where each part runs, and what separates it"

PROC = "#eff6ff"        # a process
CONT = "#f0fdf4"        # a container
STORE = "#f8fafc"       # files and volumes
EXT = "#fff7ed"         # an external service
CAPE = "#fee2e2"        # the separately isolated sandbox
BOUND = "#b91c1c"       # container boundary stroke
SOFT = "#64748b"        # process-separation stroke


def container(d: Diagram, x: float, y: float, w: float, h: float, title: str,
              body: List[str], name: str) -> Box:
    """A container: thick solid boundary, title and wrapped body."""
    return d.titled(x, y, w, title, body, h=h, fill=CONT, stroke=BOUND, sw=3, rx=6, name=name)


def service(d: Diagram, x: float, y: float, w: float, title: str, body: str, modes: str,
            fill: str = EXT, h: float = 66) -> Box:
    """An external service with the modes that reach it (D desktop, K Docker)."""
    box = d.titled(x, y, w, title, body, h=h, fill=fill, name=title)
    d.chip(x + w - 10 - 8.2 * len(modes) - 14, y - 10, modes, "#ffffff", INK, stroke=INK)
    return box


def build(meta: dict) -> Diagram:
    d = Diagram("d5", 1600, 1384, TITLE,
                f"Two execution modes and the boundaries between their parts. Branch "
                f"{meta['branch']}, commit {meta['commit']}.",
                "Deployment and trust-boundary diagram of Aegis Sentinel: the desktop app and "
                "CLI on one computer, the Docker deployment with its four containers, and the "
                "external services each mode can reach.")
    d.title_block()

    # ---------------------------------------------------------------- legend
    lx, ly = 760, 22
    d.rect(lx, ly - 10, 820, 62, "#f8fafc", "#94a3b8", 1, 6, "frame")
    d.edge([(lx + 14, ly + 8), (lx + 58, ly + 8)], "flow", check=False)
    d.text(lx + 66, ly + 12, "file content", 12)
    d.edge([(lx + 160, ly + 8), (lx + 204, ly + 8)], "msg", check=False)
    d.text(lx + 212, ly + 12, "paths, results, requests or alerts (metadata)", 12)
    d.rect(lx + 520, ly, 40, 16, PROC, SOFT, 1.4, 3, "frame", "6 4")
    d.text(lx + 568, ly + 12, "process separation, not a security boundary", 12)
    d.rect(lx + 14, ly + 26, 40, 16, CONT, BOUND, 3, 3, "frame")
    d.text(lx + 62, ly + 38, "container: OS-enforced boundary", 12)
    d.chip(lx + 280, ly + 24, "D", "#ffffff", INK, stroke=INK)
    d.chip(lx + 306, ly + 24, "K", "#ffffff", INK, stroke=INK)
    d.text(lx + 334, ly + 38, "reached from the desktop mode (D) or the Docker mode (K)", 12)

    # ------------------------------------------------- mode 1: desktop and CLI
    d.frame(20, 90, 1190, 600, "Mode 1  Desktop app and CLI: one computer, one OS user",
            sub="Everything below runs as the signed-in user, with that user's files, "
                "network and keys.")
    files = d.titled(40, 160, 230, "Files to scan",
                     ["scan folders, chosen files, watched folders (WATCH_DIRS), "
                      "saved IMAP messages"], h=104, fill=STORE)
    parent = d.titled(330, 150, 450, "Parent process (GUI, CLI or --background)",
                      ["ScanController, run_scan(), FolderMonitor, MailboxScanner, "
                       "CanaryWatcher, the alert outbox.",
                       "Configuration and keys from the OS keyring or .env. Reads files to "
                       "walk, hash and quarantine them; never parses them."],
                      h=124, fill=PROC, name="desktop parent")
    reports = d.titled(860, 200, 330, "Reports, JSON Lines, logs, outbox",
                       "report_directory and the data folder", h=66, fill=STORE)
    vault = d.titled(860, 284, 330, "Quarantine vault and key",
                     "encrypted files; key in the keystore (mode 0600)", h=66, fill=STORE)
    canary = d.titled(860, 368, 330, "Canary files in guarded folders",
                      "a trip runs containment on the user's processes", h=66, fill=STORE)

    d.frame(310, 352, 490, 312, "Worker processes (spawn), same OS user", stroke=SOFT,
            dash="6 4", fill="#ffffff")
    worker = d.titled(330, 404, 450, "Scan workers: one file each",
                      ["The whole detection pipeline. Time limit SCAN_TIMEOUT_SECONDS; "
                       "memory limit: RLIMIT_AS (Linux), Job Object (Windows), RSS watchdog "
                       "(macOS); a private temp folder.",
                       "They receive the full configuration, API keys included."],
                      h=124, fill=PROC, name="desktop worker")
    helpers = d.titled(330, 560, 450, "Helper programs started by a worker",
                       ["7-Zip or unar, Tesseract, poppler, box-js. Stopped with their "
                        "worker; one that detached before discovery can survive (L-E5)."],
                       h=84, fill=PROC, name="helpers")

    d.edge([parent.b(0.3), (parent.side("bottom", 0.3)[0], worker.top)], "msg",
           "file path (pipe)", (parent.side("bottom", 0.3)[0], 330), (parent, worker))
    d.edge([(worker.side("top", 0.7)[0], worker.top), (worker.side("top", 0.7)[0], parent.bottom)],
           "msg", "JSON replies, checked", (worker.side("top", 0.7)[0], 330), (worker, parent))
    d.edge([files.b(), (files.cx, worker.cy), worker.l()], "flow",
           "read and parsed", (files.cx, 360), (files, worker))
    d.edge([files.r(), parent.l()], "flow", ends=(files, parent), name="files to parent")
    d.edge([worker.b(), helpers.t()], "msg", "starts", (worker.cx + 26, 544), (worker, helpers))
    for t, lane, box, kind in ((0.45, 815, reports, "msg"), (0.65, 830, vault, "flow"),
                               (0.85, 845, canary, "msg")):
        y = parent.side("right", t)[1]
        d.edge([parent.r(t), (lane, y), (lane, box.cy), box.l()], kind, ends=(parent, box),
               name=f"parent to {box.name}")

    # ----------------------------------------------------- mode 2: Docker
    d.frame(20, 714, 1190, 650, "Mode 2  Docker deployment: one host, four containers "
            "(docker-compose.yml)",
            sub="Distinct users, read-only root file systems, all capabilities dropped, "
                "no-new-privileges, memory, CPU and process limits.")
    client = d.titled(40, 800, 150, "API client", "HTTPS, bearer token", h=70, fill=STORE)
    proxy = container(d, 250, 790, 220, 110, "proxy (Caddy)",
                      ["uid 10003, network edge; publishes port 8443; TLS ends here"],
                      "proxy")
    analysis = container(d, 530, 780, 410, 206,
                         "analysis: api.server (_ScanService)",
                         ["uid 10001; network_mode none: no interface but loopback.",
                          "Secrets: api_token and intel_token only. tmpfs /tmp; volumes "
                          "analysis-state (reports, logs, outbox) and content (rules, "
                          "read-only)."],
                         "analysis")
    d.frame(550, 1006, 370, 112, "Workers, same uid 10001", stroke=SOFT, dash="6 4",
            fill="#ffffff")
    dworker = d.titled(565, 1046, 340, "Scan workers",
                       "time and memory limits; no network, no API keys", h=56, fill=PROC,
                       name="docker worker")
    intel = container(d, 1000, 780, 200, 300, "intel: api.intel",
                      ["uid 10002; network egress.",
                       "Secrets: VirusTotal and OpenAI keys, sandbox token, SMTP password.",
                       "Fixed operations; only the destinations its own configuration "
                       "names."],
                      "intel")
    container(d, 530, 1170, 410, 92, "content (tools profile, run by hand)",
                        ["--update-rules; network_mode none; writes the content volume "
                         "that analysis mounts read-only"], "content")
    d.titled(40, 1170, 440, "Named volumes and Docker secrets",
             ["api-socket and intel-socket carry Unix sockets between containers; "
              "analysis-state, content and intel-state hold data; secrets are files "
              "under /run/secrets."], h=92, fill=STORE)
    d.note(40, 1300, 900,
           ["Not in this mode: webhooks, JSON Lines, S3 uploads, automatic quarantine and "
            "--scan-imap. The analysis side has no network and intel offers no IMAP "
            "operation; API results reach e-mail only, through intel."])

    d.edge([client.r(), proxy.l()], "flow", "upload", (220, 818), (client, proxy))
    d.edge([proxy.r(0.35), (analysis.left, proxy.side("right", 0.35)[1])], "flow",
           "api.sock", (500, 815), (proxy, analysis))
    d.edge([(analysis.left, proxy.side("right", 0.7)[1]), proxy.r(0.7)], "msg",
           "result", (500, 880), (analysis, proxy))
    d.edge([analysis.b(), dworker.t()], "flow", "file path; JSON replies",
           (835, 996), (analysis, dworker))
    d.edge([analysis.r(0.3), (intel.left, analysis.side("right", 0.3)[1])], "msg",
           "requests", (970, 824), (analysis, intel))
    d.edge([analysis.r(0.75), (intel.left, analysis.side("right", 0.75)[1])], "msg",
           "e-mails", (970, 933), (analysis, intel))

    # ------------------------------------------------- external services
    d.frame(1230, 90, 350, 1274, "External services, when configured",
            sub="Chips: the modes that reach each one.")
    smtp = service(d, 1250, 160, 310, "SMTP server", "alert e-mails (metadata only)", "D K")
    hook = service(d, 1250, 250, 310, "Webhook receiver", "signed alerts (metadata only)", "D")
    s3 = service(d, 1250, 340, 310, "S3-compatible storage", "reports and logs (opt-in)", "D")
    imap = service(d, 1250, 430, 310, "IMAP mail server", "messages fetched read-only", "D")
    vt = service(d, 1250, 540, 310, "VirusTotal", "hash look-ups; uploads only if switched on",
                 "D K")
    llm = service(d, 1250, 630, 310, "LLM: OpenAI or Ollama", "document text sent for an "
                  "opinion", "D K")
    cape = service(d, 1250, 720, 310, "CAPE sandbox",
                   "your own server in a separately isolated environment; files are "
                   "detonated there, never here", "D K", CAPE, 84)
    egress = d.titled(1250, 836, 310, "Docker: through intel only",
                      "intel reaches the services marked K over its egress network; the "
                      "analysis container cannot reach any of them", h=84, fill=CONT,
                      name="egress")
    d.note(1250, 950, 310,
           ["Security boundaries: the containers, and the separate CAPE environment. "
            "Worker processes are not one: on a desktop they share the user's access; in "
            "Docker they share uid 10001 with the API server."], 12)

    # desktop: the parent reaches SMTP, webhooks, S3 and IMAP
    bx = 1218
    py = parent.side("right", 0.12)[1]
    d.edge([parent.r(0.12), (bx, py), (bx, imap.cy)], "line", ends=(parent,),
           name="parent bus", check=False)
    for box in (smtp, hook, s3):
        d.edge([(bx, box.cy), box.l()], "msg", ends=(box,), name=f"parent to {box.name}",
               check=False)
    d.edge([imap.l(), (bx + 2, imap.cy)], "msg", ends=(imap,), name="IMAP to parent",
           check=False)
    d.label(1010, py - 11, "parent: alerts, uploads, IMAP", 12, fill=MUTED, check=False)
    # desktop: the worker reaches VirusTotal, the LLM and CAPE
    wy = worker.side("right", 0.75)[1]
    d.edge([worker.r(0.75), (bx, wy), (bx, cape.cy)], "line", ends=(worker,),
           name="worker bus", check=False)
    for box in (vt, llm, cape):
        d.edge([(bx, box.cy), box.l()], "msg", ends=(box,), name=f"worker to {box.name}",
               check=False)
    d.label(1010, wy - 11, "worker: hash, text or file", 12, fill=MUTED, check=False)
    # Docker: only intel goes out
    d.edge([intel.r(0.2), (1222, intel.side("right", 0.2)[1]), (1222, egress.cy), egress.l()],
           "msg", ends=(intel, egress), name="intel to egress", check=False)
    return d


NOTES: List[str] = [
    "Desktop: workers are started with multiprocessing spawn and get the full configuration, "
    "keys included (engine/workers.py, _Worker and _worker_main). The VirusTotal, LLM and "
    "sandbox layers run in the worker, so those requests leave from the worker process.",
    "Desktop: the parent sends webhook and e-mail alerts through the outbox, uploads to S3 "
    "and fetches IMAP messages (core/outputs.py, core/outbox.py, core/cloud.py, "
    "core/mailbox.py). It reads files to walk, hash (folder monitor) and quarantine them, "
    "but parsing happens only in a worker.",
    "Docker: proxy, analysis, intel and content are separate containers with their own uids "
    "(10003, 10001, 10002, 10001), read-only root file systems, cap_drop ALL and "
    "no-new-privileges. analysis and content use network_mode none; proxy is on the edge "
    "network and intel on the egress network (docker-compose.yml).",
    "Docker: the API reaches analysis through a Unix socket on the api-socket volume; "
    "analysis reaches intel through intel.sock. analysis holds only api_token and "
    "intel_token; the service keys are secrets of intel alone.",
    "The CAPE sandbox is the operator's own server and should run in its own isolated "
    "environment: files submitted there are executed. Emulation (box-js) also executes "
    "attacker JavaScript and belongs in an analysis VM only.",
]
