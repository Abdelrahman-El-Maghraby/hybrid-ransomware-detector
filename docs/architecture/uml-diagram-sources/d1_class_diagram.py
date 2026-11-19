"""Diagram 1 - Class diagram: what makes up the scanner?

The classes on the scan path, with the names they have in the code. The
relationships are the ones the code supports:

  inheritance   class RansomwareScanner(StagedPipelineMixin, ...), class X(Layer)
  composition   the owner creates the part and keeps it (self.x = X(...))
  association   the object keeps a reference to something it does not own
  dependency    a parameter, a call or a creation (run(scanner, ctx), ...)

Edit the texts and coordinates below, then run `python3 build_diagrams.py`.
"""

from __future__ import annotations

import math
from typing import List, Sequence

from umlkit import INK, MUTED, Box, Diagram, text_width

TITLE = "Class diagram: What makes up the scanner?"

FACADE, PIPE, SCORE, ISO, ENGINE, EXT, PROT = (
    "#dbeafe", "#dcfce7", "#fef3c7", "#ede9fe", "#e0f2fe", "#ffe4e6", "#f1f5f9")
HEAVY = "#fde68a"


def width_of(name: str, rows: Sequence[str], stereotype: str = "") -> int:
    need = max([text_width(name, 14, True), text_width(stereotype, 12)]
               + [text_width(r, 12.5) for r in rows])
    return math.ceil(need + 20)


def tree(d: Diagram, parent_point, rail_x: float, children: Sequence[Box], bus_y=None,
         name: str = "") -> None:
    """A shared generalisation: one hollow triangle at the parent, a rail, and a
    short tick to every child."""
    px, py = parent_point
    last = children[-1]
    if bus_y is None:                       # parent to the left of the rail
        d.edge([(rail_x, py), (px, py)], "gen", name=name, check=False)
        d.edge([(rail_x, min(py, children[0].cy)), (rail_x, last.cy)], "line", name=name,
               check=False, radius=0)
    else:                                   # parent above: trunk down to a bus
        d.edge([(rail_x, bus_y), (rail_x, last.cy)], "line", name=name, check=False, radius=0)
    for child in children:
        d.edge([(rail_x, child.cy), (child.left, child.cy)], "line", name=name, check=False)


def build(meta: dict) -> Diagram:
    d = Diagram("d1", 1600, 1650, TITLE,
                f"The classes on the scan path, with their names in the code. "
                f"Branch {meta['branch']}, commit {meta['commit']}.",
                "UML class diagram of the Aegis Sentinel scanner: the RansomwareScanner facade "
                "and its five mixins, the layer pipeline, scoring, the isolated-scan classes, "
                "the detection engines and the external-service clients.")
    d.title_block()

    # ------------------------------------------------------------- the mixins
    mixins = [
        ("StagedPipelineMixin", "«mixin» engine/staging.py",
         ["+ scan_file(file_path, _depth) : Dict", "- _run_layer(layer, ctx)",
          "- _run_heavy(layers, ctx)", "- _run_together(layers, ctx)", "- _assemble(ctx) : Dict",
          "+ provisional_result(ctx, stopped) : Dict"]),
        ("ProtectionMixin", "«mixin» engine/protection.py",
         ["+ quarantine_file(file_path, reason) : Dict", "- _maybe_auto_quarantine(result)",
          "+ check_canaries(notify, touched)", "+ deploy_canaries(directories)"]),
        ("ReportMixin", "«mixin» engine/report.py",
         ["+ generate_report(results, impact) : str"]),
        ("ExternalLookupsMixin", "«mixin» engine/external.py",
         ["+ analyze_with_llm(file_path, ...) : Dict",
          "+ scan_file_with_virustotal(file_path, hashes) : Dict", "+ vt_may_contact() : bool"]),
        ("TextExtractionMixin", "«mixin» engine/text.py",
         ["- _extract_text_from_file(file_path, allow_ocr) : str"]),
    ]
    widths = [width_of(n, rows, st) for n, st, rows in mixins]
    gap = (1560 - sum(widths)) / (len(mixins) - 1)
    x, mix = 20.0, []
    for (name, st, rows), w in zip(mixins, widths):
        mix.append(d.klass(x, 96, name, [], rows, w=w, stereotype=st, fill=FACADE))
        x += w + gap
    staged = mix[0]

    # ------------------------------------------------------------ the facade
    scanner = d.klass(756, 330, "RansomwareScanner", [
        "+ config : Dict", "+ pipeline : List[Layer]", "+ scoring : ScoringMatrix",
        "+ scan_deadline : Optional[float]", "+ member_listener, external_listener",
        "+ provisional_listener, completed_listener",
        "+ sandbox_listener, clear_provisional_listener"], [
        "+ scan_one(file_path) : Dict", "+ scan_directory(directory) : List[Dict]",
        "+ scan_all_directories() : List[Dict]", "+ run_scan() : str", "+ scan_mailbox()",
        "+ refresh_detection_content() : bool", "+ time_left() : Optional[float]",
        "- _collect_target_files(directory) : List[str]", "- _scan_targets(targets) : List[Dict]"],
        w=330, stereotype="engine/scanner.py", fill="#bfdbfe")
    bus = 300
    d.edge([scanner.t(), (scanner.cx, bus)], "line", name="inherits", check=False, radius=0)
    d.edge([(mix[0].cx, bus), (mix[-1].cx, bus)], "line", name="inherits", check=False, radius=0)
    for m in mix:
        d.edge([(m.cx, bus), m.b()], "gen", name="inherits", check=False)

    # ---------------------------------------------- context and signals (left)
    ctx = d.klass(20, 330, "ScanContext", [
        "+ path : str", "+ display : str", "+ depth : int", "+ result : Dict",
        "+ signals : Signals", "+ layer_log : List[Tuple]", "+ / scan_results : Dict"], [
        "+ start(scanner, path, depth, display)", "+ data() : Optional[bytes]"],
        w=250, stereotype="engine/layers.py (dataclass)", fill=PIPE)
    d.edge([(60, staged.bottom), (60, ctx.top)], "msg", "«create»", (96, (staged.bottom + ctx.top) / 2),
           (staged, ctx), name="scan_file creates the context")
    signals = d.klass(20, 624, "Signals", [
        "+ local_db_hit : bool", "+ allowlisted : str", "+ scan_failed : str",
        "+ yara : Optional[YaraSignal]", "+ macro, pe, mail, llm, sandbox, ...",
        "   19 typed signals: one per layer,",
        "   not hash, allowlist or local-db"], [
        "+ set(key, value)", "+ copy() : Signals", "+ changed_since(before) : Dict"],
        w=250, stereotype="detectors/signals.py (dataclass)", fill=SCORE)
    d.edge([ctx.b(), signals.t()], "comp", "signals  1", (ctx.cx + 44, (ctx.bottom + signals.top) / 2 + 6),
           (ctx, signals))

    # --------------------------------------------------------------- pipeline
    d.frame(290, 318, 420, 620, "Pipeline layers", "#f7fee7", "#4d7c0f")
    layer = d.klass(474, 350, "Layer", ["+ name : str", "+ heavy : bool = False"],
                    ["+ run(scanner, ctx)", "+ stopped_entry(scanner, ctx)"], w=200,
                    stereotype="engine/layers.py", fill=PIPE)
    between = (scanner.left + layer.right) / 2
    y_pipe = scanner.side("left", 0.2)[1]
    d.edge([(scanner.left, y_pipe), (layer.right, y_pipe)], "comp", ends=(scanner, layer),
           name="pipeline")
    d.label(between - 5, y_pipe - 12, "pipeline  22", 12, check=False)
    y_use = y_pipe + 36
    d.edge([(layer.right, y_use), (scanner.left, y_use)], "msg", ends=(layer, scanner),
           name="a layer uses the scanner's engines")
    d.label(between, y_use + 12, "«use»", 12, check=False)
    d.edge([layer.l(0.68), (ctx.right, layer.side("left", 0.68)[1])], "msg", "reads and writes",
           (382, layer.side("left", 0.68)[1] - 11), (layer, ctx))

    fast = ["HashLayer", "AllowlistLayer", "FuzzyHashLayer", "LocalDatabaseLayer", "MacroLayer",
            "YaraLayer", "IntegrityLayer", "ElfLayer", "PeLayer", "ScriptLayer",
            "PromptGuardLayer", "RelationshipLayer", "QRLayer", "ContainerLayer"]
    heavy = ["EmulationLayer", "MLLayer", "LLMLayer", "VirusTotalLayer", "SandboxLayer"]
    col_x, top, pitch = [306, 440, 574], 532, 30
    boxes = {}
    for i, name in enumerate(fast):
        col, row = divmod(i, 7)
        boxes[name] = d.name_box(col_x[col], top + row * pitch, name, w=126, h=24, fill=PIPE,
                                 size=12, pad=4)
    for row, name in enumerate(heavy):
        boxes[name] = d.name_box(col_x[2], top + row * pitch, name, w=126, h=24, fill=HEAVY,
                                 size=12)
    rail_y = 508
    d.edge([(layer.cx, rail_y), layer.b()], "gen", name="layers inherit", check=False)
    d.edge([(col_x[0] - 7, rail_y), (layer.cx, rail_y)], "line", name="layers inherit",
           check=False, radius=0)
    for col, names in ((0, fast[:7]), (1, fast[7:]), (2, heavy)):
        tree(d, None or (0, 0), col_x[col] - 7, [boxes[n] for n in names], bus_y=rail_y,
             name="layers inherit")
    d.text(col_x[2] + 126, top + 5 * pitch + 14, "heavy = True", 12, anchor="end", fill=MUTED)

    handler = d.klass(330, 778, "ContainerHandler", [], [
        "+ applies(ctx) : bool", "+ open(scanner, path)", "+ budget(scanner) : int",
        "+ items(view, ctx)", "+ signals(view_dict)"], w=190, stereotype="engine/containers.py",
        fill=PIPE)
    container = boxes["ContainerLayer"]
    d.edge([(470, container.bottom), (470, handler.top)], "comp", "handler  1",
           (506, (container.bottom + handler.top) / 2 + 5), (container, handler))
    handlers = [d.name_box(574, 790 + i * pitch, n, w=126, h=24, fill=PIPE, size=12)
                for i, n in enumerate(["ArchiveHandler", "MailHandler", "WebHandler",
                                       "EmbeddedHandler"])]
    tree(d, (handler.right, handler.cy), 556, handlers, name="handlers inherit")

    # ---------------------------------------------------------------- scoring
    matrix = d.klass(300, 992, "ScoringMatrix", ["+ registry : Registry"], [
        "+ score(signals) : ScoreResult", "- _aggregate(contribs, s) : ScoreResult"],
        stereotype="detectors/scoring.py", fill=SCORE)
    result = d.klass(640, 980, "ScoreResult", [
        "+ risk_score : int  (0 to 100)", "+ severity_score : float", "+ verdict : str",
        "+ is_malicious : bool", "+ contributions : List[Contribution]"], ["+ as_dict() : Dict"],
        stereotype="detectors/scoring.py (dataclass)", fill=SCORE)
    contrib = d.klass(960, 1000, "Contribution", [
        "+ indicator : str", "+ category : str", "+ points : float", "+ detail : str"], [],
        stereotype="(dataclass)", fill=SCORE, min_w=160)
    d.edge([scanner.b(0.12), (scanner.side("bottom", 0.12)[0], 962), (matrix.cx, 962), matrix.t()],
           "comp", "scoring  1", (610, 951), (scanner, matrix))
    d.edge([matrix.l(0.3), (280, matrix.side("left", 0.3)[1]), (280, signals.side("right", 0.8)[1]),
            signals.r(0.8)], "msg", "reads", (304, 968), (matrix, signals))
    d.edge([matrix.r(), (result.left, matrix.cy)], "msg", "«create»",
           ((matrix.right + result.left) / 2, matrix.cy - 11), (matrix, result))
    d.edge([result.r(), (contrib.left, result.cy)], "comp", ends=(result, contrib))
    d.label((result.right + contrib.left) / 2 + 6, result.cy - 11, "0..*", 12, check=False)

    # -------------------------------------------------------------- isolation
    d.frame(1210, 318, 370, 814, "Isolated scan", "#faf5ff", "#6d28d9")
    iso = d.klass(1226, 350, "_IsolatedScan", [
        "+ pool : List[_Worker]", "+ pending : List[str]", "+ timeout : float",
        "+ memory_mb : int", "+ on_result : Callable"], [
        "+ run()", "- _step(i) : bool", "- _dispatch(w)", "- _receive(w)",
        "- _progress(w, kind, payload)", "- _finish(path, result)",
        "- _fail(path, reason, evidence)", "- _replace(i) : bool"], w=338,
        stereotype="engine/workers.py", fill=ISO)
    worker = d.klass(1226, 702, "_Worker", [
        "+ proc : Process", "+ parent : Connection", "+ temp_dir : str", "+ path : Optional[str]",
        "+ provisional : Optional[Dict]", "+ settled : bool", "+ evidence : Evidence"], [
        "+ note_group()", "+ kill()", "+ remove_temp()"], w=338, stereotype="engine/workers.py",
        fill=ISO)
    d.edge([iso.b(), worker.t()], "comp", "pool  1..*", (iso.cx + 48, (iso.bottom + worker.top) / 2 + 6),
           (iso, worker))
    evidence = d.klass(1226, 1004, "Evidence", [], [
        "+ add_container(report)", "+ add(report)", "+ findings()", "+ score(scanner, path)"],
        w=164, fill=ISO)
    desc = d.klass(1400, 1004, "Descendants", [], ["+ collect(force)", "+ ready()", "+ stop(sig)"],
                   w=164, stereotype="macOS only", fill=ISO)
    d.edge([(evidence.cx, worker.bottom), evidence.t()], "comp", "1",
           (evidence.cx + 14, (worker.bottom + evidence.top) / 2 + 6), (worker, evidence))
    d.edge([(desc.cx, worker.bottom), desc.t()], "comp", "0..1",
           (desc.cx + 22, (worker.bottom + desc.top) / 2 + 6), (worker, desc))

    y_create = scanner.side("right", 0.2)[1]
    gap_x = (scanner.right + iso.left) / 2
    d.edge([(scanner.right, y_create), (iso.left, y_create)], "msg", ["«create» in", "scan_isolated()"],
           (gap_x, y_create - 19), (scanner, iso))
    y_ref = scanner.side("right", 0.42)[1]
    d.edge([(iso.left, y_ref), (scanner.right, y_ref)], "assoc", ["scanner: the", "caller's instance"],
           (gap_x, y_ref + 20), (iso, scanner))
    y_own = worker.side("left", 0.1)[1]
    d.edge([(worker.left, y_own), (1066, y_own), (1066, scanner.bottom)], "msg",
           ["its process builds", "its own scanner"], (gap_x + 2, y_own + 20), (worker, scanner))

    # ---------------------------------------------------- owned parts (below)
    d.frame(20, 1192, 724, 196, "Detection engines: one attribute each, created in "
                                "RansomwareScanner.__init__()", "#f0f9ff", "#0369a1",
            sub="QRScanner, MLClassifier and ScriptEmulator are optional (0..1).")
    engines = ["YaraEngine", "MacroAnalyzer", "FuzzyHasher", "FileIntegrityAnalyzer",
               "ElfAnalyzer", "PeAnalyzer", "ScriptAnalyzer", "PromptGuard",
               "RelationshipScanner", "QRScanner", "ContainerExtractor", "MailAnalyzer",
               "WebContentAnalyzer", "EmbeddedContentAnalyzer", "MLClassifier", "ScriptEmulator"]
    for i, name in enumerate(engines):
        row, col = divmod(i, 4)
        d.name_box(30 + col * 177, 1246 + row * 34, name, w=172, h=26, fill=ENGINE, size=12, pad=5)

    d.frame(760, 1192, 490, 408, "External services: llm_backend 1, sandbox 0..1, intel 0..1",
            "#fff1f2", "#be123c")
    backend = d.klass(776, 1232, "LLMBackend", [], [
        "+ analyze(combined_content, timeout) : Dict", "+ available : bool"],
        stereotype="«abstract» detectors/llm_backends.py", fill=EXT, abstract=True)
    kinds = [d.name_box(1110, 1232 + i * pitch, n, w=126, h=24, fill=EXT, size=12)
             for i, n in enumerate(["NullBackend", "OllamaBackend", "OpenAIBackend",
                                    "IntelLLMBackend"])]
    tree(d, (backend.right, backend.cy), 1092, kinds, name="backends inherit")
    d.klass(776, 1366, "CapeClient", [], [
        "+ analyze(path, deadline, progress)", "+ submit(path) : SandboxResult",
        "+ poll(task_id) : SandboxResult"], stereotype="core/sandbox.py", fill=EXT)
    intel_box = d.klass(776, 1500, "IntelSandbox", [], ["+ analyze(path, deadline, progress)"],
                        stereotype="core/intel_client.py", fill=EXT)
    client = d.klass(1050, 1428, "IntelClient", [], [
        "+ call(method, url, payload)", "+ vt_lookup(sha256) : Dict", "+ vt_upload(path) : Dict",
        "+ alert_email(fields)"], w=186, stereotype="core/intel_client.py", fill=EXT)
    d.edge([kinds[3].b(), (kinds[3].cx, client.top)], "assoc", "client",
           (kinds[3].cx + 24, (kinds[3].bottom + client.top) / 2), (kinds[3], client))
    d.edge([intel_box.r(), (client.left, intel_box.cy)], "assoc", ends=(intel_box, client))
    d.label((intel_box.right + client.left) / 2, intel_box.cy - 11, "client", 12, check=False)

    d.frame(1270, 1192, 310, 408, "Protection and cache", "#f8fafc", "#475569")
    d.klass(1284, 1232, "QuarantineVault", [], [
        "+ quarantine(file_path, reason) : Dict", "+ restore(item_id, destination)",
        "+ list() : List[Dict]"], w=282, stereotype="core/quarantine.py: quarantine_vault 0..1",
        fill=PROT)
    d.klass(1284, 1362, "CanaryManager", [], [
        "+ deploy(directories)", "+ verify() : CanaryReport", "+ paths() : Set[str]"], w=282,
        stereotype="core/canary.py: canaries 1", fill=PROT)
    d.klass(1284, 1492, "ResultCache", [], [
        "+ get(sha256, layer)", "+ put(sha256, layer, value)"], w=282,
        stereotype="core/cache.py: cache 0..1", fill=PROT)

    # three compositions from the facade to the frames of owned parts
    x1, x2, x3 = (scanner.side("bottom", t)[0] for t in (0.5, 0.6, 0.7))
    d.edge([(x1, scanner.bottom), (x1, 800), (1150, 800), (1150, 1172), (600, 1172), (600, 1192)],
           "comp", ends=(scanner,), name="owns the engines")
    d.edge([(x2, scanner.bottom), (x2, 784), (1170, 784), (1170, 1192)], "comp", ends=(scanner,),
           name="owns the service clients")
    d.edge([(x3, scanner.bottom), (x3, 768), (1190, 768), (1190, 1160), (1425, 1160), (1425, 1192)],
           "comp", ends=(scanner,), name="owns protection and cache")
    d.label(860, 1172, "one composition per class in the frame", 12, fill=MUTED, check=False)

    # ------------------------------------------------- callers (bottom left)
    d.frame(20, 1404, 724, 162, "Callers: the classes that start a scan", "#fefce8", "#a16207",
            sub="_ScanService owns a scanner; FolderMonitor and MailboxScanner keep a reference; "
                "ScanController receives one per call.")
    callers = [("ScanController", "aegis_gui/state.py", "+ start(scanner, mode)"),
               ("_ScanService", "api/server.py", "+ scan(path, display)"),
               ("FolderMonitor", "core/folder_watch.py", "+ scan_batch(paths)"),
               ("MailboxScanner", "core/mailbox.py", "+ run() : MailboxRun")]
    for i, (name, module, method) in enumerate(callers):
        d.klass(30 + i * 177, 1458, name, [], [method], w=172, stereotype=module, fill="#fef9c3")

    # ------------------------------------------------------------------- key
    kx, ky = 20, 880
    d.rect(kx, ky, 250, 286, "#ffffff", "#94a3b8", 1, 6, "frame")
    d.text(kx + 12, ky + 22, "Key", 13, True)
    d.edge([(kx + 12, ky + 44), (kx + 58, ky + 44)], "gen", check=False)
    d.text(kx + 68, ky + 48, "inherits from", 12)
    d.edge([(kx + 12, ky + 72), (kx + 58, ky + 72)], "comp", check=False)
    d.text(kx + 68, ky + 70, "composition: the owner", 12)
    d.text(kx + 68, ky + 85, "creates and keeps the part", 12)
    d.edge([(kx + 12, ky + 110), (kx + 58, ky + 110)], "assoc", check=False)
    d.text(kx + 68, ky + 108, "association: keeps a", 12)
    d.text(kx + 68, ky + 123, "reference it does not own", 12)
    d.edge([(kx + 12, ky + 148), (kx + 58, ky + 148)], "msg", check=False)
    d.text(kx + 68, ky + 146, "dependency: uses, calls", 12)
    d.text(kx + 68, ky + 161, "or creates", 12)
    d.rect(kx + 14, ky + 178, 42, 18, HEAVY, INK, 1.2, 3, "frame")
    d.text(kx + 68, ky + 192, "layer with heavy = True", 12)
    d.text(kx + 12, ky + 218, "+ public name", 12)
    d.text(kx + 112, ky + 218, "- name starts with _", 12)
    d.text(kx + 12, ky + 242, "A diamond line that ends at a", 12, fill=MUTED)
    d.text(kx + 12, ky + 257, "frame stands for one composition", 12, fill=MUTED)
    d.text(kx + 12, ky + 272, "to each class in that frame.", 12, fill=MUTED)
    d.h = 1620
    return d


NOTES: List[str] = [
    "RansomwareScanner inherits from the five mixins in this order: StagedPipelineMixin, "
    "ProtectionMixin, ReportMixin, ExternalLookupsMixin, TextExtractionMixin (engine/scanner.py).",
    "A layer never calls another layer. Layer.run(scanner, ctx) reaches its engine through the "
    "scanner (YaraLayer calls scanner.yara_engine) and writes its result and its typed signal "
    "into the ScanContext (engine/layers.py).",
    "The callers do not scan by themselves: ScanController, FolderMonitor and MailboxScanner "
    "call scan_one() or _scan_targets() on a RansomwareScanner, and _ScanService calls "
    "scan_isolated() with the scanner it owns.",
    "default_pipeline() builds 22 layer objects from 19 Layer subclasses: ContainerLayer is "
    "created four times, once per handler (mail, archive, web, embedded).",
    "Layer and ContainerHandler are plain base classes whose methods raise NotImplementedError; "
    "only LLMBackend is declared abstract (ABC).",
    "The six *_listener attributes are callbacks that _worker_main() sets inside a worker "
    "process; they send the pipe messages shown in the activity diagram.",
    "Each _Worker starts a child process that builds its own RansomwareScanner; _IsolatedScan "
    "keeps the caller's scanner only to build failure results and to call on_result().",
    "The scanner's sandbox attribute is a CapeClient, or an IntelSandbox when the intel service "
    "is used (Docker over a Unix socket, or Kubernetes option E over TLS: TlsEndpoint); its "
    "llm_backend is then an IntelLLMBackend.",
]
