"""Diagram 8 - layers, the shared ScanContext, and how evidence becomes a result.

Read from engine/layers.py (ScanContext, Layer, default_pipeline, ORDER_RULES),
engine/staging.py (scan_file, _run_layer, _run_heavy, _run_together,
_merge_layer, _assemble), detectors/signals.py (Signals), detectors/scoring.py
(ScoringMatrix, ScoreResult, Contribution), engine/completeness.py (assess) and
engine/provenance.py (file_provenance).

Layers never call each other. Each writes its report entry to
ctx.result["scan_results"] and its typed signal to ctx.signals; the coordinator
(scan_file) runs them, and scoring runs once, in _assemble.
"""

from __future__ import annotations

from typing import List

from umlkit import MUTED, Diagram

TITLE = "Layers, the shared context, and how evidence becomes a result"

FAST = "#eff6ff"
HEAVY = "#fef3c7"
CTX = "#dcfce7"
OUT = "#f5f3ff"


def build(meta: dict) -> object:
    d = Diagram("d8", 1600, 770, TITLE,
                f"engine/layers.py, engine/staging.py, detectors/scoring.py. Code at commit "
                f"{meta['code_commit']}.",
                "Data-flow diagram: the coordinator runs each layer on one ScanContext; layers add "
                "report entries and typed signals; heavy layers run on copies that are merged "
                "back; _assemble scores the signals and assesses completeness.")
    d.title_block()

    # ------------------------------------------------ the pipeline (left)
    d.frame(24, 92, 420, 656, "scan_file(): the coordinator", sub="runs the 22 layers in order")
    groups = [
        ("1  Identity", ["hashes  ->  md5, sha256", "allowlist  ->  flag allowlisted",
                         "fuzzy  ->  FuzzySignal", "local-db  ->  flag local_db_hit"]),
        ("2  Structure", ["macro, yara, integrity,", "elf, pe, script  ->  one signal each"]),
        ("3  Mail container", ["mail: opens the message, scans each", "attachment, keeps the body as text"]),
        ("4  Content", ["prompt-guard: extracts text + strings once", "relationships, qr"]),
        ("5  Containers", ["archive, web, embedded: members go back", "through scan_file at depth + 1"]),
    ]
    y = 150.0
    fast_boxes = []
    for title, rows in groups:
        b = d.titled(44, y, 380, title, rows, fill=FAST, size=12.5, name=title)
        fast_boxes.append(b)
        y = b.bottom + 14
    heavy = d.titled(44, y + 10, 380, "6  Heavy layers (heavy = True)",
                     ["emulation, ml, llm, virustotal: skipped when allowlisted",
                      "or already 100/100; else concurrently, each on a copy",
                      "of the context, merged back in pipeline order",
                      "sandbox: last (alone in a worker), gate risk >= 25"],
                     fill=HEAVY, size=12.5, name="heavy")
    for a, b in zip(fast_boxes, fast_boxes[1:] + [heavy]):
        d.edge([a.b(0.5), b.t(0.5)], "flow", ends=(a, b))

    # ------------------------------------------------ the context (middle)
    ctx = d.klass(560, 150, "ScanContext", [
        "path, display (\"mail.eml!/a.zip!/x.js\")",
        "depth (0 top level, +1 per container)",
        "is_archive, is_mail, is_web, embedded_kind",
        "data(): whole file once, up to 64 MiB",
        "hashes, text, strings",
        "signals: Signals",
        "result[\"scan_results\"]: report entries",
        "layer_log, member_reasons, member_shared",
    ], [], w=400, fill=CTX)
    sig = d.klass(560, ctx.bottom + 60, "Signals", [
        "19 typed signals (FuzzySignal ... EmulationSignal)",
        "flags: allowlisted, local_db_hit, scan_failed",
        "container signals carry .worst (WorstMember)",
        "extra: signals of third-party layers",
    ], [], w=400, fill=CTX)
    d.edge([(ctx.cx, ctx.bottom), (ctx.cx, sig.top)], "comp", ends=(ctx, sig))
    bus = 500
    for b in fast_boxes + [heavy]:
        d.edge([b.r(0.5), (bus, b.cy)], "line", color="#64748b", sw=1.3, check=False)
    d.edge([(bus, fast_boxes[0].cy), (bus, heavy.cy)], "line", color="#64748b", sw=1.3,
           check=False)
    d.edge([(bus, ctx.top + 60), (ctx.left, ctx.top + 60)], "msg", ends=(ctx,), check=False)
    d.edge([(bus, sig.cy), (sig.left, sig.cy)], "msg", ends=(sig,), check=False)
    d.label(bus, heavy.cy + 46, ["each layer writes", "an entry + a signal"], 12,
            fill=MUTED, check=False)

    d.note(560, sig.bottom + 30, 400, [
        "Each layer does two things: its full result goes to scan_results[key] (what reports "
        "show) and its typed signal to ctx.signals (what scoring reads).",
        "A layer that raises is recorded in layer_errors and in layer_log; the scan goes on.",
        "Order rules (ORDER_RULES): hashes before allowlist, local-db, llm, virustotal, sandbox; "
        "mail before prompt-guard; prompt-guard before llm; sandbox last."], size=12)

    # ------------------------------------------------ _assemble (right)
    d.frame(1040, 92, 536, 656, "_assemble(ctx): once, at the end", sub="no logging, no side effects")
    sc = d.titled(1060, 160, 496, "ScoringMatrix.score(signals)",
                  ["23 scorer functions turn signals into Contribution(indicator, category, "
                   "points, detail); per-category caps; total clamped to 100; semantic or "
                   "statistical evidence alone stays <= 49; allowlist sets 0 unless the hash "
                   "is in the malware database."], fill=OUT, size=12.5, name="score")
    sr = d.titled(1060, sc.bottom + 40, 496, "ScoreResult",
                  ["risk_score 0-100, verdict band, severity_score (legacy 0-10), "
                   "is_malicious, contributions, category_totals, registry_version"],
                  fill=OUT, size=12.5, name="ScoreResult")
    d.edge([sc.b(0.5), sr.t(0.5)], "flow", ends=(sc, sr))
    asx = d.titled(1060, sr.bottom + 40, 496, "assess(scanner, ctx)",
                   ["Reads scan_results, layer states and member reasons: scan_status (complete, "
                    "unsupported, partial, locked, failed) and up to 100 incomplete_reasons. "
                    "Independent of the score."],
                   fill=OUT, size=12.5, name="assess")
    pv = d.titled(1060, asx.bottom + 40, 496, "file_provenance(scanner, ctx)",
                  ["layers run, not applicable, unavailable, failed, skipped; external "
                   "services configured; what was sent outside (shared); isolation"],
                  fill=OUT, size=12.5, name="provenance")
    res = d.titled(1060, pv.bottom + 40, 496, "The result (api/scan_result.schema.json)",
                   ["verdict, risk_score, score_breakdown, scan_status, incomplete_reasons, "
                    "verdict_label (\"Clean (partial scan)\"), provenance, scan_results"],
                   fill="#e2e8f0", size=12.5, name="result")
    for a, b in ((sr, asx), (asx, pv), (pv, res)):
        d.edge([a.b(0.5), b.t(0.5)], "flow", ends=(a, b))
    d.edge([(sig.right, sig.cy), (1010, sig.cy), (1010, sc.cy), sc.l()], "msg",
           "signals", (1010, (sig.cy + sc.cy) / 2), (sig, sc))
    return d


NOTES: List[str] = [
    "Heavy layers: _run_heavy skips the group when the file is allowlisted (and not in the "
    "hash database) or already scores 100; otherwise _run_together runs them on a thread pool "
    "of four, each on a copy of the context, and _merge_layer copies back only what changed.",
    "In an isolated worker with a sandbox configured, the sandbox runs after the other heavy "
    "layers, on its own, so its provisional result holds their findings.",
]
