#!/usr/bin/env python3
"""Build the six Aegis Sentinel architecture diagrams and the page that shows them.

    python3 build_diagrams.py            write the six .svg files here and
                                         ../ARCHITECTURE_UML_DIAGRAMS.html
    python3 build_diagrams.py --check    also write ../ARCHITECTURE_UML_DIAGRAMS.check.html,
                                         a copy that measures every label in the browser and
                                         lists the ones wider than their box (open it, read
                                         the report at the top, then delete it; never commit it)

Sources: d1_class_diagram.py, d2_use_case_diagram.py, d3_activity_diagram.py,
d4_system_flowchart.py, d5_deployment_trust_boundaries.py and
d6_kubernetes_trust_boundaries.py. umlkit.py is the
drawing toolkit. Standard library only.

The build stops with exit code 1 when a diagram has a layout problem (a label
wider than its box, overlapping nodes, a connector through an unrelated node).
"""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

import umlkit

HERE = Path(__file__).resolve().parent
PAGE = HERE.parent / "ARCHITECTURE_UML_DIAGRAMS.html"

META = {
    "branch": "review/production-hardening",
    "commit": "b6966f8",
    "commit_full": "b6966f83a0b9552d0e6d9f431f842175b2f3cf7c",
    "code_commit": "b6966f8",
    "code_commit_full": "b6966f83a0b9552d0e6d9f431f842175b2f3cf7c",
    "built": "2026-11-17",
    # Diagram 6 draws deploy/kubernetes/, which is newer than the code baseline above.
    "k8s_commit": "00c0639",
    "k8s_built": "2026-11-18",
}

DIAGRAMS = [  # module, svg file, anchor, page heading, how to read it
    ("d1_class_diagram", "1-class-diagram.svg", "class-diagram",
     "1. Class diagram: what makes up the scanner?",
     "RansomwareScanner is the facade every entry point uses. It inherits its behaviour from "
     "five mixins, owns the 22-layer pipeline, the scoring matrix and the detection engines, "
     "and hands files to _IsolatedScan, which runs them in worker processes. Hollow triangles "
     "are inheritance. Filled diamonds are composition: the owner creates the part and keeps "
     "it. Solid open arrows are references that are not owned, and dashed arrows are "
     "dependencies."),
    ("d2_use_case_diagram", "2-use-case-diagram.svg", "use-case-diagram",
     "2. Use-case diagram: who uses the system, and for what?",
     "Three primary actors reach Aegis Sentinel: a desktop user, an administrator and an API "
     "client. Seven external systems take part when they are configured. The GUI, the CLI and "
     "the REST API are interfaces, so they appear as a tag on each use case that offers them, "
     "not as actors."),
    ("d3_activity_diagram", "3-activity-diagram.svg", "activity-diagram",
     "3. Activity diagram: how does one file get a verdict?",
     "One file in an isolated scan, which is the default. The entry point submits it, the "
     "parent process hands it to a worker over a pipe and watches the clock, the worker runs "
     "the pipeline and reports back, and the parent decides what the wait produced. Solid "
     "arrows are control flow. Dashed arrows are messages on the pipe or calls to a service."),
    ("d4_system_flowchart", "4-system-flowchart.svg", "system-flowchart",
     "4. Flowchart: how does the whole system fit together?",
     "Six intake channels feed one scan engine. Every file goes through the same detection "
     "stages in an isolated worker, is scored, and comes back to the parent, which sends the "
     "result to the destinations that channel uses. The coloured chips on a destination name "
     "the channels that reach it."),
    ("d5_deployment_trust_boundaries", "5-deployment-trust-boundaries.svg", "deployment",
     "5. Deployment: where does each part run, and what separates it?",
     "The two execution modes side by side: the desktop app and CLI on one computer, and the "
     "Docker deployment with its four containers. A dashed frame is process separation "
     "(time and memory limits, crash containment) inside one user: it is not a security "
     "boundary. A thick red frame is a container, an OS-enforced boundary. The chips on each "
     "external service say which mode reaches it; in Docker only the intel container does."),
    ("d6_kubernetes_trust_boundaries", "6-kubernetes-trust-boundaries.svg", "kubernetes",
     "6. Kubernetes (optional): what separates the parts in a cluster?",
     "The optional Kubernetes deployment in deploy/kubernetes, drawn on its own so the Docker "
     "view above stays as it is. A purple frame is a Pod: one network namespace, which is "
     "what a NetworkPolicy controls, so the proxy and analysis containers share one "
     "interface. A thick red frame is a container. There is no intel service on Kubernetes "
     "yet, so no external service is reachable or configured. These manifests have not been "
     "run on a cluster."),
]

CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { margin: 0; background: #eef2f7; color: #0f172a;
       font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Arial, sans-serif; }
a { color: #1d4ed8; }
a:focus-visible, button:focus-visible, summary:focus-visible { outline: 3px solid #f59e0b; outline-offset: 2px; }
.wrap { max-width: 1720px; margin: 0 auto; padding: 0 12px; }
header.page { padding: 26px 0 4px; }
h1 { margin: 0 0 8px; font-size: 30px; line-height: 1.2; letter-spacing: -0.01em; }
.lead { margin: 0 0 16px; max-width: 78ch; font-size: 17px; color: #1e293b; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 10px;
         margin: 0 0 16px; padding: 0; list-style: none; }
.facts li { background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px 14px; }
.facts b { display: block; font-size: 13px; text-transform: uppercase; letter-spacing: .04em;
           color: #334155; margin-bottom: 2px; }
code { font: 0.92em ui-monospace, "SF Mono", Menlo, Consolas, monospace; background: #e2e8f0;
       padding: 1px 5px; border-radius: 4px; }
nav.toc { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 8px; }
nav.toc a { background: #0f172a; color: #fff; text-decoration: none; padding: 8px 14px;
            border-radius: 999px; font-size: 15px; font-weight: 600; }
nav.toc a.alt { background: #fff; color: #0f172a; border: 1px solid #94a3b8; }
section.diagram { margin: 26px 0 0; }
section.diagram h2 { margin: 0 0 6px; font-size: 24px; line-height: 1.25; }
section.diagram > p { margin: 0 0 12px; max-width: 96ch; color: #1e293b; }
.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 0 0 8px; }
.toolbar button { font: inherit; font-size: 14px; font-weight: 600; padding: 6px 12px; cursor: pointer;
                  background: #fff; color: #0f172a; border: 1px solid #64748b; border-radius: 6px; }
.toolbar button:hover { background: #e2e8f0; }
.toolbar button[aria-pressed="true"] { background: #0f172a; color: #fff; border-color: #0f172a; }
.toolbar .zoom { min-width: 4.5ch; text-align: right; font-variant-numeric: tabular-nums;
                 font-size: 14px; color: #334155; }
.toolbar .hint { font-size: 14px; color: #334155; }
.canvas { background: #fff; border: 1px solid #94a3b8; border-radius: 8px; overflow: auto;
          padding: 0; max-width: 100%; }
.canvas svg { display: block; max-width: none; }
details { margin: 10px 0 0; background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; }
summary { cursor: pointer; padding: 10px 14px; font-weight: 600; }
details .body { padding: 0 14px 12px; }
details ul { margin: 0; padding-left: 20px; }
details li { margin: 0 0 6px; max-width: 110ch; }
pre { margin: 0; padding: 12px 14px; overflow: auto; max-height: 460px; background: #0f172a;
      color: #e2e8f0; border-radius: 6px; font: 13px/1.5 ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
.files { margin: 10px 0 0; font-size: 15px; color: #1e293b; }
section.ref { margin: 30px 0 0; background: #fff; border: 1px solid #cbd5e1; border-radius: 8px;
              padding: 16px 18px; }
section.ref h2 { margin: 0 0 8px; font-size: 21px; }
section.ref p, section.ref li { max-width: 100ch; }
section.ref ul { margin: 6px 0 0; padding-left: 20px; }
footer { margin: 22px 0 36px; font-size: 14px; color: #334155; }
#check-report { margin: 12px 0; padding: 12px 14px; background: #fff7ed; border: 2px solid #c2410c;
                border-radius: 8px; white-space: pre-wrap; font: 14px/1.5 ui-monospace, Menlo, monospace; }
@media print {
  body { background: #fff; }
  nav.toc, .toolbar, details { display: none; }
  .canvas { overflow: visible; border: 0; }
  .canvas svg { width: 100% !important; height: auto !important; }
  section.diagram { break-inside: avoid; }
}
"""

JS = """
(function () {
  var MIN_FIT = 0.82;                       // below this, fitting would make labels too small
  document.querySelectorAll('section.diagram').forEach(function (section) {
    var canvas = section.querySelector('.canvas');
    var svg = canvas.querySelector('svg');
    var natural = svg.viewBox.baseVal.width, naturalH = svg.viewBox.baseVal.height;
    var fitButton = section.querySelector('[data-zoom="fit"]');
    var fullButton = section.querySelector('[data-zoom="full"]');
    var readout = section.querySelector('.zoom');
    var mode = 'auto', scale = 1;
    function fitScale() { return Math.min(1, (canvas.clientWidth - 2) / natural); }
    function apply() {
      var s = scale;
      if (mode === 'auto') { s = fitScale() >= MIN_FIT ? fitScale() : 1; }
      if (mode === 'fit') { s = fitScale(); }
      scale = s;
      svg.style.width = Math.round(natural * s) + 'px';
      svg.style.height = Math.round(naturalH * s) + 'px';
      readout.textContent = Math.round(s * 100) + '%';
      fitButton.setAttribute('aria-pressed', String(Math.abs(s - fitScale()) < 0.005 && s < 0.999));
      fullButton.setAttribute('aria-pressed', String(Math.abs(s - 1) < 0.005));
    }
    section.querySelectorAll('[data-zoom]').forEach(function (button) {
      button.addEventListener('click', function () {
        var kind = button.getAttribute('data-zoom');
        if (kind === 'fit') { mode = 'fit'; }
        else if (kind === 'full') { mode = 'manual'; scale = 1; }
        else { mode = 'manual'; scale = Math.max(0.4, Math.min(3, scale * (kind === 'in' ? 1.2 : 1 / 1.2))); }
        apply();
      });
    });
    window.addEventListener('resize', function () { if (mode !== 'manual') { apply(); } });
    apply();
  });
})();
"""

CHECK_JS = """
window.addEventListener('load', function () {
  var worst = 0, wide = [], total = 0;
  document.querySelectorAll('svg text[data-w]').forEach(function (t) {
    var real = t.getComputedTextLength();
    total += 1;
    worst = Math.max(worst, real / parseFloat(t.getAttribute('data-w')));
    var limit = t.getAttribute('data-maxw');
    if (limit !== null && real > parseFloat(limit) + 0.5) {
      wide.push(t.closest('svg').id + ': "' + t.textContent + '" is ' + real.toFixed(1) +
                ' px, its box allows ' + limit + ' px');
    }
  });
  var small = [];
  document.querySelectorAll('svg text').forEach(function (t) {
    if (parseFloat(t.getAttribute('font-size')) < 12) { small.push(t.textContent); }
  });
  var report = document.getElementById('check-report');
  report.textContent = 'LABEL CHECK: ' + total + ' labels measured in this browser.\\n' +
    'Widest label relative to the predicted width: ' + (worst * 100).toFixed(1) + '% (100% or less is safe).\\n' +
    'Labels wider than their box: ' + wide.length + (wide.length ? '\\n  ' + wide.join('\\n  ') : '') + '\\n' +
    'Labels smaller than 12 px: ' + small.length + (small.length ? '\\n  ' + small.join('\\n  ') : '');
});
"""


def build_diagrams():
    out = []
    failed = False
    for module_name, svg_name, anchor, heading, how in DIAGRAMS:
        module = __import__(module_name)
        diagram = module.build(META)
        problems = diagram.check()
        for problem in problems:
            failed = True
            print(f"{module_name}: {problem}", file=sys.stderr)
        out.append((module, diagram, svg_name, anchor, heading, how))
    return out, failed


def graph_links():
    """Links to the Graphify page kept next to this page (graphify-code-graph.html),
    or to a full Graphify output folder when there is one. The raw graph data
    (about 18 MB) is not kept in the repository."""
    if (PAGE.parent / "graphify-code-graph.html").is_file():
        return ['<p><a href="graphify-code-graph.html">graphify-code-graph.html</a>: the '
                "interactive network, one node per community, named after its main symbol "
                "and that symbol's own file. It loads the vis-network library from unpkg, so "
                "it needs an internet connection.</p>"]
    if not (PAGE.parent / "graphify-out" / "graph.html").is_file():
        return ["<p>The graph is generated data and is not part of this folder. Build it again "
                "with Graphify in code-only mode from a <code>git archive</code> of the commit.</p>"]
    return ["<ul>",
            '<li><a href="graphify-out/graph.html">graphify-out/graph.html</a>: the interactive '
            "network, grouped by community</li>",
            '<li><a href="graphify-out/GRAPH_TREE.html">graphify-out/GRAPH_TREE.html</a>: the '
            "file and symbol tree</li>",
            '<li><a href="graphify-out/GRAPH_REPORT.md">graphify-out/GRAPH_REPORT.md</a>: hubs, '
            "communities and edge confidence</li>",
            "</ul>"]


def page(items, check: bool) -> str:
    m = META
    parts = [
        "<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Aegis Sentinel architecture diagrams</title>",
        f"<style>{CSS}</style>", "</head>", "<body>", '<div class="wrap">',
        '<header class="page">',
        "<h1>Aegis Sentinel architecture in six diagrams</h1>",
        '<p class="lead">What makes up the scanner, who uses it, how one file gets a verdict, and '
        "how the whole system fits together and where each part runs. Every class, method and "
        "message name is the one in "
        "the code, read at the commit below.</p>",
        '<ul class="facts">',
        f"<li><b>Branch</b><code>{escape(m['branch'])}</code></li>",
        f"<li><b>Baseline commit</b><code>{m['commit']}</code> "
        f"<span title=\"{m['commit_full']}\">(documentation checkpoint)</span></li>",
        f"<li><b>Code last changed in</b><code>{m['code_commit']}</code> "
        "Later commits change documentation only.</li>",
        f"<li><b>Drawn</b>{m['built']}, from the source files and the Graphify graph</li>",
        "</ul>",
        '<nav class="toc" aria-label="Diagrams">',
    ]
    for _, _, _, anchor, heading, _ in items:
        parts.append(f'<a href="#{anchor}">{escape(heading)}</a>')
    parts += ['<a class="alt" href="#graphify">Graphify network (reference)</a>',
              '<a class="alt" href="#editing">Editing the diagrams</a>', "</nav>", "</header>"]
    if check:
        parts.append('<div id="check-report">Measuring labels...</div>')
    for module, diagram, svg_name, anchor, heading, how in items:
        source_name = Path(module.__file__).name
        source_text = Path(module.__file__).read_text(encoding="utf-8")
        parts += [
            f'<section class="diagram" id="{anchor}">',
            f"<h2>{escape(heading)}</h2>",
            f"<p>{escape(how)}</p>",
            '<div class="toolbar">',
            '<button type="button" data-zoom="fit" aria-pressed="false">Fit width</button>',
            '<button type="button" data-zoom="full" aria-pressed="false">Actual size</button>',
            '<button type="button" data-zoom="out" aria-label="Zoom out">&minus;</button>',
            '<button type="button" data-zoom="in" aria-label="Zoom in">+</button>',
            '<span class="zoom" aria-live="polite">100%</span>',
            f'<span class="hint">Scroll inside the frame when it is zoomed in. '
            f'<a href="uml-diagram-sources/{svg_name}">Open the SVG on its own</a></span>',
            "</div>",
            f'<div class="canvas" role="group" aria-label="{escape(heading)}" tabindex="0">',
            diagram.svg(standalone=False),
            "</div>",
            "<details open>", "<summary>Checked in the code</summary>", '<div class="body"><ul>',
        ]
        parts += [f"<li>{escape(note)}</li>" for note in module.NOTES]
        parts += [
            "</ul></div>", "</details>",
            f'<p class="files">Editable sources: '
            f'<a href="uml-diagram-sources/{source_name}"><code>uml-diagram-sources/{source_name}</code></a> '
            f'(the definition) and '
            f'<a href="uml-diagram-sources/{svg_name}"><code>uml-diagram-sources/{svg_name}</code></a> '
            f"(the drawing, with its text kept as text).</p>",
            "<details>", f"<summary>Show the source of this diagram ({source_name})</summary>",
            f'<div class="body"><pre><code>{escape(source_text)}</code></pre></div>', "</details>",
            "</section>",
        ]
    parts += [
        '<section class="ref" id="graphify">',
        "<h2>Graphify network (reference)</h2>",
        "<p>The diagrams started from the Graphify code graph of the repository: 6,366 nodes, "
        "15,577 edges and 335 communities, built from the tracked source, tests and "
        "configuration with no LLM. Before drawing, the graph was built again from a "
        f"<code>git archive</code> of <code>{m['commit']}</code> and compared with the stored "
        "one: the same nodes, the same edges and the same communities.</p>",
        *graph_links(),
        "<p>The graph supplied the class list, the 88 inheritance edges (69 of them between "
        "application classes, all read from the code) and the hubs "
        "(RansomwareScanner, ContainerExtractor, ScoringMatrix, ScanContext, Signals). It is a "
        "static graph, so it cannot see what happens at run time. The pipe messages between "
        "worker and parent, the listener callbacks, the thread pool, the time-out outcomes and "
        "the network calls were read in the source files and are drawn from there.</p>",
        "</section>",
        '<section class="ref" id="editing">',
        "<h2>Editing the diagrams</h2>",
        "<ul>",
        "<li>Each diagram is defined in one Python file in <code>uml-diagram-sources/</code>: "
        "texts, positions and connectors. Change it and run <code>python3 build_diagrams.py</code> in "
        "that folder. The six SVG files and this page are written again. Python 3.9 or later; "
        "nothing to install.</li>",
        "<li>The build stops when a label no longer fits its box, when two nodes overlap or "
        "when a connector runs through a node it is not attached to.</li>",
        "<li>The SVG files are plain SVG with real text, so they also open in Inkscape, Figma "
        "or draw.io for a one-off change. A later build overwrites such changes.</li>",
        "</ul>",
        "</section>",
        f"<footer>Aegis Sentinel, branch {escape(m['branch'])}, commit {m['commit_full']}. "
        "This page is self-contained: it loads nothing from the network.</footer>",
        "</div>",
        f"<script>{JS}</script>",
    ]
    if check:
        parts.append(f"<script>{CHECK_JS}</script>")
    parts += ["</body>", "</html>"]
    return "\n".join(parts) + "\n"


def main() -> int:
    check = "--check" in sys.argv[1:]
    items, failed = build_diagrams()
    if failed:
        print("Not written: fix the layout problems above first.", file=sys.stderr)
        return 1
    for _, diagram, svg_name, _, _, _ in items:
        (HERE / svg_name).write_text(diagram.svg(), encoding="utf-8")
        print(f"wrote {svg_name} ({int(diagram.w)} x {int(diagram.h)})")
    PAGE.write_text(page(items, check=False), encoding="utf-8")
    print(f"wrote {PAGE}")
    if check:
        umlkit.Diagram.DEBUG = True
        marked, _ = build_diagrams()
        target = PAGE.with_name("ARCHITECTURE_UML_DIAGRAMS.check.html")
        target.write_text(page(marked, check=True), encoding="utf-8")
        print(f"wrote {target} (open it in a browser, then delete it)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
