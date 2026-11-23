#!/usr/bin/env python3
"""Build AEGIS_SENTINEL_TECHNICAL_OVERVIEW.pdf from the Markdown in src/.

    .venv/bin/python docs/security-overview/build_overview.py
    .venv/bin/python docs/security-overview/build_overview.py --check-only

Steps (standard tools only; nothing is downloaded and nothing leaves the host):

 1. facts.py recomputes the numbers the text quotes from the code and compares
    them with src/facts.json. A difference stops the build (--allow-drift to
    override for a draft).
 2. The diagrams are rebuilt from their Python definitions
    (docs/architecture/uml-diagram-sources/build_diagrams.py), which stops on a
    layout problem.
 3. src/*.md (in file-name order) is rendered to one HTML file with
    markdown-it-py. Diagrams are inlined as SVG, so they stay vector and their
    text stays searchable.
 4. Google Chrome (headless) prints the HTML twice. The first print records on
    which page each chapter and section starts; the second fills those page
    numbers into the table of contents. Chrome writes the PDF bookmarks
    (--generate-pdf-document-outline) and the internal links.
 5. pypdf checks the result: page count, bookmarks, links, text on every page,
    no leftover placeholder.

A separately kept edition can add chapters and diagrams that are not in this
repository: --extension DIR appends DIR/*.md after the shared chapters, and
--diagram-dir DIR lets them use DIR/*.svg. Such an edition must be written
outside the repository (--out); the script refuses an output path inside it.

Requirements: the repository's virtual environment (pypdf; markdown-it-py,
`pip install markdown-it-py` if it is missing) and Google Chrome or Chromium.
Set CHROME=/path/to/chrome when it is not in the usual place.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SRC = HERE / "src"
DIAGRAMS = REPO / "docs" / "architecture" / "uml-diagram-sources"
DEFAULT_OUT = HERE / "AEGIS_SENTINEL_TECHNICAL_OVERVIEW.pdf"
CHROME_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
)

STATUS = {   # [[tag]] in the Markdown -> a labelled chip
    "impl": ("Implemented", "st-impl"),
    "local": ("Tested locally", "st-local"),
    "ci": ("Verified in CI", "st-ci"),
    "pending": ("Not verified", "st-pending"),
    "optional": ("Optional / off by default", "st-opt"),
    "proposed": ("Proposed", "st-prop"),
    "gap": ("Gap", "st-gap"),
    "existing": ("Existing", "st-impl"),
    "adapt": ("Needs adaptation", "st-local"),
}


# ----------------------------------------------------------------- helpers
def fail(msg: str) -> None:
    print(f"build_overview: {msg}", file=sys.stderr)
    raise SystemExit(1)


def find_chrome() -> str:
    for c in [os.environ.get("CHROME", "")] + list(CHROME_CANDIDATES):
        if c and Path(c).is_file():
            return c
    for name in ("google-chrome", "chromium", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    fail("Google Chrome or Chromium not found; set CHROME=/path/to/chrome")
    return ""


def inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO)
        return True
    except ValueError:
        return False


def git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True,
                              timeout=30).stdout.strip()
    except Exception:
        return ""


# ------------------------------------------------------------------- facts
def check_facts(allow_drift: bool) -> Dict[str, object]:
    sys.path.insert(0, str(HERE))
    import facts as facts_mod
    stored = json.loads((SRC / "facts.json").read_text(encoding="utf-8"))
    current = facts_mod.compute()
    drift = {k: (stored.get(k), current.get(k)) for k in sorted(set(stored) | set(current))
             if stored.get(k) != current.get(k)}
    if drift:
        lines = "\n".join(f"  {k}: document says {a!r}, code says {b!r}" for k, (a, b) in drift.items())
        if not allow_drift:
            fail("the code no longer agrees with src/facts.json:\n" + lines +
                 "\nReview the text that cites these values, then run facts.py --write.")
        print("WARNING (draft build): facts drift\n" + lines, file=sys.stderr)
    return stored


# ---------------------------------------------------------------- markdown
def render_markdown(text: str) -> str:
    try:
        from markdown_it import MarkdownIt
    except ImportError:
        fail("markdown-it-py is not installed in this environment (pip install markdown-it-py)")
    md = MarkdownIt("commonmark", {"html": True, "typographer": False}).enable("table")
    return md.render(text)


def load_svg(name: str, diagram_dirs: List[Path]) -> str:
    for folder in diagram_dirs:
        path = folder / name
        if path.is_file():
            svg = path.read_text(encoding="utf-8")
            svg = re.sub(r"^<\?xml[^>]*>\s*", "", svg)
            # width/height from the viewBox are replaced by CSS sizing
            svg = re.sub(r'(<svg[^>]*?)\swidth="[^"]*"\sheight="[^"]*"', r"\1", svg, count=1)
            return svg
    fail(f"diagram {name} not found in {', '.join(str(d) for d in diagram_dirs)}")
    return ""


PAGE_RATIO = 172 / 273          # usable height / width of a landscape page (style.css)


def split_svg(svg: str, parts_hint: str) -> List[str]:
    """Cut a tall drawing into page-shaped parts by changing its viewBox. Cuts are
    placed where no box (other than full-height lanes and frames) and no text line
    is crossed, so a node is never split between two pages."""
    m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    if not m:
        return [svg]
    w, h = float(m.group(1)), float(m.group(2))
    if parts_hint != "auto":
        parts = max(1, int(parts_hint))
    else:   # balanced parts; a part may be up to 20 % taller than the page shape
        parts = max(1, -(-int(h) // int(w * PAGE_RATIO * 1.2)))
    if parts == 1:
        return [svg]
    target = h / parts
    blocked: List[Tuple[float, float]] = []
    # only nodes block a cut: frames, lanes and back layers may be crossed
    nodes = "".join(re.findall(r'<g id="[\w-]+-node">(.*?)</g>', svg, flags=re.S)) or svg
    for r in re.finditer(r'<rect x="([-\d.]+)" y="([-\d.]+)" width="([\d.]+)" height="([\d.]+)"', nodes):
        y, rh = float(r.group(2)), float(r.group(4))
        if rh < 0.45 * h:                                 # lanes and frames may be crossed
            blocked.append((y - 4, y + rh + 4))
    for t in re.finditer(r'<text x="[-\d.]+" y="([-\d.]+)"[^>]*font-size="([\d.]+)"', svg):
        y, size = float(t.group(1)), float(t.group(2))
        blocked.append((y - size - 3, y + 5))
    for e in re.finditer(r'<(?:ellipse|polygon)[^>]*?(?:cy="([-\d.]+)"[^>]*ry="([\d.]+)"|points="([^"]+)")', nodes):
        if e.group(1):
            cy, ry = float(e.group(1)), float(e.group(2))
            blocked.append((cy - ry - 3, cy + ry + 3))
        else:
            ys = [float(p.split(",")[1]) for p in e.group(3).split() if "," in p]
            if ys and max(ys) - min(ys) < 0.45 * h:
                blocked.append((min(ys) - 3, max(ys) + 3))

    def crossings(y: float) -> int:
        return sum(1 for a, b in blocked if a < y < b and b - a < 0.5 * target)

    cuts = [0.0]
    for k in range(1, parts):
        want = k * target        # the line crossing the fewest boxes, nearest the target
        y = min((want + d for d in range(-int(target * 0.4), int(target * 0.4) + 1)),
                key=lambda c: (crossings(c), abs(c - want)))
        cuts.append(y)
    cuts.append(h)
    out = []
    for i in range(len(cuts) - 1):
        y0, y1 = cuts[i], cuts[i + 1]
        part = re.sub(r'viewBox="[^"]*"', f'viewBox="0 {y0:.0f} {w:.0f} {y1 - y0:.0f}"', svg, count=1)
        if i:
            part = re.sub(r'\sid="', ' data-id="', part)
            part = re.sub(r'aria-labelledby="[^"]*"', "", part)
        out.append(part)
    return out


DIRECTIVE = re.compile(r"^@(\w+)\s*(.*)$")


def expand(text: str, facts: Dict[str, object], diagram_dirs: List[Path]) -> str:
    """Placeholders and block directives -> Markdown with HTML islands."""
    def fact(m: re.Match) -> str:
        key = m.group(1)
        if key not in facts:
            fail(f"unknown fact {{{{fact:{key}}}}}")
        value = facts[key]
        return ("yes" if value else "no") if isinstance(value, bool) else str(value)

    text = re.sub(r"\{\{fact:([a-z0-9_]+)\}\}", fact, text)

    def chip(m: re.Match) -> str:
        label, cls = STATUS[m.group(1)]
        return f'<span class="st {cls}">{label}</span>'

    text = re.sub(r"\[\[(" + "|".join(STATUS) + r")\]\]", chip, text)
    out: List[str] = []
    for line in text.splitlines():
        m = DIRECTIVE.match(line.strip())
        if not m:
            out.append(line)
            continue
        kind, arg = m.group(1), m.group(2).strip()
        if kind == "diagram":           # @diagram file.svg | caption | portrait|landscape|tall
            parts = [p.strip() for p in arg.split("|")]
            name, caption = parts[0], parts[1] if len(parts) > 1 else ""
            layout = parts[2] if len(parts) > 2 else "landscape"
            split = parts[3] if len(parts) > 3 else ("auto" if layout == "landscape" else "1")
            pieces = split_svg(load_svg(name, diagram_dirs), split)
            for i, svg in enumerate(pieces, start=1):
                cap = caption + (f" (part {i} of {len(pieces)})" if len(pieces) > 1 else "")
                out.append(f'\n<figure class="dgm dgm-{layout}"><div class="svgbox">{svg}</div>'
                           f'<figcaption>{html.escape(cap)}</figcaption></figure>\n')
        elif kind == "landscape":
            out.append('\n<section class="landscape">\n')
        elif kind == "endlandscape":
            out.append("\n</section>\n")
        elif kind == "pagebreak":
            out.append('\n<div class="pb"></div>\n')
        elif kind == "note":           # @note kind | text  -> callout
            cls, _, body = arg.partition("|")
            out.append(f'\n<div class="callout {cls.strip()}">\n\n{body.strip()}\n\n</div>\n')
        else:
            out.append(line)
    return "\n".join(out)


# ------------------------------------------------------------ headings/TOC
def number_headings(body: str, prefix_parts: bool = True) -> Tuple[str, List[Tuple[int, str, str, str]]]:
    """Number h1/h2/h3 (appendix chapters start with 'Appendix'), give them ids,
    and return (html, [(level, number, title, id)])."""
    # front matter titled "About this document" is chapter 0, so the main text starts at 1
    first = re.search(r"<h1[^>]*>(.*?)</h1>", body, flags=re.S)
    front = bool(first and first.group(1).strip().startswith("About this document"))
    counters = [-1 if front else 0, 0, 0]
    toc: List[Tuple[int, str, str, str]] = []
    appendix = [0]

    def repl(m: re.Match) -> str:
        level, attrs, inner = int(m.group(1)), m.group(2), m.group(3)
        if "nonum" in attrs:
            hid = "s-" + re.sub(r"[^a-z0-9]+", "-", re.sub(r"<[^>]+>", "", inner).lower()).strip("-")
            return f'<h{level} id="{hid}" class="nonum">{inner}</h{level}>'
        plain = html.unescape(re.sub(r"<[^>]+>", "", inner))
        if level == 1 and plain.startswith("Appendix"):
            appendix[0] += 1
            counters[:] = [0, 0, 0]
            letter = chr(64 + appendix[0])
            num = letter
            title = plain.split(":", 1)[-1].strip() if ":" in plain else plain
            shown = f"Appendix {letter}"
            hid = f"app-{letter.lower()}"
            toc.append((1, shown, title, hid))
            return (f'<h1 id="{hid}" class="chapter"><span class="num">{shown}</span> '
                    f'{html.escape(title)}</h1>')
        idx = level - 1
        counters[idx] += 1
        for j in range(idx + 1, 3):
            counters[j] = 0
        if appendix[0]:
            num = chr(64 + appendix[0]) + "." + ".".join(str(c) for c in counters[1:level])
        else:
            num = ".".join(str(c) for c in counters[:level])
        hid = "s-" + num.replace(".", "-").lower()
        if level <= 2:
            toc.append((level, num, plain, hid))
        cls = ' class="chapter"' if level == 1 else ""
        return f'<h{level} id="{hid}"{cls}><span class="num">{num}</span> {inner}</h{level}>'

    body = re.sub(r"<h([123])([^>]*)>(.*?)</h\1>", repl, body, flags=re.S)
    return body, toc


def toc_html(toc: List[Tuple[int, str, str, str]], pages: Dict[str, int]) -> str:
    rows = []
    for level, num, title, hid in toc:
        page = pages.get(hid)
        shown = str(page) if page else "000"
        rows.append(f'<li class="t{level}"><a href="#{hid}"><span class="tn">{html.escape(num)}</span>'
                    f'<span class="tt">{html.escape(title)}</span><span class="tp">{shown}</span></a></li>')
    return '<nav class="toc"><h1 class="nonum toc-title" id="contents">Contents</h1><ol>' + \
        "".join(rows) + "</ol></nav>"


# -------------------------------------------------------------------- page
def page_html(body: str, meta: Dict[str, str], toc: str, css: str, markers: bool) -> str:
    edition = meta["edition"]
    if markers:   # pass 1: a findable token at the top of every numbered heading
        body = re.sub(r'(<h[12] id="([^"]+)"[^>]*>)', lambda m: m.group(1) +
                      f'<span class="mk">@@{m.group(2)}@@</span>', body)
    cover = f"""
<section class="cover">
  <div class="cover-band">{html.escape(edition)}</div>
  <h1 class="nonum cover-title">{html.escape(meta['title'])}</h1>
  <p class="cover-sub">{html.escape(meta['subtitle'])}</p>
  <table class="cover-meta">
    <tr><th>Document date</th><td>{html.escape(meta['date'])}</td></tr>
    <tr><th>Code baseline</th><td>{html.escape(meta['baseline'])}</td></tr>
    <tr><th>Repository state</th><td>{html.escape(meta['repo_state'])}</td></tr>
    <tr><th>Scope</th><td>{html.escape(meta['scope'])}</td></tr>
    <tr><th>Audience</th><td>{html.escape(meta['audience'])}</td></tr>
  </table>
  <p class="cover-note">{meta['cover_note']}</p>
</section>"""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{html.escape(meta['title'])}</title>
<meta name="author" content="Aegis Sentinel project">
<meta name="description" content="{html.escape(meta['subtitle'])}">
<style>{css}
@page {{ @top-left {{ content: "{meta['running']}"; }} }}
</style></head>
<body>{cover}{toc}<main>{body}</main></body></html>"""


def print_pdf(chrome: str, html_file: Path, pdf: Path, workdir: Path) -> None:
    profile = workdir / "chrome-profile"
    cmd = [chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
           "--disable-extensions", "--disable-background-networking", "--disable-sync",
           "--disable-component-update", "--metrics-recording-only", "--no-pdf-header-footer",
           "--generate-pdf-document-outline", f"--user-data-dir={profile}",
           "--virtual-time-budget=20000", "--run-all-compositor-stages-before-draw",
           f"--print-to-pdf={pdf}", html_file.as_uri()]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if res.returncode != 0 or not pdf.is_file() or pdf.stat().st_size < 1000:
        fail(f"Chrome could not print the PDF (exit {res.returncode}):\n{res.stderr[-1500:]}")


def heading_pages(pdf: Path) -> Dict[str, int]:
    from pypdf import PdfReader
    pages: Dict[str, int] = {}
    for i, page in enumerate(PdfReader(str(pdf)).pages, start=1):
        # text extraction can insert whitespace inside a marker ("@@s-9 -1@@")
        for raw in re.findall(r"@@([a-z0-9\s-]+?)@@", page.extract_text() or ""):
            pages.setdefault(re.sub(r"\s+", "", raw), i)
    return pages


def verify(pdf: Path, toc: List[Tuple[int, str, str, str]], forbidden: List[str]) -> Dict[str, object]:
    from pypdf import PdfReader
    reader = PdfReader(str(pdf))
    texts = [p.extract_text() or "" for p in reader.pages]
    problems = []
    blank = [i + 1 for i, t in enumerate(texts) if len(t.strip()) < 40]
    if blank:
        problems.append(f"pages with almost no text: {blank}")
    joined = "\n".join(texts)
    for token in ["@@", "{{fact:", "[["] + forbidden:
        if token and token in joined:
            problems.append(f"leftover or forbidden text in the PDF: {token!r}")
    outline = reader.outline

    def count(items) -> int:
        return sum(count(x) if isinstance(x, list) else 1 for x in items)

    links = sum(1 for p in reader.pages for a in (p.get("/Annots") or [])
                if a.get_object().get("/Subtype") == "/Link")
    if count(outline) < len([t for t in toc if t[0] == 1]):
        problems.append("the PDF has fewer bookmarks than chapters")
    if links < len(toc):
        problems.append(f"only {links} links for {len(toc)} contents entries")
    return {"pages": len(reader.pages), "bookmarks": count(outline), "links": links,
            "problems": problems, "chars": len(joined)}


# -------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--extension", type=Path, help="extra chapters (DIR/*.md) appended after src/")
    ap.add_argument("--diagram-dir", type=Path, action="append", default=[],
                    help="extra folder of .svg diagrams the extension chapters use")
    ap.add_argument("--meta", type=Path, default=SRC / "meta.json",
                    help="cover and running-header text (JSON)")
    ap.add_argument("--forbid", type=Path, help="file of phrases that must not appear in the PDF")
    ap.add_argument("--keep-html", type=Path, help="also write the final HTML here")
    ap.add_argument("--skip-diagrams", action="store_true", help="do not rebuild the diagrams")
    ap.add_argument("--allow-drift", action="store_true", help="draft: warn on facts drift")
    ap.add_argument("--check-only", action="store_true", help="facts and diagrams only, no PDF")
    args = ap.parse_args()

    if args.extension and inside_repo(args.out):
        fail("an edition with --extension must be written outside the repository (--out)")
    for extra in [args.extension, *args.diagram_dir]:
        if extra is not None and inside_repo(extra):
            fail(f"{extra} is inside the repository; extension sources live outside it")

    facts = check_facts(args.allow_drift)
    if not args.skip_diagrams:
        res = subprocess.run([sys.executable, "build_diagrams.py"], cwd=DIAGRAMS,
                             capture_output=True, text=True, timeout=300)
        if res.returncode != 0:
            fail("diagram build failed:\n" + res.stdout[-1500:] + res.stderr[-1500:])
    if args.check_only:
        print("facts and diagrams: OK")
        return 0

    meta = json.loads(args.meta.read_text(encoding="utf-8"))
    head = git("rev-parse", "--short", "HEAD")
    meta.setdefault("repo_state", f"branch {git('rev-parse', '--abbrev-ref', 'HEAD')}, "
                                  f"built from commit {head}")
    chapters = sorted(SRC.glob("*.md"))
    if args.extension:   # extension chapters go before the appendices (src/9*.md)
        appendices = [p for p in chapters if p.name.startswith("9")]
        chapters = [p for p in chapters if p not in appendices]
        chapters += sorted(args.extension.glob("*.md")) + appendices
    diagram_dirs = [DIAGRAMS, *args.diagram_dir]
    source = "\n\n".join(expand(p.read_text(encoding="utf-8"), facts, diagram_dirs) for p in chapters)
    body, toc = number_headings(render_markdown(source))
    css = (HERE / "style.css").read_text(encoding="utf-8")
    forbidden = []
    if args.forbid:
        forbidden = [x.strip() for x in args.forbid.read_text(encoding="utf-8").splitlines()
                     if x.strip() and not x.startswith("#")]

    chrome = find_chrome()
    with tempfile.TemporaryDirectory(prefix="aegis_overview_") as tmp:
        work = Path(tmp)
        first_html, first_pdf = work / "pass1.html", work / "pass1.pdf"
        first_html.write_text(page_html(body, meta, toc_html(toc, {}), css, True), encoding="utf-8")
        print_pdf(chrome, first_html, first_pdf, work)
        pages = heading_pages(first_pdf)
        missing = [hid for _, _, _, hid in toc if hid not in pages]
        if missing:
            fail(f"could not find the page of {len(missing)} heading(s): {missing[:5]}")
        final_html = work / "overview.html"
        final_html.write_text(page_html(body, meta, toc_html(toc, pages), css, False), encoding="utf-8")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        print_pdf(chrome, final_html, args.out, work)
        if args.keep_html:
            args.keep_html.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(final_html, args.keep_html)
    report = verify(args.out, toc, forbidden)
    print(f"{args.out}: {report['pages']} pages, {report['bookmarks']} bookmarks, "
          f"{report['links']} links, {report['chars']} characters of text")
    if report["problems"]:
        fail("checks failed:\n  " + "\n  ".join(str(x) for x in report["problems"]))  # type: ignore[attr-defined]
    return 0


if __name__ == "__main__":
    sys.exit(main())
