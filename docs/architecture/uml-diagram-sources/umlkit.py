"""umlkit: small, dependency-free SVG helpers for the Aegis Sentinel UML diagrams.

Design rules
  * Plain SVG with inline presentation attributes: no CSS classes, no markers,
    no external fonts or scripts. A diagram therefore renders the same way in a
    browser, Inkscape, Figma or draw.io, and every label stays editable text.
  * Sizes are computed from the text (Arial / Helvetica metrics below), so a
    label that would not fit its box is reported by `Diagram.check()` instead
    of being clipped silently.
  * `Diagram.check()` also reports nodes that overlap, connectors that run
    through a node they are not attached to, and labels that collide.

Python 3.9+, standard library only.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from html import escape
from typing import Dict, List, Optional, Sequence, Tuple, Union

Point = Tuple[float, float]
Lines = Union[str, Sequence[str]]

FONT = "Arial, Helvetica, 'Liberation Sans', sans-serif"
INK = "#0f172a"        # text and outlines
MUTED = "#334155"      # secondary text (still > 9:1 on white)
PAPER = "#ffffff"

# --------------------------------------------------------------------- metrics
# Advance widths (1/1000 em) of Helvetica / Arial for ASCII 32..126.
_REG = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
        1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
        333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
        556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
         556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
         975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
         667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
         333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
         611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584]
_EXTRA_REG = {"«": 556, "»": 556, "·": 278, "–": 556, "—": 1000, "…": 1000, "≥": 549,
              "≤": 549, "×": 584, "→": 1000, "’": 222, "‘": 222, "“": 333, "”": 333,
              "•": 350, "°": 400}
_EXTRA_BOLD = dict(_EXTRA_REG, **{"’": 278, "‘": 278, "“": 500, "”": 500})
_SAFETY = 1.02


def text_width(s: str, size: float, bold: bool = False) -> float:
    """Rendered width of `s` in px at `size` px (Arial / Helvetica)."""
    table, extra = (_BOLD, _EXTRA_BOLD) if bold else (_REG, _EXTRA_REG)
    total = 0
    for ch in s:
        code = ord(ch)
        if 32 <= code <= 126:
            total += table[code - 32]
        else:
            total += extra.get(ch, 620)
    return total / 1000.0 * size * _SAFETY


def wrap(s: str, max_w: float, size: float, bold: bool = False) -> List[str]:
    """Greedy word wrap of one paragraph to `max_w` px."""
    out: List[str] = []
    line = ""
    for word in s.split():
        trial = word if not line else f"{line} {word}"
        if line and text_width(trial, size, bold) > max_w:
            out.append(line)
            line = word
        else:
            line = trial
    if line:
        out.append(line)
    return out or [""]


def as_lines(value: Lines) -> List[str]:
    return [value] if isinstance(value, str) else list(value)


def _n(v: float) -> str:
    """A compact number for SVG attributes."""
    text = f"{v:.1f}"
    return text[:-2] if text.endswith(".0") else text


# ----------------------------------------------------------------------- boxes
@dataclass
class Box:
    """A placed node. `shape` is rect | ellipse | diamond."""
    x: float
    y: float
    w: float
    h: float
    shape: str = "rect"
    name: str = ""

    @property
    def left(self) -> float:
        return self.x

    @property
    def right(self) -> float:
        return self.x + self.w

    @property
    def top(self) -> float:
        return self.y

    @property
    def bottom(self) -> float:
        return self.y + self.h

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2

    @property
    def center(self) -> Point:
        return (self.cx, self.cy)

    def side(self, side: str, t: float = 0.5) -> Point:
        """The boundary point on `side` (left/right/top/bottom), `t` along it (0..1)."""
        hw, hh = self.w / 2, self.h / 2
        if side in ("left", "right"):
            y = self.y + self.h * t
            dy = y - self.cy
            if self.shape == "ellipse":
                dx = hw * math.sqrt(max(0.0, 1 - (dy / hh) ** 2))
            elif self.shape == "diamond":
                dx = hw * max(0.0, 1 - abs(dy) / hh)
            else:
                dx = hw
            return (self.cx - dx if side == "left" else self.cx + dx, y)
        x = self.x + self.w * t
        dx = x - self.cx
        if self.shape == "ellipse":
            dy = hh * math.sqrt(max(0.0, 1 - (dx / hw) ** 2))
        elif self.shape == "diamond":
            dy = hh * max(0.0, 1 - abs(dx) / hw)
        else:
            dy = hh
        return (x, self.cy - dy if side == "top" else self.cy + dy)

    def l(self, t: float = 0.5) -> Point:  # noqa: E743 - short on purpose
        return self.side("left", t)

    def r(self, t: float = 0.5) -> Point:
        return self.side("right", t)

    def t(self, t: float = 0.5) -> Point:
        return self.side("top", t)

    def b(self, t: float = 0.5) -> Point:
        return self.side("bottom", t)

    def toward(self, p: Point) -> Point:
        """The boundary point on the straight line from the centre towards `p`."""
        dx, dy = p[0] - self.cx, p[1] - self.cy
        if dx == 0 and dy == 0:
            return self.center
        hw, hh = self.w / 2, self.h / 2
        if self.shape == "ellipse":
            k = 1 / math.sqrt((dx / hw) ** 2 + (dy / hh) ** 2)
        elif self.shape == "diamond":
            k = 1 / (abs(dx) / hw + abs(dy) / hh)
        else:
            k = min(hw / abs(dx) if dx else math.inf, hh / abs(dy) if dy else math.inf)
        return (self.cx + dx * k, self.cy + dy * k)

    def contains(self, p: Point, inset: float = 0.0) -> bool:
        dx, dy = p[0] - self.cx, p[1] - self.cy
        hw, hh = self.w / 2 - inset, self.h / 2 - inset
        if hw <= 0 or hh <= 0:
            return False
        if self.shape == "ellipse":
            return (dx / hw) ** 2 + (dy / hh) ** 2 < 1
        if self.shape == "diamond":
            return abs(dx) / hw + abs(dy) / hh < 1
        return abs(dx) < hw and abs(dy) < hh


# ---------------------------------------------------------------------- routes
def hv(a: Point, b: Point) -> List[Point]:
    """Horizontal first, then vertical."""
    return [a, (b[0], a[1]), b]


def vh(a: Point, b: Point) -> List[Point]:
    """Vertical first, then horizontal."""
    return [a, (a[0], b[1]), b]


def hvh(a: Point, b: Point, x: Optional[float] = None) -> List[Point]:
    mx = (a[0] + b[0]) / 2 if x is None else x
    return [a, (mx, a[1]), (mx, b[1]), b]


def vhv(a: Point, b: Point, y: Optional[float] = None) -> List[Point]:
    my = (a[1] + b[1]) / 2 if y is None else y
    return [a, (a[0], my), (b[0], my), b]


def _clean(points: Sequence[Point]) -> List[Point]:
    """Drop repeated points and points in the middle of a straight run."""
    out: List[Point] = []
    for p in points:
        p = (float(p[0]), float(p[1]))
        if out and abs(out[-1][0] - p[0]) < 0.01 and abs(out[-1][1] - p[1]) < 0.01:
            continue
        out.append(p)
    i = 1
    while i < len(out) - 1:
        (ax, ay), (bx, by), (cx, cy) = out[i - 1], out[i], out[i + 1]
        if abs((bx - ax) * (cy - by) - (by - ay) * (cx - bx)) < 0.01:
            del out[i]
        else:
            i += 1
    return out


def _unit(a: Point, b: Point) -> Point:
    dx, dy = b[0] - a[0], b[1] - a[1]
    length = math.hypot(dx, dy) or 1.0
    return (dx / length, dy / length)


# ------------------------------------------------------------ geometry (checks)
def _seg_hits_seg(p1: Point, p2: Point, p3: Point, p4: Point) -> bool:
    def orient(a: Point, b: Point, c: Point) -> float:
        return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
    d1, d2 = orient(p3, p4, p1), orient(p3, p4, p2)
    d3, d4 = orient(p1, p2, p3), orient(p1, p2, p4)
    return (d1 * d2 < 0) and (d3 * d4 < 0)


def _seg_hits_box(a: Point, b: Point, box: Box, inset: float = 2.0) -> bool:
    if box.contains(a, inset) or box.contains(b, inset):
        return True
    hw, hh = box.w / 2 - inset, box.h / 2 - inset
    if hw <= 0 or hh <= 0:
        return False
    if box.shape == "ellipse":
        # distance from the centre to the segment, in the ellipse's unit space
        ax, ay = (a[0] - box.cx) / hw, (a[1] - box.cy) / hh
        bx, by = (b[0] - box.cx) / hw, (b[1] - box.cy) / hh
        dx, dy = bx - ax, by - ay
        length2 = dx * dx + dy * dy
        t = 0.0 if length2 == 0 else max(0.0, min(1.0, -(ax * dx + ay * dy) / length2))
        return math.hypot(ax + t * dx, ay + t * dy) < 1
    if box.shape == "diamond":
        corners = [(box.cx - hw, box.cy), (box.cx, box.cy - hh),
                   (box.cx + hw, box.cy), (box.cx, box.cy + hh)]
    else:
        corners = [(box.cx - hw, box.cy - hh), (box.cx + hw, box.cy - hh),
                   (box.cx + hw, box.cy + hh), (box.cx - hw, box.cy + hh)]
    return any(_seg_hits_seg(a, b, corners[i], corners[(i + 1) % 4]) for i in range(4))


def _rects_overlap(a: Tuple[float, float, float, float], b: Tuple[float, float, float, float],
                   gap: float = 0.0) -> bool:
    return (a[0] < b[0] + b[2] + gap and b[0] < a[0] + a[2] + gap
            and a[1] < b[1] + b[3] + gap and b[1] < a[1] + a[3] + gap)


# --------------------------------------------------------------------- diagram
class Diagram:
    """One SVG drawing. Elements are kept in layers and written back to front."""

    LAYERS = ("back", "frame", "edge", "node", "label", "front")
    DEBUG = False          # build_diagrams.py --check: mark each text with its measured and allowed width

    def __init__(self, ident: str, width: float, height: float, title: str,
                 subtitle: str = "", desc: str = ""):
        self.ident, self.w, self.h = ident, width, height
        self.title_text, self.subtitle_text, self.desc = title, subtitle, desc
        self._layers: Dict[str, List[str]] = {k: [] for k in self.LAYERS}
        self.nodes: List[Box] = []
        self.segments: List[Tuple[Point, Point, Tuple[Box, ...], str]] = []
        self.labels: List[Tuple[Tuple[float, float, float, float], str]] = []
        self.problems: List[str] = []
        self.debug = self.DEBUG

    # ------------------------------------------------------------ primitives
    def raw(self, fragment: str, layer: str = "node") -> None:
        self._layers[layer].append(fragment)

    def rect(self, x: float, y: float, w: float, h: float, fill: str = PAPER,
             stroke: str = INK, sw: float = 1.5, rx: float = 0, layer: str = "node",
             dash: str = "", opacity: float = 1.0) -> None:
        attrs = f'x="{_n(x)}" y="{_n(y)}" width="{_n(w)}" height="{_n(h)}" fill="{fill}"'
        if rx:
            attrs += f' rx="{_n(rx)}"'
        attrs += f' stroke="{stroke}" stroke-width="{_n(sw)}"' if stroke != "none" else ' stroke="none"'
        if dash:
            attrs += f' stroke-dasharray="{dash}"'
        if opacity != 1.0:
            attrs += f' fill-opacity="{_n(opacity)}"'
        self.raw(f"<rect {attrs}/>", layer)

    def line(self, a: Point, b: Point, stroke: str = INK, sw: float = 1.5,
             layer: str = "node", dash: str = "") -> None:
        attrs = (f'x1="{_n(a[0])}" y1="{_n(a[1])}" x2="{_n(b[0])}" y2="{_n(b[1])}" '
                 f'stroke="{stroke}" stroke-width="{_n(sw)}" stroke-linecap="round"')
        if dash:
            attrs += f' stroke-dasharray="{dash}"'
        self.raw(f"<line {attrs}/>", layer)

    def polygon(self, points: Sequence[Point], fill: str = PAPER, stroke: str = INK,
                sw: float = 1.5, layer: str = "node") -> None:
        pts = " ".join(f"{_n(x)},{_n(y)}" for x, y in points)
        self.raw(f'<polygon points="{pts}" fill="{fill}" stroke="{stroke}" '
                 f'stroke-width="{_n(sw)}" stroke-linejoin="round"/>', layer)

    def ellipse(self, cx: float, cy: float, rx: float, ry: float, fill: str = PAPER,
                stroke: str = INK, sw: float = 1.5, layer: str = "node") -> None:
        self.raw(f'<ellipse cx="{_n(cx)}" cy="{_n(cy)}" rx="{_n(rx)}" ry="{_n(ry)}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="{_n(sw)}"/>', layer)

    def text(self, x: float, y: float, s: str, size: float = 13, bold: bool = False,
             italic: bool = False, anchor: str = "start", fill: str = INK,
             layer: str = "node", maxw: Optional[float] = None) -> float:
        """One line of text; `y` is the baseline. Returns the measured width."""
        width = text_width(s, size, bold)
        if maxw is not None and width > maxw + 0.5:
            self.problems.append(f"text wider than its box ({width:.0f} > {maxw:.0f} px): {s!r}")
        attrs = f'x="{_n(x)}" y="{_n(y)}" font-size="{_n(size)}" fill="{fill}"'
        if bold:
            attrs += ' font-weight="700"'
        if italic:
            attrs += ' font-style="italic"'
        if anchor != "start":
            attrs += f' text-anchor="{anchor}"'
        if self.debug:
            attrs += f' data-w="{_n(width)}"'
            if maxw is not None:
                attrs += f' data-maxw="{_n(maxw)}"'
        self.raw(f"<text {attrs}>{escape(s)}</text>", layer)
        return width

    def text_block(self, cx: float, cy: float, lines: Lines, size: float = 13,
                   bold: Union[bool, Sequence[bool]] = False, lh: Optional[float] = None,
                   fill: Union[str, Sequence[str]] = INK, layer: str = "node",
                   maxw: Optional[Union[float, Sequence[float]]] = None,
                   sizes: Optional[Sequence[float]] = None,
                   italic: Union[bool, Sequence[bool]] = False) -> None:
        """Lines centred horizontally on `cx` and vertically on `cy`."""
        rows = as_lines(lines)
        szs = list(sizes) if sizes else [size] * len(rows)
        heights = [(lh if lh else s * 1.32) for s in szs]
        y = cy - sum(heights) / 2
        for i, row in enumerate(rows):
            b = bold[i] if isinstance(bold, (list, tuple)) else bold
            it = italic[i] if isinstance(italic, (list, tuple)) else italic
            f = fill[i] if isinstance(fill, (list, tuple)) else fill
            mw = maxw[i] if isinstance(maxw, (list, tuple)) else maxw
            baseline = y + heights[i] / 2 + szs[i] * 0.36
            self.text(cx, baseline, row, szs[i], bool(b), bool(it), "middle", str(f), layer, mw)
            y += heights[i]

    def track(self, box: Box) -> Box:
        self.nodes.append(box)
        return box

    # ----------------------------------------------------------------- frames
    def title_block(self, x: float = 24, y: float = 40) -> None:
        self.text(x, y, self.title_text, 22, bold=True, layer="front")
        if self.subtitle_text:
            self.text(x, y + 23, self.subtitle_text, 13, fill=MUTED, layer="front")

    def frame(self, x: float, y: float, w: float, h: float, title: str = "",
              fill: str = "#f8fafc", stroke: str = "#475569", title_fill: str = INK,
              size: float = 13, dash: str = "", sub: str = "", rx: float = 8) -> Box:
        """A titled group box (package / region). Not checked for overlaps."""
        self.rect(x, y, w, h, fill, stroke, 1.4, rx, "frame", dash)
        if title:
            self.text(x + 12, y + 20, title, size, bold=True, fill=title_fill, layer="frame",
                      maxw=w - 24)
        if sub:
            self.text(x + 12, y + 20 + size * 1.3, sub, 12, fill=MUTED, layer="frame", maxw=w - 24)
        return Box(x, y, w, h, "rect", title)

    # ---------------------------------------------------------------- classes
    def klass(self, x: float, y: float, name: str, attrs: Sequence[str] = (),
              methods: Sequence[str] = (), w: Optional[float] = None,
              stereotype: str = "", fill: str = "#dbeafe", abstract: bool = False,
              size: float = 12.5, name_size: float = 14, lh: float = 17.5,
              pad: float = 10, min_w: float = 0) -> Box:
        """A UML class: name compartment, attributes, operations."""
        attrs, methods = list(attrs), list(methods)
        need = max([text_width(name, name_size, True)]
                   + ([text_width(stereotype, 12)] if stereotype else [])
                   + [text_width(s, size) for s in attrs + methods])
        width = math.ceil(max(min_w, need + 2 * pad)) if w is None else w
        head = 44 if stereotype else 30
        comp_a = len(attrs) * lh + 10 if attrs else 0
        comp_m = len(methods) * lh + 10 if methods else 0
        height = head + comp_a + comp_m
        self.rect(x, y, width, height, PAPER, INK, 1.6, 3)
        self.rect(x, y, width, head, fill, INK, 1.6, 3)
        if comp_a or comp_m:                       # square the header's lower corners
            self.rect(x + 0.8, y + head - 6, width - 1.6, 6, fill, "none")
            self.line((x, y + head), (x + width, y + head), INK, 1.6)
        inner = width - 2 * pad
        if stereotype:
            self.text(x + width / 2, y + 17, stereotype, 12, anchor="middle", fill=MUTED, maxw=inner)
            self.text(x + width / 2, y + 35, name, name_size, True, abstract, "middle", maxw=inner)
        else:
            self.text(x + width / 2, y + 20, name, name_size, True, abstract, "middle", maxw=inner)
        cy = y + head
        for block in (attrs, methods):
            if not block:
                continue
            if block is methods and attrs:
                self.line((x, cy), (x + width, cy), INK, 1.2)
            ty = cy + 5
            for row in block:
                ty += lh
                self.text(x + pad, ty - 4.5, row, size, maxw=inner)
            cy += len(block) * lh + 10
        return self.track(Box(x, y, width, height, "rect", name))

    def name_box(self, x: float, y: float, name: str, w: Optional[float] = None,
                 h: float = 26, fill: str = "#dbeafe", size: float = 12.5, bold: bool = True,
                 italic: bool = False, sw: float = 1.4, pad: float = 8) -> Box:
        """A class shown by name only."""
        width = math.ceil(text_width(name, size, bold) + 2 * pad) if w is None else w
        self.rect(x, y, width, h, fill, INK, sw, 3)
        self.text(x + width / 2, y + h / 2 + size * 0.36, name, size, bold, italic, "middle",
                  maxw=width - 2 * pad + 4)
        return self.track(Box(x, y, width, h, "rect", name))

    # --------------------------------------------------------- generic nodes
    def node(self, x: float, y: float, w: float, lines: Lines, h: Optional[float] = None,
             fill: str = "#eff6ff", stroke: str = INK, rx: float = 10, size: float = 13,
             bold: Union[bool, Sequence[bool]] = False, pad: float = 10, sw: float = 1.5,
             wrap_text: bool = True, lh: Optional[float] = None, name: str = "",
             fills: Union[str, Sequence[str]] = INK, sizes: Optional[Sequence[float]] = None,
             track: bool = True) -> Box:
        """A rectangle with centred text. A string is wrapped to the width; a
        list is used line by line (each line still has to fit)."""
        inner = w - 2 * pad
        if isinstance(lines, str):
            rows = wrap(lines, inner, size, bool(bold)) if wrap_text else [lines]
        else:
            rows = list(lines)
        szs = list(sizes) if sizes else [size] * len(rows)
        line_h = [(lh if lh else s * 1.32) for s in szs]
        height = h if h is not None else math.ceil(sum(line_h) + 2 * pad - 2)
        self.rect(x, y, w, height, fill, stroke, sw, rx)
        self.text_block(x + w / 2, y + height / 2, rows, size, bold, lh, fills, "node", inner, szs)
        box = Box(x, y, w, height, "rect", name or rows[0])
        return self.track(box) if track else box

    def titled(self, x: float, y: float, w: float, title: str, body: Lines = (),
               h: Optional[float] = None, fill: str = "#eff6ff", stroke: str = INK,
               rx: float = 10, size: float = 12.5, title_size: float = 13.5,
               pad: float = 10, sw: float = 1.5, name: str = "", align: str = "middle") -> Box:
        """A node with a bold title line and wrapped body text below it."""
        inner = w - 2 * pad
        title_rows = wrap(title, inner, title_size, True)
        paragraphs = [body] if isinstance(body, str) else list(body)
        body_rows: List[str] = []
        for para in paragraphs:
            body_rows += wrap(para, inner, size)
        rows = title_rows + body_rows
        szs = [title_size] * len(title_rows) + [size] * len(body_rows)
        bolds = [True] * len(title_rows) + [False] * len(body_rows)
        heights = [s * 1.32 for s in szs]
        height = h if h is not None else math.ceil(sum(heights) + 2 * pad - 2)
        self.rect(x, y, w, height, fill, stroke, sw, rx)
        if align == "middle":
            self.text_block(x + w / 2, y + height / 2, rows, size, bolds, None, INK, "node",
                            inner, szs)
        else:
            ty = y + height / 2 - sum(heights) / 2
            for row, s, b, hh in zip(rows, szs, bolds, heights):
                self.text(x + pad, ty + hh / 2 + s * 0.36, row, s, b, maxw=inner)
                ty += hh
        return self.track(Box(x, y, w, height, "rect", name or title))

    def decision(self, cx: float, cy: float, w: float, h: float, lines: Lines,
                 fill: str = "#fef9c3", size: float = 12.5, name: str = "",
                 bold: bool = False) -> Box:
        """A decision (or merge) diamond with centred text."""
        rows = as_lines(lines)
        self.polygon([(cx - w / 2, cy), (cx, cy - h / 2), (cx + w / 2, cy), (cx, cy + h / 2)],
                     fill, INK, 1.5)
        lh = size * 1.3
        y0 = cy - len(rows) * lh / 2
        maxws = []
        for i in range(len(rows)):
            mid = y0 + (i + 0.5) * lh
            edge = max(abs(mid - lh / 2 - cy), abs(mid + lh / 2 - cy))
            maxws.append(max(0.0, w * (1 - edge / (h / 2)) - 6))
        if rows and rows != [""]:
            self.text_block(cx, cy, rows, size, bold, lh, INK, "node", maxws)
        return self.track(Box(cx - w / 2, cy - h / 2, w, h, "diamond", name or " ".join(rows)))

    def initial(self, cx: float, cy: float, r: float = 9) -> Box:
        self.ellipse(cx, cy, r, r, INK, INK, 1)
        return self.track(Box(cx - r, cy - r, 2 * r, 2 * r, "ellipse", "initial"))

    def final(self, cx: float, cy: float, r: float = 12) -> Box:
        """Activity final node (bull's-eye)."""
        self.ellipse(cx, cy, r, r, PAPER, INK, 1.8)
        self.ellipse(cx, cy, r - 5, r - 5, INK, INK, 1)
        return self.track(Box(cx - r, cy - r, 2 * r, 2 * r, "ellipse", "final"))

    def flow_final(self, cx: float, cy: float, r: float = 11) -> Box:
        """Flow final node (circle with a cross): this flow ends, the activity goes on."""
        self.ellipse(cx, cy, r, r, PAPER, INK, 1.8)
        k = r * 0.7071
        self.line((cx - k, cy - k), (cx + k, cy + k), INK, 1.8)
        self.line((cx - k, cy + k), (cx + k, cy - k), INK, 1.8)
        return self.track(Box(cx - r, cy - r, 2 * r, 2 * r, "ellipse", "flow final"))

    def bar(self, x: float, y: float, w: float, h: float = 7, name: str = "bar") -> Box:
        """Fork / join bar."""
        self.rect(x, y, w, h, INK, INK, 1, 2)
        return self.track(Box(x, y, w, h, "rect", name))

    def usecase(self, cx: float, cy: float, rx: float, ry: float, lines: Lines,
                tag: str = "", fill: str = "#eff6ff", size: float = 13.5,
                tag_size: float = 12, tag_fill: str = MUTED, name: str = "",
                sw: float = 1.6) -> Box:
        """A use case: an ellipse with its name (bold) and an optional tag line."""
        rows = as_lines(lines)
        self.ellipse(cx, cy, rx, ry, fill, INK, sw)
        all_rows = rows + ([tag] if tag else [])
        szs = [size] * len(rows) + ([tag_size] if tag else [])
        bolds = [True] * len(rows) + ([False] if tag else [])
        fills = [INK] * len(rows) + ([tag_fill] if tag else [])
        heights = [s * 1.3 for s in szs]
        y0 = cy - sum(heights) / 2
        maxws = []
        for hh in heights:
            edge = max(abs(y0 - cy), abs(y0 + hh - cy))
            maxws.append(2 * rx * math.sqrt(max(0.0, 1 - (edge / ry) ** 2)) - 8)
            y0 += hh
        self.text_block(cx, cy, all_rows, size, bolds, None, fills, "node", maxws, szs)
        return self.track(Box(cx - rx, cy - ry, 2 * rx, 2 * ry, "ellipse", name or " ".join(rows)))

    def actor(self, cx: float, y: float, name: Lines, sub: Lines = (), size: float = 14,
              scale: float = 1.0, label: str = "below") -> Box:
        """A UML actor (stick figure). `label` puts the name below, left or right of
        the figure. Returns the figure's box (the name is not part of it)."""
        s = scale
        head_r = 11 * s
        neck = y + 2 * head_r
        hip = neck + 26 * s
        foot = hip + 22 * s
        self.ellipse(cx, y + head_r, head_r, head_r, PAPER, INK, 1.8)
        self.line((cx, neck), (cx, hip), INK, 1.8)
        self.line((cx - 17 * s, neck + 9 * s), (cx + 17 * s, neck + 9 * s), INK, 1.8)
        self.line((cx, hip), (cx - 14 * s, foot), INK, 1.8)
        self.line((cx, hip), (cx + 14 * s, foot), INK, 1.8)
        names, subs = as_lines(name), as_lines(sub)
        if label == "below":
            tx, anchor = cx, "middle"
            ty = foot + 8
        else:
            anchor = "end" if label == "left" else "start"
            tx = cx - 30 * s if label == "left" else cx + 30 * s
            total = len(names) * size * 1.25 + len(subs) * 12 * 1.3
            ty = (y + foot) / 2 - total / 2 - 3
        for row in names:
            ty += size * 1.25
            self.text(tx, ty, row, size, True, anchor=anchor)
        for row in subs:
            ty += 12 * 1.3
            self.text(tx, ty, row, 12, anchor=anchor, fill=MUTED)
        box = Box(cx - 20 * s, y, 40 * s, foot - y, "rect", " ".join(names))
        return self.track(box)

    def chip(self, x: float, y: float, label: str, fill: str = "#e2e8f0", color: str = INK,
             size: float = 12, h: float = 20, pad: float = 7, layer: str = "node",
             stroke: str = "none") -> float:
        """A small rounded tag; returns its width."""
        width = math.ceil(text_width(label, size, True) + 2 * pad)
        self.rect(x, y, width, h, fill, stroke, 1, h / 2, layer)
        self.text(x + width / 2, y + h / 2 + size * 0.36, label, size, True, anchor="middle",
                  fill=color, layer=layer)
        return width

    def note(self, x: float, y: float, w: float, lines: Lines, size: float = 12,
             fill: str = "#fffbeb", pad: float = 9, bold_first: bool = False,
             track: bool = True) -> Box:
        """A UML note (folded corner) with left-aligned wrapped text."""
        rows: List[str] = []
        for para in as_lines(lines):
            rows += wrap(para, w - 2 * pad - 4, size)
        lh = size * 1.34
        h = math.ceil(len(rows) * lh + 2 * pad - 2)
        fold = 12
        pts = [(x, y), (x + w - fold, y), (x + w, y + fold), (x + w, y + h), (x, y + h)]
        self.polygon(pts, fill, "#92400e", 1.2)
        self.raw(f'<polyline points="{_n(x + w - fold)},{_n(y)} {_n(x + w - fold)},{_n(y + fold)} '
                 f'{_n(x + w)},{_n(y + fold)}" fill="none" stroke="#92400e" stroke-width="1.2"/>')
        ty = y + pad - 1
        for i, row in enumerate(rows):
            ty += lh
            self.text(x + pad, ty - lh * 0.28, row, size, bold_first and i == 0,
                      maxw=w - 2 * pad)
        box = Box(x, y, w, h, "rect", rows[0] if rows else "note")
        return self.track(box) if track else box

    # ------------------------------------------------------------------ edges
    def edge(self, points: Sequence[Point], kind: str = "flow", label: Lines = "",
             lpos: Optional[Point] = None, ends: Sequence[Box] = (), color: str = INK,
             sw: float = 1.6, lsize: float = 12, lbold: bool = False, radius: float = 8,
             name: str = "", lfill: str = INK, lbg: bool = True, check: bool = True) -> None:
        """A connector through `points`.

        kind: flow  solid line, filled arrowhead        (control flow)
              msg   dashed line, open arrowhead          (message / dependency)
              gen   solid line, hollow triangle at end   (generalisation)
              comp  solid line, filled diamond at START  (composition: owner first)
              assoc solid line, open arrowhead           (navigable association)
              line  solid line, no arrowhead             (association)
              dline dashed line, no arrowhead
        """
        pts = _clean(points)
        if len(pts) < 2:
            self.problems.append(f"edge {name or label!r} has fewer than two points")
            return
        dashed = kind in ("msg", "dline")
        start_cut = 15.0 if kind == "comp" else 0.0
        end_cut = 13.0 if kind == "gen" else 0.0
        a0, a1 = pts[0], pts[1]
        z0, z1 = pts[-2], pts[-1]
        u_start, u_end = _unit(a0, a1), _unit(z0, z1)
        draw = list(pts)
        if start_cut:
            draw[0] = (a0[0] + u_start[0] * start_cut, a0[1] + u_start[1] * start_cut)
        if end_cut:
            draw[-1] = (z1[0] - u_end[0] * end_cut, z1[1] - u_end[1] * end_cut)
        d = [f"M{_n(draw[0][0])},{_n(draw[0][1])}"]
        for i in range(1, len(draw) - 1):
            prev, cur, nxt = draw[i - 1], draw[i], draw[i + 1]
            r = min(radius, math.dist(prev, cur) / 2, math.dist(cur, nxt) / 2)
            u_in, u_out = _unit(prev, cur), _unit(cur, nxt)
            p_in = (cur[0] - u_in[0] * r, cur[1] - u_in[1] * r)
            p_out = (cur[0] + u_out[0] * r, cur[1] + u_out[1] * r)
            d.append(f"L{_n(p_in[0])},{_n(p_in[1])} Q{_n(cur[0])},{_n(cur[1])} "
                     f"{_n(p_out[0])},{_n(p_out[1])}")
        d.append(f"L{_n(draw[-1][0])},{_n(draw[-1][1])}")
        attrs = (f'd="{" ".join(d)}" fill="none" stroke="{color}" stroke-width="{_n(sw)}" '
                 f'stroke-linecap="round" stroke-linejoin="round"')
        if dashed:
            attrs += ' stroke-dasharray="6 4"'
        self.raw(f"<path {attrs}/>", "edge")

        def head(tip: Point, u: Point, length: float, half: float) -> Tuple[Point, Point]:
            bx, by = tip[0] - u[0] * length, tip[1] - u[1] * length
            return ((bx - u[1] * half, by + u[0] * half), (bx + u[1] * half, by - u[0] * half))

        if kind == "flow":
            p, q = head(z1, u_end, 10, 4.2)
            self.polygon([z1, p, q], color, color, 1, "edge")
        elif kind in ("msg", "assoc"):
            p, q = head(z1, u_end, 10, 4.6)
            self.raw(f'<polyline points="{_n(p[0])},{_n(p[1])} {_n(z1[0])},{_n(z1[1])} '
                     f'{_n(q[0])},{_n(q[1])}" fill="none" stroke="{color}" '
                     f'stroke-width="{_n(sw)}" stroke-linecap="round" stroke-linejoin="round"/>',
                     "edge")
        elif kind == "gen":
            p, q = head(z1, u_end, 13, 7.5)
            self.polygon([z1, p, q], PAPER, color, sw, "edge")
        elif kind == "comp":
            mid = (a0[0] + u_start[0] * 7.5, a0[1] + u_start[1] * 7.5)
            far = (a0[0] + u_start[0] * 15, a0[1] + u_start[1] * 15)
            side_a = (mid[0] - u_start[1] * 5, mid[1] + u_start[0] * 5)
            side_b = (mid[0] + u_start[1] * 5, mid[1] - u_start[0] * 5)
            self.polygon([a0, side_a, far, side_b], color, color, 1, "edge")
        for i in range(len(pts) - 1):
            if check:
                self.segments.append((pts[i], pts[i + 1], tuple(ends), name or str(label)))
        if label:
            rows = as_lines(label)
            if lpos is None:
                best = max(range(len(pts) - 1), key=lambda i: math.dist(pts[i], pts[i + 1]))
                lpos = ((pts[best][0] + pts[best + 1][0]) / 2, (pts[best][1] + pts[best + 1][1]) / 2)
            self.label(lpos[0], lpos[1], rows, lsize, lbold, lfill, lbg, name or " ".join(rows))

    def label(self, cx: float, cy: float, lines: Lines, size: float = 12, bold: bool = False,
              fill: str = INK, bg: bool = True, name: str = "", check: bool = True) -> None:
        """Free text centred on (cx, cy) with a white backing, drawn above connectors."""
        rows = as_lines(lines)
        width = max(text_width(r, size, bold) for r in rows)
        lh = size * 1.28
        height = len(rows) * lh
        rect = (cx - width / 2 - 4, cy - height / 2 - 1.5, width + 8, height + 3)
        if bg:
            self.raw(f'<rect x="{_n(rect[0])}" y="{_n(rect[1])}" width="{_n(rect[2])}" '
                     f'height="{_n(rect[3])}" rx="3" fill="{PAPER}" fill-opacity="0.94" '
                     f'stroke="none"/>', "label")
        self.text_block(cx, cy, rows, size, bold, lh, fill, "label")
        if check:
            self.labels.append((rect, name or " ".join(rows)))

    # ------------------------------------------------------------------ output
    def check(self) -> List[str]:
        """Layout problems: overlapping nodes, connectors through nodes, label clashes."""
        out = list(self.problems)
        nodes = self.nodes
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                if _rects_overlap((a.x, a.y, a.w, a.h), (b.x, b.y, b.w, b.h), -1.0):
                    out.append(f"nodes overlap: {a.name!r} and {b.name!r}")
            if a.x < 0 or a.y < 0 or a.right > self.w or a.bottom > self.h:
                out.append(f"node outside the canvas: {a.name!r}")
        for p, q, ends, name in self.segments:
            for box in nodes:
                if any(box is e for e in ends):
                    continue
                if _seg_hits_box(p, q, box):
                    out.append(f"connector {name!r} runs through node {box.name!r}")
        for i, (ra, na) in enumerate(self.labels):
            for box in nodes:
                if _rects_overlap(ra, (box.x, box.y, box.w, box.h), -2.0) and box.shape == "rect":
                    out.append(f"label {na!r} overlaps node {box.name!r}")
                elif box.shape != "rect" and any(
                        box.contains(c, 1.0) for c in ((ra[0], ra[1]), (ra[0] + ra[2], ra[1]),
                                                       (ra[0], ra[1] + ra[3]),
                                                       (ra[0] + ra[2], ra[1] + ra[3]))):
                    out.append(f"label {na!r} overlaps node {box.name!r}")
            for rb, nb in self.labels[i + 1:]:
                if _rects_overlap(ra, rb, -1.0):
                    out.append(f"labels overlap: {na!r} and {nb!r}")
            if ra[0] < 0 or ra[1] < 0 or ra[0] + ra[2] > self.w or ra[1] + ra[3] > self.h:
                out.append(f"label outside the canvas: {na!r}")
        seen, unique = set(), []
        for item in out:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    def svg(self, standalone: bool = True) -> str:
        """The drawing as SVG text. `standalone` adds the XML declaration."""
        tid, did = f"{self.ident}-title", f"{self.ident}-desc"
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" id="{self.ident}" '
                f'width="{_n(self.w)}" height="{_n(self.h)}" viewBox="0 0 {_n(self.w)} {_n(self.h)}" '
                f'role="img" aria-labelledby="{tid} {did}" font-family="{FONT}">')
        parts = ['<?xml version="1.0" encoding="UTF-8"?>'] if standalone else []
        parts += [head, f'<title id="{tid}">{escape(self.title_text)}</title>',
                  f'<desc id="{did}">{escape(self.desc or self.subtitle_text)}</desc>',
                  f'<rect x="0" y="0" width="{_n(self.w)}" height="{_n(self.h)}" fill="{PAPER}"/>']
        for layer in self.LAYERS:
            if self._layers[layer]:
                parts.append(f'<g id="{self.ident}-{layer}">')
                parts += self._layers[layer]
                parts.append("</g>")
        parts.append("</svg>")
        return "\n".join(parts) + "\n"
