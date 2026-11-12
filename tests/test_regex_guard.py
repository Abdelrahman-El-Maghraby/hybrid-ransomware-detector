"""I-5: every module-level compiled pattern of `detectors/` stays fast on
hostile shapes, so a fourth slow pattern (after H2, H-04 and H5/M22) fails CI
instead of being found by hand.

Each pattern runs `finditer` over ~20 KB inputs: long runs of one character,
tokens taken from the pattern's own text repeated or followed by long runs, and
the H5 shape (token, long white space, three times, then a failure). A regular
expression engine cannot be interrupted, so the work runs in a child process
with a hard time limit; the parent names the last pattern and shape started.
Inline `re.search(...)` calls inside functions are not covered."""

import importlib
import json
import os
import pkgutil
import re
import subprocess
import sys
import time
from pathlib import Path

SIZE = 20_000
PER_CALL = 0.5          # seconds; linear patterns need about a millisecond here
TOTAL = 240             # seconds for the child process

# Patterns the child skips, with the reason (H-04+ entries removed when it was
# fixed, so the guard covers the web-content patterns too).
_ANCHORED = ("used only with match() at positions its caller bounds; the caller "
             "has its own linear-time test")
KNOWN_SLOW = {
    "embedded_content._JS_FUNCTION_TAIL": _ANCHORED,      # _looks_js
    "mail_analyzer._DOMAIN_CHAIN": _ANCHORED,             # _first_domain (H2)
    "mail_analyzer._DOMAIN_IN_TEXT": _ANCHORED,           # _first_domain (H2)
    "mail_analyzer._TAG": "used only through _strip_tags (H2), which cuts the text after "
                          "the last '>', so every match runs to its own '>'",
    "script_analysis._REPLACE_DOT_MID": _ANCHORED,        # _literal_matches
    "script_analysis._REPLACE_DOT_TAIL": _ANCHORED,       # _literal_matches
    "script_analysis._REVERSE_JS_TAIL": _ANCHORED,        # _literal_matches
}

GENERIC = [" ", "\n", "\t", "a", "A", "1", ".", "a.", "-", "_", "/", "\\", "=", ":", "<", ">",
           "<a", "\"", "'", "%", "&", "(", ")", "[", "#", "@", "x ", "é",
           # shapes of earlier findings: escaped quotes (M22), Script Encoder
           # starts (M22), unclosed anchors (H2)
           "\\\"", "\\'", "#@~^AAAAAA==", "<a href='x'>y"]
FILLERS = ["65", "(65)", "(65)&", "(65)_\n"]      # what follows a token in the H5 shape
WS = [" ", "\n", " \n"]
_WORD = re.compile(r"(?<!\\)\b[A-Za-z][A-Za-z_-]{2,}")
_BRACKET = re.compile(r"\\\[([A-Za-z]+)\\\]")


def _patterns():
    import detectors
    found = {}

    def walk(obj, name, depth=0):
        if isinstance(obj, re.Pattern):
            found.setdefault(id(obj), (name, obj))
        elif depth < 2 and isinstance(obj, (tuple, list)):
            for i, x in enumerate(obj):
                walk(x, f"{name}[{i}]", depth + 1)
        elif depth < 2 and isinstance(obj, dict):
            for k, x in obj.items():
                walk(x, f"{name}[{k!r}]", depth + 1)

    for info in pkgutil.iter_modules(detectors.__path__):
        module = importlib.import_module("detectors." + info.name)
        for key, value in vars(module).items():
            walk(value, f"{info.name}.{key}")
    return sorted(found.values(), key=lambda item: item[0])


def _shapes(pattern):
    source = pattern.pattern
    if isinstance(source, bytes):
        source = source.decode("latin-1")
    tokens = sorted({m.group(0) for m in _WORD.finditer(source)}
                    | {f"[{m.group(1)}]" for m in _BRACKET.finditer(source)})[:12]
    shapes = [("run", unit, unit * (SIZE // len(unit))) for unit in GENERIC]
    for tok in tokens:
        shapes.append(("repeat", tok, tok * (SIZE // len(tok))))
        for ws in WS:
            gap = ws * (SIZE // (6 * len(ws)))
            shapes.append(("tail", tok + repr(ws), tok + gap * 6))
            for filler in FILLERS:
                shapes.append(("h5", tok + filler + repr(ws), (tok + filler + gap) * 3 + "\x00"))
    return shapes


def _child():
    """Runs in the child: one JSON line before and after every call."""
    for name, rx in _patterns():
        if name in KNOWN_SLOW:
            continue
        for kind, label, text in _shapes(rx):
            data = text.encode("utf-8") if isinstance(rx.pattern, bytes) else text
            print(json.dumps({"start": name, "shape": f"{kind}:{label}"}), flush=True)
            t = time.perf_counter()
            for _ in rx.finditer(data):
                pass
            print(json.dumps({"done": name, "shape": f"{kind}:{label}",
                              "s": time.perf_counter() - t}), flush=True)
    print(json.dumps({"finished": True}), flush=True)


def test_every_detector_pattern_is_fast_on_hostile_shapes():
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(
            [sys.executable, "-B", "-c", "import tests.test_regex_guard as g; g._child()"],
            cwd=root, env=env, capture_output=True, text=True, timeout=TOTAL)
        out, timed_out = proc.stdout, False
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        timed_out = True
    lines = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    slow = sorted({(r["done"], r["shape"], round(r["s"], 2)) for r in lines
                   if "done" in r and r["s"] > PER_CALL})
    if timed_out or not (lines and lines[-1].get("finished")):
        last = next((r for r in reversed(lines) if "start" in r), {})
        raise AssertionError(f"pattern did not finish (timed out: {timed_out}): {last}; "
                             f"slow so far: {slow}; stderr: {getattr(proc, 'stderr', '')[-500:]}")
    assert not slow, slow
    assert sum(1 for r in lines if "done" in r) > 1000      # the patterns were found
