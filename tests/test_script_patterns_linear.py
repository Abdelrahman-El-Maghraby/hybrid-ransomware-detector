"""H5: the script layer's character-code patterns run in linear time and match
exactly what the original patterns matched.

Before the fix, adjacent ``\\s*`` in ``_PSCHAR_RUN`` and ``_CHR_RUN`` could split
one white-space run in many ways. ``[char]65`` and a run of spaces, three times,
then any other character took 14 s at 109 bytes (about the sixth power of the
run length), so a ~165-byte script held a worker until the scan time limit."""

import random
import re
import time

import pytest

from detectors import script_analysis as S
from detectors.script_analysis import ScriptAnalyzer, ScriptResult

# The exact patterns used before the change: the reference.
OLD_CHR_RUN = re.compile(r"(?:chrw?\s*\(\s*\d{1,5}\s*\)\s*(?:&|\+)?\s*(?:_\s*\r?\n\s*)?){4,}", re.I)
OLD_PSCHAR_RUN = re.compile(r"(?:\[char\]\s*\(?\s*\d{1,5}\s*\)?\s*\+?\s*){4,}", re.I)
OLD_PSCHAR_ONE = re.compile(r"\[char\]\s*\(?\s*(\d{1,5})", re.I)

TOKENS = ["chr(", "Chr (", "ChrW(", "chrw ", "[char]", "[CHAR] ", "(", ")", " ", "  ", "\t",
          "\n", "\r\n", "\r", "\f", "_", " _", "&", "+", "65", "104", "123456", "x", ",", "'",
          '"', "[char[]]", "chr(72)", "[char]0x41", "\v"]


WS = [" ", "\t", "\n", "\r\n", "\r", "\f", "\v"]


def _spans(rx, text):
    return [m.span() for m in rx.finditer(text)]


def _ws(rng):
    return "".join(rng.choice(WS) for _ in range(rng.choice([0, 0, 1, 2, 3])))


def _runlike(rng):
    """Near-runs: 1-6 tokens with random white space, optional parts and noise."""
    out = []
    family = rng.choice([["chr", "Chr", "ChrW"], ["[char]", "[CHAR]"]])
    for _ in range(rng.randint(1, 6)):
        head = rng.choice(family)
        paren = head.startswith("[") and rng.random() < 0.5
        parts = [head, _ws(rng), "(" if not head.startswith("[") or paren else "", _ws(rng),
                 rng.choice(["65", "104", "123456", "65", "x"]), _ws(rng),
                 ")" if not head.startswith("[") or paren else rng.choice(["", ")"]), _ws(rng),
                 rng.choice(["", "", "&", "+"]), _ws(rng), rng.choice(["", "", "_"]), _ws(rng)]
        if rng.random() < 0.05:                      # mutate one part
            parts[rng.randrange(len(parts))] = rng.choice(TOKENS)
        out.append("".join(parts))
    return "".join(out) + rng.choice(["", "x", ";", rng.choice(TOKENS)])


@pytest.mark.parametrize("old, new", [
    (OLD_CHR_RUN, S._CHR_RUN), (OLD_PSCHAR_RUN, S._PSCHAR_RUN), (OLD_PSCHAR_ONE, S._PSCHAR_ONE),
])
def test_random_inputs_match_the_original_patterns(old, new):
    rng = random.Random(4805)
    matched = 0
    for i in range(30_000):
        if i % 3:
            text = _runlike(rng)
        else:
            text = "".join(rng.choice(TOKENS) for _ in range(rng.randint(0, 40)))
        assert _spans(new, text) == _spans(old, text), repr(text)
        assert new.findall(text) == old.findall(text), repr(text)
        matched += bool(old.search(text))
    assert matched > 100                             # the comparison is not vacuous


def test_real_obfuscation_still_decodes():
    vb = 'x = Chr(104) & Chr(105) & _\r\n    Chr(33) & Chr(33)'
    ps = "$a = [char]72 + [char](105) + [char] 33 +[char]33"
    assert "hi!!" in S._t_char_codes(vb)
    assert "Hi!!" in S._t_char_codes(ps)


@pytest.mark.parametrize("token", ["[char]65", "[char](65)", "chr(65)", "ChrW(65) &", "chr(65) _\n"])
@pytest.mark.parametrize("gap", [" ", "\n", " \n "])
def test_hostile_char_code_runs_are_linear(token, gap):
    # Three tokens and a long white-space run each, then a failure: the H5 shape.
    unit = (token + gap * 2000) * 3 + "x"
    raw = (unit * (100_000 // len(unit) + 1)).encode()
    start = time.perf_counter()
    ScriptAnalyzer().analyze_bytes(raw, ScriptResult(is_script=True, language="PowerShell"))
    assert time.perf_counter() - start < 5        # the old patterns needed hours


# ---------------------------------------------------------------- M22 (script)
# Script Encoder blocks and the string-literal patterns: same results as the old
# patterns, linear time on the shapes of PROJECT_REVIEW check 3.
_OLD_STR = r"(?:\"((?:[^\"\\\n]|\\.){1,20000})\"|'((?:[^'\\\n]|\\.){1,20000})')"
OLD_SE_BLOCK = re.compile(r"#@~\^[A-Za-z0-9+/]{6}==(.*?)[A-Za-z0-9+/]{6}==\^#~@", re.S)
OLD_REVERSE_JS = re.compile(
    _OLD_STR + r"\s*\.split\(\s*(?:\"\"|'')\s*\)\s*\.reverse\(\s*\)\s*\.join\(", re.I)
OLD_REPLACE_DOT = re.compile(
    _OLD_STR + r"\s*\.replace\s*\(\s*" + _OLD_STR + r"\s*,\s*(?:\"\"|'')\s*\)", re.I)

LIT_TOKENS = ['"', "'", "\\", '\\"', "\\'", "\\\\", "\n", "\r", " ", "a", "Z", "1", ".",
              '.split("").reverse().join(', ".split('') . reverse( ) .JOIN(",
              '.replace(', " . Replace ( ", ', "")', ",'' )", ",", '""', "''", ")", "(",
              '"abc"', "'x\\'y'", "é"]
SE_TOKENS = ["#@~^", "AAAAAA==", "ab+/9Z==", "^#~@", "#@~^AAAAAA==", "AAAAAA==^#~@", "x",
             "\n", "@&", "=", "^", "#", "~", "@"]


def _old_literals(text):
    rev = [S._lit(m) for m in OLD_REVERSE_JS.finditer(text)]
    rep = [(S._lit(m, 1), S._lit(m, 3)) for m in OLD_REPLACE_DOT.finditer(text)]
    return rev, rep


def _new_literals(text):
    return ([a for a, _ in S._literal_matches(text, "reverse")],
            S._literal_matches(text, "replace"))


def test_literal_matching_equals_the_original_patterns():
    rng = random.Random(4822)
    matched = 0
    for _ in range(30_000):
        text = "".join(rng.choice(LIT_TOKENS) for _ in range(rng.randint(0, 30)))
        old = _old_literals(text)
        assert _new_literals(text) == old, repr(text)
        matched += bool(old[0] or old[1])
    assert matched > 100


def test_literal_unit_cap_is_kept():
    for n in (19_999, 20_000, 20_001):
        for text in ('"' + "a" * n + '".split("").reverse().join(',
                     '"' + "\\x" * n + '".replace("x", "")'):
            assert _new_literals(text) == _old_literals(text), (n, text[:3])


def test_script_encoder_blocks_equal_the_original_pattern():
    rng = random.Random(4823)
    matched = 0
    for _ in range(30_000):
        text = "".join(rng.choice(SE_TOKENS) for _ in range(rng.randint(0, 20)))
        old = [m.group(1) for m in OLD_SE_BLOCK.finditer(text)]
        assert list(S._se_bodies(text)) == old, repr(text)
        matched += bool(old)
    assert matched > 100


@pytest.mark.parametrize("head, unit, size", [
    ("", "#@~^AAAAAA==", 700_000),       # Script Encoder starts, no end marker
    ('"', '\\"', 1_000_000),             # a quote, then escaped quotes
    ("'", "\\'", 1_000_000),
    ('"', "\\'", 1_000_000),             # escaped quotes of the other kind
])
def test_hostile_script_text_is_linear(head, unit, size):
    raw = (head + unit * (size // len(unit))).encode()
    start = time.perf_counter()
    ScriptAnalyzer().analyze_bytes(raw, ScriptResult(is_script=True, language="JScript"))
    assert time.perf_counter() - start < 10    # the old patterns needed minutes
