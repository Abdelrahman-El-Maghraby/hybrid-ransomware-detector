"""
Static triage of Windows script attachments: JavaScript / JScript, VBScript,
HTA, WSF, PowerShell and batch files.

WHY THIS EXISTS
---------------
After Office macros were blocked by default for files from the internet, script
files became one of the most common first stages: a `.js` or `.vbs` in a ZIP,
an `.hta` opened by mshta, a `.ps1` or `.bat` launched by a shortcut. Windows
runs them with a double-click (wscript / mshta / cmd), and their job is nearly
always the same: download the next stage and run it, sometimes after turning
off defences or deleting backups.

WHAT IS CHECKED (nothing is executed)
-------------------------------------
Behaviour markers on the script text, in categories:

* download        - XMLHTTP / WinHttp / ADODB.Stream, WebClient, Invoke-WebRequest,
                    BITS, certutil -urlcache, curl/wget to a URL
* execute         - WScript.Shell Run/Exec, ShellExecute, Start-Process,
                    Invoke-Expression, powershell -enc, mshta/rundll32/regsvr32,
                    WMI process creation
* recovery        - shadow-copy deletion, boot recovery disabled, backup catalogue
                    deleted (MITRE T1490: what ransomware does right before it encrypts)
* ransom_note     - ransom-note wording
* defence_evasion - Defender switched off or excluded, AMSI bypass
* persistence     - Run keys, scheduled tasks, the Startup folder

Obfuscation markers (eval/Execute, long Chr()/fromCharCode chains, string
reversal, PowerShell backtick and -join [char] tricks, Script Encoder `#@~^`
output). PowerShell `-EncodedCommand` payloads and `FromBase64String('...')`
literals are decoded one level and analysed together with the outer script.

A download alone or an execute alone is common in admin scripts; the scoring
gives the combination (a dropper) far more weight than either part.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple, Union

PathLike = Union[str, Path]

SCRIPT_EXTENSIONS = frozenset({".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
                               ".ps1", ".psm1", ".bat", ".cmd"})
_LANG = {".js": "JScript", ".jse": "JScript (encoded)", ".vbs": "VBScript",
         ".vbe": "VBScript (encoded)", ".wsf": "Windows Script File", ".wsh": "Windows Script File",
         ".hta": "HTML Application", ".ps1": "PowerShell", ".psm1": "PowerShell",
         ".bat": "batch", ".cmd": "batch"}

MAX_READ = 5 * 1024 * 1024
MAX_DECODED = 1024 * 1024

_I = re.I

# (category, patterns as (label, regex)); one distinct marker is enough per category.
_MARKERS = [
    ("download", [
        ("XMLHTTP / WinHttp request object", r"msxml2\.(?:server)?xmlhttp|microsoft\.xmlhttp|winhttp\.winhttprequest"),
        ("ADODB.Stream saved to disk", r"adodb\.stream[\s\S]{0,400}savetofile|savetofile[\s\S]{0,400}adodb\.stream"),
        ("WebClient download", r"net\.webclient[\s\S]{0,200}download(?:file|string|data)|\$\w+\.download(?:file|string|data)\s*\("),
        ("Invoke-WebRequest / Invoke-RestMethod", r"\binvoke-(?:webrequest|restmethod)\b|\biwr\s+(?:-uri\s+)?['\"]?https?://"),
        ("BITS transfer", r"bitsadmin\s+/transfer|start-bitstransfer"),
        ("certutil download", r"certutil(?:\.exe)?\s+[^\n]{0,40}-urlcache"),
        ("curl / wget to a URL", r"\b(?:curl|wget)(?:\.exe)?\s+[^\n]{0,60}https?://"),
    ]),
    ("execute", [
        ("WScript.Shell Run/Exec", r"wscript\.shell[\s\S]{0,300}\.(?:run|exec)\b|\.(?:run|exec)\b[\s\S]{0,300}wscript\.shell"),
        ("Shell.Application ShellExecute", r"shell\.application[\s\S]{0,300}shellexecute"),
        ("Start-Process", r"\bstart-process\b"),
        ("Invoke-Expression (IEX)", r"\binvoke-expression\b|\biex\s*[\(\$'\"]|\|\s*iex\b"),
        ("PowerShell with an encoded command", r"powershell(?:\.exe)?[^\n]{0,80}\s-(?:e|en|enc|encodedcommand)\s+[a-z0-9+/=]{20,}"),
        ("LOLBin launcher (mshta / rundll32 / regsvr32)", r"\b(?:mshta|rundll32|regsvr32)(?:\.exe)?\s+[^\n]{0,80}(?:https?://|\.dll|javascript:|/i:|scrobj)"),
        ("WMI process creation", r"win32_process[\s\S]{0,200}\.?create\b|wmic\s+process\s+call\s+create"),
    ]),
    ("recovery", [
        ("shadow copies deleted", r"vssadmin(?:\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|win32_shadowcopy[\s\S]{0,200}delete"),
        ("boot recovery disabled", r"bcdedit[^\n]{0,60}recoveryenabled\s+no|bcdedit[^\n]{0,60}bootstatuspolicy\s+ignoreallfailures"),
        ("backup catalogue deleted", r"wbadmin\s+delete\s+(?:catalog|systemstatebackup)"),
    ]),
    ("ransom_note", [
        ("ransom-note wording", r"your (?:important )?(?:files|data|documents)[^\n]{0,60}(?:been )?(?:encrypted|locked)"
                                r"|(?:pay|send)[^\n]{0,40}(?:bitcoin|btc|monero|xmr)[^\n]{0,40}(?:decrypt|key|files)"),
    ]),
    ("defence_evasion", [
        ("Defender real-time protection disabled", r"set-mppreference[^\n]{0,80}-disable(?:realtimemonitoring|ioavprotection|behaviormonitoring)"),
        ("Defender exclusion added", r"add-mppreference[^\n]{0,40}-exclusion(?:path|process|extension)"),
        ("AMSI bypass", r"amsiutils|amsiinitfailed|amsiscanbuffer"),
    ]),
    ("persistence", [
        ("Run key", r"currentversion\\run(?:once)?\b"),
        ("scheduled task", r"schtasks(?:\.exe)?\s+/create|register-scheduledtask|new-scheduledtask"),
        ("Startup folder", r"\\start menu\\programs\\startup|specialfolders\s*\(\s*['\"]startup"),
    ]),
]
_COMPILED = [(cat, [(label, re.compile(rx, _I)) for label, rx in pats]) for cat, pats in _MARKERS]

_OBFUSCATION = [
    ("eval / Execute of built strings", re.compile(r"\beval\s*\(|\bexecute(?:global)?\s*[\(\s]", _I)),
    ("long Chr() chain", re.compile(r"(?:chrw?\s*\(\s*\d+\s*\)\s*[&+]\s*){20,}", _I)),
    ("long String.fromCharCode", re.compile(r"fromcharcode\s*\((?:\s*\d+\s*,){20,}", _I)),
    ("string reversal", re.compile(r"strreverse\s*\(|\.split\(\s*['\"]['\"]\s*\)\.reverse\(\)", _I)),
    ("PowerShell backtick obfuscation", re.compile(r"(?:\w`\w[\w`]*){3,}")),
    ("-join of [char] codes", re.compile(r"\[char\[\]\]\s*\(|-join\s*\(\s*\[char\]|\[char\]\s*\d+\s*\+\s*\[char\]", _I)),
    ("hidden / bypassed PowerShell", re.compile(r"-w(?:indowstyle)?\s+hidden[\s\S]{0,120}-(?:ep|exec|executionpolicy)\s+bypass"
                                              r"|-(?:ep|exec|executionpolicy)\s+bypass[\s\S]{0,120}-w(?:indowstyle)?\s+hidden", _I)),
    ("long base64 literal", re.compile(r"['\"][a-z0-9+/]{400,}={0,2}['\"]", _I)),
]
_ENCODED_SCRIPT = re.compile(rb"#@~\^[A-Za-z0-9+/]{6}==")
_PS_ENC = re.compile(r"\s-(?:e|en|enc|encodedcommand)\s+([a-z0-9+/]{20,}={0,2})", _I)
_FROM_B64 = re.compile(r"frombase64string\s*\(\s*['\"]([a-z0-9+/]{16,}={0,2})['\"]", _I)
_URL = re.compile(r"https?://[^\s'\"<>)]{4,200}", _I)


# ---------------------------------------------------------------- Script Encoder
# Windows Script Encoder (screnc) output, as in .vbe / .jse files and encoded
# blocks inside .hta / .wsf. The substitution table and the 64-step selector
# below are the published decoding tables (Didier Stevens, decode-vbe.py, public
# domain). Row r gives the plain character for codes 9 and 32..127 when the
# selector picks r.
_SE_CODES = [9] + list(range(32, 128))
_SE_ROWS = (
    'W.GzVBj/&IA42[vrC89pEhqO\tbD#uJ~J^@wJa]"KoN;LPg*}tT+-,0nkf5%!dMRc?{x)(sY3\x7fmUS|:_eFX1ilZH\'\\=$y7`Q 6',
    'n-uR`q^I\\b})6 |z\x7fkc3+hQfv1dTCL:L~LE,*t\'7DyY/o&rj9{?8wgSG4x]0#Z[lHUpi.L!$NP\tVs5aKX;W"mM%(FJ2A=_OBe',
    '{20!)[83=X:5e9\\VsfNEkbYx^}JmqA`AS@B\'Hru17MR"TjGd- \x7f.L]~loytC&v%$+(#A4\t*D?w;UiacPgQIOFh|6pnz/_KZ,W',
)
_SE_TABLE = {code: tuple(row[i] for row in _SE_ROWS) for i, code in enumerate(_SE_CODES)}
_SE_PICK = "0120121221210212021200122102122100212120200120210212001220012021"
_SE_BLOCK = re.compile(r"#@~\^[A-Za-z0-9+/]{6}==(.*?)[A-Za-z0-9+/]{6}==\^#~@", re.S)
_SE_ESCAPES = (("@&", "\n"), ("@#", "\r"), ("@*", ">"), ("@!", "<"), ("@$", "@"))


def decode_script_encoder(text: str) -> str:
    """Plain source of every Script Encoder block in `text` ('' if there is none)."""
    out = []
    for m in _SE_BLOCK.finditer(text):
        data = m.group(1)
        for esc, plain in _SE_ESCAPES:
            data = data.replace(esc, plain)
        chars, index = [], -1
        for ch in data:
            code = ord(ch)
            if code < 128:
                index += 1
            if (code == 9 or 31 < code < 128) and code not in (60, 62, 64):
                ch = _SE_TABLE[code][int(_SE_PICK[index % 64])]
            chars.append(ch)
        out.append("".join(chars))
    return "\n".join(out)


# ---------------------------------------------------------------- deobfuscation
# Each transform takes a text and returns the texts it can recover from it. The
# analyzer applies every transform to every recovered text again, so layered
# obfuscation (base64 of a Chr() chain of a reversed string ...) is unwound up to
# MAX_LAYERS deep. Nothing is evaluated: only literal patterns are decoded.
MAX_LAYERS = 5
MAX_FRAGMENTS = 64
MAX_TOTAL_DECODED = 4 * 1024 * 1024

_STR = r"(?:\"((?:[^\"\\\n]|\\.){1,20000})\"|'((?:[^'\\\n]|\\.){1,20000})')"
_CONCAT = re.compile(r"([\"'])\s*(?:\+|&)\s*(?:_\s*\r?\n\s*)?\1")
_B64_LITERAL = re.compile(r"[\"']([A-Za-z0-9+/]{40,}={0,2})[\"']")
_ATOB = re.compile(r"\batob\s*\(\s*" + _STR, re.I)
_CHR_RUN = re.compile(r"(?:chrw?\s*\(\s*\d{1,5}\s*\)\s*(?:&|\+)?\s*(?:_\s*\r?\n\s*)?){4,}", re.I)
_CHR_ONE = re.compile(r"chrw?\s*\(\s*(\d{1,5})\s*\)", re.I)
_FROMCC = re.compile(r"fromcharcode\s*\(\s*((?:\d{1,5}\s*,\s*){3,}\d{1,5})\s*\)", re.I)
_PSCHAR_ARR = re.compile(r"\[char\[\]\]\s*\(\s*((?:\d{1,5}\s*,\s*){3,}\d{1,5})\s*\)", re.I)
_PSCHAR_RUN = re.compile(r"(?:\[char\]\s*\(?\s*\d{1,5}\s*\)?\s*\+?\s*){4,}", re.I)
_PSCHAR_ONE = re.compile(r"\[char\]\s*\(?\s*(\d{1,5})", re.I)
_HEX_RUN = re.compile(r"(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){8,}", re.I)
_PCT_RUN = re.compile(r"(?:%[0-9a-f]{2}|%u[0-9a-f]{4}){8,}", re.I)
_REVERSE_VB = re.compile(r"strreverse\s*\(\s*" + _STR, re.I)
_REVERSE_JS = re.compile(_STR + r"\s*\.split\(\s*(?:\"\"|'')\s*\)\s*\.reverse\(\s*\)\s*\.join\(", re.I)
_REPLACE_DOT = re.compile(_STR + r"\s*\.replace\s*\(\s*" + _STR + r"\s*,\s*(?:\"\"|'')\s*\)", re.I)
_REPLACE_VB = re.compile(r"\breplace\s*\(\s*" + _STR + r"\s*,\s*" + _STR + r"\s*,\s*\"\"\s*\)", re.I)
_BACKTICK = re.compile(r"`(?=[a-z])", re.I)


def _lit(m, i=1) -> str:
    return m.group(i) if m.group(i) is not None else (m.group(i + 1) or "")


def _codes_to_text(codes) -> str:
    try:
        return "".join(chr(int(c)) for c in codes if 0 < int(c) < 0x110000)
    except ValueError:
        return ""


def _t_concat(text):
    joined = _CONCAT.sub("", text)
    return [joined] if len(joined) < len(text) - 8 else []


def _t_backticks(text):
    if text.count("`") < 4:
        return []
    clean = _BACKTICK.sub("", text)
    return [clean] if clean != text else []


def _t_base64(text):
    out = []
    for m in _PS_ENC.finditer(text):
        out.append(_decode_b64_text(m.group(1), utf16=True))
    for rx in (_FROM_B64, _B64_LITERAL):
        for m in rx.finditer(text):
            out.append(_decode_b64_text(m.group(1), utf16=False))
    for m in _ATOB.finditer(text):
        out.append(_decode_b64_text(_lit(m), utf16=False))
    return out


def _t_char_codes(text):
    out = [_codes_to_text(_CHR_ONE.findall(m.group(0))) for m in _CHR_RUN.finditer(text)]
    out += [_codes_to_text(re.split(r"\s*,\s*", m.group(1))) for m in _FROMCC.finditer(text)]
    out += [_codes_to_text(re.split(r"\s*,\s*", m.group(1))) for m in _PSCHAR_ARR.finditer(text)]
    out += [_codes_to_text(_PSCHAR_ONE.findall(m.group(0))) for m in _PSCHAR_RUN.finditer(text)]
    return out


def _t_escapes(text):
    out = []
    for m in _HEX_RUN.finditer(text):
        out.append(re.sub(r"\\x([0-9a-f]{2})|\\u([0-9a-f]{4})",
                          lambda e: chr(int(e.group(1) or e.group(2), 16)), m.group(0), flags=re.I))
    for m in _PCT_RUN.finditer(text):
        out.append(re.sub(r"%u([0-9a-f]{4})|%([0-9a-f]{2})",
                          lambda e: chr(int(e.group(1) or e.group(2), 16)), m.group(0), flags=re.I))
    return out


def _t_reverse_replace(text):
    out = [_lit(m)[::-1] for m in _REVERSE_VB.finditer(text)]
    out += [_lit(m)[::-1] for m in _REVERSE_JS.finditer(text)]
    out += [_lit(m, 1).replace(_lit(m, 3), "") for m in _REPLACE_DOT.finditer(text) if _lit(m, 3)]
    out += [_lit(m, 1).replace(_lit(m, 3), "") for m in _REPLACE_VB.finditer(text) if _lit(m, 3)]
    return out


_TRANSFORMS = (_t_concat, _t_backticks, _t_base64, _t_char_codes, _t_escapes, _t_reverse_replace)


def deobfuscate(text: str, max_layers: int = MAX_LAYERS) -> Tuple[List[str], int]:
    """Texts recovered from `text` (not including it) and the deepest layer reached."""
    if _SE_BLOCK.search(text):
        first = decode_script_encoder(text)
        seeds = [first] if first else []
    else:
        seeds = []
    found: List[str] = []
    seen = {hash(text)}
    frontier = [(t, 1) for t in seeds]
    frontier += [(t, 1) for tf in _TRANSFORMS for t in tf(text)]
    depth = total = 0
    while frontier and len(found) < MAX_FRAGMENTS:
        cand, level = frontier.pop(0)
        if not cand or len(cand) < 4 or hash(cand) in seen or level > max_layers:
            continue
        seen.add(hash(cand))
        total += len(cand)
        if total > MAX_TOTAL_DECODED:
            break
        found.append(cand)
        depth = max(depth, level)
        for tf in _TRANSFORMS:
            frontier.extend((t, level + 1) for t in tf(cand))
    return found, depth


@dataclass
class ScriptResult:
    is_script: bool = False
    language: str = ""
    encoded: bool = False                    # Script Encoder output (.vbe / .jse style)
    decoded_layers: int = 0                  # deepest layer of encoding unwound
    decoded_fragments: int = 0               # texts recovered across all layers
    categories: Dict[str, List[str]] = field(default_factory=dict)
    obfuscation: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    truncated: bool = False
    detail: str = ""

    @property
    def dropper(self) -> bool:
        return "download" in self.categories and "execute" in self.categories

    def as_dict(self) -> Dict:
        return {"language": self.language, "encoded": self.encoded,
                "decoded_layers": self.decoded_layers,
                "decoded_fragments": self.decoded_fragments, "behaviour": self.categories,
                "dropper": self.dropper, "obfuscation": self.obfuscation,
                "urls": self.urls[:10], "truncated": self.truncated, "detail": self.detail}


def is_script(path: PathLike) -> bool:
    return Path(path).suffix.lower() in SCRIPT_EXTENSIONS


def _decode_b64_text(blob: str, utf16: bool) -> str:
    blob = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob, validate=True)[:MAX_DECODED]
    except (binascii.Error, ValueError):
        return ""
    for enc in (("utf-16-le", "utf-8") if utf16 else ("utf-8", "utf-16-le")):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if text and printable / len(text) > 0.9:
            return text
    return ""


class ScriptAnalyzer:
    def __init__(self, max_read: int = MAX_READ):
        self.max_read = max_read

    def analyze_file(self, path: PathLike) -> ScriptResult:
        p = Path(path)
        res = ScriptResult(is_script=is_script(p), language=_LANG.get(p.suffix.lower(), ""))
        if not res.is_script:
            res.detail = "Not a script file."
            return res
        try:
            with open(p, "rb") as fh:
                raw = fh.read(self.max_read + 1)
        except OSError as e:
            res.detail = f"Could not read script: {e}"
            return res
        if len(raw) > self.max_read:
            raw, res.truncated = raw[: self.max_read], True
        return self.analyze_bytes(raw, res)

    def analyze_bytes(self, raw: bytes, res: ScriptResult) -> ScriptResult:
        res.encoded = bool(_ENCODED_SCRIPT.search(raw))
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw.decode("utf-16", errors="replace")
        else:
            text = raw.decode("utf-8", errors="replace")

        # unwind layered encodings (Script Encoder, base64 / -enc, char codes, escapes,
        # split strings, reversal, junk replacement) and analyse every layer
        inner, res.decoded_layers = deobfuscate(text)
        res.decoded_fragments = len(inner)
        full = "\n".join([text] + inner)

        for cat, pats in _COMPILED:
            hits = [label for label, rx in pats if rx.search(full)]
            if hits:
                res.categories[cat] = hits
        res.obfuscation = [label for label, rx in _OBFUSCATION if rx.search(text)]
        if res.encoded:
            res.obfuscation.insert(0, "Script Encoder output (#@~^)")
        if res.decoded_layers >= 2:
            res.obfuscation.append(f"nested encoding ({res.decoded_layers} layers)")
        seen = []
        for u in _URL.findall(full):
            if u not in seen:
                seen.append(u)
        res.urls = seen[:20]
        res.detail = self._summary(res)
        return res

    @staticmethod
    def _summary(res: ScriptResult) -> str:
        bits = [res.language or "script"]
        if res.dropper:
            bits.append("downloads and runs code (dropper)")
        if res.categories:
            bits.append("behaviour: " + ", ".join(sorted(res.categories)))
        if res.decoded_layers:
            bits.append(f"{res.decoded_layers} layer(s) of encoding unwound")
        if res.obfuscation:
            bits.append("obfuscation: " + ", ".join(res.obfuscation[:4]))
        if res.urls:
            bits.append(f"{len(res.urls)} URL(s)")
        if len(bits) == 1:
            bits.append("no download, execution or tampering markers")
        return "; ".join(bits) + "."
