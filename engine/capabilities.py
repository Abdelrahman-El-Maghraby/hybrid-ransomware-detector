"""
What this installation can run: one state per pipeline layer (up / down /
disabled), the layers the production profile requires, and what each build
flavour must have.

`layer_states(scanner)` answers from the engines the scanner really built, so
one function serves the start-up log, `--capabilities` (the build runs it on
the packaged program), GET /ready and the production-profile checks.

    up        the layer runs with everything it needs
    down      the layer is enabled but something it needs is missing
    disabled  switched off by configuration (or an opt-in that is not set)
"""

from __future__ import annotations

import importlib.util
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Mapping, Sequence, Tuple

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import RansomwareScanner

UP, DOWN, DISABLED = "up", "down", "disabled"

PROFILES = ("standard", "production")

# docs/RELEASE_SCOPE.md section 3: available AND enabled in the production profile.
PRODUCTION_REQUIRED: Tuple[str, ...] = (
    "hashes", "allowlist", "local-db", "fuzzy", "macro", "yara", "integrity", "elf", "pe",
    "script", "mail", "prompt-guard", "relationships", "qr", "archive", "web", "embedded",
    "ml",
)
# Layers that send data to another system; off unless configured.
EXTERNAL_LAYERS: Tuple[str, ...] = ("llm", "virustotal", "sandbox")
# Executes attacker code: outside the production profile.
NOT_IN_PRODUCTION: Tuple[str, ...] = ("emulation",)

# Parts a desktop binary cannot bundle on every OS: the host provides them.
HOST_TOOLS: Tuple[str, ...] = ("rar-decompressor", "zbar")

# Build flavours: the layers that must be up in the packaged program, whether
# host tools count, and the Python packages the flavour needs besides the engine.
FLAVOURS: Dict[str, Dict[str, Any]] = {
    "cli": {"layers": PRODUCTION_REQUIRED, "host_tools_required": False, "packages": ()},
    "gui": {"layers": PRODUCTION_REQUIRED, "host_tools_required": False,
            "packages": ("customtkinter",)},
    "api": {"layers": PRODUCTION_REQUIRED, "host_tools_required": True,
            "packages": ("fastapi", "uvicorn", "multipart")},
}

State = Dict[str, Any]


def _state(missing: Sequence[str] = (), disabled: str = "", detail: str = "") -> State:
    if disabled:
        return {"state": DISABLED, "detail": disabled, "missing": []}
    if missing:
        return {"state": DOWN, "detail": "needs " + ", ".join(missing), "missing": list(missing)}
    return {"state": UP, "detail": detail, "missing": []}


def _has_package(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):  # pragma: no cover - broken installs
        return False


# ------------------------------------------------------------- one per layer
def _fuzzy(s: RansomwareScanner) -> State:
    from detectors import fuzzy_hash
    return _state(["ppdeep"] if fuzzy_hash._ppdeep is None else [],
                  detail="tlsh+ssdeep" if fuzzy_hash._tlsh is not None else "ssdeep")


def _macro(s: RansomwareScanner) -> State:
    from detectors import OLEVBA_AVAILABLE
    return _state([] if OLEVBA_AVAILABLE else ["oletools"])


def _yara(s: RansomwareScanner) -> State:
    from detectors import YARA_AVAILABLE
    if not YARA_AVAILABLE:
        return _state(["yara-python"])
    count = int(getattr(s.yara_engine, "_rules_count", 0) or 0)
    return _state([] if count else ["compiled YARA rules"], detail=f"{count} rule files")


def _defusedxml(s: RansomwareScanner) -> State:
    from detectors import DEFUSEDXML_AVAILABLE
    return _state([] if DEFUSEDXML_AVAILABLE else ["defusedxml"])


def _mail(s: RansomwareScanner) -> State:
    from detectors import MSG_AVAILABLE
    return _state([] if MSG_AVAILABLE else ["olefile (.msg)"])


def _qr(s: RansomwareScanner) -> State:
    from detectors import qr_scanner as q
    if s.qr_scanner is None:
        return _state(disabled="QR_SCAN_ENABLED=0")
    if q.QR_AVAILABLE:
        return _state(detail=q.QR_BACKEND)
    if not q.PIL_AVAILABLE:
        return _state(["Pillow"])
    # pyzbar installed but its zbar shared library is not on the host
    return _state(["zbar"] if _has_package("pyzbar") else ["pyzbar"])


def _archive(s: RansomwareScanner) -> State:
    from detectors import container_extractor as c
    missing = [pkg for pkg, ok in (("pyzipper", c.AES_ZIP_AVAILABLE), ("py7zr", c.SEVENZIP_AVAILABLE),
                                   ("pycdlib", c.ISO_AVAILABLE), ("rarfile", c.RAR_AVAILABLE)) if not ok]
    if c.RAR_AVAILABLE and not c.rar_tool_available():
        missing.append("rar-decompressor")
    return _state(missing)


def _embedded(s: RansomwareScanner) -> State:
    from detectors.embedded_content import MSOFFCRYPTO_AVAILABLE
    return _state([] if MSOFFCRYPTO_AVAILABLE else ["msoffcrypto-tool"])


def _ml(s: RansomwareScanner) -> State:
    if s.ml is None:
        return _state(disabled="ML_ENABLED=0")
    return _state(detail=f"model ({s.ml.model_name})" if s.ml.has_model else "rule engine")


def _emulation(s: RansomwareScanner) -> State:
    if s.emulator is None:
        return _state(disabled="EMULATION_ENABLED=0")
    return _state([] if s.emulator.available else [str(s.config.get("emulation_tool") or "box-js")])


def _llm(s: RansomwareScanner) -> State:
    backend = s.llm_backend
    if backend.name == "none":
        return _state(disabled=f"LLM_PROVIDER={s.config.get('llm_provider', 'auto')}: no backend")
    return _state(detail=f"{backend.name} ({'local' if backend.is_local else 'cloud'})")


def _virustotal(s: RansomwareScanner) -> State:
    if not s.config.get("virustotal_api_key"):
        return _state(disabled="no VIRUSTOTAL_API_KEY")
    return _state(detail="hash look-up + upload" if s.config.get("virustotal_upload_unknown")
                  else "hash look-up")


def _sandbox(s: RansomwareScanner) -> State:
    if s.sandbox is None:
        return _state(disabled="no SANDBOX_URL")
    return _state(detail=f"submit={s.config.get('sandbox_submit', 'suspicious')}")


def _local_db(s: RansomwareScanner) -> State:
    return _state(detail=f"{len(s.hash_database)} hashes")


CHECKS: Dict[str, Callable[[RansomwareScanner], State]] = {
    "local-db": _local_db, "fuzzy": _fuzzy, "macro": _macro, "yara": _yara,
    "mail": _mail, "prompt-guard": _defusedxml, "relationships": _defusedxml, "qr": _qr,
    "archive": _archive, "embedded": _embedded, "emulation": _emulation, "ml": _ml,
    "llm": _llm, "virustotal": _virustotal, "sandbox": _sandbox,
}


def layer_states(scanner: RansomwareScanner) -> Dict[str, State]:
    """The state of every pipeline layer, in pipeline order. Layers with no
    optional part (hashes, integrity, pe, ...) are always up."""
    return {layer.name: CHECKS.get(layer.name, lambda s: _state())(scanner)
            for layer in scanner.pipeline}


# ------------------------------------------------------------- judgements
def required_problems(states: Mapping[str, State], required: Sequence[str],
                      host_tools_required: bool = True) -> List[str]:
    """One line per required layer that is not up. With `host_tools_required`
    False, a layer whose only gaps are HOST_TOOLS passes (desktop binaries)."""
    problems = []
    for name in required:
        st = states.get(name)
        if st is None:
            problems.append(f"{name}: not in the pipeline")
            continue
        if st["state"] == UP:
            continue
        if (st["state"] == DOWN and not host_tools_required
                and all(m in HOST_TOOLS for m in st["missing"])):
            continue
        problems.append(f"{name}: {st['state']} ({st['detail']})")
    return problems


def flavour_problems(states: Mapping[str, State], flavour: str) -> List[str]:
    """What the packaged program of a build flavour lacks."""
    spec = FLAVOURS[flavour]
    problems = required_problems(states, spec["layers"], spec["host_tools_required"])
    problems += [f"package {p}: not installed" for p in spec["packages"] if not _has_package(p)]
    return problems


def production_problems(states: Mapping[str, State]) -> List[str]:
    """Why this scanner does not meet the production profile (empty = it does)."""
    problems = required_problems(states, PRODUCTION_REQUIRED)
    problems += [f"{name}: enabled, but it is outside the production profile"
                 for name in NOT_IN_PRODUCTION
                 if states.get(name, {}).get("state", DISABLED) != DISABLED]
    return problems


def external_services(states: Mapping[str, State]) -> Dict[str, str]:
    """Each external layer and how it is configured ('off' when disabled)."""
    return {name: ("off" if states.get(name, {}).get("state", DISABLED) == DISABLED
                   else states[name]["detail"] or "on")
            for name in EXTERNAL_LAYERS}


def summary_line(states: Mapping[str, State]) -> str:
    """`name:state` tokens for the start-up log, with the reason when not up."""
    return "  ".join(f"{name}:{st['state']}" + (f"({st['detail']})" if st["state"] != UP else "")
                     for name, st in states.items())
