"""
Startup validation of the configuration.

Every setting has a default, so before 4.6 a typo such as SCAN_WORKERS=four or
CANARY_RESPONSE=network-off was silently replaced by the default (or ignored)
and the user believed a protection was on. The entry points now call
check_config() right after init_runtime(): errors stop the program with one
line per problem, warnings are logged.

The rules are data (RULES) checked by a few small functions, so a new setting
adds one line, not a new branch.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger("RansomwareScanner")

VERDICTS = ("Clean", "Low", "Medium", "High", "Critical")


class ConfigError(ValueError):
    """The configuration cannot be used; `problems` lists every reason."""

    def __init__(self, problems: Sequence[str]):
        self.problems = list(problems)
        super().__init__("Invalid configuration:\n" + "\n".join(f"  - {p}" for p in problems))


# key -> (environment variable, minimum, maximum); None = unbounded.
NUMBERS: Dict[str, Tuple[str, Optional[float], Optional[float]]] = {
    "scan_workers": ("SCAN_WORKERS", 0, 64),
    "scan_timeout_seconds": ("SCAN_TIMEOUT_SECONDS", 1, 86_400),
    "worker_memory_mb": ("WORKER_MEMORY_MB", 0, 1_048_576),
    "http_timeout": ("HTTP_TIMEOUT", 1, 3_600),
    "virustotal_requests_per_minute": ("VT_REQUESTS_PER_MINUTE", 0, 100_000),
    "cache_ttl_hours": ("CACHE_TTL_HOURS", 0, None),
    "sandbox_wait_seconds": ("SANDBOX_WAIT_SECONDS", 1, 86_400),
    "emulation_timeout": ("EMULATION_TIMEOUT", 1, 3_600),
    "imap_port": ("IMAP_PORT", 1, 65_535),
    "imap_since_days": ("IMAP_SINCE_DAYS", 0, 3_650),
    "imap_max_messages": ("IMAP_MAX_MESSAGES", 1, 100_000),
    "imap_max_mb": ("IMAP_MAX_MB", 1, 2_048),
    "imap_check_minutes": ("IMAP_CHECK_MINUTES", 0, 10_080),
    "canary_check_minutes": ("CANARY_CHECK_MINUTES", 1, 10_080),
    "scan_interval_hours": ("", 1, 8_760),
    "archive_max_depth": ("", 0, 16),
    "archive_max_members": ("", 1, 1_000_000),
    "archive_scan_members": ("", 0, 100_000),
    "max_nesting": ("", 0, 8),
}

# key -> (environment variable, allowed values, case-insensitive)
CHOICES: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "profile": ("AEGIS_PROFILE", ("standard", "production")),
    "llm_provider": ("LLM_PROVIDER", ("auto", "ollama", "openai", "none")),
    "sandbox_submit": ("SANDBOX_SUBMIT", ("suspicious", "all")),
    "webhook_min_verdict": ("WEBHOOK_MIN_VERDICT", VERDICTS),
    "auto_quarantine": ("AUTO_QUARANTINE", ("", "off", "medium", "high", "critical")),
    "canary_contain_mode": ("CANARY_CONTAIN_MODE", ("suspend", "terminate")),
}

URLS = {"ollama_host": "OLLAMA_HOST", "webhook_url": "WEBHOOK_URL",
        "sandbox_url": "SANDBOX_URL", "chatgpt_api_url": ""}


def validate_config(config: Mapping[str, Any],
                    env_problems: Sequence[str] = ()) -> Tuple[List[str], List[str]]:
    """(errors, warnings) for a configuration; never raises."""
    errors: List[str] = list(env_problems)
    warnings: List[str] = []
    for check in CHECKS:
        check(config, errors, warnings)
    return errors, warnings


def check_config(config: Mapping[str, Any], env_problems: Optional[Sequence[str]] = None,
                 log: bool = True) -> List[str]:
    """Raise ConfigError on any error; log and return the warnings."""
    if env_problems is None:
        from engine.config import ENV_PROBLEMS
        env_problems = ENV_PROBLEMS
    errors, warnings = validate_config(config, env_problems)
    if errors:
        raise ConfigError(errors)
    if log:
        for w in warnings:
            logger.warning("Configuration: %s", w)
    return warnings


# ------------------------------------------------------------------ the checks
def _name(key: str, env: str) -> str:
    return env or key


def _numbers(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    for key, (env, low, high) in NUMBERS.items():
        if key not in cfg:
            continue
        value = cfg[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"{_name(key, env)} must be a number, got {value!r}")
        elif (low is not None and value < low) or (high is not None and value > high):
            span = f"{low:g}..{high:g}" if high is not None else f">= {low:g}"
            errors.append(f"{_name(key, env)}={value:g} is out of range ({span})")


def _choices(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    for key, (env, allowed) in CHOICES.items():
        if key not in cfg:
            continue
        value = str(cfg[key] or "").strip()
        if value.lower() not in {a.lower() for a in allowed}:
            shown = ", ".join(a or '""' for a in allowed)
            errors.append(f"{_name(key, env)}={value!r} is not one of: {shown}")


def _urls(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    for key, env in URLS.items():
        value = str(cfg.get(key) or "").strip()
        if value and not value.lower().startswith(("http://", "https://")):
            errors.append(f"{_name(key, env)}={value!r} must start with http:// or https://")
    hook = str(cfg.get("webhook_url") or "")
    if hook.lower().startswith("http://") and not _is_local(hook):
        warnings.append("WEBHOOK_URL uses plain http to a remote host: alerts and their "
                        "signature travel unencrypted")
    if hook and not cfg.get("webhook_secret"):
        warnings.append("WEBHOOK_URL is set without WEBHOOK_SECRET: the receiver cannot "
                        "verify that alerts come from this scanner")


def _is_local(url: str) -> bool:
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


def _canary(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    raw = str(cfg.get("canary_response") or "")
    names = [n.strip().lower() for n in raw.split(",") if n.strip()]
    if names:                        # only then: scanning never loads containment
        try:
            from core.response import ACTIONS
        except ImportError:          # the server image ships without containment
            errors.append("CANARY_RESPONSE is set, but this build has no containment "
                          "(canary responses are part of the desktop builds only)")
            return
        unknown = [n for n in names if n not in ACTIONS]
        if unknown:
            errors.append(f"CANARY_RESPONSE has unknown action(s) {', '.join(unknown)}; "
                          f"known: {', '.join(ACTIONS)}")
    script = str(cfg.get("canary_response_script") or "")
    if "script" in names and not script:
        errors.append("CANARY_RESPONSE includes 'script' but CANARY_RESPONSE_SCRIPT is not set")
    if script and not os.path.isabs(script):
        errors.append(f"CANARY_RESPONSE_SCRIPT={script!r} must be an absolute path")
    for d in _split_dirs(str(cfg.get("canary_lock_dirs") or "")):
        if not os.path.isdir(d):
            warnings.append(f"CANARY_LOCK_DIRS: {d} is not a folder (skipped when locking)")


def _split_dirs(raw: str) -> List[str]:
    import re
    seps = r";" if os.name == "nt" else r"[;:]"
    return [d.strip() for d in re.split(seps, raw) if d.strip()]


def _imap(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    if int(cfg.get("imap_check_minutes") or 0) > 0 and not (cfg.get("imap_host")
                                                           and cfg.get("imap_user")):
        errors.append("IMAP_CHECK_MINUTES is set but IMAP_HOST / IMAP_USER are not")
    if cfg.get("imap_host") and not cfg.get("imap_password"):
        warnings.append("IMAP_HOST is set without IMAP_PASSWORD (use an app password)")


def _paths(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    rules = str(cfg.get("yara_rules_dir") or "")
    if rules and not Path(rules).is_dir():
        warnings.append(f"YARA_RULES_DIR={rules} does not exist: the YARA layer will be off")
    override = str(cfg.get("weights_override") or "")
    if override and not Path(override).is_file():
        errors.append(f"WEIGHTS_OVERRIDE={override} does not exist")
    for key, env in (("jsonl_path", "JSONL_PATH"),):
        value = str(cfg.get(key) or "")
        if value and Path(value).exists() and Path(value).is_dir():
            errors.append(f"{env}={value} is a folder, not a file")
    exts = cfg.get("file_extensions")
    if exts is not None and (not isinstance(exts, (list, tuple)) or not all(
            isinstance(e, str) and e.startswith(".") for e in exts)):
        errors.append("file_extensions must be a list like ['.pdf', '.docx']")
    dirs = cfg.get("scan_directories")
    if dirs is not None and not isinstance(dirs, (list, tuple)):
        errors.append("scan_directories must be a list of folders")


def _conflicts(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    if (str(cfg.get("llm_provider") or "").lower() == "openai"
            and not cfg.get("chatgpt_api_key")):
        errors.append("LLM_PROVIDER=openai needs OPENAI_API_KEY")
    if cfg.get("virustotal_upload_unknown") and not cfg.get("virustotal_api_key"):
        warnings.append("VT_UPLOAD_UNKNOWN is on but VIRUSTOTAL_API_KEY is empty: nothing "
                        "will be uploaded")
    if (cfg.get("isolate_scans") is False and int(cfg.get("worker_memory_mb") or 0) > 0
            and int(cfg.get("scan_workers") or 0) > 1):
        warnings.append("ISOLATE_SCANS is off: SCAN_WORKERS and WORKER_MEMORY_MB have no effect")
    if (str(cfg.get("canary_contain_mode") or "").lower() == "terminate"
            and "stop_writers" not in str(cfg.get("canary_response") or "")):
        warnings.append("CANARY_CONTAIN_MODE is set but CANARY_RESPONSE does not include "
                        "stop_writers")


# Settings that switch off a layer the production profile requires (docs/RELEASE_SCOPE.md).
PRODUCTION_SWITCHES = (("qr_scan_enabled", "QR_SCAN_ENABLED", "qr"),
                       ("ml_enabled", "ML_ENABLED", "ml"))


def _profile(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    """AEGIS_PROFILE=production: a required layer may not be switched off, and the
    layers that execute attacker code may not be switched on. Whether each required
    layer is also *available* is reported by GET /ready and --capabilities."""
    if str(cfg.get("profile") or "standard").strip().lower() != "production":
        return
    for key, env, layer in PRODUCTION_SWITCHES:
        if key in cfg and not cfg[key]:
            errors.append(f"{env}=0 switches off the '{layer}' layer, which the production "
                          "profile requires")
    if cfg.get("emulation_enabled"):
        errors.append("EMULATION_ENABLED runs attacker JavaScript; it is outside the "
                      "production profile (use it in an analysis VM)")
    rules = str(cfg.get("yara_rules_dir") or "")
    if rules and not Path(rules).is_dir():
        errors.append(f"YARA_RULES_DIR={rules} does not exist: the production profile "
                      "requires the YARA layer")
    if str(cfg.get("canary_response") or "").strip():
        errors.append("CANARY_RESPONSE suspends, kills or locks on the host; containment is "
                      "part of the desktop builds only, outside the production profile")
    if cfg.get("isolate_scans") is False:
        warnings.append("ISOLATE_SCANS is off: a hostile file can hang or crash the service "
                        "instead of being reported as a failed scan")


# Secrets and destinations that belong to the intel service, not to analysis.
INTEL_OWNED = (("virustotal_api_key", "VIRUSTOTAL_API_KEY"), ("chatgpt_api_key", "OPENAI_API_KEY"),
               ("sandbox_url", "SANDBOX_URL"), ("sandbox_token", "SANDBOX_TOKEN"))


def _intel(cfg: Mapping[str, Any], errors: List[str], warnings: List[str]) -> None:
    """With AEGIS_INTEL_SOCKET the external services are the intel service's: the
    analysis side needs the token and must not hold their secrets (in the
    production profile that is an error - the point is that a compromised parser
    finds no key to steal)."""
    if not cfg.get("intel_socket"):
        return
    from engine.secret_store import from_environment
    if not (cfg.get("intel_token") or from_environment("AEGIS_INTEL_TOKEN")):
        errors.append("AEGIS_INTEL_SOCKET is set but AEGIS_INTEL_TOKEN (or _FILE) is not")
    held = [env for key, env in INTEL_OWNED if cfg.get(key)]
    if held:
        text = (f"{', '.join(held)} set on the analysis side: with AEGIS_INTEL_SOCKET these "
                "belong to the intel service only")
        production = str(cfg.get("profile") or "").strip().lower() == "production"
        (errors if production else warnings).append(text)


Check = Callable[[Mapping[str, Any], List[str], List[str]], None]
CHECKS: Tuple[Check, ...] = (_numbers, _choices, _urls, _canary, _imap, _paths, _conflicts,
                             _profile, _intel)
