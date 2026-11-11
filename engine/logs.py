"""
Logging setup for the entry points (engine.config.init_runtime calls it).

LOG_FORMAT=text (default) keeps the familiar one-line format. LOG_FORMAT=json
writes one JSON object per line - what log shippers (Filebeat, Fluent Bit,
Vector, the Splunk/Elastic agents) ingest without parsing rules:

    {"timestamp": "2026-10-23T21:40:02.512+03:00", "level": "INFO",
     "logger": "RansomwareScanner", "module": "scanner", "event": "scan_completed",
     "message": "Scan completed for a.pdf ...", "path": "a.pdf",
     "sha256": "...", "verdict": "Clean", "risk_score": 0, "duration_ms": 41}

Structured fields come from `extra=` on the log call (see EVENT_FIELDS); a
plain message still produces a valid object. LOG_LEVEL sets the level.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

TEXT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
# Fields a log call may pass with extra={...}; they are copied into the JSON.
EVENT_FIELDS = ("event", "path", "sha256", "verdict", "risk_score", "duration_ms", "layer",
                "files", "files_per_sec", "error",
                # 4.7: completeness, layer states, readiness problems, lockouts, secret sources,
                # what was sent to external services
                "scan_status", "layers", "problems", "client", "sources", "shared")
_MARK = "_aegis_handler"

# L-E9: a file name may hold line breaks or bidirectional controls. In a text
# line they would forge a new log line or report entry, or reverse the shown
# name. They are shown instead: control characters as "?", the right-to-left
# override as "[RTLO]" (as visible_name does for archive members), and the
# other bidi and line-separator characters as "[U+XXXX]".
_BIDI = (0x061C, 0x200E, 0x200F, 0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
_UNSAFE = re.compile("[\\x00-\\x1f\\x7f-\\x9f" + "".join(map(chr, _BIDI)) + "]")
_RTLO = chr(0x202E)


def _show(m: re.Match[str]) -> str:
    c = m.group(0)
    if c == _RTLO:
        return "[RTLO]"
    return "?" if ord(c) < 0xA0 else f"[U+{ord(c):04X}]"


def printable(text: object) -> str:
    """`text` as one line of plain, left-to-right characters (L-E9)."""
    return _UNSAFE.sub(_show, str(text))


class TextFormatter(logging.Formatter):
    """The text log: one record is one line, whatever a file name holds (L-E9).
    A traceback is still appended on its own lines."""

    def formatMessage(self, record: logging.LogRecord) -> str:
        return printable(super().formatMessage(record))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).astimezone()
            .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "event": getattr(record, "event", "log"),
            "message": record.getMessage(),
        }
        for key in EVENT_FIELDS[1:]:
            value = getattr(record, key, None)
            if value is not None:
                out[key] = value
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False, default=str)


def _env_number(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, "") or default)
    except ValueError:
        return default
    return value if value > 0 else default


def make_formatter(fmt: Optional[str] = None) -> logging.Formatter:
    fmt = (fmt or os.getenv("LOG_FORMAT") or "text").strip().lower()
    return JsonFormatter() if fmt == "json" else TextFormatter(TEXT_FORMAT)


def configure_logging(log_file: Path, console: bool = True, level: int = logging.INFO,
                      fmt: Optional[str] = None) -> List[logging.Handler]:
    """Attach a file (and console) handler to the root logger. Handlers this
    function added before are replaced, so calling it twice does not
    duplicate every line."""
    root = logging.getLogger()
    for h in [h for h in root.handlers if getattr(h, _MARK, False)]:
        root.removeHandler(h)
        h.close()
    env_level = os.getenv("LOG_LEVEL", "").strip().upper()
    level = logging.getLevelName(env_level) if env_level in (
        "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else level
    formatter = make_formatter(fmt)
    # A long-running service must not fill its volume: LOG_MAX_MB per file (20),
    # LOG_BACKUPS old files kept (5). Only the main process writes this file.
    handlers: List[logging.Handler] = [logging.handlers.RotatingFileHandler(
        log_file, maxBytes=int(_env_number("LOG_MAX_MB", 20) * 1024 * 1024),
        backupCount=int(_env_number("LOG_BACKUPS", 5)), encoding="utf-8")]
    if console:
        handlers.append(logging.StreamHandler(sys.stdout))
    for h in handlers:
        h.setFormatter(formatter)
        setattr(h, _MARK, True)
        root.addHandler(h)
    root.setLevel(level)
    return handlers
