"""
core - host-side protection services for the Hybrid Ransomware Detection System.

Unlike `detectors/` (which decide *whether a file is malicious*), these modules
act on the host and keep state between scans:

    quarantine   AES-256-GCM encrypted quarantine vault (verify-before-delete,
                 authenticated restore)
    canary       ransomware canary (honeyfile) tripwires: decoy documents whose
                 deletion, modification, or renaming signals active encryption
    canary_watch real-time watching of the canary folders (watchdog), so a
                 tripwire is verified within a second of being touched
    cache        SQLite (WAL) cache for slow external lookups (VirusTotal, LLM)
                 keyed by SHA-256, so scheduled re-scans don't re-query them
    http         shared `requests` session with timeouts, retry/backoff on
                 429/5xx, and a simple client-side rate limiter

Every module degrades gracefully: a missing optional dependency (e.g.
`cryptography`) disables that feature with a clear message instead of
crashing the scanner.
"""

from .cache import ResultCache
from .canary import CanaryManager, CanaryReport
from .canary_watch import WATCHDOG_AVAILABLE, CanaryWatcher
from .http import RateLimiter, build_session
from .quarantine import QUARANTINE_AVAILABLE, QuarantineError, QuarantineVault

__all__ = [
    "ResultCache",
    "CanaryManager", "CanaryReport", "CanaryWatcher", "WATCHDOG_AVAILABLE",
    "RateLimiter", "build_session",
    "QUARANTINE_AVAILABLE", "QuarantineError", "QuarantineVault",
]
