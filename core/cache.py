"""
Result cache for slow external lookups (VirusTotal, LLM).

WHY THIS EXISTS
---------------
The background mode re-scans the same folders every few hours. The local layers
(hashing, fuzzy, macros, YARA, heuristics) are fast and deterministic, so they
simply run again. The *external* layers are not:

* VirusTotal's free API allows ~4 requests/minute and 500/day. Re-querying every
  unchanged file on every scheduled scan burns that quota within a few scans
  and then every lookup fails with HTTP 429.
* An LLM call can take seconds per document even when it runs locally.

This cache stores those results per (SHA-256, layer) with a TTL, in a small
SQLite database in WAL mode (safe for the GUI worker thread and the background
process to share). Because the key is the *content hash*, a renamed or copied
file still hits the cache, and any edit to a file produces a new hash and a
fresh lookup.

If the database cannot be opened (read-only home dir, corrupted file, ...) the
cache disables itself and the scanner keeps working without it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union

logger = logging.getLogger("RansomwareScanner.cache")

SCHEMA_VERSION = 1


class ResultCache:
    """Thread-safe (sha256, layer) -> JSON cache with per-entry expiry."""

    def __init__(self, db_path: Union[str, Path], default_ttl_seconds: float = 24 * 3600):
        self.db_path = str(db_path)
        self.default_ttl = float(default_ttl_seconds)
        self.enabled = False
        self.hits = 0
        self.misses = 0
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        try:
            if self.db_path != ":memory:":
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS layer_cache ("
                " sha256 TEXT NOT NULL,"
                " layer TEXT NOT NULL,"
                " value_json TEXT NOT NULL,"
                " created_at REAL NOT NULL,"
                " expires_at REAL NOT NULL,"
                " PRIMARY KEY (sha256, layer))")
            self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._conn.commit()
            self.enabled = True
            self.purge_expired()             # expired answers are never served; drop them
        except Exception as e:
            logger.warning("Result cache disabled (could not open %s): %s", self.db_path, e)
            self._close_quietly()

    # ------------------------------------------------------------------ API
    def get(self, sha256: str, layer: str) -> Optional[Dict[str, Any]]:
        """Return the cached value, or None if missing/expired/disabled."""
        if not self.enabled or not sha256:
            return None
        now = time.time()
        try:
            with self._lock:
                row = self._conn.execute(  # type: ignore[union-attr]
                    "SELECT value_json, expires_at FROM layer_cache WHERE sha256=? AND layer=?",
                    (sha256.lower(), layer)).fetchone()
                if row is None or float(row[1]) <= now:
                    self.misses += 1
                    return None
                self.hits += 1
                return json.loads(row[0])
        except Exception as e:
            logger.debug("Cache read failed (%s/%s): %s", sha256, layer, e)
            return None

    def put(self, sha256: str, layer: str, value: Dict[str, Any],
            ttl_seconds: Optional[float] = None) -> None:
        """Store `value` for (sha256, layer). A TTL <= 0 means 'don't cache'."""
        if not self.enabled or not sha256:
            return
        ttl = self.default_ttl if ttl_seconds is None else float(ttl_seconds)
        if ttl <= 0:
            return
        now = time.time()
        try:
            payload = json.dumps(value, default=str)
            with self._lock:
                self._conn.execute(  # type: ignore[union-attr]
                    "INSERT OR REPLACE INTO layer_cache "
                    "(sha256, layer, value_json, created_at, expires_at) VALUES (?,?,?,?,?)",
                    (sha256.lower(), layer, payload, now, now + ttl))
                self._conn.commit()  # type: ignore[union-attr]
        except Exception as e:
            logger.debug("Cache write failed (%s/%s): %s", sha256, layer, e)

    def purge_expired(self) -> int:
        """Delete expired rows; returns how many were removed."""
        return self._execute_delete("DELETE FROM layer_cache WHERE expires_at <= ?", (time.time(),))

    def clear(self) -> int:
        """Delete every cached row; returns how many were removed."""
        return self._execute_delete("DELETE FROM layer_cache", ())

    def stats(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"enabled": self.enabled, "path": self.db_path,
                                "hits": self.hits, "misses": self.misses,
                                "entries": 0, "expired": 0}
        if not self.enabled:
            return info
        try:
            with self._lock:
                info["entries"] = int(self._conn.execute(  # type: ignore[union-attr]
                    "SELECT COUNT(*) FROM layer_cache").fetchone()[0])
                info["expired"] = int(self._conn.execute(  # type: ignore[union-attr]
                    "SELECT COUNT(*) FROM layer_cache WHERE expires_at <= ?",
                    (time.time(),)).fetchone()[0])
        except Exception as e:  # pragma: no cover
            logger.debug("Cache stats failed: %s", e)
        return info

    def close(self) -> None:
        with self._lock:
            self._close_quietly()
            self.enabled = False

    # -------------------------------------------------------------- helpers
    def _execute_delete(self, sql: str, params: tuple) -> int:
        if not self.enabled:
            return 0
        try:
            with self._lock:
                cur = self._conn.execute(sql, params)  # type: ignore[union-attr]
                self._conn.commit()  # type: ignore[union-attr]
                return int(cur.rowcount or 0)
        except Exception as e:  # pragma: no cover
            logger.debug("Cache delete failed: %s", e)
            return 0

    def _close_quietly(self) -> None:
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:  # pragma: no cover
            pass
        self._conn = None
