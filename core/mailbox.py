"""
Scan e-mail straight from a mailbox over IMAP.

A message saved to disk often lost its transport headers (drafts, sent items,
some exports), so SPF / DKIM / DMARC and the relay chain cannot be judged. Read
from the server, every message arrives exactly as delivered.

Safety and privacy:
  * TLS only: implicit TLS (port 993) or STARTTLS, certificate and host name
    verified with the system trust store. Plain-text IMAP is refused.
  * Read-only: the folder is opened with EXAMINE and bodies are fetched with
    BODY.PEEK[], so nothing is marked as read, moved or deleted.
  * Each message is written to a private temporary folder, scanned in an
    isolated worker process like any folder scan, and deleted afterwards.
  * Only messages not seen before are scanned: the last UID per mailbox folder
    is kept in a small state file (reset when the server's UIDVALIDITY changes).
  * Bounded: at most `max_messages` per run and `max_bytes` per message.
  * Use an app password (IMAP_PASSWORD); it is never logged or written to reports.
"""

from __future__ import annotations

import imaplib
import json
import logging
import os
import re
import shutil
import ssl
import tempfile
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("RansomwareScanner.mailbox")

_SIZE = re.compile(rb"RFC822\.SIZE (\d+)")


class MailboxError(Exception):
    pass


@dataclass
class ImapSettings:
    host: str
    user: str
    password: str = field(repr=False)
    port: int = 993
    starttls: bool = False            # port 143 with STARTTLS instead of implicit TLS
    folder: str = "INBOX"
    since_days: int = 7               # first run: look this far back
    max_messages: int = 200           # per run
    max_bytes: int = 25 * 1024 * 1024  # per message
    state_path: str = ""
    timeout: int = 60

    @classmethod
    def from_config(cls, config: Dict) -> ImapSettings:
        if not config.get("imap_host") or not config.get("imap_user"):
            raise MailboxError("set IMAP_HOST and IMAP_USER (and IMAP_PASSWORD, an app password)")
        return cls(host=config["imap_host"], user=config["imap_user"],
                   password=config.get("imap_password", ""),
                   port=int(config.get("imap_port", 993) or 993),
                   starttls=bool(config.get("imap_starttls", False)),
                   folder=config.get("imap_folder") or "INBOX",
                   since_days=int(config.get("imap_since_days", 7) or 7),
                   max_messages=int(config.get("imap_max_messages", 200) or 200),
                   max_bytes=int(float(config.get("imap_max_mb", 25) or 25) * 1024 * 1024),
                   state_path=config.get("imap_state_path", ""),
                   timeout=int(config.get("http_timeout", 60) or 60))

    @property
    def key(self) -> str:
        return f"{self.user}@{self.host}:{self.port}/{self.folder}"


@dataclass
class MailboxRun:
    results: List[Dict] = field(default_factory=list)
    skipped_too_large: List[int] = field(default_factory=list)
    new_messages: int = 0
    more_waiting: bool = False         # more new messages than max_messages


def _default_connect(s: ImapSettings):
    context = ssl.create_default_context()        # verifies certificate + host name
    if s.starttls:
        conn = imaplib.IMAP4(s.host, s.port, timeout=s.timeout)
        conn.starttls(ssl_context=context)
        return conn
    return imaplib.IMAP4_SSL(s.host, s.port, ssl_context=context, timeout=s.timeout)


class MailboxScanner:
    """Fetch new messages from one IMAP folder and scan them with the engine."""

    def __init__(self, scanner, settings: ImapSettings,
                 connect: Callable[[ImapSettings], Any] = _default_connect):
        self.scanner = scanner
        self.settings = settings
        self.connect = connect

    # ------------------------------------------------------------------ state
    def _load_state(self) -> Dict:
        try:
            return json.loads(Path(self.settings.state_path).read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}

    def _save_state(self, state: Dict) -> None:
        if not self.settings.state_path:
            return
        path = Path(self.settings.state_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
        os.replace(tmp, path)

    # ------------------------------------------------------------------ run
    def run(self) -> MailboxRun:
        s = self.settings
        out = MailboxRun()
        try:
            conn = self.connect(s)
        except (OSError, imaplib.IMAP4.error, ssl.SSLError) as e:
            raise MailboxError(f"cannot connect to {s.host}:{s.port}: {e}") from e
        workdir = Path(tempfile.mkdtemp(prefix="hrd_imap_"))      # mode 700
        try:
            try:
                conn.login(s.user, s.password)
            except imaplib.IMAP4.error as e:
                raise MailboxError(f"login failed for {s.user}@{s.host}") from e
            typ, _ = conn.select(_quote(s.folder), readonly=True)   # EXAMINE: read-only
            if typ != "OK":
                raise MailboxError(f"cannot open folder {s.folder!r}")
            validity = _first_int(conn.response("UIDVALIDITY")[1])
            state = self._load_state()
            entry = state.get(s.key) or {}
            last_uid = int(entry.get("last_uid", 0)) if entry.get("uidvalidity") == validity else 0

            uids = self._new_uids(conn, last_uid)
            out.new_messages = len(uids)
            out.more_waiting = len(uids) > s.max_messages
            uids = uids[:s.max_messages]

            paths: List[str] = []
            labels: Dict[str, Tuple[int, str]] = {}
            for uid in uids:
                raw = self._fetch(conn, uid)
                if raw is None:
                    out.skipped_too_large.append(uid)
                    continue
                path = workdir / f"{uid}.eml"
                path.write_bytes(raw)
                paths.append(str(path))
                labels[str(path)] = (uid, f"imap://{s.user}@{s.host}/{s.folder};UID={uid}")

            if paths:
                for result in self.scanner._scan_targets(paths):
                    uid, label = labels.get(result.get("file_path", ""), (0, ""))
                    if label:
                        result["file_path"] = label
                        result["file_name"] = f"{s.folder} UID {uid}"
                        result["mailbox"] = {"host": s.host, "user": s.user,
                                             "folder": s.folder, "uid": uid}
                    out.results.append(result)
            if uids:
                state[s.key] = {"uidvalidity": validity, "last_uid": max(uids)}
                self._save_state(state)
            return out
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
            try:
                conn.logout()
            except Exception:                    # already closed / broken connection
                pass

    def _new_uids(self, conn, last_uid: int) -> List[int]:
        if last_uid:
            typ, data = conn.uid("SEARCH", None, f"UID {last_uid + 1}:*")
        else:
            since = (date.today() - timedelta(days=self.settings.since_days)).strftime("%d-%b-%Y")
            typ, data = conn.uid("SEARCH", None, "SINCE", since)
        if typ != "OK":
            raise MailboxError("IMAP search failed")
        uids = sorted({int(x) for x in b" ".join(d for d in data if d).split() if x.isdigit()})
        return [u for u in uids if u > last_uid]   # "N:*" also returns the last one

    def _fetch(self, conn, uid: int) -> Optional[bytes]:
        typ, data = conn.uid("FETCH", str(uid), "(RFC822.SIZE)")
        size_match = _SIZE.search(b" ".join(_flatten(data))) if typ == "OK" else None
        if size_match and int(size_match.group(1)) > self.settings.max_bytes:
            logger.warning("Skipping UID %d: %s bytes is over the %d-byte limit.",
                           uid, size_match.group(1).decode(), self.settings.max_bytes)
            return None
        typ, data = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")   # PEEK: stays unread
        if typ != "OK":
            return None
        for item in data or []:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                return item[1][:self.settings.max_bytes]
        return None


def _quote(folder: str) -> str:
    return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _first_int(values) -> int:
    for v in values or []:
        if v is None:
            continue
        text = v.decode() if isinstance(v, bytes) else str(v)
        if text.strip().isdigit():
            return int(text.strip())
    return 0


def _flatten(data) -> List[bytes]:
    out: List[bytes] = []
    for item in data or []:
        if isinstance(item, tuple):
            out.extend(x for x in item if isinstance(x, bytes))
        elif isinstance(item, bytes):
            out.append(item)
    return out
