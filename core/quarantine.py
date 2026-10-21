"""
Encrypted quarantine vault for the Hybrid Ransomware Detection System.

WHY THIS EXISTS
---------------
Flagging a malicious document is only half of incident response: while the file
sits in ~/Downloads it can still be opened (and its macro enabled) by accident.
Quarantine moves it out of reach in a form that cannot be executed, opened, or
re-detected by other tools, while keeping it recoverable for analysis or for a
false-positive restore.

HOW IT WORKS
------------
* Each file is encrypted with AES-256-GCM in fixed-size chunks (streaming, so a
  multi-GB file never has to fit in memory).
* A random 32-byte master key lives in `keystore_dir/quarantine.key` (0600).
  Every quarantined file gets its own key, derived with HKDF-SHA256 from the
  master key and a random 16-byte salt, plus a random 8-byte nonce prefix.
* Everything is authenticated: an encrypted metadata header (original path,
  SHA-256, size, mode, reason), every chunk (its sequence number is bound in as
  associated data, so chunks cannot be reordered or dropped), and an explicit
  end-of-file frame (so truncation is detected).
* VERIFY-BEFORE-DELETE: after writing the vault file, it is decrypted again and
  its SHA-256 compared with the original *before* the original is removed. The
  tool never deletes a user file unless a verified encrypted copy exists.
* Restore decrypts into a temp file next to the destination, checks the SHA-256
  against the authenticated header, then atomically renames it into place.

THREAT MODEL (be honest about it)
---------------------------------
This neutralises the file (it can't be opened or executed and other AV engines
won't keep re-flagging it). It is *not* a secrecy boundary against someone who
already controls your user account - the key sits on the same disk.

VAULT FILE LAYOUT  (<id>.quar)
------------------------------
    MAGIC (8)  "HRDQV1\\0\\0"
    salt (16) | nonce_prefix (8) | chunk_size (4, BE) | meta_len (4, BE)
    encrypted metadata JSON (meta_len bytes, GCM tag included)
    frames:      [ length (4, BE) | ciphertext + 16-byte tag ] ...
    terminator:  length = 0 (4) | eof_len (4, BE) | GCM tag over empty payload

    nonce(i) = nonce_prefix || uint32_be(i)    i = 0 meta, 1..n chunks, n+1 eof
    AAD      = MAGIC + b"meta" | MAGIC + b"chunk" + uint64_be(i) |
               MAGIC + b"eof" + uint64_be(n)

A plaintext sidecar `<id>.json` (no secrets, used only for fast listing) sits
next to each vault file; restore always trusts the authenticated header inside
the vault, never the sidecar.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import struct
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("RansomwareScanner.quarantine")

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    QUARANTINE_AVAILABLE = True
except Exception:  # pragma: no cover - absence is a valid runtime state
    InvalidTag = ValueError  # type: ignore[misc,assignment]
    QUARANTINE_AVAILABLE = False

PathLike = Union[str, Path]

MAGIC = b"HRDQV1\x00\x00"
KEY_FILE_NAME = "quarantine.key"
# Passphrase-protected key backup (--export-key / --import-key):
#   KEY_MAGIC(8) | salt(16) | scrypt n, r, p (3 x uint32 BE) | nonce(12) | AES-GCM(key) + tag
# The whole header is authenticated as AAD, so a tampered parameter is rejected.
KEY_MAGIC = b"HRDQK1\x00\x00"
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 15, 8, 1
MIN_PASSPHRASE = 10
DEFAULT_CHUNK_SIZE = 64 * 1024
_HKDF_INFO = b"hybrid-ransomware-detector/quarantine/v1"
_HEADER = struct.Struct(">II")      # chunk_size, meta_len
_U32 = struct.Struct(">I")


class QuarantineError(Exception):
    """Raised for any quarantine/restore failure the caller should surface."""


def _sha256_file(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _aad_meta() -> bytes:
    return MAGIC + b"meta"


def _aad_chunk(index: int) -> bytes:
    return MAGIC + b"chunk" + struct.pack(">Q", index)


def _aad_eof(count: int) -> bytes:
    return MAGIC + b"eof" + struct.pack(">Q", count)


class QuarantineVault:
    """AES-256-GCM chunked quarantine vault (see module docstring)."""

    def __init__(self, vault_dir: PathLike, keystore_dir: PathLike,
                 chunk_size: int = DEFAULT_CHUNK_SIZE,
                 master_key: Optional[bytes] = None):
        if not QUARANTINE_AVAILABLE:
            raise QuarantineError(
                "Quarantine needs the 'cryptography' package: pip install cryptography")
        self.vault_dir = Path(vault_dir)
        self.keystore_dir = Path(keystore_dir)
        self.chunk_size = max(4096, int(chunk_size))
        # The key is loaded (or created) on first use, so merely opening the
        # vault - e.g. to list it in the GUI - never writes anything to disk.
        self._key: Optional[bytes] = (self._validate_key(master_key)
                                      if master_key is not None else None)

    @property
    def _master_key(self) -> bytes:
        if self._key is None:
            self.keystore_dir.mkdir(parents=True, exist_ok=True)
            self._key = self._load_or_create_master_key()
        return self._key

    # ------------------------------------------------------------------ keys
    @staticmethod
    def _validate_key(key: bytes) -> bytes:
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise QuarantineError("The quarantine master key must be exactly 32 bytes.")
        return bytes(key)

    def _load_or_create_master_key(self) -> bytes:
        key_path = self.keystore_dir / KEY_FILE_NAME
        if key_path.exists():
            # Never silently regenerate: a new key would make every existing
            # vault item permanently unrecoverable.
            data = key_path.read_bytes()
            if len(data) != 32:
                raise QuarantineError(
                    f"Quarantine key at {key_path} is corrupt ({len(data)} bytes, expected 32). "
                    "Restore it from a backup; refusing to overwrite it.")
            return data
        key = os.urandom(32)
        # O_EXCL: if another process created it a moment ago, use theirs.
        try:
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self._load_or_create_master_key()
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        try:
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:  # pragma: no cover - e.g. some Windows filesystems
            pass
        logger.info("Created quarantine master key at %s", key_path)
        return key

    # ------------------------------------------------------- key backup
    def key_fingerprint(self) -> str:
        """Short, non-secret identifier of the master key (compare across machines)."""
        return hashlib.sha256(b"hrd-key-fingerprint" + self._master_key).hexdigest()[:16]

    @staticmethod
    def _key_cipher(passphrase: str, salt: bytes, n: int, r: int, p: int) -> AESGCM:
        kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
        return AESGCM(kdf.derive(passphrase.encode("utf-8")))

    def export_key(self, destination: PathLike, passphrase: str) -> Path:
        """Write the master key, encrypted with `passphrase`, to a new file.

        Creates the key if this vault has never been used, so a backup can be
        taken up front. Never overwrites an existing file.
        """
        if len(passphrase or "") < MIN_PASSPHRASE:
            raise QuarantineError(f"Use a passphrase of at least {MIN_PASSPHRASE} characters.")
        dest = Path(destination)
        salt, nonce = os.urandom(16), os.urandom(12)
        header = KEY_MAGIC + salt + struct.pack(">III", _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
        blob = header + nonce + self._key_cipher(passphrase, salt, _SCRYPT_N, _SCRYPT_R,
                                                 _SCRYPT_P).encrypt(nonce, self._master_key,
                                                                    header)
        try:
            fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise QuarantineError(f"{dest} already exists; choose another file name.") from None
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        logger.info("Exported quarantine key (fingerprint %s) to %s", self.key_fingerprint(), dest)
        return dest

    @staticmethod
    def read_key_backup(source: PathLike, passphrase: str) -> bytes:
        """Decrypt a key backup; raises QuarantineError on a wrong passphrase or tampering."""
        data = Path(source).read_bytes()
        head_len = len(KEY_MAGIC) + 16 + 12
        if not data.startswith(KEY_MAGIC) or len(data) != head_len + 12 + 32 + 16:
            raise QuarantineError("Not a quarantine key backup file.")
        header, nonce, sealed = data[:head_len], data[head_len:head_len + 12], data[head_len + 12:]
        salt = header[len(KEY_MAGIC):len(KEY_MAGIC) + 16]
        n, r, p = struct.unpack(">III", header[len(KEY_MAGIC) + 16:])
        if not (2 ** 14 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 16):
            raise QuarantineError("Key backup has unsupported scrypt parameters.")
        try:
            return QuarantineVault._key_cipher(passphrase, salt, n, r, p).decrypt(nonce, sealed, header)
        except InvalidTag:
            raise QuarantineError("Wrong passphrase, or the key backup was modified.") from None

    def import_key(self, source: PathLike, passphrase: str, replace: bool = False) -> str:
        """Install a key from a backup. Returns 'installed' | 'already-present' | 'replaced'.

        A DIFFERENT existing key is never overwritten silently: items encrypted
        with it would become unreadable. With replace=True it is first copied to
        quarantine.key.bak-<timestamp> next to it.
        """
        key = self.read_key_backup(source, passphrase)
        self.keystore_dir.mkdir(parents=True, exist_ok=True)
        key_path = self.keystore_dir / KEY_FILE_NAME
        status = "installed"
        if key_path.exists():
            current = key_path.read_bytes()
            if current == key:
                self._key = key
                return "already-present"
            if not replace:
                raise QuarantineError(
                    "A different quarantine key is already installed. Items it encrypted "
                    "would become unreadable if it were replaced; back it up first, then "
                    "import with --replace-key.")
            backup = key_path.with_name(f"{KEY_FILE_NAME}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
            fd = os.open(str(backup), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(current)
            key_path.unlink()
            status = "replaced"
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        self._key = key
        logger.info("Imported quarantine key (fingerprint %s): %s", self.key_fingerprint(), status)
        return status

    def _file_cipher(self, salt: bytes) -> AESGCM:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_HKDF_INFO)
        return AESGCM(hkdf.derive(self._master_key))

    @staticmethod
    def _nonce(prefix: bytes, counter: int) -> bytes:
        return prefix + _U32.pack(counter & 0xFFFFFFFF)

    # ------------------------------------------------------------- helpers
    def _vault_path(self, item_id: str) -> Path:
        return self.vault_dir / f"{item_id}.quar"

    def _sidecar_path(self, item_id: str) -> Path:
        return self.vault_dir / f"{item_id}.json"

    def resolve_id(self, id_or_prefix: str) -> str:
        """Accept a full item id or a unique prefix (handy on the CLI)."""
        wanted = (id_or_prefix or "").strip().lower()
        if not wanted:
            raise QuarantineError("Empty quarantine id.")
        matches = sorted(p.stem for p in self.vault_dir.glob("*.quar")
                         if p.stem.lower().startswith(wanted))
        if not matches:
            raise QuarantineError(f"No quarantined item matches id '{id_or_prefix}'.")
        if len(matches) > 1 and wanted not in matches:
            raise QuarantineError(
                f"Id prefix '{id_or_prefix}' is ambiguous ({len(matches)} matches).")
        return wanted if wanted in matches else matches[0]

    # ----------------------------------------------------------- quarantine
    def quarantine(self, file_path: PathLike, reason: str = "",
                   extra: Optional[Dict[str, Any]] = None,
                   delete_original: bool = True) -> Dict[str, Any]:
        """Encrypt `file_path` into the vault; remove the original once verified.

        Returns the item's metadata record. `original_removed` tells whether the
        original could actually be deleted (it may be locked on Windows).
        """
        src = Path(file_path)
        if src.is_symlink():
            raise QuarantineError(f"Refusing to quarantine a symbolic link: {src}")
        src = src.resolve()
        if not src.is_file():
            raise QuarantineError(f"File not found: {src}")
        try:
            src.relative_to(self.vault_dir.resolve())
            raise QuarantineError("That file is already inside the quarantine vault.")
        except ValueError:
            pass

        st = src.stat()
        original_sha256 = _sha256_file(src, self.chunk_size)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        item_id = uuid.uuid4().hex[:12]
        vault_file = self._vault_path(item_id)
        meta: Dict[str, Any] = {
            "id": item_id,
            "original_path": str(src),
            "original_name": src.name,
            "sha256": original_sha256,
            "size": st.st_size,
            "mode": stat.S_IMODE(st.st_mode),
            "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason or "",
            "extra": extra or {},
        }

        salt, prefix = os.urandom(16), os.urandom(8)
        cipher = self._file_cipher(salt)
        enc_meta = cipher.encrypt(self._nonce(prefix, 0),
                                  json.dumps(meta).encode("utf-8"), _aad_meta())
        try:
            with src.open("rb") as fin, vault_file.open("wb") as fout:
                fout.write(MAGIC + salt + prefix)
                fout.write(_HEADER.pack(self.chunk_size, len(enc_meta)))
                fout.write(enc_meta)
                index = 0
                for chunk in iter(lambda: fin.read(self.chunk_size), b""):
                    index += 1
                    ct = cipher.encrypt(self._nonce(prefix, index), chunk, _aad_chunk(index))
                    fout.write(_U32.pack(len(ct)))
                    fout.write(ct)
                eof = cipher.encrypt(self._nonce(prefix, index + 1), b"", _aad_eof(index))
                fout.write(_U32.pack(0))
                fout.write(_U32.pack(len(eof)))
                fout.write(eof)
                fout.flush()
                os.fsync(fout.fileno())
            try:
                os.chmod(vault_file, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:  # pragma: no cover
                pass
            # Verify-before-delete: decrypt what we just wrote and compare.
            if self._decrypt_stream(vault_file, sink=None)[1] != original_sha256:
                raise QuarantineError("Vault verification failed (hash mismatch).")
        except Exception:
            vault_file.unlink(missing_ok=True)
            raise

        removed = False
        if delete_original:
            try:
                src.unlink()
                removed = True
            except OSError as e:
                logger.error("Vaulted %s but could not delete the original: %s", src, e)
        meta["original_removed"] = removed
        meta["vault_file"] = str(vault_file)
        self._sidecar_path(item_id).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        logger.warning("QUARANTINED %s -> vault id %s (%s)", src, item_id, reason or "no reason")
        return meta

    # -------------------------------------------------------------- decrypt
    def _decrypt_stream(self, vault_file: Path, sink) -> tuple[Dict[str, Any], str]:
        """Authenticate + decrypt a vault file. Writes plaintext to `sink` (a
        binary file object) when given. Returns (metadata, sha256 of plaintext).
        Raises QuarantineError on any tampering, truncation or wrong key."""
        try:
            with vault_file.open("rb") as fh:
                if fh.read(len(MAGIC)) != MAGIC:
                    raise QuarantineError("Not a quarantine vault file (bad magic).")
                salt, prefix = fh.read(16), fh.read(8)
                header = fh.read(_HEADER.size)
                if len(salt) != 16 or len(prefix) != 8 or len(header) != _HEADER.size:
                    raise QuarantineError("Truncated vault header.")
                _chunk_size, meta_len = _HEADER.unpack(header)
                if meta_len > 1024 * 1024:
                    raise QuarantineError("Implausible metadata length in vault header.")
                enc_meta = fh.read(meta_len)
                cipher = self._file_cipher(salt)
                meta = json.loads(cipher.decrypt(self._nonce(prefix, 0), enc_meta, _aad_meta()))
                h = hashlib.sha256()
                index = 0
                while True:
                    raw_len = fh.read(4)
                    if len(raw_len) != 4:
                        raise QuarantineError("Vault truncated before the end-of-file frame.")
                    (frame_len,) = _U32.unpack(raw_len)
                    if frame_len == 0:
                        (eof_len,) = _U32.unpack(fh.read(4))
                        cipher.decrypt(self._nonce(prefix, index + 1), fh.read(eof_len),
                                       _aad_eof(index))
                        if fh.read(1):
                            raise QuarantineError("Unexpected data after end-of-file frame.")
                        break
                    if frame_len > _chunk_size + 1024:
                        raise QuarantineError("Implausible frame length (corrupt vault).")
                    ct = fh.read(frame_len)
                    if len(ct) != frame_len:
                        raise QuarantineError("Truncated ciphertext frame.")
                    index += 1
                    pt = cipher.decrypt(self._nonce(prefix, index), ct, _aad_chunk(index))
                    h.update(pt)
                    if sink is not None:
                        sink.write(pt)
        except InvalidTag as e:
            raise QuarantineError("Vault authentication failed: the file was modified, "
                                  "truncated, or encrypted with a different key.") from e
        except (OSError, ValueError, struct.error) as e:
            raise QuarantineError(f"Could not read vault file: {e}") from e
        return meta, h.hexdigest()

    def verify(self, item_id: str) -> bool:
        """True if the vault item decrypts, authenticates and matches its hash."""
        item_id = self.resolve_id(item_id)
        try:
            meta, digest = self._decrypt_stream(self._vault_path(item_id), sink=None)
        except QuarantineError:
            return False
        return digest == meta.get("sha256")

    def read_metadata(self, item_id: str) -> Dict[str, Any]:
        """Return the *authenticated* metadata stored inside the vault file."""
        item_id = self.resolve_id(item_id)
        meta, _ = self._decrypt_stream(self._vault_path(item_id), sink=None)
        return meta

    # --------------------------------------------------------------- restore
    def restore(self, item_id: str, destination: Optional[PathLike] = None,
                overwrite: bool = False, remove_from_vault: bool = True) -> Path:
        """Decrypt an item back to `destination` (default: its original path).

        If the destination already exists and `overwrite` is False, the file is
        restored next to it with a `.restored-<id>` suffix instead of clobbering
        whatever is there now.
        """
        item_id = self.resolve_id(item_id)
        vault_file = self._vault_path(item_id)
        meta, _ = self._decrypt_stream(vault_file, sink=None)   # authenticate first
        dest = Path(destination) if destination else Path(meta["original_path"])
        if dest.exists() and dest.is_dir():
            dest = dest / meta.get("original_name", f"{item_id}.bin")
        if dest.exists() and not overwrite:
            dest = dest.with_name(f"{dest.name}.restored-{item_id}")
        dest.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_name = tempfile.mkstemp(prefix=".restore-", dir=str(dest.parent))
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                meta, digest = self._decrypt_stream(vault_file, sink=out)
                out.flush()
                os.fsync(out.fileno())
            if digest != meta.get("sha256"):
                raise QuarantineError("Restored content does not match the recorded SHA-256.")
            os.replace(tmp, dest)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        try:
            os.chmod(dest, int(meta.get("mode", 0o600)) & 0o777)
        except OSError:  # pragma: no cover
            pass
        if remove_from_vault:
            self.delete(item_id)
        logger.warning("RESTORED vault id %s -> %s", item_id, dest)
        return dest

    # ------------------------------------------------------------ list/delete
    def list(self) -> List[Dict[str, Any]]:
        """Fast listing from the sidecar files (newest first)."""
        items: List[Dict[str, Any]] = []
        for vault_file in self.vault_dir.glob("*.quar"):
            item_id = vault_file.stem
            record: Dict[str, Any] = {"id": item_id, "vault_file": str(vault_file)}
            try:
                record.update(json.loads(self._sidecar_path(item_id).read_text(encoding="utf-8")))
            except Exception:
                record["note"] = "sidecar missing - use read_metadata() for details"
            items.append(record)
        items.sort(key=lambda r: str(r.get("quarantined_at", "")), reverse=True)
        return items

    def delete(self, item_id: str) -> bool:
        """Permanently delete an item from the vault."""
        item_id = self.resolve_id(item_id)
        existed = self._vault_path(item_id).exists()
        self._vault_path(item_id).unlink(missing_ok=True)
        self._sidecar_path(item_id).unlink(missing_ok=True)
        return existed

    # -------------------------------------------------------------- self-test
    @staticmethod
    def self_test() -> bool:
        """End-to-end check: quarantine -> verify -> restore -> tamper detection."""
        if not QUARANTINE_AVAILABLE:
            return False
        was_disabled = logger.disabled
        logger.disabled = True          # keep the self-test out of the audit log
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                vault = QuarantineVault(root / "vault", root / "keys", chunk_size=4096)
                payload = b"SELFTEST-HEADER|" + os.urandom(20000) + b"|SELFTEST-FOOTER"
                sample = root / "sample.bin"
                sample.write_bytes(payload)
                meta = vault.quarantine(sample, reason="self-test")
                if sample.exists() or not meta["original_removed"]:
                    return False
                raw = Path(meta["vault_file"]).read_bytes()
                if b"SELFTEST-HEADER" in raw:
                    return False
                tampered = bytearray(raw)
                tampered[len(tampered) // 2] ^= 0x01
                Path(meta["vault_file"]).write_bytes(bytes(tampered))
                if vault.verify(meta["id"]):
                    return False
                Path(meta["vault_file"]).write_bytes(raw)
                restored = vault.restore(meta["id"])
                return restored.read_bytes() == payload
        except Exception:  # pragma: no cover
            return False
        finally:
            logger.disabled = was_disabled
