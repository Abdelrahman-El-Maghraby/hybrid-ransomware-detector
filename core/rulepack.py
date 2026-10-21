"""
Signed detection-content packs: YARA rules and fuzzy signatures that update
without a new program release.

A pack is a gzip'd tar with a manifest.json (version, creation time, minimum
engine version, SHA-256 of every file) plus a detached Ed25519 signature of the
whole archive (`<pack>.sig`). The scanner installs a pack only if

  * the signature verifies against one of the trusted public keys
    (RULEPACK_PUBLIC_KEYS, base64, comma-separated - never taken from the pack),
  * every file in the archive is listed in the manifest with a matching hash,
  * every member is a plain file under rules/ (.yar / .yara) or the fuzzy
    signature file - no links, no absolute or ../ paths, bounded sizes,
  * its version is newer than the installed one (unless explicitly allowed),
  * the rules compile.

Installed packs live in DATA_DIR/rulepacks/<version>/; `active.json` points at
the one in use, so a bad pack can be rolled back by pointing at the previous one.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
import tarfile
import time
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PathLike = Union[str, Path]

MAX_PACK_BYTES = 50 * 1024 * 1024
MAX_MEMBER_BYTES = 20 * 1024 * 1024
MAX_MEMBERS = 2000
FUZZY_NAME = "fuzzy_signatures.json"


class RulePackError(Exception):
    pass


def _version_key(v: str) -> Tuple:
    parts = []
    for p in v.replace("-", ".").split("."):
        parts.append((0, int(p)) if p.isdigit() else (1, p))
    return tuple(parts)


# ------------------------------------------------------------------ keys
def generate_keypair(out_dir: PathLike) -> Tuple[Path, str]:
    """Write private.pem (mode 0600) and return (path, base64 public key)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    priv = out / "rulepack_private.pem"
    priv.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    priv.chmod(0o600)
    pub = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    (out / "rulepack_public.txt").write_text(pub + "\n")
    return priv, pub


def _load_private(path: PathLike) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RulePackError("not an Ed25519 private key")
    return key


def _public_keys(encoded: Iterable[str]) -> List[Ed25519PublicKey]:
    keys = []
    for k in encoded:
        k = k.strip()
        if k:
            keys.append(Ed25519PublicKey.from_public_bytes(base64.b64decode(k)))
    return keys


# ------------------------------------------------------------------ build / sign
def build_pack(rules_dir: PathLike, version: str, out: PathLike,
               fuzzy_db: Optional[PathLike] = None, min_engine: str = "4.4.0") -> Path:
    rules = sorted(p for p in Path(rules_dir).glob("*.yar*") if p.is_file())
    if not rules:
        raise RulePackError(f"no .yar files in {rules_dir}")
    files: Dict[str, bytes] = {f"rules/{p.name}": p.read_bytes() for p in rules}
    if fuzzy_db:
        files[FUZZY_NAME] = Path(fuzzy_db).read_bytes()
    manifest = {"format": 1, "version": version, "created": int(time.time()),
                "min_engine": min_engine,
                "files": {n: hashlib.sha256(d).hexdigest() for n, d in files.items()}}
    out = Path(out)
    with tarfile.open(out, "w:gz") as tar:
        for name, data in [("manifest.json", json.dumps(manifest, indent=1).encode())] + sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            tar.addfile(info, io.BytesIO(data))
    return out


def sign_pack(pack: PathLike, private_key: PathLike) -> Path:
    sig = _load_private(private_key).sign(Path(pack).read_bytes())
    out = Path(str(pack) + ".sig")
    out.write_text(base64.b64encode(sig).decode() + "\n")
    return out


# ------------------------------------------------------------------ verify / install
def verify_pack(pack: PathLike, public_keys: Iterable[str],
                signature: Optional[PathLike] = None) -> Dict:
    """Check signature and contents; returns {manifest, files} (bytes in memory)."""
    pack = Path(pack)
    if pack.stat().st_size > MAX_PACK_BYTES:
        raise RulePackError("pack is larger than the limit")
    keys = _public_keys(public_keys)
    if not keys:
        raise RulePackError("no trusted public key configured (RULEPACK_PUBLIC_KEYS)")
    sig_path = Path(signature) if signature else Path(str(pack) + ".sig")
    if not sig_path.is_file():
        raise RulePackError(f"signature file missing: {sig_path.name}")
    data = pack.read_bytes()
    sig = base64.b64decode(sig_path.read_text().strip())
    for key in keys:
        try:
            key.verify(sig, data)
            break
        except InvalidSignature:
            continue
    else:
        raise RulePackError("signature does not match any trusted key")

    files: Dict[str, bytes] = {}
    manifest = None
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise RulePackError("too many files in pack")
        for m in members:
            name = m.name
            pp = PurePosixPath(name)
            if not m.isfile() or pp.is_absolute() or ".." in pp.parts:
                raise RulePackError(f"unsafe entry in pack: {name}")
            if m.size > MAX_MEMBER_BYTES:
                raise RulePackError(f"entry too large: {name}")
            if name == "manifest.json":
                manifest = json.loads(tar.extractfile(m).read())          # type: ignore[union-attr]
                continue
            if not ((len(pp.parts) == 2 and pp.parts[0] == "rules"
                     and pp.suffix.lower() in (".yar", ".yara")) or name == FUZZY_NAME):
                raise RulePackError(f"unexpected file in pack: {name}")
            files[name] = tar.extractfile(m).read()                       # type: ignore[union-attr]
    if not manifest:
        raise RulePackError("manifest.json missing")
    listed = manifest.get("files") or {}
    if set(listed) != set(files):
        raise RulePackError("manifest does not list exactly the files in the pack")
    for name, blob in files.items():
        if hashlib.sha256(blob).hexdigest() != listed[name]:
            raise RulePackError(f"hash mismatch for {name}")
    return {"manifest": manifest, "files": files}


def active_pack(data_dir: PathLike) -> Optional[Dict]:
    f = Path(data_dir) / "rulepacks" / "active.json"
    try:
        info = json.loads(f.read_text())
        if (Path(info["path"]) / "rules").is_dir():
            return info
    except Exception:
        pass
    return None


def install_pack(pack: PathLike, data_dir: PathLike, public_keys: Iterable[str],
                 engine_version: str, allow_downgrade: bool = False,
                 signature: Optional[PathLike] = None) -> Dict:
    checked = verify_pack(pack, public_keys, signature)
    m = checked["manifest"]
    version = str(m.get("version", ""))
    if not version:
        raise RulePackError("pack has no version")
    if _version_key(str(m.get("min_engine", "0"))) > _version_key(engine_version.split("-")[0]):
        raise RulePackError(f"pack needs engine {m.get('min_engine')} or newer")
    current = active_pack(data_dir)
    if current and not allow_downgrade and _version_key(version) <= _version_key(current["version"]):
        raise RulePackError(f"pack {version} is not newer than installed {current['version']}")

    root = Path(data_dir) / "rulepacks"
    staging = root / f".staging-{version}"
    final = root / version
    shutil.rmtree(staging, ignore_errors=True)
    (staging / "rules").mkdir(parents=True)
    for name, blob in checked["files"].items():
        (staging / name).write_bytes(blob)
    try:
        import yara  # type: ignore
        yara.compile(filepaths={p.name: str(p) for p in (staging / "rules").iterdir()})
    except ImportError:
        pass
    except Exception as e:
        shutil.rmtree(staging, ignore_errors=True)
        raise RulePackError(f"rules do not compile: {e}") from e
    shutil.rmtree(final, ignore_errors=True)
    staging.rename(final)
    info = {"version": version, "path": str(final), "installed": int(time.time()),
            "files": len(checked["files"]), "has_fuzzy": FUZZY_NAME in checked["files"]}
    (root / "active.json").write_text(json.dumps(info, indent=1))
    return info
