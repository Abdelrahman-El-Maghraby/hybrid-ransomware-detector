#!/usr/bin/env python3
"""Build and sign detection-content packs (see core/rulepack.py).

    python tools/rulepack.py keygen KEYDIR                       # once; keep the .pem offline
    python tools/rulepack.py build rules/ --version 2026.10.21 --out pack.tar.gz \
           [--fuzzy fuzzy_signatures.json]
    python tools/rulepack.py sign pack.tar.gz --key KEYDIR/rulepack_private.pem
    python tools/rulepack.py verify pack.tar.gz --pub <base64 public key>
    python tools/rulepack.py rollback good-2026.10.21.tar.gz --version 2026.10.23 \
           --out pack.tar.gz --pub <base64 public key>          # then sign it

Users install with:  RULEPACK_PUBLIC_KEYS=<base64> python RansomwareScanner.py --update-rules pack.tar.gz
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.rulepack import (
    RulePackError,
    build_pack,
    generate_keypair,
    rollback_pack,
    sign_pack,
    verify_pack,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("keydir", type=Path)
    b = sub.add_parser("build")
    b.add_argument("rules", type=Path)
    b.add_argument("--version", required=True)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--fuzzy", type=Path)
    b.add_argument("--min-engine", default="4.4.0")
    s = sub.add_parser("sign")
    s.add_argument("pack", type=Path)
    s.add_argument("--key", type=Path, required=True)
    v = sub.add_parser("verify")
    v.add_argument("pack", type=Path)
    v.add_argument("--pub", action="append", required=True)
    r = sub.add_parser("rollback", help="re-issue a previous pack's content under a new version")
    r.add_argument("previous", type=Path)
    r.add_argument("--version", required=True, help="newer than the defective pack")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--pub", action="append", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "keygen":
            priv, pub = generate_keypair(a.keydir)
            print(f"private key: {priv} (keep it offline)\npublic key:  {pub}")
        elif a.cmd == "build":
            print(build_pack(a.rules, a.version, a.out, a.fuzzy, a.min_engine))
        elif a.cmd == "sign":
            print(sign_pack(a.pack, a.key))
        elif a.cmd == "rollback":
            print(rollback_pack(a.previous, a.pub, a.version, a.out))
        else:
            m = verify_pack(a.pack, a.pub)["manifest"]
            print(f"OK: version {m['version']}, {len(m['files'])} file(s)")
    except RulePackError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
