"""Container health check: `python -m api.probe SOCKET [PATH]` exits 0 when the
service on that Unix socket answers PATH (default /health) with 200. The
analysis container has no network, so curl to a port is not an option."""

from __future__ import annotations

import sys

from core.intel_client import unix_request


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: python -m api.probe SOCKET [PATH]", file=sys.stderr)
        return 2
    try:
        status, _ = unix_request(args[0], "GET", args[1] if len(args) > 1 else "/health",
                                 timeout=5)
    except OSError as e:
        print(f"unreachable: {type(e).__name__}", file=sys.stderr)
        return 1
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
