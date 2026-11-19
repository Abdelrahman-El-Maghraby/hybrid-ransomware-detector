"""Kubernetes isolation gate for the analysis Pod (docs/KUBERNETES.md).

In Docker the analysis container has no network interface (network_mode: none).
A Kubernetes Pod always has one; only a NetworkPolicy, enforced by the cluster's
network plugin, keeps the analysis Pod from the internet, the cluster DNS, the
Kubernetes API and the cloud metadata address. A policy that is missing, not yet
applied (a new Pod can start before the plugin has programmed it) or not enforced
at all leaves that Pod connected. This script checks the effect, not the YAML:

    python /opt/aegis-k8s/isolation_gate.py gate     init container: exit 1 while any
                                                     destination below answers
    python /opt/aegis-k8s/isolation_gate.py ready    readiness probe: the gate, then
                                                     the API's /ready on its socket
    python /opt/aegis-k8s/isolation_gate.py verify [HOST:PORT ...]
                                                     operator check (kubectl exec): the
                                                     gate, extra destinations, and the
                                                     container's own hardening
    python /opt/aegis-k8s/isolation_gate.py posture  the hardening checks only; opens no
                                                     network connection

The network modes are live probes and run only when the environment asks for them
explicitly: AEGIS_GATE_LIVE=1 and AEGIS_GATE_TARGETS (a comma-separated list of
tcp:HOST:PORT, udp53:HOST and dns:NAME entries), both set by the Kubernetes
manifests. Without them every network mode refuses (exit 2) before a socket is
opened; there is no built-in list of public addresses to fall back on. In live mode
the cluster DNS servers (/etc/resolv.conf) and the API server
(KUBERNETES_SERVICE_HOST) are probed as well.

A connection that succeeds, or a DNS server that answers, is a failure. A time-out,
"no route" or a refused connection counts as blocked. The gate guards against
misconfiguration; it is not a boundary against code already running in the Pod.
Standard library only, so it runs before anything else is imported.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time
from typing import Callable, List, Optional, Tuple

TIMEOUT = float(os.environ.get("AEGIS_GATE_TIMEOUT", "2"))
WAIT = TIMEOUT * 3 + 2                   # all probes together; below the probe time-outs
API_SOCKET = os.environ.get("AEGIS_API_SOCKET", "/run/aegis/api/api.sock")
CONTENT = "/var/lib/aegis/RansomwareScanner/data"
SCRATCH = "/tmp"  # noqa: S108  # nosec B108  # only its mount options are read
# Names of settings that belong to the external services. None of them may reach the
# analysis container: Kubernetes has no intel service yet (docs/KUBERNETES.md).
EXTERNAL_SETTINGS = ("VIRUSTOTAL_API_KEY", "OPENAI_API_KEY", "SANDBOX_URL", "SANDBOX_TOKEN",
                     "SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_TO",
                     "ALERT_EMAIL_FROM", "AEGIS_INTEL_TOKEN", "AEGIS_INTEL_SOCKET",
                     "OLLAMA_HOST", "WEBHOOK_URL", "CLOUD_SECRET_ACCESS_KEY")
# With the intel component (option E) analysis is an intel client over TLS: these
# are allowed then, and only then; the external services' own settings never are.
INTEL_CLIENT_SETTINGS = ("AEGIS_INTEL_TOKEN",)
SERVICE_ACCOUNT = "/var/run/secrets/kubernetes.io/serviceaccount"

Result = Tuple[str, bool, str]           # name, passed, detail


def tcp_probe(host: str, port: int) -> Tuple[bool, str]:
    """(blocked, detail) for a TCP connection attempt."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
    except ConnectionRefusedError:
        return True, "refused (a reject rule or a closed port)"
    except OSError as e:
        return True, type(e).__name__ + (": " + e.strerror if e.strerror else "")
    return False, "connected"


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p)
    return struct.pack(">HHHHHH", 0x5A5A, 0x0100, 1, 0, 0, 0) + labels + b"\0" + b"\0\1\0\1"


def udp_dns_probe(server: str, port: int = 53) -> Tuple[bool, str]:
    """(blocked, detail): a DNS server that answers at all is reachable."""
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(dns_query("kubernetes.default.svc.cluster.local"), (server, port))
            data = s.recv(512)
    except OSError as e:
        return True, type(e).__name__ + (": " + e.strerror if e.strerror else "")
    return (False, "answered") if data[:2] == b"\x5a\x5a" else (True, "unrelated reply")


def resolve_probe(name: str) -> Tuple[bool, str]:
    try:
        socket.getaddrinfo(name, 443)
    except OSError as e:
        return True, type(e).__name__
    return False, "resolved"


def nameservers(path: str = "/etc/resolv.conf") -> List[str]:
    found = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    found.append(parts[1].split("%")[0])
    except OSError:
        pass
    return found


def parse_target(text: str) -> Tuple[str, int]:
    host, _, port = text.strip().rpartition(":")
    host = host.strip("[]")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"not HOST:PORT: {text!r}")
    return host, int(port)


LIVE_ENV = "AEGIS_GATE_LIVE"
TARGETS_ENV = "AEGIS_GATE_TARGETS"


def parse_targets(text: str) -> List[Tuple[str, Callable]]:
    """AEGIS_GATE_TARGETS entries as (name, probe). ValueError on a bad entry."""
    checks: List[Tuple[str, Callable]] = []
    for raw in (t.strip() for t in text.split(",")):
        if not raw:
            continue
        kind, _, rest = raw.partition(":")
        if kind == "tcp":
            host, port = parse_target(rest)
            checks.append((f"tcp {rest}", lambda h=host, p=port: tcp_probe(h, p)))
        elif kind == "udp53" and rest and all(c.isalnum() or c in ".:[]-" for c in rest):
            server = rest.strip("[]")
            checks.append((f"udp {rest}:53", lambda s=server: udp_dns_probe(s)))
        elif kind == "dns" and rest and all(c.isalnum() or c in ".-" for c in rest):
            checks.append((f"dns {rest}", lambda n=rest: resolve_probe(n)))
        else:
            raise ValueError(f"not a gate target (tcp:HOST:PORT, udp53:HOST, dns:NAME): {raw!r}")
    return checks


def live_problem() -> Optional[str]:
    """Why the live network probes must not run, or None."""
    if os.environ.get(LIVE_ENV) != "1":
        return (f"live network probes are off ({LIVE_ENV}=1 and {TARGETS_ENV} are set "
                "only by the Kubernetes manifests)")
    try:
        if not parse_targets(os.environ.get(TARGETS_ENV, "")):
            return f"{TARGETS_ENV} names no destination"
    except ValueError as e:
        return str(e)
    return None


def network_checks(extra: Tuple[Tuple[str, int], ...] = ()) -> List[Tuple[str, Callable]]:
    """The configured destinations plus the cluster's own (live mode only; main()
    refuses before this when live_problem() is not None)."""
    checks = parse_targets(os.environ.get(TARGETS_ENV, ""))
    api_host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if api_host and api_port.isdigit():
        port = int(api_port)
        checks.append((f"tcp {api_host}:{port} (Kubernetes API)",
                       lambda: tcp_probe(api_host, port)))
    for server in nameservers():
        checks.append((f"udp {server}:53 (cluster DNS)", lambda s=server: udp_dns_probe(s)))
        checks.append((f"tcp {server}:53 (cluster DNS)", lambda s=server: tcp_probe(s, 53)))
    for host, port in extra:
        checks.append((f"tcp {host}:{port} (operator target)",
                       lambda h=host, p=port: tcp_probe(h, p)))
    return checks


def intel_target() -> Optional[Tuple[str, int]]:
    """The intel Service address analysis may reach (option E), or None."""
    url = os.environ.get("AEGIS_INTEL_URL", "")
    if not url:
        return None
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    if parts.scheme != "https" or not parts.hostname or not port:
        raise ValueError(f"AEGIS_INTEL_URL is not https://ADDRESS:PORT: {url!r}")
    return parts.hostname, port


def intel_reachable() -> List[Result]:
    """verify mode's positive control: the one allowed destination must answer, so
    the blocked probes are shown to be blocked by policy, not by a dead network."""
    try:
        target = intel_target()
    except ValueError as e:
        return [("intel reachable (the one allowed destination)", False, str(e))]
    if target is None:
        return []
    blocked, detail = tcp_probe(*target)
    return [(f"reachable: intel {target[0]}:{target[1]} (allowed, positive control)",
             not blocked, detail)]


def run_network(extra: Tuple[Tuple[str, int], ...] = ()) -> List[Result]:
    """Every destination at once, so the gate takes about one time-out."""
    checks = network_checks(extra)
    out: List[Optional[Result]] = [None] * len(checks)

    def one(i: int, name: str, probe: Callable) -> None:
        try:
            blocked, detail = probe()
        except Exception as e:  # a broken probe must not pass
            blocked, detail = False, f"probe error: {type(e).__name__}"
        out[i] = (f"blocked: {name}", blocked, detail)

    threads = [threading.Thread(target=one, args=(i, n, p), daemon=True)
               for i, (n, p) in enumerate(checks)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + WAIT
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    # Still waiting (a resolver retrying a server that never answers): nothing came
    # back, which is what blocked looks like.
    return [r if r is not None else (f"blocked: {checks[i][0]}", True,
                                     f"no answer within {WAIT:.0f} s")
            for i, r in enumerate(out)]


def _status(field: str) -> str:
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith(field + ":"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return ""


def _mount_options(path: str) -> List[str]:
    best = ("", "")
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if (path == parts[1] or path.startswith(parts[1].rstrip("/") + "/")) \
                        and len(parts[1]) >= len(best[0]):
                    best = (parts[1], parts[3])
    except OSError:
        pass
    return best[1].split(",")


def _pids_max() -> str:
    try:
        with open("/sys/fs/cgroup/pids.max") as fh:
            return fh.read().strip()
    except OSError:
        return "unreadable"


def posture_checks() -> List[Result]:
    """The container's own hardening, as the kernel reports it."""
    res: List[Result] = []
    res.append(("not root", os.getuid() != 0, f"uid {os.getuid()} gid {os.getgid()}"))
    res.append(("no capabilities", int(_status("CapEff") or "1", 16) == 0, _status("CapEff")))
    res.append(("no-new-privileges", _status("NoNewPrivs") == "1", _status("NoNewPrivs")))
    res.append(("seccomp filter", _status("Seccomp") == "2", f"Seccomp {_status('Seccomp')}"))
    res.append(("read-only root fs", "ro" in _mount_options("/"),
                ",".join(_mount_options("/")[:2])))
    res.append(("no service-account token", not os.path.exists(SERVICE_ACCOUNT), SERVICE_ACCOUNT))
    allowed = INTEL_CLIENT_SETTINGS if os.environ.get("AEGIS_INTEL_URL") else ()
    held = [k for k in EXTERNAL_SETTINGS if k not in allowed
            and (os.environ.get(k) or os.environ.get(k + "_FILE"))]
    res.append(("no external-service setting", not held, ",".join(held) or "none"))
    res.append(("detection content mounted read-only", "ro" in _mount_options(CONTENT), CONTENT))
    probe = os.path.join(CONTENT, ".aegis-gate-write-test")
    try:
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("x")
        # a failed check must not leave a file in the detection content
        try:
            os.remove(probe)
        except OSError:
            pass
        res.append(("cannot write detection content", False, "written"))
    except OSError as e:
        res.append(("cannot write detection content", True, e.strerror or type(e).__name__))
    return res


def info_lines() -> List[str]:
    """Known differences from Docker; reported, not failed (docs/KUBERNETES.md)."""
    tmp = _mount_options(SCRATCH)
    return [f"{SCRATCH} mount options: {','.join(tmp[:6])} (emptyDir: Kubernetes sets no noexec)",
            f"container pids.max: {_pids_max()} (the node's podPidsLimit is the Pod limit)"]


def report(role: str, results: List[Result]) -> int:
    width = max((len(n) for n, _, _ in results), default=0)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {role:8} {name.ljust(width)}  {detail}", flush=True)
    return 0 if all(ok for _, ok, _ in results) else 1


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    mode = args[0] if args else ""
    if mode == "posture":
        code = report("analysis", posture_checks())
        for line in info_lines():
            print(f"INFO  analysis {line}")
        return code
    if mode in ("gate", "ready", "verify"):
        problem = live_problem()
        if problem:
            print(f"refused: {problem}; nothing was contacted", file=sys.stderr)
            return 2
    if mode == "gate":
        return report("gate", run_network())
    if mode == "ready":
        failed = [r for r in run_network() if not r[1]]
        if failed:
            return report("ready", failed)
        from api.probe import main as probe  # the image's PYTHONPATH (/app)
        return probe([API_SOCKET, "/ready"])
    if mode == "verify":
        try:
            extra = tuple(parse_target(a) for a in args[1:])
        except ValueError as e:
            print(e, file=sys.stderr)
            return 2
        code = report("analysis", posture_checks() + intel_reachable() + run_network(extra))
        for line in info_lines():
            print(f"INFO  analysis {line}")
        return code
    print(__doc__.split("\n\n")[2], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
