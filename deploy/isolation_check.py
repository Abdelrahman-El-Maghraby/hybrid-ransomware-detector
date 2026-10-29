"""Run INSIDE a running container (deploy/check-deployment.sh pipes it in):

    docker compose exec -T analysis python - analysis < deploy/isolation_check.py
    docker compose exec -T intel    python - intel    < deploy/isolation_check.py

analysis: no network interface but loopback; no outbound TCP, UDP or DNS; the
intel socket answers, refuses a wrong token and has no generic operation; the
detection content is read-only; the containment code is absent.
both: not root, no capabilities, no-new-privileges, seccomp filtering, read-only
root file system, /tmp mounted noexec.
intel: no TCP or UDP listener; its sessions refuse destinations outside the
allowlist. Prints one line per check and exits 1 when any fails.
"""

import importlib.util
import json
import os
import socket
import sys

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))


def status_field(field):
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith(field + ":"):
                return line.split(":", 1)[1].strip()
    return ""


def mount_options(path):
    best = ("", "")
    with open("/proc/mounts") as fh:
        for line in fh:
            parts = line.split()
            if (path == parts[1] or path.startswith(parts[1].rstrip("/") + "/")) \
                    and len(parts[1]) >= len(best[0]):
                best = (parts[1], parts[3])
    return best[1].split(",")


def blocked(connect):
    try:
        connect()
    except OSError as e:
        return True, type(e).__name__ + ": " + (e.strerror or str(e))
    return False, "connected"


def tcp(host, port, family=socket.AF_INET):
    def go():
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))
    return go


def udp(host, port):
    def go():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(b"\0" * 12, (host, port))
            s.recv(512)
    return go


def common(role):
    check("not root", os.getuid() != 0, f"uid {os.getuid()}")
    check("no capabilities", int(status_field("CapEff") or "1", 16) == 0, status_field("CapEff"))
    check("no-new-privileges", status_field("NoNewPrivs") == "1")
    check("seccomp filter", status_field("Seccomp") == "2", f"Seccomp {status_field('Seccomp')}")
    check("read-only root fs", "ro" in mount_options("/"), ",".join(mount_options("/")[:2]))
    tmp = mount_options("/tmp")  # noqa: S108  # nosec B108 - reads mount options only
    check("tmp is noexec,nosuid", "noexec" in tmp and "nosuid" in tmp, ",".join(tmp[:6]))


def analysis():
    # The kernel creates down tunnel devices (sit0, gre0, ...) in every namespace;
    # what matters is that nothing but loopback is up and that no route exists.
    up = []
    for name in sorted(os.listdir("/sys/class/net")):
        if not os.path.isfile(f"/sys/class/net/{name}/flags"):    # bonding_masters
            continue
        with open(f"/sys/class/net/{name}/flags") as fh:
            if int(fh.read().strip(), 16) & 0x1:              # IFF_UP
                up.append(name)
    check("only loopback is up", up == ["lo"], str(up))
    with open("/proc/net/route") as fh:
        routes = fh.read().splitlines()[1:]
    check("no IPv4 route", routes == [], f"{len(routes)} route(s)")
    for name, attempt in (("tcp 1.1.1.1:443", tcp("1.1.1.1", 443)),
                          ("tcp 8.8.8.8:53", tcp("8.8.8.8", 53)),
                          ("tcp 169.254.169.254:80 (cloud metadata)", tcp("169.254.169.254", 80)),
                          ("tcp host.docker.internal gateway 172.17.0.1:80", tcp("172.17.0.1", 80)),
                          ("udp 8.8.8.8:53", udp("8.8.8.8", 53)),
                          ("dns www.virustotal.com",
                           lambda: socket.getaddrinfo("www.virustotal.com", 443))):
        ok, why = blocked(attempt)
        check(f"blocked: {name}", ok, why)
    if socket.has_ipv6:
        ok, why = blocked(tcp("2606:4700:4700::1111", 443, socket.AF_INET6))
        check("blocked: tcp [2606:4700:4700::1111]:443", ok, why)

    from core.intel_client import IntelClient, IntelError, unix_request
    path = os.environ["AEGIS_INTEL_SOCKET"]
    with open(os.environ["AEGIS_INTEL_TOKEN_FILE"]) as fh:
        token = fh.read().strip()
    status, _ = unix_request(path, "GET", "/health")
    check("intel socket reachable", status == 200, f"HTTP {status}")
    caps = IntelClient(path, token).call("GET", "/v1/capabilities")
    check("intel answers with the token", "virustotal" in caps)
    status, _ = unix_request(path, "GET", "/v1/capabilities")
    check("intel refuses no token", status == 401, f"HTTP {status}")
    for url in ("/v1/fetch", "/v1/proxy", "/v1/http"):
        status, _ = unix_request(path, "POST", url, json.dumps({"url": "https://example.com"}).encode(),
                                 {"Authorization": f"Bearer {token}",
                                  "Content-Type": "application/json"})
        check(f"intel has no {url}", status == 404, f"HTTP {status}")
    try:
        IntelClient(path, token).call("POST", "/v1/virustotal/lookup", {"sha256": "../../etc"})
        check("intel validates input", False, "accepted")
    except IntelError as e:
        check("intel validates input", "HTTP 422" in str(e) or "HTTP 403" in str(e), str(e))
    # the e-mail operation (4.8): fixed fields only; with no SMTP settings it is refused
    alert = {"alert_id": "0" * 32, "kind": "verdict", "verdict": "High", "risk_band": "60-80",
             "sha256": "", "file_name": "x.pdf", "time": "t", "scan_id": "",
             "reason_codes": [], "to": "attacker@example.com"}
    status, _ = unix_request(path, "POST", "/v1/alert/email", json.dumps(alert).encode(),
                             {"Authorization": f"Bearer {token}",
                              "Content-Type": "application/json"})
    check("intel e-mail refuses unknown fields", status in (403, 422), f"HTTP {status}")
    alert.pop("to")
    status, _ = unix_request(path, "POST", "/v1/alert/email", json.dumps(alert).encode(),
                             {"Content-Type": "application/json"})
    check("intel e-mail needs the token", status == 401, f"HTTP {status}")
    check("intel e-mail off without SMTP settings", caps.get("email") == {"enabled": False},
          str(caps.get("email")))
    check("no SMTP setting on the analysis side",
          not any(os.environ.get(k) for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD",
                                               "SMTP_PASSWORD_FILE", "ALERT_EMAIL_TO")))

    content = "/var/lib/aegis/RansomwareScanner/data"
    check("detection content read-only", "ro" in mount_options(content), content)
    try:
        with open(os.path.join(content, "allowlist.txt"), "a") as fh:
            fh.write("x")
        check("cannot write the allowlist", False, "written")
    except OSError as e:
        check("cannot write the allowlist", True, e.strerror)
    check("containment code absent", importlib.util.find_spec("core.containment") is None
          and importlib.util.find_spec("core.response") is None)


def listening():
    found = []
    for table in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(table) as fh:
                rows = fh.read().splitlines()[1:]
        except OSError:
            continue
        found += [table + " " + r.split()[1] for r in rows if r.split()[3] in ("0A", "07")
                  and not r.split()[1].startswith(DOCKER_DNS)]
    return found


DOCKER_DNS = "0B00007F:"      # 127.0.0.11: Docker's resolver, put in every user network


def intel():
    check("no TCP/UDP listener", listening() == [], str(listening()))
    from api.intel import VIRUSTOTAL_ORIGIN, IntelService
    from core.http import EgressDenied, build_session
    from engine.config import CONFIG
    service = IntelService(CONFIG)
    for name, session in (("allowlisted", build_session(allowed_origins=[VIRUSTOTAL_ORIGIN])),
                          ("llm", service.llm.__dict__.get("http")),
                          ("sandbox", getattr(service.sandbox, "session", None)),
                          ("virustotal", getattr(service._vt, "http", None))):
        if session is None or not hasattr(session, "allowed"):
            continue
        try:
            session.get("https://example.com/", timeout=5)
            check(f"{name} session refuses example.com", False, "connected")
        except EgressDenied as e:
            check(f"{name} session refuses example.com", True, str(e))


def main():
    role = sys.argv[1] if len(sys.argv) > 1 else ""
    common(role)
    {"analysis": analysis, "intel": intel}[role]()
    width = max(len(n) for n, _, _ in RESULTS)
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {role:8} {name.ljust(width)}  {detail}")
    return 0 if all(ok for _, ok, _ in RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
