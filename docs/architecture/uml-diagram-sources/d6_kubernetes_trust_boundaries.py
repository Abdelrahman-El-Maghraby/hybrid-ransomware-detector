"""Diagram 6 - Kubernetes deployment and trust boundaries (optional deployment).

The manifests in deploy/kubernetes/ (docs/KUBERNETES.md): one Pod with the
analysis service and the TLS proxy, an init container that checks the network
isolation, two claims, and an on-demand content Job. The Docker deployment is
diagram 5 and is not redrawn here. Every element is taken from the manifests
named in the notes.

A purple frame is a Pod: one network namespace, the unit NetworkPolicy applies
to (enforced by the cluster's network plugin). A thick red frame is a container:
its own user, mounts and processes, but the Pod's network. A dashed frame is
process separation inside one container user: not a security boundary.

Edit the texts and coordinates below, then run `python3 build_diagrams.py`.
"""

from __future__ import annotations

from typing import List

from umlkit import Box, Diagram

TITLE = "Kubernetes deployment: Pods, containers and what separates them"

PROC = "#eff6ff"        # a process
CONT = "#f0fdf4"        # a container
STORE = "#f8fafc"       # claims, volumes, API objects
EXT = "#f1f5f9"         # an external service this deployment does not reach
BLOCK = "#fee2e2"       # destinations the policy blocks
BOUND = "#b91c1c"       # container boundary stroke
POD = "#7c3aed"         # Pod (network namespace) stroke
SOFT = "#64748b"        # process-separation stroke


def container(d: Diagram, x: float, y: float, w: float, h: float, title: str,
              body: List[str], name: str) -> Box:
    """A container: thick solid boundary, title and wrapped body."""
    return d.titled(x, y, w, title, body, h=h, fill=CONT, stroke=BOUND, sw=3, rx=6, name=name)


def build(meta: dict) -> Diagram:
    d = Diagram("d6", 1600, 1090, TITLE,
                f"The optional Kubernetes deployment (deploy/kubernetes). Branch "
                f"{meta['branch']}, manifests at commit {meta['k8s_commit']}.",
                "Kubernetes deployment and trust-boundary diagram of Aegis Sentinel: one Pod "
                "with the TLS proxy and the analysis service joined by a Unix socket, an "
                "isolation-gate init container, two single-Pod claims, a content Job, and the "
                "destinations the NetworkPolicy blocks.")
    d.title_block()

    # ---------------------------------------------------------------- legend
    lx, ly = 760, 22
    d.rect(lx, ly - 10, 820, 62, "#f8fafc", "#94a3b8", 1, 6, "frame")
    d.edge([(lx + 14, ly + 8), (lx + 58, ly + 8)], "flow", check=False)
    d.text(lx + 66, ly + 12, "file content", 12)
    d.edge([(lx + 160, ly + 8), (lx + 204, ly + 8)], "msg", check=False)
    d.text(lx + 212, ly + 12, "results, reads and writes, checks (metadata)", 12)
    d.rect(lx + 520, ly, 40, 16, PROC, SOFT, 1.4, 3, "frame", "6 4")
    d.text(lx + 568, ly + 12, "process separation, not a security boundary", 12)
    d.rect(lx + 14, ly + 26, 40, 16, "#ffffff", POD, 2, 3, "frame")
    d.text(lx + 62, ly + 38, "Pod: one network namespace; NetworkPolicy applies here", 12)
    d.rect(lx + 470, ly + 26, 40, 16, CONT, BOUND, 3, 3, "frame")
    d.text(lx + 518, ly + 38, "container: own user, mounts, processes", 12)

    # ---------------------------------------------------------------- cluster
    d.frame(20, 90, 1190, 980, "Kubernetes cluster: namespace aegis-sentinel",
            sub="Pod Security restricted. NetworkPolicy: default deny; ingress TCP 8443 to the "
                "analysis Pod only; no egress anywhere. Enforced only by a network plugin "
                "that implements it.")
    client = d.titled(40, 170, 220, "API client", "HTTPS, bearer token", h=70, fill=STORE)
    svc = d.titled(40, 290, 220, "Service aegis-sentinel :8443",
                   ["ClusterIP in the base; LoadBalancer or NodePort with "
                    "externalTrafficPolicy Local keeps the client address"],
                   h=116, fill=STORE, name="service")
    d.note(40, 440, 220,
           ["The node: the kubelet runs the exec probes. NetworkPolicy always allows traffic "
            "between a Pod and its own node. The kubelet's podPidsLimit is the only process "
            "limit."])
    d.titled(40, 600, 220, "ConfigMaps",
             ["aegis-analysis-config (settings, public rule-pack keys) and "
              "aegis-isolation-gate (isolation_gate.py), mounted read-only"],
             h=104, fill=STORE, name="configmaps")
    d.titled(40, 730, 220, "Secrets, created by the operator",
             ["aegis-api-token (analysis only), aegis-tls (proxy only); stored in etcd: "
              "encryption at rest and RBAC are the cluster's"],
             h=122, fill=STORE, name="secrets")

    d.frame(290, 150, 700, 670, "Pod aegis-analysis: one replica, Recreate",
            stroke=POD, fill="#faf5ff",
            sub="No service-account token; fsGroup 10001; RuntimeDefault seccomp; "
                "grace period 330 s.")
    gate = container(d, 310, 205, 660, 70, "init: prepare-state, then isolation-gate (uid 10001)",
                     ["creates the state folders as 10001; then fails while the internet, DNS, "
                      "the Kubernetes API or the metadata address answers (again in every "
                      "readiness probe)"], "gate")
    proxy = container(d, 310, 300, 230, 150, "proxy (Caddy)",
                      ["uid 10003; port 8443; TLS ends here.",
                       "Secret aegis-tls; emptyDirs /data, /config."], "proxy")
    sock = d.titled(310, 470, 230, "emptyDir api-socket", "api.sock; this Pod only", h=66,
                    fill=STORE, name="socket")
    analysis = container(d, 590, 300, 380, 236, "analysis: api.server (_ScanService)",
                         ["uid 10001; listens on api.sock only; no egress.",
                          "Secret aegis-api-token only. AEGIS_PROFILE production, "
                          "LLM_PROVIDER none.",
                          "/tmp: memory-backed emptyDir, 2 GiB, "  # noqa: S108
                          "without noexec; cleared at every start."],
                         "analysis")
    d.frame(590, 556, 380, 110, "Workers, same uid 10001", stroke=SOFT, dash="6 4",
            fill="#ffffff")
    worker = d.titled(605, 596, 350, "Scan workers",
                      "time and memory limits; a fresh one per upload", h=56, fill=PROC,
                      name="worker")
    d.note(310, 690, 660,
           ["The containers share the Pod's network: the proxy and analysis have the same "
            "interface and neither may send anything out. Analysis opens no port; the "
            "proxy reaches it only through the socket."])

    state = d.titled(1010, 300, 180, "PVC aegis-analysis-state",
                     "ReadWriteOncePod, 2 GiB: the log file", h=84, fill=STORE, name="state")
    content = d.titled(1010, 410, 180, "PVC aegis-content",
                       "ReadWriteOncePod, 1 GiB: rule packs; read-only in analysis", h=96,
                       fill=STORE, name="content")
    job = container(d, 290, 850, 700, 96, "Job aegis-content-update (on demand)",
                    ["uid 10001; no egress. Runs only while analysis is scaled to zero "
                     "(content-update.sh); installs a signed pack from the ConfigMap "
                     "aegis-rulepack-import with --update-rules."], "job")
    d.note(40, 975, 1150,
           ["Not deployed on Kubernetes: the intel service. VirusTotal, the LLM, CAPE and "
            "e-mail alerts are off. Adding them needs a network path from the analysis Pod: "
            "owner decision K8S-1 (docs/KUBERNETES.md, \"Intel\")."])

    d.edge([client.b(), svc.t()], "flow", "upload", (150, 265), (client, svc))
    py = svc.cy
    d.edge([svc.r(), (proxy.left, py)], "flow", ends=(svc, proxy), name="service to proxy")
    d.edge([proxy.b(), sock.t()], "flow", ends=(proxy, sock), name="proxy to socket")
    d.edge([sock.r(), (analysis.left, sock.cy)], "flow", ends=(sock, analysis),
           name="socket to analysis")
    ry = analysis.side("left", 0.2)[1]
    d.edge([(analysis.left, ry), (proxy.right, ry)], "msg", ends=(analysis, proxy),
           name="result to proxy")
    d.label(565, ry - 14, "result", 12)
    d.edge([analysis.b(), worker.t()], "flow", "file path; JSON replies", (850, 546),
           (analysis, worker))
    d.edge([(analysis.right, state.cy), state.l()], "msg", ends=(analysis, state),
           name="analysis to state")
    d.edge([content.l(), (analysis.right, content.cy)], "msg", ends=(content, analysis),
           name="content to analysis")
    d.edge([job.r(), (1100, job.cy), (1100, content.bottom)], "msg", "writes", (1100, 700),
           (job, content))

    # ------------------------------------------------- outside the namespace
    d.frame(1230, 90, 350, 980, "Outside the namespace",
            sub="What the analysis Pod must not reach.")
    blocked = d.titled(1250, 170, 310, "Blocked by NetworkPolicy",
                       ["the internet (IPv4, IPv6), public and cluster DNS, the Kubernetes "
                        "API, cloud metadata 169.254.169.254; the gate checks each one"],
                       h=110, fill=BLOCK, name="blocked")
    gy = gate.cy
    d.edge([gate.r(), (blocked.left, gy)], "msg", "must not answer", (1110, gy - 14),
           (gate, blocked))
    y = 330
    for title in ("VirusTotal", "LLM: OpenAI or Ollama", "CAPE sandbox", "SMTP server"):
        d.titled(1250, y, 310, title, "not configured, not reachable: no intel", h=62,
                 fill=EXT, name=title)
        y += 86
    d.note(1250, y + 10, 310,
           ["The Docker deployment reaches these through its intel container (diagram 5). "
            "On Kubernetes no part of Aegis Sentinel holds their credentials."])
    return d


NOTES: List[str] = [
    "One Pod, two containers: analysis (python -m api.server, uid 10001) and proxy (the "
    "aegis-sentinel-proxy image with deploy/Caddyfile, uid 10003), joined by api.sock in a "
    "memory-backed emptyDir, as in docker-compose.yml (deploy/kubernetes/base/analysis.yaml).",
    "Containers in one Pod share its network namespace, and NetworkPolicy applies to Pods, "
    "not containers. aegis-default-deny selects every Pod for ingress and egress with no "
    "rule; aegis-allow-https admits TCP 8443 to the analysis Pod. No policy allows egress "
    "(deploy/kubernetes/base/networkpolicy.yaml).",
    "The init container prepare-state creates RansomwareScanner/data in the state claim as "
    "uid 10001 (the runtime would create that mount point as root). Then isolation-gate and "
    "the analysis readiness probe run "
    "isolation_gate.py from the ConfigMap aegis-isolation-gate: a connection that succeeds "
    "or a DNS answer fails them. Liveness asks only /health on the socket.",
    "Secrets: aegis-api-token mounted only in analysis, aegis-tls only in proxy, both mode "
    "0440; automountServiceAccountToken false; no Role. No external-service credential "
    "exists in this deployment (check_manifests.py refuses one).",
    "Claims aegis-analysis-state and aegis-content are ReadWriteOncePod; analysis mounts the "
    "content read-only (both in the volume and the mount). The content Job "
    "(deploy/kubernetes/jobs/content-update.yaml) is the only writer and can mount it only "
    "while analysis is scaled to zero.",
    "Differences from Docker (diagram 5): a Pod interface exists where Docker has none; "
    "/tmp is an emptyDir without noexec; the process limit is the node's podPidsLimit; "
    "intel is not deployed. Runtime behaviour on a cluster is unverified "
    "(deploy/kubernetes/verify-cluster.sh).",
]
