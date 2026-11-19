"""Diagram 11 - option E: how the analysis Pod reaches intel on Kubernetes.

Read from deploy/kubernetes/components/intel/ (intel.yaml, networkpolicy.yaml,
analysis-patch.yaml, kustomization.yaml), core/intel_client.py (TLS transport,
read_reply), api/intel.py (operations, token, rate limits) and docs/KUBERNETES.md
("Intel: external services"). Implemented and checked statically and against a
local TLS server; never run on a cluster.
"""

from __future__ import annotations

from typing import List

from umlkit import MUTED, Diagram

TITLE = "Option E: the analysis Pod talks to intel over TLS on one port"

POD = "#7c3aed"
BOUND = "#b91c1c"
CONT = "#f0fdf4"
STORE = "#f8fafc"
EXT = "#f1f5f9"
RULE = "#fef3c7"


def build(meta: dict) -> object:
    d = Diagram("d11", 1600, 715, TITLE,
                f"Optional component deploy/kubernetes/components/intel, commit {meta['k8s_commit']}. "
                "Implemented and statically checked; NOT yet run on a cluster.",
                "Kubernetes option E: analysis container connects by fixed ClusterIP to the intel "
                "Service on 9443, verifies the intel certificate by name against a private CA, "
                "authenticates with a bearer token; NetworkPolicies allow only that path; intel "
                "alone reaches the external services.")
    d.title_block()
    d.frame(24, 92, 1150, 600, "Namespace aegis-sentinel (Pod Security: restricted; default-deny "
            "NetworkPolicy)", fill="#ffffff")

    # analysis Pod
    d.rect(48, 140, 470, 400, "#faf5ff", POD, 2.2, 8, "frame")
    d.text(62, 162, "Pod aegis-analysis (unchanged base + patch)", 13, True, fill=POD,
           layer="frame", maxw=440)
    proxy = d.titled(72, 184, 420, "proxy (Caddy, uid 10003)",
                     ["TLS on 8443 for API clients; forwards to api.sock"], fill=CONT, stroke=BOUND,
                     sw=2.4, name="proxy")
    ana = d.titled(72, proxy.bottom + 40, 420, "analysis (api.server + workers, uid 10001)",
                   ["AEGIS_INTEL_URL = https://<fixed ClusterIP>:9443 (no DNS lookup)",
                    "AEGIS_INTEL_SERVER_NAME = aegis-intel.aegis-sentinel.svc",
                    "AEGIS_INTEL_CA_FILE from ConfigMap aegis-intel-ca",
                    "AEGIS_INTEL_TOKEN_FILE from Secret aegis-intel-token",
                    "no external-service key; LLM_PROVIDER=none in its own env"],
                   fill=CONT, stroke=BOUND, sw=2.4, align="start", name="analysis")
    d.edge([proxy.b(0.5), ana.t(0.5)], "msg", "api.sock (Unix socket)",
           (proxy.cx + 90, (proxy.bottom + ana.top) / 2), (proxy, ana))
    d.titled(72, ana.bottom + 18, 420, "What the client enforces (core/intel_client.py)",
                   ["TLS 1.2+, certificate required, name checked against SERVER_NAME, only the "
                    "private CA trusted (re-read on every connection); no redirects, no proxy "
                    "variables, no retries; reply at most 1 MiB, identity encoding, JSON object "
                    "with status 200, else an error"], fill=RULE, size=12, align="start",
                   name="client checks")

    # service
    svc = d.node(560, 300, 190, ["Service aegis-intel", "ClusterIP (fixed)", "port 9443"],
                 fill=STORE, bold=[True, False, False], size=12.5, name="service")
    d.edge([(ana.right, ana.cy - 30), (svc.left, ana.cy - 30)], "flow", ["TLS +", "token"],
           ((ana.right + svc.left) / 2 + 2, ana.cy - 58), (ana, svc))

    # intel Pod
    d.rect(790, 140, 360, 400, "#faf5ff", POD, 2.2, 8, "frame")
    d.text(804, 162, "Pod aegis-intel (optional)", 13, True, fill=POD, layer="frame", maxw=330)
    ip = d.titled(812, 184, 316, "intel-proxy (Caddy, uid 10003)",
                  ["TLS 1.2/1.3 on 9443 with Secret aegis-intel-tls (leaf for "
                   "aegis-intel.<ns>.svc); body cap 101 MiB; to intel.sock"],
                  fill=CONT, stroke=BOUND, sw=2.4, name="intel-proxy")
    it = d.titled(812, ip.bottom + 40, 316, "intel (api.intel, uid 10002)",
                  ["token >= 32 chars (Secret aegis-intel-token), compared in constant time; "
                   "fixed operations only: VirusTotal lookup/upload, LLM analyze, sandbox "
                   "submit/poll, alert e-mail; per-operation rate limits; keys from Secret "
                   "aegis-intel-credentials; answer cache on claim aegis-intel-state"],
                  fill=CONT, stroke=BOUND, sw=2.4, name="intel")
    d.edge([ip.b(0.5), it.t(0.5)], "msg", "intel.sock", (ip.cx + 50, (ip.bottom + it.top) / 2),
           (ip, it))
    d.edge([svc.r(0.5), (ip.left, svc.cy)], "flow", ends=(svc, ip))

    # policies
    d.titled(560, 400, 190, "NetworkPolicies",
                   ["analysis egress: only TCP 9443 to component=intel",
                    "intel ingress: only 9443 from analysis",
                    "intel egress: kube-dns 53; 443, 465, 587 to public addresses"],
                   fill=RULE, size=12, name="policies")

    d.note(48, 560, 1100, [
        "Requires a network plugin that enforces ingress and egress policy and evaluates it after "
        "ClusterIP translation (Calico, Cilium and Antrea do). Without enforcement the analysis Pod "
        "has full network access; the isolation gate (init container and readiness probe) then "
        "fails the Pod because DNS, the API server or the internet answers. The gate is a sample, "
        "not a proof. Analysis readiness does not depend on intel: while intel is down, external "
        "layers report 'unreachable' and the scan is partial.",
        "Rotation: a new leaf from the same CA needs an intel restart only; a CA change uses both "
        "CAs in aegis-intel-ca during the overlap; a new token needs both Deployments restarted."],
        size=12)

    # externals
    ex = 1210
    d.text(ex, 120, "Reached only by intel", 13, True, fill=MUTED)
    y = 140.0
    for title, body in (("VirusTotal", "SHA-256 lookup; upload only with VT_UPLOAD_UNKNOWN"),
                        ("LLM (OpenAI or Ollama)", "up to 8,000 characters of text"),
                        ("CAPE sandbox", "the whole file; an internal server needs its own "
                                         "egress rule in the overlay"),
                        ("SMTP server", "metadata-only alert e-mail over TLS")):
        b = d.titled(ex, y, 360, title, [body], fill=EXT, size=12, name=title)
        d.edge([(it.right, it.cy), (1180, it.cy), (1180, b.cy), b.l()], "msg", ends=(it, b),
               check=False)
        y = b.bottom + 16
    blk = d.titled(ex, y + 20, 360, "Blocked for both Pods",
                   ["cloud metadata 169.254.169.254, link-local, loopback, private ranges "
                    "(intel), everything except 9443 to intel (analysis)"],
                   fill="#fee2e2", size=12, name="blocked")
    _ = blk
    return d


NOTES: List[str] = [
    "check_manifests.py verifies these settings offline (URL equals the Service ClusterIP on "
    "9443, server name, CA from a ConfigMap, token from the Secret, exactly the 9443 egress rule "
    "for analysis, intel egress without link-local or loopback). Enforcement at run time needs "
    "a cluster and verify-cluster.sh; it has not been run.",
    "The intel service has no failed-token lockout (the REST API has one); it rate-limits per "
    "operation, not per client.",
]
