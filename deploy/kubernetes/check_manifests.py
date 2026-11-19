#!/usr/bin/env python3
"""Check rendered Aegis Sentinel Kubernetes manifests before they are applied.

    kubectl kustomize deploy/kubernetes/overlays/MY-OVERLAY > aegis.yaml
    python3 deploy/kubernetes/check_manifests.py aegis.yaml

Reads the YAML (a file, or - for standard input) and prints one line per broken
invariant (docs/KUBERNETES.md, "Checks"). Exit 0 when there is none. It checks
what the manifests say, not what a cluster does with them: admission, the
network plugin and the storage driver are checked by verify-cluster.sh.

    --allow-placeholders   accept the base's placeholder images and REPLACE values
                           (for checking the base itself)
    --allow-rwo            accept ReadWriteOnce claims (see docs/KUBERNETES.md,
                           "Storage", for what that gives up)

Needs PyYAML. Writes nothing.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from typing import Any, Dict, Iterable, List, Optional

import yaml

NAMESPACE = "aegis-sentinel"
UIDS = {"analysis": 10001, "isolation-gate": 10001, "prepare-state": 10001, "content": 10001,
        "proxy": 10003, "intel": 10002, "intel-proxy": 10003}
ANALYSIS_SECRETS = {"aegis-api-token"}
PROXY_SECRETS = {"aegis-tls"}
# Option E (components/intel, docs/KUBERNETES.md K8S-1)
INTEL_PORT = 9443
INTEL_LABELS = {"app.kubernetes.io/name": "aegis-sentinel", "app.kubernetes.io/component": "intel"}
ANALYSIS_LABELS = {"app.kubernetes.io/name": "aegis-sentinel",
                   "app.kubernetes.io/component": "analysis"}
INTEL_CLIENT_SECRETS = {"aegis-intel-token"}
INTEL_SECRETS = {"aegis-intel-token", "aegis-intel-credentials"}
INTEL_PROXY_SECRETS = {"aegis-intel-tls"}
INTEL_CLIENT_ENV = {"AEGIS_INTEL_URL", "AEGIS_INTEL_SERVER_NAME", "AEGIS_INTEL_CA_FILE",
                    "AEGIS_INTEL_TOKEN_FILE"}
# Never reachable by intel through a default route: link-local (cloud metadata),
# loopback, and the private ranges a cluster's Pods and Services live in
GUARDED_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]
ALWAYS_GUARDED = [ipaddress.ip_network(n) for n in
                  ("127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10")]
EXTERNAL_WORDS = ("VIRUSTOTAL", "OPENAI", "SANDBOX_URL", "SANDBOX_TOKEN", "SMTP_",
                  "ALERT_EMAIL_TO", "ALERT_EMAIL_FROM", "AEGIS_INTEL", "OLLAMA_HOST",
                  "WEBHOOK", "CLOUD_")
SECRET_WORDS = re.compile(r"(TOKEN|PASSWORD|SECRET|API_KEY|PRIVATE)", re.I)
PUBLIC_KEYS = {"RULEPACK_PUBLIC_KEYS"}           # public by design (docs/RULE_PACKS.md)
WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Pod"}
FORBIDDEN_KINDS = {"HorizontalPodAutoscaler", "Role", "ClusterRole", "RoleBinding",
                   "ClusterRoleBinding", "Ingress", "PodDisruptionBudget"}
CONTENT_PATH = "/var/lib/aegis/RansomwareScanner/data"
SCRATCH = "/tmp"  # noqa: S108  # nosec B108  # a mount path compared in manifests, never opened
# Outside destinations the isolation gate must probe (isolation_gate.py live mode)
GATE_TARGETS = {"tcp:1.1.1.1:443", "tcp:8.8.8.8:53", "udp53:8.8.8.8",
                "tcp:[2606:4700:4700::1111]:443", "tcp:169.254.169.254:80",
                "dns:www.virustotal.com", "dns:kubernetes.default.svc"}
PLACEHOLDER = re.compile(r"SET-VERSION-IN-OVERLAY|REPLACE")


def pod_spec(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = obj.get("kind")
    if kind == "Pod":
        return obj.get("spec") or {}
    if kind == "CronJob":
        return (((obj.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}) \
            .get("template", {}).get("spec") or {}
    if kind in WORKLOADS:
        return ((obj.get("spec") or {}).get("template") or {}).get("spec") or {}
    return None


def _name(obj: Dict[str, Any]) -> str:
    return f"{obj.get('kind')}/{(obj.get('metadata') or {}).get('name')}"


def _image_ok(image: str) -> Optional[str]:
    if "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "has no tag or digest (it would mean latest)"
    if last.rsplit(":", 1)[1] == "latest":
        return "uses the latest tag"
    return None


def check_container(owner: str, c: Dict[str, Any], pod: Dict[str, Any],
                    allow_placeholders: bool) -> List[str]:
    p: List[str] = []
    where = f"{owner} container {c.get('name')}"
    sc = c.get("securityContext") or {}
    psc = pod.get("securityContext") or {}
    if sc.get("allowPrivilegeEscalation") is not False:
        p.append(f"{where}: allowPrivilegeEscalation must be false")
    if sc.get("privileged"):
        p.append(f"{where}: privileged")
    if sc.get("readOnlyRootFilesystem") is not True:
        p.append(f"{where}: readOnlyRootFilesystem must be true")
    caps = sc.get("capabilities") or {}
    if caps.get("drop") != ["ALL"] or caps.get("add"):
        p.append(f"{where}: capabilities must drop ALL and add none")
    if sc.get("runAsNonRoot", psc.get("runAsNonRoot")) is not True:
        p.append(f"{where}: runAsNonRoot must be true")
    uid = sc.get("runAsUser", psc.get("runAsUser"))
    want = UIDS.get(str(c.get("name")))
    if want is not None and uid != want:
        p.append(f"{where}: runs as uid {uid}, the image's user for it is {want}")
    if (sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type") \
            not in ("RuntimeDefault", "Localhost"):
        p.append(f"{where}: needs a RuntimeDefault or Localhost seccomp profile")
    image = str(c.get("image") or "")
    problem = _image_ok(image)
    if problem:
        p.append(f"{where}: image {image} {problem}")
    if PLACEHOLDER.search(image) and not allow_placeholders:
        p.append(f"{where}: image {image} is still a placeholder")
    res = c.get("resources") or {}
    for part in ("requests", "limits"):
        for key in ("cpu", "memory"):
            if key not in (res.get(part) or {}):
                p.append(f"{where}: resources.{part}.{key} is missing")
    for port in c.get("ports") or []:
        if port.get("hostPort"):
            p.append(f"{where}: hostPort")
    return p


def _pod_level(owner: str, pod: Dict[str, Any], volumes: Dict[str, Any]) -> List[str]:
    p: List[str] = []
    for key in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
        if pod.get(key):
            p.append(f"{owner}: {key} is on")
    for key in ("automountServiceAccountToken", "enableServiceLinks"):
        if pod.get(key) is not False:
            p.append(f"{owner}: {key} must be false")
    psc = pod.get("securityContext") or {}
    if psc.get("runAsNonRoot") is not True:
        p.append(f"{owner}: pod runAsNonRoot must be true")
    if (psc.get("seccompProfile") or {}).get("type") not in ("RuntimeDefault", "Localhost"):
        p.append(f"{owner}: pod seccompProfile must be RuntimeDefault or Localhost")
    for v in volumes.values():
        if "hostPath" in v:
            p.append(f"{owner}: hostPath volume {v.get('name')}")
        if "docker.sock" in str(v):
            p.append(f"{owner}: Docker socket volume {v.get('name')}")
        empty = v.get("emptyDir")
        if empty is not None and not empty.get("sizeLimit"):
            p.append(f"{owner}: emptyDir {v.get('name')} has no sizeLimit")
    return p


def _container_role(owner: str, c: Dict[str, Any], pod: Dict[str, Any],
                    volumes: Dict[str, Any], intel: Dict[str, Any],
                    allow_placeholders: bool) -> List[str]:
    """What each named container may hold: secrets, claims, external settings."""
    p: List[str] = []
    name = c.get("name")
    mounts = {m.get("name"): m for m in c.get("volumeMounts") or []}
    secrets = {(volumes.get(m) or {}).get("secret", {}).get("secretName")
               for m in mounts if "secret" in (volumes.get(m) or {})}
    env = {e.get("name", ""): e.get("value") for e in c.get("env") or []}
    if name == "analysis":
        p += _check_analysis(owner, c, pod, mounts, volumes, secrets, intel)
        p += _check_intel_client(owner, env, mounts, volumes, intel, allow_placeholders)
    elif name == "proxy" and secrets - PROXY_SECRETS:
        p.append(f"{owner}: proxy mounts secrets {sorted(secrets - PROXY_SECRETS)}")
    elif name == "intel":
        if secrets - INTEL_SECRETS:
            p.append(f"{owner}: intel mounts secrets {sorted(secrets - INTEL_SECRETS)}")
        if env.get("AEGIS_INTEL_URL"):
            p.append(f"{owner}: intel is the server; AEGIS_INTEL_URL is a client setting")
        sock = str(env.get("AEGIS_INTEL_SOCKET") or "")
        socket_dirs = [m.get("mountPath") for m in mounts.values()
                       if "emptyDir" in (volumes.get(m.get("name")) or {})]
        if not sock or not any(sock.startswith(str(d).rstrip("/") + "/") for d in socket_dirs):
            p.append(f"{owner}: intel must listen on a socket in a Pod-local emptyDir")
    elif name == "intel-proxy" and secrets - INTEL_PROXY_SECRETS:
        p.append(f"{owner}: intel-proxy mounts secrets {sorted(secrets - INTEL_PROXY_SECRETS)}")
    elif name == "content" and any(m.get("mountPath") == CONTENT_PATH and m.get("readOnly")
                                   for m in mounts.values()):
        p.append(f"{owner}: the content Job must be able to write the content")
    if name not in ("analysis", "content", "intel") and any(
            (volumes.get(m.get("name")) or {}).get("persistentVolumeClaim")
            for m in mounts.values()):
        p.append(f"{owner}: container {name} mounts a claim")
    if name == "intel":
        return p                       # the external services' settings belong here
    allowed = INTEL_CLIENT_ENV if (name == "analysis" and intel.get("present")) else set()
    env_names = [n for n in env if n not in allowed]
    for word in EXTERNAL_WORDS:
        if any(word in n for n in env_names):
            p.append(f"{owner}: container {name} has an external-service setting ({word})")
    return p


def _check_intel_client(owner: str, env: Dict[str, Any], mounts: Dict[str, Any],
                        volumes: Dict[str, Any], intel: Dict[str, Any],
                        allow_placeholders: bool) -> List[str]:
    """Option E: analysis reaches the intel Service's ClusterIP over TLS, with the
    certificate checked against aegis-intel.NAMESPACE.svc (core/intel_client.py)."""
    if not intel.get("present"):
        return []
    p: List[str] = []
    missing = sorted(k for k in INTEL_CLIENT_ENV if not env.get(k))
    if missing:
        return [f"{owner}: analysis lacks {missing} for the intel service"]
    ip = str(intel.get("cluster_ip") or "")
    if PLACEHOLDER.search(ip) or PLACEHOLDER.search(str(env["AEGIS_INTEL_URL"])):
        if not allow_placeholders:
            p.append(f"{owner}: the intel address is still a placeholder")
    elif env["AEGIS_INTEL_URL"] != f"https://{_url_host(ip)}:{INTEL_PORT}":
        p.append(f"{owner}: AEGIS_INTEL_URL {env['AEGIS_INTEL_URL']} is not the intel "
                 f"Service's ClusterIP https://{_url_host(ip)}:{INTEL_PORT}")
    want = f"aegis-intel.{intel.get('namespace')}.svc"
    if env["AEGIS_INTEL_SERVER_NAME"] != want:
        p.append(f"{owner}: AEGIS_INTEL_SERVER_NAME must be {want} (the name in intel's "
                 "certificate)")

    def source(path: str) -> Dict[str, Any]:
        for m in mounts.values():
            if path.startswith(str(m.get("mountPath")).rstrip("/") + "/"):
                return volumes.get(m.get("name")) or {}
        return {}
    if "configMap" not in source(str(env["AEGIS_INTEL_CA_FILE"])):
        p.append(f"{owner}: AEGIS_INTEL_CA_FILE must come from a mounted ConfigMap")
    token = source(str(env["AEGIS_INTEL_TOKEN_FILE"])).get("secret") or {}
    if token.get("secretName") not in INTEL_CLIENT_SECRETS:
        p.append(f"{owner}: AEGIS_INTEL_TOKEN_FILE must come from the Secret aegis-intel-token")
    return p


def _url_host(ip: str) -> str:
    return f"[{ip}]" if ":" in ip else ip


def check_pod(obj: Dict[str, Any], pod: Dict[str, Any], allow_placeholders: bool,
              intel: Optional[Dict[str, Any]] = None) -> List[str]:
    owner = _name(obj)
    volumes = {v.get("name"): v for v in pod.get("volumes") or []}
    p = _pod_level(owner, pod, volumes)
    for c in list(pod.get("initContainers") or []) + list(pod.get("containers") or []):
        p += check_container(owner, c, pod, allow_placeholders)
    for c in pod.get("containers") or []:
        p += _container_role(owner, c, pod, volumes, intel or {}, allow_placeholders)
    return p


def _gate_settings(owner: str, c: Dict[str, Any]) -> List[str]:
    """The gate probes only when told to, and only the listed destinations."""
    env = {e.get("name"): e.get("value") for e in c.get("env") or []}
    name = c.get("name")
    if env.get("AEGIS_GATE_LIVE") != "1":
        return [f"{owner}: container {name} runs the isolation gate without AEGIS_GATE_LIVE=1"]
    listed = {t.strip() for t in str(env.get("AEGIS_GATE_TARGETS") or "").split(",") if t.strip()}
    missing = sorted(GATE_TARGETS - listed)
    return [f"{owner}: container {name} AEGIS_GATE_TARGETS lacks {missing}"] if missing else []


def _check_analysis(owner, c, pod, mounts, volumes, secrets, intel) -> List[str]:
    p: List[str] = []
    env = {e.get("name"): e.get("value") for e in c.get("env") or []}
    if env.get("AEGIS_PROFILE") != "production":
        p.append(f"{owner}: analysis needs AEGIS_PROFILE=production")
    if env.get("LLM_PROVIDER") != "none":
        p.append(f"{owner}: analysis needs LLM_PROVIDER=none")
    allowed = ANALYSIS_SECRETS | (INTEL_CLIENT_SECRETS if intel.get("present") else set())
    if secrets - allowed:
        p.append(f"{owner}: analysis mounts secrets {sorted(secrets - allowed)}")
    content = [m for m in mounts.values() if m.get("mountPath") == CONTENT_PATH]
    if not content:
        p.append(f"{owner}: analysis does not mount the detection content")
    for m in content:
        claim = (volumes.get(m.get("name")) or {}).get("persistentVolumeClaim") or {}
        if not m.get("readOnly") or not claim.get("readOnly"):
            p.append(f"{owner}: analysis must mount the detection content read-only")
    tmp = [m for m in mounts.values() if m.get("mountPath") == SCRATCH]
    if not tmp or (volumes.get(tmp[0].get("name")) or {}).get("emptyDir", {}).get("medium") \
            != "Memory":
        p.append(f"{owner}: analysis /tmp must be a memory-backed, size-limited emptyDir")
    for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
        if not c.get(probe):
            p.append(f"{owner}: analysis has no {probe}")
    live = str(c.get("livenessProbe") or {})
    if "/ready" in live or "isolation_gate" in live:
        p.append(f"{owner}: liveness must check the process only, not readiness")
    if "isolation_gate.py" not in str(c.get("readinessProbe") or {}):
        p.append(f"{owner}: readiness must run the isolation gate")
    gates = [i for i in pod.get("initContainers") or []
             if "isolation_gate.py" in " ".join(map(str, i.get("command") or []))]
    if not gates:
        p.append(f"{owner}: no isolation-gate init container")
    for runner in [c] + gates:
        p += _gate_settings(owner, runner)
    timeout = 300
    grace = pod.get("terminationGracePeriodSeconds", 30)
    if grace < timeout:
        p.append(f"{owner}: terminationGracePeriodSeconds {grace} is below the scan "
                 f"time limit ({timeout} s)")
    return p


def _intel_service(d: Dict[str, Any], spec: Dict[str, Any], allow_placeholders: bool) -> List[str]:
    p: List[str] = []
    ports = [x.get("port") for x in spec.get("ports") or []]
    if ports != [INTEL_PORT] or spec.get("type", "ClusterIP") != "ClusterIP":
        p.append(f"{_name(d)}: intel is only a ClusterIP Service on {INTEL_PORT}, "
                 f"not {spec.get('type')} {ports}")
    if spec.get("selector") != INTEL_LABELS:
        p.append(f"{_name(d)}: must select the intel Pods only")
    ip = str(spec.get("clusterIP") or "")
    if PLACEHOLDER.search(ip):
        if not allow_placeholders:
            p.append(f"{_name(d)}: clusterIP is still a placeholder")
    elif not _is_ip(ip):
        p.append(f"{_name(d)}: needs a fixed clusterIP (analysis has no DNS), not {ip!r}")
    return p


def _check_object(d: Dict[str, Any], allow_placeholders: bool, allow_rwo: bool) -> List[str]:
    p: List[str] = []
    kind, spec = d.get("kind"), d.get("spec") or {}
    if kind in FORBIDDEN_KINDS:
        p.append(f"{_name(d)}: {kind} is not part of this deployment "
                 "(no API access, no autoscaling, TLS ends at the proxy)")
    elif kind == "Secret":
        p.append(f"{_name(d)}: Secrets are created by the operator, never rendered "
                 "from the repository")
    elif kind == "ConfigMap":
        for key, value in (d.get("data") or {}).items():
            if SECRET_WORDS.search(key) and key not in PUBLIC_KEYS:
                p.append(f"{_name(d)}: {key} looks like a secret; use a Secret file")
            if PLACEHOLDER.search(str(value)) and not allow_placeholders:
                p.append(f"{_name(d)}: {key} is still a placeholder")
    elif kind == "ServiceAccount" and d.get("automountServiceAccountToken") is not False:
        p.append(f"{_name(d)}: automountServiceAccountToken must be false")
    elif kind == "PersistentVolumeClaim":
        modes = spec.get("accessModes") or []
        allowed = {"ReadWriteOncePod"} | ({"ReadWriteOnce"} if allow_rwo else set())
        if not modes or set(modes) - allowed:
            p.append(f"{_name(d)}: access modes {modes}; ReadWriteOncePod keeps one "
                     "writer (--allow-rwo to accept ReadWriteOnce)")
        if PLACEHOLDER.search(str(spec.get("storageClassName") or "")) and not allow_placeholders:
            p.append(f"{_name(d)}: storageClassName is still a placeholder")
    elif kind == "Deployment":
        if spec.get("replicas", 1) != 1:
            p.append(f"{_name(d)}: one replica only (docs/KUBERNETES.md, \"Scaling\")")
        if (spec.get("strategy") or {}).get("type") != "Recreate":
            p.append(f"{_name(d)}: strategy must be Recreate (ReadWriteOncePod claims)")
    elif kind == "Service" and (d.get("metadata") or {}).get("name") == "aegis-intel":
        p += _intel_service(d, spec, allow_placeholders)
    elif kind == "Service":
        ports = [x.get("port") for x in spec.get("ports") or []]
        if ports != [8443]:
            p.append(f"{_name(d)}: only the HTTPS port 8443 may be exposed, not {ports}")
        if spec.get("type") not in ("ClusterIP", "LoadBalancer", "NodePort"):
            p.append(f"{_name(d)}: type {spec.get('type')}")
    return p


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _intel_context(docs: List[Dict[str, Any]], namespace: str) -> Dict[str, Any]:
    deploys = [d for d in docs if d.get("kind") == "Deployment"
               and (d.get("metadata") or {}).get("name") == "aegis-intel"]
    services = [d for d in docs if d.get("kind") == "Service"
                and (d.get("metadata") or {}).get("name") == "aegis-intel"]
    return {"present": bool(deploys), "service": bool(services), "namespace": namespace,
            "cluster_ip": ((services[0].get("spec") or {}).get("clusterIP") if services else "")}


def _analysis_config_maps(docs: List[Dict[str, Any]]) -> List[str]:
    """ConfigMaps analysis loads with envFrom must not carry external settings:
    the env check alone would not see them."""
    p: List[str] = []
    maps = {(d.get("metadata") or {}).get("name"): d for d in docs if d.get("kind") == "ConfigMap"}
    for d in docs:
        pod = pod_spec(d) or {}
        for c in pod.get("containers") or []:
            if c.get("name") != "analysis":
                continue
            for src in c.get("envFrom") or []:
                ref = (src.get("configMapRef") or {}).get("name")
                for key in ((maps.get(ref) or {}).get("data") or {}):
                    if any(word in key for word in EXTERNAL_WORDS):
                        p.append(f"ConfigMap/{ref}: {key} reaches analysis through envFrom; "
                                 "external settings belong to intel")
            if any("secretRef" in src for src in c.get("envFrom") or []):
                p.append(f"{_name(d)}: analysis loads a Secret as environment variables")
    return p


def check(docs: Iterable[Dict[str, Any]], allow_placeholders: bool = False,
          allow_rwo: bool = False) -> List[str]:
    flat: List[Dict[str, Any]] = []
    for d in docs:                    # `kubectl get -o yaml` of several objects: a List
        if isinstance(d, dict):
            flat += [i for i in d.get("items") or [] if isinstance(i, dict)] \
                if d.get("kind") == "List" else [d]
    docs = flat
    p: List[str] = []
    kinds = [d.get("kind") for d in docs]
    ns = [d for d in docs if d.get("kind") == "Namespace"]
    if len(ns) != 1:
        p.append("expected exactly one Namespace")
    else:
        labels = (ns[0].get("metadata") or {}).get("labels") or {}
        if labels.get("pod-security.kubernetes.io/enforce") != "restricted":
            p.append("the Namespace must enforce the restricted Pod Security Standard")
    name = (ns[0].get("metadata") or {}).get("name") if ns else NAMESPACE
    intel = _intel_context(docs, str(name))
    if intel["present"] != intel["service"]:
        p.append("the intel Deployment and its Service aegis-intel come together "
                 "(components/intel)")
    for d in docs:
        if d.get("kind") != "Namespace" and (d.get("metadata") or {}).get("namespace") != name:
            p.append(f"{_name(d)}: not in namespace {name}")
        p += _check_object(d, allow_placeholders, allow_rwo)
        pod = pod_spec(d)
        if pod is not None:
            p += check_pod(d, pod, allow_placeholders, intel)
    p += _analysis_config_maps(docs)
    p += _check_policies([d for d in docs if d.get("kind") == "NetworkPolicy"],
                         allow_placeholders, intel)
    if "Deployment" not in kinds:
        p.append("no Deployment")
    return p


def _labels(spec: Dict[str, Any]) -> Dict[str, Any]:
    return dict((spec.get("podSelector") or {}).get("matchLabels") or {})


def _ports(rule: Dict[str, Any]) -> List[Any]:
    return [(q.get("protocol", "TCP"), q.get("port")) for q in rule.get("ports") or []]


def _analysis_egress(x: Dict[str, Any], intel: Dict[str, Any]) -> List[str]:
    """Option E: exactly one rule, TCP 9443 to the intel Pods."""
    spec = x.get("spec") or {}
    want = [{"to": [{"podSelector": {"matchLabels": INTEL_LABELS}}],
             "ports": [{"protocol": "TCP", "port": INTEL_PORT}]}]
    if not intel.get("present"):
        return [f"{_name(x)}: allows analysis egress without the intel component"]
    if spec.get("egress") != want or set(spec.get("policyTypes") or []) != {"Egress"}:
        return [f"{_name(x)}: analysis egress must be exactly TCP {INTEL_PORT} to the intel "
                "Pods"]
    return []


def _intel_egress(x: Dict[str, Any]) -> List[str]:
    """Intel: the cluster DNS, and public addresses on named ports. A default route
    must exclude link-local (metadata), loopback and the private ranges; a narrow
    operator rule (CAPE, Ollama) may name a private address but never link-local."""
    p: List[str] = []
    for rule in (x.get("spec") or {}).get("egress") or []:
        if not rule.get("ports") or not rule.get("to"):
            p.append(f"{_name(x)}: every intel egress rule needs destinations and ports")
            continue
        for peer in rule["to"]:
            if "ipBlock" in peer:
                p += _ip_block(x, peer["ipBlock"])
            elif peer == {"namespaceSelector": {"matchLabels": {
                    "kubernetes.io/metadata.name": "kube-system"}},
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}:
                if set(_ports(rule)) - {("UDP", 53), ("TCP", 53)}:
                    p.append(f"{_name(x)}: the cluster DNS rule may open port 53 only")
            else:
                p.append(f"{_name(x)}: intel may reach no Pod but the cluster DNS ({peer})")
    return p


def _ip_block(x: Dict[str, Any], block: Dict[str, Any]) -> List[str]:
    try:
        cidr = ipaddress.ip_network(str(block.get("cidr")), strict=False)
        excepts = [ipaddress.ip_network(str(e), strict=False) for e in block.get("except") or []]
    except ValueError:
        return [f"{_name(x)}: not an address range: {block}"]
    guarded = GUARDED_NETS if cidr.prefixlen == 0 else ALWAYS_GUARDED
    p = []
    for net in guarded:
        if net.version == cidr.version and cidr.overlaps(net) and not any(
                e.version == net.version and net.subnet_of(e) for e in excepts):
            p.append(f"{_name(x)}: {cidr} lets intel reach {net}; exclude it")
    return p


def _check_policies(policies: List[Dict[str, Any]], allow_placeholders: bool,
                    intel: Optional[Dict[str, Any]] = None) -> List[str]:
    intel = intel or {}
    p: List[str] = []
    deny = [x for x in policies
            if (x.get("spec") or {}).get("podSelector") in ({}, None)
            and set((x.get("spec") or {}).get("policyTypes") or []) == {"Ingress", "Egress"}
            and not (x.get("spec") or {}).get("ingress") and not (x.get("spec") or {}).get("egress")]
    if not deny:
        p.append("no default-deny NetworkPolicy for ingress and egress")
    for x in policies:
        spec = x.get("spec") or {}
        target = _labels(spec)
        if spec.get("egress"):
            if target == ANALYSIS_LABELS:
                p += _analysis_egress(x, intel)
            elif target == INTEL_LABELS and intel.get("present"):
                p += _intel_egress(x)
            else:
                p.append(f"{_name(x)}: allows egress; only analysis (to intel) and intel "
                         "may have it")
        for rule in spec.get("ingress") or []:
            if target == INTEL_LABELS and intel.get("present"):
                if _ports(rule) != [("TCP", INTEL_PORT)] or rule.get("from") != [
                        {"podSelector": {"matchLabels": ANALYSIS_LABELS}}]:
                    p.append(f"{_name(x)}: intel accepts TCP {INTEL_PORT} from analysis "
                             "only")
                continue
            if _ports(rule) != [("TCP", 8443)]:
                p.append(f"{_name(x)}: ingress must be limited to TCP 8443, not {_ports(rule)}")
            if PLACEHOLDER.search(str(rule.get("from") or "")) and not allow_placeholders:
                p.append(f"{_name(x)}: ingress source is still a placeholder")
        if spec.get("ingress") and target.get("app.kubernetes.io/component") not in (
                "analysis", "intel"):
            p.append(f"{_name(x)}: ingress allowed to Pods other than analysis")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file", help="rendered YAML, or - for standard input")
    ap.add_argument("--allow-placeholders", action="store_true")
    ap.add_argument("--allow-rwo", action="store_true")
    a = ap.parse_args(argv)
    text = sys.stdin.read() if a.file == "-" else open(a.file, encoding="utf-8").read()
    problems = check(yaml.safe_load_all(text), a.allow_placeholders, a.allow_rwo)
    for line in problems:
        print(f"FAIL  {line}")
    if not problems:
        print("manifests: every checked invariant holds")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
