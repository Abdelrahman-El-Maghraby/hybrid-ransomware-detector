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
import re
import sys
from typing import Any, Dict, Iterable, List, Optional

import yaml

NAMESPACE = "aegis-sentinel"
UIDS = {"analysis": 10001, "isolation-gate": 10001, "content": 10001, "proxy": 10003}
ANALYSIS_SECRETS = {"aegis-api-token"}
PROXY_SECRETS = {"aegis-tls"}
EXTERNAL_WORDS = ("VIRUSTOTAL", "OPENAI", "SANDBOX_URL", "SANDBOX_TOKEN", "SMTP_",
                  "ALERT_EMAIL_TO", "ALERT_EMAIL_FROM", "AEGIS_INTEL", "OLLAMA_HOST",
                  "WEBHOOK", "CLOUD_")
SECRET_WORDS = re.compile(r"(TOKEN|PASSWORD|SECRET|API_KEY|PRIVATE)", re.I)
PUBLIC_KEYS = {"RULEPACK_PUBLIC_KEYS"}           # public by design (docs/RULE_PACKS.md)
WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Pod"}
FORBIDDEN_KINDS = {"HorizontalPodAutoscaler", "Role", "ClusterRole", "RoleBinding",
                   "ClusterRoleBinding", "Ingress", "PodDisruptionBudget"}
CONTENT_PATH = "/var/lib/aegis/RansomwareScanner/data"
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
                    volumes: Dict[str, Any]) -> List[str]:
    """What each named container may hold: secrets, claims, external settings."""
    p: List[str] = []
    name = c.get("name")
    mounts = {m.get("name"): m for m in c.get("volumeMounts") or []}
    secrets = {(volumes.get(m) or {}).get("secret", {}).get("secretName")
               for m in mounts if "secret" in (volumes.get(m) or {})}
    if name == "analysis":
        p += _check_analysis(owner, c, pod, mounts, volumes, secrets)
    elif name == "proxy" and secrets - PROXY_SECRETS:
        p.append(f"{owner}: proxy mounts secrets {sorted(secrets - PROXY_SECRETS)}")
    elif name == "content" and any(m.get("mountPath") == CONTENT_PATH and m.get("readOnly")
                                   for m in mounts.values()):
        p.append(f"{owner}: the content Job must be able to write the content")
    if name not in ("analysis", "content") and any(
            (volumes.get(m.get("name")) or {}).get("persistentVolumeClaim")
            for m in mounts.values()):
        p.append(f"{owner}: container {name} mounts a claim")
    env_names = [e.get("name", "") for e in c.get("env") or []]
    for word in EXTERNAL_WORDS:
        if any(word in n for n in env_names):
            p.append(f"{owner}: container {name} has an external-service setting ({word})")
    return p


def check_pod(obj: Dict[str, Any], pod: Dict[str, Any], allow_placeholders: bool) -> List[str]:
    owner = _name(obj)
    volumes = {v.get("name"): v for v in pod.get("volumes") or []}
    p = _pod_level(owner, pod, volumes)
    for c in list(pod.get("initContainers") or []) + list(pod.get("containers") or []):
        p += check_container(owner, c, pod, allow_placeholders)
    for c in pod.get("containers") or []:
        p += _container_role(owner, c, pod, volumes)
    return p


def _check_analysis(owner, c, pod, mounts, volumes, secrets) -> List[str]:
    p: List[str] = []
    env = {e.get("name"): e.get("value") for e in c.get("env") or []}
    if env.get("AEGIS_PROFILE") != "production":
        p.append(f"{owner}: analysis needs AEGIS_PROFILE=production")
    if env.get("LLM_PROVIDER") != "none":
        p.append(f"{owner}: analysis needs LLM_PROVIDER=none")
    if secrets - ANALYSIS_SECRETS:
        p.append(f"{owner}: analysis mounts secrets {sorted(secrets - ANALYSIS_SECRETS)}")
    content = [m for m in mounts.values() if m.get("mountPath") == CONTENT_PATH]
    if not content:
        p.append(f"{owner}: analysis does not mount the detection content")
    for m in content:
        claim = (volumes.get(m.get("name")) or {}).get("persistentVolumeClaim") or {}
        if not m.get("readOnly") or not claim.get("readOnly"):
            p.append(f"{owner}: analysis must mount the detection content read-only")
    tmp = [m for m in mounts.values() if m.get("mountPath") == "/tmp"]  # noqa: S108  # nosec B108
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
    timeout = 300
    grace = pod.get("terminationGracePeriodSeconds", 30)
    if grace < timeout:
        p.append(f"{owner}: terminationGracePeriodSeconds {grace} is below the scan "
                 f"time limit ({timeout} s)")
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
    elif kind == "Service":
        ports = [x.get("port") for x in spec.get("ports") or []]
        if ports != [8443]:
            p.append(f"{_name(d)}: only the HTTPS port 8443 may be exposed, not {ports}")
        if spec.get("type") not in ("ClusterIP", "LoadBalancer", "NodePort"):
            p.append(f"{_name(d)}: type {spec.get('type')}")
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
    for d in docs:
        if d.get("kind") != "Namespace" and (d.get("metadata") or {}).get("namespace") != name:
            p.append(f"{_name(d)}: not in namespace {name}")
        p += _check_object(d, allow_placeholders, allow_rwo)
        pod = pod_spec(d)
        if pod is not None:
            p += check_pod(d, pod, allow_placeholders)
    p += _check_policies([d for d in docs if d.get("kind") == "NetworkPolicy"],
                         allow_placeholders)
    if "Deployment" not in kinds:
        p.append("no Deployment")
    return p


def _check_policies(policies: List[Dict[str, Any]], allow_placeholders: bool) -> List[str]:
    p: List[str] = []
    deny = [x for x in policies
            if (x.get("spec") or {}).get("podSelector") in ({}, None)
            and set((x.get("spec") or {}).get("policyTypes") or []) == {"Ingress", "Egress"}
            and not (x.get("spec") or {}).get("ingress") and not (x.get("spec") or {}).get("egress")]
    if not deny:
        p.append("no default-deny NetworkPolicy for ingress and egress")
    for x in policies:
        spec = x.get("spec") or {}
        if spec.get("egress"):
            p.append(f"{_name(x)}: allows egress; no component of this deployment needs it")
        for rule in spec.get("ingress") or []:
            ports = [(q.get("protocol", "TCP"), q.get("port")) for q in rule.get("ports") or []]
            if ports != [("TCP", 8443)]:
                p.append(f"{_name(x)}: ingress must be limited to TCP 8443, not {ports}")
            if PLACEHOLDER.search(str(rule.get("from") or "")) and not allow_placeholders:
                p.append(f"{_name(x)}: ingress source is still a placeholder")
        if spec.get("ingress"):
            labels = (spec.get("podSelector") or {}).get("matchLabels") or {}
            if labels.get("app.kubernetes.io/component") != "analysis":
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
