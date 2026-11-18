"""Optional Kubernetes deployment (deploy/kubernetes, docs/KUBERNETES.md).

The manifests are rendered with `kubectl kustomize` (offline; skipped when kubectl
is not installed) and checked with deploy/kubernetes/check_manifests.py, which is
also tested against broken copies so a weakened manifest cannot pass. The
isolation gate's classification is tested against local sockets only. Nothing
here contacts a cluster.
"""

from __future__ import annotations

import copy
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
K8S = ROOT / "deploy" / "kubernetes"
KUBECTL = shutil.which("kubectl")
needs_kubectl = pytest.mark.skipif(KUBECTL is None, reason="kubectl not installed")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


checker = _load("aegis_k8s_check", K8S / "check_manifests.py")
gate = _load("aegis_k8s_gate", K8S / "base" / "isolation_gate.py")


def render(path: Path) -> list:
    out = subprocess.run([KUBECTL, "kustomize", str(path)], capture_output=True, text=True,
                         timeout=60, check=True, env=dict(os.environ, KUBECONFIG=os.devnull))
    return [d for d in yaml.safe_load_all(out.stdout) if d]


@pytest.fixture(scope="module")
def base():
    if KUBECTL is None:
        pytest.skip("kubectl not installed")
    return render(K8S / "base")


def find(docs, kind, name=None):
    for d in docs:
        if d["kind"] == kind and (name is None or d["metadata"]["name"].startswith(name)):
            return d
    raise AssertionError(f"no {kind} {name}")


def pod(docs):
    return find(docs, "Deployment", "aegis-analysis")["spec"]["template"]["spec"]


def container(docs, name):
    spec = pod(docs)
    return next(c for c in spec["initContainers"] + spec["containers"] if c["name"] == name)


# ------------------------------------------------------------------ rendered manifests

@needs_kubectl
def test_base_passes_every_invariant_except_its_placeholders(base):
    assert checker.check(base, allow_placeholders=True) == []
    problems = checker.check(base)
    assert problems and all("placeholder" in p for p in problems)


@needs_kubectl
def test_the_example_overlay_is_refused_until_its_values_are_filled_in():
    docs = render(K8S / "overlays" / "example")
    assert checker.check(docs, allow_placeholders=True) == []
    problems = " ".join(checker.check(docs))
    for what in ("image", "storageClassName", "RULEPACK_PUBLIC_KEYS", "ingress source"):
        assert what in problems
    svc = find(docs, "Service", "aegis-sentinel")["spec"]
    assert svc["type"] == "LoadBalancer" and svc["externalTrafficPolicy"] == "Local"


@needs_kubectl
def test_only_the_expected_objects_are_rendered(base):
    kinds = sorted(d["kind"] for d in base)
    assert kinds == sorted(["Namespace", "ServiceAccount", "ConfigMap", "ConfigMap",
                            "PersistentVolumeClaim", "PersistentVolumeClaim", "Deployment",
                            "Service", "NetworkPolicy", "NetworkPolicy"])
    assert not any(d["kind"] in ("Secret", "Role", "RoleBinding", "ClusterRole",
                                 "HorizontalPodAutoscaler") for d in base)


@needs_kubectl
def test_the_uids_match_the_image(base):
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "useradd -r -M -u 10001 -g analysis" in dockerfile
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
    assert compose["proxy"]["user"].startswith("10003:")
    spec = pod(base)
    assert spec["securityContext"]["runAsUser"] == 10001
    assert spec["securityContext"]["fsGroup"] == 10001
    assert container(base, "proxy")["securityContext"]["runAsUser"] == 10003


@needs_kubectl
def test_the_proxy_uses_the_caddyfile_paths(base):
    caddy = (ROOT / "deploy" / "Caddyfile").read_text()
    assert "unix//run/aegis/api/api.sock" in caddy and "/etc/caddy/tls/cert.pem" in caddy
    proxy = {m["mountPath"] for m in container(base, "proxy")["volumeMounts"]}
    assert {"/run/aegis/api", "/etc/caddy/tls"} <= proxy
    env = {e["name"]: e.get("value") for e in container(base, "analysis")["env"]}
    assert env["AEGIS_API_SOCKET"] == "/run/aegis/api/api.sock"
    tls = next(v for v in pod(base)["volumes"] if v["name"] == "tls")["secret"]["items"]
    assert {i["path"] for i in tls} == {"cert.pem", "key.pem"}


@needs_kubectl
def test_analysis_keeps_the_docker_limits_and_settings(base):
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["analysis"]
    cfg = find(base, "ConfigMap", "aegis-analysis-config")["data"]
    assert cfg["SCAN_TIMEOUT_SECONDS"] == "300" and cfg["WORKER_MEMORY_MB"] == "2048"
    assert compose["environment"]["AEGIS_API_TRUST_PROXY"] == "1"
    res = container(base, "analysis")["resources"]
    assert res["limits"]["memory"] == "6Gi" == res["requests"]["memory"]
    assert pod(base)["terminationGracePeriodSeconds"] >= int(cfg["SCAN_TIMEOUT_SECONDS"])


@needs_kubectl
def test_a_restarted_analysis_container_starts_with_an_empty_tmp(base):
    """An emptyDir outlives a container restart; Docker's tmpfs does not."""
    command = container(base, "analysis")["command"]
    assert command[:2] == ["sh", "-c"]
    assert command[2].startswith("find /tmp -mindepth 1 -xdev -delete;")
    assert command[2].endswith("exec python -m api.server")
    scratch = {m["name"] for m in container(base, "analysis")["volumeMounts"]
               if m["mountPath"] == "/tmp"}
    others = [m for c in pod(base)["containers"] + pod(base)["initContainers"]
              if c["name"] != "analysis" for m in c.get("volumeMounts", [])]
    assert not any(m["name"] in scratch for m in others)     # only analysis uses it


@needs_kubectl
def test_the_content_job_installs_with_the_deployments_image_and_keys(base):
    text = (K8S / "jobs" / "content-update.yaml").read_text()
    text = text.replace("AEGIS_IMAGE", "registry.example/aegis-sentinel:4.8.0") \
               .replace("AEGIS_CONFIG_MAP", "aegis-analysis-config-abc")
    job = yaml.safe_load(text)
    job["metadata"]["namespace"] = "aegis-sentinel"
    docs = [d for d in base if d["kind"] != "Deployment"] + [job]
    assert checker.check(docs, allow_placeholders=True) == ["no Deployment"]
    c = job["spec"]["template"]["spec"]["containers"][0]
    assert c["command"][-2:] == ["--update-rules", "/import/pack.tar.gz"]
    mounts = {m["mountPath"]: m for m in c["volumeMounts"]}
    assert not mounts[checker.CONTENT_PATH].get("readOnly")
    assert mounts["/import"]["readOnly"] is True


def _prepare(spec):
    first = spec["initContainers"][0]
    assert first["name"] == "prepare-state"
    return first


def _job():
    text = (K8S / "jobs" / "content-update.yaml").read_text()
    return yaml.safe_load(text)["spec"]["template"]["spec"]


@needs_kubectl
@pytest.mark.parametrize("which", ["deployment", "job"])
def test_the_state_folders_are_made_by_the_service_user_before_the_content_mount(base, which):
    """The content claim is mounted inside the state volume (the Job: its home
    emptyDir). Left to the runtime, RansomwareScanner/ would be created as root 0755
    and uid 10001 could not write its log file; Docker seeds its volume from the
    image instead. prepare-state runs first, as 10001, without the content mounted."""
    spec = pod(base) if which == "deployment" else _job()
    prep = _prepare(spec)
    assert [m["mountPath"] for m in prep["volumeMounts"]] == ["/var/lib/aegis"]
    assert spec["securityContext"]["runAsUser"] == 10001
    assert prep["securityContext"]["readOnlyRootFilesystem"] is True
    main = spec["containers"][0]
    paths = {m["mountPath"]: m["name"] for m in main["volumeMounts"]}
    assert paths[checker.CONTENT_PATH] != paths["/var/lib/aegis"]
    assert prep["volumeMounts"][0]["name"] == paths["/var/lib/aegis"]


@needs_kubectl
def test_prepare_state_creates_the_folders_or_fails_clearly(base, tmp_path):
    code = _prepare(pod(base))["command"][2]
    assert code == _prepare(_job())["command"][2]
    home = tmp_path / "home"
    home.mkdir()
    run = subprocess.run([sys.executable, "-c", code.replace("/var/lib/aegis", str(home))],
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    assert (home / "RansomwareScanner" / "data").is_dir()
    assert not (home / "RansomwareScanner" / ".aegis-write-test").exists()
    locked = tmp_path / "locked"
    (locked / "RansomwareScanner" / "data").mkdir(parents=True)
    (locked / "RansomwareScanner").chmod(0o555)
    try:
        run = subprocess.run([sys.executable, "-c", code.replace("/var/lib/aegis", str(locked))],
                             capture_output=True, text=True, timeout=30)
    finally:
        (locked / "RansomwareScanner").chmod(0o755)
    if os.geteuid() != 0:                     # root ignores the mode
        assert run.returncode == 1 and "is not writable by uid" in run.stderr


@needs_kubectl
def test_prepare_state_keeps_an_existing_volume_as_it_is(base, tmp_path):
    """A claim from an earlier start (or a restored snapshot): the folders and their
    files stay, nothing is re-moded or re-owned, and running it again changes
    nothing."""
    code = _prepare(pod(base))["command"][2]
    home = tmp_path / "home"
    app = home / "RansomwareScanner"
    (app / "data").mkdir(parents=True)
    (app / "ransomware_scanner.log").write_text("earlier lines\n")
    app.chmod(0o750)
    before = {p: (p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in home.rglob("*")}
    for _ in range(2):
        run = subprocess.run([sys.executable, "-c", code.replace("/var/lib/aegis", str(home))],
                             capture_output=True, text=True, timeout=30)
        assert run.returncode == 0, run.stderr
    after = {p: (p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in home.rglob("*")}
    assert after == before
    assert (app / "ransomware_scanner.log").read_text() == "earlier lines\n"


@needs_kubectl
def test_prepare_state_changes_no_permissions_and_stays_hardened(base):
    for spec in (pod(base), _job()):
        prep = _prepare(spec)
        code = prep["command"][2]
        for call in ("chmod", "chown", "umask", "setuid", "setgid"):
            assert call not in code
        sc = prep["securityContext"]
        assert sc["allowPrivilegeEscalation"] is False and sc["capabilities"] == {"drop": ["ALL"]}
        assert sc["readOnlyRootFilesystem"] is True and "runAsUser" not in sc
        assert spec["securityContext"]["runAsUser"] == 10001
        assert spec["securityContext"]["fsGroupChangePolicy"] == "OnRootMismatch"


# ------------------------------------------------------------------ the checker rejects

def _broken(base, change):
    docs = copy.deepcopy(base)
    change(docs)
    return checker.check(docs, allow_placeholders=True)


BREAKS = {
    "privileged": lambda d: container(d, "analysis")["securityContext"].update(privileged=True),
    "allowPrivilegeEscalation": lambda d: container(d, "proxy")["securityContext"].update(
        allowPrivilegeEscalation=True),
    "readOnlyRootFilesystem": lambda d: container(d, "analysis")["securityContext"].update(
        readOnlyRootFilesystem=False),
    "capabilities": lambda d: container(d, "proxy")["securityContext"]["capabilities"].update(
        add=["NET_ADMIN"]),
    "hostNetwork": lambda d: pod(d).update(hostNetwork=True),
    "automountServiceAccountToken": lambda d: pod(d).update(automountServiceAccountToken=True),
    "seccomp": lambda d: pod(d)["securityContext"].update(seccompProfile={"type": "Unconfined"}),
    "uid": lambda d: container(d, "proxy")["securityContext"].update(runAsUser=10001),
    "latest": lambda d: container(d, "analysis").update(image="aegis-sentinel:latest"),
    "hostPath": lambda d: pod(d)["volumes"].append({"name": "x", "hostPath": {"path": "/"}}),
    "content read-only": lambda d: next(
        m for m in container(d, "analysis")["volumeMounts"]
        if m["mountPath"] == checker.CONTENT_PATH).pop("readOnly"),
    "mounts secrets": lambda d: pod(d)["volumes"].append(
        {"name": "vt", "secret": {"secretName": "virustotal"}}) or container(
        d, "analysis")["volumeMounts"].append({"name": "vt", "mountPath": "/run/vt"}),
    "external-service setting": lambda d: container(d, "analysis")["env"].append(
        {"name": "VIRUSTOTAL_API_KEY_FILE", "value": "/run/vt/key"}),
    "egress": lambda d: find(d, "NetworkPolicy", "aegis-allow-https")["spec"].update(
        egress=[{}], policyTypes=["Ingress", "Egress"]),
    "default-deny": lambda d: d.remove(find(d, "NetworkPolicy", "aegis-default-deny")),
    "one replica": lambda d: find(d, "Deployment")["spec"].update(replicas=2),
    "Recreate": lambda d: find(d, "Deployment")["spec"].update(strategy={"type": "RollingUpdate"}),
    "access modes": lambda d: find(d, "PersistentVolumeClaim")["spec"].update(
        accessModes=["ReadWriteMany"]),
    "restricted": lambda d: find(d, "Namespace")["metadata"]["labels"].pop(
        "pod-security.kubernetes.io/enforce"),
    "liveness": lambda d: container(d, "analysis")["livenessProbe"]["exec"].update(
        command=["python", "-m", "api.probe", "/run/aegis/api/api.sock", "/ready"]),
    "isolation-gate init": lambda d: pod(d).update(initContainers=[]),
    "terminationGracePeriodSeconds": lambda d: pod(d).update(terminationGracePeriodSeconds=30),
    "sizeLimit": lambda d: next(v for v in pod(d)["volumes"] if v["name"] == "scratch")[
        "emptyDir"].pop("sizeLimit"),
    "8443": lambda d: find(d, "Service")["spec"]["ports"].append({"port": 8765}),
    "Secrets are created": lambda d: d.append({"kind": "Secret", "metadata": {
        "name": "aegis-api-token", "namespace": "aegis-sentinel"}, "data": {"api_token": "eA=="}}),
    "looks like a secret": lambda d: find(d, "ConfigMap", "aegis-analysis-config")["data"].update(
        SMTP_PASSWORD="x"),
    "HorizontalPodAutoscaler": lambda d: d.append({"kind": "HorizontalPodAutoscaler", "metadata": {
        "name": "a", "namespace": "aegis-sentinel"}}),
    "resources.limits.memory": lambda d: container(d, "proxy")["resources"]["limits"].pop("memory"),
}


@needs_kubectl
@pytest.mark.parametrize("what", sorted(BREAKS))
def test_the_checker_rejects_a_weakened_manifest(base, what):
    problems = _broken(base, BREAKS[what])
    assert problems, f"{what}: accepted"
    assert any(what.split()[0].lower() in p.lower() or what.lower() in p.lower()
               for p in problems), problems


def test_the_checker_reads_a_kubectl_list():
    docs = [{"kind": "List", "items": [{"kind": "Namespace", "metadata": {"name": "n"}}]}]
    assert "the Namespace must enforce" in " ".join(checker.check(docs))


# ------------------------------------------------------------------ the isolation gate

def test_a_reachable_destination_fails_the_gate(monkeypatch):
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(16)
        port = srv.getsockname()[1]
        assert gate.tcp_probe("127.0.0.1", port) == (False, "connected")
        monkeypatch.setattr(gate, "network_checks", lambda extra=(): [
            ("local listener", lambda: gate.tcp_probe("127.0.0.1", port))])
        assert gate.run_network() == [("blocked: local listener", False, "connected")]


def test_a_refused_or_silent_destination_counts_as_blocked(monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]                     # bound, not listening: refused
    blocked, detail = gate.tcp_probe("127.0.0.1", port)
    assert blocked and "refused" in detail
    monkeypatch.setattr(gate, "WAIT", 0.2)
    monkeypatch.setattr(gate, "network_checks", lambda extra=(): [
        ("hangs", lambda: __import__("time").sleep(5))])
    (name, ok, detail), = gate.run_network()
    assert ok and "no answer" in detail


def test_a_dns_server_that_answers_fails_the_gate():
    import threading
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(5)
        port = srv.getsockname()[1]

        def answer():
            data, peer = srv.recvfrom(512)
            srv.sendto(data[:2] + b"\x81\x80" + data[4:], peer)
        t = threading.Thread(target=answer)
        t.start()
        result = gate.udp_dns_probe("127.0.0.1", port)
        t.join()
    assert result == (False, "answered")


def test_a_silent_dns_server_counts_as_blocked(monkeypatch):
    monkeypatch.setattr(gate, "TIMEOUT", 0.3)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind(("127.0.0.1", 0))
        assert gate.udp_dns_probe("127.0.0.1", srv.getsockname()[1])[0] is True


def test_a_probe_that_raises_fails_the_gate(monkeypatch):
    def boom():
        raise RuntimeError("x")
    monkeypatch.setattr(gate, "network_checks", lambda extra=(): [("broken", boom)])
    assert gate.run_network()[0][1] is False


def test_the_gate_reads_cluster_dns_and_targets(tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("search x.svc.cluster.local\nnameserver 10.96.0.10\noptions ndots:5\n")
    assert gate.nameservers(str(conf)) == ["10.96.0.10"]
    assert gate.parse_target("10.0.0.1:443") == ("10.0.0.1", 443)
    assert gate.parse_target("[fd00::1]:53") == ("fd00::1", 53)
    with pytest.raises(ValueError):
        gate.parse_target("10.0.0.1")


def test_the_gate_flags_external_settings(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY_FILE", "/run/x")
    res = dict((n, ok) for n, ok, _ in gate.posture_checks())
    assert res["no external-service setting"] is False


def test_the_gate_names_no_unknown_mode():
    assert gate.main(["nonsense"]) == 2
    assert gate.main(["verify", "not-a-target"]) == 2


# ------------------------------------------------------------------ operator scripts

@pytest.mark.parametrize("script", ["verify-cluster.sh", "content-update.sh"])
def test_scripts_are_valid_bash(script):
    subprocess.run(["bash", "-n", str(K8S / script)], check=True, timeout=30)


@pytest.mark.parametrize("script,args", [
    ("verify-cluster.sh", []),
    ("verify-cluster.sh", ["--namespace", "aegis-sentinel", "--token-file", "t", "--ca-file", "c"]),
    ("verify-cluster.sh", ["--context", "kind-test", "--token-file", "t", "--ca-file", "c"]),
    ("content-update.sh", ["--namespace", "aegis-sentinel", "--pack", "p.tar.gz"]),
    ("content-update.sh", ["--context", "kind-test", "--pack", "p.tar.gz"]),
])
def test_scripts_need_an_explicit_context_and_namespace(tmp_path, script, args):
    """Without both, nothing reaches kubectl (a recording stub stands in for it)."""
    log = tmp_path / "calls"
    stub = tmp_path / "kubectl"
    stub.write_text(f"#!/bin/sh\necho \"$@\" >> {log}\n")
    stub.chmod(0o755)
    run = subprocess.run(["bash", str(K8S / script), *args], capture_output=True, text=True,
                         timeout=30, stdin=subprocess.DEVNULL,
                         env=dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}"))
    assert run.returncode == 2
    assert not log.exists()


def test_scripts_never_switch_the_current_context():
    for script in ("verify-cluster.sh", "content-update.sh"):
        text = (K8S / script).read_text()
        assert "use-context" not in text and "set-context" not in text
        calls = [line for line in text.splitlines() if not line.lstrip().startswith("#")
                 and (line.strip().startswith("kubectl") or " kubectl " in line)]
        assert calls
        assert all('--context "$ctx" --namespace "$ns"' in c for c in calls), calls


def test_the_token_never_appears_on_a_command_line():
    text = (K8S / "verify-cluster.sh").read_text()
    assert '-H "@$work/auth"' in text
    assert "Bearer $(cat" not in text and 'echo "$token' not in text


# ------------------------------------------------------------------ docs

def test_the_deployment_docs_link_the_kubernetes_guide():
    guide = ROOT / "docs" / "KUBERNETES.md"
    assert guide.is_file()
    assert "KUBERNETES.md" in (ROOT / "docs" / "DEPLOYMENT.md").read_text()
    assert "docs/KUBERNETES.md" in (ROOT / "README.md").read_text()
    text = guide.read_text()
    for section in ("## Architecture", "## Differences from Docker Compose", "## Verify",
                    "## Rule packs", "## Backup and restore", "## Intel"):
        assert section in text


def test_the_gate_is_not_in_the_image():
    """It reaches the Pod as a ConfigMap; the image keeps deploy/ out (.dockerignore)."""
    assert "\ndeploy\n" in (ROOT / ".dockerignore").read_text()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-q"]))
