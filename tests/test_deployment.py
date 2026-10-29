"""4.7: the Docker deployment keeps its hardening. These read docker-compose.yml,
the Dockerfile and .dockerignore; deploy/check-deployment.sh (CI: docker.yml)
proves the same properties on running containers."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]
RUNNING = [name for name, s in SERVICES.items() if "tools" not in s.get("profiles", [])]
EXTERNAL_SECRETS = {"virustotal_api_key", "openai_api_key", "sandbox_token",
                    "smtp_password"}       # 4.8: e-mail alerts are sent by intel


def test_the_three_services_exist():
    assert set(RUNNING) == {"intel", "analysis", "proxy"}


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_every_service_is_hardened(name):
    s = SERVICES[name]
    assert s["read_only"] is True
    assert s["cap_drop"] == ["ALL"] and "cap_add" not in s
    assert "no-new-privileges:true" in s["security_opt"]
    assert not any("unconfined" in o or "seccomp" in o or "apparmor" in o
                   for o in s["security_opt"])            # Docker's default profiles apply
    assert not s.get("privileged") and "pid" not in s and "ipc" not in s
    user = str(s["user"]).split(":")
    assert user[0] not in ("0", "root") and int(user[0]) >= 10000
    assert not any("docker.sock" in str(v) for v in s.get("volumes", []))
    tmp = [t for t in s.get("tmpfs", []) if t.startswith("/tmp:")]  # nosec B108
    assert all("noexec" in t and "nosuid" in t and "nodev" in t for t in s.get("tmpfs", []))
    if name != "proxy":
        assert tmp, "the extraction sandbox is a size-limited tmpfs"
    if name in RUNNING:
        assert s["mem_limit"] and s["cpus"] and s["pids_limit"]


def test_analysis_has_no_network_and_no_external_secret():
    a = SERVICES["analysis"]
    assert a["network_mode"] == "none" and "networks" not in a and "ports" not in a
    assert set(a["secrets"]) == {"api_token", "intel_token"}
    env = " ".join(f"{k}={v}" for k, v in a["environment"].items())
    for word in ("VIRUSTOTAL", "OPENAI", "SANDBOX_URL", "SANDBOX_TOKEN"):
        assert word not in env
    assert a["environment"]["AEGIS_PROFILE"] == "production"
    assert "CACHE_DB_PATH" not in a["environment"]        # answers are cached by intel only
    assert a["environment"]["AEGIS_INTEL_SOCKET"].startswith("/run/aegis/intel/")


def test_detection_content_is_read_only_where_files_are_opened():
    mounts = SERVICES["analysis"]["volumes"]
    content = [m for m in mounts if m.startswith("content:")]
    assert content == ["content:/var/lib/aegis/RansomwareScanner/data:ro"]
    writers = [n for n, s in SERVICES.items()
               if any(m.startswith("content:") and not m.endswith(":ro") for m in s.get("volumes", []))]
    assert writers == ["content"] and SERVICES["content"]["network_mode"] == "none"


def test_only_the_proxy_is_reachable_and_only_intel_has_egress():
    published = [n for n, s in SERVICES.items() if s.get("ports")]
    assert published == ["proxy"]
    assert SERVICES["intel"]["networks"] == ["egress"] and "ports" not in SERVICES["intel"]
    assert SERVICES["proxy"]["networks"] == ["edge"]
    assert set(SERVICES["intel"]["secrets"]) == {"intel_token"} | EXTERNAL_SECRETS
    assert SERVICES["intel"]["environment"]["VT_UPLOAD_UNKNOWN"] == "${VT_UPLOAD_UNKNOWN:-false}"


def test_secrets_come_from_files_not_the_environment():
    for name in RUNNING:
        env = SERVICES[name].get("environment", {})
        for key, value in env.items():
            if any(w in key for w in ("TOKEN", "KEY", "PASSWORD", "SECRET")):
                assert key.endswith("_FILE") and str(value).startswith("/run/secrets/"), key


def test_sockets_are_shared_only_with_their_clients():
    def users(volume):
        return sorted(n for n, s in SERVICES.items()
                      if any(m.startswith(volume + ":") for m in s.get("volumes", [])))
    assert users("intel-socket") == ["analysis", "intel"]
    assert users("api-socket") == ["analysis", "proxy"]
    assert SERVICES["analysis"]["group_add"] == ["10010"] and SERVICES["proxy"]["group_add"] == ["10020"]


def test_dockerfile_pins_bases_and_runs_unprivileged():
    text = (ROOT / "Dockerfile").read_text()
    for arg in ("ARG PYTHON=", "ARG CADDY="):
        line = next(ln for ln in text.splitlines() if ln.startswith(arg))
        assert "@sha256:" in line, line
    assert "USER 10001:10001" in text
    assert "setcap -r /usr/bin/caddy" in text
    assert "-c requirements.lock" in text
    assert "test ! -e /app/core/containment.py && test ! -e /app/core/response.py" in text
    ignored = (ROOT / ".dockerignore").read_text().splitlines()
    assert {"core/containment.py", "core/response.py", ".env", "tests", ".git"} <= set(ignored)


def test_proxy_terminates_tls_with_the_operators_certificate():
    caddy = (ROOT / "deploy" / "Caddyfile").read_text()
    assert "tls /etc/caddy/tls/cert.pem /etc/caddy/tls/key.pem" in caddy
    assert "admin off" in caddy and "reverse_proxy unix//run/aegis/api/api.sock" in caddy
    directives = [ln for ln in caddy.splitlines() if not ln.strip().startswith("#")]
    assert not any("trusted_proxies" in ln for ln in directives)   # XFF is the real peer
    assert SERVICES["analysis"]["environment"]["AEGIS_API_TRUST_PROXY"] == "1"


def test_workflow_actions_are_pinned_to_commits():
    """A tag can be moved to other code; a commit SHA cannot (A10-1)."""
    import re
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for n, line in enumerate(wf.read_text().splitlines(), 1):
            m = re.search(r"uses:\s*(\S+)", line)
            if m and not m.group(1).startswith("./"):
                assert re.search(r"@[0-9a-f]{40}$", m.group(1)), f"{wf.name}:{n} {m.group(1)}"
