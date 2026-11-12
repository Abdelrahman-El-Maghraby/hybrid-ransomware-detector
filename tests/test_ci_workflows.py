"""4.8 CI and release gates (PR-05, PR-06, S-04, PR-13): the structure the
workflows must keep. The runs themselves are the evidence; this stops a later
edit from quietly removing a gate."""

from pathlib import Path

import yaml

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows"


def _load(name):
    return yaml.safe_load((WF / name).read_text(encoding="utf-8"))


def _steps(job):
    return {s.get("name", ""): s for s in job["steps"]}


def test_matrix_installs_the_lock_first_and_states_the_dependency_set():
    job = _load("tests.yml")["jobs"]["pytest"]
    assert job["strategy"]["matrix"]["python"] == ["3.9", "3.12"]
    install = _steps(job)["Install dependencies"]["run"]
    assert "pip install --require-hashes -r requirements.lock" in install    # 3.12: must install
    assert "S-04" in install and "Dependency set" in install and "pip freeze" in install
    assert "per_package requirements.lock" not in install    # no unhashed per-package path


def test_matrix_installs_the_api_and_test_extras_and_fails_on_their_skips():
    steps = _steps(_load("tests.yml")["jobs"]["pytest"])
    install = steps["Install dependencies"]["run"]
    for pkg in ("fastapi", "uvicorn", "python-multipart", "httpx", "hypothesis", "jsonschema"):
        assert pkg in install
    check = steps["No API or fuzz test skipped for a missing package (PR-05)"]["run"]
    assert "fastapi|hypothesis" in check and "exit 1" in check


def test_release_builds_and_publishes_only_after_the_gate():
    jobs = _load("release.yml")["jobs"]
    assert jobs["build"]["needs"] == "gate" and jobs["image"]["needs"] == "gate"
    assert "gate" in jobs["publish"]["needs"]
    gate = jobs["gate"]
    assert gate["permissions"] == {"actions": "read", "contents": "read"}
    script = gate["steps"][0]["run"]
    for wf in ("tests.yml", "quality.yml", "docker.yml"):
        assert wf in script
    assert "head_sha=$SHA" in script and "status=success" in script
    assert gate["steps"][0]["env"]["SHA"] == "${{ github.sha }}"


def test_every_release_install_is_hash_pinned():
    """I-B2: the SBOM tool was installed without hashes in the jobs that hold the
    artifacts before they are signed. The unhashed `pip install --upgrade pip` of
    the build job was removed too (owner-approved 2026-11-12): no exception."""
    import re
    text = (WF / "release.yml").read_text(encoding="utf-8")
    installs = [line.strip() for line in text.splitlines()
                if re.search(r"\bpip\"?\s+install\b", line)]
    assert installs
    unpinned = [line for line in installs if "--require-hashes -r requirements" not in line]
    assert unpinned == []
    root = WF.parent.parent
    lock = (root / "requirements-sbom.lock").read_text(encoding="utf-8")
    assert "cyclonedx-bom==7.5.0" in lock and "--hash=sha256:" in lock


def test_the_dependency_audit_also_runs_daily_and_reports_failures():
    """I-3 (owner-approved 2026-11-12): the push-only audit missed advisories
    published between runs. The scheduled run audits the same locks and opens
    or updates an issue when it fails; only that job may write issues."""
    wf = _load("dependency-audit.yml")
    on = wf[True] if True in wf else wf["on"]           # YAML 1.1 reads `on` as True
    assert on["schedule"][0]["cron"] and "workflow_dispatch" in on
    assert wf["permissions"] == {"contents": "read"}
    audit = _steps(wf["jobs"]["audit"])["Known vulnerabilities in the pinned dependencies"]["run"]
    quality = _steps(_load("quality.yml")["jobs"]["dependency-audit"])[
        "Known vulnerabilities in the pinned dependencies"]["run"]
    assert audit == quality and "--require-hashes" in audit
    report = wf["jobs"]["report"]
    assert report["needs"] == "audit" and report["permissions"] == {"issues": "write"}
    assert "failure()" in report["if"] and "schedule" in report["if"]
    script = report["steps"][0]["run"]
    assert "gh issue create" in script and "gh issue comment" in script
