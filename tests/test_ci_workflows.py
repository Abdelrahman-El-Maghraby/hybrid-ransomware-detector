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
    assert install.index("pip install -r requirements.lock") < install.index("per_package requirements.txt")
    assert "S-04" in install and "Dependency set" in install and "pip freeze" in install


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
