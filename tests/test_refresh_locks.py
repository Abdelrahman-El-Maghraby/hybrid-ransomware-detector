"""I-3 option A (owner-approved 2026-11-12): tools/refresh_locks.py regenerates
the four hash-pinned locks into a scratch folder. Its commands must stay the ones
written in each lock's header, and it must never write the tracked locks,
install, commit or open a pull request. No network here: uv and pip-audit are
replaced by stand-ins."""

import re
import shlex
import subprocess
from pathlib import Path

import pytest

import tools.refresh_locks as R

ROOT = Path(__file__).resolve().parent.parent


def _header_command(lock: str):
    text = R.header((ROOT / lock).read_text())
    parts = []
    for line in text.split("uv pip compile", 1)[1].splitlines():
        line = line.lstrip("#").strip()
        parts.append(line.rstrip("\\"))
        if not line.endswith("\\"):                       # the command's last line
            break
    return shlex.split(" ".join(parts))


@pytest.mark.parametrize("lock,inputs,constrained", R.LOCKS)
def test_commands_match_the_lock_headers(lock, inputs, constrained):
    args = R.compile_args(lock, inputs, constrained, Path("OUT"))[2:]
    args = [a.replace("OUT/", "").replace("OUT\\", "") for a in args]   # / or \
    assert args == _header_command(lock)


def test_every_lock_is_refreshed_in_dependency_order():
    assert sorted(p.name for p in ROOT.glob("requirements*.lock")) == sorted(
        lock for lock, _, _ in R.LOCKS)
    assert R.LOCKS[0][0] == "requirements.lock"           # the constraint comes first


def test_the_script_never_installs_commits_or_opens_a_pr():
    code = (ROOT / "tools" / "refresh_locks.py").read_text()
    for forbidden in ("pip install", "\"install\"", "git", "\"gh\"", "push", "shell=True"):
        assert forbidden not in code.split('"""', 2)[2], forbidden   # outside the docstring


def test_it_refuses_the_repository_as_output():
    with pytest.raises(SystemExit):
        R.main(["--out", str(ROOT), "--no-audit"])


def test_a_run_writes_only_the_output_folder(tmp_path, monkeypatch):
    tracked = {p.name: p.read_bytes() for p in ROOT.glob("requirements*.lock")}
    calls = []

    def fake_run(cmd, cwd=None, stdout=None):
        calls.append(cmd)
        if cmd[1:3] == ["pip", "compile"]:
            out = Path(cmd[cmd.index("-o") + 1])
            text = out.read_text()
            body = text[len(R.header(text)):]
            if out.name == "requirements-sbom.lock":      # a bumped pin, header dropped
                body = re.sub(r"^attrs==\S+", "attrs==99.0", body, flags=re.M)
            if "-c" in cmd:                               # uv's annotation of the constraint
                body = body.replace("-c requirements.lock", f"-c {cmd[cmd.index('-c') + 1]}")
            out.write_text(body)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(R, "_tool", lambda name: f"/stand-in/{name}")
    monkeypatch.setattr(R.subprocess, "run", fake_run)
    out = tmp_path / "locks"
    assert R.main(["--out", str(out), "--upgrade-package", "attrs"]) == 0
    assert {p.name: p.read_bytes() for p in ROOT.glob("requirements*.lock")} == tracked
    for name, old in tracked.items():
        new = (out / name).read_text()
        old_text = old.decode().replace("\r\n", "\n")    # a Windows checkout has CRLF
        assert R.header(new) == R.header(old_text)        # header kept
        if name != "requirements-sbom.lock":              # identical where no pin moved
            assert new == old_text
    assert R.pins((out / "requirements-sbom.lock").read_text())["attrs"] == "99.0"
    compiles = [c for c in calls if c[1:3] == ["pip", "compile"]]
    assert [Path(c[c.index("-o") + 1]).name for c in compiles] == [x for x, _, _ in R.LOCKS]
    assert all(c[-2:] == ["--upgrade-package", "attrs"] for c in compiles)
    audits = [c for c in calls if c[0].endswith("pip-audit")]
    assert len(audits) == 4 and all("--disable-pip" in c for c in audits)
    server = compiles[1]
    assert server[server.index("-c") + 1] == str(out.resolve() / "requirements.lock")


def test_changes_lists_moved_added_and_removed_pins():
    old = "a==1 \\\n    --hash=sha256:x\nb==2 \\\n"
    new = "a==1.1 \\\n    --hash=sha256:y\nc==3 \\\n"
    assert R.changes(old, new) == ["  a: 1 -> 1.1", "  c: added 3", "  b: removed 2"]
