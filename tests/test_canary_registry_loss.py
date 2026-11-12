"""M25 (owner-approved 2026-11-12, alert only): an overwritten or deleted canary
registry read as "No canaries deployed", so ransomware that hit the registry
silenced the tripwire. A second copy (in the reports folder) and the last good
list in memory now tell a lost registry from a first installation: the loss is
a "registry" finding that alerts but never starts the containment response,
and the remembered canaries are still checked."""

import json
import os
from pathlib import Path

import pytest

import RansomwareScanner as RS
from core import response
from core.canary import CanaryManager
from tests.test_scanner_integration import _config


@pytest.fixture
def folder(tmp_path):
    d = tmp_path / "docs"
    d.mkdir()
    return d


def _manager(tmp_path):
    return CanaryManager(tmp_path / "data" / "canaries.json",
                         copy_path=tmp_path / "reports" / ".canary_registry_copy.json")


def _statuses(report):
    return sorted(f.status for f in report.findings)


def test_a_first_installation_has_no_finding(tmp_path):
    report = _manager(tmp_path).verify()
    assert report.summary() == "No canaries deployed." and not report.triggered


@pytest.mark.parametrize("lose", ["overwrite", "delete"])
def test_a_lost_registry_trips_and_the_canaries_are_still_checked(tmp_path, folder, lose):
    """Check 7 of the review: one canary overwritten, then the registry lost."""
    m = _manager(tmp_path)
    m.deploy([folder])
    assert m.verify().summary() == "3/3 canaries intact."
    victim = next(folder.glob("!000_*.pdf"))
    victim.write_bytes(os.urandom(victim.stat().st_size))
    if lose == "overwrite":
        m.registry_path.write_bytes(os.urandom(200))
    else:
        m.registry_path.unlink()
    report = m.verify()
    assert report.triggered and _statuses(report) == ["encrypted", "registry"]
    assert report.deployed == 3 and report.intact == 2


def test_a_new_process_finds_the_loss_through_the_copy(tmp_path, folder):
    _manager(tmp_path).deploy([folder])
    (tmp_path / "data" / "canaries.json").unlink()
    report = _manager(tmp_path).verify()                    # nothing in memory
    assert _statuses(report) == ["registry"] and report.intact == 3
    assert "is missing" in report.findings[0].evidence
    assert len(_manager(tmp_path).paths()) == 3             # still excluded from scans


def test_the_last_good_list_covers_a_lost_copy_too(tmp_path, folder):
    m = _manager(tmp_path)
    m.deploy([folder])
    m.registry_path.unlink()
    m.copy_path.unlink()
    assert _statuses(m.verify()) == ["registry"]
    assert not _manager(tmp_path).verify().triggered        # a new process cannot know


def test_removing_canaries_is_not_a_loss(tmp_path, folder):
    m = _manager(tmp_path)
    m.deploy([folder])
    assert m.remove() == 3
    assert json.loads(m.copy_path.read_text())["canaries"] == []
    assert not m.verify().triggered and not _manager(tmp_path).verify().triggered


def test_an_existing_registry_without_a_copy_works_as_before(tmp_path, folder):
    """Registries written before M25 have no copy; the next save writes one."""
    old = CanaryManager(tmp_path / "data" / "canaries.json")
    old.deploy([folder])
    m = _manager(tmp_path)
    assert m.verify().summary() == "3/3 canaries intact." and not m.copy_path.exists()


def test_a_lost_registry_alerts_without_the_containment_response(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(response, "respond", lambda *a, **k: called.append(a) or [])
    sent = []
    monkeypatch.setattr("core.outbox.queue_and_send", lambda alerts, cfg: sent.extend(alerts))
    scanner = RS.RansomwareScanner(_config(tmp_path, canary_response="script"))
    scanner.deploy_canaries([str(tmp_path / "scan")])
    Path(scanner.canaries.registry_path).unlink()
    report = scanner.check_canaries(notify=False)
    assert _statuses(report) == ["registry"] and called == []
    alert = next(Path(scanner.report_dir).glob("canary_alert_*.txt")).read_text()
    assert "[registry]" in alert and "Automatic response:" not in alert
    assert [a["kind"] for a in sent] == ["canary"]
    assert sent[0]["email"]["reason_codes"] == ["canary_registry"]
    victim = next((tmp_path / "scan").glob("!000_*.pdf"))     # a real trip still responds
    victim.write_bytes(os.urandom(victim.stat().st_size))
    scanner.check_canaries(notify=False)
    assert len(called) == 1 and [f["status"] for f in called[0][1]["findings"]] == ["encrypted"]
