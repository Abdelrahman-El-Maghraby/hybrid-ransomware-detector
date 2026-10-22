"""4.4.0-beta.2: optional CAPEv2 sandbox layer. The CAPE server is simulated by a
fake HTTP session; nothing is submitted anywhere."""

import json

import pytest

import RansomwareScanner as RS
from core.sandbox import CapeClient, SandboxResult, summarise_report
from detectors.scoring import ScoringMatrix
from tests.test_scanner_integration import _config

REPORT = {
    "malscore": 9.2,
    "signatures": [
        {"name": "deletes_shadow_copies", "description": "Deletes volume shadow copies",
         "severity": 3, "categories": ["ransomware"]},
        {"name": "injection_runpe", "description": "Process hollowing", "severity": 3,
         "categories": ["injection"]},
        {"name": "antivm_checks", "description": "Checks for a virtual machine", "severity": 1},
    ],
    "network": {"hosts": [{"ip": "203.0.113.9"}], "domains": [{"domain": "c2.example.invalid"}]},
}


class FakeResponse:
    def __init__(self, body, status=200):
        self._body, self.status_code = body, status

    def json(self):
        return self._body


class FakeCape:
    """Minimal stand-in for the CAPE apiv2 endpoints."""
    def __init__(self, statuses=("pending", "running", "reported"), report=REPORT, refuse=False):
        self.statuses, self.report, self.refuse = list(statuses), report, refuse
        self.headers, self.posts, self.gets = {}, [], []

    def post(self, url, files=None, data=None, timeout=None):
        self.posts.append(url)
        if self.refuse:
            return FakeResponse({"error": True, "error_value": "file too big"}, 400)
        return FakeResponse({"error": False, "data": {"task_ids": [42]}})

    def get(self, url, timeout=None):
        self.gets.append(url)
        if "/tasks/view/" in url:
            status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            return FakeResponse({"data": {"status": status}})
        return FakeResponse(self.report)


def client(fake, wait=600):
    clock = {"t": 0.0}

    def sleep(s):
        clock["t"] += s
    return CapeClient("http://cape.lab:8000/", token="t0k", session=fake, wait_seconds=wait,
                      poll_seconds=15, sleep=sleep, clock=lambda: clock["t"])


def test_report_is_summarised():
    res = SandboxResult()
    summarise_report(REPORT, res)
    assert res.malscore == 9.2 and res.ransomware == ["deletes_shadow_copies"]
    assert [s["severity"] for s in res.signatures] == [3, 3, 1]
    assert res.network_hosts == ["203.0.113.9", "c2.example.invalid"]


def test_submit_poll_and_fetch(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"inert test bytes")
    fake = FakeCape()
    res = client(fake).analyze(str(f))
    assert res.status == "reported" and res.task_id == 42
    assert fake.posts == ["http://cape.lab:8000/apiv2/tasks/create/file/"]
    assert fake.gets[-1].endswith("/apiv2/tasks/get/report/42/")
    assert fake.headers["Authorization"] == "Token t0k"


@pytest.mark.parametrize("fake,status", [
    (FakeCape(statuses=("running",)), "timeout"),
    (FakeCape(statuses=("failed_analysis",)), "error"),
    (FakeCape(refuse=True), "error"),
])
def test_failures_are_reported_not_raised(tmp_path, fake, status):
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")
    assert client(fake, wait=60).analyze(str(f)).status == status


def test_unreachable_server(tmp_path):
    class Broken(FakeCape):
        def post(self, *a, **k):
            raise ConnectionError("refused")
    f = tmp_path / "s.bin"
    f.write_bytes(b"x")
    r = client(Broken()).analyze(str(f))
    assert r.status == "error" and "unreachable" in r.detail


def test_scoring_dynamic_category():
    m = ScoringMatrix()
    s = m.score({"sandbox": {"ransomware": ["deletes_shadow_copies"],
                             "signatures": REPORT["signatures"]}})
    ind = {c.indicator: (c.category, c.points) for c in s.contributions}
    assert ind["sandbox_ransomware_behaviour"] == ("dynamic", 80.0)
    assert ind["sandbox_behaviour"] == ("dynamic", 29.0)            # 25 + 4
    assert s.verdict == "Critical"
    weak = m.score({"sandbox": {"signatures": [{"name": "antivm", "severity": 1}]}})
    assert weak.verdict == "Low"                                     # dynamic counts as hard evidence


def _scanner(tmp_path, fake, submit="suspicious"):
    cfg = _config(tmp_path)
    cfg.update({"sandbox_url": "http://cape.lab:8000", "sandbox_submit": submit})
    s = RS.RansomwareScanner(cfg)
    s.sandbox = client(fake)
    return s


def test_scanner_submits_only_suspicious_top_level_files(tmp_path):
    from tests.helpers import make_pdf
    from tests.test_file_integrity import _pe_bytes
    (tmp_path / "scan").mkdir(exist_ok=True)
    clean = tmp_path / "scan" / "letter.pdf"
    clean.write_bytes(make_pdf("Hello"))
    odd = tmp_path / "scan" / "invoice.pdf"
    odd.write_bytes(_pe_bytes(4096) + b"\x00" * 100)
    fake = FakeCape()
    s = _scanner(tmp_path, fake)
    assert "sandbox" not in s.scan_file(str(clean))["scan_results"]
    assert fake.posts == []
    r = s.scan_file(str(odd))                     # static 100 -> heavy layers skipped too
    assert fake.posts == [] and "sandbox" in r["scan_results"]["skipped_layers"]["layers"]


def test_scanner_records_sandbox_result_and_report_line(tmp_path):
    (tmp_path / "scan").mkdir(exist_ok=True)
    p = tmp_path / "scan" / "tool.ps1"
    p.write_bytes(b"Start-Process notepad.exe\r\n")
    fake = FakeCape()
    s = _scanner(tmp_path, fake, submit="all")
    r = s.scan_file(str(p))
    assert r["scan_results"]["sandbox"]["task_id"] == 42
    assert r["verdict"] == "Critical"
    report = s.generate_report([r])
    assert "[Sandbox]" in report and "203.0.113[.]9" in report
    json.dumps(r)                                  # result stays serialisable
