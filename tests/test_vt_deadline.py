"""I-6, VirusTotal part: inside an isolated worker the opt-in upload wait (ten
status checks 15 s apart) ends with the scan's limit less the M26 margin, and a
file is not uploaded when not even one check would fit. Outside a worker nothing
changes. VirusTotal is a fake session; nothing leaves the machine."""

import time

import pytest

import RansomwareScanner as RS
from engine import external
from tests.test_intel_service import CAPS, ScriptedIntel
from tests.test_scanner_integration import _config


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body, self.text = status, body or {}, ""

    def json(self):
        return self._body


class FakeVT:
    """The hash is unknown; an upload is accepted; its analysis finishes after
    `finish_after` status checks (never, by default)."""

    def __init__(self, finish_after=None):
        self.finish_after, self.checks, self.posts = finish_after, 0, 0

    def get(self, url, headers=None, timeout=None):
        if "/analyses/" in url:
            self.checks += 1
            done = self.finish_after is not None and self.checks >= self.finish_after
            return Resp(200, {"data": {"attributes": {"status": "completed" if done else "queued"}}})
        if self.finish_after is not None and self.checks >= self.finish_after:
            return Resp(200, {"data": {"attributes": {"last_analysis_stats":
                                                      {"malicious": 3, "undetected": 60}}}})
        return Resp(404)

    def post(self, url, headers=None, files=None, timeout=None):
        self.posts += 1
        return Resp(200, {"data": {"id": "an-1"}})


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    monkeypatch.setattr(external, "VT_POLL_SECONDS", 0.2)
    s = RS.RansomwareScanner(_config(tmp_path, virustotal_api_key="k" * 64,
                                     virustotal_upload_unknown=True,
                                     virustotal_requests_per_minute=0))
    s.cache = None
    return s


def _file(tmp_path):
    p = tmp_path / "unknown.bin"
    p.write_bytes(b"inert bytes for an unknown hash")
    return str(p)


def _in_worker(s, left, limit):
    s.config["scan_timeout_seconds"] = limit
    s.scan_deadline = time.monotonic() + left


def test_outside_a_worker_the_wait_is_unchanged(scanner, tmp_path):
    scanner.http = vt = FakeVT()
    r = scanner.scan_file_with_virustotal(_file(tmp_path))
    assert vt.checks == external.VT_POLLS and "upload did not complete" in r["details"]
    assert r["sent"] == ["sha256", "file"] and "status" not in r


def test_a_finished_analysis_is_used_in_a_worker(scanner, tmp_path):
    scanner.http = FakeVT(finish_after=2)
    _in_worker(scanner, left=30, limit=20)                # 30 - 2 s margin: plenty
    r = scanner.scan_file_with_virustotal(_file(tmp_path))
    assert r["malicious_detections"] == 3 and r["sent"] == ["sha256", "file"]


def test_the_upload_wait_ends_before_the_scan_limit(scanner, tmp_path):
    scanner.http = vt = FakeVT()
    _in_worker(scanner, left=2.5, limit=5)                # 2.5 - 1 s margin = 1.5 s
    started = time.monotonic()
    r = scanner.scan_file_with_virustotal(_file(tmp_path))
    assert time.monotonic() - started < 1.6
    assert 1 <= vt.checks < external.VT_POLLS
    assert r["status"] == "timeout" and "did not finish before the scan time limit" in r["details"]
    assert r["sent"] == ["sha256", "file"]                # the upload did leave the machine


def test_no_upload_when_not_one_check_fits(scanner, tmp_path, monkeypatch):
    monkeypatch.setattr(external, "VT_POLL_SECONDS", 3.0)
    scanner.http = vt = FakeVT()
    _in_worker(scanner, left=2.5, limit=5)                # 1.5 s: a lookup, not a 3 s check
    r = scanner.scan_file_with_virustotal(_file(tmp_path))
    assert vt.posts == 0 and r["sent"] == ["sha256"]      # the hash only
    assert r["status"] == "timeout" and "not uploaded: no time left" in r["details"]


def test_a_cut_wait_makes_the_scan_partial(scanner, tmp_path):
    scanner.http = FakeVT()
    _in_worker(scanner, left=2.5, limit=5)
    r = scanner.scan_file(_file(tmp_path))
    assert r["scan_status"] == "partial"
    assert any(g["layer"] == "virustotal" for g in r["incomplete_reasons"])
    assert {"service": "virustotal", "sent": ["sha256", "file"]} in r["provenance"]["shared"]


def test_through_intel_no_upload_without_time_and_a_bounded_call(scanner, tmp_path,
                                                                  monkeypatch):
    monkeypatch.setattr(external, "VT_POLL_SECONDS", 3.0)
    calls = []

    lookups = []

    class Intel(ScriptedIntel):
        def vt_lookup(self, sha256, timeout=None):
            lookups.append(timeout)
            return super().vt_lookup(sha256)

        def vt_upload(self, path, timeout=None):
            calls.append(timeout)
            return {"not_found": True, "details": "queued", "sent": ["file"]}
    intel = Intel(CAPS, {"/v1/virustotal/lookup": {"not_found": True, "sent": ["sha256"]}})
    scanner.intel = intel
    _in_worker(scanner, left=2.5, limit=5)                # a lookup fits, a 3 s check not
    r = scanner.scan_file_with_virustotal(_file(tmp_path))
    assert calls == [] and r["sent"] == ["sha256"] and r["status"] == "timeout"
    assert 0 < lookups[0] <= 1.6                          # the lookup got the time left
    _in_worker(scanner, left=40, limit=20)
    scanner.scan_file_with_virustotal(_file(tmp_path))
    assert len(calls) == 1 and 30 < calls[0] <= 38       # the time left less the margin
    scanner.scan_deadline = None
    calls.clear()

    class Plain(ScriptedIntel):                           # an IntelClient without the
        def vt_upload(self, path):                        # timeout keyword: unchanged
            calls.append("plain")
            return {"not_found": True, "sent": ["file"]}
    scanner.intel = Plain(CAPS, {"/v1/virustotal/lookup": {"not_found": True, "sent": ["sha256"]}})
    scanner.scan_file_with_virustotal(_file(tmp_path))
    assert calls == ["plain"]
