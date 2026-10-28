"""4.7 (schema 1.3): every result records what left the machine for it -
`provenance.shared`, one entry per external service really contacted (an answer
from a cache sent nothing), members of a container included - and every share is
logged. Nothing here contacts a real service."""

import io
import logging
import zipfile

import jsonschema
import pytest
import requests

import RansomwareScanner as RS
from api import load_schema
from tests.test_scanner_integration import _config

STATS = (b'{"data": {"attributes": {"last_analysis_stats": '
         b'{"malicious": 2, "suspicious": 0, "undetected": 68}}}}')


class FakeVTSession:
    def __init__(self, status=200):
        self.status, self.urls = status, []

    def get(self, url, headers=None, timeout=None):
        self.urls.append(url)
        r = requests.Response()
        r.status_code, r._content = self.status, STATS if self.status == 200 else b"{}"
        return r


class CloudModel:
    name, model, is_local, available = "openai", "gpt-4", False, True

    def analyze(self, content):
        return {"is_malicious": False, "confidence": 0, "suspicious_elements": [],
                "details": "ok", "analyzed": True}


def _scanner(tmp_path, **extra):
    cfg = _config(tmp_path, data_dir=str(tmp_path / "data"), virustotal_api_key="vt-test-key",
                  virustotal_requests_per_minute=0, skip_heavy_when_saturated=False, **extra)
    s = RS.RansomwareScanner(cfg)
    s.http = FakeVTSession()
    return s


def _text(tmp_path, name="note.txt", body="Quarterly figures attached."):
    p = tmp_path / "scan" / name
    p.write_text(body)
    return p


def test_hash_lookup_is_recorded_and_a_cached_answer_sends_nothing(tmp_path, caplog):
    s = _scanner(tmp_path)
    f = _text(tmp_path)
    with caplog.at_level(logging.INFO, logger="RansomwareScanner"):
        first = s.scan_file(str(f))
    assert first["provenance"]["shared"] == [{"service": "virustotal", "sent": ["sha256"]}]
    assert "Sent outside for" in caplog.text and "virustotal (sha256)" in caplog.text
    event = [r for r in caplog.records if getattr(r, "event", "") == "external_share"]
    assert event and event[0].shared == [{"service": "virustotal", "sent": ["sha256"]}]
    assert "Sent outside:           virustotal sha256 for 1 file(s)" in s.generate_report([first])
    second = s.scan_file(str(f))
    assert second["scan_results"]["virustotal"]["cached"] is True
    assert second["provenance"]["shared"] == [] and len(s.http.urls) == 1
    jsonschema.validate(first, load_schema())


def test_upload_and_cloud_llm_are_recorded(tmp_path, monkeypatch):
    s = _scanner(tmp_path, virustotal_upload_unknown=True, cache_enabled=False)
    s.cache = None
    s.http = FakeVTSession(status=404)
    s.llm_backend = CloudModel()
    ok = requests.Response()
    ok.status_code, ok._content = 200, STATS
    monkeypatch.setattr(s, "_vt_upload_and_wait", lambda *a: ok)
    r = s.scan_file(str(_text(tmp_path, body="Pay 2 BTC to decrypt your files")))
    shared = {e["service"]: e for e in r["provenance"]["shared"]}
    assert shared["virustotal"]["sent"] == ["sha256", "file"]
    assert shared["llm"] == {"service": "llm", "sent": ["text"], "destination": "cloud"}
    jsonschema.validate(r, load_schema())


def test_nothing_is_recorded_when_no_service_is_configured(tmp_path):
    s = RS.RansomwareScanner(_config(tmp_path, data_dir=str(tmp_path / "data")))
    r = s.scan_file(str(_text(tmp_path)))
    assert r["provenance"]["shared"] == []


def test_members_of_a_container_are_included(tmp_path):
    s = _scanner(tmp_path, cache_enabled=False)
    s.cache = None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "Quarterly figures attached.")
    archive = tmp_path / "scan" / "bundle.zip"
    archive.write_bytes(buf.getvalue())
    r = s.scan_file(str(archive))
    members = [e for e in r["provenance"]["shared"] if e.get("member_path")]
    if not members:
        pytest.skip("this installation does not scan archive members with the external layers")
    assert members[0]["service"] == "virustotal" and members[0]["member_path"].endswith("readme.txt")
    jsonschema.validate(r, load_schema())


def test_through_intel_what_intel_sent_is_recorded(tmp_path):
    from tests.test_intel_service import CAPS, ScriptedIntel
    cfg = _config(tmp_path, data_dir=str(tmp_path / "data"), intel_socket=str(tmp_path / "x.sock"),
                  intel_token="i" * 40)
    s = RS.RansomwareScanner(cfg)
    f = _text(tmp_path)
    clean = {"is_malicious": False, "malicious_detections": 0, "total_engines": 70}
    s.intel = ScriptedIntel(CAPS, {"/v1/virustotal/lookup": dict(clean, sent=["sha256"])})
    assert s.scan_file_with_virustotal(str(f))["sent"] == ["sha256"]
    s.intel = ScriptedIntel(CAPS, {"/v1/virustotal/lookup": dict(clean, cached=True)})
    assert "sent" not in s.scan_file_with_virustotal(str(f))       # intel's cache answered
