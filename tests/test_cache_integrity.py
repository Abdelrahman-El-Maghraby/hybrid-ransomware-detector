"""4.7: the result cache cannot be poisoned from a scan worker.

In the Docker deployment the scan workers open hostile files, so a parser exploit
there must not be able to plant a clean VirusTotal / LLM / sandbox answer for some
other file. The analysis side therefore keeps no cache of external answers; the
intel service caches them, and only from the real service's reply, under a key it
derives itself (the requested hash, the hash of the bytes it received, the hash of
the text it was given)."""

import hashlib

import pytest

import RansomwareScanner as RS
from core.cache import ResultCache
from tests.test_intel_service import CAPS, FakeCape, FakeVT, ScriptedIntel, _intel_config
from tests.test_scanner_integration import _config

TOKEN = "i" * 40
CLEAN = {"is_malicious": False, "detection_ratio": 0, "malicious_detections": 0,
         "suspicious_detections": 0, "total_engines": 70, "permalink": ""}


def test_a_planted_cache_entry_is_never_served(tmp_path):
    """What a compromised worker could do: write 'clean' answers into the cache file."""
    f = tmp_path / "payload.bin"
    f.write_bytes(b"inert stand-in for a second payload")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    cache_db = tmp_path / "data" / "scan_cache.sqlite3"
    cfg = _config(tmp_path, data_dir=str(tmp_path / "data"), cache_db_path=str(cache_db),
                  intel_socket=str(tmp_path / "intel.sock"), intel_token=TOKEN)
    scanner = RS.RansomwareScanner(cfg)
    assert scanner.cache is None                       # nothing to read from or write to

    planted = ResultCache(str(cache_db))
    planted.put(sha, "virustotal", CLEAN)
    planted.put(sha, "virustotal:upload", CLEAN)
    planted.put(sha, scanner._llm_cache_layer(), {"is_malicious": False, "analyzed": True})

    scanner.intel = ScriptedIntel(CAPS, {
        "/v1/virustotal/lookup": {**CLEAN, "is_malicious": True, "malicious_detections": 41},
        "/v1/llm/analyze": {"is_malicious": True, "confidence": 90, "analyzed": True}})
    scanner.llm_backend.client = scanner.intel
    assert scanner.scan_file_with_virustotal(str(f))["malicious_detections"] == 41
    assert scanner.analyze_with_llm(str(f), "pay to decrypt", "", sha256=sha)["is_malicious"]
    assert [c[0] for c in scanner.intel.calls] == ["/v1/virustotal/lookup", "/v1/llm/analyze"]


def test_the_desktop_keeps_its_local_cache(tmp_path):
    scanner = RS.RansomwareScanner(_config(tmp_path, data_dir=str(tmp_path / "data")))
    assert scanner.cache is not None                   # no intel: one process, no boundary


@pytest.fixture
def intel_service(tmp_path):
    pytest.importorskip("fastapi")
    from api.intel import IntelService
    service = IntelService(_intel_config(tmp_path, cache_db_path=str(tmp_path / "intel.db"),
                                         cache_enabled=True))
    vt = FakeVT()
    for client in (service._vt, service._vt_upload):
        client.http = vt
    service.sandbox.session = FakeCape()
    return service, vt


def test_intel_caches_virustotal_answers_it_fetched(intel_service):
    service, vt = intel_service
    sha = "cd" * 32
    first = service.vt_lookup(sha)
    second = service.vt_lookup(sha)
    assert first["malicious_detections"] == 3 and second["cached"] is True
    assert len(vt.seen) == 1
    service.vt_lookup("ef" * 32)                       # another hash is another key
    assert len(vt.seen) == 2


def test_intel_caches_llm_answers_by_the_text_it_was_given(intel_service):
    service, _ = intel_service
    calls = []

    class Model:
        name, model, is_local, available = "ollama", "llama3.1", True, True

        def analyze(self, content):
            calls.append(content)
            return {"is_malicious": "decrypt" in content, "confidence": 80, "analyzed": True}
    service.llm = Model()
    assert service.llm_analyze("send bitcoin to decrypt")["is_malicious"] is True
    assert service.llm_analyze("send bitcoin to decrypt")["cached"] is True
    assert service.llm_analyze("quarterly figures")["is_malicious"] is False   # its own key
    assert calls == ["send bitcoin to decrypt", "quarterly figures"]


def test_intel_caches_sandbox_reports_by_the_bytes_it_received(intel_service, tmp_path):
    service, _ = intel_service
    sample = tmp_path / "sample.docm"
    sample.write_bytes(b"inert test bytes")
    task = service.sandbox_submit(str(sample), "sample.docm")["task_id"]
    while service.sandbox_poll(task)["status"] == "pending":
        pass
    again = service.sandbox_submit(str(sample), "sample.docm")
    assert again["status"] == "cached" and again["malscore"] == 8.5
    other = tmp_path / "other.docm"
    other.write_bytes(b"different inert bytes")
    assert service.sandbox_submit(str(other), "other.docm")["status"] == "submitted"


def test_intel_without_a_cache_still_answers(tmp_path):
    pytest.importorskip("fastapi")
    from api.intel import IntelService
    service = IntelService(_intel_config(tmp_path, cache_enabled=False))
    assert service.cache is None
    vt = FakeVT()
    service._vt.http = vt
    service.vt_lookup("ab" * 32)
    service.vt_lookup("ab" * 32)
    assert len(vt.seen) == 2
