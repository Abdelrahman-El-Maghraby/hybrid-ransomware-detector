import threading
import time

from core.cache import ResultCache

SHA = "a" * 64


def test_roundtrip_and_layer_separation(tmp_path):
    c = ResultCache(tmp_path / "c.sqlite3")
    assert c.enabled
    c.put(SHA, "virustotal", {"malicious_detections": 3})
    c.put(SHA, "llm:ollama:llama3.1", {"confidence": 0.2})
    assert c.get(SHA, "virustotal") == {"malicious_detections": 3}
    assert c.get(SHA, "llm:ollama:llama3.1") == {"confidence": 0.2}
    assert c.get(SHA, "llm:openai:gpt-4") is None
    assert c.get(SHA.upper(), "virustotal") is not None      # case-insensitive key
    assert c.stats()["entries"] == 2


def test_expiry(tmp_path, monkeypatch):
    c = ResultCache(tmp_path / "c.sqlite3", default_ttl_seconds=10)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    c.put(SHA, "virustotal", {"x": 1})
    monkeypatch.setattr(time, "time", lambda: now + 11)
    assert c.get(SHA, "virustotal") is None
    assert c.purge_expired() == 1


def test_zero_ttl_means_not_cached(tmp_path):
    c = ResultCache(tmp_path / "c.sqlite3")
    c.put(SHA, "virustotal", {"x": 1}, ttl_seconds=0)
    assert c.get(SHA, "virustotal") is None


def test_persistence_and_clear(tmp_path):
    path = tmp_path / "c.sqlite3"
    ResultCache(path).put(SHA, "virustotal", {"x": 1})
    again = ResultCache(path)
    assert again.get(SHA, "virustotal") == {"x": 1}
    assert again.clear() == 1 and again.get(SHA, "virustotal") is None


def test_unopenable_database_disables_cache_quietly(tmp_path):
    bad = tmp_path / "is_a_directory"
    bad.mkdir()
    c = ResultCache(bad)
    assert c.enabled is False
    c.put(SHA, "virustotal", {"x": 1})            # no exception
    assert c.get(SHA, "virustotal") is None


def test_concurrent_writers(tmp_path):
    c = ResultCache(tmp_path / "c.sqlite3")

    def work(n):
        for i in range(50):
            c.put(f"{n:02d}{i:062d}", "layer", {"n": n, "i": i})

    threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert c.stats()["entries"] == 200
