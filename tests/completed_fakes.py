"""Bounded inert service stand-ins for completed-finding retention tests."""
import time

from core.sandbox import SandboxResult
from tests.worker_fakes import SandboxProbeScanner


class Backend:
    available, is_local, name, model = True, True, "stand-in", "test"


class Box:
    url, options, poll_seconds = "http://stand-in.invalid", "", 0.01

    def analyze(self, path, deadline=None, progress=None):
        if progress:
            progress("possible")
        time.sleep(30)
        return SandboxResult(enabled=True, status="timeout")


class CompletedScanner(SandboxProbeScanner):
    def __init__(self, config):
        super().__init__(config)
        self.llm_backend = Backend()
        if config.get("_stall") == "sandbox":
            self.sandbox = Box()

    def _answer(self, layer):
        if self.config.get("_stall") == layer:
            self.external_listener(layer, ["sha256"] if layer == "virustotal" else ["text"],
                                   None if layer == "virustotal" else "local")
            time.sleep(30)
        time.sleep(self.config.get("_delays", {}).get(layer, 0))

    def scan_file_with_virustotal(self, path, hashes=None):
        self._answer("virustotal")
        return {"malicious_detections": 8, "suspicious_detections": 0, "total_engines": 10,
                "detection_ratio": 0.8, "sent": ["sha256"], "status": "reported"}

    def analyze_with_llm(self, path, text, strings, sha256=None, complete=True):
        self._answer("llm")
        return {"is_malicious": True, "confidence": 1.0, "suspicious_elements": ["inert finding"],
                "analyzed": True, "sent": ["text"], "destination": "local"}


def make(config):
    return CompletedScanner(config)


def make_vt_first(config):
    scanner = CompletedScanner(config)
    layers = scanner.pipeline
    llm = next(i for i, layer in enumerate(layers) if layer.name == "llm")
    vt = next(i for i, layer in enumerate(layers) if layer.name == "virustotal")
    layers[llm], layers[vt] = layers[vt], layers[llm]
    return scanner


def make_escaped(config):
    from tests.test_escaped_helpers import EscapedScanner
    return EscapedScanner(config)
