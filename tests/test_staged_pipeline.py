"""4.4.0-beta.2: slow layers run last, together, and not at all when the fast
layers already put the file at 100/100 (where they cannot change the verdict)."""

import threading

from engine.layers import Layer
from tests.helpers import make_pdf
from tests.test_file_integrity import _pe_bytes
from tests.test_scanner_integration import scanner  # noqa: F401  (fixture)


class Recorder(Layer):
    heavy = True

    def __init__(self, name, log, barrier=None):
        self.name, self.log, self.barrier = name, log, barrier

    def run(self, scanner, ctx):
        if self.barrier is not None:
            self.barrier.wait(timeout=10)       # only passes if both run at the same time
        self.log.append(self.name)
        ctx.scan_results[self.name] = {"thread": threading.current_thread().name}
        ctx.signals[self.name] = {"seen": True}


def _replace_heavy(scanner, layers):
    scanner.pipeline = [l for l in scanner.pipeline if not l.heavy] + layers


def test_saturated_files_skip_the_slow_layers(scanner, tmp_path):
    log = []
    _replace_heavy(scanner, [Recorder("slow_a", log), Recorder("slow_b", log)])
    p = tmp_path / "scan" / "invoice.pdf"
    p.write_bytes(_pe_bytes(4096))              # disguised executable + YARA: 100/100
    r = scanner.scan_file(str(p))
    assert r["risk_score"] == 100 and log == []
    assert r["scan_results"]["skipped_layers"]["layers"] == ["slow_a", "slow_b"]
    assert "[Skipped]" in scanner.generate_report([r])


def test_the_skip_can_be_turned_off(scanner, tmp_path):
    log = []
    scanner.config["skip_heavy_when_saturated"] = False
    _replace_heavy(scanner, [Recorder("slow_a", log)])
    p = tmp_path / "scan" / "invoice.pdf"
    p.write_bytes(_pe_bytes(4096))
    r = scanner.scan_file(str(p))
    assert log == ["slow_a"] and "skipped_layers" not in r["scan_results"]


def test_slow_layers_run_concurrently_and_merge_in_order(scanner, tmp_path):
    log = []
    barrier = threading.Barrier(2)
    _replace_heavy(scanner, [Recorder("slow_a", log, barrier), Recorder("slow_b", log, barrier)])
    p = tmp_path / "scan" / "letter.pdf"
    p.write_bytes(make_pdf("hello"))
    r = scanner.scan_file(str(p))
    assert sorted(log) == ["slow_a", "slow_b"]
    keys = list(r["scan_results"])
    assert keys[-2:] == ["slow_a", "slow_b"]                  # pipeline order, not finish order
    assert r["scan_results"]["slow_a"]["thread"].startswith("heavy-layer")


def test_sequential_mode_keeps_one_thread(scanner, tmp_path):
    log = []
    scanner.config["parallel_heavy_layers"] = False
    _replace_heavy(scanner, [Recorder("slow_a", log), Recorder("slow_b", log)])
    p = tmp_path / "scan" / "letter.pdf"
    p.write_bytes(make_pdf("hello"))
    r = scanner.scan_file(str(p))
    assert log == ["slow_a", "slow_b"]
    assert r["scan_results"]["slow_a"]["thread"] == threading.current_thread().name


def test_real_slow_layers_still_score(scanner, tmp_path):
    import os

    from tests.test_ml_classifier import SCN_WX, make_pe
    p = tmp_path / "scan" / "setup.exe"
    p.write_bytes(make_pe([("UPX0", b"\0" * 512, SCN_WX), ("UPX1", os.urandom(20_000), SCN_WX)],
                          imports=("KERNEL32.dll",)))
    r = scanner.scan_file(str(p))
    keys = list(r["scan_results"])
    assert keys.index("ml_classifier") < keys.index("chatgpt_analysis") < keys.index("virustotal")
    assert r["scan_results"]["ml_classifier"]["label"] == "suspicious"
    # The PE layer scored the packing first; the ML opinion on it is not added twice.
    assert {c["indicator"] for c in r["score_breakdown"]["contributions"]} == {"pe_packed"}
