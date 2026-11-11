"""L-C6: the report's "LLM posture" line and the dashboard's LLM card decided by
class name (Ollama, OpenAI). With AEGIS_INTEL_SOCKET the backend is
IntelLLMBackend, so both said "disabled" even when the intel service sends the
text to a cloud LLM. They now use the backend's own `available` and `is_local`."""

from types import SimpleNamespace

import pytest

from core.intel_client import IntelLLMBackend
from detectors.llm_backends import NullBackend, OllamaBackend, OpenAIBackend
from engine.report import ReportMixin


class StandInIntel:
    def __init__(self, llm):
        self.llm = llm

    def service(self, name):
        return dict(self.llm) if name == "llm" else {"enabled": False}


def _intel(**llm):
    return IntelLLMBackend(StandInIntel(llm))


def _posture(backend):
    return ReportMixin._llm_posture_label(SimpleNamespace(llm_backend=backend))


def _card(backend):
    pytest.importorskip("tkinter")                     # the card test needs the GUI import
    from aegis_gui.pages.dashboard import DashboardPage
    return DashboardPage._llm_card_state(SimpleNamespace(llm_backend=backend, config={}))


CASES = [
    (_intel(enabled=True, name="openai", model="gpt-4o", is_local=False),
     "CLOUD (gpt-4o - documents leave the machine)", ("gpt-4o", "Cloud", True)),
    (_intel(enabled=True, name="ollama", model="llama3.1", is_local=True),
     "LOCAL (llama3.1)", ("llama3.1", "Local · OPSEC", True)),
    (_intel(enabled=False), "disabled", ("—", "Disabled", False)),
    (_intel(unreachable=True, enabled=False), "disabled", ("—", "Disabled", False)),
    (OllamaBackend(model="llama3.1"), "LOCAL (llama3.1)", ("llama3.1", "Local · OPSEC", True)),
    (OpenAIBackend("k", "https://api.example/v1", model="gpt-4"),
     "CLOUD (gpt-4 - documents leave the machine)", ("gpt-4", "Cloud", True)),
    (NullBackend(), "disabled", ("—", "Disabled", False)),
]


@pytest.mark.parametrize("backend, report, card", CASES)
def test_report_follows_the_backend_not_its_class(backend, report, card):
    assert _posture(backend) == report


@pytest.mark.parametrize("backend, report, card", CASES)
def test_dashboard_card_follows_the_backend_not_its_class(backend, report, card):
    assert _card(backend) == card


def test_no_backend():
    assert _posture(None) == "none"
    assert _card(None) == ("—", "Disabled", False)


def _layers(**over):
    me = SimpleNamespace(**{"llm_backend": NullBackend(), "intel": None,
                            "config": {"virustotal_api_key": ""}, **over})
    return ReportMixin._active_layers_label(me).split(", ")


def test_layers_used_names_llm_and_virustotal_only_when_they_run():
    """L-C3 (check 14): with no LLM and no VirusTotal key the report still listed
    "llm, virustotal" as layers used."""
    assert "llm" not in _layers() and "virustotal" not in _layers()
    on = _layers(llm_backend=OllamaBackend(), config={"virustotal_api_key": "k"})
    assert "llm" in on and "virustotal" in on
    via_intel = _layers(llm_backend=_intel(enabled=True, name="openai", is_local=False),
                        intel=SimpleNamespace(service=lambda n: {"enabled": n == "virustotal"}))
    assert "llm" in via_intel and "virustotal" in via_intel
