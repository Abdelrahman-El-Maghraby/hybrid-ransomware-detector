"""L-G1: the GUI decided "LLM skipped" by searching the model's free-text
explanation for markers such as "layer skipped". A flagged answer whose text
contained one was shown as "Skipped - no LLM backend available" and its result
token was hidden. An answer the model gave (analyzed, or flagged) is never
"skipped" now; the markers remain for results saved before `analyzed` existed."""

import pytest

from detectors.llm_backends import NullBackend, _empty_analysis

formatting = pytest.importorskip("aegis_gui.formatting")


def test_a_flagged_answer_quoting_a_marker_is_not_shown_as_skipped():
    ai = {"is_malicious": True, "confidence": 0.95, "analyzed": True,
          "details": "The macro says the security layer skipped checks: not configured."}
    assert formatting.llm_skipped(ai) is False


@pytest.mark.parametrize("ai", [
    NullBackend().analyze("x"),
    _empty_analysis("OpenAI API key not configured; LLM layer skipped."),
    {"details": "No LLM backend configured; semantic layer skipped."},   # before `analyzed`
])
def test_a_layer_that_did_not_run_is_still_skipped(ai):
    assert formatting.llm_skipped(ai) is True
