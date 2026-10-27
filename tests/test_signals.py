"""detectors/signals.py: the typed contract between layers and the scorer."""

import pytest

from detectors.scoring import SCORERS, ScoringMatrix
from detectors.signals import ArchiveSignal, MailSignal, PeSignal, Signals, WorstMember, as_signals


def test_dict_and_typed_signals_score_the_same():
    d = {"local_db_hit": True, "pe": {"packed": True, "packer": "UPX"},
         "mail": {"auth_failures": ["DMARC"], "from_domain": "x.test",
                  "worst_attachment": {"name": "a.exe",
                                       "contributions": [{"indicator": "yara_match",
                                                          "category": "technical",
                                                          "points": 40, "detail": "r"}]}}}
    typed = Signals(local_db_hit=True, pe=PeSignal(packed=True, packer="UPX"),
                    mail=MailSignal(auth_failures=["DMARC"], from_domain="x.test",
                                    worst=WorstMember("a.exe", d["mail"]["worst_attachment"]
                                                      ["contributions"])))
    a, b = ScoringMatrix().score(d), ScoringMatrix().score(typed)
    assert a.as_dict() == b.as_dict()
    assert "mail_attachment:yara_match" in [c.indicator for c in a.contributions]


def test_a_misspelt_field_fails_loudly():
    with pytest.raises(TypeError):
        Signals.from_dict({"pe": {"packd": True}})


def test_empty_and_none_layers_mean_no_evidence():
    s = Signals.from_dict({"archive": {}, "mail": None, "ml": {}})
    assert s.archive is None and s.mail is None and s.ml is None
    assert ScoringMatrix().score(s).risk_score == 0
    assert as_signals(None) == Signals() and as_signals(s) is s


def test_unknown_layers_go_to_extra_and_mapping_access():
    s = Signals.from_dict({"my_layer": {"x": 1}, "allowlisted": "ok"})
    assert s.extra == {"my_layer": {"x": 1}} and s["my_layer"] == {"x": 1}
    s["other"] = 2
    s["pe"] = PeSignal(packed=True)
    assert s.get("other") == 2 and s.get("missing", 5) == 5 and s.get("ml", 7) == 7
    assert s["pe"].packed and s["allowlisted"] == "ok"


def test_changed_since_reports_only_new_values():
    before = Signals(archive=ArchiveSignal(zip_slip=True), extra={"k": 1})
    after = before.copy()
    assert after.changed_since(before) == {}
    after.pe = PeSignal()
    after.extra["n"] = 2
    assert set(after.changed_since(before)) == {"pe", "n"}
    assert before.extra == {"k": 1}                    # copy() does not share `extra`


def test_every_layer_has_a_scorer_in_report_order():
    names = [f.__name__ for f in SCORERS]
    assert names[:4] == ["_local_db", "_yara", "_fuzzy", "_macro"]
    assert names[-1] == "_llm" and len(names) == len(set(names))
