"""Keep the policy experiment bounded and the product's 15-second gate intact."""
from tests.sandbox_budget_experiment import experiment


def test_synthetic_budget_matrix():
    rows = experiment()
    assert len(rows) == 144
    assert all(row["elapsed"] <= row["budget"] for row in rows)
    denied = [r for r in rows if r["gate"] and r["budget"] < 15]
    assert len(denied) == 36 and all(r["status"] == "not_submitted" for r in denied)
    assert any(r["status"] == "reported" for r in rows if not r["gate"] and r["budget"] < 15)
    assert any(r["submitted"] and r["status"] == "timeout" for r in rows if r["gate"])
