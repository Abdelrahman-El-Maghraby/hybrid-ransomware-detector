"""tools/calibrate_weights.py: weights proposed from labelled indicator data."""

import json
import random

from tools.calibrate_weights import base_indicator, calibrate, fit_logistic, main, to_points


def synthetic_rows(n=300, seed=1):
    """'strong' fires on most malicious files and no benign ones; 'noisy' fires on
    both classes equally; 'weak' leans malicious. Current weights are all 30."""
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        mal = i % 2 == 0
        ind = {}
        if mal and rng.random() < 0.8:
            ind["strong"] = 30.0
        if rng.random() < 0.3:
            ind["noisy"] = 30.0
        if rng.random() < (0.5 if mal else 0.1):
            ind["weak"] = 30.0
        if i < 3:
            ind["rare"] = 30.0
        rows.append({"label": "malicious" if mal else "benign", "indicators": ind,
                     "risk": min(100, int(sum(ind.values())))})
    return rows


def test_base_indicator():
    assert base_indicator("mail_attachment:archive_member:yara_match") == "yara_match"
    assert base_indicator("encrypted_content") == "encrypted_content"


def test_logistic_regression_separates_a_clean_signal():
    X = [[1.0], [1.0], [0.0], [0.0]] * 20
    y = [1, 1, 0, 0] * 20
    b, w = fit_logistic(X, y)
    assert w[0] > 1 and b < 0
    assert to_points(b, w)[0] > 50                       # alone it reaches High


def test_calibration_ranks_indicators_by_evidence():
    res = calibrate(synthetic_rows(), min_support=10)
    by = {t["indicator"]: t for t in res["indicators"]}
    assert by["strong"]["proposed"] > by["weak"]["proposed"] > by["noisy"]["proposed"]
    assert by["noisy"]["proposed"] < 10                   # no evidence -> near zero
    assert by["rare"]["kept_current"] and by["rare"]["proposed"] == by["rare"]["current"]
    cv = res["proposed_cross_validated"]
    assert cv and cv["detection"] > 0.6 and cv["false_alarm"] < 0.15
    assert cv["detection"] > res["current"]["detection"]   # equal weights miss "strong" alone


def test_cli_with_saved_features(tmp_path):
    feats = tmp_path / "features.jsonl"
    feats.write_text("\n".join(json.dumps(r) for r in synthetic_rows(120)))
    out = tmp_path / "out"
    assert main(["--features-in", str(feats), "--out", str(out)]) == 0
    assert "| strong |" in (out / "summary.md").read_text()
    assert json.loads((out / "weights.json").read_text())["files"] == 120
    assert (out / "weights.override.yaml").read_text().startswith("# Proposed")


def test_override_file_loads_into_the_scoring_matrix(tmp_path):
    from detectors.registry import load_overrides
    from detectors.scoring import ScoringMatrix
    from tools.calibrate_weights import override_yaml
    res = {"files": 50, "indicators": [
        {"indicator": "disguised_executable", "proposed": 77.0, "current": 90.0,
         "kept_current": False, "malicious": 30, "benign": 0},
        {"indicator": "yara_match", "proposed": 20.0, "current": 65.0,      # dict weight: skipped
         "kept_current": False, "malicious": 30, "benign": 5}]}
    p = tmp_path / "o.yaml"
    p.write_text(override_yaml(res))
    assert load_overrides(p) == {"W_DISGUISED_EXECUTABLE": 77.0}
    assert ScoringMatrix(load_overrides(p)).score(
        {"integrity": {"disguised_executable": "pe"}}).risk_score == 77


def test_cli_scans_labelled_folders(tmp_path):
    from tests.helpers import make_pdf
    from tests.test_file_integrity import _pe_bytes
    mal, ben, out = tmp_path / "mal", tmp_path / "ben", tmp_path / "out"
    mal.mkdir(), ben.mkdir()
    for i in range(3):
        (mal / f"invoice{i}.pdf").write_bytes(_pe_bytes(4096))      # executable posing as a PDF
        (ben / f"letter{i}.pdf").write_bytes(make_pdf(f"Meeting notes {i}"))
    assert main(["--malicious", str(mal), "--benign", str(ben), "--out", str(out)]) == 0
    rows = [json.loads(l) for l in (out / "features.jsonl").read_text().splitlines()]
    assert len(rows) == 6
    assert all("disguised_executable" in r["indicators"] for r in rows if r["label"] == "malicious")


def test_a_file_that_fails_in_its_worker_gives_an_error_row(tmp_path, monkeypatch):
    """L-C9: calibration called scan_file in its own process, with no time or
    memory limit, so one hanging file stopped the run. It now scans through the
    product's isolated worker (scan_one) and records a failed scan as an error."""
    from types import SimpleNamespace

    from tools import calibrate_weights as CW
    calls = []

    def scan_one(path):
        calls.append(path)
        if path.endswith("hang.pdf"):
            return {"scan_status": "failed", "verdict": "Medium", "risk_score": 25,
                    "scan_results": {"scan_failed": {"reason": "timed out after 300s"}}}
        return {"scan_status": "complete", "risk_score": 0, "sha256_hash": "s",
                "score_breakdown": {"contributions": []}}

    def no_inline(path):
        raise AssertionError("scanned in the calibration process")

    stand_in = SimpleNamespace(file_extensions=[".pdf"], scan_one=scan_one, scan_file=no_inline)
    monkeypatch.setattr(CW, "_scanner", lambda: stand_in)
    mal = tmp_path / "mal"
    mal.mkdir()
    (mal / "hang.pdf").write_bytes(b"%PDF-1.4")
    (mal / "ok.pdf").write_bytes(b"%PDF-1.4")
    rows = CW.scan_folders([mal], [])
    assert len(calls) == 2
    errors = [r for r in rows if "error" in r]
    assert len(errors) == 1 and "timed out" in errors[0]["error"]


def test_proposed_scores_use_the_engines_caps_and_clamp():
    """L-C10: proposals were scored as a plain sum (at most 100), without the
    category caps (semantic 24, statistical 20) and the clamp at 49 the engine
    applies, so "current" and "proposed" rates were measured differently."""
    from tools.calibrate_weights import score_rows
    semantic_only = {"label": "malicious", "indicators": {"llm_semantic": 90.0,
                                                           "mail_lure_subject": 90.0}}
    with_technical = {"label": "malicious", "indicators": {"llm_semantic": 90.0,
                                                            "disguised_executable": 40.0}}
    s_only, s_tech = score_rows([semantic_only, with_technical], {})
    assert s_only <= 24 and s_tech == 40 + 24


def test_duplicate_files_count_once_and_conflicts_are_left_out():
    """L-C10: calibration did not dedupe (evaluate.py did), so a file present twice
    counted twice and one labelled both ways stayed in."""
    rows = []
    for i in range(12):
        rows.append({"label": "malicious", "sha256": f"m{i}", "risk": 80,
                     "indicators": {"disguised_executable": 80.0}})
        rows.append({"label": "benign", "sha256": f"b{i}", "risk": 0, "indicators": {}})
    rows += [dict(rows[0]), {"label": "benign", "sha256": "m1", "risk": 0, "indicators": {}}]
    res = calibrate(rows, min_support=1)
    assert res["current"]["malicious"] == 11 and res["current"]["benign"] == 12
    assert res["duplicates"] == 1 and res["conflicts"] == 1
