"""The scikit-learn version check on model files (recorded as a suspicion).
scikit-learn writes its version into every estimator it pickles and warns
(InconsistentVersionWarning) when another version loads it; the predictions of
such a model are not guaranteed. The classifier now refuses it, so the scan
uses the rule engine and says why. Models are trained here on tiny synthetic
feature rows; no file is scanned by them."""

import pytest

from detectors.ml_classifier import FEATURE_NAMES, MODEL_FORMAT, SKLEARN_AVAILABLE, MLClassifier

needs_sklearn = pytest.mark.skipif(not SKLEARN_AVAILABLE, reason="scikit-learn not installed")


def _save(path, monkeypatch=None, version=None):
    import joblib
    import sklearn.base
    from sklearn.ensemble import RandomForestClassifier
    rows = [[float(i % 3)] * len(FEATURE_NAMES) for i in range(10)]
    model = RandomForestClassifier(n_estimators=2, random_state=0).fit(rows, [i % 2 for i in range(10)])
    if version:
        monkeypatch.setattr(sklearn.base, "__version__", version)   # what an older install wrote
    joblib.dump({"format": MODEL_FORMAT, "feature_names": FEATURE_NAMES, "model": model}, path)
    if version:
        monkeypatch.undo()
    path.chmod(0o600)
    return path


@needs_sklearn
def test_a_model_from_another_scikit_learn_version_is_not_used(tmp_path, monkeypatch):
    clf = MLClassifier(_save(tmp_path / "old.joblib", monkeypatch, "0.24.2"))
    assert not clf.has_model
    assert "scikit-learn 0.24.2" in clf.load_error and "retrain" in clf.load_error


@needs_sklearn
def test_a_model_from_this_version_loads(tmp_path):
    clf = MLClassifier(_save(tmp_path / "current.joblib"))
    assert clf.has_model and clf.load_error == ""
