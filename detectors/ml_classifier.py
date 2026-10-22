"""
Lightweight static ML classifier: 15 explainable byte/PE features, a
RandomForest when a trained model is available, a transparent rule engine
when it isn't.

WHERE IT FITS
-------------
The other layers look for *specific* evidence (a YARA rule, a macro
primitive, a known hash). This layer asks a broader statistical question:
"does this file's byte-level shape look like the packed / encrypted payloads
ransomware ships with?" That catches things no signature names yet, at the
cost of being a weaker signal - so the scoring matrix gives it its own small
"statistical" budget (max 20 points) and, like the LLM layer, it can never
push a file past *Medium* on its own.

FEATURES (all computed from the first 8 MiB, pure standard library)
-------------------------------------------------------------------
  entropy_full              Shannon entropy of the sample (0-8 bits/byte)
  high_entropy_window_ratio share of 1 KiB windows with entropy > 7.5
  entropy_head / _tail      entropy of the first / last 4 KiB
  is_pe                     valid MZ + PE header
  pe_section_count          number of PE sections
  pe_max_section_entropy    entropy of the most random section
  pe_import_dll_count       DLLs in the import directory (packers hide imports)
  pe_suspicious_sections    packer section names (UPX, VMProtect, Themida, ...)
  pe_wx_sections            sections that are both writable and executable
  log2_size                 log2(file size)
  null_ratio                share of 0x00 bytes
  printable_ratio           share of printable ASCII bytes
  known_compressed_format   ZIP/OOXML, gzip, 7z, RAR, PNG, JPEG, GIF, MP4 ...
                            and encrypted vaults whose header AND extension
                            agree: KeePass .kdbx, OpenPGP .gpg/.pgp, age .age
                            (high entropy is *expected* there)
  ext_risk                  0 none, 1 other, 2 document/container, 3 executable

TRAINING
--------
No model ships with the project: a model trained on synthetic data would
claim accuracy it doesn't have. Train on your own labelled corpus:

    python RansomwareScanner.py --train-ml BENIGN_DIR MALICIOUS_DIR

(MalwareBazaar / theZoo for the malicious side, a clean document & software
folder for the benign side.) Training needs scikit-learn + joblib
(``pip install -r requirements-ml.txt``); inference with the rule engine
needs nothing beyond the standard library.

SECURITY NOTE: model files are joblib (pickle) archives - loading one runs
code. Only load models you trained yourself; the scanner only looks at the
path in ``ML_MODEL_PATH`` (default: the app data directory).
"""

from __future__ import annotations

import logging
import math
import os
import struct
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .entropy import shannon_entropy
from .file_integrity import trusted_vault

logger = logging.getLogger("RansomwareScanner.ml")

try:
    import joblib as _joblib  # type: ignore
    import numpy as _np  # type: ignore
    from sklearn.ensemble import RandomForestClassifier as _RandomForest  # type: ignore
    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    _joblib = _np = _RandomForest = None
    SKLEARN_AVAILABLE = False

PathLike = Union[str, Path]

MODEL_FORMAT = "hrd-ml-1"
SAMPLE_BYTES = 8 * 1024 * 1024
WINDOW = 1024
MAX_WINDOWS = 2048
HIGH_WINDOW_ENTROPY = 7.5
SUSPICIOUS_THRESHOLD = 0.5          # model probability / rule score that flags a file

FEATURE_NAMES: List[str] = [
    "entropy_full", "high_entropy_window_ratio", "entropy_head", "entropy_tail",
    "is_pe", "pe_section_count", "pe_max_section_entropy", "pe_import_dll_count",
    "pe_suspicious_sections", "pe_wx_sections",
    "log2_size", "null_ratio", "printable_ratio", "known_compressed_format", "ext_risk",
]

_EXECUTABLE_EXT = frozenset({
    ".exe", ".dll", ".scr", ".com", ".pif", ".sys", ".cpl", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".jar", ".msi", ".lnk", ".elf", ".so",
    ".dylib", ".bin",
})
_DOCUMENT_EXT = frozenset({
    ".pdf", ".doc", ".docx", ".docm", ".dotm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx",
    ".pptm", ".rtf", ".zip", ".iso", ".img", ".eml", ".msg", ".one",
})
_PACKER_SECTIONS = frozenset({
    "upx0", "upx1", "upx2", ".upx", ".vmp0", ".vmp1", ".vmp2", ".themida", ".winlice",
    ".aspack", ".adata", ".nsp0", ".nsp1", ".nsp2", ".mpress1", ".mpress2", ".petite",
    ".packed", ".enigma1", ".enigma2", "pec2", ".pelock", ".yp", ".perplex",
})
_COMPRESSED_MAGIC: Tuple[Tuple[int, bytes], ...] = (
    (0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"\x1f\x8b"), (0, b"7z\xbc\xaf\x27\x1c"),
    (0, b"Rar!\x1a\x07"), (0, b"\x89PNG\r\n\x1a\n"), (0, b"\xff\xd8\xff"), (0, b"GIF8"),
    (0, b"BZh"), (0, b"\xfd7zXZ\x00"), (0, b"\x28\xb5\x2f\xfd"), (4, b"ftyp"),
    (0, b"OggS"), (0, b"fLaC"), (0, b"ID3"), (0, b"RIFF"), (0, b"MSCF"),
)
_SCN_EXEC = 0x20000000


def _known_compressed(data: bytes, ext: str) -> bool:
    """A format whose body is compressed by design, so high entropy is expected.
    A PDF counts only while its object structure is intact (an encryptor that keeps
    the header destroys the 'endobj' markers): Flate streams made 18% of benign
    PDFs look 'random throughout' (4.4.0 benchmark)."""
    if any(data[o:o + len(m)] == m for o, m in _COMPRESSED_MAGIC):
        return True
    if data.startswith(b"%PDF-") and data.count(b"endobj") >= 3:
        return True
    return bool(trusted_vault(data[:64], ext))
_SCN_WRITE = 0x80000000


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class MLResult:
    available: bool = True
    label: str = "unknown"          # benign | suspicious | unknown
    probability: float = 0.0        # P(suspicious), 0-1
    model: str = "rules"            # "rules" or the model file name
    features: Dict[str, float] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    error: str = ""

    @property
    def suspicious(self) -> bool:
        return self.label == "suspicious"

    def as_dict(self) -> Dict:
        return {"available": self.available, "label": self.label,
                "probability": round(self.probability, 4), "model": self.model,
                "features": {k: round(v, 4) for k, v in self.features.items()},
                "indicators": self.indicators, "error": self.error}


# ---------------------------------------------------------------------------
# Feature extraction (standard library only)
# ---------------------------------------------------------------------------

_TEXT_BYTES = bytes([9, 10, 13, *range(32, 127)])   # printable ASCII + tab/LF/CR


def _window_ratio(data: bytes) -> float:
    total = len(data) // WINDOW
    if total == 0:
        return 0.0
    step = max(1, total // MAX_WINDOWS)
    hits = checked = 0
    for i in range(0, total, step):
        checked += 1
        if shannon_entropy(data[i * WINDOW:(i + 1) * WINDOW]) > HIGH_WINDOW_ENTROPY:
            hits += 1
    return hits / checked


def pe_features(data: bytes) -> Dict[str, float]:
    """Section/import statistics for PE files; all zeros for anything else."""
    out = {"is_pe": 0.0, "pe_section_count": 0.0, "pe_max_section_entropy": 0.0,
           "pe_import_dll_count": 0.0, "pe_suspicious_sections": 0.0, "pe_wx_sections": 0.0}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return out
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\x00\x00":
            return out
        n_sections = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        pe32_plus = magic == 0x20B
        out["is_pe"] = 1.0
        out["pe_section_count"] = float(n_sections)

        # Data directory 1 = import table (RVA, size).
        dd_offset = opt + (112 if pe32_plus else 96)
        import_rva = 0
        if opt_size >= (dd_offset - opt) + 16:
            import_rva = struct.unpack_from("<I", data, dd_offset + 8)[0]

        sections = []
        table = opt + opt_size
        for i in range(min(n_sections, 96)):
            off = table + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off + 8].rstrip(b"\x00").decode("latin-1").lower()
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            sections.append((vaddr, max(vsize, raw_size), raw_ptr))
            if raw_size and raw_ptr < len(data):
                out["pe_max_section_entropy"] = max(
                    out["pe_max_section_entropy"],
                    shannon_entropy(data[raw_ptr:raw_ptr + min(raw_size, SAMPLE_BYTES)]))
            if name in _PACKER_SECTIONS:
                out["pe_suspicious_sections"] += 1
            if chars & _SCN_EXEC and chars & _SCN_WRITE:
                out["pe_wx_sections"] += 1

        if import_rva:
            for vaddr, span, raw_ptr in sections:
                if vaddr <= import_rva < vaddr + span:
                    idt = import_rva - vaddr + raw_ptr
                    count = 0
                    while idt + 20 <= len(data) and count < 512:
                        desc = struct.unpack_from("<IIIII", data, idt)
                        if not any(desc):
                            break
                        count += 1
                        idt += 20
                    out["pe_import_dll_count"] = float(count)
                    break
    except struct.error:
        pass
    return out


def extract_features(file_path: PathLike) -> Dict[str, float]:
    """Return the 15 named features for a file (reads at most 8 MiB)."""
    path = Path(file_path)
    size = path.stat().st_size
    with open(path, "rb") as fh:
        data = fh.read(SAMPLE_BYTES)
    n = max(len(data), 1)
    ext = path.suffix.lower()
    feats = {
        "entropy_full": shannon_entropy(data),
        "high_entropy_window_ratio": _window_ratio(data),
        "entropy_head": shannon_entropy(data[:4096]),
        "entropy_tail": shannon_entropy(data[-4096:]),
    }
    feats.update(pe_features(data))
    feats.update({
        "log2_size": math.log2(size + 1),
        "null_ratio": data.count(0) / n,
        "printable_ratio": (len(data) - len(data.translate(None, _TEXT_BYTES))) / n,
        "known_compressed_format": float(_known_compressed(data, ext)),
        "ext_risk": (3.0 if ext in _EXECUTABLE_EXT else 2.0 if ext in _DOCUMENT_EXT
                     else 1.0 if ext else 0.0),
    })
    return {k: float(feats[k]) for k in FEATURE_NAMES}


def feature_vector(features: Dict[str, float]) -> List[float]:
    return [float(features[k]) for k in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Rule engine (used when no trained model is loaded)
# ---------------------------------------------------------------------------

def rule_score(f: Dict[str, float]) -> Tuple[float, List[str]]:
    """Transparent fallback: returns (score 0-1, reasons)."""
    score, why = 0.0, []
    if not f["known_compressed_format"]:
        if f["entropy_full"] > 7.5 and f["high_entropy_window_ratio"] > 0.8:
            # Random from end to end and not a known compressed or encrypted
            # container (KeePass, OpenPGP and age headers are recognised
            # above): encrypted data. Header-less volumes such as VeraCrypt
            # still match, which is one reason this layer is capped low.
            score += 0.55
            why.append(f"content is statistically random throughout "
                       f"(entropy {f['entropy_full']:.2f}, "
                       f"{f['high_entropy_window_ratio']:.0%} of windows) - "
                       "typical of encrypted or packed data")
        elif f["entropy_full"] > 7.0:
            score += 0.15
            why.append(f"high overall entropy ({f['entropy_full']:.2f})")
    if f["is_pe"]:
        if f["pe_suspicious_sections"]:
            score += 0.30
            why.append(f"{int(f['pe_suspicious_sections'])} packer section name(s)")
        if f["pe_wx_sections"]:
            score += 0.20
            why.append(f"{int(f['pe_wx_sections'])} writable+executable section(s) "
                       "(self-modifying / unpacking stub)")
        if f["pe_max_section_entropy"] > 7.2:
            score += 0.20
            why.append(f"a PE section has entropy {f['pe_max_section_entropy']:.2f} "
                       "(compressed or encrypted code)")
        if f["pe_import_dll_count"] <= 1:
            score += 0.15
            why.append("almost no imported DLLs (imports resolved at run time)")
    if why and f["ext_risk"] >= 3:
        score += 0.05
    return min(score, 1.0), why


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def _check_model_file(path: Path) -> None:
    """Loading a joblib model runs code, so on POSIX refuse a model file that
    another user owns or that the group / others may write: anyone who could
    change it could run code in every scan."""
    if os.name != "posix":
        return
    st = path.stat()
    if st.st_mode & 0o022:
        raise PermissionError(f"refusing to load {path.name}: writable by group/others "
                              f"(chmod go-w {path})")
    if hasattr(os, "getuid") and st.st_uid not in (os.getuid(), 0):
        raise PermissionError(f"refusing to load {path.name}: owned by another user")


class MLClassifier:
    """`classify()` never raises; it uses a trained model if one is loaded."""

    def __init__(self, model_path: Optional[PathLike] = None):
        self.model = None
        self.model_name = "rules"
        self.model_info: Dict = {}
        self.load_error = ""
        if model_path and Path(model_path).is_file():
            try:
                self.load(model_path)
            except Exception as exc:
                self.load_error = f"{type(exc).__name__}: {exc}"
                logger.warning("ML model %s not loaded (%s); using rule engine.",
                               model_path, self.load_error)

    @property
    def has_model(self) -> bool:
        return self.model is not None

    def classify(self, file_path: PathLike) -> MLResult:
        try:
            feats = extract_features(file_path)
        except OSError as exc:
            return MLResult(available=False, error=str(exc))
        res = MLResult(features=feats, model=self.model_name)
        _, reasons = rule_score(feats)
        if self.model is not None:
            try:
                proba = self.model.predict_proba(_np.array([feature_vector(feats)]))[0]
                classes = list(self.model.classes_)
                res.probability = float(proba[classes.index(1)]) if 1 in classes else 0.0
                res.indicators = self._model_reasons(feats) + reasons[:2]
            except Exception as exc:
                res.error = f"model inference failed ({exc}); used rule engine"
                res.model = "rules"
                res.probability, res.indicators = rule_score(feats)
        else:
            res.probability, res.indicators = rule_score(feats)
        res.label = "suspicious" if res.probability >= SUSPICIOUS_THRESHOLD else "benign"
        return res

    # ------------------------------------------------------------ persistence
    def load(self, model_path: PathLike) -> None:
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn/joblib not installed "
                              "(pip install -r requirements-ml.txt)")
        _check_model_file(Path(model_path))
        bundle = _joblib.load(model_path)
        if not isinstance(bundle, dict) or bundle.get("format") != MODEL_FORMAT:
            raise ValueError("not a hybrid-ransomware-detector model file")
        if list(bundle.get("feature_names", [])) != FEATURE_NAMES:
            raise ValueError("model was trained on a different feature set; retrain it")
        self.model = bundle["model"]
        self.model_info = {k: v for k, v in bundle.items() if k != "model"}
        self.model_name = Path(model_path).name

    def save(self, model_path: PathLike) -> None:
        if self.model is None:
            raise ValueError("no trained model to save")
        path = Path(model_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        _joblib.dump({"format": MODEL_FORMAT, "feature_names": FEATURE_NAMES,
                      "model": self.model, **self.model_info}, path)
        if os.name == "posix":
            path.chmod(0o600)                   # see _check_model_file
        self.model_name = path.name

    # ---------------------------------------------------------------- training
    def train(self, benign: Iterable[PathLike], malicious: Iterable[PathLike],
              test_size: float = 0.25, seed: int = 42) -> Dict:
        """Fit a RandomForest on labelled files; returns held-out metrics."""
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn/joblib not installed "
                              "(pip install -r requirements-ml.txt)")
        from sklearn.metrics import confusion_matrix, precision_score, recall_score
        from sklearn.model_selection import train_test_split

        X, y, skipped = [], [], 0
        for label, paths in ((0, benign), (1, malicious)):
            for p in paths:
                try:
                    X.append(feature_vector(extract_features(p)))
                    y.append(label)
                except OSError:
                    skipped += 1
        counts = Counter(y)
        if counts[0] < 5 or counts[1] < 5:
            raise ValueError(f"need at least 5 samples per class "
                             f"(got {counts[0]} benign, {counts[1]} malicious)")
        X_arr, y_arr = _np.array(X), _np.array(y)
        X_tr, X_te, y_tr, y_te = train_test_split(
            X_arr, y_arr, test_size=test_size, stratify=y_arr, random_state=seed)

        def forest():
            return _RandomForest(n_estimators=200, max_depth=12, min_samples_leaf=2,
                                 class_weight="balanced", random_state=seed, n_jobs=1)

        held_out = forest().fit(X_tr, y_tr)
        pred = held_out.predict(X_te)
        tn, fp, fn, tp = confusion_matrix(y_te, pred, labels=[0, 1]).ravel()
        metrics = {
            "samples": {"benign": counts[0], "malicious": counts[1], "unreadable": skipped},
            "holdout_size": int(len(y_te)),
            "accuracy": float((tp + tn) / len(y_te)),
            "precision": float(precision_score(y_te, pred, zero_division=0)),
            "recall": float(recall_score(y_te, pred, zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        }
        self.model = forest().fit(X_arr, y_arr)        # final model uses every sample
        self.model_name = "in-memory"
        self.model_info = {
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "metrics": metrics,
            "feature_importances": dict(zip(FEATURE_NAMES, map(
                float, self.model.feature_importances_))),
        }
        return metrics

    def _model_reasons(self, feats: Dict[str, float], top: int = 3) -> List[str]:
        imp = self.model_info.get("feature_importances") or {}
        ranked = sorted(imp.items(), key=lambda kv: kv[1], reverse=True)[:top]
        return [f"{name}={feats[name]:.3g} (weight {w:.2f})" for name, w in ranked]


def collect_files(directory: PathLike, limit: int = 100_000) -> List[Path]:
    """All regular files under a directory (symlinks skipped)."""
    out: List[Path] = []
    for p in sorted(Path(directory).rglob("*")):
        if p.is_file() and not p.is_symlink():
            out.append(p)
            if len(out) >= limit:
                break
    return out


def describe(features: Dict[str, float], names: Sequence[str] = FEATURE_NAMES) -> str:
    return ", ".join(f"{n}={features[n]:.3g}" for n in names)
