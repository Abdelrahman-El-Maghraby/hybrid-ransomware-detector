#!/usr/bin/env python3
"""Propose scoring weights from labelled data, for a human to review.

The weights in detectors/scoring.py were set by reasoning about each technique.
This tool checks them against real files: it scans labelled folders with the
engine (no VirusTotal, no LLM, no cache - the same rules as tools/evaluate.py),
records which indicators fired on each file, fits a logistic regression of
"malicious" on those indicators, and turns the coefficients into points on the
engine's 0-100 scale, where 50 (the High threshold) means 50 % probability.

    python tools/calibrate_weights.py --malicious ~/samples/malicious \
           --benign ~/samples/benign --out calib_out [--features-in features.jsonl]

Outputs (in --out):
  features.jsonl  one line per file: label + the indicators that fired (re-usable
                  with --features-in, so the folders need to be scanned only once)
  weights.json    current vs proposed points per indicator, with support counts
  summary.md      the same as a table, plus detection / false-alarm rates at the
                  High threshold for the current and the proposed weights
                  (in-sample and 5-fold cross-validated)

Nothing is applied automatically. Indicators seen fewer than --min-support
times are reported but keep their current weight: a handful of files cannot
justify a change. Run it inside the analysis VM; the outputs hold indicator
names, labels and SHA-256 hashes only.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HIGH = 50


def base_indicator(name: str) -> str:
    """'mail_attachment:archive_member:yara_match' -> 'yara_match'."""
    return name.rsplit(":", 1)[-1]


# ------------------------------------------------------------------ scanning
def _scanner():
    import os
    os.environ["LLM_PROVIDER"] = "none"
    from engine.config import CONFIG
    from engine.scanner import RansomwareScanner
    cfg = dict(CONFIG)
    cfg.update({"virustotal_api_key": "", "cache_enabled": False, "llm_provider": "none"})
    return RansomwareScanner(cfg)


def scan_folders(malicious: Sequence[Path], benign: Sequence[Path]) -> List[Dict]:
    scanner = _scanner()
    supported = tuple(e.lower() for e in scanner.file_extensions) + (
        ".exe", ".dll", ".scr", ".elf", ".bin")
    rows = []
    for label, roots in (("malicious", malicious), ("benign", benign)):
        for root in roots:
            for p in sorted(Path(root).expanduser().rglob("*")):
                if not p.is_file() or p.is_symlink():
                    continue
                if p.suffix.lower() not in supported and p.suffix:
                    continue
                try:
                    r = scanner.scan_file(str(p))
                except Exception as exc:              # recorded, never fatal
                    rows.append({"label": label, "error": type(exc).__name__, "path": str(p)})
                    continue
                contribs = (r.get("score_breakdown") or {}).get("contributions") or []
                ind: Dict[str, float] = {}
                for c in contribs:
                    name = base_indicator(str(c.get("indicator", "")))
                    ind[name] = max(ind.get(name, 0.0), float(c.get("points", 0) or 0))
                rows.append({"label": label, "sha256": r.get("sha256_hash", ""),
                             "risk": int(r.get("risk_score", 0)), "indicators": ind})
    return rows


# ------------------------------------------------------------------ model
def _sigmoid(z: float) -> float:
    if z < -40:
        return 0.0
    if z > 40:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def fit_logistic(X: List[List[float]], y: List[int], l2: float = 1.0, epochs: int = 600,
                 lr: float = 0.5) -> Tuple[float, List[float]]:
    """Plain L2 logistic regression (batch gradient descent), classes balanced."""
    n, d = len(X), len(X[0]) if X else 0
    pos = sum(y) or 1
    neg = (n - sum(y)) or 1
    wpos, wneg = n / (2 * pos), n / (2 * neg)
    b, w = 0.0, [0.0] * d
    for _ in range(epochs):
        gb, gw = 0.0, [0.0] * d
        for xi, yi in zip(X, y):
            err = (_sigmoid(b + sum(a * c for a, c in zip(w, xi))) - yi) * (wpos if yi else wneg)
            gb += err
            for j, v in enumerate(xi):
                if v:
                    gw[j] += err * v
        b -= lr * gb / n
        w = [wj - lr * (gwj / n + l2 * wj / n) for wj, gwj in zip(w, gw)]
    return b, w


def to_points(b: float, w: List[float]) -> List[float]:
    """Coefficients -> points: a file whose logit is 0 (p = 0.5) sits exactly on HIGH."""
    scale = HIGH / max(-b, 0.5)
    return [max(0.0, min(100.0, wj * scale)) for wj in w]


def score_rows(rows: List[Dict], weights: Dict[str, float]) -> List[int]:
    return [min(100, int(round(sum(weights.get(k, v) for k, v in r["indicators"].items()))))
            for r in rows]


def rates(rows: List[Dict], scores: List[int], thr: int = HIGH) -> Dict[str, float]:
    mal = [s for r, s in zip(rows, scores) if r["label"] == "malicious"]
    ben = [s for r, s in zip(rows, scores) if r["label"] == "benign"]
    return {"detection": sum(s >= thr for s in mal) / len(mal) if mal else 0.0,
            "false_alarm": sum(s >= thr for s in ben) / len(ben) if ben else 0.0,
            "malicious": len(mal), "benign": len(ben)}


def calibrate(rows: Iterable[Dict], min_support: int = 10, folds: int = 5,
              seed: int = 7) -> Dict:
    rows = [r for r in rows if "indicators" in r]
    names = sorted({k for r in rows for k in r["indicators"]})
    current: Dict[str, float] = {}
    for k in names:
        pts = [r["indicators"][k] for r in rows if k in r["indicators"]]
        current[k] = sum(pts) / len(pts)
    support = {k: {"malicious": sum(1 for r in rows if r["label"] == "malicious" and k in r["indicators"]),
                   "benign": sum(1 for r in rows if r["label"] == "benign" and k in r["indicators"])}
               for k in names}

    def fit(train: List[Dict]) -> Dict[str, float]:
        X = [[1.0 if k in r["indicators"] else 0.0 for k in names] for r in train]
        y = [1 if r["label"] == "malicious" else 0 for r in train]
        if not X or len(set(y)) < 2:
            return dict(current)
        b, w = fit_logistic(X, y)
        pts = dict(zip(names, to_points(b, w)))
        return {k: (pts[k] if sum(support[k].values()) >= min_support else current[k])
                for k in names}

    proposed = fit(rows)
    as_is = {k: v for k, v in current.items()}
    cur_scores = [min(100, r["risk"]) if "risk" in r else s
                  for r, s in zip(rows, score_rows(rows, as_is))]

    shuffled = rows[:]
    random.Random(seed).shuffle(shuffled)
    cv_scores: List[Tuple[Dict, int]] = []
    if len(shuffled) >= folds * 2:
        for f in range(folds):
            test = shuffled[f::folds]
            train = [r for i, r in enumerate(shuffled) if i % folds != f]
            wts = fit(train)
            cv_scores += list(zip(test, score_rows(test, wts)))

    table = [{"indicator": k, "current": round(current[k], 1), "proposed": round(proposed[k], 1),
              "change": round(proposed[k] - current[k], 1), **support[k],
              "kept_current": sum(support[k].values()) < min_support} for k in names]
    table.sort(key=lambda t: -abs(t["change"]))
    return {
        "indicators": table,
        "current": rates(rows, cur_scores),
        "proposed_in_sample": rates(rows, score_rows(rows, proposed)),
        "proposed_cross_validated": (rates([r for r, _ in cv_scores], [s for _, s in cv_scores])
                                     if cv_scores else None),
        "min_support": min_support,
        "files": len(rows),
    }


def summary_md(res: Dict) -> str:
    def pct(x): return f"{100 * x:.1f}%"
    lines = ["# Weight calibration", "",
             f"{res['files']} files. Rates at the High threshold ({HIGH}).", "",
             "| | detection | false alarms |", "|---|---:|---:|"]
    for label, key in (("current weights", "current"), ("proposed, in-sample", "proposed_in_sample"),
                       ("proposed, 5-fold CV", "proposed_cross_validated")):
        r = res.get(key)
        if r:
            lines.append(f"| {label} | {pct(r['detection'])} | {pct(r['false_alarm'])} |")
    lines += ["", "In-sample numbers flatter the proposal; decide on the cross-validated row.", "",
              "| indicator | current | proposed | change | malicious | benign |",
              "|---|---:|---:|---:|---:|---:|"]
    for t in res["indicators"]:
        note = " (kept: too few files)" if t["kept_current"] else ""
        lines.append(f"| {t['indicator']}{note} | {t['current']} | {t['proposed']} | "
                     f"{t['change']:+} | {t['malicious']} | {t['benign']} |")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--malicious", nargs="*", type=Path, default=[])
    ap.add_argument("--benign", nargs="*", type=Path, default=[])
    ap.add_argument("--features-in", type=Path, help="reuse features.jsonl instead of scanning")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--min-support", type=int, default=10)
    a = ap.parse_args(argv)
    a.out.mkdir(parents=True, exist_ok=True)
    if a.features_in:
        rows = [json.loads(l) for l in a.features_in.read_text().splitlines() if l.strip()]
    else:
        if not a.malicious or not a.benign:
            ap.error("give --malicious and --benign folders, or --features-in")
        rows = scan_folders(a.malicious, a.benign)
        with open(a.out / "features.jsonl", "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
    res = calibrate(rows, min_support=a.min_support)
    (a.out / "weights.json").write_text(json.dumps(res, indent=2))
    (a.out / "summary.md").write_text(summary_md(res))
    print(summary_md(res).split("\n\n| indicator")[0])
    print(f"\nFull table: {a.out / 'summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
